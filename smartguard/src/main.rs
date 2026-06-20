mod config;
mod dns;
mod route;
mod tunnel;

use std::path::{Path, PathBuf};
use std::process;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use clap::{Parser, Subcommand};
use ipnet::IpNet;

use config::{Config, PrivateKeyConfig};
use secrecy::SecretString;
use smartguard_crypto::{list_cards, AsyncDhOracle, CardHandle, DhOracle, PeerConfig};

use rustyguard_core::{PublicKey, StaticPrivateKey};

#[derive(Parser)]
#[command(
    name = "smartguard",
    version,
    about = "WireGuard with smartcard key protection"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Bring up the WireGuard tunnel.
    Up {
        /// Path to the configuration file.
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Bring down the WireGuard tunnel.
    Down,
    /// Show tunnel status.
    Status,
    /// List connected OpenPGP smartcards with X25519 decryption keys.
    ShowCard,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Up { config } => cmd_up(&config),
        Command::Down => cmd_down(),
        Command::Status => cmd_status(),
        Command::ShowCard => cmd_show_card(),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

fn cmd_up(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_file(config_path)?;

    let listen_port = config.interface.listen_port.unwrap_or(51820);
    let mtu = config.interface.mtu.unwrap_or(1420);
    if config.interface.address.is_empty() {
        return Err("interface.address is required for tunnel mode".into());
    }
    let tun_addrs: Vec<IpNet> = config
        .interface
        .address
        .iter()
        .map(|s| s.parse())
        .collect::<Result<_, _>>()?;

    // Parse the config peers into the runtime `PeerConfig` (one struct per
    // peer, carrying everything the session builder and tunnel loop need).
    // A `persistent_keepalive` of `0` or absent both disable keepalive.
    let peers: Vec<PeerConfig> = config
        .peers
        .iter()
        .map(|p| PeerConfig {
            public_key: PublicKey(p.public_key),
            preshared_key: p.preshared_key,
            endpoint: p.endpoint,
            allowed_ips: p
                .allowed_ips
                .iter()
                .map(|s| s.parse().expect("invalid AllowedIP prefix"))
                .collect(),
            persistent_keepalive: match p.persistent_keepalive {
                Some(0) | None => None,
                Some(s) => Some(Duration::from_secs(s as u64)),
            },
        })
        .collect();

    match &config.interface.private_key {
        PrivateKeyConfig::Software(key) => {
            eprintln!("Using software private key");
            let private_key = StaticPrivateKey(*key);
            eprintln!(
                "Public key: {}",
                BASE64.encode(private_key.x25519_pubkey().0)
            );
            eprintln!("{} peer(s) configured", peers.len());

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(tunnel::run_tunnel(
                private_key,
                peers,
                listen_port,
                &tun_addrs,
                mtu,
                &config.interface.dns,
            ))?;
        }
        PrivateKeyConfig::Smartcard(ident) => {
            run_smartcard(
                ident,
                &config.interface.smartcard.pin_entry,
                peers,
                listen_port,
                &tun_addrs,
                mtu,
                &config.interface.dns,
            )?;
        }
        PrivateKeyConfig::SmartcardAuto => {
            run_smartcard(
                "auto",
                &config.interface.smartcard.pin_entry,
                peers,
                listen_port,
                &tun_addrs,
                mtu,
                &config.interface.dns,
            )?;
        }
    }

    Ok(())
}

/// Bring up the tunnel using a smartcard-backed key.
///
/// The card thread is async-spawned (it awaits a one-shot for the card to
/// be opened, PIN-verified, and ready), so we set up the tokio runtime
/// first and drive both setup and the tunnel under the same `block_on`.
#[allow(clippy::too_many_arguments)]
fn run_smartcard(
    ident: &str,
    pin_entry: &str,
    peers: Vec<PeerConfig>,
    listen_port: u16,
    tun_addrs: &[IpNet],
    mtu: i32,
    dns: &[std::net::IpAddr],
) -> Result<(), Box<dyn std::error::Error>> {
    let pin = obtain_pin(pin_entry)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async move {
        eprintln!("Opening smartcard {ident}...");
        let mut card = CardHandle::open(ident, pin).await?;
        eprintln!(
            "Public key: {}",
            BASE64.encode(card.async_x25519_pubkey().await)
        );

        // Precompute ss for each peer so handshakes don't pay a card
        // round-trip for the static-static DH on the hot path.
        for peer in &peers {
            if let Err(e) = card.prime_ss(&peer.public_key).await {
                eprintln!("warning: failed to prime ss for peer: {e}");
            }
        }
        eprintln!("{} peer(s) configured", peers.len());

        tunnel::run_tunnel(card, peers, listen_port, tun_addrs, mtu, dns).await
    })
}

fn cmd_down() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Down not yet implemented (no active tunnel to tear down).");
    Ok(())
}

fn cmd_status() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Status not yet implemented (no active tunnel to query).");
    Ok(())
}

fn cmd_show_card() -> Result<(), Box<dyn std::error::Error>> {
    let cards = list_cards()?;
    if cards.is_empty() {
        println!("No OpenPGP smartcards with X25519 decryption keys found.");
        println!();
        println!("Make sure:");
        println!("  - A smartcard reader is connected");
        println!("  - The card has an X25519 key in the decryption slot");
        println!("  - pcscd is running (Linux: systemctl start pcscd)");
        return Ok(());
    }

    println!("Found {} card(s):\n", cards.len());
    for card in &cards {
        println!("  Card:       {}", card.ident);
        println!("  Public key: {}", BASE64.encode(card.public_key));
        println!();
    }

    Ok(())
}

/// Obtain the smartcard PIN based on the configured pin_entry method.
fn obtain_pin(pin_entry: &str) -> Result<SecretString, Box<dyn std::error::Error>> {
    if pin_entry == "prompt" {
        Ok(rpassword::prompt_password_with_config(
            "Smartcard PIN: ",
            rpassword::ConfigBuilder::new()
                .password_feedback_mask('*')
                .build(),
        )?
        .into())
    } else if let Some(var_name) = pin_entry.strip_prefix("env:") {
        Ok(std::env::var(var_name)?.into())
    } else {
        Err(format!("unsupported pin_entry method: {pin_entry}").into())
    }
}
