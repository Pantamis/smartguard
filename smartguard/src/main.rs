mod config;
mod route;
mod tunnel;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use clap::{Parser, Subcommand};
use iptrie::Ipv4Prefix;

use config::{Config, PrivateKeyConfig};
use secrecy::SecretString;
use smartguard_crypto::{list_cards, CardHandle, DhOracle};

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
    let tun_addr: ipnet::Ipv4Net = config
        .interface
        .address
        .as_deref()
        .ok_or("interface.address is required for tunnel mode")?
        .parse()?;

    // Parse peers into the format needed by build_sessions
    let peers: Vec<(
        PublicKey,
        Option<[u8; 32]>,
        Option<SocketAddr>,
        Vec<Ipv4Prefix>,
    )> = config
        .peers
        .iter()
        .map(|p| {
            let allowed_ips: Vec<Ipv4Prefix> = p
                .allowed_ips
                .iter()
                .map(|s| s.parse().expect("invalid AllowedIP prefix"))
                .collect();
            (
                PublicKey(p.public_key),
                p.preshared_key,
                p.endpoint,
                allowed_ips,
            )
        })
        .collect();

    let all_allowed_ips: Vec<Ipv4Prefix> = peers.iter().flat_map(|p| p.3.clone()).collect();
    let peer_endpoints: Vec<Option<SocketAddr>> = peers.iter().map(|p| p.2).collect();

    match &config.interface.private_key {
        PrivateKeyConfig::Software(key) => {
            eprintln!("Using software private key");
            let private_key = StaticPrivateKey(*key);
            eprintln!(
                "Public key: {}",
                BASE64.encode(private_key.x25519_pubkey().0)
            );
            eprintln!("{} peer(s) configured", peers.len());

            let (sessions, peer_net, peer_ids) =
                smartguard_crypto::build_sessions(private_key, &peers);

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(tunnel::run_tunnel(
                sessions,
                peer_net,
                &peer_ids,
                listen_port,
                tun_addr,
                mtu,
                &all_allowed_ips,
                &peer_endpoints,
            ))?;
        }
        PrivateKeyConfig::Smartcard(ident) => {
            let pin = obtain_pin(&config.interface.smartcard.pin_entry)?;
            let card = open_smartcard(ident, &pin, &peers)?;
            eprintln!("{} peer(s) configured", peers.len());

            let (sessions, peer_net, peer_ids) = smartguard_crypto::build_sessions(card, &peers);

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(tunnel::run_tunnel(
                sessions,
                peer_net,
                &peer_ids,
                listen_port,
                tun_addr,
                mtu,
                &all_allowed_ips,
                &peer_endpoints,
            ))?;
        }
        PrivateKeyConfig::SmartcardAuto => {
            let pin = obtain_pin(&config.interface.smartcard.pin_entry)?;
            let card = open_smartcard("auto", &pin, &peers)?;
            eprintln!("{} peer(s) configured", peers.len());

            let (sessions, peer_net, peer_ids) = smartguard_crypto::build_sessions(card, &peers);

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(tunnel::run_tunnel(
                sessions,
                peer_net,
                &peer_ids,
                listen_port,
                tun_addr,
                mtu,
                &all_allowed_ips,
                &peer_endpoints,
            ))?;
        }
    }

    Ok(())
}

/// Open the smartcard, verify PIN, and prime the ss cache for each peer.
fn open_smartcard(
    ident: &str,
    pin: &SecretString,
    peers: &[(
        PublicKey,
        Option<[u8; 32]>,
        Option<SocketAddr>,
        Vec<Ipv4Prefix>,
    )],
) -> Result<CardHandle, Box<dyn std::error::Error>> {
    eprintln!("Opening smartcard {ident}...");
    let card = CardHandle::open(ident, pin)?;
    eprintln!("Public key: {}", BASE64.encode(card.x25519_pubkey().0));

    // Precompute ss for each peer so the card is only called once per peer.
    for (peer_pk, _, _, _) in peers {
        if let Err(e) = card.prime_ss(peer_pk) {
            eprintln!("warning: failed to prime ss for peer: {e}");
        }
    }

    Ok(card)
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
