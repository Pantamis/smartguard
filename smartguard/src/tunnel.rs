//! High-level tunnel event loop with signal handling and route management.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use iptrie::{Ipv4LCTrieMap, Ipv4Prefix};
use rand::{rngs::OsRng, TryRngCore};
use rustyguard_core::{PeerId, Sessions};
use rustyguard_crypto::DhOracle;
use rustyguard_tun::tun::Device as _;
use rustyguard_tun::{handle_extern, handle_intern, tun, AlignedPacket, Write, TUN_BUF_START};

use tai64::Tai64N;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadBuf},
    net::UdpSocket,
};

use crate::route::{cleanup_routes, setup_routes};

/// Run the WireGuard tunnel event loop.
///
/// Creates a TUN device, sets up routes for AllowedIPs, listens on a UDP socket,
/// and shuttles packets between the TUN interface and the WireGuard protocol.
/// Handles SIGINT/SIGTERM for graceful shutdown with route cleanup.
///
/// Sessions calls go through `tokio::task::spawn_blocking` because they may
/// trigger smartcard DH operations that block for ~tens-to-hundreds of ms.
/// This tells the tokio runtime "this work is blocking, run it on the
/// blocking pool" — the async worker stays free to drive the reactor and
/// any other tasks.
pub async fn run_tunnel<O>(
    mut sessions: Sessions<O>,
    mut peer_net: Ipv4LCTrieMap<PeerId>,
    peer_ids: &[PeerId],
    listen_port: u16,
    tun_addr: ipnet::Ipv4Net,
    mtu: i32,
    allowed_ips: &[Ipv4Prefix],
    peer_endpoints: &[Option<SocketAddr>],
) -> Result<(), Box<dyn std::error::Error>>
where
    O: DhOracle + Send + 'static,
{
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), listen_port);
    let endpoint = UdpSocket::bind(bind_addr).await?;
    eprintln!("Listening on UDP {bind_addr}");

    let mut tun_config = tun::Configuration::default();
    tun_config
        .address(tun_addr.addr())
        .netmask(tun_addr.netmask())
        .mtu(mtu)
        .up();

    let tun_dev = tun::platform::create(&tun_config)?;
    let tun_name = tun_dev.name().to_owned();
    let mut dev = tun::AsyncDevice::new(tun_dev)?;
    eprintln!("TUN interface {tun_name} up with address {tun_addr}");

    // Set up routes for AllowedIPs.
    let added_routes = setup_routes(&tun_name, allowed_ips, peer_endpoints);

    // Initiate handshake to all peers with known endpoints at startup.
    for &peer_id in peer_ids {
        let init;
        (sessions, init) = tokio::task::spawn_blocking(move || {
            let mut dummy = [0u8; 16];
            let init = match sessions.send_message(peer_id, &mut dummy) {
                Ok(rustyguard_core::SendMessage::Maintenance(msg)) => Some(msg),
                _ => None,
            };

            (sessions, init)
        })
        .await?;
        if let Some(msg) = init {
            let addr = msg.to();
            eprintln!("Initiating handshake to {addr}");
            endpoint.send_to(msg.data(), addr).await?;
        }
    }

    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));

    use tokio::signal::unix;
    let mut sigint = unix::signal(unix::SignalKind::interrupt())?;
    let mut sigterm = unix::signal(unix::SignalKind::terminate())?;

    let mut maintenance_buffer = Vec::with_capacity(peer_ids.len());

    let mut endpoint_buffer = Box::new(AlignedPacket([0; 2048]));
    let mut tun_buffer = vec![0u8; 2048];

    let result: Result<(), Box<dyn std::error::Error>> = 'main: loop {
        let mut ep_buf = ReadBuf::new(&mut endpoint_buffer.0);
        let mut tun_reply_buf = ReadBuf::new(&mut tun_buffer[TUN_BUF_START..]);
        tokio::select! {
            _ = sigint.recv() => break Ok(()),
            _ = sigterm.recv() => break Ok(()),
            _ = tick.tick() => {
                // turn blocks on the smart card for a handshake
                // every 2 minutes, although spawn_blocking has a cost
                // it is negligible once every second compared to
                // blocking the runtime 100 ms every 2 minutes
                (sessions, maintenance_buffer) = tokio::task::spawn_blocking(move || {
                    while let Some(msg) = sessions.turn(Tai64N::now(), &mut OsRng.unwrap_err()) {
                        maintenance_buffer.push(msg);
                    }
                    (sessions, maintenance_buffer)
                })
                .await?;

                for msg in maintenance_buffer.drain(..) {
                    endpoint.send_to(msg.data(), msg.to()).await?;
                }
            },
            res = endpoint.recv_buf_from(&mut ep_buf) => {
                let (n, addr) = res?;
                let ep_buf = ep_buf.filled_mut();
                // Fast path: avoid spawn_blocking if we are in case
                // where no handshake will be performed
                const MSG_FIRST: u8 = 1;
                if n > 0 && (ep_buf[0] != MSG_FIRST) {
                    if let Write::Inbound(data) = handle_extern(
                        &mut sessions,
                        &peer_net,
                        addr,
                        ep_buf,
                    ) {
                        dev.write_all(data).await?;
                    }

                    // recv_message for MSG_DATA only ever produces
                    // Read (→ Inbound), Noop, or Err — it never
                    // generates a reply.
                    continue 'main;
                }

                let msg_len;
                (sessions, peer_net, endpoint_buffer, msg_len) = tokio::task::spawn_blocking(move || {
                    let msg_len = if let Write::Outbound(data, _) = handle_extern(
                        &mut sessions,
                        &peer_net,
                        addr,
                        &mut endpoint_buffer.0[..n],
                    )
                    {
                        data.len()
                    } else {
                        // Invalid message received continue
                        0
                    };

                    (sessions, peer_net, endpoint_buffer, msg_len)
                })
                .await?;
                if msg_len == 0 {
                    continue 'main
                }
                // If here we performed a handshake
                endpoint.send_to(&endpoint_buffer.0[..msg_len], addr).await?;
            }
            res = dev.read_buf(&mut tun_reply_buf) => {
                // Not spawn on the blocking pool as this can triggers
                // a smart card handshake only when there's no active
                // session, `tick_timers` runs every second and pushes
                // `RekeyAttempt` ~60s before the session window closes
                // (REKEY_AFTER_TIME = 120s vs. REJECT_AFTER_TIME = 180s),
                // so a packet-driven cold handshake here is a corner case.
                if let Write::Outbound(data, dst) =
                    handle_intern(&mut sessions, &peer_net, &mut tun_buffer, TUN_BUF_START + res?)
                {
                    endpoint.send_to(data, dst).await?;
                };
                // handle_intern never produces Inbound (it always
                // wraps a TUN-read packet for outbound transmission).
                // Or produce None so no-op in else case.
            }
        }
    };

    // Clean up routes, then drop the TUN fd (destroys the utun interface)
    eprintln!("\nShutting down...");
    cleanup_routes(&added_routes);
    result
}
