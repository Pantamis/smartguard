//! Scoped WireGuard event loop for Android.
//!
//! A faithful port of the desktop `smartguard/src/tunnel.rs` loop, minus the
//! desktop-only parts: no TUN creation (we adopt the `VpnService` fd), no route
//! or DNS management (that's `VpnService.Builder`'s job in Kotlin), and shutdown
//! is a cancellation pipe rather than SIGINT/SIGTERM.
//!
//! The oracle (a `CardHandle`) is moved into `Sessions`, so the long-lived card
//! thread lives exactly as long as this loop — the scoped lifecycle that maps
//! cleanly onto a single blocking `nativeRunTunnel` call.

use std::os::fd::OwnedFd;
use std::time::Duration;

use rand::{TryRngCore, rngs::OsRng};
use rustyguard_core::{DataHeader, PeerId, SendMessage, Sessions};
use rustyguard_crypto::AsyncDhOracle;
use smartguard_crypto::{PeerConfig, build_sessions};
use tai64::Tai64N;
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::time::{Instant, interval};

use crate::framing::{IP_PACKET_START, Write, handle_extern, handle_intern};
use crate::tun::AsyncTun;

/// 16-byte-aligned 2048-byte scratch buffer (matches rustyguard's
/// `AlignedPacket`; the crypto paths prefer aligned input).
#[repr(align(16))]
struct AlignedPacket([u8; 2048]);

/// Per-peer persistent-keepalive bookkeeping.
struct PeerRuntime {
    id: PeerId,
    keepalive: Option<Duration>,
    last_sent: Instant,
}

/// Run the tunnel until `cancel` becomes readable (Kotlin closes/writes the
/// pipe's write end to stop), then return — dropping `Sessions` (and with it
/// the card thread), the sockets, and the TUN fd.
pub async fn run_tunnel<O>(
    oracle: O,
    peers: Vec<PeerConfig>,
    tun: AsyncTun,
    udp: UdpSocket,
    cancel: AsyncFd<OwnedFd>,
) -> std::io::Result<()>
where
    O: AsyncDhOracle + Send + 'static,
{
    let (mut sessions, peer_net, peer_ids) = build_sessions(oracle, &peers).await;

    let now0 = Instant::now();
    let mut peer_rt: Vec<PeerRuntime> = peer_ids
        .iter()
        .zip(&peers)
        .map(|(id, p)| PeerRuntime {
            id: *id,
            keepalive: p.persistent_keepalive,
            last_sent: now0,
        })
        .collect();

    // Initiate a handshake to each peer that has a configured endpoint.
    for p in &peer_rt {
        if let Ok(SendMessage::Maintenance(msg)) =
            sessions.send_message(p.id, &mut [0u8; 16]).await
        {
            let _ = udp.send_to(msg.data(), msg.to()).await;
        }
    }

    let mut tick = interval(Duration::from_secs(1));
    let mut maintenance = Vec::with_capacity(peer_rt.len());
    let mut ep_buf = Box::new(AlignedPacket([0u8; 2048]));
    let mut tun_buf = Box::new(AlignedPacket([0u8; 2048]));

    loop {
        tokio::select! {
            // Shutdown: the read end becoming readable means Kotlin signalled stop.
            _ = cancel.readable() => break,

            _ = tick.tick() => {
                while let Some(msg) = sessions.turn(Tai64N::now(), &mut OsRng.unwrap_err()).await {
                    maintenance.push(msg);
                }
                for msg in maintenance.drain(..) {
                    let _ = udp.send_to(msg.data(), msg.to()).await;
                }

                let now = Instant::now();
                for p in peer_rt.iter_mut().filter(|p| {
                    p.keepalive.is_some_and(|i| now.duration_since(p.last_sent) >= i)
                }) {
                    send_keepalive(&mut sessions, p.id, &udp).await;
                    p.last_sent = now;
                }
            }

            // Inbound from the network.
            r = udp.recv_from(&mut ep_buf.0) => {
                let (n, addr) = r?;
                match handle_extern(&mut sessions, &peer_net, addr, &mut ep_buf.0[..n]).await {
                    Write::Inbound(data) => { let _ = tun.write(data).await; }
                    Write::Outbound(data, to) => { let _ = udp.send_to(data, to).await; }
                    Write::None => {}
                }
            }

            // Outbound from the TUN. Read the IP packet at IP_PACKET_START so the
            // WireGuard header can be framed in place ahead of it.
            r = tun.read(&mut tun_buf.0[IP_PACKET_START..]) => {
                let filled = IP_PACKET_START + r?;
                if let Write::Outbound(data, dst) =
                    handle_intern(&mut sessions, &peer_net, &mut tun_buf.0, filled).await
                {
                    let _ = udp.send_to(data, dst).await;
                }
            }
        }
    }

    Ok(())
}

/// Send a keepalive (empty-payload data packet) to `peer_id`; if there's no
/// active session yet, the underlying call returns a handshake init instead.
async fn send_keepalive<O>(sessions: &mut Sessions<O>, peer_id: PeerId, socket: &UdpSocket)
where
    O: AsyncDhOracle + Send,
{
    const HEADER: usize = std::mem::size_of::<DataHeader>();
    const TAG: usize = 16;
    let mut buf = [0u8; HEADER + TAG];

    let payload_slot = &mut buf[HEADER..HEADER];
    match sessions.send_message(peer_id, payload_slot).await {
        Ok(SendMessage::Data(ep, metadata)) => {
            metadata.frame_in_place(&mut buf);
            let _ = socket.send_to(&buf, ep).await;
        }
        Ok(SendMessage::Maintenance(msg)) => {
            let _ = socket.send_to(msg.data(), msg.to()).await;
        }
        Err(_) => {}
    }
}
