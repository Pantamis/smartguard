//! High-level tunnel event loop with signal handling and route management.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use ipnet::{IpNet, Ipv6Net};
use rand::{rngs::OsRng, TryRngCore};
use rustyguard_core::{DataHeader, PeerId, SendMessage, Sessions};
use rustyguard_crypto::AsyncDhOracle;
use rustyguard_tun::{
    tun::{self, Device as _},
    AlignedPacket, Write, TUN_BUF_START,
};
use smartguard_crypto::{handle_extern, handle_intern, PeerConfig};
use tai64::Tai64N;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadBuf},
    net::UdpSocket,
    task::spawn_blocking,
    time::{interval, Instant},
};

use crate::dns::{apply_dns, cleanup_dns, AppliedDns};
use crate::route::{
    cleanup_routes, recheck_routes, setup_routes, setup_unconfigured_family, AddedRoute, Family,
};

/// Guard to cleanup our networking settings when exiting for any reason:
struct CleanupGuard {
    added_routes: Vec<AddedRoute>,
    applied_dns: Option<AppliedDns>,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        eprintln!("\nCleaning up tunnel routes / DNS...");
        if let Some(d) = self.applied_dns.as_ref() {
            cleanup_dns(d);
        }
        cleanup_routes(&self.added_routes);
    }
}

/// Per-peer runtime state, collected into one `Vec<PeerRuntime>` (one entry
/// per configured peer) instead of several parallel index-aligned `Vec`s.
/// The companion `HashMap<SocketAddr, usize>` (see `run_tunnel`) maps a
/// destination endpoint back to its index in O(1) on the packet hot path.
struct PeerRuntime {
    id: PeerId,
    endpoint: Option<SocketAddr>,
    /// Persistent-keepalive interval; `None` disables keepalive for this peer.
    keepalive: Option<Duration>,
    /// Last time we sent any packet to this peer. Gates persistent keepalive:
    /// a keepalive is only emitted after `keepalive` of silence, and every
    /// data packet we send postpones it (WireGuard semantics).
    last_sent: Instant,
}

/// Apply an IPv6 address to the TUN by shelling out to the platform tool.
/// rustyguard_tun's `Configuration` only handles IPv4 ioctls; IPv6 is set
/// after the device is up — same shell-out pattern wg-quick uses.
fn apply_ipv6_addr(tun_name: &str, net: Ipv6Net) -> bool {
    let cidr = net.to_string();
    #[cfg(target_os = "macos")]
    let status = std::process::Command::new("ifconfig")
        .args([tun_name, "inet6", &cidr, "alias"])
        .status();
    #[cfg(target_os = "linux")]
    let status = std::process::Command::new("ip")
        .args(["-6", "addr", "add", &cidr, "dev", tun_name])
        .status();
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let status: std::io::Result<std::process::ExitStatus> = {
        eprintln!("IPv6 address configuration not supported on this platform");
        Err(std::io::Error::other("unsupported platform"))
    };
    match status {
        Ok(s) if s.success() => {
            eprintln!("TUN address added: {cidr}");
            true
        }
        Ok(s) => {
            eprintln!("  ifconfig/ip add {cidr} => exit {s}");
            false
        }
        Err(e) => {
            eprintln!("  ifconfig/ip add {cidr} failed: {e}");
            false
        }
    }
}

/// Run the WireGuard tunnel event loop.
///
/// Creates a TUN device, sets up routes for AllowedIPs, listens on a UDP socket,
/// and shuttles packets between the TUN interface and the WireGuard protocol.
/// Handles SIGINT/SIGTERM for graceful shutdown with route cleanup.
///
/// Sessions calls go through the async DH oracle: a smartcard `CardHandle`
/// awaits the card thread, a `StaticPrivateKey` resolves immediately (via the
/// `AsyncDhOracle` blanket impl over `DhOracle`). Either way, the runtime
/// stays free to drive the reactor while DH is in flight — no spawn_blocking
/// needed for handshakes.
pub async fn run_tunnel<O>(
    oracle: O,
    peers: Vec<PeerConfig>,
    listen_port: u16,
    tun_addrs: &[IpNet],
    mtu: i32,
    dns_servers: &[IpAddr],
) -> Result<(), Box<dyn std::error::Error>>
where
    O: AsyncDhOracle + Send + 'static,
{
    let (mut sessions, peer_net, peer_ids) =
        smartguard_crypto::build_sessions(oracle, &peers).await;

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), listen_port);
    let endpoint = UdpSocket::bind(bind_addr).await?;
    eprintln!("Listening on UDP {bind_addr}");

    // First IPv4 address (if any) goes through the rustyguard_tun ioctl path.
    // IPv6 addresses are applied after the device is up via shell-out.
    let v4_addr = tun_addrs.iter().find_map(|n| match n {
        IpNet::V4(p) => Some(*p),
        IpNet::V6(_) => None,
    });

    let mut tun_config = tun::Configuration::default();
    if let Some(v4) = v4_addr {
        tun_config
            .address(v4.addr())
            .netmask(v4.netmask())
            .mtu(mtu)
            .up();
    } else {
        tun_config.mtu(mtu).up();
    }

    let tun_dev = tun::platform::create(&tun_config)?;
    let tun_name = tun_dev.name().to_owned();
    let mut dev = tun::AsyncDevice::new(tun_dev)?;
    eprintln!("TUN interface {tun_name} up");

    for net in tun_addrs {
        if let IpNet::V6(v6) = net {
            apply_ipv6_addr(&tun_name, *v6);
        }
    }

    // Consolidate per-peer runtime state. `peer_ids` is index-aligned with
    // `peers` (build_sessions preserves the input order), so we zip them into
    // one `Vec<PeerRuntime>`. Seed `last_sent` at `now` so the first keepalive
    // fires `interval` after startup rather than immediately.
    let now0 = Instant::now();
    let mut peer_rt: Vec<PeerRuntime> = peer_ids
        .into_iter()
        .zip(&peers)
        .map(|(id, p)| PeerRuntime {
            id,
            endpoint: p.endpoint,
            keepalive: p.persistent_keepalive,
            last_sent: now0,
        })
        .collect();
    // Reverse index: destination endpoint → peer slot, for O(1) lookup on the
    // packet hot path (a data send reports the endpoint, not a peer index).
    let endpoint_to_idx: HashMap<SocketAddr, usize> = peer_rt
        .iter()
        .enumerate()
        .filter_map(|(i, p)| p.endpoint.map(|ep| (ep, i)))
        .collect();

    let mut allowed_ips: Vec<IpNet> = Vec::with_capacity(peers.len());
    let peer_endpoints: Vec<SocketAddr> = peers
        .into_iter()
        .flat_map(|p| {
            allowed_ips.extend(p.allowed_ips);
            p.endpoint
        })
        .collect();

    // Deliberately *not* assigning a placeholder ULA when no v6 address is
    // configured: doing so would make NWPathMonitor report utun5 as a
    // usable v6 path. NEPacketTunnelProvider-based apps (Tailscale, etc.)
    // would then route their v6 underlay traffic to utun5 — but their
    // sandbox only entitles them to send via their own utun and en0, not
    // ours, so every such connection fails with `network is unreachable`.
    //
    // Without the placeholder, NWPathMonitor sees utun5's only v6 source
    // is link-local (auto-assigned by the kernel), rejects it for global
    // destinations, and lets NEVPN apps bind to en0 instead. They keep
    // working. The cost: regular apps' v6 traffic also routes via en0,
    // which means v6 leaks to the ISP. There's no way to distinguish "a
    // NEVPN process I should let escape" from "a raw socket I should
    // capture" at the raw-routes level — that distinction lives entirely
    // inside Apple's NEPacketTunnelProvider framework and isn't
    // accessible to a CLI.

    let mut guard = CleanupGuard {
        added_routes: setup_routes(&tun_name, &allowed_ips, &peer_endpoints),
        applied_dns: None,
    };

    // For any address family the interface has no address of, route the
    // family's /1 halves into our utun. Packets dead-end there (no source
    // address available), achieving the same no-leak effect as a hard
    // blackhole — but without the side-effect that Network.framework reads
    // a `-blackhole` route as "permanently unreachable" and refuses to let
    // NEPacketTunnelProvider-based apps (Tailscale, etc.) override it for
    // their own bootstrap traffic. See `setup_unconfigured_family` doc.
    let has_v4 = tun_addrs.iter().any(|n| matches!(n, IpNet::V4(_)));
    let has_v6 = tun_addrs.iter().any(|n| matches!(n, IpNet::V6(_)));
    if !has_v4 {
        guard.added_routes.extend(setup_unconfigured_family(
            Family::V4,
            &tun_name,
            &peer_endpoints,
        ));
    }
    if !has_v6 {
        guard.added_routes.extend(setup_unconfigured_family(
            Family::V6,
            &tun_name,
            &peer_endpoints,
        ));
    }

    // Replace the system resolver while the tunnel is up (mirrors wg-quick).
    guard.applied_dns = apply_dns(&tun_name, dns_servers);

    // Initiate handshake to all peers with known endpoints at startup.
    for p in &peer_rt {
        if let Ok(rustyguard_core::SendMessage::Maintenance(msg)) =
            sessions.send_message(p.id, &mut [0u8; 16]).await
        {
            let addr = msg.to();
            eprintln!("Initiating handshake to {addr}");
            if let Err(e) = endpoint.send_to(msg.data(), addr).await {
                eprintln!("  send_to {addr} failed: {e}");
            }
        }
    }

    let mut tick = interval(Duration::from_secs(1));
    let host_route_idx = guard
        .added_routes
        .iter()
        .position(|r| matches!(r, AddedRoute::Host { .. }));

    use tokio::signal::unix;
    let mut sigint = unix::signal(unix::SignalKind::interrupt())?;
    let mut sigterm = unix::signal(unix::SignalKind::terminate())?;

    let mut maintenance_buffer = Vec::with_capacity(peer_rt.len());

    let mut endpoint_buffer = Box::new(AlignedPacket([0; 2048]));
    let mut tun_buffer = vec![0u8; 2048];

    let result: Result<(), Box<dyn std::error::Error>> = loop {
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

                while let Some(msg) = sessions.turn(Tai64N::now(), &mut OsRng.unwrap_err()).await {
                    maintenance_buffer.push(msg);
                }

                if host_route_idx.is_some_and(|i| {
                    matches!(guard.added_routes[i], AddedRoute::Host { gateway: None, .. })
                }) {
                    guard = spawn_blocking(move || {
                        recheck_routes(&mut guard.added_routes);
                        guard
                    }).await?;
                }

                for msg in maintenance_buffer.drain(..) {
                    if let Err(e) = endpoint.send_to(msg.data(), msg.to()).await {
                        eprintln!("send_to {} failed: {e}", msg.to());
                    }
                }

                // `persistent_keepalive`: per-peer proactive empty-payload
                // data packet that keeps the NAT/firewall mapping open when
                // there is no organic traffic. `last_sent` is postponed by
                // any data packet we send to the peer (see the TUN→net path
                // below), so we only emit a keepalive after `keepalive` of
                // true silence. If there's no active session yet, send_message
                // returns a Maintenance handshake init instead — we send that,
                // recovering the tunnel after e.g. a server restart.
                let now = Instant::now();
                for p in peer_rt.iter_mut().filter(|p| {
                    p.keepalive
                        .is_some_and(|interval| now.duration_since(p.last_sent) >= interval)
                }) {
                    send_keepalive(&mut sessions, p.id, &endpoint).await;
                    p.last_sent = now;
                }
            },
            res = endpoint.recv_buf_from(&mut ep_buf) => {
                let (_, addr) = res?;

                let ep_buf = ep_buf.filled_mut();
                match handle_extern(&mut sessions, &peer_net, addr, ep_buf).await {
                    Write::Inbound(data) => {
                        dev.write_all(data).await?;
                    }
                    Write::Outbound(data, _) => {
                        // Handshake reply produced by the responder path.
                        if let Err(e) = endpoint.send_to(&data[..data.len()], addr).await {
                            eprintln!("send_to {addr} failed: {e}");
                            guard = spawn_blocking(move || {
                                recheck_routes(&mut guard.added_routes);
                                guard
                            }).await?;
                        }
                    }
                    Write::None => {}
                }
            }
            res = dev.read_buf(&mut tun_reply_buf) => {
                let filled = TUN_BUF_START + res?;
                if let Write::Outbound(data, dst) =
                    handle_intern(&mut sessions, &peer_net, &mut tun_buffer, filled).await
                {
                    if let Err(e) = endpoint.send_to(data, dst).await {
                        eprintln!("send_to {dst} failed: {e}");
                        guard = spawn_blocking(move || {
                            recheck_routes(&mut guard.added_routes);
                            guard
                        }).await?;
                    } else if let Some(&i) = endpoint_to_idx.get(&dst) {
                        // A real packet went to this peer's endpoint — postpone
                        // its persistent keepalive. Falls through harmlessly if
                        // the peer has roamed away from its configured endpoint
                        // (worst case: one redundant keepalive).
                        peer_rt[i].last_sent = Instant::now();
                    }
                }
                // handle_intern never produces Inbound (it always
                // wraps a TUN-read packet for outbound transmission).
            }
        }
    };

    // Cleanup is handled by `guard`'s Drop
    result
}

/// Send a keepalive (empty-payload data packet) to `peer_id`. If no active
/// transport session exists yet, the underlying `async_send_message` returns
/// a `Maintenance(handshake_init)` instead — we forward that, which kicks
/// off a fresh handshake. Either case advances the tunnel's liveness.
async fn send_keepalive<O>(sessions: &mut Sessions<O>, peer_id: PeerId, socket: &UdpSocket)
where
    O: AsyncDhOracle + Send,
{
    // Wire layout for a keepalive: [DataHeader (16) | payload (0) | tag (16)].
    const HEADER: usize = std::mem::size_of::<DataHeader>();
    const TAG: usize = 16;
    let mut buf = [0u8; HEADER + TAG];

    // Pass a zero-length subslice as the payload slot. encrypt_message
    // produces a 0-byte ciphertext + 16-byte tag; frame_in_place then writes
    // the header at [0..HEADER] and the tag at [HEADER..HEADER+TAG].
    let payload_slot = &mut buf[HEADER..HEADER];
    match sessions.send_message(peer_id, payload_slot).await {
        Ok(SendMessage::Data(ep, metadata)) => {
            metadata.frame_in_place(&mut buf);
            if let Err(e) = socket.send_to(&buf, ep).await {
                eprintln!("keepalive to {ep} failed: {e}");
            }
        }
        Ok(SendMessage::Maintenance(msg)) => {
            if let Err(e) = socket.send_to(msg.data(), msg.to()).await {
                eprintln!("keepalive handshake to {} failed: {e}", msg.to());
            }
        }
        Err(_) => {
            // No endpoint configured, or peer rejected — nothing to do.
        }
    }
}
