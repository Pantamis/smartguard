//! High-level tunnel event loop with signal handling and route management.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use ipnet::{IpNet, Ipv6Net};
use rand::{rngs::OsRng, TryRngCore};
use rustyguard_core::{PeerId, Sessions};
use rustyguard_crypto::DhOracle;
use rustyguard_tun::{
    tun::{self, Device as _},
    AlignedPacket, Write, TUN_BUF_START,
};
use smartguard_crypto::{handle_extern, handle_intern, PeerNet};
use tai64::Tai64N;
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt, ReadBuf},
    net::UdpSocket,
    task::spawn_blocking,
    time::{interval, sleep},
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
/// Sessions calls go through `tokio::task::spawn_blocking` because they may
/// trigger smartcard DH operations that block for ~tens-to-hundreds of ms.
/// This tells the tokio runtime "this work is blocking, run it on the
/// blocking pool" — the async worker stays free to drive the reactor and
/// any other tasks.
pub async fn run_tunnel<O>(
    mut sessions: Sessions<O>,
    mut peer_net: PeerNet,
    peer_ids: &[PeerId],
    listen_port: u16,
    tun_addrs: &[IpNet],
    mtu: i32,
    allowed_ips: &[IpNet],
    peer_endpoints: &[Option<SocketAddr>],
    dns_servers: &[IpAddr],
) -> Result<(), Box<dyn std::error::Error>>
where
    O: DhOracle + Send + 'static,
{
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
        added_routes: setup_routes(&tun_name, allowed_ips, peer_endpoints),
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
        guard
            .added_routes
            .extend(setup_unconfigured_family(Family::V4, &tun_name, peer_endpoints));
    }
    if !has_v6 {
        guard
            .added_routes
            .extend(setup_unconfigured_family(Family::V6, &tun_name, peer_endpoints));
    }

    // Replace the system resolver while the tunnel is up (mirrors wg-quick).
    guard.applied_dns = apply_dns(&tun_name, dns_servers);

    // Initiate handshake to all peers with known endpoints at startup.
    for &peer_id in peer_ids {
        let init;
        (sessions, init) = spawn_blocking(move || {
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
            if let Err(e) = endpoint.send_to(msg.data(), addr).await {
                eprintln!("  send_to {addr} failed: {e}");
            }
        }
    }

    let mut tick = interval(Duration::from_secs(1));
    let host_route_idx = guard
        .added_routes
        .iter()
        .position(|r| matches!(r, AddedRoute::Host { .. }))
        .ok_or(io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "Gateway must exist",
        ))?;

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
                (sessions, maintenance_buffer) = spawn_blocking(move || {
                    while let Some(msg) = sessions.turn(Tai64N::now(), &mut OsRng.unwrap_err()) {
                        maintenance_buffer.push(msg);
                    }
                    (sessions, maintenance_buffer)
                })
                .await?;

                if matches!(guard.added_routes[host_route_idx], AddedRoute::Host { gateway: None, ..}) {
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
                (sessions, peer_net, endpoint_buffer, msg_len) = spawn_blocking(move || {
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
                if let Err(e) = endpoint.send_to(&endpoint_buffer.0[..msg_len], addr).await {
                    eprintln!("send_to {addr} failed: {e}");
                    guard = spawn_blocking(move || {
                        recheck_routes(&mut guard.added_routes);
                        guard
                    }).await?;
                }
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
                    if let Err(e) = endpoint.send_to(data, dst).await {
                        eprintln!("send_to {dst} failed: {e}");
                        guard = spawn_blocking(move || {
                            recheck_routes(&mut guard.added_routes);
                            guard
                        }).await?;
                    }
                };
                // handle_intern never produces Inbound (it always
                // wraps a TUN-read packet for outbound transmission).
                // Or produce None so no-op in else case.
            }
        }
    };

    // Cleanup is handled by `guard`'s Drop
    result
}
