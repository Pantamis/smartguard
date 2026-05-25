//! Route management for the WireGuard tunnel.
//!
//! Three kinds of route lifecycle here, all reversed by `cleanup_routes`:
//!
//! - **Tunnel routes** — AllowedIPs prefixes pointed at the TUN interface.
//!   Catch-all (`/0`) gets split into the two `/1` halves so the system
//!   default route is preserved underneath.
//! - **Endpoint bypass** — host routes for each peer endpoint via the
//!   original outgoing interface, so WireGuard's UDP traffic doesn't loop
//!   back through the tunnel.
//! - **Unconfigured-family catch-all** — for an address family the TUN has
//!   no address of, the `/1` halves are still pointed at our utun. Packets
//!   dead-end (no usable source address on utun for that family), giving
//!   the same no-leak effect as a hard blackhole but with a softer
//!   framework-level signal: NEPacketTunnelProvider-based apps (Tailscale
//!   et al.) can still claim those destinations through their own NEVPN
//!   tunnel for bootstrap traffic. A literal `-blackhole` would tell
//!   Network.framework the destination is permanently unreachable and
//!   break that.

use std::net::{IpAddr, SocketAddr};

use ipnet::IpNet;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    fn route_flag(self) -> &'static str {
        match self {
            Family::V4 => "-inet",
            Family::V6 => "-inet6",
        }
    }
}

pub enum AddedRoute {
    /// route add -inet[6] -net <prefix> -interface <tun>
    Net {
        prefix: String,
        tun_name: String,
        family: Family,
    },
    /// route add -inet[6] -host <ip> (via gateway or interface).
    /// `gateway` is the discovered default-route gateway at install time;
    /// stored so `recheck_routes` can detect a network change (laptop moved
    /// between Wi-Fi networks, etc.) and replace the stale bypass. `None`
    /// means the original install used `-interface` (no gateway available
    /// at the time); we don't track / refresh interface-based bypasses.
    Host {
        ip: String,
        family: Family,
        gateway: Option<String>,
    },
    /// Pass-through route for a non-routable prefix that we want to *avoid*
    /// blackholing (e.g. RFC1918, CGNAT). Points at the discovered default
    /// gateway so traffic to these ranges falls through to whatever the
    /// kernel would have done before the blackhole — typically dropped at
    /// the gateway, but if the user has a more-specific route (corporate
    /// VPN, Tailscale, etc.) it'll win on longest-prefix-match.
    Passthrough { prefix: String, family: Family },
}

/// IPv4 prefixes to exempt from the blackhole. Each gets a pass-through
/// installed pointing at the original default gateway so kernel routing
/// behaves "as before the blackhole" for these ranges.
///
/// Things deliberately *not* listed: 127.0.0.0/8, 169.254.0.0/16,
/// 224.0.0.0/4, 240.0.0.0/4, the user's on-link subnet — the kernel already
/// has more-specific routes for them from interface setup, and longest-
/// prefix-match means our /1 blackhole halves never override them.
const V4_BLACKHOLE_EXEMPTIONS: &[&str] = &[
    "10.0.0.0/8",     // RFC1918
    "100.64.0.0/10",  // CGNAT (Tailscale, Mullvad internal, etc.)
    "172.16.0.0/12",  // RFC1918
    "192.168.0.0/16", // RFC1918
];

/// IPv6 needs no exemptions: the blackhole targets only `2000::/3` (IANA
/// global-unicast allocation), and everything we'd want to spare —
/// `fc00::/7` ULA, `fe80::/10` link-local, `ff00::/8` multicast, `::1`
/// loopback — sits outside that prefix so it's automatically untouched.
const V6_BLACKHOLE_EXEMPTIONS: &[&str] = &[];

fn route_cmd(args: &[&str]) -> bool {
    let out = std::process::Command::new("route").args(args).output();
    match out {
        Ok(o) => {
            if !o.status.success() {
                let stderr = String::from_utf8_lossy(&o.stderr);
                eprintln!("  route {} => {}", args.join(" "), stderr.trim());
            }
            o.status.success()
        }
        Err(e) => {
            eprintln!("  route cmd failed: {e}");
            false
        }
    }
}

fn add_net(tun_name: &str, prefix: &str, family: Family) -> Option<AddedRoute> {
    if route_cmd(&[
        "-n",
        "add",
        family.route_flag(),
        "-net",
        prefix,
        "-interface",
        tun_name,
    ]) {
        eprintln!("Route added: {prefix} via {tun_name}");
        Some(AddedRoute::Net {
            prefix: prefix.to_string(),
            tun_name: tun_name.to_string(),
            family,
        })
    } else {
        None
    }
}

/// Install pass-through routes for the family's blackhole exemption list,
/// pointing each prefix at the family's default gateway. We discover the
/// gateway by asking `route -n get` for a known public IP — it returns the
/// gateway of the *original* default route, since at this point we haven't
/// touched the routing table for `family` yet.
fn install_passthroughs(family: Family) -> Vec<AddedRoute> {
    let exemptions = match family {
        Family::V4 => V4_BLACKHOLE_EXEMPTIONS,
        Family::V6 => V6_BLACKHOLE_EXEMPTIONS,
    };
    if exemptions.is_empty() {
        return Vec::new();
    }
    // Probe with a known public address — for v4, `1.1.1.1`; for v6,
    // Cloudflare's public resolver. The kernel resolves these to the
    // current default route, giving us the gateway we want.
    let probe = match family {
        Family::V4 => "1.1.1.1",
        Family::V6 => "2606:4700:4700::1111",
    };
    let Some(info) = get_route_info(probe, family) else {
        eprintln!("Warning: could not discover {family:?} default gateway; skipping passthroughs");
        return Vec::new();
    };

    let mut routes = Vec::new();
    for prefix in exemptions {
        let added = if let Some(ref gw) = info.gateway {
            route_cmd(&[
                "-n",
                "add",
                family.route_flag(),
                "-net",
                prefix,
                "-gateway",
                gw,
            ])
        } else if let Some(ref iface) = info.interface {
            route_cmd(&[
                "-n",
                "add",
                family.route_flag(),
                "-net",
                prefix,
                "-interface",
                iface,
            ])
        } else {
            false
        };
        if added {
            let via = info
                .gateway
                .as_deref()
                .or(info.interface.as_deref())
                .unwrap_or("?");
            eprintln!("Passthrough {family:?}: {prefix} via {via}");
            routes.push(AddedRoute::Passthrough {
                prefix: prefix.to_string(),
                family,
            });
        }
    }
    routes
}

/// Install host-route bypass for each peer endpoint of `family`. Used by
/// any rule that would otherwise capture the WireGuard underlay UDP itself
/// (catch-all routes, blackhole routes).
fn install_endpoint_bypass(peer_endpoints: &[SocketAddr], family: Family) -> Vec<AddedRoute> {
    let mut routes = Vec::new();
    for ep in peer_endpoints.iter() {
        let ep_family = match ep.ip() {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        };
        if ep_family != family {
            continue;
        }
        let ip = ep.ip().to_string();
        let Some(info) = get_route_info(&ip, family) else {
            eprintln!("Warning: could not determine route for endpoint {ip}");
            continue;
        };
        let added = if let Some(ref gw) = info.gateway {
            route_cmd(&[
                "-n",
                "add",
                family.route_flag(),
                "-host",
                &ip,
                "-gateway",
                gw,
            ])
        } else if let Some(ref iface) = info.interface {
            route_cmd(&[
                "-n",
                "add",
                family.route_flag(),
                "-host",
                &ip,
                "-interface",
                iface,
            ])
        } else {
            false
        };
        if added {
            let via = info
                .gateway
                .as_deref()
                .or(info.interface.as_deref())
                .unwrap_or("?");
            eprintln!("Endpoint bypass: {ip} via {via}");
            routes.push(AddedRoute::Host {
                ip: ip.clone(),
                family,
                // Remember the gateway we routed through so a later
                // `recheck_routes` can compare it against the *current*
                // default and rebuild the bypass when the laptop moves
                // between networks. Interface-based bypasses (no
                // gateway) don't get tracked.
                gateway: info.gateway.clone(),
            });
        }
    }
    routes
}

/// Set up routes for AllowedIPs via the TUN interface.
///
/// For `0.0.0.0/0` / `::/0`: adds the two `/1` halves via TUN (covers all
/// addresses, more specific than the default route), plus a host route for
/// each peer endpoint via the original outgoing interface so the WG UDP
/// packets bypass the tunnel.
pub fn setup_routes(
    tun_name: &str,
    allowed_ips: &[IpNet],
    peer_endpoints: &[SocketAddr],
) -> Vec<AddedRoute> {
    let mut routes = Vec::new();

    let has_catchall_v4 = allowed_ips
        .iter()
        .any(|n| matches!(n, IpNet::V4(p) if p.prefix_len() == 0));
    let has_catchall_v6 = allowed_ips
        .iter()
        .any(|n| matches!(n, IpNet::V6(p) if p.prefix_len() == 0));

    // Step 1: endpoint bypass routes BEFORE catch-alls so `route -n get` sees
    // the original routing table.
    if has_catchall_v4 {
        routes.extend(install_endpoint_bypass(peer_endpoints, Family::V4));
    }
    if has_catchall_v6 {
        routes.extend(install_endpoint_bypass(peer_endpoints, Family::V6));
    }

    // Step 2: TUN routes for AllowedIPs.
    for net in allowed_ips {
        match net {
            IpNet::V4(p) if p.prefix_len() == 0 => {
                for half in ["0.0.0.0/1", "128.0.0.0/1"] {
                    if let Some(r) = add_net(tun_name, half, Family::V4) {
                        routes.push(r);
                    }
                }
            }
            IpNet::V6(p) if p.prefix_len() == 0 => {
                for half in ["::/1", "8000::/1"] {
                    if let Some(r) = add_net(tun_name, half, Family::V6) {
                        routes.push(r);
                    }
                }
            }
            IpNet::V4(_) => {
                let s = net.to_string();
                if let Some(r) = add_net(tun_name, &s, Family::V4) {
                    routes.push(r);
                }
            }
            IpNet::V6(_) => {
                let s = net.to_string();
                if let Some(r) = add_net(tun_name, &s, Family::V6) {
                    routes.push(r);
                }
            }
        }
    }

    routes
}

/// For an address family the TUN has no address of, route the family's
/// `/1` halves *into our utun* rather than installing a hard blackhole.
///
/// The packets effectively dead-end: the kernel forwards them to our utun,
/// fails to pick a usable source address (utun has no global address of
/// this family, only link-local), and drops them with `EADDRNOTAVAIL`.
/// Net effect for raw socket users is the same as a blackhole — no leak.
///
/// The reason we route to utun instead of hard-blackholing: NEPacketTunnel-
/// Provider-based apps (Tailscale being the canonical case) use
/// `NWConnection` / `NWPathMonitor`, which consult both NEVPN provider
/// claims *and* the kernel routing table. A hard `-blackhole` entry tells
/// Network.framework "this destination is unreachable" with such finality
/// that even Tailscale's own NEVPN-managed tunnel can't claim it back —
/// breaking Tailscale's IPv6 bootstrap. Routing to our utun is a softer
/// signal: it's just another tunnel claiming the prefix, which NEVPN
/// providers can override for their own apps' traffic.
///
/// We still install endpoint bypass and passthrough routes underneath for
/// the same reason as before: they're more specific than `/1`, so they
/// preserve WG-underlay reachability (bypass) and let RFC1918/CGNAT escape
/// the catch-all (passthrough) when those make sense to keep working.
pub fn setup_unconfigured_family(
    family: Family,
    tun_name: &str,
    peer_endpoints: &[SocketAddr],
) -> Vec<AddedRoute> {
    let mut routes = install_endpoint_bypass(peer_endpoints, family);
    routes.extend(install_passthroughs(family));

    let halves: &[&str] = match family {
        Family::V4 => &["0.0.0.0/1", "128.0.0.0/1"],
        Family::V6 => &["::/1", "8000::/1"],
    };
    for half in halves {
        if let Some(r) = add_net(tun_name, half, family) {
            routes.push(r);
        }
    }
    routes
}

pub fn cleanup_routes(routes: &[AddedRoute]) {
    for r in routes {
        match r {
            AddedRoute::Net {
                prefix,
                tun_name,
                family,
            } => {
                let _ = route_cmd(&[
                    "-n",
                    "delete",
                    family.route_flag(),
                    "-net",
                    prefix,
                    "-interface",
                    tun_name,
                ]);
                eprintln!("Route removed: {prefix}");
            }
            AddedRoute::Host {
                ip,
                family,
                gateway: _,
            } => {
                let _ = route_cmd(&["-n", "delete", family.route_flag(), "-host", ip]);
                eprintln!("Route removed: {ip}");
            }
            AddedRoute::Passthrough { prefix, family } => {
                let _ = route_cmd(&["-n", "delete", family.route_flag(), "-net", prefix]);
                eprintln!("Passthrough removed: {prefix}");
            }
        }
    }
}

struct RouteInfo {
    gateway: Option<String>,
    interface: Option<String>,
}

/// Current default-route gateway for `family`, or `None` if there isn't one
/// (no network connectivity, or kernel has only interface-attached defaults).
/// Asks the kernel via `route -n get -inet[6] default` — that's the literal
/// default-route entry, not a longest-prefix match, so it returns the *real*
/// gateway even when our `/1` catch-all routes are in place above it.
pub fn current_default_gateway(family: Family) -> Option<String> {
    get_route_info("default", family)?.gateway
}

/// Re-evaluate every endpoint-bypass `Host` route in `added_routes` against
/// the current default gateway. If the gateway changed (laptop moved
/// networks while smartguard was running), delete the stale bypass and
/// install a fresh one pointing at whatever's now the default. Bypass
/// routes that were installed without a gateway (interface-mode) are left
/// alone — we don't know what to compare against.
///
/// Two fork/execs of `route` per call (one per family) for the gateway
/// lookup, plus 0–N more for actual updates. Cheap enough to run on the
/// runtime thread; called from `run_tunnel`'s select loop.
pub fn recheck_routes(added_routes: &mut [AddedRoute]) {
    let v4_current = current_default_gateway(Family::V4);
    let v6_current = current_default_gateway(Family::V6);

    for r in added_routes.iter_mut() {
        let AddedRoute::Host {
            ip,
            family,
            gateway: stored,
        } = r
        else {
            continue;
        };
        let current = match family {
            Family::V4 => &v4_current,
            Family::V6 => &v6_current,
        };
        if stored.as_deref() == current.as_deref() {
            continue;
        }
        eprintln!(
            "Endpoint bypass for {ip}: gateway {:?} → {:?}, updating",
            stored, current
        );
        // Delete the stale bypass first.
        let _ = route_cmd(&["-n", "delete", family.route_flag(), "-host", ip]);
        // Install the new one if we have a gateway to point at; otherwise
        // we just leave the bypass torn down until the next recheck finds
        // a default route.
        let installed = match current {
            Some(gw) => route_cmd(&[
                "-n",
                "add",
                family.route_flag(),
                "-host",
                ip,
                "-gateway",
                gw,
            ]),
            None => {
                eprintln!(
                    "  no current {family:?} default; bypass torn down until network returns"
                );
                true
            }
        };
        if installed {
            *stored = current.clone();
        } else {
            eprintln!("  failed to install new bypass for {ip}; will retry");
        }
    }
}

/// Use `route -n get -inet[6] <ip>` to find the current gateway and interface
/// for an IP. Must be called BEFORE adding catch-all / blackhole routes.
fn get_route_info(ip: &str, family: Family) -> Option<RouteInfo> {
    let output = std::process::Command::new("route")
        .args(["-n", "get", family.route_flag(), ip])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut gateway = None;
    let mut interface = None;
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(gw) = line.strip_prefix("gateway:") {
            let gw = gw.trim();
            if !gw.is_empty() {
                gateway = Some(gw.to_string());
            }
        } else if let Some(iface) = line.strip_prefix("interface:") {
            let iface = iface.trim();
            if !iface.is_empty() {
                interface = Some(iface.to_string());
            }
        }
    }
    eprintln!(
        "Route for {ip}: gateway={:?}, interface={:?}",
        gateway, interface
    );
    Some(RouteInfo { gateway, interface })
}
