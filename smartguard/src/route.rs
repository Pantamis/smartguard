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
//! - **Blackhole** — `/1`-half drop routes installed for an address family
//!   that the interface isn't configured for. Mirrors wireguard-apple's
//!   implicit kill-switch behavior (it always sets both `ipv4Settings` and
//!   `ipv6Settings`; an empty family blackholes that family at the OS
//!   level). For us the same effect comes from the routing table.

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
    /// route add -inet[6] -host <ip> (via gateway or interface)
    Host { ip: String, family: Family },
    /// Drop route for an unconfigured family — `route -blackhole` on macOS,
    /// `ip route add blackhole` on Linux.
    Blackhole { prefix: String, family: Family },
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

#[cfg(target_os = "macos")]
fn add_blackhole(prefix: &str, family: Family) -> Option<AddedRoute> {
    // BSD route: -blackhole is a flag on the route itself; you still need a
    // target, so we point at lo0 (the kernel will drop instead of looping).
    if route_cmd(&[
        "-n",
        "add",
        family.route_flag(),
        "-net",
        prefix,
        "-blackhole",
        "-interface",
        "lo0",
    ]) {
        eprintln!("Blackhole {family:?}: {prefix}");
        Some(AddedRoute::Blackhole {
            prefix: prefix.to_string(),
            family,
        })
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn add_blackhole(prefix: &str, family: Family) -> Option<AddedRoute> {
    // Linux has a first-class blackhole route type — no interface needed.
    let status = std::process::Command::new("ip")
        .args(["route", "add", "blackhole", prefix])
        .status();
    match status {
        Ok(s) if s.success() => {
            eprintln!("Blackhole {family:?}: {prefix}");
            Some(AddedRoute::Blackhole {
                prefix: prefix.to_string(),
                family,
            })
        }
        _ => None,
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn add_blackhole(_prefix: &str, _family: Family) -> Option<AddedRoute> {
    eprintln!("Blackhole routes not supported on this platform");
    None
}

#[cfg(target_os = "linux")]
fn remove_blackhole(prefix: &str, _family: Family) {
    let _ = std::process::Command::new("ip")
        .args(["route", "del", "blackhole", prefix])
        .status();
}

#[cfg(not(target_os = "linux"))]
fn remove_blackhole(prefix: &str, family: Family) {
    let _ = route_cmd(&["-n", "delete", family.route_flag(), "-net", prefix]);
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
fn install_endpoint_bypass(
    peer_endpoints: &[Option<SocketAddr>],
    family: Family,
) -> Vec<AddedRoute> {
    let mut routes = Vec::new();
    for ep in peer_endpoints.iter().flatten() {
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
    peer_endpoints: &[Option<SocketAddr>],
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

/// Install blackhole `/1` halves for `family`, plus an endpoint bypass for
/// any peer endpoint of that family — without the bypass we'd cut off our
/// own WG underlay UDP if the WG endpoint happens to use the blackholed
/// family. Use when the interface has no address of `family`.
pub fn setup_blackhole(
    family: Family,
    peer_endpoints: &[Option<SocketAddr>],
) -> Vec<AddedRoute> {
    // Endpoint bypass + exemption passthroughs first — both need the
    // original routing table to discover gateways before we install the
    // blackhole halves on top.
    let mut routes = install_endpoint_bypass(peer_endpoints, family);
    routes.extend(install_passthroughs(family));

    // For v6, blackhole the IANA global-unicast allocation (2000::/3) AND
    // every /3 reserved for *future* global-unicast assignment. None of
    // these /3s touch link-local (fe80::/10), multicast (ff00::/8), ULA
    // (fc00::/7), or loopback (::1) — they're all in `f000::/4` or below
    // — so we get defense-in-depth against future IANA expansions without
    // re-introducing the "wants to access local network" prompt that
    // killed the broader `::/1` + `8000::/1` approach.
    //
    // Deliberately *not* blackholed: `e000::/4`, `f000::/5`, `f800::/6`,
    // `0000::/3` — covering these would force explicit pass-throughs for
    // `fc00::/7` / `fe80::/10` / `ff00::/8` / `::1`, which is what broke
    // local v6 networking last time we tried.
    //
    // For v4 we still split by halves; the equivalent surgical approach
    // would have to re-enumerate RFC1918 / link-local / multicast / loopback
    // exceptions. That's only relevant if the interface is v6-only (the
    // current underlay is v4 UDP, so v4 blackhole is dormant in practice).
    let prefixes: &[&str] = match family {
        Family::V4 => &["0.0.0.0/1", "128.0.0.0/1"],
        Family::V6 => &[
            "2000::/3", // current global unicast
            "4000::/3", // reserved for future global unicast (RFC 4291)
            "6000::/3",
            "8000::/3",
            "a000::/3",
            "c000::/3",
        ],
    };
    for prefix in prefixes {
        if let Some(r) = add_blackhole(prefix, family) {
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
            AddedRoute::Host { ip, family } => {
                let _ = route_cmd(&["-n", "delete", family.route_flag(), "-host", ip]);
                eprintln!("Route removed: {ip}");
            }
            AddedRoute::Blackhole { prefix, family } => {
                remove_blackhole(prefix, *family);
                eprintln!("Blackhole removed: {prefix}");
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
