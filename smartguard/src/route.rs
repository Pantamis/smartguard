//! Route management for the WireGuard tunnel.
//!
//! Sets up AllowedIPs routes via the TUN interface and cleans them up on
//! shutdown. For catch-all (0.0.0.0/0) routes, splits into /1 routes and
//! adds endpoint bypass routes to prevent routing loops.

use std::net::SocketAddr;

use iptrie::Ipv4Prefix;

pub enum AddedRoute {
    /// route add -net <prefix> -interface <tun>
    Net { prefix: String, tun_name: String },
    /// route add -host <ip> (via gateway or interface, cleaned up by host)
    Host { ip: String },
}

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

/// Set up routes for AllowedIPs via the TUN interface.
///
/// For `0.0.0.0/0`: adds 0.0.0.0/1 + 128.0.0.0/1 via TUN (covers all IPs,
/// more specific than the default route), plus a host route for each peer
/// endpoint IP via the original outgoing interface (so WireGuard UDP traffic
/// bypasses the TUN).
pub fn setup_routes(
    tun_name: &str,
    allowed_ips: &[Ipv4Prefix],
    peer_endpoints: &[Option<SocketAddr>],
) -> Vec<AddedRoute> {
    let mut routes = Vec::new();
    let has_catchall = allowed_ips.iter().any(|p| format!("{p}") == "0.0.0.0/0");

    // Step 1: For catch-all, add endpoint bypass routes FIRST (before /1 routes)
    // so that `route -n get` sees the original routing table.
    if has_catchall {
        for ep in peer_endpoints {
            if let Some(addr) = ep {
                let ip = addr.ip().to_string();
                if let Some(info) = get_route_info(&ip) {
                    let added = if let Some(ref gw) = info.gateway {
                        route_cmd(&["-n", "add", "-host", &ip, "-gateway", gw])
                    } else if let Some(ref iface) = info.interface {
                        route_cmd(&["-n", "add", "-host", &ip, "-interface", iface])
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
                        routes.push(AddedRoute::Host { ip: ip.clone() });
                    }
                } else {
                    eprintln!("Warning: could not determine route for endpoint {ip}");
                }
            }
        }
    }

    // Step 2: Add TUN routes for AllowedIPs.
    for prefix in allowed_ips {
        let prefix_str = format!("{prefix}");
        if prefix_str == "0.0.0.0/0" {
            for half in &["0.0.0.0/1", "128.0.0.0/1"] {
                if route_cmd(&["-n", "add", "-net", half, "-interface", tun_name]) {
                    eprintln!("Route added: {half} via {tun_name}");
                    routes.push(AddedRoute::Net {
                        prefix: half.to_string(),
                        tun_name: tun_name.to_string(),
                    });
                }
            }
        } else if route_cmd(&["-n", "add", "-net", &prefix_str, "-interface", tun_name]) {
            eprintln!("Route added: {prefix_str} via {tun_name}");
            routes.push(AddedRoute::Net {
                prefix: prefix_str,
                tun_name: tun_name.to_string(),
            });
        }
    }

    routes
}

pub fn cleanup_routes(routes: &[AddedRoute]) {
    for r in routes {
        match r {
            AddedRoute::Net { prefix, tun_name } => {
                let _ = route_cmd(&["-n", "delete", "-net", prefix, "-interface", tun_name]);
                eprintln!("Route removed: {prefix}");
            }
            AddedRoute::Host { ip } => {
                let _ = route_cmd(&["-n", "delete", "-host", ip]);
                eprintln!("Route removed: {ip}");
            }
        }
    }
}

struct RouteInfo {
    gateway: Option<String>,
    interface: Option<String>,
}

/// Use `route -n get <ip>` to find the current gateway and interface for an IP.
/// Must be called BEFORE adding catch-all TUN routes.
fn get_route_info(ip: &str) -> Option<RouteInfo> {
    let output = std::process::Command::new("route")
        .args(["-n", "get", ip])
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
