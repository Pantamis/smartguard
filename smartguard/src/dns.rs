//! System resolver management for the WireGuard tunnel.
//!
//! Mirrors wg-quick's behaviour: while the tunnel is up the configured DNS
//! servers replace the system resolver, and on shutdown the previous state
//! is restored. Privileged — requires the same root we already need for TUN
//! and route management.

use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

/// Handle returned by [`apply_dns`]. Pass to [`cleanup_dns`] on shutdown.
pub struct AppliedDns {
    tun_name: String,
}

/// Install `dns_servers` as the system resolver. Returns `None` and is a
/// no-op when the list is empty so callers can unconditionally apply.
pub fn apply_dns(tun_name: &str, dns_servers: &[IpAddr]) -> Option<AppliedDns> {
    if dns_servers.is_empty() {
        return None;
    }

    #[cfg(target_os = "macos")]
    let ok = apply_macos(tun_name, dns_servers);

    #[cfg(target_os = "linux")]
    let ok = apply_linux(tun_name, dns_servers);

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let ok = {
        eprintln!("DNS configuration not supported on this platform");
        false
    };

    if ok {
        let list = dns_servers
            .iter()
            .map(IpAddr::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!("DNS set to {list}");
        Some(AppliedDns {
            tun_name: tun_name.to_string(),
        })
    } else {
        None
    }
}

pub fn cleanup_dns(applied: &AppliedDns) {
    #[cfg(target_os = "macos")]
    cleanup_macos(&applied.tun_name);

    #[cfg(target_os = "linux")]
    cleanup_linux(&applied.tun_name);

    eprintln!("DNS restored");
}

/// Writes `State:/Network/Service/<utun>/DNS` via scutil. Adds
/// `SupplementalMatchDomains: [""]` to mirror what `NEDNSSettings.matchDomains
/// = [""]` produces in the macOS WireGuard app — without it, configd registers
/// the entry as scope-only (visible in `scutil --dns` under "DNS configuration
/// (for scoped queries)" but not the global section), so normal lookups
/// bypass the tunnel resolver. The empty-string match makes this resolver
/// apply to every query as a supplemental, which is what we want for "all DNS
/// goes through the tunnel". wg-quick.bash omits this and is therefore flaky
/// on configurations where utun isn't in the service order.
#[cfg(target_os = "macos")]
fn apply_macos(tun_name: &str, dns_servers: &[IpAddr]) -> bool {
    let mut script = String::new();
    script.push_str("open\n");
    script.push_str("d.init\n");
    script.push_str("d.add ServerAddresses *");
    for ip in dns_servers {
        script.push(' ');
        script.push_str(&ip.to_string());
    }
    script.push('\n');
    // [""] = match every domain. scutil parses "" as an empty-string token.
    script.push_str("d.add SupplementalMatchDomains * \"\"\n");
    // Empty SearchDomains so previous search domains don't leak through the
    // tunnel resolver.
    script.push_str("d.add SearchDomains *\n");
    script.push_str(&format!("set State:/Network/Service/{tun_name}/DNS\n"));
    script.push_str("quit\n");
    run_scutil(&script)
}

#[cfg(target_os = "macos")]
fn cleanup_macos(tun_name: &str) {
    let script = format!("open\nremove State:/Network/Service/{tun_name}/DNS\nquit\n");
    let _ = run_scutil(&script);
}

#[cfg(target_os = "macos")]
fn run_scutil(script: &str) -> bool {
    let mut child = match Command::new("scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  scutil spawn failed: {e}");
            return false;
        }
    };
    if let Some(stdin) = child.stdin.as_mut() {
        if let Err(e) = stdin.write_all(script.as_bytes()) {
            eprintln!("  scutil write failed: {e}");
            let _ = child.kill();
            let _ = child.wait();
            return false;
        }
    }
    match child.wait() {
        Ok(s) if s.success() => true,
        Ok(s) => {
            eprintln!("  scutil exited with status {s}");
            false
        }
        Err(e) => {
            eprintln!("  scutil wait failed: {e}");
            false
        }
    }
}

/// On Linux we shell out to `resolvconf` (openresolv or the systemd-resolved
/// shim) — same approach as wg-quick. The interface tag `tun.<name>` is the
/// convention wg-quick uses, with `-m 0` priority and `-x` to mark it as
/// exclusive (replaces other resolvers).
#[cfg(target_os = "linux")]
fn apply_linux(tun_name: &str, dns_servers: &[IpAddr]) -> bool {
    let iface_id = format!("tun.{tun_name}");
    let mut child = match Command::new("resolvconf")
        .args(["-a", &iface_id, "-m", "0", "-x"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  resolvconf spawn failed ({e}); install openresolv or systemd-resolved");
            return false;
        }
    };
    if let Some(stdin) = child.stdin.as_mut() {
        let mut buf = String::new();
        for ip in dns_servers {
            buf.push_str(&format!("nameserver {ip}\n"));
        }
        if let Err(e) = stdin.write_all(buf.as_bytes()) {
            eprintln!("  resolvconf write failed: {e}");
            let _ = child.kill();
            let _ = child.wait();
            return false;
        }
    }
    match child.wait() {
        Ok(s) if s.success() => true,
        Ok(s) => {
            eprintln!("  resolvconf exited with status {s}");
            false
        }
        Err(e) => {
            eprintln!("  resolvconf wait failed: {e}");
            false
        }
    }
}

#[cfg(target_os = "linux")]
fn cleanup_linux(tun_name: &str) {
    let iface_id = format!("tun.{tun_name}");
    let _ = Command::new("resolvconf")
        .args(["-d", &iface_id, "-f"])
        .status();
}
