//! Dual-stack peer routing table for cryptokey routing.
//!
//! Both address families use iptrie's longest-prefix-match LC-Trie (since
//! 0.11 the v6 variant is available alongside v4), with the standard build
//! pattern: insert into a radix trie carrying a sentinel root, then
//! compress into the final LC-Trie. Lookup is O(log n) for both families,
//! and the sentinel root means lookups for unmatched IPs return the
//! configured `PeerId::sentinal()` rather than `Option<&PeerId>`.

use std::net::IpAddr;

use ipnet::IpNet;
use iptrie::{Ipv4LCTrieMap, Ipv4Prefix, Ipv4RTrieMap, Ipv6LCTrieMap, Ipv6Prefix, Ipv6RTrieMap};
use rustyguard_core::PeerId;

/// Dual-stack peer lookup table. Construct via [`PeerNetBuilder`].
pub struct PeerNet {
    v4: Ipv4LCTrieMap<PeerId>,
    v6: Ipv6LCTrieMap<PeerId>,
}

impl PeerNet {
    /// Look up the peer that owns `ip`. Returns the configured sentinel
    /// (typically `PeerId::sentinal()`) when no AllowedIP prefix matches —
    /// the sentinel sits at the trie root in both families.
    pub fn lookup(&self, ip: IpAddr) -> PeerId {
        match ip {
            IpAddr::V4(v4) => *self.v4.lookup(&v4).1,
            IpAddr::V6(v6) => *self.v6.lookup(&v6).1,
        }
    }
}

pub struct PeerNetBuilder {
    v4: Ipv4RTrieMap<PeerId>,
    v6: Ipv6RTrieMap<PeerId>,
}

impl PeerNetBuilder {
    pub fn new(sentinel: PeerId) -> Self {
        Self {
            v4: Ipv4RTrieMap::with_root(sentinel),
            v6: Ipv6RTrieMap::with_root(sentinel),
        }
    }

    pub fn insert(&mut self, prefix: IpNet, id: PeerId) {
        // ipnet → iptrie prefix via Display/FromStr round-trip. Both crates
        // use the standard "addr/len" format so the round-trip is total,
        // and it avoids depending on iptrie's private constructor surface.
        match prefix {
            IpNet::V4(p) => {
                let prefix: Ipv4Prefix = p
                    .to_string()
                    .parse()
                    .expect("Ipv4Net Display always produces a valid Ipv4Prefix");
                self.v4.insert(prefix, id);
            }
            IpNet::V6(p) => {
                let prefix: Ipv6Prefix = p
                    .to_string()
                    .parse()
                    .expect("Ipv6Net Display always produces a valid Ipv6Prefix");
                self.v6.insert(prefix, id);
            }
        }
    }

    pub fn build(self) -> PeerNet {
        PeerNet {
            v4: self.v4.compress(),
            v6: self.v6.compress(),
        }
    }
}
