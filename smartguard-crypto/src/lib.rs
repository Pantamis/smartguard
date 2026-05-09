//! Smartcard-backed `DhOracle` for rustyguard, plus high-level helpers
//! for building a WireGuard session manager.
//!
//! `CardHandle` directly implements `DhOracle` from `rustyguard-crypto`, so
//! you can pass `&card_handle` anywhere the handshake/Sessions API expects an
//! oracle — symmetric with passing `&static_private_key` for software mode.
//!
//! There's no `SmartcardCrypto` wrapper type, no sentinel keys, no thread-locals:
//! the card *is* the oracle.

mod card;

use std::net::SocketAddr;

use iptrie::{Ipv4LCTrieMap, Ipv4Prefix, Ipv4RTrieMap};
use rand::{TryRngCore, rngs::OsRng};
use rustyguard_core::{Config, PeerId, Sessions};
use rustyguard_crypto::StaticPeerConfig;

pub use card::{CardHandle, CardInfo, SmartcardError, list_cards};
pub use rustyguard_crypto::{
    CryptoCore, CryptoError, CryptoPrimatives, DhOracle, EphemeralPrivateKey, Key, Mac, PublicKey,
    StaticPrivateKey,
};

/// Build a WireGuard session manager and AllowedIPs routing table.
///
/// `oracle` owns our static private key — pass a `StaticPrivateKey` by value
/// for software mode or a `CardHandle` by value for smartcard mode (both
/// impl `DhOracle`). The oracle is moved into `Sessions` so it lives for as
/// long as the tunnel.
pub fn build_sessions<O: DhOracle>(
    oracle: O,
    peers: &[(
        PublicKey,
        Option<[u8; 32]>,
        Option<SocketAddr>,
        Vec<Ipv4Prefix>,
    )],
) -> (Sessions<O>, Ipv4LCTrieMap<PeerId>, Vec<PeerId>) {
    let mut config = Config::from_oracle(oracle);
    let mut peer_ids = Vec::new();

    let mut peer_net = Ipv4RTrieMap::with_root(PeerId::sentinal());
    for (peer_pk, psk, endpoint, allowed_ips) in peers {
        let id = config.insert_peer(StaticPeerConfig::new(PublicKey(peer_pk.0), *psk, *endpoint));
        peer_ids.push(id);

        for prefix in allowed_ips {
            peer_net.insert(*prefix, id);
        }
    }
    let peer_net = peer_net.compress();

    let sessions = Sessions::new_with(config, &mut OsRng.unwrap_err());
    (sessions, peer_net, peer_ids)
}
