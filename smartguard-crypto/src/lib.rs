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
// All macOS/Linux-only code lives here, gated in one place. Everything else in
// the crate is platform-agnostic. The Android counterparts are in the
// `smartguard-mobile` crate.
#[cfg(not(target_os = "android"))]
mod desktop;
pub mod session;
mod thread;
pub mod transport;

use std::net::SocketAddr;
use std::time::Duration;

use ipnet::IpNet;
use rand::{TryRngCore, rngs::OsRng};
use rustyguard_core::{Config, PeerId, Sessions};
use rustyguard_crypto::StaticPeerConfig;

pub use card::{CardHandle, SmartcardError};
pub use transport::{ApduBackend, ApduLink, CardBackendBox, CardOpener};
#[cfg(not(target_os = "android"))]
pub use desktop::{CardInfo, handle_extern, handle_intern, list_cards, pcsc_opener};
pub use rustyguard_crypto::{
    AsyncDhOracle, CryptoCore, CryptoError, CryptoPrimatives, DhOracle, EphemeralPrivateKey, Key,
    Mac, PublicKey, StaticPrivateKey,
};
pub use session::{PeerNet, PeerNetBuilder};

pub struct PeerConfig {
    pub public_key: PublicKey,
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpNet>,
    pub persistent_keepalive: Option<Duration>,
}

/// Build a WireGuard session manager and dual-stack AllowedIPs routing table.
///
/// `oracle` owns our static private key — pass a `StaticPrivateKey` by value
/// for software mode (auto-lifted to `AsyncDhOracle` by the blanket impl) or
/// a `CardHandle` by value for smartcard mode. The oracle is moved into
/// `Sessions` so it lives for as long as the tunnel.
///
/// AllowedIPs accept mixed v4/v6 prefixes; the returned [`PeerNet`] dispatches
/// internally based on address family. The returned `Vec<PeerId>` is aligned
/// with `peers` (input order preserved), so callers can zip the two.
pub async fn build_sessions<O: AsyncDhOracle>(
    oracle: O,
    peers: &[PeerConfig],
) -> (Sessions<O>, PeerNet, Vec<PeerId>) {
    let mut config = Config::from_oracle_async(oracle).await;
    let mut peer_ids = Vec::new();
    let mut builder = PeerNetBuilder::new(PeerId::sentinal());

    for peer in peers {
        let id = config.insert_peer(StaticPeerConfig::new(
            PublicKey(peer.public_key.0),
            peer.preshared_key,
            peer.endpoint,
        ));
        peer_ids.push(id);

        for prefix in &peer.allowed_ips {
            builder.insert(*prefix, id);
        }
    }

    let sessions = Sessions::new_with(config, &mut OsRng.unwrap_err());
    (sessions, builder.build(), peer_ids)
}
