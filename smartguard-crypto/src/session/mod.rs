//! Dual-stack session management: peer-routing table and the message-handling
//! glue between Sessions, the UDP socket, and the TUN device.
//!
//! Lives here (rather than rustyguard-tun) so `rustyguard-tun` stays a
//! self-contained adapter — peer routing and cryptokey-routing checks are
//! application-level concerns.

mod handle;
mod peer_net;

pub use handle::{handle_extern, handle_intern};
pub use peer_net::{PeerNet, PeerNetBuilder};
