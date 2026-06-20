//! Dual-stack session management: peer-routing table and the message-handling
//! glue between Sessions, the UDP socket, and the TUN device.

mod handle;
mod peer_net;

pub use handle::{handle_extern, handle_intern};
pub use peer_net::{PeerNet, PeerNetBuilder};
