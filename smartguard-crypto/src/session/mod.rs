//! Dual-stack peer-routing table (platform-agnostic).
//!
//! The packet-framing glue (`handle_extern`/`handle_intern`) is platform
//! specific and lives under `desktop/` (macOS/Linux) and in the mobile crate
//! (Android); only the routing table is shared, so it lives here.

mod peer_net;

pub use peer_net::{PeerNet, PeerNetBuilder};
