//! Desktop-only (macOS / Linux) code.
//!
//! **Every file in this module is platform-dependent.** Its submodules pull in
//! transports that don't build for Android — `card-backend-pcsc` (PC/SC) and
//! `rustyguard-tun` (TUN framing). The whole module is gated at its declaration
//! in `lib.rs` with `#[cfg(not(target_os = "android"))]`, so platform-specific
//! code lives *only* here; everything elsewhere in the crate is
//! platform-agnostic (the card thread, `ApduBackend`, sessions, peer routing).
//!
//! The Android counterparts live in the `smartguard-mobile` crate (a JNI/USB
//! card transport and a raw-IP data plane).

mod handle;
mod pcsc;

pub use handle::{handle_extern, handle_intern};
pub use pcsc::{CardInfo, list_cards, pcsc_opener};
