//! Android (JNI) entry points for smartguard.
//!
//! This crate is the mobile app shell's view of smartguard: it builds as a
//! `cdylib` (`libsmartguard_mobile.so`) loaded by an Android `VpnService`, and
//! exposes a thin JNI surface that the Kotlin side calls.
//!
//! The load-bearing piece is the **card transport**: Android has no PC/SC, so
//! the OpenPGP card is reached over CCID-over-USB. [`apdu::JniApduLink`] fills
//! the `smartguard-crypto` transport seam by forwarding APDUs to a Kotlin
//! object (see [`apdu`]); everything above it (handshake, `ss` cache, async DH
//! oracle, session management) is shared verbatim with the desktop build.
//!
//! Uses the `jni` 0.22 native-method model: each entry takes an FFI-safe
//! [`EnvUnowned`], upgrades it via [`EnvUnowned::with_env`] (which scopes the
//! thread attachment and catches panics at the FFI boundary), and resolves the
//! result with an error policy that throws a Java exception on failure.
//!
//! ## JNI surface (class `smartguard.SmartguardNative`)
//!
//! ```text
//! static native long  nativeOpenCard(Object transport, String ident, String pin)
//! static native byte[] nativeCardPublicKey(long cardHandle)
//! static native void  nativeCloseCard(long cardHandle)
//! static native long  nativeStartTunnel(long cardHandle, int tunFd)   // TODO
//! ```
//!
//! `transport` is any object exposing `byte[] transceive(byte[] command)`.
//! Handles are opaque `long`s (raw pointers); Kotlin must call the matching
//! close to free them.

mod apdu;
mod framing;
mod tun;
mod tunnel;

use std::net::SocketAddr;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use base64::Engine;
use ipnet::IpNet;
use jni::objects::{JByteArray, JClass, JObject, JString};
use jni::sys::{jint, jlong};
use jni::{Env, EnvUnowned};
use secrecy::SecretString;
use smartguard_crypto::{AsyncDhOracle, CardHandle, PeerConfig, PublicKey};
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;

use apdu::jni_opener;

/// Error type for the native methods. `with_env` requires `From<jni::Error>`;
/// `ThrowRuntimeExAndDefault` requires `std::error::Error`. `Msg` carries our
/// own (non-JNI) failures — card open, runtime build — into the thrown
/// `RuntimeException` message.
#[derive(Debug)]
enum MobileError {
    Jni(jni::errors::Error),
    Msg(String),
}

impl std::fmt::Display for MobileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MobileError::Jni(e) => write!(f, "{e}"),
            MobileError::Msg(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for MobileError {}

impl From<jni::errors::Error> for MobileError {
    fn from(e: jni::errors::Error) -> Self {
        MobileError::Jni(e)
    }
}

// The opaque `long` handle Kotlin holds is a `Box<CardHandle>` raw pointer.
// Dropping the box drops the request sender, which stops the card thread.
//
// `CardHandle`'s methods are `async`, but the only thing they await is a
// one-shot reply from the card thread — there is no async I/O on this side
// (the real blocking card I/O runs on that thread). So we don't need a tokio
// runtime/reactor: `pollster::block_on` parks the calling JNI thread until the
// one-shot resolves, which is exactly what these synchronous setup calls want.
// (The future tunnel loop in `nativeStartTunnel` is the part that will need a
// real tokio runtime, owned for the duration of that single blocking call.)

/// Open the OpenPGP card over the JNI/USB transport, verify the PIN, and return
/// an opaque handle. On failure a `RuntimeException` is thrown and 0 returned.
///
/// `transport` must expose `byte[] transceive(byte[])`. `ident` is the card
/// identifier or `"auto"`. The returned handle must be released exactly once
/// via [`Java_smartguard_SmartguardNative_nativeCloseCard`].
#[unsafe(no_mangle)]
pub extern "system" fn Java_smartguard_SmartguardNative_nativeOpenCard<'caller>(
    mut unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    transport: JObject<'caller>,
    ident: JString<'caller>,
    pin: JString<'caller>,
) -> jlong {
    unowned
        .with_env(|env: &mut Env| -> Result<jlong, MobileError> {
            let ident: String = ident.to_string();
            let pin: String = pin.to_string();

            let vm = env.get_java_vm()?;
            let object = env.new_global_ref(transport)?;

            let opener = jni_opener(vm, object);

            let card = pollster::block_on(CardHandle::open_with(
                opener,
                &ident,
                SecretString::from(pin),
            ))
            .map_err(|e| MobileError::Msg(format!("open card: {e}")))?;

            Ok(Box::into_raw(Box::new(card)) as jlong)
        })
        .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

/// Return the card's X25519 public key (32 bytes) as a Java `byte[]`. Throws on
/// a null/invalid handle.
#[unsafe(no_mangle)]
pub extern "system" fn Java_smartguard_SmartguardNative_nativeCardPublicKey<'caller>(
    mut unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
) -> JByteArray<'caller> {
    unowned
        .with_env(|env: &mut Env| -> Result<JByteArray, MobileError> {
            if handle == 0 {
                return Err(MobileError::Msg("null card handle".to_owned()));
            }
            // SAFETY: `handle` is a pointer previously returned by
            // `nativeOpenCard` and not yet closed; Kotlin guarantees
            // single-threaded access to one handle.
            let card = unsafe { &mut *(handle as *mut CardHandle) };

            let pk = pollster::block_on(card.async_x25519_pubkey());
            Ok(env.byte_array_from_slice(&pk)?)
        })
        .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

/// Close the card and free the handle. Idempotent for `0`. Makes no JNI calls,
/// so it does not enter `with_env`.
///
/// # Safety
/// `handle` must be a value returned by `nativeOpenCard` that has not already
/// been closed.
#[unsafe(no_mangle)]
pub extern "system" fn Java_smartguard_SmartguardNative_nativeCloseCard<'caller>(
    _unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
) {
    if handle != 0 {
        // SAFETY: reconstruct and drop the box created in `nativeOpenCard`.
        unsafe { drop(Box::from_raw(handle as *mut CardHandle)) };
    }
}

/// Build a single-peer config from the JNI string args.
///
/// Scaffold limitation: one peer (the common client→server case). Multi-peer
/// would take a structured/serialized config instead of flat args.
fn parse_peer(
    public_key_b64: &str,
    endpoint: &str,
    allowed_ips_csv: &str,
    keepalive_seconds: i32,
) -> Result<PeerConfig, MobileError> {
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(public_key_b64.trim())
        .map_err(|e| MobileError::Msg(format!("peer public key base64: {e}")))?;
    let key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| MobileError::Msg("peer public key must be 32 bytes".to_owned()))?;

    let endpoint: SocketAddr = endpoint
        .trim()
        .parse()
        .map_err(|e| MobileError::Msg(format!("peer endpoint: {e}")))?;

    let allowed_ips: Vec<IpNet> = allowed_ips_csv
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<IpNet>())
        .collect::<Result<_, _>>()
        .map_err(|e| MobileError::Msg(format!("peer allowed_ips: {e}")))?;

    Ok(PeerConfig {
        public_key: PublicKey(key),
        preshared_key: None,
        endpoint: Some(endpoint),
        allowed_ips,
        persistent_keepalive: (keepalive_seconds > 0)
            .then(|| Duration::from_secs(keepalive_seconds as u64)),
    })
}

/// Run the WireGuard tunnel until cancelled. **Blocks** for the tunnel's whole
/// lifetime — call it on a dedicated Kotlin thread, never the main thread.
///
/// Opens the card over `transport` (long-lived card thread), then drives the
/// event loop on a current-thread tokio runtime scoped to this call. Returns
/// when `cancelFd` becomes readable (close/write the pipe's other end to stop),
/// dropping the card, sockets, and runtime — cleanup is enforced by `Drop`, no
/// handle to leak.
///
/// All three fds are **adopted** (closed on return): `tunFd` is the
/// `VpnService` descriptor (raw IP); `udpFd` is a socket the app already
/// created and `protect()`ed so its packets bypass the tunnel; `cancelFd` is
/// the read end of a pipe the app keeps the write end of.
///
/// On any error a `RuntimeException` is thrown.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_smartguard_SmartguardNative_nativeRunTunnel<'caller>(
    mut unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    transport: JObject<'caller>,
    ident: JString<'caller>,
    pin: JString<'caller>,
    tun_fd: jint,
    udp_fd: jint,
    cancel_fd: jint,
    peer_public_key: JString<'caller>,
    endpoint: JString<'caller>,
    allowed_ips: JString<'caller>,
    keepalive_seconds: jint,
) {
    unowned
        .with_env(|env: &mut Env| -> Result<(), MobileError> {
            let ident: String = ident.to_string();
            let pin: String = pin.to_string();
            let peer = parse_peer(
                &peer_public_key.to_string(),
                &endpoint.to_string(),
                &allowed_ips.to_string(),
                keepalive_seconds,
            )?;

            let vm = env.get_java_vm()?;
            let object = env.new_global_ref(transport)?;
            let opener = jni_opener(vm, object);

            // A current-thread runtime is enough: the card does its blocking
            // I/O on its own thread; this runtime only drives the reactor for
            // the UDP/TUN fds. Scoped to this call — dropped on return.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| MobileError::Msg(format!("build runtime: {e}")))?;

            rt.block_on(async move {
                let card = CardHandle::open_with(opener, &ident, SecretString::from(pin))
                    .await
                    .map_err(|e| MobileError::Msg(format!("open card: {e}")))?;

                // Adopt the fds inside the runtime so they register with the reactor.
                let udp = adopt_udp(udp_fd).map_err(|e| MobileError::Msg(format!("udp fd: {e}")))?;
                // SAFETY: the app hands over an open, owned TUN descriptor.
                let tun = unsafe { tun::AsyncTun::from_raw_fd(tun_fd) }
                    .map_err(|e| MobileError::Msg(format!("tun fd: {e}")))?;
                let cancel =
                    adopt_cancel(cancel_fd).map_err(|e| MobileError::Msg(format!("cancel fd: {e}")))?;

                tunnel::run_tunnel(card, vec![peer], tun, udp, cancel)
                    .await
                    .map_err(|e| MobileError::Msg(format!("tunnel: {e}")))
            })
        })
        .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

/// Adopt an already-created, `protect()`ed UDP socket fd as a tokio socket.
fn adopt_udp(fd: RawFd) -> std::io::Result<UdpSocket> {
    // SAFETY: the app transfers ownership of a valid bound UDP socket fd.
    let std_udp = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    std_udp.set_nonblocking(true)?;
    UdpSocket::from_std(std_udp)
}

/// Adopt the read end of the cancellation pipe and register it for readiness.
fn adopt_cancel(fd: RawFd) -> std::io::Result<AsyncFd<OwnedFd>> {
    tun::set_nonblocking(fd)?;
    // SAFETY: the app transfers ownership of a valid pipe read-end fd.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    AsyncFd::new(owned)
}
