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
//! ## JNI surface (class `am.ito.smartguard.SmartguardNative`)
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

use std::sync::Arc;

use jni::objects::{JByteArray, JClass, JObject, JString};
use jni::sys::{jint, jlong};
use jni::{Env, EnvUnowned};
use secrecy::SecretString;
use smartguard_crypto::{AsyncDhOracle, CardHandle};

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

/// Opaque handle handed back to Kotlin as a `long`. Owns the tokio runtime that
/// drives the async card API and the open [`CardHandle`]; dropping it stops the
/// card thread (the request sender is dropped) and shuts the runtime down.
struct MobileCard {
    rt: tokio::runtime::Runtime,
    card: CardHandle,
}

/// Open the OpenPGP card over the JNI/USB transport, verify the PIN, and return
/// an opaque handle. On failure a `RuntimeException` is thrown and 0 returned.
///
/// `transport` must expose `byte[] transceive(byte[])`. `ident` is the card
/// identifier or `"auto"`. The returned handle must be released exactly once
/// via [`Java_am_ito_smartguard_SmartguardNative_nativeCloseCard`].
#[unsafe(no_mangle)]
pub extern "system" fn Java_am_ito_smartguard_SmartguardNative_nativeOpenCard<'caller>(
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

            let vm = Arc::new(env.get_java_vm()?);
            let transport = Arc::new(env.new_global_ref(transport)?);

            let opener = jni_opener(vm, transport);

            // One worker thread is enough: the card thread does the blocking
            // I/O, the runtime only drives the async oracle plumbing.
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .map_err(|e| MobileError::Msg(format!("build runtime: {e}")))?;

            let card = rt
                .block_on(CardHandle::open_with(opener, &ident, SecretString::from(pin)))
                .map_err(|e| MobileError::Msg(format!("open card: {e}")))?;

            Ok(Box::into_raw(Box::new(MobileCard { rt, card })) as jlong)
        })
        .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

/// Return the card's X25519 public key (32 bytes) as a Java `byte[]`. Throws on
/// a null/invalid handle.
#[unsafe(no_mangle)]
pub extern "system" fn Java_am_ito_smartguard_SmartguardNative_nativeCardPublicKey<'caller>(
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
            let mc = unsafe { &mut *(handle as *mut MobileCard) };

            let pk = mc.rt.block_on(mc.card.async_x25519_pubkey());
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
pub extern "system" fn Java_am_ito_smartguard_SmartguardNative_nativeCloseCard<'caller>(
    _unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
) {
    if handle != 0 {
        // SAFETY: reconstruct and drop the box created in `nativeOpenCard`.
        unsafe { drop(Box::from_raw(handle as *mut MobileCard)) };
    }
}

/// Start the WireGuard tunnel on a `VpnService` file descriptor.
///
/// TODO: not yet implemented. The desktop tunnel loop (`smartguard/src/tunnel.rs`)
/// creates its own TUN device and manages routes/DNS via the OS; on Android
/// those responsibilities move to Kotlin (`VpnService.Builder.addAddress`/
/// `addRoute`/`addDnsServer`), and `tunFd` is the already-established
/// `ParcelFileDescriptor`. The port should:
///   1. Wrap `tunFd` as an async fd (read/write raw IP packets).
///   2. Bind a UDP socket (the VpnService must `protect()` it on the Kotlin side
///      so its packets bypass the tunnel).
///   3. Reuse `smartguard_crypto::build_sessions` + `handle_intern`/`handle_extern`
///      exactly as the desktop loop does, minus the route/DNS management.
#[unsafe(no_mangle)]
pub extern "system" fn Java_am_ito_smartguard_SmartguardNative_nativeStartTunnel<'caller>(
    mut unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    _card_handle: jlong,
    _tun_fd: jint,
) -> jlong {
    unowned
        .with_env(|_env: &mut Env| -> Result<jlong, MobileError> {
            Err(MobileError::Msg(
                "nativeStartTunnel: not yet implemented (see TODO in smartguard-mobile)".to_owned(),
            ))
        })
        .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}
