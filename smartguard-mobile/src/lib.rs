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

use jni::JNIEnv;
use jni::objects::{JObject, JString};
use jni::sys::{jbyteArray, jint, jlong};
use secrecy::SecretString;
use smartguard_crypto::{AsyncDhOracle, CardHandle};

use apdu::jni_opener;

/// Opaque handle handed back to Kotlin as a `long`. Owns the tokio runtime that
/// drives the async card API and the open [`CardHandle`]; dropping it stops the
/// card thread (the request sender is dropped) and shuts the runtime down.
struct MobileCard {
    rt: tokio::runtime::Runtime,
    card: CardHandle,
}

/// Open the OpenPGP card over the JNI/USB transport, verify the PIN, and return
/// an opaque handle (or 0, with a Java exception thrown, on failure).
///
/// `transport` must expose `byte[] transceive(byte[])`. `ident` is the card
/// identifier or `"auto"`.
///
/// # Safety
/// JNI calls this with valid arguments; the returned handle must be released
/// exactly once via [`nativeCloseCard`].
#[no_mangle]
pub extern "system" fn Java_am_ito_smartguard_SmartguardNative_nativeOpenCard<'local>(
    mut env: JNIEnv<'local>,
    _class: JObject<'local>,
    transport: JObject<'local>,
    ident: JString<'local>,
    pin: JString<'local>,
) -> jlong {
    let opened = (|| -> Result<jlong, String> {
        let ident: String = env
            .get_string(&ident)
            .map_err(|e| format!("read ident: {e}"))?
            .into();
        let pin: String = env
            .get_string(&pin)
            .map_err(|e| format!("read pin: {e}"))?
            .into();

        let vm = Arc::new(env.get_java_vm().map_err(|e| format!("get_java_vm: {e}"))?);
        let transport = env
            .new_global_ref(transport)
            .map_err(|e| format!("new_global_ref: {e}"))?;

        let opener = jni_opener(vm, transport);

        // One worker thread is enough: the card thread does the blocking I/O,
        // the runtime only drives the async oracle plumbing.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map_err(|e| format!("build runtime: {e}"))?;

        let card = rt
            .block_on(CardHandle::open_with(opener, &ident, SecretString::from(pin)))
            .map_err(|e| format!("open card: {e}"))?;

        Ok(Box::into_raw(Box::new(MobileCard { rt, card })) as jlong)
    })();

    match opened {
        Ok(handle) => handle,
        Err(msg) => {
            let _ = env.throw_new("java/lang/RuntimeException", msg);
            0
        }
    }
}

/// Return the card's X25519 public key (32 bytes) as a Java `byte[]`, or `null`
/// on a bad handle.
#[no_mangle]
pub extern "system" fn Java_am_ito_smartguard_SmartguardNative_nativeCardPublicKey<'local>(
    env: JNIEnv<'local>,
    _class: JObject<'local>,
    handle: jlong,
) -> jbyteArray {
    if handle == 0 {
        return std::ptr::null_mut();
    }
    // SAFETY: `handle` is a pointer previously returned by `nativeOpenCard` and
    // not yet closed; Kotlin guarantees single-threaded access to one handle.
    let mc = unsafe { &mut *(handle as *mut MobileCard) };

    let pk = mc.rt.block_on(mc.card.async_x25519_pubkey());
    match env.byte_array_from_slice(&pk) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Close the card and free the handle. Idempotent for `0`.
///
/// # Safety
/// `handle` must be a value returned by [`nativeOpenCard`] that has not already
/// been closed.
#[no_mangle]
pub extern "system" fn Java_am_ito_smartguard_SmartguardNative_nativeCloseCard(
    _env: JNIEnv,
    _class: JObject,
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
#[no_mangle]
pub extern "system" fn Java_am_ito_smartguard_SmartguardNative_nativeStartTunnel<'local>(
    mut env: JNIEnv<'local>,
    _class: JObject<'local>,
    _card_handle: jlong,
    _tun_fd: jint,
) -> jlong {
    let _ = env.throw_new(
        "java/lang/UnsupportedOperationException",
        "nativeStartTunnel: not yet implemented (see TODO in smartguard-mobile)",
    );
    0
}
