//! [`ApduLink`] implemented over a JNI callback into the Android app shell.
//!
//! This is the Android realization of the transport seam introduced in
//! `smartguard-crypto` (see `smartguard_crypto::transport`). On desktop the
//! seam is filled by PC/SC; here each command APDU is forwarded across JNI to
//! a Kotlin object that performs one CCID-over-USB exchange with the connected
//! token. All of `openpgp-card`'s logic (SELECT, public-key read, VERIFY PIN,
//! DECIPHER) is reused unchanged on top of it.

use std::sync::Arc;

use jni::objects::{JByteArray, JObject, JValue};
use jni::refs::Global;
use jni::{jni_sig, jni_str, Env, JavaVM};
use smartguard_crypto::{ApduBackend, ApduLink, CardBackendBox, CardOpener, SmartcardError};

/// The JVM handle plus a global reference to the Kotlin transport object.
///
/// These always travel together — the global ref is only meaningful within
/// this VM, and both must outlive every link the opener produces — so they
/// live in one `Arc` (one allocation, one refcount) rather than two. The `Arc`
/// is also what lets every link share them: `jni::refs::Global` is not `Clone`,
/// and the underlying JNI global ref is freed once when the last link drops.
struct Transport {
    vm: JavaVM,
    object: Global<JObject<'static>>,
}

type SharedTransport = Arc<Transport>;

/// An [`ApduLink`] that forwards each command APDU to a Kotlin transport object
/// across JNI.
///
/// The Kotlin object must expose exactly this method:
///
/// ```java
/// byte[] transceive(byte[] command)
/// ```
///
/// which performs one CCID-over-USB exchange with the connected token and
/// returns the response APDU (`data || SW1 SW2`).
///
/// The card is driven from a dedicated *native* OS thread (the card thread in
/// `smartguard-crypto`) that the JVM does not know about. [`JavaVM`] is
/// `Send + Sync`; the [`Global`] keeps the Kotlin transport object alive across
/// calls and threads.
pub struct JniApduLink {
    transport: SharedTransport,
}

impl ApduLink for JniApduLink {
    fn transceive(&mut self, command: &[u8]) -> Result<Vec<u8>, String> {
        // `attach_current_thread` permanently attaches this native card thread
        // (cheap on re-entry) and hands us a scoped `&mut Env`. The closure form
        // is what makes the TLS attachment sound: the `Env` cannot escape the
        // scope, so the attachment state can't outlive its validity.
        self.transport
            .vm
            .attach_current_thread(|env: &mut Env| -> Result<Vec<u8>, jni::errors::Error> {
                let arg = env.byte_array_from_slice(command)?;

                // Signature and method name are validated and MUTF-8-encoded at
                // compile time by `jni_sig!` / `jni_str!`.
                let ret = env.call_method(
                    self.transport.object.as_obj(),
                    jni_str!("transceive"),
                    jni_sig!("([B)[B"),
                    &[JValue::Object(arg.as_ref())],
                )?;

                let obj = ret.l()?;
                if obj.is_null() {
                    return Err(jni::errors::Error::NullPtr("transceive() returned null"));
                }
                let arr = env.cast_local::<JByteArray>(obj)?;
                env.convert_byte_array(&arr)
            })
            .map_err(|e| format!("transceive over JNI: {e}"))
    }
}

/// Build a [`CardOpener`] backed by the Kotlin transport object.
///
/// The opener is invoked at startup *and* on every reconnect, so it builds a
/// fresh [`JniApduLink`] each time (the underlying USB connection is
/// re-established on the Kotlin side when needed). A single connected token
/// presents one card, so the opener yields exactly one backend.
pub fn jni_opener(vm: JavaVM, object: Global<JObject<'static>>) -> CardOpener {
    let transport: SharedTransport = Arc::new(Transport { vm, object });
    Box::new(move || {
        let link = JniApduLink {
            transport: transport.clone(),
        };
        let backend: CardBackendBox = ApduBackend::new(link).into();
        Ok::<Vec<CardBackendBox>, SmartcardError>(vec![backend])
    })
}
