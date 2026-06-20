//! [`ApduLink`] implemented over a JNI callback into the Android app shell.
//!
//! This is the Android realization of the transport seam introduced in
//! `smartguard-crypto` (see `smartguard_crypto::transport`). On desktop the
//! seam is filled by PC/SC; here each command APDU is forwarded across JNI to
//! a Kotlin object that performs one CCID-over-USB exchange with the connected
//! token. All of `openpgp-card`'s logic (SELECT, public-key read, VERIFY PIN,
//! DECIPHER) is reused unchanged on top of it.

use std::sync::Arc;

use jni::JavaVM;
use jni::objects::{GlobalRef, JByteArray, JValue};
use smartguard_crypto::{ApduBackend, ApduLink, CardBackendBox, CardOpener, SmartcardError};

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
/// `smartguard-crypto`) that the JVM does not know about, so every call must
/// attach the current thread to the JVM before invoking Java. [`JavaVM`] is
/// `Send + Sync` and cheap to share; [`GlobalRef`] keeps the Kotlin transport
/// object alive across calls and threads.
///
/// TODO(perf): this attaches/detaches the card thread on every call. Since the
/// card thread is long-lived, switch to `attach_current_thread_permanently`
/// (attach once on first use) to avoid the per-DH attach overhead.
pub struct JniApduLink {
    vm: Arc<JavaVM>,
    transport: GlobalRef,
}

impl JniApduLink {
    pub fn new(vm: Arc<JavaVM>, transport: GlobalRef) -> Self {
        Self { vm, transport }
    }
}

impl ApduLink for JniApduLink {
    fn transceive(&mut self, command: &[u8]) -> Result<Vec<u8>, String> {
        // Attach this native thread to the JVM for the duration of the call.
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|e| format!("attach_current_thread: {e}"))?;

        let arg = env
            .byte_array_from_slice(command)
            .map_err(|e| format!("byte_array_from_slice: {e}"))?;

        let ret = env
            .call_method(
                self.transport.as_obj(),
                "transceive",
                "([B)[B",
                &[JValue::Object(arg.as_ref())],
            )
            .map_err(|e| format!("call transceive(): {e}"))?;

        let obj = ret.l().map_err(|e| format!("transceive return value: {e}"))?;
        if obj.is_null() {
            return Err("transceive() returned null".to_owned());
        }
        env.convert_byte_array(JByteArray::from(obj))
            .map_err(|e| format!("convert_byte_array: {e}"))
    }
}

/// Build a [`CardOpener`] backed by the Kotlin transport object.
///
/// The opener is invoked at startup *and* on every reconnect, so it builds a
/// fresh [`JniApduLink`] each time (the underlying USB connection is
/// re-established on the Kotlin side when needed). A single connected token
/// presents one card, so the opener yields exactly one backend.
pub fn jni_opener(vm: Arc<JavaVM>, transport: GlobalRef) -> CardOpener {
    Box::new(move || {
        let link = JniApduLink::new(vm.clone(), transport.clone());
        let backend: CardBackendBox = ApduBackend::new(link).into();
        Ok::<Vec<CardBackendBox>, SmartcardError>(vec![backend])
    })
}
