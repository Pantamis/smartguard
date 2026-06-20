//! Card transport seam — how we obtain APDU access to the OpenPGP card.
//!
//! Everything `openpgp-card` does (SELECT, read DEC-slot public key, VERIFY
//! PIN, DECIPHER) flows through the APDU-level [`card_backend::CardBackend`] /
//! [`card_backend::CardTransaction`] traits: `transmit(cmd) -> response`. That
//! makes the physical link the *only* platform-specific part of the smartcard
//! path, and this module is where it is abstracted:
//!
//! * Desktop (Linux/macOS/Windows) talks to the card over **PC/SC**. The
//!   `card-backend-pcsc` crate already implements `CardBackend`, so the desktop
//!   path doesn't go through [`ApduLink`] at all — see [`pcsc_opener`].
//! * Android (and any future mobile/NFC backend) has no PC/SC. There, the card
//!   is reached over **CCID-over-USB** (USB-C connected token) and the raw APDU
//!   exchange happens in the app shell. [`ApduBackend`] wraps any [`ApduLink`]
//!   — e.g. one that forwards APDU bytes across JNI to a Kotlin
//!   `UsbDeviceConnection` — as a `CardBackend`, so all of `openpgp-card`'s
//!   logic is reused unchanged.
//!
//! Card acquisition is abstracted as a [`CardOpener`]: a closure that produces
//! candidate backends. It is invoked at startup *and* on every reconnect, so a
//! PC/SC opener re-enumerates readers live and an Android opener rebuilds the
//! USB link. This keeps the long-lived card thread (see [`crate::thread`])
//! transport-agnostic.

use card_backend::{
    CardBackend, CardCaps, CardTransaction, PinType, SmartcardError as CardBackendError,
};
use card_backend_pcsc::PcscBackend;

use crate::card::SmartcardError;

/// A boxed [`CardBackend`] ready to hand to `openpgp_card::Card::new`.
pub type CardBackendBox = Box<dyn CardBackend + Send + Sync>;

/// Produces the candidate card backends to try when opening (or reopening)
/// the card.
///
/// Called once at startup and again on every reconnect, so the closure must
/// re-acquire the link each time rather than caching a single backend:
/// the PC/SC opener re-enumerates readers; an Android opener rebuilds the
/// CCID-over-USB link from the current `UsbDeviceConnection`.
///
/// Boxed and `Send` so the transport is chosen at runtime and the opener can
/// be moved onto the dedicated card thread.
pub type CardOpener = Box<dyn FnMut() -> Result<Vec<CardBackendBox>, SmartcardError> + Send>;

/// Default desktop opener: enumerate every card reachable over PC/SC.
///
/// Individual enumeration errors for a single reader are dropped (that reader
/// is skipped); only a failure to establish the PC/SC context surfaces.
pub fn pcsc_opener() -> CardOpener {
    Box::new(|| {
        let backends = PcscBackend::card_backends(None)
            .map_err(|e| SmartcardError::CardError(e.to_string()))?;
        Ok(backends.filter_map(Result::ok).collect())
    })
}

/// The single seam between `openpgp-card` and a physical card link that is not
/// PC/SC.
///
/// `transceive` takes a complete command APDU and returns the response APDU
/// (`data || SW1 SW2`). On Android this is implemented by forwarding the bytes
/// across JNI to a CCID-over-USB exchange in the app shell. Implementors carry
/// whatever connection state they need; `&mut self` gives exclusive access for
/// the duration of a call.
pub trait ApduLink: Send + Sync {
    /// Send one command APDU and return the raw response APDU.
    fn transceive(&mut self, command: &[u8]) -> Result<Vec<u8>, String>;
}

/// Adapts any [`ApduLink`] into a `card_backend::CardBackend`, so
/// `openpgp_card::Card::new(ApduBackend::new(link))` works for any link.
///
/// Build a [`CardOpener`] for a non-PC/SC platform by returning
/// `vec![ApduBackend::new(link).into()]`.
pub struct ApduBackend<L: ApduLink> {
    link: L,
}

impl<L: ApduLink> ApduBackend<L> {
    pub fn new(link: L) -> Self {
        Self { link }
    }
}

impl<L: ApduLink + 'static> From<ApduBackend<L>> for CardBackendBox {
    fn from(backend: ApduBackend<L>) -> CardBackendBox {
        Box::new(backend)
    }
}

impl<L: ApduLink> CardBackend for ApduBackend<L> {
    fn limit_card_caps(&self, card_caps: CardCaps) -> CardCaps {
        // A raw APDU link imposes no extra limits beyond what the card itself
        // reports; pass the capabilities through unchanged.
        card_caps
    }

    fn transaction(
        &mut self,
        _reselect_application: Option<&[u8]>,
    ) -> Result<Box<dyn CardTransaction + Send + Sync + '_>, CardBackendError> {
        // A connected USB token holds a single persistent logical channel: the
        // OpenPGP application stays SELECTed across transactions and we never
        // observe a card reset (`was_reset` is always false). This mirrors the
        // PC/SC backend, which only re-SELECTs on the reset path — so there is
        // nothing to do for `reselect_application` here.
        Ok(Box::new(ApduTransaction {
            link: &mut self.link,
        }))
    }
}

/// One transaction over an [`ApduLink`]. Holds the link exclusively for its
/// lifetime; `transmit` is a direct passthrough to [`ApduLink::transceive`].
struct ApduTransaction<'a, L: ApduLink> {
    link: &'a mut L,
}

impl<L: ApduLink> CardTransaction for ApduTransaction<'_, L> {
    fn transmit(&mut self, cmd: &[u8], _buf_size: usize) -> Result<Vec<u8>, CardBackendError> {
        self.link.transceive(cmd).map_err(CardBackendError::Error)
    }

    // USB security tokens (YubiKey, Nitrokey) do not expose a CCID pinpad; the
    // User PIN is sent via a normal VERIFY APDU, which `openpgp-card` issues
    // through `transmit`. Advertise no pinpad so it never takes that path.
    fn feature_pinpad_verify(&self) -> bool {
        false
    }

    fn feature_pinpad_modify(&self) -> bool {
        false
    }

    fn pinpad_verify(
        &mut self,
        _pin: PinType,
        _card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, CardBackendError> {
        Err(CardBackendError::Error(
            "pinpad PIN entry is not supported over this APDU link".into(),
        ))
    }

    fn pinpad_modify(
        &mut self,
        _pin: PinType,
        _card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, CardBackendError> {
        Err(CardBackendError::Error(
            "pinpad PIN entry is not supported over this APDU link".into(),
        ))
    }

    fn was_reset(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Records every APDU it is asked to send and replies with a canned
    /// response, so we can assert the seam plumbs bytes through unchanged
    /// without a real card or applet.
    struct MockLink {
        log: Arc<Mutex<Vec<Vec<u8>>>>,
        response: Vec<u8>,
    }

    impl ApduLink for MockLink {
        fn transceive(&mut self, command: &[u8]) -> Result<Vec<u8>, String> {
            self.log.lock().unwrap().push(command.to_vec());
            Ok(self.response.clone())
        }
    }

    #[test]
    fn transmit_forwards_command_and_returns_response() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut backend = ApduBackend::new(MockLink {
            log: log.clone(),
            response: vec![0x12, 0x34, 0x90, 0x00],
        });

        let mut tx = CardBackend::transaction(&mut backend, None).unwrap();
        let cmd = [0x00, 0xA4, 0x04, 0x00];
        let resp = tx.transmit(&cmd, 256).unwrap();
        drop(tx);

        assert_eq!(resp, vec![0x12, 0x34, 0x90, 0x00]);
        let recorded = log.lock().unwrap();
        assert_eq!(recorded.as_slice(), &[cmd.to_vec()]);
    }

    #[test]
    fn advertises_no_pinpad_and_no_reset() {
        let mut backend = ApduBackend::new(MockLink {
            log: Arc::new(Mutex::new(Vec::new())),
            response: vec![0x90, 0x00],
        });
        let tx = CardBackend::transaction(&mut backend, None).unwrap();

        assert!(!tx.feature_pinpad_verify());
        assert!(!tx.feature_pinpad_modify());
        assert!(!tx.was_reset());
    }

    /// The backend must be usable as the boxed type `openpgp_card::Card::new`
    /// accepts — this is the Android opener's return shape.
    #[test]
    fn converts_into_boxed_card_backend() {
        let link = MockLink {
            log: Arc::new(Mutex::new(Vec::new())),
            response: vec![0x90, 0x00],
        };
        let _boxed: CardBackendBox = ApduBackend::new(link).into();
    }
}
