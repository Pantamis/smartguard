//! PC/SC card transport (desktop only).
//!
//! Card enumeration and the default opener over `card-backend-pcsc`, plus the
//! [`CardHandle::open`] convenience that uses them. Android supplies its own
//! transport to [`CardHandle::open_with`] instead.

use card_backend_pcsc::PcscBackend;
use openpgp_card::{
    Card,
    ocard::{KeyType::Decryption, crypto::PublicKeyMaterial},
};
use secrecy::SecretString;

use crate::card::{CardHandle, SmartcardError};
use crate::transport::CardOpener;

/// Information about a connected OpenPGP card with an X25519 decryption key.
pub struct CardInfo {
    pub ident: String,
    pub public_key: [u8; 32],
}

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

/// Enumerate connected OpenPGP cards that expose an X25519 decryption key.
/// Setup-time helper; no PIN verification, no long-lived state.
pub fn list_cards() -> Result<Vec<CardInfo>, SmartcardError> {
    let mut cards = Vec::new();
    for backend in PcscBackend::cards(None).map_err(|e| SmartcardError::CardError(e.to_string()))? {
        let Ok(backend) = backend else { continue };
        let Ok(mut card) = Card::new(backend) else {
            continue;
        };
        let Ok(mut tx) = card.transaction() else {
            continue;
        };
        let Ok(ident) = tx.application_identifier() else {
            continue;
        };
        let ident = ident.ident();
        let pk = match tx.public_key_material(Decryption) {
            Ok(PublicKeyMaterial::E(ecc)) => match ecc.data().first_chunk::<32>().copied() {
                Some(b) => b,
                None => continue,
            },
            _ => continue,
        };
        cards.push(CardInfo {
            ident,
            public_key: pk,
        });
    }
    Ok(cards)
}

impl CardHandle {
    /// Open a card over PC/SC by identifier (`"auto"` picks the first
    /// X25519-capable card), verify the PIN, and spawn the worker thread.
    ///
    /// Desktop entry point. On Android use [`CardHandle::open_with`] with an
    /// opener built around the platform's APDU link.
    pub async fn open(ident: &str, pin: SecretString) -> Result<Self, SmartcardError> {
        Self::open_with(pcsc_opener(), ident, pin).await
    }
}
