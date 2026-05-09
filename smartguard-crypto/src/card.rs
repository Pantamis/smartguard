use card_backend_pcsc::PcscBackend;
use openpgp_card::{
    Card,
    ocard::{
        KeyType::Decryption,
        crypto::{Cryptogram, PublicKeyMaterial},
    },
    state::Open,
};
use rustyguard_crypto::{CryptoError, DhOracle, Key, PublicKey};
use secrecy::SecretString;
use std::cell::RefCell;
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use thiserror::Error;

/// Information about a connected OpenPGP card with an X25519 decryption key.
pub struct CardInfo {
    pub ident: String,
    pub public_key: [u8; 32],
}

/// Enumerate all connected OpenPGP cards that have an X25519 decryption key.
///
/// Returns card identifiers and their public keys without verifying any PIN.
pub fn list_cards() -> Result<Vec<CardInfo>, SmartcardError> {
    let mut cards = Vec::new();
    for backend in PcscBackend::cards(None).map_err(|e| SmartcardError::CardError(e.to_string()))? {
        let backend = match backend {
            Ok(b) => b,
            Err(_) => continue,
        };
        let mut card = match Card::new(backend) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let mut tx = match card.transaction() {
            Ok(t) => t,
            Err(_) => continue,
        };
        let ident = match tx.application_identifier() {
            Ok(ai) => ai.ident(),
            Err(_) => continue,
        };
        let pk = match tx.public_key_material(Decryption) {
            Ok(PublicKeyMaterial::E(ecc)) if ecc.data().len() == 32 => {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(ecc.data());
                buf
            }
            _ => continue,
        };
        cards.push(CardInfo {
            ident,
            public_key: pk,
        });
    }
    Ok(cards)
}

#[derive(Error, Debug)]
pub enum SmartcardError {
    #[error("card not found: {0}")]
    CardNotFound(String),
    #[error("card does not have an X25519 decryption key")]
    NoDecryptionKey,
    #[error("PIN verification failed: {0}")]
    PinFailed(String),
    #[error("DH operation failed: {0}")]
    DhFailed(String),
    #[error("card communication error: {0}")]
    CardError(String),
    #[error("shared secret is zero (invalid peer public key)")]
    ZeroSharedSecret,
}

/// Mutable card state, hidden behind a `RefCell` so `DhOracle` can take
/// `&self` (matches `StaticPrivateKey`'s impl — callers don't need a `mut`
/// binding, which would be misleading since the bytes don't change).
struct Inner {
    card: Card<Open>,
    /// User PIN cached for the lifetime of the agent so we can re-verify on
    /// every transaction (smartcard sessions reset between transactions, on
    /// USB suspend, when scdaemon steals the card, etc.). Wrapped in
    /// `SecretString` so it's not leaked via `Debug` and gets zeroized on
    /// drop.
    pin: SecretString,
    /// Cache of `DH(our_static, peer_static)` results, keyed by peer pubkey.
    /// Prime via `CardHandle::prime_ss` at startup; safe because the Noise
    /// IKpsk2 chain mixes all four DH results — caching `ss` alone can't
    /// produce valid handshakes.
    ss_cache: HashMap<[u8; 32], Key>,
}

/// Smartcard-backed `DhOracle`.
///
/// All DH calls dispatch to the OpenPGP card's DECIPHER command. The card
/// transaction state and the `ss` cache live behind a `RefCell` so the
/// oracle can be passed as `&self`, just like `StaticPrivateKey`.
pub struct CardHandle {
    inner: RefCell<Inner>,
    /// Read once at `open()`, immutable thereafter.
    pub cached_public_key: PublicKey,
    pub ident: String,
}

impl CardHandle {
    /// Open a card by its identifier (or `"auto"` for the first card with an
    /// X25519 decryption key), read the public key, verify the PIN, and return
    /// a handle ready to perform DH operations.
    pub fn open(ident: &str, pin: &SecretString) -> Result<Self, SmartcardError> {
        for backend in
            PcscBackend::cards(None).map_err(|e| SmartcardError::CardError(e.to_string()))?
        {
            let backend = backend.map_err(|e| SmartcardError::CardError(e.to_string()))?;
            let mut card =
                Card::new(backend).map_err(|e| SmartcardError::CardError(e.to_string()))?;

            let mut tx = card
                .transaction()
                .map_err(|e| SmartcardError::CardError(e.to_string()))?;

            let card_ident = tx
                .application_identifier()
                .map_err(|e| SmartcardError::CardError(e.to_string()))?
                .ident();

            if ident != "auto" && ident != card_ident {
                continue;
            }

            let pk_bytes = if let PublicKeyMaterial::E(ecc) = tx
                .public_key_material(Decryption)
                .map_err(|e| SmartcardError::CardError(e.to_string()))?
                && let Some(buf) = ecc.data().as_array::<32>().copied()
            {
                buf
            } else {
                if ident == "auto" {
                    continue;
                }
                return Err(SmartcardError::NoDecryptionKey);
            };

            tx.verify_user_pin(pin.clone())
                .map_err(|e| SmartcardError::PinFailed(e.to_string()))?;

            drop(tx);

            return Ok(CardHandle {
                inner: RefCell::new(Inner {
                    card,
                    pin: pin.clone(),
                    ss_cache: HashMap::new(),
                }),
                cached_public_key: PublicKey(pk_bytes),
                ident: card_ident,
            });
        }

        Err(SmartcardError::CardNotFound(ident.to_string()))
    }

    /// Prime the `ss` cache for a peer by performing DH(our_static, peer_static)
    /// on the smartcard now.
    ///
    /// Once primed, subsequent `dh_static(peer_pk)` calls during handshakes
    /// return the cached value instead of hitting the card.
    pub fn prime_ss(&self, peer_pk: &PublicKey) -> Result<(), SmartcardError> {
        let mut inner = self.inner.borrow_mut();
        let ss = decipher_with_retry(&mut inner, &peer_pk.0, &self.ident)?;
        inner.ss_cache.insert(peer_pk.0, ss);
        Ok(())
    }

    /// Drop a cached ss result for a peer (e.g. when removing the peer).
    pub fn forget_peer(&self, peer_pk: &PublicKey) {
        self.inner.borrow_mut().ss_cache.remove(&peer_pk.0);
    }
}

impl DhOracle for CardHandle {
    fn x25519(&self, public: &PublicKey) -> Result<Key, CryptoError> {
        let mut inner = self.inner.borrow_mut();
        if let Some(&ss) = inner.ss_cache.get(&public.0) {
            return Ok(ss);
        }
        decipher_with_retry(&mut inner, &public.0, &self.ident).map_err(|e| {
            eprintln!("[smartcard] DH failed: {e}");
            CryptoError::KeyExchangeError
        })
    }

    fn x25519_pubkey(&self) -> PublicKey {
        PublicKey(self.cached_public_key.0)
    }
}

/// Try DECIPHER once, and if the card transaction is stale (e.g. scdaemon
/// reclaimed it) reconnect to the same identity and retry.
fn decipher_with_retry(
    inner: &mut Inner,
    peer_pk: &[u8; 32],
    ident: &str,
) -> Result<Key, SmartcardError> {
    match try_decipher(inner, peer_pk) {
        Ok(k) => Ok(k),
        Err(_) => {
            eprintln!("[smartcard] reconnecting to card {ident}...");
            reconnect(inner, ident)?;
            try_decipher(inner, peer_pk)
        }
    }
}

fn try_decipher(inner: &mut Inner, peer_pk: &[u8; 32]) -> Result<Key, SmartcardError> {
    let mut tx = inner
        .card
        .transaction()
        .map_err(|e| SmartcardError::CardError(e.to_string()))?;

    tx.verify_user_pin(inner.pin.clone())
        .map_err(|e| SmartcardError::PinFailed(e.to_string()))?;

    let shared_secret = tx
        .card()
        .decipher(Cryptogram::ECDH(peer_pk))
        .map_err(|e| SmartcardError::DhFailed(e.to_string()))?
        .first_chunk()
        .copied()
        .expect("Received at least 32 bytes on success");

    let is_zero: bool = shared_secret
        .iter()
        .fold(0u8, |acc, b| acc | b)
        .ct_eq(&0u8)
        .into();
    if is_zero {
        return Err(SmartcardError::ZeroSharedSecret);
    }

    Ok(shared_secret)
}

fn reconnect(inner: &mut Inner, ident: &str) -> Result<(), SmartcardError> {
    'cards: for backend in
        PcscBackend::cards(None).map_err(|e| SmartcardError::CardError(e.to_string()))?
    {
        if let Ok(backend) = backend
            && let Ok(mut card) = Card::new(backend)
        {
            let Ok(tx) = card.transaction() else {
                continue 'cards;
            };
            if let Ok(card_ident) = tx.application_identifier()
                && card_ident.ident() == ident
            {
                drop(tx);
                inner.card = card;
                eprintln!("[smartcard] reconnected to {ident}");
                return Ok(());
            } else {
                continue 'cards;
            };
        } else {
            continue 'cards;
        };
    }
    Err(SmartcardError::CardNotFound(ident.to_string()))
}
