//! Public `CardHandle` surface and `AsyncDhOracle` implementation.
//!
//! All card I/O happens on the long-lived thread spawned by
//! [`crate::thread::spawn_card_thread`]. From this side we only push DH
//! requests through the channel and wait on the one-shot reply. The `ss`
//! cache (DH of two static keys, constant per peer) lives here to short-
//! circuit the channel on cache hit.

use std::sync::mpsc::{SyncSender, TrySendError};
use std::{collections::HashMap, future::Future, thread::JoinHandle};

use card_backend_pcsc::PcscBackend;
use openpgp_card::{
    Card,
    ocard::{KeyType::Decryption, crypto::PublicKeyMaterial},
};
use rustyguard_crypto::{AsyncDhOracle, CryptoError, Key, PublicKey};
use secrecy::SecretString;
use thiserror::Error;

use crate::thread::{Request, spawn_card_thread};

/// Information about a connected OpenPGP card with an X25519 decryption key.
pub struct CardInfo {
    pub ident: String,
    pub public_key: [u8; 32],
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
    #[error("card thread request queue is full")]
    QueueFull,
}

/// Smartcard-backed oracle. Implements [`AsyncDhOracle`]; every DH call goes
/// through the dedicated card thread.
pub struct CardHandle {
    sender: SyncSender<Request>,
    /// Cache of `DH(our_static, peer_static)` results, keyed by peer pubkey.
    /// Safe to cache: the Noise IKpsk2 chain mixes all four DH results, so a
    /// leaked `ss` alone can't be used to forge a handshake. Pre-populated
    /// by [`Self::prime_ss`] so the hot path never blocks on the card.
    ///
    /// Plain `HashMap` (no `RefCell`): the trait methods take `&mut self`,
    /// so we have exclusive access without needing interior mutability.
    ss_cache: HashMap<[u8; 32], Key>,
    pub ident: String,
    // Field order matters: `sender` drops before `_thread`, which signals
    // the worker to exit (recv -> Err) before we detach its handle.
    _thread: JoinHandle<()>,
}

impl CardHandle {
    /// Open a card by identifier (`"auto"` picks the first X25519-capable
    /// card), verify the PIN, and spawn the worker thread that will serve
    /// DH requests for the rest of the tunnel's life.
    pub async fn open(ident: &str, pin: SecretString) -> Result<Self, SmartcardError> {
        let t = spawn_card_thread(ident.to_owned(), pin).await?;
        Ok(Self {
            sender: t.sender,
            ss_cache: HashMap::new(),
            ident: t.ident,
            _thread: t.join,
        })
    }

    /// Compute and cache `DH(our_static, peer_static)` so subsequent
    /// handshake `ss` mixes hit the cache instead of the card.
    pub async fn prime_ss(&mut self, peer_pk: &PublicKey) -> Result<(), SmartcardError> {
        let ss = self.dh(peer_pk.0).await?;
        self.ss_cache.insert(peer_pk.0, ss);
        Ok(())
    }

    /// Drop a cached `ss` entry (peer being removed, key rotated, etc.).
    pub fn forget_peer(&mut self, peer_pk: &PublicKey) {
        self.ss_cache.remove(&peer_pk.0);
    }

    /// Send a DH request to the card thread and await its reply.
    async fn dh(&mut self, peer_pk: [u8; 32]) -> Result<Key, SmartcardError> {
        let (tx, rx) = oneshot::channel();
        match self.sender.try_send(Request::Dh { peer_pk, reply: tx }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(SmartcardError::QueueFull),
            Err(TrySendError::Disconnected(_)) => {
                return Err(SmartcardError::CardError("card thread is gone".to_owned()));
            }
        }
        rx.await
            .map_err(|_| SmartcardError::CardError("card thread dropped reply".to_owned()))?
    }

    /// Send a public key request to the card thread and await its reply.
    async fn pubkey(&mut self) -> Key {
        let (tx, rx) = oneshot::channel();
        self.sender
            .try_send(Request::PubKey { reply: tx })
            .expect("Must be called first so queue not full");

        rx.await.expect("already got the public key when opening")
    }
}

impl AsyncDhOracle for CardHandle {
    fn async_x25519(
        &mut self,
        public: &PublicKey,
    ) -> impl Future<Output = Result<Key, CryptoError>> + Send {
        let cached = self.ss_cache.get(&public.0).copied();
        let peer_pk = public.0;
        async move {
            if let Some(ss) = cached {
                return Ok(ss);
            }
            self.dh(peer_pk).await.map_err(|e| {
                eprintln!("[smartcard] DH failed: {e}");
                CryptoError::KeyExchangeError
            })
        }
    }

    fn async_x25519_pubkey(&mut self) -> impl Future<Output = Key> + Send {
        self.pubkey()
    }
}
