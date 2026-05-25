//! Long-lived OS thread that owns the OpenPGP card.
//!
//! `Card<Open>` is `Send`, but `Card<Transaction<'_>>` is not — we can't park
//! the card inside a tokio task and resume on a different worker. The
//! simplest model that fits both PC/SC's transactional API and the async DH
//! oracle interface is one dedicated OS thread that holds the card across
//! its lifetime and drains a bounded MPSC queue of DH requests, replying to
//! each via a one-shot.
//!
//! The thread exits cleanly when the request-sender on the [`CardHandle`]
//! side is dropped (the `recv()` here returns Err and the loop ends).

use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread::JoinHandle;

use card_backend_pcsc::PcscBackend;
use openpgp_card::{
    Card,
    ocard::{
        KeyType::Decryption,
        crypto::{Cryptogram, PublicKeyMaterial},
    },
    state::Open,
};
use rustyguard_crypto::Key;
use secrecy::SecretString;
use subtle::ConstantTimeEq;

use crate::card::SmartcardError;

/// Cap on in-flight DH requests. Each handshake costs at most 2 card ops
/// (`ss` + `se`/`es`), and `ss` is cached after the first hit, so 32 covers
/// many simultaneous rekeys with margin. A flood past that is treated as
/// congestion: `try_send` fails fast rather than blocking the executor.
const MAX_HANDSHAKE_REQUEST: usize = 32;

/// One DH operation: peer pubkey to ECDH against, and a one-shot to reply on.
pub(crate) enum Request {
    Dh {
        peer_pk: [u8; 32],
        reply: oneshot::Sender<Result<Key, SmartcardError>>,
    },
    PubKey {
        reply: oneshot::Sender<Key>,
    },
}

/// Handle returned by [`spawn_card_thread`].
pub(crate) struct CardThread {
    pub sender: SyncSender<Request>,
    pub ident: String,
    pub join: JoinHandle<()>,
}

/// Spawn the card thread and wait until it has opened the card, verified the
/// PIN, and read out the public key. After that it is ready to serve DH
/// requests pushed through `sender`.
pub(crate) async fn spawn_card_thread(
    requested_ident: String,
    pin: SecretString,
) -> Result<CardThread, SmartcardError> {
    let (req_tx, req_rx) = sync_channel::<Request>(MAX_HANDSHAKE_REQUEST);
    let (ready_tx, ready_rx) = oneshot::channel::<Result<String, SmartcardError>>();

    let join = std::thread::Builder::new()
        .name("smartguard-pcsc".to_owned())
        .spawn(move || run(requested_ident, pin, req_rx, ready_tx))
        .map_err(|e| SmartcardError::CardError(format!("spawn thread: {e}")))?;

    let ident = ready_rx
        .await
        .map_err(|_| SmartcardError::CardError("card thread exited before ready".to_owned()))??;

    Ok(CardThread {
        sender: req_tx,
        ident,
        join,
    })
}

fn run(
    requested_ident: String,
    pin: SecretString,
    req_rx: Receiver<Request>,
    ready_tx: oneshot::Sender<Result<String, SmartcardError>>,
) {
    let (mut card, ident) = match open_and_verify(&requested_ident, pin.clone()) {
        Ok((card, ident)) => {
            let _ = ready_tx.send(Ok(ident.clone()));
            (card, ident)
        }
        Err(e) => {
            let _ = ready_tx.send(Err(e));
            return;
        }
    };

    while let Ok(req) = req_rx.recv() {
        match req {
            Request::Dh { peer_pk, reply } => {
                let result = decipher_with_retry(&mut card, &ident, &pin, &peer_pk);
                // Receiver dropped before getting the answer — caller went away
                // (e.g. its future was cancelled). Discard, keep serving others.
                let _ = reply.send(result);
            }
            Request::PubKey { reply } => {
                let Ok(mut tx) = card.transaction() else {
                    continue;
                };
                if let Ok(PublicKeyMaterial::E(ecc)) = tx.public_key_material(Decryption)
                    && let Some(&pk_bytes) = ecc.data().first_chunk::<32>()
                {
                    let _ = reply.send(pk_bytes);
                };
            }
        }
    }
}

/// Walk the connected PC/SC backends, find one matching `requested_ident`
/// (or any X25519-capable card when `requested_ident == "auto"`), verify the
/// User PIN, and return the opened card with its DEC-slot public key.
fn open_and_verify(
    requested_ident: &str,
    pin: SecretString,
) -> Result<(Card<Open>, String), SmartcardError> {
    let mut backends =
        PcscBackend::cards(None).map_err(|e| SmartcardError::CardError(e.to_string()))?;

    let (mut card, card_ident) = backends
        .find_map(|backend| {
            let mut card = Card::new(backend.ok()?).ok()?;
            let mut tx = card.transaction().ok()?;
            let card_ident = tx.application_identifier().ok()?.ident();
            if requested_ident != "auto" && requested_ident != card_ident {
                return None;
            }
            match tx.public_key_material(Decryption) {
                Ok(PublicKeyMaterial::E(ecc)) if ecc.data().len() >= 32 => {
                    drop(tx);
                    Some(Ok((card, card_ident)))
                }
                _ if requested_ident == "auto" => None,
                _ => Some(Err(SmartcardError::NoDecryptionKey)),
            }
        })
        .ok_or_else(|| SmartcardError::CardNotFound(requested_ident.to_string()))??;

    card.transaction()
        .expect("card available")
        .verify_user_pin(pin)
        .map_err(|e| SmartcardError::PinFailed(e.to_string()))?;

    Ok((card, card_ident))
}

/// One DH op, with a single reconnect attempt if the first try fails
/// (scdaemon will reclaim the card mid-session if it gets prodded; the
/// reconnect re-opens the same identity and re-verifies the PIN inside
/// `try_decipher`).
fn decipher_with_retry(
    card: &mut Card<Open>,
    ident: &str,
    pin: &SecretString,
    peer_pk: &[u8; 32],
) -> Result<Key, SmartcardError> {
    match try_decipher(card, pin, peer_pk) {
        Ok(k) => Ok(k),
        Err(e) => {
            eprintln!("[smartcard] {e}; reconnecting to {ident}...");
            std::thread::sleep(core::time::Duration::from_secs(5));
            reconnect(card, ident)?;
            try_decipher(card, pin, peer_pk)
        }
    }
}

fn try_decipher(
    card: &mut Card<Open>,
    pin: &SecretString,
    peer_pk: &[u8; 32],
) -> Result<Key, SmartcardError> {
    let mut tx = card
        .transaction()
        .map_err(|e| SmartcardError::CardError(e.to_string()))?;

    tx.verify_user_pin(pin.clone())
        .map_err(|e| SmartcardError::PinFailed(e.to_string()))?;

    let ss = tx
        .card()
        .decipher(Cryptogram::ECDH(peer_pk))
        .map_err(|e| SmartcardError::DhFailed(e.to_string()))?;

    let key: Key = ss
        .first_chunk()
        .copied()
        .ok_or_else(|| SmartcardError::DhFailed("DECIPHER returned <32 bytes".to_owned()))?;

    let is_zero: bool = key.iter().fold(0u8, |a, b| a | b).ct_eq(&0u8).into();
    if is_zero {
        return Err(SmartcardError::ZeroSharedSecret);
    }
    Ok(key)
}

fn reconnect(card: &mut Card<Open>, ident: &str) -> Result<(), SmartcardError> {
    for backend in PcscBackend::cards(None).map_err(|e| SmartcardError::CardError(e.to_string()))? {
        let Ok(backend) = backend else { continue };
        let Ok(mut new_card) = Card::new(backend) else {
            continue;
        };
        let Ok(tx) = new_card.transaction() else {
            continue;
        };
        let Ok(ai) = tx.application_identifier() else {
            continue;
        };
        if ai.ident() == ident {
            drop(tx);
            *card = new_card;
            eprintln!("[smartcard] reconnected to {ident}");
            return Ok(());
        }
    }
    Err(SmartcardError::CardNotFound(ident.to_string()))
}
