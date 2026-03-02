//! Shared test helpers for the `event_log` module.
//!
//! Consolidates helper functions previously duplicated across `tree.rs`,
//! `proof.rs`, `checkpoint.rs`, and `metrics.rs` test modules.

use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};

use super::tree::{GENESIS_PREV_HASH, compute_event_canonical_hash};
use super::{Event, EventLog, EventPayload, EventType};
use crate::event_log::tree;
use crate::identity::DID;

/// Creates an Ed25519 signing keypair and returns (`verifying_key`, `signing_key`).
pub fn test_keypair() -> (ed25519_dalek::VerifyingKey, ed25519_dalek::SigningKey) {
    let mut rng = rand::thread_rng();
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    (verifying_key, signing_key)
}

/// Encodes a public key as a test DID (`did:key:<hex>`).
///
/// Returns `DID` (the newtype wrapper) for consistency across all callers.
pub fn did_from_pubkey(verifying_key: &ed25519_dalek::VerifyingKey) -> DID {
    let hex: String = verifying_key
        .as_bytes()
        .iter()
        .fold(String::new(), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        });
    format!("did:key:{hex}").into()
}

/// Signs an event and returns it with the signature populated.
///
/// Accepts `&str` for `actor_did` since `DID` derefs to `str`.
pub fn sign_event(
    event_type: EventType,
    actor_did: &str,
    timestamp: u64,
    sequence: u64,
    payload: Vec<u8>,
    prev_hash: [u8; 32],
    signing_key: &ed25519_dalek::SigningKey,
) -> Event {
    let mut event = Event {
        event_type,
        actor_did: actor_did.into(),
        timestamp,
        sequence,
        payload: EventPayload { data: payload },
        prev_hash,
        signature: Vec::new(),
    };

    let canonical_hash = compute_event_canonical_hash(&event);
    let signature = signing_key.sign(&canonical_hash);
    event.signature = signature.to_bytes().to_vec();

    event
}

/// Computes a leaf hash with the 0x00 domain separation prefix (RFC 6962).
pub fn leaf_hash_from_event(event: &Event) -> [u8; 32] {
    let serialized = rmp_serde::to_vec(event).expect("event serialization should succeed");
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(&serialized);
    hasher.finalize().into()
}

/// Builds an event log with `n` events and returns the log and leaf hashes.
pub fn build_test_log(n: u64) -> (EventLog, Vec<[u8; 32]>) {
    let (verifying_key, signing_key) = test_keypair();
    let did = did_from_pubkey(&verifying_key);
    let mut log = EventLog::new("ctx-test".to_owned());
    let mut prev_hash = GENESIS_PREV_HASH;
    let mut leaf_hashes = Vec::new();

    for i in 0..n {
        let event = sign_event(
            EventType::MessageSent,
            &did,
            1_000_000 + i,
            i,
            format!("message {i}").into_bytes(),
            prev_hash,
            &signing_key,
        );
        tree::append(&mut log, &event).expect("append should succeed");
        let leaf_hash = leaf_hash_from_event(&event);
        leaf_hashes.push(leaf_hash);
        prev_hash = leaf_hash;
    }

    (log, leaf_hashes)
}
