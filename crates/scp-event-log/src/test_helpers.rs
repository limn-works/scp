//! Shared test helpers for the `event_log` module.
//!
//! Consolidates helper functions previously duplicated across `tree.rs`,
//! `proof.rs`, `checkpoint.rs`, and `metrics.rs` test modules.

use ed25519_dalek::Signer;
use scp_did::DidDocument;
use sha2::{Digest, Sha256};

use super::tree::{GENESIS_PREV_HASH, compute_event_canonical_hash};
use super::{Event, EventLog, EventPayload, EventType};
use crate::DID;
use crate::tree;

/// Creates an Ed25519 signing keypair and returns (`verifying_key`, `signing_key`).
#[must_use]
pub fn test_keypair() -> (ed25519_dalek::VerifyingKey, ed25519_dalek::SigningKey) {
    let mut rng = rand::thread_rng();
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    (verifying_key, signing_key)
}

/// Encodes a public key as a canonical `did:dht:z<z-base-32>` test DID.
///
/// `tree::verify_event_signature` gates an actor DID through
/// `scp_did::extract_public_key_from_did`, which accepts `did:key:<hex>` only
/// under a `testing` feature. Producing a `did:dht` string keeps every test in
/// this crate on a DID form a shipped build also accepts, so a test never
/// depends on a testing-only DID method.
///
/// Returns `DID` (a newtype wrapper) for consistency across callers.
#[must_use]
pub fn did_from_pubkey(verifying_key: &ed25519_dalek::VerifyingKey) -> DID {
    scp_did::did_dht_from_public_key(verifying_key.as_bytes())
}

/// Identity Key (`#0`) every test DID document carries.
///
/// A test document names an Identity Key that matches no signing key any test
/// holds, so a verifier reaching for `#0` — a key every DID string encodes —
/// rejects every signature instead of accepting one. `tree::verify_event_signature`
/// reads `#active` and `#agent` only, and this constant is what makes a
/// regression toward `#0` fail a test rather than pass one.
const UNUSED_IDENTITY_KEY: [u8; 32] = [0xA5; 32];

/// Pre-rotation commitment every test DID document publishes.
///
/// `verify_event_signature` reads no service entry, so this value only has to
/// exist.
const UNUSED_PRE_ROTATION_COMMITMENT: [u8; 32] = [0x5A; 32];

/// Builds a DID document for `did` whose `#active` verification method carries
/// `active_public_key`.
///
/// Callers hand a result to [`tree::append`](crate::tree::append) and
/// [`tree::verify_event_signature`](crate::tree::verify_event_signature) as an
/// actor document a resolver would return.
#[must_use]
pub fn test_did_document(
    did: &str,
    active_public_key: &ed25519_dalek::VerifyingKey,
) -> DidDocument {
    DidDocument::new(
        did,
        &UNUSED_IDENTITY_KEY,
        active_public_key.as_bytes(),
        &UNUSED_PRE_ROTATION_COMMITMENT,
    )
}

/// Builds a DID document for `did` carrying both an `#active` and an `#agent`
/// verification method (ADR-039).
#[must_use]
pub fn test_did_document_with_agent(
    did: &str,
    active_public_key: &ed25519_dalek::VerifyingKey,
    agent_public_key: &ed25519_dalek::VerifyingKey,
) -> DidDocument {
    DidDocument::new_with_agent_key(
        did,
        &UNUSED_IDENTITY_KEY,
        active_public_key.as_bytes(),
        &UNUSED_PRE_ROTATION_COMMITMENT,
        Some(agent_public_key.as_bytes()),
    )
}

/// Signs an event and returns it with the signature populated.
///
/// Accepts `&str` for `actor_did` since `DID` derefs to `str`.
#[must_use]
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
///
/// # Panics
///
/// Panics if event serialization fails.
#[must_use]
pub fn leaf_hash_from_event(event: &Event) -> [u8; 32] {
    let serialized = rmp_serde::to_vec(event).expect("event serialization should succeed");
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(&serialized);
    hasher.finalize().into()
}

/// A test-only [`EventLogSigner`](crate::EventLogSigner) that wraps an Ed25519 signing key directly.
///
/// Replaces `InMemoryKeyCustody` for tests within scp-event-log, which cannot
/// depend on scp-platform.
pub struct TestSigner {
    signing_key: ed25519_dalek::SigningKey,
}

impl Default for TestSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl TestSigner {
    /// Creates a new `TestSigner` with a freshly generated Ed25519 keypair.
    #[must_use]
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
        Self { signing_key }
    }

    /// Returns the verifying (public) key for manual signature verification.
    #[must_use]
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }
}

#[async_trait::async_trait]
impl crate::EventLogSigner for TestSigner {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let sig = self.signing_key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }
}

/// Builds an event log with `n` events and returns the log and leaf hashes.
///
/// # Panics
///
/// Panics if event append fails.
#[must_use]
pub fn build_test_log(n: u64) -> (EventLog, Vec<[u8; 32]>) {
    let (verifying_key, signing_key) = test_keypair();
    let did = did_from_pubkey(&verifying_key);
    let actor_document = test_did_document(&did, &verifying_key);
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
        tree::append(&mut log, &event, &actor_document).expect("append should succeed");
        let leaf_hash = leaf_hash_from_event(&event);
        leaf_hashes.push(leaf_hash);
        prev_hash = leaf_hash;
    }

    (log, leaf_hashes)
}
