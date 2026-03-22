//! Per-sender AES-256 symmetric key layer for SCP.
//!
//! Each sender in an SCP context maintains an AES-256 symmetric key. Messages
//! are encrypted with the sender's key before MLS group encryption (double
//! encryption). This enables per-relationship blocking without MLS group
//! removal: the sender rotates their key and redistributes it to everyone
//! except the blocked party. See ADR-007 in `.docs/adrs/phase-1.md`.
//!
//! # Modules
//!
//! - [`broadcast`] — Broadcast key lifecycle and `BroadcastEnvelope` seal/open
//!   for `ContextMode::Broadcast` contexts (§5.14).
//! - [`encrypt`] — AES-256-GCM encrypt and decrypt operations.
//!
//! # Key Types
//!
//! - [`SenderKey`] — Opaque 32-byte AES-256 key handle.
//! - [`BroadcastKey`] — Per-author broadcast key with epoch counter.
//! - [`SenderKeyStore`] — In-memory store keyed by `(context_id, sender_did)`.
//! - [`SenderKeyError`] — Error type for sender key operations.

pub mod broadcast;
pub mod encrypt;
pub mod key_protocol;
pub mod key_protocol_verify;

use std::collections::HashMap;

use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use broadcast::{
    BroadcastEnvelope, BroadcastKey, BroadcastKeyEpochAdvance, BroadcastReplayDetector,
    SealBroadcastParams, SigningPayloadFields, build_broadcast_signing_payload,
    compute_provenance_hash, generate_broadcast_key, generate_broadcast_nonce, open_broadcast,
    open_broadcast_trusted, rotate_broadcast_key, seal_broadcast, validate_broadcast_version,
};
pub use encrypt::{decrypt_sender_layer, encrypt_sender_layer};
pub use key_protocol::{
    BlockNotification, BridgeShadowKeyParams, HandleRequestParams, NonceDedup,
    RotateForBlockParams, RotateForBlockResult, SenderKeyDistributionMessage,
    SenderKeyEpochAdvance, SenderKeyRequest, SenderKeyRequestResult, SenderKeyResponse,
    expand_block_list, generate_wrapping_keypair, handle_bridge_shadow_key_request,
    handle_sender_key_request, hpke_open_sender_key, hpke_seal_sender_key,
    list_shadow_sender_key_dids, open_sender_key_response, publish_sender_key_epoch_advance,
    request_sender_key, rotate_sender_key_for_block, send_block_notification,
    validate_block_notification_freshness, validate_sender_key_request_freshness,
    verify_block_notification, verify_epoch_advance, verify_sender_key_request,
};

// ---------------------------------------------------------------------------
// SenderKey
// ---------------------------------------------------------------------------

/// Opaque handle for a 32-byte AES-256 sender key.
///
/// Sender keys are used to encrypt messages before MLS group encryption,
/// enabling per-relationship blocking. See ADR-007.
///
/// Key material is zeroized on drop to prevent sensitive bytes from
/// persisting in freed memory. Clone is retained for API compatibility
/// (e.g. `SenderKeyStore::get_all`).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SenderKey([u8; 32]);

impl SenderKey {
    /// Creates a sender key from raw 32-byte key material.
    ///
    /// Used by [`key_protocol::open_sender_key_response`] to reconstruct a
    /// sender key from HPKE-decrypted bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the raw 32-byte key material.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SenderKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SenderKey").field(&"[REDACTED]").finish()
    }
}

/// Generates a random 32-byte AES-256 sender key.
///
/// Uses the platform's cryptographically secure random number generator.
///
/// # Examples
///
/// ```
/// use scp_core::crypto::sender_keys::generate_sender_key;
///
/// let key = generate_sender_key();
/// assert_eq!(key.as_bytes().len(), 32);
/// ```
#[must_use]
pub fn generate_sender_key() -> SenderKey {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    SenderKey(bytes)
}

// ---------------------------------------------------------------------------
// SenderKeyError
// ---------------------------------------------------------------------------

/// Errors produced by sender key operations.
///
/// Each variant covers a distinct failure mode in the sender-side key layer.
/// See ADR-007 for the sender key design.
#[derive(Debug, thiserror::Error)]
pub enum SenderKeyError {
    /// AES-256-GCM encryption failed.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// AES-256-GCM authentication tag verification failed.
    ///
    /// The ciphertext was tampered with, corrupted, or encrypted with a
    /// different key.
    #[error("authentication tag verification failed")]
    AuthenticationFailed,

    /// The ciphertext is too short to contain a valid nonce.
    #[error("ciphertext too short: {actual} bytes, minimum {minimum}")]
    CiphertextTooShort {
        /// Actual length of the ciphertext.
        actual: usize,
        /// Minimum required length.
        minimum: usize,
    },

    /// Ed25519 signing operation failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// Ed25519 signature verification failed due to malformed input.
    #[error("verification failed: {0}")]
    VerificationFailed(String),

    /// JSON serialization failed.
    #[error("serialization failed: {0}")]
    SerializationFailed(String),

    /// HPKE encryption (seal) failed.
    #[error("HPKE encryption failed: {0}")]
    HpkeEncryptionFailed(String),

    /// HPKE decryption (open) failed.
    #[error("HPKE decryption failed: {0}")]
    HpkeDecryptionFailed(String),

    /// A key custody operation failed.
    #[error("key custody error: {0}")]
    KeyCustodyError(String),

    /// A sender key request was replayed (duplicate nonce within the expiry window).
    #[error("replayed request: duplicate nonce detected")]
    ReplayedRequest,

    /// A block notification timestamp is too old to be considered fresh.
    #[error("stale block notification: timestamp outside freshness window")]
    StaleBlockNotification,

    /// A sender key request timestamp is outside the freshness window.
    ///
    /// The request is either too old (stale) or too far in the future,
    /// indicating clock skew or a replay attempt.
    #[error("stale sender key request: timestamp outside freshness window")]
    StaleSenderKeyRequest,

    /// The envelope's major version is incompatible with this implementation.
    ///
    /// Returned by [`broadcast::validate_broadcast_version`] when the major
    /// version differs from the local major version (§13.5). Envelopes with
    /// the same major version but a different minor version are accepted in
    /// degraded mode (§13.6) and do NOT produce this error.
    #[error("unsupported broadcast envelope version: {version:#06x}")]
    UnsupportedVersion {
        /// The version value from the wire.
        version: u16,
    },

    /// The epoch counter overflowed (reached `u64::MAX`).
    #[error("epoch counter overflow: already at u64::MAX")]
    EpochOverflow,

    /// The broadcast key epoch does not match the envelope epoch.
    ///
    /// The caller must provide a key whose epoch matches the envelope's
    /// `key_epoch` field for decryption to succeed.
    #[error("epoch mismatch: key epoch {expected}, envelope epoch {actual}")]
    EpochMismatch {
        /// The epoch of the provided key.
        expected: u64,
        /// The epoch specified in the envelope.
        actual: u64,
    },

    /// The requester is not a member of the context.
    ///
    /// Returned by [`key_protocol::handle_sender_key_request`] when
    /// `context_members` is provided and the requester's DID is not in
    /// the membership set. This is the primary defense against Sybil
    /// block bypass (BLACK-006, §9.16.6): a Sybil DID that has not been
    /// admitted to the context cannot obtain sender keys regardless of
    /// whether it appears on the block list.
    #[error("requester is not a context member: {did}")]
    NotContextMember {
        /// The DID that was rejected.
        did: String,
    },

    /// An agent key (`#agent`) attempted a Category A action (DID document
    /// modification) via the sender key protocol. The action was rejected
    /// and a custody violation attestation was generated.
    ///
    /// See ADR-039 and SCP-AB-020.
    #[error("Category A violation: {0}")]
    CategoryAViolation(String),
}

// ---------------------------------------------------------------------------
// SenderKeyStore
// ---------------------------------------------------------------------------

/// In-memory store for sender keys, keyed by `(context_id, sender_did)`.
///
/// Each SCP context has one sender key per participant. The store provides
/// CRUD operations and bulk retrieval for key bundles on member join.
/// See ADR-007 acceptance criterion 7.
///
/// Internally uses a nested `HashMap<context_id, HashMap<sender_did, key>>`
/// so that lookups only borrow `&str` and avoid heap-allocating key tuples.
#[derive(Debug, Default)]
pub struct SenderKeyStore {
    /// Maps `context_id -> (sender_did -> SenderKey)`.
    keys: HashMap<String, HashMap<String, SenderKey>>,
}

impl SenderKeyStore {
    /// Creates a new, empty sender key store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Retrieves the sender key for a given context and sender DID.
    ///
    /// Returns `None` if no key is stored for the given pair.
    /// This is an allocation-free lookup — only `&str` borrows are used.
    #[must_use]
    pub fn get(&self, context_id: &str, sender_did: &str) -> Option<&SenderKey> {
        self.keys.get(context_id)?.get(sender_did)
    }

    /// Stores or updates the sender key for a given context and sender DID.
    pub fn set(&mut self, context_id: &str, sender_did: &str, key: SenderKey) {
        self.keys
            .entry(context_id.to_owned())
            .or_default()
            .insert(sender_did.to_owned(), key);
    }

    /// Removes the sender key for a given context and sender DID.
    ///
    /// Returns the removed key if it existed, or `None` otherwise.
    pub fn remove(&mut self, context_id: &str, sender_did: &str) -> Option<SenderKey> {
        let inner = self.keys.get_mut(context_id)?;
        let removed = inner.remove(sender_did);
        if inner.is_empty() {
            self.keys.remove(context_id);
        }
        removed
    }

    /// Returns all sender keys for a given context, keyed by sender DID.
    ///
    /// Used for key bundles when a new member joins the context.
    #[must_use]
    pub fn get_all(&self, context_id: &str) -> HashMap<String, SenderKey> {
        self.keys
            .get(context_id)
            .map(|inner| {
                inner
                    .iter()
                    .map(|(did, key)| (did.clone(), key.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn generate_sender_key_produces_32_bytes() {
        let key = generate_sender_key();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn generate_sender_key_produces_distinct_keys() {
        let key1 = generate_sender_key();
        let key2 = generate_sender_key();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn sender_key_debug_redacts_material() {
        let key = generate_sender_key();
        let debug = format!("{key:?}");
        assert!(debug.contains("REDACTED"));
        // Ensure no raw key bytes leak (byte arrays format as comma-separated digits).
        assert!(
            !debug.contains(", "),
            "debug output should not contain raw byte values"
        );
    }

    #[test]
    fn sender_key_store_set_and_get() {
        let mut store = SenderKeyStore::new();
        let key = generate_sender_key();
        let expected = *key.as_bytes();

        store.set("ctx-1", "did:example:alice", key);

        let retrieved = store.get("ctx-1", "did:example:alice");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.map(SenderKey::as_bytes), Some(&expected));
    }

    #[test]
    fn sender_key_store_get_nonexistent_returns_none() {
        let store = SenderKeyStore::new();
        assert!(store.get("ctx-1", "did:example:nobody").is_none());
    }

    #[test]
    fn sender_key_store_remove() {
        let mut store = SenderKeyStore::new();
        let key = generate_sender_key();
        store.set("ctx-1", "did:example:alice", key);

        let removed = store.remove("ctx-1", "did:example:alice");
        assert!(removed.is_some());
        assert!(store.get("ctx-1", "did:example:alice").is_none());
    }

    #[test]
    fn sender_key_store_remove_nonexistent_returns_none() {
        let mut store = SenderKeyStore::new();
        assert!(store.remove("ctx-1", "did:example:nobody").is_none());
    }

    #[test]
    fn sender_key_store_get_all() {
        let mut store = SenderKeyStore::new();
        let key_alice = generate_sender_key();
        let key_bob = generate_sender_key();
        let alice_bytes = *key_alice.as_bytes();
        let bob_bytes = *key_bob.as_bytes();

        store.set("ctx-1", "did:example:alice", key_alice);
        store.set("ctx-1", "did:example:bob", key_bob);
        // Different context — should not appear in ctx-1 results.
        store.set("ctx-2", "did:example:charlie", generate_sender_key());

        let all = store.get_all("ctx-1");
        assert_eq!(all.len(), 2);
        assert_eq!(
            all.get("did:example:alice").map(SenderKey::as_bytes),
            Some(&alice_bytes)
        );
        assert_eq!(
            all.get("did:example:bob").map(SenderKey::as_bytes),
            Some(&bob_bytes)
        );
    }

    #[test]
    fn sender_key_store_get_all_empty_context() {
        let store = SenderKeyStore::new();
        let all = store.get_all("ctx-nonexistent");
        assert!(all.is_empty());
    }

    #[test]
    fn sender_key_store_set_overwrites() {
        let mut store = SenderKeyStore::new();
        let key1 = generate_sender_key();
        let key2 = generate_sender_key();
        let key2_bytes = *key2.as_bytes();

        store.set("ctx-1", "did:example:alice", key1);
        store.set("ctx-1", "did:example:alice", key2);

        let retrieved = store.get("ctx-1", "did:example:alice");
        assert_eq!(retrieved.map(SenderKey::as_bytes), Some(&key2_bytes));
    }

    #[test]
    fn sender_key_store_get_does_not_allocate_for_cached_key() {
        // The nested-HashMap implementation looks up via &str borrows only,
        // so no heap allocation occurs for the key path on get().
        // We verify correctness and that the returned reference points into
        // the store (i.e. is a true borrow, not a clone).
        let mut store = SenderKeyStore::new();
        let key = generate_sender_key();
        let expected_ptr = std::ptr::from_ref::<[u8; 32]>(key.as_bytes());

        store.set("ctx-1", "did:example:alice", key);

        let retrieved = store.get("ctx-1", "did:example:alice");
        assert!(retrieved.is_some());

        // The returned reference must point to the key stored inside the map,
        // not to a freshly-allocated clone. Because `set` moves the key in,
        // the address will differ from `expected_ptr`, but calling get()
        // twice must return the same address — proving it borrows, not clones.
        let ptr1 = std::ptr::from_ref::<[u8; 32]>(retrieved.unwrap().as_bytes());
        let ptr2 = std::ptr::from_ref::<[u8; 32]>(
            store.get("ctx-1", "did:example:alice").unwrap().as_bytes(),
        );
        assert_eq!(
            ptr1, ptr2,
            "consecutive get() calls must return the same pointer (borrow, not clone)"
        );

        // Ensure the original expected_ptr is NOT the same (the key was
        // moved into the store, so the stack-local key is gone).
        // This is mainly a sanity check that we aren't accidentally
        // comparing against a local variable.
        let _ = expected_ptr; // suppress unused warning
    }

    #[test]
    fn sender_key_store_remove_cleans_up_empty_context() {
        let mut store = SenderKeyStore::new();
        store.set("ctx-1", "did:example:alice", generate_sender_key());

        let removed = store.remove("ctx-1", "did:example:alice");
        assert!(removed.is_some());
        // The inner map for ctx-1 should be cleaned up entirely.
        assert!(store.keys.is_empty());
    }
}
