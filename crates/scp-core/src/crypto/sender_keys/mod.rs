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
//! - [`encrypt`] — AES-256-GCM encrypt and decrypt operations.
//!
//! # Key Types
//!
//! - [`SenderKey`] — Opaque 32-byte AES-256 key handle.
//! - [`SenderKeyStore`] — In-memory store keyed by `(context_id, sender_did)`.
//! - [`SenderKeyError`] — Error type for sender key operations.

pub mod encrypt;
pub mod key_protocol;

use std::collections::HashMap;

use rand::RngCore;
use rand::rngs::OsRng;

pub use encrypt::{decrypt_sender_layer, encrypt_sender_layer};
pub use key_protocol::{
    BlockNotification, RotateForBlockResult, SenderKeyEpochAdvance, SenderKeyRequest,
    SenderKeyRequestResult, SenderKeyResponse, handle_sender_key_request, open_sender_key_response,
    publish_sender_key_epoch_advance, request_sender_key, rotate_sender_key_for_block,
    send_block_notification, verify_block_notification, verify_epoch_advance,
    verify_sender_key_request,
};

// ---------------------------------------------------------------------------
// SenderKey
// ---------------------------------------------------------------------------

/// Opaque handle for a 32-byte AES-256 sender key.
///
/// Sender keys are used to encrypt messages before MLS group encryption,
/// enabling per-relationship blocking. See ADR-007.
#[derive(Clone)]
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
}

// ---------------------------------------------------------------------------
// SenderKeyStore
// ---------------------------------------------------------------------------

/// In-memory store for sender keys, keyed by `(context_id, sender_did)`.
///
/// Each SCP context has one sender key per participant. The store provides
/// CRUD operations and bulk retrieval for key bundles on member join.
/// See ADR-007 acceptance criterion 7.
#[derive(Debug, Default)]
pub struct SenderKeyStore {
    /// Maps `(context_id, sender_did)` to the sender's current key.
    keys: HashMap<(String, String), SenderKey>,
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
    #[must_use]
    pub fn get(&self, context_id: &str, sender_did: &str) -> Option<&SenderKey> {
        self.keys
            .get(&(context_id.to_owned(), sender_did.to_owned()))
    }

    /// Stores or updates the sender key for a given context and sender DID.
    pub fn set(&mut self, context_id: &str, sender_did: &str, key: SenderKey) {
        self.keys
            .insert((context_id.to_owned(), sender_did.to_owned()), key);
    }

    /// Removes the sender key for a given context and sender DID.
    ///
    /// Returns the removed key if it existed, or `None` otherwise.
    pub fn remove(&mut self, context_id: &str, sender_did: &str) -> Option<SenderKey> {
        self.keys
            .remove(&(context_id.to_owned(), sender_did.to_owned()))
    }

    /// Returns all sender keys for a given context, keyed by sender DID.
    ///
    /// Used for key bundles when a new member joins the context.
    #[must_use]
    pub fn get_all(&self, context_id: &str) -> HashMap<String, SenderKey> {
        self.keys
            .iter()
            .filter(|((ctx, _), _)| ctx == context_id)
            .map(|((_, did), key)| (did.clone(), key.clone()))
            .collect()
    }
}

#[cfg(test)]
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
}
