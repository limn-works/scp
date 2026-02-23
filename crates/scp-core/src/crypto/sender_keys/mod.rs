//! Sender-side key layer for per-sender encryption. See ADR-007.
//!
//! Each sender maintains an AES-256 symmetric key that encrypts their messages
//! before MLS group encryption. This enables per-relationship blocking: rotating
//! the sender key and redistributing to everyone except the blocked party makes
//! future messages from the blocker unreadable to the blocked party without
//! removing them from the MLS group.
//!
//! Wire format: `nonce (12 bytes) || ciphertext || auth_tag (16 bytes)`.

pub mod encrypt;

use std::collections::HashMap;

use rand::RngCore;
use tokio::sync::RwLock;

pub use encrypt::{decrypt_sender_layer, encrypt_sender_layer};

/// A 32-byte AES-256 symmetric key used for sender-side encryption.
///
/// See ADR-007 criterion 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderKey(pub(crate) [u8; 32]);

impl SenderKey {
    /// Returns a reference to the raw 32-byte key material.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Creates a `SenderKey` from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Generates a random 32-byte AES-256 sender key.
///
/// See ADR-007 criterion 1.
#[must_use]
pub fn generate_sender_key() -> SenderKey {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    SenderKey(key)
}

/// Errors that can occur during sender-key operations.
#[derive(Debug, thiserror::Error)]
pub enum SenderKeyError {
    /// AES-256-GCM encryption failed.
    #[error("sender key encryption failed")]
    EncryptionFailed,

    /// AES-256-GCM decryption failed (wrong key or tampered ciphertext).
    #[error("sender key decryption failed: authentication tag mismatch")]
    DecryptionFailed,

    /// Ciphertext is too short to contain a valid nonce + auth tag.
    #[error("ciphertext too short: {len} bytes, minimum {min}")]
    CiphertextTooShort {
        /// Actual length received.
        len: usize,
        /// Minimum required length (nonce + auth tag = 28 bytes).
        min: usize,
    },
}

/// Composite key for the sender key store: `(context_id, sender_did)`.
type StoreKey = (String, String);

/// In-memory store for sender keys, keyed by `(context_id, sender_did)`.
///
/// Phase 1 uses an in-memory `HashMap` behind a `tokio::sync::RwLock`.
/// Production implementations will use persistent storage.
///
/// See ADR-007 criterion 7.
#[derive(Debug)]
pub struct SenderKeyStore {
    keys: RwLock<HashMap<StoreKey, SenderKey>>,
}

impl Default for SenderKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SenderKeyStore {
    /// Creates a new empty `SenderKeyStore`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }

    /// Retrieves the sender key for the given context and sender DID.
    ///
    /// Returns `None` if no key is stored for this pair.
    pub async fn get(&self, context_id: &str, sender_did: &str) -> Option<SenderKey> {
        let keys = self.keys.read().await;
        keys.get(&(context_id.to_owned(), sender_did.to_owned()))
            .cloned()
    }

    /// Stores or updates the sender key for the given context and sender DID.
    pub async fn set(&self, context_id: &str, sender_did: &str, key: SenderKey) {
        let mut keys = self.keys.write().await;
        keys.insert((context_id.to_owned(), sender_did.to_owned()), key);
    }

    /// Removes the sender key for the given context and sender DID.
    ///
    /// After removal, [`get`](Self::get) returns `None` for this pair.
    pub async fn remove(&self, context_id: &str, sender_did: &str) {
        let mut keys = self.keys.write().await;
        keys.remove(&(context_id.to_owned(), sender_did.to_owned()));
    }

    /// Returns all sender keys for a given context, keyed by sender DID.
    ///
    /// Useful for building a key bundle when a new member joins.
    pub async fn get_all(&self, context_id: &str) -> HashMap<String, SenderKey> {
        let keys = self.keys.read().await;
        keys.iter()
            .filter(|((ctx, _), _)| ctx == context_id)
            .map(|((_, did), key)| (did.clone(), key.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_sender_key_produces_32_byte_key() {
        let key = generate_sender_key();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn generate_sender_key_produces_distinct_keys() {
        let k1 = generate_sender_key();
        let k2 = generate_sender_key();
        assert_ne!(k1, k2);
    }

    #[test]
    fn sender_key_from_bytes_roundtrip() {
        let bytes = [42u8; 32];
        let key = SenderKey::from_bytes(bytes);
        assert_eq!(*key.as_bytes(), bytes);
    }

    #[tokio::test]
    async fn store_get_set_roundtrip() {
        let store = SenderKeyStore::new();
        let key = generate_sender_key();
        store.set("ctx-1", "did:dht:alice", key.clone()).await;
        let retrieved = store.get("ctx-1", "did:dht:alice").await;
        assert_eq!(retrieved, Some(key));
    }

    #[tokio::test]
    async fn store_get_returns_none_for_unknown() {
        let store = SenderKeyStore::new();
        assert_eq!(store.get("ctx-1", "did:dht:unknown").await, None);
    }

    #[tokio::test]
    async fn store_remove_makes_get_return_none() {
        let store = SenderKeyStore::new();
        let key = generate_sender_key();
        store.set("ctx-1", "did:dht:alice", key).await;
        store.remove("ctx-1", "did:dht:alice").await;
        assert_eq!(store.get("ctx-1", "did:dht:alice").await, None);
    }

    #[tokio::test]
    async fn store_remove_nonexistent_is_noop() {
        let store = SenderKeyStore::new();
        store.remove("ctx-1", "did:dht:ghost").await;
        // No panic, no error — just a no-op
    }

    #[tokio::test]
    async fn store_get_all_returns_all_keys_for_context() {
        let store = SenderKeyStore::new();
        let key_a = generate_sender_key();
        let key_b = generate_sender_key();
        let key_other = generate_sender_key();

        store.set("ctx-1", "did:dht:alice", key_a.clone()).await;
        store.set("ctx-1", "did:dht:bob", key_b.clone()).await;
        store.set("ctx-2", "did:dht:carol", key_other.clone()).await;

        let all = store.get_all("ctx-1").await;
        assert_eq!(all.len(), 2);
        assert_eq!(all.get("did:dht:alice"), Some(&key_a));
        assert_eq!(all.get("did:dht:bob"), Some(&key_b));
    }

    #[tokio::test]
    async fn store_get_all_returns_empty_for_unknown_context() {
        let store = SenderKeyStore::new();
        let all = store.get_all("ctx-unknown").await;
        assert!(all.is_empty());
    }

    #[tokio::test]
    async fn store_set_overwrites_existing_key() {
        let store = SenderKeyStore::new();
        let key1 = generate_sender_key();
        let key2 = generate_sender_key();

        store.set("ctx-1", "did:dht:alice", key1).await;
        store.set("ctx-1", "did:dht:alice", key2.clone()).await;

        let retrieved = store.get("ctx-1", "did:dht:alice").await;
        assert_eq!(retrieved, Some(key2));
    }

    #[tokio::test]
    async fn store_isolates_contexts() {
        let store = SenderKeyStore::new();
        let key1 = generate_sender_key();
        let key2 = generate_sender_key();

        store.set("ctx-1", "did:dht:alice", key1.clone()).await;
        store.set("ctx-2", "did:dht:alice", key2.clone()).await;

        assert_eq!(store.get("ctx-1", "did:dht:alice").await, Some(key1));
        assert_eq!(store.get("ctx-2", "did:dht:alice").await, Some(key2));
    }
}
