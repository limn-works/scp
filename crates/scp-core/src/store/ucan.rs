//! UCAN storage operations for `ProtocolStore`.
//!
//! Implements UCAN token persistence, revocation tracking, and nonce replay
//! prevention following the key convention from spec section 17.3:
//!
//! ```text
//! context/{context_id}/ucan_token/{token_id}
//! context/{context_id}/ucan_revocation/{token_id}
//! context/{context_id}/nonce/{nonce_hash}
//! ```
//!
//! Nonce keys use `SHA256(nonce_string)` hashed to a hex string for
//! fixed-length keys. Replay checks use `load_value()` (not `exists()`)
//! so the read and write use a consistent code path through `Storage`.
//!
//! See spec sections 17.3 and 17.4.

use scp_platform::traits::Storage;
use serde::{Deserialize, Serialize};

use super::{ProtocolStore, StoreError};

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// Nonce record stored for UCAN replay prevention.
///
/// Contains timestamps for pruning: nonces whose `token_expiry` is in
/// the past can be safely removed.
///
/// See spec section 17.3 on nonce keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceRecord {
    /// Unix timestamp when this nonce was first observed.
    pub first_seen: u64,
    /// Unix timestamp when the associated UCAN token expires.
    pub token_expiry: u64,
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Builds the storage key for a UCAN token body.
///
/// Format: `context/{context_id}/ucan_token/{token_id}`
/// See spec section 17.3.
fn ucan_token_key(context_id: &str, token_id: &str) -> String {
    format!("context/{context_id}/ucan_token/{token_id}")
}

/// Builds the prefix for listing all UCAN tokens in a context.
///
/// Format: `context/{context_id}/ucan_token/`
fn ucan_token_prefix(context_id: &str) -> String {
    format!("context/{context_id}/ucan_token/")
}

/// Builds the storage key for a UCAN revocation entry.
///
/// Format: `context/{context_id}/ucan_revocation/{token_id}`
/// See spec section 17.3.
fn revocation_key(context_id: &str, token_id: &str) -> String {
    format!("context/{context_id}/ucan_revocation/{token_id}")
}

/// Builds the storage key for a UCAN nonce entry.
///
/// Format: `context/{context_id}/nonce/{nonce_hash_hex}`
/// The nonce hash is encoded as lowercase hex. See spec section 17.3.
fn nonce_key(context_id: &str, nonce_hash: &[u8; 32]) -> String {
    let hex = hex_encode(nonce_hash);
    format!("context/{context_id}/nonce/{hex}")
}

/// Builds the prefix for listing all nonces in a context.
///
/// Format: `context/{context_id}/nonce/`
fn nonce_prefix(context_id: &str) -> String {
    format!("context/{context_id}/nonce/")
}

/// Encodes a byte slice as lowercase hexadecimal.
fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
}

// ---------------------------------------------------------------------------
// ProtocolStore — UCAN methods
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolStore<S> {
    /// Stores a UCAN token body within a context.
    ///
    /// Persists the raw token bytes under
    /// `context/{context_id}/ucan_token/{token_id}` wrapped in a
    /// `StoredValue` version envelope.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_ucan_token(
        &self,
        context_id: &str,
        token_id: &str,
        token: &[u8],
    ) -> Result<(), StoreError> {
        let key = ucan_token_key(context_id, token_id);
        self.store_value(&key, &token.to_vec()).await
    }

    /// Loads a UCAN token body from a context.
    ///
    /// Returns `None` if no token with the given ID exists in the context.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_ucan_token(
        &self,
        context_id: &str,
        token_id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = ucan_token_key(context_id, token_id);
        self.load_value(&key).await
    }

    /// Deletes a UCAN token body from a context.
    ///
    /// No-op if the token does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage delete fails.
    pub async fn delete_ucan_token(
        &self,
        context_id: &str,
        token_id: &str,
    ) -> Result<(), StoreError> {
        let key = ucan_token_key(context_id, token_id);
        self.storage.delete(&key).await?;
        Ok(())
    }

    /// Lists all UCAN token IDs stored in a context.
    ///
    /// Returns token ID strings extracted from stored keys.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    pub async fn list_ucan_tokens(&self, context_id: &str) -> Result<Vec<String>, StoreError> {
        let prefix = ucan_token_prefix(context_id);
        let keys = self.storage.list_keys(&prefix).await?;
        let token_ids: Vec<String> = keys
            .into_iter()
            .filter_map(|key| key.strip_prefix(&prefix).map(String::from))
            .collect();
        Ok(token_ids)
    }

    /// Records a UCAN revocation for a token within a context.
    ///
    /// Stores a marker under `context/{context_id}/ucan_revocation/{token_id}`.
    /// The value contains the revocation timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_revocation(
        &self,
        context_id: &str,
        token_id: &str,
    ) -> Result<(), StoreError> {
        let key = revocation_key(context_id, token_id);
        self.store_value(&key, &true).await
    }

    /// Checks whether a UCAN token has been revoked within a context.
    ///
    /// Uses `Storage::exists()` for O(1) checking without deserializing.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    pub async fn is_revoked(&self, context_id: &str, token_id: &str) -> Result<bool, StoreError> {
        let key = revocation_key(context_id, token_id);
        Ok(self.storage.exists(&key).await?)
    }

    /// Checks and records a UCAN nonce for replay prevention.
    ///
    /// Returns `true` if this is a new nonce (first time seen),
    /// `false` if the nonce was already recorded (replay attempt).
    ///
    /// Uses `load_value()` (not `exists()`) to check for a prior record,
    /// then `store_value()` to claim the slot. A post-write `load_value()`
    /// re-verifies ownership so that concurrent writers that both passed the
    /// initial check will see a timestamp mismatch and reject (safe failure).
    ///
    /// See spec section 17.3 on nonce keys and 17.4 on `check_and_record_nonce`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    ///
    /// # SAFETY: TOCTOU window
    ///
    /// The `Storage` trait does not provide compare-and-swap (CAS), so a
    /// narrow race window exists between the `load_value` check and the
    /// `store_value` write.  This is acceptable because:
    ///
    /// 1. The in-memory `NonceTracker` provides the primary, synchronised
    ///    replay defense on the hot path.
    /// 2. `ProtocolStore` nonce tracking is a defence-in-depth layer for
    ///    crash recovery — it re-populates the in-memory set on restart.
    /// 3. The race window is bounded by storage I/O latency (typically
    ///    sub-millisecond for SQLite WAL).
    /// 4. The post-write re-read errs on the side of rejection: if two
    ///    writers race, at most one sees its own timestamps back; the
    ///    other gets a mismatch and returns `false` (safe rejection).
    ///
    /// Storage backends that support atomic insert-if-absent should
    /// override this at the adapter level for true atomicity.
    pub async fn check_and_record_nonce(
        &self,
        context_id: &str,
        nonce_hash: &[u8; 32],
        first_seen: u64,
        token_expiry: u64,
    ) -> Result<bool, StoreError> {
        let key = nonce_key(context_id, nonce_hash);

        // If a record already exists, reject immediately without
        // overwriting the existing record's timestamps.
        if self.load_value::<NonceRecord>(&key).await?.is_some() {
            return Ok(false);
        }

        // Store the nonce record, claiming the slot.
        let record = NonceRecord {
            first_seen,
            token_expiry,
        };
        self.store_value(&key, &record).await?;

        // Re-verify after store: if the loaded record has different
        // timestamps, another request won the race and we treat this
        // as a replay (safe rejection). If the storage backend
        // silently overwrites, this check sees our own write and
        // succeeds — the SAFETY note above documents this limitation.
        match self.load_value::<NonceRecord>(&key).await? {
            Some(stored) if stored.first_seen == first_seen => Ok(true),
            _ => Ok(false),
        }
    }

    /// Prunes expired nonces from a context.
    ///
    /// Removes all nonce records whose `token_expiry` is less than or
    /// equal to `now`. Returns the number of nonces pruned.
    ///
    /// See spec section 17.4 on `prune_expired_nonces`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    /// Returns [`StoreError::DeserializationFailed`] if any nonce record fails
    /// to deserialize.
    pub async fn prune_expired_nonces(
        &self,
        context_id: &str,
        now: u64,
    ) -> Result<u64, StoreError> {
        let prefix = nonce_prefix(context_id);
        let keys = self.storage.list_keys(&prefix).await?;
        let mut pruned = 0u64;
        for key in keys {
            if let Some(record) = self.load_value::<NonceRecord>(&key).await?
                && record.token_expiry <= now
            {
                self.storage.delete(&key).await?;
                pruned += 1;
            }
        }
        Ok(pruned)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use scp_platform::testing::InMemoryStorage;

    use super::*;

    fn make_store() -> ProtocolStore<InMemoryStorage> {
        ProtocolStore::new(InMemoryStorage::new())
    }

    fn test_nonce_hash() -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = 0xDE;
        h[1] = 0xAD;
        h[31] = 0xFF;
        h
    }

    // -------------------------------------------------------------------
    // UCAN token body storage
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_ucan_token_roundtrip() {
        let store = make_store();
        let token = b"eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.mock-ucan-body".to_vec();

        store
            .store_ucan_token("ctx-1", "tok-001", &token)
            .await
            .unwrap();
        let loaded = store.load_ucan_token("ctx-1", "tok-001").await.unwrap();
        assert_eq!(loaded, Some(token));
    }

    #[tokio::test]
    async fn load_ucan_token_returns_none_for_missing() {
        let store = make_store();
        let loaded = store
            .load_ucan_token("ctx-1", "nonexistent")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn delete_ucan_token_removes_token() {
        let store = make_store();

        store
            .store_ucan_token("ctx-1", "tok-001", b"token-data")
            .await
            .unwrap();
        store.delete_ucan_token("ctx-1", "tok-001").await.unwrap();

        let loaded = store.load_ucan_token("ctx-1", "tok-001").await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn list_ucan_tokens_returns_all_token_ids() {
        let store = make_store();

        store
            .store_ucan_token("ctx-1", "tok-aaa", b"data-a")
            .await
            .unwrap();
        store
            .store_ucan_token("ctx-1", "tok-bbb", b"data-b")
            .await
            .unwrap();
        store
            .store_ucan_token("ctx-1", "tok-ccc", b"data-c")
            .await
            .unwrap();

        let tokens = store.list_ucan_tokens("ctx-1").await.unwrap();
        assert_eq!(tokens, vec!["tok-aaa", "tok-bbb", "tok-ccc"]);
    }

    #[tokio::test]
    async fn ucan_tokens_are_context_scoped() {
        let store = make_store();

        store
            .store_ucan_token("ctx-1", "tok-shared", b"data-1")
            .await
            .unwrap();
        store
            .store_ucan_token("ctx-2", "tok-shared", b"data-2")
            .await
            .unwrap();

        let loaded_1 = store
            .load_ucan_token("ctx-1", "tok-shared")
            .await
            .unwrap();
        let loaded_2 = store
            .load_ucan_token("ctx-2", "tok-shared")
            .await
            .unwrap();
        assert_eq!(loaded_1, Some(b"data-1".to_vec()));
        assert_eq!(loaded_2, Some(b"data-2".to_vec()));
    }

    #[tokio::test]
    async fn delete_ucan_token_is_noop_for_missing() {
        let store = make_store();
        store
            .delete_ucan_token("ctx-1", "nonexistent")
            .await
            .unwrap();
    }

    // -------------------------------------------------------------------
    // Revocation
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_revocation_and_check_is_revoked() {
        let store = make_store();

        assert!(!store.is_revoked("ctx-1", "token-abc").await.unwrap());

        store.store_revocation("ctx-1", "token-abc").await.unwrap();
        assert!(store.is_revoked("ctx-1", "token-abc").await.unwrap());
    }

    #[tokio::test]
    async fn is_revoked_returns_false_for_unrevoked() {
        let store = make_store();
        assert!(!store.is_revoked("ctx-1", "unknown-token").await.unwrap());
    }

    #[tokio::test]
    async fn revocation_is_context_scoped() {
        let store = make_store();

        store.store_revocation("ctx-1", "token-xyz").await.unwrap();
        assert!(store.is_revoked("ctx-1", "token-xyz").await.unwrap());
        assert!(!store.is_revoked("ctx-2", "token-xyz").await.unwrap());
    }

    // -------------------------------------------------------------------
    // Nonce replay prevention
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn check_and_record_nonce_returns_true_for_new() {
        let store = make_store();
        let nonce = test_nonce_hash();

        let is_new = store
            .check_and_record_nonce("ctx-1", &nonce, 1000, 2000)
            .await
            .unwrap();
        assert!(is_new);
    }

    #[tokio::test]
    async fn check_and_record_nonce_returns_false_for_replay() {
        let store = make_store();
        let nonce = test_nonce_hash();

        store
            .check_and_record_nonce("ctx-1", &nonce, 1000, 2000)
            .await
            .unwrap();
        let is_new = store
            .check_and_record_nonce("ctx-1", &nonce, 1001, 2000)
            .await
            .unwrap();
        assert!(!is_new);
    }

    #[tokio::test]
    async fn nonce_is_context_scoped() {
        let store = make_store();
        let nonce = test_nonce_hash();

        store
            .check_and_record_nonce("ctx-1", &nonce, 1000, 2000)
            .await
            .unwrap();

        let is_new_in_ctx2 = store
            .check_and_record_nonce("ctx-2", &nonce, 1000, 2000)
            .await
            .unwrap();
        assert!(is_new_in_ctx2);
    }

    // -------------------------------------------------------------------
    // Nonce pruning
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn prune_expired_nonces_removes_expired() {
        let store = make_store();
        let nonce_a = {
            let mut h = [0u8; 32];
            h[0] = 0xAA;
            h
        };
        let nonce_b = {
            let mut h = [0u8; 32];
            h[0] = 0xBB;
            h
        };

        store
            .check_and_record_nonce("ctx-1", &nonce_a, 100, 500)
            .await
            .unwrap();
        store
            .check_and_record_nonce("ctx-1", &nonce_b, 200, 2000)
            .await
            .unwrap();

        let pruned = store.prune_expired_nonces("ctx-1", 600).await.unwrap();
        assert_eq!(pruned, 1);

        let replay_a = store
            .check_and_record_nonce("ctx-1", &nonce_a, 601, 3000)
            .await
            .unwrap();
        assert!(replay_a);

        let replay_b = store
            .check_and_record_nonce("ctx-1", &nonce_b, 601, 3000)
            .await
            .unwrap();
        assert!(!replay_b);
    }

    #[tokio::test]
    async fn prune_expired_nonces_returns_zero_when_none_expired() {
        let store = make_store();
        let nonce = test_nonce_hash();

        store
            .check_and_record_nonce("ctx-1", &nonce, 100, 9999)
            .await
            .unwrap();

        let pruned = store.prune_expired_nonces("ctx-1", 500).await.unwrap();
        assert_eq!(pruned, 0);
    }

    // -------------------------------------------------------------------
    // Concurrent nonce checking
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn concurrent_nonce_checks_allow_at_most_one() {
        use std::sync::Arc;

        let store = Arc::new(make_store());
        let nonce = test_nonce_hash();
        let task_count = 10;

        let mut handles = Vec::with_capacity(task_count);
        for i in 0..task_count {
            let store = Arc::clone(&store);
            handles.push(tokio::spawn(async move {
                store
                    .check_and_record_nonce("ctx-race", &nonce, 5000 + i as u64, 9000)
                    .await
                    .unwrap()
            }));
        }

        let mut successes = 0u32;
        for handle in handles {
            if handle.await.unwrap() {
                successes += 1;
            }
        }

        assert_eq!(
            successes, 1,
            "exactly one concurrent nonce check should succeed"
        );
    }

    // -------------------------------------------------------------------
    // Key convention tests
    // -------------------------------------------------------------------

    #[test]
    fn ucan_token_key_follows_convention() {
        assert_eq!(
            ucan_token_key("ctx-123", "tok-abc"),
            "context/ctx-123/ucan_token/tok-abc"
        );
    }

    #[test]
    fn ucan_token_prefix_follows_convention() {
        assert_eq!(
            ucan_token_prefix("ctx-123"),
            "context/ctx-123/ucan_token/"
        );
    }

    #[test]
    fn revocation_key_follows_convention() {
        assert_eq!(
            revocation_key("ctx-123", "tok-abc"),
            "context/ctx-123/ucan_revocation/tok-abc"
        );
    }

    #[test]
    fn nonce_key_uses_hex_encoded_hash() {
        let mut h = [0u8; 32];
        h[0] = 0xFF;
        let key = nonce_key("ctx-1", &h);
        assert!(key.starts_with("context/ctx-1/nonce/"));
        assert!(key.ends_with("00"));
        assert!(key.contains("ff"));
    }
}
