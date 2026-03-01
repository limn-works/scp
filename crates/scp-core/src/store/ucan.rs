//! UCAN storage operations for `ProtocolStore`.
//!
//! Implements UCAN token persistence, revocation tracking, and nonce replay
//! prevention following the key convention from spec section 17.3:
//!
//! ```text
//! context/{context_id}/ucan_revocation/{token_id}
//! context/{context_id}/nonce/{nonce_hash}
//! ```
//!
//! Nonce keys use `SHA256(nonce_string)` hashed to a hex string for
//! fixed-length keys. The `exists()` method on `Storage` enables O(1)
//! replay checks without deserializing.
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
    /// Uses `Storage::exists()` for the check, then stores a `NonceRecord`
    /// with timestamps for later pruning.
    ///
    /// See spec section 17.3 on nonce keys and 17.4 on `check_and_record_nonce`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    pub async fn check_and_record_nonce(
        &self,
        context_id: &str,
        nonce_hash: &[u8; 32],
        first_seen: u64,
        token_expiry: u64,
    ) -> Result<bool, StoreError> {
        let key = nonce_key(context_id, nonce_hash);
        if self.storage.exists(&key).await? {
            return Ok(false);
        }
        let record = NonceRecord {
            first_seen,
            token_expiry,
        };
        self.store_value(&key, &record).await?;
        Ok(true)
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
    // Key convention tests
    // -------------------------------------------------------------------

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
