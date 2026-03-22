//! Access key storage operations for `ProtocolRepository`.
//!
//! Implements access key persistence following the key convention from
//! spec section 17.3:
//!
//! ```text
//! context/{context_id}/access_key/{did_hex}
//! context/{context_id}/access_key/{did_hex}/epoch
//! ```
//!
//! The `{did_hex}` component is a hex-encoded SHA-256 hash of the member's
//! DID, avoiding issues with DID characters (`:`, etc.) in storage keys
//! while providing consistent key lengths.
//!
//! See spec §9.17 and ADR-038 §2.

use scp_platform::traits::Storage;
use sha2::{Digest, Sha256};

use crate::crypto::access_keys::AccessKey;

use super::{ProtocolRepository, StoreError, sanitize_key_component};

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Computes a hex-encoded SHA-256 hash of a DID for use as a storage key
/// component.
///
/// DIDs contain `:` characters which are valid in storage keys but could
/// cause issues with some storage backends. Hashing provides a consistent,
/// safe key component.
fn did_hex(did: &str) -> String {
    let hash = Sha256::digest(did.as_bytes());
    hex::encode(hash)
}

/// Builds the storage key for a member's access key.
///
/// Format: `context/{context_id}/access_key/{did_hex}`
fn access_key_key(context_id: &str, member_did: &str) -> Result<String, StoreError> {
    let ctx = sanitize_key_component(context_id)?;
    let did_hash = did_hex(member_did);
    Ok(format!("context/{ctx}/access_key/{did_hash}"))
}

/// Builds the storage key for a member's access key epoch counter.
///
/// Format: `context/{context_id}/access_key/{did_hex}/epoch`
fn access_key_epoch_key(context_id: &str, member_did: &str) -> Result<String, StoreError> {
    let ctx = sanitize_key_component(context_id)?;
    let did_hash = did_hex(member_did);
    Ok(format!("context/{ctx}/access_key/{did_hash}/epoch"))
}

// ---------------------------------------------------------------------------
// ProtocolRepository impl
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolRepository<S> {
    /// Stores a member's access key.
    ///
    /// Uses zeroizing storage to prevent key material from lingering in
    /// memory after the write completes.
    ///
    /// Also persists the epoch counter separately for fast epoch lookups
    /// without deserializing the full access key.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if the context ID
    /// contains path traversal characters.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_access_key(&self, access_key: &AccessKey) -> Result<(), StoreError> {
        let key = access_key_key(access_key.context_id(), access_key.member_did())?;
        let epoch_key = access_key_epoch_key(access_key.context_id(), access_key.member_did())?;

        self.store_value_zeroize(&key, access_key).await?;
        self.store_value(&epoch_key, &access_key.epoch()).await?;
        Ok(())
    }

    /// Loads a member's access key.
    ///
    /// Returns `None` if no access key is stored for the given context
    /// and member.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if the context ID
    /// contains path traversal characters.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_access_key(
        &self,
        context_id: &str,
        member_did: &str,
    ) -> Result<Option<AccessKey>, StoreError> {
        let key = access_key_key(context_id, member_did)?;
        self.load_value(&key).await
    }

    /// Loads the epoch counter for a member's access key.
    ///
    /// Returns `None` if no epoch is stored for the given context and member.
    /// This is a lightweight operation that does not deserialize the full
    /// access key.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if the context ID
    /// contains path traversal characters.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_access_key_epoch(
        &self,
        context_id: &str,
        member_did: &str,
    ) -> Result<Option<u64>, StoreError> {
        let key = access_key_epoch_key(context_id, member_did)?;
        self.load_value(&key).await
    }

    /// Deletes a member's access key and its epoch counter.
    ///
    /// Called on revocation (spec §9.17.2 step 3). After deletion, the
    /// member cannot unwrap CEKs for any stored content.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if the context ID
    /// contains path traversal characters.
    /// Returns [`StoreError::Storage`] if the underlying storage delete fails.
    pub async fn delete_access_key(
        &self,
        context_id: &str,
        member_did: &str,
    ) -> Result<(), StoreError> {
        let key = access_key_key(context_id, member_did)?;
        let epoch_key = access_key_epoch_key(context_id, member_did)?;

        self.storage.delete(&key).await?;
        self.storage.delete(&epoch_key).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::access_keys::generate_access_key;

    fn make_store() -> ProtocolRepository<scp_platform::testing::InMemoryStorage> {
        ProtocolRepository::new_for_testing(scp_platform::testing::InMemoryStorage::new())
    }

    #[tokio::test]
    async fn store_and_load_access_key_roundtrip() {
        let store = make_store();
        let key = generate_access_key("ctx-1", "did:dht:alice");
        let original_bytes = *key.as_bytes();

        store.store_access_key(&key).await.unwrap();

        let loaded = store
            .load_access_key("ctx-1", "did:dht:alice")
            .await
            .unwrap();
        let loaded = loaded.expect("access key should exist");

        assert_eq!(loaded.as_bytes(), &original_bytes);
        assert_eq!(loaded.context_id(), "ctx-1");
        assert_eq!(loaded.member_did(), "did:dht:alice");
        assert_eq!(loaded.epoch(), 0);
    }

    #[tokio::test]
    async fn load_access_key_returns_none_for_missing() {
        let store = make_store();
        let loaded = store
            .load_access_key("ctx-1", "did:dht:nobody")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn store_access_key_persists_epoch() {
        let store = make_store();
        let key = generate_access_key("ctx-1", "did:dht:alice");

        store.store_access_key(&key).await.unwrap();

        let epoch = store
            .load_access_key_epoch("ctx-1", "did:dht:alice")
            .await
            .unwrap();
        assert_eq!(epoch, Some(0));
    }

    #[tokio::test]
    async fn load_access_key_epoch_returns_none_for_missing() {
        let store = make_store();
        let epoch = store
            .load_access_key_epoch("ctx-1", "did:dht:nobody")
            .await
            .unwrap();
        assert!(epoch.is_none());
    }

    #[tokio::test]
    async fn store_access_key_overwrites_existing() {
        let store = make_store();

        let key1 = generate_access_key("ctx-1", "did:dht:alice");
        store.store_access_key(&key1).await.unwrap();

        let key2 = AccessKey::from_parts(
            [42u8; 32],
            "ctx-1".to_owned(),
            "did:dht:alice".to_owned(),
            5,
        );
        store.store_access_key(&key2).await.unwrap();

        let loaded = store
            .load_access_key("ctx-1", "did:dht:alice")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.as_bytes(), &[42u8; 32]);
        assert_eq!(loaded.epoch(), 5);

        let epoch = store
            .load_access_key_epoch("ctx-1", "did:dht:alice")
            .await
            .unwrap();
        assert_eq!(epoch, Some(5));
    }

    #[tokio::test]
    async fn delete_access_key_removes_key_and_epoch() {
        let store = make_store();
        let key = generate_access_key("ctx-1", "did:dht:alice");

        store.store_access_key(&key).await.unwrap();

        // Verify it exists.
        assert!(
            store
                .load_access_key("ctx-1", "did:dht:alice")
                .await
                .unwrap()
                .is_some()
        );

        // Delete.
        store
            .delete_access_key("ctx-1", "did:dht:alice")
            .await
            .unwrap();

        // Verify both key and epoch are gone.
        assert!(
            store
                .load_access_key("ctx-1", "did:dht:alice")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .load_access_key_epoch("ctx-1", "did:dht:alice")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn delete_access_key_nonexistent_succeeds() {
        let store = make_store();
        // Deleting a nonexistent key should not error.
        store
            .delete_access_key("ctx-1", "did:dht:nobody")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn access_keys_isolated_by_context() {
        let store = make_store();

        let key1 = generate_access_key("ctx-1", "did:dht:alice");
        let key2 = generate_access_key("ctx-2", "did:dht:alice");
        let key1_bytes = *key1.as_bytes();
        let key2_bytes = *key2.as_bytes();

        store.store_access_key(&key1).await.unwrap();
        store.store_access_key(&key2).await.unwrap();

        let loaded1 = store
            .load_access_key("ctx-1", "did:dht:alice")
            .await
            .unwrap()
            .unwrap();
        let loaded2 = store
            .load_access_key("ctx-2", "did:dht:alice")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(loaded1.as_bytes(), &key1_bytes);
        assert_eq!(loaded2.as_bytes(), &key2_bytes);
    }

    #[tokio::test]
    async fn access_keys_isolated_by_member() {
        let store = make_store();

        let key_alice = generate_access_key("ctx-1", "did:dht:alice");
        let key_bob = generate_access_key("ctx-1", "did:dht:bob");
        let alice_bytes = *key_alice.as_bytes();
        let bob_bytes = *key_bob.as_bytes();

        store.store_access_key(&key_alice).await.unwrap();
        store.store_access_key(&key_bob).await.unwrap();

        let loaded_alice = store
            .load_access_key("ctx-1", "did:dht:alice")
            .await
            .unwrap()
            .unwrap();
        let loaded_bob = store
            .load_access_key("ctx-1", "did:dht:bob")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(loaded_alice.as_bytes(), &alice_bytes);
        assert_eq!(loaded_bob.as_bytes(), &bob_bytes);
    }

    #[tokio::test]
    async fn store_access_key_rejects_traversal_context_id() {
        let store = make_store();
        let key = AccessKey::from_parts(
            [0u8; 32],
            "../identity/victim".to_owned(),
            "did:dht:alice".to_owned(),
            0,
        );
        let result = store.store_access_key(&key).await;
        assert!(result.is_err());
    }
}
