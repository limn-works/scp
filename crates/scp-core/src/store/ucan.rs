//! UCAN storage operations for `ProtocolStore`.
//!
//! Implements UCAN token persistence and revocation tracking following
//! the key convention from spec section 17.3:
//!
//! ```text
//! context/{context_id}/ucan_token/{token_id}
//! context/{context_id}/ucan_revocation/{token_id}
//! ```
//!
//! Nonce replay prevention has been refactored into `store/nonce.rs`
//! per spec section 17.4 Module Structure (see SCP-PERSIST-011).
//!
//! See spec sections 17.3 and 17.4.

use scp_platform::traits::Storage;

use super::{ProtocolStore, StoreError};

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Builds the storage key for a UCAN token body.
///
/// Format: `context/{context_id}/ucan_token/{token_id}`
/// See spec section 17.3.
fn ucan_token_key(context_id: &str, token_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    let tok = super::sanitize_key_component(token_id)?;
    Ok(format!("context/{ctx}/ucan_token/{tok}"))
}

/// Builds the prefix for listing all UCAN tokens in a context.
///
/// Format: `context/{context_id}/ucan_token/`
fn ucan_token_prefix(context_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/ucan_token/"))
}

/// Builds the storage key for a UCAN revocation entry.
///
/// Format: `context/{context_id}/ucan_revocation/{token_id}`
/// See spec section 17.3.
fn revocation_key(context_id: &str, token_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    let tok = super::sanitize_key_component(token_id)?;
    Ok(format!("context/{ctx}/ucan_revocation/{tok}"))
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
        let key = ucan_token_key(context_id, token_id)?;
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
        let key = ucan_token_key(context_id, token_id)?;
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
        let key = ucan_token_key(context_id, token_id)?;
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
        let prefix = ucan_token_prefix(context_id)?;
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
        let key = revocation_key(context_id, token_id)?;
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
        let key = revocation_key(context_id, token_id)?;
        Ok(self.storage.exists(&key).await?)
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
        let loaded = store.load_ucan_token("ctx-1", "nonexistent").await.unwrap();
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

        let loaded_1 = store.load_ucan_token("ctx-1", "tok-shared").await.unwrap();
        let loaded_2 = store.load_ucan_token("ctx-2", "tok-shared").await.unwrap();
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
    // Key convention tests
    // -------------------------------------------------------------------

    #[test]
    fn ucan_token_key_follows_convention() {
        assert_eq!(
            ucan_token_key("ctx-123", "tok-abc").unwrap(),
            "context/ctx-123/ucan_token/tok-abc"
        );
    }

    #[test]
    fn ucan_token_prefix_follows_convention() {
        assert_eq!(
            ucan_token_prefix("ctx-123").unwrap(),
            "context/ctx-123/ucan_token/"
        );
    }

    #[test]
    fn revocation_key_follows_convention() {
        assert_eq!(
            revocation_key("ctx-123", "tok-abc").unwrap(),
            "context/ctx-123/ucan_revocation/tok-abc"
        );
    }
}
