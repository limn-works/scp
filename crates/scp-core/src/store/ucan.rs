//! UCAN token storage operations for `ProtocolStore`.
//!
//! Implements UCAN token persistence following the key convention from
//! spec section 17.3:
//!
//! ```text
//! ucan/{context_id}/tokens/{token_id}
//! ```
//!
//! All key components are validated through [`sanitize_key_component`] to
//! prevent path traversal attacks (e.g., a malicious `context_id` like
//! `"../../secrets"`).
//!
//! See spec sections 17.3, 17.4, and ADR-016.

use scp_platform::traits::Storage;

use super::{ProtocolStore, StoreError, sanitize_key_component};

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Builds the storage key for a UCAN token.
///
/// Format: `ucan/{context_id}/tokens/{token_id}`
/// See spec section 17.3.
///
/// Both `context_id` and `token_id` are validated through
/// [`sanitize_key_component`] to reject path traversal characters.
///
/// # Errors
///
/// Returns [`StoreError::SerializationFailed`] if either component contains
/// forbidden characters (`/`, `\`, `..`, or `\0`).
fn ucan_token_key(context_id: &str, token_id: &str) -> Result<String, StoreError> {
    let ctx = sanitize_key_component(context_id)?;
    let tok = sanitize_key_component(token_id)?;
    Ok(format!("ucan/{ctx}/tokens/{tok}"))
}

/// Builds the prefix for listing all UCAN tokens in a context.
///
/// Format: `ucan/{context_id}/tokens/`
///
/// # Errors
///
/// Returns [`StoreError::SerializationFailed`] if `context_id` contains
/// forbidden characters.
fn ucan_tokens_prefix(context_id: &str) -> Result<String, StoreError> {
    let ctx = sanitize_key_component(context_id)?;
    Ok(format!("ucan/{ctx}/tokens/"))
}

// ---------------------------------------------------------------------------
// ProtocolStore -- UCAN token methods
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolStore<S> {
    /// Stores a UCAN token for a context.
    ///
    /// Stores raw token bytes under `ucan/{context_id}/tokens/{token_id}`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if `context_id` or
    /// `token_id` contain path traversal characters.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_ucan_token(
        &self,
        context_id: &str,
        token_id: &str,
        token_data: &[u8],
    ) -> Result<(), StoreError> {
        let key = ucan_token_key(context_id, token_id)?;
        self.storage.store(&key, token_data).await?;
        Ok(())
    }

    /// Loads a UCAN token for a context.
    ///
    /// Returns `None` if no token exists for the given pair.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if `context_id` or
    /// `token_id` contain path traversal characters.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_ucan_token(
        &self,
        context_id: &str,
        token_id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = ucan_token_key(context_id, token_id)?;
        Ok(self.storage.retrieve(&key).await?)
    }

    /// Lists all UCAN token IDs for a context.
    ///
    /// Returns `token_id` strings extracted from the stored keys.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if `context_id` contains
    /// path traversal characters.
    /// Returns [`StoreError::Storage`] if the underlying storage list fails.
    pub async fn list_ucan_tokens(&self, context_id: &str) -> Result<Vec<String>, StoreError> {
        let prefix = ucan_tokens_prefix(context_id)?;
        let keys = self.storage.list_keys(&prefix).await?;
        let token_ids: Vec<String> = keys
            .into_iter()
            .filter_map(|key| key.strip_prefix(&prefix).map(String::from))
            .collect();
        Ok(token_ids)
    }

    /// Removes a UCAN token for a context.
    ///
    /// No-op if the token does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if `context_id` or
    /// `token_id` contain path traversal characters.
    /// Returns [`StoreError::Storage`] if the underlying storage delete fails.
    pub async fn remove_ucan_token(
        &self,
        context_id: &str,
        token_id: &str,
    ) -> Result<(), StoreError> {
        let key = ucan_token_key(context_id, token_id)?;
        self.storage.delete(&key).await?;
        Ok(())
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
    // Key convention tests
    // -------------------------------------------------------------------

    #[test]
    fn ucan_token_key_follows_convention() {
        let key = ucan_token_key("ctx-abc", "tok-001").unwrap();
        assert_eq!(key, "ucan/ctx-abc/tokens/tok-001");
    }

    #[test]
    fn ucan_tokens_prefix_follows_convention() {
        let prefix = ucan_tokens_prefix("ctx-abc").unwrap();
        assert_eq!(prefix, "ucan/ctx-abc/tokens/");
    }

    // -------------------------------------------------------------------
    // Path traversal rejection tests
    // -------------------------------------------------------------------

    #[test]
    fn rejects_context_id_with_slash() {
        let err = ucan_token_key("../../secrets", "tok-001").unwrap_err();
        assert!(err.to_string().contains("forbidden characters"));
    }

    #[test]
    fn rejects_context_id_with_backslash() {
        let err = ucan_token_key("..\\secrets", "tok-001").unwrap_err();
        assert!(err.to_string().contains("forbidden characters"));
    }

    #[test]
    fn rejects_context_id_with_dot_dot() {
        let err = ucan_token_key("..", "tok-001").unwrap_err();
        assert!(err.to_string().contains("forbidden characters"));
    }

    #[test]
    fn rejects_context_id_with_null_byte() {
        let err = ucan_token_key("ctx\0evil", "tok-001").unwrap_err();
        assert!(err.to_string().contains("forbidden characters"));
    }

    #[test]
    fn rejects_token_id_with_slash() {
        let err = ucan_token_key("ctx-abc", "../other").unwrap_err();
        assert!(err.to_string().contains("forbidden characters"));
    }

    #[test]
    fn rejects_token_id_with_backslash() {
        let err = ucan_token_key("ctx-abc", "tok\\evil").unwrap_err();
        assert!(err.to_string().contains("forbidden characters"));
    }

    #[test]
    fn rejects_token_id_with_dot_dot() {
        let err = ucan_token_key("ctx-abc", "..").unwrap_err();
        assert!(err.to_string().contains("forbidden characters"));
    }

    #[test]
    fn rejects_token_id_with_null_byte() {
        let err = ucan_token_key("ctx-abc", "tok\0evil").unwrap_err();
        assert!(err.to_string().contains("forbidden characters"));
    }

    #[test]
    fn rejects_prefix_with_traversal() {
        let err = ucan_tokens_prefix("../../secrets").unwrap_err();
        assert!(err.to_string().contains("forbidden characters"));
    }

    // -------------------------------------------------------------------
    // Store/load roundtrip tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_ucan_token_roundtrip() {
        let store = make_store();
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];

        store
            .store_ucan_token("ctx-abc", "tok-001", &data)
            .await
            .unwrap();

        let loaded = store.load_ucan_token("ctx-abc", "tok-001").await.unwrap();
        assert_eq!(loaded, Some(data));
    }

    #[tokio::test]
    async fn load_nonexistent_token_returns_none() {
        let store = make_store();

        let loaded = store.load_ucan_token("ctx-abc", "missing").await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn list_ucan_tokens_returns_token_ids() {
        let store = make_store();

        store
            .store_ucan_token("ctx-abc", "tok-001", &[1])
            .await
            .unwrap();
        store
            .store_ucan_token("ctx-abc", "tok-002", &[2])
            .await
            .unwrap();

        let mut ids = store.list_ucan_tokens("ctx-abc").await.unwrap();
        ids.sort();
        assert_eq!(ids, vec!["tok-001", "tok-002"]);
    }

    #[tokio::test]
    async fn remove_ucan_token_deletes() {
        let store = make_store();

        store
            .store_ucan_token("ctx-abc", "tok-001", &[1])
            .await
            .unwrap();
        store.remove_ucan_token("ctx-abc", "tok-001").await.unwrap();

        let loaded = store.load_ucan_token("ctx-abc", "tok-001").await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn tokens_isolated_between_contexts() {
        let store = make_store();

        store
            .store_ucan_token("ctx-a", "tok-001", &[0xAA])
            .await
            .unwrap();
        store
            .store_ucan_token("ctx-b", "tok-001", &[0xBB])
            .await
            .unwrap();

        let loaded_a = store.load_ucan_token("ctx-a", "tok-001").await.unwrap();
        let loaded_b = store.load_ucan_token("ctx-b", "tok-001").await.unwrap();

        assert_eq!(loaded_a, Some(vec![0xAA]));
        assert_eq!(loaded_b, Some(vec![0xBB]));
    }

    #[tokio::test]
    async fn store_rejects_traversal_context_id() {
        let store = make_store();
        let err = store
            .store_ucan_token("../../secrets", "tok-001", &[1])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("forbidden characters"));
    }

    #[tokio::test]
    async fn store_rejects_traversal_token_id() {
        let store = make_store();
        let err = store
            .store_ucan_token("ctx-abc", "../evil", &[1])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("forbidden characters"));
    }
}
