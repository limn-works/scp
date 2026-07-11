//! Outlet storage operations for `ProtocolRepository`.
//!
//! Implements outlet registration and session persistence following the key
//! convention from spec section 17.3:
//!
//! ```text
//! context/{context_id}/outlet/{outlet_id}
//! context/{context_id}/outlet_session/{session_id}
//! ```
//!
//! See spec sections 17.3 and 17.4.

use scp_platform::traits::Storage;

use super::{ProtocolRepository, StoreError};

// ---------------------------------------------------------------------------
// Type aliases (matching the codebase convention)
// ---------------------------------------------------------------------------

/// Outlet identifier. Matches `type OutletId = String` used elsewhere
/// in the codebase (e.g., `context/outlets/mod.rs`).
type OutletId = String;

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Builds the storage key for a outlet registration.
///
/// Format: `context/{context_id}/outlet/{outlet_id}`
/// See spec section 17.3.
fn outlet_key(context_id: &str, outlet_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    let outlet = super::sanitize_key_component(outlet_id)?;
    Ok(format!("context/{ctx}/outlet/{outlet}"))
}

/// Builds the prefix for listing all outlets in a context.
///
/// Format: `context/{context_id}/outlet/`
fn outlets_prefix(context_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/outlet/"))
}

/// Builds the storage key for a outlet session.
///
/// Format: `context/{context_id}/outlet_session/{session_id}`
/// See spec section 17.3.
fn outlet_session_key(context_id: &str, session_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    let sess = super::sanitize_key_component(session_id)?;
    Ok(format!("context/{ctx}/outlet_session/{sess}"))
}

// ---------------------------------------------------------------------------
// ProtocolRepository — outlet methods
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolRepository<S> {
    /// Stores a outlet registration within a context.
    ///
    /// The registration data is serialized under
    /// `context/{context_id}/outlet/{outlet_id}`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_outlet(
        &self,
        context_id: &str,
        outlet_id: &str,
        registration: &[u8],
    ) -> Result<(), StoreError> {
        let key = outlet_key(context_id, outlet_id)?;
        self.store_value(&key, &registration.to_vec()).await
    }

    /// Loads a outlet registration from a context.
    ///
    /// Returns `None` if no outlet with the given ID exists in the context.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_outlet(
        &self,
        context_id: &str,
        outlet_id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = outlet_key(context_id, outlet_id)?;
        self.load_value(&key).await
    }

    /// Lists all outlet IDs registered in a context.
    ///
    /// Returns outlet ID strings extracted from stored keys.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    pub async fn list_outlets(&self, context_id: &str) -> Result<Vec<OutletId>, StoreError> {
        let prefix = outlets_prefix(context_id)?;
        let keys = self.storage.list_keys(&prefix).await?;
        let outlet_ids: Vec<OutletId> = keys
            .into_iter()
            .filter_map(|key| key.strip_prefix(&prefix).map(String::from))
            .collect();
        Ok(outlet_ids)
    }

    /// Deletes a outlet registration from a context.
    ///
    /// No-op if the outlet does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage delete fails.
    pub async fn delete_outlet(&self, context_id: &str, outlet_id: &str) -> Result<(), StoreError> {
        let key = outlet_key(context_id, outlet_id)?;
        self.storage.delete(&key).await?;
        Ok(())
    }

    /// Stores a outlet session within a context.
    ///
    /// The session data is serialized under
    /// `context/{context_id}/outlet_session/{session_id}`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_outlet_session(
        &self,
        context_id: &str,
        session_id: &str,
        session: &[u8],
    ) -> Result<(), StoreError> {
        let key = outlet_session_key(context_id, session_id)?;
        self.store_value(&key, &session.to_vec()).await
    }

    /// Loads a outlet session from a context.
    ///
    /// Returns `None` if no session with the given ID exists.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_outlet_session(
        &self,
        context_id: &str,
        session_id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = outlet_session_key(context_id, session_id)?;
        self.load_value(&key).await
    }

    /// Deletes a outlet session from a context.
    ///
    /// No-op if the session does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage delete fails.
    pub async fn delete_outlet_session(
        &self,
        context_id: &str,
        session_id: &str,
    ) -> Result<(), StoreError> {
        let key = outlet_session_key(context_id, session_id)?;
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

    fn make_store() -> ProtocolRepository<InMemoryStorage> {
        ProtocolRepository::new_for_testing(InMemoryStorage::new())
    }

    // -------------------------------------------------------------------
    // Outlet registration
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_outlet_roundtrip() {
        let store = make_store();
        let registration = b"outlet-registration-data".to_vec();

        store
            .store_outlet("ctx-1", "outlet-abc", &registration)
            .await
            .unwrap();
        let loaded = store.load_outlet("ctx-1", "outlet-abc").await.unwrap();
        assert_eq!(loaded, Some(registration));
    }

    #[tokio::test]
    async fn load_outlet_returns_none_for_missing() {
        let store = make_store();
        let loaded = store.load_outlet("ctx-1", "nonexistent").await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn list_outlets_returns_all_outlet_ids() {
        let store = make_store();

        store
            .store_outlet("ctx-1", "calculator", b"calc")
            .await
            .unwrap();
        store
            .store_outlet("ctx-1", "search", b"search")
            .await
            .unwrap();
        store
            .store_outlet("ctx-1", "weather", b"weather")
            .await
            .unwrap();

        let outlets = store.list_outlets("ctx-1").await.unwrap();
        assert_eq!(outlets, vec!["calculator", "search", "weather"]);
    }

    #[tokio::test]
    async fn delete_outlet_removes_registration() {
        let store = make_store();

        store
            .store_outlet("ctx-1", "outlet-abc", b"data")
            .await
            .unwrap();
        store.delete_outlet("ctx-1", "outlet-abc").await.unwrap();

        let loaded = store.load_outlet("ctx-1", "outlet-abc").await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn outlets_are_context_scoped() {
        let store = make_store();

        store
            .store_outlet("ctx-1", "outlet-abc", b"data-1")
            .await
            .unwrap();
        store
            .store_outlet("ctx-2", "outlet-abc", b"data-2")
            .await
            .unwrap();

        let loaded_1 = store.load_outlet("ctx-1", "outlet-abc").await.unwrap();
        let loaded_2 = store.load_outlet("ctx-2", "outlet-abc").await.unwrap();
        assert_eq!(loaded_1, Some(b"data-1".to_vec()));
        assert_eq!(loaded_2, Some(b"data-2".to_vec()));
    }

    // -------------------------------------------------------------------
    // Outlet sessions
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_outlet_session_roundtrip() {
        let store = make_store();
        let session = b"session-state-data".to_vec();

        store
            .store_outlet_session("ctx-1", "sess-123", &session)
            .await
            .unwrap();
        let loaded = store
            .load_outlet_session("ctx-1", "sess-123")
            .await
            .unwrap();
        assert_eq!(loaded, Some(session));
    }

    #[tokio::test]
    async fn load_outlet_session_returns_none_for_missing() {
        let store = make_store();
        let loaded = store
            .load_outlet_session("ctx-1", "nonexistent")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn delete_outlet_session_removes_session() {
        let store = make_store();

        store
            .store_outlet_session("ctx-1", "sess-123", b"data")
            .await
            .unwrap();
        store
            .delete_outlet_session("ctx-1", "sess-123")
            .await
            .unwrap();

        let loaded = store
            .load_outlet_session("ctx-1", "sess-123")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    // -------------------------------------------------------------------
    // Key convention tests
    // -------------------------------------------------------------------

    #[test]
    fn outlet_key_follows_convention() {
        assert_eq!(
            outlet_key("ctx-123", "outlet-abc").unwrap(),
            "context/ctx-123/outlet/outlet-abc"
        );
    }

    #[test]
    fn outlet_session_key_follows_convention() {
        assert_eq!(
            outlet_session_key("ctx-123", "sess-456").unwrap(),
            "context/ctx-123/outlet_session/sess-456"
        );
    }
}
