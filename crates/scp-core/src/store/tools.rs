//! Tool storage operations for `ProtocolStore`.
//!
//! Implements tool registration and session persistence following the key
//! convention from spec section 17.3:
//!
//! ```text
//! context/{context_id}/tool/{tool_id}
//! context/{context_id}/tool_session/{session_id}
//! ```
//!
//! See spec sections 17.3 and 17.4.

use scp_platform::traits::Storage;

use super::{ProtocolStore, StoreError};

// ---------------------------------------------------------------------------
// Type aliases (matching the codebase convention)
// ---------------------------------------------------------------------------

/// Tool identifier. Matches `type ToolId = String` used elsewhere
/// in the codebase (e.g., `context/tools/mod.rs`).
type ToolId = String;

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Builds the storage key for a tool registration.
///
/// Format: `context/{context_id}/tool/{tool_id}`
/// See spec section 17.3.
fn tool_key(context_id: &str, tool_id: &str) -> String {
    format!("context/{context_id}/tool/{tool_id}")
}

/// Builds the prefix for listing all tools in a context.
///
/// Format: `context/{context_id}/tool/`
fn tools_prefix(context_id: &str) -> String {
    format!("context/{context_id}/tool/")
}

/// Builds the storage key for a tool session.
///
/// Format: `context/{context_id}/tool_session/{session_id}`
/// See spec section 17.3.
fn tool_session_key(context_id: &str, session_id: &str) -> String {
    format!("context/{context_id}/tool_session/{session_id}")
}

// ---------------------------------------------------------------------------
// ProtocolStore — tool methods
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolStore<S> {
    /// Stores a tool registration within a context.
    ///
    /// The registration data is serialized under
    /// `context/{context_id}/tool/{tool_id}`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_tool(
        &self,
        context_id: &str,
        tool_id: &str,
        registration: &[u8],
    ) -> Result<(), StoreError> {
        let key = tool_key(context_id, tool_id);
        self.store_value(&key, &registration.to_vec()).await
    }

    /// Loads a tool registration from a context.
    ///
    /// Returns `None` if no tool with the given ID exists in the context.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_tool(
        &self,
        context_id: &str,
        tool_id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = tool_key(context_id, tool_id);
        self.load_value(&key).await
    }

    /// Lists all tool IDs registered in a context.
    ///
    /// Returns tool ID strings extracted from stored keys.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    pub async fn list_tools(&self, context_id: &str) -> Result<Vec<ToolId>, StoreError> {
        let prefix = tools_prefix(context_id);
        let keys = self.storage.list_keys(&prefix).await?;
        let tool_ids: Vec<ToolId> = keys
            .into_iter()
            .filter_map(|key| key.strip_prefix(&prefix).map(String::from))
            .collect();
        Ok(tool_ids)
    }

    /// Deletes a tool registration from a context.
    ///
    /// No-op if the tool does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage delete fails.
    pub async fn delete_tool(
        &self,
        context_id: &str,
        tool_id: &str,
    ) -> Result<(), StoreError> {
        let key = tool_key(context_id, tool_id);
        self.storage.delete(&key).await?;
        Ok(())
    }

    /// Stores a tool session within a context.
    ///
    /// The session data is serialized under
    /// `context/{context_id}/tool_session/{session_id}`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_tool_session(
        &self,
        context_id: &str,
        session_id: &str,
        session: &[u8],
    ) -> Result<(), StoreError> {
        let key = tool_session_key(context_id, session_id);
        self.store_value(&key, &session.to_vec()).await
    }

    /// Loads a tool session from a context.
    ///
    /// Returns `None` if no session with the given ID exists.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_tool_session(
        &self,
        context_id: &str,
        session_id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = tool_session_key(context_id, session_id);
        self.load_value(&key).await
    }

    /// Deletes a tool session from a context.
    ///
    /// No-op if the session does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage delete fails.
    pub async fn delete_tool_session(
        &self,
        context_id: &str,
        session_id: &str,
    ) -> Result<(), StoreError> {
        let key = tool_session_key(context_id, session_id);
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
    // Tool registration
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_tool_roundtrip() {
        let store = make_store();
        let registration = b"tool-registration-data".to_vec();

        store
            .store_tool("ctx-1", "tool-abc", &registration)
            .await
            .unwrap();
        let loaded = store.load_tool("ctx-1", "tool-abc").await.unwrap();
        assert_eq!(loaded, Some(registration));
    }

    #[tokio::test]
    async fn load_tool_returns_none_for_missing() {
        let store = make_store();
        let loaded = store.load_tool("ctx-1", "nonexistent").await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn list_tools_returns_all_tool_ids() {
        let store = make_store();

        store
            .store_tool("ctx-1", "calculator", b"calc")
            .await
            .unwrap();
        store
            .store_tool("ctx-1", "search", b"search")
            .await
            .unwrap();
        store
            .store_tool("ctx-1", "weather", b"weather")
            .await
            .unwrap();

        let tools = store.list_tools("ctx-1").await.unwrap();
        assert_eq!(tools, vec!["calculator", "search", "weather"]);
    }

    #[tokio::test]
    async fn delete_tool_removes_registration() {
        let store = make_store();

        store
            .store_tool("ctx-1", "tool-abc", b"data")
            .await
            .unwrap();
        store.delete_tool("ctx-1", "tool-abc").await.unwrap();

        let loaded = store.load_tool("ctx-1", "tool-abc").await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn tools_are_context_scoped() {
        let store = make_store();

        store
            .store_tool("ctx-1", "tool-abc", b"data-1")
            .await
            .unwrap();
        store
            .store_tool("ctx-2", "tool-abc", b"data-2")
            .await
            .unwrap();

        let loaded_1 = store.load_tool("ctx-1", "tool-abc").await.unwrap();
        let loaded_2 = store.load_tool("ctx-2", "tool-abc").await.unwrap();
        assert_eq!(loaded_1, Some(b"data-1".to_vec()));
        assert_eq!(loaded_2, Some(b"data-2".to_vec()));
    }

    // -------------------------------------------------------------------
    // Tool sessions
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_tool_session_roundtrip() {
        let store = make_store();
        let session = b"session-state-data".to_vec();

        store
            .store_tool_session("ctx-1", "sess-123", &session)
            .await
            .unwrap();
        let loaded = store
            .load_tool_session("ctx-1", "sess-123")
            .await
            .unwrap();
        assert_eq!(loaded, Some(session));
    }

    #[tokio::test]
    async fn load_tool_session_returns_none_for_missing() {
        let store = make_store();
        let loaded = store
            .load_tool_session("ctx-1", "nonexistent")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn delete_tool_session_removes_session() {
        let store = make_store();

        store
            .store_tool_session("ctx-1", "sess-123", b"data")
            .await
            .unwrap();
        store
            .delete_tool_session("ctx-1", "sess-123")
            .await
            .unwrap();

        let loaded = store
            .load_tool_session("ctx-1", "sess-123")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    // -------------------------------------------------------------------
    // Key convention tests
    // -------------------------------------------------------------------

    #[test]
    fn tool_key_follows_convention() {
        assert_eq!(
            tool_key("ctx-123", "tool-abc"),
            "context/ctx-123/tool/tool-abc"
        );
    }

    #[test]
    fn tool_session_key_follows_convention() {
        assert_eq!(
            tool_session_key("ctx-123", "sess-456"),
            "context/ctx-123/tool_session/sess-456"
        );
    }
}
