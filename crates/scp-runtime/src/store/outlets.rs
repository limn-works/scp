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

/// Builds the storage key for an outlet registration.
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

/// Builds the storage key for an outlet session.
///
/// Format: `context/{context_id}/outlet_session/{session_id}`
/// See spec section 17.3.
fn outlet_session_key(context_id: &str, session_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    let sess = super::sanitize_key_component(session_id)?;
    Ok(format!("context/{ctx}/outlet_session/{sess}"))
}

/// Builds the storage key for a pinned per-outlet, per-registration
/// `outlet_message_key` (§5.4.4 round-5, SCP-OUT-041a).
///
/// Format:
/// `context/{context_id}/outlet/{outlet_id}/registration/{registration_event_id_hex}/message_key`
///
/// Keying by `registration_event_id` (rather than just `outlet_id`)
/// supports the SCP-OUT-041b receiver-side LRU: concurrent registrations
/// of the same outlet (e.g., mid-flight at the moment of re-registration)
/// must not overwrite each other.
fn outlet_message_key_storage_key(
    context_id: &str,
    outlet_id: &str,
    registration_event_id: &[u8; 32],
) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    let outlet = super::sanitize_key_component(outlet_id)?;
    // Hex encoding sidesteps any non-ASCII / path-separator concerns from
    // the raw 32-byte event-log id; `hex::encode` always produces a
    // 64-character `[0-9a-f]+` string, satisfying `sanitize_key_component`
    // by construction.
    let event_hex = hex::encode(registration_event_id);
    Ok(format!(
        "context/{ctx}/outlet/{outlet}/registration/{event_hex}/message_key"
    ))
}

// ---------------------------------------------------------------------------
// ProtocolRepository — outlet methods
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolRepository<S> {
    /// Stores an outlet registration within a context.
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

    /// Loads an outlet registration from a context.
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

    /// Deletes an outlet registration from a context.
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

    /// Stores an outlet session within a context.
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

    /// Loads an outlet session from a context.
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

    /// Deletes an outlet session from a context.
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

    /// Stores a 32-byte pinned `outlet_message_key` for an outlet
    /// registration (§5.4.4 round-5, SCP-OUT-041a).
    ///
    /// Persisted under
    /// `context/{context_id}/outlet/{outlet_id}/registration/{registration_event_id_hex}/message_key`.
    /// Keying by `registration_event_id` (the 32-byte event-log id of the
    /// `OutletRegistration` event) preserves prior registrations across
    /// re-registration windows — the SCP-OUT-041b receiver LRU keeps up
    /// to four most-recent registrations per outlet resolvable
    /// concurrently.
    ///
    /// The persisted bytes are wrapped in `StoredValue` and the
    /// serialization buffer is zeroized after the write completes (the
    /// 32-byte key is a long-term HMAC key for the outlet's lifetime).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_outlet_message_key(
        &self,
        context_id: &str,
        outlet_id: &str,
        registration_event_id: &[u8; 32],
        outlet_message_key: &[u8; 32],
    ) -> Result<(), StoreError> {
        let key = outlet_message_key_storage_key(context_id, outlet_id, registration_event_id)?;
        // `Vec<u8>` round-trips losslessly through the StoredValue
        // envelope; storing the array as a 32-byte vec keeps the
        // serialization shape stable.
        self.store_value_zeroize(&key, &outlet_message_key.to_vec())
            .await
    }

    /// Loads a pinned `outlet_message_key` for an outlet registration.
    ///
    /// Returns `None` if no key has been pinned for the given
    /// `(context_id, outlet_id, registration_event_id)` triple.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if the stored bytes
    /// are not a 32-byte payload. Returns [`StoreError::Storage`] if the
    /// underlying read fails.
    pub async fn load_outlet_message_key(
        &self,
        context_id: &str,
        outlet_id: &str,
        registration_event_id: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, StoreError> {
        let key = outlet_message_key_storage_key(context_id, outlet_id, registration_event_id)?;
        let raw: Option<Vec<u8>> = self.load_value(&key).await?;
        match raw {
            None => Ok(None),
            Some(bytes) if bytes.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                Ok(Some(out))
            }
            Some(bytes) => Err(StoreError::DeserializationFailed(format!(
                "outlet_message_key must be 32 bytes, got {len}",
                len = bytes.len()
            ))),
        }
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

    // -------------------------------------------------------------------
    // Outlet message keys (§5.4.4 round-5, SCP-OUT-041a)
    // -------------------------------------------------------------------

    #[test]
    fn outlet_message_key_storage_key_follows_spec_convention() {
        let event_id = [0xABu8; 32];
        let key = outlet_message_key_storage_key("ctx-123", "calculator", &event_id).unwrap();
        let expected = format!(
            "context/ctx-123/outlet/calculator/registration/{}/message_key",
            "ab".repeat(32)
        );
        assert_eq!(key, expected);
    }

    #[tokio::test]
    async fn store_and_load_outlet_message_key_roundtrip() {
        let store = make_store();
        let event_id = [0x11u8; 32];
        let key = [0x42u8; 32];
        store
            .store_outlet_message_key("ctx-1", "calculator", &event_id, &key)
            .await
            .unwrap();
        let loaded = store
            .load_outlet_message_key("ctx-1", "calculator", &event_id)
            .await
            .unwrap();
        assert_eq!(loaded, Some(key));
    }

    #[tokio::test]
    async fn load_outlet_message_key_returns_none_for_missing() {
        let store = make_store();
        let event_id = [0x22u8; 32];
        let loaded = store
            .load_outlet_message_key("ctx-1", "calculator", &event_id)
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn outlet_message_keys_are_keyed_by_registration_event_id() {
        // Concurrent registrations of the same outlet (different
        // registration_event_id values) must NOT overwrite each other.
        // This is the SCP-OUT-041b LRU prerequisite.
        let store = make_store();
        let event_id_a = [0x33u8; 32];
        let event_id_b = [0x44u8; 32];
        let key_a = [0xAAu8; 32];
        let key_b = [0xBBu8; 32];
        store
            .store_outlet_message_key("ctx-1", "calculator", &event_id_a, &key_a)
            .await
            .unwrap();
        store
            .store_outlet_message_key("ctx-1", "calculator", &event_id_b, &key_b)
            .await
            .unwrap();
        let loaded_a = store
            .load_outlet_message_key("ctx-1", "calculator", &event_id_a)
            .await
            .unwrap();
        let loaded_b = store
            .load_outlet_message_key("ctx-1", "calculator", &event_id_b)
            .await
            .unwrap();
        assert_eq!(loaded_a, Some(key_a));
        assert_eq!(loaded_b, Some(key_b));
        assert_ne!(loaded_a, loaded_b);
    }

    #[tokio::test]
    async fn outlet_message_keys_are_context_scoped() {
        // Same outlet_id + same registration_event_id in two contexts:
        // each context's store has its own independent path, so writes
        // do not leak across.
        let store = make_store();
        let event_id = [0x55u8; 32];
        let key_one = [0x10u8; 32];
        let key_two = [0x20u8; 32];
        store
            .store_outlet_message_key("ctx-1", "calculator", &event_id, &key_one)
            .await
            .unwrap();
        store
            .store_outlet_message_key("ctx-2", "calculator", &event_id, &key_two)
            .await
            .unwrap();
        let loaded_one = store
            .load_outlet_message_key("ctx-1", "calculator", &event_id)
            .await
            .unwrap();
        let loaded_two = store
            .load_outlet_message_key("ctx-2", "calculator", &event_id)
            .await
            .unwrap();
        assert_eq!(loaded_one, Some(key_one));
        assert_eq!(loaded_two, Some(key_two));
    }
}
