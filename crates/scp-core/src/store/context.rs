//! Context storage operations for `ProtocolStore`.
//!
//! Implements context state CRUD following the key convention from
//! spec section 17.3:
//!
//! ```text
//! context/{context_id}/state
//! context/{context_id}/params
//! context/{context_id}/membership/{did}
//! context/{context_id}/role/{role_name}
//! ```
//!
//! See spec sections 17.3 and 17.4.

use scp_platform::traits::Storage;

use crate::identity::DID;

use super::{ProtocolStore, StoreError};

// ---------------------------------------------------------------------------
// Type aliases (matching the codebase convention)
// ---------------------------------------------------------------------------

/// Context identifier. Matches `type ContextId = String` used elsewhere
/// in the codebase (e.g., `sync/mod.rs`, `event_log/mod.rs`).
type ContextId = String;

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Builds the storage key for context state.
///
/// Format: `context/{context_id}/state`
/// See spec section 17.3.
fn context_state_key(context_id: &str) -> String {
    format!("context/{context_id}/state")
}

/// Builds the storage key for context params.
///
/// Format: `context/{context_id}/params`
/// See spec section 17.3.
fn context_params_key(context_id: &str) -> String {
    format!("context/{context_id}/params")
}

/// Builds the storage key for a member's membership record.
///
/// Format: `context/{context_id}/membership/{did}`
/// See spec section 17.3.
fn membership_key(context_id: &str, did: &DID) -> String {
    format!("context/{context_id}/membership/{did}")
}

/// Builds the prefix for listing all memberships in a context.
///
/// Format: `context/{context_id}/membership/`
fn membership_prefix(context_id: &str) -> String {
    format!("context/{context_id}/membership/")
}

/// Builds the storage key for a role definition within a context.
///
/// Format: `context/{context_id}/role/{role_name}`
/// See spec section 17.3.
fn role_key(context_id: &str, role_name: &str) -> String {
    format!("context/{context_id}/role/{role_name}")
}

/// Builds the prefix for listing all roles in a context.
///
/// Format: `context/{context_id}/role/`
fn roles_prefix(context_id: &str) -> String {
    format!("context/{context_id}/role/")
}

/// Builds the prefix for all keys belonging to a context.
///
/// Format: `context/{context_id}/`
fn context_prefix(context_id: &str) -> String {
    format!("context/{context_id}/")
}

// ---------------------------------------------------------------------------
// ProtocolStore — context methods
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolStore<S> {
    /// Stores the state for a context.
    ///
    /// Serializes context state bytes under `context/{context_id}/state`
    /// wrapped in a `StoredValue` version envelope.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_context_state(
        &self,
        context_id: &str,
        state: &[u8],
    ) -> Result<(), StoreError> {
        let key = context_state_key(context_id);
        self.store_value(&key, &state.to_vec()).await
    }

    /// Loads the state for a context.
    ///
    /// Returns `None` if no state exists for the given context.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_context_state(
        &self,
        context_id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = context_state_key(context_id);
        self.load_value(&key).await
    }

    /// Stores the parameters for a context.
    ///
    /// Serializes context params bytes under `context/{context_id}/params`
    /// wrapped in a `StoredValue` version envelope.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_context_params(
        &self,
        context_id: &str,
        params: &[u8],
    ) -> Result<(), StoreError> {
        let key = context_params_key(context_id);
        self.store_value(&key, &params.to_vec()).await
    }

    /// Loads the parameters for a context.
    ///
    /// Returns `None` if no params exist for the given context.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_context_params(
        &self,
        context_id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = context_params_key(context_id);
        self.load_value(&key).await
    }

    /// Deletes all stored state for a context.
    ///
    /// Removes all keys under `context/{context_id}/` including state,
    /// params, memberships, roles, events, tools, etc. Returns the
    /// number of keys deleted.
    ///
    /// See spec section 17.3 on context cleanup via `delete_prefix`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    pub async fn delete_context(&self, context_id: &str) -> Result<u64, StoreError> {
        let prefix = context_prefix(context_id);
        Ok(self.storage.delete_prefix(&prefix).await?)
    }

    /// Lists all active context IDs.
    ///
    /// Scans for keys matching `context/*/state` by listing all keys
    /// with the `context/` prefix and extracting unique context IDs.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    pub async fn list_active_contexts(&self) -> Result<Vec<ContextId>, StoreError> {
        let keys = self.storage.list_keys("context/").await?;
        let mut context_ids: Vec<ContextId> = keys
            .into_iter()
            .filter_map(|key| {
                let rest = key.strip_prefix("context/")?;
                if rest.ends_with("/state") {
                    let id = rest.strip_suffix("/state")?;
                    Some(id.to_owned())
                } else {
                    None
                }
            })
            .collect();
        context_ids.sort();
        context_ids.dedup();
        Ok(context_ids)
    }

    /// Stores a membership record for a DID within a context.
    ///
    /// The role string is serialized under
    /// `context/{context_id}/membership/{did}`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_membership(
        &self,
        context_id: &str,
        did: &DID,
        role: &str,
    ) -> Result<(), StoreError> {
        let key = membership_key(context_id, did);
        self.store_value(&key, &role.to_owned()).await
    }

    /// Loads the membership role for a DID within a context.
    ///
    /// Returns `None` if the DID is not a member of the context.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_membership(
        &self,
        context_id: &str,
        did: &DID,
    ) -> Result<Option<String>, StoreError> {
        let key = membership_key(context_id, did);
        self.load_value(&key).await
    }

    /// Lists all members and their roles for a context.
    ///
    /// Returns a vector of `(DID, role_string)` pairs.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    /// Returns [`StoreError::DeserializationFailed`] if any member record fails
    /// to deserialize.
    pub async fn list_members(&self, context_id: &str) -> Result<Vec<(DID, String)>, StoreError> {
        let prefix = membership_prefix(context_id);
        let keys = self.storage.list_keys(&prefix).await?;
        let mut members = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(did_str) = key.strip_prefix(&prefix) {
                let did = DID::from(did_str);
                if let Some(role) = self.load_membership(context_id, &did).await? {
                    members.push((did, role));
                }
            }
        }
        Ok(members)
    }

    /// Removes a membership record for a DID within a context.
    ///
    /// No-op if the membership does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage delete fails.
    pub async fn remove_membership(&self, context_id: &str, did: &DID) -> Result<(), StoreError> {
        let key = membership_key(context_id, did);
        self.storage.delete(&key).await?;
        Ok(())
    }

    /// Stores a role definition within a context.
    ///
    /// The role data is serialized under
    /// `context/{context_id}/role/{role_name}`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_role(
        &self,
        context_id: &str,
        role_name: &str,
        role_data: &[u8],
    ) -> Result<(), StoreError> {
        let key = role_key(context_id, role_name);
        self.store_value(&key, &role_data.to_vec()).await
    }

    /// Loads a role definition from a context.
    ///
    /// Returns `None` if the role does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_role(
        &self,
        context_id: &str,
        role_name: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = role_key(context_id, role_name);
        self.load_value(&key).await
    }

    /// Lists all role names defined in a context.
    ///
    /// Returns role name strings extracted from stored keys.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    pub async fn list_roles(&self, context_id: &str) -> Result<Vec<String>, StoreError> {
        let prefix = roles_prefix(context_id);
        let keys = self.storage.list_keys(&prefix).await?;
        let role_names: Vec<String> = keys
            .into_iter()
            .filter_map(|key| key.strip_prefix(&prefix).map(String::from))
            .collect();
        Ok(role_names)
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

    fn test_did() -> DID {
        DID::from("did:dht:z6MkTestMember")
    }

    // -------------------------------------------------------------------
    // Context state
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_context_state_roundtrip() {
        let store = make_store();
        let state = b"context-state-data".to_vec();

        store.store_context_state("ctx-1", &state).await.unwrap();
        let loaded = store.load_context_state("ctx-1").await.unwrap();
        assert_eq!(loaded, Some(state));
    }

    #[tokio::test]
    async fn load_context_state_returns_none_for_missing() {
        let store = make_store();
        let loaded = store.load_context_state("nonexistent").await.unwrap();
        assert!(loaded.is_none());
    }

    // -------------------------------------------------------------------
    // Context params
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_context_params_roundtrip() {
        let store = make_store();
        let params = b"context-params-data".to_vec();

        store.store_context_params("ctx-1", &params).await.unwrap();
        let loaded = store.load_context_params("ctx-1").await.unwrap();
        assert_eq!(loaded, Some(params));
    }

    #[tokio::test]
    async fn load_context_params_returns_none_for_missing() {
        let store = make_store();
        let loaded = store.load_context_params("nonexistent").await.unwrap();
        assert!(loaded.is_none());
    }

    // -------------------------------------------------------------------
    // Context deletion
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn delete_context_removes_all_state() {
        let store = make_store();
        let did = test_did();

        store.store_context_state("ctx-1", b"state").await.unwrap();
        store
            .store_context_params("ctx-1", b"params")
            .await
            .unwrap();
        store
            .store_membership("ctx-1", &did, "member")
            .await
            .unwrap();
        store
            .store_role("ctx-1", "admin", b"role-data")
            .await
            .unwrap();

        let deleted = store.delete_context("ctx-1").await.unwrap();
        assert!(deleted >= 4);

        assert!(store.load_context_state("ctx-1").await.unwrap().is_none());
        assert!(store.load_context_params("ctx-1").await.unwrap().is_none());
        assert!(
            store
                .load_membership("ctx-1", &did)
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.load_role("ctx-1", "admin").await.unwrap().is_none());
    }

    // -------------------------------------------------------------------
    // Active contexts listing
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn list_active_contexts_returns_context_ids() {
        let store = make_store();

        store
            .store_context_state("ctx-a", b"state-a")
            .await
            .unwrap();
        store
            .store_context_state("ctx-b", b"state-b")
            .await
            .unwrap();
        store
            .store_context_params("ctx-c", b"params-only")
            .await
            .unwrap();

        let contexts = store.list_active_contexts().await.unwrap();
        assert_eq!(contexts, vec!["ctx-a", "ctx-b"]);
    }

    // -------------------------------------------------------------------
    // Membership
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_membership_roundtrip() {
        let store = make_store();
        let did = test_did();

        store
            .store_membership("ctx-1", &did, "admin")
            .await
            .unwrap();
        let role = store.load_membership("ctx-1", &did).await.unwrap();
        assert_eq!(role, Some("admin".to_owned()));
    }

    #[tokio::test]
    async fn load_membership_returns_none_for_non_member() {
        let store = make_store();
        let did = test_did();

        let role = store.load_membership("ctx-1", &did).await.unwrap();
        assert!(role.is_none());
    }

    #[tokio::test]
    async fn list_members_returns_all_members() {
        let store = make_store();
        let did_a = DID::from("did:dht:z6MkAlice");
        let did_b = DID::from("did:dht:z6MkBob");

        store
            .store_membership("ctx-1", &did_a, "admin")
            .await
            .unwrap();
        store
            .store_membership("ctx-1", &did_b, "member")
            .await
            .unwrap();

        let mut members = store.list_members("ctx-1").await.unwrap();
        members.sort_by(|a, b| a.0.cmp(&b.0));

        assert_eq!(members.len(), 2);
        assert_eq!(members[0], (did_a, "admin".to_owned()));
        assert_eq!(members[1], (did_b, "member".to_owned()));
    }

    #[tokio::test]
    async fn remove_membership_deletes_member() {
        let store = make_store();
        let did = test_did();

        store
            .store_membership("ctx-1", &did, "member")
            .await
            .unwrap();
        store.remove_membership("ctx-1", &did).await.unwrap();

        let role = store.load_membership("ctx-1", &did).await.unwrap();
        assert!(role.is_none());
    }

    // -------------------------------------------------------------------
    // Roles
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_role_roundtrip() {
        let store = make_store();
        let role_data = b"role-definition-bytes".to_vec();

        store
            .store_role("ctx-1", "moderator", &role_data)
            .await
            .unwrap();
        let loaded = store.load_role("ctx-1", "moderator").await.unwrap();
        assert_eq!(loaded, Some(role_data));
    }

    #[tokio::test]
    async fn list_roles_returns_all_role_names() {
        let store = make_store();

        store
            .store_role("ctx-1", "admin", b"admin-data")
            .await
            .unwrap();
        store
            .store_role("ctx-1", "member", b"member-data")
            .await
            .unwrap();
        store
            .store_role("ctx-1", "viewer", b"viewer-data")
            .await
            .unwrap();

        let roles = store.list_roles("ctx-1").await.unwrap();
        assert_eq!(roles, vec!["admin", "member", "viewer"]);
    }

    // -------------------------------------------------------------------
    // Key convention tests
    // -------------------------------------------------------------------

    #[test]
    fn context_state_key_follows_convention() {
        assert_eq!(context_state_key("ctx-123"), "context/ctx-123/state");
    }

    #[test]
    fn context_params_key_follows_convention() {
        assert_eq!(context_params_key("ctx-123"), "context/ctx-123/params");
    }

    #[test]
    fn membership_key_follows_convention() {
        let did = DID::from("did:dht:z6MkTest");
        assert_eq!(
            membership_key("ctx-123", &did),
            "context/ctx-123/membership/did:dht:z6MkTest"
        );
    }

    #[test]
    fn role_key_follows_convention() {
        assert_eq!(role_key("ctx-123", "admin"), "context/ctx-123/role/admin");
    }
}
