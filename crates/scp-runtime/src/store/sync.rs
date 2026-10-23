//! Reconnection sync state for `ProtocolRepository`.
//!
//! Stores the last successful relay contact per context under the ADR-029
//! key `sync/{context_id}/last_relay_contact`, as local Unix seconds. The
//! push-wake pull (ADR-029 §2, push-wake pull mode) reads it to set the
//! relay QUERY `since`. Three paths write it: a full reconnection after it
//! clears `needs_reconnect`, a push-wake pull after a context's Phase 1 query
//! succeeds, and a live subscription after the actor accepts a delivered
//! envelope (ADR-029 Implementation).
//!
//! [`RelayContactStore`] is the dyn-compatible view the FFI bridge layer
//! holds, because `ProtocolRepository<S>` is generic over a storage backend
//! that is not dyn-compatible.

use scp_platform::traits::Storage;

use super::{ProtocolRepository, StoreError};

/// Builds the storage key for a context's last relay contact.
///
/// Format: `sync/{context_id}/last_relay_contact` (ADR-029 Implementation).
///
/// # Errors
///
/// Returns [`StoreError::SerializationFailed`] when `context_id` contains a
/// character `sanitize_key_component` forbids.
fn last_relay_contact_key(context_id: &str) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("sync/{ctx}/last_relay_contact"))
}

impl<S: Storage> ProtocolRepository<S> {
    /// Stores the last successful relay contact for `context_id`, in local
    /// Unix seconds, replacing any earlier value.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] for a `context_id` the key
    /// convention rejects, and [`StoreError::Storage`] when the write fails.
    pub async fn store_last_relay_contact(
        &self,
        context_id: &str,
        unix_secs: u64,
    ) -> Result<(), StoreError> {
        let key = last_relay_contact_key(context_id)?;
        self.store_value(&key, &unix_secs).await
    }

    /// Loads the last successful relay contact for `context_id`.
    ///
    /// Returns `None` when no contact was ever stored for the context.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] for a `context_id` the key
    /// convention rejects, [`StoreError::Storage`] when the read fails, and
    /// [`StoreError::DeserializationFailed`] or
    /// [`StoreError::IncompatibleVersion`] for a stored value this build
    /// cannot read.
    pub async fn load_last_relay_contact(
        &self,
        context_id: &str,
    ) -> Result<Option<u64>, StoreError> {
        let key = last_relay_contact_key(context_id)?;
        self.load_value(&key).await
    }
}

/// Dyn-compatible store of each context's last successful relay contact
/// (ADR-029 key `sync/{context_id}/last_relay_contact`).
///
/// The FFI bridge layer holds it as `Arc<dyn RelayContactStore>`, injected at
/// each bridge's repository construction. The only implementation is
/// [`ProtocolRepository`], so every write lands in the backend the caller
/// chose (spec §17.6).
#[async_trait::async_trait]
pub trait RelayContactStore: Send + Sync {
    /// Stores the last successful relay contact for `context_id`.
    ///
    /// # Errors
    ///
    /// Returns the [`StoreError`] of
    /// [`ProtocolRepository::store_last_relay_contact`].
    async fn store_last_relay_contact(
        &self,
        context_id: &str,
        unix_secs: u64,
    ) -> Result<(), StoreError>;

    /// Loads the last successful relay contact for `context_id`, or `None`
    /// when none was stored.
    ///
    /// # Errors
    ///
    /// Returns the [`StoreError`] of
    /// [`ProtocolRepository::load_last_relay_contact`].
    async fn load_last_relay_contact(&self, context_id: &str) -> Result<Option<u64>, StoreError>;
}

#[async_trait::async_trait]
impl<S: Storage + 'static> RelayContactStore for ProtocolRepository<S> {
    async fn store_last_relay_contact(
        &self,
        context_id: &str,
        unix_secs: u64,
    ) -> Result<(), StoreError> {
        Self::store_last_relay_contact(self, context_id, unix_secs).await
    }

    async fn load_last_relay_contact(&self, context_id: &str) -> Result<Option<u64>, StoreError> {
        Self::load_last_relay_contact(self, context_id).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use scp_platform::in_memory::InMemoryStorage;

    use super::*;

    fn make_store() -> ProtocolRepository<InMemoryStorage> {
        ProtocolRepository::new_for_testing(InMemoryStorage::new())
    }

    #[test]
    fn key_follows_the_adr_029_convention() {
        assert_eq!(
            last_relay_contact_key("ctx-1").unwrap(),
            "sync/ctx-1/last_relay_contact"
        );
    }

    #[test]
    fn key_rejects_a_context_id_with_a_separator() {
        assert!(matches!(
            last_relay_contact_key("a/b"),
            Err(StoreError::SerializationFailed(_))
        ));
    }

    #[tokio::test]
    async fn absent_contact_loads_as_none() {
        let repo = make_store();
        assert_eq!(repo.load_last_relay_contact("ctx").await.unwrap(), None);
    }

    #[tokio::test]
    async fn stored_contact_round_trips_and_overwrites() {
        let repo = make_store();
        repo.store_last_relay_contact("ctx", 100).await.unwrap();
        assert_eq!(
            repo.load_last_relay_contact("ctx").await.unwrap(),
            Some(100)
        );
        repo.store_last_relay_contact("ctx", 250).await.unwrap();
        assert_eq!(
            repo.load_last_relay_contact("ctx").await.unwrap(),
            Some(250)
        );
        assert_eq!(repo.load_last_relay_contact("other").await.unwrap(), None);
    }

    #[tokio::test]
    async fn dyn_store_reaches_the_repository_key() {
        let repo = std::sync::Arc::new(make_store());
        let store: std::sync::Arc<dyn RelayContactStore> = repo.clone();
        store.store_last_relay_contact("ctx", 42).await.unwrap();
        assert_eq!(repo.load_last_relay_contact("ctx").await.unwrap(), Some(42));
        assert_eq!(
            store.load_last_relay_contact("ctx").await.unwrap(),
            Some(42)
        );
    }

    #[tokio::test]
    async fn store_rejects_a_context_id_with_a_separator() {
        let repo = make_store();
        assert!(repo.store_last_relay_contact("a/b", 1).await.is_err());
        assert!(repo.load_last_relay_contact("a/b").await.is_err());
    }
}
