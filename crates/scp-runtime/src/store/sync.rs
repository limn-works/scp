//! Reconnection sync state for `ProtocolRepository`.
//!
//! Stores the last successful relay contact per context under the ADR-029
//! key `sync/{context_id}/last_relay_contact`, as local Unix seconds. The
//! push-wake pull (ADR-029 §2, push-wake pull mode) reads it to set the
//! relay QUERY `since`, and a full reconnection reads it to classify the
//! offline tier. Creating a context, joining it by Welcome, and importing it
//! write the first value before the actor starts; after that, three paths
//! advance it: a full reconnection after it clears `needs_reconnect`, a
//! push-wake pull after Phases 2 and 4 have fed every blob of the context's
//! Phase 1 buffer to the actor and the actor reached a verdict on each, and a
//! live subscription after the actor accepts a delivered envelope. Restoring
//! a context writes nothing (ADR-029 Implementation).
//!
//! [`RelayContactStore`] is the dyn-compatible view, because
//! `ProtocolRepository<S>` is generic over a storage backend that is not
//! dyn-compatible. The supervisor holds the one instance, built by
//! [`relay_contact_store_over`] from the storage handle its other durable
//! providers derive from.

use std::sync::Arc;

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

    /// Deletes the last relay contact of `context_id`; deleting an absent
    /// value succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] for a `context_id` the key
    /// convention rejects, and [`StoreError::Storage`] when the delete fails.
    pub async fn delete_last_relay_contact(&self, context_id: &str) -> Result<(), StoreError> {
        let key = last_relay_contact_key(context_id)?;
        self.storage.delete(&key).await?;
        Ok(())
    }
}

/// Builds the relay-contact store over `handle`, the storage handle the
/// supervisor's saga journal and MLS storage derive from, so the key lands in
/// the backend the caller chose (spec §17.6).
///
/// The handle is the one `DurableProviders::from_handle` receives; that
/// constructor is the only production caller.
pub(crate) fn relay_contact_store_over<S: Storage + 'static>(
    handle: Arc<S>,
) -> Arc<dyn RelayContactStore> {
    Arc::new(ProtocolRepository { storage: handle })
}

/// Dyn-compatible store of each context's last successful relay contact
/// (ADR-029 key `sync/{context_id}/last_relay_contact`).
///
/// The supervisor holds it as `Arc<dyn RelayContactStore>`, built from its
/// storage handle, and every bridge reads the supervisor's instance. The only
/// production implementation is [`ProtocolRepository`], so every write lands
/// in the backend the caller chose (spec §17.6).
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

    /// Deletes the last relay contact of `context_id`, which rolls back the
    /// first write of a create, Welcome join or import that then fails.
    ///
    /// # Errors
    ///
    /// Returns the [`StoreError`] of
    /// [`ProtocolRepository::delete_last_relay_contact`].
    async fn delete_last_relay_contact(&self, context_id: &str) -> Result<(), StoreError>;
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

    async fn delete_last_relay_contact(&self, context_id: &str) -> Result<(), StoreError> {
        Self::delete_last_relay_contact(self, context_id).await
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
        assert!(repo.delete_last_relay_contact("a/b").await.is_err());
    }

    #[tokio::test]
    async fn delete_removes_only_that_contact() {
        let repo = make_store();
        repo.store_last_relay_contact("ctx", 7).await.unwrap();
        repo.store_last_relay_contact("other", 8).await.unwrap();
        repo.delete_last_relay_contact("ctx").await.unwrap();
        assert_eq!(repo.load_last_relay_contact("ctx").await.unwrap(), None);
        assert_eq!(
            repo.load_last_relay_contact("other").await.unwrap(),
            Some(8)
        );
        repo.delete_last_relay_contact("ctx").await.unwrap();
    }

    /// The store over a shared handle writes into that handle's backend, so a
    /// repository over the same storage reads what it wrote.
    #[tokio::test]
    async fn store_over_a_handle_writes_into_that_backend() {
        let storage = Arc::new(InMemoryStorage::new());
        let store = relay_contact_store_over(Arc::clone(&storage));
        store.store_last_relay_contact("ctx", 99).await.unwrap();
        let view = ProtocolRepository::new_for_testing(Arc::clone(&storage));
        assert_eq!(view.load_last_relay_contact("ctx").await.unwrap(), Some(99));
        store.delete_last_relay_contact("ctx").await.unwrap();
        assert_eq!(view.load_last_relay_contact("ctx").await.unwrap(), None);
    }
}
