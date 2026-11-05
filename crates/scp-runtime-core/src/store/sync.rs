//! Reconnection sync state: each context's last successful relay contact.
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
//! The key convention and the `StoredValue` envelope live in free functions
//! over `&S`, which both [`ProtocolRepository`] and
//! [`StorageRelayContactStore`] call. [`RelayContactStore`] is the
//! dyn-compatible view, because a `Storage` backend is not dyn-compatible.
//! The supervisor holds the one instance, a [`StorageRelayContactStore`] over
//! the storage handle its other durable providers derive from.

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

/// Writes `unix_secs` as the last relay contact of `context_id` into
/// `storage`, in the `StoredValue` envelope every repository value uses
/// (spec §17.5).
async fn store_contact<S: Storage>(
    storage: &S,
    context_id: &str,
    unix_secs: u64,
) -> Result<(), StoreError> {
    let key = last_relay_contact_key(context_id)?;
    let bytes = scp_platform::store_value::to_stored_value_bytes(&unix_secs)?;
    storage.store(&key, &bytes).await?;
    Ok(())
}

/// Reads the last relay contact of `context_id` from `storage`; `None` when
/// none is stored.
async fn load_contact<S: Storage>(
    storage: &S,
    context_id: &str,
) -> Result<Option<u64>, StoreError> {
    let key = last_relay_contact_key(context_id)?;
    match storage.retrieve(&key).await? {
        Some(bytes) => Ok(Some(scp_platform::store_value::from_stored_value_bytes(
            &bytes,
        )?)),
        None => Ok(None),
    }
}

/// Deletes the last relay contact of `context_id` from `storage`; deleting an
/// absent value succeeds.
async fn delete_contact<S: Storage>(storage: &S, context_id: &str) -> Result<(), StoreError> {
    let key = last_relay_contact_key(context_id)?;
    storage.delete(&key).await?;
    Ok(())
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
        store_contact(self.storage(), context_id, unix_secs).await
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
        load_contact(self.storage(), context_id).await
    }
}

/// The production [`RelayContactStore`]: the ADR-029 key over a shared
/// storage handle.
///
/// The supervisor builds it from the handle `DurableProviders::from_handle`
/// receives, the one its saga journal and MLS storage derive from, so every
/// value lands in the backend the caller chose (spec §17.6). It holds the
/// handle directly, as `ProtocolRepositorySagaJournal` does, and builds no
/// [`ProtocolRepository`], whose constructors require `EncryptedStorage`.
pub struct StorageRelayContactStore<S: Storage + 'static> {
    storage: Arc<S>,
}

impl<S: Storage + 'static> StorageRelayContactStore<S> {
    /// Creates the store over the shared storage handle.
    #[must_use]
    pub const fn new(storage: Arc<S>) -> Self {
        Self { storage }
    }
}

/// Dyn-compatible store of each context's last successful relay contact
/// (ADR-029 key `sync/{context_id}/last_relay_contact`).
///
/// The supervisor holds it as `Arc<dyn RelayContactStore>`, and every bridge
/// reads the supervisor's instance. The only production implementation is
/// [`StorageRelayContactStore`].
#[async_trait::async_trait]
pub trait RelayContactStore: Send + Sync {
    /// Stores the last successful relay contact for `context_id`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] for a `context_id` the key
    /// convention rejects, and [`StoreError::Storage`] when the write fails.
    async fn store_last_relay_contact(
        &self,
        context_id: &str,
        unix_secs: u64,
    ) -> Result<(), StoreError>;

    /// Loads the last successful relay contact for `context_id`; `None` when
    /// none was stored.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] for a `context_id` the key
    /// convention rejects, [`StoreError::Storage`] when the read fails, and
    /// [`StoreError::DeserializationFailed`] or
    /// [`StoreError::IncompatibleVersion`] for a stored value this build
    /// cannot read.
    async fn load_last_relay_contact(&self, context_id: &str) -> Result<Option<u64>, StoreError>;

    /// Deletes the last relay contact of `context_id`, which rolls back the
    /// first write of a create, Welcome join or import that then fails;
    /// deleting an absent value succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] for a `context_id` the key
    /// convention rejects, and [`StoreError::Storage`] when the delete fails.
    async fn delete_last_relay_contact(&self, context_id: &str) -> Result<(), StoreError>;
}

#[async_trait::async_trait]
impl<S: Storage + 'static> RelayContactStore for StorageRelayContactStore<S> {
    async fn store_last_relay_contact(
        &self,
        context_id: &str,
        unix_secs: u64,
    ) -> Result<(), StoreError> {
        store_contact(&*self.storage, context_id, unix_secs).await
    }

    async fn load_last_relay_contact(&self, context_id: &str) -> Result<Option<u64>, StoreError> {
        load_contact(&*self.storage, context_id).await
    }

    async fn delete_last_relay_contact(&self, context_id: &str) -> Result<(), StoreError> {
        delete_contact(&*self.storage, context_id).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use scp_platform::in_memory::InMemoryStorage;

    use super::*;

    fn make_store() -> StorageRelayContactStore<InMemoryStorage> {
        StorageRelayContactStore::new(Arc::new(InMemoryStorage::new()))
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
        let store = make_store();
        assert_eq!(store.load_last_relay_contact("ctx").await.unwrap(), None);
    }

    #[tokio::test]
    async fn stored_contact_round_trips_and_overwrites() {
        let store = make_store();
        store.store_last_relay_contact("ctx", 100).await.unwrap();
        assert_eq!(
            store.load_last_relay_contact("ctx").await.unwrap(),
            Some(100)
        );
        store.store_last_relay_contact("ctx", 250).await.unwrap();
        assert_eq!(
            store.load_last_relay_contact("ctx").await.unwrap(),
            Some(250)
        );
        assert_eq!(store.load_last_relay_contact("other").await.unwrap(), None);
    }

    #[tokio::test]
    async fn store_rejects_a_context_id_with_a_separator() {
        let store = make_store();
        assert!(store.store_last_relay_contact("a/b", 1).await.is_err());
        assert!(store.load_last_relay_contact("a/b").await.is_err());
        assert!(store.delete_last_relay_contact("a/b").await.is_err());
    }

    #[tokio::test]
    async fn delete_removes_only_that_contact() {
        let store = make_store();
        store.store_last_relay_contact("ctx", 7).await.unwrap();
        store.store_last_relay_contact("other", 8).await.unwrap();
        store.delete_last_relay_contact("ctx").await.unwrap();
        assert_eq!(store.load_last_relay_contact("ctx").await.unwrap(), None);
        assert_eq!(
            store.load_last_relay_contact("other").await.unwrap(),
            Some(8)
        );
        store.delete_last_relay_contact("ctx").await.unwrap();
    }

    /// The store and a repository over the same handle share the key and
    /// envelope: each reads what the other wrote.
    #[tokio::test]
    async fn store_and_repository_share_the_key_and_envelope() {
        let storage = Arc::new(InMemoryStorage::new());
        let store: Arc<dyn RelayContactStore> =
            Arc::new(StorageRelayContactStore::new(Arc::clone(&storage)));
        let repo = ProtocolRepository::new_for_testing(Arc::clone(&storage));
        store.store_last_relay_contact("ctx", 99).await.unwrap();
        assert_eq!(repo.load_last_relay_contact("ctx").await.unwrap(), Some(99));
        repo.store_last_relay_contact("ctx", 120).await.unwrap();
        assert_eq!(
            store.load_last_relay_contact("ctx").await.unwrap(),
            Some(120)
        );
        store.delete_last_relay_contact("ctx").await.unwrap();
        assert_eq!(repo.load_last_relay_contact("ctx").await.unwrap(), None);
    }
}
