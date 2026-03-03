//! In-memory [`Storage`] implementation for testing.
//!
//! Stores key-value pairs in a `HashMap<String, Vec<u8>>` behind a
//! `tokio::sync::Mutex`. See ADR-006 in `.docs/adrs/phase-1.md`.

use std::collections::HashMap;

use tokio::sync::Mutex;

use crate::error::PlatformError;
use crate::traits::Storage;

/// In-memory implementation of [`Storage`] for testing and development.
///
/// All data is stored in a `HashMap<String, Vec<u8>>`. This provides the same
/// API surface as production storage adapters (Keychain, encrypted `SQLite`)
/// but requires no platform dependencies and stores everything in memory.
///
/// # Thread Safety
///
/// All mutable state is protected by a `tokio::sync::Mutex`, making this type
/// safe to share across async tasks.
///
/// See ADR-006 in `.docs/adrs/phase-1.md`.
pub struct InMemoryStorage {
    data: Mutex<HashMap<String, Vec<u8>>>,
}

impl InMemoryStorage {
    /// Creates a new empty in-memory storage.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

// Trait uses RPITIT with explicit `+ Send` bound; async fn in trait
// does not guarantee Send futures, so manual impl Future is required.
#[allow(clippy::manual_async_fn)]
impl Storage for InMemoryStorage {
    fn store(
        &self,
        key: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key = key.to_owned();
        let data = data.to_vec();
        async move {
            self.data.lock().await.insert(key, data);
            Ok(())
        }
    }

    fn retrieve(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, PlatformError>> + Send {
        let key = key.to_owned();
        async move { Ok(self.data.lock().await.get(&key).cloned()) }
    }

    fn delete(&self, key: &str) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            self.data.lock().await.remove(&key);
            Ok(())
        }
    }

    fn list_keys(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<String>, PlatformError>> + Send {
        let prefix = prefix.to_owned();
        async move {
            let store = self.data.lock().await;
            let mut keys: Vec<String> = store
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .cloned()
                .collect();
            drop(store);
            keys.sort();
            Ok(keys)
        }
    }

    fn delete_prefix(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<u64, PlatformError>> + Send {
        let prefix = prefix.to_owned();
        async move {
            let mut store = self.data.lock().await;
            let keys_to_delete: Vec<String> = store
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .cloned()
                .collect();
            let count = keys_to_delete.len() as u64;
            for key in keys_to_delete {
                store.remove(&key);
            }
            drop(store);
            Ok(count)
        }
    }

    fn exists(&self, key: &str) -> impl Future<Output = Result<bool, PlatformError>> + Send {
        let key = key.to_owned();
        async move { Ok(self.data.lock().await.contains_key(&key)) }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_and_retrieve_roundtrip() {
        let storage = InMemoryStorage::new();
        storage.store("key1", b"value1").await.unwrap();
        let result = storage.retrieve("key1").await.unwrap();
        assert_eq!(result, Some(b"value1".to_vec()));
    }

    #[tokio::test]
    async fn retrieve_nonexistent_returns_none() {
        let storage = InMemoryStorage::new();
        let result = storage.retrieve("missing").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn store_overwrites_existing_value() {
        let storage = InMemoryStorage::new();
        storage.store("key", b"first").await.unwrap();
        storage.store("key", b"second").await.unwrap();
        let result = storage.retrieve("key").await.unwrap();
        assert_eq!(result, Some(b"second".to_vec()));
    }

    #[tokio::test]
    async fn delete_removes_value() {
        let storage = InMemoryStorage::new();
        storage.store("key", b"value").await.unwrap();
        storage.delete("key").await.unwrap();
        let result = storage.retrieve("key").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn delete_nonexistent_is_noop() {
        let storage = InMemoryStorage::new();
        // Should not error.
        storage.delete("nonexistent").await.unwrap();
    }

    #[tokio::test]
    async fn list_keys_returns_matching_prefix_in_sorted_order() {
        let storage = InMemoryStorage::new();
        storage.store("prefix/c", b"").await.unwrap();
        storage.store("prefix/a", b"").await.unwrap();
        storage.store("prefix/b", b"").await.unwrap();
        storage.store("other/x", b"").await.unwrap();

        let keys = storage.list_keys("prefix/").await.unwrap();
        assert_eq!(keys, vec!["prefix/a", "prefix/b", "prefix/c"]);
    }

    #[tokio::test]
    async fn list_keys_empty_prefix_returns_all_sorted() {
        let storage = InMemoryStorage::new();
        storage.store("b", b"").await.unwrap();
        storage.store("a", b"").await.unwrap();

        let keys = storage.list_keys("").await.unwrap();
        assert_eq!(keys, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn list_keys_no_matches_returns_empty() {
        let storage = InMemoryStorage::new();
        storage.store("foo", b"").await.unwrap();

        let keys = storage.list_keys("bar").await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    async fn delete_prefix_removes_matching_keys_and_returns_count() {
        let storage = InMemoryStorage::new();
        storage.store("ctx/a", b"1").await.unwrap();
        storage.store("ctx/b", b"2").await.unwrap();
        storage.store("ctx/c", b"3").await.unwrap();
        storage.store("other/d", b"4").await.unwrap();

        let deleted = storage.delete_prefix("ctx/").await.unwrap();
        assert_eq!(deleted, 3);

        // The ctx/ keys should be gone.
        assert_eq!(storage.retrieve("ctx/a").await.unwrap(), None);
        assert_eq!(storage.retrieve("ctx/b").await.unwrap(), None);
        assert_eq!(storage.retrieve("ctx/c").await.unwrap(), None);

        // The other key should remain.
        assert_eq!(
            storage.retrieve("other/d").await.unwrap(),
            Some(b"4".to_vec())
        );
    }

    #[tokio::test]
    async fn delete_prefix_no_matches_returns_zero() {
        let storage = InMemoryStorage::new();
        storage.store("foo", b"bar").await.unwrap();
        let deleted = storage.delete_prefix("zzz").await.unwrap();
        assert_eq!(deleted, 0);
    }

    #[tokio::test]
    async fn exists_returns_true_for_stored_key() {
        let storage = InMemoryStorage::new();
        storage.store("key", b"value").await.unwrap();
        assert!(storage.exists("key").await.unwrap());
    }

    #[tokio::test]
    async fn exists_returns_false_for_missing_key() {
        let storage = InMemoryStorage::new();
        assert!(!storage.exists("missing").await.unwrap());
    }

    #[tokio::test]
    async fn exists_returns_false_after_delete() {
        let storage = InMemoryStorage::new();
        storage.store("key", b"value").await.unwrap();
        storage.delete("key").await.unwrap();
        assert!(!storage.exists("key").await.unwrap());
    }

    #[tokio::test]
    async fn store_empty_value_succeeds() {
        let storage = InMemoryStorage::new();
        storage.store("empty", b"").await.unwrap();
        let result = storage.retrieve("empty").await.unwrap();
        assert_eq!(result, Some(vec![]));
    }
}
