//! A `Storage` wrapper that fails writes and deletes on a configured key
//! prefix, or fails only writes, before or after they commit, or fails every
//! write from the Nth on, for tests of fail-closed storage branches. The faults sit behind `std::sync::RwLock`s
//! never held across an `.await` (`clippy.toml` bans `std::sync::Mutex` in
//! this crate).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use scp_platform::PlatformError;
use scp_platform::in_memory::InMemoryStorage;
use scp_platform::traits::Storage;

/// Fails writes and deletes whose key starts with a configured prefix and
/// delegates everything else to an inner [`InMemoryStorage`].
pub struct FaultyStorage {
    inner: Arc<InMemoryStorage>,
    /// Fails both `store` and `delete` for keys under this prefix.
    fail_prefix: RwLock<Option<String>>,
    /// Fails only `delete` for keys under this prefix (`store` and `retrieve`
    /// pass), so a test can target the delete of a record that was written.
    fail_delete_prefix: RwLock<Option<String>>,
    /// Makes `store` for keys under this prefix write to the inner storage
    /// and then report an error: a write that commits and still fails.
    fail_after_commit_prefix: RwLock<Option<String>>,
    /// Fails only `store` for keys under this prefix, without writing;
    /// `delete` and `retrieve` pass.
    fail_store_prefix: RwLock<Option<String>>,
    /// Fails `delete_prefix` calls whose prefix argument starts with this
    /// prefix. `delete` is not affected.
    fail_delete_prefix_calls: RwLock<Option<String>>,
    /// When nonzero, the Nth `store` call after arming (1-based) and every
    /// later one fail without writing: a crash at the Nth put.
    fail_from_store: AtomicU64,
    /// Counts `store` calls since [`FaultyStorage::fail_nth_store`] armed.
    stores_seen: AtomicU64,
}

impl FaultyStorage {
    pub const fn new(inner: Arc<InMemoryStorage>) -> Self {
        Self {
            inner,
            fail_prefix: RwLock::new(None),
            fail_delete_prefix: RwLock::new(None),
            fail_after_commit_prefix: RwLock::new(None),
            fail_store_prefix: RwLock::new(None),
            fail_delete_prefix_calls: RwLock::new(None),
            fail_from_store: AtomicU64::new(0),
            stores_seen: AtomicU64::new(0),
        }
    }

    /// Fails the `n`th `store` call from now (1-based) and every later one,
    /// without writing, as a crash at that put would. `n == 0` disarms.
    pub fn fail_nth_store(&self, n: u64) {
        self.stores_seen.store(0, Ordering::SeqCst);
        self.fail_from_store.store(n, Ordering::SeqCst);
    }

    /// Fails later `delete_prefix` calls whose prefix starts with `prefix`.
    pub fn fail_delete_prefix_calls(&self, prefix: &str) {
        *self
            .fail_delete_prefix_calls
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(prefix.to_owned());
    }

    /// Fails later `store` calls for keys under `prefix` without writing,
    /// while `delete` and `retrieve` succeed.
    pub fn fail_store_prefix(&self, prefix: &str) {
        *self
            .fail_store_prefix
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(prefix.to_owned());
    }

    /// Makes later `store` calls for keys under `prefix` commit to the inner
    /// storage and then report an error.
    pub fn fail_after_commit_prefix(&self, prefix: &str) {
        *self
            .fail_after_commit_prefix
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(prefix.to_owned());
    }

    /// Fails later `store` and `delete` calls for keys under `prefix`.
    pub fn fail_prefix(&self, prefix: &str) {
        *self
            .fail_prefix
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(prefix.to_owned());
    }

    /// Fails later `delete` calls for keys under `prefix`, while `store` and
    /// `retrieve` succeed.
    pub fn fail_delete_prefix(&self, prefix: &str) {
        *self
            .fail_delete_prefix
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(prefix.to_owned());
    }

    /// Clears every fault.
    pub fn clear_fail(&self) {
        self.fail_from_store.store(0, Ordering::SeqCst);
        *self
            .fail_delete_prefix_calls
            .write()
            .unwrap_or_else(PoisonError::into_inner) = None;
        *self
            .fail_store_prefix
            .write()
            .unwrap_or_else(PoisonError::into_inner) = None;
        *self
            .fail_after_commit_prefix
            .write()
            .unwrap_or_else(PoisonError::into_inner) = None;
        *self
            .fail_prefix
            .write()
            .unwrap_or_else(PoisonError::into_inner) = None;
        *self
            .fail_delete_prefix
            .write()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }

    fn should_fail(&self, key: &str) -> bool {
        self.fail_prefix
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_deref()
            .is_some_and(|p| key.starts_with(p))
    }

    /// True when the store-and-delete prefix or the delete-only prefix
    /// matches `key`.
    fn should_fail_delete(&self, key: &str) -> bool {
        self.should_fail(key)
            || self
                .fail_delete_prefix
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .as_deref()
                .is_some_and(|p| key.starts_with(p))
    }
}

impl Storage for FaultyStorage {
    async fn store(&self, key: &str, data: &[u8]) -> Result<(), PlatformError> {
        let fail_from = self.fail_from_store.load(Ordering::SeqCst);
        if fail_from != 0 && self.stores_seen.fetch_add(1, Ordering::SeqCst) + 1 >= fail_from {
            return Err(PlatformError::StorageError(
                "injected store fault at the nth put".to_owned(),
            ));
        }
        let store_only = self
            .fail_store_prefix
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_deref()
            .is_some_and(|p| key.starts_with(p));
        if store_only || self.should_fail(key) {
            return Err(PlatformError::StorageError(
                "injected store fault".to_owned(),
            ));
        }
        self.inner.store(key, data).await?;
        let fail_after_commit = self
            .fail_after_commit_prefix
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_deref()
            .is_some_and(|p| key.starts_with(p));
        if fail_after_commit {
            return Err(PlatformError::StorageError(
                "injected store fault after commit".to_owned(),
            ));
        }
        Ok(())
    }

    async fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, PlatformError> {
        self.inner.retrieve(key).await
    }

    async fn delete(&self, key: &str) -> Result<(), PlatformError> {
        if self.should_fail_delete(key) {
            return Err(PlatformError::StorageError(
                "injected delete fault".to_owned(),
            ));
        }
        self.inner.delete(key).await
    }

    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, PlatformError> {
        self.inner.list_keys(prefix).await
    }

    async fn delete_prefix(&self, prefix: &str) -> Result<u64, PlatformError> {
        let fail = self
            .fail_delete_prefix_calls
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_deref()
            .is_some_and(|p| prefix.starts_with(p));
        if fail {
            return Err(PlatformError::StorageError(
                "injected delete_prefix fault".to_owned(),
            ));
        }
        self.inner.delete_prefix(prefix).await
    }

    async fn exists(&self, key: &str) -> Result<bool, PlatformError> {
        self.inner.exists(key).await
    }
}
