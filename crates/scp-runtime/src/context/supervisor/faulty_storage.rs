//! A `Storage` wrapper that fails writes and deletes on a configured key
//! prefix, for tests of fail-closed storage branches. The faults sit behind
//! `std::sync::RwLock`s never held across an `.await` (`clippy.toml` bans
//! `std::sync::Mutex` in this crate).

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
}

impl FaultyStorage {
    pub const fn new(inner: Arc<InMemoryStorage>) -> Self {
        Self {
            inner,
            fail_prefix: RwLock::new(None),
            fail_delete_prefix: RwLock::new(None),
        }
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

    /// Clears both faults.
    pub fn clear_fail(&self) {
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
        if self.should_fail(key) {
            return Err(PlatformError::StorageError(
                "injected store fault".to_owned(),
            ));
        }
        self.inner.store(key, data).await
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
        self.inner.delete_prefix(prefix).await
    }

    async fn exists(&self, key: &str) -> Result<bool, PlatformError> {
        self.inner.exists(key).await
    }
}
