//! Async key-value adapter trait for the `OpenMLS` storage bridge.
//!
//! Introduced by commit 4 of the actor-per-context refactor (ADR-049 §6/§7).
//!
//! # Why a new trait
//!
//! `OpenMLS`'s `StorageProvider` is a **sync** trait — the upstream contract
//! returns `Result<..., Self::Error>` from every method and does not support
//! async. The existing sync-to-async bridge in [`super::storage`] satisfies
//! that contract by running `block_in_place(|| handle.block_on(...))` around
//! each call, which pins the tokio worker thread and makes `current_thread`
//! runtimes panic.
//!
//! Commit 4 introduces [`OpenMlsStorageAdapter`] as an **async** KV surface
//! that underlies the sync `OpenMLS` bridge. The adapter is dyn-compatible
//! (via `#[async_trait]`) so `Arc<dyn OpenMlsStorageAdapter>` can be cloned
//! into every actor's `ActorDeps`. Later commits (≥5) build the sync
//! `StorageProvider` impl on top of this adapter using a single
//! `tokio::task::spawn_blocking` hop per call at the sync→async seam,
//! replacing the `block_in_place` pattern.
//!
//! # Methods
//!
//! The minimum surface `OpenMLS` needs is a keyed blob store: `store`,
//! `retrieve`, `delete`. Higher-level shapes (lists, composite keys,
//! namespacing) live in the `OpenMLS` bridge on top, exactly where they live
//! today in [`super::storage::MlsStorageBridge`].
//!
//! # Production impl
//!
//! [`SpawnBlockingStorageAdapter<S>`] wraps an `Arc<S>` where
//! `S: scp_platform::traits::Storage + 'static`. The underlying `Storage`
//! trait is already async, so the adapter forwards directly. The name
//! "`SpawnBlocking`" signals the role in the future `OpenMLS` sync-bridge
//! composition: the sync bridge wraps each adapter call in
//! `spawn_blocking` so that sync-heavy backends (e.g. `SqliteStorage`,
//! which today uses `rusqlite` under the hood) do not pin async worker
//! threads when `OpenMLS` reaches for the KV store.
//!
//! # Why `Arc<dyn OpenMlsStorageAdapter>` and not `Arc<dyn Storage>`
//!
//! The `scp-platform` `Storage` trait uses return-position impl Trait in
//! traits (RPITIT) and is therefore **not dyn-compatible**. We cannot write
//! `Arc<dyn Storage>` — the compiler refuses. `OpenMlsStorageAdapter` is a
//! dyn-compatible wrapper whose methods are `async_trait`-desugared to
//! boxed futures. The adapter is instantiated once per process against a
//! concrete generic `S` and erased to `Arc<dyn OpenMlsStorageAdapter>` for
//! distribution across actors.

use std::sync::Arc;

use async_trait::async_trait;

use scp_platform::traits::Storage;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by [`OpenMlsStorageAdapter`] operations.
#[derive(Debug, thiserror::Error)]
pub enum OpenMlsStorageError {
    /// The underlying `Storage` backend returned an error.
    #[error("storage error: {0}")]
    Storage(#[from] scp_platform::PlatformError),

    /// The `spawn_blocking` join handle failed (task panicked or was
    /// cancelled). Only reachable if the storage backend itself panics.
    #[error("storage task join failure: {0}")]
    JoinFailure(String),
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Async key-value surface underpinning the `OpenMLS` sync `StorageProvider`.
///
/// Implementations are `Send + Sync` and shared across actors via
/// `Arc<dyn OpenMlsStorageAdapter>`. All methods are cancel-safe: the caller
/// can drop the future at any point without corrupting the underlying KV.
///
/// ### Contract
///
/// - `store` overwrites any existing value at `key` atomically from the
///   caller's perspective (atomicity guarantees come from the backend).
/// - `retrieve` returns `None` if the key is not present.
/// - `delete` is a no-op if the key is not present; it never errors on a
///   missing key.
#[async_trait]
pub trait OpenMlsStorageAdapter: Send + Sync {
    /// Store `value` at `key`. Overwrites any existing value.
    ///
    /// # Errors
    ///
    /// Returns [`OpenMlsStorageError::Storage`] if the backend rejects the
    /// write; [`OpenMlsStorageError::JoinFailure`] if the blocking task
    /// handling the call panics.
    async fn store(&self, key: &str, value: &[u8]) -> Result<(), OpenMlsStorageError>;

    /// Retrieve the value at `key`. Returns `None` if the key is not present.
    ///
    /// # Errors
    ///
    /// Returns [`OpenMlsStorageError::Storage`] if the backend rejects the
    /// read; [`OpenMlsStorageError::JoinFailure`] if the blocking task
    /// handling the call panics.
    async fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, OpenMlsStorageError>;

    /// Delete the value at `key`. No-op if the key is not present.
    ///
    /// # Errors
    ///
    /// Returns [`OpenMlsStorageError::Storage`] if the backend rejects the
    /// delete; [`OpenMlsStorageError::JoinFailure`] if the blocking task
    /// handling the call panics.
    async fn delete(&self, key: &str) -> Result<(), OpenMlsStorageError>;
}

// ---------------------------------------------------------------------------
// Production impl
// ---------------------------------------------------------------------------

/// Production [`OpenMlsStorageAdapter`] over any `Storage` backend.
///
/// `SpawnBlockingStorageAdapter<S>` is generic over the concrete `Storage`
/// implementation and owns an `Arc<S>`. Each method forwards directly to the
/// underlying async `Storage` method — `Storage` is already an async trait, so
/// an extra `spawn_blocking` hop inside the adapter would be redundant for
/// the common case of an async-native backend.
///
/// The "`SpawnBlocking`" name reflects the composition role in the future
/// `OpenMLS` sync-bridge layer: the sync `StorageProvider` impl (commit ≥5)
/// wraps every call to this adapter's methods in `tokio::task::spawn_blocking`
/// so that sync-heavy backends do not pin async worker threads.
///
/// The struct is `Send + Sync` for any `S: Storage + 'static`.
pub struct SpawnBlockingStorageAdapter<S: Storage + 'static> {
    inner: Arc<S>,
}

impl<S: Storage + 'static> SpawnBlockingStorageAdapter<S> {
    /// Constructs a new adapter over the given shared `Storage` backend.
    #[must_use]
    pub const fn new(inner: Arc<S>) -> Self {
        Self { inner }
    }

    /// Returns a reference to the inner `Storage` backend.
    #[must_use]
    pub const fn inner(&self) -> &Arc<S> {
        &self.inner
    }
}

#[async_trait]
impl<S: Storage + 'static> OpenMlsStorageAdapter for SpawnBlockingStorageAdapter<S> {
    async fn store(&self, key: &str, value: &[u8]) -> Result<(), OpenMlsStorageError> {
        self.inner.store(key, value).await?;
        Ok(())
    }

    async fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, OpenMlsStorageError> {
        let v = self.inner.retrieve(key).await?;
        Ok(v)
    }

    async fn delete(&self, key: &str) -> Result<(), OpenMlsStorageError> {
        self.inner.delete(key).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_platform::testing::InMemoryStorage;

    fn new_adapter() -> Arc<dyn OpenMlsStorageAdapter> {
        Arc::new(SpawnBlockingStorageAdapter::new(Arc::new(
            InMemoryStorage::new(),
        )))
    }

    #[tokio::test]
    async fn store_retrieve_delete_roundtrip() {
        let adapter = new_adapter();

        adapter.store("k1", b"v1").await.unwrap();
        let got = adapter.retrieve("k1").await.unwrap();
        assert_eq!(got.as_deref(), Some(&b"v1"[..]));

        adapter.store("k1", b"v2").await.unwrap();
        let got = adapter.retrieve("k1").await.unwrap();
        assert_eq!(got.as_deref(), Some(&b"v2"[..]));

        adapter.delete("k1").await.unwrap();
        let got = adapter.retrieve("k1").await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn retrieve_missing_key_returns_none() {
        let adapter = new_adapter();
        let got = adapter.retrieve("absent").await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn delete_missing_key_is_noop() {
        let adapter = new_adapter();
        // delete a key that doesn't exist — must not error
        adapter.delete("absent").await.unwrap();
    }

    /// Concurrent access stress: N=4 tokio tasks × 100 ops, distinct keys per
    /// task. Verifies no interleaving corruption on a shared adapter.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_access_stress_disjoint_keys() {
        const TASKS: usize = 4;
        const OPS: usize = 100;

        let adapter = new_adapter();
        let mut handles = Vec::with_capacity(TASKS);
        for t in 0..TASKS {
            let ad = Arc::clone(&adapter);
            handles.push(tokio::spawn(async move {
                for i in 0..OPS {
                    let key = format!("task-{t}-key-{i}");
                    let expected = format!("value-{t}-{i}");
                    ad.store(&key, expected.as_bytes()).await.unwrap();
                    let got = ad.retrieve(&key).await.unwrap();
                    assert_eq!(got.as_deref(), Some(expected.as_bytes()));
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        // Every key must still be readable — no overwrite or loss.
        for t in 0..TASKS {
            for i in 0..OPS {
                let key = format!("task-{t}-key-{i}");
                let expected = format!("value-{t}-{i}");
                let got = adapter.retrieve(&key).await.unwrap();
                assert_eq!(
                    got.as_deref(),
                    Some(expected.as_bytes()),
                    "key {key} lost or overwritten",
                );
            }
        }
    }
}
