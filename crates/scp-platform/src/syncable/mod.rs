//! `SyncableStorage` — mutation-tracking wrapper for P2P state synchronization.
//!
//! Wraps any [`Storage`] implementation and logs all mutations (store/delete) to
//! a write-ahead changelog stored in the inner storage itself under a `_sync/`
//! key prefix. This enables export/import of changesets for P2P state
//! replication between devices.
//!
//! # Key layout
//!
//! - `_sync/log/{seq:020d}` — individual changelog entries (MessagePack-encoded)
//! - `_sync/meta/next_seq` — monotonically incrementing sequence counter
//!
//! # Feature flag
//!
//! This module requires the `sync` feature in `scp-platform`.
//!
//! See SCP-PERSIST-064.

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::error::PlatformError;
use crate::traits::Storage;

// ---------------------------------------------------------------------------
// Key constants
// ---------------------------------------------------------------------------

/// Prefix for all sync-internal keys.
const SYNC_PREFIX: &str = "_sync/";

/// Prefix for changelog entry keys.
const LOG_PREFIX: &str = "_sync/log/";

/// Key storing the next sequence number.
const NEXT_SEQ_KEY: &str = "_sync/meta/next_seq";

// ---------------------------------------------------------------------------
// Changeset types
// ---------------------------------------------------------------------------

/// A single mutation recorded in the changelog.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChangeEntry {
    /// Monotonically increasing sequence number (local to this storage).
    pub seq: u64,
    /// The storage key that was mutated.
    pub key: String,
    /// `Some(bytes)` for a store operation, `None` for a delete operation.
    pub value: Option<Vec<u8>>,
}

/// An ordered list of mutations, suitable for transport between peers.
///
/// Serialized with `MessagePack` via `rmp-serde` for compact wire representation.
pub type Changeset = Vec<ChangeEntry>;

// ---------------------------------------------------------------------------
// SyncableStorage
// ---------------------------------------------------------------------------

/// A [`Storage`] wrapper that tracks mutations for P2P synchronization.
///
/// Delegates all six [`Storage`] methods to the inner storage. `store` and
/// `delete` additionally append a [`ChangeEntry`] to the write-ahead changelog.
///
/// The changelog is stored in the inner storage itself under the `_sync/`
/// prefix. Protocol keys never use this prefix (they use `context/`,
/// `identity/`, `mls/`, etc.), so there is no collision risk.
pub struct SyncableStorage<S: Storage> {
    inner: S,
    /// Serializes mutations to ensure atomic seq allocation + log append.
    /// Without this, concurrent `store`/`delete` calls could read the same
    /// sequence number and overwrite each other's changelog entries.
    seq_lock: Mutex<()>,
}

impl<S: Storage> SyncableStorage<S> {
    /// Wraps an existing [`Storage`] implementation with mutation tracking.
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            seq_lock: Mutex::new(()),
        }
    }

    /// Returns the next sequence number, reading from persistent storage.
    ///
    /// If no sequence has been stored yet (fresh storage), returns 0.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::StorageError`] if the read or deserialization
    /// fails.
    pub async fn next_seq(&self) -> Result<u64, PlatformError> {
        self.inner
            .retrieve(NEXT_SEQ_KEY)
            .await?
            .map_or(Ok(0), |bytes| {
                rmp_serde::from_slice(&bytes).map_err(|e| {
                    PlatformError::StorageError(format!("failed to deserialize next_seq: {e}"))
                })
            })
    }

    /// Exports all changelog entries with sequence number >= `since`.
    ///
    /// Returns entries in ascending sequence order.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::StorageError`] if any read or deserialization
    /// fails.
    pub async fn export_changeset(&self, since: u64) -> Result<Changeset, PlatformError> {
        let all_log_keys = self.inner.list_keys(LOG_PREFIX).await?;
        let since_key = log_key(since);

        let mut entries = Vec::new();
        for key in all_log_keys {
            if key >= since_key
                && let Some(bytes) = self.inner.retrieve(&key).await?
            {
                let entry: ChangeEntry = rmp_serde::from_slice(&bytes).map_err(|e| {
                    PlatformError::StorageError(format!(
                        "failed to deserialize changelog entry {key}: {e}"
                    ))
                })?;
                entries.push(entry);
            }
        }

        // Already sorted by key (lexicographic == numeric due to zero-padding).
        Ok(entries)
    }

    /// Namespaces that must never be writable via sync changesets.
    ///
    /// These contain identity material, MLS key state, and internal metadata
    /// that would enable privilege escalation or key theft if overwritten by
    /// a malicious sync peer.
    const SYNC_DENIED_PREFIXES: &'static [&'static str] =
        &["identity/", "mls/", "_meta/", "_sync/"];

    /// Applies a remote changeset to local storage.
    ///
    /// For each entry in the changeset, applies the operation to the inner
    /// storage and appends a new local changelog entry with a fresh local
    /// sequence number. Last-write-wins semantics: operations are applied in
    /// order.
    ///
    /// Keys in protected namespaces (`identity/`, `mls/`, `_meta/`, `_sync/`)
    /// are rejected to prevent privilege escalation via sync injection.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::StorageError`] if any write fails or a key
    /// targets a denied namespace.
    pub async fn apply_changeset(&self, changeset: Changeset) -> Result<(), PlatformError> {
        for entry in &changeset {
            // Reject keys targeting protected namespaces.
            if Self::SYNC_DENIED_PREFIXES
                .iter()
                .any(|p| entry.key.starts_with(p))
            {
                return Err(PlatformError::StorageError(format!(
                    "changeset key '{}' targets a protected namespace",
                    entry.key
                )));
            }
        }
        for entry in changeset {
            match &entry.value {
                Some(data) => {
                    self.store(&entry.key, data).await?;
                }
                None => {
                    self.delete(&entry.key).await?;
                }
            }
        }
        Ok(())
    }

    /// Allocates and persists the next sequence number, returning the allocated
    /// value.
    async fn allocate_seq(&self) -> Result<u64, PlatformError> {
        let seq = self.next_seq().await?;
        let next = seq + 1;
        let encoded = rmp_serde::to_vec(&next).map_err(|e| {
            PlatformError::StorageError(format!("failed to serialize next_seq: {e}"))
        })?;
        self.inner.store(NEXT_SEQ_KEY, &encoded).await?;
        Ok(seq)
    }

    /// Appends a changelog entry to the inner storage.
    async fn append_log(&self, entry: &ChangeEntry) -> Result<(), PlatformError> {
        let key = log_key(entry.seq);
        let encoded = rmp_serde::to_vec(entry).map_err(|e| {
            PlatformError::StorageError(format!("failed to serialize changelog entry: {e}"))
        })?;
        self.inner.store(&key, &encoded).await
    }
}

/// Formats a sequence number into its corresponding log key.
///
/// Uses 20-digit zero-padded formatting so that lexicographic ordering
/// matches numeric ordering.
fn log_key(seq: u64) -> String {
    format!("{LOG_PREFIX}{seq:020}")
}

// ---------------------------------------------------------------------------
// Storage trait delegation
// ---------------------------------------------------------------------------

#[allow(clippy::manual_async_fn)]
impl<S: Storage> Storage for SyncableStorage<S> {
    fn store(
        &self,
        key: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key = key.to_owned();
        let data = data.to_vec();
        async move {
            // Skip changelog for internal sync keys to avoid infinite recursion.
            if key.starts_with(SYNC_PREFIX) {
                return self.inner.store(&key, &data).await;
            }

            // Serialize data mutation + seq allocation + log append to ensure
            // the changelog accurately reflects the order mutations were applied
            // to the inner storage. Without this, concurrent store/delete calls
            // could produce a changelog that diverges from the actual data state.
            let _guard = self.seq_lock.lock().await;
            self.inner.store(&key, &data).await?;
            let seq = self.allocate_seq().await?;
            let entry = ChangeEntry {
                seq,
                key,
                value: Some(data),
            };
            self.append_log(&entry).await
        }
    }

    fn retrieve(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, PlatformError>> + Send {
        let key = key.to_owned();
        async move { self.inner.retrieve(&key).await }
    }

    fn delete(&self, key: &str) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            // Skip changelog for internal sync keys to avoid infinite recursion.
            if key.starts_with(SYNC_PREFIX) {
                return self.inner.delete(&key).await;
            }

            // Serialize data mutation + seq allocation + log append to ensure
            // the changelog accurately reflects the order mutations were applied.
            let _guard = self.seq_lock.lock().await;
            self.inner.delete(&key).await?;
            let seq = self.allocate_seq().await?;
            let entry = ChangeEntry {
                seq,
                key,
                value: None,
            };
            self.append_log(&entry).await
        }
    }

    fn list_keys(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<String>, PlatformError>> + Send {
        let prefix = prefix.to_owned();
        async move {
            let keys = self.inner.list_keys(&prefix).await?;
            // Filter out internal _sync/ keys so the wrapper is transparent
            // to callers. The _sync/ namespace is only accessed internally via
            // export_changeset which reads from inner storage directly.
            if prefix.starts_with(SYNC_PREFIX) {
                Ok(keys)
            } else {
                Ok(keys
                    .into_iter()
                    .filter(|k| !k.starts_with(SYNC_PREFIX))
                    .collect())
            }
        }
    }

    fn delete_prefix(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<u64, PlatformError>> + Send {
        let prefix = prefix.to_owned();
        async move {
            if prefix.starts_with(SYNC_PREFIX) {
                // Allow direct deletion of sync keys (e.g., for cleanup).
                return self.inner.delete_prefix(&prefix).await;
            }
            // List matching keys, filter out _sync/ keys, then delete each
            // through self.delete() to log each deletion in the changelog.
            let keys = self.inner.list_keys(&prefix).await?;
            let mut count: u64 = 0;
            for key in keys {
                if !key.starts_with(SYNC_PREFIX) {
                    self.delete(&key).await?;
                    count += 1;
                }
            }
            Ok(count)
        }
    }

    fn exists(&self, key: &str) -> impl Future<Output = Result<bool, PlatformError>> + Send {
        let key = key.to_owned();
        async move { self.inner.exists(&key).await }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::testing::InMemoryStorage;

    // Required so that `scp_testing::storage_conformance!` can resolve
    // `scp_platform::Storage` when invoked from within this crate.
    extern crate self as scp_platform;

    // -----------------------------------------------------------------------
    // Storage conformance suite — proves the wrapper is transparent.
    // -----------------------------------------------------------------------

    scp_testing::storage_conformance!(SyncableStorage::new(InMemoryStorage::new()));

    // -----------------------------------------------------------------------
    // Sync-specific tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn export_after_mutations() {
        let storage = SyncableStorage::new(InMemoryStorage::new());
        storage.store("a", b"1").await.unwrap();
        storage.store("b", b"2").await.unwrap();
        storage.store("c", b"3").await.unwrap();

        let changeset = storage.export_changeset(0).await.unwrap();
        assert_eq!(changeset.len(), 3);
        assert_eq!(changeset[0].seq, 0);
        assert_eq!(changeset[0].key, "a");
        assert_eq!(changeset[0].value, Some(b"1".to_vec()));
        assert_eq!(changeset[1].seq, 1);
        assert_eq!(changeset[1].key, "b");
        assert_eq!(changeset[1].value, Some(b"2".to_vec()));
        assert_eq!(changeset[2].seq, 2);
        assert_eq!(changeset[2].key, "c");
        assert_eq!(changeset[2].value, Some(b"3".to_vec()));
    }

    #[tokio::test]
    async fn export_since_filters() {
        let storage = SyncableStorage::new(InMemoryStorage::new());
        storage.store("a", b"1").await.unwrap();
        storage.store("b", b"2").await.unwrap();
        storage.store("c", b"3").await.unwrap();

        // Export only entries with seq >= 2.
        let changeset = storage.export_changeset(2).await.unwrap();
        assert_eq!(changeset.len(), 1);
        assert_eq!(changeset[0].seq, 2);
        assert_eq!(changeset[0].key, "c");
    }

    #[tokio::test]
    async fn apply_changeset_roundtrip() {
        let storage_a = SyncableStorage::new(InMemoryStorage::new());
        storage_a.store("key1", b"val1").await.unwrap();
        storage_a.store("key2", b"val2").await.unwrap();
        storage_a.delete("key1").await.unwrap();

        let changeset = storage_a.export_changeset(0).await.unwrap();

        let storage_b = SyncableStorage::new(InMemoryStorage::new());
        storage_b.apply_changeset(changeset).await.unwrap();

        // key1 was stored then deleted — should be absent.
        assert_eq!(storage_b.retrieve("key1").await.unwrap(), None);
        // key2 was stored — should be present.
        assert_eq!(
            storage_b.retrieve("key2").await.unwrap(),
            Some(b"val2".to_vec())
        );
    }

    #[tokio::test]
    async fn apply_changeset_lww() {
        // Verify last-write-wins: applying a changeset with conflicting writes
        // results in the last value winning.
        let storage_a = SyncableStorage::new(InMemoryStorage::new());
        storage_a.store("key", b"first").await.unwrap();
        storage_a.store("key", b"second").await.unwrap();
        storage_a.store("key", b"third").await.unwrap();

        let changeset = storage_a.export_changeset(0).await.unwrap();

        let storage_b = SyncableStorage::new(InMemoryStorage::new());
        storage_b.apply_changeset(changeset).await.unwrap();

        // The last write should win.
        assert_eq!(
            storage_b.retrieve("key").await.unwrap(),
            Some(b"third".to_vec())
        );
    }

    #[tokio::test]
    async fn next_seq_starts_at_zero() {
        let storage = SyncableStorage::new(InMemoryStorage::new());
        assert_eq!(storage.next_seq().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn next_seq_increments() {
        let storage = SyncableStorage::new(InMemoryStorage::new());
        storage.store("a", b"1").await.unwrap();
        assert_eq!(storage.next_seq().await.unwrap(), 1);
        storage.store("b", b"2").await.unwrap();
        assert_eq!(storage.next_seq().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn delete_logged_in_changelog() {
        let storage = SyncableStorage::new(InMemoryStorage::new());
        storage.store("key", b"value").await.unwrap();
        storage.delete("key").await.unwrap();

        let changeset = storage.export_changeset(0).await.unwrap();
        assert_eq!(changeset.len(), 2);
        // First entry: store.
        assert_eq!(changeset[0].value, Some(b"value".to_vec()));
        // Second entry: delete.
        assert_eq!(changeset[1].key, "key");
        assert_eq!(changeset[1].value, None);
    }

    #[tokio::test]
    async fn sync_keys_not_in_user_changelog() {
        let storage = SyncableStorage::new(InMemoryStorage::new());
        storage.store("user_key", b"data").await.unwrap();

        // The changelog should only contain the user_key entry, not the
        // _sync/ metadata writes.
        let changeset = storage.export_changeset(0).await.unwrap();
        assert_eq!(changeset.len(), 1);
        assert_eq!(changeset[0].key, "user_key");
    }
}
