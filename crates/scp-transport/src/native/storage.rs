//! Blob storage trait and implementations for the SCP native relay.
//!
//! The [`BlobStorage`] trait defines the storage interface used by the relay
//! server. Phase 1 provides [`InMemoryBlobStorage`], a `HashMap`-backed
//! implementation suitable for development and testing.
//!
//! [`BlobStorageBackend`] is a concrete enum that wraps all available storage
//! implementations, eliminating the need for generic type parameters on
//! [`RelayServer`](super::server::RelayServer) and its downstream consumers.
//! New storage backends are added as enum variants.
//!
//! Blobs are keyed by `(routing_id, blob_id)` and carry a TTL. The storage
//! layer is responsible for tracking when blobs expire so the relay's
//! background task can purge them.
//!
//! See ADR-004 in `.docs/adrs/phase-1.md` for the full specification.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

/// A stored blob with its metadata.
#[derive(Debug, Clone)]
pub struct StoredBlob {
    /// Per-context pseudonym this blob was published to (32 bytes).
    pub routing_id: [u8; 32],
    /// SHA-256 hash identifying the blob (32 bytes).
    pub blob_id: [u8; 32],
    /// Optional recipient pseudonym for directed delivery (32 bytes).
    pub recipient_hint: Option<[u8; 32]>,
    /// TTL at time of storage (seconds).
    pub blob_ttl: u32,
    /// Unix timestamp when the relay stored the blob.
    pub stored_at: u64,
    /// The opaque blob content.
    pub blob: Vec<u8>,
}

/// Errors that can occur during blob storage operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum StorageError {
    /// The storage backend is full and cannot accept new blobs.
    #[error("storage full")]
    StorageFull,

    /// An internal storage error occurred.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Trait defining the blob storage interface for the SCP native relay.
///
/// Implementations must be `Send + Sync` to support concurrent access from
/// multiple connection handlers. All methods are async to allow for
/// future persistent backends (`SQLite`, redb).
///
/// # Phase 1
///
/// Phase 1 provides [`InMemoryBlobStorage`], a `HashMap`-backed implementation.
/// Persistent backends are planned for later phases.
pub trait BlobStorage: Send + Sync {
    /// Stores a blob and returns the stored metadata.
    ///
    /// The `stored_at` timestamp is set by the storage implementation.
    /// If a blob with the same `blob_id` already exists under the same
    /// `routing_id`, the implementation may overwrite or ignore.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::StorageFull`] if the backend cannot accept
    /// more blobs.
    fn store(
        &self,
        routing_id: [u8; 32],
        blob_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        blob_ttl: u32,
        blob: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<StoredBlob, StorageError>> + Send;

    /// Retrieves a specific blob by its `blob_id`.
    ///
    /// Returns `None` if the blob does not exist or has expired.
    fn get(
        &self,
        blob_id: &[u8; 32],
    ) -> impl std::future::Future<Output = Result<Option<StoredBlob>, StorageError>> + Send;

    /// Queries stored blobs for a `routing_id`, optionally filtered by a
    /// `since` timestamp, with an optional `limit`.
    ///
    /// Results are ordered oldest-first (ascending `stored_at` timestamp).
    fn query(
        &self,
        routing_id: &[u8; 32],
        since: Option<u64>,
        limit: u32,
    ) -> impl std::future::Future<Output = Result<Vec<StoredBlob>, StorageError>> + Send;

    /// Deletes a blob by its `blob_id`. Best-effort; returns `true` if
    /// the blob was found and removed.
    fn delete(
        &self,
        blob_id: &[u8; 32],
    ) -> impl std::future::Future<Output = Result<bool, StorageError>> + Send;

    /// Removes all blobs whose TTL has expired. Returns the number of
    /// blobs purged.
    fn purge_expired(
        &self,
    ) -> impl std::future::Future<Output = Result<usize, StorageError>> + Send;
}

/// Internal entry stored in the in-memory map.
#[derive(Debug, Clone)]
struct BlobEntry {
    stored_blob: StoredBlob,
    /// Absolute expiry time (unix timestamp).
    expires_at: u64,
}

/// Secondary index mapping `routing_id` to a list of `blob_id`s.
type RoutingIndex = Arc<RwLock<HashMap<[u8; 32], Vec<[u8; 32]>>>>;

/// Default maximum number of blobs that can be stored.
const DEFAULT_MAX_BLOBS: usize = 100_000;

/// In-memory blob storage backed by a `HashMap`.
///
/// Suitable for development and testing. Not persistent -- all data is lost
/// when the process exits.
///
/// Thread-safe via `Arc<RwLock<...>>`. Clone is cheap (shared inner state).
#[derive(Debug, Clone)]
pub struct InMemoryBlobStorage {
    /// Map from `blob_id` to blob entry.
    blobs: Arc<RwLock<HashMap<[u8; 32], BlobEntry>>>,
    /// Secondary index: `routing_id` -> set of `blob_id`s.
    routing_index: RoutingIndex,
    /// Maximum number of blobs this storage will accept.
    max_blobs: usize,
}

impl InMemoryBlobStorage {
    /// Creates a new, empty in-memory blob storage with default capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_BLOBS)
    }

    /// Creates a new, empty in-memory blob storage with the given capacity limit.
    #[must_use]
    pub fn with_capacity(max_blobs: usize) -> Self {
        Self {
            blobs: Arc::new(RwLock::new(HashMap::new())),
            routing_index: Arc::new(RwLock::new(HashMap::new())),
            max_blobs,
        }
    }
}

impl Default for InMemoryBlobStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the current unix timestamp in seconds.
///
/// # Errors
///
/// Returns [`StorageError::Internal`] if the system clock is unavailable.
fn now_secs() -> Result<u64, StorageError> {
    scp_core::time::now_secs().map_err(|e| StorageError::Internal(format!("clock error: {e}")))
}

// Lock guards are held for the minimal scope needed across async operations.
#[allow(clippy::significant_drop_tightening)]
impl BlobStorage for InMemoryBlobStorage {
    async fn store(
        &self,
        routing_id: [u8; 32],
        blob_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        blob_ttl: u32,
        blob: Vec<u8>,
    ) -> Result<StoredBlob, StorageError> {
        let stored_at = now_secs()?;
        let expires_at = stored_at.saturating_add(u64::from(blob_ttl));

        let stored_blob = StoredBlob {
            routing_id,
            blob_id,
            recipient_hint,
            blob_ttl,
            stored_at,
            blob,
        };

        let entry = BlobEntry {
            stored_blob: stored_blob.clone(),
            expires_at,
        };

        {
            let mut blobs = self.blobs.write().await;
            // Enforce capacity limit. Overwrites of existing blob_ids are allowed.
            if blobs.len() >= self.max_blobs && !blobs.contains_key(&blob_id) {
                return Err(StorageError::StorageFull);
            }
            blobs.insert(blob_id, entry);
        }

        {
            let mut index = self.routing_index.write().await;
            index.entry(routing_id).or_default().push(blob_id);
        }

        Ok(stored_blob)
    }

    async fn get(&self, blob_id: &[u8; 32]) -> Result<Option<StoredBlob>, StorageError> {
        let blobs = self.blobs.read().await;
        let now = now_secs()?;

        Ok(blobs.get(blob_id).and_then(|entry| {
            if entry.expires_at > now {
                Some(entry.stored_blob.clone())
            } else {
                None
            }
        }))
    }

    async fn query(
        &self,
        routing_id: &[u8; 32],
        since: Option<u64>,
        limit: u32,
    ) -> Result<Vec<StoredBlob>, StorageError> {
        let blobs = self.blobs.read().await;
        let index = self.routing_index.read().await;
        let now = now_secs()?;

        let Some(blob_ids) = index.get(routing_id) else {
            return Ok(Vec::new());
        };

        let mut results: Vec<StoredBlob> = blob_ids
            .iter()
            .filter_map(|id| {
                let entry = blobs.get(id)?;
                // Skip expired blobs.
                if entry.expires_at <= now {
                    return None;
                }
                // Apply since filter.
                if let Some(since_ts) = since
                    && entry.stored_blob.stored_at <= since_ts
                {
                    return None;
                }
                Some(entry.stored_blob.clone())
            })
            .collect();

        // Sort oldest-first (ascending stored_at).
        results.sort_by_key(|b| b.stored_at);

        // Apply limit.
        results.truncate(limit as usize);

        Ok(results)
    }

    async fn delete(&self, blob_id: &[u8; 32]) -> Result<bool, StorageError> {
        let mut blobs = self.blobs.write().await;

        if let Some(entry) = blobs.remove(blob_id) {
            let routing_id = entry.stored_blob.routing_id;
            drop(blobs); // Release blobs lock before acquiring index lock.

            let mut index = self.routing_index.write().await;
            if let Some(ids) = index.get_mut(&routing_id) {
                ids.retain(|id| id != blob_id);
                if ids.is_empty() {
                    index.remove(&routing_id);
                }
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn purge_expired(&self) -> Result<usize, StorageError> {
        let now = now_secs()?;

        // Phase 1: identify expired blob IDs under a read lock.
        let expired_ids: Vec<([u8; 32], [u8; 32])> = {
            let blobs = self.blobs.read().await;
            blobs
                .iter()
                .filter(|(_, entry)| entry.expires_at <= now)
                .map(|(blob_id, entry)| (*blob_id, entry.stored_blob.routing_id))
                .collect()
        };

        if expired_ids.is_empty() {
            return Ok(0);
        }

        let count = expired_ids.len();

        // Phase 2: remove expired entries under a brief write lock.
        {
            let mut blobs = self.blobs.write().await;
            let mut index = self.routing_index.write().await;

            for (blob_id, routing_id) in &expired_ids {
                blobs.remove(blob_id);
                if let Some(ids) = index.get_mut(routing_id) {
                    ids.retain(|id| id != blob_id);
                    if ids.is_empty() {
                        index.remove(routing_id);
                    }
                }
            }
        }

        Ok(count)
    }
}

// ---------------------------------------------------------------------------
// Enum dispatch: concrete storage backend (eliminates generic propagation)
// ---------------------------------------------------------------------------

/// Concrete blob storage backend used by [`RelayServer`](super::server::RelayServer).
///
/// Wraps all available [`BlobStorage`] implementations behind an enum,
/// eliminating the `<S: BlobStorage>` generic parameter from `RelayServer`
/// and all downstream handler functions. This trades a single `match` per
/// storage call (negligible cost vs. the I/O itself) for removing turbofish
/// operators and generic propagation across the entire server stack.
///
/// New backends (e.g., `SQLite`, redb) are added as variants here.
///
/// See issue [#242](https://github.com/limn-works/scp/issues/242).
#[derive(Debug, Clone)]
pub enum BlobStorageBackend {
    /// In-memory `HashMap`-backed storage (development / testing).
    InMemory(InMemoryBlobStorage),
}

impl BlobStorageBackend {
    /// Creates a new in-memory backend with default capacity.
    #[must_use]
    pub fn in_memory() -> Self {
        Self::InMemory(InMemoryBlobStorage::new())
    }

    /// Creates a new in-memory backend with the given capacity limit.
    #[must_use]
    pub fn in_memory_with_capacity(max_blobs: usize) -> Self {
        Self::InMemory(InMemoryBlobStorage::with_capacity(max_blobs))
    }
}

impl Default for BlobStorageBackend {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl From<InMemoryBlobStorage> for BlobStorageBackend {
    fn from(storage: InMemoryBlobStorage) -> Self {
        Self::InMemory(storage)
    }
}

impl BlobStorage for BlobStorageBackend {
    async fn store(
        &self,
        routing_id: [u8; 32],
        blob_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        blob_ttl: u32,
        blob: Vec<u8>,
    ) -> Result<StoredBlob, StorageError> {
        match self {
            Self::InMemory(s) => {
                s.store(routing_id, blob_id, recipient_hint, blob_ttl, blob)
                    .await
            }
        }
    }

    async fn get(&self, blob_id: &[u8; 32]) -> Result<Option<StoredBlob>, StorageError> {
        match self {
            Self::InMemory(s) => s.get(blob_id).await,
        }
    }

    async fn query(
        &self,
        routing_id: &[u8; 32],
        since: Option<u64>,
        limit: u32,
    ) -> Result<Vec<StoredBlob>, StorageError> {
        match self {
            Self::InMemory(s) => s.query(routing_id, since, limit).await,
        }
    }

    async fn delete(&self, blob_id: &[u8; 32]) -> Result<bool, StorageError> {
        match self {
            Self::InMemory(s) => s.delete(blob_id).await,
        }
    }

    async fn purge_expired(&self) -> Result<usize, StorageError> {
        match self {
            Self::InMemory(s) => s.purge_expired().await,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn make_blob_id(data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        out
    }

    #[tokio::test]
    async fn store_and_get_returns_blob() {
        let storage = InMemoryBlobStorage::new();
        let routing_id = [0xAA; 32];
        let blob_data = vec![1, 2, 3, 4];
        let blob_id = make_blob_id(&blob_data);

        let stored = storage
            .store(routing_id, blob_id, None, 3600, blob_data.clone())
            .await
            .unwrap();

        assert_eq!(stored.blob_id, blob_id);
        assert_eq!(stored.routing_id, routing_id);
        assert_eq!(stored.blob, blob_data);
        assert_eq!(stored.blob_ttl, 3600);
        assert!(stored.stored_at > 0);

        let retrieved = storage.get(&blob_id).await.unwrap().unwrap();
        assert_eq!(retrieved.blob, blob_data);
        assert_eq!(retrieved.blob_id, blob_id);
    }

    #[tokio::test]
    async fn get_nonexistent_returns_none() {
        let storage = InMemoryBlobStorage::new();
        let blob_id = [0xFF; 32];
        let result = storage.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_removes_blob() {
        let storage = InMemoryBlobStorage::new();
        let routing_id = [0xAA; 32];
        let blob_data = vec![5, 6, 7];
        let blob_id = make_blob_id(&blob_data);

        storage
            .store(routing_id, blob_id, None, 3600, blob_data)
            .await
            .unwrap();

        let deleted = storage.delete(&blob_id).await.unwrap();
        assert!(deleted);

        let result = storage.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_nonexistent_returns_false() {
        let storage = InMemoryBlobStorage::new();
        let blob_id = [0xFF; 32];
        let deleted = storage.delete(&blob_id).await.unwrap();
        assert!(!deleted);
    }

    #[tokio::test]
    async fn query_returns_blobs_for_routing_id() {
        let storage = InMemoryBlobStorage::new();
        let routing_id = [0xAA; 32];

        for i in 0u8..5 {
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            storage
                .store(routing_id, blob_id, None, 3600, data)
                .await
                .unwrap();
        }

        let results = storage.query(&routing_id, None, 100).await.unwrap();
        assert_eq!(results.len(), 5);
    }

    #[tokio::test]
    async fn query_respects_limit() {
        let storage = InMemoryBlobStorage::new();
        let routing_id = [0xBB; 32];

        for i in 0u8..10 {
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            storage
                .store(routing_id, blob_id, None, 3600, data)
                .await
                .unwrap();
        }

        let results = storage.query(&routing_id, None, 3).await.unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn query_returns_oldest_first() {
        let storage = InMemoryBlobStorage::new();
        let routing_id = [0xCC; 32];

        for i in 0u8..3 {
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            storage
                .store(routing_id, blob_id, None, 3600, data)
                .await
                .unwrap();
        }

        let results = storage.query(&routing_id, None, 100).await.unwrap();
        // All should be sorted by stored_at ascending.
        for window in results.windows(2) {
            assert!(window[0].stored_at <= window[1].stored_at);
        }
    }

    #[tokio::test]
    async fn query_different_routing_id_returns_empty() {
        let storage = InMemoryBlobStorage::new();
        let routing_id_a = [0xAA; 32];
        let routing_id_b = [0xBB; 32];

        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);
        storage
            .store(routing_id_a, blob_id, None, 3600, data)
            .await
            .unwrap();

        let results = storage.query(&routing_id_b, None, 100).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn store_with_recipient_hint_preserves_it() {
        let storage = InMemoryBlobStorage::new();
        let routing_id = [0xAA; 32];
        let hint = [0xBB; 32];
        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);

        let stored = storage
            .store(routing_id, blob_id, Some(hint), 3600, data)
            .await
            .unwrap();

        assert_eq!(stored.recipient_hint, Some(hint));

        let retrieved = storage.get(&blob_id).await.unwrap().unwrap();
        assert_eq!(retrieved.recipient_hint, Some(hint));
    }

    #[tokio::test]
    async fn purge_expired_removes_old_blobs() {
        let storage = InMemoryBlobStorage::new();
        let routing_id = [0xAA; 32];
        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);

        // Store with TTL of 0 seconds so it expires immediately.
        // We manually manipulate the entry after storage to ensure expiry.
        storage
            .store(routing_id, blob_id, None, 1, data)
            .await
            .unwrap();

        // Manually set expires_at to the past.
        {
            let mut blobs = storage.blobs.write().await;
            if let Some(entry) = blobs.get_mut(&blob_id) {
                entry.expires_at = 1; // Far in the past.
            }
        }

        let purged = storage.purge_expired().await.unwrap();
        assert_eq!(purged, 1);

        let result = storage.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn purge_expired_does_not_remove_active_blobs() {
        let storage = InMemoryBlobStorage::new();
        let routing_id = [0xAA; 32];
        let data = vec![4, 5, 6];
        let blob_id = make_blob_id(&data);

        storage
            .store(routing_id, blob_id, None, 3600, data)
            .await
            .unwrap();

        let purged = storage.purge_expired().await.unwrap();
        assert_eq!(purged, 0);

        let result = storage.get(&blob_id).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn default_creates_empty_storage() {
        let storage = InMemoryBlobStorage::default();
        let blob_id = [0xFF; 32];
        let result = storage.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_cleans_up_routing_index() {
        let storage = InMemoryBlobStorage::new();
        let routing_id = [0xDD; 32];
        let data = vec![7, 8, 9];
        let blob_id = make_blob_id(&data);

        storage
            .store(routing_id, blob_id, None, 3600, data)
            .await
            .unwrap();

        storage.delete(&blob_id).await.unwrap();

        // After deletion, query should return empty.
        let results = storage.query(&routing_id, None, 100).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn store_rejects_when_at_capacity() {
        let storage = InMemoryBlobStorage::with_capacity(3);
        let routing_id = [0xAA; 32];

        // Fill to capacity.
        for i in 0u8..3 {
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            storage
                .store(routing_id, blob_id, None, 3600, data)
                .await
                .unwrap();
        }

        // The 4th store should fail.
        let data = vec![99u8; 10];
        let blob_id = make_blob_id(&data);
        let result = storage.store(routing_id, blob_id, None, 3600, data).await;
        assert!(matches!(result, Err(StorageError::StorageFull)));
    }

    #[tokio::test]
    async fn store_allows_overwrite_at_capacity() {
        let storage = InMemoryBlobStorage::with_capacity(2);
        let routing_id = [0xAA; 32];

        let data1 = vec![1u8; 10];
        let blob_id1 = make_blob_id(&data1);
        storage
            .store(routing_id, blob_id1, None, 3600, data1.clone())
            .await
            .unwrap();

        let data2 = vec![2u8; 10];
        let blob_id2 = make_blob_id(&data2);
        storage
            .store(routing_id, blob_id2, None, 3600, data2)
            .await
            .unwrap();

        // At capacity (2/2). Overwriting an existing blob_id should succeed.
        let updated_data = vec![1u8; 20];
        let result = storage
            .store(routing_id, blob_id1, None, 7200, updated_data)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn store_succeeds_after_delete_frees_capacity() {
        let storage = InMemoryBlobStorage::with_capacity(2);
        let routing_id = [0xAA; 32];

        let data1 = vec![1u8; 10];
        let blob_id1 = make_blob_id(&data1);
        storage
            .store(routing_id, blob_id1, None, 3600, data1)
            .await
            .unwrap();

        let data2 = vec![2u8; 10];
        let blob_id2 = make_blob_id(&data2);
        storage
            .store(routing_id, blob_id2, None, 3600, data2)
            .await
            .unwrap();

        // Delete one blob to free capacity.
        storage.delete(&blob_id1).await.unwrap();

        // Now a new store should succeed.
        let data3 = vec![3u8; 10];
        let blob_id3 = make_blob_id(&data3);
        let result = storage.store(routing_id, blob_id3, None, 3600, data3).await;
        assert!(result.is_ok());
    }
}
