//! Blob storage trait and in-memory implementation for the SCP native relay.
//!
//! The [`BlobStorage`] trait defines the storage interface used by the relay
//! server. Phase 1 provides [`InMemoryBlobStorage`], a `HashMap`-backed
//! implementation suitable for development and testing.
//!
//! Blobs are keyed by `(routing_id, blob_id)` and carry a TTL. The storage
//! layer is responsible for tracking when blobs expire so the relay's
//! background task can purge them.
//!
//! See ADR-004 in `.docs/adrs/phase-1.md` for the full specification.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
}

impl InMemoryBlobStorage {
    /// Creates a new, empty in-memory blob storage.
    #[must_use]
    pub fn new() -> Self {
        Self {
            blobs: Arc::new(RwLock::new(HashMap::new())),
            routing_index: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryBlobStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the current unix timestamp in seconds.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

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
        let stored_at = now_secs();
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
        let now = now_secs();

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
        let now = now_secs();

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
        let now = now_secs();
        let mut blobs = self.blobs.write().await;
        let mut index = self.routing_index.write().await;

        let expired_ids: Vec<([u8; 32], [u8; 32])> = blobs
            .iter()
            .filter(|(_, entry)| entry.expires_at <= now)
            .map(|(blob_id, entry)| (*blob_id, entry.stored_blob.routing_id))
            .collect();

        let count = expired_ids.len();

        for (blob_id, routing_id) in &expired_ids {
            blobs.remove(blob_id);
            if let Some(ids) = index.get_mut(routing_id) {
                ids.retain(|id| id != blob_id);
                if ids.is_empty() {
                    index.remove(routing_id);
                }
            }
        }

        Ok(count)
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
}
