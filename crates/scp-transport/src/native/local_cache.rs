//! Size-limited blob cache wrapper for P2P clients.
//!
//! [`LocalBlobCache`] wraps any [`BlobStorage`] implementation and adds
//! configurable size-limited caching with oldest-first eviction. This enables
//! P2P clients without a relay to cache blobs locally while bounding memory
//! usage.
//!
//! # Eviction strategy
//!
//! When a `store()` call causes the blob count to exceed `max_cache_size`:
//! 1. Expired blobs are purged first via `purge_expired()`.
//! 2. If still over the limit, the oldest blobs (by `stored_at` timestamp)
//!    are deleted until the count is at or below the limit.
//!
//! See SCP-PERSIST-065.

use std::sync::Arc;

use tokio::sync::Mutex;

use super::storage::{BlobStorage, StorageError, StoredBlob};

/// Clock function type for timestamp injection (testing).
///
/// Returns the current Unix timestamp in seconds. The default uses
/// [`scp_core::time::now_secs`].
type ClockFn = Arc<dyn Fn() -> Result<u64, StorageError> + Send + Sync>;

/// Metadata tracked for each cached blob, used for eviction ordering.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The blob's unique identifier.
    blob_id: [u8; 32],
    /// Unix timestamp when the blob was stored (used for oldest-first eviction).
    stored_at: u64,
}

/// A size-limited blob cache that wraps any [`BlobStorage`] implementation.
///
/// Delegates all operations to the inner storage and enforces a maximum blob
/// count by evicting the oldest blobs when the limit is exceeded after a
/// `store()` call.
///
/// # Thread safety
///
/// The tracking state is protected by a [`Mutex`]. The inner storage's own
/// concurrency guarantees are preserved.
pub struct LocalBlobCache<S: BlobStorage> {
    /// The underlying blob storage implementation.
    inner: S,
    /// Maximum number of blobs to retain in the cache.
    max_cache_size: usize,
    /// Ordered list of blob metadata for eviction (oldest first).
    entries: Arc<Mutex<Vec<CacheEntry>>>,
    /// Clock function for obtaining the current timestamp.
    ///
    /// Reserved for future eviction policies that need time awareness beyond
    /// what the inner storage provides (e.g., TTL-aware eviction ordering).
    /// Currently stored but not read — the inner storage handles all
    /// time-dependent operations.
    #[allow(dead_code)]
    clock: ClockFn,
}

impl<S: BlobStorage + Clone> Clone for LocalBlobCache<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            max_cache_size: self.max_cache_size,
            entries: Arc::clone(&self.entries),
            clock: Arc::clone(&self.clock),
        }
    }
}

impl<S: BlobStorage> LocalBlobCache<S> {
    /// Creates a new `LocalBlobCache` wrapping the given storage with the
    /// specified maximum cache size.
    ///
    /// Uses the system clock for timestamps.
    #[must_use]
    pub fn new(inner: S, max_cache_size: usize) -> Self {
        Self {
            inner,
            max_cache_size,
            entries: Arc::new(Mutex::new(Vec::new())),
            clock: Arc::new(|| {
                scp_core::time::now_secs()
                    .map_err(|e| StorageError::Internal(format!("clock error: {e}")))
            }),
        }
    }

    /// Creates a new `LocalBlobCache` with a custom clock function for testing.
    ///
    /// The clock function is called to obtain the current Unix timestamp in
    /// seconds whenever time-dependent operations are performed.
    #[must_use]
    pub fn with_clock(inner: S, max_cache_size: usize, clock: ClockFn) -> Self {
        Self {
            inner,
            max_cache_size,
            entries: Arc::new(Mutex::new(Vec::new())),
            clock,
        }
    }

    /// Returns the current number of tracked blobs.
    #[cfg(test)]
    async fn tracked_count(&self) -> usize {
        self.entries.lock().await.len()
    }

    /// Evicts blobs until the tracked count is at or below `max_cache_size`.
    ///
    /// First purges expired blobs from the inner storage, then removes the
    /// oldest non-expired blobs if still over the limit.
    #[allow(clippy::significant_drop_tightening)]
    async fn evict_if_needed(&self) -> Result<(), StorageError> {
        let mut entries = self.entries.lock().await;

        if entries.len() <= self.max_cache_size {
            return Ok(());
        }

        // Phase 1: purge expired blobs from inner storage.
        let purged = self.inner.purge_expired().await?;

        if purged > 0 {
            // Rebuild tracking: remove entries whose blobs were purged.
            // The inner storage already removed expired blobs, so we verify
            // each tracked entry still exists via `get()`.
            let mut retained = Vec::with_capacity(entries.len());
            for entry in entries.iter() {
                if (self.inner.get(&entry.blob_id).await?).is_some() {
                    retained.push(entry.clone());
                }
            }
            *entries = retained;
        }

        // Phase 2: if still over limit, evict oldest blobs.
        // Entries are maintained in insertion order; sort by stored_at for
        // deterministic oldest-first eviction.
        entries.sort_by_key(|e| e.stored_at);

        while entries.len() > self.max_cache_size {
            let oldest = entries.remove(0);
            // Best-effort delete — if it fails, we still remove from tracking.
            let _ = self.inner.delete(&oldest.blob_id).await;
        }

        Ok(())
    }
}

#[allow(clippy::significant_drop_tightening)]
impl<S: BlobStorage> BlobStorage for LocalBlobCache<S> {
    async fn store(
        &self,
        routing_id: [u8; 32],
        blob_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        blob_ttl: u32,
        blob: Vec<u8>,
    ) -> Result<StoredBlob, StorageError> {
        let stored = self
            .inner
            .store(routing_id, blob_id, recipient_hint, blob_ttl, blob)
            .await?;

        // Update tracking.
        {
            let mut entries = self.entries.lock().await;
            // Remove any existing entry with the same blob_id (overwrite case).
            entries.retain(|e| e.blob_id != blob_id);
            entries.push(CacheEntry {
                blob_id,
                stored_at: stored.stored_at,
            });
        }

        // Evict if over the limit.
        self.evict_if_needed().await?;

        Ok(stored)
    }

    async fn get(&self, blob_id: &[u8; 32]) -> Result<Option<StoredBlob>, StorageError> {
        self.inner.get(blob_id).await
    }

    async fn query(
        &self,
        routing_id: &[u8; 32],
        since: Option<u64>,
        limit: u32,
    ) -> Result<Vec<StoredBlob>, StorageError> {
        self.inner.query(routing_id, since, limit).await
    }

    async fn delete(&self, blob_id: &[u8; 32]) -> Result<bool, StorageError> {
        let removed = self.inner.delete(blob_id).await?;
        if removed {
            let mut entries = self.entries.lock().await;
            entries.retain(|e| &e.blob_id != blob_id);
        }
        Ok(removed)
    }

    async fn purge_expired(&self) -> Result<usize, StorageError> {
        let purged = self.inner.purge_expired().await?;
        if purged > 0 {
            // Rebuild tracking — remove entries whose blobs no longer exist.
            let mut entries = self.entries.lock().await;
            let mut retained = Vec::with_capacity(entries.len());
            for entry in entries.iter() {
                if (self.inner.get(&entry.blob_id).await?).is_some() {
                    retained.push(entry.clone());
                }
            }
            *entries = retained;
        }
        Ok(purged)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::native::storage::InMemoryBlobStorage;

    fn make_blob_id(data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        out
    }

    fn controllable_clock(start: u64) -> (ClockFn, Arc<AtomicU64>) {
        let time = Arc::new(AtomicU64::new(start));
        let time_clone = Arc::clone(&time);
        let clock: ClockFn = Arc::new(move || Ok(time_clone.load(Ordering::Relaxed)));
        (clock, time)
    }

    // -----------------------------------------------------------------------
    // BlobStorage trait conformance tests (mirrors spec §16.12.6)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn store_retrieve_roundtrip() {
        let inner = InMemoryBlobStorage::new();
        let cache = LocalBlobCache::new(inner, 100);
        let routing_id = [0xAA; 32];
        let blob_data = vec![1, 2, 3, 4];
        let blob_id = make_blob_id(&blob_data);

        let stored = cache
            .store(routing_id, blob_id, None, 3600, blob_data.clone())
            .await
            .unwrap();

        assert_eq!(stored.blob_id, blob_id);
        assert_eq!(stored.routing_id, routing_id);
        assert_eq!(stored.blob, blob_data);
        assert_eq!(stored.blob_ttl, 3600);
        assert!(stored.stored_at > 0);

        let retrieved = cache.get(&blob_id).await.unwrap().unwrap();
        assert_eq!(retrieved.blob, blob_data);
        assert_eq!(retrieved.blob_id, blob_id);
    }

    #[tokio::test]
    async fn retrieve_missing_returns_none() {
        let inner = InMemoryBlobStorage::new();
        let cache = LocalBlobCache::new(inner, 100);
        let blob_id = [0xFF; 32];
        let result = cache.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn store_and_delete_removes_blob() {
        let inner = InMemoryBlobStorage::new();
        let cache = LocalBlobCache::new(inner, 100);
        let routing_id = [0xAA; 32];
        let blob_data = vec![5, 6, 7];
        let blob_id = make_blob_id(&blob_data);

        cache
            .store(routing_id, blob_id, None, 3600, blob_data)
            .await
            .unwrap();

        let deleted = cache.delete(&blob_id).await.unwrap();
        assert!(deleted);

        let result = cache.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_nonexistent_returns_false() {
        let inner = InMemoryBlobStorage::new();
        let cache = LocalBlobCache::new(inner, 100);
        let blob_id = [0xFF; 32];
        let deleted = cache.delete(&blob_id).await.unwrap();
        assert!(!deleted);
    }

    #[tokio::test]
    async fn query_returns_blobs_for_routing_id() {
        let inner = InMemoryBlobStorage::new();
        let cache = LocalBlobCache::new(inner, 100);
        let routing_id = [0xAA; 32];

        for i in 0u8..5 {
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            cache
                .store(routing_id, blob_id, None, 3600, data)
                .await
                .unwrap();
        }

        let results = cache.query(&routing_id, None, 100).await.unwrap();
        assert_eq!(results.len(), 5);
    }

    #[tokio::test]
    async fn query_respects_limit() {
        let inner = InMemoryBlobStorage::new();
        let cache = LocalBlobCache::new(inner, 100);
        let routing_id = [0xBB; 32];

        for i in 0u8..10 {
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            cache
                .store(routing_id, blob_id, None, 3600, data)
                .await
                .unwrap();
        }

        let results = cache.query(&routing_id, None, 3).await.unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn query_returns_oldest_first() {
        let inner = InMemoryBlobStorage::new();
        let cache = LocalBlobCache::new(inner, 100);
        let routing_id = [0xCC; 32];

        for i in 0u8..3 {
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            cache
                .store(routing_id, blob_id, None, 3600, data)
                .await
                .unwrap();
        }

        let results = cache.query(&routing_id, None, 100).await.unwrap();
        for window in results.windows(2) {
            assert!(window[0].stored_at <= window[1].stored_at);
        }
    }

    #[tokio::test]
    async fn query_different_routing_id_returns_empty() {
        let inner = InMemoryBlobStorage::new();
        let cache = LocalBlobCache::new(inner, 100);
        let routing_id_a = [0xAA; 32];
        let routing_id_b = [0xBB; 32];

        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);
        cache
            .store(routing_id_a, blob_id, None, 3600, data)
            .await
            .unwrap();

        let results = cache.query(&routing_id_b, None, 100).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn store_with_recipient_hint_preserves_it() {
        let inner = InMemoryBlobStorage::new();
        let cache = LocalBlobCache::new(inner, 100);
        let routing_id = [0xAA; 32];
        let hint = [0xBB; 32];
        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);

        let stored = cache
            .store(routing_id, blob_id, Some(hint), 3600, data)
            .await
            .unwrap();

        assert_eq!(stored.recipient_hint, Some(hint));

        let retrieved = cache.get(&blob_id).await.unwrap().unwrap();
        assert_eq!(retrieved.recipient_hint, Some(hint));
    }

    #[tokio::test]
    async fn delete_cleans_up_routing_index() {
        let inner = InMemoryBlobStorage::new();
        let cache = LocalBlobCache::new(inner, 100);
        let routing_id = [0xDD; 32];
        let data = vec![7, 8, 9];
        let blob_id = make_blob_id(&data);

        cache
            .store(routing_id, blob_id, None, 3600, data)
            .await
            .unwrap();

        cache.delete(&blob_id).await.unwrap();

        let results = cache.query(&routing_id, None, 100).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn store_allows_overwrite_at_capacity() {
        let inner = InMemoryBlobStorage::with_capacity(10);
        let cache = LocalBlobCache::new(inner, 2);
        let routing_id = [0xAA; 32];

        let data1 = vec![1u8; 10];
        let blob_id1 = make_blob_id(&data1);
        cache
            .store(routing_id, blob_id1, None, 3600, data1)
            .await
            .unwrap();

        let data2 = vec![2u8; 10];
        let blob_id2 = make_blob_id(&data2);
        cache
            .store(routing_id, blob_id2, None, 3600, data2)
            .await
            .unwrap();

        // Overwrite blob_id1 — should succeed even though at capacity.
        let updated_data = vec![1u8; 20];
        let result = cache
            .store(routing_id, blob_id1, None, 7200, updated_data)
            .await;
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Cache-specific tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn evicts_oldest_when_full() {
        let inner = InMemoryBlobStorage::with_capacity(100);
        let cache = LocalBlobCache::new(inner, 3);
        let routing_id = [0xAA; 32];

        let mut blob_ids = Vec::new();
        for i in 0u8..4 {
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            blob_ids.push(blob_id);
            cache
                .store(routing_id, blob_id, None, 3600, data)
                .await
                .unwrap();
        }

        // The oldest blob (index 0) should have been evicted.
        let oldest = cache.get(&blob_ids[0]).await.unwrap();
        assert!(oldest.is_none(), "oldest blob should have been evicted");

        // The remaining 3 blobs should still exist.
        for blob_id in &blob_ids[1..] {
            let result = cache.get(blob_id).await.unwrap();
            assert!(result.is_some(), "newer blob should still exist");
        }

        // Tracking should report exactly max_cache_size entries.
        assert_eq!(cache.tracked_count().await, 3);
    }

    #[tokio::test]
    async fn delete_updates_tracking() {
        let inner = InMemoryBlobStorage::with_capacity(100);
        let cache = LocalBlobCache::new(inner, 3);
        let routing_id = [0xAA; 32];

        // Store 3 blobs (at capacity).
        let mut blob_ids = Vec::new();
        for i in 0u8..3 {
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            blob_ids.push(blob_id);
            cache
                .store(routing_id, blob_id, None, 3600, data)
                .await
                .unwrap();
        }

        assert_eq!(cache.tracked_count().await, 3);

        // Delete one blob — frees a slot.
        cache.delete(&blob_ids[1]).await.unwrap();
        assert_eq!(cache.tracked_count().await, 2);

        // Store another blob — should not trigger eviction since we're under the limit.
        let new_data = vec![99u8; 10];
        let new_blob_id = make_blob_id(&new_data);
        cache
            .store(routing_id, new_blob_id, None, 3600, new_data)
            .await
            .unwrap();

        // All remaining blobs should exist (no eviction triggered).
        assert!(cache.get(&blob_ids[0]).await.unwrap().is_some());
        assert!(cache.get(&blob_ids[2]).await.unwrap().is_some());
        assert!(cache.get(&new_blob_id).await.unwrap().is_some());
        assert_eq!(cache.tracked_count().await, 3);
    }

    #[tokio::test]
    async fn purge_expired_before_evict() {
        // Use a controllable clock: start at t=1_000_000.
        let (clock, time) = controllable_clock(1_000_000);

        // Use InMemoryBlobStorage (which uses system clock internally).
        // We'll store blobs with short TTL, then manipulate the inner storage
        // to simulate expiry. For this test, we directly use the inner storage
        // to force expiry by storing with TTL=1 and then advancing.
        //
        // Note: InMemoryBlobStorage uses system clock, so to properly test
        // expiry we manipulate entry timestamps directly.
        let inner = InMemoryBlobStorage::with_capacity(100);
        let cache = LocalBlobCache::with_clock(inner, 3, clock);
        let routing_id = [0xAA; 32];

        // Store 3 blobs with TTL=1 second.
        let mut blob_ids = Vec::new();
        for i in 0u8..3 {
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            blob_ids.push(blob_id);
            cache
                .store(routing_id, blob_id, None, 1, data)
                .await
                .unwrap();
        }

        assert_eq!(cache.tracked_count().await, 3);

        // Force the inner storage entries to be expired by manipulating the
        // InMemoryBlobStorage internals. Since InMemoryBlobStorage uses system
        // clock in `now_secs()`, and we can't control that, we access the
        // inner storage's blobs directly through our wrapper.
        //
        // Instead, we test the flow where purge_expired is called via the
        // eviction path. The InMemoryBlobStorage::purge_expired uses real time,
        // so for TTL=1, blobs won't actually be expired unless real time passes.
        //
        // The correct test: store 3 short-TTL blobs, wait for them to expire
        // naturally (TTL=1), then store a 4th. The eviction path should purge
        // the expired ones first.
        //
        // We use tokio::time::sleep with a short delay to let TTL=1 expire.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Advance our controllable clock too (for consistency).
        time.store(1_000_002, Ordering::Relaxed);

        // Now store a 4th blob. This should trigger eviction.
        // Since the 3 existing blobs have expired, purge_expired should
        // remove them, leaving room for the new one.
        let new_data = vec![99u8; 10];
        let new_blob_id = make_blob_id(&new_data);
        cache
            .store(routing_id, new_blob_id, None, 3600, new_data)
            .await
            .unwrap();

        // The new blob should exist.
        assert!(cache.get(&new_blob_id).await.unwrap().is_some());

        // The expired blobs should have been purged.
        for blob_id in &blob_ids {
            assert!(
                cache.get(blob_id).await.unwrap().is_none(),
                "expired blob should have been purged"
            );
        }

        // Only the new blob should be tracked.
        assert_eq!(cache.tracked_count().await, 1);
    }

    #[tokio::test]
    async fn evicts_multiple_when_significantly_over_limit() {
        let inner = InMemoryBlobStorage::with_capacity(100);
        let cache = LocalBlobCache::new(inner, 2);
        let routing_id = [0xAA; 32];

        // Store 5 blobs with max_cache_size=2.
        let mut blob_ids = Vec::new();
        for i in 0u8..5 {
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            blob_ids.push(blob_id);
            cache
                .store(routing_id, blob_id, None, 3600, data)
                .await
                .unwrap();
        }

        // Only the 2 newest blobs should remain.
        let count = cache.tracked_count().await;
        assert_eq!(count, 2);

        // The last 2 blobs stored should be the ones that remain.
        assert!(cache.get(&blob_ids[3]).await.unwrap().is_some());
        assert!(cache.get(&blob_ids[4]).await.unwrap().is_some());

        // The older ones should be evicted.
        for blob_id in &blob_ids[..3] {
            assert!(cache.get(blob_id).await.unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn purge_expired_delegates_and_updates_tracking() {
        let inner = InMemoryBlobStorage::with_capacity(100);
        let cache = LocalBlobCache::new(inner, 100);
        let routing_id = [0xAA; 32];

        // Store a blob with TTL=1 (expires almost immediately).
        let data = vec![1u8; 10];
        let blob_id = make_blob_id(&data);
        cache
            .store(routing_id, blob_id, None, 1, data)
            .await
            .unwrap();

        assert_eq!(cache.tracked_count().await, 1);

        // Wait for TTL to expire.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Purge expired through the cache wrapper.
        let purged = cache.purge_expired().await.unwrap();
        assert_eq!(purged, 1);

        // Tracking should be updated.
        assert_eq!(cache.tracked_count().await, 0);

        // Blob should be gone.
        assert!(cache.get(&blob_id).await.unwrap().is_none());
    }
}
