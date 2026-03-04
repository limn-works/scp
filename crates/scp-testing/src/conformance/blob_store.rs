//! Blob store conformance test macro.
//!
//! The [`blob_store_conformance`] macro generates 11 test cases that validate
//! any [`BlobStorage`](scp_transport::native::storage::BlobStorage)
//! implementation against the spec (section 17.11, 17.13):
//!
//! 1. `roundtrip` — store/get roundtrip preserves all fields
//! 2. `missing_returns_none` — get for nonexistent `blob_id` returns None
//! 3. `ttl_expiry` — expired blob not returned by get
//! 4. `query_routing_order` — query by `routing_id` returns results in `stored_at` order
//! 5. `query_since` — query with since filter excludes older blobs
//! 6. `query_limit` — query respects limit parameter
//! 7. `delete` — delete removes blob, returns true; second delete returns false
//! 8. `store_returns_blob_id` — returned `StoredBlob.blob_id` matches SHA-256 of content
//! 9. `concurrent_store_purge` — concurrent store + `purge_expired` is safe
//! 10. `purge_expired_only` — `purge_expired` removes only expired blobs
//! 11. `query_empty_returns_empty` — query for unknown `routing_id` returns empty Vec
//!
//! See spec section 17.11 "Custom `BlobStore` Adapters" and 17.13 "Conformance Testing".

/// Generates 11 conformance tests for a [`BlobStorage`] implementation.
///
/// # Arguments
///
/// The macro takes a single expression that evaluates to a tuple of
/// `(impl BlobStorage, Arc<AtomicU64>)`. The first element is the storage
/// backend to test. The second element is a controllable clock backed by an
/// `AtomicU64` — the storage implementation must use this clock for all
/// timestamp operations so that TTL and purge tests are deterministic.
///
/// The expression is called once per test to create a fresh storage instance.
///
/// # Example
///
/// ```ignore
/// use scp_testing::blob_store_conformance;
/// use std::sync::Arc;
/// use std::sync::atomic::AtomicU64;
///
/// blob_store_conformance!({
///     let clock = Arc::new(AtomicU64::new(1_000_000));
///     let clock_fn = {
///         let c = clock.clone();
///         Arc::new(move || c.load(std::sync::atomic::Ordering::Relaxed))
///     };
///     let store = InMemoryBlobStorage::with_clock(clock_fn);
///     (store, clock)
/// });
/// ```
///
/// See spec section 17.11.
#[macro_export]
macro_rules! blob_store_conformance {
    ($factory:expr) => {
        #[allow(
            clippy::unwrap_used,
            clippy::expect_used,
            clippy::panic,
            unused_imports
        )]
        mod blob_store_conformance {
            use super::*;

            use std::sync::Arc;
            use std::sync::atomic::{AtomicU64, Ordering};

            use scp_transport::native::storage::BlobStorage;
            use sha2::{Digest, Sha256};

            /// Compute SHA-256 `blob_id` from content bytes.
            fn sha256_blob_id(data: &[u8]) -> [u8; 32] {
                let hash = Sha256::digest(data);
                let mut out = [0u8; 32];
                out.copy_from_slice(&hash);
                out
            }

            #[tokio::test]
            async fn roundtrip() {
                let (store, clock) = $factory;
                let _ = &clock; // ensure clock is available even if unused
                let routing_id = [0xAA; 32];
                let blob_data = vec![1, 2, 3, 4, 5];
                let blob_id = sha256_blob_id(&blob_data);
                let hint = [0xBB; 32];

                let stored = store
                    .store(routing_id, blob_id, Some(hint), 3600, blob_data.clone())
                    .await
                    .expect("store should succeed");

                assert_eq!(stored.blob_id, blob_id, "blob_id mismatch");
                assert_eq!(stored.routing_id, routing_id, "routing_id mismatch");
                assert_eq!(stored.blob, blob_data, "blob content mismatch");
                assert_eq!(stored.blob_ttl, 3600, "blob_ttl mismatch");
                assert_eq!(stored.recipient_hint, Some(hint), "recipient_hint mismatch");
                assert!(stored.stored_at > 0, "stored_at should be positive");

                let retrieved = store
                    .get(&blob_id)
                    .await
                    .expect("get should succeed")
                    .expect("blob should exist");

                assert_eq!(retrieved.blob, blob_data, "retrieved blob content mismatch");
                assert_eq!(retrieved.blob_id, blob_id, "retrieved blob_id mismatch");
                assert_eq!(
                    retrieved.routing_id, routing_id,
                    "retrieved routing_id mismatch"
                );
                assert_eq!(
                    retrieved.recipient_hint,
                    Some(hint),
                    "retrieved recipient_hint mismatch"
                );
                assert_eq!(retrieved.blob_ttl, 3600, "retrieved blob_ttl mismatch");
                assert_eq!(
                    retrieved.stored_at, stored.stored_at,
                    "stored_at should match"
                );
            }

            #[tokio::test]
            async fn missing_returns_none() {
                let (store, _clock) = $factory;
                let blob_id = [0xFF; 32];
                let result = store.get(&blob_id).await.expect("get should succeed");
                assert!(result.is_none(), "missing blob should return None");
            }

            #[tokio::test]
            async fn ttl_expiry() {
                let (store, clock) = $factory;
                let routing_id = [0xAA; 32];
                let blob_data = vec![10, 20, 30];
                let blob_id = sha256_blob_id(&blob_data);

                // Store with TTL of 60 seconds.
                store
                    .store(routing_id, blob_id, None, 60, blob_data)
                    .await
                    .expect("store should succeed");

                // Blob should be retrievable before TTL expires.
                let before = store.get(&blob_id).await.expect("get should succeed");
                assert!(before.is_some(), "blob should exist before TTL expiry");

                // Advance clock past TTL expiry.
                let current = clock.load(Ordering::Relaxed);
                clock.store(current + 61, Ordering::Relaxed);

                // Blob should no longer be returned after TTL expires.
                let after = store.get(&blob_id).await.expect("get should succeed");
                assert!(after.is_none(), "expired blob should return None");
            }

            #[tokio::test]
            async fn query_routing_order() {
                let (store, clock) = $factory;
                let routing_id = [0xCC; 32];

                // Store 3 blobs at different timestamps.
                for i in 0u8..3 {
                    let data = vec![i; 10];
                    let blob_id = sha256_blob_id(&data);
                    store
                        .store(routing_id, blob_id, None, 3600, data)
                        .await
                        .expect("store should succeed");

                    // Advance clock by 1 second between stores to ensure
                    // distinct timestamps.
                    let current = clock.load(Ordering::Relaxed);
                    clock.store(current + 1, Ordering::Relaxed);
                }

                let results = store
                    .query(&routing_id, None, 100)
                    .await
                    .expect("query should succeed");

                assert_eq!(results.len(), 3, "should return 3 blobs");

                // Results must be sorted by stored_at ascending.
                for window in results.windows(2) {
                    assert!(
                        window[0].stored_at <= window[1].stored_at,
                        "results must be ordered by stored_at ascending: {} > {}",
                        window[0].stored_at,
                        window[1].stored_at
                    );
                }
            }

            #[tokio::test]
            async fn query_since() {
                let (store, clock) = $factory;
                let routing_id = [0xDD; 32];

                // Store 3 blobs with 1-second gaps.
                let mut timestamps = Vec::new();
                for i in 0u8..3 {
                    let data = vec![i + 100; 10];
                    let blob_id = sha256_blob_id(&data);
                    let stored = store
                        .store(routing_id, blob_id, None, 3600, data)
                        .await
                        .expect("store should succeed");
                    timestamps.push(stored.stored_at);

                    let current = clock.load(Ordering::Relaxed);
                    clock.store(current + 1, Ordering::Relaxed);
                }

                // Query with since = first blob's stored_at. Should exclude
                // the first blob (since filter is exclusive: stored_at > since).
                let results = store
                    .query(&routing_id, Some(timestamps[0]), 100)
                    .await
                    .expect("query should succeed");

                assert_eq!(results.len(), 2, "since filter should exclude first blob");
                for result in &results {
                    assert!(
                        result.stored_at > timestamps[0],
                        "all results should be after the since timestamp"
                    );
                }
            }

            #[tokio::test]
            async fn query_limit() {
                let (store, clock) = $factory;
                let routing_id = [0xEE; 32];

                // Store 5 blobs.
                for i in 0u8..5 {
                    let data = vec![i + 200; 10];
                    let blob_id = sha256_blob_id(&data);
                    store
                        .store(routing_id, blob_id, None, 3600, data)
                        .await
                        .expect("store should succeed");

                    let current = clock.load(Ordering::Relaxed);
                    clock.store(current + 1, Ordering::Relaxed);
                }

                let results = store
                    .query(&routing_id, None, 2)
                    .await
                    .expect("query should succeed");

                assert_eq!(results.len(), 2, "limit should cap results at 2");
            }

            #[tokio::test]
            async fn delete() {
                let (store, _clock) = $factory;
                let routing_id = [0xAA; 32];
                let blob_data = vec![50, 60, 70];
                let blob_id = sha256_blob_id(&blob_data);

                store
                    .store(routing_id, blob_id, None, 3600, blob_data)
                    .await
                    .expect("store should succeed");

                // First delete should return true.
                let deleted = store.delete(&blob_id).await.expect("delete should succeed");
                assert!(deleted, "delete of existing blob should return true");

                // Blob should no longer exist.
                let result = store.get(&blob_id).await.expect("get should succeed");
                assert!(result.is_none(), "deleted blob should return None");

                // Second delete should return false.
                let deleted_again = store.delete(&blob_id).await.expect("delete should succeed");
                assert!(
                    !deleted_again,
                    "delete of already-deleted blob should return false"
                );

                // Query should also not return the deleted blob.
                let query_results = store
                    .query(&routing_id, None, 100)
                    .await
                    .expect("query should succeed");
                assert!(
                    query_results.is_empty(),
                    "query after delete should return empty"
                );
            }

            #[tokio::test]
            async fn store_returns_blob_id() {
                let (store, _clock) = $factory;
                let routing_id = [0xAA; 32];
                let blob_data = vec![11, 22, 33, 44, 55];
                let expected_id = sha256_blob_id(&blob_data);

                let stored = store
                    .store(routing_id, expected_id, None, 3600, blob_data)
                    .await
                    .expect("store should succeed");

                assert_eq!(
                    stored.blob_id, expected_id,
                    "store should return the correct SHA-256 blob_id"
                );
            }

            #[tokio::test]
            async fn concurrent_store_purge() {
                let (store, clock) = $factory;
                let routing_id = [0xAA; 32];

                // Store some blobs with short TTL.
                for i in 0u8..5 {
                    let data = vec![i; 10];
                    let blob_id = sha256_blob_id(&data);
                    store
                        .store(routing_id, blob_id, None, 10, data)
                        .await
                        .expect("store should succeed");
                }

                // Advance clock past TTL.
                let current = clock.load(Ordering::Relaxed);
                clock.store(current + 11, Ordering::Relaxed);

                // Run purge and store concurrently — both must succeed without
                // panics or data corruption.
                let store_clone = store.clone();
                let purge_handle = tokio::spawn(async move { store_clone.purge_expired().await });

                // Store new blobs while purge runs.
                for i in 10u8..15 {
                    let data = vec![i; 10];
                    let blob_id = sha256_blob_id(&data);
                    store
                        .store(routing_id, blob_id, None, 3600, data)
                        .await
                        .expect("concurrent store should succeed");
                }

                let purge_result = purge_handle.await.expect("purge task should not panic");
                assert!(
                    purge_result.is_ok(),
                    "purge_expired should succeed during concurrent stores"
                );

                // Verify that the newly stored blobs (stored after clock
                // advance, with long TTL) are still retrievable — purge must
                // not have corrupted them.
                for i in 10u8..15 {
                    let data = vec![i; 10];
                    let blob_id = sha256_blob_id(&data);
                    let result = store
                        .get(&blob_id)
                        .await
                        .expect("get should succeed after concurrent purge");
                    assert!(
                        result.is_some(),
                        "newly stored blob {i} should survive concurrent purge"
                    );
                    assert_eq!(
                        result.unwrap().blob,
                        data,
                        "blob {i} content should be intact after concurrent purge"
                    );
                }
            }

            #[tokio::test]
            async fn purge_expired_only() {
                let (store, clock) = $factory;
                let routing_id = [0xAA; 32];

                // Store a short-lived blob (TTL 10s).
                let short_data = vec![1, 2, 3];
                let short_id = sha256_blob_id(&short_data);
                store
                    .store(routing_id, short_id, None, 10, short_data)
                    .await
                    .expect("store should succeed");

                // Store a long-lived blob (TTL 3600s).
                let long_data = vec![4, 5, 6];
                let long_id = sha256_blob_id(&long_data);
                store
                    .store(routing_id, long_id, None, 3600, long_data.clone())
                    .await
                    .expect("store should succeed");

                // Advance clock past short TTL but not long TTL.
                let current = clock.load(Ordering::Relaxed);
                clock.store(current + 11, Ordering::Relaxed);

                let purged = store.purge_expired().await.expect("purge should succeed");
                assert_eq!(purged, 1, "only the short-lived blob should be purged");

                // Short-lived blob should be gone.
                let short_result = store.get(&short_id).await.expect("get should succeed");
                assert!(short_result.is_none(), "short-lived blob should be purged");

                // Long-lived blob should still exist.
                let long_result = store
                    .get(&long_id)
                    .await
                    .expect("get should succeed")
                    .expect("long-lived blob should still exist");
                assert_eq!(long_result.blob, long_data);
            }

            #[tokio::test]
            async fn query_empty_returns_empty() {
                let (store, _clock) = $factory;
                let unknown_routing_id = [0xFF; 32];

                let results = store
                    .query(&unknown_routing_id, None, 100)
                    .await
                    .expect("query should succeed");

                assert!(
                    results.is_empty(),
                    "query for unknown routing_id should return empty Vec"
                );
            }
        }
    };
}

/// Helper functions used by the conformance test macro.
///
/// These are public so the macro-generated tests can reference them, but
/// they are implementation details of the conformance suite.
pub mod test_helpers {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use scp_transport::native::storage::ClockFn;

    /// Default starting timestamp for conformance test clocks.
    ///
    /// Set to a reasonable value (well past Unix epoch) to avoid edge cases
    /// with timestamp 0.
    pub const DEFAULT_START_TIME: u64 = 1_000_000;

    /// Creates a controllable clock for conformance testing.
    ///
    /// Returns `(ClockFn, Arc<AtomicU64>)` — the clock function to pass to the
    /// storage constructor and the underlying atomic value for manual time
    /// control.
    #[must_use]
    pub fn make_test_clock() -> (ClockFn, Arc<AtomicU64>) {
        let value = Arc::new(AtomicU64::new(DEFAULT_START_TIME));
        let v = value.clone();
        let clock: ClockFn = Arc::new(move || v.load(Ordering::Relaxed));
        (clock, value)
    }
}
