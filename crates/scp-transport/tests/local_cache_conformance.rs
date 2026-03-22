//! Conformance tests for `LocalBlobCache`.
//!
//! Applies [`blob_store_conformance`] macro to validate the size-limited
//! cache wrapper against spec section 17.7.
//!
//! See SCP-PERSIST-065.
#![cfg(feature = "local-cache")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use scp_transport::native::local_cache::LocalBlobCache;
use scp_transport::native::storage::{ClockFn, InMemoryBlobStorage, StorageError};

fn make_local_cache() -> (LocalBlobCache<InMemoryBlobStorage>, Arc<AtomicU64>) {
    let clock = Arc::new(AtomicU64::new(1_000_000));

    // InMemoryBlobStorage clock: returns u64 (no Result).
    let inner_clock: ClockFn = {
        let c = clock.clone();
        Arc::new(move || c.load(Ordering::Relaxed))
    };
    let inner = InMemoryBlobStorage::with_clock(inner_clock);

    // LocalBlobCache clock: returns u64 directly.
    let cache_clock: Arc<dyn Fn() -> u64 + Send + Sync> = {
        let c = clock.clone();
        Arc::new(move || c.load(Ordering::Relaxed))
    };
    let cache = LocalBlobCache::with_clock(inner, 1000, cache_clock);

    (cache, clock)
}

// 11 blob store conformance tests (spec section 17.7).
scp_testing::blob_store_conformance!(make_local_cache());
