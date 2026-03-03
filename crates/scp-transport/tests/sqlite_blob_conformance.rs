//! Conformance tests for `SqliteBlobStore`.
//!
//! Applies the [`blob_store_conformance`] macro to validate the SQLite-backed
//! blob storage against spec section 17.7.
#![cfg(feature = "sqlite-blob")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use scp_transport::native::sqlite_blob::SqliteBlobStore;
use scp_transport::native::storage::ClockFn;

fn make_sqlite_blob_store() -> (SqliteBlobStore, Arc<AtomicU64>) {
    let clock = Arc::new(AtomicU64::new(1_000_000));
    let clock_fn: ClockFn = {
        let c = clock.clone();
        Arc::new(move || c.load(Ordering::Relaxed))
    };
    let store = SqliteBlobStore::in_memory_with_clock(clock_fn).expect("sqlite should open");
    (store, clock)
}

// Run all 11 blob store conformance tests.
scp_testing::blob_store_conformance!(make_sqlite_blob_store());
