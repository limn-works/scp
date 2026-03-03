//! Conformance tests for `RedbBlobStore`.
//!
//! Applies the [`blob_store_conformance`] macro to validate the redb-backed
//! blob storage against spec section 17.7.
#![cfg(feature = "redb-blob")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use scp_transport::native::redb_blob::RedbBlobStore;
use scp_transport::native::storage::ClockFn;

fn make_redb_blob_store() -> (RedbBlobStore, Arc<AtomicU64>) {
    let clock = Arc::new(AtomicU64::new(1_000_000));
    let clock_fn: ClockFn = {
        let c = clock.clone();
        Arc::new(move || c.load(Ordering::Relaxed))
    };
    let store = RedbBlobStore::temporary_with_clock(clock_fn).expect("redb should open");
    (store, clock)
}

// Run all 11 blob store conformance tests.
scp_testing::blob_store_conformance!(make_redb_blob_store());
