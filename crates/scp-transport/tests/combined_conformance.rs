//! Conformance tests for `CombinedNodeStorage`.
//!
//! Applies both [`storage_conformance`] and [`blob_store_conformance`] macros
//! to validate the combined client+relay storage against spec sections 17.6
//! and 17.7.
//!
//! See SCP-PERSIST-063.
#![cfg(feature = "combined")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use scp_transport::native::combined::{ClockFn, CombinedNodeStorage};

fn make_combined_storage() -> CombinedNodeStorage {
    let dir = tempfile::tempdir().expect("tempdir should succeed");
    let key = [0xABu8; 32];
    let dir_path = dir.path().to_path_buf();
    // Leak the TempDir so it outlives the test — the directory must remain
    // on disk while the SQLite connection is open.
    let _ = Box::leak(Box::new(dir));
    CombinedNodeStorage::new(&dir_path, &key).expect("CombinedNodeStorage::new should succeed")
}

fn make_combined_blob_store() -> (CombinedNodeStorage, Arc<AtomicU64>) {
    let dir = tempfile::tempdir().expect("tempdir should succeed");
    let key = [0xABu8; 32];
    let dir_path = dir.path().to_path_buf();
    let _ = Box::leak(Box::new(dir));

    let clock = Arc::new(AtomicU64::new(1_000_000));
    let clock_fn: ClockFn = {
        let c = clock.clone();
        Arc::new(move || Ok(c.load(Ordering::Relaxed)))
    };
    let store = CombinedNodeStorage::with_clock(&dir_path, &key, clock_fn)
        .expect("CombinedNodeStorage::with_clock should succeed");
    (store, clock)
}

// 13 storage conformance tests (spec section 17.11).
scp_testing::storage_conformance!(make_combined_storage());

// 11 blob store conformance tests (spec section 17.7).
scp_testing::blob_store_conformance!(make_combined_blob_store());
