//! Conformance tests for `S3BlobStore`.
//!
//! Applies the [`blob_store_conformance`] macro to the S3 blob store
//! (persistence spec §17.11). The tests need a live S3-compatible endpoint
//! named by `S3_TEST_ENDPOINT` holding the bucket `S3_TEST_BUCKET`; each test
//! uses its own key prefix. CI's blob-backend step starts the endpoint.
#![cfg(feature = "s3-blob")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use scp_transport::native::s3_blob::S3BlobStore;
use scp_transport::native::storage::ClockFn;

async fn make_s3_blob_store() -> (S3BlobStore, Arc<AtomicU64>) {
    let endpoint = std::env::var("S3_TEST_ENDPOINT")
        .expect("S3_TEST_ENDPOINT names the S3 endpoint these tests run against");
    let bucket = std::env::var("S3_TEST_BUCKET")
        .expect("S3_TEST_BUCKET names the bucket these tests run against");
    let clock = Arc::new(AtomicU64::new(1_000_000));
    let clock_fn: ClockFn = {
        let c = clock.clone();
        Arc::new(move || c.load(Ordering::Relaxed))
    };
    let prefix = format!("conformance/{:016x}", rand::random::<u64>());
    let store = S3BlobStore::open_with_endpoint(&bucket, &prefix, &endpoint, clock_fn)
        .await
        .expect("S3 store should open");
    (store, clock)
}

scp_testing::blob_store_conformance!(make_s3_blob_store().await);
