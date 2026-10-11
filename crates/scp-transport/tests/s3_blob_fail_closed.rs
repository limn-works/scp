//! The S3 relay blob backend fails closed when its object store is
//! unreachable (spec `.docs/specs/17-persistence-and-storage.md` §17.17.1
//! SCP-CAPSEL-8001, §17.7).
//!
//! `S3BlobStore` is one of the relay blob-storage arms
//! `scp_transport::startup::storage_from_env` selects among, and the `s3-blob`
//! feature that compiles it ships in `scp-relay` and `scp-node` under their
//! `cloud-blobs` feature. The file-backed arms carry their assertion in
//! `blob_storage_fail_closed.rs`; this file carries the S3 arm's.
//!
//! Both public constructors go through one private path that issues a
//! `ListObjectsV2` probe, so this test reaches the probe `S3BlobStore::open`
//! reaches. Without that probe the constructor returned `Ok` for every input,
//! because loading the SDK configuration and building a client perform no I/O,
//! and the relay learned of an unreachable store on its first `store` call.
//!
//! The `[[test]]` entry in `Cargo.toml` requires `s3-blob`, so a build without
//! it skips this target instead of compiling it empty.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use scp_transport::native::s3_blob::S3BlobStore;
use scp_transport::native::storage::{ClockFn, StorageError};

/// Binds a loopback listener that accepts every connection and closes it at
/// once, and returns its URL. The listener stays bound for the test's
/// lifetime, so no other process can take the port, and a request to it fails
/// on a closed connection instead of waiting on a network timeout.
async fn endpoint_that_closes_every_connection() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback listener");
    let addr = listener.local_addr().expect("read the listener address");
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            drop(socket);
        }
    });
    format!("http://{addr}")
}

/// Opening the S3 blob backend against an endpoint that answers no request
/// returns `StorageError::Internal` naming the failed bucket probe. An
/// operator who sets `SCP_RELAY_STORAGE_BACKEND=s3` against a store the
/// process cannot use learns that at construction, because SCP-CAPSEL-8001
/// makes an unsatisfiable production selection a terminal error the caller
/// observes. Whether the probe fails on the closed connection or earlier, on a
/// credential chain that resolves nothing, both mean the selected backend
/// cannot be satisfied.
#[tokio::test]
async fn s3_blob_open_against_unusable_endpoint_fails_closed_with_internal() {
    let endpoint = endpoint_that_closes_every_connection().await;
    let clock: ClockFn = Arc::new(|| 1_000_000);

    // The SDK retries a failed request on its default schedule. Ninety seconds
    // bounds the test if a later SDK widens that schedule; the assertion is on
    // the returned variant, never on the elapsed time.
    let result = tokio::time::timeout(
        Duration::from_secs(90),
        S3BlobStore::open_with_endpoint("scp-relay-blobs", "blobs/", &endpoint, clock),
    )
    .await
    .expect("the S3 constructor must answer rather than hang");

    match result {
        Err(StorageError::Internal(message)) => {
            assert!(
                message.contains("S3 list probe failed for scp-relay-blobs"),
                "the error must name the bucket probe that failed: {message}"
            );
        }
        Err(other) => panic!("expected StorageError::Internal, got {other:?}"),
        Ok(_) => panic!(
            "opening the S3 blob backend against an endpoint that answers no request must \
             fail closed with StorageError::Internal; returning a store here hands the relay a \
             backend that drops every blob at run time (spec §17.17.1 SCP-CAPSEL-8001)"
        ),
    }
}
