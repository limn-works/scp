//! The S3 relay blob backend fails closed when its object store is
//! unreachable (spec `.docs/specs/17-persistence-and-storage.md` §17.17.1
//! SCP-CAPSEL-8001, §17.7).
//!
//! `S3BlobStore` is one of the four relay blob-storage arms
//! `scp_transport::startup::storage_from_env` selects among, and the `s3-blob`
//! feature that compiles it ships in both `scp-relay` and `scp-node`. Its
//! sibling file-backed arms carry their assertion in
//! `blob_storage_fail_closed.rs`; this file carries the S3 arm's.
//!
//! Both public constructors funnel through one private path that issues a
//! `HeadBucket` request, so this test reaches the same probe
//! `S3BlobStore::open` reaches. Without that probe the constructor returned
//! `Ok` for every input — `aws_config::load_defaults` and `Client::new` perform
//! no I/O — and handed the relay a store whose every `store` call then failed
//! at run time, after the relay had already told its operator it was using S3
//! blob storage.

#![cfg(feature = "s3-blob")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use scp_transport::native::s3_blob::S3BlobStore;
use scp_transport::native::storage::StorageError;

/// Reserves a TCP port, then releases it, so nothing listens on the returned
/// address. A connection to it is refused rather than left hanging, which keeps
/// this test's duration bounded by the SDK's retry schedule instead of by a
/// network timeout.
fn address_nothing_listens_on() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a loopback port");
    let addr = listener.local_addr().expect("read the reserved port");
    drop(listener);
    format!("http://{addr}")
}

/// Opening the S3 blob backend against an endpoint that refuses the connection
/// returns `StorageError::Internal`. A relay operator who sets
/// `SCP_RELAY_STORAGE_BACKEND=s3` against a bucket the process cannot reach
/// must learn that at construction, because SCP-CAPSEL-8001 makes an
/// unsatisfiable production selection a terminal error the caller observes.
#[tokio::test]
async fn s3_blob_open_against_unreachable_endpoint_fails_closed_with_internal() {
    let endpoint = address_nothing_listens_on();
    let clock: scp_transport::native::storage::ClockFn = Arc::new(|| 1_000_000);

    // The AWS SDK retries a refused connection on its default schedule, which
    // took 3.2 seconds when this test was written. Forty-five seconds is far
    // above that and bounds the test if a future SDK version widens the
    // schedule; the assertion is on the returned variant, never on the elapsed
    // time.
    let result = tokio::time::timeout(
        Duration::from_secs(45),
        S3BlobStore::open_with_endpoint("scp-relay-blobs", "blobs/", &endpoint, clock),
    )
    .await
    .expect("the S3 constructor must answer rather than hang");

    match result {
        Err(StorageError::Internal(message)) => {
            assert!(
                !message.is_empty(),
                "the fail-closed S3 open error must carry a diagnostic message"
            );
        }
        Err(other) => panic!("expected StorageError::Internal, got {other:?}"),
        Ok(_) => panic!(
            "opening the S3 blob backend against an endpoint that refuses every connection must \
             fail closed with StorageError::Internal; returning a store here hands the relay a \
             backend that drops every blob at run time while the startup path reports the S3 \
             backend selected (spec §17.17.1 SCP-CAPSEL-8001)"
        ),
    }
}
