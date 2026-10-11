//! The `PostgreSQL` relay blob backend fails closed when its database is
//! unreachable (spec `.docs/specs/17-persistence-and-storage.md` §17.17.1
//! SCP-CAPSEL-8001, §17.7).
//!
//! `PostgresBlobStore` is one of the relay blob-storage arms
//! `scp_transport::startup::storage_from_env` selects among, compiled into
//! `scp-relay` and `scp-node` under their `cloud-blobs` feature. Its open
//! establishes a pooled connection and applies the schema before it returns, so
//! a database the process cannot reach is a terminal error at construction
//! rather than at the relay's first `store`.
//!
//! The `[[test]]` entry in `Cargo.toml` requires `postgres-blob`, so a build
//! without it skips this target instead of compiling it empty.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use scp_transport::native::postgres_blob::PostgresBlobStore;
use scp_transport::native::storage::StorageError;

/// Binds a loopback listener that accepts every connection and closes it at
/// once, and returns its address. The listener stays bound for the test's
/// lifetime, so no other process can take the port, and a connection to it
/// fails on a closed socket instead of waiting on a network timeout.
async fn address_that_closes_every_connection() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback listener");
    let addr = listener.local_addr().expect("read the listener address");
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            drop(socket);
        }
    });
    addr
}

/// Opening the `PostgreSQL` blob backend against a server that closes every
/// connection returns `StorageError::Internal` naming the failed connect. An
/// operator who sets `SCP_RELAY_STORAGE_BACKEND=postgres` against a database
/// the process cannot use learns that at construction (SCP-CAPSEL-8001).
#[tokio::test]
async fn postgres_blob_open_against_unusable_server_fails_closed_with_internal() {
    let addr = address_that_closes_every_connection().await;
    let url = format!("postgres://scp:scp@{addr}/scp_relay");

    // The pool retries a failed connect until its acquire timeout. Ninety
    // seconds bounds the test above that schedule; the assertion is on the
    // returned variant, never on the elapsed time.
    let result = tokio::time::timeout(Duration::from_secs(90), PostgresBlobStore::open(&url))
        .await
        .expect("the PostgreSQL constructor must answer rather than hang");

    match result {
        Err(StorageError::Internal(message)) => {
            assert!(
                message.contains("postgres connect"),
                "the error must name the connect that failed: {message}"
            );
        }
        Err(other) => panic!("expected StorageError::Internal, got {other:?}"),
        Ok(_) => panic!(
            "opening the PostgreSQL blob backend against a server that closes every connection \
             must fail closed with StorageError::Internal (spec §17.17.1 SCP-CAPSEL-8001)"
        ),
    }
}
