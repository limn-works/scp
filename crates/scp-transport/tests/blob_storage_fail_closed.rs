//! Relay blob storage fails closed when its backing store cannot be opened
//! (spec `.docs/specs/17-persistence-and-storage.md` §17.17.1 SCP-CAPSEL-8001,
//! §17.7).
//!
//! SCP-CAPSEL-8001 requires the construction boundary to return a terminal
//! error the caller observes when a selected production backend cannot be
//! satisfied. Relay blob storage selects among `SqliteBlobStore`,
//! `RedbBlobStore`, `PostgresBlobStore` and `S3BlobStore` (§17.7). This file
//! carries the two file-backed arms; `s3_blob_fail_closed.rs` carries the S3
//! arm.
//!
//! Each test constructs the real production arm — `BlobStorageBackend::sqlite`
//! and `BlobStorageBackend::redb`, the two selection-boundary constructors that
//! `scp_transport::startup::storage_from_env` calls — against a path the
//! operating system refuses, and asserts the named
//! [`StorageError::Internal`](scp_transport::native::storage::StorageError)
//! variant. A backend that answered `Ok` on an unopenable store would hand the
//! relay a store that silently drops every blob, which is the silent-fallback
//! §17.17.1 forbids.
//!
//! The `[[test]]` entry in `Cargo.toml` requires `sqlite-blob` and `redb-blob`,
//! so a build without them skips this target instead of compiling it empty.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use scp_transport::native::storage::{BlobStorageBackend, StorageError};

/// Builds a path whose parent component is a regular file, so the operating
/// system cannot create or open anything underneath it. Returns the temporary
/// directory alongside the path because dropping it deletes the tree.
fn path_under_a_regular_file(leaf: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let blocker = tmp.path().join("this-is-a-file");
    std::fs::write(&blocker, b"not a directory").expect("write the blocking regular file");
    let path = blocker.join(leaf);
    (tmp, path)
}

/// `BlobStorageBackend::sqlite` at a path the operating system refuses returns
/// `StorageError::Internal` — it never yields a usable backend. Selecting a
/// durable blob backend that cannot be opened is a terminal error the caller
/// observes (SCP-CAPSEL-8001), never a silent degrade to the in-memory arm.
#[tokio::test]
async fn sqlite_blob_open_at_unusable_path_fails_closed_with_internal() {
    let (_tmp, path) = path_under_a_regular_file("blobs.db");

    let result = BlobStorageBackend::sqlite(&path).await;

    match result {
        Err(StorageError::Internal(message)) => {
            assert!(
                !message.is_empty(),
                "the fail-closed blob-open error must carry a diagnostic message"
            );
        }
        Err(other) => panic!("expected StorageError::Internal, got {other:?}"),
        Ok(_) => panic!(
            "opening a SQLite blob store under a regular file must fail closed with \
             StorageError::Internal; returning a backend here hands the relay a store \
             that silently drops every blob (spec §17.17.1 SCP-CAPSEL-8001)"
        ),
    }
}

/// A `SQLite` blob store pointed at a file that holds non-database bytes returns
/// `StorageError::Internal`. `SQLite` opens the file handle lazily, so this
/// exercises the schema-application half of the open path: corruption is
/// detected and reported, never absorbed.
#[tokio::test]
async fn sqlite_blob_open_on_corrupt_file_fails_closed_with_internal() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let path = tmp.path().join("corrupt.db");
    std::fs::write(&path, vec![0x5Au8; 8192]).expect("write non-database bytes");

    let result = BlobStorageBackend::sqlite(&path).await;

    match result {
        Err(StorageError::Internal(message)) => {
            assert!(
                !message.is_empty(),
                "the fail-closed blob-open error must carry a diagnostic message"
            );
        }
        Err(other) => panic!("expected StorageError::Internal, got {other:?}"),
        Ok(_) => panic!(
            "opening a corrupt SQLite blob database must fail closed with \
             StorageError::Internal (spec §17.17.1 SCP-CAPSEL-8001)"
        ),
    }
}

/// `BlobStorageBackend::redb` at a path the operating system refuses returns
/// `StorageError::Internal`, the same fail-closed contract the `SQLite` arm
/// honours.
#[tokio::test]
async fn redb_blob_open_at_unusable_path_fails_closed_with_internal() {
    let (_tmp, path) = path_under_a_regular_file("blobs.redb");

    let result = BlobStorageBackend::redb(&path).await;

    match result {
        Err(StorageError::Internal(message)) => {
            assert!(
                !message.is_empty(),
                "the fail-closed blob-open error must carry a diagnostic message"
            );
        }
        Err(other) => panic!("expected StorageError::Internal, got {other:?}"),
        Ok(_) => panic!(
            "opening a redb blob store under a regular file must fail closed with \
             StorageError::Internal (spec §17.17.1 SCP-CAPSEL-8001)"
        ),
    }
}

/// A redb store pointed at a file that holds non-database bytes returns
/// `StorageError::Internal`.
#[tokio::test]
async fn redb_blob_open_on_corrupt_file_fails_closed_with_internal() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let path = tmp.path().join("corrupt.redb");
    std::fs::write(&path, vec![0x5Au8; 8192]).expect("write non-database bytes");

    let result = BlobStorageBackend::redb(&path).await;

    match result {
        Err(StorageError::Internal(message)) => {
            assert!(
                !message.is_empty(),
                "the fail-closed blob-open error must carry a diagnostic message"
            );
        }
        Err(other) => panic!("expected StorageError::Internal, got {other:?}"),
        Ok(_) => panic!(
            "opening a corrupt redb blob database must fail closed with \
             StorageError::Internal (spec §17.17.1 SCP-CAPSEL-8001)"
        ),
    }
}

/// `BlobStorageBackend::sqlite` runs the open on tokio's blocking pool, so an
/// open waiting for a lock another connection holds leaves the runtime thread
/// free.
///
/// A second connection holds an exclusive lock on the database, so the open's
/// first statement waits for `SQLite`'s busy timeout (5 s). The test runs on a
/// `current_thread` runtime, starts the open, sleeps 300 ms, and then releases
/// the lock. Run inline, the open parks the runtime's only thread in that
/// wait, so the sleep returns about 5 s late and the elapsed-time assertion
/// fails.
#[tokio::test(flavor = "current_thread")]
async fn a_sqlite_open_waiting_for_a_held_lock_leaves_the_runtime_thread_free() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let path = tmp.path().join("blobs.db");
    let holder = rusqlite::Connection::open(&path).expect("open the lock holder");
    holder
        .execute_batch("CREATE TABLE held (x INTEGER); BEGIN EXCLUSIVE;")
        .expect("take an exclusive lock");

    let opening_path = path.clone();
    let opening = tokio::spawn(async move { BlobStorageBackend::sqlite(&opening_path).await });

    let started = std::time::Instant::now();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "a 300 ms sleep took {elapsed:?}: the blob-store open held the runtime thread"
    );
    assert!(
        !opening.is_finished(),
        "the open must still be waiting for the held lock"
    );

    holder.execute_batch("COMMIT;").expect("release the lock");
    drop(holder);
    opening
        .await
        .expect("the open task completes")
        .expect("the open succeeds once the lock is released");
}
