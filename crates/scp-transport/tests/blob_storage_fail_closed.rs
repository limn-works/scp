//! Relay blob storage fails closed when its backing store cannot be opened
//! (spec `.docs/specs/17-persistence-and-storage.md` §17.17.1 SCP-CAPSEL-8001,
//! §17.7).
//!
//! SCP-CAPSEL-8001 requires the construction boundary to return a terminal
//! error the caller observes when a selected production backend cannot be
//! satisfied. Relay blob storage selects among `SqliteBlobStore`,
//! `RedbBlobStore`, `PostgresBlobStore` and `S3BlobStore` (§17.7); the two
//! file-backed arms are the ones a test can make genuinely unavailable without
//! a network service, so they carry the assertion here.
//!
//! Each test constructs the real production arm — `BlobStorageBackend::sqlite`
//! and `BlobStorageBackend::redb`, the two selection-boundary constructors that
//! `scp_transport::startup::storage_from_env` calls — against a path the
//! operating system refuses, and asserts the named
//! [`StorageError::Internal`](scp_transport::native::storage::StorageError)
//! variant. A backend that answered `Ok` on an unopenable store would hand the
//! relay a store that silently drops every blob, which is the silent-fallback
//! §17.17.1 forbids.

#![cfg(all(feature = "sqlite-blob", feature = "redb-blob"))]
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
#[test]
fn sqlite_blob_open_at_unusable_path_fails_closed_with_internal() {
    let (_tmp, path) = path_under_a_regular_file("blobs.db");

    let result = BlobStorageBackend::sqlite(&path);

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
#[test]
fn sqlite_blob_open_on_corrupt_file_fails_closed_with_internal() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let path = tmp.path().join("corrupt.db");
    std::fs::write(&path, vec![0x5Au8; 8192]).expect("write non-database bytes");

    let result = BlobStorageBackend::sqlite(&path);

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
#[test]
fn redb_blob_open_at_unusable_path_fails_closed_with_internal() {
    let (_tmp, path) = path_under_a_regular_file("blobs.redb");

    let result = BlobStorageBackend::redb(&path);

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
#[test]
fn redb_blob_open_on_corrupt_file_fails_closed_with_internal() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let path = tmp.path().join("corrupt.redb");
    std::fs::write(&path, vec![0x5Au8; 8192]).expect("write non-database bytes");

    let result = BlobStorageBackend::redb(&path);

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
