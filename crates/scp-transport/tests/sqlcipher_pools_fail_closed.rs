//! A `SQLCipher` constructor in this crate refuses to open storage when it
//! cannot prove `SQLite`'s page-cache bulk block off, here because `SQLite` was
//! initialized before `scp_sqlite_pools` could configure it (spec §17.6,
//! `SQLCipher` configuration, and §9.15 of the security-model spec, freed heap
//! memory).
//!
//! Every test first opens a connection without `scp_sqlite_pools`, which
//! initializes `SQLite` with the bulk block on; the file runs in a process of
//! its own, so no other test sees that state.

#![cfg(any(feature = "combined", feature = "sqlite-blob"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use scp_transport::native::storage::StorageError;

fn initialize_sqlite_without_the_pools_crate() -> rusqlite::Connection {
    rusqlite::Connection::open_in_memory().expect("a plain connection should open")
}

fn assert_page_cache_refusal<T>(result: Result<T, StorageError>, constructor: &str) {
    let refusal = result.err();
    assert!(
        matches!(
            &refusal,
            Some(StorageError::Internal(message))
                if message.contains("page-cache bulk block cannot be proven off")
        ),
        "{constructor} must refuse with the page-cache error when SQLite initialized \
         first, got {refusal:?}"
    );
}

#[cfg(feature = "combined")]
#[test]
fn combined_storage_fails_closed_when_sqlite_initialized_first() {
    use scp_transport::native::combined::CombinedNodeStorage;
    let _plain = initialize_sqlite_without_the_pools_crate();
    let dir = tempfile::tempdir().expect("tempdir should succeed");
    assert_page_cache_refusal(
        CombinedNodeStorage::open(dir.path(), &[0xAB; 32]),
        "CombinedNodeStorage::open",
    );
    assert_page_cache_refusal(
        CombinedNodeStorage::open_with_clock(
            dir.path(),
            &[0xAB; 32],
            scp_transport::native::combined::system_clock(),
        ),
        "CombinedNodeStorage::open_with_clock",
    );
}

#[cfg(feature = "sqlite-blob")]
#[test]
fn sqlite_blob_store_fails_closed_when_sqlite_initialized_first() {
    use scp_transport::native::sqlite_blob::SqliteBlobStore;
    let _plain = initialize_sqlite_without_the_pools_crate();
    let dir = tempfile::tempdir().expect("tempdir should succeed");
    assert_page_cache_refusal(
        SqliteBlobStore::open(&dir.path().join("blobs.db")),
        "SqliteBlobStore::open",
    );
    assert_page_cache_refusal(SqliteBlobStore::in_memory(), "SqliteBlobStore::in_memory");
}
