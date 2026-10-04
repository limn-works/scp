//! A `SQLCipher` constructor in this crate refuses to open storage when it
//! cannot prove `SQLite`'s page-cache bulk block off, here because `SQLite` was
//! initialized before `scp_sqlite_pools` could configure it (spec §17.6,
//! `SQLCipher` configuration, and §9.15 of the security-model spec, freed heap
//! memory).
//!
//! Every test first opens a connection without `scp_sqlite_pools`, which
//! initializes `SQLite` with the bulk block on; the file runs in a process of
//! its own, so no other test sees that state.

#![cfg(any(feature = "sqlite", feature = "apple"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use scp_platform::PlatformError;

fn initialize_sqlite_without_the_pools_crate() -> rusqlite::Connection {
    rusqlite::Connection::open_in_memory().expect("a plain connection should open")
}

fn assert_page_cache_refusal<T>(result: Result<T, PlatformError>, constructor: &str) {
    let refusal = result.err();
    assert!(
        matches!(
            &refusal,
            Some(PlatformError::StorageError(message))
                if message.contains("page-cache bulk block cannot be proven off")
        ),
        "{constructor} must refuse with the page-cache error when SQLite initialized \
         first, got {refusal:?}"
    );
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_storage_fails_closed_when_sqlite_initialized_first() {
    let _plain = initialize_sqlite_without_the_pools_crate();
    let dir = tempfile::tempdir().expect("tempdir should succeed");
    assert_page_cache_refusal(
        scp_platform::sqlite::SqliteStorage::new(dir.path(), &[0xAB; 32]),
        "SqliteStorage::new",
    );
}

#[cfg(feature = "apple")]
#[test]
fn apple_storage_fails_closed_when_sqlite_initialized_first() {
    let _plain = initialize_sqlite_without_the_pools_crate();
    let dir = tempfile::tempdir().expect("tempdir should succeed");
    assert_page_cache_refusal(
        scp_platform::apple::AppleStorage::open(dir.path(), &[0xAB; 32]),
        "AppleStorage::open",
    );
}
