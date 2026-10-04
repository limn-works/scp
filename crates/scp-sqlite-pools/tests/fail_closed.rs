//! When `SQLite` was initialized before the crate's page-cache configuration
//! call, the call records `SQLITE_MISUSE` and every open fails with
//! `PoolsError::PageCacheBulkOn` (spec §17.6, `SQLCipher` configuration).
//!
//! Every test in this file first opens a connection without the crate, which
//! initializes `SQLite` with the bulk block on; the file runs in a process of
//! its own, so no other test sees that state.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use scp_sqlite_pools::{PoolsError, open, open_in_memory};

fn initialize_sqlite_without_the_crate() -> rusqlite::Connection {
    rusqlite::Connection::open_in_memory().expect("a plain connection should open")
}

fn assert_page_cache_refusal(result: Result<rusqlite::Connection, PoolsError>) {
    let refusal = result.err();
    assert!(
        matches!(
            refusal,
            Some(PoolsError::PageCacheBulkOn {
                code: rusqlite::ffi::SQLITE_MISUSE
            })
        ),
        "open must fail with PageCacheBulkOn {{ code: SQLITE_MISUSE }} when SQLite was \
         initialized before the page-cache call, got {refusal:?}"
    );
}

#[test]
fn open_in_memory_fails_after_sqlite_initialized_first() {
    let _plain = initialize_sqlite_without_the_crate();
    assert_page_cache_refusal(open_in_memory());
}

#[test]
fn open_fails_after_sqlite_initialized_first() {
    let _plain = initialize_sqlite_without_the_crate();
    let dir = tempfile::tempdir().expect("tempdir should succeed");
    assert_page_cache_refusal(open(&dir.path().join("pools.db")));
}
