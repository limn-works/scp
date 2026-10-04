//! [`scp_sqlite_pools::open`] refuses, before it opens the file, a process
//! whose `SQLite` serves pages from a `SQLITE_CONFIG_PAGECACHE` buffer (spec
//! §17.6, `SQLCipher` configuration). The buffer is configured before `SQLite`
//! starts, which happens once per process, so this file holds one test and
//! runs in a process of its own; the open is the first thing that runs
//! `SQLite`, so only its own probe can raise the high-water mark it refuses.

#![allow(clippy::unwrap_used, clippy::expect_used, unsafe_code)]

#[path = "support/page_cache_buffer.rs"]
mod page_cache_buffer;

use scp_sqlite_pools::PoolsError;

#[test]
fn open_refuses_a_configured_buffer_before_opening() {
    page_cache_buffer::install();

    let dir = tempfile::tempdir().expect("tempdir should succeed");
    let path = dir.path().join("pools.db");
    let e = scp_sqlite_pools::open(&path).expect_err(
        "open must refuse a process whose SQLite serves pages from a page-cache buffer",
    );
    assert!(
        matches!(e, PoolsError::PageCacheBufferUsed { high_water } if high_water > 0),
        "open must refuse a page-cache buffer with a high-water mark above 0, got {e:?}"
    );
    page_cache_buffer::assert_refused_before_open("scp_sqlite_pools::open", &e.to_string(), &path);
}
