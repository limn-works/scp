//! [`scp_sqlite_pools::open`] refuses a process whose `SQLITE_CONFIG_PAGECACHE`
//! buffer has slots that fit a 512-byte page but not a 4096-byte one (spec
//! §17.6, `SQLCipher` configuration). Such a buffer serves nothing to a
//! connection at `SQLite`'s default 4096-byte page, yet serves a database whose
//! page size is 512 bytes, so the probe must run at 512 bytes to draw a slot
//! from it. The buffer is configured before `SQLite` starts, which happens once
//! per process, so this file holds one test and runs in a process of its own;
//! the open is the first thing that runs `SQLite`, so only its own probe can
//! raise the high-water mark it refuses.

#![allow(clippy::unwrap_used, clippy::expect_used, unsafe_code)]

#[path = "support/page_cache_buffer.rs"]
mod page_cache_buffer;

use scp_sqlite_pools::PoolsError;

/// `SQLite`'s smallest page size.
const SMALLEST_PAGE: i32 = 512;

#[test]
fn open_refuses_a_buffer_whose_slots_fit_only_small_pages() {
    page_cache_buffer::install(SMALLEST_PAGE);

    let dir = tempfile::tempdir().expect("tempdir should succeed");
    let path = dir.path().join("pools.db");
    let e = scp_sqlite_pools::open(&path)
        .expect_err("open must refuse a process whose page-cache buffer can serve a 512-byte page");
    assert!(
        matches!(e, PoolsError::PageCacheBufferUsed { high_water } if high_water > 0),
        "open must refuse a page-cache buffer with a high-water mark above 0, got {e:?}"
    );
    page_cache_buffer::assert_refused_before_open("scp_sqlite_pools::open", &e.to_string(), &path);
}
