//! Hands `SQLite` a page-cache buffer with `SQLITE_CONFIG_PAGECACHE` before it
//! starts, shared by the test binaries that check each constructor refuses
//! such a process (spec §17.6, `SQLCipher` configuration). `scp-platform` and
//! `scp-transport` include this file by path.
//!
//! `SQLite` serves pages from the buffer's slots and returns a freed slot to
//! its own free list without calling `sqlite3_free`, so `SQLCipher`'s memory
//! security never wipes it. Each including test binary installs the buffer
//! once, before anything starts `SQLite`, and runs one test.

use std::ffi::{c_int, c_void};

use rusqlite::ffi;

/// Slots in the buffer: enough for the first statements of a constructor.
const SLOTS: c_int = 16;
/// The largest `SQLite` page size; a slot holds a page and its header.
const LARGEST_PAGE: c_int = 65_536;

/// Installs a leaked, 8-byte-aligned buffer of [`SLOTS`] slots, each large
/// enough for any page. Must run before `SQLite` starts.
pub fn install() {
    let mut header: c_int = 0;
    // SAFETY: `SQLITE_CONFIG_PCACHE_HDRSZ` takes one `int*` and writes the
    // bytes each page-cache slot needs beyond the page; nothing runs `SQLite`
    // yet.
    let code = unsafe { ffi::sqlite3_config(ffi::SQLITE_CONFIG_PCACHE_HDRSZ, &raw mut header) };
    assert_eq!(code, ffi::SQLITE_OK, "SQLite must not be started yet");
    let slot = (LARGEST_PAGE + header + 7) / 8 * 8;
    let words = usize::try_from(slot * SLOTS / 8).expect("buffer size fits usize");
    let buffer: &'static mut [u64] = Vec::leak(vec![0_u64; words]);
    let start: *mut c_void = buffer.as_mut_ptr().cast();
    // SAFETY: `SQLITE_CONFIG_PAGECACHE` takes a `void*` buffer, an `int` slot
    // size and an `int` slot count, and these are exactly those types. The
    // buffer is leaked, so it outlives `SQLite`, holds `slot * SLOTS` bytes,
    // and is 8-byte aligned as `SQLite` requires.
    let code = unsafe { ffi::sqlite3_config(ffi::SQLITE_CONFIG_PAGECACHE, start, slot, SLOTS) };
    assert_eq!(code, ffi::SQLITE_OK, "SQLite must not be started yet");
}

/// Positive control: a statement on a fresh connection checks a buffer slot
/// out, so the high-water mark the constructors read is above 0.
pub fn assert_buffer_serves_pages() {
    let conn = scp_sqlite_pools::open_in_memory().expect("control connection should open");
    conn.execute_batch("CREATE TABLE control (x); INSERT INTO control VALUES (1);")
        .expect("control statements should run");
    let result = scp_sqlite_pools::require_no_page_cache_buffer();
    assert!(
        matches!(
            result,
            Err(scp_sqlite_pools::PoolsError::PageCacheBufferUsed { high_water }) if high_water > 0
        ),
        "the configured buffer must have served a page, got {result:?}"
    );
}
