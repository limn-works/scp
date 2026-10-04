//! Hands `SQLite` a page-cache buffer with `SQLITE_CONFIG_PAGECACHE` before it
//! starts, shared by the test binaries that check each constructor refuses
//! such a process (spec §17.6, `SQLCipher` configuration). `scp-platform` and
//! `scp-transport` include this file by path.
//!
//! `SQLite` serves pages from the buffer's slots and returns a freed slot to
//! its own free list without calling `sqlite3_free`, so `SQLCipher`'s memory
//! security never wipes it. Each including test binary installs the buffer
//! once, before anything starts `SQLite`, calls the constructor under test
//! first, and runs one test. Nothing reads a page before that constructor, so
//! only the constructor's own probe can raise the high-water mark it refuses.

use std::ffi::{c_int, c_void};
use std::path::Path;

use rusqlite::ffi;

/// Slots in the buffer: enough for the first statements of a constructor.
const SLOTS: c_int = 16;
/// The largest `SQLite` page size; a slot holds a page and its header.
const LARGEST_PAGE: c_int = 65_536;
/// The text `PoolsError::PageCacheBufferUsed` puts before its high-water mark.
const REFUSAL: &str = "SQLITE_CONFIG_PAGECACHE buffer has held pages in this process \
                       (high-water mark ";

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

/// The high-water mark in a storage error that carries the text of
/// `PoolsError::PageCacheBufferUsed`, or `None` when `message` is another
/// error. The constructors map `PoolsError` into storage errors that keep
/// only its text, so the tests read the value from there.
pub fn refused_high_water(message: &str) -> Option<i64> {
    let (_, rest) = message.split_once(REFUSAL)?;
    let (value, _) = rest.split_once(')')?;
    value.parse().ok()
}

/// Asserts that a constructor's error `message` is the page-cache buffer
/// refusal with a high-water mark above 0, and that `database` does not exist,
/// so the refusal came before the constructor opened its connection. Then,
/// as a control after the refusal, asserts that `scp_sqlite_pools` itself
/// refuses an in-memory open with the same structured error.
pub fn assert_refused_before_open(constructor: &str, message: &str, database: &Path) {
    let refused = refused_high_water(message);
    assert!(
        matches!(refused, Some(h) if h > 0),
        "{constructor} must refuse with the page-cache buffer error and a high-water mark above \
         0, got {message}"
    );
    let high_water = refused.unwrap_or_default();
    assert!(
        !database.exists(),
        "{constructor} must refuse before it opens {}",
        database.display()
    );
    let control = scp_sqlite_pools::open_in_memory();
    assert!(
        matches!(
            control,
            Err(scp_sqlite_pools::PoolsError::PageCacheBufferUsed { high_water: h }) if h >= high_water
        ),
        "scp_sqlite_pools::open_in_memory must refuse the same buffer, got {control:?}"
    );
}
