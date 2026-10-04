//! On the `SQLite` this crate links, a page that a rollback drops is freed
//! through `SQLite`'s allocator, the path `SQLCipher`'s memory security wipes,
//! instead of staying on a bulk block's private free list (spec §17.6,
//! `SQLCipher` configuration).
//!
//! The test installs a recording allocator under `SQLite` before it initializes:
//! it forwards every call to `SQLite`'s default allocator and counts each freed
//! block of at least a page that still holds a marker. `SQLCipher` wraps that
//! allocator at initialization, and its memory security is off in this
//! process, so the recorder sees each freed block as `SQLite` left it. A
//! transaction inserts rows carrying the marker into new pages, small enough
//! that every page would fit in the twenty-page bulk block `SQLite` allocates
//! by default, then rolls back. A page taken from a bulk block goes back to the
//! cache's free list when dropped, and nothing holding the marker is freed
//! before the connection closes; a page allocated on its own is freed at once.
//!
//! The bundled `SQLCipher` that libsqlite3-sys 0.30.1 compiles defines
//! `SQLITE_ENABLE_MEMORY_MANAGEMENT`, which makes every cache share one page
//! group and allocate no bulk block, and `scp_sqlite_pools::open` refuses a
//! `SQLite` without that option. This test shows the property the check
//! stands for on this build: ROLLBACK frees each marked page through
//! `sqlite3_free`.
//!
//! The file holds one test and runs in a process of its own, because the
//! allocator must be installed before anything initializes `SQLite`.

#![allow(clippy::unwrap_used, clippy::expect_used, unsafe_code)]

use std::ffi::{c_int, c_void};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::ffi;

const MARKER: &[u8; 32] = b"SCP-PAGE-CACHE-ROLLBACK-MARKER!!";
/// `cipher_page_size` below; a page buffer is this plus the cache's header.
const PAGE_SIZE: c_int = 4096;
/// Rows of `ROW_BYTES` each; about two rows share a page, so the transaction
/// adds well under twenty pages.
const ROWS: usize = 8;
const ROW_BYTES: usize = 1600;

type FreeFn = unsafe extern "C" fn(*mut c_void);
type SizeFn = unsafe extern "C" fn(*mut c_void) -> c_int;

static DEFAULT_FREE: OnceLock<FreeFn> = OnceLock::new();
static DEFAULT_SIZE: OnceLock<SizeFn> = OnceLock::new();
static MARKED_PAGE_FREES: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn recording_free(p: *mut c_void) {
    let size_fn = *DEFAULT_SIZE.get().expect("recorder installed");
    let free_fn = *DEFAULT_FREE.get().expect("recorder installed");
    if !p.is_null() {
        // SAFETY: `p` is a live block from `SQLite`'s default allocator, which
        // reports its usable size, and the block stays live until `free_fn`.
        let size = unsafe { size_fn(p) };
        if size >= PAGE_SIZE {
            // SAFETY: `p` points at `size` readable bytes, as above.
            let block = unsafe {
                std::slice::from_raw_parts(p.cast::<u8>(), usize::try_from(size).unwrap())
            };
            if block.windows(MARKER.len()).any(|w| w == MARKER) {
                MARKED_PAGE_FREES.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    // SAFETY: forwards the free of a block `SQLite`'s default allocator made.
    unsafe { free_fn(p) }
}

/// Installs the recording allocator; must run before `SQLite` initializes.
fn install_recorder() {
    // SAFETY: `sqlite3_mem_methods` is a plain C struct of nullable function
    // pointers and a data pointer, for which all-zero bytes are valid.
    let mut methods: ffi::sqlite3_mem_methods = unsafe { std::mem::zeroed() };
    // SAFETY: `SQLITE_CONFIG_GETMALLOC` takes one `sqlite3_mem_methods*` and
    // writes the current methods into it; nothing else runs `SQLite` yet.
    let code = unsafe { ffi::sqlite3_config(ffi::SQLITE_CONFIG_GETMALLOC, &raw mut methods) };
    assert_eq!(code, ffi::SQLITE_OK, "SQLite must not be initialized yet");
    DEFAULT_FREE
        .set(methods.xFree.expect("default xFree"))
        .expect("recorder installed once");
    DEFAULT_SIZE
        .set(methods.xSize.expect("default xSize"))
        .expect("recorder installed once");
    methods.xFree = Some(recording_free);
    // SAFETY: `SQLITE_CONFIG_MALLOC` takes one `sqlite3_mem_methods*` and
    // copies the struct; every method forwards to the default allocator.
    let code = unsafe { ffi::sqlite3_config(ffi::SQLITE_CONFIG_MALLOC, &raw const methods) };
    assert_eq!(code, ffi::SQLITE_OK, "SQLite must not be initialized yet");
}

#[test]
fn rolled_back_pages_are_freed_through_sqlite_free() {
    install_recorder();

    let dir = tempfile::tempdir().expect("tempdir should succeed");
    let conn = scp_sqlite_pools::open(&dir.path().join("pools.db")).expect("open should succeed");
    conn.execute_batch(
        "PRAGMA key = \"x'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'\";\n\
         PRAGMA cipher_page_size = 4096;\n\
         CREATE TABLE t (b BLOB NOT NULL);",
    )
    .expect("key statement and schema should run");
    let memory_security: String = conn
        .query_row("PRAGMA cipher_memory_security", [], |row| row.get(0))
        .expect("SQLCipher should report cipher_memory_security");
    assert_eq!(
        memory_security, "0",
        "the recorder must see freed blocks unwiped"
    );

    let row: Vec<u8> = MARKER.iter().copied().cycle().take(ROW_BYTES).collect();
    conn.execute_batch("BEGIN").expect("BEGIN should run");
    for _ in 0..ROWS {
        conn.execute("INSERT INTO t (b) VALUES (?1)", [&row])
            .expect("insert should run");
    }
    let before_rollback = MARKED_PAGE_FREES.load(Ordering::SeqCst);
    conn.execute_batch("ROLLBACK").expect("ROLLBACK should run");
    let freed_by_rollback = MARKED_PAGE_FREES.load(Ordering::SeqCst) - before_rollback;

    assert!(
        freed_by_rollback > 0,
        "ROLLBACK must free the pages holding the marker through SQLite's allocator; \
         none reached it, so the page cache kept them on its bulk free list"
    );
    drop(conn);
}
