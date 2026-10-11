//! On the `SQLite` this crate links, a page that a rollback drops is freed
//! through `SQLite`'s allocator, the path `SQLCipher`'s memory security wipes,
//! instead of staying on a bulk block's private free list (spec §17.6,
//! `SQLCipher` configuration).
//!
//! The test installs the recording allocator of `support/freed_blocks.rs`
//! under `SQLite` before it initializes, counting each freed block of at least
//! a page that still holds a marker. `SQLCipher`'s memory security is off in
//! this process, so the recorder sees each freed block as `SQLite` left it. A
//! transaction inserts rows carrying the marker into new pages, small enough
//! that every page would fit in the twenty-page bulk block `SQLite` allocates
//! by default, then rolls back. A page taken from a bulk block goes back to the
//! cache's free list when dropped, and nothing holding the marker is freed
//! before the connection closes; a page allocated on its own is freed at once.
//!
//! The bundled `SQLCipher` that libsqlite3-sys 0.30.1 compiles defines
//! `SQLITE_ENABLE_MEMORY_MANAGEMENT`, which makes every cache share one page
//! group and allocate no bulk block, and `scp_sqlite_pools::open` refuses a
//! `SQLite` without that option. This test checks that property on its own:
//! it opens with `rusqlite::Connection::open`, bypassing the crate's check, so
//! a build without the option fails here at the assertion. A test that
//! opened through the crate would stop at the crate's refusal instead.
//!
//! The file holds one test and runs in a process of its own, because the
//! allocator must be installed before anything initializes `SQLite`.

#![allow(clippy::unwrap_used, clippy::expect_used, unsafe_code)]

mod support {
    pub mod freed_blocks;
}

use std::ffi::c_int;

use support::freed_blocks;

const MARKER: &[u8; 32] = b"SCP-PAGE-CACHE-ROLLBACK-MARKER!!";
/// `cipher_page_size` below; a page buffer is this plus the cache's header.
const PAGE_SIZE: c_int = 4096;
/// Rows of `ROW_BYTES` each; about two rows share a page, so the transaction
/// adds well under twenty pages.
const ROWS: usize = 8;
const ROW_BYTES: usize = 1600;

#[test]
fn rolled_back_pages_are_freed_through_sqlite_free() {
    freed_blocks::install(MARKER.to_vec(), PAGE_SIZE);

    let dir = tempfile::tempdir().expect("tempdir should succeed");
    let conn =
        rusqlite::Connection::open(dir.path().join("pools.db")).expect("open should succeed");
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
    freed_blocks::take_matching_frees();
    conn.execute_batch("ROLLBACK").expect("ROLLBACK should run");
    let freed_by_rollback = freed_blocks::take_matching_frees();

    assert!(
        freed_by_rollback > 0,
        "ROLLBACK must free the pages holding the marker through SQLite's allocator; \
         none reached it, so the page cache kept them on its bulk free list"
    );
    drop(conn);
}
