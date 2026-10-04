//! Every `SQLCipher` connection in this crate runs with `SQLite`'s lookaside
//! pool off, so each block the connection frees passes through `SQLCipher`'s
//! allocator, which `PRAGMA cipher_memory_security` makes wipe it (spec §17.6,
//! and §9.15 of the security-model spec, freed heap memory).
//!
//! The pool size is a property of the linked library, which every connection
//! in this process shares. The probe test measures the pool directly on a
//! connection that runs the production key statement and binds a value; each
//! constructor test proves the constructor's own connection passed its
//! fail-closed `PRAGMA compile_options` check.
//!
//! The probe calls `sqlite3_db_status` through the C API, which needs
//! `unsafe`; the library crate itself forbids unsafe code.

#![cfg(any(feature = "sqlite", feature = "apple"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rusqlite::ffi;

/// The high-water mark of the `sqlite3_db_status` counter `op` on `conn` since
/// it opened.
fn status_high_water(conn: &rusqlite::Connection, op: i32) -> i32 {
    let mut current = 0_i32;
    let mut high_water = 0_i32;
    // SAFETY: `conn.handle()` is the live `sqlite3*` that `conn` owns and keeps
    // open for this call; `sqlite3_db_status` only writes the two `int`
    // out-pointers, which point at locals that outlive the call.
    let rc = unsafe {
        ffi::sqlite3_db_status(conn.handle(), op, &raw mut current, &raw mut high_water, 0)
    };
    assert_eq!(rc, ffi::SQLITE_OK, "sqlite3_db_status({op}) should succeed");
    high_water
}

/// The high-water marks of `SQLITE_DBSTATUS_LOOKASIDE_USED` (slots checked out
/// at once) and `SQLITE_DBSTATUS_LOOKASIDE_HIT` (allocations the pool served)
/// on `conn` since it opened.
fn lookaside_high_water(conn: &rusqlite::Connection) -> (i32, i32) {
    (
        status_high_water(conn, ffi::SQLITE_DBSTATUS_LOOKASIDE_USED),
        status_high_water(conn, ffi::SQLITE_DBSTATUS_LOOKASIDE_HIT),
    )
}

#[test]
fn probe_connection_after_key_statement_has_no_lookaside_pool() {
    let probe = rusqlite::Connection::open_in_memory().expect("probe connection should open");
    probe
        .execute_batch(
            "PRAGMA cipher_memory_security = ON;\n\
             PRAGMA key = \"x'abababababababababababababababababababababababababababababababab'\";\n\
             PRAGMA cipher_page_size = 4096;\n\
             CREATE TABLE kv (key TEXT PRIMARY KEY, value BLOB NOT NULL);",
        )
        .expect("key statement should run");
    probe
        .execute(
            "INSERT INTO kv (key, value) VALUES (?1, ?2)",
            rusqlite::params!["secret", [0xCD_u8; 32].as_slice()],
        )
        .expect("insert should run");

    assert_eq!(
        lookaside_high_water(&probe),
        (0, 0),
        "the lookaside pool must be zero-size: no slot used and no allocation served"
    );
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_storage_opens_only_with_lookaside_off() {
    let dir = tempfile::tempdir().expect("tempdir should succeed");
    scp_platform::sqlite::SqliteStorage::new(dir.path(), &[0xAB; 32])
        .expect("SqliteStorage::new should pass its lookaside check");
}

#[cfg(feature = "apple")]
#[test]
fn apple_storage_opens_only_with_lookaside_off() {
    let dir = tempfile::tempdir().expect("tempdir should succeed");
    scp_platform::apple::AppleStorage::open(dir.path(), &[0xAB; 32])
        .expect("AppleStorage::open should pass its lookaside check");
}
