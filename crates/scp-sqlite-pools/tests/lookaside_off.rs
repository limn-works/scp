//! A connection from `open` or `open_in_memory` serves nothing from `SQLite`'s
//! lookaside pool, even after the key statement and an insert with bound
//! values, the statements whose text and values a lookaside slot would keep
//! (spec §17.6, `SQLCipher` configuration).
//!
//! Every connection in this file opens through the crate, so `SQLite`
//! initializes after the page-cache configuration call.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use rusqlite::Connection;
use scp_sqlite_pools::{LookasideUse, lookaside_use, open, open_in_memory};

const NO_LOOKASIDE: LookasideUse = LookasideUse {
    slots_high_water: 0,
    hits: 0,
};

fn key_and_insert(conn: &Connection) {
    conn.execute_batch(
        "PRAGMA key = \"x'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'\";\n\
         CREATE TABLE kv (key TEXT PRIMARY KEY, value BLOB NOT NULL);",
    )
    .expect("key statement and schema should run");
    conn.execute(
        "INSERT INTO kv (key, value) VALUES (?1, ?2)",
        rusqlite::params!["a-key", vec![0x5A_u8; 64]],
    )
    .expect("insert should run");
}

#[test]
fn file_connection_serves_nothing_from_lookaside() {
    let dir = tempfile::tempdir().expect("tempdir should succeed");
    let conn = open(&dir.path().join("pools.db")).expect("open should succeed");
    key_and_insert(&conn);
    assert_eq!(
        lookaside_use(&conn).expect("status should read"),
        NO_LOOKASIDE
    );
}

#[test]
fn in_memory_connection_serves_nothing_from_lookaside() {
    let conn = open_in_memory().expect("open_in_memory should succeed");
    key_and_insert(&conn);
    assert_eq!(
        lookaside_use(&conn).expect("status should read"),
        NO_LOOKASIDE
    );
}
