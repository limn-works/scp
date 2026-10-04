//! `SqliteStorage::new` turns on `SQLCipher`'s memory security, which makes
//! `SQLCipher` wipe every block it frees (spec §17.6, and §9.15 of the
//! security-model spec, freed heap memory).
//!
//! `SQLCipher` keeps the setting process-wide and never turns it off once on, so
//! this file holds exactly one test and runs in a process of its own: a probe
//! connection reads the setting as off, the production constructor runs, and
//! the probe reads it as on.

#![cfg(feature = "sqlite")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use scp_platform::sqlite::SqliteStorage;

/// `SQLCipher`'s process-wide memory-security setting as `PRAGMA
/// cipher_memory_security` reports it on a fresh probe connection: `"1"` once
/// a connection has turned it on and `SQLCipher`'s allocator has run.
fn memory_security() -> String {
    let probe = rusqlite::Connection::open_in_memory().expect("probe connection should open");
    probe
        .query_row("PRAGMA cipher_memory_security", [], |row| row.get(0))
        .expect("SQLCipher should report cipher_memory_security")
}

#[test]
fn sqlite_storage_turns_on_sqlcipher_memory_security() {
    assert_eq!(
        memory_security(),
        "0",
        "nothing has turned memory security on yet"
    );

    let dir = tempfile::tempdir().expect("tempdir should succeed");
    let storage =
        SqliteStorage::new(dir.path(), &[0xAB; 32]).expect("SqliteStorage::new should succeed");

    assert_eq!(
        memory_security(),
        "1",
        "SqliteStorage::new must set PRAGMA cipher_memory_security = ON"
    );
    drop(storage);
}
