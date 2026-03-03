//! SQLite storage conformance tests.
//!
//! Validates that `SqliteStorage` passes all 13 conformance tests defined
//! in `storage_conformance!()` (spec sections 17.6, 17.11, 17.13).

#![cfg(feature = "sqlite")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use scp_platform::sqlite::SqliteStorage;

fn make_sqlite_storage() -> SqliteStorage {
    let dir = tempfile::tempdir().expect("tempdir should succeed");
    // Use a fixed 32-byte test key.
    let key = [0xABu8; 32];
    // Keep the tempdir so it lives for the duration of the test. The OS
    // reclaims on process exit.
    let dir_path = dir.keep();
    SqliteStorage::new(&dir_path, &key).expect("SqliteStorage::new should succeed")
}

scp_testing::storage_conformance!(make_sqlite_storage());
