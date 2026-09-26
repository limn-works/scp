//! `SQLCipher`-backed key-custody conformance tests.
//!
//! Expands `key_custody_conformance!()` — 4 tests for
//! `scp_platform::KeyCustody` — against `SqliteKeyCustody`. ADR-006
//! (`.docs/adrs/phase-1.md`, platform abstraction) requires every adapter, not
//! only its in-memory reference, to satisfy one contract; spec §16.15.1 of
//! `.docs/specs/16-test-infrastructure.md` requires these generated tests to
//! run under `cargo nextest run --workspace`. Before this file existed, that
//! macro had zero expansion sites, so neither requirement held.
//!
//! This expansion lives in scp-platform rather than scp-testing because
//! `SqliteKeyCustody` sits behind scp-platform's `sqlite` feature, which
//! scp-testing enables only through its own optional `sqlite` feature.

#![cfg(feature = "sqlite")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use scp_platform::sqlite::{SqliteKeyCustody, SqliteStorage};

/// Builds a custody instance over a temporary `SQLCipher` database.
///
/// Each call gets its own directory, so all four generated tests share no key
/// material. `Box::leak` keeps that directory alive while its connection is
/// open, matching `crates/scp-platform/tests/conformance_sqlite.rs`.
async fn make_sqlite_key_custody() -> SqliteKeyCustody {
    let dir = tempfile::tempdir().expect("tempdir should succeed");
    let dir_path = dir.path().to_path_buf();
    let _ = Box::leak(Box::new(dir));
    let key = [0xCDu8; 32];
    let storage = SqliteStorage::new(&dir_path, &key).expect("SqliteStorage::new should succeed");
    SqliteKeyCustody::new(storage)
        .await
        .expect("SqliteKeyCustody::new should succeed")
}

scp_testing::key_custody_conformance!(make_sqlite_key_custody().await);
