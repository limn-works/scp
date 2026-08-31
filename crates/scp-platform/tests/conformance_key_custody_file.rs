//! File-backed key-custody conformance tests.
//!
//! Expands `key_custody_conformance!()` — 4 tests for
//! `scp_platform::KeyCustody` — against `FileKeyCustody`. ADR-006
//! (`.docs/adrs/phase-1.md`, platform abstraction) requires every adapter, not
//! only its in-memory reference, to satisfy one contract; spec §16.15.1 of
//! `.docs/specs/16-test-infrastructure.md` requires these generated tests to
//! run under `cargo nextest run --workspace`. Before this file existed, that
//! macro had zero expansion sites, so neither requirement held.
//!
//! This expansion lives in scp-platform rather than scp-testing because
//! `FileKeyCustody` sits behind scp-platform's `file` feature, which
//! scp-testing does not enable.

#![cfg(feature = "file")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use scp_platform::file::FileKeyCustody;

/// Builds a custody instance over a temporary key file.
///
/// Each call gets its own directory, so all four generated tests share no key
/// material. `Box::leak` keeps that directory alive for this process, matching
/// `crates/scp-platform/tests/conformance_sqlite.rs`, because
/// `key_custody_conformance!` binds its factory expression inside each test
/// body and keeps no guard of its own.
fn make_file_key_custody() -> FileKeyCustody {
    let dir = tempfile::tempdir().expect("tempdir should succeed");
    let path = dir.path().join("keys.scp");
    let _ = Box::leak(Box::new(dir));
    FileKeyCustody::new(&path, "conformance-passphrase")
        .expect("FileKeyCustody::new should succeed")
}

scp_testing::key_custody_conformance!(make_file_key_custody());
