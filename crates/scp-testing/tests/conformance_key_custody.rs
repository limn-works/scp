//! In-memory key-custody conformance tests.
//!
//! Expands `key_custody_conformance!()` — 4 tests for
//! `scp_platform::KeyCustody` — against `InMemoryKeyCustody`, which ADR-006
//! (`.docs/adrs/phase-1.md`, platform abstraction) names as its reference
//! implementation. `FileKeyCustody` and `SqliteKeyCustody` carry their own
//! expansions under `crates/scp-platform/tests/`, because scp-testing enables
//! neither `file` nor `sqlite` on scp-platform.
//!
//! Spec §16.15.1 of `.docs/specs/16-test-infrastructure.md` requires these
//! generated tests to run under `cargo nextest run --workspace`. Before this
//! file existed, that macro had zero expansion sites, so that requirement did
//! not hold.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use scp_platform::testing::InMemoryKeyCustody;

scp_testing::key_custody_conformance!(InMemoryKeyCustody::new());
