//! Push-adapter conformance tests.
//!
//! Expands `push_conformance!()` — 2 tests for `scp_platform::Push` — against
//! `InMemoryPush`, sole Rust implementation of that trait in this workspace.
//!
//! Spec §16.15.1 of `.docs/specs/16-test-infrastructure.md` requires these
//! generated tests to run under `cargo nextest run --workspace`, and ADR-006
//! (`.docs/adrs/phase-1.md`, platform abstraction) requires every adapter
//! implementation to satisfy one contract. Before this file existed, that
//! macro had zero expansion sites, so neither requirement held.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use scp_platform::in_memory::InMemoryPush;

scp_testing::push_conformance!(InMemoryPush::new());
