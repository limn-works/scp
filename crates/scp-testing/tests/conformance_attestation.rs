//! Device-attestation conformance tests.
//!
//! Expands `attestation_conformance!()` — 2 tests for
//! `scp_platform::DeviceAttestation` — against `InMemoryDeviceAttestation`,
//! sole Rust implementation of that trait in this workspace.
//!
//! Spec §16.15.1 of `.docs/specs/16-test-infrastructure.md` requires these
//! generated tests to run under `cargo nextest run --workspace`, and ADR-006
//! (`.docs/adrs/phase-1.md`, platform abstraction) requires every adapter
//! implementation to satisfy one contract. Before this file existed, that
//! macro had zero expansion sites, so neither requirement held.
//!
//! `invalid_token_rejected`, one of two generated cases, is what catches an
//! attestation verifier that answers `true` for every input.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use scp_platform::testing::InMemoryDeviceAttestation;

scp_testing::attestation_conformance!(InMemoryDeviceAttestation::new());
