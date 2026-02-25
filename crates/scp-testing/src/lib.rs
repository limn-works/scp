//! Integration test crate for SCP (Shareable Context Protocol).
//!
//! This crate contains cross-crate integration tests that exercise multiple
//! SCP components together. The primary test is the Phase 1 integration test
//! (`tests/integration/phase1.rs`) which proves all 7 Phase 1 ADRs work in
//! concert.
//!
//! See `.docs/adrs/phase-1.md` for the Phase 1 architecture and test design.

#![forbid(unsafe_code)]
