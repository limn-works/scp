//! Testing crate for SCP (Shareable Context Protocol).
//!
//! This crate contains cross-crate integration tests and conformance test
//! macros that validate SCP trait implementations against the protocol
//! specification.
//!
//! # Conformance macros
//!
//! - [`payment_adapter_conformance!`] — 8 tests for [`PaymentAdapter`]
//!   implementations (spec section 19.2.6).
//! - [`storage_conformance!`] — 13 tests for [`Storage`](scp_platform::Storage)
//!   implementations (spec sections 17.11, 17.13).
//!
//! # Integration tests
//!
//! The primary integration test is the Phase 1 test
//! (`tests/integration/phase1.rs`) which proves all 7 Phase 1 ADRs work in
//! concert.
//!
//! See `.docs/adrs/phase-1.md` for the Phase 1 architecture and test design.

#![forbid(unsafe_code)]

mod blob_store_tests;
pub mod conformance;
pub mod test_adapter;

pub use test_adapter::TestAdapter;
