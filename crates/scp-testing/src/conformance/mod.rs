//! Conformance test macros for SCP trait implementations.
//!
//! Each conformance macro generates a suite of tests that validate an
//! implementation of a core SCP trait against the protocol specification.
//! Mirrors the pattern established for transport conformance (spec section
//! 16.12.1) and blob store conformance (spec section 17.11, 17.13).

pub mod attestation;
pub mod blob_store;
pub mod key_custody;
pub mod outlet_capability_parse;
pub mod outlet_caveats_binding;
pub mod outlet_registration;
pub mod payment;
pub mod push;
pub mod storage;
pub mod transport;
