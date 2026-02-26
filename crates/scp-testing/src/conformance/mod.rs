//! Conformance test macros for SCP trait implementations.
//!
//! Each conformance macro generates a suite of tests that validate an
//! implementation of a core SCP trait against the protocol specification.
//! Mirrors the pattern established for transport conformance (spec section
//! 16.12.1) and blob store conformance (spec section 16.12.6).

pub mod payment;
