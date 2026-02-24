//! Core protocol implementation for SCP (Shareable Context Protocol).
//!
//! `scp-core` contains the cryptographic and protocol logic that all SCP
//! clients share:
//!
//! - [`crypto::mls`] — MLS (Messaging Layer Security) group encryption wrapper.
//!   Every SCP context maps to one MLS group. Provides create, add member,
//!   remove member, and destroy operations. See ADR-001.
//!
//! # Architecture
//!
//! `scp-core` depends on `scp-platform` for platform abstraction traits
//! (key custody, storage). It does not depend on any transport layer — the
//! core is purely about identity, crypto, and protocol logic.
//!
//! See `.docs/architecture.md` for the full crate layout and build phases.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod envelope;
pub mod identity;

// Re-export the MLS module's primary types at the crate level for convenience.
pub use crypto::mls;
