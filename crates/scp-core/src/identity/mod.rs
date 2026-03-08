//! Identity types and utilities for SCP.
//!
//! For DID resolution and key management, import directly from
//! [`scp_identity`] instead of `scp_core::identity`. This module provides
//! protocol-level identity types used across `scp-core`.
//!
//! See ADR-003 in `.docs/adrs/phase-1.md` for the full identity design
//! and ADR-039 for the shared-DID human-agent identity model.

pub mod block_list;
pub mod blocking;
pub mod recovery;

// Re-export SigningKeyId from scp-identity — the single canonical definition.
// All scp-core consumers should use this re-export via `crate::identity::SigningKeyId`.
pub use scp_identity::SigningKeyId;
