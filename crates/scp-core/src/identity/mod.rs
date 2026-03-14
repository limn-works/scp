//! Identity types and utilities for SCP.
//!
//! For DID resolution and key management, import directly from
//! [`scp_identity`] instead of `scp_core::identity`. This module provides
//! protocol-level identity types used across `scp-core`.
//!
//! See ADR-003 in `.docs/adrs/phase-1.md` for the full identity design
//! and ADR-039 for the shared-DID human-agent identity model.

pub mod attestation;
pub mod block_list;
pub mod blocking;
pub mod custody_migration;
pub mod private_state;
pub mod private_state_events;
pub mod recovery;
pub mod scpid;

// Re-export SigningKeyId from scp-identity — the single canonical definition.
// All scp-core consumers should use this re-export via `crate::identity::SigningKeyId`.
pub use scp_identity::SigningKeyId;

pub use scpid::{ScpIdAuthentication, ScpIdChallenge, ScpIdError, ScpIdResponse, scpid_challenge};
