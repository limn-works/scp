//! Identity types and utilities for SCP — pure protocol types.
//!
//! Pure module re-exports. Async modules (blocking, recovery,
//! `custody_migration`, scpid) stay in scp-runtime.

pub mod attestation;
pub mod block_list;
pub mod private_state;
pub mod private_state_events;

// Re-export identity primitives from scp-primitives for convenience.
pub use scp_primitives::{SigningKeyId, extract_public_key_from_did};
