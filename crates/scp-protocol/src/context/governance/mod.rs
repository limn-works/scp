//! Governance interface contract for SCP contexts (ADR-031) — pure protocol types.
//!
//! GovernanceAction, GovernanceEngine trait, compute_proposal_id.
//! The `timeout` module (async timeout logic) stays in scp-runtime.

pub mod majority;
pub mod mls_integration;
pub mod multisig;
pub mod unanimity;
