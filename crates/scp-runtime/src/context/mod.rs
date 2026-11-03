//! The 13 domains, at the module paths they held before the split (ADR-070 §2).
//! The tree is private to the crate, which exports only `domain_handlers` and
//! `test_supervisor` (plan §3).

pub mod broadcast_helpers;
pub mod economy_helpers;
pub mod economy_logic;
pub mod governance_helpers;
pub mod governance_logic;
pub mod lifecycle_helpers;
pub mod lifecycle_logic;
pub mod messaging_helpers;
pub mod outlets_helpers;
pub mod push_helpers;
pub mod queries_helpers;
pub mod standing_helpers;
pub mod trust_recovery_helpers;
pub mod ttl_close_helpers;

pub mod actor;

// The agent-binding live-pipeline tests (the whole file is `#![cfg(test)]`).
#[cfg(test)]
mod agent_binding_pipeline_tests;

// Runtime pseudonym-rotation tests (spec 09 §9.10.4.1), also `#![cfg(test)]`.
#[cfg(test)]
mod pseudonym_rotation_runtime_tests;

// Receive-side and reset tests for a membership Commit (spec 07 §7.3.1.1,
// story PUSH-030), also `#![cfg(test)]`.
#[cfg(test)]
mod processed_commit_tests;

// A sender-key distribution whose publish fails (spec 09 §9.16.9), also
// `#![cfg(test)]`.
#[cfg(test)]
mod sender_key_requeue_tests;
