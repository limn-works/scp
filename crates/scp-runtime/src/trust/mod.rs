//! Trust engine module for SCP (Four-Layer Evaluation) — async runtime.
//!
//! Pure types are in `scp-protocol::trust`. This module retains the
//! `ProtocolRepositoryTrustBridge` re-export and functions that depend on
//! scp-identity types (`DidDocument`).

pub mod caveat_counters;
pub mod participation_service;

// Async submodule re-exports remain here. Pure types are in scp-protocol.
pub use crate::store::trust::ProtocolRepositoryTrustBridge;

/// Owned Class-S §7.3.8 caveat-counter primitives (value-caveat runtime
/// enforcement). See [`caveat_counters`].
pub use caveat_counters::{CaveatCounters, CounterExhausted, prune_expired_window_entries};
