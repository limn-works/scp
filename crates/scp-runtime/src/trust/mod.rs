//! Trust engine module for SCP (Four-Layer Evaluation) — async runtime.
//!
//! Pure types are in `scp-protocol::trust`. This module retains the
//! `ProtocolRepositoryTrustBridge` re-export and functions that depend on
//! scp-identity types (`DidDocument`).

pub mod caveat_counter_store;
pub mod participation_service;

// Async submodule re-exports remain here. Pure types are in scp-protocol.
pub use crate::store::caveat_counters::CaveatCounters;
pub use crate::store::trust::ProtocolRepositoryTrustBridge;
pub use caveat_counter_store::{
    CaveatCounterStore, CounterError, CounterExhausted, prune_expired_window_entries,
};

// Re-export the pure CaveatKind enum (defined in scp-protocol) so callers can
// reach it via the runtime trust module without importing scp-protocol.
pub use scp_protocol::trust::CaveatKind;
