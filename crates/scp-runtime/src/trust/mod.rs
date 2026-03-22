//! Trust engine module for SCP (Four-Layer Evaluation) — async runtime.
//!
//! Pure types are in scp-protocol::trust. This module retains the
//! ProtocolRepositoryTrustBridge re-export.

// Async submodule re-exports remain here. Pure types are in scp-protocol.
pub use crate::store::trust::ProtocolRepositoryTrustBridge;
