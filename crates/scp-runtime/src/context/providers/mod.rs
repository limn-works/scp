//! Production provider implementations for `ContextManager`.
//!
//! These providers wrap the real SCP crypto, event log, and persistence
//! subsystems, allowing `ContextManager` to operate outside of tests.
//!
//! - [`MlsCryptoProvider`] — Production `ContextCryptoProvider` backed by
//!   `OpenMLS` with HPKE sender key distribution, nonce deduplication, and
//!   per-context crypto state persistence.
//! - [`MerkleEventLogProvider`] — Merkle-chained event log with append-only
//!   semantics and optional persistence (#636).
//! - [`ProtocolRepositoryContextBridge`] — Wraps [`ProtocolRepository`](crate::store::ProtocolRepository)
//!   for context state persistence across process restarts.
//! - [`ProtocolRepositoryEventLogBridge`] — Wraps `ProtocolRepository` for event
//!   log entry persistence across process restarts (#636).
//!
//! The transport provider (`RelayTransportProvider`) lives in `scp-transport`
//! because it wraps `NativeRelayAdapter`.

pub mod event_log;
pub mod persistence;

pub use crate::crypto::mls::provider::MlsCryptoProvider;
pub use event_log::{EventLogPersistence, MerkleEventLogProvider};
pub use persistence::{InMemoryPersistence, ProtocolRepositoryContextBridge};

// Re-export the ProtocolRepository bridge for event log persistence.
pub use crate::store::context::ProtocolRepositoryEventLogBridge;
