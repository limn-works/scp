//! Production provider implementations for [`ContextManager`].
//!
//! These providers wrap the real SCP crypto, event log, and persistence
//! subsystems, allowing [`ContextManager`] to operate outside of tests.
//!
//! - [`MlsCryptoProvider`] — Wraps `crypto::mls::group` and `crypto::sender_keys`
//!   for real MLS group operations, sender key management, and encryption.
//! - [`MerkleEventLogProvider`] — Merkle-chained event log with append-only
//!   semantics and optional persistence (#636).
//! - [`ProtocolRepositoryContextBridge`] — Wraps [`ProtocolRepository`](crate::store::ProtocolRepository)
//!   for context state persistence across process restarts.
//! - [`ProtocolRepositoryEventLogBridge`] — Wraps `ProtocolRepository` for event
//!   log entry persistence across process restarts (#636).
//!
//! The transport provider (`RelayTransportProvider`) lives in `scp-transport`
//! because it wraps `NativeRelayAdapter`.
//!
//! [`ContextManager`]: super::manager::ContextManager

pub mod crypto;
pub mod event_log;
pub mod persistence;

pub use crypto::MlsCryptoProvider;
pub use event_log::{EventLogEntry, EventLogPersistence, MerkleEventLogProvider};
pub use persistence::{InMemoryPersistence, ProtocolRepositoryContextBridge};

// Re-export the ProtocolRepository bridge for event log persistence.
pub use crate::store::context::ProtocolRepositoryEventLogBridge;
