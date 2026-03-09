//! Production provider implementations for [`ContextManager`].
//!
//! These providers wrap the real SCP crypto, event log, and persistence
//! subsystems, allowing [`ContextManager`] to operate outside of tests.
//!
//! - [`MlsCryptoProvider`] — Wraps `crypto::mls::group` and `crypto::sender_keys`
//!   for real MLS group operations, sender key management, and encryption.
//! - [`MerkleEventLogProvider`] — In-memory Merkle-chained event log with
//!   append-only semantics.
//! - [`ProtocolStorePersistence`] — Wraps [`ProtocolStore`](crate::store::ProtocolStore)
//!   for context state persistence across process restarts.
//!
//! The transport provider ([`RelayTransportProvider`]) lives in `scp-transport`
//! because it wraps [`NativeRelayAdapter`].
//!
//! [`ContextManager`]: super::manager::ContextManager
//! [`NativeRelayAdapter`]: scp_transport::native::adapter::NativeRelayAdapter

pub mod crypto;
pub mod event_log;
pub mod persistence;

pub use crypto::MlsCryptoProvider;
pub use event_log::MerkleEventLogProvider;
pub use persistence::{InMemoryPersistence, ProtocolStorePersistence};
