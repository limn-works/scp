//! Shared mock providers for scp-runtime examples.
//!
//! After ADR-049 commit 12c.9e, crypto is the concrete
//! [`MlsCryptoProvider`]. Examples construct one per local DID; the
//! old `MockCrypto` trait-impl scaffold was deleted along with the
//! trait. The `MockTransport` / `MockEventLog` trait-based stubs
//! remain because the transport and event-log traits are still
//! dyn-dispatched.

#![allow(dead_code)]

use scp_did::DID;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::{ContextError, ContextParams};
use scp_runtime::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use scp_runtime::crypto::mls::provider::MlsCryptoProvider;

/// Derives a deterministic signing key from a DID string for example use.
pub fn signing_key_for(did: &DID) -> ed25519_dalek::SigningKey {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    did.as_ref().hash(&mut hasher);
    let h = hasher.finish();
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&h.to_le_bytes());
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

/// Convenience constructor: real `MlsCryptoProvider` bound to a DID.
pub fn example_crypto(did: &str) -> std::sync::Arc<MlsCryptoProvider> {
    std::sync::Arc::new(MlsCryptoProvider::new(
        did.to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ))
}

/// Convenience constructor: an in-memory `OpenMLS` storage adapter for the
/// required `mls_storage` provider. Examples are dev affordances, so the
/// in-memory backend (a bridge-layer dev opt-in) is the correct choice —
/// production wires a real `Storage` (`SQLCipher`).
pub fn example_mls_storage()
-> std::sync::Arc<dyn scp_runtime::crypto::mls::storage_adapter::OpenMlsStorageAdapter> {
    std::sync::Arc::new(
        scp_runtime::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(
            std::sync::Arc::new(scp_platform::testing::InMemoryStorage::new()),
        ),
    )
}

/// Mock transport provider — reports connected, all sends succeed silently.
pub struct MockTransport;

impl ContextTransportProvider for MockTransport {
    fn is_connected(&self) -> bool {
        true
    }
    fn publish_context(
        &self,
        _id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn delete_published(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn send_message(&self, _id: &[u8; 32], _encrypted_payload: &[u8]) -> Result<(), ContextError> {
        Ok(())
    }
}

/// Mock event log provider — all operations succeed with no persistence.
pub struct MockEventLog;

impl ContextEventLogProvider for MockEventLog {
    fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn append_event(
        &self,
        _id: &[u8; 32],
        _event_type: scp_event_log::EventType,
        _actor_did: &str,
        _payload: scp_event_log::EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
}
