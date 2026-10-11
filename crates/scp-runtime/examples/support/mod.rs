//! Shared mock providers for scp-runtime examples.
//!
//! After ADR-049 commit 12c.9e, crypto is the concrete
//! [`NodeMlsFactory`]. Examples construct one per local DID; the
//! old `MockCrypto` trait-impl scaffold was deleted along with the
//! trait. The `MockTransport` / `MockEventLog` trait-based stubs
//! remain because the transport and event-log traits are still
//! dyn-dispatched.

#![allow(dead_code)]

use scp_did::DID;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::{ContextError, ContextParams};
use scp_runtime::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use scp_runtime::context::supervisor::DurableProviders;
use scp_runtime::crypto::mls::provider::NodeMlsFactory;

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

/// Convenience constructor: real `NodeMlsFactory` bound to a DID.
pub fn example_crypto(did: &str) -> std::sync::Arc<NodeMlsFactory> {
    std::sync::Arc::new(NodeMlsFactory::new(
        did.to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ))
}

/// The supervisor's storage-derived providers, all over ONE explicitly
/// selected in-memory `Storage` backend: the saga journal and the `OpenMLS`
/// view (bound into one [`DurableProviders`]) and the context persistence.
///
/// `InMemoryStorage` is a durability-only backend (spec §17.17
/// `SCP-CAPSEL-8010`): it loses state when the process exits but stores every
/// write while it runs. Examples select it explicitly; production selects a
/// durable `Storage` (`SQLCipher`).
pub fn example_storage_providers() -> (
    DurableProviders,
    Box<dyn scp_runtime::context::persistence::ContextPersistence>,
) {
    let storage = std::sync::Arc::new(scp_platform::in_memory::InMemoryStorage::new());
    let durable = DurableProviders::from_handle(std::sync::Arc::clone(&storage));
    let persistence =
        scp_runtime::store::context::ProtocolRepositoryContextBridge::new(std::sync::Arc::new(
            scp_runtime::store::ProtocolRepository::new_for_testing(storage),
        ));
    (durable, Box::new(persistence))
}

/// Mock transport provider — reports connected, all sends succeed silently.
pub struct MockTransport;

#[async_trait::async_trait]
impl ContextTransportProvider for MockTransport {
    fn is_connected(&self) -> bool {
        true
    }
    async fn publish_context(
        &self,
        _id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn delete_published(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn send_message(
        &self,
        _id: &[u8; 32],
        _encrypted_payload: &[u8],
    ) -> Result<(), ContextError> {
        Ok(())
    }
}

/// Mock event log provider — all operations succeed with no persistence.
pub struct MockEventLog;

#[async_trait::async_trait]
impl ContextEventLogProvider for MockEventLog {
    async fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn append_event(
        &self,
        _id: &[u8; 32],
        _event_type: scp_event_log::EventType,
        _actor_did: &str,
        _payload: scp_event_log::EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
}
