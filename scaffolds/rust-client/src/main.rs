//! Minimal SCP client in Rust.
//!
//! This scaffold demonstrates the core SCP workflow:
//! 1. Create a DID identity
//! 2. Create an encrypted context
//! 3. Send a message
//!
//! Uses mock providers for crypto, transport, and event log.
//! Replace these with production implementations for real usage:
//! - `scp-core::crypto::mls::provider` for MLS encryption
//! - `scp-transport` for relay transport
//! - `scp-event-log` for Merkle event log

use std::sync::Arc;

use scp_core::context::builder::{
    ContextCryptoProvider, ContextEventLogProvider, ContextTransportProvider,
};
use scp_core::context::governance::KeyResolver;
use scp_core::context::manager::ContextManager;
use scp_core::context::{
    Capability, ContextCreationError, ContextError, ContextMode, ContextParams,
};
use scp_identity::dht::DidDht;
use scp_identity::dht_client::InMemoryDhtClient;
use scp_identity::cache::DidCache;
use scp_identity::{DidMethod, DID};
use scp_platform::testing::InMemoryKeyCustody;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── 1. Create a DID identity ──────────────────────────────────
    let custody = Arc::new(InMemoryKeyCustody::new());
    let dht_client = Arc::new(InMemoryDhtClient::new());
    let cache = Arc::new(DidCache::new());
    let sign_fn = DidDht::<InMemoryDhtClient>::make_sign_fn(Arc::clone(&custody));
    let did_dht = DidDht::with_client_and_signer(dht_client, cache, sign_fn);

    let (identity, document) = did_dht.create(&*custody).await?;
    did_dht.publish(&identity, &document).await?;
    println!("Created identity: {}", identity.did);

    // ── 2. Build a ContextManager ─────────────────────────────────
    let key_resolver: KeyResolver = Arc::new(|_did| None);
    let manager = ContextManager::new(
        Box::new(MockCrypto),
        Box::new(MockTransport),
        Box::new(MockEventLog),
        key_resolver,
    );

    let did = DID(identity.did.clone());
    manager.register_local_did(did.clone()).await;

    // ── 3. Create an encrypted context ────────────────────────────
    let params = ContextParams {
        mode: ContextMode::Encrypted,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::RoleAssign,
            Capability::MemberInvite,
            Capability::MemberRemove,
        ],
        ..ContextParams::default()
    };

    let handle = manager
        .create_context("my-context".to_owned(), params, did.clone())
        .await?;
    println!("Created context: {}", handle.context_id());

    // ── 4. Send a message ─────────────────────────────────────────
    manager
        .send_message(&handle, &did, b"Hello, SCP!", None)
        .await?;
    println!("Message sent.");

    // ── 5. Drain events ───────────────────────────────────────────
    let events = manager.drain_events("my-context").await;
    println!("Events: {}", events.len());
    for event in &events {
        println!("  - {event:?}");
    }

    Ok(())
}

// ── Mock providers (replace with production implementations) ──────

struct MockCrypto;
impl ContextCryptoProvider for MockCrypto {
    fn validate_creator_identity(&self) -> Result<(), ContextCreationError> { Ok(()) }
    fn create_mls_group(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> { Ok(()) }
    fn generate_sender_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> { Ok(()) }
    fn init_broadcast_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> { Ok(()) }
    fn destroy_mls_group(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> { Ok(()) }
    fn destroy_sender_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> { Ok(()) }
    fn validate_key_package(&self, _owner_did: &str, _key_package_bytes: Option<&[u8]>) -> Result<(), ContextError> { Ok(()) }
    fn encrypt_message(&self, _id: &[u8; 32], _sender_did: &str, payload: &[u8], _epoch: u64, _sequence: u64) -> Result<Vec<u8>, ContextError> { Ok(payload.to_vec()) }
    fn add_member(&self, _id: &[u8; 32], _member_did: &str, _key_package_bytes: Option<&[u8]>) -> Result<(), ContextError> { Ok(()) }
    fn remove_member(&self, _id: &[u8; 32], _member_did: &str) -> Result<(), ContextError> { Ok(()) }
    fn distribute_sender_key(&self, _id: &[u8; 32], _member_did: &str) -> Result<(), ContextError> { Ok(()) }
    fn remove_member_sender_key(&self, _id: &[u8; 32], _member_did: &str) -> Result<(), ContextError> { Ok(()) }
}

struct MockTransport;
impl ContextTransportProvider for MockTransport {
    fn is_connected(&self) -> bool { true }
    fn publish_context(&self, _id: &[u8; 32], _params: &ContextParams) -> Result<(), ContextCreationError> { Ok(()) }
    fn delete_published(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> { Ok(()) }
    fn send_message(&self, _id: &[u8; 32], _encrypted_payload: &[u8]) -> Result<(), ContextError> { Ok(()) }
}

struct MockEventLog;
impl ContextEventLogProvider for MockEventLog {
    fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> { Ok(()) }
    fn append_event(&self, _id: &[u8; 32], _event: &str) -> Result<(), ContextCreationError> { Ok(()) }
    fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> { Ok(()) }
}
