//! Minimal SCP client in Rust.
//!
//! This scaffold demonstrates the core SCP workflow on the current
//! actor-per-context runtime (ADR-049):
//! 1. Create a DID identity
//! 2. Build a [`Supervisor`] with providers
//! 3. Create an encrypted context
//! 4. Send a message
//! 5. Drain the resulting events
//!
//! Crypto is the real [`NodeMlsFactory`] (MLS) over an in-memory OpenMLS
//! storage adapter; transport and event-log use mock providers. Replace these
//! with production implementations for real usage:
//! - a real `scp_transport::RelayTransportProvider` for relay transport
//! - `MerkleEventLogProvider::with_persistence(...)` for the Merkle event log
//! - a durable `scp_platform::Storage` (SQLCipher) behind the MLS storage adapter
//!
//! Run:
//!   `cargo run`

use std::sync::Arc;

use scp_clock::SystemClock;
use scp_core::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use scp_core::context::governance::KeyResolver;
use scp_core::context::supervisor::{MessageSigner, Supervisor};
use scp_core::context::{
    Capability, ContextCreationError, ContextError, ContextMode, ContextParams,
};
use scp_core::crypto::mls::NodeMlsFactory;
use scp_core::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter;
use scp_dht::InMemoryDhtClient;
use scp_did::DID;
use scp_event_log::{EventPayload, EventType};
use scp_identity::cache::DidCache;
use scp_identity::dht::DidDht;
use scp_identity::DidMethod;
use scp_platform::in_memory::InMemoryStorage;
use scp_platform::testing::{InMemoryKeyCustody, InMemoryPreRotationCustody};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── 1. Create a DID identity ──────────────────────────────────
    // The DID is self-certifying; `create` also stores a cold pre-rotation
    // commitment (spec §9.7.4.1) in a *distinct* custody instance.
    let custody = Arc::new(InMemoryKeyCustody::new());
    let pre_rotation_custody = InMemoryPreRotationCustody::new();
    let dht_client = Arc::new(InMemoryDhtClient::new());
    let cache = Arc::new(DidCache::new());
    let sign_fn = DidDht::<InMemoryDhtClient>::make_sign_fn(Arc::clone(&custody));
    let did_dht = DidDht::with_client_and_signer(dht_client, cache, sign_fn);

    let (identity, document, _pre_rotation_handle) =
        did_dht.create(&*custody, &pre_rotation_custody).await?;
    did_dht.publish(&identity, &document).await?;
    println!("Created identity: {}", identity.did);

    let did = DID(identity.did.clone());

    // ── 2. Build a Supervisor with providers ──────────────────────
    // Crypto is the production MLS factory bound to our DID; transport and
    // event log are mocks. `mls_storage` is a required, explicitly-selected
    // capability — here the in-memory dev arm behind the spawn-blocking adapter.
    let crypto = Arc::new(NodeMlsFactory::new(
        identity.did.clone(),
        Arc::new(SystemClock),
    ));
    let mls_storage = Arc::new(SpawnBlockingStorageAdapter::new(Arc::new(
        InMemoryStorage::new(),
    )));
    let key_resolver: KeyResolver = Arc::new(|_did: &DID, _kid: scp_did::SigningKeyId| None);

    let manager = Supervisor::with_providers(
        crypto,
        Box::new(MockTransport),
        Box::new(MockEventLog),
        key_resolver,
        None, // persistence: in-memory only
        None, // payment adapter
        None, // event broadcast sender
        None, // clock override (defaults to SystemClock)
        mls_storage,
    );

    // Register our DID so the supervisor recognizes us as a local participant.
    manager.register_local_did(did.clone()).await?;

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
        .create_context("my-context".to_owned(), params, did.clone(), None)
        .await?;
    println!(
        "Created context: {} (state: {:?})",
        handle.context_id(),
        handle.state()
    );

    // ── 4. Send a message ─────────────────────────────────────────
    // In production the message is signed by the identity's `#active` key via
    // the SDK; this scaffold derives a demo key deterministically from the DID.
    let signing_key = demo_signing_key(&identity.did);
    manager
        .send_message(
            &handle,
            &did,
            b"Hello, SCP!",
            MessageSigner::Active(&signing_key),
            None, // source provenance (cross-context only)
            None, // spending UCAN (paid actions only)
        )
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

/// Derives a deterministic Ed25519 signing key from a DID for demonstration.
///
/// Production clients sign with the identity's real `#active` verification-method
/// key held in key custody; this helper keeps the scaffold self-contained.
fn demo_signing_key(did: &str) -> ed25519_dalek::SigningKey {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    did.hash(&mut hasher);
    let h = hasher.finish();
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&h.to_le_bytes());
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

// ── Mock providers (replace with production implementations) ──────

/// Mock transport — reports connected; all sends succeed silently.
struct MockTransport;

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

/// Mock event log — all operations succeed with no persistence.
struct MockEventLog;

#[async_trait::async_trait]
impl ContextEventLogProvider for MockEventLog {
    async fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn append_event(
        &self,
        _id: &[u8; 32],
        _event_type: EventType,
        _actor_did: &str,
        _payload: EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
}
