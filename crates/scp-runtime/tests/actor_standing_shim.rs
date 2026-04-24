//! Integration test for the ADR-049 commit-11 standing shim.
//!
//! Exercises the path
//! [`Supervisor::dispatch_standing_command`](scp_runtime::context::supervisor::Supervisor::dispatch_standing_command)
//! → migrated
//! [`standing`](scp_runtime::context::actor::handlers::standing)
//! handler → delegated
//! [`ContextManager::standing_context`](scp_runtime::context::manager::ContextManager::standing_context)
//! / `..count` / `has_standing_context` / `register_standing_context`
//! / `reconnect_all_standing` — byte-identical to the legacy direct
//! path.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::disallowed_types,
    clippy::missing_const_for_fn
)]

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use scp_identity::DID;
use scp_platform::testing::InMemoryStorage;
use scp_protocol::context::ContextError;
use scp_protocol::context::builder::{ContextCreationError, ContextCryptoProvider};
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::params::ContextParams;
use scp_runtime::context::actor::commands::StandingCommand;
use scp_runtime::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use scp_runtime::context::manager::{ContextManager, ContextPersistence};
use scp_runtime::context::supervisor::{
    ProtocolRepositorySagaJournal, SagaJournal, Supervisor, SupervisorConfig,
};

// ---------------------------------------------------------------------------
// Mocks (inlined — mirrors pattern in actor_economy_shim.rs / actor_governance_shim.rs)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockCrypto;
impl ContextCryptoProvider for MockCrypto {
    fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn create_mls_group(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn generate_sender_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn init_broadcast_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn destroy_mls_group(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn destroy_sender_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn validate_key_package(
        &self,
        _owner_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<(), ContextError> {
        Ok(())
    }
    fn add_member(
        &self,
        _id: &[u8; 32],
        _member_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<scp_protocol::context::builder::AddMemberOutput, ContextError> {
        Ok(scp_protocol::context::builder::AddMemberOutput::default())
    }
    fn remove_member(
        &self,
        _id: &[u8; 32],
        _member_did: &str,
    ) -> Result<scp_protocol::context::builder::RemoveMemberOutput, ContextError> {
        Ok(scp_protocol::context::builder::RemoveMemberOutput::default())
    }
    fn distribute_sender_key(&self, _id: &[u8; 32], _member_did: &str) -> Result<(), ContextError> {
        Ok(())
    }
    fn remove_member_sender_key(
        &self,
        _id: &[u8; 32],
        _member_did: &str,
    ) -> Result<(), ContextError> {
        Ok(())
    }
    fn seal(
        &self,
        _context_id: &[u8; 32],
        inner: &scp_protocol::envelope::inner::InnerEnvelope,
        _routing_id: &[u8],
        _blob_ttl: u32,
    ) -> Result<Vec<u8>, ContextError> {
        rmp_serde::to_vec_named(inner)
            .map_err(|e| ContextError::CryptoFailed(format!("mock seal: {e}")))
    }
    fn open(
        &self,
        _context_id: &[u8; 32],
        outer_bytes: &[u8],
    ) -> Result<scp_protocol::context::builder::OpenResult, ContextError> {
        let inner: scp_protocol::envelope::inner::InnerEnvelope =
            rmp_serde::from_slice(outer_bytes)
                .map_err(|e| ContextError::CryptoFailed(format!("mock open: {e}")))?;
        let sender_did = inner.sender_did.clone();
        Ok(scp_protocol::context::builder::OpenResult::Application(
            Box::new(scp_protocol::context::builder::OpenedEnvelope { inner, sender_did }),
        ))
    }
}

#[derive(Default)]
struct TransportCaptures(Mutex<Vec<([u8; 32], Vec<u8>)>>);

struct MockTransport {
    captures: Arc<TransportCaptures>,
    connected: AtomicBool,
}
impl MockTransport {
    fn new(captures: Arc<TransportCaptures>) -> Self {
        Self {
            captures,
            connected: AtomicBool::new(true),
        }
    }
}
impl ContextTransportProvider for MockTransport {
    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
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
    fn send_message(&self, id: &[u8; 32], payload: &[u8]) -> Result<(), ContextError> {
        self.captures
            .0
            .lock()
            .unwrap()
            .push((*id, payload.to_vec()));
        Ok(())
    }
}

#[derive(Default)]
struct MockEventLog;
impl ContextEventLogProvider for MockEventLog {
    fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn append_event(
        &self,
        _id: &[u8; 32],
        _event: &str,
        _actor_did: &str,
        _payload: Option<&serde_json::Value>,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
}

struct NoopPersistence;
impl ContextPersistence for NoopPersistence {
    fn persist_context(
        &self,
        _: &str,
        _: &scp_runtime::context::manager::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    fn load_context(
        &self,
        _: &str,
    ) -> Result<
        Option<scp_runtime::context::manager::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(None)
    }
    fn persist_broadcast(
        &self,
        _: &str,
        _: &scp_protocol::context::broadcast::BroadcastContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    fn load_broadcast(
        &self,
        _: &str,
    ) -> Result<
        Option<scp_protocol::context::broadcast::BroadcastContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(None)
    }
    fn delete_context(&self, _: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Vec::new())
    }
}

fn did_to_seed(did: &DID) -> [u8; 32] {
    let mut s = [0u8; 32];
    let bytes = did.as_ref().as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        s[i % 32] ^= *b;
    }
    s
}

fn mock_key_resolver() -> KeyResolver {
    Arc::new(|did| {
        let seed = did_to_seed(did);
        Some(ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key())
    })
}

fn new_fixture() -> (Arc<ContextManager>, Arc<Supervisor>) {
    let captures = Arc::new(TransportCaptures::default());
    let manager = Arc::new(ContextManager::new(
        Box::new(MockCrypto),
        Box::new(MockTransport::new(Arc::clone(&captures))),
        Box::new(MockEventLog),
        mock_key_resolver(),
    ));
    let persistence: Arc<dyn ContextPersistence> = Arc::new(NoopPersistence);
    let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::new(
        InMemoryStorage::new(),
    )));
    let supervisor = Arc::new(Supervisor::new(
        persistence,
        journal,
        SupervisorConfig::default(),
    ));
    supervisor.attach_context_manager(&manager).unwrap();
    (manager, supervisor)
}

fn alice() -> DID {
    DID::from("did:dht:z6MkAlice")
}
fn bob() -> DID {
    DID::from("did:dht:z6MkBob")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn shim_standing_context_matches_legacy_context_id() {
    let (manager, supervisor) = new_fixture();
    // ADR-049 commit 12c.9d: `standing_context` now resolves the
    // Supervisor through the `Weak` back-pointer, so we must keep the
    // legacy fixture's Supervisor alive for the duration of the test.
    let (manager_legacy, _supervisor_legacy) = new_fixture();
    // Register the local DID on both managers so `create_context`
    // succeeds inside `standing_context`.
    manager.register_local_did(alice()).await;
    manager_legacy.register_local_did(alice()).await;

    // Shim.
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = StandingCommand::StandingContext {
        local_did: alice(),
        peer_did: bob(),
        reply: tx,
    };
    supervisor.dispatch_standing_command(cmd).await.unwrap();
    let shim_id = rx.await.unwrap().expect("standing_context should succeed");

    // Legacy.
    let legacy_id = manager_legacy
        .standing_context(&alice(), &bob())
        .await
        .expect("legacy standing_context should succeed");

    // Both paths use the same deterministic derivation.
    assert_eq!(
        shim_id, legacy_id,
        "shim and legacy standing_context must yield byte-identical context IDs"
    );
}

#[tokio::test]
async fn shim_standing_context_count_matches_legacy() {
    let (_manager, supervisor) = new_fixture();

    let (tx, rx) = tokio::sync::oneshot::channel();
    supervisor
        .dispatch_standing_command(StandingCommand::StandingContextCount { reply: tx })
        .await
        .unwrap();
    let count = rx.await.unwrap().unwrap();
    assert_eq!(count, 0, "fresh manager has zero standing contexts");
}

#[tokio::test]
async fn shim_has_standing_context_matches_legacy_false_case() {
    let (_manager, supervisor) = new_fixture();

    let (tx, rx) = tokio::sync::oneshot::channel();
    supervisor
        .dispatch_standing_command(StandingCommand::HasStandingContext {
            peer_did: bob(),
            reply: tx,
        })
        .await
        .unwrap();
    let has = rx.await.unwrap().unwrap();
    assert!(!has, "non-registered peer must not have standing context");
}

#[tokio::test]
async fn shim_register_standing_context_records_peer() {
    let (manager, supervisor) = new_fixture();

    let (tx, rx) = tokio::sync::oneshot::channel();
    supervisor
        .dispatch_standing_command(StandingCommand::RegisterStandingContext {
            peer_did: bob(),
            reply: tx,
        })
        .await
        .unwrap();
    rx.await.unwrap().unwrap();

    // Directly verify through the manager.
    assert!(manager.has_standing_context(&bob()).await);
}

#[tokio::test]
async fn shim_reconnect_all_standing_returns_count() {
    let (_manager, supervisor) = new_fixture();

    let (tx, rx) = tokio::sync::oneshot::channel();
    supervisor
        .dispatch_standing_command(StandingCommand::ReconnectAllStanding { reply: tx })
        .await
        .unwrap();
    let count = rx.await.unwrap().unwrap();
    assert_eq!(count, 0, "no standing contexts → reconnect returns 0");
}

/// The saga-initiator variant is spec-gapped in commit 11 — verify
/// the handler returns NotImplemented with the DEFERRED reference so
/// operators know where to look.
#[tokio::test]
async fn shim_initiate_standing_pair_create_returns_not_implemented() {
    let (_manager, supervisor) = new_fixture();

    let (tx, rx) = tokio::sync::oneshot::channel();
    supervisor
        .dispatch_standing_command(StandingCommand::InitiateStandingPairCreate {
            local_did: alice(),
            peer_did: bob(),
            reply: tx,
        })
        .await
        .unwrap();
    let err = rx.await.unwrap().unwrap_err();
    match err {
        ContextError::NotImplemented(msg) => {
            assert!(
                msg.contains("DEFERRED-commit-11-saga-use-cases.md")
                    || msg.contains("standing-pair 2-phase decomposition"),
                "NotImplemented message must reference DEFERRED doc, got: {msg}"
            );
        }
        other => panic!("expected NotImplemented, got {other:?}"),
    }
}

#[tokio::test]
async fn dispatch_standing_without_manager_returns_not_initialized() {
    let persistence: Arc<dyn ContextPersistence> = Arc::new(NoopPersistence);
    let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::new(
        InMemoryStorage::new(),
    )));
    let supervisor = Supervisor::new(persistence, journal, SupervisorConfig::default());

    let (tx, _rx) = tokio::sync::oneshot::channel();
    let result = supervisor
        .dispatch_standing_command(StandingCommand::HasStandingContext {
            peer_did: bob(),
            reply: tx,
        })
        .await;
    match result {
        Ok(_) => panic!("dispatch_standing_command without attached manager must error"),
        Err(ContextError::NotInitialized(_)) => {}
        Err(other) => panic!("expected NotInitialized, got {other:?}"),
    }
}
