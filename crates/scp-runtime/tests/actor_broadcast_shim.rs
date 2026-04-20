//! Integration test for the ADR-049 commit-11 broadcast shim.
//!
//! Exercises the path
//! [`Supervisor::dispatch_broadcast_command`](scp_runtime::context::supervisor::Supervisor::dispatch_broadcast_command)
//! → migrated
//! [`broadcast`](scp_runtime::context::actor::handlers::broadcast)
//! handler → delegated
//! [`ContextManager::broadcast_subscriber_count`](scp_runtime::context::manager::ContextManager::broadcast_subscriber_count)
//! / `is_broadcast_subscriber` / `broadcast_admission`.
//!
//! Non-handshake variants only — the
//! `InitiateBroadcastHostingHandshake` saga-initiator variant is
//! spec-gapped per
//! `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`.

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
use scp_runtime::context::actor::commands::BroadcastCommand;
use scp_runtime::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use scp_runtime::context::manager::{ContextManager, ContextPersistence};
use scp_runtime::context::supervisor::{
    ProtocolRepositorySagaJournal, SagaJournal, Supervisor, SupervisorConfig,
};

// ---------------------------------------------------------------------------
// Mocks
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
    fn new(c: Arc<TransportCaptures>) -> Self {
        Self {
            captures: c,
            connected: AtomicBool::new(true),
        }
    }
}
impl ContextTransportProvider for MockTransport {
    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
    fn publish_context(&self, _: &[u8; 32], _: &ContextParams) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn delete_published(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn send_message(&self, id: &[u8; 32], p: &[u8]) -> Result<(), ContextError> {
        self.captures.0.lock().unwrap().push((*id, p.to_vec()));
        Ok(())
    }
}

#[derive(Default)]
struct MockEventLog;
impl ContextEventLogProvider for MockEventLog {
    fn init_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn append_event(
        &self,
        _: &[u8; 32],
        _: &str,
        _: &str,
        _: Option<&serde_json::Value>,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn destroy_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `broadcast_subscriber_count` on an unknown context returns
/// `Ok(None)` — verifies shim preserves the legacy contract.
#[tokio::test]
async fn shim_subscriber_count_unknown_returns_none() {
    let (_manager, supervisor) = new_fixture();

    let (tx, rx) = tokio::sync::oneshot::channel();
    supervisor
        .dispatch_broadcast_command(BroadcastCommand::BroadcastSubscriberCount {
            context_id: "ctx-unknown".into(),
            reply: tx,
        })
        .await
        .unwrap();
    let got = rx.await.unwrap().unwrap();
    assert!(
        got.is_none(),
        "unknown context must yield Ok(None) from broadcast_subscriber_count"
    );
}

/// `is_broadcast_subscriber` on an unknown context returns `false`.
#[tokio::test]
async fn shim_is_subscriber_unknown_returns_false() {
    let (_manager, supervisor) = new_fixture();

    let (tx, rx) = tokio::sync::oneshot::channel();
    supervisor
        .dispatch_broadcast_command(BroadcastCommand::IsBroadcastSubscriber {
            context_id: "ctx-unknown".into(),
            did: "did:example:nobody".into(),
            reply: tx,
        })
        .await
        .unwrap();
    let got = rx.await.unwrap().unwrap();
    assert!(
        !got,
        "unknown context must yield Ok(false) from is_broadcast_subscriber"
    );
}

/// `broadcast_admission` on an unknown context returns `Ok(None)`.
#[tokio::test]
async fn shim_admission_unknown_returns_none() {
    let (_manager, supervisor) = new_fixture();

    let (tx, rx) = tokio::sync::oneshot::channel();
    supervisor
        .dispatch_broadcast_command(BroadcastCommand::BroadcastAdmission {
            context_id: "ctx-unknown".into(),
            reply: tx,
        })
        .await
        .unwrap();
    let got = rx.await.unwrap().unwrap();
    assert!(
        got.is_none(),
        "unknown context must yield Ok(None) from broadcast_admission"
    );
}

/// Subscribe on an unknown (non-registered) context returns
/// `ContextNotRegistered` — legacy parity.
#[tokio::test]
async fn shim_subscribe_unknown_context_returns_not_registered() {
    let (_manager, supervisor) = new_fixture();

    let (tx, rx) = tokio::sync::oneshot::channel();
    supervisor
        .dispatch_broadcast_command(BroadcastCommand::SubscribeBroadcast {
            payload: Box::new(
                scp_runtime::context::actor::commands::SubscribeBroadcastPayload {
                    context_id: "ctx-unknown".into(),
                    subscriber_did: alice(),
                    ucan: None,
                    timestamp: 1_700_000_000,
                },
            ),
            reply: tx,
        })
        .await
        .unwrap();
    let err = rx.await.unwrap().unwrap_err();
    match err {
        ContextError::ContextNotRegistered(_) => {}
        other => panic!("expected ContextNotRegistered, got {other:?}"),
    }
}

/// The hosting-handshake saga-initiator variant is spec-gapped — must
/// surface NotImplemented with the DEFERRED reference.
#[tokio::test]
async fn shim_initiate_hosting_handshake_returns_not_implemented() {
    let (_manager, supervisor) = new_fixture();

    let (tx, rx) = tokio::sync::oneshot::channel();
    supervisor
        .dispatch_broadcast_command(BroadcastCommand::InitiateBroadcastHostingHandshake {
            host_context_id: [1u8; 32],
            broadcast_context_id: [2u8; 32],
            subscriber_did: alice(),
            reply: tx,
        })
        .await
        .unwrap();
    let err = rx.await.unwrap().unwrap_err();
    match err {
        ContextError::NotImplemented(msg) => {
            assert!(
                msg.contains("DEFERRED-commit-11-saga-use-cases.md")
                    || msg.contains("broadcast hosting handshake protocol"),
                "NotImplemented message must reference DEFERRED doc, got: {msg}"
            );
        }
        other => panic!("expected NotImplemented, got {other:?}"),
    }
}

/// `PublishBroadcast` through the non-custody entry point surfaces a
/// typed error directing the caller to the custody-generic path.
#[tokio::test]
async fn shim_publish_without_custody_returns_invalid_state() {
    let (_manager, supervisor) = new_fixture();

    // Construct a dummy payload — the handler rejects at the dispatch
    // layer before any payload field is read.
    let dummy_handle = scp_platform::KeyHandle::new(42);
    let (tx, rx) = tokio::sync::oneshot::channel();
    supervisor
        .dispatch_broadcast_command(BroadcastCommand::PublishBroadcast {
            payload: Box::new(
                scp_runtime::context::actor::commands::PublishBroadcastPayload {
                    context_id: "ctx".into(),
                    author_did: alice(),
                    payload: Vec::new(),
                    signing_key_handle: dummy_handle,
                },
            ),
            reply: tx,
        })
        .await
        .unwrap();
    let err = rx.await.unwrap().unwrap_err();
    match err {
        ContextError::InvalidState(msg) => {
            assert!(
                msg.contains("KeyCustody") || msg.contains("_with_custody"),
                "InvalidState must direct caller to the custody path, got: {msg}"
            );
        }
        other => panic!("expected InvalidState, got {other:?}"),
    }
}

#[tokio::test]
async fn dispatch_broadcast_without_manager_returns_not_initialized() {
    let persistence: Arc<dyn ContextPersistence> = Arc::new(NoopPersistence);
    let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::new(
        InMemoryStorage::new(),
    )));
    let supervisor = Supervisor::new(persistence, journal, SupervisorConfig::default());

    let (tx, _rx) = tokio::sync::oneshot::channel();
    let result = supervisor
        .dispatch_broadcast_command(BroadcastCommand::BroadcastSubscriberCount {
            context_id: "ctx".into(),
            reply: tx,
        })
        .await;
    match result {
        Ok(_) => panic!("dispatch_broadcast_command without attached manager must error"),
        Err(ContextError::NotInitialized(_)) => {}
        Err(other) => panic!("expected NotInitialized, got {other:?}"),
    }
}
