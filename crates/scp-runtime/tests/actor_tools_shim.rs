//! Integration test for the ADR-049 commit-11 tools shim.
//!
//! Exercises the path
//! [`Supervisor::dispatch_tools_command`](scp_runtime::context::supervisor::Supervisor::dispatch_tools_command)
//! → migrated
//! [`tools`](scp_runtime::context::actor::handlers::tools)
//! handler → delegated
//! [`ContextManager::try_consume_hard_rate_limit`](scp_runtime::context::manager::ContextManager::try_consume_hard_rate_limit)
//! / [`ContextManager::refund_hard_rate_limit`](scp_runtime::context::manager::ContextManager::refund_hard_rate_limit).
//! Non-cross-context variants only — cross-context invoke is spec-
//! gapped per `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`.

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
use scp_runtime::context::actor::commands::ToolsCommand;
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

/// Legacy `try_consume_hard_rate_limit` on an unknown context returns
/// `true` (pass-through semantics). The shim must preserve that
/// byte-identical behaviour.
#[tokio::test]
async fn shim_try_consume_unknown_context_returns_true() {
    let (_manager, supervisor) = new_fixture();

    let (tx, rx) = tokio::sync::oneshot::channel();
    supervisor
        .dispatch_tools_command(ToolsCommand::TryConsumeHardRateLimit {
            context_id: "ctx-unknown".into(),
            did: alice(),
            now_secs: 1_700_000_000,
            reply: tx,
        })
        .await
        .unwrap();
    let got = rx.await.unwrap().unwrap();
    assert!(
        got,
        "try_consume on unknown context must pass through as Ok(true) — matches legacy contract"
    );
}

/// Legacy `refund_hard_rate_limit` on an unknown context is a no-op.
/// The shim must preserve that.
#[tokio::test]
async fn shim_refund_unknown_context_is_noop() {
    let (_manager, supervisor) = new_fixture();

    let (tx, rx) = tokio::sync::oneshot::channel();
    supervisor
        .dispatch_tools_command(ToolsCommand::RefundHardRateLimit {
            context_id: "ctx-unknown".into(),
            did: alice(),
            reply: tx,
        })
        .await
        .unwrap();
    rx.await.unwrap().unwrap();
}

/// Cross-context invoke is spec-gapped — must return NotImplemented
/// with the DEFERRED reference.
#[tokio::test]
async fn shim_initiate_cross_context_invoke_returns_not_implemented() {
    let (_manager, supervisor) = new_fixture();

    let (tx, rx) = tokio::sync::oneshot::channel();
    supervisor
        .dispatch_tools_command(ToolsCommand::InitiateCrossContextToolInvocation {
            caller_context_id: [1u8; 32],
            caller_did: alice(),
            tool_registration_id: "tool:foo".into(),
            reply: tx,
        })
        .await
        .unwrap();
    let err = rx.await.unwrap().unwrap_err();
    match err {
        ContextError::NotImplemented(msg) => {
            assert!(
                msg.contains("DEFERRED-commit-11-saga-use-cases.md")
                    || msg.contains("cross-context tool"),
                "NotImplemented message must reference DEFERRED doc, got: {msg}"
            );
        }
        other => panic!("expected NotImplemented, got {other:?}"),
    }
}

#[tokio::test]
async fn dispatch_tools_without_manager_returns_not_initialized() {
    let persistence: Arc<dyn ContextPersistence> = Arc::new(NoopPersistence);
    let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::new(
        InMemoryStorage::new(),
    )));
    let supervisor = Supervisor::new(persistence, journal, SupervisorConfig::default());

    let (tx, _rx) = tokio::sync::oneshot::channel();
    let result = supervisor
        .dispatch_tools_command(ToolsCommand::RefundHardRateLimit {
            context_id: "ctx".into(),
            did: alice(),
            reply: tx,
        })
        .await;
    match result {
        Ok(_) => panic!("dispatch_tools_command without attached manager must error"),
        Err(ContextError::NotInitialized(_)) => {}
        Err(other) => panic!("expected NotInitialized, got {other:?}"),
    }
}
