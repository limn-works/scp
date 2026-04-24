//! Integration test for the ADR-049 commit-10 economy shim.
//!
//! Exercises the path
//! [`Supervisor::dispatch_economy_command`](scp_runtime::context::supervisor::Supervisor::dispatch_economy_command)
//! → `MutationStateView` (deleted in commit 12c.7 of ADR-049)
//! → migrated
//! [`economy`](scp_runtime::context::actor::handlers::economy)
//! handler → delegated
//! [`ContextManager::verify_payment_receipts`](scp_runtime::context::manager::ContextManager::verify_payment_receipts)
//! against the legacy direct path.
//!
//! The economy's public FFI surface is narrow (one method), so this
//! test focuses on the routing layer: an empty receipts vector must
//! produce an empty result vector on both paths, and the boot-order
//! `NotInitialized` invariant must hold.
//!
//! Acceptance for plan row 10: "governance tests pass; in-flight
//! sagas resolve correctly" — economy falls under the same row's
//! coverage.

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
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::params::ContextParams;
use scp_runtime::context::actor::commands::EconomyCommand;
use scp_runtime::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use scp_runtime::context::manager::{ContextManager, ContextPersistence};
use scp_runtime::context::supervisor::{
    ProtocolRepositorySagaJournal, SagaJournal, Supervisor, SupervisorConfig,
};
use scp_runtime::crypto::mls::provider::MlsCryptoProvider;

// ---------------------------------------------------------------------------
// Mock providers (copied from actor_lifecycle_shim.rs; self-contained)
// ---------------------------------------------------------------------------

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
    fn send_message(&self, id: &[u8; 32], encrypted_payload: &[u8]) -> Result<(), ContextError> {
        self.captures
            .0
            .lock()
            .unwrap()
            .push((*id, encrypted_payload.to_vec()));
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
        _context_id: &str,
        _snapshot: &scp_runtime::context::manager::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    fn load_context(
        &self,
        _context_id: &str,
    ) -> Result<
        Option<scp_runtime::context::manager::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(None)
    }
    fn persist_broadcast(
        &self,
        _context_id: &str,
        _snapshot: &scp_protocol::context::broadcast::BroadcastContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    fn load_broadcast(
        &self,
        _context_id: &str,
    ) -> Result<
        Option<scp_protocol::context::broadcast::BroadcastContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(None)
    }
    fn delete_context(
        &self,
        _context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
        Arc::new(MlsCryptoProvider::new(
            "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_owned(),
        )),
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
    supervisor
        .attach_context_manager(&manager)
        .expect("attach_context_manager should succeed");
    (manager, supervisor)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Empty-receipt parity: the shim and the legacy path both return an
/// empty vector when no receipts are supplied.
#[tokio::test]
async fn shim_verify_empty_receipts_matches_legacy() {
    let (manager, supervisor) = new_fixture();

    // Shim path.
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = EconomyCommand::VerifyPaymentReceipts {
        receipts: Box::new(Vec::new()),
        reply: tx,
    };
    supervisor
        .dispatch_economy_command(cmd)
        .await
        .expect("shim dispatch should succeed");
    let shim_results = rx.await.expect("reply alive");

    // Legacy path.
    let legacy_results = manager.verify_payment_receipts(&[]).await;

    assert_eq!(
        shim_results.len(),
        legacy_results.len(),
        "shim and legacy verify_payment_receipts must agree on result count",
    );
    assert!(
        shim_results.is_empty(),
        "empty receipts in means empty results out",
    );
}

/// An economy dispatch without an attached `ContextManager` surfaces
/// [`ContextError::NotInitialized`].
#[tokio::test]
async fn dispatch_economy_without_manager_returns_not_initialized() {
    let persistence: Arc<dyn ContextPersistence> = Arc::new(NoopPersistence);
    let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::new(
        InMemoryStorage::new(),
    )));
    let supervisor = Supervisor::new(persistence, journal, SupervisorConfig::default());

    let (tx, _rx) = tokio::sync::oneshot::channel();
    let cmd = EconomyCommand::VerifyPaymentReceipts {
        receipts: Box::new(Vec::new()),
        reply: tx,
    };
    let result = supervisor.dispatch_economy_command(cmd).await;

    match result {
        Ok(_) => panic!("dispatch_economy_command without attached manager must error"),
        Err(ContextError::NotInitialized(_)) => {}
        Err(other) => panic!("expected NotInitialized, got {other:?}"),
    }
}
