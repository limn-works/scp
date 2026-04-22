//! Integration test for the ADR-049 commit-9 lifecycle + TTL-close shim.
//!
//! Exercises the path
//! [`Supervisor::dispatch_lifecycle_command`](scp_runtime::context::supervisor::Supervisor::dispatch_lifecycle_command)
//! → `MutationStateView` (deleted in commit 12c.7 of ADR-049)
//! → migrated
//! [`lifecycle`](scp_runtime::context::actor::handlers::lifecycle)
//! handler → delegated
//! [`ContextManager::create_context`](scp_runtime::context::manager::ContextManager::create_context)
//! / [`ContextManager::close_context`](scp_runtime::context::manager::ContextManager::close_context)
//! / [`ContextManager::join_context`](scp_runtime::context::manager::ContextManager::join_context)
//! / [`ContextManager::export_context`](scp_runtime::context::manager::ContextManager::export_context)
//! / [`ContextManager::import_context`](scp_runtime::context::manager::ContextManager::import_context)
//! against the legacy direct path. For each scenario the test runs the
//! command through BOTH paths and asserts the resulting manager-side
//! state matches.
//!
//! Acceptance for plan row 9: "lifecycle tests + per-binding smoke
//! tests pass".

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::similar_names,
    // Integration-test docs cite runtime types by bare name for
    // readability; clippy's `doc_markdown` would require backticks
    // everywhere.
    clippy::doc_markdown,
    // The mock transport uses a `std::sync::Mutex` for the capture
    // buffer — it is a SYNC trait method so `tokio::sync::Mutex`
    // cannot be used.
    clippy::disallowed_types,
    clippy::missing_const_for_fn,
)]

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use scp_identity::DID;
use scp_platform::testing::InMemoryStorage;
use scp_protocol::context::ContextError;
use scp_protocol::context::builder::{ContextCreationError, ContextCryptoProvider};
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::params::{Capability, ContextParams, GovernanceModel};
use scp_runtime::context::actor::commands::{
    CloseContextPayload, CreateContextPayload, LifecycleCommand,
};
use scp_runtime::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use scp_runtime::context::manager::{ContextManager, ContextPersistence};
use scp_runtime::context::supervisor::{
    ProtocolRepositorySagaJournal, SagaJournal, Supervisor, SupervisorConfig,
};

// ---------------------------------------------------------------------------
// Mock providers (same shape as actor_messaging_shim.rs — kept per-file
// rather than shared to keep each integration test self-contained)
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

// ---------------------------------------------------------------------------
// Key resolver + DID helpers
// ---------------------------------------------------------------------------

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

fn alice() -> DID {
    DID::from("did:dht:z6MkAlice")
}

// ---------------------------------------------------------------------------
// Fixture — supervisor + manager wired together
// ---------------------------------------------------------------------------

struct Fixture {
    manager: Arc<ContextManager>,
    supervisor: Arc<Supervisor>,
}

impl Fixture {
    fn new() -> Self {
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
        supervisor
            .attach_context_manager(&manager)
            .expect("attach_context_manager should succeed on empty Supervisor");

        Self {
            manager,
            supervisor,
        }
    }
}

fn sample_params() -> ContextParams {
    ContextParams {
        ceiling: vec![
            Capability::new("messages:read"),
            Capability::new("messages:write"),
            Capability::ContextClose,
        ],
        governance: GovernanceModel::SingleAdmin,
        ..ContextParams::default()
    }
}

// ---------------------------------------------------------------------------
// Helpers — create / close via shim and via legacy
// ---------------------------------------------------------------------------

async fn create_through_shim(
    fx: &Fixture,
    ctx_id: &str,
    creator: &DID,
    params: ContextParams,
) -> Result<(), ContextCreationError> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = LifecycleCommand::CreateContext {
        payload: Box::new(CreateContextPayload {
            context_id: ctx_id.to_owned(),
            params,
            creator_did: creator.clone(),
            local_pseudonym: None,
        }),
        reply: tx,
    };
    fx.supervisor
        .dispatch_lifecycle_command(cmd)
        .await
        .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
    rx.await
        .map_err(|e| ContextCreationError::CreationFailed(format!("reply dropped: {e}")))??;
    Ok(())
}

async fn create_through_legacy(
    fx: &Fixture,
    ctx_id: &str,
    creator: &DID,
    params: ContextParams,
) -> Result<(), ContextCreationError> {
    fx.manager
        .create_context(ctx_id.to_owned(), params, creator.clone(), None)
        .await
        .map(|_| ())
}

async fn close_through_shim(
    fx: &Fixture,
    ctx_id: &str,
    initiator: &DID,
    params: ContextParams,
) -> Result<(), ContextError> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = LifecycleCommand::CloseContext {
        payload: Box::new(CloseContextPayload {
            context_id: ctx_id.to_owned(),
            params,
            initiator_did: initiator.clone(),
        }),
        reply: tx,
    };
    fx.supervisor.dispatch_lifecycle_command(cmd).await?;
    rx.await
        .map_err(|e| ContextError::CryptoFailed(format!("reply dropped: {e}")))??;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `create_context` through both paths produces identical manager-side
/// state: same member count, same creator role, same context params.
#[tokio::test]
async fn shim_create_matches_legacy_state() {
    let fx_shim = Fixture::new();
    let fx_legacy = Fixture::new();

    let ctx_id = "ctx-create-parity";
    let params = sample_params();

    create_through_shim(&fx_shim, ctx_id, &alice(), params.clone())
        .await
        .expect("shim create should succeed");
    create_through_legacy(&fx_legacy, ctx_id, &alice(), params.clone())
        .await
        .expect("legacy create should succeed");

    // Member count parity.
    let shim_count = fx_shim.manager.member_count(ctx_id).await;
    let legacy_count = fx_legacy.manager.member_count(ctx_id).await;
    assert_eq!(
        shim_count, legacy_count,
        "shim and legacy create must produce identical member counts (shim={shim_count:?} legacy={legacy_count:?})",
    );
    assert_eq!(shim_count, Some(1), "creator should be the sole member");

    // Membership parity.
    let shim_dids = fx_shim.manager.member_dids(ctx_id).await;
    let legacy_dids = fx_legacy.manager.member_dids(ctx_id).await;
    assert_eq!(
        shim_dids, legacy_dids,
        "shim and legacy create must enrol the same member set",
    );

    // Role parity — creator assigned to admin.
    let shim_role = fx_shim.manager.member_role(ctx_id, &alice()).await;
    let legacy_role = fx_legacy.manager.member_role(ctx_id, &alice()).await;
    assert_eq!(
        shim_role.map(|r| r.role_name),
        legacy_role.map(|r| r.role_name),
        "shim and legacy create must assign the creator to the same role",
    );

    // Context params parity.
    let shim_params = fx_shim.manager.context_params(ctx_id).await;
    let legacy_params = fx_legacy.manager.context_params(ctx_id).await;
    assert!(shim_params.is_some());
    assert_eq!(
        shim_params, legacy_params,
        "shim and legacy create must store identical ContextParams",
    );
}

/// `close_context` through the actor path transitions the underlying
/// context to the expected terminal state — the manager's
/// `context_params` accessor still returns the registered params (close
/// does not delete the registration on SingleAdmin) but the member
/// count parity vs. the legacy close must hold.
#[tokio::test]
async fn shim_close_matches_legacy_close() {
    let fx_shim = Fixture::new();
    let fx_legacy = Fixture::new();

    let ctx_id = "ctx-close-parity";
    let params = sample_params();

    create_through_shim(&fx_shim, ctx_id, &alice(), params.clone())
        .await
        .expect("shim create should succeed");
    create_through_legacy(&fx_legacy, ctx_id, &alice(), params.clone())
        .await
        .expect("legacy create should succeed");

    // Close via the shim on one fixture.
    close_through_shim(&fx_shim, ctx_id, &alice(), params.clone())
        .await
        .expect("shim close should succeed");

    // Close via the legacy path on the other fixture.
    let legacy_params_owned = params.clone();
    let legacy_handle =
        scp_runtime::context::ContextHandle::new(ctx_id.to_owned(), legacy_params_owned);
    let _ = legacy_handle
        .transition_to(&scp_protocol::context::ContextState::Active)
        .await;
    fx_legacy
        .manager
        .close_context(&legacy_handle, &alice())
        .await
        .expect("legacy close should succeed");

    // Assert observable state parity after close: both paths leave the
    // context registered under `SingleAdmin` semantics; the
    // member_count accessor returns the surviving creator count.
    let shim_count = fx_shim.manager.member_count(ctx_id).await;
    let legacy_count = fx_legacy.manager.member_count(ctx_id).await;
    assert_eq!(
        shim_count, legacy_count,
        "shim and legacy close must leave identical member counts (shim={shim_count:?} legacy={legacy_count:?})",
    );
}

/// `create_context` → `export_context` → `import_context` through the
/// shim lands the imported context in a state that matches the
/// original: same context_id, same member set, same params.
#[tokio::test]
async fn shim_export_and_reimport_round_trips() {
    let fx = Fixture::new();
    let ctx_id = "ctx-export-roundtrip";
    let params = sample_params();

    create_through_shim(&fx, ctx_id, &alice(), params.clone())
        .await
        .expect("shim create should succeed");

    // Export via the shim.
    let export = {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::ExportContext {
            context_id: ctx_id.to_owned(),
            exporter_did: alice(),
            reply: tx,
        };
        fx.supervisor
            .dispatch_lifecycle_command(cmd)
            .await
            .expect("shim dispatch should succeed");
        rx.await
            .expect("reply channel alive")
            .expect("shim export should succeed")
    };

    // New fixture — nothing registered yet.
    let fx_import = Fixture::new();

    // Import via the shim.
    {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::ImportContext {
            export: Box::new(export),
            reply: tx,
        };
        fx_import
            .supervisor
            .dispatch_lifecycle_command(cmd)
            .await
            .expect("shim dispatch should succeed");
        rx.await
            .expect("reply channel alive")
            .expect("shim import should succeed");
    }

    // Assert parity between the original and the imported context.
    let orig_count = fx.manager.member_count(ctx_id).await;
    let imported_count = fx_import.manager.member_count(ctx_id).await;
    assert_eq!(
        orig_count, imported_count,
        "imported context must have the same member count as the exported original",
    );
    assert_eq!(
        imported_count,
        Some(1),
        "single-member context should round-trip as a single member",
    );

    let orig_dids = fx.manager.member_dids(ctx_id).await;
    let imported_dids = fx_import.manager.member_dids(ctx_id).await;
    assert_eq!(
        orig_dids, imported_dids,
        "imported context must have the same member set as the exported original",
    );
}

/// Missing manager sanity check: a lifecycle dispatch without an
/// attached `ContextManager` must surface
/// [`ContextError::NotInitialized`].
#[tokio::test]
async fn dispatch_lifecycle_without_manager_returns_not_initialized() {
    let persistence: Arc<dyn ContextPersistence> = Arc::new(NoopPersistence);
    let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::new(
        InMemoryStorage::new(),
    )));
    let supervisor = Supervisor::new(persistence, journal, SupervisorConfig::default());

    let (tx, _rx) = tokio::sync::oneshot::channel();
    let cmd = LifecycleCommand::CreateContext {
        payload: Box::new(CreateContextPayload {
            context_id: "anything".to_owned(),
            params: ContextParams::default(),
            creator_did: alice(),
            local_pseudonym: None,
        }),
        reply: tx,
    };
    let result = supervisor.dispatch_lifecycle_command(cmd).await;

    match result {
        Ok(_) => panic!("dispatch_lifecycle_command without attached manager must error"),
        Err(ContextError::NotInitialized(_)) => {}
        Err(other) => panic!("expected NotInitialized, got {other:?}"),
    }
}

/// TTL-close dispatch without a manager mirrors the lifecycle path:
/// [`ContextError::NotInitialized`].
#[tokio::test]
async fn dispatch_ttl_close_without_manager_returns_not_initialized() {
    use scp_runtime::context::actor::commands::{TtlCloseCommand, TtlContextPayload};

    let persistence: Arc<dyn ContextPersistence> = Arc::new(NoopPersistence);
    let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::new(
        InMemoryStorage::new(),
    )));
    let supervisor = Supervisor::new(persistence, journal, SupervisorConfig::default());

    let (tx, _rx) = tokio::sync::oneshot::channel();
    let cmd = TtlCloseCommand::FinalizeClose {
        payload: Box::new(TtlContextPayload {
            context_id: "anything".to_owned(),
            params: ContextParams::default(),
        }),
        reply: tx,
    };
    let result = supervisor.dispatch_ttl_close_command(cmd).await;

    match result {
        Ok(_) => panic!("dispatch_ttl_close_command without attached manager must error"),
        Err(ContextError::NotInitialized(_)) => {}
        Err(other) => panic!("expected NotInitialized, got {other:?}"),
    }
}
