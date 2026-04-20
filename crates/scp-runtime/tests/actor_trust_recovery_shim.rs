//! Integration test for the ADR-049 commit-10 trust-recovery shim.
//!
//! Exercises the path
//! [`Supervisor::dispatch_trust_recovery_command`](scp_runtime::context::supervisor::Supervisor::dispatch_trust_recovery_command)
//! → [`MutationStateView`](scp_runtime::context::actor::mutation_state_view)
//! → migrated
//! [`trust_recovery`](scp_runtime::context::actor::handlers::trust_recovery)
//! handler → delegated
//! [`ContextManager::create_governance_checkpoint`](scp_runtime::context::manager::ContextManager::create_governance_checkpoint)
//! against the legacy direct path.
//!
//! Acceptance for plan row 10: "governance tests pass; in-flight
//! sagas resolve correctly" — trust_recovery falls under the same
//! row's coverage.

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
use scp_protocol::context::params::{Capability, ContextParams, GovernanceModel};
use scp_runtime::context::actor::commands::{
    CreateGovernanceCheckpointPayload, TrustRecoveryCommand,
};
use scp_runtime::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use scp_runtime::context::manager::{ContextManager, ContextPersistence};
use scp_runtime::context::supervisor::{
    ProtocolRepositorySagaJournal, SagaJournal, Supervisor, SupervisorConfig,
};

// ---------------------------------------------------------------------------
// Mock providers (self-contained — same shape as peer shim tests)
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

fn sample_params() -> ContextParams {
    ContextParams {
        ceiling: vec![
            Capability::new("messages:read"),
            Capability::new("messages:write"),
        ],
        governance: GovernanceModel::SingleAdmin,
        ..ContextParams::default()
    }
}

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
            .expect("attach_context_manager should succeed");
        Self {
            manager,
            supervisor,
        }
    }
}

async fn bootstrap_context(fx: &Fixture, ctx_id: &str) {
    fx.manager
        .create_context(ctx_id.to_owned(), sample_params(), alice(), None)
        .await
        .expect("mock crypto must allow create_context");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Create a governance checkpoint through BOTH paths and assert the
/// observable manager-side result is consistent — both paths should
/// produce checkpoints with the same `checkpoint_seq`, `merkle_root`,
/// and `event_count` from the same inputs. The creator signature is
/// caller-provided, so the emitted checkpoint's signature field must
/// equal the input verbatim.
#[tokio::test]
async fn shim_create_governance_checkpoint_matches_legacy() {
    let fx_shim = Fixture::new();
    let fx_legacy = Fixture::new();

    let ctx_id = "ctx-checkpoint-parity";
    bootstrap_context(&fx_shim, ctx_id).await;
    bootstrap_context(&fx_legacy, ctx_id).await;

    // Deterministic inputs.
    let merkle_root = [1u8; 32];
    let last_event_hash = [2u8; 32];
    let state_snapshot_hash = [3u8; 32];
    let creator_signature = vec![0xAB; 64];

    // Shim path.
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = TrustRecoveryCommand::CreateGovernanceCheckpoint {
        payload: Box::new(CreateGovernanceCheckpointPayload {
            context_id: ctx_id.to_owned(),
            checkpoint_seq: 42,
            merkle_root,
            event_count: 100,
            last_event_hash,
            state_snapshot_hash,
            creator_did: alice(),
            creator_signature: creator_signature.clone(),
        }),
        reply: tx,
    };
    fx_shim
        .supervisor
        .dispatch_trust_recovery_command(cmd)
        .await
        .expect("shim dispatch should succeed");
    let shim_checkpoint = rx
        .await
        .expect("shim reply alive")
        .expect("shim create_governance_checkpoint should succeed");

    // Legacy path.
    let legacy_checkpoint = fx_legacy
        .manager
        .create_governance_checkpoint(
            ctx_id,
            42,
            merkle_root,
            100,
            last_event_hash,
            state_snapshot_hash,
            &alice(),
            creator_signature.clone(),
        )
        .await
        .expect("legacy create_governance_checkpoint should succeed");

    // Input fields must be reflected byte-identically in both
    // checkpoints.
    assert_eq!(
        shim_checkpoint.checkpoint_seq,
        legacy_checkpoint.checkpoint_seq
    );
    assert_eq!(shim_checkpoint.merkle_root, legacy_checkpoint.merkle_root);
    assert_eq!(shim_checkpoint.event_count, legacy_checkpoint.event_count);
    assert_eq!(
        shim_checkpoint.last_event_hash,
        legacy_checkpoint.last_event_hash
    );
    assert_eq!(
        shim_checkpoint.state_snapshot_hash,
        legacy_checkpoint.state_snapshot_hash
    );
    assert_eq!(shim_checkpoint.creator_did, legacy_checkpoint.creator_did);
    assert_eq!(
        shim_checkpoint.creator_signature,
        legacy_checkpoint.creator_signature
    );
    // Both paths produce FullyAttested under SingleAdmin (min_count == 0).
    assert_eq!(
        format!("{:?}", shim_checkpoint.attestation_status),
        format!("{:?}", legacy_checkpoint.attestation_status),
    );
}

/// A trust-recovery dispatch without an attached `ContextManager`
/// surfaces [`ContextError::NotInitialized`].
#[tokio::test]
async fn dispatch_trust_recovery_without_manager_returns_not_initialized() {
    let persistence: Arc<dyn ContextPersistence> = Arc::new(NoopPersistence);
    let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::new(
        InMemoryStorage::new(),
    )));
    let supervisor = Supervisor::new(persistence, journal, SupervisorConfig::default());

    let (tx, _rx) = tokio::sync::oneshot::channel();
    let cmd = TrustRecoveryCommand::RecoveryAdvanceEpoch {
        context_id: "anything".to_owned(),
        reply: tx,
    };
    let result = supervisor.dispatch_trust_recovery_command(cmd).await;

    match result {
        Ok(_) => panic!("dispatch_trust_recovery_command without attached manager must error"),
        Err(ContextError::NotInitialized(_)) => {}
        Err(other) => panic!("expected NotInitialized, got {other:?}"),
    }
}
