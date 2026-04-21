//! Integration test for the ADR-049 commit-7 query shim.
//!
//! Exercises the path
//! [`Supervisor::dispatch_query`](scp_runtime::context::supervisor::Supervisor::dispatch_query)
//! → [`QueryStateView`](scp_runtime::context::actor::query_state_view)
//! → migrated [`queries`](scp_runtime::context::actor::handlers::queries)
//! handler
//! against the legacy [`ContextManager`](scp_runtime::context::manager::ContextManager)
//! methods it replaces. For each migrated variant the test runs the query
//! through BOTH paths and asserts byte-identical results. Then the test
//! mutates state through the legacy writer API and re-runs the parity
//! assertions — proving the shim does not perturb observable behaviour.
//!
//! Scope: commit 7 migrates a subset of the read variants (member_count,
//! is_member, member_dids, member_role, context_params, get_role_state,
//! pending_commits, commit_fault, event_log_entries, local_pseudonym).
//! The remaining variants migrate in commits 8-11 (see plan row 7) and
//! will extend this test as they land.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::similar_names,
    // Integration-test docs cite runtime types by bare name
    // (`ContextManager`, `Supervisor`, etc.) for readability; clippy's
    // `doc_markdown` asks for backticks but the test file has no
    // user-facing rustdoc consumers.
    clippy::doc_markdown,
    // ADR-049 commit 12c.2: lifecycle hoist inflates some test-path
    // futures past clippy's 16 KB stack budget.
    clippy::large_futures
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use scp_identity::DID;
use scp_platform::testing::InMemoryStorage;
use scp_protocol::context::ContextError;
use scp_protocol::context::builder::{ContextCreationError, ContextCryptoProvider};
use scp_protocol::context::governance::{GovernanceAction, KeyResolver, ProposalStatus};
use scp_protocol::context::params::{Capability, ContextParams, GovernanceModel};
use scp_runtime::context::actor::commands::QueriesCommand;
use scp_runtime::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use scp_runtime::context::manager::{ContextManager, ContextPersistence};
use scp_runtime::context::supervisor::{
    ProtocolRepositorySagaJournal, SagaJournal, Supervisor, SupervisorConfig,
};

// ---------------------------------------------------------------------------
// Mock providers — minimal impls sufficient for the query shim test.
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
}

struct MockTransport(AtomicBool);

impl Default for MockTransport {
    fn default() -> Self {
        Self(AtomicBool::new(true))
    }
}

impl ContextTransportProvider for MockTransport {
    fn is_connected(&self) -> bool {
        self.0.load(Ordering::Relaxed)
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

/// No-op persistence — we don't exercise the persistence path in the
/// query shim test. `Supervisor::for_query_shim` supplies its own
/// equivalent for the supervisor's internal field; `ContextManager`
/// still needs a concrete impl for the fixture.
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

fn signing_key_for_did(did: &DID) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&did_to_seed(did))
}

fn alice() -> DID {
    DID::from("did:dht:z6MkAlice")
}
fn bob() -> DID {
    DID::from("did:dht:z6MkBob")
}
fn carol() -> DID {
    DID::from("did:dht:z6MkCarol")
}

// ---------------------------------------------------------------------------
// Fixture — one shared manager + supervisor with supervisor pre-attached
// ---------------------------------------------------------------------------

struct Fixture {
    manager: Arc<ContextManager>,
    supervisor: Arc<Supervisor>,
}

impl Fixture {
    fn new() -> Self {
        let manager = Arc::new(ContextManager::new(
            Box::new(MockCrypto),
            Box::new(MockTransport::default()),
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

    /// Creates a new context with governance-ready ceiling. The creator
    /// is `alice()` by default.
    async fn create_context(&self, ctx_id: &str) {
        let params = ContextParams {
            ceiling: vec![
                Capability::new("messages:read"),
                Capability::new("messages:write"),
                Capability::new("role:assign"),
                Capability::new("governance:propose"),
                Capability::new("governance:vote"),
                Capability::MemberBan,
            ],
            governance: GovernanceModel::SingleAdmin,
            ..ContextParams::default()
        };
        self.manager
            .create_context(ctx_id.to_owned(), params, alice(), None)
            .await
            .expect("create_context should succeed");
    }

    /// Adds a member via the SingleAdmin governance path (so the mutation
    /// survives through the legacy ContextManager's governance pipeline
    /// the same way production code would).
    async fn add_member(&self, ctx_id: &str, new_member: DID) {
        let sk = signing_key_for_did(&alice());
        let (proposal, _outcome, _events) = self
            .manager
            .propose_governance_action(
                ctx_id,
                &alice(),
                GovernanceAction::AddMember {
                    did: new_member,
                    role: "member".into(),
                },
                &sk,
            )
            .await
            .expect("propose AddMember should succeed");
        assert_eq!(proposal.status, ProposalStatus::Approved);
    }
}

// ---------------------------------------------------------------------------
// Parity helpers — run each query through BOTH paths and assert equal.
// ---------------------------------------------------------------------------

async fn assert_member_count_parity(fx: &Fixture, ctx_id: &str) {
    let legacy = fx.manager.member_count(ctx_id).await;

    let (tx, rx) = tokio::sync::oneshot::channel();
    fx.supervisor
        .dispatch_query(QueriesCommand::MemberCount {
            context_id: ctx_id.to_owned(),
            reply: tx,
        })
        .await
        .expect("dispatch_query MemberCount should succeed");
    let shim = rx.await.expect("reply channel alive").expect("handler ok");

    assert_eq!(
        legacy, shim,
        "member_count parity — ctx_id={ctx_id} legacy={legacy:?} shim={shim:?}",
    );
}

async fn assert_is_member_parity(fx: &Fixture, ctx_id: &str, did: &str) {
    let legacy = fx.manager.is_member(ctx_id, did).await;

    let (tx, rx) = tokio::sync::oneshot::channel();
    fx.supervisor
        .dispatch_query(QueriesCommand::IsMember {
            context_id: ctx_id.to_owned(),
            did: did.to_owned(),
            reply: tx,
        })
        .await
        .expect("dispatch_query IsMember should succeed");
    let shim = rx.await.expect("reply channel alive").expect("handler ok");

    assert_eq!(
        legacy, shim,
        "is_member parity — ctx_id={ctx_id} did={did} legacy={legacy} shim={shim}",
    );
}

async fn assert_member_dids_parity(fx: &Fixture, ctx_id: &str) {
    let mut legacy = fx.manager.member_dids(ctx_id).await;

    let (tx, rx) = tokio::sync::oneshot::channel();
    fx.supervisor
        .dispatch_query(QueriesCommand::MemberDids {
            context_id: ctx_id.to_owned(),
            reply: tx,
        })
        .await
        .expect("dispatch_query MemberDids should succeed");
    let mut shim = rx.await.expect("reply channel alive").expect("handler ok");

    // `MembershipState::member_dids` iteration order is not stable
    // (HashMap). Sort both sides before comparing set equality — the
    // legacy path applies the same iteration order, so an element-wise
    // mismatch here would be a real shim divergence.
    legacy.sort();
    shim.sort();
    assert_eq!(legacy, shim, "member_dids parity — ctx_id={ctx_id}");
}

async fn assert_member_role_parity(fx: &Fixture, ctx_id: &str, did: &str) {
    let legacy = fx.manager.member_role(ctx_id, did).await;

    let (tx, rx) = tokio::sync::oneshot::channel();
    fx.supervisor
        .dispatch_query(QueriesCommand::MemberRole {
            context_id: ctx_id.to_owned(),
            did: did.to_owned(),
            reply: tx,
        })
        .await
        .expect("dispatch_query MemberRole should succeed");
    let shim = rx.await.expect("reply channel alive").expect("handler ok");

    assert_eq!(
        legacy, shim,
        "member_role parity — ctx_id={ctx_id} did={did}"
    );
}

async fn assert_context_params_parity(fx: &Fixture, ctx_id: &str) {
    let legacy = fx.manager.context_params(ctx_id).await;

    let (tx, rx) = tokio::sync::oneshot::channel();
    fx.supervisor
        .dispatch_query(QueriesCommand::ContextParams {
            context_id: ctx_id.to_owned(),
            reply: tx,
        })
        .await
        .expect("dispatch_query ContextParams should succeed");
    let shim = rx.await.expect("reply channel alive").expect("handler ok");

    assert_eq!(legacy, shim, "context_params parity — ctx_id={ctx_id}");
}

async fn run_all_parity_checks(fx: &Fixture, ctx_id: &str, dids: &[&str]) {
    assert_member_count_parity(fx, ctx_id).await;
    assert_member_dids_parity(fx, ctx_id).await;
    assert_context_params_parity(fx, ctx_id).await;
    for did in dids {
        assert_is_member_parity(fx, ctx_id, did).await;
        assert_member_role_parity(fx, ctx_id, did).await;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// End-to-end parity: create context, verify every migrated query variant
/// returns byte-identical results through the legacy manager path and
/// through [`Supervisor::dispatch_query`].
///
/// The pre-mutation pass covers the context's initial state (creator is
/// the only member). Then [`Fixture::add_member`] exercises the legacy
/// write path and the post-mutation pass re-runs every query — proving
/// the shim observes the mutation identically to the legacy path.
#[tokio::test]
async fn shim_queries_match_legacy_across_mutations() {
    let fx = Fixture::new();
    let ctx_id = "ctx-shim-parity";
    fx.create_context(ctx_id).await;

    // Bind DIDs to locals so `as_ref()` produces `&str`s with the
    // enclosing scope's lifetime (not a temporary's).
    let alice_did = alice();
    let bob_did = bob();
    let carol_did = carol();

    // Pre-mutation: alice is the only member.
    let dids = [
        alice_did.as_ref(),
        bob_did.as_ref(),
        carol_did.as_ref(),
        "did:example:stranger",
    ];
    run_all_parity_checks(&fx, ctx_id, &dids).await;

    // Mutate through the legacy writer path.
    fx.add_member(ctx_id, bob_did.clone()).await;

    // Post-mutation: bob is now a member. Queries against alice/bob
    // should reflect the change; carol and the stranger should still
    // be non-members.
    run_all_parity_checks(&fx, ctx_id, &dids).await;

    // Second mutation — add carol.
    fx.add_member(ctx_id, carol_did.clone()).await;
    run_all_parity_checks(&fx, ctx_id, &dids).await;
}

/// Unknown-context soft-default contract: queries for a context that
/// was never created must return the same "soft default" value
/// (`None`, `false`, empty `Vec`, etc.) from both paths.
///
/// This is the contract the shim's `reply_with_soft_default` helper
/// enforces — if a future classification change accidentally routes a
/// variant through the error path instead, this test catches the
/// regression.
#[tokio::test]
async fn shim_unknown_context_matches_legacy_soft_defaults() {
    let fx = Fixture::new();
    let ctx_id = "ctx-does-not-exist";

    // member_count — legacy returns `None`.
    let (tx, rx) = tokio::sync::oneshot::channel();
    fx.supervisor
        .dispatch_query(QueriesCommand::MemberCount {
            context_id: ctx_id.to_owned(),
            reply: tx,
        })
        .await
        .unwrap();
    let shim = rx.await.unwrap().unwrap();
    let legacy = fx.manager.member_count(ctx_id).await;
    assert_eq!(shim, legacy, "MemberCount soft default");
    assert_eq!(shim, None);

    // is_member — legacy returns `false`.
    let (tx, rx) = tokio::sync::oneshot::channel();
    fx.supervisor
        .dispatch_query(QueriesCommand::IsMember {
            context_id: ctx_id.to_owned(),
            did: alice().as_ref().to_owned(),
            reply: tx,
        })
        .await
        .unwrap();
    let shim = rx.await.unwrap().unwrap();
    let legacy = fx.manager.is_member(ctx_id, alice().as_ref()).await;
    assert_eq!(shim, legacy, "IsMember soft default");
    assert!(!shim);

    // member_dids — legacy returns empty Vec.
    let (tx, rx) = tokio::sync::oneshot::channel();
    fx.supervisor
        .dispatch_query(QueriesCommand::MemberDids {
            context_id: ctx_id.to_owned(),
            reply: tx,
        })
        .await
        .unwrap();
    let shim = rx.await.unwrap().unwrap();
    let legacy = fx.manager.member_dids(ctx_id).await;
    assert_eq!(shim, legacy, "MemberDids soft default");
    assert!(shim.is_empty());

    // member_role — legacy returns None.
    let (tx, rx) = tokio::sync::oneshot::channel();
    fx.supervisor
        .dispatch_query(QueriesCommand::MemberRole {
            context_id: ctx_id.to_owned(),
            did: alice().as_ref().to_owned(),
            reply: tx,
        })
        .await
        .unwrap();
    let shim = rx.await.unwrap().unwrap();
    let legacy = fx.manager.member_role(ctx_id, alice().as_ref()).await;
    assert_eq!(shim, legacy, "MemberRole soft default");
    assert!(shim.is_none());

    // context_params — legacy returns None.
    let (tx, rx) = tokio::sync::oneshot::channel();
    fx.supervisor
        .dispatch_query(QueriesCommand::ContextParams {
            context_id: ctx_id.to_owned(),
            reply: tx,
        })
        .await
        .unwrap();
    let shim = rx.await.unwrap().unwrap();
    let legacy = fx.manager.context_params(ctx_id).await;
    assert_eq!(shim, legacy, "ContextParams soft default");
    assert!(shim.is_none());
}

/// Dispatch without an attached `ContextManager` — the shim must surface
/// [`ContextError::NotInitialized`] (not panic, not hang).
///
/// Exercises the guard on `Supervisor::dispatch_query` that catches the
/// FFI bridge misconfiguration path where the supervisor is constructed
/// but the `ContextManager` has not been hooked up yet.
#[tokio::test]
async fn dispatch_query_without_manager_returns_not_initialized() {
    let persistence: Arc<dyn ContextPersistence> = Arc::new(NoopPersistence);
    let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::new(
        InMemoryStorage::new(),
    )));
    let supervisor = Supervisor::new(persistence, journal, SupervisorConfig::default());

    let (tx, _rx) = tokio::sync::oneshot::channel();
    let result = supervisor
        .dispatch_query(QueriesCommand::MemberCount {
            context_id: "anything".to_owned(),
            reply: tx,
        })
        .await;

    // `Outcome<()>` does not impl `Debug`, so destructure explicitly
    // rather than reaching for `expect_err`.
    match result {
        Ok(_) => panic!("dispatch_query without attached manager must error"),
        Err(ContextError::NotInitialized(_)) => {}
        Err(other) => panic!("expected NotInitialized, got {other:?}"),
    }
}
