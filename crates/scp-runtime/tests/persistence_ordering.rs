//! ADR-049 §9 persistence-ORDERING verification (`persistence_ordering`).
//!
//! ADR-049 (`.docs/adrs/ADR-049-actor-per-context.md`) names this test in its
//! `## Verification` executable-checks list. It pins the §9
//! *"never ack success unless durable"* ordering guarantee for **Class-S**
//! (sync-persisted, security-critical) state, END-TO-END through the PUBLIC
//! `Supervisor` actor API — the layer the combinator-level unit tests in
//! `class_s.rs` do not exercise.
//!
//! ## What §9 requires (the invariant under test)
//!
//! > For Class-S state, a persist FAILURE must FAIL-CLOSED (the operation
//! > returns an error) — never best-effort-swallow that returns `Ok`.
//! > [Class-S state is] durably persisted synchronously BEFORE the mutating
//! > operation returns success.
//!
//! Concretely, the durable write is a *precondition* of acknowledging success.
//! That is a two-directional claim, and each direction needs its own case:
//!
//! 1. **ack ⟹ durable** (`class_s_mutation_commits_durably_before_acking_success`):
//!    a Class-S mutation that returns `Ok` has ALREADY committed to the
//!    persistence backend. Because `ContextPersistence::persist_context` is
//!    awaited on the ack path before the handler replies, observing `Ok` proves
//!    the durable snapshot already reflects the mutation.
//! 2. **¬durable ⟹ ¬ack** (`class_s_mutation_persist_failure_fails_closed_and_withholds_durable_commit`):
//!    if the durable write FAILS, the operation returns `Err` (fail-closed) and
//!    the mutation is NOT observable as committed in the backend. Success is
//!    withheld precisely because durability was not achieved.
//!
//! Neither direction alone is the guarantee: case 2 in isolation only says
//! "a failing write fails," and case 1 in isolation only says "a good write
//! commits." Together they pin the ORDERING — durability gates the ack.
//!
//! ## Why this is not a duplicate
//!
//! - The `class_s.rs` unit tests (`commit_keeps_mutation_and_surfaces_error_on_persist_failure`,
//!   `keep_retains_mutation_on_persist_failure`, `restore_rolls_back_class_s_on_persist_failure`,
//!   …) exercise the persist-on-commit COMBINATORS in ISOLATION against a hand-built
//!   `ClassSCell` + fault-injected `ActorDeps`. They prove each combinator's
//!   fail-closed contract, but not that a real governance operation dispatched
//!   through the public `Supervisor` mailbox surfaces that `Err` all the way to the
//!   caller and withholds the durable commit. This file exercises the whole
//!   dispatch path (`Supervisor::propose_governance_action` →
//!   actor → `dispatch_governance_action` → `execute_suspend_member` →
//!   `commit_class_s_keep`), which the unit tests cannot reach.
//! - `security_critical_state_is_class_s_or_m_not_coalesced` (also in `class_s.rs`)
//!   is the FIELD-round-trip property — it proves every Class-S field SURVIVES a
//!   snapshot round-trip. It says nothing about the temporal ORDERING of the
//!   durable write relative to the caller ack. This file is the ORDERING
//!   complement, not a re-run of the round-trip.
//!
//! The Class-S mutation exercised is member capability suspension
//! (`GovernanceAction::SuspendCapability` → `execute_suspend_member`), a §9
//! downward-authorization arm that persists **fail-closed** via
//! `commit_class_s_keep`.

// Gated on `testing`: the test drives `Supervisor::test_insert_member` and
// `Supervisor::propose_governance_action`, both `#[cfg(feature = "testing")]`.
// Gated via the Cargo.toml `[[test]] required-features = ["testing"]` entry
// (matching every sibling gated integration test), so the mandated
// `cargo test -p scp-runtime --test persistence_ordering --features testing`
// runs the cases and a bare `cargo test` skips the target with a visible note.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::disallowed_types,
    clippy::doc_markdown
)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use scp_did::DID;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::governance::{GovernanceAction, KeyResolver};
use scp_protocol::context::params::{Capability, ContextParams, GovernanceModel};
use scp_protocol::context::{ContextError, ContextState};
use scp_runtime::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use scp_runtime::context::persistence::ContextPersistence;
use scp_runtime::context::state::ContextSnapshot;
use scp_runtime::context::supervisor::Supervisor;
use scp_runtime::crypto::mls::provider::MlsCryptoProvider;

// ---------------------------------------------------------------------------
// RecordingPersistence — the fail-on-demand persistence fixture.
// ---------------------------------------------------------------------------

/// A `ContextPersistence` that records the last durably-COMMITTED snapshot per
/// context and can be armed to FAIL every `persist_context` write on demand.
///
/// - `store` holds only snapshots whose write SUCCEEDED — a durable commit.
///   A failed (armed) `persist_context` leaves `store` untouched, mirroring a
///   real backend where a rejected write commits nothing.
/// - `fail` is the arming toggle. When set, `persist_context` returns `Err`
///   WITHOUT committing.
/// - `persist_attempts` counts every `persist_context` CALL (committed or
///   rejected), so a test can prove the handler actually reached the
///   fail-closed persist on the ack path rather than skipping it.
///
/// State lives behind `Arc` so a `clone()` handed to the `Supervisor` and the
/// clone the test retains share one backend. Reads (`load_context`) serve
/// whatever was last committed, so restore paths behave like a durable backend
/// that retains committed state across a failed write.
#[derive(Clone, Default)]
struct RecordingPersistence {
    store: Arc<Mutex<HashMap<String, ContextSnapshot>>>,
    fail: Arc<AtomicBool>,
    persist_attempts: Arc<AtomicUsize>,
}

impl RecordingPersistence {
    fn arm_failure(&self) {
        self.fail.store(true, Ordering::SeqCst);
    }

    /// The last DURABLY-COMMITTED snapshot for `context_id`, if any.
    fn committed(&self, context_id: &str) -> Option<ContextSnapshot> {
        self.store.lock().unwrap().get(context_id).cloned()
    }

    fn attempts(&self) -> usize {
        self.persist_attempts.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl ContextPersistence for RecordingPersistence {
    async fn persist_context(
        &self,
        context_id: &str,
        snapshot: &ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.persist_attempts.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err("injected persist fault (persistence_ordering fixture)".into());
        }
        self.store
            .lock()
            .unwrap()
            .insert(context_id.to_owned(), snapshot.clone());
        Ok(())
    }

    async fn load_context(
        &self,
        context_id: &str,
    ) -> Result<Option<ContextSnapshot>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.store.lock().unwrap().get(context_id).cloned())
    }

    async fn delete_context(
        &self,
        context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.store.lock().unwrap().remove(context_id);
        Ok(())
    }

    async fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.store.lock().unwrap().keys().cloned().collect())
    }
}

// ---------------------------------------------------------------------------
// Mock providers (mirrors governance_integration.rs).
// ---------------------------------------------------------------------------

#[derive(Default)]
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

#[derive(Default)]
struct MockEventLog;

#[async_trait::async_trait]
impl ContextEventLogProvider for MockEventLog {
    async fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn append_event(
        &self,
        _id: &[u8; 32],
        _event: scp_event_log::EventType,
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

// ---------------------------------------------------------------------------
// Key + DID helpers (mirrors governance_integration.rs).
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
    Arc::new(|did, _kid: scp_did::SigningKeyId| {
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

/// Ceiling carrying the capabilities the suspension flow needs: `MemberBan`
/// (authorizes the downward-auth suspension) and `GovernanceVote` (the
/// capability that gets suspended off `bob`).
fn suspension_ceiling() -> Vec<Capability> {
    vec![
        Capability::new("messages:read").expect("known capability"),
        Capability::new("messages:write").expect("known capability"),
        Capability::new("governance:propose").expect("known capability"),
        Capability::GovernanceVote,
        Capability::MemberBan,
    ]
}

/// Builds a `Supervisor` wired to `persistence`, mirroring
/// `scp_runtime::context::test_supervisor` but injecting the caller's
/// persistence provider (which `test_supervisor` hardcodes to `None`).
fn build_supervisor(persistence: RecordingPersistence) -> Arc<Supervisor> {
    let mls_storage: Arc<dyn scp_runtime::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
        Arc::new(
            scp_runtime::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                scp_platform::testing::InMemoryStorage::new(),
            )),
        );
    Supervisor::with_providers(
        Arc::new(MlsCryptoProvider::new(
            "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_owned(),
            Arc::new(scp_clock::SystemClock),
        )),
        Box::new(MockTransport),
        Box::new(MockEventLog),
        mock_key_resolver(),
        Some(Box::new(persistence)),
        None,
        None,
        None,
        mls_storage,
    )
}

/// Creates a SingleAdmin context with `alice` as admin and inserts `bob` as a
/// plain member, so a later `SuspendCapability { did: bob, .. }` has a target.
/// Returns once both durable commits (create + member insert) have landed.
async fn setup_context_with_member(supervisor: &Arc<Supervisor>, ctx_id: &str) {
    let params = ContextParams {
        ceiling: suspension_ceiling(),
        governance: GovernanceModel::SingleAdmin,
        ..ContextParams::default()
    };
    let handle = supervisor
        .create_context(ctx_id.into(), params, alice(), None)
        .await
        .expect("create_context should succeed while persistence is healthy");
    assert_eq!(handle.state(), ContextState::Active);

    supervisor
        .test_insert_member(ctx_id, bob(), "member")
        .await
        .expect("test_insert_member should succeed while persistence is healthy");
}

/// The Class-S mutation under test: suspend `bob`'s `GovernanceVote` capability
/// via a SingleAdmin governance proposal (auto-approves + auto-executes).
async fn suspend_bob_governance_vote(
    supervisor: &Arc<Supervisor>,
    ctx_id: &str,
) -> Result<(), ContextError> {
    let sk = signing_key_for_did(&alice());
    let action = GovernanceAction::SuspendCapability {
        did: bob(),
        capabilities: vec![Capability::GovernanceVote],
    };
    supervisor
        .propose_governance_action(ctx_id, &alice(), action, &sk)
        .await
        .map(|_| ())
}

// ---------------------------------------------------------------------------
// Case 1: ack ⟹ durable. A Class-S mutation that acks success has already
// committed the mutation to the persistence backend.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn class_s_mutation_commits_durably_before_acking_success() {
    let persistence = RecordingPersistence::default();
    let supervisor = build_supervisor(persistence.clone());
    let ctx_id = "ctx-persist-ordering-positive";

    setup_context_with_member(&supervisor, ctx_id).await;

    // Baseline: the durable snapshot does NOT yet show bob suspended.
    let before = persistence
        .committed(ctx_id)
        .expect("create + insert must have committed a durable snapshot");
    assert!(
        before.role_state.suspended_for(bob().as_ref()).is_none(),
        "precondition: bob must not be suspended in the durable snapshot before the op"
    );

    // The Class-S mutation, with persistence HEALTHY.
    suspend_bob_governance_vote(&supervisor, ctx_id)
        .await
        .expect("suspension must succeed while persistence is healthy");

    // ORDERING: because the op returned Ok, the fail-closed persist awaited on
    // its ack path has ALREADY committed the suspension to the backend.
    let after = persistence
        .committed(ctx_id)
        .expect("a committed snapshot must exist after a successful Class-S mutation");
    let suspended = after
        .role_state
        .suspended_for(bob().as_ref())
        .expect("the durable snapshot backing the ack must record bob's suspension");
    assert!(
        suspended.contains(&Capability::GovernanceVote),
        "the durable snapshot must carry the exact suspended capability (GovernanceVote), got {suspended:?}"
    );
}

// ---------------------------------------------------------------------------
// Case 2: ¬durable ⟹ ¬ack. When the fail-closed persist FAILS, the operation
// returns Err and the mutation is NOT observable as durably committed.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn class_s_mutation_persist_failure_fails_closed_and_withholds_durable_commit() {
    let persistence = RecordingPersistence::default();
    let supervisor = build_supervisor(persistence.clone());
    let ctx_id = "ctx-persist-ordering-failclosed";

    setup_context_with_member(&supervisor, ctx_id).await;

    // Snapshot the durable state (bob not suspended) and the attempt count
    // right before arming the fault.
    let durable_before = persistence
        .committed(ctx_id)
        .expect("create + insert must have committed a durable snapshot");
    assert!(
        durable_before
            .role_state
            .suspended_for(bob().as_ref())
            .is_none(),
        "precondition: bob must not be suspended in the durable snapshot before the op"
    );
    let attempts_before = persistence.attempts();

    // Arm the backend to reject every subsequent write.
    persistence.arm_failure();

    // The Class-S mutation now cannot achieve durability.
    let result = suspend_bob_governance_vote(&supervisor, ctx_id).await;

    // FAIL-CLOSED: the operation returns Err — success is NOT acked when the
    // durable write fails. §9: "a persist FAILURE must FAIL-CLOSED ... never
    // best-effort-swallow that returns Ok."
    match result {
        Err(ContextError::PersistenceFailed(_)) => {}
        other => panic!(
            "Class-S suspension must FAIL-CLOSED with PersistenceFailed when the fail-closed \
             persist fails; got {other:?}"
        ),
    }

    // The handler actually REACHED the fail-closed persist on the ack path
    // (rather than short-circuiting before it): at least one persist was
    // attempted after arming the fault.
    assert!(
        persistence.attempts() > attempts_before,
        "the operation must have ATTEMPTED the fail-closed persist (attempts must increase): \
         before={attempts_before}, after={}",
        persistence.attempts()
    );

    // NOT OBSERVABLE AS COMMITTED: the durable backend holds no committed
    // snapshot recording bob's suspension — the last durable commit is
    // unchanged from before the op. The in-memory mutation may persist
    // (keep-direction), but it was NEVER acknowledged as durable, so a respawn
    // from the durable snapshot would not see it.
    let durable_after = persistence
        .committed(ctx_id)
        .expect("the pre-op committed snapshot must still be the durable state");
    assert!(
        durable_after
            .role_state
            .suspended_for(bob().as_ref())
            .is_none(),
        "the failed Class-S mutation must NOT be observable as durably committed: \
         no committed snapshot may record bob's suspension"
    );
}
