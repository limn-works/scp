//! Tests moved out of `scp-runtime-core` `context::actor::class_s` (ADR-070 §6.2): they build a
//! `Supervisor`, which needs the domain handlers only `scp-runtime` assembles.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use scp_did::DID;
use scp_platform::in_memory::InMemoryStorage;
use scp_protocol::context::ContextError;
use scp_protocol::context::roles::CapabilityCeiling;
use scp_protocol::economy::types::EconomicPolicy;
use scp_runtime_core::context::actor::class_s::AppendOutcomeError;
use scp_runtime_core::context::actor::class_s::*;
use scp_runtime_core::context::actor::deps::ActorDeps;
use scp_runtime_core::context::actor::state::PerContextState;
use scp_runtime_core::context::persistence::ContextPersistence;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Minimal event log provider — accepts every call (the combinator paths do
/// not touch the event log).
struct TestEventLog;
#[async_trait::async_trait]
impl scp_runtime_core::context::builder::ContextEventLogProvider for TestEventLog {
    fn event_log_entries(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<Option<Vec<scp_event_log::Event>>, scp_protocol::context::ContextError> {
        Ok(None)
    }

    async fn init_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    async fn append_event(
        &self,
        _id: &[u8; 32],
        _event_type: scp_event_log::EventType,
        _actor: &str,
        _payload: scp_event_log::EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    async fn destroy_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
}

/// Persistence SPY: accepts every write but counts `persist_context` calls,
/// so a test can assert a combinator actually performed its persist.
struct SpyPersistence {
    persist_calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl ContextPersistence for SpyPersistence {
    async fn persist_context(
        &self,
        _: &str,
        _: &scp_runtime_core::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.persist_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn load_context(
        &self,
        _: &str,
    ) -> Result<
        Option<scp_runtime_core::context::state::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(None)
    }
    async fn delete_context(
        &self,
        _: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    async fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Vec::new())
    }
}

/// Persistence that SUCCEEDS the first `persist_context` call then FAILS
/// every subsequent one — lets `then_append` exercise "post-f persist OK,
/// rollback re-persist FAILS" (the hard-divergence `durability_diverged ==
/// true` path).
struct SucceedThenFail {
    calls: Arc<AtomicUsize>,
}
#[async_trait::async_trait]
impl ContextPersistence for SucceedThenFail {
    async fn persist_context(
        &self,
        _: &str,
        _: &scp_runtime_core::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            Ok(())
        } else {
            Err("re-persist failure".into())
        }
    }
    async fn load_context(
        &self,
        _: &str,
    ) -> Result<
        Option<scp_runtime_core::context::state::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(None)
    }
    async fn delete_context(
        &self,
        _: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    async fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Vec::new())
    }
}

/// Assemble an `ActorDeps` with the supplied persistence backend (and the
/// minimal `TestEventLog`, whose entry reads are empty).
async fn build_deps(persistence: Box<dyn ContextPersistence>) -> ActorDeps {
    build_deps_with_event_log(persistence, Box::new(TestEventLog)).await
}

/// Assemble an `ActorDeps` with the supplied persistence backend AND a custom
/// event-log provider — used by the paid-send-with-suspension test, which seeds
/// a `GovernanceAction` into a real [`MerkleEventLogProvider`] so the
/// consequence engine reads convergent `WarningCount` evidence (Source 1 of
/// `event_log_entries_for_consequences`; the receive buffer never sources
/// governance events).
async fn build_deps_with_event_log(
    persistence: Box<dyn ContextPersistence>,
    event_log: Box<dyn scp_runtime_core::context::builder::ContextEventLogProvider>,
) -> ActorDeps {
    use scp_runtime_core::context::supervisor::supervisor::Supervisor;

    let crypto = Arc::new(
        scp_runtime_core::crypto::mls::provider::NodeMlsFactory::new(
            "did:dht:z6MktestClassSCell".to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        ),
    );
    let transport: Box<dyn scp_runtime_core::context::builder::ContextTransportProvider> =
        Box::new(scp_runtime_core::context::builder::NotConfiguredTransportProvider);
    let key_resolver: scp_protocol::context::governance::KeyResolver = Arc::new(|_, _| None);
    let mls_storage: Arc<
        dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter,
    > = Arc::new(
        scp_runtime_types::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(
            Arc::new(InMemoryStorage::new()),
        ),
    );
    let supervisor = Supervisor::with_providers(
        crypto,
        transport,
        event_log,
        key_resolver,
        Some(persistence),
        None,
        None,
        None,
        mls_storage,
        scp_runtime::domain_handlers(),
    );
    scp_runtime_core::context::supervisor::supervisor::leak_for_test(&supervisor);
    supervisor
        .build_actor_deps_loaded(&DID("did:example:class-s-cell-test".to_owned()))
        .await
        .expect("build_actor_deps")
}

/// A fresh encrypted test state.
fn fresh_state(ctx_byte: u8) -> PerContextState {
    PerContextState::new_for_test_encrypted(
        [ctx_byte; 32],
        1_700_000_000,
        DID("did:example:admin".to_owned()),
    )
}

/// Like [`fresh_state`] but seeds the role-state ceiling via the sanctioned
/// [`scp_protocol::context::roles::ContextRoleState::set_ceiling`] mutator.
/// Mint-time ceiling enforcement (spec §7.2.1 step 8) now runs on the system
/// path, so fixtures that seed role definitions must seat a ceiling that
/// contains the capabilities those roles grant.
fn fresh_state_with_ceiling(
    ctx_byte: u8,
    caps: impl IntoIterator<Item = scp_protocol::context::roles::Capability>,
) -> PerContextState {
    let mut state = fresh_state(ctx_byte);
    state
        .role_state
        .set_ceiling(scp_protocol::context::roles::CapabilityCeiling::new(caps))
        .expect("well-formed test ceiling");
    state
}

fn ctx_hex(byte: u8) -> String {
    let mut s = String::with_capacity(64);
    for _ in 0..32 {
        use std::fmt::Write;
        let _ = write!(s, "{byte:02x}");
    }
    s
}

fn saga(id: &str) -> scp_runtime_types::context::supervisor::saga_journal::SagaId {
    scp_runtime_types::context::supervisor::saga_journal::SagaId(id.to_owned())
}

/// Build a `CrossContextOutletInvocation` prepared-state for `saga_pending`.
fn prepared_invocation()
-> scp_runtime_core::context::supervisor::saga_prepared_state::SagaPreparedState {
    use scp_runtime_core::context::supervisor::saga_prepared_state::{
        CrossContextOutletInvocationPrepared, SagaPreparedState,
    };
    SagaPreparedState::CrossContextOutletInvocation(CrossContextOutletInvocationPrepared {
        caller_context_id: [0x1Au8; 32],
        target_context_id: [0x2Bu8; 32],
        caller_did: DID("did:example:caller".to_owned()),
        outlet_registration_id: "outlet-v1".to_owned(),
        ucan_proof_id: "ucan-1".to_owned(),
        recorded_timestamp_ms: 1_700_000_000_123,
        recorded_nonce: [0x3Cu8; 16],
        recorded_chain_depth: 1,
    })
}

/// Seed a straggler caller-reservation into the Class-S
/// `xctx_caller_reservations` map through the sanctioned fail-closed
/// combinator (the SAME path production `prepare_a` uses), so the
/// `clear_committed_reservation_idempotent` straggler-cleanup path can be
/// exercised on a pre-seeded reservation WITHOUT the `state_mut()` escape
/// hatch. Returns nothing; panics if the seed persist does not land.
async fn seed_caller_reservation_for_test(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    saga_id: scp_runtime_types::context::supervisor::saga_journal::SagaId,
    record: scp_runtime_core::context::supervisor::saga_prepared_state::CallerReservationRecord,
) {
    cell.commit_class_s_restore(deps, context_id, |mut view| {
        view.class_s_mut()
            .xctx_caller_reservations
            .insert(saga_id, record);
        Ok::<(), ContextError>(())
    })
    .await
    .expect("seed caller reservation persists");
}

// ------------------------------------------------------------------
// begin_class_s / begin_class_s_conditional + ClassSCommitToken
// ------------------------------------------------------------------

/// `begin_class_s` runs the early mutation, issues a token, and does NOT
/// persist; the deferred `commit` performs exactly one fail-closed persist.
#[tokio::test]
async fn begin_class_s_defers_persist_until_commit() {
    let persist_calls = Arc::new(AtomicUsize::new(0));
    let deps = build_deps(Box::new(SpyPersistence {
        persist_calls: Arc::clone(&persist_calls),
    }))
    .await;
    let mut cell = ClassSCell::new(fresh_state(0x61));
    let ctx = ctx_hex(0x61);

    let (value, token) = cell
        .begin_class_s(&ctx, |mut view| {
            view.class_s_mut().xctx_nonce_dedup.record([0x6Au8; 16], 0);
            Ok("early")
        })
        .expect("f Ok ⇒ (value, token)");
    assert_eq!(value, "early");
    assert_eq!(
        persist_calls.load(Ordering::SeqCst),
        0,
        "begin_class_s must NOT persist"
    );
    assert!(
        cell.class_s
            .xctx_nonce_dedup
            .entries()
            .contains_key(&[0x6Au8; 16]),
        "early mutation applied in memory"
    );

    // The deferred commit persists fail-closed (exactly once).
    token
        .commit(&cell, &deps, &ctx)
        .await
        .expect("commit persists fail-closed ⇒ Ok");
    assert_eq!(
        persist_calls.load(Ordering::SeqCst),
        1,
        "commit performs the single deferred persist"
    );
}

/// `begin_class_s` issues NO token when `f` errs — a rejected operation
/// staged no consume to discharge.
#[tokio::test]
async fn begin_class_s_issues_no_token_on_f_error() {
    let persist_calls = Arc::new(AtomicUsize::new(0));
    let deps = build_deps(Box::new(SpyPersistence {
        persist_calls: Arc::clone(&persist_calls),
    }))
    .await;
    let mut cell = ClassSCell::new(fresh_state(0x62));
    let ctx = ctx_hex(0x62);

    let result: Result<((), ClassSCommitToken), ContextError> = cell.begin_class_s(&ctx, |_view| {
        Err(ContextError::PermissionDenied("no".into()))
    });
    assert!(matches!(result, Err(ContextError::PermissionDenied(_))));
    assert_eq!(
        persist_calls.load(Ordering::SeqCst),
        0,
        "no persist on f-error (no token issued, so nothing to drop unconsumed)"
    );
    // Note: `result` is `Err`, so no token exists — no Drop obligation.
    drop(deps);
}

/// The token's `commit` KEEPS the Class-S mutation on persist failure
/// (keep-direction) and surfaces the persist error.
#[tokio::test]
async fn commit_keeps_mutation_and_surfaces_error_on_persist_failure() {
    let deps = build_deps(Box::new(FailPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x63));
    let ctx = ctx_hex(0x63);

    let (_v, token) = cell
        .begin_class_s(&ctx, |mut view| {
            view.class_s_mut().xctx_nonce_dedup.record([0x6Bu8; 16], 0);
            Ok(())
        })
        .expect("f Ok");
    let err = token
        .commit(&cell, &deps, &ctx)
        .await
        .expect_err("FailPersistence ⇒ commit Err");
    assert!(matches!(err, ContextError::PersistenceFailed(_)));
    assert!(
        cell.class_s
            .xctx_nonce_dedup
            .entries()
            .contains_key(&[0x6Bu8; 16]),
        "keep-direction: consume retained on persist failure"
    );
}

/// `begin_class_s_conditional` issues a token only when `f` reports a
/// mutation happened (`true`).
#[tokio::test]
async fn conditional_issues_token_only_when_mutation_happened() {
    let deps = build_deps(Box::new(OkPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x64));
    let ctx = ctx_hex(0x64);

    // Mutation happened ⇒ Some(token).
    let (v, token) = cell
        .begin_class_s_conditional(&ctx, |mut view| {
            view.class_s_mut().xctx_nonce_dedup.record([0x6Cu8; 16], 0);
            Ok((1u8, true))
        })
        .expect("Ok");
    assert_eq!(v, 1);
    let token = token.expect("did_mutate=true ⇒ Some(token)");
    token.commit(&cell, &deps, &ctx).await.expect("commit Ok");

    // No mutation ⇒ None (free/best-effort path stays token-free).
    let (v2, token2) = cell
        .begin_class_s_conditional(&ctx, |_view| Ok((2u8, false)))
        .expect("Ok");
    assert_eq!(v2, 2);
    assert!(
        token2.is_none(),
        "did_mutate=false ⇒ None (no deferred fail-closed obligation)"
    );
}

/// ADR-049 §9 (RED-CS3) — `note_downward_auth` is IDEMPOTENT and a NO-OP when
/// no GROW occurred: a consequence cascade owes EXACTLY ONE fail-closed persist
/// regardless of how many downward-auth GROWs it applies (the single
/// cell-boundary `commit` makes the whole in-memory state durable), and a
/// cascade that applied no GROW arms no obligation at all (the hot path stays
/// coalesced).
///
/// This drives the central sink invariant directly on the constructor the GROW
/// methods funnel through, so it is covered independently of any one GROW
/// caller:
/// - Two successive `note_downward_auth(&mut sink, true, ctx)` calls leave
///   EXACTLY ONE token. The first arms the sink (`is_none() → is_some()`); the
///   second is a no-op because `sink.is_some()` — it does NOT replace or stack a
///   second obligation. We confirm exactly-one by discharging the single armed
///   token through the real fail-closed `commit` under a `SpyPersistence` and
///   asserting the spy saw EXACTLY ONE persist (a duplicated/stacked obligation
///   would surface as a leaked second token tripping the `Drop` guard, or, were
///   it committed too, a second persist).
/// - `note_downward_auth(&mut sink, false, ctx)` against a `None` sink is a
///   no-op: `sink.is_none()` stays true, no token is armed, nothing to discharge.
#[tokio::test]
async fn note_downward_auth_is_idempotent_and_noops_without_grow() {
    let persist_calls = Arc::new(AtomicUsize::new(0));
    let deps = build_deps(Box::new(SpyPersistence {
        persist_calls: Arc::clone(&persist_calls),
    }))
    .await;
    let cell = ClassSCell::new(fresh_state(0x69));
    let ctx = ctx_hex(0x69);

    // No GROW (did_grow == false) against an empty sink: stays empty, arms
    // nothing — the coalesced persist suffices, no fail-closed obligation owed.
    let mut sink: Option<ClassSCommitToken> = None;
    ClassSCommitToken::note_downward_auth(&mut sink, false, &ctx);
    assert!(
        sink.is_none(),
        "no GROW must arm no obligation (hot path stays coalesced)"
    );

    // First GROW arms the single obligation.
    ClassSCommitToken::note_downward_auth(&mut sink, true, &ctx);
    assert!(
        sink.is_some(),
        "the first downward-auth GROW arms the fail-closed obligation sink"
    );

    // Second GROW in the SAME cascade is a no-op (`sink.is_some()`): one cascade
    // owes one persist, so the existing token is reused, not duplicated.
    ClassSCommitToken::note_downward_auth(&mut sink, true, &ctx);
    assert!(
        sink.is_some(),
        "a second GROW in the same cascade reuses the armed token (idempotent)"
    );

    // A later `false` call must not clear or replace the armed obligation either.
    ClassSCommitToken::note_downward_auth(&mut sink, false, &ctx);

    // EXACTLY ONE owed persist: discharge the single token and confirm the spy
    // saw exactly one fail-closed persist. (A stacked second obligation would
    // either leak a token — tripping the `Drop` guard at end of scope — or, if
    // also committed, bump this count past one.)
    let token = sink
        .take()
        .expect("the cascade armed exactly one obligation");
    token
        .commit(&cell, &deps, &ctx)
        .await
        .expect("the single armed obligation commits fail-closed (SpyPersistence Ok)");
    assert_eq!(
        persist_calls.load(Ordering::SeqCst),
        1,
        "a coalesced cascade owes EXACTLY ONE fail-closed persist, no double-arm"
    );
    assert!(
        sink.is_none(),
        "the sink is emptied by `take` — no residual obligation to drop"
    );
}

/// `discharge_with` on the ABORT path — `f` returns `Err` — STILL discharges
/// the Drop obligation (keep-direction: the persist runs regardless of `f`'s
/// result, so the token is consumed). The test would PANIC in the `Drop`
/// `debug_assert!` if `discharge_with` failed to mark the obligation
/// discharged on the error path; reaching the assertions proves the abort path
/// does not leave a leaked token, and that the keep-direction persist still
/// ran (`SpyPersistence` counts exactly one call) while `f`'s error is surfaced.
#[tokio::test]
async fn discharge_with_consumes_token_on_f_error_keep_direction() {
    let persist_calls = Arc::new(AtomicUsize::new(0));
    let deps = build_deps(Box::new(SpyPersistence {
        persist_calls: Arc::clone(&persist_calls),
    }))
    .await;
    let mut cell = ClassSCell::new(fresh_state(0x66));
    let ctx = ctx_hex(0x66);

    let (_v, token) = cell
        .begin_class_s(&ctx, |mut view| {
            view.class_s_mut().xctx_nonce_dedup.record([0x6Eu8; 16], 0);
            Ok(())
        })
        .expect("f Ok ⇒ token");

    // `f` aborts (Err). Keep-direction: the persist still runs and the token
    // is consumed — so no Drop panic, `f`'s error is surfaced.
    let err = token
        .discharge_with(&mut cell, &deps, &ctx, |_view| {
            Err::<(), _>(ContextError::PermissionDenied("abort".into()))
        })
        .await
        .expect_err("f Err ⇒ discharge_with surfaces it");
    assert!(matches!(err, ContextError::PermissionDenied(_)));
    assert_eq!(
        persist_calls.load(Ordering::SeqCst),
        1,
        "keep-direction: the deferred persist runs even on the f-abort path"
    );
    assert!(
        cell.class_s
            .xctx_nonce_dedup
            .entries()
            .contains_key(&[0x6Eu8; 16]),
        "keep-direction: the early consume stays in memory through the abort"
    );
    // `token` was moved into `discharge_with` and consumed — no leaked Drop
    // obligation. (A failure to set `consumed` would have panicked above.)
}

// ------------------------------------------------------------------
// RED-CS3 — consequence-engine auto-suspension is fail-closed
// ------------------------------------------------------------------

/// ADR-049 §9 (RED-CS3) — the consequence-engine capability suspension is
/// persisted FAIL-CLOSED, not silently coalesced. This drives a triggered
/// `SuspendCapability` consequence through the SAME path the receive handler
/// uses — `enforce_triggered_consequences` against the cell's
/// `class_c_view().split_class_c()` — to set the in-memory suspension and the
/// `downward_auth_applied` flag, then performs the handler's fail-closed persist
/// (`persist_state_fail_closed`) under a FAILING persistence backend. It
/// asserts (a) the handler surfaces the §9 durability error
/// (`PersistenceFailed`) rather than a silent coalesced ack, AND (b) the
/// suspension is RETAINED in memory (keep-direction) — so it is NOT lost on a
/// coalesce-window crash and the denied capability is not silently re-granted.
#[tokio::test]
async fn consequence_suspension_persists_fail_closed_and_keeps_suspension() {
    use scp_protocol::context::roles::Capability;
    use scp_protocol::trust::consequence::{
        ConsequenceAction, ConsequenceRule, EnforcementSeverity, TriggeredConsequence,
    };
    use scp_runtime_core::context::shared::governance::EnforceConsequencesCtx;

    let deps = build_deps(Box::new(FailPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x71));
    let ctx = ctx_hex(0x71);
    let subject = DID("did:example:suspend-subject".to_owned());

    // The subject must be a member for enforcement to apply a suspension.
    {
        let mut view = cell.class_c_view();
        view.membership_class_c_mut()
            .add_member(subject.clone(), "member".to_owned(), Vec::new());
    }

    // A `SuspendCapability` consequence (explicit caps) unconditionally
    // mutates `suspended_capabilities` for the present member, so the
    // downward-auth fail-closed flag must be `true`.
    let rules = vec![ConsequenceRule {
        trigger: scp_protocol::trust::consequence::ConsequenceTrigger::WarningCount,
        action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability {
            capabilities: vec![Capability::MessagesWrite],
        }),
        threshold: 1,
        window: std::time::Duration::from_hours(1),
    }];
    let triggered = vec![TriggeredConsequence {
        rule_index: 0,
        action: rules[0].action.clone(),
        evidence: Vec::new(),
    }];

    // Drive the suspension through the handler's exact view path. The GROW
    // method ARMS the obligation sink (coupled to the mutation — GAP-A closed).
    let mut obligation = None;
    let downward_auth_applied = {
        let mut view = cell.class_c_view();
        let mut split = view.consequence_split();
        scp_runtime::domain_handlers()
            .governance
            .enforce_triggered_consequences(
                &mut split,
                &EnforceConsequencesCtx {
                    context_id: &ctx,
                    member_did: &subject,
                    now: 1_700_000_100,
                    triggered: &triggered,
                    rules: &rules,
                    clock: deps.clock.as_ref(),
                    event_log: deps.event_log.as_ref(),
                    event_tx: None,
                },
                &mut obligation,
            )
            .await
    };
    assert!(
        downward_auth_applied,
        "a SuspendCapability against a present member applies a downward-auth \
             suspension and must signal the fail-closed flag (RED-CS3)"
    );
    let token = obligation
        .take()
        .expect("the SuspendCapability GROW arms the fail-closed obligation sink");
    assert!(
        cell.role_state
            .suspended_for(subject.as_ref())
            .is_some_and(|caps| caps.contains(&Capability::MessagesWrite)),
        "the suspension is applied in memory before the persist"
    );

    // Discharging the armed obligation IS the §9 fail-closed persist. Under
    // FailPersistence it must surface the durability error (not a silent ack).
    let persist = token.commit(&cell, &deps, &ctx).await;
    let err = persist.expect_err("FailPersistence ⇒ fail-closed persist Err");
    assert!(
        matches!(err, ContextError::PersistenceFailed(_)),
        "the §9 durability error must surface (not a silent coalesced ack): {err:?}"
    );

    // KEEP-direction: the suspension is RETAINED in memory after the failed
    // persist — it is not silently lost on a coalesce-window crash.
    assert!(
        cell.role_state
            .suspended_for(subject.as_ref())
            .is_some_and(|caps| caps.contains(&Capability::MessagesWrite)),
        "keep-direction: the auto-suspension stays in memory through a persist \
             failure, so the denied capability is not silently re-granted (RED-CS3)"
    );
}

/// ADR-049 §9 (RED-CS3) — a PAID send (one that burns a spending nonce, minting
/// the deferred nonce [`ClassSCommitToken`]) that ALSO trips a downward-auth
/// consequence suspension persists the WHOLE Class-S state — the burned nonce
/// AND the new suspension — under EXACTLY ONE fail-closed persist, and that
/// persist is fail-closed (not a silent coalesced ack).
///
/// This drives the PRODUCTION `finalize_send` end-to-end on the paid branch,
/// exercising the seam Item 2 targets:
/// - `finalize_send` evaluates this send's consequence rules. A
///   `SuspendCapability` `WarningCount` rule against the sender (seeded as a
///   `GovernanceAction` leaf in a real [`MerkleEventLogProvider`] — the
///   convergent Source-1 evidence the receive buffer never supplies) fires and
///   ARMS the `downward_auth_sink` from inside the GROW (GAP-A coupled).
/// - The reconcile match (`(downward_auth_sink, token.is_some())`) sees the PAID
///   token, so it `subsume`s the redundant sink token (consuming it WITHOUT a
///   second persist — NOT a drop, NOT a `mem::forget`) and threads `None` as the
///   separate obligation into `persist_finalized_send`.
/// - `persist_finalized_send`'s paid arm then commits the SINGLE nonce token
///   fail-closed: under `FailPersistence` it surfaces `PersistenceFailed` rather
///   than acking silently, and the suspension stays applied in memory
///   (keep-direction).
///
/// The single nonce `commit` is the ONLY persist owed: the paid branch mints no
/// second obligation, and the `subsume` discharges the redundant armed sink — so
/// no double-commit and no lost obligation. (A leaked sink token would trip the
/// `Drop` guard inside `finalize_send`; reaching the `PersistenceFailed`
/// assertion proves the reconcile consumed it cleanly.)
///
/// END-TO-END SCOPE: this drives the real `finalize_send` → consequence
/// enforcement → GROW-arming → reconcile/`subsume` → paid-branch fail-closed
/// `commit`. The ONE element it does not drive through production wiring is the
/// nonce BURN itself: minting the deferred nonce token directly
/// (`ClassSCommitToken::new_for_test`) is exactly how the existing production
/// `finalize_send` send-path tests model a paid send (the burn lives upstream in
/// `enforce_send_economy`, a separate seam with its own coverage), so the paid
/// branch is exercised with a faithful stand-in for the burned-nonce obligation.
#[tokio::test]
async fn paid_send_with_suspension_owes_single_fail_closed_persist() {
    use scp_protocol::context::roles::Capability;
    use scp_protocol::trust::consequence::{
        ConsequenceAction, ConsequenceRule, ConsequenceTrigger, EnforcementSeverity,
    };
    use scp_runtime_core::context::builder::ContextEventLogProvider;

    let event_log = scp_runtime_core::context::providers::event_log::MerkleEventLogProvider::new();
    let ctx_byte = 0x73u8;
    let ctx = ctx_hex(ctx_byte);
    // ADR-056: the event-log key the consequence reader derives from the
    // context-id STRING is the canonical digest — for a real 64-hex id
    // (`ctx_hex` = `hex([ctx_byte; 32])`) that is the DECODED digest
    // `[ctx_byte; 32]`, NOT `SHA-256(ctx)`. The seeded governance leaf must
    // be stored under that same digest to be visible to
    // `event_log_entries_for_consequences`.
    let ctx_id_bytes = scp_runtime_core::context::state::context_id_to_bytes(&ctx);
    let sender = DID("did:example:paid-suspend-sender".to_owned());

    // Seed a convergent `WarningCount` evidence leaf: a `GovernanceAction`
    // whose actor is SOMEONE ELSE and whose payload `target_did` is the sender
    // (the `matches_trigger(WarningCount, …)` shape). This MUST come from the
    // durable log (Source 1) — `merge_consequence_events` deliberately omits
    // governance events from the receive buffer to preserve durable-leaf
    // convergence.
    event_log
        .init_event_log(&ctx_id_bytes)
        .await
        .expect("init event log");
    let warning_payload = scp_event_log::EventPayload {
        data: serde_json::to_vec(&serde_json::json!({ "target_did": sender.as_ref() }))
            .expect("serialize warning payload"),
    };
    event_log
        .append_event(
            &ctx_id_bytes,
            scp_event_log::EventType::GovernanceAction,
            "did:example:warning-issuer",
            warning_payload,
            1_700_000_050,
        )
        .await
        .expect("seed governance warning leaf");

    // FailPersistence ⇒ the single nonce-token commit must surface the §9
    // durability error (not a silent coalesced ack).
    let deps = build_deps_with_event_log(Box::new(FailPersistence), Box::new(event_log)).await;
    let mut cell = ClassSCell::new(fresh_state(ctx_byte));

    // The send path requires an ACTIVE context (else `finalize_send` takes the
    // TTL-inactive early return and never runs consequence enforcement).
    cell.class_c_view()
        .handle_mut()
        .transition_to(&scp_protocol::context::ContextState::Active)
        .expect("transition to Active");

    // The sender must be a present member for the suspension GROW to apply.
    cell.class_c_view().membership_class_c_mut().add_member(
        sender.clone(),
        "member".to_owned(),
        Vec::new(),
    );

    // Configure the consequence rule this send will evaluate: a
    // `SuspendCapability` (threshold 1) keyed on `WarningCount`.
    {
        let mut view = cell.class_c_view();
        *view.governance_class_c_mut().consequence_rules_mut() = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::WarningCount,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability {
                capabilities: vec![Capability::MessagesWrite],
            }),
            threshold: 1,
            window: std::time::Duration::from_hours(1),
        }];
    }

    // Drive the PRODUCTION paid send. `Some(nonce_token)` models the burned
    // spending-nonce obligation (the exact stand-in the production send-path
    // fail-closed tests use). The send signs any due checkpoint through a
    // local test signer; the consequence path runs regardless.
    let paid = scp_runtime::domain_handlers()
        .messaging
        .finalize_send(
            &mut cell,
            &deps,
            scp_runtime_core::context::domains::FinalizeSendRequest {
                context_id: &ctx,
                context_id_bytes: &ctx_id_bytes,
                sender_did: &sender,
                sequence: 0,
                payload: b"paid-with-suspension",
                signer: scp_runtime_core::context::supervisor::MessageSigner::Active(
                    &scp_runtime_core::context::actor::signer::CommandSigner::local_ed25519(
                        ed25519_dalek::SigningKey::from_bytes(&[0x5au8; 32]),
                    ),
                ),
                token: Some(ClassSCommitToken::new_for_test(&ctx)),
                is_broadcast: false,
            },
        )
        .await;

    // The single nonce-token commit covers BOTH the burned nonce and the armed
    // suspension; under FailPersistence it surfaces the §9 durability error
    // (the redundant sink token was `subsume`d, leaving exactly one obligation —
    // a leaked sink would have tripped the Drop guard before we got here).
    assert!(
        matches!(paid, Err(ContextError::PersistenceFailed(_))),
        "a paid send that also armed a downward-auth suspension must persist \
             fail-closed through the single nonce token (not a silent ack): {paid:?}"
    );

    // KEEP-direction: the suspension applied during the send stays in memory
    // through the failed persist — the denied capability is not silently
    // re-granted on a coalesce-window crash.
    assert!(
        cell.role_state
            .suspended_for(sender.as_ref())
            .is_some_and(|caps| caps.contains(&Capability::MessagesWrite)),
        "keep-direction: the consequence suspension armed during the paid send \
             is retained in memory even when the fail-closed persist fails (RED-CS3)"
    );
}

/// ADR-049 §9 (RED-CS3) — a consequence-engine `AssignRole` DEMOTION is
/// persisted FAIL-CLOSED, exactly like a capability suspension. An
/// `AssignRole` consequence → `system_assign_role` REPLACES the member's
/// `member_capabilities` with the new role's set; on a demotion (admin→member
/// here) that is a downward-auth SHRINK of effective authority
/// (`member_capabilities` − `suspended_capabilities`). A coalesce-window crash
/// would restore the pre-demotion (HIGHER) `member_capabilities` from the
/// snapshot, silently re-granting the demoted member's removed authority — the
/// §9 invariant violation this test guards.
///
/// It drives the demotion through the SAME view path the receive handler uses
/// (`enforce_triggered_consequences` against `class_c_view().split_class_c()`)
/// and asserts (a) the `downward_auth_applied` flag is `true` (so the caller
/// routes the persist fail-closed, not best-effort coalesced), (b) under a
/// FAILING persistence backend the handler's fail-closed persist surfaces the
/// §9 durability error (`PersistenceFailed`), and (c) the demotion is RETAINED
/// in memory (keep-direction) — the member's `member_capabilities` reflect the
/// LOWER role even when the persist failed.
// `.await` continuation lines from the ADR-049 Decision 7 async-event-log
// conversion pushed this test one line over the heuristic; the body is a
// single cohesive fail-closed-persist scenario, not separable work.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn consequence_assign_role_demotion_owes_fail_closed_persist() {
    use scp_protocol::context::roles::{Capability, RoleDefinition};
    use scp_protocol::trust::consequence::{
        ConsequenceAction, ConsequenceRule, TriggeredConsequence,
    };
    use scp_runtime_core::context::shared::governance::EnforceConsequencesCtx;

    let deps = build_deps(Box::new(FailPersistence)).await;
    // Ceiling holds the HIGH/LOW role caps: mint-time enforcement (§7.2.1 step 8).
    let caps = [Capability::MessagesRead, Capability::MessagesWrite];
    let mut cell = ClassSCell::new(fresh_state_with_ceiling(0x72, caps));
    let ctx = ctx_hex(0x72);
    let subject = DID("did:example:demote-subject".to_owned());

    // Seed: a HIGH role ({MessagesRead, MessagesWrite}) and a LOW role
    // ({MessagesRead}); the subject starts holding the HIGH role's
    // capabilities. The subject must be present in BOTH `membership` (the
    // present-member gate in `process_one_triggered_consequence`) AND
    // `role_state.members` (the `system_assign_role` member check).
    {
        let mut view = cell.class_c_view();
        view.membership_class_c_mut()
            .add_member(subject.clone(), "high".to_owned(), Vec::new());
        let mut role_state = view.role_state_class_c_mut();
        role_state.role_definitions_mut().insert(
            "high".to_owned(),
            RoleDefinition {
                name: "high".to_owned(),
                capabilities: HashSet::from([Capability::MessagesRead, Capability::MessagesWrite]),
            },
        );
        role_state.role_definitions_mut().insert(
            "low".to_owned(),
            RoleDefinition {
                name: "low".to_owned(),
                capabilities: HashSet::from([Capability::MessagesRead]),
            },
        );
        role_state.members_mut().insert(subject.as_ref().to_owned());
        // Seed the subject's HIGH-role granted capabilities ({MessagesRead,
        // MessagesWrite}) through the sanctioned `system_assign_role` REPLACEMENT
        // (the F2 whole-`&mut` `member_capabilities_mut()` shrink accessor is
        // deleted from this best-effort view).
        role_state
            .system_assign_role(subject.as_ref(), "high", deps.clock.as_ref())
            .expect("seed HIGH role assignment");
    }

    // An `AssignRole { to_role: "low" }` consequence demotes the subject,
    // replacing `member_capabilities[subject]` with the LOWER set — a
    // downward-auth mutation that MUST signal the fail-closed flag.
    let rules = vec![ConsequenceRule {
        trigger: scp_protocol::trust::consequence::ConsequenceTrigger::WarningCount,
        action: ConsequenceAction::AssignRole {
            to_role: "low".to_owned(),
        },
        threshold: 1,
        window: std::time::Duration::from_hours(1),
    }];
    let triggered = vec![TriggeredConsequence {
        rule_index: 0,
        action: rules[0].action.clone(),
        evidence: Vec::new(),
    }];

    // Drive the demotion through the handler's exact view path. The GROW
    // (`system_assign_role` on the consequence view) ARMS the obligation sink
    // (coupled to the mutation — GAP-A closed).
    let mut obligation = None;
    let downward_auth_applied = {
        let mut view = cell.class_c_view();
        let mut split = view.consequence_split();
        scp_runtime::domain_handlers()
            .governance
            .enforce_triggered_consequences(
                &mut split,
                &EnforceConsequencesCtx {
                    context_id: &ctx,
                    member_did: &subject,
                    now: 1_700_000_100,
                    triggered: &triggered,
                    rules: &rules,
                    clock: deps.clock.as_ref(),
                    event_log: deps.event_log.as_ref(),
                    event_tx: None,
                },
                &mut obligation,
            )
            .await
    };
    assert!(
        downward_auth_applied,
        "an AssignRole demotion shrinks `member_capabilities` and must signal \
             the downward-auth fail-closed flag (RED-CS3)"
    );
    let token = obligation
        .take()
        .expect("the AssignRole demotion GROW arms the fail-closed obligation sink");
    assert_eq!(
        cell.role_state.member_capabilities.get(subject.as_ref()),
        Some(&HashSet::from([Capability::MessagesRead])),
        "the demotion is applied in memory before the persist: the member now \
             holds only the LOWER role's capabilities (MessagesWrite removed)"
    );

    // Discharging the armed obligation IS the §9 fail-closed persist. Under
    // FailPersistence it must surface the durability error rather than a silent
    // coalesced ack.
    let persist = token.commit(&cell, &deps, &ctx).await;
    let err = persist.expect_err("FailPersistence ⇒ fail-closed persist Err");
    assert!(
        matches!(err, ContextError::PersistenceFailed(_)),
        "the §9 durability error must surface (not a silent coalesced ack): {err:?}"
    );

    // KEEP-direction: the demotion is RETAINED in memory after the failed
    // persist — it is not silently lost on a coalesce-window crash, so the
    // demoted member's removed authority is not silently re-granted.
    assert_eq!(
        cell.role_state.member_capabilities.get(subject.as_ref()),
        Some(&HashSet::from([Capability::MessagesRead])),
        "keep-direction: the demotion stays in memory through a persist failure, \
             so the demoted member does not regain the higher role's authority (RED-CS3)"
    );
}

// ------------------------------------------------------------------
// commit_class_s_keep
// ------------------------------------------------------------------

/// `*_keep` persists fail-closed and returns `Ok(value)` on persist success,
/// retaining the mutation.
#[tokio::test]
async fn keep_persists_and_returns_ok_on_success() {
    let persist_calls = Arc::new(AtomicUsize::new(0));
    let deps = build_deps(Box::new(SpyPersistence {
        persist_calls: Arc::clone(&persist_calls),
    }))
    .await;
    let mut cell = ClassSCell::new(fresh_state(0x11));
    let ctx = ctx_hex(0x11);

    let returned = cell
        .commit_class_s_keep(&deps, &ctx, |mut view| {
            view.class_s_mut().xctx_nonce_dedup.record([0x3Cu8; 16], 0);
            Ok("kept")
        })
        .await
        .expect("persist succeeds ⇒ Ok");

    assert_eq!(returned, "kept");
    assert!(
        cell.class_s
            .xctx_nonce_dedup
            .entries()
            .contains_key(&[0x3Cu8; 16]),
        "mutation retained on persist success"
    );
    assert_eq!(
        persist_calls.load(Ordering::SeqCst),
        1,
        "exactly one persist"
    );
}

/// `*_keep` KEEPS the mutation on persist failure (fail-closed direction) and
/// surfaces the persist error.
#[tokio::test]
async fn keep_retains_mutation_on_persist_failure() {
    let deps = build_deps(Box::new(FailPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x12));
    let ctx = ctx_hex(0x12);

    let result = cell
        .commit_class_s_keep(&deps, &ctx, |mut view| {
            view.class_s_mut().xctx_nonce_dedup.record([0x3Cu8; 16], 0);
            Ok(())
        })
        .await;

    assert!(
        matches!(result, Err(ContextError::PersistenceFailed(_))),
        "persist failure surfaces; got {result:?}"
    );
    assert!(
        cell.class_s
            .xctx_nonce_dedup
            .entries()
            .contains_key(&[0x3Cu8; 16]),
        "keep variant retains the recorded nonce even on persist failure"
    );
}

/// `*_keep` returns `f`'s error without persisting when `f` rejects.
#[tokio::test]
async fn keep_returns_f_error_without_persisting() {
    let persist_calls = Arc::new(AtomicUsize::new(0));
    let deps = build_deps(Box::new(SpyPersistence {
        persist_calls: Arc::clone(&persist_calls),
    }))
    .await;
    let mut cell = ClassSCell::new(fresh_state(0x13));
    let ctx = ctx_hex(0x13);

    let result: Result<(), ContextError> = cell
        .commit_class_s_keep(&deps, &ctx, |_view| {
            Err(ContextError::PermissionDenied("rejected".to_owned()))
        })
        .await;

    assert!(
        matches!(result, Err(ContextError::PermissionDenied(_))),
        "f's error propagates unchanged; got {result:?}"
    );
    assert_eq!(
        persist_calls.load(Ordering::SeqCst),
        0,
        "no Class-S persist runs when f rejects"
    );
}

// ------------------------------------------------------------------
// commit_class_s_restore
// ------------------------------------------------------------------

/// `*_restore` persists fail-closed and returns `Ok` on success, retaining
/// the mutation.
#[tokio::test]
async fn restore_persists_and_returns_ok_on_success() {
    let deps = build_deps(Box::new(OkPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x21));
    let ctx = ctx_hex(0x21);
    let saga_a = saga("saga-restore-ok");

    let value = cell
        .commit_class_s_restore(&deps, &ctx, |mut view| {
            view.class_s_mut()
                .saga_pending
                .insert(saga_a.clone(), prepared_invocation());
            Ok(99u32)
        })
        .await
        .expect("persist succeeds ⇒ Ok");

    assert_eq!(value, 99);
    assert!(
        cell.class_s.saga_pending.contains_key(&saga_a),
        "mutation retained on persist success"
    );
}

/// (key behaviour) `*_restore` ROLLS BACK the Class-S sub-structs on persist
/// failure — asserted via the mirror across BOTH `saga_pending` and the
/// nonce dedup cache, plus the governance Class-S sub-struct.
#[tokio::test]
async fn restore_rolls_back_class_s_on_persist_failure() {
    let deps = build_deps(Box::new(FailPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x22));
    let ctx = ctx_hex(0x22);
    let saga_a = saga("saga-restore-rollback");

    let result = cell
        .commit_class_s_restore(&deps, &ctx, |mut view| {
            // Mutate Class-S: saga_pending + nonce dedup …
            let cs = view.class_s_mut();
            cs.saga_pending
                .insert(saga_a.clone(), prepared_invocation());
            cs.xctx_nonce_dedup.record([0x3Cu8; 16], 1_700_000_000);
            // … and governance Class-S (threshold).
            view.governance_class_s_mut().threshold_value = 7;
            Ok(())
        })
        .await;

    assert!(
        matches!(result, Err(ContextError::PersistenceFailed(_))),
        "persist failure surfaces; got {result:?}"
    );
    assert!(
        cell.class_s.saga_pending.is_empty(),
        "saga_pending rolled back via the mirror"
    );
    assert!(
        !cell
            .class_s
            .xctx_nonce_dedup
            .entries()
            .contains_key(&[0x3Cu8; 16]),
        "recorded nonce rolled back via the mirror"
    );
    assert_eq!(
        cell.governance.class_s.threshold_value, 0,
        "governance threshold rolled back via the mirror"
    );
}

/// `*_restore` returns `f`'s error without persisting when `f` rejects.
#[tokio::test]
async fn restore_returns_f_error_without_persisting() {
    let persist_calls = Arc::new(AtomicUsize::new(0));
    let deps = build_deps(Box::new(SpyPersistence {
        persist_calls: Arc::clone(&persist_calls),
    }))
    .await;
    let mut cell = ClassSCell::new(fresh_state(0x23));
    let ctx = ctx_hex(0x23);

    let result: Result<(), ContextError> = cell
        .commit_class_s_restore(&deps, &ctx, |_view| {
            Err(ContextError::PermissionDenied("rejected".to_owned()))
        })
        .await;

    assert!(matches!(result, Err(ContextError::PermissionDenied(_))));
    assert_eq!(persist_calls.load(Ordering::SeqCst), 0);
}

// ------------------------------------------------------------------
// commit_class_s_compensating
// ------------------------------------------------------------------

/// `*_compensating` on persist success returns `Ok` and does NOT run the
/// async compensation.
#[tokio::test]
async fn compensating_does_not_compensate_on_persist_success() {
    let deps = build_deps(Box::new(OkPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x31));
    let ctx = ctx_hex(0x31);
    let compensated = Arc::new(AtomicUsize::new(0));
    let comp_for_closure = Arc::clone(&compensated);

    let value = cell
        .commit_class_s_compensating(
            &deps,
            &ctx,
            |mut view| {
                view.class_s_mut().xctx_nonce_dedup.record([0x3Cu8; 16], 0);
                Ok((5u32, "escrow-handle"))
            },
            async move |_external, _classc: ClassCMut<'_>, _deps: &ActorDeps| {
                comp_for_closure.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await
        .expect("persist succeeds ⇒ Ok");

    assert_eq!(value, 5);
    assert_eq!(
        compensated.load(Ordering::SeqCst),
        0,
        "compensation does not run on persist success"
    );
    assert!(
        cell.class_s
            .xctx_nonce_dedup
            .entries()
            .contains_key(&[0x3Cu8; 16]),
        "mutation retained on success"
    );
}

/// (key behaviour) `*_compensating` on persist FAILURE restores Class-S
/// IN-STATE first, then runs the async compensation exactly once.
#[tokio::test]
async fn compensating_restores_then_compensates_on_persist_failure() {
    let deps = build_deps(Box::new(FailPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x32));
    let ctx = ctx_hex(0x32);
    let saga_a = saga("saga-compensate");
    // Compensation observes the post-restore Class-S state: it records
    // whether saga_pending was already empty (i.e. restore ran BEFORE it).
    let saw_empty_after_restore = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let comp_flag = Arc::clone(&saw_empty_after_restore);

    let result = cell
        .commit_class_s_compensating(
            &deps,
            &ctx,
            |mut view| {
                view.class_s_mut()
                    .saga_pending
                    .insert(saga_a.clone(), prepared_invocation());
                Ok(((), "escrow-handle"))
            },
            async move |external, classc: ClassCMut<'_>, _deps: &ActorDeps| {
                assert_eq!(external, "escrow-handle");
                // The Class-S in-state restore has already run, so the
                // ClassCMut view reads an empty saga_pending — via the
                // field-granular `class_s()` read accessor (the view no
                // longer Derefs to the whole state).
                comp_flag.store(classc.class_s().saga_pending.is_empty(), Ordering::SeqCst);
            },
        )
        .await;

    assert!(matches!(result, Err(ContextError::PersistenceFailed(_))));
    assert!(
        saw_empty_after_restore.load(Ordering::SeqCst),
        "compensation runs AFTER the in-state restore (saga_pending already empty)"
    );
    assert!(
        cell.class_s.saga_pending.is_empty(),
        "Class-S restored on persist failure"
    );
}

// ------------------------------------------------------------------
// commit_class_s_keep_compensating
// ------------------------------------------------------------------

/// `*_keep_compensating` on persist SUCCESS returns `Ok(value)`, runs NO
/// compensation, and retains the Class-S mutation. (The Class-C effect `f`
/// staged also stands — nothing to compensate when the persist landed.)
#[tokio::test]
async fn keep_compensating_does_not_compensate_on_persist_success() {
    let deps = build_deps(Box::new(OkPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x36));
    let ctx = ctx_hex(0x36);
    let compensated = Arc::new(AtomicUsize::new(0));
    let comp_for_closure = Arc::clone(&compensated);
    let member = DID("did:example:keep-comp-success".to_owned());
    let member_for_f = member.clone();

    let value = cell
        .commit_class_s_keep_compensating(
            &deps,
            &ctx,
            move |mut view| {
                // Class-S: consume a replay nonce (kept).
                view.class_s_mut().xctx_nonce_dedup.record([0x3Cu8; 16], 0);
                // Class-C: stage an in-memory reservation (a member here).
                view.rest_mut().members.insert(member_for_f);
                Ok((5u32, "reservation-handle"))
            },
            async move |_external, _classc: ClassCMut<'_>, _deps: &ActorDeps| {
                comp_for_closure.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await
        .expect("persist succeeds ⇒ Ok");

    assert_eq!(value, 5);
    assert_eq!(
        compensated.load(Ordering::SeqCst),
        0,
        "no compensation on persist success"
    );
    assert!(
        cell.class_s
            .xctx_nonce_dedup
            .entries()
            .contains_key(&[0x3Cu8; 16]),
        "Class-S nonce kept on success"
    );
    assert!(
        cell.members.contains(&member),
        "Class-C reservation stands on success"
    );
}

/// (key behaviour) `*_keep_compensating` on persist FAILURE runs
/// `on_persist_failure` (which undoes the Class-C effect), KEEPS the Class-S
/// mutation (NOT restored — fail-closed direction), and returns the persist
/// error.
#[tokio::test]
async fn keep_compensating_keeps_class_s_and_compensates_class_c_on_persist_failure() {
    let deps = build_deps(Box::new(FailPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x37));
    let ctx = ctx_hex(0x37);
    let member = DID("did:example:keep-comp-failure".to_owned());
    let member_for_f = member.clone();
    let external_for_undo = member.clone();
    // The compensation observes that the Class-S nonce was NOT restored
    // (still present) at the time it runs.
    let saw_nonce_kept = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let kept_flag = Arc::clone(&saw_nonce_kept);

    let result = cell
        .commit_class_s_keep_compensating(
            &deps,
            &ctx,
            move |mut view| {
                view.class_s_mut().xctx_nonce_dedup.record([0x3Cu8; 16], 0);
                view.rest_mut().members.insert(member_for_f);
                Ok(((), external_for_undo))
            },
            async move |external: DID, mut classc: ClassCMut<'_>, _deps: &ActorDeps| {
                // Class-S kept: the nonce is still recorded when we compensate
                // (read via the field-granular `class_s()` read accessor; the
                // restricted `ClassCMut` view exposes no Class-S *mutator* and
                // no longer Derefs to the whole state).
                kept_flag.store(
                    classc
                        .class_s()
                        .xctx_nonce_dedup
                        .entries()
                        .contains_key(&[0x3Cu8; 16]),
                    Ordering::SeqCst,
                );
                // Undo the Class-C reservation the failed persist did not make
                // durable.
                classc.members_mut().remove(&external);
            },
        )
        .await;

    assert!(
        matches!(result, Err(ContextError::PersistenceFailed(_))),
        "persist failure surfaces; got {result:?}"
    );
    assert!(
        saw_nonce_kept.load(Ordering::SeqCst),
        "Class-S nonce is KEPT (not restored) when on_persist_failure runs"
    );
    assert!(
        cell.class_s
            .xctx_nonce_dedup
            .entries()
            .contains_key(&[0x3Cu8; 16]),
        "Class-S nonce retained on persist failure (fail-closed direction)"
    );
    assert!(
        !cell.members.contains(&member),
        "Class-C reservation undone by on_persist_failure"
    );
}

/// `*_keep_compensating` returns `f`'s error without persisting or
/// compensating when `f` rejects.
#[tokio::test]
async fn keep_compensating_returns_f_error_without_persisting() {
    let persist_calls = Arc::new(AtomicUsize::new(0));
    let deps = build_deps(Box::new(SpyPersistence {
        persist_calls: Arc::clone(&persist_calls),
    }))
    .await;
    let mut cell = ClassSCell::new(fresh_state(0x38));
    let ctx = ctx_hex(0x38);
    let compensated = Arc::new(AtomicUsize::new(0));
    let comp_for_closure = Arc::clone(&compensated);

    let result: Result<(), ContextError> = cell
        .commit_class_s_keep_compensating(
            &deps,
            &ctx,
            |_view| Err(ContextError::PermissionDenied("rejected".to_owned())),
            async move |_external: (), _classc: ClassCMut<'_>, _deps: &ActorDeps| {
                comp_for_closure.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;

    assert!(
        matches!(result, Err(ContextError::PermissionDenied(_))),
        "f's error propagates unchanged; got {result:?}"
    );
    assert_eq!(
        persist_calls.load(Ordering::SeqCst),
        0,
        "no persist runs when f rejects"
    );
    assert_eq!(
        compensated.load(Ordering::SeqCst),
        0,
        "no compensation runs when f rejects"
    );
}

// ------------------------------------------------------------------
// commit_class_s_then_append
// ------------------------------------------------------------------

/// `*_then_append` on persist-OK + after-OK returns `Ok(value)` and retains
/// both the mutation and whatever `after` did.
#[tokio::test]
async fn then_append_ok_when_persist_and_after_succeed() {
    let deps = build_deps(Box::new(OkPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x41));
    let ctx = ctx_hex(0x41);
    let saga_a = saga("saga-append-ok");

    let value = cell
        .commit_class_s_then_append(
            &deps,
            &ctx,
            |mut view| {
                view.class_s_mut()
                    .saga_pending
                    .insert(saga_a.clone(), prepared_invocation());
                Ok((11u32, "append-input"))
            },
            async |input: &&str, _state: &PerContextState, _deps: &ActorDeps| {
                assert_eq!(*input, "append-input");
                Ok(())
            },
        )
        .await
        .expect("persist + after succeed ⇒ Ok");

    assert_eq!(value, 11);
    assert!(cell.class_s.saga_pending.contains_key(&saga_a));
}

/// (new contract — FIX 1) `*_then_append`'s `after` receives a READ-ONLY
/// `&PerContextState` reflecting the JUST-PERSISTED state, and performs only
/// an EXTERNAL append. On `after`-Ok there is NO re-persist (the append wrote
/// to an external sink, not to `ContextSnapshot`-backed in-state), so exactly
/// ONE persist runs — the post-`f` fail-closed persist.
///
/// The `&PerContextState` view (no `&mut`) provably CANNOT name `class_s_mut`
/// / `governance_class_s_mut`: that is enforced by the type, not by this test.
/// Were `after` to take a `ClassSMut`, an un-persisted Class-S mutation could
/// escape the combinator's guarantee; the read-only view makes that a compile
/// error. This test confirms the view TYPE and the single-persist behaviour.
#[tokio::test]
async fn then_append_after_reads_just_persisted_state_and_does_not_repersist() {
    let persist_calls = Arc::new(AtomicUsize::new(0));
    let deps = build_deps(Box::new(SpyPersistence {
        persist_calls: Arc::clone(&persist_calls),
    }))
    .await;
    let mut cell = ClassSCell::new(fresh_state(0x46));
    let ctx = ctx_hex(0x46);
    let saga_a = saga("saga-append-reads-state");
    // `after` records whether the read-only state it was handed already
    // reflects `f`'s Class-S mutation (i.e. it observes the just-persisted
    // state, not a pre-`f` view).
    let saw_mutation = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let saw_flag = Arc::clone(&saw_mutation);
    let saga_for_after = saga_a.clone();

    let value = cell
        .commit_class_s_then_append(
            &deps,
            &ctx,
            |mut view| {
                view.class_s_mut()
                    .saga_pending
                    .insert(saga_a.clone(), prepared_invocation());
                Ok((7u32, "append-input"))
            },
            // `state: &PerContextState` — a read-only view. There is no
            // `state.class_s_mut()` to call; mutating Class-S here would not
            // compile. `after` reads the just-persisted state, then performs
            // its (here, no-op stand-in for an external) append.
            async move |input: &&str, state: &PerContextState, _deps: &ActorDeps| {
                assert_eq!(*input, "append-input");
                saw_flag.store(
                    state.class_s.saga_pending.contains_key(&saga_for_after),
                    Ordering::SeqCst,
                );
                Ok(())
            },
        )
        .await
        .expect("persist + after succeed ⇒ Ok");

    assert_eq!(value, 7);
    assert!(
        saw_mutation.load(Ordering::SeqCst),
        "after reads the JUST-PERSISTED state (f's mutation is visible)"
    );
    assert!(cell.class_s.saga_pending.contains_key(&saga_a));
    assert_eq!(
        persist_calls.load(Ordering::SeqCst),
        1,
        "after-Ok does NOT re-persist: exactly one (post-f) persist runs"
    );
}

/// (key behaviour) `*_then_append` when `after` fails RESTORES + RE-PERSISTS
/// the snapshot and reports `durability_diverged == false` (rollback made
/// durable).
#[tokio::test]
async fn then_append_restores_and_repersists_on_after_failure() {
    // Persistence succeeds for the initial persist AND the re-persist.
    let persist_calls = Arc::new(AtomicUsize::new(0));
    let deps = build_deps(Box::new(SpyPersistence {
        persist_calls: Arc::clone(&persist_calls),
    }))
    .await;
    let mut cell = ClassSCell::new(fresh_state(0x42));
    let ctx = ctx_hex(0x42);
    let saga_a = saga("saga-append-fail");

    let result = cell
        .commit_class_s_then_append(
            &deps,
            &ctx,
            |mut view| {
                view.class_s_mut()
                    .saga_pending
                    .insert(saga_a.clone(), prepared_invocation());
                Ok(((), "append-input"))
            },
            async |_input: &&str, _state: &PerContextState, _deps: &ActorDeps| {
                Err(ContextError::EventLogFailed("append failed".to_owned()))
            },
        )
        .await;

    match result {
        Err(AppendOutcomeError {
            durability_diverged,
            err,
        }) => {
            assert!(
                !durability_diverged,
                "rollback re-persisted ⇒ durability_diverged is false"
            );
            assert!(
                matches!(err, ContextError::EventLogFailed(_)),
                "carries the after error; got {err:?}"
            );
        }
        Ok(()) => panic!("expected AppendOutcomeError"),
    }
    assert!(
        cell.class_s.saga_pending.is_empty(),
        "saga_pending rolled back after the after-failure"
    );
    // Two persists: the post-f fail-closed persist + the rollback re-persist.
    assert_eq!(persist_calls.load(Ordering::SeqCst), 2);
}

/// `*_then_append` reports `durability_diverged == true` when the post-`f`
/// persist itself fails (the mutation is in memory but did not durably land).
#[tokio::test]
async fn then_append_reports_diverged_on_initial_persist_failure() {
    let deps = build_deps(Box::new(FailPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x43));
    let ctx = ctx_hex(0x43);
    let saga_a = saga("saga-append-persistfail");
    let after_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let after_flag = Arc::clone(&after_ran);

    let result = cell
        .commit_class_s_then_append(
            &deps,
            &ctx,
            |mut view| {
                view.class_s_mut()
                    .saga_pending
                    .insert(saga_a.clone(), prepared_invocation());
                Ok(((), "append-input"))
            },
            async move |_input: &&str, _state: &PerContextState, _deps: &ActorDeps| {
                after_flag.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;

    match result {
        Err(AppendOutcomeError {
            durability_diverged,
            err,
        }) => {
            assert!(
                durability_diverged,
                "initial persist failed ⇒ durability_diverged is true"
            );
            assert!(matches!(err, ContextError::PersistenceFailed(_)));
        }
        Ok(()) => panic!("expected AppendOutcomeError"),
    }
    assert!(
        !after_ran.load(Ordering::SeqCst),
        "after never runs when the initial fail-closed persist fails"
    );
}

/// `*_then_append` when `after` fails AND the rollback re-persist also fails:
/// reports `durability_diverged == true` (could not make the rollback
/// durable).
#[tokio::test]
async fn then_append_reports_diverged_when_repersist_fails() {
    // Fail ONLY the second persist (the re-persist): succeed the first
    // post-f persist, fail the rollback re-persist (see `SucceedThenFail`).
    let persist_calls = Arc::new(AtomicUsize::new(0));
    let deps = build_deps(Box::new(SucceedThenFail {
        calls: Arc::clone(&persist_calls),
    }))
    .await;
    let mut cell = ClassSCell::new(fresh_state(0x44));
    let ctx = ctx_hex(0x44);
    let saga_a = saga("saga-append-repersistfail");

    let result = cell
        .commit_class_s_then_append(
            &deps,
            &ctx,
            |mut view| {
                view.class_s_mut()
                    .saga_pending
                    .insert(saga_a.clone(), prepared_invocation());
                Ok(((), "x"))
            },
            async |_input: &&str, _state: &PerContextState, _deps: &ActorDeps| {
                Err(ContextError::EventLogFailed("append failed".to_owned()))
            },
        )
        .await;

    match result {
        Err(AppendOutcomeError {
            durability_diverged,
            err,
        }) => {
            assert!(
                durability_diverged,
                "re-persist failed ⇒ durability_diverged is true"
            );
            assert!(
                matches!(err, ContextError::PersistenceFailed(_)),
                "carries the re-persist error; got {err:?}"
            );
        }
        Ok(()) => panic!("expected AppendOutcomeError"),
    }
    assert_eq!(persist_calls.load(Ordering::SeqCst), 2);
}

/// `*_then_append` returns `AppendOutcomeError { durability_diverged: false }`
/// when `f` itself rejects (no persist ran).
#[tokio::test]
async fn then_append_reports_not_diverged_when_f_rejects() {
    let persist_calls = Arc::new(AtomicUsize::new(0));
    let deps = build_deps(Box::new(SpyPersistence {
        persist_calls: Arc::clone(&persist_calls),
    }))
    .await;
    let mut cell = ClassSCell::new(fresh_state(0x45));
    let ctx = ctx_hex(0x45);

    let result: Result<(), AppendOutcomeError> = cell
        .commit_class_s_then_append(
            &deps,
            &ctx,
            |_view| Err(ContextError::PermissionDenied("rejected".to_owned())),
            async |_input: &(), _state: &PerContextState, _deps: &ActorDeps| Ok(()),
        )
        .await;

    match result {
        Err(AppendOutcomeError {
            durability_diverged,
            err,
        }) => {
            assert!(!durability_diverged);
            assert!(matches!(err, ContextError::PermissionDenied(_)));
        }
        Ok(()) => panic!("expected AppendOutcomeError"),
    }
    assert_eq!(persist_calls.load(Ordering::SeqCst), 0);
}

// ------------------------------------------------------------------
// commit_class_c_best_effort
// ------------------------------------------------------------------

/// `commit_class_c_best_effort` runs the Class-C mutation and issues exactly one
/// best-effort persist.
#[tokio::test]
async fn best_effort_runs_mutation_and_persists() {
    let persist_calls = Arc::new(AtomicUsize::new(0));
    let deps = build_deps(Box::new(SpyPersistence {
        persist_calls: Arc::clone(&persist_calls),
    }))
    .await;
    let mut cell = ClassSCell::new(fresh_state(0x51));
    let ctx = ctx_hex(0x51);
    let member = DID("did:example:best-effort-member".to_owned());
    let member_for_closure = member.clone();

    cell.commit_class_c_best_effort(&deps, &ctx, move |mut view| {
        view.members_mut().insert(member_for_closure);
    })
    .await;

    assert!(
        cell.members.contains(&member),
        "best-effort mutation is applied"
    );
    assert_eq!(
        persist_calls.load(Ordering::SeqCst),
        1,
        "commit_class_c_best_effort issues exactly one persist"
    );
}

/// `ClassCMut::split_class_c` yields the five disjoint borrows the
/// `ConsequenceStateSplit` pattern needs, simultaneously.
#[tokio::test]
async fn best_effort_split_yields_disjoint_class_c_borrows() {
    let persist_calls = Arc::new(AtomicUsize::new(0));
    let deps = build_deps(Box::new(SpyPersistence {
        persist_calls: Arc::clone(&persist_calls),
    }))
    .await;
    let mut cell = ClassSCell::new(fresh_state(0x52));
    let ctx = ctx_hex(0x52);

    cell.commit_class_c_best_effort(&deps, &ctx, |mut view| {
        let mut split = view.split_class_c();
        // Hold all five borrows live at once; mutate two of them to prove
        // they are independent mutable references.
        *split.checkpoint_events_since += 3;
        // Exercise the GovernanceClassCMut field-granular accessor (a Class-C
        // field) AND a field-granular READ accessor — neither can reach
        // `governance.class_s` (the whole-bucket Deref was removed).
        split
            .governance
            .cooldown_until_mut()
            .insert(7usize, 1_700_000_999);
        let _ = split.governance.next_proposal_seq();
        let _ = &split.role_state;
        let _ = split.membership.count();
        let _ = split.receive_buffer.len();
    })
    .await;

    assert_eq!(
        cell.checkpoint_events_since, 3,
        "the disjoint &mut checkpoint counter was mutated through the split"
    );
    assert_eq!(
        cell.governance.cooldown_until.get(&7usize),
        Some(&1_700_000_999),
        "the GovernanceClassCMut Class-C accessor mutated cooldown_until through the split"
    );
}

/// `ClassCMut::governance_class_c_mut` yields a `GovernanceClassCMut` whose
/// field-granular accessors mutate a Class-C governance field, and whose
/// field-granular read accessor (`next_proposal_seq`) reads a Class-C
/// governance field — with no `&mut` path to `governance.class_s`.
#[tokio::test]
async fn best_effort_governance_class_c_mut_mutates_class_c_field() {
    let persist_calls = Arc::new(AtomicUsize::new(0));
    let deps = build_deps(Box::new(SpyPersistence {
        persist_calls: Arc::clone(&persist_calls),
    }))
    .await;
    let mut cell = ClassSCell::new(fresh_state(0x53));
    let ctx = ctx_hex(0x53);

    cell.commit_class_c_best_effort(&deps, &ctx, |mut view| {
        let gov = view.governance_class_c_mut();
        // Mutate a Class-C governance field through the field-granular
        // accessor.
        gov.cooldown_until_mut().insert(3usize, 1_700_000_500);
        // Read a Class-C governance field via the field-granular read
        // accessor (reads cannot violate the fail-closed invariant). There is
        // no `&mut self.gov` / `class_s` accessor to reach Class-S, and the
        // whole-bucket Deref was removed.
        let _ = gov.next_proposal_seq();
    })
    .await;

    assert_eq!(
        cell.governance.cooldown_until.get(&3usize),
        Some(&1_700_000_500),
        "Class-C governance field mutated through governance_class_c_mut"
    );
    assert_eq!(
        persist_calls.load(Ordering::SeqCst),
        1,
        "best-effort issues exactly one persist"
    );
}

/// `GovernanceClassCMut::velocity_tracker_mut` hands out a `&mut` to the
/// per-sender velocity tracker; a recorded message is observable on the
/// underlying `cell.governance.velocity_tracker`.
#[tokio::test]
async fn best_effort_velocity_tracker_mut_records_through_view() {
    let deps = build_deps(Box::new(OkPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x54));
    let ctx = ctx_hex(0x54);
    let sender = DID("did:example:velocity-sender".to_owned());
    let sender_for_closure = sender.clone();

    cell.commit_class_c_best_effort(&deps, &ctx, move |mut view| {
        let gov = view.governance_class_c_mut();
        let vt = gov.velocity_tracker_mut();
        vt.record_message(&sender_for_closure, 1_700_000_000);
    })
    .await;

    assert_eq!(
        cell.governance
            .velocity_tracker
            .get_velocity(&sender, 1_700_000_000),
        1,
        "velocity message recorded through velocity_tracker_mut"
    );
}

/// `GovernanceClassCMut::budget_tracker_mut` hands out a `&mut` to the
/// per-member budget tracker; a grant is observable on the underlying
/// `cell.governance.budget_tracker`.
#[tokio::test]
async fn best_effort_budget_tracker_mut_grants_through_view() {
    use scp_protocol::economy::types::Amount;

    let deps = build_deps(Box::new(OkPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x55));
    let ctx = ctx_hex(0x55);
    let member = DID("did:example:budget-member".to_owned());
    let member_for_closure = member.clone();

    cell.commit_class_c_best_effort(&deps, &ctx, move |mut view| {
        view.governance_class_c_mut()
            .budget_tracker_mut()
            .grant(&member_for_closure, Amount(500));
    })
    .await;

    assert_eq!(
        cell.governance.budget_tracker.remaining(&member),
        Amount(500),
        "budget grant landed through budget_tracker_mut"
    );
}

/// `GovernanceClassCMut::economic_policy_mut` hands out a `&mut Option<…>`;
/// setting it to `Some(policy)` is observable on the underlying
/// `cell.governance.economic_policy`.
#[tokio::test]
async fn best_effort_economic_policy_mut_sets_through_view() {
    use scp_protocol::economy::types::{CostSchedule, CurrencyCode};

    let deps = build_deps(Box::new(OkPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x56));
    let ctx = ctx_hex(0x56);

    let policy = EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: CurrencyCode::from("USD"),
            per_message: None,
            per_outlet_call: None,
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec![],
        pricing_formula: None,
        payee: DID("did:example:payee".to_owned()),
    };
    let expected = policy.clone();

    cell.commit_class_c_best_effort(&deps, &ctx, move |mut view| {
        *view.governance_class_c_mut().economic_policy_mut() = Some(policy);
    })
    .await;

    assert_eq!(
        cell.governance.economic_policy,
        Some(expected),
        "economic policy set through economic_policy_mut"
    );
}

/// `ClassCMut::receive_buffer_mut` hands out a `&mut ReceiveBuffer`; a pushed
/// event is observable on the underlying `cell.receive_buffer`.
#[tokio::test]
async fn best_effort_receive_buffer_mut_pushes_through_view() {
    use scp_protocol::context::membership::ContextEvent;

    let deps = build_deps(Box::new(OkPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x57));
    let ctx = ctx_hex(0x57);

    let before = cell.receive_buffer.len();

    cell.commit_class_c_best_effort(&deps, &ctx, |mut view| {
        view.receive_buffer_mut().push(ContextEvent::MemberLeft {
            member_did: DID("did:example:left".to_owned()),
        });
    })
    .await;

    assert_eq!(
        cell.receive_buffer.len(),
        before + 1,
        "event pushed through receive_buffer_mut"
    );
}

/// `ClassCMut::role_state_class_c_mut` hands out a `RoleStateClassCMut` (no
/// whole `&mut`, no GROW); a member inserted into its `members` set via
/// `members_mut()` is observable on the underlying `cell.role_state`.
#[tokio::test]
async fn best_effort_role_state_class_c_mut_mutates_members_through_view() {
    let deps = build_deps(Box::new(OkPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x58));
    let ctx = ctx_hex(0x58);
    let member_did = "did:example:role-member".to_owned();
    let member_for_assert = member_did.clone();

    cell.commit_class_c_best_effort(&deps, &ctx, move |mut view| {
        view.role_state_class_c_mut()
            .members_mut()
            .insert(member_did);
    })
    .await;

    assert!(
        cell.role_state.members.contains(&member_for_assert),
        "member inserted through role_state_class_c_mut().members_mut()"
    );
}

// ------------------------------------------------------------------
// class_c_view (Add #1 — non-persisting Class-C view)
// ------------------------------------------------------------------

/// `class_c_view` hands out the same restricted `ClassCMut` and performs NO
/// persist (the run loop coalesce-persists instead). A Class-C mutation
/// through it lands in memory; zero persists occur.
#[tokio::test]
async fn class_c_view_mutates_without_persisting() {
    let persist_calls = Arc::new(AtomicUsize::new(0));
    let deps = build_deps(Box::new(SpyPersistence {
        persist_calls: Arc::clone(&persist_calls),
    }))
    .await;
    let mut cell = ClassSCell::new(fresh_state(0x71));
    // `deps` is unused by `class_c_view` itself (no persist); kept to mirror
    // the other tests' setup and to prove no persist runs.
    let _ = &deps;
    let member = DID("did:example:class-c-view-member".to_owned());

    {
        let mut view = cell.class_c_view();
        view.members_mut().insert(member.clone());
    }

    assert!(
        cell.members.contains(&member),
        "class_c_view mutation applied in memory"
    );
    assert_eq!(
        persist_calls.load(Ordering::SeqCst),
        0,
        "class_c_view performs NO persist (run loop coalesces)"
    );
}

// ------------------------------------------------------------------
// role_state_class_c_mut (Add #2 — restricted ContextRoleState view)
// ------------------------------------------------------------------

/// `RoleStateClassCMut` exposes `&mut` for the STRUCTURAL fields (members,
/// assignments, role definitions) and READS the granted/derived capabilities
/// (`member_capabilities`, read-only — the F2 whole-`&mut` shrink accessor is
/// deleted) and the downward-auth fields (`ceiling`, `suspended_capabilities`)
/// — observed via `commit_class_c_best_effort`.
#[tokio::test]
async fn role_state_class_c_mut_mutates_structural_and_reads_downward_auth() {
    let deps = build_deps(Box::new(OkPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x72));
    let ctx = ctx_hex(0x72);
    let member = "did:example:rs-classc-member".to_owned();
    let member_for_f = member.clone();

    cell.commit_class_c_best_effort(&deps, &ctx, move |mut view| {
        let mut rs = view.role_state_class_c_mut();
        // Structural &mut: add a member to the role-state member set.
        rs.members_mut().insert(member_for_f);
        // Read-only downward-auth accessors are reachable and return refs.
        let _ceiling: &CapabilityCeiling = rs.ceiling();
        let _suspended = rs.suspended_capabilities();
        let _ = rs.context_id();
        let _ = rs.creator_did();
        // Other structural &mut accessors compile/reach their fields.
        let _ = rs.role_definitions_mut().len();
        let _ = rs.assignments_mut().len();
        // `member_capabilities` is READ-ONLY on this best-effort view (the F2
        // whole-`&mut` shrink accessor is deleted).
        let _ = rs.member_capabilities().len();
    })
    .await;

    assert!(
        cell.role_state.members.contains(&member),
        "structural member add landed through role_state_class_c_mut"
    );
}

// ------------------------------------------------------------------
// membership_class_c_mut (Add #2 — restricted MembershipState view)
// ------------------------------------------------------------------

/// `MembershipClassCMut` forwards the STRUCTURAL membership mutators (add,
/// sequence bookkeeping) and reads — observed via `commit_class_c_best_effort`.
/// It deliberately exposes NO `remove_member`.
#[tokio::test]
async fn membership_class_c_mut_adds_and_bumps_sequence() {
    let deps = build_deps(Box::new(OkPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x73));
    let ctx = ctx_hex(0x73);
    let member = DID("did:example:membership-classc".to_owned());
    let member_for_f = member.clone();

    cell.commit_class_c_best_effort(&deps, &ctx, move |mut view| {
        let mut m = view.membership_class_c_mut();
        m.add_member(member_for_f.clone(), "member".to_owned(), Vec::new());
        assert!(
            m.contains(member_for_f.0.as_str()),
            "member present after add"
        );
        // Sequence bookkeeping (Class-C) is reachable and monotonic.
        let first = m.next_sequence_number(member_for_f.0.as_str());
        assert_eq!(first, Some(1));
        m.rollback_sequence_number(member_for_f.0.as_str());
        // `get_mut` reaches per-member metadata (not a removal path).
        assert!(m.get_mut(member_for_f.0.as_str()).is_some());
        let _ = m.get(member_for_f.0.as_str());
        let _ = m.count();
    })
    .await;

    assert!(
        cell.membership.contains(member.0.as_str()),
        "member added through membership_class_c_mut"
    );
    assert_eq!(
        cell.membership
            .get(member.0.as_str())
            .map(|info| info.sequence_number),
        Some(0),
        "sequence bumped then rolled back through the restricted view"
    );
}

// ------------------------------------------------------------------
// commit_class_s_keep_restore_split (Add #3 — keep-one / restore-one)
// ------------------------------------------------------------------

/// On persist SUCCESS, the split combinator keeps BOTH fields and returns
/// `Ok(value)`.
#[tokio::test]
async fn keep_restore_split_persists_and_keeps_both_on_success() {
    let persist_calls = Arc::new(AtomicUsize::new(0));
    let deps = build_deps(Box::new(SpyPersistence {
        persist_calls: Arc::clone(&persist_calls),
    }))
    .await;
    let mut cell = ClassSCell::new(fresh_state(0x74));
    let ctx = ctx_hex(0x74);
    let saga_a = saga("saga-split-ok");
    let saga_for_f = saga_a.clone();

    let value = cell
        .commit_class_s_keep_restore_split(
            &deps,
            &ctx,
            // Snapshot ONLY the restore-targeted field (saga_pending).
            |class_s| class_s.saga_pending.keys().cloned().collect::<Vec<_>>(),
            move |mut view| {
                let cs = view.class_s_mut();
                cs.xctx_nonce_dedup.record([0x3Cu8; 16], 0); // keep
                cs.saga_pending.insert(saga_for_f, prepared_invocation()); // restore
                Ok(42u32)
            },
            |class_s, keys_before| {
                // Restore = remove any saga_pending key not present before.
                class_s.saga_pending.retain(|k, _| keys_before.contains(k));
            },
        )
        .await
        .expect("persist succeeds ⇒ Ok");

    assert_eq!(value, 42);
    assert!(
        cell.class_s.saga_pending.contains_key(&saga_a),
        "restore field kept on persist success"
    );
    assert!(
        cell.class_s
            .xctx_nonce_dedup
            .entries()
            .contains_key(&[0x3Cu8; 16]),
        "kept field kept on persist success"
    );
    assert_eq!(
        persist_calls.load(Ordering::SeqCst),
        1,
        "exactly one persist"
    );
}

/// (key behaviour) On persist FAILURE, the split combinator RESTORES the
/// restore-targeted field (`saga_pending`) while KEEPING the kept field
/// (`xctx_nonce_dedup`), and returns the persist error.
#[tokio::test]
async fn keep_restore_split_restores_one_keeps_other_on_persist_failure() {
    let deps = build_deps(Box::new(FailPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x75));
    let ctx = ctx_hex(0x75);
    let saga_for_f = saga("saga-split-fail");

    let result = cell
        .commit_class_s_keep_restore_split(
            &deps,
            &ctx,
            |class_s| class_s.saga_pending.keys().cloned().collect::<Vec<_>>(),
            move |mut view| {
                let cs = view.class_s_mut();
                cs.xctx_nonce_dedup.record([0x3Cu8; 16], 0); // keep
                cs.saga_pending.insert(saga_for_f, prepared_invocation()); // restore
                Ok(())
            },
            |class_s, keys_before| {
                class_s.saga_pending.retain(|k, _| keys_before.contains(k));
            },
        )
        .await;

    assert!(
        matches!(result, Err(ContextError::PersistenceFailed(_))),
        "persist failure surfaces; got {result:?}"
    );
    assert!(
        cell.class_s.saga_pending.is_empty(),
        "RESTORE field rolled back on persist failure"
    );
    assert!(
        cell.class_s
            .xctx_nonce_dedup
            .entries()
            .contains_key(&[0x3Cu8; 16]),
        "KEEP field retained on persist failure (fail-closed direction)"
    );
}

/// `f`-reject runs NEITHER the persist NOR `restore_on_failure`.
#[tokio::test]
async fn keep_restore_split_f_reject_no_persist_no_restore() {
    let persist_calls = Arc::new(AtomicUsize::new(0));
    let deps = build_deps(Box::new(SpyPersistence {
        persist_calls: Arc::clone(&persist_calls),
    }))
    .await;
    let mut cell = ClassSCell::new(fresh_state(0x76));
    let ctx = ctx_hex(0x76);
    let restore_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let restore_flag = Arc::clone(&restore_ran);

    let result: Result<(), ContextError> = cell
        .commit_class_s_keep_restore_split(
            &deps,
            &ctx,
            |class_s| class_s.saga_pending.keys().cloned().collect::<Vec<_>>(),
            |_view| Err(ContextError::PermissionDenied("rejected".to_owned())),
            move |_class_s, _snap: Vec<_>| {
                restore_flag.store(true, Ordering::SeqCst);
            },
        )
        .await;

    assert!(
        matches!(result, Err(ContextError::PermissionDenied(_))),
        "f's error propagates unchanged; got {result:?}"
    );
    assert_eq!(
        persist_calls.load(Ordering::SeqCst),
        0,
        "no persist runs when f rejects"
    );
    assert!(
        !restore_ran.load(Ordering::SeqCst),
        "restore_on_failure does NOT run on f-reject (only on persist failure)"
    );
}

// ------------------------------------------------------------------
// new / into_inner
// ------------------------------------------------------------------

/// `into_inner` returns the wrapped state with mutations intact, and `Deref`
/// reads see the same state.
#[tokio::test]
async fn into_inner_returns_wrapped_state() {
    let deps = build_deps(Box::new(OkPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x61));
    let ctx = ctx_hex(0x61);
    let saga_a = saga("saga-unwrap");

    cell.commit_class_s_keep(&deps, &ctx, |mut view| {
        view.class_s_mut()
            .saga_pending
            .insert(saga_a.clone(), prepared_invocation());
        Ok(())
    })
    .await
    .expect("persist succeeds");
    // Read through Deref before unwrap.
    assert!(cell.saga_pending().contains_key(&saga_a));

    let state = cell.into_inner();
    assert!(
        state.saga_pending().contains_key(&saga_a),
        "into_inner preserves the committed mutation"
    );
}

// ------------------------------------------------------------------
// economy_pre_check_borrows (foundation #1 — simultaneous §19 borrows)
// ------------------------------------------------------------------

/// `GovernanceClassCMut::economy_pre_check_borrows` hands back a `&mut`
/// `budget_tracker` held SIMULTANEOUSLY with shared reads of `velocity_tracker`,
/// `economic_policy`, `consequence_rules`, and `message_pricing` — a debit through
/// the `&mut` lands while the four reads are live in the same scope.
#[tokio::test]
async fn economy_pre_check_borrows_debits_while_reading() {
    use scp_protocol::economy::types::Amount;

    let deps = build_deps(Box::new(OkPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x90));
    let ctx = ctx_hex(0x90);
    let member = DID("did:example:precheck-member".to_owned());
    let member_for_closure = member.clone();

    cell.commit_class_c_best_effort(&deps, &ctx, move |mut view| {
        let gov = view.governance_class_c_mut();
        let borrows = gov.economy_pre_check_borrows();
        // The four shared reads are live alongside the single &mut.
        let policy_is_none = borrows.economic_policy.is_none();
        let no_rules = borrows.consequence_rules.is_empty();
        let no_pricing = borrows.message_pricing.is_none();
        // Read the velocity tracker too (a fresh tracker reports zero).
        let no_velocity = borrows
            .velocity_tracker
            .get_velocity(&member_for_closure, 1_700_000_000)
            == 0;
        assert!(policy_is_none && no_rules && no_pricing && no_velocity);
        // Debit through the &mut while those reads are still in scope.
        borrows
            .budget_tracker
            .grant(&member_for_closure, Amount(700));
    })
    .await;

    assert_eq!(
        cell.governance.budget_tracker.remaining(&member),
        Amount(700),
        "budget debit landed through economy_pre_check_borrows.budget_tracker"
    );
}

// ------------------------------------------------------------------
// clear_committed_reservation_idempotent (foundation #2 — no-persist Class-S)
// ------------------------------------------------------------------

/// `clear_committed_reservation_idempotent` removes a present
/// caller-reservation straggler (returns `true`), is idempotent on a second
/// call (returns `false`), and performs NO persist.
#[tokio::test]
async fn clear_committed_reservation_idempotent_removes_then_noops() {
    use scp_runtime_core::context::supervisor::saga_prepared_state::CallerReservationRecord;

    let persist_calls = Arc::new(AtomicUsize::new(0));
    let deps = build_deps(Box::new(SpyPersistence {
        persist_calls: Arc::clone(&persist_calls),
    }))
    .await;
    let mut cell = ClassSCell::new(fresh_state(0x91));
    let ctx = ctx_hex(0x91);
    let saga_a = saga("saga-straggler");

    // Seed a straggler reservation via the test-only seed helper, which
    // routes through the sanctioned fail-closed combinator (no `state_mut`).
    let record = CallerReservationRecord {
        actor_did: DID("did:example:straggler".to_owned()),
        deducted_cost: None,
        needs_hard_rate_limit_refund: false,
        recorded_at_secs: 1_700_000_000,
        escrow_authorization: None,
    };
    seed_caller_reservation_for_test(&mut cell, &deps, &ctx, saga_a.clone(), record).await;

    // Snapshot the persist count AFTER the seed (the seed's combinator
    // persisted once, fail-closed); the clears below must add ZERO.
    let persist_after_seed = persist_calls.load(Ordering::SeqCst);

    // First clear removes the straggler.
    assert!(
        cell.clear_committed_reservation_idempotent(&saga_a),
        "first clear removes the present reservation"
    );
    assert!(
        !cell.class_s.xctx_caller_reservations.contains_key(&saga_a),
        "reservation gone after clear"
    );

    // Second clear is an idempotent no-op.
    assert!(
        !cell.clear_committed_reservation_idempotent(&saga_a),
        "second clear is an idempotent no-op (returns false)"
    );

    // The clear method NEVER persists — no combinator was invoked by either
    // clear call (the count is unchanged from the post-seed snapshot).
    assert_eq!(
        persist_calls.load(Ordering::SeqCst),
        persist_after_seed,
        "clear_committed_reservation_idempotent performs NO persist"
    );
}

// ------------------------------------------------------------------
// remove_subscriber (foundation #4 — broadcast-roster best-effort removal)
// ------------------------------------------------------------------

/// `MembershipClassCMut::remove_subscriber` removes a broadcast subscriber
/// from the roster (returns `true` when present, `false` when absent), via
/// the restricted Class-C membership view.
#[tokio::test]
async fn remove_subscriber_removes_from_roster() {
    let deps = build_deps(Box::new(OkPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x92));
    let ctx = ctx_hex(0x92);
    let sub = DID("did:example:broadcast-subscriber".to_owned());
    let sub_for_f = sub.clone();

    cell.commit_class_c_best_effort(&deps, &ctx, move |mut view| {
        let mut m = view.membership_class_c_mut();
        m.add_member(sub_for_f.clone(), "member".to_owned(), Vec::new());
        assert!(
            m.contains(sub_for_f.0.as_str()),
            "subscriber present after add"
        );
        // Remove the broadcast subscriber through the scoped removal.
        assert!(
            m.remove_subscriber(&sub_for_f),
            "remove_subscriber returns true for a present subscriber"
        );
        assert!(
            !m.contains(sub_for_f.0.as_str()),
            "subscriber gone after remove_subscriber"
        );
        // A second removal of the now-absent subscriber returns false.
        assert!(
            !m.remove_subscriber(&sub_for_f),
            "remove_subscriber returns false for an absent subscriber"
        );
    })
    .await;

    assert!(
        !cell.membership.contains(sub.0.as_str()),
        "subscriber removed from the underlying roster"
    );
}

/// Keep-direction: the mutation stays in memory whether or not the persist
/// lands, so `commit_class_s_keep` advances the epoch on the persist-failure
/// arm as well. A dispatch error after this combinator must keep the
/// replay marker.
#[tokio::test]
async fn mutation_epoch_advances_on_keep_even_when_persist_fails() {
    let deps = build_deps(Box::new(FailPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x92));
    let ctx = ctx_hex(0x92);

    let result = cell
        .commit_class_s_keep(&deps, &ctx, |mut view| {
            view.governance_class_s_mut().threshold_value = 7;
            Ok(())
        })
        .await;

    assert!(
        matches!(result, Err(ContextError::PersistenceFailed(_))),
        "persist failure surfaces; got {result:?}"
    );
    assert_eq!(
        cell.governance.class_s.threshold_value, 7,
        "keep-direction retains the mutation"
    );
    assert_eq!(
        cell.mutation_epoch(),
        1,
        "the retained mutation counts even though the persist failed"
    );
}

/// A closure that rejects before mutating hands nothing durable out, so the
/// epoch holds: a dispatch error raised by a helper's own pre-check must
/// leave the proposal retryable.
#[tokio::test]
async fn mutation_epoch_holds_when_the_closure_rejects() {
    let deps = build_deps(Box::new(OkPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x93));
    let ctx = ctx_hex(0x93);

    let result = cell
        .commit_class_s_keep(&deps, &ctx, |_view| {
            Err::<(), _>(ContextError::PermissionDenied("rejected".into()))
        })
        .await;

    assert!(
        matches!(result, Err(ContextError::PermissionDenied(_))),
        "the closure's rejection surfaces; got {result:?}"
    );
    assert_eq!(
        cell.mutation_epoch(),
        0,
        "a rejected closure applied nothing, so the epoch holds"
    );
}

/// Restore-direction: `commit_class_s_restore` rolls the Class-S state back
/// on persist failure, so nothing of `f` survives and the epoch holds; on a
/// landed persist the mutation survives and the epoch advances.
#[tokio::test]
async fn mutation_epoch_follows_the_restore_combinators_outcome() {
    let failing = build_deps(Box::new(FailPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x94));
    let ctx = ctx_hex(0x94);

    let result = cell
        .commit_class_s_restore(&failing, &ctx, |mut view| {
            view.governance_class_s_mut().threshold_value = 7;
            Ok(())
        })
        .await;
    assert!(
        matches!(result, Err(ContextError::PersistenceFailed(_))),
        "persist failure surfaces; got {result:?}"
    );
    assert_eq!(
        cell.governance.class_s.threshold_value, 0,
        "restore-direction rolled the mutation back"
    );
    assert_eq!(
        cell.mutation_epoch(),
        0,
        "a rolled-back mutation leaves no effect, so the epoch holds"
    );

    let ok = build_deps(Box::new(OkPersistence)).await;
    cell.commit_class_s_restore(&ok, &ctx, |mut view| {
        view.governance_class_s_mut().threshold_value = 9;
        Ok(())
    })
    .await
    .expect("persist lands");
    assert_eq!(
        cell.mutation_epoch(),
        1,
        "a persisted restore-direction mutation counts once"
    );
}

/// `commit_class_c_best_effort` applies a Class-C mutation in memory and
/// advances the epoch once, regardless of the best-effort persist.
#[tokio::test]
async fn mutation_epoch_advances_on_commit_class_c_best_effort() {
    let deps = build_deps(Box::new(FailPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x95));
    let ctx = ctx_hex(0x95);

    cell.commit_class_c_best_effort(&deps, &ctx, |mut view| {
        view.members_mut()
            .insert(DID("did:example:best-effort-member".to_owned()));
    })
    .await;

    assert_eq!(
        cell.mutation_epoch(),
        1,
        "the in-memory Class-C mutation counts even when its best-effort persist fails"
    );
}

/// The deferred-persist token flow advances the epoch at `begin_class_s`
/// (the early mutation) and again at `discharge_with` (the final mutation),
/// so `execute_governance_action` reads its baseline AFTER its own
/// `begin_class_s` and before the dispatch.
#[tokio::test]
async fn mutation_epoch_advances_at_begin_and_at_discharge() {
    let deps = build_deps(Box::new(OkPersistence)).await;
    let mut cell = ClassSCell::new(fresh_state(0x96));
    let ctx = ctx_hex(0x96);

    let ((), token) = cell
        .begin_class_s(&ctx, |mut view| {
            view.governance_class_s_mut().threshold_value = 3;
            Ok(())
        })
        .expect("begin");
    assert_eq!(
        cell.mutation_epoch(),
        1,
        "the early mutation counts at begin"
    );

    token
        .discharge_with(&mut cell, &deps, &ctx, |mut view| {
            view.governance_class_s_mut().threshold_value = 4;
            Ok(())
        })
        .await
        .expect("discharge");
    assert_eq!(
        cell.mutation_epoch(),
        2,
        "the discharge mutation counts once more"
    );
}

/// Persistence that accepts every write (success path).
struct OkPersistence;
/// Persistence whose `persist_context` ALWAYS fails (fail-closed path).
struct FailPersistence;

macro_rules! impl_persistence {
    ($ty:ty, $persist_result:expr) => {
        #[async_trait::async_trait]
        impl ContextPersistence for $ty {
            async fn persist_context(
                &self,
                _: &str,
                _: &scp_runtime_core::context::state::ContextSnapshot,
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                $persist_result
            }
            async fn load_context(
                &self,
                _: &str,
            ) -> Result<
                Option<scp_runtime_core::context::state::ContextSnapshot>,
                Box<dyn std::error::Error + Send + Sync>,
            > {
                Ok(None)
            }
            async fn delete_context(
                &self,
                _: &str,
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Ok(())
            }
            async fn list_persisted_contexts(
                &self,
            ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
                Ok(Vec::new())
            }
        }
    };
}

impl_persistence!(OkPersistence, Ok(()));
impl_persistence!(FailPersistence, Err("induced persist failure".into()));
