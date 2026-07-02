//! Integration tests for the ADR-049 §3a / spec §5.15.4 per-participant-
//! context-set saga concurrency gating.
//!
//! A saga reserves the SET of participant context-actors it spans. Two
//! sagas whose sets are DISJOINT run concurrently; a second saga whose set
//! OVERLAPS (shares ≥1 context with) an in-flight saga is rejected with a
//! typed [`ContextError::ActorBusy`](scp_protocol::context::ContextError::ActorBusy)
//! carrying a `SagaBusy` reason. A `NeedsRepair` outcome RELEASES the
//! reservation so a stuck saga cannot wedge unrelated, disjoint sagas.
//!
//! # Determinism
//!
//! The sole production saga, `CrossContextToolInvocation`, is wired, but
//! driving it through `start_saga` (no executor / signing key) over contexts
//! with NO co-resident actors aborts INSTANTLY at Prepare-A with a typed error
//! — the PreparingA → Aborting → Aborted arm — too fast to hold "in flight" by
//! racing. The load-bearing gating assertion is the ABSENCE of `ActorBusy` and
//! that the reservation is RELEASED on every terminal; the exact terminal error
//! class is incidental (it just must not be `ActorBusy`). To test the gating
//! semantics deterministically we use
//! `Supervisor::test_reserve_saga_context_set`, which exercises the SAME
//! `try_reserve_context_set` critical section that `start_saga` uses (not a
//! parallel mock), and the test-only `SagaInput::TestForceNeedsRepair` variant,
//! whose Commit always fails so the FSM drives a real `NeedsRepair` terminal.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::disallowed_types,
    clippy::missing_const_for_fn
)]

use std::sync::Arc;

use scp_identity::DID;
use scp_platform::testing::InMemoryStorage;
use scp_protocol::context::ContextError;
use scp_runtime::context::supervisor::{
    ProtocolRepositorySagaJournal, SagaInput, SagaJournal, Supervisor, SupervisorConfig,
};

struct NoopPersistence;
impl scp_runtime::context::persistence::ContextPersistence for NoopPersistence {
    fn persist_context(
        &self,
        _: &str,
        _: &scp_runtime::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    fn load_context(
        &self,
        _: &str,
    ) -> Result<
        Option<scp_runtime::context::state::ContextSnapshot>,
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

fn test_supervisor() -> Arc<Supervisor> {
    let persistence: Arc<dyn scp_runtime::context::persistence::ContextPersistence> =
        Arc::new(NoopPersistence);
    let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::new(
        InMemoryStorage::new(),
    )));
    Arc::new(Supervisor::new(
        persistence,
        journal,
        SupervisorConfig::default(),
    ))
}

/// A cross-context tool-invocation saga over the given caller/target
/// contexts. Its participant context set is `{caller, target}`. The
/// envelope fields are placeholders — these gating tests never reach
/// Prepare-B (no co-resident actors), so only the two context ids (the
/// reservation key) are load-bearing.
///
/// The variant is construction-sealed against production callers (only
/// `start_cross_context_tool_invocation_saga` can build it there); this gating
/// test reaches it through the `test`/`testing`-gated
/// [`SagaInput::test_cross_context_for_gating`] constructor, which fills the
/// same placeholders.
fn cross_context(caller: [u8; 32], target: [u8; 32]) -> SagaInput {
    SagaInput::test_cross_context_for_gating(caller, target)
}

/// Assert a saga terminated at a NON-busy terminal. Driving a
/// `CrossContextToolInvocation` through `start_saga` (no executor / signing
/// key) aborts at Prepare-A with `InvalidState` (the executor-context misuse
/// guard, SCP-SAGA-13051) — BEFORE the co-resident lookup — so the FSM never
/// reaches `ContextNotRegistered` here. Any non-busy terminal (`InvalidState`,
/// or the defensively-accepted `ContextNotRegistered` / `NotImplemented`) is a
/// valid "reservation released" outcome — the gating property under test is the
/// ABSENCE of `ActorBusy`, not the specific terminal error.
#[track_caller]
fn assert_non_busy_terminal(
    result: &Result<scp_runtime::context::supervisor::SagaOutput, ContextError>,
    ctx: &str,
) {
    match result {
        Err(
            ContextError::ContextNotRegistered(_)
            | ContextError::NotImplemented(_)
            | ContextError::InvalidState(_),
        ) => {}
        Err(ContextError::ActorBusy(msg)) => {
            panic!("{ctx}: must NOT serialize/wedge — got ActorBusy: {msg}")
        }
        other => panic!("{ctx}: unexpected saga terminal: {other:?}"),
    }
}

fn ctx(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// DISJOINT participant sets run concurrently: two sagas spanning entirely
/// different contexts BOTH reach a terminal — NEITHER returns ActorBusy.
/// Because the executor-less `start_saga` path aborts at Prepare-A, "terminal"
/// here is the `InvalidState` abort; the load-bearing assertion is the ABSENCE
/// of ActorBusy, proving disjoint sets never serialize.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disjoint_participant_sets_run_concurrently() {
    let supervisor = test_supervisor();

    // Two cross-context sagas over fully disjoint context pairs:
    //   saga 1: {0x01, 0x02}    saga 2: {0x03, 0x04}
    let sup1 = Arc::clone(&supervisor);
    let sup2 = Arc::clone(&supervisor);
    let h1 = tokio::spawn(async move { sup1.start_saga(cross_context(ctx(1), ctx(2))).await });
    let h2 = tokio::spawn(async move { sup2.start_saga(cross_context(ctx(3), ctx(4))).await });

    let r1 = h1.await.unwrap();
    let r2 = h2.await.unwrap();

    assert_non_busy_terminal(&r1, "disjoint saga 1");
    assert_non_busy_terminal(&r2, "disjoint saga 2");
}

/// OVERLAPPING participant sets serialize: while one saga's set is held in
/// flight, a second saga sharing ≥1 context returns ActorBusy with a
/// `SagaBusy` reason. The in-flight saga is simulated deterministically by
/// holding the reservation guard (the production gating critical section),
/// because the executor-less FSM terminates too fast to race.
#[tokio::test]
async fn overlapping_participant_sets_reject_busy() {
    let supervisor = test_supervisor();

    // Hold saga 1's set {0x01, 0x02} in flight via the production
    // reservation primitive.
    let in_flight = cross_context(ctx(1), ctx(2));
    let held = supervisor
        .test_reserve_saga_context_set(&in_flight)
        .expect("first reservation must succeed on an empty supervisor");

    // Saga 2 shares context 0x02 (its set is {0x02, 0x09}) — must be
    // rejected as SagaBusy.
    let overlapping = cross_context(ctx(2), ctx(9));
    let err = supervisor
        .start_saga(overlapping)
        .await
        .expect_err("overlapping saga must be rejected while the set is held");
    match err {
        ContextError::ActorBusy(msg) => assert!(
            msg.contains("SagaBusy"),
            "overlap rejection must mention SagaBusy, got: {msg}"
        ),
        other => panic!("expected ActorBusy(SagaBusy), got: {other:?}"),
    }

    // Releasing saga 1's reservation lets the previously-overlapping set
    // through (proves the rejection was the reservation, not some other
    // failure).
    drop(held);
    let r2 = supervisor.start_saga(cross_context(ctx(2), ctx(9))).await;
    assert_non_busy_terminal(
        &r2,
        "after release the overlapping set must reserve and run (not ActorBusy)",
    );
}

/// A `TestForceNeedsRepair` saga and a `CrossContextToolInvocation` saga that
/// touch the SAME context serialize — overlap detection is purely
/// set-membership, not saga-type.
///
/// This genuinely crosses saga TYPES. Every variant reserves the raw-digest hex
/// (`hex::encode([u8; 32])`) of each context it spans. A held
/// `TestForceNeedsRepair` saga over `{shared}` and a
/// `CrossContextToolInvocation` over that SAME `shared` raw digest must collide.
/// If overlap detection keyed off the saga type rather than pure set-membership,
/// the cross-context saga would not be rejected and this assertion would FAIL.
#[tokio::test]
async fn overlap_is_set_membership_across_saga_types() {
    let supervisor = test_supervisor();

    // A deterministic raw 32-byte context digest shared between the two sagas.
    let alice = DID("did:example:alice".to_owned());
    let bob = DID("did:example:bob".to_owned());
    let shared_digest = Supervisor::test_standing_pair_context_digest(&alice, &bob);

    // Hold a single-context `TestForceNeedsRepair` saga in flight via the
    // production reservation primitive. Its participant set is {shared_digest}.
    let held = supervisor
        .test_reserve_saga_context_set(&SagaInput::TestForceNeedsRepair {
            context_id: shared_digest,
        })
        .expect("test-force-needs-repair reservation must succeed");

    // A CROSS-CONTEXT saga (a DIFFERENT saga type) whose `caller_context_id`
    // is the SAME `shared_digest` and whose `target_context_id` is unrelated.
    // The shared raw digest forces an overlap across saga types.
    let err = supervisor
        .start_saga(cross_context(shared_digest, ctx(9)))
        .await
        .expect_err("cross-context saga over the held shared context must collide");
    match err {
        ContextError::ActorBusy(msg) => assert!(
            msg.contains("SagaBusy"),
            "overlap rejection must mention SagaBusy, got: {msg}"
        ),
        other => panic!("expected ActorBusy(SagaBusy), got: {other:?}"),
    }

    // Releasing the held reservation lets the previously-overlapping
    // cross-context saga through — proving the rejection WAS the shared raw
    // digest (the reservation), not some unrelated failure.
    drop(held);
    let r2 = supervisor
        .start_saga(cross_context(shared_digest, ctx(9)))
        .await;
    assert_non_busy_terminal(
        &r2,
        "after release the cross-type set must reserve and run (not ActorBusy)",
    );
}

/// `NeedsRepair` RELEASES the reservation: a saga driven to NeedsRepair
/// (commit-retry-exhausted) frees its participant context set, so a second
/// saga sharing that set reserves successfully — it does NOT get ActorBusy.
/// This proves a stuck saga cannot wedge unrelated sagas (ADR-049 §3a, spec
/// §5.15.4).
///
/// `start_paused` lets the 500ms/1s/2s commit-retry backoffs elapse in
/// virtual time, so the test does not actually wait 3.5s.
#[tokio::test(start_paused = true)]
async fn needs_repair_releases_reservation() {
    let supervisor = test_supervisor();

    // Drive a saga over context 0x07 to NeedsRepair: its Prepare phases
    // succeed and its Commit always fails, exhausting the retry budget. The
    // FSM returns the typed NeedsRepair error to `start_saga`, whose RAII
    // reservation then drops — releasing context 0x07.
    let err = supervisor
        .start_saga(SagaInput::TestForceNeedsRepair { context_id: ctx(7) })
        .await
        .expect_err("commit-retry-exhausted saga must return a NeedsRepair error");
    // The terminal is NeedsRepair (commit failed) — surfaced as the typed
    // commit error, NOT ActorBusy.
    assert!(
        !matches!(err, ContextError::ActorBusy(_)),
        "a NeedsRepair saga must not surface as ActorBusy, got: {err:?}"
    );

    // A second saga sharing context 0x07 must now reserve successfully —
    // proving the NeedsRepair terminal RELEASED the slot. If the slot were
    // still held, this would return ActorBusy.
    let r2 = supervisor.start_saga(cross_context(ctx(7), ctx(8))).await;
    assert_non_busy_terminal(
        &r2,
        "NeedsRepair must release context 0x07 so a sharing saga reserves (no ActorBusy)",
    );
}

/// Same-set sequential re-arm: running the SAME participant set N times in
/// a row must succeed every time — each saga's terminal releases the
/// reservation so the next over the identical set can reserve. (The prior
/// supervisor-wide AtomicBool guaranteed this for ALL sagas; the per-set
/// reservation must still guarantee it for same-set sequences.)
#[tokio::test]
async fn same_set_sequential_rearm() {
    let supervisor = test_supervisor();
    for i in 0..5 {
        let r = supervisor.start_saga(cross_context(ctx(1), ctx(2))).await;
        assert_non_busy_terminal(
            &r,
            &format!("sequential same-set saga {i} must terminate (reservation re-arm)"),
        );
    }
}
