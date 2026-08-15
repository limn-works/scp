//! Integration test for the ADR-049 commit-11 saga crash-recovery
//! path.
//!
//! On supervisor startup, `Supervisor::replay_unresolved_sagas`
//! reads the journal's latest unresolved entries and dispatches
//! per-state recovery:
//!   - `Initiated` — discard (Prepare-A never dispatched, no remote
//!     side-effects yet).
//!   - `PreparingA` / `PreparingB` — record-keyed reversal-and-confirm
//!     (Prepare-A durably staged the caller deduction + reservation
//!     record before the PreparingB journal append, so a crash in
//!     either window may leave a live durable reservation): reverse the
//!     caller's LOCAL economy from the durable record and mark terminal
//!     only on a confirmed reversal, else leave non-terminal. A
//!     non-xctx entry (no caller triple) has nothing to reverse and is
//!     marked terminal directly.
//!   - `Committing` / `Aborting` — emit `NeedsRepair` for operator
//!     review.
//!   - `NeedsRepair` — carry over (operator intervention required).
//!
//! These tests inject synthetic unresolved entries for each state and
//! verify the post-replay observable state of the journal.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::disallowed_types,
    clippy::missing_const_for_fn
)]

use std::sync::Arc;

use scp_platform::in_memory::InMemoryStorage;
use scp_runtime::context::supervisor::{
    JournalEntry, ProtocolRepositorySagaJournal, RestoredContexts, SagaId, SagaJournal, SagaState,
    Supervisor, SupervisorConfig,
};

struct NoOpPersistence;
#[async_trait::async_trait]
impl scp_runtime::context::persistence::ContextPersistence for NoOpPersistence {
    async fn persist_context(
        &self,
        _: &str,
        _: &scp_runtime::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    async fn load_context(
        &self,
        _: &str,
    ) -> Result<
        Option<scp_runtime::context::state::ContextSnapshot>,
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

async fn inject(
    journal: &ProtocolRepositorySagaJournal<InMemoryStorage>,
    saga_id: &SagaId,
    state: SagaState,
    seq: u64,
) {
    journal
        .append(JournalEntry {
            saga_id: saga_id.clone(),
            state,
            participants: vec!["did:example:participant-a".into()],
            evidence: zeroize::Zeroizing::new(b"synthetic".to_vec()),
            timestamp_ms: 1_800_000_000_000 + seq,
            seq_per_saga: seq,
        })
        .await
        .unwrap();
}

fn build_supervisor(storage: &Arc<InMemoryStorage>) -> Supervisor {
    let persistence: Arc<dyn scp_runtime::context::persistence::ContextPersistence> =
        Arc::new(NoOpPersistence);
    let journal: Arc<dyn SagaJournal> =
        Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(storage)));
    Supervisor::new(persistence, journal, SupervisorConfig::default())
}

/// Multiple saga states in the same journal — replay handles each per
/// its classification and the coordinator ends with the expected
/// per-state resolution.
#[tokio::test]
async fn replay_mixed_states_resolves_each_per_classification() {
    let storage = Arc::new(InMemoryStorage::new());
    let probe_journal = ProtocolRepositorySagaJournal::new(Arc::clone(&storage));

    // Inject one saga per non-terminal state.
    let s_initiated = SagaId::new();
    inject(&probe_journal, &s_initiated, SagaState::Initiated, 0).await;

    let s_preparing_a = SagaId::new();
    inject(&probe_journal, &s_preparing_a, SagaState::Initiated, 0).await;
    inject(&probe_journal, &s_preparing_a, SagaState::PreparingA, 1).await;

    let s_preparing_b = SagaId::new();
    inject(&probe_journal, &s_preparing_b, SagaState::PreparingA, 0).await;
    inject(&probe_journal, &s_preparing_b, SagaState::PreparingB, 1).await;

    let s_committing = SagaId::new();
    inject(&probe_journal, &s_committing, SagaState::PreparingB, 0).await;
    inject(&probe_journal, &s_committing, SagaState::Committing, 1).await;

    let s_needs_repair = SagaId::new();
    inject(&probe_journal, &s_needs_repair, SagaState::NeedsRepair, 0).await;

    // Pre-replay: 5 unresolved sagas.
    let pre = probe_journal.load_unresolved().await.unwrap();
    assert_eq!(
        pre.len(),
        5,
        "5 synthetic unresolved sagas expected, got {pre:?}"
    );

    // Build a supervisor — replay happens manually (not from new). This harness
    // wires no persistence provider, so it cannot obtain a `RestoredContexts`
    // witness from a real `restore_all_contexts`; the `saga-witness-test-mint`-gated `for_test`
    // mints the empty witness that proves restore-then-replay ordering to the
    // type system (these tests exercise the replay arms in isolation).
    let supervisor = build_supervisor(&storage);
    supervisor
        .replay_unresolved_sagas(&RestoredContexts::for_test(Vec::new()))
        .await
        .unwrap();

    // Post-replay: Initiated, PreparingA, PreparingB resolved to
    // Aborted; Committing transitioned to NeedsRepair;
    // existing NeedsRepair is carryover. So load_unresolved returns
    // exactly 2 sagas — the two NeedsRepair entries.
    let post = probe_journal.load_unresolved().await.unwrap();
    let needs_repair_count = post
        .iter()
        .filter(|e| e.state == SagaState::NeedsRepair)
        .count();
    assert_eq!(
        needs_repair_count, 2,
        "expected 2 NeedsRepair entries post-replay, got: {post:?}"
    );
    let others_count = post
        .iter()
        .filter(|e| e.state != SagaState::NeedsRepair)
        .count();
    assert_eq!(
        others_count, 0,
        "no non-NeedsRepair entries must remain, got: {post:?}"
    );
}

/// Replay is idempotent — a second call is a no-op once all sagas are
/// resolved.
#[tokio::test]
async fn replay_is_idempotent_after_first_pass() {
    let storage = Arc::new(InMemoryStorage::new());
    let probe_journal = ProtocolRepositorySagaJournal::new(Arc::clone(&storage));

    let saga_id = SagaId::new();
    inject(&probe_journal, &saga_id, SagaState::Initiated, 0).await;

    let supervisor = build_supervisor(&storage);
    supervisor
        .replay_unresolved_sagas(&RestoredContexts::for_test(Vec::new()))
        .await
        .unwrap();

    // Second replay must succeed without side effects.
    supervisor
        .replay_unresolved_sagas(&RestoredContexts::for_test(Vec::new()))
        .await
        .unwrap();
    let post = probe_journal.load_unresolved().await.unwrap();
    assert!(post.is_empty(), "second replay must leave journal stable");
}

/// Replay over an empty journal must succeed.
#[tokio::test]
async fn replay_on_empty_journal_succeeds() {
    let storage = Arc::new(InMemoryStorage::new());
    let supervisor = build_supervisor(&storage);
    supervisor
        .replay_unresolved_sagas(&RestoredContexts::for_test(Vec::new()))
        .await
        .unwrap();
}

/// Process-restart bootstrap wiring (ADR-049), §17.16.4
/// restore-THEN-replay ordering, FAIL-CLOSED half: a fresh supervisor over
/// storage that durably retains an unresolved saga journal entry runs the
/// single startup entry point `Supervisor::restore_on_startup`, whose RESTORE
/// leg runs FIRST. This lightweight `Supervisor::new` harness wires no
/// helper-side persistence provider (production builds go through
/// `with_providers`), so the restore leg fails with `PersistenceFailed` and —
/// because restore precedes replay and short-circuits on `?` — the replay leg
/// does NOT run, so the orphaned saga is left UNRESOLVED for the next process
/// start. This pins the fail-closed property: a failed restore must not let
/// recovery proceed against an un-restored (non-resident) world.
///
/// The companion POSITIVE proof — that with a REAL persistence provider the
/// restore leg SUCCEEDS and the replay leg then resolves the orphan and
/// DELIVERS the cross-context caller refund — is the unit gate
/// `restore_on_startup_xctx_caller_reversal_delivered_entry_terminal` in
/// `supervisor.rs`, where the full provider bootstrap (and a helper-persistence-
/// wired supervisor) is reachable. This integration crate can only construct a
/// `Supervisor::new` harness (no helper persistence), so it carries the
/// fail-closed half. The structural ordering + bootstrap-routing guards are in
/// `pipeline_wiring.rs` (`restore_on_startup_runs_restore_before_replay`,
/// `bridge_resume_path_routes_through_restore_on_startup`).
#[tokio::test]
async fn restore_on_startup_fails_closed_when_restore_leg_errors() {
    // First "process": durably journal an unresolved saga, then crash
    // (drop the supervisor) WITHOUT resolving it.
    let storage = Arc::new(InMemoryStorage::new());
    let probe_journal = ProtocolRepositorySagaJournal::new(Arc::clone(&storage));
    let saga_id = SagaId::new();
    inject(&probe_journal, &saga_id, SagaState::Initiated, 0).await;

    let pre = probe_journal.load_unresolved().await.unwrap();
    assert_eq!(
        pre.len(),
        1,
        "one synthetic unresolved saga must survive the crash, got {pre:?}"
    );

    // Second "process": a fresh supervisor over the SAME durable storage with no
    // helper-side persistence provider, so the restore leg returns
    // `PersistenceFailed`.
    let persistence: Arc<dyn scp_runtime::context::persistence::ContextPersistence> =
        Arc::new(NoOpPersistence);
    let journal: Arc<dyn SagaJournal> =
        Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let restarted = Arc::new(Supervisor::new(
        persistence,
        journal,
        SupervisorConfig::default(),
    ));

    // The bootstrap entry point — no manual replay_unresolved_sagas() call.
    let startup = restarted.restore_on_startup().await;

    // Restore ran FIRST and failed, so replay never ran: the orphaned saga is
    // STILL unresolved (carried to the next process start). With the OLD
    // replay-before-restore ordering this would instead be empty — so this
    // assertion also pins the new restore-then-replay order at runtime.
    let post = probe_journal.load_unresolved().await.unwrap();
    assert_eq!(
        post.len(),
        1,
        "restore_on_startup must fail closed: a failed restore leg short-circuits BEFORE replay, \
         leaving the orphaned journal entry unresolved for the next process start, got {post:?}"
    );

    // The startup surfaced the restore-leg `PersistenceFailed` (fail-closed) —
    // it did not silently swallow it.
    match startup {
        Err(scp_protocol::context::ContextError::PersistenceFailed(_)) => {}
        other => panic!(
            "expected restore_on_startup to surface the restore leg's PersistenceFailed \
             (fail-closed), got {other:?}"
        ),
    }
}
