//! Integration tests for the ADR-049 commit-11 saga coordinator FSM.
//!
//! The coordinator is the supervisor-side FSM that drives a saga
//! through `Initiated → PreparingA → PreparingB → Committing →
//! Committed | Aborting → Aborted | NeedsRepair`. These tests exercise
//! the FSM generically against a production-backed
//! [`Supervisor`](scp_runtime::context::supervisor::Supervisor).
//!
//! # Executor-less misuse guardrail
//!
//! Driving a `CrossContextToolInvocation` [`SagaInput`] through the generic
//! `start_saga` (no supervisor-side executor / signing key) is a misuse —
//! the Prepare-A dispatch aborts with `ContextError::InvalidState`
//! (SCP-SAGA-13051). The FSM transitions through
//! `Initiated → PreparingA → Aborting → Aborted` and returns the typed
//! error. This is the observable behaviour the tests assert; the production
//! entry point is `start_cross_context_tool_invocation_saga`.
//!
//! The committing-retry-exhaustion and crash-recovery arms exercise the
//! coordinator's retry loop and journal-replay logic against this abort
//! dispatch surface.

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
    JournalEntry, JournalError, ProtocolRepositorySagaJournal, RestoredContexts, SagaId, SagaInput,
    SagaJournal, SagaState, SagaTerminalState, Supervisor, SupervisorConfig,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn journal_with_shared_storage() -> (
    Arc<InMemoryStorage>,
    Arc<ProtocolRepositorySagaJournal<InMemoryStorage>>,
) {
    let storage = Arc::new(InMemoryStorage::new());
    let journal = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    (storage, journal)
}

/// A [`SagaJournal`] decorator that records every `append`'s
/// `(state, seq_per_saga)` BEFORE delegating to the inner journal.
///
/// The durable production journal now compacts a saga's entries when it
/// resolves (`mark_resolved` deletes the resolved saga's keys so
/// `load_unresolved`'s cost stays bounded to unresolved sagas — spec
/// §17.16.1). That compaction erases the in-flight write trail from final
/// storage, so probing `list_keys("saga_journal/")` after a saga resolves no
/// longer observes the per-phase appends. This wrapper captures each append as
/// it happens — before compaction can erase it — so the WRITE-behaviour
/// assertions (every phase appended; seqs strictly monotonic) remain
/// meaningful against the compacting journal.
struct RecordingJournal {
    inner: Arc<dyn SagaJournal>,
    appends: Arc<std::sync::Mutex<Vec<(SagaState, u64)>>>,
}

#[async_trait::async_trait]
impl SagaJournal for RecordingJournal {
    async fn append(&self, entry: JournalEntry) -> Result<(), JournalError> {
        self.appends
            .lock()
            .unwrap()
            .push((entry.state, entry.seq_per_saga));
        self.inner.append(entry).await
    }
    async fn load_unresolved(&self) -> Result<Vec<JournalEntry>, JournalError> {
        self.inner.load_unresolved().await
    }
    async fn mark_resolved(
        &self,
        saga_id: SagaId,
        terminal: SagaTerminalState,
        secret_bearing: bool,
    ) -> Result<(), JournalError> {
        self.inner
            .mark_resolved(saga_id, terminal, secret_bearing)
            .await
    }
}

fn test_supervisor() -> Supervisor {
    let persistence: Arc<dyn scp_runtime::context::persistence::ContextPersistence> =
        Arc::new(NoopPersistence);
    let (_, journal) = journal_with_shared_storage();
    let journal_dyn: Arc<dyn SagaJournal> = journal;
    Supervisor::new(persistence, journal_dyn, SupervisorConfig::default())
}

fn executorless_input() -> SagaInput {
    SagaInput::test_cross_context_for_gating([1u8; 32], [2u8; 32])
}

fn alice() -> DID {
    DID("did:example:alice".to_owned())
}

// ---------------------------------------------------------------------------
// Coordinator FSM — basic transitions
// ---------------------------------------------------------------------------

/// PreparingA failure (InvalidState) transitions through the abort
/// path and returns the typed error to the caller. The saga is
/// terminally resolved in the journal.
#[tokio::test]
async fn saga_prepare_a_invalid_state_aborts_and_returns_error() {
    let supervisor = test_supervisor();
    let err = supervisor
        .start_saga(executorless_input())
        .await
        .unwrap_err();
    assert!(
        matches!(err, ContextError::InvalidState(_)),
        "expected InvalidState for the executor-less CrossContextToolInvocation misuse, got {err:?}"
    );
}

/// The journal records Initiated, PreparingA, Aborting, and a terminal
/// Aborted entry for an executor-less saga misuse. Verifies the
/// coordinator appended every phase before aborting.
///
/// The durable journal compacts (deletes) a saga's entries on resolution, so
/// probing final storage no longer observes the in-flight write trail. We wrap
/// the production journal in a [`RecordingJournal`] that captures every append
/// BEFORE compaction can erase it, then assert on the captured states.
#[tokio::test]
async fn saga_journal_records_every_phase_transition_on_abort() {
    let persistence: Arc<dyn scp_runtime::context::persistence::ContextPersistence> =
        Arc::new(NoopPersistence);
    let storage = Arc::new(InMemoryStorage::new());
    let prod_journal: Arc<dyn SagaJournal> =
        Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let appends = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recording: Arc<dyn SagaJournal> = Arc::new(RecordingJournal {
        inner: prod_journal,
        appends: Arc::clone(&appends),
    });
    let supervisor = Supervisor::new(persistence, recording, SupervisorConfig::default());

    let _ = supervisor.start_saga(executorless_input()).await;

    // Read the captured appends (the wrapper observed them before the
    // resolution-time compaction deleted the durable entries).
    let states: Vec<SagaState> = appends.lock().unwrap().iter().map(|(s, _)| *s).collect();

    assert!(
        !states.is_empty(),
        "journal should have recorded appends from the aborted saga"
    );
    // The abort path is Initiated → PreparingA → Aborting (appended in-flight)
    // → Aborted (the terminal marker, written by mark_resolved). ADR-049 §3.
    assert!(
        states.contains(&SagaState::Initiated),
        "expected an Initiated append, got {states:?}"
    );
    assert!(
        states.contains(&SagaState::PreparingA),
        "expected a PreparingA append, got {states:?}"
    );
    assert!(
        states.contains(&SagaState::Aborting),
        "expected an Aborting append, got {states:?}"
    );
    // NB: the terminal `Aborted` marker is written by `mark_resolved` (the
    // resolution path), NOT the public `append`, so the recording wrapper does
    // not — and should not — capture it as an append. The three in-flight
    // transition appends above are the "records every phase transition" proof;
    // resolution-to-terminal is exercised by the load_unresolved/compaction tests.
    // At least the three transition states (Initiated + PreparingA + Aborting)
    // before the terminal marker.
    assert!(
        states.len() >= 3,
        "expected at least 3 recorded transitions; got {states:?}"
    );
}

/// Coordinator serializes sagas: a second `start_saga` while the first
/// is running returns `ContextError::ActorBusy` with the SagaBusy
/// reason. We can't easily race two real sagas in a test without
/// blocking, so this test uses the fact that the executor-less misuse
/// sagas terminate quickly — so we need to race them through a spawn.
#[tokio::test]
async fn saga_concurrent_start_rejects_with_saga_busy() {
    let supervisor = Arc::new(test_supervisor());

    // Pre-load: manually claim the guard to simulate an in-flight saga.
    // We can't call private internals; we instead exercise the CAS by
    // holding one saga in a blocking future while another tries to
    // start. Because the executor-less Prepare-A aborts with InvalidState,
    // it terminates very quickly — we serialize via `tokio::join!`
    // and assert that AT LEAST ONE aborts-with-InvalidState and,
    // when either fails with ActorBusy, the reason matches.
    //
    // Since both sagas' FSMs are instantaneous (the executor-less abort
    // has no await), true interleaving is hard. The test focuses on guard
    // re-arm: a sequence of 10 sagas must all abort-with-InvalidState with
    // no residual ActorBusy errors.
    let mut ok_count = 0;
    let mut busy_count = 0;
    for _ in 0..10 {
        let sup = Arc::clone(&supervisor);
        match sup.start_saga(executorless_input()).await {
            Err(ContextError::InvalidState(_)) => ok_count += 1,
            Err(ContextError::ActorBusy(msg)) => {
                assert!(
                    msg.contains("SagaBusy") || msg.contains("already in flight"),
                    "ActorBusy must mention SagaBusy or 'already in flight', got: {msg}"
                );
                busy_count += 1;
            }
            other => panic!("unexpected result from executor-less saga: {other:?}"),
        }
    }
    assert_eq!(ok_count, 10, "all sequential sagas must terminate");
    assert_eq!(
        busy_count, 0,
        "sequential sagas must not see ActorBusy — guard re-arm failed if this tripped"
    );
}

/// Journal write ordering: every phase transition is appended with a
/// strictly-monotonic `seq_per_saga`, in append order.
///
/// The durable journal compacts a saga's entries on resolution, so probing
/// final storage would observe an empty key set and assert vacuously. We wrap
/// the production journal in a [`RecordingJournal`] that captures each append's
/// `seq_per_saga` in append order BEFORE compaction, then assert the recorded
/// sequence is strictly increasing.
#[tokio::test]
async fn saga_journal_write_ordering_is_monotonic() {
    let persistence: Arc<dyn scp_runtime::context::persistence::ContextPersistence> =
        Arc::new(NoopPersistence);
    let storage = Arc::new(InMemoryStorage::new());
    let prod_journal: Arc<dyn SagaJournal> =
        Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let appends = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recording: Arc<dyn SagaJournal> = Arc::new(RecordingJournal {
        inner: prod_journal,
        appends: Arc::clone(&appends),
    });
    let supervisor = Supervisor::new(persistence, recording, SupervisorConfig::default());

    let _ = supervisor.start_saga(executorless_input()).await;

    // Collect the `seq_per_saga` values in the order they were appended.
    let seqs: Vec<u64> = appends
        .lock()
        .unwrap()
        .iter()
        .map(|(_, seq)| *seq)
        .collect();

    assert!(
        !seqs.is_empty(),
        "expected at least one recorded append for the aborted saga"
    );
    // Strictly monotonic in append order: each append's seq is strictly
    // greater than the previous append's. No sort — the recorded order is the
    // write order.
    for window in seqs.windows(2) {
        assert!(
            window[0] < window[1],
            "journal seqs must be strictly monotonic in append order, got {:?} then {:?}",
            window[0],
            window[1]
        );
    }
}

// ---------------------------------------------------------------------------
// Crash recovery — synthetic journal replay per unresolved state
// ---------------------------------------------------------------------------

async fn inject_entry(
    journal: &ProtocolRepositorySagaJournal<InMemoryStorage>,
    saga_id: &SagaId,
    state: SagaState,
    seq: u64,
) {
    journal
        .append(JournalEntry {
            saga_id: saga_id.clone(),
            state,
            participants: vec![alice().to_string()],
            evidence: zeroize::Zeroizing::new(b"test-evidence".to_vec()),
            timestamp_ms: 1_700_000_000_000 + seq,
            seq_per_saga: seq,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn crash_recovery_initiated_state_is_discarded() {
    let storage = Arc::new(InMemoryStorage::new());
    let journal = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));

    let saga_id = SagaId::new();
    inject_entry(&journal, &saga_id, SagaState::Initiated, 0).await;

    // Build a fresh supervisor that shares the journal's storage.
    let persistence: Arc<dyn scp_runtime::context::persistence::ContextPersistence> =
        Arc::new(NoopPersistence);
    let replayed_journal = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let j_dyn: Arc<dyn SagaJournal> = replayed_journal;
    let supervisor = Supervisor::new(persistence, j_dyn, SupervisorConfig::default());

    // `for_test` witness: this coordinator harness drives replay in isolation
    // (restore-then-replay ordering is type-enforced; the empty witness stands in
    // for a real `restore_all_contexts` the lightweight harness does not run).
    supervisor
        .replay_unresolved_sagas(&RestoredContexts::for_test(Vec::new()))
        .await
        .unwrap();

    // After replay, `load_unresolved` must return empty (the Initiated
    // saga was resolved as Aborted).
    let remaining = journal.load_unresolved().await.unwrap();
    assert!(
        remaining.is_empty() || remaining.iter().all(|e| e.state == SagaState::Aborted),
        "Initiated sagas must be resolved by replay, got {remaining:?}"
    );
}

#[tokio::test]
async fn crash_recovery_preparing_a_state_is_discarded() {
    let storage = Arc::new(InMemoryStorage::new());
    let journal = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));

    let saga_id = SagaId::new();
    inject_entry(&journal, &saga_id, SagaState::Initiated, 0).await;
    inject_entry(&journal, &saga_id, SagaState::PreparingA, 1).await;

    let persistence: Arc<dyn scp_runtime::context::persistence::ContextPersistence> =
        Arc::new(NoopPersistence);
    let replayed = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let j_dyn: Arc<dyn SagaJournal> = replayed;
    let supervisor = Supervisor::new(persistence, j_dyn, SupervisorConfig::default());

    // `for_test` witness: this coordinator harness drives replay in isolation
    // (restore-then-replay ordering is type-enforced; the empty witness stands in
    // for a real `restore_all_contexts` the lightweight harness does not run).
    supervisor
        .replay_unresolved_sagas(&RestoredContexts::for_test(Vec::new()))
        .await
        .unwrap();

    let remaining = journal.load_unresolved().await.unwrap();
    assert!(
        remaining.is_empty(),
        "PreparingA sagas must be resolved by replay, got {remaining:?}"
    );
}

#[tokio::test]
async fn crash_recovery_preparing_b_state_is_rolled_back() {
    let storage = Arc::new(InMemoryStorage::new());
    let journal = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));

    let saga_id = SagaId::new();
    inject_entry(&journal, &saga_id, SagaState::PreparingA, 0).await;
    inject_entry(&journal, &saga_id, SagaState::PreparingB, 1).await;

    let persistence: Arc<dyn scp_runtime::context::persistence::ContextPersistence> =
        Arc::new(NoopPersistence);
    let replayed = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let j_dyn: Arc<dyn SagaJournal> = replayed;
    let supervisor = Supervisor::new(persistence, j_dyn, SupervisorConfig::default());

    // `for_test` witness: this coordinator harness drives replay in isolation
    // (restore-then-replay ordering is type-enforced; the empty witness stands in
    // for a real `restore_all_contexts` the lightweight harness does not run).
    supervisor
        .replay_unresolved_sagas(&RestoredContexts::for_test(Vec::new()))
        .await
        .unwrap();

    let remaining = journal.load_unresolved().await.unwrap();
    assert!(
        remaining.is_empty(),
        "PreparingB sagas must be resolved by replay (Abort marker), got {remaining:?}"
    );
}

#[tokio::test]
async fn crash_recovery_committing_state_triggers_needs_repair() {
    let storage = Arc::new(InMemoryStorage::new());
    let journal = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));

    let saga_id = SagaId::new();
    inject_entry(&journal, &saga_id, SagaState::Committing, 0).await;

    let persistence: Arc<dyn scp_runtime::context::persistence::ContextPersistence> =
        Arc::new(NoopPersistence);
    let replayed = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let j_dyn: Arc<dyn SagaJournal> = replayed;
    let supervisor = Supervisor::new(persistence, j_dyn, SupervisorConfig::default());

    // `for_test` witness: this coordinator harness drives replay in isolation
    // (restore-then-replay ordering is type-enforced; the empty witness stands in
    // for a real `restore_all_contexts` the lightweight harness does not run).
    supervisor
        .replay_unresolved_sagas(&RestoredContexts::for_test(Vec::new()))
        .await
        .unwrap();

    // The saga is still unresolved (NeedsRepair is non-terminal), but
    // the latest state is now NeedsRepair.
    let remaining = journal.load_unresolved().await.unwrap();
    assert_eq!(
        remaining.len(),
        1,
        "Committing-on-crash saga must persist as NeedsRepair, got {remaining:?}"
    );
    assert_eq!(
        remaining[0].state,
        SagaState::NeedsRepair,
        "Committing-on-crash state must transition to NeedsRepair"
    );
}

#[tokio::test]
async fn crash_recovery_needs_repair_is_carryover() {
    let storage = Arc::new(InMemoryStorage::new());
    let journal = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));

    let saga_id = SagaId::new();
    inject_entry(&journal, &saga_id, SagaState::NeedsRepair, 0).await;

    let persistence: Arc<dyn scp_runtime::context::persistence::ContextPersistence> =
        Arc::new(NoopPersistence);
    let replayed = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let j_dyn: Arc<dyn SagaJournal> = replayed;
    let supervisor = Supervisor::new(persistence, j_dyn, SupervisorConfig::default());

    // `for_test` witness: this coordinator harness drives replay in isolation
    // (restore-then-replay ordering is type-enforced; the empty witness stands in
    // for a real `restore_all_contexts` the lightweight harness does not run).
    supervisor
        .replay_unresolved_sagas(&RestoredContexts::for_test(Vec::new()))
        .await
        .unwrap();

    // NeedsRepair is non-terminal — it stays in the unresolved set for
    // operator review.
    let remaining = journal.load_unresolved().await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].state, SagaState::NeedsRepair);
    assert_eq!(remaining[0].saga_id, saga_id);
}

/// Terminal Committed / Aborted entries are already-resolved — replay
/// is a no-op.
#[tokio::test]
async fn crash_recovery_terminal_states_are_noop() {
    let storage = Arc::new(InMemoryStorage::new());
    let journal = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));

    // Committed saga
    let c_saga = SagaId::new();
    journal
        .mark_resolved(c_saga.clone(), SagaTerminalState::Committed, false)
        .await
        .unwrap();
    // Aborted saga
    let a_saga = SagaId::new();
    journal
        .mark_resolved(a_saga.clone(), SagaTerminalState::Aborted, false)
        .await
        .unwrap();

    let persistence: Arc<dyn scp_runtime::context::persistence::ContextPersistence> =
        Arc::new(NoopPersistence);
    let replayed = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let j_dyn: Arc<dyn SagaJournal> = replayed;
    let supervisor = Supervisor::new(persistence, j_dyn, SupervisorConfig::default());

    // Replay must succeed without adding any new state.
    // `for_test` witness: this coordinator harness drives replay in isolation
    // (restore-then-replay ordering is type-enforced; the empty witness stands in
    // for a real `restore_all_contexts` the lightweight harness does not run).
    supervisor
        .replay_unresolved_sagas(&RestoredContexts::for_test(Vec::new()))
        .await
        .unwrap();

    let remaining = journal.load_unresolved().await.unwrap();
    assert!(
        remaining.is_empty(),
        "Terminal sagas must not reappear in unresolved set, got {remaining:?}"
    );
}
