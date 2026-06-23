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

use scp_platform::testing::InMemoryStorage;
use scp_runtime::context::supervisor::{
    JournalEntry, ProtocolRepositorySagaJournal, SagaId, SagaJournal, SagaState, Supervisor,
    SupervisorConfig,
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
        Arc::new(NoopPersistence);
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

    // Build a supervisor — replay happens manually (not from new).
    let supervisor = build_supervisor(&storage);
    supervisor.replay_unresolved_sagas().await.unwrap();

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
    supervisor.replay_unresolved_sagas().await.unwrap();

    // Second replay must succeed without side effects.
    supervisor.replay_unresolved_sagas().await.unwrap();
    let post = probe_journal.load_unresolved().await.unwrap();
    assert!(post.is_empty(), "second replay must leave journal stable");
}

/// Replay over an empty journal must succeed.
#[tokio::test]
async fn replay_on_empty_journal_succeeds() {
    let storage = Arc::new(InMemoryStorage::new());
    let supervisor = build_supervisor(&storage);
    supervisor.replay_unresolved_sagas().await.unwrap();
}

/// Process-restart bootstrap wiring (ADR-049 Phase 2D): a fresh supervisor
/// over storage that durably retains an unresolved saga journal entry
/// RESOLVES that entry via the single startup entry point
/// `Supervisor::restore_on_startup` — WITHOUT any manual
/// `replay_unresolved_sagas()` call. This is the regression guard against the
/// "exported but never called from the bootstrap path" failure mode: if the
/// startup method ever stopped folding in the replay sweep, the injected
/// `Initiated` saga would remain unresolved after `restore_on_startup`.
#[tokio::test]
async fn restore_on_startup_replays_unresolved_journal_without_manual_replay() {
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

    // Second "process": a fresh supervisor over the SAME durable storage. This
    // lightweight `Supervisor::new` harness wires no helper-side persistence
    // provider (production builds go through `with_providers`), so the restore
    // leg of the startup sweep returns `PersistenceFailed`. That is exactly the
    // ordering probe we want: `restore_on_startup` runs the replay sweep FIRST
    // (resolving the orphaned journal entry) and ONLY THEN reaches the restore
    // leg that errors — proving replay ran BEFORE restore, on the bootstrap
    // path, with no manual `replay_unresolved_sagas()` call.
    let persistence: Arc<dyn scp_runtime::context::persistence::ContextPersistence> =
        Arc::new(NoopPersistence);
    let journal: Arc<dyn SagaJournal> =
        Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let restarted = Arc::new(Supervisor::new(
        persistence,
        journal,
        SupervisorConfig::default(),
    ));

    // The bootstrap entry point — no manual replay_unresolved_sagas() call.
    let startup = restarted.restore_on_startup().await;

    // The orphaned `Initiated` saga was discarded by the replay leg of the SAME
    // startup call — observable on the journal REGARDLESS of the restore leg's
    // outcome. Without the replay-before-restore wiring this would still be 1.
    let post = probe_journal.load_unresolved().await.unwrap();
    assert!(
        post.is_empty(),
        "restore_on_startup must replay+resolve the orphaned journal entry on the bootstrap \
         path before reaching the restore leg, got {post:?}"
    );

    // The restore leg ran AFTER replay and surfaced the (expected) missing
    // helper-persistence error for this minimal harness — confirming replay did
    // not short-circuit on the restore failure (it had already completed).
    match startup {
        Err(scp_protocol::context::ContextError::PersistenceFailed(_)) => {}
        other => panic!(
            "expected the restore leg to surface PersistenceFailed after replay completed, got \
             {other:?}"
        ),
    }
}
