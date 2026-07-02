//! Behavioral proof for the production saga-journal swap (§17.16 / ADR-049).
//!
//! PR-7 / Phase 2D swaps every production `Supervisor` construction seam from
//! `NoopSagaJournal` to `ProtocolRepositorySagaJournal` over the single chosen
//! `Storage` backend. The structural wiring is pinned by
//! `prod_supervisor_construction_wires_durable_saga_journal` in
//! `pipeline_wiring.rs`; THIS file is the BEHAVIORAL proof that, with the durable
//! journal attached, a process restart actually runs BOTH legs of the §17.16.4
//! restore-then-replay crash-recovery sweep over a REAL persistence backend AND a
//! REAL durable journal sharing one storage backend — exactly the shape every
//! swapped bridge now constructs.
//!
//! These tests drive the production provider bootstrap
//! `Supervisor::with_providers_and_journal` (the constructor every swapped seam
//! now calls) directly, over an `InMemoryStorage` shared across the "crash" and
//! "restart" supervisors, and assert:
//!
//! 1. Both legs run end-to-end: a persisted `Active` context is restored AND a
//!    crash-orphaned saga is reconciled to a reconciled terminal/carryover per
//!    `load_unresolved`'s classification.
//! 2. Restore runs BEFORE replay (so recovery arms drive now-resident
//!    participants).
//! 3. An empty journal replays as a no-op — proving the swap is INERT-but-correct
//!    while the §6.2.4 producer is still dark (a restart loads zero entries).
//! 4. A second replay over the same real journal is idempotent.
//! 5. A `NeedsRepair` entry is carried over (non-terminal) and leaves no live
//!    gating reservation rebuilt by replay.
//!
//! Run:
//! ```sh
//! cargo test -p scp-testing --test saga_bridge_journal_swap
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use scp_core::context::builder::ContextCreationError;
use scp_core::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use scp_core::context::governance::KeyResolver;
use scp_core::context::persistence::ContextPersistence;
use scp_core::context::state::ContextSnapshot;
use scp_core::context::supervisor::{
    JournalEntry, ProtocolRepositorySagaJournal, SagaId, SagaJournal, SagaState, Supervisor,
};
use scp_core::context::{ContextMode, ContextParams, ContextState, LocalTransportProvider};
use scp_core::crypto::mls::provider::MlsCryptoProvider;
use scp_core::crypto::mls::storage_adapter::{OpenMlsStorageAdapter, SpawnBlockingStorageAdapter};
use scp_did::DID;
use scp_ffi_common::bridge_instance::CoreFields;
use scp_platform::testing::InMemoryStorage;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

// ---------------------------------------------------------------------------
// Shared in-memory persistence double (mirrors `saga_bridge_bootstrap.rs`).
//
// One backing map survives the "crash" (drop of process 1's supervisor) so the
// context process 1 persists is the context process 2 restores.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct SharedPersistence {
    contexts: Mutex<HashMap<String, ContextSnapshot>>,
}

impl ContextPersistence for SharedPersistence {
    fn persist_context(
        &self,
        context_id: &str,
        snapshot: &ContextSnapshot,
    ) -> Result<(), BoxError> {
        self.contexts
            .lock()
            .unwrap()
            .insert(context_id.to_owned(), snapshot.clone());
        Ok(())
    }

    fn load_context(&self, context_id: &str) -> Result<Option<ContextSnapshot>, BoxError> {
        Ok(self.contexts.lock().unwrap().get(context_id).cloned())
    }

    fn delete_context(&self, context_id: &str) -> Result<(), BoxError> {
        self.contexts.lock().unwrap().remove(context_id);
        Ok(())
    }

    fn list_persisted_contexts(&self) -> Result<Vec<String>, BoxError> {
        Ok(self.contexts.lock().unwrap().keys().cloned().collect())
    }
}

/// `Box<dyn ContextPersistence>` newtype sharing the `Arc` backing map between
/// the two supervisors (the constructor takes an owned `Box`).
struct SharedPersistenceArc(Arc<SharedPersistence>);
impl ContextPersistence for SharedPersistenceArc {
    fn persist_context(
        &self,
        context_id: &str,
        snapshot: &ContextSnapshot,
    ) -> Result<(), BoxError> {
        self.0.persist_context(context_id, snapshot)
    }
    fn load_context(&self, context_id: &str) -> Result<Option<ContextSnapshot>, BoxError> {
        self.0.load_context(context_id)
    }
    fn delete_context(&self, context_id: &str) -> Result<(), BoxError> {
        self.0.delete_context(context_id)
    }
    fn list_persisted_contexts(&self) -> Result<Vec<String>, BoxError> {
        self.0.list_persisted_contexts()
    }
}

// Minimal no-op event-log provider (mirrors the bridge_instance test harness).
struct NoOpEventLog;
impl ContextEventLogProvider for NoOpEventLog {
    fn init_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn append_event(
        &self,
        _: &[u8; 32],
        _: scp_event_log::EventType,
        _: &str,
        _: scp_event_log::EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn destroy_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
}

fn test_mls_storage() -> Arc<dyn OpenMlsStorageAdapter> {
    Arc::new(SpawnBlockingStorageAdapter::new(Arc::new(
        InMemoryStorage::new(),
    )))
}

/// Builds a per-instance `Supervisor` via the EXACT production provider
/// bootstrap (`with_providers_and_journal`) every swapped bridge now calls,
/// over a caller-supplied persistence backend AND a caller-supplied durable saga
/// journal (the two ingredients the swap attaches in production).
fn journal_supervisor(
    creator_did: &str,
    persistence: Arc<SharedPersistence>,
    journal: Arc<dyn SagaJournal>,
    mls_storage: Arc<dyn OpenMlsStorageAdapter>,
) -> Arc<Supervisor> {
    let key_resolver: KeyResolver = Arc::new(|_: &DID, _: scp_did::SigningKeyId| None);
    Supervisor::with_providers_and_journal(
        Arc::new(MlsCryptoProvider::new(creator_did.to_owned())),
        Box::new(LocalTransportProvider) as Box<dyn ContextTransportProvider>,
        Box::new(NoOpEventLog) as Box<dyn ContextEventLogProvider>,
        key_resolver,
        Some(Box::new(SharedPersistenceArc(persistence))),
        None,
        None,
        None,
        // The swap suite deliberately builds the journal and `mls_storage` over
        // ONE shared `InMemoryStorage` (see callers), then pairs them via the
        // test-only `for_test` constructor — production sites use `from_handle`.
        scp_core::context::supervisor::DurableProviders::for_test(journal, mls_storage),
    )
}

/// Appends one crash-orphaned (non-terminal) journal entry to the shared journal
/// storage, modeling the durable state a crash leaves behind. Empty evidence is
/// the realistic shape for the entries reachable here: `Initiated` carries none,
/// and a non-xctx single-participant entry routes through the participant-keyed
/// recovery without an evidence reconstruction.
async fn append_entry(
    journal: &ProtocolRepositorySagaJournal<InMemoryStorage>,
    saga_id: &SagaId,
    state: SagaState,
    participants: Vec<String>,
    seq: u64,
) {
    journal
        .append(JournalEntry {
            saga_id: saga_id.clone(),
            state,
            participants,
            evidence: zeroize::Zeroizing::new(Vec::new()),
            timestamp_ms: 1_900_000_000_000 + seq,
            seq_per_saga: seq,
        })
        .await
        .expect("append crash-orphaned entry");
}

// ===========================================================================
// 1. Both legs run end-to-end over a REAL persistence backend + REAL journal.
// ===========================================================================

/// Drives the production `with_providers_and_journal` bootstrap (every swapped
/// bridge's constructor) across a simulated crash + restart over ONE shared
/// `InMemoryStorage` journal backend and ONE shared persistence backend, then
/// runs `restore_on_startup` (restore THEN replay) and asserts BOTH legs ran:
/// the persisted `Active` context is restored AND each crash-orphaned saga is
/// reconciled per `load_unresolved`'s classification.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn journal_swap_runs_restore_and_replay_legs_over_real_journal() {
    let creator_did = "did:dht:z6MkJournalSwapCreator";
    let ctx_id = "ctx-journal-swap-both-legs";

    // Shared durable stores survive the crash (drop of process 1's supervisor).
    let persistence = Arc::new(SharedPersistence::default());
    let journal_storage = Arc::new(InMemoryStorage::new());
    let mls_storage = test_mls_storage();

    // Non-terminal sagas the crash leaves behind, one per recovery class that is
    // deterministic without xctx evidence reconstruction:
    //   - Initiated         -> terminal Aborted (Prepare-A never dispatched).
    //   - Committing (empty) -> NeedsRepair carryover (non-reconstructible).
    let initiated_saga = SagaId::new();
    let committing_saga = SagaId::new();

    // === Process 1: create + persist a context, then "crash" mid-saga ===
    {
        let journal1: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(
            Arc::clone(&journal_storage),
        ));
        let sup1 = journal_supervisor(
            creator_did,
            Arc::clone(&persistence),
            journal1,
            Arc::clone(&mls_storage),
        );
        sup1.register_local_did(DID::from(creator_did))
            .await
            .unwrap();

        let params = ContextParams {
            mode: ContextMode::Encrypted,
            ..ContextParams::default()
        };
        sup1.create_context(ctx_id.to_owned(), params, DID::from(creator_did), None)
            .await
            .expect("create_context");
        sup1.flush_all_contexts().await.expect("flush_all_contexts");
        assert_eq!(
            persistence.load_context(ctx_id).unwrap().unwrap().state,
            ContextState::Active,
            "the flushed snapshot must be Active for the restore leg to rehydrate it"
        );
        // Drop sup1 (= crash) without resolving the sagas below.
    }

    // Append the crash-orphaned saga entries directly to the shared journal
    // backend (the durable state a crash leaves behind).
    let probe_journal = ProtocolRepositorySagaJournal::new(Arc::clone(&journal_storage));
    append_entry(
        &probe_journal,
        &initiated_saga,
        SagaState::Initiated,
        vec![creator_did.to_owned()],
        0,
    )
    .await;
    append_entry(
        &probe_journal,
        &committing_saga,
        SagaState::Committing,
        vec![creator_did.to_owned()],
        0,
    )
    .await;
    let pre = probe_journal.load_unresolved().await.unwrap();
    assert!(
        pre.iter().any(|e| e.saga_id == initiated_saga)
            && pre.iter().any(|e| e.saga_id == committing_saga),
        "both crash-orphaned sagas must be unresolved before restart recovery"
    );

    // === Process 2: fresh supervisor over the SAME durable stores, restored via
    // the shared bridge entry (restore THEN replay) ===
    let journal2: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(
        &journal_storage,
    )));
    let sup2 = journal_supervisor(
        creator_did,
        Arc::clone(&persistence),
        Arc::clone(&journal2),
        Arc::clone(&mls_storage),
    );
    sup2.register_local_did(DID::from(creator_did))
        .await
        .unwrap();

    let bridge = CoreFields::with_supervisor(Arc::clone(&sup2));
    assert!(
        sup2.read_context_state(ctx_id).await.is_none(),
        "the context must be non-resident before the bridge restore entry runs"
    );

    // DRIVE THE SHARED BRIDGE RESTORE ENTRY (restore THEN replay).
    bridge.restore_all_persisted_contexts().await;

    // LEG 1 (RESTORE): the persisted context was rehydrated.
    assert_eq!(
        sup2.read_context_state(ctx_id).await,
        Some(ContextState::Active),
        "the bridge restore entry MUST rehydrate the persisted Active context (restore leg)"
    );

    // LEG 2 (REPLAY): the crash-orphaned sagas were reconciled per class.
    let unresolved = journal2.load_unresolved().await.unwrap();
    // Initiated -> terminal Aborted: drops out of load_unresolved entirely.
    assert!(
        !unresolved.iter().any(|e| e.saga_id == initiated_saga),
        "the Initiated saga MUST be reconciled to terminal-Aborted (replay leg) — still \
         unresolved means replay never ran, got {unresolved:?}"
    );
    // Committing (empty evidence) -> NeedsRepair carryover: stays non-terminal
    // but now as the operator-repair carryover state (NeedsRepair), proving the
    // commit-in-progress recovery arm ran rather than being skipped.
    let committing_now = unresolved
        .iter()
        .find(|e| e.saga_id == committing_saga)
        .expect("the Committing saga must remain as a NeedsRepair carryover after replay");
    assert_eq!(
        committing_now.state,
        SagaState::NeedsRepair,
        "a non-reconstructible Committing entry MUST be reclassified NeedsRepair by the \
         commit-in-progress recovery arm (replay ran), not left as raw Committing"
    );
}

// ===========================================================================
// 2. Restore-then-replay ordering at the bridge level over the real journal.
// ===========================================================================

/// Mirrors the bootstrap ordering proof but pinned to the journal-swap
/// constructor: the bridge restore entry restores the persisted context BEFORE
/// the saga replay reconciles the crash-orphaned entry. If replay ran first, the
/// recovery arm would drive a non-resident participant; the saga reaching a
/// reconciled terminal proves restore ran first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn journal_swap_restores_context_before_replaying_sagas() {
    let creator_did = "did:dht:z6MkJournalSwapOrdering";
    let ctx_id = "ctx-journal-swap-ordering";

    let persistence = Arc::new(SharedPersistence::default());
    let journal_storage = Arc::new(InMemoryStorage::new());
    let mls_storage = test_mls_storage();
    let saga_id = SagaId::new();

    {
        let journal1: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(
            Arc::clone(&journal_storage),
        ));
        let sup1 = journal_supervisor(
            creator_did,
            Arc::clone(&persistence),
            journal1,
            Arc::clone(&mls_storage),
        );
        sup1.register_local_did(DID::from(creator_did))
            .await
            .unwrap();
        let params = ContextParams {
            mode: ContextMode::Encrypted,
            ..ContextParams::default()
        };
        sup1.create_context(ctx_id.to_owned(), params, DID::from(creator_did), None)
            .await
            .expect("create_context");
        sup1.flush_all_contexts().await.expect("flush_all_contexts");
    }

    let probe_journal = ProtocolRepositorySagaJournal::new(Arc::clone(&journal_storage));
    append_entry(
        &probe_journal,
        &saga_id,
        SagaState::Initiated,
        vec![creator_did.to_owned()],
        0,
    )
    .await;

    let journal2: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(
        &journal_storage,
    )));
    let sup2 = journal_supervisor(
        creator_did,
        Arc::clone(&persistence),
        Arc::clone(&journal2),
        Arc::clone(&mls_storage),
    );
    sup2.register_local_did(DID::from(creator_did))
        .await
        .unwrap();

    // Drive the combined restore-then-replay entry directly on the supervisor.
    let restored = sup2.restore_on_startup().await.expect("restore_on_startup");
    assert!(
        restored.iter().any(|id| id == ctx_id),
        "restore leg must report the persisted context as restored, got {restored:?}"
    );
    assert_eq!(
        sup2.read_context_state(ctx_id).await,
        Some(ContextState::Active),
        "the restored context must be resident (restore ran)"
    );
    let unresolved = journal2.load_unresolved().await.unwrap();
    assert!(
        !unresolved.iter().any(|e| e.saga_id == saga_id),
        "the saga must be reconciled to terminal after restore_on_startup (replay ran AFTER \
         restore), got {unresolved:?}"
    );
}

// ===========================================================================
// 3. Empty-journal no-op — proves the swap is INERT-but-correct while the
//    §6.2.4 producer is still dark (a restart loads zero unresolved entries).
// ===========================================================================

/// With the durable journal attached but NO producer appending (the §6.2.4
/// actor-mailbox producer is still a deferred stub), a restart's replay loads an
/// empty journal and is a no-op. This is the load-bearing correctness claim of
/// the "land the swap now" decision: the swap changes nothing observable until
/// the producer lands, yet is correctly wired.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn journal_swap_replay_on_empty_journal_is_a_noop() {
    let creator_did = "did:dht:z6MkJournalSwapEmpty";
    let persistence = Arc::new(SharedPersistence::default());
    let journal_storage = Arc::new(InMemoryStorage::new());
    let mls_storage = test_mls_storage();

    let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(
        &journal_storage,
    )));
    let sup = journal_supervisor(
        creator_did,
        Arc::clone(&persistence),
        Arc::clone(&journal),
        mls_storage,
    );
    sup.register_local_did(DID::from(creator_did))
        .await
        .unwrap();

    // No entries appended (producer dark). The empty-journal precondition.
    assert!(
        journal.load_unresolved().await.unwrap().is_empty(),
        "precondition: no producer has appended — the journal must be empty"
    );

    // restore_on_startup runs restore (no contexts) THEN replay (no entries):
    // both legs succeed without error, and the journal stays empty.
    let restored = sup
        .restore_on_startup()
        .await
        .expect("restore_on_startup over an empty journal must succeed (inert-but-correct)");
    assert!(
        restored.is_empty(),
        "no contexts persisted — restore leg restores nothing, got {restored:?}"
    );
    assert!(
        journal.load_unresolved().await.unwrap().is_empty(),
        "replay over an empty journal must leave it empty — the swap is inert while dark"
    );
}

// ===========================================================================
// 4. Idempotent second replay over the real journal.
// ===========================================================================

/// A second `restore_on_startup` (= restore + replay) over the SAME real journal
/// after the first pass already reconciled every entry leaves the journal stable
/// — a redundant restart never double-applies. Mirrors the unit-level
/// `replay_is_idempotent_after_first_pass`, but driven through the production
/// `restore_on_startup` entry over the `with_providers_and_journal` supervisor +
/// real `ProtocolRepositorySagaJournal`. (Replay is driven via `restore_on_startup`
/// because the `RestoredContexts` restore-ran witness is unforgeable outside the
/// supervisor — exactly the §17.16.4 ordering guarantee.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn journal_swap_second_restart_replay_is_idempotent() {
    let creator_did = "did:dht:z6MkJournalSwapIdempotent";
    let persistence = Arc::new(SharedPersistence::default());
    let journal_storage = Arc::new(InMemoryStorage::new());
    let mls_storage = test_mls_storage();
    let saga_id = SagaId::new();

    let probe_journal = ProtocolRepositorySagaJournal::new(Arc::clone(&journal_storage));
    append_entry(
        &probe_journal,
        &saga_id,
        SagaState::Initiated,
        vec![creator_did.to_owned()],
        0,
    )
    .await;

    let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(
        &journal_storage,
    )));
    let sup = journal_supervisor(
        creator_did,
        Arc::clone(&persistence),
        Arc::clone(&journal),
        mls_storage,
    );
    sup.register_local_did(DID::from(creator_did))
        .await
        .unwrap();

    // First restart: reconciles the Initiated saga to terminal Aborted.
    sup.restore_on_startup()
        .await
        .expect("first restore_on_startup");
    let after_first = journal.load_unresolved().await.unwrap();
    assert!(
        !after_first.iter().any(|e| e.saga_id == saga_id),
        "first replay must reconcile the Initiated saga to terminal"
    );

    // Second restart: must succeed and leave the journal stable.
    sup.restore_on_startup()
        .await
        .expect("second restore_on_startup must succeed (idempotent)");
    let after_second = journal.load_unresolved().await.unwrap();
    assert_eq!(
        after_first.len(),
        after_second.len(),
        "second replay must leave the journal stable (idempotent), \
         first={after_first:?} second={after_second:?}"
    );
}

// ===========================================================================
// 6. SQLite durability — the on-disk durable path actually round-trips a
//    crash-orphaned saga across a process restart.
//
//    The other crash-recovery tests above all use `InMemoryStorage`, which
//    never exercises the production SQLite/SQLCipher path. This test mirrors the
//    both-legs crash-recovery shape over a REAL `SqliteStorage` file: process 1
//    appends a non-terminal saga to the on-disk journal, then drops + closes its
//    storage handle (releasing the SQLite advisory exclusive lock); process 2
//    opens the SAME sqlite file and runs `restore_on_startup`, which reconciles
//    the crash-orphaned saga to terminal — proving the durable journal genuinely
//    round-trips on disk, not just in memory.
// ===========================================================================

/// Drives the journal-swap crash-recovery shape over a REAL `SqliteStorage`
/// file. Process 1 appends an `Initiated` crash-orphaned saga to the on-disk
/// journal; its handle is closed/dropped (releasing the SQLite exclusive lock)
/// before process 2 opens the SAME file and runs `restore_on_startup`, which
/// must reconcile the saga to terminal (it drops out of `load_unresolved`).
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn journal_swap_sqlite_durable_crash_recovery_round_trips_on_disk() {
    use scp_platform::sqlite::SqliteStorage;

    let creator_did = "did:dht:z6MkJournalSwapSqlite";
    // One temp dir backs both "processes" — the on-disk DB survives the crash.
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_dir = tmp.path().to_path_buf();
    let db_key = [0x5Au8; 32];
    let saga_id = SagaId::new();

    // === Process 1: open the sqlite journal, append a crash-orphaned saga,
    // then CLOSE + drop the handle (= crash, releasing the exclusive lock). ===
    {
        let storage1 = Arc::new(
            SqliteStorage::new(&db_dir, &db_key).expect("process-1 sqlite open must succeed"),
        );
        let journal1 = ProtocolRepositorySagaJournal::new(Arc::clone(&storage1));
        journal1
            .append(JournalEntry {
                saga_id: saga_id.clone(),
                state: SagaState::Initiated,
                participants: vec![creator_did.to_owned()],
                evidence: zeroize::Zeroizing::new(Vec::new()),
                timestamp_ms: 1_900_000_000_000,
                seq_per_saga: 0,
            })
            .await
            .expect("append crash-orphaned entry to on-disk journal");

        // Confirm it is durably unresolved on disk before the crash.
        let pre = journal1
            .load_unresolved()
            .await
            .expect("load_unresolved over the on-disk journal");
        assert!(
            pre.iter().any(|e| e.saga_id == saga_id),
            "the crash-orphaned saga must be durably unresolved on disk before restart"
        );

        // Release the SQLite advisory exclusive lock so process 2 can open the
        // SAME database directory (drop alone would also release it, but close()
        // releases even while outstanding Arc clones persist).
        storage1.close();
        drop(journal1);
        drop(storage1);
    }

    // === Process 2: fresh supervisor over the SAME sqlite file via the
    // production `with_providers_and_journal` bootstrap; restore_on_startup
    // reconciles the crash-orphaned saga to terminal. ===
    let storage2 = Arc::new(
        SqliteStorage::new(&db_dir, &db_key).expect("process-2 sqlite reopen must succeed"),
    );
    let journal2: Arc<dyn SagaJournal> =
        Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage2)));
    let mls_storage: Arc<dyn OpenMlsStorageAdapter> =
        Arc::new(SpawnBlockingStorageAdapter::new(Arc::clone(&storage2)));

    let sup2 = journal_supervisor(
        creator_did,
        // The journal durability is the unit under test; context persistence is
        // an in-memory double (no persisted contexts in this scenario).
        Arc::new(SharedPersistence::default()),
        Arc::clone(&journal2),
        mls_storage,
    );
    sup2.register_local_did(DID::from(creator_did))
        .await
        .unwrap();

    sup2.restore_on_startup()
        .await
        .expect("restore_on_startup over the reopened sqlite journal");

    // The crash-orphaned Initiated saga must be reconciled to terminal-Aborted
    // (it drops out of load_unresolved) — proving the on-disk durable path
    // genuinely round-tripped the entry across the restart.
    let unresolved = journal2
        .load_unresolved()
        .await
        .expect("load_unresolved over the reopened sqlite journal");
    assert!(
        !unresolved.iter().any(|e| e.saga_id == saga_id),
        "the crash-orphaned saga MUST be reconciled to terminal after restore_on_startup over \
         the REAL sqlite file (durable on-disk round-trip), got {unresolved:?}"
    );

    storage2.close();
}

// ===========================================================================
// 5. NeedsRepair is carried over (non-terminal) and replay rebuilds NO live
//    gating reservation for it.
// ===========================================================================

/// A `NeedsRepair` journal entry is the operator-repair carryover state: it is
/// non-terminal, so `load_unresolved` keeps surfacing it across restarts until an
/// operator repairs it, and the recovery arm rebuilds NO live saga gating
/// reservation for it (the durable account is rehydrated, but the saga does NOT
/// re-enter the active flow). After replay, a fresh saga over the SAME participant
/// context set can therefore still be started — proving no live reservation was
/// rebuilt for the carried-over `NeedsRepair` saga.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn journal_swap_needs_repair_carries_over_without_rebuilding_reservation() {
    let creator_did = "did:dht:z6MkJournalSwapNeedsRepair";
    let persistence = Arc::new(SharedPersistence::default());
    let journal_storage = Arc::new(InMemoryStorage::new());
    let mls_storage = test_mls_storage();
    let needs_repair_saga = SagaId::new();
    // A participant context the NeedsRepair entry names — if replay (wrongly)
    // rebuilt a live reservation, this id would be reserved afterward. The saga
    // gating layer keys reservations on `hex::encode(context_id)`.
    let participant_ctx_id: [u8; 32] = [0x11u8; 32];
    let participant_ctx_hex = hex::encode(participant_ctx_id);

    let probe_journal = ProtocolRepositorySagaJournal::new(Arc::clone(&journal_storage));
    append_entry(
        &probe_journal,
        &needs_repair_saga,
        SagaState::NeedsRepair,
        vec![participant_ctx_hex.clone()],
        0,
    )
    .await;

    let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(
        &journal_storage,
    )));
    let sup = journal_supervisor(
        creator_did,
        Arc::clone(&persistence),
        Arc::clone(&journal),
        mls_storage,
    );
    sup.register_local_did(DID::from(creator_did))
        .await
        .unwrap();

    sup.restore_on_startup()
        .await
        .expect("restore_on_startup over a NeedsRepair carryover");

    // The NeedsRepair entry is carried over: still surfaced by load_unresolved
    // (non-terminal), so an operator keeps being alerted on every restart.
    let unresolved = journal.load_unresolved().await.unwrap();
    let carried = unresolved
        .iter()
        .find(|e| e.saga_id == needs_repair_saga)
        .expect("the NeedsRepair entry must be carried over (non-terminal) after replay");
    assert_eq!(
        carried.state,
        SagaState::NeedsRepair,
        "the carried-over entry must remain NeedsRepair (operator-repair carryover)"
    );

    // No live gating reservation was rebuilt for the carried-over saga's
    // participant context: a brand-new reservation over that SAME context set
    // succeeds (it would fail with SagaBusy if replay had reserved it).
    let reservation = sup.test_reserve_saga_context_set(
        &scp_core::context::supervisor::SagaInput::TestForceNeedsRepair {
            context_id: participant_ctx_id,
        },
    );
    assert!(
        reservation.is_ok(),
        "replay of a NeedsRepair carryover MUST NOT rebuild a live gating reservation — the \
         participant context set must be re-reservable, but got: {:?}",
        reservation.err()
    );
}
