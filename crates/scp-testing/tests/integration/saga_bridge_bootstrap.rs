//! Bridge-path startup recovery bootstrap (ADR-049, §17.16.4).
//!
//! This is the BEHAVIORAL enforcement that the shared bridge restore entry
//! `CoreFields::restore_all_persisted_contexts`, which all three FFI
//! bridges (`PyBridgeInstance`, `NapiBridgeInstance`, `UniffiBridgeInstance`)
//! reach through the `BridgeInstanceCore::resume` default body — runs BOTH legs
//! of the §17.16.4 restore-then-replay startup sweep:
//!
//! 1. RESTORE — rehydrate every persisted `Active` context's actor from the
//!    persistence provider.
//! 2. REPLAY — sweep the durable saga journal and reconcile every unresolved
//!    entry left by a crash mid-saga.
//!
//! The source-text gate `bridge_resume_path_routes_through_restore_on_startup`
//! in `pipeline_wiring.rs` is best-effort for IN-CRATE callers: it can only
//! assert that the bridge entry *names* `restore_on_startup()`, and a substring
//! denylist cannot soundly distinguish "calls the combined entry" from "names the
//! token" (an in-crate caller could name `restore_all_contexts(&sup)` via UFCS
//! plus a no-op `restore_on_startup` shadow and still pass). The cross-crate UFCS
//! route is now compile-blocked — `Supervisor::restore_all_contexts` is
//! `pub(crate)`, so naming it from another crate is `error[E0624]`. The type
//! system is the real enforcement; this test drives the REAL bridge
//! entry over a real persistence backend (holding a persisted `Active` context)
//! and a real durable saga journal (holding a PENDING unresolved entry), then
//! asserts BOTH the context was restored AND the saga reached a reconciled
//! terminal state — which only holds if the bridge path actually executed both
//! legs.
//!
//! Run:
//! ```sh
//! cargo test -p scp-testing --test saga_bridge_bootstrap
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
// Shared in-memory persistence double (mirrors `persistence.rs`).
//
// The two supervisors (process 1 "before crash", process 2 "after restart")
// share ONE backing map, so the context process 1 persists is the context
// process 2 restores. `list_persisted_contexts` is what `restore_all_contexts`
// enumerates, so it must return the persisted id.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct SharedPersistence {
    contexts: Mutex<HashMap<String, ContextSnapshot>>,
}

#[async_trait::async_trait]
impl ContextPersistence for SharedPersistence {
    async fn persist_context(
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

    async fn load_context(&self, context_id: &str) -> Result<Option<ContextSnapshot>, BoxError> {
        Ok(self.contexts.lock().unwrap().get(context_id).cloned())
    }

    async fn delete_context(&self, context_id: &str) -> Result<(), BoxError> {
        self.contexts.lock().unwrap().remove(context_id);
        Ok(())
    }

    async fn list_persisted_contexts(&self) -> Result<Vec<String>, BoxError> {
        Ok(self.contexts.lock().unwrap().keys().cloned().collect())
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

/// Builds a per-instance Supervisor with the production provider bootstrap
/// (`with_providers_and_journal`) over a caller-supplied persistence backend and
/// a caller-supplied durable saga journal. This is exactly the pair of
/// ingredients a real `restore_on_startup` needs: a populated helper-persistence
/// slot (so the restore leg lists/loads contexts) AND a durable journal (so the
/// replay leg sees the unresolved entry).
fn bridge_supervisor(
    creator_did: &str,
    persistence: Arc<SharedPersistence>,
    journal: Arc<dyn SagaJournal>,
    mls_storage: Arc<dyn OpenMlsStorageAdapter>,
) -> Arc<Supervisor> {
    let key_resolver: KeyResolver = Arc::new(|_: &DID, _: scp_did::SigningKeyId| None);
    Supervisor::with_providers_and_journal(
        Arc::new(MlsCryptoProvider::new(
            creator_did.to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        )),
        Box::new(LocalTransportProvider) as Box<dyn ContextTransportProvider>,
        Box::new(NoOpEventLog) as Box<dyn ContextEventLogProvider>,
        key_resolver,
        Some(Box::new(SharedPersistenceArc(persistence))),
        None,
        None,
        None,
        // The bootstrap suite builds the journal and `mls_storage` over a
        // caller-supplied shared store, then pairs them via the test-only
        // `for_test` constructor — production sites use `from_handle`.
        scp_core::context::supervisor::DurableProviders::for_test(journal, mls_storage),
    )
}

/// `Box<dyn ContextPersistence>` newtype that shares the `Arc` backing map
/// between the two supervisors (the constructor takes an owned `Box`, but both
/// processes must read/write the SAME map).
struct SharedPersistenceArc(Arc<SharedPersistence>);
#[async_trait::async_trait]
impl ContextPersistence for SharedPersistenceArc {
    async fn persist_context(
        &self,
        context_id: &str,
        snapshot: &ContextSnapshot,
    ) -> Result<(), BoxError> {
        self.0.persist_context(context_id, snapshot).await
    }
    async fn load_context(&self, context_id: &str) -> Result<Option<ContextSnapshot>, BoxError> {
        self.0.load_context(context_id).await
    }
    async fn delete_context(&self, context_id: &str) -> Result<(), BoxError> {
        self.0.delete_context(context_id).await
    }
    async fn list_persisted_contexts(&self) -> Result<Vec<String>, BoxError> {
        self.0.list_persisted_contexts().await
    }
}

/// Driving the shared bridge restore entry `restore_all_persisted_contexts`
/// reconciles a crash-orphaned saga journal entry AND restores a persisted
/// context — proving the bridge path runs BOTH legs of the §17.16.4
/// restore-then-replay startup sweep.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridge_restore_entry_runs_restore_and_replay_legs() {
    let creator_did = "did:dht:z6MkSagaBridgeBootstrapCreator";
    let ctx_id = "ctx-saga-bridge-bootstrap";

    // Shared backing stores survive the "crash" (drop of process 1's supervisor).
    // The MLS storage backend MUST be shared too: a context's MLS group state
    // lives in the OpenMLS storage, and the restart's restore leg reinstates the
    // group FROM that same backend (production shares one `Storage` across
    // persistence + MLS + event log — see the bridge's `derive_mls_storage`).
    let persistence = Arc::new(SharedPersistence::default());
    let journal_storage = Arc::new(InMemoryStorage::new());
    let mls_storage = test_mls_storage();

    // === Process 1: create + persist a context, then crash mid-saga ===
    {
        let journal1: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(
            Arc::clone(&journal_storage),
        ));
        let sup1 = bridge_supervisor(
            creator_did,
            Arc::clone(&persistence),
            journal1,
            Arc::clone(&mls_storage),
        );
        sup1.register_local_did(DID::from(creator_did))
            .await
            .unwrap();

        // `Encrypted` (MLS-backed) is the standard restore path: the group state
        // lives in the shared OpenMLS storage and the restore leg reinstates it.
        let params = ContextParams {
            mode: ContextMode::Encrypted,
            ..ContextParams::default()
        };
        sup1.create_context(ctx_id.to_owned(), params, DID::from(creator_did), None)
            .await
            .expect("create_context");

        // Flush the live context to persistence — this is the durable `Active`
        // snapshot the restart's restore leg must rehydrate.
        sup1.flush_all_contexts().await.expect("flush_all_contexts");
        assert!(
            persistence
                .list_persisted_contexts()
                .await
                .unwrap()
                .iter()
                .any(|id| id == ctx_id),
            "the created context must be persisted before the crash"
        );
        // The flushed snapshot must be `Active` so the restart's restore leg keeps
        // it (Closing/Closed/Expired are skipped by `restore_all_contexts`).
        assert_eq!(
            persistence
                .load_context(ctx_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            ContextState::Active,
            "the flushed snapshot must be Active for the restore leg to rehydrate it"
        );

        // process 1 crashes mid-saga: a `Initiated` (seq 0) journal entry is left
        // unresolved. `Initiated` reconciles to terminal-`Aborted` in the replay
        // leg with no actor/caller dependency — the minimal both-legs probe.
        // Drop sup1 (= crash) without resolving it.
    }

    // Append the crash-orphaned saga entry directly to the shared journal storage
    // (the durable state a crash leaves behind).
    let saga_id = SagaId::new();
    let probe_journal = ProtocolRepositorySagaJournal::new(Arc::clone(&journal_storage));
    probe_journal
        .append(JournalEntry {
            saga_id: saga_id.clone(),
            state: SagaState::Initiated,
            participants: vec![creator_did.to_owned()],
            evidence: zeroize::Zeroizing::new(Vec::new()),
            timestamp_ms: 1_900_000_000_000,
            seq_per_saga: 0,
        })
        .await
        .expect("append crash-orphaned Initiated entry");
    assert!(
        probe_journal
            .load_unresolved()
            .await
            .unwrap()
            .iter()
            .any(|e| e.saga_id == saga_id),
        "the orphaned saga must be unresolved before restart recovery"
    );

    // === Process 2: fresh supervisor over the SAME durable stores, attached to a
    // real bridge instance, restored via the SHARED bridge entry point ===
    let journal2_for_probe: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(
        Arc::clone(&journal_storage),
    ));
    let sup2 = bridge_supervisor(
        creator_did,
        Arc::clone(&persistence),
        Arc::clone(&journal2_for_probe),
        Arc::clone(&mls_storage),
    );
    sup2.register_local_did(DID::from(creator_did))
        .await
        .unwrap();

    let bridge = CoreFields::with_supervisor(Arc::clone(&sup2));

    // Pre-condition: the context is NOT yet resident (process 2 hasn't restored).
    assert!(
        sup2.read_context_state(ctx_id).await.is_none(),
        "the context must be non-resident before the bridge restore entry runs"
    );

    // DRIVE THE SHARED BRIDGE RESTORE ENTRY. This is the exact method all three
    // FFI bridges delegate to on resume/startup. It routes through
    // `Supervisor::restore_on_startup`, which runs restore THEN replay.
    bridge.restore_all_persisted_contexts().await;

    // LEG 1 (RESTORE): the persisted context was rehydrated — its actor is
    // resident again, so `read_context_state` returns a live state.
    assert_eq!(
        sup2.read_context_state(ctx_id).await,
        Some(ContextState::Active),
        "the bridge restore entry MUST rehydrate the persisted Active context (restore leg)"
    );

    // LEG 2 (REPLAY): the crash-orphaned `Initiated` saga was reconciled to a
    // terminal state, so it drops out of `load_unresolved`.
    let unresolved = journal2_for_probe.load_unresolved().await.unwrap();
    assert!(
        !unresolved.iter().any(|e| e.saga_id == saga_id),
        "the bridge restore entry MUST reconcile the crash-orphaned saga to terminal (replay leg) \
         — still unresolved means replay never ran, got {unresolved:?}"
    );
}
