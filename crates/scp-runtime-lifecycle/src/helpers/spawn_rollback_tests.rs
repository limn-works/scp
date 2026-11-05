//! Tests of the lifecycle domain moved from `scp-runtime-core`
//! `context::supervisor::supervisor` (ADR-070 §6.1): they call a function private to this domain.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use dashmap::DashMap;
use scp_did::DID;
use scp_protocol::context::ContextError;
use scp_runtime_core::context::persistence::ContextPersistence;
use scp_runtime_core::context::shared::lifecycle::FirstStateRollback;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use scp_platform::in_memory::InMemoryStorage;
use scp_runtime_core::context::actor::signer::CommandSigner;
use scp_runtime_core::context::supervisor::supervisor::*;

// -----------------------------------------------------------------
// Verify-before-side-effect on the import dispatch path.
//
// `Supervisor::import_context` is a public runtime API. The
// `ImportContext` dispatch arm must verify the snapshot signature
// BEFORE deriving `owning_did` from the (otherwise unverified)
// roster and calling `build_actor_deps` → `key_package_store_for`,
// which would otherwise spawn a `KeyPackageStoreActor` and insert a
// permanent entry into the unbounded `key_package_stores` map keyed
// on an attacker-chosen DID. This test drives a forged export (valid
// structure, wrong verifying key) and asserts (a) it is rejected and
// (b) no key-package-store entry leaked.
// -----------------------------------------------------------------

/// Minimal active-context snapshot whose `creator_did` is `creator`.
fn import_test_snapshot(
    context_id: &str,
    creator: &str,
) -> scp_runtime_core::context::state::ContextSnapshot {
    use scp_protocol::context::ContextState;
    use scp_protocol::context::membership::MembershipState;
    use scp_protocol::context::params::ContextParams;
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

    let role_state = ContextRoleState::new(
        context_id,
        creator,
        default_ceiling(),
        vec![],
        &scp_clock::SystemClock,
    )
    .unwrap();

    scp_runtime_core::context::state::ContextSnapshot {
        context_id: context_id.to_owned(),
        creation_timestamp_secs: 1_700_000_000,
        state: ContextState::Active,
        // A non-empty ceiling: import runs the params validator, which refuses an empty one.
        context_params: ContextParams {
            ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
            ..ContextParams::default()
        },
        membership: MembershipState::new(),
        role_state,
        event_log_merkle_root: [0u8; 32],
        executed_proposals: HashSet::new(),
        ttl_deadline_secs: None,
        registered_outlets: Vec::new(),
        outlet_interfaces: Vec::new(),
        threshold_signers: Vec::new(),
        threshold_value: 0,
        capability_requirements: scp_runtime_core::context::state::Replicated::Live(
            scp_protocol::trust::CapabilityRequirements::default(),
        ),
        pruning_policy: None,
        governance_model_config: None,
        economic_policy: None,
        budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
        read_exclusion_list: HashSet::new(),
        approved_proposals: HashMap::new(),
        next_proposal_seq: 0,
        governance_freeze: None,
        pending_ceiling_modification: None,
        pending_economic_policy_change: None,
        mls_epoch: 0,
        epoch_coordination_records: Vec::new(),
        grace_entries: Vec::new(),
        needs_reconnect: false,
        mls_crypto_state: scp_runtime_core::context::state::MlsCryptoState::default(),
        migration_state: None,
        access_key_store: scp_protocol::crypto::access_keys::AccessKeyStore::new(),
        consequence_rules: Vec::new(),
        participation_cache: HashMap::new(),
        velocity_tracker: None,
        velocity_tracker_state: None,
        cooldown_until: HashMap::new(),
        proposal_timestamps: HashMap::new(),
        message_pricing: None,
        hard_rate_limit_config: None,
        hard_rate_limit_state: HashMap::new(),
        spending_nonce_tracker_state: HashMap::new(),
        revoked_spending_ucan_cids: HashSet::new(),
        pending_commits: std::collections::VecDeque::new(),
        commit_fault: None,
        checkpoint_events_since: 0,
        checkpoint_last_time_secs: 0,
        generation: 0,
        routing: scp_runtime_core::context::actor::state::ContextRouting::Broadcast,
        relay_urls: Vec::new(),
        pseudonym_rotation:
            scp_runtime_core::context::actor::pseudonym_rotation::PseudonymRotationState::default(),
        saga_pending: HashMap::new(),
        xctx_committed_outputs: HashMap::new(),
        xctx_committed_stream_outputs: HashMap::new(),
        xctx_committed_invocations: std::collections::HashSet::new(),
        xctx_caller_reservations: HashMap::new(),
        xctx_nonce_dedup: HashMap::new(),
        caveat_counters: HashMap::new(),
        stream_reservations: HashMap::new(),
        broadcast: None,
    }
}

// =================================================================
// Watchdog / respawn / poison integration tests (ADR-049 §10).
//
// These spawn real state-bearing actors, induce panics via the
// testing-only `TestInducePanic` seam, and assert the watchdog's
// crash-budget, poison, respawn, and payload-redaction behaviour.
// They run on a multi-thread runtime so the watchdog task (spawned
// separately from the actor) makes progress, and inject a
// `TestClock` so the 60s crash window is driven deterministically.
// =================================================================

use scp_clock::TestClock;

/// `ContextPersistence` backed by a shared `DashMap` so a snapshot
/// persisted in a test is actually returned by `load_context` — unlike
/// `TestPersistence`, which always returns `None`. Used by the respawn
/// tests, which need `restore_context` to find a real snapshot.
#[derive(Clone, Default)]
struct MapPersistence {
    contexts: Arc<DashMap<String, scp_runtime_core::context::state::ContextSnapshot>>,
}
#[async_trait::async_trait]
impl ContextPersistence for MapPersistence {
    async fn persist_context(
        &self,
        id: &str,
        snap: &scp_runtime_core::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.contexts.insert(id.to_owned(), snap.clone());
        Ok(())
    }
    async fn load_context(
        &self,
        id: &str,
    ) -> Result<
        Option<scp_runtime_core::context::state::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(self.contexts.get(id).map(|s| s.value().clone()))
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
        Ok(self.contexts.iter().map(|e| e.key().clone()).collect())
    }
}

/// The supervisor clock's time in the first-relay-contact tests.
const FIRST_CONTACT_NOW: u64 = 1_700_000_000;

/// A supervisor over `persistence` and `durable`, with a clock fixed at
/// [`FIRST_CONTACT_NOW`], in-memory wrapping custody, and an event log
/// that exports and imports.
fn first_contact_supervisor(
    persistence: Box<dyn ContextPersistence>,
    durable: DurableProviders,
) -> Arc<Supervisor> {
    Supervisor::with_providers_and_journal(
        Arc::new(
            scp_runtime_core::crypto::mls::provider::NodeMlsFactory::new(
                "did:dht:z6MktestFirstRelayContact".to_owned(),
                Arc::new(scp_clock::SystemClock),
            ),
        ),
        Box::new(scp_runtime_core::context::builder::NotConfiguredTransportProvider),
        Box::new(scp_runtime_core::context::providers::event_log::MerkleEventLogProvider::new()),
        Arc::new(|_: &DID, _: scp_did::SigningKeyId| None),
        persistence,
        None,
        None,
        Some(Arc::new(TestClock::new(FIRST_CONTACT_NOW))),
        durable,
        scp_runtime_core::crypto::wrapping::single_custody_source(Arc::new(
            scp_platform::testing::InMemoryKeyCustody::new(),
        )),
        crate::test_support::test_domain_handlers(),
    )
}

/// The production pairing: every durable provider over one store.
fn durable_over_one_store() -> DurableProviders {
    DurableProviders::from_handle(Arc::new(InMemoryStorage::new()))
}

fn first_contact_params() -> scp_protocol::context::ContextParams {
    scp_protocol::context::ContextParams {
        ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
        ..Default::default()
    }
}

/// An export of a context `exporter` created, signed by the returned key.
async fn first_contact_export(
    ctx: &str,
) -> (
    scp_runtime_core::context::export_import::ContextExport,
    ed25519_dalek::SigningKey,
) {
    let exporter = first_contact_supervisor(
        Box::new(MapPersistence::default()),
        durable_over_one_store(),
    );
    let identity = exporter.node_identity().unwrap();
    exporter
        .create_context(
            ctx.to_owned(),
            first_contact_params(),
            identity.clone(),
            None,
            Vec::new(),
        )
        .await
        .unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x5Au8; 32]);
    let export = exporter
        .export_context(
            ctx,
            identity,
            &CommandSigner::local_ed25519(signing_key.clone()),
        )
        .await
        .unwrap();
    (export, signing_key)
}

/// A snapshot store over a shared map whose writes fail, wait forever,
/// land late, or whose deletes fail, as each test sets. Clones share the
/// map and the switches, so a test keeps one clone to seed and inspect.
/// `close_gate_on_write` closes that Supervisor's spawn gate once a
/// snapshot write lands, so the spawn after it is refused. A write under
/// `delay_writes` runs on its own task, as a `spawn_blocking` or
/// host-callback store's does, so dropping its future does not stop it.
#[derive(Clone, Default)]
struct FaultyPersistence {
    contexts: Arc<DashMap<String, scp_runtime_core::context::state::ContextSnapshot>>,
    fail_writes: Arc<std::sync::atomic::AtomicBool>,
    hang_writes: Arc<std::sync::atomic::AtomicBool>,
    delay_writes: Arc<std::sync::OnceLock<std::time::Duration>>,
    write_started: Arc<std::sync::atomic::AtomicBool>,
    fail_deletes: Arc<std::sync::atomic::AtomicBool>,
    close_gate_on_write: Arc<std::sync::OnceLock<std::sync::Weak<Supervisor>>>,
}
impl FaultyPersistence {
    /// A store wired to `sup` through `close_gate_on_write`.
    fn closing_the_gate_of(&self, sup: &Arc<Supervisor>) {
        assert!(
            self.close_gate_on_write.set(Arc::downgrade(sup)).is_ok(),
            "the gate hook is set once"
        );
    }
    fn set(flag: &std::sync::atomic::AtomicBool) {
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    fn is_set(flag: &std::sync::atomic::AtomicBool) -> bool {
        flag.load(std::sync::atomic::Ordering::SeqCst)
    }
    /// The stored snapshot's creation time, the marker these tests seed.
    fn created_at(&self, id: &str) -> Option<u64> {
        self.contexts.get(id).map(|s| s.creation_timestamp_secs)
    }
}
#[async_trait::async_trait]
impl ContextPersistence for FaultyPersistence {
    async fn persist_context(
        &self,
        id: &str,
        snap: &scp_runtime_core::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Self::set(&self.write_started);
        if Self::is_set(&self.hang_writes) {
            std::future::pending::<()>().await;
        }
        if let Some(delay) = self.delay_writes.get().copied() {
            let contexts = Arc::clone(&self.contexts);
            let (id, snap) = (id.to_owned(), snap.clone());
            return tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                contexts.insert(id, snap);
            })
            .await
            .map_err(|e| e.to_string().into());
        }
        if Self::is_set(&self.fail_writes) {
            return Err("injected snapshot write failure".into());
        }
        self.contexts.insert(id.to_owned(), snap.clone());
        if let Some(sup) = self
            .close_gate_on_write
            .get()
            .and_then(std::sync::Weak::upgrade)
        {
            sup.close_spawn_gate_for_test();
        }
        Ok(())
    }
    async fn load_context(
        &self,
        id: &str,
    ) -> Result<
        Option<scp_runtime_core::context::state::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(self.contexts.get(id).map(|s| s.value().clone()))
    }
    async fn delete_context(
        &self,
        id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if Self::is_set(&self.fail_deletes) {
            return Err("injected snapshot delete failure".into());
        }
        self.contexts.remove(id);
        Ok(())
    }
    async fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.contexts.iter().map(|e| e.key().clone()).collect())
    }
}

/// The creation time a seeded prior snapshot carries, which no create in
/// these tests writes.
const PRIOR_CREATED_AT: u64 = 1_234;
/// The `last_relay_contact` a test stores before the call under test.
const PRIOR_CONTACT: u64 = 42;

/// A snapshot for `ctx` in `state`, marked with [`PRIOR_CREATED_AT`].
fn prior_snapshot(
    ctx: &str,
    state: scp_protocol::context::ContextState,
) -> scp_runtime_core::context::state::ContextSnapshot {
    let mut snapshot = import_test_snapshot(ctx, "did:dht:z6MkPriorSnapshotCreator");
    snapshot.state = state;
    snapshot.creation_timestamp_secs = PRIOR_CREATED_AT;
    snapshot
}

/// A create and an import whose spawn fails after both first-state
/// writes landed roll back: the create puts back the snapshot and the
/// contact stored before it, and the import, which had none, leaves
/// neither. The spawn fails because the spawn gate closes as the
/// snapshot write lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_spawn_rolls_back_create_and_import() {
    let persistence = FaultyPersistence::default();
    let sup = first_contact_supervisor(Box::new(persistence.clone()), durable_over_one_store());
    persistence.closing_the_gate_of(&sup);
    let contacts = sup.relay_contact_store();
    let identity = sup.node_identity().unwrap();
    let created = hex::encode([0xE9u8; 32]);
    persistence.contexts.insert(
        created.clone(),
        prior_snapshot(&created, scp_protocol::context::ContextState::Active),
    );
    contacts
        .store_last_relay_contact(&created, PRIOR_CONTACT)
        .await
        .unwrap();
    let deps = sup.build_actor_deps_loaded(&identity).await.unwrap();

    let guard = FirstStateRollback::new(&deps, &created).unwrap();
    let err = Box::pin(crate::helpers::create_context(
        &deps,
        created.clone(),
        first_contact_params(),
        identity,
        None,
        Vec::new(),
        &guard,
    ))
    .await
    .unwrap_err();
    assert!(
        matches!(
            err,
            scp_protocol::context::builder::ContextCreationError::StateTransition(
                ContextError::SupervisorShutDown(_)
            )
        ),
        "{err:?}"
    );
    assert_ne!(
        persistence.created_at(&created),
        Some(PRIOR_CREATED_AT),
        "the create replaced the snapshot before the spawn"
    );
    assert_eq!(
        contacts.load_last_relay_contact(&created).await.unwrap(),
        Some(FIRST_CONTACT_NOW),
        "the create wrote its contact before the spawn"
    );
    guard
        .rollback_for_test(sup.lock_bootstrap_spawn_for_test())
        .await
        .unwrap();
    assert!(sup.lookup_for_test(&created).is_none(), "no actor started");
    assert_eq!(persistence.created_at(&created), Some(PRIOR_CREATED_AT));
    assert_eq!(
        contacts.load_last_relay_contact(&created).await.unwrap(),
        Some(PRIOR_CONTACT)
    );

    let persistence = FaultyPersistence::default();
    let sup = first_contact_supervisor(Box::new(persistence.clone()), durable_over_one_store());
    persistence.closing_the_gate_of(&sup);
    let contacts = sup.relay_contact_store();
    let identity = sup.node_identity().unwrap();
    let imported = hex::encode([0xEAu8; 32]);
    let (export, signing_key) = first_contact_export(&imported).await;
    let deps = sup.build_actor_deps_loaded(&identity).await.unwrap();
    let guard = FirstStateRollback::new(&deps, &imported).unwrap();
    let err = Box::pin(crate::helpers::import_context(
        &deps,
        export,
        &signing_key.verifying_key(),
        None,
        &guard,
    ))
    .await
    .unwrap_err();
    assert!(
        matches!(err, ContextError::SupervisorShutDown(_)),
        "{err:?}"
    );
    assert!(
        persistence.contexts.contains_key(&imported),
        "the import wrote its snapshot before the spawn"
    );
    assert_eq!(
        contacts.load_last_relay_contact(&imported).await.unwrap(),
        Some(FIRST_CONTACT_NOW),
        "the import wrote its contact before the spawn"
    );
    guard
        .rollback_for_test(sup.lock_bootstrap_spawn_for_test())
        .await
        .unwrap();
    assert!(sup.lookup_for_test(&imported).is_none(), "no actor started");
    assert!(!persistence.contexts.contains_key(&imported));
    assert_eq!(
        contacts.load_last_relay_contact(&imported).await.unwrap(),
        None
    );
}
