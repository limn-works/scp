use super::*;
use crate::context::actor::signer::CommandSigner;
use crate::context::supervisor::saga_journal::ProtocolRepositorySagaJournal;
use scp_platform::in_memory::InMemoryStorage;

/// A `Supervisor` built without providers holds no transport slot, so a
/// bridge cannot bind a node's relay transport to it.
#[test]
fn transport_slot_is_absent_without_providers() {
    assert!(
        Supervisor::for_query_shim(crate::domain_handlers())
            .transport_slot()
            .is_none()
    );
}

/// The escrow-reversal join log names a panic as a panic without its
/// payload, and names a cancelled task as cancelled, never as panicked.
#[tokio::test]
async fn escrow_reversal_join_failure_message_splits_panic_from_cancel() {
    let panicked = tokio::spawn(async { panic!("secret-reversal-payload") })
        .await
        .expect_err("a panicking task yields a JoinError");
    assert!(panicked.is_panic());
    let msg = escrow_reversal_join_failure_message(&panicked);
    assert!(msg.contains("panicked"), "{msg}");
    assert!(!msg.contains("cancelled"), "{msg}");
    assert!(!msg.contains("secret-reversal-payload"), "{msg}");

    let pending = tokio::spawn(std::future::pending::<()>());
    pending.abort();
    let cancelled = pending
        .await
        .expect_err("an aborted task yields a JoinError");
    assert!(cancelled.is_cancelled());
    let msg = escrow_reversal_join_failure_message(&cancelled);
    assert!(msg.contains("cancelled"), "{msg}");
    assert!(!msg.contains("panicked"), "{msg}");
}

/// SECURITY regression guard for the hard-rate-limit fail-closed mapping
/// ([`hard_rate_limit_allow`]): an ALIVE-but-wedged actor (`Elapsed`) MUST
/// deny (`false`), never fold into the `true` pass-through — that fold
/// would bypass the per-context hard-rate cap for the reply-timeout window.
/// The "no live bucket to enforce" cases (handler `Err`, terminated actor
/// `Dropped`) stay pass-through (`true`); a real consume verdict rides
/// through unchanged. Directly unit-tests the classifier the live
/// actor-mailbox path routes through (wedging a fully-wired Supervisor is
/// impractical; the mechanics of producing `Elapsed` are covered by
/// `bounded_reply_await`'s own `start_paused` unit test).
#[test]
fn hard_rate_limit_wedged_actor_fails_closed() {
    // Wedged/alive actor → deny.
    assert!(
        !hard_rate_limit_allow(&Err(BoundedReplyError::Elapsed)),
        "an Elapsed (wedged actor, unreachable bucket) MUST deny — never bypass the cap"
    );
    // Terminated actor (no live bucket) → legacy pass-through.
    assert!(
        hard_rate_limit_allow(&Err(BoundedReplyError::Dropped)),
        "a Dropped reply channel (terminated actor, no bucket) stays pass-through"
    );
    // Handler error (e.g. unregistered context, no bucket) → pass-through.
    assert!(
        hard_rate_limit_allow(&Ok(Err(ContextError::ContextNotRegistered(
            "ctx".to_owned()
        )))),
        "a handler Err (no live bucket) stays pass-through"
    );
    // Real handler verdicts ride through unchanged.
    assert!(
        hard_rate_limit_allow(&Ok(Ok(true))),
        "a real consume (token available) allows"
    );
    assert!(
        !hard_rate_limit_allow(&Ok(Ok(false))),
        "a real over-budget verdict denies"
    );
}

// -----------------------------------------------------------------
// DurableProviders same-backend behavioral proof (spec §17.6 / §17.16 /
// ADR-049). The same-backend invariant is enforced by construction
// (`from_handle` derives BOTH the journal and the `mls_storage` view from one
// handle), but this test pins the behavior the type guarantee rests on: an
// entry appended through the bundled journal is visible through the SAME
// handle that was passed to `from_handle`. A `from_handle` that ignored its
// handle and built a fresh store for either half would fail this read-back.
// This is the single canonical same-backend proof for all four production
// construction sites (PyO3, NAPI, UniFFI, scp-node), which all derive their
// pair via `DurableProviders::from_handle`.
// -----------------------------------------------------------------

#[tokio::test]
async fn durable_providers_from_handle_shares_one_backend() {
    use crate::context::supervisor::saga_journal::{JournalEntry, SagaId, SagaState};
    use scp_platform::traits::Storage;

    // ONE chosen backend handed to `from_handle`.
    let storage = Arc::new(InMemoryStorage::new());
    let durable = DurableProviders::from_handle(Arc::clone(&storage));

    // `into_parts` is `pub(crate)`, so this in-crate test can reach the
    // bundled journal to append through it. Out-of-crate callers cannot.
    let (journal, _mls_storage, _relay_contacts) = durable.into_parts();

    let saga = SagaId::new();
    let seq: u64 = 0;
    let entry = JournalEntry {
        saga_id: saga.clone(),
        state: SagaState::PreparingB,
        participants: vec!["ctx-seam".to_owned()],
        evidence: zeroize::Zeroizing::new(Vec::new()),
        timestamp_ms: 1_900_000_000_000,
        seq_per_saga: seq,
    };

    // Production journal write key: `saga_journal/{saga_id}/{seq:020}`.
    let expected_key = format!(
        "{}{saga}/{seq:020}",
        crate::context::supervisor::SAGA_JOURNAL_KEY_PREFIX
    );

    journal
        .append(entry)
        .await
        .expect("append via durable journal");

    // The entry MUST be visible through the ORIGINAL handle — proving the
    // journal and the handle that also feeds `mls_storage` share one backend.
    let raw = storage
        .retrieve(&expected_key)
        .await
        .expect("retrieve via the original storage handle");
    assert!(
        raw.is_some(),
        "the journal entry MUST be visible through the SAME handle passed to \
             from_handle — the journal and mls_storage share one backend by \
             construction; a from_handle that built a fresh store would miss key \
             {expected_key}"
    );
}

// -----------------------------------------------------------------
// CrashWindow pure-method unit tests (ADR-049 §10).
//
// These exercise the respawn-budget logic with explicit `now_ms`
// values — no clock, no actor, no async. They prove eviction,
// the exactly-3-in-window poison threshold, the
// 2-then-gap-then-1 non-poison case, sticky poison, and clear().
// -----------------------------------------------------------------

#[test]
fn crash_window_three_in_window_poisons() {
    let mut w = CrashWindow::default();
    assert!(!w.record(0), "1st crash does not poison");
    assert!(!w.record(100), "2nd crash does not poison");
    assert!(w.record(200), "3rd crash within 60s poisons");
    assert!(w.is_poisoned());
    assert_eq!(w.crash_count(), CRASH_POISON_THRESHOLD);
}

#[test]
fn crash_window_two_then_gap_then_one_does_not_poison() {
    let mut w = CrashWindow::default();
    // Two crashes near t=0.
    assert!(!w.record(0));
    assert!(!w.record(1_000));
    // A third crash AFTER the window has slid past the first two: at
    // t = 1_000 + 60_001, the entries at 0 and 1_000 are both strictly
    // older than 60s relative to `now_ms` and get evicted, leaving only
    // the newest. Count is 1, so no poison.
    let now = 1_000 + CRASH_WINDOW_MS + 1;
    assert!(
        !w.record(now),
        "the two early crashes evicted; only 1 remains"
    );
    assert!(!w.is_poisoned());
    assert_eq!(w.crash_count(), 1);
}

#[test]
fn crash_window_evicts_only_strictly_older_than_window() {
    let mut w = CrashWindow::default();
    // Crash at the exact window edge is RETAINED (eviction is strict
    // `> CRASH_WINDOW_MS`).
    assert!(!w.record(0));
    assert!(!w.record(CRASH_WINDOW_MS)); // exactly 60s later: front kept
    assert_eq!(w.crash_count(), 2, "edge-of-window crash is not evicted");
    // A third within the same window poisons (all three within 60s of
    // the newest).
    assert!(w.record(CRASH_WINDOW_MS), "3rd within window poisons");
}

#[test]
fn crash_window_poison_is_sticky_across_later_eviction() {
    let mut w = CrashWindow::default();
    w.record(0);
    w.record(100);
    assert!(w.record(200), "poisoned at 3 crashes");
    // A much-later record evicts the old crashes (count drops) but the
    // sticky flag must stay set — an in-window eviction must NOT
    // silently un-poison.
    let later = 200 + CRASH_WINDOW_MS * 10;
    assert!(
        w.record(later),
        "poison persists even after the window slides past the old crashes"
    );
    assert!(w.is_poisoned());
}

#[test]
fn crash_window_clear_unpoison_and_resets() {
    let mut w = CrashWindow::default();
    w.record(0);
    w.record(100);
    w.record(200);
    assert!(w.is_poisoned());
    w.clear();
    assert!(!w.is_poisoned(), "clear() un-poisons");
    assert_eq!(w.crash_count(), 0, "clear() empties the deque");
    // After clear the budget starts fresh: one crash does not re-poison.
    assert!(!w.record(300));
}

#[test]
fn crash_window_deque_is_length_capped() {
    // Under a pathological non-monotonic clock that never advances past
    // the window, the deque must stay bounded by the defensive cap.
    let mut w = CrashWindow::default();
    for _ in 0..100 {
        w.record(0);
    }
    assert!(
        w.crash_count() <= CRASH_DEQUE_CAP,
        "deque length is defensively capped at {CRASH_DEQUE_CAP}"
    );
    assert!(w.is_poisoned(), "many same-instant crashes poison");
}

/// In-memory `ContextPersistence` stub for tests only. Returns an
/// empty snapshot for every load and silently accepts every persist.
/// Production callers wire the real
/// `ProtocolRepositoryContextBridge`.
struct TestPersistence;
#[async_trait::async_trait]
impl ContextPersistence for TestPersistence {
    async fn persist_context(
        &self,
        _: &str,
        _: &crate::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    async fn load_context(
        &self,
        _: &str,
    ) -> Result<
        Option<crate::context::state::ContextSnapshot>,
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

fn test_supervisor() -> Supervisor {
    let persistence: Arc<dyn ContextPersistence> = Arc::new(TestPersistence);
    let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::new(
        InMemoryStorage::new(),
    )));
    Supervisor::new(
        persistence,
        journal,
        SupervisorConfig::default(),
        crate::domain_handlers(),
    )
}

#[tokio::test]
async fn fresh_supervisor_has_empty_registries() {
    let s = test_supervisor();
    assert!(s.lookup("any-ctx").is_none());
    assert!(s.local_dids.load().is_empty());
    assert!(s.standing_contexts.load().is_empty());
}

/// A supervisor with no event-log provider wired reports the summary as
/// `NotInitialized` rather than as an empty log.
#[tokio::test]
async fn event_log_summary_without_a_provider_is_not_initialized() {
    let s = test_supervisor();
    let summary = s.event_log_summary(&[7u8; 32]);
    assert!(
        matches!(summary, Err(ContextError::NotInitialized(_))),
        "a supervisor with no event-log provider must not summarize a log, got {summary:?}"
    );
}

// ---------------------------------------------------------------
// Outlet streaming (spec §5.4.5) — pump semaphore + per-context
// admission-tracker registry (chunk 3d).
// ---------------------------------------------------------------

/// The node-wide pump semaphore is sized from
/// `SupervisorConfig::max_concurrent_outlet_stream_pumps` (default
/// `DEFAULT_MAX_CONCURRENT_OUTLET_STREAM_PUMPS`) and the getter hands
/// back a clone of the SAME shared semaphore.
#[tokio::test]
async fn outlet_stream_pump_semaphore_sized_from_config_default() {
    let s = test_supervisor();
    let sem = s.outlet_stream_pump_semaphore();
    assert_eq!(
        sem.available_permits(),
        DEFAULT_MAX_CONCURRENT_OUTLET_STREAM_PUMPS as usize,
        "default config sizes the semaphore at the default cap",
    );
    // The getter returns a clone of the same underlying semaphore:
    // acquiring a permit from one view is observed by another.
    let permit = sem.try_acquire().expect("a permit is available");
    assert_eq!(
        s.outlet_stream_pump_semaphore().available_permits(),
        DEFAULT_MAX_CONCURRENT_OUTLET_STREAM_PUMPS as usize - 1,
        "getter clones share one semaphore, not independent copies",
    );
    drop(permit);
}

/// A non-default (and out-of-range) config value is clamped into
/// `[MIN, MAX]` when sizing the semaphore.
#[tokio::test]
async fn outlet_stream_pump_semaphore_clamps_config_value() {
    let persistence: Arc<dyn ContextPersistence> = Arc::new(TestPersistence);
    let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::new(
        InMemoryStorage::new(),
    )));
    // 0 requested → clamped up to the floor (MIN).
    let cfg_zero = SupervisorConfig {
        max_concurrent_outlet_stream_pumps: 0,
    };
    let s_zero = Supervisor::new(
        Arc::clone(&persistence),
        Arc::clone(&journal),
        cfg_zero,
        crate::domain_handlers(),
    );
    assert_eq!(
        s_zero.outlet_stream_pump_semaphore().available_permits(),
        MIN_MAX_CONCURRENT_OUTLET_STREAM_PUMPS as usize,
        "a 0 config clamps up to MIN (streaming must not deadlock)",
    );
    // Above MAX → clamped down to the ceiling (MAX).
    let cfg_huge = SupervisorConfig {
        max_concurrent_outlet_stream_pumps: MAX_MAX_CONCURRENT_OUTLET_STREAM_PUMPS + 1,
    };
    let s_huge = Supervisor::new(persistence, journal, cfg_huge, crate::domain_handlers());
    assert_eq!(
        s_huge.outlet_stream_pump_semaphore().available_permits(),
        MAX_MAX_CONCURRENT_OUTLET_STREAM_PUMPS as usize,
        "an over-MAX config clamps down to MAX",
    );
}

/// `outlet_stream_admission_for` is get-or-create: repeated calls for
/// one `context_id` return clones of the SAME `Arc`; distinct
/// `context_id`s get distinct trackers.
#[tokio::test]
async fn outlet_stream_admission_for_is_get_or_create() {
    let s = test_supervisor();
    let a1 = s.outlet_stream_admission_for("ctx-a");
    let a2 = s.outlet_stream_admission_for("ctx-a");
    assert!(
        Arc::ptr_eq(&a1, &a2),
        "repeated calls for one context_id share the SAME tracker Arc",
    );
    let b1 = s.outlet_stream_admission_for("ctx-b");
    assert!(
        !Arc::ptr_eq(&a1, &b1),
        "distinct context_ids get distinct trackers",
    );
}

/// `reap_stream_admission` removes the registry entry so it does not
/// leak. A subsequent get-or-create yields a FRESH tracker (distinct
/// `Arc`), and a live `Arc` held across the reap stays valid (only the
/// registry's reference is dropped, never a live tracker).
#[tokio::test]
async fn reap_stream_admission_removes_entry_without_invalidating_live_arc() {
    let s = test_supervisor();
    let before = s.outlet_stream_admission_for("ctx-reap");
    // Hold a live clone across the reap — mirrors an in-flight pump.
    let live = Arc::clone(&before);

    s.reap_stream_admission("ctx-reap");

    // The live Arc is still usable after the registry entry is dropped.
    {
        let _guard = live
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // (tracker is accessible; no panic / poisoning)
    }

    // A fresh get-or-create after the reap allocates a NEW tracker.
    let after = s.outlet_stream_admission_for("ctx-reap");
    assert!(
        !Arc::ptr_eq(&before, &after),
        "after reap, get-or-create allocates a fresh tracker",
    );
    // Reaping an absent context is a harmless no-op.
    s.reap_stream_admission("never-existed");
}

/// A supervisor whose `mls_storage` view is over `storage` and whose
/// wrapping keys live in `custody`, so two supervisors built on one store
/// and one custody model a node restart.
fn supervisor_over_storage<
    S: scp_platform::traits::Storage + 'static,
    C: scp_platform::traits::KeyCustody + 'static,
>(
    storage: Arc<S>,
    custody: &Arc<C>,
) -> Arc<Supervisor> {
    let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
        "did:dht:z6MktestDoNotRely".to_owned(),
        Arc::new(scp_clock::SystemClock),
    ));
    supervisor_with_crypto_storage_and_custody(crypto, storage, custody)
}

/// The raw bytes stored under `did`'s wrapping key record.
async fn stored_wrapping_record(sup: &Supervisor, did: &str) -> Option<Vec<u8>> {
    sup.mls_storage_ref()
        .unwrap()
        .retrieve(&format!("wrapping_key/{did}"))
        .await
        .unwrap()
}

/// The public point custody reports for `handle`.
async fn custody_public(
    custody: &crate::crypto::dh_counting_custody::DhCountingCustody,
    handle: &scp_platform::KeyHandle,
) -> [u8; 65] {
    use scp_platform::traits::KeyCustody as _;
    custody
        .inner
        .public_key(handle)
        .await
        .unwrap()
        .as_bytes()
        .try_into()
        .unwrap()
}

/// The first load of an identity generates a P-256 key in custody and
/// stores only its handle and public point (spec 09 §9.16.1): the record
/// names the custody's handle, carries the public point custody reports
/// for it, and holds no field for key material. Later loads return the
/// same key, and another identity gets its own.
#[tokio::test]
async fn load_wrapping_key_generates_a_custody_handle_and_stores_only_the_handle() {
    let storage = Arc::new(InMemoryStorage::new());
    let custody = Arc::new(crate::crypto::dh_counting_custody::DhCountingCustody::new());
    let sup = supervisor_over_storage(Arc::clone(&storage), &custody);
    let alice = DID("did:example:wrap-alice".to_owned());
    let bob = DID("did:example:wrap-bob".to_owned());

    let key = sup.load_wrapping_key(&alice).await.unwrap();
    assert_eq!(custody.generate_calls(), 1, "one key is generated");
    assert_eq!(*key.public(), custody_public(&custody, key.handle()).await);
    let again = sup.load_wrapping_key(&alice).await.unwrap();
    assert!(Arc::ptr_eq(&key, &again), "one key per identity");
    assert_eq!(
        custody.generate_calls(),
        1,
        "a second load generates nothing"
    );

    let bytes = stored_wrapping_record(&sup, &alice.0)
        .await
        .expect("the handle is stored before use");
    let stored: crate::store::wrapping_key::StoredWrappingKeyHandle =
        scp_platform::store_value::from_stored_value_bytes(&bytes).unwrap();
    assert_eq!(stored.v, 1);
    assert_eq!(&stored.handle, key.handle());
    assert_eq!(stored.public.as_slice(), key.public().as_slice());
    let record = crate::store::wrapping_key::load_wrapping_key_handle(
        sup.mls_storage_ref().unwrap().as_ref(),
        &alice,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&record.handle, key.handle());
    assert_eq!(record.public, *key.public());

    let bob_key = sup.load_wrapping_key(&bob).await.unwrap();
    assert_ne!(
        bob_key.handle(),
        key.handle(),
        "each identity has its own key"
    );
    assert_ne!(bob_key.public(), key.public());
}

/// A supervisor restarted over the same storage and the same custody
/// loads the stored handle: the handle and public point are unchanged and
/// custody generated one key across both supervisors.
#[tokio::test]
async fn load_wrapping_key_reloads_the_same_handle_after_restart() {
    let storage = Arc::new(InMemoryStorage::new());
    let custody = Arc::new(crate::crypto::dh_counting_custody::DhCountingCustody::new());
    let alice = DID("did:example:wrap-restart".to_owned());

    let first = supervisor_over_storage(Arc::clone(&storage), &custody);
    let key = first.load_wrapping_key(&alice).await.unwrap();
    let (handle, public) = (*key.handle(), *key.public());
    drop(key);
    first.shutdown_all_contexts().await;
    drop(first);

    let restarted = supervisor_over_storage(storage, &custody);
    let reloaded = restarted.load_wrapping_key(&alice).await.unwrap();
    assert_eq!(
        reloaded.handle(),
        &handle,
        "a restart loads the stored handle"
    );
    assert_eq!(*reloaded.public(), public);
    assert_eq!(
        custody.generate_calls(),
        1,
        "a restart never generates a fresh key"
    );
}

/// A stored record whose handle the custody does not hold fails closed
/// with `WrappingKeyHandleInvalid`: no key is generated over it, the record
/// stays as it was, and no key is loaded.
#[tokio::test]
async fn load_wrapping_key_refuses_a_record_whose_handle_the_custody_does_not_hold() {
    let storage = Arc::new(InMemoryStorage::new());
    let did = DID("did:example:wrap-lost-custody".to_owned());
    let original = Arc::new(crate::crypto::dh_counting_custody::DhCountingCustody::new());
    let first = supervisor_over_storage(Arc::clone(&storage), &original);
    first.load_wrapping_key(&did).await.unwrap();
    let before = stored_wrapping_record(&first, &did.0).await;
    first.shutdown_all_contexts().await;
    drop(first);

    let other = Arc::new(crate::crypto::dh_counting_custody::DhCountingCustody::new());
    let sup = supervisor_over_storage(storage, &other);
    let err = sup.load_wrapping_key(&did).await.unwrap_err();
    assert!(
        matches!(err, ContextError::WrappingKeyHandleInvalid),
        "{err:?}"
    );
    assert_eq!(
        other.generate_calls(),
        0,
        "no key is generated over the record"
    );
    assert_eq!(stored_wrapping_record(&sup, &did.0).await, before);
    assert!(sup.wrapping_keys.get(&did).is_none());
}

/// A stored record whose public point differs from the point custody
/// reports for its handle fails closed with `WrappingKeyHandleInvalid`,
/// and no key is generated.
#[tokio::test]
async fn load_wrapping_key_refuses_a_record_whose_public_key_differs_from_the_record() {
    use scp_platform::traits::KeyCustody as _;
    let storage = Arc::new(InMemoryStorage::new());
    let custody = Arc::new(crate::crypto::dh_counting_custody::DhCountingCustody::new());
    let sup = supervisor_over_storage(Arc::clone(&storage), &custody);
    let did = DID("did:example:wrap-swapped".to_owned());
    let held = custody
        .inner
        .generate_keypair(scp_platform::traits::KeyType::HpkeP256)
        .await
        .unwrap();
    let other = custody
        .inner
        .generate_keypair(scp_platform::traits::KeyType::HpkeP256)
        .await
        .unwrap();
    let swapped = custody_public(&custody, &other).await;
    crate::store::wrapping_key::store_wrapping_key_handle(
        sup.mls_storage_ref().unwrap().as_ref(),
        &did,
        &held,
        &swapped,
    )
    .await
    .unwrap();

    let err = sup.load_wrapping_key(&did).await.unwrap_err();
    assert!(
        matches!(err, ContextError::WrappingKeyHandleInvalid),
        "{err:?}"
    );
    assert_eq!(custody.generate_calls(), 0, "no key is generated");
    assert!(sup.wrapping_keys.get(&did).is_none());
}

/// The `0xFF01` key the own leaf publishes in a context's persisted
/// crypto snapshot.
fn persisted_own_wrapping_key(
    contexts: &DashMap<String, crate::context::state::ContextSnapshot>,
    context_id: &str,
) -> Option<[u8; 65]> {
    let mls_state = contexts
        .get(context_id)
        .expect("context persisted")
        .mls_crypto_state
        .clone();
    let (owned, _floors) = crate::crypto::mls::provider::NodeMlsFactory::build_restored_owned(
        &crate::context::state::context_id_to_bytes(context_id),
        &mls_state,
    )
    .unwrap();
    scp_mls::wrapping_extension::extract_own_wrapping_key(&owned.mls_group)
        .unwrap()
        .map(|key| *key.as_bytes())
}

/// One identity publishes one wrapping key (spec 09 §9.16.1): two
/// contexts it creates carry the same `0xFF01`, equal to the key the
/// supervisor holds for it; restoring one of them leaves that key as it
/// was and loads no key for any other DID.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn contexts_of_one_identity_share_its_wrapping_key_across_a_restore() {
    let persistence = MapPersistence::default();
    let contexts = Arc::clone(&persistence.contexts);
    let sup = supervisor_with_clock_and_persistence(
        Arc::new(TestClock::new(1_700_000_000)),
        Box::new(persistence),
    );
    let identity = sup.node_identity().unwrap();
    let ctx_a = hex::encode([0xA1u8; 32]);
    let ctx_b = hex::encode([0xB2u8; 32]);
    let mut handle_a = None;
    for ctx in [&ctx_a, &ctx_b] {
        let handle = sup
            .create_context(
                ctx.clone(),
                scp_protocol::context::ContextParams {
                    ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
                    ..Default::default()
                },
                identity.clone(),
                None,
                Vec::new(),
            )
            .await
            .unwrap();
        handle_a.get_or_insert(handle);
    }
    let key = sup.load_wrapping_key(&identity).await.unwrap();
    let owner = *key.public();
    assert_eq!(persisted_own_wrapping_key(&contexts, &ctx_a), Some(owner));
    assert_eq!(persisted_own_wrapping_key(&contexts, &ctx_b), Some(owner));

    assert!(sup.despawn_actor(&ctx_a).await);
    sup.restore_context(&ctx_a, &handle_a.unwrap())
        .await
        .unwrap();
    let after = sup.load_wrapping_key(&identity).await.unwrap();
    assert!(
        Arc::ptr_eq(&key, &after),
        "the restore keeps the owner's loaded key"
    );
    assert_eq!(*after.public(), owner, "the restore keeps the owner's key");
    assert_eq!(
        sup.wrapping_keys.len(),
        1,
        "no key is loaded for another DID"
    );
    assert_eq!(persisted_own_wrapping_key(&contexts, &ctx_a), Some(owner));
}

/// A context's relay set (§5.12.3.1 `relay_urls`, PUSH-025) is the
/// creator's set at create, deduplicated in first-seen order, and its
/// snapshot persists it. Restore installs the stored set: the test rewrites
/// the stored set while the actor is down, deletes the snapshot after the
/// restore, and the flush writes the rewritten set back from the live actor.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn context_relay_set_is_set_at_create_and_installed_on_restore() {
    const RELAY_A: &str = "wss://relay-a.example/scp/v1";
    const RELAY_B: &str = "wss://relay-b.example/scp/v1";
    const RELAY_C: &str = "wss://relay-c.example/scp/v1";
    let persistence = MapPersistence::default();
    let contexts = Arc::clone(&persistence.contexts);
    let sup = supervisor_with_clock_and_persistence(
        Arc::new(TestClock::new(1_700_000_000)),
        Box::new(persistence),
    );
    let identity = sup.node_identity().unwrap();
    let ctx = hex::encode([0xC3u8; 32]);
    let stored = |contexts: &DashMap<String, crate::context::state::ContextSnapshot>| {
        contexts
            .get(&ctx)
            .map(|snapshot| snapshot.relay_urls.clone())
    };

    let handle = sup
        .create_context(
            ctx.clone(),
            scp_protocol::context::ContextParams {
                ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
                ..Default::default()
            },
            identity,
            None,
            vec![RELAY_B.to_owned(), RELAY_A.to_owned(), RELAY_B.to_owned()],
        )
        .await
        .unwrap();
    assert_eq!(
        stored(&contexts),
        Some(vec![RELAY_B.to_owned(), RELAY_A.to_owned()]),
        "create persists the creator's relay set, each relay once"
    );

    assert!(sup.despawn_actor(&ctx).await);
    contexts
        .get_mut(&ctx)
        .expect("context persisted")
        .relay_urls = vec![RELAY_C.to_owned()];
    sup.restore_context(&ctx, &handle).await.unwrap();
    contexts.remove(&ctx);
    sup.flush_all_contexts().await.unwrap();
    assert_eq!(
        stored(&contexts),
        Some(vec![RELAY_C.to_owned()]),
        "restore installs the stored relay set on the live actor"
    );
}

/// Creates a context on `relay_urls`, then returns the relay set its
/// snapshot persists and the relay set its live actor holds.
#[cfg(feature = "testing")]
async fn created_relay_set(
    ctx_byte: u8,
    relay_urls: &[&str],
) -> (Option<Vec<String>>, Option<Vec<String>>) {
    let persistence = MapPersistence::default();
    let contexts = Arc::clone(&persistence.contexts);
    let sup = supervisor_with_clock_and_persistence(
        Arc::new(TestClock::new(1_700_000_000)),
        Box::new(persistence),
    );
    let identity = sup.node_identity().unwrap();
    let ctx = hex::encode([ctx_byte; 32]);
    sup.create_context(
        ctx.clone(),
        scp_protocol::context::ContextParams {
            ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
            ..Default::default()
        },
        identity,
        None,
        relay_urls.iter().map(|u| (*u).to_owned()).collect(),
    )
    .await
    .expect("create succeeds whatever the relay URLs");
    let persisted = contexts.get(&ctx).map(|s| s.relay_urls.clone());
    (persisted, sup.context_relay_urls(&ctx).await)
}

/// Create stores two spellings of one relay as one entry, the §9.18.2
/// canonical relay URL (§5.12.3.1 `relay_urls`).
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_stores_two_spellings_of_a_relay_as_one_canonical_entry() {
    const SPELLING_1: &str = "WSS://Relay-A.Example:443/scp/v1/";
    const SPELLING_2: &str = "wss://relay-a.example/scp/v1";
    let want = Some(vec![SPELLING_2.to_owned()]);
    assert_eq!(
        created_relay_set(0xC4, &[SPELLING_1, SPELLING_2]).await,
        (want.clone(), want)
    );
}

/// Create stores a relay URL with no §9.18.2 canonical form exactly as
/// written, and succeeds.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_stores_a_relay_url_without_canonical_form_as_written() {
    const HTTPS: &str = "https://Relay-A.Example/scp/v1/";
    let want = Some(vec![HTTPS.to_owned()]);
    assert_eq!(
        created_relay_set(0xC5, &[HTTPS]).await,
        (want.clone(), want)
    );
}

/// Creates a context, rewrites its persisted relay set to `stored` while
/// its actor is down, restores it, and returns the relay set the flush
/// writes back from the live actor.
#[cfg(feature = "testing")]
async fn restored_relay_set(ctx_byte: u8, stored: &[&str]) -> Option<Vec<String>> {
    let persistence = MapPersistence::default();
    let contexts = Arc::clone(&persistence.contexts);
    let sup = supervisor_with_clock_and_persistence(
        Arc::new(TestClock::new(1_700_000_000)),
        Box::new(persistence),
    );
    let identity = sup.node_identity().unwrap();
    let ctx = hex::encode([ctx_byte; 32]);
    let handle = sup
        .create_context(
            ctx.clone(),
            scp_protocol::context::ContextParams {
                ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
                ..Default::default()
            },
            identity,
            None,
            vec!["wss://relay-z.example".to_owned()],
        )
        .await
        .unwrap();
    assert!(sup.despawn_actor(&ctx).await);
    contexts
        .get_mut(&ctx)
        .expect("context persisted")
        .relay_urls = stored.iter().map(|u| (*u).to_owned()).collect();
    sup.restore_context(&ctx, &handle)
        .await
        .expect("restore succeeds whatever the relay URLs");
    contexts.remove(&ctx);
    sup.flush_all_contexts().await.unwrap();
    contexts.get(&ctx).map(|s| s.relay_urls.clone())
}

/// Restore stores two spellings of one relay as one entry, the §9.18.2
/// canonical relay URL.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_stores_two_spellings_of_a_relay_as_one_canonical_entry() {
    const SPELLING_1: &str = "WSS://Relay-A.Example:443/scp/v1/";
    const SPELLING_2: &str = "wss://relay-a.example/scp/v1";
    assert_eq!(
        restored_relay_set(0xC6, &[SPELLING_1, SPELLING_2]).await,
        Some(vec![SPELLING_2.to_owned()])
    );
}

/// Restore stores a relay URL with no §9.18.2 canonical form exactly as
/// written, and succeeds.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_stores_a_relay_url_without_canonical_form_as_written() {
    const HTTPS: &str = "https://Relay-A.Example/scp/v1/";
    assert_eq!(
        restored_relay_set(0xC7, &[HTTPS]).await,
        Some(vec![HTTPS.to_owned()])
    );
}

/// PUSH-013: with two contexts on two relays, one of them on both,
/// `push_routing_ids` maps each relay to exactly the routing IDs of the
/// contexts on it, and holds this
/// device's current local pseudonym routing ID for each context. After the
/// local pseudonym changes through the join path, the next query returns
/// the new one and not the old one.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_routing_ids_group_by_relay_and_follow_the_local_pseudonym() {
    use std::collections::{BTreeMap, BTreeSet};

    const RELAY_A: &str = "wss://relay-a.example/scp/v1";
    const RELAY_B: &str = "wss://relay-b.example/scp/v1";
    const PSEUDONYM_A: [u8; 32] = [0xA1; 32];
    const PSEUDONYM_B: [u8; 32] = [0xB1; 32];
    const PSEUDONYM_A_NEW: [u8; 32] = [0xA2; 32];
    let sup = supervisor_with_providers();
    let identity = sup.node_identity().unwrap();
    let params = || scp_protocol::context::ContextParams {
        ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
        ..Default::default()
    };
    let ctx_a = hex::encode([0xA0u8; 32]);
    let ctx_b = hex::encode([0xB0u8; 32]);
    let handle_a = sup
        .create_context(
            ctx_a.clone(),
            params(),
            identity.clone(),
            Some(PSEUDONYM_A),
            vec![RELAY_A.to_owned()],
        )
        .await
        .unwrap();
    sup.create_context(
        ctx_b.clone(),
        params(),
        identity,
        Some(PSEUDONYM_B),
        vec![RELAY_B.to_owned(), RELAY_A.to_owned()],
    )
    .await
    .unwrap();
    let shared_a = scp_protocol::context::context_routing_id(&ctx_a);
    let shared_b = scp_protocol::context::context_routing_id(&ctx_b);

    assert_eq!(
        sup.push_routing_ids().await.unwrap(),
        BTreeMap::from([
            (
                RELAY_A.to_owned(),
                BTreeSet::from([shared_a, PSEUDONYM_A, shared_b, PSEUDONYM_B]),
            ),
            (RELAY_B.to_owned(), BTreeSet::from([shared_b, PSEUDONYM_B])),
        ]),
        "each relay maps to exactly the routing IDs of the contexts on it"
    );

    sup.join_context(
        &handle_a,
        scp_protocol::context::membership::KeyPackage::mock(DID(
            "did:dht:z6MkPushRoutingJoiner".to_owned()
        )),
        None,
        Some(PSEUDONYM_A_NEW),
    )
    .await
    .unwrap();

    let after = sup.push_routing_ids().await.unwrap();
    assert_eq!(
        after.get(RELAY_A),
        Some(&BTreeSet::from([
            shared_a,
            PSEUDONYM_A_NEW,
            shared_b,
            PSEUDONYM_B
        ])),
        "the next query returns the new local pseudonym and not the old one"
    );
    assert_eq!(
        after.get(RELAY_B),
        Some(&BTreeSet::from([shared_b, PSEUDONYM_B])),
        "the other context's routing IDs are unchanged"
    );
}

/// A supervisor with no context actors returns an empty map.
#[tokio::test]
async fn push_routing_ids_is_empty_without_contexts() {
    let sup = supervisor_with_providers();
    assert!(sup.push_routing_ids().await.unwrap().is_empty());
}

/// Creates an encrypted context `ctx_id` on `relay_urls` for the
/// `push_routing_ids` tests.
#[cfg(feature = "testing")]
async fn create_push_context(sup: &Arc<Supervisor>, ctx_id: &str, relay_urls: &[&str]) {
    let identity = sup.node_identity().unwrap();
    sup.create_context(
        ctx_id.to_owned(),
        scp_protocol::context::ContextParams {
            ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
            ..Default::default()
        },
        identity,
        Some([0x5A; 32]),
        relay_urls.iter().map(|u| (*u).to_owned()).collect(),
    )
    .await
    .unwrap();
}

/// Two spellings of one relay share one key, the §9.18.2 canonical URL.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_routing_ids_group_equivalent_relay_spellings_under_one_key() {
    let sup = supervisor_with_providers();
    let ctx_a = hex::encode([0xC0u8; 32]);
    let ctx_b = hex::encode([0xC1u8; 32]);
    create_push_context(&sup, &ctx_a, &["wss://relay.example"]).await;
    create_push_context(&sup, &ctx_b, &["WSS://Relay.Example:443/"]).await;
    let by_relay = sup.push_routing_ids().await.unwrap();
    assert_eq!(
        by_relay.keys().collect::<Vec<_>>(),
        vec!["wss://relay.example"],
        "both spellings map to the one canonical relay URL"
    );
    let ids = &by_relay["wss://relay.example"];
    assert!(ids.contains(&scp_protocol::context::context_routing_id(&ctx_a)));
    assert!(ids.contains(&scp_protocol::context::context_routing_id(&ctx_b)));
}

/// A relay URL with no §9.18.2 canonical form gets no entry. The query
/// still returns the routing IDs for the context's other relay and for a
/// second context on the same device.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_routing_ids_skip_a_relay_url_with_no_canonical_form() {
    use std::collections::{BTreeMap, BTreeSet};

    let sup = supervisor_with_providers();
    let mixed = hex::encode([0xC2u8; 32]);
    let other = hex::encode([0xC3u8; 32]);
    create_push_context(
        &sup,
        &mixed,
        &["wss://relay-a.example", "https://relay-b.example"],
    )
    .await;
    create_push_context(&sup, &other, &["wss://relay-c.example"]).await;
    assert_eq!(
        sup.push_routing_ids().await.unwrap(),
        BTreeMap::from([
            (
                "wss://relay-a.example".to_owned(),
                BTreeSet::from([
                    scp_protocol::context::context_routing_id(&mixed),
                    [0x5A; 32]
                ]),
            ),
            (
                "wss://relay-c.example".to_owned(),
                BTreeSet::from([
                    scp_protocol::context::context_routing_id(&other),
                    [0x5A; 32]
                ]),
            ),
        ]),
        "the https URL gets no entry, and both contexts keep their routing IDs"
    );
}

/// A context whose actor is down — poisoned, its last respawn failed, or
/// mid-respawn — fails the query with the typed error `lookup_miss_error`
/// gives it, instead of being left out of an `Ok` result.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_routing_ids_fail_when_a_context_actor_is_down() {
    for down in 0..3u8 {
        let sup = supervisor_with_providers();
        let healthy = hex::encode([0xD0u8; 32]);
        let broken = hex::encode([0xD1u8; 32]);
        create_push_context(&sup, &healthy, &["wss://relay.example"]).await;
        create_push_context(&sup, &broken, &["wss://relay.example"]).await;
        assert!(sup.push_routing_ids().await.is_ok(), "both actors are up");
        match down {
            0 => sup.test_poison_context(&broken).await,
            1 => sup.test_fail_context_respawn(&broken).await,
            _ => sup.test_hold_context_mid_respawn(&broken).await,
        }
        let result = sup.push_routing_ids().await;
        if down == 0 {
            assert!(
                matches!(result, Err(ContextError::ContextPoisoned(ref id)) if *id == broken),
                "a poisoned context fails the query: {result:?}"
            );
        } else {
            assert!(
                matches!(result, Err(ContextError::ActorCrashed(ref id)) if *id == broken),
                "a crashed context fails the query: {result:?}"
            );
        }
    }
}

/// `wake_targets` returns each `Active` context's ID, persisted relay set,
/// shared routing ID and local pseudonym, and fails closed when a context
/// actor is down (ADR-029 §2, push-wake pull mode).
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wake_targets_list_active_contexts_and_fail_when_an_actor_is_down() {
    let sup = supervisor_with_providers();
    assert!(sup.wake_targets().await.unwrap().is_empty());
    assert!(!sup.has_known_contexts());
    let a = hex::encode([0xC0u8; 32]);
    let b = hex::encode([0xC1u8; 32]);
    create_push_context(&sup, &a, &["wss://relay-a.example"]).await;
    create_push_context(&sup, &b, &["wss://relay-b.example"]).await;
    assert!(sup.has_known_contexts());
    let mut targets = sup.wake_targets().await.unwrap();
    targets.sort_by(|x, y| x.context_id.cmp(&y.context_id));
    assert_eq!(
        targets,
        vec![
            crate::context::push_routes::ContextWakeTarget {
                context_id: a.clone(),
                relay_urls: vec!["wss://relay-a.example".to_owned()],
                routing_ids: vec![scp_protocol::context::context_routing_id(&a), [0x5A; 32]],
            },
            crate::context::push_routes::ContextWakeTarget {
                context_id: b.clone(),
                relay_urls: vec!["wss://relay-b.example".to_owned()],
                routing_ids: vec![scp_protocol::context::context_routing_id(&b), [0x5A; 32]],
            },
        ]
    );
    sup.test_poison_context(&b).await;
    let result = sup.wake_targets().await;
    assert!(
        matches!(result, Err(ContextError::ContextPoisoned(ref id)) if *id == b),
        "a poisoned context fails the wake targets: {result:?}"
    );
}

/// A [`MapPersistence`] whose `load_context` fails for one id, for the
/// load-error arm of `unrestored_active_contexts`.
struct FailingLoadPersistence {
    inner: MapPersistence,
    failing_id: String,
}
#[async_trait::async_trait]
impl ContextPersistence for FailingLoadPersistence {
    async fn persist_context(
        &self,
        id: &str,
        snap: &crate::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner.persist_context(id, snap).await
    }
    async fn load_context(
        &self,
        id: &str,
    ) -> Result<
        Option<crate::context::state::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        if id == self.failing_id {
            return Err("injected load failure".into());
        }
        self.inner.load_context(id).await
    }
    async fn delete_context(
        &self,
        id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner.delete_context(id).await
    }
    async fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        self.inner.list_persisted_contexts().await
    }
}

/// `unrestored_active_contexts` lists a persisted `Active` context with no
/// actor, and skips a resident context and a persisted non-`Active` one
/// (ADR-029 §2 push-wake pull mode, step 2).
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrestored_active_contexts_skip_resident_and_non_active_contexts() {
    let persistence = MapPersistence::default();
    let contexts = Arc::clone(&persistence.contexts);
    let sup = supervisor_with_clock_and_persistence(
        Arc::new(TestClock::new(1_700_000_000)),
        Box::new(persistence),
    );
    let resident = hex::encode([0xD0u8; 32]);
    create_push_context(&sup, &resident, &["wss://relay.example"]).await;
    let snapshot = contexts.get(&resident).unwrap().value().clone();
    assert_eq!(
        sup.unrestored_active_contexts().await.unwrap(),
        Vec::<String>::new()
    );

    let unrestored = hex::encode([0xD1u8; 32]);
    contexts.insert(unrestored.clone(), snapshot.clone());
    let mut closed_snapshot = snapshot;
    closed_snapshot.state = scp_protocol::context::ContextState::Closed;
    contexts.insert(hex::encode([0xD2u8; 32]), closed_snapshot);
    assert_eq!(
        sup.unrestored_active_contexts().await.unwrap(),
        vec![unrestored],
        "only the persisted Active context with no actor is listed"
    );
}

/// `unrestored_active_contexts` fails on a snapshot load error instead of
/// skipping the context, because the wake would then report `NoData` for a
/// context it never pulled.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrestored_active_contexts_fail_on_a_load_error() {
    let inner = MapPersistence::default();
    let contexts = Arc::clone(&inner.contexts);
    let failing_id = hex::encode([0xD3u8; 32]);
    let sup = supervisor_with_clock_and_persistence(
        Arc::new(TestClock::new(1_700_000_000)),
        Box::new(FailingLoadPersistence {
            inner,
            failing_id: failing_id.clone(),
        }),
    );
    let resident = hex::encode([0xD4u8; 32]);
    create_push_context(&sup, &resident, &["wss://relay.example"]).await;
    let snapshot = contexts.get(&resident).unwrap().value().clone();
    contexts.insert(failing_id.clone(), snapshot);
    let result = sup.unrestored_active_contexts().await;
    assert!(
        matches!(result, Err(ContextError::PersistenceFailed(ref m)) if m.contains(&failing_id)),
        "{result:?}"
    );
}

/// `restore_unrestored_contexts` restores a persisted `Active` context that
/// has no actor, in a supervisor that already holds a live one, and leaves
/// the live actor in place.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_unrestored_contexts_restores_only_the_missing_context() {
    let sup = supervisor_with_clock_and_persistence(
        Arc::new(TestClock::new(1_700_000_000)),
        Box::new(MapPersistence::default()),
    );
    let resident = hex::encode([0xD5u8; 32]);
    create_push_context(&sup, &resident, &["wss://relay.example"]).await;
    // A second real context whose actor goes away while its snapshot
    // stays persisted: the state a failed restore leaves.
    let missing = hex::encode([0xD6u8; 32]);
    create_push_context(&sup, &missing, &["wss://relay.example"]).await;
    sup.flush_all_contexts().await.unwrap();
    assert!(sup.despawn_actor(&missing).await);
    assert_eq!(
        sup.unrestored_active_contexts().await.unwrap(),
        vec![missing.clone()]
    );

    assert_eq!(
        sup.restore_unrestored_contexts().await.unwrap(),
        Vec::<String>::new()
    );
    let mut answering: Vec<String> = sup
        .wake_targets()
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.context_id)
        .collect();
    answering.sort();
    assert_eq!(answering, vec![resident, missing], "both actors answer");
}

/// `unrestored_active_contexts` fails with `PersistenceFailed` on a
/// supervisor with no persistence provider.
#[tokio::test]
async fn unrestored_active_contexts_fail_without_persistence() {
    let result = test_supervisor().unrestored_active_contexts().await;
    assert!(
        matches!(result, Err(ContextError::PersistenceFailed(_))),
        "{result:?}"
    );
}

/// `node_identity` is the crypto provider's DID, and `NotInitialized` on
/// a supervisor with no crypto provider wired.
#[tokio::test]
async fn node_identity_reads_the_crypto_provider() {
    let sup = supervisor_with_providers();
    let crypto_did = sup.crypto_ref().unwrap().local_did().to_owned();
    assert_eq!(sup.node_identity().unwrap().0, crypto_did);
    assert!(matches!(
        test_supervisor().node_identity(),
        Err(ContextError::NotInitialized(_))
    ));
}

/// `known_context_ids` lists registered actors and contexts whose actor is
/// down, and leaves out KeyPackage-actor windows and crash windows that do
/// not mark an actor down.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn known_context_ids_list_live_and_down_contexts_only() {
    let sup = supervisor_with_providers();
    let live = hex::encode([0xE0u8; 32]);
    create_push_context(&sup, &live, &["wss://relay.example"]).await;
    let crash = |id: String, crashes: usize| {
        let mut window = sup.crash_windows.entry(id).or_default();
        for _ in 0..crashes {
            window.record(0);
        }
    };
    crash("poisoned-ctx".to_owned(), CRASH_POISON_THRESHOLD);
    crash("crashed-once-ctx".to_owned(), 1);
    crash(
        format!("{KP_CRASH_KEY_PREFIX}did:dht:z6MkKnownIds"),
        CRASH_POISON_THRESHOLD,
    );
    sup.crash_windows
        .entry("respawning-ctx".to_owned())
        .or_default()
        .mark_respawning();
    assert_eq!(
        sup.known_context_ids(),
        vec![live, "poisoned-ctx".to_owned(), "respawning-ctx".to_owned()]
    );
}

/// The `0xFF01` wrapping key a KeyPackage's leaf publishes.
fn key_package_wrapping_key(kp_bytes: &[u8]) -> Option<[u8; 65]> {
    use openmls::prelude::{OpenMlsProvider as _, ProtocolVersion};
    let provider = scp_mls::InMemoryMlsProvider::default();
    let verified = scp_mls::wire::parse_key_package_in(kp_bytes)
        .unwrap()
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap();
    scp_mls::wrapping_extension::extract_wrapping_key(verified.leaf_node().extensions())
        .unwrap()
        .map(|key| *key.as_bytes())
}

/// A fixed `#active` key for the `KeyPackage`-attestation tests, and the
/// shared test resolver over `owner` alone.
fn kp_owner_key_and_resolver(owner: &DID) -> (ed25519_dalek::SigningKey, KeyResolver) {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x3C; 32]);
    let owner = owner.clone();
    let resolver = crate::crypto::mls::test_support::role_resolver(&[(owner, key.clone())]);
    (key, resolver)
}

/// The fixed key behind [`kp_other_signer`].
fn kp_other_signer_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x3D; 32])
}

/// A signer over a fixed key that no test resolver names.
fn kp_other_signer() -> crate::context::actor::CommandSigner {
    crate::context::actor::CommandSigner::local_ed25519(kp_other_signer_key())
}

/// A `KeyPackage` the production store actor mints for a reserve publishes,
/// in `0xFF01`, the wrapping public key of the identity that owns the
/// store, and carries a `0xFF03` attestation that verifies as an Add
/// against the owner's resolved `#active` key.
#[tokio::test]
async fn production_key_package_carries_the_owner_wrapping_key() {
    let did = DID("did:dht:z6MkKpWrapOwner".to_owned());
    let (key, resolver) = kp_owner_key_and_resolver(&did);
    let sup = supervisor_with_resolver(Arc::clone(&resolver));
    let signer = crate::context::actor::CommandSigner::local_ed25519(key);
    let (_reservation, kp_bytes) = sup.reserve_key_package(did.clone(), &signer).await.unwrap();
    let owner = *sup.load_wrapping_key(&did).await.unwrap().public();
    assert_eq!(key_package_wrapping_key(&kp_bytes), Some(owner));
    let validated = sup
        .crypto_ref()
        .unwrap()
        .mls_backend()
        .validate_key_package(&kp_bytes, &scp_clock::SystemClock)
        .await
        .unwrap();
    let attestation = validated
        .leaf
        .attestation
        .as_ref()
        .expect("the KeyPackage carries 0xFF03");
    crate::crypto::mls::attestation_verification::verify_add_attestation(
        resolver,
        &scp_clock::SystemClock,
        &validated.leaf,
        &owner,
        attestation,
    )
    .await
    .expect("the attestation verifies against the owner's #active key");
}

/// N1: with the owner's pool full, a reserve whose signer holds a key
/// other than the owner's resolved `#active` key is refused with
/// `AttestationSignerNotActiveKey`, and the store's pool is unchanged.
#[tokio::test]
async fn reserve_rejects_a_handle_that_is_not_the_identitys_active_key() {
    use crate::context::supervisor::key_package_actor::KeyPackageCommand;
    let did = DID("did:dht:z6MkKpWrongHandleReserve".to_owned());
    let (key, resolver) = kp_owner_key_and_resolver(&did);
    let sup = supervisor_with_resolver(resolver);
    sup.reserve_key_package(
        did.clone(),
        &crate::context::actor::CommandSigner::local_ed25519(key),
    )
    .await
    .expect("the #active signer reserves and fills the pool");
    let store = sup.key_package_store_for_loaded(&did).await.unwrap();
    store
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await
        .expect("the refill ends");
    let full = store
        .send(|reply| KeyPackageCommand::ListPooled { reply })
        .await
        .unwrap();
    assert_eq!(
        full.len(),
        crate::context::supervisor::key_package_actor::MIN_BUFFER - 1,
        "the pool is full"
    );

    let err = sup
        .reserve_key_package(did.clone(), &kp_other_signer())
        .await
        .unwrap_err();
    assert!(
        matches!(err, ContextError::AttestationSignerNotActiveKey),
        "got {err:?}"
    );
    let pooled = store
        .send(|reply| KeyPackageCommand::ListPooled { reply })
        .await
        .unwrap();
    assert_eq!(pooled, full, "the refused signer changed nothing");
}

/// N1: a self-join mint whose signer holds a key other than the owner's
/// resolved `#active` key is refused with `AttestationSignerNotActiveKey`
/// before custody is asked to sign: the key is resolved and compared
/// before the sign, so a wrong handle never triggers a custody sign (a
/// biometric prompt or a hardware sign).
#[tokio::test]
async fn mint_rejects_a_handle_that_is_not_the_identitys_active_key() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    /// The other signer's key, counting every sign it is asked for.
    struct CountingSigner {
        key: scp_crypto::LocalEd25519Signer,
        signs: Arc<AtomicUsize>,
    }
    impl scp_crypto::ScpSigner for CountingSigner {
        fn algorithm(&self) -> scp_crypto::SigAlg {
            scp_crypto::ScpSigner::algorithm(&self.key)
        }
        fn public_key(&self) -> Vec<u8> {
            scp_crypto::ScpSigner::public_key(&self.key)
        }
        async fn sign(&self, digest: &[u8; 32]) -> Result<[u8; 64], scp_crypto::SignError> {
            self.signs.fetch_add(1, Ordering::SeqCst);
            scp_crypto::ScpSigner::sign(&self.key, digest).await
        }
    }
    let did = DID("did:dht:z6MkKpWrongHandleMint".to_owned());
    let (_key, resolver) = kp_owner_key_and_resolver(&did);
    let sup = supervisor_with_resolver(resolver);
    let signs = Arc::new(AtomicUsize::new(0));
    let signer = crate::context::actor::CommandSigner::new(Arc::new(CountingSigner {
        key: scp_crypto::LocalEd25519Signer::new(kp_other_signer_key()),
        signs: Arc::clone(&signs),
    }));
    let err = sup
        .mint_attested_key_package(&did, &signer)
        .await
        .unwrap_err();
    assert!(
        matches!(err, ContextError::AttestationSignerNotActiveKey),
        "got {err:?}"
    );
    assert_eq!(
        signs.load(Ordering::SeqCst),
        0,
        "a handle that is not the resolved #active key is never asked to sign"
    );
}

/// N1: when the owner's `#active` key does not resolve, a reserve and a
/// self-join mint both fail with `AttestationSignerActiveKeyUnresolved`.
#[tokio::test]
async fn reserve_and_mint_fail_closed_when_the_owning_did_does_not_resolve() {
    let did = DID("did:dht:z6MkKpUnresolvedOwner".to_owned());
    let sup = supervisor_with_providers();
    let (key, _resolver) = kp_owner_key_and_resolver(&did);
    let signer = crate::context::actor::CommandSigner::local_ed25519(key);
    let err = sup
        .reserve_key_package(did.clone(), &signer)
        .await
        .unwrap_err();
    assert!(
        matches!(err, ContextError::AttestationSignerActiveKeyUnresolved),
        "got {err:?}"
    );
    let err = sup
        .mint_attested_key_package(&did, &signer)
        .await
        .unwrap_err();
    assert!(
        matches!(err, ContextError::AttestationSignerActiveKeyUnresolved),
        "got {err:?}"
    );
}

/// A record in the format that stored the scalar itself fails closed with
/// `CryptoFailed`: no key is generated over it, the stored bytes stay, and
/// the identity has no loaded key afterwards.
#[tokio::test]
async fn load_wrapping_key_fails_closed_on_an_old_format_record() {
    /// The record shape that held the 32-byte secret scalar.
    #[derive(serde::Serialize)]
    struct OldScalarRecord {
        key: Vec<u8>,
    }
    let storage = Arc::new(InMemoryStorage::new());
    let custody = Arc::new(crate::crypto::dh_counting_custody::DhCountingCustody::new());
    let sup = supervisor_over_storage(Arc::clone(&storage), &custody);
    let did = DID("did:example:wrap-corrupt".to_owned());
    let bytes =
        scp_platform::store_value::to_stored_value_bytes(&OldScalarRecord { key: vec![7u8; 32] })
            .unwrap();
    let adapter = sup.mls_storage_ref().unwrap();
    adapter
        .store("wrapping_key/did:example:wrap-corrupt", &bytes)
        .await
        .unwrap();

    let err = sup.load_wrapping_key(&did).await.unwrap_err();
    assert!(matches!(err, ContextError::CryptoFailed(_)), "{err:?}");
    assert_eq!(custody.generate_calls(), 0, "no key is generated over it");
    assert!(sup.wrapping_keys.get(&did).is_none());
    assert_eq!(
        stored_wrapping_record(&sup, &did.0).await.as_deref(),
        Some(bytes.as_slice()),
        "the stored value is not overwritten"
    );
}

/// A load whose caller is dropped while custody generates still stores
/// the generated key's record, because generate and store run in their
/// own task: the next load waits for that task, returns the stored key,
/// and generates nothing.
#[tokio::test]
async fn load_wrapping_key_stores_the_generated_key_when_its_caller_is_dropped() {
    let storage = Arc::new(InMemoryStorage::new());
    let (custody, gate) =
        crate::crypto::dh_counting_custody::DhCountingCustody::with_generate_gate();
    let custody = Arc::new(custody);
    let sup = supervisor_over_storage(Arc::clone(&storage), &custody);
    let did = DID("did:example:wrap-dropped".to_owned());
    let loading = tokio::spawn({
        let sup = Arc::clone(&sup);
        let did = did.clone();
        async move { sup.load_wrapping_key(&did).await.map(|_| ()) }
    });
    gate.entered.notified().await;
    loading.abort();
    assert!(loading.await.unwrap_err().is_cancelled());
    gate.release.notify_one();

    let key = sup.load_wrapping_key(&did).await.unwrap();
    assert_eq!(
        custody.generate_calls(),
        1,
        "the dropped load's key is the one loaded"
    );
    let record = crate::store::wrapping_key::load_wrapping_key_handle(
        sup.mls_storage_ref().unwrap().as_ref(),
        &did,
    )
    .await
    .unwrap()
    .expect("the dropped load stored its record");
    assert_eq!(record.handle, *key.handle());
    assert_eq!(record.public, *key.public());
}

/// A custody that never answers `generate` fails the load with
/// `SCP-CRYPTO-4062` once the custody budget runs out, and no record is
/// stored for the identity.
#[tokio::test(start_paused = true)]
async fn load_wrapping_key_times_out_when_custody_never_answers_generate() {
    let storage = Arc::new(InMemoryStorage::new());
    let (custody, _gate) =
        crate::crypto::dh_counting_custody::DhCountingCustody::with_generate_gate();
    let custody = Arc::new(custody);
    let sup = supervisor_over_storage(Arc::clone(&storage), &custody);
    let did = DID("did:example:wrap-generate-timeout".to_owned());

    let err = sup.load_wrapping_key(&did).await.unwrap_err();
    assert!(
        matches!(
            &err,
            ContextError::Custody(f)
                if f.kind == scp_crypto::CustodyFailureKind::TimedOut
                    && f.detail == "custody did not answer generate within 30s"
        ),
        "{err:?}"
    );
    assert_eq!(custody.generate_calls(), 1);
    assert!(stored_wrapping_record(&sup, &did.0).await.is_none());
    assert!(sup.wrapping_keys.get(&did).is_none());
}

/// A generated key whose record write is refused is destroyed in custody
/// once the record is removed, no record remains, and the load fails with
/// `PersistenceFailed`.
#[tokio::test]
async fn load_wrapping_key_destroys_the_generated_key_when_its_record_cannot_be_stored() {
    let storage = Arc::new(
        crate::context::supervisor::faulty_storage::FaultyStorage::new(Arc::new(
            InMemoryStorage::new(),
        )),
    );
    storage.fail_store_prefix("wrapping_key/");
    let custody = Arc::new(crate::crypto::dh_counting_custody::DhCountingCustody::new());
    let sup = supervisor_over_storage(Arc::clone(&storage), &custody);
    let did = DID("did:example:wrap-store-fails".to_owned());

    let err = sup.load_wrapping_key(&did).await.unwrap_err();
    assert!(matches!(err, ContextError::PersistenceFailed(_)), "{err:?}");
    let generated = custody.generated_handles();
    assert_eq!(generated.len(), 1, "one key was generated");
    let gone = {
        use scp_platform::traits::KeyCustody as _;
        custody.inner.public_key(&generated[0]).await
    };
    assert!(
        matches!(gone, Err(scp_platform::PlatformError::KeyNotFound)),
        "the unrecorded key is destroyed: {gone:?}"
    );
    assert!(stored_wrapping_record(&sup, &did.0).await.is_none());
    assert!(sup.wrapping_keys.get(&did).is_none());
}

/// Whether custody still holds `handle`.
async fn custody_holds(
    custody: &crate::crypto::dh_counting_custody::DhCountingCustody,
    handle: &scp_platform::KeyHandle,
) -> bool {
    use scp_platform::traits::KeyCustody as _;
    match custody.inner.public_key(handle).await {
        Ok(_) => true,
        Err(scp_platform::PlatformError::KeyNotFound) => false,
        Err(e) => panic!("custody public_key: {e:?}"),
    }
}

/// A record write that commits and then reports an error leaves no record
/// naming the destroyed key: the load removes the record, then destroys
/// the key, and fails with `PersistenceFailed`. The next load generates
/// and stores a key instead of refusing a record whose handle is gone.
#[tokio::test]
async fn a_record_write_that_commits_and_errors_is_removed_before_its_key_is_destroyed() {
    let storage = Arc::new(
        crate::context::supervisor::faulty_storage::FaultyStorage::new(Arc::new(
            InMemoryStorage::new(),
        )),
    );
    storage.fail_after_commit_prefix("wrapping_key/");
    let custody = Arc::new(crate::crypto::dh_counting_custody::DhCountingCustody::new());
    let sup = supervisor_over_storage(Arc::clone(&storage), &custody);
    let did = DID("did:example:wrap-store-commits-then-fails".to_owned());

    let err = sup.load_wrapping_key(&did).await.unwrap_err();
    assert!(matches!(err, ContextError::PersistenceFailed(_)), "{err:?}");
    let generated = custody.generated_handles();
    assert_eq!(generated.len(), 1, "one key was generated");
    assert!(
        stored_wrapping_record(&sup, &did.0).await.is_none(),
        "the committed record is removed"
    );
    assert!(
        !custody_holds(&custody, &generated[0]).await,
        "the unrecorded key is destroyed"
    );

    storage.clear_fail();
    let key = sup.load_wrapping_key(&did).await.unwrap();
    assert_eq!(custody.generate_calls(), 2, "the next load creates a key");
    let record = crate::store::wrapping_key::load_wrapping_key_handle(
        sup.mls_storage_ref().unwrap().as_ref(),
        &did,
    )
    .await
    .unwrap()
    .expect("the next load stores its record");
    assert_eq!(record.handle, *key.handle());
    assert!(custody_holds(&custody, key.handle()).await);
}

/// When a record write commits and errors and the record cannot be
/// removed either, the key is kept: the committed record names a live
/// key, and the next load returns that key without generating one.
#[tokio::test]
async fn a_committed_record_that_cannot_be_removed_keeps_its_key() {
    let storage = Arc::new(
        crate::context::supervisor::faulty_storage::FaultyStorage::new(Arc::new(
            InMemoryStorage::new(),
        )),
    );
    storage.fail_after_commit_prefix("wrapping_key/");
    storage.fail_delete_prefix("wrapping_key/");
    let custody = Arc::new(crate::crypto::dh_counting_custody::DhCountingCustody::new());
    let sup = supervisor_over_storage(Arc::clone(&storage), &custody);
    let did = DID("did:example:wrap-store-commits-delete-fails".to_owned());

    let err = sup.load_wrapping_key(&did).await.unwrap_err();
    assert!(matches!(err, ContextError::PersistenceFailed(_)), "{err:?}");
    let generated = custody.generated_handles();
    assert_eq!(generated.len(), 1, "one key was generated");
    assert!(
        custody_holds(&custody, &generated[0]).await,
        "the key a committed record may name is kept"
    );

    storage.clear_fail();
    let key = sup.load_wrapping_key(&did).await.unwrap();
    assert_eq!(*key.handle(), generated[0], "the recorded key loads");
    assert_eq!(custody.generate_calls(), 1, "nothing is regenerated");
}

/// A custody refusal that is not key-not-found, met while checking a
/// stored record, passes through as `Custody`: it says nothing about the
/// handle, so it is not reported as `WrappingKeyHandleInvalid`.
#[tokio::test]
async fn load_wrapping_key_passes_a_custody_refusal_through_on_a_stored_record() {
    let storage = Arc::new(InMemoryStorage::new());
    let custody = Arc::new(crate::crypto::dh_counting_custody::DhCountingCustody::new());
    let did = DID("did:example:wrap-refused-record".to_owned());
    let first = supervisor_over_storage(Arc::clone(&storage), &custody);
    first.load_wrapping_key(&did).await.unwrap();
    first.shutdown_all_contexts().await;
    drop(first);

    custody.set_public_key_fault(Some(
        crate::crypto::dh_counting_custody::PublicKeyFault::Refuse(
            "the device is locked".to_owned(),
        ),
    ));
    let restarted = supervisor_over_storage(Arc::clone(&storage), &custody);
    let err = restarted.load_wrapping_key(&did).await.unwrap_err();
    assert!(
        matches!(&err, ContextError::Custody(f) if !f.is_key_not_found()),
        "{err:?}"
    );
    assert!(
        stored_wrapping_record(&restarted, &did.0).await.is_some(),
        "the record is kept"
    );
}

/// A custody that reports a public key that is not a 65-byte uncompressed
/// P-256 point fails a fresh load with `CryptoFailed` and the generated key
/// is destroyed; for a stored record the same answer is
/// `WrappingKeyHandleInvalid`.
#[tokio::test]
async fn load_wrapping_key_refuses_a_custody_public_key_that_is_not_a_p256_point() {
    let storage = Arc::new(InMemoryStorage::new());
    let custody = Arc::new(crate::crypto::dh_counting_custody::DhCountingCustody::new());
    let fresh = DID("did:example:wrap-bad-point-fresh".to_owned());
    let stored = DID("did:example:wrap-bad-point-stored".to_owned());
    let first = supervisor_over_storage(Arc::clone(&storage), &custody);
    first.load_wrapping_key(&stored).await.unwrap();
    first.shutdown_all_contexts().await;
    drop(first);

    custody.set_public_key_fault(Some(
        crate::crypto::dh_counting_custody::PublicKeyFault::Bytes(vec![4; 64]),
    ));
    let sup = supervisor_over_storage(Arc::clone(&storage), &custody);
    let err = sup.load_wrapping_key(&fresh).await.unwrap_err();
    assert!(matches!(err, ContextError::CryptoFailed(_)), "{err:?}");
    let generated = custody.generated_handles();
    assert_eq!(generated.len(), 2, "the stored key and the fresh one");
    custody.set_public_key_fault(None);
    let gone = {
        use scp_platform::traits::KeyCustody as _;
        custody.inner.public_key(&generated[1]).await
    };
    assert!(
        matches!(gone, Err(scp_platform::PlatformError::KeyNotFound)),
        "the fresh key is destroyed: {gone:?}"
    );
    assert!(stored_wrapping_record(&sup, &fresh.0).await.is_none());

    custody.set_public_key_fault(Some(
        crate::crypto::dh_counting_custody::PublicKeyFault::Bytes(vec![4; 64]),
    ));
    let err = sup.load_wrapping_key(&stored).await.unwrap_err();
    assert!(
        matches!(err, ContextError::WrappingKeyHandleInvalid),
        "{err:?}"
    );
}

/// Two concurrent first loads of one identity generate one key: the second
/// waits on the identity's load lock and returns the key the first stored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_first_loads_of_one_identity_generate_one_key() {
    let storage = Arc::new(InMemoryStorage::new());
    let (custody, gate) =
        crate::crypto::dh_counting_custody::DhCountingCustody::with_generate_gate();
    let custody = Arc::new(custody);
    let sup = supervisor_over_storage(Arc::clone(&storage), &custody);
    let did = DID("did:example:wrap-concurrent".to_owned());
    let load = |sup: Arc<Supervisor>, did: DID| {
        tokio::spawn(async move { sup.load_wrapping_key(&did).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let first = load(Arc::clone(&sup), did.clone());
        gate.entered.notified().await;
        let second = load(Arc::clone(&sup), did.clone());
        // The second load holds a clone of the identity's load lock (the
        // map, the first load's guard, and the second load's wait make
        // three) once it waits on that lock.
        while sup
            .wrapping_key_loads
            .get(&did)
            .is_none_or(|lock| Arc::strong_count(lock.value()) < 3)
        {
            tokio::task::yield_now().await;
        }
        assert_eq!(custody.generate_calls(), 1, "the second load waits");
        gate.release.notify_one();
        let first = first.await.unwrap().unwrap();
        let second = second.await.unwrap().unwrap();
        assert!(Arc::ptr_eq(&first, &second), "both loads return one key");
    })
    .await
    .expect("both loads finish");
    assert_eq!(custody.generate_calls(), 1);
}

/// `wrapping_key` reads the map before the shutdown gate: a loaded key is
/// returned even once the gate is closed, so a shutdown that clears the
/// map between a gate check and the read cannot turn a miss into
/// `InvalidState`. A miss is `InvalidState` while the gate is open and
/// `SupervisorShutDown` once it is closed.
#[tokio::test]
async fn wrapping_key_reads_the_map_before_the_shutdown_gate() {
    let sup = supervisor_with_providers();
    let loaded = DID("did:example:wrap-gate-loaded".to_owned());
    let missing = DID("did:example:wrap-gate-missing".to_owned());
    let key = sup.load_wrapping_key(&loaded).await.unwrap();
    let err = sup.wrapping_key(&missing).unwrap_err();
    assert!(matches!(err, ContextError::InvalidState(_)), "{err:?}");

    sup.close_spawn_gate();
    assert!(Arc::ptr_eq(&sup.wrapping_key(&loaded).unwrap(), &key));
    let err = sup.wrapping_key(&missing).unwrap_err();
    assert!(
        matches!(err, ContextError::SupervisorShutDown(_)),
        "{err:?}"
    );
}

/// After shutdown, `wrapping_public_key` refuses with `SupervisorShutDown`
/// and loads no secret back into the map, though the identity's pair is
/// still in storage.
#[tokio::test]
async fn wrapping_public_key_refuses_after_shutdown_and_loads_no_secret() {
    let sup = supervisor_with_providers();
    let did = DID("did:example:wrap-after-shutdown".to_owned());
    sup.wrapping_public_key(&did).await.unwrap();
    sup.shutdown_all_contexts().await;
    assert!(sup.wrapping_keys.is_empty(), "shutdown clears the map");

    let err = sup.wrapping_public_key(&did).await.unwrap_err();
    assert!(
        matches!(err, ContextError::SupervisorShutDown(_)),
        "{err:?}"
    );
    assert!(
        sup.wrapping_keys.is_empty(),
        "no wrapping secret is resident after shutdown"
    );
}

/// After shutdown, resolving an identity's KeyPackage store refuses with
/// `SupervisorShutDown` and leaves no wrapping secret in the map.
#[tokio::test]
async fn key_package_store_refuses_after_shutdown_and_loads_no_secret() {
    let sup = supervisor_with_providers();
    let did = DID("did:example:kp-after-shutdown".to_owned());
    sup.shutdown_all_contexts().await;

    let res = sup.key_package_store_for_loaded(&did).await.map(|_| ());
    assert!(
        matches!(res, Err(ContextError::SupervisorShutDown(_))),
        "{res:?}"
    );
    assert!(
        sup.wrapping_keys.is_empty(),
        "no wrapping secret is resident after shutdown"
    );
}

/// A load that passed the entry check before shutdown and reaches
/// `write_lock` while shutdown holds it, closes the gate and clears the
/// map is refused at its insert: it inserts no key after the clear.
#[tokio::test]
async fn load_racing_shutdown_inserts_nothing() {
    let sup = supervisor_with_providers();
    let did = DID("did:example:wrap-in-flight".to_owned());
    let guard = sup.write_lock.lock().await;
    let load = tokio::spawn({
        let sup = Arc::clone(&sup);
        let did = did.clone();
        async move { sup.load_wrapping_key(&did).await.map(|_| ()) }
    });
    // The current-thread runtime runs the load past its entry gate check;
    // it cannot finish while shutdown holds `write_lock`.
    tokio::task::yield_now().await;
    assert!(!load.is_finished(), "the load waits on write_lock");
    sup.close_spawn_gate();
    sup.clear_wrapping_keys(&guard);
    drop(guard);

    let err = load.await.unwrap().unwrap_err();
    assert!(
        matches!(err, ContextError::SupervisorShutDown(_)),
        "{err:?}"
    );
    assert!(
        sup.wrapping_keys.is_empty(),
        "the in-flight load inserts no key after the clear"
    );
}

#[tokio::test]
async fn start_saga_returns_invalid_state_for_executorless_input() {
    // Driving a `CrossContextOutletInvocation` through the generic
    // `start_saga` (no supervisor-side executor / signing key) is a
    // misuse — the FSM journals Initiated + PreparingA then fails the
    // Prepare-A dispatch with InvalidState (SCP-SAGA-13051), rolls back
    // via abort_saga, and returns the typed error. This exercises the
    // coordinator through the PreparingA → Aborting → Aborted arm of the
    // FSM without needing a co-resident executor context.
    let s = test_supervisor();
    let err = s
        .start_saga(SagaInput::test_cross_context_for_gating(
            [1u8; 32], [2u8; 32],
        ))
        .await
        .unwrap_err();
    assert!(matches!(err, ContextError::InvalidState(_)));

    // The participant-context-set reservation must be RELEASED after a
    // saga terminates (even on an InvalidState abort) so a subsequent
    // saga over the SAME set can reserve and start. This is the
    // same-set sequential re-arm property: the RAII `SagaSetReservation`
    // drop frees the slots on every terminal.
    let err2 = s
        .start_saga(SagaInput::test_cross_context_for_gating(
            [1u8; 32], [2u8; 32],
        ))
        .await
        .unwrap_err();
    assert!(matches!(err2, ContextError::InvalidState(_)));
}

// -----------------------------------------------------------------
// ADR-049 §15 — `spawn_actor_with_state` tests
// -----------------------------------------------------------------

/// Construct a minimal [`crate::context::actor::deps::ActorDeps`] for
/// the `spawn_actor_with_state` tests. Builds through the
/// supervisor's `build_actor_deps` path so we exercise real
/// construction rather than invent synthetic mocks.
async fn test_actor_deps(supervisor: &Arc<Supervisor>) -> crate::context::actor::deps::ActorDeps {
    supervisor
        .build_actor_deps_loaded(&DID("did:example:spawn-state-test".to_owned()))
        .await
        .expect("build_actor_deps requires providers populated")
}

/// A tiny `ContextEventLogProvider` that accepts every call and
/// returns empty data for every read. Exists only so
/// [`supervisor_with_providers`] can construct a supervisor with
/// minimal providers without dragging in the full mock stack from
/// the `tests/actor_*_shim.rs` integration harnesses.
struct TestEventLog;
#[async_trait::async_trait]
impl crate::context::builder::ContextEventLogProvider for TestEventLog {
    fn event_log_entries(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<Option<Vec<scp_event_log::Event>>, scp_protocol::context::ContextError> {
        Ok(None)
    }

    async fn init_event_log(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    async fn append_event(
        &self,
        _context_id: &[u8; 32],
        _event: scp_event_log::EventType,
        _actor_did: &str,
        _payload: scp_event_log::EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    async fn destroy_event_log(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
}

/// An event-log double PRE-SEEDED with a fixed entry history, returned
/// verbatim by `event_log_entries`. Its `restore_event_log` is the trait
/// default (a no-op `init_event_log`), so the seeded entries SURVIVE the
/// restore path — letting restore re-arm tests exercise the single-source
/// `convergent_ttl_deadline` against a real leaf history (a `ContextPromoted`
/// disarm, a `TtlExtended` raise) without standing up a full Merkle provider.
#[derive(Clone)]
struct SeededEventLog {
    #[allow(clippy::disallowed_types)]
    entries: Arc<std::sync::Mutex<Vec<scp_event_log::Event>>>,
}
impl SeededEventLog {
    fn new(entries: Vec<scp_event_log::Event>) -> Self {
        Self {
            entries: Arc::new(std::sync::Mutex::new(entries)),
        }
    }
}
#[async_trait::async_trait]
impl crate::context::builder::ContextEventLogProvider for SeededEventLog {
    async fn init_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    async fn append_event(
        &self,
        _id: &[u8; 32],
        event_type: scp_event_log::EventType,
        actor: &str,
        payload: scp_event_log::EventPayload,
        timestamp_secs: u64,
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        {
            let mut entries = self
                .entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let sequence = entries.len() as u64;
            entries.push(scp_event_log::Event {
                event_type,
                actor_did: DID(actor.to_owned()),
                timestamp: timestamp_secs,
                sequence,
                payload,
                prev_hash: [0u8; 32],
                signature: Vec::new(),
            });
        }
        Ok(())
    }
    async fn destroy_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    fn event_log_entries(
        &self,
        _id: &[u8; 32],
    ) -> Result<Option<Vec<scp_event_log::Event>>, ContextError> {
        Ok(Some(
            self.entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        ))
    }
}

/// The convergent creation instant every TTL restore/re-arm test uses as
/// `T0`. Post pass-4e the create base is the PRUNE-IMMUNE snapshot
/// `creation_timestamp_secs + params.ttl` (E1), which these tests set to `T0`
/// via `new_for_test_encrypted(_, T0, _)`; the genesis leaf's own `timestamp`
/// is NO LONGER read for the base. This constant is kept aligned with `T0` so
/// seeded leaves remain realistic, though the derivation ignores it.
const SEEDED_CREATION_TS: u64 = 1_700_000_000;

/// A genesis `ContextCreated` leaf for [`SeededEventLog`] histories. Post
/// pass-4e the deadline derivation does NOT read this leaf (base + promotion
/// come from the prune-immune snapshot; the log is read only for `TtlExtended`
/// leaves) — it is retained so restore/expiry histories stay realistic and to
/// prove the base is unaffected by its presence/absence.
fn seeded_context_created(sequence: u64) -> scp_event_log::Event {
    scp_event_log::Event {
        event_type: scp_event_log::EventType::ContextCreated,
        actor_did: DID("did:example:seeded-creator".to_owned()),
        timestamp: SEEDED_CREATION_TS,
        sequence,
        payload: scp_event_log::EventPayload::default(),
        prev_hash: [0u8; 32],
        signature: Vec::new(),
    }
}

/// Bare `ContextPromoted` leaf for [`SeededEventLog`] histories. Post pass-4e
/// this leaf is the event-log RECORD of promotion but is NOT read for the arm
/// decision (promotion is `params.ttl == None`, the prune-immune authority);
/// tests seed it to prove a stray promotion leaf does not move the deadline.
fn seeded_context_promoted(sequence: u64) -> scp_event_log::Event {
    scp_event_log::Event {
        event_type: scp_event_log::EventType::ContextPromoted,
        actor_did: DID("did:example:seeded-creator".to_owned()),
        timestamp: 0,
        sequence,
        payload: scp_event_log::EventPayload::default(),
        prev_hash: [0u8; 32],
        signature: Vec::new(),
    }
}

/// `TtlExtended` leaf carrying `new_deadline_unix` for [`SeededEventLog`]
/// histories.
fn seeded_ttl_extended(sequence: u64, old_dl: u64, new_dl: u64) -> scp_event_log::Event {
    let payload =
        scp_event_log::payload::encode_payload(&scp_event_log::payload::TtlExtendedPayload {
            old_deadline_unix: old_dl,
            new_deadline_unix: new_dl,
            proposal_id: [0u8; 32],
            consenting_members: vec!["did:example:seeded-member".to_owned()],
        })
        .expect("encode TtlExtendedPayload");
    scp_event_log::Event {
        event_type: scp_event_log::EventType::TtlExtended,
        actor_did: DID("did:example:seeded-creator".to_owned()),
        timestamp: 0,
        sequence,
        payload,
        prev_hash: [0u8; 32],
        signature: Vec::new(),
    }
}

/// Build a supervisor with minimal providers so
/// [`test_actor_deps`] can construct `ActorDeps` via the real
/// `build_actor_deps` path. The plain `test_supervisor` helper
/// above does NOT populate providers because its saga / lookup
/// tests do not need them.
fn supervisor_with_providers() -> Arc<Supervisor> {
    supervisor_with_providers_and_event_log(Box::new(TestEventLog))
}

/// [`supervisor_with_providers`] with a caller-supplied event-log provider,
/// for tests that assert what did (or did NOT) reach the durable event log
/// (e.g. via a [`RecordingEventLog`]).
fn supervisor_with_providers_and_event_log(
    event_log: Box<dyn crate::context::builder::ContextEventLogProvider>,
) -> Arc<Supervisor> {
    supervisor_with_event_log_and_resolver(
        event_log,
        Arc::new(|_: &DID, _: scp_did::SigningKeyId| None),
    )
}

/// [`supervisor_with_providers`] with a caller-supplied [`KeyResolver`].
fn supervisor_with_resolver(key_resolver: KeyResolver) -> Arc<Supervisor> {
    supervisor_with_event_log_and_resolver(Box::new(TestEventLog), key_resolver)
}

fn supervisor_with_event_log_and_resolver(
    event_log: Box<dyn crate::context::builder::ContextEventLogProvider>,
    key_resolver: KeyResolver,
) -> Arc<Supervisor> {
    // Minimal providers — the spawn-registry tests only care about
    // the supervisor's actor map, not the providers' behaviour.
    // `NodeMlsFactory::new` takes a String DID; the stub DID is
    // never used by the spawn tests because no
    // `create_context` call runs.
    let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
        "did:dht:z6MktestDoNotRely".to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
        Box::new(crate::context::builder::NotConfiguredTransportProvider);
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            InMemoryStorage::new(),
        )),
    );
    Supervisor::with_providers(
        crypto,
        transport,
        event_log,
        key_resolver,
        None,
        None,
        None,
        None,
        mls_storage,
        crate::domain_handlers(),
    )
}

/// A minimal valid `0xFF02` extension bound to `ctx` for test births. The
/// export/restore tests below only exercise the crypto MATERIAL + floors, not
/// the §5.13.3 binding, so any well-formed extension suffices.
fn test_ctx_ext(ctx: &[u8; 32]) -> scp_protocol::context::ScpContextExtension {
    let params = scp_protocol::context::ContextParams::default();
    scp_protocol::context::ScpContextExtension::for_root(scp_protocol::context::ScpContextGenesis {
        context_id: hex::encode(ctx),
        creator_did: DID(String::new()),
        creation_timestamp_secs: 1_700_000_000,
        mode: params.mode,
        governance: &params.governance,
        ceiling_policy: params.ceiling_policy,
        ceiling: &scp_protocol::context::roles::CapabilityCeiling::new(params.ceiling.clone()),
    })
    .expect("build test 0xFF02 extension")
}

/// The floors of `blob` (an [`actor_export`] of a [`test_ctx_ext`] group, or
/// empty for a keyless snapshot) after the real `0xFF02` binding check, the
/// only source of a `VerifiedFloors`.
fn verified_test_floors(
    ctx: &[u8; 32],
    blob: &[u8],
) -> crate::context::restored_crypto::VerifiedFloors {
    let restored = crate::context::restored_crypto::build_restored_crypto(ctx, blob, "test")
        .expect("the blob rebuilds");
    crate::context::restored_crypto::VerifiedRestoredCrypto::verify_scp_context_binding(
        restored,
        &hex::encode(ctx),
        "",
        &scp_protocol::context::ContextParams::default(),
        1_700_000_000,
        1_700_000_000,
        "test",
    )
    .expect("the test_ctx_ext binding verifies")
    .replace_floors()
}

/// #2148 (ADR-049 birth-into-actor): BIRTH an owned context group on `crypto`
/// via the owned-return `create_mls_group_with_context` and seed it onto a
/// throwaway actor `PerContextState` — the actor-native replacement for the
/// deleted `create_mls_group[_with_context]` + `generate_sender_key` +
/// `take_crypto_state` triad. The provider holds no per-context state.
fn take_into_actor(
    crypto: &Arc<crate::crypto::mls::provider::NodeMlsFactory>,
    ctx: &[u8; 32],
    ext: &scp_protocol::context::ScpContextExtension,
) -> crate::context::actor::state::PerContextState {
    let owned = crypto
        .create_mls_group_with_context(
            ext,
            scp_protocol::crypto::sender_keys::generate_wrapping_keypair()
                .0
                .as_bytes(),
        )
        .expect("birth owned crypto material");
    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        *ctx,
        0,
        DID::from(crypto.local_did().to_owned()),
    );
    state.seed_encrypted_crypto_from_owned(owned);
    state
}

/// Births a context on a throwaway actor and exports it through
/// [`PerContextState::export_crypto_state`](crate::context::actor::state::PerContextState::export_crypto_state).
fn actor_export(
    crypto: &Arc<crate::crypto::mls::provider::NodeMlsFactory>,
    ctx: &[u8; 32],
    ext: &scp_protocol::context::ScpContextExtension,
    sender_key_epochs: Vec<(String, u64)>,
    recv_sequence_floors: Vec<(String, scp_protocol::context::builder::ReceiveFloor)>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, ContextError> {
    let state = take_into_actor(crypto, ctx, ext);
    state.export_crypto_state(sender_key_epochs, recv_sequence_floors)
}

/// Build a `Supervisor` around an EXISTING crypto provider `Arc` — used by the
/// two-party seam-level e2e tests to wrap Bob's post-join `bob_crypto` (which
/// holds the joined group) in a fresh supervisor so `build_actor_deps` yields
/// an `ActorDeps` whose `crypto` opens Alice's real ciphertext and whose
/// `supervisor` floor registry starts empty. A no-op resolver suffices —
/// `decrypt_and_dispatch` defers signature verification to `ContextManager`.
fn supervisor_with_crypto(
    crypto: Arc<crate::crypto::mls::provider::NodeMlsFactory>,
) -> Arc<Supervisor> {
    supervisor_with_crypto_and_resolver(crypto, Arc::new(|_: &DID, _: scp_did::SigningKeyId| None))
}

/// Like [`supervisor_with_crypto`] but with a caller-supplied `key_resolver`
/// — used by the §9.16.2 sender-key receive-path test, whose
/// `decrypt_and_dispatch` must resolve the requester's verification key to
/// check the request signature.
#[cfg(feature = "testing")]
fn supervisor_with_crypto_and_resolver(
    crypto: Arc<crate::crypto::mls::provider::NodeMlsFactory>,
    key_resolver: KeyResolver,
) -> Arc<Supervisor> {
    let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
        Box::new(crate::context::builder::NotConfiguredTransportProvider);
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            InMemoryStorage::new(),
        )),
    );
    Supervisor::with_providers(
        crypto,
        transport,
        Box::new(TestEventLog),
        key_resolver,
        None,
        None,
        None,
        None,
        mls_storage,
        crate::domain_handlers(),
    )
}

/// Block until the KP-actor watchdog has FULLY processed one more crash than
/// `baseline` — the [`Supervisor::kp_watchdog_processed_tx`] counter value
/// captured *before* the panic was induced.
///
/// The watchdog bumps the counter exactly once per crash, AFTER it has
/// recorded the crash in `crash_windows` and settled the respawn-or-poison
/// decision (see [`Supervisor::kp_actor_watchdog`]). So when this returns,
/// the crash is durably reflected in supervisor state — the test can assert
/// on `is_context_poisoned` / `crash_count` with no polling.
///
/// This is the deterministic fix for the load-induced flake: it waits on the *event*
/// (`watch::Receiver::changed`), never a wall-clock budget, so it CANNOT
/// false-timeout when the watchdog task is scheduled late under CPU load —
/// the exact tail that made the previous bounded `poll_until` wait flaky. A
/// genuinely stuck watchdog surfaces as a harness-level hang (a real bug),
/// not a probabilistic assertion failure. `watch` version-tracking makes the
/// wait immune to lost wakeups even if the bump lands between the borrow and
/// the `changed()` await.
#[cfg(feature = "testing")]
async fn await_kp_crash_processed(rx: &mut tokio::sync::watch::Receiver<u64>, baseline: u64) {
    while *rx.borrow_and_update() <= baseline {
        rx.changed()
            .await
            .expect("supervisor kp-watchdog completion channel stays open");
    }
}

/// Structural: a supervisor built through the production
/// `Supervisor::with_providers` factory ALWAYS attaches the consumed-init-key
/// store to the shared MLS backend. Proven behaviorally: a join through the
/// supervisor's own backend must NOT fail closed (it would
/// `MlsError::StorageError` if the store were unattached). A future
/// `with_providers` that forgets the `set_consumed_init_key_store` wiring
/// would make this join fail closed and the test would fail.
#[tokio::test]
async fn with_providers_attaches_consumed_init_key_store() {
    use crate::crypto::mls::test_support::MintAttestedForTest as _;
    use scp_mls::credential::ScpCredential;

    let supervisor = supervisor_with_providers();
    let crypto = supervisor
        .crypto_ref()
        .expect("with_providers populates crypto");
    let backend = crypto.mls_backend();

    let joiner = ScpCredential::new(
        "did:dht:z6MkWithProvidersStoreCheck".to_owned(),
        None,
        scp_did::SigningKeyId::Active,
    )
    .expect("valid credential");
    let generated = backend
        .mint_attested_for_test(
            &joiner,
            &scp_crypto::p256::testing::uncompressed_point_for(&joiner.did),
        )
        .await
        .expect("generate kp");

    // Build a real Welcome for the generated KP.
    let inviter = ScpCredential::new(
        "did:dht:z6MkWithProvidersInviter".to_owned(),
        None,
        scp_did::SigningKeyId::Active,
    )
    .expect("valid inviter credential");
    let mut group = backend
        .create_group(
            &inviter,
            &scp_crypto::p256::testing::uncompressed_point_for(&inviter.did),
        )
        .await
        .expect("create group");
    let added = backend
        .add_member_raw(&mut group, &generated.key_package_bytes)
        .await
        .expect("add member");

    // The join must succeed — i.e. NOT fail closed with StorageError, which
    // is the symptom of a missing consumed-init-key store. (ScpMlsGroup is
    // not Debug, so assert on the error shape, not the Ok value.)
    let result = backend
        .join_from_welcome(
            &added.welcome,
            generated.signer_state,
            &generated.key_package_bytes,
        )
        .await;
    assert!(
        !matches!(result, Err(scp_mls::error::MlsError::StorageError(_))),
        "with_providers must attach the consumed-init-key store \
             (a store-less backend fails the join closed with StorageError)"
    );
    assert!(
        result.is_ok(),
        "the join through the supervisor backend must succeed once the store is attached"
    );
}

#[tokio::test]
async fn spawn_actor_with_state_registers_handle_and_accepts_commands() {
    let supervisor_arc = supervisor_with_providers();
    let deps = test_actor_deps(&supervisor_arc).await;

    // Construct a fresh encrypted-mode PerContextState. The
    // context_id is arbitrary for this test — the registry key
    // is derived from it via `hex::encode`.
    let ctx_id_bytes = [0xABu8; 32];
    let expected_ctx_key = hex::encode(ctx_id_bytes);
    let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        DID("did:example:admin".to_owned()),
    );

    let handle = supervisor_arc
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn_actor_with_state: fresh context id registers");
    // Handle is registered under the hex-encoded context id key.
    assert!(
        supervisor_arc.lookup(&expected_ctx_key).is_some(),
        "actor must be registered under hex-encoded context id"
    );

    // Handle is alive — send a read-only member-count query and
    // observe the actor answer it. This exercises both the mpsc
    // plumbing and the `ContextActor::new` + `run()` happy path.
    let count = handle
        .send(|reply| {
            ContextCommand::Queries(QueriesCommand::MemberCount {
                context_id: expected_ctx_key.clone(),
                reply,
            })
        })
        .await
        .expect("member-count query round-trips through the live actor");
    // The test fixture (`new_for_test_encrypted`) seeds the admin DID into
    // `governance`, not into `membership`, so the roster is empty and
    // `MemberCount` (which reads `state.membership.count()`) answers the
    // exact count 0 — not merely "some" count.
    assert_eq!(
        count,
        Some(0),
        "the owning actor answers MemberCount with the exact roster count \
             (empty test fixture ⇒ 0)"
    );

    // Cleanly shut down.
    handle.send_shutdown().await.unwrap();
}

/// End-to-end (ADR-049 Decision-1 / finding A3): the ACTOR-OWNED TTL
/// arm fires from owned state — NO supervisor `task_set` spawn and NO
/// `FireTimer` mailbox hop. The actor's `run()` loop reconciles a
/// one-shot `sleep` against `state.ttl.timer.deadline_unix_secs`
/// (`reconcile_timers`), fires `on_ttl_tick` → the expiry pipeline on
/// owned state (`Active → Expired`), and breaks the loop on the
/// terminal state so the actor task exits (its mailbox closes).
///
/// Paused tokio time: the deadline is armed `TTL_SECS` ahead of the
/// actor's clock and the fire is driven by `advance`, not wall-clock
/// sleeping.
#[tokio::test(start_paused = true)]
#[allow(clippy::too_many_lines)] // inline recording provider + 4-part post-expiry contract
async fn actor_owned_ttl_arm_fires_and_despawns_self() {
    use async_trait::async_trait;

    use crate::context::persistence::ContextPersistence;
    use crate::context::state::ContextSnapshot;

    type PersistErr = Box<dyn std::error::Error + Send + Sync>;

    /// Captures the last persisted snapshot's state so the test can prove
    /// the terminal `Expired` state is DURABLE even though the actor
    /// despawned (its live mailbox is gone, so `read_context_state`
    /// returns `None` — the Expired signal lives in the snapshot).
    struct RecordingPersistence {
        // Test-only capture; the guard is never held across `.await`.
        #[allow(clippy::disallowed_types)]
        last_state: Arc<std::sync::Mutex<Option<scp_protocol::context::ContextState>>>,
    }
    #[async_trait]
    impl ContextPersistence for RecordingPersistence {
        async fn persist_context(
            &self,
            _context_id: &str,
            snapshot: &ContextSnapshot,
        ) -> Result<(), PersistErr> {
            *self.last_state.lock().unwrap() = Some(snapshot.state.clone());
            Ok(())
        }
        async fn load_context(
            &self,
            _context_id: &str,
        ) -> Result<Option<ContextSnapshot>, PersistErr> {
            Ok(None)
        }
        async fn delete_context(&self, _context_id: &str) -> Result<(), PersistErr> {
            Ok(())
        }
        async fn list_persisted_contexts(&self) -> Result<Vec<String>, PersistErr> {
            Ok(Vec::new())
        }
    }

    const TTL_SECS: u64 = 30;

    let supervisor_arc = supervisor_with_providers();
    let mut deps = test_actor_deps(&supervisor_arc).await;
    #[allow(clippy::disallowed_types)]
    let last_state: Arc<std::sync::Mutex<Option<scp_protocol::context::ContextState>>> =
        Arc::new(std::sync::Mutex::new(None));
    deps.persistence = Arc::new(RecordingPersistence {
        last_state: Arc::clone(&last_state),
    });
    // The expiry pipeline derives its `ContextExpired` leaf timestamp from the
    // partitioned single-source deadline; a finite params.ttl (below) yields
    // the prune-immune snapshot base `creation_timestamp_secs + ttl`, so the
    // derivation is `Some` and the expiry proceeds (a `params.ttl == None`
    // would make `handle_ttl_expiry` ABORT, A3). The seeded genesis leaf is
    // realistic history but is no longer read for the base.
    deps.event_log = Arc::new(SeededEventLog::new(vec![seeded_context_created(0)]));

    let ctx_id_bytes = [0x7Au8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        DID("did:example:admin".to_owned()),
    );
    // Finite params.ttl so the single-source deadline derives (prune-immune
    // snapshot base `creation_timestamp_secs + ttl`); the scalar below
    // independently drives the one-shot sleep timing.
    state.handle = crate::context::ContextHandle::new(
        ctx_key.clone(),
        scp_protocol::context::params::ContextParams {
            ttl: Some(std::time::Duration::from_secs(TTL_SECS)),
            ..Default::default()
        },
    );
    // Arm a convergent TTL deadline `TTL_SECS` ahead of the actor's own
    // clock. `reconcile_timers` derives the one-shot sleep from this.
    state.ttl.timer.deadline_unix_secs = Some(deps.clock.now_secs() + TTL_SECS);

    // Clone the shared handle BEFORE moving state into the actor so we
    // can observe the FSM transition. Must be `Active` for the expiry
    // pipeline (it rejects non-Active contexts).
    let observed_handle = state.handle.clone();
    observed_handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();

    let actor_handle = supervisor_arc
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn_actor_with_state: fresh context id registers");
    assert!(supervisor_arc.lookup(&ctx_key).is_some());
    assert_eq!(
        actor_handle.exited_deliberately(),
        None,
        "a running actor has recorded no exit"
    );

    // Let the actor reach its `select!` and arm the sleep, then confirm
    // it has NOT fired before the deadline.
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        observed_handle.state(),
        crate::context::ContextState::Active,
        "context must remain Active before its TTL deadline"
    );

    // Advance past the deadline (but before the 60s governance interval)
    // and drive the actor until the TTL arm fires the expiry pipeline.
    tokio::time::advance(std::time::Duration::from_secs(TTL_SECS + 1)).await;
    let mut expired = false;
    for _ in 0..64 {
        if observed_handle.state() == crate::context::ContextState::Expired {
            expired = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        expired,
        "the actor-owned TTL arm must fire on_ttl_tick and expire the context"
    );

    // Despawn-on-terminal: the actor despawns its OWN registry handle and
    // exits. Poll until the registry entry is gone.
    let mut despawned = false;
    for _ in 0..64 {
        if supervisor_arc.lookup(&ctx_key).is_none() {
            despawned = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        despawned,
        "on terminal TTL expiry the actor must despawn its own registry handle \
             (no dead-but-registered zombie)"
    );
    // The actor records the expiry as a deliberate exit once its run loop
    // breaks, so a flush sweep holding this handle skips it instead of
    // reporting a lost context.
    let mut recorded = None;
    for _ in 0..64 {
        recorded = actor_handle.exited_deliberately();
        if recorded.is_some() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        recorded,
        Some(crate::context::actor::handle::DeliberateExit::Expired),
        "a TTL expiry must record DeliberateExit::Expired"
    );

    // Post-expiry contract (ADR-049 finding A3): the actor is fully gone,
    // so `read_context_state` returns `None` (NOT a hung/closed mailbox
    // read, and NOT a stale live `Expired`). The old design left the actor
    // alive to answer `Expired`, but that leaked the actor forever AND
    // blocked re-creation (duplicate rejection); despawn trades the live
    // read for a durable snapshot + re-creatability.
    assert_eq!(
        supervisor_arc.read_context_state(&ctx_key).await,
        None,
        "a despawned expired context reads as None (unknown), not a zombie"
    );

    // The terminal `Expired` state is DURABLE — it was captured in the
    // persisted snapshot before the actor exited (so the signal is not
    // lost; anti-resurrection will not respawn an `Expired` snapshot).
    assert_eq!(
        *last_state.lock().unwrap(),
        Some(crate::context::ContextState::Expired),
        "the durable snapshot must record the terminal Expired state"
    );

    // Re-creatable: with the zombie gone, a fresh actor can register under
    // the same context id (the duplicate-rejection no longer trips).
    let deps2 = test_actor_deps(&supervisor_arc).await;
    let fresh = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        DID("did:example:admin".to_owned()),
    );
    supervisor_arc
        .spawn_actor_with_state(fresh, deps2, None)
        .await
        .expect("after despawn, the expired context id must be re-creatable");
}

/// The ACTOR-OWNED governance-timeout interval fires the sweep from the
/// actor's own `run()` loop (ADR-049 Decision-1 / finding A3) — no
/// supervisor `task_set` spawn, no `EvaluateTimeouts` mailbox hop. The
/// sweep marks the actor dirty, which the coalesced-persist arm flushes;
/// a recording persistence provider observes that a persist lands after
/// the 60s tick. Transitioning the context out of `Active` then stops
/// the interval: no further governance-driven persist accrues.
#[tokio::test(start_paused = true)]
async fn actor_owned_governance_interval_fires_and_stops_when_not_active() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;

    use crate::context::persistence::ContextPersistence;
    use crate::context::state::ContextSnapshot;

    type PersistErr = Box<dyn std::error::Error + Send + Sync>;

    /// Counts `persist_context` calls so the test can observe the
    /// governance sweep marking the actor dirty (→ coalesced persist).
    struct CountingPersistence {
        persists: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl ContextPersistence for CountingPersistence {
        async fn persist_context(
            &self,
            _context_id: &str,
            _snapshot: &ContextSnapshot,
        ) -> Result<(), PersistErr> {
            self.persists.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn load_context(
            &self,
            _context_id: &str,
        ) -> Result<Option<ContextSnapshot>, PersistErr> {
            Ok(None)
        }
        async fn delete_context(&self, _context_id: &str) -> Result<(), PersistErr> {
            Ok(())
        }
        async fn list_persisted_contexts(&self) -> Result<Vec<String>, PersistErr> {
            Ok(Vec::new())
        }
    }

    let supervisor_arc = supervisor_with_providers();
    let mut deps = test_actor_deps(&supervisor_arc).await;
    let persists = Arc::new(AtomicUsize::new(0));
    deps.persistence = Arc::new(CountingPersistence {
        persists: Arc::clone(&persists),
    });

    let ctx_id_bytes = [0x6Bu8; 32];
    let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        DID("did:example:admin".to_owned()),
    );
    // No TTL deadline: only the governance interval is armed.
    let observed_handle = state.handle.clone();
    observed_handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();

    let _actor_handle = supervisor_arc
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn_actor_with_state: fresh context id registers");

    // Let the actor arm the 60s governance interval.
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    let before = persists.load(Ordering::SeqCst);

    // Advance past one governance interval (+ the 50ms coalesce window)
    // and drive the actor until the sweep-driven persist lands.
    tokio::time::advance(std::time::Duration::from_secs(61)).await;
    let mut fired = false;
    for _ in 0..64 {
        if persists.load(Ordering::SeqCst) > before {
            fired = true;
            break;
        }
        tokio::time::advance(std::time::Duration::from_millis(60)).await;
        tokio::task::yield_now().await;
    }
    assert!(
        fired,
        "the actor-owned governance interval must fire the sweep (marking dirty → persist)"
    );

    // Move the context out of `Active`: the next sweep signals stop and
    // the actor nulls its interval, so no further governance-driven
    // persist accrues over the subsequent intervals.
    observed_handle
        .transition_to(&crate::context::ContextState::Closing)
        .unwrap();
    // Let the actor reconcile (the Closing state clears the interval) and
    // drain the one already-pending tick.
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(std::time::Duration::from_secs(61)).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    let after_close = persists.load(Ordering::SeqCst);
    tokio::time::advance(std::time::Duration::from_mins(3)).await;
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        persists.load(Ordering::SeqCst),
        after_close,
        "no governance-driven persist may accrue once the context is not Active \
             (the interval was nulled)"
    );
}

/// D1 (create-window stuck-open): restoring an `Active` snapshot that
/// carries a persisted convergent `ttl_deadline_secs` re-arms the
/// actor-owned TTL arm to that ABSOLUTE deadline. The real
/// `restore_context` respawn path resolves the deadline, mailboxes
/// `StartTtlTimer`, and `reconcile_timers` arms the one-shot sleep; once
/// paused time is advanced past the deadline the context transitions
/// `Active → Expired`.
#[tokio::test(start_paused = true)]
async fn restore_rearms_ttl_from_convergent_deadline() {
    const T0: u64 = 1_700_000_000;
    const TTL_SECS: u64 = 30;

    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(T0));
    let persistence = MapPersistence::default();
    // E1: restore re-arms from the partitioned single-source deadline. The
    // create base is the PRUNE-IMMUNE snapshot `creation_timestamp_secs (= T0)
    // + params.ttl`, so the base is `T0 + TTL_SECS` regardless of the log. The
    // seeded genesis leaf is realistic history but no longer sources the base.
    let event_log = SeededEventLog::new(vec![seeded_context_created(0)]);
    let sup = supervisor_with_clock_persistence_and_event_log(
        clock_dyn,
        Box::new(persistence.clone()),
        Box::new(event_log),
    );

    let ctx_id_bytes = [0x51u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:restore-ttl-admin".to_owned());

    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        T0,
        admin.clone(),
    );
    // Give the context a finite params TTL and install the convergent
    // absolute deadline (`creation + ttl`) the live context held.
    state.handle = crate::context::ContextHandle::new(
        ctx_key.clone(),
        scp_protocol::context::params::ContextParams {
            ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
            ttl: Some(std::time::Duration::from_secs(TTL_SECS)),
            ..Default::default()
        },
    );
    state.ttl.timer.deadline_unix_secs = Some(T0 + TTL_SECS);
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();

    // Persist the Active snapshot (captures `ttl_deadline_secs`), then drive
    // the REAL restore path.
    let snap = crate::context::manager_methods::snapshot_context(&state);
    assert_eq!(
        snap.ttl_deadline_secs,
        Some(T0 + TTL_SECS),
        "snapshot must carry the absolute convergent deadline"
    );
    persistence.persist_context(&ctx_key, &snap).await.unwrap();

    sup.load_wrapping_key(&admin)
        .await
        .expect("an entry point loads the owner's wrapping key");
    sup.respawn_from_snapshot(&ctx_key, &admin)
        .await
        .expect("respawn must restore the Active snapshot");
    assert!(
        sup.lookup(&ctx_key).is_some(),
        "restored actor must be resident"
    );

    // Let the actor reach its `select!` and arm the sleep; it must NOT have
    // fired before the deadline.
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        sup.read_context_state(&ctx_key).await,
        Some(crate::context::ContextState::Active),
        "restored context must remain Active before its re-armed deadline"
    );

    // Advance past the re-armed deadline (before the 60s governance
    // interval) and drive the actor until the TTL arm fires + despawns.
    tokio::time::advance(std::time::Duration::from_secs(TTL_SECS + 1)).await;
    let mut despawned = false;
    for _ in 0..64 {
        if sup.lookup(&ctx_key).is_none() {
            despawned = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        despawned,
        "the re-armed TTL arm must fire and despawn the restored context"
    );
    let persisted = persistence
        .load_context(&ctx_key)
        .await
        .unwrap()
        .expect("expiry must persist a durable snapshot");
    assert_eq!(
        persisted.state,
        crate::context::ContextState::Expired,
        "the re-armed TTL arm must drive the restored context to Expired"
    );
}

/// D1 (create-window stuck-open, REGRESSION GATE): restoring an `Active`
/// snapshot that carries NO persisted `ttl_deadline_secs` (`None`) but a
/// finite `params.ttl` must still re-arm — from the convergent
/// `creation + ttl` fallback — and expire.
///
/// Pre-fix this FAILED: the restore path gated the re-arm on
/// `if let Some(remaining) = snapshot.ttl_remaining_secs`, so a `None`
/// remaining (an Active snapshot persisted before the timer was recorded)
/// skipped arming entirely and the context stayed open forever. The fix
/// gates on `params.ttl.is_some()` and falls back to `creation + ttl`, so
/// the context still expires.
#[tokio::test(start_paused = true)]
async fn restore_active_with_no_ttl_remaining() {
    const T0: u64 = 1_700_000_000;
    const TTL_SECS: u64 = 30;

    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(T0));
    let persistence = MapPersistence::default();
    // E1: the create base is the PRUNE-IMMUNE snapshot `creation_timestamp_secs
    // (= T0) + params.ttl` — NOT a log leaf. So `convergent_ttl_deadline`
    // derives `T0 + TTL_SECS` and re-arms (D1) even though the persisted
    // `ttl_deadline_secs` scalar is None. The seeded genesis leaf is realistic
    // history; an empty log would derive the SAME base from the snapshot.
    let event_log = SeededEventLog::new(vec![seeded_context_created(0)]);
    let sup = supervisor_with_clock_persistence_and_event_log(
        clock_dyn,
        Box::new(persistence.clone()),
        Box::new(event_log),
    );

    let ctx_id_bytes = [0x52u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:restore-noremaining-admin".to_owned());

    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        T0,
        admin.clone(),
    );
    state.handle = crate::context::ContextHandle::new(
        ctx_key.clone(),
        scp_protocol::context::params::ContextParams {
            ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
            ttl: Some(std::time::Duration::from_secs(TTL_SECS)),
            // Ephemeral scope with a live TTL (`params.ttl == Some`) ⇒
            // `convergent_ttl_deadline` derives the `creation + ttl` base and
            // re-arms (D1). The promotion-disarm case (`params.ttl == None`)
            // is covered by `restore_promoted_context_does_not_re_expire`.
            memory_scope: scp_protocol::context::params::MemoryScope::Ephemeral,
            ..Default::default()
        },
    );
    // No recorded deadline: model an Active snapshot persisted before the
    // TTL arm was recorded.
    state.ttl.timer.deadline_unix_secs = None;
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();

    let snap = crate::context::manager_methods::snapshot_context(&state);
    assert_eq!(
        snap.ttl_deadline_secs, None,
        "snapshot carries no absolute deadline (the create-window case)"
    );
    persistence.persist_context(&ctx_key, &snap).await.unwrap();

    sup.load_wrapping_key(&admin)
        .await
        .expect("an entry point loads the owner's wrapping key");
    sup.respawn_from_snapshot(&ctx_key, &admin)
        .await
        .expect("respawn must restore the Active snapshot");

    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        sup.read_context_state(&ctx_key).await,
        Some(crate::context::ContextState::Active),
        "restored context must be Active before the fallback deadline"
    );

    // Advance past the `creation + ttl` fallback deadline; it must fire.
    tokio::time::advance(std::time::Duration::from_secs(TTL_SECS + 1)).await;
    let mut despawned = false;
    for _ in 0..64 {
        if sup.lookup(&ctx_key).is_none() {
            despawned = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        despawned,
        "a None-remaining Active snapshot must re-arm via creation+ttl and expire (D1)"
    );
    let persisted = persistence
        .load_context(&ctx_key)
        .await
        .unwrap()
        .expect("expiry must persist a durable snapshot");
    assert_eq!(persisted.state, crate::context::ContextState::Expired);
}

/// H1/E2 (promote→re-expiry, REGRESSION GATE — prune-safe rewrite): restoring
/// a PROMOTED context (`params.ttl == None`, the prune-immune promotion
/// authority set by `execute_promote_context` per §5.10) must NOT re-arm a TTL
/// timer — a promoted context is permanent. Crucially this must hold even with
/// an EMPTY event log: the promotion signal lives in the snapshot params, not
/// a prunable `ContextPromoted` leaf, so pruning the log cannot resurrect the
/// TTL. A stray `ContextPromoted` leaf is ALSO seeded to prove it is not read.
///
/// Pre-redesign the restore re-arm read `params.ttl` + a `memory_scope`
/// heuristic (pass-4d read the prunable `ContextPromoted` leaf). Pass-4e reads
/// the prune-immune `params.ttl == None`, so the timer stays disarmed past the
/// stale `creation + ttl` instant with no `memory_scope` gate — and survives a
/// pruned log.
#[tokio::test(start_paused = true)]
async fn restore_promoted_context_does_not_re_expire() {
    const T0: u64 = 1_700_000_000;
    const STALE_TTL: u64 = 30;

    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(T0));
    let persistence = MapPersistence::default();
    // A leaf history that carries a stray `ContextPromoted` leaf (the RECORD)
    // AND no `ContextCreated` base — i.e. a partially-pruned log. Neither is
    // read for the arm: promotion is `params.ttl == None` in the snapshot.
    let event_log = SeededEventLog::new(vec![seeded_context_promoted(1)]);
    let sup = supervisor_with_clock_persistence_and_event_log(
        clock_dyn,
        Box::new(persistence.clone()),
        Box::new(event_log),
    );

    let ctx_id_bytes = [0x5Au8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:restore-promoted-admin".to_owned());

    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        T0,
        admin.clone(),
    );
    // Model a PROMOTED context exactly as `execute_promote_context` leaves it:
    // `params.ttl == None` (TTL removed, §5.10) and scope `Full`. Deliberately
    // leave a STALE non-`None` recorded deadline scalar (`T0 + STALE_TTL`) —
    // the STRONGER case: even with a live-looking cached deadline, restore must
    // derive `None` from the prune-immune `params.ttl == None` and NOT re-arm.
    state.handle = crate::context::ContextHandle::new(
        ctx_key.clone(),
        scp_protocol::context::params::ContextParams {
            ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
            ttl: None,
            memory_scope: scp_protocol::context::params::MemoryScope::Full,
            ..Default::default()
        },
    );
    state.ttl.timer.deadline_unix_secs = Some(T0 + STALE_TTL);
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();

    let snap = crate::context::manager_methods::snapshot_context(&state);
    persistence.persist_context(&ctx_key, &snap).await.unwrap();

    sup.load_wrapping_key(&admin)
        .await
        .expect("an entry point loads the owner's wrapping key");
    sup.respawn_from_snapshot(&ctx_key, &admin)
        .await
        .expect("respawn must restore the promoted Active snapshot");

    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        sup.read_context_state(&ctx_key).await,
        Some(crate::context::ContextState::Active),
        "the restored promoted context must be Active"
    );

    // Advance WELL past the stale `creation + ttl` (T0 + 30) instant — a
    // re-armed timer would have fired and destroyed the context here. The
    // promoted context must remain resident and Active.
    tokio::time::advance(std::time::Duration::from_secs(STALE_TTL + 5)).await;
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert!(
        sup.lookup(&ctx_key).is_some(),
        "a promoted context (params.ttl == None) must NOT be re-armed and \
             destroyed on restore, even with a pruned log (H1/E2)"
    );
    assert_eq!(
        sup.read_context_state(&ctx_key).await,
        Some(crate::context::ContextState::Active),
        "a promoted context stays Active past the stale creation+ttl instant (H1/E2)"
    );
}

/// H1 companion (created `Full`+ttl broadcast re-arms, REGRESSION GATE): a
/// context CREATED with `memory_scope == Full` AND a finite `params.ttl`
/// (e.g. a broadcast context — `Full` is its only supported scope) and NO
/// `ContextPromoted` leaf MUST re-arm and expire. The retired
/// `memory_scope != Full` gate WRONGLY skipped this context (mistaking a
/// created-`Full` context for a promoted one), leaving it stuck open. The
/// single-source derivation distinguishes them: no `ContextPromoted` leaf ⇒
/// `creation + ttl` base ⇒ re-arm.
#[tokio::test(start_paused = true)]
async fn restore_created_full_scope_with_ttl_re_arms() {
    const T0: u64 = 1_700_000_000;
    const TTL_SECS: u64 = 30;

    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(T0));
    let persistence = MapPersistence::default();
    // Created `Full`+ttl: the log has `ContextCreated` but NO
    // `ContextPromoted` — so the TTL is live.
    let event_log = SeededEventLog::new(vec![seeded_context_created(0)]);
    let sup = supervisor_with_clock_persistence_and_event_log(
        clock_dyn,
        Box::new(persistence.clone()),
        Box::new(event_log),
    );

    let ctx_id_bytes = [0x5Fu8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:restore-full-ttl-admin".to_owned());

    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        T0,
        admin.clone(),
    );
    state.handle = crate::context::ContextHandle::new(
        ctx_key.clone(),
        scp_protocol::context::params::ContextParams {
            ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
            ttl: Some(std::time::Duration::from_secs(TTL_SECS)),
            // Created `Full` scope (NOT promoted) — the case the old gate
            // mis-classified.
            memory_scope: scp_protocol::context::params::MemoryScope::Full,
            ..Default::default()
        },
    );
    state.ttl.timer.deadline_unix_secs = Some(T0 + TTL_SECS);
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();

    let snap = crate::context::manager_methods::snapshot_context(&state);
    persistence.persist_context(&ctx_key, &snap).await.unwrap();

    sup.load_wrapping_key(&admin)
        .await
        .expect("an entry point loads the owner's wrapping key");
    sup.respawn_from_snapshot(&ctx_key, &admin)
        .await
        .expect("respawn must restore the Active snapshot");

    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        sup.read_context_state(&ctx_key).await,
        Some(crate::context::ContextState::Active),
        "a created Full+ttl context must be Active before its deadline"
    );

    // Advance past the re-armed `creation + ttl`; it MUST fire (the old
    // memory_scope gate would have left it stuck open).
    tokio::time::advance(std::time::Duration::from_secs(TTL_SECS + 1)).await;
    let mut despawned = false;
    for _ in 0..64 {
        if sup.lookup(&ctx_key).is_none() {
            despawned = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        despawned,
        "a created Full-scope context WITH a ttl (no ContextPromoted leaf) must \
             re-arm and expire — the retired memory_scope gate wrongly skipped it (H1)"
    );
    let persisted = persistence
        .load_context(&ctx_key)
        .await
        .unwrap()
        .expect("expiry must persist a durable snapshot");
    assert_eq!(persisted.state, crate::context::ContextState::Expired);
}

/// D2 (extension-preserved-on-restore, REGRESSION GATE — single-source
/// rewrite): restoring an `Active` context whose event log records a
/// `TtlExtended` leaf pushing the deadline beyond `creation + ttl` must
/// re-arm to the EXTENDED absolute deadline — derived from the log, never
/// recomputed back to `creation + ttl`.
///
/// The redesign reads the extension from the single authoritative source
/// (the `TtlExtended` leaf's `new_deadline_unix`), not the persisted scalar.
/// The still-Active assertion past `creation + ttl` but before the extended
/// deadline catches a regression that dropped the extension.
#[tokio::test(start_paused = true)]
async fn restore_preserves_extended_ttl_deadline() {
    const T0: u64 = 1_700_000_000;
    const TTL_SECS: u64 = 20;
    // Extended 30s beyond the original `creation + ttl` (= T0 + 20).
    const EXTENDED_DEADLINE: u64 = T0 + 50;

    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(T0));
    let persistence = MapPersistence::default();
    // The event log records the prior unanimous extension: `ContextCreated`
    // then `TtlExtended` to `EXTENDED_DEADLINE`. `convergent_ttl_deadline`
    // derives `max(creation+ttl, extended)` = `EXTENDED_DEADLINE`.
    let event_log = SeededEventLog::new(vec![
        seeded_context_created(0),
        seeded_ttl_extended(1, T0 + TTL_SECS, EXTENDED_DEADLINE),
    ]);
    let sup = supervisor_with_clock_persistence_and_event_log(
        clock_dyn,
        Box::new(persistence.clone()),
        Box::new(event_log),
    );

    let ctx_id_bytes = [0x53u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:restore-extended-admin".to_owned());

    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        T0,
        admin.clone(),
    );
    state.handle = crate::context::ContextHandle::new(
        ctx_key.clone(),
        scp_protocol::context::params::ContextParams {
            ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
            ttl: Some(std::time::Duration::from_secs(TTL_SECS)),
            ..Default::default()
        },
    );
    // A prior unanimous extension pushed the deadline out past creation+ttl.
    state.ttl.timer.deadline_unix_secs = Some(EXTENDED_DEADLINE);
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();

    let snap = crate::context::manager_methods::snapshot_context(&state);
    assert_eq!(snap.ttl_deadline_secs, Some(EXTENDED_DEADLINE));
    persistence.persist_context(&ctx_key, &snap).await.unwrap();

    sup.load_wrapping_key(&admin)
        .await
        .expect("an entry point loads the owner's wrapping key");
    sup.respawn_from_snapshot(&ctx_key, &admin)
        .await
        .expect("respawn must restore the Active snapshot");

    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    // Advance PAST the original creation+ttl (T0+20) but BEFORE the extended
    // deadline (T0+50): a context restored to creation+ttl would already
    // have expired here; the fixed context is still Active.
    tokio::time::advance(std::time::Duration::from_secs(TTL_SECS + 5)).await; // → T0+25
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        sup.read_context_state(&ctx_key).await,
        Some(crate::context::ContextState::Active),
        "restore must preserve the EXTENDED deadline, not recompute creation+ttl (D2)"
    );

    // Advance past the extended deadline: now it must fire.
    tokio::time::advance(std::time::Duration::from_secs(30)).await; // → T0+55
    let mut despawned = false;
    for _ in 0..64 {
        if sup.lookup(&ctx_key).is_none() {
            despawned = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        despawned,
        "the extended TTL arm must fire once paused time passes the extended deadline"
    );
    let persisted = persistence
        .load_context(&ctx_key)
        .await
        .unwrap()
        .expect("expiry must persist a durable snapshot");
    assert_eq!(persisted.state, crate::context::ContextState::Expired);
}

/// BUG-1 (stale TTL arm on Closed/Tombstoned, REGRESSION GATE): once a
/// context leaves `Active`, a stale recorded deadline must NOT arm and fire
/// — firing on a terminal context would despawn it, re-opening the close
/// window and defeating tombstone finality. Also asserts the close path
/// clears `deadline_unix_secs` durably in the fail-closed snapshot.
///
/// Pre-fix this FAILED two ways: (1) `reconcile_timers` armed the TTL
/// one-shot regardless of state, so a stale deadline fired `on_ttl_tick` on
/// a Closed/Tombstoned context → terminal → despawn; (2) the close/tombstone
/// closures never cleared `deadline_unix_secs`, so a later restore re-armed
/// the stale deadline. The `is_active` gate + the in-closure clear fix both.
#[tokio::test(start_paused = true)]
#[allow(clippy::too_many_lines)]
async fn stale_ttl_arm_does_not_fire_on_closed_or_tombstoned() {
    use scp_protocol::context::roles::Capability;

    const T0: u64 = 1_700_000_000;
    const STALE_TTL: u64 = 30;

    // --- Part (a): reconcile disarms a stale deadline on a terminal actor.
    // Drive both Closed and Tombstoned; neither may despawn on the stale arm.
    for (tag, terminal_edges) in [
        (
            0xC1u8,
            &[
                crate::context::ContextState::Closing,
                crate::context::ContextState::Closed,
            ][..],
        ),
        (
            0xC2u8,
            &[
                crate::context::ContextState::MigratingOut,
                crate::context::ContextState::Tombstoned,
            ][..],
        ),
    ] {
        let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(T0));
        // Inject a counting event log: if the stale arm fired against the
        // terminal context, `handle_ttl_expiry`'s Phase-2 append would record
        // a `ContextExpired` leaf. Asserting ZERO such appends isolates the
        // reconcile `is_active` gate — the actor-resident assertion alone is
        // independently guaranteed by the SEC-1 keep-alive path and would
        // pass even if the gate regressed (N3).
        let expiry_counter = ContextExpiredAppendCounter::default();
        let sup = supervisor_with_clock_persistence_and_event_log(
            clock_dyn,
            Box::new(MapPersistence::default()),
            Box::new(expiry_counter.clone()),
        );

        let ctx_id_bytes = [tag; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let admin = DID("did:example:stale-arm-admin".to_owned());

        let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            T0,
            admin.clone(),
        );
        // A stale absolute deadline lingering from when the context was Active.
        state.ttl.timer.deadline_unix_secs = Some(T0 + STALE_TTL);
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .unwrap();
        for edge in terminal_edges {
            state.handle.transition_to(edge).unwrap();
        }

        let deps = test_actor_deps(&sup).await;
        sup.spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn a terminal-state actor for the reconcile-gate check");
        assert!(sup.lookup(&ctx_key).is_some());

        // Advance well past the stale deadline. The `is_active` gate must keep
        // the arm disarmed, so the actor never fires + never despawns.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(std::time::Duration::from_secs(STALE_TTL + 5)).await;
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        assert!(
            sup.lookup(&ctx_key).is_some(),
            "a stale TTL deadline must NOT fire against a terminal context and despawn it (BUG-1)"
        );
        // The distinguishing signal (N3): the expiry pipeline never ran, so
        // no `ContextExpired` leaf was appended against the terminal context.
        // A regressed `is_active` reconcile gate would fire `on_ttl_tick` →
        // `handle_ttl_expiry` → `finish_ttl_expiry_io` and record one here.
        assert_eq!(
            expiry_counter
                .context_expired_appends
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the stale TTL arm must NOT drive a ContextExpired append against a \
                 terminal context — a non-zero count means the is_active reconcile \
                 gate regressed (N3)"
        );
    }

    // --- Part (b): the close path clears the recorded deadline durably.
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(T0));
    let persistence = MapPersistence::default();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

    let ctx_id_bytes = [0xC3u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:stale-arm-close-admin".to_owned());

    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        T0,
        admin.clone(),
    );
    // SingleAdmin close gate: the initiator must hold ContextClose.
    state
        .role_state
        .member_capabilities
        .entry(admin.0.clone())
        .or_default()
        .insert(Capability::ContextClose);
    state.ttl.timer.deadline_unix_secs = Some(T0 + STALE_TTL);
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();

    let deps = test_actor_deps(&sup).await;
    let handle_clone = state.handle.clone();
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);
    crate::context::lifecycle_helpers::close_context(&mut cell, &deps, &handle_clone, &admin)
        .await
        .expect("close_context must succeed for a SingleAdmin context");
    assert_eq!(
        cell.ttl.timer.deadline_unix_secs, None,
        "the close closure must clear the recorded TTL deadline in memory (BUG-1)"
    );
    // The clear is DURABLE: the fail-closed close persist wrote a snapshot
    // whose ttl_deadline_secs is None, so a later restore cannot re-arm a
    // stale deadline against the closed context.
    let persisted = persistence
        .load_context(&ctx_key)
        .await
        .unwrap()
        .expect("close must fail-closed persist a snapshot");
    assert_eq!(
        persisted.ttl_deadline_secs, None,
        "the durable close snapshot must carry no TTL deadline (BUG-1)"
    );
}

/// B7 (bilateral reset uses convergent deadline, REGRESSION GATE): a
/// unanimous TTL extension re-records `old_deadline + additional` — the
/// convergent absolute instant every member computes — NOT the local
/// arm-time `now + additional`.
///
/// Pre-fix this FAILED: `reset_ttl_timer` armed `now + new_duration` off the
/// dispatcher's local clock, which diverges across members under clock skew.
/// Choosing `old_deadline != now` makes the two formulas disagree, so
/// asserting the recorded deadline equals `old_deadline + additional`
/// (and not `now + additional`) catches the local-clock regression.
#[tokio::test]
async fn bilateral_reset_uses_convergent_deadline() {
    const T0: u64 = 1_700_000_000;
    // Finite create TTL whose prune-immune snapshot base (`creation_timestamp_secs
    // (= T0) + this ttl`) is the current convergent deadline the reset extends.
    // The reset derives `old` through `convergent_ttl_deadline` (snapshot base +
    // fail-safe log extensions), not the scalar cache.
    const CREATE_TTL: u64 = 500;
    const OLD_DEADLINE: u64 = T0 + CREATE_TTL;
    const ADDITIONAL: u64 = 100;

    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(T0));
    // Seed the genesis `ContextCreated` leaf so `convergent_ttl_deadline`
    // derives `T0 + CREATE_TTL = OLD_DEADLINE`.
    let event_log = SeededEventLog::new(vec![seeded_context_created(0)]);
    let sup = supervisor_with_clock_persistence_and_event_log(
        clock_dyn,
        Box::new(MapPersistence::default()),
        Box::new(event_log),
    );
    let deps = test_actor_deps(&sup).await;
    assert_eq!(
        deps.clock.now_secs(),
        T0,
        "deps clock is the injected TestClock"
    );

    let ctx_id_bytes = [0x57u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:bilateral-reset-admin".to_owned());

    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        T0,
        admin,
    );
    // Finite params.ttl so the log-derived base is `T0 + CREATE_TTL`; the
    // scalar cache is seeded to the same value (consistent state).
    state.handle = crate::context::ContextHandle::new(
        ctx_key.clone(),
        scp_protocol::context::params::ContextParams {
            ttl: Some(std::time::Duration::from_secs(CREATE_TTL)),
            ..Default::default()
        },
    );
    state.ttl.timer.deadline_unix_secs = Some(OLD_DEADLINE);
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);

    crate::context::ttl_close_helpers::reset_ttl_timer(
        &mut cell,
        &deps,
        &ctx_key,
        std::time::Duration::from_secs(ADDITIONAL),
    )
    .await
    .expect("the reset appends its TtlExtended leaf");

    assert_eq!(
        cell.ttl.timer.deadline_unix_secs,
        Some(OLD_DEADLINE + ADDITIONAL),
        "bilateral reset must record old_deadline + additional (convergent)"
    );
    assert_ne!(
        cell.ttl.timer.deadline_unix_secs,
        Some(T0 + ADDITIONAL),
        "bilateral reset must NOT record now + additional (local-clock, divergent)"
    );
}

/// An event log whose reads succeed and whose appends all fail.
struct AppendFailingEventLog(SeededEventLog);
#[async_trait::async_trait]
impl crate::context::builder::ContextEventLogProvider for AppendFailingEventLog {
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
        Err(
            scp_protocol::context::builder::ContextCreationError::EventLogFailed(
                "append refused".to_owned(),
            ),
        )
    }
    async fn destroy_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    fn event_log_entries(
        &self,
        id: &[u8; 32],
    ) -> Result<Option<Vec<scp_event_log::Event>>, ContextError> {
        self.0.event_log_entries(id)
    }
}

/// A reset whose `TtlExtended` append fails returns the error, keeps the
/// consent tally, and leaves the deadline where it was: the tally clears
/// only after the leaf is in the log (spec section 17.3, "Event log write
/// failures").
#[tokio::test]
async fn a_reset_whose_append_fails_keeps_the_tally_and_the_deadline() {
    const T0: u64 = 1_700_000_000;
    const CREATE_TTL: u64 = 500;
    const OLD_DEADLINE: u64 = T0 + CREATE_TTL;
    const ADDITIONAL: u64 = 100;

    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(T0));
    let event_log = AppendFailingEventLog(SeededEventLog::new(vec![seeded_context_created(0)]));
    let sup = supervisor_with_clock_persistence_and_event_log(
        clock_dyn,
        Box::new(MapPersistence::default()),
        Box::new(event_log),
    );
    let deps = test_actor_deps(&sup).await;

    let ctx_id_bytes = [0x5Au8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        T0,
        DID("did:example:failed-reset-admin".to_owned()),
    );
    state.handle = crate::context::ContextHandle::new(
        ctx_key.clone(),
        scp_protocol::context::params::ContextParams {
            ttl: Some(std::time::Duration::from_secs(CREATE_TTL)),
            ..Default::default()
        },
    );
    state.ttl.timer.deadline_unix_secs = Some(OLD_DEADLINE);
    let mut ext =
        crate::context::ttl::TtlExtension::new(std::time::Duration::from_secs(ADDITIONAL), 2);
    ext.add_consent(DID("did:example:m-alpha".to_owned()));
    ext.add_consent(DID("did:example:m-bravo".to_owned()));
    state.ttl.extension = Some(ext);
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);

    let reset = crate::context::ttl_close_helpers::reset_ttl_timer(
        &mut cell,
        &deps,
        &ctx_key,
        std::time::Duration::from_secs(ADDITIONAL),
    )
    .await;

    assert!(
        matches!(reset, Err(ContextError::EventLogFailed(_))),
        "a failed TtlExtended append fails the reset, got {reset:?}"
    );
    assert!(
        cell.ttl.extension.is_some(),
        "the consent tally survives a reset whose leaf was not logged"
    );
    assert_eq!(cell.ttl.timer.deadline_unix_secs, Some(OLD_DEADLINE));
}

/// H2 (reset on a no-TTL context, REGRESSION GATE): `reset_ttl_timer` on a
/// context with NO recorded deadline (`deadline_unix_secs == None`) must be
/// a no-op — it must NOT arm a deadline.
///
/// Pre-fix this FAILED: `reset_ttl_timer` computed
/// `old_dl = deadline.unwrap_or(0); new_dl = old_dl + duration`, so a
/// no-TTL context (`None` deadline) armed `0 + duration ≈ 1970` — a
/// long-past instant → immediate `sleep(0)` expiry / key destruction,
/// reachable via the FFI `context_reset_ttl_timer` op. The fix only re-arms
/// when a deadline is actually recorded (mirrors `execute_extend_ttl`).
#[tokio::test]
async fn reset_ttl_on_no_ttl_context_does_not_expire() {
    const T0: u64 = 1_700_000_000;
    const ADDITIONAL: u64 = 100;

    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(T0));
    // Recording event log so we can assert NO leaf was appended for a no-op.
    let event_log = SeededEventLog::new(Vec::new());
    let entries_handle = event_log.entries.clone();
    let sup = supervisor_with_clock_persistence_and_event_log(
        clock_dyn,
        Box::new(MapPersistence::default()),
        Box::new(event_log),
    );
    let deps = test_actor_deps(&sup).await;

    let ctx_id_bytes = [0x5Bu8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:reset-no-ttl-admin".to_owned());

    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        T0,
        admin,
    );
    // No recorded deadline: a context with no live TTL arm.
    state.ttl.timer.deadline_unix_secs = None;
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);

    crate::context::ttl_close_helpers::reset_ttl_timer(
        &mut cell,
        &deps,
        &ctx_key,
        std::time::Duration::from_secs(ADDITIONAL),
    )
    .await
    .expect("the reset appends its TtlExtended leaf");

    assert_eq!(
        cell.ttl.timer.deadline_unix_secs, None,
        "reset on a no-TTL context must NOT arm a deadline (H2); pre-fix it \
             armed `0 + additional ≈ 1970`, an immediate-expiry sleep(0)"
    );
    // A no-op reset mutates no deadline, so it emits NO `TtlExtended` leaf.
    let leaf_count = entries_handle
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter(|e| e.event_type == scp_event_log::EventType::TtlExtended)
        .count();
    assert_eq!(
        leaf_count, 0,
        "a no-op reset (no deadline to extend) must NOT append a TtlExtended leaf"
    );
}

/// Single-source invariant (reset emits a leaf): `reset_ttl_timer` on a
/// context WITH a recorded deadline both extends the deadline
/// (`old + additional`) AND appends a `TtlExtended` leaf recording the
/// `(old, new)` transition (§5.10.1 step 5). Without the leaf a
/// reset-extension would live only in the runtime scalar and be LOST on the
/// next restore/import — the deadline-source-of-truth bug this redesign
/// closes. Parity with the governance `execute_extend_ttl` path.
#[tokio::test]
async fn reset_ttl_timer_emits_ttl_extended_leaf() {
    const T0: u64 = 1_700_000_000;
    // Finite create TTL whose prune-immune snapshot base (`creation_timestamp_secs
    // (= T0) + ttl`) is the current convergent deadline the reset extends (the
    // reset derives `old` through `convergent_ttl_deadline`, not the scalar cache).
    const CREATE_TTL: u64 = 500;
    const OLD_DEADLINE: u64 = T0 + CREATE_TTL;
    const ADDITIONAL: u64 = 100;
    const NEW_DEADLINE: u64 = OLD_DEADLINE + ADDITIONAL;

    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(T0));
    let event_log = SeededEventLog::new(vec![seeded_context_created(0)]);
    let entries_handle = event_log.entries.clone();
    let sup = supervisor_with_clock_persistence_and_event_log(
        clock_dyn,
        Box::new(MapPersistence::default()),
        Box::new(event_log),
    );
    let deps = test_actor_deps(&sup).await;

    let ctx_id_bytes = [0x58u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:reset-leaf-admin".to_owned());

    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        T0,
        admin,
    );
    // Finite params.ttl so the log-derived base is `OLD_DEADLINE`; the scalar
    // cache is seeded to the same value (consistent state).
    state.handle = crate::context::ContextHandle::new(
        ctx_key.clone(),
        scp_protocol::context::params::ContextParams {
            ttl: Some(std::time::Duration::from_secs(CREATE_TTL)),
            ..Default::default()
        },
    );
    state.ttl.timer.deadline_unix_secs = Some(OLD_DEADLINE);
    // Record a member's consent so the leaf's `consenting_members` is
    // populated (the propose→reset activation flow).
    state.ttl.extension = Some(crate::context::ttl::TtlExtension::new(
        std::time::Duration::from_secs(ADDITIONAL),
        1,
    ));
    state
        .ttl
        .extension
        .as_mut()
        .unwrap()
        .add_consent(DID("did:example:reset-consenter".to_owned()));
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);

    crate::context::ttl_close_helpers::reset_ttl_timer(
        &mut cell,
        &deps,
        &ctx_key,
        std::time::Duration::from_secs(ADDITIONAL),
    )
    .await
    .expect("the reset appends its TtlExtended leaf");

    assert_eq!(
        cell.ttl.timer.deadline_unix_secs,
        Some(NEW_DEADLINE),
        "reset extends the recorded convergent deadline by the duration"
    );

    let extended: Vec<(u64, u64, Vec<String>)> = entries_handle
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter(|e| e.event_type == scp_event_log::EventType::TtlExtended)
        .filter_map(|e| {
            scp_event_log::payload::decode_payload::<scp_event_log::payload::TtlExtendedPayload>(
                &e.payload,
            )
            .ok()
        })
        .map(|p| {
            (
                p.old_deadline_unix,
                p.new_deadline_unix,
                p.consenting_members,
            )
        })
        .collect();
    assert_eq!(
        extended,
        vec![(
            OLD_DEADLINE,
            NEW_DEADLINE,
            vec!["did:example:reset-consenter".to_owned()]
        )],
        "reset must append exactly one TtlExtended leaf recording (old, new) and \
             the consenting members (§5.10.1 step 5)"
    );
}

/// A2 + `consented_dids` sort gate: two honest members with WILDLY different
/// local clocks but IDENTICAL convergent state (same genesis leaf, same
/// params.ttl, same 2-member consent tally) must append BYTE-IDENTICAL
/// `TtlExtended` leaves on a bilateral reset — required for their Merkle
/// roots to converge. This gates BOTH the A2 fix (the leaf `timestamp` is the
/// convergent PRE-extension deadline `old`, NOT local `now()`) AND the
/// `TtlExtension::consented_dids` sort (the leaf's `consenting_members` is a
/// lexicographically-sorted, per-process-`RandomState`-independent list).
#[tokio::test]
async fn two_members_reset_leaves_are_byte_identical() {
    const T0: u64 = 1_700_000_000;
    const CREATE_TTL: u64 = 500;
    const OLD_DEADLINE: u64 = T0 + CREATE_TTL;
    const ADDITIONAL: u64 = 100;

    // Run one member's reset under local clock `now`, returning the appended
    // `TtlExtended` leaf. The two consenters are inserted in OPPOSITE orders on
    // the two members to exercise the sort (a per-`HashSet` `RandomState` can
    // otherwise iterate them differently).
    async fn member_reset_leaf(now: u64, insert_alpha_first: bool) -> scp_event_log::Event {
        let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(now));
        let event_log = SeededEventLog::new(vec![seeded_context_created(0)]);
        let entries_handle = event_log.entries.clone();
        let sup = supervisor_with_clock_persistence_and_event_log(
            clock_dyn,
            Box::new(MapPersistence::default()),
            Box::new(event_log),
        );
        let deps = test_actor_deps(&sup).await;

        let ctx_id_bytes = [0x60u8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        // Same creator DID on both members ⇒ the leaf `actor_did` converges.
        let admin = DID("did:example:reset-converge-admin".to_owned());
        let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            T0,
            admin,
        );
        state.handle = crate::context::ContextHandle::new(
            ctx_key.clone(),
            scp_protocol::context::params::ContextParams {
                ttl: Some(std::time::Duration::from_secs(CREATE_TTL)),
                ..Default::default()
            },
        );
        state.ttl.timer.deadline_unix_secs = Some(OLD_DEADLINE);
        let mut ext =
            crate::context::ttl::TtlExtension::new(std::time::Duration::from_secs(ADDITIONAL), 2);
        let alpha = DID("did:example:m-alpha".to_owned());
        let bravo = DID("did:example:m-bravo".to_owned());
        if insert_alpha_first {
            ext.add_consent(alpha);
            ext.add_consent(bravo);
        } else {
            ext.add_consent(bravo);
            ext.add_consent(alpha);
        }
        state.ttl.extension = Some(ext);
        let mut cell = crate::context::actor::class_s::ClassSCell::new(state);

        crate::context::ttl_close_helpers::reset_ttl_timer(
            &mut cell,
            &deps,
            &ctx_key,
            std::time::Duration::from_secs(ADDITIONAL),
        )
        .await
        .expect("the reset appends its TtlExtended leaf");

        entries_handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|e| e.event_type == scp_event_log::EventType::TtlExtended)
            .cloned()
            .expect("reset appended a TtlExtended leaf")
    }

    let leaf_a = member_reset_leaf(T0, true).await;
    let leaf_b = member_reset_leaf(T0 + 9_999_999, false).await;

    assert_eq!(
        leaf_a.timestamp, OLD_DEADLINE,
        "the reset leaf timestamp is the convergent PRE-extension deadline (A2), not local now()"
    );
    assert_eq!(
        leaf_a.timestamp, leaf_b.timestamp,
        "clock-skewed members must stamp the SAME leaf timestamp (A2)"
    );
    assert_eq!(
        leaf_a.actor_did, leaf_b.actor_did,
        "same creator ⇒ same actor"
    );
    assert_eq!(leaf_a.sequence, leaf_b.sequence, "same log position");
    assert_eq!(
        leaf_a.payload, leaf_b.payload,
        "identical (old, new, proposal_id, SORTED consenting_members) ⇒ byte-identical payload"
    );
    // Prove the sorted, canonical consent list explicitly (the sort gate).
    let decoded = scp_event_log::payload::decode_payload::<
        scp_event_log::payload::TtlExtendedPayload,
    >(&leaf_a.payload)
    .expect("decode TtlExtendedPayload");
    assert_eq!(
        decoded.consenting_members,
        vec![
            "did:example:m-alpha".to_owned(),
            "did:example:m-bravo".to_owned(),
        ],
        "consenting_members must be lexicographically SORTED (convergent across members)"
    );
}

/// A3/E2 (expiry aborts on `None`): if a TTL timer fires against a context
/// whose partitioned single-source deadline is `None` (here a PROMOTED context
/// — `params.ttl == None` per §5.10 — whose STALE scalar still holds a live
/// deadline), `handle_ttl_expiry` must ABORT: NO terminal transition, NO key
/// destruction, NO `ContextExpired` leaf, and the stale cached deadline CLEARED
/// so `reconcile_timers` disarms. A stray `ContextPromoted` leaf is seeded to
/// prove the abort comes from `params.ttl == None`, not the (prunable) leaf.
/// Pre-fix a `None` deadline was masked into `clock.now()` and the expiry
/// destroyed keys.
#[tokio::test]
async fn ttl_expiry_aborts_when_convergent_deadline_is_none() {
    const T0: u64 = 1_700_000_000;
    const STALE_TTL: u64 = 30;

    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(T0));
    let event_log =
        SeededEventLog::new(vec![seeded_context_created(0), seeded_context_promoted(1)]);
    let entries_handle = event_log.entries.clone();
    let sup = supervisor_with_clock_persistence_and_event_log(
        clock_dyn,
        Box::new(MapPersistence::default()),
        Box::new(event_log),
    );
    let deps = test_actor_deps(&sup).await;

    let ctx_id_bytes = [0x61u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:expiry-abort-admin".to_owned());
    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        T0,
        admin,
    );
    state.handle = crate::context::ContextHandle::new(
        ctx_key.clone(),
        scp_protocol::context::params::ContextParams {
            // Promoted ⇒ TTL removed (§5.10): `params.ttl == None` is the
            // prune-immune authority that drives the derivation to `None`.
            ttl: None,
            memory_scope: scp_protocol::context::params::MemoryScope::Full,
            ..Default::default()
        },
    );
    // A STALE non-`None` recorded deadline (params.ttl == None ⇒ derive None).
    state.ttl.timer.deadline_unix_secs = Some(T0 + STALE_TTL);
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);
    let handle = cell.handle.clone();

    // ADR-049 floor-registry SAFETY gate (F-1): seed a real registry
    // floor. An ABORTED expiry (params.ttl == None, A3) leaves the context
    // LIVE (`Active`), so its floors MUST survive — pruning here would drop a
    // live context's anti-replay floors. This guards the `state_transitioned()`
    // gate on the prune.
    sup.check_and_advance_sender_epoch(&ctx_id_bytes, "did:example:floor-sender", 1, u64::MAX)
        .expect("first sender-epoch advance is accepted");

    let outcome =
        crate::context::ttl_close_helpers::handle_ttl_expiry(&mut cell, &deps, &handle, 0).await;

    assert!(
        !outcome.result.is_complete(),
        "an aborted expiry is NOT a completed expiry"
    );
    assert!(
        sup.floors.contains_key(&ctx_id_bytes),
        "an ABORTED expiry leaves the context Active, so its registry floors MUST \
             survive — the prune is gated on a genuine terminal transition"
    );
    assert_eq!(
        cell.handle.state(),
        crate::context::ContextState::Active,
        "the FSM must stay Active — no terminal Expired transition off a None deadline (A3)"
    );
    assert_eq!(
        cell.ttl.timer.deadline_unix_secs, None,
        "the stale cached deadline must be cleared so reconcile_timers disarms (A3)"
    );
    let expired_leaves = entries_handle
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter(|e| e.event_type == scp_event_log::EventType::ContextExpired)
        .count();
    assert_eq!(
        expired_leaves, 0,
        "no ContextExpired leaf may be appended when the expiry aborts (A3)"
    );
}

/// F4 (finalize_close stamps the ACTUAL close time, not the TTL deadline):
/// `finalize_close` is the EXPLICIT Closing→Closed path (FFI
/// `context_finalize_close`). For a context with a LIVE finite `params.ttl`
/// closed BEFORE it expires, the convergent TTL deadline (`creation + ttl`) is
/// a FUTURE instant unrelated to when the close happened — stamping it would
/// record a future close time. The `ContextClosed` leaf must instead carry the
/// actual local close instant (`clock.now_secs()`). (The timer-driven expiry
/// path stamps a `ContextExpired` leaf off the convergent deadline and never
/// reaches `finalize_close`; cross-member convergence of an explicit governance
/// close is anchored by the prior `ContextClosing` committer leaf.)
#[tokio::test]
async fn finalize_close_explicit_stamps_actual_close_time() {
    const T0: u64 = 1_700_000_000;
    const CREATE_TTL: u64 = 500;
    // Close time is BEFORE the finite TTL deadline (`T0 + CREATE_TTL`), so the
    // convergent deadline is a FUTURE instant. `now` is the actual close time.
    const NOW_CLOSE: u64 = T0 + 100;
    const FUTURE_TTL_DEADLINE: u64 = T0 + CREATE_TTL;

    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(NOW_CLOSE));
    let event_log = SeededEventLog::new(vec![seeded_context_created(0)]);
    let entries_handle = event_log.entries.clone();
    let sup = supervisor_with_clock_persistence_and_event_log(
        clock_dyn,
        Box::new(MapPersistence::default()),
        Box::new(event_log),
    );
    let deps = test_actor_deps(&sup).await;

    let ctx_id_bytes = [0x62u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:finalize-actual-close-admin".to_owned());
    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        T0,
        admin,
    );
    // `Full` scope so finalize destroys no keys; a LIVE finite ttl whose
    // convergent deadline (`T0 + CREATE_TTL`) lies in the FUTURE relative to
    // the close instant, so the old code would (wrongly) stamp that future
    // deadline.
    state.handle = crate::context::ContextHandle::new(
        ctx_key.clone(),
        scp_protocol::context::params::ContextParams {
            ttl: Some(std::time::Duration::from_secs(CREATE_TTL)),
            memory_scope: scp_protocol::context::params::MemoryScope::Full,
            ..Default::default()
        },
    );
    // finalize_close requires the context to be in `Closing`.
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    state
        .handle
        .transition_to(&crate::context::ContextState::Closing)
        .unwrap();
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);
    let handle = cell.handle.clone();

    // ADR-049 floor-registry prune (F-1): seed a real registry floor for
    // this ctx (Full scope, so finalize destroys NO crypto — this proves the
    // prune is driven by the terminal close, not by key destruction), assert
    // it is present, then confirm the explicit close prunes it.
    sup.check_and_advance_sender_epoch(&ctx_id_bytes, "did:example:floor-sender", 1, u64::MAX)
        .expect("first sender-epoch advance is accepted");
    assert!(
        sup.floors.contains_key(&ctx_id_bytes),
        "a registry floor entry exists before the explicit close"
    );

    crate::context::shared::ttl_close::finalize_close(&mut cell, &deps, &handle)
        .await
        .expect("finalize_close on a Closing context succeeds");

    assert!(
        !sup.floors.contains_key(&ctx_id_bytes),
        "the explicit close (Closed) prunes the registry floor entry — no leak on \
             the dominant teardown path, even for Full scope where crypto is retained"
    );

    let closed_ts = entries_handle
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|e| e.event_type == scp_event_log::EventType::ContextClosed)
        .map(|e| e.timestamp)
        .expect("finalize_close appended a ContextClosed leaf");
    assert_eq!(
        closed_ts, NOW_CLOSE,
        "an explicit close must stamp the ACTUAL close time (now), not the TTL deadline (F4)"
    );
    assert_ne!(
        closed_ts, FUTURE_TTL_DEADLINE,
        "an explicit close of a live finite-ttl context must NOT stamp the future \
             creation+ttl deadline (F4)"
    );
}

/// An event-log double that FAILS the first append (modelling a transient
/// event-log failure that forces a TTL-expiry retry), then STORES and
/// returns every subsequent append so a test can read the timestamp the
/// retry stamped on the `ContextExpired` leaf. `fail_next_read` fails the
/// next `event_log_entries` read the same way.
#[derive(Clone, Default)]
struct FailFirstThenRecordEventLog {
    #[allow(clippy::disallowed_types)]
    entries: Arc<std::sync::Mutex<Vec<scp_event_log::Event>>>,
    fail_next: Arc<std::sync::atomic::AtomicBool>,
    fail_next_read: Arc<std::sync::atomic::AtomicBool>,
}
#[async_trait::async_trait]
impl crate::context::builder::ContextEventLogProvider for FailFirstThenRecordEventLog {
    async fn init_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    async fn append_event(
        &self,
        _id: &[u8; 32],
        event_type: scp_event_log::EventType,
        actor: &str,
        payload: scp_event_log::EventPayload,
        timestamp_secs: u64,
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        if self
            .fail_next
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            // Model a transient failure: DO NOT record, so the retry sees no
            // terminal leaf and re-appends.
            return Err(
                scp_protocol::context::builder::ContextCreationError::EventLogFailed(
                    "induced transient event-log append failure".to_owned(),
                ),
            );
        }
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(scp_event_log::Event {
                event_type,
                actor_did: DID(actor.to_owned()),
                timestamp: timestamp_secs,
                sequence: 0,
                payload,
                prev_hash: [0u8; 32],
                signature: Vec::new(),
            });
        Ok(())
    }
    async fn destroy_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    fn event_log_entries(
        &self,
        _id: &[u8; 32],
    ) -> Result<Option<Vec<scp_event_log::Event>>, ContextError> {
        if self
            .fail_next_read
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(ContextError::EventLogFailed(
                "induced transient event-log read failure".to_owned(),
            ));
        }
        Ok(Some(
            self.entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        ))
    }
}

/// A governance checkpoint whose event-log prune fails returns the
/// error, not a checkpoint over a log that kept the entries the policy
/// prunes (spec section 17.3, "Event log write failures").
#[tokio::test]
async fn a_checkpoint_whose_prune_fails_returns_the_error() {
    use crate::context::builder::ContextEventLogProvider as _;
    const T0: u64 = 1_700_000_000;
    let faulty = Arc::new(
        crate::context::supervisor::faulty_storage::FaultyStorage::new(Arc::new(
            scp_platform::in_memory::InMemoryStorage::new(),
        )),
    );
    let log =
        crate::context::providers::event_log::MerkleEventLogProvider::with_persistence(Arc::new(
            crate::store::context::ProtocolRepositoryEventLogBridge::new(Arc::new(
                crate::store::ProtocolRepository::new_for_testing(Arc::clone(&faulty)),
            )),
        ));
    let ctx_id = hex::encode([0x6Cu8; 32]);
    let ctx_bytes = crate::context::state::context_id_to_bytes(&ctx_id);
    log.init_event_log(&ctx_bytes).await.expect("init log");
    for i in 0..5u64 {
        log.append_event(
            &ctx_bytes,
            scp_event_log::EventType::MemberJoined,
            "did:example:checkpoint-admin",
            scp_event_log::EventPayload::default(),
            T0 + i,
        )
        .await
        .expect("append");
    }
    let sup = supervisor_with_clock_persistence_and_event_log(
        Arc::new(TestClock::new(T0)),
        Box::new(MapPersistence::default()),
        Box::new(log),
    );
    let deps = test_actor_deps(&sup).await;
    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        [0x6Cu8; 32],
        T0,
        DID("did:example:checkpoint-admin".to_owned()),
    );
    state.handle = crate::context::ContextHandle::new(
        ctx_id.clone(),
        scp_protocol::context::params::ContextParams::default(),
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    state.governance.pruning_policy = Some(scp_protocol::context::governance::PruningPolicy {
        size_based: Some(scp_protocol::context::governance::SizeBasedPolicy {
            max_event_count: 2,
            max_storage_bytes: u64::MAX,
        }),
        ..Default::default()
    });
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);

    faulty.fail_nth_store(1);
    let checkpoint = crate::context::shared::trust_recovery::create_governance_checkpoint(
        &mut cell,
        &deps,
        &ctx_id,
        1,
        [0u8; 32],
        5,
        [0u8; 32],
        [0u8; 32],
        &DID("did:example:checkpoint-admin".to_owned()),
        Vec::new(),
    )
    .await;
    assert!(
        matches!(checkpoint, Err(ContextError::EventLogFailed(_))),
        "the failed prune fails the checkpoint: {checkpoint:?}"
    );
    assert_eq!(
        deps.event_log
            .event_log_entries(&ctx_bytes)
            .expect("the log reads")
            .map(|entries| entries.len()),
        Some(5),
        "the in-memory log is unchanged"
    );
}

/// M1 (retry stamps the convergent deadline, REGRESSION GATE): when the
/// FIRST TTL-expiry attempt's `ContextExpired` append fails and a RETRY
/// performs the actual append, the stamped leaf timestamp must be the
/// CONVERGENT deadline (`creation + ttl`), NOT the retry-time clock.
///
/// Pre-fix this FAILED: `handle_ttl_expiry` read the leaf timestamp as
/// `deadline_unix_secs.unwrap_or(now())` at the top; Phase 1 cleared
/// `deadline_unix_secs` to `None`, so the retry re-read `None` → the local
/// `now()` clock. Under clock skew that diverges from the deadline a member
/// who appended on its first try stamped (§7.3.1/§9.9.3). The fix re-derives
/// the convergent deadline from `creation + ttl` (+ recorded extensions) on
/// the retry, independent of the cleared field.
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "linear TTL-expiry retry fixture (setup + two-attempt drive + convergent-timestamp asserts + ADR-049 PR-4 floor-prune asserts); reads clearer unsplit"
)]
async fn retry_stamps_convergent_leaf_timestamp() {
    const T0: u64 = 1_700_000_000;
    const TTL_SECS: u64 = 3_600;
    const CONVERGENT_DEADLINE: u64 = T0 + TTL_SECS;
    // The actor's LOCAL clock is far from the convergent deadline — a
    // `now()`-stamped retry would record THIS, not `CONVERGENT_DEADLINE`.
    const NOW_SKEWED: u64 = T0 + 1_000_000;

    // Seed the genesis `ContextCreated` leaf (`T0`) so the single-source
    // `convergent_ttl_deadline` derives the base `T0 + TTL_SECS =
    // CONVERGENT_DEADLINE` (A1) — the value the retry must stamp regardless of
    // the cleared scalar and the skewed clock.
    let event_log = FailFirstThenRecordEventLog {
        entries: Arc::new(std::sync::Mutex::new(vec![seeded_context_created(0)])),
        fail_next: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        ..Default::default()
    };
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(NOW_SKEWED));

    // Build a supervisor with the skewed clock AND the fail-first event log.
    let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
        "did:dht:z6MktestM1Convergent".to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
        Box::new(crate::context::builder::NotConfiguredTransportProvider);
    let key_resolver: KeyResolver = Arc::new(|_: &DID, _: scp_did::SigningKeyId| None);
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            InMemoryStorage::new(),
        )),
    );
    let sup = Supervisor::with_providers(
        crypto,
        transport,
        Box::new(event_log.clone()),
        key_resolver,
        Some(Box::new(MapPersistence::default())),
        None,
        None,
        Some(clock_dyn),
        mls_storage,
        crate::domain_handlers(),
    );
    let deps = test_actor_deps(&sup).await;

    let ctx_id_bytes = [0x5Cu8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:m1-convergent-admin".to_owned());

    // A `Full`-scope context: expiry needs no key destruction, so the only
    // completeness-critical step gated on the event log is the leaf append.
    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        T0,
        admin.clone(),
    );
    state.handle = crate::context::ContextHandle::new(
        ctx_key.clone(),
        scp_protocol::context::params::ContextParams {
            ttl: Some(std::time::Duration::from_secs(TTL_SECS)),
            memory_scope: scp_protocol::context::params::MemoryScope::Full,
            ..Default::default()
        },
    );
    state.ttl.timer.deadline_unix_secs = Some(CONVERGENT_DEADLINE);
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);
    let handle = cell.handle.clone();

    // ADR-049 floor-registry prune (F-1): seed a real registry floor and
    // assert the TERMINAL TTL expiry drops it. The Phase-1 terminal transition
    // (`state_transitioned()`) runs on the FIRST attempt even though the leaf
    // append fails, so the prune lands on `out1` — and the RETRY (`out2`) is a
    // harmless idempotent no-op (remove-on-absent).
    sup.check_and_advance_sender_epoch(&ctx_id_bytes, "did:example:floor-sender", 1, u64::MAX)
        .expect("first sender-epoch advance is accepted");
    assert!(
        sup.floors.contains_key(&ctx_id_bytes),
        "a registry floor entry exists before the terminal TTL expiry"
    );

    // First attempt: append FAILS ⇒ incomplete. Phase 1 clears the recorded
    // deadline.
    let out1 =
        crate::context::ttl_close_helpers::handle_ttl_expiry(&mut cell, &deps, &handle, 0).await;
    assert!(
        !out1.result.is_complete(),
        "first attempt's append must fail (forcing a retry): {}",
        out1.result
    );
    assert!(
        !sup.floors.contains_key(&ctx_id_bytes),
        "the terminal TTL transition (Expired) prunes the registry floor entry — no \
             leak on the TTL-expiry teardown path"
    );
    assert_eq!(
        cell.ttl.timer.deadline_unix_secs, None,
        "Phase 1 clears the recorded convergent deadline"
    );

    // Retry: the recorded deadline is gone, so the leaf timestamp must be
    // RE-DERIVED as `creation + ttl` — NOT the skewed local clock.
    let out2 = crate::context::ttl_close_helpers::handle_ttl_expiry(
        &mut cell,
        &deps,
        &handle,
        out1.result.completed_steps(),
    )
    .await;
    assert!(
        out2.result.is_complete(),
        "retry re-appends the ContextExpired leaf ⇒ complete: {}",
        out2.result
    );

    let expired: Vec<u64> = {
        let entries = event_log
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries
            .iter()
            .filter(|e| e.event_type == scp_event_log::EventType::ContextExpired)
            .map(|e| e.timestamp)
            .collect()
    };
    assert_eq!(
        expired,
        vec![CONVERGENT_DEADLINE],
        "the retry must stamp the CONVERGENT deadline (creation+ttl), not the \
             skewed retry-time clock ({NOW_SKEWED}) (M1)"
    );
}

/// M1 companion (retry stamps a RESET-EXTENDED convergent deadline): when the
/// live deadline was pushed out by a `reset_ttl_timer` extension (now recorded
/// as a `TtlExtended` leaf), a failed-then-retried `ContextExpired` append
/// must stamp the EXTENDED deadline — re-derived from the log's `TtlExtended`
/// leaf, not the create base and not the skewed retry-time clock. This proves
/// the single-source terminal-leaf derivation reads reset extensions too (the
/// whole point of making reset emit a leaf).
#[tokio::test]
async fn retry_stamps_reset_extended_convergent_deadline() {
    use crate::context::ttl_close_helpers::handle_ttl_expiry;
    const T0: u64 = 1_700_000_000;
    const TTL_SECS: u64 = 3_600;
    const BASE_DEADLINE: u64 = T0 + TTL_SECS;
    // A reset extension pushed the deadline out beyond the create base.
    const EXTENDED_DEADLINE: u64 = BASE_DEADLINE + 1_000;
    const NOW_SKEWED: u64 = T0 + 5_000_000;

    // Pre-seed the log with the create + reset-extension leaves so the
    // derivation reconstructs the EXTENDED deadline.
    let event_log = FailFirstThenRecordEventLog {
        entries: Arc::new(std::sync::Mutex::new(vec![
            seeded_context_created(0),
            seeded_ttl_extended(1, BASE_DEADLINE, EXTENDED_DEADLINE),
        ])),
        fail_next: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        ..Default::default()
    };
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(NOW_SKEWED));

    let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
        "did:dht:z6MktestM1Reset".to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
        Box::new(crate::context::builder::NotConfiguredTransportProvider);
    let key_resolver: KeyResolver = Arc::new(|_: &DID, _: scp_did::SigningKeyId| None);
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            InMemoryStorage::new(),
        )),
    );
    let sup = Supervisor::with_providers(
        crypto,
        transport,
        Box::new(event_log.clone()),
        key_resolver,
        Some(Box::new(MapPersistence::default())),
        None,
        None,
        Some(clock_dyn),
        mls_storage,
        crate::domain_handlers(),
    );
    let deps = test_actor_deps(&sup).await;

    let ctx_id_bytes = [0x5Du8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:m1-reset-admin".to_owned());

    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        T0,
        admin.clone(),
    );
    state.handle = crate::context::ContextHandle::new(
        ctx_key.clone(),
        scp_protocol::context::params::ContextParams {
            ttl: Some(std::time::Duration::from_secs(TTL_SECS)),
            memory_scope: scp_protocol::context::params::MemoryScope::Full,
            ..Default::default()
        },
    );
    state.ttl.timer.deadline_unix_secs = Some(EXTENDED_DEADLINE);
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);
    let handle = cell.handle.clone();

    let out1 = handle_ttl_expiry(&mut cell, &deps, &handle, 0).await;
    assert!(
        !out1.result.is_complete(),
        "first attempt's append must fail (forcing a retry): {}",
        out1.result
    );

    let out2 = handle_ttl_expiry(&mut cell, &deps, &handle, out1.result.completed_steps()).await;
    assert!(
        out2.result.is_complete(),
        "retry re-appends the ContextExpired leaf ⇒ complete: {}",
        out2.result
    );

    let expired: Vec<u64> = {
        let entries = event_log
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries
            .iter()
            .filter(|e| e.event_type == scp_event_log::EventType::ContextExpired)
            .map(|e| e.timestamp)
            .collect()
    };
    assert_eq!(
        expired,
        vec![EXTENDED_DEADLINE],
        "the retry must stamp the RESET-EXTENDED convergent deadline derived from \
             the TtlExtended leaf, not the create base ({BASE_DEADLINE}) or the skewed \
             clock ({NOW_SKEWED})"
    );
}

/// An expiry whose event log cannot be read stamps no `ContextExpired`
/// leaf: the leaf's deadline raises the snapshot base to the log's
/// extensions, and a log read as empty would stamp the shorter base. The
/// leaf step stays undone with the read error recorded, and the retry,
/// whose read succeeds, stamps the extended deadline (spec section 17.3,
/// "Event log write failures").
#[tokio::test]
async fn an_unreadable_log_at_expiry_stamps_no_shortened_deadline() {
    const T0: u64 = 1_700_000_000;
    const TTL_SECS: u64 = 3_600;
    const BASE_DEADLINE: u64 = T0 + TTL_SECS;
    const EXTENDED_DEADLINE: u64 = BASE_DEADLINE + 1_000;

    let event_log = FailFirstThenRecordEventLog {
        entries: Arc::new(std::sync::Mutex::new(vec![
            seeded_context_created(0),
            seeded_ttl_extended(1, BASE_DEADLINE, EXTENDED_DEADLINE),
        ])),
        fail_next_read: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        ..Default::default()
    };
    let sup = supervisor_with_clock_persistence_and_event_log(
        Arc::new(TestClock::new(T0)),
        Box::new(MapPersistence::default()),
        Box::new(event_log.clone()),
    );
    let deps = test_actor_deps(&sup).await;

    let ctx_id_bytes = [0x5Eu8; 32];
    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        T0,
        DID("did:example:unreadable-expiry-admin".to_owned()),
    );
    state.handle = crate::context::ContextHandle::new(
        hex::encode(ctx_id_bytes),
        scp_protocol::context::params::ContextParams {
            ttl: Some(std::time::Duration::from_secs(TTL_SECS)),
            memory_scope: scp_protocol::context::params::MemoryScope::Full,
            ..Default::default()
        },
    );
    state.ttl.timer.deadline_unix_secs = Some(EXTENDED_DEADLINE);
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);
    let handle = cell.handle.clone();
    let expired_leaves = || -> Vec<u64> {
        event_log
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|e| e.event_type == scp_event_log::EventType::ContextExpired)
            .map(|e| e.timestamp)
            .collect()
    };

    let out1 =
        crate::context::ttl_close_helpers::handle_ttl_expiry(&mut cell, &deps, &handle, 0).await;
    assert!(
        !out1.result.event_logged()
            && out1
                .result
                .errors()
                .iter()
                .any(|e| e.contains("induced transient event-log read failure")),
        "an unreadable log leaves the leaf step undone with the read error: {}",
        out1.result
    );
    assert_eq!(expired_leaves(), Vec::<u64>::new(), "no leaf is stamped");

    let out2 = crate::context::ttl_close_helpers::handle_ttl_expiry(
        &mut cell,
        &deps,
        &handle,
        out1.result.completed_steps(),
    )
    .await;
    assert!(
        out2.result.is_complete(),
        "the retry completes: {}",
        out2.result
    );
    assert_eq!(
        expired_leaves(),
        vec![EXTENDED_DEADLINE],
        "the retry stamps the extended deadline, not the base ({BASE_DEADLINE})"
    );
}

/// Reconcile idempotency: repeated per-turn reconciliation against an
/// UNCHANGED deadline must not drift or duplicate the one-shot arm — the
/// timer still fires exactly at the deadline despite many intervening
/// run-loop turns (each dispatched query re-runs `reconcile_timers`).
#[tokio::test(start_paused = true)]
async fn reconcile_timers_idempotent_no_rearm_when_deadline_unchanged() {
    const T0: u64 = 1_700_000_000;
    const TTL_SECS: u64 = 40;

    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(T0));
    let persistence = MapPersistence::default();
    // The expiry pipeline derives its leaf timestamp / abort decision from the
    // partitioned single-source deadline — the prune-immune snapshot base
    // `creation_timestamp_secs (= T0) + TTL_SECS` (matching the armed scalar).
    let event_log = SeededEventLog::new(vec![seeded_context_created(0)]);
    let sup = supervisor_with_clock_persistence_and_event_log(
        clock_dyn,
        Box::new(persistence.clone()),
        Box::new(event_log),
    );

    let ctx_id_bytes = [0x56u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:reconcile-idem-admin".to_owned());

    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        T0,
        admin.clone(),
    );
    // Finite params.ttl so the single-source deadline derives (prune-immune
    // snapshot base) and the expiry does not ABORT (A3).
    state.handle = crate::context::ContextHandle::new(
        ctx_key.clone(),
        scp_protocol::context::params::ContextParams {
            ttl: Some(std::time::Duration::from_secs(TTL_SECS)),
            ..Default::default()
        },
    );
    state.ttl.timer.deadline_unix_secs = Some(T0 + TTL_SECS);
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();

    let deps = test_actor_deps(&sup).await;
    sup.spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn Active actor with a fixed TTL deadline");

    // Force many run-loop turns (hence reconcile passes) BELOW the deadline,
    // advancing only a little each time. The unchanged deadline must not
    // cause a premature fire.
    for _ in 0..12 {
        assert_eq!(
            sup.read_context_state(&ctx_key).await,
            Some(crate::context::ContextState::Active),
            "the arm must not fire early despite repeated reconciliation"
        );
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
    }

    // Advance past the (unchanged) deadline: it must still fire exactly once.
    tokio::time::advance(std::time::Duration::from_secs(TTL_SECS)).await;
    let mut despawned = false;
    for _ in 0..64 {
        if sup.lookup(&ctx_key).is_none() {
            despawned = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        despawned,
        "the arm must still fire at the deadline after many idempotent reconciliations"
    );
    let persisted = persistence
        .load_context(&ctx_key)
        .await
        .unwrap()
        .expect("expiry must persist a durable snapshot");
    assert_eq!(persisted.state, crate::context::ContextState::Expired);
}

#[tokio::test]
async fn spawn_actor_with_state_rejects_duplicate_context_id() {
    // First-writer-wins: a second spawn with the same context_id is
    // REJECTED with CreationFailed rather than silently overwriting a
    // live actor (which would leak the loser's task and diverge
    // crypto state). This restores the duplicate-rejection the legacy
    // `manager_methods::insert_context` provided. The import replace
    // path despawns the prior actor first, so it never trips this.
    let supervisor_arc = supervisor_with_providers();

    let ctx_id_bytes = [0xCDu8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);

    let state1 = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        DID("did:example:admin".to_owned()),
    );
    let deps1 = test_actor_deps(&supervisor_arc).await;
    let h1 = supervisor_arc
        .spawn_actor_with_state(state1, deps1, None)
        .await
        .expect("first spawn of a fresh context id registers");
    assert!(supervisor_arc.lookup(&ctx_key).is_some());

    let state2 = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_001,
        DID("did:example:admin".to_owned()),
    );
    let deps2 = test_actor_deps(&supervisor_arc).await;
    // `ContextActorHandle` is not `Debug`, so pattern-match on the
    // `Result` rather than calling `expect_err` (which needs `Debug`
    // on the `Ok` variant).
    let dup = supervisor_arc
        .spawn_actor_with_state(state2, deps2, None)
        .await;
    // `ContextActorHandle` (the Ok variant) is not Debug, so assert via
    // `matches!` (which never formats the value) rather than `panic!`-arms.
    assert!(
        matches!(dup, Err(ContextError::CreationFailed(_))),
        "duplicate spawn must be rejected with CreationFailed"
    );
    // The original actor is still the registered one.
    assert!(supervisor_arc.lookup(&ctx_key).is_some());

    // Shut down the survivor to avoid a leaked task.
    let _ = h1.send_shutdown().await;
}

/// `shutdown_all_contexts` must DEREGISTER every actor, not just
/// dispatch `ShutdownSelf` to it. `ShutdownSelf` tears down the
/// per-context crypto/log/timers but does NOT break the actor
/// `run()` loop, and nothing else despawns the handle — so without
/// the explicit `despawn_actor` the contexts stay discoverable via
/// `lookup` / `actor_ids` and the spawned tasks linger as zombies
/// (the regression introduced when the lock-step `contexts.remove`
/// mirror was deleted). Asserts the registry is empty afterwards.
#[tokio::test]
async fn shutdown_all_contexts_deregisters_every_actor() {
    let supervisor_arc = supervisor_with_providers();

    // Spawn two distinct contexts.
    let ctx_a = [0x1Au8; 32];
    let ctx_b = [0x2Bu8; 32];
    let key_a = hex::encode(ctx_a);
    let key_b = hex::encode(ctx_b);
    for ctx_id_bytes in [ctx_a, ctx_b] {
        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        let deps = test_actor_deps(&supervisor_arc).await;
        supervisor_arc
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("fresh context id registers");
    }
    assert_eq!(
        supervisor_arc.actor_ids().len(),
        2,
        "both actors must be registered before shutdown"
    );

    crate::context::lifecycle_helpers::shutdown_all_contexts(&supervisor_arc).await;

    // Every actor must be deregistered: no zombie handles remain.
    assert!(
        supervisor_arc.actor_ids().is_empty(),
        "actor_ids must be empty after shutdown_all_contexts, got {:?}",
        supervisor_arc.actor_ids()
    );
    assert!(
        supervisor_arc.lookup(&key_a).is_none(),
        "context A must not be discoverable after shutdown"
    );
    assert!(
        supervisor_arc.lookup(&key_b).is_none(),
        "context B must not be discoverable after shutdown"
    );
}

/// ADR-049 Decision 16, item 2: once the closed flag is set,
/// `spawn_tracked_on` refuses a caller outside the tracker and still
/// accepts a tracked caller, and the drain waits for the task that caller
/// spawned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawn_tracked_on_after_close_admits_only_tracked_callers() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let supervisor = supervisor_with_providers();
    let runtime = tokio::runtime::Handle::current();

    supervisor
        .spawn_tracked_on(SinkHandoff::StreamSettlement, async {}, &runtime)
        .expect("an open gate accepts an outside caller")
        .await
        .expect("the task spawned before close runs");

    // A tracked task, started before close, that spawns once told to.
    let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let finished = Arc::new(AtomicBool::new(false));
    let finished_in_child = Arc::clone(&finished);
    let weak = Arc::downgrade(&supervisor);
    let child_runtime = runtime.clone();
    let parent = supervisor
        .spawn_tracked("tracked parent", async move {
            let _ = go_rx.await;
            let supervisor = weak.upgrade().expect("the test holds the supervisor");
            supervisor
                .spawn_tracked_on(
                    SinkHandoff::StreamSettlement,
                    async move {
                        let _ = release_rx.await;
                        finished_in_child.store(true, Ordering::SeqCst);
                    },
                    &child_runtime,
                )
                .map(drop)
        })
        .expect("an open gate accepts the parent");

    supervisor.close_spawn_gate();
    assert!(
        matches!(
            supervisor.spawn_tracked_on(SinkHandoff::StreamSettlement, async {}, &runtime),
            Err(ContextError::SupervisorShutDown(_))
        ),
        "a closed gate refuses spawn_tracked_on from a caller outside the tracker"
    );

    go_tx.send(()).expect("the parent is waiting");
    parent
        .await
        .expect("the parent does not panic")
        .expect("a closed gate accepts spawn_tracked_on from a tracked caller");

    let drain_supervisor = Arc::clone(&supervisor);
    let drain = tokio::spawn(async move { drain_supervisor.await_tracked_tasks().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        !drain.is_finished(),
        "the drain must wait for the task the tracked caller spawned"
    );
    release_tx.send(()).expect("the child is still waiting");
    tokio::time::timeout(std::time::Duration::from_secs(5), drain)
        .await
        .expect("the drain finishes once its last task exits")
        .expect("the drain does not panic");
    assert!(
        finished.load(Ordering::SeqCst),
        "the drain returned only after the child ran to completion"
    );
}

/// ADR-049 Decision 16: the shutdown token every streaming pump selects on
/// is live until the closed flag is set, and setting the flag cancels it.
#[tokio::test]
async fn close_spawn_gate_cancels_the_pump_shutdown_token() {
    let supervisor = supervisor_with_providers();
    assert!(
        !supervisor.shutdown_token.is_cancelled(),
        "the token is live while the gate is open"
    );
    supervisor.close_spawn_gate();
    assert!(
        supervisor.shutdown_token.is_cancelled(),
        "closing the gate cancels the token"
    );
}

/// The two kinds ADR-049 Decision 16 item 2 admits after the closed flag
/// is set. The exhaustive match fails to compile when a variant is added
/// without a row here.
fn every_sink_handoff() -> [SinkHandoff; 2] {
    const fn listed(kind: SinkHandoff) -> SinkHandoff {
        match kind {
            SinkHandoff::StreamSettlement | SinkHandoff::OutletInvokedEventAppend => kind,
        }
    }
    [
        listed(SinkHandoff::StreamSettlement),
        listed(SinkHandoff::OutletInvokedEventAppend),
    ]
}

/// ADR-049 Decision 16, item 2: after the closed flag is set, a tracked
/// caller's `spawn_tracked_on` accepts each of the two hand-off kinds,
/// and each spawned task runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawn_tracked_on_after_close_accepts_each_handoff_kind_from_a_tracked_caller() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let supervisor = supervisor_with_providers();
    let runtime = tokio::runtime::Handle::current();
    let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
    let ran = Arc::new(AtomicUsize::new(0));
    let ran_in_parent = Arc::clone(&ran);
    let weak = Arc::downgrade(&supervisor);
    let child_runtime = runtime.clone();
    let parent = supervisor
        .spawn_tracked("tracked parent", async move {
            let _ = go_rx.await;
            let supervisor = weak.upgrade().expect("the test holds the supervisor");
            let mut results = Vec::new();
            for kind in every_sink_handoff() {
                let ran = Arc::clone(&ran_in_parent);
                results.push((
                    kind,
                    supervisor
                        .spawn_tracked_on(
                            kind,
                            async move {
                                ran.fetch_add(1, Ordering::SeqCst);
                            },
                            &child_runtime,
                        )
                        .map(drop),
                ));
            }
            results
        })
        .expect("an open gate accepts the parent");

    supervisor.close_spawn_gate();
    go_tx.send(()).expect("the parent is waiting");
    for (kind, result) in parent.await.expect("the parent does not panic") {
        assert!(
            result.is_ok(),
            "a closed gate accepts {kind:?} from a tracked caller, got {result:?}"
        );
    }
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        supervisor.await_tracked_tasks(),
    )
    .await
    .expect("the drain finishes once the hand-off tasks exit");
    assert_eq!(
        ran.load(Ordering::SeqCst),
        every_sink_handoff().len(),
        "each accepted hand-off ran"
    );
}

/// ADR-049 Decision 16, item 2: after the closed flag is set, a spawn
/// outside the exception is refused with `SupervisorShutDown`:
/// `spawn_tracked` from any caller, `tracked_spawner` from any caller, and
/// `spawn_tracked_on` of each hand-off kind from a caller outside the
/// tracker. No refused future runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawn_after_close_outside_the_handoff_exception_is_refused() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let supervisor = supervisor_with_providers();
    let runtime = tokio::runtime::Handle::current();
    let ran = Arc::new(AtomicUsize::new(0));
    supervisor.close_spawn_gate();

    let ran_in = Arc::clone(&ran);
    assert!(
        matches!(
            supervisor.spawn_tracked("spawn after close", async move {
                ran_in.fetch_add(1, Ordering::SeqCst);
            }),
            Err(ContextError::SupervisorShutDown(_))
        ),
        "a closed gate refuses spawn_tracked"
    );
    assert!(
        matches!(
            supervisor.tracked_spawner("operation after close"),
            Err(ContextError::SupervisorShutDown(_))
        ),
        "a closed gate refuses tracked_spawner"
    );
    for kind in every_sink_handoff() {
        let ran_in = Arc::clone(&ran);
        let result = supervisor
            .spawn_tracked_on(
                kind,
                async move {
                    ran_in.fetch_add(1, Ordering::SeqCst);
                },
                &runtime,
            )
            .map(drop);
        assert!(
            matches!(result, Err(ContextError::SupervisorShutDown(_))),
            "a closed gate refuses {kind:?} from a caller outside the tracker, got {result:?}"
        );
    }
    supervisor.await_tracked_tasks().await;
    assert_eq!(ran.load(Ordering::SeqCst), 0, "no refused future ran");
}

/// ADR-049 Decision 16, item 2 — a closed gate issues no spawner to any
/// caller, a task on another Supervisor's tracker cannot spawn onto this
/// one, and a spawner issued before close keeps the drain waiting for
/// every task it spawns after close.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tracked_exception_is_per_supervisor_and_spawner_holds_the_drain() {
    let a = supervisor_with_providers();
    let b = supervisor_with_providers();
    let runtime = tokio::runtime::Handle::current();

    b.close_spawn_gate();
    assert!(
        matches!(
            b.tracked_spawner("outside caller after close"),
            Err(ContextError::SupervisorShutDown(_))
        ),
        "a closed gate refuses a spawner to a caller outside the tracker"
    );

    // A task on A's tracker is outside B's tracker.
    let b_in_a = Arc::clone(&b);
    let a_runtime = runtime.clone();
    let (onto_b, spawner_on_b) = a
        .spawn_tracked("task of A", async move {
            (
                b_in_a
                    .spawn_tracked_on(SinkHandoff::StreamSettlement, async {}, &a_runtime)
                    .map(drop),
                b_in_a.tracked_spawner("A's task onto B").map(drop),
            )
        })
        .expect("A's gate is open")
        .await
        .expect("the task of A does not panic");
    assert!(
        matches!(onto_b, Err(ContextError::SupervisorShutDown(_))),
        "B's closed gate refuses spawn_tracked_on from a task tracked by A"
    );
    assert!(
        matches!(spawner_on_b, Err(ContextError::SupervisorShutDown(_))),
        "B's closed gate refuses a spawner to a task tracked by A"
    );

    let spawner = a
        .tracked_spawner("operation begun before close")
        .expect("an open gate issues a spawner");
    a.close_spawn_gate();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let a_in_child = Arc::clone(&a);
    let child = spawner.spawn(async move {
        let nested = a_in_child.tracked_spawner("nested").map(drop);
        let _ = release_rx.await;
        nested
    });
    drop(spawner);

    let drain_supervisor = Arc::clone(&a);
    let drain = tokio::spawn(async move { drain_supervisor.await_tracked_tasks().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        !drain.is_finished(),
        "the drain waits for a task spawned after close through an earlier spawner"
    );
    release_tx.send(()).expect("the child is still waiting");
    tokio::time::timeout(std::time::Duration::from_secs(5), drain)
        .await
        .expect("the drain finishes once its last task exits")
        .expect("the drain does not panic");
    assert!(
        matches!(
            child.await.expect("the child does not panic"),
            Err(ContextError::SupervisorShutDown(_))
        ),
        "a closed gate refuses a spawner to a task on the same tracker"
    );
}

/// After `shutdown_all_contexts` returns and the owner drops its handle,
/// nothing keeps the Supervisor alive (ADR-049 Decision 16): every
/// supervisor-spawned task holds a `Weak` and the tracker wait has seen
/// each one exit. A `Weak` probe taken before shutdown must fail to
/// upgrade.
#[tokio::test]
async fn supervisor_drops_after_shutdown_and_owner_release() {
    let supervisor_arc = supervisor_with_providers();
    for ctx_id_bytes in [[0x3Cu8; 32], [0x4Du8; 32]] {
        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        let deps = test_actor_deps(&supervisor_arc).await;
        supervisor_arc
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("fresh context id registers");
    }
    supervisor_arc
        .key_package_store_for_loaded(&DID("did:dht:z6MkProbeKp".to_owned()))
        .await
        .expect("kp store resolves with providers");
    let probe = Arc::downgrade(&supervisor_arc);

    supervisor_arc.shutdown_all_contexts().await;
    assert!(
        supervisor_arc.key_package_stores.is_empty(),
        "shutdown must clear key_package_stores"
    );
    drop(supervisor_arc);

    assert!(
        probe.upgrade().is_none(),
        "a supervisor-spawned task still holds the Supervisor after shutdown"
    );
}

/// ADR-049 Decision 16 item 4: with no shutdown, dropping the owner's last
/// `Arc` drops the Supervisor while its context actors, their watchdogs,
/// and a key-package actor and its watchdog still run, because each holds
/// only a `Weak`. A strong back-reference in any of them keeps the probe
/// upgradable, and the bounded wait below fails.
#[tokio::test]
async fn supervisor_drops_on_owner_release_without_shutdown() {
    let supervisor_arc = supervisor_with_providers();
    for ctx_id_bytes in [[0x5Eu8; 32], [0x6Fu8; 32]] {
        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        let deps = test_actor_deps(&supervisor_arc).await;
        supervisor_arc
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("fresh context id registers");
    }
    supervisor_arc
        .key_package_store_for_loaded(&DID("did:dht:z6MkNoShutdownKp".to_owned()))
        .await
        .expect("kp store resolves with providers");
    let probe = Arc::downgrade(&supervisor_arc);
    drop(supervisor_arc);

    // A task may hold an upgraded `Arc` for one operation (item 4), so
    // the check waits a bounded time for any such operation to end.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while probe.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a supervisor-spawned task holds a strong reference to the Supervisor");
}

/// `drain_with_deadline` runs the post-drain step only after the last
/// tracked task exits. A drain slower than the deadline returns `TimedOut`
/// with the step not yet run, keeps running, and hands the step's value to
/// `on_late`; a drain within the deadline returns `Finished` with that
/// value.
#[tokio::test]
async fn drain_with_deadline_waits_for_tracked_tasks_before_the_post_drain_step() {
    let supervisor_arc = supervisor_with_providers();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    drop(
        supervisor_arc
            .spawn_tracked("slow tracked task", async move {
                let _ = release_rx.await;
            })
            .expect("an open supervisor accepts a tracked spawn"),
    );
    let step_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let step_flag = Arc::clone(&step_ran);
    let (late_tx, late_rx) = tokio::sync::oneshot::channel();
    let outcome = supervisor_arc
        .drain_with_deadline(
            tokio::time::Instant::now() + std::time::Duration::from_millis(20),
            move || {
                step_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                7_u8
            },
            move |late| {
                let _ = late_tx.send(late);
            },
        )
        .await;
    assert!(
        matches!(outcome, DrainWithDeadline::TimedOut),
        "a drain blocked on a tracked task must time out, got {outcome:?}"
    );
    assert!(
        !step_ran.load(std::sync::atomic::Ordering::SeqCst),
        "the post-drain step must not run while a tracked task is live"
    );
    release_tx.send(()).expect("the tracked task still waits");
    let late = tokio::time::timeout(std::time::Duration::from_secs(5), late_rx)
        .await
        .expect("the drain keeps running past the deadline")
        .expect("on_late receives the drain's result");
    assert_eq!(late, Ok(7), "on_late receives the post-drain step's value");

    let fast = supervisor_with_providers();
    let outcome = fast
        .drain_with_deadline(
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
            || 9_u8,
            |_| panic!("on_late must not run for a drain that met its deadline"),
        )
        .await;
    assert!(
        matches!(outcome, DrainWithDeadline::Finished(9)),
        "a drain within the deadline must finish with the step's value, got {outcome:?}"
    );
}

/// A post-drain step that panics makes `drain_with_deadline` return
/// `Failed(JoinFailure::Panicked)`, never `Finished`, and the late callback
/// receives `Err(JoinFailure::Panicked)`, which carries no panic payload.
#[tokio::test]
async fn drain_with_deadline_reports_a_panicking_post_drain_step() {
    let supervisor_arc = supervisor_with_providers();
    let outcome = supervisor_arc
        .drain_with_deadline(
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
            || -> u8 { panic!("secret-drain-payload") },
            |_| {},
        )
        .await;
    assert!(
        matches!(outcome, DrainWithDeadline::Failed(JoinFailure::Panicked)),
        "a panicking post-drain step must report Failed(Panicked), got {outcome:?}"
    );
    assert!(!format!("{outcome:?}").contains("secret-drain-payload"));

    let late_sup = supervisor_with_providers();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    drop(
        late_sup
            .spawn_tracked("slow tracked task", async move {
                let _ = release_rx.await;
            })
            .expect("an open supervisor accepts a tracked spawn"),
    );
    let (late_tx, late_rx) = tokio::sync::oneshot::channel();
    let outcome = late_sup
        .drain_with_deadline(
            tokio::time::Instant::now() + std::time::Duration::from_millis(20),
            || -> u8 { panic!("secret-late-payload") },
            move |late| {
                let _ = late_tx.send(late);
            },
        )
        .await;
    assert!(
        matches!(outcome, DrainWithDeadline::TimedOut),
        "{outcome:?}"
    );
    release_tx.send(()).expect("the tracked task still waits");
    let late = tokio::time::timeout(std::time::Duration::from_secs(5), late_rx)
        .await
        .expect("the drain keeps running past the deadline")
        .expect("on_late receives the drain's result");
    assert_eq!(late, Err(JoinFailure::Panicked));
}

/// `JoinFailure` names a panic as a panic and a cancellation as a
/// cancellation, and its text never carries the panic payload.
#[tokio::test]
async fn join_failure_splits_panic_from_cancel_without_payload() {
    let panicked = tokio::spawn(async { panic!("secret-join-payload") })
        .await
        .expect_err("a panicking task yields a JoinError");
    assert_eq!(
        JoinFailure::from_join_error(&panicked),
        JoinFailure::Panicked
    );
    let text = JoinFailure::from_join_error(&panicked).to_string();
    assert!(!text.contains("secret-join-payload"), "{text}");

    let pending = tokio::spawn(std::future::pending::<()>());
    pending.abort();
    let cancelled = pending
        .await
        .expect_err("an aborted task yields a JoinError");
    assert_eq!(
        JoinFailure::from_join_error(&cancelled),
        JoinFailure::Cancelled
    );
    assert!(!JoinFailure::Cancelled.to_string().contains("panicked"));
}

/// Once shutdown has begun, a spawn through the tracker is refused with
/// a typed error rather than run untracked (ADR-049 Decision 16).
#[tokio::test]
async fn spawn_after_shutdown_is_refused() {
    let supervisor_arc = supervisor_with_providers();
    supervisor_arc.shutdown_all_contexts().await;
    let refused = supervisor_arc.spawn_tracked("probe spawn", async {});
    assert!(
        matches!(refused, Err(ContextError::SupervisorShutDown(_))),
        "a spawn after shutdown must fail with SupervisorShutDown"
    );
    let kp = supervisor_arc
        .key_package_store_for_loaded(&DID("did:dht:z6MkLateKp".to_owned()))
        .await;
    assert!(
        matches!(kp, Err(ContextError::SupervisorShutDown(_))),
        "a key-package actor spawn after shutdown must be refused"
    );
}

/// A Phase-3 outlet-economy settle that finds NO registered actor for
/// its context (the actor was despawned during the off-mailbox
/// executor window) must NOT silently drop the in-flight ticket:
/// `settle_outlet_economy_via_actor` reclaims the ticket, voids its
/// external escrow (none here), consumes it so the `#[must_use]` Drop
/// balance guard does not `debug_assert!`-panic, and returns a typed
/// `ContextNotRegistered`. Reaching the assertions without a panic
/// proves the ticket was consumed rather than leaked.
#[tokio::test]
async fn settle_with_no_registered_actor_voids_and_consumes_ticket() {
    let supervisor_arc = supervisor_with_providers();
    let invoker = DID("did:example:invoker".to_owned());

    // A settle request for a context that has no actor registered.
    let ticket = crate::context::shared::outlets::OutletEconomyTicket::new_for_test_no_escrow(
        invoker.clone(),
    );
    let request = crate::context::shared::outlets::OutletSettleRequest::Rollback {
        generation: 1,
        ticket,
    };

    let result = supervisor_arc
        .settle_outlet_economy_via_actor("ctx-never-registered", &invoker, request)
        .await;

    assert!(
        matches!(&result, Err(ContextError::ContextNotRegistered(msg)) if msg.contains("registered actor")),
        "settle with no registered actor must return ContextNotRegistered \
             explaining the missing actor, got {result:?}"
    );
    // No panic ⇒ the ticket was consumed, not dropped unbalanced.
}

/// Each spawn pulls a DISTINCT monotonic spawn-generation from the
/// supervisor's `spawn_generation` counter, starting at 1 (never the
/// default 0 a fresh `PerContextState` carries). This is the token
/// stamped onto the actor's state and compared by the outlet-economy
/// settle to detect a settle landing on a replaced instance.
#[tokio::test]
async fn spawn_stamps_distinct_monotonic_generations() {
    use std::sync::atomic::Ordering;

    let supervisor_arc = supervisor_with_providers();

    // The counter starts at 0; the first spawn stamps 1.
    assert_eq!(
        supervisor_arc.spawn_generation.load(Ordering::Acquire),
        0,
        "a fresh supervisor's spawn-generation counter starts at 0"
    );

    for i in 0..3u8 {
        let ctx_id_bytes = [0x30 + i; 32];
        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        assert_eq!(state.generation, 0, "fresh test state defaults to gen 0");
        let deps = test_actor_deps(&supervisor_arc).await;
        supervisor_arc
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn registers");
        // After n spawns the counter has advanced to n, and the nth
        // spawn stamped generation n (>0, strictly increasing).
        assert_eq!(
            supervisor_arc.spawn_generation.load(Ordering::Acquire),
            u64::from(i) + 1,
            "spawn-generation counter must advance once per spawn"
        );
    }
}

/// Security invariant (import): `PrepareForReplace` MUST reject a
/// LIVE (Active) context — an import may never overwrite a live
/// context. The actor stays alive after the reject so the still-live
/// context keeps being served (no terminal break on reject).
#[tokio::test]
async fn prepare_for_replace_rejects_live_context() {
    use crate::context::actor::commands::LifecycleControlCommand;

    let supervisor_arc = supervisor_with_providers();
    let deps = test_actor_deps(&supervisor_arc).await;
    let ctx_id_bytes = [0x9Eu8; 32];
    let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        DID("did:example:admin".to_owned()),
    );
    // Drive the context's handle to Active — a live, non-replaceable
    // context.
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    let handle = supervisor_arc
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn registers the live context");

    let result: Result<(), ContextError> = handle
        .send(|reply| {
            ContextCommand::LifecycleControl(LifecycleControlCommand::PrepareForReplace {
                floors: verified_test_floors(&ctx_id_bytes, &[]),
                reply,
            })
        })
        .await;
    assert!(
        matches!(result, Err(ContextError::MembershipFailed(_))),
        "import must REJECT overwriting a live context, got {result:?}"
    );

    // The actor must still be alive after the reject — prove it by
    // issuing a follow-up read-only query and observing a reply (not
    // an ActorBusy/closed-inbox error).
    let followup: Result<Option<usize>, ContextError> = handle
        .send(|reply| {
            ContextCommand::Queries(QueriesCommand::MemberCount {
                context_id: hex::encode(ctx_id_bytes),
                reply,
            })
        })
        .await;
    assert!(
        !matches!(followup, Err(ContextError::ActorBusy(_))),
        "live context's actor must survive a rejected PrepareForReplace, got {followup:?}"
    );

    let _ = handle.send_shutdown().await;
}

/// `PrepareForReplace` SUCCEEDS for a replaceable (Closing/Closed)
/// context: it runs the §23.17 crypto teardown + epoch-floor merge,
/// claims itself terminal, and the actor exits its run loop.
#[tokio::test]
async fn prepare_for_replace_succeeds_for_replaceable_context() {
    use crate::context::actor::commands::LifecycleControlCommand;

    let supervisor_arc = supervisor_with_providers();
    let deps = test_actor_deps(&supervisor_arc).await;
    let ctx_id_bytes = [0x8Du8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        DID("did:example:admin".to_owned()),
    );
    // Drive the handle Active → Closing — a replaceable state.
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    state
        .handle
        .transition_to(&crate::context::ContextState::Closing)
        .unwrap();
    let handle = supervisor_arc
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn registers the replaceable context");

    let result: Result<(), ContextError> = handle
        .send(|reply| {
            ContextCommand::LifecycleControl(LifecycleControlCommand::PrepareForReplace {
                floors: verified_test_floors(&ctx_id_bytes, &[]),
                reply,
            })
        })
        .await;
    assert!(
        result.is_ok(),
        "PrepareForReplace must succeed for a replaceable (Closing) context, got {result:?}"
    );

    // The actor claimed itself terminal and exits — a follow-up send
    // must observe the closed inbox. (The supervisor despawns the
    // dead handle in the import path; here we just prove termination.)
    let followup: Result<Option<usize>, ContextError> = handle
        .send(|reply| {
            ContextCommand::Queries(QueriesCommand::MemberCount {
                context_id: ctx_key.clone(),
                reply,
            })
        })
        .await;
    assert!(
        matches!(followup, Err(ContextError::ActorBusy(_))),
        "actor must have exited after a successful PrepareForReplace, got {followup:?}"
    );

    // Handle is still registered until the import path despawns it.
    assert!(supervisor_arc.lookup(&ctx_key).is_some());
}

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
fn import_test_snapshot(context_id: &str, creator: &str) -> crate::context::state::ContextSnapshot {
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

    crate::context::state::ContextSnapshot {
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
        capability_requirements: crate::context::state::Replicated::Live(
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
        mls_crypto_state: crate::context::state::MlsCryptoState::default(),
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
        routing: crate::context::actor::state::ContextRouting::Broadcast,
        relay_urls: Vec::new(),
        pseudonym_rotation:
            crate::context::actor::pseudonym_rotation::PseudonymRotationState::default(),
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

/// A forged export — structurally valid and signed by the creator's
/// key, but presented with a DIFFERENT verifying key on import — must
/// be rejected WITHOUT leaking a key-package-store actor/entry.
#[tokio::test]
async fn import_rejects_forged_export_before_building_actor_deps() {
    use ed25519_dalek::{Signer, SigningKey};

    let supervisor = supervisor_with_providers();
    // Providers ARE wired here, so `build_actor_deps` would succeed and
    // spawn a key-package store if it were reached — the verify gate is
    // what must keep it from being reached.
    assert!(
        supervisor.key_package_stores.is_empty(),
        "fixture starts with no key-package stores"
    );

    let creator = "did:key:forge-test-creator";
    let snapshot = import_test_snapshot("forge-ctx", creator);
    let event_log_data =
        create_event_log_data(&[0x11u8; 32], &[scp_event_log::EventType::ContextCreated]).await;

    // Sign with the real creator key so the export is internally
    // consistent (exporter_did == creator_did, signature authentic
    // under `signing_key`).
    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let export = crate::context::export_import::create_export(
        snapshot,
        event_log_data,
        DID(creator.to_owned()),
        crate::context::export_import::ExportScope::Full,
        &scp_clock::SystemClock,
        |hash: &[u8; 32]| Ok::<_, scp_crypto::CustodyFailure>(signing_key.sign(hash).to_bytes()),
    )
    .expect("build a valid signed export");

    // Present a DIFFERENT verifying key — simulating a forgery / a
    // resolver returning the wrong creator key. Verification must fail.
    let wrong_key = SigningKey::from_bytes(&[1u8; 32]).verifying_key();

    let result = supervisor.import_context(export, &wrong_key, None).await;

    assert!(
        matches!(result, Err(ContextError::SnapshotSignatureInvalid { .. })),
        "forged export must be rejected with a signature error, got {result:?}"
    );
    // The verify-before-side-effect gate must have short-circuited
    // BEFORE `build_actor_deps`/`key_package_store_for`: no actor and
    // no permanent map entry may have leaked.
    assert!(
        supervisor.key_package_stores.is_empty(),
        "rejected forged import must not leak a key-package-store entry"
    );
}

/// §9.10.4 (FIX 1 runtime defense): a validly-signed BROADCAST-mode export
/// is rejected with `ImportRejected` (the import path is encrypted-only) —
/// NOT silently re-homed as an encrypted context with the reserved zero
/// pseudonym. With verify-before-init, the signature must VERIFY first, so the export is
/// signed by the creator key and presented with the matching verifying key;
/// rejection then comes from the broadcast guard inside `import_context`.
#[tokio::test]
async fn import_rejects_broadcast_export() {
    use ed25519_dalek::{Signer, SigningKey};

    let supervisor = supervisor_with_providers();
    let creator = "did:key:broadcast-import-creator";
    let mut snapshot = import_test_snapshot("broadcast-ctx", creator);
    snapshot.context_params.mode = scp_protocol::context::ContextMode::Broadcast;
    snapshot.routing = crate::context::actor::state::ContextRouting::Broadcast;
    let event_log_data =
        create_event_log_data(&[0x22u8; 32], &[scp_event_log::EventType::ContextCreated]).await;

    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let export = crate::context::export_import::create_export(
        snapshot,
        event_log_data,
        DID(creator.to_owned()),
        crate::context::export_import::ExportScope::Full,
        &scp_clock::SystemClock,
        |hash: &[u8; 32]| Ok::<_, scp_crypto::CustodyFailure>(signing_key.sign(hash).to_bytes()),
    )
    .expect("build a valid signed broadcast export");
    let verifying_key = signing_key.verifying_key();

    let result = supervisor
        .import_context(export, &verifying_key, Some([0x42u8; 32]))
        .await;
    assert!(
        matches!(result, Err(ContextError::ImportRejected { .. })),
        "a broadcast-mode export must be rejected with ImportRejected; got {result:?}"
    );
}

/// Builds an `OutletRegistration` that
/// `OutletRegistration::validate_registrable` accepts: two properties on each
/// schema (the §6.2/§9.2.1 specificity floor is `MIN_SCHEMA_FIELDS == 2`), an
/// `Action` kind with no cost, and an operator DID that parses.
fn importable_outlet_fixture(
    outlet_id: &str,
) -> scp_protocol::context::outlets::OutletRegistration {
    use scp_protocol::context::outlets::{OutletKind, OutletRegistration, OutletSchema};
    OutletRegistration {
        outlet_id: outlet_id.to_owned(),
        kind: OutletKind::Action,
        name: outlet_id.to_owned(),
        description: "imported outlet fixture".to_owned(),
        schema: OutletSchema {
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {"lhs": {"type": "number"}, "rhs": {"type": "number"}}
            }),
            output_schema: serde_json::json!({
                "type": "object",
                "properties": {"sum": {"type": "number"}, "carry": {"type": "boolean"}}
            }),
            aggregate_schema: None,
        },
        implementation_hash: [7u8; 32],
        test_vectors: vec![],
        message_catalog: Vec::new(),
        operator_did: DID("did:dht:z6MkImportedOutletOperator".to_owned()),
        cost: None,
        registered_at: 0,
        signature: Vec::new(),
    }
}

/// Signs `snapshot` as `creator` and imports it, returning whatever
/// `Supervisor::import_context` returned. Every outlet-registry import test
/// below drives this one helper, so the only difference between them is the
/// `registered_outlets` vector the caller put on the snapshot.
async fn import_snapshot_signed_by_creator(
    snapshot: crate::context::state::ContextSnapshot,
    creator: &str,
    ctx_id_bytes: &[u8; 32],
) -> Result<crate::context::ContextHandle, ContextError> {
    Box::pin(import_snapshot_into(
        MapPersistence::default(),
        snapshot,
        creator,
        ctx_id_bytes,
    ))
    .await
}

/// [`import_snapshot_signed_by_creator`] into a supervisor that persists
/// to `persistence`, so a test can read what the import persisted.
async fn import_snapshot_into(
    persistence: MapPersistence,
    snapshot: crate::context::state::ContextSnapshot,
    creator: &str,
    ctx_id_bytes: &[u8; 32],
) -> Result<crate::context::ContextHandle, ContextError> {
    use ed25519_dalek::{Signer, SigningKey};

    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_persistence_and_merkle_log(clock_dyn, Box::new(persistence));
    let event_log_data =
        create_event_log_data(ctx_id_bytes, &[scp_event_log::EventType::ContextCreated]).await;
    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let export = crate::context::export_import::create_export(
        snapshot,
        event_log_data,
        DID(creator.to_owned()),
        crate::context::export_import::ExportScope::Full,
        &scp_clock::SystemClock,
        |hash: &[u8; 32]| Ok::<_, scp_crypto::CustodyFailure>(signing_key.sign(hash).to_bytes()),
    )
    .expect("build a valid signed full export");

    sup.import_context(export, &verifying_key, None).await
}

/// Import installs the relay set the creator-signed snapshot names
/// (§5.12.3.1 `relay_urls`, PUSH-025), each relay once, and persists it.
#[tokio::test]
async fn import_installs_the_exported_relay_set() {
    let creator = "did:key:import-relay-set-creator";
    let context_id = "import-relay-set-ctx";
    let ctx_id_bytes = crate::context::state::context_id_to_bytes(context_id);
    let mut snapshot = import_test_snapshot(context_id, creator);
    snapshot.relay_urls = vec![
        "wss://relay-b.example/scp/v1".to_owned(),
        "wss://relay-a.example/scp/v1".to_owned(),
        "wss://relay-b.example/scp/v1".to_owned(),
    ];
    let persistence = MapPersistence::default();
    let contexts = Arc::clone(&persistence.contexts);

    Box::pin(import_snapshot_into(
        persistence,
        snapshot,
        creator,
        &ctx_id_bytes,
    ))
    .await
    .expect("a creator-signed export imports");
    assert_eq!(
        contexts
            .get(context_id)
            .map(|stored| stored.relay_urls.clone()),
        Some(vec![
            "wss://relay-b.example/scp/v1".to_owned(),
            "wss://relay-a.example/scp/v1".to_owned(),
        ]),
        "import installs and persists the exported relay set, each relay once"
    );
}

/// Imports a creator-signed export whose snapshot names `relay_urls`, then
/// returns the relay set the importer persists.
async fn imported_relay_set(context_id: &str, relay_urls: &[&str]) -> Option<Vec<String>> {
    let creator = "did:key:import-relay-set-creator";
    let ctx_id_bytes = crate::context::state::context_id_to_bytes(context_id);
    let mut snapshot = import_test_snapshot(context_id, creator);
    snapshot.relay_urls = relay_urls.iter().map(|u| (*u).to_owned()).collect();
    let persistence = MapPersistence::default();
    let contexts = Arc::clone(&persistence.contexts);
    Box::pin(import_snapshot_into(
        persistence,
        snapshot,
        creator,
        &ctx_id_bytes,
    ))
    .await
    .expect("a creator-signed export imports whatever the relay URLs");
    contexts
        .get(context_id)
        .map(|stored| stored.relay_urls.clone())
}

/// Import stores two spellings of one relay as one entry, the §9.18.2
/// canonical relay URL.
#[tokio::test]
async fn import_stores_two_spellings_of_a_relay_as_one_canonical_entry() {
    const SPELLING_1: &str = "WSS://Relay-A.Example:443/scp/v1/";
    const SPELLING_2: &str = "wss://relay-a.example/scp/v1";
    assert_eq!(
        imported_relay_set("import-relay-spellings-ctx", &[SPELLING_1, SPELLING_2]).await,
        Some(vec![SPELLING_2.to_owned()])
    );
}

/// Import stores a relay URL with no §9.18.2 canonical form exactly as
/// written, and succeeds.
#[tokio::test]
async fn import_stores_a_relay_url_without_canonical_form_as_written() {
    const HTTPS: &str = "https://Relay-A.Example/scp/v1/";
    assert_eq!(
        imported_relay_set("import-relay-https-ctx", &[HTTPS]).await,
        Some(vec![HTTPS.to_owned()])
    );
}

/// The import path installs `export.snapshot.registered_outlets` into the
/// live `GovernanceState::registered_outlets`, which
/// `actor::handlers::saga::validate_input_specificity` reads as an
/// authorization grant. A creator-signed export carrying MORE than
/// `MAX_REGISTERED_OUTLETS` registrations must be refused, exactly as the
/// genesis path and `execute_register_outlet` refuse an over-cap set — the
/// snapshot signature authenticates the writer of those bytes and does not
/// establish that the registry is admissible (GitHub #2250).
#[tokio::test]
async fn import_rejects_an_over_cap_outlet_registry() {
    let creator = "did:key:import-outlet-cap-creator";
    let context_id = "import-outlet-cap-ctx";
    let ctx_id_bytes = crate::context::state::context_id_to_bytes(context_id);
    let mut snapshot = import_test_snapshot(context_id, creator);
    snapshot.registered_outlets = (0..=crate::context::state::MAX_REGISTERED_OUTLETS)
        .map(|i| importable_outlet_fixture(&format!("outlet-{i}")))
        .collect();

    let err = import_snapshot_signed_by_creator(snapshot, creator, &ctx_id_bytes)
        .await
        .expect_err("an over-cap imported outlet registry must be refused");
    let ContextError::ImportRejected { reason } = &err else {
        panic!("expected ImportRejected for an over-cap outlet registry, got {err:?}");
    };
    assert!(
        reason.contains("imported outlet count"),
        "the refusal names the imported outlet-count bound, got {reason}"
    );
}

/// An imported registration that `register_outlet` would refuse — an
/// `operator_did` that is not a DID (§5.4.1) — must not reach the live
/// registry.
#[tokio::test]
async fn import_rejects_an_unregistrable_outlet() {
    let creator = "did:key:import-outlet-operator-creator";
    let context_id = "import-outlet-operator-ctx";
    let ctx_id_bytes = crate::context::state::context_id_to_bytes(context_id);
    let mut snapshot = import_test_snapshot(context_id, creator);
    let mut hostile = importable_outlet_fixture("alpha");
    hostile.operator_did = DID("not-a-did".to_owned());
    snapshot.registered_outlets = vec![hostile];

    let err = import_snapshot_signed_by_creator(snapshot, creator, &ctx_id_bytes)
        .await
        .expect_err("an unregistrable imported outlet must be refused");
    let ContextError::ImportRejected { reason } = &err else {
        panic!("expected ImportRejected for an unregistrable outlet, got {err:?}");
    };
    assert!(
        reason.contains("is not a registrable OutletRegistration"),
        "the refusal names the registration check, got {reason}"
    );
}

/// Two imported registrations sharing one `outlet_id` must be refused:
/// `registered_outlets` is a `Vec`, so both would install, and a later
/// `execute_remove_outlet` would delete one and leave the other answering
/// invocations the context revoked.
#[tokio::test]
async fn import_rejects_duplicate_outlet_ids() {
    let creator = "did:key:import-outlet-dup-creator";
    let context_id = "import-outlet-dup-ctx";
    let ctx_id_bytes = crate::context::state::context_id_to_bytes(context_id);
    let mut snapshot = import_test_snapshot(context_id, creator);
    snapshot.registered_outlets = vec![
        importable_outlet_fixture("alpha"),
        importable_outlet_fixture("alpha"),
    ];

    let err = import_snapshot_signed_by_creator(snapshot, creator, &ctx_id_bytes)
        .await
        .expect_err("a duplicate imported outlet id must be refused");
    let ContextError::ImportRejected { reason } = &err else {
        panic!("expected ImportRejected for a duplicate outlet id, got {err:?}");
    };
    assert!(
        reason.contains("more than once"),
        "the refusal names the duplication, got {reason}"
    );
}

/// The control for the three rejections above: an imported registry of two
/// registrable outlets imports successfully, so the new check refuses
/// inadmissible registries rather than every registry.
#[tokio::test]
async fn import_accepts_a_registrable_outlet_registry() {
    let creator = "did:key:import-outlet-ok-creator";
    let context_id = "import-outlet-ok-ctx";
    let ctx_id_bytes = crate::context::state::context_id_to_bytes(context_id);
    let mut snapshot = import_test_snapshot(context_id, creator);
    snapshot.registered_outlets = vec![
        importable_outlet_fixture("alpha"),
        importable_outlet_fixture("beta"),
    ];

    let _handle = import_snapshot_signed_by_creator(snapshot, creator, &ctx_id_bytes)
        .await
        .expect("an export carrying registrable outlets imports successfully");
}

/// An imported `sybil_policy` that breaks a §9.3.1 validity rule (here a
/// device-attestation max age one second above the one-year maximum) is
/// refused with `ImportRejected`, as a create with the same policy is.
/// The reason names the sybil policy, so the refusal comes from this check
/// and not from a later import step.
#[tokio::test]
async fn import_rejects_invalid_policy() {
    let creator = "did:key:import-sybil-invalid-creator";
    let context_id = "import-sybil-invalid-ctx";
    let ctx_id_bytes = crate::context::state::context_id_to_bytes(context_id);
    let mut snapshot = import_test_snapshot(context_id, creator);
    snapshot.context_params.sybil_policy = Some(scp_protocol::trust::sybil::ContextSybilPolicy {
        device_attestation_max_age_secs:
            scp_protocol::trust::sybil::MAX_DEVICE_ATTESTATION_MAX_AGE_SECS + 1,
        ..scp_protocol::trust::sybil::ContextSybilPolicy::casual()
    });

    let result = import_snapshot_signed_by_creator(snapshot, creator, &ctx_id_bytes).await;
    assert!(
        matches!(
            result,
            Err(ContextError::ImportRejected { ref reason }) if reason.contains("sybil_policy")
        ),
        "an invalid imported sybil policy must be refused with ImportRejected; got {:?}",
        result.as_ref().map(|_| ())
    );
}

/// The control for `import_rejects_invalid_policy`: the same import with a
/// sybil policy at the one-year maximum succeeds, so the check refuses only
/// an invalid policy.
#[tokio::test]
async fn import_accepts_valid_policy() {
    let creator = "did:key:import-sybil-valid-creator";
    let context_id = "import-sybil-valid-ctx";
    let ctx_id_bytes = crate::context::state::context_id_to_bytes(context_id);
    let mut snapshot = import_test_snapshot(context_id, creator);
    snapshot.context_params.sybil_policy = Some(scp_protocol::trust::sybil::ContextSybilPolicy {
        device_attestation_max_age_secs:
            scp_protocol::trust::sybil::MAX_DEVICE_ATTESTATION_MAX_AGE_SECS,
        ..scp_protocol::trust::sybil::ContextSybilPolicy::casual()
    });

    let result = import_snapshot_signed_by_creator(snapshot, creator, &ctx_id_bytes).await;
    assert!(
        result.is_ok(),
        "an import carrying a valid sybil policy must succeed; got {:?}",
        result.as_ref().map(|_| ())
    );
}

/// An import that `import_accepts_a_registrable_outlet_registry` shows
/// succeeding is refused with the typed `ContextError::SupervisorShutDown`
/// (`SCP-CTX-2138`, ADR-049 Decision 16 item 2) once
/// `shutdown_all_contexts` has begun.
#[tokio::test]
async fn import_after_shutdown_keeps_supervisor_shut_down() {
    use ed25519_dalek::{Signer, SigningKey};

    let creator = "did:key:import-after-shutdown-creator";
    let context_id = "import-after-shutdown-ctx";
    let ctx_id_bytes = crate::context::state::context_id_to_bytes(context_id);
    let mut snapshot = import_test_snapshot(context_id, creator);
    snapshot.registered_outlets = vec![
        importable_outlet_fixture("alpha"),
        importable_outlet_fixture("beta"),
    ];

    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_persistence_and_merkle_log(
        clock_dyn,
        Box::new(MapPersistence::default()),
    );
    let event_log_data =
        create_event_log_data(&ctx_id_bytes, &[scp_event_log::EventType::ContextCreated]).await;
    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let export = crate::context::export_import::create_export(
        snapshot,
        event_log_data,
        DID(creator.to_owned()),
        crate::context::export_import::ExportScope::Full,
        &scp_clock::SystemClock,
        |hash: &[u8; 32]| Ok::<_, scp_crypto::CustodyFailure>(signing_key.sign(hash).to_bytes()),
    )
    .expect("build a valid signed full export");

    sup.shutdown_all_contexts().await;
    let result = sup.import_context(export, &verifying_key, None).await;
    assert!(
        matches!(result, Err(ContextError::SupervisorShutDown(_))),
        "an import after shutdown must fail with SupervisorShutDown; got {result:?}"
    );
}

/// A validly-signed export whose ceiling carries a MALFORMED entry (spec
/// §5.3.1.1) must be rejected with `ImportRejected`. A valid signature
/// authenticates the ORIGIN, not the WELL-FORMEDNESS of the payload — so a
/// non-conformant peer's signed export (which could carry a malformed ceiling
/// the local construction invariant would never produce) must not poison a
/// conformant importer. The export is signed by the creator key and presented
/// with the matching verifying key, so it passes signature verification;
/// rejection comes from the ceiling-grammar check inside `import_context`.
#[tokio::test]
async fn import_rejects_malformed_ceiling_entry() {
    use ed25519_dalek::{Signer, SigningKey};

    let supervisor = supervisor_with_providers();
    let creator = "did:key:malformed-ceiling-import-creator";
    let context_id = "malformed-ceiling-import-ctx";
    let mut snapshot = import_test_snapshot(context_id, creator);
    // Inject a malformed (no-colon) custom directly into the ceiling's backing
    // set via the test-only accessor, simulating a non-conformant peer's
    // export — the construction invariant forbids producing this legitimately.
    snapshot.role_state.ceiling_mut().capabilities_mut().insert(
        scp_protocol::context::roles::Capability::Custom("payments".to_owned()),
    );
    let event_log_data =
        create_event_log_data(&[0x33u8; 32], &[scp_event_log::EventType::ContextCreated]).await;

    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let export = crate::context::export_import::create_export(
        snapshot,
        event_log_data,
        DID(creator.to_owned()),
        crate::context::export_import::ExportScope::Full,
        &scp_clock::SystemClock,
        |hash: &[u8; 32]| Ok::<_, scp_crypto::CustodyFailure>(signing_key.sign(hash).to_bytes()),
    )
    .expect("build a valid signed export with a malformed ceiling");
    let verifying_key = signing_key.verifying_key();

    let result = supervisor
        .import_context(export, &verifying_key, Some([0x42u8; 32]))
        .await;
    assert!(
        matches!(
            result,
            Err(ContextError::ImportRejected { ref reason }) if reason.contains("malformed")
        ),
        "an export with a malformed ceiling entry must be rejected with \
             ImportRejected; got {result:?}"
    );
}

// -----------------------------------------------------------------
// Eviction-path coverage for the `ImportContext` dispatch arm.
//
// The forged-import test above exercises the verify-GATE (the
// export is rejected before `build_actor_deps`, so no key-package
// store is ever spawned). These two tests exercise the
// POST-verify rejection path: a VALIDLY-signed export that passes
// `validate_export_for_import` but is then rejected inside
// `lifecycle_helpers::import_context` by the live-context-overwrite
// guard (a live actor is already registered for the same id, so
// `dispatch_prepare_for_replace` returns `MembershipFailed`). That
// is the branch where `kp_store_newly_spawned` matters, and where
// the TOCTOU fix (probe + spawn + evict all under
// `bootstrap_spawn_lock`) keeps the eviction race-free.
//
// Invariants asserted:
//   1. A store this import NEWLY spawned is evicted on its failure
//      (no orphan).
//   2. A PRE-EXISTING/shared store is NOT torn down by this import's
//      failure (no wrongful teardown).
// -----------------------------------------------------------------

/// Spawn a LIVE (Active) encrypted-mode actor under the hex id key
/// `hex::encode(ctx_id_bytes)` and return the registry key. After
/// this, `lookup(&hex_key)` is `Some`, so an import targeting the
/// same id hits the live-context-overwrite guard.
async fn spawn_live_context(supervisor: &Arc<Supervisor>, ctx_id_bytes: [u8; 32]) -> String {
    let deps = test_actor_deps(supervisor).await;
    let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        DID("did:example:live-admin".to_owned()),
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .expect("drive live context to Active");
    supervisor
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn registers the live context");
    hex::encode(ctx_id_bytes)
}

/// The standing-direct Outcome sketch keeps a Supervisor shutdown typed,
/// and still records an error it has no arm for as a crypto failure.
#[test]
fn standing_sketch_keeps_supervisor_shut_down_typed() {
    let sketch =
        super::standing_outcome_error_sketch(&ContextError::SupervisorShutDown("gone".to_owned()));
    assert!(
        matches!(&sketch, ContextError::SupervisorShutDown(m) if m == "gone"),
        "got {sketch:?}"
    );
    let unmapped =
        super::standing_outcome_error_sketch(&ContextError::ActorBusy("busy".to_owned()));
    assert!(
        matches!(unmapped, ContextError::CryptoFailed(_)),
        "got {unmapped:?}"
    );
}

/// A caller that drops `release_stream_escrow` after its first poll leaves
/// the reversal running as a tracked task and gets no second refund from
/// the ticket's `Drop`. Awaiting the reversal inside the caller's future
/// would spawn no task, so the tracker count would not rise.
#[tokio::test]
async fn release_stream_escrow_dropped_mid_reversal_does_not_refund_again() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingRefundSink(AtomicUsize);
    impl crate::context::outlets::dispatch::StreamEscrowRefundSink for CountingRefundSink {
        fn refund(
            &self,
            _context_id: &str,
            _member_did: &DID,
            _amount: scp_protocol::economy::types::Amount,
        ) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let supervisor = supervisor_with_providers();
    let member = DID("did:example:live-admin".to_owned());
    let deps = test_actor_deps(&supervisor).await;
    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        [0x5e; 32],
        1_700_000_000,
        member.clone(),
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .expect("drive live context to Active");
    // The open-time hold this release reverses: 50 of 100 spent.
    state
        .governance
        .budget_tracker
        .grant(&member, scp_protocol::economy::types::Amount::new(100));
    state
        .governance
        .budget_tracker
        .record_spend(&member, scp_protocol::economy::types::Amount::new(50))
        .expect("the grant covers the hold");
    supervisor
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn registers the live context");
    let context_id = hex::encode([0x5e; 32]);
    let sink = Arc::new(CountingRefundSink(AtomicUsize::new(0)));
    let ticket = crate::context::outlets::dispatch::StreamEscrowTicket::new(
        Arc::clone(&sink) as Arc<dyn crate::context::outlets::dispatch::StreamEscrowRefundSink>,
        context_id.clone(),
        member.clone(),
        scp_protocol::economy::types::Amount::new(50),
    );

    let spawner = supervisor
        .tracked_spawner("release test")
        .expect("an open gate issues a spawner");
    let tracked_before = supervisor.task_tracker.len();

    // One poll spawns the reversal and parks on its join handle, which
    // this single-threaded runtime cannot complete mid-poll; the future is
    // then dropped.
    let release = supervisor.release_stream_escrow(&spawner, ticket, &context_id, &member);
    assert!(
        futures::FutureExt::now_or_never(release).is_none(),
        "the release waits for the reversal task"
    );
    assert_eq!(
        supervisor.task_tracker.len(),
        tracked_before + 1,
        "the reversal runs as a tracked task that outlives the dropped release"
    );
    // The spawner's token leaves the count; the reversal task leaves it
    // once it has run.
    drop(spawner);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while supervisor.task_tracker.len() >= tracked_before {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the reversal task runs to completion");
    let (tx, rx) = tokio::sync::oneshot::channel();
    supervisor
        .dispatch_query(QueriesCommand::RemainingBudgetForTest {
            context_id: context_id.clone(),
            member_did: member.clone(),
            reply: tx,
        })
        .await
        .expect("dispatch RemainingBudgetForTest");
    assert_eq!(
        rx.await.expect("budget reply").expect("budget ok"),
        scp_protocol::economy::types::Amount::new(100),
        "the reversal reached the actor and returned the hold"
    );
    assert_eq!(
        sink.0.load(Ordering::SeqCst),
        0,
        "a dropped release must not refund the hold a second time"
    );
}

/// After shutdown has begun, an unconsumed escrow ticket that an untracked
/// caller drops still reverses its hold through the open's spawner
/// (ADR-049 Decision 16, item 2), and the reversal returns exactly the
/// ticket's amount.
#[tokio::test]
async fn escrow_ticket_dropped_after_shutdown_began_refunds_through_the_spawner() {
    async fn remaining(supervisor: &Arc<Supervisor>, context_id: &str, member: &DID) -> u64 {
        let (tx, rx) = tokio::sync::oneshot::channel();
        supervisor
            .dispatch_query(QueriesCommand::RemainingBudgetForTest {
                context_id: context_id.to_owned(),
                member_did: member.clone(),
                reply: tx,
            })
            .await
            .expect("dispatch RemainingBudgetForTest");
        rx.await.expect("budget reply").expect("budget ok").value()
    }

    let supervisor = supervisor_with_providers();
    let member = DID("did:example:live-admin".to_owned());
    let deps = test_actor_deps(&supervisor).await;
    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        [0x5f; 32],
        1_700_000_000,
        member.clone(),
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .expect("drive live context to Active");
    // Two open-time holds of 25 each: 50 of 100 spent.
    state
        .governance
        .budget_tracker
        .grant(&member, scp_protocol::economy::types::Amount::new(100));
    state
        .governance
        .budget_tracker
        .record_spend(&member, scp_protocol::economy::types::Amount::new(50))
        .expect("the grant covers the holds");
    supervisor
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn registers the live context");
    let context_id = hex::encode([0x5f; 32]);
    let spawner = supervisor
        .tracked_spawner("refund test")
        .expect("an open gate issues a spawner");
    let ticket = |sink: Arc<dyn crate::context::outlets::dispatch::StreamEscrowRefundSink>| {
        crate::context::outlets::dispatch::StreamEscrowTicket::new(
            sink,
            context_id.clone(),
            member.clone(),
            scp_protocol::economy::types::Amount::new(25),
        )
    };
    let through_spawner = ticket(Arc::new(SpawnerEscrowRefundSink::new(
        &supervisor,
        &spawner,
    )));

    supervisor.close_spawn_gate();
    assert_eq!(
        remaining(&supervisor, &context_id, &member).await,
        50,
        "no refund runs before the ticket drops"
    );

    drop(through_spawner);
    drop(spawner);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while remaining(&supervisor, &context_id, &member).await != 75 {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the refund through the spawner returns its hold");
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        remaining(&supervisor, &context_id, &member).await,
        75,
        "the refund through the spawner ran once"
    );
}

/// Build a VALIDLY-signed full-scope export for `context_id` whose
/// roster contains exactly `owning_member`. Signed by `signing_key`;
/// verifies under its public half.
async fn signed_import_export_with_member(
    context_id: &str,
    creator: &str,
    owning_member: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> crate::context::export_import::ContextExport {
    use ed25519_dalek::Signer;
    let mut snapshot = import_test_snapshot(context_id, creator);
    // A fresh DID guarantees the member is NOT already in
    // `key_package_stores`.
    snapshot
        .membership
        .add_member(DID(owning_member.to_owned()), "member".to_owned(), vec![]);
    // Event-log bytes keyed via the canonical ADR-056 resolver — the
    // same chokepoint `import_context` uses — so the recomputed Merkle
    // root matches what the importer derives. The caller passes a real
    // 64-hex id; the raw primitive would double-hash it and diverge.
    let ctx_id_bytes = crate::context::state::context_id_to_bytes(context_id);
    let event_log_data =
        create_event_log_data(&ctx_id_bytes, &[scp_event_log::EventType::ContextCreated]).await;
    crate::context::export_import::create_export(
        snapshot,
        event_log_data,
        DID(creator.to_owned()),
        crate::context::export_import::ExportScope::Full,
        &scp_clock::SystemClock,
        |hash: &[u8; 32]| Ok::<_, scp_crypto::CustodyFailure>(signing_key.sign(hash).to_bytes()),
    )
    .expect("build a valid signed export")
}

/// A VALID import that is REJECTED post-verification (live-context
/// overwrite) must evict the key-package store IT newly spawned —
/// no orphaned actor/entry is left behind. This is the eviction
/// branch the forged-import test cannot reach (there the store is
/// never spawned).
#[tokio::test]
async fn rejected_import_evicts_only_its_newly_spawned_kp_store() {
    let supervisor = supervisor_with_providers();
    let ctx_id_bytes = [0x5Au8; 32];
    let context_id = spawn_live_context(&supervisor, ctx_id_bytes).await;

    let creator = "did:key:evict-test-creator";
    // The import acts as the node identity, whose store is not
    // pre-seeded, so the import arm newly spawns it, then evicts it on
    // the live-context rejection. The roster member selects nothing.
    let owning_member = "did:key:aaa-evict-owning-member";
    let node_did = supervisor.node_identity().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let verifying_key = signing_key.verifying_key();

    let export =
        signed_import_export_with_member(&context_id, creator, owning_member, &signing_key).await;

    // Baseline: `spawn_live_context` builds deps for a test DID, so
    // the map already holds that store. The node identity's store must
    // NOT yet exist — the import is what spawns it.
    let baseline = supervisor.key_package_stores.len();
    assert!(
        !supervisor.key_package_stores.contains_key(&node_did),
        "the node identity's key-package store must not exist before the import"
    );

    let result = supervisor
        .import_context(export, &verifying_key, None)
        .await;

    // Live-context-overwrite rejection propagates from
    // `import_context`.
    assert!(
        matches!(result, Err(ContextError::MembershipFailed(_))),
        "import over a live context must be rejected, got {result:?}"
    );
    // The store this import spawned for the node identity must have
    // been evicted on the failure path (no orphan), and none was ever
    // spawned for the roster member.
    assert!(
        !supervisor.key_package_stores.contains_key(&node_did),
        "the newly-spawned key-package store must be evicted on a rejected import"
    );
    assert!(
        !supervisor
            .key_package_stores
            .contains_key(&DID(owning_member.to_owned())),
        "a roster member never selects the import's identity"
    );
    // No net change to the store map: the only store the import
    // touched was the one it spawned, and that was evicted.
    assert_eq!(
        supervisor.key_package_stores.len(),
        baseline,
        "a rejected import must leave the key-package-store count unchanged (no orphan)"
    );
}

/// A rejected import must NOT tear down a PRE-EXISTING key-package
/// store shared with other contexts/identities: eviction is gated
/// on `kp_store_newly_spawned`, so when the owning store already
/// exists the rejection leaves it intact. This guards the invariant
/// the TOCTOU fix protects — a concurrent import's failure can never
/// evict a store another op is using.
#[tokio::test]
async fn rejected_import_preserves_preexisting_kp_store() {
    let supervisor = supervisor_with_providers();
    let ctx_id_bytes = [0x6Bu8; 32];
    let context_id = spawn_live_context(&supervisor, ctx_id_bytes).await;

    let creator = "did:key:preserve-test-creator";
    let owning_member = "did:key:aaa-preserve-owning-member";
    let owning_did = supervisor.node_identity().unwrap();

    // Pre-seed the node identity's key-package store, simulating a
    // store already in use by another context/import. The rejected
    // import below must NOT evict it.
    let preexisting = supervisor
        .key_package_store_for_loaded(&owning_did)
        .await
        .expect("kp store resolves with providers");
    assert!(
        supervisor.key_package_stores.contains_key(&owning_did),
        "pre-seeded store registered"
    );
    let baseline = supervisor.key_package_stores.len();

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let export =
        signed_import_export_with_member(&context_id, creator, owning_member, &signing_key).await;

    let result = supervisor
        .import_context(export, &verifying_key, None)
        .await;
    assert!(
        matches!(result, Err(ContextError::MembershipFailed(_))),
        "import over a live context must be rejected, got {result:?}"
    );
    // The pre-existing store must survive — `kp_store_newly_spawned`
    // was false, so the eviction branch is skipped.
    assert!(
        supervisor.key_package_stores.contains_key(&owning_did),
        "a pre-existing/shared key-package store must NOT be torn down by a rejected import"
    );
    assert_eq!(
        supervisor.key_package_stores.len(),
        baseline,
        "no second actor spawned and none evicted; the pre-seeded store remains"
    );
    preexisting
        .send_shutdown()
        .await
        .expect("pre-existing store handle is still live after the rejected import");
}

/// SECURITY (§5.3.2, §19.3): a Full export whose `pending_economic_policy_change`
/// has a BACKDATED `observed_at` (and backdated `effective_at`) MUST NOT be
/// immediately effective on import. `import_context` re-pins `observed_at` to
/// the importing member's local clock, so the non-backdatable notification
/// window restarts from import time. Without the re-pin, a malicious exporter
/// who signs a backdated `observed_at` collapses the window to zero and the
/// policy applies on the first apply tick — exactly the bypass this guards.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_repins_observed_at_so_backdated_pending_change_is_not_effective() {
    use crate::context::state::ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS;
    use ed25519_dalek::Signer;
    use scp_protocol::economy::types::{Amount, CostSchedule, CurrencyCode, EconomicPolicy};

    // Deterministic import-time clock.
    const IMPORT_TIME: u64 = 1_700_000_000;
    let clock = Arc::new(TestClock::new(IMPORT_TIME));
    let clock_dyn: Arc<dyn Clock> = clock.clone();
    let supervisor =
        supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

    let creator = "did:key:repin-test-creator";
    let context_id = "repin-observed-at-ctx";
    let mut snapshot = import_test_snapshot(context_id, creator);

    // Attacker backdates BOTH the convergent `effective_at` AND the
    // non-backdatable floor `observed_at` to the distant past. Installed
    // verbatim, `is_effective(IMPORT_TIME + 1)` would be true (window
    // collapsed). `effective_at` is well below import time too, so only the
    // re-pinned floor keeps the change pending.
    let backdated = IMPORT_TIME - 10 * ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS;
    let policy = EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: CurrencyCode(*b"USD\0"),
            per_message: Some(Amount(1)),
            per_outlet_call: None,
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec!["test".to_owned()],
        pricing_formula: None,
        payee: DID("did:dht:z6MkPayee".to_owned()),
    };
    snapshot.pending_economic_policy_change =
        Some(crate::context::state::PendingEconomicPolicyChange {
            new_policy: policy,
            notified_at: backdated,
            effective_at: backdated + ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS,
            observed_at: backdated,
            proposal_id: [0u8; 32],
        });

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let verifying_key = signing_key.verifying_key();
    // Empty event-log data: `recompute_event_log_root([])` is `[0u8; 32]`,
    // which matches `import_test_snapshot`'s signed `event_log_merkle_root`
    // so the Merkle-binding check passes and the import succeeds.
    let export = crate::context::export_import::create_export(
        snapshot,
        Vec::new(),
        DID(creator.to_owned()),
        crate::context::export_import::ExportScope::Full,
        &scp_clock::SystemClock,
        |hash: &[u8; 32]| Ok::<_, scp_crypto::CustodyFailure>(signing_key.sign(hash).to_bytes()),
    )
    .expect("build a valid signed full export");

    // Fresh import (no live context for this id) — succeeds.
    supervisor
        .import_context(export, &verifying_key, None)
        .await
        .expect("a valid signed full export imports successfully");

    // At import_time + 1: the re-pinned floor is `IMPORT_TIME +
    // ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS`, so the change is NOT yet
    // effective despite the backdated `effective_at`. Without the re-pin
    // this apply would return `true`.
    let applied_early = {
        let (tx, rx) = tokio::sync::oneshot::channel();
        supervisor
                .dispatch_governance_command(
                    crate::context::actor::commands::GovernanceCommand::ApplyPendingEconomicPolicyChange {
                        context_id: context_id.to_owned(),
                        current_timestamp: IMPORT_TIME + 1,
                        reply: tx,
                    },
                )
                .await
                .expect("apply dispatch routes to the imported actor");
        rx.await.expect("apply handler replies").expect("apply ok")
    };
    assert!(
        !applied_early,
        "a backdated pending economic-policy change MUST NOT be effective just after import \
             — `observed_at` is re-pinned to local import time, restarting the §19.3 window"
    );

    // At import_time + PERIOD: the re-pinned window has elapsed, so the
    // change now applies. This proves the re-pin restarts (does not destroy)
    // the window.
    let applied_after_period = {
        let (tx, rx) = tokio::sync::oneshot::channel();
        supervisor
                .dispatch_governance_command(
                    crate::context::actor::commands::GovernanceCommand::ApplyPendingEconomicPolicyChange {
                        context_id: context_id.to_owned(),
                        current_timestamp: IMPORT_TIME
                            + ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS
                            + 1,
                        reply: tx,
                    },
                )
                .await
                .expect("apply dispatch routes to the imported actor");
        rx.await.expect("apply handler replies").expect("apply ok")
    };
    assert!(
        applied_after_period,
        "the change MUST become effective once the re-pinned notification window \
             (import_time + PERIOD) has elapsed"
    );
}

/// Builds Merkle event-log bytes with a `ContextCreated` genesis followed by
/// a `TtlExtended` leaf carrying `extended_deadline_unix` — a COMPLETE
/// history recording a valid TTL extension, for the M3 import tests.
async fn create_event_log_data_with_extension(
    context_id_bytes: &[u8; 32],
    extended_deadline_unix: u64,
) -> Vec<u8> {
    use crate::context::builder::ContextEventLogProvider;
    let provider = crate::context::providers::event_log::MerkleEventLogProvider::new();
    provider.init_event_log(context_id_bytes).await.unwrap();
    provider
        .append_event(
            context_id_bytes,
            scp_event_log::EventType::ContextCreated,
            "",
            scp_event_log::EventPayload::default(),
            1_700_000_000,
        )
        .await
        .unwrap();
    let payload =
        scp_event_log::payload::encode_payload(&scp_event_log::payload::TtlExtendedPayload {
            old_deadline_unix: 0,
            new_deadline_unix: extended_deadline_unix,
            proposal_id: [0u8; 32],
            consenting_members: Vec::new(),
        })
        .unwrap();
    provider
        .append_event(
            context_id_bytes,
            scp_event_log::EventType::TtlExtended,
            "",
            payload,
            1_700_000_000,
        )
        .await
        .unwrap();
    provider.export_event_log_entries(context_id_bytes).unwrap()
}

/// A supervisor with a caller-supplied clock + persistence AND the REAL
/// [`MerkleEventLogProvider`](crate::context::providers::event_log::MerkleEventLogProvider)
/// (which supports event-log import) so the M3 import tests can import a
/// full export whose `event_log_data` is non-empty.
fn supervisor_with_clock_persistence_and_merkle_log(
    clock: Arc<dyn Clock>,
    persistence: Box<dyn ContextPersistence>,
) -> Arc<Supervisor> {
    let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
        "did:dht:z6MktestM3Import".to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
        Box::new(crate::context::builder::NotConfiguredTransportProvider);
    let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
        Box::new(crate::context::providers::event_log::MerkleEventLogProvider::new());
    let key_resolver: KeyResolver = Arc::new(|_: &DID, _: scp_did::SigningKeyId| None);
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            InMemoryStorage::new(),
        )),
    );
    Supervisor::with_providers(
        crypto,
        transport,
        event_log,
        key_resolver,
        Some(persistence),
        None,
        None,
        Some(clock),
        mls_storage,
        crate::domain_handlers(),
    )
}

/// M3 (import ignores an over-long scalar, derives the prune-immune base —
/// REGRESSION GATE, prune-safe rewrite): a validly SIGNED export with a
/// Merkle-valid log `[ContextCreated]` (no extension), `params.ttl = 1h`, but a
/// persisted `ttl_deadline_secs = creation + 1yr` (a malicious exporter
/// smuggling a window extension) must arm `creation + 1h` on import — the
/// over-long persisted scalar is NEVER read.
///
/// The redesign dissolves this attack class WITHOUT a clamp: the deadline base
/// is the prune-immune, creator-signed `snapshot.creation_timestamp_secs +
/// params.ttl` (= `creation + 1h`, no `TtlExtended` leaf to raise it), so the
/// attacker-controlled `ttl_deadline_secs` scalar cannot extend the window
/// (§7.3.1 / §9.9.3). `creation_timestamp_secs` is itself rejected if
/// future-dated (E3), so the base cannot be smuggled long either. The context
/// expires at `creation + 1h`.
#[tokio::test(start_paused = true)]
async fn import_ignores_over_long_scalar_derives_from_log() {
    const T0: u64 = 1_700_000_000;
    const TTL_SECS: u64 = 3_600; // 1h
    const ONE_YEAR: u64 = 31_536_000;

    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(T0));
    let persistence = MapPersistence::default();
    let sup =
        supervisor_with_clock_persistence_and_merkle_log(clock_dyn, Box::new(persistence.clone()));

    let creator = "did:key:m3-clamp-creator";
    let context_id = "m3-clamp-over-long-ctx";
    let ctx_id_bytes = crate::context::state::context_id_to_bytes(context_id);

    let mut snapshot = import_test_snapshot(context_id, creator);
    snapshot.context_params.ttl = Some(std::time::Duration::from_secs(TTL_SECS));
    // Attacker signs an over-long deadline far beyond `creation + ttl`.
    snapshot.ttl_deadline_secs = Some(T0 + ONE_YEAR);

    // COMPLETE history (genesis present) with NO extension leaf.
    let event_log_data =
        create_event_log_data(&ctx_id_bytes, &[scp_event_log::EventType::ContextCreated]).await;

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let export = crate::context::export_import::create_export(
        snapshot,
        event_log_data,
        DID(creator.to_owned()),
        crate::context::export_import::ExportScope::Full,
        &scp_clock::SystemClock,
        |hash: &[u8; 32]| {
            use ed25519_dalek::Signer;
            Ok::<_, scp_crypto::CustodyFailure>(signing_key.sign(hash).to_bytes())
        },
    )
    .expect("build a valid signed full export");

    sup.import_context(export, &verifying_key, None)
        .await
        .expect("a valid signed export imports successfully");

    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        sup.read_context_state(context_id).await,
        Some(crate::context::ContextState::Active),
        "the imported context is Active before its snapshot-base deadline"
    );

    // Advance PAST the snapshot-base `creation + ttl` (T0 + 3600) but FAR
    // before the persisted `creation + 1yr`: an arm off the over-long scalar
    // would still be Active here; the prune-immune snapshot-base arm fires and
    // (fail-closed) transitions to Expired.
    tokio::time::advance(std::time::Duration::from_secs(TTL_SECS + 1)).await;
    let mut expired = false;
    for _ in 0..128 {
        if matches!(
            sup.read_context_state(context_id).await,
            Some(crate::context::ContextState::Expired) | None
        ) {
            expired = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        expired,
        "import must arm the prune-immune snapshot base creation+ttl (ignoring the \
             over-long scalar) and expire (M3); pre-fix it armed creation+1yr and stayed Active"
    );
}

/// E3 (import rejects a future-dated creation timestamp — REGRESSION GATE): a
/// validly SIGNED export whose `creation_timestamp_secs` is dated FAR beyond
/// the importer's clock is MALFORMED — a malicious creator future-dating their
/// OWN creation instant to smuggle a long absolute key-destruction deadline
/// (`future + ttl`) via the prune-immune create base. The import must be
/// REJECTED fail-closed at the boundary (before any poisoned base is
/// persisted), NOT clamped in memory (pass-4d's clamp was reversed on the next
/// restart). This is the durable base-future-dating fix (ADR-049 §9).
///
/// F2 (the reject is SIDE-EFFECT-FREE): the future-date gate is hoisted to the
/// TOP of `import_context` — ABOVE `restore_crypto_state_with_floor_guard`
/// (installs the MLS group + sets the replay floor) and
/// `import_event_log_data` (persists the foreign log). This test additionally
/// asserts the rejected import leaves NO persisted foreign event log; before
/// the hoist, the reject ran AFTER `import_event_log_data`, orphaning the
/// foreign `ContextCreated` leaf (and, with a non-empty crypto blob, a resident
/// group + a replay floor pinned from the future-dated epoch that could
/// floor-reject a later LEGITIMATE re-import — griefing/DoS).
#[tokio::test]
async fn import_rejects_future_dated_creation_timestamp() {
    const T0: u64 = 1_700_000_000;
    const TTL_SECS: u64 = 3_600;
    const ONE_YEAR: u64 = 31_536_000;

    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(T0));
    let persistence = MapPersistence::default();
    let sup =
        supervisor_with_clock_persistence_and_merkle_log(clock_dyn, Box::new(persistence.clone()));

    let creator = "did:key:e3-future-creator";
    let context_id = "e3-future-dated-ctx";
    let ctx_id_bytes = crate::context::state::context_id_to_bytes(context_id);

    let mut snapshot = import_test_snapshot(context_id, creator);
    snapshot.context_params.ttl = Some(std::time::Duration::from_secs(TTL_SECS));
    // Malicious: creation instant dated a year into the importer's future — a
    // `creation + ttl` base a year+1h out.
    snapshot.creation_timestamp_secs = T0 + ONE_YEAR;

    let event_log_data =
        create_event_log_data(&ctx_id_bytes, &[scp_event_log::EventType::ContextCreated]).await;

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let export = crate::context::export_import::create_export(
        snapshot,
        event_log_data,
        DID(creator.to_owned()),
        crate::context::export_import::ExportScope::Full,
        &scp_clock::SystemClock,
        |hash: &[u8; 32]| {
            use ed25519_dalek::Signer;
            Ok::<_, scp_crypto::CustodyFailure>(signing_key.sign(hash).to_bytes())
        },
    )
    .expect("build a valid signed full export");

    let result = sup.import_context(export, &verifying_key, None).await;
    assert!(
        result.is_err(),
        "a future-dated creation_timestamp_secs must be rejected fail-closed (E3)"
    );
    // No poisoned base persisted: the rejected import leaves no resident actor.
    assert!(
        sup.lookup(context_id).is_none(),
        "a rejected future-dated import must not leave a resident actor"
    );
    // F2: the reject is SIDE-EFFECT-FREE — the foreign event log was NOT
    // persisted. Before the hoist, `import_event_log_data` ran before the
    // reject and orphaned the foreign `ContextCreated` leaf.
    let persisted_log = sup
        .event_log_entries(&ctx_id_bytes)
        .expect("event-log query succeeds");
    assert!(
        persisted_log.is_none_or(|entries| entries.is_empty()),
        "a rejected future-dated import must not persist the foreign event log (F2)"
    );
}

// -----------------------------------------------------------------
// Spec 05 §5.13.3 rule 9: import and restore install the committed T0.
// -----------------------------------------------------------------

/// The importer's and restorer's clock, and the creation timestamp the
/// rule-9 fixtures record.
const RULE9_T0: u64 = 1_700_000_000;

/// The sender whose epoch floor every keyed rule-9 fixture carries, so a
/// replay-floor merge from it shows up in the Supervisor's registry.
const RULE9_FLOOR_SENDER: &str = "did:key:rule9-floor-sender";

/// The epoch floor the keyed rule-9 fixtures carry for `RULE9_FLOOR_SENDER`.
const RULE9_FLOOR_EPOCH: u64 = 7;

/// How the rule-9 fixture's group commits `creation_timestamp_secs`.
enum CommittedT0 {
    /// The extension commits this value.
    Value(u64),
    /// The extension omits the field.
    Omitted,
}

/// A rule-9 snapshot of `context_id`, created by `creator` at `RULE9_T0`
/// under `params`, whose `mls_crypto_state` (when `committed` is `Some`) is
/// a group born on `sup`'s crypto with an `0xFF02` extension committing
/// `committed`. `None` yields a keyless (needs-reconnect) snapshot.
fn rule9_snapshot(
    sup: &Arc<Supervisor>,
    context_id: &str,
    creator: &str,
    params: &scp_protocol::context::ContextParams,
    committed: Option<CommittedT0>,
) -> crate::context::state::ContextSnapshot {
    let mut snapshot = import_test_snapshot(context_id, creator);
    snapshot.context_params = params.clone();
    snapshot.creation_timestamp_secs = RULE9_T0;
    snapshot.routing = crate::context::actor::state::ContextRouting::for_mode(false, [0x5a; 32]);
    let Some(committed) = committed else {
        return snapshot;
    };
    let honest = scp_protocol::context::ScpContextExtension::for_root(
        scp_protocol::context::ScpContextGenesis {
            context_id: context_id.to_owned(),
            creator_did: DID(creator.to_owned()),
            creation_timestamp_secs: RULE9_T0,
            mode: params.mode,
            governance: &params.governance,
            ceiling_policy: params.ceiling_policy,
            ceiling: &scp_protocol::context::roles::CapabilityCeiling::new(params.ceiling.clone()),
        },
    )
    .expect("honest extension");
    let mut json = serde_json::to_value(&honest).expect("extension to JSON");
    let fields = json.as_object_mut().expect("extension is a JSON object");
    match committed {
        CommittedT0::Value(t0) => {
            fields.insert("creation_timestamp_secs".to_owned(), t0.into());
        }
        CommittedT0::Omitted => {
            fields.remove("creation_timestamp_secs");
        }
    }
    let crypto = sup.crypto_ref().expect("test supervisor has crypto");
    let owned = crypto
        .create_mls_group_with_raw_context_params(
            serde_json::to_vec(&json).expect("extension bytes"),
            scp_protocol::crypto::sender_keys::generate_wrapping_keypair()
                .0
                .as_bytes(),
        )
        .expect("birth the fixture group");
    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        crate::context::state::context_id_to_bytes(context_id),
        RULE9_T0,
        DID::from(crypto.local_did().to_owned()),
    );
    state.seed_encrypted_crypto_from_owned(owned);
    snapshot.mls_crypto_state = crate::context::state::MlsCryptoState(
        state
            .export_crypto_state(
                vec![(RULE9_FLOOR_SENDER.to_owned(), RULE9_FLOOR_EPOCH)],
                Vec::new(),
            )
            .expect("export the fixture group"),
    );
    snapshot
}

/// A signed full export of `snapshot`, with a one-leaf event log, and the
/// key that verifies it.
async fn rule9_export(
    snapshot: crate::context::state::ContextSnapshot,
) -> (
    crate::context::export_import::ContextExport,
    ed25519_dalek::VerifyingKey,
) {
    let ctx_id_bytes = crate::context::state::context_id_to_bytes(&snapshot.context_id);
    let creator = snapshot.role_state.creator_did.clone();
    let event_log_data =
        create_event_log_data(&ctx_id_bytes, &[scp_event_log::EventType::ContextCreated]).await;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[19u8; 32]);
    let export = crate::context::export_import::create_export(
        snapshot,
        event_log_data,
        DID(creator),
        crate::context::export_import::ExportScope::Full,
        &scp_clock::SystemClock,
        |hash: &[u8; 32]| {
            use ed25519_dalek::Signer;
            Ok::<_, scp_crypto::CustodyFailure>(signing_key.sign(hash).to_bytes())
        },
    )
    .expect("build a valid signed full export");
    (export, signing_key.verifying_key())
}

/// The rule-9 context parameters: an hourly interval policy and a five-hour
/// TTL, so a deadline counted from `RULE9_T0` still lies ahead of a clock at
/// `RULE9_T0 + 9_000`.
fn rule9_params() -> scp_protocol::context::ContextParams {
    scp_protocol::context::ContextParams {
        ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
        pseudonym_rotation: Some(scp_protocol::context::params::PseudonymRotationPolicy {
            interval_secs: Some(3_600),
            on_membership_change: false,
        }),
        ttl: Some(std::time::Duration::from_secs(RULE9_TTL_SECS)),
        ..Default::default()
    }
}

/// The rule-9 TTL.
const RULE9_TTL_SECS: u64 = 18_000;

/// Imports a rule-9 export whose group commits `committed`, and asserts the
/// import is refused with a reason naming `reason_part`, leaving no actor
/// and no persisted snapshot.
async fn assert_import_refuses_committed_t0(seed: u8, committed: CommittedT0, reason_part: &str) {
    let persistence = MapPersistence::default();
    let contexts = Arc::clone(&persistence.contexts);
    let sup = supervisor_with_clock_persistence_and_merkle_log(
        Arc::new(TestClock::new(RULE9_T0)),
        Box::new(persistence),
    );
    let context_id = hex::encode([seed; 32]);
    let snapshot = rule9_snapshot(
        &sup,
        &context_id,
        "did:key:rule9-import-creator",
        &rule9_params(),
        Some(committed),
    );
    let (export, verifying_key) = rule9_export(snapshot).await;
    let err = sup
        .import_context(export, &verifying_key, None)
        .await
        .expect_err("the import must be refused");
    let ContextError::ImportRejected { reason } = &err else {
        panic!("expected ImportRejected, got {err:?}");
    };
    assert!(
        reason.contains("context import refused") && reason.contains(reason_part),
        "{reason}"
    );
    assert!(
        sup.lookup(&context_id).is_none(),
        "no actor may be registered"
    );
    assert!(contexts.is_empty(), "no snapshot may be persisted");
    assert!(
        sup.export_sender_key_epochs(&crate::context::state::context_id_to_bytes(&context_id))
            .is_empty(),
        "a refused import must merge no replay floor into the registry"
    );
}

#[tokio::test]
async fn import_refuses_an_extension_without_a_creation_timestamp() {
    assert_import_refuses_committed_t0(0x91, CommittedT0::Omitted, "creation_timestamp_secs").await;
}

#[tokio::test]
async fn import_refuses_a_committed_creation_timestamp_above_two_to_the_53_minus_one() {
    assert_import_refuses_committed_t0(
        0x92,
        CommittedT0::Value(scp_protocol::context::MAX_CREATION_TIMESTAMP_SECS + 1),
        "exceeds 2^53 - 1",
    )
    .await;
}

#[tokio::test]
async fn import_refuses_a_committed_creation_timestamp_beyond_the_future_bound() {
    assert_import_refuses_committed_t0(
        0x93,
        CommittedT0::Value(
            RULE9_T0 + scp_protocol::context::CREATION_TIMESTAMP_FUTURE_BOUND_SECS + 1,
        ),
        "lies more than 300 s",
    )
    .await;
}

#[tokio::test]
async fn import_refuses_a_snapshot_whose_creation_timestamp_differs_from_the_committed_one() {
    assert_import_refuses_committed_t0(
        0x94,
        CommittedT0::Value(RULE9_T0 - 60),
        "the snapshot records creation timestamp",
    )
    .await;
}

/// §5.13.3 rule 9 checked before any side effect: an import whose snapshot
/// records a creation timestamp other than the committed `T0` is refused
/// before the replay-floor merge, so the registry holds no floor for the
/// context afterwards although the export carries one.
#[tokio::test]
async fn a_refused_import_merges_no_replay_floor() {
    let sup = supervisor_with_clock_persistence_and_merkle_log(
        Arc::new(TestClock::new(RULE9_T0)),
        Box::new(MapPersistence::default()),
    );
    let context_id = hex::encode([0x97; 32]);
    let ctx_id_bytes = crate::context::state::context_id_to_bytes(&context_id);
    let snapshot = rule9_snapshot(
        &sup,
        &context_id,
        "did:key:rule9-import-creator",
        &rule9_params(),
        Some(CommittedT0::Value(RULE9_T0 - 60)),
    );
    let (export, verifying_key) = rule9_export(snapshot).await;
    let err = sup
        .import_context(export, &verifying_key, None)
        .await
        .expect_err("a T0 mismatch must be refused");
    assert!(
        matches!(&err, ContextError::ImportRejected { reason }
                if reason.contains("the snapshot records creation timestamp")),
        "expected the rule-9 refusal, got {err:?}"
    );
    assert_eq!(
        sup.export_sender_key_epochs(&ctx_id_bytes),
        Vec::<(String, u64)>::new(),
        "the refused import must leave the registry's replay floors unchanged"
    );
}

/// §5.13.3 rule 9 checked before any side effect: an import over a
/// replaceable (Closing) prior actor that is refused for a `T0` mismatch
/// never reaches `PrepareForReplace`, so the prior actor stays registered
/// and keeps answering, and the registry holds no floor from the export.
#[tokio::test]
async fn a_refused_import_leaves_a_replaceable_prior_actor_live() {
    let sup = supervisor_with_clock_persistence_and_merkle_log(
        Arc::new(TestClock::new(RULE9_T0)),
        Box::new(MapPersistence::default()),
    );
    let context_id = hex::encode([0x98; 32]);
    let ctx_id_bytes = crate::context::state::context_id_to_bytes(&context_id);
    let prior = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        RULE9_T0,
        DID("did:example:rule9-prior-admin".to_owned()),
    );
    prior
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .expect("drive the prior context to Active");
    prior
        .handle
        .transition_to(&crate::context::ContextState::Closing)
        .expect("drive the prior context to Closing, which an import may replace");
    let deps = test_actor_deps(&sup).await;
    let prior_handle = sup
        .spawn_actor_with_state(prior, deps, None)
        .await
        .expect("spawn registers the prior context");

    let snapshot = rule9_snapshot(
        &sup,
        &context_id,
        "did:key:rule9-import-creator",
        &rule9_params(),
        Some(CommittedT0::Value(RULE9_T0 - 60)),
    );
    let (export, verifying_key) = rule9_export(snapshot).await;
    let err = sup
        .import_context(export, &verifying_key, None)
        .await
        .expect_err("a T0 mismatch must be refused");
    assert!(
        matches!(&err, ContextError::ImportRejected { reason }
                if reason.contains("the snapshot records creation timestamp")),
        "expected the rule-9 refusal, got {err:?}"
    );
    assert!(
        sup.lookup(&context_id).is_some(),
        "the refused import must not despawn the prior actor"
    );
    let member_count: Result<Option<usize>, ContextError> = prior_handle
        .send(|reply| {
            ContextCommand::Queries(QueriesCommand::MemberCount {
                context_id: context_id.clone(),
                reply,
            })
        })
        .await;
    assert!(
        member_count.is_ok(),
        "the prior actor must not have claimed itself terminal, got {member_count:?}"
    );
    assert_eq!(
        sup.export_sender_key_epochs(&ctx_id_bytes),
        Vec::<(String, u64)>::new(),
        "the refused import must leave the registry's replay floors unchanged"
    );
}

/// Drops the stored snapshot of `context_id`, flushes `sup`'s live contexts,
/// and returns the TTL deadline the fresh snapshot records.
async fn persisted_ttl_deadline(
    sup: &Supervisor,
    contexts: &DashMap<String, crate::context::state::ContextSnapshot>,
    context_id: &str,
) -> u64 {
    contexts.remove(context_id);
    sup.flush_all_contexts().await.expect("flush");
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Some(deadline) = contexts
                .get(context_id)
                .and_then(|s| s.value().ttl_deadline_secs)
            {
                return deadline;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the TTL deadline is persisted")
}

/// §5.13.3 rule 9: a keyed import follows the interval schedule counted from
/// the committed `T0` and arms its TTL at `T0 + ttl`. The importer's clock
/// sits 2.5 intervals after `T0`, so the first v2 epoch is 2.
#[tokio::test]
async fn a_keyed_import_installs_the_committed_creation_timestamp() {
    let persistence = MapPersistence::default();
    let contexts = Arc::clone(&persistence.contexts);
    let sup = supervisor_with_clock_persistence_and_merkle_log(
        Arc::new(TestClock::new(RULE9_T0 + 9_000)),
        Box::new(persistence),
    );
    let context_id = hex::encode([0x95; 32]);
    let snapshot = rule9_snapshot(
        &sup,
        &context_id,
        "did:key:rule9-import-creator",
        &rule9_params(),
        Some(CommittedT0::Value(RULE9_T0)),
    );
    let (export, verifying_key) = rule9_export(snapshot).await;
    sup.import_context(export, &verifying_key, None)
        .await
        .expect("an honest keyed export imports");
    let ids = sup
        .local_routing_ids(&context_id)
        .await
        .expect("the imported context's routing ids");
    assert_eq!(ids.next_pseudonym_epoch, Some(2));
    assert_eq!(
        persisted_ttl_deadline(&sup, &contexts, &context_id).await,
        RULE9_T0 + RULE9_TTL_SECS
    );
}

/// §5.13.3 rule 9, keyless clause: a keyless import installs no `T0`, so
/// under an interval policy no rotation is admissible, and its local TTL
/// close uses the deadline its snapshot records (`creation + ttl`).
#[tokio::test]
async fn a_keyless_import_installs_no_creation_timestamp_and_keeps_its_snapshot_deadline() {
    let persistence = MapPersistence::default();
    let contexts = Arc::clone(&persistence.contexts);
    let sup = supervisor_with_clock_persistence_and_merkle_log(
        Arc::new(TestClock::new(RULE9_T0 + 9_000)),
        Box::new(persistence),
    );
    let context_id = hex::encode([0x96; 32]);
    let snapshot = rule9_snapshot(
        &sup,
        &context_id,
        "did:key:rule9-import-creator",
        &rule9_params(),
        None,
    );
    let (export, verifying_key) = rule9_export(snapshot).await;
    sup.import_context(export, &verifying_key, None)
        .await
        .expect("a keyless export imports");
    let ids = sup
        .local_routing_ids(&context_id)
        .await
        .expect("the imported context's routing ids");
    assert_eq!(ids.next_pseudonym_epoch, None);
    assert_eq!(
        persisted_ttl_deadline(&sup, &contexts, &context_id).await,
        RULE9_T0 + RULE9_TTL_SECS
    );
}

/// Persists a rule-9 snapshot of a fresh context whose group commits
/// `committed` (keyless when `None`), restores it, and returns the restore
/// outcome with the supervisor, the persisted map, the context id, and the
/// JSON of the snapshot as stored before the restore.
async fn rule9_restore(
    seed: u8,
    committed: Option<CommittedT0>,
    snapshot_t0: u64,
    clock_secs: u64,
) -> (
    Result<(), ContextError>,
    Arc<Supervisor>,
    Arc<DashMap<String, crate::context::state::ContextSnapshot>>,
    String,
    serde_json::Value,
) {
    let persistence = MapPersistence::default();
    let contexts = Arc::clone(&persistence.contexts);
    let sup = supervisor_with_clock_and_persistence(
        Arc::new(TestClock::new(clock_secs)),
        Box::new(persistence),
    );
    let context_id = hex::encode([seed; 32]);
    let mut snapshot = rule9_snapshot(
        &sup,
        &context_id,
        "did:key:rule9-restore-creator",
        &rule9_params(),
        committed,
    );
    snapshot.creation_timestamp_secs = snapshot_t0;
    let stored = serde_json::to_value(&snapshot).expect("snapshot to JSON");
    contexts.insert(context_id.clone(), snapshot);
    let handle = crate::context::ContextHandle::new(context_id.clone(), rule9_params());
    let result = sup.restore_context(&context_id, &handle).await;
    (result, sup, contexts, context_id, stored)
}

/// Restores a rule-9 snapshot whose group commits `committed`, and asserts
/// the restore is refused with a reason naming `reason_part`, leaving no
/// actor and the stored snapshot unchanged.
async fn assert_restore_refuses_committed_t0(
    seed: u8,
    committed: CommittedT0,
    snapshot_t0: u64,
    reason_part: &str,
) {
    let (result, sup, contexts, context_id, stored) =
        rule9_restore(seed, Some(committed), snapshot_t0, RULE9_T0).await;
    let err = result.expect_err("the restore must be refused");
    let ContextError::PersistenceFailed(reason) = &err else {
        panic!("expected PersistenceFailed, got {err:?}");
    };
    assert!(
        reason.contains("context restore refused") && reason.contains(reason_part),
        "{reason}"
    );
    assert!(
        sup.lookup(&context_id).is_none(),
        "no actor may be registered"
    );
    assert_eq!(contexts.len(), 1, "no other snapshot may be persisted");
    assert_eq!(
        serde_json::to_value(contexts.get(&context_id).expect("stored snapshot").value())
            .expect("snapshot to JSON"),
        stored,
        "the refused restore must not rewrite the stored snapshot"
    );
}

#[tokio::test]
async fn restore_refuses_an_extension_without_a_creation_timestamp() {
    assert_restore_refuses_committed_t0(
        0xA1,
        CommittedT0::Omitted,
        RULE9_T0,
        "creation_timestamp_secs",
    )
    .await;
}

#[tokio::test]
async fn restore_refuses_a_committed_creation_timestamp_above_two_to_the_53_minus_one() {
    assert_restore_refuses_committed_t0(
        0xA2,
        CommittedT0::Value(scp_protocol::context::MAX_CREATION_TIMESTAMP_SECS + 1),
        RULE9_T0,
        "exceeds 2^53 - 1",
    )
    .await;
}

#[tokio::test]
async fn restore_refuses_a_committed_creation_timestamp_beyond_the_future_bound() {
    let future = RULE9_T0 + scp_protocol::context::CREATION_TIMESTAMP_FUTURE_BOUND_SECS + 1;
    assert_restore_refuses_committed_t0(
        0xA3,
        CommittedT0::Value(future),
        future,
        "lies more than 300 s",
    )
    .await;
}

#[tokio::test]
async fn restore_refuses_a_snapshot_whose_creation_timestamp_differs_from_the_committed_one() {
    assert_restore_refuses_committed_t0(
        0xA4,
        CommittedT0::Value(RULE9_T0),
        RULE9_T0 + 60,
        "the snapshot records creation timestamp",
    )
    .await;
}

/// Counts `restore_event_log` and `init_event_log` calls; every call is a
/// success no-op.
#[derive(Clone, Default)]
struct EventLogHydrationCounter {
    hydrations: Arc<std::sync::atomic::AtomicUsize>,
}
#[async_trait::async_trait]
impl crate::context::builder::ContextEventLogProvider for EventLogHydrationCounter {
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
        self.hydrations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    async fn restore_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<
        crate::context::builder::EventLogRestore,
        scp_protocol::context::builder::ContextCreationError,
    > {
        self.hydrations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(crate::context::builder::EventLogRestore::Absent)
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

/// An event-log provider whose `restore_event_log` always fails, as a
/// stored log that does not load makes it fail.
struct FailingEventLogRestore;
#[async_trait::async_trait]
impl crate::context::builder::ContextEventLogProvider for FailingEventLogRestore {
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
    async fn restore_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<
        crate::context::builder::EventLogRestore,
        scp_protocol::context::builder::ContextCreationError,
    > {
        Err(
            scp_protocol::context::builder::ContextCreationError::EventLogFailed(
                "stored event log is misaligned".to_owned(),
            ),
        )
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

/// Spec 17 §17.3 "Merkle event log entries": a restore refused because the
/// stored event log does not load leaves the registry's replay floors
/// unchanged. The control restore, whose event log loads, merges the
/// snapshot's floor, so the snapshot carries one to merge.
#[tokio::test]
async fn a_restore_refused_by_the_event_log_merges_no_replay_floor() {
    let restore_with = |event_log: Box<dyn crate::context::builder::ContextEventLogProvider>| async move {
        let persistence = MapPersistence::default();
        let contexts = Arc::clone(&persistence.contexts);
        let sup = supervisor_with_clock_persistence_and_event_log(
            Arc::new(TestClock::new(RULE9_T0)),
            Box::new(persistence),
            event_log,
        );
        let context_id = hex::encode([0xA8; 32]);
        let snapshot = rule9_snapshot(
            &sup,
            &context_id,
            "did:key:rule9-restore-creator",
            &rule9_params(),
            Some(CommittedT0::Value(RULE9_T0)),
        );
        contexts.insert(context_id.clone(), snapshot);
        let handle = crate::context::ContextHandle::new(context_id.clone(), rule9_params());
        let result = sup.restore_context(&context_id, &handle).await;
        let floors =
            sup.export_sender_key_epochs(&crate::context::state::context_id_to_bytes(&context_id));
        (result, floors)
    };

    let (control, floors) = restore_with(Box::<EventLogHydrationCounter>::default()).await;
    control.expect("the control restore succeeds");
    assert_eq!(
        floors,
        vec![(RULE9_FLOOR_SENDER.to_owned(), RULE9_FLOOR_EPOCH)],
        "the control restore merges the snapshot's floor"
    );

    let (refused, floors) = restore_with(Box::new(FailingEventLogRestore)).await;
    let err = refused.expect_err("an event log that does not load refuses the restore");
    assert!(
        matches!(&err, ContextError::EventLogFailed(reason) if reason.contains("misaligned")),
        "expected the event-log refusal, got {err:?}"
    );
    assert_eq!(
        floors,
        Vec::<(String, u64)>::new(),
        "the refused restore must leave the registry's replay floors unchanged"
    );
}

/// §5.13.3 rule 9 checked before any side effect: a restore whose snapshot
/// records a creation timestamp other than the committed `T0` is refused
/// before the event log is hydrated and before the replay-floor merge.
#[tokio::test]
async fn a_refused_restore_hydrates_no_event_log_and_merges_no_replay_floor() {
    let persistence = MapPersistence::default();
    let contexts = Arc::clone(&persistence.contexts);
    let counter = EventLogHydrationCounter::default();
    let sup = supervisor_with_clock_persistence_and_event_log(
        Arc::new(TestClock::new(RULE9_T0)),
        Box::new(persistence),
        Box::new(counter.clone()),
    );
    let context_id = hex::encode([0xA7; 32]);
    let ctx_id_bytes = crate::context::state::context_id_to_bytes(&context_id);
    let mut snapshot = rule9_snapshot(
        &sup,
        &context_id,
        "did:key:rule9-restore-creator",
        &rule9_params(),
        Some(CommittedT0::Value(RULE9_T0)),
    );
    snapshot.creation_timestamp_secs = RULE9_T0 + 60;
    contexts.insert(context_id.clone(), snapshot);
    let handle = crate::context::ContextHandle::new(context_id.clone(), rule9_params());
    let err = sup
        .restore_context(&context_id, &handle)
        .await
        .expect_err("a T0 mismatch must be refused");
    assert!(
        matches!(&err, ContextError::PersistenceFailed(reason)
                if reason.contains("the snapshot records creation timestamp")),
        "expected the rule-9 refusal, got {err:?}"
    );
    assert_eq!(
        counter.hydrations.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the refused restore must leave the event log unhydrated"
    );
    assert_eq!(
        sup.export_sender_key_epochs(&ctx_id_bytes),
        Vec::<(String, u64)>::new(),
        "the refused restore must leave the registry's replay floors unchanged"
    );
}

/// §5.13.3 rule 9: a keyed restore follows the interval schedule counted
/// from the committed `T0` and arms its TTL at `T0 + ttl`.
#[tokio::test]
async fn a_keyed_restore_installs_the_committed_creation_timestamp() {
    let (result, sup, contexts, context_id, _) = rule9_restore(
        0xA5,
        Some(CommittedT0::Value(RULE9_T0)),
        RULE9_T0,
        RULE9_T0 + 9_000,
    )
    .await;
    result.expect("an honest keyed snapshot restores");
    let ids = sup
        .local_routing_ids(&context_id)
        .await
        .expect("the restored context's routing ids");
    assert_eq!(ids.next_pseudonym_epoch, Some(2));
    assert_eq!(
        persisted_ttl_deadline(&sup, &contexts, &context_id).await,
        RULE9_T0 + RULE9_TTL_SECS
    );
}

/// §5.13.3 rule 9, keyless clause: a keyless restore installs no `T0`, even
/// when its persisted rotation state holds one, and its local TTL close
/// uses the deadline its snapshot records.
#[tokio::test]
async fn a_keyless_restore_installs_no_creation_timestamp_and_keeps_its_snapshot_deadline() {
    let persistence = MapPersistence::default();
    let contexts = Arc::clone(&persistence.contexts);
    let sup = supervisor_with_clock_and_persistence(
        Arc::new(TestClock::new(RULE9_T0 + 9_000)),
        Box::new(persistence),
    );
    let context_id = hex::encode([0xA6; 32]);
    let mut snapshot = rule9_snapshot(
        &sup,
        &context_id,
        "did:key:rule9-restore-creator",
        &rule9_params(),
        None,
    );
    snapshot.pseudonym_rotation =
        crate::context::actor::pseudonym_rotation::PseudonymRotationState::anchored(
            rule9_params().pseudonym_rotation.as_ref(),
            Some(RULE9_T0),
            RULE9_T0,
        );
    contexts.insert(context_id.clone(), snapshot);
    let handle = crate::context::ContextHandle::new(context_id.clone(), rule9_params());
    sup.restore_context(&context_id, &handle)
        .await
        .expect("a keyless snapshot restores");
    let ids = sup
        .local_routing_ids(&context_id)
        .await
        .expect("the restored context's routing ids");
    assert_eq!(ids.next_pseudonym_epoch, None);
    assert_eq!(
        persisted_ttl_deadline(&sup, &contexts, &context_id).await,
        RULE9_T0 + RULE9_TTL_SECS
    );
}

/// M3 companion (a valid extension survives import, REGRESSION GATE): an
/// export whose history records a `TtlExtended` leaf pushing the deadline to
/// `creation + 2h` must arm the EXTENDED deadline on import — the fail-safe
/// extension term raises the prune-immune snapshot base, so a validly extended
/// deadline (`ttl_deadline_secs = creation + 2h`, `params.ttl = 1h`) survives
/// (preserves D2). The context must still be Active past `creation + 1h`.
#[tokio::test(start_paused = true)]
async fn import_preserves_extended_deadline_with_history() {
    const T0: u64 = 1_700_000_000;
    const TTL_SECS: u64 = 3_600; // 1h
    const EXTENDED_DEADLINE: u64 = T0 + 7_200; // creation + 2h

    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(T0));
    let persistence = MapPersistence::default();
    let sup =
        supervisor_with_clock_persistence_and_merkle_log(clock_dyn, Box::new(persistence.clone()));

    let creator = "did:key:m3-preserve-creator";
    let context_id = "m3-preserve-extended-ctx";
    let ctx_id_bytes = crate::context::state::context_id_to_bytes(context_id);

    let mut snapshot = import_test_snapshot(context_id, creator);
    snapshot.context_params.ttl = Some(std::time::Duration::from_secs(TTL_SECS));
    // The VALID extended deadline (within the log-recorded bound).
    snapshot.ttl_deadline_secs = Some(EXTENDED_DEADLINE);

    // COMPLETE history recording the extension to `creation + 2h`.
    let event_log_data =
        create_event_log_data_with_extension(&ctx_id_bytes, EXTENDED_DEADLINE).await;

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[10u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let export = crate::context::export_import::create_export(
        snapshot,
        event_log_data,
        DID(creator.to_owned()),
        crate::context::export_import::ExportScope::Full,
        &scp_clock::SystemClock,
        |hash: &[u8; 32]| {
            use ed25519_dalek::Signer;
            Ok::<_, scp_crypto::CustodyFailure>(signing_key.sign(hash).to_bytes())
        },
    )
    .expect("build a valid signed full export");

    sup.import_context(export, &verifying_key, None)
        .await
        .expect("a valid signed export imports successfully");

    for _ in 0..8 {
        tokio::task::yield_now().await;
    }

    // Advance PAST the un-extended `creation + ttl` (T0 + 3600) but BEFORE
    // the extended deadline (T0 + 7200): a wrongly-clamped arm would have
    // expired at 3600; the correctly-preserved extended arm is still Active.
    tokio::time::advance(std::time::Duration::from_secs(TTL_SECS + 1_000)).await; // → T0+4600
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        sup.read_context_state(context_id).await,
        Some(crate::context::ContextState::Active),
        "a validly-extended deadline (recorded in the log) must NOT be clamped \
             below the extension on import (M3 / D2)"
    );

    // And it DOES expire once the extended deadline passes.
    tokio::time::advance(std::time::Duration::from_mins(50)).await; // +3000s → T0+7600 > 7200
    let mut expired = false;
    for _ in 0..128 {
        if matches!(
            sup.read_context_state(context_id).await,
            Some(crate::context::ContextState::Expired) | None
        ) {
            expired = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        expired,
        "the imported context expires at its (preserved) extended deadline"
    );
}

/// Helper mirroring `export_import::tests::create_event_log_data` —
/// builds a Merkle event log byte payload via the provider.
async fn create_event_log_data(
    context_id_bytes: &[u8; 32],
    event_types: &[scp_event_log::EventType],
) -> Vec<u8> {
    use crate::context::builder::ContextEventLogProvider;
    let provider = crate::context::providers::event_log::MerkleEventLogProvider::new();
    provider.init_event_log(context_id_bytes).await.unwrap();
    for event_type in event_types {
        provider
            .append_event(
                context_id_bytes,
                *event_type,
                "",
                scp_event_log::EventPayload::default(),
                1_700_000_000,
            )
            .await
            .unwrap();
    }
    provider.export_event_log_entries(context_id_bytes).unwrap()
}

// -----------------------------------------------------------------
// ADR-049 §1 — `build_actor_deps` self-sourcing (storage foundation)
//
// `build_actor_deps` is `pub(in crate::context)` (only dispatch arms
// call it), so these live in-crate rather than in
// `tests/actor_deps_complete.rs`, which was an external-crate
// integration test back when the method was `pub`.
// -----------------------------------------------------------------

/// A `MlsStorage`-witnessing fixture that retains the supervisor's
/// authoritative `crypto` + `mls_storage` Arcs so tests can assert
/// `build_actor_deps` self-sources the exact same handles.
fn build_deps_fixture() -> (
    Arc<Supervisor>,
    Arc<crate::crypto::mls::provider::NodeMlsFactory>,
    Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter>,
) {
    let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
        "did:dht:z6MktestBuildDeps".to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
        Box::new(crate::context::builder::NotConfiguredTransportProvider);
    let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
        Box::new(TestEventLog);
    // Resolver returns Some for every DID — witnesses key_resolver
    // propagation.
    let key_resolver: KeyResolver = Arc::new(|did: &DID, _kid: scp_did::SigningKeyId| {
        let mut seed = [0u8; 32];
        for (i, b) in did.as_ref().as_bytes().iter().enumerate() {
            seed[i % 32] ^= *b;
        }
        Some(ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key())
    });
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            InMemoryStorage::new(),
        )),
    );
    let supervisor = Supervisor::with_providers(
        Arc::clone(&crypto),
        transport,
        event_log,
        key_resolver,
        None,
        None,
        None,
        None,
        Arc::clone(&mls_storage),
        crate::domain_handlers(),
    );
    (supervisor, crypto, mls_storage)
}

/// `build_actor_deps` populates every `ActorDeps` field from the
/// supervisor's own slots; mls/hpke are the single backend pair owned
/// by the `NodeMlsFactory` (ADR-049 §6 — no second source).
#[tokio::test]
async fn build_actor_deps_reads_single_backend_pair() {
    let (supervisor, crypto, mls_storage) = build_deps_fixture();
    let deps = supervisor
        .build_actor_deps_loaded(&DID("did:example:alice".to_owned()))
        .await
        .expect("build_actor_deps succeeds when providers are populated");

    assert!(
        Arc::ptr_eq(&deps.mls, crypto.mls_backend()),
        "mls must be the crypto provider's single MlsBackend"
    );
    assert!(
        Arc::ptr_eq(&deps.mls_storage, &mls_storage),
        "mls_storage must be the exact Arc threaded into with_providers"
    );
    assert!(
        (deps.key_resolver)(
            &DID("did:example:alice".to_owned()),
            scp_did::SigningKeyId::Active
        )
        .is_some(),
        "key_resolver must populate from the supervisor"
    );
    assert!(
        deps.payment_adapter.is_none(),
        "payment_adapter is None when unconfigured"
    );
    assert!(
        deps.local_dids.load().is_empty(),
        "local_dids shares the fresh supervisor's (empty) set"
    );
    deps.key_package_store
        .send_shutdown()
        .await
        .expect("KP store handle is live");
}

/// `build_actor_deps` propagates the supervisor's `mls_storage` slot
/// verbatim — the single-handle storage-foundation guarantee.
#[tokio::test]
async fn build_actor_deps_propagates_supervisor_mls_storage() {
    let (supervisor, _crypto, mls_storage) = build_deps_fixture();
    let deps = supervisor
        .build_actor_deps_loaded(&DID("did:example:storage".to_owned()))
        .await
        .expect("build_actor_deps succeeds");
    assert!(
        Arc::ptr_eq(&deps.mls_storage, &mls_storage),
        "ActorDeps.mls_storage must be the same Arc set on the supervisor"
    );
    deps.key_package_store
        .send_shutdown()
        .await
        .expect("KP store handle is live");
}

/// `build_actor_deps` fails clean when no providers were attached
/// (`for_query_shim` path).
#[tokio::test]
async fn build_actor_deps_fails_when_no_providers() {
    let supervisor = Arc::new(Supervisor::for_query_shim(crate::domain_handlers()));
    let result = supervisor
        .build_actor_deps_loaded(&DID("did:example:none".to_owned()))
        .await;
    // `ActorDeps` (the Ok variant) is not Debug; assert via `matches!`,
    // which never formats the value.
    assert!(
        matches!(result, Err(ContextError::NotInitialized(_))),
        "build_actor_deps must fail with NotInitialized when providers are unpopulated"
    );
}

/// The returned `SupervisorHandle` holds a `Weak` to the OUTER
/// supervisor `Arc` (ADR-049 Decision 16): a copy of the handle adds one
/// weak reference and no strong one. The weak count is compared around a
/// handle clone, because `build_actor_deps` also spawns a key-package
/// watchdog that holds its own `Weak`.
#[tokio::test]
async fn build_actor_deps_handle_holds_weak_outer_arc() {
    let (supervisor, _crypto, _mls_storage) = build_deps_fixture();
    let strong_before = Arc::strong_count(&supervisor);
    let deps = supervisor
        .build_actor_deps_loaded(&DID("did:example:alice".to_owned()))
        .await
        .expect("build_actor_deps succeeds");
    let weak_with_deps = Arc::weak_count(&supervisor);
    let handle_copy = deps.supervisor.clone();
    assert_eq!(
        Arc::weak_count(&supervisor),
        weak_with_deps + 1,
        "SupervisorHandle must downgrade the outer Arc"
    );
    drop(handle_copy);
    assert_eq!(Arc::weak_count(&supervisor), weak_with_deps);
    assert_eq!(
        Arc::strong_count(&supervisor),
        strong_before,
        "SupervisorHandle must not hold a strong reference"
    );
    assert!(deps.supervisor.local_dids().unwrap().is_empty());
    deps.key_package_store
        .send_shutdown()
        .await
        .expect("KP store handle is live");
}

/// `key_package_store_for` is idempotent: two calls for the same DID
/// return handles to the same actor (double-checked get-or-spawn).
#[tokio::test]
async fn key_package_store_for_is_idempotent() {
    let supervisor = supervisor_with_providers();
    let did = DID("did:dht:z6MkKpIdem".to_owned());
    let first = supervisor
        .key_package_store_for_loaded(&did)
        .await
        .expect("kp store resolves with providers");
    let second = supervisor
        .key_package_store_for_loaded(&did)
        .await
        .expect("kp store resolves with providers");
    // The registry holds exactly one entry for this DID.
    assert_eq!(
        supervisor.key_package_stores.len(),
        1,
        "exactly one KeyPackageStoreActor must be spawned per identity"
    );
    // A different DID spawns a distinct actor.
    let other = supervisor
        .key_package_store_for_loaded(&DID("did:dht:z6MkKpOther".to_owned()))
        .await
        .expect("kp store resolves with providers");
    assert_eq!(supervisor.key_package_stores.len(), 2);
    first.send_shutdown().await.expect("first handle is live");
    // `second` targets the same actor as `first`; the actor may have
    // already shut down, so a failed send is acceptable here.
    let _ = second.send_shutdown().await;
    other.send_shutdown().await.expect("other handle is live");
}

/// A KP-actor panic is caught by the watchdog, recorded payload-free in the
/// per-identity crash window, and the actor is respawned — a subsequent
/// `key_package_store_for` resolves a fresh, live handle.
///
/// Deterministic by construction: the test awaits the watchdog's completion
/// signal ([`Supervisor::kp_watchdog_processed_tx`]) rather than polling
/// `crash_windows` against a wall-clock budget, so it cannot false-timeout
/// under CPU load (the load-induced flake). The 2-worker multi-thread runtime
/// lets the `tokio::spawn`'d watchdog task make progress concurrently with
/// the test task while the latter awaits the signal.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kp_actor_watchdog_records_panic_and_respawns() {
    let supervisor = supervisor_with_providers();
    let did = DID("did:dht:z6MkKpWatchdog".to_owned());
    let poison_key = format!("kp::{}", did.0);
    let mut watchdog = supervisor.kp_watchdog_processed_tx.subscribe();

    let handle = supervisor
        .key_package_store_for_loaded(&did)
        .await
        .expect("kp store resolves");

    // Induce a panic through the testing-only seam. The watchdog catches
    // it, records a crash, removes the dead handle, and respawns. Capture
    // the completion counter BEFORE inducing so we wait for exactly this
    // crash's bump.
    let baseline = *watchdog.borrow_and_update();
    handle
        .send_induce_panic("kp-panic-sentinel")
        .await
        .expect("induce-panic command is accepted");

    // Deterministic wait: settles the instant the watchdog finishes
    // recording the crash + respawning — no polling, no timeout.
    await_kp_crash_processed(&mut watchdog, baseline).await;
    assert!(
        supervisor
            .crash_windows
            .get(&poison_key)
            .is_some_and(|w| w.crash_count() >= 1),
        "watchdog must record the KP-actor panic"
    );
    assert!(
        !supervisor.is_context_poisoned(&poison_key),
        "a single crash must not poison the identity"
    );

    // The respawned actor resolves a live handle (the dead one was removed).
    let fresh = supervisor
        .key_package_store_for_loaded(&did)
        .await
        .expect("respawned kp store resolves");
    fresh
        .send_shutdown()
        .await
        .expect("respawned handle is live");
}

/// Three KP-actor panics within the budget window poison the identity; the
/// next `key_package_store_for` surfaces a typed `ContextPoisoned` error.
///
/// Deterministic by construction: after each induced panic the test awaits
/// the watchdog's completion signal ([`Supervisor::kp_watchdog_processed_tx`])
/// — which fires only after the crash is recorded and the respawn-or-poison
/// decision has taken effect — instead of polling `is_context_poisoned`
/// against a wall-clock budget. So once the loop completes the `record`ed
/// third crash, the poison flag is GUARANTEED set (no post-loop poll), and
/// the assertions cannot false-timeout under CPU load (the load-induced
/// flake). The 2-worker multi-thread runtime lets the `tokio::spawn`'d
/// watchdog task run concurrently while the test awaits the signal.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kp_actor_poisons_after_budget() {
    let supervisor = supervisor_with_providers();
    let did = DID("did:dht:z6MkKpPoison".to_owned());
    let poison_key = format!("kp::{}", did.0);
    let mut watchdog = supervisor.kp_watchdog_processed_tx.subscribe();

    for _ in 0..CRASH_POISON_THRESHOLD {
        // Resolve (get-or-respawn) the live actor. Poison is set only AFTER
        // the final crash is recorded (below), so no resolution inside the
        // loop can observe it — a `ContextPoisoned` here would be a bug.
        let handle = supervisor
            .key_package_store_for_loaded(&did)
            .await
            .expect("live actor resolves before the budget is exhausted");

        // Capture the completion counter, induce the panic, then wait for
        // exactly this crash's watchdog bump before inducing the next.
        let baseline = *watchdog.borrow_and_update();
        handle
            .send_induce_panic("kp-poison-sentinel")
            .await
            .expect("induce-panic command is accepted by the live actor");
        await_kp_crash_processed(&mut watchdog, baseline).await;
    }

    // The watchdog's completion signal for the third crash fired only after
    // `CrashWindow::record` flipped the poison flag, so it is already set —
    // asserted directly, with no polling.
    assert!(
        supervisor.is_context_poisoned(&poison_key),
        "identity must poison after the crash budget"
    );

    // The next resolution surfaces a typed poison error.
    match supervisor.key_package_store_for_loaded(&did).await {
        Err(ContextError::ContextPoisoned(_)) => {}
        Ok(_) => panic!("poisoned identity must not resolve a live handle"),
        Err(e) => panic!("expected ContextPoisoned, got {e:?}"),
    }
}

/// `clear_kp_poison` is the operator recovery surface for a poisoned
/// per-identity KeyPackage actor (E1): it clears the sticky `kp::{did}`
/// window and re-resolves the actor via `key_package_store_for` (which
/// reconciles from the journal), WITHOUT routing through the per-context
/// snapshot respawn (there is no KP context-snapshot). After recovery the
/// identity resolves a live handle again.
///
/// Deterministic by construction: the poison precondition is driven by
/// awaiting the watchdog's completion signal
/// ([`Supervisor::kp_watchdog_processed_tx`]) after each induced panic,
/// rather than polling `is_context_poisoned` against a wall-clock budget —
/// so it cannot false-timeout under CPU load (the load-induced flake). The
/// 2-worker multi-thread runtime lets the `tokio::spawn`'d watchdog task run
/// concurrently while the test awaits the signal.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clear_kp_poison_recovers_poisoned_actor() {
    let supervisor = supervisor_with_providers();
    let did = DID("did:dht:z6MkKpClearPoison".to_owned());
    let poison_key = format!("kp::{}", did.0);
    let mut watchdog = supervisor.kp_watchdog_processed_tx.subscribe();

    // Drive the actor to the poison threshold, waiting for each crash to be
    // fully processed before inducing the next.
    for _ in 0..CRASH_POISON_THRESHOLD {
        let handle = supervisor
            .key_package_store_for_loaded(&did)
            .await
            .expect("live actor resolves before the budget is exhausted");
        let baseline = *watchdog.borrow_and_update();
        handle
            .send_induce_panic("kp-clear-sentinel")
            .await
            .expect("induce-panic command is accepted by the live actor");
        await_kp_crash_processed(&mut watchdog, baseline).await;
    }
    assert!(
        supervisor.is_context_poisoned(&poison_key),
        "precondition: identity poisoned after the budget"
    );

    // Operator recovery: clear the KP poison and re-resolve.
    supervisor
        .clear_kp_poison(&did)
        .await
        .expect("clear_kp_poison recovers a poisoned KP actor");

    assert!(
        !supervisor.is_context_poisoned(&poison_key),
        "clear_kp_poison clears the sticky poison flag"
    );
    supervisor
        .key_package_store_for_loaded(&did)
        .await
        .expect("a recovered identity resolves a live handle");
}

/// Two publishes through `dispatch_broadcast_command` each sign inside
/// the actor turn with the payload's `CommandSigner`, take consecutive
/// sequences, and produce envelopes whose signatures verify against the
/// signer's key.
#[tokio::test]
async fn publish_broadcast_dispatches_through_mailbox() {
    use crate::context::actor::commands::PublishBroadcastPayload;

    let supervisor_arc = supervisor_with_providers();
    let mut deps = test_actor_deps(&supervisor_arc).await;
    // The test supervisor's transport refuses sends; publish delivers
    // the sealed envelope, so this actor gets one that accepts them.
    deps.transport = Arc::new(crate::context::builder::LocalTransportProvider);

    let ctx_id_bytes = [0xC0u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let author = DID("did:example:author".to_owned());

    // A broadcast-mode state with the author registered (so the
    // reservation passes) and present in membership (so the seal's
    // per-sender sequence resolves), in the Active state.
    let mut state = crate::context::actor::state::PerContextState::new_for_test_broadcast(
        ctx_id_bytes,
        1_700_000_000,
        DID("did:example:admin".to_owned()),
    );
    let mut bc = scp_protocol::context::broadcast::BroadcastContext::new(
        ctx_key.clone(),
        &scp_protocol::context::ContextMode::Broadcast,
        scp_protocol::context::broadcast::BroadcastAdmission::Open,
    )
    .expect("broadcast context constructs");
    bc.add_author(author.as_ref()).expect("author registers");
    state.broadcast_context = Some(bc);
    state
        .membership
        .add_member(author.clone(), "author".to_owned(), vec![]);
    state
        .handle
        .transition_to(&scp_protocol::context::ContextState::Active)
        .expect("transition to Active");

    let handle = supervisor_arc
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn_actor_with_state: fresh context id registers");

    let signer = CommandSigner::local_ed25519(ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]));
    let verifying_key = signer.verifying_key().expect("Ed25519 signer");

    let mut envelopes = Vec::new();
    for body in [b"first".as_slice(), b"second".as_slice()] {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = BroadcastCommand::PublishBroadcast {
            payload: Box::new(PublishBroadcastPayload {
                context_id: ctx_key.clone(),
                author_did: author.clone(),
                payload: body.to_vec(),
                signer: signer.clone(),
            }),
            reply: tx,
        };
        supervisor_arc
            .dispatch_broadcast_command(cmd)
            .await
            .expect("mailbox dispatch succeeds");
        envelopes.push(rx.await.expect("publish reply").expect("publish succeeds"));
    }

    assert_eq!(
        envelopes[1].sequence,
        envelopes[0].sequence + 1,
        "the mailbox serializes publishes onto consecutive sequences",
    );
    for envelope in &envelopes {
        crate::context::broadcast_helpers::check_envelope_signed_by(envelope, &verifying_key)
            .expect("each envelope verifies under the custody key");
    }

    handle.send_shutdown().await.expect("handle is live");
}

/// A broadcast command for a context with no registered actor replies
/// `ContextNotRegistered` on its own channel, publish included.
#[tokio::test]
async fn publish_broadcast_without_actor_replies_not_registered() {
    use crate::context::actor::commands::PublishBroadcastPayload;

    let supervisor_arc = supervisor_with_providers();
    let ctx_key = hex::encode([0xC1u8; 32]);
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = BroadcastCommand::PublishBroadcast {
        payload: Box::new(PublishBroadcastPayload {
            context_id: ctx_key.clone(),
            author_did: DID("did:example:author".to_owned()),
            payload: b"x".to_vec(),
            signer: CommandSigner::local_ed25519(ed25519_dalek::SigningKey::from_bytes(
                &[0x42; 32],
            )),
        }),
        reply: tx,
    };
    let outcome = supervisor_arc
        .dispatch_broadcast_command(cmd)
        .await
        .expect("an absent actor is reported on the reply channel");
    assert!(outcome.result.is_err(), "the outcome carries the miss");
    match rx.await.expect("publish reply") {
        Err(ContextError::ContextNotRegistered(id)) => assert_eq!(id, ctx_key),
        other => panic!("expected ContextNotRegistered, got {other:?}"),
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

// -----------------------------------------------------------------
// Global tracing capture (test-only) for the payload-redaction test.
//
// The watchdog's `tracing::error!` runs on a tokio worker thread, so a
// thread-local subscriber on the test thread would miss it. We install
// a process-global capturing subscriber exactly once (`std::sync::Once`)
// and let every watchdog test read its own lines out of the shared
// buffer (filtered by the test's unique `context_id`). The static lives
// inside `mod tests`, so the no-mutable-globals gate ignores it.
// -----------------------------------------------------------------
static CAPTURED_LOG: std::sync::OnceLock<Arc<std::sync::Mutex<Vec<String>>>> =
    std::sync::OnceLock::new();
static CAPTURE_INIT: std::sync::Once = std::sync::Once::new();

fn capture_buffer() -> Arc<std::sync::Mutex<Vec<String>>> {
    Arc::clone(CAPTURED_LOG.get_or_init(|| Arc::new(std::sync::Mutex::new(Vec::new()))))
}

/// Install the process-global capturing subscriber (idempotent).
fn install_capture_subscriber() {
    use tracing::field::{Field, Visit};
    use tracing::{Event, Metadata};

    struct CaptureSub;
    struct LineVisitor<'a>(&'a mut String);
    impl Visit for LineVisitor<'_> {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write;
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
        fn record_str(&mut self, field: &Field, value: &str) {
            use std::fmt::Write;
            let _ = write!(self.0, " {}={value}", field.name());
        }
    }
    impl tracing::Subscriber for CaptureSub {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &Event<'_>) {
            let mut line = String::new();
            let mut v = LineVisitor(&mut line);
            event.record(&mut v);
            if let Some(buf) = CAPTURED_LOG.get() {
                buf.lock().unwrap().push(line);
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    CAPTURE_INIT.call_once(|| {
        let _ = capture_buffer(); // ensure the buffer OnceLock is set.
        // Best-effort: if another test already set a global default this
        // is a no-op (returns Err), but no other test installs one.
        let _ = tracing::subscriber::set_global_default(CaptureSub);
    });
}

/// Captured watchdog log lines that mention `ctx_key`.
#[cfg(feature = "testing")]
fn captured_log_lines_for(ctx_key: &str) -> Vec<String> {
    capture_buffer()
        .lock()
        .unwrap()
        .iter()
        .filter(|l| l.contains(ctx_key))
        .cloned()
        .collect()
}

/// `ContextPersistence` backed by a shared `DashMap` so a snapshot
/// persisted in a test is actually returned by `load_context` — unlike
/// `TestPersistence`, which always returns `None`. Used by the respawn
/// tests, which need `restore_context` to find a real snapshot.
#[derive(Clone, Default)]
struct MapPersistence {
    contexts: Arc<DashMap<String, crate::context::state::ContextSnapshot>>,
}
#[async_trait::async_trait]
impl ContextPersistence for MapPersistence {
    async fn persist_context(
        &self,
        id: &str,
        snap: &crate::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.contexts.insert(id.to_owned(), snap.clone());
        Ok(())
    }
    async fn load_context(
        &self,
        id: &str,
    ) -> Result<
        Option<crate::context::state::ContextSnapshot>,
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

/// Build a providers-populated supervisor with an injected clock and
/// persistence backend so the watchdog/respawn tests can drive the
/// crash window deterministically and rehydrate real snapshots.
fn supervisor_with_clock_and_persistence(
    clock: Arc<dyn Clock>,
    persistence: Box<dyn ContextPersistence>,
) -> Arc<Supervisor> {
    supervisor_with_clock_persistence_and_event_log(clock, persistence, Box::new(TestEventLog))
}

/// [`supervisor_with_clock_and_persistence`] with a caller-supplied event-log
/// provider, for tests that assert what did (or did NOT) reach the durable
/// event log — e.g. injecting a [`ContextExpiredAppendCounter`] to prove the
/// TTL-expiry pipeline never ran against a terminal context (N3).
fn supervisor_with_clock_persistence_and_event_log(
    clock: Arc<dyn Clock>,
    persistence: Box<dyn ContextPersistence>,
    event_log: Box<dyn crate::context::builder::ContextEventLogProvider>,
) -> Arc<Supervisor> {
    // Install the global capture subscriber so the payload-redaction
    // test can observe the watchdog's log (emitted on a worker thread).
    install_capture_subscriber();
    let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
        "did:dht:z6MktestDoNotRely".to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
        Box::new(crate::context::builder::NotConfiguredTransportProvider);
    let key_resolver: KeyResolver = Arc::new(|_: &DID, _: scp_did::SigningKeyId| None);
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            InMemoryStorage::new(),
        )),
    );
    Supervisor::with_providers(
        crypto,
        transport,
        event_log,
        key_resolver,
        Some(persistence),
        None,
        None,
        Some(clock),
        mls_storage,
        crate::domain_handlers(),
    )
}

/// Event-log double that COUNTS `ContextExpired` append attempts (N3). A TTL
/// arm that (wrongly) fired against a terminal context would drive
/// `handle_ttl_expiry`'s Phase-2 `finish_ttl_expiry_io`, which appends a
/// `ContextExpired` leaf — so a non-zero count is the distinguishing signal
/// that the `is_active` reconcile gate regressed. Every other call is a
/// success no-op.
#[derive(Clone, Default)]
struct ContextExpiredAppendCounter {
    context_expired_appends: Arc<std::sync::atomic::AtomicUsize>,
}
#[async_trait::async_trait]
impl crate::context::builder::ContextEventLogProvider for ContextExpiredAppendCounter {
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
        event_type: scp_event_log::EventType,
        _actor: &str,
        _payload: scp_event_log::EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        if event_type == scp_event_log::EventType::ContextExpired {
            self.context_expired_appends
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }
    async fn destroy_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
}

/// B8 — create-time terminal-snapshot precheck (tombstone finality). A
/// `CreateContext` over a DURABLE snapshot whose lifecycle state is TERMINAL
/// (`Expired` / `Closed` / `Tombstoned`) is REFUSED fail-closed: re-creating
/// such an id would resurrect a finished (expired/closed/tombstoned) context
/// under a fresh actor, defeating tombstone finality. Each terminal state is
/// exercised.
#[tokio::test]
async fn create_after_terminal_snapshot_is_refused() {
    use scp_protocol::context::ContextState;

    let creator = "did:dht:z6MkB8CreateTerminalCreator";
    let ctx_id = "b8-terminal-precheck-ctx";

    for terminal in [
        ContextState::Expired,
        ContextState::Closed,
        ContextState::Tombstoned,
    ] {
        let map = MapPersistence::default();
        let mut snap = import_test_snapshot(ctx_id, creator);
        snap.state = terminal.clone();
        map.contexts.insert(ctx_id.to_owned(), snap);

        let clock: Arc<dyn Clock> = Arc::new(scp_clock::TestClock::new(1_700_000_000));
        let sup = supervisor_with_clock_and_persistence(clock, Box::new(map));

        let result = sup
            .create_context(
                ctx_id.to_owned(),
                scp_protocol::context::ContextParams {
                    ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
                    ..scp_protocol::context::ContextParams::default()
                },
                DID(creator.to_owned()),
                None,
                Vec::new(),
            )
            .await;

        let err = result.expect_err(&format!(
            "create over a durable {terminal:?} snapshot must be REFUSED (tombstone finality)"
        ));
        let msg = err.to_string();
        assert!(
            msg.contains("terminal") && msg.contains("tombstone finality"),
            "refusal must cite terminal/tombstone finality for {terminal:?}, got: {msg}"
        );
    }
}

/// B8 counter-case: an ABSENT snapshot (no durable state for the id — the
/// standing-context / fresh-create path) is NOT blocked by the terminal
/// precheck. The create proceeds past the precheck and succeeds.
#[tokio::test]
async fn create_over_absent_snapshot_still_creates() {
    let creator = "did:dht:z6MkB8CreateAbsentCreator";
    let ctx_id = "b8-absent-precheck-ctx";

    // Empty persistence: `load_context` ⇒ `Ok(None)`.
    let map = MapPersistence::default();
    let clock: Arc<dyn Clock> = Arc::new(scp_clock::TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_and_persistence(clock, Box::new(map));

    let handle = sup
        .create_context(
            ctx_id.to_owned(),
            scp_protocol::context::ContextParams {
                ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
                ..scp_protocol::context::ContextParams::default()
            },
            DID(creator.to_owned()),
            None,
            Vec::new(),
        )
        .await
        .expect("create over an ABSENT snapshot must succeed (precheck allows it)");
    assert_eq!(handle.context_id(), ctx_id);
}

/// A create succeeds before `shutdown_all_contexts` and, once shutdown has
/// begun, fails with the typed `SupervisorShutDown` (`SCP-CTX-2138`,
/// ADR-049 Decision 16 item 2), never a flattened `CreationFailed`.
#[tokio::test]
async fn create_after_shutdown_keeps_supervisor_shut_down() {
    let creator = "did:dht:z6MkCreateAfterShutdownCreator";
    let clock: Arc<dyn Clock> = Arc::new(scp_clock::TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_and_persistence(clock, Box::new(MapPersistence::default()));
    let params = || scp_protocol::context::ContextParams {
        ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
        ..scp_protocol::context::ContextParams::default()
    };

    sup.create_context(
        "create-before-shutdown-ctx".to_owned(),
        params(),
        DID(creator.to_owned()),
        None,
        Vec::new(),
    )
    .await
    .expect("a create before shutdown succeeds");

    sup.shutdown_all_contexts().await;
    // A creator with no key-package actor yet, so the create reaches the
    // refused key-package actor spawn in `build_actor_deps`.
    let result = sup
        .create_context(
            "create-after-shutdown-ctx".to_owned(),
            params(),
            DID("did:dht:z6MkCreateAfterShutdownSecondCreator".to_owned()),
            None,
            Vec::new(),
        )
        .await;
    assert!(
        matches!(
            result,
            Err(
                scp_protocol::context::builder::ContextCreationError::StateTransition(
                    ContextError::SupervisorShutDown(_)
                )
            )
        ),
        "a create after shutdown must keep SupervisorShutDown; got {result:?}"
    );
}

/// Drive a panic into the actor via the testing-only seam and wait for
/// the watchdog to observe it. Sending `TestInducePanic` returns an
/// `Err` (the reply channel drops when the actor task unwinds) — that
/// is the signal the actor has crashed. We then poll until the
/// supervisor's registry/budget reflects the watchdog's reaction.
#[cfg(feature = "testing")]
async fn induce_panic(handle: &ContextActorHandle, sentinel: &str) {
    // Fire-and-forget: `TestInducePanic` carries no reply channel and the
    // actor unwinds on dispatch, so use the pre-built-command send path.
    let cmd = ContextCommand::LifecycleControl(
        crate::context::actor::commands::LifecycleControlCommand::TestInducePanic {
            sentinel: sentinel.to_owned(),
        },
    );
    let _ = handle
        .send_with_timeout(cmd, std::time::Duration::from_secs(5))
        .await;
}

/// Spawn-and-panic helper: registers a fresh encrypted actor for
/// `ctx_key`, drives it Active, persists a snapshot, then returns the
/// handle so the test can panic it. Returns `(handle, ctx_key)`.
async fn spawn_active_with_snapshot(
    sup: &Arc<Supervisor>,
    ctx_id_bytes: [u8; 32],
) -> (ContextActorHandle, String) {
    let ctx_key = hex::encode(ctx_id_bytes);
    let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        DID("did:example:admin".to_owned()),
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    // Persist a snapshot so a respawn can rehydrate the context.
    let snap = crate::context::manager_methods::snapshot_context(&state);
    sup.persistence_ref()
        .expect("test supervisor has persistence")
        .persist_context(&ctx_key, &snap)
        .await
        .unwrap();
    let deps = test_actor_deps(sup).await;
    // `Box::pin` keeps the large (state-carrying) spawn future off the
    // test's stack frame, mirroring the production call sites.
    let handle = Box::pin(sup.spawn_actor_with_state(state, deps, None))
        .await
        .expect("spawn registers");
    (handle, ctx_key)
}

/// Poll until `cond` holds or the timeout elapses. Returns whether the
/// condition became true. Used to wait on the watchdog (which runs on a
/// separate task) without a fixed sleep.
async fn wait_until<F>(timeout: std::time::Duration, mut cond: F) -> bool
where
    F: FnMut() -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if cond() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// Async variant of [`wait_until`]: polls an async predicate (e.g. a
/// mailbox query) until it holds or the timeout elapses. Used to wait on
/// a RESPONSIVE respawned actor — a bare registry `lookup` is not enough
/// because a just-crashed actor's handle lingers in the registry until
/// the watchdog despawns it.
#[cfg(feature = "testing")]
async fn wait_until_async<F, Fut>(timeout: std::time::Duration, mut cond: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if cond().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// 3 panics within 60s poison the context: `is_context_poisoned` becomes
/// true, `lookup` returns None (the dead handle is despawned), a
/// subsequent dispatch surfaces `ContextPoisoned`, and no respawn
/// happens after the poison.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_crashes_poison_and_stop_respawning() {
    let clock = Arc::new(TestClock::new(1_700_000_000));
    let clock_dyn: Arc<dyn Clock> = clock.clone();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

    let ctx_id_bytes = [0xC1u8; 32];
    let (handle, ctx_key) = spawn_active_with_snapshot(&sup, ctx_id_bytes).await;

    // Crash 1 and 2: each below the threshold, so the watchdog respawns.
    // After each crash we wait for a RESPONSIVE respawned actor before
    // capturing the next handle — a bare `lookup` would return the
    // lingering dead handle (despawned only by the watchdog), and the
    // next panic would land on a closed mailbox and never crash.
    let mut handle = handle;
    for i in 0..2u32 {
        induce_panic(&handle, "SECRET_SENTINEL_abc123").await;
        let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
            sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
                && !sup.is_context_poisoned(&ctx_key)
        })
        .await;
        assert!(
            respawned,
            "watchdog must respawn a responsive actor below the poison threshold (crash {i})"
        );
        clock.advance_millis(100);
        handle = sup
            .lookup(&ctx_key)
            .expect("respawned responsive actor is registered");
    }

    // Crash 3: reaches the threshold (3 within 60s) → poison.
    induce_panic(&handle, "SECRET_SENTINEL_abc123").await;
    let poisoned = wait_until(std::time::Duration::from_secs(5), || {
        sup.is_context_poisoned(&ctx_key)
    })
    .await;
    assert!(poisoned, "the 3rd crash within 60s must poison the context");

    // The poisoned context's dead handle is despawned (lookup None).
    let despawned = wait_until(std::time::Duration::from_secs(5), || {
        sup.lookup(&ctx_key).is_none()
    })
    .await;
    assert!(despawned, "a poisoned context's actor must be despawned");

    // A subsequent per-context dispatch surfaces ContextPoisoned (not
    // the generic ContextNotRegistered). `dispatch_command` returns
    // `Result<Outcome<()>, _>` (Outcome is not Debug), so inspect the
    // error arm directly.
    let result = sup
        .dispatch_command(
            &ctx_key,
            crate::context::actor::commands::MessagingCommand::DrainEvents {
                context_id: ctx_key.clone(),
                reply: tokio::sync::oneshot::channel().0,
            },
        )
        .await;
    match result {
        Err(ContextError::ContextPoisoned(id)) => {
            assert_eq!(id, ctx_key, "ContextPoisoned must carry the context id");
        }
        Err(other) => {
            panic!("dispatch to a poisoned context must surface ContextPoisoned, got {other:?}")
        }
        Ok(_) => panic!("dispatch to a poisoned context must fail, but it succeeded"),
    }

    // No respawn after poison: even after time passes, lookup stays None.
    clock.advance_millis(1_000);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        sup.lookup(&ctx_key).is_none(),
        "a poisoned context must NOT be respawned"
    );
}

/// Operator recovery (ADR-049 §10): `clear_poison` clears a poisoned
/// context's crash window and attempts ONE respawn from the snapshot,
/// returning it to a usable Active state. The poison flag is cleared and
/// per-context dispatch resolves to the live actor again.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clear_poison_recovers_a_poisoned_context() {
    let clock = Arc::new(TestClock::new(1_700_000_000));
    let clock_dyn: Arc<dyn Clock> = clock.clone();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

    let ctx_id_bytes = [0xDBu8; 32];
    let (handle, ctx_key) = spawn_active_with_snapshot(&sup, ctx_id_bytes).await;

    // Poison: 3 crashes within 60s.
    let mut handle = handle;
    for _ in 0..2u32 {
        induce_panic(&handle, "SECRET_SENTINEL_clear").await;
        let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
            sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
                && !sup.is_context_poisoned(&ctx_key)
        })
        .await;
        assert!(respawned, "watchdog must respawn below the threshold");
        clock.advance_millis(100);
        handle = sup.lookup(&ctx_key).expect("respawned actor registered");
    }
    induce_panic(&handle, "SECRET_SENTINEL_clear").await;
    let poisoned = wait_until(std::time::Duration::from_secs(5), || {
        sup.is_context_poisoned(&ctx_key)
    })
    .await;
    assert!(poisoned, "3 crashes within 60s must poison");

    // Operator recovery: clear_poison clears the window + respawns once.
    let owning = DID(format!("did:scp:{ctx_key}"));
    sup.clear_poison(&ctx_key, &owning)
        .await
        .expect("clear_poison must succeed: snapshot is present and Active");

    assert!(
        !sup.is_context_poisoned(&ctx_key),
        "clear_poison must clear the sticky poison flag"
    );
    assert_eq!(
        sup.read_context_state(&ctx_key).await,
        Some(crate::context::ContextState::Active),
        "clear_poison must respawn the context back to a usable Active state"
    );

    // Per-context dispatch resolves to the live actor again (no longer
    // ContextPoisoned).
    let result = sup
        .dispatch_command(
            &ctx_key,
            crate::context::actor::commands::MessagingCommand::DrainEvents {
                context_id: ctx_key.clone(),
                reply: tokio::sync::oneshot::channel().0,
            },
        )
        .await;
    assert!(
        !matches!(result, Err(ContextError::ContextPoisoned(_))),
        "after clear_poison, dispatch must NOT surface ContextPoisoned"
    );
}

/// `clear_poison` touches the crash window only once it holds
/// `bootstrap_spawn_lock`, so while it waits for the lock the sticky
/// poison flag stands and the checked lifecycle read reports `Poisoned`,
/// never `Ok(None)`: a bridge's `context_close` that treats `Ok(None)` as
/// "already closed" skips the `ContextClose` check. A bootstrap that
/// holds the lock meanwhile cannot clear a marker `clear_poison` has not
/// set yet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clear_poison_wait_for_the_spawn_lock_reads_as_poisoned_not_absent() {
    let clock = Arc::new(TestClock::new(1_700_000_000));
    let clock_dyn: Arc<dyn Clock> = clock.clone();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));
    let ctx_key = hex::encode([0xDDu8; 32]);
    let owning = DID(format!("did:scp:{ctx_key}"));
    sup.crash_windows
        .entry(ctx_key.clone())
        .or_default()
        .poisoned = true;

    // Another lifecycle operation holds the global spawn lock.
    let spawn_guard = sup.bootstrap_spawn_lock.lock().await;
    let task = {
        let sup = Arc::clone(&sup);
        let ctx_key = ctx_key.clone();
        tokio::spawn(async move { sup.clear_poison(&ctx_key, &owning).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        !task.is_finished(),
        "clear_poison must wait for the spawn lock"
    );
    let read = sup.read_context_state_checked(&ctx_key).await;
    assert!(
        matches!(
            read,
            Ok(Some(scp_protocol::context::ContextState::Poisoned))
        ),
        "the clear_poison wait must read as Poisoned, got {read:?}"
    );

    drop(spawn_guard);
    let respawn = task.await.expect("clear_poison task must not panic");
    assert!(
        matches!(respawn, Err(ContextError::ActorCrashed(_))),
        "the respawn with no snapshot fails, got {respawn:?}"
    );
}

/// A bootstrap over a poisoned id reads as `ActorCrashed` while it runs,
/// and one that registers no actor (a failed import or create) puts the
/// poisoned window back, so the context never reads as `Ok(None)`. A
/// bootstrap over an id with no crash history leaves no window behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_bootstrap_restores_the_prior_crash_window() {
    let clock = Arc::new(TestClock::new(1_700_000_000));
    let clock_dyn: Arc<dyn Clock> = clock.clone();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));
    let poisoned = hex::encode([0xDEu8; 32]);
    sup.crash_windows
        .entry(poisoned.clone())
        .or_default()
        .poisoned = true;

    let window = sup.begin_bootstrap_window(&poisoned);
    assert!(
        !sup.is_context_poisoned(&poisoned),
        "the bootstrap starts the new actor on a clean budget"
    );
    let during = sup.read_context_state_checked(&poisoned).await;
    assert!(
        matches!(during, Err(ContextError::ActorCrashed(_))),
        "a bootstrap in progress must read as ActorCrashed, got {during:?}"
    );
    drop(window);
    let after = sup.read_context_state_checked(&poisoned).await;
    assert!(
        matches!(
            after,
            Ok(Some(scp_protocol::context::ContextState::Poisoned))
        ),
        "a bootstrap that registered no actor must restore the poison, got {after:?}"
    );

    let clean = hex::encode([0xDFu8; 32]);
    drop(sup.begin_bootstrap_window(&clean));
    assert!(
        !sup.crash_windows.contains_key(&clean),
        "a bootstrap over an id with no crash history leaves no window"
    );
}

/// Reads `read_context_state_checked` for `id` at the instant a bootstrap
/// arm sends its reply: tokio's oneshot `send` wakes the receiver's waker
/// synchronously, so `wake` runs before the arm executes its next line.
struct StateReadAtReply {
    sup: Arc<Supervisor>,
    id: String,
    seen:
        std::sync::Mutex<Option<Result<Option<scp_protocol::context::ContextState>, ContextError>>>,
}

impl std::task::Wake for StateReadAtReply {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let read = futures::FutureExt::now_or_never(self.sup.read_context_state_checked(&self.id))
            .expect("a checked read of an id no actor serves completes without awaiting");
        *self.seen.lock().expect("probe lock") = Some(read);
    }
}

/// Dispatch `cmd`, whose reply goes to `rx`, and return the checked state
/// read taken when the reply was sent, together with the reply.
async fn state_read_at_reply<T: Send>(
    sup: &Arc<Supervisor>,
    id: &str,
    mut rx: tokio::sync::oneshot::Receiver<T>,
    cmd: LifecycleCommand,
) -> (
    Result<Option<scp_protocol::context::ContextState>, ContextError>,
    T,
) {
    let probe = Arc::new(StateReadAtReply {
        sup: Arc::clone(sup),
        id: id.to_owned(),
        seen: std::sync::Mutex::new(None),
    });
    {
        let waker = std::task::Waker::from(Arc::clone(&probe));
        let mut cx = std::task::Context::from_waker(&waker);
        assert!(
            std::future::Future::poll(std::pin::Pin::new(&mut rx), &mut cx).is_pending(),
            "no reply before dispatch"
        );
    }
    sup.dispatch_lifecycle_command(cmd)
        .await
        .expect("bootstrap commands dispatch directly");
    let reply = rx.await.expect("the arm sends a reply");
    let seen = probe
        .seen
        .lock()
        .expect("probe lock")
        .take()
        .expect("the reply woke the probe");
    (seen, reply)
}

/// Marks `id` poisoned in `sup`'s crash windows, so a bootstrap that
/// restores the window before it replies leaves a checked read at the
/// reply reading `Ok(Some(Poisoned))`.
fn poison_crash_window(sup: &Supervisor, id: &str) {
    sup.crash_windows.entry(id.to_owned()).or_default().poisoned = true;
}

/// A `CreateContext` command for `id` with `params`, and its reply receiver.
fn reply_order_create(
    id: &str,
    params: scp_protocol::context::ContextParams,
) -> (
    LifecycleCommand,
    tokio::sync::oneshot::Receiver<
        Result<crate::context::ContextHandle, scp_protocol::context::builder::ContextCreationError>,
    >,
) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let payload = Box::new(crate::context::actor::commands::CreateContextPayload {
        context_id: id.to_owned(),
        params,
        creator_did: DID("did:dht:z6MkReplyOrderCreator".to_owned()),
        local_pseudonym: None,
        relay_urls: Vec::new(),
    });
    (LifecycleCommand::CreateContext { payload, reply: tx }, rx)
}

/// An `ImportContext` command for a validly signed export of `id`, and its
/// reply receiver.
async fn reply_order_import(
    id: &str,
    member: &str,
) -> (
    LifecycleCommand,
    tokio::sync::oneshot::Receiver<Result<crate::context::ContextHandle, ContextError>>,
) {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let export =
        signed_import_export_with_member(id, "did:key:reply-order-creator", member, &signing_key)
            .await;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = LifecycleCommand::ImportContext {
        export: Box::new(export),
        verifying_key: Box::new(signing_key.verifying_key()),
        local_pseudonym: None,
        reply: tx,
    };
    (cmd, rx)
}

/// Every failing exit of the `CreateContext` arm drops its bootstrap
/// window before it replies. A caller that reads the checked state the
/// moment it receives the error sees the restored poisoned window
/// (`Ok(Some(Poisoned))`), never the bootstrap's marker-only window
/// (`Err(ActorCrashed)`).
///
/// The test drives one failure through each explicit `drop(crash_window)`
/// that precedes a `reply.send` in the arm: the deps failure, the
/// terminal-snapshot refusal, the snapshot read fault, and the failed
/// `create_context` tail, whose drop the timeout arm shares.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_create_restores_the_crash_window_before_it_replies() {
    use scp_protocol::context::{ContextParams, ContextState};

    // `build_actor_deps` fails: no providers are attached.
    let sup = Arc::new(Supervisor::for_query_shim(crate::domain_handlers()));
    let id = hex::encode([0xC1u8; 32]);
    poison_crash_window(&sup, &id);
    let (cmd, rx) = reply_order_create(
        &id,
        ContextParams {
            ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
            ..ContextParams::default()
        },
    );
    let (seen, reply) = state_read_at_reply(&sup, &id, rx, cmd).await;
    assert!(reply.is_err(), "a create without providers fails");
    assert!(
        matches!(seen, Ok(Some(ContextState::Poisoned))),
        "create, deps failure: the reply must follow the window restore, got {seen:?}"
    );

    // Refused by the terminal-snapshot precheck.
    let id = hex::encode([0xC2u8; 32]);
    let map = MapPersistence::default();
    let mut snap = import_test_snapshot(&id, "did:dht:z6MkReplyOrderCreator");
    snap.state = ContextState::Closed;
    map.contexts.insert(id.clone(), snap);
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_and_persistence(clock, Box::new(map));
    poison_crash_window(&sup, &id);
    let (cmd, rx) = reply_order_create(
        &id,
        ContextParams {
            ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
            ..ContextParams::default()
        },
    );
    let (seen, reply) = state_read_at_reply(&sup, &id, rx, cmd).await;
    assert!(reply.is_err(), "a create over a closed snapshot is refused");
    assert!(
        matches!(seen, Ok(Some(ContextState::Poisoned))),
        "create, terminal precheck: the reply must follow the window restore, got {seen:?}"
    );

    // The terminal-snapshot precheck cannot read the snapshot.
    let id = hex::encode([0xC4u8; 32]);
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_and_persistence(clock, Box::new(ErringLoadPersistence));
    poison_crash_window(&sup, &id);
    let (cmd, rx) = reply_order_create(
        &id,
        ContextParams {
            ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
            ..ContextParams::default()
        },
    );
    let (seen, reply) = state_read_at_reply(&sup, &id, rx, cmd).await;
    assert!(
        reply.is_err(),
        "a create whose snapshot read faults is refused"
    );
    assert!(
        matches!(seen, Ok(Some(ContextState::Poisoned))),
        "create, snapshot read fault: the reply must follow the window restore, got {seen:?}"
    );

    // Deps and precheck pass and `create_context` fails: the params
    // demand a protocol major this build does not speak.
    let id = hex::encode([0xC5u8; 32]);
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_and_persistence(clock, Box::new(MapPersistence::default()));
    poison_crash_window(&sup, &id);
    let params = ContextParams {
        min_protocol_version: Some((9, 0)),
        ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
        ..ContextParams::default()
    };
    let (cmd, rx) = reply_order_create(&id, params);
    let (seen, reply) = state_read_at_reply(&sup, &id, rx, cmd).await;
    assert!(
        matches!(
            reply,
            Err(
                scp_protocol::context::builder::ContextCreationError::StateTransition(
                    scp_protocol::context::ContextError::VersionIncompatible { .. }
                )
            )
        ),
        "the create must fail inside `create_context`, got {reply:?}"
    );
    assert!(
        matches!(seen, Ok(Some(ContextState::Poisoned))),
        "create, failed tail: the reply must follow the window restore, got {seen:?}"
    );
}

/// Every failing exit of the `ImportContext` arm drops its bootstrap
/// window before it replies, with the same observable result as
/// [`a_failed_create_restores_the_crash_window_before_it_replies`]. The
/// test drives the deps failure and the failed `import_context` tail,
/// whose drop the timeout arm shares.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_import_restores_the_crash_window_before_it_replies() {
    use scp_protocol::context::ContextState;

    // `build_actor_deps` fails after the export verifies.
    let sup = Arc::new(Supervisor::for_query_shim(crate::domain_handlers()));
    let id = hex::encode([0xC3u8; 32]);
    poison_crash_window(&sup, &id);
    let (cmd, rx) = reply_order_import(&id, "did:key:reply-order-member").await;
    let (seen, reply) = state_read_at_reply(&sup, &id, rx, cmd).await;
    assert!(reply.is_err(), "an import without providers fails");
    assert!(
        matches!(seen, Ok(Some(ContextState::Poisoned))),
        "import, deps failure: the reply must follow the window restore, got {seen:?}"
    );

    // Deps build and `import_context` rejects the export: the supervisor
    // clock predates the snapshot's creation time, so the export reads
    // as future-dated.
    let id = hex::encode([0xC6u8; 32]);
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(1_000_000_000));
    let sup = supervisor_with_clock_and_persistence(clock, Box::new(MapPersistence::default()));
    poison_crash_window(&sup, &id);
    let (cmd, rx) = reply_order_import(&id, "did:key:reply-order-tail-member").await;
    let (seen, reply) = state_read_at_reply(&sup, &id, rx, cmd).await;
    assert!(
        matches!(&reply, Err(ContextError::PersistenceFailed(msg)) if msg.contains("future-dated")),
        "the import must fail inside `import_context`, got {reply:?}"
    );
    assert!(
        matches!(seen, Ok(Some(ContextState::Poisoned))),
        "import, failed tail: the reply must follow the window restore, got {seen:?}"
    );
}

/// A checked read racing bootstraps that fail over a poisoned id never
/// reads as `Ok(None)`. Each failed bootstrap swaps a marker-only window
/// in and then restores the poisoned one. A read that took the poison
/// flag and the respawn markers from two separate `crash_windows` reads
/// could see the fresh window's clear poison flag and then the restored
/// window's clear markers, and report the poisoned context as absent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_checked_read_racing_failed_bootstraps_never_reads_a_poisoned_id_as_absent() {
    let clock = Arc::new(TestClock::new(1_700_000_000));
    let clock_dyn: Arc<dyn Clock> = clock.clone();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));
    let poisoned = hex::encode([0xD1u8; 32]);
    sup.crash_windows
        .entry(poisoned.clone())
        .or_default()
        .poisoned = true;

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flipper = {
        let sup = Arc::clone(&sup);
        let id = poisoned.clone();
        let stop = Arc::clone(&stop);
        tokio::task::spawn_blocking(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                drop(sup.begin_bootstrap_window(&id));
            }
        })
    };
    for _ in 0..20_000 {
        let read = sup.read_context_state_checked(&poisoned).await;
        assert!(
            !matches!(read, Ok(None)),
            "a poisoned id must never read as absent mid-bootstrap"
        );
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    flipper.await.expect("the bootstrap loop must not panic");
}

/// `clear_poison` on a context with NO persisted snapshot records a FRESH
/// respawn failure (the single retry fails) and returns an error WITHOUT
/// looping: the budget is reset to one fresh failure, not re-poisoned in a
/// tight loop. The caller (operator) sees the failure and can decide.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clear_poison_without_snapshot_records_one_failure_no_loop() {
    let clock = Arc::new(TestClock::new(1_700_000_000));
    let clock_dyn: Arc<dyn Clock> = clock.clone();
    // Empty persistence: a respawn finds no snapshot and fails.
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

    let ctx_key = hex::encode([0xDCu8; 32]);
    let owning = DID(format!("did:scp:{ctx_key}"));

    // Pre-mark the context poisoned (no actor, no snapshot).
    {
        let mut entry = sup.crash_windows.entry(ctx_key.clone()).or_default();
        // Drive it to poisoned by recording the budget's worth of crashes.
        entry.mark_respawn_failed();
    }

    // clear_poison clears the window and attempts ONE respawn, which fails
    // (no snapshot) and is recorded as a single fresh failure.
    let result = sup.clear_poison(&ctx_key, &owning).await;
    assert!(
        matches!(result, Err(ContextError::ActorCrashed(_))),
        "clear_poison with no snapshot must surface the failed single retry, got {result:?}"
    );

    // The single retry recorded ONE crash, not a poison loop: the window
    // exists with a fresh (non-poisoned) failure, and the context is NOT
    // re-poisoned by a tight loop.
    assert!(
        !sup.is_context_poisoned(&ctx_key),
        "a single failed retry must NOT immediately re-poison (no loop)"
    );
    assert!(
        sup.lookup(&ctx_key).is_none(),
        "no actor is registered after a failed no-snapshot respawn"
    );
}

/// A single crash (below the threshold) respawns the actor from its
/// persisted snapshot, and the rehydrated context preserves the
/// persisted state — including the §9.10.4 routing axis.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_crash_respawns_and_preserves_state() {
    let clock = Arc::new(TestClock::new(1_700_000_000));
    let clock_dyn: Arc<dyn Clock> = clock.clone();
    let persistence = MapPersistence::default();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

    // Build an encrypted state with a non-default member, persist it,
    // and spawn.
    let ctx_id_bytes = [0xC2u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        DID("did:example:admin".to_owned()),
    );
    // Mutate membership so the snapshot carries an observable field.
    // `is_member` reads `state.membership` (a `MembershipState`), and
    // restore derives the actor's member set from the snapshot's
    // `membership`, so add through the membership API (NOT the `members`
    // HashSet, which the snapshot does not persist).
    let member = DID("did:example:preserved-member".to_owned());
    state
        .membership
        .add_member(member.clone(), "member".to_owned(), Vec::new());
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    let snap = crate::context::manager_methods::snapshot_context(&state);
    // The snapshot's routing axis must be encrypted (not broadcast) —
    // the §9.10.4 axis carried through restore.
    assert!(
        !snap.routing.is_broadcast(),
        "encrypted context snapshot must carry a non-broadcast routing axis"
    );
    persistence.persist_context(&ctx_key, &snap).await.unwrap();

    let deps = test_actor_deps(&sup).await;
    let handle = sup
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn registers");

    // Crash once (below threshold).
    induce_panic(&handle, "SECRET_SENTINEL_abc123").await;

    // Wait for a RESPONSIVE respawned actor. A bare `lookup().is_some()`
    // is not sufficient: between the crash and the watchdog's
    // despawn-then-respawn, the dead actor's handle still lingers in the
    // registry, so we must wait until a live query actually succeeds —
    // i.e. the respawned actor answers `read_context_state`.
    let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
        sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
            && !sup.is_context_poisoned(&ctx_key)
    })
    .await;
    assert!(
        respawned,
        "a single crash must respawn a RESPONSIVE actor from the snapshot"
    );

    // Query membership through the supervisor's mailbox dispatch (the
    // production read path, which re-resolves the live actor each call)
    // — the persisted member is present, proving the snapshot was
    // rehydrated.
    let is_member = {
        let (tx, rx) = tokio::sync::oneshot::channel();
        sup.dispatch_query(crate::context::actor::commands::QueriesCommand::IsMember {
            context_id: ctx_key.clone(),
            did: member.to_string(),
            reply: tx,
        })
        .await
        .expect("dispatch_query routes to the respawned actor");
        rx.await.expect("respawned actor replies")
    };
    assert_eq!(
        is_member.ok(),
        Some(true),
        "respawned context must preserve the persisted membership"
    );

    // §9.10.4 routing-axis assertion: an encrypted context that
    // rehydrated as broadcast would have failed the restore-time
    // routing-agreement check (`restore_context` fails closed when the
    // snapshot's routing variant disagrees with the reconstructed mode),
    // so reaching a responsive Active state at all proves the encrypted
    // routing axis survived the snapshot round-trip.
    assert_eq!(
        sup.read_context_state(&ctx_key).await,
        Some(crate::context::ContextState::Active),
        "respawned encrypted context must be Active with its routing axis intact"
    );
}

/// An actor that crashes while a create, import or join of its id holds
/// the id's first-state claim is not respawned while the claim stands,
/// since its snapshot may be the one the operation's rollback puts back,
/// and is respawned from the snapshot once the operation rolls back.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_under_an_unsettled_first_state_is_respawned_after_the_rollback() {
    let clock = Arc::new(TestClock::new(1_700_000_000));
    let clock_dyn: Arc<dyn Clock> = clock.clone();
    let persistence = MapPersistence::default();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));
    let ctx_id_bytes = [0xC9u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        DID("did:example:admin".to_owned()),
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    let snap = crate::context::manager_methods::snapshot_context(&state);
    persistence.persist_context(&ctx_key, &snap).await.unwrap();
    let deps = test_actor_deps(&sup).await;
    let claim =
        crate::context::shared::lifecycle::FirstStateRollback::new(&deps, &ctx_key).unwrap();
    let handle = sup
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn registers");

    induce_panic(&handle, "SECRET_SENTINEL_claimed").await;
    let respawned_early = wait_until_async(std::time::Duration::from_millis(500), || async {
        sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
    })
    .await;
    assert!(
        !respawned_early,
        "no actor is respawned while the first state is unsettled"
    );

    claim
        .rollback(sup.bootstrap_spawn_lock.lock())
        .await
        .expect("the operation rolls back");
    let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
        sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
            && !sup.is_context_poisoned(&ctx_key)
    })
    .await;
    assert!(
        respawned,
        "the crashed actor is respawned once the first state settles"
    );
}

/// §23.17.2 Invariant 2 (the round-2 HIGH-bug regression test): a respawn
/// from a COALESCE-LAGGED snapshot — one whose per-sender epoch floor is
/// BELOW the live floor because the epoch advanced in the ≤50ms window
/// before the crash — must SUCCEED, max-merging the live floor, NOT fail
/// (which would poison a healthy context). The crash-surviving live floor
/// (Class M, supervisor-owned crypto provider) is authoritative.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respawn_from_coalesce_lagged_snapshot_max_merges_floor() {
    let clock = Arc::new(TestClock::new(1_700_000_000));
    let clock_dyn: Arc<dyn Clock> = clock.clone();
    let persistence = MapPersistence::default();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

    let ctx_id_bytes = [0xC7u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let sender_did = "did:dht:z6MkLaggedSenderLaggedSenderLaggedSenderXX";

    // Stand up live MLS + sender-key crypto so the snapshot carries a
    // non-empty `mls_crypto_state` (otherwise the floor guard is skipped).
    let crypto = sup
        .crypto_ref()
        .expect("test supervisor has crypto")
        .clone();
    // Create the group with the SAME creator-committed `scp_context_params`
    // (`0xFF02`) extension the honest creator commits, bound to this
    // context's id + params — so the load-time §5.13.3 binding check on the
    // respawn path (`restore_context`) passes on this legitimate
    // self-respawn, exactly as a real persisted group would. The snapshot's
    // `context_params` are the state handle's params (see
    // `new_for_test_encrypted`: the defaults plus a `MessagesRead`
    // ceiling), and its `context_id` is `ctx_key`, so the extension is
    // bound to precisely those values.
    let ctx_params = scp_protocol::context::ContextParams {
        ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
        ..scp_protocol::context::ContextParams::default()
    };
    // The committed genesis creator must equal the snapshot's
    // `role_state.creator_did` so the restore-time §5.13.3 rule-8 creator
    // binding passes on this legitimate self-respawn. The state below is
    // built via `new_for_test_encrypted`, whose `role_state` is the empty
    // test role state (`ContextRoleState::empty_for_test`, `creator_did =
    // ""`) — so the honest committed creator here is the same empty DID
    // the snapshot carries. The committed creation timestamp equals the
    // `created_at` the state is built with, which the snapshot records
    // (§5.13.3 rule 9).
    let ctx_ceiling =
        scp_protocol::context::roles::CapabilityCeiling::new(ctx_params.ceiling.clone());
    let ctx_extension = scp_protocol::context::ScpContextExtension::for_root(
        scp_protocol::context::ScpContextGenesis {
            context_id: ctx_key.clone(),
            creator_did: DID(String::new()),
            creation_timestamp_secs: 1_700_000_000,
            mode: ctx_params.mode,
            governance: &ctx_params.governance,
            ceiling_policy: ctx_params.ceiling_policy,
            ceiling: &ctx_ceiling,
        },
    )
    .expect("build scp_context_params (0xFF02) extension for respawn fixture");

    // ADR-049 PR-6: the AUTHORITATIVE per-sender floor lives in the
    // Supervisor-owned Class-M registry. Advance it to epoch 5 — the
    // coalesced state captured into the snapshot below.
    sup.check_and_advance_sender_epoch(
        &ctx_id_bytes,
        sender_did,
        5,
        scp_protocol::crypto::sender_keys::MAX_EPOCH_ADVANCE,
    )
    .expect("seed registry floor to epoch 5");

    let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        DID("did:example:admin".to_owned()),
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    let mut snap = crate::context::manager_methods::snapshot_context(&state);
    // Capture the live crypto state INCLUDING the registry floor (=5) into
    // the persisted snapshot, exactly as `build_snapshot_for_persist` does
    // (floors sourced from the authoritative registry).
    snap.mls_crypto_state = crate::context::state::MlsCryptoState(
        actor_export(
            &crypto,
            &ctx_id_bytes,
            &ctx_extension,
            sup.export_sender_key_epochs(&ctx_id_bytes),
            sup.export_recv_sequence_floors(&ctx_id_bytes),
        )
        .unwrap(),
    );
    assert!(
        !snap.mls_crypto_state.is_empty(),
        "snapshot must carry crypto state so the floor guard runs on respawn"
    );
    persistence.persist_context(&ctx_key, &snap).await.unwrap();

    let deps = test_actor_deps(&sup).await;
    let handle = sup
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn registers");

    // The LIVE floor advances to epoch 12 AFTER the snapshot was persisted
    // — the snapshot now lags the live floor by 7 epochs. This live floor
    // survives the crash (it lives in the supervisor-owned Class-M registry,
    // which a mailbox/handle despawn does not tear down).
    sup.check_and_advance_sender_epoch(
        &ctx_id_bytes,
        sender_did,
        12,
        scp_protocol::crypto::sender_keys::MAX_EPOCH_ADVANCE,
    )
    .expect("advance registry floor to epoch 12");

    // Crash before any re-persist of the advanced floor.
    induce_panic(&handle, "SECRET_SENTINEL_lagged").await;

    // The respawn MUST succeed (round-2 bug: it failed with
    // SnapshotFloorRegression and poisoned the context).
    let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
        sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
            && !sup.is_context_poisoned(&ctx_key)
    })
    .await;
    assert!(
        respawned,
        "a respawn from a coalesce-lagged snapshot (floor 5 < live 12) must SUCCEED \
             and max-merge — not reject and poison the context"
    );
    assert!(
        !sup.is_context_poisoned(&ctx_key),
        "a healthy context must not be poisoned by a benign coalesce-lag floor regression"
    );

    // ADR-049 PR-6: the AUTHORITATIVE registry floor is the higher LIVE
    // value (12) after the respawn max-merges the snapshot's stale 5 — never
    // lowered to 5. `restore_crypto_state_with_floor_guard` merges the
    // snapshot floors (incoming=5) INTO the live registry (12) under
    // MaxMergeTrustedLocal, so 12 dominates.
    let merged = sup.export_sender_key_epochs(&ctx_id_bytes);
    assert!(
        merged.iter().any(|(d, e)| d == sender_did && *e == 12),
        "authoritative registry floor must be the higher live value (12), got {merged:?}"
    );
}

/// ADR-049 PR-6 §0.1 — COLD-RESTART DURABILITY (the D2 regression guard).
///
/// Advances the authoritative Class-M registry floors non-trivially, persists
/// the durable blob FROM the registry, then restores that blob into a FRESH
/// Supervisor whose registry starts EMPTY (the cold restart — the origin
/// registry is not shared). Asserts the fresh registry is EMPTY-then-POPULATED
/// from the blob (this is the exact line the deleted provider
/// `local_floors.is_empty()` short-circuit would have broken — it skips the
/// merge on an empty live registry, silently losing the blob floors) and that
/// a replay AT or BELOW the restored recv floor is REJECTED by the same gate
/// primitive the `deliver_incoming` recv seam calls fail-closed
/// (`check_and_advance_recv_sequence`; the seam→gate wiring is enforced
/// structurally in `pipeline_wiring.rs`).
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::too_many_lines,
    reason = "single cohesive cold-restart D2 scenario: advance floors, persist, fresh-restore, assert empty-then-populated + replay-rejected — splitting it would obscure the one flow"
)]
async fn cold_restart_restores_floors_into_fresh_registry_and_rejects_replay() {
    use scp_protocol::context::builder::ReceiveFloor;
    use scp_protocol::crypto::sender_keys::MAX_EPOCH_ADVANCE;

    let ctx = [0xD2u8; 32];
    let sender = "did:dht:z6MkColdRestartSenderColdRestartSenderXX";

    // Origin node: keyed context + non-trivially advanced registry floors.
    let origin = supervisor_with_providers();
    let origin_crypto = origin.crypto_ref().expect("origin crypto").clone();
    origin
        .check_and_advance_sender_epoch(&ctx, sender, 4, MAX_EPOCH_ADVANCE)
        .unwrap();
    origin
        .check_and_advance_recv_sequence(
            &ctx,
            sender,
            ReceiveFloor {
                epoch: 3,
                sequence: 5,
            },
            MAX_EPOCH_ADVANCE,
        )
        .unwrap();

    // Persist the durable blob, floors sourced FROM the registry (the G2 path).
    let blob = actor_export(
        &origin_crypto,
        &ctx,
        &test_ctx_ext(&ctx),
        origin.export_sender_key_epochs(&ctx),
        origin.export_recv_sequence_floors(&ctx),
    )
    .unwrap();
    assert!(
        !blob.is_empty(),
        "keyed context must export a non-empty blob"
    );

    // FRESH node: a NEW Supervisor (EMPTY registry) + a new provider. The
    // origin registry is NOT shared — this is the cold restart.
    let fresh = supervisor_with_providers();
    let fresh_deps = test_actor_deps(&fresh).await;
    assert!(
        fresh.export_sender_key_epochs(&ctx).is_empty(),
        "fresh registry must start EMPTY (the cold-restart precondition)"
    );
    assert!(fresh.export_recv_sequence_floors(&ctx).is_empty());

    crate::context::restored_crypto::restore_crypto_state_with_floor_guard(
        &fresh_deps,
        &ctx,
        &verified_test_floors(&ctx, &blob),
        true,
    )
    .expect("cold restore must SUCCEED and populate the empty registry");

    // D2 CORE: the empty registry was POPULATED from the blob. This is the
    // empty-short-circuit catcher.
    assert_eq!(
        fresh.export_sender_key_epochs(&ctx),
        vec![(sender.to_owned(), 4)],
        "epoch floor must be populated from the blob on cold restart"
    );
    assert_eq!(
        fresh.export_recv_sequence_floors(&ctx),
        vec![(
            sender.to_owned(),
            ReceiveFloor {
                epoch: 3,
                sequence: 5
            }
        )],
        "recv floor must be populated from the blob on cold restart"
    );

    // D2 CLOSE: a replay AT the restored floor is rejected …
    assert!(
        fresh
            .check_and_advance_recv_sequence(
                &ctx,
                sender,
                ReceiveFloor {
                    epoch: 3,
                    sequence: 5
                },
                MAX_EPOCH_ADVANCE
            )
            .is_err(),
        "a replay AT the restored recv floor must be rejected after cold restart"
    );
    // … and BELOW it …
    assert!(
        fresh
            .check_and_advance_recv_sequence(
                &ctx,
                sender,
                ReceiveFloor {
                    epoch: 2,
                    sequence: 9
                },
                MAX_EPOCH_ADVANCE
            )
            .is_err(),
        "a replay BELOW the restored recv floor must be rejected after cold restart"
    );
    // … while a strictly-higher floor still advances (liveness preserved).
    assert!(
        fresh
            .check_and_advance_recv_sequence(
                &ctx,
                sender,
                ReceiveFloor {
                    epoch: 3,
                    sequence: 6
                },
                MAX_EPOCH_ADVANCE
            )
            .is_ok(),
        "a legitimate higher recv floor must still advance after cold restart"
    );
}

/// ADR-049 PR-6 BUG-1 — an UNTRUSTED import whose blob floor REGRESSES below
/// the live registry floor must be REJECTED (`Err(CryptoFailed)`), roll the
/// just-restored crypto back (provider group destroyed), and leave the
/// registry UNCHANGED (atomic — the validating merge validates before it
/// applies, so a rejected merge touches nothing).
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn untrusted_import_regressing_floor_is_rejected_and_atomic() {
    use scp_protocol::crypto::sender_keys::MAX_EPOCH_ADVANCE;

    let ctx = [0xB1u8; 32];
    let sender = "did:dht:z6MkBug1SenderBug1SenderBug1SenderBug1XX";

    // Exporter snapshot carries a LOW sender-epoch floor (=2).
    let exporter = supervisor_with_providers();
    let exporter_crypto = exporter.crypto_ref().expect("exporter crypto").clone();
    exporter
        .check_and_advance_sender_epoch(&ctx, sender, 2, MAX_EPOCH_ADVANCE)
        .unwrap();
    let blob = actor_export(
        &exporter_crypto,
        &ctx,
        &test_ctx_ext(&ctx),
        exporter.export_sender_key_epochs(&ctx),
        exporter.export_recv_sequence_floors(&ctx),
    )
    .unwrap();

    // Importer's LIVE registry floor for `sender` is HIGHER (=9).
    let importer = supervisor_with_providers();
    let importer_crypto = importer.crypto_ref().expect("importer crypto").clone();
    let importer_deps = test_actor_deps(&importer).await;
    importer
        .check_and_advance_sender_epoch(&ctx, sender, 9, MAX_EPOCH_ADVANCE)
        .unwrap();
    let before = importer.export_sender_key_epochs(&ctx);

    // Untrusted import (trusted_local=false): blob floor 2 < live floor 9 →
    // RejectRegression → Err(CryptoFailed).
    let err = crate::context::restored_crypto::restore_crypto_state_with_floor_guard(
        &importer_deps,
        &ctx,
        &verified_test_floors(&ctx, &blob),
        false,
    )
    .expect_err("a regressing untrusted import must be rejected");
    assert!(
        matches!(err, ContextError::CryptoFailed(_)),
        "regressing import must map to CryptoFailed, got {err:?}"
    );

    // Atomic: the registry is UNCHANGED (still 9, never lowered to 2).
    assert_eq!(
        importer.export_sender_key_epochs(&ctx),
        before,
        "a rejected import must leave the registry unchanged (atomic)"
    );
    assert!(
        importer
            .export_sender_key_epochs(&ctx)
            .iter()
            .any(|(d, e)| d == sender && *e == 9),
        "the live floor (9) must survive the rejected import"
    );

    // #2148 (ADR-049 birth-into-actor): rollback = the owned material is
    // dropped on the Err path (the `SenderKey` and the MLS group's signer
    // zeroize on drop) and never seeded onto an actor. The
    // provider holds NO per-context state (the `contexts` map and the
    // `context_crypto_present` residency probe are deleted), so there is no
    // provider residency to assert — the floor-registry state above is the
    // observable evidence the rejected import left nothing behind.
    let _ = &importer_crypto;
}

/// ADR-049 A2 — a cold restart of a context whose per-sender epoch high-water
/// EXCEEDS `MAX_EPOCH_ADVANCE` (1000) must SUCCEED under trusted-local and
/// reject a replay at or below the restored floor. The pre-A2 code applied the
/// overshoot ceiling on the trusted restore path too (`local=0` on a cold
/// registry → `ceiling=1000`), which would have made any such context
/// PERMANENTLY unrestorable.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_restart_high_epoch_beyond_ceiling_restores_under_trusted_local() {
    use scp_protocol::context::builder::ReceiveFloor;
    use scp_protocol::crypto::sender_keys::MAX_EPOCH_ADVANCE;

    let ctx = [0xE5u8; 32];
    let sender = "did:dht:z6MkHighEpochSenderHighEpochSenderHighXX";
    let high = 5_000u64; // > MAX_EPOCH_ADVANCE (1000)
    assert!(high > MAX_EPOCH_ADVANCE);

    let origin = supervisor_with_providers();
    let origin_crypto = origin.crypto_ref().expect("origin crypto").clone();
    origin
        .check_and_advance_sender_epoch(&ctx, sender, high, high)
        .unwrap();
    origin
        .check_and_advance_recv_sequence(
            &ctx,
            sender,
            ReceiveFloor {
                epoch: high,
                sequence: 2,
            },
            high,
        )
        .unwrap();
    let blob = actor_export(
        &origin_crypto,
        &ctx,
        &test_ctx_ext(&ctx),
        origin.export_sender_key_epochs(&ctx),
        origin.export_recv_sequence_floors(&ctx),
    )
    .unwrap();

    // Cold restart: fresh Supervisor, EMPTY registry (local=0), trusted_local.
    let fresh = supervisor_with_providers();
    let fresh_deps = test_actor_deps(&fresh).await;
    crate::context::restored_crypto::restore_crypto_state_with_floor_guard(
        &fresh_deps,
        &ctx,
        &verified_test_floors(&ctx, &blob),
        true,
    )
    .expect("a high-epoch (>MAX_EPOCH_ADVANCE) context must restore under trusted-local");

    assert_eq!(
        fresh.export_sender_key_epochs(&ctx),
        vec![(sender.to_owned(), high)],
        "the high epoch floor must load VERBATIM on a trusted cold restart"
    );
    // A replay at the restored recv floor is still rejected.
    assert!(
        fresh
            .check_and_advance_recv_sequence(
                &ctx,
                sender,
                ReceiveFloor {
                    epoch: high,
                    sequence: 2
                },
                MAX_EPOCH_ADVANCE
            )
            .is_err(),
        "a replay at the restored high recv floor must be rejected"
    );
}

/// ADR-049 BUG-1b — an untrusted import whose EPOCH floor validates (>= live,
/// within ceiling) but whose RECV floor REGRESSES must be rejected AND leave
/// the epoch floor UNCHANGED — the cross-axis atomicity guarantee (the epoch
/// merge must NOT stick when the recv merge rejects).
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn untrusted_import_recv_regression_leaves_epoch_floor_unchanged() {
    use scp_protocol::context::builder::ReceiveFloor;
    use scp_protocol::crypto::sender_keys::MAX_EPOCH_ADVANCE;

    let ctx = [0xB2u8; 32];
    let sender = "did:dht:z6MkBug1bSenderBug1bSenderBug1bSenderXX";

    // Exporter blob: epoch 9 (will be >= importer live), recv rf(2, 0) (will
    // regress below importer live recv).
    let exporter = supervisor_with_providers();
    let exporter_crypto = exporter.crypto_ref().expect("exporter crypto").clone();
    exporter
        .check_and_advance_sender_epoch(&ctx, sender, 9, MAX_EPOCH_ADVANCE)
        .unwrap();
    exporter
        .check_and_advance_recv_sequence(
            &ctx,
            sender,
            ReceiveFloor {
                epoch: 2,
                sequence: 0,
            },
            MAX_EPOCH_ADVANCE,
        )
        .unwrap();
    let blob = actor_export(
        &exporter_crypto,
        &ctx,
        &test_ctx_ext(&ctx),
        exporter.export_sender_key_epochs(&ctx),
        exporter.export_recv_sequence_floors(&ctx),
    )
    .unwrap();

    // Importer live: epoch 5 (< blob's 9 → epoch axis PASSES), recv rf(4, 0)
    // (> blob's rf(2,0) → recv axis REGRESSES under RejectRegression).
    let importer = supervisor_with_providers();
    let importer_deps = test_actor_deps(&importer).await;
    importer
        .check_and_advance_sender_epoch(&ctx, sender, 5, MAX_EPOCH_ADVANCE)
        .unwrap();
    importer
        .check_and_advance_recv_sequence(
            &ctx,
            sender,
            ReceiveFloor {
                epoch: 4,
                sequence: 0,
            },
            MAX_EPOCH_ADVANCE,
        )
        .unwrap();
    let epoch_before = importer.export_sender_key_epochs(&ctx);
    let recv_before = importer.export_recv_sequence_floors(&ctx);

    let err = crate::context::restored_crypto::restore_crypto_state_with_floor_guard(
        &importer_deps,
        &ctx,
        &verified_test_floors(&ctx, &blob),
        false,
    )
    .expect_err("a recv-floor regression on an untrusted import must be rejected");
    assert!(matches!(err, ContextError::CryptoFailed(_)), "got {err:?}");

    // CROSS-AXIS ATOMICITY: the epoch floor did NOT advance to 9 despite the
    // epoch axis validating — the whole merge was rejected atomically.
    assert_eq!(
        importer.export_sender_key_epochs(&ctx),
        epoch_before,
        "epoch floor must be UNCHANGED (5) — the epoch merge must not stick when recv rejects"
    );
    assert_eq!(importer.export_recv_sequence_floors(&ctx), recv_before);
}

/// Seals a `Content` inner envelope that Alice (`sender`, signing with
/// `alice_signing_key`) sends at `epoch`, through her actor state as the
/// send path does.
#[cfg(feature = "testing")]
fn alice_seals_content(
    state: &mut crate::context::actor::PerContextState,
    ctx_str: &str,
    sender: &str,
    epoch: u64,
    payload: &[u8],
) -> Vec<u8> {
    let params = crate::envelope::inner::InnerEnvelopeParams {
        version: scp_protocol::envelope::SCP_PROTOCOL_VERSION,
        context_id: ctx_str,
        sender_did: sender,
        epoch,
        generation: 0,
        sequence: 0,
        timestamp: 1_700_000_000,
        message_type: crate::envelope::inner::MessageType::Content,
        payload,
        provenance: None,
        signing_key_id: scp_did::SigningKeyId::Active,
    };
    let inner = crate::envelope::inner::sign::create_inner_envelope_raw(
        &params,
        &crate::crypto::mls::two_party_test_support::alice_signing_key(),
    )
    .expect("the sender signs its inner envelope");
    state
        .seal(sender, &inner)
        .expect("the sender seals the application message")
}

/// ADR-049 §9(1) FAIL-CLOSED-BLOCKS (e2e). Alice seals two REAL application
/// envelopes through the joined MLS group; Bob opens them with the
/// production `decrypt_and_dispatch` seam and feeds each surfaced
/// `receive_floor` to the Supervisor recv-floor gate, as `deliver_incoming`
/// does after verification. Proves that (a) the surfaced floor is correct and
/// the gate consumes it into the authoritative registry, and (b) an
/// out-of-order or replayed older floor is rejected fail-closed.
#[cfg(feature = "testing")]
#[test]
fn recv_floor_gate_blocks_reorder_and_replay_e2e() {
    const ALICE: &str = "did:dht:z6MkAliceE2eSenderAliceE2eSenderAlice1";
    const BOB: &str = "did:dht:z6MkBobE2eReceiverBobE2eReceiverBob123";
    let ctx_str = "e2e-decrypt-and-dispatch-fail-closed";

    // Real two-party join, born DIRECTLY onto actor-owned state: Bob's actor
    // holds the group + Alice's pulled sender key at epoch 1, Alice's actor
    // owns her group + sender key.
    let crate::crypto::mls::two_party_test_support::TwoPartyPair {
        alice_state: mut alice_actor,
        bob_provider: bob_crypto,
        bob_state: mut bob_actor,
        ctx_bytes,
        ..
    } = crate::crypto::mls::two_party_test_support::stand_up_two_party(ctx_str, ALICE, BOB);

    // Wrap Bob's provider in a fresh Supervisor (empty registry) and build his
    // production ActorDeps. App-data delivery never touches the provider's
    // per-context crypto (Bob's crypto lives on his actor state), so the
    // groupless `bob_deps.crypto` is only read for `local_did`.
    let bob_sup = supervisor_with_crypto(Arc::clone(&bob_crypto));
    let rt = tokio::runtime::Builder::new_current_thread() // ci-allow: block-on: test-only, builds Bob's ActorDeps from a sync #[test]; not a production async bridge
        .enable_all()
        .build()
        .unwrap();
    let bob_deps = rt
        .block_on(bob_sup.build_actor_deps_loaded(&DID::from(BOB)))
        .expect("build bob's actor deps");

    let msg_a = alice_seals_content(
        &mut alice_actor,
        ctx_str,
        ALICE,
        1,
        b"first-application-message",
    ); // header sequence 0
    let msg_b = alice_seals_content(
        &mut alice_actor,
        ctx_str,
        ALICE,
        1,
        b"second-application-message",
    ); // header sequence 1

    // Hand `decrypt_and_dispatch` Bob's actor-owned crypto state: the receive
    // seam opens through the actor's `&mut ContextCryptoState`.
    let crate::context::actor::ContextModeState::Encrypted(bob_cs) = &mut bob_actor.mode else {
        panic!("expected encrypted mode")
    };
    let mut open = |msg: &[u8]| {
        rt.block_on(crate::context::messaging_helpers::decrypt_and_dispatch(
            &bob_deps,
            Some(&mut *bob_cs),
            ctx_str,
            &ctx_bytes,
            msg,
            &std::collections::HashSet::new(),
        ))
        .map(|dispatched| match dispatched {
            crate::context::shared::messaging::Dispatched::Envelope(env) => Some(*env),
            _ => None,
        })
    };

    // The gate `deliver_incoming` runs once the inner envelope verifies.
    let gate = |floor| {
        bob_sup
            .check_and_advance_recv_sequence(
                &ctx_bytes,
                ALICE,
                floor,
                scp_protocol::crypto::sender_keys::MAX_EPOCH_ADVANCE,
            )
            .map_err(ContextError::from)
    };

    // Deliver the LATER message (b, sequence 1) FIRST. Accepted; the registry
    // recv floor advances to exactly the surfaced receive_floor.
    let opened_b = open(&msg_b)
        .expect("first (in-order) delivery must succeed")
        .expect("an Application envelope must surface");
    let floor_b = opened_b.receive_floor;
    gate(floor_b).expect("the first floor is accepted");
    assert_eq!(
        bob_sup.export_recv_sequence_floors(&ctx_bytes),
        vec![(ALICE.to_owned(), floor_b)],
        "the recv seam must CONSUME the surfaced receive_floor into the registry"
    );

    // Now deliver the EARLIER message (a, sequence 0) — a DISTINCT, never-seen
    // MLS ciphertext (so MLS decrypts it), but an older floor. The authoritative
    // registry recv gate MUST reject it fail-closed.
    let opened_a = open(&msg_a)
        .expect("MLS decrypts the distinct older ciphertext")
        .expect("an Application envelope must surface");
    let reorder = gate(opened_a.receive_floor);
    // Pin the REASON: the rejection must be the registry recv-floor gate
    // (`FloorAdvanceError::RecvSequenceNotMonotonic`, whose Display is
    // "recv-sequence floor … is non-monotonic …"), NOT an MLS-decrypt failure
    // — so a future OpenMLS `out_of_order_tolerance` change can't silently
    // turn this into a pass-for-the-wrong-reason.
    assert!(
        matches!(
            &reorder,
            Err(ContextError::CryptoFailed(m))
                if m.contains("recv-sequence floor") && m.contains("non-monotonic")
        ),
        "an out-of-order older floor must be rejected by the registry recv-floor gate, got {reorder:?}"
    );
    // The registry floor is unchanged by the rejected reorder.
    assert_eq!(
        bob_sup.export_recv_sequence_floors(&ctx_bytes),
        vec![(ALICE.to_owned(), floor_b)],
        "a rejected reorder must not move the registry floor"
    );

    // A replay of the accepted message b is also rejected: MLS refuses the
    // reused ciphertext, and its floor would not pass the gate either.
    let replay = open(&msg_b);
    assert!(
        replay.is_err(),
        "a replay of an already-accepted message must be rejected, got {replay:?}"
    );
    assert!(
        gate(floor_b).is_err(),
        "the accepted floor must not be accepted twice"
    );
}

/// Security-model spec §9.7.1, the receiver, on the native receive path.
/// Alice adds Carol on her actor state, and Bob's actor opens the add
/// Commit through `decrypt_and_dispatch` while his injected `ActorDeps`
/// clock reads `bob_clock_secs(not_before, not_after)` of Carol's
/// `Lifetime`. Asserts that Bob merges: his epoch advances by one and
/// Carol's leaf joins his member set. The wall clock stays inside Carol's
/// `Lifetime`, so openmls's own wall-clock reads pass, and only a
/// receive-side check against the injected clock could refuse the Add.
#[cfg(feature = "testing")]
fn actor_merges_add_under_receiver_clock(
    ctx_str: &str,
    alice: &str,
    bob: &str,
    carol: &str,
    bob_clock_secs: fn(u64, u64) -> u64,
) {
    use openmls::prelude::tls_codec::Serialize as _;
    use scp_clock::{Clock as _, SystemClock, TestClock};
    use scp_did::SigningKeyId;

    let crate::crypto::mls::two_party_test_support::TwoPartyPair {
        alice_state: mut alice_actor,
        bob_provider: bob_crypto,
        bob_state: mut bob_actor,
        ctx_bytes,
        ..
    } = crate::crypto::mls::two_party_test_support::stand_up_two_party(ctx_str, alice, bob);

    let bob_sup = supervisor_with_crypto(Arc::clone(&bob_crypto));
    let rt = tokio::runtime::Builder::new_current_thread() // ci-allow: block-on: test-only, builds Bob's ActorDeps from a sync #[test]; not a production async bridge
        .enable_all()
        .build()
        .unwrap();
    let mut bob_deps = rt
        .block_on(bob_sup.build_actor_deps_loaded(&DID::from(bob)))
        .expect("build Bob's actor deps");

    // Carol's KeyPackage is minted under the wall clock, so the wall clock
    // lies inside its `Lifetime`.
    let carol_credential =
        scp_mls::ScpCredential::new(carol.to_owned(), None, SigningKeyId::Active)
            .expect("Carol's credential");
    let (carol_bundle, carol_signer, _carol_provider) =
        scp_mls::group::generate_key_package_with_context_params(
            &carol_credential,
            &scp_crypto::p256::testing::uncompressed_point_for(carol),
            &SystemClock,
        )
        .expect("Carol's KeyPackage");
    let lifetime = carol_bundle.key_package().life_time();
    let (not_before, not_after) = (lifetime.not_before(), lifetime.not_after());
    let carol_kp = carol_bundle
        .key_package()
        .tls_serialize_detached()
        .expect("serialize Carol's KeyPackage");

    let commit = alice_actor
        .add_member(carol, Some(&carol_kp), &SystemClock)
        .expect("Alice adds Carol")
        .commit_bytes;

    let bob_now = bob_clock_secs(not_before, not_after);
    bob_deps.clock = Arc::new(TestClock::new(bob_now));
    let wall = SystemClock.now_secs();
    assert!(
        not_before <= wall && wall <= not_after,
        "the wall clock lies inside Carol's Lifetime"
    );
    assert!(
        bob_now < not_before || not_after < bob_now,
        "Bob's injected clock lies outside Carol's Lifetime"
    );

    let bob_cs = match &mut bob_actor.mode {
        crate::context::actor::ContextModeState::Encrypted(c) => c,
        crate::context::actor::ContextModeState::Broadcast(_) => {
            panic!("expected encrypted mode")
        }
    };
    let epoch_before = bob_cs
        .mls_group
        .as_ref()
        .expect("Bob's group")
        .epoch()
        .expect("Bob's epoch");
    let opened = rt
        .block_on(crate::context::messaging_helpers::decrypt_and_dispatch(
            &bob_deps,
            Some(&mut *bob_cs),
            ctx_str,
            &ctx_bytes,
            &commit,
            &std::collections::HashSet::new(),
        ))
        .expect("Bob merges the add-Carol Commit");
    assert!(
        matches!(
            opened,
            crate::context::shared::messaging::Dispatched::Commit { .. }
        ),
        "a Commit surfaces as a processed Commit, got {opened:?}"
    );
    let group = bob_cs.mls_group.as_ref().expect("Bob's group");
    assert_eq!(
        group.epoch().expect("Bob's epoch"),
        epoch_before + 1,
        "Bob's epoch advances by the add Commit"
    );
    let carol_key = carol_signer.to_public_vec();
    assert!(
        group
            .members()
            .expect("Bob's members")
            .iter()
            .any(|m| m.signature_key == carol_key),
        "Carol is in Bob's member set"
    );
}

/// Bob's injected clock stands past Carol's `not_after`: Bob merges.
#[cfg(feature = "testing")]
#[test]
fn decrypt_and_dispatch_merges_add_expired_under_receiver_clock() {
    actor_merges_add_under_receiver_clock(
        "e2e-decrypt-and-dispatch-add-expired-under-receiver-clock",
        "did:dht:z6MkAliceRecvExpiredAliceRecvExpiredAlice1",
        "did:dht:z6MkBobRecvExpiredBobRecvExpiredBobRecvExp1",
        "did:dht:z6MkCarolRecvExpiredCarolRecvExpiredCarol1",
        |_not_before, not_after| not_after + 1,
    );
}

/// Bob's injected clock stands before Carol's `not_before`: Bob merges.
#[cfg(feature = "testing")]
#[test]
fn decrypt_and_dispatch_merges_add_not_yet_valid_under_receiver_clock() {
    actor_merges_add_under_receiver_clock(
        "e2e-decrypt-and-dispatch-add-not-yet-valid-under-receiver-clock",
        "did:dht:z6MkAliceRecvEarlyAliceRecvEarlyAliceRecv1",
        "did:dht:z6MkBobRecvEarlyBobRecvEarlyBobRecvEarlyB1",
        "did:dht:z6MkCarolRecvEarlyCarolRecvEarlyCarolRec1",
        |not_before, _not_after| not_before - 3600,
    );
}

/// ADR-049 §9(2) CATCH-UP-AFTER-LAG (F-2, e2e). After Alice ROTATES her
/// sender key (epoch 1 → 2) and the key-distribution seam advances the
/// registry `sender_epochs[alice]` to 2, a recv from Alice at the NEW epoch is
/// ACCEPTED — proving the recv ceiling reads the just-advanced epoch floor
/// from the same registry (no stale-floor over-rejection).
#[cfg(feature = "testing")]
#[test]
fn recv_floor_gate_catch_up_after_epoch_rotation_e2e() {
    use scp_protocol::crypto::sender_keys::MAX_EPOCH_ADVANCE;

    const ALICE: &str = "did:dht:z6MkAliceCatchUpAliceCatchUpAliceCat1";
    const BOB: &str = "did:dht:z6MkBobCatchUpBobCatchUpBobCatchUpBob12";
    let ctx_str = "e2e-decrypt-and-dispatch-catch-up";

    let crate::crypto::mls::two_party_test_support::TwoPartyPair {
        alice_state: mut alice_actor,
        bob_provider: bob_crypto,
        bob_wrapping,
        bob_state: mut bob_actor,
        ctx_bytes,
        ..
    } = crate::crypto::mls::two_party_test_support::stand_up_two_party(ctx_str, ALICE, BOB);

    // Alice rotates her sender key (epoch 1 → 2) on her owned actor state and
    // redistributes it to Bob, who installs it on HIS owned actor state via
    // the actor-native receive-side seams — exactly what the live flow does.
    let rt = tokio::runtime::Builder::new_current_thread() // ci-allow: block-on: test-only, builds Bob's ActorDeps from a sync #[test]; not a production async bridge
        .enable_all()
        .build()
        .unwrap();
    alice_actor.rotate_sender_key(ALICE, None).unwrap();
    alice_actor.distribute_sender_key(ALICE, ALICE, None).ok();
    for (_t, msg) in alice_actor.drain_pending_sender_key_messages().unwrap() {
        if let Ok((key, _epoch)) = rt.block_on(
            crate::crypto::mls::provider::NodeMlsFactory::open_incoming_sender_key_bytes(
                &bob_wrapping,
                &bob_actor.context_id,
                ALICE,
                &msg,
            ),
        ) {
            bob_actor.set_sender_key_unchecked(ALICE, key);
        }
    }

    let bob_sup = supervisor_with_crypto(Arc::clone(&bob_crypto));
    let bob_deps = rt
        .block_on(bob_sup.build_actor_deps_loaded(&DID::from(BOB)))
        .expect("build bob's actor deps");

    // The key-distribution seam advanced the registry epoch floor to 2.
    bob_sup
        .check_and_advance_sender_epoch(&ctx_bytes, ALICE, 2, MAX_EPOCH_ADVANCE)
        .expect("key-dist seam advances the registry epoch floor to 2");

    // Alice seals at the NEW epoch (2); Bob's recv at epoch 2 is ACCEPTED (the
    // recv ceiling reads the just-advanced sender_epochs[alice]=2, not a stale
    // lower floor).
    let sealed = alice_seals_content(
        &mut alice_actor,
        ctx_str,
        ALICE,
        2,
        b"post-rotation-application-message",
    );

    // Hand Bob's actor-owned crypto state (carrying the rotated key installed
    // above) to the receive seam; it opens through the actor's
    // `&mut ContextCryptoState`.
    let bob_cs = match &mut bob_actor.mode {
        crate::context::actor::ContextModeState::Encrypted(c) => c,
        crate::context::actor::ContextModeState::Broadcast(_) => {
            panic!("expected encrypted mode")
        }
    };
    let opened = rt
        .block_on(crate::context::messaging_helpers::decrypt_and_dispatch(
            &bob_deps,
            Some(bob_cs),
            ctx_str,
            &ctx_bytes,
            &sealed,
            &std::collections::HashSet::new(),
        ))
        .expect("a recv at the just-advanced epoch must open");
    let crate::context::shared::messaging::Dispatched::Envelope(opened) = opened else {
        panic!("an Application envelope must surface, got {opened:?}");
    };
    assert_eq!(
        opened.receive_floor.epoch, 2,
        "the surfaced recv floor must be at the rotated epoch 2"
    );
    bob_sup
        .check_and_advance_recv_sequence(&ctx_bytes, ALICE, opened.receive_floor, MAX_EPOCH_ADVANCE)
        .expect("a recv at the just-advanced epoch must be ACCEPTED (no stale over-reject)");
    assert!(
        bob_sup
            .export_recv_sequence_floors(&ctx_bytes)
            .iter()
            .any(|(d, f)| d == ALICE && f.epoch == 2),
        "the registry recv floor must track the epoch-2 receive"
    );
}

/// Spec 09 §9.16.1: a KeyResponse on the production receive seam opens
/// through the owning identity's wrapping key in custody. Bob's loaded key
/// lives in a `DhCountingCustody`; Alice seals her rotated sender key to
/// it. Delivering the MLS-wrapped KeyResponse runs exactly one HpkeP256
/// `dh_agree`, and the opened key is installed: Alice's next application
/// message at the rotated epoch opens on Bob's state.
#[cfg(feature = "testing")]
#[tokio::test]
async fn key_response_opens_through_custody_dh_agree() {
    const ALICE: &str = "did:dht:z6MkAliceDhAgreeAliceDhAgreeAliceDhAgr1";
    const BOB: &str = "did:dht:z6MkBobDhAgreeBobDhAgreeBobDhAgreeBobD1";
    let ctx_str = "e2e-key-response-opens-through-custody";

    let crate::crypto::mls::two_party_test_support::TwoPartyPair {
        alice_state: mut alice_actor,
        bob_provider: bob_crypto,
        bob_state: mut bob_actor,
        ctx_bytes,
        ..
    } = crate::crypto::mls::two_party_test_support::stand_up_two_party(ctx_str, ALICE, BOB);

    let custody = Arc::new(crate::crypto::dh_counting_custody::DhCountingCustody::new());
    let bob_key = crate::crypto::wrapping::test_wrapping_key(&custody)
        .await
        .expect("bob's wrapping key is created in custody");
    let bob_sup = supervisor_with_crypto(Arc::clone(&bob_crypto));
    bob_sup
        .wrapping_keys
        .insert(DID::from(BOB), Arc::clone(&bob_key));
    let bob_deps = bob_sup
        .build_actor_deps(&DID::from(BOB))
        .await
        .expect("build bob's actor deps over his loaded key");

    // Alice records Bob's custody key as his wrapping key, rotates, and so
    // seals her new sender key to it.
    let alice_cs = alice_actor.mode.crypto_mut().expect("encrypted context");
    alice_cs.member_wrapping_keys.insert(
        BOB.to_owned(),
        scp_protocol::crypto::hpke::p256::P256Point::try_from(*bob_key.public()).unwrap(),
    );
    alice_actor.rotate_sender_key(ALICE, None).unwrap();
    let rotated_epoch = alice_actor.local_sender_key_epoch();
    let msgs = alice_actor.drain_pending_sender_key_messages().unwrap();
    assert_eq!(msgs.len(), 1, "one KeyResponse for Bob");
    let sealed = alice_actor
        .mode
        .crypto_mut()
        .expect("encrypted context")
        .mls_encrypt_management(&msgs[0].1)
        .expect("alice MLS-wraps the KeyResponse");

    let bob_cs = bob_actor.mode.crypto_mut().expect("encrypted context");
    let opened = crate::context::messaging_helpers::decrypt_and_dispatch(
        &bob_deps,
        Some(&mut *bob_cs),
        ctx_str,
        &ctx_bytes,
        &sealed,
        &std::collections::HashSet::new(),
    )
    .await
    .expect("bob opens the KeyResponse through custody");
    assert!(
        matches!(
            opened,
            crate::context::shared::messaging::Dispatched::Handled
        ),
        "a KeyResponse surfaces no envelope, got {opened:?}"
    );
    assert_eq!(
        custody.dh_calls(),
        1,
        "exactly one dh_agree per KeyResponse"
    );

    let app = alice_seals_content(
        &mut alice_actor,
        ctx_str,
        ALICE,
        rotated_epoch,
        b"after-key-response",
    );
    let opened = crate::context::messaging_helpers::decrypt_and_dispatch(
        &bob_deps,
        Some(&mut *bob_cs),
        ctx_str,
        &ctx_bytes,
        &app,
        &std::collections::HashSet::new(),
    )
    .await
    .expect("the installed sender key opens alice's message");
    let crate::context::shared::messaging::Dispatched::Envelope(opened) = opened else {
        panic!("an Application envelope must surface, got {opened:?}");
    };
    assert_eq!(opened.receive_floor.epoch, rotated_epoch);
    assert_eq!(
        custody.dh_calls(),
        1,
        "an application open runs no dh_agree"
    );
}

/// The KeyResponse arm refuses a response from its public fields before
/// any custody call: one that names a sender other than its MLS sender,
/// and one whose epoch is at or below Bob's recorded floor for Alice. Each
/// delivery fails closed and Bob's custody records zero `dh_agree` calls.
/// `key_response_opens_through_custody_dh_agree` is the positive control:
/// the same delivery, unmodified and above the floor, runs one `dh_agree`.
#[cfg(feature = "testing")]
#[tokio::test]
async fn key_response_public_checks_run_before_custody() {
    use scp_protocol::crypto::sender_keys::{MAX_EPOCH_ADVANCE, SenderKeyDistributionMessage};

    const ALICE: &str = "did:dht:z6MkAlicePublicChkAlicePublicChkAlicePu1";
    const BOB: &str = "did:dht:z6MkBobPublicChkBobPublicChkBobPublicChk1";
    const MALLORY: &str = "did:dht:z6MkMalloryPublicChkMalloryPublicChkMa1";
    let ctx_str = "e2e-key-response-public-checks";

    let crate::crypto::mls::two_party_test_support::TwoPartyPair {
        alice_state: mut alice_actor,
        bob_provider: bob_crypto,
        bob_state: mut bob_actor,
        ctx_bytes,
        ..
    } = crate::crypto::mls::two_party_test_support::stand_up_two_party(ctx_str, ALICE, BOB);

    let custody = Arc::new(crate::crypto::dh_counting_custody::DhCountingCustody::new());
    let bob_key = crate::crypto::wrapping::test_wrapping_key(&custody)
        .await
        .expect("bob's wrapping key is created in custody");
    let bob_sup = supervisor_with_crypto(Arc::clone(&bob_crypto));
    bob_sup
        .wrapping_keys
        .insert(DID::from(BOB), Arc::clone(&bob_key));
    let bob_deps = bob_sup
        .build_actor_deps(&DID::from(BOB))
        .await
        .expect("build bob's actor deps over his loaded key");

    let alice_cs = alice_actor.mode.crypto_mut().expect("encrypted context");
    alice_cs.member_wrapping_keys.insert(
        BOB.to_owned(),
        scp_protocol::crypto::hpke::p256::P256Point::try_from(*bob_key.public()).unwrap(),
    );
    alice_actor.rotate_sender_key(ALICE, None).unwrap();
    let rotated_epoch = alice_actor.local_sender_key_epoch();
    let msgs = alice_actor.drain_pending_sender_key_messages().unwrap();
    assert_eq!(msgs.len(), 1, "one KeyResponse for Bob");
    let SenderKeyDistributionMessage::KeyResponse(response) =
        SenderKeyDistributionMessage::from_bytes(&msgs[0].1).unwrap()
    else {
        panic!("alice queued a KeyResponse");
    };
    let mut wrap = |payload: &[u8]| {
        alice_actor
            .mode
            .crypto_mut()
            .expect("encrypted context")
            .mls_encrypt_management(payload)
            .expect("alice MLS-wraps the KeyResponse")
    };

    // Alice is the MLS sender; the response names Mallory.
    let mut forged = response.clone();
    forged.sender_did = MALLORY.to_owned();
    let forged_sealed = wrap(
        &SenderKeyDistributionMessage::KeyResponse(forged)
            .to_bytes()
            .unwrap(),
    );
    // The genuine response, delivered after Bob's floor for Alice already
    // reached its epoch.
    let genuine_sealed = wrap(&msgs[0].1);

    let bob_cs = bob_actor.mode.crypto_mut().expect("encrypted context");
    let wrong_sender = crate::context::messaging_helpers::decrypt_and_dispatch(
        &bob_deps,
        Some(&mut *bob_cs),
        ctx_str,
        &ctx_bytes,
        &forged_sealed,
        &std::collections::HashSet::new(),
    )
    .await;
    assert!(
        matches!(&wrong_sender, Err(ContextError::CryptoFailed(m)) if m.contains("sender DID mismatch")),
        "a response naming another sender fails closed: {wrong_sender:?}"
    );
    assert_eq!(custody.dh_calls(), 0, "no dh_agree for a wrong sender");

    bob_sup
        .check_and_advance_sender_epoch(&ctx_bytes, ALICE, rotated_epoch, MAX_EPOCH_ADVANCE)
        .expect("bob's floor for alice reaches the rotated epoch");
    let stale = crate::context::messaging_helpers::decrypt_and_dispatch(
        &bob_deps,
        Some(&mut *bob_cs),
        ctx_str,
        &ctx_bytes,
        &genuine_sealed,
        &std::collections::HashSet::new(),
    )
    .await;
    assert!(
        matches!(&stale, Err(ContextError::CryptoFailed(m)) if m.contains("equals the floor with another key")),
        "a response at the recorded floor whose key is not the installed key fails closed: \
             {stale:?}"
    );
    assert_eq!(
        custody.dh_calls(),
        1,
        "a response at the floor is opened once, to compare its key with the installed key"
    );
}

/// Bob's side of a two-party context whose wrapping key lives in a
/// `DhCountingCustody` and is published to Alice: Alice's state, Bob's
/// state, deps and supervisor, and the context id bytes.
async fn alice_and_bob_with_counting_custody(
    ctx_str: &str,
    alice: &str,
    bob: &str,
) -> (
    crate::context::actor::PerContextState,
    crate::context::actor::PerContextState,
    crate::context::actor::deps::ActorDeps,
    Arc<Supervisor>,
    [u8; 32],
) {
    let crate::crypto::mls::two_party_test_support::TwoPartyPair {
        alice_state: mut alice_actor,
        bob_provider: bob_crypto,
        bob_state: bob_actor,
        ctx_bytes,
        ..
    } = crate::crypto::mls::two_party_test_support::stand_up_two_party(ctx_str, alice, bob);
    let custody = Arc::new(crate::crypto::dh_counting_custody::DhCountingCustody::new());
    let bob_key = crate::crypto::wrapping::test_wrapping_key(&custody)
        .await
        .expect("bob's wrapping key is created in custody");
    let bob_sup = supervisor_with_crypto(Arc::clone(&bob_crypto));
    bob_sup
        .wrapping_keys
        .insert(DID::from(bob), Arc::clone(&bob_key));
    let bob_deps = bob_sup
        .build_actor_deps(&DID::from(bob))
        .await
        .expect("build bob's actor deps over his loaded key");
    alice_actor
        .mode
        .crypto_mut()
        .expect("encrypted context")
        .member_wrapping_keys
        .insert(
            bob.to_owned(),
            scp_protocol::crypto::hpke::p256::P256Point::try_from(*bob_key.public()).unwrap(),
        );
    (alice_actor, bob_actor, bob_deps, bob_sup, ctx_bytes)
}

/// Alice rotates and returns the one distribution of her new key to Bob,
/// unwrapped, with the new epoch.
fn rotate_for(
    alice_actor: &mut crate::context::actor::PerContextState,
    alice: &str,
) -> (Vec<u8>, u64) {
    alice_actor.rotate_sender_key(alice, None).unwrap();
    let epoch = alice_actor.local_sender_key_epoch();
    let mut msgs = alice_actor.drain_pending_sender_key_messages().unwrap();
    assert_eq!(msgs.len(), 1, "one distribution for Bob");
    (msgs.remove(0).1, epoch)
}

/// Spec 09 §9.16.9: the sender removes a distribution only after a relay
/// accepts it, so a receiver can get the same distribution twice. The
/// second delivery is handled with no change: the floor stays at the
/// epoch, and Alice's message at that epoch still opens.
///
/// Fails if a response at the floor is refused even when its key is the
/// installed key.
#[cfg(feature = "testing")]
#[tokio::test]
async fn a_distribution_delivered_twice_is_handled_once() {
    const ALICE: &str = "did:dht:z6MkAliceDuplicateDistAliceDuplicateDistA1";
    const BOB: &str = "did:dht:z6MkBobDuplicateDistBobDuplicateDistBobDu1";
    let ctx_str = "e2e-distribution-delivered-twice";
    let (mut alice_actor, mut bob_actor, bob_deps, bob_sup, ctx_bytes) =
        alice_and_bob_with_counting_custody(ctx_str, ALICE, BOB).await;
    let (distribution, epoch) = rotate_for(&mut alice_actor, ALICE);
    let mut wrap = |payload: &[u8]| {
        alice_actor
            .mode
            .crypto_mut()
            .expect("encrypted context")
            .mls_encrypt_management(payload)
            .expect("alice MLS-wraps the distribution")
    };
    let first = wrap(&distribution);
    let second = wrap(&distribution);

    let bob_cs = bob_actor.mode.crypto_mut().expect("encrypted context");
    for (n, sealed) in [first, second].iter().enumerate() {
        let got = crate::context::messaging_helpers::decrypt_and_dispatch(
            &bob_deps,
            Some(&mut *bob_cs),
            ctx_str,
            &ctx_bytes,
            sealed,
            &std::collections::HashSet::new(),
        )
        .await;
        assert!(
            matches!(
                got,
                Ok(crate::context::shared::messaging::Dispatched::Handled)
            ),
            "delivery {n} of the same distribution is handled: {got:?}"
        );
    }
    assert_eq!(
        bob_sup.sender_epoch_floor(&ctx_bytes, ALICE),
        epoch,
        "the duplicate leaves the floor at the epoch"
    );
    let app = alice_seals_content(&mut alice_actor, ctx_str, ALICE, epoch, b"after-duplicate");
    let opened = crate::context::messaging_helpers::decrypt_and_dispatch(
        &bob_deps,
        Some(&mut *bob_cs),
        ctx_str,
        &ctx_bytes,
        &app,
        &std::collections::HashSet::new(),
    )
    .await
    .expect("the installed key opens alice's message");
    assert!(matches!(
        opened,
        crate::context::shared::messaging::Dispatched::Envelope(_)
    ));
}

/// Spec 09 §9.16.9: distributions can arrive out of order. Epoch N
/// delivered after N+1 is below the floor and refused, and the key of N+1
/// stays installed.
///
/// Fails if a response below the floor is admitted, or if the duplicate
/// rule widens to every epoch at or below the floor.
#[cfg(feature = "testing")]
#[tokio::test]
async fn an_older_distribution_after_a_newer_one_is_refused() {
    const ALICE: &str = "did:dht:z6MkAliceOutOfOrderDistAliceOutOfOrderDis1";
    const BOB: &str = "did:dht:z6MkBobOutOfOrderDistBobOutOfOrderDistBo1";
    let ctx_str = "e2e-distribution-out-of-order";
    let (mut alice_actor, mut bob_actor, bob_deps, bob_sup, ctx_bytes) =
        alice_and_bob_with_counting_custody(ctx_str, ALICE, BOB).await;
    let (older, _) = rotate_for(&mut alice_actor, ALICE);
    let (newer, newer_epoch) = rotate_for(&mut alice_actor, ALICE);
    let mut wrap = |payload: &[u8]| {
        alice_actor
            .mode
            .crypto_mut()
            .expect("encrypted context")
            .mls_encrypt_management(payload)
            .expect("alice MLS-wraps the distribution")
    };
    let newer_sealed = wrap(&newer);
    let older_sealed = wrap(&older);

    let bob_cs = bob_actor.mode.crypto_mut().expect("encrypted context");
    crate::context::messaging_helpers::decrypt_and_dispatch(
        &bob_deps,
        Some(&mut *bob_cs),
        ctx_str,
        &ctx_bytes,
        &newer_sealed,
        &std::collections::HashSet::new(),
    )
    .await
    .expect("the newer distribution installs");
    let late = crate::context::messaging_helpers::decrypt_and_dispatch(
        &bob_deps,
        Some(&mut *bob_cs),
        ctx_str,
        &ctx_bytes,
        &older_sealed,
        &std::collections::HashSet::new(),
    )
    .await;
    assert!(
        matches!(&late, Err(ContextError::CryptoFailed(_))),
        "a distribution below the floor fails closed: {late:?}"
    );
    assert_eq!(bob_sup.sender_epoch_floor(&ctx_bytes, ALICE), newer_epoch);
    let app = alice_seals_content(&mut alice_actor, ctx_str, ALICE, newer_epoch, b"after-late");
    let opened = crate::context::messaging_helpers::decrypt_and_dispatch(
        &bob_deps,
        Some(&mut *bob_cs),
        ctx_str,
        &ctx_bytes,
        &app,
        &std::collections::HashSet::new(),
    )
    .await
    .expect("the newer key stays installed");
    assert!(matches!(
        opened,
        crate::context::shared::messaging::Dispatched::Envelope(_)
    ));
}

/// A supervisor over `crypto` whose `mls_storage` view is over `storage`
/// and whose wrapping keys live in `custody`.
fn supervisor_with_crypto_storage_and_custody<
    S: scp_platform::traits::Storage + 'static,
    C: scp_platform::traits::KeyCustody + 'static,
>(
    crypto: Arc<crate::crypto::mls::provider::NodeMlsFactory>,
    storage: Arc<S>,
    custody: &Arc<C>,
) -> Arc<Supervisor> {
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
        Arc::new(crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(storage));
    Supervisor::with_providers_and_wrapping_custody(
        crypto,
        Box::new(crate::context::builder::NotConfiguredTransportProvider),
        Box::new(TestEventLog),
        Arc::new(|_: &DID, _: scp_did::SigningKeyId| None),
        None,
        None,
        None,
        None,
        mls_storage,
        crate::crypto::wrapping::single_custody_source(Arc::clone(custody)),
        crate::domain_handlers(),
    )
}

/// Alice and Bob in one two-party context, with Bob's wrapping key loaded
/// by `bob_sup` from `storage` and `custody`, and published to Alice.
struct KeyResponseToBob {
    alice_actor: crate::context::actor::PerContextState,
    bob_actor: crate::context::actor::PerContextState,
    bob_crypto: Arc<crate::crypto::mls::provider::NodeMlsFactory>,
    bob_sup: Arc<Supervisor>,
    bob_deps: crate::context::actor::deps::ActorDeps,
    ctx_bytes: [u8; 32],
}

const KR_ALICE: &str = "did:dht:z6MkAliceKeyLossAliceKeyLossAliceKeyLos1";
const KR_BOB: &str = "did:dht:z6MkBobKeyLossBobKeyLossBobKeyLossBobKe1";

async fn key_response_to_bob<C: scp_platform::traits::KeyCustody + 'static>(
    ctx_str: &str,
    storage: &Arc<InMemoryStorage>,
    custody: &Arc<C>,
) -> KeyResponseToBob {
    let crate::crypto::mls::two_party_test_support::TwoPartyPair {
        alice_state: mut alice_actor,
        bob_provider: bob_crypto,
        bob_state: bob_actor,
        ctx_bytes,
        ..
    } = crate::crypto::mls::two_party_test_support::stand_up_two_party(ctx_str, KR_ALICE, KR_BOB);
    let bob_sup = supervisor_with_crypto_storage_and_custody(
        Arc::clone(&bob_crypto),
        Arc::clone(storage),
        custody,
    );
    let bob_key = bob_sup
        .load_wrapping_key(&DID::from(KR_BOB))
        .await
        .expect("bob's wrapping key loads from custody");
    let bob_deps = bob_sup
        .build_actor_deps(&DID::from(KR_BOB))
        .await
        .expect("build bob's actor deps over his loaded key");
    alice_actor
        .mode
        .crypto_mut()
        .expect("encrypted context")
        .member_wrapping_keys
        .insert(
            KR_BOB.to_owned(),
            scp_protocol::crypto::hpke::p256::P256Point::try_from(*bob_key.public()).unwrap(),
        );
    KeyResponseToBob {
        alice_actor,
        bob_actor,
        bob_crypto,
        bob_sup,
        bob_deps,
        ctx_bytes,
    }
}

/// Alice rotates and MLS-wraps the KeyResponse that seals her new sender
/// key to Bob; returns it with the rotated epoch.
fn alice_rotates_for_bob(
    alice_actor: &mut crate::context::actor::PerContextState,
) -> (Vec<u8>, u64) {
    alice_actor.rotate_sender_key(KR_ALICE, None).unwrap();
    let epoch = alice_actor.local_sender_key_epoch();
    let msgs = alice_actor.drain_pending_sender_key_messages().unwrap();
    assert_eq!(msgs.len(), 1, "one KeyResponse for Bob");
    let sealed = alice_actor
        .mode
        .crypto_mut()
        .expect("encrypted context")
        .mls_encrypt_management(&msgs[0].1)
        .expect("alice MLS-wraps the KeyResponse");
    (sealed, epoch)
}

/// Spec 09 §9.16.1: when custody cannot agree with Bob's wrapping key, the
/// KeyResponse fails closed with `ContextError::Custody`: no sender key is
/// installed (Alice's message at the rotated epoch does not open) and the
/// registry's sender-epoch floor is unchanged.
#[cfg(feature = "testing")]
#[tokio::test]
async fn key_response_fails_closed_when_custody_cannot_agree() {
    let ctx_str = "e2e-key-response-custody-cannot-agree";
    let storage = Arc::new(InMemoryStorage::new());
    let custody = Arc::new(crate::crypto::key_loss_custody::KeyLossCustody::new(
        crate::crypto::key_loss_custody::KeyLoss::OnDhAgree,
    ));
    let KeyResponseToBob {
        mut alice_actor,
        mut bob_actor,
        bob_sup,
        bob_deps,
        ctx_bytes,
        ..
    } = key_response_to_bob(ctx_str, &storage, &custody).await;
    let floors_before = bob_sup.export_sender_key_epochs(&ctx_bytes);

    let (sealed, rotated_epoch) = alice_rotates_for_bob(&mut alice_actor);
    let bob_cs = bob_actor.mode.crypto_mut().expect("encrypted context");
    let err = crate::context::messaging_helpers::decrypt_and_dispatch(
        &bob_deps,
        Some(&mut *bob_cs),
        ctx_str,
        &ctx_bytes,
        &sealed,
        &std::collections::HashSet::new(),
    )
    .await
    .expect_err("a KeyResponse custody cannot open fails closed");
    assert!(
        matches!(&err, ContextError::Custody(f) if f.is_key_not_found()),
        "{err:?}"
    );
    assert_eq!(
        bob_sup.export_sender_key_epochs(&ctx_bytes),
        floors_before,
        "the sender-epoch floor is unchanged"
    );

    let app = alice_seals_content(
        &mut alice_actor,
        ctx_str,
        KR_ALICE,
        rotated_epoch,
        b"after-refused-key-response",
    );
    let opened = crate::context::messaging_helpers::decrypt_and_dispatch(
        &bob_deps,
        Some(&mut *bob_cs),
        ctx_str,
        &ctx_bytes,
        &app,
        &std::collections::HashSet::new(),
    )
    .await;
    assert!(
        !matches!(
            opened,
            Ok(crate::context::shared::messaging::Dispatched::Envelope(_))
        ),
        "no rotated sender key was installed: {opened:?}"
    );
}

/// Spec 09 §9.16.1: custody that loses Bob's wrapping key after agreeing
/// lets that KeyResponse open and install, because no custody call follows
/// the agree. The next KeyResponse fails closed with `Custody`, and a
/// supervisor rebuilt over the same storage and custody reports
/// `WrappingKeyHandleInvalid` from its first load.
#[cfg(feature = "testing")]
#[tokio::test]
async fn key_response_opens_then_a_reload_reports_the_wrapping_handle_invalid() {
    let ctx_str = "e2e-key-response-then-handle-invalid";
    let storage = Arc::new(InMemoryStorage::new());
    let custody = Arc::new(crate::crypto::key_loss_custody::KeyLossCustody::new(
        crate::crypto::key_loss_custody::KeyLoss::AfterDhAgree,
    ));
    let KeyResponseToBob {
        mut alice_actor,
        mut bob_actor,
        bob_crypto,
        bob_sup,
        bob_deps,
        ctx_bytes,
    } = key_response_to_bob(ctx_str, &storage, &custody).await;

    let (sealed, rotated_epoch) = alice_rotates_for_bob(&mut alice_actor);
    let bob_cs = bob_actor.mode.crypto_mut().expect("encrypted context");
    crate::context::messaging_helpers::decrypt_and_dispatch(
        &bob_deps,
        Some(&mut *bob_cs),
        ctx_str,
        &ctx_bytes,
        &sealed,
        &std::collections::HashSet::new(),
    )
    .await
    .expect("the KeyResponse opens before the key is lost");
    let app = alice_seals_content(
        &mut alice_actor,
        ctx_str,
        KR_ALICE,
        rotated_epoch,
        b"after-key-response",
    );
    let opened = crate::context::messaging_helpers::decrypt_and_dispatch(
        &bob_deps,
        Some(&mut *bob_cs),
        ctx_str,
        &ctx_bytes,
        &app,
        &std::collections::HashSet::new(),
    )
    .await
    .expect("the installed sender key opens alice's message");
    let crate::context::shared::messaging::Dispatched::Envelope(opened) = opened else {
        panic!("an Application envelope must surface, got {opened:?}");
    };
    assert_eq!(opened.receive_floor.epoch, rotated_epoch);

    let (second, _) = alice_rotates_for_bob(&mut alice_actor);
    let err = crate::context::messaging_helpers::decrypt_and_dispatch(
        &bob_deps,
        Some(&mut *bob_cs),
        ctx_str,
        &ctx_bytes,
        &second,
        &std::collections::HashSet::new(),
    )
    .await
    .expect_err("the lost key cannot open the next KeyResponse");
    assert!(
        matches!(&err, ContextError::Custody(f) if f.is_key_not_found()),
        "{err:?}"
    );

    drop(bob_deps);
    bob_sup.shutdown_all_contexts().await;
    drop(bob_sup);
    let rebuilt =
        supervisor_with_crypto_storage_and_custody(bob_crypto, Arc::clone(&storage), &custody);
    let err = rebuilt
        .load_wrapping_key(&DID::from(KR_BOB))
        .await
        .unwrap_err();
    assert!(
        matches!(err, ContextError::WrappingKeyHandleInvalid),
        "{err:?}"
    );
}

/// Spec 07 §7.3.1.1 step 3: openmls opens a message from up to two past
/// epochs, verified against the sender's leaf in the epoch it was sent
/// in. Alice seals two KeyResponses to Bob, then Bob commits her removal
/// and later adds Carol, who takes Alice's blank leaf. The first
/// KeyResponse arrives while that leaf is blank and the second after Carol
/// holds it. Bob refuses both: neither installs a sender key for Alice or
/// Carol, and his sender-epoch floors are unchanged.
#[cfg(feature = "testing")]
#[tokio::test]
async fn a_removed_senders_past_epoch_key_response_installs_nothing() {
    use openmls::prelude::tls_codec::Serialize as _;
    const CAROL: &str = "did:dht:z6MkCarolKeyLossCarolKeyLossCarolKeyLo1";
    let ctx_str = "key-response-from-a-removed-sender";
    let storage = Arc::new(InMemoryStorage::new());
    let custody = Arc::new(scp_platform::testing::InMemoryKeyCustody::new());
    let KeyResponseToBob {
        mut alice_actor,
        mut bob_actor,
        bob_sup,
        bob_deps,
        ctx_bytes,
        ..
    } = key_response_to_bob(ctx_str, &storage, &custody).await;
    let (blank_leaf, _) = alice_rotates_for_bob(&mut alice_actor);
    let (reused_leaf, _) = alice_rotates_for_bob(&mut alice_actor);

    let sender_key_ctx = hex::encode(ctx_bytes);
    let key_of = |actor: &crate::context::actor::PerContextState, did: &str| {
        actor
            .mode
            .crypto()
            .expect("encrypted context")
            .sender_key_store
            .get(&sender_key_ctx, did)
            .map(|k| *k.as_bytes())
    };
    let alice_key = key_of(&bob_actor, KR_ALICE);
    assert!(alice_key.is_some(), "bob holds alice's pulled sender key");
    let floors_before = bob_sup.export_sender_key_epochs(&ctx_bytes);

    // Bob commits Alice's removal: her leaf is blank.
    bob_actor
        .remove_member(KR_BOB, KR_ALICE, &scp_clock::SystemClock)
        .expect("bob removes alice's leaf");
    let err = crate::context::messaging_helpers::decrypt_and_dispatch(
        &bob_deps,
        bob_actor.mode.crypto_mut(),
        ctx_str,
        &ctx_bytes,
        &blank_leaf,
        &std::collections::HashSet::new(),
    )
    .await
    .expect_err("a KeyResponse from a blank leaf is refused");
    assert!(matches!(err, ContextError::CryptoFailed(_)), "{err:?}");

    // Bob adds Carol, who takes the blank leaf; the KeyResponse is still
    // within the two past epochs openmls opens.
    let carol_credential =
        scp_mls::ScpCredential::new(CAROL.to_owned(), None, scp_did::SigningKeyId::Active)
            .expect("carol's credential");
    let (carol_bundle, _signer, _provider) =
        scp_mls::group::generate_key_package_with_context_params(
            &carol_credential,
            &scp_crypto::p256::testing::uncompressed_point_for(CAROL),
            &scp_clock::SystemClock,
        )
        .expect("carol's key package");
    let carol_kp = carol_bundle
        .key_package()
        .tls_serialize_detached()
        .expect("serialize carol's key package");
    bob_actor
        .add_member(CAROL, Some(&carol_kp), &scp_clock::SystemClock)
        .expect("bob adds carol into alice's blank leaf");
    let err = crate::context::messaging_helpers::decrypt_and_dispatch(
        &bob_deps,
        bob_actor.mode.crypto_mut(),
        ctx_str,
        &ctx_bytes,
        &reused_leaf,
        &std::collections::HashSet::new(),
    )
    .await
    .expect_err("a KeyResponse from a leaf another member now holds is refused");
    assert!(matches!(err, ContextError::CryptoFailed(_)), "{err:?}");

    assert_eq!(key_of(&bob_actor, KR_ALICE), alice_key, "alice's key kept");
    assert_eq!(
        key_of(&bob_actor, CAROL),
        None,
        "nothing installed for carol"
    );
    assert_eq!(
        bob_sup.export_sender_key_epochs(&ctx_bytes),
        floors_before,
        "the sender-epoch floor is unchanged"
    );
}

/// A supervisor with a clock and `persistence` whose wrapping keys come
/// from `wrapping_custody`. Its event log is a `MerkleEventLogProvider`,
/// because a context export fails closed on a provider that cannot export
/// its log, and an import needs a provider that takes the log.
fn supervisor_with_persistence_and_custody_source(
    persistence: Box<dyn ContextPersistence>,
    wrapping_custody: WrappingCustodySource,
) -> Arc<Supervisor> {
    let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
        "did:dht:z6MktestDoNotRely".to_owned(),
        Arc::new(scp_clock::SystemClock),
    ));
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            InMemoryStorage::new(),
        )),
    );
    Supervisor::with_providers_and_wrapping_custody(
        crypto,
        Box::new(crate::context::builder::NotConfiguredTransportProvider),
        Box::new(crate::context::providers::event_log::MerkleEventLogProvider::new()),
        Arc::new(|_: &DID, _: scp_did::SigningKeyId| None),
        Some(persistence),
        None,
        None,
        Some(Arc::new(TestClock::new(1_700_000_000))),
        mls_storage,
        wrapping_custody,
        crate::domain_handlers(),
    )
}

/// Spec 09 §9.16.1: with no custody registered for the owner's wrapping
/// key, CreateContext fails closed with `WrappingKeyCustodyUnavailable`
/// and registers no actor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_context_fails_closed_without_the_owners_wrapping_custody() {
    let none: WrappingCustodySource = Arc::new(|_: &DID| None);
    let sup =
        supervisor_with_persistence_and_custody_source(Box::new(MapPersistence::default()), none);
    let identity = sup.node_identity().unwrap();
    let ctx = hex::encode([0xC5u8; 32]);
    let err = sup
        .create_context(
            ctx.clone(),
            scp_protocol::context::ContextParams {
                ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
                ..Default::default()
            },
            identity,
            None,
            Vec::new(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            scp_protocol::context::builder::ContextCreationError::StateTransition(
                ContextError::WrappingKeyCustodyUnavailable
            )
        ),
        "{err:?}"
    );
    assert!(sup.lookup(&ctx).is_none(), "no actor is registered");
    assert!(sup.wrapping_keys.is_empty(), "no key is loaded");
}

/// A wrapping-key load failure ends CreateContext, RestoreContext and
/// ImportContext before any of them takes `bootstrap_spawn_lock`: with
/// that lock held elsewhere, each returns the load error without waiting
/// on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_restore_and_import_return_a_wrapping_key_load_failure_before_any_lock() {
    let none: WrappingCustodySource = Arc::new(|_: &DID| None);
    let sup =
        supervisor_with_persistence_and_custody_source(Box::new(MapPersistence::default()), none);
    let identity = sup.node_identity().unwrap();
    let ctx = hex::encode([0xC6u8; 32]);
    let params = scp_protocol::context::ContextParams {
        ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
        ..Default::default()
    };
    // A valid export from a supervisor that has custody, so the import
    // passes its export check and reaches the wrapping-key load.
    let (exporter, _exporter_custody) = lock_checking_supervisor();
    let exporter_identity = exporter.node_identity().unwrap();
    let exported_ctx = hex::encode([0xC7u8; 32]);
    exporter
        .create_context(
            exported_ctx.clone(),
            params.clone(),
            exporter_identity.clone(),
            None,
            Vec::new(),
        )
        .await
        .unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let export = exporter
        .export_context(
            &exported_ctx,
            exporter_identity,
            &CommandSigner::local_ed25519(signing_key.clone()),
        )
        .await
        .unwrap();
    let budget = std::time::Duration::from_secs(5);
    let _held = sup.bootstrap_spawn_lock.lock().await;

    let err = tokio::time::timeout(
        budget,
        sup.create_context(ctx.clone(), params.clone(), identity, None, Vec::new()),
    )
    .await
    .expect("create returns without taking bootstrap_spawn_lock")
    .unwrap_err();
    assert!(
        matches!(
            err,
            scp_protocol::context::builder::ContextCreationError::StateTransition(
                ContextError::WrappingKeyCustodyUnavailable
            )
        ),
        "{err:?}"
    );

    let handle = crate::context::ContextHandle::new(ctx.clone(), params);
    let err = tokio::time::timeout(budget, sup.restore_context(&ctx, &handle))
        .await
        .expect("restore returns without taking bootstrap_spawn_lock")
        .unwrap_err();
    assert!(
        matches!(err, ContextError::WrappingKeyCustodyUnavailable),
        "{err:?}"
    );
    assert!(sup.lookup(&ctx).is_none(), "no actor is registered");

    let err = tokio::time::timeout(
        budget,
        Box::pin(sup.import_context(export, &signing_key.verifying_key(), None)),
    )
    .await
    .expect("import returns without taking bootstrap_spawn_lock")
    .unwrap_err();
    assert!(
        matches!(err, ContextError::WrappingKeyCustodyUnavailable),
        "{err:?}"
    );
    assert!(
        sup.lookup(&exported_ctx).is_none(),
        "no imported actor is registered"
    );
    assert!(sup.wrapping_keys.is_empty(), "no key is loaded");
}

/// The supervisor clock's time in the first-relay-contact tests.
const FIRST_CONTACT_NOW: u64 = 1_700_000_000;

/// A relay-contact store whose writes fail.
struct FailingRelayContacts;
#[async_trait::async_trait]
impl crate::store::sync::RelayContactStore for FailingRelayContacts {
    async fn store_last_relay_contact(
        &self,
        _: &str,
        _: u64,
    ) -> Result<(), crate::store::StoreError> {
        Err(crate::store::StoreError::SerializationFailed(
            "injected relay-contact write failure".to_owned(),
        ))
    }
    async fn load_last_relay_contact(
        &self,
        _: &str,
    ) -> Result<Option<u64>, crate::store::StoreError> {
        Ok(None)
    }
    async fn delete_last_relay_contact(&self, _: &str) -> Result<(), crate::store::StoreError> {
        Ok(())
    }
}

/// A supervisor over `persistence` and `durable`, with a clock fixed at
/// [`FIRST_CONTACT_NOW`], in-memory wrapping custody, and an event log
/// that exports and imports.
fn first_contact_supervisor(
    persistence: Box<dyn ContextPersistence>,
    durable: DurableProviders,
) -> Arc<Supervisor> {
    Supervisor::with_providers_and_journal(
        Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
            "did:dht:z6MktestFirstRelayContact".to_owned(),
            Arc::new(scp_clock::SystemClock),
        )),
        Box::new(crate::context::builder::NotConfiguredTransportProvider),
        Box::new(crate::context::providers::event_log::MerkleEventLogProvider::new()),
        Arc::new(|_: &DID, _: scp_did::SigningKeyId| None),
        persistence,
        None,
        None,
        Some(Arc::new(TestClock::new(FIRST_CONTACT_NOW))),
        durable,
        crate::crypto::wrapping::single_custody_source(Arc::new(
            scp_platform::testing::InMemoryKeyCustody::new(),
        )),
        crate::domain_handlers(),
    )
}

/// The production pairing: every durable provider over one store.
fn durable_over_one_store() -> DurableProviders {
    DurableProviders::from_handle(Arc::new(InMemoryStorage::new()))
}

/// Durable providers whose relay-contact writes fail.
fn durable_with_failing_contacts() -> DurableProviders {
    DurableProviders::for_test_with_relay_contacts(
        Arc::new(NoOpSagaJournal),
        Arc::new(
            crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                InMemoryStorage::new(),
            )),
        ),
        Arc::new(FailingRelayContacts),
    )
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
    crate::context::export_import::ContextExport,
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

/// Create stores the context's first `last_relay_contact` at the
/// supervisor clock's time, and restoring the context writes none
/// (ADR-029 Implementation): a contact moved back stays where it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_stores_the_first_relay_contact_and_restore_keeps_it() {
    let sup = first_contact_supervisor(
        Box::new(MapPersistence::default()),
        durable_over_one_store(),
    );
    let identity = sup.node_identity().unwrap();
    let ctx = hex::encode([0xE1u8; 32]);
    let handle = sup
        .create_context(
            ctx.clone(),
            first_contact_params(),
            identity,
            None,
            Vec::new(),
        )
        .await
        .unwrap();
    let contacts = sup.relay_contact_store();
    assert_eq!(
        contacts.load_last_relay_contact(&ctx).await.unwrap(),
        Some(FIRST_CONTACT_NOW)
    );

    let offline_since = FIRST_CONTACT_NOW - 3600;
    contacts
        .store_last_relay_contact(&ctx, offline_since)
        .await
        .unwrap();
    assert!(sup.despawn_actor(&ctx).await);
    sup.wrapping_keys.clear();
    sup.restore_context(&ctx, &handle).await.unwrap();
    assert!(sup.lookup(&ctx).is_some(), "the context is restored");
    assert_eq!(
        contacts.load_last_relay_contact(&ctx).await.unwrap(),
        Some(offline_since),
        "a restore keeps the stored contact"
    );
}

/// A failed first-contact write fails create with a typed error, spawns
/// no actor, and leaves no snapshot behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_fails_without_an_actor_when_the_first_contact_write_fails() {
    let sup = first_contact_supervisor(
        Box::new(crate::context::providers::InMemoryPersistence::new()),
        durable_with_failing_contacts(),
    );
    let identity = sup.node_identity().unwrap();
    let ctx = hex::encode([0xE2u8; 32]);
    let err = sup
        .create_context(
            ctx.clone(),
            first_contact_params(),
            identity,
            None,
            Vec::new(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            scp_protocol::context::builder::ContextCreationError::StateTransition(
                ContextError::PersistenceFailed(_)
            )
        ),
        "{err:?}"
    );
    assert!(sup.lookup(&ctx).is_none(), "no actor is registered");
    let persistence = sup.persistence_ref().expect("persistence installed");
    assert!(
        persistence.load_context(&ctx).await.unwrap().is_none(),
        "the first snapshot is deleted"
    );
}

/// A persistence whose snapshot writes fail.
struct FailingSnapshotWrites;
#[async_trait::async_trait]
impl ContextPersistence for FailingSnapshotWrites {
    async fn persist_context(
        &self,
        _: &str,
        _: &crate::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("injected snapshot write failure".into())
    }
    async fn load_context(
        &self,
        _: &str,
    ) -> Result<
        Option<crate::context::state::ContextSnapshot>,
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

/// A failed first-snapshot write fails create and import with a typed
/// error before either spawns an actor (ADR-049 Decision 9), and stores
/// no relay contact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_and_import_fail_without_an_actor_when_the_first_snapshot_write_fails() {
    let sup = first_contact_supervisor(Box::new(FailingSnapshotWrites), durable_over_one_store());
    let identity = sup.node_identity().unwrap();
    let ctx = hex::encode([0xE5u8; 32]);
    let err = sup
        .create_context(
            ctx.clone(),
            first_contact_params(),
            identity,
            None,
            Vec::new(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            scp_protocol::context::builder::ContextCreationError::StateTransition(
                ContextError::PersistenceFailed(_)
            )
        ),
        "{err:?}"
    );
    assert!(sup.lookup(&ctx).is_none(), "create registers no actor");

    let imported = hex::encode([0xE6u8; 32]);
    let (export, signing_key) = first_contact_export(&imported).await;
    let err = Box::pin(sup.import_context(export, &signing_key.verifying_key(), None))
        .await
        .unwrap_err();
    assert!(matches!(err, ContextError::PersistenceFailed(_)), "{err:?}");
    assert!(sup.lookup(&imported).is_none(), "import registers no actor");

    let contacts = sup.relay_contact_store();
    for id in [&ctx, &imported] {
        assert_eq!(contacts.load_last_relay_contact(id).await.unwrap(), None);
    }
}

/// A migration whose destination create fails after its first contact
/// was written returns the create's error, never a retryable
/// `ActorBusy`, even with another bootstrap parked on
/// `bootstrap_spawn_lock`: the governance call recorded its proposal or
/// vote before the create, so ADR-049 Decision 9 forbids a busy error
/// from here on. The rollback runs under the guard the call reserved, so
/// the contact is gone and the destination unclaimed when the call
/// returns, and only then does the parked bootstrap get the lock.
// The reservation is moved into the migration; the nursery lint misreads
// that move as a guard held to the end of the test.
#[allow(clippy::significant_drop_tightening)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_migration_create_rolls_back_under_its_reserved_lock_and_is_never_busy() {
    use crate::context::governance_helpers::execute_propose_context_migration;
    use crate::context::shared::governance::CommitMeta;
    use crate::context::shared::governance::MigrationBootstrap;
    use crate::context::shared::governance::migration_destination_id;

    let sup = first_contact_supervisor(Box::new(FailingSnapshotWrites), durable_over_one_store());
    let admin = sup.node_identity().unwrap();
    let deps = sup.build_actor_deps_loaded(&admin).await.unwrap();
    let source = [0xE7u8; 32];
    let ctx = hex::encode(source);
    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        source,
        FIRST_CONTACT_NOW,
        admin.clone(),
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    state
        .membership
        .add_member(admin.clone(), "admin".to_owned(), vec![]);
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);
    let pid = [0xE8u8; 32];
    let destination = migration_destination_id(&ctx, &pid);

    let bootstrap = MigrationBootstrap::reserve(&deps, &ctx, &pid).unwrap();
    let (parked_tx, parked_rx) = tokio::sync::oneshot::channel::<()>();
    let (acquired_tx, acquired_rx) = tokio::sync::oneshot::channel::<()>();
    let lock = Arc::clone(&sup.bootstrap_spawn_lock);
    let waiter = tokio::spawn(async move {
        let acquire = lock.lock_owned();
        tokio::pin!(acquire);
        // Poll once so the waiter is queued before the migration runs.
        assert!(
            futures::poll!(acquire.as_mut()).is_pending(),
            "the reservation holds the lock"
        );
        parked_tx.send(()).unwrap();
        let guard = acquire.await;
        acquired_tx.send(()).unwrap();
        drop(guard);
    });
    parked_rx.await.unwrap();

    let result = execute_propose_context_migration(
        &mut cell,
        &deps,
        &ctx,
        &first_contact_params(),
        "fixture",
        60,
        false,
        CommitMeta {
            pid,
            actor_did: admin.as_ref(),
            timestamp_secs: FIRST_CONTACT_NOW,
        },
        bootstrap,
    )
    .await;

    assert!(
        matches!(
            &result,
            Err(ContextError::PermissionDenied(msg))
                if msg.starts_with("failed to create destination context")
                    && msg.contains("injected snapshot write failure")
        ),
        "the create's own error, not ActorBusy: {result:?}"
    );
    assert_eq!(
        sup.relay_contact_store()
            .load_last_relay_contact(&destination)
            .await
            .unwrap(),
        None,
        "the destination's first contact is removed before the call returns"
    );
    assert!(sup.lookup(&destination).is_none(), "no destination runs");
    assert_eq!(
        cell.handle.state(),
        crate::context::ContextState::Active,
        "the source returns to Active"
    );
    deps.supervisor
        .claim_first_state(&destination)
        .expect("the rollback released the destination's claim");
    deps.supervisor.release_first_state(&destination);
    tokio::time::timeout(std::time::Duration::from_secs(5), acquired_rx)
        .await
        .expect("the parked bootstrap gets the lock once the call returns")
        .unwrap();
    waiter.await.unwrap();
}

/// Import stores the context's first `last_relay_contact` at the
/// supervisor clock's time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_stores_the_first_relay_contact() {
    let ctx = hex::encode([0xE3u8; 32]);
    let (export, signing_key) = first_contact_export(&ctx).await;
    let importer = first_contact_supervisor(
        Box::new(MapPersistence::default()),
        durable_over_one_store(),
    );
    Box::pin(importer.import_context(export, &signing_key.verifying_key(), None))
        .await
        .unwrap();
    assert!(importer.lookup(&ctx).is_some(), "the context is imported");
    assert_eq!(
        importer
            .relay_contact_store()
            .load_last_relay_contact(&ctx)
            .await
            .unwrap(),
        Some(FIRST_CONTACT_NOW)
    );
}

/// A failed first-contact write fails import with a typed error, spawns
/// no actor, and leaves no snapshot behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_fails_without_an_actor_when_the_first_contact_write_fails() {
    let ctx = hex::encode([0xE4u8; 32]);
    let (export, signing_key) = first_contact_export(&ctx).await;
    let importer = first_contact_supervisor(
        Box::new(crate::context::providers::InMemoryPersistence::new()),
        durable_with_failing_contacts(),
    );
    let err = Box::pin(importer.import_context(export, &signing_key.verifying_key(), None))
        .await
        .unwrap_err();
    assert!(matches!(err, ContextError::PersistenceFailed(_)), "{err:?}");
    assert!(importer.lookup(&ctx).is_none(), "no actor is registered");
    let persistence = importer.persistence_ref().expect("persistence installed");
    assert!(
        persistence.load_context(&ctx).await.unwrap().is_none(),
        "the first snapshot is deleted"
    );
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
    contexts: Arc<DashMap<String, crate::context::state::ContextSnapshot>>,
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
        snap: &crate::context::state::ContextSnapshot,
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
            sup.close_spawn_gate();
        }
        Ok(())
    }
    async fn load_context(
        &self,
        id: &str,
    ) -> Result<
        Option<crate::context::state::ContextSnapshot>,
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
) -> crate::context::state::ContextSnapshot {
    let mut snapshot = import_test_snapshot(ctx, "did:dht:z6MkPriorSnapshotCreator");
    snapshot.state = state;
    snapshot.creation_timestamp_secs = PRIOR_CREATED_AT;
    snapshot
}

/// An import over a Tombstoned context whose first-contact write fails
/// keeps the tombstone: the contact is written before the snapshot, so
/// the failure stops the import before it replaces the snapshot, and the
/// rollback deletes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_over_a_tombstone_with_a_failing_contact_write_keeps_the_tombstone() {
    let ctx = hex::encode([0xE7u8; 32]);
    let (export, signing_key) = first_contact_export(&ctx).await;
    let persistence = FaultyPersistence::default();
    persistence.contexts.insert(
        ctx.clone(),
        prior_snapshot(&ctx, scp_protocol::context::ContextState::Tombstoned),
    );
    let importer = first_contact_supervisor(
        Box::new(persistence.clone()),
        durable_with_failing_contacts(),
    );
    let err = Box::pin(importer.import_context(export, &signing_key.verifying_key(), None))
        .await
        .unwrap_err();
    assert!(matches!(err, ContextError::PersistenceFailed(_)), "{err:?}");
    assert!(importer.lookup(&ctx).is_none(), "no actor is registered");
    let kept = persistence.contexts.get(&ctx).map(|s| s.state.clone());
    assert_eq!(
        kept,
        Some(scp_protocol::context::ContextState::Tombstoned),
        "the tombstone is kept"
    );
}

/// A create whose first-snapshot write fails over an existing snapshot
/// keeps that snapshot and puts back the contact stored before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_snapshot_write_over_an_existing_snapshot_keeps_it_and_its_contact() {
    let ctx = hex::encode([0xE8u8; 32]);
    let persistence = FaultyPersistence::default();
    persistence.contexts.insert(
        ctx.clone(),
        prior_snapshot(&ctx, scp_protocol::context::ContextState::Active),
    );
    FaultyPersistence::set(&persistence.fail_writes);
    let sup = first_contact_supervisor(Box::new(persistence.clone()), durable_over_one_store());
    let contacts = sup.relay_contact_store();
    contacts
        .store_last_relay_contact(&ctx, PRIOR_CONTACT)
        .await
        .unwrap();
    let identity = sup.node_identity().unwrap();
    let err = sup
        .create_context(
            ctx.clone(),
            first_contact_params(),
            identity,
            None,
            Vec::new(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            scp_protocol::context::builder::ContextCreationError::StateTransition(
                ContextError::PersistenceFailed(_)
            )
        ),
        "{err:?}"
    );
    assert!(sup.lookup(&ctx).is_none(), "no actor is registered");
    assert_eq!(persistence.created_at(&ctx), Some(PRIOR_CREATED_AT));
    assert_eq!(
        contacts.load_last_relay_contact(&ctx).await.unwrap(),
        Some(PRIOR_CONTACT),
        "the prior contact is put back"
    );
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

    let guard =
        crate::context::shared::lifecycle::FirstStateRollback::new(&deps, &created).unwrap();
    let err = Box::pin(crate::context::lifecycle_helpers::create_context(
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
        .rollback(sup.bootstrap_spawn_lock.lock())
        .await
        .unwrap();
    assert!(sup.lookup(&created).is_none(), "no actor started");
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
    let guard =
        crate::context::shared::lifecycle::FirstStateRollback::new(&deps, &imported).unwrap();
    let err = Box::pin(crate::context::lifecycle_helpers::import_context(
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
        .rollback(sup.bootstrap_spawn_lock.lock())
        .await
        .unwrap();
    assert!(sup.lookup(&imported).is_none(), "no actor started");
    assert!(!persistence.contexts.contains_key(&imported));
    assert_eq!(
        contacts.load_last_relay_contact(&imported).await.unwrap(),
        None
    );
}

/// When the rollback cannot delete the snapshot a failed create wrote, it
/// fails with `PersistenceFailed` and keeps the contact, so no path
/// leaves a snapshot with no contact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rollback_whose_snapshot_delete_fails_keeps_the_contact() {
    let persistence = FaultyPersistence::default();
    FaultyPersistence::set(&persistence.fail_deletes);
    let sup = first_contact_supervisor(Box::new(persistence.clone()), durable_over_one_store());
    let contacts = sup.relay_contact_store();
    let identity = sup.node_identity().unwrap();
    persistence.closing_the_gate_of(&sup);
    let ctx = hex::encode([0xEBu8; 32]);
    let deps = sup.build_actor_deps_loaded(&identity).await.unwrap();

    let guard = crate::context::shared::lifecycle::FirstStateRollback::new(&deps, &ctx).unwrap();
    Box::pin(crate::context::lifecycle_helpers::create_context(
        &deps,
        ctx.clone(),
        first_contact_params(),
        identity,
        None,
        Vec::new(),
        &guard,
    ))
    .await
    .unwrap_err();
    let err = guard
        .rollback(sup.bootstrap_spawn_lock.lock())
        .await
        .unwrap_err();
    assert!(matches!(err, ContextError::PersistenceFailed(_)), "{err:?}");
    assert!(persistence.contexts.contains_key(&ctx), "the delete failed");
    assert_eq!(
        contacts.load_last_relay_contact(&ctx).await.unwrap(),
        Some(FIRST_CONTACT_NOW),
        "the contact stays while its snapshot does"
    );
}

/// A create whose snapshot write outlasts `LIFECYCLE_TIMEOUT` and then
/// lands is dropped by the dispatch arm, whose rollback waits for that
/// write before it reads which records were touched: the late snapshot
/// is deleted and the contact stored before is put back. The write runs
/// on its own task, so dropping the create's future does not stop it.
#[tokio::test(start_paused = true)]
async fn a_timed_out_create_whose_write_lands_late_rolls_back_both_records() {
    let persistence = FaultyPersistence::default();
    persistence
        .delay_writes
        .set(Supervisor::LIFECYCLE_TIMEOUT + std::time::Duration::from_secs(5))
        .unwrap();
    let sup = first_contact_supervisor(Box::new(persistence.clone()), durable_over_one_store());
    let contacts = sup.relay_contact_store();
    let ctx = hex::encode([0xECu8; 32]);
    contacts
        .store_last_relay_contact(&ctx, PRIOR_CONTACT)
        .await
        .unwrap();
    let identity = sup.node_identity().unwrap();
    let err = sup
        .create_context(
            ctx.clone(),
            first_contact_params(),
            identity,
            None,
            Vec::new(),
        )
        .await
        .unwrap_err();
    assert!(
        FaultyPersistence::is_set(&persistence.write_started),
        "the create reached its snapshot write before the timeout: {err:?}"
    );
    assert!(
        err.to_string().contains("exceeded"),
        "the create timed out: {err:?}"
    );
    // Long past the late write, which has landed by now if it ever will.
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    assert!(sup.lookup(&ctx).is_none(), "no actor is registered");
    assert!(
        !persistence.contexts.contains_key(&ctx),
        "the late snapshot is deleted"
    );
    assert_eq!(
        contacts.load_last_relay_contact(&ctx).await.unwrap(),
        Some(PRIOR_CONTACT),
        "the prior contact is put back"
    );
}

/// A create whose snapshot write never finishes cannot be rolled back,
/// because the write could still land: the rollback waits for it, then
/// keeps the records, and the create's error says so.
#[tokio::test(start_paused = true)]
async fn a_timed_out_create_whose_write_never_finishes_keeps_its_records_and_says_so() {
    let persistence = FaultyPersistence::default();
    FaultyPersistence::set(&persistence.hang_writes);
    let sup = first_contact_supervisor(Box::new(persistence.clone()), durable_over_one_store());
    let contacts = sup.relay_contact_store();
    let ctx = hex::encode([0xEEu8; 32]);
    contacts
        .store_last_relay_contact(&ctx, PRIOR_CONTACT)
        .await
        .unwrap();
    let identity = sup.node_identity().unwrap();
    let err = sup
        .create_context(
            ctx.clone(),
            first_contact_params(),
            identity,
            None,
            Vec::new(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            scp_protocol::context::builder::ContextCreationError::StateTransition(
                ContextError::PersistenceFailed(ref msg)
            ) if msg.contains("exceeded") && msg.contains("did not finish")
        ),
        "{err:?}"
    );
    assert!(sup.lookup(&ctx).is_none(), "no actor is registered");
    assert_eq!(
        contacts.load_last_relay_contact(&ctx).await.unwrap(),
        Some(FIRST_CONTACT_NOW),
        "the contact written before the hung snapshot write is kept"
    );
}

/// A guard dropped with a touched record rolls back on a tracked task
/// that takes `bootstrap_spawn_lock` before it reads anything: while
/// another bootstrap holds the lock the records stay, and the undo runs
/// once the lock is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_guard_rolls_back_only_under_the_bootstrap_lock() {
    let persistence = FaultyPersistence::default();
    FaultyPersistence::set(&persistence.fail_writes);
    let sup = first_contact_supervisor(Box::new(persistence.clone()), durable_over_one_store());
    let contacts = sup.relay_contact_store();
    let identity = sup.node_identity().unwrap();
    let ctx = hex::encode([0xEFu8; 32]);
    contacts
        .store_last_relay_contact(&ctx, PRIOR_CONTACT)
        .await
        .unwrap();
    let deps = sup.build_actor_deps_loaded(&identity).await.unwrap();
    let guard = crate::context::shared::lifecycle::FirstStateRollback::new(&deps, &ctx).unwrap();
    let err = Box::pin(crate::context::lifecycle_helpers::create_context(
        &deps,
        ctx.clone(),
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
                ContextError::PersistenceFailed(_)
            )
        ),
        "{err:?}"
    );
    assert_eq!(
        contacts.load_last_relay_contact(&ctx).await.unwrap(),
        Some(FIRST_CONTACT_NOW),
        "the create wrote its contact before the failed snapshot write"
    );

    let held = sup.bootstrap_spawn_lock.lock().await;
    drop(guard);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        contacts.load_last_relay_contact(&ctx).await.unwrap(),
        Some(FIRST_CONTACT_NOW),
        "the undo waits for the bootstrap lock"
    );
    drop(held);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while contacts.load_last_relay_contact(&ctx).await.unwrap() != Some(PRIOR_CONTACT) {
        assert!(
            std::time::Instant::now() < deadline,
            "the undo puts back the prior contact once the lock is free"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// A create that times out with its snapshot write still running waits
/// for that write with `bootstrap_spawn_lock` released, so every other
/// bootstrap can run during the wait; once the write lands the rollback
/// retakes the lock and puts back both records.
#[tokio::test(start_paused = true)]
async fn a_timed_out_create_drains_its_writes_with_the_bootstrap_lock_released() {
    let persistence = FaultyPersistence::default();
    persistence
        .delay_writes
        .set(Supervisor::LIFECYCLE_TIMEOUT + std::time::Duration::from_secs(10))
        .unwrap();
    let sup = first_contact_supervisor(Box::new(persistence.clone()), durable_over_one_store());
    let contacts = sup.relay_contact_store();
    let ctx = hex::encode([0xF0u8; 32]);
    contacts
        .store_last_relay_contact(&ctx, PRIOR_CONTACT)
        .await
        .unwrap();
    let identity = sup.node_identity().unwrap();
    let create = tokio::spawn({
        let sup = Arc::clone(&sup);
        let ctx = ctx.clone();
        async move {
            sup.create_context(ctx, first_contact_params(), identity, None, Vec::new())
                .await
        }
    });
    // Past the create's timeout, inside its rollback's wait for the write.
    tokio::time::sleep(Supervisor::LIFECYCLE_TIMEOUT + std::time::Duration::from_secs(1)).await;
    assert!(FaultyPersistence::is_set(&persistence.write_started));
    assert!(
        !create.is_finished(),
        "the rollback is waiting for the snapshot write"
    );
    assert!(
        sup.bootstrap_spawn_lock.try_lock().is_ok(),
        "the rollback waits for the write with the bootstrap lock released"
    );
    let err = create.await.unwrap().unwrap_err();
    assert!(err.to_string().contains("exceeded"), "{err:?}");
    assert!(sup.lookup(&ctx).is_none(), "no actor is registered");
    assert!(
        !persistence.contexts.contains_key(&ctx),
        "the late snapshot is deleted"
    );
    assert_eq!(
        contacts.load_last_relay_contact(&ctx).await.unwrap(),
        Some(PRIOR_CONTACT),
        "the prior contact is put back"
    );
}

/// While a bootstrap's first state of an id is written and not yet
/// committed or rolled back, a restore and an operator `clear_poison` of
/// that id are refused with a retryable `ActorBusy`, so neither starts an
/// actor from the snapshot the rollback is about to delete. After the
/// rollback the restore finds no snapshot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restore_or_respawn_of_an_unsettled_first_state_is_busy() {
    let persistence = FaultyPersistence::default();
    let sup = first_contact_supervisor(Box::new(persistence.clone()), durable_over_one_store());
    let identity = sup.node_identity().unwrap();
    let ctx_bytes = [0xF1u8; 32];
    let ctx = hex::encode(ctx_bytes);
    let deps = sup.build_actor_deps_loaded(&identity).await.unwrap();
    let guard = crate::context::shared::lifecycle::FirstStateRollback::new(&deps, &ctx).unwrap();
    let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_bytes,
        FIRST_CONTACT_NOW,
        identity.clone(),
    );
    crate::context::shared::lifecycle::persist_first_state(&state, &deps, &ctx, &guard)
        .await
        .unwrap();
    assert!(
        persistence.contexts.contains_key(&ctx),
        "the snapshot is written"
    );

    let handle = crate::context::ContextHandle::new(ctx.clone(), first_contact_params());
    let err = sup.restore_context(&ctx, &handle).await.unwrap_err();
    assert!(
        matches!(&err, ContextError::ActorBusy(msg) if msg.contains("retry")),
        "{err:?}"
    );
    let err = Box::pin(sup.clear_poison(&ctx, &identity))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ContextError::ActorBusy(msg) if msg.contains("retry")),
        "{err:?}"
    );
    assert!(sup.lookup(&ctx).is_none(), "no actor started");

    guard
        .rollback(sup.bootstrap_spawn_lock.lock())
        .await
        .unwrap();
    assert!(
        !persistence.contexts.contains_key(&ctx),
        "the snapshot is deleted"
    );
    let handle = crate::context::ContextHandle::new(ctx.clone(), first_contact_params());
    let err = sup.restore_context(&ctx, &handle).await.unwrap_err();
    assert!(
        !matches!(err, ContextError::ActorBusy(_)),
        "the claim is released after the rollback: {err:?}"
    );
}

/// A recovery notification an actor turn sends to a context with no
/// registered actor needs that actor respawned. While another bootstrap
/// holds `bootstrap_spawn_lock` the send returns a retryable `ActorBusy`
/// on its reply instead of waiting for the lock, whose holder may be
/// waiting on the sending actor's mailbox.
#[tokio::test(start_paused = true)]
async fn an_in_turn_recovery_send_needing_a_respawn_is_busy_while_the_lock_is_held() {
    let persistence = FaultyPersistence::default();
    let sup = first_contact_supervisor(Box::new(persistence), durable_over_one_store());
    let ctx = hex::encode([0xF3u8; 32]);
    let _held = sup.bootstrap_spawn_lock.lock().await;
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let payload = crate::context::actor::commands::RecoverySendNotificationPayload {
        context_id: ctx.clone(),
        sender_did: "did:example:recovery-sender".to_owned(),
        payload: b"recovery-notification-payload".to_vec(),
        sequence: 1,
        signer: CommandSigner::local_ed25519(ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32])),
    };
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        sup.dispatch_recovery_send_notification_in_turn(Box::new(payload), reply_tx),
    )
    .await
    .expect("the in-turn send does not wait for the bootstrap lock")
    .unwrap();
    let err = reply_rx.await.unwrap().unwrap_err();
    assert!(
        matches!(&err, ContextError::ActorBusy(msg) if msg.contains("retry")),
        "{err:?}"
    );
    assert!(sup.lookup(&ctx).is_none(), "no actor was respawned");
}

/// Shutdown ends while a first-state snapshot write hangs: after shutdown
/// begins the writes task gives the write a bounded time, then abandons
/// it, so `shutdown_all_contexts`, which awaits every tracked task, does
/// not hang. A rollback after that keeps the records, since the write may
/// still land.
#[tokio::test(start_paused = true)]
async fn shutdown_ends_while_a_first_state_write_hangs() {
    let persistence = FaultyPersistence::default();
    FaultyPersistence::set(&persistence.hang_writes);
    let sup = first_contact_supervisor(Box::new(persistence.clone()), durable_over_one_store());
    let contacts = sup.relay_contact_store();
    let identity = sup.node_identity().unwrap();
    let ctx_bytes = [0xF2u8; 32];
    let ctx = hex::encode(ctx_bytes);
    let deps = sup.build_actor_deps_loaded(&identity).await.unwrap();
    let guard = crate::context::shared::lifecycle::FirstStateRollback::new(&deps, &ctx).unwrap();
    let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_bytes,
        FIRST_CONTACT_NOW,
        identity.clone(),
    );
    // The operation's future is dropped mid-write; the tracked writes
    // task keeps waiting on the hung snapshot write.
    let abandoned = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        crate::context::shared::lifecycle::persist_first_state(&state, &deps, &ctx, &guard),
    )
    .await;
    assert!(abandoned.is_err(), "the snapshot write hangs");
    assert!(FaultyPersistence::is_set(&persistence.write_started));

    let shutdown = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        sup.shutdown_all_contexts(),
    )
    .await;
    assert!(shutdown.is_ok(), "shutdown ends while the write hangs");

    let err = guard
        .rollback(sup.bootstrap_spawn_lock.lock())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ContextError::PersistenceFailed(msg) if msg.contains("abandoned")),
        "{err:?}"
    );
    assert_eq!(
        contacts.load_last_relay_contact(&ctx).await.unwrap(),
        Some(FIRST_CONTACT_NOW),
        "the contact written before the hung snapshot write is kept"
    );
}

/// A second create of a running context's id fails with `CreationFailed`
/// and leaves the first context's snapshot, contact, and actor in place.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_create_over_a_running_context_keeps_its_snapshot_and_contact() {
    let persistence = FaultyPersistence::default();
    let sup = first_contact_supervisor(Box::new(persistence.clone()), durable_over_one_store());
    let contacts = sup.relay_contact_store();
    let identity = sup.node_identity().unwrap();
    let ctx = hex::encode([0xEDu8; 32]);
    sup.create_context(
        ctx.clone(),
        first_contact_params(),
        identity.clone(),
        None,
        Vec::new(),
    )
    .await
    .unwrap();
    // A later contact, which a second create's first contact would
    // replace.
    contacts
        .store_last_relay_contact(&ctx, FIRST_CONTACT_NOW + 60)
        .await
        .unwrap();
    let err = sup
        .create_context(
            ctx.clone(),
            first_contact_params(),
            identity,
            None,
            Vec::new(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            scp_protocol::context::builder::ContextCreationError::CreationFailed(ref msg)
                if msg.contains("is running")
        ),
        "{err:?}"
    );
    assert!(sup.lookup(&ctx).is_some(), "the first context still runs");
    assert!(
        persistence.contexts.contains_key(&ctx),
        "the snapshot is kept"
    );
    assert_eq!(
        contacts.load_last_relay_contact(&ctx).await.unwrap(),
        Some(FIRST_CONTACT_NOW + 60),
        "the contact is kept"
    );
}

/// Shutdown closes the spawn gate before it clears the wrapping-key map,
/// so a `wrapping_key` call that misses the map has already met the
/// closed gate and reports `SupervisorShutDown`, never `InvalidState`.
/// The map holds the only reference to the loaded key and through it to
/// its custody, so the clear drops that custody, which records whether
/// the gate was closed at that moment.
#[tokio::test]
async fn shutdown_closes_the_spawn_gate_before_it_clears_the_wrapping_keys() {
    let custody = Arc::new(LockCheckingCustody::new());
    let gate_closed_at_drop = Arc::clone(&custody.gate_closed_at_drop);
    // The source hands the custody out once, so after the load the loaded
    // key holds the only reference to it.
    let slot = std::sync::RwLock::new(Some(Arc::clone(&custody)));
    let source: WrappingCustodySource = Arc::new(move |_: &DID| {
        slot.write()
            .unwrap()
            .take()
            .map(|c| -> Arc<dyn crate::crypto::wrapping::WrappingCustody> {
                Arc::new(crate::crypto::wrapping::ErasedCustody(c))
            })
    });
    let sup =
        supervisor_with_persistence_and_custody_source(Box::new(MapPersistence::default()), source);
    custody
        .supervisor
        .set(Arc::downgrade(&sup))
        .unwrap_or_else(|_| unreachable!("set once"));
    drop(custody);
    let did = DID("did:example:wrap-shutdown-order".to_owned());
    drop(sup.load_wrapping_key(&did).await.unwrap());
    assert!(
        gate_closed_at_drop.get().is_none(),
        "the map keeps the loaded key's custody alive"
    );

    sup.shutdown_all_contexts().await;
    assert!(sup.wrapping_keys.is_empty(), "shutdown clears the map");
    assert_eq!(
        gate_closed_at_drop.get(),
        Some(&true),
        "the gate is closed when the clear drops the key"
    );
}

/// In-memory custody that, on every wrapping-key call, tries the
/// supervisor's `write_lock` and `bootstrap_spawn_lock` and records each
/// one it finds held: a host custody call may wait on a prompt, so no
/// such call may run while either lock is held.
struct LockCheckingCustody {
    inner: scp_platform::testing::InMemoryKeyCustody,
    supervisor: std::sync::OnceLock<std::sync::Weak<Supervisor>>,
    calls: std::sync::atomic::AtomicUsize,
    held: std::sync::Mutex<Vec<String>>,
    /// Set when this custody drops, while its supervisor is alive, to
    /// whether that supervisor's spawn gate was closed at the drop.
    gate_closed_at_drop: Arc<std::sync::OnceLock<bool>>,
}

impl LockCheckingCustody {
    fn new() -> Self {
        Self {
            inner: scp_platform::testing::InMemoryKeyCustody::new(),
            supervisor: std::sync::OnceLock::new(),
            calls: std::sync::atomic::AtomicUsize::new(0),
            held: std::sync::Mutex::new(Vec::new()),
            gate_closed_at_drop: Arc::new(std::sync::OnceLock::new()),
        }
    }

    fn check(&self, call: &str) {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let Some(sup) = self.supervisor.get().and_then(std::sync::Weak::upgrade) else {
            return;
        };
        let under_write = sup.write_lock.try_lock().is_err();
        let under_spawn = sup.bootstrap_spawn_lock.try_lock().is_err();
        let found = [
            under_write.then(|| format!("{call} under write_lock")),
            under_spawn.then(|| format!("{call} under bootstrap_spawn_lock")),
        ];
        self.held
            .lock()
            .unwrap()
            .extend(found.into_iter().flatten());
    }

    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl scp_platform::KeyEventSigner for LockCheckingCustody {
    type Member = scp_platform::KeyHandle;

    async fn sign_change(
        &self,
        member: &scp_platform::KeyHandle,
        change: &scp_platform::SigningChange,
    ) -> Result<scp_platform::IndexedSignature, scp_platform::KeyEventSignError> {
        self.check("sign_change");
        self.inner.sign_change(member, change).await
    }

    async fn sign_probe(
        &self,
        member: &scp_platform::KeyHandle,
        probe: &scp_platform::CustodyProbe,
    ) -> Result<scp_platform::ProbeSignature, scp_platform::KeyEventSignError> {
        self.check("sign_probe");
        self.inner.sign_probe(member, probe).await
    }
}

impl scp_platform::traits::KeyCustody for LockCheckingCustody {
    async fn generate_key_event_keypair(
        &self,
    ) -> Result<scp_platform::KeyHandle, scp_platform::PlatformError> {
        self.check("generate_key_event_keypair");
        self.inner.generate_key_event_keypair().await
    }

    async fn generate_keypair(
        &self,
        key_type: scp_platform::traits::KeyType,
    ) -> Result<scp_platform::KeyHandle, scp_platform::PlatformError> {
        self.check("generate_keypair");
        self.inner.generate_keypair(key_type).await
    }

    async fn generate_identity_keypair(
        &self,
    ) -> Result<scp_platform::KeyHandle, scp_platform::PlatformError> {
        self.inner.generate_identity_keypair().await
    }

    async fn sign(
        &self,
        key: &scp_platform::KeyHandle,
        data: &[u8],
    ) -> Result<scp_platform::traits::Signature, scp_platform::PlatformError> {
        self.inner.sign(key, data).await
    }

    async fn public_key(
        &self,
        key: &scp_platform::KeyHandle,
    ) -> Result<scp_platform::traits::PublicKey, scp_platform::PlatformError> {
        self.check("public_key");
        self.inner.public_key(key).await
    }

    async fn destroy_key(
        &self,
        key: &scp_platform::KeyHandle,
    ) -> Result<(), scp_platform::PlatformError> {
        self.inner.destroy_key(key).await
    }

    async fn dh_agree(
        &self,
        key: &scp_platform::KeyHandle,
        peer_public: &[u8],
    ) -> Result<scp_platform::traits::SharedSecret, scp_platform::PlatformError> {
        self.check("dh_agree");
        self.inner.dh_agree(key, peer_public).await
    }

    async fn derive_pseudonym(
        &self,
        key: &scp_platform::KeyHandle,
        context_id: &[u8],
    ) -> Result<scp_platform::traits::Pseudonym, scp_platform::PlatformError> {
        self.inner.derive_pseudonym(key, context_id).await
    }

    async fn derive_rotatable_pseudonym(
        &self,
        key: &scp_platform::KeyHandle,
        context_id: &[u8],
        pseudonym_epoch: u64,
    ) -> Result<scp_platform::traits::Pseudonym, scp_platform::PlatformError> {
        self.inner
            .derive_rotatable_pseudonym(key, context_id, pseudonym_epoch)
            .await
    }

    fn custody_type(&self, key: &scp_platform::KeyHandle) -> scp_platform::traits::CustodyType {
        self.inner.custody_type(key)
    }
}

impl Drop for LockCheckingCustody {
    fn drop(&mut self) {
        if let Some(sup) = self.supervisor.get().and_then(std::sync::Weak::upgrade) {
            let _ = self
                .gate_closed_at_drop
                .set(sup.refuse_if_shut_down("custody drop probe").is_err());
        }
    }
}

/// A supervisor whose wrapping custody is a [`LockCheckingCustody`] bound
/// to it.
fn lock_checking_supervisor() -> (Arc<Supervisor>, Arc<LockCheckingCustody>) {
    let custody = Arc::new(LockCheckingCustody::new());
    let sup = supervisor_with_persistence_and_custody_source(
        Box::new(MapPersistence::default()),
        crate::crypto::wrapping::single_custody_source(Arc::clone(&custody)),
    );
    custody
        .supervisor
        .set(Arc::downgrade(&sup))
        .unwrap_or_else(|_| unreachable!("set once"));
    (sup, custody)
}

/// Runs `driver`, then asserts it made at least one wrapping custody call
/// and returns its result.
async fn assert_custody_called<T>(
    custody: &LockCheckingCustody,
    driver: &str,
    fut: impl std::future::Future<Output = T>,
) -> T {
    let before = custody.calls();
    let out = fut.await;
    assert!(
        custody.calls() > before,
        "{driver} must reach wrapping custody for this test to check it"
    );
    out
}

/// The join driver of
/// [`no_wrapping_custody_call_runs_under_write_lock_or_bootstrap_spawn_lock`]:
/// opens a sealed invitation for `identity` with no wrapping key loaded,
/// so the open reaches custody.
async fn drive_join_open_before_spawn_lock(
    sup: &Arc<Supervisor>,
    custody: &Arc<LockCheckingCustody>,
    identity: &DID,
) {
    use crate::context::supervisor::key_package_actor::{
        KeyPackageCommand, KeyPackageStoreHandle, ReservationId,
    };
    // The join reads the reservation's `0xFF01` from the owner's
    // KeyPackage store. This supervisor's resolver names no `#active` key,
    // so no store can mint; a store stand-in answers with the owner's own
    // wrapping key. The sealed bytes are no bundle, so the join fails at
    // the bundle decode, under `bootstrap_spawn_lock`, after the open.
    let owner_key = sup.load_wrapping_key(identity).await.unwrap();
    let reserved =
        scp_protocol::crypto::hpke::p256::P256Point::try_from(*owner_key.public()).unwrap();
    let (store_tx, mut store_rx) = tokio::sync::mpsc::channel(4);
    let store = tokio::spawn(async move {
        while let Some(cmd) = store_rx.recv().await {
            if let KeyPackageCommand::ReservedWrappingKey { reply, .. } = cmd {
                let _ = reply.send(Ok(reserved));
            }
        }
    });
    sup.key_package_stores.insert(
        identity.clone(),
        KeyPackageStoreHandle::from_sender(store_tx),
    );
    sup.wrapping_keys.clear();
    let join_ctx = hex::encode([0xD2u8; 32]);
    let creator = "did:example:lock-discipline-creator";
    let (ct, enc) = scp_protocol::crypto::envelope_seal::hpke_seal_invitation(
        b"not an invitation bundle",
        &reserved,
        &join_ctx,
        creator,
    )
    .unwrap();
    let joined = assert_custody_called(
        custody,
        "spawn_actor_from_welcome",
        sup.spawn_actor_from_welcome(
            identity.clone(),
            WelcomeJoinRequest {
                context_id: join_ctx,
                creator_did: DID(creator.to_owned()),
                sealed_bundle_enc: enc.as_bytes().to_vec(),
                sealed_bundle_ct: ct,
                reservation_id: ReservationId::new_random(),
                local_pseudonym: None,
            },
        ),
    )
    .await;
    assert!(
        matches!(&joined, Err(ContextError::CryptoFailed(m)) if m.contains("bundle decode")),
        "the join opened the invitation and failed at the decode: {joined:?}"
    );
    store.abort();
}

/// Spec 09 §9.16.1 and ADR-049: a host custody call may wait on a user
/// prompt, so no wrapping custody call runs under `write_lock` or
/// `bootstrap_spawn_lock`. Each driver below starts with no key loaded, so
/// it reaches custody: CreateContext, Restore, Import, `standing_context`,
/// `reserve_key_package`, `clear_poison` and `spawn_actor_from_welcome`,
/// whose invitation open (`public_key`, `dh_agree`) runs before it takes
/// `bootstrap_spawn_lock`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_wrapping_custody_call_runs_under_write_lock_or_bootstrap_spawn_lock() {
    let (sup, custody) = lock_checking_supervisor();
    // Control: a call made while `write_lock` is held is recorded.
    {
        let _guard = sup.write_lock.lock().await;
        custody.check("control");
    }
    assert_eq!(
        std::mem::take(&mut *custody.held.lock().unwrap()),
        vec!["control under write_lock".to_owned()],
        "the custody detects a held lock"
    );
    let identity = sup.node_identity().unwrap();
    let params = scp_protocol::context::ContextParams {
        ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
        ..Default::default()
    };

    let ctx = hex::encode([0xD1u8; 32]);
    let handle = assert_custody_called(
        &custody,
        "CreateContext",
        sup.create_context(
            ctx.clone(),
            params.clone(),
            identity.clone(),
            None,
            Vec::new(),
        ),
    )
    .await
    .unwrap();

    assert!(sup.despawn_actor(&ctx).await);
    sup.wrapping_keys.clear();
    assert_custody_called(&custody, "Restore", sup.restore_context(&ctx, &handle))
        .await
        .unwrap();

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let export = sup
        .export_context(
            &ctx,
            identity.clone(),
            &CommandSigner::local_ed25519(signing_key.clone()),
        )
        .await
        .unwrap();
    let (importer, importer_custody) = lock_checking_supervisor();
    assert_custody_called(
        &importer_custody,
        "Import",
        Box::pin(importer.import_context(export, &signing_key.verifying_key(), None)),
    )
    .await
    .unwrap();

    sup.wrapping_keys.clear();
    let peer = DID("did:example:lock-discipline-peer".to_owned());
    assert_custody_called(
        &custody,
        "standing_context",
        Box::pin(sup.standing_context(&identity, &peer, Vec::new())),
    )
    .await
    .unwrap();

    // The reserve loads the owner's wrapping key before anything else; the
    // supervisor's resolver names no `#active` key, so it then refuses.
    let fresh = DID("did:dht:z6MkLockDisciplineKpOwner".to_owned());
    let fresh_signer = crate::context::actor::CommandSigner::local_ed25519(
        ed25519_dalek::SigningKey::from_bytes(&[0x3C; 32]),
    );
    let reserved = assert_custody_called(
        &custody,
        "reserve_key_package",
        sup.reserve_key_package(fresh, &fresh_signer),
    )
    .await;
    assert!(matches!(
        reserved,
        Err(ContextError::AttestationSignerActiveKeyUnresolved)
    ));

    // `clear_poison` loads the owner's wrapping key before it takes
    // `bootstrap_spawn_lock`. The context carries no poison record, so
    // what the respawn answers is not what this test checks and the
    // result is ignored; the custody call before the lock is checked.
    sup.wrapping_keys.clear();
    let _ = assert_custody_called(
        &custody,
        "clear_poison",
        Box::pin(sup.clear_poison(&ctx, &identity)),
    )
    .await;

    Box::pin(drive_join_open_before_spawn_lock(&sup, &custody, &identity)).await;

    let held: Vec<String> = custody
        .held
        .lock()
        .unwrap()
        .iter()
        .chain(importer_custody.held.lock().unwrap().iter())
        .cloned()
        .collect();
    assert!(held.is_empty(), "custody calls ran under a lock: {held:?}");
}

/// With no wrapping key loaded for an owner, building its actor deps and
/// resolving its KeyPackage store fail closed with `InvalidState` and
/// load nothing; once shutdown begins, the same lookup reports
/// `SupervisorShutDown`.
#[tokio::test]
async fn build_actor_deps_without_a_loaded_wrapping_key_is_invalid_state() {
    let sup = supervisor_with_providers();
    let did = DID("did:example:never-loaded".to_owned());

    let deps = sup.build_actor_deps(&did).await.map(|_| ());
    assert!(
        matches!(&deps, Err(ContextError::InvalidState(m)) if m == "wrapping key not loaded for the actor owner"),
        "{deps:?}"
    );
    let store = sup.key_package_store_for(&did).await.map(|_| ());
    assert!(
        matches!(&store, Err(ContextError::InvalidState(m)) if m == "wrapping key not loaded for the actor owner"),
        "{store:?}"
    );
    assert!(sup.wrapping_keys.is_empty(), "a lookup loads nothing");

    sup.shutdown_all_contexts().await;
    let store = sup.key_package_store_for(&did).await.map(|_| ());
    assert!(
        matches!(&store, Err(ContextError::SupervisorShutDown(_))),
        "{store:?}"
    );
}

/// Bob's receive side for the `deliver_incoming` tests: his actor-owned
/// state (active, holding Bob and Alice as members and Bob's access key) in
/// a cell, his production `ActorDeps` over `resolver`, Alice's actor state
/// for sealing, and Bob's access key.
#[cfg(feature = "testing")]
struct DeliverFixture {
    rt: tokio::runtime::Runtime,
    bob_cell: crate::context::actor::class_s::ClassSCell,
    bob_deps: crate::context::actor::deps::ActorDeps,
    bob_sup: Arc<Supervisor>,
    alice_state: crate::context::actor::state::PerContextState,
    bob_access_key: scp_protocol::crypto::access_keys::AccessKey,
    ctx_bytes: [u8; 32],
}

#[cfg(feature = "testing")]
impl DeliverFixture {
    const ALICE: &'static str = "did:dht:z6MkAliceDeliverAliceDeliverAliceDeli1";
    const BOB: &'static str = "did:dht:z6MkBobDeliverBobDeliverBobDeliverBo1";

    fn new(ctx_str: &str, resolver: KeyResolver) -> Self {
        use scp_protocol::context::ContextState;

        let crate::crypto::mls::two_party_test_support::TwoPartyPair {
            alice_state,
            bob_provider,
            mut bob_state,
            ctx_bytes,
            ..
        } = crate::crypto::mls::two_party_test_support::stand_up_two_party(
            ctx_str,
            Self::ALICE,
            Self::BOB,
        );
        let bob_sup = supervisor_with_crypto_and_resolver(bob_provider, resolver);
        let rt = tokio::runtime::Builder::new_current_thread() // ci-allow: block-on: test-only, drives Bob's actor dispatch from a sync #[test]; not a production async bridge
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(bob_sup.register_local_did(DID::from(Self::BOB)));
        let bob_deps = rt
            .block_on(bob_sup.build_actor_deps_loaded(&DID::from(Self::BOB)))
            .expect("build bob's actor deps");

        bob_state
            .handle
            .transition_to(&ContextState::Active)
            .expect("transition bob's context to Active");
        for did in [Self::ALICE, Self::BOB] {
            bob_state
                .membership
                .add_member(DID::from(did), "member".to_owned(), Vec::new());
            bob_state.members.insert(DID::from(did));
            // The receive path delivers only a sender holding
            // `messages:write`, so each member gets it.
            bob_state.role_state.members.insert(did.to_owned());
            bob_state.role_state.member_capabilities.insert(
                did.to_owned(),
                std::collections::HashSet::from([
                    scp_protocol::context::roles::Capability::MessagesWrite,
                ]),
            );
        }
        let bob_access_key =
            scp_protocol::crypto::access_keys::generate_access_key(ctx_str, Self::BOB);
        bob_state
            .access
            .access_key_store
            .set(ctx_str, Self::BOB, bob_access_key.clone());

        Self {
            rt,
            bob_cell: crate::context::actor::class_s::ClassSCell::new(bob_state),
            bob_deps,
            bob_sup,
            alice_state,
            bob_access_key,
            ctx_bytes,
        }
    }

    /// Seals `payload` through Alice's production app-data seal at sender
    /// sequence `aad_sequence`, naming `claimed_sender` as the inner sender
    /// and signing with `signing_key`. Sequences start at 1; the receive
    /// path rejects sequence 0.
    fn seal_from_alice(
        &mut self,
        ctx_str: &str,
        claimed_sender: &str,
        signing_key: &ed25519_dalek::SigningKey,
        aad_sequence: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        let clock: Arc<dyn scp_clock::Clock> = Arc::new(scp_clock::SystemClock);
        let recipients =
            std::collections::HashMap::from([(Self::BOB.to_owned(), self.bob_access_key.clone())]);
        let signer = CommandSigner::local_ed25519(signing_key.clone());
        let crypto = self
            .alice_state
            .mode
            .crypto_mut()
            .expect("encrypted context");
        self.rt
            .block_on(
                crate::context::shared::messaging::build_encrypted_envelope_actor(
                    &clock,
                    crypto,
                    Self::ALICE,
                    ctx_str,
                    &DID::from(claimed_sender),
                    payload,
                    crate::context::supervisor::MessageSigner::Active(&signer),
                    &recipients,
                    aad_sequence,
                    None,
                    scp_protocol::envelope::inner::MessageType::Content,
                ),
            )
            .expect("alice seals the application message")
    }

    /// Alice's correctly signed inner envelope for `payload` at sender
    /// sequence `aad_sequence`, before sealing.
    fn alice_inner(
        &self,
        ctx_str: &str,
        aad_sequence: u64,
        payload: &[u8],
    ) -> (crate::envelope::inner::InnerEnvelope, [u8; 32]) {
        let clock: Arc<dyn scp_clock::Clock> = Arc::new(scp_clock::SystemClock);
        let recipients =
            std::collections::HashMap::from([(Self::BOB.to_owned(), self.bob_access_key.clone())]);
        let signer = CommandSigner::local_ed25519(
            crate::crypto::mls::two_party_test_support::alice_signing_key(),
        );
        self.rt
            .block_on(crate::context::shared::messaging::build_inner_wire(
                &clock,
                ctx_str,
                &DID::from(Self::ALICE),
                payload,
                crate::context::supervisor::MessageSigner::Active(&signer),
                &recipients,
                aad_sequence,
                None,
                scp_protocol::envelope::inner::MessageType::Content,
            ))
            .expect("alice builds the inner envelope")
    }

    /// Seals `inner` through Alice's production sender-key and MLS seal at
    /// sender sequence `aad_sequence`.
    fn seal_inner_from_alice(
        &mut self,
        context_id_bytes: &[u8; 32],
        inner: &crate::envelope::inner::InnerEnvelope,
        aad_sequence: u64,
    ) -> Vec<u8> {
        self.alice_state
            .mode
            .crypto_mut()
            .expect("encrypted context")
            .seal(context_id_bytes, Self::ALICE, inner, aad_sequence)
            .expect("alice seals the application message")
    }

    /// Asserts `result` is the receive path's content-integrity rejection
    /// and that Bob's recv floor did not move.
    fn assert_integrity_rejection(
        &self,
        result: &Result<crate::context::actor::commands::DeliverOutcome, ContextError>,
    ) {
        assert!(
            matches!(result, Err(ContextError::CryptoFailed(m)) if m == "content integrity check failed"),
            "the content-integrity check must reject the envelope, got {result:?}"
        );
        assert!(
            self.bob_sup
                .export_recv_sequence_floors(&self.ctx_bytes)
                .is_empty(),
            "a rejected envelope must not move the recv floor"
        );
    }

    /// Delivers `blob` to Bob through the production actor receive path
    /// (`MessagingCommand::DeliverIncoming` → `deliver_incoming`).
    fn deliver(
        &mut self,
        ctx_str: &str,
        blob: Vec<u8>,
    ) -> Result<crate::context::actor::commands::DeliverOutcome, ContextError> {
        use crate::context::actor::commands::MessagingCommand;
        self.rt.block_on(async {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let _outcome = crate::context::actor::handlers::messaging::dispatch(
                &mut self.bob_cell,
                &self.bob_deps,
                MessagingCommand::DeliverIncoming {
                    context_id: ctx_str.to_owned(),
                    envelope_bytes: blob,
                    mode: crate::context::actor::commands::DeliveryMode::Live,
                    reply: tx,
                },
            )
            .await;
            rx.await.expect("deliver reply")
        })
    }
}

/// §9.8.1 on the production receive path: Alice, an authenticated MLS
/// member, sends an inner envelope whose `sender_did` names Carol. The
/// receive path rejects it with `SenderMismatch` naming only the MLS sender,
/// and it rejects it before resolving any key.
#[cfg(feature = "testing")]
#[test]
fn deliver_incoming_rejects_inner_sender_other_than_mls_sender() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    const CAROL: &str = "did:dht:z6MkCarolDeliverCarolDeliverCarolDelive1";
    let ctx_str = "deliver-incoming-sender-binding";

    let lookups = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&lookups);
    let inner_resolver = crate::crypto::mls::two_party_test_support::pair_resolver(
        DeliverFixture::ALICE,
        DeliverFixture::BOB,
    );
    let resolver: KeyResolver = Arc::new(move |did: &DID, kid| {
        counted.fetch_add(1, Ordering::SeqCst);
        inner_resolver(did, kid)
    });
    let mut fx = DeliverFixture::new(ctx_str, resolver);

    let forged = fx.seal_from_alice(
        ctx_str,
        CAROL,
        &crate::crypto::mls::two_party_test_support::alice_signing_key(),
        1,
        b"claims to come from carol",
    );
    let before = lookups.load(Ordering::SeqCst);
    let result = fx.deliver(ctx_str, forged);

    match &result {
        Err(ContextError::SenderMismatch { mls_sender }) => {
            assert_eq!(mls_sender, DeliverFixture::ALICE);
        }
        other => panic!("expected SenderMismatch naming the MLS sender, got {other:?}"),
    }
    let rendered = format!("{}", result.unwrap_err());
    assert!(
        !rendered.contains(CAROL),
        "the error must not echo the attacker-chosen inner sender: {rendered}"
    );
    assert_eq!(
        lookups.load(Ordering::SeqCst) - before,
        0,
        "no key may be resolved for a mismatched sender"
    );
}

/// §9.8.2 on the production receive path: an envelope whose inner
/// signature fails at `(epoch, sequence)` does not advance the recv floor,
/// so the genuine envelope at the same `(epoch, sequence)` is still
/// accepted.
#[cfg(feature = "testing")]
#[test]
fn deliver_incoming_failed_verification_does_not_burn_the_floor() {
    let ctx_str = "deliver-incoming-floor-after-verify";
    let resolver = crate::crypto::mls::two_party_test_support::pair_resolver(
        DeliverFixture::ALICE,
        DeliverFixture::BOB,
    );
    let mut fx = DeliverFixture::new(ctx_str, resolver);

    let wrong_key = ed25519_dalek::SigningKey::from_bytes(&[0x99; 32]);
    let forged = fx.seal_from_alice(
        ctx_str,
        DeliverFixture::ALICE,
        &wrong_key,
        1,
        b"forged at (1, 1)",
    );
    let genuine = fx.seal_from_alice(
        ctx_str,
        DeliverFixture::ALICE,
        &crate::crypto::mls::two_party_test_support::alice_signing_key(),
        1,
        b"genuine at (1, 1)",
    );

    let rejected = fx.deliver(ctx_str, forged);
    assert!(
        matches!(&rejected, Err(ContextError::CryptoFailed(m)) if m.contains("signature")),
        "a bad inner signature must be rejected, got {rejected:?}"
    );
    assert!(
        fx.bob_sup
            .export_recv_sequence_floors(&fx.ctx_bytes)
            .is_empty(),
        "a rejected envelope must not move the recv floor"
    );

    let accepted = fx
        .deliver(ctx_str, genuine)
        .expect("the genuine envelope at the same (epoch, sequence) is accepted");
    assert!(
        matches!(
            &accepted,
            crate::context::actor::commands::DeliverOutcome::Application((pt, sender))
                if pt.as_slice() == b"genuine at (1, 1)" && sender == DeliverFixture::ALICE
        ),
        "the genuine envelope must surface as Alice's application message, got {accepted:?}"
    );
}

/// The production receive path rejects an inner envelope whose payload was
/// replaced after Alice signed it. The signature covers `payload_hash`, not
/// the padded payload, so only the content-integrity check
/// (`payload_hash == SHA256(stripped_payload)`) catches the swap.
#[cfg(feature = "testing")]
#[test]
fn deliver_incoming_rejects_a_payload_altered_after_signing() {
    let ctx_str = "deliver-incoming-altered-payload";
    let resolver = crate::crypto::mls::two_party_test_support::pair_resolver(
        DeliverFixture::ALICE,
        DeliverFixture::BOB,
    );
    let mut fx = DeliverFixture::new(ctx_str, resolver);

    let (mut inner, ctx_id) = fx.alice_inner(ctx_str, 1, b"signed content");
    let (other, _) = fx.alice_inner(ctx_str, 1, b"swapped content");
    assert_ne!(inner.payload, other.payload);
    inner.payload = other.payload;
    let altered = fx.seal_inner_from_alice(&ctx_id, &inner, 1);

    let result = fx.deliver(ctx_str, altered);
    fx.assert_integrity_rejection(&result);
}

/// The production receive path rejects an inner envelope whose signed
/// `payload_hash` does not match its payload: Alice signs the hash of other
/// content, so the signature verifies and only the content-integrity check
/// rejects it.
#[cfg(feature = "testing")]
#[test]
fn deliver_incoming_rejects_a_signed_payload_hash_that_does_not_match_the_payload() {
    let ctx_str = "deliver-incoming-mismatched-payload-hash";
    let resolver = crate::crypto::mls::two_party_test_support::pair_resolver(
        DeliverFixture::ALICE,
        DeliverFixture::BOB,
    );
    let mut fx = DeliverFixture::new(ctx_str, resolver);

    let (mut inner, ctx_id) = fx.alice_inner(ctx_str, 1, b"signed content");
    let (other, _) = fx.alice_inner(ctx_str, 1, b"other content");
    inner.payload_hash = other.payload_hash;
    let canonical = scp_protocol::envelope::inner::compute_canonical_hash(
        &crate::envelope::inner::InnerEnvelopeParams {
            version: inner.version,
            context_id: &inner.context_id,
            sender_did: &inner.sender_did,
            epoch: inner.epoch,
            generation: inner.generation,
            sequence: inner.sequence,
            timestamp: inner.timestamp,
            message_type: inner.message_type,
            payload: &[],
            provenance: None,
            signing_key_id: inner.signing_key_id,
        },
        &inner.payload_hash,
        &inner.provenance_hash,
    )
    .expect("canonical hash");
    inner.signature = ed25519_dalek::Signer::sign(
        &crate::crypto::mls::two_party_test_support::alice_signing_key(),
        &canonical,
    )
    .to_bytes();
    assert!(
        scp_protocol::envelope::inner::verify_inner_signature(
            &inner,
            crate::crypto::mls::two_party_test_support::alice_signing_key()
                .verifying_key()
                .as_bytes(),
        )
        .expect("verifiable"),
        "the mismatched hash carries Alice's valid signature"
    );
    let mismatched = fx.seal_inner_from_alice(&ctx_id, &inner, 1);

    let result = fx.deliver(ctx_str, mismatched);
    fx.assert_integrity_rejection(&result);
}

/// An application message whose MLS sender is the receiving node's own DID
/// is rejected with an error, in debug builds too. The receiver here is
/// Bob's group state driven by deps whose local DID is Alice's, which is the
/// shape a second device of Alice's identity would have.
#[cfg(feature = "testing")]
#[test]
fn decrypt_and_dispatch_rejects_application_message_from_own_did() {
    use crate::envelope::inner::sign::create_inner_envelope_raw;
    use crate::envelope::inner::{InnerEnvelopeParams, MessageType};
    use scp_did::SigningKeyId;

    const ALICE: &str = "did:dht:z6MkAliceOwnDidAliceOwnDidAliceOwnDidA1";
    const BOB: &str = "did:dht:z6MkBobOwnDidBobOwnDidBobOwnDidBobOwnD1";
    let ctx_str = "decrypt-and-dispatch-own-did";

    let crate::crypto::mls::two_party_test_support::TwoPartyPair {
        alice_provider,
        alice_state: mut alice_actor,
        bob_state: mut bob_actor,
        ctx_bytes,
        ..
    } = crate::crypto::mls::two_party_test_support::stand_up_two_party(ctx_str, ALICE, BOB);

    let alice_sup = supervisor_with_crypto(Arc::clone(&alice_provider));
    let rt = tokio::runtime::Builder::new_current_thread() // ci-allow: block-on: test-only, builds ActorDeps from a sync #[test]; not a production async bridge
        .enable_all()
        .build()
        .unwrap();
    let own_did_deps = rt
        .block_on(alice_sup.build_actor_deps_loaded(&DID::from(ALICE)))
        .expect("build deps whose local DID is alice");

    let inner = create_inner_envelope_raw(
        &InnerEnvelopeParams {
            version: scp_protocol::envelope::SCP_PROTOCOL_VERSION,
            context_id: ctx_str,
            sender_did: ALICE,
            epoch: 1,
            generation: 0,
            sequence: 0,
            timestamp: 1_700_000_000,
            message_type: MessageType::Content,
            payload: b"from alice to her own identity",
            provenance: None,
            signing_key_id: SigningKeyId::Active,
        },
        &crate::crypto::mls::two_party_test_support::alice_signing_key(),
    )
    .expect("alice signs");
    let sealed = alice_actor.seal(ALICE, &inner).expect("alice seals");

    let bob_cs = bob_actor.mode.crypto_mut().expect("encrypted context");
    let result = rt.block_on(crate::context::messaging_helpers::decrypt_and_dispatch(
        &own_did_deps,
        Some(bob_cs),
        ctx_str,
        &ctx_bytes,
        &sealed,
        &std::collections::HashSet::new(),
    ));
    assert!(
        matches!(&result, Err(ContextError::CryptoFailed(m)) if m == "application message from own DID"),
        "an application message from the local DID must be rejected, got {result:?}"
    );
}

/// ADR-049 §9 / cryptographer HIGH-1 regression: a heartbeat send reports
/// `Outcome { mutated: true }`. `send_heartbeat` SEALS an encrypted
/// `Heartbeat` envelope, which advances the actor-owned MLS group's send
/// ratchet GENERATION — Class-C per-context crypto state that a
/// `mutated: false` would silently drop on a ≤50ms coalesce-window crash.
/// The handler previously returned `Outcome::ok(())`; this pins the
/// `ok_mutated` fix so a heartbeat-only generation advance is coalesced.
#[cfg(feature = "testing")]
#[test]
fn send_heartbeat_handler_reports_mutated() {
    use crate::context::actor::class_s::ClassSCell;
    use crate::context::actor::commands::MessagingCommand;
    use scp_protocol::context::ContextState;
    use scp_protocol::context::roles::Capability;

    const ALICE: &str = "did:dht:z6MkAliceHeartbeatAliceHeartbeatAlice1";
    const BOB: &str = "did:dht:z6MkBobHeartbeatBobHeartbeatBobHeartbe1";
    let ctx_str = "heartbeat-mutated-regression";

    // Real two-party join, born directly onto actor-owned state: Alice's
    // actor owns the joined MLS group + her sender key.
    let crate::crypto::mls::two_party_test_support::TwoPartyPair {
        alice_provider: alice_crypto,
        mut alice_state,
        ..
    } = crate::crypto::mls::two_party_test_support::stand_up_two_party(ctx_str, ALICE, BOB);

    let alice_sup = supervisor_with_crypto(Arc::clone(&alice_crypto));
    let rt = tokio::runtime::Builder::new_current_thread() // ci-allow: block-on: test-only, drives async dispatch from a sync #[test]; not a production async bridge
        .enable_all()
        .build()
        .unwrap();
    let alice_deps = rt
        .block_on(alice_sup.build_actor_deps_loaded(&DID::from(ALICE)))
        .expect("build alice's actor deps");

    // Activate the context on Alice's owned actor state and seed Alice as a
    // member with `messages:write` directly (mirroring the
    // `writable_encrypted_state` fixture) so the heartbeat's require-active and
    // send-authorization gates pass without a governance round-trip.
    alice_state
        .handle
        .transition_to(&ContextState::Active)
        .expect("transition test handle to Active");
    alice_state
        .membership
        .add_member(DID::from(ALICE), "member".to_owned(), Vec::new());
    alice_state.members.insert(DID::from(ALICE));
    alice_state.role_state.members.insert(ALICE.to_owned());
    alice_state.role_state.member_capabilities.insert(
        ALICE.to_owned(),
        std::collections::HashSet::from([Capability::MessagesWrite]),
    );
    let mut cell = ClassSCell::new(alice_state);

    rt.block_on(async {
        // Send a heartbeat as Alice. The encrypted seal advances the MLS
        // generation even with no peers to fan out to (the seal precedes the
        // empty-routing no-op), so the handler MUST report `mutated: true`.
        let (htx, hrx) = tokio::sync::oneshot::channel();
        let heartbeat = MessagingCommand::SendHeartbeat {
            context_id: ctx_str.to_owned(),
            sender_did: DID::from(ALICE),
            signer: CommandSigner::local_ed25519(
                crate::crypto::mls::two_party_test_support::alice_signing_key(),
            ),
            reply: htx,
        };
        let outcome =
            crate::context::actor::handlers::messaging::dispatch(&mut cell, &alice_deps, heartbeat)
                .await;
        assert!(
            outcome.result.is_ok(),
            "a peerless heartbeat is a successful no-op send: {:?}",
            outcome.result
        );
        assert!(
            outcome.mutated,
            "a heartbeat seals an MLS envelope and advances the send-ratchet \
                 generation — the handler MUST report mutated (ADR-049 §9 HIGH-1)"
        );
        hrx.await.expect("heartbeat reply").expect("heartbeat ok");
    });
}

/// ADR-049 Decision 7a: a custody that never answers fails a signing
/// handler's turn with a custody failure of kind `TimedOut`
/// (`SCP-CRYPTO-4062`), not the handler's `TransportTimeout`. The handler
/// budget (`SIGNING_HANDLER_TIMEOUT`) outlasts the sign budget
/// (`SIGN_TIMEOUT`), so the sign budget always fires first.
#[cfg(feature = "testing")]
#[test]
fn stalled_custody_fails_signing_handler_with_custody_timeout() {
    use crate::context::actor::class_s::ClassSCell;
    use crate::context::actor::commands::MessagingCommand;
    use crate::context::actor::signer::SIGN_TIMEOUT;
    use scp_crypto::{CustodyFailure, CustodyFailureKind, DynScpSigner, SigAlg, SignFuture};
    use scp_protocol::context::ContextState;
    use scp_protocol::context::roles::Capability;

    /// A signer whose sign never completes, standing in for an
    /// unanswered biometric prompt.
    struct StalledSigner(Vec<u8>);

    impl DynScpSigner for StalledSigner {
        fn algorithm(&self) -> SigAlg {
            SigAlg::Ed25519
        }

        fn public_key(&self) -> Vec<u8> {
            self.0.clone()
        }

        fn sign_boxed<'a>(&'a self, _digest: &'a [u8; 32]) -> SignFuture<'a> {
            Box::pin(std::future::pending())
        }
    }

    const ALICE: &str = "did:dht:z6MkAliceStalledAliceStalledAliceStall1";
    const BOB: &str = "did:dht:z6MkBobStalledBobStalledBobStalledBobSt1";
    let ctx_str = "stalled-custody-handler-timeout";

    let crate::crypto::mls::two_party_test_support::TwoPartyPair {
        alice_provider: alice_crypto,
        mut alice_state,
        ..
    } = crate::crypto::mls::two_party_test_support::stand_up_two_party(ctx_str, ALICE, BOB);

    let alice_sup = supervisor_with_crypto(Arc::clone(&alice_crypto));
    let rt = tokio::runtime::Builder::new_current_thread() // ci-allow: block-on: test-only, drives async dispatch from a sync #[test]; not a production async bridge
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    let alice_deps = rt
        .block_on(alice_sup.build_actor_deps_loaded(&DID::from(ALICE)))
        .expect("build alice's actor deps");

    alice_state
        .handle
        .transition_to(&ContextState::Active)
        .expect("transition test handle to Active");
    alice_state
        .membership
        .add_member(DID::from(ALICE), "member".to_owned(), Vec::new());
    alice_state.members.insert(DID::from(ALICE));
    alice_state.role_state.members.insert(ALICE.to_owned());
    alice_state.role_state.member_capabilities.insert(
        ALICE.to_owned(),
        std::collections::HashSet::from([Capability::MessagesWrite]),
    );
    let mut cell = ClassSCell::new(alice_state);
    let public_key = crate::crypto::mls::two_party_test_support::alice_signing_key()
        .verifying_key()
        .to_bytes()
        .to_vec();

    rt.block_on(async {
        let (htx, hrx) = tokio::sync::oneshot::channel();
        let heartbeat = MessagingCommand::SendHeartbeat {
            context_id: ctx_str.to_owned(),
            sender_did: DID::from(ALICE),
            signer: CommandSigner::new(Arc::new(StalledSigner(public_key))),
            reply: htx,
        };
        let started = tokio::time::Instant::now();
        let outcome =
            crate::context::actor::handlers::messaging::dispatch(&mut cell, &alice_deps, heartbeat)
                .await;
        assert!(outcome.result.is_err(), "a stalled sign must fail the turn");
        assert!(started.elapsed() >= SIGN_TIMEOUT);
        let result = hrx.await.expect("heartbeat reply");
        assert!(
            matches!(
                &result,
                Err(ContextError::Custody(CustodyFailure {
                    kind: CustodyFailureKind::TimedOut,
                    ..
                }))
            ),
            "a stalled custody must surface as TimedOut (SCP-CRYPTO-4062), got {result:?}"
        );
    });
}

/// ADR-049 §9.16.2 sender-key PULL through the PRODUCTION receive path
/// (`decrypt_and_dispatch`). One test, two findings:
///
/// - **BLACK-P7-1 (identity binding):** a KeyRequest whose payload
///   `requester_did` != the MLS-authenticated sender is REJECTED before any
///   answer is enqueued (a blocked/impersonating member cannot request under
///   another member's identity).
/// - **BLACK-P7-2 (wire format):** a well-formed request is answered, and the
///   enqueued answer parses via the SAME
///   `SenderKeyDistributionMessage::from_bytes` the receiver uses — proving
///   the answer is the `KeyResponse` envelope, not a bare `SenderKeyResponse`
///   — and the requester recovers a real sender key from the ephemeral seal.
#[cfg(feature = "testing")]
#[test]
#[allow(clippy::too_many_lines)] // one cohesive receive-path flow: BLACK-P7-1 identity-binding reject + BLACK-P7-2 wire-format answer round-trip
fn sender_key_pull_receive_path_binds_identity_and_wire_format() {
    use ed25519_dalek::Signer as _;
    use scp_clock::Clock as _;
    use scp_protocol::crypto::sender_keys::{SenderKeyDistributionMessage, SenderKeyRequest};

    const ALICE: &str = "did:dht:z6MkAlicePullAlicePullAlicePullAlice12";
    const BOB: &str = "did:dht:z6MkBobPullBobPullBobPullBobPullBobPu12";
    const CHARLIE: &str = "did:dht:z6MkCharliePullCharliePullCharliePul12";
    let ctx_str = "sender-key-pull-receive-path";

    let crate::crypto::mls::two_party_test_support::TwoPartyPair {
        alice_provider: alice_crypto,
        alice_state: mut alice_actor,
        bob_state: mut bob_actor,
        ctx_bytes,
        ..
    } = crate::crypto::mls::two_party_test_support::stand_up_two_party(ctx_str, ALICE, BOB);
    let ctx_hex = hex::encode(ctx_bytes);

    // Alice's production receive deps, with a resolver that maps BOB → his
    // #active key so the request signature check can run.
    let alice_sup = supervisor_with_crypto_and_resolver(
        Arc::clone(&alice_crypto),
        crate::crypto::mls::two_party_test_support::pair_resolver(ALICE, BOB),
    );
    let rt = tokio::runtime::Builder::new_current_thread() // ci-allow: block-on: test-only, builds Alice's ActorDeps from a sync #[test]; not a production async bridge
        .enable_all()
        .build()
        .unwrap();
    let alice_deps = rt
        .block_on(alice_sup.build_actor_deps_loaded(&DID::from(ALICE)))
        .expect("build alice's actor deps");

    // Build a Bob-signed KeyRequest (for Alice's key) sealing to a fresh
    // ephemeral wrapping key, wrapped in the distribution-message envelope.
    let bob_sk = crate::crypto::mls::two_party_test_support::bob_signing_key();
    let build_request = |requester_did: &str,
                         nonce: [u8; 16]|
     -> (Vec<u8>, zeroize::Zeroizing<[u8; 32]>) {
        let (wrapping_pub, wrapping_secret) =
            scp_protocol::crypto::sender_keys::generate_wrapping_keypair();
        let timestamp = scp_clock::SystemClock.now_secs();
        let hash = scp_protocol::crypto::sender_keys::key_protocol_verify::compute_request_hash(
            requester_did,
            ALICE,
            &wrapping_pub,
            &nonce,
            scp_protocol::crypto::sender_keys::key_protocol_verify::RequestHashInput {
                epoch: 1,
                requested_at: timestamp,
            },
        )
        .unwrap();
        let signature: [u8; 64] = bob_sk.sign(&hash).to_bytes();
        let request = SenderKeyRequest {
            requester_did: requester_did.to_owned(),
            sender_did: ALICE.to_owned(),
            epoch: 1,
            wrapping_pubkey: wrapping_pub,
            nonce,
            timestamp,
            signature,
        };
        let dist = SenderKeyDistributionMessage::KeyRequest(request)
            .to_bytes()
            .unwrap();
        (dist, wrapping_secret)
    };

    // Bob seals both requests through his actor-owned MLS group as management
    // envelopes (in MLS-generation order: mismatch first, then well-formed).
    let bob_cs = match &mut bob_actor.mode {
        crate::context::actor::ContextModeState::Encrypted(c) => c.as_mut(),
        crate::context::actor::ContextModeState::Broadcast(_) => panic!("expected encrypted"),
    };
    // Mismatch: Bob (authenticated) claims requester_did = CHARLIE.
    let (mismatch_dist, _) = build_request(CHARLIE, [1u8; 16]);
    let mismatch_sealed = bob_cs
        .mls_encrypt_management(&mismatch_dist)
        .expect("bob seals the mismatched request");
    // Well-formed: requester_did == BOB (the authenticated sender).
    let (ok_dist, bob_ephemeral_secret) = build_request(BOB, [2u8; 16]);
    let ok_sealed = bob_cs
        .mls_encrypt_management(&ok_dist)
        .expect("bob seals the well-formed request");

    // Alice opens on the production receive seam using her owned actor state.
    let alice_cs = match &mut alice_actor.mode {
        crate::context::actor::ContextModeState::Encrypted(c) => c.as_mut(),
        crate::context::actor::ContextModeState::Broadcast(_) => panic!("expected encrypted"),
    };

    // BLACK-P7-1: the mismatch is rejected, and NO answer is enqueued.
    let reject = rt.block_on(crate::context::messaging_helpers::decrypt_and_dispatch(
        &alice_deps,
        Some(&mut *alice_cs),
        ctx_str,
        &ctx_bytes,
        &mismatch_sealed,
        &std::collections::HashSet::new(),
    ));
    assert!(
        matches!(
            &reject,
            Err(ContextError::CryptoFailed(m))
                if m.contains("does not match the")
        ),
        "a requester_did != authenticated sender must be rejected, got {reject:?}"
    );
    assert!(
        alice_cs.pending_distributions.is_empty(),
        "a rejected request must not enqueue an answer"
    );

    // BLACK-P7-2: the well-formed request is answered.
    let ok = rt
        .block_on(crate::context::messaging_helpers::decrypt_and_dispatch(
            &alice_deps,
            Some(&mut *alice_cs),
            ctx_str,
            &ctx_bytes,
            &ok_sealed,
            &std::collections::HashSet::new(),
        ))
        .expect("a well-formed request is accepted on the receive path");
    assert!(
        matches!(ok, crate::context::shared::messaging::Dispatched::Handled),
        "a KeyRequest is consumed on the receive side (no application envelope surfaces)"
    );
    assert_eq!(
        alice_cs.pending_distributions.len(),
        1,
        "alice enqueues exactly one answer for the authenticated requester"
    );
    let crate::crypto::mls::provider::PendingDistribution {
        target_did: dest_did,
        message: answer_bytes,
        ..
    } = alice_cs.pending_distributions[0].clone();
    assert_eq!(
        dest_did, BOB,
        "the answer is addressed to the authenticated requester"
    );

    // The answer parses via the SAME call the receiver makes (a bare
    // SenderKeyResponse would fail here) and recovers a real sender key from
    // the ephemeral seal.
    let resp = match SenderKeyDistributionMessage::from_bytes(&answer_bytes)
        .expect("the answer parses as a SenderKeyDistributionMessage")
    {
        SenderKeyDistributionMessage::KeyResponse(r) => r,
        other => panic!("expected a KeyResponse envelope, got {other:?}"),
    };
    assert_eq!(resp.sender_did, ALICE);
    assert_eq!(resp.epoch, 1);
    assert_eq!(
        resp.request_nonce, [2u8; 16],
        "the answer echoes the request nonce"
    );
    let recovered = scp_protocol::crypto::sender_keys::hpke_open_sender_key(
        &resp.hpke_sealed_key,
        &resp.ephemeral_pubkey,
        &bob_ephemeral_secret,
        &ctx_hex,
        &resp.sender_did,
        resp.epoch,
    )
    .expect("the requester opens the ephemeral-sealed answer");
    assert_eq!(
        recovered.as_bytes().len(),
        32,
        "a real 32-byte sender key was recovered from the KeyResponse envelope"
    );
}

/// ADR-056 regression guard: `recovery_send_notification_direct` MUST
/// resolve its MLS-keying bytes through the canonical
/// [`context_id_to_bytes`](crate::context::state::context_id_to_bytes)
/// chokepoint, NOT the raw
/// [`context_id_bytes`](scp_protocol::context::context_id_bytes) primitive.
///
/// This direct path is reached for ANY unregistered context — including
/// REAL 64-hex member contexts whose actor is not spawned at recovery time
/// (the `revoke_ucans` / `rotate_key_packages` compromise-recovery
/// notifications). For a real id, the chokepoint DECODES the 64-hex string
/// to its 32-byte digest, whereas the raw primitive would double-hash it
/// (`SHA-256(hex(digest))`) and key a slot no member listens on — the
/// ADR-056 fail-open.
///
/// The test seeds an MLS group + sender key under the *digest* of a real
/// 64-hex id, then drives the direct path. Because `seal` looks up crypto
/// state by the exact keying bytes:
///
/// - With the chokepoint (digest), `seal` SUCCEEDS and the method proceeds
///   to the transport step, where `NotConfiguredTransportProvider` returns
///   `TransportFailed` — proving the seal keyed off the digest.
/// - With the raw primitive (`SHA-256(id)`), `seal` finds NO state under
///   that key and returns `CryptoFailed("no MLS group ...")` — never
///   reaching the transport.
///
/// Asserting `TransportFailed` (and NOT `CryptoFailed`) therefore FAILS if
/// line is regressed to the raw primitive (mutation-resistant).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_direct_keys_real_context_via_chokepoint_not_raw_primitive() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

    // A REAL (64-hex) member-context id: `hex(digest)` of a 32-byte digest.
    let digest = [0x5Au8; 32];
    let context_id = hex::encode(digest);
    assert_eq!(context_id.len(), 64, "fixture must be a real 64-hex id");

    // Precondition: the canonical resolver DECODES the id to its digest,
    // while the raw primitive RE-HASHES it — the two must differ, otherwise
    // this test could not distinguish the keying paths.
    let chokepoint_bytes = crate::context::state::context_id_to_bytes(&context_id);
    let raw_bytes = scp_protocol::context::context_id_bytes(&context_id);
    assert_eq!(
        chokepoint_bytes, digest,
        "the chokepoint must decode a 64-hex id to its digest"
    );
    assert_ne!(
        chokepoint_bytes, raw_bytes,
        "test precondition: digest must differ from SHA-256(hex(digest))"
    );

    // ADR-049 PR-7 (SCP-CRYPTOMOVE-001): the per-context MLS crypto is now
    // OWNED by the context actor, so `recovery_send_notification_direct` no
    // longer seals through the supervisor-scoped provider — it respawns the
    // target actor from its persisted Active snapshot and seals through the
    // actor's owned `ContextCryptoState`. Stand up a REAL context under the
    // 64-hex id via the production create path (`persist_first_state` durably
    // persists the initial Active snapshot, and the created group commits its
    // `scp_context_params` `0xFF02` extension under the DIGEST via the ADR-056
    // chokepoint) so the direct path's `respawn_from_snapshot` finds state and
    // stands the actor back up with a sealable owned crypto state. Because the
    // group's crypto is keyed under the digest, a respawn/restore that
    // (wrongly) resolved the id through the raw `SHA-256(hex(digest))`
    // primitive would key a slot with no crypto and fail the seal with
    // `CryptoFailed` — which is exactly what the `TransportFailed`-not-
    // `CryptoFailed` assertion below rejects.
    let creator = DID::from(
        sup.crypto_ref()
            .expect("test supervisor has crypto")
            .local_did()
            .to_owned(),
    );
    let created = sup
        .create_context(
            context_id.clone(),
            scp_protocol::context::ContextParams {
                ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
                ..scp_protocol::context::ContextParams::default()
            },
            creator,
            None,
            Vec::new(),
        )
        .await
        .expect("create the real 64-hex context under the digest");
    assert_eq!(created.context_id(), context_id);

    let signing_key =
        CommandSigner::local_ed25519(ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]));
    let result = sup
        .recovery_send_notification_direct(
            &context_id,
            "did:example:recovery-sender",
            b"recovery-notification-payload",
            1,
            &signing_key,
        )
        .await;

    // The seal MUST have succeeded (state found under the digest), so the
    // method reaches the transport step and fails THERE with
    // `TransportFailed` (the unconfigured test transport). A `CryptoFailed`
    // "no MLS group" here would mean the seal keyed off the raw primitive's
    // `SHA-256(id)` — the ADR-056 double-hash fail-open.
    match result {
        Err(ContextError::TransportFailed(msg)) => {
            assert!(
                msg.contains("transport not configured"),
                "expected the unconfigured-transport error (proving the seal \
                     succeeded under the digest), got: {msg}"
            );
        }
        Err(ContextError::CryptoFailed(msg)) => {
            panic!(
                "ADR-056 REGRESSION: seal keyed off the raw SHA-256(id) primitive \
                     instead of the canonical digest — recovery notification keyed to the \
                     wrong slot. got CryptoFailed: {msg}"
            );
        }
        other => {
            panic!("expected TransportFailed (seal succeeded under the digest), got: {other:?}")
        }
    }
}

/// The watchdog logs the crash WITHOUT the panic payload: the captured
/// tracing output contains the diagnostic message and `crash_count` but
/// NEVER the panic sentinel (which could be plaintext or key material).
///
/// Capture mechanism: a hand-rolled `tracing::Subscriber` (no
/// `tracing-subscriber` dependency) installed as the PROCESS-GLOBAL
/// default exactly once (the watchdog runs on a separate tokio worker
/// thread, so a thread-local `set_default` on the test thread would not
/// see its events). Every test using a distinct `context_id` reads only
/// its own lines out of the shared global buffer.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn panic_payload_is_not_logged() {
    const SENTINEL: &str = "SECRET_SENTINEL_abc123";

    let clock = Arc::new(TestClock::new(1_700_000_000));
    let clock_dyn: Arc<dyn Clock> = clock.clone();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

    // Distinct context id → the global capture buffer can be filtered to
    // this test's watchdog lines only.
    let ctx_id_bytes = [0xC3u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let (handle, _k) = spawn_active_with_snapshot(&sup, ctx_id_bytes).await;

    induce_panic(&handle, SENTINEL).await;

    // Wait until the watchdog's crash line for THIS context appears.
    let logged = wait_until(std::time::Duration::from_secs(5), || {
        captured_log_lines_for(&ctx_key)
            .iter()
            .any(|l| l.contains("context actor panicked") && l.contains("crash_count"))
    })
    .await;
    assert!(
        logged,
        "the watchdog must log a payload-free crash diagnostic"
    );

    let lines = captured_log_lines_for(&ctx_key);
    let joined = lines.join("\n");
    assert!(
        joined.contains("payload intentionally not logged"),
        "the diagnostic must state the payload was withheld; got: {joined}"
    );
    assert!(
        !joined.contains(SENTINEL),
        "SECURITY: the panic payload sentinel MUST NOT appear in the log; got: {joined}"
    );
}

/// A context actor that panics after shutdown has begun is despawned and
/// not respawned, and its panic records no crash (ADR-049 Decision 16
/// item 2).
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn panic_after_shutdown_began_records_no_crash_and_does_not_respawn() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));
    let (handle, ctx_key) = spawn_active_with_snapshot(&sup, [0xC7u8; 32]).await;

    sup.close_spawn_gate();
    induce_panic(&handle, "SECRET_SENTINEL_abc123").await;
    let despawned = wait_until(std::time::Duration::from_secs(5), || {
        sup.lookup(&ctx_key).is_none()
    })
    .await;
    assert!(despawned, "the watchdog must despawn the dead handle");
    // The watchdog despawns as its last step on the closed path, so the
    // crash window is settled here.
    assert!(
        sup.crash_windows.get(&ctx_key).is_none(),
        "a panic after shutdown began must record no crash"
    );
    assert!(
        sup.lookup(&ctx_key).is_none(),
        "a panic after shutdown began must not respawn the actor"
    );
}

/// A respawn that fails once shutdown has begun records no crash and sets
/// no failed-respawn flag, whether shutdown refused the spawn or the
/// respawn failed for another reason; before shutdown the same failure is
/// recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respawn_failure_after_shutdown_began_records_nothing() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));
    let owner = DID("did:example:admin".to_owned());

    // Before shutdown: a respawn with no snapshot is recorded.
    let before = sup
        .respawn_from_snapshot("no-snapshot-before", &owner)
        .await;
    assert!(matches!(before, Err(ContextError::ActorCrashed(_))));
    assert!(
        sup.crash_windows
            .get("no-snapshot-before")
            .is_some_and(|w| w.last_respawn_failed() && w.crash_count() == 1),
        "a respawn failure before shutdown must be recorded"
    );

    // A persisted Active snapshot whose respawn reaches the refused
    // key-package actor spawn in `build_actor_deps`.
    let ctx_bytes = [0xC8u8; 32];
    let ctx_key = hex::encode(ctx_bytes);
    let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_bytes,
        1_700_000_000,
        owner.clone(),
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    let snap = crate::context::manager_methods::snapshot_context(&state);
    sup.persistence_ref()
        .expect("test supervisor has persistence")
        .persist_context(&ctx_key, &snap)
        .await
        .unwrap();

    sup.close_spawn_gate();
    let refused = sup.respawn_from_snapshot(&ctx_key, &owner).await;
    assert!(
        matches!(refused, Err(ContextError::SupervisorShutDown(_))),
        "a respawn after shutdown began must be refused; got {refused:?}"
    );
    assert!(
        sup.crash_windows.get(&ctx_key).is_none(),
        "a shutdown refusal must record no crash and leave no respawn marker"
    );

    let after = sup.respawn_from_snapshot("no-snapshot-after", &owner).await;
    assert!(matches!(after, Err(ContextError::ActorCrashed(_))));
    assert!(
        sup.crash_windows.get("no-snapshot-after").is_none(),
        "a respawn failure after shutdown began must record nothing"
    );
}

/// A crash window recorded before shutdown for a context with no
/// registered actor (its respawn despawned the actor before the sweep's
/// snapshot) is removed once the drain returns; a poisoned window stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_reaps_a_crash_window_whose_actor_left_before_the_sweep() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));
    let owner = DID("did:example:admin".to_owned());

    let failed = sup.respawn_from_snapshot("unswept-crash", &owner).await;
    assert!(matches!(failed, Err(ContextError::ActorCrashed(_))));
    assert!(sup.lookup("unswept-crash").is_none());
    assert!(
        sup.crash_windows
            .get("unswept-crash")
            .is_some_and(|w| w.crash_count() == 1 && !w.is_poisoned()),
        "the crash is recorded before shutdown"
    );
    sup.crash_windows
        .entry("unswept-poison".to_owned())
        .or_default()
        .poisoned = true;

    sup.shutdown_all_contexts().await;

    assert!(
        !sup.crash_windows.contains_key("unswept-crash"),
        "a non-poison window outside the sweep's snapshot must not outlive the drain"
    );
    assert!(
        sup.crash_windows
            .get("unswept-poison")
            .is_some_and(|w| w.is_poisoned()),
        "a poisoned window survives shutdown"
    );
}

/// A clean shutdown is NOT a crash: the watchdog sees `Ok(())`, records
/// no crash, and does not respawn. Same for an inbox-closed exit (all
/// handles dropped).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clean_shutdown_is_not_a_crash() {
    let clock = Arc::new(TestClock::new(1_700_000_000));
    let clock_dyn: Arc<dyn Clock> = clock.clone();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

    // --- Case 1: explicit shutdown ---
    let ctx_id_bytes = [0xC4u8; 32];
    let (handle, ctx_key) = spawn_active_with_snapshot(&sup, ctx_id_bytes).await;
    handle.send_shutdown().await.expect("shutdown acks");
    // Give the watchdog time to observe the clean Ok exit.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        !sup.is_context_poisoned(&ctx_key),
        "a clean shutdown must not record a crash or poison the context"
    );
    // The watchdog must NOT respawn on a clean exit — but `despawn_actor`
    // was not called by the watchdog either; the handle's mailbox closed
    // on shutdown, so the actor exited and no respawn re-registered it.
    let no_respawn = wait_until(std::time::Duration::from_secs(2), || {
        // Confirm the crash window has no entry (never recorded a crash).
        !sup.crash_windows.contains_key(&ctx_key)
    })
    .await;
    assert!(
        no_respawn,
        "a clean shutdown must not create a crash-window entry"
    );

    // --- Case 2: inbox closed (all handles dropped) ---
    let ctx2_bytes = [0xC5u8; 32];
    let (handle2, ctx2_key) = spawn_active_with_snapshot(&sup, ctx2_bytes).await;
    drop(handle2); // close the inbox; the run loop exits via `None`.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        !sup.is_context_poisoned(&ctx2_key),
        "an inbox-closed exit is clean — no crash, no poison"
    );
    assert!(
        !sup.crash_windows.contains_key(&ctx2_key),
        "an inbox-closed exit must not record a crash"
    );
}

/// A respawn that reliably fails (no persisted snapshot — the lost-state
/// case) is counted as a crash. One induced panic therefore records TWO
/// crashes (the panic itself + the failed respawn), proving failed
/// respawns consume the budget rather than looping forever. The context
/// is left dormant (lookup None) — it was not resurrected.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_respawn_counts_as_crash() {
    let clock = Arc::new(TestClock::new(1_700_000_000));
    let clock_dyn: Arc<dyn Clock> = clock.clone();
    // Empty persistence: load_context always returns None, so the
    // watchdog's respawn fails (the lost-state case).
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

    // Spawn WITHOUT persisting a snapshot — the crash's respawn will
    // fail (no snapshot), counting as an additional crash.
    let ctx_id_bytes = [0xC6u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        DID("did:example:admin".to_owned()),
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    let deps = test_actor_deps(&sup).await;
    let handle = sup
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn registers");

    // One induced panic: the watchdog records crash #1, then the respawn
    // loads no snapshot and `record_respawn_failure` records crash #2.
    induce_panic(&handle, "SECRET_SENTINEL_abc123").await;

    let recorded = wait_until(std::time::Duration::from_secs(5), || {
        sup.crash_windows
            .get(&ctx_key)
            .is_some_and(|w| w.crash_count() >= 2)
    })
    .await;
    assert!(
        recorded,
        "a failed respawn must be counted as an additional crash \
             (1 panic + 1 failed respawn = 2 crashes)"
    );
    assert!(
        sup.lookup(&ctx_key).is_none(),
        "a context with no recoverable snapshot must not be resurrected"
    );
}

/// Repeated failed respawns within the window cross the threshold and
/// poison the context — proving the failed-respawn crash accounting
/// feeds the budget. Driven directly via `respawn_from_snapshot` (the
/// watchdog's respawn primitive) against an empty persistence so each
/// call is a guaranteed failed respawn that records one crash.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_failed_respawns_poison() {
    let clock = Arc::new(TestClock::new(1_700_000_000));
    let clock_dyn: Arc<dyn Clock> = clock.clone();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

    let ctx_key = "ctx-no-snapshot".to_owned();
    let owning = DID("did:example:admin".to_owned());

    // Each respawn fails (no snapshot) and records exactly one crash.
    // After CRASH_POISON_THRESHOLD failed respawns within the window the
    // context must be poisoned.
    for i in 0..CRASH_POISON_THRESHOLD {
        let result = sup.respawn_from_snapshot(&ctx_key, &owning).await;
        assert!(
            matches!(result, Err(ContextError::ActorCrashed(_))),
            "respawn #{i} with no snapshot must surface ActorCrashed, got {result:?}"
        );
        clock.advance_millis(100);
    }

    assert!(
        sup.is_context_poisoned(&ctx_key),
        "{CRASH_POISON_THRESHOLD} failed respawns within the window must poison the context"
    );
}

/// Anti-resurrection (ADR-049 §10): `respawn_from_snapshot` must NOT
/// respawn a snapshot whose persisted state is terminal (`Closing` here),
/// must surface `ContextClosed`, must NOT spawn an actor, and must NOT
/// count the skip as a crash (a terminal context is an expected dormancy,
/// not a fault).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respawn_skips_terminal_snapshot() {
    let clock = Arc::new(TestClock::new(1_700_000_000));
    let clock_dyn: Arc<dyn Clock> = clock.clone();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

    // Build a state, drive its handle to a TERMINAL state, then snapshot
    // and persist it. `snapshot_context` reads the handle's state, so the
    // persisted snapshot is non-`Active`.
    let ctx_id_bytes = [0xCAu8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        DID("did:example:admin".to_owned()),
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    state
        .handle
        .transition_to(&crate::context::ContextState::Closing)
        .unwrap();
    let snap = crate::context::manager_methods::snapshot_context(&state);
    assert_eq!(
        snap.state,
        crate::context::ContextState::Closing,
        "fixture must persist a terminal snapshot"
    );
    sup.persistence_ref()
        .expect("test supervisor has persistence")
        .persist_context(&ctx_key, &snap)
        .await
        .unwrap();

    let owning = DID("did:example:admin".to_owned());
    let result = sup.respawn_from_snapshot(&ctx_key, &owning).await;
    assert!(
        matches!(result, Err(ContextError::ContextClosed)),
        "respawn of a terminal snapshot must surface ContextClosed, got {result:?}"
    );
    assert!(
        sup.lookup(&ctx_key).is_none(),
        "a terminal snapshot must NOT be resurrected into a live actor"
    );
    assert!(
        !sup.crash_windows.contains_key(&ctx_key),
        "the terminal-skip must NOT record a crash (no crash window entry)"
    );
    assert!(
        !sup.is_context_poisoned(&ctx_key),
        "the terminal-skip must NOT poison the context"
    );
}

/// A crashed context whose respawn FAILED (no snapshot) but has NOT hit
/// the poison threshold must surface `ActorCrashed` from a per-context
/// lookup miss — NOT `ContextNotRegistered` ("never existed"). Mirrors
/// `failed_respawn_counts_as_crash`, asserting the lookup-miss error class.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lookup_miss_after_failed_respawn_is_actor_crashed() {
    let clock = Arc::new(TestClock::new(1_700_000_000));
    let clock_dyn: Arc<dyn Clock> = clock.clone();
    // Empty persistence: every respawn fails (no snapshot).
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

    let ctx_key = "ctx-failed-respawn".to_owned();
    let owning = DID("did:example:admin".to_owned());

    // One failed respawn: records crash #1 and sets `last_respawn_failed`
    // WITHOUT poisoning (1 < threshold).
    let result = sup.respawn_from_snapshot(&ctx_key, &owning).await;
    assert!(
        matches!(result, Err(ContextError::ActorCrashed(_))),
        "a failed respawn must surface ActorCrashed, got {result:?}"
    );
    assert!(
        !sup.is_context_poisoned(&ctx_key),
        "a single failed respawn must NOT poison (below threshold)"
    );

    // The lookup-miss error must now be ActorCrashed (silently dead),
    // not ContextNotRegistered.
    let miss = sup.lookup_miss_error(&ctx_key, "context not registered: x".to_owned());
    assert!(
        matches!(miss, ContextError::ActorCrashed(_)),
        "a crashed-but-unpoisoned context must surface ActorCrashed on lookup miss, got {miss:?}"
    );

    // A genuinely-unknown context still surfaces ContextNotRegistered.
    let unknown = sup.lookup_miss_error("never-existed", "context not registered: y".to_owned());
    assert!(
        matches!(unknown, ContextError::ContextNotRegistered(_)),
        "an unknown context must still surface ContextNotRegistered, got {unknown:?}"
    );
}

/// Captured log lines that record a standing auto-revive of `ctx_key`.
fn standing_revive_log_lines(ctx_key: &str) -> Vec<String> {
    capture_buffer()
        .lock()
        .unwrap()
        .iter()
        .filter(|l| l.contains(ctx_key) && l.contains("auto-revived on re-contact"))
        .cloned()
        .collect()
}

/// A standing context with no actor whose last respawn failed below the
/// poison threshold is dormant: nothing retries the respawn, so
/// `standing_context` recreates over it exactly as it does over a poisoned
/// one, and logs the revive once the recreate registered an actor
/// (ADR-049 §10, standing-context auto-revive residual).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standing_context_revives_a_context_past_a_failed_respawn() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));
    let local = DID::from(
        sup.crypto_ref()
            .expect("test supervisor has crypto")
            .local_did()
            .to_owned(),
    );
    let peer = DID("did:example:peer-revive-after-failed-respawn".to_owned());
    let ctx_key = crate::context::shared::standing::generate_standing_context_id(&local, &peer);

    // Empty persistence: the respawn fails, recording one crash and
    // `last_respawn_failed` without poisoning (1 < threshold).
    let respawn = sup.respawn_from_snapshot(&ctx_key, &local).await;
    assert!(
        matches!(respawn, Err(ContextError::ActorCrashed(_))),
        "a failed respawn must surface ActorCrashed, got {respawn:?}"
    );
    assert!(!sup.is_context_poisoned(&ctx_key));

    let revived = sup.standing_context(&local, &peer, Vec::new()).await;
    assert_eq!(
        revived.as_deref().ok(),
        Some(ctx_key.as_str()),
        "a standing context past a failed respawn must be recreated, got {revived:?}"
    );
    assert!(
        sup.lookup(&ctx_key).is_some(),
        "the recreate must register an actor for the standing id"
    );
    assert!(
        !sup.crash_windows
            .get(&ctx_key)
            .is_some_and(|w| w.last_respawn_failed() || w.is_respawning()),
        "the revive must drop the failed-respawn record and the bootstrap marker"
    );
    assert!(
        sup.standing_contexts.load().contains_key(&peer.to_string()),
        "a revived standing context must track the peer"
    );
    let lines = standing_revive_log_lines(&ctx_key);
    assert_eq!(
        lines.len(),
        1,
        "the revive must log one operator-audit warning, got {lines:?}"
    );
    assert!(
        lines[0].contains("respawn_failed"),
        "the warning must name the dormant state it revived, got {lines:?}"
    );
}

/// A recreate over a dormant standing context that registers no actor
/// restores the dormant window, so the id still reads `Poisoned` or
/// `ActorCrashed`, and logs no revive: the operator-audit warning records
/// only a revive that happened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standing_context_restores_a_dormant_window_when_the_recreate_fails() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    // Empty persistence, so a respawn fails.
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));
    let local = DID::from(
        sup.crypto_ref()
            .expect("test supervisor has crypto")
            .local_did()
            .to_owned(),
    );
    // A poisoned key-package actor for the creator makes
    // `build_actor_deps` fail, so every recreate below registers no actor.
    {
        let mut entry = sup
            .crash_windows
            .entry(Supervisor::kp_crash_key(&local))
            .or_default();
        for _ in 0..CRASH_POISON_THRESHOLD {
            entry.record(1_700_000_000);
        }
    }

    // Past a failed respawn below the poison threshold.
    let peer = DID("did:example:peer-failed-recreate-respawn".to_owned());
    let ctx_key = crate::context::shared::standing::generate_standing_context_id(&local, &peer);
    let respawn = sup.respawn_from_snapshot(&ctx_key, &local).await;
    assert!(matches!(respawn, Err(ContextError::ActorCrashed(_))));
    let failed = sup.standing_context(&local, &peer, Vec::new()).await;
    assert!(
        matches!(failed, Err(ContextError::TransportFailed(_))),
        "a recreate that registers no actor must surface the create error, got {failed:?}"
    );
    assert!(sup.lookup(&ctx_key).is_none());
    assert!(
        matches!(
            sup.read_context_state_checked(&ctx_key).await,
            Err(ContextError::ActorCrashed(_))
        ),
        "a failed recreate must restore the failed-respawn record"
    );
    assert!(
        standing_revive_log_lines(&ctx_key).is_empty(),
        "a recreate that registered no actor must not log a revive"
    );
    assert!(
        !sup.standing_contexts.load().contains_key(&peer.to_string()),
        "a failed get-or-create must not track the peer"
    );

    // Poisoned.
    let peer = DID("did:example:peer-failed-recreate-poisoned".to_owned());
    let ctx_key = crate::context::shared::standing::generate_standing_context_id(&local, &peer);
    {
        let mut entry = sup.crash_windows.entry(ctx_key.clone()).or_default();
        for _ in 0..CRASH_POISON_THRESHOLD {
            entry.record(1_700_000_000);
        }
    }
    assert!(sup.is_context_poisoned(&ctx_key));
    let failed = sup.standing_context(&local, &peer, Vec::new()).await;
    assert!(
        matches!(failed, Err(ContextError::TransportFailed(_))),
        "a recreate that registers no actor must surface the create error, got {failed:?}"
    );
    assert!(
        matches!(
            sup.read_context_state_checked(&ctx_key).await,
            Ok(Some(scp_protocol::context::ContextState::Poisoned))
        ),
        "a failed recreate must restore the poisoned window"
    );
    assert!(
        standing_revive_log_lines(&ctx_key).is_empty(),
        "a recreate that registered no actor must not log a revive"
    );
}

/// Once shutdown has begun, `standing_context` returns the typed
/// `SupervisorShutDown` (`SCP-CTX-2138`, ADR-049 Decision 16 item 2), not
/// a `TransportFailed`, whether the refusal comes from the actor spawn in
/// `create_context` or from the key-package actor spawn in
/// `build_actor_deps`. A deps failure of another kind stays
/// `TransportFailed`
/// (`standing_context_restores_a_dormant_window_when_the_recreate_fails`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standing_context_after_shutdown_keeps_supervisor_shut_down() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));
    let local = DID::from(
        sup.crypto_ref()
            .expect("test supervisor has crypto")
            .local_did()
            .to_owned(),
    );

    // A live key-package actor for `local`, so `build_actor_deps`
    // succeeds and the refusal comes from the actor spawn.
    sup.key_package_store_for_loaded(&local)
        .await
        .expect("a key-package actor spawns before shutdown");
    sup.close_spawn_gate();
    let peer = DID("did:example:peer-standing-after-shutdown-spawn".to_owned());
    let spawn_refused = sup.standing_context(&local, &peer, Vec::new()).await;
    assert!(
        matches!(spawn_refused, Err(ContextError::SupervisorShutDown(_))),
        "a refused actor spawn must keep SupervisorShutDown; got {spawn_refused:?}"
    );

    // No key-package actor, so the refusal comes from `build_actor_deps`.
    sup.stop_key_package_actors().await;
    let peer = DID("did:example:peer-standing-after-shutdown-deps".to_owned());
    let deps_refused = sup.standing_context(&local, &peer, Vec::new()).await;
    assert!(
        matches!(deps_refused, Err(ContextError::SupervisorShutDown(_))),
        "a refused key-package spawn must keep SupervisorShutDown; got {deps_refused:?}"
    );
    assert!(
        sup.standing_contexts.load().is_empty(),
        "a refused get-or-create must not track the peer"
    );
}

/// A standing context whose registered actor does not answer is present,
/// so `standing_context` returns the checked read's `ActorBusy` and
/// creates nothing over the id (ADR-049 §10: a caller whose decision
/// turns on absence treats a present, unreachable context as present).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standing_context_returns_the_error_for_a_present_unreachable_context() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));
    let local = DID("did:example:local".to_owned());
    let peer = DID("did:example:peer".to_owned());
    let ctx_key = crate::context::shared::standing::generate_standing_context_id(&local, &peer);

    // A registered actor no task drains: the checked read answers
    // `ActorBusy`, and the get-or-create returns it.
    let (tx, rx) = tokio::sync::mpsc::channel::<ContextCommand>(1);
    drop(rx);
    sup.actors
        .insert(ctx_key.clone(), ContextActorHandle::from_sender(tx));
    let busy = sup.standing_context(&local, &peer, Vec::new()).await;
    assert!(
        matches!(busy, Err(ContextError::ActorBusy(_))),
        "a standing context whose actor does not answer must surface ActorBusy, got {busy:?}"
    );
    assert!(
        sup.lookup(&ctx_key).is_some(),
        "the unreachable actor must stay registered, not be replaced"
    );
    assert!(
        !sup.standing_contexts.load().contains_key(&peer.to_string()),
        "a refused get-or-create must not track the peer"
    );
}

/// A registered actor this call cannot reach reads as `ActorBusy` from
/// [`Supervisor::read_context_state_checked`] and as `None` from
/// [`Supervisor::read_context_state`].
///
/// The `Option` form collapses "the supervisor holds no actor for this id"
/// and "the supervisor holds an actor that did not answer" into one value.
/// A bridge's `context_close` that reads `None` as proof that the close
/// already happened skips the `CloseContext` dispatch, which carries the
/// only `ContextClose` capability check on that path, so it reads the
/// checked form instead. The `Option` form keeps its collapse
/// because no caller of that form reads `None` as an authorization.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_actor_reads_as_actor_busy_not_as_an_absent_context() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

    let ctx_key = "ctx-unreachable-actor";
    // A mailbox no task drains. `send_with_timeout` fails on it with
    // `ActorBusy`, which is the error a saturated mailbox produces once
    // `SEND_TIMEOUT` elapses and a wedged actor produces once
    // `REPLY_TIMEOUT` elapses.
    let (tx, rx) = tokio::sync::mpsc::channel::<ContextCommand>(1);
    drop(rx);
    sup.actors
        .insert(ctx_key.to_owned(), ContextActorHandle::from_sender(tx));

    let checked = sup.read_context_state_checked(ctx_key).await;
    assert!(
        matches!(checked, Err(ContextError::ActorBusy(_))),
        "an actor the supervisor still holds but this call cannot reach must read as \
             ActorBusy, got {checked:?}"
    );
    assert_eq!(
        sup.read_context_state(ctx_key).await,
        None,
        "the Option form keeps folding an unreachable actor into None, which no caller of \
             that form reads as an authorization"
    );

    // An id the supervisor holds no actor for still reads as absent, so
    // the checked form did not turn every miss into an error.
    let absent = sup.read_context_state_checked("never-existed").await;
    assert!(
        matches!(absent, Ok(None)),
        "an id with no actor and no poison flag must read as Ok(None), got {absent:?}"
    );
}

/// A context in the respawn gap, and a context whose last respawn failed
/// below the poison threshold, read as `ActorCrashed` from
/// [`Supervisor::read_context_state_checked`], not as an absent context.
///
/// Both contexts have no registered actor, and both still exist: the
/// watchdog re-registers the first one when its respawn finishes, the
/// operator's `clear_poison` respawns the second one (as it does a
/// poisoned context), and `lookup_miss_error` classifies both as crashed.
/// A bridge's `context_close` that reads `Ok(None)` as proof that the
/// close already happened skips the `CloseContext` dispatch, which carries
/// the only `ContextClose` capability check on that path, so a `None` here
/// would let a caller holding no `context:close` capability release a
/// context the supervisor can serve as `Active` again.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crashed_context_with_no_actor_reads_as_actor_crashed_not_as_absent() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

    sup.test_hold_context_mid_respawn("ctx-checked-mid-respawn")
        .await;
    let mid_respawn = sup
        .read_context_state_checked("ctx-checked-mid-respawn")
        .await;
    assert!(
        matches!(mid_respawn, Err(ContextError::ActorCrashed(_))),
        "a context the watchdog is respawning must read as ActorCrashed, got {mid_respawn:?}"
    );

    sup.test_fail_context_respawn("ctx-checked-respawn-failed")
        .await;
    assert!(
        !sup.is_context_poisoned("ctx-checked-respawn-failed"),
        "the fixture must leave the context below the poison threshold"
    );
    let respawn_failed = sup
        .read_context_state_checked("ctx-checked-respawn-failed")
        .await;
    assert!(
        matches!(respawn_failed, Err(ContextError::ActorCrashed(_))),
        "a context whose last respawn failed must read as ActorCrashed, got \
             {respawn_failed:?}"
    );

    let absent = sup.read_context_state_checked("never-existed").await;
    assert!(
        matches!(absent, Ok(None)),
        "an id with no actor and no crash-window record must read as Ok(None), got {absent:?}"
    );
}

/// [`Supervisor::get_role_state_checked`] reports an unreachable actor as
/// `ActorBusy`, a crashed context as `ActorCrashed`, and a poisoned context
/// as `ContextPoisoned`, and answers `Ok(None)` only for an id the
/// supervisor never served. [`Supervisor::get_role_state`] folds all four
/// into `None`, so a bridge authorizing against it tells its caller that
/// a merely saturated context does not exist.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_checked_role_state_read_tells_a_busy_or_crashed_context_from_an_absent_one() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

    sup.test_make_actor_unreachable("ctx-role-unreachable");
    assert!(sup.get_role_state("ctx-role-unreachable").await.is_none());
    let busy = sup.get_role_state_checked("ctx-role-unreachable").await;
    assert!(
        matches!(busy, Err(ContextError::ActorBusy(_))),
        "an unreachable actor must read as ActorBusy, got {busy:?}"
    );

    sup.test_hold_context_mid_respawn("ctx-role-mid-respawn")
        .await;
    let crashed = sup.get_role_state_checked("ctx-role-mid-respawn").await;
    assert!(
        matches!(crashed, Err(ContextError::ActorCrashed(_))),
        "a context mid-respawn must read as ActorCrashed, got {crashed:?}"
    );

    sup.test_poison_context("ctx-role-poisoned").await;
    let poisoned = sup.get_role_state_checked("ctx-role-poisoned").await;
    assert!(
        matches!(poisoned, Err(ContextError::ContextPoisoned(_))),
        "a poisoned context must read as ContextPoisoned, got {poisoned:?}"
    );

    let absent = sup.get_role_state_checked("never-existed").await;
    assert!(
        matches!(absent, Ok(None)),
        "an id the supervisor never served must read as Ok(None), got {absent:?}"
    );
}

/// A live actor that accepts a read and never answers it, and a live actor
/// whose mailbox stays full, read as `ActorBusy` from both checked reads,
/// after `REPLY_TIMEOUT` and `SEND_TIMEOUT` respectively, never as
/// `Ok(None)`.
///
/// The unreachable-actor tests above close the mailbox, so the send fails
/// at once. This test keeps the receiving half alive and never drains it,
/// so each read reaches its timeout: a wedged actor for the first read of
/// each form, and a saturated mailbox for the second, because the first
/// read's command still fills the one mailbox slot. A caller that
/// enumerates contexts, such as a member's context listing, reads
/// `Ok(None)` as "drop this id", so a timeout folded into `Ok(None)`
/// would drop a live context. `start_paused` advances virtual time so
/// both timeouts elapse at once.
#[tokio::test(start_paused = true)]
async fn a_timed_out_actor_reads_as_actor_busy_from_both_checked_reads() {
    use crate::context::actor::{REPLY_TIMEOUT, SEND_TIMEOUT};

    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

    let (state_tx, _state_rx) = tokio::sync::mpsc::channel::<ContextCommand>(1);
    sup.actors.insert(
        "ctx-state-wedged".to_owned(),
        ContextActorHandle::from_sender(state_tx),
    );
    let (role_tx, _role_rx) = tokio::sync::mpsc::channel::<ContextCommand>(1);
    sup.actors.insert(
        "ctx-role-wedged".to_owned(),
        ContextActorHandle::from_sender(role_tx),
    );

    for (label, budget, form) in [
        ("reply timeout", REPLY_TIMEOUT, "state"),
        ("send timeout", SEND_TIMEOUT, "state"),
        ("reply timeout", REPLY_TIMEOUT, "role"),
        ("send timeout", SEND_TIMEOUT, "role"),
    ] {
        let start = tokio::time::Instant::now();
        let read = if form == "state" {
            sup.read_context_state_checked("ctx-state-wedged")
                .await
                .map(|state| state.is_some())
        } else {
            sup.get_role_state_checked("ctx-role-wedged")
                .await
                .map(|role| role.is_some())
        };
        assert!(
            matches!(read, Err(ContextError::ActorBusy(_))),
            "a {form} read that hits the {label} must read as ActorBusy, got {read:?}"
        );
        assert!(
            start.elapsed() >= budget,
            "the {form} read must wait out the {label} ({budget:?}) before failing, so \
                 the error came from the timeout and not a closed mailbox"
        );
    }
}

/// ADR-049 §10 transient-respawn observability: while a context is
/// mid-respawn (despawned, not yet re-registered), a concurrent
/// per-context dispatch that `lookup`-misses must surface the retryable
/// `ActorCrashed` class — NOT `ContextNotRegistered` ("never existed") —
/// because the context genuinely exists and is recovering.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lookup_miss_during_respawn_window_is_actor_crashed() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

    let ctx_key = "ctx-mid-respawn".to_owned();

    // Seed the transient respawn marker (the state `respawn_from_snapshot`
    // sets between despawn and re-registration) WITHOUT any crash history
    // or poison.
    sup.crash_windows
        .entry(ctx_key.clone())
        .or_default()
        .mark_respawning();
    assert!(
        !sup.is_context_poisoned(&ctx_key),
        "a mid-respawn context must not be poisoned"
    );

    // The lookup-miss must be the retryable ActorCrashed class.
    let miss = sup.lookup_miss_error(&ctx_key, "context not registered: z".to_owned());
    assert!(
        matches!(miss, ContextError::ActorCrashed(_)),
        "a mid-respawn lookup miss must surface ActorCrashed (retryable), got {miss:?}"
    );

    // Clearing the marker returns the window to a non-signalling state, so
    // the lookup-miss falls back to ContextNotRegistered.
    if let Some(mut entry) = sup.crash_windows.get_mut(&ctx_key) {
        entry.clear_respawning();
    }
    let after = sup.lookup_miss_error(&ctx_key, "context not registered: z".to_owned());
    assert!(
        matches!(after, ContextError::ContextNotRegistered(_)),
        "after the respawn window closes, a lookup miss falls back to \
             ContextNotRegistered, got {after:?}"
    );
}

/// A lifecycle-state read whose registry lookup misses, and whose
/// crash-window read runs after a respawn registered the replacement actor
/// and cleared its marker, reads the replacement's state and not `Ok(None)`.
/// `read_context_state_checked` holds no lock across the two reads, so
/// both come back clean in that interleaving; only the second `lookup`
/// after the window read finds the replacement. A bridge's `context_close`
/// that reads `Ok(None)` as a close that already happened skips the
/// `ContextClose` capability check, so `Ok(None)` here is a fail-open.
///
/// The test forces the interleaving. It holds the context's crash-window
/// shard lock, so the reader task's first `crash_windows` read blocks after
/// its `lookup` has missed. While the reader waits, the test re-registers
/// the actor and clears the marker, in the order the respawn success path
/// uses, and then releases the lock. If the reader has not reached its
/// `lookup` when the actor is re-registered, the lookup hits and the test
/// passes without exercising the gap, so the pause below only has to be
/// long enough for a spawned task to start.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn state_read_that_misses_a_respawning_actor_reads_the_replacement() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));
    let (_handle, ctx_key) = spawn_active_with_snapshot(&sup, [0xC7u8; 32]).await;

    // The respawn gap: marker set, actor out of the registry. The removed
    // handle keeps the actor's mailbox open for re-registration.
    sup.crash_windows
        .entry(ctx_key.clone())
        .or_default()
        .mark_respawning();
    let (_, actor) = sup
        .actors
        .remove(&ctx_key)
        .expect("the spawned actor must be registered");

    let mut window_guard = sup
        .crash_windows
        .get_mut(&ctx_key)
        .expect("the marker created the window");
    let reader = {
        let sup = Arc::clone(&sup);
        let ctx_key = ctx_key.clone();
        tokio::spawn(async move { sup.read_context_state_checked(&ctx_key).await })
    };
    // Blocking pause on the test thread, which runs no runtime task, so the
    // reader runs on a worker, misses the lookup, and blocks on the shard.
    std::thread::sleep(std::time::Duration::from_millis(200));
    sup.actors.insert(ctx_key.clone(), actor);
    window_guard.clear_respawning();
    drop(window_guard);

    let read = reader.await.expect("reader task must not panic");
    assert!(
        matches!(read, Ok(Some(crate::context::ContextState::Active))),
        "a read that missed a respawning actor must report the replacement's \
             state, got {read:?}"
    );
}

/// The import-replace gap reads as `ActorCrashed`, not as an absent
/// context. `import_context` despawns the actor it replaces through
/// `despawn_for_replace` and registers the imported actor later; a
/// `context_close` that read `Ok(None)` in that gap would skip the
/// `ContextClose` capability check and release the bridge's state. Once
/// the `ImportContext` arm ends the gap, the marker is gone and a window
/// the marker alone created is reaped, while a window holding real crash
/// history survives with the marker cleared.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_replace_gap_reads_as_actor_crashed_until_the_window_ends() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

    let ctx_key = spawn_live_context(&sup, [0xC8u8; 32]).await;
    assert!(
        sup.despawn_for_replace(&ctx_key).await,
        "the live actor must be despawned"
    );
    assert!(sup.lookup(&ctx_key).is_none(), "no actor serves the gap");
    let in_gap = sup.read_context_state_checked(&ctx_key).await;
    assert!(
        matches!(in_gap, Err(ContextError::ActorCrashed(_))),
        "a context in the import-replace gap must read as ActorCrashed, got {in_gap:?}"
    );
    sup.end_bootstrap_window(&ctx_key);
    assert!(
        !sup.crash_windows.contains_key(&ctx_key),
        "a crash window the replace marker alone created must be reaped"
    );

    let with_history = spawn_live_context(&sup, [0xC9u8; 32]).await;
    let now_ms = sup.crash_now_ms("context_actor", &with_history);
    sup.crash_windows
        .entry(with_history.clone())
        .or_default()
        .record(now_ms);
    sup.despawn_for_replace(&with_history).await;
    sup.end_bootstrap_window(&with_history);
    let window = sup
        .crash_windows
        .get(&with_history)
        .expect("a window with crash history must survive the replace");
    assert!(
        !window.is_respawning(),
        "the replace marker must be cleared"
    );
    assert_eq!(window.crash_count(), 1, "the crash history must be kept");
}

/// `Supervisor::import_context` over a replaceable actor marks the replace
/// gap on its own production path, and its `ImportContext` arm clears the
/// mark once the imported actor registers. The test above drives
/// `despawn_for_replace` and `end_bootstrap_window` by hand, so it stays
/// green when `lifecycle_helpers::import_context` calls `despawn_actor`
/// instead or when the arm stops ending its bootstrap window; this one
/// goes red in either case.
///
/// The test holds `write_lock`, which `despawn_actor` takes after
/// `despawn_for_replace` sets the mark, so the import stops at the start
/// of the gap and the mark stays observable. The owning member's
/// key-package store is resolved first so `build_actor_deps` takes no
/// `write_lock` before that point.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_over_replaceable_actor_marks_and_ends_the_replace_gap() {
    // `TestEventLog` refuses `import_event_log_data`; the import needs a
    // provider that takes the export's event-log bytes.
    let sup = supervisor_with_providers_and_event_log(Box::new(
        crate::context::providers::event_log::MerkleEventLogProvider::new(),
    ));
    let ctx_id_bytes = [0xCAu8; 32];
    let deps = test_actor_deps(&sup).await;
    let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        DID("did:example:replace-admin".to_owned()),
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .expect("drive the prior context to Active");
    state
        .handle
        .transition_to(&crate::context::ContextState::Closing)
        .expect("drive the prior context to Closing, which an import may replace");
    sup.spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn registers the prior context");
    let ctx_key = hex::encode(ctx_id_bytes);

    let owning_member = "did:key:aaa-replace-gap-owning-member";
    // Pre-load the node identity's store and wrapping keypair, so the
    // import's deps build does not wait on the `write_lock` held below.
    sup.key_package_store_for_loaded(&sup.node_identity().unwrap())
        .await
        .expect("kp store resolves with providers");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let export = signed_import_export_with_member(
        &ctx_key,
        "did:key:replace-gap-creator",
        owning_member,
        &signing_key,
    )
    .await;

    let write_guard = sup.write_lock.lock().await;
    let import = {
        let sup = Arc::clone(&sup);
        tokio::spawn(async move { sup.import_context(export, &verifying_key, None).await })
    };
    let marked = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if sup
                .crash_windows
                .get(&ctx_key)
                .is_some_and(|window| window.is_respawning())
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        marked.is_ok(),
        "import_context must mark the replace gap before it despawns the prior actor"
    );
    // Stand in for the despawn the held `write_lock` is blocking, so the
    // read below lands in the gap the production marker covers. The
    // import's own `despawn_actor` then finds the slot empty.
    sup.actors.remove(&ctx_key);
    let in_gap = sup.read_context_state_checked(&ctx_key).await;
    assert!(
        matches!(in_gap, Err(ContextError::ActorCrashed(_))),
        "a context in the import-replace gap must read as ActorCrashed, got {in_gap:?}"
    );
    drop(write_guard);

    import
        .await
        .expect("import task must not panic")
        .expect("an import over a Closing context succeeds");
    assert!(
        !sup.crash_windows.contains_key(&ctx_key),
        "the ImportContext arm must end the replace gap and reap the window it created"
    );
    assert!(
        sup.despawn_actor(&ctx_key).await,
        "the imported actor must be registered"
    );
    let after = sup.read_context_state_checked(&ctx_key).await;
    assert!(
        matches!(after, Ok(None)),
        "with the gap ended, a despawned context must read as absent, got {after:?}"
    );
}

/// The transient respawn marker must NOT leave a lingering crash-window
/// record on a terminal-skip: a clean terminal context (no crash history)
/// whose respawn is skipped must end with NO `crash_windows` entry,
/// preserving the invariant `respawn_skips_terminal_snapshot` asserts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respawn_marker_reaped_on_clean_terminal_skip() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

    let ctx_id_bytes = [0xCEu8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        DID("did:example:admin".to_owned()),
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    state
        .handle
        .transition_to(&crate::context::ContextState::Closing)
        .unwrap();
    let snap = crate::context::manager_methods::snapshot_context(&state);
    sup.persistence_ref()
        .expect("test supervisor has persistence")
        .persist_context(&ctx_key, &snap)
        .await
        .unwrap();

    let owning = DID("did:example:admin".to_owned());
    let result = sup.respawn_from_snapshot(&ctx_key, &owning).await;
    assert!(
        matches!(result, Err(ContextError::ContextClosed)),
        "terminal-skip must surface ContextClosed, got {result:?}"
    );
    assert!(
        !sup.crash_windows.contains_key(&ctx_key),
        "a clean terminal-skip must leave NO crash-window entry (the transient \
             respawn marker must be reaped)"
    );
}

/// A successful respawn clears the `last_respawn_failed` flag so the
/// recovered context no longer reports `ActorCrashed` on a lookup miss.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successful_respawn_clears_unrecoverable_flag() {
    let clock = Arc::new(TestClock::new(1_700_000_000));
    let clock_dyn: Arc<dyn Clock> = clock.clone();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

    let ctx_id_bytes = [0xCBu8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);

    // First, a failed respawn (no snapshot yet) sets the flag.
    let owning = DID("did:example:admin".to_owned());
    let _ = sup.respawn_from_snapshot(&ctx_key, &owning).await;
    assert!(
        sup.crash_windows
            .get(&ctx_key)
            .is_some_and(|w| w.last_respawn_failed()),
        "a failed respawn must set the unrecoverable flag"
    );

    // Now persist a valid Active snapshot and respawn again — it succeeds
    // and must clear the flag.
    let (handle, _) = spawn_active_with_snapshot(&sup, ctx_id_bytes).await;
    // Despawn the freshly-spawned actor so the respawn re-insert is clean
    // (respawn despawns internally too, but this keeps the test explicit).
    drop(handle);
    sup.load_wrapping_key(&owning)
        .await
        .expect("an entry point loads the owner's wrapping key");
    sup.respawn_from_snapshot(&ctx_key, &owning)
        .await
        .expect("respawn from a valid Active snapshot must succeed");
    assert!(
        !sup.crash_windows
            .get(&ctx_key)
            .is_some_and(|w| w.last_respawn_failed()),
        "a successful respawn must clear the unrecoverable flag"
    );
}

/// A poisoned context's state is OBSERVABLE: `read_context_state` reports
/// `Poisoned` even though the actor has been despawned (the state is read
/// from the sticky `crash_windows` poison flag, not the dead mailbox).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poisoned_context_state_reads_as_poisoned() {
    let clock = Arc::new(TestClock::new(1_700_000_000));
    let clock_dyn: Arc<dyn Clock> = clock.clone();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

    let ctx_key = "ctx-poison-observable".to_owned();
    let owning = DID("did:example:admin".to_owned());

    // Drive the context to poison via repeated failed respawns (empty
    // persistence guarantees each respawn fails and records one crash).
    for _ in 0..CRASH_POISON_THRESHOLD {
        let _ = sup.respawn_from_snapshot(&ctx_key, &owning).await;
        clock.advance_millis(100);
    }
    assert!(
        sup.is_context_poisoned(&ctx_key),
        "fixture must poison the context"
    );
    assert!(
        sup.lookup(&ctx_key).is_none(),
        "a poisoned context's actor must be despawned"
    );

    // The poison is observable through the public read path.
    assert_eq!(
        sup.read_context_state(&ctx_key).await,
        Some(crate::context::ContextState::Poisoned),
        "a poisoned context (no live actor) must read as Poisoned, not None"
    );

    // An unknown context still reads as None (genuinely absent).
    assert_eq!(
        sup.read_context_state("never-existed").await,
        None,
        "an unknown context must read as None"
    );
}

/// Multi-identity node (ADR-049 §10): a respawn rebuilds deps for the DID
/// the crashed actor's deps were built for, and the deps' `local_dids`
/// view is the SHARED full set, not a snapshot of one DID. Verify the
/// respawn succeeds and the actor is responsive on a node with two local
/// DIDs.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respawn_preserves_owning_identity_on_multi_did_node() {
    let clock = Arc::new(TestClock::new(1_700_000_000));
    let clock_dyn: Arc<dyn Clock> = clock.clone();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

    // Register TWO local DIDs. `min()` of these is the lexicographically
    // smaller one; the respawn will derive that as `owning_did`.
    let did_a = DID("did:example:aaa-first".to_owned());
    let did_b = DID("did:example:zzz-second".to_owned());
    sup.register_local_did(did_a.clone()).await;
    sup.register_local_did(did_b.clone()).await;

    // Spawn an Active context (creator = did_b, the NON-min DID) and
    // persist its snapshot.
    let ctx_id_bytes = [0xCCu8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        did_b.clone(),
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    let snap = crate::context::manager_methods::snapshot_context(&state);
    sup.persistence_ref()
        .expect("test supervisor has persistence")
        .persist_context(&ctx_key, &snap)
        .await
        .unwrap();
    let deps = sup.build_actor_deps_loaded(&did_b).await.unwrap();
    let handle = Box::pin(sup.spawn_actor_with_state(state, deps, None))
        .await
        .expect("spawn registers");

    // Crash it once: the watchdog respawns with deps for did_b, the DID
    // the crashed actor's deps were built for, not the min DID did_a. The
    // respawn must succeed and the actor must be responsive (Active).
    induce_panic(&handle, "SECRET_SENTINEL_abc123").await;
    let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
        sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
            && !sup.is_context_poisoned(&ctx_key)
    })
    .await;
    assert!(
        respawned,
        "respawn on a multi-DID node must succeed and yield a responsive Active actor"
    );
    assert!(
        !sup.key_package_stores.contains_key(&did_a) && !sup.wrapping_keys.contains_key(&did_a),
        "the respawn acts as did_b and never loads did_a's store or wrapping keypair"
    );

    // Both DIDs remain registered (the respawn did not narrow the node's
    // identity set).
    let dids = sup.local_dids_ref().load();
    assert!(
        dids.contains(&did_a) && dids.contains(&did_b),
        "respawn must not narrow the node's local DID set"
    );
}

// -----------------------------------------------------------------------
// ADR-049 §9 sync-persist invariant — crash-rollback regression tests.
//
// §9 mandates that any downward-authorization transition (member removal,
// capability/access revocation, role demotion) is SYNC-persisted before
// the mutation is observable, so a crash+respawn cannot re-grant authority
// that was removed. The governance leaf helpers (`execute_revoke`,
// `execute_remove_member`, …) implement this by calling
// `persist_state_best_effort` synchronously BEFORE they return (and thus
// before the handler sends its reply). These tests prove the mutation
// survives a crash+respawn that occurs BEFORE any 50ms coalesce could fire
// — i.e. the survival is owed to the sync persist, not the coalesce.
// -----------------------------------------------------------------------

/// Drive a real `execute_revoke` (a downward-authorization transition),
/// then crash the actor and respawn it. The revocation MUST survive: the
/// respawned snapshot must still show the target's write capability
/// suspended and the read-exclusion entry present. If `execute_revoke`
/// rode the coalesce path, the crash (which lands before any coalesce)
/// would roll the revocation back and re-grant access.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capability_revocation_survives_crash_before_coalesce() {
    use scp_protocol::context::roles::Capability;

    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let persistence = MapPersistence::default();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

    let ctx_id_bytes = [0xD3u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:revoke-admin".to_owned());
    let target = DID("did:example:revoke-target".to_owned());

    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        admin.clone(),
    );
    // The target must be a member, and the ceiling must permit MemberBan
    // for `execute_revoke` to run. Grant the target write+read so the
    // revocation is an actual downward transition.
    state
        .membership
        .add_member(target.clone(), "member".to_owned(), Vec::new());
    state
        .role_state
        .set_ceiling(scp_protocol::context::roles::CapabilityCeiling::new([
            Capability::MemberBan,
        ]))
        .expect("well-formed built-in ceiling");
    state
        .role_state
        .member_capabilities
        .entry(target.0.clone())
        .or_default()
        .extend([Capability::MessagesWrite, Capability::MessagesRead]);
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();

    let deps = test_actor_deps(&sup).await;

    // Persist the pre-revocation snapshot so respawn has a baseline.
    let pre = crate::context::manager_methods::snapshot_context(&state);
    persistence.persist_context(&ctx_key, &pre).await.unwrap();

    // Perform the downward-authorization transition. `execute_revoke`
    // routes the suspension through `commit_class_s_keep` (a fail-closed
    // persist) synchronously before returning, so the persisted snapshot
    // now reflects the suspension. It takes `&mut ClassSCell`, so wrap the
    // local `state` in a cell for the call, then unwrap it back out for the
    // subsequent `spawn_actor_with_state` hand-off.
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);
    crate::context::governance_helpers::execute_revoke(
        &mut cell,
        &deps,
        &ctx_key,
        &target,
        scp_protocol::context::governance::AccessScope::Both,
        crate::context::shared::governance::CommitMeta {
            pid: [1u8; 32],
            actor_did: admin.as_ref(),
            timestamp_secs: 1_700_000_000,
        },
    )
    .await
    .expect("execute_revoke (Both scope) must succeed");
    let state = cell.into_inner();

    // Sanity: the just-persisted snapshot already carries the revocation,
    // proving the sync persist happened inside the helper (no coalesce).
    let persisted = persistence
        .load_context(&ctx_key)
        .await
        .unwrap()
        .expect("revocation must have been sync-persisted by the helper");
    assert!(
        persisted
            .role_state
            .suspended_for(target.as_ref())
            .is_some_and(|c| c.contains(&Capability::MessagesWrite)),
        "sync-persisted snapshot must show MessagesWrite suspended"
    );

    // Spawn the actor from the (revoked) state and crash it. The crash
    // lands before any coalesce; respawn rehydrates from the snapshot.
    let handle = sup
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn registers");
    induce_panic(&handle, "SECRET_SENTINEL_revoke").await;

    let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
        sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
            && !sup.is_context_poisoned(&ctx_key)
    })
    .await;
    assert!(
        respawned,
        "the revoked context must respawn to a responsive Active actor"
    );

    // The revocation must have survived the crash+respawn: re-load the
    // snapshot the respawn rehydrated from and assert the suspension and
    // read-exclusion entry are still present. A coalesce-only persist
    // would have lost the revocation (re-granting authority).
    let after = persistence
        .load_context(&ctx_key)
        .await
        .unwrap()
        .expect("respawned context must have a snapshot");
    assert!(
        after
            .role_state
            .suspended_for(target.as_ref())
            .is_some_and(|c| {
                c.contains(&Capability::MessagesWrite) && c.contains(&Capability::MessagesRead)
            }),
        "crash+respawn must NOT re-grant the revoked write/read capability"
    );
    assert!(
        after.read_exclusion_list.contains(&target),
        "crash+respawn must NOT drop the read-exclusion entry"
    );
}

/// ADR-049 §9 crash-safety invariant — STRUCTURAL ENFORCEMENT (FIELD
/// ROUND-TRIP HALF).
///
/// Every security-critical, monotonic piece of per-context state must be
/// either Class S (sync-persisted — therefore present in the persisted
/// `ContextSnapshot` and round-trippable) or Class M (crash-surviving in the
/// supervisor-owned MLS crypto provider). A new security-critical field that
/// silently rides only the coalesced (Class C) path is a respawn rollback
/// vulnerability and is FORBIDDEN.
///
/// SCOPE — what THIS test catches, and what it does NOT. This test catches
/// a security FIELD dropped from the snapshot builder: it populates EVERY
/// Class-S `GovernanceState` field with a non-default sentinel, runs the
/// real snapshot build (`build_snapshot_from_state`) + the real persistence
/// serialization round-trip (`serde_json` is the on-disk format), and
/// asserts each sentinel survives. It does NOT catch a missed CONSUME SITE
/// — a code path that mutates a Class-S field and then acknowledges the
/// operation WITHOUT a fail-closed persist (e.g. the message-send / paid-
/// join nonce-consume sites that earlier rounds missed while the outlet-invoke
/// site was fixed). That complementary half is now enforced at COMPILE TIME
/// by the `ClassSCell` boundary (no `DerefMut` / `state_mut`; the only `&mut`
/// reach to a Class-S field is through a persist-on-commit combinator), plus
/// the `class_s_no_persist_mutator_whitelist_is_bounded` tripwire test in
/// `context::actor::class_s`. The two together — field round-trip HERE,
/// mutation-must-persist THERE — are what the §9 enforcement guarantees.
///
/// The mechanism that catches a NEW coalesced-only security FIELD:
///
/// - To add it to `GovernanceState` and have it tested here, the author
///   must populate it below — and the round-trip assertion then FAILS unless
///   the field was also wired into `build_snapshot_from_state` (persist) AND
///   `restore_context` (restore). A field added to `GovernanceState` but NOT
///   to the snapshot is dropped by the round-trip, failing this test.
/// - The `CLASS_M_FIELDS` / `CLASS_C_ACCEPTED` enumerations below document
///   the non-Class-S exceptions explicitly, so a reviewer adding a field can
///   see exactly where each class is enforced.
///
/// Demonstrated to fail on a planted Class-C regression (a new security
/// field added to `GovernanceState` but not the snapshot drops on
/// round-trip → the corresponding assertion fires).
#[test]
#[allow(clippy::too_many_lines)]
fn security_critical_state_is_class_s_or_m_not_coalesced() {
    use crate::context::supervisor::saga_prepared_state::{
        SagaPreparedState, SagaPreparedStateSnapshot,
    };
    // ---- Class M (crash-surviving in the supervisor-owned crypto Arc;
    // restored by monotonic max-merge per §23.17.2 Inv 2, NOT via the
    // ContextSnapshot governance fields). Documented, not asserted here —
    // the floor-guard tests in `crypto::mls::provider` cover these. ----
    const CLASS_M_FIELDS: &[&str] = &[
        "sender_key_epoch_floors", // per-sender MLS replay floors
    ];
    // ---- Class C (accepted soft anti-spam residual, ADR-049 §10): ≤50ms
    // rollback relaxes a rate limit, not an authorization break. ----
    const CLASS_C_ACCEPTED: &[&str] = &["velocity_tracker", "earned_capacity"];
    assert!(
        !CLASS_M_FIELDS.is_empty() && !CLASS_C_ACCEPTED.is_empty(),
        "the Class-M / Class-C enumerations document the non-Class-S exceptions; \
             a new security field must be Class S (below), or explicitly added to one \
             of these with an ADR justification"
    );

    // ---- Class S: populate every sync-persisted security-critical field
    // with a non-default sentinel, then prove it round-trips the snapshot. ----
    let ctx_id_bytes = [0xE1u8; 32];
    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        DID("did:example:class-s-admin".to_owned()),
    );

    // membership (a member to drop is the unit of the removal/leave class).
    let member = DID("did:example:class-s-member".to_owned());
    state
        .membership
        .add_member(member.clone(), "member".to_owned(), Vec::new());

    // executed_proposals (replay protection).
    let executed_id = [0x11u8; 32];
    state
        .governance
        .class_s
        .executed_proposals
        .insert(executed_id, 1_700_000_000);

    // revoked_spending_ucan_cids (revocation set).
    let revoked_cid = "bafyClassSRevokedCid".to_owned();
    state
        .governance
        .revoked_spending_ucan_cids
        .insert(revoked_cid.clone());

    // spending-nonce tracker (replay protection).
    let consumed_nonce = "1700000000000-fedcba9876543210fedcba9876543210".to_owned();
    let mut nonce_entries = std::collections::HashMap::new();
    nonce_entries.insert(consumed_nonce.clone(), (1_700_000_000_u64, u64::MAX));
    let nonce_clock: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    state.governance.class_s.spending_nonce_tracker =
        scp_protocol::crypto::ucan::nonce::NonceTracker::from_snapshot(
            hex::encode(ctx_id_bytes),
            nonce_clock,
            nonce_entries,
        );

    // read-exclusion list (downward access revocation).
    let excluded = DID("did:example:class-s-excluded".to_owned());
    state.access.read_exclusion_list.insert(excluded.clone());

    // saga_pending (ADR-049 §9 line 144 — staged cross-context saga
    // evidence). Stage the cross-context-outlet prepared variant (eight
    // journaled fields); it must survive the snapshot round-trip through
    // its sanctioned non-derive mirror.
    let xctx_saga_id =
        crate::context::supervisor::saga_journal::SagaId("saga-class-s-xctx".to_owned());
    state.class_s.saga_pending.insert(
            xctx_saga_id.clone(),
            crate::context::supervisor::saga_prepared_state::SagaPreparedState::CrossContextOutletInvocation(
                crate::context::supervisor::saga_prepared_state::CrossContextOutletInvocationPrepared {
                    caller_context_id: [0x5Au8; 32],
                    target_context_id: [0x6Bu8; 32],
                    caller_did: DID("did:example:class-s-caller".to_owned()),
                    outlet_registration_id: "class-s-outlet-v1".to_owned(),
                    ucan_proof_id: "class-s-ucan-token".to_owned(),
                    recorded_timestamp_ms: 1_700_000_000_456,
                    recorded_nonce: [0xC7u8; 16],
                    recorded_chain_depth: 4,
                },
            ),
        );
    // Committed cross-context outlet invocation (ADR-049 §9 line 144 — spec
    // §6.2.4 "Exactly-once execution with durable output capture"). Both the
    // TARGET-side durable output capture and the CALLER-side commit witness
    // are Class S: a coalesce-window rollback would re-invoke the outlet /
    // double-settle the escrow on replay. Seed both so the round-trip
    // asserts they survive the production sync-persist builder.
    let committed_saga_id =
        crate::context::supervisor::saga_journal::SagaId("saga-class-s-committed".to_owned());
    let committed_receipt =
        scp_protocol::context::outlets::cross_context_saga::CrossContextOutletReceipt::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[0x3Cu8; 32]),
            scp_protocol::context::outlets::cross_context_saga::CrossContextOutletReceiptFields {
                caller_context_id: [0x5Au8; 32],
                target_context_id: [0x6Bu8; 32],
                caller_did: "did:example:class-s-caller".to_owned(),
                nonce: [0xC7u8; 16],
                outlet_registration_id: "class-s-outlet-v1".to_owned(),
                output_jcs: br#"{"result":42}"#.to_vec(),
                outlet_invoked_event_id: "OutletInvoked:saga-class-s-committed".to_owned(),
                chain_depth: 4,
                timestamp_ms: 1_700_000_000_456,
            },
        )
        .expect("Class-S committed receipt signs");
    state.class_s.xctx_committed_outputs.insert(
        committed_saga_id.clone(),
        crate::context::supervisor::saga_prepared_state::CommittedOutletInvocation {
            receipt: committed_receipt.clone(),
            output_bytes: br#"{"result":42}"#.to_vec(),
            outlet_invoked_event_id: "OutletInvoked:saga-class-s-committed".to_owned(),
        },
    );
    state
        .class_s
        .xctx_committed_invocations
        .insert(committed_saga_id.clone());

    // Broadcast security + roster state (ADR-049 §9, §5.14.8 block-before-serve).
    // A per-author block ADVANCES the key epoch + adds the subscriber to the
    // author block list — a downward-authorization revocation that MUST ride
    // the fail-closed snapshot. Seed one author with a NON-ZERO epoch + a
    // blocked-DID sentinel in its block list + a subscriber in the roster, then
    // assert all three survive the production sync-persist round-trip. A future
    // change that drops `ContextSnapshot::broadcast` from the builder is exactly
    // the regression this catches.
    let bcast_author = "did:example:class-s-bcast-author".to_owned();
    let bcast_blocked = "did:example:class-s-bcast-blocked".to_owned();
    let bcast_subscriber = "did:example:class-s-bcast-subscriber".to_owned();
    let mut seed_bc = scp_protocol::context::broadcast::BroadcastContext::new(
        hex::encode(ctx_id_bytes),
        &scp_protocol::context::params::ContextMode::Broadcast,
        scp_protocol::context::broadcast::BroadcastAdmission::Open,
    )
    .expect("broadcast context seeds");
    seed_bc.add_author(&bcast_author).expect("author registers");
    // Block advances the author epoch (0 -> 1) and inserts the blocked DID.
    seed_bc
        .block_subscriber(&bcast_author, &bcast_blocked)
        .expect("block advances epoch + records block");
    // Inject a subscriber via the snapshot boundary (the roster ADD path is
    // generic over the UCAN-validation context; the snapshot boundary is the
    // faithful equivalent for this field-round-trip probe).
    let mut seed_snap = seed_bc.to_snapshot();
    seed_snap.subscribers.insert(
        bcast_subscriber.clone(),
        scp_protocol::context::broadcast::SubscriberRecord {
            subscriber_did: bcast_subscriber.clone(),
            registered_at: 1_700_000_000,
            has_ucan: false,
        },
    );
    state.broadcast_context =
        Some(scp_protocol::context::broadcast::BroadcastContext::from_snapshot(seed_snap));

    // Build the snapshot via the EXACT production sync-persist builder
    // (`build_snapshot_from_state`, the one `persist_state_fail_closed`
    // calls), then round-trip through the real on-disk serialization format.
    // Using this builder (not `snapshot_context`) is deliberate: it is the
    // Class-S persist path, so a field that this builder drops is exactly
    // the regression the test must catch.
    let snap = crate::context::snapshot::build_snapshot_from_state(&state);
    let json = serde_json::to_vec(&snap).expect("snapshot serializes");
    let restored: crate::context::state::ContextSnapshot =
        serde_json::from_slice(&json).expect("snapshot deserializes");

    // Each Class-S field MUST survive the persistence round-trip. A field
    // that rode only the coalesced path (absent from the snapshot) would be
    // dropped here.
    assert!(
        restored.membership.members().any(|m| m.did == member),
        "Class S: membership must round-trip the snapshot"
    );
    assert!(
        restored.executed_proposals.contains(&executed_id),
        "Class S: executed_proposals must round-trip (replay protection)"
    );
    assert!(
        restored.revoked_spending_ucan_cids.contains(&revoked_cid),
        "Class S: revoked_spending_ucan_cids must round-trip (revocation)"
    );
    assert!(
        restored
            .spending_nonce_tracker_state
            .contains_key(&consumed_nonce),
        "Class S: spending-nonce tracker must round-trip (replay protection)"
    );
    assert!(
        restored.read_exclusion_list.contains(&excluded),
        "Class S: read_exclusion_list must round-trip (access revocation)"
    );

    // saga_pending (ADR-049 §9 line 144): the staged variant must survive
    // the snapshot round-trip through the `SagaPreparedStateSnapshot`
    // mirror, and rehydrate to the identical live `SagaPreparedState`. A
    // field that the builder dropped, or a mirror that lost a journaled
    // field, is exactly the regression this asserts against.
    assert_eq!(
        restored.saga_pending.len(),
        1,
        "Class S: the staged saga must round-trip the snapshot"
    );
    // `SagaPreparedStateSnapshot`/`SagaPreparedState` mismatches are asserted
    // via `let ... else { panic!(…) }` (this test module carries
    // `#[allow(clippy::panic)]`), making the field checks unconditional.
    let xctx_snap = restored
        .saga_pending
        .get(&xctx_saga_id)
        .expect("Class S: cross-context saga must round-trip");
    // The enum now has a streaming sibling, so the bind is refutable; the
    // `let ... else` asserts the unary variant survived, then the body
    // checks field-level fidelity.
    let SagaPreparedStateSnapshot::CrossContextOutletInvocation(snap) = xctx_snap else {
        panic!("Class S: cross-context saga must round-trip as the unary variant");
    };
    assert_eq!(snap.caller_context_id, [0x5Au8; 32]);
    assert_eq!(snap.target_context_id, [0x6Bu8; 32]);
    assert_eq!(snap.caller_did, "did:example:class-s-caller");
    assert_eq!(snap.outlet_registration_id, "class-s-outlet-v1");
    assert_eq!(snap.ucan_proof_id, "class-s-ucan-token");
    assert_eq!(snap.recorded_timestamp_ms, 1_700_000_000_456);
    assert_eq!(snap.recorded_nonce, [0xC7u8; 16]);
    assert_eq!(snap.recorded_chain_depth, 4);

    // The mirror must rehydrate to the identical live `SagaPreparedState`
    // (the same-node restore contract). Exercise `into_prepared` directly.
    let rehydrated = restored
        .saga_pending
        .get(&xctx_saga_id)
        .expect("present")
        .clone()
        .into_prepared();
    let SagaPreparedState::CrossContextOutletInvocation(p) = rehydrated else {
        panic!("rehydration must preserve the unary cross-context outlet variant");
    };
    assert_eq!(p.recorded_chain_depth, 4);
    assert_eq!(p.caller_did, DID("did:example:class-s-caller".to_owned()));

    // Committed cross-context outlet invocation (spec §6.2.4 "Exactly-once
    // execution with durable output capture"): the TARGET-side durable
    // output capture (signed receipt + output) and the CALLER-side commit
    // witness MUST both survive the snapshot round-trip. A capture dropped
    // here would re-invoke the outlet on replay; a witness dropped here would
    // double-settle the escrow.
    let restored_committed = restored
        .xctx_committed_outputs
        .get(&committed_saga_id)
        .expect("Class S: committed cross-context output capture must round-trip");
    assert_eq!(
        restored_committed.receipt, committed_receipt,
        "Class S: the signed receipt must round-trip byte-for-byte (replay reproducibility)"
    );
    assert_eq!(
        restored_committed.outlet_invoked_event_id,
        "OutletInvoked:saga-class-s-committed"
    );
    assert_eq!(
        restored_committed.output_bytes,
        br#"{"result":42}"#.to_vec()
    );
    assert!(
        restored
            .xctx_committed_invocations
            .contains(&committed_saga_id),
        "Class S: the caller-side commit witness must round-trip (idempotency / no double-settle)"
    );

    // Broadcast security + roster state (ADR-049 §9, §5.14.8): the folded
    // `ContextSnapshot::broadcast` must round-trip the author key epoch, the
    // author block list, and the subscriber roster. A builder that dropped this
    // field would silently re-grant a blocked subscriber post-block key access
    // across a respawn — the block-before-serve rollback this test forbids.
    let restored_bc = restored
        .broadcast
        .expect("Class S: broadcast state must round-trip the snapshot");
    let restored_author = restored_bc
        .authors
        .get(&bcast_author)
        .expect("Class S: broadcast author must round-trip");
    assert!(
        restored_author.epoch >= 1,
        "Class S: the author key epoch advance (block) must round-trip"
    );
    assert!(
        restored_author.block_list.contains(&bcast_blocked),
        "Class S: the author block list must round-trip (no post-block re-grant)"
    );
    assert!(
        restored_bc.subscribers.contains_key(&bcast_subscriber),
        "Class S: the broadcast subscriber roster must round-trip"
    );
}

/// Drive a membership mutation through its sync-persisting helper boundary
/// (`persist_state_best_effort`, the exact primitive `execute_remove_member`
/// calls before returning), then crash+respawn. The removed member MUST
/// stay removed: a respawn that re-admitted them would be a security
/// rollback. Asserted through the production mailbox read path (`IsMember`).
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn member_removal_survives_crash_before_coalesce() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let persistence = MapPersistence::default();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

    let ctx_id_bytes = [0xD4u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:remove-admin".to_owned());
    let removed = DID("did:example:removed-member".to_owned());

    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        admin,
    );
    state
        .membership
        .add_member(removed.clone(), "member".to_owned(), Vec::new());
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();

    let deps = test_actor_deps(&sup).await;

    // Apply the removal (the membership-state mutation `execute_remove_member`
    // performs) and sync-persist via the SAME helper the production handler
    // calls before its reply.
    state.membership.remove_member(&removed);
    state.role_state.members.remove(removed.as_ref());
    crate::context::snapshot::persist_state_best_effort(&state, &deps, &ctx_key).await;

    let handle = sup
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn registers");
    induce_panic(&handle, "SECRET_SENTINEL_remove").await;

    let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
        sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
            && !sup.is_context_poisoned(&ctx_key)
    })
    .await;
    assert!(
        respawned,
        "the context must respawn to a responsive Active actor"
    );

    // Query membership through the production mailbox path. The removed
    // member must NOT reappear after the crash+respawn.
    let is_member = {
        let (tx, rx) = tokio::sync::oneshot::channel();
        sup.dispatch_query(crate::context::actor::commands::QueriesCommand::IsMember {
            context_id: ctx_key.clone(),
            did: removed.to_string(),
            reply: tx,
        })
        .await
        .expect("dispatch_query routes to the respawned actor");
        rx.await.expect("respawned actor replies")
    };
    assert_eq!(
        is_member.ok(),
        Some(false),
        "crash+respawn must NOT re-admit the removed member"
    );
}

/// ADR-049 §9 Class S: a consumed spending-UCAN nonce MUST survive a crash
/// before any coalesce. The nonce-consume is sync-persisted (fail-closed)
/// inside `reserve_outlet_economy` BEFORE the reservation is acknowledged; a
/// respawn that re-opened the consumed nonce would let the spending UCAN be
/// replayed. Asserted through the persisted snapshot the respawn rehydrates
/// from (the nonce-tracker entry must be present post-crash).
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spending_nonce_consume_survives_crash_before_coalesce() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let persistence = MapPersistence::default();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

    let ctx_id_bytes = [0xD8u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:nonce-admin".to_owned());

    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        admin,
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();

    // Seed a consumed nonce into the tracker via the snapshot path (the
    // same `(first_seen, token_expiry)` shape `snapshot_entries` persists),
    // with a far-future expiry so the restore-time prune keeps it. This is
    // the post-`commit_spending_ucan_nonce` state. Then sync-persist via the
    // SAME fail-closed primitive `reserve_outlet_economy` calls before reply.
    // Nonce format is `{unix_millis}-{16_byte_hex}` (see `generate_nonce`).
    let consumed_nonce = "1700000000000-0123456789abcdef0123456789abcdef".to_owned();
    let mut seed_entries = std::collections::HashMap::new();
    seed_entries.insert(consumed_nonce.clone(), (1_700_000_000_u64, u64::MAX));
    let nonce_clock: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    state.governance.class_s.spending_nonce_tracker =
        scp_protocol::crypto::ucan::nonce::NonceTracker::from_snapshot(
            ctx_key.clone(),
            nonce_clock,
            seed_entries,
        );
    let deps = test_actor_deps(&sup).await;
    crate::context::snapshot::persist_state_fail_closed(&state, &deps, &ctx_key)
        .await
        .expect("fail-closed persist of the consumed nonce must succeed");

    let handle = sup
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn registers");
    induce_panic(&handle, "SECRET_SENTINEL_nonce").await;

    let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
        sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
            && !sup.is_context_poisoned(&ctx_key)
    })
    .await;
    assert!(
        respawned,
        "the context must respawn to a responsive Active actor"
    );

    // The respawn rehydrates from the persisted snapshot — assert the
    // consumed nonce is still recorded there, so the replayed token would
    // be rejected by the rehydrated tracker.
    let snap = persistence
        .load_context(&ctx_key)
        .await
        .expect("load")
        .expect("snapshot present after respawn");
    assert!(
        snap.spending_nonce_tracker_state
            .contains_key(&consumed_nonce),
        "crash+respawn must NOT drop the consumed spending-UCAN nonce"
    );
}

/// A persistence double whose `persist_context` ALWAYS fails. Used to
/// prove the send path's fail-closed gating: a paid send must surface the
/// persist error (not silently `Ok`) when a spending nonce was committed.
#[derive(Default)]
struct FailingPersistence;
#[async_trait::async_trait]
impl ContextPersistence for FailingPersistence {
    async fn persist_context(
        &self,
        _id: &str,
        _snap: &crate::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("induced persist failure".into())
    }
    async fn load_context(
        &self,
        _id: &str,
    ) -> Result<
        Option<crate::context::state::ContextSnapshot>,
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

/// ADR-049 §9 Class S (BLACK-001) — the MESSAGE-SEND path's spending-nonce
/// persist GATING is fail-closed, structurally identical to the outlet-invoke
/// path. Asserted against the PRODUCTION `finalize_send`: with a persistence
/// backend that always fails, `finalize_send` with a `Some(ClassSCommitToken)`
/// (a paid send) returns an error (the paid send is NOT acknowledged while
/// its nonce-consume is unpersisted), whereas a `None` token
/// (a free / non-spending send) swallows the same failure and returns `Ok`
/// (the common path stays best-effort, un-regressed).
///
/// Before this fix, the send path persisted via `persist_state_best_effort`
/// regardless of whether a spending nonce was committed: a crash in the
/// ≤50ms coalesce window rolled the consume back, freshening the nonce after
/// the caller already saw the send succeed (replay / double-spend).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_path_spending_nonce_persist_is_fail_closed() {
    let sup = supervisor_with_providers();
    let mut deps = test_actor_deps(&sup).await;
    // Swap in a persistence double that always fails.
    deps.persistence = Arc::new(FailingPersistence);

    let ctx_id_bytes = [0xDAu8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let sender = DID("did:example:send-fail-closed".to_owned());
    let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        sender.clone(),
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    let signing_key =
        CommandSigner::local_ed25519(ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]));

    // `finalize_send` is actor-shape (ADR-049 §9): it takes the owning
    // `ClassSCell` so it can drive the Class-S fail-closed persist (via the
    // shared `&*cell`) and the Class-C field mutations (via `class_c_view`).
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);

    // A paid send (spending nonce committed) MUST surface the persist
    // failure — fail-closed.
    let paid = crate::context::messaging_helpers::finalize_send(
        &mut cell,
        &deps,
        &ctx_key,
        &ctx_id_bytes,
        &sender,
        0,
        b"paid",
        crate::context::supervisor::MessageSigner::Active(&signing_key),
        // Paid send: a deferred spending-nonce token whose fail-closed
        // commit drives the persist (previously the `true` bool).
        Some(crate::context::actor::class_s::ClassSCommitToken::new_for_test(&ctx_key)),
        /* is_broadcast = */ false,
    )
    .await;
    assert!(
        matches!(paid, Err(ContextError::PersistenceFailed(_))),
        "a paid send whose spending-nonce consume cannot be persisted MUST \
             fail-closed, not return Ok: got {paid:?}"
    );

    // A free send (no spending nonce) swallows the same failure — the
    // common path stays best-effort, un-regressed.
    let free = crate::context::messaging_helpers::finalize_send(
        &mut cell,
        &deps,
        &ctx_key,
        &ctx_id_bytes,
        &sender,
        1,
        b"free",
        crate::context::supervisor::MessageSigner::Active(&signing_key),
        // Free send: no token (previously the `false` bool) — keeps the
        // best-effort persist, un-regressed.
        None,
        /* is_broadcast = */ false,
    )
    .await;
    assert!(
        free.is_ok(),
        "a free (non-spending) send must keep best-effort persist and \
             not be regressed to fail-closed: got {free:?}"
    );
}

/// §9.9.3 + ADR-039: a checkpoint is stamped `#active`, so an agent-persona
/// send that makes one due builds none (no agent-key signature under the
/// `#active` stamp), and the next `#active` send builds one that verifies
/// against the `#active` key, as a peer checks it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_send_leaves_the_due_checkpoint_to_the_next_active_send() {
    let sup = supervisor_with_providers();
    let mut deps = test_actor_deps(&sup).await;
    let ctx_id_bytes = [0xC7u8; 32];
    // A real Merkle log: the checkpoint signs the log's count and root.
    let event_log = Arc::new(crate::context::providers::event_log::MerkleEventLogProvider::new());
    event_log.init_event_log(&ctx_id_bytes).await.unwrap();
    deps.event_log = event_log;
    let ctx_key = hex::encode(ctx_id_bytes);
    let sender = DID("did:example:checkpoint-persona".to_owned());
    let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        sender.clone(),
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    let active_key = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);
    let active = CommandSigner::local_ed25519(active_key.clone());
    let agent = CommandSigner::local_ed25519(ed25519_dalek::SigningKey::from_bytes(&[0x22u8; 32]));
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);
    // One more send reaches the 50-event threshold.
    *cell.class_c_view().checkpoint_events_since_mut() = 49;

    crate::context::messaging_helpers::finalize_send(
        &mut cell,
        &deps,
        &ctx_key,
        &ctx_id_bytes,
        &sender,
        0,
        b"agent",
        MessageSigner::Agent(&agent),
        None,
        /* is_broadcast = */ false,
    )
    .await
    .unwrap();
    assert!(
        cell.class_c_view().checkpoints_mut().is_empty(),
        "an agent-persona send must not build a checkpoint"
    );
    assert_eq!(*cell.class_c_view().checkpoint_events_since_mut(), 50);

    crate::context::messaging_helpers::finalize_send(
        &mut cell,
        &deps,
        &ctx_key,
        &ctx_id_bytes,
        &sender,
        1,
        b"active",
        MessageSigner::Active(&active),
        None,
        /* is_broadcast = */ false,
    )
    .await
    .unwrap();
    let checkpoints = cell.class_c_view().checkpoints_mut().clone();
    assert_eq!(
        checkpoints.len(),
        1,
        "the #active send builds the due checkpoint"
    );
    scp_event_log::checkpoint::verify_checkpoint_signature(
        &checkpoints[0],
        &active_key.verifying_key(),
    )
    .unwrap();
    assert_eq!(*cell.class_c_view().checkpoint_events_since_mut(), 0);
}

/// Build an Active broadcast `PerContextState` with `author` registered as
/// a broadcast author (§5.14.8 test scaffold).
fn broadcast_state_with_author(
    ctx_id_bytes: [u8; 32],
    author: &DID,
) -> crate::context::actor::state::PerContextState {
    let ctx_key = hex::encode(ctx_id_bytes);
    // Broadcast-mode constructor: sets `mode` + `routing` to the broadcast
    // variants, which the restore path cross-checks against the presence of
    // broadcast state in the snapshot (an encrypted-routing snapshot carrying
    // broadcast state is rejected as corrupt/tampered).
    let mut state = crate::context::actor::state::PerContextState::new_for_test_broadcast(
        ctx_id_bytes,
        1_700_000_000,
        author.clone(),
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    let mut bc = scp_protocol::context::broadcast::BroadcastContext::new(
        ctx_key,
        &scp_protocol::context::params::ContextMode::Broadcast,
        scp_protocol::context::broadcast::BroadcastAdmission::Open,
    )
    .expect("broadcast context");
    bc.add_author(author.as_ref()).expect("author registers");
    state.broadcast_context = Some(bc);
    state
}

/// Test 4 — §5.14.8 block-before-serve. A per-author block whose fail-closed
/// persist FAILS returns `Err(PersistenceFailed)` (NOT `Ok`) — the caller
/// never observes a non-durable block — and the block is RETAINED in memory
/// (keep-direction: un-blocking would be the unsafe direction).
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broadcast_block_persist_is_fail_closed_and_retains_block() {
    let sup = supervisor_with_providers();
    let mut deps = test_actor_deps(&sup).await;
    deps.persistence = Arc::new(FailingPersistence);

    let ctx_id_bytes = [0xB1u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let author = DID("did:example:bcast-block-author".to_owned());
    let blocked = DID("did:example:bcast-block-target".to_owned());

    let state = broadcast_state_with_author(ctx_id_bytes, &author);
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);

    let res = crate::context::broadcast_helpers::block_broadcast_subscriber(
        &mut cell, &deps, &ctx_key, &author, &blocked,
    )
    .await;
    assert!(
        matches!(res, Err(ContextError::PersistenceFailed(_))),
        "a broadcast block whose persist fails MUST fail-closed, not return Ok: got {res:?}"
    );
    assert!(
        cell.broadcast_context
            .as_ref()
            .unwrap()
            .is_blocked(author.as_ref(), blocked.as_ref()),
        "the block must be RETAINED in memory (keep-direction) on persist failure"
    );
}

/// Test 6 — the UNBLOCK path (upward authorization, block-list REMOVE) stays
/// BEST-EFFORT: with a persistence backend that always fails, unblock still
/// returns `Ok`. Proves the fail-closed tightening did not over-reach onto the
/// grant direction (no liveness regression).
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broadcast_unblock_stays_best_effort_on_persist_failure() {
    let sup = supervisor_with_providers();
    let mut deps = test_actor_deps(&sup).await;
    deps.persistence = Arc::new(FailingPersistence);

    let ctx_id_bytes = [0xB2u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let author = DID("did:example:bcast-unblock-author".to_owned());
    let blocked = DID("did:example:bcast-unblock-target".to_owned());

    let mut state = broadcast_state_with_author(ctx_id_bytes, &author);
    // Pre-block the subscriber in memory so there is something to unblock.
    state
        .broadcast_context
        .as_mut()
        .unwrap()
        .block_subscriber(author.as_ref(), blocked.as_ref())
        .unwrap();
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);

    let res = crate::context::broadcast_helpers::unblock_broadcast_subscriber(
        &mut cell, &deps, &ctx_key, &author, &blocked,
    )
    .await;
    assert!(
        res.is_ok(),
        "unblock (upward authorization) must stay best-effort and return Ok on \
             persist failure — no over-tightening: got {res:?}"
    );
    assert!(
        !cell
            .broadcast_context
            .as_ref()
            .unwrap()
            .is_blocked(author.as_ref(), blocked.as_ref()),
        "the unblock must have removed the block in memory"
    );
}

/// Test 7 — §5.14.8 serve-path exclusion consult. A read-excluded (governance-
/// banned) DID is DENIED a broadcast key request even if it is adversarially
/// still present in the subscriber registry and not on the author's own block
/// list. Uses the uniform deny reason (non-leakage).
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broadcast_key_request_denies_read_excluded_even_if_subscriber() {
    let sup = supervisor_with_providers();
    let deps = test_actor_deps(&sup).await;

    let ctx_id_bytes = [0xB3u8; 32];
    let author = DID("did:example:serve-author".to_owned());
    let requester = DID("did:example:serve-excluded".to_owned());
    // The serve path requires the author DID to be locally controlled.
    deps.local_dids
        .store(Arc::new(std::collections::HashSet::from([author.clone()])));

    let mut state = broadcast_state_with_author(ctx_id_bytes, &author);
    // Make the requester a VALID subscriber, NOT on the author block list, so
    // the only thing denying the request is the read_exclusion consult.
    let mut seed = state.broadcast_context.as_ref().unwrap().to_snapshot();
    seed.subscribers.insert(
        requester.to_string(),
        scp_protocol::context::broadcast::SubscriberRecord {
            subscriber_did: requester.to_string(),
            registered_at: 1_700_000_000,
            has_ucan: false,
        },
    );
    state.broadcast_context =
        Some(scp_protocol::context::broadcast::BroadcastContext::from_snapshot(seed));
    // Governance ban wrote the exclusion set (Class-S, fail-closed).
    state.access.read_exclusion_list.insert(requester.clone());
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);

    let decision = crate::context::shared::broadcast::handle_broadcast_key_request(
        &mut cell,
        &deps,
        &author,
        &requester,
        &scp_protocol::crypto::sender_keys::generate_wrapping_keypair().0,
    )
    .expect("serve consult returns a decision");
    assert!(
        matches!(
            &decision,
            scp_protocol::context::broadcast::KeyRequestDecision::Deny { reason }
                if reason == scp_protocol::context::broadcast::KEY_REQUEST_DENY_REASON
        ),
        "a read-excluded requester must be DENIED with the uniform reason even \
             when still a subscriber: got {decision:?}"
    );
}

/// Register `subscriber` in `state`'s broadcast context via the snapshot
/// boundary (the roster ADD path is generic over the UCAN-validation context;
/// the snapshot boundary is the faithful equivalent for these probes).
fn seed_broadcast_subscriber(
    state: &mut crate::context::actor::state::PerContextState,
    subscriber: &DID,
) {
    let mut seed = state.broadcast_context.as_ref().unwrap().to_snapshot();
    seed.subscribers.insert(
        subscriber.to_string(),
        scp_protocol::context::broadcast::SubscriberRecord {
            subscriber_did: subscriber.to_string(),
            registered_at: 1_700_000_000,
            has_ucan: false,
        },
    );
    state.broadcast_context =
        Some(scp_protocol::context::broadcast::BroadcastContext::from_snapshot(seed));
}

/// Build an Active broadcast state where `banned` is a subscriber AND a
/// member, with a ceiling permitting `MemberBan` — everything
/// `execute_revoke` requires of a governance-ban target (§5.14.8 test
/// scaffold shared by the ban durability / atomicity / fail-closed probes).
fn ban_ready_broadcast_state(
    ctx_id_bytes: [u8; 32],
    author: &DID,
    banned: &DID,
) -> crate::context::actor::state::PerContextState {
    use scp_protocol::context::roles::Capability;

    let mut state = broadcast_state_with_author(ctx_id_bytes, author);
    seed_broadcast_subscriber(&mut state, banned);
    state
        .membership
        .add_member(banned.clone(), "subscriber".to_owned(), Vec::new());
    state
        .role_state
        .set_ceiling(scp_protocol::context::roles::CapabilityCeiling::new([
            Capability::MemberBan,
        ]))
        .expect("well-formed built-in ceiling");
    state
        .role_state
        .member_capabilities
        .entry(banned.0.clone())
        .or_default()
        .extend([Capability::MessagesRead]);
    state
}

/// Test 1 — §5.14.8 block-before-serve durability. A per-author block driven
/// through the fail-closed production helper (`block_broadcast_subscriber`)
/// survives a crash that lands before any coalesce: the respawn rehydrates a
/// snapshot whose author block list still holds the blocked DID, and the
/// restored broadcast context DENIES that DID's key request. A block that
/// rode only the coalesced path would be rolled back by the crash, silently
/// re-granting post-block key access (encryption-as-access-control violation).
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broadcast_per_author_block_survives_crash_before_coalesce() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let persistence = MapPersistence::default();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

    let ctx_id_bytes = [0xB5u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let author = DID("did:example:bcast-crash-author".to_owned());
    let blocked = DID("did:example:bcast-crash-blocked".to_owned());

    let mut state = broadcast_state_with_author(ctx_id_bytes, &author);
    // The blocked DID is a VALID subscriber so the post-restore serve-deny is
    // attributable to the BLOCK (not to being unregistered).
    seed_broadcast_subscriber(&mut state, &blocked);
    let deps = test_actor_deps(&sup).await;

    // Persist a pre-block baseline so the respawn has a snapshot to rehydrate.
    let pre = crate::context::manager_methods::snapshot_context(&state);
    persistence.persist_context(&ctx_key, &pre).await.unwrap();

    // Drive the block through the PRODUCTION fail-closed helper (sync-persists
    // atomically into the Class-S snapshot before returning).
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);
    crate::context::broadcast_helpers::block_broadcast_subscriber(
        &mut cell, &deps, &ctx_key, &author, &blocked,
    )
    .await
    .expect("block must sync-persist and return Ok on a working backend");
    let state = cell.into_inner();

    // Spawn from the (blocked) state and crash before any coalesce.
    let handle = sup
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn registers");
    induce_panic(&handle, "SECRET_SENTINEL_bcast_block").await;

    let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
        sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
            && !sup.is_context_poisoned(&ctx_key)
    })
    .await;
    assert!(
        respawned,
        "the context must respawn to a responsive Active actor"
    );

    // The respawn rehydrates from the persisted snapshot — assert the block
    // survived (block_list ∋ blocked) and the restored context DENIES serve.
    let after = persistence
        .load_context(&ctx_key)
        .await
        .unwrap()
        .expect("respawned context must have a snapshot");
    let bc_snap = after
        .broadcast
        .expect("Class S: broadcast state must round-trip the snapshot");
    assert!(
        !bc_snap.authors.is_empty(),
        "the author must be present in the restored snapshot (non-vacuous)"
    );
    let restored_author = bc_snap
        .authors
        .get(author.as_ref())
        .expect("the blocking author must round-trip");
    assert!(
        restored_author.block_list.contains(blocked.as_ref()),
        "crash+respawn must NOT drop the per-author block (no post-block re-grant)"
    );
    // Serve-deny: the restored broadcast context denies the blocked DID's key
    // request (per-author block-list check).
    let restored_bc = scp_protocol::context::broadcast::BroadcastContext::from_snapshot(bc_snap);
    let decision = restored_bc.handle_key_request(
        author.as_ref(),
        blocked.as_ref(),
        &scp_protocol::crypto::sender_keys::generate_wrapping_keypair().0,
    );
    assert!(
        matches!(
            &decision,
            scp_protocol::context::broadcast::KeyRequestDecision::Deny { reason }
                if reason == scp_protocol::context::broadcast::KEY_REQUEST_DENY_REASON
        ),
        "the restored context must DENY the blocked DID's key request: got {decision:?}"
    );
}

/// Test 2 — §5.14.8 governance-ban durability. A context-wide governance ban
/// driven through the fail-closed `execute_revoke` survives a crash before
/// coalesce: the respawned snapshot shows the banned DID in the
/// `read_exclusion_list` AND in every author's block list, the author key
/// epoch advanced, and the subscriber removed — and the restored context
/// DENIES the banned DID's key request. All five facts ride ONE Class-S
/// snapshot, so none can be lost independently.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broadcast_governance_ban_survives_crash_before_coalesce() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let persistence = MapPersistence::default();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

    let ctx_id_bytes = [0xB6u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let author = DID("did:example:ban-crash-author".to_owned());
    let banned = DID("did:example:ban-crash-target".to_owned());

    let state = ban_ready_broadcast_state(ctx_id_bytes, &author, &banned);
    let deps = test_actor_deps(&sup).await;

    let pre = crate::context::manager_methods::snapshot_context(&state);
    persistence.persist_context(&ctx_key, &pre).await.unwrap();

    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);
    crate::context::governance_helpers::execute_revoke(
        &mut cell,
        &deps,
        &ctx_key,
        &banned,
        scp_protocol::context::governance::AccessScope::Read,
        crate::context::shared::governance::CommitMeta {
            pid: [2u8; 32],
            actor_did: author.as_ref(),
            timestamp_secs: 1_700_000_000,
        },
    )
    .await
    .expect("governance ban (Read scope) must sync-persist and succeed");
    let state = cell.into_inner();

    let handle = sup
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn registers");
    induce_panic(&handle, "SECRET_SENTINEL_bcast_ban").await;

    let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
        sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
            && !sup.is_context_poisoned(&ctx_key)
    })
    .await;
    assert!(
        respawned,
        "the banned context must respawn to a responsive Active actor"
    );

    let after = persistence
        .load_context(&ctx_key)
        .await
        .unwrap()
        .expect("respawned context must have a snapshot");
    assert!(
        after.read_exclusion_list.contains(&banned),
        "crash+respawn must NOT drop the governance-ban read-exclusion entry"
    );
    let bc_snap = after
        .broadcast
        .expect("Class S: broadcast state must round-trip the snapshot");
    assert!(
        !bc_snap.authors.is_empty(),
        "the author must be present in the restored snapshot (non-vacuous)"
    );
    let restored_author = bc_snap
        .authors
        .get(author.as_ref())
        .expect("the author must round-trip");
    assert!(
        restored_author.epoch >= 1,
        "crash+respawn must NOT drop the governance-ban key-epoch advance"
    );
    assert!(
        restored_author.block_list.contains(banned.as_ref()),
        "crash+respawn must NOT drop the governance-ban all-author block insert"
    );
    assert!(
        !bc_snap.subscribers.contains_key(banned.as_ref()),
        "crash+respawn must NOT re-admit the banned subscriber to the roster"
    );
    let restored_bc = scp_protocol::context::broadcast::BroadcastContext::from_snapshot(bc_snap);
    let decision = restored_bc.handle_key_request(
        author.as_ref(),
        banned.as_ref(),
        &scp_protocol::crypto::sender_keys::generate_wrapping_keypair().0,
    );
    assert!(
        matches!(
            &decision,
            scp_protocol::context::broadcast::KeyRequestDecision::Deny { reason }
                if reason == scp_protocol::context::broadcast::KEY_REQUEST_DENY_REASON
        ),
        "the restored context must DENY the banned DID's key request: got {decision:?}"
    );
}

/// Test 3 — §5.14.8: a governance ban's read-exclusion entry AND the author
/// key-epoch advance are ONE atomic snapshot round-trip. Because broadcast
/// security state now rides the Class-S `ContextSnapshot`, a SINGLE
/// `build_snapshot_from_state` (the production sync-persist builder) + serde
/// round-trip carries BOTH — proving the exclusion set and the epoch advance
/// cannot diverge across a crash (there is no separate best-effort broadcast
/// write that could land one without the other).
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broadcast_governance_ban_exclusion_and_epoch_advance_are_one_atomic_snapshot() {
    let sup = supervisor_with_providers();
    let deps = test_actor_deps(&sup).await;

    let ctx_id_bytes = [0xB7u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let author = DID("did:example:atomic-author".to_owned());
    let banned = DID("did:example:atomic-banned".to_owned());

    let state = ban_ready_broadcast_state(ctx_id_bytes, &author, &banned);
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);
    crate::context::governance_helpers::execute_revoke(
        &mut cell,
        &deps,
        &ctx_key,
        &banned,
        scp_protocol::context::governance::AccessScope::Read,
        crate::context::shared::governance::CommitMeta {
            pid: [3u8; 32],
            actor_did: author.as_ref(),
            timestamp_secs: 1_700_000_000,
        },
    )
    .await
    .expect("governance ban (Read scope) must succeed");
    let state = cell.into_inner();

    // ONE round-trip through the EXACT production sync-persist builder carries
    // BOTH the exclusion set and the epoch advance.
    let snap = crate::context::snapshot::build_snapshot_from_state(&state);
    let json = serde_json::to_vec(&snap).expect("snapshot serializes");
    let restored: crate::context::state::ContextSnapshot =
        serde_json::from_slice(&json).expect("snapshot deserializes");

    assert!(
        restored.read_exclusion_list.contains(&banned),
        "the exclusion set must be in the atomic snapshot (non-vacuous)"
    );
    let bc_snap = restored
        .broadcast
        .expect("broadcast rides the SAME snapshot as the exclusion set");
    assert!(
        !bc_snap.authors.is_empty(),
        "the author must be present (non-vacuous)"
    );
    let restored_author = bc_snap
        .authors
        .get(author.as_ref())
        .expect("the author must round-trip");
    assert!(
        restored_author.epoch >= 1,
        "the ban key-epoch advance must ride the SAME snapshot as the exclusion set"
    );
    assert!(
        restored_author.block_list.contains(banned.as_ref()),
        "the ban all-author block must ride the SAME snapshot"
    );
    assert!(
        !bc_snap.subscribers.contains_key(banned.as_ref()),
        "the ban subscriber removal must ride the SAME snapshot"
    );
}

/// Test 5 — §5.14.8: a governance ban whose fail-closed persist FAILS returns
/// `Err(PersistenceFailed)` (NOT `Ok`) BEFORE any post-persist event-log
/// append or ack, and the ban is RETAINED in memory (keep-direction). Proves
/// the context-wide ban path shares the block path's fail-closed guarantee:
/// a crash in the coalesce window can never surface a ban the caller was told
/// succeeded but that did not durably land.
///
/// The "BEFORE event-log" ordering is pinned with a [`RecordingEventLog`]:
/// the failing arm must record ZERO durable appends, and a control arm with
/// working persistence proves the SAME revoke path DOES append
/// `AccessRevoked` through this recorder — so the zero-append assertion is
/// non-vacuous (moving the append ahead of the persist fails the test).
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broadcast_governance_ban_persist_is_fail_closed() {
    let recorder = RecordingEventLog::default();
    let sup = supervisor_with_providers_and_event_log(Box::new(recorder.clone()));
    let mut deps = test_actor_deps(&sup).await;
    deps.persistence = Arc::new(FailingPersistence);

    let ctx_id_bytes = [0xB8u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let author = DID("did:example:ban-failclosed-author".to_owned());
    let banned = DID("did:example:ban-failclosed-target".to_owned());

    let state = ban_ready_broadcast_state(ctx_id_bytes, &author, &banned);
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);
    let res = crate::context::governance_helpers::execute_revoke(
        &mut cell,
        &deps,
        &ctx_key,
        &banned,
        scp_protocol::context::governance::AccessScope::Read,
        crate::context::shared::governance::CommitMeta {
            pid: [5u8; 32],
            actor_did: author.as_ref(),
            timestamp_secs: 1_700_000_000,
        },
    )
    .await;
    assert!(
        matches!(res, Err(ContextError::PersistenceFailed(_))),
        "a governance ban whose persist fails MUST fail-closed, not return Ok: got {res:?}"
    );
    // BEFORE event-log/ack: the `Err` must land before the post-persist
    // `AccessRevoked` durable append — nothing may reach the event log.
    let events: Vec<RecordedEvent> = recorder
        .events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert!(
        events.is_empty(),
        "a failed ban persist must return BEFORE any durable event-log \
             append: got {events:?}"
    );
    // Keep-direction: the ban is RETAINED in memory (un-banning would be the
    // unsafe re-grant direction). The banned DID stays excluded + blocked.
    assert!(
        cell.access.read_exclusion_list.contains(&banned),
        "the ban read-exclusion must be RETAINED in memory on persist failure"
    );
    let bc = cell
        .broadcast_context
        .as_ref()
        .expect("broadcast context present");
    assert!(
        bc.is_blocked(author.as_ref(), banned.as_ref()),
        "the ban all-author block must be RETAINED in memory (keep-direction)"
    );

    // CONTROL (non-vacuity): the same revoke path with WORKING persistence
    // appends `AccessRevoked` through this recorder — proving the recorder
    // observes the exact append site the failing arm asserted silent.
    let control_ctx_bytes = [0xB9u8; 32];
    let control_ctx_key = hex::encode(control_ctx_bytes);
    let control_deps = test_actor_deps(&sup).await;
    let control_state = ban_ready_broadcast_state(control_ctx_bytes, &author, &banned);
    let mut control_cell = crate::context::actor::class_s::ClassSCell::new(control_state);
    crate::context::governance_helpers::execute_revoke(
        &mut control_cell,
        &control_deps,
        &control_ctx_key,
        &banned,
        scp_protocol::context::governance::AccessScope::Read,
        crate::context::shared::governance::CommitMeta {
            pid: [6u8; 32],
            actor_did: author.as_ref(),
            timestamp_secs: 1_700_000_000,
        },
    )
    .await
    .expect("the control ban with working persistence must succeed");
    let events: Vec<RecordedEvent> = recorder
        .events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let control_appends = events
        .iter()
        .filter(|(id, event_type, ..)| {
            *id == control_ctx_bytes && *event_type == scp_event_log::EventType::AccessRevoked
        })
        .count();
    assert_eq!(
        control_appends, 1,
        "the successful control ban must append exactly one AccessRevoked \
             (proves the recorder sees the revoke append site): got {events:?}"
    );
}

/// ADR-049 §9 Class S (BLACK-001) — the MESSAGE-SEND path's spending-nonce
/// consume survives a crash before coalesce. With a working backend, a
/// consumed nonce persisted via the PRODUCTION `finalize_send(.. = true)` is
/// still present in the snapshot the respawn rehydrates from — so a replayed
/// spending UCAN would be rejected post-crash.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_path_spending_nonce_consume_survives_crash_before_coalesce() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let persistence = MapPersistence::default();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

    let ctx_id_bytes = [0xDBu8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let sender = DID("did:example:send-nonce-sender".to_owned());

    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        sender.clone(),
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();

    // Seed the post-`commit_spending_ucan_nonce` tracker state (the same
    // shape `snapshot_entries` persists), then run the PRODUCTION send-path
    // finalize with a `Some(ClassSCommitToken)` — the exact gating the
    // metered send path uses. This drives the real fail-closed persist.
    let consumed_nonce = "1700000000000-aabbccddeeff00112233445566778899".to_owned();
    let mut seed_entries = std::collections::HashMap::new();
    seed_entries.insert(consumed_nonce.clone(), (1_700_000_000_u64, u64::MAX));
    let nonce_clock: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    state.governance.class_s.spending_nonce_tracker =
        scp_protocol::crypto::ucan::nonce::NonceTracker::from_snapshot(
            ctx_key.clone(),
            nonce_clock,
            seed_entries,
        );
    let deps = test_actor_deps(&sup).await;
    let signing_key =
        CommandSigner::local_ed25519(ed25519_dalek::SigningKey::from_bytes(&[0x22u8; 32]));
    // `finalize_send` is actor-shape (ADR-049 §9): wrap the state in the
    // owning `ClassSCell` for the call, then reclaim it via `into_inner` to
    // hand off to `spawn_actor_with_state`.
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);
    crate::context::messaging_helpers::finalize_send(
        &mut cell,
        &deps,
        &ctx_key,
        &ctx_id_bytes,
        &sender,
        0,
        b"paid-send",
        crate::context::supervisor::MessageSigner::Active(&signing_key),
        // Paid send: deferred token whose fail-closed commit persists the
        // consumed nonce (previously the `true` bool).
        Some(crate::context::actor::class_s::ClassSCommitToken::new_for_test(&ctx_key)),
        /* is_broadcast = */ false,
    )
    .await
    .expect("fail-closed finalize of the send-path consumed nonce must succeed");
    let state = cell.into_inner();

    let handle = sup
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn registers");
    induce_panic(&handle, "SECRET_SENTINEL_send_nonce").await;

    let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
        sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
            && !sup.is_context_poisoned(&ctx_key)
    })
    .await;
    assert!(
        respawned,
        "the context must respawn to a responsive Active actor"
    );

    let snap = persistence
        .load_context(&ctx_key)
        .await
        .expect("load")
        .expect("snapshot present after respawn");
    assert!(
        snap.spending_nonce_tracker_state
            .contains_key(&consumed_nonce),
        "crash+respawn must NOT drop the send-path consumed spending-UCAN nonce"
    );
}

/// ADR-049 §9 Class S: an executed-proposal id MUST survive a crash before
/// any coalesce. The conflict-resolution handler that records it
/// (`execute_resolve_conflict`) sync-persists fail-closed before its reply;
/// a respawn that dropped it would let an already-resolved proposal be
/// re-executed.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn executed_proposal_survives_crash_before_coalesce() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let persistence = MapPersistence::default();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

    let ctx_id_bytes = [0xD9u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:proposal-admin".to_owned());

    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        admin,
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();

    // Mark a proposal executed (the mutation the conflict-resolution
    // handler performs), then sync-persist fail-closed.
    let executed_id = [0x42u8; 32];
    state
        .governance
        .class_s
        .executed_proposals
        .insert(executed_id, 1_700_000_000);
    let deps = test_actor_deps(&sup).await;
    crate::context::snapshot::persist_state_fail_closed(&state, &deps, &ctx_key)
        .await
        .expect("fail-closed persist of executed proposal must succeed");

    let handle = sup
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn registers");
    induce_panic(&handle, "SECRET_SENTINEL_proposal").await;

    let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
        sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
            && !sup.is_context_poisoned(&ctx_key)
    })
    .await;
    assert!(
        respawned,
        "the context must respawn to a responsive Active actor"
    );

    let snap = persistence
        .load_context(&ctx_key)
        .await
        .expect("load")
        .expect("snapshot present after respawn");
    assert!(
        snap.executed_proposals.contains(&executed_id),
        "crash+respawn must NOT drop the executed-proposal id (replay protection)"
    );
}

/// ADR-049 §9 Class S: a spending-UCAN revocation MUST survive a crash
/// before any coalesce. The revocation set is now a persisted snapshot
/// field (it was previously reset to empty on every restore — a silent
/// downward-authorization rollback the instant a writer existed). A respawn
/// that dropped it would re-admit a revoked token.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spending_ucan_revocation_survives_crash_before_coalesce() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let persistence = MapPersistence::default();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

    let ctx_id_bytes = [0xDAu8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:revoke-admin".to_owned());

    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        admin,
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();

    // Add a revoked CID (the mutation a future revocation handler will
    // perform), then sync-persist fail-closed.
    let revoked_cid = "bafyRevokedSpendingUcanCid".to_owned();
    state
        .governance
        .revoked_spending_ucan_cids
        .insert(revoked_cid.clone());
    let deps = test_actor_deps(&sup).await;
    crate::context::snapshot::persist_state_fail_closed(&state, &deps, &ctx_key)
        .await
        .expect("fail-closed persist of revocation must succeed");

    let handle = sup
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn registers");
    induce_panic(&handle, "SECRET_SENTINEL_revoke").await;

    let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
        sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
            && !sup.is_context_poisoned(&ctx_key)
    })
    .await;
    assert!(
        respawned,
        "the context must respawn to a responsive Active actor"
    );

    let snap = persistence
        .load_context(&ctx_key)
        .await
        .expect("load")
        .expect("snapshot present after respawn");
    assert!(
        snap.revoked_spending_ucan_cids.contains(&revoked_cid),
        "crash+respawn must NOT drop the spending-UCAN revocation"
    );
}

/// A lifecycle close transitions the context to `Closing` and
/// SYNCHRONOUSLY persists that terminal snapshot (via
/// `persist_state_best_effort` inside `close_context_with_key`). A crash
/// immediately after close must therefore NOT resurrect the context as
/// `Active`: `respawn_from_snapshot` reads the `Closing` snapshot and
/// applies the anti-resurrection skip. This closes the manual-close
/// resurrection window (a coalesce-deferred Closing transition could have
/// respawned Active from a stale Active snapshot).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_to_closing_is_sync_persisted_no_resurrection() {
    use scp_protocol::context::roles::Capability;

    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let persistence = MapPersistence::default();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

    let ctx_id_bytes = [0xD5u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:close-admin".to_owned());

    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        admin.clone(),
    );
    // The initiator must hold ContextClose for the close role gate.
    state
        .role_state
        .member_capabilities
        .entry(admin.0.clone())
        .or_default()
        .insert(Capability::ContextClose);
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();

    let deps = test_actor_deps(&sup).await;
    // Persist an Active baseline first — this is the snapshot a
    // coalesce-deferred close would have left behind, which a buggy
    // respawn could resurrect as Active.
    let active_snap = crate::context::manager_methods::snapshot_context(&state);
    assert_eq!(active_snap.state, crate::context::ContextState::Active);
    persistence
        .persist_context(&ctx_key, &active_snap)
        .await
        .unwrap();

    // Run the real close path. It drives the handle to Closing and
    // sync-persists before returning. `close_context` now takes a
    // `&mut ClassSCell` (the close fail-closed persist is performed by the
    // Class-S `_keep` combinator), so wrap the bare test state in a cell.
    let handle_clone = state.handle.clone();
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);
    crate::context::lifecycle_helpers::close_context(&mut cell, &deps, &handle_clone, &admin)
        .await
        .expect("close_context must succeed for a SingleAdmin context");

    // The persisted snapshot must now reflect Closing SYNCHRONOUSLY (no
    // coalesce was given the chance to run).
    let persisted = persistence
        .load_context(&ctx_key)
        .await
        .unwrap()
        .expect("close must have sync-persisted a snapshot");
    assert_eq!(
        persisted.state,
        crate::context::ContextState::Closing,
        "close must sync-persist a Closing snapshot before returning"
    );

    // A respawn from that snapshot must NOT resurrect Active — it applies
    // the anti-resurrection skip and surfaces ContextClosed.
    let result = sup.respawn_from_snapshot(&ctx_key, &admin).await;
    assert!(
        matches!(result, Err(ContextError::ContextClosed)),
        "respawn of a sync-persisted Closing snapshot must skip (ContextClosed), got {result:?}"
    );
    assert!(
        sup.lookup(&ctx_key).is_none(),
        "a closed context must NOT be resurrected into a live actor"
    );
}

/// ADR-049 §9 Class S: `SuspendAccess` (`suspend_all`) strips a member's
/// ENTIRE capability set — a downward-authorization transition that MUST
/// survive a crash before any coalesce. `SuspendAccess` now sync-persists
/// (fail-closed) BEFORE acknowledging, mirroring `execute_suspend_member`.
/// A respawn that re-granted the banned member's capabilities would be a
/// security rollback. Asserted through the persisted snapshot the respawn
/// rehydrates from (the suspended-capabilities entry must be present).
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn suspend_all_survives_crash_before_coalesce() {
    use scp_protocol::context::roles::Capability;

    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let persistence = MapPersistence::default();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

    let ctx_id_bytes = [0xE1u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:suspendall-admin".to_owned());
    let target = DID("did:example:suspendall-target".to_owned());

    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        admin,
    );
    state
        .membership
        .add_member(target.clone(), "member".to_owned(), Vec::new());
    state
        .role_state
        .member_capabilities
        .entry(target.0.clone())
        .or_default()
        .extend([Capability::MessagesWrite, Capability::MessagesRead]);
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();

    let deps = test_actor_deps(&sup).await;

    // Apply the `SuspendAccess` mutation (the same `suspend_all` the
    // production arm performs) and sync-persist via the SAME fail-closed
    // primitive that arm now calls before its reply.
    state.role_state.suspend_all(target.as_ref());
    crate::context::snapshot::persist_state_fail_closed(&state, &deps, &ctx_key)
        .await
        .expect("fail-closed persist of the suspend_all transition must succeed");

    let handle = sup
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn registers");
    induce_panic(&handle, "SECRET_SENTINEL_suspendall").await;

    let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
        sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
            && !sup.is_context_poisoned(&ctx_key)
    })
    .await;
    assert!(
        respawned,
        "the context must respawn to a responsive Active actor"
    );

    // The respawn rehydrates from the persisted snapshot — the suspended
    // capability set for the banned member must still be present, so the
    // ban is NOT rolled back by the crash.
    let snap = persistence
        .load_context(&ctx_key)
        .await
        .expect("load")
        .expect("snapshot present after respawn");
    let suspended = snap
        .role_state
        .suspended_for(target.as_ref())
        .expect("the banned member's suspension must survive the crash");
    assert!(
        suspended.contains(&Capability::MessagesWrite)
            && suspended.contains(&Capability::MessagesRead),
        "crash+respawn must NOT re-grant the SuspendAccess-banned member's capabilities"
    );
}

/// ADR-049 §9 Class S: the `executed_proposals` anti-replay marker MUST
/// survive a crash before any coalesce. A downward-authorization governance
/// arm sync-persists (fail-closed) after the entry point inserts the marker,
/// so the marker is durably captured in the same snapshot. A respawn that
/// dropped the marker would let an already-executed governance proposal be
/// replayed. Asserted through the persisted snapshot.
#[cfg(feature = "testing")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn executed_proposals_marker_survives_crash_before_coalesce() {
    let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
    let persistence = MapPersistence::default();
    let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

    let ctx_id_bytes = [0xE2u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let admin = DID("did:example:execprop-admin".to_owned());

    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        admin,
    );
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();

    let deps = test_actor_deps(&sup).await;

    // Insert the executed-proposal marker (the same anti-replay state
    // `execute_governance_action` records before dispatching a downward-auth
    // arm) and sync-persist via the SAME fail-closed primitive the downward
    // arm calls — the marker rides the downward arm's durable persist.
    let proposal_id: scp_protocol::context::governance::ProposalId = [0xABu8; 32];
    state
        .governance
        .class_s
        .executed_proposals
        .insert(proposal_id, 1_700_000_000);
    crate::context::snapshot::persist_state_fail_closed(&state, &deps, &ctx_key)
        .await
        .expect("fail-closed persist of the executed-proposals marker must succeed");

    let handle = sup
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn registers");
    induce_panic(&handle, "SECRET_SENTINEL_execprop").await;

    let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
        sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
            && !sup.is_context_poisoned(&ctx_key)
    })
    .await;
    assert!(
        respawned,
        "the context must respawn to a responsive Active actor"
    );

    let snap = persistence
        .load_context(&ctx_key)
        .await
        .expect("load")
        .expect("snapshot present after respawn");
    assert!(
        snap.executed_proposals.contains(&proposal_id),
        "crash+respawn must NOT drop the executed-proposals anti-replay marker"
    );
}

/// ADR-049 §9 (round-5 regression): `finalize_send` owns the sequence-number
/// rollback on its error exits, and rolls it back EXACTLY ONCE per error
/// path. The prior code double-rolled (the TTL early-return rolled back AND
/// the `send_message` caller rolled back again on the same `Err`), leaving
/// the counter one BELOW correct via `saturating_sub`. Here we reserve a
/// sequence, drive a paid `finalize_send` against an always-failing
/// persistence backend (the bottom persist-failure path), and assert the
/// counter is rolled back to EXACTLY the pre-reservation baseline — neither
/// short (no rollback) nor over (double rollback).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finalize_send_rolls_back_sequence_exactly_once_on_persist_failure() {
    let sup = supervisor_with_providers();
    let mut deps = test_actor_deps(&sup).await;
    deps.persistence = Arc::new(FailingPersistence);

    let ctx_id_bytes = [0xE3u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let sender = DID("did:example:seq-rollback-sender".to_owned());
    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        ctx_id_bytes,
        1_700_000_000,
        sender.clone(),
    );
    // The sender must be a member to reserve a sequence (membership starts
    // empty in the test constructor).
    state
        .membership
        .add_member(sender.clone(), "member".to_owned(), Vec::new());
    state
        .handle
        .transition_to(&crate::context::ContextState::Active)
        .unwrap();
    let signing_key =
        CommandSigner::local_ed25519(ed25519_dalek::SigningKey::from_bytes(&[0x33u8; 32]));

    // Baseline: the sender's sequence counter before any reservation.
    let baseline = state
        .membership
        .get(sender.as_ref())
        .expect("sender is a member")
        .sequence_number;

    // Reserve a sequence (Phase 1 of a real send), then drive the paid
    // finalize whose fail-closed persist will fail.
    let reserved = state
        .membership
        .next_sequence_number(sender.as_ref())
        .expect("sender is a member");
    assert_eq!(
        reserved,
        baseline + 1,
        "reservation must advance the counter by exactly 1"
    );

    // `finalize_send` is actor-shape (ADR-049 §9): wrap the state in the
    // owning `ClassSCell` for the call, then reclaim it via `into_inner` for
    // the post-send sequence-rollback assertion below.
    let mut cell = crate::context::actor::class_s::ClassSCell::new(state);
    let result = crate::context::messaging_helpers::finalize_send(
        &mut cell,
        &deps,
        &ctx_key,
        &ctx_id_bytes,
        &sender,
        reserved,
        b"paid",
        crate::context::supervisor::MessageSigner::Active(&signing_key),
        // Paid send: deferred token whose fail-closed commit fails here,
        // driving the sequence-rollback path (previously the `true` bool).
        Some(crate::context::actor::class_s::ClassSCommitToken::new_for_test(&ctx_key)),
        /* is_broadcast = */ false,
    )
    .await;
    let state = cell.into_inner();
    assert!(
        matches!(result, Err(ContextError::PersistenceFailed(_))),
        "a paid send whose fail-closed persist fails must surface the error: got {result:?}"
    );

    let after = state
        .membership
        .get(sender.as_ref())
        .expect("sender is a member")
        .sequence_number;
    assert_eq!(
        after, baseline,
        "finalize_send must roll the reserved sequence back to the baseline \
             EXACTLY ONCE (not double-rolled below it)"
    );
}

// -----------------------------------------------------------------
// §6.2.4 cross-context outlet-invocation saga — end-to-end FSM over
// two co-resident actors (slice 5: supervisor FSM dispatch).
//
// These drive the REAL FSM through
// `start_cross_context_outlet_invocation_saga` over two actors spawned
// in ONE supervisor (caller + target), with the supervisor-side outlet
// executor running between Commit-B reserve and settle.
// -----------------------------------------------------------------

/// Caller / target context ids for the saga E2E tests.
const XCTX_CALLER: [u8; 32] = [0x11u8; 32];
const XCTX_TARGET: [u8; 32] = [0x22u8; 32];
const XCTX_OUTLET: &str = "calculator-v1";

/// A recorded event-log append:
/// `(context_id, event_type, actor_did, payload_bytes, timestamp_secs)`.
type RecordedEvent = ([u8; 32], scp_event_log::EventType, String, Vec<u8>, u64);

/// An event-log provider that RECORDS every append so a test can assert
/// the dual `OutletInvoked` / `CrossContextOutletInvoked` records (§6.2.4
/// "Dual event-log recording") landed with the shared correlation nonce.
#[derive(Clone, Default)]
struct RecordingEventLog {
    events: Arc<std::sync::Mutex<Vec<RecordedEvent>>>,
}
#[async_trait::async_trait]
impl crate::context::builder::ContextEventLogProvider for RecordingEventLog {
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
        id: &[u8; 32],
        event_type: scp_event_log::EventType,
        actor: &str,
        payload: scp_event_log::EventPayload,
        timestamp_secs: u64,
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((
                *id,
                event_type,
                actor.to_owned(),
                payload.data,
                timestamp_secs,
            ));
        Ok(())
    }
    async fn destroy_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
}

/// Build a supervisor whose key_resolver resolves `creator_did` to
/// `creator_key` (needed for the target's UCAN re-bind validation), with
/// real (in-memory) providers so both actors can be spawned via
/// `spawn_actor_with_state`. The caller supplies the `event_log` provider
/// so a test can inject a recording log to assert the dual event-log
/// records.
fn xctx_supervisor_with_event_log(
    creator_did: String,
    creator_key: ed25519_dalek::VerifyingKey,
    event_log: Box<dyn crate::context::builder::ContextEventLogProvider>,
) -> Arc<Supervisor> {
    let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
        "did:dht:z6MktestXctxSaga".to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
        Box::new(crate::context::builder::NotConfiguredTransportProvider);
    let key_resolver: KeyResolver = Arc::new(move |did: &DID, _| {
        if did.as_ref() == creator_did {
            Some(creator_key)
        } else {
            None
        }
    });
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            InMemoryStorage::new(),
        )),
    );
    Supervisor::with_providers(
        crypto,
        transport,
        event_log,
        key_resolver,
        None,
        None,
        None,
        None,
        mls_storage,
        crate::domain_handlers(),
    )
}

/// Convenience: a supervisor with a swallowing `TestEventLog` (for tests
/// that do not inspect the event log).
fn xctx_supervisor(
    creator_did: String,
    creator_key: ed25519_dalek::VerifyingKey,
) -> Arc<Supervisor> {
    xctx_supervisor_with_event_log(creator_did, creator_key, Box::new(TestEventLog))
}

/// A persistence double that fails the persist for ONE specific context the
/// Nth time it is called (1-based), then succeeds — modelling a transient
/// Class-S persist failure at a chosen saga step (e.g. the target's
/// Commit-B settle persist). All other contexts / calls succeed.
///
/// With `always = true` the failure is made PERMANENT from `fail_on_call`
/// onward (every call `n >= fail_on_call` fails), modelling a Commit-B settle
/// that NEVER succeeds: Prepare-B (the target's first persist, `n == 1`)
/// still lands, but every Commit-B settle retry fails, so `commit_with_retry`
/// exhausts its budget and the FSM transitions to `NeedsRepair`.
#[derive(Clone)]
struct FailContextPersistOncePersistence {
    target_hex: String,
    fail_on_call: usize,
    /// When `true`, fail every target persist at or after `fail_on_call`
    /// (a permanent Commit-B settle failure → commit-retry exhaustion),
    /// instead of only the single `fail_on_call`-th call.
    always: bool,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}
#[async_trait::async_trait]
impl ContextPersistence for FailContextPersistOncePersistence {
    async fn persist_context(
        &self,
        id: &str,
        _snap: &crate::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if id == self.target_hex {
            let n = self
                .calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                .saturating_add(1);
            if n == self.fail_on_call || (self.always && n >= self.fail_on_call) {
                return Err("induced transient target persist failure".into());
            }
        }
        Ok(())
    }
    async fn load_context(
        &self,
        _id: &str,
    ) -> Result<
        Option<crate::context::state::ContextSnapshot>,
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

/// A supervisor wired with a caller-supplied persistence backend (for the
/// settle-retry test that injects a transient persist failure).
fn xctx_supervisor_with_persistence(
    creator_did: String,
    creator_key: ed25519_dalek::VerifyingKey,
    persistence: Box<dyn ContextPersistence>,
) -> Arc<Supervisor> {
    let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
        "did:dht:z6MktestXctxSagaPersist".to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
        Box::new(crate::context::builder::NotConfiguredTransportProvider);
    let key_resolver: KeyResolver = Arc::new(move |did: &DID, _| {
        if did.as_ref() == creator_did {
            Some(creator_key)
        } else {
            None
        }
    });
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            InMemoryStorage::new(),
        )),
    );
    Supervisor::with_providers(
        crypto,
        transport,
        Box::new(TestEventLog),
        key_resolver,
        Some(persistence),
        None,
        None,
        None,
        mls_storage,
        crate::domain_handlers(),
    )
}

/// Build the CALLER context state: `caller_did` is a member (so the
/// authorize-before-reserve `is_member` check passes) holding
/// `OutletInterface` (so Prepare-A's outbound gate passes). `creator_did` is
/// the role-state creator.
fn xctx_caller_state(
    caller_did: &str,
    creator_did: &str,
) -> crate::context::actor::state::PerContextState {
    use scp_protocol::context::roles::Capability;
    let mut st = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        XCTX_CALLER,
        1_700_000_000,
        DID(creator_did.to_owned()),
    );
    st.handle
        .transition_to(&scp_protocol::context::ContextState::Active)
        .expect("active");
    st.role_state.creator_did = creator_did.to_owned();
    // `is_member` reads `membership`; the outbound gate reads `role_state`.
    st.membership
        .add_member(DID(caller_did.to_owned()), "member".to_owned(), Vec::new());
    st.role_state.members.insert(caller_did.to_owned());
    let mut caps = std::collections::HashSet::new();
    caps.insert(Capability::OutletInterface);
    caps.insert(Capability::OutletCallAll);
    st.role_state
        .member_capabilities
        .insert(caller_did.to_owned(), caps);
    st.role_state
        .set_ceiling(scp_protocol::context::roles::CapabilityCeiling::new([
            Capability::OutletInterface,
            Capability::OutletCallAll,
        ]))
        .expect("well-formed built-in ceiling");
    // Established (both-approved) outbound interface caller→target for
    // XCTX_OUTLET, so the target-axis authorize-before-reserve gate (gate 2)
    // passes. Source/target ids are the hex id-form §6.2.4 stores.
    st.governance.outlet_interfaces.push(
        scp_protocol::context::outlets::interface::OutletInterface {
            source_context: hex::encode(XCTX_CALLER),
            target_context: hex::encode(XCTX_TARGET),
            outlet_id: XCTX_OUTLET.to_owned(),
            rate_limit: None,
            inbound_rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        },
    );
    st
}

/// Build the TARGET context state: registered `XCTX_OUTLET` (2-field schemas,
/// passing the specificity floor), `caller_did` granted OutletInterface +
/// OutletCallAll, `creator_did` the role-state creator / UCAN root issuer.
fn xctx_target_state(
    caller_did: &str,
    creator_did: &str,
) -> crate::context::actor::state::PerContextState {
    use scp_protocol::context::outlets::registry::{OutletRegistration, OutletSchema};
    use scp_protocol::context::roles::Capability;
    let mut st = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        XCTX_TARGET,
        1_700_000_000,
        DID(creator_did.to_owned()),
    );
    st.handle
        .transition_to(&scp_protocol::context::ContextState::Active)
        .expect("active");
    st.role_state.creator_did = creator_did.to_owned();
    st.membership
        .add_member(DID(caller_did.to_owned()), "member".to_owned(), Vec::new());
    st.role_state.members.insert(caller_did.to_owned());
    let mut caps = std::collections::HashSet::new();
    caps.insert(Capability::OutletInterface);
    caps.insert(Capability::OutletCallAll);
    st.role_state
        .member_capabilities
        .insert(caller_did.to_owned(), caps);
    st.role_state
        .set_ceiling(scp_protocol::context::roles::CapabilityCeiling::new([
            Capability::OutletInterface,
            Capability::OutletCallAll,
        ]))
        .expect("well-formed built-in ceiling");
    st.governance.registered_outlets.push(OutletRegistration {
        outlet_id: XCTX_OUTLET.to_owned(),
        kind: scp_protocol::context::outlets::OutletKind::default(),
        name: "Calculator".to_owned(),
        description: "adds".to_owned(),
        schema: OutletSchema {
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "a": {"type": "number"}, "b": {"type": "number"} }
            }),
            output_schema: serde_json::json!({
                "type": "object",
                "properties": { "result": {"type": "number"} }
            }),
            aggregate_schema: None,
        },
        implementation_hash: [0xAA; 32],
        test_vectors: vec![],
        operator_did: DID(creator_did.to_owned()),
        cost: None,
        message_catalog: Vec::new(),
        registered_at: 0,
        signature: Vec::new(),
    });
    st
}

/// Spawn both participant actors in `supervisor` and return their handles
/// (caller, target). The deps are built per-actor through the production
/// `build_actor_deps` path so the actors run real handlers.
async fn spawn_xctx_pair(
    supervisor: &Arc<Supervisor>,
    caller_state: crate::context::actor::state::PerContextState,
    target_state: crate::context::actor::state::PerContextState,
) {
    let caller_deps = supervisor
        .build_actor_deps_loaded(&DID("did:example:xctx-caller-owner".to_owned()))
        .await
        .expect("caller deps");
    supervisor
        .spawn_actor_with_state(caller_state, caller_deps, None)
        .await
        .expect("spawn caller actor");
    let target_deps = supervisor
        .build_actor_deps_loaded(&DID("did:example:xctx-target-owner".to_owned()))
        .await
        .expect("target deps");
    supervisor
        .spawn_actor_with_state(target_state, target_deps, None)
        .await
        .expect("spawn target actor");
}

// -----------------------------------------------------------------------
// Fault-injectable saga-journal harness (live FSM terminal-arm coverage)
// -----------------------------------------------------------------------

/// A `SagaJournal` that wraps the PRODUCTION
/// [`ProtocolRepositorySagaJournal`] (so the post-fault ON-DISK state is
/// byte-for-byte what production leaves behind) and injects a fault at one of
/// two FSM-driven write points:
///
/// - `fail_append_on_state` — fail [`SagaJournal::append`] when the entry's
///   state equals the selector (keyed on [`SagaState::NeedsRepair`] = the
///   seq-4 terminal append, robust to seq renumbering). Proves an append
///   fault at the NeedsRepair terminal does NOT downgrade the in-memory
///   terminal classification (the FSM sets `reached_needs_repair = true`
///   BEFORE the fallible append).
/// - `fail_mark_resolved_committed` — fail the FIRST
///   [`SagaJournal::mark_resolved`] call with terminal `Committed`, then
///   succeed (one-shot, via `swap`). Drives the Ok-arm
///   `resolve_committed_or_needs_repair` divergence (post-dual-commit
///   resolution failure → NeedsRepair, never Aborted) while leaving the
///   journal self-healable on reopen (the second `mark_resolved`, during
///   `recover_committing_entry`, succeeds).
///
/// `load_unresolved` always delegates (reads only) so a reopened supervisor
/// over the SAME inner storage observes the real durable state.
struct FailingSagaJournal {
    inner: ProtocolRepositorySagaJournal<InMemoryStorage>,
    fail_append_on_state: Option<crate::context::supervisor::saga_journal::SagaState>,
    fail_mark_resolved_committed: std::sync::atomic::AtomicBool,
}

impl FailingSagaJournal {
    fn new(
        storage: Arc<InMemoryStorage>,
        fail_append_on_state: Option<crate::context::supervisor::saga_journal::SagaState>,
        fail_mark_resolved_committed: bool,
    ) -> Self {
        Self {
            inner: ProtocolRepositorySagaJournal::new(storage),
            fail_append_on_state,
            fail_mark_resolved_committed: std::sync::atomic::AtomicBool::new(
                fail_mark_resolved_committed,
            ),
        }
    }
}

#[async_trait::async_trait]
impl SagaJournal for FailingSagaJournal {
    async fn append(
        &self,
        entry: crate::context::supervisor::saga_journal::JournalEntry,
    ) -> Result<(), crate::context::supervisor::saga_journal::JournalError> {
        if self.fail_append_on_state == Some(entry.state) {
            return Err(crate::context::supervisor::saga_journal::JournalError::Io(
                "injected saga-journal append fault".to_owned(),
            ));
        }
        self.inner.append(entry).await
    }

    async fn load_unresolved(
        &self,
    ) -> Result<
        Vec<crate::context::supervisor::saga_journal::JournalEntry>,
        crate::context::supervisor::saga_journal::JournalError,
    > {
        self.inner.load_unresolved().await
    }

    async fn mark_resolved(
        &self,
        saga_id: SagaId,
        terminal: crate::context::supervisor::saga_journal::SagaTerminalState,
        secret_bearing: bool,
    ) -> Result<(), crate::context::supervisor::saga_journal::JournalError> {
        if terminal == crate::context::supervisor::saga_journal::SagaTerminalState::Committed
            && self
                .fail_mark_resolved_committed
                .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(crate::context::supervisor::saga_journal::JournalError::Io(
                "injected mark_resolved(Committed) fault".to_owned(),
            ));
        }
        self.inner
            .mark_resolved(saga_id, terminal, secret_bearing)
            .await
    }
}

/// Build a `with_providers_and_journal` supervisor over a caller-supplied
/// saga `journal` + `mls_storage` view + required `persistence`,
/// with a key_resolver mapping `creator_did → creator_key`
/// (the target's UCAN re-bind / divergence-signing root). Sibling of
/// [`xctx_supervisor_with_real_journal_persistence`], but the caller controls
/// the journal + mls backing store so a fault-injecting journal and a
/// reopened supervisor can share one durable store.
fn xctx_supervisor_with_journal(
    creator_did: String,
    creator_key: ed25519_dalek::VerifyingKey,
    journal: Arc<dyn SagaJournal>,
    mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter>,
    persistence: Box<dyn ContextPersistence>,
    wrapping_custody: WrappingCustodySource,
) -> Arc<Supervisor> {
    let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
        "did:dht:z6MktestXctxFaultJournal".to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
        Box::new(crate::context::builder::NotConfiguredTransportProvider);
    let key_resolver: KeyResolver = Arc::new(move |did: &DID, _| {
        if did.as_ref() == creator_did {
            Some(creator_key)
        } else {
            None
        }
    });
    Supervisor::with_providers_and_journal(
        crypto,
        transport,
        Box::new(TestEventLog),
        key_resolver,
        persistence,
        // The live §6.2.4 xctx outbound path stages no caller-side external
        // escrow (Prepare-A presents no outbound spending UCAN), so this
        // helper never needs a payment adapter — faithful production shape.
        None,
        None,
        None,
        crate::context::supervisor::DurableProviders::for_test(journal, mls_storage),
        wrapping_custody,
        crate::domain_handlers(),
    )
}

/// Build the standard caller/target free-outlet xctx invocation request over the
/// `{a:1,b:2}` calculator outlet with the given nonce.
fn xctx_request(
    caller_did: &str,
    now_ms: u64,
    nonce: [u8; 16],
) -> CrossContextOutletInvocationRequest {
    CrossContextOutletInvocationRequest {
        caller_context_id: XCTX_CALLER,
        target_context_id: XCTX_TARGET,
        caller_did: DID(caller_did.to_owned()),
        outlet_registration_id: XCTX_OUTLET.to_owned(),
        ucan_proof_id: None,
        input: serde_json::json!({ "a": 1, "b": 2 }),
        asserted_chain_depth: 2,
        asserted_nonce: nonce,
        asserted_timestamp_ms: now_ms,
    }
}

/// Drive a real two-actor cross-context saga whose Commit-B settle persist
/// ALWAYS fails — exhausting `commit_with_retry` (three commit attempts with
/// exponential back-off sleeps: the first attempt is immediate, then 1s and 2s)
/// into the `NeedsRepair` terminal — over a caller-supplied `journal`.
/// Returns the lifted saga result. The shared body of the Err-arm test's two
/// variants (production journal vs a [`FailingSagaJournal`] that faults the
/// seq-4 `NeedsRepair` append).
async fn drive_commit_exhaustion(
    journal: Arc<dyn SagaJournal>,
    creator_did: &str,
    creator_key_seed: u8,
    caller_did: &str,
    nonce: [u8; 16],
) -> Result<SagaOutput, SagaError> {
    use std::sync::atomic::AtomicUsize;

    let creator_key =
        ed25519_dalek::SigningKey::from_bytes(&[creator_key_seed; 32]).verifying_key();
    let persistence = FailContextPersistOncePersistence {
        target_hex: hex::encode(XCTX_TARGET),
        fail_on_call: 2, // Prepare-B = call 1 (succeeds); every Commit-B settle fails.
        always: true,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            InMemoryStorage::new(),
        )),
    );
    let supervisor = xctx_supervisor_with_journal(
        creator_did.to_owned(),
        creator_key,
        journal,
        mls_storage,
        Box::new(persistence),
        crate::crypto::wrapping::single_custody_source(Arc::new(
            scp_platform::testing::InMemoryKeyCustody::new(),
        )),
    );
    let caller_state = xctx_caller_state(caller_did, creator_did);
    let target_state = xctx_target_state(caller_did, creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let executor = move |input: serde_json::Value| async move {
        let a = input["a"].as_i64().unwrap_or(0);
        let b = input["b"].as_i64().unwrap_or(0);
        Ok(serde_json::json!({ "result": a + b }))
    };
    let now_ms = supervisor.clock_ref().expect("clock").now_millis();
    supervisor
        .start_cross_context_outlet_invocation_saga(
            xctx_request(caller_did, now_ms, nonce),
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            executor,
        )
        .await
}

/// Cumulative read of the `scp_saga_repair_needed_total` operator counter
/// from a `DebuggingRecorder` snapshot. `snapshot()` is non-destructive and
/// the counter is cumulative, so intermediate reads pin the per-variant
/// increment (mutation-distinguishing) rather than inferring it from a bare
/// final total.
fn snapshot_repair_needed_total(snap: &metrics_util::debugging::Snapshotter) -> u64 {
    use metrics_util::debugging::DebugValue;
    snap.snapshot()
        .into_vec()
        .iter()
        .find_map(|(ck, _, _, v)| {
            if ck.key().name() == "scp_saga_repair_needed_total" {
                if let DebugValue::Counter(c) = v {
                    Some(*c)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .unwrap_or(0)
}

/// LIVE Err-arm coverage (spec §6.2.4 "commit_with_retry exhausts (3×) →
/// NeedsRepair"): a real two-actor cross-context saga whose Commit-B settle
/// persist ALWAYS fails drives `commit_with_retry` to exhaust its budget and
/// the FSM lifts the saga to `NeedsRepair`.
///
/// Two variants over the SAME always-fail Commit-B seam:
///
/// - **journal-ok:** the production journal records the seq-4 `NeedsRepair`
///   terminal durably and the saga surfaces from `load_unresolved` at
///   `NeedsRepair`; the `scp_saga_repair_needed_total` operator metric fired.
/// - **journal-faulting:** a [`FailingSagaJournal`] faults the seq-4
///   `NeedsRepair` append, yet the lift STILL returns `NeedsRepair` (the FSM
///   set `reached_needs_repair = true` BEFORE the fallible append), and the
///   durable journal stays at `Committing` — proving the terminal
///   classification is independent of the journal append's success. The
///   `scp_saga_repair_needed_total` operator metric STILL fires for this
///   variant too: it is recorded on the in-memory divergence determination
///   BEFORE the fallible append, so a compound fault (divergence + failed
///   durable append) does not suppress the live operator alert.
///
/// What this test deliberately does NOT assert: that the caller-side
/// Prepare-A external escrow is HELD (not auto-voided) on the `NeedsRepair`
/// terminal. On the live §6.2.4 xctx outbound path the caller-side external
/// escrow is ALWAYS absent — Prepare-A presents no outbound spending UCAN, so
/// no escrow is ever staged; a paid policy would abort at Prepare (never
/// reaching `NeedsRepair`). The hold-vs-void distinction is therefore
/// trivially unobservable here (every terminal voids zero escrows). Exercising
/// the genuine held-not-voided property requires a test-only escrow seam that
/// injects a non-empty external reservation, and is covered by a separate
/// follow-up rather than mis-asserted on this path.
///
/// `#[test]` + a MANUALLY-built `start_paused` current-thread runtime so the
/// three commit attempts' exponential back-off sleeps (first attempt immediate,
/// then 1s and 2s) auto-advance (the only timer; actor message-passing wakes via
/// wakers, not timers) AND the operator metric is captured through a THREAD-LOCAL
/// recorder (the process-global tracing/metrics cache is poisoned across the
/// parallel test binary).
#[test]
fn xctx_saga_err_arm_commit_exhaustion_lifts_needs_repair() {
    use metrics_util::debugging::DebuggingRecorder;

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();

    metrics::with_local_recorder(&recorder, || {
        rt.block_on(async {
            // Variant 1: the production journal records the seq-4 NeedsRepair
            // terminal durably; the saga surfaces from load_unresolved at
            // NeedsRepair, and the operator metric fires.
            let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(
                Arc::new(InMemoryStorage::new()),
            ));
            let result = Box::pin(drive_commit_exhaustion(
                Arc::clone(&journal),
                "did:dht:z6MkXctxErrArmCreator",
                5,
                "did:dht:z6MkXctxErrArmCaller",
                [0x42u8; 16],
            ))
            .await;
            let err =
                result.expect_err("an always-failing Commit-B settle must exhaust → NeedsRepair");
            assert!(
                matches!(err, SagaError::NeedsRepair { .. }),
                "commit-retry exhaustion must lift to NeedsRepair, got {err:?}"
            );
            let unresolved = journal.load_unresolved().await.unwrap();
            assert_eq!(
                unresolved.len(),
                1,
                "variant 1: expected exactly one unresolved saga entry, got {unresolved:?}"
            );
            let entry = &unresolved[0];
            assert_eq!(
                entry.state,
                crate::context::supervisor::saga_journal::SagaState::NeedsRepair,
                "the durable journal must record the NeedsRepair terminal, got {entry:?}"
            );
            // Per-variant pin: variant 1's SUCCESSFUL NeedsRepair append
            // fired the operator metric, so the cumulative counter is 1 now.
            assert_eq!(
                snapshot_repair_needed_total(&snapshotter),
                1,
                "variant 1 (journal-ok) must fire the operator metric exactly once by now"
            );

            // Variant 2: a FailingSagaJournal faults the seq-4 NeedsRepair
            // append; the lift STILL returns NeedsRepair (reached_needs_repair
            // is set BEFORE the fallible append) and the durable journal stays
            // at Committing — the terminal classification is independent of the
            // journal append's success.
            let journal2: Arc<dyn SagaJournal> = Arc::new(FailingSagaJournal::new(
                Arc::new(InMemoryStorage::new()),
                Some(crate::context::supervisor::saga_journal::SagaState::NeedsRepair),
                false,
            ));
            let result2 = Box::pin(drive_commit_exhaustion(
                Arc::clone(&journal2),
                "did:dht:z6MkXctxErrArmFaultCreator",
                6,
                "did:dht:z6MkXctxErrArmFaultCaller",
                [0x43u8; 16],
            ))
            .await;
            let err2 = result2
                .expect_err("commit exhaustion → NeedsRepair even when the journal append faults");
            assert!(
                matches!(err2, SagaError::NeedsRepair { .. }),
                "a NeedsRepair journal-append fault MUST NOT downgrade the terminal \
                     classification (reached_needs_repair is set before the fallible append), \
                     got {err2:?}"
            );
            let unresolved2 = journal2.load_unresolved().await.unwrap();
            assert_eq!(
                unresolved2.len(),
                1,
                "variant 2: expected exactly one unresolved saga entry, got {unresolved2:?}"
            );
            let entry2 = &unresolved2[0];
            assert_eq!(
                entry2.state,
                crate::context::supervisor::saga_journal::SagaState::Committing,
                "with the NeedsRepair append faulted, the durable latest entry stays at \
                     Committing, got {entry2:?}"
            );
            // Per-variant pin — the crux of this fix: variant 2's FAULTED
            // NeedsRepair append STILL fired the operator metric, because it
            // is recorded on the in-memory divergence determination BEFORE
            // the fallible append. The cumulative counter therefore advances
            // to 2. A regression that moved the metric back after the append
            // would leave this at 1.
            assert_eq!(
                snapshot_repair_needed_total(&snapshotter),
                2,
                "variant 2's FAULTED NeedsRepair append must STILL fire the operator metric \
                     (recorded on the in-memory divergence, before the fallible append), \
                     bringing the cumulative total to 2"
            );
        });
    });

    // The operator-alerting metric fired for the diverged saga EXACTLY twice
    // — once per variant, INCLUDING variant 2 whose NeedsRepair append
    // faulted. Both variants increment it because the metric fires on the
    // in-memory divergence determination BEFORE the fallible NeedsRepair
    // append: the divergence is a fact the instant commit-retry exhausts, so
    // recording it does not depend on the durable append succeeding. Variant
    // 2 proves the core guarantee — the live operator alert fires even when
    // the durable NeedsRepair append faults (a compound fault). `== 2` is the
    // precise, mutation-distinguishing assertion; a regression that moved the
    // metric back after the append would leave this at 1.
    let count = snapshot_repair_needed_total(&snapshotter);
    assert_eq!(
        count, 2,
        "a NeedsRepair terminal must increment scp_saga_repair_needed_total once per variant \
             (2 total), INCLUDING variant 2 whose NeedsRepair append faulted (the metric now \
             reflects the in-memory divergence, recorded before the fallible append); got {count}"
    );
}

/// Drive a real two-actor cross-context saga whose dual-commit FULLY succeeds,
/// but whose terminal `mark_resolved(Committed)` journal write faults
/// one-shot. Returns the shared journal + mls backing stores, the capturing
/// (restore-enabled) persistence, the executor call counter, and the lifted
/// terminal — the shared setup of the Ok-arm and self-heal-on-reopen tests.
/// Supervisor #1 is dropped before returning (its actors shut down cleanly on
/// mailbox close) so the reopen test genuinely resurrects from durable state.
async fn drive_xctx_mark_resolved_committed_fault() -> (
    Arc<InMemoryStorage>,
    Arc<InMemoryStorage>,
    CapturingPersistence,
    Arc<std::sync::atomic::AtomicUsize>,
    Result<SagaOutput, SagaError>,
    WrappingCustodySource,
) {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let creator_did = "did:dht:z6MkXctxOkArmCreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();

    let journal_storage = Arc::new(InMemoryStorage::new());
    let mls_inner = Arc::new(InMemoryStorage::new());
    let persistence = CapturingPersistence::with_restore();

    let journal: Arc<dyn SagaJournal> = Arc::new(FailingSagaJournal::new(
        Arc::clone(&journal_storage),
        None,
        /*fail_mark_resolved_committed=*/ true,
    ));
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::clone(
            &mls_inner,
        )),
    );
    // The wrapping keys' custody outlives supervisor #1, as the host's
    // custody outlives a process restart.
    let wrapping_custody: WrappingCustodySource = crate::crypto::wrapping::single_custody_source(
        Arc::new(scp_platform::testing::InMemoryKeyCustody::new()),
    );
    let supervisor = xctx_supervisor_with_journal(
        creator_did.clone(),
        creator_key,
        journal,
        mls_storage,
        Box::new(persistence.clone()),
        Arc::clone(&wrapping_custody),
    );
    let caller_did = "did:dht:z6MkXctxOkArmCaller";
    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_exec = Arc::clone(&calls);
    let executor = move |input: serde_json::Value| {
        let calls = Arc::clone(&calls_for_exec);
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            let a = input["a"].as_i64().unwrap_or(0);
            let b = input["b"].as_i64().unwrap_or(0);
            Ok(serde_json::json!({ "result": a + b }))
        }
    };
    let now_ms = supervisor.clock_ref().expect("clock").now_millis();
    let result = supervisor
        .start_cross_context_outlet_invocation_saga(
            xctx_request(caller_did, now_ms, [0x44u8; 16]),
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            executor,
        )
        .await;

    // Drop supervisor #1: its actor mailboxes close, the actor tasks exit, and
    // only the durable state (journal_storage + mls_inner + persistence
    // snapshots) survives — exactly what a process restart leaves behind.
    drop(supervisor);

    (
        journal_storage,
        mls_inner,
        persistence,
        calls,
        result,
        wrapping_custody,
    )
}

/// LIVE Ok-arm coverage (spec §6.2.4): after a FULLY successful dual-commit
/// (both sides executed and charged), a faulting terminal
/// `mark_resolved(Committed)` MUST surface as `NeedsRepair` — NEVER `Aborted`
/// (Aborted's contract is "neither side committed", which would invite a
/// double-charging retry). The executor ran exactly once (no re-execute), and
/// the durable journal stays at `Committing` (the terminal marker never
/// landed) ready for self-heal on reopen.
#[tokio::test]
async fn xctx_saga_ok_arm_mark_resolved_fault_is_needs_repair_not_aborted() {
    use std::sync::atomic::Ordering;

    let (journal_storage, _mls_inner, _persistence, calls, result, _wrapping_custody) =
        Box::pin(drive_xctx_mark_resolved_committed_fault()).await;

    let err = result.expect_err(
        "a faulting mark_resolved(Committed) after a full dual-commit must surface an error",
    );
    assert!(
        matches!(err, SagaError::NeedsRepair { .. }),
        "a post-dual-commit mark_resolved failure MUST lift to NeedsRepair, got {err:?}"
    );
    assert!(
        !matches!(err, SagaError::Aborted { .. }),
        "it MUST NOT be Aborted (the 'neither committed' contract a retry would honour → \
             double-charge), got {err:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the outlet executed exactly once across the saga (no re-execute on the Ok arm)"
    );

    // The terminal marker never landed (mark_resolved faulted), so the durable
    // journal still shows the seq-3 Committing entry — uncompacted, recoverable.
    let probe = ProtocolRepositorySagaJournal::new(Arc::clone(&journal_storage));
    let unresolved = probe.load_unresolved().await.unwrap();
    assert_eq!(
        unresolved.len(),
        1,
        "ok-arm: expected exactly one unresolved saga entry, got {unresolved:?}"
    );
    let entry = &unresolved[0];
    assert_eq!(
        entry.state,
        crate::context::supervisor::saga_journal::SagaState::Committing,
        "the durable journal must still show the Committing entry (mark_resolved faulted), \
             got {entry:?}"
    );
}

/// LIVE self-heal-on-reopen coverage (spec §17.16.4): a saga left at
/// `Committing` by a faulting terminal resolution self-heals when a FRESH
/// supervisor reopens the SAME durable stores with a NON-failing journal.
/// `restore_on_startup` restores both actors (carrying their committed Class-S
/// capture) THEN replays: the `Committing` entry → `recover_committing_entry`
/// → `redrive_xctx_commit_in_progress` re-drives the idempotent Commit
/// (`AlreadyCommitted` — the executor is NEVER re-invoked) → resolves to
/// `Committed` → the saga compacts away. `load_unresolved` is then empty.
#[tokio::test]
async fn xctx_saga_committing_self_heals_to_committed_on_reopen() {
    use std::sync::atomic::Ordering;

    let (journal_storage, mls_inner, persistence, calls, result, wrapping_custody) =
        Box::pin(drive_xctx_mark_resolved_committed_fault()).await;
    assert!(
        matches!(result, Err(SagaError::NeedsRepair { .. })),
        "precondition: supervisor #1 left the saga at NeedsRepair / Committing"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "precondition: the outlet ran exactly once on supervisor #1"
    );

    // Reopen: a fresh supervisor #2 over the SAME durable stores, with a
    // NON-failing production journal (so the recovery mark_resolved succeeds).
    let creator_did = "did:dht:z6MkXctxOkArmCreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(
        &journal_storage,
    )));
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::clone(
            &mls_inner,
        )),
    );
    // Pre-reopen: the durable journal is NOT empty from the start — it holds
    // exactly the one unresolved saga at `Committing` that supervisor #1 left
    // behind. Asserting this explicitly rules out a vacuous "empty in, empty
    // out" pass of the post-reopen `is_empty()` check below.
    let pre_reopen = journal.load_unresolved().await.unwrap();
    assert_eq!(
        pre_reopen.len(),
        1,
        "pre-reopen: the durable journal must hold exactly one unresolved saga, got \
             {pre_reopen:?}"
    );
    assert_eq!(
        pre_reopen[0].state,
        crate::context::supervisor::saga_journal::SagaState::Committing,
        "pre-reopen: the single unresolved saga must be at Committing, got {:?}",
        pre_reopen[0]
    );

    let supervisor2 = xctx_supervisor_with_journal(
        creator_did,
        creator_key,
        Arc::clone(&journal),
        mls_storage,
        Box::new(persistence.clone()),
        wrapping_custody,
    );

    // Restore-then-replay: restores both actors (resident, carrying their
    // committed capture) then reconciles the unresolved Committing entry.
    supervisor2
        .restore_on_startup()
        .await
        .expect("restore_on_startup (restore both actors, then replay) must succeed");

    // The Committing entry self-healed to Committed and compacted away.
    let unresolved = journal.load_unresolved().await.unwrap();
    assert!(
        unresolved.is_empty(),
        "the Committing entry must self-heal to Committed and compact away on reopen, got \
             {unresolved:?}"
    );
    // The replay re-drove the idempotent Commit (AlreadyCommitted) — the outlet
    // was NEVER re-invoked. NOTE: this post-reopen `calls == 1` check is a
    // STRUCTURAL guard, not a behavioral pin — the executor closure was dropped
    // together with supervisor #1, so the recovery path has no executor to
    // invoke at all; the `AlreadyCommitted` redrive merely re-emits the stored
    // output. The load-bearing recovery assertion is the
    // `load_unresolved().is_empty()` check above; this one documents the
    // never-re-invoke invariant.
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the self-heal replay must re-drive the idempotent Commit (AlreadyCommitted), never \
             re-invoke the outlet"
    );
}

/// Happy path: an ungated cross-context outlet invocation drives the FULL FSM
/// to a committed terminal. The outlet executes EXACTLY ONCE supervisor-side,
/// a verifiable receipt + the captured output are surfaced in `SagaOutput`,
/// and the caller-side escrow reservation is settled (no unbalanced-ticket
/// panic). The signed receipt's preimage fields (nonce / target ctx id /
/// outlet id) reflect what B recorded.
#[tokio::test]
#[allow(clippy::too_many_lines)] // full happy-path E2E: drive + receipt + dual-log assertions
async fn xctx_saga_happy_path_commits_and_executes_once() {
    use scp_protocol::context::outlets::cross_context_saga::CrossContextOutletReceipt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let creator_did = "did:dht:z6MkXctxHappyCreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let event_log = RecordingEventLog::default();
    let supervisor = xctx_supervisor_with_event_log(
        creator_did.clone(),
        creator_key,
        Box::new(event_log.clone()),
    );
    let caller_did = "did:dht:z6MkXctxHappyCaller";

    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    // The target's Active Signing Key (caller-supplied, ADR-049 — the actor
    // holds no key).
    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    // The caller's Active Signing Key (caller-supplied, ADR-049) — used to
    // sign the caller-side divergence marker on a NeedsRepair.
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);

    // Count executor invocations to prove exactly-once.
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_exec = Arc::clone(&calls);
    let executor = move |input: serde_json::Value| {
        let calls = Arc::clone(&calls_for_exec);
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            let a = input["a"].as_i64().unwrap_or(0);
            let b = input["b"].as_i64().unwrap_or(0);
            Ok(serde_json::json!({ "result": a + b }))
        }
    };

    let now_ms = supervisor.clock_ref().expect("clock").now_millis();
    let nonce = [0x42u8; 16];
    let output = supervisor
        .start_cross_context_outlet_invocation_saga(
            CrossContextOutletInvocationRequest {
                caller_context_id: XCTX_CALLER,
                target_context_id: XCTX_TARGET,
                caller_did: DID(caller_did.to_owned()),
                outlet_registration_id: XCTX_OUTLET.to_owned(),
                ucan_proof_id: None, // ungated outlet — no UCAN proof
                input: serde_json::json!({ "a": 1, "b": 2 }),
                asserted_chain_depth: 2,
                asserted_nonce: nonce,
                asserted_timestamp_ms: now_ms,
            },
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            executor,
        )
        .await
        .expect("cross-context saga must commit");

    // The outlet ran exactly once.
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the outlet MUST execute exactly once across the saga"
    );

    // The receipt + output are surfaced.
    let receipt_bytes = output.receipt.expect("committed saga surfaces a receipt");
    let output_bytes = output.output.expect("committed saga surfaces the output");
    let receipt: CrossContextOutletReceipt =
        serde_json::from_slice(&receipt_bytes).expect("receipt decodes");
    // The receipt is signed by the target's key over B-recorded provenance.
    assert!(
        receipt.verify(&target_signing.verifying_key()).is_ok(),
        "the receipt must verify under the target's signing key"
    );
    assert_eq!(receipt.target_context_id, XCTX_TARGET);
    assert_eq!(receipt.caller_context_id, XCTX_CALLER);
    assert_eq!(receipt.nonce, nonce);
    assert_eq!(receipt.outlet_registration_id, XCTX_OUTLET);
    // B re-derived chain depth = incoming(2) + 1.
    assert_eq!(receipt.chain_depth, 3);
    // The output is the canonical outlet result.
    let out_value: serde_json::Value =
        serde_json::from_slice(&output_bytes).expect("output decodes");
    assert_eq!(out_value, serde_json::json!({ "result": 3 }));

    // Dual event-log recording (§6.2.4): `OutletInvoked` on the TARGET log and
    // `CrossContextOutletInvoked` on the CALLER log, sharing the nonce.
    let events = event_log
        .events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let nonce_hex = hex::encode(nonce);
    // The committer-assigned (convergent) leaf timestamp both records MUST
    // carry: B's signed `recorded_timestamp_ms`, in seconds. The two
    // `nonce`-joined records date the one provenance edge identically, and
    // every honest member reconstructs the same leaf (§7.3.1, §9.9.3).
    let expected_leaf_secs = receipt.timestamp_ms / 1000;
    let outlet_invoked = events
        .iter()
        .find(|(id, event_type, _, _, _)| {
            *id == XCTX_TARGET && *event_type == scp_event_log::EventType::OutletInvoked
        })
        .expect("target log must carry a OutletInvoked record");
    // The target's record carries B's re-derived chain depth + the saga id.
    let ti_payload: serde_json::Value =
        serde_json::from_slice(&outlet_invoked.3).expect("OutletInvoked payload");
    assert_eq!(ti_payload["chain_depth"], serde_json::json!(3));
    // Convergent leaf timestamp (NOT a per-member clock read).
    assert_eq!(outlet_invoked.4, expected_leaf_secs);
    let xctx_invoked = events
        .iter()
        .find(|(id, event_type, _, _, _)| {
            *id == XCTX_CALLER && *event_type == scp_event_log::EventType::CrossContextOutletInvoked
        })
        .expect("caller log must carry a CrossContextOutletInvoked record");
    let cci_payload: serde_json::Value =
        serde_json::from_slice(&xctx_invoked.3).expect("CrossContextOutletInvoked payload");
    // The two records share the correlation nonce (the join key) and the
    // caller record references the target ctx id.
    assert_eq!(cci_payload["nonce"], serde_json::json!(nonce_hex));
    assert_eq!(
        cci_payload["target_context_id"],
        serde_json::json!(hex::encode(XCTX_TARGET))
    );
    // The caller-side leaf dates the SAME convergent instant as the
    // target's `OutletInvoked` leaf (drawn from B's signed receipt).
    assert_eq!(xctx_invoked.4, expected_leaf_secs);
}

/// #2196 — a non-active (Closing) CALLER context rejects the UNARY
/// cross-context outlet-invocation saga at Prepare-A's caller-side reserve
/// (`reserve_outlet_economy`, gated by `ensure_context_active`), surfacing
/// the typed `ContextError::OutletContextNotActive` carrier — rendered as
/// the structured, state-free `SCP-OUTLET-6101`
/// `protocol.context-closed-mid-stream` (SCP-OUT-031 PR-2a). Prepare-A fails before
/// Prepare-B / Commit, so the outlet NEVER executes and no A-side reservation
/// is applied. Covers the caller/A-leg of the unary saga, which the runtime
/// previously left ungated (bridge-guard only, on a stale handle cache).
#[tokio::test]
async fn xctx_saga_closing_caller_rejected_at_prepare_a_no_execution() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let creator_did = "did:dht:z6MkXctxClosingCreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let supervisor = xctx_supervisor(creator_did.clone(), creator_key);
    let caller_did = "did:dht:z6MkXctxClosingCaller";

    // Caller transitioned Active → Closing before spawn (its actor stays
    // alive); target stays Active. Gates 1/2 (outbound-caller authorize +
    // established interface) and the rate-limit consume all pass, so the
    // Prepare-A reserve's active gate is the barrier under test.
    let caller_state = xctx_caller_state(caller_did, &creator_did);
    caller_state
        .handle
        .transition_to(&scp_protocol::context::ContextState::Closing)
        .expect("Active → Closing");
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);

    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_exec = Arc::clone(&calls);
    let executor = move |input: serde_json::Value| {
        let calls = Arc::clone(&calls_for_exec);
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            let a = input["a"].as_i64().unwrap_or(0);
            let b = input["b"].as_i64().unwrap_or(0);
            Ok(serde_json::json!({ "result": a + b }))
        }
    };

    let now_ms = supervisor.clock_ref().expect("clock").now_millis();
    let err = supervisor
        .start_cross_context_outlet_invocation_saga(
            CrossContextOutletInvocationRequest {
                caller_context_id: XCTX_CALLER,
                target_context_id: XCTX_TARGET,
                caller_did: DID(caller_did.to_owned()),
                outlet_registration_id: XCTX_OUTLET.to_owned(),
                ucan_proof_id: None,
                input: serde_json::json!({ "a": 1, "b": 2 }),
                asserted_chain_depth: 2,
                asserted_nonce: [0x43u8; 16],
                asserted_timestamp_ms: now_ms,
            },
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            executor,
        )
        .await
        .expect_err("a Closing caller must reject the unary saga at Prepare-A");

    // SCP-OUT-031 PR-2a: the caller reserve gate now surfaces the TYPED
    // `ContextError::OutletContextNotActive`, whose Display is the
    // structured, state-free Protocol-session teardown surface — NOT the old
    // raw `SCP-OUTLET-6080: context not active: {state}` prose.
    let rendered = format!("{err}");
    assert!(
        rendered.contains(
            scp_protocol::context::outlets::error_codes::SLUG_PROTOCOL_CONTEXT_CLOSED_MID_STREAM
        ) || rendered.contains(scp_protocol::context::outlets::error_codes::CODE_PROTOCOL_SESSION),
        "the abort surfaces the caller context-not-active reserve rejection (structured): {err}"
    );
    assert!(
        !rendered.contains("Closing"),
        "the structured surface must NOT leak the raw lifecycle state: {rendered}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the outlet MUST NOT execute — Prepare-A rejected before Prepare-B / Commit"
    );
}

/// Prepare-B reject (confused deputy): the caller references a UCAN proof in
/// B's store that is delegated to a DIFFERENT principal. Prepare-B rejects
/// (SCP-SAGA-13013), the saga ABORTS, the outlet NEVER executes, and the
/// participant-context-set reservation is released (a follow-up saga over
/// the same set is NOT ActorBusy).
#[tokio::test]
#[allow(clippy::too_many_lines)] // confused-deputy E2E: mint UCAN + reject + release assertions
async fn xctx_saga_prepare_b_confused_deputy_aborts_no_execution() {
    use scp_platform::testing::InMemoryKeyCustody;
    use scp_platform::traits::{KeyCustody, KeyType};
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Mint a UCAN delegated to OTHER (not the caller) — the confused-deputy
    // attempt. The creator (root issuer) key must resolve via the
    // supervisor's key_resolver.
    let custody = InMemoryKeyCustody::new();
    let creator_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let creator_pk = custody.public_key(&creator_handle).await.unwrap();
    let creator_did = format!("did:dht:z{}", zbase32::encode(creator_pk.as_bytes()));
    let creator_key =
        ed25519_dalek::VerifyingKey::from_bytes(creator_pk.as_bytes().try_into().unwrap()).unwrap();

    let supervisor = xctx_supervisor(creator_did.clone(), creator_key);
    let caller_did = "did:dht:z6MkXctxDeputyCaller";
    let other_did = "did:dht:z6MkXctxDeputyOther";

    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let mut target_state = xctx_target_state(caller_did, &creator_did);

    // Proof audience = OTHER, NOT the carried caller_did.
    let ctx_hex = hex::encode(XCTX_TARGET);
    let caps = vec![format!("outlet_call:{XCTX_OUTLET}")];
    let params = crate::crypto::ucan::mint::MintParams {
        issuer_did: &creator_did,
        issuer_key: &creator_handle,
        audience_did: other_did,
        context_id: &ctx_hex,
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: None,
    };
    let token = crate::crypto::ucan::mint::mint_ucan(&params, &custody, &scp_clock::SystemClock)
        .await
        .expect("mint");
    target_state
        .xctx_ucan_proofs
        .proofs
        .insert("proof-other".to_owned(), token);

    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    // The caller's Active Signing Key (caller-supplied, ADR-049) — used to
    // sign the caller-side divergence marker on a NeedsRepair.
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_exec = Arc::clone(&calls);
    let executor = move |_input: serde_json::Value| {
        let calls = Arc::clone(&calls_for_exec);
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::json!({ "result": 0 }))
        }
    };

    let now_ms = supervisor.clock_ref().expect("clock").now_millis();
    let err = supervisor
        .start_cross_context_outlet_invocation_saga(
            CrossContextOutletInvocationRequest {
                caller_context_id: XCTX_CALLER,
                target_context_id: XCTX_TARGET,
                caller_did: DID(caller_did.to_owned()),
                outlet_registration_id: XCTX_OUTLET.to_owned(),
                ucan_proof_id: Some("proof-other".to_owned()),
                input: serde_json::json!({ "a": 1, "b": 2 }),
                asserted_chain_depth: 1,
                asserted_nonce: [0x43u8; 16],
                asserted_timestamp_ms: now_ms,
            },
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            executor,
        )
        .await
        .expect_err("confused-deputy proof must abort the saga");
    assert!(
        matches!(
            &err,
            SagaError::Aborted {
                reason: SagaAbortReason::Rejected,
                code: 13013,
                ..
            }
        ),
        "expected SCP-SAGA-13013 confused-deputy Aborted/Rejected, got {err:?}"
    );
    // The outlet NEVER executed.
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a rejected Prepare-B must NOT execute the outlet"
    );

    // The reservation was released: a follow-up over the SAME set is not
    // ActorBusy (it aborts again at Prepare-B, NOT with SagaBusy).
    let now_ms2 = supervisor.clock_ref().expect("clock").now_millis();
    let err2 = supervisor
        .start_cross_context_outlet_invocation_saga(
            CrossContextOutletInvocationRequest {
                caller_context_id: XCTX_CALLER,
                target_context_id: XCTX_TARGET,
                caller_did: DID(caller_did.to_owned()),
                outlet_registration_id: XCTX_OUTLET.to_owned(),
                ucan_proof_id: Some("proof-other".to_owned()),
                input: serde_json::json!({ "a": 1, "b": 2 }),
                asserted_chain_depth: 1,
                asserted_nonce: [0x44u8; 16],
                asserted_timestamp_ms: now_ms2,
            },
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            |_v: serde_json::Value| async move { Ok(serde_json::json!({})) },
        )
        .await
        .expect_err("follow-up still rejects at Prepare-B");
    assert!(
        !matches!(err2, SagaError::Busy { .. }),
        "the aborted saga must RELEASE its reservation (no SagaBusy), got {err2:?}"
    );
}

/// END-TO-END: a participant actor whose mailbox is CLOSED during the
/// Prepare phase surfaces a transient `ContextError::ActorBusy`, which the
/// boundary lift turns into the RETRYABLE
/// `SagaAbortReason::ParticipantUnavailable` terminal (code `13068`) — NOT
/// the permanent `Rejected`/`13067` an untyped abort would produce.
///
/// Determinism: spawn a live caller+target pair (so the supervisor-side
/// authorize-before-reserve gates — `is_member` and
/// `has_established_outlet_interface`, both of which route through the CALLER
/// actor's mailbox — and Prepare-A, which also dispatches to the caller, all
/// pass), then swap ONLY the TARGET registry handle for a closed-inbox one
/// (`from_sender(tx)` with the receiver dropped). `lookup(target_hex)` still
/// resolves (so this is NOT the `ContextNotRegistered`/`13053` path), but
/// Prepare-B's `send` hits the closed-channel arm → `ActorBusy`. The saga
/// never reaches Commit, so `needs_repair` stays `false` and the lift takes
/// the Prepare-phase `ActorBusy` branch.
#[tokio::test]
async fn xctx_saga_closed_participant_mailbox_aborts_participant_unavailable() {
    let creator_did = "did:dht:z6MkXctxMailboxCreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let supervisor = xctx_supervisor(creator_did.clone(), creator_key);
    let caller_did = "did:dht:z6MkXctxMailboxCaller";

    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    // Swap the TARGET handle for a closed-inbox one: the receiver is dropped,
    // so the next `send` resolves to the closed-channel arm → `ActorBusy`.
    // The caller stays LIVE so every caller-routed gate + Prepare-A pass; the
    // saturation is isolated to Prepare-B's target send.
    let target_hex = hex::encode(XCTX_TARGET);
    let (dead_tx, dead_rx) = tokio::sync::mpsc::channel::<ContextCommand>(1);
    drop(dead_rx);
    supervisor
        .actors
        .insert(target_hex, ContextActorHandle::from_sender(dead_tx));

    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let now_ms = supervisor.clock_ref().expect("clock").now_millis();

    let err = supervisor
        .start_cross_context_outlet_invocation_saga(
            CrossContextOutletInvocationRequest {
                caller_context_id: XCTX_CALLER,
                target_context_id: XCTX_TARGET,
                caller_did: DID(caller_did.to_owned()),
                outlet_registration_id: XCTX_OUTLET.to_owned(),
                ucan_proof_id: None,
                input: serde_json::json!({ "a": 1, "b": 2 }),
                asserted_chain_depth: 1,
                asserted_nonce: [0x4Du8; 16],
                asserted_timestamp_ms: now_ms,
            },
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            |_v: serde_json::Value| async move { Ok(serde_json::json!({})) },
        )
        .await
        .expect_err("a closed participant mailbox during Prepare must abort the saga");

    assert!(
        matches!(
            &err,
            SagaError::Aborted {
                reason: SagaAbortReason::ParticipantUnavailable,
                code: 13068,
                ..
            }
        ),
        "a Prepare-phase closed-mailbox ActorBusy must lift to the retryable \
             Aborted/ParticipantUnavailable/13068, got {err:?}"
    );
    // EXPLICITLY rule out the untyped-abort mis-classification.
    assert!(
        !matches!(
            &err,
            SagaError::Aborted {
                reason: SagaAbortReason::Rejected,
                ..
            }
        ),
        "a transient unavailable participant actor must NOT surface as a permanent Rejected, got {err:?}"
    );
    assert!(
        err.to_string().contains("SCP-SAGA-13068"),
        "Display must carry the canonical retryable code, got {err}"
    );
}

/// FIX A target-wedge (BLACK-624-02): a caller who is a member of its OWN
/// context but has NO established interface to a VICTIM target cannot reserve
/// (and thereby wedge) the victim's saga slot. The saga rejects with the
/// target-axis authorize-before-reserve error (SCP-SAGA-13062) BEFORE any
/// reservation, and a LEGITIMATE saga touching the victim target is NOT
/// locked out afterward (the victim slot was never taken).
#[tokio::test]
async fn xctx_saga_unestablished_target_is_rejected_before_reservation() {
    const XCTX_VICTIM: [u8; 32] = [0xBBu8; 32];

    let creator_did = "did:dht:z6MkXctxWedgeCreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let supervisor = xctx_supervisor(creator_did.clone(), creator_key);
    let caller_did = "did:dht:z6MkXctxWedgeCaller";

    // The caller context has an established interface to XCTX_TARGET only —
    // NOT to XCTX_VICTIM. The caller is a member of its own context (so the
    // caller-axis is_member gate trivially passes).
    let caller_state = xctx_caller_state(caller_did, &creator_did);
    supervisor
        .spawn_actor_with_state(
            caller_state,
            supervisor
                .build_actor_deps_loaded(&DID("did:example:xctx-wedge-caller-owner".to_owned()))
                .await
                .expect("caller deps"),
            None,
        )
        .await
        .expect("spawn caller actor");

    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let now_ms = supervisor.clock_ref().expect("clock").now_millis();

    // The caller names the VICTIM target it has NO established interface
    // with. The saga MUST reject at the target-axis gate, before reserving.
    let err = supervisor
        .start_cross_context_outlet_invocation_saga(
            CrossContextOutletInvocationRequest {
                caller_context_id: XCTX_CALLER,
                target_context_id: XCTX_VICTIM,
                caller_did: DID(caller_did.to_owned()),
                outlet_registration_id: XCTX_OUTLET.to_owned(),
                ucan_proof_id: None,
                input: serde_json::json!({ "a": 1, "b": 2 }),
                asserted_chain_depth: 1,
                asserted_nonce: [0x4Au8; 16],
                asserted_timestamp_ms: now_ms,
            },
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            |_v: serde_json::Value| async move { Ok(serde_json::json!({ "result": 3 })) },
        )
        .await
        .expect_err("a caller with no established interface to the victim must be rejected");
    assert!(
        matches!(
            &err,
            SagaError::Aborted {
                reason: SagaAbortReason::Rejected,
                code: 13062,
                ..
            }
        ),
        "expected target-axis authorize-before-reserve Aborted/Rejected (SCP-SAGA-13062), \
             got: {err:?}"
    );

    // The victim's saga slot was NEVER reserved — a legitimate saga that
    // genuinely involves the victim target can still reserve it. (We exercise
    // the SAME reservation critical section the start path uses.)
    let legit =
        supervisor.test_reserve_saga_context_set(&SagaInput::CrossContextOutletInvocation {
            caller_context_id: [0xC1u8; 32],
            target_context_id: XCTX_VICTIM,
            caller_did: DID("did:dht:zLegit".to_owned()),
            outlet_registration_id: "legit-outlet".to_owned(),
            ucan_proof_id: None,
            input: serde_json::json!({}),
            asserted_chain_depth: 0,
            asserted_nonce: [0u8; 16],
            asserted_timestamp_ms: 0,
            _seal: CrossContextSagaSeal::new(),
        });
    assert!(
        !matches!(legit, Err(ContextError::ActorBusy(_))),
        "the victim target slot must be free (the rejected saga never reserved it), \
             got {:?}",
        legit.err()
    );
}

/// Per-context-set busy: while one saga's participant set is reserved
/// in-flight (held via the production reservation primitive), a second
/// overlapping cross-context saga is rejected with ActorBusy / SagaBusy.
#[tokio::test]
async fn xctx_saga_overlapping_set_is_saga_busy() {
    let creator_did = "did:dht:z6MkXctxBusyCreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let supervisor = xctx_supervisor(creator_did.clone(), creator_key);
    let caller_did = "did:dht:z6MkXctxBusyCaller";

    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    // Hold the {caller, target} set in flight via the production reservation
    // primitive (same critical section start_saga uses).
    let held = supervisor
        .test_reserve_saga_context_set(&SagaInput::CrossContextOutletInvocation {
            caller_context_id: XCTX_CALLER,
            target_context_id: XCTX_TARGET,
            caller_did: DID(caller_did.to_owned()),
            outlet_registration_id: XCTX_OUTLET.to_owned(),
            ucan_proof_id: None,
            input: serde_json::json!({}),
            asserted_chain_depth: 0,
            asserted_nonce: [0u8; 16],
            asserted_timestamp_ms: 0,
            _seal: CrossContextSagaSeal::new(),
        })
        .expect("first reservation succeeds");

    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    // The caller's Active Signing Key (caller-supplied, ADR-049) — used to
    // sign the caller-side divergence marker on a NeedsRepair.
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let now_ms = supervisor.clock_ref().expect("clock").now_millis();
    let err = supervisor
        .start_cross_context_outlet_invocation_saga(
            CrossContextOutletInvocationRequest {
                caller_context_id: XCTX_CALLER,
                target_context_id: XCTX_TARGET,
                caller_did: DID(caller_did.to_owned()),
                outlet_registration_id: XCTX_OUTLET.to_owned(),
                ucan_proof_id: None,
                input: serde_json::json!({ "a": 1, "b": 2 }),
                asserted_chain_depth: 1,
                asserted_nonce: [0x45u8; 16],
                asserted_timestamp_ms: now_ms,
            },
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            |_v: serde_json::Value| async move { Ok(serde_json::json!({ "result": 3 })) },
        )
        .await
        .expect_err("overlapping saga must be rejected while the set is held");
    assert!(
        matches!(
            &err,
            SagaError::Busy { contended_context, .. }
                if !contended_context.is_empty()
        ),
        "overlap rejection must be SagaError::Busy carrying the contended context, got: {err:?}"
    );
    drop(held);
}

/// `lift_run_saga_error` reads the `SCP-SAGA-13xxx` `code` STRUCTURALLY off
/// `RunSagaError::saga_code` (carried from the [`SagaReject`] reject path) —
/// it NEVER parses the message string. This pins the parse-removal: the
/// `error` message here deliberately embeds a DIFFERENT but otherwise VALID
/// `SCP-SAGA-` token than the structural `saga_code`, and a `None` structural
/// code with a code-bearing message still lifts to the generic `13067`. If
/// any string parse were reintroduced, the asserted codes would change.
#[test]
fn lift_reads_saga_code_structurally_not_from_message() {
    // Structural code wins even when the MESSAGE bears a different token.
    //
    // The decoy token MUST be a VALID `u16` code (`13050 < u16::MAX`) that
    // DIFFERS from the structural `13013`. A token like `99999` would not
    // exercise this assertion: codes are `u16`, so a reintroduced
    // `parse::<u16>()` on `99999` would OVERFLOW → `None` → fall back to the
    // structural `13013` for the WRONG reason (parse failure, not "we never
    // parse"). `13050` parses cleanly to a value `≠ 13013`, so a message-first
    // parse would yield `13050` and this assert would catch the regression.
    let lifted = Supervisor::lift_run_saga_error(
        SagaId("saga-structural".to_owned()),
        RunSagaError {
            error: ContextError::PermissionDenied(
                "SCP-SAGA-13050: a message whose embedded token is NOT the real code".to_owned(),
            ),
            needs_repair: false,
            saga_code: Some(13013),
        },
    );
    assert!(
        matches!(
            lifted,
            SagaError::Aborted {
                reason: SagaAbortReason::Rejected,
                code: 13013,
                ..
            }
        ),
        "the lift must read the STRUCTURAL saga_code (13013), never the message's token (13050)"
    );

    // A `None` structural code falls back to the generic `13067` EVEN WHEN
    // the message embeds a `SCP-SAGA-` token (a re-introduced parse would
    // wrongly recover 13050 here).
    let lifted = Supervisor::lift_run_saga_error(
        SagaId("saga-none".to_owned()),
        RunSagaError {
            error: ContextError::InvalidState(
                "SCP-SAGA-13050: a codeless terminal whose message happens to embed a token"
                    .to_owned(),
            ),
            needs_repair: false,
            saga_code: None,
        },
    );
    assert!(
        matches!(
            lifted,
            SagaError::Aborted {
                reason: SagaAbortReason::Rejected,
                code: 13067,
                ..
            }
        ),
        "a None structural code must fall back to 13067, never parse 13050 out of the message"
    );
}

/// `lift_run_saga_error` maps the FSM's internal `RunSagaError` into the
/// typed terminal `SagaError`: `needs_repair` ⇒ `NeedsRepair` carrying the
/// minted `saga_id`; a `RateLimited` abort ⇒ `Aborted{RateLimited}` with a
/// STRUCTURED `retry_after_ms` (never re-parsed); a Prepare-phase `ActorBusy`
/// ⇒ `Aborted{ParticipantUnavailable}` / `SCP-SAGA-13068` (synthesized); any
/// other reject ⇒ `Aborted{Rejected}` carrying its structural saga code. (The
/// `SagaAbortReason` variant rustdoc remains the authoritative rationale.)
#[test]
fn lift_run_saga_error_maps_every_terminal() {
    // NeedsRepair carries the minted saga id (the operator-repair handle).
    let saga_id = SagaId("saga-lift-test".to_owned());
    let lifted = Supervisor::lift_run_saga_error(
        saga_id.clone(),
        RunSagaError {
            error: ContextError::InvalidState("commit retries exhausted".to_owned()),
            needs_repair: true,
            saga_code: None,
        },
    );
    match lifted {
        SagaError::NeedsRepair { saga_id: id, .. } => assert_eq!(id, saga_id),
        other => panic!("expected NeedsRepair, got {other:?}"),
    }

    // A RateLimited abort surfaces the structured retry_after_ms + the
    // STRUCTURAL saga code (the message carries no SCP-SAGA token — the code
    // rides `saga_code`).
    let lifted = Supervisor::lift_run_saga_error(
        SagaId("saga-rl".to_owned()),
        RunSagaError {
            error: ContextError::RateLimited {
                resource: "outlet_interface".to_owned(),
                message: "per-interface rate limit exceeded".to_owned(),
                retry_after_ms: Some(4500),
            },
            needs_repair: false,
            saga_code: Some(13023),
        },
    );
    assert!(
        matches!(
            lifted,
            SagaError::Aborted {
                reason: SagaAbortReason::RateLimited {
                    retry_after_ms: Some(4500)
                },
                code: 13023,
                ..
            }
        ),
        "RateLimited abort must carry structured retry_after_ms + code 13023"
    );

    // A Prepare-phase ActorBusy ⇒ ParticipantUnavailable/13068 (synthesized,
    // asserted below); every OTHER non-RateLimited reject ⇒ Aborted/Rejected
    // carrying its STRUCTURAL code.
    let lifted = Supervisor::lift_run_saga_error(
        SagaId("saga-rej".to_owned()),
        RunSagaError {
            error: ContextError::PermissionDenied("confused-deputy".to_owned()),
            needs_repair: false,
            saga_code: Some(13013),
        },
    );
    assert!(
        matches!(
            lifted,
            SagaError::Aborted {
                reason: SagaAbortReason::Rejected,
                code: 13013,
                ..
            }
        ),
        "a coded policy reject (the 13013 confused-deputy case) must lift to Aborted/Rejected carrying its structural code"
    );

    // A genuinely-reachable prefix-less abort — the Prepare-phase 30s
    // timeout, which surfaces as a `TransportTimeout` carrying NO
    // `SCP-SAGA-` prefix — must fall back to the generic saga-abort code
    // `13067`, NOT `13050` (the SPECIFIC caller-membership-gate reject). A
    // `13050` here would surface as a caller-authorization failure that
    // never occurred.
    let lifted = Supervisor::lift_run_saga_error(
        SagaId("saga-timeout".to_owned()),
        RunSagaError {
            error: ContextError::TransportTimeout(
                "saga PrepareA exceeded 30s phase budget".to_owned(),
            ),
            needs_repair: false,
            saga_code: None,
        },
    );
    assert!(
        matches!(
            lifted,
            SagaError::Aborted {
                reason: SagaAbortReason::Rejected,
                code: 13067,
                ..
            }
        ),
        "a reject with no saga code (e.g. a Prepare-phase timeout) must fall back to the \
             generic saga-abort code 13067, not the specific caller-membership code 13050"
    );

    // A Prepare-phase `ActorBusy` (needs_repair == false) lifts to the
    // RETRYABLE `ParticipantUnavailable` reason + code 13068, not
    // Rejected/13067.
    let lifted = Supervisor::lift_run_saga_error(
        SagaId("saga-participant-unavailable".to_owned()),
        RunSagaError {
            error: ContextError::ActorBusy("mailbox full for 30 seconds".to_owned()),
            needs_repair: false,
            saga_code: None,
        },
    );
    assert!(
        matches!(
            lifted,
            SagaError::Aborted {
                reason: SagaAbortReason::ParticipantUnavailable,
                code: 13068,
                ..
            }
        ),
        "Prepare-phase ActorBusy must lift to retryable ParticipantUnavailable/13068, not Rejected/13067"
    );
}

/// Regression for the SYMMETRIC `commit_result == Ok(())` defect in
/// `run_saga_fsm`: after a FULLY SUCCESSFUL dual-commit (both sides executed
/// and charged), a failed terminal `mark_resolved(Committed)` journal write
/// surfaces as a prefix-less InvalidState whose message text begins with
/// "saga journal mark_resolved:" and carries no saga error code.
///
/// WITHOUT the fix, the Ok arm propagated that error with
/// `reached_needs_repair == false`, so the boundary lift produced
/// `SagaError::Aborted { reason: Rejected, code: 13067 }`. `Aborted`'s
/// contract is "NEITHER side committed", so a contract-honoring caller would
/// RETRY with a fresh `SagaId` (a new §6.2.4 idempotency key) → the
/// cross-context outlet EXECUTES AND CHARGES A SECOND TIME.
///
/// WITH the fix, the Ok arm sets `reached_needs_repair = true` before
/// returning, so the SAME journal-I/O error lifts to `SagaError::NeedsRepair`
/// carrying the `saga_id` operator-repair handle — "needs reconciliation, do
/// NOT blindly retry". This asserts BOTH directions over the EXACT
/// `mark_resolved` message the Ok arm emits, pinning the classification pivot
/// the fix turns on. (The full live two-actor dual-commit + journal-fault
/// pipeline needed to drive `run_saga_fsm`'s Ok arm end-to-end is the same
/// prohibitive infra that made the `Err`-arm regression test infeasible; the
/// durable journal self-heals via `recover_committing_entry` on next open,
/// for which dedicated recovery tests already exist.)
#[test]
fn lift_run_saga_error_mark_resolved_failure_is_needs_repair_not_aborted() {
    let mark_resolved_msg = "saga journal mark_resolved: io: disk full".to_owned();

    // The exact pre-fix path: `needs_repair == false` over the
    // `mark_resolved` journal-I/O error lifts to the DANGEROUS `Aborted`
    // (the false "neither committed" terminal that would invite a
    // double-charging retry). This documents the bug the fix closes.
    let aborted = Supervisor::lift_run_saga_error(
        SagaId("saga-mark-resolved-bug".to_owned()),
        RunSagaError {
            error: ContextError::InvalidState(mark_resolved_msg.clone()),
            needs_repair: false,
            saga_code: None,
        },
    );
    assert!(
        matches!(
            aborted,
            SagaError::Aborted {
                reason: SagaAbortReason::Rejected,
                code: 13067,
                ..
            }
        ),
        "without the flag, a mark_resolved failure would mis-classify a fully-committed saga \
             as a clean Aborted (the double-charge hazard the fix closes)"
    );

    // The post-fix path: the Ok arm sets `reached_needs_repair = true` before
    // returning the SAME error, so it lifts to `NeedsRepair` carrying the
    // saga id — never a retry-inviting `Aborted`.
    let saga_id = SagaId("saga-mark-resolved-fixed".to_owned());
    let repaired = Supervisor::lift_run_saga_error(
        saga_id.clone(),
        RunSagaError {
            error: ContextError::InvalidState(mark_resolved_msg),
            needs_repair: true,
            saga_code: None,
        },
    );
    match repaired {
        SagaError::NeedsRepair { saga_id: id, .. } => assert_eq!(id, saga_id),
        other => panic!(
            "a committed saga whose mark_resolved(Committed) failed MUST lift to NeedsRepair \
                 (carrying the saga_id), never Aborted; got {other:?}"
        ),
    }
}

/// The token-bucket hard rate limit (`reserve_outlet_economy` on the saga's
/// Prepare-A path) returns `ContextError::RateLimited { retry_after_ms:
/// None, .. }` — it has no precise refill instant. Lifting it MUST propagate
/// the `None` through to `SagaAbortReason::RateLimited`, never coerce it to
/// `Some(0)`: a `0` back-off reads as "retry immediately" and re-trips the
/// same hard limit, defeating the structured back-off.
#[test]
fn lift_run_saga_error_propagates_token_bucket_none_backoff() {
    let lifted = Supervisor::lift_run_saga_error(
        SagaId("saga-token-bucket".to_owned()),
        RunSagaError {
            error: ContextError::RateLimited {
                resource: "outlet_call".to_owned(),
                message: "SCP-ECON-12090: rate limit exceeded on outlet_call: hard limit"
                    .to_owned(),
                retry_after_ms: None,
            },
            needs_repair: false,
            // Token-bucket ECON hard limit is CODELESS at the saga layer —
            // it stays on the `Err(ContextError)` channel and lifts to 13067
            // (reason RateLimited via the variant; the §6.2.0.2 sliding-
            // window saga rejects, by contrast, carry Some(130xx)).
            saga_code: None,
        },
    );
    assert!(
        matches!(
            lifted,
            SagaError::Aborted {
                reason: SagaAbortReason::RateLimited {
                    retry_after_ms: None
                },
                ..
            }
        ),
        "token-bucket hard-limit abort must propagate retry_after_ms: None, never coerce to Some(0)"
    );
}

/// A Prepare-phase `ContextError::ActorBusy` — a TRANSIENT unavailable
/// participant actor (a closed/terminated inbox or a dropped reply channel;
/// NEITHER side committed, since the Prepare-phase reservation is released or
/// reconciled on every terminal path) — MUST lift to the dedicated retryable
/// `SagaAbortReason::ParticipantUnavailable` terminal carrying the new code
/// `13068`, NOT the permanent `Rejected` reason and NOT the generic `13067`
/// abort fallback.
///
/// WITHOUT the structural `ActorBusy` arm, this transient unavailability
/// falls through to `_ => Rejected` + `saga_code.unwrap_or(13067)` —
/// surfacing a retryable participant-unavailable failure as a PERMANENT
/// policy rejection with no back-off hint, so a contract-honoring caller
/// would treat a transient condition as terminal. This pins the exact pre-fix
/// mutation: `reason: Rejected` and `code: 13067`.
#[test]
fn lift_run_saga_error_participant_unavailable_is_retryable_not_rejected() {
    let lifted = Supervisor::lift_run_saga_error(
        SagaId("saga-participant-unavailable".to_owned()),
        RunSagaError {
            error: ContextError::ActorBusy("mailbox full for 30 seconds".to_owned()),
            needs_repair: false,
            saga_code: None,
        },
    );

    // The reason is the retryable ParticipantUnavailable (carrying a
    // conservative None back-off), with the dedicated code 13068.
    assert!(
        matches!(
            &lifted,
            SagaError::Aborted {
                reason: SagaAbortReason::ParticipantUnavailable,
                code: 13068,
                ..
            }
        ),
        "a Prepare-phase ActorBusy must lift to Aborted/ParticipantUnavailable/13068, got {lifted:?}"
    );

    // EXPLICITLY pin the pre-fix mutation: it is NEITHER a permanent
    // `Rejected` NOR the generic `13067` fallback code.
    match &lifted {
        SagaError::Aborted { reason, code, .. } => {
            assert_ne!(
                *reason,
                SagaAbortReason::Rejected,
                "a transient unavailable participant actor must NOT be the permanent Rejected reason"
            );
            assert_ne!(
                *code, 13067,
                "a transient unavailable participant actor must carry the dedicated 13068, not \
                     the generic 13067 abort fallback"
            );
        }
        other => panic!("expected Aborted, got {other:?}"),
    }

    // The terminal renders its canonical SCP-SAGA-13068 code in Display so a
    // flattened log line still grep-disambiguates.
    assert!(
        lifted.to_string().contains("SCP-SAGA-13068"),
        "Display must carry the canonical SCP-SAGA-13068 code, got {lifted}"
    );
}

/// SAFETY-CRITICAL ORDERING: the `needs_repair` short-circuit in
/// [`Supervisor::lift_run_saga_error`] runs BEFORE the `ActorBusy` reason
/// arm, so a COMMIT-phase `ActorBusy` — which exhausts the commit-retry
/// budget and sets `needs_repair` — lifts to [`SagaError::NeedsRepair`]
/// (operator-repair, possible divergence), NOT the retryable
/// `Aborted/ParticipantUnavailable` abort. Mislabeling a commit-phase
/// `ActorBusy` as a clean retryable abort would tell the caller "neither side
/// committed, just retry" when the saga may have PARTIALLY committed — a
/// silent-divergence hazard. This pins that the `needs_repair` branch wins.
#[test]
fn lift_run_saga_error_actor_busy_with_needs_repair_is_needs_repair_not_aborted() {
    let saga_id = SagaId("saga-commit-phase-actor-busy".to_owned());
    let lifted = Supervisor::lift_run_saga_error(
        saga_id.clone(),
        RunSagaError {
            error: ContextError::ActorBusy(
                "commit-phase send to participant failed after retries".to_owned(),
            ),
            needs_repair: true,
            saga_code: None,
        },
    );

    // A commit-phase ActorBusy (needs_repair == true) MUST be NeedsRepair,
    // carrying the minted operator-repair handle.
    match &lifted {
        SagaError::NeedsRepair { saga_id: id, .. } => assert_eq!(*id, saga_id),
        other => panic!("expected NeedsRepair, got {other:?}"),
    }

    // EXPLICITLY rule out the retryable-abort mis-classification: the
    // `needs_repair` short-circuit must win over the ActorBusy reason arm.
    assert!(
        !matches!(
            &lifted,
            SagaError::Aborted {
                reason: SagaAbortReason::ParticipantUnavailable,
                ..
            }
        ),
        "a commit-phase ActorBusy must NOT be mislabeled a retryable \
             Aborted/ParticipantUnavailable, got {lifted:?}"
    );
}

/// The typed `SagaError` variants render their canonical `SCP-SAGA-*` code
/// in `Display`, so a flattened log line still `grep`-disambiguates the
/// terminal — `NeedsRepair` ⇒ `13065`, `Busy` ⇒ `13066`, `Aborted` ⇒ the
/// inner reject's code.
#[test]
fn saga_error_display_carries_canonical_codes() {
    let needs_repair = SagaError::NeedsRepair {
        saga_id: SagaId("saga-x".to_owned()),
        message: "diverged".to_owned(),
    };
    assert!(needs_repair.to_string().contains("SCP-SAGA-13065"));

    let busy = SagaError::Busy {
        contended_context: "ctx-1".to_owned(),
        message: "overlaps in-flight saga".to_owned(),
    };
    assert!(busy.to_string().contains("SCP-SAGA-13066"));

    let aborted = SagaError::Aborted {
        reason: SagaAbortReason::Rejected,
        code: 13013,
        message: "confused-deputy".to_owned(),
    };
    assert!(aborted.to_string().contains("SCP-SAGA-13013"));
}

/// A target custody that never answers fails each Commit attempt with
/// `SCP-CRYPTO-4062` from `CommandSigner::sign_bounded_ed25519`, never with the phase's
/// `TransportTimeout`: the Commit budget is built from the executor budget
/// plus the signing turn's budget, so the sign budget always fires first.
#[tokio::test(start_paused = true)]
async fn xctx_saga_stalled_target_custody_fails_commit_with_custody_timeout() {
    use crate::context::actor::signer::{SIGN_TIMEOUT, custody_timed_out};
    use scp_crypto::{DynScpSigner, SigAlg, SignFuture};

    /// A signer whose sign never completes, standing in for an
    /// unanswered biometric prompt.
    struct StalledSigner(Vec<u8>);

    impl DynScpSigner for StalledSigner {
        fn algorithm(&self) -> SigAlg {
            SigAlg::Ed25519
        }

        fn public_key(&self) -> Vec<u8> {
            self.0.clone()
        }

        fn sign_boxed<'a>(&'a self, _digest: &'a [u8; 32]) -> SignFuture<'a> {
            Box::pin(std::future::pending())
        }
    }

    let creator_did = "did:dht:z6MkXctxStallCreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let supervisor = xctx_supervisor(creator_did.clone(), creator_key);
    let caller_did = "did:dht:z6MkXctxStallCaller";

    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    let target_public = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
        .verifying_key()
        .to_bytes()
        .to_vec();
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let executor =
        |_input: serde_json::Value| async move { Ok(serde_json::json!({ "result": 3 })) };

    let now_ms = supervisor.clock_ref().expect("clock").now_millis();
    let started = tokio::time::Instant::now();
    let err = supervisor
        .start_cross_context_outlet_invocation_saga(
            CrossContextOutletInvocationRequest {
                caller_context_id: XCTX_CALLER,
                target_context_id: XCTX_TARGET,
                caller_did: DID(caller_did.to_owned()),
                outlet_registration_id: XCTX_OUTLET.to_owned(),
                ucan_proof_id: None,
                input: serde_json::json!({ "a": 1, "b": 2 }),
                asserted_chain_depth: 1,
                asserted_nonce: [0x47u8; 16],
                asserted_timestamp_ms: now_ms,
            },
            SagaSigners {
                target: CommandSigner::new(Arc::new(StalledSigner(target_public))),
                caller: CommandSigner::local_ed25519(caller_signing),
            },
            executor,
        )
        .await
        .expect_err("a stalled target custody fails the saga");

    let SagaError::NeedsRepair { message, .. } = err else {
        panic!("a failed Commit lifts to NeedsRepair, got {err:?}");
    };
    // The public NeedsRepair carries the last Commit attempt's error as
    // text; it is the typed `CommandSigner::sign_bounded_ed25519` timeout (`SCP-CRYPTO-4062` at
    // the bridges), not the phase's `TransportTimeout`.
    let expected = custody_timed_out("sign");
    assert_eq!(message, expected.to_string());
    assert!(started.elapsed() >= SIGN_TIMEOUT);
}

/// Replay: after a saga commits, re-driving Commit-B for the SAME `SagaId`
/// (the crash-recovery replay path) re-emits the STORED output + receipt
/// WITHOUT re-invoking the outlet. We run a full saga, then directly send a
/// second `CommitBReserve` for that saga id to the target actor and assert
/// it returns `AlreadyCommitted` with the same output — the executor call
/// counter stays at 1.
#[tokio::test]
async fn xctx_saga_commit_replay_reemits_without_reinvoke() {
    use crate::context::actor::commands::{CommitBReserveOutcome, SagaPhaseMessage};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let creator_did = "did:dht:z6MkXctxReplayCreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let supervisor = xctx_supervisor(creator_did.clone(), creator_key);
    let caller_did = "did:dht:z6MkXctxReplayCaller";

    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    // The caller's Active Signing Key (caller-supplied, ADR-049) — used to
    // sign the caller-side divergence marker on a NeedsRepair.
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_exec = Arc::clone(&calls);
    let executor = move |_input: serde_json::Value| {
        let calls = Arc::clone(&calls_for_exec);
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::json!({ "result": 3 }))
        }
    };

    let now_ms = supervisor.clock_ref().expect("clock").now_millis();
    let output = supervisor
        .start_cross_context_outlet_invocation_saga(
            CrossContextOutletInvocationRequest {
                caller_context_id: XCTX_CALLER,
                target_context_id: XCTX_TARGET,
                caller_did: DID(caller_did.to_owned()),
                outlet_registration_id: XCTX_OUTLET.to_owned(),
                ucan_proof_id: None,
                input: serde_json::json!({ "a": 1, "b": 2 }),
                asserted_chain_depth: 1,
                asserted_nonce: [0x46u8; 16],
                asserted_timestamp_ms: now_ms,
            },
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            executor,
        )
        .await
        .expect("saga commits");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "outlet ran once on first commit"
    );

    // Recover the committed SagaId from the journal (the only unresolved
    // set is empty after Committed, so use the durable receipt's output to
    // compare). We need the SagaId — re-derive it by replaying Commit-B
    // reserve against the target for the committed saga.
    //
    // The supervisor minted a fresh SagaId internally; the durable capture
    // is keyed by it. The receipt carries the SagaId-stable
    // `outlet_invoked_event_id` (`OutletInvoked:<saga_id>`), so recover the
    // saga id from it.
    let receipt: scp_protocol::context::outlets::cross_context_saga::CrossContextOutletReceipt =
        serde_json::from_slice(&output.receipt.expect("receipt")).expect("decode");
    let saga_id_str = receipt
        .outlet_invoked_event_id
        .strip_prefix("OutletInvoked:")
        .expect("event id carries the saga id")
        .to_owned();
    let saga_id = crate::context::supervisor::saga_journal::SagaId(saga_id_str);

    // Re-drive Commit-B reserve for the SAME saga id (the replay path).
    let target = supervisor
        .lookup(&hex::encode(XCTX_TARGET))
        .expect("target actor co-resident");
    let reserve = target
        .send(move |reply| {
            ContextCommand::SagaPhase(SagaPhaseMessage::CommitBReserve { saga_id, reply })
        })
        .await
        .expect("replay reserve");

    assert!(
        matches!(reserve, CommitBReserveOutcome::AlreadyCommitted { .. }),
        "a committed saga's replay must be AlreadyCommitted, not ReadyToExecute, got {reserve:?}"
    );
    if let CommitBReserveOutcome::AlreadyCommitted { output_bytes, .. } = reserve {
        let v: serde_json::Value =
            serde_json::from_slice(&output_bytes).expect("decode replay output");
        assert_eq!(
            v,
            serde_json::json!({ "result": 3 }),
            "replay re-emits the stored output"
        );
    }

    // The executor was NEVER re-invoked by the replay.
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "replay MUST NOT re-invoke the outlet"
    );
}

// -----------------------------------------------------------------
// §6.2.4 slice 6 — NeedsRepair dual divergence marker +
// §17.16.4 crash-recovery replay arms.
// -----------------------------------------------------------------

/// Build a `CrossContextSagaCtx` with the TARGET marked as committed
/// (`committed_b_outlet_invoked_event_id = Some(event_id)`) so
/// `emit_divergence_markers` records `committed_side = Target`. The executor
/// is a never-called no-op (divergence emission never runs the outlet).
fn divergence_ctx<'a>(
    nonce: [u8; 16],
    outlet_invoked_event_id: String,
    target_signing: &ed25519_dalek::SigningKey,
    caller_signing: &ed25519_dalek::SigningKey,
    caller_did: &str,
) -> CrossContextSagaCtx<'a> {
    CrossContextSagaCtx {
        caller_context_id: XCTX_CALLER,
        target_context_id: XCTX_TARGET,
        caller_did: DID(caller_did.to_owned()),
        outlet_registration_id: XCTX_OUTLET.to_owned(),
        ucan_proof_id: None,
        input: serde_json::json!({ "a": 1, "b": 2 }),
        asserted_chain_depth: 2,
        asserted_nonce: nonce,
        asserted_timestamp_ms: 1_700_000_000,
        caller_source_role: None,
        target_signer: CommandSigner::local_ed25519(target_signing.clone()),
        caller_signer: CommandSigner::local_ed25519(caller_signing.clone()),
        executor: Some(Box::new(|_v: serde_json::Value| {
            Box::pin(async move { Ok(serde_json::json!({})) }) as _
        })),
        executor_output: None,
        prepared_a: None,
        // A committed Commit-B (`committed_b_outlet_invoked_event_id` is
        // `Some`) always implies Prepare-B ran, so `prepared_b` is `Some` on
        // the real FSM path. The marker draws its convergent nonce/timestamp
        // from B's VERIFIED staged provenance here (never the caller-asserted
        // values), so the staged copies mirror the asserted ones.
        prepared_b: Some(crate::context::actor::commands::PreparedBFields {
            recorded_timestamp_ms: 1_700_000_000,
            recorded_nonce: nonce,
            recorded_chain_depth: 3,
        }),
        committed: None,
        committed_b_outlet_invoked_event_id: Some(outlet_invoked_event_id),
        reached_needs_repair: false,
    }
}

/// Security regression (black-hat): `divergence_marker_plan` MUST refuse to
/// mint a marker plan when `prepared_b` is absent — otherwise a future
/// recovery path could substitute the caller-ASSERTED (untrusted) nonce /
/// timestamp into a convergent durable marker leaf. With no verified
/// Commit-B provenance there is no honest convergent value, so the plan is
/// `None` (no marker emitted).
#[test]
fn divergence_marker_plan_refuses_without_verified_commit_b() {
    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let mut ctx = divergence_ctx(
        [0x42u8; 16],
        "OutletInvoked:test".to_owned(),
        &target_signing,
        &caller_signing,
        "did:dht:z6MkXctxDivCaller",
    );
    // Real path: committed Commit-B ⇒ prepared_b is Some ⇒ a plan exists.
    assert!(Supervisor::divergence_marker_plan(&ctx).is_some());
    // Synthetic unreachable case: committed event id present but no verified
    // Prepare-B provenance ⇒ refuse to produce a plan (no untrusted fallback).
    ctx.prepared_b = None;
    assert!(Supervisor::divergence_marker_plan(&ctx).is_none());
}

/// NeedsRepair dual divergence marker (spec §6.2.4 "Dual event-log
/// recording"): when the TARGET committed but the saga diverged, BOTH the
/// target and caller actors emit a signed `CrossContextDivergenceMarker`
/// into their OWN event log. The markers record `committed_side = Target`,
/// the saga id, the nonce, and the committed event id, and each verifies
/// under its own side's Active Signing Key. Both sides reachable ⇒ NO
/// supervisor-level repair record.
#[tokio::test]
async fn xctx_needs_repair_emits_dual_signed_divergence_markers() {
    use scp_protocol::context::outlets::cross_context_saga::{
        CommittedSide, CrossContextDivergenceMarker,
    };

    let creator_did = "did:dht:z6MkXctxDivCreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let event_log = RecordingEventLog::default();
    let supervisor = xctx_supervisor_with_event_log(
        creator_did.clone(),
        creator_key,
        Box::new(event_log.clone()),
    );
    let caller_did = "did:dht:z6MkXctxDivCaller";
    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let nonce = [0x42u8; 16];
    let saga_id = crate::context::supervisor::saga_journal::SagaId::new();
    let committed_event_id = format!("OutletInvoked:{}", saga_id.0);

    let ctx = divergence_ctx(
        nonce,
        committed_event_id.clone(),
        &target_signing,
        &caller_signing,
        caller_did,
    );
    let plan = Supervisor::divergence_marker_plan(&ctx).expect("target committed ⇒ plan");
    Box::pin(supervisor.emit_divergence_markers(&saga_id, plan)).await;

    // Both sides reachable ⇒ no supervisor repair fallback.
    assert!(
        supervisor.saga_repair_records_for(&saga_id).is_empty(),
        "both actors reachable ⇒ NO supervisor-level repair record"
    );

    let events = event_log
        .events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    // TARGET log carries a marker signed by the TARGET key.
    let (_, _, _, target_payload, _) = events
        .iter()
        .find(|(id, event_type, _, _, _)| {
            *id == XCTX_TARGET
                && *event_type == scp_event_log::EventType::CrossContextDivergenceMarker
        })
        .expect("target log must carry a divergence marker");
    let target_marker: CrossContextDivergenceMarker =
        serde_json::from_slice(target_payload).expect("decode target marker");
    assert_eq!(target_marker.committed_side, CommittedSide::Target);
    assert_eq!(target_marker.saga_id, saga_id.0);
    assert_eq!(target_marker.nonce, nonce);
    assert_eq!(target_marker.committed_event_id, committed_event_id);
    assert!(
        target_marker
            .verify(&target_signing.verifying_key())
            .is_ok(),
        "target marker must verify under the target key"
    );

    // CALLER log carries a marker signed by the CALLER key.
    let (_, _, _, caller_payload, _) = events
        .iter()
        .find(|(id, event_type, _, _, _)| {
            *id == XCTX_CALLER
                && *event_type == scp_event_log::EventType::CrossContextDivergenceMarker
        })
        .expect("caller log must carry a divergence marker");
    let caller_marker: CrossContextDivergenceMarker =
        serde_json::from_slice(caller_payload).expect("decode caller marker");
    assert_eq!(caller_marker.committed_side, CommittedSide::Target);
    assert_eq!(caller_marker.saga_id, saga_id.0);
    assert_eq!(caller_marker.nonce, nonce);
    assert_eq!(caller_marker.committed_event_id, committed_event_id);
    assert!(
        caller_marker
            .verify(&caller_signing.verifying_key())
            .is_ok(),
        "caller marker must verify under the caller key"
    );
    // The marker is NOT cross-verifiable: each side signs with its own key.
    assert!(
        caller_marker
            .verify(&target_signing.verifying_key())
            .is_err(),
        "the caller marker must NOT verify under the target key"
    );
}

/// NeedsRepair with an UNREACHABLE side: when the caller actor is gone, its
/// signed marker cannot be appended into its (absent) log, so the divergence
/// is recorded into the supervisor-level repair journal instead (spec
/// §6.2.4 — "or a supervisor-level repair journal if one side is
/// unreachable"). The reachable target side still records into its own log.
#[tokio::test]
async fn xctx_needs_repair_unreachable_side_records_supervisor_repair() {
    let creator_did = "did:dht:z6MkXctxRepairCreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let event_log = RecordingEventLog::default();
    let supervisor = xctx_supervisor_with_event_log(
        creator_did.clone(),
        creator_key,
        Box::new(event_log.clone()),
    );
    let caller_did = "did:dht:z6MkXctxRepairCaller";
    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    // Despawn the CALLER actor so it is unreachable at divergence time.
    assert!(
        supervisor.despawn_actor(&hex::encode(XCTX_CALLER)).await,
        "despawn caller actor"
    );

    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let nonce = [0x55u8; 16];
    let saga_id = crate::context::supervisor::saga_journal::SagaId::new();
    let committed_event_id = format!("OutletInvoked:{}", saga_id.0);

    let ctx = divergence_ctx(
        nonce,
        committed_event_id.clone(),
        &target_signing,
        &caller_signing,
        caller_did,
    );
    let plan = Supervisor::divergence_marker_plan(&ctx).expect("target committed ⇒ plan");
    Box::pin(supervisor.emit_divergence_markers(&saga_id, plan)).await;

    // The unreachable CALLER side is recorded in the supervisor repair journal.
    let repair = supervisor.saga_repair_records_for(&saga_id);
    assert_eq!(
        repair.len(),
        1,
        "exactly one supervisor repair record for the unreachable caller side, got {repair:?}"
    );
    assert_eq!(repair[0].unreachable_context_hex, hex::encode(XCTX_CALLER));
    assert_eq!(repair[0].committed_event_id, committed_event_id);
    assert_eq!(repair[0].nonce, nonce);
    assert_eq!(
        repair[0].committed_side,
        scp_protocol::context::outlets::cross_context_saga::CommittedSide::Target
    );

    // The reachable TARGET side still recorded into its own log.
    let events = event_log
        .events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert!(
        events.iter().any(|(id, event_type, _, _, _)| {
            *id == XCTX_TARGET
                && *event_type == scp_event_log::EventType::CrossContextDivergenceMarker
        }),
        "the reachable target side must still record its marker into its own log"
    );
}

/// FIX 2 (durable repair journal): a supervisor-level divergence repair
/// record (recorded when a `NeedsRepair` side is unreachable) MUST survive a
/// supervisor restart — the spec's "durably auditable" guarantee for the
/// unreachable leg. `record_supervisor_repair` durably appends the record to
/// the saga journal; a fresh supervisor over the SAME storage rehydrates it
/// from the journal via `replay_unresolved_sagas`. Without the durable write
/// the in-memory DashMap would be empty after restart and the divergence
/// account lost.
#[tokio::test]
async fn supervisor_repair_record_survives_restart() {
    use crate::context::supervisor::saga_journal::{ProtocolRepositorySagaJournal, SagaId};
    use scp_protocol::context::outlets::cross_context_saga::CommittedSide;

    // Shared durable storage so a second supervisor sees the first's writes.
    let storage = Arc::new(InMemoryStorage::new());
    let journal: Arc<dyn SagaJournal> =
        Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let persistence: Arc<dyn ContextPersistence> =
        Arc::new(crate::context::persistence::NoOpContextPersistence);
    let supervisor = Supervisor::new(
        persistence,
        journal,
        SupervisorConfig::default(),
        crate::domain_handlers(),
    );

    let saga_id = SagaId("saga-durable-repair".to_owned());
    let unreachable_hex = hex::encode([0x9Au8; 32]);
    let committed_event_id = format!("OutletInvoked:{}", saga_id.0);
    let nonce = [0x9Bu8; 16];

    // Record the unreachable-side divergence (durably journals it).
    supervisor
        .record_supervisor_repair(
            &saga_id,
            &unreachable_hex,
            CommittedSide::Target,
            &committed_event_id,
            nonce,
        )
        .await;

    // The in-memory read cache holds it on the live supervisor.
    let live = supervisor.saga_repair_records_for(&saga_id);
    assert_eq!(live.len(), 1, "live supervisor caches the repair record");

    // The journal durably retains a NeedsRepair entry whose evidence decodes
    // to the record set — the durable half of the two-tier write.
    let unresolved = supervisor
        .saga_journal
        .load_unresolved()
        .await
        .expect("load_unresolved");
    let entry = unresolved
        .iter()
        .find(|e| e.saga_id == saga_id)
        .expect("a NeedsRepair entry for the saga is durably retained");
    assert_eq!(entry.state, SagaState::NeedsRepair);
    assert!(
        !entry.evidence.is_empty(),
        "the durable repair entry carries non-empty repair-record evidence"
    );
    let decoded = decode_repair_records_evidence(&entry.evidence).expect("evidence decodes");
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].unreachable_context_hex, unreachable_hex);
    assert_eq!(decoded[0].committed_event_id, committed_event_id);
    assert_eq!(decoded[0].nonce, nonce);
    assert_eq!(decoded[0].committed_side, CommittedSide::Target);

    // RESTART: a fresh supervisor over the SAME storage starts with an EMPTY
    // in-memory cache, then rehydrates it from the durable journal.
    let journal2: Arc<dyn SagaJournal> =
        Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let persistence2: Arc<dyn ContextPersistence> =
        Arc::new(crate::context::persistence::NoOpContextPersistence);
    let restarted = Supervisor::new(
        persistence2,
        journal2,
        SupervisorConfig::default(),
        crate::domain_handlers(),
    );
    assert!(
        restarted.saga_repair_records_for(&saga_id).is_empty(),
        "a fresh supervisor starts with an empty in-memory repair cache"
    );
    restarted
        .replay_unresolved_sagas(&RestoredContexts::new(Vec::new()))
        .await
        .expect("replay rehydrates");
    let rehydrated = restarted.saga_repair_records_for(&saga_id);
    assert_eq!(
        rehydrated.len(),
        1,
        "the repair record MUST be rehydrated from the durable journal on restart"
    );
    assert_eq!(rehydrated[0].unreachable_context_hex, unreachable_hex);
    assert_eq!(rehydrated[0].committed_event_id, committed_event_id);
    assert_eq!(rehydrated[0].nonce, nonce);
    assert_eq!(rehydrated[0].committed_side, CommittedSide::Target);
}

/// NeedsRepair concurrency-slot release: a `TestForceNeedsRepair` saga
/// (commit always fails → NeedsRepair) RELEASES the participant-context-set
/// reservation, so an OVERLAPPING saga over the same context then reserves
/// successfully (no `ActorBusy`). Confirms the concurrency slot is released
/// while the (separate) escrow path is unaffected (spec §6.2.4 "`NeedsRepair`
/// reservation semantics" — the two release differently).
#[tokio::test]
async fn xctx_needs_repair_releases_concurrency_slot() {
    let supervisor = Arc::new(Supervisor::for_query_shim(crate::domain_handlers()));
    let ctx_id = [0x77u8; 32];

    // Drive a saga to NeedsRepair (commit-retry exhaustion).
    let err = supervisor
        .start_saga(SagaInput::TestForceNeedsRepair { context_id: ctx_id })
        .await
        .expect_err("commit-retry-exhausted saga returns NeedsRepair");
    assert!(
        !matches!(err, ContextError::ActorBusy(_)),
        "a NeedsRepair terminal must not surface as ActorBusy, got {err:?}"
    );

    // The NeedsRepair terminal RELEASED the slot: a follow-up saga over the
    // SAME (overlapping) context reserves successfully (it does not reject
    // with SagaBusy).
    let reservation = supervisor
        .test_reserve_saga_context_set(&SagaInput::TestForceNeedsRepair { context_id: ctx_id });
    assert!(
        reservation.is_ok(),
        "NeedsRepair must release the context slot so an overlapping saga reserves, got {:?}",
        reservation.err()
    );
}

/// §17.16.4 participant-set reconstruction (option (a)): the journaled
/// `CrossContextOutletInvocationPrepared` evidence carries BOTH context ids, so
/// a crash-recovery replay reconstructs the FULL `{caller, target}`
/// participant set — NOT the caller-only journal triple. Proves the
/// reservation-gap the field doc flags is closed.
#[test]
fn xctx_replay_reconstructs_full_participant_set() {
    use crate::context::supervisor::saga_journal::{JournalEntry, SagaId, SagaState};
    use crate::context::supervisor::saga_prepared_state::CrossContextOutletInvocationPrepared;

    let prepared = CrossContextOutletInvocationPrepared {
        caller_context_id: XCTX_CALLER,
        target_context_id: XCTX_TARGET,
        caller_did: DID("did:dht:z6MkReconCaller".to_owned()),
        outlet_registration_id: XCTX_OUTLET.to_owned(),
        ucan_proof_id: String::new(),
        recorded_timestamp_ms: 1_700_000_111,
        recorded_nonce: [0x66u8; 16],
        recorded_chain_depth: 3,
    };
    let evidence = prepared.to_evidence_bytes().expect("encode evidence");
    let entry = JournalEntry {
        saga_id: SagaId::new(),
        state: SagaState::Committing,
        // The journal provenance triple is caller-ONLY (no target).
        participants: vec![
            hex::encode(XCTX_CALLER),
            "did:dht:z6MkReconCaller".to_owned(),
            XCTX_OUTLET.to_owned(),
        ],
        evidence: Zeroizing::new(evidence),
        timestamp_ms: 1_700_000_111,
        seq_per_saga: 3,
    };

    let recon =
        Supervisor::reconstruct_xctx_prepared(&entry).expect("cross-context evidence reconstructs");
    // The FULL {caller, target} set is recoverable from the evidence even
    // though `participants` omits the target.
    assert_eq!(recon.caller_context_id, XCTX_CALLER);
    assert_eq!(recon.target_context_id, XCTX_TARGET);
    assert_eq!(recon.recorded_chain_depth, 3);
    assert_eq!(recon.recorded_nonce, [0x66u8; 16]);
    assert!(
        !entry.participants.contains(&hex::encode(XCTX_TARGET)),
        "the journal participant triple deliberately omits the target — the evidence closes \
             the gap"
    );
}

/// Build a `with_providers_and_journal` supervisor over a SHARED durable
/// saga journal + a `MapPersistence` pre-seeded with the given `present`
/// context hexes. No xctx actors are spawned, so a caller-reversal re-drive
/// `lookup`-misses (the caller is non-resident) and yields
/// `ReversalOutstanding` — exactly the crash-recovery sweep ordering the
/// §17.16.4 invariant reasons about (`replay_unresolved_sagas` running before
/// the caller context is restored). The returned journal handle lets the test
/// assert terminal-vs-non-terminal via `load_unresolved`.
fn xctx_recovery_supervisor_with_present_contexts(
    present: &[String],
) -> (Arc<Supervisor>, Arc<dyn SagaJournal>) {
    let contexts: Arc<DashMap<String, crate::context::state::ContextSnapshot>> =
        Arc::new(DashMap::new());
    for hex_id in present {
        contexts.insert(
            hex_id.clone(),
            import_test_snapshot(hex_id, "did:dht:z6MkRecoveryCreator"),
        );
    }
    let persistence: Box<dyn ContextPersistence> = Box::new(MapPersistence {
        contexts: Arc::clone(&contexts),
    });
    xctx_recovery_supervisor_with_persistence(persistence)
}

/// A `ContextPersistence` whose `load_context` ALWAYS returns `Err` — models a
/// TRANSIENT storage failure (the backend is reachable for some ops but the
/// existence read errored). The §17.16.4 reaper MUST treat this conservatively
/// as "context still present" (NOT deleted) so a transient read failure cannot
/// be mistaken for a permanent deletion and mis-reap a recoverable caller —
/// see [`Supervisor::caller_context_deleted_from_persistence`]'s `Err` arm.
struct ErringLoadPersistence;
#[async_trait::async_trait]
impl ContextPersistence for ErringLoadPersistence {
    async fn persist_context(
        &self,
        _: &str,
        _: &crate::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    async fn load_context(
        &self,
        _: &str,
    ) -> Result<
        Option<crate::context::state::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Err("synthetic transient storage failure on load_context".into())
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

/// Build a `with_providers_and_journal` recovery supervisor over a SHARED
/// durable saga journal + the GIVEN persistence backend. No xctx actors are
/// spawned, so a caller-reversal re-drive `lookup`-misses (the caller is
/// non-resident) and yields `ReversalOutstanding` — exactly the crash-recovery
/// sweep ordering the §17.16.4 invariant reasons about
/// (`replay_unresolved_sagas` running before the caller context is restored).
/// The persistence backend's `load_context` verdict (`Ok(None)` / `Ok(Some)` /
/// `Err`) then decides reap-vs-leave-non-terminal, which the returned journal
/// handle lets the test assert via `load_unresolved`.
fn xctx_recovery_supervisor_with_persistence(
    persistence: Box<dyn ContextPersistence>,
) -> (Arc<Supervisor>, Arc<dyn SagaJournal>) {
    use crate::context::supervisor::saga_journal::ProtocolRepositorySagaJournal;

    let storage = Arc::new(InMemoryStorage::new());
    let journal: Arc<dyn SagaJournal> =
        Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));

    let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
        "did:dht:z6MkRecoverySupervisor".to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
        Box::new(crate::context::builder::NotConfiguredTransportProvider);
    let key_resolver: KeyResolver = Arc::new(|_: &DID, _| None);
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            InMemoryStorage::new(),
        )),
    );
    let supervisor = Supervisor::with_providers_and_journal(
        crypto,
        transport,
        Box::new(TestEventLog),
        key_resolver,
        persistence,
        None,
        None,
        None,
        crate::context::supervisor::DurableProviders::for_test(Arc::clone(&journal), mls_storage),
        crate::crypto::wrapping::single_custody_source(Arc::new(
            scp_platform::testing::InMemoryKeyCustody::new(),
        )),
        crate::domain_handlers(),
    );
    (supervisor, journal)
}

/// Inject a `PreparingB` xctx journal entry whose PLAINTEXT participant
/// triple names the caller in `participants[0]` but whose EVIDENCE blob is
/// deliberately mangled (non-empty but unparseable), then drive
/// `replay_unresolved_sagas`. Returns whether the saga survived as a
/// non-terminal `PreparingB` entry (true) or was marked terminal (false).
async fn replay_corrupt_evidence_preparing_b(
    supervisor: &Arc<Supervisor>,
    journal: &Arc<dyn SagaJournal>,
    saga_id: &crate::context::supervisor::saga_journal::SagaId,
    caller_hex: &str,
) -> bool {
    use crate::context::supervisor::saga_journal::{JournalEntry, SagaState};

    // A real xctx PreparingB entry: `participants = [hex(caller), did, outlet]`
    // (length 3, 64-hex first element) but with corrupt/unparseable evidence
    // (NON-empty so `reconstruct_xctx_prepared` reaches the decode path and
    // fails there, rather than short-circuiting on the empty-evidence guard).
    let entry = JournalEntry {
        saga_id: saga_id.clone(),
        state: SagaState::PreparingB,
        participants: vec![
            caller_hex.to_owned(),
            "did:dht:z6MkCorruptEvidenceCaller".to_owned(),
            XCTX_OUTLET.to_owned(),
        ],
        evidence: Zeroizing::new(vec![0xFFu8, 0x00, 0x13, 0x37]),
        timestamp_ms: 1_700_000_222,
        seq_per_saga: 1,
    };
    journal
        .append(entry)
        .await
        .expect("append PreparingB entry");

    // Pre-condition: the corrupt evidence does NOT reconstruct, so the wave-15
    // `None` arm is exercised.
    let probe = journal
        .load_unresolved()
        .await
        .expect("load_unresolved")
        .into_iter()
        .find(|e| &e.saga_id == saga_id)
        .expect("PreparingB entry present pre-replay");
    assert!(
        Supervisor::reconstruct_xctx_prepared(&probe).is_none(),
        "the mangled evidence must NOT reconstruct (exercises the None arm)"
    );

    supervisor
        .replay_unresolved_sagas(&RestoredContexts::new(Vec::new()))
        .await
        .expect("replay");

    journal
        .load_unresolved()
        .await
        .expect("load_unresolved post-replay")
        .iter()
        .any(|e| &e.saga_id == saga_id && e.state == SagaState::PreparingB)
}

/// FIX 1 (bug-catcher LOW): a `PreparingB` cross-context entry whose EVIDENCE
/// is corrupt — but whose PLAINTEXT `participants[0]` still names a LIVE caller
/// context — must NOT be marked terminal-`Aborted` (which would falsely assert
/// "fully compensated" and STRAND the caller's durable deduction). The
/// crash-recovery sweep must instead reconcile the caller via the record-keyed
/// `redrive_caller_local_reversal`; with the caller non-resident (and PRESENT
/// in persistence — not deleted) the reversal is outstanding and the journal
/// stays NON-terminal for a later sweep.
///
/// PRE-FIX this stranded the caller: the `None` arm collapsed to
/// `SettledOrAbsent` → terminal-`Aborted`. POST-FIX it stays `PreparingB`.
#[tokio::test]
async fn xctx_corrupt_evidence_preparing_b_reconciles_caller_not_stranded() {
    use crate::context::supervisor::saga_journal::SagaId;

    let caller_hex = hex::encode(XCTX_CALLER);
    // Caller PRESENT in persistence (not-yet-restored, not deleted) so the
    // FIX-3 deleted-context reaping does NOT apply — the saga must stay
    // non-terminal purely on the outstanding-reversal invariant.
    let (supervisor, journal) =
        xctx_recovery_supervisor_with_present_contexts(std::slice::from_ref(&caller_hex));
    let saga_id = SagaId("saga-corrupt-evidence-live-caller".to_owned());

    let stayed_non_terminal =
        replay_corrupt_evidence_preparing_b(&supervisor, &journal, &saga_id, &caller_hex).await;

    assert!(
        stayed_non_terminal,
        "a corrupt-evidence PreparingB xctx entry naming a LIVE (present, non-resident) caller \
             must stay NON-terminal (caller reversal outstanding) — NOT be marked terminal-Aborted \
             and strand the caller deduction"
    );
}

/// FIX 3 (black-hat LOW): a `PreparingB` xctx entry whose caller context is
/// PERMANENTLY DELETED (ABSENT from durable persistence) must be REAPED
/// (marked terminal-`Aborted`) instead of looping forever non-terminal — its
/// `CallerReservationRecord` died with the context, so there is nothing to
/// reverse. Contrast with the present-but-not-restored case, which stays
/// non-terminal (the prior test).
#[tokio::test]
async fn xctx_corrupt_evidence_preparing_b_deleted_caller_is_reaped() {
    use crate::context::supervisor::saga_journal::SagaId;

    let caller_hex = hex::encode(XCTX_CALLER);
    // Caller ABSENT from persistence (deleted): `present` is empty.
    let (supervisor, journal) = xctx_recovery_supervisor_with_present_contexts(&[]);
    let saga_id = SagaId("saga-corrupt-evidence-deleted-caller".to_owned());

    let stayed_non_terminal =
        replay_corrupt_evidence_preparing_b(&supervisor, &journal, &saga_id, &caller_hex).await;

    assert!(
        !stayed_non_terminal,
        "a corrupt-evidence PreparingB xctx entry whose caller context is ABSENT from durable \
             persistence (permanently deleted) must be REAPED as terminal-Aborted — NOT left to \
             never-reap"
    );
}

/// FIX 3 over-restriction guard: a caller context that is PRESENT in durable
/// persistence (not-yet-restored, NOT deleted) must NOT be reaped — the
/// reversal is genuinely still outstanding and a later sweep (after respawn)
/// must re-drive it. This is the same shape as the FIX-1 test but asserted
/// against the deleted-context distinction specifically: present ⇒ keep
/// non-terminal, absent ⇒ reap.
#[tokio::test]
async fn xctx_corrupt_evidence_preparing_b_present_caller_not_reaped() {
    use crate::context::supervisor::saga_journal::SagaId;

    let caller_hex = hex::encode(XCTX_CALLER);
    let (supervisor, journal) =
        xctx_recovery_supervisor_with_present_contexts(std::slice::from_ref(&caller_hex));
    let saga_id = SagaId("saga-corrupt-evidence-present-caller".to_owned());

    let stayed_non_terminal =
        replay_corrupt_evidence_preparing_b(&supervisor, &journal, &saga_id, &caller_hex).await;

    assert!(
        stayed_non_terminal,
        "a present-but-not-restored caller context must NOT be reaped (its reversal is still \
             outstanding) — only an ABSENT (deleted) caller is reaped"
    );
}

/// FIX 3 conservative-on-error guard: a `PreparingB` xctx entry whose caller
/// context existence check ERRORS (`load_context` ⇒ `Err`, a TRANSIENT storage
/// failure) must NOT be reaped — a transient read failure must not be mistaken
/// for a permanent deletion. The reaper's `Err` arm
/// ([`Supervisor::caller_context_deleted_from_persistence`]) returns `false`
/// (treat as still present), so the saga is LEFT non-terminal for a later
/// sweep (after the storage recovers). Without this guard an `Err` mis-read as
/// "deleted" would reap a still-recoverable caller and silently OVER-CHARGE it
/// (the durable `CallerReservationRecord` would never be reversed). This test
/// FAILS if the `Err` arm is inverted to reap (e.g. `Err(_) => true`).
#[tokio::test]
async fn xctx_corrupt_evidence_preparing_b_load_error_not_reaped() {
    use crate::context::supervisor::saga_journal::SagaId;

    let caller_hex = hex::encode(XCTX_CALLER);
    // `load_context` ALWAYS errors → the existence check cannot confirm
    // deletion → conservative leave-non-terminal.
    let (supervisor, journal) =
        xctx_recovery_supervisor_with_persistence(Box::new(ErringLoadPersistence));
    let saga_id = SagaId("saga-corrupt-evidence-load-error-caller".to_owned());

    let stayed_non_terminal =
        replay_corrupt_evidence_preparing_b(&supervisor, &journal, &saga_id, &caller_hex).await;

    assert!(
        stayed_non_terminal,
        "a corrupt-evidence PreparingB xctx entry whose caller-context existence check ERRORS \
             (transient storage failure) must be LEFT non-terminal (conservative-on-error) — NOT \
             reaped, which would over-charge a still-recoverable caller"
    );
}

/// Direct unit pin of the §17.16.4 reaper predicate
/// [`Supervisor::caller_context_deleted_from_persistence`] across all three
/// `load_context` verdicts. The end-to-end recovery tests above exercise the
/// arm through the full sweep; this pins the predicate's CONTRACT at the
/// source so an inversion is caught fast:
///
/// - `Ok(None)` (snapshot key absent ⇒ PERMANENTLY deleted) ⇒ `true` (reap).
/// - `Err(_)` (TRANSIENT read failure ⇒ existence unknowable) ⇒ `false`
///   (conservative — leave non-terminal; a transient error must NEVER be
///   mistaken for deletion).
/// - `Ok(Some(_))` (snapshot present ⇒ not-yet-restored, not deleted) ⇒
///   `false` (do not reap a recoverable caller).
///
/// FAILS if the `Err` arm is inverted to reap (`Err(_) => true`) — the exact
/// over-charge regression §17.16.4's "err toward `Err`" rule forecloses.
#[tokio::test]
async fn caller_context_deleted_predicate_reaps_only_on_confirmed_absence() {
    let caller_hex = hex::encode(XCTX_CALLER);

    // Ok(None) — empty MapPersistence ⇒ load_context returns Ok(None) ⇒ reap.
    let (sup_absent, _journal) = xctx_recovery_supervisor_with_present_contexts(&[]);
    assert!(
        sup_absent
            .caller_context_deleted_from_persistence(&caller_hex)
            .await,
        "Ok(None) (permanently-deleted snapshot) MUST be reaped (true)"
    );

    // Err(_) — load_context always errors ⇒ conservative, do NOT reap.
    let (sup_err, _journal2) =
        xctx_recovery_supervisor_with_persistence(Box::new(ErringLoadPersistence));
    assert!(
        !sup_err
            .caller_context_deleted_from_persistence(&caller_hex)
            .await,
        "Err(_) (transient read failure) MUST be treated conservatively as still-present \
             (false) — never mistaken for deletion"
    );

    // Ok(Some(_)) — snapshot present (not-yet-restored) ⇒ do NOT reap.
    let (sup_present, _journal3) =
        xctx_recovery_supervisor_with_present_contexts(std::slice::from_ref(&caller_hex));
    assert!(
        !sup_present
            .caller_context_deleted_from_persistence(&caller_hex)
            .await,
        "Ok(Some(_)) (present-but-not-yet-restored) MUST NOT be reaped (false)"
    );
}

/// §17.16.4 Commit-in-progress replay re-emits the STORED output WITHOUT
/// re-invoking the outlet. We commit a real saga (executor runs once), then
/// reconstruct the prepared state from journaled evidence and re-drive the
/// Commit-in-progress recovery path; the target re-emits the stored output
/// via the idempotent `AlreadyCommitted`, and the executor counter stays 1.
#[tokio::test]
async fn xctx_replay_commit_in_progress_reemits_without_reinvoke() {
    use crate::context::supervisor::saga_journal::{JournalEntry, SagaId, SagaState};
    use crate::context::supervisor::saga_prepared_state::CrossContextOutletInvocationPrepared;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let creator_did = "did:dht:z6MkXctxReplay2Creator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let supervisor = xctx_supervisor(creator_did.clone(), creator_key);
    let caller_did = "did:dht:z6MkXctxReplay2Caller";
    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_exec = Arc::clone(&calls);
    let executor = move |_input: serde_json::Value| {
        let calls = Arc::clone(&calls_for_exec);
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::json!({ "result": 3 }))
        }
    };
    let now_ms = supervisor.clock_ref().expect("clock").now_millis();
    let nonce = [0x42u8; 16];
    let output = supervisor
        .start_cross_context_outlet_invocation_saga(
            CrossContextOutletInvocationRequest {
                caller_context_id: XCTX_CALLER,
                target_context_id: XCTX_TARGET,
                caller_did: DID(caller_did.to_owned()),
                outlet_registration_id: XCTX_OUTLET.to_owned(),
                ucan_proof_id: None,
                input: serde_json::json!({ "a": 1, "b": 2 }),
                asserted_chain_depth: 2,
                asserted_nonce: nonce,
                asserted_timestamp_ms: now_ms,
            },
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            executor,
        )
        .await
        .expect("saga commits");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "outlet ran once");

    // Recover the committed saga id from the receipt.
    let receipt: scp_protocol::context::outlets::cross_context_saga::CrossContextOutletReceipt =
        serde_json::from_slice(&output.receipt.expect("receipt")).expect("decode");
    let saga_id_str = receipt
        .outlet_invoked_event_id
        .strip_prefix("OutletInvoked:")
        .expect("event id carries saga id")
        .to_owned();
    let saga_id = SagaId(saga_id_str);

    // Build a Commit-in-progress journal entry whose evidence carries the
    // full {caller, target} prepared state, then run the recovery re-drive.
    let prepared = CrossContextOutletInvocationPrepared {
        caller_context_id: XCTX_CALLER,
        target_context_id: XCTX_TARGET,
        caller_did: DID(caller_did.to_owned()),
        outlet_registration_id: XCTX_OUTLET.to_owned(),
        ucan_proof_id: String::new(),
        recorded_timestamp_ms: now_ms,
        recorded_nonce: nonce,
        recorded_chain_depth: 3,
    };
    let entry = JournalEntry {
        saga_id: saga_id.clone(),
        state: SagaState::Committing,
        participants: vec![hex::encode(XCTX_CALLER)],
        evidence: Zeroizing::new(prepared.to_evidence_bytes().expect("encode")),
        timestamp_ms: now_ms,
        seq_per_saga: 3,
    };
    let recon = Supervisor::reconstruct_xctx_prepared(&entry).expect("reconstruct");
    Box::pin(supervisor.redrive_xctx_commit_in_progress(&saga_id, &recon)).await;

    // The re-drive re-emitted the stored output via AlreadyCommitted — the
    // outlet was NEVER re-invoked.
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "Commit-in-progress replay MUST NOT re-invoke the outlet"
    );
}

/// FIX 2 (§17.16.4): a Commit-in-progress recovery whose A-side
/// `xctx_committed_invocations` witness IS present resolves to `Committed`,
/// NOT a spurious `NeedsRepair`. We commit a real saga (both witnesses land),
/// then run the recovery re-drive and assert it returns `Committed` (the
/// A-side witness re-ack succeeded) — and the outlet never re-runs.
///
/// (The journal is the no-op test journal here, so the resolution is
/// asserted on the re-drive's RETURN value — the input `recover_committing_entry`
/// consumes to choose `mark_resolved(Committed)` vs the NeedsRepair append.)
#[tokio::test]
async fn xctx_commit_in_progress_with_witness_resolves_committed() {
    use crate::context::supervisor::saga_journal::SagaId;
    use crate::context::supervisor::saga_prepared_state::CrossContextOutletInvocationPrepared;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let creator_did = "did:dht:z6MkXctxWitnessCreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let supervisor = xctx_supervisor(creator_did.clone(), creator_key);
    let caller_did = "did:dht:z6MkXctxWitnessCaller";
    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_exec = Arc::clone(&calls);
    let executor = move |_input: serde_json::Value| {
        let calls = Arc::clone(&calls_for_exec);
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::json!({ "result": 3 }))
        }
    };
    let now_ms = supervisor.clock_ref().expect("clock").now_millis();
    let nonce = [0x42u8; 16];
    let out = supervisor
        .start_cross_context_outlet_invocation_saga(
            CrossContextOutletInvocationRequest {
                caller_context_id: XCTX_CALLER,
                target_context_id: XCTX_TARGET,
                caller_did: DID(caller_did.to_owned()),
                outlet_registration_id: XCTX_OUTLET.to_owned(),
                ucan_proof_id: None,
                input: serde_json::json!({ "a": 1, "b": 2 }),
                asserted_chain_depth: 2,
                asserted_nonce: nonce,
                asserted_timestamp_ms: now_ms,
            },
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            executor,
        )
        .await
        .expect("saga commits");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "outlet ran once");

    // Recover the committed saga id from the receipt — its A-side witness is
    // present in the (still-live) caller actor.
    let receipt: scp_protocol::context::outlets::cross_context_saga::CrossContextOutletReceipt =
        serde_json::from_slice(&out.receipt.expect("receipt")).expect("decode");
    let saga_id_str = receipt
        .outlet_invoked_event_id
        .strip_prefix("OutletInvoked:")
        .expect("event id carries saga id")
        .to_owned();
    let saga_id = SagaId(saga_id_str);

    let prepared = CrossContextOutletInvocationPrepared {
        caller_context_id: XCTX_CALLER,
        target_context_id: XCTX_TARGET,
        caller_did: DID(caller_did.to_owned()),
        outlet_registration_id: XCTX_OUTLET.to_owned(),
        ucan_proof_id: String::new(),
        recorded_timestamp_ms: now_ms,
        recorded_nonce: nonce,
        recorded_chain_depth: 3,
    };
    // The re-drive re-acks Commit-A FROM THE WITNESS and resolves Committed —
    // not a false NeedsRepair.
    let resolution =
        Box::pin(supervisor.redrive_xctx_commit_in_progress(&saga_id, &prepared)).await;
    assert_eq!(
        resolution,
        CommitInProgressResolution::Committed,
        "a Commit-in-progress recovery with a present A-side witness MUST resolve to \
             Committed (not a false NeedsRepair)"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "recovery must not re-invoke the outlet"
    );

    // Contrast: with NO A-side witness (a different, never-committed saga id),
    // the same re-drive stays NeedsRepair — only a genuine commit resolves.
    let absent = SagaId("never-committed-saga".to_owned());
    let resolution_absent =
        Box::pin(supervisor.redrive_xctx_commit_in_progress(&absent, &prepared)).await;
    assert_eq!(
        resolution_absent,
        CommitInProgressResolution::NeedsRepair,
        "a saga with no committed B-side / A-witness must stay NeedsRepair"
    );
}

/// FIX 4 (crash-recovery one-sided divergence): a Commit-in-progress recovery
/// where the TARGET committed (B replays `AlreadyCommitted`) but the A side
/// is UNREACHABLE (caller actor gone post-crash) is a genuine one-sided
/// commit. The signing keys died with the crash, so a signed
/// `CrossContextDivergenceMarker` cannot be appended — but the SUPERVISOR
/// REPAIR JOURNAL is available, so the divergence MUST be durably recorded
/// there (spec §6.2.4 "or a supervisor-level repair journal if one side is
/// unreachable") rather than silently resolving to a bare `NeedsRepair`.
#[tokio::test]
async fn xctx_commit_in_progress_one_sided_records_supervisor_repair() {
    use crate::context::supervisor::saga_journal::SagaId;
    use crate::context::supervisor::saga_prepared_state::CrossContextOutletInvocationPrepared;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let creator_did = "did:dht:z6MkXctxOneSidedCreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let supervisor = xctx_supervisor(creator_did.clone(), creator_key);
    let caller_did = "did:dht:z6MkXctxOneSidedCaller";
    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_exec = Arc::clone(&calls);
    let executor = move |_input: serde_json::Value| {
        let calls = Arc::clone(&calls_for_exec);
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::json!({ "result": 3 }))
        }
    };
    let now_ms = supervisor.clock_ref().expect("clock").now_millis();
    let nonce = [0x77u8; 16];
    let out = supervisor
        .start_cross_context_outlet_invocation_saga(
            CrossContextOutletInvocationRequest {
                caller_context_id: XCTX_CALLER,
                target_context_id: XCTX_TARGET,
                caller_did: DID(caller_did.to_owned()),
                outlet_registration_id: XCTX_OUTLET.to_owned(),
                ucan_proof_id: None,
                input: serde_json::json!({ "a": 1, "b": 2 }),
                asserted_chain_depth: 2,
                asserted_nonce: nonce,
                asserted_timestamp_ms: now_ms,
            },
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            executor,
        )
        .await
        .expect("saga commits");

    let receipt: scp_protocol::context::outlets::cross_context_saga::CrossContextOutletReceipt =
        serde_json::from_slice(&out.receipt.expect("receipt")).expect("decode");
    let saga_id_str = receipt
        .outlet_invoked_event_id
        .strip_prefix("OutletInvoked:")
        .expect("event id carries saga id")
        .to_owned();
    let saga_id = SagaId(saga_id_str);

    // Despawn the CALLER (A) actor: post-crash it is unreachable, so the
    // A-side witness cannot be confirmed even though B durably committed.
    assert!(
        supervisor.despawn_actor(&hex::encode(XCTX_CALLER)).await,
        "despawn caller actor (A unreachable post-crash)"
    );

    let prepared = CrossContextOutletInvocationPrepared {
        caller_context_id: XCTX_CALLER,
        target_context_id: XCTX_TARGET,
        caller_did: DID(caller_did.to_owned()),
        outlet_registration_id: XCTX_OUTLET.to_owned(),
        ucan_proof_id: String::new(),
        recorded_timestamp_ms: now_ms,
        recorded_nonce: nonce,
        recorded_chain_depth: 3,
    };

    // B re-emits AlreadyCommitted; A is unreachable ⇒ genuine one-sided
    // commit ⇒ NeedsRepair AND a supervisor repair record.
    let resolution =
        Box::pin(supervisor.redrive_xctx_commit_in_progress(&saga_id, &prepared)).await;
    assert_eq!(
        resolution,
        CommitInProgressResolution::NeedsRepair,
        "target committed + caller unreachable is a one-sided commit ⇒ NeedsRepair"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "recovery must not re-invoke"
    );

    // FIX 4: the divergence is durably recorded in the supervisor repair
    // journal (the post-crash fallback for the unreachable signing side).
    let repair = supervisor.saga_repair_records_for(&saga_id);
    assert_eq!(
        repair.len(),
        1,
        "a one-sided crash-recovery divergence MUST record exactly one supervisor repair \
             record, got {repair:?}"
    );
    assert_eq!(repair[0].unreachable_context_hex, hex::encode(XCTX_CALLER));
    assert_eq!(
        repair[0].committed_event_id,
        format!("OutletInvoked:{}", saga_id.0)
    );
    assert_eq!(repair[0].nonce, nonce);
    assert_eq!(
        repair[0].committed_side,
        scp_protocol::context::outlets::cross_context_saga::CommittedSide::Target
    );
}

/// FIX 3 (crypto, §6.2.4 "Signer authorization"): the Commit-A path verifies
/// B's receipt signature against the key authorized for `target_context_id`
/// BEFORE settling. A receipt signed by a DIFFERENT key is rejected — the
/// saga aborts before any settle/record. Exercised directly on
/// `verify_commit_b_receipt`: a ctx holding target key Y rejects a receipt
/// signed by key X.
#[tokio::test]
async fn xctx_commit_a_rejects_receipt_signed_by_wrong_key() {
    use crate::context::supervisor::saga_journal::SagaId;
    use scp_protocol::context::outlets::cross_context_saga::{
        CrossContextOutletReceipt, CrossContextOutletReceiptFields,
    };

    let authorized = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let attacker = ed25519_dalek::SigningKey::from_bytes(&[0x99u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let nonce = [0x42u8; 16];

    // The ctx is authorized for the TARGET key `authorized`.
    let ctx = divergence_ctx(
        nonce,
        "OutletInvoked:wrong-key-saga".to_owned(),
        &authorized,
        &caller_signing,
        "did:dht:z6MkWrongKeyCaller",
    );

    // A receipt signed by the ATTACKER key (not authorized for the target).
    let forged = CrossContextOutletReceipt::sign(
        &attacker,
        CrossContextOutletReceiptFields {
            caller_context_id: XCTX_CALLER,
            target_context_id: XCTX_TARGET,
            caller_did: "did:dht:z6MkWrongKeyCaller".to_owned(),
            nonce,
            outlet_registration_id: XCTX_OUTLET.to_owned(),
            output_jcs: br#"{"result":3}"#.to_vec(),
            outlet_invoked_event_id: "OutletInvoked:wrong-key-saga".to_owned(),
            chain_depth: 3,
            timestamp_ms: 1_700_000_000,
        },
    )
    .expect("sign forged receipt");
    let forged_bytes = serde_json::to_vec(&forged).expect("encode");

    let saga_id = SagaId("wrong-key-saga".to_owned());
    let result = Supervisor::verify_commit_b_receipt(&saga_id, &ctx, &forged_bytes);
    assert!(
        matches!(
            &result,
            Err(ContextError::CryptoFailed(m)) if m.contains("SCP-SAGA-13064")
        ),
        "a receipt signed by a key NOT authorized for the target context must be rejected \
             before settle, got {result:?}"
    );

    // Sanity: the SAME receipt signed by the AUTHORIZED key verifies.
    let valid = CrossContextOutletReceipt::sign(
        &authorized,
        CrossContextOutletReceiptFields {
            caller_context_id: XCTX_CALLER,
            target_context_id: XCTX_TARGET,
            caller_did: "did:dht:z6MkWrongKeyCaller".to_owned(),
            nonce,
            outlet_registration_id: XCTX_OUTLET.to_owned(),
            output_jcs: br#"{"result":3}"#.to_vec(),
            outlet_invoked_event_id: "OutletInvoked:wrong-key-saga".to_owned(),
            chain_depth: 3,
            timestamp_ms: 1_700_000_000,
        },
    )
    .expect("sign valid receipt");
    let valid_bytes = serde_json::to_vec(&valid).expect("encode");
    assert!(
        Supervisor::verify_commit_b_receipt(&saga_id, &ctx, &valid_bytes).is_ok(),
        "a receipt signed by the authorized target key must verify"
    );
}

/// FIX 5 (§6.2.4 "Exactly-once execution"): a transient Commit-B SETTLE
/// failure is retryable WITHOUT re-invoking the outlet. The target's Commit-B
/// settle persist fails once (Class-S fail-closed → the capture rolls back),
/// so the FSM retries: reserve reports `ReadyToExecute` again, but the
/// executor output is STASHED in the ctx — the settle is re-sent with the
/// stashed bytes and the outlet is NEVER re-invoked. The saga commits on retry
/// and the executor ran exactly once.
#[tokio::test]
async fn xctx_commit_b_settle_retry_does_not_reinvoke_outlet() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let creator_did = "did:dht:z6MkXctxSettleRetryCreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    // Fail the TARGET context's 2nd persist (Prepare-B = call 1, Commit-B
    // settle = call 2) exactly once; the retried settle (call 3) succeeds.
    let persistence = FailContextPersistOncePersistence {
        target_hex: hex::encode(XCTX_TARGET),
        fail_on_call: 2,
        always: false,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let supervisor =
        xctx_supervisor_with_persistence(creator_did.clone(), creator_key, Box::new(persistence));
    let caller_did = "did:dht:z6MkXctxSettleRetryCaller";
    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_exec = Arc::clone(&calls);
    let executor = move |input: serde_json::Value| {
        let calls = Arc::clone(&calls_for_exec);
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            let a = input["a"].as_i64().unwrap_or(0);
            let b = input["b"].as_i64().unwrap_or(0);
            Ok(serde_json::json!({ "result": a + b }))
        }
    };

    let now_ms = supervisor.clock_ref().expect("clock").now_millis();
    let output = supervisor
        .start_cross_context_outlet_invocation_saga(
            CrossContextOutletInvocationRequest {
                caller_context_id: XCTX_CALLER,
                target_context_id: XCTX_TARGET,
                caller_did: DID(caller_did.to_owned()),
                outlet_registration_id: XCTX_OUTLET.to_owned(),
                ucan_proof_id: None,
                input: serde_json::json!({ "a": 1, "b": 2 }),
                asserted_chain_depth: 2,
                asserted_nonce: [0x42u8; 16],
                asserted_timestamp_ms: now_ms,
            },
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            executor,
        )
        .await
        .expect("saga must commit after the transient settle failure is retried");

    // The transient settle failure was retried to a committed terminal …
    let out_value: serde_json::Value =
        serde_json::from_slice(&output.output.expect("output")).expect("decode");
    assert_eq!(out_value, serde_json::json!({ "result": 3 }));
    // … and despite the retry the outlet executed EXACTLY ONCE (the stashed
    // output was re-sent, never re-invoked).
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a Commit-B settle retry MUST re-send the stashed output, never re-invoke the outlet"
    );
}

/// FIX 1 (§6.2.4): a Commit-A whose mailbox SEND fails (the caller actor
/// died between `lookup` and send) does NOT drop the escrow ticket unbalanced
/// (no debug-assert panic under `--features testing`, no escrow leak in
/// release) and KEEPS the reservation consumable for a retry. We Prepare-A on
/// a live caller (staging a real reservation), DESPAWN the caller, then call
/// `commit_a_settle`: it returns Err but RECOVERS the reservation back into
/// `ctx.prepared_a` — proving the ticket was not dropped and the retry can
/// re-drive Commit-A.
#[tokio::test]
async fn xctx_commit_a_send_failure_recovers_ticket_for_retry() {
    use scp_protocol::context::outlets::cross_context_saga::{
        CrossContextOutletReceipt, CrossContextOutletReceiptFields,
    };

    let creator_did = "did:dht:z6MkXctxSendFailCreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let supervisor = xctx_supervisor(creator_did.clone(), creator_key);
    let caller_did = "did:dht:z6MkXctxSendFailCaller";
    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let nonce = [0x42u8; 16];

    // Build a saga ctx and run the REAL Prepare-A so `prepared_a` holds a
    // genuine `#[must_use]` reservation (its ticket's Drop guard fires if it
    // is ever dropped unbalanced).
    let mut ctx = CrossContextSagaCtx {
        caller_context_id: XCTX_CALLER,
        target_context_id: XCTX_TARGET,
        caller_did: DID(caller_did.to_owned()),
        outlet_registration_id: XCTX_OUTLET.to_owned(),
        ucan_proof_id: None,
        input: serde_json::json!({ "a": 1, "b": 2 }),
        asserted_chain_depth: 2,
        asserted_nonce: nonce,
        asserted_timestamp_ms: supervisor.clock_ref().expect("clock").now_millis(),
        caller_source_role: None,
        target_signer: CommandSigner::local_ed25519(target_signing.clone()),
        caller_signer: CommandSigner::local_ed25519(caller_signing.clone()),
        executor: Some(Box::new(|_v: serde_json::Value| {
            Box::pin(async move { Ok(serde_json::json!({ "result": 3 })) }) as _
        })),
        executor_output: None,
        prepared_a: None,
        prepared_b: None,
        committed: None,
        committed_b_outlet_invoked_event_id: None,
        reached_needs_repair: false,
    };
    supervisor
        .dispatch_xctx_prepare_a(&SagaId::new(), &mut ctx)
        .await
        .expect("Prepare-A stages a real reservation");
    assert!(ctx.prepared_a.is_some(), "Prepare-A held a reservation");

    // Now the caller actor dies BEFORE Commit-A reaches it.
    let despawned = supervisor.despawn_actor(&hex::encode(XCTX_CALLER)).await;
    assert!(despawned, "caller actor despawned");

    // Build a verified receipt signed by the target's authorized key (the
    // Commit-A path passes the VERIFIED receipt; we mirror that here).
    let receipt = CrossContextOutletReceipt::sign(
        &target_signing,
        CrossContextOutletReceiptFields {
            caller_context_id: XCTX_CALLER,
            target_context_id: XCTX_TARGET,
            caller_did: caller_did.to_owned(),
            nonce,
            outlet_registration_id: XCTX_OUTLET.to_owned(),
            output_jcs: br#"{"result":3}"#.to_vec(),
            outlet_invoked_event_id: "OutletInvoked:send-fail-saga".to_owned(),
            chain_depth: 3,
            timestamp_ms: 1_700_000_000,
        },
    )
    .expect("sign receipt");
    let receipt_bytes = serde_json::to_vec(&receipt).expect("encode");

    let saga_id = SagaId("send-fail-saga".to_owned());
    let result = supervisor
        .commit_a_settle(&saga_id, &mut ctx, &receipt_bytes, &receipt)
        .await;

    // The send failed (caller gone) — but the ticket was NOT dropped: it is
    // recovered back into `ctx.prepared_a`, consumable on retry. Reaching
    // this assertion without a drop-guard panic IS the FIX-1 guarantee.
    assert!(
        result.is_err(),
        "Commit-A to a despawned caller must surface the send failure"
    );
    assert!(
        ctx.prepared_a.is_some(),
        "the escrow reservation MUST be recovered into ctx for retry (never dropped \
             unbalanced — no ticket-drop panic, no escrow leak)"
    );

    // Drain the recovered reservation cleanly so the test does not itself
    // leak the must-use ticket (mirrors the run_saga tail's void+consume for
    // a Commit-A that never landed).
    if let Some(reservation) = ctx.prepared_a.take() {
        reservation
            .reservation
            .ticket
            .void_external_and_consume(supervisor.payment_adapter_ref())
            .await;
    }
}

/// FIX 1 (abort ticket-safe send): a caller-side `Abort` whose mailbox SEND
/// fails (the caller handle is FOUND in the registry but its mailbox is
/// closed) must NOT drop the `#[must_use]` reservation ticket carried in the
/// boxed command — that would trip the ticket's unbalanced-`Drop`
/// debug-assert under `--features testing` (and leak escrow in release).
/// `abort_xctx_participants` uses `send_recover_on_failure`, recovers the
/// un-delivered `Abort` command via `extract_abort_reservation`, and voids
/// its external escrow + consumes the ticket. This injects a registered-but-
/// dead handle (closed mailbox) so the lookup HITS and the SEND fails —
/// exercising the recover path, not the lookup-miss branch. Reaching the end
/// without a drop-guard panic IS the guarantee.
#[tokio::test]
async fn xctx_abort_send_failure_voids_ticket_no_panic() {
    use crate::context::actor::ContextActorHandle;

    let creator_did = "did:dht:z6MkXctxAbortSendFailCreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let supervisor = xctx_supervisor(creator_did.clone(), creator_key);
    let caller_did = "did:dht:z6MkXctxAbortSendFailCaller";
    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let nonce = [0x42u8; 16];

    // Run the REAL Prepare-A (on the still-live caller actor) so `prepared_a`
    // holds a genuine must-use reservation whose ticket Drop guard fires if
    // it is ever dropped unbalanced.
    let mut ctx = CrossContextSagaCtx {
        caller_context_id: XCTX_CALLER,
        target_context_id: XCTX_TARGET,
        caller_did: DID(caller_did.to_owned()),
        outlet_registration_id: XCTX_OUTLET.to_owned(),
        ucan_proof_id: None,
        input: serde_json::json!({ "a": 1, "b": 2 }),
        asserted_chain_depth: 2,
        asserted_nonce: nonce,
        asserted_timestamp_ms: supervisor.clock_ref().expect("clock").now_millis(),
        caller_source_role: None,
        target_signer: CommandSigner::local_ed25519(target_signing.clone()),
        caller_signer: CommandSigner::local_ed25519(caller_signing.clone()),
        executor: Some(Box::new(|_v: serde_json::Value| {
            Box::pin(async move { Ok(serde_json::json!({ "result": 3 })) }) as _
        })),
        executor_output: None,
        prepared_a: None,
        prepared_b: None,
        committed: None,
        committed_b_outlet_invoked_event_id: None,
        reached_needs_repair: false,
    };
    supervisor
        .dispatch_xctx_prepare_a(&SagaId::new(), &mut ctx)
        .await
        .expect("Prepare-A stages a real reservation");
    assert!(ctx.prepared_a.is_some(), "Prepare-A held a reservation");

    // REPLACE the live caller handle with a registered-but-DEAD one: a
    // channel whose receiver is dropped. `lookup` now HITS, but the mailbox
    // is closed, so `send_recover_on_failure` fails the send and returns the
    // un-delivered `Abort` command for ticket recovery — the exact path FIX 1
    // hardens (the old plain `send` would drop the command + ticket here).
    let (dead_tx, dead_rx) = tokio::sync::mpsc::channel::<ContextCommand>(1);
    drop(dead_rx);
    supervisor.actors.insert(
        hex::encode(XCTX_CALLER),
        ContextActorHandle::from_sender(dead_tx),
    );

    // Abort: the caller-side send fails on the closed mailbox. The held
    // reservation's ticket must be recovered + voided + consumed, never
    // dropped unbalanced. `abort_xctx_participants` takes `prepared_a` out.
    let saga_id = SagaId("abort-send-fail-saga".to_owned());
    Box::pin(supervisor.abort_xctx_participants(&saga_id, &mut ctx)).await;

    // The reservation was taken out of ctx and balanced (voided+consumed) by
    // the abort path — not left in ctx and not dropped unbalanced.
    assert!(
        ctx.prepared_a.is_none(),
        "the abort path must take and balance the reservation (no leftover in ctx)"
    );
    // Reaching here without a ticket-drop panic IS the FIX-1 guarantee.
}

/// A persistence double that CAPTURES the latest snapshot per context, so a
/// test can read an actor's owned economy (`hard_rate_limit_state`) and its
/// durable `xctx_caller_reservations` after a `FlushSnapshot` without
/// reaching into the actor's private state.
///
/// `list_persisted_contexts` returns an EMPTY list by default (`restore_enabled
/// == false`), so `restore_all_contexts` is a no-op over it — the shape the
/// "resident caller" tests want. Set `restore_enabled = true` (via
/// [`CapturingPersistence::with_restore`]) to make it ALSO act as a restore
/// source: `list_persisted_contexts` then returns the captured snapshot keys
/// and `load_context` rehydrates them, so `restore_all_contexts` resurrects a
/// previously-flushed (and since-despawned) actor — the order-discriminating
/// restore-then-replay path.
#[derive(Clone, Default)]
struct CapturingPersistence {
    snapshots: Arc<dashmap::DashMap<String, crate::context::state::ContextSnapshot>>,
    /// When `true`, `list_persisted_contexts` lists the captured snapshots so
    /// the double doubles as a restore source.
    restore_enabled: bool,
}
impl CapturingPersistence {
    /// A capturing double that ALSO serves as a restore source (lists +
    /// loads captured snapshots), so `restore_all_contexts` can resurrect a
    /// despawned actor from its last flush.
    fn with_restore() -> Self {
        Self {
            snapshots: Arc::default(),
            restore_enabled: true,
        }
    }
}
#[async_trait::async_trait]
impl ContextPersistence for CapturingPersistence {
    async fn persist_context(
        &self,
        id: &str,
        snap: &crate::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.snapshots.insert(id.to_owned(), snap.clone());
        Ok(())
    }
    async fn load_context(
        &self,
        id: &str,
    ) -> Result<
        Option<crate::context::state::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(self.snapshots.get(id).map(|e| e.value().clone()))
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
        if self.restore_enabled {
            Ok(self.snapshots.iter().map(|e| e.key().clone()).collect())
        } else {
            Ok(Vec::new())
        }
    }
}

/// Flush a co-resident actor's snapshot through the production
/// `FlushSnapshot` command and return the captured `ContextSnapshot` (the
/// economy + durable-reservation state the persistence double recorded).
async fn flush_and_read_snapshot(
    supervisor: &Arc<Supervisor>,
    persistence: &CapturingPersistence,
    context_id: [u8; 32],
) -> crate::context::state::ContextSnapshot {
    use crate::context::actor::commands::LifecycleCommand;
    let hex = hex::encode(context_id);
    let actor = supervisor
        .lookup(&hex)
        .expect("actor co-resident for flush");
    actor
        .send(|reply| ContextCommand::Lifecycle(LifecycleCommand::FlushSnapshot { reply }))
        .await
        .expect("flush snapshot");
    persistence
        .snapshots
        .get(&hex)
        .map(|e| e.value().clone())
        .expect("snapshot captured by the persistence double")
}

/// §6.2.4 "Reservation release on every terminal path" (review wave-8): a
/// LIVE abort whose caller-side `Abort { Some }` mailbox send FAILS must NOT
/// mark the journal terminal-`Aborted` while the caller's LOCAL economy
/// reversal is still outstanding — that would durably over-charge the caller
/// forever (the §17.16.4 sweep re-drives ONLY a non-terminal `PreparingB`,
/// never an `Aborted`). Instead the coordinator leaves the journal
/// non-terminal, and the durable `CallerReservationRecord` makes the LOCAL
/// economy reversible by a record-based `Abort { None }` re-drive.
///
/// PART 1 (the regression — FAILS pre-fix): with the caller handle replaced
/// by a registered-but-DEAD one (closed mailbox), the caller-side
/// `Abort { Some }` send fails AND the `Abort { None }` re-drive to the same
/// dead handle fails, so the caller's LOCAL economy reversal is outstanding.
/// `abort_saga` MUST therefore leave the journal NON-terminal (at
/// `PreparingB`, the sweep-redrivable state) — NOT mark terminal-`Aborted`.
/// Pre-fix, `abort_saga` marked `Aborted` unconditionally (the over-charge).
///
/// PART 2 (reconciliation via the production re-drive): the (still-live)
/// caller actor — restored to the registry, exactly as a respawn would
/// surface it — is driven through the SAME `Abort { None }` re-drive the
/// crash-recovery sweep uses. It reverses the caller's LOCAL economy from the
/// durable record: the hard-rate-limit token is refunded, the durable record
/// is consumed, and the helper reports the reversal settled. This is the
/// reconciliation the BUGGY terminal-`Aborted` path destroyed by never
/// re-driving.
#[tokio::test]
#[allow(clippy::too_many_lines)] // full send-failure abort E2E: reserve + journal + re-drive
async fn live_abort_send_failure_reverses_caller_economy_via_record_redrive() {
    use crate::context::supervisor::saga_journal::{
        ProtocolRepositorySagaJournal, SagaId, SagaState,
    };

    let creator_did = "did:dht:z6MkXctxWave8Creator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let persistence = CapturingPersistence::default();
    // A REAL durable saga journal (over in-memory storage) so the terminal-
    // marker decision is observable via `load_unresolved` — the default
    // `with_providers` journal is a no-op stub.
    let journal_storage = Arc::new(InMemoryStorage::new());
    let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(
        &journal_storage,
    )));
    let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
        "did:dht:z6MktestXctxWave8".to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
        Box::new(crate::context::builder::NotConfiguredTransportProvider);
    let key_resolver: KeyResolver = {
        let creator_did = creator_did.clone();
        Arc::new(move |did: &DID, _| {
            if did.as_ref() == creator_did {
                Some(creator_key)
            } else {
                None
            }
        })
    };
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            InMemoryStorage::new(),
        )),
    );
    let supervisor = Supervisor::with_providers_and_journal(
        crypto,
        transport,
        Box::new(TestEventLog),
        key_resolver,
        Box::new(persistence.clone()),
        None,
        None,
        None,
        crate::context::supervisor::DurableProviders::for_test(journal, mls_storage),
        crate::crypto::wrapping::single_custody_source(Arc::new(
            scp_platform::testing::InMemoryKeyCustody::new(),
        )),
        crate::domain_handlers(),
    );
    let caller_did = "did:dht:z6MkXctxWave8Caller";
    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    let caller_hex = hex::encode(XCTX_CALLER);
    // Capture the LIVE caller handle — never despawned; we only swap the
    // registry pointer for Part 1, then restore this same live handle for the
    // Part 2 re-drive (the actor keeps its consumed token + durable record
    // throughout, exactly as a restored snapshot would carry them).
    let live_caller = supervisor.lookup(&caller_hex).expect("caller co-resident");

    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let nonce = [0x42u8; 16];

    let mut ctx = CrossContextSagaCtx {
        caller_context_id: XCTX_CALLER,
        target_context_id: XCTX_TARGET,
        caller_did: DID(caller_did.to_owned()),
        outlet_registration_id: XCTX_OUTLET.to_owned(),
        ucan_proof_id: None,
        input: serde_json::json!({ "a": 1, "b": 2 }),
        asserted_chain_depth: 2,
        asserted_nonce: nonce,
        asserted_timestamp_ms: supervisor.clock_ref().expect("clock").now_millis(),
        caller_source_role: None,
        target_signer: CommandSigner::local_ed25519(target_signing.clone()),
        caller_signer: CommandSigner::local_ed25519(caller_signing.clone()),
        executor: Some(Box::new(|_v: serde_json::Value| {
            Box::pin(async move { Ok(serde_json::json!({ "result": 3 })) }) as _
        })),
        executor_output: None,
        prepared_a: None,
        prepared_b: None,
        committed: None,
        committed_b_outlet_invoked_event_id: None,
        reached_needs_repair: false,
    };

    let saga_id = SagaId("wave8-send-fail-saga".to_owned());
    let participants = vec![caller_hex.clone(), hex::encode(XCTX_TARGET)];

    // Real Prepare-A on the live caller actor: consumes a hard-rate-limit
    // token, records velocity, and stages the durable
    // `CallerReservationRecord`. Returns the must-use carrier into `ctx`.
    supervisor
        .dispatch_xctx_prepare_a(&saga_id, &mut ctx)
        .await
        .expect("Prepare-A stages a real reservation");
    assert!(ctx.prepared_a.is_some(), "Prepare-A held a reservation");

    // Baseline: the reserve mutated OWNED state (else the test proves
    // nothing). The hard-rate-limit bucket dropped below full burst and the
    // durable record is present.
    let burst_milli = {
        let snap = flush_and_read_snapshot(&supervisor, &persistence, XCTX_CALLER).await;
        let token_after_reserve = snap
            .hard_rate_limit_state
            .get(caller_did)
            .map(|(tokens, _)| *tokens)
            .expect("reserve created a hard-rate-limit entry");
        assert!(
            snap.xctx_caller_reservations.contains_key(&saga_id),
            "Prepare-A staged the durable caller reservation record"
        );
        // A fresh caller starts at full burst; a reserve drains exactly one
        // token. Recover the burst ceiling from the snapshot: it is the
        // refunded value asserted in Part 2.
        let burst = token_after_reserve + 1000; // one token = 1000 milli-tokens
        assert!(
            token_after_reserve < burst,
            "reserve must have consumed a hard-rate-limit token \
                 (after_reserve={token_after_reserve}, burst={burst})"
        );
        burst
    };

    // Journal the FSM up to PreparingB (the real state at the post-Prepare-B-
    // failure `abort_saga` call site), carrying the full caller+target
    // evidence the sweep re-drives.
    let evidence = Supervisor::xctx_prepared_evidence_bytes(
        &SagaInput::test_cross_context_for_gating(XCTX_CALLER, XCTX_TARGET),
        &ctx,
    )
    .expect("xctx evidence");
    supervisor
        .append_journal(&saga_id, SagaState::Initiated, &participants, 0, &[])
        .await
        .expect("journal Initiated");
    supervisor
        .append_journal(&saga_id, SagaState::PreparingA, &participants, 1, &[])
        .await
        .expect("journal PreparingA");
    supervisor
        .append_journal(&saga_id, SagaState::PreparingB, &participants, 2, &evidence)
        .await
        .expect("journal PreparingB");

    // ---- PART 1: send-failure abort MUST NOT mark terminal-Aborted ----
    // Swap the registry caller handle for a DEAD one (closed mailbox): the
    // caller-side `Abort { Some }` send fails, and the `Abort { None }`
    // re-drive to the same dead handle also fails ⇒ the LOCAL reversal is
    // outstanding. The real live actor is untouched (still holds the consumed
    // token + record); we only swapped the registry pointer.
    let (dead_tx, dead_rx) = tokio::sync::mpsc::channel::<ContextCommand>(1);
    drop(dead_rx);
    supervisor
        .actors
        .insert(caller_hex.clone(), ContextActorHandle::from_sender(dead_tx));

    supervisor
        .abort_saga(
            &saga_id,
            &participants,
            3,
            /*secret_bearing=*/ false,
            Some(&mut ctx),
        )
        .await
        .expect("abort_saga returns Ok (best-effort, non-terminal on outstanding reversal)");

    // The journal MUST be non-terminal: the saga is still unresolved (latest
    // entry PreparingB), NOT marked terminal-Aborted. Pre-fix this FAILED —
    // `abort_saga` marked `Aborted` unconditionally, dropping the saga out of
    // `load_unresolved` and leaving the caller over-charged forever.
    let unresolved = supervisor
        .saga_journal
        .load_unresolved()
        .await
        .expect("load_unresolved");
    let entry = unresolved.iter().find(|e| e.saga_id == saga_id).expect(
        "the send-failure saga MUST remain UNRESOLVED (not terminal-Aborted) so the \
                     crash-recovery sweep can re-drive the caller's LOCAL economy reversal",
    );
    assert_eq!(
        entry.state,
        SagaState::PreparingB,
        "the journal must stay at the sweep-redrivable PreparingB state, not advance to \
             Aborting/Aborted while the caller refund is outstanding"
    );
    assert_ne!(
        entry.state,
        SagaState::Aborted,
        "abort_saga MUST NOT write a terminal-Aborted marker with the caller's LOCAL \
             economy reversal outstanding (the durable over-charge this fix closes)"
    );

    // ---- PART 2: record-based Abort{None} re-drive reverses LOCAL economy --
    // Restore the live caller actor to the registry (as a respawn would
    // surface it) and drive the SAME production re-drive the sweep uses.
    supervisor.actors.insert(caller_hex.clone(), live_caller);
    let reversal = supervisor
        .redrive_caller_local_reversal(&saga_id, &caller_hex)
        .await;
    assert_eq!(
        reversal,
        CallerAbortReversal::SettledOrAbsent,
        "the Abort{{None}} re-drive must be delivered and settle the caller's LOCAL economy"
    );

    // The caller's LOCAL economy is reversed and the durable record consumed.
    let snap = flush_and_read_snapshot(&supervisor, &persistence, XCTX_CALLER).await;
    let token_after_abort = snap
        .hard_rate_limit_state
        .get(caller_did)
        .map(|(tokens, _)| *tokens)
        .expect("hard-rate-limit entry present after abort");
    assert_eq!(
        token_after_abort, burst_milli,
        "the record-based Abort{{None}} re-drive MUST refund the consumed hard-rate-limit \
             token (restore to full burst) — the caller is NOT over-charged"
    );
    assert!(
        !snap.xctx_caller_reservations.contains_key(&saga_id),
        "the durable CallerReservationRecord MUST be consumed by the reversal so it can \
             never double-reverse"
    );
}

/// Build a supervisor over a REAL durable saga journal (in-memory storage) +
/// a capturing persistence, so the crash-recovery terminal-marker decision is
/// observable via `load_unresolved` (the default `with_providers` journal is a
/// no-op stub). Returns the supervisor and the live persistence double.
fn xctx_supervisor_with_real_journal(
    creator_did: String,
    creator_key: ed25519_dalek::VerifyingKey,
) -> (Arc<Supervisor>, CapturingPersistence) {
    xctx_supervisor_with_real_journal_persistence(
        creator_did,
        creator_key,
        CapturingPersistence::default(),
    )
}

/// Variant of [`xctx_supervisor_with_real_journal`] that takes the capturing
/// persistence double, so a test can supply a restore-ENABLED one (see
/// [`CapturingPersistence::with_restore`]) to exercise the order-discriminating
/// restore-then-replay path (`restore_all_contexts` resurrects a despawned
/// caller from its last flush before the replay leg drives the reversal).
fn xctx_supervisor_with_real_journal_persistence(
    creator_did: String,
    creator_key: ed25519_dalek::VerifyingKey,
    persistence: CapturingPersistence,
) -> (Arc<Supervisor>, CapturingPersistence) {
    use crate::context::supervisor::saga_journal::ProtocolRepositorySagaJournal;
    let journal_storage = Arc::new(InMemoryStorage::new());
    let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(
        &journal_storage,
    )));
    let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
        "did:dht:z6MktestXctxWave15".to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
        Box::new(crate::context::builder::NotConfiguredTransportProvider);
    let key_resolver: KeyResolver = Arc::new(move |did: &DID, _| {
        if did.as_ref() == creator_did {
            Some(creator_key)
        } else {
            None
        }
    });
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            InMemoryStorage::new(),
        )),
    );
    let supervisor = Supervisor::with_providers_and_journal(
        crypto,
        transport,
        Box::new(TestEventLog),
        key_resolver,
        Box::new(persistence.clone()),
        None,
        None,
        None,
        crate::context::supervisor::DurableProviders::for_test(journal, mls_storage),
        crate::crypto::wrapping::single_custody_source(Arc::new(
            scp_platform::testing::InMemoryKeyCustody::new(),
        )),
        crate::domain_handlers(),
    );
    (supervisor, persistence)
}

/// Stage a cross-context caller saga crashed at `PreparingB`: build a
/// real-journal supervisor over `persistence`, spawn the caller/target pair,
/// run the genuine FSM triple through `dispatch_xctx_prepare_a` (durably
/// staging the caller deduction + `CallerReservationRecord` on the live caller
/// actor + flushing it to persistence), void the must-use carrier, and journal
/// `Initiated`/`PreparingA`/`PreparingB`. This is the ~95%-shared setup of the
/// two `restore_on_startup` crash-recovery gates (the resident-caller in-pass
/// reversal and the order-discriminating restore-from-persistence reversal),
/// which differ only in the `CapturingPersistence` variant + whether the
/// caller is despawned before `restore_on_startup`.
///
/// Returns `(supervisor, persistence, caller_hex, burst_milli)` — the full
/// burst the caller's hard-rate-limit token must be refunded to once the
/// crash-orphaned reversal lands. Leaves the `PreparingB` entry unresolved.
async fn stage_xctx_preparing_b_crash(
    creator_did: &str,
    creator_key_seed: u8,
    caller_did: &str,
    saga_id: &SagaId,
    persistence: CapturingPersistence,
) -> (Arc<Supervisor>, CapturingPersistence, String, u64) {
    let creator_key =
        ed25519_dalek::SigningKey::from_bytes(&[creator_key_seed; 32]).verifying_key();
    let (supervisor, persistence) = xctx_supervisor_with_real_journal_persistence(
        creator_did.to_owned(),
        creator_key,
        persistence,
    );
    let caller_state = xctx_caller_state(caller_did, creator_did);
    let target_state = xctx_target_state(caller_did, creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    let caller_hex = hex::encode(XCTX_CALLER);
    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    // The genuine FSM cross-context participants shape: the caller-provenance
    // TRIPLE `[caller_hex, caller_did, outlet_id]` (`saga_input_participants`),
    // length 3 with a 64-hex first element — the xctx-caller path the
    // 2-element wave-15 tests do NOT exercise (they take the evidence-
    // reconstruction route).
    let participants = vec![
        caller_hex.clone(),
        caller_did.to_owned(),
        XCTX_OUTLET.to_owned(),
    ];

    let mut ctx = CrossContextSagaCtx {
        caller_context_id: XCTX_CALLER,
        target_context_id: XCTX_TARGET,
        caller_did: DID(caller_did.to_owned()),
        outlet_registration_id: XCTX_OUTLET.to_owned(),
        ucan_proof_id: None,
        input: serde_json::json!({ "a": 1, "b": 2 }),
        asserted_chain_depth: 2,
        asserted_nonce: [0x42u8; 16],
        asserted_timestamp_ms: supervisor.clock_ref().expect("clock").now_millis(),
        caller_source_role: None,
        target_signer: CommandSigner::local_ed25519(target_signing),
        caller_signer: CommandSigner::local_ed25519(caller_signing),
        executor: Some(Box::new(|_v: serde_json::Value| {
            Box::pin(async move { Ok(serde_json::json!({ "result": 3 })) }) as _
        })),
        executor_output: None,
        prepared_a: None,
        prepared_b: None,
        committed: None,
        committed_b_outlet_invoked_event_id: None,
        reached_needs_repair: false,
    };

    // Journal `Initiated` (seq 0) + `PreparingA` (seq 1, empty evidence) then
    // Prepare-A durably stages the caller deduction + reservation record on
    // the live caller actor (the durable state a crash leaves behind), and
    // journal `PreparingB` (seq 2, empty evidence — the genuine
    // participant-keyed shape, so the reversal MUST come through the triple).
    supervisor
        .append_journal(saga_id, SagaState::Initiated, &participants, 0, &[])
        .await
        .expect("journal Initiated");
    supervisor
        .append_journal(saga_id, SagaState::PreparingA, &participants, 1, &[])
        .await
        .expect("journal PreparingA");
    supervisor
        .dispatch_xctx_prepare_a(saga_id, &mut ctx)
        .await
        .expect("Prepare-A stages a real reservation");
    let burst_milli = {
        let snap = flush_and_read_snapshot(&supervisor, &persistence, XCTX_CALLER).await;
        let token_after_reserve = snap
            .hard_rate_limit_state
            .get(caller_did)
            .map(|(tokens, _)| *tokens)
            .expect("reserve created a hard-rate-limit entry");
        assert!(
            snap.xctx_caller_reservations.contains_key(saga_id),
            "Prepare-A staged the durable caller reservation record"
        );
        // The flushed caller snapshot is Active, so a restore-enabled double
        // can resurrect it after a despawn (the order-discriminating gate
        // relies on this; the resident gate shares the same invariant).
        assert_eq!(
            snap.state,
            scp_protocol::context::ContextState::Active,
            "the flushed caller snapshot must be Active so restore_all_contexts resurrects it"
        );
        token_after_reserve + 1000 // one token = 1000 milli-tokens
    };
    // Balance the must-use carrier (lost-reply shape) so its drop guard does
    // not fire; the durable record is what recovery reverses.
    if let Some(prepared) = ctx.prepared_a.take() {
        prepared
            .reservation
            .ticket
            .void_external_and_consume(supervisor.payment_adapter_ref())
            .await;
    }
    supervisor
        .append_journal(saga_id, SagaState::PreparingB, &participants, 2, &[])
        .await
        .expect("journal PreparingB");

    (supervisor, persistence, caller_hex, burst_milli)
}

/// §6.2.4 review wave-15 — CRASH-RECOVERY symmetry with the live abort path.
/// The startup `recover_saga_entry` `PreparingB` arm re-drives the prepared
/// side(s) and then marks the journal terminal-`Aborted`. But the caller-side
/// record-based `Abort { None }` re-drive can FAIL to deliver in the
/// genuinely-undeliverable case: when the caller context is not resident
/// (e.g. it failed to restore on the §17.16.4 restore-then-replay startup
/// pass), the `lookup` misses. Pre-fix the arm marked terminal-`Aborted`
/// UNCONDITIONALLY — so the caller's durable LOCAL-economy deduction was
/// NEVER reversed AND recovery (which re-drives ONLY non-terminal journals)
/// could never re-drive a terminal entry: a permanent over-charge. The fix
/// makes the arm honour the SAME invariant the live abort path (`abort_saga`)
/// enforces — terminal-`Aborted` MUST NOT be written until the caller
/// reversal is CONFIRMED delivered.
///
/// NON-RESIDENT caller (this test): the durable record is staged (real
/// Prepare-A), then the caller actor is despawned BEFORE recovery to model a
/// caller that did not become resident, so the re-drive `lookup` misses ⇒ the
/// journal MUST be LEFT non-terminal (carried to the next process start, whose
/// restore-then-replay re-drives it once the caller is resident). PRE-FIX this
/// marked terminal-Aborted.
#[tokio::test]
async fn crash_recovery_preparing_b_non_resident_caller_left_non_terminal() {
    use crate::context::supervisor::saga_journal::{SagaId, SagaState};

    let creator_did = "did:dht:z6MkXctxWave15NonResCreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let (supervisor, persistence) =
        xctx_supervisor_with_real_journal(creator_did.clone(), creator_key);
    let caller_did = "did:dht:z6MkXctxWave15NonResCaller";
    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    let caller_hex = hex::encode(XCTX_CALLER);
    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let saga_id = SagaId("wave15-nonresident-saga".to_owned());
    let participants = vec![caller_hex.clone(), hex::encode(XCTX_TARGET)];

    let mut ctx = CrossContextSagaCtx {
        caller_context_id: XCTX_CALLER,
        target_context_id: XCTX_TARGET,
        caller_did: DID(caller_did.to_owned()),
        outlet_registration_id: XCTX_OUTLET.to_owned(),
        ucan_proof_id: None,
        input: serde_json::json!({ "a": 1, "b": 2 }),
        asserted_chain_depth: 2,
        asserted_nonce: [0x42u8; 16],
        asserted_timestamp_ms: supervisor.clock_ref().expect("clock").now_millis(),
        caller_source_role: None,
        target_signer: CommandSigner::local_ed25519(target_signing),
        caller_signer: CommandSigner::local_ed25519(caller_signing),
        executor: Some(Box::new(|_v: serde_json::Value| {
            Box::pin(async move { Ok(serde_json::json!({ "result": 3 })) }) as _
        })),
        executor_output: None,
        prepared_a: None,
        prepared_b: None,
        committed: None,
        committed_b_outlet_invoked_event_id: None,
        reached_needs_repair: false,
    };

    // Real Prepare-A: durably stages the caller deduction + reservation
    // record on the live caller actor. (We balance the returned carrier
    // immediately — like a lost-reply supervisor would — so its #[must_use]
    // drop guard does not fire; the durable record is what recovery reverses.)
    supervisor
        .dispatch_xctx_prepare_a(&saga_id, &mut ctx)
        .await
        .expect("Prepare-A stages a real reservation");
    if let Some(prepared) = ctx.prepared_a.take() {
        prepared
            .reservation
            .ticket
            .void_external_and_consume(supervisor.payment_adapter_ref())
            .await;
    }
    let snap_before = flush_and_read_snapshot(&supervisor, &persistence, XCTX_CALLER).await;
    assert!(
        snap_before.xctx_caller_reservations.contains_key(&saga_id),
        "Prepare-A staged the durable caller reservation record"
    );

    // Journal up to a RECONSTRUCTIBLE PreparingB carrying the full
    // caller+target evidence (the real post-Prepare-B-failure state).
    let evidence = Supervisor::xctx_prepared_evidence_bytes(
        &SagaInput::test_cross_context_for_gating(XCTX_CALLER, XCTX_TARGET),
        &ctx,
    )
    .expect("xctx evidence");
    supervisor
        .append_journal(&saga_id, SagaState::PreparingB, &participants, 2, &evidence)
        .await
        .expect("journal PreparingB");

    // Despawn the caller BEFORE recovery: this models `replay_unresolved_sagas`
    // running before the caller context is restored. The re-drive `lookup`
    // now misses ⇒ the record-based reversal cannot be delivered.
    assert!(
        supervisor.actors.remove(&caller_hex).is_some(),
        "caller actor despawned to simulate restore-after-replay ordering"
    );

    // Drive the REAL crash-recovery path on the PreparingB entry.
    let entry = JournalEntry {
        saga_id: saga_id.clone(),
        state: SagaState::PreparingB,
        participants: participants.clone(),
        evidence: Zeroizing::new(evidence),
        timestamp_ms: supervisor.clock_ref().expect("clock").now_millis(),
        seq_per_saga: 2,
    };
    supervisor.recover_saga_entry(entry).await;

    // CORE: the journal MUST stay NON-terminal at PreparingB (still in
    // load_unresolved) so the next sweep — after the caller is restored —
    // re-drives the reversal. PRE-FIX recover_saga_entry marked terminal-
    // Aborted UNCONDITIONALLY, dropping the saga out of load_unresolved and
    // stranding the caller's durable deduction forever.
    let unresolved = supervisor
        .saga_journal
        .load_unresolved()
        .await
        .expect("load_unresolved");
    let found = unresolved.iter().find(|e| e.saga_id == saga_id).expect(
        "the non-resident-caller PreparingB saga MUST remain UNRESOLVED (not terminal-Aborted) \
             so a later crash-recovery sweep re-drives the caller's LOCAL economy reversal",
    );
    assert_eq!(
        found.state,
        SagaState::PreparingB,
        "the journal must stay at the sweep-redrivable PreparingB state, not advance to \
             terminal-Aborted while the caller reversal is outstanding"
    );
    // The durable record is UNTOUCHED (reversal never ran against the missing
    // actor), so a respawn + sweep can still reverse it — the over-charge is
    // recoverable, not permanent. The caller actor is despawned, so we read
    // its LAST persisted snapshot directly from the persistence double (it
    // still carries the record Prepare-A staged before despawn).
    let snap_after = persistence
        .snapshots
        .get(&caller_hex)
        .map(|e| e.value().clone())
        .expect("the despawned caller's last persisted snapshot is retained");
    assert!(
        snap_after.xctx_caller_reservations.contains_key(&saga_id),
        "the durable record survives a non-resident-caller recovery so the next sweep can \
             still reverse it (the reversal did not silently run against a missing actor)"
    );
}

/// §6.2.4 review wave-15 companion — RESIDENT caller with a durable record:
/// the crash-recovery `PreparingB` re-drive DELIVERS the record-based
/// `Abort { None }`, reverses the caller's LOCAL economy from the durable
/// record, AND (only then) marks the journal terminal-`Aborted`. This proves
/// the fix still resolves the happy case — it gates the terminal marker on a
/// CONFIRMED reversal, it does not block it unconditionally.
#[tokio::test]
#[allow(clippy::too_many_lines)] // full recovery E2E: reserve + journal + recover + assert
async fn crash_recovery_preparing_b_resident_caller_reverses_then_marks_terminal() {
    use crate::context::supervisor::saga_journal::{SagaId, SagaState};

    let creator_did = "did:dht:z6MkXctxWave15ResCreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let (supervisor, persistence) =
        xctx_supervisor_with_real_journal(creator_did.clone(), creator_key);
    let caller_did = "did:dht:z6MkXctxWave15ResCaller";
    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    let caller_hex = hex::encode(XCTX_CALLER);
    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let saga_id = SagaId("wave15-resident-saga".to_owned());
    let participants = vec![caller_hex.clone(), hex::encode(XCTX_TARGET)];

    let mut ctx = CrossContextSagaCtx {
        caller_context_id: XCTX_CALLER,
        target_context_id: XCTX_TARGET,
        caller_did: DID(caller_did.to_owned()),
        outlet_registration_id: XCTX_OUTLET.to_owned(),
        ucan_proof_id: None,
        input: serde_json::json!({ "a": 1, "b": 2 }),
        asserted_chain_depth: 2,
        asserted_nonce: [0x42u8; 16],
        asserted_timestamp_ms: supervisor.clock_ref().expect("clock").now_millis(),
        caller_source_role: None,
        target_signer: CommandSigner::local_ed25519(target_signing),
        caller_signer: CommandSigner::local_ed25519(caller_signing),
        executor: Some(Box::new(|_v: serde_json::Value| {
            Box::pin(async move { Ok(serde_json::json!({ "result": 3 })) }) as _
        })),
        executor_output: None,
        prepared_a: None,
        prepared_b: None,
        committed: None,
        committed_b_outlet_invoked_event_id: None,
        reached_needs_repair: false,
    };

    supervisor
        .dispatch_xctx_prepare_a(&saga_id, &mut ctx)
        .await
        .expect("Prepare-A stages a real reservation");
    // Recover the burst ceiling + balance the carrier (lost-reply shape).
    let burst_milli = {
        let snap = flush_and_read_snapshot(&supervisor, &persistence, XCTX_CALLER).await;
        let token_after_reserve = snap
            .hard_rate_limit_state
            .get(caller_did)
            .map(|(tokens, _)| *tokens)
            .expect("reserve created a hard-rate-limit entry");
        assert!(
            snap.xctx_caller_reservations.contains_key(&saga_id),
            "Prepare-A staged the durable caller reservation record"
        );
        token_after_reserve + 1000 // one token = 1000 milli-tokens
    };
    if let Some(prepared) = ctx.prepared_a.take() {
        prepared
            .reservation
            .ticket
            .void_external_and_consume(supervisor.payment_adapter_ref())
            .await;
    }

    let evidence = Supervisor::xctx_prepared_evidence_bytes(
        &SagaInput::test_cross_context_for_gating(XCTX_CALLER, XCTX_TARGET),
        &ctx,
    )
    .expect("xctx evidence");
    supervisor
        .append_journal(&saga_id, SagaState::PreparingB, &participants, 2, &evidence)
        .await
        .expect("journal PreparingB");

    // The caller stays RESIDENT (as a restore-before-replay ordering would
    // surface it). Drive the REAL crash-recovery path.
    let entry = JournalEntry {
        saga_id: saga_id.clone(),
        state: SagaState::PreparingB,
        participants: participants.clone(),
        evidence: Zeroizing::new(evidence),
        timestamp_ms: supervisor.clock_ref().expect("clock").now_millis(),
        seq_per_saga: 2,
    };
    supervisor.recover_saga_entry(entry).await;

    // The record-based reversal RAN: the hard-rate-limit token is refunded to
    // full burst and the durable record is consumed.
    let snap = flush_and_read_snapshot(&supervisor, &persistence, XCTX_CALLER).await;
    let token_after = snap
        .hard_rate_limit_state
        .get(caller_did)
        .map(|(tokens, _)| *tokens)
        .expect("hard-rate-limit entry present after recovery");
    assert_eq!(
        token_after, burst_milli,
        "the resident-caller PreparingB recovery MUST reverse the caller's LOCAL economy from \
             the durable record (refund to full burst) — the caller is NOT over-charged"
    );
    assert!(
        !snap.xctx_caller_reservations.contains_key(&saga_id),
        "the durable record MUST be consumed by the record-based reversal"
    );

    // The reversal was CONFIRMED, so the journal IS marked terminal-Aborted:
    // the saga drops out of load_unresolved.
    let unresolved = supervisor
        .saga_journal
        .load_unresolved()
        .await
        .expect("load_unresolved");
    assert!(
        !unresolved.iter().any(|e| e.saga_id == saga_id),
        "a CONFIRMED caller reversal lets recovery mark the journal terminal-Aborted (the \
             saga is resolved, no longer in load_unresolved)"
    );
}

/// §17.16.4 restore-then-replay START-UP path (ADR-049) — the
/// crash-recovery GATE for the cross-context caller reversal over a RESIDENT
/// caller. Drives the SINGLE production startup entry point
/// [`Supervisor::restore_on_startup`] (NOT `recover_saga_entry` directly)
/// over a REAL persistence provider and asserts the xctx-caller-reversal path
/// (the genuine length-3 `[caller_hex, caller_did, outlet_id]` triple →
/// `recover_preparing_b_entry` → `redrive_caller_local_reversal`) ends the
/// journal entry TERMINAL-`Aborted` with the caller's LOCAL economy refund
/// DELIVERED (the durable `CallerReservationRecord` consumed, the
/// hard-rate-limit token refunded to full burst).
///
/// **Scope (no over-claim).** This test pins the IN-PASS reversal +
/// terminal-`Aborted` resolution when the caller is already resident; it is
/// NOT order-discriminating. The caller here is pre-spawned and
/// `CapturingPersistence::list_persisted_contexts` is empty, so restore is a
/// no-op and the replay leg would deliver the reversal regardless of the
/// restore/replay order — running replay first would NOT change this test's
/// outcome. The restore-THEN-replay ORDERING is enforced elsewhere: by the
/// TYPE SYSTEM (`replay_unresolved_sagas` requires the `&RestoredContexts`
/// witness `restore_all_contexts` mints — a reorder does not compile) and by
/// the structural gate `restore_on_startup_runs_restore_before_replay`. The
/// genuinely order-discriminating behavioral proof — where the caller is
/// restored FROM PERSISTENCE in-pass and the reversal would miss it under
/// replay-first — is
/// `restore_on_startup_restores_caller_from_persistence_then_delivers_reversal`.
/// This test complements that one by exercising the genuine FSM triple over a
/// resident caller end-to-end through `restore_on_startup`.
#[tokio::test]
async fn restore_on_startup_xctx_caller_reversal_delivered_entry_terminal() {
    let creator_did = "did:dht:z6MkRestoreReplayResCreator";
    let caller_did = "did:dht:z6MkRestoreReplayResCaller";
    let saga_id = SagaId("restore-replay-resident-saga".to_owned());
    // Resident-caller gate: the caller is pre-spawned and the (default,
    // restore-DISABLED) capturing persistence lists no contexts, so the
    // restore leg is a no-op and the replay leg drives the reversal against
    // the already-resident caller.
    let (supervisor, persistence, _caller_hex, burst_milli) = stage_xctx_preparing_b_crash(
        creator_did,
        5,
        caller_did,
        &saga_id,
        CapturingPersistence::default(),
    )
    .await;

    // Pre-condition: the saga is unresolved (the crash left it at PreparingB).
    let pre = supervisor
        .saga_journal
        .load_unresolved()
        .await
        .expect("load_unresolved pre");
    assert!(
        pre.iter().any(|e| e.saga_id == saga_id),
        "the crashed saga must be unresolved before startup recovery"
    );

    // DRIVE THE PRODUCTION STARTUP ENTRY POINT against a RESIDENT caller. The
    // caller is pre-spawned and `CapturingPersistence::list_persisted_contexts`
    // is empty, so the restore leg is a no-op and the replay leg drives the
    // record-keyed reversal against the already-resident caller. This exercises
    // the in-pass reversal through `restore_on_startup` end-to-end with the
    // genuine FSM triple — it does NOT discriminate restore-vs-replay order
    // (the order is type-enforced + structurally gated; see the doc-comment
    // and the `_restores_caller_from_persistence_` sibling test).
    let restored = supervisor
        .restore_on_startup()
        .await
        .expect("restore_on_startup must succeed (real persistence, empty context list)");
    assert!(
        restored.is_empty(),
        "the capturing persistence lists no contexts to restore; the live caller stays \
             resident for the replay leg"
    );

    // GATE 1 — the refund is DELIVERED: the hard-rate-limit token is refunded
    // to full burst and the durable record consumed (the in-pass reversal ran
    // against the resident caller).
    let snap = flush_and_read_snapshot(&supervisor, &persistence, XCTX_CALLER).await;
    let token_after = snap
        .hard_rate_limit_state
        .get(caller_did)
        .map(|(tokens, _)| *tokens)
        .expect("hard-rate-limit entry present after restore_on_startup");
    assert_eq!(
        token_after, burst_milli,
        "restore_on_startup MUST reverse the caller's LOCAL economy from the durable record \
             (refund to full burst) — the refund is DELIVERED, NOT stranded"
    );
    assert!(
        !snap.xctx_caller_reservations.contains_key(&saga_id),
        "the durable CallerReservationRecord MUST be consumed by the startup reversal"
    );

    // GATE 2 — the entry ends TERMINAL-Aborted: a CONFIRMED reversal lets the
    // replay leg mark the journal resolved, so it drops out of load_unresolved.
    let unresolved = supervisor
        .saga_journal
        .load_unresolved()
        .await
        .expect("load_unresolved post");
    assert!(
        !unresolved.iter().any(|e| e.saga_id == saga_id),
        "after restore_on_startup the xctx-caller saga MUST be terminal-Aborted (resolved, \
             no longer in load_unresolved) — the refund-delivered + entry-terminal gate"
    );
}

/// §17.16.4 restore-then-replay START-UP path (ADR-049) — the
/// genuinely ORDER-DISCRIMINATING behavioral proof. Unlike
/// `restore_on_startup_xctx_caller_reversal_delivered_entry_terminal` (whose
/// caller is pre-spawned + persistence empty, so it would pass under either
/// order), HERE the caller is RESTORED FROM PERSISTENCE during the same
/// startup pass: it is despawned before `restore_on_startup` and resurrected
/// by the restore leg, carrying its durably-staged `CallerReservationRecord`.
/// The replay leg then drives the record-keyed reversal against the
/// now-resident caller, delivering the refund and resolving the journal.
///
/// This is order-discriminating because a replay-BEFORE-restore ordering
/// would run the reversal while the caller was still despawned (the restore
/// had not yet resurrected it), the `lookup` would miss, and the journal
/// would be LEFT non-terminal with the refund stranded for the next process
/// start (the exact stranding the resident test cannot exhibit). The
/// restore-then-replay ordering — enforced by the `RestoredContexts` type
/// witness and threaded by `restore_on_startup` — is what makes the reversal
/// land in this single pass.
#[tokio::test]
async fn restore_on_startup_restores_caller_from_persistence_then_delivers_reversal() {
    let creator_did = "did:dht:z6MkRestoreReplayFromPersistCreator";
    let caller_did = "did:dht:z6MkRestoreReplayFromPersistCaller";
    let saga_id = SagaId("restore-from-persistence-saga".to_owned());
    // RESTORE-ENABLED capturing persistence: `list_persisted_contexts` lists
    // the flushed snapshots, so `restore_all_contexts` resurrects the caller.
    // The shared staging flushes the caller's Active snapshot (asserting it is
    // Active) + the durable reservation record before journaling PreparingB.
    let (supervisor, persistence, caller_hex, burst_milli) = stage_xctx_preparing_b_crash(
        creator_did,
        5,
        caller_did,
        &saga_id,
        CapturingPersistence::with_restore(),
    )
    .await;

    // DESPAWN the caller actor: model a crash where the caller is NOT yet
    // resident at process start. The reversal can only be delivered once
    // RESTORE resurrects it — so this exercises the restore-leg-first ordering.
    assert!(
        supervisor.actors.remove(&caller_hex).is_some(),
        "despawn the caller so it must be RESTORED FROM PERSISTENCE before the reversal"
    );
    assert!(
        supervisor.lookup(&caller_hex).is_none(),
        "the caller is non-resident immediately before restore_on_startup"
    );

    // Pre-condition: the saga is unresolved (the crash left it at PreparingB).
    let pre = supervisor
        .saga_journal
        .load_unresolved()
        .await
        .expect("load_unresolved pre");
    assert!(
        pre.iter().any(|e| e.saga_id == saga_id),
        "the crashed saga must be unresolved before startup recovery"
    );

    // DRIVE THE PRODUCTION STARTUP ENTRY POINT. restore_all_contexts lists the
    // flushed caller, loads its snapshot, and resurrects its actor (with the
    // durable reservation) — THEN replay drives the record-keyed reversal
    // against the now-resident caller. Replay-before-restore would miss the
    // still-despawned caller and strand the refund.
    let restored = supervisor
        .restore_on_startup()
        .await
        .expect("restore_on_startup must succeed");
    assert!(
        restored.iter().any(|id| id == &caller_hex),
        "the restore leg MUST resurrect the caller from persistence in this pass, got {restored:?}"
    );
    assert!(
        supervisor.lookup(&caller_hex).is_some(),
        "the caller actor must be RESIDENT after restore_on_startup (restored from persistence)"
    );

    // GATE 1 — the refund is DELIVERED against the freshly-RESTORED caller: the
    // hard-rate-limit token is refunded to full burst and the durable record
    // consumed. This is the order-discriminating assertion: it can only hold
    // because restore ran BEFORE replay (resurrecting the caller first).
    let snap = flush_and_read_snapshot(&supervisor, &persistence, XCTX_CALLER).await;
    let token_after = snap
        .hard_rate_limit_state
        .get(caller_did)
        .map(|(tokens, _)| *tokens)
        .expect("hard-rate-limit entry present after restore_on_startup");
    assert_eq!(
        token_after, burst_milli,
        "restore_on_startup MUST restore the caller THEN reverse its LOCAL economy from the \
             durable record (refund to full burst) — delivered in-pass, NOT stranded"
    );
    assert!(
        !snap.xctx_caller_reservations.contains_key(&saga_id),
        "the durable CallerReservationRecord MUST be consumed by the in-pass reversal against \
             the restored caller"
    );

    // GATE 2 — the entry ends TERMINAL-Aborted: a CONFIRMED reversal lets the
    // replay leg mark the journal resolved, so it drops out of load_unresolved.
    let unresolved = supervisor
        .saga_journal
        .load_unresolved()
        .await
        .expect("load_unresolved post");
    assert!(
        !unresolved.iter().any(|e| e.saga_id == saga_id),
        "after restore-from-persistence-then-replay the xctx-caller saga MUST be terminal- \
             Aborted (resolved) — restore made the caller resident so the reversal landed in-pass"
    );
}

/// §17.16.4 restore-then-replay START-UP path — the genuinely-undeliverable
/// SIBLING of the gate test above. The caller context is PERMANENTLY DELETED
/// (absent from durable persistence), so its `CallerReservationRecord` died
/// with the context and there is nothing to reverse. Driving
/// [`Supervisor::restore_on_startup`] must REAP the entry to terminal-
/// `Aborted` via the `caller_context_deleted_from_persistence` `Ok(None)`
/// reap branch — NOT loop forever non-terminal. This pins the
/// reap-vs-stay-non-terminal decision through the production startup path.
#[tokio::test]
async fn restore_on_startup_xctx_deleted_caller_is_reaped_terminal() {
    use crate::context::supervisor::saga_journal::{SagaId, SagaState};

    let creator_did = "did:dht:z6MkRestoreReplayDelCreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let (supervisor, _persistence) =
        xctx_supervisor_with_real_journal(creator_did.clone(), creator_key);

    // NOTE: we do NOT spawn the caller context, and `CapturingPersistence`
    // has no snapshot for it — so it is ABSENT from durable persistence
    // (the permanently-deleted case). The journal still names the caller in
    // the genuine length-3 triple.
    let caller_hex = hex::encode(XCTX_CALLER);
    let caller_did = "did:dht:z6MkRestoreReplayDelCaller";
    let saga_id = SagaId("restore-replay-deleted-saga".to_owned());
    let participants = vec![
        caller_hex.clone(),
        caller_did.to_owned(),
        XCTX_OUTLET.to_owned(),
    ];

    supervisor
        .append_journal(&saga_id, SagaState::Initiated, &participants, 0, &[])
        .await
        .expect("journal Initiated");
    supervisor
        .append_journal(&saga_id, SagaState::PreparingB, &participants, 1, &[])
        .await
        .expect("journal PreparingB");

    let pre = supervisor
        .saga_journal
        .load_unresolved()
        .await
        .expect("load_unresolved pre");
    assert!(
        pre.iter().any(|e| e.saga_id == saga_id),
        "the saga must be unresolved before startup recovery"
    );

    // Drive the production startup path. Restore succeeds (empty list); the
    // replay leg finds the caller ABSENT from persistence and reaps the entry.
    supervisor
        .restore_on_startup()
        .await
        .expect("restore_on_startup must succeed");

    let unresolved = supervisor
        .saga_journal
        .load_unresolved()
        .await
        .expect("load_unresolved post");
    assert!(
        !unresolved.iter().any(|e| e.saga_id == saga_id),
        "a PERMANENTLY-DELETED caller (absent from persistence) MUST be reaped to \
             terminal-Aborted by restore_on_startup — NOT left to never-reap"
    );
}

/// §6.2.4 review wave-23 — CRASH-RECOVERY in the `PreparingA` window.
/// The FSM journals `PreparingA` (seq 1) BEFORE dispatching Prepare-A, and
/// Prepare-A DURABLY persists the caller deduction + the
/// `CallerReservationRecord` into the Class-S snapshot BEFORE the FSM appends
/// the `PreparingB` entry (seq 2). A crash in that window leaves the journal's
/// latest state at `PreparingA` over a LIVE durable reservation.
///
/// PRE-FIX the `recover_saga_entry` arm treated `Initiated | PreparingA`
/// identically and marked terminal-`Aborted` UNCONDITIONALLY ("no remote
/// side-effects yet"). For `PreparingA` that is FALSE: the terminal marker
/// asserts "fully compensated" while the caller deduction + record are still
/// live, so the §17.16.4 sweep (which re-drives ONLY non-terminal journals)
/// can never reverse them — a permanent silent over-charge + leaked record.
///
/// The fix routes `PreparingA` through the SAME record-keyed reversal-and-
/// confirm path as `PreparingB` (`recover_preparing_b_entry`). A `PreparingA`
/// xctx entry journals the SAME caller-provenance TRIPLE
/// (`saga_input_participants`: `[caller_hex, caller_did, outlet_id]`) and EMPTY
/// evidence (`&[]`), so `reconstruct_xctx_prepared` returns `None` and the
/// participant-keyed `redrive_caller_local_reversal` reverses the caller's
/// LOCAL economy from the durable record. RESIDENT caller (this test): the
/// re-drive DELIVERS, the record is reversed + consumed, and ONLY THEN the
/// journal is marked terminal-`Aborted`. PRE-FIX the deduction was stranded
/// and the record leaked.
#[tokio::test]
#[allow(clippy::too_many_lines)] // full recovery E2E: reserve + journal + recover + assert
async fn crash_recovery_preparing_a_resident_caller_reverses_then_marks_terminal() {
    use crate::context::supervisor::saga_journal::{SagaId, SagaState};

    let creator_did = "did:dht:z6MkXctxWave23PrepACreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let (supervisor, persistence) =
        xctx_supervisor_with_real_journal(creator_did.clone(), creator_key);
    let caller_did = "did:dht:z6MkXctxWave23PrepACaller";
    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    let caller_hex = hex::encode(XCTX_CALLER);
    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let saga_id = SagaId("wave23-preparing-a-resident-saga".to_owned());
    // The REAL FSM journals a cross-context entry's participants as the
    // caller-provenance TRIPLE `[caller_hex, caller_did, outlet_id]`
    // (`saga_input_participants`), NOT the 2-element `[caller, target]` set
    // the wave-15 PreparingB tests hand-built (they relied on the
    // evidence-reconstruction path). A PreparingA entry has EMPTY evidence, so
    // the reversal MUST come through the participant-keyed path — which
    // REQUIRES the genuine length-3 triple here.
    let participants = vec![
        caller_hex.clone(),
        caller_did.to_owned(),
        XCTX_OUTLET.to_owned(),
    ];

    let mut ctx = CrossContextSagaCtx {
        caller_context_id: XCTX_CALLER,
        target_context_id: XCTX_TARGET,
        caller_did: DID(caller_did.to_owned()),
        outlet_registration_id: XCTX_OUTLET.to_owned(),
        ucan_proof_id: None,
        input: serde_json::json!({ "a": 1, "b": 2 }),
        asserted_chain_depth: 2,
        asserted_nonce: [0x42u8; 16],
        asserted_timestamp_ms: supervisor.clock_ref().expect("clock").now_millis(),
        caller_source_role: None,
        target_signer: CommandSigner::local_ed25519(target_signing),
        caller_signer: CommandSigner::local_ed25519(caller_signing),
        executor: Some(Box::new(|_v: serde_json::Value| {
            Box::pin(async move { Ok(serde_json::json!({ "result": 3 })) }) as _
        })),
        executor_output: None,
        prepared_a: None,
        prepared_b: None,
        committed: None,
        committed_b_outlet_invoked_event_id: None,
        reached_needs_repair: false,
    };

    // Journal `Initiated` (seq 0) then `PreparingA` (seq 1) with EMPTY
    // evidence — EXACTLY the FSM's pre-dispatch journal shape (the FSM appends
    // `PreparingA` with `&[]` BEFORE `dispatch_prepare_phase(A)`).
    supervisor
        .append_journal(&saga_id, SagaState::Initiated, &participants, 0, &[])
        .await
        .expect("journal Initiated");
    supervisor
        .append_journal(&saga_id, SagaState::PreparingA, &participants, 1, &[])
        .await
        .expect("journal PreparingA");

    // Real Prepare-A: durably stages the caller deduction + reservation
    // record on the live caller actor (the durable state a crash in the
    // PreparingA window leaves behind). Balance the returned carrier
    // immediately (lost-reply shape) so its #[must_use] drop guard does not
    // fire; the durable record is what recovery reverses.
    supervisor
        .dispatch_xctx_prepare_a(&saga_id, &mut ctx)
        .await
        .expect("Prepare-A stages a real reservation");
    let burst_milli = {
        let snap = flush_and_read_snapshot(&supervisor, &persistence, XCTX_CALLER).await;
        let token_after_reserve = snap
            .hard_rate_limit_state
            .get(caller_did)
            .map(|(tokens, _)| *tokens)
            .expect("reserve created a hard-rate-limit entry");
        assert!(
            snap.xctx_caller_reservations.contains_key(&saga_id),
            "Prepare-A staged the durable caller reservation record"
        );
        token_after_reserve + 1000 // one token = 1000 milli-tokens
    };
    if let Some(prepared) = ctx.prepared_a.take() {
        prepared
            .reservation
            .ticket
            .void_external_and_consume(supervisor.payment_adapter_ref())
            .await;
    }

    // Drive the REAL crash-recovery dispatcher on a `PreparingA` entry with
    // EMPTY evidence (the genuine FSM journal shape). The caller stays
    // RESIDENT (restore-before-replay ordering).
    let entry = JournalEntry {
        saga_id: saga_id.clone(),
        state: SagaState::PreparingA,
        participants: participants.clone(),
        evidence: Zeroizing::new(Vec::new()),
        timestamp_ms: supervisor.clock_ref().expect("clock").now_millis(),
        seq_per_saga: 1,
    };
    supervisor.recover_saga_entry(entry).await;

    // CORE: the record-based reversal RAN — the hard-rate-limit token is
    // refunded to full burst and the durable record is consumed. PRE-FIX the
    // PreparingA arm marked terminal-Aborted WITHOUT reversing, so the token
    // stayed deducted and the record leaked ⇒ these assertions FAIL.
    let snap = flush_and_read_snapshot(&supervisor, &persistence, XCTX_CALLER).await;
    let token_after = snap
        .hard_rate_limit_state
        .get(caller_did)
        .map(|(tokens, _)| *tokens)
        .expect("hard-rate-limit entry present after recovery");
    assert_eq!(
        token_after, burst_milli,
        "the resident-caller PreparingA recovery MUST reverse the caller's LOCAL economy from \
             the durable record (refund to full burst) — the caller is NOT over-charged. PRE-FIX \
             the unconditional-Aborted PreparingA arm stranded this deduction forever"
    );
    assert!(
        !snap.xctx_caller_reservations.contains_key(&saga_id),
        "the durable CallerReservationRecord MUST be consumed by the PreparingA recovery \
             reversal (PRE-FIX it leaked — the arm never touched it)"
    );

    // The reversal was CONFIRMED, so the journal IS marked terminal-Aborted
    // and the saga drops out of load_unresolved.
    let unresolved = supervisor
        .saga_journal
        .load_unresolved()
        .await
        .expect("load_unresolved");
    assert!(
        !unresolved.iter().any(|e| e.saga_id == saga_id),
        "a CONFIRMED caller reversal lets PreparingA recovery mark the journal terminal-\
             Aborted (the saga is resolved, no longer in load_unresolved)"
    );
}

/// §6.2.4 review wave-23 companion — `PreparingA` crash with a NON-RESIDENT
/// caller (despawned before recovery, modelling `replay_unresolved_sagas`
/// running before the caller is restored). The record-keyed re-drive `lookup`
/// misses ⇒ the reversal is outstanding ⇒ the journal MUST be LEFT
/// non-terminal at `PreparingA` so a later sweep re-drives it after a respawn.
/// PRE-FIX the unconditional-Aborted arm marked it terminal, dropping it out
/// of `load_unresolved` and stranding the durable deduction forever.
#[tokio::test]
#[allow(clippy::too_many_lines)] // full recovery E2E: reserve + journal + despawn + recover + assert
async fn crash_recovery_preparing_a_non_resident_caller_left_non_terminal() {
    use crate::context::supervisor::saga_journal::{SagaId, SagaState};

    let creator_did = "did:dht:z6MkXctxWave23PrepANonResCreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let (supervisor, persistence) =
        xctx_supervisor_with_real_journal(creator_did.clone(), creator_key);
    let caller_did = "did:dht:z6MkXctxWave23PrepANonResCaller";
    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    let caller_hex = hex::encode(XCTX_CALLER);
    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let saga_id = SagaId("wave23-preparing-a-nonresident-saga".to_owned());
    let participants = vec![
        caller_hex.clone(),
        caller_did.to_owned(),
        XCTX_OUTLET.to_owned(),
    ];

    let mut ctx = CrossContextSagaCtx {
        caller_context_id: XCTX_CALLER,
        target_context_id: XCTX_TARGET,
        caller_did: DID(caller_did.to_owned()),
        outlet_registration_id: XCTX_OUTLET.to_owned(),
        ucan_proof_id: None,
        input: serde_json::json!({ "a": 1, "b": 2 }),
        asserted_chain_depth: 2,
        asserted_nonce: [0x42u8; 16],
        asserted_timestamp_ms: supervisor.clock_ref().expect("clock").now_millis(),
        caller_source_role: None,
        target_signer: CommandSigner::local_ed25519(target_signing),
        caller_signer: CommandSigner::local_ed25519(caller_signing),
        executor: Some(Box::new(|_v: serde_json::Value| {
            Box::pin(async move { Ok(serde_json::json!({ "result": 3 })) }) as _
        })),
        executor_output: None,
        prepared_a: None,
        prepared_b: None,
        committed: None,
        committed_b_outlet_invoked_event_id: None,
        reached_needs_repair: false,
    };

    supervisor
        .append_journal(&saga_id, SagaState::Initiated, &participants, 0, &[])
        .await
        .expect("journal Initiated");
    supervisor
        .append_journal(&saga_id, SagaState::PreparingA, &participants, 1, &[])
        .await
        .expect("journal PreparingA");

    supervisor
        .dispatch_xctx_prepare_a(&saga_id, &mut ctx)
        .await
        .expect("Prepare-A stages a real reservation");
    if let Some(prepared) = ctx.prepared_a.take() {
        prepared
            .reservation
            .ticket
            .void_external_and_consume(supervisor.payment_adapter_ref())
            .await;
    }
    let snap_before = flush_and_read_snapshot(&supervisor, &persistence, XCTX_CALLER).await;
    assert!(
        snap_before.xctx_caller_reservations.contains_key(&saga_id),
        "Prepare-A staged the durable caller reservation record"
    );

    // Despawn the caller BEFORE recovery so the record-keyed re-drive lookup
    // misses (restore-after-replay ordering). The caller context's snapshot
    // is STILL PRESENT in persistence (it was not deleted), so recovery must
    // distinguish "not yet restored" from "permanently deleted" and leave the
    // journal non-terminal (NOT reap it).
    assert!(
        supervisor.actors.remove(&caller_hex).is_some(),
        "caller actor despawned to simulate restore-after-replay ordering"
    );

    let entry = JournalEntry {
        saga_id: saga_id.clone(),
        state: SagaState::PreparingA,
        participants: participants.clone(),
        evidence: Zeroizing::new(Vec::new()),
        timestamp_ms: supervisor.clock_ref().expect("clock").now_millis(),
        seq_per_saga: 1,
    };
    supervisor.recover_saga_entry(entry).await;

    // The journal MUST stay NON-terminal at PreparingA (still in
    // load_unresolved) so the next sweep — after the caller is restored —
    // re-drives the reversal. PRE-FIX recover_saga_entry marked terminal-
    // Aborted UNCONDITIONALLY, stranding the durable deduction forever.
    let unresolved = supervisor
        .saga_journal
        .load_unresolved()
        .await
        .expect("load_unresolved");
    let found = unresolved.iter().find(|e| e.saga_id == saga_id).expect(
        "the non-resident-caller PreparingA saga MUST remain UNRESOLVED (not terminal-Aborted) \
             so a later crash-recovery sweep re-drives the caller's LOCAL economy reversal",
    );
    assert_eq!(
        found.state,
        SagaState::PreparingA,
        "the journal must stay at the sweep-redrivable PreparingA state, not advance to \
             terminal-Aborted while the caller reversal is outstanding"
    );
    // The durable record is UNTOUCHED (reversal never ran against the missing
    // actor), so a respawn + sweep can still reverse it.
    let snap_after = persistence
        .snapshots
        .get(&caller_hex)
        .map(|e| e.value().clone())
        .expect("the despawned caller's last persisted snapshot is retained");
    assert!(
        snap_after.xctx_caller_reservations.contains_key(&saga_id),
        "the durable record survives a non-resident-caller PreparingA recovery so the next \
             sweep can still reverse it (the reversal did not silently run against a missing actor)"
    );
}

/// HIGH 2 (§6.2.4 review wave-14): `abort_xctx_participants` with
/// `ctx.prepared_a == None` MUST still reconcile the durable
/// `CallerReservationRecord`. The carrier is `None` whenever the Prepare-A
/// REPLY was lost — e.g. the `dispatch_prepare_phase` 30s `PHASE_TIMEOUT`
/// fired and dropped the supervisor's reply receiver EVEN THOUGH the caller
/// actor already durably persisted the deduction + record. Pre-fix the `else`
/// branch returned `SettledOrAbsent` WITHOUT consulting the record or sending
/// anything, so the abort marked the saga terminal-`Aborted` while the caller
/// stayed over-charged forever (the §17.16.4 sweep re-drives only NON-terminal
/// journals). The fix drives a record-based `Abort { None }` (the same path
/// `redrive_caller_local_reversal` uses) so EVERY abort path reconciles the
/// record before `mark_resolved(Aborted)`.
///
/// We Prepare-A on a live caller (staging the durable record + deduction),
/// then BALANCE + DROP the in-memory carrier exactly as a lost-reply
/// supervisor would (so `ctx.prepared_a == None` over a real durable
/// deduction), then call `abort_xctx_participants` directly. The captured
/// snapshot MUST show the hard-rate-limit token refunded to full burst and the
/// record consumed. PRE-FIX it returns `SettledOrAbsent` and the token stays
/// deducted ⇒ FAIL.
#[tokio::test]
async fn abort_with_lost_carrier_reconciles_durable_record() {
    let creator_did = "did:dht:z6MkXctxHigh2Creator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let persistence = CapturingPersistence::default();
    let supervisor = xctx_supervisor_with_persistence(
        creator_did.clone(),
        creator_key,
        Box::new(persistence.clone()),
    );
    let caller_did = "did:dht:z6MkXctxHigh2Caller";
    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let saga_id = SagaId("high2-lost-carrier-saga".to_owned());

    let mut ctx = CrossContextSagaCtx {
        caller_context_id: XCTX_CALLER,
        target_context_id: XCTX_TARGET,
        caller_did: DID(caller_did.to_owned()),
        outlet_registration_id: XCTX_OUTLET.to_owned(),
        ucan_proof_id: None,
        input: serde_json::json!({ "a": 1, "b": 2 }),
        asserted_chain_depth: 2,
        asserted_nonce: [0x42u8; 16],
        asserted_timestamp_ms: supervisor.clock_ref().expect("clock").now_millis(),
        caller_source_role: None,
        target_signer: CommandSigner::local_ed25519(target_signing.clone()),
        caller_signer: CommandSigner::local_ed25519(caller_signing.clone()),
        executor: Some(Box::new(|_v: serde_json::Value| {
            Box::pin(async move { Ok(serde_json::json!({ "result": 3 })) }) as _
        })),
        executor_output: None,
        prepared_a: None,
        prepared_b: None,
        committed: None,
        committed_b_outlet_invoked_event_id: None,
        reached_needs_repair: false,
    };

    // Real Prepare-A: stages the durable record + deduction on the live
    // caller and returns the must-use carrier into `ctx.prepared_a`.
    supervisor
        .dispatch_xctx_prepare_a(&saga_id, &mut ctx)
        .await
        .expect("Prepare-A stages a real reservation");
    assert!(ctx.prepared_a.is_some(), "Prepare-A held a reservation");

    // Baseline: the reserve moved owned state and staged the record.
    let burst_milli = {
        let snap = flush_and_read_snapshot(&supervisor, &persistence, XCTX_CALLER).await;
        let token_after_reserve = snap
            .hard_rate_limit_state
            .get(caller_did)
            .map(|(tokens, _)| *tokens)
            .expect("reserve created a hard-rate-limit entry");
        assert!(
            snap.xctx_caller_reservations.contains_key(&saga_id),
            "Prepare-A staged the durable caller reservation record"
        );
        let burst = token_after_reserve + 1000; // one token = 1000 milli-tokens
        assert!(token_after_reserve < burst, "reserve consumed a token");
        burst
    };

    // Simulate the LOST Prepare-A reply: the supervisor never received the
    // carrier (phase-timeout dropped the reply receiver). A lost-carrier
    // supervisor balances the recovered must-use ticket (void escrow +
    // consume) and leaves `ctx.prepared_a == None` over the real durable
    // deduction. We reproduce exactly that state.
    if let Some(prepared) = ctx.prepared_a.take() {
        prepared
            .reservation
            .ticket
            .void_external_and_consume(supervisor.payment_adapter_ref())
            .await;
    }
    assert!(
        ctx.prepared_a.is_none(),
        "the lost-carrier state has prepared_a == None over a durable deduction"
    );

    // Drive the abort. The fix's `else` branch re-drives `Abort { None }`,
    // reversing the caller's LOCAL economy from the durable record.
    let verdict = supervisor.abort_xctx_participants(&saga_id, &mut ctx).await;
    assert_eq!(
        verdict,
        CallerAbortReversal::SettledOrAbsent,
        "a delivered record-based Abort{{None}} settles the caller reversal"
    );

    // CORE: the caller's LOCAL economy IS reversed and the record consumed.
    // PRE-FIX the else branch returned SettledOrAbsent without driving
    // anything, so the token stays deducted and the record stays present.
    let snap = flush_and_read_snapshot(&supervisor, &persistence, XCTX_CALLER).await;
    let token_after_abort = snap
        .hard_rate_limit_state
        .get(caller_did)
        .map(|(tokens, _)| *tokens)
        .expect("hard-rate-limit entry present after abort");
    assert_eq!(
        token_after_abort, burst_milli,
        "the prepared_a==None abort MUST reverse the caller's LOCAL economy from the \
             durable record (refund to full burst) — the caller is NOT over-charged"
    );
    assert!(
        !snap.xctx_caller_reservations.contains_key(&saga_id),
        "the durable record MUST be consumed by the record-based reversal"
    );
}

/// §17.16.4 Prepare-in-progress replay aborts the Prepared side(s) and
/// discards — never re-Prepares. We Prepare-B (staging the target's
/// `saga_pending` session slot keyed by the saga id), then run the
/// Prepare-in-progress recovery re-drive, which sends `Abort` to the target
/// to RELEASE the staged slot. We then confirm the slot is gone: a
/// subsequent Commit-B reserve for that saga finds NO staged prepared
/// (SCP-SAGA-13030), proving the recovery released-and-discarded it. The
/// outlet never executes (no Commit ever ran).
#[tokio::test]
async fn xctx_replay_prepare_in_progress_releases_and_discards() {
    use crate::context::actor::commands::SagaPhaseMessage;
    use crate::context::supervisor::saga_journal::SagaId;
    use crate::context::supervisor::saga_prepared_state::CrossContextOutletInvocationPrepared;

    let creator_did = "did:dht:z6MkXctxPrepReplayCreator".to_owned();
    let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let supervisor = xctx_supervisor(creator_did.clone(), creator_key);
    let caller_did = "did:dht:z6MkXctxPrepReplayCaller";
    let caller_state = xctx_caller_state(caller_did, &creator_did);
    let target_state = xctx_target_state(caller_did, &creator_did);
    Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

    let saga_id = SagaId::new();

    // Stage Prepare-B on the target actor: this stages the eight-field
    // prepared into `saga_pending`, keyed by the saga id (the session slot
    // the recovery Abort releases).
    let target = supervisor
        .lookup(&hex::encode(XCTX_TARGET))
        .expect("target co-resident");
    let prepare_saga_id = saga_id.clone();
    let prepare_did = DID(caller_did.to_owned());
    let prepare_now_ms = supervisor.clock_ref().expect("clock").now_millis();
    target
        .send(move |reply| {
            ContextCommand::SagaPhase(SagaPhaseMessage::PrepareB {
                saga_id: prepare_saga_id,
                caller_context_id: XCTX_CALLER,
                target_context_id: XCTX_TARGET,
                caller_did: prepare_did,
                outlet_registration_id: XCTX_OUTLET.to_owned(),
                ucan_proof_id: None,
                input: serde_json::json!({ "a": 1, "b": 2 }),
                asserted_chain_depth: 2,
                asserted_nonce: [0x99u8; 16],
                asserted_timestamp_ms: prepare_now_ms,
                caller_source_role: None,
                reply,
            })
        })
        .await
        .expect("Prepare-B stages the target session slot");

    // Run the Prepare-in-progress recovery re-drive: it aborts the prepared
    // side(s), releasing the target's staged `saga_pending` slot.
    let prepared = CrossContextOutletInvocationPrepared {
        caller_context_id: XCTX_CALLER,
        target_context_id: XCTX_TARGET,
        caller_did: DID(caller_did.to_owned()),
        outlet_registration_id: XCTX_OUTLET.to_owned(),
        ucan_proof_id: String::new(),
        recorded_timestamp_ms: 1,
        recorded_nonce: [0x99u8; 16],
        recorded_chain_depth: 3,
    };
    let verdict = Box::pin(supervisor.redrive_xctx_prepare_in_progress(&saga_id, &prepared)).await;
    // The caller actor is resident and Prepare-A never staged a reservation
    // here, so the caller-side `Abort { None }` is delivered to a clean
    // record no-op: the reversal is settled (`SettledOrAbsent`), which is the
    // verdict that lets `recover_saga_entry` mark the journal terminal.
    assert_eq!(
        verdict,
        CallerAbortReversal::SettledOrAbsent,
        "a resident caller with no staged reservation settles the reversal (clean no-op)"
    );

    // The staged slot was RELEASED: a Commit-B reserve for this saga now
    // finds NO staged prepared (the recovery discarded it; it was never
    // re-Prepared).
    let reserve_saga_id = saga_id.clone();
    let reserve = target
        .send(move |reply| {
            ContextCommand::SagaPhase(SagaPhaseMessage::CommitBReserve {
                saga_id: reserve_saga_id,
                reply,
            })
        })
        .await;
    assert!(
        matches!(
            &reserve,
            Err(ContextError::InvalidState(m)) if m.contains("SCP-SAGA-13030")
        ),
        "after Prepare-in-progress recovery the staged slot must be released (no staged \
             prepared on Commit-B reserve), got {reserve:?}"
    );
}

/// The NeedsRepair `run_saga` tail HOLDS the escrow reserved (does NOT void
/// it) for operator repair, while every other terminal voids/settles it
/// (spec §6.2.4 "`NeedsRepair` reservation semantics"). Exercised directly
/// on the ticket primitive: `hold_external_for_repair` consumes the carrier
/// (no unbalanced-drop panic) WITHOUT voiding the external escrow, distinct
/// from `void_external_and_consume`.
#[test]
fn needs_repair_holds_escrow_without_voiding() {
    // A no-escrow ticket: `hold_external_for_repair` simply consumes it so
    // its `#[must_use]` drop guard does not fire (no panic). The semantic
    // difference from voiding is documented + asserted by the no-panic drop:
    // had the carrier been dropped WITHOUT being consumed, the debug-assert
    // in `OutletEconomyTicket::drop` would fire.
    let ticket = crate::context::shared::outlets::OutletEconomyTicket::new_for_test_no_escrow(DID(
        "did:dht:z6MkHoldRepair".to_owned(),
    ));
    ticket.hold_external_for_repair();
    // Reaching here without a drop-guard panic proves the carrier was marked
    // consumed (held for repair), not leaked.
}

fn void_counting_auth(
    payer: &DID,
    payee: &DID,
    amount: scp_protocol::economy::types::Amount,
    currency: scp_protocol::economy::types::CurrencyCode,
) -> crate::economy::adapter::PaymentAuthorization {
    crate::economy::adapter::PaymentAuthorization {
        auth_id: [9u8; 32],
        payer: payer.clone(),
        payee: payee.clone(),
        amount,
        currency,
        adapter_id: "void-counting".to_owned(),
        created_at: 1_000_000,
        expires_at: 2_000_000,
        adapter_state: vec![],
    }
}

/// A supervisor whose `payment_adapter_ref()` returns a shared
/// [`CountingPaymentAdapter`](crate::economy::adapter::CountingPaymentAdapter)
/// wired over the shared void counter, so the REAL
/// `drain_terminal_reservation` void path is observable.
fn supervisor_with_void_counter(voids: &Arc<std::sync::atomic::AtomicUsize>) -> Arc<Supervisor> {
    let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
        "did:dht:z6MkDrainTerminal".to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
        Box::new(crate::context::builder::NotConfiguredTransportProvider);
    let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
        Box::new(TestEventLog);
    let key_resolver: KeyResolver = Arc::new(|_, _| None);
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            InMemoryStorage::new(),
        )),
    );
    let payment_adapter: Arc<dyn PaymentAdapterDyn> =
        Arc::new(crate::economy::adapter::CountingPaymentAdapter {
            voided: Arc::clone(voids),
            ..Default::default()
        });
    Supervisor::with_providers(
        crypto,
        transport,
        event_log,
        key_resolver,
        None,
        Some(payment_adapter),
        None,
        None,
        mls_storage,
        crate::domain_handlers(),
    )
}

/// Build a real `PreparedAFields` carrying a `#[must_use]` escrow-BEARING
/// ticket (`escrow: Some(..)` with a live `PaymentAuthorization`), so the
/// drain path's void reaches the adapter — unlike the live Prepare-A, which
/// stages an escrow-`None` ticket (making hold and void indistinguishable).
fn build_prepared_a_fields_with_escrow_for_test() -> crate::context::actor::commands::PreparedAFields
{
    use scp_protocol::context::params::ContextParams;
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};
    use scp_protocol::economy::types::{Amount, CostSchedule, CurrencyCode, PaidActionType};

    let invoker = DID("did:example:xctx-drain-escrow".to_owned());
    let payee = DID("did:example:xctx-drain-payee".to_owned());
    let handle =
        crate::context::ContextHandle::new("ctx-drain-escrow".to_owned(), ContextParams::default());
    let role_state = ContextRoleState::new(
        "ctx-drain-escrow",
        "did:example:xctx-drain-escrow",
        default_ceiling(),
        vec![],
        &scp_clock::SystemClock,
    )
    .unwrap();
    let policy = scp_protocol::economy::types::EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: CurrencyCode::from("USD"),
            per_message: None,
            per_outlet_call: Some(Amount(50)),
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec!["void-counting".to_owned()],
        pricing_formula: None,
        payee: payee.clone(),
    };
    let escrow = crate::economy::integration::PreparedAction {
        envelope: crate::economy::integration::ActionEnvelope {
            actor: invoker.clone(),
            action_type: PaidActionType::OutletCall,
            context_id: None,
            authorization: Some(void_counting_auth(
                &invoker,
                &payee,
                Amount(50),
                CurrencyCode::from("USD"),
            )),
            payload: Vec::new(),
        },
        evaluated_cost: Amount(50),
    };
    let ticket = crate::context::shared::outlets::OutletEconomyTicket::new_for_test_with_escrow(
        invoker, escrow, policy,
    );
    let reservation = crate::context::shared::outlets::OutletEconomyReservation {
        handle,
        role_state,
        generation: 1,
        ticket,
    };
    crate::context::actor::commands::PreparedAFields { reservation }
}

/// `drain_terminal_reservation` with `reached_needs_repair == true` HOLDS the
/// caller-side external escrow (anti-free-execution, spec §6.2.4 "`NeedsRepair`
/// reservation semantics"): the recording adapter's void counter stays 0 (the
/// escrow is NOT voided), and the `#[must_use]` ticket is still marked consumed
/// so no unbalanced-drop guard fires. Exercised with a NON-EMPTY escrow so
/// HOLD is observationally distinct from VOID.
#[tokio::test]
async fn drain_terminal_reservation_needs_repair_holds_escrow() {
    let voids = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let supervisor = supervisor_with_void_counter(&voids);
    let mut prepared_a = Some(build_prepared_a_fields_with_escrow_for_test());

    supervisor
        .drain_terminal_reservation(
            &SagaId("saga-drain-needs-repair".to_owned()),
            true,
            &mut prepared_a,
        )
        .await;

    assert!(
        prepared_a.is_none(),
        "the carrier is taken (consumed) so its #[must_use] drop guard does not fire"
    );
    assert_eq!(
        voids.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "NeedsRepair must HOLD the external escrow for operator repair — auto-voiding a \
             partially-committed saga's escrow would be a free-execution exploit"
    );
}

/// `drain_terminal_reservation` with `reached_needs_repair == false` VOIDS the
/// caller-side external escrow (a held Prepare-A reservation survived to a
/// terminal without a Commit-A settle): the recording adapter's void counter
/// is 1. The mirror of the HOLD test above, proving the branch is the ONLY
/// difference and that the escrow is genuinely non-empty (a `None`-escrow
/// ticket would leave the counter at 0 on BOTH branches).
#[tokio::test]
async fn drain_terminal_reservation_non_needs_repair_voids_escrow() {
    let voids = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let supervisor = supervisor_with_void_counter(&voids);
    let mut prepared_a = Some(build_prepared_a_fields_with_escrow_for_test());

    supervisor
        .drain_terminal_reservation(
            &SagaId("saga-drain-terminal-void".to_owned()),
            false,
            &mut prepared_a,
        )
        .await;

    assert!(
        prepared_a.is_none(),
        "the carrier is taken (consumed) so its #[must_use] drop guard does not fire"
    );
    assert_eq!(
        voids.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a non-NeedsRepair terminal with a held reservation must VOID the external escrow \
             exactly once (never drop the ticket unbalanced)"
    );
}

/// Build a real `PreparedAFields` carrying a `#[must_use]` no-escrow ticket —
/// the exact carrier the Prepare-A handler hands the FSM. Used by the
/// extractor round-trip tests below so the recovered reservation is a genuine
/// ticket-bearing reservation (not a synthetic stand-in), making the
/// round-trip assertion meaningful.
fn build_prepared_a_fields_for_test() -> crate::context::actor::commands::PreparedAFields {
    use scp_protocol::context::params::ContextParams;
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

    let invoker = DID("did:example:xctx-extractor".to_owned());
    let handle =
        crate::context::ContextHandle::new("ctx-extractor".to_owned(), ContextParams::default());
    let role_state = ContextRoleState::new(
        "ctx-extractor",
        "did:example:xctx-extractor",
        default_ceiling(),
        vec![],
        &scp_clock::SystemClock,
    )
    .unwrap();
    let ticket =
        crate::context::shared::outlets::OutletEconomyTicket::new_for_test_no_escrow(invoker);
    let reservation = crate::context::shared::outlets::OutletEconomyReservation {
        handle,
        role_state,
        generation: 1,
        ticket,
    };
    crate::context::actor::commands::PreparedAFields { reservation }
}

/// `extract_abort_reservation` must recover the `#[must_use]` ticket-bearing
/// reservation from the EXACT `Abort { reservation: Some(..) }` command that
/// `abort_xctx_participants` builds. The `else`/`None` arm is "unreachable in
/// practice" but was previously enforced only by a comment; this test makes a
/// future command-shape refactor that breaks the lockstep fail HERE (a
/// returned `None` that silently drops the ticket) instead of leaking a
/// reservation at runtime. The recovered ticket is consumed so its drop guard
/// does not fire under `--features testing`.
#[test]
fn extract_abort_reservation_round_trips_the_exact_built_command() {
    let prepared = build_prepared_a_fields_for_test();
    let (reply, _rx) = tokio::sync::oneshot::channel::<Result<(), ContextError>>();
    // The EXACT command shape `abort_xctx_participants` constructs for the
    // caller-side abort (carrying `Some(Box::new(reservation))`).
    let cmd = Box::new(ContextCommand::SagaPhase(
        crate::context::actor::commands::SagaPhaseMessage::Abort {
            saga_id: SagaId("saga-extract-abort".to_owned()),
            reservation: Some(Box::new(prepared)),
            reply,
        },
    ));

    let recovered = Supervisor::extract_abort_reservation(cmd);
    assert!(
        recovered.is_some(),
        "extract_abort_reservation must recover the reservation from the exact \
             Abort {{ reservation: Some(..) }} command abort_xctx_participants builds — \
             a None here means the extractor/builder command shape drifted out of lockstep \
             and a held ticket would be silently dropped"
    );
    // Consume the recovered ticket so the `#[must_use]` drop guard does not
    // fire (mirrors the real abort path's void+consume).
    recovered
        .unwrap()
        .reservation
        .ticket
        .consume_abandoning_escrow();
}

/// `extract_commit_a_reservation` must recover the reservation from the EXACT
/// `CommitA { reservation: Box::new(..), .. }` command that `commit_a_settle`
/// builds. Same lockstep guarantee as the abort extractor: a command-shape
/// refactor that breaks the re-pattern-match fails this test rather than
/// silently dropping the held ticket on the recovery path.
#[test]
fn extract_commit_a_reservation_round_trips_the_exact_built_command() {
    let prepared = build_prepared_a_fields_for_test();
    let (reply, _rx) = tokio::sync::oneshot::channel::<Result<(), ContextError>>();
    // The EXACT command shape `commit_a_settle` constructs.
    let cmd = Box::new(ContextCommand::SagaPhase(
        crate::context::actor::commands::SagaPhaseMessage::CommitA {
            saga_id: SagaId("saga-extract-commit-a".to_owned()),
            reservation: Box::new(prepared),
            caller_context_id: [0x11; 32],
            caller_did: DID("did:example:caller".to_owned()),
            target_context_id: [0x22; 32],
            nonce: [0x33; 16],
            receipt: vec![1, 2, 3],
            output_bytes: vec![4, 5, 6],
            reply,
        },
    ));

    let recovered = Supervisor::extract_commit_a_reservation(cmd);
    assert!(
        recovered.is_some(),
        "extract_commit_a_reservation must recover the reservation from the exact \
             CommitA command commit_a_settle builds — a None here means the extractor/builder \
             command shape drifted out of lockstep and a held ticket would be silently dropped"
    );
    recovered
        .unwrap()
        .reservation
        .ticket
        .consume_abandoning_escrow();
}
