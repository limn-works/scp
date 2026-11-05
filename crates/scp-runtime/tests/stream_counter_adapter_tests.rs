//! Tests moved out of `scp-runtime-core` `context::outlets::stream_counter_adapter` (ADR-070 §6.2): they build a
//! `Supervisor`, which needs the domain handlers only `scp-runtime` assembles.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use scp_protocol::trust::CaveatKind;
use scp_runtime_core::context::supervisor::supervisor::Supervisor;
use scp_runtime_core::trust::caveat_counters::{CaveatCounterApi, CounterError, CounterExhausted};
use std::sync::Arc;

use scp_did::DID;
use scp_platform::in_memory::InMemoryStorage;

use scp_runtime_core::context::actor::state::PerContextState;
use scp_runtime_core::context::outlets::stream_counter_adapter::ActorClassSCaveatCounterAdapter;

const INVOKER: &str = "did:dht:z6MkStreamCounterAdapter";
const CTX_BYTE: u8 = 0x5C;

fn ctx_key() -> String {
    hex::encode([CTX_BYTE; 32])
}

/// Build a supervisor with a fixed clock + no-op persistence and REGISTER a
/// live actor owning the Class-S `caveat_counters` slice keyed by
/// [`ctx_key`]. The adapter routes every op ONTO this actor's mailbox, so
/// counter state persists across independent adapter calls exactly because
/// the actor owns it — the property the round-trip tests below assert.
async fn supervisor_with_registered_context() -> Arc<Supervisor> {
    let crypto = Arc::new(
        scp_runtime_core::crypto::mls::provider::NodeMlsFactory::new(
            INVOKER.to_owned(),
            Arc::new(scp_clock::SystemClock),
        ),
    );
    let transport: Box<dyn scp_runtime_core::context::builder::ContextTransportProvider> =
        Box::new(scp_runtime_core::context::builder::NotConfiguredTransportProvider);
    let event_log: Box<dyn scp_runtime_core::context::builder::ContextEventLogProvider> =
        Box::new(scp_runtime_core::context::providers::MerkleEventLogProvider::new());
    let key_resolver: scp_protocol::context::governance::KeyResolver = Arc::new(|_, _| None);
    let mls_storage: Arc<
        dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter,
    > = Arc::new(
        scp_runtime_types::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(
            Arc::new(InMemoryStorage::new()),
        ),
    );
    // A fixed test clock so the adapter's `now_secs` is deterministic across
    // every round-trip; no-op persistence so `commit_class_s_keep` succeeds.
    let clock: Arc<dyn scp_clock::Clock> = Arc::new(scp_clock::TestClock::new(1_700_000_000));
    let supervisor = Supervisor::with_providers(
        crypto,
        transport,
        event_log,
        key_resolver,
        Some(Box::new(
            scp_runtime_core::context::persistence::NoOpContextPersistence,
        )),
        None,
        None,
        Some(clock),
        mls_storage,
        scp_runtime::domain_handlers(),
    );

    let deps = supervisor
        .build_actor_deps_loaded(&DID(INVOKER.to_owned()))
        .await
        .expect("build_actor_deps");
    // The counter handlers gate only on the owned record, not context state,
    // so the fresh (non-promoted) test fixture suffices.
    let state = PerContextState::new_for_test_encrypted(
        [CTX_BYTE; 32],
        1_700_000_000,
        DID(INVOKER.to_owned()),
    );
    supervisor
        .spawn_actor_with_state_for_test(state, deps, None)
        .await
        .expect("spawn_actor_with_state registers the live actor");
    assert!(
        supervisor.lookup_for_test(&ctx_key()).is_some(),
        "actor must be registered under the context key the adapter targets"
    );
    supervisor
}

/// The round-trip mutates the actor-owned Class-S counter: a `max_calls`
/// cap of 2 admits the first two increments and exhausts on the third. That
/// exhaustion can only happen if each admitted consume PERSISTED on the
/// actor's owned state — three independent adapter calls against fresh
/// state would never exhaust. The rejection carries the STRUCTURED
/// [`CounterExhausted::MaxCalls`] the pump maps to the §7.3.8 slug (a
/// stringified `ContextError` would erase the variant).
#[tokio::test]
async fn check_and_increment_admits_then_exhausts_and_mutates_owned_state() {
    let supervisor = supervisor_with_registered_context().await;
    let adapter = ActorClassSCaveatCounterAdapter::new_for_test(Arc::downgrade(&supervisor));
    let cid = "cid-mc";

    adapter
        .check_and_increment(&ctx_key(), cid, CaveatKind::MaxCalls, 1, 2, 0)
        .await
        .expect("first increment within max_calls=2 admits");
    adapter
        .check_and_increment(&ctx_key(), cid, CaveatKind::MaxCalls, 1, 2, 0)
        .await
        .expect("second increment within max_calls=2 admits");

    let err = adapter
        .check_and_increment(&ctx_key(), cid, CaveatKind::MaxCalls, 1, 2, 0)
        .await
        .expect_err("third increment exceeds max_calls=2 — proves owned state accrued");
    match err {
        CounterError::Exhausted(CounterExhausted::MaxCalls { would_be, cap }) => {
            assert_eq!(would_be, 3, "the rejected increment is the third call");
            assert_eq!(cap, 2, "cap is echoed back structurally");
        }
        other => panic!("expected structured MaxCalls exhaustion, got {other:?}"),
    }
}

/// `release` returns capacity to the owned counter and SATURATES at `0`: a
/// release larger than the recorded usage clamps rather than underflowing,
/// so a subsequent increment admits against the freed slot. If release had
/// wrapped (or not persisted), the reuse would be rejected.
#[tokio::test]
async fn release_returns_capacity_and_saturates_at_zero() {
    let supervisor = supervisor_with_registered_context().await;
    let adapter = ActorClassSCaveatCounterAdapter::new_for_test(Arc::downgrade(&supervisor));
    let cid = "cid-rel";

    // Consume the single slot; a second consume must now reject.
    adapter
        .check_and_increment(&ctx_key(), cid, CaveatKind::MaxCalls, 1, 1, 0)
        .await
        .expect("consume the single max_calls=1 slot");
    adapter
        .check_and_increment(&ctx_key(), cid, CaveatKind::MaxCalls, 1, 1, 0)
        .await
        .expect_err("cap=1 is exhausted before release");

    // Release far more than was used — must saturate at 0, not wrap.
    adapter
        .release(&ctx_key(), cid, CaveatKind::MaxCalls, 100)
        .await
        .expect("release saturates rather than erroring");

    // The freed slot is reusable exactly once (used clamped to 0, not a
    // wrapped huge value that would still reject).
    adapter
        .check_and_increment(&ctx_key(), cid, CaveatKind::MaxCalls, 1, 1, 0)
        .await
        .expect("the released slot admits a fresh consume");
    adapter
        .check_and_increment(&ctx_key(), cid, CaveatKind::MaxCalls, 1, 1, 0)
        .await
        .expect_err("only one slot was freed — the cap re-exhausts");
}

/// Counters are keyed by `ucan_cid`: exhausting one delegation's cap leaves
/// a different delegation's counter untouched (independent admission).
#[tokio::test]
async fn per_ucan_cid_isolation() {
    let supervisor = supervisor_with_registered_context().await;
    let adapter = ActorClassSCaveatCounterAdapter::new_for_test(Arc::downgrade(&supervisor));

    // Exhaust cid-a's max_calls=1.
    adapter
        .check_and_increment(&ctx_key(), "cid-a", CaveatKind::MaxCalls, 1, 1, 0)
        .await
        .expect("cid-a first consume admits");
    adapter
        .check_and_increment(&ctx_key(), "cid-a", CaveatKind::MaxCalls, 1, 1, 0)
        .await
        .expect_err("cid-a is exhausted at cap=1");

    // cid-b is entirely independent — its own cap=1 still admits.
    adapter
        .check_and_increment(&ctx_key(), "cid-b", CaveatKind::MaxCalls, 1, 1, 0)
        .await
        .expect("cid-b admits — a different delegation's counter is isolated");
    // ...and cid-b now enforces its OWN cap independently.
    adapter
        .check_and_increment(&ctx_key(), "cid-b", CaveatKind::MaxCalls, 1, 1, 0)
        .await
        .expect_err("cid-b enforces its own cap=1 after its own single consume");
}

/// `AmountCumulative` consumes by amount and exhausts structurally when the
/// running total would breach the cap.
#[tokio::test]
async fn amount_cumulative_exhausts_structurally() {
    let supervisor = supervisor_with_registered_context().await;
    let adapter = ActorClassSCaveatCounterAdapter::new_for_test(Arc::downgrade(&supervisor));
    let cid = "cid-amt";

    adapter
        .check_and_increment(&ctx_key(), cid, CaveatKind::AmountCumulative, 6, 10, 0)
        .await
        .expect("6 <= cap 10 admits");
    let err = adapter
        .check_and_increment(&ctx_key(), cid, CaveatKind::AmountCumulative, 6, 10, 0)
        .await
        .expect_err("6 + 6 = 12 > cap 10 exhausts");
    match err {
        CounterError::Exhausted(CounterExhausted::AmountCumulative { would_be, cap }) => {
            assert_eq!(would_be, 12);
            assert_eq!(cap, 10);
        }
        other => panic!("expected AmountCumulative exhaustion, got {other:?}"),
    }
}

/// An op targeting an UNREGISTERED context fails CLOSED as
/// [`CounterError::Store`] (infra), NOT an admission `Exhausted` — the
/// pump's `counter_error_to_open_rejection` treats `Store(_)` as a denial,
/// so a missing actor can never silently admit an open.
#[tokio::test]
async fn missing_actor_fails_closed_as_store_error() {
    let supervisor = supervisor_with_registered_context().await;
    let adapter = ActorClassSCaveatCounterAdapter::new_for_test(Arc::downgrade(&supervisor));
    let unregistered = hex::encode([0xEE_u8; 32]);

    let err = adapter
        .check_and_increment(&unregistered, "cid-x", CaveatKind::MaxCalls, 1, 5, 0)
        .await
        .expect_err("an unregistered context cannot enforce the cap");
    assert!(
        matches!(err, CounterError::Store(_)),
        "a routing miss must fail closed as Store(_), got {err:?}"
    );
}
