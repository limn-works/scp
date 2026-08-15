//! Off-mailbox streaming §7.3.8 value-caveat counter adapter.
//!
//! The §5.4.5 streaming pump ([`crate::context::outlets::dispatch`]) runs
//! supervisor-side, OFF the per-context actor mailbox: it holds no `&mut` to
//! the actor-owned Class-S state and therefore cannot mutate
//! `ClassSState.caveat_counters` directly. Its open-time counter reservation
//! and close-time release are expressed against the type-erased
//! [`CaveatCounterApi`] seam
//! ([`crate::trust::caveat_counters`]).
//!
//! [`ActorClassSCaveatCounterAdapter`] is the concrete implementation of that
//! seam for main's actor/supervisor architecture. Every operation routes back
//! ONTO the mailbox as an [`OutletsCommand`], so the actual mutation of the
//! owned counter record happens on the actor (under the fail-closed
//! `commit_class_s_keep` persist — durable via the ADR-049 §9 snapshot). This
//! is the deliberate design decision recorded in the outlet-streaming plan:
//! the counter store is the actor-owned Class-S value-caveat slice, NOT a
//! separate durable repository.
//!
//! ## `now_secs` sourcing
//!
//! [`CaveatCounterApi::check_and_increment`] does not carry a timestamp (the
//! sliding rate-window needs one). The adapter sources it from the supervisor's
//! injected clock ([`Supervisor::clock_ref`]) — the SAME clock the on-mailbox
//! unary path stamps its `now_secs` from — so the two paths share one
//! deterministic time source (a `TestClock` under test, the wall clock in
//! production). A supervisor with no clock configured fails CLOSED: the
//! reservation is rejected as a [`CounterError::Store`] rather than admitted
//! with a fabricated timestamp.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use scp_platform::PlatformError;
use scp_protocol::context::ContextError;
use scp_protocol::trust::CaveatKind;

use crate::context::actor::commands::OutletsCommand;
use crate::context::supervisor::supervisor::Supervisor;
use crate::store::StoreError;
use crate::trust::caveat_counters::{CaveatCounterApi, CounterError, CounterExhausted};

/// Concrete [`CaveatCounterApi`] implementation routing to the actor-owned
/// Class-S `caveat_counters` slice via the supervisor mailbox.
///
/// Held as `Arc<dyn CaveatCounterApi>` inside the streaming pump's
/// [`StreamCounterReservation`](crate::context::outlets::dispatch::StreamCounterReservation);
/// constructed by the streaming open orchestrator with a clone of the
/// supervisor `Arc`.
pub(crate) struct ActorClassSCaveatCounterAdapter {
    /// The supervisor whose mailbox owns the target context's Class-S state.
    /// Held as an `Arc` because the adapter outlives any single call and is
    /// shared across the async stream pump's tasks.
    supervisor: Arc<Supervisor>,
}

impl ActorClassSCaveatCounterAdapter {
    /// Wrap a supervisor `Arc` as the streaming counter store.
    ///
    /// The non-test constructor is the streaming open orchestrator
    /// (`Supervisor::open_outlet_stream<E>`, chunk 3e).
    pub(crate) const fn new(supervisor: Arc<Supervisor>) -> Self {
        Self { supervisor }
    }

    /// Current Unix time in seconds from the supervisor's injected clock, or a
    /// fail-closed [`CounterError::Store`] when no clock is configured.
    fn now_secs(&self) -> Result<u64, CounterError> {
        use scp_clock::Clock as _;
        let clock = self.supervisor.clock_ref().ok_or_else(|| {
            CounterError::Store(StoreError::Storage(PlatformError::StorageError(
                "ActorClassSCaveatCounterAdapter: no clock configured on the supervisor — \
                 cannot stamp the caveat-counter reservation timestamp; failing closed"
                    .to_owned(),
            )))
        })?;
        Ok(clock.now_secs())
    }

    /// Route [`OutletsCommand::ReserveStreamCaveatCounter`] onto the mailbox and
    /// await the actor's admission decision.
    ///
    /// The outer `Result` carries the persist / transport INFRA outcome (a
    /// dispatch miss, a closed reply channel, or a fail-closed persist error);
    /// the inner `Result` carries the structured admission decision.
    #[allow(clippy::too_many_arguments)]
    async fn reserve_via_actor(
        &self,
        context_id: &str,
        ucan_cid: &str,
        kind: CaveatKind,
        amount: u64,
        cap: u64,
        window_secs: u32,
        now_secs: u64,
    ) -> Result<Result<(), CounterExhausted>, ContextError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = OutletsCommand::ReserveStreamCaveatCounter {
            context_id: context_id.to_owned(),
            ucan_cid: ucan_cid.to_owned(),
            kind,
            amount,
            cap,
            window_secs,
            now_secs,
            reply: reply_tx,
        };
        self.supervisor.dispatch_outlets_command(cmd).await?;
        reply_rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "ActorClassSCaveatCounterAdapter::reserve_via_actor — actor reply channel closed"
                    .to_owned(),
            )
        })?
    }

    /// Route [`OutletsCommand::ReleaseStreamCaveatCounter`] onto the mailbox and
    /// await the persist / transport infra outcome. Release itself never
    /// rejects (it saturates at `0`).
    async fn release_via_actor(
        &self,
        context_id: &str,
        ucan_cid: &str,
        kind: CaveatKind,
        amount: u64,
    ) -> Result<(), ContextError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = OutletsCommand::ReleaseStreamCaveatCounter {
            context_id: context_id.to_owned(),
            ucan_cid: ucan_cid.to_owned(),
            kind,
            amount,
            reply: reply_tx,
        };
        self.supervisor.dispatch_outlets_command(cmd).await?;
        reply_rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "ActorClassSCaveatCounterAdapter::release_via_actor — actor reply channel closed"
                    .to_owned(),
            )
        })?
    }
}

/// Maps an infrastructure [`ContextError`] (dispatch miss, closed reply
/// channel, fail-closed persist failure) onto the counter seam's
/// [`CounterError::Store`] — an infrastructure failure that cannot enforce the
/// cap, so the pump fails CLOSED (rejects the open / swallows the release)
/// rather than silently admitting.
fn context_error_to_counter_store(err: &ContextError) -> CounterError {
    CounterError::Store(StoreError::Storage(PlatformError::StorageError(format!(
        "actor caveat-counter routing failed: {err}"
    ))))
}

impl CaveatCounterApi for ActorClassSCaveatCounterAdapter {
    fn check_and_increment<'a>(
        &'a self,
        context_id: &'a str,
        ucan_cid: &'a str,
        kind: CaveatKind,
        amount: u64,
        cap: u64,
        window_secs: u32,
    ) -> Pin<Box<dyn Future<Output = Result<(), CounterError>> + Send + 'a>> {
        Box::pin(async move {
            let now_secs = self.now_secs()?;
            match self
                .reserve_via_actor(
                    context_id,
                    ucan_cid,
                    kind,
                    amount,
                    cap,
                    window_secs,
                    now_secs,
                )
                .await
            {
                Ok(Ok(())) => Ok(()),
                Ok(Err(exhausted)) => Err(CounterError::Exhausted(exhausted)),
                Err(infra) => Err(context_error_to_counter_store(&infra)),
            }
        })
    }

    fn release<'a>(
        &'a self,
        context_id: &'a str,
        ucan_cid: &'a str,
        kind: CaveatKind,
        amount: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), CounterError>> + Send + 'a>> {
        Box::pin(async move {
            self.release_via_actor(context_id, ucan_cid, kind, amount)
                .await
                .map_err(|infra| context_error_to_counter_store(&infra))
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

    use scp_did::DID;
    use scp_platform::in_memory::InMemoryStorage;
    use scp_protocol::trust::CaveatKind;

    use super::ActorClassSCaveatCounterAdapter;
    use crate::context::actor::state::PerContextState;
    use crate::context::supervisor::supervisor::Supervisor;
    use crate::trust::caveat_counters::{CaveatCounterApi, CounterError, CounterExhausted};

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
        let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
            INVOKER.to_owned(),
            Arc::new(scp_clock::SystemClock),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(crate::context::providers::MerkleEventLogProvider::new());
        let key_resolver: scp_protocol::context::governance::KeyResolver = Arc::new(|_, _| None);
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
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
                crate::context::persistence::NoOpContextPersistence,
            )),
            None,
            None,
            Some(clock),
            mls_storage,
        );

        let deps = supervisor
            .build_actor_deps(&DID(INVOKER.to_owned()))
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
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn_actor_with_state registers the live actor");
        assert!(
            supervisor.lookup(&ctx_key()).is_some(),
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
        let adapter = ActorClassSCaveatCounterAdapter::new(Arc::clone(&supervisor));
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
        let adapter = ActorClassSCaveatCounterAdapter::new(Arc::clone(&supervisor));
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
        let adapter = ActorClassSCaveatCounterAdapter::new(Arc::clone(&supervisor));

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
        let adapter = ActorClassSCaveatCounterAdapter::new(Arc::clone(&supervisor));
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
        let adapter = ActorClassSCaveatCounterAdapter::new(Arc::clone(&supervisor));
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
}
