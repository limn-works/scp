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
use std::sync::{Arc, Weak};

use scp_platform::PlatformError;
use scp_protocol::context::ContextError;
use scp_protocol::trust::CaveatKind;

use crate::context::actor::commands::OutletsCommand;
use crate::context::supervisor::supervisor::Supervisor;
use crate::store::StoreError;
use crate::trust::caveat_counters::{CaveatCounterApi, CounterError, CounterExhausted};

scp_runtime_types::pub_under_testing! {
    /// Concrete [`CaveatCounterApi`] implementation routing to the actor-owned
    /// Class-S `caveat_counters` slice via the supervisor mailbox.
    ///
    /// Held as `Arc<dyn CaveatCounterApi>` inside the streaming pump's
    /// [`StreamCounterReservation`](crate::context::outlets::dispatch::StreamCounterReservation);
    /// constructed by the streaming open orchestrator with a `Weak` reference to
    /// the supervisor.
    ///
    /// Core-internal; `pub` under `testing` for the runtime crates' tests (ADR-070 §5).
    pub(crate) struct ActorClassSCaveatCounterAdapter {
        /// The supervisor whose mailbox owns the target context's Class-S state.
        /// A `Weak` (ADR-049 Decision 16): the adapter lives inside the streaming
        /// pump, a supervisor-spawned task, so it never keeps the Supervisor alive.
        /// Each operation upgrades it; a failed upgrade returns a typed error.
        supervisor: Weak<Supervisor>,
    }
}

impl ActorClassSCaveatCounterAdapter {
    /// Test-only reach into [`Self::new`] for tests outside this crate.
    /// Compiled only under `testing`, so no production or bridge build
    /// reaches it (ADR-070 §4).
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub const fn new_for_test(supervisor: Weak<Supervisor>) -> Self {
        Self::new(supervisor)
    }

    /// Wrap a supervisor `Arc` as the streaming counter store.
    ///
    /// The non-test constructor is the streaming open orchestrator
    /// (`Supervisor::open_outlet_stream<E>`, chunk 3e).
    #[must_use]
    pub(crate) const fn new(supervisor: Weak<Supervisor>) -> Self {
        Self { supervisor }
    }

    /// Upgrades the back-reference for one operation.
    ///
    /// # Errors
    ///
    /// [`ContextError::SupervisorShutDown`] when the Supervisor has dropped.
    fn supervisor(&self) -> Result<Arc<Supervisor>, ContextError> {
        self.supervisor.upgrade().ok_or_else(|| {
            ContextError::SupervisorShutDown(
                "ActorClassSCaveatCounterAdapter: supervisor dropped".to_owned(),
            )
        })
    }

    /// Current Unix time in seconds from the supervisor's injected clock, or a
    /// fail-closed [`CounterError::Store`] when no clock is configured.
    fn now_secs(&self) -> Result<u64, CounterError> {
        use scp_clock::Clock as _;
        let supervisor = self
            .supervisor()
            .map_err(|e| context_error_to_counter_store(&e))?;
        let clock = supervisor.clock_ref().ok_or_else(|| {
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
        self.supervisor()?.dispatch_outlets_command(cmd).await?;
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
        self.supervisor()?.dispatch_outlets_command(cmd).await?;
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

    use scp_protocol::trust::CaveatKind;

    use super::ActorClassSCaveatCounterAdapter;

    use crate::trust::caveat_counters::{CaveatCounterApi, CounterError};
    const CTX_BYTE: u8 = 0x5C;

    fn ctx_key() -> String {
        hex::encode([CTX_BYTE; 32])
    }

    /// A dropped Supervisor fails the op closed as [`CounterError::Store`]
    /// carrying the `SupervisorShutDown` reason, never an admission.
    #[tokio::test]
    async fn dropped_supervisor_fails_closed_as_store_error() {
        let adapter = ActorClassSCaveatCounterAdapter::new(std::sync::Weak::new());
        let err = adapter
            .check_and_increment(&ctx_key(), "cid-gone", CaveatKind::MaxCalls, 1, 5, 0)
            .await
            .expect_err("a dropped Supervisor cannot enforce the cap");
        assert!(
            matches!(&err, CounterError::Store(_))
                && format!("{err:?}").contains("supervisor dropped"),
            "a dropped Supervisor must fail closed as Store(_), got {err:?}"
        );
    }
}
