//! The outlets domain of the SCP runtime (ADR-070 §2): outlet invocation, streams and their economy reservations.
//!
//! The crate exports [`Outlets`], the
//! [`OutletsDomain`](scp_runtime_core::context::domains::OutletsDomain) implementation
//! that the assembly crate `scp-runtime` installs in
//! [`DomainHandlers`](scp_runtime_core::context::domains::DomainHandlers). Every other item is
//! private to the crate, except the `testing`-gated `testing_access` module.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

// Test targets require the `testing` feature: the `#[cfg(test)]` modules call
// `#[cfg(feature = "testing")]`-gated helpers of `scp-runtime-core`, and the
// command variants core gates on `testing` need this crate's match arms. No
// dev-dependency edge turns it on, so every test command names the feature. This
// tripwire turns a missing `--features` into a clear message instead of a cryptic E0599.
#[cfg(all(test, not(feature = "testing")))]
compile_error!(
    "scp-runtime-outlets test targets require the `testing` feature: pass \
     `--features testing` (or `--features scp-runtime-outlets/testing` in a multi-package command)."
);

mod handler;
mod helpers;
#[cfg(test)]
mod test_support;

/// The items sibling domain crates' tests call directly (`testing` only).
///
/// A domain's tests stay beside its code (ADR-070 plan §6.1), and a few of them
/// drive another domain's functions to set up or observe state. A sibling reaches
/// a domain only as a dev-dependency, so these items are exported here and
/// nowhere else; no production build compiles this module.
#[cfg(feature = "testing")]
pub mod testing_access {
    pub use crate::helpers::reverse_caller_reservation_record;
}

/// The outlets domain's [`OutletsDomain`](scp_runtime_core::context::domains::OutletsDomain)
/// implementation, which the assembly's `domain_handlers()` installs.
pub struct Outlets;

#[async_trait::async_trait]
impl scp_runtime_core::context::domains::OutletsDomain for Outlets {
    async fn dispatch(
        &self,
        cell: &mut scp_runtime_core::context::actor::class_s::ClassSCell,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        cmd: scp_runtime_core::context::actor::commands::OutletsCommand,
    ) -> scp_runtime_core::context::actor::outcome::Outcome<()> {
        handler::dispatch(cell, deps, cmd).await
    }

    async fn reserve_outlet_economy(
        &self,
        cell: &mut scp_runtime_core::context::actor::class_s::ClassSCell,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        reserve: scp_runtime_core::context::domains::ReserveOutletEconomyRequest<'_>,
    ) -> Result<
        scp_runtime_core::context::shared::outlets::OutletEconomyReservation,
        scp_protocol::context::ContextError,
    > {
        crate::helpers::reserve_outlet_economy(
            cell,
            deps,
            reserve.context_id,
            reserve.invoker_did,
            reserve.spending_ucan,
            reserve.caveat_binding,
            reserve.input,
            reserve.now_secs,
        )
        .await
    }

    async fn reverse_caller_reservation_record(
        &self,
        view: scp_runtime_core::context::actor::class_s::ClassCMut<'_>,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        record: &scp_runtime_core::context::supervisor::saga_prepared_state::CallerReservationRecord,
    ) -> bool {
        crate::helpers::reverse_caller_reservation_record(view, deps, record).await
    }

    async fn settle_outlet_economy(
        &self,
        cell: &mut scp_runtime_core::context::actor::class_s::ClassSCell,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        context_id: &str,
        invoker_did: &scp_did::DID,
        request: scp_runtime_core::context::shared::outlets::OutletSettleRequest,
    ) -> Result<
        scp_runtime_core::context::shared::outlets::OutletSettleOutcome,
        scp_protocol::context::ContextError,
    > {
        crate::helpers::settle_outlet_economy(cell, deps, context_id, invoker_did, request).await
    }
}
