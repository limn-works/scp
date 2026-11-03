//! The economy domain of the SCP runtime (ADR-070 §2): paid-action authorization, capture and payment receipts.
//!
//! The crate exports [`Economy`], the
//! [`EconomyDomain`](scp_runtime_core::context::domains::EconomyDomain) implementation
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
    "scp-runtime-economy test targets require the `testing` feature: pass \
     `--features testing` (or `--features scp-runtime-economy/testing` in a multi-package command)."
);

mod handler;
mod helpers;
mod logic;

/// The items sibling domain crates' tests call directly (`testing` only).
///
/// A domain's tests stay beside its code (ADR-070 plan §6.1), and a few of them
/// drive another domain's functions to set up or observe state. A sibling reaches
/// a domain only as a dev-dependency, so these items are exported here and
/// nowhere else; no production build compiles this module.
#[cfg(feature = "testing")]
pub mod testing_access {
    pub use crate::helpers::{
        authorize_paid_action_hold, authorize_paid_action_prepare, complete_paid_action,
    };
}

/// The economy domain's [`EconomyDomain`](scp_runtime_core::context::domains::EconomyDomain)
/// implementation, which the assembly's `domain_handlers()` installs.
pub struct Economy;

#[async_trait::async_trait]
impl scp_runtime_core::context::domains::EconomyDomain for Economy {
    async fn dispatch(
        &self,
        cell: &mut scp_runtime_core::context::actor::class_s::ClassSCell,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        cmd: scp_runtime_core::context::actor::commands::EconomyCommand,
    ) -> scp_runtime_core::context::actor::outcome::Outcome<()> {
        handler::dispatch(cell, deps, cmd).await
    }

    async fn authorize_paid_action_hold(
        &self,
        inputs: scp_runtime_core::context::shared::economy::OwnedAuthInputs,
        payer_did: &scp_did::DID,
        context_id: &str,
    ) -> Result<
        Option<scp_runtime_core::context::shared::economy::PaidActionAuthorization>,
        scp_protocol::context::ContextError,
    > {
        crate::helpers::authorize_paid_action_hold(inputs, payer_did, context_id).await
    }

    fn authorize_paid_action_prepare(
        &self,
        state: &scp_runtime_core::context::actor::state::PerContextState,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        action_type: scp_protocol::economy::types::PaidActionType,
        payer_did: &scp_did::DID,
    ) -> Option<scp_runtime_core::context::shared::economy::OwnedAuthInputs> {
        crate::helpers::authorize_paid_action_prepare(state, deps, action_type, payer_did)
    }

    async fn capture_and_verify_paid_action(
        &self,
        auth: scp_runtime_core::context::shared::economy::PaidActionAuthorization,
    ) -> Result<
        Option<scp_runtime_types::economy::adapter::PaymentReceipt>,
        scp_protocol::context::ContextError,
    > {
        crate::helpers::capture_and_verify_paid_action(auth).await
    }

    fn emit_payment_received_event(
        &self,
        receive_buffer: &mut scp_protocol::context::membership::ReceiveBuffer,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        receipt: &scp_runtime_types::economy::adapter::PaymentReceipt,
        context_id: &str,
    ) {
        crate::helpers::emit_payment_received_event(receive_buffer, deps, receipt, context_id);
    }

    fn enforce_economy(
        &self,
        req: scp_runtime_core::context::shared::economy::EnforceEconomyRequest<'_>,
    ) -> Result<Option<scp_protocol::economy::types::Amount>, scp_protocol::context::ContextError>
    {
        crate::logic::enforce_economy(req)
    }
}
