//! Economy handlers — see
//! [`EconomyCommand`](crate::context::actor::commands::EconomyCommand)
//! and spec §19 / plan row 10 of the commit ladder.
//!
//! # Phase 2A.3 — actor-shape dispatch
//!
//! The handler's primary entry point [`dispatch`] takes
//! `(&mut PerContextState, &ActorDeps, EconomyCommand)` and routes to
//! actor-shaped helpers in [`crate::context::economy_helpers`]. The shim
//! entry point was deleted in Phase 2A finalization; the
//! no-mailbox-context fallback now lives on
//! [`Supervisor::dispatch_economy_direct`](crate::context::supervisor::Supervisor::dispatch_economy_direct).

use crate::context::actor::class_s::ClassSCell;
use crate::context::actor::commands::EconomyCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use scp_runtime_types::economy::receipt::ReceiptVerificationError;

use crate::context::actor::handle::HANDLER_TIMEOUT;

/// Dispatch an [`EconomyCommand`] against actor-owned state and
/// capability-reduced dependencies.
///
/// Read-only domain: the cell is threaded as `&mut ClassSCell` to match
/// the actor dispatch seam, but this domain reads NOTHING from the owned
/// state (receipt verification flows entirely through the payment
/// adapter on `deps`). It is therefore taken as `_cell` — no
/// `ClassSCell::state_mut` escape hatch, no [`Deref`](std::ops::Deref)
/// read (ADR-049 §9). The `&mut` referent also keeps the spawned dispatch
/// future `Send`, which a shared `&ClassSCell` would not (`ClassSCell` is
/// not `Sync`).
#[allow(clippy::needless_pass_by_ref_mut)]
pub(crate) async fn dispatch(
    _cell: &mut ClassSCell,
    deps: &ActorDeps,
    cmd: EconomyCommand,
) -> Outcome<()> {
    dispatch_inner(deps, cmd).await
}

async fn dispatch_inner(deps: &ActorDeps, cmd: EconomyCommand) -> Outcome<()> {
    match cmd {
        EconomyCommand::VerifyPaymentReceipts { receipts, reply } => {
            handle_verify_payment_receipts(deps, *receipts, reply).await
        }
    }
}

/// Handle [`EconomyCommand::VerifyPaymentReceipts`] — delegates to
/// [`economy_helpers::verify_payment_receipts`](crate::context::economy_helpers::verify_payment_receipts)
/// under a 30s timeout. Read-only — the helper does not read or mutate
/// per-context state; it calls the configured payment adapter's
/// `verify_dyn` method per receipt and collates results.
async fn handle_verify_payment_receipts(
    deps: &ActorDeps,
    receipts: Vec<scp_runtime_types::economy::adapter::PaymentReceipt>,
    reply: crate::context::actor::commands::VerifyPaymentReceiptsReply,
) -> Outcome<()> {
    let verify_fut = crate::context::economy_helpers::verify_payment_receipts(deps, &receipts);

    let results = match tokio::time::timeout(HANDLER_TIMEOUT, verify_fut).await {
        Ok(vec) => vec,
        Err(_elapsed) => {
            // On timeout, synthesize a per-receipt NoVerifierForAdapter
            // error — callers see the same vector shape whether the
            // adapter returned per-receipt errors or the handler timed
            // out. The legacy method returns `Vec<Result<..>>` (always
            // Ok(vec)), so the outer Result here surfaces ONLY the
            // timeout path.
            receipts
                .iter()
                .map(|r| {
                    Err(ReceiptVerificationError::NoVerifierForAdapter {
                        receipt_id: r.receipt_id,
                        adapter_id: r.adapter_id.clone(),
                    })
                })
                .collect()
        }
    };

    let _ = reply.send(results);
    // Verify payment receipts is a pure read — mutated=false.
    Outcome::ok(())
}

/// The economy domain's [`EconomyDomain`](crate::context::domains::EconomyDomain)
/// implementation, which the assembly's `domain_handlers()` installs.
pub struct Economy;

#[async_trait::async_trait]
impl crate::context::domains::EconomyDomain for Economy {
    async fn dispatch(
        &self,
        cell: &mut crate::context::actor::class_s::ClassSCell,
        deps: &crate::context::actor::deps::ActorDeps,
        cmd: crate::context::actor::commands::EconomyCommand,
    ) -> crate::context::actor::outcome::Outcome<()> {
        dispatch(cell, deps, cmd).await
    }

    async fn authorize_paid_action_hold(
        &self,
        inputs: crate::context::shared::economy::OwnedAuthInputs,
        payer_did: &scp_did::DID,
        context_id: &str,
    ) -> Result<
        Option<crate::context::shared::economy::PaidActionAuthorization>,
        scp_protocol::context::ContextError,
    > {
        crate::context::economy_helpers::authorize_paid_action_hold(inputs, payer_did, context_id)
            .await
    }

    fn authorize_paid_action_prepare(
        &self,
        state: &crate::context::actor::state::PerContextState,
        deps: &crate::context::actor::deps::ActorDeps,
        action_type: scp_protocol::economy::types::PaidActionType,
        payer_did: &scp_did::DID,
    ) -> Option<crate::context::shared::economy::OwnedAuthInputs> {
        crate::context::economy_helpers::authorize_paid_action_prepare(
            state,
            deps,
            action_type,
            payer_did,
        )
    }

    async fn capture_and_verify_paid_action(
        &self,
        auth: crate::context::shared::economy::PaidActionAuthorization,
    ) -> Result<
        Option<scp_runtime_types::economy::adapter::PaymentReceipt>,
        scp_protocol::context::ContextError,
    > {
        crate::context::economy_helpers::capture_and_verify_paid_action(auth).await
    }

    fn emit_payment_received_event(
        &self,
        receive_buffer: &mut scp_protocol::context::membership::ReceiveBuffer,
        deps: &crate::context::actor::deps::ActorDeps,
        receipt: &scp_runtime_types::economy::adapter::PaymentReceipt,
        context_id: &str,
    ) {
        crate::context::economy_helpers::emit_payment_received_event(
            receive_buffer,
            deps,
            receipt,
            context_id,
        );
    }

    fn enforce_economy(
        &self,
        req: crate::context::shared::economy::EnforceEconomyRequest<'_>,
    ) -> Result<Option<scp_protocol::economy::types::Amount>, scp_protocol::context::ContextError>
    {
        crate::context::economy_logic::enforce_economy(req)
    }
}
