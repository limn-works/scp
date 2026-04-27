//! Economy handlers — see
//! [`EconomyCommand`](crate::context::actor::commands::EconomyCommand)
//! and spec §19 / plan row 10 of the commit ladder.
//!
//! # Phase 2A.3 — actor-shape dispatch
//!
//! The handler's primary entry point [`dispatch`] takes
//! `(&mut PerContextState, &ActorDeps, EconomyCommand)` and routes to
//! actor-shaped helpers in [`crate::context::economy_helpers`]. The shim
//! entry point is retained during Phase 2A and routes through
//! [`crate::context::economy_helpers_legacy`].

use std::time::Duration;

use crate::context::actor::commands::EconomyCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState;
use crate::context::supervisor::Supervisor;
use crate::economy::receipt::ReceiptVerificationError;
use scp_protocol::context::ContextError;
use tokio::sync::oneshot;

/// Per-call transport budget for economy handlers. Plan §"Transport
/// timeouts inside actor handlers": 30 seconds.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch an [`EconomyCommand`] against actor-owned state and
/// capability-reduced dependencies.
pub async fn dispatch(
    state: &mut PerContextState,
    deps: &ActorDeps,
    cmd: EconomyCommand,
) -> Outcome<()> {
    dispatch_inner(state, deps, cmd).await
}

/// Shim-callable dispatch. Used by
/// [`Supervisor::dispatch_economy_command`](crate::context::supervisor::supervisor::Supervisor::dispatch_economy_command)
/// during the commits-10-to-11 migration window — deleted in commit 12
/// when the shim dissolves.
pub(crate) async fn dispatch_from_shim(
    supervisor: &Supervisor,
    cmd: EconomyCommand,
) -> Outcome<()> {
    dispatch_from_shim_inner(supervisor, cmd).await
}

async fn dispatch_inner(
    state: &mut PerContextState,
    deps: &ActorDeps,
    cmd: EconomyCommand,
) -> Outcome<()> {
    match cmd {
        EconomyCommand::Placeholder { reply } => reply_not_implemented(reply),
        EconomyCommand::VerifyPaymentReceipts { receipts, reply } => {
            handle_verify_payment_receipts(state, deps, *receipts, reply).await
        }
    }
}

async fn dispatch_from_shim_inner(supervisor: &Supervisor, cmd: EconomyCommand) -> Outcome<()> {
    match cmd {
        EconomyCommand::Placeholder { reply } => reply_not_implemented(reply),
        EconomyCommand::VerifyPaymentReceipts { receipts, reply } => {
            shim_handle_verify_payment_receipts(supervisor, *receipts, reply).await
        }
    }
}

/// Handle [`EconomyCommand::VerifyPaymentReceipts`] — delegates to
/// [`economy_helpers::verify_payment_receipts`](crate::context::economy_helpers::verify_payment_receipts)
/// under a 30s timeout. Read-only — the helper does not mutate
/// per-context state; it calls the configured payment adapter's
/// `verify_dyn` method per receipt and collates results.
async fn handle_verify_payment_receipts(
    state: &mut PerContextState,
    deps: &ActorDeps,
    receipts: Vec<crate::economy::adapter::PaymentReceipt>,
    reply: crate::context::actor::commands::VerifyPaymentReceiptsReply,
) -> Outcome<()> {
    let verify_fut =
        crate::context::economy_helpers::verify_payment_receipts(state, deps, &receipts);

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

async fn shim_handle_verify_payment_receipts(
    supervisor: &Supervisor,
    receipts: Vec<crate::economy::adapter::PaymentReceipt>,
    reply: crate::context::actor::commands::VerifyPaymentReceiptsReply,
) -> Outcome<()> {
    let verify_fut = crate::context::economy_helpers_legacy::verify_payment_receipts_legacy(
        supervisor, &receipts,
    );

    let results = match tokio::time::timeout(HANDLER_TIMEOUT, verify_fut).await {
        Ok(vec) => vec,
        Err(_elapsed) => receipts
            .iter()
            .map(|r| {
                Err(ReceiptVerificationError::NoVerifierForAdapter {
                    receipt_id: r.receipt_id,
                    adapter_id: r.adapter_id.clone(),
                })
            })
            .collect(),
    };

    let _ = reply.send(results);
    Outcome::ok(())
}

fn reply_not_implemented(reply: oneshot::Sender<Result<(), ContextError>>) -> Outcome<()> {
    const MSG: &str = "EconomyCommand::Placeholder — real variant (VerifyPaymentReceipts) \
                       migrates in commit 10 of ADR-049; Placeholder retained for commit-6 \
                       compile stability and deleted in commit 12 with the shim";
    let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
    Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
}
