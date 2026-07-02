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

use std::time::Duration;

use crate::context::actor::class_s::ClassSCell;
use crate::context::actor::commands::EconomyCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::economy::receipt::ReceiptVerificationError;

/// Per-call transport budget for economy handlers. Plan §"Transport
/// timeouts inside actor handlers": 30 seconds.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch an [`EconomyCommand`] against actor-owned state and
/// capability-reduced dependencies.
///
/// Read-only domain: the cell is threaded as `&mut ClassSCell` to match
/// the actor dispatch seam, but this domain reads NOTHING from the owned
/// state (receipt verification flows entirely through the payment
/// adapter on `deps`). It is therefore taken as `_cell` — no
/// [`ClassSCell::state_mut`] escape hatch, no [`Deref`](std::ops::Deref)
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
    receipts: Vec<crate::economy::adapter::PaymentReceipt>,
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
