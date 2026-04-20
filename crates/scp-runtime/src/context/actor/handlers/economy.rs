//! Economy handlers — see
//! [`EconomyCommand`](crate::context::actor::commands::EconomyCommand)
//! and spec §19 / plan row 10 of the commit ladder.
//!
//! # Commit 10 scope
//!
//! Migrates the dispatch shape: the handler takes
//! [`MutationStateView`](crate::context::actor::mutation_state_view::MutationStateView)
//! + [`ActorDeps`] + [`EconomyCommand`], returns `Outcome<()>`.
//!
//! The underlying byte-identical implementation still lives on
//! [`ContextManager::verify_payment_receipts`](crate::context::manager::ContextManager::verify_payment_receipts).
//! The shim wraps the delegated call in [`tokio::time::timeout`] with a
//! 30s budget per ADR-049 §7. The method never returns an error (the
//! vector of per-receipt results already embeds
//! [`ReceiptVerificationError`](crate::economy::receipt::ReceiptVerificationError)
//! variants for each failed receipt), so the handler surfaces timeout
//! as a synthetic single-element `NoVerifierForAdapter` result
//! covering every input receipt — legible and matches the per-receipt
//! error convention.
//!
//! Economy's other public-surface methods (`authorize_paid_action`,
//! `complete_paid_action`, `void_paid_action`) are `pub(super)` —
//! invoked by the messaging path, not by FFI bridges. They migrate
//! implicitly with the messaging / lifecycle handlers, not as
//! dedicated commands.

use std::time::Duration;

use crate::context::actor::commands::EconomyCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::mutation_state_view::MutationStateView;
use crate::context::actor::outcome::Outcome;
use crate::economy::receipt::ReceiptVerificationError;
use scp_protocol::context::ContextError;
use tokio::sync::oneshot;

/// Per-call transport budget for economy handlers. Plan §"Transport
/// timeouts inside actor handlers": 30 seconds.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch an [`EconomyCommand`] against a mutation state view + deps
/// bundle.
///
/// Plan-conforming dispatch signature: matches the post-refactor actor
/// `run()` loop's call shape
/// (`handlers::economy::dispatch(&mut self.state, &self.deps, cmd).await`).
/// `deps` is accepted for symmetry — the economy handler does not yet
/// touch deps during the shim period. Commit 12 rewires these paths.
// `needless_pass_by_ref_mut` allow — matches the `&mut` contract
// used by every migrated handler dispatch for signature stability.
#[allow(clippy::needless_pass_by_ref_mut)]
pub async fn dispatch(
    view: &mut MutationStateView<'_>,
    _deps: &ActorDeps,
    cmd: EconomyCommand,
) -> Outcome<()> {
    dispatch_inner(view, cmd).await
}

/// Shim-callable dispatch. Used by
/// [`Supervisor::dispatch_economy_command`](crate::context::supervisor::supervisor::Supervisor::dispatch_economy_command)
/// during the commits-10-to-11 migration window — deleted in commit 12
/// when the shim dissolves.
// `needless_pass_by_ref_mut` allow — see the comment on [`dispatch`].
#[allow(clippy::needless_pass_by_ref_mut)]
pub(crate) async fn dispatch_from_shim(
    view: &mut MutationStateView<'_>,
    cmd: EconomyCommand,
) -> Outcome<()> {
    dispatch_inner(view, cmd).await
}

async fn dispatch_inner(view: &MutationStateView<'_>, cmd: EconomyCommand) -> Outcome<()> {
    match cmd {
        EconomyCommand::Placeholder { reply } => reply_not_implemented(reply),
        EconomyCommand::VerifyPaymentReceipts { receipts, reply } => {
            handle_verify_payment_receipts(view, *receipts, reply).await
        }
    }
}

/// Handle [`EconomyCommand::VerifyPaymentReceipts`] — delegates to
/// [`ContextManager::verify_payment_receipts`](crate::context::manager::ContextManager::verify_payment_receipts)
/// under a 30s timeout. Read-only — the method does not mutate
/// per-context state; it calls the configured payment adapter's
/// `verify_dyn` method per receipt and collates results.
async fn handle_verify_payment_receipts(
    view: &MutationStateView<'_>,
    receipts: Vec<crate::economy::adapter::PaymentReceipt>,
    reply: crate::context::actor::commands::VerifyPaymentReceiptsReply,
) -> Outcome<()> {
    let manager = std::sync::Arc::clone(view.manager());

    let verify_fut = manager.verify_payment_receipts(&receipts);

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

fn reply_not_implemented(reply: oneshot::Sender<Result<(), ContextError>>) -> Outcome<()> {
    const MSG: &str = "EconomyCommand::Placeholder — real variant (VerifyPaymentReceipts) \
                       migrates in commit 10 of ADR-049; Placeholder retained for commit-6 \
                       compile stability and deleted in commit 12 with the shim";
    let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
    Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
}
