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

use scp_protocol::context::ContextError;

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
/// The domain is mixed: [`EconomyCommand::VerifyPaymentReceipts`] is
/// read-only (receipt verification flows entirely through the payment
/// adapter on `deps`), while [`EconomyCommand::RevokeSpendingUcan`] mutates
/// the actor's Class-S `revoked_spending_ucan_cids` gate through the cell's
/// fail-closed persist-on-commit combinator (ADR-049 §9). The `&mut cell`
/// referent also keeps the spawned dispatch future `Send`, which a shared
/// `&ClassSCell` would not (`ClassSCell` is not `Sync`).
pub(crate) async fn dispatch(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    cmd: EconomyCommand,
) -> Outcome<()> {
    match cmd {
        EconomyCommand::VerifyPaymentReceipts { receipts, reply } => {
            handle_verify_payment_receipts(deps, *receipts, reply).await
        }
        EconomyCommand::RevokeSpendingUcan {
            context_id,
            revoked_cid,
            scope,
            revoker_did,
            reply,
        } => {
            handle_revoke_spending_ucan(
                cell,
                deps,
                context_id,
                revoked_cid,
                scope,
                revoker_did,
                reply,
            )
            .await
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

/// Handle [`EconomyCommand::RevokeSpendingUcan`] — carry a revoked spending
/// UCAN's revocation CID into the actor's Class-S `revoked_spending_ucan_cids`
/// set (the authoritative paid-action gate consulted by
/// `validate_spending_ucan_signed`), then emit the convergent
/// [`SpendingUcanRevoked`](scp_event_log::EventType::SpendingUcanRevoked) leaf
/// (spec §19.5, §19.6.1).
///
/// # Fail-closed ordering (ADR-049 §9)
///
/// 1. The insertion rides [`ClassSCell::commit_class_s_keep`] — a **fail-closed**
///    persist-on-commit combinator, keep-direction: the CID is written through a
///    [`ClassSMut`](crate::context::actor::class_s::ClassSMut) view (reaching the
///    `pub(in crate::context)` set via `rest_mut`, the documented route for this
///    Class-S field, which lives in `GovernanceState` rather than the
///    `GovernanceClassS` sub-struct) and persisted before the revocation is
///    acknowledged. On persist failure the in-memory revocation is RETAINED
///    (un-revoking would re-open the re-spend window the human closed) and the
///    error is surfaced — the caller never observes a half-durable revocation as
///    success.
/// 2. Only after the gate is durably closed is the `SpendingUcanRevoked` leaf
///    appended. A leaf-append failure is surfaced but does NOT roll the gate
///    back — the safe direction (the gate stays closed; only the audit leaf is
///    missing).
async fn handle_revoke_spending_ucan(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: String,
    revoked_cid: String,
    scope: String,
    revoker_did: String,
    reply: tokio::sync::oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // Step 1: insert the CID into the Class-S gate, persisted fail-closed.
    let cid_for_leaf = revoked_cid.clone();
    let insert_result = cell
        .commit_class_s_keep(deps, &context_id, |mut view| {
            // `revoked_spending_ucan_cids` is a Class-S field of `GovernanceState`
            // (not the `GovernanceClassS` sub-struct); its documented mutation
            // route is a fail-closed combinator via the whole-state `rest_mut`
            // reach. `insert` is idempotent — a re-revocation is a no-op.
            view.rest_mut()
                .governance
                .revoked_spending_ucan_cids
                .insert(revoked_cid);
            Ok(())
        })
        .await;
    if let Err(e) = insert_result {
        // Keep-direction: the in-memory insertion is retained; surface the
        // persist error so the caller does not treat a non-durable revocation
        // as success.
        let _ = reply.send(Err(e));
        return Outcome::ok_mutated(());
    }

    // Step 2: append the convergent SpendingUcanRevoked leaf (§19.6.1).
    let payload = match scp_event_log::payload::encode_payload(
        &scp_event_log::payload::SpendingUcanRevokedPayload {
            token_cid: cid_for_leaf,
            scope,
        },
    ) {
        Ok(p) => p,
        Err(e) => {
            let _ = reply.send(Err(ContextError::EventLogFailed(e.to_string())));
            return Outcome::ok_mutated(());
        }
    };
    let context_id_bytes = crate::context::state::context_id_to_bytes(&context_id);
    let timestamp_secs = deps.clock.now_secs();
    let append_result = deps
        .event_log
        .append_context_event_with_payload(
            &context_id_bytes,
            scp_event_log::EventType::SpendingUcanRevoked,
            &revoker_did,
            payload,
            timestamp_secs,
        )
        .await;
    let _ = reply.send(append_result);
    Outcome::ok_mutated(())
}
