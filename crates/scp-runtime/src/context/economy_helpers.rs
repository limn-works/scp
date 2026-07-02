//! Economy helpers — actor-shape signatures
//! (ADR-049 Phase 2A.3, `economy` domain migration).
//!
//! # Purpose
//!
//! This module hosts the economy-domain helpers that actor handlers and
//! migrated actor-shaped helper bodies call. Provider access flows
//! through [`ActorDeps`](crate::context::actor::deps::ActorDeps);
//! per-context policy, velocity, and checkpoint state flow through
//! [`PerContextState`](crate::context::actor::state::PerContextState).
//!
//! # Legacy fallback
//!
//! The pre-migration `&Supervisor` bodies live in
//! [`crate::context::economy_helpers_legacy`]. Still-legacy domains
//! such as messaging and lifecycle call that module until their own
//! Phase 2A migrations move them to actor-owned state.

#![allow(clippy::needless_pass_by_ref_mut)]

use std::sync::Arc;

use scp_did::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::economy::policy::ObservableMetrics;
use scp_protocol::economy::types::PaidActionType;

use crate::context::actor::deps::ActorDeps;
use crate::context::actor::state::PerContextState;
use crate::context::economy_logic::PaidActionAuthorization;
use crate::economy::adapter::{PaymentMetadata, PaymentReceipt};
use crate::economy::integration;
use crate::economy::receipt::{ReceiptVerification, ReceiptVerificationError};

// ---------------------------------------------------------------------------
// verify_payment_receipts (top-level, actor-handler entry point)
// ---------------------------------------------------------------------------

/// Verifies payment receipts using the configured payment adapter.
///
/// For each receipt whose `adapter_id` matches the configured adapter,
/// calls `verify_dyn` directly. Receipts whose `adapter_id` does not
/// match the configured adapter return
/// [`ReceiptVerificationError::NoVerifierForAdapter`].
///
/// If no payment adapter is configured, all receipts return
/// [`ReceiptVerificationError::NoVerifierForAdapter`].
pub async fn verify_payment_receipts(
    deps: &ActorDeps,
    receipts: &[PaymentReceipt],
) -> Vec<Result<ReceiptVerification, ReceiptVerificationError>> {
    let mut results = Vec::with_capacity(receipts.len());
    for receipt in receipts {
        let result = match deps.payment_adapter.as_ref() {
            Some(adapter) if adapter.adapter_id() == receipt.adapter_id => adapter
                .verify_dyn(receipt)
                .await
                .map(|r| ReceiptVerification {
                    receipt_id: receipt.receipt_id,
                    result: r,
                })
                .map_err(|e| ReceiptVerificationError::VerificationFailed {
                    receipt_id: receipt.receipt_id,
                    error: e,
                }),
            _ => Err(ReceiptVerificationError::NoVerifierForAdapter {
                receipt_id: receipt.receipt_id,
                adapter_id: receipt.adapter_id.clone(),
            }),
        };
        results.push(result);
    }
    results
}

// ---------------------------------------------------------------------------
// authorize_paid_action (escrow phase 1) — sync `prepare` + async `hold` split
// ---------------------------------------------------------------------------
//
// ADR-049 §9 Class-S cell seam: paid-action authorization is split into a SYNC
// state-reading half ([`authorize_paid_action_prepare`]) and an async escrow-hold
// half ([`authorize_paid_action_hold`]). The split exists because the async
// future must be `Send`, but a borrow of `&PerContextState` held across an
// `.await` is NOT `Send` (`PerContextState` is `!Sync` — it owns a `!Sync`
// `Box<dyn FnMut>` in the epoch-grace store). So a caller reads state through the
// SYNC prepare (a `&*cell` borrow that drops before the await — owned
// `OwnedAuthInputs` cross the boundary) and then awaits the hold with NO state
// borrow live. Both the send (`messaging_helpers::authorize_send_payment_prepare`)
// and join (`lifecycle_helpers::join_context`) paths drive the pair directly.

/// Owned inputs that cross the sync→async boundary of the authorize split. All
/// fields are owned / `Send`, so the async [`authorize_paid_action_hold`] future
/// holds NO `&PerContextState` borrow (which would not be `Send`).
#[allow(dead_code)]
pub struct OwnedAuthInputs {
    adapter: Arc<dyn crate::economy::adapter::PaymentAdapterDyn>,
    policy: scp_protocol::economy::types::EconomicPolicy,
    action_type: PaidActionType,
    metrics: ObservableMetrics,
}

/// Sync half of the authorize split: READS per-context governance / membership
/// state (clones the economic policy, counts members, samples the velocity
/// tracker) and evaluates whether a non-zero cost applies. Returns the owned
/// inputs the async hold needs, or `None` when no adapter / no policy / zero cost
/// short-circuits the authorization.
///
/// Takes a SHARED `&PerContextState` and performs NO `.await`, so a cell-holder
/// calls it as `authorize_paid_action_prepare(&*cell, …)` and the borrow drops at
/// the call boundary (the result is owned), leaving the cell free for the async
/// hold's `.await`.
#[allow(dead_code)]
pub fn authorize_paid_action_prepare(
    state: &PerContextState,
    deps: &ActorDeps,
    action_type: PaidActionType,
    payer_did: &DID,
) -> Option<OwnedAuthInputs> {
    let adapter = deps.payment_adapter.as_ref().map(Arc::clone)?;

    let policy = state.governance.economic_policy.clone();
    let member_count = u64::try_from(state.membership.count()).unwrap_or(u64::MAX);
    let now_secs = deps.clock.now_secs();
    let velocity = state
        .governance
        .velocity_tracker
        .get_velocity(payer_did, now_secs);

    let metrics = ObservableMetrics {
        sender_velocity: velocity,
        member_count,
        context_message_rate: state
            .governance
            .velocity_tracker
            .aggregate_velocity(now_secs),
        relay_queue_depth: 0,
        time_of_day: now_secs % 86400,
        storage_usage: 0,
    };

    let policy = policy?;

    if scp_protocol::economy::policy::evaluate_cost(&policy, &action_type, &metrics)
        .as_ref()
        .is_none_or(|c| c.0 == 0)
    {
        return None;
    }

    Some(OwnedAuthInputs {
        adapter,
        policy,
        action_type,
        metrics,
    })
}

/// Async half of the authorize split: creates the escrow hold from the owned
/// [`OwnedAuthInputs`]. Holds NO `&PerContextState` borrow (only owned values +
/// `&Sync` ids), so its future is `Send`.
///
/// # Errors
///
/// Returns any error from the payment integration layer mapped to
/// [`ContextError`].
#[allow(dead_code)]
pub async fn authorize_paid_action_hold(
    inputs: OwnedAuthInputs,
    payer_did: &DID,
    context_id: &str,
) -> Result<Option<PaidActionAuthorization>, ContextError> {
    let OwnedAuthInputs {
        adapter,
        policy,
        action_type,
        metrics,
    } = inputs;

    let metadata = PaymentMetadata {
        action_type: action_type.clone(),
        context_id: Some(context_id.to_owned()),
        idempotency_key: crate::context::economy_logic::rand_idempotency_key(),
    };

    let prepared = integration::prepare_paid_action(
        adapter.as_ref(),
        Some(&policy),
        action_type,
        payer_did,
        Some(context_id.to_owned()),
        &metrics,
        metadata,
        Vec::new(),
    )
    .await
    .map_err(crate::context::economy_logic::integration_error_to_context)?;

    Ok(Some(PaidActionAuthorization {
        prepared,
        adapter,
        policy,
        metrics,
    }))
}

// ---------------------------------------------------------------------------
// complete_paid_action (escrow phase 3)
// ---------------------------------------------------------------------------

/// Completes a paid action after successful execution (escrow capture).
///
/// Calls `adapter.capture`, verifies the receipt, surfaces it as a LOCAL
/// `ContextEvent::PaymentReceived` (receive-buffer push + `event_tx`
/// notification), and records it in the per-context `payment_receipts` buffer
/// for the `payment_history` query (spec §19.11).
///
/// Per ADR-051 §6 / the phase-2.md ADR-011 amendment exclusion taxonomy §2, a
/// `PaymentReceived` is per-payee application activity appended by the payee
/// alone — it is **excluded from the canonical Merkle log** so that two honest
/// members derive the same `event_log_merkle_root` (§9.9.3). The former durable
/// `EventType::PaymentReceived` append (and its `checkpoint_events_since`
/// increment) is removed; the local `ContextEvent` and the `payment_receipts`
/// buffer are the sole surfacing of a capture. The emitted event carries BOTH
/// `payer` and `payee` from the verified receipt (the payee records the
/// payment per §19.6.1) with `anchored: false` (not Merkle-proven until
/// ADR-051).
///
/// # Errors
///
/// Returns any error from the payment integration layer.
// Transitional Phase 2A surface: messaging/lifecycle call the legacy
// twins until those domains migrate to actor-owned state.
//
// ADR-049 §9 Class-S cell seam: this `&mut PerContextState`-shaped wrapper is the
// SEND-path surface (`messaging_helpers::capture_send_payment`). It composes the
// two field-granular helpers below — the state-free async capture
// ([`capture_and_verify_paid_action`]) and the sync, field-narrowed surfacing
// ([`surface_paid_action_receipt`]) — so the join tail can call those two
// directly through a `ClassCMut` view (no whole `&mut PerContextState`, hence no
// `state_mut()` escape hatch) while the send path keeps its existing
// whole-`&mut` call shape unchanged.
#[allow(dead_code)]
pub async fn complete_paid_action(
    state: &mut PerContextState,
    deps: &ActorDeps,
    auth: PaidActionAuthorization,
    context_id: &str,
) -> Result<Option<PaymentReceipt>, ContextError> {
    let Some(receipt) = capture_and_verify_paid_action(auth).await? else {
        return Ok(None);
    };

    surface_paid_action_receipt(
        &mut state.receive_buffer,
        &mut state.payment_receipts,
        deps,
        &receipt,
        context_id,
    );

    Ok(Some(receipt))
}

/// Capture + verify a paid action's escrow hold (the async, provider-driven half
/// of [`complete_paid_action`]). Drives only the adapter on the authorization —
/// it touches NO per-context state and needs no [`ActorDeps`], so it runs OUTSIDE
/// any Class-C view borrow (the join tail awaits it before re-borrowing the cell
/// to surface the receipt). Returns the verified [`PaymentReceipt`], or `None`
/// when the adapter produced no receipt.
///
/// # Errors
///
/// Returns any error from the payment integration layer or receipt verification.
#[allow(dead_code)]
pub async fn capture_and_verify_paid_action(
    auth: PaidActionAuthorization,
) -> Result<Option<PaymentReceipt>, ContextError> {
    let processed = integration::process_paid_action(
        auth.adapter.as_ref(),
        Some(&auth.policy),
        &auth.prepared.envelope,
        &auth.metrics,
        |payload| async move { Ok(payload) },
    )
    .await
    .map_err(crate::context::economy_logic::integration_error_to_context)?;

    let Some(receipt) = processed.receipt else {
        return Ok(None);
    };

    crate::context::economy_logic::verify_and_check_receipt(auth.adapter.as_ref(), &receipt)
        .await?;

    Ok(Some(receipt))
}

/// Surface a verified capture into per-context state (the sync, field-narrowed
/// half of [`complete_paid_action`]): emit the LOCAL
/// `ContextEvent::PaymentReceived` and record the receipt in the bounded
/// `payment_receipts` ring.
///
/// Takes the two Class-C fields it mutates (`&mut ReceiveBuffer`,
/// `&mut VecDeque<PaymentReceipt>`) rather than `&mut PerContextState`, so a
/// cell-holder supplies them from a `ClassCMut` view
/// (`receive_buffer_mut()` / `payment_receipts_mut()`) with no whole-state
/// borrow.
///
/// Per ADR-051 §6 / the phase-2.md ADR-011 amendment exclusion taxonomy §2, the
/// `PaymentReceived` is per-payee application activity appended by the payee
/// alone — it is **excluded from the canonical Merkle log** so that two honest
/// members derive the same `event_log_merkle_root` (§9.9.3). The local
/// `ContextEvent` and the `payment_receipts` buffer are the sole surfacing of a
/// capture. The emitted event carries BOTH `payer` and `payee` from the verified
/// receipt (the payee records the payment per §19.6.1) with `anchored: false`
/// (not Merkle-proven until ADR-051).
#[allow(dead_code)]
pub fn surface_paid_action_receipt(
    receive_buffer: &mut scp_protocol::context::membership::ReceiveBuffer,
    payment_receipts: &mut std::collections::VecDeque<PaymentReceipt>,
    deps: &ActorDeps,
    receipt: &PaymentReceipt,
    context_id: &str,
) {
    emit_payment_received_event(receive_buffer, deps, receipt, context_id);
    record_payment_receipt(payment_receipts, receipt);
}

/// Emit the LOCAL `ContextEvent::PaymentReceived` for a verified capture (the
/// receive-buffer half of [`surface_paid_action_receipt`]). Takes only
/// `&mut ReceiveBuffer`, so a cell-holder supplies it from a `ClassCMut` view
/// (`receive_buffer_mut()`) — sequenced before [`record_payment_receipt`] so the
/// view's two `&mut self` reborrows are never live at once.
#[allow(dead_code)]
pub fn emit_payment_received_event(
    receive_buffer: &mut scp_protocol::context::membership::ReceiveBuffer,
    deps: &ActorDeps,
    receipt: &PaymentReceipt,
    context_id: &str,
) {
    // Surface the capture as a LOCAL `ContextEvent` (no durable Merkle leaf —
    // per-payee, non-convergent; ADR-051 §6 / phase-2.md §2). Both `payer` and
    // `payee` come from the verified receipt; `anchored` is false (pre-ADR-051).
    let event = ContextEvent::PaymentReceived {
        receipt_id: receipt.receipt_id,
        payer: receipt.payer.clone(),
        payee: receipt.payee.clone(),
        amount: receipt.amount.value(),
        action: paid_action_label(&receipt.action_type).to_owned(),
        anchored: false,
    };
    crate::context::state::emit_event_into(
        receive_buffer,
        event,
        context_id,
        deps.event_tx.as_ref(),
    );
}

/// Record a verified receipt in the bounded `payment_receipts` ring (the
/// buffer half of [`surface_paid_action_receipt`]). Takes only the
/// `&mut VecDeque<PaymentReceipt>` field.
///
/// Spec §19.11: backs the `payment_history` query — NOT the durable Merkle log.
/// Bounded oldest-evicted ring at the same capacity as the sibling
/// `receive_buffer` so a long-lived paid context cannot grow this buffer without
/// limit (memory-growth `DoS`). Evicts the oldest before pushing the newest once
/// the buffer is full.
#[allow(dead_code)]
pub fn record_payment_receipt(
    payment_receipts: &mut std::collections::VecDeque<PaymentReceipt>,
    receipt: &PaymentReceipt,
) {
    if payment_receipts.len() >= scp_protocol::context::membership::DEFAULT_BUFFER_CAPACITY {
        payment_receipts.pop_front();
    }
    payment_receipts.push_back(receipt.clone());
}

/// Maps a [`PaidActionType`] to the canonical action label carried in
/// [`ContextEvent::PaymentReceived`] / [`ContextEvent::PaymentCaptureFailed`]
/// (`"send_message"` / `"join_context"`; spec §19.6.1).
const fn paid_action_label(action_type: &PaidActionType) -> &'static str {
    match action_type {
        PaidActionType::MessageSend => "send_message",
        PaidActionType::ContextJoin => "join_context",
        PaidActionType::ToolInvoke => "tool_invoke",
        PaidActionType::SubscriptionPeriod => "subscription_period",
        PaidActionType::ByteStored => "byte_stored",
    }
}

// ---------------------------------------------------------------------------
// void_paid_action (escrow rollback)
// ---------------------------------------------------------------------------

/// Voids a paid action authorization on failure (escrow rollback).
///
/// Calls `adapter.void` to release the escrow hold. Best-effort: logs
/// but does not propagate void failures.
// Transitional Phase 2A surface: messaging/lifecycle call the legacy
// twins until those domains migrate to actor-owned state.
//
// ADR-049 §9 Class-S cell seam: takes NO per-context state — it touches only the
// adapter on the authorization. The former `&mut PerContextState` parameter was
// unused (`_state`); it is dropped rather than narrowed because this is an `async`
// fn and a `&PerContextState` held across the void `.await` is not `Send`
// (`PerContextState` is `!Sync`). Both callers (the join tail and the send path)
// drop the now-removed argument — a mechanical, behaviour-neutral call-site edit.
#[allow(dead_code)]
pub async fn void_paid_action(_deps: &ActorDeps, auth: PaidActionAuthorization, context_id: &str) {
    if let Some(ref authorization) = auth.prepared.envelope.authorization
        && let Err(e) = auth.adapter.void_dyn(authorization).await
    {
        tracing::warn!(context_id, "failed to void payment authorization: {e}");
    }
}
