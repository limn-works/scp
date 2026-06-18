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

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::economy::policy::ObservableMetrics;
use scp_protocol::economy::types::PaidActionType;

use crate::context::actor::deps::ActorDeps;
use crate::context::actor::state::PerContextState;
use crate::context::economy_logic::PaidActionAuthorization;
use crate::context::state::context_id_to_bytes;
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
    _state: &mut PerContextState,
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
// authorize_paid_action (escrow phase 1)
// ---------------------------------------------------------------------------

/// Authorizes a paid action (escrow pattern, step 1).
///
/// Evaluates cost from actor-owned governance policy and metrics, checks
/// spending authorization through the payment integration layer, and
/// calls the configured adapter to create an escrow hold.
///
/// Returns `Ok(None)` when no payment adapter is configured, no economic
/// policy is configured, or the evaluated cost is zero.
///
/// # Errors
///
/// Returns any error from the payment integration layer mapped to
/// [`ContextError`].
// Transitional Phase 2A surface: messaging/lifecycle call the legacy
// twins until those domains migrate to actor-owned state.
#[allow(dead_code)]
pub async fn authorize_paid_action(
    state: &mut PerContextState,
    deps: &ActorDeps,
    action_type: PaidActionType,
    payer_did: &DID,
    context_id: &str,
) -> Result<Option<PaidActionAuthorization>, ContextError> {
    let Some(adapter_arc) = deps.payment_adapter.as_ref().map(Arc::clone) else {
        return Ok(None);
    };

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

    let Some(policy) = policy else {
        return Ok(None);
    };

    if scp_protocol::economy::policy::evaluate_cost(&policy, &action_type, &metrics)
        .as_ref()
        .is_none_or(|c| c.0 == 0)
    {
        return Ok(None);
    }

    let metadata = PaymentMetadata {
        action_type: action_type.clone(),
        context_id: Some(context_id.to_owned()),
        idempotency_key: crate::context::economy_logic::rand_idempotency_key(),
    };

    let prepared = integration::prepare_paid_action(
        adapter_arc.as_ref(),
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
        adapter: adapter_arc,
        policy,
        metrics,
    }))
}

// ---------------------------------------------------------------------------
// complete_paid_action (escrow phase 3)
// ---------------------------------------------------------------------------

/// Completes a paid action after successful execution (escrow capture).
///
/// Calls `adapter.capture`, verifies the receipt, stores it in the event
/// log, and updates actor-owned checkpoint tracking.
///
/// # Errors
///
/// Returns any error from the payment integration layer.
// Transitional Phase 2A surface: messaging/lifecycle call the legacy
// twins until those domains migrate to actor-owned state.
#[allow(dead_code)]
pub async fn complete_paid_action(
    state: &mut PerContextState,
    deps: &ActorDeps,
    auth: PaidActionAuthorization,
    payer_did: &DID,
    context_id: &str,
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

    let context_id_bytes = context_id_to_bytes(context_id);
    if let Err(e) = deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::PaymentReceived,
        payer_did.as_ref(),
    ) {
        tracing::warn!(
            context_id,
            "failed to store payment receipt in event log: {e}"
        );
    }

    state.checkpoint_events_since += 1;

    Ok(Some(receipt))
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
#[allow(dead_code)]
pub async fn void_paid_action(
    _state: &mut PerContextState,
    _deps: &ActorDeps,
    auth: PaidActionAuthorization,
    context_id: &str,
) {
    if let Some(ref authorization) = auth.prepared.envelope.authorization
        && let Err(e) = auth.adapter.void_dyn(authorization).await
    {
        tracing::warn!(context_id, "failed to void payment authorization: {e}");
    }
}
