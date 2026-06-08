// Module-level allow — the legacy inherent-impl form in
// `manager/economy.rs` carried `#[allow(clippy::significant_drop_tightening)]`
// on its impl block. The hoisted bodies preserve the same lock-hold-across-await
// patterns deliberately (narrowing changes lock-ordering semantics across the
// per-context mutex); allowing the lint crate-locally keeps the hoist
// byte-identical to the legacy behavior.
#![allow(clippy::significant_drop_tightening)]

//! Economy helpers with explicit-collaborator signatures (ADR-049 commit 12).
//!
//! # Purpose
//!
//! This module hoists the economy-domain method that the actor handler in
//! [`crate::context::actor::handlers::economy`] currently reaches via
//! `view.manager().X(...)`. After ADR-049 commit 12 (`ContextManager`
//! deletion) every helper takes `&Supervisor`; Phase 2 of the
//! post-review-round-1 plan will retarget the handler-side helpers to
//! `&mut PerContextState + &ActorDeps`.
//!
//! This file is the economy counterpart to
//! [`crate::context::messaging_helpers`] (12b.1, 12c.1, 12c.1b),
//! [`crate::context::lifecycle_helpers`] (12c.2),
//! [`crate::context::governance_helpers`] (12c.3), and
//! [`crate::context::trust_recovery_helpers`] (12c.3).
//!
//! # Supervisor receiver (ADR-049 commit 12)
//!
//! The remaining escrow helpers take `supervisor: &Supervisor`. The
//! payment adapter is lifted onto the supervisor by
//! `Supervisor::with_providers` (commit 12c.9a).
//!
//! The top-level `verify_payment_receipts` entry point that previously
//! lived here was supervisor-/payment-adapter-scoped only (no per-context
//! read); its sole live caller — `Supervisor::dispatch_economy_direct` —
//! now inlines the adapter-only verification loop directly, and the
//! actor-shape twin [`economy_helpers::verify_payment_receipts`](crate::context::economy_helpers::verify_payment_receipts)
//! serves the per-actor path. This module retains only the three escrow
//! primitives below, reached exclusively from
//! [`crate::context::lifecycle_helpers_legacy`].
//!
//! # Escrow primitives hoisted (ADR-049 commit 12)
//!
//! [`authorize_paid_action`], [`complete_paid_action`], and
//! [`void_paid_action`] are the three-phase escrow primitives reached
//! from the hoisted messaging / lifecycle helpers as
//! `economy_helpers::X(supervisor, ...)`. The 12c.9g.1 hoist commit
//! moved their bodies here as free functions on `&Supervisor`; the
//! 12c.9g.2 helper rewire migrated every callsite from the legacy
//! manager-method form to the direct free-function call. The legacy
//! methods on [`Supervisor`](crate::context::supervisor::Supervisor)
//! remain as one-line forwarders for FFI use. The companion
//! `record_payment_capture_failure` lives in
//! [`crate::context::manager_methods`] (cross-domain infrastructure used
//! by both messaging and economy paths).

use std::sync::Arc;

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::economy::policy::ObservableMetrics;
use scp_protocol::economy::types::PaidActionType;

use crate::context::economy_logic::PaidActionAuthorization;
use crate::context::supervisor::Supervisor;
use crate::economy::adapter::{PaymentMetadata, PaymentReceipt};
use crate::economy::integration;

// Phase 1 fix-up of ADR-049 (post-review-round-1): per-helper
// `ATTACHED_EXPECT` constants consolidated to the single
// `PROVIDER_NOT_INITIALIZED` definition in `manager_methods`.
use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED as ATTACHED_EXPECT;

// ---------------------------------------------------------------------------
// authorize_paid_action (escrow phase 1; ADR-049 commit 12c.9g.1)
// ---------------------------------------------------------------------------

/// Authorizes a paid action (escrow pattern, step 1).
///
/// Hoisted body of the legacy
/// [`ContextManager::authorize_paid_action`](crate::context::supervisor::Supervisor::authorize_paid_action)
/// (ADR-049 commit 12). Byte-identical behavior.
///
/// Evaluates cost, checks spending UCAN, checks budget, and calls
/// `adapter.authorize` to create an escrow hold. The caller performs the
/// action, then calls [`complete_paid_action`] or [`void_paid_action`].
///
/// Returns `Ok(None)` when no payment adapter is configured or cost is
/// zero.
///
/// # Errors
///
/// Returns [`ContextError::NotInitialized`] if the supervisor has not
/// been attached, [`ContextError::ContextNotRegistered`] if the context
/// is unknown, or any error from the payment integration layer
/// (mapped via `integration_error_to_context`).
pub async fn authorize_paid_action_legacy(
    supervisor: &Supervisor,
    action_type: PaidActionType,
    payer_did: &DID,
    context_id: &str,
) -> Result<Option<PaidActionAuthorization>, ContextError> {
    // Early exit: no adapter means no payment flow.
    let Some(adapter_arc) = supervisor.payment_adapter_ref().map(Arc::clone) else {
        return Ok(None);
    };
    let clock = supervisor
        .clock_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;

    // Phase 1: Extract policy + metrics under lock, then drop.
    let (policy, metrics) = {
        let ctx_arc = crate::context::manager_methods::get_context_arc(supervisor, context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        let guard = ctx_arc.lock().await;
        let ctx = &*guard;

        let policy = ctx.governance.economic_policy.clone();
        let member_count = u64::try_from(ctx.membership.count()).unwrap_or(u64::MAX);
        let velocity = ctx
            .governance
            .velocity_tracker
            .get_velocity(payer_did, clock.now_secs());

        let now_secs = clock.now_secs();
        let metrics = ObservableMetrics {
            sender_velocity: velocity,
            member_count,
            context_message_rate: ctx.governance.velocity_tracker.aggregate_velocity(now_secs),
            relay_queue_depth: 0,
            time_of_day: now_secs % 86400,
            storage_usage: 0,
        };
        (policy, metrics)
    };

    // No economic policy -> no payment flow.
    let Some(policy) = policy else {
        return Ok(None);
    };

    // Evaluate cost — zero cost means no payment needed.
    if scp_protocol::economy::policy::evaluate_cost(&policy, &action_type, &metrics)
        .as_ref()
        .is_none_or(|c| c.0 == 0)
    {
        return Ok(None);
    }

    // Phase 2: Authorize (escrow) via adapter (no lock held).
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
// complete_paid_action (escrow phase 3; ADR-049 commit 12c.9g.1)
// ---------------------------------------------------------------------------

/// Completes a paid action after successful execution (escrow capture).
///
/// Hoisted body of the legacy
/// [`ContextManager::complete_paid_action`](crate::context::supervisor::Supervisor::complete_paid_action)
/// (ADR-049 commit 12). Byte-identical behavior.
///
/// Calls `adapter.capture`, verifies the receipt, stores it in the event
/// log, and records budget spend.
///
/// # Errors
///
/// Returns [`ContextError::NotInitialized`] if the supervisor has not
/// been attached, or any error from the payment integration layer.
pub async fn complete_paid_action_legacy(
    supervisor: &Supervisor,
    auth: PaidActionAuthorization,
    payer_did: &DID,
    context_id: &str,
) -> Result<Option<PaymentReceipt>, ContextError> {
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    // Capture the escrowed authorization via process_paid_action.
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

    // Verify the receipt.
    crate::context::economy_logic::verify_and_check_receipt(auth.adapter.as_ref(), &receipt)
        .await?;

    // Store receipt in event log.
    let context_id_bytes = crate::context::state::context_id_to_bytes(context_id);
    if let Err(e) =
        event_log.append_context_event(&context_id_bytes, "PaymentReceived", payer_did.as_ref())
    {
        tracing::warn!(
            context_id,
            "failed to store payment receipt in event log: {e}"
        );
    }

    // Checkpoint tracking: count this event for threshold-based checkpoints.
    {
        if let Ok(ctx_arc) =
            crate::context::manager_methods::get_context_arc(supervisor, context_id)
        {
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            ctx.checkpoint_events_since += 1;
        }
    }

    Ok(Some(receipt))
}

// ---------------------------------------------------------------------------
// void_paid_action (escrow rollback; ADR-049 commit 12c.9g.1)
// ---------------------------------------------------------------------------

/// Voids a paid action authorization on failure (escrow rollback).
///
/// Hoisted body of the legacy
/// [`ContextManager::void_paid_action`](crate::context::supervisor::Supervisor::void_paid_action)
/// (ADR-049 commit 12). Byte-identical behavior.
///
/// Calls `adapter.void` to release the escrow hold. Best-effort —
/// logs but does not propagate void failures.
///
/// Used by `send_message` when `encrypt_and_send` fails after
/// `authorize_paid_action` succeeded (escrow pattern: authorize →
/// action → complete on success / void on failure).
pub async fn void_paid_action_legacy(
    _supervisor: &Supervisor,
    auth: PaidActionAuthorization,
    context_id: &str,
) {
    if let Some(ref authorization) = auth.prepared.envelope.authorization
        && let Err(e) = auth.adapter.void_dyn(authorization).await
    {
        tracing::warn!(context_id, "failed to void payment authorization: {e}");
    }
}
