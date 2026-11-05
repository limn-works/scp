//! Escrow-based payment flow on `ContextManager` (spec section 19.2.2, #1537).
//!
//! Implements the correct 9-step payment integration as an escrow pattern:
//! 1. `authorize_paid_action` — evaluates cost, checks spending UCAN,
//!    checks budget, calls adapter.authorize (escrow). Returns authorization.
//! 2. The caller performs the action (encrypt, MLS add, outlet execute).
//! 3. `complete_paid_action` — captures payment, stores receipt, records spend.
//! 4. `void_paid_action` — voids authorization, rolls back budget on failure.
//!
//! This eliminates the previous payment-before-action ordering bug where
//! payment was captured before the action succeeded.
//!
//! When no payment adapter is configured (`self.payment_adapter` is `None`),
//! `authorize_paid_action` returns `Ok(None)` immediately.
//!
//! See spec section 19.2.2 and ADR-033 in `.docs/adrs/phase-3.md`.

use scp_runtime_core::context::shared::economy::EnforceEconomyRequest;
use scp_runtime_core::context::shared::economy::validate_spending_ucan_or_error;

use scp_protocol::context::ContextError;
use scp_protocol::economy::policy::ObservableMetrics;
use scp_protocol::economy::types::PaidActionType;

use scp_runtime_types::economy::adapter::{PaymentAdapterDyn, PaymentReceipt};
use scp_runtime_types::economy::integration::IntegrationError;

// ---------------------------------------------------------------------------
// Spending UCAN signature validation wiring (C1, PR #1606)
// ---------------------------------------------------------------------------

/// Maps an [`IntegrationError`] to a [`ContextError`] with proper SCP error codes.
///
/// [`crate::helpers`] maps errors through it (ADR-049 §15). The enclosing
/// `logic` module is private, so it is crate-internal despite `pub`.
pub fn integration_error_to_context(err: IntegrationError) -> ContextError {
    match err {
        IntegrationError::CostEvaluationOverflow => {
            ContextError::PermissionDenied("SCP-ECON-12040: cost evaluation overflow".to_owned())
        }
        IntegrationError::AuthorizationFailed(e) => ContextError::PermissionDenied(format!(
            "SCP-ECON-12041: payment authorization failed: {e}"
        )),
        IntegrationError::CostInsufficient {
            expected, provided, ..
        } => ContextError::PermissionDenied(format!(
            "SCP-ECON-12042: cost insufficient: expected {expected}, provided {provided}"
        )),
        IntegrationError::AuthorizationVerificationFailed(e) => ContextError::PermissionDenied(
            format!("SCP-ECON-12043: authorization verification failed: {e}"),
        ),
        IntegrationError::ActionProcessingFailed(msg) => ContextError::PermissionDenied(format!(
            "SCP-ECON-12044: action processing failed: {msg}"
        )),
        IntegrationError::CaptureFailed(e) => {
            ContextError::PermissionDenied(format!("SCP-ECON-12045: payment capture failed: {e}"))
        }
        IntegrationError::VoidFailed {
            original,
            void_error,
        } => ContextError::PermissionDenied(format!(
            "SCP-ECON-12046: void failed (original: {original}, void: {void_error})"
        )),
        IntegrationError::NoEconomicPolicy => ContextError::PermissionDenied(
            "SCP-ECON-12047: no economic policy configured".to_owned(),
        ),
    }
}

/// Verifies a receipt and checks it is valid.
///
/// Visibility widened in ADR-049 §15 so the hoisted
/// [`crate::helpers::complete_paid_action`] free
/// function can call the same verifier the legacy method did. The
/// enclosing `economy` module is `pub(crate)` so the effective
/// visibility is unchanged.
pub async fn verify_and_check_receipt(
    adapter: &dyn PaymentAdapterDyn,
    receipt: &PaymentReceipt,
) -> Result<(), ContextError> {
    // Call verify_dyn directly — we have one adapter and one receipt, so
    // the multi-verifier dispatch in `verify_receipts_dyn` adds no value here.
    let result = adapter.verify_dyn(receipt).await.map_err(|e| {
        ContextError::PermissionDenied(format!("SCP-ECON-12049: receipt verification error: {e}"))
    })?;
    if !result.valid {
        return Err(ContextError::PermissionDenied(
            "SCP-ECON-12048: receipt verification failed: receipt marked invalid".to_owned(),
        ));
    }
    Ok(())
}

/// Unified economy enforcement: evaluate cost, check spending UCAN, check budget.
///
/// This replaces the former separate economy enforcement functions.
/// One unified flow per the escrow
/// pattern: evaluate cost -> check spending UCAN -> check budget -> deduct.
///
/// The cost is composed by (a) evaluating the policy formula (if any) to obtain
/// a base cost — falling back to `pricing.base_cost` when the formula is absent
/// — and then (b) layering the per-DID escalation/floor/cap from `pricing` via
/// [`SenderVelocityTracker::compute_escalated_cost`](scp_protocol::economy::antispam::SenderVelocityTracker::compute_escalated_cost) (spec §19.7).
///
/// Returns the deducted cost for rollback on failure, or `None` if no cost.
pub fn enforce_economy(
    req: EnforceEconomyRequest<'_>,
) -> Result<Option<scp_protocol::economy::types::Amount>, ContextError> {
    let EnforceEconomyRequest {
        economic_policy,
        budget_tracker,
        velocity_tracker,
        member_count,
        action_type,
        actor_did,
        now,
        spending_ucan,
        action_label,
        context_id,
        clock,
        pricing,
        nonce_tracker,
        revoked_spending_ucan_cids,
        key_resolver,
    } = req;
    // Free contexts (no `economic_policy`) do not charge at the cost layer.
    // Defense-in-depth against spam on free contexts is provided by the
    // Matrix-style token-bucket hard rate limit, which is enforced earlier
    // in the send/join/invoke paths and operates independently of cost.
    let Some(policy) = economic_policy else {
        return Ok(None);
    };

    // Step 1: derive a base cost from the policy. When the policy carries a
    // pricing formula, evaluate it against observable metrics; otherwise the
    // formula is absent and `evaluate_cost` consults the flat `CostSchedule`.
    //
    // §19.7 escalation applies to MessageSend, ContextJoin, and OutletCall.
    // For SubscriptionPeriod and ByteStored we delegate entirely to the
    // policy (no per-DID escalation makes sense for them).
    let escalation_eligible = matches!(
        action_type,
        PaidActionType::MessageSend | PaidActionType::ContextJoin | PaidActionType::OutletCall
    );

    let velocity = velocity_tracker.get_velocity(actor_did, now);
    let metrics = ObservableMetrics {
        sender_velocity: velocity,
        member_count: u64::try_from(member_count).unwrap_or(u64::MAX),
        context_message_rate: velocity_tracker.aggregate_velocity(now),
        relay_queue_depth: 0,
        time_of_day: now % 86400,
        storage_usage: 0,
    };
    let Some(base_cost) =
        scp_protocol::economy::policy::evaluate_cost(policy, &action_type, &metrics)
    else {
        return Err(ContextError::PermissionDenied(
            "SCP-ECON-12040: cost evaluation overflow".to_owned(),
        ));
    };

    // Step 2: layer per-DID escalation/floor/cap (§19.7) on top of the
    // policy-derived base cost for eligible actions. When the policy
    // explicitly prices an action at zero (`per_message: Some(Amount(0))`
    // or `per_message: None`), the action remains free — escalation only
    // layers on top of an existing non-zero cost so that operators can
    // define free action types even under a priced policy.
    let cost = if escalation_eligible && base_cost.value() > 0 {
        velocity_tracker.compute_escalated_cost(
            actor_did,
            now,
            base_cost,
            &pricing.escalation,
            pricing.floor,
            pricing.cap,
        )
    } else {
        base_cost
    };

    if cost.0 == 0 {
        return Ok(None);
    }

    // AND-composition (spec §19.5, #1593): paid actions require both the
    // action capability AND a spending UCAN. The action capability side is
    // verified UPSTREAM at the `member_has_capability` gate (see
    // `messaging.rs` for `MessagesWrite`, `lifecycle.rs` for `ContextJoin`,
    // etc.). This block verifies the spending side.
    // Free actions (cost == 0) pass through above.
    if spending_ucan.is_none() {
        return Err(ContextError::PermissionDenied(
            "SCP-ECON-12060: paid action requires spending UCAN".to_owned(),
        ));
    }
    debug_assert!(
        spending_ucan.is_some(),
        "spending UCAN should be Some at this point — None case returns above"
    );
    scp_protocol::crypto::ucan::spending::check_spending_capability(
        spending_ucan,
        scp_protocol::crypto::ucan::spending::Amount(cost.0),
        action_label,
    )
    .map_err(|e| ContextError::PermissionDenied(format!("SCP-ECON-12061: {e}")))?;

    // Cryptographic + replay probe + scope + expiry + attenuation validation
    // of the spending UCAN. `spending_ucan` is guaranteed `Some` by the guard
    // above.
    //
    // C1 (PR #1606): before this call landed, only `validate_spending_ucan`
    // was invoked, which checks scope and lifetime but performs NO
    // signature verification, NO `iss == actor_did` binding, NO key-scope
    // check, NO revocation lookup, and (separately) only the nonce check
    // below. A fabricated `UcanToken` with attacker-chosen fields and
    // `signature: vec![]` passed enforcement. The combined entry point
    // `validate_spending_ucan_signed` runs the full pipeline — signature,
    // chain, key scope, expiry, revocation, nonce probe (check_replay only),
    // scope, capability, attenuation — in one call, with the per-context
    // nonce tracker and revocation set wired in.
    //
    // H11: the nonce is only PROBED here (check_replay), not recorded.
    // Recording happens below, after the budget gate, via
    // `commit_spending_ucan_nonce`. This prevents nonce-burn DoS: a
    // budget-rejected request must not exhaust tracker capacity.
    if let Some(spending) = spending_ucan {
        validate_spending_ucan_or_error(
            spending,
            actor_did,
            context_id,
            nonce_tracker,
            revoked_spending_ucan_cids,
            key_resolver,
            clock,
        )?;
    }

    // Budget check — no auto-grant. If the member has no budget, fail with
    // NoBudget error telling the caller to request an ApproveSpend governance
    // action. Budget must be explicitly granted via governance.
    if !budget_tracker.has_budget(actor_did) {
        return Err(ContextError::PermissionDenied(format!(
            "SCP-ECON-12010: no budget for {actor_did} — request ApproveSpend governance action"
        )));
    }
    budget_tracker.record_spend(actor_did, cost).map_err(|e| {
        ContextError::PermissionDenied(format!("SCP-ECON-12011: budget exceeded: {e}"))
    })?;

    // H11: commit the nonce AFTER the budget gate passes. This is the
    // second phase of the split-phase nonce protocol — the read-only probe
    // (check_replay) ran inside validate_spending_ucan_or_error above;
    // the durable insertion (record) happens here so that budget-rejected
    // requests cannot burn nonce tracker capacity.
    if let Some(spending) = spending_ucan {
        scp_protocol::crypto::ucan::spending::commit_spending_ucan_nonce(spending, nonce_tracker)
            .map_err(|e| {
            ContextError::PermissionDenied(format!(
                "SCP-ECON-12066: nonce commit failed after budget acceptance: {e}"
            ))
        })?;
    }

    Ok(Some(cost))
}

pub fn rand_idempotency_key() -> [u8; 16] {
    *uuid::Uuid::new_v4().as_bytes()
}
