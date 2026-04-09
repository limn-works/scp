//! Escrow-based payment flow on `ContextManager` (spec section 19.2.2, #1537).
//!
//! Implements the correct 9-step payment integration as an escrow pattern:
//! 1. `authorize_paid_action` — evaluates cost, checks spending UCAN,
//!    checks budget, calls adapter.authorize (escrow). Returns authorization.
//! 2. The caller performs the action (encrypt, MLS add, tool execute).
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

use std::sync::Arc;

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::economy::policy::ObservableMetrics;
use scp_protocol::economy::types::PaidActionType;

use crate::economy::adapter::{
    AdapterAsVerifier, PaymentAdapter, PaymentAdapterDyn, PaymentMetadata, PaymentReceipt,
};
use crate::economy::integration::{self, IntegrationError};
use crate::economy::receipt::{
    PaymentVerifierDyn, ReceiptVerification, ReceiptVerificationError, verify_receipts_dyn,
};

use super::ContextManager;

/// Authorization token returned by `authorize_paid_action`.
///
/// Holds the escrow authorization and evaluated cost so that
/// `complete_paid_action` and `void_paid_action` can finalize or roll back.
pub(super) struct PaidActionAuthorization {
    /// The prepared action containing the authorization envelope.
    prepared: integration::PreparedAction,
    /// The adapter bridge for capture/void.
    bridge: DynAdapterBridge,
    /// The economic policy used for evaluation.
    policy: scp_protocol::economy::types::EconomicPolicy,
    /// Metrics snapshot for `process_paid_action`.
    metrics: ObservableMetrics,
}

/// Wrapper that delegates [`crate::economy::adapter::PaymentAdapter`] methods
/// to a `dyn PaymentAdapterDyn` behind an `Arc`.
///
/// The generic functions `prepare_paid_action` and `process_paid_action` require
/// `A: PaymentAdapter`. This wrapper implements `PaymentAdapter` by forwarding
/// through the boxed-future `PaymentAdapterDyn` methods, bridging the generic
/// and trait-object worlds.
struct DynAdapterBridge(Arc<dyn PaymentAdapterDyn>);

#[allow(clippy::similar_names)] // payer/payee is the domain language
impl crate::economy::adapter::PaymentAdapter for DynAdapterBridge {
    fn adapter_id(&self) -> &str {
        self.0.adapter_id()
    }

    fn capabilities(&self) -> crate::economy::adapter::AdapterCapabilities {
        self.0.capabilities()
    }

    async fn authorize(
        &self,
        payer: &DID,
        payee: &DID,
        amount: scp_protocol::economy::types::Amount,
        currency: scp_protocol::economy::types::CurrencyCode,
        metadata: PaymentMetadata,
    ) -> Result<crate::economy::adapter::PaymentAuthorization, crate::economy::adapter::PaymentError>
    {
        self.0
            .authorize_dyn(payer, payee, amount, currency, metadata)
            .await
    }

    async fn capture(
        &self,
        auth: &crate::economy::adapter::PaymentAuthorization,
    ) -> Result<PaymentReceipt, crate::economy::adapter::PaymentError> {
        self.0.capture_dyn(auth).await
    }

    async fn void(
        &self,
        auth: &crate::economy::adapter::PaymentAuthorization,
    ) -> Result<(), crate::economy::adapter::PaymentError> {
        self.0.void_dyn(auth).await
    }

    async fn verify_authorization(
        &self,
        auth: &crate::economy::adapter::PaymentAuthorization,
    ) -> Result<(), crate::economy::adapter::PaymentError> {
        self.0.verify_authorization_dyn(auth).await
    }

    async fn verify(
        &self,
        receipt: &PaymentReceipt,
    ) -> Result<crate::economy::adapter::VerificationResult, crate::economy::adapter::PaymentError>
    {
        self.0.verify_dyn(receipt).await
    }

    async fn refund(
        &self,
        receipt: &PaymentReceipt,
        amount: Option<scp_protocol::economy::types::Amount>,
    ) -> Result<crate::economy::adapter::RefundConfirmation, crate::economy::adapter::PaymentError>
    {
        self.0.refund_dyn(receipt, amount).await
    }
}

/// Maps an [`IntegrationError`] to a [`ContextError`] with proper SCP error codes.
fn integration_error_to_context(err: IntegrationError) -> ContextError {
    match err {
        IntegrationError::CostEvaluationOverflow => {
            ContextError::PermissionDenied("SCP-ECON-7040: cost evaluation overflow".to_owned())
        }
        IntegrationError::AuthorizationFailed(e) => ContextError::PermissionDenied(format!(
            "SCP-ECON-7041: payment authorization failed: {e}"
        )),
        IntegrationError::CostInsufficient {
            expected, provided, ..
        } => ContextError::PermissionDenied(format!(
            "SCP-ECON-7042: cost insufficient: expected {expected}, provided {provided}"
        )),
        IntegrationError::AuthorizationVerificationFailed(e) => ContextError::PermissionDenied(
            format!("SCP-ECON-7043: authorization verification failed: {e}"),
        ),
        IntegrationError::ActionProcessingFailed(msg) => ContextError::PermissionDenied(format!(
            "SCP-ECON-7044: action processing failed: {msg}"
        )),
        IntegrationError::CaptureFailed(e) => {
            ContextError::PermissionDenied(format!("SCP-ECON-7045: payment capture failed: {e}"))
        }
        IntegrationError::VoidFailed {
            original,
            void_error,
        } => ContextError::PermissionDenied(format!(
            "SCP-ECON-7046: void failed (original: {original}, void: {void_error})"
        )),
        IntegrationError::NoEconomicPolicy => ContextError::PermissionDenied(
            "SCP-ECON-7047: no economic policy configured".to_owned(),
        ),
    }
}

/// Verifies a receipt and checks it is valid.
async fn verify_and_check_receipt(
    bridge: &DynAdapterBridge,
    receipt: &PaymentReceipt,
) -> Result<(), ContextError> {
    let verifier = AdapterAsVerifier(&*bridge.0);
    let verification_results = verify_receipts_dyn(
        &[&verifier as &dyn PaymentVerifierDyn],
        std::slice::from_ref(receipt),
    )
    .await;
    if verification_results.is_empty() {
        return Err(ContextError::PermissionDenied(
            "SCP-ECON-7050: receipt verification returned no results (vacuous pass)".to_owned(),
        ));
    }
    for result in &verification_results {
        match result {
            Ok(v) if !v.result.valid => {
                return Err(ContextError::PermissionDenied(
                    "SCP-ECON-7048: receipt verification failed: receipt marked invalid".to_owned(),
                ));
            }
            Err(e) => {
                return Err(ContextError::PermissionDenied(format!(
                    "SCP-ECON-7049: receipt verification error: {e}"
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Input parameters for [`enforce_economy`].
///
/// F9: grouped into a struct to stop the parameter list from drifting
/// back above the `clippy::too_many_arguments` threshold as new layers
/// (pricing, nonce tracker, per-DID escalation) are added. Constructing
/// this struct directly at call sites is the contract; positional
/// argument calls are compile-rejected.
pub(super) struct EnforceEconomyRequest<'a> {
    /// Per-context economic policy, if any. `None` means a free context.
    pub economic_policy: Option<&'a scp_protocol::economy::types::EconomicPolicy>,
    /// Per-context budget tracker (mutable — deductions happen in-place).
    pub budget_tracker: &'a mut scp_protocol::economy::budget::MemberBudgetTracker,
    /// Per-context velocity tracker — consulted for per-DID escalation.
    pub velocity_tracker: &'a scp_protocol::economy::antispam::SenderVelocityTracker,
    /// Current member count (used for the `member_count` metric).
    pub member_count: usize,
    /// The kind of paid action being enforced.
    pub action_type: PaidActionType,
    /// The DID being charged.
    pub actor_did: &'a DID,
    /// Unix seconds when this enforcement is running.
    pub now: u64,
    /// Optional spending UCAN provided by the caller. Required for paid actions.
    pub spending_ucan: Option<&'a scp_protocol::crypto::ucan::UcanToken>,
    /// Capability URI label stamped onto spending-UCAN validation errors.
    pub action_label: &'a str,
    /// Context ID the spending UCAN must scope to.
    pub context_id: &'a str,
    /// Clock used for UCAN expiry validation.
    pub clock: &'a dyn scp_primitives::Clock,
    /// Per-context pricing configuration (escalation curve, floor, cap).
    pub pricing: &'a scp_protocol::economy::antispam::ContextMessagePricingConfig,
    /// Per-context nonce tracker for spending-UCAN replay prevention.
    pub nonce_tracker: &'a mut scp_protocol::crypto::ucan::nonce::NonceTracker<
        std::sync::Arc<dyn scp_primitives::Clock>,
    >,
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
/// [`SenderVelocityTracker::compute_escalated_cost`] (spec §19.7).
///
/// Returns the deducted cost for rollback on failure, or `None` if no cost.
pub(super) fn enforce_economy(
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
    // §19.7 escalation applies to MessageSend, ContextJoin, and ToolInvoke.
    // For SubscriptionPeriod and ByteStored we delegate entirely to the
    // policy (no per-DID escalation makes sense for them).
    let escalation_eligible = matches!(
        action_type,
        PaidActionType::MessageSend | PaidActionType::ContextJoin | PaidActionType::ToolInvoke
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
            "SCP-ECON-7063: cost evaluation overflow".to_owned(),
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
            "SCP-ECON-7060: paid action requires spending UCAN".to_owned(),
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
    .map_err(|e| ContextError::PermissionDenied(format!("SCP-ECON-7061: {e}")))?;

    // Validate the spending UCAN itself: context scope, expiry, attenuation.
    // `spending_ucan` is guaranteed `Some` by the guard above.
    if let Some(spending) = spending_ucan {
        scp_protocol::crypto::ucan::spending::validate_spending_ucan(
            spending, context_id, None, // no parent capability (top-level delegation)
            clock,
        )
        .map_err(|e| ContextError::PermissionDenied(format!("SCP-ECON-7062: {e}")))?;

        // Nonce replay prevention: validate the spending UCAN nonce has not been
        // used before. This prevents replay attacks where a valid spending UCAN
        // is resubmitted to authorize the same action multiple times.
        nonce_tracker
            .check_and_record(&spending.payload.nnc, spending.payload.exp)
            .map_err(|e| {
                ContextError::PermissionDenied(format!(
                    "SCP-ECON-7064: spending UCAN nonce replay: {e}"
                ))
            })?;
    }

    // Budget check — no auto-grant. If the member has no budget, fail with
    // NoBudget error telling the caller to request an ApproveSpend governance
    // action. Budget must be explicitly granted via governance.
    if !budget_tracker.has_budget(actor_did) {
        return Err(ContextError::PermissionDenied(format!(
            "SCP-ECON-7010: no budget for {actor_did} — request ApproveSpend governance action"
        )));
    }
    budget_tracker.record_spend(actor_did, cost).map_err(|e| {
        ContextError::PermissionDenied(format!("SCP-ECON-7010: budget exceeded: {e}"))
    })?;

    Ok(Some(cost))
}

/// Bundle of per-DID economy state that Phase 1 of a paid action took
/// ownership of. Every ticket **must** be consumed by either
/// [`commit_economy_ticket`] (success path) or [`rollback_economy_ticket`]
/// (failure path). Dropping a ticket without consuming it leaks budget
/// deduction, a velocity entry, and a hard-rate-limit token — the
/// `#[must_use]` attribute makes this a compile-time warning, and the
/// `Drop` impl logs + debug-asserts so unit tests fail loudly.
///
/// F4: this type exists because the previous `send_message` Phase 2 error
/// path only rolled back the budget, silently leaking the velocity entry
/// and the hard-rate-limit token. Unifying the rollback under a single
/// must-use handle prevents that class of bug from recurring when new
/// error branches are added.
#[must_use = "EconomyTicket must be committed or rolled back — dropping leaks budget, velocity, and hard-rate-limit state"]
pub(super) struct EconomyTicket {
    /// The DID being charged — needed for every rollback operation.
    pub actor_did: DID,
    /// The budget amount deducted by [`enforce_economy`] (if any).
    pub deducted_cost: Option<scp_protocol::economy::types::Amount>,
    /// Identifier of the velocity entry appended in Phase 1; used to
    /// roll back the specific entry and not race concurrent senders.
    pub velocity_token: scp_protocol::economy::antispam::VelocityRollbackToken,
    /// When `true`, Phase 1 consumed a hard-rate-limit token that must
    /// be refunded on rollback. `false` only for code paths that did
    /// not consume a token (e.g., `ContextJoin`).
    pub needs_hard_rate_limit_refund: bool,
    /// Set to `true` by `commit`/`rollback` so the `Drop` guard knows
    /// the caller honored the contract. Visible to the `messaging` /
    /// `lifecycle` modules that construct the ticket; mutated only via
    /// the `commit`/`rollback` helpers below.
    pub(super) consumed: bool,
}

impl Drop for EconomyTicket {
    fn drop(&mut self) {
        if !self.consumed {
            // Log at error level so a leak is visible in production, and
            // debug-assert so the next CI run fails loudly.
            tracing::error!(
                actor_did = %self.actor_did,
                cost = ?self.deducted_cost,
                "EconomyTicket dropped without commit or rollback — budget and velocity state may be inconsistent"
            );
            debug_assert!(
                false,
                "EconomyTicket dropped without commit or rollback for actor {}",
                self.actor_did
            );
        }
    }
}

/// Marks the ticket as committed (success path). Returns the deducted
/// cost so callers can pass it to the payment capture step.
///
/// Call this exactly once per ticket. Dropping the returned
/// `Option<Amount>` is safe; the budget deduction has already been
/// recorded under the Phase 1 lock.
pub(super) fn commit_economy_ticket(
    mut ticket: EconomyTicket,
) -> Option<scp_protocol::economy::types::Amount> {
    ticket.consumed = true;
    ticket.deducted_cost
}

/// Rolls back every piece of state the ticket represents: the budget
/// deduction, the velocity entry (via its rollback token, so we do not
/// race concurrent senders), and the hard-rate-limit token (when the
/// Phase 1 path consumed one).
///
/// Re-acquires the `contexts` lock internally so this is safe to call
/// from Phase 2 (off-lock) error paths. If the context has been
/// deregistered between Phase 1 and rollback (unusual), the rollback
/// is a best-effort no-op — the ticket is still marked consumed so
/// the `Drop` guard does not fire.
pub(super) async fn rollback_economy_ticket(
    manager: &ContextManager,
    context_id: &str,
    mut ticket: EconomyTicket,
) {
    ticket.consumed = true;
    let mut contexts = manager.contexts.lock().await;
    if let Some(ctx) = contexts.get_mut(context_id) {
        ctx.governance
            .velocity_tracker
            .rollback(&ticket.actor_did, ticket.velocity_token);
        if ticket.needs_hard_rate_limit_refund {
            ctx.governance.hard_rate_limit.refund(&ticket.actor_did);
        }
        if let Some(cost) = ticket.deducted_cost {
            ctx.governance
                .budget_tracker
                .reverse_spend(&ticket.actor_did, cost);
        }
    }
}

#[allow(clippy::significant_drop_tightening)]
impl ContextManager {
    /// Authorizes a paid action (escrow pattern, step 1).
    ///
    /// Evaluates cost, checks spending UCAN, checks budget, and calls
    /// `adapter.authorize` to create an escrow hold. The caller performs the
    /// action, then calls `complete_paid_action` or `void_paid_action`.
    ///
    /// Returns `Ok(None)` when no payment adapter is configured or cost is zero.
    /// M3: accepts an optional `pre_evaluated_cost` to avoid re-evaluating
    /// the pricing formula when cost was already computed by `enforce_economy`.
    /// When `Some`, the adapter escrow uses the same cost the budget saw.
    /// When `None`, cost is evaluated fresh (backward-compatible path).
    pub(super) async fn authorize_paid_action(
        &self,
        action_type: PaidActionType,
        payer_did: &DID,
        context_id: &str,
        pre_evaluated_cost: Option<scp_protocol::economy::types::Amount>,
    ) -> Result<Option<PaidActionAuthorization>, ContextError> {
        // Early exit: no adapter means no payment flow.
        let Some(adapter_arc) = self.payment_adapter.as_ref().map(Arc::clone) else {
            return Ok(None);
        };

        // If caller already evaluated cost and it was zero/absent, skip.
        if let Some(cost) = pre_evaluated_cost
            && cost.0 == 0
        {
            return Ok(None);
        }

        // Phase 1: Extract policy + metrics under lock, then drop.
        let (policy, metrics) = {
            let contexts = self.contexts.lock().await;
            let ctx = contexts
                .get(context_id)
                .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;

            let policy = ctx.governance.economic_policy.clone();
            let member_count = u64::try_from(ctx.membership.count()).unwrap_or(u64::MAX);
            let velocity = ctx
                .governance
                .velocity_tracker
                .get_velocity(payer_did, self.clock.now_secs());

            let now_secs = self.clock.now_secs();
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

        // M3: skip re-evaluation if cost was already computed upstream.
        if pre_evaluated_cost.is_none() {
            // Evaluate cost — zero cost means no payment needed.
            if scp_protocol::economy::policy::evaluate_cost(&policy, &action_type, &metrics)
                .filter(|c| c.0 > 0)
                .is_none()
            {
                return Ok(None);
            }
        }

        // Phase 2: Authorize (escrow) via adapter (no lock held).
        let bridge = DynAdapterBridge(adapter_arc);
        let metadata = PaymentMetadata {
            action_type: action_type.clone(),
            context_id: Some(context_id.to_owned()),
            idempotency_key: rand_idempotency_key(),
        };

        let prepared = integration::prepare_paid_action(
            &bridge,
            Some(&policy),
            action_type,
            payer_did,
            Some(context_id.to_owned()),
            &metrics,
            metadata,
            Vec::new(),
        )
        .await
        .map_err(integration_error_to_context)?;

        Ok(Some(PaidActionAuthorization {
            prepared,
            bridge,
            policy,
            metrics,
        }))
    }

    /// Completes a paid action after successful execution (escrow capture).
    ///
    /// Calls `adapter.capture`, verifies the receipt, stores it in the event
    /// log, and records budget spend.
    pub(super) async fn complete_paid_action(
        &self,
        auth: PaidActionAuthorization,
        payer_did: &DID,
        context_id: &str,
    ) -> Result<Option<PaymentReceipt>, ContextError> {
        // Capture the escrowed authorization via process_paid_action.
        let processed = integration::process_paid_action(
            &auth.bridge,
            Some(&auth.policy),
            &auth.prepared.envelope,
            &auth.metrics,
            |payload| async move { Ok(payload) },
        )
        .await
        .map_err(integration_error_to_context)?;

        let Some(receipt) = processed.receipt else {
            return Ok(None);
        };

        // Verify the receipt.
        verify_and_check_receipt(&auth.bridge, &receipt).await?;

        // Store receipt in event log.
        let context_id_bytes = super::context_id_to_bytes(context_id);
        if let Err(e) = self.event_log.append_context_event(
            &context_id_bytes,
            "PaymentReceived",
            payer_did.as_ref(),
        ) {
            tracing::warn!(
                context_id,
                "failed to store payment receipt in event log: {e}"
            );
        }

        Ok(Some(receipt))
    }

    /// Voids a paid action authorization on failure (escrow rollback).
    ///
    /// Calls `adapter.void` to release the escrow hold. Best-effort —
    /// logs but does not propagate void failures.
    ///
    /// Used by `send_message` when `encrypt_and_send` fails after
    /// `authorize_paid_action` succeeded (escrow pattern: authorize →
    /// action → complete on success / void on failure).
    pub(super) async fn void_paid_action(&self, auth: PaidActionAuthorization, context_id: &str) {
        if let Some(ref authorization) = auth.prepared.envelope.authorization
            && let Err(e) = auth.bridge.void(authorization).await
        {
            tracing::warn!(context_id, "failed to void payment authorization: {e}");
        }
    }

    /// Verifies payment receipts using the configured payment adapter.
    ///
    /// Wraps [`verify_receipts_dyn`] using the payment adapter as verifier.
    /// Returns per-receipt results (no fail-fast).
    ///
    /// If no payment adapter is configured, returns
    /// [`ReceiptVerificationError::NoVerifierForAdapter`] for each receipt.
    pub async fn verify_payment_receipts(
        &self,
        receipts: &[PaymentReceipt],
    ) -> Vec<Result<ReceiptVerification, ReceiptVerificationError>> {
        match &self.payment_adapter {
            Some(adapter) => {
                let verifier = AdapterAsVerifier(adapter.as_ref());
                verify_receipts_dyn(&[&verifier as &dyn PaymentVerifierDyn], receipts).await
            }
            None => receipts
                .iter()
                .map(|r| {
                    Err(ReceiptVerificationError::NoVerifierForAdapter {
                        receipt_id: r.receipt_id,
                        adapter_id: r.adapter_id.clone(),
                    })
                })
                .collect(),
        }
    }
}

/// Generates a random 16-byte idempotency key for payment metadata.
fn rand_idempotency_key() -> [u8; 16] {
    *uuid::Uuid::new_v4().as_bytes()
}
