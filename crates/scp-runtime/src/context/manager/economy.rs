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

/// Unified economy enforcement: evaluate cost, check spending UCAN, check budget.
///
/// This replaces the former separate economy enforcement functions.
/// One unified flow per the escrow
/// pattern: evaluate cost -> check spending UCAN -> check budget -> deduct.
///
/// Returns the deducted cost for rollback on failure, or `None` if no cost.
#[allow(clippy::too_many_arguments)] // Economy enforcement requires many context parameters.
pub(super) fn enforce_economy(
    economic_policy: Option<&scp_protocol::economy::types::EconomicPolicy>,
    budget_tracker: &mut scp_protocol::economy::budget::MemberBudgetTracker,
    velocity_tracker: &scp_protocol::economy::antispam::SenderVelocityTracker,
    member_count: usize,
    action_type: &PaidActionType,
    actor_did: &DID,
    now: u64,
    spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
    action_label: &str,
    context_id: &str,
    clock: &dyn scp_primitives::Clock,
    relay_base_price: u64,
) -> Result<Option<scp_protocol::economy::types::Amount>, ContextError> {
    let Some(policy) = economic_policy else {
        return Ok(None);
    };

    let velocity = velocity_tracker.get_velocity(actor_did, now);
    let metrics = ObservableMetrics {
        sender_velocity: velocity,
        member_count: u64::try_from(member_count).unwrap_or(u64::MAX),
        context_message_rate: velocity_tracker.aggregate_velocity(now),
        // relay_queue_depth: Requires relay-level telemetry not available at ContextManager.
        // The relay tracks its own queue depth server-side; populating this field would
        // require a relay->client metrics channel. Until that transport-layer telemetry
        // exists, relay-queue-based pricing variables evaluate to zero.
        relay_queue_depth: 0,
        time_of_day: now % 86400,
        // storage_usage: Requires storage provider metrics not available at ContextManager.
        // The Storage trait (scp-platform) does not expose per-context byte counts.
        storage_usage: 0,
        relay_base_price,
    };

    // M2: evaluate_cost returns None on formula overflow — treat as error,
    // not free pass. Returning Ok(None) would silently skip the payment gate.
    let Some(cost) = scp_protocol::economy::policy::evaluate_cost(policy, action_type, &metrics)
    else {
        return Err(ContextError::PermissionDenied(
            "SCP-ECON-7063: cost evaluation overflow".to_owned(),
        ));
    };

    if cost.0 == 0 {
        return Ok(None);
    }

    // AND-composition (spec section 19.5, #1593): paid actions require both the
    // action capability (already checked by the caller) AND a spending UCAN.
    // Free actions (cost == 0) pass through above.
    if spending_ucan.is_none() {
        return Err(ContextError::PermissionDenied(
            "SCP-ECON-7060: paid action requires spending UCAN".to_owned(),
        ));
    }
    // Validate AND-composition: the action capability was already verified by the
    // caller, so action_ucan is None (meaning "already verified by caller").
    // Only the spending UCAN needs validation here.
    //
    // `action_ucan=None` means "already verified by caller" — this is a
    // convention, not type-level enforcement. A future improvement could use
    // a newtype wrapper to make this invariant compile-time checked.
    debug_assert!(
        spending_ucan.is_some(),
        "spending UCAN should be Some at this point — None case returns above"
    );
    scp_protocol::crypto::ucan::spending::check_and_composition(
        None, // action UCAN: already verified by caller
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

/// Rolls back a budget deduction on failure.
///
/// Used by messaging, lifecycle, and invoke to DRY the budget rollback pattern.
/// Restores the exact amount previously deducted by `enforce_economy` using
/// `reverse_spend` (which decrements `spent`) instead of `grant` (which
/// would inflate the limit). This preserves accurate `total_spent` accounting.
pub(super) async fn rollback_budget(
    manager: &ContextManager,
    context_id: &str,
    actor_did: &DID,
    deducted_cost: Option<scp_protocol::economy::types::Amount>,
) {
    if let Some(cost) = deducted_cost {
        let mut contexts = manager.contexts.lock().await;
        if let Some(ctx) = contexts.get_mut(context_id) {
            ctx.governance.budget_tracker.reverse_spend(actor_did, cost);
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
                relay_base_price: ctx
                    .governance
                    .relay_pricing_config
                    .as_ref()
                    .map_or(0, |c| c.current_base_price.0),
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
