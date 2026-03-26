//! Reusable payment flow on `ContextManager` (spec section 19.2.2, #1537).
//!
//! Provides [`ContextManager::execute_paid_action`] — the single entry point
//! for the 9-step payment integration. Every paid entry point (`send_message`,
//! `join_context`, `invoke_tool`) calls this method rather than inlining the
//! payment logic.
//!
//! When no payment adapter is configured (`self.payment_adapter` is `None`),
//! the method returns `Ok(None)` immediately — budget enforcement
//! (`evaluate_cost` + `record_spend`) is handled separately by the per-action
//! economy functions.
//!
//! See spec section 19.2.2 and ADR-033 in `.docs/adrs/phase-3.md`.

use std::sync::Arc;

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::economy::policy::ObservableMetrics;
use scp_protocol::economy::types::PaidActionType;

use crate::economy::adapter::{
    AdapterAsVerifier, PaymentAdapterDyn, PaymentMetadata, PaymentReceipt,
};
use crate::economy::integration::{self, IntegrationError};
use crate::economy::receipt::{
    PaymentVerifierDyn, ReceiptVerification, ReceiptVerificationError, verify_receipts_dyn,
};

use super::ContextManager;

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

#[allow(clippy::significant_drop_tightening)]
impl ContextManager {
    /// Executes the 9-step payment flow for a paid action (spec section 19.2.2).
    ///
    /// This is the **reusable layer** that every paid entry point calls:
    /// - `send_message` calls with `PaidActionType::MessageSend`
    /// - `join_context` calls with `PaidActionType::ContextJoin`
    /// - `invoke_tool` calls with `PaidActionType::ToolInvoke`
    ///
    /// When no payment adapter is configured, returns `Ok(None)` immediately.
    /// When the evaluated cost is zero, also returns `Ok(None)`.
    ///
    /// **Known gaps (#1593):** Steps 2 (spending UCAN verification) and 4
    /// (authorization attachment to envelope) are not yet implemented. These
    /// require UCAN parameters threaded through `send_message` and
    /// `join_context` from the FFI layer. Tool invoke has UCAN plumbing via
    /// `ToolEconomyContext` but send/join do not.
    ///
    /// # Lock pattern
    ///
    /// Policy and metrics are extracted under the contexts lock, then the lock
    /// is dropped before calling async adapter methods. This matches the
    /// `send_message` Phase 1 to Phase 2 pattern.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::PermissionDenied`] with SCP-ECON-70xx codes
    /// for any payment flow failure.
    pub async fn execute_paid_action(
        &self,
        action_type: PaidActionType,
        payer_did: &DID,
        context_id: &str,
    ) -> Result<Option<PaymentReceipt>, ContextError> {
        // Early exit: no adapter means no payment flow.
        let Some(adapter_arc) = self.payment_adapter.as_ref().map(Arc::clone) else {
            return Ok(None);
        };

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
                // context_message_rate: requires relay-level telemetry (#1597)
                context_message_rate: 0,
                // relay_queue_depth: requires relay-level telemetry (#1597)
                relay_queue_depth: 0,
                // time_of_day: seconds since midnight UTC from injected clock
                time_of_day: now_secs % 86400,
                // storage_usage: requires storage provider metrics (#1597)
                storage_usage: 0,
            };
            (policy, metrics)
        };

        // No economic policy -> no payment flow.
        let Some(policy) = policy else {
            return Ok(None);
        };

        // Evaluate cost — zero cost means no payment needed.
        let Some(_cost) =
            scp_protocol::economy::policy::evaluate_cost(&policy, &action_type, &metrics)
                .filter(|c| c.0 > 0)
        else {
            return Ok(None);
        };

        // Phase 2: Run payment flow (no lock held).
        let bridge = DynAdapterBridge(adapter_arc);
        let receipt = self
            .run_payment_flow(
                &bridge,
                &policy,
                action_type,
                payer_did,
                context_id,
                &metrics,
            )
            .await?;

        let Some(receipt) = receipt else {
            return Ok(None);
        };

        // Verify the receipt.
        verify_and_check_receipt(&bridge, &receipt).await?;

        // Store receipt in event log.
        let context_id_bytes = super::context_id_to_bytes(context_id);
        if let Err(e) = self
            .event_log
            .append_context_event(&context_id_bytes, "PaymentReceived")
        {
            tracing::warn!(
                context_id,
                "failed to store payment receipt in event log: {e}"
            );
        }

        // Budget tracking (record_spend) is the responsibility of the
        // per-action enforcement functions (enforce_send_economy,
        // enforce_join_economy, check_tool_economy). The payment adapter
        // handles real-money settlement independently. Recording spend
        // here would double-charge the member.

        Ok(Some(receipt))
    }

    /// Runs the prepare + process payment flow, returning the receipt.
    async fn run_payment_flow(
        &self,
        bridge: &DynAdapterBridge,
        policy: &scp_protocol::economy::types::EconomicPolicy,
        action_type: PaidActionType,
        payer_did: &DID,
        context_id: &str,
        metrics: &ObservableMetrics,
    ) -> Result<Option<PaymentReceipt>, ContextError> {
        let metadata = PaymentMetadata {
            action_type: action_type.clone(),
            context_id: Some(context_id.to_owned()),
            idempotency_key: rand_idempotency_key(),
        };

        // Steps 1-4: Sender-side preparation (cost eval + authorize).
        let prepared = integration::prepare_paid_action(
            bridge,
            Some(policy),
            action_type,
            payer_did,
            Some(context_id.to_owned()),
            metrics,
            metadata,
            Vec::new(), // payload is opaque to payment flow
        )
        .await
        .map_err(integration_error_to_context)?;

        // Steps 5-8: Receiver-side processing (verify auth + capture).
        let processed = integration::process_paid_action(
            bridge,
            Some(policy),
            &prepared.envelope,
            metrics,
            |payload| async move { Ok(payload) },
        )
        .await
        .map_err(integration_error_to_context)?;

        Ok(processed.receipt)
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
