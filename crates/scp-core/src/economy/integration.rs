//! Action-payment integration sequence for SCP economic governance.
//!
//! Implements the 9-step action-payment integration sequence described in spec
//! section 19.2.2 and referenced by ADR-033. The main entry point is
//! [`execute_paid_action`], which orchestrates cost evaluation, UCAN
//! verification, authorization, action processing, capture, and event logging.
//!
//! Two primary flow patterns are supported:
//!
//! - **Authorize-then-capture** (x402, Stripe): Funds reserved on authorize,
//!   moved on capture. Supports void.
//! - **Invoice-then-preimage** (Lightning): Preimage revelation IS capture.
//!   `capture()` is a no-op that returns the receipt derived from the preimage.
//!
//! Both patterns satisfy the [`PaymentAdapter`] trait and are handled uniformly
//! by this module.
//!
//! # Error handling
//!
//! On failure at steps 5-7 (verification, processing, capture), the module
//! calls `adapter.void(auth)` to release reserved funds before returning the
//! error. This ensures no funds are held after a failed action.
//!
//! See spec section 19.2.2, 19.4, 19.5, and ADR-033.

use super::adapter::{ContextId, PaymentAdapter, PaymentAuthorization, PaymentError, PaymentMetadata, PaymentReceipt};
use super::policy::{CostInsufficient, ObservableMetrics, evaluate_cost, verify_cost_sufficiency};
use super::types::{Amount, EconomicPolicy, PaidActionType};
use crate::identity::DID;

// ---------------------------------------------------------------------------
// IntegrationError
// ---------------------------------------------------------------------------

/// Errors that can occur during the action-payment integration sequence.
///
/// See spec section 19.2.2.
#[derive(Debug)]
pub enum IntegrationError {
    /// Step 1: Cost evaluation failed (arithmetic overflow in formula).
    CostEvaluationFailed,
    /// Step 2: Spending UCAN does not cover the computed cost.
    SpendingCapabilityInsufficient {
        /// The computed cost.
        required: Amount,
        /// The spending UCAN's `max_per_action` limit.
        allowed: Amount,
    },
    /// Step 5: Receiver's computed cost exceeds the authorized amount.
    CostInsufficient(CostInsufficient),
    /// Step 3/5/7: Payment adapter returned an error.
    PaymentFailed(PaymentError),
    /// Step 6: Action processing failed. The associated string describes
    /// the failure. Authorization has been voided.
    ActionFailed(String),
    /// Step 9: Void failed after a prior failure. Contains both the original
    /// error and the void error.
    VoidFailed {
        /// The original error that triggered the void attempt.
        original: Box<IntegrationError>,
        /// The error from the void attempt itself.
        void_error: PaymentError,
    },
}

impl std::fmt::Display for IntegrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CostEvaluationFailed => write!(f, "cost evaluation failed: arithmetic overflow"),
            Self::SpendingCapabilityInsufficient { required, allowed } => write!(
                f,
                "spending capability insufficient: required {required}, allowed {allowed}"
            ),
            Self::CostInsufficient(ci) => write!(f, "{ci}"),
            Self::PaymentFailed(pe) => write!(f, "payment failed: {pe}"),
            Self::ActionFailed(msg) => write!(f, "action failed: {msg}"),
            Self::VoidFailed { original, void_error } => write!(
                f,
                "void failed after error ({original}): {void_error}"
            ),
        }
    }
}

impl std::error::Error for IntegrationError {}

// ---------------------------------------------------------------------------
// SpendingAuthorization — UCAN spending check abstraction
// ---------------------------------------------------------------------------

/// Represents a verified spending UCAN's constraints for a single action.
///
/// The caller provides this after verifying that the payer holds a valid
/// spending UCAN (spec section 19.5). The integration module checks that the
/// UCAN's `max_per_action` covers the computed cost.
///
/// This struct decouples the integration module from UCAN token parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendingAuth {
    /// Maximum amount the spending UCAN allows for a single action.
    pub max_per_action: Amount,
    /// Allowed payment adapter IDs. Empty means any adapter is allowed.
    pub allowed_adapters: Vec<String>,
}

// ---------------------------------------------------------------------------
// ActionOutcome — result of action processing
// ---------------------------------------------------------------------------

/// The result of executing the paid action (step 6).
///
/// Generic over the action's return type. Contains the action result
/// plus the payment receipt for event log recording.
#[derive(Debug)]
pub struct ActionOutcome<T> {
    /// The action's return value.
    pub result: T,
    /// The payment receipt from capture (step 7).
    pub receipt: PaymentReceipt,
}

// ---------------------------------------------------------------------------
// execute_paid_action — the 9-step integration sequence
// ---------------------------------------------------------------------------

/// Executes the full 9-step action-payment integration sequence.
///
/// This is the main entry point for paid actions. It orchestrates:
///
/// 1. Cost evaluation (economic policy + pricing formula + observable metrics)
/// 2. Spending UCAN verification (`max_per_action` covers computed cost)
/// 3. Payment authorization via adapter
/// 4. Authorization is attached to the action envelope (caller responsibility)
/// 5. Receiver-side cost verification (re-evaluates formula, checks sufficiency)
/// 6. Action processing (caller-provided closure)
/// 7. Payment capture via adapter
/// 8. Receipt returned for event log recording (caller responsibility)
/// 9. On failure at steps 5-7: void releases reserved funds
///
/// # Free action bypass
///
/// If no economic policy is present, or the computed cost is zero, the action
/// is executed directly without any payment sequence. Returns `Ok(None)` to
/// indicate no payment was made, alongside the action result.
///
/// # Type parameters
///
/// - `T`: The return type of the action processing closure.
/// - `A`: The payment adapter implementation.
/// - `F`: The async action processing closure.
///
/// # Arguments
///
/// - `policy`: The context's economic policy. `None` means free context.
/// - `action_type`: The type of paid action being performed.
/// - `payer`: The DID of the entity paying for the action.
/// - `sender_metrics`: Observable metrics from the payer's perspective (step 1).
/// - `receiver_metrics`: Observable metrics from the receiver's perspective (step 5).
/// - `spending_auth`: Verified spending UCAN constraints. `None` if no spending
///   UCAN is available (will fail for paid actions).
/// - `adapter`: The payment adapter to use.
/// - `metadata`: Payment metadata for the authorization request.
/// - `process_action`: Async closure that processes the action (step 6).
///   Receives the [`PaymentAuthorization`] so it can be attached to the
///   action envelope.
///
/// See spec section 19.2.2.
pub async fn execute_paid_action<T, A, F, Fut>(
    policy: Option<&EconomicPolicy>,
    action_type: &PaidActionType,
    payer: &DID,
    sender_metrics: &ObservableMetrics,
    receiver_metrics: &ObservableMetrics,
    spending_auth: Option<&SpendingAuth>,
    adapter: &A,
    metadata: PaymentMetadata,
    process_action: F,
) -> Result<(T, Option<ActionOutcome<()>>), IntegrationError>
where
    A: PaymentAdapter,
    F: FnOnce(&PaymentAuthorization) -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    // -----------------------------------------------------------------------
    // Free action bypass: no policy or zero cost => skip payment entirely
    // -----------------------------------------------------------------------
    let policy = match policy {
        Some(p) => p,
        None => {
            // No economic policy — free context. Execute action directly.
            // We create a dummy auth for the closure signature. In practice,
            // callers should use `execute_free_action` for free contexts, but
            // this path handles the case gracefully.
            let dummy_auth = PaymentAuthorization {
                auth_id: [0u8; 32],
                payer: payer.clone(),
                payee: payer.clone(),
                amount: Amount(0),
                currency: super::types::CurrencyCode::from(""),
                adapter_id: String::new(),
                created_at: 0,
                expires_at: 0,
                adapter_state: Vec::new(),
            };
            let result = process_action(&dummy_auth)
                .await
                .map_err(IntegrationError::ActionFailed)?;
            return Ok((result, None));
        }
    };

    // Step 1: Evaluate cost using economic policy + pricing formula + metrics
    let cost = evaluate_cost(policy, action_type, sender_metrics)
        .ok_or(IntegrationError::CostEvaluationFailed)?;

    // Free action bypass: zero cost
    if cost == Amount(0) {
        let dummy_auth = PaymentAuthorization {
            auth_id: [0u8; 32],
            payer: payer.clone(),
            payee: policy.payee.clone(),
            amount: Amount(0),
            currency: policy.cost_schedule.currency,
            adapter_id: String::new(),
            created_at: 0,
            expires_at: 0,
            adapter_state: Vec::new(),
        };
        let result = process_action(&dummy_auth)
            .await
            .map_err(IntegrationError::ActionFailed)?;
        return Ok((result, None));
    }

    // Step 2: Verify spending UCAN covers computed cost
    let spending = spending_auth.ok_or(IntegrationError::SpendingCapabilityInsufficient {
        required: cost,
        allowed: Amount(0),
    })?;

    if cost > spending.max_per_action {
        return Err(IntegrationError::SpendingCapabilityInsufficient {
            required: cost,
            allowed: spending.max_per_action,
        });
    }

    // Check adapter compatibility if spending UCAN restricts adapters.
    if !spending.allowed_adapters.is_empty()
        && !spending.allowed_adapters.iter().any(|a| a == adapter.adapter_id())
    {
        return Err(IntegrationError::PaymentFailed(
            PaymentError::NoCompatiblePaymentAdapter,
        ));
    }

    // Step 3: Authorize payment via adapter
    let auth = adapter
        .authorize(
            payer,
            &policy.payee,
            cost,
            policy.cost_schedule.currency,
            metadata,
        )
        .await
        .map_err(IntegrationError::PaymentFailed)?;

    // Step 4: PaymentAuthorization is passed to the action closure, which
    // attaches it to the action envelope (inside encrypted payload).

    // Step 5: Receiver-side cost verification
    if let Err(ci) = verify_cost_sufficiency(policy, action_type, receiver_metrics, auth.amount) {
        // Void the authorization before returning error (step 9).
        void_on_failure(adapter, &auth, IntegrationError::CostInsufficient(ci)).await
    } else {
        // Step 6: Process the action
        let action_result = match process_action(&auth).await {
            Ok(result) => result,
            Err(msg) => {
                // Void on action failure (step 9).
                return void_on_failure(adapter, &auth, IntegrationError::ActionFailed(msg)).await;
            }
        };

        // Step 7: Capture payment
        match adapter.capture(&auth).await {
            Ok(receipt) => {
                // Step 8: Receipt returned for event log recording.
                Ok((action_result, Some(ActionOutcome { result: (), receipt })))
            }
            Err(capture_err) => {
                // Void on capture failure (step 9).
                void_on_failure(
                    adapter,
                    &auth,
                    IntegrationError::PaymentFailed(capture_err),
                )
                .await
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Receiver-side verification (standalone, for use by receiving contexts)
// ---------------------------------------------------------------------------

/// Verifies an incoming payment authorization from the receiver's perspective.
///
/// Re-evaluates the cost using the receiver's observable metrics and checks
/// that the authorized amount covers the computed cost. This corresponds to
/// step 5 of the integration sequence.
///
/// # Errors
///
/// Returns [`CostInsufficient`] if the authorized amount is less than the
/// receiver's computed cost.
pub fn verify_incoming_authorization(
    policy: &EconomicPolicy,
    action_type: &PaidActionType,
    receiver_metrics: &ObservableMetrics,
    auth: &PaymentAuthorization,
) -> Result<(), CostInsufficient> {
    verify_cost_sufficiency(policy, action_type, receiver_metrics, auth.amount)
}

// ---------------------------------------------------------------------------
// void_on_failure — step 9 helper
// ---------------------------------------------------------------------------

/// Attempts to void a payment authorization after a failure at steps 5-7.
///
/// If the void succeeds, returns the original error. If the void itself fails,
/// wraps both errors in [`IntegrationError::VoidFailed`].
async fn void_on_failure<T, A: PaymentAdapter>(
    adapter: &A,
    auth: &PaymentAuthorization,
    original_error: IntegrationError,
) -> Result<T, IntegrationError> {
    match adapter.void(auth).await {
        Ok(()) => Err(original_error),
        Err(void_err) => Err(IntegrationError::VoidFailed {
            original: Box::new(original_error),
            void_error: void_err,
        }),
    }
}

// ---------------------------------------------------------------------------
// execute_free_action — bypass helper
// ---------------------------------------------------------------------------

/// Executes an action that requires no payment.
///
/// This is a convenience wrapper for actions in free contexts or actions with
/// zero cost. Skips the entire payment sequence.
///
/// # Arguments
///
/// - `process_action`: Async closure that processes the action.
///
/// # Returns
///
/// The action result. No payment receipt is generated.
pub async fn execute_free_action<T, F, Fut>(process_action: F) -> Result<T, IntegrationError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    process_action()
        .await
        .map_err(IntegrationError::ActionFailed)
}

// ---------------------------------------------------------------------------
// is_free_action — predicate for routing
// ---------------------------------------------------------------------------

/// Returns `true` if the given action in the given context is free (no payment
/// required).
///
/// An action is free when:
/// - No economic policy is present (`None`).
/// - The computed cost is zero.
///
/// Used by [`ContextManager`](crate::context::manager::ContextManager) to
/// decide whether to route through the payment sequence or bypass it.
///
/// See spec section 19.3: "No economic policy = free."
#[must_use]
pub fn is_free_action(
    policy: Option<&EconomicPolicy>,
    action_type: &PaidActionType,
    metrics: &ObservableMetrics,
) -> bool {
    match policy {
        None => true,
        Some(p) => {
            let cost = evaluate_cost(p, action_type, metrics);
            matches!(cost, Some(Amount(0)))
        }
    }
}

// ---------------------------------------------------------------------------
// PaymentEventData — for recording in event log
// ---------------------------------------------------------------------------

/// Data needed to record a `PaymentReceived` event in the context event log.
///
/// Extracted from [`ActionOutcome`] for convenience. The caller serializes
/// this and appends it as a `PaymentReceived` event.
#[derive(Debug, Clone)]
pub struct PaymentEventData {
    /// The payment receipt to record.
    pub receipt: PaymentReceipt,
    /// The context in which the payment occurred.
    pub context_id: Option<ContextId>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::economy::adapter::{
        AdapterCapabilities, PaymentMetadata, VerificationResult, RefundConfirmation,
    };
    use crate::economy::types::{
        Coefficient, CostSchedule, CurrencyCode, PricingFormula, PricingMetric, PricingVariable,
    };

    // -----------------------------------------------------------------------
    // TestAdapter — in-memory payment adapter for testing
    // -----------------------------------------------------------------------

    /// Test payment adapter with configurable behavior.
    struct TestAdapter {
        /// If `Some`, `authorize` returns this error.
        authorize_error: Option<PaymentError>,
        /// If `Some`, `capture` returns this error.
        capture_error: Option<PaymentError>,
        /// If `Some`, `void` returns this error.
        void_error: Option<PaymentError>,
        /// If `Some`, `verify` returns this result.
        verify_valid: bool,
    }

    impl TestAdapter {
        fn new() -> Self {
            Self {
                authorize_error: None,
                capture_error: None,
                void_error: None,
                verify_valid: true,
            }
        }

        fn with_capture_error(mut self, err: PaymentError) -> Self {
            self.capture_error = Some(err);
            self
        }

        fn with_void_error(mut self, err: PaymentError) -> Self {
            self.void_error = Some(err);
            self
        }
    }

    impl PaymentAdapter for TestAdapter {
        fn adapter_id(&self) -> &str {
            "test"
        }

        fn capabilities(&self) -> AdapterCapabilities {
            AdapterCapabilities {
                supported_currencies: vec![CurrencyCode::from("USD")],
                supports_streaming: false,
                supports_batch_auth: false,
                supports_single_step: false,
                min_amount: None,
                max_amount: None,
                typical_settlement_ms: 0,
                requires_facilitator: false,
            }
        }

        async fn authorize(
            &self,
            payer: &DID,
            payee: &DID,
            amount: Amount,
            currency: CurrencyCode,
            _metadata: PaymentMetadata,
        ) -> Result<PaymentAuthorization, PaymentError> {
            if let Some(ref err) = self.authorize_error {
                return Err(err.clone());
            }
            Ok(PaymentAuthorization {
                auth_id: [0xAA; 32],
                payer: payer.clone(),
                payee: payee.clone(),
                amount,
                currency,
                adapter_id: "test".to_string(),
                created_at: 1_000_000,
                expires_at: 1_001_000,
                adapter_state: vec![],
            })
        }

        async fn capture(
            &self,
            auth: &PaymentAuthorization,
        ) -> Result<PaymentReceipt, PaymentError> {
            if let Some(ref err) = self.capture_error {
                return Err(err.clone());
            }
            Ok(PaymentReceipt {
                receipt_id: [0xBB; 32],
                payer: auth.payer.clone(),
                payee: auth.payee.clone(),
                amount: auth.amount,
                currency: auth.currency,
                action_type: PaidActionType::MessageSend,
                context_id: Some("ctx-test".to_string()),
                adapter_id: "test".to_string(),
                adapter_proof: vec![0x01],
                timestamp: 1_000_001,
                signature: vec![0xFF; 64],
            })
        }

        async fn void(
            &self,
            _auth: &PaymentAuthorization,
        ) -> Result<(), PaymentError> {
            if let Some(ref err) = self.void_error {
                return Err(err.clone());
            }
            Ok(())
        }

        async fn verify(
            &self,
            _receipt: &PaymentReceipt,
        ) -> Result<VerificationResult, PaymentError> {
            Ok(VerificationResult {
                valid: self.verify_valid,
                adapter_id: "test".to_string(),
                verified_amount: Amount(0),
                verified_currency: CurrencyCode::from("USD"),
                verification_timestamp: 1_000_002,
            })
        }

        async fn refund(
            &self,
            receipt: &PaymentReceipt,
            amount: Option<Amount>,
        ) -> Result<RefundConfirmation, PaymentError> {
            Ok(RefundConfirmation {
                refund_id: [0xCC; 32],
                original_receipt_id: receipt.receipt_id,
                refunded_amount: amount.unwrap_or(receipt.amount),
                currency: receipt.currency,
                adapter_proof: vec![0x02],
            })
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn usd() -> CurrencyCode {
        CurrencyCode::from("USD")
    }

    fn payer_did() -> DID {
        DID::from("did:dht:z6MkPayer")
    }

    fn payee_did() -> DID {
        DID::from("did:dht:z6MkPayee")
    }

    fn paid_policy(per_message: u64) -> EconomicPolicy {
        EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: usd(),
                per_message: Some(Amount(per_message)),
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec!["test".to_string()],
            pricing_formula: None,
            payee: payee_did(),
        }
    }

    fn free_schedule_policy() -> EconomicPolicy {
        EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: usd(),
                per_message: None,
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec![],
            pricing_formula: None,
            payee: payee_did(),
        }
    }

    fn test_metadata() -> PaymentMetadata {
        PaymentMetadata {
            action_type: PaidActionType::MessageSend,
            context_id: Some("ctx-test".to_string()),
            idempotency_key: [0u8; 16],
        }
    }

    fn spending_auth(max: u64) -> SpendingAuth {
        SpendingAuth {
            max_per_action: Amount(max),
            allowed_adapters: vec![],
        }
    }

    fn default_metrics() -> ObservableMetrics {
        ObservableMetrics::default()
    }

    // =======================================================================
    // Full 9-step happy path
    // =======================================================================

    #[tokio::test]
    async fn full_sequence_happy_path() {
        let policy = paid_policy(10);
        let adapter = TestAdapter::new();
        let spending = spending_auth(100);
        let metrics = default_metrics();

        let (result, outcome) = execute_paid_action(
            Some(&policy),
            &PaidActionType::MessageSend,
            &payer_did(),
            &metrics,
            &metrics,
            Some(&spending),
            &adapter,
            test_metadata(),
            |_auth| async { Ok("message sent") },
        )
        .await
        .unwrap();

        assert_eq!(result, "message sent");
        let outcome = outcome.expect("should have payment outcome for paid action");
        assert_eq!(outcome.receipt.amount, Amount(10));
        assert_eq!(outcome.receipt.payer, payer_did());
        assert_eq!(outcome.receipt.payee, payee_did());
    }

    // =======================================================================
    // Free action bypass: no economic policy
    // =======================================================================

    #[tokio::test]
    async fn free_action_bypass_no_policy() {
        let adapter = TestAdapter::new();
        let metrics = default_metrics();

        let (result, outcome) = execute_paid_action::<&str, _, _, _>(
            None,
            &PaidActionType::MessageSend,
            &payer_did(),
            &metrics,
            &metrics,
            None,
            &adapter,
            test_metadata(),
            |_auth| async { Ok("free message") },
        )
        .await
        .unwrap();

        assert_eq!(result, "free message");
        assert!(outcome.is_none(), "no payment outcome for free action");
    }

    // =======================================================================
    // Free action bypass: zero cost
    // =======================================================================

    #[tokio::test]
    async fn free_action_bypass_zero_cost() {
        // Policy exists but no cost for the action type.
        let policy = free_schedule_policy();
        let adapter = TestAdapter::new();
        let metrics = default_metrics();

        let (result, outcome) = execute_paid_action::<&str, _, _, _>(
            Some(&policy),
            &PaidActionType::MessageSend,
            &payer_did(),
            &metrics,
            &metrics,
            None,
            &adapter,
            test_metadata(),
            |_auth| async { Ok("zero-cost message") },
        )
        .await
        .unwrap();

        assert_eq!(result, "zero-cost message");
        assert!(outcome.is_none(), "no payment outcome for zero-cost action");
    }

    // =======================================================================
    // CostInsufficient: payer amount < receiver computed cost
    // =======================================================================

    #[tokio::test]
    async fn cost_insufficient_returns_metric_snapshot() {
        // Receiver has higher metrics than sender, causing cost divergence.
        let policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: usd(),
                per_message: Some(Amount(5)),
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec!["test".to_string()],
            pricing_formula: Some(PricingFormula {
                base_cost: Amount(0),
                variables: vec![PricingVariable::Linear {
                    metric: PricingMetric::MemberCount,
                    coefficient: Coefficient(1_000_000), // 1.0
                }],
                cap: None,
                floor: None,
            }),
            payee: payee_did(),
        };

        let adapter = TestAdapter::new();
        let spending = spending_auth(1000);

        // Sender sees 10 members: cost = 5 + (1.0 * 10) = 15
        let sender_metrics = ObservableMetrics {
            member_count: 10,
            ..default_metrics()
        };

        // Receiver sees 100 members: cost = 5 + (1.0 * 100) = 105
        // Authorization amount (15) < receiver cost (105) => CostInsufficient
        let receiver_metrics = ObservableMetrics {
            member_count: 100,
            ..default_metrics()
        };

        let err = execute_paid_action::<&str, _, _, _>(
            Some(&policy),
            &PaidActionType::MessageSend,
            &payer_did(),
            &sender_metrics,
            &receiver_metrics,
            Some(&spending),
            &adapter,
            test_metadata(),
            |_auth| async { Ok("should not reach here") },
        )
        .await
        .unwrap_err();

        match err {
            IntegrationError::CostInsufficient(ci) => {
                assert_eq!(ci.provided, Amount(15));
                assert_eq!(ci.expected, Amount(105));
                assert_eq!(ci.currency, usd());
                // Metric snapshot should contain the MemberCount metric.
                assert!(
                    ci.metric_snapshot
                        .iter()
                        .any(|(m, v)| *m == PricingMetric::MemberCount && *v == 100),
                    "metric snapshot should contain MemberCount=100"
                );
            }
            other => panic!("expected CostInsufficient, got: {other}"),
        }
    }

    // =======================================================================
    // Void on verification failure (step 5)
    // =======================================================================

    #[tokio::test]
    async fn void_on_verification_failure() {
        // Same policy but receiver sees higher cost => CostInsufficient at step 5.
        // Verify that void is called (adapter does not error => original error returned).
        let adapter = TestAdapter::new();
        let spending = spending_auth(100);

        let sender_metrics = default_metrics();
        // Receiver's policy evaluates to higher cost: we use a different policy
        // perspective. Actually, since both sides use the same policy object in
        // our test setup, we need formula divergence. Let's use a formula policy.
        let formula_policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: usd(),
                per_message: Some(Amount(5)),
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec!["test".to_string()],
            pricing_formula: Some(PricingFormula {
                base_cost: Amount(0),
                variables: vec![PricingVariable::Step {
                    metric: PricingMetric::SenderVelocity,
                    thresholds: vec![(5, Amount(50))],
                }],
                cap: None,
                floor: None,
            }),
            payee: payee_did(),
        };

        // Sender: velocity=0 => cost = 5 + 0 = 5
        // Receiver: velocity=10 => cost = 5 + 50 = 55
        // Auth amount = 5 < 55 => CostInsufficient, void called
        let receiver_metrics = ObservableMetrics {
            sender_velocity: 10,
            ..default_metrics()
        };

        let err = execute_paid_action::<&str, _, _, _>(
            Some(&formula_policy),
            &PaidActionType::MessageSend,
            &payer_did(),
            &sender_metrics,
            &receiver_metrics,
            Some(&spending),
            &adapter,
            test_metadata(),
            |_auth| async { Ok("should not reach") },
        )
        .await
        .unwrap_err();

        // Should be CostInsufficient (void succeeded, so original error returned)
        assert!(matches!(err, IntegrationError::CostInsufficient(_)));
    }

    // =======================================================================
    // Void on action processing failure (step 6)
    // =======================================================================

    #[tokio::test]
    async fn void_on_action_failure() {
        let policy = paid_policy(10);
        let adapter = TestAdapter::new();
        let spending = spending_auth(100);
        let metrics = default_metrics();

        let err = execute_paid_action::<&str, _, _, _>(
            Some(&policy),
            &PaidActionType::MessageSend,
            &payer_did(),
            &metrics,
            &metrics,
            Some(&spending),
            &adapter,
            test_metadata(),
            |_auth| async { Err("action processing failed".to_string()) },
        )
        .await
        .unwrap_err();

        match err {
            IntegrationError::ActionFailed(msg) => {
                assert_eq!(msg, "action processing failed");
            }
            other => panic!("expected ActionFailed, got: {other}"),
        }
    }

    // =======================================================================
    // Void on capture failure (step 7)
    // =======================================================================

    #[tokio::test]
    async fn void_on_capture_failure() {
        let policy = paid_policy(10);
        let adapter = TestAdapter::new().with_capture_error(
            PaymentError::AdapterError("capture failed".to_string()),
        );
        let spending = spending_auth(100);
        let metrics = default_metrics();

        let err = execute_paid_action::<&str, _, _, _>(
            Some(&policy),
            &PaidActionType::MessageSend,
            &payer_did(),
            &metrics,
            &metrics,
            Some(&spending),
            &adapter,
            test_metadata(),
            |_auth| async { Ok("action succeeded") },
        )
        .await
        .unwrap_err();

        // Should be PaymentFailed (void succeeded, so original error returned)
        assert!(matches!(err, IntegrationError::PaymentFailed(_)));
    }

    // =======================================================================
    // VoidFailed: both action and void fail
    // =======================================================================

    #[tokio::test]
    async fn void_failed_wraps_both_errors() {
        let policy = paid_policy(10);
        let adapter = TestAdapter::new()
            .with_capture_error(PaymentError::AdapterError("capture failed".to_string()))
            .with_void_error(PaymentError::AdapterError("void also failed".to_string()));
        let spending = spending_auth(100);
        let metrics = default_metrics();

        let err = execute_paid_action::<&str, _, _, _>(
            Some(&policy),
            &PaidActionType::MessageSend,
            &payer_did(),
            &metrics,
            &metrics,
            Some(&spending),
            &adapter,
            test_metadata(),
            |_auth| async { Ok("action succeeded") },
        )
        .await
        .unwrap_err();

        match err {
            IntegrationError::VoidFailed {
                original,
                void_error,
            } => {
                assert!(matches!(*original, IntegrationError::PaymentFailed(_)));
                assert!(matches!(void_error, PaymentError::AdapterError(_)));
            }
            other => panic!("expected VoidFailed, got: {other}"),
        }
    }

    // =======================================================================
    // Spending capability insufficient
    // =======================================================================

    #[tokio::test]
    async fn spending_capability_insufficient() {
        let policy = paid_policy(100);
        let adapter = TestAdapter::new();
        // max_per_action (50) < cost (100)
        let spending = spending_auth(50);
        let metrics = default_metrics();

        let err = execute_paid_action::<&str, _, _, _>(
            Some(&policy),
            &PaidActionType::MessageSend,
            &payer_did(),
            &metrics,
            &metrics,
            Some(&spending),
            &adapter,
            test_metadata(),
            |_auth| async { Ok("should not reach") },
        )
        .await
        .unwrap_err();

        match err {
            IntegrationError::SpendingCapabilityInsufficient { required, allowed } => {
                assert_eq!(required, Amount(100));
                assert_eq!(allowed, Amount(50));
            }
            other => panic!("expected SpendingCapabilityInsufficient, got: {other}"),
        }
    }

    // =======================================================================
    // No spending UCAN for paid action
    // =======================================================================

    #[tokio::test]
    async fn no_spending_ucan_for_paid_action() {
        let policy = paid_policy(10);
        let adapter = TestAdapter::new();
        let metrics = default_metrics();

        let err = execute_paid_action::<&str, _, _, _>(
            Some(&policy),
            &PaidActionType::MessageSend,
            &payer_did(),
            &metrics,
            &metrics,
            None, // no spending UCAN
            &adapter,
            test_metadata(),
            |_auth| async { Ok("should not reach") },
        )
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            IntegrationError::SpendingCapabilityInsufficient { .. }
        ));
    }

    // =======================================================================
    // execute_free_action
    // =======================================================================

    #[tokio::test]
    async fn execute_free_action_succeeds() {
        let result = execute_free_action(|| async { Ok::<_, String>("free result") })
            .await
            .unwrap();
        assert_eq!(result, "free result");
    }

    #[tokio::test]
    async fn execute_free_action_propagates_error() {
        let err = execute_free_action(|| async { Err::<(), _>("free failed".to_string()) })
            .await
            .unwrap_err();
        assert!(matches!(err, IntegrationError::ActionFailed(msg) if msg == "free failed"));
    }

    // =======================================================================
    // is_free_action
    // =======================================================================

    #[test]
    fn is_free_action_no_policy() {
        assert!(is_free_action(
            None,
            &PaidActionType::MessageSend,
            &default_metrics()
        ));
    }

    #[test]
    fn is_free_action_zero_cost() {
        let policy = free_schedule_policy();
        assert!(is_free_action(
            Some(&policy),
            &PaidActionType::MessageSend,
            &default_metrics()
        ));
    }

    #[test]
    fn is_free_action_nonzero_cost() {
        let policy = paid_policy(10);
        assert!(!is_free_action(
            Some(&policy),
            &PaidActionType::MessageSend,
            &default_metrics()
        ));
    }

    // =======================================================================
    // verify_incoming_authorization
    // =======================================================================

    #[test]
    fn verify_incoming_authorization_sufficient() {
        let policy = paid_policy(10);
        let metrics = default_metrics();
        let auth = PaymentAuthorization {
            auth_id: [0u8; 32],
            payer: payer_did(),
            payee: payee_did(),
            amount: Amount(10),
            currency: usd(),
            adapter_id: "test".to_string(),
            created_at: 0,
            expires_at: 0,
            adapter_state: vec![],
        };
        assert!(verify_incoming_authorization(&policy, &PaidActionType::MessageSend, &metrics, &auth).is_ok());
    }

    #[test]
    fn verify_incoming_authorization_insufficient() {
        let policy = paid_policy(10);
        let metrics = default_metrics();
        let auth = PaymentAuthorization {
            auth_id: [0u8; 32],
            payer: payer_did(),
            payee: payee_did(),
            amount: Amount(5), // less than required 10
            currency: usd(),
            adapter_id: "test".to_string(),
            created_at: 0,
            expires_at: 0,
            adapter_state: vec![],
        };
        let err = verify_incoming_authorization(&policy, &PaidActionType::MessageSend, &metrics, &auth)
            .unwrap_err();
        assert_eq!(err.expected, Amount(10));
        assert_eq!(err.provided, Amount(5));
    }

    // =======================================================================
    // Adapter compatibility check
    // =======================================================================

    #[tokio::test]
    async fn spending_ucan_restricts_adapter() {
        let policy = paid_policy(10);
        let adapter = TestAdapter::new();
        let spending = SpendingAuth {
            max_per_action: Amount(100),
            allowed_adapters: vec!["lightning".to_string()], // does not include "test"
        };
        let metrics = default_metrics();

        let err = execute_paid_action::<&str, _, _, _>(
            Some(&policy),
            &PaidActionType::MessageSend,
            &payer_did(),
            &metrics,
            &metrics,
            Some(&spending),
            &adapter,
            test_metadata(),
            |_auth| async { Ok("should not reach") },
        )
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            IntegrationError::PaymentFailed(PaymentError::NoCompatiblePaymentAdapter)
        ));
    }

    // =======================================================================
    // Authorize-then-capture pattern (already tested in happy path)
    // Invoice-then-preimage pattern (capture is no-op, adapter returns receipt)
    // Both patterns are uniform through the PaymentAdapter trait.
    // =======================================================================

    #[tokio::test]
    async fn invoice_then_preimage_pattern() {
        // In Lightning, capture() returns a receipt derived from the preimage.
        // Our TestAdapter simulates this: capture succeeds and returns a receipt.
        // The integration sequence treats it identically to authorize-then-capture.
        let policy = paid_policy(10);
        let adapter = TestAdapter::new();
        let spending = spending_auth(100);
        let metrics = default_metrics();

        let (result, outcome) = execute_paid_action(
            Some(&policy),
            &PaidActionType::MessageSend,
            &payer_did(),
            &metrics,
            &metrics,
            Some(&spending),
            &adapter,
            test_metadata(),
            |_auth| async { Ok("lightning payment") },
        )
        .await
        .unwrap();

        assert_eq!(result, "lightning payment");
        assert!(outcome.is_some());
    }
}
