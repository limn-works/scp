//! Action-payment integration sequence for SCP economic governance.
//!
//! Implements the 9-step action-payment integration defined in spec section
//! 19.2.2. The sequence orchestrates cost evaluation, spending UCAN
//! verification, payment authorization, receiving-side verification, action
//! processing, capture, receipt recording, and void-on-failure.
//!
//! Key design decisions:
//! - Free actions return `None` for the authorization -- no dummy
//!   `PaymentAuthorization` structs are created.
//! - The receiving side verifies the authorization via
//!   `adapter.verify_authorization()` (step 5) BEFORE processing the action,
//!   preventing forged authorization structs.
//! - Errors are typed via [`IntegrationError`], not type-erased to strings.
//!
//! See spec section 19.2.2 and ADR-033 in `.docs/adrs/phase-3.md`.

use serde::{Deserialize, Serialize};

use super::adapter::{
    ContextId, PaymentAdapterDyn, PaymentAuthorization, PaymentError, PaymentMetadata,
    PaymentReceipt,
};
use scp_did::DID;
use scp_protocol::economy::policy::{ObservableMetrics, evaluate_cost, verify_cost_sufficiency};
use scp_protocol::economy::types::{Amount, EconomicPolicy, PaidActionType};

// ---------------------------------------------------------------------------
// IntegrationError
// ---------------------------------------------------------------------------

/// Errors produced by the action-payment integration sequence.
///
/// Each variant maps to a specific failure mode in the 9-step sequence.
/// Preserves typed error information rather than erasing to strings.
///
/// See spec section 19.2.2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrationError {
    /// Step 1: Cost evaluation failed (arithmetic overflow in formula).
    CostEvaluationOverflow,
    /// Step 3: Payment adapter returned an error during authorization.
    AuthorizationFailed(PaymentError),
    /// Step 5: Receiving side cost verification failed -- payer's authorized
    /// amount is less than receiver's computed cost.
    CostInsufficient {
        /// Receiver's computed cost.
        expected: Amount,
        /// Payer's authorized amount.
        provided: Amount,
        /// Receiver's observed metric values at evaluation time.
        metric_snapshot: Vec<(scp_protocol::economy::types::PricingMetric, u64)>,
    },
    /// Step 5: Receiving side authorization verification failed -- the
    /// authorization could not be verified by the adapter (forged, expired,
    /// or tampered).
    AuthorizationVerificationFailed(PaymentError),
    /// Step 6: Action processing failed. The authorization will be voided.
    ActionProcessingFailed(String),
    /// Step 7: Capture failed after successful action processing.
    CaptureFailed(PaymentError),
    /// Step 9: Void failed during cleanup after a prior failure.
    VoidFailed {
        /// The original error that triggered the void attempt.
        original: Box<Self>,
        /// The error from the void attempt itself.
        void_error: PaymentError,
    },
    /// No economic policy configured but payment was expected.
    NoEconomicPolicy,
}

impl std::fmt::Display for IntegrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CostEvaluationOverflow => {
                write!(f, "cost evaluation overflow during formula computation")
            }
            Self::AuthorizationFailed(e) => write!(f, "authorization failed: {e}"),
            Self::CostInsufficient {
                expected, provided, ..
            } => write!(
                f,
                "cost insufficient: expected {expected}, provided {provided}"
            ),
            Self::AuthorizationVerificationFailed(e) => {
                write!(f, "authorization verification failed: {e}")
            }
            Self::ActionProcessingFailed(msg) => {
                write!(f, "action processing failed: {msg}")
            }
            Self::CaptureFailed(e) => write!(f, "capture failed: {e}"),
            Self::VoidFailed {
                original,
                void_error,
            } => write!(
                f,
                "void failed during cleanup (original: {original}, void: {void_error})"
            ),
            Self::NoEconomicPolicy => write!(f, "no economic policy configured"),
        }
    }
}

impl std::error::Error for IntegrationError {}

// ---------------------------------------------------------------------------
// ActionEnvelope
// ---------------------------------------------------------------------------

/// An action envelope carrying an optional payment authorization.
///
/// The authorization is `None` for free actions (no economic policy, or zero
/// cost for this action type). When `Some`, the authorization is attached
/// inside the encrypted payload -- not visible to relays (spec section
/// 19.2.2, step 4).
#[derive(Clone, Debug)]
pub struct ActionEnvelope {
    /// The DID of the actor performing the action.
    pub actor: DID,
    /// The type of action being performed.
    pub action_type: PaidActionType,
    /// The context in which the action is being performed.
    pub context_id: Option<ContextId>,
    /// Payment authorization, if this action requires payment.
    /// `None` for free actions.
    pub authorization: Option<PaymentAuthorization>,
    /// Opaque action payload (message content, tool invocation, etc.).
    pub payload: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Sender-side: prepare_paid_action (steps 1-4)
// ---------------------------------------------------------------------------

/// Result of sender-side preparation for a paid action.
///
/// Contains the action envelope with the optional authorization attached.
#[derive(Clone, Debug)]
pub struct PreparedAction {
    /// The action envelope ready for sending.
    pub envelope: ActionEnvelope,
    /// The cost that was evaluated (0 for free actions).
    pub evaluated_cost: Amount,
}

/// Prepares a paid action on the sender side (steps 1-4).
///
/// 1. Evaluates cost from economic policy + pricing formula + observable metrics.
/// 2. (Spending UCAN verification is the caller's responsibility -- the
///    integration module does not access the UCAN store.)
/// 3. If cost > 0, calls `adapter.authorize()` to reserve payment.
/// 4. Returns an [`ActionEnvelope`] with the authorization attached (or `None`
///    for free actions).
///
/// Free actions (no economic policy, or zero cost for this action type) bypass
/// the payment sequence entirely -- no adapter calls, no authorization.
///
/// # Errors
///
/// Returns [`IntegrationError::CostEvaluationOverflow`] if formula evaluation
/// overflows. Returns [`IntegrationError::AuthorizationFailed`] if the adapter
/// rejects the authorization request.
#[allow(clippy::too_many_arguments)] // Spec-defined 9-step flow requires all parameters.
pub async fn prepare_paid_action(
    adapter: &dyn PaymentAdapterDyn,
    policy: Option<&EconomicPolicy>,
    action_type: PaidActionType,
    actor: &DID,
    context_id: Option<ContextId>,
    metrics: &ObservableMetrics,
    metadata: PaymentMetadata,
    payload: Vec<u8>,
) -> Result<PreparedAction, IntegrationError> {
    // Step 1: Evaluate cost.
    let cost = match policy {
        Some(p) => evaluate_cost(p, &action_type, metrics)
            .ok_or(IntegrationError::CostEvaluationOverflow)?,
        None => Amount(0),
    };

    // Free action: no payment needed.
    if cost == Amount(0) || policy.is_none() {
        return Ok(PreparedAction {
            envelope: ActionEnvelope {
                actor: actor.clone(),
                action_type,
                context_id,
                authorization: None,
                payload,
            },
            evaluated_cost: Amount(0),
        });
    }

    // policy is Some and cost > 0 at this point.
    let policy = policy.ok_or(IntegrationError::NoEconomicPolicy)?;

    // Step 3: Authorize payment.
    let auth = adapter
        .authorize_dyn(
            actor,
            &policy.payee,
            cost,
            policy.cost_schedule.currency,
            metadata,
        )
        .await
        .map_err(IntegrationError::AuthorizationFailed)?;

    // Step 4: Attach authorization to envelope.
    Ok(PreparedAction {
        envelope: ActionEnvelope {
            actor: actor.clone(),
            action_type,
            context_id,
            authorization: Some(auth),
            payload,
        },
        evaluated_cost: cost,
    })
}

// ---------------------------------------------------------------------------
// Receiver-side: process_paid_action (steps 5-9)
// ---------------------------------------------------------------------------

/// Result of receiver-side processing of a paid action.
#[derive(Clone, Debug)]
pub struct ProcessedAction {
    /// The receipt from capturing the payment. `None` for free actions.
    pub receipt: Option<PaymentReceipt>,
    /// The result of the action processing (opaque bytes from the callback).
    pub action_result: Vec<u8>,
}

/// Processes a paid action on the receiver side (steps 5-9).
///
/// 5. Verifies authorization via `adapter.verify_authorization()` AND
///    `verify_cost_sufficiency()`.
/// 6. Calls the `process_action` callback to execute the action.
/// 7. Captures the payment via `adapter.capture()`.
/// 8. Returns the receipt for recording in the event log.
/// 9. On failure at steps 5-7, calls `adapter.void()` to release funds.
///
/// Free actions (where `envelope.authorization` is `None`) bypass all payment
/// verification and capture -- only the action callback is invoked.
///
/// # Errors
///
/// Returns [`IntegrationError`] for any failure in the sequence. When a
/// failure occurs after authorization, the adapter's `void()` is called
/// to release reserved funds.
pub async fn process_paid_action<F, Fut>(
    adapter: &dyn PaymentAdapterDyn,
    policy: Option<&EconomicPolicy>,
    envelope: &ActionEnvelope,
    metrics: &ObservableMetrics,
    process_action: F,
) -> Result<ProcessedAction, IntegrationError>
where
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, String>>,
{
    // Free action path: no authorization means no payment flow.
    let Some(auth) = &envelope.authorization else {
        // Free action -- just run the callback.
        let action_result = process_action(envelope.payload.clone())
            .await
            .map_err(IntegrationError::ActionProcessingFailed)?;
        return Ok(ProcessedAction {
            receipt: None,
            action_result,
        });
    };

    // Step 5a: Verify authorization via adapter (prevents forged auth structs).
    if let Err(e) = adapter.verify_authorization_dyn(auth).await {
        return Err(IntegrationError::AuthorizationVerificationFailed(e));
    }

    // Step 5b: Verify cost sufficiency.
    if let Some(policy) = policy
        && let Err(insufficient) =
            verify_cost_sufficiency(policy, &envelope.action_type, metrics, auth.amount)
    {
        // Void the authorization -- payer's funds should not remain locked.
        return void_on_failure(
            adapter,
            auth,
            IntegrationError::CostInsufficient {
                expected: insufficient.expected,
                provided: insufficient.provided,
                metric_snapshot: insufficient.metric_snapshot,
            },
        )
        .await;
    }

    // Step 6: Process the action.
    let action_result = match process_action(envelope.payload.clone()).await {
        Ok(result) => result,
        Err(msg) => {
            return void_on_failure(adapter, auth, IntegrationError::ActionProcessingFailed(msg))
                .await;
        }
    };

    // Step 7: Capture the payment.
    let receipt = match adapter.capture_dyn(auth).await {
        Ok(receipt) => receipt,
        Err(e) => {
            // Void is not needed after capture failure -- the adapter is
            // responsible for the authorization state. But we still report
            // the error.
            return Err(IntegrationError::CaptureFailed(e));
        }
    };

    // Step 8: Return receipt (caller records it in the event log).
    Ok(ProcessedAction {
        receipt: Some(receipt),
        action_result,
    })
}

// ---------------------------------------------------------------------------
// Step 9: Void on failure
// ---------------------------------------------------------------------------

/// Attempts to void a payment authorization after a failure in steps 5-7.
///
/// Always returns `Err` -- either the original error (if void succeeds) or
/// a [`IntegrationError::VoidFailed`] wrapping both errors (if void fails).
async fn void_on_failure<T>(
    adapter: &dyn PaymentAdapterDyn,
    auth: &PaymentAuthorization,
    original_error: IntegrationError,
) -> Result<T, IntegrationError> {
    match adapter.void_dyn(auth).await {
        Ok(()) => Err(original_error),
        Err(void_err) => Err(IntegrationError::VoidFailed {
            original: Box::new(original_error),
            void_error: void_err,
        }),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::struct_field_names,
    clippy::similar_names
)]
mod tests {
    use super::*;
    use crate::economy::adapter::{
        AdapterCapabilities, PaymentAdapter, PaymentMetadata, RefundConfirmation,
        VerificationResult,
    };
    use scp_protocol::economy::types::{CostSchedule, CurrencyCode};

    // -----------------------------------------------------------------------
    // TestAdapter -- in-memory ledger for testing
    // -----------------------------------------------------------------------

    struct TestAdapter {
        /// If set, `authorize` will fail with this error.
        authorize_fail: Option<PaymentError>,
        /// If set, `verify_authorization` will fail with this error.
        verify_auth_fail: Option<PaymentError>,
        /// If set, `capture` will fail with this error.
        capture_fail: Option<PaymentError>,
        /// If set, `void` will fail with this error.
        void_fail: Option<PaymentError>,
    }

    impl TestAdapter {
        fn new() -> Self {
            Self {
                authorize_fail: None,
                verify_auth_fail: None,
                capture_fail: None,
                void_fail: None,
            }
        }
    }

    impl PaymentAdapter for TestAdapter {
        fn adapter_id(&self) -> &'static str {
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
            if let Some(ref err) = self.authorize_fail {
                return Err(err.clone());
            }
            Ok(PaymentAuthorization {
                auth_id: [1u8; 32],
                payer: payer.clone(),
                payee: payee.clone(),
                amount,
                currency,
                adapter_id: "test".to_owned(),
                created_at: 1_000_000,
                expires_at: 2_000_000,
                adapter_state: vec![],
            })
        }

        async fn verify_authorization(
            &self,
            _auth: &PaymentAuthorization,
        ) -> Result<(), PaymentError> {
            if let Some(ref err) = self.verify_auth_fail {
                return Err(err.clone());
            }
            Ok(())
        }

        async fn capture(
            &self,
            auth: &PaymentAuthorization,
        ) -> Result<PaymentReceipt, PaymentError> {
            if let Some(ref err) = self.capture_fail {
                return Err(err.clone());
            }
            Ok(PaymentReceipt {
                receipt_id: [2u8; 32],
                payer: auth.payer.clone(),
                payee: auth.payee.clone(),
                amount: auth.amount,
                currency: auth.currency,
                action_type: PaidActionType::MessageSend,
                context_id: None,
                adapter_id: "test".to_owned(),
                adapter_proof: vec![0xAB],
                timestamp: 1_000_001,
                anchored: false,
                signature: vec![0xCD],
            })
        }

        async fn void(&self, _auth: &PaymentAuthorization) -> Result<(), PaymentError> {
            if let Some(ref err) = self.void_fail {
                return Err(err.clone());
            }
            Ok(())
        }

        async fn verify(
            &self,
            _receipt: &PaymentReceipt,
        ) -> Result<VerificationResult, PaymentError> {
            Ok(VerificationResult {
                valid: true,
                adapter_id: "test".to_owned(),
                verified_amount: Amount(0),
                verified_currency: CurrencyCode::from("USD"),
                verification_timestamp: 1_000_002,
            })
        }

        async fn refund(
            &self,
            _receipt: &PaymentReceipt,
            _amount: Option<Amount>,
        ) -> Result<RefundConfirmation, PaymentError> {
            Ok(RefundConfirmation {
                refund_id: [3u8; 32],
                original_receipt_id: [2u8; 32],
                refunded_amount: Amount(0),
                currency: CurrencyCode::from("USD"),
                adapter_proof: vec![],
            })
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn usd() -> CurrencyCode {
        CurrencyCode::from("USD")
    }

    fn payer() -> DID {
        DID::from("did:dht:z6MkPayer")
    }

    fn payee() -> DID {
        DID::from("did:dht:z6MkPayee")
    }

    fn paid_policy() -> EconomicPolicy {
        EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: usd(),
                per_message: Some(Amount(10)),
                per_outlet_call: Some(Amount(50)),
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec!["test".to_owned()],
            pricing_formula: None,
            payee: payee(),
        }
    }

    fn test_metadata() -> PaymentMetadata {
        PaymentMetadata {
            action_type: PaidActionType::MessageSend,
            context_id: Some("ctx-1".to_owned()),
            idempotency_key: [0u8; 16],
        }
    }

    fn default_metrics() -> ObservableMetrics {
        ObservableMetrics::default()
    }

    // -----------------------------------------------------------------------
    // Tests: Full 9-step sequence
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn full_9_step_sequence_with_test_adapter() {
        let adapter = TestAdapter::new();
        let policy = paid_policy();
        let metrics = default_metrics();

        // Steps 1-4: Sender prepares paid action.
        let prepared = prepare_paid_action(
            &adapter,
            Some(&policy),
            PaidActionType::MessageSend,
            &payer(),
            Some("ctx-1".to_owned()),
            &metrics,
            test_metadata(),
            b"hello".to_vec(),
        )
        .await
        .unwrap();

        assert_eq!(prepared.evaluated_cost, Amount(10));
        assert!(prepared.envelope.authorization.is_some());

        // Steps 5-8: Receiver processes paid action.
        let result = process_paid_action(
            &adapter,
            Some(&policy),
            &prepared.envelope,
            &metrics,
            |payload| async move {
                assert_eq!(payload, b"hello".to_vec());
                Ok(b"ack".to_vec())
            },
        )
        .await
        .unwrap();

        assert!(result.receipt.is_some());
        let receipt = result.receipt.unwrap();
        assert_eq!(receipt.amount, Amount(10));
        assert_eq!(result.action_result, b"ack");
    }

    // -----------------------------------------------------------------------
    // Tests: Free action bypass
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn free_action_no_policy_returns_none_authorization() {
        let adapter = TestAdapter::new();
        let metrics = default_metrics();

        let prepared = prepare_paid_action(
            &adapter,
            None,
            PaidActionType::MessageSend,
            &payer(),
            None,
            &metrics,
            test_metadata(),
            b"free message".to_vec(),
        )
        .await
        .unwrap();

        assert_eq!(prepared.evaluated_cost, Amount(0));
        assert!(prepared.envelope.authorization.is_none());
    }

    #[tokio::test]
    async fn free_action_in_paid_context_bypasses_payment() {
        // Context has a paid policy but no cost for ContextJoin.
        let adapter = TestAdapter::new();
        let policy = paid_policy(); // has per_message but not per_join
        let metrics = default_metrics();

        let prepared = prepare_paid_action(
            &adapter,
            Some(&policy),
            PaidActionType::ContextJoin, // No cost in schedule
            &payer(),
            Some("ctx-1".to_owned()),
            &metrics,
            test_metadata(),
            b"join".to_vec(),
        )
        .await
        .unwrap();

        assert_eq!(prepared.evaluated_cost, Amount(0));
        assert!(prepared.envelope.authorization.is_none());
    }

    #[tokio::test]
    async fn free_action_receiver_processes_without_payment() {
        let adapter = TestAdapter::new();

        let envelope = ActionEnvelope {
            actor: payer(),
            action_type: PaidActionType::MessageSend,
            context_id: None,
            authorization: None,
            payload: b"free".to_vec(),
        };

        let result = process_paid_action(
            &adapter,
            None,
            &envelope,
            &default_metrics(),
            |p| async move {
                assert_eq!(p, b"free".to_vec());
                Ok(b"done".to_vec())
            },
        )
        .await
        .unwrap();

        assert!(result.receipt.is_none());
        assert_eq!(result.action_result, b"done");
    }

    // -----------------------------------------------------------------------
    // Tests: Void on failure
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn void_on_verification_failure() {
        let adapter = TestAdapter {
            verify_auth_fail: Some(PaymentError::AdapterError("forged auth".into())),
            ..TestAdapter::new()
        };
        let policy = paid_policy();
        let metrics = default_metrics();

        // Prepare a valid action on sender side.
        let valid_adapter = TestAdapter::new();
        let prepared = prepare_paid_action(
            &valid_adapter,
            Some(&policy),
            PaidActionType::MessageSend,
            &payer(),
            Some("ctx-1".to_owned()),
            &metrics,
            test_metadata(),
            b"msg".to_vec(),
        )
        .await
        .unwrap();

        // Receiver's adapter rejects the authorization.
        let err = process_paid_action(
            &adapter,
            Some(&policy),
            &prepared.envelope,
            &metrics,
            |_| async { Ok(b"should not reach".to_vec()) },
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, IntegrationError::AuthorizationVerificationFailed(_)),
            "expected AuthorizationVerificationFailed, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn void_on_action_processing_failure() {
        let adapter = TestAdapter::new();
        let policy = paid_policy();
        let metrics = default_metrics();

        let prepared = prepare_paid_action(
            &adapter,
            Some(&policy),
            PaidActionType::MessageSend,
            &payer(),
            Some("ctx-1".to_owned()),
            &metrics,
            test_metadata(),
            b"msg".to_vec(),
        )
        .await
        .unwrap();

        let err = process_paid_action(
            &adapter,
            Some(&policy),
            &prepared.envelope,
            &metrics,
            |_| async { Err("action failed".to_owned()) },
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, IntegrationError::ActionProcessingFailed(_)),
            "expected ActionProcessingFailed, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn void_failure_wraps_both_errors() {
        let adapter = TestAdapter {
            verify_auth_fail: Some(PaymentError::AdapterError("bad auth".into())),
            void_fail: Some(PaymentError::AdapterError("void also failed".into())),
            ..TestAdapter::new()
        };

        let envelope = ActionEnvelope {
            actor: payer(),
            action_type: PaidActionType::MessageSend,
            context_id: None,
            authorization: Some(PaymentAuthorization {
                auth_id: [1u8; 32],
                payer: payer(),
                payee: payee(),
                amount: Amount(10),
                currency: usd(),
                adapter_id: "test".to_owned(),
                created_at: 1_000_000,
                expires_at: 2_000_000,
                adapter_state: vec![],
            }),
            payload: b"msg".to_vec(),
        };

        // verify_authorization fails, then void also fails.
        // Note: verify_authorization failure does NOT trigger void because
        // the authorization was never verified as authentic -- voiding an
        // unverified auth is the sender's responsibility.
        let err = process_paid_action(
            &adapter,
            Some(&paid_policy()),
            &envelope,
            &default_metrics(),
            |_| async { Ok(b"".to_vec()) },
        )
        .await
        .unwrap_err();

        // Since verify_authorization failure returns early without void,
        // we get AuthorizationVerificationFailed directly.
        assert!(
            matches!(err, IntegrationError::AuthorizationVerificationFailed(_)),
            "expected AuthorizationVerificationFailed, got: {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Tests: CostInsufficient with metric_snapshot
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn cost_insufficient_returns_metric_snapshot() {
        let adapter = TestAdapter::new();
        // Policy requires 10 per message, but we'll craft an auth with amount 5.
        let policy = paid_policy();
        let metrics = default_metrics();

        let envelope = ActionEnvelope {
            actor: payer(),
            action_type: PaidActionType::MessageSend,
            context_id: Some("ctx-1".to_owned()),
            authorization: Some(PaymentAuthorization {
                auth_id: [1u8; 32],
                payer: payer(),
                payee: payee(),
                amount: Amount(5), // Less than required 10
                currency: usd(),
                adapter_id: "test".to_owned(),
                created_at: 1_000_000,
                expires_at: 2_000_000,
                adapter_state: vec![],
            }),
            payload: b"msg".to_vec(),
        };

        let err = process_paid_action(&adapter, Some(&policy), &envelope, &metrics, |_| async {
            Ok(b"".to_vec())
        })
        .await
        .unwrap_err();

        match err {
            IntegrationError::CostInsufficient {
                expected, provided, ..
            } => {
                assert_eq!(expected, Amount(10));
                assert_eq!(provided, Amount(5));
            }
            other => panic!("expected CostInsufficient, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Tests: Authorization failure
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn authorization_failure_returns_adapter_error() {
        let adapter = TestAdapter {
            authorize_fail: Some(PaymentError::InsufficientBalance {
                available: Amount(5),
                requested: Amount(10),
            }),
            ..TestAdapter::new()
        };
        let policy = paid_policy();

        let err = prepare_paid_action(
            &adapter,
            Some(&policy),
            PaidActionType::MessageSend,
            &payer(),
            Some("ctx-1".to_owned()),
            &default_metrics(),
            test_metadata(),
            b"msg".to_vec(),
        )
        .await
        .unwrap_err();

        assert!(
            matches!(
                err,
                IntegrationError::AuthorizationFailed(PaymentError::InsufficientBalance { .. })
            ),
            "expected AuthorizationFailed(InsufficientBalance), got: {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Tests: Option<PaymentAuthorization> -- no dummy auth
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn no_dummy_authorization_for_free_actions() {
        let adapter = TestAdapter::new();

        // Case 1: No policy.
        let prepared = prepare_paid_action(
            &adapter,
            None,
            PaidActionType::MessageSend,
            &payer(),
            None,
            &default_metrics(),
            test_metadata(),
            b"free".to_vec(),
        )
        .await
        .unwrap();
        assert!(
            prepared.envelope.authorization.is_none(),
            "free action should have None authorization, not a dummy"
        );

        // Case 2: Policy exists but action type has zero cost.
        let prepared = prepare_paid_action(
            &adapter,
            Some(&paid_policy()),
            PaidActionType::ContextJoin, // No per_join cost in our test policy
            &payer(),
            None,
            &default_metrics(),
            test_metadata(),
            b"join".to_vec(),
        )
        .await
        .unwrap();
        assert!(
            prepared.envelope.authorization.is_none(),
            "zero-cost action should have None authorization, not a dummy"
        );
    }
}
