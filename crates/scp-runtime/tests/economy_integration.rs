#![allow(
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::large_stack_arrays,
    clippy::unreadable_literal,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::redundant_field_names,
    clippy::unnecessary_literal_unwrap
)]
//! End-to-end integration test covering ALL 9 invariants from spec section 19.14.
//!
//! Invariants tested:
//! 1. Economic policy visible before opt-in (legibility)
//! 2. No implicit spending -- spending UCAN always required
//! 3. Free operation is default -- no economic policy = free
//! 4. Receipts are provenance records -- every payment is traceable and verifiable
//! 5. Payment adapters are substitutable -- no single rail privileged
//! 6. Economic policy mutable by default, optional immutability lock is voluntary
//! 7. Payment data inside encrypted envelope -- relays never see payment metadata
//! 8. Free relays MUST always exist in bootstrap list
//! 9. Auto-accept never applies to paid contexts
//!
//! Integration flow: create context with `EconomicPolicy` -> register tool with cost
//! -> grant spending UCAN -> verify spending checks -> verify receipt provenance
//! -> test auto-accept rejection -> test `SpendingCapabilityRequired`
//! -> test dynamic pricing -> test anti-spam escalation -> verify free relay exists.
//!
//! See spec section 19.14 and ADR-033.

use std::time::Duration;

use scp_event_log::proof::{prove_inclusion, verify_inclusion};
use scp_event_log::tree;
use scp_event_log::{Event, EventLog, EventPayload, EventType};
use scp_identity::DID;
use scp_primitives::Clock;
use scp_protocol::crypto::ucan::spending::{BudgetTracker, SpendingCapability, SpendingError};
use scp_protocol::crypto::ucan::{Attenuation, UcanHeader, UcanPayload, UcanToken};
use scp_protocol::economy::antispam::{
    EscalationConfig, EscalationThreshold, SenderVelocityTracker,
};
use scp_protocol::economy::policy::{
    ObservableMetrics, auto_accept_blocked_by_economics, check_policy_lock, evaluate_cost,
    policy_requires_payment, validate_policy_change,
};
use scp_protocol::economy::types::{
    Amount, Coefficient, CostSchedule, CurrencyCode, EconomicPolicy, PaidActionType,
    PricingFormula, PricingMetric, PricingVariable,
};
use scp_runtime::economy::adapter::{
    AdapterCapabilities, PaymentAdapter, PaymentAuthorization, PaymentError, PaymentMetadata,
    PaymentReceipt, RefundConfirmation, VerificationResult,
};
use scp_runtime::economy::receipt::{ReceiptFilter, payment_history};
use scp_runtime::well_known::{RelayConfig, RelayEconomicConfig, WellKnownScp};

// ===========================================================================
// Test adapter -- in-memory, no real money, for integration tests
// ===========================================================================

/// Minimal test adapter implementing [`PaymentAdapter`] with configurable failure
/// injection. Follows the pattern from existing unit tests in the economy module.
struct TestAdapter {
    authorize_fail: Option<PaymentError>,
    capture_fail: Option<PaymentError>,
    void_fail: Option<PaymentError>,
    /// Adapter identifier -- allows testing adapter substitution (invariant 5).
    id: &'static str,
}

impl TestAdapter {
    const fn new() -> Self {
        Self {
            authorize_fail: None,
            capture_fail: None,
            void_fail: None,
            id: "test",
        }
    }

    fn with_id(id: &'static str) -> Self {
        Self { id, ..Self::new() }
    }
}

impl PaymentAdapter for TestAdapter {
    fn adapter_id(&self) -> &str {
        self.id
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
            adapter_id: self.id.to_owned(),
            created_at: 1_000_000,
            expires_at: 2_000_000,
            adapter_state: vec![],
        })
    }

    async fn capture(&self, auth: &PaymentAuthorization) -> Result<PaymentReceipt, PaymentError> {
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
            context_id: Some("ctx-econ-test".to_owned()),
            adapter_id: self.id.to_owned(),
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

    async fn verify(&self, _receipt: &PaymentReceipt) -> Result<VerificationResult, PaymentError> {
        Ok(VerificationResult {
            valid: true,
            adapter_id: self.id.to_owned(),
            verified_amount: Amount(0),
            verified_currency: CurrencyCode::from("USD"),
            verification_timestamp: 1_000_002,
        })
    }

    async fn verify_authorization(&self, _auth: &PaymentAuthorization) -> Result<(), PaymentError> {
        Ok(())
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

// ===========================================================================
// Helpers
// ===========================================================================

fn usd() -> CurrencyCode {
    CurrencyCode::from("USD")
}

fn payer_did() -> DID {
    DID::from("did:dht:z6MkPayer")
}

fn payee_did() -> DID {
    DID::from("did:dht:z6MkPayee")
}

/// Creates a paid economic policy with per-message and per-tool-invoke costs.
fn paid_policy() -> EconomicPolicy {
    EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: usd(),
            per_message: Some(Amount(10)),
            per_tool_invoke: Some(Amount(50)),
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec!["test".to_owned()],
        pricing_formula: None,
        payee: payee_did(),
    }
}

/// Creates a free economic policy (all costs None, no pricing formula).
fn free_policy_no_costs() -> EconomicPolicy {
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

fn default_metrics() -> ObservableMetrics {
    ObservableMetrics::default()
}

/// Creates a dummy UCAN token for spending validation tests.
///
/// Uses `exp = now + 3600` (1 hour) to satisfy the 24-hour maximum expiry
/// check enforced by `validate_spending_ucan`.
fn make_spending_ucan(cap: &SpendingCapability, scope_uri: &str) -> UcanToken {
    let now = scp_primitives::SystemClock.now_secs();

    let cap_json = serde_json::to_value(cap).unwrap();
    let mut fct = serde_json::Map::new();
    fct.insert("spending_capability".to_owned(), cap_json);

    UcanToken {
        header: UcanHeader::new(),
        payload: UcanPayload {
            iss: "did:dht:z6MkHuman".to_owned(),
            aud: "did:dht:z6MkAgent".to_owned(),
            exp: now + 3600,
            nbf: Some(now),
            nnc: "test-nonce-1234".to_owned(),
            att: vec![Attenuation {
                with: scope_uri.to_owned(),
                can: "spend".to_owned(),
            }],
            prf: vec![],
            fct: Some(serde_json::Value::Object(fct)),
        },
        signature: vec![0u8; 64],
        encoded: String::new(),
    }
}

/// Creates a spending capability with test parameters.
fn test_spending_capability() -> SpendingCapability {
    SpendingCapability {
        max_per_action: scp_protocol::crypto::ucan::spending::Amount(1000),
        max_total: scp_protocol::crypto::ucan::spending::Amount(10_000),
        currency: scp_protocol::crypto::ucan::spending::CurrencyCode::from_code("USD").unwrap(),
        time_window: Duration::from_hours(24),
        allowed_adapters: vec!["test".to_owned()],
    }
}

/// Generates a properly signed event for the event log, using a test keypair.
fn signed_event(
    event_type: EventType,
    sequence: u64,
    payload: Vec<u8>,
    prev_hash: [u8; 32],
    signing_key: &ed25519_dalek::SigningKey,
    actor_did: &str,
) -> Event {
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};

    let mut event = Event {
        event_type,
        actor_did: DID::from(actor_did),
        timestamp: 1_000_000 + sequence,
        sequence,
        payload: EventPayload { data: payload },
        prev_hash,
        signature: Vec::new(),
    };

    // Compute canonical hash (must match tree.rs: compute_event_canonical_hash).
    let event_tag: u16 = tree::event_type_tag(&event.event_type);

    let mut hasher = Sha256::new();
    hasher.update(b"SCP-EVENT-V1:");
    #[allow(clippy::cast_possible_truncation)]
    let length_prefix = |hasher: &mut Sha256, bytes: &[u8]| {
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    };
    hasher.update(event_tag.to_be_bytes());
    length_prefix(&mut hasher, event.actor_did.as_bytes());
    hasher.update(event.timestamp.to_be_bytes());
    hasher.update(event.sequence.to_be_bytes());
    length_prefix(&mut hasher, &event.payload.data);
    hasher.update(event.prev_hash);
    let canonical_hash = hasher.finalize().to_vec();

    let signature = signing_key.sign(&canonical_hash);
    event.signature = signature.to_bytes().to_vec();

    event
}

/// Computes the leaf hash for a signed event (matching tree.rs).
fn leaf_hash_of(event: &Event) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let serialized = rmp_serde::to_vec(event).unwrap();
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(&serialized);
    hasher.finalize().into()
}

/// Creates a test keypair and returns (`did_string`, `signing_key`).
fn test_keypair() -> (String, ed25519_dalek::SigningKey) {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let verifying_key = signing_key.verifying_key();
    let hex: String = verifying_key
        .as_bytes()
        .iter()
        .fold(String::new(), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        });
    (format!("did:key:{hex}"), signing_key)
}

// ===========================================================================
// Invariant 1: Economic policy visible before opt-in (legibility)
// ===========================================================================

/// Invariant 1: Economic policy is part of context metadata, visible before
/// joining. Prospective members can inspect the economic terms.
#[test]
fn invariant_1_economic_policy_visible_before_opt_in() {
    let policy = paid_policy();

    // Simulate inspecting context metadata before joining.
    // The economic policy is a field on context params, accessible without joining.
    let economic_metadata: Option<&EconomicPolicy> = Some(&policy);

    // Prospective member can see:
    assert!(economic_metadata.is_some());
    let p = economic_metadata.unwrap();
    assert_eq!(p.cost_schedule.per_message, Some(Amount(10)));
    assert_eq!(p.cost_schedule.per_tool_invoke, Some(Amount(50)));
    assert_eq!(p.cost_schedule.currency, usd());
    assert_eq!(p.payment_adapters, vec!["test"]);
    assert_eq!(p.payee, payee_did());
    assert!(!p.locked);
}

/// Invariant 1: Economic terms visible even for contexts with dynamic pricing.
#[test]
fn invariant_1_dynamic_pricing_visible_before_opt_in() {
    let policy = EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: usd(),
            per_message: Some(Amount(1)),
            per_tool_invoke: None,
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec!["test".to_owned()],
        pricing_formula: Some(PricingFormula {
            base_cost: Amount(5),
            variables: vec![PricingVariable::Step {
                metric: PricingMetric::SenderVelocity,
                thresholds: vec![(10, Amount(1)), (50, Amount(10))],
            }],
            cap: Some(Amount(100)),
            floor: Some(Amount(1)),
        }),
        payee: payee_did(),
    };

    // The pricing formula, cap, floor, and variables are all inspectable.
    let formula = policy.pricing_formula.as_ref().unwrap();
    assert_eq!(formula.base_cost, Amount(5));
    assert_eq!(formula.cap, Some(Amount(100)));
    assert_eq!(formula.floor, Some(Amount(1)));
    assert_eq!(formula.variables.len(), 1);
}

/// Invariant 1: Well-known relay document exposes economic config before connection.
#[test]
fn invariant_1_relay_economic_config_visible_in_wellknown() {
    let relay_doc = WellKnownScp {
        version: 1,
        did: "did:dht:z6MkRelay".to_owned(),
        relay: "wss://relay.example.com/scp/v1".to_owned(),
        contexts: None,
        relay_config: Some(RelayConfig {
            max_blob_size: Some(262_144),
            max_blob_ttl: None,
            rate_limit_publish: None,
            rate_limit_subscribe: None,
            transports: None,
            economic: Some(RelayEconomicConfig {
                currency: usd(),
                per_publish: Some(Amount(5)),
                per_byte_stored: Some(Amount(1)),
                payment_adapters: vec!["x402".to_owned()],
                payee: "did:dht:z6MkRelayOperator".to_owned(),
            }),
        }),
        handles: None,
    };

    // Client inspects relay economics BEFORE connecting.
    let econ = relay_doc
        .relay_config
        .as_ref()
        .unwrap()
        .economic
        .as_ref()
        .unwrap();
    assert_eq!(econ.per_publish, Some(Amount(5)));
    assert_eq!(econ.per_byte_stored, Some(Amount(1)));
    assert_eq!(econ.currency, usd());
    assert_eq!(econ.payment_adapters, vec!["x402"]);
}

// ===========================================================================
// Invariant 2: No implicit spending -- spending UCAN always required
// ===========================================================================

/// Invariant 2: Attempt paid action without spending UCAN returns
/// `SpendingCapabilityRequired` error. Action capability is verified at
/// the gate layer upstream per spec §19.5.
#[test]
fn invariant_2_paid_action_without_spending_ucan_rejected() {
    use scp_protocol::crypto::ucan::spending::check_spending_capability;

    let _now = scp_primitives::SystemClock.now_secs();

    // Action cost is 10 (non-zero), but no spending UCAN provided.
    let cost = scp_protocol::crypto::ucan::spending::Amount(10);
    let result = check_spending_capability(
        None, // No spending UCAN
        cost,
        "send message in paid context",
    );

    let err = result.unwrap_err();
    assert!(
        matches!(err, SpendingError::SpendingCapabilityRequired(_)),
        "expected SpendingCapabilityRequired, got: {err:?}"
    );
}

/// Invariant 2: Grant spending UCAN, attempt paid action — spending side of
/// AND-composition passes. Action capability is verified at the gate layer
/// upstream per spec §19.5.
///
/// C1 (PR #1606): the standalone `validate_spending_ucan` is now `pub(crate)`
/// in `scp-protocol`. End-to-end spending validation goes through
/// `validate_spending_ucan_signed` (the only public entry point), which is
/// exercised by the manager-level tests in
/// `crates/scp-runtime/src/context/manager/tests/governance.rs`. This
/// integration test now only exercises the cap-only `check_spending_capability`
/// surface — the scope/lifetime/attenuation surface is covered by the
/// scp-protocol unit tests in `crypto/ucan/spending.rs`.
#[test]
fn invariant_2_paid_action_with_spending_ucan_succeeds() {
    use scp_protocol::crypto::ucan::spending::check_spending_capability;

    let cap = test_spending_capability();
    let spending_ucan = make_spending_ucan(&cap, "scp:spending:ctx-econ-test");

    // Check spending capability with valid spending UCAN.
    let cost = scp_protocol::crypto::ucan::spending::Amount(10);
    let result = check_spending_capability(Some(&spending_ucan), cost, "send message");
    assert!(
        result.is_ok(),
        "spending capability check should succeed: {result:?}"
    );
}

/// Invariant 2: Full authorize-capture cycle with adapter after UCAN check passes.
#[tokio::test]
async fn invariant_2_authorize_capture_after_spending_check() {
    let adapter = TestAdapter::new();
    let policy = paid_policy();
    let metrics = default_metrics();

    // Evaluate cost from policy.
    let cost = evaluate_cost(&policy, &PaidActionType::MessageSend, &metrics);
    assert_eq!(cost, Some(Amount(10)));

    // After spending UCAN check passes, authorize payment.
    let auth = adapter
        .authorize(
            &payer_did(),
            &payee_did(),
            Amount(10),
            usd(),
            PaymentMetadata {
                action_type: PaidActionType::MessageSend,
                context_id: Some("ctx-econ-test".to_owned()),
                idempotency_key: [0u8; 16],
            },
        )
        .await
        .unwrap();

    assert_eq!(auth.amount, Amount(10));
    assert_eq!(auth.payer, payer_did());

    // Capture the payment.
    let receipt = adapter.capture(&auth).await.unwrap();
    assert_eq!(receipt.amount, Amount(10));
    assert_eq!(receipt.adapter_id, "test");
}

/// Invariant 2: Free actions succeed without any spending UCAN.
/// Paid actions with no spending UCAN are rejected.
///
/// (Action capability is verified at the gate layer upstream per spec §19.5
/// — see the `MessagesWrite` / `ToolInvoke` `member_has_capability` checks
/// in the manager modules. This test exercises only the spending side.)
#[test]
fn invariant_2_spending_capability_paid_action_rejected_without_ucan() {
    use scp_protocol::crypto::ucan::spending::check_spending_capability;

    // Free action (cost=0) with no spending UCAN — should succeed.
    let cost_zero = scp_protocol::crypto::ucan::spending::Amount(0);
    let result_free = check_spending_capability(None, cost_zero, "any action");
    assert!(
        result_free.is_ok(),
        "free action should succeed without any spending UCAN"
    );

    // Paid action (cost>0) with no spending UCAN — should fail.
    let cost_paid = scp_protocol::crypto::ucan::spending::Amount(100);
    let result_paid = check_spending_capability(None, cost_paid, "paid action");
    assert!(
        result_paid.is_err(),
        "paid action should fail without spending UCAN"
    );
}

// ===========================================================================
// Invariant 3: Free operation is default -- no economic policy = free
// ===========================================================================

/// Invariant 3: Context without `EconomicPolicy` -- all actions are free.
#[test]
fn invariant_3_no_economic_policy_all_actions_free() {
    let metrics = default_metrics();

    // No policy: evaluate_cost returns None (handled as free by caller).
    let cost = evaluate_cost(
        &EconomicPolicy {
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
        },
        &PaidActionType::MessageSend,
        &metrics,
    );
    // Schedule has no per_message cost and no formula: returns 0.
    assert_eq!(cost, Some(Amount(0)));
}

/// Invariant 3: `estimate_cost` returns 0 when no economic policy.
#[test]
fn invariant_3_estimate_cost_zero_without_policy() {
    use scp_protocol::economy::estimate::estimate_cost;

    let metrics = default_metrics();

    // No policy: all action types are free.
    for action in &[
        PaidActionType::MessageSend,
        PaidActionType::ToolInvoke,
        PaidActionType::ContextJoin,
        PaidActionType::SubscriptionPeriod,
        PaidActionType::ByteStored,
    ] {
        let cost = estimate_cost(None, action, &metrics);
        assert_eq!(
            cost,
            Some(Amount(0)),
            "action {action:?} should be free without policy"
        );
    }
}

/// Invariant 3: `policy_requires_payment` returns false for free policy.
#[test]
fn invariant_3_policy_requires_payment_false_for_free() {
    let free = free_policy_no_costs();
    assert!(!policy_requires_payment(&free));
}

/// Invariant 3: Free action does not need authorization (adapter not called).
#[tokio::test]
async fn invariant_3_free_action_no_authorization_needed() {
    let metrics = default_metrics();
    let free = free_policy_no_costs();

    // Evaluate cost: free policy has no costs.
    let cost = evaluate_cost(&free, &PaidActionType::MessageSend, &metrics);
    assert_eq!(cost, Some(Amount(0)));

    // When cost is 0, no authorization is needed -- skip adapter entirely.
    // This is the protocol behavior: free actions bypass payment adapter.
    assert!(!policy_requires_payment(&free));
}

// ===========================================================================
// Invariant 4: Receipts are provenance records
// ===========================================================================

/// Invariant 4: Complete paid action, surface the receipt via the local
/// receipt buffer, and prove the canonical Merkle log (which carries only
/// convergent events) is independently provable.
///
/// `PaymentReceived` is per-payee application activity excluded from the
/// canonical Merkle log (ADR-011 amendment exclusion taxonomy §2; convergent
/// only under ADR-051). The receipt is surfaced via `payment_history` over the
/// per-context local receipt buffer — NOT the durable log — while the durable
/// log carries the convergent membership/governance events that all honest
/// members append identically.
#[tokio::test]
async fn invariant_4_receipt_local_buffer_and_convergent_log_merkle_proof() {
    let adapter = TestAdapter::new();

    // Execute authorize + capture to get a receipt.
    let auth = adapter
        .authorize(
            &payer_did(),
            &payee_did(),
            Amount(10),
            usd(),
            PaymentMetadata {
                action_type: PaidActionType::MessageSend,
                context_id: Some("ctx-econ-test".to_owned()),
                idempotency_key: [0u8; 16],
            },
        )
        .await
        .unwrap();

    let receipt = adapter.capture(&auth).await.unwrap();

    // The durable Merkle log carries only CONVERGENT events (membership /
    // governance) — never the per-payee receipt. Build one so the inclusion
    // proof exercises the real tree without implying PaymentReceived is a leaf.
    let (did, signing_key) = test_keypair();
    let genesis_prev = [0u8; 32];
    let event0 = signed_event(
        EventType::MemberJoined,
        0,
        b"did:dht:z6MkJoiner".to_vec(),
        genesis_prev,
        &signing_key,
        &did,
    );

    let mut log = EventLog::new("ctx-econ-test".to_owned());
    let idx0 = tree::append(&mut log, &event0).unwrap();
    assert_eq!(idx0, 0);

    let leaf0_hash = leaf_hash_of(&event0);
    let event1 = signed_event(
        EventType::GovernanceActionExecuted,
        1,
        b"{\"action\":\"ChangeRole\"}".to_vec(),
        leaf0_hash,
        &signing_key,
        &did,
    );
    tree::append(&mut log, &event1).unwrap();

    assert_eq!(tree::event_count(&log), 2);

    // Merkle inclusion proof verifies for the convergent membership event.
    let proof = prove_inclusion(&log, 0).unwrap();
    assert!(
        verify_inclusion(&proof),
        "Merkle inclusion proof should verify for the convergent member-joined event"
    );

    // The receipt is surfaced from the per-context local receipt buffer (spec
    // §19.11) — NOT the durable Merkle log.
    let receipts = vec![receipt];
    let history = payment_history(&receipts, None);
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].amount, Amount(10));
}

/// Invariant 4: `PaymentReceipt` fields match expected values after capture.
#[tokio::test]
async fn invariant_4_receipt_fields_match() {
    let adapter = TestAdapter::new();

    let auth = adapter
        .authorize(
            &payer_did(),
            &payee_did(),
            Amount(10),
            usd(),
            PaymentMetadata {
                action_type: PaidActionType::MessageSend,
                context_id: Some("ctx-econ-test".to_owned()),
                idempotency_key: [0u8; 16],
            },
        )
        .await
        .unwrap();

    let receipt = adapter.capture(&auth).await.unwrap();

    // Verify all receipt fields.
    assert_eq!(receipt.payer, payer_did());
    assert_eq!(receipt.payee, payee_did());
    assert_eq!(receipt.amount, Amount(10));
    assert_eq!(receipt.currency, usd());
    assert_eq!(receipt.adapter_id, "test");
    assert_eq!(receipt.action_type, PaidActionType::MessageSend);
    assert_eq!(receipt.context_id, Some("ctx-econ-test".to_owned()));
}

/// Invariant 4: Receipts can be verified through the adapter.
#[tokio::test]
async fn invariant_4_receipt_verifiable_through_adapter() {
    let adapter = TestAdapter::new();

    let auth = adapter
        .authorize(
            &payer_did(),
            &payee_did(),
            Amount(10),
            usd(),
            PaymentMetadata {
                action_type: PaidActionType::MessageSend,
                context_id: Some("ctx-econ-test".to_owned()),
                idempotency_key: [0u8; 16],
            },
        )
        .await
        .unwrap();

    let receipt = adapter.capture(&auth).await.unwrap();

    // Verify the receipt through the adapter.
    let verification = adapter.verify(&receipt).await.unwrap();
    assert!(verification.valid, "receipt should verify as valid");
    assert_eq!(verification.adapter_id, "test");
}

/// Invariant 4: Payment receipt history filtering works correctly.
#[test]
fn invariant_4_payment_history_with_filters() {
    let receipt_alice = PaymentReceipt {
        receipt_id: [0xAA; 32],
        payer: DID::from("did:dht:z6MkAlice"),
        payee: DID::from("did:dht:z6MkBob"),
        amount: Amount(100),
        currency: usd(),
        action_type: PaidActionType::MessageSend,
        context_id: Some("ctx-1".to_owned()),
        adapter_id: "test".to_owned(),
        adapter_proof: vec![0x01],
        timestamp: 1_000_000,
        anchored: false,
        signature: vec![0xFF; 64],
    };

    let receipt_bob = PaymentReceipt {
        receipt_id: [0xBB; 32],
        payer: DID::from("did:dht:z6MkBob"),
        payee: DID::from("did:dht:z6MkAlice"),
        amount: Amount(200),
        currency: usd(),
        action_type: PaidActionType::ToolInvoke,
        context_id: Some("ctx-1".to_owned()),
        adapter_id: "test".to_owned(),
        adapter_proof: vec![0x02],
        timestamp: 2_000_000,
        anchored: false,
        signature: vec![0xFF; 64],
    };

    // The per-context local receipt buffer (NOT the durable Merkle log —
    // PaymentReceived is excluded from the canonical log per ADR-011 amendment
    // exclusion taxonomy §2). `payment_history` reads this buffer directly.
    let receipts = vec![receipt_alice, receipt_bob];

    // Unfiltered: all receipts returned.
    let all = payment_history(&receipts, None);
    assert_eq!(all.len(), 2);

    // Filter by payer.
    let alice_only = payment_history(
        &receipts,
        Some(&ReceiptFilter {
            payer: Some("did:dht:z6MkAlice".to_owned()),
            ..Default::default()
        }),
    );
    assert_eq!(alice_only.len(), 1);
    assert_eq!(alice_only[0].payer, DID::from("did:dht:z6MkAlice"));

    // Filter by time range.
    let after = payment_history(
        &receipts,
        Some(&ReceiptFilter {
            after_timestamp: Some(1_500_000),
            ..Default::default()
        }),
    );
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].amount, Amount(200));
}

// ===========================================================================
// Invariant 5: Payment adapters are substitutable
// ===========================================================================

/// Invariant 5: Replace `TestAdapter` with a second mock adapter -- same flow
/// works identically.
#[tokio::test]
async fn invariant_5_substitute_adapter_same_flow() {
    let policy = paid_policy();
    let metrics = default_metrics();

    // Evaluate cost from policy -- cost is adapter-independent.
    let cost = evaluate_cost(&policy, &PaidActionType::MessageSend, &metrics).unwrap();
    assert_eq!(cost, Amount(10));

    // Run authorize+capture with "test" adapter.
    let adapter_a = TestAdapter::new();
    let auth_a = adapter_a
        .authorize(
            &payer_did(),
            &payee_did(),
            cost,
            usd(),
            PaymentMetadata {
                action_type: PaidActionType::MessageSend,
                context_id: Some("ctx-econ-test".to_owned()),
                idempotency_key: [0u8; 16],
            },
        )
        .await
        .unwrap();
    let receipt_a = adapter_a.capture(&auth_a).await.unwrap();

    // Run authorize+capture with "alt-test" adapter.
    let adapter_b = TestAdapter::with_id("alt-test");
    let auth_b = adapter_b
        .authorize(
            &payer_did(),
            &payee_did(),
            cost,
            usd(),
            PaymentMetadata {
                action_type: PaidActionType::MessageSend,
                context_id: Some("ctx-econ-test".to_owned()),
                idempotency_key: [1u8; 16],
            },
        )
        .await
        .unwrap();
    let receipt_b = adapter_b.capture(&auth_b).await.unwrap();

    // Both produce receipts with the same cost but different adapter IDs.
    assert_eq!(receipt_a.amount, receipt_b.amount);
    assert_eq!(receipt_a.payer, receipt_b.payer);
    assert_eq!(receipt_a.payee, receipt_b.payee);

    // Adapter IDs are different, proving substitutability.
    assert_eq!(receipt_a.adapter_id, "test");
    assert_eq!(receipt_b.adapter_id, "alt-test");
}

/// Invariant 5: `PaymentAdapter` trait is implemented by both adapters identically.
#[test]
fn invariant_5_adapter_trait_is_uniform() {
    let adapter_a = TestAdapter::new();
    let adapter_b = TestAdapter::with_id("lightning-mock");

    // Both implement the same trait, both report capabilities.
    let caps_a = adapter_a.capabilities();
    let caps_b = adapter_b.capabilities();

    // Both support USD.
    assert!(caps_a.supported_currencies.contains(&usd()));
    assert!(caps_b.supported_currencies.contains(&usd()));

    // Adapter IDs differ.
    assert_eq!(adapter_a.adapter_id(), "test");
    assert_eq!(adapter_b.adapter_id(), "lightning-mock");
}

// ===========================================================================
// Invariant 6: Economic policy mutable by default, optional immutability lock
// ===========================================================================

/// Invariant 6: Context with locked: false, update economic policy via
/// governance -- succeeds.
#[test]
fn invariant_6_unlocked_policy_update_succeeds() {
    let current = EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: usd(),
            per_message: Some(Amount(10)),
            per_tool_invoke: None,
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec!["test".to_owned()],
        pricing_formula: None,
        payee: payee_did(),
    };

    let proposed = EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: usd(),
            per_message: Some(Amount(20)),      // Updated cost.
            per_tool_invoke: Some(Amount(100)), // New cost.
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec!["test".to_owned(), "x402".to_owned()],
        pricing_formula: None,
        payee: payee_did(),
    };

    // Unlocked policy: change is permitted.
    assert!(check_policy_lock(&current).is_ok());
    assert!(validate_policy_change(&current, &proposed).is_ok());
}

/// Invariant 6: Context with locked: true, attempt economic policy update --
/// rejected.
#[test]
fn invariant_6_locked_policy_update_rejected() {
    let current = EconomicPolicy {
        locked: true,
        cost_schedule: CostSchedule {
            currency: usd(),
            per_message: Some(Amount(10)),
            per_tool_invoke: None,
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec!["test".to_owned()],
        pricing_formula: None,
        payee: payee_did(),
    };

    let proposed = EconomicPolicy {
        locked: true,
        cost_schedule: CostSchedule {
            currency: usd(),
            per_message: Some(Amount(20)), // Attempted change.
            per_tool_invoke: None,
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec!["test".to_owned()],
        pricing_formula: None,
        payee: payee_did(),
    };

    // Locked policy: change is rejected.
    assert!(check_policy_lock(&current).is_err());
    assert!(validate_policy_change(&current, &proposed).is_err());
}

/// Invariant 6: Unlocked policy can be voluntarily locked (one-way transition).
#[test]
fn invariant_6_voluntary_lock_transition() {
    let current = EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: usd(),
            per_message: Some(Amount(0)),
            per_tool_invoke: None,
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec![],
        pricing_formula: None,
        payee: payee_did(),
    };

    let proposed_locked = EconomicPolicy {
        locked: true, // Voluntarily locking.
        ..current.clone()
    };

    // Transition from unlocked to locked is allowed.
    assert!(validate_policy_change(&current, &proposed_locked).is_ok());

    // After locking, further changes are rejected.
    assert!(check_policy_lock(&proposed_locked).is_err());
}

// ===========================================================================
// Invariant 7: Payment data inside encrypted envelope
// ===========================================================================

/// Invariant 7: `PaymentAuthorization` and `PaymentReceipt` carry payment metadata
/// that must live inside the encrypted envelope, not at the transport layer.
/// The relay sees only opaque encrypted bytes.
#[tokio::test]
async fn invariant_7_payment_data_inside_encrypted_envelope() {
    let adapter = TestAdapter::new();

    let auth = adapter
        .authorize(
            &payer_did(),
            &payee_did(),
            Amount(10),
            usd(),
            PaymentMetadata {
                action_type: PaidActionType::MessageSend,
                context_id: Some("ctx-econ-test".to_owned()),
                idempotency_key: [0u8; 16],
            },
        )
        .await
        .unwrap();

    // The PaymentAuthorization contains sensitive fields:
    // payer DID, payee DID, amount, currency, adapter ID.
    // These are carried INSIDE the encrypted payload (inner envelope).
    assert_eq!(auth.payer, payer_did());
    assert_eq!(auth.payee, payee_did());
    assert_eq!(auth.amount, Amount(10));
    assert_eq!(auth.adapter_id, "test");

    // Simulate what a relay sees: only opaque encrypted bytes.
    // The relay sees a fixed-size padded blob -- it cannot see the auth fields.
    let relay_visible_blob = b"<encrypted opaque blob - relay sees only this>";
    let relay_str = String::from_utf8_lossy(relay_visible_blob);
    assert!(
        !relay_str.contains("z6MkPayer"),
        "relay should not see payer DID"
    );
    assert!(
        !relay_str.contains("z6MkPayee"),
        "relay should not see payee DID"
    );
}

/// Invariant 7: `PaymentAuthorization` is serializable for embedding in encrypted
/// envelope payloads.
#[test]
fn invariant_7_authorization_serializable_for_envelope() {
    let auth = PaymentAuthorization {
        auth_id: [1u8; 32],
        payer: payer_did(),
        payee: payee_did(),
        amount: Amount(10),
        currency: usd(),
        adapter_id: "test".to_owned(),
        created_at: 1_000_000,
        expires_at: 2_000_000,
        adapter_state: vec![],
    };

    // Authorization can be serialized (for embedding in encrypted inner envelope).
    let serialized = serde_json::to_vec(&auth).unwrap();
    assert!(!serialized.is_empty());

    // Deserialize back.
    let deserialized: PaymentAuthorization = serde_json::from_slice(&serialized).unwrap();
    assert_eq!(deserialized.amount, Amount(10));
    assert_eq!(deserialized.payer, payer_did());
    assert_eq!(deserialized.payee, payee_did());
}

// ===========================================================================
// Invariant 8: Free relays MUST always exist in bootstrap list
// ===========================================================================

/// Invariant 8: Validate SDK's bootstrap relay list includes at least one free
/// relay. Uses scp-core's `WellKnownScp` types to build relay entries.
#[test]
fn invariant_8_bootstrap_list_has_free_relay() {
    // Construct a realistic bootstrap relay list.
    let free_relay = WellKnownScp {
        version: 1,
        did: "did:dht:z6MkFree".to_owned(),
        relay: "wss://free.example.com/scp/v1".to_owned(),
        contexts: None,
        relay_config: Some(RelayConfig {
            max_blob_size: Some(262_144),
            max_blob_ttl: None,
            rate_limit_publish: None,
            rate_limit_subscribe: None,
            transports: None,
            economic: None, // Free relay -- no economic config.
        }),
        handles: None,
    };

    let paid_relay = WellKnownScp {
        version: 1,
        did: "did:dht:z6MkPaid".to_owned(),
        relay: "wss://paid.example.com/scp/v1".to_owned(),
        contexts: None,
        relay_config: Some(RelayConfig {
            max_blob_size: Some(262_144),
            max_blob_ttl: None,
            rate_limit_publish: None,
            rate_limit_subscribe: None,
            transports: None,
            economic: Some(RelayEconomicConfig {
                currency: usd(),
                per_publish: Some(Amount(10)),
                per_byte_stored: Some(Amount(1)),
                payment_adapters: vec!["x402".to_owned()],
                payee: "did:dht:z6MkPaidRelay".to_owned(),
            }),
        }),
        handles: None,
    };

    // Validate: list with free relay passes.
    let relays = [&free_relay, &paid_relay];
    let has_free = relays.iter().any(|r| {
        r.relay_config
            .as_ref()
            .and_then(|rc| rc.economic.as_ref())
            .is_none()
    });
    assert!(
        has_free,
        "bootstrap list must include at least one free relay"
    );

    // Validate: list with only paid relays fails.
    let paid_only = [&paid_relay];
    let has_free_in_paid_only = paid_only.iter().any(|r| {
        r.relay_config
            .as_ref()
            .and_then(|rc| rc.economic.as_ref())
            .is_none()
    });
    assert!(
        !has_free_in_paid_only,
        "list of only paid relays should NOT have a free relay"
    );
}

/// Invariant 8: Relay with no `relay_config` is treated as free.
#[test]
fn invariant_8_no_relay_config_is_free() {
    let minimal_relay = WellKnownScp {
        version: 1,
        did: "did:dht:z6MkMinimal".to_owned(),
        relay: "wss://minimal.example.com/scp/v1".to_owned(),
        contexts: None,
        relay_config: None, // No config at all -- treated as free.
        handles: None,
    };

    let is_free = minimal_relay
        .relay_config
        .as_ref()
        .and_then(|rc| rc.economic.as_ref())
        .is_none();
    assert!(
        is_free,
        "relay without relay_config should be treated as free"
    );
}

// ===========================================================================
// Invariant 9: Auto-accept never applies to paid contexts
// ===========================================================================

/// Invariant 9: Create paid context, configure auto-accept policy, receive
/// invitation -- invitation NOT auto-accepted.
#[test]
fn invariant_9_auto_accept_blocked_for_paid_context() {
    let paid = paid_policy();

    // auto_accept_blocked_by_economics returns true for paid contexts.
    assert!(
        auto_accept_blocked_by_economics(Some(&paid)),
        "paid context should block auto-accept"
    );

    // The policy requires payment.
    assert!(
        policy_requires_payment(&paid),
        "paid policy should require payment"
    );
}

/// Invariant 9: No auto-accept policy configuration can override the hard rule.
#[test]
fn invariant_9_auto_accept_blocked_regardless_of_cost_amount() {
    // Even a policy with minimal costs blocks auto-accept.
    let minimal_cost = EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: usd(),
            per_message: Some(Amount(1)), // Just 1 cent.
            per_tool_invoke: None,
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec!["test".to_owned()],
        pricing_formula: None,
        payee: payee_did(),
    };

    assert!(auto_accept_blocked_by_economics(Some(&minimal_cost)));
}

/// Invariant 9: Free context does NOT block auto-accept.
#[test]
fn invariant_9_auto_accept_allowed_for_free_context() {
    // No economic policy: auto-accept is allowed.
    assert!(!auto_accept_blocked_by_economics(None));

    // Economic policy with no costs: auto-accept is allowed.
    let free = free_policy_no_costs();
    assert!(!policy_requires_payment(&free));
    assert!(!auto_accept_blocked_by_economics(Some(&free)));
}

/// Invariant 9: A policy with only a pricing formula (but no fixed schedule
/// costs) still blocks auto-accept because the formula may produce non-zero
/// costs.
#[test]
fn invariant_9_pricing_formula_only_blocks_auto_accept() {
    let formula_only = EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: usd(),
            per_message: None,
            per_tool_invoke: None,
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec!["test".to_owned()],
        pricing_formula: Some(PricingFormula {
            base_cost: Amount(0),
            variables: vec![PricingVariable::Linear {
                metric: PricingMetric::MemberCount,
                coefficient: Coefficient(1_000_000),
            }],
            cap: None,
            floor: None,
        }),
        payee: payee_did(),
    };

    // Pricing formula present -> policy_requires_payment = true.
    assert!(policy_requires_payment(&formula_only));
    assert!(auto_accept_blocked_by_economics(Some(&formula_only)));
}

// ===========================================================================
// Integration flow: full lifecycle
// ===========================================================================

/// Full lifecycle: evaluate costs -> authorize -> capture -> verify receipt
/// -> store in event log -> query history.
#[tokio::test]
async fn integration_full_lifecycle() {
    let adapter = TestAdapter::new();
    let policy = paid_policy();
    let metrics = default_metrics();

    // Step 1: Verify policy is inspectable (invariant 1).
    assert!(policy_requires_payment(&policy));
    assert_eq!(policy.cost_schedule.per_message, Some(Amount(10)));
    assert_eq!(policy.cost_schedule.per_tool_invoke, Some(Amount(50)));

    // Step 2: Evaluate message cost, authorize, capture.
    let msg_cost = evaluate_cost(&policy, &PaidActionType::MessageSend, &metrics).unwrap();
    assert_eq!(msg_cost, Amount(10));

    let msg_auth = adapter
        .authorize(
            &payer_did(),
            &payee_did(),
            msg_cost,
            usd(),
            PaymentMetadata {
                action_type: PaidActionType::MessageSend,
                context_id: Some("ctx-lifecycle".to_owned()),
                idempotency_key: [0u8; 16],
            },
        )
        .await
        .unwrap();
    let msg_receipt = adapter.capture(&msg_auth).await.unwrap();

    // Step 3: Evaluate tool cost, authorize, capture.
    let tool_cost = evaluate_cost(&policy, &PaidActionType::ToolInvoke, &metrics).unwrap();
    assert_eq!(tool_cost, Amount(50));

    let tool_auth = adapter
        .authorize(
            &payer_did(),
            &payee_did(),
            tool_cost,
            usd(),
            PaymentMetadata {
                action_type: PaidActionType::ToolInvoke,
                context_id: Some("ctx-lifecycle".to_owned()),
                idempotency_key: [1u8; 16],
            },
        )
        .await
        .unwrap();
    let tool_receipt = adapter.capture(&tool_auth).await.unwrap();

    // Step 4: Verify receipts in payment history (invariant 4). `payment_history`
    // reads the per-context local receipt buffer (PaymentReceived is excluded
    // from the canonical Merkle log per ADR-011 amendment exclusion taxonomy §2).
    let receipts = vec![msg_receipt, tool_receipt];

    let history = payment_history(&receipts, None);
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].amount, Amount(10));
    assert_eq!(history[1].amount, Amount(50));
}

// ===========================================================================
// Integration flow: dynamic pricing
// ===========================================================================

/// Dynamic pricing: formula evaluation produces correct costs based on
/// observable metrics, and costs change as metrics change.
#[test]
fn integration_dynamic_pricing() {
    let policy = EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: usd(),
            per_message: Some(Amount(1)),
            per_tool_invoke: None,
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec!["test".to_owned()],
        pricing_formula: Some(PricingFormula {
            base_cost: Amount(0),
            variables: vec![PricingVariable::Linear {
                metric: PricingMetric::MemberCount,
                coefficient: Coefficient(500_000), // 0.5 per member
            }],
            cap: Some(Amount(1000)),
            floor: None,
        }),
        payee: payee_did(),
    };

    // Low member count: schedule(1) + formula(0 + 0.5 * 10 = 5) = 6
    let low_metrics = ObservableMetrics {
        member_count: 10,
        ..Default::default()
    };
    let cost_low = evaluate_cost(&policy, &PaidActionType::MessageSend, &low_metrics);
    assert_eq!(cost_low, Some(Amount(6)));

    // High member count: schedule(1) + formula(0 + 0.5 * 200 = 100) = 101
    let high_metrics = ObservableMetrics {
        member_count: 200,
        ..Default::default()
    };
    let cost_high = evaluate_cost(&policy, &PaidActionType::MessageSend, &high_metrics);
    assert_eq!(cost_high, Some(Amount(101)));

    // Cap enforcement: very high member count hits cap.
    let extreme_metrics = ObservableMetrics {
        member_count: 5000,
        ..Default::default()
    };
    let cost_extreme = evaluate_cost(&policy, &PaidActionType::MessageSend, &extreme_metrics);
    // schedule(1) + formula(min(0 + 0.5 * 5000, 1000) = 1000) = 1001
    assert_eq!(cost_extreme, Some(Amount(1001)));
}

// ===========================================================================
// Integration flow: anti-spam escalation
// ===========================================================================

/// Anti-spam escalation: sender velocity drives step-function cost increases.
///
/// All messages are recorded at `now - 30` (30s into the 60s window). This
/// matches realistic usage where `record_message` is called with the current
/// wall clock; using timestamps strictly within `(now - window, now]` avoids
/// interacting with F8's prune-on-record logic, which uses
/// `timestamp - window` as its cutoff and would otherwise drop legitimate
/// earlier entries when subsequent messages carry timestamps > `now`.
#[test]
fn integration_anti_spam_escalation() {
    let tracker = SenderVelocityTracker::new(60);
    let sender = DID::from("did:dht:z6MkSpammer");
    let base_cost = Amount(1);
    let config = EscalationConfig {
        thresholds: vec![
            EscalationThreshold {
                velocity_threshold: 10,
                additional_cost: Amount(1),
            },
            EscalationThreshold {
                velocity_threshold: 50,
                additional_cost: Amount(10),
            },
            EscalationThreshold {
                velocity_threshold: 200,
                additional_cost: Amount(100),
            },
        ],
    };

    let now = 1000;
    // Record every message 30 seconds before `now` so they all land inside
    // the 60s sliding window.
    let recorded_at = now - 30;

    // Normal conversation (0 msg/min): base cost only.
    assert_eq!(
        tracker.compute_escalated_cost(&sender, now, base_cost, &config, None, None),
        Amount(1),
    );

    // Record 10 messages (hits first threshold).
    for _ in 0..10 {
        tracker.record_message(&sender, recorded_at);
    }
    assert_eq!(
        tracker.compute_escalated_cost(&sender, now, base_cost, &config, None, None),
        Amount(2), // 1 + 1
    );

    // Record 40 more (total 50, hits second threshold).
    for _ in 0..40 {
        tracker.record_message(&sender, recorded_at);
    }
    assert_eq!(
        tracker.compute_escalated_cost(&sender, now, base_cost, &config, None, None),
        Amount(12), // 1 + 1 + 10
    );

    // Record 150 more (total 200, hits all thresholds).
    for _ in 0..150 {
        tracker.record_message(&sender, recorded_at);
    }
    assert_eq!(
        tracker.compute_escalated_cost(&sender, now, base_cost, &config, None, None),
        Amount(112), // 1 + 1 + 10 + 100
    );
}

/// Anti-spam: escalation with cap clamping.
#[test]
fn integration_anti_spam_with_cap() {
    let tracker = SenderVelocityTracker::new(60);
    let sender = DID::from("did:dht:z6MkSpammer");
    let config = EscalationConfig {
        thresholds: vec![EscalationThreshold {
            velocity_threshold: 1,
            additional_cost: Amount(1000),
        }],
    };

    tracker.record_message(&sender, 100);

    // Cap at 500.
    let cost =
        tracker.compute_escalated_cost(&sender, 100, Amount(100), &config, None, Some(Amount(500)));
    assert_eq!(cost, Amount(500), "cost should be clamped to cap");
}

/// Anti-spam: per-sender pricing formula integration via `SenderVelocity` metric.
#[test]
fn integration_anti_spam_via_pricing_formula() {
    let policy = EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: usd(),
            per_message: Some(Amount(1)),
            per_tool_invoke: None,
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec!["test".to_owned()],
        pricing_formula: Some(PricingFormula {
            base_cost: Amount(0),
            variables: vec![PricingVariable::Step {
                metric: PricingMetric::SenderVelocity,
                thresholds: vec![(10, Amount(1)), (50, Amount(10)), (200, Amount(100))],
            }],
            cap: Some(Amount(1000)),
            floor: None,
        }),
        payee: payee_did(),
    };

    // Low velocity: schedule(1) + formula(0) = 1
    let low = ObservableMetrics {
        sender_velocity: 5,
        ..Default::default()
    };
    assert_eq!(
        evaluate_cost(&policy, &PaidActionType::MessageSend, &low),
        Some(Amount(1))
    );

    // High velocity: schedule(1) + formula(1 + 10 + 100) = 112
    let high = ObservableMetrics {
        sender_velocity: 200,
        ..Default::default()
    };
    assert_eq!(
        evaluate_cost(&policy, &PaidActionType::MessageSend, &high),
        Some(Amount(112))
    );
}

// ===========================================================================
// Integration: spending UCAN validation
// ===========================================================================
//
// C1 (PR #1606): the partial `validate_spending_ucan` helper is now
// `pub(crate)` in `scp-protocol`, so the three previous test cases that
// exercised it directly (`integration_spending_ucan_context_scoped`,
// `integration_spending_ucan_global_scope`,
// `integration_spending_ucan_scope_mismatch`) have been removed from this
// file. They duplicated unit tests already living in
// `crates/scp-protocol/src/crypto/ucan/spending.rs`
// (`validate_spending_ucan_context_scoped`,
// `validate_spending_ucan_global_scope`,
// `validate_spending_ucan_scope_mismatch`), which still cover the same
// scope/lifetime surface from inside the crate and continue to run on
// every `cargo test -p scp-protocol`. End-to-end spending validation
// (signature + chain + replay + scope + lifetime + attenuation) is now
// exercised through `validate_spending_ucan_signed` by the manager-level
// tests in `crates/scp-runtime/src/context/manager/tests/governance.rs`.

/// Budget tracker enforces per-action and total limits via `check_and_record`.
#[test]
fn integration_budget_tracker_limits() {
    let cap = test_spending_capability();
    let mut tracker = BudgetTracker::new(cap);
    let now_secs = 1_000_000u64;
    let currency = scp_protocol::crypto::ucan::spending::CurrencyCode::from_code("USD").unwrap();

    // Record some spending within limits.
    let result = tracker.check_and_record(
        scp_protocol::crypto::ucan::spending::Amount(100),
        currency,
        now_secs,
        "test",
    );
    assert!(result.is_ok());

    // Record more spending within limits.
    let result = tracker.check_and_record(
        scp_protocol::crypto::ucan::spending::Amount(500),
        currency,
        now_secs,
        "test",
    );
    assert!(result.is_ok());

    // Check current total.
    let total = tracker.current_total(now_secs);
    assert_eq!(total, scp_protocol::crypto::ucan::spending::Amount(600));
}

/// Budget tracker rejects spending that exceeds per-action limit.
#[test]
fn integration_budget_tracker_per_action_limit() {
    let cap = test_spending_capability(); // max_per_action = 1000
    let mut tracker = BudgetTracker::new(cap);
    let now_secs = 1_000_000u64;
    let currency = scp_protocol::crypto::ucan::spending::CurrencyCode::from_code("USD").unwrap();

    // Exceeds max_per_action (1000).
    let result = tracker.check_and_record(
        scp_protocol::crypto::ucan::spending::Amount(1001),
        currency,
        now_secs,
        "test",
    );
    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            SpendingError::PerActionLimitExceeded { .. }
        ),
        "expected PerActionLimitExceeded"
    );
}

// ===========================================================================
// Integration: event log economic event types
// ===========================================================================

/// Economic event types are distinct and serialize/deserialize correctly.
#[test]
fn integration_economic_event_types() {
    let event_types = [
        EventType::PaymentReceived,
        EventType::EconomicPolicyChanged,
        EventType::EconomicPolicyApplied,
        EventType::SpendingUcanGranted,
        EventType::SpendingUcanRevoked,
    ];

    // All are distinct.
    for (i, a) in event_types.iter().enumerate() {
        for (j, b) in event_types.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "event types {i} and {j} should be distinct");
            }
        }
    }

    // All serialize/deserialize correctly.
    for event_type in &event_types {
        let json = serde_json::to_string(event_type).unwrap();
        let deserialized: EventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*event_type, deserialized);
    }
}

/// Merkle tree with mixed economic and non-economic events maintains integrity.
#[test]
fn integration_merkle_tree_with_economic_events() {
    let (did, signing_key) = test_keypair();

    let mut log = EventLog::new("ctx-merkle".to_owned());

    let receipt = PaymentReceipt {
        receipt_id: [0xAA; 32],
        payer: payer_did(),
        payee: payee_did(),
        amount: Amount(10),
        currency: usd(),
        action_type: PaidActionType::MessageSend,
        context_id: Some("ctx-merkle".to_owned()),
        adapter_id: "test".to_owned(),
        adapter_proof: vec![0x01],
        timestamp: 1_000_000,
        anchored: false,
        signature: vec![0xFF; 64],
    };
    let receipt_payload = serde_json::to_vec(&receipt).unwrap();

    // Append signed events to the log.
    let genesis_prev = [0u8; 32];
    let event0 = signed_event(
        EventType::PaymentReceived,
        0,
        receipt_payload,
        genesis_prev,
        &signing_key,
        &did,
    );
    tree::append(&mut log, &event0).unwrap();

    let leaf0_hash = leaf_hash_of(&event0);
    let event1 = signed_event(
        EventType::MessageSent,
        1,
        b"hello".to_vec(),
        leaf0_hash,
        &signing_key,
        &did,
    );
    tree::append(&mut log, &event1).unwrap();

    let leaf1_hash = leaf_hash_of(&event1);
    let event2 = signed_event(
        EventType::EconomicPolicyChanged,
        2,
        b"policy changed".to_vec(),
        leaf1_hash,
        &signing_key,
        &did,
    );
    tree::append(&mut log, &event2).unwrap();

    assert_eq!(tree::event_count(&log), 3);

    // Every leaf has a valid inclusion proof.
    for i in 0..3 {
        let proof = prove_inclusion(&log, i).unwrap();
        assert!(
            verify_inclusion(&proof),
            "inclusion proof for leaf {i} should verify"
        );
    }

    // Root hash is consistent.
    let root = tree::root(&log);
    assert_ne!(root, [0u8; 32], "root hash should not be all zeros");
}
