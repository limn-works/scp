#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names
)]

//! Integration tests for SCP economic governance types and operations.
//!
//! Tests cover core economic types (`Amount`, `CurrencyCode`, `Coefficient`),
//! cost schedule lookup, pricing formula evaluation, policy lock enforcement,
//! the `TestAdapter` payment flow, velocity tracking, relay pricing, and
//! payment receipt construction.

use scp_core::economy::{
    Amount, Coefficient, CostSchedule, CurrencyCode, EconomicPolicy, PaidActionType,
    PaymentAdapter, PaymentMetadata, PaymentReceipt, PricingFormula, PricingMetric,
    PricingVariable, SenderVelocityTracker,
};
use scp_core::economy::{
    ObservableMetrics, PriceDirection, RelayPricingConfig, adjust_relay_price, check_policy_lock,
    evaluate_formula, lookup_cost,
};
use scp_identity::DID;
use scp_testing::TestAdapter;

/// Helper: create a payer DID.
fn payer() -> DID {
    DID::from("did:dht:z6MkTestPayer")
}

/// Helper: create a payee DID.
fn payee() -> DID {
    DID::from("did:dht:z6MkTestPayee")
}

/// Helper: create a `PaymentMetadata` with a unique idempotency key.
fn make_metadata() -> PaymentMetadata {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut key = [0u8; 16];
    key[..8].copy_from_slice(&counter.to_le_bytes());
    PaymentMetadata {
        action_type: PaidActionType::MessageSend,
        context_id: Some("ctx-test".to_owned()),
        idempotency_key: key,
    }
}

// -----------------------------------------------------------------------
// Test 1: amount_arithmetic
// -----------------------------------------------------------------------

#[tokio::test]
async fn amount_arithmetic() {
    let a = Amount::new(100);
    let b = Amount::new(200);

    // checked_add
    assert_eq!(a.checked_add(b), Some(Amount::new(300)));
    assert_eq!(Amount::new(u64::MAX).checked_add(Amount::new(1)), None);

    // checked_sub
    assert_eq!(b.checked_sub(a), Some(Amount::new(100)));
    assert_eq!(a.checked_sub(b), None);

    // checked_mul
    assert_eq!(a.checked_mul(5), Some(Amount::new(500)));
    assert_eq!(Amount::new(u64::MAX).checked_mul(2), None);

    // saturating_add
    assert_eq!(
        Amount::new(u64::MAX).saturating_add(Amount::new(1)),
        Amount::new(u64::MAX)
    );
    assert_eq!(a.saturating_add(b), Amount::new(300));

    // saturating_sub
    assert_eq!(a.saturating_sub(b), Amount::new(0));
    assert_eq!(b.saturating_sub(a), Amount::new(100));
}

// -----------------------------------------------------------------------
// Test 2: currency_code_roundtrip
// -----------------------------------------------------------------------

#[tokio::test]
async fn currency_code_roundtrip() {
    let usd = CurrencyCode::from("USD");
    assert_eq!(usd.as_str(), "USD");

    let btc = CurrencyCode::from("BTC");
    assert_eq!(btc.as_str(), "BTC");

    let usdc = CurrencyCode::from("USDC");
    assert_eq!(usdc.as_str(), "USDC");

    // Empty code roundtrips
    let empty = CurrencyCode::from("");
    assert_eq!(empty.as_str(), "");

    // Truncation to 4 bytes
    let long = CurrencyCode::from("ABCDE");
    assert_eq!(long.as_str(), "ABCD");

    // Equality
    assert_eq!(CurrencyCode::from("USD"), CurrencyCode::from("USD"));
    assert_ne!(CurrencyCode::from("USD"), CurrencyCode::from("EUR"));
}

// -----------------------------------------------------------------------
// Test 3: coefficient_evaluation
// -----------------------------------------------------------------------

#[tokio::test]
async fn coefficient_evaluation() {
    // 1.5 * 100 = 150
    let coeff = Coefficient::new(1_500_000);
    assert_eq!(coeff.evaluate(100), Some(150));

    // 0.5 * 10 = 5
    let coeff_half = Coefficient::new(500_000);
    assert_eq!(coeff_half.evaluate(10), Some(5));

    // Negative coefficient: -0.5 * 100 = -50
    let coeff_neg = Coefficient::new(-500_000);
    assert_eq!(coeff_neg.evaluate(100), Some(-50));

    // Zero metric always yields 0
    assert_eq!(coeff.evaluate(0), Some(0));

    // Overflow returns None
    let coeff_max = Coefficient::new(i64::MAX);
    assert_eq!(coeff_max.evaluate(2), None);

    // Raw value roundtrip
    assert_eq!(coeff.raw(), 1_500_000);
}

// -----------------------------------------------------------------------
// Test 4: cost_schedule_lookup
// -----------------------------------------------------------------------

#[tokio::test]
async fn cost_schedule_lookup() {
    let schedule = CostSchedule {
        currency: CurrencyCode::from("USD"),
        per_message: Some(Amount::new(1)),
        per_tool_invoke: Some(Amount::new(10)),
        per_join: Some(Amount::new(100)),
        per_period: None,
        per_byte_stored: Some(Amount::new(2)),
    };

    assert_eq!(
        lookup_cost(&schedule, &PaidActionType::MessageSend),
        Some(Amount::new(1))
    );
    assert_eq!(
        lookup_cost(&schedule, &PaidActionType::ToolInvoke),
        Some(Amount::new(10))
    );
    assert_eq!(
        lookup_cost(&schedule, &PaidActionType::ContextJoin),
        Some(Amount::new(100))
    );
    assert_eq!(
        lookup_cost(&schedule, &PaidActionType::SubscriptionPeriod),
        None
    );
    assert_eq!(
        lookup_cost(&schedule, &PaidActionType::ByteStored),
        Some(Amount::new(2))
    );
}

// -----------------------------------------------------------------------
// Test 5: pricing_formula_evaluation
// -----------------------------------------------------------------------

#[tokio::test]
async fn pricing_formula_evaluation() {
    // Formula: base_cost=10, linear MemberCount*1.5, step SenderVelocity
    let formula = PricingFormula {
        base_cost: Amount::new(10),
        variables: vec![
            PricingVariable::Linear {
                metric: PricingMetric::MemberCount,
                coefficient: Coefficient::new(1_500_000), // 1.5
            },
            PricingVariable::Step {
                metric: PricingMetric::SenderVelocity,
                thresholds: vec![(10, Amount::new(5)), (50, Amount::new(50))],
            },
        ],
        cap: Some(Amount::new(1000)),
        floor: Some(Amount::new(5)),
    };

    let metrics = ObservableMetrics {
        member_count: 20,    // 1.5 * 20 = 30
        sender_velocity: 75, // >= 10 -> +5, >= 50 -> +50 => +55
        ..ObservableMetrics::default()
    };

    // 10 (base) + 30 (linear) + 55 (step) = 95
    let result = evaluate_formula(&formula, &metrics);
    assert_eq!(result, Some(Amount::new(95)));

    // Test floor enforcement
    let low_formula = PricingFormula {
        base_cost: Amount::new(1),
        variables: vec![],
        cap: None,
        floor: Some(Amount::new(100)),
    };
    assert_eq!(
        evaluate_formula(&low_formula, &ObservableMetrics::default()),
        Some(Amount::new(100))
    );

    // Test cap enforcement
    let high_formula = PricingFormula {
        base_cost: Amount::new(500),
        variables: vec![PricingVariable::Linear {
            metric: PricingMetric::MemberCount,
            coefficient: Coefficient::new(1_000_000),
        }],
        cap: Some(Amount::new(600)),
        floor: None,
    };
    let high_metrics = ObservableMetrics {
        member_count: 500,
        ..ObservableMetrics::default()
    };
    // 500 + 500 = 1000, capped at 600
    assert_eq!(
        evaluate_formula(&high_formula, &high_metrics),
        Some(Amount::new(600))
    );
}

// -----------------------------------------------------------------------
// Test 6: economic_policy_lock
// -----------------------------------------------------------------------

#[tokio::test]
async fn economic_policy_lock() {
    let unlocked_policy = EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: CurrencyCode::from("USD"),
            per_message: None,
            per_tool_invoke: None,
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec![],
        pricing_formula: None,
        payee: DID::from("did:dht:z6MkPayee"),
    };

    // Unlocked policy allows changes.
    assert!(check_policy_lock(&unlocked_policy).is_ok());

    let locked_policy = EconomicPolicy {
        locked: true,
        ..unlocked_policy
    };

    // Locked policy rejects changes.
    assert!(check_policy_lock(&locked_policy).is_err());
}

// -----------------------------------------------------------------------
// Test 7: test_adapter_payment_flow
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_adapter_payment_flow() {
    let adapter = TestAdapter::new();
    let the_payer = payer();
    let the_payee = payee();
    let currency = CurrencyCode::from("USD");

    // Seed balance for the payer.
    adapter.seed_balance(the_payer.clone(), Amount::new(10_000), currency);

    // Verify initial balance.
    assert_eq!(
        adapter.available_balance(&the_payer, &currency),
        Amount::new(10_000)
    );

    // Authorize payment.
    let auth = adapter
        .authorize(
            &the_payer,
            &the_payee,
            Amount::new(500),
            currency,
            make_metadata(),
        )
        .await
        .unwrap();

    assert_eq!(auth.amount, Amount::new(500));
    assert_eq!(auth.payer, the_payer);
    assert_eq!(auth.payee, the_payee);
    assert_eq!(auth.adapter_id, "test");

    // Balance reduced by hold.
    assert_eq!(
        adapter.available_balance(&the_payer, &currency),
        Amount::new(9_500)
    );

    // Capture the payment.
    let receipt = adapter.capture(&auth).await.unwrap();
    assert_eq!(receipt.amount, Amount::new(500));
    assert_eq!(receipt.payer, the_payer);
    assert_eq!(receipt.payee, the_payee);
    assert_eq!(receipt.adapter_id, "test");

    // Verify the receipt.
    let verification = adapter.verify(&receipt).await.unwrap();
    assert!(verification.valid);
    assert_eq!(verification.verified_amount, Amount::new(500));

    // Payee received funds.
    assert_eq!(
        adapter.available_balance(&the_payee, &currency),
        Amount::new(500)
    );
}

// -----------------------------------------------------------------------
// Test 8: test_adapter_refund
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_adapter_refund() {
    let adapter = TestAdapter::new();
    let the_payer = payer();
    let the_payee = payee();
    let currency = CurrencyCode::from("USD");

    adapter.seed_balance(the_payer.clone(), Amount::new(10_000), currency);

    // Authorize and capture.
    let auth = adapter
        .authorize(
            &the_payer,
            &the_payee,
            Amount::new(1_000),
            currency,
            make_metadata(),
        )
        .await
        .unwrap();
    let receipt = adapter.capture(&auth).await.unwrap();

    // Payee has 1000, payer has 9000.
    assert_eq!(
        adapter.available_balance(&the_payee, &currency),
        Amount::new(1_000)
    );
    assert_eq!(
        adapter.available_balance(&the_payer, &currency),
        Amount::new(9_000)
    );

    // Full refund.
    let refund = adapter.refund(&receipt, None).await.unwrap();
    assert_eq!(refund.refunded_amount, Amount::new(1_000));
    assert_eq!(refund.original_receipt_id, receipt.receipt_id);

    // Balances restored.
    assert_eq!(
        adapter.available_balance(&the_payee, &currency),
        Amount::new(0)
    );
    assert_eq!(
        adapter.available_balance(&the_payer, &currency),
        Amount::new(10_000)
    );
}

// -----------------------------------------------------------------------
// Test 9: velocity_tracker
// -----------------------------------------------------------------------

#[tokio::test]
async fn velocity_tracker() {
    let tracker = SenderVelocityTracker::new(60); // 60-second window
    let sender = DID::from("did:dht:z6MkSpammer");

    // Initially zero.
    assert_eq!(tracker.get_velocity(&sender, 1000), 0);

    // Record 5 messages.
    for i in 0..5 {
        tracker.record_message(&sender, 1000 + i);
    }
    assert_eq!(tracker.get_velocity(&sender, 1005), 5);

    // Messages outside window not counted.
    assert_eq!(tracker.get_velocity(&sender, 1070), 0);

    // Two senders tracked independently.
    let sender2 = DID::from("did:dht:z6MkOther");
    tracker.record_message(&sender2, 1000);
    assert_eq!(tracker.get_velocity(&sender2, 1005), 1);
    // sender's messages are now outside the window at t=1070
    assert_eq!(tracker.get_velocity(&sender, 1070), 0);
}

// -----------------------------------------------------------------------
// Test 10: relay_pricing_adjustment
// -----------------------------------------------------------------------

#[tokio::test]
async fn relay_pricing_adjustment() {
    let config = RelayPricingConfig {
        target_utilization_pct: 50,
        current_base_price: Amount::new(1000),
        max_change_per_mille: 125, // 12.5%
        floor: Amount::new(100),
        cap: Amount::new(10_000),
        target_capacity_per_window: None,
    };

    // Above target: price increases.
    let result = adjust_relay_price(&config, 80);
    assert_eq!(result.direction, PriceDirection::Increased);
    assert!(result.new_base_price > config.current_base_price);
    // max_change = 1000 * 125 / 1000 = 125
    // proportional = 125 * 30 / 100 = 37
    // new_price = 1000 + 37 = 1037
    assert_eq!(result.new_base_price, Amount::new(1037));

    // Below target: price decreases.
    let result_low = adjust_relay_price(&config, 20);
    assert_eq!(result_low.direction, PriceDirection::Decreased);
    // proportional = 125 * 30 / 100 = 37
    // new_price = 1000 - 37 = 963
    assert_eq!(result_low.new_base_price, Amount::new(963));

    // At target: unchanged.
    let result_eq = adjust_relay_price(&config, 50);
    assert_eq!(result_eq.direction, PriceDirection::Unchanged);
    assert_eq!(result_eq.new_base_price, Amount::new(1000));

    // Cap enforcement.
    let high_config = RelayPricingConfig {
        current_base_price: Amount::new(9900),
        target_utilization_pct: config.target_utilization_pct,
        max_change_per_mille: config.max_change_per_mille,
        floor: config.floor,
        cap: config.cap,
        target_capacity_per_window: config.target_capacity_per_window,
    };
    let result_cap = adjust_relay_price(&high_config, 100);
    assert!(result_cap.new_base_price <= Amount::new(10_000));

    // Floor enforcement.
    let low_config = RelayPricingConfig {
        current_base_price: Amount::new(105),
        max_change_per_mille: 500,
        target_utilization_pct: config.target_utilization_pct,
        floor: config.floor,
        cap: config.cap,
        target_capacity_per_window: config.target_capacity_per_window,
    };
    let result_floor = adjust_relay_price(&low_config, 0);
    assert!(result_floor.new_base_price >= Amount::new(100));
}

// -----------------------------------------------------------------------
// Test 11: payment_receipt_fields
// -----------------------------------------------------------------------

#[tokio::test]
async fn payment_receipt_fields() {
    let receipt = PaymentReceipt {
        receipt_id: [0xAA; 32],
        payer: DID::from("did:dht:z6MkAlice"),
        payee: DID::from("did:dht:z6MkBob"),
        amount: Amount::new(42_000),
        currency: CurrencyCode::from("USD"),
        action_type: PaidActionType::ToolInvoke,
        context_id: Some("ctx-123".to_owned()),
        adapter_id: "x402".to_owned(),
        adapter_proof: vec![0x01, 0x02, 0x03],
        timestamp: 1_700_000_000,
        signature: vec![0xFF; 64],
    };

    // Verify all fields are accessible and correct.
    assert_eq!(receipt.receipt_id, [0xAA; 32]);
    assert_eq!(receipt.payer, DID::from("did:dht:z6MkAlice"));
    assert_eq!(receipt.payee, DID::from("did:dht:z6MkBob"));
    assert_eq!(receipt.amount, Amount::new(42_000));
    assert_eq!(receipt.currency, CurrencyCode::from("USD"));
    assert_eq!(receipt.action_type, PaidActionType::ToolInvoke);
    assert_eq!(receipt.context_id.as_deref(), Some("ctx-123"));
    assert_eq!(receipt.adapter_id, "x402");
    assert_eq!(receipt.adapter_proof, vec![0x01, 0x02, 0x03]);
    assert_eq!(receipt.timestamp, 1_700_000_000);
    assert_eq!(receipt.signature.len(), 64);

    // Serde roundtrip.
    let json = serde_json::to_string(&receipt).unwrap();
    let deserialized: PaymentReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt.receipt_id, deserialized.receipt_id);
    assert_eq!(receipt.amount, deserialized.amount);
    assert_eq!(receipt.payer, deserialized.payer);
    assert_eq!(receipt.payee, deserialized.payee);
    assert_eq!(receipt.currency, deserialized.currency);
    assert_eq!(receipt.action_type, deserialized.action_type);
    assert_eq!(receipt.context_id, deserialized.context_id);
    assert_eq!(receipt.adapter_id, deserialized.adapter_id);
    assert_eq!(receipt.adapter_proof, deserialized.adapter_proof);
    assert_eq!(receipt.timestamp, deserialized.timestamp);
    assert_eq!(receipt.signature, deserialized.signature);
}
