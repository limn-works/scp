//! Core economic types for SCP economic governance.
//!
//! Defines the foundational types used across all economic operations in SCP:
//! amounts, currency codes, coefficients, cost schedules, pricing formulas,
//! and economic policy. All types use integer arithmetic exclusively -- no
//! IEEE 754 floating-point -- to guarantee cross-party determinism.
//!
//! See spec section 19.1.1 (core types), 19.3 (economic policy), and
//! 19.4 (dynamic pricing). See ADR-033 in `.docs/adrs/phase-3.md`.

use serde::{Deserialize, Serialize};

use scp_primitives::DID;

// ---------------------------------------------------------------------------
// Amount
// ---------------------------------------------------------------------------

/// Amount in the smallest currency unit. USD: cents (1 USD = 100).
/// BTC: satoshis (1 BTC = `100_000_000`).
///
/// Always integer -- no floating-point in economic calculations. Cross-party
/// determinism guaranteed: both payer and receiver evaluate the same `Amount`
/// from the same inputs with identical results.
///
/// See spec section 19.1.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Amount(pub u64);

impl Amount {
    /// Creates a new `Amount` with the given value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Checked addition. Returns `None` on overflow.
    #[must_use]
    pub const fn checked_add(self, other: Self) -> Option<Self> {
        match self.0.checked_add(other.0) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// Checked subtraction. Returns `None` on underflow.
    #[must_use]
    pub const fn checked_sub(self, other: Self) -> Option<Self> {
        match self.0.checked_sub(other.0) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// Checked multiplication by a scalar. Returns `None` on overflow.
    #[must_use]
    pub const fn checked_mul(self, factor: u64) -> Option<Self> {
        match self.0.checked_mul(factor) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// Saturating addition. Returns `u64::MAX` on overflow.
    #[must_use]
    pub const fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    /// Saturating subtraction. Returns `0` on underflow.
    #[must_use]
    pub const fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

impl std::fmt::Display for Amount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// CurrencyCode
// ---------------------------------------------------------------------------

/// ISO 4217 currency code (USD, EUR) or protocol-defined code (BTC, SAT, SOL,
/// USDC). Stored as a 3-4 character code, null-padded to 4 bytes.
///
/// See spec section 19.1.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CurrencyCode(pub [u8; 4]);

impl CurrencyCode {
    /// Creates a `CurrencyCode` from a byte array.
    #[must_use]
    pub const fn new(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    /// Returns the code as a string, trimming null bytes.
    #[must_use]
    pub fn as_str(&self) -> &str {
        let len = self.0.iter().position(|&b| b == 0).unwrap_or(4);
        // SAFETY: CurrencyCode is only constructed from valid ASCII via
        // From<&str>, so this is always valid UTF-8. For codes constructed
        // directly from bytes, callers are responsible for ensuring ASCII.
        // We use from_utf8 which returns a Result, and fall back to empty.
        std::str::from_utf8(&self.0[..len]).unwrap_or("")
    }
}

impl From<&str> for CurrencyCode {
    /// Creates a `CurrencyCode` from a string slice. The string is truncated
    /// to 4 bytes and null-padded if shorter.
    fn from(s: &str) -> Self {
        let bytes = s.as_bytes();
        let mut code = [0u8; 4];
        let len = bytes.len().min(4);
        code[..len].copy_from_slice(&bytes[..len]);
        Self(code)
    }
}

impl std::fmt::Display for CurrencyCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Coefficient
// ---------------------------------------------------------------------------

/// Fixed-point coefficient with 6 decimal places of precision.
///
/// Value = raw / `1_000_000`. Example: `1_500_000` = 1.5, 100 = 0.0001.
/// Used in pricing formulas where fractional multipliers are needed.
/// Both sides evaluate identically -- no IEEE 754 variance.
///
/// See spec section 19.1.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Coefficient(pub i64);

/// The fixed-point scale factor for [`Coefficient`]: `1_000_000`.
pub const COEFFICIENT_SCALE: i64 = 1_000_000;

impl Coefficient {
    /// Creates a new `Coefficient` with the given raw value.
    #[must_use]
    pub const fn new(raw: i64) -> Self {
        Self(raw)
    }

    /// Returns the raw fixed-point value.
    #[must_use]
    pub const fn raw(self) -> i64 {
        self.0
    }

    /// Evaluates this coefficient against an integer metric value.
    ///
    /// Computes `(self.0 * metric_value) / 1_000_000` using checked
    /// arithmetic. Returns `None` on overflow.
    #[must_use]
    pub const fn evaluate(self, metric_value: u64) -> Option<i64> {
        // Cast metric_value to i64 first to avoid sign issues.
        // If metric_value > i64::MAX, that's an overflow.
        if metric_value > i64::MAX as u64 {
            return None;
        }
        let mv = metric_value.cast_signed();
        match self.0.checked_mul(mv) {
            Some(product) => Some(product / COEFFICIENT_SCALE),
            None => None,
        }
    }
}

impl std::fmt::Display for Coefficient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let negative = self.0 < 0;
        let abs_val = self.0.unsigned_abs();
        let whole = abs_val / COEFFICIENT_SCALE as u64;
        let frac = abs_val % COEFFICIENT_SCALE as u64;
        if negative {
            write!(f, "-{whole}.{frac:06}")
        } else {
            write!(f, "{whole}.{frac:06}")
        }
    }
}

// ---------------------------------------------------------------------------
// SubscriptionPeriod
// ---------------------------------------------------------------------------

/// Subscription period for recurring payments.
///
/// See spec section 19.1.1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubscriptionPeriod {
    /// Daily billing cycle.
    Daily,
    /// Weekly billing cycle.
    Weekly,
    /// Monthly billing cycle.
    Monthly,
    /// Custom billing cycle with duration in seconds.
    Custom {
        /// Duration of the custom period in seconds.
        seconds: u64,
    },
}

// ---------------------------------------------------------------------------
// SubscriptionCost
// ---------------------------------------------------------------------------

/// Subscription cost for recurring payments.
///
/// See spec section 19.1.1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionCost {
    /// The amount charged per period.
    pub amount: Amount,
    /// The billing period.
    pub period: SubscriptionPeriod,
    /// The currency for this subscription (may differ from context currency).
    pub currency: CurrencyCode,
}

// ---------------------------------------------------------------------------
// PaymentAdapterRef
// ---------------------------------------------------------------------------

/// String identifier for a payment adapter accepted by a context or relay.
///
/// Matches `PaymentAdapter::adapter_id()`. Example values: `"x402"`,
/// `"lightning"`, `"spl"`, `"stripe"`.
///
/// See spec section 19.1.1.
pub type PaymentAdapterRef = String;

// ---------------------------------------------------------------------------
// PaidActionType
// ---------------------------------------------------------------------------

/// Action type for which a payment is made.
///
/// Used in `PaymentReceipt` and cost
/// estimation to identify the category of paid action.
///
/// See spec section 19.1.1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaidActionType {
    /// Sending a message in a context.
    MessageSend,
    /// Invoking a tool.
    ToolInvoke,
    /// Joining a context.
    ContextJoin,
    /// A subscription period payment.
    SubscriptionPeriod,
    /// Per-byte storage cost.
    ByteStored,
}

// ---------------------------------------------------------------------------
// PricingMetric
// ---------------------------------------------------------------------------

/// Observable metric used in dynamic pricing formulas.
///
/// Both payer and receiver evaluate the same metric from their observable
/// state. See spec section 19.4.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PricingMetric {
    /// Messages per minute in this context.
    ContextMessageRate,
    /// Current member count.
    MemberCount,
    /// Relay-level queue depth (relay-level pricing only).
    RelayQueueDepth,
    /// UTC hour (0-23), enables off-peak pricing.
    TimeOfDay,
    /// Sender's messages in sliding window (anti-spam).
    SenderVelocity,
    /// Context storage usage in bytes.
    StorageUsage,
}

// ---------------------------------------------------------------------------
// PricingVariable
// ---------------------------------------------------------------------------

/// A variable component in a pricing formula.
///
/// See spec section 19.4.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PricingVariable {
    /// Linear multiplier: cost += (coefficient.0 * `metric_value`) / `1_000_000`.
    ///
    /// [`Coefficient`] is fixed-point with 6 decimal places (section 19.1.1).
    Linear {
        /// The metric to observe.
        metric: PricingMetric,
        /// The fixed-point multiplier.
        coefficient: Coefficient,
    },
    /// Step function: cost += additional amount when metric value exceeds
    /// threshold. Thresholds are integer metric values (messages/min, member
    /// count, bytes, etc.).
    Step {
        /// The metric to observe.
        metric: PricingMetric,
        /// Threshold-amount pairs. When the metric value exceeds a threshold,
        /// the corresponding amount is added.
        thresholds: Vec<(u64, Amount)>,
    },
}

// ---------------------------------------------------------------------------
// PricingFormula
// ---------------------------------------------------------------------------

/// Formula-based dynamic pricing configuration.
///
/// Both sides evaluate the same formula against observable metrics --
/// deterministic, no external dependency, no new trust surface. Directly
/// inspired by EIP-1559.
///
/// See spec section 19.4.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PricingFormula {
    /// Base cost before variable adjustments.
    pub base_cost: Amount,
    /// Variable pricing components.
    pub variables: Vec<PricingVariable>,
    /// Maximum cost regardless of formula result.
    pub cap: Option<Amount>,
    /// Minimum cost regardless of formula result.
    pub floor: Option<Amount>,
}

// ---------------------------------------------------------------------------
// CostSchedule
// ---------------------------------------------------------------------------

/// Cost schedule for a context's economic policy.
///
/// Defines per-action costs. All `Amount` fields use the currency specified
/// in `currency`. The `per_period` field carries its own currency for
/// flexibility.
///
/// See spec section 19.3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CostSchedule {
    /// Currency for all `Amount` fields in this schedule.
    pub currency: CurrencyCode,
    /// Cost per message sent.
    pub per_message: Option<Amount>,
    /// Default cost per tool invocation (tools without their own cost).
    pub per_tool_invoke: Option<Amount>,
    /// One-time membership cost.
    pub per_join: Option<Amount>,
    /// Recurring subscription cost (carries its own currency).
    pub per_period: Option<SubscriptionCost>,
    /// Cost per byte stored.
    pub per_byte_stored: Option<Amount>,
}

// ---------------------------------------------------------------------------
// EconomicPolicy
// ---------------------------------------------------------------------------

/// Economic policy for a context, governing costs and payment methods.
///
/// Economic policy is a context setting governed through the context's
/// governance model (spec section 5.9). Mutable by default -- changes go
/// through governance, are logged in the event log, and take effect after a
/// notification period. The creator may lock economic policy at creation to
/// make it immutable.
///
/// See spec section 19.3 and ADR-033.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EconomicPolicy {
    /// If `true`, economic policy is immutable (cannot be changed through
    /// governance). If `false` (default), changes go through governance.
    /// The lock is itself immutable -- once locked, cannot unlock.
    pub locked: bool,
    /// The cost schedule defining per-action costs.
    pub cost_schedule: CostSchedule,
    /// Accepted payment adapter identifiers.
    pub payment_adapters: Vec<PaymentAdapterRef>,
    /// Optional dynamic pricing formula (section 19.4).
    pub pricing_formula: Option<PricingFormula>,
    /// The DID that receives payments.
    pub payee: DID,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // --- Amount arithmetic ---

    #[test]
    fn amount_checked_add_success() {
        let a = Amount(100);
        let b = Amount(200);
        assert_eq!(a.checked_add(b), Some(Amount(300)));
    }

    #[test]
    fn amount_checked_add_overflow() {
        let a = Amount(u64::MAX);
        let b = Amount(1);
        assert_eq!(a.checked_add(b), None);
    }

    #[test]
    fn amount_checked_sub_success() {
        let a = Amount(300);
        let b = Amount(100);
        assert_eq!(a.checked_sub(b), Some(Amount(200)));
    }

    #[test]
    fn amount_checked_sub_underflow() {
        let a = Amount(100);
        let b = Amount(200);
        assert_eq!(a.checked_sub(b), None);
    }

    #[test]
    fn amount_checked_mul_success() {
        let a = Amount(100);
        assert_eq!(a.checked_mul(5), Some(Amount(500)));
    }

    #[test]
    fn amount_checked_mul_overflow() {
        let a = Amount(u64::MAX);
        assert_eq!(a.checked_mul(2), None);
    }

    #[test]
    fn amount_saturating_add() {
        assert_eq!(Amount(u64::MAX).saturating_add(Amount(1)), Amount(u64::MAX));
        assert_eq!(Amount(100).saturating_add(Amount(200)), Amount(300));
    }

    #[test]
    fn amount_saturating_sub() {
        assert_eq!(Amount(100).saturating_sub(Amount(200)), Amount(0));
        assert_eq!(Amount(300).saturating_sub(Amount(100)), Amount(200));
    }

    #[test]
    fn amount_ordering() {
        assert!(Amount(100) < Amount(200));
        assert!(Amount(200) > Amount(100));
        assert_eq!(Amount(100), Amount(100));
    }

    #[test]
    fn amount_display() {
        assert_eq!(format!("{}", Amount(42)), "42");
    }

    // --- Coefficient evaluation ---

    #[test]
    fn coefficient_evaluate_positive() {
        // 1.5 * 100 = 150
        let coeff = Coefficient(1_500_000); // 1.5
        assert_eq!(coeff.evaluate(100), Some(150));
    }

    #[test]
    fn coefficient_evaluate_fractional() {
        // 0.5 * 10 = 5
        let coeff = Coefficient(500_000); // 0.5
        assert_eq!(coeff.evaluate(10), Some(5));
    }

    #[test]
    fn coefficient_evaluate_small() {
        // 0.0001 * 1000 = 0 (integer truncation)
        let coeff = Coefficient(100); // 0.0001
        assert_eq!(coeff.evaluate(1000), Some(0));
    }

    #[test]
    fn coefficient_evaluate_negative() {
        // -0.5 * 100 = -50
        let coeff = Coefficient(-500_000);
        assert_eq!(coeff.evaluate(100), Some(-50));
    }

    #[test]
    fn coefficient_evaluate_zero_metric() {
        let coeff = Coefficient(1_500_000);
        assert_eq!(coeff.evaluate(0), Some(0));
    }

    #[test]
    fn coefficient_evaluate_overflow() {
        let coeff = Coefficient(i64::MAX);
        assert_eq!(coeff.evaluate(2), None);
    }

    #[test]
    fn coefficient_display() {
        assert_eq!(format!("{}", Coefficient(1_500_000)), "1.500000");
        assert_eq!(format!("{}", Coefficient(100)), "0.000100");
        assert_eq!(format!("{}", Coefficient(-500_000)), "-0.500000");
        assert_eq!(format!("{}", Coefficient(-1_500_000)), "-1.500000");
        assert_eq!(format!("{}", Coefficient(0)), "0.000000");
    }

    // --- CurrencyCode string roundtrip ---

    #[test]
    fn currency_code_from_str_3char() {
        let code = CurrencyCode::from("USD");
        assert_eq!(code.as_str(), "USD");
        assert_eq!(code.0, [b'U', b'S', b'D', 0]);
    }

    #[test]
    fn currency_code_from_str_4char() {
        let code = CurrencyCode::from("USDC");
        assert_eq!(code.as_str(), "USDC");
        assert_eq!(code.0, [b'U', b'S', b'D', b'C']);
    }

    #[test]
    fn currency_code_from_str_truncates() {
        let code = CurrencyCode::from("ABCDE");
        assert_eq!(code.as_str(), "ABCD");
    }

    #[test]
    fn currency_code_from_str_empty() {
        let code = CurrencyCode::from("");
        assert_eq!(code.as_str(), "");
        assert_eq!(code.0, [0, 0, 0, 0]);
    }

    #[test]
    fn currency_code_display() {
        let code = CurrencyCode::from("BTC");
        assert_eq!(format!("{code}"), "BTC");
    }

    #[test]
    fn currency_code_equality() {
        assert_eq!(CurrencyCode::from("USD"), CurrencyCode::from("USD"));
        assert_ne!(CurrencyCode::from("USD"), CurrencyCode::from("EUR"));
    }

    // --- Serde roundtrip tests ---

    #[test]
    fn amount_serde_roundtrip() {
        let amount = Amount(42_000);
        let json = serde_json::to_string(&amount).unwrap();
        let deserialized: Amount = serde_json::from_str(&json).unwrap();
        assert_eq!(amount, deserialized);
    }

    #[test]
    fn currency_code_serde_roundtrip() {
        let code = CurrencyCode::from("USD");
        let json = serde_json::to_string(&code).unwrap();
        let deserialized: CurrencyCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, deserialized);
    }

    #[test]
    fn coefficient_serde_roundtrip() {
        let coeff = Coefficient(1_500_000);
        let json = serde_json::to_string(&coeff).unwrap();
        let deserialized: Coefficient = serde_json::from_str(&json).unwrap();
        assert_eq!(coeff, deserialized);
    }

    #[test]
    fn subscription_period_serde_roundtrip() {
        let periods = [
            SubscriptionPeriod::Daily,
            SubscriptionPeriod::Weekly,
            SubscriptionPeriod::Monthly,
            SubscriptionPeriod::Custom { seconds: 86400 },
        ];
        for period in &periods {
            let json = serde_json::to_string(period).unwrap();
            let deserialized: SubscriptionPeriod = serde_json::from_str(&json).unwrap();
            assert_eq!(*period, deserialized);
        }
    }

    #[test]
    fn pricing_metric_serde_roundtrip() {
        let metrics = [
            PricingMetric::ContextMessageRate,
            PricingMetric::MemberCount,
            PricingMetric::RelayQueueDepth,
            PricingMetric::TimeOfDay,
            PricingMetric::SenderVelocity,
            PricingMetric::StorageUsage,
        ];
        for metric in &metrics {
            let json = serde_json::to_string(metric).unwrap();
            let deserialized: PricingMetric = serde_json::from_str(&json).unwrap();
            assert_eq!(*metric, deserialized);
        }
    }

    #[test]
    fn economic_policy_serde_roundtrip() {
        let policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: CurrencyCode::from("USD"),
                per_message: Some(Amount(1)),
                per_tool_invoke: Some(Amount(10)),
                per_join: Some(Amount(100)),
                per_period: Some(SubscriptionCost {
                    amount: Amount(999),
                    period: SubscriptionPeriod::Monthly,
                    currency: CurrencyCode::from("USD"),
                }),
                per_byte_stored: Some(Amount(1)),
            },
            payment_adapters: vec!["x402".to_owned(), "lightning".to_owned()],
            pricing_formula: Some(PricingFormula {
                base_cost: Amount(10),
                variables: vec![
                    PricingVariable::Linear {
                        metric: PricingMetric::ContextMessageRate,
                        coefficient: Coefficient(500_000),
                    },
                    PricingVariable::Step {
                        metric: PricingMetric::SenderVelocity,
                        thresholds: vec![(10, Amount(1)), (50, Amount(10)), (200, Amount(100))],
                    },
                ],
                cap: Some(Amount(1000)),
                floor: Some(Amount(1)),
            }),
            payee: DID::from("did:dht:z6MkTestPayee"),
        };

        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: EconomicPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, deserialized);
    }

    #[test]
    fn economic_policy_locked_serde_roundtrip() {
        let policy = EconomicPolicy {
            locked: true,
            cost_schedule: CostSchedule {
                currency: CurrencyCode::from("BTC"),
                per_message: None,
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec![],
            pricing_formula: None,
            payee: DID::from("did:dht:z6MkFreeRelay"),
        };

        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: EconomicPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, deserialized);
    }

    #[test]
    fn pricing_formula_serde_roundtrip() {
        let formula = PricingFormula {
            base_cost: Amount(100),
            variables: vec![PricingVariable::Linear {
                metric: PricingMetric::MemberCount,
                coefficient: Coefficient(1_000_000),
            }],
            cap: Some(Amount(10_000)),
            floor: None,
        };
        let json = serde_json::to_string(&formula).unwrap();
        let deserialized: PricingFormula = serde_json::from_str(&json).unwrap();
        assert_eq!(formula, deserialized);
    }

    // --- No f64 compile-time guarantee ---
    // The types themselves contain no f64. This test verifies the sizes make
    // sense (Amount is u64, Coefficient is i64).

    #[test]
    fn amount_is_8_bytes() {
        assert_eq!(std::mem::size_of::<Amount>(), 8);
    }

    #[test]
    fn coefficient_is_8_bytes() {
        assert_eq!(std::mem::size_of::<Coefficient>(), 8);
    }

    #[test]
    fn currency_code_is_4_bytes() {
        assert_eq!(std::mem::size_of::<CurrencyCode>(), 4);
    }
}
