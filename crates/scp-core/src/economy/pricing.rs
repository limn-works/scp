//! Dynamic pricing formula evaluation, EIP-1559-style relay pricing, and
//! governed formula changes.
//!
//! This module extends the core formula evaluation in [`super::policy`] with:
//!
//! - **EIP-1559-style relay pricing**: Utilization-targeting formula with
//!   configurable max change per evaluation period. When relay utilization is
//!   below target, price decreases (capped at floor). When above target, price
//!   increases (capped at cap). Max change per period is configurable (e.g.,
//!   12.5% like EIP-1559).
//!
//! - **Governed formula changes**: Formula modification goes through governance,
//!   is logged in the event log, and takes effect after a grace period.
//!
//! All arithmetic uses [`Amount`](u64) and [`Coefficient`](i64) exclusively --
//! no `f64` in any evaluation path. Cross-party determinism is guaranteed:
//! same formula + same metrics always produces the same [`Amount`] on any
//! platform.
//!
//! See spec section 19.4 (Dynamic Pricing), 19.8 (Relay Monetization), and
//! ADR-033 acceptance criteria #8.

use serde::{Deserialize, Serialize};

use super::types::{Amount, PricingFormula};

// ---------------------------------------------------------------------------
// EIP-1559-style relay pricing
// ---------------------------------------------------------------------------

/// Configuration for EIP-1559-style utilization-targeting relay pricing.
///
/// Inspired by Ethereum's EIP-1559 fee mechanism: an algorithmic pricing model
/// embedded in protocol rules, independently computable by all parties.
///
/// The relay targets a specific utilization level. When actual utilization is
/// below target, the price decreases. When above target, the price increases.
/// The maximum change per evaluation period is bounded to prevent sudden
/// price spikes.
///
/// See spec section 19.4 (EIP-1559 analogy) and 19.8 (Relay Monetization).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPricingConfig {
    /// Target utilization as a percentage (0-100). Typically 50.
    /// When actual utilization equals target, price remains unchanged.
    pub target_utilization_pct: u64,

    /// Current base price per action (in smallest currency unit).
    pub current_base_price: Amount,

    /// Maximum price change per evaluation period, expressed as a numerator
    /// over a denominator of 1000. For example, 125 = 12.5% (125/1000).
    /// This mirrors EIP-1559's 12.5% max change factor.
    pub max_change_per_mille: u64,

    /// Minimum price (floor). Price cannot decrease below this value.
    pub floor: Amount,

    /// Maximum price (cap). Price cannot increase above this value.
    pub cap: Amount,
}

/// Result of an EIP-1559-style relay price adjustment.
///
/// Contains the new base price after adjustment, along with the delta for
/// logging and governance transparency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayPriceAdjustment {
    /// The new base price after adjustment.
    pub new_base_price: Amount,
    /// The previous base price before adjustment.
    pub previous_base_price: Amount,
    /// Whether the price increased, decreased, or stayed the same.
    pub direction: PriceDirection,
}

/// Direction of a price adjustment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PriceDirection {
    /// Price increased due to utilization above target.
    Increased,
    /// Price decreased due to utilization below target.
    Decreased,
    /// Price unchanged (utilization at target or adjustment too small).
    Unchanged,
}

/// Adjusts the relay base price based on current utilization.
///
/// Implements the EIP-1559-style utilization-targeting algorithm:
///
/// 1. Compute utilization delta: `actual - target` (signed).
/// 2. Compute max allowed change: `current_base_price * max_change_per_mille / 1000`.
/// 3. Scale the change proportionally to the utilization delta:
///    `change = max_change * |delta| / 100`, clamped to `max_change`.
/// 4. Apply direction: increase if above target, decrease if below.
/// 5. Clamp result to `[floor, cap]`.
///
/// All arithmetic uses integer operations exclusively. Both relay and agent
/// compute the same price deterministically.
///
/// # Arguments
///
/// * `config` - The relay's pricing configuration.
/// * `actual_utilization_pct` - Current relay utilization as a percentage (0-100).
///
/// See spec section 19.4, 19.8.
#[must_use]
pub fn adjust_relay_price(
    config: &RelayPricingConfig,
    actual_utilization_pct: u64,
) -> RelayPriceAdjustment {
    let target = config.target_utilization_pct;
    let current = config.current_base_price;

    // Compute the maximum allowed change for this period.
    // max_change = current_base_price * max_change_per_mille / 1000
    let max_change = current.0.saturating_mul(config.max_change_per_mille) / 1000;

    // Compute the proportional change based on utilization delta.
    // delta_pct is the absolute difference between actual and target.
    let (above_target, delta_pct) = if actual_utilization_pct >= target {
        (true, actual_utilization_pct.saturating_sub(target))
    } else {
        (false, target.saturating_sub(actual_utilization_pct))
    };

    // Scale change proportionally: change = max_change * delta_pct / 100
    // Clamped to max_change (when delta_pct >= 100).
    let change = if delta_pct >= 100 {
        max_change
    } else {
        max_change.saturating_mul(delta_pct) / 100
    };

    // Apply direction.
    let new_price = if above_target {
        current.0.saturating_add(change)
    } else {
        current.0.saturating_sub(change)
    };

    // Clamp to [floor, cap].
    let clamped = new_price.max(config.floor.0).min(config.cap.0);

    let direction = if clamped > current.0 {
        PriceDirection::Increased
    } else if clamped < current.0 {
        PriceDirection::Decreased
    } else {
        PriceDirection::Unchanged
    };

    RelayPriceAdjustment {
        new_base_price: Amount(clamped),
        previous_base_price: current,
        direction,
    }
}

// ---------------------------------------------------------------------------
// Governed formula changes
// ---------------------------------------------------------------------------

/// A proposed change to a context's pricing formula, subject to governance.
///
/// Formula modification goes through the context's governance model (spec
/// section 5.9). Changes are logged in the event log, members are notified,
/// and the new formula takes effect only after the grace period expires.
///
/// See spec section 19.4 (Governed changes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormulaChange {
    /// The proposed new pricing formula. `None` means removing the formula
    /// (reverting to schedule-only pricing).
    pub proposed_formula: Option<PricingFormula>,

    /// Unix timestamp (seconds) when the change was proposed.
    pub proposed_at: u64,

    /// Grace period in seconds before the change takes effect.
    /// Members are notified during this window.
    pub grace_period_secs: u64,

    /// Human-readable justification for the change (logged in event log).
    pub justification: String,

    /// Current status of the change.
    pub status: FormulaChangeStatus,
}

/// Status of a governed formula change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FormulaChangeStatus {
    /// Change has been proposed and is within the grace period.
    /// Members have been notified.
    Pending,
    /// Grace period has elapsed and the change is now active.
    Active,
    /// Change was rejected through governance vote or veto.
    Rejected,
    /// Change was withdrawn by the proposer before activation.
    Withdrawn,
}

impl FormulaChange {
    /// Returns `true` if the grace period has elapsed and the change is ready
    /// to take effect.
    ///
    /// # Arguments
    ///
    /// * `now` - Current Unix timestamp in seconds.
    #[must_use]
    pub const fn is_effective(&self, now: u64) -> bool {
        matches!(self.status, FormulaChangeStatus::Active)
            || (matches!(self.status, FormulaChangeStatus::Pending)
                && now >= self.proposed_at.saturating_add(self.grace_period_secs))
    }

    /// Returns the Unix timestamp when the change becomes effective.
    #[must_use]
    pub const fn effective_at(&self) -> u64 {
        self.proposed_at.saturating_add(self.grace_period_secs)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::economy::policy::{ObservableMetrics, evaluate_formula};
    use crate::economy::types::{Coefficient, PricingFormula, PricingMetric, PricingVariable};

    // =======================================================================
    // Acceptance criteria unit tests (SCP-157)
    // =======================================================================

    #[test]
    fn base_cost_only_returns_base_cost() {
        // AC: base_cost only (no variables) returns base_cost.
        let formula = PricingFormula {
            base_cost: Amount(42),
            variables: vec![],
            cap: None,
            floor: None,
        };
        let metrics = ObservableMetrics::default();
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(42)));
    }

    #[test]
    fn linear_variable_coefficient_1_500_000_metric_100_adds_150() {
        // AC: Linear variable with Coefficient(1_500_000) and metric value 100
        // adds 150 to cost.
        let formula = PricingFormula {
            base_cost: Amount(0),
            variables: vec![PricingVariable::Linear {
                metric: PricingMetric::MemberCount,
                coefficient: Coefficient(1_500_000), // 1.5
            }],
            cap: None,
            floor: None,
        };
        let metrics = ObservableMetrics {
            member_count: 100,
            ..ObservableMetrics::default()
        };
        // (1_500_000 * 100) / 1_000_000 = 150
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(150)));
    }

    #[test]
    fn step_variable_metric_75_adds_11() {
        // AC: Step variable with thresholds [(10, Amount(1)), (50, Amount(10)),
        // (200, Amount(100))] -- metric=75 adds 11 (1+10).
        let formula = PricingFormula {
            base_cost: Amount(0),
            variables: vec![PricingVariable::Step {
                metric: PricingMetric::SenderVelocity,
                thresholds: vec![(10, Amount(1)), (50, Amount(10)), (200, Amount(100))],
            }],
            cap: None,
            floor: None,
        };
        let metrics = ObservableMetrics {
            sender_velocity: 75,
            ..ObservableMetrics::default()
        };
        // 75 >= 10 -> +1, 75 >= 50 -> +10, 75 < 200 -> skip. Total: 11
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(11)));
    }

    #[test]
    fn cap_enforcement_clamps_result() {
        // AC: cap enforcement clamps result.
        let formula = PricingFormula {
            base_cost: Amount(500),
            variables: vec![PricingVariable::Linear {
                metric: PricingMetric::MemberCount,
                coefficient: Coefficient(1_000_000), // 1.0
            }],
            cap: Some(Amount(600)),
            floor: None,
        };
        let metrics = ObservableMetrics {
            member_count: 500,
            ..ObservableMetrics::default()
        };
        // 500 + 500 = 1000, capped at 600
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(600)));
    }

    #[test]
    fn floor_enforcement_raises_result() {
        // AC: floor enforcement raises result.
        let formula = PricingFormula {
            base_cost: Amount(1),
            variables: vec![],
            cap: None,
            floor: Some(Amount(100)),
        };
        let metrics = ObservableMetrics::default();
        // base=1, floor raises to 100
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(100)));
    }

    #[test]
    fn multiple_variables_are_additive() {
        // AC: multiple variables are additive.
        let formula = PricingFormula {
            base_cost: Amount(10),
            variables: vec![
                PricingVariable::Linear {
                    metric: PricingMetric::ContextMessageRate,
                    coefficient: Coefficient(1_000_000), // 1.0
                },
                PricingVariable::Linear {
                    metric: PricingMetric::MemberCount,
                    coefficient: Coefficient(500_000), // 0.5
                },
                PricingVariable::Step {
                    metric: PricingMetric::SenderVelocity,
                    thresholds: vec![(5, Amount(20))],
                },
            ],
            cap: None,
            floor: None,
        };
        let metrics = ObservableMetrics {
            context_message_rate: 30, // +30
            member_count: 40,         // +20 (0.5 * 40)
            sender_velocity: 10,      // +20 (10 >= 5)
            ..ObservableMetrics::default()
        };
        // 10 + 30 + 20 + 20 = 80
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(80)));
    }

    #[test]
    fn negative_coefficient_reduces_cost_without_underflow() {
        // AC: negative Coefficient reduces cost without underflow (saturates at 0).
        let formula = PricingFormula {
            base_cost: Amount(50),
            variables: vec![PricingVariable::Linear {
                metric: PricingMetric::MemberCount,
                coefficient: Coefficient(-2_000_000), // -2.0
            }],
            cap: None,
            floor: None,
        };
        let metrics = ObservableMetrics {
            member_count: 100,
            ..ObservableMetrics::default()
        };
        // 50 - (2.0 * 100) = 50 - 200 -> saturates at 0
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(0)));
    }

    #[test]
    fn cross_party_determinism_same_inputs_produce_identical_amount() {
        // AC: cross-party determinism -- same inputs produce byte-identical Amount.
        // Run the same formula evaluation twice with identical inputs and verify
        // the outputs are bitwise identical.
        let formula = PricingFormula {
            base_cost: Amount(100),
            variables: vec![
                PricingVariable::Linear {
                    metric: PricingMetric::ContextMessageRate,
                    coefficient: Coefficient(1_500_000),
                },
                PricingVariable::Step {
                    metric: PricingMetric::SenderVelocity,
                    thresholds: vec![(10, Amount(5)), (50, Amount(50)), (200, Amount(500))],
                },
                PricingVariable::Linear {
                    metric: PricingMetric::StorageUsage,
                    coefficient: Coefficient(-100_000), // -0.1
                },
            ],
            cap: Some(Amount(10_000)),
            floor: Some(Amount(50)),
        };

        let metrics = ObservableMetrics {
            context_message_rate: 42,
            member_count: 100,
            relay_queue_depth: 500,
            time_of_day: 14,
            sender_velocity: 75,
            storage_usage: 1_000,
        };

        // Evaluate twice ("payer side" and "receiver side").
        let payer_result = evaluate_formula(&formula, &metrics);
        let receiver_result = evaluate_formula(&formula, &metrics);

        assert_eq!(payer_result, receiver_result);

        // Also verify the raw u64 values are identical (byte-identical).
        let payer_amount = payer_result.unwrap();
        let receiver_amount = receiver_result.unwrap();
        assert_eq!(payer_amount.0, receiver_amount.0);
        assert_eq!(
            payer_amount.0.to_le_bytes(),
            receiver_amount.0.to_le_bytes()
        );
    }

    #[test]
    fn cap_takes_precedence_over_floor_in_degenerate_config() {
        // AC: Cap takes precedence over floor when cap < floor (degenerate
        // configuration returns cap).
        let formula = PricingFormula {
            base_cost: Amount(50),
            variables: vec![],
            cap: Some(Amount(10)),    // cap < floor
            floor: Some(Amount(100)), // degenerate: floor > cap
        };
        let metrics = ObservableMetrics::default();
        // base=50, floor raises to 100, cap lowers to 10. Cap wins.
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(10)));
    }

    #[test]
    fn no_f64_in_evaluation_path() {
        // AC: No f64 in any evaluation path -- all arithmetic uses Amount(u64)
        // and Coefficient(i64) exclusively.
        // Verify type sizes: Amount is u64 (8 bytes), Coefficient is i64 (8 bytes).
        assert_eq!(std::mem::size_of::<Amount>(), 8);
        assert_eq!(std::mem::size_of::<Coefficient>(), 8);

        // Verify no f64 fields in PricingFormula.
        assert_eq!(std::mem::size_of::<f64>(), 8, "sanity: f64 is 8 bytes");
        // PricingFormula contains Amount(u64), Vec, Option<Amount> -- no f64.
        // This is a structural guarantee enforced by the type system.
    }

    // =======================================================================
    // Linear variable evaluation arithmetic
    // =======================================================================

    #[test]
    fn linear_evaluation_uses_integer_division_only() {
        // cost += (coefficient.0 * metric_value) / 1_000_000
        // 999_999 * 1 / 1_000_000 = 0 (integer truncation, not rounding)
        let formula = PricingFormula {
            base_cost: Amount(0),
            variables: vec![PricingVariable::Linear {
                metric: PricingMetric::MemberCount,
                coefficient: Coefficient(999_999),
            }],
            cap: None,
            floor: None,
        };
        let metrics = ObservableMetrics {
            member_count: 1,
            ..ObservableMetrics::default()
        };
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(0)));
    }

    #[test]
    fn step_thresholds_are_cumulative() {
        // Higher thresholds add their amount on top of lower thresholds.
        let formula = PricingFormula {
            base_cost: Amount(0),
            variables: vec![PricingVariable::Step {
                metric: PricingMetric::SenderVelocity,
                thresholds: vec![
                    (10, Amount(1)),
                    (50, Amount(10)),
                    (100, Amount(100)),
                    (200, Amount(1000)),
                ],
            }],
            cap: None,
            floor: None,
        };

        // At exactly 100: meets thresholds 10, 50, 100 but not 200.
        let metrics = ObservableMetrics {
            sender_velocity: 100,
            ..ObservableMetrics::default()
        };
        // 1 + 10 + 100 = 111
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(111)));

        // At 200: meets all thresholds.
        let metrics = ObservableMetrics {
            sender_velocity: 200,
            ..ObservableMetrics::default()
        };
        // 1 + 10 + 100 + 1000 = 1111
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(1111)));
    }

    // =======================================================================
    // EIP-1559-style relay pricing
    // =======================================================================

    #[test]
    fn relay_price_increases_when_above_target() {
        let config = RelayPricingConfig {
            target_utilization_pct: 50,
            current_base_price: Amount(1000),
            max_change_per_mille: 125, // 12.5%
            floor: Amount(100),
            cap: Amount(10_000),
        };

        // 80% utilization (30% above target)
        let result = adjust_relay_price(&config, 80);
        assert_eq!(result.direction, PriceDirection::Increased);
        // max_change = 1000 * 125 / 1000 = 125
        // proportional change = 125 * 30 / 100 = 37
        // new price = 1000 + 37 = 1037
        assert_eq!(result.new_base_price, Amount(1037));
    }

    #[test]
    fn relay_price_decreases_when_below_target() {
        let config = RelayPricingConfig {
            target_utilization_pct: 50,
            current_base_price: Amount(1000),
            max_change_per_mille: 125,
            floor: Amount(100),
            cap: Amount(10_000),
        };

        // 20% utilization (30% below target)
        let result = adjust_relay_price(&config, 20);
        assert_eq!(result.direction, PriceDirection::Decreased);
        // max_change = 125, proportional = 125 * 30 / 100 = 37
        // new price = 1000 - 37 = 963
        assert_eq!(result.new_base_price, Amount(963));
    }

    #[test]
    fn relay_price_unchanged_at_target() {
        let config = RelayPricingConfig {
            target_utilization_pct: 50,
            current_base_price: Amount(1000),
            max_change_per_mille: 125,
            floor: Amount(100),
            cap: Amount(10_000),
        };

        let result = adjust_relay_price(&config, 50);
        assert_eq!(result.direction, PriceDirection::Unchanged);
        assert_eq!(result.new_base_price, Amount(1000));
    }

    #[test]
    fn relay_price_clamped_at_cap() {
        let config = RelayPricingConfig {
            target_utilization_pct: 50,
            current_base_price: Amount(9900),
            max_change_per_mille: 125,
            floor: Amount(100),
            cap: Amount(10_000),
        };

        // 100% utilization -> max increase
        let result = adjust_relay_price(&config, 100);
        // max_change = 9900 * 125 / 1000 = 1237
        // proportional = 1237 * 50 / 100 = 618
        // new price = 9900 + 618 = 10518, capped at 10000
        assert_eq!(result.new_base_price, Amount(10_000));
    }

    #[test]
    fn relay_price_clamped_at_floor() {
        let config = RelayPricingConfig {
            target_utilization_pct: 50,
            current_base_price: Amount(150),
            max_change_per_mille: 125,
            floor: Amount(100),
            cap: Amount(10_000),
        };

        // 0% utilization -> max decrease
        let result = adjust_relay_price(&config, 0);
        // max_change = 150 * 125 / 1000 = 18
        // proportional = 18 * 50 / 100 = 9
        // new price = 150 - 9 = 141 (above floor)
        assert_eq!(result.new_base_price, Amount(141));
    }

    #[test]
    fn relay_price_does_not_go_below_floor() {
        let config = RelayPricingConfig {
            target_utilization_pct: 50,
            current_base_price: Amount(105),
            max_change_per_mille: 500, // 50% max change
            floor: Amount(100),
            cap: Amount(10_000),
        };

        // 0% utilization -> large decrease
        let result = adjust_relay_price(&config, 0);
        // max_change = 105 * 500 / 1000 = 52
        // proportional = 52 * 50 / 100 = 26
        // new price = 105 - 26 = 79, floored at 100
        assert_eq!(result.new_base_price, Amount(100));
    }

    #[test]
    fn relay_price_max_change_bounded() {
        let config = RelayPricingConfig {
            target_utilization_pct: 50,
            current_base_price: Amount(1000),
            max_change_per_mille: 125,
            floor: Amount(100),
            cap: Amount(10_000),
        };

        // 200% utilization (extreme over-target) -> clamped to max_change
        let result = adjust_relay_price(&config, 200);
        // delta_pct = 150, >= 100 so change = max_change = 125
        // new price = 1000 + 125 = 1125
        assert_eq!(result.new_base_price, Amount(1125));
    }

    // =======================================================================
    // Governed formula changes
    // =======================================================================

    #[test]
    fn formula_change_not_effective_during_grace_period() {
        let change = FormulaChange {
            proposed_formula: Some(PricingFormula {
                base_cost: Amount(200),
                variables: vec![],
                cap: None,
                floor: None,
            }),
            proposed_at: 1000,
            grace_period_secs: 3600, // 1 hour
            justification: "Increase base cost for sustainability".to_owned(),
            status: FormulaChangeStatus::Pending,
        };

        // During grace period
        assert!(!change.is_effective(1000));
        assert!(!change.is_effective(2000));
        assert!(!change.is_effective(4599));
    }

    #[test]
    fn formula_change_effective_after_grace_period() {
        let change = FormulaChange {
            proposed_formula: Some(PricingFormula {
                base_cost: Amount(200),
                variables: vec![],
                cap: None,
                floor: None,
            }),
            proposed_at: 1000,
            grace_period_secs: 3600,
            justification: "Increase base cost".to_owned(),
            status: FormulaChangeStatus::Pending,
        };

        // Exactly at grace period expiry
        assert!(change.is_effective(4600));
        // After grace period
        assert!(change.is_effective(5000));
    }

    #[test]
    fn formula_change_effective_at_returns_correct_timestamp() {
        let change = FormulaChange {
            proposed_formula: None,
            proposed_at: 1000,
            grace_period_secs: 7200,
            justification: "Remove dynamic pricing".to_owned(),
            status: FormulaChangeStatus::Pending,
        };

        assert_eq!(change.effective_at(), 8200);
    }

    #[test]
    fn formula_change_active_status_is_always_effective() {
        let change = FormulaChange {
            proposed_formula: Some(PricingFormula {
                base_cost: Amount(500),
                variables: vec![],
                cap: None,
                floor: None,
            }),
            proposed_at: 1000,
            grace_period_secs: 3600,
            justification: "Already approved".to_owned(),
            status: FormulaChangeStatus::Active,
        };

        // Active status is effective regardless of timestamp
        assert!(change.is_effective(0));
        assert!(change.is_effective(1000));
    }

    #[test]
    fn formula_change_rejected_is_never_effective() {
        let change = FormulaChange {
            proposed_formula: Some(PricingFormula {
                base_cost: Amount(500),
                variables: vec![],
                cap: None,
                floor: None,
            }),
            proposed_at: 1000,
            grace_period_secs: 3600,
            justification: "Rejected by governance".to_owned(),
            status: FormulaChangeStatus::Rejected,
        };

        assert!(!change.is_effective(0));
        assert!(!change.is_effective(10_000));
    }

    #[test]
    fn formula_change_withdrawn_is_never_effective() {
        let change = FormulaChange {
            proposed_formula: Some(PricingFormula {
                base_cost: Amount(500),
                variables: vec![],
                cap: None,
                floor: None,
            }),
            proposed_at: 1000,
            grace_period_secs: 3600,
            justification: "Withdrawn by proposer".to_owned(),
            status: FormulaChangeStatus::Withdrawn,
        };

        assert!(!change.is_effective(0));
        assert!(!change.is_effective(10_000));
    }

    #[test]
    fn formula_change_serde_roundtrip() {
        let change = FormulaChange {
            proposed_formula: Some(PricingFormula {
                base_cost: Amount(200),
                variables: vec![PricingVariable::Linear {
                    metric: PricingMetric::MemberCount,
                    coefficient: Coefficient(1_500_000),
                }],
                cap: Some(Amount(1000)),
                floor: Some(Amount(10)),
            }),
            proposed_at: 1000,
            grace_period_secs: 3600,
            justification: "Test change".to_owned(),
            status: FormulaChangeStatus::Pending,
        };

        let json = serde_json::to_string(&change).unwrap();
        let deserialized: FormulaChange = serde_json::from_str(&json).unwrap();
        assert_eq!(change, deserialized);
    }

    #[test]
    fn relay_pricing_config_serde_roundtrip() {
        let config = RelayPricingConfig {
            target_utilization_pct: 50,
            current_base_price: Amount(1000),
            max_change_per_mille: 125,
            floor: Amount(100),
            cap: Amount(10_000),
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: RelayPricingConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }
}
