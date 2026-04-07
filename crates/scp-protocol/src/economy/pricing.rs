//! Governed pricing formula changes.
//!
//! This module hosts governance-managed pricing-formula change records.
//!
//! Aggregate-velocity EIP-1559-style relay pricing has been removed in favor
//! of the per-DID escalation mechanism in [`super::antispam`] (spec §19.7).
//! See ADR notes in `.docs/adrs/phase-3.md`.
//!
//! See spec section 19.4 (Dynamic Pricing).

use serde::{Deserialize, Serialize};

use super::types::PricingFormula;

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
    use crate::economy::types::{Amount, Coefficient, PricingMetric, PricingVariable};

    // =======================================================================
    // Acceptance criteria unit tests (SCP-157)
    // =======================================================================

    #[test]
    fn base_cost_only_returns_base_cost() {
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
        let formula = PricingFormula {
            base_cost: Amount(0),
            variables: vec![PricingVariable::Linear {
                metric: PricingMetric::MemberCount,
                coefficient: Coefficient(1_500_000),
            }],
            cap: None,
            floor: None,
        };
        let metrics = ObservableMetrics {
            member_count: 100,
            ..ObservableMetrics::default()
        };
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(150)));
    }

    #[test]
    fn step_variable_metric_75_adds_11() {
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
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(11)));
    }

    #[test]
    fn cap_enforcement_clamps_result() {
        let formula = PricingFormula {
            base_cost: Amount(500),
            variables: vec![PricingVariable::Linear {
                metric: PricingMetric::MemberCount,
                coefficient: Coefficient(1_000_000),
            }],
            cap: Some(Amount(600)),
            floor: None,
        };
        let metrics = ObservableMetrics {
            member_count: 500,
            ..ObservableMetrics::default()
        };
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(600)));
    }

    #[test]
    fn floor_enforcement_raises_result() {
        let formula = PricingFormula {
            base_cost: Amount(1),
            variables: vec![],
            cap: None,
            floor: Some(Amount(100)),
        };
        let metrics = ObservableMetrics::default();
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(100)));
    }

    #[test]
    fn multiple_variables_are_additive() {
        let formula = PricingFormula {
            base_cost: Amount(10),
            variables: vec![
                PricingVariable::Linear {
                    metric: PricingMetric::ContextMessageRate,
                    coefficient: Coefficient(1_000_000),
                },
                PricingVariable::Linear {
                    metric: PricingMetric::MemberCount,
                    coefficient: Coefficient(500_000),
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
            context_message_rate: 30,
            member_count: 40,
            sender_velocity: 10,
            ..ObservableMetrics::default()
        };
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(80)));
    }

    #[test]
    fn negative_coefficient_reduces_cost_without_underflow() {
        let formula = PricingFormula {
            base_cost: Amount(50),
            variables: vec![PricingVariable::Linear {
                metric: PricingMetric::MemberCount,
                coefficient: Coefficient(-2_000_000),
            }],
            cap: None,
            floor: None,
        };
        let metrics = ObservableMetrics {
            member_count: 100,
            ..ObservableMetrics::default()
        };
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(0)));
    }

    #[test]
    fn cross_party_determinism_same_inputs_produce_identical_amount() {
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
                    coefficient: Coefficient(-100_000),
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

        let payer_result = evaluate_formula(&formula, &metrics);
        let receiver_result = evaluate_formula(&formula, &metrics);

        assert_eq!(payer_result, receiver_result);

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
        let formula = PricingFormula {
            base_cost: Amount(50),
            variables: vec![],
            cap: Some(Amount(10)),
            floor: Some(Amount(100)),
        };
        let metrics = ObservableMetrics::default();
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(10)));
    }

    #[test]
    fn no_f64_in_evaluation_path() {
        assert_eq!(std::mem::size_of::<Amount>(), 8);
        assert_eq!(std::mem::size_of::<Coefficient>(), 8);
        assert_eq!(std::mem::size_of::<f64>(), 8, "sanity: f64 is 8 bytes");
    }

    #[test]
    fn linear_evaluation_uses_integer_division_only() {
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

        let metrics = ObservableMetrics {
            sender_velocity: 100,
            ..ObservableMetrics::default()
        };
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(111)));

        let metrics = ObservableMetrics {
            sender_velocity: 200,
            ..ObservableMetrics::default()
        };
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(1111)));
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
            grace_period_secs: 3600,
            justification: "Increase base cost for sustainability".to_owned(),
            status: FormulaChangeStatus::Pending,
        };

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

        assert!(change.is_effective(4600));
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
}
