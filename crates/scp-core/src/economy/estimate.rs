//! SDK-facing cost estimation for SCP economic governance.
//!
//! Provides the [`estimate_cost`] function that evaluates a context's pricing
//! formula against current observable metrics to produce a cost estimate. This
//! is the SDK entry point described in spec section 19.11:
//!
//! ```text
//! SCP.Economy.estimateCost(context, action) -> Amount
//! ```
//!
//! The function takes a context's economic policy and the caller-provided
//! observable metrics, and returns the estimated cost for a given action type.
//! When no economic policy is present, the context is free and the cost is
//! `Amount(0)`.
//!
//! See spec section 19.11 (SDK Surface) and ADR-033.

use super::policy::{self, ObservableMetrics};
use super::types::{Amount, EconomicPolicy, PaidActionType};

// ---------------------------------------------------------------------------
// estimate_cost — SDK entry point
// ---------------------------------------------------------------------------

/// Estimates the cost for a given action in a context.
///
/// This is the SDK-facing function (`SCP.Economy.estimateCost`) described in
/// spec section 19.11. It evaluates the pricing formula against current
/// observable metrics.
///
/// # Arguments
///
/// * `economic_policy` - The context's economic policy. `None` means the
///   context is free.
/// * `action` - The type of action being estimated.
/// * `metrics` - Current observable metric values gathered from context state.
///
/// # Returns
///
/// The estimated cost as an [`Amount`]. Returns `Amount(0)` when:
/// - No economic policy is present (free context).
/// - No cost is configured for the action type and no formula is present.
///
/// Returns `None` only on arithmetic overflow (should not happen with
/// reasonable metric values and coefficients).
///
/// # Example
///
/// ```rust,ignore
/// let cost = estimate_cost(
///     context.params.economic_policy.as_ref(),
///     &PaidActionType::MessageSend,
///     &metrics,
/// );
/// ```
///
/// See spec section 19.11.
#[must_use]
pub fn estimate_cost(
    economic_policy: Option<&EconomicPolicy>,
    action: &PaidActionType,
    metrics: &ObservableMetrics,
) -> Option<Amount> {
    economic_policy.map_or(Some(Amount(0)), |p| {
        policy::evaluate_cost(p, action, metrics)
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::economy::types::{
        Coefficient, CostSchedule, CurrencyCode, EconomicPolicy, PricingFormula, PricingMetric,
        PricingVariable,
    };
    use crate::identity::DID;

    fn usd() -> CurrencyCode {
        CurrencyCode::from("USD")
    }

    fn payee() -> DID {
        DID::from("did:dht:z6MkPayee")
    }

    // =======================================================================
    // No economic policy = free
    // =======================================================================

    #[test]
    fn no_economic_policy_returns_zero() {
        let metrics = ObservableMetrics::default();
        assert_eq!(
            estimate_cost(None, &PaidActionType::MessageSend, &metrics),
            Some(Amount(0))
        );
    }

    #[test]
    fn no_economic_policy_free_for_all_action_types() {
        let metrics = ObservableMetrics::default();
        assert_eq!(
            estimate_cost(None, &PaidActionType::MessageSend, &metrics),
            Some(Amount(0))
        );
        assert_eq!(
            estimate_cost(None, &PaidActionType::ToolInvoke, &metrics),
            Some(Amount(0))
        );
        assert_eq!(
            estimate_cost(None, &PaidActionType::ContextJoin, &metrics),
            Some(Amount(0))
        );
        assert_eq!(
            estimate_cost(None, &PaidActionType::SubscriptionPeriod, &metrics),
            Some(Amount(0))
        );
        assert_eq!(
            estimate_cost(None, &PaidActionType::ByteStored, &metrics),
            Some(Amount(0))
        );
    }

    // =======================================================================
    // With economic policy
    // =======================================================================

    #[test]
    fn with_policy_returns_schedule_cost() {
        let policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: usd(),
                per_message: Some(Amount(10)),
                per_tool_invoke: Some(Amount(50)),
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec!["x402".to_owned()],
            pricing_formula: None,
            payee: payee(),
        };
        let metrics = ObservableMetrics::default();

        assert_eq!(
            estimate_cost(Some(&policy), &PaidActionType::MessageSend, &metrics),
            Some(Amount(10))
        );
        assert_eq!(
            estimate_cost(Some(&policy), &PaidActionType::ToolInvoke, &metrics),
            Some(Amount(50))
        );
        // No per_join cost configured -> 0.
        assert_eq!(
            estimate_cost(Some(&policy), &PaidActionType::ContextJoin, &metrics),
            Some(Amount(0))
        );
    }

    #[test]
    fn with_policy_and_formula_adds_formula_cost() {
        let policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: usd(),
                per_message: Some(Amount(10)),
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec!["x402".to_owned()],
            pricing_formula: Some(PricingFormula {
                base_cost: Amount(5),
                variables: vec![PricingVariable::Linear {
                    metric: PricingMetric::MemberCount,
                    coefficient: Coefficient(1_000_000), // 1.0
                }],
                cap: None,
                floor: None,
            }),
            payee: payee(),
        };
        let metrics = ObservableMetrics {
            member_count: 20,
            ..ObservableMetrics::default()
        };
        // schedule: 10, formula: 5 + (1.0 * 20) = 25, total: 35
        assert_eq!(
            estimate_cost(Some(&policy), &PaidActionType::MessageSend, &metrics),
            Some(Amount(35))
        );
    }

    #[test]
    fn estimate_cost_evaluates_against_current_metrics() {
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
            payment_adapters: vec!["x402".to_owned()],
            pricing_formula: Some(PricingFormula {
                base_cost: Amount(0),
                variables: vec![PricingVariable::Step {
                    metric: PricingMetric::SenderVelocity,
                    thresholds: vec![(10, Amount(1)), (50, Amount(10)), (200, Amount(100))],
                }],
                cap: Some(Amount(1000)),
                floor: None,
            }),
            payee: payee(),
        };

        // Low velocity: schedule(1) + formula(0) = 1
        let low = ObservableMetrics {
            sender_velocity: 5,
            ..ObservableMetrics::default()
        };
        assert_eq!(
            estimate_cost(Some(&policy), &PaidActionType::MessageSend, &low),
            Some(Amount(1))
        );

        // High velocity: schedule(1) + formula(0 + 1 + 10 + 100) = 112
        let high = ObservableMetrics {
            sender_velocity: 200,
            ..ObservableMetrics::default()
        };
        assert_eq!(
            estimate_cost(Some(&policy), &PaidActionType::MessageSend, &high),
            Some(Amount(112))
        );
    }
}
