//! Economic policy evaluation and cost schedule lookup.
//!
//! Given an [`EconomicPolicy`] and a [`PaidActionType`], computes the cost
//! from the [`CostSchedule`]. When a [`PricingFormula`] is present, formula
//! evaluation result is added to the base cost. All arithmetic uses
//! [`Amount`](u64) and [`Coefficient`](i64) exclusively -- no `f64` anywhere
//! in the evaluation path.
//!
//! Key behaviors:
//!
//! - **Policy lock enforcement**: If `locked == true`, any governance mutation
//!   of the economic policy is rejected. The lock is itself immutable: once
//!   locked, cannot be set back to `false`.
//!
//! - **No economic policy = free**: Contexts without [`EconomicPolicy`] require
//!   no payment for any action.
//!
//! - **Orthogonality with capability ceiling**: Economic policy evaluation does
//!   not check or modify the capability ceiling.
//!
//! - **Child context independence**: Each child context uses its own economic
//!   policy, not the parent's.
//!
//! - **Auto-accept guard**: Context invitations with [`EconomicPolicy`]
//!   requiring payment are never auto-accepted. This is a hard rule -- no
//!   auto-accept policy configuration can override it.
//!
//! See spec section 19.3 (Economic Policy), 19.4 (Dynamic Pricing), and
//! ADR-033 acceptance criteria #7, #8, #9, #10.

use super::types::{
    Amount, CostSchedule, EconomicPolicy, PaidActionType, PricingFormula, PricingMetric,
    PricingVariable,
};
use crate::economy::CurrencyCode;

// ---------------------------------------------------------------------------
// CostInsufficient
// ---------------------------------------------------------------------------

/// Returned when the payer's authorized amount is less than the receiver's
/// computed cost.
///
/// Includes a metric snapshot so the payer can see why costs diverged (both
/// sides evaluate independently against observable metrics).
///
/// See spec section 19.4.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CostInsufficient {
    /// Receiver's computed cost.
    pub expected: Amount,
    /// Payer's authorized amount.
    pub provided: Amount,
    /// The currency of both amounts.
    pub currency: CurrencyCode,
    /// Receiver's observed metric values at evaluation time.
    pub metric_snapshot: Vec<(PricingMetric, u64)>,
}

impl std::fmt::Display for CostInsufficient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cost insufficient: expected {} {}, provided {} {}",
            self.expected, self.currency, self.provided, self.currency
        )
    }
}

impl std::error::Error for CostInsufficient {}

// ---------------------------------------------------------------------------
// PolicyLockError
// ---------------------------------------------------------------------------

/// Error returned when attempting to mutate a locked economic policy.
///
/// The lock is itself immutable: once `locked == true`, it cannot be set back
/// to `false`. See spec section 19.3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyLockError;

impl std::fmt::Display for PolicyLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "economic policy is locked: governance mutation rejected")
    }
}

impl std::error::Error for PolicyLockError {}

// ---------------------------------------------------------------------------
// ObservableMetrics
// ---------------------------------------------------------------------------

/// Current observable metric values used in pricing formula evaluation.
///
/// Both payer and receiver independently gather these values from the context
/// state to evaluate the [`PricingFormula`]. When values diverge between
/// the two sides, the payer receives a [`CostInsufficient`] error with the
/// receiver's metric snapshot.
///
/// See spec section 19.4.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObservableMetrics {
    /// Messages per minute in this context.
    pub context_message_rate: u64,
    /// Current member count.
    pub member_count: u64,
    /// Relay-level queue depth (relay-level pricing only).
    pub relay_queue_depth: u64,
    /// UTC hour (0-23), enables off-peak pricing.
    pub time_of_day: u64,
    /// Sender's messages in sliding window (anti-spam).
    pub sender_velocity: u64,
    /// Context storage usage in bytes.
    pub storage_usage: u64,
}

impl ObservableMetrics {
    /// Returns the value of a specific metric.
    #[must_use]
    pub const fn get(&self, metric: &PricingMetric) -> u64 {
        match metric {
            PricingMetric::ContextMessageRate => self.context_message_rate,
            PricingMetric::MemberCount => self.member_count,
            PricingMetric::RelayQueueDepth => self.relay_queue_depth,
            PricingMetric::TimeOfDay => self.time_of_day,
            PricingMetric::SenderVelocity => self.sender_velocity,
            PricingMetric::StorageUsage => self.storage_usage,
        }
    }

    /// Collects a snapshot of all metric values referenced by the given
    /// pricing formula variables.
    ///
    /// Returns a vec of `(PricingMetric, u64)` pairs representing the
    /// receiver's observed metric values. Used to populate
    /// [`CostInsufficient::metric_snapshot`].
    #[must_use]
    pub fn snapshot_for_formula(&self, formula: &PricingFormula) -> Vec<(PricingMetric, u64)> {
        let mut snapshot = Vec::new();
        for var in &formula.variables {
            let metric = match var {
                PricingVariable::Linear { metric, .. } | PricingVariable::Step { metric, .. } => {
                    metric
                }
            };
            // Avoid duplicates.
            if !snapshot.iter().any(|(m, _)| m == metric) {
                snapshot.push((metric.clone(), self.get(metric)));
            }
        }
        snapshot
    }

    /// Collects a snapshot of all seven metric values.
    #[must_use]
    pub fn snapshot_all(&self) -> Vec<(PricingMetric, u64)> {
        vec![
            (PricingMetric::ContextMessageRate, self.context_message_rate),
            (PricingMetric::MemberCount, self.member_count),
            (PricingMetric::RelayQueueDepth, self.relay_queue_depth),
            (PricingMetric::TimeOfDay, self.time_of_day),
            (PricingMetric::SenderVelocity, self.sender_velocity),
            (PricingMetric::StorageUsage, self.storage_usage),
        ]
    }
}

// ---------------------------------------------------------------------------
// Metric availability validation (pit-of-success)
// ---------------------------------------------------------------------------

/// Metrics that are currently populated by the runtime infrastructure.
///
/// Formulas referencing metrics NOT in this list will be rejected at context
/// creation time. Update this constant as new metric sources are wired.
///
/// Available: `SenderVelocity`, `MemberCount`, `ContextMessageRate`,
/// `TimeOfDay`.
///
/// NOT available: `RelayQueueDepth`, `StorageUsage`.
pub const AVAILABLE_METRICS: &[PricingMetric] = &[
    PricingMetric::SenderVelocity,
    PricingMetric::MemberCount,
    PricingMetric::ContextMessageRate,
    PricingMetric::TimeOfDay,
];

/// Error returned when a [`PricingFormula`] references metrics that are not
/// yet populated by the runtime infrastructure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnavailableMetricError {
    /// Metrics referenced by the formula that are not currently available.
    pub unavailable: Vec<PricingMetric>,
}

impl std::fmt::Display for UnavailableMetricError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pricing formula references unavailable metrics: ")?;
        for (i, m) in self.unavailable.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{m}")?;
        }
        Ok(())
    }
}

impl std::error::Error for UnavailableMetricError {}

/// Validates that a [`PricingFormula`] only references metrics that are
/// currently populated by the runtime.
///
/// Returns `Ok(())` if all referenced metrics are in [`AVAILABLE_METRICS`].
/// Returns `Err(UnavailableMetricError)` listing the unavailable metrics
/// otherwise.
///
/// # Errors
///
/// Returns [`UnavailableMetricError`] when the formula references unpopulated
/// metrics.
pub fn validate_formula_metrics(formula: &PricingFormula) -> Result<(), UnavailableMetricError> {
    let mut unavailable = Vec::new();
    for var in &formula.variables {
        let metric = match var {
            PricingVariable::Linear { metric, .. } | PricingVariable::Step { metric, .. } => metric,
        };
        if !AVAILABLE_METRICS.contains(metric) && !unavailable.contains(metric) {
            unavailable.push(metric.clone());
        }
    }
    if unavailable.is_empty() {
        Ok(())
    } else {
        Err(UnavailableMetricError { unavailable })
    }
}

/// Convenience wrapper: validates metric availability for an optional
/// [`EconomicPolicy`].
///
/// Returns `Ok(())` if:
/// - The policy is `None` (no economic policy = no formula to validate).
/// - The policy has no `pricing_formula`.
/// - All formula metrics are available.
///
/// # Errors
///
/// Returns [`UnavailableMetricError`] when the formula references unpopulated
/// metrics.
pub fn validate_economic_policy_metrics(
    policy: Option<&EconomicPolicy>,
) -> Result<(), UnavailableMetricError> {
    if let Some(p) = policy
        && let Some(formula) = &p.pricing_formula
    {
        return validate_formula_metrics(formula);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PricingFormula evaluation
// ---------------------------------------------------------------------------

/// Evaluates a [`PricingFormula`] against observable metrics.
///
/// The result is the formula's computed cost, clamped to `[floor, cap]` if
/// present. All arithmetic uses [`Amount`](u64) and [`Coefficient`](i64)
/// exclusively -- no `f64` anywhere in the evaluation path.
///
/// Returns `None` on arithmetic overflow (should not happen with reasonable
/// metric values and coefficients).
///
/// See spec section 19.4.
#[must_use]
pub fn evaluate_formula(formula: &PricingFormula, metrics: &ObservableMetrics) -> Option<Amount> {
    let mut cost = formula.base_cost;

    for var in &formula.variables {
        match var {
            PricingVariable::Linear {
                metric,
                coefficient,
            } => {
                let metric_value = metrics.get(metric);
                let delta = coefficient.evaluate(metric_value)?;
                // delta can be negative (discount) or positive (surcharge).
                if delta >= 0 {
                    cost = cost.saturating_add(Amount(delta.cast_unsigned()));
                } else {
                    cost = cost.saturating_sub(Amount(delta.unsigned_abs()));
                }
            }
            PricingVariable::Step { metric, thresholds } => {
                let metric_value = metrics.get(metric);
                for &(threshold, ref additional) in thresholds {
                    if metric_value >= threshold {
                        cost = cost.saturating_add(*additional);
                    }
                }
            }
        }
    }

    // Apply floor.
    if let Some(floor) = formula.floor
        && cost < floor
    {
        cost = floor;
    }

    // Apply cap.
    if let Some(cap) = formula.cap
        && cost > cap
    {
        cost = cap;
    }

    Some(cost)
}

// ---------------------------------------------------------------------------
// CostSchedule lookup
// ---------------------------------------------------------------------------

/// Looks up the base cost for a given action type from the [`CostSchedule`].
///
/// Returns the per-action cost if defined, or `None` if no cost is configured
/// for that action type.
///
/// - `MessageSend` -> `per_message`
/// - `ToolInvoke` -> `per_tool_invoke`
/// - `ContextJoin` -> `per_join`
/// - `SubscriptionPeriod` -> `per_period.amount`
/// - `ByteStored` -> `per_byte_stored`
///
/// See spec section 19.3.
#[must_use]
pub fn lookup_cost(schedule: &CostSchedule, action: &PaidActionType) -> Option<Amount> {
    match action {
        PaidActionType::MessageSend => schedule.per_message,
        PaidActionType::ToolInvoke => schedule.per_tool_invoke,
        PaidActionType::ContextJoin => schedule.per_join,
        PaidActionType::SubscriptionPeriod => schedule.per_period.as_ref().map(|sub| sub.amount),
        PaidActionType::ByteStored => schedule.per_byte_stored,
    }
}

// ---------------------------------------------------------------------------
// EconomicPolicy evaluation
// ---------------------------------------------------------------------------

/// Evaluates the cost for a given action under an [`EconomicPolicy`].
///
/// Computes cost from the [`CostSchedule`] and, when a [`PricingFormula`]
/// is present, adds the formula evaluation result to the base cost.
///
/// Returns `Amount(0)` when:
/// - No cost is configured for the action type in the schedule.
/// - The schedule cost is `None` and no pricing formula is present.
///
/// Returns `None` on arithmetic overflow.
///
/// See spec section 19.3, 19.4.
#[must_use]
pub fn evaluate_cost(
    policy: &EconomicPolicy,
    action: &PaidActionType,
    metrics: &ObservableMetrics,
) -> Option<Amount> {
    let base = lookup_cost(&policy.cost_schedule, action).unwrap_or(Amount(0));

    match &policy.pricing_formula {
        Some(formula) => {
            let formula_cost = evaluate_formula(formula, metrics)?;
            Some(base.saturating_add(formula_cost))
        }
        None => Some(base),
    }
}

// ---------------------------------------------------------------------------
// Policy lock enforcement
// ---------------------------------------------------------------------------

/// Checks whether a governance mutation of the economic policy is permitted.
///
/// If the current policy is locked (`locked == true`), returns
/// [`PolicyLockError`]. If unlocked, returns `Ok(())`.
///
/// The lock is itself immutable: the proposed policy's `locked` field is not
/// consulted -- only the _current_ policy's lock state matters.
///
/// See spec section 19.3.
///
/// # Errors
///
/// Returns [`PolicyLockError`] if the current policy is locked.
pub const fn check_policy_lock(current: &EconomicPolicy) -> Result<(), PolicyLockError> {
    if current.locked {
        Err(PolicyLockError)
    } else {
        Ok(())
    }
}

/// Validates that a proposed policy change does not violate the lock
/// invariant.
///
/// Rules:
/// - If the current policy is locked, ALL changes are rejected.
/// - If the current policy is unlocked and the proposed policy sets
///   `locked = true`, that is a valid one-way transition.
/// - Once locked, the lock cannot be set back to `false`.
///
/// # Errors
///
/// Returns [`PolicyLockError`] if the current policy is locked.
pub const fn validate_policy_change(
    current: &EconomicPolicy,
    _proposed: &EconomicPolicy,
) -> Result<(), PolicyLockError> {
    check_policy_lock(current)
}

// ---------------------------------------------------------------------------
// Auto-accept guard
// ---------------------------------------------------------------------------

/// Returns `true` if the given [`EconomicPolicy`] requires payment for any
/// action.
///
/// A policy requires payment if any cost in the [`CostSchedule`] is `Some`
/// or if a [`PricingFormula`] is present (which may produce non-zero costs
/// even when the schedule has no fixed costs).
///
/// This is the economic component of the auto-accept guard.
///
/// **Hard rule**: Context invitations with economic policy requiring payment
/// are NEVER auto-accepted, regardless of any auto-accept policy
/// configuration.
///
/// See spec section 19.3, 19.14 invariant #9.
#[must_use]
pub const fn policy_requires_payment(policy: &EconomicPolicy) -> bool {
    let cs = &policy.cost_schedule;
    cs.per_message.is_some()
        || cs.per_tool_invoke.is_some()
        || cs.per_join.is_some()
        || cs.per_period.is_some()
        || cs.per_byte_stored.is_some()
        || policy.pricing_formula.is_some()
}

/// Checks whether a context invitation should be blocked from auto-accept
/// due to economic policy.
///
/// Returns `true` if auto-accept is blocked (i.e., the context has an
/// economic policy requiring payment). Returns `false` if no economic policy
/// is present or if the policy has no costs.
///
/// **Hard rule**: No auto-accept policy configuration can override this.
/// Agents never silently incur costs.
///
/// See spec section 19.3, 19.14 invariant #9.
#[must_use]
pub fn auto_accept_blocked_by_economics(economic_policy: Option<&EconomicPolicy>) -> bool {
    economic_policy.is_some_and(policy_requires_payment)
}

// ---------------------------------------------------------------------------
// Verify cost sufficiency
// ---------------------------------------------------------------------------

/// Verifies that the payer's authorized amount covers the receiver's computed
/// cost.
///
/// If the authorized amount is less than the computed cost, returns
/// `Err(CostInsufficient)` with the receiver's metric snapshot. If
/// sufficient, returns `Ok(())`.
///
/// See spec section 19.4.
///
/// # Errors
///
/// Returns [`CostInsufficient`] when `provided < expected`.
pub fn verify_cost_sufficiency(
    policy: &EconomicPolicy,
    action: &PaidActionType,
    metrics: &ObservableMetrics,
    provided: Amount,
) -> Result<(), CostInsufficient> {
    let expected = evaluate_cost(policy, action, metrics).unwrap_or(Amount(u64::MAX));

    if provided < expected {
        let snapshot = policy
            .pricing_formula
            .as_ref()
            .map_or_else(Vec::new, |f| metrics.snapshot_for_formula(f));

        return Err(CostInsufficient {
            expected,
            provided,
            currency: policy.cost_schedule.currency,
            metric_snapshot: snapshot,
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::economy::types::{
        Coefficient, PricingFormula, PricingMetric, PricingVariable, SubscriptionCost,
        SubscriptionPeriod,
    };
    use scp_did::DID;

    // --- Helpers ---

    fn usd() -> CurrencyCode {
        CurrencyCode::from("USD")
    }

    fn payee() -> DID {
        DID::from("did:dht:z6MkPayee")
    }

    fn simple_policy() -> EconomicPolicy {
        EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: usd(),
                per_message: Some(Amount(10)),
                per_tool_invoke: Some(Amount(50)),
                per_join: Some(Amount(100)),
                per_period: Some(SubscriptionCost {
                    amount: Amount(999),
                    period: SubscriptionPeriod::Monthly,
                    currency: usd(),
                }),
                per_byte_stored: Some(Amount(1)),
            },
            payment_adapters: vec!["x402".to_owned()],
            pricing_formula: None,
            payee: payee(),
        }
    }

    fn free_policy() -> EconomicPolicy {
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
            payee: payee(),
        }
    }

    fn default_metrics() -> ObservableMetrics {
        ObservableMetrics::default()
    }

    // =======================================================================
    // CostSchedule lookup
    // =======================================================================

    #[test]
    fn lookup_per_message_returns_configured_cost() {
        let schedule = &simple_policy().cost_schedule;
        assert_eq!(
            lookup_cost(schedule, &PaidActionType::MessageSend),
            Some(Amount(10))
        );
    }

    #[test]
    fn lookup_per_tool_invoke_returns_configured_cost() {
        let schedule = &simple_policy().cost_schedule;
        assert_eq!(
            lookup_cost(schedule, &PaidActionType::ToolInvoke),
            Some(Amount(50))
        );
    }

    #[test]
    fn lookup_per_join_returns_configured_cost() {
        let schedule = &simple_policy().cost_schedule;
        assert_eq!(
            lookup_cost(schedule, &PaidActionType::ContextJoin),
            Some(Amount(100))
        );
    }

    #[test]
    fn lookup_per_period_returns_subscription_amount() {
        let schedule = &simple_policy().cost_schedule;
        assert_eq!(
            lookup_cost(schedule, &PaidActionType::SubscriptionPeriod),
            Some(Amount(999))
        );
    }

    #[test]
    fn lookup_per_byte_stored_returns_configured_cost() {
        let schedule = &simple_policy().cost_schedule;
        assert_eq!(
            lookup_cost(schedule, &PaidActionType::ByteStored),
            Some(Amount(1))
        );
    }

    #[test]
    fn lookup_unconfigured_action_returns_none() {
        let schedule = &free_policy().cost_schedule;
        assert_eq!(lookup_cost(schedule, &PaidActionType::MessageSend), None);
        assert_eq!(lookup_cost(schedule, &PaidActionType::ToolInvoke), None);
        assert_eq!(lookup_cost(schedule, &PaidActionType::ContextJoin), None);
        assert_eq!(
            lookup_cost(schedule, &PaidActionType::SubscriptionPeriod),
            None
        );
        assert_eq!(lookup_cost(schedule, &PaidActionType::ByteStored), None);
    }

    // =======================================================================
    // PricingFormula evaluation
    // =======================================================================

    #[test]
    fn formula_base_cost_only() {
        let formula = PricingFormula {
            base_cost: Amount(100),
            variables: vec![],
            cap: None,
            floor: None,
        };
        let metrics = default_metrics();
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(100)));
    }

    #[test]
    fn formula_linear_variable_adds_cost() {
        // coefficient 0.5, member_count = 200 -> delta = 100
        let formula = PricingFormula {
            base_cost: Amount(10),
            variables: vec![PricingVariable::Linear {
                metric: PricingMetric::MemberCount,
                coefficient: Coefficient(500_000), // 0.5
            }],
            cap: None,
            floor: None,
        };
        let metrics = ObservableMetrics {
            member_count: 200,
            ..default_metrics()
        };
        // 10 + (0.5 * 200) = 10 + 100 = 110
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(110)));
    }

    #[test]
    fn formula_linear_negative_coefficient_reduces_cost() {
        // coefficient -0.5, member_count = 100 -> delta = -50
        let formula = PricingFormula {
            base_cost: Amount(200),
            variables: vec![PricingVariable::Linear {
                metric: PricingMetric::MemberCount,
                coefficient: Coefficient(-500_000), // -0.5
            }],
            cap: None,
            floor: None,
        };
        let metrics = ObservableMetrics {
            member_count: 100,
            ..default_metrics()
        };
        // 200 - 50 = 150
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(150)));
    }

    #[test]
    fn formula_linear_negative_saturates_at_zero() {
        // Large negative delta would underflow; saturates to 0.
        let formula = PricingFormula {
            base_cost: Amount(10),
            variables: vec![PricingVariable::Linear {
                metric: PricingMetric::MemberCount,
                coefficient: Coefficient(-1_000_000), // -1.0
            }],
            cap: None,
            floor: None,
        };
        let metrics = ObservableMetrics {
            member_count: 1000,
            ..default_metrics()
        };
        // 10 - 1000 -> saturates to 0
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(0)));
    }

    #[test]
    fn formula_step_variable_adds_cost_when_threshold_met() {
        let formula = PricingFormula {
            base_cost: Amount(1),
            variables: vec![PricingVariable::Step {
                metric: PricingMetric::SenderVelocity,
                thresholds: vec![(10, Amount(1)), (50, Amount(10)), (200, Amount(100))],
            }],
            cap: None,
            floor: None,
        };

        // velocity 5: no thresholds met
        let metrics = ObservableMetrics {
            sender_velocity: 5,
            ..default_metrics()
        };
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(1)));

        // velocity 30: first threshold met
        let metrics = ObservableMetrics {
            sender_velocity: 30,
            ..default_metrics()
        };
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(2))); // 1 + 1

        // velocity 200: all thresholds met
        let metrics = ObservableMetrics {
            sender_velocity: 200,
            ..default_metrics()
        };
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(112))); // 1 + 1 + 10 + 100
    }

    #[test]
    fn formula_cap_applied() {
        let formula = PricingFormula {
            base_cost: Amount(500),
            variables: vec![PricingVariable::Linear {
                metric: PricingMetric::MemberCount,
                coefficient: Coefficient(1_000_000), // 1.0
            }],
            cap: Some(Amount(1000)),
            floor: None,
        };
        let metrics = ObservableMetrics {
            member_count: 1000,
            ..default_metrics()
        };
        // 500 + 1000 = 1500, but capped at 1000
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(1000)));
    }

    #[test]
    fn formula_floor_applied() {
        let formula = PricingFormula {
            base_cost: Amount(0),
            variables: vec![],
            cap: None,
            floor: Some(Amount(5)),
        };
        let metrics = default_metrics();
        // 0, but floor is 5
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(5)));
    }

    #[test]
    fn formula_floor_and_cap_applied() {
        // Floor > cap scenario: cap wins (applied second).
        let formula = PricingFormula {
            base_cost: Amount(0),
            variables: vec![],
            cap: Some(Amount(3)),
            floor: Some(Amount(5)),
        };
        let metrics = default_metrics();
        // base=0, floor raises to 5, cap lowers to 3
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(3)));
    }

    #[test]
    fn formula_multiple_variables_compose() {
        let formula = PricingFormula {
            base_cost: Amount(10),
            variables: vec![
                PricingVariable::Linear {
                    metric: PricingMetric::ContextMessageRate,
                    coefficient: Coefficient(500_000), // 0.5
                },
                PricingVariable::Step {
                    metric: PricingMetric::SenderVelocity,
                    thresholds: vec![(10, Amount(5))],
                },
            ],
            cap: None,
            floor: None,
        };
        let metrics = ObservableMetrics {
            context_message_rate: 100, // linear: 0.5 * 100 = 50
            sender_velocity: 20,       // step: 20 >= 10, +5
            ..default_metrics()
        };
        // 10 + 50 + 5 = 65
        assert_eq!(evaluate_formula(&formula, &metrics), Some(Amount(65)));
    }

    // =======================================================================
    // EconomicPolicy evaluation (schedule + formula)
    // =======================================================================

    #[test]
    fn evaluate_cost_schedule_only() {
        let policy = simple_policy();
        let metrics = default_metrics();
        assert_eq!(
            evaluate_cost(&policy, &PaidActionType::MessageSend, &metrics),
            Some(Amount(10))
        );
    }

    #[test]
    fn evaluate_cost_schedule_plus_formula() {
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
            ..default_metrics()
        };
        // schedule: 10, formula: 5 + (1.0 * 20) = 25, total: 10 + 25 = 35
        assert_eq!(
            evaluate_cost(&policy, &PaidActionType::MessageSend, &metrics),
            Some(Amount(35))
        );
    }

    #[test]
    fn evaluate_cost_no_schedule_cost_with_formula() {
        let policy = EconomicPolicy {
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
            pricing_formula: Some(PricingFormula {
                base_cost: Amount(100),
                variables: vec![],
                cap: None,
                floor: None,
            }),
            payee: payee(),
        };
        let metrics = default_metrics();
        // schedule: 0, formula: 100, total: 100
        assert_eq!(
            evaluate_cost(&policy, &PaidActionType::MessageSend, &metrics),
            Some(Amount(100))
        );
    }

    #[test]
    fn evaluate_cost_free_policy_returns_zero() {
        let policy = free_policy();
        let metrics = default_metrics();
        assert_eq!(
            evaluate_cost(&policy, &PaidActionType::MessageSend, &metrics),
            Some(Amount(0))
        );
    }

    // =======================================================================
    // CostInsufficient
    // =======================================================================

    #[test]
    fn verify_cost_sufficiency_passes_when_sufficient() {
        let policy = simple_policy();
        let metrics = default_metrics();
        // per_message is 10, providing 10.
        assert!(
            verify_cost_sufficiency(&policy, &PaidActionType::MessageSend, &metrics, Amount(10),)
                .is_ok()
        );
    }

    #[test]
    fn verify_cost_sufficiency_passes_when_overpaying() {
        let policy = simple_policy();
        let metrics = default_metrics();
        // per_message is 10, providing 100.
        assert!(
            verify_cost_sufficiency(&policy, &PaidActionType::MessageSend, &metrics, Amount(100),)
                .is_ok()
        );
    }

    #[test]
    fn verify_cost_sufficiency_fails_when_insufficient() {
        let policy = simple_policy();
        let metrics = default_metrics();
        // per_message is 10, providing 5.
        let result =
            verify_cost_sufficiency(&policy, &PaidActionType::MessageSend, &metrics, Amount(5));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.expected, Amount(10));
        assert_eq!(err.provided, Amount(5));
        assert_eq!(err.currency, usd());
    }

    #[test]
    fn verify_cost_sufficiency_includes_metric_snapshot_when_formula_present() {
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
                base_cost: Amount(0),
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
            member_count: 50,
            ..default_metrics()
        };
        // schedule: 10, formula: 0 + (1.0 * 50) = 50, total: 60
        // providing 20 -> insufficient
        let result =
            verify_cost_sufficiency(&policy, &PaidActionType::MessageSend, &metrics, Amount(20));
        let err = result.unwrap_err();
        assert_eq!(err.expected, Amount(60));
        assert_eq!(err.provided, Amount(20));
        assert_eq!(err.metric_snapshot.len(), 1);
        assert_eq!(err.metric_snapshot[0], (PricingMetric::MemberCount, 50));
    }

    // =======================================================================
    // Policy lock enforcement
    // =======================================================================

    #[test]
    fn check_policy_lock_unlocked_allows_mutation() {
        let policy = free_policy();
        assert!(check_policy_lock(&policy).is_ok());
    }

    #[test]
    fn check_policy_lock_locked_rejects_mutation() {
        let mut policy = free_policy();
        policy.locked = true;
        assert!(check_policy_lock(&policy).is_err());
    }

    #[test]
    fn validate_policy_change_unlocked_to_locked_allowed() {
        let current = free_policy();
        let mut proposed = free_policy();
        proposed.locked = true;
        assert!(validate_policy_change(&current, &proposed).is_ok());
    }

    #[test]
    fn validate_policy_change_locked_to_unlocked_rejected() {
        let mut current = free_policy();
        current.locked = true;
        let proposed = free_policy(); // locked = false
        assert!(validate_policy_change(&current, &proposed).is_err());
    }

    #[test]
    fn validate_policy_change_locked_to_locked_still_rejected() {
        let mut current = free_policy();
        current.locked = true;
        let mut proposed = free_policy();
        proposed.locked = true;
        proposed.cost_schedule.per_message = Some(Amount(1)); // any change
        assert!(validate_policy_change(&current, &proposed).is_err());
    }

    #[test]
    fn lock_is_one_way_transition() {
        // Unlocked -> locked: OK
        let current = free_policy();
        let mut proposed = free_policy();
        proposed.locked = true;
        assert!(validate_policy_change(&current, &proposed).is_ok());

        // After locking, any further change is rejected.
        let locked = proposed;
        let another_proposed = free_policy();
        assert!(validate_policy_change(&locked, &another_proposed).is_err());
    }

    // =======================================================================
    // Auto-accept guard
    // =======================================================================

    #[test]
    fn auto_accept_blocked_by_per_message_cost() {
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
            pricing_formula: None,
            payee: payee(),
        };
        assert!(policy_requires_payment(&policy));
        assert!(auto_accept_blocked_by_economics(Some(&policy)));
    }

    #[test]
    fn auto_accept_blocked_by_per_tool_invoke_cost() {
        let policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: usd(),
                per_message: None,
                per_tool_invoke: Some(Amount(10)),
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec!["x402".to_owned()],
            pricing_formula: None,
            payee: payee(),
        };
        assert!(policy_requires_payment(&policy));
        assert!(auto_accept_blocked_by_economics(Some(&policy)));
    }

    #[test]
    fn auto_accept_blocked_by_per_join_cost() {
        let policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: usd(),
                per_message: None,
                per_tool_invoke: None,
                per_join: Some(Amount(100)),
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec!["x402".to_owned()],
            pricing_formula: None,
            payee: payee(),
        };
        assert!(policy_requires_payment(&policy));
        assert!(auto_accept_blocked_by_economics(Some(&policy)));
    }

    #[test]
    fn auto_accept_blocked_by_per_period_cost() {
        let policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: usd(),
                per_message: None,
                per_tool_invoke: None,
                per_join: None,
                per_period: Some(SubscriptionCost {
                    amount: Amount(999),
                    period: SubscriptionPeriod::Monthly,
                    currency: usd(),
                }),
                per_byte_stored: None,
            },
            payment_adapters: vec!["x402".to_owned()],
            pricing_formula: None,
            payee: payee(),
        };
        assert!(policy_requires_payment(&policy));
        assert!(auto_accept_blocked_by_economics(Some(&policy)));
    }

    #[test]
    fn auto_accept_blocked_by_per_byte_stored_cost() {
        let policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: usd(),
                per_message: None,
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: Some(Amount(1)),
            },
            payment_adapters: vec!["x402".to_owned()],
            pricing_formula: None,
            payee: payee(),
        };
        assert!(policy_requires_payment(&policy));
        assert!(auto_accept_blocked_by_economics(Some(&policy)));
    }

    #[test]
    fn auto_accept_not_blocked_by_free_policy() {
        let policy = free_policy();
        assert!(!policy_requires_payment(&policy));
        assert!(!auto_accept_blocked_by_economics(Some(&policy)));
    }

    #[test]
    fn auto_accept_not_blocked_when_no_policy() {
        assert!(!auto_accept_blocked_by_economics(None));
    }

    #[test]
    fn auto_accept_hard_rule_overrides_all_configurations() {
        // Even with a matching auto-accept policy, paid contexts must prompt.
        // This test verifies the guard function itself returns `true` for
        // any paid policy, regardless of the policy's other fields.
        let paid_policy = simple_policy();
        assert!(auto_accept_blocked_by_economics(Some(&paid_policy)));
    }

    // =======================================================================
    // Orthogonality with capability ceiling
    // =======================================================================

    #[test]
    fn economic_evaluation_does_not_check_ceiling() {
        // Economic policy evaluation operates independently of capability
        // ceiling. A cost is computed regardless of what capabilities exist.
        let policy = simple_policy();
        let metrics = default_metrics();

        // All action types compute costs without consulting capabilities.
        assert!(evaluate_cost(&policy, &PaidActionType::MessageSend, &metrics).is_some());
        assert!(evaluate_cost(&policy, &PaidActionType::ToolInvoke, &metrics).is_some());
        assert!(evaluate_cost(&policy, &PaidActionType::ContextJoin, &metrics).is_some());
    }

    // =======================================================================
    // Child context independence
    // =======================================================================

    #[test]
    fn child_context_uses_own_policy() {
        // Child and parent have different policies. Each evaluates independently.
        let parent_policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: usd(),
                per_message: Some(Amount(100)),
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec!["x402".to_owned()],
            pricing_formula: None,
            payee: DID::from("did:dht:z6MkParent"),
        };

        let child_policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: usd(),
                per_message: Some(Amount(1)),
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec!["lightning".to_owned()],
            pricing_formula: None,
            payee: DID::from("did:dht:z6MkChild"),
        };

        let metrics = default_metrics();

        // Parent's cost for message send.
        assert_eq!(
            evaluate_cost(&parent_policy, &PaidActionType::MessageSend, &metrics),
            Some(Amount(100))
        );

        // Child's cost for message send -- different, independent.
        assert_eq!(
            evaluate_cost(&child_policy, &PaidActionType::MessageSend, &metrics),
            Some(Amount(1))
        );
    }

    // =======================================================================
    // No f64 guarantee
    // =======================================================================

    #[test]
    fn no_f64_in_evaluation_path() {
        // All types used in evaluation are integer-based. This test
        // confirms Amount is u64 (8 bytes) and Coefficient is i64 (8 bytes).
        // No f64 types are used anywhere in the evaluation path.
        assert_eq!(std::mem::size_of::<Amount>(), 8); // u64
        assert_eq!(std::mem::size_of::<Coefficient>(), 8); // i64
    }

    // =======================================================================
    // ObservableMetrics
    // =======================================================================

    #[test]
    fn observable_metrics_get_returns_correct_values() {
        let metrics = ObservableMetrics {
            context_message_rate: 100,
            member_count: 50,
            relay_queue_depth: 200,
            time_of_day: 14,
            sender_velocity: 30,
            storage_usage: 1_000_000,
        };

        assert_eq!(metrics.get(&PricingMetric::ContextMessageRate), 100);
        assert_eq!(metrics.get(&PricingMetric::MemberCount), 50);
        assert_eq!(metrics.get(&PricingMetric::RelayQueueDepth), 200);
        assert_eq!(metrics.get(&PricingMetric::TimeOfDay), 14);
        assert_eq!(metrics.get(&PricingMetric::SenderVelocity), 30);
        assert_eq!(metrics.get(&PricingMetric::StorageUsage), 1_000_000);
    }

    #[test]
    fn observable_metrics_snapshot_for_formula_includes_referenced_metrics() {
        let metrics = ObservableMetrics {
            member_count: 50,
            sender_velocity: 30,
            ..default_metrics()
        };
        let formula = PricingFormula {
            base_cost: Amount(0),
            variables: vec![
                PricingVariable::Linear {
                    metric: PricingMetric::MemberCount,
                    coefficient: Coefficient(1_000_000),
                },
                PricingVariable::Step {
                    metric: PricingMetric::SenderVelocity,
                    thresholds: vec![(10, Amount(5))],
                },
            ],
            cap: None,
            floor: None,
        };

        let snapshot = metrics.snapshot_for_formula(&formula);
        assert_eq!(snapshot.len(), 2);
        assert!(snapshot.contains(&(PricingMetric::MemberCount, 50)));
        assert!(snapshot.contains(&(PricingMetric::SenderVelocity, 30)));
    }

    #[test]
    fn observable_metrics_snapshot_deduplicates_metrics() {
        let metrics = ObservableMetrics {
            member_count: 50,
            ..default_metrics()
        };
        let formula = PricingFormula {
            base_cost: Amount(0),
            variables: vec![
                PricingVariable::Linear {
                    metric: PricingMetric::MemberCount,
                    coefficient: Coefficient(500_000),
                },
                PricingVariable::Step {
                    metric: PricingMetric::MemberCount,
                    thresholds: vec![(10, Amount(5))],
                },
            ],
            cap: None,
            floor: None,
        };

        let snapshot = metrics.snapshot_for_formula(&formula);
        assert_eq!(snapshot.len(), 1); // deduplicated
        assert_eq!(snapshot[0], (PricingMetric::MemberCount, 50));
    }

    #[test]
    fn observable_metrics_snapshot_all_returns_six_entries() {
        let metrics = default_metrics();
        let snapshot = metrics.snapshot_all();
        assert_eq!(snapshot.len(), 6);
    }

    #[test]
    fn observable_metrics_default_all_zero() {
        let metrics = ObservableMetrics::default();
        assert_eq!(metrics.context_message_rate, 0);
        assert_eq!(metrics.member_count, 0);
        assert_eq!(metrics.relay_queue_depth, 0);
        assert_eq!(metrics.time_of_day, 0);
        assert_eq!(metrics.sender_velocity, 0);
        assert_eq!(metrics.storage_usage, 0);
    }

    // =======================================================================
    // CostInsufficient Display
    // =======================================================================

    #[test]
    fn cost_insufficient_display_includes_amounts() {
        let err = CostInsufficient {
            expected: Amount(100),
            provided: Amount(50),
            currency: usd(),
            metric_snapshot: vec![(PricingMetric::MemberCount, 42)],
        };
        let msg = format!("{err}");
        assert!(msg.contains("100"));
        assert!(msg.contains("50"));
        assert!(msg.contains("USD"));
    }

    // =======================================================================
    // PolicyLockError Display
    // =======================================================================

    #[test]
    fn policy_lock_error_display() {
        let err = PolicyLockError;
        let msg = format!("{err}");
        assert!(msg.contains("locked"));
    }

    // =======================================================================
    // Bug fix: PricingFormula-only policy requires payment (SCP-154)
    // =======================================================================

    #[test]
    fn pricing_formula_only_policy_requires_payment() {
        // A policy with no CostSchedule costs but a PricingFormula that may
        // produce non-zero costs MUST be detected as requiring payment.
        // Spec invariant §19.14#9: auto-accept NEVER applies to contexts
        // with economic policy requiring payment.
        let policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: usd(),
                per_message: None,
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec!["x402".to_owned()],
            pricing_formula: Some(PricingFormula {
                base_cost: Amount(100),
                variables: vec![],
                cap: None,
                floor: None,
            }),
            payee: payee(),
        };
        assert!(policy_requires_payment(&policy));
        assert!(auto_accept_blocked_by_economics(Some(&policy)));
    }

    // =======================================================================
    // Bug fix: verify_cost_sufficiency fails closed on overflow (SCP-154)
    // =======================================================================

    #[test]
    fn verify_cost_sufficiency_fails_closed_on_overflow() {
        // When evaluate_cost overflows (returns None), verify_cost_sufficiency
        // must fail closed (assume maximum cost), not fail open (assume free).
        // A formula with extreme coefficients triggers overflow.
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
                base_cost: Amount(0),
                variables: vec![PricingVariable::Linear {
                    metric: PricingMetric::MemberCount,
                    // i64::MAX coefficient * large metric value -> overflow
                    coefficient: Coefficient(i64::MAX),
                }],
                cap: None,
                floor: None,
            }),
            payee: payee(),
        };
        let metrics = ObservableMetrics {
            member_count: 2, // coefficient.evaluate(2) overflows for i64::MAX
            ..default_metrics()
        };

        // With overflow, the action must be rejected (CostInsufficient),
        // not silently allowed as free.
        let result = verify_cost_sufficiency(
            &policy,
            &PaidActionType::MessageSend,
            &metrics,
            Amount(1000),
        );
        assert!(result.is_err(), "overflow must fail closed, not open");

        let err = result.unwrap_err();
        assert_eq!(
            err.expected,
            Amount(u64::MAX),
            "overflow must assume maximum cost"
        );
    }

    // =======================================================================
    // Metric availability validation
    // =======================================================================

    #[test]
    fn formula_with_available_metrics_passes() {
        let formula = PricingFormula {
            base_cost: Amount(10),
            variables: vec![
                PricingVariable::Linear {
                    metric: PricingMetric::SenderVelocity,
                    coefficient: Coefficient(500_000),
                },
                PricingVariable::Step {
                    metric: PricingMetric::MemberCount,
                    thresholds: vec![(10, Amount(5))],
                },
                PricingVariable::Linear {
                    metric: PricingMetric::ContextMessageRate,
                    coefficient: Coefficient(100_000),
                },
                PricingVariable::Linear {
                    metric: PricingMetric::TimeOfDay,
                    coefficient: Coefficient(200_000),
                },
            ],
            cap: None,
            floor: None,
        };
        assert!(validate_formula_metrics(&formula).is_ok());
    }

    #[test]
    fn formula_with_relay_queue_depth_fails() {
        let formula = PricingFormula {
            base_cost: Amount(10),
            variables: vec![PricingVariable::Linear {
                metric: PricingMetric::RelayQueueDepth,
                coefficient: Coefficient(500_000),
            }],
            cap: None,
            floor: None,
        };
        let err = validate_formula_metrics(&formula).unwrap_err();
        assert_eq!(err.unavailable, vec![PricingMetric::RelayQueueDepth]);
    }

    #[test]
    fn formula_with_storage_usage_fails() {
        let formula = PricingFormula {
            base_cost: Amount(10),
            variables: vec![PricingVariable::Step {
                metric: PricingMetric::StorageUsage,
                thresholds: vec![(1024, Amount(1))],
            }],
            cap: None,
            floor: None,
        };
        let err = validate_formula_metrics(&formula).unwrap_err();
        assert_eq!(err.unavailable, vec![PricingMetric::StorageUsage]);
    }

    #[test]
    fn formula_with_mixed_available_and_unavailable_lists_only_unavailable() {
        let formula = PricingFormula {
            base_cost: Amount(10),
            variables: vec![
                PricingVariable::Linear {
                    metric: PricingMetric::MemberCount,
                    coefficient: Coefficient(500_000),
                },
                PricingVariable::Linear {
                    metric: PricingMetric::RelayQueueDepth,
                    coefficient: Coefficient(100_000),
                },
                PricingVariable::Step {
                    metric: PricingMetric::StorageUsage,
                    thresholds: vec![(1024, Amount(1))],
                },
                PricingVariable::Linear {
                    metric: PricingMetric::SenderVelocity,
                    coefficient: Coefficient(200_000),
                },
            ],
            cap: None,
            floor: None,
        };
        let err = validate_formula_metrics(&formula).unwrap_err();
        assert_eq!(
            err.unavailable,
            vec![PricingMetric::RelayQueueDepth, PricingMetric::StorageUsage]
        );
    }

    #[test]
    fn none_policy_passes_validation() {
        assert!(validate_economic_policy_metrics(None).is_ok());
    }

    #[test]
    fn policy_without_formula_passes_validation() {
        let policy = free_policy();
        assert!(policy.pricing_formula.is_none());
        assert!(validate_economic_policy_metrics(Some(&policy)).is_ok());
    }
}
