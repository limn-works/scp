//! Economic governance types for SCP — pure protocol types.
//!
//! Pure module declarations (types, policy, budget, pricing, estimate, antispam).
//! Async modules (credentials, integration, adapter, receipt) stay in scp-runtime.

pub mod antispam;
pub mod budget;
pub mod estimate;
pub mod policy;
pub mod pricing;
pub mod types;

// Re-exports for backward compatibility.
pub use antispam::{
    ContextMessagePricingConfig, EscalationConfig, EscalationThreshold, HardRateLimitConfig,
    SenderVelocityTracker, TokenBucketLimiter,
};
pub use policy::{
    AVAILABLE_METRICS, UnavailableMetricError, validate_economic_policy_metrics,
    validate_formula_metrics,
};
pub use types::{
    Amount, Coefficient, CostSchedule, CurrencyCode, EconomicPolicy, PaidActionType,
    PricingFormula, PricingMetric, PricingVariable, SubscriptionCost, SubscriptionPeriod,
};
