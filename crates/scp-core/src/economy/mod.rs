//! Economic governance types for SCP.
//!
//! This module defines the core economic types used across all SCP economic
//! operations: amounts, currency codes, coefficients, cost schedules, pricing
//! formulas, and economic policy. All types use integer arithmetic exclusively
//! for cross-party determinism.
//!
//! See spec section 19 (Economic Governance) and ADR-033 in
//! `.docs/adrs/phase-3.md`.

pub mod types;

pub use types::{
    Amount, COEFFICIENT_SCALE, Coefficient, CostSchedule, CurrencyCode, EconomicPolicy,
    PaymentAdapterRef, PricingFormula, PricingMetric, PricingVariable, SubscriptionCost,
    SubscriptionPeriod,
};
