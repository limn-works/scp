//! Economic governance types for SCP.
//!
//! This module defines the core economic types used across all SCP economic
//! operations: amounts, currency codes, coefficients, cost schedules, pricing
//! formulas, economic policy, and the payment adapter trait. All monetary types
//! use integer arithmetic exclusively for cross-party determinism.
//!
//! See spec section 19 (Economic Governance) and ADR-033 in
//! `.docs/adrs/phase-3.md`.

pub mod adapter;
pub mod types;

pub use adapter::{
    AdapterCapabilities, PaymentAdapter, PaymentAuthorization, PaymentError, PaymentMetadata,
    PaymentReceipt, RefundConfirmation, VerificationResult,
};
pub use types::{
    Amount, COEFFICIENT_SCALE, Coefficient, CostSchedule, CurrencyCode, EconomicPolicy,
    PaidActionType, PaymentAdapterRef, PricingFormula, PricingMetric, PricingVariable,
    SubscriptionCost, SubscriptionPeriod,
};
