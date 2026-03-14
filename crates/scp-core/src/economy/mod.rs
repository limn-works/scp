//! Economic governance types for SCP.
//!
//! This module defines the core economic types used across all SCP economic
//! operations: amounts, currency codes, coefficients, cost schedules, pricing
//! formulas, economic policy, and the payment adapter trait. All monetary types
//! use integer arithmetic exclusively for cross-party determinism.
//!
//! # Modules
//!
//! - [`types`] — Core economic types: `Amount`, `CurrencyCode`, `Coefficient`,
//!   `CostSchedule`, `PricingFormula`, `EconomicPolicy`, etc.
//! - [`adapter`] — `PaymentAdapter` trait and supporting types.
//! - [`antispam`] — Sender velocity tracking and cost escalation.
//! - [`policy`] — Economic policy evaluation, cost schedule lookup, formula
//!   evaluation, lock enforcement, and auto-accept guard.
//! - [`estimate`] — SDK-facing `estimate_cost` function.
//! - [`pricing`] — Dynamic pricing: EIP-1559-style relay pricing and governed
//!   formula changes.
//! - [`receipt`] — Payment receipt verification and history queries.
//! - [`credentials`] — Adapter credential management: storage, validation,
//!   and the `configureAdapter` SDK function.
//!
//! See spec section 19 (Economic Governance) and ADR-033 in
//! `.docs/adrs/phase-3.md`.

pub mod adapter;
pub mod antispam;
pub mod budget;
pub mod credentials;
pub mod estimate;
pub mod integration;
pub mod policy;
pub mod pricing;
pub mod receipt;
pub mod types;

pub use adapter::{
    AdapterCapabilities, PaymentAdapter, PaymentAuthorization, PaymentError, PaymentMetadata,
    PaymentReceipt, RefundConfirmation, VerificationResult,
};
pub use antispam::{EscalationConfig, EscalationThreshold, SenderVelocityTracker};
pub use budget::{BudgetError, MemberBudgetTracker};
pub use credentials::{
    AdapterCredential, AdapterCredentialStore, CredentialError, EncryptedBlob, configure_adapter,
    retrieve_adapter_credential, validate_adapter,
};
pub use estimate::estimate_cost;
pub use integration::{
    ActionEnvelope, IntegrationError, PreparedAction, ProcessedAction, prepare_paid_action,
    process_paid_action,
};
pub use policy::{
    CostInsufficient, ObservableMetrics, PolicyLockError, auto_accept_blocked_by_economics,
    check_policy_lock, evaluate_cost, evaluate_formula, lookup_cost, policy_requires_payment,
    validate_policy_change, verify_cost_sufficiency,
};
pub use pricing::{
    FormulaChange, FormulaChangeStatus, PriceDirection, RelayPriceAdjustment, RelayPricingConfig,
    adjust_relay_price,
};
pub use receipt::{
    PaymentVerifier, PaymentVerifierDyn, ReceiptFilter, ReceiptVerification,
    ReceiptVerificationError, payment_history, verify_receipts, verify_receipts_dyn,
};
pub use types::{
    Amount, COEFFICIENT_SCALE, Coefficient, CostSchedule, CurrencyCode, EconomicPolicy,
    PaidActionType, PaymentAdapterRef, PricingFormula, PricingMetric, PricingVariable,
    SubscriptionCost, SubscriptionPeriod,
};
