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
