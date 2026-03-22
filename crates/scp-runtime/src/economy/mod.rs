//! Economic governance — async runtime.
//!
//! Pure types are in scp-protocol::economy. This module retains the async
//! modules: adapter, credentials, integration, receipt.

pub mod adapter;
pub mod credentials;
pub mod integration;
pub mod receipt;

// Re-export pure modules from scp-protocol.
pub use scp_protocol::economy::antispam;
pub use scp_protocol::economy::budget;
pub use scp_protocol::economy::estimate;
pub use scp_protocol::economy::policy;
pub use scp_protocol::economy::pricing;
pub use scp_protocol::economy::types;
pub use scp_protocol::economy::{Amount, CurrencyCode, EconomicPolicy, PaidActionType};
