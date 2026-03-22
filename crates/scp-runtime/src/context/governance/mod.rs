//! Governance interface contract — async runtime.
//!
//! Pure types are in scp-protocol::context::governance. This module retains
//! the async `timeout` module.

pub mod timeout;

// Re-export everything from scp-protocol::context::governance.
pub use scp_protocol::context::governance::*;
