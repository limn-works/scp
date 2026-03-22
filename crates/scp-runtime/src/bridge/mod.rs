//! Bridge connector protocol — async runtime.
//!
//! Pure types are in scp-protocol::bridge. This module retains the async
//! modules: oauth, credentials.

pub mod credentials;
pub mod oauth;

// Re-export pure modules from scp-protocol.
pub use scp_protocol::bridge::*;
