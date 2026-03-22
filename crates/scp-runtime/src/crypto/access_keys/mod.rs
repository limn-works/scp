//! Per-member access key lifecycle — async runtime.
//!
//! Pure types are in scp-protocol::crypto::access_keys. This module retains
//! the async `lifecycle` and `wire` modules.

pub mod lifecycle;
pub mod wire;

// Re-export pure types from scp-protocol.
pub use scp_protocol::crypto::access_keys::wrapping;
pub use scp_protocol::crypto::access_keys::*;
