//! Cryptographic modules for SCP — async runtime.
//!
//! Pure modules are in scp-protocol::crypto. This module retains the MLS
//! module and agent binding tests, and re-exports pure modules from scp-protocol.

pub mod mls;

pub mod access_keys;
pub mod sender_keys;
pub mod ucan;

// Re-export pure modules from scp-protocol for backward compatibility.
pub use scp_protocol::crypto::canonical;
pub use scp_protocol::crypto::ed25519;
pub use scp_protocol::crypto::envelope_seal;
pub use scp_protocol::crypto::key_continuity;
pub use scp_protocol::crypto::tofu;

#[cfg(test)]
mod agent_binding_tests;
