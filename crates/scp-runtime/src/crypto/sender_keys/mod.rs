//! Per-sender AES-256 symmetric key layer — async runtime.
//!
//! Pure types are in scp-protocol::crypto::sender_keys. This module retains
//! the async `key_protocol` module and re-exports pure types.

pub mod key_protocol;

// Re-export submodules from scp-protocol sender_keys.
pub use scp_protocol::crypto::sender_keys::broadcast;
pub use scp_protocol::crypto::sender_keys::encrypt;
pub use scp_protocol::crypto::sender_keys::key_protocol_verify;
// Re-export all items (types, functions) from scp-protocol sender_keys.
pub use scp_protocol::crypto::sender_keys::*;
