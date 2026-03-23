//! Re-exports sender key types from `scp-protocol`.
//!
//! The sender-side AES-256-GCM key layer is implemented in `scp-protocol`
//! and shared across all bridges. This module re-exports the public API
//! and provides an error adapter to `WasmCryptoError`.

pub use scp_protocol::crypto::sender_keys::encrypt::{decrypt_sender_layer, encrypt_sender_layer};
pub use scp_protocol::crypto::sender_keys::{SenderKey, SenderKeyError, generate_sender_key};

use super::error::WasmCryptoError;

impl From<SenderKeyError> for WasmCryptoError {
    fn from(err: SenderKeyError) -> Self {
        match err {
            SenderKeyError::AuthenticationFailed => WasmCryptoError::AuthenticationFailed,
            SenderKeyError::CiphertextTooShort { actual, minimum } => {
                WasmCryptoError::CiphertextTooShort { actual, minimum }
            }
            other => WasmCryptoError::SenderKeyError(other.to_string()),
        }
    }
}
