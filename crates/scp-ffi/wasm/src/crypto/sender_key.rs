//! Re-exports sender key types from `scp-protocol`.
//!
//! The sender-side AES-256-GCM key layer is implemented in `scp-protocol`
//! and shared across all bridges. This module re-exports the public API
//! and provides an error adapter to `WasmCryptoError`.

pub use scp_protocol::crypto::sender_keys::encrypt::{
    SENDER_HEADER_SIZE, build_sender_header, decrypt_sender_layer, encrypt_sender_layer,
    parse_sender_header,
};
pub use scp_protocol::crypto::sender_keys::{
    MAX_EPOCH_ADVANCE, SenderKey, SenderKeyError, SenderKeyStore, generate_sender_key,
};

use super::error::WasmCryptoError;

impl From<SenderKeyError> for WasmCryptoError {
    fn from(err: SenderKeyError) -> Self {
        match err {
            SenderKeyError::AuthenticationFailed => Self::AuthenticationFailed,
            SenderKeyError::CiphertextTooShort { actual, minimum } => {
                Self::CiphertextTooShort { actual, minimum }
            }
            other => Self::SenderKeyError(other.to_string()),
        }
    }
}
