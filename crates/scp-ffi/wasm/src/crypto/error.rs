//! WASM MLS crypto error types.
//!
//! All errors produced by the WASM crypto module are represented as
//! [`WasmCryptoError`]. These map to `JsError` for propagation to JavaScript.

use std::fmt;
use wasm_bindgen::JsError;

/// Errors produced by WASM MLS and sender key operations.
///
/// Each variant covers a distinct failure mode. Error messages include
/// the underlying cause (stringified to avoid leaking `OpenMLS` types).
#[derive(Debug)]
pub enum WasmCryptoError {
    /// Failed to create a new MLS group.
    GroupCreationFailed(String),
    /// Failed to add a member to the group.
    AddMemberFailed(String),
    /// Failed to remove a member from the group.
    RemoveMemberFailed(String),
    /// Failed to generate a key package.
    KeyPackageGenerationFailed(String),
    /// Failed to process a Welcome message.
    WelcomeProcessingFailed(String),
    /// Credential serialization or deserialization failed.
    CredentialSerializationFailed(String),
    /// The MLS group has been destroyed and cannot be used.
    GroupDestroyed,
    /// MLS encryption failed.
    EncryptionFailed(String),
    /// MLS decryption failed.
    DecryptionFailed(String),
    /// Sender key layer error.
    SenderKeyError(String),
    /// Failed to merge a pending commit.
    MergePendingCommitFailed(String),
    /// The processed message was not an application message.
    NotApplicationMessage,
    /// Ciphertext too short for sender key decryption.
    CiphertextTooShort {
        /// Actual ciphertext length.
        actual: usize,
        /// Minimum required length.
        minimum: usize,
    },
    /// Sender key authentication tag verification failed.
    AuthenticationFailed,
    /// Invalid DID format.
    InvalidDidFormat(String),
}

impl fmt::Display for WasmCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GroupCreationFailed(msg) => write!(f, "group creation failed: {msg}"),
            Self::AddMemberFailed(msg) => write!(f, "add member failed: {msg}"),
            Self::RemoveMemberFailed(msg) => write!(f, "remove member failed: {msg}"),
            Self::KeyPackageGenerationFailed(msg) => {
                write!(f, "key package generation failed: {msg}")
            }
            Self::WelcomeProcessingFailed(msg) => write!(f, "welcome processing failed: {msg}"),
            Self::CredentialSerializationFailed(msg) => {
                write!(f, "credential serialization failed: {msg}")
            }
            Self::GroupDestroyed => write!(f, "group has been destroyed"),
            Self::EncryptionFailed(msg) => write!(f, "encryption failed: {msg}"),
            Self::DecryptionFailed(msg) => write!(f, "decryption failed: {msg}"),
            Self::SenderKeyError(msg) => write!(f, "sender key error: {msg}"),
            Self::MergePendingCommitFailed(msg) => {
                write!(f, "merge pending commit failed: {msg}")
            }
            Self::NotApplicationMessage => write!(f, "not an application message"),
            Self::CiphertextTooShort { actual, minimum } => {
                write!(f, "ciphertext too short: {actual} bytes, minimum {minimum}")
            }
            Self::AuthenticationFailed => {
                write!(f, "authentication tag verification failed")
            }
            Self::InvalidDidFormat(did) => write!(f, "invalid DID format: {did}"),
        }
    }
}

impl From<WasmCryptoError> for JsError {
    fn from(err: WasmCryptoError) -> Self {
        Self::new(&err.to_string())
    }
}
