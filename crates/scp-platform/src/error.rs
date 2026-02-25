//! Platform error types for SCP platform abstraction traits.
//!
//! All platform trait methods return [`PlatformError`] as their error type.
//! See ADR-006 for the platform adapter architecture.

use crate::traits::KeyType;

/// Errors returned by platform abstraction trait implementations.
///
/// Each variant covers a distinct failure mode across the four platform traits
/// ([`KeyCustody`](crate::traits::KeyCustody), [`DeviceAttestation`](crate::traits::DeviceAttestation),
/// [`Push`](crate::traits::Push), [`Storage`](crate::traits::Storage)).
/// See ADR-006 for the full platform adapter design.
#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    /// The specified key handle does not exist or has been destroyed.
    #[error("key not found")]
    KeyNotFound,

    /// An operation was attempted with a key of the wrong type.
    ///
    /// For example, calling `sign` with an X25519 key handle, or calling
    /// `dh_agree` with an Ed25519 key handle.
    #[error("wrong key type: expected {expected:?}, got {actual:?}")]
    WrongKeyType {
        /// The key type the operation requires.
        expected: KeyType,
        /// The key type that was actually provided.
        actual: KeyType,
    },

    /// A storage operation failed.
    #[error("storage error: {0}")]
    StorageError(String),

    /// A device attestation operation failed.
    #[error("attestation error: {0}")]
    AttestationError(String),

    /// A push notification operation failed.
    #[error("push error: {0}")]
    PushError(String),

    /// A key custody operation failed for reasons other than key-not-found or
    /// wrong-key-type.
    #[error("custody error: {0}")]
    CustodyError(String),
}
