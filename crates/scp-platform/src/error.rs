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

    /// A caller supplied key material whose length the backend rejects.
    ///
    /// Raised at the construction boundary, before the backend opens any
    /// file, so a wrong-length key creates nothing on disk. `SqliteStorage`
    /// and `AppleStorage` both require exactly 32 bytes for the `SQLCipher`
    /// PRAGMA key (spec §17.6); an empty key would select `SQLCipher`'s
    /// no-encryption mode and store the database in plaintext, so the length
    /// check is the difference between an encrypted database and a plaintext
    /// one. `SqliteKeyCustody` requires exactly 32 bytes for its per-entry
    /// AES-256-GCM key.
    ///
    /// Callers match on this variant to distinguish a caller-supplied key of
    /// the wrong size from an I/O failure, which `StorageError` carries as a
    /// string.
    #[error("invalid key length: expected {expected} bytes, got {actual}")]
    InvalidKeyLength {
        /// The exact length in bytes the backend requires.
        expected: usize,
        /// The length in bytes the caller supplied.
        actual: usize,
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

    /// The custody backend does not support an optional operation.
    ///
    /// Used by [`KeyCustody::generate_ephemeral_ed25519_seed`](crate::traits::KeyCustody::generate_ephemeral_ed25519_seed)
    /// for HSM-backed implementations whose Ed25519 keys are non-extractable
    /// (Apple Secure Enclave, Android `StrongBox`). The carried message
    /// describes which operation was unsupported so SDK callers can route to
    /// a platform-specific alternative (`SecRandomCopyBytes`, etc.).
    #[error("unsupported operation: {0}")]
    Unsupported(&'static str),
}
