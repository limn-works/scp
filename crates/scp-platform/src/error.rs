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

    /// A pseudonym derivation named a key that is not an identity key.
    ///
    /// Only the identity key (`#0`, minted by
    /// [`KeyCustody::generate_identity_keypair`](crate::traits::KeyCustody::generate_identity_keypair))
    /// may be the source of a pseudonym (`09-security-model.md` §9.10.4.A); an
    /// operational key of any type fails with this error before its type is
    /// checked.
    #[error("not an identity key: only the identity key is a pseudonym-derivation source")]
    NotIdentityKey,

    /// A storage operation failed.
    #[error("storage error: {0}")]
    StorageError(String),

    /// The store has released its database connection, so it refuses every
    /// operation (spec §17.6 "One Opener per Durable Directory": a closed
    /// store refuses operations and never reopens its database implicitly).
    ///
    /// Open a new store on the directory to continue.
    #[error(
        "storage closed: the store released its database connection and refuses \
         every operation — open a new store on the directory"
    )]
    StorageClosed,

    /// Another store holds the directory's exclusive advisory lock, in this
    /// process or another (spec §17.6 "One Opener per Durable Directory": one
    /// opener per directory). The open fails at once; it neither waits for
    /// the lock nor opens the database.
    ///
    /// Within one process the lock stays held until the previous owner's
    /// shutdown completes and its last writer exits.
    #[error(
        "storage lock still held: another store holds the advisory lock on {lock_path} \
         — shut down the instance that opened {dir} and let its shutdown complete \
         before opening the directory again"
    )]
    StorageLockHeld {
        /// The database directory whose lock is held.
        dir: String,
        /// The lock file (`{dir}/scp.db.lock`).
        lock_path: String,
    },

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

    /// A bridge rejected a pseudonym that a host custody provider derived
    /// (spec §9.10.4): the returned key id or point is malformed,
    /// `get_public_key(key_id)` fails or reports a different point, or the key id is
    /// already bound to another pseudonym point.
    #[error("pseudonym rejected: {0}")]
    PseudonymRejected(String),

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

impl From<&PlatformError> for scp_crypto::CustodyFailure {
    /// Classifies a custody error for the error types that cannot hold a
    /// [`PlatformError`]: [`PlatformError::KeyNotFound`] is key-not-found,
    /// [`PlatformError::PseudonymRejected`] is a rejected pseudonym,
    /// [`PlatformError::StorageClosed`] and [`PlatformError::StorageLockHeld`]
    /// keep their own kinds so a bridge reports the same storage code whether
    /// the error arrives bare or wrapped, and every other variant is a custody
    /// failure.
    fn from(e: &PlatformError) -> Self {
        let kind = match e {
            PlatformError::KeyNotFound => scp_crypto::CustodyFailureKind::KeyNotFound,
            PlatformError::PseudonymRejected(_) => {
                scp_crypto::CustodyFailureKind::PseudonymRejected
            }
            PlatformError::StorageClosed => scp_crypto::CustodyFailureKind::StorageClosed,
            PlatformError::StorageLockHeld { .. } => {
                scp_crypto::CustodyFailureKind::StorageLockHeld
            }
            PlatformError::WrongKeyType { .. }
            | PlatformError::NotIdentityKey
            | PlatformError::StorageError(_)
            | PlatformError::AttestationError(_)
            | PlatformError::PushError(_)
            | PlatformError::CustodyError(_)
            | PlatformError::Unsupported(_) => scp_crypto::CustodyFailureKind::Failed,
        };
        Self {
            kind,
            detail: e.to_string(),
        }
    }
}

impl From<PlatformError> for scp_crypto::CustodyFailure {
    fn from(e: PlatformError) -> Self {
        Self::from(&e)
    }
}
