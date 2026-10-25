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
    /// For example, calling `sign` with an HPKE P-256 key handle, or calling
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

    /// A push notification operation failed; `kind` names which failure.
    #[error("push error ({kind}): {detail}")]
    PushError {
        /// Which push failure occurred.
        kind: PushFailureKind,
        /// The backend's description of the failure.
        detail: String,
    },

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

/// Which push failure occurred (ADR-006 2026-10-12 amendment in
/// `.docs/adrs/phase-1.md`). The kind alone decides the error code a bridge reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushFailureKind {
    /// A received push payload is not the platform's wake signal.
    WakePayloadInvalid,
    /// The relay rejected a push registration: its signature, key state or
    /// encoding is invalid.
    RegistrationRejected,
    /// The relay cannot verify a push registration's signature yet.
    VerifierUnavailable,
    /// The relay has no push sender for the registration's platform.
    PlatformUnavailable,
    /// The device's push provider (APNs, FCM) failed, such as a failed token
    /// registration.
    ProviderFailed,
}

impl std::fmt::Display for PushFailureKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::WakePayloadInvalid => "wake payload invalid",
            Self::RegistrationRejected => "registration rejected",
            Self::VerifierUnavailable => "verifier unavailable",
            Self::PlatformUnavailable => "platform unavailable",
            Self::ProviderFailed => "provider failed",
        })
    }
}

impl From<&PlatformError> for scp_crypto::CustodyFailure {
    /// Classifies a platform error for the error types that cannot hold a
    /// [`PlatformError`]: [`PlatformError::KeyNotFound`] is key-not-found,
    /// [`PlatformError::PseudonymRejected`] is a rejected pseudonym,
    /// [`PlatformError::StorageClosed`], [`PlatformError::StorageLockHeld`],
    /// [`PlatformError::AttestationError`], [`PlatformError::Unsupported`] and
    /// each [`PushFailureKind`] of [`PlatformError::PushError`] keep their own
    /// kinds so a bridge reports the same code whether the error arrives bare
    /// or wrapped, and every other variant is a custody failure.
    fn from(e: &PlatformError) -> Self {
        use scp_crypto::CustodyFailureKind as Kind;
        let kind = match e {
            PlatformError::KeyNotFound => Kind::KeyNotFound,
            PlatformError::PseudonymRejected(_) => Kind::PseudonymRejected,
            PlatformError::StorageClosed => Kind::StorageClosed,
            PlatformError::StorageLockHeld { .. } => Kind::StorageLockHeld,
            PlatformError::AttestationError(_) => Kind::AttestationFailed,
            PlatformError::Unsupported(_) => Kind::Unsupported,
            PlatformError::PushError { kind, .. } => match kind {
                PushFailureKind::WakePayloadInvalid => Kind::PushWakePayloadInvalid,
                PushFailureKind::RegistrationRejected => Kind::PushRegistrationRejected,
                PushFailureKind::VerifierUnavailable => Kind::PushVerifierUnavailable,
                PushFailureKind::PlatformUnavailable => Kind::PushPlatformUnavailable,
                PushFailureKind::ProviderFailed => Kind::PushProviderFailed,
            },
            PlatformError::WrongKeyType { .. }
            | PlatformError::NotIdentityKey
            | PlatformError::StorageError(_)
            | PlatformError::CustodyError(_) => Kind::Failed,
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

impl From<PlatformError> for scp_kel::KeyEventSignError {
    /// The key-event signing error a custody's [`PlatformError`] means
    /// (SCP-345): a wrong-type or non-identity key is
    /// [`WrongKeyType`](scp_kel::KeyEventSignError::WrongKeyType), an unknown
    /// handle is [`MemberNotFound`](scp_kel::KeyEventSignError::MemberNotFound),
    /// an unsupported operation keeps its message, and every other failure is
    /// a [`Substrate`](scp_kel::KeyEventSignError::Substrate) failure carrying
    /// the [`CustodyFailure`](scp_crypto::CustodyFailure) the same error
    /// classifies as, so a bridge reports the one code
    /// `scp_ffi_common::error_codes::custody_failure_code` assigns. The match names every variant, so a new one is
    /// classified here before it compiles.
    fn from(e: PlatformError) -> Self {
        match e {
            PlatformError::WrongKeyType { .. } | PlatformError::NotIdentityKey => {
                Self::WrongKeyType
            }
            PlatformError::KeyNotFound => Self::MemberNotFound,
            PlatformError::Unsupported(what) => Self::Unsupported(what),
            PlatformError::StorageError(_)
            | PlatformError::StorageClosed
            | PlatformError::StorageLockHeld { .. }
            | PlatformError::AttestationError(_)
            | PlatformError::PushError { .. }
            | PlatformError::CustodyError(_)
            | PlatformError::PseudonymRejected(_) => {
                Self::Substrate(scp_crypto::CustodyFailure::from(&e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use scp_crypto::{CustodyFailure, CustodyFailureKind};
    use scp_kel::KeyEventSignError;

    use super::{PlatformError, PushFailureKind};
    use crate::traits::KeyType;

    fn substrate(kind: CustodyFailureKind, detail: &str) -> KeyEventSignError {
        KeyEventSignError::Substrate(CustodyFailure {
            kind,
            detail: detail.to_owned(),
        })
    }

    #[test]
    fn platform_errors_map_to_key_event_sign_errors() {
        let push = || PlatformError::PushError {
            kind: PushFailureKind::ProviderFailed,
            detail: "x".into(),
        };
        let cases = [
            (
                PlatformError::WrongKeyType {
                    expected: KeyType::P256Signing,
                    actual: KeyType::Ed25519,
                },
                KeyEventSignError::WrongKeyType,
            ),
            (
                PlatformError::NotIdentityKey,
                KeyEventSignError::WrongKeyType,
            ),
            (
                PlatformError::KeyNotFound,
                KeyEventSignError::MemberNotFound,
            ),
            (
                PlatformError::Unsupported("key-event signing"),
                KeyEventSignError::Unsupported("key-event signing"),
            ),
            (
                PlatformError::StorageError("disk".into()),
                substrate(CustodyFailureKind::Failed, "storage error: disk"),
            ),
            (
                PlatformError::StorageClosed,
                substrate(
                    CustodyFailureKind::StorageClosed,
                    &PlatformError::StorageClosed.to_string(),
                ),
            ),
            (
                PlatformError::CustodyError("host".into()),
                substrate(CustodyFailureKind::Failed, "custody error: host"),
            ),
            (
                push(),
                substrate(CustodyFailureKind::PushProviderFailed, &push().to_string()),
            ),
            (
                PlatformError::PseudonymRejected("p".into()),
                substrate(
                    CustodyFailureKind::PseudonymRejected,
                    &PlatformError::PseudonymRejected("p".into()).to_string(),
                ),
            ),
        ];
        for (platform, expected) in cases {
            assert_eq!(KeyEventSignError::from(platform), expected);
        }
    }
}
