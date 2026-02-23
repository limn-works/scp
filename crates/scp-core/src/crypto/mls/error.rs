//! MLS-specific error types for the SCP protocol.
//!
//! [`MlsError`] wraps `OpenMLS` errors and adds SCP-specific variants for
//! epoch management, stale messages, and group lifecycle. See ADR-001.

use openmls::prelude::{
    AddMembersError, CreateMessageError, MergePendingCommitError, NewGroupError,
    ProcessMessageError, RemoveMembersError, WelcomeError,
};
use openmls_rust_crypto::MemoryStorageError;

/// The storage error type used throughout the SCP MLS wrapper.
///
/// Phase 1 uses [`MemoryStorageError`] from `openmls_rust_crypto`.
/// Future phases will bridge to `scp-platform`'s `Storage` trait.
pub type StorageError = MemoryStorageError;

/// Errors arising from SCP's MLS wrapper operations.
///
/// This enum unifies `OpenMLS` errors with SCP-specific error conditions
/// such as epoch expiry, stale messages, and group destruction. All
/// public MLS wrapper functions return `Result<T, MlsError>`.
#[derive(Debug, thiserror::Error)]
pub enum MlsError {
    /// Failed to create a new MLS group.
    #[error("failed to create MLS group: {0}")]
    CreateGroup(#[from] NewGroupError<StorageError>),

    /// Failed to add members to an MLS group.
    #[error("failed to add members: {0}")]
    AddMembers(#[from] AddMembersError<StorageError>),

    /// Failed to remove members from an MLS group.
    #[error("failed to remove members: {0}")]
    RemoveMembers(#[from] RemoveMembersError<StorageError>),

    /// Failed to create an application message (encrypt).
    #[error("failed to create message: {0}")]
    CreateMessage(#[from] CreateMessageError),

    /// Failed to process an incoming MLS message (decrypt / commit).
    #[error("failed to process message: {0}")]
    ProcessMessage(#[from] ProcessMessageError<StorageError>),

    /// Failed to merge a pending commit (epoch advance).
    #[error("failed to merge pending commit: {0}")]
    MergePendingCommit(#[from] MergePendingCommitError<StorageError>),

    /// Failed to process a Welcome message for group joining.
    #[error("failed to process Welcome: {0}")]
    Welcome(#[from] WelcomeError<StorageError>),

    /// The MLS epoch has expired and the grace window has closed.
    ///
    /// Messages encrypted under this epoch are no longer decryptable.
    /// See ADR-001 criterion 6 for grace window semantics.
    #[error("epoch {epoch} has expired for group {group_id}")]
    EpochExpired {
        /// The expired epoch number.
        epoch: u64,
        /// The group identifier (hex-encoded).
        group_id: String,
    },

    /// A message was received that references a past epoch beyond the
    /// grace window. The message is unrecoverable.
    #[error("stale message from epoch {message_epoch} (current: {current_epoch})")]
    StaleMessage {
        /// The epoch referenced by the stale message.
        message_epoch: u64,
        /// The group's current epoch.
        current_epoch: u64,
    },

    /// The MLS group has been destroyed and all key material deleted.
    ///
    /// This occurs after ephemeral context closure (ADR-001 criterion 9).
    /// No further operations are possible on this group.
    #[error("group has been destroyed")]
    GroupDestroyed,

    /// A credential operation failed (e.g., invalid DID or UCAN).
    #[error("credential error: {0}")]
    Credential(String),

    /// An operation was attempted on a group the local client is not
    /// a member of.
    #[error("not a member of the group")]
    NotAMember,

    /// The key package is invalid or has already been consumed.
    #[error("invalid or consumed key package")]
    InvalidKeyPackage,

    /// Storage backend error from the [`super::storage::MlsStorageBridge`].
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    /// Serialization or deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(String),
}
