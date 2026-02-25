//! MLS-specific error types for the SCP MLS wrapper.
//!
//! All errors produced by the MLS group lifecycle operations are represented
//! as [`MlsError`], defined via `thiserror`. These errors wrap `OpenMLS` errors
//! and add SCP-specific failure modes. See ADR-001 for the MLS wrapper design.

/// Errors produced by MLS group lifecycle operations.
///
/// Each variant covers a distinct failure mode in the SCP MLS wrapper.
/// `OpenMLS`-internal errors are wrapped as strings to avoid leaking `OpenMLS`
/// types through the public API boundary.
#[derive(Debug, thiserror::Error)]
pub enum MlsError {
    /// Failed to create a new MLS group.
    #[error("group creation failed: {0}")]
    GroupCreationFailed(String),

    /// Failed to add a member to the group.
    #[error("add member failed: {0}")]
    AddMemberFailed(String),

    /// Failed to remove a member from the group.
    #[error("remove member failed: {0}")]
    RemoveMemberFailed(String),

    /// Failed to merge a pending commit after a group operation.
    #[error("merge pending commit failed: {0}")]
    MergePendingCommitFailed(String),

    /// The group is not in an active state (e.g., it has been destroyed or
    /// a pending commit exists that must be merged first).
    #[error("group is not active")]
    GroupNotActive,

    /// Failed to generate a key package for offline member addition.
    #[error("key package generation failed: {0}")]
    KeyPackageGenerationFailed(String),

    /// Failed to process a Welcome message when joining a group.
    #[error("welcome processing failed: {0}")]
    WelcomeProcessingFailed(String),

    /// The provided credential is invalid or malformed.
    #[error("invalid credential: {0}")]
    InvalidCredential(String),

    /// Serialization or deserialization of SCP credential data failed.
    #[error("credential serialization failed: {0}")]
    CredentialSerializationFailed(String),

    /// A storage operation on the MLS provider failed.
    #[error("storage error: {0}")]
    StorageError(String),

    /// The group has already been destroyed and cannot be used.
    #[error("group has been destroyed")]
    GroupDestroyed,

    /// Failed to encrypt plaintext as an MLS application message.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// Failed to decrypt an MLS ciphertext.
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// The processed message was not an application message.
    #[error("not an application message")]
    NotApplicationMessage,

    /// Failed to process an incoming Commit message.
    #[error("commit processing failed: {0}")]
    CommitProcessingFailed(String),

    /// Failed to issue an MLS Update proposal or commit.
    #[error("update failed: {0}")]
    UpdateFailed(String),

    /// A message arrived referencing an epoch whose grace window has closed.
    ///
    /// The old epoch keys have been destroyed for forward secrecy. The message
    /// is unrecoverable.
    #[error("stale epoch message from {sender_did} at epoch {epoch}")]
    StaleEpochMessage {
        /// The DID of the sender whose message arrived too late.
        sender_did: String,
        /// The epoch number the message was encrypted under.
        epoch: u64,
    },

    /// The key package buffer is empty and cannot provide a key package.
    #[error("key package buffer exhausted")]
    KeyPackageBufferExhausted,
}
