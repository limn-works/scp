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

    /// The provided DID does not match the expected `did:dht:z...` format.
    #[error("invalid DID format: {0}")]
    InvalidDidFormat(String),

    /// An MLS `LeafNode` extension is malformed or failed validation.
    #[error("extension error: {0}")]
    ExtensionError(String),

    /// A member with the given leaf index was not found in the group.
    #[error("member not found at leaf index {0}")]
    MemberNotFound(u32),

    /// A join was attempted with a `KeyPackage` whose HPKE init key is already
    /// in the durable consumed-init-key set — a replay of a single-use
    /// `KeyPackage`, rejected at the crypto layer (ADR-049 §9 two-anchor
    /// single-use model).
    #[error("key package replay: init key already consumed")]
    KeyPackageReplay,

    /// A `KeyPackage` `Lifetime` failed validation: it is expired, not yet
    /// valid, or its total range (`not_after - not_before`) is empty, inverted,
    /// or exceeds the RFC 9420 maximum acceptable range (ADR-057 §Prereq-1).
    /// The variant has two sources:
    /// - [`validate_key_package_lifetime`](crate::lifetime::validate_key_package_lifetime),
    ///   SCP's hardened counterpart to openmls's un-injectable internal
    ///   `Lifetime::validate`, with `now` read from the injected hardened
    ///   [`Clock`](scp_clock::Clock);
    /// - `scp-runtime`'s native `ProductionMlsBackend::join_from_welcome`,
    ///   which maps openmls's internal-clock rejection of the joiner's own
    ///   `KeyPackage` to this variant with that `KeyPackage`'s bounds and
    ///   `now` read from openmls's clock (`0` when that clock reads before
    ///   the Unix epoch).
    ///
    /// From [`join_group`](crate::group::join_group),
    /// [`join_group_from_bytes`](crate::group::join_group_from_bytes) and
    /// `MlsBackend::join_from_welcome` it always names the joiner's own
    /// `KeyPackage`; another member's tree leaf is
    /// [`MlsError::TreeLeafLifetimeRangeInvalid`]. From the add and commit
    /// paths it names the added member's `KeyPackage`, and from a standalone
    /// `KeyPackage` validation it names the `KeyPackage` validated.
    #[error(
        "key package lifetime invalid: not_before={not_before}, not_after={not_after}, now={now}"
    )]
    KeyPackageLifetimeInvalid {
        /// The `Lifetime`'s `not_before` bound (Unix seconds).
        not_before: u64,
        /// The `Lifetime`'s `not_after` bound (Unix seconds).
        not_after: u64,
        /// The current time of the clock that rejected the `Lifetime` (Unix
        /// seconds): the injected clock, or, when `scp-runtime`'s native join
        /// reports openmls's internal-clock rejection of the joiner's own
        /// `KeyPackage`, the time openmls read (`0` when openmls's clock reads
        /// before the Unix epoch).
        now: u64,
    },

    /// Another member's KeyPackage-sourced leaf of a Welcome's ratchet tree has
    /// a malformed `Lifetime` range: it is empty or inverted (`not_after` is
    /// not later than `not_before`), or
    /// `not_after - not_before` exceeds
    /// [`KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS`](crate::lifetime::KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS)
    /// (RFC 9420 §7.2). Raised by
    /// [`join_group_from_bytes`](crate::group::join_group_from_bytes), which
    /// reads no clock for another member's tree leaf (ADR-057 §Prereq-1). A
    /// fault in the joiner's own leaf is
    /// [`KeyPackageLifetimeInvalid`](Self::KeyPackageLifetimeInvalid) instead.
    /// `leaf_index` names the offending leaf in the Welcome's ratchet tree.
    #[error(
        "tree leaf lifetime range is empty, inverted, or over the maximum: leaf_index={leaf_index}, not_before={not_before}, not_after={not_after}"
    )]
    TreeLeafLifetimeRangeInvalid {
        /// The offending leaf's index in the Welcome's ratchet tree
        /// (RFC 9420 `LeafIndex`); never the joiner's own leaf.
        leaf_index: u32,
        /// The leaf `Lifetime`'s `not_before` bound (Unix seconds).
        not_before: u64,
        /// The leaf `Lifetime`'s `not_after` bound (Unix seconds).
        not_after: u64,
    },

    /// Serializing or deserializing an [`crate::ScpMlsGroup`] state snapshot
    /// failed (the out-of-band persistence path used by the in-browser driver
    /// to snapshot the in-memory MLS provider to durable storage — ADR-057
    /// component 3, §17.9.1). Covers a `MessagePack` (de)serialization failure, a
    /// poisoned provider-storage lock, or a group that could not be reloaded
    /// from the restored provider (`MlsGroup::load` returned `None`).
    #[error("MLS state snapshot error: {0}")]
    Snapshot(String),

    /// A decrypted-and-verified MLS frame carried **no** convergent-timestamp
    /// AAD (its `FramedContent.authenticated_data` was empty), so the receiver
    /// has no authenticated committer timestamp to stamp on its mirrored
    /// event-log leaf. Raised by
    /// [`decode_convergent_timestamp_aad`](crate::convergent_timestamp::decode_convergent_timestamp_aad)
    /// on an empty AAD — a frame authored without `set_aad` (an old-path or
    /// forged message). Fail-closed: the receiver rejects rather than substitute
    /// its own clock, which would diverge its §9.9.3 Merkle root (ADR-057).
    #[error("convergent committer timestamp missing from MLS AAD")]
    ConvergentTimestampMissing,

    /// The MLS frame is this member's OWN message, echoed back by the relay.
    ///
    /// The untrusted relay delivers a PUBLISH to ALL subscribers of a routing id
    /// — INCLUDING the publisher (`deliver_to_subscribers` has no publisher
    /// exclusion). Every member publishes its `PseudonymAnnouncement` to the shared
    /// `context_routing_id` AND subscribes to it, so each announcement is echoed to
    /// its author, whose MLS state cannot decrypt its own outbound message
    /// (openmls 0.9.0 returns it as `ProcessedMessageContent::OwnPrivateMessage`,
    /// which `scp-mls` maps to this variant). This is a **benign,
    /// expected** outcome under the untrusted-relay model — the receive loop MUST
    /// treat it as a DROP (symmetric with an unknown-routing_id drop), NOT a
    /// failure. Distinct from [`Self::DecryptionFailed`] so callers can tell a
    /// self-echo apart from a genuine bad/tampered frame. (ADR-057; shared by the
    /// native runtime and the in-browser driver — see the receive paths that map
    /// this to a benign drop.)
    #[error("cannot decrypt own message (relay echo of a self-authored frame)")]
    CannotDecryptOwnMessage,

    /// A decrypted-and-verified MLS frame carried an AAD that is not a
    /// well-formed convergent-timestamp blob (wrong length, wrong magic, or an
    /// unrecognized version). Raised by
    /// [`decode_convergent_timestamp_aad`](crate::convergent_timestamp::decode_convergent_timestamp_aad).
    /// Fail-closed: the receiver never guesses a timestamp from malformed bytes
    /// (ADR-057).
    #[error("convergent committer timestamp malformed: {0}")]
    ConvergentTimestampMalformed(String),

    /// The per-context pseudonym could not be derived from this member's MLS
    /// signing key (ADR-057 Option A, §9.10.4.A). Raised by
    /// [`ScpMlsGroup::derive_pseudonym`](crate::group::ScpMlsGroup::derive_pseudonym)
    /// if the signer's private seed cannot be recovered, or is not the expected
    /// 32-byte Ed25519 seed (a non-Ed25519 or malformed signer — SCP groups are
    /// Ed25519-only per `SCP_CIPHERSUITE`). Fail-closed: never truncate a
    /// wrong-size key into the derivation.
    #[error("pseudonym derivation failed: {0}")]
    PseudonymDerivationFailed(String),
}
