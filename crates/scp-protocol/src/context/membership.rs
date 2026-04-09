//! Context membership tracking and receive stream buffer.
//!
//! This module provides:
//! - [`MemberInfo`] -- Per-member metadata (DID, role, sequence number).
//! - [`MembershipState`] -- Thread-safe member list for a context.
//! - [`ReceiveBuffer`] -- Bounded event buffer with oldest-drop overflow and
//!   `BufferOverflow` warning emission.
//!
//! The receive buffer implements the semantics from `.docs/sketch.md` section
//! "Context > Buffer semantics" and `.docs/standards/sdk-common.md` section
//! "Receive stream buffer tests":
//! - Default capacity: 1,000 events.
//! - Configurable: minimum 100, maximum 10,000.
//! - When full, the oldest unconsumed event is dropped.
//! - A `BufferOverflow` warning event is emitted with the count of dropped
//!   events since the last successful consumption.
//!
//! See SCP-020 and ADR-008 in `.docs/adrs/phase-2.md`.

use std::collections::{HashMap, VecDeque};

use serde::{Deserialize, Serialize};

use super::roles::UcanToken;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default receive buffer capacity (events).
pub const DEFAULT_BUFFER_CAPACITY: usize = 1_000;

/// Minimum configurable receive buffer capacity.
pub const MIN_BUFFER_CAPACITY: usize = 100;

/// Maximum configurable receive buffer capacity.
pub const MAX_BUFFER_CAPACITY: usize = 10_000;

// ---------------------------------------------------------------------------
// DID (re-exported from identity module -- SCP-187)
// ---------------------------------------------------------------------------

use scp_primitives::DID;

// ---------------------------------------------------------------------------
// KeyPackage (stub)
// ---------------------------------------------------------------------------

/// Key package wrapper for membership operations (ADR-001, §9.7).
///
/// Wraps an optional TLS-serialized MLS `KeyPackage` from `OpenMLS` alongside
/// the member's DID. The `mls_key_package_bytes` field is `None` when using
/// mock crypto providers in tests; the production `MlsCryptoProvider` requires
/// real MLS key package bytes.
///
/// The MLS key package is stored as TLS-serialized bytes rather than the
/// `OpenMLS` `KeyPackage` type directly because:
/// 1. `openmls::prelude::KeyPackage` does not implement `Eq` or `Serialize`.
/// 2. Byte representation is the canonical wire format for key packages.
/// 3. Deserialization to `KeyPackageIn` is done lazily by the crypto provider.
#[derive(Debug, Clone)]
pub struct KeyPackage {
    /// The DID of the member this key package belongs to.
    pub owner_did: DID,
    /// TLS-serialized MLS `KeyPackage` bytes, or `None` for mock/test usage.
    pub mls_key_package_bytes: Option<Vec<u8>>,
}

impl KeyPackage {
    /// Creates a new key package with both the owner DID and MLS key package bytes.
    #[must_use]
    pub const fn new(owner_did: DID, mls_key_package_bytes: Vec<u8>) -> Self {
        Self {
            owner_did,
            mls_key_package_bytes: Some(mls_key_package_bytes),
        }
    }

    /// Creates a key package with only the owner DID (no MLS key package).
    ///
    /// Used by mock crypto providers in tests where real MLS key packages
    /// are not needed.
    #[must_use]
    pub const fn mock(owner_did: DID) -> Self {
        Self {
            owner_did,
            mls_key_package_bytes: None,
        }
    }
}

impl PartialEq for KeyPackage {
    fn eq(&self, other: &Self) -> bool {
        self.owner_did == other.owner_did
            && self.mls_key_package_bytes == other.mls_key_package_bytes
    }
}

impl Eq for KeyPackage {}

// ---------------------------------------------------------------------------
// MemberInfo
// ---------------------------------------------------------------------------

/// Per-member metadata tracked within a context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberInfo {
    /// The member's decentralized identifier.
    pub did: DID,
    /// The member's assigned role name.
    pub role_name: String,
    /// UCAN tokens issued to this member.
    pub tokens: Vec<UcanToken>,
    /// Per-sender monotonic sequence number (spec section 9.8.5).
    /// Incremented on each `send_message` call by this member.
    pub sequence_number: u64,
}

// ---------------------------------------------------------------------------
// MembershipState
// ---------------------------------------------------------------------------

/// Tracks all members of a context.
///
/// Provides member list queries, member count, and role assignment per member.
/// Designed to be held inside a `ContextHandle`'s inner state or alongside it
/// in the `ContextManager`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipState {
    /// Members indexed by DID.
    members: HashMap<DID, MemberInfo>,
}

impl MembershipState {
    /// Creates an empty membership state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            members: HashMap::new(),
        }
    }

    /// Adds a member with the given role and tokens.
    ///
    /// If a member with the same DID already exists, they are replaced.
    pub fn add_member(&mut self, did: DID, role_name: String, tokens: Vec<UcanToken>) {
        self.members.insert(
            did.clone(),
            MemberInfo {
                did,
                role_name,
                tokens,
                sequence_number: 0,
            },
        );
    }

    /// Removes a member by DID. Returns `true` if the member was present.
    pub fn remove_member(&mut self, did: &str) -> bool {
        self.members.remove(did).is_some()
    }

    /// Returns the number of members.
    #[must_use]
    pub fn count(&self) -> usize {
        self.members.len()
    }

    /// Returns `true` if the given DID is a member.
    #[must_use]
    pub fn contains(&self, did: &str) -> bool {
        self.members.contains_key(did)
    }

    /// Returns information about a specific member, if present.
    #[must_use]
    pub fn get(&self, did: &str) -> Option<&MemberInfo> {
        self.members.get(did)
    }

    /// Returns a mutable reference to a specific member, if present.
    pub fn get_mut(&mut self, did: &str) -> Option<&mut MemberInfo> {
        self.members.get_mut(did)
    }

    /// Returns all member DIDs.
    pub fn member_dids(&self) -> impl Iterator<Item = &DID> {
        self.members.keys()
    }

    /// Returns all members as an iterator.
    pub fn members(&self) -> impl Iterator<Item = &MemberInfo> {
        self.members.values()
    }

    /// Increments and returns the next sequence number for the given sender.
    ///
    /// Returns `None` if the sender is not a member.
    pub fn next_sequence_number(&mut self, sender_did: &str) -> Option<u64> {
        self.members.get_mut(sender_did).map(|info| {
            info.sequence_number += 1;
            info.sequence_number
        })
    }

    /// Rolls back the last sequence number increment for the given sender.
    ///
    /// Called when `send_message` fails after sequence assignment (Phase 1)
    /// but before successful transport delivery, so the sequence is not
    /// permanently burned on failure. No-op if the sender is not a member
    /// or the sequence is already at 0.
    pub fn rollback_sequence_number(&mut self, sender_did: &str) {
        if let Some(info) = self.members.get_mut(sender_did) {
            info.sequence_number = info.sequence_number.saturating_sub(1);
        }
    }
}

impl Default for MembershipState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RedactedBytes — debug-safe wrapper for sensitive protocol bytes
// ---------------------------------------------------------------------------

/// Wrapper for MLS protocol bytes that redacts content in `Debug` output.
///
/// Used for `WelcomeGenerated` fields (`welcome_bytes`, `commit_bytes`) which
/// contain MLS keying material (tree secrets, epoch keys). Printing these via
/// `Debug` in log or panic output would leak cryptographic secrets.
#[derive(Clone, PartialEq, Eq, serde::Serialize)]
pub struct RedactedBytes(pub Vec<u8>);

impl std::fmt::Debug for RedactedBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{} bytes, REDACTED]", self.0.len())
    }
}

// ---------------------------------------------------------------------------
// ContextEvent
// ---------------------------------------------------------------------------

/// Events produced by context operations, buffered for the receive stream.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum ContextEvent {
    /// A member joined the context.
    MemberJoined {
        /// The DID of the member who joined.
        member_did: DID,
        /// The role assigned to the joining member.
        role_name: String,
    },
    /// A member left the context.
    MemberLeft {
        /// The DID of the member who left.
        member_did: DID,
    },
    /// A message was sent in the context.
    MessageSent {
        /// The DID of the sender.
        sender_did: DID,
        /// The per-sender sequence number.
        sequence_number: u64,
        /// The message payload (encrypted in production; plaintext for tests).
        payload: Vec<u8>,
    },
    /// A message was received from the relay and successfully decrypted.
    MessageReceived {
        /// The DID of the sender (extracted from MLS credential).
        sender_did: DID,
        /// The decrypted plaintext payload.
        payload: Vec<u8>,
    },
    /// The context is being closed by a participant or governance action.
    ///
    /// Replaces the former sentinel DID string `"__close_notification:<did>"`.
    SystemClose {
        /// The DID of the participant who initiated the close, if any.
        initiator_did: DID,
    },
    /// A subscriber was blocked by an author in a broadcast context (SCP-227).
    ///
    /// The author's broadcast key has been rotated; the blocked subscriber
    /// will not receive key material for future epochs.
    MemberBlocked {
        /// The DID of the blocked subscriber.
        blocked_did: DID,
        /// The DID of the author who performed the block.
        author_did: DID,
    },
    /// A subscriber was unblocked by an author in a broadcast context (§9.16.8).
    ///
    /// The author's broadcast key has NOT been rotated (forward-only
    /// restoration). The unblocked subscriber can request the current key
    /// on next pull but cannot decrypt content from the block period.
    MemberUnblocked {
        /// The DID of the unblocked subscriber.
        unblocked_did: DID,
        /// The DID of the author who performed the unblock.
        author_did: DID,
    },
    /// An author was blocked from publishing in a broadcast context (SCP-227).
    ///
    /// The author's sender key has been destroyed; they can no longer publish
    /// new messages. Subscribers who cached the author's old key can still
    /// decrypt historical messages. See spec section 5.14.8.
    AuthorBlocked {
        /// The DID of the blocked author.
        author_did: DID,
    },
    /// A member's read access was revoked via governance (ADR-031, §5.9).
    ///
    /// In broadcast mode: subscriber removed from registry, added to all
    /// authors' block lists, all author keys rotated. The member remains
    /// in the context for governance/presence purposes but cannot read
    /// new content.
    ReadAccessRevoked {
        /// The DID whose read access was revoked.
        did: DID,
    },
    /// A member's read access was restored via governance (ADR-031, §5.9).
    ///
    /// Removes the DID from all authors' block lists. The member must
    /// re-subscribe to regain access. Restoration is always forward-only:
    /// content missed during revocation remains inaccessible.
    ReadAccessRestored {
        /// The DID whose read access was restored.
        did: DID,
    },
    /// A member's write access was revoked via governance (§9.17, ADR-038).
    ///
    /// The member remains in the context for governance/presence purposes
    /// but cannot publish new content. In `Full` scope, the member's
    /// sender/broadcast key is also destroyed and historical content is
    /// suppressed.
    WriteAccessRevoked {
        /// The DID whose write access was revoked.
        did: DID,
    },
    /// One or more capabilities were suspended for a member via governance
    /// (ADR-017, §7.3.7 — `SuspendMember` action).
    ///
    /// Unlike [`Self::WriteAccessRevoked`] / [`Self::ReadAccessRevoked`],
    /// which correspond to the stronger cryptographic `Revoke` action
    /// (key destruction + exclusion list), suspension is an
    /// application-level capability gate: the member retains their MLS
    /// membership, sender keys, access keys, and broadcast subscription,
    /// but the listed capabilities are blocked at every authorization
    /// gate (`member_has_capability` fold).
    ///
    /// The event carries the exact capability set that was suspended so
    /// consumers can apply path-specific UI hints (e.g., "this member
    /// can no longer vote but can still send messages") without having
    /// to re-read the role state. Replaces the previously hardcoded
    /// `WriteAccessRevoked` emission in `execute_suspend_member` which
    /// was wrong for any suspension that did not include `MessagesWrite`.
    CapabilitiesSuspended {
        /// The DID of the member whose capabilities were suspended.
        did: DID,
        /// The capabilities that were suspended.
        capabilities: Vec<super::params::Capability>,
    },
    /// A member's write access was restored via governance (§9.17, ADR-038).
    ///
    /// Forward-only: the member can publish new content but previously
    /// suppressed content remains suppressed.
    WriteAccessRestored {
        /// The DID whose write access was restored.
        did: DID,
    },
    /// A member's access key was revoked via governance (§9.17, ADR-038).
    ///
    /// The member can no longer decrypt content. All members must purge
    /// the target's access key from their key stores.
    AccessKeyRevoked {
        /// The DID whose access key was revoked.
        did: DID,
    },
    /// A member's access key was restored via governance (§9.17, ADR-038).
    ///
    /// The member can decrypt future content. A new access key was generated
    /// at the specified epoch. Historical content remains inaccessible
    /// (forward-only restoration).
    AccessKeyRestored {
        /// The DID whose access key was restored.
        did: DID,
        /// The epoch of the newly generated access key.
        new_epoch: u64,
    },
    /// Context-wide content key rotation was performed (§9.17, ADR-038).
    ///
    /// All members received new access keys. Old keys are retained locally
    /// for historical message decryption.
    ContentKeysRotated {
        /// Optional reason for the rotation.
        reason: Option<String>,
    },
    /// A governance action was successfully executed (ADR-031 §8).
    ///
    /// Emitted after every successful governance action execution so SDK
    /// consumers can observe governance outcomes through the receive buffer.
    /// The `action_summary` is a human-readable description (e.g.,
    /// `"AddMember"`, `"UpdateParams"`) since the full [`super::governance::GovernanceAction`]
    /// type lives in the governance module.
    GovernanceActionExecuted {
        /// The proposal ID that was executed (SHA-256 hash).
        proposal_id: [u8; 32],
        /// Human-readable summary of the action (variant name).
        action_summary: String,
        /// The DID of the executor (proposer of the approved proposal).
        executor_did: DID,
        /// The MLS epoch after execution, if applicable.
        resulting_epoch: Option<u64>,
        /// The DID targeted by this governance action, if any.
        ///
        /// Present for member-targeting actions (`AddMember`, `Eject`,
        /// `ChangeRole`, `SuspendMember`, `Revoke`, etc.). Used by
        /// consequence triggers (`WarningCount`, `Custom`) and participation
        /// records to identify the target without relying on opaque payloads.
        target_did: Option<DID>,
    },
    /// A ceiling change notification was emitted (§5.3.2).
    ///
    /// All current members receive this when a `ModifyCeiling` governance
    /// action is approved. The notification period must expire before the
    /// new ceiling takes effect. Members may leave during the notification
    /// period if they disagree with the proposed changes.
    CeilingChangeNotification {
        /// The capabilities in the proposed new ceiling.
        new_capabilities: Vec<super::roles::Capability>,
        /// Unix timestamp (seconds) when the notification period started.
        notified_at: u64,
        /// Unix timestamp (seconds) when the new ceiling takes effect.
        effective_at: u64,
        /// The governance proposal ID that approved this modification.
        proposal_id: [u8; 32],
    },
    /// An economic policy change notification was emitted (§19.3).
    ///
    /// All current members receive this when a `SetEconomicPolicy` governance
    /// action is approved. The notification period (minimum 24 hours) must
    /// expire before the new policy takes effect. Members may leave during
    /// the notification period if they disagree with the proposed pricing.
    EconomicPolicyChangeNotification {
        /// Unix timestamp (seconds) when the notification period started.
        notified_at: u64,
        /// Unix timestamp (seconds) when the new policy takes effect.
        effective_at: u64,
        /// The governance proposal ID that approved this change.
        proposal_id: [u8; 32],
    },
    /// The context expired due to TTL.
    ///
    /// Replaces the former sentinel DID string `"__ttl_expiry_notification"`.
    Expired,
    /// TTL expiry cleanup failed after exhausting all retry attempts.
    ///
    /// The context transitioned to `Expired` state but one or more cleanup
    /// operations failed (MLS group destruction, sender key destruction,
    /// or event log write). The `reason` field contains a human-readable
    /// description of what failed.
    ///
    /// Application layers should treat this as a degraded state: the context
    /// is expired but cryptographic material may not have been fully destroyed.
    ExpiryFailed {
        /// Human-readable description of the failure(s).
        reason: String,
        /// Whether the state transition to `Expired` succeeded.
        state_transitioned: bool,
        /// Whether MLS group keys were successfully destroyed (or not required).
        mls_destroyed: bool,
        /// Whether sender keys were successfully destroyed (or not required).
        sender_key_destroyed: bool,
        /// Whether the `ContextExpired` event was logged.
        event_logged: bool,
    },
    /// A governance vote was withdrawn (ADR-031 §5).
    ///
    /// Emitted when a voter's vote is removed from a pending proposal,
    /// typically due to voter departure from the context.
    VoteWithdrawn {
        /// The proposal ID the vote was withdrawn from.
        proposal_id: [u8; 32],
        /// The DID of the voter whose vote was withdrawn.
        voter_did: DID,
    },
    /// A governance proposal was resolved by the timeout system (ADR-031 §5).
    ///
    /// Emitted when a pending proposal is resolved (expired, rejected,
    /// invalidated) by the background timeout task rather than by an
    /// explicit governance action execution.
    ProposalTimedOut {
        /// The proposal ID that was resolved.
        proposal_id: [u8; 32],
        /// Human-readable summary of the resolution status.
        resolution_summary: String,
        /// The MLS epoch at the time of resolution, if applicable.
        resulting_epoch: Option<u64>,
    },
    /// A governance deadlock condition was detected (ADR-031 §10).
    ///
    /// Emitted by the background timeout task when the governance model
    /// cannot make progress due to insufficient active participants.
    /// SDK consumers should observe this event and consider initiating
    /// a `ReconfigureGovernance` proposal with deadlock justification.
    DeadlockDetected {
        /// Human-readable summary of the deadlock condition.
        condition_summary: String,
        /// The MLS epoch at the time of detection, if applicable.
        resulting_epoch: Option<u64>,
    },
    /// An app was bound to the context (spec §8.4.2).
    ///
    /// Recorded in the event log for auditability. Context members can
    /// inspect which apps are bound and what capabilities they hold.
    AppBound {
        /// The DID of the app that was bound.
        app_did: DID,
        /// The capabilities granted to the app.
        capabilities: Vec<super::roles::Capability>,
    },
    /// An app was unbound from the context (spec §8.4.2).
    ///
    /// Recorded in the event log when an app is removed.
    AppUnbound {
        /// The DID of the app that was unbound.
        app_did: DID,
    },
    /// The local implementation is operating in degraded mode (§13.6) because
    /// a received envelope has a different minor version within the same major
    /// version.
    ///
    /// Constructed by callers who receive
    /// [`VersionCompatibility::DegradedMode`] from envelope processing
    /// functions. The envelope layer returns the compatibility result; the
    /// application/SDK layer emits this event.
    ///
    /// [`VersionCompatibility::DegradedMode`]: crate::envelope::VersionCompatibility::DegradedMode
    DegradedMode {
        /// The context where the envelope was received.
        context_id: String,
        /// The local implementation's protocol version as `(major, minor)`.
        local_version: (u8, u8),
        /// The remote (wire) protocol version as `(major, minor)`.
        remote_version: (u8, u8),
        /// Features present in the remote version that the local
        /// implementation does not support. At SCP/1.x there are no
        /// known feature flags, so callers should pass `vec![]`.
        unsupported_features: Vec<String>,
    },
    /// An MLS Welcome was generated for a newly added member.
    ///
    /// The application layer must ECIES-encrypt and deliver it to the
    /// joiner's personal routing ID (spec §5.12.3, issue #1311).
    WelcomeGenerated {
        /// Context ID for ECIES domain binding.
        context_id: String,
        /// DID of the context creator (for ECIES domain binding).
        creator_did: DID,
        /// DID of the member being invited.
        member_did: DID,
        /// TLS-serialized MLS Welcome message (redacted in Debug output to
        /// prevent MLS tree secrets and epoch keys from appearing in logs).
        welcome_bytes: RedactedBytes,
        /// TLS-serialized MLS Commit message for existing members (redacted
        /// in Debug output for the same reason as `welcome_bytes`).
        commit_bytes: RedactedBytes,
    },
    /// Warning: the receive buffer overflowed and events were dropped.
    ///
    /// Emitted when the buffer is full and the oldest event is dropped.
    /// Includes the count of events dropped since the last successful
    /// consumption.
    BufferOverflow {
        /// Number of events dropped since the last successful consumption.
        dropped_count: u64,
    },
    /// A sequence gap was detected and force-closed (§9.8.5, §9.9.2).
    ///
    /// Emitted when buffered out-of-order messages are force-delivered because
    /// the gap persisted beyond the timeout (30 seconds) or the reorder buffer
    /// reached its capacity (100 messages per sender). This is a suppression
    /// alert: the missing sequence numbers may have been suppressed by an
    /// adversarial relay.
    SequenceGapDetected {
        /// The sender whose messages had a gap.
        sender_did: DID,
        /// The expected sequence number (start of the gap).
        expected_sequence: u64,
        /// The first buffered sequence that was force-delivered.
        first_delivered_sequence: u64,
        /// Why the gap was force-closed.
        reason: String,
    },
    /// A governance action execution has triggered checkpoint cosignature
    /// collection (ADR-031 §9, issue #630).
    ///
    /// Emitted after governance actions in multi-admin contexts (Threshold,
    /// Majority, Unanimity) to notify the SDK that a checkpoint should be
    /// created and cosignatures collected from governance quorum members.
    /// `SingleAdmin` contexts do not require cosignatures and will not emit
    /// this event.
    CheckpointCosignatureRequired {
        /// The governance proposal that triggered checkpoint collection.
        proposal_id: [u8; 32],
        /// DIDs required to cosign the checkpoint.
        required_signers: Vec<DID>,
        /// Minimum cosignature count for `FullyAttested` status.
        minimum_count: usize,
        /// The MLS epoch at which the checkpoint should be taken.
        at_epoch: u64,
    },
    /// A context migration has been proposed (§5.11A.3).
    ///
    /// All source context members receive this notification containing
    /// the migration details. Members can evaluate the destination
    /// parameters before accepting.
    ContextMigrationProposed {
        /// The destination context ID (created after approval).
        destination_context_id: String,
        /// The reason for migration.
        reason: String,
        /// Grace period duration in seconds.
        grace_period_secs: u64,
        /// Whether bulk auto-invites will be sent.
        auto_invite: bool,
        /// The governance proposal ID that authorized this migration.
        proposal_id: [u8; 32],
    },
    /// The context migration grace period has started (§5.11A.4).
    ///
    /// The source context is now in read-only mode. Members should
    /// join the destination context before the grace period expires.
    ContextMigrationStarted {
        /// The destination context ID.
        destination_context_id: String,
        /// Unix timestamp (seconds) when the grace period ends.
        grace_period_end: u64,
    },
    /// A context migration was cancelled (§5.11A).
    ///
    /// The source context has returned to Active state. All migration
    /// state has been cleared.
    ContextMigrationCancelled {
        /// The governance proposal ID of the original migration.
        original_proposal_id: [u8; 32],
    },
    /// The context has been tombstoned after migration (§5.11A.5).
    ///
    /// The source context is permanently closed with a pointer to the
    /// destination. Late-arriving members can discover the migration
    /// destination from the tombstone record.
    ContextTombstoned {
        /// The destination context ID.
        destination_context_id: String,
        /// The governance proposal ID that authorized the migration.
        migration_proposal_id: [u8; 32],
    },
    /// A consequence rule was triggered (ADR-017, #1531).
    ///
    /// Emitted when a consequence rule's trigger condition is met for a
    /// member. Contains the rule index and trigger/action types for
    /// observability.
    ConsequenceTriggered {
        /// The context where the consequence was triggered.
        context_id: String,
        /// The member whose behavior triggered the consequence.
        member_did: DID,
        /// Index of the triggered rule in the context's `consequence_rules`.
        rule_index: usize,
        /// Human-readable trigger type (e.g., `"MessageVelocity"`).
        trigger_type: String,
        /// Human-readable action type (e.g., `"Suspend"`).
        action_type: String,
    },
    /// A consequence enforcement action was executed (ADR-017, #1531).
    ///
    /// Emitted after the enforcement action (capability suspension, suspend
    /// all, or role assignment) has been applied. The `success` field
    /// indicates whether the enforcement was successfully applied.
    ConsequenceEnforced {
        /// The context where the consequence was enforced.
        context_id: String,
        /// The member the enforcement was applied to.
        member_did: DID,
        /// Human-readable action type (e.g., `"Suspend"`).
        action_type: String,
        /// Whether the enforcement was successfully applied.
        success: bool,
    },
}

// ---------------------------------------------------------------------------
// ReceiveBuffer
// ---------------------------------------------------------------------------

/// Bounded event buffer for the receive stream.
///
/// Buffers up to `capacity` events. When the buffer is full, the oldest
/// unconsumed event is dropped and a [`ContextEvent::BufferOverflow`] warning
/// is emitted on the stream. The `BufferOverflow` event includes the count of
/// dropped events since the last successful consumption.
///
/// Buffer size is configurable:
/// - Minimum: [`MIN_BUFFER_CAPACITY`] (100)
/// - Maximum: [`MAX_BUFFER_CAPACITY`] (10,000)
/// - Default: [`DEFAULT_BUFFER_CAPACITY`] (1,000)
///
/// See `.docs/standards/sdk-common.md` "Receive stream buffer tests".
#[derive(Debug)]
pub struct ReceiveBuffer {
    /// The event queue.
    events: VecDeque<ContextEvent>,
    /// Maximum number of events to buffer.
    capacity: usize,
    /// Number of events dropped since the last successful consumption.
    dropped_since_last_consume: u64,
}

impl ReceiveBuffer {
    /// Creates a new receive buffer with the default capacity (1,000).
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_BUFFER_CAPACITY)
    }

    /// Creates a new receive buffer with the specified capacity.
    ///
    /// The capacity is clamped to the range
    /// [`MIN_BUFFER_CAPACITY`]..=[`MAX_BUFFER_CAPACITY`].
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.clamp(MIN_BUFFER_CAPACITY, MAX_BUFFER_CAPACITY);
        Self {
            events: VecDeque::with_capacity(capacity),
            capacity,
            dropped_since_last_consume: 0,
        }
    }

    /// Returns the configured capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the number of events currently in the buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns `true` if the buffer contains no events.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Pushes an event into the buffer.
    ///
    /// If the buffer is full, the oldest event(s) are dropped to make room
    /// for a [`ContextEvent::BufferOverflow`] warning and the new event.
    /// The `BufferOverflow` event is always emitted when events are
    /// displaced, and consecutive overflows coalesce into a single
    /// `BufferOverflow` with an updated count.
    ///
    /// Returns `Some(BufferOverflow { dropped_count })` when events were
    /// displaced, or `None` when the event was inserted without overflow.
    pub fn push(&mut self, event: ContextEvent) -> Option<ContextEvent> {
        if self.events.len() < self.capacity {
            // Room available -- no overflow.
            self.events.push_back(event);
            return None;
        }

        // Buffer is full. We need to make room for the new event, and
        // also ensure a BufferOverflow marker is present.

        // Check if the last event is already a BufferOverflow we can
        // update in place. If so, we only need to drop one oldest event
        // (the overflow marker is already occupying its slot).
        if let Some(ContextEvent::BufferOverflow { .. }) = self.events.back() {
            // Drop the oldest event to make room for the new event.
            self.events.pop_front();
            self.dropped_since_last_consume += 1;

            // Update the existing overflow marker's count in place.
            if let Some(ContextEvent::BufferOverflow { dropped_count }) = self.events.back_mut() {
                *dropped_count = self.dropped_since_last_consume;
            }
        } else {
            // No existing overflow marker. We need two slots: one for the
            // overflow marker and one for the new event. Drop two oldest.
            self.events.pop_front();
            self.dropped_since_last_consume += 1;
            self.events.pop_front();
            self.dropped_since_last_consume += 1;

            // Push the overflow marker.
            self.events.push_back(ContextEvent::BufferOverflow {
                dropped_count: self.dropped_since_last_consume,
            });
        }

        // Push the new event.
        self.events.push_back(event);

        // Return the overflow indicator.
        Some(ContextEvent::BufferOverflow {
            dropped_count: self.dropped_since_last_consume,
        })
    }

    /// Consumes and returns the oldest event from the buffer.
    ///
    /// Resets the dropped counter on successful consumption.
    pub fn pop(&mut self) -> Option<ContextEvent> {
        let event = self.events.pop_front();
        if event.is_some() {
            self.dropped_since_last_consume = 0;
        }
        event
    }

    /// Returns the number of events dropped since the last successful
    /// consumption.
    #[must_use]
    pub const fn dropped_since_last_consume(&self) -> u64 {
        self.dropped_since_last_consume
    }

    /// Drains all events from the buffer into a `Vec`.
    ///
    /// Resets the dropped counter.
    pub fn drain(&mut self) -> Vec<ContextEvent> {
        self.dropped_since_last_consume = 0;
        self.events.drain(..).collect()
    }

    /// Truncates the buffer to `len` events, removing from the back.
    ///
    /// If `len` is greater than or equal to the current length, this is a
    /// no-op. Used by rollback paths to remove only the events pushed
    /// after a recorded checkpoint, without disturbing events that were
    /// already in the buffer or added by concurrent operations.
    pub fn truncate(&mut self, len: usize) {
        self.events.truncate(len);
    }

    /// Returns a read-only view of buffered events for consequence rule
    /// evaluation and participation record computation.
    ///
    /// Does NOT consume events — they remain in the buffer for SDK
    /// consumption via [`drain`](Self::drain). This enables governance
    /// consequence evaluation (#1531) and standing checks (#1530) to
    /// inspect recent events without side effects.
    #[must_use]
    pub const fn event_log_entries(&self) -> &VecDeque<ContextEvent> {
        &self.events
    }
}

impl Default for ReceiveBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // MembershipState tests
    // -----------------------------------------------------------------------

    #[test]
    fn membership_state_new_is_empty() {
        let state = MembershipState::new();
        assert_eq!(state.count(), 0);
    }

    #[test]
    fn membership_state_add_and_query_member() {
        let mut state = MembershipState::new();
        state.add_member("did:key:alice".into(), "member".into(), vec![]);

        assert_eq!(state.count(), 1);
        assert!(state.contains("did:key:alice"));
        assert!(!state.contains("did:key:bob"));

        let info = state.get("did:key:alice").unwrap();
        assert_eq!(info.did, "did:key:alice");
        assert_eq!(info.role_name, "member");
        assert_eq!(info.sequence_number, 0);
    }

    #[test]
    fn membership_state_remove_member() {
        let mut state = MembershipState::new();
        state.add_member("did:key:alice".into(), "member".into(), vec![]);
        assert_eq!(state.count(), 1);

        assert!(state.remove_member("did:key:alice"));
        assert_eq!(state.count(), 0);
        assert!(!state.contains("did:key:alice"));

        // Removing non-existent member returns false.
        assert!(!state.remove_member("did:key:bob"));
    }

    #[test]
    fn membership_state_sequence_numbers() {
        let mut state = MembershipState::new();
        state.add_member("did:key:alice".into(), "member".into(), vec![]);

        assert_eq!(state.next_sequence_number("did:key:alice"), Some(1));
        assert_eq!(state.next_sequence_number("did:key:alice"), Some(2));
        assert_eq!(state.next_sequence_number("did:key:alice"), Some(3));

        // Non-existent member returns None.
        assert_eq!(state.next_sequence_number("did:key:bob"), None);
    }

    #[test]
    fn membership_state_member_dids() {
        let mut state = MembershipState::new();
        state.add_member("did:key:alice".into(), "admin".into(), vec![]);
        state.add_member("did:key:bob".into(), "member".into(), vec![]);

        let mut dids: Vec<&str> = state
            .member_dids()
            .map(std::convert::AsRef::as_ref)
            .collect();
        dids.sort_unstable();
        assert_eq!(dids, vec!["did:key:alice", "did:key:bob"]);
    }

    // -----------------------------------------------------------------------
    // ReceiveBuffer tests -- conformance
    // -----------------------------------------------------------------------

    /// `receive-buffer-capacity-001`: buffer holds 1,000 events without dropping.
    #[test]
    fn receive_buffer_capacity_001() {
        let mut buffer = ReceiveBuffer::new();
        assert_eq!(buffer.capacity(), DEFAULT_BUFFER_CAPACITY);

        // Fill to capacity.
        for i in 0..1_000 {
            buffer.push(ContextEvent::MessageSent {
                sender_did: "did:key:alice".into(),
                sequence_number: i,
                payload: vec![],
            });
        }

        assert_eq!(buffer.len(), 1_000);
        assert_eq!(buffer.dropped_since_last_consume(), 0);
    }

    /// `receive-buffer-overflow-drop-002`: event 1,001 causes oldest event to
    /// be dropped.
    #[test]
    fn receive_buffer_overflow_drop_002() {
        let mut buffer = ReceiveBuffer::new();

        // Fill to capacity.
        for i in 0..1_000 {
            buffer.push(ContextEvent::MessageSent {
                sender_did: "did:key:alice".into(),
                sequence_number: i,
                payload: vec![],
            });
        }

        // Push one more -- should drop oldest (seq 0).
        buffer.push(ContextEvent::MessageSent {
            sender_did: "did:key:alice".into(),
            sequence_number: 1_000,
            payload: vec![],
        });

        // Buffer should still be at capacity.
        assert_eq!(buffer.len(), 1_000);

        // The oldest event should now be either a BufferOverflow warning or
        // seq 1 (seq 0 was dropped). Let's verify the first event is the
        // overflow warning.
        let first = buffer.pop().unwrap();
        match first {
            ContextEvent::BufferOverflow { dropped_count } => {
                assert!(dropped_count >= 1);
            }
            ContextEvent::MessageSent {
                sequence_number, ..
            } => {
                // If the overflow event replaced seq 0, then seq 1 should be first.
                assert!(sequence_number >= 1);
            }
            _ => panic!("unexpected event type"),
        }
    }

    /// `receive-buffer-overflow-warning-003`: `BufferOverflow` warning event is
    /// emitted when events are dropped, including dropped count.
    #[test]
    fn receive_buffer_overflow_warning_003() {
        let mut buffer = ReceiveBuffer::new();

        // Fill to capacity.
        for i in 0..1_000 {
            buffer.push(ContextEvent::MessageSent {
                sender_did: "did:key:alice".into(),
                sequence_number: i,
                payload: vec![],
            });
        }

        // Push 3 more to cause 3 drops.
        for i in 1_000..1_003 {
            buffer.push(ContextEvent::MessageSent {
                sender_did: "did:key:alice".into(),
                sequence_number: i,
                payload: vec![],
            });
        }

        // Drain and check for BufferOverflow events.
        let events = buffer.drain();
        let overflow_events: Vec<_> = events
            .iter()
            .filter_map(|e| {
                if let ContextEvent::BufferOverflow { dropped_count } = e {
                    Some(*dropped_count)
                } else {
                    None
                }
            })
            .collect();

        // There should be at least one BufferOverflow event.
        assert!(
            !overflow_events.is_empty(),
            "expected at least one BufferOverflow event"
        );

        // The dropped count in any overflow event should be >= 1.
        for count in &overflow_events {
            assert!(*count >= 1, "dropped count should be >= 1, got {count}");
        }
    }

    /// `receive-buffer-configurable-004`: custom buffer size is respected.
    #[test]
    fn receive_buffer_configurable_004() {
        // Custom size within bounds.
        let buffer = ReceiveBuffer::with_capacity(500);
        assert_eq!(buffer.capacity(), 500);

        // Below minimum -- clamped.
        let buffer = ReceiveBuffer::with_capacity(50);
        assert_eq!(buffer.capacity(), MIN_BUFFER_CAPACITY);

        // Above maximum -- clamped.
        let buffer = ReceiveBuffer::with_capacity(20_000);
        assert_eq!(buffer.capacity(), MAX_BUFFER_CAPACITY);

        // Custom capacity fills correctly.
        let mut buffer = ReceiveBuffer::with_capacity(200);
        for i in 0..200 {
            buffer.push(ContextEvent::MessageSent {
                sender_did: "did:key:alice".into(),
                sequence_number: i,
                payload: vec![],
            });
        }
        assert_eq!(buffer.len(), 200);
        assert_eq!(buffer.dropped_since_last_consume(), 0);

        // Overflow at custom capacity.
        buffer.push(ContextEvent::MessageSent {
            sender_did: "did:key:alice".into(),
            sequence_number: 200,
            payload: vec![],
        });
        assert_eq!(buffer.len(), 200);
        assert!(buffer.dropped_since_last_consume() > 0);
    }

    // -----------------------------------------------------------------------
    // Additional ReceiveBuffer unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn receive_buffer_pop_returns_fifo_order() {
        let mut buffer = ReceiveBuffer::new();
        buffer.push(ContextEvent::MemberJoined {
            member_did: "did:key:alice".into(),
            role_name: "admin".into(),
        });
        buffer.push(ContextEvent::MemberJoined {
            member_did: "did:key:bob".into(),
            role_name: "member".into(),
        });

        let first = buffer.pop().unwrap();
        assert_eq!(
            first,
            ContextEvent::MemberJoined {
                member_did: "did:key:alice".into(),
                role_name: "admin".into(),
            }
        );

        let second = buffer.pop().unwrap();
        assert_eq!(
            second,
            ContextEvent::MemberJoined {
                member_did: "did:key:bob".into(),
                role_name: "member".into(),
            }
        );

        assert!(buffer.pop().is_none());
    }

    #[test]
    fn receive_buffer_pop_resets_dropped_counter() {
        let mut buffer = ReceiveBuffer::with_capacity(100);
        for i in 0..101 {
            buffer.push(ContextEvent::MessageSent {
                sender_did: "did:key:alice".into(),
                sequence_number: i,
                payload: vec![],
            });
        }
        assert!(buffer.dropped_since_last_consume() > 0);

        // Consuming resets the counter.
        buffer.pop();
        assert_eq!(buffer.dropped_since_last_consume(), 0);
    }

    #[test]
    fn receive_buffer_drain_returns_all_events() {
        let mut buffer = ReceiveBuffer::new();
        for i in 0..5 {
            buffer.push(ContextEvent::MessageSent {
                sender_did: "did:key:alice".into(),
                sequence_number: i,
                payload: vec![],
            });
        }

        let events = buffer.drain();
        assert_eq!(events.len(), 5);
        assert!(buffer.is_empty());
    }

    #[test]
    fn receive_buffer_default_capacity() {
        let buffer = ReceiveBuffer::default();
        assert_eq!(buffer.capacity(), DEFAULT_BUFFER_CAPACITY);
    }

    // -----------------------------------------------------------------------
    // SystemClose / Expired variant tests (SCP-203)
    // -----------------------------------------------------------------------

    /// SCP-203: `SystemClose` variant carries the initiator DID.
    #[test]
    fn system_close_event_carries_initiator_did() {
        let event = ContextEvent::SystemClose {
            initiator_did: "did:key:admin".into(),
        };

        match &event {
            ContextEvent::SystemClose { initiator_did } => {
                assert_eq!(initiator_did, "did:key:admin");
            }
            _ => panic!("expected SystemClose variant"),
        }
    }

    /// SCP-203: `Expired` variant is a unit variant (no sentinel DID).
    #[test]
    fn expired_event_is_unit_variant() {
        let event = ContextEvent::Expired;
        assert_eq!(event, ContextEvent::Expired);
    }

    /// SCP-203: `SystemClose` and `Expired` implement `Eq` / `Clone`.
    #[test]
    fn close_and_expiry_events_are_eq_and_clone() {
        let close = ContextEvent::SystemClose {
            initiator_did: "did:key:alice".into(),
        };
        let close2 = close.clone();
        assert_eq!(close, close2);

        let expired = ContextEvent::Expired;
        let expired2 = expired.clone();
        assert_eq!(expired, expired2);
    }

    /// SCP-203: `SystemClose` is distinct from `MemberLeft`.
    #[test]
    fn system_close_is_not_member_left() {
        let close = ContextEvent::SystemClose {
            initiator_did: "did:key:alice".into(),
        };
        let left = ContextEvent::MemberLeft {
            member_did: "did:key:alice".into(),
        };
        assert_ne!(close, left);
    }

    /// SCP-203: `Expired` is distinct from `MemberLeft`.
    #[test]
    fn expired_is_not_member_left() {
        let expired = ContextEvent::Expired;
        let left = ContextEvent::MemberLeft {
            member_did: "__ttl_expiry_notification".into(),
        };
        assert_ne!(expired, left);
    }

    /// SCP-203: Buffer can hold `SystemClose` and `Expired` events.
    #[test]
    fn buffer_holds_close_and_expiry_events() {
        let mut buffer = ReceiveBuffer::new();
        buffer.push(ContextEvent::SystemClose {
            initiator_did: "did:key:admin".into(),
        });
        buffer.push(ContextEvent::Expired);

        assert_eq!(buffer.len(), 2);

        let first = buffer.pop().unwrap();
        assert_eq!(
            first,
            ContextEvent::SystemClose {
                initiator_did: "did:key:admin".into(),
            }
        );

        let second = buffer.pop().unwrap();
        assert_eq!(second, ContextEvent::Expired);
    }

    // -----------------------------------------------------------------------
    // MessagePack roundtrip -- SCP-PERSIST-001
    // -----------------------------------------------------------------------

    /// SCP-PERSIST-001: `MembershipState` survives `MessagePack` roundtrip.
    #[test]
    fn membership_state_msgpack_roundtrip() {
        use crate::context::roles::{UcanAttestation, UcanToken};

        let mut state = MembershipState::new();

        // Add members with various roles and tokens.
        state.add_member(
            "did:key:alice".into(),
            "admin".into(),
            vec![UcanToken {
                iss: "did:dht:creator".to_owned(),
                aud: "did:key:alice".to_owned(),
                att: vec![UcanAttestation {
                    with: "scp:ctx:ctx-1/messages:read".to_owned(),
                    can: "invoke".to_owned(),
                }],
                nnc: "1708646400000-aabbccdd".to_owned(),
            }],
        );
        state.add_member("did:key:bob".into(), "member".into(), vec![]);
        state.add_member("did:key:carol".into(), "observer".into(), vec![]);

        // Advance sequence numbers so they are non-zero.
        state.next_sequence_number("did:key:alice");
        state.next_sequence_number("did:key:alice");
        state.next_sequence_number("did:key:bob");

        // Serialize to MessagePack.
        let bytes = rmp_serde::to_vec(&state).expect("MembershipState serialization failed");
        assert!(!bytes.is_empty());

        // Deserialize back.
        let decoded: MembershipState =
            rmp_serde::from_slice(&bytes).expect("MembershipState deserialization failed");

        assert_eq!(state, decoded);
    }
}
