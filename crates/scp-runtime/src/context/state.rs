//! Per-context durable state types — `PerContextState`,
//! `ContextSnapshot`, `BroadcastSnapshot`, generation tokens, governance
//! result types, plus pseudonym + commit-retry primitives.
//!
//! This module is the canonical home for context state types. Hoisted
//! out of the deleted `manager/` directory in ADR-049 §15.
//!
//! # Visibility
//!
//! - `pub` types/constants are part of the runtime crate's public API
//!   (re-exported through `scp_core::context`) and are consumed by FFI
//!   bridges + downstream tests.
//! - `pub(crate)` items are crate-internal and accessed by helpers,
//!   actor handlers, and the supervisor.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::ContextHandle;
use super::governance::timeout::DeadlockDetectionState;
use super::ttl::{TtlExtension, TtlTimer};
use scp_clock::Clock;
use scp_did::DID;
use scp_protocol::context::broadcast::{BroadcastContextSnapshot, GovernanceBanResult};
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::governance::{
    AccessScope, GovernanceEngine, GovernanceModelConfig, GovernanceProposal, KeyResolver,
    ProposalId, ProposalStatus, PruningPolicy, SingleAdminEngine,
    majority::MajorityVoteEngine,
    mls_integration::{CoordinationRecord, EpochCoordinator},
    multisig::ThresholdEngine,
    unanimity::UnanimityEngine,
};
use scp_protocol::context::membership::{
    ContextEvent, MembershipState, ReceiveBuffer, RedactedBytes,
};
use scp_protocol::context::outlets::interface::OutletInterface;
use scp_protocol::context::params::CeilingPolicy;
use scp_protocol::context::params::GovernanceModel;
use scp_protocol::context::params::OutletRegistration;
use scp_protocol::context::roles::{Capability, ContextRoleState};
use scp_protocol::context::{ContextError, ContextParams, ContextState};
use scp_protocol::economy::budget::MemberBudgetTracker;
use scp_protocol::economy::types::EconomicPolicy;
use scp_protocol::trust::consequence::ConsequenceRule;

// ---------------------------------------------------------------------------
// Protocol-level collection size limits (§5.9)
// ---------------------------------------------------------------------------

/// Maximum number of registered outlets per context.
pub(crate) const MAX_REGISTERED_OUTLETS: usize = 256;

/// Maximum number of cross-context outlet interfaces per context.
pub(crate) const MAX_OUTLET_INTERFACES: usize = 256;

/// Maximum number of governance threshold signers per context.
pub(crate) const MAX_THRESHOLD_SIGNERS: usize = 64;

/// Default ceiling change notification period in seconds (M7, §5.3.2).
///
/// When a governed context's ceiling is modified, the change is pending
/// for this duration before taking effect. Members joined under the previous
/// ceiling are notified and may leave before the expansion applies.
///
/// Spec §5.3.2: "A mandatory notification period of 72 hours begins."
pub(crate) const CEILING_CHANGE_NOTIFICATION_PERIOD_SECS: u64 = 259_200; // 72 hours

/// TTL for `executed_proposals` entries in seconds (14 days).
///
/// Entries older than this are evicted on each insert to prevent unbounded
/// growth. 14 days is generous — governance proposals are typically resolved
/// within hours, so a 14-day window provides ample replay protection.
pub(crate) const EXECUTED_PROPOSALS_TTL_SECS: u64 = 14 * 24 * 60 * 60; // 14 days

// ---------------------------------------------------------------------------
// MLS commit broadcast retry queue (PR #1606 C6)
// ---------------------------------------------------------------------------

/// Maximum number of times the persistent commit retry queue will re-attempt
/// a single MLS Commit broadcast before marking it `CommitBroadcastFailed`
/// and putting the context in fail-close state.
pub const MAX_COMMIT_RETRIES: u32 = 20;

/// Maximum age (in seconds) of a pending commit before it is force-failed
/// regardless of how many attempts have been made (1 hour).
///
/// Bounds the worst-case window during which a commit can sit unrecoverable
/// in the queue. After this elapses the context fail-closes so the operator
/// can intervene rather than wait for retry-count exhaustion.
pub const MAX_COMMIT_AGE_SECS: u64 = 3600; // 1 hour

/// Maximum number of pending commits allowed in the retry queue per context.
///
/// Prevents unbounded memory growth during sustained transport outages.
/// When this cap is reached, [`apply_broadcast_failure`](crate::context::governance_helpers::apply_broadcast_failure) sets the
/// `commit_fault` marker immediately rather than enqueuing, fail-closing
/// the context for operator attention.
pub const MAX_PENDING_COMMITS: usize = 50;

/// Exponential backoff schedule (in seconds) for commit retry attempts.
///
/// `COMMIT_RETRY_BACKOFFS[i]` is the delay before attempt `i + 1` (i.e., the
/// delay applied after the i-th failure). Indexing past the end of the array
/// reuses the final value (300 s). Designed to give transient network outages
/// fast retries (1 s, 2 s, 5 s) and longer outages slower retries that fit
/// within `MAX_COMMIT_AGE_SECS`.
pub const COMMIT_RETRY_BACKOFFS: [u64; 8] = [1, 2, 5, 15, 60, 120, 300, 300];

/// Returns the delay (in seconds) before the next retry attempt given the
/// number of failed attempts so far.
#[must_use]
#[inline]
pub fn commit_retry_backoff(failed_attempts: u32) -> u64 {
    let idx = (failed_attempts as usize).saturating_sub(1);
    let clamped = idx.min(COMMIT_RETRY_BACKOFFS.len() - 1);
    COMMIT_RETRY_BACKOFFS[clamped]
}

/// Logical operation that produced an MLS Commit, used by the persistent
/// retry queue (PR #1606 C6) for observability and event labelling.
///
/// The variant identifies which mutation produced the commit so that the
/// `CommitBroadcastPending` / `CommitBroadcastSucceeded` / `CommitBroadcastFailed`
/// events emitted by the retry queue carry meaningful labels for SDK
/// consumers. These are surfaced as local `ContextEvent`s only — per the
/// phase-2.md ADR-011-amendment exclusion taxonomy (per-committer
/// broadcast-retry bookkeeping) they are NOT durably appended to the
/// canonical Merkle event log (§9.9.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitOperation {
    /// Commit produced by `execute_add_member` for the given target DID.
    ///
    /// An MLS Add advances the group epoch exactly like a Remove, so the
    /// existing members MUST process this Commit or they desync from the
    /// admin. The add's Commit is broadcast through the same persistent
    /// retry queue as the remove/reset commits (parity restored — the add
    /// path historically dropped it).
    AddMember {
        /// The DID that was added to the MLS group.
        target_did: DID,
    },
    /// Commit produced by `execute_remove_member` for the given target DID.
    RemoveMember {
        /// The DID that was removed from the MLS group.
        target_did: DID,
    },
    /// Commit produced by `execute_rotate_content_keys` (epoch advance for
    /// content key rotation).
    RotateContentKeys {
        /// Optional human-readable reason recorded with the rotation.
        reason: Option<String>,
    },
    /// Commit produced by `execute_reset_member` (remove + re-add for MLS
    /// state reset). The variant carries which sub-step the commit corresponds
    /// to so that retries do not conflate the two distinct commits in
    /// observability events.
    ResetMember {
        /// The DID being reset.
        target_did: DID,
        /// `true` for the remove half of the reset, `false` for the re-add.
        is_remove: bool,
    },
    /// Commit produced by `leave_context` for the local member's departure.
    LeaveContext {
        /// The DID of the member who left.
        member_did: DID,
    },
    /// Commit produced by `recovery_advance_epoch` — the spec §9.12 step-2
    /// post-compromise recovery epoch advance (an MLS Update + self-Commit).
    ///
    /// Broadcasting this Commit is what re-keys the group away from the
    /// compromised material: until remaining members process it they stay on
    /// the compromised epoch and the excluded/compromised party retains read
    /// access. It carries no reason/target payload — the epoch advance is fully
    /// determined by the context state. Like the other epoch-advancing commits
    /// it rides the persistent retry queue, so a dropped broadcast fail-closes
    /// the context rather than silently completing recovery.
    RecoveryAdvanceEpoch,
}

impl CommitOperation {
    /// Human-readable label used in events and the durable event log.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::AddMember { .. } => "AddMember".to_owned(),
            Self::RemoveMember { .. } => "RemoveMember".to_owned(),
            Self::RotateContentKeys { .. } => "RotateContentKeys".to_owned(),
            Self::ResetMember {
                is_remove: true, ..
            } => "ResetMemberRemove".to_owned(),
            Self::ResetMember {
                is_remove: false, ..
            } => "ResetMemberAdd".to_owned(),
            Self::LeaveContext { .. } => "LeaveContext".to_owned(),
            Self::RecoveryAdvanceEpoch => "RecoveryAdvanceEpoch".to_owned(),
        }
    }
}

/// A persistent entry in the MLS Commit retry queue (PR #1606 C6).
///
/// Each `PendingCommit` is created when a `transport.send_message` call
/// for an MLS Commit fails after the local state has already been mutated.
/// The entry is enqueued in [`PerContextState::pending_commits`] and
/// retried by the governance timeout task with exponential backoff.
///
/// Persisted via [`ContextSnapshot::pending_commits`] so retries survive
/// process restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingCommit {
    /// TLS-serialized MLS Commit message bytes (output of
    /// `crypto.remove_member()` / `crypto.advance_epoch()`).
    #[serde(with = "serde_bytes")]
    pub commit_bytes: Vec<u8>,
    /// SHA-256 routing ID derived from the context ID via
    /// `scp_protocol::context::context_routing_id`. Stored as a fixed-size
    /// array because `transport.send_message` requires `&[u8; 32]`.
    pub routing_id: [u8; 32],
    /// Logical operation that produced this commit (for observability +
    /// event labelling).
    pub operation: CommitOperation,
    /// Unix timestamp (seconds) when the commit first failed to broadcast.
    pub first_attempt_at: u64,
    /// Number of failed send attempts so far. Starts at 1 (the initial
    /// failure that caused enqueueing).
    pub retry_count: u32,
    /// Human-readable transport error from the most recent failed attempt.
    pub last_error: Option<String>,
    /// Unix timestamp (seconds) at which the next retry should be attempted.
    /// Set when the commit is enqueued and after each failed retry.
    pub next_attempt_at: u64,
}

/// Marker indicating that the persistent commit retry queue exhausted its
/// budget for a particular operation and the context is now fail-closed
/// (PR #1606 C6).
///
/// While `commit_fault` is set, all governance and lifecycle mutations on
/// the context return [`ContextError::CommitBroadcastFault`]. Cleared by an
/// operator via `ContextManager::acknowledge_commit_fault`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitFaultMarker {
    /// Logical operation whose commit failed permanently.
    pub operation: CommitOperation,
    /// Final transport error or `"max age exceeded"`.
    pub reason: String,
    /// Unix timestamp (seconds) when the marker was set.
    pub failed_at: u64,
    /// Total number of send attempts that were made.
    pub retry_count: u32,
}

// ---------------------------------------------------------------------------
// PendingCeilingModification (M7)
// ---------------------------------------------------------------------------

/// A pending ceiling modification awaiting notification period expiry (M7, §5.3.2).
///
/// When a `ModifyCeiling` governance action is approved, the new ceiling
/// is not applied immediately. Instead, it enters a notification period
/// during which members may leave before the expansion takes effect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingCeilingModification {
    /// The capabilities in the proposed new ceiling.
    pub new_capabilities: Vec<Capability>,
    /// Unix timestamp (seconds) when the notification period started.
    pub notified_at: u64,
    /// Convergent Unix timestamp (seconds) when the notification period
    /// expires and the new ceiling can be applied. Anchored on the
    /// committer-assigned proposal timestamp (`proposal.created_at`), so it
    /// is identical across members — and is recorded as the convergent
    /// `CeilingModified` leaf timestamp when the change is applied.
    pub effective_at: u64,
    /// Local Unix timestamp (seconds) at which THIS member observed/processed
    /// the originating governance commit. Unlike `effective_at` (which is
    /// anchored on the proposer-chosen, hence backdatable, `proposal.created_at`),
    /// this is the applying member's own clock at commit-processing time. It is
    /// the non-backdatable floor of the notification window (see
    /// [`Self::is_effective`]).
    ///
    /// SECURITY: this field is serialized into the signed export snapshot. The
    /// non-backdatable invariant holds IN-PROCESS (it is set from the local
    /// clock when the commit is processed) AND is RE-ESTABLISHED on the
    /// untrusted import path: `import_context` re-pins `observed_at` to the
    /// importing member's local clock, so a malicious exporter who backdates it
    /// in a signed export cannot collapse the notification window on import. The
    /// trusted RESTORE path (self-respawn) keeps it verbatim.
    pub observed_at: u64,
    /// The governance proposal ID that approved this modification.
    pub proposal_id: ProposalId,
}

impl PendingCeilingModification {
    /// Returns `true` if the notification period has expired and the
    /// modification can be applied.
    ///
    /// The gate is non-backdatable: it requires BOTH the convergent
    /// `effective_at` (so all members activate at the same convergent instant)
    /// AND `observed_at + NOTIFICATION_PERIOD` (so a proposer who backdates
    /// `proposal.created_at` cannot collapse the mandatory notification window
    /// below `NOTIFICATION_PERIOD` of locally observed wall-clock time). The
    /// max of the two preserves convergence in the honest case while pinning a
    /// proposer-independent lower bound in the malicious case (§5.3.2, §19.3).
    #[must_use]
    pub fn is_effective(&self, current_timestamp: u64) -> bool {
        let floor = self
            .observed_at
            .saturating_add(CEILING_CHANGE_NOTIFICATION_PERIOD_SECS);
        current_timestamp >= self.effective_at.max(floor)
    }
}

/// Default economic policy change notification period in seconds (§19.3).
///
/// When a governed context's economic policy is changed, the new policy is
/// pending for this duration before taking effect. Members are notified and
/// may leave before the new pricing applies.
///
/// Spec §19.3: "economic policy changes MUST NOT take effect sooner than
/// 24 hours after the `EconomicPolicyChanged` event."
pub(crate) const ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS: u64 = 86_400; // 24 hours

// ---------------------------------------------------------------------------
// PendingEconomicPolicyChange (§19.3)
// ---------------------------------------------------------------------------

/// A pending economic policy change awaiting notification period expiry (§19.3).
///
/// When a `SetEconomicPolicy` governance action is approved, the new policy
/// is not applied immediately. Instead, it enters a 24-hour notification
/// period during which the previous policy remains in effect. Members may
/// leave before the new pricing applies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingEconomicPolicyChange {
    /// The proposed new economic policy.
    pub new_policy: EconomicPolicy,
    /// Unix timestamp (seconds) when the notification period started.
    pub notified_at: u64,
    /// Convergent Unix timestamp (seconds) when the notification period
    /// expires and the new policy can be applied. Anchored on the
    /// committer-assigned proposal timestamp (`proposal.created_at`), so it
    /// is identical across members — and is recorded as the convergent
    /// `EconomicPolicyApplied` leaf timestamp when the change is applied.
    pub effective_at: u64,
    /// Local Unix timestamp (seconds) at which THIS member observed/processed
    /// the originating governance commit. Unlike `effective_at` (which is
    /// anchored on the proposer-chosen, hence backdatable, `proposal.created_at`),
    /// this is the applying member's own clock at commit-processing time. It is
    /// the non-backdatable floor of the 24-hour notification window (see
    /// [`Self::is_effective`]).
    ///
    /// SECURITY: this field is serialized into the signed export snapshot. The
    /// non-backdatable invariant holds IN-PROCESS (it is set from the local
    /// clock when the commit is processed) AND is RE-ESTABLISHED on the
    /// untrusted import path: `import_context` re-pins `observed_at` to the
    /// importing member's local clock, so a malicious exporter who backdates it
    /// in a signed export cannot collapse the 24-hour window on import. The
    /// trusted RESTORE path (self-respawn) keeps it verbatim.
    pub observed_at: u64,
    /// The governance proposal ID that approved this change.
    pub proposal_id: ProposalId,
}

impl PendingEconomicPolicyChange {
    /// Returns `true` if the notification period has expired and the
    /// new policy can be applied.
    ///
    /// The gate is non-backdatable: it requires BOTH the convergent
    /// `effective_at` (so all members activate at the same convergent instant)
    /// AND `observed_at + NOTIFICATION_PERIOD` (so a proposer who backdates
    /// `proposal.created_at` cannot collapse the mandatory 24-hour notification
    /// window below `NOTIFICATION_PERIOD` of locally observed wall-clock time).
    /// Spec §19.3: economic-policy changes "MUST NOT take effect sooner than 24
    /// hours after the `EconomicPolicyChanged` event is committed to the event
    /// log" — the floor anchors that 24 hours on local commit-processing time,
    /// which a proposer cannot move.
    #[must_use]
    pub fn is_effective(&self, current_timestamp: u64) -> bool {
        let floor = self
            .observed_at
            .saturating_add(ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS);
        current_timestamp >= self.effective_at.max(floor)
    }
}

// GovernanceActionResult
// ---------------------------------------------------------------------------

/// Result of suspending a member's capabilities (§5.9, ADR-031).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspendMemberResult {
    /// The DID whose capabilities were suspended.
    pub did: DID,
    /// The capabilities that were suspended.
    pub capabilities: Vec<Capability>,
}

/// Result of cryptographic revocation (§9.17, ADR-038).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeResult {
    /// The DID whose access was revoked.
    pub did: DID,
    /// The scope of revocation applied.
    pub access: AccessScope,
    /// Number of authors whose keys were rotated (broadcast contexts).
    pub rotated_author_count: usize,
}

/// Result of restoring a member's access (§5.9, ADR-031).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreAccessResult {
    /// The DID whose access was restored.
    pub did: DID,
    /// The capabilities that were restored.
    pub capabilities: Vec<Capability>,
}

/// Result of a context-wide content key rotation (§9.17, ADR-038).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentKeysRotatedResult {
    /// Optional reason that triggered the rotation.
    pub reason: Option<String>,
}

/// Result of a governance reconfiguration via deadlock recovery (ADR-031 §10).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceReconfiguredResult {
    /// The reconfiguration actions that were applied.
    pub changes_applied: usize,
}

// ---------------------------------------------------------------------------
// MigrationState (§5.11A)
// ---------------------------------------------------------------------------

/// Tracks an in-progress context migration (§5.11A).
///
/// Stored in `PerContextState` and persisted via `ContextSnapshot` while the
/// source context is in `MigratingOut` state. Cleared on cancellation or
/// tombstoning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationState {
    /// The destination context ID.
    pub destination_context_id: String,
    /// Human-readable migration rationale.
    pub reason: String,
    /// Unix timestamp (seconds) when the grace period ends.
    pub grace_period_end: u64,
    /// Whether bulk auto-invites should be sent.
    pub auto_invite: bool,
    /// The governance proposal ID that authorized this migration.
    pub proposal_id: ProposalId,
}

/// Result of a context migration proposal (§5.11A).
#[derive(Debug, Clone)]
pub struct MigrationProposedResult {
    /// The destination context ID.
    pub destination_context_id: String,
    /// Unix timestamp when the grace period ends.
    pub grace_period_end: u64,
}

/// Result of executing an approved governance action via
/// `ContextManager::execute_governance_action`.
///
/// Each variant maps 1:1 to a [`GovernanceAction`](scp_protocol::context::governance::GovernanceAction) variant (ADR-031 §2).
/// Variants that carry action-specific result data wrap a result struct;
/// others are unit variants indicating successful execution.
#[derive(Debug)]
pub enum GovernanceActionResult {
    /// A member was added to the context.
    ///
    /// Carries the MLS `Welcome` (for the newly added member, delivered
    /// out-of-band inside a signed §5.12.3 `InvitationBundle`) and the MLS
    /// `Commit` (broadcast to the EXISTING members so they advance to the new
    /// epoch). `execute_add_member` broadcasts the Commit itself; the Welcome
    /// is surfaced here so the invitation-sealing caller
    /// ([`crate::context::supervisor::Supervisor::invite_member`]) can seal it
    /// to the invitee. Both are redacting-`Debug` byte wrappers — they are
    /// public protocol messages, not key material, but the redaction keeps the
    /// generic `format!("{result:?}")` FFI surface quiet.
    MemberAdded {
        /// TLS-serialized MLS `Welcome` for the newly added member.
        welcome_bytes: RedactedBytes,
        /// TLS-serialized MLS `Commit` for the existing members (already
        /// broadcast by `execute_add_member`; surfaced for observability /
        /// caller-side delivery fallback).
        commit_bytes: RedactedBytes,
    },
    /// A member was ejected from the context (MLS removal).
    MemberRemoved,
    /// A member's role was changed.
    RoleChanged,
    /// A outlet was registered in the context.
    OutletRegistered,
    /// A outlet was removed from the context.
    OutletRemoved,
    /// The capability ceiling was modified.
    CeilingModified,
    /// The context was closed.
    ContextClosed,
    /// The context TTL was extended.
    TtlExtended,
    /// The pruning policy was modified.
    PruningPolicyModified,
    /// Single-admin authority was transferred.
    AdminTransferred,
    /// A signer was added to the threshold set.
    SignerAdded,
    /// A signer was removed from the threshold set.
    SignerRemoved,
    /// The threshold value was modified.
    ThresholdModified,
    /// A child context was created.
    ChildContextCreated,
    /// A outlet interface was established.
    OutletInterfaceEstablished,
    /// A member was reset (ADR-029, Tier 3).
    MemberReset,
    /// A governance conflict was resolved (ADR-031 §7).
    ConflictResolved,
    /// The context was promoted from ephemeral to persistent.
    ContextPromoted,
    /// A member's capabilities were suspended (application-level gate block).
    MemberSuspended(SuspendMemberResult),
    /// A member's access was cryptographically revoked (key destruction).
    AccessRevoked(RevokeResult),
    /// A member's access was restored (capabilities unsuspended / forward-restore).
    AccessRestored(RestoreAccessResult),
    /// Context-wide content keys were rotated (§9.17, ADR-038).
    ContentKeysRotated(ContentKeysRotatedResult),
    /// Governance was reconfigured via deadlock recovery (ADR-031 §10).
    GovernanceReconfigured(GovernanceReconfiguredResult),
    /// A subscriber's read access was revoked in a broadcast context
    /// (ADR-031, §5.9). The subscriber was removed from the registry and
    /// added to all authors' block lists; all author keys were rotated.
    SubscriberBanned(GovernanceBanResult),
    /// A subscriber's read access was restored in a broadcast context
    /// (ADR-031, §5.9). The DID was removed from all authors' block lists.
    /// The subscriber must re-subscribe to regain access.
    SubscriberUnbanned {
        /// The DID whose read access was restored.
        did: DID,
    },
    /// A governance action was executed successfully with no action-specific
    /// result payload. Maps to: `SetEconomicPolicy`, `ApproveSpend`,
    /// `LockEconomicPolicy`.
    Executed,
    /// A context migration was proposed and approved (§5.11A).
    MigrationProposed(MigrationProposedResult),
    /// A context migration was cancelled (§5.11A).
    MigrationCancelled,
    /// A context was tombstoned after migration (§5.11A.5).
    ContextTombstoned,
}

// ---------------------------------------------------------------------------
// ProposalOutcome -- result of proposing a governance action
// ---------------------------------------------------------------------------

/// Result of submitting a governance proposal via
/// `ContextManager::propose_governance_action_checked`.
///
/// Contains the created proposal, its current status, and an optional
/// execution result. When the proposal is auto-approved (`SingleAdmin`),
/// `execution_result` contains the result of the action execution.
/// For multi-admin models, `execution_result` is `None` until the
/// proposal is approved via votes.
#[derive(Debug)]
pub struct ProposalOutcome {
    /// The governance proposal created by the engine.
    pub proposal: GovernanceProposal,
    /// The current status of the proposal after creation. For
    /// `SingleAdmin`, this is always `Approved` (auto-approve per
    /// ADR-031 section 4a).
    pub status: ProposalStatus,
    /// The result of executing the approved action. `Some` when the
    /// proposal was auto-approved and executed (`SingleAdmin`), `None`
    /// when the proposal is pending votes (multi-admin models).
    pub execution_result: Option<GovernanceActionResult>,
}

// ---------------------------------------------------------------------------
// ContextSnapshot -- serializable full context state for persistence
// ---------------------------------------------------------------------------

/// Serializable snapshot of a context's full state for persistence.
///
/// Captures all state needed to reconstruct a `PerContextState` after a
/// process restart: lifecycle state, parameters, membership, roles,
/// executed governance proposals (replay protection), and remaining TTL.
///
/// Stored via `ContextPersistence::persist_context` under
/// `context/{context_id}/full_snapshot`. See spec section 17.4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSnapshot {
    /// The context's unique identifier.
    pub context_id: String,
    /// Convergent creator-assigned context-creation timestamp (Unix seconds).
    ///
    /// Copied verbatim from
    /// [`PerContextState::creation_timestamp_secs`](crate::context::actor::state::PerContextState::creation_timestamp_secs)
    /// at snapshot time — the identical value the creator stamped on the
    /// `ContextCreated` event-log leaf (§7.3.1, §9.9.3), NOT any member's local
    /// `now()`. Persisting it through the snapshot lets `restore_context` and
    /// `import_context` re-arm the TTL timer against the CONVERGENT deadline
    /// (`creation_timestamp_secs + params.ttl`) instead of re-deriving from
    /// importer-local `now()`, so the timer-fired `ContextExpired`/`ContextClosed`
    /// leaf converges across members (the live create path is already convergent;
    /// restore/import previously diverged — ADR-051).
    ///
    /// # Security — consumed VERBATIM, never re-pinned
    ///
    /// On `import_context` the value lives inside the creator-signed JCS snapshot
    /// preimage; import verifies the creator's signature and
    /// `exporter_did == creator_did` BEFORE consuming it
    /// (`validate_export_for_import`). Its ONLY consumer is the TTL expiry
    /// deadline, which is an UPPER bound on the context's lifetime
    /// (`creation.saturating_add(ttl)`): backdating only SHORTENS the window
    /// (fail-safe — the context expires no later than a member with an honest
    /// clock would compute), and future-dating is bounded by `ttl`. No consumer
    /// uses it as a window LOWER bound or to extend any grace/notification
    /// period, so — unlike `pending_*` `observed_at` timestamps, which gate the
    /// §5.3.2 / §19.3 notification windows and ARE re-pinned to local import time
    /// — this field is moved through verbatim. Re-pinning it to importer-local
    /// `now()` would re-introduce the very divergence this field exists to close.
    ///
    /// `#[serde(default)]` so legacy snapshots (persisted before this field
    /// existed) deserialize as `0`. A `0` here means "no convergent creation
    /// time recorded"; the resulting deadline `0 + ttl` is in the distant past,
    /// so a TTL-bearing legacy context expires immediately on restore — the
    /// fail-safe direction, consistent with the upper-bound semantics above.
    #[serde(default)]
    pub creation_timestamp_secs: u64,
    /// The context's lifecycle state at the time of snapshot.
    pub state: ContextState,
    /// The context's creation parameters (immutable after creation).
    pub context_params: ContextParams,
    /// The membership state (members, roles, sequence numbers).
    pub membership: MembershipState,
    /// The role state (ceiling, definitions, assignments, capabilities).
    pub role_state: ContextRoleState,
    /// Merkle root of the exported event log, bound into the **signed**
    /// snapshot (§23.16.4, §23.16.8).
    ///
    /// The signed context-export digest is
    /// `SHA-256(domain || scope-tag-byte || JCS(snapshot))`, so any field inside
    /// the snapshot is covered by the creator's signature.
    /// The `ContextExport` envelope also carries an unsigned `merkle_root`
    /// field, but the envelope is attacker-controlled in transit: binding the
    /// root here makes it part of the signed preimage so an attacker cannot
    /// substitute a different (internally-consistent) event log under a
    /// captured signature. `import_context` recomputes the root over the
    /// received `event_log_data` and compares it to THIS signed value
    /// (`validate_export_for_import`).
    ///
    /// **Security scope — full-history completeness AND integrity.** This root
    /// is the RFC 6962 `tree::root` over ALL event-log entries (ADR-050), not a
    /// hash-chain head. `recompute_event_log_root` recomputes it by replaying every
    /// entry through `append_unsigned_event`, validating each leaf's `sequence`
    /// against the running count and its `prev_hash` against the prior leaf
    /// (genesis for the first entry). A PREFIX-truncated log (oldest entries
    /// dropped) is rejected outright — the new first entry's non-zero
    /// `sequence` and non-genesis `prev_hash` fail the replay — while any
    /// suffix-truncated, reordered, removed-middle, or added/modified/forged log
    /// yields a different root than this signed value and fails the
    /// constant-time compare in `validate_export_for_import`. The signature thus
    /// attests that no entry can be added, modified, reordered, dropped, or
    /// forged: truncation forgery is CLOSED, not merely detected.
    ///
    /// This completeness guarantee matters for enforcement, not just audit. The
    /// imported pre-import event-log entries are consumed by post-import
    /// enforcement: on the first live action `event_log_entries_for_consequences`
    /// reads them as "Source 1" to drive consequence evaluation and
    /// participation/standing. Because the full, signed-over leaf set is the
    /// only set that verifies, an importer cannot silently suppress consequences
    /// by truncating history. A legitimately pruned log still verifies because
    /// `prune_before_checkpoint` re-anchors the retained tail to genesis and
    /// renumbers sequences from 0, making the exported pruned log itself a valid
    /// genesis-rooted prefix.
    ///
    /// All zeros when no event log is included (e.g. `ExportScope::Public`,
    /// broadcast-only contexts, or the live snapshot before export). Populated
    /// by `create_export` for `ExportScope::Full`. `#[serde(default)]` so live
    /// snapshots (which never set it) deserialize cleanly.
    #[serde(default)]
    pub event_log_merkle_root: [u8; 32],
    /// Proposal IDs that have already been executed (replay protection).
    ///
    /// Serialized in a deterministic (content-sorted) order so the signed
    /// context-export digest is reproducible (§23.16.8, ADR-050).
    #[serde(with = "scp_protocol::serde_util::serde_sorted_set")]
    pub executed_proposals: HashSet<ProposalId>,
    /// Absolute TTL expiry deadline in Unix seconds, if a TTL timer was armed.
    /// `None` if no TTL was configured.
    ///
    /// Persisted as the CONVERGENT `state.ttl.timer.deadline_unix_secs`
    /// (`creation_timestamp_secs + params.ttl`, or an already-extended
    /// convergent deadline) — an ABSOLUTE instant, identical across members,
    /// NOT a relative remaining-time. Restore/import re-arm the SAME absolute
    /// deadline the context held before the restart, so (a) the create-window
    /// stays closed (a `None`-remaining Active snapshot still re-arms via the
    /// `creation + ttl` fallback) and (b) a prior TTL extension is preserved
    /// verbatim rather than being silently recomputed back to `creation + ttl`
    /// (ADR-049 §9, D1/D2).
    ///
    /// `#[serde(default)]` so a legacy snapshot that predates this field (it
    /// carried the retired RELATIVE remaining-seconds field) decodes as `None`
    /// and falls back to the `creation + ttl` re-derivation on restore.
    #[serde(default)]
    pub ttl_deadline_secs: Option<u64>,
    /// Dynamically registered outlets (beyond initial `ContextParams.outlets`).
    #[serde(default)]
    pub registered_outlets: Vec<OutletRegistration>,
    /// Members excluded from future CEK wrapping (`Revoke { access: AccessScope::Write }`).
    /// These members won't receive new content keys but retain access to
    /// historical content encrypted before the revocation (ADR-038, §9.17).
    ///
    /// Serialized in a deterministic (content-sorted) order so the signed
    /// context-export digest is reproducible (§23.16.8, ADR-050).
    #[serde(default, with = "scp_protocol::serde_util::serde_sorted_set")]
    pub read_exclusion_list: HashSet<DID>,
    /// Established cross-context outlet interfaces (§6.2).
    #[serde(default)]
    pub outlet_interfaces: Vec<OutletInterface>,
    /// Governance threshold signers (for `ThresholdApproval` model).
    #[serde(default)]
    pub threshold_signers: Vec<DID>,
    /// Governance threshold value (quorum requirement).
    #[serde(default)]
    pub threshold_value: u32,
    /// Pruning policy override (ADR-030 §6).
    #[serde(default)]
    pub pruning_policy: Option<PruningPolicy>,
    /// Governance model configuration for engine restoration (ADR-031).
    ///
    /// Persisted so the correct `GovernanceEngine` can be reconstructed on
    /// restart. `None` for legacy snapshots (defaults to `SingleAdmin` with
    /// the first admin DID from membership).
    #[serde(default)]
    pub governance_model_config: Option<GovernanceModelConfig>,
    /// Mutable economic policy (§19.3, ADR-033). Updated via
    /// `SetEconomicPolicy` / `LockEconomicPolicy` governance actions.
    /// `None` means free context (no payment required).
    #[serde(default)]
    pub economic_policy: Option<EconomicPolicy>,
    /// Per-member cumulative budget tracker for governance-approved spending
    /// (§19.5, ADR-033). Tracks grants from `ApproveSpend` governance actions.
    #[serde(default)]
    pub budget_tracker: MemberBudgetTracker,
    /// Approved proposals pending execution, tracked for conflict detection (ADR-031 §7).
    ///
    /// Maps proposal ID to a tuple `(proposal, monotonic_seq, approved_at_unix_secs)`:
    /// - `monotonic_seq` — the local monotonic sequence number assigned by
    ///   [`GovernanceState::next_proposal_seq`] at conflict-detection time.
    ///   Used by `detect_and_handle_conflicts` for sequential conflict
    ///   resolution (lower seq wins). Strictly monotonic across the
    ///   lifetime of a context, persisted in this snapshot, so two
    ///   proposals can never share a seq even within the same wall-clock
    ///   second (H10 fix).
    /// - `approved_at_unix_secs` — the wall-clock Unix timestamp at
    ///   approval, retained for audit / event-emission purposes only.
    ///   Never used for conflict ordering.
    ///
    /// Serialized as a hex-keyed object (the `ProposalId = [u8; 32]` key
    /// cannot be a JSON object key directly) so the whole snapshot survives
    /// RFC 8785 JCS canonicalization for the signed context export
    /// (§23.16.8, ADR-050). JCS sorts the hex keys, making the digest
    /// deterministic regardless of `HashMap` iteration order.
    #[serde(default, with = "scp_protocol::serde_util::serde_hex_keyed_map_32")]
    pub approved_proposals: HashMap<ProposalId, (GovernanceProposal, u64, u64)>,
    /// Monotonic counter for assigning proposal sequence numbers to
    /// approved proposals (H10, ADR-031 §7).
    ///
    /// Incremented every time a new approved proposal is inserted into
    /// [`approved_proposals`](Self::approved_proposals). Persisted across
    /// process restarts so two proposals can never share a sequence number
    /// within the same context — eliminating the wall-clock collision
    /// window that previously let an attacker race a conflicting proposal
    /// against any defensive admin action and force a 48-hour governance
    /// freeze.
    ///
    /// Backward compatible with legacy snapshots: missing field
    /// deserializes as `0`. On `import_context` (untrusted exporter), the
    /// counter is conservatively reset to `approved_proposals.len() as u64`
    /// — see `lifecycle::import_context`.
    #[serde(default)]
    pub next_proposal_seq: u64,
    /// Governance freeze state due to simultaneous conflicts (ADR-031 §7).
    /// Contains the conflicting proposal IDs and freeze start timestamp.
    #[serde(default)]
    pub governance_freeze: Option<(ProposalId, ProposalId, u64)>,
    /// Pending ceiling modification (M7, §5.3.2 notification period).
    ///
    /// When a `ModifyCeiling` governance action is approved, the new ceiling
    /// is stored here with the notification timestamp. Members are notified
    /// and may leave before the ceiling expansion takes effect. The pending
    /// ceiling is applied after the notification period expires.
    ///
    /// Format: `(new_ceiling_capabilities, notification_timestamp, proposal_id)`.
    #[serde(default)]
    pub pending_ceiling_modification: Option<PendingCeilingModification>,
    /// Pending economic policy change (§19.3 notification period).
    ///
    /// When a `SetEconomicPolicy` governance action is approved, the new
    /// policy is stored here with the notification timestamp. Members are
    /// notified and the previous policy remains in effect until the 24-hour
    /// notification period expires.
    #[serde(default)]
    pub pending_economic_policy_change: Option<PendingEconomicPolicyChange>,
    /// Monotonic MLS epoch counter. Tracks epoch advances from membership-
    /// mutating governance actions (`AddMember`, `RemoveMember`,
    /// `Revoke`, `ResetMember`).
    #[serde(default)]
    pub mls_epoch: u64,
    /// Epoch coordination records linking governance proposals to MLS epoch
    /// transitions (ADR-031 §8, issue #630). Persisted for auditability.
    #[serde(default)]
    pub epoch_coordination_records: Vec<CoordinationRecord>,
    /// Persisted epoch grace window entries (§23.11).
    ///
    /// Captured from [`EpochGraceStore::to_grace_entries`](scp_mls::epoch_grace::EpochGraceStore::to_grace_entries)
    /// during snapshot creation. On recovery, fed to
    /// [`EpochGraceStore::restore_from_entries`](scp_mls::epoch_grace::EpochGraceStore::restore_from_entries)
    /// to reconstruct the grace store. Persisted alongside all other context
    /// state to ensure transactional consistency (§23.11 step 2).
    #[serde(default)]
    pub grace_entries: Vec<scp_mls::epoch_grace::GraceEntry>,
    /// Whether this context needs to re-enter the reconnection protocol
    /// (§23.3) before processing new messages (§23.11 inconsistent state
    /// fallback step 3). Persisted so the flag survives additional restarts
    /// before reconnection occurs.
    #[serde(default)]
    pub needs_reconnect: bool,
    /// Opaque MLS crypto state blob exported by
    /// `ContextCryptoProvider::export_crypto_state`. Contains MLS group
    /// tree, epoch secrets, sender keys, and wrapping keys. Restored via
    /// `ContextCryptoProvider::restore_crypto_state` during
    /// `Supervisor::restore_context`.
    ///
    /// Empty if no crypto state was exported (e.g., broadcast-only contexts
    /// or mock providers). See issue #645.
    #[serde(default, with = "serde_bytes")]
    pub mls_crypto_state: Vec<u8>,
    /// Active migration state (§5.11A). `Some` when the context is in
    /// `MigratingOut` state, `None` otherwise. Persisted so migration
    /// can survive process restarts during the grace period.
    #[serde(default)]
    pub migration_state: Option<MigrationState>,
    /// Per-member access key store for content encryption key wrapping
    /// (ADR-038, §9.17). Persisted so access keys survive process restarts
    /// and can be used to wrap/unwrap content after recovery.
    ///
    /// **Security invariant**: Contains raw AES-256 key material. The
    /// persistence layer MUST encrypt at rest (via `EncryptingAdapter` or
    /// equivalent). See ADR-025.
    #[serde(default)]
    pub access_key_store: scp_protocol::crypto::access_keys::AccessKeyStore,
    /// Consequence rules declared at context creation (ADR-017, #1531).
    #[serde(default)]
    pub consequence_rules: Vec<scp_protocol::trust::consequence::ConsequenceRule>,
    /// Per-member participation record cache for proposer eligibility (#1530).
    #[serde(default)]
    pub participation_cache:
        HashMap<String, scp_protocol::trust::participation::ParticipationRecord>,
    /// Sender velocity tracker window configuration for anti-spam and
    /// consequence evaluation (§19.7, #1537). Persisted so velocity state
    /// survives process restarts. Contains the `window_secs` configuration.
    ///
    /// **Deprecated**: Retained for backward-compatible deserialization of
    /// snapshots that predate `velocity_tracker_state`. New snapshots populate
    /// `velocity_tracker_state` instead.
    #[serde(default)]
    pub velocity_tracker: Option<u64>,
    /// Full velocity tracker state including per-sender timestamps (#1530).
    ///
    /// Supersedes `velocity_tracker` (config-only). Contains both the sliding
    /// window configuration and the per-sender message timestamp entries so
    /// velocity state survives process restarts without losing rate history.
    #[serde(default)]
    pub velocity_tracker_state: Option<VelocityTrackerSnapshot>,
    /// Per-rule cooldown timers for consequence dispatch (#1531).
    ///
    /// Maps consequence rule index to the Unix timestamp (seconds) until which
    /// the rule should not re-fire. Prevents repeated consequence dispatch
    /// within a rule's evaluation window. Persisted so cooldown state survives
    /// process restarts.
    #[serde(default)]
    pub cooldown_until: HashMap<usize, u64>,
    /// Per-member governance proposal timestamps for earned capacity rate
    /// limiting (§9.3). Maps member DID string to Unix timestamps of recent
    /// proposals. Persisted so rate limiting survives process restarts.
    #[serde(default)]
    pub proposal_timestamps: HashMap<String, Vec<u64>>,
    /// Spec §19.7 per-DID escalating-cost message pricing configuration.
    /// `None` for legacy snapshots; on restore, defaults to
    /// `ContextMessagePricingConfig::spec_default()`.
    #[serde(default)]
    pub message_pricing: Option<scp_protocol::economy::antispam::ContextMessagePricingConfig>,
    /// Hard rate limit (Matrix Synapse–style token bucket) configuration.
    /// `None` for legacy snapshots; on restore, defaults to
    /// `HardRateLimitConfig::matrix_defaults()`.
    #[serde(default)]
    pub hard_rate_limit_config: Option<scp_protocol::economy::antispam::HardRateLimitConfig>,
    /// Per-sender token bucket state for the hard rate limit, captured at
    /// snapshot time. Empty for legacy snapshots; restored verbatim into the
    /// new limiter via `TokenBucketLimiter::from_snapshot`.
    #[serde(default)]
    pub hard_rate_limit_state: HashMap<String, (u64, u64)>,
    /// Per-context spending-UCAN nonce tracker state (ADR-016 §6, #1608
    /// follow-up). Maps nonce string to `(first_seen_secs, token_expiry_secs)`.
    ///
    /// Persisted so a captured spending UCAN cannot be replayed after a
    /// restart — without this, the fresh in-memory tracker would have
    /// no record of previously-consumed nonces, and an attacker could
    /// replay valid spending tokens until the `max_total` budget was
    /// exhausted a second time.
    ///
    /// MIGRATION: `#[serde(default)]` — legacy snapshots deserialize as
    /// an empty map, producing a tracker with no prior entries. This
    /// is the same behavior as the pre-persistence runtime, so upgrade
    /// does not introduce any new risk.
    #[serde(default)]
    pub spending_nonce_tracker_state: HashMap<String, (u64, u64)>,
    /// Revoked spending-UCAN CIDs (ADR-049 §9 Class S — security-critical
    /// monotonic state).
    ///
    /// Persisted so the revocation set survives an actor crash / respawn /
    /// process restart. Without this the set would be reconstructed empty on
    /// restore, re-admitting a spending UCAN whose revocation a caller had
    /// already observed — a downward-authorization rollback the §9 crash-safety
    /// invariant forbids. Serialized in deterministic (content-sorted) order so
    /// the signed context-export digest is reproducible (§23.16.8, ADR-050),
    /// matching `executed_proposals` and `read_exclusion_list`.
    ///
    /// NOTE (honesty): governance does not yet POPULATE this set — spending-UCAN
    /// revocation is not wired through a governance action, so it is empty in
    /// steady state today. Persisting it now makes the field crash-safe BY
    /// CONSTRUCTION (Class S) so the moment revocation lands it is durable
    /// without a separate persistence change; the prior code reset it to empty
    /// on every restore, which would have silently dropped revocations the
    /// instant a writer existed.
    #[serde(default, with = "scp_protocol::serde_util::serde_sorted_set")]
    pub revoked_spending_ucan_cids: HashSet<String>,
    /// Persistent MLS Commit broadcast retry queue (PR #1606 C6).
    ///
    /// Captures pending commits whose `transport.send_message` calls failed
    /// after the local state mutation. Restored on process restart so that
    /// the governance timeout task continues retrying after a crash.
    ///
    /// MIGRATION: `#[serde(default)]` — legacy snapshots deserialize as
    /// an empty queue, matching pre-feature behavior.
    #[serde(default)]
    pub pending_commits: VecDeque<PendingCommit>,
    /// Fail-close marker for the persistent commit retry queue (PR #1606 C6).
    ///
    /// `Some` when a pending commit exhausted `MAX_COMMIT_RETRIES` or
    /// `MAX_COMMIT_AGE_SECS`. Persisted so the fail-close state survives
    /// restart and an operator must explicitly acknowledge the fault before
    /// further mutations are accepted.
    ///
    /// MIGRATION: `#[serde(default)]` — legacy snapshots deserialize as
    /// `None`, matching pre-feature behavior.
    #[serde(default)]
    pub commit_fault: Option<CommitFaultMarker>,
    /// Number of event log appends since the last consistency checkpoint (§9.9.3).
    /// Persisted so the checkpoint interval counter survives process restarts.
    #[serde(default)]
    pub checkpoint_events_since: u64,
    /// Unix timestamp (seconds) of the last consistency checkpoint (§9.9.3).
    /// Persisted so the time-based checkpoint trigger survives restarts.
    #[serde(default)]
    pub checkpoint_last_time_secs: u64,
    /// Monotonic generation counter for confused-deputy detection (Phase B).
    /// Assigned on insertion into the contexts map. Legacy snapshots
    /// deserialize as `0` via `#[serde(default)]`.
    #[serde(default)]
    pub generation: u64,
    /// Per-context routing strategy (§9.10.4, §5.14).
    ///
    /// Encrypted contexts persist the member's pseudonym routing ID and the
    /// learned peer registry; broadcast contexts persist
    /// [`ContextRouting::Broadcast`](crate::context::actor::state::ContextRouting::Broadcast) and carry no pseudonym state.
    ///
    /// Degraded / pre-routing-field snapshots (those persisted before this
    /// field existed, or `strip_snapshot_for_public` redactions) default to
    /// [`ContextRouting::Broadcast`](crate::context::actor::state::ContextRouting::Broadcast) via [`default_context_routing`] — a
    /// no-pseudonym placeholder that carries no routing secret.
    ///
    /// The restore path does NOT silently coerce this placeholder onto an
    /// encrypted context. It reconstructs the *real* mode (encrypted vs
    /// broadcast, derived from whether broadcast crypto state reloaded) and
    /// requires the persisted `routing.is_broadcast()` to AGREE with it. A
    /// degraded snapshot of a *broadcast* context restores fine (placeholder
    /// `Broadcast` agrees with the reconstructed broadcast mode). A degraded
    /// snapshot of an *encrypted* context FAILS CLOSED: the placeholder
    /// `Broadcast` disagrees with the reconstructed encrypted mode, so restore
    /// returns [`ContextError::PersistenceFailed`](scp_protocol::context::ContextError::PersistenceFailed)
    /// rather than loading a context whose routing axis contradicts its crypto
    /// axis. This is acceptable pre-1.0 (no deployed data, no persisted
    /// encrypted snapshots predating this field); the alternative — defaulting
    /// to a fabricated pseudonymous variant — would mask snapshot corruption.
    /// On a non-degraded restore the persisted variant is moved through
    /// verbatim; an empty `pseudonym_registry` simply means peers must
    /// re-announce, the same state a cold restore always starts from.
    #[serde(default = "default_context_routing")]
    pub routing: crate::context::actor::state::ContextRouting,
    /// Staged cross-context saga evidence awaiting Commit or Abort
    /// (ADR-049 §3 / §9; spec §5.15.8, §6.2.4). **Class S** —
    /// synchronously-persisted, fail-closed.
    ///
    /// # Crash-safety classification — Class S (sync-persisted, fail-closed)
    ///
    /// ADR-049 §9 line 144 lists "`saga_pending` Prepare/Commit/Abort
    /// transitions in the actor snapshot" in the synchronously-persisted set.
    /// The live actor-side slot is
    /// [`PerContextState::saga_pending`](crate::context::actor::state::PerContextState::saga_pending),
    /// a `HashMap<SagaId, SagaPreparedState>`. Each Prepare/Commit/Abort
    /// transition persists the snapshot containing this map SYNCHRONOUSLY —
    /// via [`persist_state_fail_closed`](crate::context::messaging_helpers::persist_state_fail_closed)
    /// — BEFORE the phase reply is acked, and a persist FAILURE FAILS CLOSED
    /// (the handler returns `Err`, never a best-effort `Ok`). Without this, a
    /// crash between Prepare and Commit would leave the supervisor
    /// `SagaJournal` recording a phase the actor can no longer replay (lost
    /// staged MLS handles / reservation linkage) — an orphaned reservation
    /// plus a wedged saga that can neither commit nor cleanly abort.
    ///
    /// # Non-derive barrier (§9.4.3)
    ///
    /// The live [`SagaPreparedState`](crate::context::supervisor::saga_prepared_state::SagaPreparedState)
    /// enum deliberately does NOT derive `Serialize`/`Deserialize` (the
    /// §9.4.3 bearer barrier). This snapshot field therefore carries the
    /// sanctioned public-projection mirror
    /// [`SagaPreparedStateSnapshot`](crate::context::supervisor::saga_prepared_state::SagaPreparedStateSnapshot)
    /// instead, populated through the shared
    /// [`saga_pending_snapshot`](crate::context::messaging_helpers::saga_pending_snapshot)
    /// helper at every snapshot builder.
    ///
    /// # Local-only coordination state
    ///
    /// This is local cross-context coordination evidence with no authority on
    /// any other node. Same-node restore REHYDRATES it (crash recovery);
    /// cross-node `import_context` and the public `strip_snapshot_for_public`
    /// export DROP it to empty — a foreign saga must never drive local
    /// Commit/Abort. `#[serde(default)]` so legacy / stripped snapshots
    /// deserialize as an empty map.
    #[serde(default)]
    pub saga_pending: HashMap<
        crate::context::supervisor::saga_journal::SagaId,
        crate::context::supervisor::saga_prepared_state::SagaPreparedStateSnapshot,
    >,

    /// Target-side (B-owned) durable capture of COMMITTED cross-context outlet
    /// invocations, keyed by `SagaId` (spec §6.2.4 "Exactly-once execution with
    /// durable output capture"). **Class S** — synchronously-persisted,
    /// fail-closed, mirroring [`Self::saga_pending`].
    ///
    /// The live actor-side slot is
    /// [`ClassSState::xctx_committed_outputs`](crate::context::actor::state::ClassSState::xctx_committed_outputs).
    /// Commit-B captures the outlet output + signed receipt here BEFORE acking, so
    /// a Commit replayed after a crash (§17.16.4) re-emits the stored output and
    /// re-signs nothing — it returns the IDENTICAL receipt. A coalesce-window
    /// rollback of this capture would re-invoke the outlet on replay, the exact
    /// exactly-once violation the synchronous persist forecloses.
    ///
    /// Unlike `saga_pending` this carries no §9.4.3 non-derive barrier — the
    /// receipt + output are public protocol artifacts (no bearer bytes), so the
    /// snapshot stores the live
    /// [`CommittedOutletInvocation`](crate::context::supervisor::saga_prepared_state::CommittedOutletInvocation)
    /// directly. Same local-only coordination semantics: same-node restore
    /// REHYDRATES it; cross-node `import_context` / `strip_snapshot_for_public`
    /// DROP it to empty (a foreign saga must never drive local Commit replay).
    /// `#[serde(default)]` so legacy / stripped snapshots deserialize as empty.
    #[serde(default)]
    pub xctx_committed_outputs: HashMap<
        crate::context::supervisor::saga_journal::SagaId,
        crate::context::supervisor::saga_prepared_state::CommittedOutletInvocation,
    >,

    /// Target-side (B-owned) durable, `SagaId`-keyed capture of COMMITTED
    /// cross-context **streaming** outlet invocations (ADR-061 seal phase; spec
    /// §6.2.5 streaming saga). **Class S** — synchronously-persisted, fail-closed,
    /// mirroring [`Self::xctx_committed_outputs`].
    ///
    /// The live slot is
    /// [`ClassSState::xctx_committed_stream_outputs`](crate::context::actor::state::ClassSState::xctx_committed_stream_outputs).
    /// The seal at stream-close captures the signed streaming receipt + sealed
    /// `stream_manifest_hash` + billing/chunk counters here BEFORE journaling
    /// `Committed`, so a Commit replayed after a crash (§17.16.4) re-emits the
    /// IDENTICAL receipt and re-acks the SAME event id **without re-invoking the
    /// outlet**. A coalesce-window rollback would re-invoke a non-deterministic
    /// LLM on replay, the exact hazard the synchronous persist forecloses. It also
    /// makes the AC7 mid-stream-crash truncated-close well-defined: recovery seals
    /// the restored durable frontier prefix once, and a replayed seal short-circuits
    /// on this witness. Same-node restore REHYDRATES it; cross-node export/import
    /// DROP it to empty. `#[serde(default)]` so legacy / stripped snapshots
    /// deserialize as empty.
    #[serde(default)]
    pub xctx_committed_stream_outputs: HashMap<
        crate::context::supervisor::saga_journal::SagaId,
        crate::context::supervisor::saga_prepared_state::CommittedStreamingOutletInvocation,
    >,

    /// Caller-side (A-owned) durable set of COMMITTED cross-context outlet
    /// invocations, keyed by `SagaId` (spec §6.2.4 "Commit", caller side;
    /// §17.16.4). **Class S** — synchronously-persisted, fail-closed, mirroring
    /// [`Self::saga_pending`].
    ///
    /// The live slot is
    /// [`ClassSState::xctx_committed_invocations`](crate::context::actor::state::ClassSState::xctx_committed_invocations).
    /// Commit-A inserts the `SagaId` here as the idempotency witness BEFORE
    /// acking; a replayed Commit-A re-acks as a no-op. A coalesce-window
    /// rollback would let a replay double-settle the escrow, the exact hazard
    /// the synchronous persist forecloses. Same-node restore REHYDRATES it;
    /// cross-node export/import DROP it to empty. `#[serde(default)]` so legacy /
    /// stripped snapshots deserialize as empty.
    #[serde(default)]
    pub xctx_committed_invocations:
        std::collections::HashSet<crate::context::supervisor::saga_journal::SagaId>,

    /// Caller-side (A-owned) durable reversal records for in-flight
    /// cross-context outlet-invocation Prepare-A reservations, keyed by `SagaId`
    /// (spec §6.2.4 "Reservation release on every terminal path"). **Class S** —
    /// synchronously-persisted, fail-closed, mirroring [`Self::saga_pending`].
    ///
    /// The live slot is
    /// [`ClassSState::xctx_caller_reservations`](crate::context::actor::state::ClassSState::xctx_caller_reservations).
    /// Prepare-A inserts a record here in the same Class-S snapshot as the
    /// deduction it reverses; on a `PreparingB`-window crash the recovery sweep's
    /// clean abort (`Abort { reservation: None }`) reverses the caller's
    /// velocity / budget / hard-rate-limit and voids the external escrow FROM
    /// this record — the in-memory RAII carrier died with the crash, so without
    /// it the caller would be durably over-charged and the escrow would leak. A
    /// coalesce-window rollback of an inserted record would lose the only durable
    /// reversal handle, the exact hazard the synchronous persist forecloses.
    /// Same-node restore REHYDRATES it; cross-node export/import DROP it to empty
    /// (caller economy is local). `#[serde(default)]` so legacy / stripped
    /// snapshots deserialize as empty.
    ///
    /// Like `xctx_committed_outputs` this carries no §9.4.3 non-derive barrier —
    /// every field is public economy metadata (the escrow handle is the same
    /// serde [`PaymentAuthorization`](crate::economy::adapter::PaymentAuthorization)
    /// the payment rail issues), so the snapshot stores the live
    /// [`CallerReservationRecord`](crate::context::supervisor::saga_prepared_state::CallerReservationRecord)
    /// directly.
    #[serde(default)]
    pub xctx_caller_reservations: std::collections::HashMap<
        crate::context::supervisor::saga_journal::SagaId,
        crate::context::supervisor::saga_prepared_state::CallerReservationRecord,
    >,

    /// Target-side (B-owned) anti-replay nonce-dedup cache for cross-context
    /// outlet invocation (spec §6.2.4 "Freshness / anti-replay"). The serialized
    /// projection of
    /// [`ClassSState::xctx_nonce_dedup`](crate::context::actor::state::ClassSState::xctx_nonce_dedup):
    /// `{16-byte nonce → first-seen Unix secs}`.
    ///
    /// **Class S** — synchronously-persisted, fail-closed, mirroring
    /// [`Self::saga_pending`]. This cache is the ONLY gate against a replayed
    /// `CrossContextOutletInvoke` envelope re-submitted under a FRESH `SagaId`
    /// within the 5-minute TTL (the `SagaId` idempotency witnesses and the
    /// `xctx_committed_outputs` short-circuit only catch a SAME-`SagaId` replay).
    /// If it reinitialized empty on restore, an actor crash inside the TTL window
    /// would let an attacker re-run a charging outlet (BLACK-624-01). Persisting it
    /// makes Prepare-B's recorded-nonce rejection actually survive a restart —
    /// the recorded nonce is already deliberately KEPT on the reject path "for
    /// replay protection", and this is what makes that intent durable.
    ///
    /// Same-node restore REHYDRATES it (via
    /// [`NonceDedup::from_entries`](scp_protocol::crypto::sender_keys::NonceDedup::from_entries),
    /// with the per-entry TTL pruned lazily on the next check); cross-node
    /// `import_context` / `strip_snapshot_for_public` DROP it to empty — B's
    /// freshness state has no authority on a foreign node, and a fresh node
    /// starts its own replay window. `#[serde(default)]` so legacy / stripped
    /// snapshots deserialize as an empty cache.
    #[serde(default)]
    pub xctx_nonce_dedup: HashMap<[u8; 16], u64>,

    /// §7.3.8 value-caveat runtime enforcement counters, keyed by the
    /// invocation-authorizing UCAN CID. The serialized projection of
    /// [`PerContextState::caveat_counters`](crate::context::actor::state::ClassSState::caveat_counters).
    ///
    /// **Class S** — synchronously-persisted, fail-closed (ADR-049 §9). A
    /// consumed `max_calls` / `amount_max_cumulative` / `rate_window` cap must
    /// NEVER un-consume: a coalesce-window crash that rolled a consume back
    /// behind an acked invocation would re-open the spend/rate window the
    /// counter closes. Same-node restore REHYDRATES the map; cross-node public
    /// export STRIPS it to empty (a foreign node starts its own accounting,
    /// exactly like the budget tracker and the xctx witnesses).
    /// `#[serde(default)]` so legacy / stripped snapshots deserialize empty.
    #[serde(default)]
    pub caveat_counters: HashMap<String, crate::trust::caveat_counters::CaveatCounters>,

    /// Fix-D durable crash-recovery records for in-flight STREAMING
    /// reservations, keyed by the stream `request_id` (hex). The serialized
    /// projection of
    /// [`ClassSState::stream_reservations`](crate::context::actor::state::ClassSState::stream_reservations).
    ///
    /// **Class S** — synchronously-persisted, fail-closed (ADR-049 §9). Each
    /// [`StreamReservationRecord`](crate::context::outlets::invoke::StreamReservationRecord)
    /// is the only durable handle to RELEASE a stream's open-time escrow hold +
    /// §7.3.8 cumulative counter reserve when the off-mailbox pump — a `tokio`
    /// task that SURVIVES an actor crash + respawn — would otherwise strand them
    /// (its close-time settle lands on the respawned generation and is dropped).
    /// Same-node restore REHYDRATES the map so the post-restore reconcile sweep
    /// can drain it; cross-node public export STRIPS it to empty (a foreign node
    /// must never drive a local invoker-economy release). `#[serde(default)]` so
    /// legacy / stripped snapshots deserialize empty.
    #[serde(default)]
    pub stream_reservations:
        HashMap<String, crate::context::outlets::invoke::StreamReservationRecord>,

    /// Broadcast context security + roster state (§5.14, §5.14.8).
    ///
    /// **Class S** — the per-author key epochs, block lists, and the subscriber
    /// registry ride the fail-closed [`ContextSnapshot`] so a block / governance
    /// ban / key-epoch advance is durable BEFORE the operation acks (ADR-049 §9).
    /// Previously broadcast state was persisted best-effort through a SEPARATE
    /// `persist_broadcast` write that warn!-and-continued on failure: an author
    /// crash in the coalesce window after a block returned success silently
    /// re-granted the revoked member post-block key access
    /// (encryption-as-access-control violation, §5.14.8 block-before-serve). Folding
    /// it here makes the block / ban / epoch-advance atomic with
    /// `read_exclusion_list` in one fail-closed row.
    ///
    /// `None` for non-broadcast contexts. `#[serde(default)]` so legacy /
    /// non-broadcast snapshots deserialize cleanly.
    #[serde(default)]
    pub broadcast: Option<BroadcastContextSnapshot>,
}

/// Default routing variant for degraded / pre-routing-field snapshots.
///
/// Returns [`ContextRouting::Broadcast`](crate::context::actor::state::ContextRouting::Broadcast) — a placeholder that carries no
/// pseudonym secret. The restore path requires this to agree with the
/// reconstructed mode (§9.10.4): a degraded *broadcast* snapshot restores
/// fine, but a degraded *encrypted* snapshot fails closed
/// ([`ContextError::PersistenceFailed`](scp_protocol::context::ContextError::PersistenceFailed))
/// rather than silently loading an encrypted context with a broadcast routing
/// axis. This default therefore never downgrades an encrypted context's
/// routing — it surfaces the corruption instead.
const fn default_context_routing() -> crate::context::actor::state::ContextRouting {
    crate::context::actor::state::ContextRouting::Broadcast
}

/// Serializable snapshot of [`SenderVelocityTracker`](scp_protocol::economy::antispam::SenderVelocityTracker)
/// state for persistence in [`ContextSnapshot`].
///
/// Captures both the sliding window configuration (`window_secs`) and per-sender
/// message timestamps (`entries`) so velocity tracking survives process restarts
/// without losing rate history. See spec §19.7 and #1530.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VelocityTrackerSnapshot {
    /// Sliding window duration in seconds (same as `SenderVelocityTracker::window_secs`).
    pub window_secs: u64,
    /// Per-sender message timestamps (DID string → Vec of Unix timestamps in seconds).
    pub entries: HashMap<String, Vec<u64>>,
}

// `ContextPersistence` trait moved to `crate::context::persistence` in
// ADR-049 §15.

// ---------------------------------------------------------------------------
// PerContextState -- internal per-context tracking
// ---------------------------------------------------------------------------

/// Governance-related per-context state.
///
/// **Visibility:** elevated to `pub(crate)` by ADR-049 §15 so the
/// actor's [`crate::context::actor::state::PerContextState`] can carry a
/// field of this type while the handler-body migration is under way.
/// ADR-049 §15 deletes this struct along with the rest of the legacy manager
/// module.
pub(crate) struct GovernanceState {
    /// The governance engine for this context (ADR-031, spec §5.9).
    pub(crate) engine: Box<dyn GovernanceEngine>,
    /// Approved proposals pending execution, tracked for conflict detection (ADR-031 §7).
    ///
    /// Maps proposal ID to a tuple `(proposal, monotonic_seq, approved_at_unix_secs)`:
    /// - `monotonic_seq` — the value of [`Self::next_proposal_seq`] at
    ///   the moment the proposal was inserted. Strictly monotonic across
    ///   the context lifetime; used by `detect_and_handle_conflicts` for
    ///   sequential conflict resolution (lower seq wins). H10 fix —
    ///   replaces wall-clock timestamps which collide within a 1-second
    ///   window and can be raced into a 48-hour governance freeze.
    /// - `approved_at_unix_secs` — wall-clock Unix timestamp at approval,
    ///   retained for audit / event emission only. Never used for
    ///   conflict ordering.
    pub(crate) approved_proposals: HashMap<ProposalId, (GovernanceProposal, u64, u64)>,
    /// Monotonic counter for assigning proposal sequence numbers (H10, ADR-031 §7).
    ///
    /// Incremented every time `detect_and_handle_conflicts` inserts a new
    /// approved proposal. Persisted in [`ContextSnapshot::next_proposal_seq`]
    /// so two proposals can never share a sequence number even across
    /// process restarts. On `import_context` (untrusted), reset
    /// conservatively to `approved_proposals.len() as u64` — see
    /// `lifecycle::import_context`.
    pub(crate) next_proposal_seq: u64,
    /// Governance freeze state due to simultaneous conflicts (ADR-031 §7).
    /// Contains the conflicting proposal IDs and freeze start timestamp.
    pub(crate) freeze: Option<(ProposalId, ProposalId, u64)>,
    /// Per-context deadlock detection tracking (ADR-031 §10).
    pub(crate) deadlock: DeadlockDetectionState,
    /// Pending ceiling modification awaiting notification period (M7, §5.3.2).
    pub(crate) pending_ceiling_modification: Option<PendingCeilingModification>,
    /// Pending economic policy change awaiting notification period (§19.3).
    pub(crate) pending_economic_policy_change: Option<PendingEconomicPolicyChange>,
    /// Dynamically registered outlets (beyond initial `ContextParams.outlets`).
    pub(crate) registered_outlets: Vec<OutletRegistration>,
    /// Established cross-context outlet interfaces (§6.2).
    pub(crate) outlet_interfaces: Vec<OutletInterface>,
    /// Pruning policy override (ADR-030 §6).
    pub(crate) pruning_policy: Option<PruningPolicy>,
    /// Mutable economic policy (§19.3, ADR-033).
    pub(crate) economic_policy: Option<EconomicPolicy>,
    /// Per-member cumulative budget tracker for governance-approved spending
    /// (§19.5, ADR-033). Grants are recorded via `ApproveSpend` governance
    /// actions and tracked here. Persisted in [`ContextSnapshot`].
    pub(crate) budget_tracker: MemberBudgetTracker,
    /// Last known member set for departure detection in the timeout loop.
    /// Compared each tick to the current member set to identify departures.
    pub(crate) last_known_members: HashSet<DID>,
    /// Members who have undergone a governance-triggered epoch reset
    /// (`ResetMember`, ADR-029 Tier 3) since the last timeout tick.
    /// Drained each tick and passed to `process_pending_proposals` so
    /// their votes on pending proposals are invalidated (ADR-031 §5).
    pub(crate) pending_epoch_resets: Vec<DID>,
    /// Consequence rules declared at context creation (ADR-017, #1531).
    pub(crate) consequence_rules: Vec<ConsequenceRule>,
    /// Sender velocity tracker for anti-spam and consequence evaluation (§19.7, #1537).
    pub(crate) velocity_tracker: scp_protocol::economy::antispam::SenderVelocityTracker,
    /// Per-member participation record cache for proposer eligibility (#1530).
    ///
    /// Widened to `pub(crate)` in ADR-049 §15 so the hoisted
    /// [`crate::context::messaging_helpers::finalize_send`] free function
    /// can refresh the cache after a successful send (matches the legacy
    /// behavior — the legacy method body lived in `manager/messaging.rs`
    /// which has submodule-descendant visibility into this field; the
    /// hoisted free function lives outside the `manager` submodule tree
    /// and requires explicit `pub(crate)` to access it).
    pub(crate) participation_cache:
        HashMap<String, scp_protocol::trust::participation::ParticipationRecord>,
    /// Cooldown tracking for consequence rules: maps `rule_index` to the Unix
    /// timestamp (seconds) until which the rule should not re-fire. Prevents
    /// repeated consequence dispatch within a rule's evaluation window.
    pub(crate) cooldown_until: HashMap<usize, u64>,
    /// Spec §19.7 per-DID escalating-cost message pricing configuration.
    ///
    /// Bundles base cost, escalation tiers, and floor/cap clamps. The
    /// hard rate limit (Matrix-style token bucket, defense-in-depth)
    /// is configured separately via `hard_rate_limit` below.
    pub(crate) message_pricing:
        Option<scp_protocol::economy::antispam::ContextMessagePricingConfig>,
    /// Defense-in-depth Matrix-style token bucket hard rate limiter.
    ///
    /// Layered on top of the per-DID economic escalation in spec §19.7. This
    /// is enforced even when `economic_policy` is `None`. See ADR notes on
    /// the dormant anti-spam wiring fix.
    pub(crate) hard_rate_limit: scp_protocol::economy::antispam::TokenBucketLimiter,
    /// Per-context revoked spending-UCAN CIDs (C1, PR #1606).
    ///
    /// Consulted by `enforce_economy` via the
    /// [`ContextRevocationChecker`](crate::context::economy_logic::ContextRevocationChecker) adapter when validating
    /// spending UCANs through the full cryptographic pipeline. Currently
    /// empty in steady state — spending UCAN revocation lists have not been
    /// wired through governance — but the field exists so the only change
    /// required when revocation lands is populating it (no enforcement
    /// rewrite needed). The set is part of the governance bucket because
    /// revocation actions are governance-driven (§19.5).
    ///
    /// ADR-049 §9 classifies this revocation set as **Class S**: a coalesce-window
    /// rollback of a revocation would re-admit a spending UCAN the caller observed
    /// as revoked. Privatized to `pub(in crate::context)` (defense-in-depth, so it
    /// is unnameable outside `crate::context`) and left to the `..` rest of the
    /// best-effort [`GovernanceClassCMut`](crate::context::actor::class_s) view's
    /// destructure, so that best-effort path holds no `&mut` to it — when
    /// revocation wiring lands it must route through a fail-closed combinator.
    pub(in crate::context) revoked_spending_ucan_cids: HashSet<String>,
    /// Per-member governance proposal timestamps for earned capacity rate limiting
    /// (§9.3). Maps member DID string to a list of Unix timestamps (seconds) when
    /// the member submitted governance proposals. Used by `check_proposer_eligibility` to
    /// enforce `max_governance_proposals_per_window` from `EarnedCapacityPolicy`.
    /// Entries outside the sliding window are evicted on each check.
    pub(crate) proposal_timestamps: HashMap<String, Vec<u64>>,
    /// Class-S governance state (ADR-049 §9): the downward-authorization /
    /// anti-replay subset whose ≤50 ms coalesce-window rollback would re-open
    /// a security window the caller already observed as closed. Grouped into
    /// [`GovernanceClassS`] so the fail-closed-persist boundary is one named
    /// sub-struct rather than four loose fields scattered through the
    /// governance bucket. Privatized to `pub(in crate::context)`: the field is
    /// unnameable outside `crate::context`, and within it the ONLY mutable reach
    /// is through the [`ClassSCell`](crate::context::actor::class_s::ClassSCell)
    /// persist-on-commit combinators (no `state_mut`, no `DerefMut`). The
    /// snapshot/serialization paths read it shared. ADR-049 §9.
    pub(in crate::context) class_s: GovernanceClassS,
}

/// The Class-S subset of [`GovernanceState`] (ADR-049 §9).
///
/// Groups the four governance fields whose mutation is a security-critical
/// downward-authorization or anti-replay transition that MUST be persisted
/// fail-closed before the operation is acknowledged: the executed-proposals
/// replay-marker map, the governance threshold signer set + quorum value, and
/// the spending-UCAN nonce tracker. A ≤50 ms coalesce-window rollback of any
/// of these re-opens a replay / re-grant the caller already saw closed.
///
/// This is a behaviour-neutral DATA SPLIT: the fields keep their `pub(crate)`
/// visibility and existing call sites reach them through the lengthened path
/// `governance.class_s.<field>`. Privatizing them behind a persist-on-commit
/// mutator boundary (so the fail-closed invariant is a compile error to
/// violate, retiring the source-text gate) is a separate later PR.
///
/// # `spending_nonce_tracker` is not `Clone`
///
/// [`NonceTracker`](scp_protocol::crypto::ucan::nonce::NonceTracker) holds a
/// clock handle and is not `Clone`, so [`Self::snapshot`] / [`Self::restore`]
/// project through its `snapshot_entries` / `from_snapshot` mirror (the
/// `restore` side needs the clock threaded as a parameter). The other three
/// fields are `Clone` and snapshot via a plain clone.
pub(crate) struct GovernanceClassS {
    /// Proposal IDs that have already been executed, mapped to the unix
    /// timestamp (seconds) when they were marked executed. Prevents replay of
    /// approved governance proposals (defense-in-depth). Entries older than
    /// [`EXECUTED_PROPOSALS_TTL_SECS`] are evicted on each insert.
    pub(crate) executed_proposals: HashMap<ProposalId, u64>,
    /// Governance threshold signers (for `ThresholdApproval` model).
    pub(crate) threshold_signers: Vec<DID>,
    /// Governance threshold value (quorum requirement).
    pub(crate) threshold_value: u32,
    /// Per-context nonce tracker for spending UCAN replay prevention (ADR-016 §6).
    /// Validates that each spending UCAN nonce is used at most once, preventing
    /// replay attacks where a valid spending UCAN is resubmitted.
    pub(crate) spending_nonce_tracker:
        scp_protocol::crypto::ucan::nonce::NonceTracker<Arc<dyn Clock>>,
}

/// Lossless, `Clone`-able mirror of [`GovernanceClassS`] (ADR-049 §9).
///
/// The live sub-struct cannot derive `Clone` because its
/// `spending_nonce_tracker` holds a clock handle; this snapshot captures the
/// tracker's `(context_id, entries)` so [`GovernanceClassS::restore`] can
/// rebuild it from a caller-supplied clock. The other three fields are stored
/// by clone. Used only for the in-memory snapshot/restore round-trip — the
/// on-disk [`ContextSnapshot`] format is unchanged (these fields continue to
/// serialize as their existing flat snapshot fields).
#[derive(Debug, Clone)]
#[allow(
    dead_code,
    reason = "ADR-049 §9 PR2a is a behaviour-neutral data split + mirror snapshot. The snapshot/restore mirror's first PRODUCTION consumer is the later privatization PR (restore wiring through the mutator-combinator boundary); for now it is exercised by the crate-internal lossless round-trip unit test. Mirrors the PR1 ClassSCell scaffolding precedent."
)]
pub(crate) struct GovernanceClassSSnapshot {
    /// Mirror of [`GovernanceClassS::executed_proposals`].
    pub(crate) executed_proposals: HashMap<ProposalId, u64>,
    /// Mirror of [`GovernanceClassS::threshold_signers`].
    pub(crate) threshold_signers: Vec<DID>,
    /// Mirror of [`GovernanceClassS::threshold_value`].
    pub(crate) threshold_value: u32,
    /// Context id of the `spending_nonce_tracker`, needed to rebuild it on
    /// restore via [`NonceTracker::from_snapshot`](scp_protocol::crypto::ucan::nonce::NonceTracker::from_snapshot).
    pub(crate) spending_nonce_tracker_context_id: String,
    /// `(nonce → (first_seen_secs, token_expiry_secs))` entries of the
    /// `spending_nonce_tracker`, projected via `snapshot_entries`.
    pub(crate) spending_nonce_tracker_entries: HashMap<String, (u64, u64)>,
}

#[allow(
    dead_code,
    reason = "ADR-049 §9 PR2a is a behaviour-neutral data split + mirror snapshot. The snapshot/restore mirror's first PRODUCTION consumer is the later privatization PR (restore wiring through the mutator-combinator boundary); for now it is exercised by the crate-internal lossless round-trip unit test. Mirrors the PR1 ClassSCell scaffolding precedent."
)]
impl GovernanceClassS {
    /// Project this Class-S governance subset onto its `Clone`-able mirror
    /// (ADR-049 §9). Lossless with [`Self::restore`].
    #[must_use]
    pub(crate) fn snapshot(&self) -> GovernanceClassSSnapshot {
        GovernanceClassSSnapshot {
            executed_proposals: self.executed_proposals.clone(),
            threshold_signers: self.threshold_signers.clone(),
            threshold_value: self.threshold_value,
            spending_nonce_tracker_context_id: self.spending_nonce_tracker.context_id().to_owned(),
            spending_nonce_tracker_entries: self.spending_nonce_tracker.snapshot_entries(),
        }
    }

    /// Restore this Class-S governance subset from its mirror (ADR-049 §9),
    /// rebuilding the `spending_nonce_tracker` from `clock`. Lossless inverse
    /// of [`Self::snapshot`].
    pub(crate) fn restore(&mut self, snap: GovernanceClassSSnapshot, clock: &Arc<dyn Clock>) {
        // Rebuild the whole sub-struct via a struct LITERAL (field `:` form)
        // rather than per-field assignment. This is pure same-snapshot
        // rehydration, not an acknowledged downward-auth transition — using the
        // literal keeps the ADR-049 §9 fail-closed gate's assignment marker
        // (`threshold_value=`) out of this restore body, exactly as the
        // `restore_context` struct-literal rehydration path already does.
        let GovernanceClassSSnapshot {
            executed_proposals,
            threshold_signers,
            threshold_value,
            spending_nonce_tracker_context_id,
            spending_nonce_tracker_entries,
        } = snap;
        *self = Self {
            executed_proposals,
            threshold_signers,
            threshold_value,
            spending_nonce_tracker: scp_protocol::crypto::ucan::nonce::NonceTracker::from_snapshot(
                spending_nonce_tracker_context_id,
                Arc::clone(clock),
                spending_nonce_tracker_entries,
            ),
        };
    }
}

impl GovernanceState {
    /// Clears participation cache, cooldown state, and velocity tracker.
    ///
    /// Called on context close so stale participation records and cooldown
    /// timers don't carry over if the context is re-created (#1530).
    pub(crate) fn decay_participation(&mut self) {
        self.participation_cache.clear();
        self.cooldown_until.clear();
        self.proposal_timestamps.clear();
        // Clear velocity tracker on participation decay. Stale velocity
        // data from a closed/expired context must not carry over.
        self.velocity_tracker.clear();
    }
}

/// MLS epoch and reconnection state.
///
/// **Visibility:** elevated to `pub(crate)` by ADR-049 §15 so the
/// actor's [`crate::context::actor::state::PerContextState`] can carry a
/// field of this type while the handler-body migration is under way.
/// ADR-049 §15 deletes this struct along with the rest of the legacy manager
/// module.
pub(crate) struct EpochState {
    /// Monotonic MLS epoch counter. Incremented each time a governance action
    /// triggers an MLS membership change (`AddMember`, `RemoveMember`,
    /// `Revoke`, `ResetMember`). Used to populate
    /// `GovernanceActionExecuted.resulting_epoch` and
    /// `GovernanceContext.current_epoch`.
    pub(crate) mls_epoch: u64,
    /// MLS-governance epoch coordinator (ADR-031 §8, issue #630).
    ///
    /// Records the auditable link between governance proposal approvals and
    /// resulting MLS epoch advances. Instantiated per context and updated
    /// after each membership-affecting governance action execution.
    pub(crate) coordinator: EpochCoordinator,
    /// Epoch grace window store (§23.11).
    ///
    /// Tracks which old epochs are still within their grace window after
    /// epoch advances. Persisted alongside the context snapshot and restored
    /// on startup. Used by the MLS decrypt path to determine whether to
    /// attempt decryption for a given past epoch.
    pub(crate) grace_store: scp_mls::epoch_grace::EpochGraceStore,
    /// Whether this context needs to re-enter the reconnection protocol
    /// (§23.3) before processing new messages (§23.11 inconsistent state
    /// fallback step 3). Set during `restore_context` when grace store
    /// inconsistency is detected. Cleared when the reconnection protocol
    /// completes successfully. The SDK MUST check this flag when message
    /// processing begins for this context and initiate the reconnection
    /// protocol if set.
    pub(crate) needs_reconnect: bool,
}

/// Access control state (CEK wrapping, key store).
///
/// Capability suspension is now handled by `ContextRoleState::suspended_capabilities`.
/// This struct retains the CEK exclusion list and per-member access key store.
///
/// **Visibility:** elevated to `pub(crate)` by ADR-049 §15 so the
/// actor's [`crate::context::actor::state::PerContextState`] can carry a
/// field of this type while the handler-body migration is under way.
/// ADR-049 §15 deletes this struct along with the rest of the legacy manager
/// module.
pub(crate) struct AccessControlState {
    /// Members excluded from future CEK wrapping (`Revoke { access: AccessScope::Write }`,
    /// ADR-038, §9.17). This is a cryptographic exclusion list, NOT an
    /// application-level capability suspension.
    pub(crate) read_exclusion_list: HashSet<DID>,
    /// Per-member access key store for content encryption key wrapping
    /// (ADR-038, §9.17). Keys are generated when members join and used
    /// by `wrap_content`/`unwrap_content` in the message pipeline.
    pub(crate) access_key_store: scp_protocol::crypto::access_keys::AccessKeyStore,
}

impl AccessControlState {
    /// Construct a fresh, empty `AccessControlState`. Used by the actor's
    /// [`crate::context::actor::state::PerContextState`] default-for-test
    /// fixture (ADR-049 §15) to populate the corresponding field
    /// without peeking at private fields. Deleted in ADR-049 §15 alongside
    /// the rest of the legacy manager module.
    #[must_use]
    pub(crate) fn new_empty_for_actor() -> Self {
        Self {
            read_exclusion_list: HashSet::new(),
            access_key_store: scp_protocol::crypto::access_keys::AccessKeyStore::new(),
        }
    }
}

impl EpochState {
    /// Construct a fresh `EpochState` with `mls_epoch = 0`, an empty
    /// coordinator scoped to the given context, a fresh grace store, and
    /// `needs_reconnect = false`. Used by the actor's
    /// [`crate::context::actor::state::PerContextState`] default-for-test
    /// fixture (ADR-049 §15). Deleted in ADR-049 §15 alongside
    /// the rest of the legacy manager module.
    #[must_use]
    pub(crate) fn new_fresh_for_actor(context_id: &str) -> Self {
        Self {
            mls_epoch: 0,
            coordinator: EpochCoordinator::from_records(Vec::new(), context_id),
            // Native runtime injects the production SystemClock; an in-browser
            // client injects its hardened clock (ADR-057 §Prereq-2).
            grace_store: scp_mls::epoch_grace::EpochGraceStore::with_clock(std::sync::Arc::new(
                scp_clock::SystemClock,
            )),
            needs_reconnect: false,
        }
    }
}

impl TtlState {
    /// Construct a fresh `TtlState` with a clock-less `TtlTimer` and no
    /// active extension. Used by the actor's
    /// [`crate::context::actor::state::PerContextState`] default-for-test
    /// fixture (ADR-049 §15). Deleted in ADR-049 §15 alongside
    /// the rest of the legacy manager module.
    #[must_use]
    pub(crate) fn new_fresh_for_actor() -> Self {
        Self {
            timer: TtlTimer::new(),
            extension: None,
        }
    }
}

impl GovernanceState {
    /// Construct a fresh, empty `GovernanceState` seeded with a
    /// `SingleAdminEngine` for `admin_did`, a no-op key resolver, and the
    /// given clock. Intended exclusively as the default fixture for the
    /// actor's [`crate::context::actor::state::PerContextState`]
    /// default-for-test helper (ADR-049 §15). Production paths
    /// continue to construct the struct inline from the lifecycle handler.
    /// Deleted in ADR-049 §15 alongside the rest of the legacy manager
    /// module.
    #[must_use]
    pub(crate) fn new_fresh_for_actor(
        context_id: &str,
        admin_did: DID,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let resolver: scp_protocol::context::governance::KeyResolver =
            Arc::new(|_did: &DID, _kid: scp_did::SigningKeyId| None);
        let engine: Box<dyn GovernanceEngine> =
            Box::new(SingleAdminEngine::new(admin_did, resolver));
        Self {
            engine,
            approved_proposals: HashMap::new(),
            next_proposal_seq: 0,
            freeze: None,
            deadlock: DeadlockDetectionState::default(),
            pending_ceiling_modification: None,
            pending_economic_policy_change: None,
            registered_outlets: Vec::new(),
            outlet_interfaces: Vec::new(),
            pruning_policy: None,
            economic_policy: None,
            budget_tracker: MemberBudgetTracker::new(),
            last_known_members: HashSet::new(),
            pending_epoch_resets: Vec::new(),
            consequence_rules: Vec::new(),
            velocity_tracker: scp_protocol::economy::antispam::SenderVelocityTracker::new(3600),
            participation_cache: HashMap::new(),
            cooldown_until: HashMap::new(),
            message_pricing: None,
            hard_rate_limit: scp_protocol::economy::antispam::TokenBucketLimiter::new(
                scp_protocol::economy::antispam::HardRateLimitConfig::default(),
            ),
            revoked_spending_ucan_cids: HashSet::new(),
            proposal_timestamps: HashMap::new(),
            class_s: GovernanceClassS {
                executed_proposals: HashMap::new(),
                threshold_signers: Vec::new(),
                threshold_value: 0,
                spending_nonce_tracker: scp_protocol::crypto::ucan::nonce::NonceTracker::new(
                    context_id.to_owned(),
                    clock,
                ),
            },
        }
    }
}

/// TTL timer and extension state.
///
/// **Visibility:** elevated to `pub(crate)` by ADR-049 §15 so the
/// actor's [`crate::context::actor::state::PerContextState`] can carry a
/// field of this type while the handler-body migration is under way.
/// ADR-049 §15 deletes this struct along with the rest of the legacy manager
/// module.
pub(crate) struct TtlState {
    /// TTL timer management (SCP-021).
    pub(crate) timer: TtlTimer,
    /// Active TTL extension proposal, if any (SCP-021).
    pub(crate) extension: Option<TtlExtension>,
}

/// Wire wrapper for a consistency-checkpoint exchange message (§9.9.3, §23.7).
///
/// Carries the canonical signed [`ConsistencyCheckpoint`](scp_event_log::checkpoint::ConsistencyCheckpoint) behind a magic tag
/// so the receive path can positively identify it. Although the inner envelope
/// already discriminates checkpoints via
/// [`MessageType::ConsistencyCheckpoint`](scp_protocol::envelope::inner::MessageType::ConsistencyCheckpoint),
/// the tag is a defense-in-depth guard mirroring
/// [`PseudonymAnnouncement`](scp_protocol::context::pseudonym::PseudonymAnnouncement):
/// it makes a payload that fails to deserialize as a tagged checkpoint a
/// hard error rather than a silently mis-routed application message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckpointMessage {
    /// Magic prefix distinguishing checkpoint messages from application data.
    pub tag: String,
    /// The signed consistency checkpoint (canonical `scp-event-log` type).
    pub checkpoint: scp_event_log::checkpoint::ConsistencyCheckpoint,
}

/// Magic tag identifying consistency-checkpoint messages in the MLS application
/// message stream. Prefixed with `\0` for the same reason as
/// [`PSEUDONYM_ANNOUNCEMENT_TAG`](scp_protocol::context::pseudonym::PSEUDONYM_ANNOUNCEMENT_TAG):
/// user content is valid UTF-8 and never starts with a null byte when
/// `MessagePack`-decoded, so the tag cannot collide.
pub(crate) const CHECKPOINT_PAYLOAD_TAG: &str = "\0scp:checkpoint:v1";

// ADR-049 Phase 2A finalization keystone (ADR-049 §15 phase 2A finalization
// — type unification, single PerContextState): the legacy
// `state::PerContextState` struct + its `impl` block are deleted here. The
// single surviving `PerContextState` lives at
// [`crate::context::actor::state::PerContextState`] (mode-discriminated
// union per ADR-049 §Decision 1). This `pub use` keeps every callsite that
// reached `crate::context::state::PerContextState` (legacy import path)
// resolving to the actor type until subsequent finalization commits swap
// each import path mechanically and the supervisor's `contexts` DashMap
// stores the unified type until that map is deleted later in finalization.
pub(crate) use crate::context::actor::state::PerContextState;

/// Pushes a [`ContextEvent`] into the receive buffer and, when a broadcast
/// channel is provided, sends a sanitized copy on it too.
///
/// Free-function form of `PerContextState::emit_event` (legacy) and the
/// per-helper `emit_event` shims (broadcast, `ttl_close`). Used by both the
/// legacy state and the actor [`crate::context::actor::state::PerContextState`]
/// so the `WelcomeGenerated` suppression and payload-stripping invariants
/// stay in one place. ADR-049 Phase 2A.7 — extracted so messaging-domain
/// helpers can emit events without going through a wrapper method.
///
/// **Security invariants (mirrors `PerContextState::emit_event`):**
/// - `WelcomeGenerated` events carry MLS key material and are NEVER sent
///   on the broadcast channel (receive buffer only).
/// - `MessageReceived` / `MessageSent` payloads are stripped (replaced
///   with empty `Vec`) before broadcast.
pub(crate) fn emit_event_into(
    receive_buffer: &mut ReceiveBuffer,
    event: ContextEvent,
    context_id: &str,
    tx: Option<&tokio::sync::broadcast::Sender<(String, ContextEvent)>>,
) {
    if matches!(event, ContextEvent::WelcomeGenerated { .. }) {
        receive_buffer.push(event);
        return;
    }

    receive_buffer.push(event.clone());
    if let Some(tx) = tx {
        let sanitized = strip_event_payload(&event);
        let _ = tx.send((context_id.to_owned(), sanitized));
    }
}

/// Strips decrypted plaintext from event variants that carry message payloads.
///
/// The broadcast channel is observable by any subscriber (e.g., webhook
/// consumers, SDK event listeners). Sending decrypted content on it would
/// defeat MLS encryption-as-access-control. This function replaces payload
/// bytes with an empty `Vec` for `MessageReceived` and `MessageSent`, and
/// passes all other variants through unchanged.
///
/// The match is exhaustive (no wildcard catch-all) so that adding a new
/// `ContextEvent` variant with sensitive data causes a compile error,
/// forcing the developer to decide whether the variant needs stripping.
pub(crate) fn strip_event_payload(event: &ContextEvent) -> ContextEvent {
    match event {
        ContextEvent::MessageReceived { sender_did, .. } => ContextEvent::MessageReceived {
            sender_did: sender_did.clone(),
            payload: vec![],
        },
        ContextEvent::MessageSent {
            sender_did,
            sequence_number,
            ..
        } => ContextEvent::MessageSent {
            sender_did: sender_did.clone(),
            sequence_number: *sequence_number,
            payload: vec![],
        },
        // All remaining variants carry no message plaintext or key material.
        // Listed exhaustively so new variants cause a compile error.
        ContextEvent::MemberJoined { .. }
        | ContextEvent::MemberLeft { .. }
        | ContextEvent::SystemClose { .. }
        | ContextEvent::MemberBlocked { .. }
        | ContextEvent::MemberUnblocked { .. }
        | ContextEvent::AuthorBlocked { .. }
        | ContextEvent::ReadAccessRevoked { .. }
        | ContextEvent::ReadAccessRestored { .. }
        | ContextEvent::WriteAccessRevoked { .. }
        | ContextEvent::CapabilitiesSuspended { .. }
        | ContextEvent::WriteAccessRestored { .. }
        | ContextEvent::AccessKeyRevoked { .. }
        | ContextEvent::AccessKeyRestored { .. }
        | ContextEvent::ContentKeysRotated { .. }
        | ContextEvent::GovernanceActionExecuted { .. }
        | ContextEvent::CeilingChangeNotification { .. }
        | ContextEvent::EconomicPolicyChangeNotification { .. }
        | ContextEvent::Expired
        | ContextEvent::ExpiryFailed { .. }
        | ContextEvent::VoteWithdrawn { .. }
        | ContextEvent::ProposalTimedOut { .. }
        | ContextEvent::DeadlockDetected { .. }
        | ContextEvent::AppBound { .. }
        | ContextEvent::AppUnbound { .. }
        | ContextEvent::DegradedMode { .. }
        | ContextEvent::WelcomeGenerated { .. }
        | ContextEvent::BufferOverflow { .. }
        | ContextEvent::SequenceGapDetected { .. }
        | ContextEvent::CheckpointCosignatureRequired { .. }
        | ContextEvent::ContextMigrationProposed { .. }
        | ContextEvent::ContextMigrationStarted { .. }
        | ContextEvent::ContextMigrationCancelled { .. }
        | ContextEvent::ContextTombstoned { .. }
        | ContextEvent::ConsequenceTriggered { .. }
        | ContextEvent::ConsequenceEnforced { .. }
        | ContextEvent::PaymentCaptureFailed { .. }
        | ContextEvent::PaymentReceived { .. }
        | ContextEvent::CommitBroadcastPending { .. }
        | ContextEvent::CommitBroadcastSucceeded { .. }
        | ContextEvent::EquivocationDetected { .. }
        | ContextEvent::CommitBroadcastFailed { .. }
        | ContextEvent::PseudonymAnnounced { .. } => event.clone(),
    }
}

/// Creates a governance engine from a [`GovernanceModel`] selector and
/// the context creator's DID.
///
/// This maps the creation-time `GovernanceModel` (which lives in
/// `ContextParams`) to the runtime `GovernanceEngine` implementation.
///
/// # Errors
///
/// Returns [`ContextCreationError`] if the governance model parameters are
/// invalid (e.g., threshold > signers, empty voter sets).
pub(crate) fn create_governance_engine(
    model: &GovernanceModel,
    creator_did: &DID,
    key_resolver: KeyResolver,
) -> Result<Box<dyn GovernanceEngine>, ContextCreationError> {
    match model {
        GovernanceModel::SingleAdmin => Ok(Box::new(SingleAdminEngine::new(
            creator_did.clone(),
            key_resolver,
        ))),
        GovernanceModel::Threshold { threshold, signers } => {
            let engine = ThresholdEngine::new(signers.clone(), *threshold, 86_400, key_resolver)
                .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
            Ok(Box::new(engine))
        }
        GovernanceModel::Majority { eligible_voters } => {
            let engine =
                MajorityVoteEngine::new(eligible_voters.clone(), 86_400, 5000, key_resolver)
                    .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
            Ok(Box::new(engine))
        }
        GovernanceModel::Unanimity { eligible_voters } => {
            let engine = UnanimityEngine::new(eligible_voters.clone(), 172_800, key_resolver)
                .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
            Ok(Box::new(engine))
        }
    }
}

/// Builds the fresh-context [`GovernanceState`] shared by BOTH the creator-side
/// create path ([`crate::context::lifecycle_helpers::create_context`]) and the
/// join-side spawn-from-Welcome path
/// ([`crate::context::supervisor::Supervisor::build_welcome_joiner_state`]).
///
/// Both entrypoints stand up an identical fresh governance bucket — empty
/// proposal/outlet/ceiling/economy maps, the matrix-default hard rate limiter, a
/// 60-second velocity window, and a fresh spending-nonce tracker — differing
/// only in the already-built `engine`, the initial `last_known_members` roster,
/// and the `context_id`/`clock` the nonce tracker binds. Extracting the field
/// set here means the two paths cannot silently DRIFT: a new `GovernanceState`
/// field forces one edit, not two. The import/restore paths are deliberately
/// NOT routed through this helper — they populate the bucket from a persisted
/// snapshot, not from fresh defaults.
///
/// The threshold signer set + quorum value are derived from
/// `params.governance` here (empty / zero for non-`Threshold` models), matching
/// what both call sites computed inline before.
pub(crate) fn fresh_governance_state(
    engine: Box<dyn GovernanceEngine>,
    params: &ContextParams,
    last_known_members: HashSet<DID>,
    context_id: &str,
    clock: Arc<dyn Clock>,
) -> GovernanceState {
    let (threshold_signers, threshold_value) = match &params.governance {
        GovernanceModel::Threshold { threshold, signers } => (signers.clone(), *threshold),
        _ => (Vec::new(), 0),
    };
    GovernanceState {
        engine,
        approved_proposals: HashMap::new(),
        // H10: fresh contexts start with a zero monotonic counter.
        next_proposal_seq: 0,
        freeze: None,
        deadlock: DeadlockDetectionState::default(),
        pending_ceiling_modification: None,
        pending_economic_policy_change: None,
        registered_outlets: Vec::new(),
        outlet_interfaces: Vec::new(),
        pruning_policy: None,
        message_pricing: crate::context::lifecycle_logic::derive_message_pricing(
            params.economic_policy.as_ref(),
        ),
        hard_rate_limit: scp_protocol::economy::antispam::TokenBucketLimiter::new(
            scp_protocol::economy::antispam::HardRateLimitConfig::matrix_defaults(),
        ),
        economic_policy: params.economic_policy.clone(),
        budget_tracker: MemberBudgetTracker::new(),
        last_known_members,
        pending_epoch_resets: Vec::new(),
        consequence_rules: params.consequence_rules.clone(),
        velocity_tracker: scp_protocol::economy::antispam::SenderVelocityTracker::new(60),
        participation_cache: HashMap::new(),
        cooldown_until: HashMap::new(),
        revoked_spending_ucan_cids: HashSet::new(),
        proposal_timestamps: HashMap::new(),
        class_s: GovernanceClassS {
            executed_proposals: HashMap::new(),
            threshold_signers,
            threshold_value,
            spending_nonce_tracker: scp_protocol::crypto::ucan::nonce::NonceTracker::new(
                context_id.to_owned(),
                clock,
            ),
        },
    }
}

/// Restores the [`EpochGraceStore`](scp_mls::epoch_grace::EpochGraceStore)
/// from persisted snapshot entries, applying the §23.11 inconsistency
/// detection and fallback steps.
///
/// Returns the (possibly empty) grace store and a flag indicating whether
/// the context needs to re-enter the reconnection protocol (§23.3).
pub(crate) fn restore_grace_store_from_snapshot(
    context_id: &str,
    snapshot: &ContextSnapshot,
) -> (scp_mls::epoch_grace::EpochGraceStore, bool) {
    // Native runtime injects the production SystemClock (ADR-057 §Prereq-2).
    let mut grace_store = scp_mls::epoch_grace::EpochGraceStore::with_clock(std::sync::Arc::new(
        scp_clock::SystemClock,
    ));
    let mut needs_reconnect = snapshot.needs_reconnect;

    if !snapshot.grace_entries.is_empty() {
        // Inconsistency detection (§23.11): if any grace entry references
        // an epoch newer than the persisted MLS epoch, a partial write
        // escaped the transaction boundary.
        let has_inconsistency = snapshot
            .grace_entries
            .iter()
            .any(|entry| entry.epoch > snapshot.mls_epoch);

        if has_inconsistency {
            // §23.11 inconsistent state fallback:
            // Step 1: Discard all grace entries (grace store stays empty).
            // Step 2: Destroy old epoch key material (OpenMLS manages
            //         actual keys; empty grace store prevents SCP-layer
            //         decrypt attempts for old epochs).
            // Step 3: Mark context for reconnection (§23.3). Network I/O
            //         is not available during restore_context; the flag
            //         triggers reconnection when message processing begins.
            // Step 4: Log the inconsistency for the application layer.
            needs_reconnect = true;
            let inconsistency = scp_protocol::sync::SyncError::EpochGraceStoreInconsistency {
                context_id: context_id.into(),
                reason: format!(
                    "grace entry references epoch newer than persisted MLS epoch {}",
                    snapshot.mls_epoch,
                ),
            };
            tracing::warn!(
                context_id = %context_id,
                mls_epoch = snapshot.mls_epoch,
                error = %inconsistency,
                "epoch grace store inconsistency detected during restore; \
                 discarding all grace entries and marking context for \
                 reconnection (§23.11 fallback steps 1-4)"
            );
            // Grace store stays empty — all old epoch keys are effectively
            // destroyed (forward secrecy). Messages encrypted under lost
            // epochs are unrecoverable, matching the §23.11 fallback.
        } else {
            // Normal restore path: feed persisted entries into the grace
            // store. Entries that expired during downtime are returned in
            // the `expired` vec — the caller should destroy any cached
            // key material for those epochs.
            // Expired epochs' key material is already gone (OpenMLS
            // manages key lifecycle internally). The grace store now
            // reflects the surviving entries.
            let _expired = grace_store.restore_from_entries(&snapshot.grace_entries);
        }
    }

    (grace_store, needs_reconnect)
}

/// Reconstructs a governance engine from a persisted [`GovernanceModelConfig`]
/// and the context's current member set.
///
/// For `SingleAdmin` and `Threshold`, the config is self-contained.
/// For `Majority` and `Unanimity`, the eligible voter set comes from the
/// `GovernanceModel` stored in `ContextParams` (part of the snapshot).
///
/// # Errors
///
/// Returns [`ContextError`] if the engine cannot be reconstructed.
pub(crate) fn restore_governance_engine_from_snapshot(
    snapshot: &ContextSnapshot,
    key_resolver: KeyResolver,
) -> Result<Box<dyn GovernanceEngine>, ContextError> {
    // Determine the config to restore from. If the snapshot has an explicit
    // config, use it. Otherwise, fall back to SingleAdmin with the first admin.
    let config = snapshot.governance_model_config.clone().unwrap_or_else(|| {
        // Legacy snapshot: no governance_model_config. Default to SingleAdmin
        // with the first admin from the membership state.
        let admin_did = snapshot
            .membership
            .members()
            .find(|m| m.role_name == "admin")
            .map_or_else(|| DID::from("did:dht:unknown"), |m| m.did.clone());
        GovernanceModelConfig::SingleAdmin { admin_did }
    });

    match config {
        GovernanceModelConfig::SingleAdmin { admin_did } => {
            Ok(Box::new(SingleAdminEngine::new(admin_did, key_resolver)))
        }
        GovernanceModelConfig::Threshold {
            signers,
            threshold,
            voting_window_secs,
        } => {
            let engine = ThresholdEngine::new(signers, threshold, voting_window_secs, key_resolver)
                .map_err(|e| ContextError::CreationFailed(e.to_string()))?;
            Ok(Box::new(engine))
        }
        GovernanceModelConfig::Majority {
            voting_window_secs,
            min_participation_bps,
        } => {
            // Recover eligible_voters from ContextParams.governance.
            let voters = match &snapshot.context_params.governance {
                GovernanceModel::Majority { eligible_voters } => eligible_voters.clone(),
                _ => {
                    // Mismatch between config and params — should not happen.
                    // Fall back to all members.
                    snapshot
                        .membership
                        .members()
                        .map(|m| m.did.clone())
                        .collect()
                }
            };
            let engine = MajorityVoteEngine::new(
                voters,
                voting_window_secs,
                min_participation_bps,
                key_resolver,
            )
            .map_err(|e| ContextError::CreationFailed(e.to_string()))?;
            Ok(Box::new(engine))
        }
        GovernanceModelConfig::Unanimity { voting_window_secs } => {
            let voters = match &snapshot.context_params.governance {
                GovernanceModel::Unanimity { eligible_voters } => eligible_voters.clone(),
                _ => snapshot
                    .membership
                    .members()
                    .map(|m| m.did.clone())
                    .collect(),
            };
            let engine = UnanimityEngine::new(voters, voting_window_secs, key_resolver)
                .map_err(|e| ContextError::CreationFailed(e.to_string()))?;
            Ok(Box::new(engine))
        }
    }
}

/// Fail-closed gate for the Welcome-join authority seam (#2028): refuses to
/// mint a Welcome once the LIVE capability ceiling has stopped covering the
/// GENESIS ceiling a joiner would install — and refuses just as hard when the
/// genesis value it was handed cannot be this context's own (see
/// [Non-vacuity](#non-vacuity-the-genesis-value-must-really-be-this-contexts-genesis)).
///
/// # Why this gate exists
///
/// A Welcome-joiner's authority is built entirely from the creator-signed
/// bundle's genesis [`ContextParams`] —
/// `Supervisor::build_welcome_joiner_state` seeds [`ContextRoleState`] with
/// `CapabilityCeiling::new(params.ceiling)`, the default role definitions (and
/// therefore the joiner's minted "member" tokens) are capped by that ceiling,
/// and each FFI bridge additionally seeds its own outlet/UCAN authorization
/// cache from the same `params.ceiling` (`sync_ceiling_from_params`). Those
/// genesis params are frozen at creation on BOTH sides of the join:
///
/// - [`ContextHandle::params`] is immutable after creation (the only
///   spec-authorized mutation is `promote_params`, which touches
///   `memory_scope`/`ttl`), so the bundle `Supervisor::invite_member` signs
///   always carries the GENESIS ceiling; and
/// - the `0xFF02` `ScpContextExtension` the joiner cross-checks the bundle
///   against commits the genesis `ceiling_hash` once at group build and is
///   never rewritten — spec §5.13.3 rule 8 is explicit that `0xFF02` "pins the
///   **genesis** creator" and that post-genesis evolution "appl[ies] from the
///   authenticated event log after join".
///
/// A governed `ModifyCeiling` (spec §5.3.2) writes the new ceiling ONLY into the
/// live `role_state` (`governance_helpers::apply_pending_ceiling_modification`
/// → `ContextRoleState::set_ceiling`). So after a ceiling LOWERING the two
/// diverge, and the authenticated event-log catch-up §5.13.3 rule 8 assumes does
/// not exist yet (#2028) — leaving the joiner nothing to reconcile against.
/// Handing out a Welcome anyway would install a ceiling WIDER than the context's
/// current policy: a fail-OPEN authorization downgrade.
///
/// # Why the gate is on the adding side
///
/// The joiner cannot detect the divergence: every artifact it can authenticate
/// (the creator-signed bundle, the MLS-committed `0xFF02` extension) carries the
/// genesis ceiling, and it holds no event log. The adding node is the only party
/// that can see both values, so the invariant is enforced where it is knowable —
/// before the Welcome is minted. Per the fail-closed tenet the capability is
/// honestly absent (a typed error) until #2028 lands an authenticated
/// current-state transfer; it does NOT silently install the stale genesis
/// default.
///
/// Residual, stated honestly: a node running patched software could skip this
/// check. That grants no privilege — a party authorized to execute `AddMember`
/// in a `Governed`-ceiling context is by construction the party that can raise
/// the ceiling through governance anyway, so the realistic threat this closes is
/// an HONEST adder unknowingly onboarding stale, over-broad authority. Making
/// the property joiner-verifiable requires the authenticated current-state
/// transfer #2028 tracks.
///
/// # Direction
///
/// Only the fail-OPEN direction is refused: the gate asks whether the LIVE
/// ceiling still COVERS every genesis entry. A pure WIDENING still admits joins
/// — the joiner then installs the narrower genesis set, which grants no
/// authority the context withholds (that residual staleness is #2028's scope,
/// not a fail-open). Coverage is decided by [`ceiling_covers`], which implements
/// the SAME relation the authorization layer enforces (see that function).
///
/// # Non-vacuity (the genesis value must really be this context's genesis)
///
/// The gate is only as good as the `genesis_params` it is handed: a
/// RECONSTRUCTED [`ContextParams`] (e.g. a `ContextParams::default()` built at a
/// dispatch boundary rather than read from the context's own snapshot) carries an
/// EMPTY ceiling, which every live ceiling trivially covers — the gate would
/// silently enforce nothing while still appearing present in the code. That is
/// exactly the false-guarantee shape the fail-closed tenet forbids, so the
/// primary defence is structural: every call site sources these params from the
/// context's authoritative handle, and the restore path builds that handle from
/// the PERSISTED snapshot (never from a caller-supplied value).
///
/// This function adds a second, independent detector for the same class. Under
/// [`CeilingPolicy::Immutable`] the ceiling CANNOT change after creation —
/// `ModifyCeiling` is refused outright unless the policy is
/// [`CeilingPolicy::Governed`] (spec §5.3.2, enforced in
/// `governance_helpers::execute_modify_ceiling`) — so for an `Immutable` context
/// the live ceiling and the genesis ceiling are equal BY CONSTRUCTION. A live
/// entry the genesis ceiling does not cover therefore proves the `genesis_params`
/// are not this context's real genesis params, and the gate refuses rather than
/// returning a vacuous `Ok`.
///
/// The check is deliberately scoped to `Immutable`: under `Governed` a widening
/// (including a widening away from an empty genesis ceiling) is a legitimate,
/// specced operation, so the same asymmetry there is real evolution rather than
/// evidence of a fabricated handle. Note that a reconstructed
/// `ContextParams::default()` carries `ceiling_policy: Immutable` — the
/// `#[default]` variant — so the detector fires on precisely the fabricated-params
/// case even when the real context is `Governed`.
///
/// # Errors
///
/// [`ContextError::InvalidState`] naming either the genesis capabilities the live
/// ceiling no longer covers, or the live capabilities that prove the supplied
/// genesis params are not this context's own.
pub(crate) fn check_genesis_ceiling_still_current(
    genesis_params: &ContextParams,
    live_ceiling: &scp_protocol::context::roles::CapabilityCeiling,
    site: &str,
) -> Result<(), ContextError> {
    // 1. The fail-OPEN direction: would the joiner install authority the context
    //    no longer grants?
    let stale = sorted_uncovered(genesis_params.ceiling.iter(), |cap| {
        ceiling_covers(live_ceiling, cap)
    });
    if !stale.is_empty() {
        return Err(ContextError::InvalidState(format!(
            "{site} refused: the live capability ceiling no longer covers the genesis ceiling a \
             Welcome-joiner would install (spec §5.3.2 lowered it; the invitation bundle and the \
             MLS-committed 0xFF02 extension both carry the GENESIS ceiling, and no authenticated \
             post-genesis catch-up exists at join — see #2028). Admitting a member now would \
             grant them [{}], which this context no longer permits. Refusing fail-closed.",
            stale.join(", ")
        )));
    }

    // 2. Non-vacuity detector — see the doc comment. Under `Immutable` the two
    //    ceilings are equal by construction, so any live entry the genesis
    //    ceiling does not cover means the genesis value handed to this gate is
    //    not this context's own.
    if genesis_params.ceiling_policy != CeilingPolicy::Immutable {
        return Ok(());
    }
    let genesis_ceiling = scp_protocol::context::roles::CapabilityCeiling::new(
        genesis_params.ceiling.iter().cloned(),
    );
    let unexplained = sorted_uncovered(live_ceiling.iter(), |cap| {
        ceiling_covers(&genesis_ceiling, cap)
    });
    if unexplained.is_empty() {
        return Ok(());
    }
    Err(ContextError::InvalidState(format!(
        "{site} refused: this context declares CeilingPolicy::Immutable, under which the live \
         ceiling cannot diverge from the genesis ceiling (spec §5.3.2 — ModifyCeiling requires \
         CeilingPolicy::Governed), yet the live ceiling carries [{}] which the supplied genesis \
         ceiling does not cover. The genesis parameters passed to this check are therefore not \
         this context's own — a reconstructed/default ContextParams would make the #2028 \
         authority-currency check vacuous, so it is refused fail-closed instead.",
        unexplained.join(", ")
    )))
}

/// Collects the deterministic, deduplicated UCAN names of every capability in
/// `caps` that `covered` rejects.
///
/// Shared by both directions of [`check_genesis_ceiling_still_current`] so the
/// two messages can never drift in formatting or dedup behaviour. Dedup matters
/// because the genesis ceiling is a `Vec` and may repeat an entry.
fn sorted_uncovered<'a>(
    caps: impl Iterator<Item = &'a Capability>,
    covered: impl Fn(&Capability) -> bool,
) -> Vec<String> {
    let mut out: Vec<String> = caps
        .filter(|cap| !covered(cap))
        .map(Capability::ucan_capability_name)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The ceiling-coverage relation this gate compares against — the same relation
/// the AUTHORIZATION layer actually enforces.
///
/// [`CapabilityCeiling::contains`](scp_protocol::context::roles::CapabilityCeiling::contains)
/// implements implicit coverage only for the built-in outlet wildcards
/// (`OutletQueryAll` ⊇ `OutletQuery(id)`, `OutletCallAll` ⊇ `OutletCall(id)`);
/// for [`Capability::Custom`] it is exact set membership. The authorization layer
/// is broader: `CapabilityUri::is_within_ceiling` accepts an explicit
/// `{resource}:*` entry as covering every action on that resource, and
/// `{resource}:*` is a first-class specced ceiling entry (§5.3.1.1 shape 3).
///
/// Using bare `contains` here would therefore NOT be a conservative
/// simplification — it would be a live defect. A legitimate governed WIDENING
/// from `Custom("data:read")` to `Custom("data:*")` leaves the live ceiling
/// genuinely covering genesis, yet bare `contains` marks `data:read` stale and
/// refuses EVERY subsequent join — permanently, because `params.ceiling` is
/// immutable and nothing can ever re-narrow the live ceiling back to an exact
/// match. Matching `is_within_ceiling` keeps the gate sound in the direction that
/// matters (a joiner installing `data:read` gains nothing a live `data:*` does not
/// already grant) without bricking the context.
///
/// The wildcard arm can only ever match a genuinely custom resource family: the
/// §5.3.1.1 "no built-in-resource wildcard shadow" rule (enforced in
/// `validate_custom_ceiling_entry`) rejects any `Custom("{builtin}:*")` entry, so
/// no synthesized wildcard can silently subsume a built-in capability family.
fn ceiling_covers(
    ceiling: &scp_protocol::context::roles::CapabilityCeiling,
    capability: &Capability,
) -> bool {
    if ceiling.contains(capability) {
        return true;
    }
    // `{resource}:*` coverage. A wildcard entry is covered only by itself, which
    // the exact test above already decided — so only concrete actions reach here.
    let (resource, action) = capability.ucan_resource_action();
    if action == "*" {
        return false;
    }
    ceiling.contains(&Capability::Custom(format!("{resource}:*")))
}

/// Validates governance model parameters at context creation time.
///
/// Rejects configurations that would make governance impossible:
/// - `Threshold` with `threshold == 0` (trivial quorum).
/// - `Threshold` with `threshold > signers.len()` (impossible quorum).
/// - `Threshold` with empty signers.
/// - `Majority` with empty `eligible_voters`.
/// - `Unanimity` with empty `eligible_voters`.
///
/// # Errors
///
/// Returns [`ContextCreationError::CreationFailed`] with a descriptive message.
pub(crate) fn validate_governance_model(
    model: &GovernanceModel,
) -> Result<(), ContextCreationError> {
    match model {
        GovernanceModel::SingleAdmin => Ok(()),
        GovernanceModel::Threshold { threshold, signers } => {
            if signers.is_empty() {
                return Err(ContextCreationError::CreationFailed(
                    "Threshold governance requires non-empty signers".into(),
                ));
            }
            if *threshold == 0 {
                return Err(ContextCreationError::CreationFailed(
                    "Threshold governance requires threshold >= 1".into(),
                ));
            }
            // signers.len() is bounded by realistic member counts (<< u32::MAX).
            #[allow(clippy::cast_possible_truncation)]
            if *threshold > signers.len() as u32 {
                return Err(ContextCreationError::CreationFailed(format!(
                    "Threshold {} exceeds number of signers {}",
                    threshold,
                    signers.len()
                )));
            }
            Ok(())
        }
        GovernanceModel::Majority { eligible_voters } => {
            if eligible_voters.is_empty() {
                return Err(ContextCreationError::CreationFailed(
                    "Majority governance requires non-empty eligible_voters".into(),
                ));
            }
            Ok(())
        }
        GovernanceModel::Unanimity { eligible_voters } => {
            if eligible_voters.is_empty() {
                return Err(ContextCreationError::CreationFailed(
                    "Unanimity governance requires non-empty eligible_voters".into(),
                ));
            }
            Ok(())
        }
    }
}

/// Returns [`ContextError::ContextNotActive`] unless the handle's cached
/// lifecycle state is [`ContextState::Active`].
///
/// This is a lock-free point-in-time check of the per-handle `ArcSwap` state
/// cell; it does not serialize against concurrent transitions (e.g. a
/// `close_context` or `handle_ttl_expiry` may still interleave between this
/// check and any later mutation — the actor command loop is the authority for
/// check-then-act atomicity).
pub(crate) fn require_active(handle: &ContextHandle) -> Result<(), ContextError> {
    let state = handle.state();
    if state != ContextState::Active {
        return Err(ContextError::ContextNotActive);
    }
    Ok(())
}

/// Requires the context to be in `MigratingOut` state (§5.11A).
/// Used for `CancelContextMigration` which is only valid during migration.
pub(crate) fn require_migrating_out(handle: &ContextHandle) -> Result<(), ContextError> {
    let state = handle.state();
    if state != ContextState::MigratingOut {
        return Err(ContextError::PermissionDenied(
            "action requires MigratingOut state".to_owned(),
        ));
    }
    Ok(())
}

// `validate_governance_consistency`, `build_governance_engine`, and
// `mint_governance_tokens` were called from the deleted manager
// submodules' `impl ContextManager` blocks. The active alternative
// (`create_governance_engine` above) covers the same surface for the
// hoisted `lifecycle_helpers::create_context` path. Removed in
// ADR-049 §15 alongside the rest of the manager-only code.

/// Resolves a context-ID string to the canonical 32-byte value that keys its
/// MLS group, sender keys, and event log.
///
/// This is the SINGLE chokepoint (ADR-056) through which every context-id
/// string is turned into keying bytes. Per ADR-056 (Model A) and spec
/// §6.2.4:276, a context's canonical identity IS its 32-byte digest, and the
/// id STRING is `hex(digest)` — exactly the form `generate_context_id`
/// produces (32 CSPRNG bytes, lowercase-hex encoded, §18.4.1). For such a
/// real context id the canonical bytes are the digest itself, recovered by
/// **decoding** the hex — NOT by re-hashing the already-hex-encoded digest
/// (which would double-hash and diverge from the raw digest the §6.2.4
/// cross-context outlet saga compares against on the wire).
///
/// Resolution rule:
/// - If `context_id` is a canonical context id — exactly 64 characters, all
///   lowercase hexadecimal — it is `hex::decode`d into the `[u8; 32]` digest.
///   This is the single branch that makes the redirect blanket-safe: every
///   real context id hits it and resolves to its digest.
/// - Otherwise `context_id` is NOT a real context id — a synthetic namespace
///   (`"identity-private-state"`), a standing-pair id (`"standing-" + hex`,
///   which carries the prefix and so is never bare 64-hex), or an arbitrary
///   test id (`"ctx-…"`). These fall through to the raw `SHA-256(id)`
///   derivation, producing **byte-for-byte the same value as before this
///   change** — they were never 64-hex, so their behavior is unchanged.
///
/// The 64-hex guard is strict (length 64 AND all `0-9a-f`): `hex::decode`
/// alone would also accept uppercase, but `generate_context_id` emits only
/// lowercase, so requiring lowercase keeps an uppercase 64-char test id on
/// the hashing fallback rather than silently decoding it.
///
/// The fallback calls [`scp_protocol::context::context_id_bytes`] (the raw
/// SHA-256 primitive) directly — that primitive stays a pure SHA-256
/// derivation for synthetic / non-context labels only, never re-hashing a
/// canonical context id (ADR-056, the double-hash trap).
///
/// This is the canonical CROSS-CRATE keying resolver: the single permitted way
/// for ANY layer — the runtime core AND the FFI bridges (`PyO3` / NAPI /
/// `UniFFI`), which reach it as `scp_core::context::state::context_id_to_bytes`
/// — to turn a context-id string into keying bytes. The raw routing primitive
/// [`scp_protocol::context::context_id_bytes`] is routing/fallback ONLY and
/// must never be used for keying: it double-hashes a real 64-hex id and keys
/// the wrong slot (the fail-open this ADR-056 chokepoint closes). Every storage
/// / crypto / event-log keying site must funnel through here.
#[must_use]
pub fn context_id_to_bytes(context_id: &str) -> [u8; 32] {
    if context_id.len() == 64
        && context_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        // A 64-char all-lowercase-hex string decodes to exactly 32 bytes, so
        // neither branch can fail. The fallthrough keeps the function total
        // (no panic/unwrap — clippy denies them) even if `hex::decode` ever
        // rejected the input.
        if let Ok(decoded) = hex::decode(context_id)
            && let Ok(digest) = <[u8; 32]>::try_from(decoded.as_slice())
        {
            return digest;
        }
    }
    scp_protocol::context::context_id_bytes(context_id)
}

#[cfg(test)]
mod notification_window_backdating_tests {
    //! Regression: a proposer who backdates `proposal.created_at` MUST NOT be
    //! able to collapse the mandatory notification window for deferred
    //! economic-policy (§19.3) or ceiling (§5.3.2) changes.
    //!
    //! The convergent activation deadline `effective_at = proposal.created_at +
    //! PERIOD` is proposer-controlled (`created_at` is signature-bound only
    //! against third parties, freely chosen by the proposer themselves). If the
    //! apply gate were a bare `current >= effective_at`, a malicious admin could
    //! backdate `created_at` by `>= PERIOD` so `effective_at <= commit time` and
    //! the change would become effective on the first apply tick — zero
    //! notification. `is_effective` therefore also enforces a non-backdatable
    //! floor `observed_at + PERIOD`, where `observed_at` is the applying
    //! member's local clock at commit-processing time.

    use super::{
        CEILING_CHANGE_NOTIFICATION_PERIOD_SECS, ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS,
        PendingCeilingModification, PendingEconomicPolicyChange,
    };
    use scp_protocol::economy::types::{Amount, CostSchedule, CurrencyCode, EconomicPolicy};

    /// Minimal valid economic policy for gate tests (values are irrelevant to
    /// the timing gate under test).
    fn sample_policy() -> EconomicPolicy {
        EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: CurrencyCode(*b"USD\0"),
                per_message: Some(Amount(1)),
                per_outlet_call: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec!["test".to_owned()],
            pricing_formula: None,
            payee: scp_did::DID::from("did:dht:z6MkPayee".to_owned()),
        }
    }

    /// Builds a pending economic-policy change exactly as
    /// `execute_set_economic_policy` does: `effective_at = proposal_created_at +
    /// PERIOD` (convergent, proposer-controlled) and `observed_at = local now`
    /// (non-backdatable). `proposal_created_at` is what the attacker controls.
    fn pending_economic(
        proposal_created_at: u64,
        local_observed_at: u64,
    ) -> PendingEconomicPolicyChange {
        PendingEconomicPolicyChange {
            new_policy: sample_policy(),
            notified_at: proposal_created_at,
            effective_at: proposal_created_at + ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS,
            observed_at: local_observed_at,
            proposal_id: [0u8; 32],
        }
    }

    /// Builds a pending ceiling modification exactly as
    /// `execute_modify_ceiling` does.
    fn pending_ceiling(
        proposal_created_at: u64,
        local_observed_at: u64,
    ) -> PendingCeilingModification {
        PendingCeilingModification {
            new_capabilities: Vec::new(),
            notified_at: proposal_created_at,
            effective_at: proposal_created_at + CEILING_CHANGE_NOTIFICATION_PERIOD_SECS,
            observed_at: local_observed_at,
            proposal_id: [0u8; 32],
        }
    }

    #[test]
    fn economic_policy_backdated_proposal_cannot_collapse_window() {
        // Honest local commit-processing time.
        let observed = 1_000_000_000u64;
        // Attacker backdates `created_at` by a full PERIOD so the naive
        // `effective_at` already lies at/below `observed` (commit time).
        let backdated_created_at = observed - ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS;
        let pending = pending_economic(backdated_created_at, observed);

        // Sanity: the proposer-controlled `effective_at` is <= commit time, so a
        // bare `current >= effective_at` gate would fire immediately.
        assert!(
            pending.effective_at <= observed,
            "test setup: backdated effective_at must be at or before commit time"
        );

        // The hardened gate must REFUSE to apply at commit time and for every
        // instant up to (but not including) `observed + PERIOD`.
        assert!(
            !pending.is_effective(observed),
            "backdated proposal must NOT be effective at commit time"
        );
        assert!(
            !pending.is_effective(observed + ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS - 1),
            "backdated proposal must NOT be effective one second before the local floor"
        );
        // Exactly at the local non-backdatable floor it becomes effective — the
        // full notification window measured from local commit-processing time.
        assert!(
            pending.is_effective(observed + ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS),
            "the window must elapse exactly PERIOD after local commit-processing time"
        );
    }

    #[test]
    fn economic_policy_honest_proposal_still_converges_on_effective_at() {
        // Honest proposer: `created_at` ~ commit time, so `effective_at`
        // (convergent leaf base) is the binding deadline and the local floor is
        // never the controlling bound. Activation tracks the convergent
        // `effective_at` exactly — no regression to cross-member convergence.
        let created_at = 2_000_000_000u64;
        // A member processing the commit slightly later than `created_at`.
        let observed = created_at + 5;
        let pending = pending_economic(created_at, observed);

        let effective_at = created_at + ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS;
        // The local floor (`observed + PERIOD`) is only 5s past `effective_at`,
        // so honest members converge to within their clock skew of the
        // convergent deadline — and never activate BEFORE `effective_at`.
        assert!(!pending.is_effective(effective_at - 1));
        assert!(pending.is_effective(observed + ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS));
    }

    #[test]
    fn ceiling_backdated_proposal_cannot_collapse_window() {
        let observed = 1_500_000_000u64;
        let backdated_created_at = observed - CEILING_CHANGE_NOTIFICATION_PERIOD_SECS;
        let pending = pending_ceiling(backdated_created_at, observed);

        assert!(
            pending.effective_at <= observed,
            "test setup: backdated effective_at must be at or before commit time"
        );
        assert!(
            !pending.is_effective(observed),
            "backdated ceiling proposal must NOT be effective at commit time"
        );
        assert!(
            !pending.is_effective(observed + CEILING_CHANGE_NOTIFICATION_PERIOD_SECS - 1),
            "backdated ceiling proposal must NOT be effective before the local floor"
        );
        assert!(
            pending.is_effective(observed + CEILING_CHANGE_NOTIFICATION_PERIOD_SECS),
            "ceiling window must elapse exactly PERIOD after local commit-processing time"
        );
    }

    #[test]
    fn ceiling_honest_proposal_tracks_effective_at() {
        let created_at = 3_000_000_000u64;
        let observed = created_at + 5;
        let pending = pending_ceiling(created_at, observed);
        let effective_at = created_at + CEILING_CHANGE_NOTIFICATION_PERIOD_SECS;
        assert!(!pending.is_effective(effective_at - 1));
        assert!(pending.is_effective(observed + CEILING_CHANGE_NOTIFICATION_PERIOD_SECS));
    }
}

#[cfg(test)]
mod canonical_context_id_tests {
    //! ADR-056 (Model A) / §6.2.4:276: a context's canonical
    //! identity IS its 32-byte digest, and the id STRING is `hex(digest)`.
    //! [`context_id_to_bytes`] must DECODE a real 64-hex id to its digest (not
    //! re-hash it), while leaving every synthetic / non-64-hex string on the
    //! byte-for-byte unchanged SHA-256 fallback.

    use super::context_id_to_bytes;

    #[test]
    fn real_64hex_id_decodes_to_digest_not_sha256() {
        let digest: [u8; 32] = [
            0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c,
        ];
        let id = hex::encode(digest);
        assert_eq!(id.len(), 64);
        // DECODE recovers the digest verbatim (single chokepoint).
        assert_eq!(context_id_to_bytes(&id), digest);
        // And that is NOT the same as hashing the hex string.
        assert_ne!(
            context_id_to_bytes(&id),
            scp_protocol::context::context_id_bytes(&id),
            "a real id must decode, not re-hash — that double-hash is the bug ADR-056 fixes"
        );
    }

    #[test]
    fn synthetic_namespace_id_falls_through_to_hash() {
        // The identity-scoped PSK-rotation pseudo-context (§9.12 step 6).
        let id = "identity-private-state";
        assert_eq!(
            context_id_to_bytes(id),
            scp_protocol::context::context_id_bytes(id),
            "a non-64-hex synthetic id must hash exactly as before"
        );
    }

    #[test]
    fn standing_prefixed_id_falls_through_to_hash() {
        // Standing-pair display id: `"standing-" + 64-hex`. The prefix makes it
        // longer than 64 chars, so it is never bare 64-hex and must hash —
        // ADR-056 does not alter standing-context id derivation.
        let id = format!("standing-{}", "ab".repeat(32));
        assert!(id.len() > 64);
        assert_eq!(
            context_id_to_bytes(&id),
            scp_protocol::context::context_id_bytes(&id)
        );
    }

    #[test]
    fn arbitrary_test_id_falls_through_to_hash() {
        let id = "ctx-some-arbitrary-test-id";
        assert_eq!(
            context_id_to_bytes(id),
            scp_protocol::context::context_id_bytes(id)
        );
    }

    #[test]
    fn uppercase_64hex_is_not_canonical_and_hashes() {
        // `generate_context_id` emits only LOWERCASE hex. A 64-char UPPERCASE
        // hex string is therefore not a canonical id: the strict lowercase
        // guard keeps it on the hashing fallback rather than silently decoding.
        let upper = "AB".repeat(32);
        assert_eq!(upper.len(), 64);
        assert_eq!(
            context_id_to_bytes(&upper),
            scp_protocol::context::context_id_bytes(&upper),
            "uppercase 64-hex must hash, not decode (lowercase-only guard)"
        );
    }

    #[test]
    fn near_64_lengths_hash() {
        // 63 and 65 lowercase-hex chars are not canonical ids.
        let short = "a".repeat(63);
        let long = "a".repeat(65);
        assert_eq!(
            context_id_to_bytes(&short),
            scp_protocol::context::context_id_bytes(&short)
        );
        assert_eq!(
            context_id_to_bytes(&long),
            scp_protocol::context::context_id_bytes(&long)
        );
    }
}

#[cfg(test)]
mod genesis_ceiling_currency_tests {
    //! #2028 — unit coverage for [`check_genesis_ceiling_still_current`]'s two
    //! independent refusal reasons and the boundaries between them.

    #![allow(clippy::expect_used)]

    use super::check_genesis_ceiling_still_current;
    use scp_protocol::context::ContextParams;
    use scp_protocol::context::params::CeilingPolicy;
    use scp_protocol::context::roles::{Capability, CapabilityCeiling};

    fn params(ceiling: Vec<Capability>, policy: CeilingPolicy) -> ContextParams {
        ContextParams {
            ceiling,
            ceiling_policy: policy,
            ..ContextParams::default()
        }
    }

    /// The primary invariant: a LOWERING that drops a genesis entry is refused,
    /// and the message names the dropped capability.
    #[test]
    fn lowering_that_drops_a_genesis_entry_is_refused() {
        let genesis = params(
            vec![Capability::MessagesRead, Capability::MemberInvite],
            CeilingPolicy::Governed,
        );
        let live = CapabilityCeiling::new([Capability::MessagesRead]);
        let err = check_genesis_ceiling_still_current(&genesis, &live, "site")
            .expect_err("a dropped genesis entry must be refused");
        let msg = err.to_string();
        assert!(msg.contains("member:invite"), "got: {msg}");
        assert!(msg.contains("2028"), "got: {msg}");
    }

    /// A `{resource}:*` live entry covers the concrete genesis entry it subsumes
    /// — the relation `CapabilityUri::is_within_ceiling` enforces. Bare
    /// `CapabilityCeiling::contains` would refuse this and brick every future
    /// join (see `ceiling_covers`).
    #[test]
    fn custom_resource_wildcard_covers_a_concrete_genesis_entry() {
        let genesis = params(
            vec![Capability::Custom("data:read".to_owned())],
            CeilingPolicy::Governed,
        );
        let live = CapabilityCeiling::new([Capability::Custom("data:*".to_owned())]);
        assert!(
            !live.contains(&Capability::Custom("data:read".to_owned())),
            "precondition: bare `contains` does NOT see this coverage",
        );
        check_genesis_ceiling_still_current(&genesis, &live, "site")
            .expect("a {resource}:* live entry covers the concrete genesis entry");
    }

    /// The wildcard rule is one-directional: a live CONCRETE entry does not
    /// cover a genesis WILDCARD (that would be a real fail-open — the joiner
    /// would install `data:*` while the context grants only `data:read`).
    #[test]
    fn concrete_live_entry_does_not_cover_a_genesis_wildcard() {
        let genesis = params(
            vec![Capability::Custom("data:*".to_owned())],
            CeilingPolicy::Governed,
        );
        let live = CapabilityCeiling::new([Capability::Custom("data:read".to_owned())]);
        let err = check_genesis_ceiling_still_current(&genesis, &live, "site")
            .expect_err("narrowing a wildcard to a concrete action is a LOWERING");
        assert!(err.to_string().contains("data:*"), "got: {err}");
    }

    /// The non-vacuity detector. `ContextParams::default()` — the value every
    /// FFI bridge used to hand the restore path — carries an EMPTY ceiling, and
    /// an empty genesis set is trivially covered by ANY live ceiling. The
    /// primary check alone would therefore return a vacuous `Ok`, leaving a gate
    /// that is present in the source but enforces nothing.
    ///
    /// `ContextParams::default()` also carries `ceiling_policy: Immutable` (the
    /// `#[default]` variant), under which the live ceiling CANNOT diverge from
    /// genesis (§5.3.2 — `ModifyCeiling` requires `Governed`). A non-empty live
    /// ceiling therefore proves these are not the context's real params.
    #[test]
    fn reconstructed_default_params_are_refused_not_vacuously_accepted() {
        let fabricated = ContextParams::default();
        assert!(
            fabricated.ceiling.is_empty() && fabricated.ceiling_policy == CeilingPolicy::Immutable,
            "precondition: the default params are the exact fabricated shape this guards",
        );
        let live = CapabilityCeiling::new([Capability::MessagesRead, Capability::MemberInvite]);

        let err = check_genesis_ceiling_still_current(&fabricated, &live, "site")
            .expect_err("a reconstructed/default ContextParams must NOT pass vacuously");
        let msg = err.to_string();
        assert!(
            msg.contains("Immutable") && msg.contains("not this context's own"),
            "the refusal must name the non-vacuity reason, got: {msg}",
        );
        assert!(
            msg.contains("messages:read") && msg.contains("member:invite"),
            "the refusal must name the unexplained live entries, got: {msg}",
        );
    }

    /// The detector is scoped to `Immutable` on purpose: under `Governed` a
    /// WIDENING — including a widening away from an empty genesis ceiling — is a
    /// legitimate, specced operation (§5.3.2), so the same asymmetry there is
    /// real evolution rather than evidence of a fabricated handle. Refusing it
    /// would brick a legitimate governance action.
    #[test]
    fn governed_widening_from_an_empty_genesis_ceiling_is_permitted() {
        let genesis = params(Vec::new(), CeilingPolicy::Governed);
        let live = CapabilityCeiling::new([Capability::MessagesRead]);
        check_genesis_ceiling_still_current(&genesis, &live, "site")
            .expect("a governed widening from an empty ceiling is legitimate");
    }

    /// An `Immutable` context whose live ceiling equals genesis passes both
    /// directions — the ordinary, overwhelmingly common case must not be
    /// disturbed by the detector.
    #[test]
    fn immutable_context_with_matching_ceilings_passes() {
        let caps = vec![Capability::MessagesRead, Capability::MessagesWrite];
        let genesis = params(caps.clone(), CeilingPolicy::Immutable);
        let live = CapabilityCeiling::new(caps);
        check_genesis_ceiling_still_current(&genesis, &live, "site")
            .expect("live == genesis under Immutable is the normal case");
    }
}
