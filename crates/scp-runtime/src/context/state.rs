//! Per-context durable state types — `PerContextState`,
//! `ContextSnapshot`, `BroadcastSnapshot`, generation tokens, governance
//! result types, plus pseudonym + commit-retry primitives.
//!
//! This module is the canonical home for context state types. Hoisted
//! out of the deleted `manager/` directory in ADR-049 commit 12.
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
use super::governance::timeout::{DeadlockDetectionState, GovernanceTimeoutTask};
use super::ttl::{TtlExtension, TtlTimer};
use scp_identity::DID;
use scp_primitives::Clock;
use scp_protocol::context::broadcast::GovernanceBanResult;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::governance::{
    AccessScope, GovernanceEngine, GovernanceModelConfig, GovernanceProposal, KeyResolver,
    ProposalId, ProposalStatus, PruningPolicy, SingleAdminEngine,
    majority::MajorityVoteEngine,
    mls_integration::{CoordinationRecord, EpochCoordinator},
    multisig::ThresholdEngine,
    unanimity::UnanimityEngine,
};
use scp_protocol::context::membership::{ContextEvent, MembershipState, ReceiveBuffer};
use scp_protocol::context::params::GovernanceModel;
use scp_protocol::context::params::ToolRegistration;
use scp_protocol::context::roles::{Capability, ContextRoleState};
use scp_protocol::context::tools::interface::ToolInterface;
use scp_protocol::context::{ContextError, ContextParams, ContextState};
use scp_protocol::economy::budget::MemberBudgetTracker;
use scp_protocol::economy::types::EconomicPolicy;
use scp_protocol::trust::consequence::ConsequenceRule;

// ---------------------------------------------------------------------------
// Protocol-level collection size limits (§5.9)
// ---------------------------------------------------------------------------

/// Maximum number of registered tools per context.
pub(crate) const MAX_REGISTERED_TOOLS: usize = 256;

/// Maximum number of cross-context tool interfaces per context.
pub(crate) const MAX_TOOL_INTERFACES: usize = 256;

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
/// When this cap is reached, [`try_broadcast_commit_or_enqueue`](crate::context::governance_helpers::try_broadcast_commit_or_enqueue) sets the
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
/// consumers and the durable event log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitOperation {
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
}

impl CommitOperation {
    /// Human-readable label used in events and the durable event log.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::RemoveMember { .. } => "RemoveMember".to_owned(),
            Self::RotateContentKeys { .. } => "RotateContentKeys".to_owned(),
            Self::ResetMember {
                is_remove: true, ..
            } => "ResetMemberRemove".to_owned(),
            Self::ResetMember {
                is_remove: false, ..
            } => "ResetMemberAdd".to_owned(),
            Self::LeaveContext { .. } => "LeaveContext".to_owned(),
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
    /// Unix timestamp (seconds) when the notification period expires and
    /// the new ceiling can be applied.
    pub effective_at: u64,
    /// The governance proposal ID that approved this modification.
    pub proposal_id: ProposalId,
}

impl PendingCeilingModification {
    /// Returns `true` if the notification period has expired and the
    /// modification can be applied.
    #[must_use]
    pub const fn is_effective(&self, current_timestamp: u64) -> bool {
        current_timestamp >= self.effective_at
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
    /// Unix timestamp (seconds) when the notification period expires and
    /// the new policy can be applied.
    pub effective_at: u64,
    /// The governance proposal ID that approved this change.
    pub proposal_id: ProposalId,
}

impl PendingEconomicPolicyChange {
    /// Returns `true` if the notification period has expired and the
    /// new policy can be applied.
    #[must_use]
    pub const fn is_effective(&self, current_timestamp: u64) -> bool {
        current_timestamp >= self.effective_at
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
    MemberAdded,
    /// A member was ejected from the context (MLS removal).
    MemberRemoved,
    /// A member's role was changed.
    RoleChanged,
    /// A tool was registered in the context.
    ToolRegistered,
    /// A tool was removed from the context.
    ToolRemoved,
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
    /// A tool interface was established.
    ToolInterfaceEstablished,
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
    /// hash-chain head. `verify_merkle_chain` recomputes it by replaying every
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
    /// Remaining TTL in seconds, if a TTL timer was active. `None` if no
    /// TTL was configured or the timer was not running.
    pub ttl_remaining_secs: Option<u64>,
    /// Dynamically registered tools (beyond initial `ContextParams.tools`).
    #[serde(default)]
    pub registered_tools: Vec<ToolRegistration>,
    /// Members excluded from future CEK wrapping (`Revoke { access: AccessScope::Write }`).
    /// These members won't receive new content keys but retain access to
    /// historical content encrypted before the revocation (ADR-038, §9.17).
    ///
    /// Serialized in a deterministic (content-sorted) order so the signed
    /// context-export digest is reproducible (§23.16.8, ADR-050).
    #[serde(default, with = "scp_protocol::serde_util::serde_sorted_set")]
    pub read_exclusion_list: HashSet<DID>,
    /// Established cross-context tool interfaces (§6.2).
    #[serde(default)]
    pub tool_interfaces: Vec<ToolInterface>,
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
    /// Captured from [`EpochGraceStore::to_grace_entries`](crate::crypto::mls::epoch_grace::EpochGraceStore::to_grace_entries)
    /// during snapshot creation. On recovery, fed to
    /// [`EpochGraceStore::restore_from_entries`](crate::crypto::mls::epoch_grace::EpochGraceStore::restore_from_entries)
    /// to reconstruct the grace store. Persisted alongside all other context
    /// state to ensure transactional consistency (§23.11 step 2).
    #[serde(default)]
    pub grace_entries: Vec<crate::crypto::mls::epoch_grace::GraceEntry>,
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
    /// `ContextManager::restore_context`.
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
    /// [`ContextRouting::Broadcast`] and carry no pseudonym state.
    ///
    /// Degraded / pre-routing-field snapshots (those persisted before this
    /// field existed, or `strip_snapshot_for_public` redactions) default to
    /// [`ContextRouting::Broadcast`] via [`default_context_routing`] — a
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

    /// Target-side (B-owned) durable capture of COMMITTED cross-context tool
    /// invocations, keyed by `SagaId` (spec §6.2.4 "Exactly-once execution with
    /// durable output capture"). **Class S** — synchronously-persisted,
    /// fail-closed, mirroring [`Self::saga_pending`].
    ///
    /// The live actor-side slot is
    /// [`PerContextState::xctx_committed_outputs`](crate::context::actor::state::PerContextState::xctx_committed_outputs).
    /// Commit-B captures the tool output + signed receipt here BEFORE acking, so
    /// a Commit replayed after a crash (§17.16.4) re-emits the stored output and
    /// re-signs nothing — it returns the IDENTICAL receipt. A coalesce-window
    /// rollback of this capture would re-invoke the tool on replay, the exact
    /// exactly-once violation the synchronous persist forecloses.
    ///
    /// Unlike `saga_pending` this carries no §9.4.3 non-derive barrier — the
    /// receipt + output are public protocol artifacts (no bearer bytes), so the
    /// snapshot stores the live
    /// [`CommittedToolInvocation`](crate::context::supervisor::saga_prepared_state::CommittedToolInvocation)
    /// directly. Same local-only coordination semantics: same-node restore
    /// REHYDRATES it; cross-node `import_context` / `strip_snapshot_for_public`
    /// DROP it to empty (a foreign saga must never drive local Commit replay).
    /// `#[serde(default)]` so legacy / stripped snapshots deserialize as empty.
    #[serde(default)]
    pub xctx_committed_outputs: HashMap<
        crate::context::supervisor::saga_journal::SagaId,
        crate::context::supervisor::saga_prepared_state::CommittedToolInvocation,
    >,

    /// Caller-side (A-owned) durable set of COMMITTED cross-context tool
    /// invocations, keyed by `SagaId` (spec §6.2.4 "Commit", caller side;
    /// §17.16.4). **Class S** — synchronously-persisted, fail-closed, mirroring
    /// [`Self::saga_pending`].
    ///
    /// The live slot is
    /// [`PerContextState::xctx_committed_invocations`](crate::context::actor::state::PerContextState::xctx_committed_invocations).
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
    /// cross-context tool-invocation Prepare-A reservations, keyed by `SagaId`
    /// (spec §6.2.4 "Reservation release on every terminal path"). **Class S** —
    /// synchronously-persisted, fail-closed, mirroring [`Self::saga_pending`].
    ///
    /// The live slot is
    /// [`PerContextState::xctx_caller_reservations`](crate::context::actor::state::PerContextState::xctx_caller_reservations).
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
    /// tool invocation (spec §6.2.4 "Freshness / anti-replay"). The serialized
    /// projection of
    /// [`PerContextState::xctx_nonce_dedup`](crate::context::actor::state::PerContextState::xctx_nonce_dedup):
    /// `{16-byte nonce → first-seen Unix secs}`.
    ///
    /// **Class S** — synchronously-persisted, fail-closed, mirroring
    /// [`Self::saga_pending`]. This cache is the ONLY gate against a replayed
    /// `CrossContextToolInvoke` envelope re-submitted under a FRESH `SagaId`
    /// within the 5-minute TTL (the `SagaId` idempotency witnesses and the
    /// `xctx_committed_outputs` short-circuit only catch a SAME-`SagaId` replay).
    /// If it reinitialized empty on restore, an actor crash inside the TTL window
    /// would let an attacker re-run a charging tool (BLACK-624-01). Persisting it
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
}

/// Default routing variant for degraded / pre-routing-field snapshots.
///
/// Returns [`ContextRouting::Broadcast`] — a placeholder that carries no
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
// ADR-049 commit 12.

// ---------------------------------------------------------------------------
// PerContextState -- internal per-context tracking
// ---------------------------------------------------------------------------

/// Governance-related per-context state.
///
/// **Visibility:** elevated to `pub(crate)` by commit 12a of ADR-049 so the
/// actor's [`crate::context::actor::state::PerContextState`] can carry a
/// field of this type while the handler-body migration is under way.
/// Commit 12d deletes this struct along with the rest of the legacy manager
/// module.
pub(crate) struct GovernanceState {
    /// The governance engine for this context (ADR-031, spec §5.9).
    pub(crate) engine: Box<dyn GovernanceEngine>,
    /// Proposal IDs that have already been executed, mapped to the unix
    /// timestamp (seconds) when they were marked executed. Prevents replay of
    /// approved governance proposals (defense-in-depth). Entries older than
    /// [`EXECUTED_PROPOSALS_TTL_SECS`] are evicted on each insert.
    pub(crate) executed_proposals: HashMap<ProposalId, u64>,
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
    /// Governance timeout task (SCP-271, ADR-031 §5).
    pub(crate) timeout_task: GovernanceTimeoutTask,
    /// Per-context deadlock detection tracking (ADR-031 §10).
    pub(crate) deadlock: DeadlockDetectionState,
    /// Governance threshold signers (for `ThresholdApproval` model).
    pub(crate) threshold_signers: Vec<DID>,
    /// Governance threshold value (quorum requirement).
    pub(crate) threshold_value: u32,
    /// Pending ceiling modification awaiting notification period (M7, §5.3.2).
    pub(crate) pending_ceiling_modification: Option<PendingCeilingModification>,
    /// Pending economic policy change awaiting notification period (§19.3).
    pub(crate) pending_economic_policy_change: Option<PendingEconomicPolicyChange>,
    /// Dynamically registered tools (beyond initial `ContextParams.tools`).
    pub(crate) registered_tools: Vec<ToolRegistration>,
    /// Established cross-context tool interfaces (§6.2).
    pub(crate) tool_interfaces: Vec<ToolInterface>,
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
    /// Widened to `pub(crate)` in ADR-049 commit 12c.1b so the hoisted
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
    /// Per-context nonce tracker for spending UCAN replay prevention (ADR-016 §6).
    /// Validates that each spending UCAN nonce is used at most once, preventing
    /// replay attacks where a valid spending UCAN is resubmitted.
    pub(crate) spending_nonce_tracker:
        scp_protocol::crypto::ucan::nonce::NonceTracker<Arc<dyn Clock>>,
    /// Per-context revoked spending-UCAN CIDs (C1, PR #1606).
    ///
    /// Consulted by `enforce_economy` via the
    /// [`super::economy::ContextRevocationChecker`] adapter when validating
    /// spending UCANs through the full cryptographic pipeline. Currently
    /// empty in steady state — spending UCAN revocation lists have not been
    /// wired through governance — but the field exists so the only change
    /// required when revocation lands is populating it (no enforcement
    /// rewrite needed). The set is part of the governance bucket because
    /// revocation actions are governance-driven (§19.5).
    pub(crate) revoked_spending_ucan_cids: HashSet<String>,
    /// Per-member governance proposal timestamps for earned capacity rate limiting
    /// (§9.3). Maps member DID string to a list of Unix timestamps (seconds) when
    /// the member submitted governance proposals. Used by `check_proposer_eligibility` to
    /// enforce `max_governance_proposals_per_window` from `EarnedCapacityPolicy`.
    /// Entries outside the sliding window are evicted on each check.
    pub(crate) proposal_timestamps: HashMap<String, Vec<u64>>,
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

    /// Evicts stale entries from caches to prevent unbounded growth.
    ///
    /// Unlike [`decay_participation`](Self::decay_participation) (which
    /// clears everything), this performs targeted eviction based on current
    /// state:
    /// - `participation_cache`: removes DIDs not in `last_known_members`.
    /// - `cooldown_until`: removes entries where `now >= expiry`.
    ///
    /// Visibility widened to `pub(crate)` in ADR-049 commit 12c.9g.1 so
    /// the hoisted
    /// [`crate::context::governance_helpers::start_governance_timeout_task`]
    /// free function can call it from outside the `manager/` submodule
    /// tree.
    pub(crate) fn evict_stale_entries(&mut self, now: u64) {
        // M25: O(1) membership check per entry via HashSet::contains.
        // last_known_members is HashSet<DID> which implements Borrow<str>,
        // so we can look up &str keys directly.
        self.participation_cache
            .retain(|did, _| self.last_known_members.contains(did.as_str()));
        // Evict expired cooldown entries.
        self.cooldown_until.retain(|_, expiry| now < *expiry);
        // Evict departed members from proposal timestamps.
        self.proposal_timestamps
            .retain(|did, _| self.last_known_members.contains(did.as_str()));
    }
}

/// MLS epoch and reconnection state.
///
/// **Visibility:** elevated to `pub(crate)` by commit 12a of ADR-049 so the
/// actor's [`crate::context::actor::state::PerContextState`] can carry a
/// field of this type while the handler-body migration is under way.
/// Commit 12d deletes this struct along with the rest of the legacy manager
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
    pub(crate) grace_store: crate::crypto::mls::epoch_grace::EpochGraceStore,
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
/// **Visibility:** elevated to `pub(crate)` by commit 12a of ADR-049 so the
/// actor's [`crate::context::actor::state::PerContextState`] can carry a
/// field of this type while the handler-body migration is under way.
/// Commit 12d deletes this struct along with the rest of the legacy manager
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
    /// fixture (commit 12a of ADR-049) to populate the corresponding field
    /// without peeking at private fields. Deleted in commit 12d alongside
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
    /// fixture (commit 12a of ADR-049). Deleted in commit 12d alongside
    /// the rest of the legacy manager module.
    #[must_use]
    pub(crate) fn new_fresh_for_actor(context_id: &str) -> Self {
        Self {
            mls_epoch: 0,
            coordinator: EpochCoordinator::from_records(Vec::new(), context_id),
            grace_store: crate::crypto::mls::epoch_grace::EpochGraceStore::new(),
            needs_reconnect: false,
        }
    }
}

impl TtlState {
    /// Construct a fresh `TtlState` with a clock-less `TtlTimer` and no
    /// active extension. Used by the actor's
    /// [`crate::context::actor::state::PerContextState`] default-for-test
    /// fixture (commit 12a of ADR-049). Deleted in commit 12d alongside
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
    /// default-for-test helper (commit 12a of ADR-049). Production paths
    /// continue to construct the struct inline from the lifecycle handler.
    /// Deleted in commit 12d alongside the rest of the legacy manager
    /// module.
    #[must_use]
    pub(crate) fn new_fresh_for_actor(
        context_id: &str,
        admin_did: DID,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let resolver: scp_protocol::context::governance::KeyResolver = Arc::new(|_did: &DID| None);
        let engine: Box<dyn GovernanceEngine> =
            Box::new(SingleAdminEngine::new(admin_did, resolver));
        Self {
            engine,
            executed_proposals: HashMap::new(),
            approved_proposals: HashMap::new(),
            next_proposal_seq: 0,
            freeze: None,
            timeout_task: GovernanceTimeoutTask::new(),
            deadlock: DeadlockDetectionState::default(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pending_ceiling_modification: None,
            pending_economic_policy_change: None,
            registered_tools: Vec::new(),
            tool_interfaces: Vec::new(),
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
            spending_nonce_tracker: scp_protocol::crypto::ucan::nonce::NonceTracker::new(
                context_id.to_owned(),
                clock,
            ),
            revoked_spending_ucan_cids: HashSet::new(),
            proposal_timestamps: HashMap::new(),
        }
    }
}

/// TTL timer and extension state.
///
/// **Visibility:** elevated to `pub(crate)` by commit 12a of ADR-049 so the
/// actor's [`crate::context::actor::state::PerContextState`] can carry a
/// field of this type while the handler-body migration is under way.
/// Commit 12d deletes this struct along with the rest of the legacy manager
/// module.
pub(crate) struct TtlState {
    /// TTL timer management (SCP-021).
    pub(crate) timer: TtlTimer,
    /// Active TTL extension proposal, if any (SCP-021).
    pub(crate) extension: Option<TtlExtension>,
}

/// Wire format for pseudonym announcements sent as MLS application messages.
///
/// When a member joins or creates a context with a pre-derived pseudonym,
/// they announce it to other members via this structure serialized with
/// `MessagePack`. Recipients store the mapping in their pseudonym registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PseudonymAnnouncement {
    /// Magic prefix to distinguish from regular application messages.
    pub tag: String,
    /// The announcing member's DID.
    pub member_did: String,
    /// The 32-byte pseudonym routing ID.
    #[serde(with = "serde_bytes")]
    pub pseudonym: [u8; 32],
}

/// Magic tag used to identify pseudonym announcement messages in the MLS
/// application message stream. Prefixed with `\0` to avoid collision with
/// user-generated content (which is always valid UTF-8 and will never start
/// with a null byte when deserialized from `MessagePack`).
pub(crate) const PSEUDONYM_ANNOUNCEMENT_TAG: &str = "\0scp:pseudonym-announce:v1";

/// Wire wrapper for a consistency-checkpoint exchange message (§9.9.3, §23.7).
///
/// Carries the canonical signed [`ConsistencyCheckpoint`] behind a magic tag
/// so the receive path can positively identify it. Although the inner envelope
/// already discriminates checkpoints via
/// [`MessageType::ConsistencyCheckpoint`](scp_protocol::envelope::inner::MessageType::ConsistencyCheckpoint),
/// the tag is a defense-in-depth guard mirroring [`PseudonymAnnouncement`]:
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
/// [`PSEUDONYM_ANNOUNCEMENT_TAG`]: user content is valid UTF-8 and never starts
/// with a null byte when `MessagePack`-decoded, so the tag cannot collide.
pub(crate) const CHECKPOINT_PAYLOAD_TAG: &str = "\0scp:checkpoint:v1";

// ADR-049 Phase 2A finalization keystone (commit 12 phase 2A finalization
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

/// Restores the [`EpochGraceStore`](crate::crypto::mls::epoch_grace::EpochGraceStore)
/// from persisted snapshot entries, applying the §23.11 inconsistency
/// detection and fallback steps.
///
/// Returns the (possibly empty) grace store and a flag indicating whether
/// the context needs to re-enter the reconnection protocol (§23.3).
pub(crate) fn restore_grace_store_from_snapshot(
    context_id: &str,
    snapshot: &ContextSnapshot,
) -> (crate::crypto::mls::epoch_grace::EpochGraceStore, bool) {
    let mut grace_store = crate::crypto::mls::epoch_grace::EpochGraceStore::new();
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

/// Reads the context state synchronously via [`ContextHandle::try_read_state`].
/// Returns `ContextNotActive` if the read lock cannot be acquired (a state
/// transition is in progress) or if the state is not `Active`.
///
/// This is used inside `Mutex` lock scopes to avoid TOCTOU races: the state
/// check and the subsequent mutation happen within the same lock acquisition,
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

/// guaranteeing that no concurrent `close_context` or `handle_ttl_expiry` can
/// interleave between the check and the mutation.
pub(crate) fn require_active(handle: &ContextHandle) -> Result<(), ContextError> {
    let state = handle
        .try_read_state()
        .ok_or(ContextError::ContextNotActive)?;
    if state != ContextState::Active {
        return Err(ContextError::ContextNotActive);
    }
    Ok(())
}

/// Requires the context to be in `MigratingOut` state (§5.11A).
/// Used for `CancelContextMigration` which is only valid during migration.
pub(crate) fn require_migrating_out(handle: &ContextHandle) -> Result<(), ContextError> {
    let state = handle
        .try_read_state()
        .ok_or(ContextError::ContextNotActive)?;
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
// ADR-049 commit 12 alongside the rest of the manager-only code.

/// Uses the canonical SHA-256 context ID byte derivation.
/// Delegates to [`scp_protocol::context::context_id_bytes`] to match builder.rs.
pub(crate) fn context_id_to_bytes(context_id: &str) -> [u8; 32] {
    scp_protocol::context::context_id_bytes(context_id)
}
