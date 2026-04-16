//! Context Manager -- central coordinator for context lifecycle.
//!
//! The [`ContextManager`] owns the provider implementations and exposes the
//! public API for context creation, membership, and messaging. It delegates
//! to [`super::builder::create_context`] for the two-phase commit flow.
//!
//! Providers are injected through the constructor, making the manager fully
//! testable with mock implementations. See ADR-008 in
//! `.docs/adrs/phase-2.md` for the full context lifecycle specification.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::BuildHasher;
use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use super::ContextHandle;
use super::builder::{
    ContextEventLogProvider, ContextTransportProvider, create_context as builder_create_context,
};
use super::governance::timeout::{
    DeadlockDetectionState, GovernanceTimeoutTask, collect_active_voters,
    process_pending_proposals, update_detection_state,
};
use super::ttl::{self, CloseResult, TtlExtension, TtlTimer};
use scp_identity::DID;
use scp_primitives::Clock;
use scp_protocol::context::broadcast::{
    BlockResult, BroadcastAdmission, BroadcastContext, BroadcastContextSnapshot,
    GovernanceBanResult, KeyRequestDecision, SubscriptionResult, UnsubscribeResult,
};
use scp_protocol::context::broadcast_content::{BroadcastContent, serialize_broadcast_content};
use scp_protocol::context::builder::{ContextCreationError, ContextCryptoProvider};
use scp_protocol::context::governance::{
    AccessScope, CheckpointAttestationStatus, ContextCheckpoint, CosignedCheckpoint,
    GovernanceAction, GovernanceContext, GovernanceEngine, GovernanceEvent, GovernanceModelConfig,
    GovernanceProposal, KeyResolver, ProposalId, ProposalStatus, PruningPolicy, SingleAdminEngine,
    majority::MajorityVoteEngine,
    mls_integration::{
        CoordinationRecord, EpochCoordinator, MlsImpact, classify_action, generate_mls_operations,
    },
    multisig::ThresholdEngine,
    unanimity::UnanimityEngine,
};
use scp_protocol::context::membership::{ContextEvent, KeyPackage, MembershipState, ReceiveBuffer};
use scp_protocol::context::params::GovernanceModel;
use scp_protocol::context::params::{ContextMode, TemplateId, ToolRegistration};
use scp_protocol::context::roles::{
    self, Capability, CapabilityCeiling, ContextRoleState, RoleAssignment,
};
use scp_protocol::context::tools::interface::ToolInterface;
use scp_protocol::context::{ContextError, ContextParams, ContextState};
use scp_protocol::crypto::sender_keys::BroadcastEnvelope;
use scp_protocol::crypto::ucan::UcanToken;
use scp_protocol::crypto::ucan::validate::{
    DidResolver, NonceTracker, ProofResolver, RevocationChecker, ValidationContext,
};
use scp_protocol::economy::budget::MemberBudgetTracker;
use scp_protocol::economy::types::EconomicPolicy;
use scp_protocol::trust::consequence::{
    ConsequenceRule, TriggeredConsequence, evaluate_consequence_rules,
};
use tracing::instrument;
use zeroize::Zeroizing;

mod broadcast;
mod economy;
mod governance;
mod lifecycle;
mod messaging;
mod queries;
pub(crate) mod standing;
mod tools;
mod trust_recovery;
mod ttl_close;

// ---------------------------------------------------------------------------
// Protocol-level collection size limits (§5.9)
// ---------------------------------------------------------------------------

/// Maximum number of registered tools per context.
const MAX_REGISTERED_TOOLS: usize = 256;

/// Maximum number of cross-context tool interfaces per context.
const MAX_TOOL_INTERFACES: usize = 256;

/// Maximum number of governance threshold signers per context.
const MAX_THRESHOLD_SIGNERS: usize = 64;

/// Default ceiling change notification period in seconds (M7, §5.3.2).
///
/// When a governed context's ceiling is modified, the change is pending
/// for this duration before taking effect. Members joined under the previous
/// ceiling are notified and may leave before the expansion applies.
///
/// Spec §5.3.2: "A mandatory notification period of 72 hours begins."
const CEILING_CHANGE_NOTIFICATION_PERIOD_SECS: u64 = 259_200; // 72 hours

/// TTL for `executed_proposals` entries in seconds (14 days).
///
/// Entries older than this are evicted on each insert to prevent unbounded
/// growth. 14 days is generous — governance proposals are typically resolved
/// within hours, so a 14-day window provides ample replay protection.
const EXECUTED_PROPOSALS_TTL_SECS: u64 = 14 * 24 * 60 * 60; // 14 days

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
/// When this cap is reached, [`try_broadcast_commit_or_enqueue`] sets the
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
/// operator via [`ContextManager::acknowledge_commit_fault`].
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
// Welcome event helper
// ---------------------------------------------------------------------------

/// Pushes a [`ContextEvent::WelcomeGenerated`] event to the receive buffer
/// if the `AddMemberOutput` contains a non-empty Welcome message.
///
/// Used by both `join_context` and `execute_add_member` to avoid
/// duplicating the emission logic.
fn push_welcome_event(
    buffer: &mut ReceiveBuffer,
    context_id: &str,
    creator_did: &DID,
    member_did: &DID,
    add_output: scp_protocol::context::builder::AddMemberOutput,
) {
    if !add_output.welcome_bytes.is_empty() {
        buffer.push(ContextEvent::WelcomeGenerated {
            context_id: context_id.to_owned(),
            creator_did: creator_did.clone(),
            member_did: member_did.clone(),
            welcome_bytes: scp_protocol::context::membership::RedactedBytes(
                add_output.welcome_bytes,
            ),
            commit_bytes: scp_protocol::context::membership::RedactedBytes(add_output.commit_bytes),
        });
    }
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
const ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS: u64 = 86_400; // 24 hours

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
/// [`ContextManager::execute_governance_action`].
///
/// Each variant maps 1:1 to a [`GovernanceAction`] variant (ADR-031 §2).
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
/// [`ContextManager::propose_governance_action_checked`].
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
    /// Proposal IDs that have already been executed (replay protection).
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
    #[serde(default)]
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
    #[serde(default)]
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
    /// [`ContextCryptoProvider::export_crypto_state`]. Contains MLS group
    /// tree, epoch secrets, sender keys, and wrapping keys. Restored via
    /// [`ContextCryptoProvider::restore_crypto_state`] during
    /// [`ContextManager::restore_context`].
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

// ---------------------------------------------------------------------------
// ContextPersistence -- unified persistence provider
// ---------------------------------------------------------------------------

/// Provider for persisting full context state across process restarts.
///
/// Replaces the previous `BroadcastPersistence` trait. This is the single
/// persistence trait for all context state: both the full context snapshot
/// (membership, roles, governance, TTL) and the broadcast-specific state
/// (author keys, subscribers, block lists).
///
/// Implementors must be dyn-compatible (`Send + Sync`, no generics, no
/// RPITIT). All methods return `Result<_, Box<dyn Error + Send + Sync>>`
/// for best-effort semantics: the `ContextManager` logs errors but does
/// not abort mutations when persistence fails.
///
/// The canonical implementation is `ProtocolRepositoryContextBridge<S>` which
/// wraps `Arc<ProtocolRepository<S>>`.
///
/// See spec section 17.4.
pub trait ContextPersistence: Send + Sync {
    /// Persists the full context snapshot.
    ///
    /// Called after each context-mutating operation. Idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage write fails.
    fn persist_context(
        &self,
        context_id: &str,
        snapshot: &ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Loads a previously persisted full context snapshot.
    ///
    /// Returns `None` if no snapshot exists for the given context.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage read fails.
    fn load_context(
        &self,
        context_id: &str,
    ) -> Result<Option<ContextSnapshot>, Box<dyn std::error::Error + Send + Sync>>;

    /// Persists the broadcast context state snapshot.
    ///
    /// Called after each broadcast-mutating operation. Idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage write fails.
    fn persist_broadcast(
        &self,
        context_id: &str,
        snapshot: &BroadcastContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Loads a previously persisted broadcast context snapshot.
    ///
    /// Returns `None` if no snapshot exists for the given context.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage read fails.
    fn load_broadcast(
        &self,
        context_id: &str,
    ) -> Result<Option<BroadcastContextSnapshot>, Box<dyn std::error::Error + Send + Sync>>;

    /// Deletes all persisted state for a context.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage delete fails.
    fn delete_context(
        &self,
        context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Lists all persisted context IDs.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage list fails.
    fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>>;
}

// ---------------------------------------------------------------------------
// PerContextState -- internal per-context tracking
// ---------------------------------------------------------------------------

/// Governance-related per-context state.
struct GovernanceState {
    /// The governance engine for this context (ADR-031, spec §5.9).
    engine: Box<dyn GovernanceEngine>,
    /// Proposal IDs that have already been executed, mapped to the unix
    /// timestamp (seconds) when they were marked executed. Prevents replay of
    /// approved governance proposals (defense-in-depth). Entries older than
    /// [`EXECUTED_PROPOSALS_TTL_SECS`] are evicted on each insert.
    executed_proposals: HashMap<ProposalId, u64>,
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
    approved_proposals: HashMap<ProposalId, (GovernanceProposal, u64, u64)>,
    /// Monotonic counter for assigning proposal sequence numbers (H10, ADR-031 §7).
    ///
    /// Incremented every time `detect_and_handle_conflicts` inserts a new
    /// approved proposal. Persisted in [`ContextSnapshot::next_proposal_seq`]
    /// so two proposals can never share a sequence number even across
    /// process restarts. On `import_context` (untrusted), reset
    /// conservatively to `approved_proposals.len() as u64` — see
    /// `lifecycle::import_context`.
    next_proposal_seq: u64,
    /// Governance freeze state due to simultaneous conflicts (ADR-031 §7).
    /// Contains the conflicting proposal IDs and freeze start timestamp.
    freeze: Option<(ProposalId, ProposalId, u64)>,
    /// Governance timeout task (SCP-271, ADR-031 §5).
    timeout_task: GovernanceTimeoutTask,
    /// Per-context deadlock detection tracking (ADR-031 §10).
    deadlock: DeadlockDetectionState,
    /// Governance threshold signers (for `ThresholdApproval` model).
    threshold_signers: Vec<DID>,
    /// Governance threshold value (quorum requirement).
    threshold_value: u32,
    /// Pending ceiling modification awaiting notification period (M7, §5.3.2).
    pending_ceiling_modification: Option<PendingCeilingModification>,
    /// Pending economic policy change awaiting notification period (§19.3).
    pending_economic_policy_change: Option<PendingEconomicPolicyChange>,
    /// Dynamically registered tools (beyond initial `ContextParams.tools`).
    registered_tools: Vec<ToolRegistration>,
    /// Established cross-context tool interfaces (§6.2).
    tool_interfaces: Vec<ToolInterface>,
    /// Pruning policy override (ADR-030 §6).
    pruning_policy: Option<PruningPolicy>,
    /// Mutable economic policy (§19.3, ADR-033).
    economic_policy: Option<EconomicPolicy>,
    /// Per-member cumulative budget tracker for governance-approved spending
    /// (§19.5, ADR-033). Grants are recorded via `ApproveSpend` governance
    /// actions and tracked here. Persisted in [`ContextSnapshot`].
    budget_tracker: MemberBudgetTracker,
    /// Last known member set for departure detection in the timeout loop.
    /// Compared each tick to the current member set to identify departures.
    last_known_members: HashSet<DID>,
    /// Members who have undergone a governance-triggered epoch reset
    /// (`ResetMember`, ADR-029 Tier 3) since the last timeout tick.
    /// Drained each tick and passed to `process_pending_proposals` so
    /// their votes on pending proposals are invalidated (ADR-031 §5).
    pending_epoch_resets: Vec<DID>,
    /// Consequence rules declared at context creation (ADR-017, #1531).
    consequence_rules: Vec<ConsequenceRule>,
    /// Sender velocity tracker for anti-spam and consequence evaluation (§19.7, #1537).
    velocity_tracker: scp_protocol::economy::antispam::SenderVelocityTracker,
    /// Per-member participation record cache for proposer eligibility (#1530).
    participation_cache: HashMap<String, scp_protocol::trust::participation::ParticipationRecord>,
    /// Cooldown tracking for consequence rules: maps `rule_index` to the Unix
    /// timestamp (seconds) until which the rule should not re-fire. Prevents
    /// repeated consequence dispatch within a rule's evaluation window.
    cooldown_until: HashMap<usize, u64>,
    /// Spec §19.7 per-DID escalating-cost message pricing configuration.
    ///
    /// Bundles base cost, escalation tiers, and floor/cap clamps. The
    /// hard rate limit (Matrix-style token bucket, defense-in-depth)
    /// is configured separately via `hard_rate_limit` below.
    message_pricing: Option<scp_protocol::economy::antispam::ContextMessagePricingConfig>,
    /// Defense-in-depth Matrix-style token bucket hard rate limiter.
    ///
    /// Layered on top of the per-DID economic escalation in spec §19.7. This
    /// is enforced even when `economic_policy` is `None`. See ADR notes on
    /// the dormant anti-spam wiring fix.
    hard_rate_limit: scp_protocol::economy::antispam::TokenBucketLimiter,
    /// Per-context nonce tracker for spending UCAN replay prevention (ADR-016 §6).
    /// Validates that each spending UCAN nonce is used at most once, preventing
    /// replay attacks where a valid spending UCAN is resubmitted.
    spending_nonce_tracker: scp_protocol::crypto::ucan::nonce::NonceTracker<Arc<dyn Clock>>,
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
    revoked_spending_ucan_cids: HashSet<String>,
    /// Per-member governance proposal timestamps for earned capacity rate limiting
    /// (§9.3). Maps member DID string to a list of Unix timestamps (seconds) when
    /// the member submitted governance proposals. Used by `check_proposer_eligibility` to
    /// enforce `max_governance_proposals_per_window` from `EarnedCapacityPolicy`.
    /// Entries outside the sliding window are evicted on each check.
    proposal_timestamps: HashMap<String, Vec<u64>>,
}

impl GovernanceState {
    /// Clears participation cache, cooldown state, and velocity tracker.
    ///
    /// Called on context close so stale participation records and cooldown
    /// timers don't carry over if the context is re-created (#1530).
    fn decay_participation(&mut self) {
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
    fn evict_stale_entries(&mut self, now: u64) {
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
struct EpochState {
    /// Monotonic MLS epoch counter. Incremented each time a governance action
    /// triggers an MLS membership change (`AddMember`, `RemoveMember`,
    /// `Revoke`, `ResetMember`). Used to populate
    /// `GovernanceActionExecuted.resulting_epoch` and
    /// `GovernanceContext.current_epoch`.
    mls_epoch: u64,
    /// MLS-governance epoch coordinator (ADR-031 §8, issue #630).
    ///
    /// Records the auditable link between governance proposal approvals and
    /// resulting MLS epoch advances. Instantiated per context and updated
    /// after each membership-affecting governance action execution.
    coordinator: EpochCoordinator,
    /// Epoch grace window store (§23.11).
    ///
    /// Tracks which old epochs are still within their grace window after
    /// epoch advances. Persisted alongside the context snapshot and restored
    /// on startup. Used by the MLS decrypt path to determine whether to
    /// attempt decryption for a given past epoch.
    grace_store: crate::crypto::mls::epoch_grace::EpochGraceStore,
    /// Whether this context needs to re-enter the reconnection protocol
    /// (§23.3) before processing new messages (§23.11 inconsistent state
    /// fallback step 3). Set during `restore_context` when grace store
    /// inconsistency is detected. Cleared when the reconnection protocol
    /// completes successfully. The SDK MUST check this flag when message
    /// processing begins for this context and initiate the reconnection
    /// protocol if set.
    needs_reconnect: bool,
}

/// Access control state (CEK wrapping, key store).
///
/// Capability suspension is now handled by `ContextRoleState::suspended_capabilities`.
/// This struct retains the CEK exclusion list and per-member access key store.
struct AccessControlState {
    /// Members excluded from future CEK wrapping (`Revoke { access: AccessScope::Write }`,
    /// ADR-038, §9.17). This is a cryptographic exclusion list, NOT an
    /// application-level capability suspension.
    read_exclusion_list: HashSet<DID>,
    /// Per-member access key store for content encryption key wrapping
    /// (ADR-038, §9.17). Keys are generated when members join and used
    /// by `wrap_content`/`unwrap_content` in the message pipeline.
    access_key_store: scp_protocol::crypto::access_keys::AccessKeyStore,
}

/// TTL timer and extension state.
struct TtlState {
    /// TTL timer management (SCP-021).
    timer: TtlTimer,
    /// Active TTL extension proposal, if any (SCP-021).
    extension: Option<TtlExtension>,
}

/// Internal state tracked by the manager for each context.
pub(super) struct PerContextState {
    /// Monotonic generation counter. Assigned on insertion into the contexts
    /// map. Used by Phase 3 re-checks to detect the confused-deputy scenario
    /// where a context was removed and recreated between lock release and
    /// reacquire (same `context_id`, different state).
    generation: u64,
    /// The context handle (retained for state checks and lifecycle operations).
    handle: ContextHandle,
    /// Member tracking.
    membership: MembershipState,
    /// Role state (ceiling, role definitions, assignments).
    role_state: ContextRoleState,
    /// Receive event buffer.
    receive_buffer: ReceiveBuffer,
    /// Broadcast context state (SCP-227). `Some` for `ContextMode::Broadcast`,
    /// `None` for `ContextMode::Encrypted`. Broadcast contexts do not use MLS;
    /// they use per-author AES-256-GCM keys managed by [`BroadcastContext`].
    broadcast_context: Option<BroadcastContext>,
    /// Active migration state (§5.11A). `Some` when the context is in
    /// `MigratingOut` state. `None` otherwise.
    migration_state: Option<MigrationState>,
    /// Governance-related state (ADR-031).
    governance: GovernanceState,
    /// MLS epoch and reconnection state.
    epoch: EpochState,
    /// Write/read revocation state.
    access: AccessControlState,
    /// TTL timer and extension state (SCP-021).
    ttl: TtlState,
    /// Per-sender sequence tracker for anti-replay protection (§9.8.2).
    /// Validates that per-sender sequence numbers and timestamps are
    /// monotonically increasing within this context.
    sequence_tracker: scp_protocol::envelope::SequenceTracker,
    /// Per-sender reorder buffer for out-of-order message delivery (§9.8.5).
    /// Buffers messages arriving ahead of their expected sequence number and
    /// delivers them when the gap fills or a 30-second timeout expires.
    reorder_buffer: scp_protocol::envelope::ReorderBuffer,
    /// Persistent retry queue for MLS Commit broadcasts that failed at the
    /// transport layer after the local state mutation already happened
    /// (PR #1606 C6). Drained by the governance timeout task.
    pending_commits: VecDeque<PendingCommit>,
    /// Fail-close marker set when a `PendingCommit` exhausts its retry
    /// budget. While `Some`, all context-mutating operations return
    /// [`ContextError::CommitBroadcastFault`] until cleared via
    /// [`ContextManager::acknowledge_commit_fault`].
    commit_fault: Option<CommitFaultMarker>,
    /// Number of event log appends since the last consistency checkpoint (§9.9.3).
    checkpoint_events_since: u64,
    /// Unix timestamp (seconds) of the last consistency checkpoint (§9.9.3).
    checkpoint_last_time_secs: u64,
    /// Locally generated consistency checkpoints for equivocation detection (§9.9.3).
    checkpoints: Vec<scp_event_log::checkpoint::ConsistencyCheckpoint>,
    /// RFC 6962 Merkle tree event log for inclusion/consistency proofs (ADR-011).
    /// Parallel to the `MerkleEventLogProvider` — both receive the same events.
    /// This log enables O(log n) Merkle proofs via `scp_event_log::proof` functions.
    ///
    /// Not persisted in `ContextSnapshot` — the tree is rebuilt from the
    /// `MerkleEventLogProvider`'s entries on `restore_context` / `import_context`.
    merkle_tree: scp_event_log::EventLog,
}

/// Helper type for generation tokens captured during Phase 1 lock acquisition.
///
/// Captures the `context_id` and the `generation` counter at the time the
/// per-context lock was first acquired. Passed to [`ContextManager::relock_context`]
/// to verify the context was not removed and recreated between lock release
/// and reacquire (confused-deputy detection, Phase B).
#[must_use]
pub(super) struct ContextGeneration {
    pub context_id: String,
    pub generation: u64,
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
fn create_governance_engine(
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
fn restore_grace_store_from_snapshot(
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
fn restore_governance_engine_from_snapshot(
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
fn validate_governance_model(model: &GovernanceModel) -> Result<(), ContextCreationError> {
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
fn require_active(handle: &ContextHandle) -> Result<(), ContextError> {
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
fn require_migrating_out(handle: &ContextHandle) -> Result<(), ContextError> {
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

// ---------------------------------------------------------------------------
// Governance engine construction helpers (SCP-267, ADR-031)
// ---------------------------------------------------------------------------

/// Validates that a [`GovernanceModel`] variant is consistent with a
/// [`GovernanceModelConfig`] variant. Returns a creation error on mismatch.
fn validate_governance_consistency(
    model: &GovernanceModel,
    config: &GovernanceModelConfig,
) -> Result<(), ContextCreationError> {
    let consistent = matches!(
        (model, config),
        (
            GovernanceModel::SingleAdmin,
            GovernanceModelConfig::SingleAdmin { .. }
        ) | (
            GovernanceModel::Threshold { .. },
            GovernanceModelConfig::Threshold { .. }
        ) | (
            GovernanceModel::Majority { .. },
            GovernanceModelConfig::Majority { .. }
        ) | (
            GovernanceModel::Unanimity { .. },
            GovernanceModelConfig::Unanimity { .. }
        )
    );
    if !consistent {
        return Err(ContextCreationError::CreationFailed(format!(
            "GovernanceModel::{model:?} does not match GovernanceModelConfig variant"
        )));
    }
    Ok(())
}

/// Constructs a boxed [`GovernanceEngine`] from a [`GovernanceModelConfig`].
///
/// For `Majority` and `Unanimity` models, `initial_voters` provides the
/// initial eligible voter set (typically the context creator at creation
/// time). For `SingleAdmin` and `Threshold`, voters are embedded in the
/// config itself. The voter set is updated by the `ContextManager` when
/// members join/leave.
///
/// Validates configuration parameters (threshold bounds, empty signers,
/// `min_participation_bps` range) and returns a creation error on invalid input.
fn build_governance_engine(
    config: GovernanceModelConfig,
    initial_voters: Vec<DID>,
    key_resolver: KeyResolver,
) -> Result<Box<dyn GovernanceEngine>, ContextCreationError> {
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
                .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
            Ok(Box::new(engine))
        }
        GovernanceModelConfig::Majority {
            voting_window_secs,
            min_participation_bps,
        } => {
            let engine = MajorityVoteEngine::new(
                initial_voters,
                voting_window_secs,
                min_participation_bps,
                key_resolver,
            )
            .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
            Ok(Box::new(engine))
        }
        GovernanceModelConfig::Unanimity { voting_window_secs } => {
            let engine = UnanimityEngine::new(initial_voters, voting_window_secs, key_resolver)
                .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
            Ok(Box::new(engine))
        }
    }
}

/// Mints `GovernancePropose` and `GovernanceVote` UCAN tokens for each
/// designated voter in the governance engine (ADR-031 §6).
///
/// For `SingleAdmin`, the admin already receives these via the admin role.
/// For multi-party models, each signer/voter receives both capabilities.
///
/// Returns the minted tokens. The tokens are also stored in the context's
/// role state by the caller.
fn mint_governance_tokens(
    context_id: &str,
    creator_did: &DID,
    engine: &dyn GovernanceEngine,
    clock: &dyn Clock,
) -> Vec<scp_protocol::context::roles::UcanToken> {
    use scp_protocol::context::roles::{Capability, UcanAttestation, UcanToken};

    let config = engine.model_config();
    let voter_dids: Vec<DID> = match &config {
        GovernanceModelConfig::SingleAdmin { admin_did } => vec![admin_did.clone()],
        GovernanceModelConfig::Threshold { signers, .. } => signers.clone(),
        GovernanceModelConfig::Majority { .. } | GovernanceModelConfig::Unanimity { .. } => {
            // For Majority/Unanimity, voters are "all members with GovernanceVote
            // capability." At creation time, the creator is the only member.
            vec![creator_did.clone()]
        }
    };

    let capabilities = [Capability::GovernancePropose, Capability::GovernanceVote];
    let mut tokens = Vec::with_capacity(voter_dids.len() * capabilities.len());

    for voter in &voter_dids {
        for cap in &capabilities {
            let att = UcanAttestation {
                with: format!("scp:ctx:{context_id}/{cap}"),
                can: "invoke".to_owned(),
            };
            // Nonce generation: if the clock is unavailable, fall back to a
            // static nonce (acceptable for governance tokens minted at creation
            // time — replay prevention is handled by the engine's proposal-ID
            // scheme).
            let nonce = scp_protocol::crypto::ucan::nonce::generate_nonce(clock);
            tokens.push(UcanToken {
                iss: creator_did.to_string(),
                aud: voter.to_string(),
                att: vec![att],
                nnc: nonce,
            });
        }
    }

    tokens
}

// ---------------------------------------------------------------------------
// ContextManagerBuilder
// ---------------------------------------------------------------------------

/// Step-by-step builder for [`ContextManager`].
///
/// Provides a more ergonomic API than the raw constructors. Required
/// providers can be set individually, or use [`.storage()`](Self::storage)
/// to auto-wire persistence and event log from a single `EncryptedStorage` impl.
///
/// # Required
///
/// * `crypto` — always required (no sensible default for MLS operations).
///
/// # Optional with defaults
///
/// * `transport` — defaults to [`LocalTransportProvider`](super::builder::LocalTransportProvider) (all ops succeed).
/// * `event_log` — defaults to [`MerkleEventLogProvider::new()`](super::providers::MerkleEventLogProvider::new) (in-memory).
/// * `persistence` — defaults to `None` (no crash recovery).
/// * `key_resolver` — defaults to a no-op resolver that returns `None`.
///
/// # `.storage()` convenience
///
/// Calling `.storage(my_storage)` auto-constructs:
/// 1. A `ProtocolRepository<S>` wrapping the storage.
/// 2. A `ProtocolRepositoryContextBridge<S>` for context persistence.
/// 3. A `ProtocolRepositoryEventLogBridge<S>` for event log persistence.
/// 4. A `MerkleEventLogProvider` backed by that persistence.
///
/// This replaces ~8 lines of manual wiring with a single call.
pub struct ContextManagerBuilder {
    crypto: Option<Box<dyn ContextCryptoProvider>>,
    transport: Option<Box<dyn ContextTransportProvider>>,
    event_log: Option<Box<dyn ContextEventLogProvider>>,
    persistence: Option<Box<dyn ContextPersistence>>,
    key_resolver: Option<KeyResolver>,
    clock: Option<Arc<dyn Clock>>,
    payment_adapter: Option<Arc<dyn crate::economy::adapter::PaymentAdapterDyn>>,
}

impl ContextManagerBuilder {
    /// Creates a new builder with all fields unset.
    #[must_use]
    fn new() -> Self {
        Self {
            crypto: None,
            transport: None,
            event_log: None,
            persistence: None,
            key_resolver: None,
            clock: None,
            payment_adapter: None,
        }
    }

    /// Sets the crypto provider (required).
    #[must_use]
    pub fn crypto(mut self, crypto: Box<dyn ContextCryptoProvider>) -> Self {
        self.crypto = Some(crypto);
        self
    }

    /// Sets the transport provider.
    ///
    /// If not called, defaults to [`LocalTransportProvider`](super::builder::LocalTransportProvider).
    #[must_use]
    pub fn transport(mut self, transport: Box<dyn ContextTransportProvider>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Sets the event log provider.
    ///
    /// If not called (and `.storage()` is not used), defaults to
    /// [`MerkleEventLogProvider::new()`](super::providers::MerkleEventLogProvider::new) (in-memory, no persistence).
    #[must_use]
    pub fn event_log(mut self, event_log: Box<dyn ContextEventLogProvider>) -> Self {
        self.event_log = Some(event_log);
        self
    }

    /// Sets the context persistence provider.
    ///
    /// If not called, no persistence is configured (in-memory only).
    #[must_use]
    pub fn persistence(mut self, persistence: Box<dyn ContextPersistence>) -> Self {
        self.persistence = Some(persistence);
        self
    }

    /// Sets the key resolver for governance vote verification.
    ///
    /// If not called, defaults to a no-op resolver that returns `None`
    /// for all DIDs (governance voting will not verify signatures).
    #[must_use]
    pub fn key_resolver(mut self, key_resolver: KeyResolver) -> Self {
        self.key_resolver = Some(key_resolver);
        self
    }

    /// Sets the clock for time-dependent operations.
    ///
    /// If not called, defaults to [`scp_primitives::SystemClock`].
    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Sets the payment adapter for the 9-step paid action flow (spec §19.2.2).
    ///
    /// If not called, paid action entry points skip the payment rail
    /// integration while still enforcing budget tracking.
    #[must_use]
    pub fn payment_adapter(
        mut self,
        adapter: Arc<dyn crate::economy::adapter::PaymentAdapterDyn>,
    ) -> Self {
        self.payment_adapter = Some(adapter);
        self
    }

    /// Auto-wires persistence and event log from a single `EncryptedStorage` impl.
    ///
    /// Constructs a [`ProtocolRepository`](crate::store::ProtocolRepository), then
    /// creates both the context persistence bridge and event log persistence
    /// bridge, plus a [`MerkleEventLogProvider`](super::providers::MerkleEventLogProvider)
    /// backed by that persistence. This replaces ~8 lines of manual wiring.
    ///
    /// Calling this overwrites any previously set `persistence` and `event_log`.
    #[must_use]
    pub fn storage<S: scp_platform::EncryptedStorage + 'static>(mut self, storage: S) -> Self {
        let store = std::sync::Arc::new(crate::store::ProtocolRepository::new(storage));
        let persistence = Box::new(crate::store::context::ProtocolRepositoryContextBridge::new(
            store.clone(),
        ));
        let event_log_persistence =
            crate::store::context::ProtocolRepositoryEventLogBridge::new(store);
        let event_log = Box::new(super::providers::MerkleEventLogProvider::with_persistence(
            std::sync::Arc::new(event_log_persistence),
        ));
        self.persistence = Some(persistence);
        self.event_log = Some(event_log);
        self
    }

    /// Builds the [`ContextManager`].
    ///
    /// # Errors
    ///
    /// Returns an error if the `crypto` provider was not set (the only
    /// required field).
    pub fn build(self) -> Result<ContextManager, ContextManagerBuildError> {
        let crypto = self.crypto.ok_or(ContextManagerBuildError::MissingCrypto)?;

        let transport: Box<dyn ContextTransportProvider> = self
            .transport
            .unwrap_or_else(|| Box::new(super::builder::LocalTransportProvider));

        let event_log: Box<dyn ContextEventLogProvider> = self
            .event_log
            .unwrap_or_else(|| Box::new(super::providers::MerkleEventLogProvider::new()));

        let key_resolver = self
            .key_resolver
            .unwrap_or_else(|| Arc::new(|_: &DID| None));

        let clock = self
            .clock
            .unwrap_or_else(|| Arc::new(scp_primitives::SystemClock));

        let mut manager = match self.persistence {
            Some(persistence) => ContextManager::with_persistence(
                crypto,
                transport,
                event_log,
                persistence,
                key_resolver,
            ),
            None => ContextManager::new(crypto, transport, event_log, key_resolver),
        };
        manager.clock = clock;
        manager.payment_adapter = self.payment_adapter;
        Ok(manager)
    }
}

/// Error returned when [`ContextManagerBuilder::build`] fails.
#[derive(Debug, thiserror::Error)]
pub enum ContextManagerBuildError {
    /// The `crypto` provider is required but was not set.
    #[error("crypto provider is required — call .crypto() before .build()")]
    MissingCrypto,
}

// ---------------------------------------------------------------------------
// ContextManager
// ---------------------------------------------------------------------------

/// Central coordinator for SCP context lifecycle operations.
///
/// `ContextManager` holds the injected providers for crypto, transport, and
/// event log operations and exposes the public API for context creation,
/// membership (join/leave), and messaging (send).
///
/// # Thread Safety
///
/// `ContextManager` is `Send + Sync` when all providers are `Send + Sync`
/// (which is enforced by the trait bounds). It is safe to share across
/// threads and async tasks. Per-context state is protected by a
/// `tokio::sync::Mutex` which does not poison on panic.
///
/// # Examples
///
/// ```ignore
/// let manager = ContextManager::new(crypto, transport, event_log, key_resolver);
/// let handle = manager.create_context("ctx-1".into(), params, "did:key:creator".into()).await?;
/// assert_eq!(handle.state().await, ContextState::Active);
/// ```
pub struct ContextManager {
    /// Provider for MLS group and sender key operations.
    ///
    /// Stored as `Arc` (not `Box`) so the provider can be shared with
    /// spawned TTL timer tasks that need crypto access for key destruction
    /// on context expiry (SCP-169).
    crypto: Arc<dyn ContextCryptoProvider>,
    /// Provider for relay connectivity and publication.
    transport: Arc<dyn ContextTransportProvider>,
    /// Provider for event log initialisation and append.
    ///
    /// Stored as `Arc` (not `Box`) so the provider can be shared with
    /// spawned TTL timer tasks that need event log access for logging
    /// `ContextExpired` events on context expiry (SCP-169).
    event_log: Arc<dyn ContextEventLogProvider>,
    /// Optional provider for persisting full context and broadcast state
    /// across process restarts. When `Some`, the manager persists context
    /// state after every mutating operation (best-effort).
    persistence: Option<Arc<dyn ContextPersistence>>,
    /// DIDs controlled by the local node/SDK.
    ///
    /// Used for defense-in-depth validation in
    /// [`handle_broadcast_key_request`](Self::handle_broadcast_key_request):
    /// the method verifies the `author_did` is locally controlled before
    /// processing the request. While transport-layer auth (spec section
    /// 9.16.6) is the primary enforcement mechanism, this check prevents
    /// misuse if the method is called from an unexpected context.
    ///
    /// Populated via [`register_local_did`](Self::register_local_did).
    /// Uses `RwLock` because reads (validation checks) are frequent and
    /// writes (DID registration) are rare.
    local_dids: RwLock<HashSet<DID>>,
    /// Per-context state, keyed by `context_id` string.
    ///
    /// Each context has its own `tokio::sync::Mutex` so operations on
    /// different contexts never serialize against each other (`DashMap`
    /// shard locks are released immediately after cloning the `Arc`).
    ///
    /// Wrapped in `Arc` so spawned background tasks (TTL expiry, governance
    /// timeout) can clone the outer `Arc<DashMap>` and access contexts by ID
    /// without holding a reference to the entire `ContextManager`.
    contexts: Arc<DashMap<String, Arc<Mutex<PerContextState>>>>,
    /// Resolver that maps a DID to its Ed25519 verifying key for governance
    /// vote signature verification (spec §5.9, ADR-031). Passed through to
    /// governance engines at creation and restoration time.
    key_resolver: KeyResolver,
    /// Clock for time-dependent operations.
    ///
    /// Injected via constructors / builder to allow test clock injection.
    /// Defaults to [`scp_primitives::SystemClock`].
    clock: Arc<dyn Clock>,
    /// Standing bilateral contexts indexed by peer DID string (contact graph).
    ///
    /// Maps peer DID string to the peer's [`DID`]. The context ID is derived
    /// deterministically via [`standing::generate_standing_context_id`], and
    /// the context handle lives in [`Self::contexts`]. This map tracks which
    /// peers have standing contexts without duplicating handle storage.
    standing_contexts: Mutex<HashMap<String, DID>>,
    /// Optional payment adapter for the 9-step paid action flow (spec §19.2.2).
    ///
    /// When `Some`, `authorize_paid_action`→`complete_paid_action` runs the
    /// full escrow flow via this adapter. When `None`, paid action entry
    /// points skip payment (free context) while still enforcing budget
    /// tracking via `evaluate_cost` and `record_spend`.
    ///
    /// Set via [`set_payment_adapter`](Self::set_payment_adapter) or the builder.
    payment_adapter: Option<Arc<dyn crate::economy::adapter::PaymentAdapterDyn>>,
    /// Shared task set for TTL timers and governance timeout tasks.
    ///
    /// Background tasks spawned by [`spawn_ttl_timer`](Self::spawn_ttl_timer) and
    /// [`start_governance_timeout_task`](Self::start_governance_timeout_task) are
    /// added to this `JoinSet`. When the `ContextManager` is dropped, all tasks
    /// in the set are automatically cancelled, providing structured lifecycle
    /// management. Prerequisite for Phase B (`DashMap` per-context locking).
    ///
    /// Wrapped in `Arc<Mutex<_>>` because `JoinSet` requires `&mut self` for
    /// `spawn` and is not `Sync`.
    task_set: Arc<tokio::sync::Mutex<tokio::task::JoinSet<()>>>,
    /// Global monotonic counter for assigning generation IDs to contexts.
    ///
    /// Starts at 1 so that generation 0 (the `#[serde(default)]` value for
    /// legacy snapshots) is never actively assigned. Incremented with
    /// `Relaxed` ordering — uniqueness is guaranteed by the `fetch_add`
    /// atomicity, and no other memory accesses depend on the ordering.
    next_generation: std::sync::atomic::AtomicU64,
    /// Optional broadcast channel for notifying external consumers of context
    /// events (e.g., webhook dispatchers in scp-node). When `Some`, every event
    /// pushed to a per-context `ReceiveBuffer` is also sent on this channel as
    /// `(context_id, ContextEvent)`. Lagging receivers lose events (bounded
    /// channel) — this is acceptable because webhook delivery is best-effort.
    ///
    /// Created via [`with_event_channel`](Self::with_event_channel).
    event_tx: Option<tokio::sync::broadcast::Sender<(String, ContextEvent)>>,
}

// Nursery lint — false-positives on async functions holding tokio::sync::MutexGuard
// across block boundaries. The lock-snapshot-persist pattern is intentional.
#[allow(clippy::significant_drop_tightening)]
impl ContextManager {
    /// Creates a new `ContextManager` with the given providers.
    ///
    /// All providers are boxed trait objects, allowing any implementation
    /// to be injected (production implementations, test mocks, etc.).
    ///
    /// # Arguments
    ///
    /// * `crypto` -- Provider for MLS and sender key operations.
    /// * `transport` -- Provider for relay connectivity and publication.
    /// * `event_log` -- Provider for event log initialisation and append.
    /// * `key_resolver` -- Resolver for DID-to-Ed25519 key mapping (governance vote verification).
    #[must_use]
    pub fn new(
        crypto: Box<dyn ContextCryptoProvider>,
        transport: Box<dyn ContextTransportProvider>,
        event_log: Box<dyn ContextEventLogProvider>,
        key_resolver: KeyResolver,
    ) -> Self {
        Self {
            crypto: Arc::from(crypto),
            transport: Arc::from(transport),
            event_log: Arc::from(event_log),
            persistence: None,
            local_dids: RwLock::new(HashSet::new()),
            contexts: Arc::new(DashMap::new()),
            key_resolver,
            clock: Arc::new(scp_primitives::SystemClock),
            standing_contexts: Mutex::new(HashMap::new()),
            payment_adapter: None,
            task_set: Arc::new(tokio::sync::Mutex::new(tokio::task::JoinSet::new())),
            next_generation: std::sync::atomic::AtomicU64::new(1),
            event_tx: None,
        }
    }

    /// Creates a new `ContextManager` with persistence support.
    ///
    /// Same as [`new`](Self::new) but additionally accepts a
    /// [`ContextPersistence`] provider. When provided, the manager
    /// persists full context and broadcast state after every mutating
    /// operation (best-effort: errors logged, not propagated).
    ///
    /// # Arguments
    ///
    /// * `crypto` -- Provider for MLS and sender key operations.
    /// * `transport` -- Provider for relay connectivity and publication.
    /// * `event_log` -- Provider for event log initialisation and append.
    /// * `persistence` -- Provider for context state persistence.
    /// * `key_resolver` -- Resolver for DID-to-Ed25519 key mapping (governance vote verification).
    #[must_use]
    pub fn with_persistence(
        crypto: Box<dyn ContextCryptoProvider>,
        transport: Box<dyn ContextTransportProvider>,
        event_log: Box<dyn ContextEventLogProvider>,
        persistence: Box<dyn ContextPersistence>,
        key_resolver: KeyResolver,
    ) -> Self {
        Self {
            crypto: Arc::from(crypto),
            transport: Arc::from(transport),
            event_log: Arc::from(event_log),
            persistence: Some(Arc::from(persistence)),
            local_dids: RwLock::new(HashSet::new()),
            contexts: Arc::new(DashMap::new()),
            key_resolver,
            clock: Arc::new(scp_primitives::SystemClock),
            standing_contexts: Mutex::new(HashMap::new()),
            payment_adapter: None,
            task_set: Arc::new(tokio::sync::Mutex::new(tokio::task::JoinSet::new())),
            next_generation: std::sync::atomic::AtomicU64::new(1),
            event_tx: None,
        }
    }

    /// Returns a [`ContextManagerBuilder`] for step-by-step assembly.
    ///
    /// The builder provides a more ergonomic API than the raw constructors,
    /// with optional defaults and a `.storage()` method that auto-wires
    /// persistence and event log bridges from a single `Storage` impl.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let manager = ContextManager::builder()
    ///     .crypto(Box::new(my_crypto))
    ///     .storage(my_storage)  // auto-wires persistence + event log
    ///     .build()?;
    /// ```
    #[must_use]
    pub fn builder() -> ContextManagerBuilder {
        ContextManagerBuilder::new()
    }

    /// Removes all registered contexts from the manager.
    ///
    /// This is a best-effort teardown: it clears the `DashMap` and cancels
    /// all background tasks (TTL timers, governance timeouts) associated
    /// with each context. MLS groups are destroyed via the crypto provider.
    ///
    /// Used by [`scp_ffi_common::BridgeInstance::shutdown`] to clean up
    /// context state during bridge lifecycle teardown.
    ///
    /// Does NOT send leave messages to relays or notify remote peers —
    /// this is a local cleanup operation for process exit / test teardown.
    pub fn shutdown_all_contexts(&self) {
        // Collect IDs first to avoid holding DashMap shard locks while
        // performing cleanup (which may acquire per-context mutexes).
        let context_ids: Vec<String> = self
            .contexts
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        for context_id in &context_ids {
            let ctx_id_bytes = context_id_to_bytes(context_id);

            // Destroy sender key BEFORE MLS group. The MLS crypto provider
            // stores both in the same internal HashMap entry — destroy_mls_group
            // removes the entry entirely, making a subsequent destroy_sender_key
            // a no-op (key not zeroized). Ordering: zeroize secrets first,
            // then tear down the group structure.
            if let Err(e) = self.crypto.destroy_sender_key(&ctx_id_bytes) {
                tracing::debug!(
                    context_id = %context_id,
                    error = %e,
                    "failed to destroy sender key during shutdown — may already be gone"
                );
            }
            if let Err(e) = self.crypto.destroy_mls_group(&ctx_id_bytes) {
                tracing::debug!(
                    context_id = %context_id,
                    error = %e,
                    "failed to destroy MLS group during shutdown — may already be gone"
                );
            }
            if let Err(e) = self.event_log.destroy_event_log(&ctx_id_bytes) {
                tracing::debug!(
                    context_id = %context_id,
                    error = %e,
                    "failed to destroy event log during shutdown — may already be gone"
                );
            }

            // Remove from the DashMap (drops the Arc, which may drop the
            // PerContextState if no other references exist).
            self.contexts.remove(context_id);
        }

        // Clear standing contexts tracking.
        if let Ok(mut standing) = self.standing_contexts.try_lock() {
            standing.clear();
        }

        // Abort all background tasks (TTL timers, governance timeouts).
        // Best-effort: if the mutex is contended, tasks will be cleaned
        // up when their contexts are dropped.
        if let Ok(mut tasks) = self.task_set.try_lock() {
            tasks.abort_all();
        }

        tracing::info!(
            removed_count = context_ids.len(),
            "shutdown: removed all contexts and aborted background tasks"
        );
    }

    // -----------------------------------------------------------------
    // Persistence flush (sync, best-effort)
    // -----------------------------------------------------------------

    /// Persists all currently-unlocked contexts as a best-effort snapshot flush.
    ///
    /// Iterates the context map and, for each context that can be locked
    /// without blocking (via [`Mutex::try_lock`]), takes a snapshot and calls
    /// [`ContextPersistence::persist_context`]. Contexts held by other tasks
    /// are silently skipped — this is deliberate; their in-progress mutations
    /// will be persisted by the normal per-operation persistence path.
    ///
    /// Intended for use by [`BridgeInstance::suspend`] and
    /// [`BridgeInstance::shutdown`] to flush state before transport is
    /// torn down or MLS groups are destroyed. Errors from individual
    /// contexts are logged and do not abort the flush.
    ///
    /// No-op if no persistence provider is configured.
    pub fn flush_all_contexts_sync(&self) {
        if !self.has_persistence() {
            return;
        }
        // Collect Arcs first to avoid holding DashMap shard locks.
        let arcs = self.collect_context_arcs();
        let mut flushed = 0usize;
        let mut skipped = 0usize;
        for (context_id, arc) in arcs {
            match arc.try_lock() {
                Ok(ctx) => {
                    let snapshot = Self::snapshot_context(&ctx);
                    let bc_snapshot = ctx
                        .broadcast_context
                        .as_ref()
                        .map(BroadcastContext::to_snapshot);
                    drop(ctx);
                    self.persist_context_snapshot(&context_id, snapshot);
                    if let Some(ref bcs) = bc_snapshot {
                        self.persist_broadcast_snapshot(&context_id, bcs);
                    }
                    flushed += 1;
                }
                Err(_) => {
                    // Context is locked by an in-progress operation — skip it.
                    // That operation's normal completion path will persist the
                    // final state.
                    skipped += 1;
                }
            }
        }
        tracing::debug!(
            flushed,
            skipped,
            "flush_all_contexts_sync: flushed {} context(s), skipped {} locked",
            flushed,
            skipped,
        );
    }

    /// Attaches a bounded broadcast channel for external event consumers.
    ///
    /// After calling this, every event pushed to a per-context
    /// `ReceiveBuffer` is also sent on the channel as
    /// `(context_id, ContextEvent)`. Lagging receivers lose events —
    /// this is acceptable because external consumers (e.g., webhook
    /// dispatchers) treat delivery as best-effort.
    ///
    /// Returns `&mut Self` for chaining.
    ///
    /// # Arguments
    ///
    /// * `capacity` — bounded channel capacity. `1024` is a sensible
    ///   default for most deployments.
    pub fn with_event_channel(&mut self, capacity: usize) -> &mut Self {
        let (tx, _rx) = tokio::sync::broadcast::channel(capacity);
        self.event_tx = Some(tx);
        self
    }

    /// Returns a new [`tokio::sync::broadcast::Receiver`] for the event
    /// channel, if one was configured via [`with_event_channel`](Self::with_event_channel).
    ///
    /// Each call returns an independent receiver. Multiple consumers
    /// (e.g., webhook dispatcher, metrics collector) can subscribe
    /// concurrently.
    #[must_use]
    pub fn subscribe_events(
        &self,
    ) -> Option<tokio::sync::broadcast::Receiver<(String, ContextEvent)>> {
        self.event_tx
            .as_ref()
            .map(tokio::sync::broadcast::Sender::subscribe)
    }

    /// Sends a context event on the broadcast channel if one is configured.
    ///
    /// This is an internal helper called after each `receive_buffer.push`
    /// in the submodules. `SendError` (no active receivers) is silently
    /// ignored — best-effort delivery.
    pub(super) fn fire_event(&self, context_id: &str, event: &ContextEvent) {
        if let Some(tx) = &self.event_tx {
            let _ = tx.send((context_id.to_owned(), event.clone()));
        }
    }

    // -----------------------------------------------------------------
    // Per-context lock helpers (DashMap → Arc<Mutex<PerContextState>>)
    // -----------------------------------------------------------------

    /// Acquires the per-context `Mutex`. Returns an owned guard (the
    /// `Arc` is cloned so the `DashMap` shard lock is released
    /// immediately) and a [`ContextGeneration`] token for later
    /// reacquire verification.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] if `context_id`
    /// is not in the map.
    pub(super) async fn lock_context(
        &self,
        context_id: &str,
    ) -> Result<
        (
            tokio::sync::OwnedMutexGuard<PerContextState>,
            ContextGeneration,
        ),
        ContextError,
    > {
        let arc = self.get_context_arc(context_id)?;
        let guard = arc.lock_owned().await;
        let token = ContextGeneration {
            context_id: context_id.to_owned(),
            generation: guard.generation,
        };
        Ok((guard, token))
    }

    /// Reacquires the per-context `Mutex` and verifies the generation
    /// counter matches `token`. Detects the confused-deputy scenario
    /// where the context was removed and recreated between lock release
    /// and reacquire (same `context_id`, different state).
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is gone.
    /// - [`ContextError::PermissionDenied`] if the generation changed.
    pub(super) async fn relock_context(
        &self,
        token: &ContextGeneration,
    ) -> Result<tokio::sync::OwnedMutexGuard<PerContextState>, ContextError> {
        let arc = self.get_context_arc(&token.context_id)?;
        let guard = arc.lock_owned().await;
        if guard.generation != token.generation {
            return Err(ContextError::PermissionDenied(format!(
                "context {} was removed and recreated (generation {} != {})",
                token.context_id, guard.generation, token.generation,
            )));
        }
        Ok(guard)
    }

    /// Clones the `Arc<Mutex<PerContextState>>` for a context without
    /// locking the per-context mutex. Used when the caller needs the
    /// `Arc` but will lock it later.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] if the context is
    /// not in the map.
    pub(super) fn get_context_arc(
        &self,
        context_id: &str,
    ) -> Result<Arc<Mutex<PerContextState>>, ContextError> {
        self.contexts
            .get(context_id)
            .map(|entry| Arc::clone(entry.value()))
            .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))
    }

    /// Insert a new context into the map. Returns an error if
    /// `context_id` is already registered.
    ///
    /// Assigns a monotonically increasing generation counter so that
    /// [`relock_context`](Self::relock_context) can detect remove-and-recreate
    /// races.
    #[allow(clippy::needless_pass_by_value)] // DashMap::entry takes ownership
    pub(super) fn insert_context(
        &self,
        context_id: String,
        mut state: PerContextState,
    ) -> Result<(), ContextCreationError> {
        use dashmap::mapref::entry::Entry;
        let generation = self
            .next_generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        state.generation = generation;
        match self.contexts.entry(context_id.clone()) {
            Entry::Occupied(_) => Err(ContextCreationError::CreationFailed(format!(
                "context '{context_id}' already registered"
            ))),
            Entry::Vacant(v) => {
                v.insert(Arc::new(Mutex::new(state)));
                Ok(())
            }
        }
    }

    /// Remove a context from the map, returning its state `Arc` if it existed.
    pub(super) fn remove_context(&self, context_id: &str) -> Option<Arc<Mutex<PerContextState>>> {
        self.contexts.remove(context_id).map(|(_, v)| v)
    }

    /// Check if a context is registered.
    #[allow(dead_code)] // Available for callers added as contexts migrate.
    pub(super) fn context_exists(&self, context_id: &str) -> bool {
        self.contexts.contains_key(context_id)
    }

    /// Number of registered contexts.
    pub(super) fn context_count(&self) -> usize {
        self.contexts.len()
    }

    /// Clone the `Arc<DashMap>` for use in spawned background tasks that
    /// outlive the borrow of `&self`.
    pub(super) fn contexts_arc(&self) -> Arc<DashMap<String, Arc<Mutex<PerContextState>>>> {
        Arc::clone(&self.contexts)
    }

    /// Collect all context `Arc`s. Releases `DashMap` shard locks immediately.
    ///
    /// Useful for iteration patterns that need to lock individual contexts
    /// without holding shard locks (metrics, reconnection scans).
    pub(super) fn collect_context_arcs(&self) -> Vec<(String, Arc<Mutex<PerContextState>>)> {
        self.contexts
            .iter()
            .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
            .collect()
    }

    /// Increment the checkpoint counter for a context. Best-effort: silently
    /// skips if the context is not found (e.g., removed concurrently).
    #[allow(dead_code)] // Available for callers added as contexts migrate.
    pub(super) async fn increment_checkpoint_counter(&self, context_id: &str) {
        if let Ok(arc) = self.get_context_arc(context_id) {
            let mut guard = arc.lock().await;
            guard.checkpoint_events_since += 1;
        }
    }

    /// Returns `true` if a persistence provider is configured.
    ///
    /// Use this to guard snapshot creation so that expensive deep-clones
    /// of `PerContextState` are skipped when no persistence provider
    /// exists (the common case for most bridges).
    #[inline]
    fn has_persistence(&self) -> bool {
        self.persistence.is_some()
    }

    /// Persists a context snapshot if a persistence provider is configured.
    ///
    /// Best-effort: logs errors but does not propagate them to callers.
    /// In-memory state is authoritative; persistence is for crash recovery.
    ///
    /// # Ordering note
    ///
    /// The snapshot is captured under the contexts mutex lock, but
    /// `persist` is called after the lock is released. A concurrent
    /// mutation could therefore persist a stale snapshot (the second
    /// mutation's snapshot would overwrite it shortly after). This is
    /// low probability and acceptable for v1 -- the worst case is a
    /// single extra key-epoch replay on restart, which the pull-based
    /// key distribution protocol already handles idempotently.
    /// Updates operational gauge metrics (active contexts, buffer occupancy).
    ///
    /// Called after mutations that change context count or buffer state.
    /// Takes the contexts lock, so callers must NOT hold it. Best-effort:
    /// if no metrics recorder is installed, these are no-ops (#1467).
    fn update_context_gauges(&self) {
        crate::metrics::set_active_contexts(self.context_count());
        // Collect Arcs first to release DashMap shard locks.
        let arcs = self.collect_context_arcs();
        let mut total_buffered: usize = 0;
        for (_id, arc) in arcs {
            // Use try_lock to avoid convoy effects: metrics are approximate,
            // so skipping locked contexts is acceptable.
            if let Ok(ctx) = arc.try_lock() {
                total_buffered += ctx.receive_buffer.len();
            }
        }
        crate::metrics::set_buffer_occupancy(total_buffered);
    }

    fn persist_context_snapshot(&self, context_id: &str, mut snapshot: ContextSnapshot) {
        if let Some(ref persistence) = self.persistence {
            // Export MLS crypto state alongside the context snapshot (#645).
            // Populate `mls_crypto_state` in-place on the owned snapshot (#711).
            // Best-effort: if export fails, persist without crypto state (the
            // context will need reconnection on restore, matching §23.11 fallback).
            let ctx_id_bytes = context_id_to_bytes(context_id);
            match self.crypto.export_crypto_state(&ctx_id_bytes) {
                Ok(state) => snapshot.mls_crypto_state = state,
                Err(e) => {
                    tracing::warn!(
                        context_id = %context_id,
                        error = %e,
                        "failed to export MLS crypto state for persistence; \
                         context will need reconnection on restore"
                    );
                }
            }
            if let Err(e) = persistence.persist_context(context_id, &snapshot) {
                // Best-effort persistence: log but don't fail the operation.
                // In-memory state remains authoritative.
                crate::metrics::record_persistence_failure();
                tracing::warn!(
                    context_id = %context_id,
                    error = %e,
                    "failed to persist context snapshot"
                );
            }
        }
    }

    /// Persists a broadcast context snapshot if a persistence provider is
    /// configured. Best-effort: logs errors but does not propagate.
    fn persist_broadcast_snapshot(&self, context_id: &str, snapshot: &BroadcastContextSnapshot) {
        if let Some(ref persistence) = self.persistence
            && let Err(e) = persistence.persist_broadcast(context_id, snapshot)
        {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to persist broadcast snapshot"
            );
        }
    }

    /// Initializes a `BroadcastContext` if the context is in Broadcast mode
    /// (SCP-227). Derives admission policy from `template_id` and registers
    /// the creator as the first author. Persists the initial broadcast state
    /// for crash recovery.
    fn init_broadcast_context(
        &self,
        context_id: &str,
        params: &ContextParams,
        creator_did: &DID,
    ) -> Result<Option<BroadcastContext>, ContextCreationError> {
        if params.mode != ContextMode::Broadcast {
            return Ok(None);
        }
        let admission = match params.template_id {
            Some(TemplateId::GatedBroadcast) => BroadcastAdmission::Gated,
            Some(TemplateId::PublicBroadcast | TemplateId::PaidBroadcast) => {
                BroadcastAdmission::Open
            }
            _ => BroadcastAdmission::Open,
        };
        let mut bc = BroadcastContext::new(context_id.to_owned(), &params.mode, admission)
            .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
        // Register the creator as the first author (messagesWrite).
        bc.add_author(creator_did)
            .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
        // Persist initial broadcast state for crash recovery.
        if self.has_persistence() {
            self.persist_broadcast_snapshot(context_id, &bc.to_snapshot());
        }
        Ok(Some(bc))
    }

    /// Persists context and broadcast state if a persistence provider is configured.
    async fn persist_context_and_broadcast(&self, context_id: &str) {
        if self.has_persistence()
            && let Ok(arc) = self.get_context_arc(context_id)
        {
            let ctx = arc.lock().await;
            let snapshot = Self::snapshot_context(&ctx);
            let bc_snapshot = ctx
                .broadcast_context
                .as_ref()
                .map(BroadcastContext::to_snapshot);
            drop(ctx);
            self.persist_context_snapshot(context_id, snapshot);
            if let Some(ref bcs) = bc_snapshot {
                self.persist_broadcast_snapshot(context_id, bcs);
            }
        }
    }

    /// Takes a `ContextSnapshot` from the current `PerContextState`.
    ///
    /// Must be called while the contexts mutex is held (snapshot under lock).
    fn snapshot_context(ctx: &PerContextState) -> ContextSnapshot {
        let state = ctx.handle.try_read_state().unwrap_or(ContextState::Active);
        let ttl_remaining_secs = ctx.ttl.timer.remaining_secs();
        // Capture grace entries for transactional persistence (§23.11).
        // On clock error, persist an empty vec — the recovery path will
        // treat the missing entries as expired (conservative: forward secrecy
        // prioritized over message recovery, per §23.11 inconsistent state
        // fallback).
        let grace_entries = ctx.epoch.grace_store.to_grace_entries();
        ContextSnapshot {
            context_id: ctx.handle.context_id().to_owned(),
            state,
            context_params: ctx.handle.params().clone(),
            membership: ctx.membership.clone(),
            role_state: ctx.role_state.clone(),
            executed_proposals: ctx.governance.executed_proposals.keys().copied().collect(),
            ttl_remaining_secs,
            registered_tools: ctx.governance.registered_tools.clone(),
            read_exclusion_list: ctx.access.read_exclusion_list.clone(),
            tool_interfaces: ctx.governance.tool_interfaces.clone(),
            threshold_signers: ctx.governance.threshold_signers.clone(),
            threshold_value: ctx.governance.threshold_value,
            pruning_policy: ctx.governance.pruning_policy.clone(),
            governance_model_config: Some(ctx.governance.engine.model_config()),
            economic_policy: ctx.governance.economic_policy.clone(),
            budget_tracker: ctx.governance.budget_tracker.clone(),
            approved_proposals: ctx.governance.approved_proposals.clone(),
            next_proposal_seq: ctx.governance.next_proposal_seq,
            governance_freeze: ctx.governance.freeze,
            pending_ceiling_modification: ctx.governance.pending_ceiling_modification.clone(),
            pending_economic_policy_change: ctx.governance.pending_economic_policy_change.clone(),
            mls_epoch: ctx.epoch.mls_epoch,
            epoch_coordination_records: ctx.epoch.coordinator.records().to_vec(),
            grace_entries,
            needs_reconnect: ctx.epoch.needs_reconnect,
            // MLS crypto state is populated in `persist_context_snapshot`
            // where the crypto provider is available. Initialized empty here.
            mls_crypto_state: Vec::new(),
            migration_state: ctx.migration_state.clone(),
            access_key_store: ctx.access.access_key_store.clone(),
            consequence_rules: ctx.governance.consequence_rules.clone(),
            participation_cache: ctx.governance.participation_cache.clone(),
            velocity_tracker: Some(ctx.governance.velocity_tracker.window_secs()),
            velocity_tracker_state: Some(VelocityTrackerSnapshot {
                window_secs: ctx.governance.velocity_tracker.window_secs(),
                entries: ctx.governance.velocity_tracker.snapshot_entries(),
            }),
            cooldown_until: ctx.governance.cooldown_until.clone(),
            proposal_timestamps: ctx.governance.proposal_timestamps.clone(),
            message_pricing: ctx.governance.message_pricing.clone(),
            hard_rate_limit_config: Some(ctx.governance.hard_rate_limit.config().clone()),
            hard_rate_limit_state: ctx.governance.hard_rate_limit.snapshot_entries(),
            spending_nonce_tracker_state: ctx.governance.spending_nonce_tracker.snapshot_entries(),
            pending_commits: ctx.pending_commits.clone(),
            commit_fault: ctx.commit_fault.clone(),
            checkpoint_events_since: ctx.checkpoint_events_since,
            checkpoint_last_time_secs: ctx.checkpoint_last_time_secs,
            generation: ctx.generation,
        }
    }

    /// Appends a `PaymentCaptureFailed` entry to the event log and pushes a
    /// matching [`ContextEvent::PaymentCaptureFailed`] to the receive buffer.
    ///
    /// Called by `capture_send_payment` and `capture_join_payment` when the
    /// payment adapter returns an error after a successful action (H19 audit
    /// trail). The budget deduction is NOT reversed — service was rendered (H8).
    ///
    /// # Errors on event-log append
    ///
    /// If the event log append fails, a warning is logged but the method
    /// does not propagate the error (best-effort, same as the outer capture).
    ///
    /// The method is `pub(crate)` so that unit tests can invoke it directly
    /// without needing to construct the internal `PaidActionAuthorization`
    /// type. Not part of the public API.
    pub(crate) async fn record_payment_capture_failure(
        &self,
        context_id: &str,
        action: &str,
        actor_did: &DID,
        error_msg: &str,
        cost: Option<scp_protocol::economy::types::Amount>,
    ) {
        let context_id_bytes = context_id_to_bytes(context_id);
        let payload = serde_json::json!({
            "action": action,
            "error": error_msg,
            "cost": cost.map(scp_protocol::economy::types::Amount::value),
        });
        if let Err(log_err) = self.event_log.append_context_event_with_payload(
            &context_id_bytes,
            "PaymentCaptureFailed",
            actor_did.as_ref(),
            Some(&payload),
        ) {
            tracing::warn!(
                context_id,
                "failed to append PaymentCaptureFailed to event log: {log_err}"
            );
        }
        if let Ok(arc) = self.get_context_arc(context_id) {
            let mut ctx = arc.lock().await;
            ctx.checkpoint_events_since += 1;
            ctx.receive_buffer.push(ContextEvent::PaymentCaptureFailed {
                action: action.to_owned(),
                actor_did: actor_did.clone(),
                error: error_msg.to_owned(),
                cost: cost.map(scp_protocol::economy::types::Amount::value),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Uses the canonical SHA-256 context ID byte derivation.
/// Delegates to [`scp_protocol::context::context_id_bytes`] to match builder.rs.
fn context_id_to_bytes(context_id: &str) -> [u8; 32] {
    scp_protocol::context::context_id_bytes(context_id)
}

#[cfg(test)]
#[allow(dead_code)] // Phase B test helper — callers added as tests migrate
#[allow(private_bounds)] // PerContextState is pub(super) but test helper is test-only
impl ContextManager {
    /// Test helper: acquires the per-context lock for direct state manipulation.
    pub(crate) async fn with_context_mut<F, R>(&self, context_id: &str, f: F) -> R
    where
        F: FnOnce(&mut PerContextState) -> R,
    {
        let arc = self
            .get_context_arc(context_id)
            .unwrap_or_else(|_| unreachable!("context not found in test"));
        let mut guard = arc.lock().await;
        f(&mut guard)
    }

    /// Test helper: returns a reference to the underlying `DashMap` for
    /// test-only assertions that need direct map access (e.g., checking
    /// entry presence, count, iteration).
    #[allow(private_interfaces)] // PerContextState is pub(super); tests are within the module.
    pub(crate) fn contexts_map(&self) -> &DashMap<String, Arc<Mutex<PerContextState>>> {
        &self.contexts
    }
}

// Compile-time assertion that `ContextManager` is `Send + Sync`.
const fn _assert_send_sync() {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ContextManager>();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::needless_collect,
    clippy::significant_drop_tightening,
    clippy::match_same_arms,
    clippy::type_complexity,
    clippy::similar_names,
    clippy::items_after_statements
)]
mod tests;
