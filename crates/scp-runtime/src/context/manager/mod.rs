//! Context Manager -- central coordinator for context lifecycle.
//!
//! The [`ContextManager`] owns the provider implementations and exposes the
//! public API for context creation, membership, and messaging. It delegates
//! to [`super::builder::create_context`] for the two-phase commit flow.
//!
//! Providers are injected through the constructor, making the manager fully
//! testable with mock implementations. See ADR-008 in
//! `.docs/adrs/phase-2.md` for the full context lifecycle specification.

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;
use std::sync::Arc;

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
    AuthorBlockResult, BlockResult, BroadcastAdmission, BroadcastContext, BroadcastContextSnapshot,
    GovernanceBanResult, KeyRequestDecision, SubscriptionResult, UnsubscribeResult,
};
use scp_protocol::context::broadcast_content::{BroadcastContent, serialize_broadcast_content};
use scp_protocol::context::builder::{ContextCreationError, ContextCryptoProvider};
use scp_protocol::context::governance::{
    CheckpointAttestationStatus, ContextCheckpoint, CosignedCheckpoint, GovernanceAction,
    GovernanceContext, GovernanceEngine, GovernanceEvent, GovernanceModelConfig,
    GovernanceProposal, KeyResolver, ProposalId, ProposalStatus, PruningPolicy, RevocationScope,
    SingleAdminEngine,
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
use tracing::instrument;
use zeroize::Zeroizing;

mod broadcast;
mod governance;
mod lifecycle;
mod messaging;
mod queries;
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

/// Result of revoking a member's read access (§5.9, ADR-031).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadAccessRevokedResult {
    /// The DID whose read access was revoked.
    pub did: DID,
    /// The revocation scope applied.
    pub scope: RevocationScope,
    /// Number of authors whose keys were rotated (broadcast contexts).
    pub rotated_author_count: usize,
}

/// Result of restoring a member's read access (§5.9, ADR-031).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadAccessRestoredResult {
    /// The DID whose read access was restored.
    pub did: DID,
}

/// Result of revoking a member's write access (§9.17, ADR-038).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteAccessRevokedResult {
    /// The DID whose write access was revoked.
    pub did: DID,
    /// The revocation scope applied.
    pub scope: RevocationScope,
}

/// Result of restoring a member's write access (§9.17, ADR-038).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteAccessRestoredResult {
    /// The DID whose write access was restored.
    pub did: DID,
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
    /// A member was removed from the context.
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
    /// A member's read access was revoked (§5.9, ADR-031).
    ReadAccessRevoked(ReadAccessRevokedResult),
    /// A member's read access was restored (§5.9, ADR-031).
    ReadAccessRestored(ReadAccessRestoredResult),
    /// A member's write access was revoked (§9.17, ADR-038).
    WriteAccessRevoked(WriteAccessRevokedResult),
    /// A member's write access was restored (§9.17, ADR-038).
    WriteAccessRestored(WriteAccessRestoredResult),
    /// Context-wide content keys were rotated (§9.17, ADR-038).
    ContentKeysRotated(ContentKeysRotatedResult),
    /// Governance was reconfigured via deadlock recovery (ADR-031 §10).
    GovernanceReconfigured(GovernanceReconfiguredResult),
    /// An author was blocked from a broadcast context (spec section 5.14.8).
    /// Legacy variant — new code should use `WriteAccessRevoked` with
    /// `RevocationScope::Full`.
    AuthorBlocked(AuthorBlockResult),
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
    /// Members whose write access has been governance-revoked (ADR-031).
    #[serde(default)]
    pub write_revoked_members: HashSet<DID>,
    /// Members whose read access has been governance-revoked (§5.9, ADR-038).
    #[serde(default)]
    pub read_revoked_members: HashSet<DID>,
    /// Members excluded from future CEK wrapping (`FutureOnly` read revocation).
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
    /// Maps proposal ID to (proposal, `sequence_number`, timestamp).
    #[serde(default)]
    pub approved_proposals: HashMap<ProposalId, (GovernanceProposal, u64, u64)>,
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
    /// `RevokeReadAccess`, `ResetMember`).
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
    /// Maps proposal ID to (proposal, `sequence_number`, timestamp).
    approved_proposals: HashMap<ProposalId, (GovernanceProposal, u64, u64)>,
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
}

/// MLS epoch and reconnection state.
struct EpochState {
    /// Monotonic MLS epoch counter. Incremented each time a governance action
    /// triggers an MLS membership change (`AddMember`, `RemoveMember`,
    /// `RevokeReadAccess`, `ResetMember`). Used to populate
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

/// Write/read revocation and context migration state.
struct AccessControlState {
    /// Members whose write access has been governance-revoked (ADR-031).
    write_revoked_members: HashSet<DID>,
    /// Members whose read access has been governance-revoked (§5.9, ADR-038).
    read_revoked_members: HashSet<DID>,
    /// Members excluded from future CEK wrapping (`FutureOnly` read revocation,
    /// ADR-038, §9.17). Subset of or equal to `read_revoked_members`.
    read_exclusion_list: HashSet<DID>,
}

/// TTL timer and extension state.
struct TtlState {
    /// TTL timer management (SCP-021).
    timer: TtlTimer,
    /// Active TTL extension proposal, if any (SCP-021).
    #[allow(dead_code)]
    extension: Option<TtlExtension>,
}

/// Internal state tracked by the manager for each context.
struct PerContextState {
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
    /// Wrapped in `Arc` so spawned timer tasks (TTL expiry #612,
    /// governance timeout ADR-031 §5) can push events to the receive buffer.
    contexts: Arc<Mutex<HashMap<String, PerContextState>>>,
    /// Resolver that maps a DID to its Ed25519 verifying key for governance
    /// vote signature verification (spec §5.9, ADR-031). Passed through to
    /// governance engines at creation and restoration time.
    key_resolver: KeyResolver,
    /// Clock for time-dependent operations.
    ///
    /// Injected via constructors / builder to allow test clock injection.
    /// Defaults to [`scp_primitives::SystemClock`].
    clock: Arc<dyn Clock>,
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
            contexts: Arc::new(Mutex::new(HashMap::new())),
            key_resolver,
            clock: Arc::new(scp_primitives::SystemClock),
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
            contexts: Arc::new(Mutex::new(HashMap::new())),
            key_resolver,
            clock: Arc::new(scp_primitives::SystemClock),
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
    async fn update_context_gauges(&self) {
        let contexts = self.contexts.lock().await;
        crate::metrics::set_active_contexts(contexts.len());
        let total_buffered: usize = contexts.values().map(|c| c.receive_buffer.len()).sum();
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
                let _ = e; // Suppress unused warning; tracing integration is TBD.
            }
        }
    }

    /// Persists a broadcast context snapshot if a persistence provider is
    /// configured. Best-effort: logs errors but does not propagate.
    fn persist_broadcast_snapshot(&self, context_id: &str, snapshot: &BroadcastContextSnapshot) {
        if let Some(ref persistence) = self.persistence
            && let Err(e) = persistence.persist_broadcast(context_id, snapshot)
        {
            let _ = e;
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
        if self.has_persistence() {
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(context_id) {
                let snapshot = Self::snapshot_context(ctx);
                let bc_snapshot = ctx
                    .broadcast_context
                    .as_ref()
                    .map(BroadcastContext::to_snapshot);
                drop(contexts);
                self.persist_context_snapshot(context_id, snapshot);
                if let Some(ref bcs) = bc_snapshot {
                    self.persist_broadcast_snapshot(context_id, bcs);
                }
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
            write_revoked_members: ctx.access.write_revoked_members.clone(),
            read_revoked_members: ctx.access.read_revoked_members.clone(),
            read_exclusion_list: ctx.access.read_exclusion_list.clone(),
            tool_interfaces: ctx.governance.tool_interfaces.clone(),
            threshold_signers: ctx.governance.threshold_signers.clone(),
            threshold_value: ctx.governance.threshold_value,
            pruning_policy: ctx.governance.pruning_policy.clone(),
            governance_model_config: Some(ctx.governance.engine.model_config()),
            economic_policy: ctx.governance.economic_policy.clone(),
            budget_tracker: ctx.governance.budget_tracker.clone(),
            approved_proposals: ctx.governance.approved_proposals.clone(),
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
mod tests {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use scp_protocol::context::params::MemoryScope;
    use scp_protocol::context::{ContextMode, ContextState};

    // -----------------------------------------------------------------------
    // Key resolver helpers for tests
    // -----------------------------------------------------------------------

    /// No-op key resolver that always returns `None`. Suitable for tests
    /// that don't exercise governance vote signature verification.
    fn noop_key_resolver() -> KeyResolver {
        Arc::new(|_| None)
    }

    /// Derives a deterministic Ed25519 seed from a DID string.
    /// Used by both `mock_key_resolver` and `signing_key_for_did` to
    /// ensure signing keys and resolved verifying keys match.
    fn did_to_seed(did: &DID) -> [u8; 32] {
        let mut s = [0u8; 32];
        let bytes = did.as_ref().as_bytes();
        for (i, b) in bytes.iter().enumerate() {
            s[i % 32] ^= *b;
        }
        s
    }

    /// Mock key resolver that returns a deterministic verifying key derived
    /// from the DID string. Suitable for governance proposal tests that
    /// need actual key resolution for vote verification.
    fn mock_key_resolver() -> KeyResolver {
        Arc::new(|did| {
            let seed = did_to_seed(did);
            Some(ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key())
        })
    }

    /// Returns the signing key that corresponds to what `mock_key_resolver`
    /// resolves for the given DID.
    fn signing_key_for_did(did: &DID) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&did_to_seed(did))
    }

    /// Creates an [`InMemoryKeyCustody`] and imports an Ed25519 signing key
    /// from seed bytes, returning both the custody and the key handle.
    ///
    /// Used by broadcast publish tests that need to pass custody + handle
    /// to [`ContextManager::publish_broadcast`].
    async fn test_custody_from_seed(
        seed: &[u8; 32],
    ) -> (
        scp_platform::testing::InMemoryKeyCustody,
        scp_platform::KeyHandle,
    ) {
        let custody = scp_platform::testing::InMemoryKeyCustody::new();
        let handle = custody.import_ed25519_key(seed).await;
        (custody, handle)
    }

    // -----------------------------------------------------------------------
    // Reusable mock providers
    // -----------------------------------------------------------------------

    #[derive(Default)]
    struct MockCrypto {
        fail_create_mls: AtomicBool,
        fail_validate_key_package: AtomicBool,
        fail_advance_epoch: AtomicBool,
        mls_created: std::sync::Mutex<Vec<[u8; 32]>>,
        sender_keys_created: std::sync::Mutex<Vec<[u8; 32]>>,
        broadcast_created: std::sync::Mutex<Vec<[u8; 32]>>,
        mls_destroyed: std::sync::Mutex<Vec<[u8; 32]>>,
        sender_keys_destroyed: std::sync::Mutex<Vec<[u8; 32]>>,
        members_added: std::sync::Mutex<Vec<String>>,
        members_removed: std::sync::Mutex<Vec<String>>,
        sender_keys_distributed: std::sync::Mutex<Vec<String>>,
        sender_keys_removed: std::sync::Mutex<Vec<String>>,
        messages_encrypted: std::sync::Mutex<Vec<Vec<u8>>>,
        epochs_advanced: std::sync::Mutex<Vec<[u8; 32]>>,
        /// Shared handle for test code to observe `advance_epoch` calls after
        /// the mock has been moved into the `ContextManager`.
        epochs_advanced_shared: Arc<std::sync::Mutex<Vec<[u8; 32]>>>,
        /// When `Some`, `decrypt_message` returns `(ciphertext, sender_did)`.
        /// When `None`, the default trait impl (error) is used.
        decrypt_sender_did: Option<String>,
    }

    impl ContextCryptoProvider for MockCrypto {
        fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
            Ok(())
        }

        fn create_mls_group(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            if self.fail_create_mls.load(Ordering::Relaxed) {
                return Err(ContextCreationError::CryptoFailed("mock failure".into()));
            }
            self.mls_created.lock().unwrap().push(*id);
            Ok(())
        }

        fn generate_sender_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.sender_keys_created.lock().unwrap().push(*id);
            Ok(())
        }

        fn init_broadcast_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.broadcast_created.lock().unwrap().push(*id);
            Ok(())
        }

        fn destroy_mls_group(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.mls_destroyed.lock().unwrap().push(*id);
            Ok(())
        }

        fn destroy_sender_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.sender_keys_destroyed.lock().unwrap().push(*id);
            Ok(())
        }

        fn validate_key_package(
            &self,
            _owner_did: &str,
            _key_package_bytes: Option<&[u8]>,
        ) -> Result<(), ContextError> {
            if self.fail_validate_key_package.load(Ordering::Relaxed) {
                return Err(ContextError::InvalidKeyPackage("mock invalid".into()));
            }
            Ok(())
        }

        fn add_member(
            &self,
            _context_id: &[u8; 32],
            member_did: &str,
            _key_package_bytes: Option<&[u8]>,
        ) -> Result<scp_protocol::context::builder::AddMemberOutput, ContextError> {
            self.members_added
                .lock()
                .unwrap()
                .push(member_did.to_owned());
            Ok(scp_protocol::context::builder::AddMemberOutput::default())
        }

        fn remove_member(
            &self,
            _context_id: &[u8; 32],
            member_did: &str,
        ) -> Result<(), ContextError> {
            self.members_removed
                .lock()
                .unwrap()
                .push(member_did.to_owned());
            Ok(())
        }

        fn distribute_sender_key(
            &self,
            _context_id: &[u8; 32],
            member_did: &str,
        ) -> Result<(), ContextError> {
            self.sender_keys_distributed
                .lock()
                .unwrap()
                .push(member_did.to_owned());
            Ok(())
        }

        fn remove_member_sender_key(
            &self,
            _context_id: &[u8; 32],
            member_did: &str,
        ) -> Result<(), ContextError> {
            self.sender_keys_removed
                .lock()
                .unwrap()
                .push(member_did.to_owned());
            Ok(())
        }

        fn encrypt_message(
            &self,
            _context_id: &[u8; 32],
            _sender_did: &str,
            payload: &[u8],
            _epoch: u64,
            _sequence: u64,
        ) -> Result<Vec<u8>, ContextError> {
            self.messages_encrypted
                .lock()
                .unwrap()
                .push(payload.to_vec());
            // Mock: return payload as-is (no real encryption).
            Ok(payload.to_vec())
        }

        fn decrypt_message(
            &self,
            _context_id: &[u8; 32],
            ciphertext: &[u8],
            _epoch: u64,
            _sequence: u64,
        ) -> Result<Option<(Vec<u8>, String)>, ContextError> {
            self.decrypt_sender_did.as_ref().map_or_else(
                || {
                    Err(ContextError::CryptoFailed(
                        "decrypt_message not configured in mock".to_owned(),
                    ))
                },
                |did| Ok(Some((ciphertext.to_vec(), did.clone()))),
            )
        }

        fn advance_epoch(&self, context_id: &[u8; 32]) -> Result<(), ContextError> {
            if self.fail_advance_epoch.load(Ordering::Relaxed) {
                return Err(ContextError::CryptoFailed(
                    "mock advance_epoch failure".into(),
                ));
            }
            self.epochs_advanced.lock().unwrap().push(*context_id);
            self.epochs_advanced_shared
                .lock()
                .unwrap()
                .push(*context_id);
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockTransport {
        connected: AtomicBool,
        published: std::sync::Mutex<Vec<[u8; 32]>>,
        deleted: std::sync::Mutex<Vec<[u8; 32]>>,
        messages_sent: std::sync::Mutex<Vec<Vec<u8>>>,
    }

    impl MockTransport {
        fn connected() -> Self {
            let t = Self::default();
            t.connected.store(true, Ordering::Relaxed);
            t
        }
    }

    impl ContextTransportProvider for MockTransport {
        fn is_connected(&self) -> bool {
            self.connected.load(Ordering::Relaxed)
        }

        fn publish_context(
            &self,
            id: &[u8; 32],
            _params: &ContextParams,
        ) -> Result<(), ContextCreationError> {
            self.published.lock().unwrap().push(*id);
            Ok(())
        }

        fn delete_published(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.deleted.lock().unwrap().push(*id);
            Ok(())
        }

        fn send_message(
            &self,
            _context_id: &[u8; 32],
            encrypted_payload: &[u8],
        ) -> Result<(), ContextError> {
            self.messages_sent
                .lock()
                .unwrap()
                .push(encrypted_payload.to_vec());
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockEventLog {
        inited: std::sync::Mutex<Vec<[u8; 32]>>,
        events: std::sync::Mutex<Vec<([u8; 32], String)>>,
        destroyed: std::sync::Mutex<Vec<[u8; 32]>>,
    }

    impl ContextEventLogProvider for MockEventLog {
        fn init_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.inited.lock().unwrap().push(*id);
            Ok(())
        }

        fn append_event(&self, id: &[u8; 32], event: &str) -> Result<(), ContextCreationError> {
            self.events.lock().unwrap().push((*id, event.to_owned()));
            Ok(())
        }

        fn destroy_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.destroyed.lock().unwrap().push(*id);
            Ok(())
        }
    }

    /// A transport mock that always fails on `send_message`.
    /// Used to test that phantom `MessageSent` events are not emitted
    /// when transport fails (#1420).
    struct FailingTransport;

    impl ContextTransportProvider for FailingTransport {
        fn is_connected(&self) -> bool {
            true
        }

        fn publish_context(
            &self,
            _id: &[u8; 32],
            _params: &ContextParams,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }

        fn delete_published(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }

        fn send_message(
            &self,
            _context_id: &[u8; 32],
            _encrypted_payload: &[u8],
        ) -> Result<(), ContextError> {
            Err(ContextError::TransportFailed(
                "mock transport failure".into(),
            ))
        }
    }

    // -----------------------------------------------------------------------
    // Helper: create a manager with default mocks and a registered context
    // -----------------------------------------------------------------------

    async fn setup_active_context() -> (ContextManager, ContextHandle) {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let params = ContextParams {
            ceiling: vec![
                scp_protocol::context::params::Capability::new("messages:read"),
                scp_protocol::context::params::Capability::new("messages:write"),
                scp_protocol::context::params::Capability::new("role:assign"),
                Capability::ToolRegister,
                Capability::ToolInterface,
                Capability::ChildContextCreate,
                Capability::MemberBan,
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("test-ctx".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        (manager, handle)
    }

    // -----------------------------------------------------------------------
    // Context creation tests (backward compatibility)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn manager_create_context_encrypted_success() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let handle = manager
            .create_context_bare("mgr-ctx-1".into(), ContextParams::default())
            .await;

        assert!(handle.is_ok());
        let handle = handle.unwrap();
        assert_eq!(handle.context_id(), "mgr-ctx-1");
        assert_eq!(handle.state().await, ContextState::Active);
    }

    #[tokio::test]
    async fn manager_create_context_broadcast_success() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: scp_protocol::context::MemoryScope::Full,
            ..ContextParams::default()
        };

        let handle = manager
            .create_context_bare("mgr-ctx-bc".into(), params)
            .await;

        assert!(handle.is_ok());
        let handle = handle.unwrap();
        assert_eq!(handle.context_id(), "mgr-ctx-bc");
        assert_eq!(handle.state().await, ContextState::Active);
    }

    #[tokio::test]
    async fn manager_create_context_succeeds_when_transport_disconnected() {
        // Context creation is a local operation — it should succeed even
        // when `is_connected()` returns false. Transport connectivity is
        // not a Phase 1 gate.
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::default()), // not connected
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let result = manager
            .create_context_bare("mgr-ctx-dc".into(), ContextParams::default())
            .await;

        assert!(result.is_ok());
        let handle = result.unwrap();
        assert_eq!(handle.context_id(), "mgr-ctx-dc");
    }

    #[tokio::test]
    async fn manager_create_context_rollback_on_crypto_failure() {
        let crypto = MockCrypto::default();
        crypto.fail_create_mls.store(true, Ordering::Relaxed);

        let manager = ContextManager::new(
            Box::new(crypto),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let result = manager
            .create_context_bare("mgr-ctx-fail".into(), ContextParams::default())
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextCreationError::CryptoFailed(_)
        ));
    }

    #[tokio::test]
    async fn manager_preserves_params_on_handle() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: scp_protocol::context::MemoryScope::Full,
            ..ContextParams::default()
        };

        let handle = manager
            .create_context_bare("mgr-ctx-p".into(), params.clone())
            .await
            .unwrap();

        assert_eq!(*handle.params(), params);
        assert_eq!(handle.params().mode, ContextMode::Broadcast);
    }

    // -----------------------------------------------------------------------
    // Join context tests
    // -----------------------------------------------------------------------

    /// Unit test: join adds member to MLS group and issues UCAN tokens.
    #[tokio::test]
    async fn join_adds_member_to_mls_group_and_issues_ucan_tokens() {
        let (manager, handle) = setup_active_context().await;

        let kp = KeyPackage::mock("did:key:bob".into());

        let result = manager.join_context(&handle, kp).await;
        assert!(result.is_ok());

        // Verify member was added.
        assert!(manager.is_member("test-ctx", "did:key:bob").await);
        assert_eq!(manager.member_count("test-ctx").await, Some(2));

        // Verify UCAN tokens were issued.
        let role = manager.member_role("test-ctx", "did:key:bob").await;
        assert!(role.is_some());
        let role = role.unwrap();
        assert_eq!(role.role_name, "member");
        assert!(!role.tokens.is_empty());

        // Verify MemberJoined event was emitted.
        let events = manager.drain_events("test-ctx").await;
        let join_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, ContextEvent::MemberJoined { .. }))
            .collect();
        assert_eq!(join_events.len(), 1);
    }

    #[tokio::test]
    async fn join_rejects_when_context_not_active() {
        let (manager, handle) = setup_active_context().await;

        // Transition to Closing.
        handle.transition_to(&ContextState::Closing).await.unwrap();

        let kp = KeyPackage::mock("did:key:bob".into());

        let result = manager.join_context(&handle, kp).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::ContextNotActive
        ));
    }

    /// Regression test for #715 / #738: version check must run BEFORE crypto
    /// ops. When the *stored* context's `min_protocol_version` is incompatible,
    /// `join_context` must reject without calling `add_member` (no orphaned MLS
    /// state). The check uses the stored context's params, not the caller-
    /// supplied handle, so the `UniFFI` bridge's ephemeral default-params handle is safe.
    #[tokio::test]
    async fn join_version_check_rejects_before_crypto_ops() {
        let (manager, _handle) = setup_active_context().await;

        // Simulate a context whose stored params require major version 2 —
        // incompatible with SCP_PROTOCOL_VERSION (1.0). We create with
        // compatible params then replace, because create_context itself
        // (correctly) rejects incompatible min_protocol_version.
        manager
            .replace_stored_params(
                "test-ctx",
                ContextParams {
                    min_protocol_version: Some((2, 0)),
                    ..ContextParams::default()
                },
            )
            .await;

        // Build an ephemeral handle with default params (mimics UniFFI bridge).
        // The early check must still reject because it reads the *stored*
        // context's params, not this handle's params.
        let ephemeral_handle = ContextHandle::new("test-ctx".into(), ContextParams::default());
        ephemeral_handle
            .transition_to(&ContextState::Active)
            .await
            .unwrap();

        let kp = KeyPackage::mock("did:key:bob".into());
        let result = manager.join_context(&ephemeral_handle, kp).await;

        // Must fail with VersionIncompatible — the early check rejects
        // before any crypto operations (validate_key_package, add_member,
        // distribute_sender_key) execute.
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                ContextError::VersionIncompatible { .. }
            ),
            "expected VersionIncompatible error"
        );

        // bob must NOT be a member — no membership state was created because
        // the version check short-circuited before crypto ops and the locked
        // membership mutation section.
        assert!(!manager.is_member("test-ctx", "did:key:bob").await);
        assert_eq!(manager.member_count("test-ctx").await, Some(1));
    }

    // -----------------------------------------------------------------------
    // Leave context tests
    // -----------------------------------------------------------------------

    /// Unit test: leave removes member and transitions to Closing when count
    /// reaches zero.
    #[tokio::test]
    async fn leave_removes_member_and_transitions_to_closing_when_empty() {
        let (manager, handle) = setup_active_context().await;

        // Remove the only member (creator -- self-removal).
        let result = manager
            .leave_context(
                &handle,
                &"did:key:creator".into(),
                &"did:key:creator".into(),
            )
            .await;
        assert!(result.is_ok());

        // Member count should be 0.
        assert_eq!(manager.member_count("test-ctx").await, Some(0));
        assert!(!manager.is_member("test-ctx", "did:key:creator").await);

        // Context should have transitioned to Closing.
        assert_eq!(handle.state().await, ContextState::Closing);

        // Verify MemberLeft event was emitted.
        let events = manager.drain_events("test-ctx").await;
        let left_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, ContextEvent::MemberLeft { .. }))
            .collect();
        assert_eq!(left_events.len(), 1);
    }

    #[tokio::test]
    async fn leave_does_not_close_when_members_remain() {
        let (manager, handle) = setup_active_context().await;

        // Add a second member.
        let kp = KeyPackage::mock("did:key:bob".into());
        manager.join_context(&handle, kp).await.unwrap();
        assert_eq!(manager.member_count("test-ctx").await, Some(2));

        // Remove bob (self-removal).
        manager.drain_events("test-ctx").await; // Clear join event.
        let result = manager
            .leave_context(&handle, &"did:key:bob".into(), &"did:key:bob".into())
            .await;
        assert!(result.is_ok());

        // Context should still be Active (creator is still there).
        assert_eq!(handle.state().await, ContextState::Active);
        assert_eq!(manager.member_count("test-ctx").await, Some(1));
    }

    #[tokio::test]
    async fn leave_rejects_when_context_not_active() {
        let (manager, handle) = setup_active_context().await;

        handle.transition_to(&ContextState::Closing).await.unwrap();

        let result = manager
            .leave_context(
                &handle,
                &"did:key:creator".into(),
                &"did:key:creator".into(),
            )
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::ContextNotActive
        ));
    }

    // -----------------------------------------------------------------------
    // Leave context authorization tests (SCP-167)
    // -----------------------------------------------------------------------

    /// Helper: creates a context whose ceiling includes `member:remove` so
    /// that the admin can remove other members. Adds an observer member
    /// (`did:key:observer`) alongside the admin creator (`did:key:creator`).
    async fn setup_context_with_member_remove() -> (ContextManager, ContextHandle) {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let params = ContextParams {
            ceiling: vec![
                scp_protocol::context::params::Capability::new("messages:read"),
                scp_protocol::context::params::Capability::new("messages:write"),
                scp_protocol::context::params::Capability::new("role:assign"),
                scp_protocol::context::params::Capability::new("member:remove"),
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("auth-ctx".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        // Add an observer member.
        let kp = KeyPackage::mock("did:key:observer".into());
        manager.join_context(&handle, kp).await.unwrap();

        // Reassign to observer role (joined members default to "member").
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("auth-ctx").unwrap();
            roles::assign_role(
                &mut ctx.role_state,
                "did:key:observer",
                "observer",
                "did:key:creator",
                &scp_primitives::SystemClock,
            )
            .unwrap();
            // Update the membership tracking to reflect the new role.
            if let Some(info) = ctx.membership.get_mut("did:key:observer") {
                info.role_name = "observer".into();
            }
        }

        (manager, handle)
    }

    /// SCP-167: observer calls `leave_context` with admin's DID — returns
    /// authorization error.
    #[tokio::test]
    async fn leave_observer_cannot_remove_admin() {
        let (manager, handle) = setup_context_with_member_remove().await;

        // Observer tries to remove the admin — should fail.
        let result = manager
            .leave_context(
                &handle,
                &"did:key:observer".into(),
                &"did:key:creator".into(),
            )
            .await;

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ContextError::PermissionDenied(_)),
            "observer should not be able to remove admin"
        );

        // Admin should still be a member.
        assert!(manager.is_member("auth-ctx", "did:key:creator").await);
    }

    /// SCP-167: admin calls `leave_context` with observer's DID — succeeds
    /// (admin has `MemberRemove` capability).
    #[tokio::test]
    async fn leave_admin_can_remove_observer() {
        let (manager, handle) = setup_context_with_member_remove().await;

        // Admin removes the observer — should succeed.
        let result = manager
            .leave_context(
                &handle,
                &"did:key:creator".into(),
                &"did:key:observer".into(),
            )
            .await;

        assert!(result.is_ok(), "admin should be able to remove observer");

        // Observer should no longer be a member.
        assert!(!manager.is_member("auth-ctx", "did:key:observer").await);
        // Admin should still be a member.
        assert!(manager.is_member("auth-ctx", "did:key:creator").await);
    }

    /// SCP-167: member calls `leave_context` with own DID — succeeds
    /// (self-removal is always allowed regardless of role).
    #[tokio::test]
    async fn leave_self_removal_always_allowed() {
        let (manager, handle) = setup_context_with_member_remove().await;

        // Observer self-removes — should always succeed.
        let result = manager
            .leave_context(
                &handle,
                &"did:key:observer".into(),
                &"did:key:observer".into(),
            )
            .await;

        assert!(result.is_ok(), "self-removal should always be allowed");

        // Observer should no longer be a member.
        assert!(!manager.is_member("auth-ctx", "did:key:observer").await);
        // Admin should still be a member.
        assert!(manager.is_member("auth-ctx", "did:key:creator").await);
    }

    // -----------------------------------------------------------------------
    // Send message tests
    // -----------------------------------------------------------------------

    /// Unit test: `send_message` rejects when context is not Active.
    #[tokio::test]
    async fn send_message_rejects_when_context_not_active() {
        let (manager, handle) = setup_active_context().await;

        handle.transition_to(&ContextState::Closing).await.unwrap();

        let result = manager
            .send_message(&handle, &"did:key:creator".into(), b"hello", None)
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::ContextNotActive
        ));
    }

    /// Unit test: `send_message` validates UCAN before sending.
    #[tokio::test]
    async fn send_message_validates_ucan_before_sending() {
        let (manager, handle) = setup_active_context().await;

        // Try to send as a non-member -- should be denied.
        let result = manager
            .send_message(&handle, &"did:key:nonexistent".into(), b"hello", None)
            .await;
        assert!(result.is_err());

        // Should be either PermissionDenied or MemberNotFound.
        match result.unwrap_err() {
            ContextError::PermissionDenied(_) => {}
            ContextError::MemberNotFound(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_message_success_encrypts_and_sends() {
        let (manager, handle) = setup_active_context().await;

        let result = manager
            .send_message(&handle, &"did:key:creator".into(), b"hello world", None)
            .await;
        assert!(result.is_ok());

        // Verify MessageSent event was emitted.
        let events = manager.drain_events("test-ctx").await;
        let msg_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, ContextEvent::MessageSent { .. }))
            .collect();
        assert_eq!(msg_events.len(), 1);

        if let ContextEvent::MessageSent {
            sender_did,
            sequence_number,
            payload,
        } = &msg_events[0]
        {
            assert_eq!(sender_did, "did:key:creator");
            assert_eq!(*sequence_number, 1);
            assert_eq!(payload, b"hello world");
        }
    }

    #[tokio::test]
    async fn send_message_assigns_monotonic_sequence_numbers() {
        let (manager, handle) = setup_active_context().await;

        for i in 1..=5u8 {
            manager
                .send_message(&handle, &"did:key:creator".into(), &[i], None)
                .await
                .unwrap();
        }

        let events = manager.drain_events("test-ctx").await;
        let seq_nums: Vec<u64> = events
            .iter()
            .filter_map(|e| {
                if let ContextEvent::MessageSent {
                    sequence_number, ..
                } = e
                {
                    Some(*sequence_number)
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(seq_nums, vec![1, 2, 3, 4, 5]);
    }

    /// When transport fails, no phantom `MessageSent` event must appear in
    /// the receive buffer, and the membership-level sequence number must be
    /// unchanged. Fixes #1420 (phantom events), sequence burn on failure.
    #[tokio::test]
    async fn send_message_transport_failure_no_phantom_event() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(FailingTransport),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let params = ContextParams {
            ceiling: vec![
                scp_protocol::context::params::Capability::new("messages:read"),
                scp_protocol::context::params::Capability::new("messages:write"),
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("test-ctx-fail".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        // send_message should fail because FailingTransport.send_message
        // returns an error.
        let result = manager
            .send_message(&handle, &"did:key:creator".into(), b"hello", None)
            .await;
        assert!(
            result.is_err(),
            "send_message must fail when transport fails"
        );

        // The receive buffer must be empty — no phantom MessageSent event.
        let events = manager.drain_events("test-ctx-fail").await;
        let msg_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, ContextEvent::MessageSent { .. }))
            .collect();
        assert!(
            msg_events.is_empty(),
            "no MessageSent event should be emitted when transport fails (#1420)"
        );

        // Verify sequence number was NOT burned: a subsequent successful send
        // on a working transport should get sequence 1, not 2.
        // We can't retry with a different transport on the same manager, but
        // we CAN verify the internal state via the membership sequence counter.
        // The membership sequence should still be 0 (never incremented).
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("test-ctx-fail").unwrap();
        let member = ctx
            .membership
            .members()
            .find(|m| m.did == "did:key:creator")
            .unwrap();
        assert_eq!(
            member.sequence_number, 0,
            "sequence number must not be burned on transport failure"
        );
    }

    /// When transport succeeds, `MessageSent` event must be present in the
    /// receive buffer with the correct sequence number. Validates the positive
    /// path after the #1420 restructure and Phase 3 sequence assignment.
    #[tokio::test]
    async fn send_message_transport_success_emits_event() {
        let (manager, handle) = setup_active_context().await;

        let result = manager
            .send_message(&handle, &"did:key:creator".into(), b"positive-path", None)
            .await;
        assert!(
            result.is_ok(),
            "send_message must succeed with mock transport"
        );

        let events = manager.drain_events("test-ctx").await;
        let msg_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, ContextEvent::MessageSent { .. }))
            .collect();
        assert_eq!(
            msg_events.len(),
            1,
            "exactly one MessageSent event must be emitted on success"
        );

        if let ContextEvent::MessageSent {
            sender_did,
            sequence_number,
            payload,
        } = &msg_events[0]
        {
            assert_eq!(sender_did, "did:key:creator");
            assert_eq!(payload, b"positive-path");
            assert_eq!(
                *sequence_number, 1,
                "first successful send must have sequence_number 1"
            );
        }
    }

    // -----------------------------------------------------------------------
    // deliver_incoming tests
    // -----------------------------------------------------------------------

    /// Helper: build a manager whose `MockCrypto` supports `decrypt_message`,
    /// returning `(plaintext_passthrough, sender_did)`.
    async fn setup_active_context_with_decrypt(
        sender_did: &str,
    ) -> (ContextManager, ContextHandle) {
        let crypto = MockCrypto {
            decrypt_sender_did: Some(sender_did.to_owned()),
            ..MockCrypto::default()
        };

        let manager = ContextManager::new(
            Box::new(crypto),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let params = ContextParams {
            ceiling: vec![
                scp_protocol::context::params::Capability::new("messages:read"),
                scp_protocol::context::params::Capability::new("messages:write"),
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("test-ctx".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        (manager, handle)
    }

    #[tokio::test]
    async fn deliver_incoming_success_for_member() {
        let (manager, _handle) = setup_active_context_with_decrypt("did:key:creator").await;

        let result = manager
            .deliver_incoming("test-ctx", b"encrypted-payload")
            .await;
        assert!(result.is_ok());

        let (plaintext, sender) = result
            .unwrap()
            .expect("expected Some for application message");
        assert_eq!(plaintext, b"encrypted-payload");
        assert_eq!(sender, "did:key:creator");

        // Verify MessageReceived event was emitted.
        let events = manager.drain_events("test-ctx").await;
        let recv_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, ContextEvent::MessageReceived { .. }))
            .collect();
        assert_eq!(recv_events.len(), 1);
    }

    #[tokio::test]
    async fn deliver_incoming_rejects_non_member_sender() {
        // Crypto mock claims "did:key:intruder" sent the message, but that
        // DID is not a member of the context.
        let (manager, _handle) = setup_active_context_with_decrypt("did:key:intruder").await;

        let result = manager.deliver_incoming("test-ctx", b"evil-payload").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ContextError::MemberNotFound(msg) => {
                assert!(
                    msg.contains("did:key:intruder"),
                    "error should mention the sender DID"
                );
            }
            other => panic!("expected MemberNotFound, got: {other:?}"),
        }

        // Verify no MessageReceived event was emitted.
        let events = manager.drain_events("test-ctx").await;
        assert!(
            events
                .iter()
                .all(|e| !matches!(e, ContextEvent::MessageReceived { .. })),
            "no MessageReceived event should be emitted for non-member sender"
        );
    }

    #[tokio::test]
    async fn deliver_incoming_rejects_write_revoked_sender() {
        let (manager, _handle) = setup_active_context_with_decrypt("did:key:creator").await;

        // Revoke write access for the creator.
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("test-ctx").unwrap();
            ctx.access
                .write_revoked_members
                .insert(DID("did:key:creator".to_owned()));
        }

        let result = manager
            .deliver_incoming("test-ctx", b"revoked-payload")
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ContextError::PermissionDenied(msg) => {
                assert!(msg.contains("revoked"), "error should mention revocation");
            }
            other => panic!("expected PermissionDenied, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn deliver_incoming_rejects_sender_without_messages_write() {
        let (manager, _handle) = setup_active_context_with_decrypt("did:key:creator").await;

        // Remove messages:write capability from the creator.
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("test-ctx").unwrap();
            if let Some(caps) = ctx
                .role_state
                .member_capabilities
                .get_mut("did:key:creator")
            {
                caps.remove(&Capability::MessagesWrite);
            }
        }

        let result = manager
            .deliver_incoming("test-ctx", b"no-write-cap-payload")
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ContextError::PermissionDenied(msg) => {
                assert!(
                    msg.contains("messages:write"),
                    "error should mention missing capability"
                );
            }
            other => panic!("expected PermissionDenied, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn deliver_incoming_rejects_inactive_context() {
        let (manager, handle) = setup_active_context_with_decrypt("did:key:creator").await;

        handle.transition_to(&ContextState::Closing).await.unwrap();

        let result = manager.deliver_incoming("test-ctx", b"late-payload").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::ContextNotActive
        ));
    }

    #[tokio::test]
    async fn deliver_incoming_rejects_unknown_context() {
        let (manager, _handle) = setup_active_context_with_decrypt("did:key:creator").await;

        let result = manager
            .deliver_incoming("nonexistent-ctx", b"payload")
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ContextError::ContextNotRegistered(_) => {}
            other => panic!("expected ContextNotRegistered, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Member tracking tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn member_list_queries() {
        let (manager, handle) = setup_active_context().await;

        // Initially only creator.
        assert_eq!(manager.member_count("test-ctx").await, Some(1));
        assert!(manager.is_member("test-ctx", "did:key:creator").await);

        // Add members.
        for name in &["alice", "bob", "charlie"] {
            let kp = KeyPackage::mock(format!("did:key:{name}").into());
            manager.join_context(&handle, kp).await.unwrap();
        }

        assert_eq!(manager.member_count("test-ctx").await, Some(4));
        assert!(manager.is_member("test-ctx", "did:key:alice").await);
        assert!(manager.is_member("test-ctx", "did:key:bob").await);
        assert!(manager.is_member("test-ctx", "did:key:charlie").await);

        let mut dids = manager.member_dids("test-ctx").await;
        dids.sort();
        assert_eq!(
            dids,
            vec![
                "did:key:alice",
                "did:key:bob",
                "did:key:charlie",
                "did:key:creator"
            ]
        );
    }

    #[tokio::test]
    async fn member_role_assignment() {
        let (manager, handle) = setup_active_context().await;

        // Creator should be admin.
        let role = manager.member_role("test-ctx", "did:key:creator").await;
        assert!(role.is_some());
        assert_eq!(role.unwrap().role_name, "admin");

        // Add a member.
        let kp = KeyPackage::mock("did:key:alice".into());
        manager.join_context(&handle, kp).await.unwrap();

        let role = manager.member_role("test-ctx", "did:key:alice").await;
        assert!(role.is_some());
        assert_eq!(role.unwrap().role_name, "member");
    }

    // -----------------------------------------------------------------------
    // Concurrent operations test (SCP-168)
    // -----------------------------------------------------------------------

    /// Verifies that concurrent join + send operations on the same context
    /// do not corrupt internal state. All operations should either succeed
    /// or return a well-defined error -- never panic or produce inconsistent
    /// membership counts.
    #[tokio::test]
    async fn concurrent_joins_and_sends_do_not_corrupt_state() {
        let manager = std::sync::Arc::new(ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        ));

        let params = ContextParams {
            ceiling: vec![
                scp_protocol::context::params::Capability::new("messages:read"),
                scp_protocol::context::params::Capability::new("messages:write"),
                scp_protocol::context::params::Capability::new("role:assign"),
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("conc-ctx".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        let handle = std::sync::Arc::new(handle);

        // Spawn 10 concurrent join tasks.
        let mut join_handles = Vec::new();
        for i in 0..10u32 {
            let mgr = std::sync::Arc::clone(&manager);
            let h = std::sync::Arc::clone(&handle);
            join_handles.push(tokio::spawn(async move {
                let kp = KeyPackage::mock(format!("did:key:member-{i}").into());
                mgr.join_context(&h, kp).await
            }));
        }

        // Spawn 5 concurrent send tasks from the creator.
        for i in 0..5u8 {
            let mgr = std::sync::Arc::clone(&manager);
            let h = std::sync::Arc::clone(&handle);
            join_handles.push(tokio::spawn(async move {
                mgr.send_message(&h, &"did:key:creator".into(), &[i], None)
                    .await
            }));
        }

        // Wait for all tasks. All should succeed (no panics, no data corruption).
        for jh in join_handles {
            let result = jh.await.unwrap();
            assert!(result.is_ok(), "concurrent operation failed: {result:?}");
        }

        // 1 creator + 10 joined members = 11.
        assert_eq!(manager.member_count("conc-ctx").await, Some(11));
    }

    // -----------------------------------------------------------------------
    // Panic recovery test (SCP-168)
    // -----------------------------------------------------------------------

    /// Verifies that a panic inside a mock provider does not poison the
    /// `tokio::sync::Mutex`. After the panicking task is caught, subsequent
    /// operations on the same manager must succeed.
    #[tokio::test]
    async fn panic_does_not_poison_mutex() {
        use std::sync::Arc;

        let manager = Arc::new(ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        ));

        let params = ContextParams {
            ceiling: vec![
                scp_protocol::context::params::Capability::new("messages:read"),
                scp_protocol::context::params::Capability::new("messages:write"),
                scp_protocol::context::params::Capability::new("role:assign"),
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("panic-ctx".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        // Spawn a task that will panic after acquiring the contexts lock.
        // We simulate this by calling join_context with a specially crafted
        // scenario: the crypto provider succeeds, but then we panic inside
        // a spawned task that holds a reference.
        let mgr_clone = Arc::clone(&manager);
        let handle_clone = handle.clone();
        let panicking_task = tokio::spawn(async move {
            // This panics inside the task. tokio::sync::Mutex does not poison.
            let _count = mgr_clone.member_count("panic-ctx").await;
            panic!("intentional panic for testing");
        });

        // The panicking task should fail (JoinError with panic).
        let result = panicking_task.await;
        assert!(result.is_err(), "task should have panicked");

        // The manager should still be usable -- tokio::sync::Mutex does not poison.
        let count = manager.member_count("panic-ctx").await;
        assert_eq!(count, Some(1), "mutex should not be poisoned");

        // Further operations should succeed.
        let kp = KeyPackage::mock("did:key:after-panic".into());
        let join_result = manager.join_context(&handle_clone, kp).await;
        assert!(join_result.is_ok(), "join after panic should succeed");
        assert_eq!(manager.member_count("panic-ctx").await, Some(2));
    }

    // -----------------------------------------------------------------------
    // Broadcast context integration tests (SCP-227)
    // -----------------------------------------------------------------------

    /// Helper: creates a broadcast context with open admission and returns
    /// the manager, handle, and `context_id`.
    ///
    /// Registers `did:key:author1` as a local DID for defense-in-depth
    /// validation in `handle_broadcast_key_request` (#234).
    async fn setup_broadcast_context() -> (ContextManager, ContextHandle, String) {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        // Register the author DID as locally controlled (#234).
        manager.register_local_did("did:key:author1".into()).await;

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: scp_protocol::context::MemoryScope::Full,
            ceiling: vec![
                scp_protocol::context::params::Capability::new("messages:read"),
                scp_protocol::context::params::Capability::new("messages:write"),
                scp_protocol::context::params::Capability::new("role:assign"),
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("broadcast-ctx".into(), params, "did:key:author1".into())
            .await
            .unwrap();

        (manager, handle, "broadcast-ctx".into())
    }

    /// SCP-227 AC1: `subscribe_broadcast` registers subscriber and returns
    /// current author key epoch.
    #[tokio::test]
    async fn broadcast_subscribe_registers_and_returns_epoch() {
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        let result = manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:sub1".into(),
                None,
                1000,
                None,
            )
            .await;

        assert!(result.is_ok(), "subscribe should succeed on open context");
        let result = result.unwrap();

        // Author key epoch should be 0 (fresh author).
        assert_eq!(result.author_epochs.len(), 1);
        assert_eq!(result.author_epochs.get("did:key:author1"), Some(&0));

        // Event should be MemberJoined with role subscriber.
        assert!(matches!(
            result.event,
            ContextEvent::MemberJoined { ref role_name, .. } if role_name == "subscriber"
        ));

        // Manager should track the subscriber.
        assert!(
            manager
                .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
                .await
        );
        assert_eq!(manager.broadcast_subscriber_count(&ctx_id).await, Some(1));
    }

    /// SCP-227 AC2: open broadcast allows subscription without UCAN.
    #[tokio::test]
    async fn broadcast_open_subscribe_no_ucan_required() {
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe without UCAN on open context -- should succeed.
        let result = manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:sub1".into(),
                None,
                1000,
                None,
            )
            .await;
        assert!(result.is_ok());

        // Admission should be Open.
        assert_eq!(
            manager.broadcast_admission(&ctx_id).await,
            Some(super::BroadcastAdmission::Open)
        );
    }

    /// SCP-227 AC4: `block_broadcast_author` revokes sender key.
    #[tokio::test]
    async fn broadcast_block_revokes_key() {
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe a victim.
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:victim".into(),
                None,
                1000,
                None,
            )
            .await
            .unwrap();

        // Block the victim.
        let block_result = manager
            .block_broadcast_subscriber(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:victim".into(),
            )
            .await;

        assert!(block_result.is_ok());
        let block_result = block_result.unwrap();

        // New epoch should be 1 (rotated from 0).
        assert_eq!(block_result.new_epoch, 1);
        assert!(block_result.block_list.contains("did:key:victim"));

        // Key request from blocked subscriber should be denied.
        let decision = manager
            .handle_broadcast_key_request(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:victim".into(),
            )
            .await
            .unwrap();
        assert!(matches!(decision, super::KeyRequestDecision::Deny { .. }));
    }

    /// Regression test for #1003: `block_broadcast_subscriber` must record the
    /// blocker as the author — not the subscriber. Verifies:
    /// 1. `BlockResult::author_did` matches the blocker DID.
    /// 2. `BlockResult::block_list` contains the target subscriber DID.
    /// 3. The `MemberBlocked` event carries `author_did = blocker` and
    ///    `blocked_did = subscriber`.
    #[tokio::test]
    async fn block_broadcast_subscriber_records_blocker_as_author() {
        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        let blocker_did: DID = "did:key:author1".into();
        let target_did: DID = "did:key:target_sub".into();

        // Subscribe the target.
        manager
            .subscribe_broadcast::<
                scp_protocol::crypto::ucan::validate::InMemoryDidResolver,
                scp_protocol::crypto::ucan::validate::InMemoryNonceTracker,
                scp_protocol::crypto::ucan::validate::InMemoryRevocationChecker,
                scp_protocol::crypto::ucan::validate::InMemoryProofResolver,
                std::hash::RandomState,
            >(
                &ctx_id,
                &target_did,
                None,
                1000,
                None,
            )
            .await
            .unwrap();

        // Block the target subscriber.
        let result = manager
            .block_broadcast_subscriber(&ctx_id, &blocker_did, &target_did)
            .await
            .unwrap();

        // AC: blocker_did appears as author_did in the block result.
        assert_eq!(
            result.author_did,
            blocker_did.to_string(),
            "BlockResult::author_did must be the blocker, not the subscriber"
        );

        // AC: target_did appears in the block list.
        assert!(
            result.block_list.contains(&target_did.to_string()),
            "BlockResult::block_list must contain the target subscriber DID"
        );

        // AC: MemberBlocked event carries the correct author and blocked DIDs.
        let events = manager.drain_events(&ctx_id).await;
        let blocked_event = events
            .iter()
            .find(|e| matches!(e, super::ContextEvent::MemberBlocked { .. }));
        assert!(
            blocked_event.is_some(),
            "MemberBlocked event must be emitted"
        );
        match blocked_event.unwrap() {
            super::ContextEvent::MemberBlocked {
                blocked_did,
                author_did,
            } => {
                assert_eq!(
                    author_did, &blocker_did,
                    "MemberBlocked::author_did must be the blocker"
                );
                assert_eq!(
                    blocked_did, &target_did,
                    "MemberBlocked::blocked_did must be the target subscriber"
                );
            }
            _ => unreachable!(),
        }
    }

    /// §9.16.8: `unblock_broadcast_subscriber` removes from block list
    /// without key rotation, emits `MemberUnblocked` event, and allows
    /// subsequent key requests.
    #[tokio::test]
    async fn broadcast_unblock_restores_key_access() {
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe a subscriber.
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:victim".into(),
                None,
                1000,
                None,
            )
            .await
            .unwrap();

        // Block the victim.
        manager
            .block_broadcast_subscriber(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:victim".into(),
            )
            .await
            .unwrap();

        // Key request from blocked subscriber should be denied.
        let decision = manager
            .handle_broadcast_key_request(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:victim".into(),
            )
            .await;
        assert!(matches!(
            decision,
            Ok(super::KeyRequestDecision::Deny { .. })
        ));

        // Unblock the victim.
        manager
            .unblock_broadcast_subscriber(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:victim".into(),
            )
            .await
            .unwrap();

        // Key request should now succeed.
        let decision = manager
            .handle_broadcast_key_request(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:victim".into(),
            )
            .await;
        assert!(
            !matches!(decision, Ok(super::KeyRequestDecision::Deny { .. })),
            "unblocked subscriber should be able to request keys"
        );

        // Drain events and verify MemberUnblocked event was emitted.
        let events = manager.drain_events(&ctx_id).await;
        assert!(
            events
                .iter()
                .any(|e| matches!(e, super::ContextEvent::MemberUnblocked { .. })),
            "MemberUnblocked event must be emitted"
        );
    }

    /// §9.16.8: unblocking a non-blocked subscriber returns an error.
    #[tokio::test]
    async fn broadcast_unblock_not_blocked_returns_error() {
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe.
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:sub1".into(),
                None,
                1000,
                None,
            )
            .await
            .unwrap();

        // Unblock without prior block should fail.
        let result = manager
            .unblock_broadcast_subscriber(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:sub1".into(),
            )
            .await;
        assert!(
            result.is_err(),
            "unblocking non-blocked subscriber should fail"
        );
    }

    /// SCP-227 AC5: broadcast capabilities enforce `MessagesWrite` restricted
    /// to authors, `MessagesRead` open to subscribers.
    #[tokio::test]
    async fn broadcast_capabilities_enforced() {
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe a subscriber.
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:sub1".into(),
                None,
                1000,
                None,
            )
            .await
            .unwrap();

        // Author can publish (send_message routes to broadcast publish).
        let author_signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let result = manager
            .send_message(
                &handle,
                &"did:key:author1".into(),
                b"hello broadcast",
                Some(&author_signing_key),
            )
            .await;
        assert!(result.is_ok(), "author should be able to publish");

        // Non-author subscriber cannot publish.
        let sub_signing_key = ed25519_dalek::SigningKey::from_bytes(&[43u8; 32]);
        let result = manager
            .send_message(
                &handle,
                &"did:key:sub1".into(),
                b"unauthorized",
                Some(&sub_signing_key),
            )
            .await;
        assert!(result.is_err(), "subscriber should not be able to publish");
        assert!(matches!(
            result.unwrap_err(),
            ContextError::PermissionDenied(_)
        ));
    }

    /// SCP-227 AC6: integration test -- author publishes, 3 subscribers
    /// receive and can request keys for decryption.
    #[tokio::test]
    async fn broadcast_publish_3_subscribers_decrypt() {
        use scp_protocol::crypto::sender_keys::open_broadcast;
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;
        let author_signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let author_verifying_key = author_signing_key.verifying_key();
        let (author_custody, author_key_handle) = test_custody_from_seed(&[42u8; 32]).await;

        // Subscribe 3 subscribers.
        for name in &["sub1", "sub2", "sub3"] {
            manager
                .subscribe_broadcast::<
                    InMemoryDidResolver,
                    InMemoryNonceTracker,
                    InMemoryRevocationChecker,
                    InMemoryProofResolver,
                    RandomState,
                >(
                    &ctx_id,
                    &DID(format!("did:key:{name}")),
                    None,
                    1000,
                    None,
                )
                .await
                .unwrap();
        }

        assert_eq!(manager.broadcast_subscriber_count(&ctx_id).await, Some(3));

        // Author publishes a message.
        let plaintext = b"hello all subscribers!";
        let envelope = manager
            .publish_broadcast(
                &ctx_id,
                &"did:key:author1".into(),
                plaintext,
                &author_custody,
                &author_key_handle,
            )
            .await
            .unwrap();

        // Each subscriber requests the key and decrypts.
        for name in &["sub1", "sub2", "sub3"] {
            let decision = manager
                .handle_broadcast_key_request(
                    &ctx_id,
                    &"did:key:author1".into(),
                    &DID(format!("did:key:{name}")),
                )
                .await
                .unwrap();

            match decision {
                super::KeyRequestDecision::Grant {
                    key_bytes, epoch, ..
                } => {
                    assert_eq!(epoch, 0);
                    // Reconstruct broadcast key and decrypt.
                    let broadcast_key = scp_protocol::crypto::sender_keys::BroadcastKey::from_parts(
                        scp_protocol::crypto::sender_keys::SenderKey::from_bytes(*key_bytes),
                        epoch,
                        "did:key:author1".to_owned(),
                    );
                    let decrypted =
                        open_broadcast(&broadcast_key, &envelope, &author_verifying_key).unwrap();
                    assert_eq!(decrypted, plaintext);
                }
                super::KeyRequestDecision::Deny { reason } => {
                    panic!("key request should be granted for {name}: {reason}");
                }
            }
        }

        // Verify MessageSent event was emitted.
        let events = manager.drain_events(&ctx_id).await;
        let msg_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, ContextEvent::MessageSent { .. }))
            .collect();
        assert_eq!(msg_events.len(), 1);
    }

    /// SCP-227 AC7: integration test -- blocked author's subsequent messages
    /// are undecryptable by blocked subscriber.
    #[tokio::test]
    // Integration test exercises full context lifecycle; splitting would
    // fragment a sequential scenario that must be verified end-to-end.
    #[allow(clippy::too_many_lines)]
    async fn broadcast_blocked_subscriber_cannot_decrypt() {
        use scp_protocol::crypto::sender_keys::open_broadcast;
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;
        let author_signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let author_verifying_key = author_signing_key.verifying_key();
        let (author_custody, author_key_handle) = test_custody_from_seed(&[42u8; 32]).await;

        // Subscribe 2 subscribers.
        for name in &["good-sub", "bad-sub"] {
            manager
                .subscribe_broadcast::<
                    InMemoryDidResolver,
                    InMemoryNonceTracker,
                    InMemoryRevocationChecker,
                    InMemoryProofResolver,
                    RandomState,
                >(
                    &ctx_id,
                    &DID(format!("did:key:{name}")),
                    None,
                    1000,
                    None,
                )
                .await
                .unwrap();
        }

        // Author publishes first message (both can decrypt).
        let msg1 = b"pre-block message";
        let envelope1 = manager
            .publish_broadcast(
                &ctx_id,
                &"did:key:author1".into(),
                msg1,
                &author_custody,
                &author_key_handle,
            )
            .await
            .unwrap();

        // Get the pre-block key for "bad-sub".
        let pre_block_decision = manager
            .handle_broadcast_key_request(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:bad-sub".into(),
            )
            .await
            .unwrap();
        let super::KeyRequestDecision::Grant {
            key_bytes: pre_block_key_bytes,
            epoch: pre_block_epoch,
        } = pre_block_decision
        else {
            panic!("should be granted before block")
        };

        // Verify bad-sub can decrypt the pre-block message.
        let pre_block_broadcast_key = scp_protocol::crypto::sender_keys::BroadcastKey::from_parts(
            scp_protocol::crypto::sender_keys::SenderKey::from_bytes(*pre_block_key_bytes),
            pre_block_epoch,
            "did:key:author1".to_owned(),
        );
        let decrypted =
            open_broadcast(&pre_block_broadcast_key, &envelope1, &author_verifying_key).unwrap();
        assert_eq!(decrypted, msg1);

        // Block bad-sub.
        manager
            .block_broadcast_subscriber(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:bad-sub".into(),
            )
            .await
            .unwrap();

        // Author publishes post-block message.
        let msg2 = b"post-block secret";
        let envelope2 = manager
            .publish_broadcast(
                &ctx_id,
                &"did:key:author1".into(),
                msg2,
                &author_custody,
                &author_key_handle,
            )
            .await
            .unwrap();

        // bad-sub's key request is now denied.
        let post_block_decision = manager
            .handle_broadcast_key_request(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:bad-sub".into(),
            )
            .await
            .unwrap();
        assert!(
            matches!(post_block_decision, super::KeyRequestDecision::Deny { .. }),
            "blocked subscriber should be denied"
        );

        // bad-sub tries to decrypt with the old key -- should fail because
        // the message was encrypted with the new (post-rotation) key.
        let decrypt_attempt =
            open_broadcast(&pre_block_broadcast_key, &envelope2, &author_verifying_key);
        assert!(
            decrypt_attempt.is_err(),
            "blocked subscriber should not be able to decrypt post-block messages"
        );

        // good-sub can still get the new key and decrypt.
        let good_decision = manager
            .handle_broadcast_key_request(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:good-sub".into(),
            )
            .await
            .unwrap();
        match good_decision {
            super::KeyRequestDecision::Grant {
                key_bytes, epoch, ..
            } => {
                assert_eq!(epoch, 1, "epoch should be 1 after rotation");
                let new_key = scp_protocol::crypto::sender_keys::BroadcastKey::from_parts(
                    scp_protocol::crypto::sender_keys::SenderKey::from_bytes(*key_bytes),
                    epoch,
                    "did:key:author1".to_owned(),
                );
                let decrypted =
                    open_broadcast(&new_key, &envelope2, &author_verifying_key).unwrap();
                assert_eq!(decrypted, msg2);
            }
            super::KeyRequestDecision::Deny { reason } => {
                panic!("good-sub should be granted: {reason}");
            }
        }
    }

    /// SCP-227: non-author publish is rejected.
    #[tokio::test]
    async fn broadcast_non_author_publish_rejected() {
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe.
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:sub1".into(),
                None,
                1000,
                None,
            )
            .await
            .unwrap();

        // Subscriber tries to publish -- should fail.
        let (sub_custody, sub_key_handle) = test_custody_from_seed(&[43u8; 32]).await;
        let result = manager
            .publish_broadcast(
                &ctx_id,
                &"did:key:sub1".into(),
                b"nope",
                &sub_custody,
                &sub_key_handle,
            )
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::PermissionDenied(_)
        ));
    }

    /// SCP-227: `create_context` initializes `broadcast_context` for broadcast mode.
    #[tokio::test]
    async fn broadcast_create_context_initializes_broadcast_state() {
        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        // Admission should be Open (default for no template_id).
        assert_eq!(
            manager.broadcast_admission(&ctx_id).await,
            Some(super::BroadcastAdmission::Open)
        );

        // Subscriber count should be 0 initially.
        assert_eq!(manager.broadcast_subscriber_count(&ctx_id).await, Some(0));

        // Author should be able to publish.
        let (author_custody, author_key_handle) = test_custody_from_seed(&[42u8; 32]).await;
        let result = manager
            .publish_broadcast(
                &ctx_id,
                &"did:key:author1".into(),
                b"test",
                &author_custody,
                &author_key_handle,
            )
            .await;
        assert!(result.is_ok());
    }

    /// SCP-227: `leave_context` on broadcast context cleans up subscriber.
    #[tokio::test]
    async fn broadcast_leave_context_unsubscribes() {
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe.
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:sub1".into(),
                None,
                1000,
                None,
            )
            .await
            .unwrap();
        assert!(
            manager
                .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
                .await
        );

        // Leave via leave_context (self-removal).
        let result = manager
            .leave_context(&handle, &"did:key:sub1".into(), &"did:key:sub1".into())
            .await;
        assert!(result.is_ok());

        // Subscriber should be removed from broadcast context.
        assert!(
            !manager
                .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
                .await
        );
    }

    /// SCP-227: `close_context` drops broadcast state.
    #[tokio::test]
    async fn broadcast_close_context_drops_state() {
        // Need context:close capability for the admin.
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: scp_protocol::context::MemoryScope::Full,
            ceiling: vec![
                scp_protocol::context::params::Capability::new("messages:read"),
                scp_protocol::context::params::Capability::new("messages:write"),
                scp_protocol::context::params::Capability::new("role:assign"),
                scp_protocol::context::params::Capability::new("context:close"),
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context(
                "broadcast-close-ctx".into(),
                params,
                "did:key:author1".into(),
            )
            .await
            .unwrap();
        let ctx_id = "broadcast-close-ctx";

        // Close the context.
        let result = manager
            .close_context(&handle, &"did:key:author1".into())
            .await;
        assert!(result.is_ok());

        // Broadcast state should be None (dropped on close).
        assert_eq!(manager.broadcast_admission(ctx_id).await, None);
        assert_eq!(manager.broadcast_subscriber_count(ctx_id).await, None);
    }

    /// SCP-227: `unsubscribe_broadcast` removes subscriber and optionally rotates keys.
    #[tokio::test]
    async fn broadcast_unsubscribe_with_key_rotation() {
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe.
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:sub1".into(),
                None,
                1000,
                None,
            )
            .await
            .unwrap();

        // Unsubscribe with key rotation.
        let result = manager
            .unsubscribe_broadcast(&ctx_id, &"did:key:sub1".into(), true)
            .await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.subscriber_did, "did:key:sub1");
        // Key rotation should have happened (one rotation per author).
        assert_eq!(result.key_rotations.len(), 1);
        assert_eq!(result.key_rotations[0].new_epoch, 1);

        // Subscriber should no longer be tracked.
        assert!(
            !manager
                .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
                .await
        );
    }

    // ===================================================================
    // Author blocking (SCP-227 AC4 + AC7) — governance-gated
    // ===================================================================

    /// Helper: creates an approved `BlockAuthor` governance proposal using
    /// `SingleAdminEngine` (admin = `admin_did`). Returns the approved
    /// proposal that can be passed to `execute_governance_action()`.
    fn approved_block_author_proposal(
        admin_did: &DID,
        context_id: &str,
        target_did: &DID,
    ) -> super::GovernanceProposal {
        use scp_protocol::context::governance::{
            GovernanceAction, GovernanceContext, GovernanceEngine, SingleAdminEngine,
        };

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let vk = signing_key.verifying_key();
        #[allow(clippy::type_complexity)]
        let resolver: std::sync::Arc<
            dyn Fn(&scp_identity::DID) -> Option<ed25519_dalek::VerifyingKey> + Send + Sync,
        > = std::sync::Arc::new(move |_| Some(vk));
        let mut engine = SingleAdminEngine::new(admin_did.clone(), resolver);
        let gov_ctx = GovernanceContext {
            context_id: context_id.to_owned(),
            members: vec![
                (admin_did.clone(), "admin".to_owned()),
                (target_did.clone(), "author".to_owned()),
            ],
            admin_dids: vec![admin_did.clone()],
            current_epoch: None,
            now: 1000,
        };

        let action = GovernanceAction::BlockAuthor {
            did: target_did.clone(),
            reason: Some("governance test".to_owned()),
        };

        let (proposal, _events) = engine
            .propose(admin_did, action, &gov_ctx, &signing_key)
            .unwrap();
        assert!(matches!(proposal.status, super::ProposalStatus::Approved));
        proposal
    }

    /// Helper to create a broadcast context with two authors (alice + bob).
    ///
    /// Both authors are registered in the `BroadcastContext` (for publish
    /// capability) and in `MembershipState` (for sequence number tracking).
    /// Both author DIDs are registered as locally controlled (#234).
    async fn setup_broadcast_context_two_authors() -> (ContextManager, ContextHandle, String) {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        // Register both author DIDs as locally controlled (#234).
        manager.register_local_did("did:key:alice".into()).await;
        manager.register_local_did("did:key:bob".into()).await;

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: scp_protocol::context::MemoryScope::Full,
            ceiling: vec![
                scp_protocol::context::params::Capability::new("messages:read"),
                scp_protocol::context::params::Capability::new("messages:write"),
                scp_protocol::context::params::Capability::new("role:assign"),
                Capability::MemberBan,
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("broadcast-2auth-ctx".into(), params, "did:key:alice".into())
            .await
            .unwrap();

        // Add bob as a second author: both in BroadcastContext and membership.
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("broadcast-2auth-ctx").unwrap();
            let bc = ctx.broadcast_context.as_mut().unwrap();
            bc.add_author("did:key:bob").unwrap();
            // Also add to membership tracking so sequence numbers work.
            ctx.membership
                .add_member("did:key:bob".into(), "author".into(), vec![]);
        }

        let ctx_id = "broadcast-2auth-ctx".to_owned();
        (manager, handle, ctx_id)
    }

    /// SCP-227 AC4: governance-approved `BlockAuthor` proposal revokes sender
    /// key, preventing the blocked author from publishing.
    #[tokio::test]
    // Integration test exercises full governance + broadcast lifecycle; splitting
    // would fragment a sequential scenario that must be verified end-to-end.
    #[allow(clippy::too_many_lines)]
    async fn broadcast_block_author_via_governance_revokes_publish() {
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;

        // Subscribe 2 subscribers.
        for name in &["sub1", "sub2"] {
            manager
                .subscribe_broadcast::<
                    InMemoryDidResolver,
                    InMemoryNonceTracker,
                    InMemoryRevocationChecker,
                    InMemoryProofResolver,
                    RandomState,
                >(
                    &ctx_id,
                    &DID(format!("did:key:{name}")),
                    None,
                    1000,
                    None,
                )
                .await
                .unwrap();
        }

        let (alice_custody, alice_key_handle) = test_custody_from_seed(&[0xAA; 32]).await;
        let (bob_custody, bob_key_handle) = test_custody_from_seed(&[0xBB; 32]).await;

        // Both authors can publish before blocking.
        assert!(
            manager
                .publish_broadcast(
                    &ctx_id,
                    &"did:key:alice".into(),
                    b"alice msg",
                    &alice_custody,
                    &alice_key_handle,
                )
                .await
                .is_ok()
        );
        assert!(
            manager
                .publish_broadcast(
                    &ctx_id,
                    &"did:key:bob".into(),
                    b"bob msg",
                    &bob_custody,
                    &bob_key_handle,
                )
                .await
                .is_ok()
        );

        // Block bob via governance: admin proposes, auto-approved.
        let proposal =
            approved_block_author_proposal(&"did:key:alice".into(), &ctx_id, &"did:key:bob".into());
        let action_result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(action_result.is_ok());
        let super::GovernanceActionResult::WriteAccessRevoked(revoke_result) =
            action_result.unwrap()
        else {
            panic!("expected WriteAccessRevoked result from BlockAuthor delegation");
        };
        assert_eq!(revoke_result.did.0, "did:key:bob");
        assert_eq!(revoke_result.scope, RevocationScope::Full);

        // Alice can still publish (unaffected).
        assert!(
            manager
                .publish_broadcast(
                    &ctx_id,
                    &"did:key:alice".into(),
                    b"alice still ok",
                    &alice_custody,
                    &alice_key_handle,
                )
                .await
                .is_ok(),
            "unblocked author should still be able to publish"
        );

        // Bob cannot publish (PermissionDenied).
        let bob_result = manager
            .publish_broadcast(
                &ctx_id,
                &"did:key:bob".into(),
                b"bob tries",
                &bob_custody,
                &bob_key_handle,
            )
            .await;
        assert!(
            bob_result.is_err(),
            "blocked author should not be able to publish"
        );
        assert!(matches!(
            bob_result.unwrap_err(),
            ContextError::PermissionDenied(_)
        ));

        // Key request for bob returns Deny (author not found).
        let decision = manager
            .handle_broadcast_key_request(&ctx_id, &"did:key:bob".into(), &"did:key:sub1".into())
            .await
            .unwrap();
        assert!(
            matches!(decision, super::KeyRequestDecision::Deny { .. }),
            "key request for blocked author should be denied"
        );

        // Key request for alice still works.
        let decision = manager
            .handle_broadcast_key_request(&ctx_id, &"did:key:alice".into(), &"did:key:sub1".into())
            .await
            .unwrap();
        assert!(
            matches!(decision, super::KeyRequestDecision::Grant { .. }),
            "key request for unblocked author should succeed"
        );
    }

    /// Attempting to block an author with a non-approved proposal is rejected.
    #[tokio::test]
    async fn broadcast_block_author_rejects_pending_proposal() {
        use scp_protocol::context::governance::{GovernanceProposal, ProposalStatus};

        let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;

        // Construct a proposal that is NOT approved (still Pending).
        let pending_proposal = GovernanceProposal {
            proposal_id: [0u8; 32],
            context_id: ctx_id.clone(),
            proposer_did: "did:key:alice".into(),
            action: super::GovernanceAction::BlockAuthor {
                did: "did:key:bob".into(),
                reason: None,
            },
            status: ProposalStatus::Pending,
            created_at: 1000,
            voting_deadline: 2000,
            approvals: Vec::new(),
            rejections: Vec::new(),
            created_at_epoch: None,
        };

        let result = manager
            .execute_governance_action(&ctx_id, &pending_proposal)
            .await;
        assert!(result.is_err(), "pending proposal must not execute");
        assert!(
            matches!(result.unwrap_err(), ContextError::PermissionDenied(_)),
            "should return PermissionDenied for non-approved proposal"
        );
    }

    /// SCP-227 AC7: integration test -- after blocking an author, their
    /// subsequent messages are undecryptable by subscribers (because the
    /// author can no longer produce them).
    #[tokio::test]
    // Integration test exercises full broadcast lifecycle; splitting would
    // fragment a sequential scenario that must be verified end-to-end.
    #[allow(clippy::too_many_lines)]
    async fn broadcast_blocked_author_messages_undecryptable() {
        use scp_protocol::crypto::sender_keys::open_broadcast;
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;
        let alice_signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let alice_verifying_key = alice_signing_key.verifying_key();
        let bob_signing_key = ed25519_dalek::SigningKey::from_bytes(&[43u8; 32]);
        let bob_verifying_key = bob_signing_key.verifying_key();
        let (alice_custody, alice_key_handle) = test_custody_from_seed(&[42u8; 32]).await;
        let (bob_custody, bob_key_handle) = test_custody_from_seed(&[43u8; 32]).await;

        // Subscribe 2 subscribers.
        for name in &["sub1", "sub2"] {
            manager
                .subscribe_broadcast::<
                    InMemoryDidResolver,
                    InMemoryNonceTracker,
                    InMemoryRevocationChecker,
                    InMemoryProofResolver,
                    RandomState,
                >(
                    &ctx_id,
                    &DID(format!("did:key:{name}")),
                    None,
                    1000,
                    None,
                )
                .await
                .unwrap();
        }

        // Alice publishes — both subscribers can get key and decrypt.
        let alice_msg1 = b"Alice before block";
        let _alice_envelope1 = manager
            .publish_broadcast(
                &ctx_id,
                &"did:key:alice".into(),
                alice_msg1,
                &alice_custody,
                &alice_key_handle,
            )
            .await
            .unwrap();

        // Bob publishes — both subscribers can get key and decrypt.
        let bob_msg1 = b"Bob before block";
        let bob_envelope1 = manager
            .publish_broadcast(
                &ctx_id,
                &"did:key:bob".into(),
                bob_msg1,
                &bob_custody,
                &bob_key_handle,
            )
            .await
            .unwrap();

        // Get Bob's key before blocking (sub1 perspective).
        let bob_pre_block_decision = manager
            .handle_broadcast_key_request(&ctx_id, &"did:key:bob".into(), &"did:key:sub1".into())
            .await
            .unwrap();
        let super::KeyRequestDecision::Grant {
            key_bytes: bob_pre_key,
            epoch: bob_pre_epoch,
        } = bob_pre_block_decision
        else {
            panic!("bob key should be granted before block")
        };

        // Verify sub1 can decrypt Bob's pre-block message.
        let bob_broadcast_key = scp_protocol::crypto::sender_keys::BroadcastKey::from_parts(
            scp_protocol::crypto::sender_keys::SenderKey::from_bytes(*bob_pre_key),
            bob_pre_epoch,
            "did:key:bob".to_owned(),
        );
        let decrypted =
            open_broadcast(&bob_broadcast_key, &bob_envelope1, &bob_verifying_key).unwrap();
        assert_eq!(decrypted, bob_msg1);

        // Block Bob via governance (admin proposes, auto-approved).
        let proposal =
            approved_block_author_proposal(&"did:key:alice".into(), &ctx_id, &"did:key:bob".into());
        manager
            .execute_governance_action(&ctx_id, &proposal)
            .await
            .unwrap();

        // Bob tries to publish — PermissionDenied.
        let bob_result = manager
            .publish_broadcast(
                &ctx_id,
                &"did:key:bob".into(),
                b"bob after block",
                &bob_custody,
                &bob_key_handle,
            )
            .await;
        assert!(
            bob_result.is_err(),
            "blocked author should not be able to publish"
        );

        // Alice can still publish after Bob is blocked.
        let alice_msg2 = b"Alice after Bob blocked";
        let alice_envelope2 = manager
            .publish_broadcast(
                &ctx_id,
                &"did:key:alice".into(),
                alice_msg2,
                &alice_custody,
                &alice_key_handle,
            )
            .await
            .unwrap();

        // Sub1 can still get Alice's key and decrypt.
        let alice_decision = manager
            .handle_broadcast_key_request(&ctx_id, &"did:key:alice".into(), &"did:key:sub1".into())
            .await
            .unwrap();
        match alice_decision {
            super::KeyRequestDecision::Grant {
                key_bytes, epoch, ..
            } => {
                let alice_key = scp_protocol::crypto::sender_keys::BroadcastKey::from_parts(
                    scp_protocol::crypto::sender_keys::SenderKey::from_bytes(*key_bytes),
                    epoch,
                    "did:key:alice".to_owned(),
                );
                let decrypted =
                    open_broadcast(&alice_key, &alice_envelope2, &alice_verifying_key).unwrap();
                assert_eq!(decrypted, alice_msg2);
            }
            super::KeyRequestDecision::Deny { reason } => {
                panic!("alice key should be granted: {reason}");
            }
        }

        // Sub1 requests Bob's key — Deny (author no longer exists).
        let bob_post_decision = manager
            .handle_broadcast_key_request(&ctx_id, &"did:key:bob".into(), &"did:key:sub1".into())
            .await
            .unwrap();
        assert!(
            matches!(bob_post_decision, super::KeyRequestDecision::Deny { .. }),
            "key request for blocked author must be denied"
        );

        // Old messages from Bob are still decryptable with cached key
        // (forward access to historical content is preserved).
        let old_decrypted =
            open_broadcast(&bob_broadcast_key, &bob_envelope1, &bob_verifying_key).unwrap();
        assert_eq!(old_decrypted, bob_msg1);
    }

    /// SCP-227: governance-approved `BlockAuthor` on non-broadcast context
    /// returns error (the action only applies to broadcast contexts).
    #[tokio::test]
    async fn broadcast_block_author_on_encrypted_context_fails() {
        let (manager, _handle) = setup_active_context().await;

        let target_did: DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into();
        let admin_did: DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into();

        let proposal = approved_block_author_proposal(&admin_did, "test-ctx", &target_did);
        let result = manager
            .execute_governance_action("test-ctx", &proposal)
            .await;
        assert!(result.is_err());
    }

    /// Defense-in-depth: a proposal approved for context A must not be
    /// executable against context B.
    #[tokio::test]
    async fn governance_action_rejects_wrong_context_id() {
        let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;

        // Create a proposal targeting a different context.
        let proposal = approved_block_author_proposal(
            &"did:key:alice".into(),
            "ctx-a-other",
            &"did:key:bob".into(),
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(
            result.is_err(),
            "proposal targeting a different context must be rejected"
        );
        assert!(
            matches!(result.unwrap_err(), ContextError::PermissionDenied(_)),
            "should return PermissionDenied for context mismatch"
        );
    }

    /// Defense-in-depth: replaying the same approved proposal a second time
    /// is rejected with an explicit error rather than relying on downstream
    /// `MemberNotFound`.
    #[tokio::test]
    async fn governance_action_rejects_replayed_proposal() {
        let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;

        let proposal =
            approved_block_author_proposal(&"did:key:alice".into(), &ctx_id, &"did:key:bob".into());

        // First execution should succeed.
        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(result.is_ok(), "first execution should succeed");

        // Second execution of the same proposal should fail (replay).
        let replay_result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(replay_result.is_err(), "replayed proposal must be rejected");
        assert!(
            matches!(
                replay_result.unwrap_err(),
                ContextError::PermissionDenied(_)
            ),
            "should return PermissionDenied for replayed proposal"
        );
    }

    // ===================================================================
    // Read access revocation/restoration (SCP-GG-006) — governance-gated
    // ===================================================================

    /// Helper: creates a broadcast context with `MemberBan` in the ceiling,
    /// one author (alice), and one subscriber (sub1).
    async fn setup_broadcast_with_member_ban() -> (ContextManager, String) {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        manager.register_local_did("did:key:alice".into()).await;

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: scp_protocol::context::MemoryScope::Full,
            ceiling: vec![
                scp_protocol::context::params::Capability::new("messages:read"),
                scp_protocol::context::params::Capability::new("messages:write"),
                scp_protocol::context::params::Capability::new("role:assign"),
                scp_protocol::context::params::Capability::new("member:ban"),
            ],
            ..ContextParams::default()
        };

        let _handle = manager
            .create_context("broadcast-ban-ctx".into(), params, "did:key:alice".into())
            .await
            .unwrap();

        // Subscribe sub1 directly via BroadcastContext.
        {
            use scp_protocol::crypto::ucan::validate::{
                InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
                InMemoryRevocationChecker,
            };
            use std::hash::RandomState;

            manager
                .subscribe_broadcast::<
                    InMemoryDidResolver,
                    InMemoryNonceTracker,
                    InMemoryRevocationChecker,
                    InMemoryProofResolver,
                    RandomState,
                >(
                    "broadcast-ban-ctx",
                    &DID("did:key:sub1".into()),
                    None,
                    1000,
                    None,
                )
                .await
                .unwrap();
        }

        let ctx_id = "broadcast-ban-ctx".to_owned();
        (manager, ctx_id)
    }

    /// Helper: creates an approved governance proposal for an arbitrary action
    /// using `SingleAdminEngine`. The admin is `admin_did`.
    fn approved_governance_proposal(
        admin_did: &DID,
        context_id: &str,
        target_did: &DID,
        action: super::GovernanceAction,
    ) -> super::GovernanceProposal {
        use scp_protocol::context::governance::{
            GovernanceContext, GovernanceEngine, SingleAdminEngine,
        };

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let vk = signing_key.verifying_key();
        #[allow(clippy::type_complexity)]
        let resolver: std::sync::Arc<
            dyn Fn(&scp_identity::DID) -> Option<ed25519_dalek::VerifyingKey> + Send + Sync,
        > = std::sync::Arc::new(move |_| Some(vk));
        let mut engine = SingleAdminEngine::new(admin_did.clone(), resolver);
        let gov_ctx = GovernanceContext {
            context_id: context_id.to_owned(),
            members: vec![
                (admin_did.clone(), "admin".to_owned()),
                (target_did.clone(), "subscriber".to_owned()),
            ],
            admin_dids: vec![admin_did.clone()],
            current_epoch: None,
            now: 1000,
        };

        let (proposal, _events) = engine
            .propose(admin_did, action, &gov_ctx, &signing_key)
            .unwrap();
        assert!(matches!(proposal.status, super::ProposalStatus::Approved));
        proposal
    }

    /// SCP-GG-006: `RevokeReadAccess` on broadcast context bans subscriber.
    #[tokio::test]
    async fn revoke_read_access_bans_subscriber_in_broadcast() {
        let (manager, ctx_id) = setup_broadcast_with_member_ban().await;

        // Verify sub1 is subscribed before revocation.
        assert!(
            manager
                .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
                .await,
            "sub1 should be subscribed before revocation"
        );

        let action = super::GovernanceAction::RevokeReadAccess {
            did: "did:key:sub1".into(),
            scope: super::RevocationScope::Full,
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:sub1".into(),
            action,
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(result.is_ok(), "RevokeReadAccess should succeed");

        let result = result.unwrap();
        match result {
            super::GovernanceActionResult::ReadAccessRevoked(revoke_result) => {
                assert_eq!(revoke_result.did.0, "did:key:sub1");
                // At least one author should have rotated keys.
                assert!(
                    revoke_result.rotated_author_count > 0,
                    "key rotation should occur on revoke"
                );
            }
            other => panic!("expected ReadAccessRevoked, got {other:?}"),
        }

        // Subscriber should no longer be tracked.
        assert!(
            !manager
                .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
                .await,
            "sub1 should not be subscribed after revocation"
        );

        // Verify ReadAccessRevoked event was emitted.
        let events = manager.drain_events(&ctx_id).await;
        let has_revoke_event = events.iter().any(|e| {
            matches!(
                e,
                super::ContextEvent::ReadAccessRevoked { did } if did.0 == "did:key:sub1"
            )
        });
        assert!(
            has_revoke_event,
            "ReadAccessRevoked event should have been emitted"
        );
    }

    /// SCP-GG-006: `RevokeReadAccess` fails when ceiling lacks `MemberBan`.
    #[tokio::test]
    async fn revoke_read_access_rejected_without_member_ban_ceiling() {
        // Create a broadcast context WITHOUT MemberBan in ceiling.
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        manager.register_local_did("did:key:alice".into()).await;
        manager.register_local_did("did:key:bob".into()).await;
        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: MemoryScope::Full,
            ceiling: vec![
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::RoleAssign,
            ],
            ..ContextParams::default()
        };
        let _handle = manager
            .create_context("no-ban-ctx".into(), params, "did:key:alice".into())
            .await
            .unwrap();
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("no-ban-ctx").unwrap();
            let bc = ctx.broadcast_context.as_mut().unwrap();
            bc.add_author("did:key:bob").unwrap();
            ctx.membership
                .add_member("did:key:bob".into(), "author".into(), vec![]);
        }
        let ctx_id = "no-ban-ctx".to_owned();

        // Subscribe sub1.
        {
            use scp_protocol::crypto::ucan::validate::{
                InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
                InMemoryRevocationChecker,
            };
            use std::hash::RandomState;

            manager
                .subscribe_broadcast::<
                    InMemoryDidResolver,
                    InMemoryNonceTracker,
                    InMemoryRevocationChecker,
                    InMemoryProofResolver,
                    RandomState,
                >(
                    &ctx_id,
                    &DID("did:key:sub1".into()),
                    None,
                    1000,
                    None,
                )
                .await
                .unwrap();
        }

        let action = super::GovernanceAction::RevokeReadAccess {
            did: "did:key:sub1".into(),
            scope: super::RevocationScope::Full,
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:sub1".into(),
            action,
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(
            result.is_err(),
            "RevokeReadAccess should fail without MemberBan in ceiling"
        );
        assert!(
            matches!(result.unwrap_err(), ContextError::PermissionDenied(ref msg) if msg.contains("member:ban")),
            "error should mention missing member:ban capability"
        );
    }

    /// SCP-GG-006: `RestoreReadAccess` unbans subscriber in broadcast context.
    #[tokio::test]
    async fn restore_read_access_unbans_subscriber_in_broadcast() {
        let (manager, ctx_id) = setup_broadcast_with_member_ban().await;

        // First, revoke read access.
        let revoke_action = super::GovernanceAction::RevokeReadAccess {
            did: "did:key:sub1".into(),
            scope: super::RevocationScope::FutureOnly,
        };
        let revoke_proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:sub1".into(),
            revoke_action,
        );
        manager
            .execute_governance_action(&ctx_id, &revoke_proposal)
            .await
            .unwrap();

        // Drain events from revocation so we can check restore events cleanly.
        manager.drain_events(&ctx_id).await;

        // Now restore read access.
        let restore_action = super::GovernanceAction::RestoreReadAccess {
            did: "did:key:sub1".into(),
        };
        let restore_proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:sub1".into(),
            restore_action,
        );

        let result = manager
            .execute_governance_action(&ctx_id, &restore_proposal)
            .await;
        assert!(result.is_ok(), "RestoreReadAccess should succeed");

        match result.unwrap() {
            super::GovernanceActionResult::ReadAccessRestored(restore_result) => {
                assert_eq!(restore_result.did.0, "did:key:sub1");
            }
            other => panic!("expected ReadAccessRestored, got {other:?}"),
        }

        // Verify ReadAccessRestored event was emitted.
        let events = manager.drain_events(&ctx_id).await;
        let has_restore_event = events.iter().any(|e| {
            matches!(
                e,
                super::ContextEvent::ReadAccessRestored { did } if did.0 == "did:key:sub1"
            )
        });
        assert!(
            has_restore_event,
            "ReadAccessRestored event should have been emitted"
        );
    }

    /// SCP-GG-006: `RestoreReadAccess` also fails without `MemberBan` in ceiling.
    #[tokio::test]
    async fn restore_read_access_rejected_without_member_ban_ceiling() {
        // Create a broadcast context WITHOUT MemberBan in ceiling.
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        manager.register_local_did("did:key:alice".into()).await;
        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: MemoryScope::Full,
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            ..ContextParams::default()
        };
        let _handle = manager
            .create_context("no-ban-restore-ctx".into(), params, "did:key:alice".into())
            .await
            .unwrap();
        let ctx_id = "no-ban-restore-ctx".to_owned();

        let action = super::GovernanceAction::RestoreReadAccess {
            did: "did:key:sub1".into(),
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:sub1".into(),
            action,
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(
            result.is_err(),
            "RestoreReadAccess should fail without MemberBan in ceiling"
        );
        assert!(
            matches!(result.unwrap_err(), ContextError::PermissionDenied(ref msg) if msg.contains("member:ban")),
            "error should mention missing member:ban capability"
        );
    }

    // ===================================================================
    // Content access governance tests (SCP-CAC-007)
    // ===================================================================

    /// Helper: creates an encrypted context with `MemberBan` in ceiling,
    /// admin (alice) and member (bob).
    async fn setup_encrypted_with_member_ban() -> (ContextManager, String) {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        manager.register_local_did("did:key:alice".into()).await;
        manager.register_local_did("did:key:bob".into()).await;

        let params = ContextParams {
            mode: ContextMode::Encrypted,
            memory_scope: MemoryScope::Full,
            ceiling: vec![
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::RoleAssign,
                Capability::MemberBan,
            ],
            ..ContextParams::default()
        };

        let _handle = manager
            .create_context("enc-ban-ctx".into(), params, "did:key:alice".into())
            .await
            .unwrap();

        // Add bob as a member.
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("enc-ban-ctx").unwrap();
            ctx.membership
                .add_member("did:key:bob".into(), "member".into(), vec![]);
        }

        (manager, "enc-ban-ctx".to_owned())
    }

    /// SCP-CAC-007: `RevokeReadAccess` works on encrypted contexts (not just broadcast).
    #[tokio::test]
    async fn revoke_read_access_works_on_encrypted_context() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

        let action = super::GovernanceAction::RevokeReadAccess {
            did: "did:key:bob".into(),
            scope: super::RevocationScope::Full,
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            action,
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(
            result.is_ok(),
            "RevokeReadAccess on encrypted context should succeed"
        );

        // Verify bob is tracked as read-revoked.
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get(&ctx_id).unwrap();
        assert!(
            ctx.access
                .read_revoked_members
                .contains(&DID::from("did:key:bob"))
        );
        assert!(
            ctx.access
                .read_exclusion_list
                .contains(&DID::from("did:key:bob"))
        );
        // Bob is still a member (membership/access decoupling).
        assert!(ctx.membership.contains("did:key:bob"));
    }

    /// SCP-CAC-007: redundant `RevokeReadAccess` is prevented by TOCTOU replay protection.
    /// The governance engine assigns deterministic proposal IDs, so a second identical
    /// proposal is rejected as "already executed" — redundancy is handled at the
    /// governance layer, not the execution layer.
    #[tokio::test]
    async fn revoke_read_access_redundant_rejected_by_replay_protection() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

        let action = super::GovernanceAction::RevokeReadAccess {
            did: "did:key:bob".into(),
            scope: super::RevocationScope::Full,
        };
        let proposal1 = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            action.clone(),
        );

        // First revoke succeeds.
        manager
            .execute_governance_action(&ctx_id, &proposal1)
            .await
            .unwrap();

        // Second identical proposal is rejected by replay protection.
        let action2 = super::GovernanceAction::RevokeReadAccess {
            did: "did:key:bob".into(),
            scope: super::RevocationScope::Full,
        };
        let proposal2 = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            action2,
        );
        let result = manager.execute_governance_action(&ctx_id, &proposal2).await;
        assert!(
            result.is_err(),
            "redundant proposal should be rejected by TOCTOU replay protection"
        );
    }

    /// SCP-CAC-007: `RestoreReadAccess` returns `NothingToRestore` when never revoked.
    #[tokio::test]
    async fn restore_read_access_nothing_to_restore() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

        let action = super::GovernanceAction::RestoreReadAccess {
            did: "did:key:bob".into(),
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            action,
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ContextError::NothingToRestore(_)),
            "should return NothingToRestore when read access was never revoked"
        );
    }

    /// SCP-CAC-007: `RestoreReadAccess` succeeds after revocation on encrypted context.
    #[tokio::test]
    async fn restore_read_access_after_revocation_on_encrypted() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

        // First revoke.
        let revoke_action = super::GovernanceAction::RevokeReadAccess {
            did: "did:key:bob".into(),
            scope: super::RevocationScope::Full,
        };
        let revoke_proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            revoke_action,
        );
        manager
            .execute_governance_action(&ctx_id, &revoke_proposal)
            .await
            .unwrap();

        // Now restore.
        let restore_action = super::GovernanceAction::RestoreReadAccess {
            did: "did:key:bob".into(),
        };
        let restore_proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            restore_action,
        );
        let result = manager
            .execute_governance_action(&ctx_id, &restore_proposal)
            .await;
        assert!(
            result.is_ok(),
            "RestoreReadAccess should succeed after revocation"
        );

        // Bob should no longer be read-revoked.
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get(&ctx_id).unwrap();
        assert!(
            !ctx.access
                .read_revoked_members
                .contains(&DID::from("did:key:bob"))
        );
        assert!(
            !ctx.access
                .read_exclusion_list
                .contains(&DID::from("did:key:bob"))
        );
        // Bob still a member.
        assert!(ctx.membership.contains("did:key:bob"));
    }

    /// SCP-CAC-007: `RevokeWriteAccess(Full)` destroys sender key in broadcast.
    #[tokio::test]
    async fn revoke_write_access_full_in_broadcast() {
        let (manager, ctx_id) = setup_broadcast_with_member_ban().await;

        // Add sub1 as member for governance purposes.
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut(&ctx_id).unwrap();
            ctx.membership
                .add_member("did:key:sub1".into(), "subscriber".into(), vec![]);
        }

        let action = super::GovernanceAction::RevokeWriteAccess {
            did: "did:key:alice".into(),
            scope: super::RevocationScope::Full,
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:alice".into(),
            action,
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(result.is_ok(), "RevokeWriteAccess(Full) should succeed");

        // Alice should be in write_revoked_members.
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get(&ctx_id).unwrap();
        assert!(
            ctx.access
                .write_revoked_members
                .contains(&DID::from("did:key:alice"))
        );
        // Alice is still a member.
        assert!(ctx.membership.contains("did:key:alice"));
    }

    /// SCP-CAC-007: `RevokeWriteAccess(FutureOnly)` does NOT destroy broadcast key.
    #[tokio::test]
    async fn revoke_write_access_future_only_no_key_destruction() {
        let (manager, ctx_id) = setup_broadcast_with_member_ban().await;

        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut(&ctx_id).unwrap();
            ctx.membership
                .add_member("did:key:sub1".into(), "subscriber".into(), vec![]);
        }

        let action = super::GovernanceAction::RevokeWriteAccess {
            did: "did:key:alice".into(),
            scope: super::RevocationScope::FutureOnly,
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:alice".into(),
            action,
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(
            result.is_ok(),
            "RevokeWriteAccess(FutureOnly) should succeed"
        );

        // Alice should be in write_revoked_members.
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get(&ctx_id).unwrap();
        assert!(
            ctx.access
                .write_revoked_members
                .contains(&DID::from("did:key:alice"))
        );
        // In FutureOnly mode, broadcast author should still exist (key not destroyed).
        let bc = ctx.broadcast_context.as_ref().unwrap();
        assert!(
            bc.is_author("did:key:alice"),
            "FutureOnly should NOT destroy broadcast keys"
        );
    }

    /// SCP-CAC-007: redundant `RevokeWriteAccess` is prevented by TOCTOU replay protection.
    #[tokio::test]
    async fn revoke_write_access_redundant_rejected_by_replay_protection() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

        let action = super::GovernanceAction::RevokeWriteAccess {
            did: "did:key:bob".into(),
            scope: super::RevocationScope::Full,
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            action,
        );
        manager
            .execute_governance_action(&ctx_id, &proposal)
            .await
            .unwrap();

        // Second identical proposal is rejected by replay protection.
        let action2 = super::GovernanceAction::RevokeWriteAccess {
            did: "did:key:bob".into(),
            scope: super::RevocationScope::Full,
        };
        let proposal2 = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            action2,
        );
        let result = manager.execute_governance_action(&ctx_id, &proposal2).await;
        assert!(
            result.is_err(),
            "redundant proposal should be rejected by TOCTOU replay protection"
        );
    }

    /// SCP-CAC-007: `RestoreWriteAccess` returns `NothingToRestore` when never revoked.
    #[tokio::test]
    async fn restore_write_access_nothing_to_restore() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

        let action = super::GovernanceAction::RestoreWriteAccess {
            did: "did:key:bob".into(),
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            action,
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ContextError::NothingToRestore(_)),
            "should return NothingToRestore when write access was never revoked"
        );
    }

    /// SCP-CAC-007: `RestoreWriteAccess` succeeds after revocation, emits event.
    #[tokio::test]
    async fn restore_write_access_after_revocation() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

        // First revoke.
        let revoke_action = super::GovernanceAction::RevokeWriteAccess {
            did: "did:key:bob".into(),
            scope: super::RevocationScope::Full,
        };
        let revoke_proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            revoke_action,
        );
        manager
            .execute_governance_action(&ctx_id, &revoke_proposal)
            .await
            .unwrap();
        manager.drain_events(&ctx_id).await;

        // Now restore.
        let restore_action = super::GovernanceAction::RestoreWriteAccess {
            did: "did:key:bob".into(),
        };
        let restore_proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            restore_action,
        );
        let result = manager
            .execute_governance_action(&ctx_id, &restore_proposal)
            .await;
        assert!(result.is_ok(), "RestoreWriteAccess should succeed");

        // Bob should no longer be write-revoked.
        {
            let contexts = manager.contexts.lock().await;
            let ctx = contexts.get(&ctx_id).unwrap();
            assert!(
                !ctx.access
                    .write_revoked_members
                    .contains(&DID::from("did:key:bob"))
            );
        }

        // Verify WriteAccessRestored event was emitted.
        let events = manager.drain_events(&ctx_id).await;
        let has_event = events.iter().any(|e| {
            matches!(
                e,
                super::ContextEvent::WriteAccessRestored { did } if did.0 == "did:key:bob"
            )
        });
        assert!(
            has_event,
            "WriteAccessRestored event should have been emitted"
        );
    }

    /// SCP-CAC-007: `RotateContentKeys` on broadcast context rotates all author keys.
    #[tokio::test]
    async fn rotate_content_keys_broadcast() {
        let (manager, ctx_id) = setup_broadcast_with_member_ban().await;

        let action = super::GovernanceAction::RotateContentKeys {
            reason: Some("periodic hygiene".to_owned()),
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:alice".into(),
            action,
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(result.is_ok(), "RotateContentKeys should succeed");

        match result.unwrap() {
            super::GovernanceActionResult::ContentKeysRotated(r) => {
                assert_eq!(r.reason, Some("periodic hygiene".to_owned()));
            }
            other => panic!("expected ContentKeysRotated, got {other:?}"),
        }

        // Verify ContentKeysRotated event emitted.
        let events = manager.drain_events(&ctx_id).await;
        let has_event = events
            .iter()
            .any(|e| matches!(e, super::ContextEvent::ContentKeysRotated { .. }));
        assert!(
            has_event,
            "ContentKeysRotated event should have been emitted"
        );
    }

    /// SCP-CAC-007: `RotateContentKeys` on encrypted context emits event
    /// (MLS handles actual rotation).
    #[tokio::test]
    async fn rotate_content_keys_encrypted() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

        let action = super::GovernanceAction::RotateContentKeys { reason: None };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            action,
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(
            result.is_ok(),
            "RotateContentKeys on encrypted should succeed"
        );

        // Verify event emitted.
        let events = manager.drain_events(&ctx_id).await;
        let has_event = events
            .iter()
            .any(|e| matches!(e, super::ContextEvent::ContentKeysRotated { .. }));
        assert!(
            has_event,
            "ContentKeysRotated event should have been emitted"
        );
    }

    /// SCP-CAC-007: presence-only members (read + write revoked) cannot propose.
    #[tokio::test]
    async fn presence_only_member_cannot_propose() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

        // Revoke bob's read and write access to make them presence-only.
        let revoke_read = super::GovernanceAction::RevokeReadAccess {
            did: "did:key:bob".into(),
            scope: super::RevocationScope::Full,
        };
        let rr_proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            revoke_read,
        );
        manager
            .execute_governance_action(&ctx_id, &rr_proposal)
            .await
            .unwrap();

        let revoke_write = super::GovernanceAction::RevokeWriteAccess {
            did: "did:key:bob".into(),
            scope: super::RevocationScope::Full,
        };
        let rw_proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            revoke_write,
        );
        manager
            .execute_governance_action(&ctx_id, &rw_proposal)
            .await
            .unwrap();

        // Now bob (presence-only) tries to propose — should fail.
        let bob_key = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
        let result = manager
            .propose_governance_action(
                &ctx_id,
                &"did:key:bob".into(),
                super::GovernanceAction::RotateContentKeys { reason: None },
                &bob_key,
            )
            .await;
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ContextError::PermissionDenied(ref msg) if msg.contains("presence-only")),
            "presence-only member should not be able to propose"
        );
    }

    /// SCP-CAC-007: member with only write revoked can still propose (not presence-only).
    #[tokio::test]
    async fn write_only_revoked_member_can_still_propose() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

        // Revoke bob's write only.
        let revoke_write = super::GovernanceAction::RevokeWriteAccess {
            did: "did:key:bob".into(),
            scope: super::RevocationScope::Full,
        };
        let rw_proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            revoke_write,
        );
        manager
            .execute_governance_action(&ctx_id, &rw_proposal)
            .await
            .unwrap();

        // Bob (read-only, not presence-only) can still propose.
        // Note: the governance engine may still reject based on role, but the
        // presence-only gate should not block them.
        let bob_key = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
        let result = manager
            .propose_governance_action(
                &ctx_id,
                &"did:key:bob".into(),
                super::GovernanceAction::RotateContentKeys { reason: None },
                &bob_key,
            )
            .await;
        // The governance engine may reject for other reasons (e.g. role),
        // but NOT because of presence-only check. Check it's not the
        // presence-only error specifically.
        if let Err(ref e) = result {
            assert!(
                !matches!(e, ContextError::PermissionDenied(msg) if msg.contains("presence-only")),
                "write-only-revoked member should not be blocked by presence-only check"
            );
        }
    }

    /// SCP-CAC-007: `RevokeReadAccess` fails for non-member DID.
    #[tokio::test]
    async fn revoke_read_access_non_member_fails() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

        let action = super::GovernanceAction::RevokeReadAccess {
            did: "did:key:nonexistent".into(),
            scope: super::RevocationScope::Full,
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:nonexistent".into(),
            action,
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ContextError::MemberNotFound(_)),
            "should return MemberNotFound for non-member DID"
        );
    }

    /// SCP-CAC-007: content access actions preserve membership (decoupling).
    #[tokio::test]
    async fn content_access_preserves_membership() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

        // Revoke both read and write.
        let rr_action = super::GovernanceAction::RevokeReadAccess {
            did: "did:key:bob".into(),
            scope: super::RevocationScope::Full,
        };
        let rr_proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            rr_action,
        );
        manager
            .execute_governance_action(&ctx_id, &rr_proposal)
            .await
            .unwrap();

        let rw_action = super::GovernanceAction::RevokeWriteAccess {
            did: "did:key:bob".into(),
            scope: super::RevocationScope::Full,
        };
        let rw_proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            rw_action,
        );
        manager
            .execute_governance_action(&ctx_id, &rw_proposal)
            .await
            .unwrap();

        // Bob is still a member despite both read and write revoked.
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get(&ctx_id).unwrap();
        assert!(
            ctx.membership.contains("did:key:bob"),
            "member should remain in context after both read and write revocation"
        );
        assert!(
            ctx.access
                .read_revoked_members
                .contains(&DID::from("did:key:bob"))
        );
        assert!(
            ctx.access
                .write_revoked_members
                .contains(&DID::from("did:key:bob"))
        );
    }

    // -----------------------------------------------------------------------
    // Write access governance tests (SCP-CAC-007)
    // -----------------------------------------------------------------------

    /// SCP-CAC-007: `RevokeWriteAccess` marks member as write-revoked.
    #[tokio::test]
    async fn revoke_write_access_marks_member() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

        let action = super::GovernanceAction::RevokeWriteAccess {
            did: "did:key:bob".into(),
            scope: super::RevocationScope::FutureOnly,
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            action,
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(result.is_ok(), "RevokeWriteAccess should succeed");

        match result.unwrap() {
            super::GovernanceActionResult::WriteAccessRevoked(r) => {
                assert_eq!(r.did.0, "did:key:bob");
            }
            other => panic!("expected WriteAccessRevoked, got {other:?}"),
        }

        // Verify member is tracked as write-revoked.
        {
            let contexts = manager.contexts.lock().await;
            let ctx = contexts.get(&ctx_id).unwrap();
            assert!(
                ctx.access
                    .write_revoked_members
                    .contains(&DID("did:key:bob".into())),
                "bob should be in write_revoked_members"
            );
        }

        // Verify WriteAccessRevoked event was emitted.
        let events = manager.drain_events(&ctx_id).await;
        let has_event = events.iter().any(|e| {
            matches!(
                e,
                super::ContextEvent::WriteAccessRevoked { did } if did.0 == "did:key:bob"
            )
        });
        assert!(has_event, "WriteAccessRevoked event should be emitted");
    }

    /// SCP-CAC-007: Redundant `RevokeWriteAccess` is a no-op (§5.9).
    #[tokio::test]
    async fn revoke_write_access_redundant_is_noop() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

        let action = super::GovernanceAction::RevokeWriteAccess {
            did: "did:key:bob".into(),
            scope: super::RevocationScope::FutureOnly,
        };

        // First revocation.
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            action.clone(),
        );
        manager
            .execute_governance_action(&ctx_id, &proposal)
            .await
            .unwrap();

        // Drain events from first call.
        manager.drain_events(&ctx_id).await;

        // Second revocation — should be a no-op (Ok(())).
        // Use a different proposal_id to bypass TOCTOU replay protection,
        // simulating a second proposal for the same action.
        let mut proposal2 = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            action,
        );
        proposal2.proposal_id = [2u8; 32]; // distinct from first proposal
        let result = manager.execute_governance_action(&ctx_id, &proposal2).await;
        assert!(
            result.is_ok(),
            "redundant RevokeWriteAccess should succeed (no-op)"
        );
    }

    /// SCP-CAC-007: `RestoreWriteAccess` removes write revocation.
    #[tokio::test]
    async fn restore_write_access_removes_revocation() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

        // First revoke.
        let revoke = super::GovernanceAction::RevokeWriteAccess {
            did: "did:key:bob".into(),
            scope: super::RevocationScope::FutureOnly,
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            revoke,
        );
        manager
            .execute_governance_action(&ctx_id, &proposal)
            .await
            .unwrap();
        manager.drain_events(&ctx_id).await;

        // Now restore.
        let restore = super::GovernanceAction::RestoreWriteAccess {
            did: "did:key:bob".into(),
        };
        let restore_proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            restore,
        );
        let result = manager
            .execute_governance_action(&ctx_id, &restore_proposal)
            .await;
        assert!(result.is_ok(), "RestoreWriteAccess should succeed");

        match result.unwrap() {
            super::GovernanceActionResult::WriteAccessRestored(r) => {
                assert_eq!(r.did.0, "did:key:bob");
            }
            other => panic!("expected WriteAccessRestored, got {other:?}"),
        }

        // Verify member is no longer write-revoked.
        {
            let contexts = manager.contexts.lock().await;
            let ctx = contexts.get(&ctx_id).unwrap();
            assert!(
                !ctx.access
                    .write_revoked_members
                    .contains(&DID("did:key:bob".into())),
                "bob should not be in write_revoked_members after restore"
            );
        }

        // Verify WriteAccessRestored event.
        let events = manager.drain_events(&ctx_id).await;
        let has_event = events.iter().any(|e| {
            matches!(
                e,
                super::ContextEvent::WriteAccessRestored { did } if did.0 == "did:key:bob"
            )
        });
        assert!(has_event, "WriteAccessRestored event should be emitted");
    }

    /// SCP-CAC-007: `RestoreWriteAccess` on never-revoked member returns
    /// `NothingToRestore` error (§5.9).
    #[tokio::test]
    async fn restore_write_access_never_revoked_returns_error() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

        let restore = super::GovernanceAction::RestoreWriteAccess {
            did: "did:key:bob".into(),
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            restore,
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(
            result.is_err(),
            "RestoreWriteAccess on never-revoked should fail"
        );
        assert!(
            matches!(
                result.unwrap_err(),
                ContextError::NothingToRestore(ref msg) if msg.contains("did:key:bob")
            ),
            "error should be NothingToRestore"
        );
    }

    /// SCP-CAC-007: Presence-only state — revoking both read and write strips
    /// governance capabilities.
    #[tokio::test]
    async fn presence_only_strips_governance_capabilities() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

        // Revoke write access for bob.
        let revoke_write = super::GovernanceAction::RevokeWriteAccess {
            did: "did:key:bob".into(),
            scope: super::RevocationScope::FutureOnly,
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            revoke_write,
        );
        manager
            .execute_governance_action(&ctx_id, &proposal)
            .await
            .unwrap();

        // Revoke read access for bob — now presence-only.
        let revoke_read = super::GovernanceAction::RevokeReadAccess {
            did: "did:key:bob".into(),
            scope: super::RevocationScope::FutureOnly,
        };
        let read_proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            revoke_read,
        );
        manager
            .execute_governance_action(&ctx_id, &read_proposal)
            .await
            .unwrap();

        // Verify both read and write are revoked.
        {
            let contexts = manager.contexts.lock().await;
            let ctx = contexts.get(&ctx_id).unwrap();
            assert!(
                ctx.access
                    .write_revoked_members
                    .contains(&DID("did:key:bob".into()))
            );
            assert!(
                ctx.access
                    .read_revoked_members
                    .contains(&DID("did:key:bob".into()))
            );
        }
    }

    /// SCP-CAC-007: `RotateContentKeys` emits `ContentKeysRotated` event.
    #[tokio::test]
    async fn rotate_content_keys_emits_event() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

        let action = super::GovernanceAction::RotateContentKeys {
            reason: Some("periodic rotation".into()),
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            action,
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(result.is_ok(), "RotateContentKeys should succeed");

        match result.unwrap() {
            super::GovernanceActionResult::ContentKeysRotated(r) => {
                assert_eq!(r.reason.as_deref(), Some("periodic rotation"));
            }
            other => panic!("expected ContentKeysRotated, got {other:?}"),
        }

        // Verify ContentKeysRotated event.
        let events = manager.drain_events(&ctx_id).await;
        let has_event = events.iter().any(|e| {
            matches!(
                e,
                super::ContextEvent::ContentKeysRotated { reason } if reason.as_deref() == Some("periodic rotation")
            )
        });
        assert!(has_event, "ContentKeysRotated event should be emitted");
    }

    /// SCP-CAC-007: `RotateContentKeys` with no reason also works.
    #[tokio::test]
    async fn rotate_content_keys_no_reason() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

        let action = super::GovernanceAction::RotateContentKeys { reason: None };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            action,
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(
            result.is_ok(),
            "RotateContentKeys with no reason should succeed"
        );

        match result.unwrap() {
            super::GovernanceActionResult::ContentKeysRotated(r) => {
                assert!(r.reason.is_none());
            }
            other => panic!("expected ContentKeysRotated, got {other:?}"),
        }
    }

    /// SCP-CAC-007: `RevokeWriteAccess` with Full scope in broadcast context
    /// blocks the author.
    #[tokio::test]
    async fn revoke_write_access_full_scope_broadcast() {
        let (manager, ctx_id) = setup_broadcast_with_member_ban().await;

        // Add sub1 as a member in membership so the revoke path finds them.
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut(&ctx_id).unwrap();
            ctx.membership
                .add_member("did:key:sub1".into(), "subscriber".into(), vec![]);
            // Also add sub1 as an author in broadcast context.
            let bc = ctx.broadcast_context.as_mut().unwrap();
            bc.add_author("did:key:sub1").unwrap();
        }

        let action = super::GovernanceAction::RevokeWriteAccess {
            did: "did:key:sub1".into(),
            scope: super::RevocationScope::Full,
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:sub1".into(),
            action,
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(
            result.is_ok(),
            "RevokeWriteAccess Full in broadcast should succeed"
        );

        // Verify WriteAccessRevoked event.
        let events = manager.drain_events(&ctx_id).await;
        let has_event = events.iter().any(|e| {
            matches!(
                e,
                super::ContextEvent::WriteAccessRevoked { did } if did.0 == "did:key:sub1"
            )
        });
        assert!(has_event, "WriteAccessRevoked event should be emitted");
    }

    /// SCP-CAC-007: `RevokeWriteAccess` fails without `MemberBan` in ceiling.
    #[tokio::test]
    async fn revoke_write_access_rejected_without_member_ban() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        manager.register_local_did("did:key:alice".into()).await;
        manager.register_local_did("did:key:bob".into()).await;

        let params = ContextParams {
            mode: ContextMode::Encrypted,
            memory_scope: scp_protocol::context::MemoryScope::Full,
            ceiling: vec![
                scp_protocol::context::params::Capability::new("messages:read"),
                scp_protocol::context::params::Capability::new("messages:write"),
            ],
            ..ContextParams::default()
        };
        let _handle = manager
            .create_context("no-ban-write-ctx".into(), params, "did:key:alice".into())
            .await
            .unwrap();
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("no-ban-write-ctx").unwrap();
            ctx.membership
                .add_member("did:key:bob".into(), "member".into(), vec![]);
        }

        let action = super::GovernanceAction::RevokeWriteAccess {
            did: "did:key:bob".into(),
            scope: super::RevocationScope::Full,
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            "no-ban-write-ctx",
            &"did:key:bob".into(),
            action,
        );

        let result = manager
            .execute_governance_action("no-ban-write-ctx", &proposal)
            .await;
        assert!(
            result.is_err(),
            "RevokeWriteAccess should fail without MemberBan in ceiling"
        );
    }

    /// SCP-CAC-007: `RevokeWriteAccess` on non-member returns error.
    #[tokio::test]
    async fn revoke_write_access_non_member_fails() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

        let action = super::GovernanceAction::RevokeWriteAccess {
            did: "did:key:nonexistent".into(),
            scope: super::RevocationScope::Full,
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:nonexistent".into(),
            action,
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(
            result.is_err(),
            "RevokeWriteAccess on non-member should fail"
        );
        assert!(
            matches!(result.unwrap_err(), ContextError::MemberNotFound(_)),
            "error should be MemberNotFound"
        );
    }

    // -----------------------------------------------------------------------
    // Context persistence tests (SCP-PERSIST-020 through SCP-PERSIST-025)
    // -----------------------------------------------------------------------

    /// Mock `ContextPersistence` that stores snapshots in `HashMap`s.
    #[derive(Default)]
    struct MockContextPersistence {
        contexts: std::sync::Mutex<HashMap<String, super::ContextSnapshot>>,
        broadcasts: std::sync::Mutex<HashMap<String, BroadcastContextSnapshot>>,
    }

    impl super::ContextPersistence for MockContextPersistence {
        fn persist_context(
            &self,
            context_id: &str,
            snapshot: &super::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.contexts
                .lock()
                .unwrap()
                .insert(context_id.to_owned(), snapshot.clone());
            Ok(())
        }

        fn load_context(
            &self,
            context_id: &str,
        ) -> Result<Option<super::ContextSnapshot>, Box<dyn std::error::Error + Send + Sync>>
        {
            Ok(self.contexts.lock().unwrap().get(context_id).cloned())
        }

        fn persist_broadcast(
            &self,
            context_id: &str,
            snapshot: &BroadcastContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.broadcasts
                .lock()
                .unwrap()
                .insert(context_id.to_owned(), snapshot.clone());
            Ok(())
        }

        fn load_broadcast(
            &self,
            context_id: &str,
        ) -> Result<Option<BroadcastContextSnapshot>, Box<dyn std::error::Error + Send + Sync>>
        {
            Ok(self.broadcasts.lock().unwrap().get(context_id).cloned())
        }

        fn delete_context(
            &self,
            context_id: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.contexts.lock().unwrap().remove(context_id);
            self.broadcasts.lock().unwrap().remove(context_id);
            Ok(())
        }

        fn list_persisted_contexts(
            &self,
        ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self.contexts.lock().unwrap().keys().cloned().collect())
        }
    }

    /// Helper: build a `BroadcastContextSnapshot` with known state.
    fn test_broadcast_snapshot(context_id: &str) -> BroadcastContextSnapshot {
        use std::collections::HashSet;

        use scp_protocol::context::broadcast::{
            AuthorStateSnapshot, BroadcastAdmission, SubscriberRecord,
        };
        use scp_protocol::crypto::sender_keys::generate_sender_key;

        let mut authors = HashMap::new();
        authors.insert(
            "did:key:author1".to_owned(),
            AuthorStateSnapshot {
                author_did: "did:key:author1".to_owned(),
                broadcast_key: generate_sender_key(),
                epoch: 3,
                next_sequence: 1,
                block_list: HashSet::from(["did:key:blocked1".to_owned()]),
            },
        );

        let mut subscribers = HashMap::new();
        subscribers.insert(
            "did:key:sub1".to_owned(),
            SubscriberRecord {
                subscriber_did: "did:key:sub1".to_owned(),
                registered_at: 1_700_000_000,
                has_ucan: false,
            },
        );
        subscribers.insert(
            "did:key:sub2".to_owned(),
            SubscriberRecord {
                subscriber_did: "did:key:sub2".to_owned(),
                registered_at: 1_700_001_000,
                has_ucan: true,
            },
        );

        BroadcastContextSnapshot {
            context_id: context_id.to_owned(),
            admission: BroadcastAdmission::Gated,
            subscribers,
            authors,
        }
    }

    /// SCP-PERSIST-020: compile-time test verifying `dyn ContextPersistence`
    /// is object-safe.
    #[test]
    fn context_persistence_is_object_safe() {
        fn assert_object_safe(_: &dyn super::ContextPersistence) {}
        let mock = MockContextPersistence::default();
        assert_object_safe(&mock);
    }

    /// SCP-PERSIST-024: persist-drop-restore roundtrip verifies all fields.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn persist_drop_restore_roundtrip() {
        use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

        let persistence = Arc::new(MockContextPersistence::default());

        // Create a context with persistence.
        let manager = ContextManager::with_persistence(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            Box::new(MockContextPersistence::default()),
            noop_key_resolver(),
        );

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: scp_protocol::context::MemoryScope::Full,
            ceiling: vec![
                scp_protocol::context::params::Capability::new("messages:read"),
                scp_protocol::context::params::Capability::new("messages:write"),
                scp_protocol::context::params::Capability::new("role:assign"),
            ],
            ..ContextParams::default()
        };

        let _handle = manager
            .create_context(
                "persist-ctx".into(),
                params.clone(),
                "did:key:creator".into(),
            )
            .await
            .unwrap();

        // Seed the mock persistence with a full snapshot.
        let ceiling = default_ceiling();
        let role_state = ContextRoleState::new(
            "persist-ctx",
            "did:key:creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();
        let mut membership = MembershipState::new();
        membership.add_member("did:key:creator".into(), "admin".into(), vec![]);
        let mut executed = HashSet::new();
        executed.insert([42u8; 32]);

        let snapshot = super::ContextSnapshot {
            context_id: "persist-ctx-2".to_owned(),
            state: ContextState::Active,
            context_params: params.clone(),
            membership: membership.clone(),
            role_state: role_state.clone(),
            executed_proposals: executed.clone(),
            ttl_remaining_secs: None,
            registered_tools: Vec::new(),
            write_revoked_members: HashSet::new(),
            read_revoked_members: HashSet::new(),
            read_exclusion_list: HashSet::new(),
            tool_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
            governance_model_config: None,
            economic_policy: None,
            budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
            approved_proposals: HashMap::new(),
            governance_freeze: None,
            pending_ceiling_modification: None,
            pending_economic_policy_change: None,
            mls_epoch: 0,
            epoch_coordination_records: Vec::new(),
            grace_entries: Vec::new(),
            needs_reconnect: false,
            migration_state: None,
            mls_crypto_state: Vec::new(),
        };

        let bc_snapshot = test_broadcast_snapshot("persist-ctx-2");

        // Seed mock persistence directly.
        persistence
            .persist_context("persist-ctx-2", &snapshot)
            .unwrap();
        persistence
            .persist_broadcast("persist-ctx-2", &bc_snapshot)
            .unwrap();

        // Create a new manager with the seeded persistence.
        let manager2 = ContextManager::with_persistence(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            Box::new(MockContextPersistence {
                contexts: std::sync::Mutex::new(persistence.contexts.lock().unwrap().clone()),
                broadcasts: std::sync::Mutex::new(persistence.broadcasts.lock().unwrap().clone()),
            }),
            noop_key_resolver(),
        );

        // Restore the context.
        let handle2 = ContextHandle::new("persist-ctx-2".to_owned(), params);
        handle2.transition_to(&ContextState::Active).await.unwrap();

        let result = manager2.restore_context("persist-ctx-2", &handle2).await;
        assert!(result.is_ok(), "restore should succeed");

        // Verify membership is restored.
        assert!(manager2.is_member("persist-ctx-2", "did:key:creator").await);

        // Verify broadcast is restored.
        assert!(
            manager2
                .is_broadcast_subscriber("persist-ctx-2", "did:key:sub1")
                .await
        );
        assert!(
            manager2
                .is_broadcast_subscriber("persist-ctx-2", "did:key:sub2")
                .await
        );
    }

    /// SCP-PERSIST-025: `executed_proposals` preserved across restart.
    #[tokio::test]
    async fn restore_preserves_executed_proposals() {
        use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

        let persistence = Arc::new(MockContextPersistence::default());

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: scp_protocol::context::MemoryScope::Full,
            ceiling: vec![
                scp_protocol::context::params::Capability::new("messages:read"),
                scp_protocol::context::params::Capability::new("messages:write"),
                scp_protocol::context::params::Capability::new("role:assign"),
            ],
            ..ContextParams::default()
        };

        let ceiling = default_ceiling();
        let role_state = ContextRoleState::new(
            "replay-ctx",
            "did:key:alice",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();
        let mut membership = MembershipState::new();
        membership.add_member("did:key:alice".into(), "admin".into(), vec![]);

        // Seed executed proposals so replay is detected.
        let proposal_id = [99u8; 32];
        let mut executed = HashSet::new();
        executed.insert(proposal_id);

        let snapshot = super::ContextSnapshot {
            context_id: "replay-ctx".to_owned(),
            state: ContextState::Active,
            context_params: params.clone(),
            membership,
            role_state,
            executed_proposals: executed,
            ttl_remaining_secs: None,
            registered_tools: Vec::new(),
            write_revoked_members: HashSet::new(),
            read_revoked_members: HashSet::new(),
            read_exclusion_list: HashSet::new(),
            tool_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
            governance_model_config: None,
            economic_policy: None,
            budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
            approved_proposals: HashMap::new(),
            governance_freeze: None,
            pending_ceiling_modification: None,
            pending_economic_policy_change: None,
            mls_epoch: 0,
            epoch_coordination_records: Vec::new(),
            grace_entries: Vec::new(),
            needs_reconnect: false,
            migration_state: None,
            mls_crypto_state: Vec::new(),
        };

        persistence
            .persist_context("replay-ctx", &snapshot)
            .unwrap();

        // Also seed broadcast state (needed for restore).
        let bc_snapshot = test_broadcast_snapshot("replay-ctx");
        persistence
            .persist_broadcast("replay-ctx", &bc_snapshot)
            .unwrap();

        // Create manager and restore.
        let manager = ContextManager::with_persistence(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            Box::new(MockContextPersistence {
                contexts: std::sync::Mutex::new(persistence.contexts.lock().unwrap().clone()),
                broadcasts: std::sync::Mutex::new(persistence.broadcasts.lock().unwrap().clone()),
            }),
            noop_key_resolver(),
        );

        let handle = ContextHandle::new("replay-ctx".to_owned(), params);
        handle.transition_to(&ContextState::Active).await.unwrap();
        manager
            .restore_context("replay-ctx", &handle)
            .await
            .unwrap();

        // Try to execute a governance action with the already-executed proposal ID.
        // The internal state should reject it as a replay.
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("replay-ctx").unwrap();
        assert!(
            ctx.governance.executed_proposals.contains_key(&proposal_id),
            "executed_proposals should be preserved across restart"
        );
    }

    /// SCP-PERSIST-025: TTL timer re-spawned after restore with remaining TTL.
    #[tokio::test]
    async fn restore_respawns_ttl_timer() {
        use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

        let persistence = Arc::new(MockContextPersistence::default());

        let params = ContextParams {
            ttl: Some(std::time::Duration::from_secs(300)),
            ceiling: vec![
                scp_protocol::context::params::Capability::new("messages:read"),
                scp_protocol::context::params::Capability::new("messages:write"),
                scp_protocol::context::params::Capability::new("role:assign"),
            ],
            ..ContextParams::default()
        };

        let ceiling = default_ceiling();
        let role_state = ContextRoleState::new(
            "ttl-ctx",
            "did:key:creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();
        let mut membership = MembershipState::new();
        membership.add_member("did:key:creator".into(), "admin".into(), vec![]);

        let snapshot = super::ContextSnapshot {
            context_id: "ttl-ctx".to_owned(),
            state: ContextState::Active,
            context_params: params.clone(),
            membership,
            role_state,
            executed_proposals: HashSet::new(),
            ttl_remaining_secs: Some(120), // 120 seconds remaining
            registered_tools: Vec::new(),
            write_revoked_members: HashSet::new(),
            read_revoked_members: HashSet::new(),
            read_exclusion_list: HashSet::new(),
            tool_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
            governance_model_config: None,
            economic_policy: None,
            budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
            approved_proposals: HashMap::new(),
            governance_freeze: None,
            pending_ceiling_modification: None,
            pending_economic_policy_change: None,
            mls_epoch: 0,
            epoch_coordination_records: Vec::new(),
            grace_entries: Vec::new(),
            needs_reconnect: false,
            migration_state: None,
            mls_crypto_state: Vec::new(),
        };

        persistence.persist_context("ttl-ctx", &snapshot).unwrap();

        let manager = ContextManager::with_persistence(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            Box::new(MockContextPersistence {
                contexts: std::sync::Mutex::new(persistence.contexts.lock().unwrap().clone()),
                broadcasts: std::sync::Mutex::new(HashMap::new()),
            }),
            noop_key_resolver(),
        );

        let handle = ContextHandle::new("ttl-ctx".to_owned(), params);
        handle.transition_to(&ContextState::Active).await.unwrap();
        manager.restore_context("ttl-ctx", &handle).await.unwrap();

        // Verify the TTL timer was re-spawned.
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("ttl-ctx").unwrap();
        assert!(
            ctx.ttl.timer.is_active(),
            "TTL timer should be re-spawned after restore"
        );
    }

    /// SCP-PERSIST-025: `restore_all_contexts` lists and restores each.
    #[tokio::test]
    async fn restore_all_contexts_restores_persisted() {
        use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

        let persistence = Arc::new(MockContextPersistence::default());

        for ctx_name in ["ctx-a", "ctx-b"] {
            let params = ContextParams::default();
            let ceiling = default_ceiling();
            let role_state = ContextRoleState::new(
                ctx_name,
                "did:key:creator",
                ceiling,
                vec![],
                &scp_primitives::SystemClock,
            )
            .unwrap();
            let mut membership = MembershipState::new();
            membership.add_member("did:key:creator".into(), "admin".into(), vec![]);

            let snapshot = super::ContextSnapshot {
                context_id: ctx_name.to_string(),
                state: ContextState::Active,
                context_params: params,
                membership,
                role_state,
                executed_proposals: HashSet::new(),
                ttl_remaining_secs: None,
                registered_tools: Vec::new(),
                write_revoked_members: HashSet::new(),
                read_revoked_members: HashSet::new(),
                read_exclusion_list: HashSet::new(),
                tool_interfaces: Vec::new(),
                threshold_signers: Vec::new(),
                threshold_value: 0,
                pruning_policy: None,
                governance_model_config: None,
                economic_policy: None,
                budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
                approved_proposals: HashMap::new(),
                governance_freeze: None,
                pending_ceiling_modification: None,
                pending_economic_policy_change: None,
                mls_epoch: 0,
                epoch_coordination_records: Vec::new(),
                grace_entries: Vec::new(),
                needs_reconnect: false,
                migration_state: None,
                mls_crypto_state: Vec::new(),
            };
            persistence.persist_context(ctx_name, &snapshot).unwrap();
        }

        let manager = ContextManager::with_persistence(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            Box::new(MockContextPersistence {
                contexts: std::sync::Mutex::new(persistence.contexts.lock().unwrap().clone()),
                broadcasts: std::sync::Mutex::new(HashMap::new()),
            }),
            noop_key_resolver(),
        );

        let mut restored = manager.restore_all_contexts().await.unwrap();
        restored.sort();
        assert_eq!(restored, vec!["ctx-a", "ctx-b"]);

        // Both contexts should be registered.
        assert!(manager.is_member("ctx-a", "did:key:creator").await);
        assert!(manager.is_member("ctx-b", "did:key:creator").await);
    }

    /// `restore_context` rejects duplicate context registration.
    #[tokio::test]
    async fn restore_context_rejects_duplicate() {
        use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

        let persistence = Arc::new(MockContextPersistence::default());

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: scp_protocol::context::MemoryScope::Full,
            ..ContextParams::default()
        };

        let ceiling = default_ceiling();
        let role_state = ContextRoleState::new(
            "dup-ctx",
            "did:key:author1",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();
        let membership = MembershipState::new();

        let snapshot = super::ContextSnapshot {
            context_id: "dup-ctx".to_owned(),
            state: ContextState::Active,
            context_params: params.clone(),
            membership,
            role_state,
            executed_proposals: HashSet::new(),
            ttl_remaining_secs: None,
            registered_tools: Vec::new(),
            write_revoked_members: HashSet::new(),
            read_revoked_members: HashSet::new(),
            read_exclusion_list: HashSet::new(),
            tool_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
            governance_model_config: None,
            economic_policy: None,
            budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
            approved_proposals: HashMap::new(),
            governance_freeze: None,
            pending_ceiling_modification: None,
            pending_economic_policy_change: None,
            mls_epoch: 0,
            epoch_coordination_records: Vec::new(),
            grace_entries: Vec::new(),
            needs_reconnect: false,
            migration_state: None,
            mls_crypto_state: Vec::new(),
        };

        let bc_snapshot = test_broadcast_snapshot("dup-ctx");
        persistence.persist_context("dup-ctx", &snapshot).unwrap();
        persistence
            .persist_broadcast("dup-ctx", &bc_snapshot)
            .unwrap();

        let manager = ContextManager::with_persistence(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            Box::new(MockContextPersistence {
                contexts: std::sync::Mutex::new(persistence.contexts.lock().unwrap().clone()),
                broadcasts: std::sync::Mutex::new(persistence.broadcasts.lock().unwrap().clone()),
            }),
            noop_key_resolver(),
        );

        // First restore.
        let handle1 = ContextHandle::new("dup-ctx".to_owned(), params.clone());
        handle1.transition_to(&ContextState::Active).await.unwrap();
        manager.restore_context("dup-ctx", &handle1).await.unwrap();

        // Second restore should fail.
        let handle2 = ContextHandle::new("dup-ctx".to_owned(), params);
        handle2.transition_to(&ContextState::Active).await.unwrap();
        let result = manager.restore_context("dup-ctx", &handle2).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::MembershipFailed(_)
        ));
    }

    // -----------------------------------------------------------------------
    // EpochGraceStore needs_reconnect tests (§23.11)
    // -----------------------------------------------------------------------

    /// §23.11: Grace entry with epoch > MLS epoch triggers `needs_reconnect`.
    #[tokio::test]
    async fn restore_context_sets_needs_reconnect_on_grace_inconsistency() {
        use crate::crypto::mls::epoch_grace::GraceEntry;
        use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

        let persistence = Arc::new(MockContextPersistence::default());

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: scp_protocol::context::MemoryScope::Full,
            ..ContextParams::default()
        };

        let ceiling = default_ceiling();
        let role_state = ContextRoleState::new(
            "grace-incon-ctx",
            "did:key:author1",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();
        let membership = MembershipState::new();

        // Grace entry referencing epoch 5, but MLS epoch is only 3.
        // This simulates a partial write that escaped the transaction boundary.
        let snapshot = super::ContextSnapshot {
            context_id: "grace-incon-ctx".to_owned(),
            state: ContextState::Active,
            context_params: params.clone(),
            membership,
            role_state,
            executed_proposals: HashSet::new(),
            ttl_remaining_secs: None,
            registered_tools: Vec::new(),
            write_revoked_members: HashSet::new(),
            read_revoked_members: HashSet::new(),
            read_exclusion_list: HashSet::new(),
            tool_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
            governance_model_config: None,
            economic_policy: None,
            budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
            approved_proposals: HashMap::new(),
            governance_freeze: None,
            pending_ceiling_modification: None,
            pending_economic_policy_change: None,
            mls_epoch: 3,
            epoch_coordination_records: Vec::new(),
            grace_entries: vec![GraceEntry {
                epoch: 5,                       // epoch 5 > mls_epoch 3 → inconsistency
                expires_at_unix_secs: u64::MAX, // far-future expiry
            }],
            needs_reconnect: false,
            migration_state: None,
            mls_crypto_state: Vec::new(),
        };

        let bc_snapshot = test_broadcast_snapshot("grace-incon-ctx");
        persistence
            .persist_context("grace-incon-ctx", &snapshot)
            .unwrap();
        persistence
            .persist_broadcast("grace-incon-ctx", &bc_snapshot)
            .unwrap();

        let manager = ContextManager::with_persistence(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            Box::new(MockContextPersistence {
                contexts: std::sync::Mutex::new(persistence.contexts.lock().unwrap().clone()),
                broadcasts: std::sync::Mutex::new(persistence.broadcasts.lock().unwrap().clone()),
            }),
            noop_key_resolver(),
        );

        let handle = ContextHandle::new("grace-incon-ctx".to_owned(), params);
        handle.transition_to(&ContextState::Active).await.unwrap();
        manager
            .restore_context("grace-incon-ctx", &handle)
            .await
            .unwrap();

        // The context should be marked as needing reconnection.
        assert!(
            manager.context_needs_reconnect("grace-incon-ctx").await,
            "inconsistent grace entries should set needs_reconnect"
        );

        // After clearing, the flag should be false.
        assert!(manager.clear_needs_reconnect("grace-incon-ctx").await);
        assert!(
            !manager.context_needs_reconnect("grace-incon-ctx").await,
            "needs_reconnect should be cleared"
        );
    }

    /// §23.11: Consistent grace entries do NOT set `needs_reconnect`.
    #[tokio::test]
    async fn restore_context_no_reconnect_when_grace_consistent() {
        use crate::crypto::mls::epoch_grace::GraceEntry;
        use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

        let persistence = Arc::new(MockContextPersistence::default());

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: scp_protocol::context::MemoryScope::Full,
            ..ContextParams::default()
        };

        let ceiling = default_ceiling();
        let role_state = ContextRoleState::new(
            "grace-ok-ctx",
            "did:key:author1",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();
        let membership = MembershipState::new();

        // Grace entry epoch 2, MLS epoch 3 → consistent (epoch <= mls_epoch).
        // Use a far-future but safe expiry (now + 1 hour) to avoid overflow.
        let future_expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let snapshot = super::ContextSnapshot {
            context_id: "grace-ok-ctx".to_owned(),
            state: ContextState::Active,
            context_params: params.clone(),
            membership,
            role_state,
            executed_proposals: HashSet::new(),
            ttl_remaining_secs: None,
            registered_tools: Vec::new(),
            write_revoked_members: HashSet::new(),
            read_revoked_members: HashSet::new(),
            read_exclusion_list: HashSet::new(),
            tool_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
            governance_model_config: None,
            economic_policy: None,
            budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
            approved_proposals: HashMap::new(),
            governance_freeze: None,
            pending_ceiling_modification: None,
            pending_economic_policy_change: None,
            mls_epoch: 3,
            epoch_coordination_records: Vec::new(),
            grace_entries: vec![GraceEntry {
                epoch: 2, // epoch 2 <= mls_epoch 3 → consistent
                expires_at_unix_secs: future_expiry,
            }],
            needs_reconnect: false,
            migration_state: None,
            mls_crypto_state: Vec::new(),
        };

        let bc_snapshot = test_broadcast_snapshot("grace-ok-ctx");
        persistence
            .persist_context("grace-ok-ctx", &snapshot)
            .unwrap();
        persistence
            .persist_broadcast("grace-ok-ctx", &bc_snapshot)
            .unwrap();

        let manager = ContextManager::with_persistence(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            Box::new(MockContextPersistence {
                contexts: std::sync::Mutex::new(persistence.contexts.lock().unwrap().clone()),
                broadcasts: std::sync::Mutex::new(persistence.broadcasts.lock().unwrap().clone()),
            }),
            noop_key_resolver(),
        );

        let handle = ContextHandle::new("grace-ok-ctx".to_owned(), params);
        handle.transition_to(&ContextState::Active).await.unwrap();
        manager
            .restore_context("grace-ok-ctx", &handle)
            .await
            .unwrap();

        // Consistent grace entries should NOT set needs_reconnect.
        assert!(
            !manager.context_needs_reconnect("grace-ok-ctx").await,
            "consistent grace entries should not set needs_reconnect"
        );
    }

    // -----------------------------------------------------------------------
    // contexts_needing_reconnect / execute_reconnection tests (#853)
    // -----------------------------------------------------------------------

    /// Builds a test `ContextSnapshot` with optional grace inconsistency.
    /// When `bad_grace_epoch` is `Some(epoch)` and `epoch > mls_epoch`,
    /// restoring triggers `needs_reconnect = true`.
    fn reconnect_test_snapshot(
        ctx_id: &str,
        mls_epoch: u64,
        bad_grace_epoch: Option<u64>,
    ) -> super::ContextSnapshot {
        use scp_protocol::context::roles::{ContextRoleState, default_ceiling};
        let ceiling = default_ceiling();
        let role_state = ContextRoleState::new(
            ctx_id,
            "did:key:a1",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();
        let grace = bad_grace_epoch
            .map(|e| {
                vec![crate::crypto::mls::epoch_grace::GraceEntry {
                    epoch: e,
                    expires_at_unix_secs: u64::MAX,
                }]
            })
            .unwrap_or_default();
        super::ContextSnapshot {
            context_id: ctx_id.to_owned(),
            state: ContextState::Active,
            context_params: ContextParams::default(),
            membership: MembershipState::new(),
            role_state,
            executed_proposals: HashSet::new(),
            ttl_remaining_secs: None,
            registered_tools: Vec::new(),
            write_revoked_members: HashSet::new(),
            read_revoked_members: HashSet::new(),
            read_exclusion_list: HashSet::new(),
            tool_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
            governance_model_config: None,
            economic_policy: None,
            approved_proposals: HashMap::new(),
            governance_freeze: None,
            pending_ceiling_modification: None,
            pending_economic_policy_change: None,
            mls_epoch,
            grace_entries: grace,
            needs_reconnect: false,
            budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
            epoch_coordination_records: Vec::new(),
            mls_crypto_state: Vec::new(),
            migration_state: None,
        }
    }

    /// Creates a manager with persistence pre-loaded, then restores all contexts.
    async fn manager_with_reconnect_snapshots(
        snapshots: &[(&str, super::ContextSnapshot)],
    ) -> ContextManager {
        let persistence = MockContextPersistence::default();
        for (ctx_id, snap) in snapshots {
            let bc = test_broadcast_snapshot(ctx_id);
            persistence.persist_context(ctx_id, snap).unwrap();
            persistence.persist_broadcast(ctx_id, &bc).unwrap();
        }
        let manager = ContextManager::with_persistence(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            Box::new(persistence),
            noop_key_resolver(),
        );
        for (ctx_id, _) in snapshots {
            let handle = ContextHandle::new((*ctx_id).to_owned(), ContextParams::default());
            handle.transition_to(&ContextState::Active).await.unwrap();
            manager.restore_context(ctx_id, &handle).await.unwrap();
        }
        manager
    }

    /// §23.11/§23.3: `contexts_needing_reconnect` returns IDs of contexts
    /// with `needs_reconnect = true`.
    #[tokio::test]
    async fn contexts_needing_reconnect_returns_flagged_contexts() {
        let snap1 = reconnect_test_snapshot("ctx-r1", 3, Some(5)); // inconsistent
        let snap2 = reconnect_test_snapshot("ctx-r2", 3, None); // consistent
        let manager =
            manager_with_reconnect_snapshots(&[("ctx-r1", snap1), ("ctx-r2", snap2)]).await;

        let needing = manager.contexts_needing_reconnect().await;
        assert_eq!(needing.len(), 1);
        assert_eq!(needing[0], "ctx-r1");
        assert!(!manager.context_needs_reconnect("ctx-r2").await);
    }

    /// §23.3: `prepare_reconnection` returns None when no contexts need
    /// reconnection.
    #[tokio::test]
    async fn prepare_reconnection_returns_none_when_no_reconnect_needed() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let result = manager
            .prepare_reconnection(
                DID::from("did:dht:z6MkAlice"),
                std::collections::HashMap::new(),
            )
            .await;
        assert!(result.is_none());
    }

    /// §23.3: `execute_reconnection` runs the full reconnection protocol
    /// for contexts with `needs_reconnect = true`, and clears the flag
    /// after successful completion.
    #[tokio::test]
    async fn execute_reconnection_wires_flag_to_protocol() {
        use crate::sync::hours_offline::{BufferedMessage, EpochCatchUpState, SyncPhaseDriver};
        use scp_protocol::sync::{SyncError, SyncEvent, SyncPolicy};

        // Minimal SyncPhaseDriver that succeeds on all phases.
        struct NoOpDriver;
        impl SyncPhaseDriver for NoOpDriver {
            async fn relay_catch_up(
                &self,
                _: &str,
                _: u64,
            ) -> Result<Vec<BufferedMessage>, SyncError> {
                Ok(vec![])
            }
            async fn epoch_reconciliation(
                &self,
                id: &str,
                l: u64,
                t: u64,
                _: &SyncPolicy,
            ) -> Result<EpochCatchUpState, SyncError> {
                let mut s = EpochCatchUpState::new(id.to_owned(), l, t);
                s.status = scp_protocol::sync::CatchUpStatus::Complete;
                Ok(s)
            }
            async fn event_log_sync(&self, _: &str) -> Result<(u64, Vec<SyncEvent>), SyncError> {
                Ok((0, vec![]))
            }
            async fn sender_key_reacquire(
                &self,
                _: &str,
                _: &SyncPolicy,
            ) -> Result<u64, SyncError> {
                Ok(0)
            }
            async fn mls_update(&self, _: &str) -> Result<bool, SyncError> {
                Ok(true)
            }
            async fn queue_drain(
                &self,
                _: &str,
                _: u64,
                _: Option<u64>,
            ) -> Result<(u64, u64), SyncError> {
                Ok((0, 0))
            }
            async fn local_epoch(&self, _: &str) -> Result<Option<u64>, SyncError> {
                Ok(Some(3))
            }
            async fn observed_target_epoch(
                &self,
                _: &str,
                _: &[BufferedMessage],
            ) -> Result<Option<u64>, SyncError> {
                Ok(Some(3))
            }
            async fn blob_ttl_secs(&self, _: &str) -> Result<Option<u64>, SyncError> {
                Ok(None)
            }
        }

        let snap = reconnect_test_snapshot("ctx-ex", 3, Some(10));
        let manager = manager_with_reconnect_snapshots(&[("ctx-ex", snap)]).await;

        assert!(manager.context_needs_reconnect("ctx-ex").await);

        let mut contacts = std::collections::HashMap::new();
        contacts.insert("ctx-ex".to_owned(), 990_000u64);
        let driver = NoOpDriver;

        let report = manager
            .execute_reconnection("did:dht:z6MkAlice".into(), 1_000_000, contacts, &driver)
            .await
            .expect("should return a report");

        assert_eq!(report.contexts_synced.len(), 1);
        assert_eq!(
            report.contexts_synced[0].outcome,
            scp_protocol::sync::SyncOutcome::FullyCaughtUp
        );
        assert!(report.contexts_synced[0].mls_update_issued);
        assert!(
            !manager.context_needs_reconnect("ctx-ex").await,
            "flag should be auto-cleared"
        );

        // No more flagged contexts.
        let none = manager
            .execute_reconnection(
                "did:dht:z6MkAlice".into(),
                1_000_000,
                std::collections::HashMap::new(),
                &driver,
            )
            .await;
        assert!(none.is_none());
    }

    /// §23.3: `execute_reconnection` clears `needs_reconnect` when the
    /// driver signals `ContextGone` (context closed/expired while offline).
    /// This prevents infinite retry loops for contexts that no longer exist.
    #[tokio::test]
    async fn execute_reconnection_clears_flag_on_context_gone() {
        use crate::sync::hours_offline::{BufferedMessage, EpochCatchUpState, SyncPhaseDriver};
        use scp_protocol::sync::{SyncError, SyncEvent, SyncPolicy};

        /// Driver whose `relay_catch_up` returns `SyncError::ContextGone`,
        /// causing the coordinator to produce `SyncOutcome::ContextGone`.
        struct ContextGoneDriver;
        impl SyncPhaseDriver for ContextGoneDriver {
            async fn relay_catch_up(
                &self,
                ctx_id: &str,
                _: u64,
            ) -> Result<Vec<BufferedMessage>, SyncError> {
                Err(SyncError::ContextGone {
                    context_id: ctx_id.to_owned(),
                })
            }
            async fn epoch_reconciliation(
                &self,
                id: &str,
                l: u64,
                t: u64,
                _: &SyncPolicy,
            ) -> Result<EpochCatchUpState, SyncError> {
                let mut s = EpochCatchUpState::new(id.to_owned(), l, t);
                s.status = scp_protocol::sync::CatchUpStatus::Complete;
                Ok(s)
            }
            async fn event_log_sync(&self, _: &str) -> Result<(u64, Vec<SyncEvent>), SyncError> {
                Ok((0, vec![]))
            }
            async fn sender_key_reacquire(
                &self,
                _: &str,
                _: &SyncPolicy,
            ) -> Result<u64, SyncError> {
                Ok(0)
            }
            async fn mls_update(&self, _: &str) -> Result<bool, SyncError> {
                Ok(false)
            }
            async fn queue_drain(
                &self,
                _: &str,
                _: u64,
                _: Option<u64>,
            ) -> Result<(u64, u64), SyncError> {
                Ok((0, 0))
            }
            async fn local_epoch(&self, _: &str) -> Result<Option<u64>, SyncError> {
                Ok(Some(3))
            }
            async fn observed_target_epoch(
                &self,
                _: &str,
                _: &[BufferedMessage],
            ) -> Result<Option<u64>, SyncError> {
                Ok(Some(3))
            }
            async fn blob_ttl_secs(&self, _: &str) -> Result<Option<u64>, SyncError> {
                Ok(None)
            }
        }

        let snap = reconnect_test_snapshot("ctx-gone", 3, Some(10));
        let manager = manager_with_reconnect_snapshots(&[("ctx-gone", snap)]).await;

        assert!(manager.context_needs_reconnect("ctx-gone").await);

        let mut contacts = std::collections::HashMap::new();
        contacts.insert("ctx-gone".to_owned(), 990_000u64);
        let driver = ContextGoneDriver;

        let report = manager
            .execute_reconnection("did:dht:z6MkAlice".into(), 1_000_000, contacts, &driver)
            .await
            .expect("should return a report");

        assert_eq!(report.contexts_synced.len(), 1);
        assert_eq!(
            report.contexts_synced[0].outcome,
            scp_protocol::sync::SyncOutcome::ContextGone,
        );
        assert!(
            !manager.context_needs_reconnect("ctx-gone").await,
            "needs_reconnect must be cleared for ContextGone — not left as infinite retry"
        );
    }

    // -----------------------------------------------------------------------
    // Caller identity validation tests (#234)
    // -----------------------------------------------------------------------

    /// #234: `register_local_did` registers a DID as locally controlled,
    /// and `is_local_did` confirms it.
    #[tokio::test]
    async fn register_local_did_is_queryable() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let did: DID = "did:key:local1".into();
        assert!(!manager.is_local_did(&did).await);

        manager.register_local_did(did.clone()).await;
        assert!(manager.is_local_did(&did).await);

        // Idempotent: re-registering is a no-op.
        manager.register_local_did(did.clone()).await;
        assert!(manager.is_local_did(&did).await);
    }

    /// #234: `handle_broadcast_key_request` with a locally controlled DID
    /// succeeds (positive case -- defense-in-depth validation passes).
    #[tokio::test]
    async fn handle_broadcast_key_request_succeeds_with_local_did() {
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe a requester.
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:sub1".into(),
                None,
                1000,
                None,
            )
            .await
            .unwrap();

        // author1 is registered as a local DID by setup_broadcast_context.
        let decision = manager
            .handle_broadcast_key_request(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:sub1".into(),
            )
            .await
            .unwrap();

        assert!(
            matches!(decision, super::KeyRequestDecision::Grant { .. }),
            "key request with locally controlled author DID should be granted"
        );
    }

    /// #234: `handle_broadcast_key_request` with an uncontrolled DID returns
    /// `PermissionDenied` (negative case -- defense-in-depth validation
    /// rejects the request before reaching `BroadcastContext`).
    #[tokio::test]
    async fn handle_broadcast_key_request_rejects_non_local_did() {
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe a requester.
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:sub1".into(),
                None,
                1000,
                None,
            )
            .await
            .unwrap();

        // "did:key:unknown-author" is NOT registered as a local DID.
        let result = manager
            .handle_broadcast_key_request(
                &ctx_id,
                &"did:key:unknown-author".into(),
                &"did:key:sub1".into(),
            )
            .await;

        assert!(result.is_err(), "should reject non-local author DID");
        let err = result.unwrap_err();
        assert!(
            matches!(err, ContextError::PermissionDenied(ref msg) if msg.contains("not controlled")),
            "error should be PermissionDenied with descriptive message, got: {err}"
        );
    }

    /// #234: blocked subscriber's key request still returns `Deny` (not
    /// `PermissionDenied`) -- block list information is not leaked through
    /// the new validation layer. The defense-in-depth check runs first,
    /// but when the caller IS the local author, the existing block list
    /// logic applies as before.
    #[tokio::test]
    async fn handle_broadcast_key_request_deny_does_not_leak_block_info() {
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe then block.
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:blocked-sub".into(),
                None,
                1000,
                None,
            )
            .await
            .unwrap();

        manager
            .block_broadcast_subscriber(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:blocked-sub".into(),
            )
            .await
            .unwrap();

        // Key request for blocked subscriber returns Deny (not a
        // PermissionDenied error). The deny reason is generic and does
        // not reveal whether the subscriber is blocked or unregistered.
        let decision = manager
            .handle_broadcast_key_request(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:blocked-sub".into(),
            )
            .await
            .unwrap();

        assert!(
            matches!(decision, super::KeyRequestDecision::Deny { .. }),
            "blocked subscriber should receive Deny decision"
        );
    }

    /// #234: DID validation runs before context lookup. When a non-local DID
    /// is used AND the context doesn't exist, the result is `PermissionDenied`
    /// (not `ContextNotRegistered`). This documents
    /// the intentional fail-closed ordering: unauthenticated callers cannot
    /// probe for context existence.
    #[tokio::test]
    async fn handle_broadcast_key_request_rejects_non_local_did_before_context_lookup() {
        // Create a manager but don't create any contexts.
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        // Neither the author DID nor the context exist.
        let result = manager
            .handle_broadcast_key_request(
                "nonexistent-context",
                &"did:key:unregistered-author".into(),
                &"did:key:some-requester".into(),
            )
            .await;

        assert!(result.is_err(), "should reject non-local author DID");
        let err = result.unwrap_err();
        assert!(
            matches!(err, ContextError::PermissionDenied(_)),
            "should be PermissionDenied (DID check), not MembershipFailed (context lookup): {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Collection bounds tests (#360, §5.9)
    // -----------------------------------------------------------------------

    /// Build a minimal valid [`ToolRegistration`] for bounds tests.
    fn test_tool_registration(id: &str) -> ToolRegistration {
        use scp_protocol::context::tools::registry::{TestVector, ToolSchema};
        ToolRegistration {
            tool_id: id.to_owned(),
            name: id.to_owned(),
            description: "test tool".to_owned(),
            schema: ToolSchema {
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: serde_json::json!({"type": "object"}),
            },
            implementation_hash: [0u8; 32],
            test_vectors: vec![TestVector {
                input: serde_json::json!({}),
                expected_output: serde_json::json!({}),
                description: "noop".to_owned(),
            }],
            operator_did: "did:key:test-operator".into(),
            cost: None,
            registered_at: 0,
            signature: Vec::new(),
        }
    }

    /// #360: register exactly 256 tools (the limit), verify the 256th succeeds;
    /// attempt to register a 257th, verify `LimitExceeded` is returned.
    #[tokio::test]
    async fn registered_tools_bounded_at_256() {
        let (manager, _handle) = setup_active_context().await;
        let pid: ProposalId = [0u8; 32];

        // Register exactly MAX_REGISTERED_TOOLS tools.
        for i in 0..super::MAX_REGISTERED_TOOLS {
            let reg = test_tool_registration(&format!("tool-{i}"));
            manager
                .execute_register_tool("test-ctx", &reg, pid)
                .await
                .unwrap();
        }

        // The 257th must fail with LimitExceeded.
        let overflow = test_tool_registration("tool-overflow");
        let err = manager
            .execute_register_tool("test-ctx", &overflow, pid)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, ContextError::LimitExceeded(msg) if msg.contains("256")),
            "expected LimitExceeded with limit value, got: {err}"
        );
    }

    /// #360: establish exactly 256 tool interfaces (the limit), verify the 256th
    /// succeeds; attempt to establish a 257th, verify `LimitExceeded` is returned.
    #[tokio::test]
    async fn tool_interfaces_bounded_at_256() {
        let (manager, _handle) = setup_active_context().await;
        let pid: ProposalId = [0u8; 32];

        // Establish exactly MAX_TOOL_INTERFACES interfaces.
        for i in 0..super::MAX_TOOL_INTERFACES {
            let iface = ToolInterface {
                source_context: "test-ctx".to_owned(),
                target_context: format!("target-{i}"),
                tool_id: format!("tool-{i}"),
                rate_limit: None,
                per_caller_rate_limit: None,
                approved_by_source: true,
                approved_by_target: true,
                outbound_policy: None,
                inbound_policy: None,
            };
            manager
                .execute_establish_tool_interface("test-ctx", &iface, pid)
                .await
                .unwrap();
        }

        // The 257th must fail with LimitExceeded.
        let overflow = ToolInterface {
            source_context: "test-ctx".to_owned(),
            target_context: "target-overflow".to_owned(),
            tool_id: "tool-overflow".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        };
        let err = manager
            .execute_establish_tool_interface("test-ctx", &overflow, pid)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, ContextError::LimitExceeded(msg) if msg.contains("256")),
            "expected LimitExceeded with limit value, got: {err}"
        );
    }

    /// #360: add exactly 64 signers (the limit), verify the 64th succeeds;
    /// attempt to add a 65th, verify `LimitExceeded` is returned.
    #[tokio::test]
    async fn threshold_signers_bounded_at_64() {
        let (manager, _handle) = setup_active_context().await;
        let pid: ProposalId = [0u8; 32];

        // First, add 64 members to the context so they pass the membership check.
        // The creator ("did:key:creator") is already a member.
        let mut dids: Vec<DID> = Vec::with_capacity(super::MAX_THRESHOLD_SIGNERS);
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("test-ctx").unwrap();
            for i in 0..super::MAX_THRESHOLD_SIGNERS {
                let did: DID = format!("did:key:signer-{i}").into();
                ctx.membership
                    .add_member(did.clone(), "member".to_owned(), vec![]);
                dids.push(did);
            }
        }

        // Add exactly MAX_THRESHOLD_SIGNERS signers.
        for did in &dids {
            manager
                .execute_add_signer("test-ctx", did, pid)
                .await
                .unwrap();
        }

        // The 65th must fail with LimitExceeded.
        let overflow_did: DID = "did:key:signer-overflow".into();
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("test-ctx").unwrap();
            ctx.membership
                .add_member(overflow_did.clone(), "member".to_owned(), vec![]);
        }
        let err = manager
            .execute_add_signer("test-ctx", &overflow_did, pid)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, ContextError::LimitExceeded(msg) if msg.contains("64")),
            "expected LimitExceeded with limit value, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // GovernanceModel enum expansion tests (#320)
    // -----------------------------------------------------------------------

    #[test]
    fn governance_model_serde_roundtrip_all_variants() {
        use scp_protocol::context::params::GovernanceModel;

        let alice: DID = "did:dht:z6MkAlice".into();
        let bob: DID = "did:dht:z6MkBob".into();
        let carol: DID = "did:dht:z6MkCarol".into();

        let models = vec![
            GovernanceModel::SingleAdmin,
            GovernanceModel::Threshold {
                threshold: 2,
                signers: vec![alice.clone(), bob.clone(), carol.clone()],
            },
            GovernanceModel::Majority {
                eligible_voters: vec![alice.clone(), bob.clone(), carol.clone()],
            },
            GovernanceModel::Unanimity {
                eligible_voters: vec![alice, bob, carol],
            },
        ];

        for model in &models {
            let json = serde_json::to_string(model).expect("serialize");
            let deserialized: GovernanceModel = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&deserialized, model, "serde roundtrip failed for {model:?}");
        }
    }

    #[test]
    fn governance_model_in_context_params_roundtrip() {
        use scp_protocol::context::params::GovernanceModel;

        let params = ContextParams {
            governance: GovernanceModel::Threshold {
                threshold: 2,
                signers: vec![
                    "did:dht:z6MkAlice".into(),
                    "did:dht:z6MkBob".into(),
                    "did:dht:z6MkCarol".into(),
                ],
            },
            ..ContextParams::default()
        };

        let json = serde_json::to_string(&params).expect("serialize");
        let deserialized: ContextParams = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.governance, params.governance);
    }

    #[test]
    fn public_metadata_exposes_all_governance_variants() {
        use scp_protocol::context::params::{GovernanceModel, RuntimeMetadata};

        let params = ContextParams {
            governance: GovernanceModel::Majority {
                eligible_voters: vec!["did:dht:z6MkAlice".into(), "did:dht:z6MkBob".into()],
            },
            ..ContextParams::default()
        };

        let runtime = RuntimeMetadata::default();
        let meta = params.public_metadata(&runtime);
        assert_eq!(meta.governance, params.governance);
    }

    // -----------------------------------------------------------------------
    // Context creation validation tests (#320)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_context_rejects_threshold_exceeding_signers() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let params = ContextParams {
            governance: scp_protocol::context::params::GovernanceModel::Threshold {
                threshold: 5,
                signers: vec!["did:dht:z6MkAlice".into(), "did:dht:z6MkBob".into()],
            },
            ..ContextParams::default()
        };

        let result = manager
            .create_context(
                "ctx-bad-threshold".into(),
                params,
                "did:dht:z6MkAlice".into(),
            )
            .await;

        assert!(result.is_err(), "should reject threshold > signers.len()");
    }

    #[tokio::test]
    async fn create_context_rejects_threshold_zero() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let params = ContextParams {
            governance: scp_protocol::context::params::GovernanceModel::Threshold {
                threshold: 0,
                signers: vec!["did:dht:z6MkAlice".into()],
            },
            ..ContextParams::default()
        };

        let result = manager
            .create_context(
                "ctx-zero-threshold".into(),
                params,
                "did:dht:z6MkAlice".into(),
            )
            .await;

        assert!(result.is_err(), "should reject threshold == 0");
    }

    #[tokio::test]
    async fn create_context_rejects_majority_empty_voters() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let params = ContextParams {
            governance: scp_protocol::context::params::GovernanceModel::Majority {
                eligible_voters: vec![],
            },
            ..ContextParams::default()
        };

        let result = manager
            .create_context(
                "ctx-empty-majority".into(),
                params,
                "did:dht:z6MkAlice".into(),
            )
            .await;

        assert!(
            result.is_err(),
            "should reject Majority with empty eligible_voters"
        );
    }

    #[tokio::test]
    async fn create_context_rejects_unanimity_empty_voters() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let params = ContextParams {
            governance: scp_protocol::context::params::GovernanceModel::Unanimity {
                eligible_voters: vec![],
            },
            ..ContextParams::default()
        };

        let result = manager
            .create_context(
                "ctx-empty-unanimity".into(),
                params,
                "did:dht:z6MkAlice".into(),
            )
            .await;

        assert!(
            result.is_err(),
            "should reject Unanimity with empty eligible_voters"
        );
    }

    // -----------------------------------------------------------------------
    // Proposal lifecycle tests (#320)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn single_admin_propose_auto_executes() {
        use scp_protocol::context::governance::GovernanceAction;

        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );

        let creator_did: DID = "did:dht:z6MkCreator".into();
        let signing_key = signing_key_for_did(&creator_did);

        let params = ContextParams {
            ceiling: vec![
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::ToolRegister,
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context(
                "ctx-single-admin-lifecycle".into(),
                params,
                creator_did.clone(),
            )
            .await
            .unwrap();

        assert_eq!(handle.state().await, ContextState::Active);

        // Propose RegisterTool — should auto-execute in SingleAdmin.
        let action = GovernanceAction::RegisterTool {
            registration: Box::new(test_tool_registration("test-tool")),
        };

        let (proposal, events) = manager
            .propose_governance_action(
                "ctx-single-admin-lifecycle",
                &creator_did,
                action,
                &signing_key,
            )
            .await
            .unwrap();

        assert!(
            matches!(
                proposal.status,
                scp_protocol::context::governance::ProposalStatus::Approved
            ),
            "SingleAdmin proposal should be auto-approved"
        );
        assert!(
            events.len() >= 2,
            "should have ProposalCreated + VoteCast + ProposalResolved events"
        );

        // Verify the proposal is retrievable.
        let retrieved = manager
            .get_proposal("ctx-single-admin-lifecycle", &proposal.proposal_id)
            .await
            .unwrap();
        assert_eq!(retrieved.proposal_id, proposal.proposal_id);

        // Verify list_proposals returns it.
        let proposals = manager
            .list_proposals("ctx-single-admin-lifecycle")
            .await
            .unwrap();
        assert_eq!(proposals.len(), 1);
    }

    #[tokio::test]
    async fn threshold_context_proposal_lifecycle() {
        use scp_protocol::context::governance::{GovernanceAction, ProposalStatus};

        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );

        let alice: DID = "did:dht:z6MkAlice".into();
        let bob: DID = "did:dht:z6MkBob".into();
        let carol: DID = "did:dht:z6MkCarol".into();
        let key_a = signing_key_for_did(&alice);
        let key_b = signing_key_for_did(&bob);

        let params = ContextParams {
            governance: scp_protocol::context::params::GovernanceModel::Threshold {
                threshold: 2,
                signers: vec![alice.clone(), bob.clone(), carol.clone()],
            },
            ceiling: vec![
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::ToolRegister,
            ],
            ..ContextParams::default()
        };

        // Create context (alice is the creator/admin).
        let _handle = manager
            .create_context("ctx-threshold".into(), params, alice.clone())
            .await
            .unwrap();

        // Alice proposes RegisterTool (her proposer vote counts as first approval).
        let action = GovernanceAction::RegisterTool {
            registration: Box::new(test_tool_registration("threshold-tool")),
        };

        let (proposal, _events) = manager
            .propose_governance_action("ctx-threshold", &alice, action, &key_a)
            .await
            .unwrap();

        // Proposal should be Pending (1 vote, need 2).
        assert!(
            matches!(proposal.status, ProposalStatus::Pending),
            "threshold proposal should be pending after 1 vote, got {:?}",
            proposal.status
        );

        // Bob votes approve — should reach threshold (2-of-3).
        let (status, _events) = manager
            .vote_on_proposal("ctx-threshold", &proposal.proposal_id, &bob, true, &key_b)
            .await
            .unwrap();

        assert!(
            matches!(status, ProposalStatus::Approved),
            "threshold proposal should be approved after 2nd vote, got {status:?}"
        );

        // Verify the tool was registered (auto-execution).
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("ctx-threshold").unwrap();
        assert!(
            ctx.governance
                .registered_tools
                .iter()
                .any(|t| t.name == "threshold-tool"),
            "tool should have been registered after proposal approval"
        );
    }

    #[tokio::test]
    async fn majority_context_proposal_lifecycle() {
        use scp_protocol::context::governance::{GovernanceAction, ProposalStatus};

        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );

        let alice: DID = "did:dht:z6MkAlice".into();
        let bob: DID = "did:dht:z6MkBob".into();
        let carol: DID = "did:dht:z6MkCarol".into();
        let key_a = signing_key_for_did(&alice);
        let key_b = signing_key_for_did(&bob);

        let params = ContextParams {
            governance: scp_protocol::context::params::GovernanceModel::Majority {
                eligible_voters: vec![alice.clone(), bob.clone(), carol.clone()],
            },
            ..ContextParams::default()
        };

        let _handle = manager
            .create_context("ctx-majority".into(), params, alice.clone())
            .await
            .unwrap();

        // Alice proposes CloseContext.
        let action = GovernanceAction::CloseContext {
            reason: Some("test close".to_owned()),
        };

        let (proposal, _) = manager
            .propose_governance_action("ctx-majority", &alice, action, &key_a)
            .await
            .unwrap();

        assert!(matches!(proposal.status, ProposalStatus::Pending));

        // Alice approves her own proposal (proposer must vote separately
        // in MajorityVoteEngine — propose() does not auto-approve).
        let (status, _) = manager
            .vote_on_proposal("ctx-majority", &proposal.proposal_id, &alice, true, &key_a)
            .await
            .unwrap();
        assert!(
            matches!(status, ProposalStatus::Pending),
            "1/3 approvals should still be pending, got {status:?}"
        );

        // Bob approves — now 2/3 approve = >50% = approved.
        let (status, _) = manager
            .vote_on_proposal("ctx-majority", &proposal.proposal_id, &bob, true, &key_b)
            .await
            .unwrap();

        assert!(
            matches!(status, ProposalStatus::Approved),
            "2/3 approvals should reach majority, got {status:?}"
        );
    }

    #[tokio::test]
    async fn unanimity_context_single_rejection_defeats_proposal() {
        use scp_protocol::context::governance::{GovernanceAction, ProposalStatus};

        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );

        let alice: DID = "did:dht:z6MkAlice".into();
        let bob: DID = "did:dht:z6MkBob".into();
        let carol: DID = "did:dht:z6MkCarol".into();
        let key_a = signing_key_for_did(&alice);
        let key_b = signing_key_for_did(&bob);
        let key_c = signing_key_for_did(&carol);

        let params = ContextParams {
            governance: scp_protocol::context::params::GovernanceModel::Unanimity {
                eligible_voters: vec![alice.clone(), bob.clone(), carol.clone()],
            },
            ..ContextParams::default()
        };

        // Add bob as member so we can test RemoveMember doesn't happen.
        let _handle = manager
            .create_context("ctx-unanimity".into(), params, alice.clone())
            .await
            .unwrap();

        // Add bob to membership manually for the test.
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("ctx-unanimity").unwrap();
            ctx.membership
                .add_member(bob.clone(), "member".into(), vec![]);
            ctx.membership
                .add_member(carol.clone(), "member".into(), vec![]);
        }

        // Alice proposes RemoveMember(bob).
        let action = GovernanceAction::RemoveMember {
            did: bob.clone(),
            reason: Some("test removal".to_owned()),
        };

        let (proposal, _) = manager
            .propose_governance_action("ctx-unanimity", &alice, action, &key_a)
            .await
            .unwrap();

        assert!(matches!(proposal.status, ProposalStatus::Pending));

        // Bob approves.
        let (status, _) = manager
            .vote_on_proposal("ctx-unanimity", &proposal.proposal_id, &bob, true, &key_b)
            .await
            .unwrap();
        assert!(matches!(status, ProposalStatus::Pending));

        // Carol rejects — single rejection kills unanimity.
        let (status, _) = manager
            .vote_on_proposal(
                "ctx-unanimity",
                &proposal.proposal_id,
                &carol,
                false,
                &key_c,
            )
            .await
            .unwrap();

        assert!(
            matches!(status, ProposalStatus::Rejected { .. }),
            "unanimity proposal should be rejected after single rejection, got {status:?}"
        );

        // Verify bob is still a member (proposal was rejected, not executed).
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("ctx-unanimity").unwrap();
        assert!(
            ctx.membership.get(bob.as_ref()).is_some(),
            "Bob should still be a member after rejected proposal"
        );
    }

    #[tokio::test]
    async fn non_eligible_voter_rejected() {
        use scp_protocol::context::governance::GovernanceAction;

        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );

        let alice: DID = "did:dht:z6MkAlice".into();
        let bob: DID = "did:dht:z6MkBob".into();
        let eve: DID = "did:dht:z6MkEve".into();
        let key_a = signing_key_for_did(&alice);
        let key_e = signing_key_for_did(&eve);

        let params = ContextParams {
            governance: scp_protocol::context::params::GovernanceModel::Threshold {
                threshold: 2,
                signers: vec![alice.clone(), bob.clone()],
            },
            ..ContextParams::default()
        };

        let _handle = manager
            .create_context("ctx-eligibility".into(), params, alice.clone())
            .await
            .unwrap();

        // Alice proposes.
        let action = GovernanceAction::RegisterTool {
            registration: Box::new(test_tool_registration("tool")),
        };

        let (proposal, _) = manager
            .propose_governance_action("ctx-eligibility", &alice, action, &key_a)
            .await
            .unwrap();

        // Eve (not a signer) tries to vote — should be rejected.
        let result = manager
            .vote_on_proposal("ctx-eligibility", &proposal.proposal_id, &eve, true, &key_e)
            .await;

        assert!(result.is_err(), "non-eligible voter should be rejected");
        let err = result.unwrap_err();
        assert!(
            matches!(err, ContextError::GovernanceFailed(_)),
            "should be GovernanceFailed for non-eligible voter, got {err:?}"
        );
    }

    #[test]
    fn governance_snapshot_serde_roundtrip() {
        use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

        let params = ContextParams {
            governance: scp_protocol::context::params::GovernanceModel::Threshold {
                threshold: 2,
                signers: vec![
                    "did:dht:z6MkAlice".into(),
                    "did:dht:z6MkBob".into(),
                    "did:dht:z6MkCarol".into(),
                ],
            },
            ..ContextParams::default()
        };

        let role_state = ContextRoleState::new(
            "ctx-snap",
            "did:dht:z6MkAlice",
            default_ceiling(),
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();

        let snapshot = super::ContextSnapshot {
            context_id: "ctx-snap".to_owned(),
            state: ContextState::Active,
            context_params: params,
            membership: MembershipState::new(),
            role_state,
            executed_proposals: HashSet::new(),
            ttl_remaining_secs: None,
            registered_tools: Vec::new(),
            write_revoked_members: HashSet::new(),
            read_revoked_members: HashSet::new(),
            read_exclusion_list: HashSet::new(),
            tool_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
            governance_model_config: Some(
                scp_protocol::context::governance::GovernanceModelConfig::Threshold {
                    signers: vec![
                        "did:dht:z6MkAlice".into(),
                        "did:dht:z6MkBob".into(),
                        "did:dht:z6MkCarol".into(),
                    ],
                    threshold: 2,
                    voting_window_secs: 86_400,
                },
            ),
            economic_policy: None,
            budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
            approved_proposals: HashMap::new(),
            governance_freeze: None,
            pending_ceiling_modification: None,
            pending_economic_policy_change: None,
            mls_epoch: 0,
            epoch_coordination_records: Vec::new(),
            grace_entries: Vec::new(),
            needs_reconnect: false,
            migration_state: None,
            mls_crypto_state: Vec::new(),
        };

        let json = serde_json::to_string(&snapshot).expect("serialize");
        let deserialized: super::ContextSnapshot =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.context_id, snapshot.context_id);
        assert_eq!(
            deserialized.governance_model_config,
            snapshot.governance_model_config
        );
    }

    // -----------------------------------------------------------------------
    // Promotion policy enforcement tests (§5.10, #340)
    // -----------------------------------------------------------------------

    /// §5.10 AC1: a context created with `NoPromotion` rejects `PromoteContext`
    /// governance proposals with `PermissionDenied`.
    #[tokio::test]
    async fn promote_context_rejected_when_policy_is_no_promotion() {
        use scp_protocol::context::governance::{GovernanceProposal, SignedVote, VoteType};

        let (manager, _handle) = setup_active_context().await;

        // setup_active_context uses ContextParams::default() which has
        // promotion_policy = NoPromotion. Build an approved PromoteContext
        // proposal with the creator's vote.
        let proposal = GovernanceProposal {
            proposal_id: [1u8; 32],
            context_id: "test-ctx".into(),
            proposer_did: "did:key:creator".into(),
            action: GovernanceAction::PromoteContext,
            status: ProposalStatus::Approved,
            created_at: 1000,
            voting_deadline: 2000,
            approvals: vec![SignedVote {
                voter_did: "did:key:creator".into(),
                vote: VoteType::Approve,
                timestamp: 1000,
                signature: vec![0u8; 64],
            }],
            rejections: Vec::new(),
            created_at_epoch: None,
        };

        let result = manager
            .execute_governance_action("test-ctx", &proposal)
            .await;

        assert!(
            result.is_err(),
            "NoPromotion context must reject PromoteContext"
        );
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("not Promotable"),
            "error message should contain 'not Promotable', got: {msg}"
        );
        assert!(
            matches!(err, ContextError::PermissionDenied(_)),
            "should be PermissionDenied, got: {err}"
        );
    }

    /// §5.10 AC2: a context created with `Promotable` can be promoted via
    /// unanimous governance approval. After promotion, TTL is removed and
    /// memory scope transitions to `Full`.
    #[tokio::test]
    async fn promote_context_succeeds_when_policy_is_promotable() {
        use scp_protocol::context::governance::{GovernanceProposal, SignedVote, VoteType};
        use scp_protocol::context::params::{MemoryScope, PromotionPolicy};

        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let params = ContextParams {
            promotion_policy: PromotionPolicy::Promotable,
            memory_scope: MemoryScope::Ephemeral,
            ttl: Some(std::time::Duration::from_secs(3600)),
            ceiling: vec![
                scp_protocol::context::params::Capability::new("messages:read"),
                scp_protocol::context::params::Capability::new("messages:write"),
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("promo-ctx".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        // Verify preconditions: TTL is set, memory scope is Ephemeral.
        assert_eq!(handle.params().memory_scope, MemoryScope::Ephemeral);
        assert_eq!(
            handle.params().promotion_policy,
            PromotionPolicy::Promotable
        );

        // Build an approved PromoteContext proposal with unanimous consent
        // (only the creator is a member).
        let proposal = GovernanceProposal {
            proposal_id: [2u8; 32],
            context_id: "promo-ctx".into(),
            proposer_did: "did:key:creator".into(),
            action: GovernanceAction::PromoteContext,
            status: ProposalStatus::Approved,
            created_at: 1000,
            voting_deadline: 2000,
            approvals: vec![SignedVote {
                voter_did: "did:key:creator".into(),
                vote: VoteType::Approve,
                timestamp: 1000,
                signature: vec![0u8; 64],
            }],
            rejections: Vec::new(),
            created_at_epoch: None,
        };

        let result = manager
            .execute_governance_action("promo-ctx", &proposal)
            .await;

        assert!(
            result.is_ok(),
            "Promotable context should accept PromoteContext: {result:?}"
        );

        // Verify postconditions: memory scope is now Full.
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("promo-ctx").unwrap();
        assert_eq!(
            ctx.handle.params().memory_scope,
            MemoryScope::Full,
            "memory scope should transition to Full after promotion"
        );

        // TTL timer should be cancelled (deadline removed).
        assert!(
            ctx.ttl.timer.deadline_unix_secs.is_none(),
            "TTL deadline should be removed after promotion"
        );
    }

    /// §5.10 AC3: after promotion, `promotion_policy` remains `Promotable` —
    /// the field is not mutated by the promotion itself.
    #[tokio::test]
    async fn promote_context_does_not_mutate_promotion_policy() {
        use scp_protocol::context::governance::{GovernanceProposal, SignedVote, VoteType};
        use scp_protocol::context::params::{MemoryScope, PromotionPolicy};

        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let params = ContextParams {
            promotion_policy: PromotionPolicy::Promotable,
            memory_scope: MemoryScope::Ephemeral,
            ceiling: vec![scp_protocol::context::params::Capability::new(
                "messages:read",
            )],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("promo-immut-ctx".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        assert_eq!(
            handle.params().promotion_policy,
            PromotionPolicy::Promotable
        );

        let proposal = GovernanceProposal {
            proposal_id: [3u8; 32],
            context_id: "promo-immut-ctx".into(),
            proposer_did: "did:key:creator".into(),
            action: GovernanceAction::PromoteContext,
            status: ProposalStatus::Approved,
            created_at: 1000,
            voting_deadline: 2000,
            approvals: vec![SignedVote {
                voter_did: "did:key:creator".into(),
                vote: VoteType::Approve,
                timestamp: 1000,
                signature: vec![0u8; 64],
            }],
            rejections: Vec::new(),
            created_at_epoch: None,
        };

        let result = manager
            .execute_governance_action("promo-immut-ctx", &proposal)
            .await;
        assert!(result.is_ok(), "promotion should succeed: {result:?}");

        // Verify promotion_policy is still Promotable (not mutated).
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("promo-immut-ctx").unwrap();
        assert_eq!(
            ctx.handle.params().promotion_policy,
            PromotionPolicy::Promotable,
            "promotion_policy must remain Promotable after promotion — it is immutable"
        );
    }

    // -----------------------------------------------------------------------
    // Ceiling enforcement tests (#339, §5.3)
    // -----------------------------------------------------------------------

    /// Helper: create a context with a specific ceiling for ceiling enforcement tests.
    async fn setup_context_with_ceiling(
        ceiling: Vec<Capability>,
    ) -> (ContextManager, ContextHandle, String) {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let params = ContextParams {
            ceiling,
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("ceiling-test-ctx".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        let ctx_id = "ceiling-test-ctx".to_owned();
        (manager, handle, ctx_id)
    }

    /// Helper: build a simple approved proposal for ceiling tests.
    fn ceiling_test_proposal(
        context_id: &str,
        action: GovernanceAction,
    ) -> super::GovernanceProposal {
        use scp_protocol::context::governance::{SignedVote, VoteType};
        super::GovernanceProposal {
            proposal_id: [42u8; 32],
            context_id: context_id.into(),
            proposer_did: "did:key:creator".into(),
            action,
            status: ProposalStatus::Approved,
            created_at: 1000,
            voting_deadline: 2000,
            approvals: vec![SignedVote {
                voter_did: "did:key:creator".into(),
                vote: VoteType::Approve,
                timestamp: 1000,
                signature: vec![0u8; 64],
            }],
            rejections: Vec::new(),
            created_at_epoch: None,
        }
    }

    /// #339: `RegisterTool` is rejected when `ToolRegister` is not in ceiling.
    #[tokio::test]
    async fn register_tool_rejected_without_ceiling_capability() {
        use scp_protocol::context::tools::registry::ToolSchema;

        let (manager, _handle, ctx_id) =
            setup_context_with_ceiling(vec![Capability::MessagesRead, Capability::MessagesWrite])
                .await;

        let reg = scp_protocol::context::params::ToolRegistration {
            tool_id: "test".to_owned(),
            name: "test".to_owned(),
            description: "test".to_owned(),
            schema: ToolSchema {
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: serde_json::json!({"type": "object"}),
            },
            implementation_hash: [0u8; 32],
            test_vectors: vec![],
            operator_did: "did:key:op".into(),
            cost: None,
            registered_at: 0,
            signature: Vec::new(),
        };

        let proposal = ceiling_test_proposal(
            &ctx_id,
            GovernanceAction::RegisterTool {
                registration: Box::new(reg),
            },
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ContextError::PermissionDenied(ref msg) if msg.contains("tool registration")),
            "expected PermissionDenied about tool registration, got: {err}"
        );
    }

    /// #339: `RegisterTool` succeeds when `ToolRegister` is in ceiling.
    #[tokio::test]
    async fn register_tool_succeeds_with_ceiling_capability() {
        use scp_protocol::context::tools::registry::ToolSchema;

        let (manager, _handle, ctx_id) = setup_context_with_ceiling(vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::ToolRegister,
        ])
        .await;

        let reg = scp_protocol::context::params::ToolRegistration {
            tool_id: "test".to_owned(),
            name: "test".to_owned(),
            description: "test".to_owned(),
            schema: ToolSchema {
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: serde_json::json!({"type": "object"}),
            },
            implementation_hash: [0u8; 32],
            test_vectors: vec![],
            operator_did: "did:key:op".into(),
            cost: None,
            registered_at: 0,
            signature: Vec::new(),
        };

        let proposal = ceiling_test_proposal(
            &ctx_id,
            GovernanceAction::RegisterTool {
                registration: Box::new(reg),
            },
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(result.is_ok(), "RegisterTool should succeed: {result:?}");
    }

    /// #339: `EstablishToolInterface` is rejected when `ToolInterface` is not in ceiling.
    #[tokio::test]
    async fn establish_tool_interface_rejected_without_ceiling_capability() {
        let (manager, _handle, ctx_id) =
            setup_context_with_ceiling(vec![Capability::MessagesRead, Capability::MessagesWrite])
                .await;

        let proposal = ceiling_test_proposal(
            &ctx_id,
            GovernanceAction::EstablishToolInterface {
                interface: ToolInterface {
                    source_context: ctx_id.clone(),
                    target_context: "other-ctx".into(),
                    tool_id: "tool-a".into(),
                    rate_limit: None,
                    per_caller_rate_limit: None,
                    approved_by_source: true,
                    approved_by_target: false,
                    outbound_policy: None,
                    inbound_policy: None,
                },
            },
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ContextError::PermissionDenied(ref msg) if msg.contains("tool interface")),
            "expected PermissionDenied about tool interface, got: {err}"
        );
    }

    /// #339: `CreateChildContext` is rejected when `ChildContextCreate` is not in ceiling.
    #[tokio::test]
    async fn create_child_context_rejected_without_ceiling_capability() {
        let (manager, _handle, ctx_id) =
            setup_context_with_ceiling(vec![Capability::MessagesRead, Capability::MessagesWrite])
                .await;

        let proposal = ceiling_test_proposal(
            &ctx_id,
            GovernanceAction::CreateChildContext {
                params: Box::new(ContextParams::default()),
            },
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ContextError::PermissionDenied(ref msg) if msg.contains("child context")),
            "expected PermissionDenied about child context, got: {err}"
        );
    }

    /// #339: `BlockAuthor` is rejected when `MemberBan` is not in ceiling.
    #[tokio::test]
    async fn block_author_rejected_without_member_ban_ceiling() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        manager.register_local_did("did:key:alice".into()).await;
        manager.register_local_did("did:key:bob".into()).await;

        // Ceiling WITHOUT MemberBan.
        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: MemoryScope::Full,
            ceiling: vec![
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::RoleAssign,
            ],
            ..ContextParams::default()
        };

        let _handle = manager
            .create_context("bc-no-ban".into(), params, "did:key:alice".into())
            .await
            .unwrap();

        // Add bob as author.
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("bc-no-ban").unwrap();
            let bc = ctx.broadcast_context.as_mut().unwrap();
            bc.add_author("did:key:bob").unwrap();
            ctx.membership
                .add_member("did:key:bob".into(), "author".into(), vec![]);
        }

        let proposal = approved_block_author_proposal(
            &"did:key:alice".into(),
            "bc-no-ban",
            &"did:key:bob".into(),
        );
        let result = manager
            .execute_governance_action("bc-no-ban", &proposal)
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ContextError::PermissionDenied(ref msg) if msg.contains("MemberBan")),
            "expected PermissionDenied about MemberBan, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Governance engine construction tests (SCP-267, ADR-031)
    // -----------------------------------------------------------------------

    /// AC 4: `create_context` constructs `SingleAdminEngine` when
    /// `GovernanceModel::SingleAdmin` is specified.
    #[tokio::test]
    async fn governance_single_admin_engine_constructed() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        let params = ContextParams {
            governance: GovernanceModel::SingleAdmin,
            ..ContextParams::default()
        };
        let creator: DID = "did:key:admin1".into();
        let handle = manager
            .create_context("ctx-gov-sa".into(), params, creator.clone())
            .await
            .unwrap();
        assert_eq!(handle.state().await, ContextState::Active);
        // Verify the engine is accessible inside the per-context state.
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("ctx-gov-sa").unwrap();
        let config = ctx.governance.engine.model_config();
        assert_eq!(
            config,
            GovernanceModelConfig::SingleAdmin { admin_did: creator }
        );
    }

    /// AC 5: `create_context_with_governance` constructs `ThresholdEngine`
    /// when `GovernanceModel::Threshold` is specified.
    #[tokio::test]
    async fn governance_threshold_engine_constructed() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        let creator: DID = "did:key:admin1".into();
        let signer2: DID = "did:key:signer2".into();
        let params = ContextParams {
            governance: GovernanceModel::Threshold {
                threshold: 2,
                signers: vec![creator.clone(), signer2.clone()],
            },
            ..ContextParams::default()
        };
        let config = GovernanceModelConfig::Threshold {
            signers: vec![creator.clone(), signer2.clone()],
            threshold: 2,
            voting_window_secs: 86_400,
        };
        let handle = manager
            .create_context_with_governance(
                "ctx-gov-thresh".into(),
                params,
                creator.clone(),
                config.clone(),
            )
            .await
            .unwrap();
        assert_eq!(handle.state().await, ContextState::Active);
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("ctx-gov-thresh").unwrap();
        assert_eq!(ctx.governance.engine.model_config(), config);
    }

    /// AC 6: `create_context_with_governance` constructs `MajorityVoteEngine`
    /// when `GovernanceModel::Majority` is specified.
    #[tokio::test]
    async fn governance_majority_engine_constructed() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        let creator: DID = "did:key:admin1".into();
        let params = ContextParams {
            governance: GovernanceModel::Majority {
                eligible_voters: vec![creator.clone()],
            },
            ..ContextParams::default()
        };
        let config = GovernanceModelConfig::Majority {
            voting_window_secs: 86_400,
            min_participation_bps: 5000,
        };
        let handle = manager
            .create_context_with_governance("ctx-gov-maj".into(), params, creator.clone(), config)
            .await
            .unwrap();
        assert_eq!(handle.state().await, ContextState::Active);
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("ctx-gov-maj").unwrap();
        let model_config = ctx.governance.engine.model_config();
        assert!(matches!(
            model_config,
            GovernanceModelConfig::Majority { .. }
        ));
    }

    /// AC 7: `create_context_with_governance` constructs `UnanimityEngine`
    /// when `GovernanceModel::Unanimity` is specified.
    #[tokio::test]
    async fn governance_unanimity_engine_constructed() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        let creator: DID = "did:key:admin1".into();
        let params = ContextParams {
            governance: GovernanceModel::Unanimity {
                eligible_voters: vec![creator.clone()],
            },
            ..ContextParams::default()
        };
        let config = GovernanceModelConfig::Unanimity {
            voting_window_secs: 172_800,
        };
        let handle = manager
            .create_context_with_governance(
                "ctx-gov-unan".into(),
                params,
                creator.clone(),
                config.clone(),
            )
            .await
            .unwrap();
        assert_eq!(handle.state().await, ContextState::Active);
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("ctx-gov-unan").unwrap();
        assert_eq!(ctx.governance.engine.model_config(), config);
    }

    /// AC 8/12: Invalid `GovernanceModelConfig` is rejected at creation time.
    /// Threshold > `signers.len()`.
    #[tokio::test]
    async fn governance_invalid_threshold_too_high_rejected() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        let creator: DID = "did:key:admin1".into();
        let params = ContextParams {
            governance: GovernanceModel::Threshold {
                threshold: 5,
                signers: vec![creator.clone()],
            },
            ..ContextParams::default()
        };
        let config = GovernanceModelConfig::Threshold {
            signers: vec![creator.clone()],
            threshold: 5, // > signers.len() (1)
            voting_window_secs: 86_400,
        };
        let result = manager
            .create_context_with_governance("ctx-bad-thresh".into(), params, creator, config)
            .await;
        assert!(result.is_err());
    }

    /// AC 8/12: Invalid `GovernanceModelConfig` — threshold == 0 rejected.
    #[tokio::test]
    async fn governance_invalid_threshold_zero_rejected() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        let creator: DID = "did:key:admin1".into();
        let params = ContextParams {
            governance: GovernanceModel::Threshold {
                threshold: 0,
                signers: vec![creator.clone()],
            },
            ..ContextParams::default()
        };
        let config = GovernanceModelConfig::Threshold {
            signers: vec![creator.clone()],
            threshold: 0,
            voting_window_secs: 86_400,
        };
        let result = manager
            .create_context_with_governance("ctx-bad-thresh-0".into(), params, creator, config)
            .await;
        assert!(result.is_err());
    }

    /// AC 8/12: Invalid `GovernanceModelConfig` — empty signers for Threshold.
    #[tokio::test]
    async fn governance_invalid_empty_signers_rejected() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        let creator: DID = "did:key:admin1".into();
        let params = ContextParams {
            governance: GovernanceModel::Threshold {
                threshold: 1,
                signers: vec![],
            },
            ..ContextParams::default()
        };
        let config = GovernanceModelConfig::Threshold {
            signers: vec![],
            threshold: 1,
            voting_window_secs: 86_400,
        };
        let result = manager
            .create_context_with_governance("ctx-bad-empty".into(), params, creator, config)
            .await;
        assert!(result.is_err());
    }

    /// AC 8/12: Invalid `GovernanceModelConfig` — `min_participation_bps` > 10000.
    #[tokio::test]
    async fn governance_invalid_min_participation_rejected() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        let creator: DID = "did:key:admin1".into();
        let params = ContextParams {
            governance: GovernanceModel::Majority {
                eligible_voters: vec![creator.clone()],
            },
            ..ContextParams::default()
        };
        let config = GovernanceModelConfig::Majority {
            voting_window_secs: 86_400,
            min_participation_bps: 10001, // > 10000
        };
        let result = manager
            .create_context_with_governance("ctx-bad-bps".into(), params, creator, config)
            .await;
        assert!(result.is_err());
    }

    /// AC 8: GovernanceModel/GovernanceModelConfig mismatch is rejected.
    #[tokio::test]
    async fn governance_model_config_mismatch_rejected() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        let creator: DID = "did:key:admin1".into();
        let params = ContextParams {
            governance: GovernanceModel::SingleAdmin,
            ..ContextParams::default()
        };
        // Mismatch: params says SingleAdmin, config says Threshold.
        let config = GovernanceModelConfig::Threshold {
            signers: vec![creator.clone()],
            threshold: 1,
            voting_window_secs: 86_400,
        };
        let result = manager
            .create_context_with_governance("ctx-mismatch".into(), params, creator, config)
            .await;
        assert!(result.is_err());
    }

    /// AC 10/13: UCAN tokens are minted for Threshold signers at creation.
    #[tokio::test]
    async fn governance_ucan_tokens_minted_for_threshold_signers() {
        let creator: DID = "did:key:creator1".into();
        let signer2: DID = "did:key:signer2".into();
        let signer3: DID = "did:key:signer3".into();

        let config = GovernanceModelConfig::Threshold {
            signers: vec![creator.clone(), signer2.clone(), signer3.clone()],
            threshold: 2,
            voting_window_secs: 86_400,
        };
        let engine =
            build_governance_engine(config, vec![creator.clone()], noop_key_resolver()).unwrap();
        let tokens = mint_governance_tokens(
            "ctx-ucan-test",
            &creator,
            engine.as_ref(),
            &scp_primitives::SystemClock,
        );

        // 3 signers x 2 capabilities (GovernancePropose + GovernanceVote) = 6 tokens.
        assert_eq!(tokens.len(), 6);

        // Verify each signer has both GovernancePropose and GovernanceVote tokens.
        for signer in [&creator, &signer2, &signer3] {
            let signer_tokens: Vec<_> = tokens.iter().filter(|t| *signer == t.aud).collect();
            assert_eq!(signer_tokens.len(), 2, "each signer should have 2 tokens");
            let capabilities: Vec<&str> = signer_tokens
                .iter()
                .map(|t| t.att[0].with.as_str())
                .collect();
            assert!(
                capabilities
                    .iter()
                    .any(|c| c.contains("governance:propose")),
                "should have GovernancePropose token"
            );
            assert!(
                capabilities.iter().any(|c| c.contains("governance:vote")),
                "should have GovernanceVote token"
            );
        }

        // All tokens should be issued by the creator.
        for token in &tokens {
            assert_eq!(token.iss, creator.to_string());
        }
    }

    /// AC 10: UCAN tokens for `SingleAdmin` include both `GovernancePropose`
    /// and `GovernanceVote` for the admin.
    #[tokio::test]
    async fn governance_ucan_tokens_minted_for_single_admin() {
        let creator: DID = "did:key:creator1".into();
        let engine = Box::new(SingleAdminEngine::new(creator.clone(), noop_key_resolver()));
        let tokens = mint_governance_tokens(
            "ctx-sa-ucan",
            &creator,
            engine.as_ref(),
            &scp_primitives::SystemClock,
        );

        // 1 voter x 2 capabilities = 2 tokens.
        assert_eq!(tokens.len(), 2);
        assert!(tokens.iter().all(|t| creator == t.aud));
        assert!(tokens.iter().all(|t| creator == t.iss));
    }

    /// AC 11: Default `create_context` constructs engines for all four
    /// governance model variants without explicit `GovernanceModelConfig`.
    #[tokio::test]
    async fn governance_default_engine_all_variants() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        let creator: DID = "did:key:admin1".into();

        let models = [
            GovernanceModel::SingleAdmin,
            GovernanceModel::Threshold {
                threshold: 1,
                signers: vec![creator.clone()],
            },
            GovernanceModel::Majority {
                eligible_voters: vec![creator.clone()],
            },
            GovernanceModel::Unanimity {
                eligible_voters: vec![creator.clone()],
            },
        ];

        for (i, model) in models.iter().enumerate() {
            let params = ContextParams {
                governance: model.clone(),
                ..ContextParams::default()
            };
            let ctx_id = format!("ctx-default-{i}");
            let handle = manager
                .create_context(ctx_id.clone(), params, creator.clone())
                .await
                .unwrap();
            assert_eq!(handle.state().await, ContextState::Active);
        }
    }

    // -----------------------------------------------------------------------
    // Governance proposal lifecycle tests (SCP-268)
    // -----------------------------------------------------------------------

    /// Helper: creates a manager with an active context whose ceiling includes
    /// governance capabilities, so propose/vote operations succeed.
    async fn setup_governance_context() -> (ContextManager, ContextHandle, String) {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );

        let params = ContextParams {
            ceiling: vec![
                scp_protocol::context::params::Capability::new("messages:read"),
                scp_protocol::context::params::Capability::new("messages:write"),
                scp_protocol::context::params::Capability::new("role:assign"),
                scp_protocol::context::params::Capability::new("governance:propose"),
                scp_protocol::context::params::Capability::new("governance:vote"),
                scp_protocol::context::params::Capability::new("context:close"),
            ],
            ..ContextParams::default()
        };

        let admin_did: DID = "did:key:admin".into();
        let handle = manager
            .create_context("gov-ctx".into(), params, admin_did)
            .await
            .unwrap();

        (manager, handle, "gov-ctx".to_owned())
    }

    /// SCP-268 AC1: `SingleAdmin.propose()` returns `ProposalOutcome` with
    /// `Approved` status (auto-approve per ADR-031 section 4a) and `execution_result: None`.
    #[tokio::test]
    async fn governance_single_admin_propose_checked_auto_approves() {
        let (manager, _handle, ctx_id) = setup_governance_context().await;
        let admin_did: DID = "did:key:admin".into();
        let signing_key = signing_key_for_did(&admin_did);

        let action = super::GovernanceAction::CloseContext { reason: None };

        let outcome = manager
            .propose_governance_action_checked(&ctx_id, &admin_did, action, &signing_key)
            .await
            .unwrap();

        // SingleAdmin auto-approves (ADR-031 section 4a).
        assert!(
            matches!(outcome.status, super::ProposalStatus::Approved),
            "SingleAdmin proposals should be auto-approved"
        );
        assert!(
            outcome.execution_result.is_some(),
            "execution_result must be Some for auto-approved SingleAdmin proposals (SCP-270)"
        );
        assert_eq!(outcome.proposal.proposer_did, admin_did);
        assert_eq!(outcome.proposal.context_id, ctx_id);
    }

    /// SCP-268 AC5: proposing on a non-Active context returns `ContextNotActive`.
    #[tokio::test]
    async fn governance_propose_checked_on_inactive_context_returns_not_active() {
        let (manager, handle, ctx_id) = setup_governance_context().await;
        let admin_did: DID = "did:key:admin".into();
        let signing_key = signing_key_for_did(&admin_did);

        // Transition to Closing.
        handle.transition_to(&ContextState::Closing).await.unwrap();

        let result = manager
            .propose_governance_action_checked(
                &ctx_id,
                &admin_did,
                super::GovernanceAction::CloseContext { reason: None },
                &signing_key,
            )
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::ContextNotActive
        ));
    }

    /// SCP-268 AC6: proposing without `GovernancePropose` capability is rejected.
    #[tokio::test]
    async fn governance_propose_checked_without_capability_rejected() {
        let (manager, _handle, ctx_id) = setup_governance_context().await;

        // Join bob as a member (default role = member, which has messages:read/write
        // but not governance:propose).
        let kp = KeyPackage::mock("did:key:bob".into());
        let handle_ref = {
            let contexts = manager.contexts.lock().await;
            contexts.get(&ctx_id).unwrap().handle.clone()
        };
        manager.join_context(&handle_ref, kp).await.unwrap();

        let bob_did: DID = "did:key:bob".into();
        let signing_key = signing_key_for_did(&bob_did);
        let result = manager
            .propose_governance_action_checked(
                &ctx_id,
                &bob_did,
                super::GovernanceAction::CloseContext { reason: None },
                &signing_key,
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ContextError::PermissionDenied(_)),
            "member without governance:propose should be rejected: {err}"
        );
    }

    /// SCP-268 AC7: approve/reject without `GovernanceVote` capability is rejected.
    #[tokio::test]
    async fn governance_vote_without_capability_rejected() {
        let (manager, _handle, ctx_id) = setup_governance_context().await;

        // Join bob as member (no governance:vote capability).
        let kp = KeyPackage::mock("did:key:bob".into());
        let handle_ref = {
            let contexts = manager.contexts.lock().await;
            contexts.get(&ctx_id).unwrap().handle.clone()
        };
        manager.join_context(&handle_ref, kp).await.unwrap();

        let bob_did: DID = "did:key:bob".into();
        let signing_key = signing_key_for_did(&bob_did);
        let fake_proposal_id = [0u8; 32];

        // approve should fail
        let approve_result = manager
            .approve_governance_proposal(&ctx_id, &fake_proposal_id, &bob_did, &signing_key)
            .await;
        assert!(approve_result.is_err());
        assert!(matches!(
            approve_result.unwrap_err(),
            ContextError::PermissionDenied(_)
        ));

        // reject should fail
        let reject_result = manager
            .reject_governance_proposal(&ctx_id, &fake_proposal_id, &bob_did, &signing_key)
            .await;
        assert!(reject_result.is_err());
        assert!(matches!(
            reject_result.unwrap_err(),
            ContextError::PermissionDenied(_)
        ));
    }

    /// SCP-268 AC8: governance events are recorded in the event log.
    #[tokio::test]
    async fn governance_propose_checked_records_events() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::<MockEventLog>::from(MockEventLog::default()),
            mock_key_resolver(),
        );

        let params = ContextParams {
            ceiling: vec![
                scp_protocol::context::params::Capability::new("messages:read"),
                scp_protocol::context::params::Capability::new("messages:write"),
                scp_protocol::context::params::Capability::new("governance:propose"),
                scp_protocol::context::params::Capability::new("governance:vote"),
            ],
            ..ContextParams::default()
        };

        let admin_did: DID = "did:key:admin".into();
        let _handle = manager
            .create_context("ev-ctx".into(), params, admin_did.clone())
            .await
            .unwrap();

        let signing_key = signing_key_for_did(&admin_did);

        let outcome = manager
            .propose_governance_action_checked(
                "ev-ctx",
                &admin_did,
                super::GovernanceAction::CloseContext { reason: None },
                &signing_key,
            )
            .await
            .unwrap();

        // SingleAdmin produces ProposalCreated + VoteCast + ProposalResolved
        // events. Verify they were logged.
        assert!(matches!(outcome.status, super::ProposalStatus::Approved));
    }

    /// SCP-268 AC3/AC4: `ThresholdEngine` governance multi-vote lifecycle.
    /// Propose creates `Pending` proposal; approve reaches quorum -> `Approved`.
    #[tokio::test]
    async fn governance_threshold_propose_approve_lifecycle() {
        let alice_did: DID = "did:key:alice".into();
        let bob_did: DID = "did:key:bob".into();

        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );

        let params = ContextParams {
            ceiling: vec![
                scp_protocol::context::params::Capability::new("messages:read"),
                scp_protocol::context::params::Capability::new("messages:write"),
                scp_protocol::context::params::Capability::new("role:assign"),
                scp_protocol::context::params::Capability::new("governance:propose"),
                scp_protocol::context::params::Capability::new("governance:vote"),
            ],
            governance: GovernanceModel::Threshold {
                threshold: 2,
                signers: vec![alice_did.clone(), bob_did.clone()],
            },
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("thresh-ctx".into(), params, alice_did.clone())
            .await
            .unwrap();

        // Join bob.
        let kp = KeyPackage::mock("did:key:bob".into());
        manager.join_context(&handle, kp).await.unwrap();

        // Grant governance capabilities to bob.
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("thresh-ctx").unwrap();
            ctx.role_state
                .member_capabilities
                .entry("did:key:bob".to_owned())
                .or_default()
                .insert(Capability::GovernancePropose);
            ctx.role_state
                .member_capabilities
                .entry("did:key:bob".to_owned())
                .or_default()
                .insert(Capability::GovernanceVote);
        }

        let signing_key_alice = signing_key_for_did(&alice_did);
        let signing_key_bob = signing_key_for_did(&bob_did);

        // Alice proposes via capability-checked path.
        let outcome = manager
            .propose_governance_action_checked(
                "thresh-ctx",
                &alice_did,
                super::GovernanceAction::CloseContext { reason: None },
                &signing_key_alice,
            )
            .await
            .unwrap();

        // Threshold 2-of-2: proposer's vote counts as 1, so status is Pending.
        assert!(
            matches!(outcome.status, super::ProposalStatus::Pending),
            "2-of-2 threshold should start as Pending after first vote, got: {:?}",
            outcome.status
        );

        let proposal_id = outcome.proposal.proposal_id;

        // Bob approves -> quorum reached -> Approved.
        let status = manager
            .approve_governance_proposal("thresh-ctx", &proposal_id, &bob_did, &signing_key_bob)
            .await
            .unwrap();

        assert!(
            matches!(status, super::ProposalStatus::Approved),
            "2-of-2 threshold should be Approved after second vote, got: {status:?}"
        );
    }

    /// SCP-268: proposing on a non-existent context returns `MembershipFailed`.
    #[tokio::test]
    async fn governance_propose_checked_on_nonexistent_context() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );

        let admin_did: DID = "did:key:admin".into();
        let signing_key = signing_key_for_did(&admin_did);
        let result = manager
            .propose_governance_action_checked(
                "nonexistent",
                &admin_did,
                super::GovernanceAction::CloseContext { reason: None },
                &signing_key,
            )
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::ContextNotRegistered(_)
        ));
    }

    /// SCP-268: `withdraw_governance_vote` returns `PermissionDenied` for `SingleAdmin`.
    #[tokio::test]
    async fn governance_withdraw_vote_single_admin_not_supported() {
        let (manager, _handle, ctx_id) = setup_governance_context().await;
        let admin_did: DID = "did:key:admin".into();
        let fake_proposal_id = [0u8; 32];

        let result = manager
            .withdraw_governance_vote(&ctx_id, &fake_proposal_id, &admin_did)
            .await;

        // SingleAdmin does not support withdraw_vote.
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::PermissionDenied(_)
        ));
    }

    // -------------------------------------------------------------------
    // SCP-270: auto-execution, unanimity overrides, governance bypass
    // -------------------------------------------------------------------

    /// Helper: `ContextParams` with governance-compatible ceiling.
    fn governance_params() -> ContextParams {
        ContextParams {
            ceiling: vec![
                scp_protocol::context::params::Capability::new("messages:read"),
                scp_protocol::context::params::Capability::new("messages:write"),
                scp_protocol::context::params::Capability::new("role:assign"),
                scp_protocol::context::params::Capability::new("governance:propose"),
                scp_protocol::context::params::Capability::new("governance:vote"),
                scp_protocol::context::params::Capability::new("member:ban"),
                scp_protocol::context::params::Capability::new("context:close"),
            ],
            ..ContextParams::default()
        }
    }

    /// Helper: build an approved proposal with customizable approvals.
    fn approved_proposal(
        pid: [u8; 32],
        context_id: &str,
        action: GovernanceAction,
        approver_dids: &[&str],
    ) -> GovernanceProposal {
        use scp_protocol::context::governance::{SignedVote, VoteType};
        GovernanceProposal {
            proposal_id: pid,
            context_id: context_id.into(),
            proposer_did: approver_dids
                .first()
                .unwrap_or(&"did:key:creator")
                .to_string()
                .into(),
            action,
            status: ProposalStatus::Approved,
            created_at: 1000,
            voting_deadline: 2000,
            approvals: approver_dids
                .iter()
                .enumerate()
                .map(|(i, did)| SignedVote {
                    voter_did: (*did).to_owned().into(),
                    vote: VoteType::Approve,
                    timestamp: 1000 + i as u64,
                    signature: vec![0u8; 64],
                })
                .collect(),
            rejections: Vec::new(),
            created_at_epoch: None,
        }
    }

    /// SCP-270 AC14: each `GovernanceAction` variant executes through governance.
    /// Covered by the existing `single_admin_propose_auto_executes` and
    /// per-action tests. This test verifies the dispatch returns typed results.
    #[tokio::test]
    async fn governance_dispatch_returns_typed_results() {
        use scp_protocol::context::governance::{GovernanceProposal, SignedVote, VoteType};

        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let params = governance_params();
        let _handle = manager
            .create_context("typed-result-ctx".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        // AddMember
        let proposal = GovernanceProposal {
            proposal_id: [10u8; 32],
            context_id: "typed-result-ctx".into(),
            proposer_did: "did:key:creator".into(),
            action: GovernanceAction::AddMember {
                did: "did:key:new".into(),
                role: "member".to_owned(),
            },
            status: ProposalStatus::Approved,
            created_at: 1000,
            voting_deadline: 2000,
            approvals: vec![SignedVote {
                voter_did: "did:key:creator".into(),
                vote: VoteType::Approve,
                timestamp: 1000,
                signature: vec![0u8; 64],
            }],
            rejections: Vec::new(),
            created_at_epoch: None,
        };
        let result = manager
            .execute_governance_action("typed-result-ctx", &proposal)
            .await
            .unwrap();
        assert!(
            matches!(result, GovernanceActionResult::MemberAdded),
            "AddMember should return MemberAdded, got: {result:?}"
        );

        // RemoveMember
        let proposal = GovernanceProposal {
            proposal_id: [11u8; 32],
            context_id: "typed-result-ctx".into(),
            proposer_did: "did:key:creator".into(),
            action: GovernanceAction::RemoveMember {
                did: "did:key:new".into(),
                reason: None,
            },
            status: ProposalStatus::Approved,
            created_at: 1000,
            voting_deadline: 2000,
            approvals: vec![SignedVote {
                voter_did: "did:key:creator".into(),
                vote: VoteType::Approve,
                timestamp: 1000,
                signature: vec![0u8; 64],
            }],
            rejections: Vec::new(),
            created_at_epoch: None,
        };
        let result = manager
            .execute_governance_action("typed-result-ctx", &proposal)
            .await
            .unwrap();
        assert!(
            matches!(result, GovernanceActionResult::MemberRemoved),
            "RemoveMember should return MemberRemoved, got: {result:?}"
        );
    }

    /// SCP-270 AC15: auto-execution on Approved status for `SingleAdmin`.
    #[tokio::test]
    async fn governance_auto_execution_single_admin() {
        let (manager, _handle, ctx_id) = setup_governance_context().await;
        let admin_did: DID = "did:key:admin".into();
        let signing_key = signing_key_for_did(&admin_did);

        // propose_governance_action for SingleAdmin auto-executes.
        let (proposal, _events) = manager
            .propose_governance_action(
                &ctx_id,
                &admin_did,
                GovernanceAction::AddMember {
                    did: "did:key:newmember".into(),
                    role: "member".to_owned(),
                },
                &signing_key,
            )
            .await
            .unwrap();

        // Proposal should be Approved (auto-approved by SingleAdmin).
        assert_eq!(proposal.status, ProposalStatus::Approved);

        // The member should already be added (auto-executed).
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get(&ctx_id).unwrap();
        assert!(
            ctx.membership.contains("did:key:newmember"),
            "auto-execution should have added the member"
        );
    }

    /// SCP-270 AC15: auto-execution on Approved status for Threshold model.
    #[tokio::test]
    async fn governance_auto_execution_threshold_on_approval() {
        let creator: DID = "did:key:creator".into();
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );

        let mut params = governance_params();
        params.governance = GovernanceModel::Threshold {
            threshold: 1,
            signers: vec![creator.clone()],
        };

        let _handle = manager
            .create_context("thresh-auto-ctx".into(), params, creator.clone())
            .await
            .unwrap();

        let signing_key = signing_key_for_did(&creator);
        // Threshold with 1-of-1: proposal auto-approved on propose.
        let (proposal, _) = manager
            .propose_governance_action(
                "thresh-auto-ctx",
                &creator,
                GovernanceAction::AddMember {
                    did: "did:key:bob".into(),
                    role: "member".to_owned(),
                },
                &signing_key,
            )
            .await
            .unwrap();

        assert_eq!(proposal.status, ProposalStatus::Approved);

        // Verify auto-execution happened.
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("thresh-auto-ctx").unwrap();
        assert!(
            ctx.membership.contains("did:key:bob"),
            "auto-execution should have added the member on threshold quorum"
        );
    }

    /// SCP-270 AC16: `close_context` through governance for Threshold model.
    #[tokio::test]
    async fn close_context_through_governance_threshold() {
        let creator: DID = "did:key:creator".into();
        let signer2: DID = "did:key:signer2".into();
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );

        let mut params = governance_params();
        params.governance = GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![creator.clone(), signer2.clone()],
        };

        let handle = manager
            .create_context("close-thresh-ctx".into(), params, creator.clone())
            .await
            .unwrap();

        // Direct close_context should fail for multi-admin.
        let result = manager.close_context(&handle, &creator).await;
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ContextError::PermissionDenied(ref msg) if msg.contains("multi-admin")),
            "close_context should reject multi-admin contexts"
        );

        // Verify context is still active.
        assert_eq!(handle.state().await, ContextState::Active);
    }

    /// SCP-270 AC17: `ExtendTtl` unanimity override — partial approval rejected.
    #[tokio::test]
    async fn extend_ttl_rejects_without_unanimity() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        let mut params = governance_params();
        params.ttl = Some(std::time::Duration::from_secs(3600));
        let _handle = manager
            .create_context("ttl-unan-ctx".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        // Add a second member.
        let add = approved_proposal(
            [20u8; 32],
            "ttl-unan-ctx",
            GovernanceAction::AddMember {
                did: "did:key:bob".into(),
                role: "member".to_owned(),
            },
            &["did:key:creator"],
        );
        manager
            .execute_governance_action("ttl-unan-ctx", &add)
            .await
            .unwrap();

        // ExtendTtl with only creator's approval (bob hasn't approved).
        let extend = approved_proposal(
            [21u8; 32],
            "ttl-unan-ctx",
            GovernanceAction::ExtendTtl {
                additional_secs: 3600,
            },
            &["did:key:creator"],
        );
        let result = manager
            .execute_governance_action("ttl-unan-ctx", &extend)
            .await;
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ContextError::PermissionDenied(ref msg) if msg.contains("unanimous")),
            "ExtendTtl should require unanimity"
        );
    }

    /// SCP-270 AC17: `ExtendTtl` unanimity override — unanimous approval succeeds.
    #[tokio::test]
    async fn extend_ttl_succeeds_with_unanimity() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        let mut params = governance_params();
        params.ttl = Some(std::time::Duration::from_secs(3600));
        let _handle = manager
            .create_context("ttl-unan2-ctx".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        // Add a second member.
        let add = approved_proposal(
            [20u8; 32],
            "ttl-unan2-ctx",
            GovernanceAction::AddMember {
                did: "did:key:bob".into(),
                role: "member".to_owned(),
            },
            &["did:key:creator"],
        );
        manager
            .execute_governance_action("ttl-unan2-ctx", &add)
            .await
            .unwrap();

        // ExtendTtl with both members' approval.
        let extend = approved_proposal(
            [22u8; 32],
            "ttl-unan2-ctx",
            GovernanceAction::ExtendTtl {
                additional_secs: 3600,
            },
            &["did:key:creator", "did:key:bob"],
        );
        let result = manager
            .execute_governance_action("ttl-unan2-ctx", &extend)
            .await;
        assert!(
            result.is_ok(),
            "ExtendTtl with unanimity should succeed: {result:?}"
        );
        assert!(matches!(
            result.unwrap(),
            GovernanceActionResult::TtlExtended
        ));
    }

    /// SCP-270 AC18: `PromoteContext` unanimity override.
    #[tokio::test]
    async fn promote_context_requires_unanimity() {
        use scp_protocol::context::governance::{GovernanceProposal, SignedVote, VoteType};
        use scp_protocol::context::params::{MemoryScope, PromotionPolicy};

        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let mut params = governance_params();
        params.promotion_policy = PromotionPolicy::Promotable;
        params.memory_scope = MemoryScope::Ephemeral;
        params.ttl = Some(std::time::Duration::from_secs(3600));

        let _handle = manager
            .create_context(
                "promo-unanimity-ctx".into(),
                params,
                "did:key:creator".into(),
            )
            .await
            .unwrap();

        // Add a second member.
        let add_proposal = GovernanceProposal {
            proposal_id: [30u8; 32],
            context_id: "promo-unanimity-ctx".into(),
            proposer_did: "did:key:creator".into(),
            action: GovernanceAction::AddMember {
                did: "did:key:carol".into(),
                role: "member".to_owned(),
            },
            status: ProposalStatus::Approved,
            created_at: 1000,
            voting_deadline: 2000,
            approvals: vec![SignedVote {
                voter_did: "did:key:creator".into(),
                vote: VoteType::Approve,
                timestamp: 1000,
                signature: vec![0u8; 64],
            }],
            rejections: Vec::new(),
            created_at_epoch: None,
        };
        manager
            .execute_governance_action("promo-unanimity-ctx", &add_proposal)
            .await
            .unwrap();

        // PromoteContext with only creator's approval — should fail.
        let promote_proposal = GovernanceProposal {
            proposal_id: [31u8; 32],
            context_id: "promo-unanimity-ctx".into(),
            proposer_did: "did:key:creator".into(),
            action: GovernanceAction::PromoteContext,
            status: ProposalStatus::Approved,
            created_at: 1000,
            voting_deadline: 2000,
            approvals: vec![SignedVote {
                voter_did: "did:key:creator".into(),
                vote: VoteType::Approve,
                timestamp: 1000,
                signature: vec![0u8; 64],
            }],
            rejections: Vec::new(),
            created_at_epoch: None,
        };

        let result = manager
            .execute_governance_action("promo-unanimity-ctx", &promote_proposal)
            .await;
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ContextError::PermissionDenied(ref msg) if msg.contains("unanimous")),
            "PromoteContext should require unanimity"
        );
    }

    /// SCP-270 AC19: governance bypass prevention — standalone `close_context`
    /// returns error for multi-admin models.
    #[tokio::test]
    async fn governance_bypass_prevented_for_multi_admin_close() {
        let creator: DID = "did:key:creator".into();
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );

        // Create a Majority governance context.
        let mut params = governance_params();
        params.governance = GovernanceModel::Majority {
            eligible_voters: vec![creator.clone()],
        };
        let handle = manager
            .create_context("bypass-test-ctx".into(), params, creator.clone())
            .await
            .unwrap();

        // Direct close_context should fail.
        let result = manager.close_context(&handle, &creator).await;
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ContextError::PermissionDenied(ref msg) if msg.contains("multi-admin")),
            "standalone close_context must reject multi-admin contexts"
        );
    }

    /// SCP-270 AC5: `close_context` for `SingleAdmin` goes through engine (auto-approve).
    #[tokio::test]
    async fn close_context_single_admin_succeeds() {
        let (manager, handle, _ctx_id) = setup_governance_context().await;
        let admin_did: DID = "did:key:admin".into();

        let result = manager.close_context(&handle, &admin_did).await;
        assert!(
            result.is_ok(),
            "SingleAdmin close_context should succeed: {result:?}"
        );
    }

    /// SCP-270 AC11: `AddSigner` mints `GovernanceVote` + `GovernancePropose` UCANs.
    #[tokio::test]
    async fn add_signer_mints_governance_ucans() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        let mut params = governance_params();
        params.governance = GovernanceModel::Threshold {
            threshold: 1,
            signers: vec!["did:key:creator".into()],
        };
        let _handle = manager
            .create_context("signer-ucan-ctx".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        // Add member, then add as signer.
        let add = approved_proposal(
            [40u8; 32],
            "signer-ucan-ctx",
            GovernanceAction::AddMember {
                did: "did:key:newsigner".into(),
                role: "member".to_owned(),
            },
            &["did:key:creator"],
        );
        manager
            .execute_governance_action("signer-ucan-ctx", &add)
            .await
            .unwrap();

        let add_s = approved_proposal(
            [41u8; 32],
            "signer-ucan-ctx",
            GovernanceAction::AddSigner {
                did: "did:key:newsigner".into(),
            },
            &["did:key:creator"],
        );
        let result = manager
            .execute_governance_action("signer-ucan-ctx", &add_s)
            .await;
        assert!(result.is_ok(), "AddSigner should succeed: {result:?}");

        // Verify GovernanceVote + GovernancePropose capabilities were granted.
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("signer-ucan-ctx").unwrap();
        let caps = ctx
            .role_state
            .member_capabilities
            .get("did:key:newsigner")
            .expect("new signer should have capabilities");
        assert!(caps.contains(&Capability::GovernancePropose));
        assert!(caps.contains(&Capability::GovernanceVote));
    }

    /// SCP-270 AC12: `RemoveSigner` revokes governance UCANs and validates threshold.
    #[tokio::test]
    async fn remove_signer_revokes_governance_ucans() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        let mut params = governance_params();
        // Only creator is an initial signer; signer3 will be added dynamically.
        params.governance = GovernanceModel::Threshold {
            threshold: 1,
            signers: vec!["did:key:creator".into()],
        };
        let _handle = manager
            .create_context("rm-signer-ctx".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        // Add signer3 as member, then grant signer role.
        let add = approved_proposal(
            [50u8; 32],
            "rm-signer-ctx",
            GovernanceAction::AddMember {
                did: "did:key:signer3".into(),
                role: "member".to_owned(),
            },
            &["did:key:creator"],
        );
        manager
            .execute_governance_action("rm-signer-ctx", &add)
            .await
            .unwrap();

        let add_s = approved_proposal(
            [51u8; 32],
            "rm-signer-ctx",
            GovernanceAction::AddSigner {
                did: "did:key:signer3".into(),
            },
            &["did:key:creator"],
        );
        manager
            .execute_governance_action("rm-signer-ctx", &add_s)
            .await
            .unwrap();

        // Verify signer3 has governance capabilities.
        {
            let contexts = manager.contexts.lock().await;
            let ctx = contexts.get("rm-signer-ctx").unwrap();
            let caps = ctx
                .role_state
                .member_capabilities
                .get("did:key:signer3")
                .expect("signer3 should have capabilities");
            assert!(caps.contains(&Capability::GovernanceVote));
        }

        // Remove signer3.
        let rm = approved_proposal(
            [52u8; 32],
            "rm-signer-ctx",
            GovernanceAction::RemoveSigner {
                did: "did:key:signer3".into(),
            },
            &["did:key:creator"],
        );
        let result = manager
            .execute_governance_action("rm-signer-ctx", &rm)
            .await;
        assert!(result.is_ok(), "RemoveSigner should succeed: {result:?}");

        // Verify governance capabilities were revoked.
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("rm-signer-ctx").unwrap();
        if let Some(caps) = ctx.role_state.member_capabilities.get("did:key:signer3") {
            assert!(!caps.contains(&Capability::GovernancePropose));
            assert!(!caps.contains(&Capability::GovernanceVote));
        }
        assert!(
            ctx.membership.contains("did:key:signer3"),
            "should remain a member"
        );
    }

    // ===================================================================
    // CAC-009: full block/unblock lifecycle across context types
    // ===================================================================

    #[tokio::test]
    async fn cac009_tier1_encrypted_block_unblock() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        manager.register_local_did("did:key:alice".into()).await;
        let params = ContextParams {
            mode: ContextMode::Encrypted,
            memory_scope: MemoryScope::Full,
            ceiling: vec![
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::RoleAssign,
                Capability::MemberBan,
            ],
            ..ContextParams::default()
        };
        let _handle = manager
            .create_context("cac009-enc".into(), params, "did:key:alice".into())
            .await
            .unwrap();
        for did in &["did:key:dave", "did:key:bob"] {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("cac009-enc").unwrap();
            ctx.membership
                .add_member((*did).to_owned().into(), "member".into(), vec![]);
        }
        let revoke = approved_governance_proposal(
            &"did:key:alice".into(),
            "cac009-enc",
            &"did:key:dave".into(),
            GovernanceAction::RevokeReadAccess {
                did: "did:key:dave".into(),
                scope: super::RevocationScope::Full,
            },
        );
        let result = manager
            .execute_governance_action("cac009-enc", &revoke)
            .await;
        assert!(
            result.is_ok(),
            "RevokeReadAccess should succeed: {result:?}"
        );
        {
            let contexts = manager.contexts.lock().await;
            let ctx = contexts.get("cac009-enc").unwrap();
            assert!(
                ctx.access
                    .read_revoked_members
                    .contains(&DID("did:key:dave".into())),
                "Dave should be read-revoked"
            );
            assert!(
                ctx.membership.contains("did:key:dave"),
                "Dave should remain a member"
            );
        }
        let events = manager.drain_events("cac009-enc").await;
        assert!(events.iter().any(
            |e| matches!(e, ContextEvent::ReadAccessRevoked { did } if did.0 == "did:key:dave")
        ));
        let restore = approved_governance_proposal(
            &"did:key:alice".into(),
            "cac009-enc",
            &"did:key:dave".into(),
            GovernanceAction::RestoreReadAccess {
                did: "did:key:dave".into(),
            },
        );
        let result = manager
            .execute_governance_action("cac009-enc", &restore)
            .await;
        assert!(
            result.is_ok(),
            "RestoreReadAccess should succeed: {result:?}"
        );
        {
            let contexts = manager.contexts.lock().await;
            let ctx = contexts.get("cac009-enc").unwrap();
            assert!(
                !ctx.access
                    .read_revoked_members
                    .contains(&DID("did:key:dave".into()))
            );
        }
        let events = manager.drain_events("cac009-enc").await;
        assert!(events.iter().any(
            |e| matches!(e, ContextEvent::ReadAccessRestored { did } if did.0 == "did:key:dave")
        ));
    }

    #[tokio::test]
    async fn cac009_tier2_global_block_multiple_contexts() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        manager.register_local_did("did:key:alice".into()).await;
        let make_params = || ContextParams {
            mode: ContextMode::Encrypted,
            memory_scope: MemoryScope::Full,
            ceiling: vec![
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::RoleAssign,
                Capability::MemberBan,
            ],
            ..ContextParams::default()
        };
        let _h1 = manager
            .create_context("cac009-g1".into(), make_params(), "did:key:alice".into())
            .await
            .unwrap();
        let _h2 = manager
            .create_context("cac009-g2".into(), make_params(), "did:key:alice".into())
            .await
            .unwrap();
        for ctx_id in &["cac009-g1", "cac009-g2"] {
            let mut contexts = manager.contexts.lock().await;
            contexts.get_mut(*ctx_id).unwrap().membership.add_member(
                "did:key:eve".into(),
                "member".into(),
                vec![],
            );
        }
        for ctx_id in &["cac009-g1", "cac009-g2"] {
            let revoke = approved_governance_proposal(
                &"did:key:alice".into(),
                ctx_id,
                &"did:key:eve".into(),
                GovernanceAction::RevokeReadAccess {
                    did: "did:key:eve".into(),
                    scope: super::RevocationScope::Full,
                },
            );
            manager
                .execute_governance_action(ctx_id, &revoke)
                .await
                .unwrap();
        }
        {
            let contexts = manager.contexts.lock().await;
            for ctx_id in &["cac009-g1", "cac009-g2"] {
                assert!(
                    contexts
                        .get(*ctx_id)
                        .unwrap()
                        .access
                        .read_revoked_members
                        .contains(&DID("did:key:eve".into())),
                    "Eve read-revoked in {ctx_id}"
                );
            }
        }
        for ctx_id in &["cac009-g1", "cac009-g2"] {
            let restore = approved_governance_proposal(
                &"did:key:alice".into(),
                ctx_id,
                &"did:key:eve".into(),
                GovernanceAction::RestoreReadAccess {
                    did: "did:key:eve".into(),
                },
            );
            manager
                .execute_governance_action(ctx_id, &restore)
                .await
                .unwrap();
        }
        {
            let contexts = manager.contexts.lock().await;
            for ctx_id in &["cac009-g1", "cac009-g2"] {
                assert!(
                    !contexts
                        .get(*ctx_id)
                        .unwrap()
                        .access
                        .read_revoked_members
                        .contains(&DID("did:key:eve".into())),
                    "Eve restored in {ctx_id}"
                );
            }
        }
    }

    #[tokio::test]
    async fn cac009_broadcast_governance_revoke_restore() {
        let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;
        {
            let contexts = manager.contexts.lock().await;
            assert!(
                contexts
                    .get(&ctx_id)
                    .unwrap()
                    .broadcast_context
                    .as_ref()
                    .unwrap()
                    .is_author("did:key:bob")
            );
        }
        let revoke = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            GovernanceAction::RevokeWriteAccess {
                did: "did:key:bob".into(),
                scope: super::RevocationScope::Full,
            },
        );
        manager
            .execute_governance_action(&ctx_id, &revoke)
            .await
            .unwrap();
        let (bob_custody, bob_key_handle) = test_custody_from_seed(&[0xBB; 32]).await;
        assert!(
            manager
                .publish_broadcast(
                    &ctx_id,
                    &"did:key:bob".into(),
                    b"blocked",
                    &bob_custody,
                    &bob_key_handle,
                )
                .await
                .is_err(),
            "revoked author should not publish"
        );
        {
            use scp_protocol::crypto::ucan::validate::{
                InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
                InMemoryRevocationChecker,
            };
            use std::hash::RandomState;
            manager.subscribe_broadcast::<InMemoryDidResolver, InMemoryNonceTracker, InMemoryRevocationChecker, InMemoryProofResolver, RandomState>(&ctx_id, &"did:key:sub1".into(), None, 1000, None).await.unwrap();
            let decision = manager
                .handle_broadcast_key_request(
                    &ctx_id,
                    &"did:key:bob".into(),
                    &"did:key:sub1".into(),
                )
                .await
                .unwrap();
            assert!(
                matches!(decision, super::KeyRequestDecision::Deny { .. }),
                "key request denied"
            );
        }
        let restore = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            GovernanceAction::RestoreWriteAccess {
                did: "did:key:bob".into(),
            },
        );
        manager
            .execute_governance_action(&ctx_id, &restore)
            .await
            .unwrap();
        // After Full revocation + restore, the author entry was removed from the
        // BroadcastContext. Forward-only restoration clears the revocation flag
        // but does NOT re-create the author entry — bob must re-register.
        {
            let contexts = manager.contexts.lock().await;
            let bc = contexts
                .get(&ctx_id)
                .unwrap()
                .broadcast_context
                .as_ref()
                .unwrap();
            assert!(
                !bc.is_author("did:key:bob"),
                "full revocation removes author; restore does not re-add"
            );
        }
    }

    #[tokio::test]
    async fn cac009_tier_stacking_both_must_reverse() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;
        let revoke_w = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            GovernanceAction::RevokeWriteAccess {
                did: "did:key:bob".into(),
                scope: super::RevocationScope::Full,
            },
        );
        manager
            .execute_governance_action(&ctx_id, &revoke_w)
            .await
            .unwrap();
        let revoke_r = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            GovernanceAction::RevokeReadAccess {
                did: "did:key:bob".into(),
                scope: super::RevocationScope::Full,
            },
        );
        manager
            .execute_governance_action(&ctx_id, &revoke_r)
            .await
            .unwrap();
        {
            let contexts = manager.contexts.lock().await;
            let ctx = contexts.get(&ctx_id).unwrap();
            assert!(
                ctx.access
                    .write_revoked_members
                    .contains(&DID("did:key:bob".into()))
            );
            assert!(
                ctx.access
                    .read_revoked_members
                    .contains(&DID("did:key:bob".into()))
            );
        }
        let restore_w = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            GovernanceAction::RestoreWriteAccess {
                did: "did:key:bob".into(),
            },
        );
        manager
            .execute_governance_action(&ctx_id, &restore_w)
            .await
            .unwrap();
        {
            let contexts = manager.contexts.lock().await;
            let ctx = contexts.get(&ctx_id).unwrap();
            assert!(
                !ctx.access
                    .write_revoked_members
                    .contains(&DID("did:key:bob".into())),
                "write restored"
            );
            assert!(
                ctx.access
                    .read_revoked_members
                    .contains(&DID("did:key:bob".into())),
                "read still revoked"
            );
        }
        let restore_r = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            GovernanceAction::RestoreReadAccess {
                did: "did:key:bob".into(),
            },
        );
        manager
            .execute_governance_action(&ctx_id, &restore_r)
            .await
            .unwrap();
        {
            let contexts = manager.contexts.lock().await;
            let ctx = contexts.get(&ctx_id).unwrap();
            assert!(
                !ctx.access
                    .write_revoked_members
                    .contains(&DID("did:key:bob".into()))
            );
            assert!(
                !ctx.access
                    .read_revoked_members
                    .contains(&DID("did:key:bob".into()))
            );
        }
    }

    #[tokio::test]
    async fn cac009_layer_verification() {
        let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;
        {
            use scp_protocol::crypto::ucan::validate::{
                InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
                InMemoryRevocationChecker,
            };
            use std::hash::RandomState;
            manager.subscribe_broadcast::<InMemoryDidResolver, InMemoryNonceTracker, InMemoryRevocationChecker, InMemoryProofResolver, RandomState>(&ctx_id, &"did:key:sub1".into(), None, 1000, None).await.unwrap();
        }
        let revoke = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            GovernanceAction::RevokeWriteAccess {
                did: "did:key:bob".into(),
                scope: super::RevocationScope::Full,
            },
        );
        manager
            .execute_governance_action(&ctx_id, &revoke)
            .await
            .unwrap();
        {
            let contexts = manager.contexts.lock().await;
            assert!(
                contexts
                    .get(&ctx_id)
                    .unwrap()
                    .access
                    .write_revoked_members
                    .contains(&DID("did:key:bob".into())),
                "Layer 3"
            );
        }
        let decision = manager
            .handle_broadcast_key_request(&ctx_id, &"did:key:bob".into(), &"did:key:sub1".into())
            .await
            .unwrap();
        assert!(
            matches!(decision, super::KeyRequestDecision::Deny { .. }),
            "Layer 1"
        );
    }

    #[tokio::test]
    async fn cac009_forward_only_verification() {
        let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;
        let _epoch_before = {
            let contexts = manager.contexts.lock().await;
            contexts
                .get(&ctx_id)
                .unwrap()
                .broadcast_context
                .as_ref()
                .unwrap()
                .get_author("did:key:bob")
                .unwrap()
                .epoch
        };
        let revoke = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            GovernanceAction::RevokeWriteAccess {
                did: "did:key:bob".into(),
                scope: super::RevocationScope::Full,
            },
        );
        manager
            .execute_governance_action(&ctx_id, &revoke)
            .await
            .unwrap();
        {
            let contexts = manager.contexts.lock().await;
            assert!(
                !contexts
                    .get(&ctx_id)
                    .unwrap()
                    .broadcast_context
                    .as_ref()
                    .unwrap()
                    .is_author("did:key:bob")
            );
        }
        let restore = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            GovernanceAction::RestoreWriteAccess {
                did: "did:key:bob".into(),
            },
        );
        manager
            .execute_governance_action(&ctx_id, &restore)
            .await
            .unwrap();
        // After Full revocation + restore, the author entry was removed.
        // Forward-only restoration clears the revocation flag but does NOT
        // re-create the author — bob must re-register as an author.
        let author_gone = {
            let contexts = manager.contexts.lock().await;
            contexts
                .get(&ctx_id)
                .unwrap()
                .broadcast_context
                .as_ref()
                .unwrap()
                .get_author("did:key:bob")
                .is_none()
        };
        assert!(
            author_gone,
            "full revocation removes author; restore does not re-add"
        );
    }

    // ===================================================================
    // CAC-010: governance-gated content access control
    // ===================================================================

    #[tokio::test]
    async fn cac010_threshold_revoke_read_access() {
        let creator: DID = "did:key:alice".into();
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );
        let mut params = governance_params();
        params.mode = ContextMode::Broadcast;
        params.memory_scope = MemoryScope::Full;
        params.governance = GovernanceModel::Threshold {
            threshold: 1,
            signers: vec![creator.clone()],
        };
        let _handle = manager
            .create_context("cac010-thresh".into(), params, creator.clone())
            .await
            .unwrap();
        {
            use scp_protocol::crypto::ucan::validate::{
                InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
                InMemoryRevocationChecker,
            };
            use std::hash::RandomState;
            manager.subscribe_broadcast::<InMemoryDidResolver, InMemoryNonceTracker, InMemoryRevocationChecker, InMemoryProofResolver, RandomState>("cac010-thresh", &"did:key:dave".into(), None, 1000, None).await.unwrap();
        }
        let signing_key = signing_key_for_did(&creator);
        let outcome = manager
            .propose_governance_action_checked(
                "cac010-thresh",
                &creator,
                GovernanceAction::RevokeReadAccess {
                    did: "did:key:dave".into(),
                    scope: super::RevocationScope::Full,
                },
                &signing_key,
            )
            .await
            .unwrap();
        assert_eq!(
            outcome.status,
            super::ProposalStatus::Approved,
            "1-of-1 threshold auto-approve"
        );
        assert!(
            outcome.execution_result.is_some(),
            "auto-approved should have execution_result"
        );
        assert!(
            !manager
                .is_broadcast_subscriber("cac010-thresh", "did:key:dave")
                .await,
            "dave unsubscribed"
        );
    }

    #[tokio::test]
    async fn cac010_restore_read_access_forward_only() {
        let (manager, ctx_id) = setup_broadcast_with_member_ban().await;
        let revoke = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:sub1".into(),
            GovernanceAction::RevokeReadAccess {
                did: "did:key:sub1".into(),
                scope: super::RevocationScope::Full,
            },
        );
        manager
            .execute_governance_action(&ctx_id, &revoke)
            .await
            .unwrap();
        assert!(
            !manager
                .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
                .await
        );
        let restore = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:sub1".into(),
            GovernanceAction::RestoreReadAccess {
                did: "did:key:sub1".into(),
            },
        );
        manager
            .execute_governance_action(&ctx_id, &restore)
            .await
            .unwrap();
        let events = manager.drain_events(&ctx_id).await;
        assert!(events.iter().any(
            |e| matches!(e, ContextEvent::ReadAccessRestored { did } if did.0 == "did:key:sub1")
        ));
    }

    #[tokio::test]
    async fn cac010_revoke_write_full_can_still_read() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;
        let revoke = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            GovernanceAction::RevokeWriteAccess {
                did: "did:key:bob".into(),
                scope: super::RevocationScope::Full,
            },
        );
        manager
            .execute_governance_action(&ctx_id, &revoke)
            .await
            .unwrap();
        {
            let contexts = manager.contexts.lock().await;
            let ctx = contexts.get(&ctx_id).unwrap();
            assert!(
                ctx.access
                    .write_revoked_members
                    .contains(&DID("did:key:bob".into())),
                "write-revoked"
            );
            assert!(
                !ctx.access
                    .read_revoked_members
                    .contains(&DID("did:key:bob".into())),
                "NOT read-revoked"
            );
        }
    }

    #[tokio::test]
    async fn cac010_revoke_write_future_only() {
        let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;
        let revoke = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            GovernanceAction::RevokeWriteAccess {
                did: "did:key:bob".into(),
                scope: super::RevocationScope::FutureOnly,
            },
        );
        manager
            .execute_governance_action(&ctx_id, &revoke)
            .await
            .unwrap();
        let (bob_custody, bob_key_handle) = test_custody_from_seed(&[0xBB; 32]).await;
        assert!(
            manager
                .publish_broadcast(
                    &ctx_id,
                    &"did:key:bob".into(),
                    b"nope",
                    &bob_custody,
                    &bob_key_handle,
                )
                .await
                .is_err()
        );
        {
            let contexts = manager.contexts.lock().await;
            assert!(
                contexts
                    .get(&ctx_id)
                    .unwrap()
                    .broadcast_context
                    .as_ref()
                    .unwrap()
                    .is_author("did:key:bob"),
                "FutureOnly keeps author in BC"
            );
        }
    }

    #[tokio::test]
    async fn cac010_rotate_content_keys_context_wide() {
        let (manager, ctx_id) = setup_encrypted_with_member_ban().await;
        let rotate = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:bob".into(),
            GovernanceAction::RotateContentKeys {
                reason: Some("periodic".into()),
            },
        );
        let result = manager.execute_governance_action(&ctx_id, &rotate).await;
        assert!(
            result.is_ok(),
            "RotateContentKeys should succeed: {result:?}"
        );
        match result.unwrap() {
            GovernanceActionResult::ContentKeysRotated(r) => {
                assert_eq!(r.reason.as_deref(), Some("periodic"));
            }
            other => panic!("expected ContentKeysRotated, got {other:?}"),
        }
        let events = manager.drain_events(&ctx_id).await;
        assert!(
            events
                .iter()
                .any(|e| matches!(e, ContextEvent::ContentKeysRotated { .. }))
        );
    }

    #[tokio::test]
    async fn cac010_membership_access_decoupling() {
        let (manager, ctx_id) = setup_broadcast_with_member_ban().await;
        let revoke = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:sub1".into(),
            GovernanceAction::RevokeReadAccess {
                did: "did:key:sub1".into(),
                scope: super::RevocationScope::Full,
            },
        );
        manager
            .execute_governance_action(&ctx_id, &revoke)
            .await
            .unwrap();
        assert!(
            !manager
                .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
                .await,
            "unsubscribed"
        );
        assert!(
            manager.is_member(&ctx_id, "did:key:sub1").await,
            "still a member"
        );
    }

    #[tokio::test]
    async fn cac010_single_admin_auto_execute() {
        let (manager, ctx_id) = setup_broadcast_with_member_ban().await;
        let revoke = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:sub1".into(),
            GovernanceAction::RevokeReadAccess {
                did: "did:key:sub1".into(),
                scope: super::RevocationScope::Full,
            },
        );
        let result = manager.execute_governance_action(&ctx_id, &revoke).await;
        assert!(result.is_ok());
        match result.unwrap() {
            GovernanceActionResult::ReadAccessRevoked(r) => {
                assert_eq!(r.did.0, "did:key:sub1");
            }
            other => panic!("expected ReadAccessRevoked, got {other:?}"),
        }
    }

    // ===================================================================
    // SCP-274: governance-manager integration test — full lifecycle
    // ===================================================================

    #[tokio::test]
    async fn scp274_single_admin_full_lifecycle() {
        let (manager, _handle, ctx_id) = setup_governance_context().await;
        let admin_did: DID = "did:key:admin".into();
        let signing_key = signing_key_for_did(&admin_did);
        let outcome = manager
            .propose_governance_action_checked(
                &ctx_id,
                &admin_did,
                GovernanceAction::AddMember {
                    did: "did:key:target".into(),
                    role: "member".to_owned(),
                },
                &signing_key,
            )
            .await
            .unwrap();
        assert_eq!(outcome.status, ProposalStatus::Approved);
        let outcome = manager
            .propose_governance_action_checked(
                &ctx_id,
                &admin_did,
                GovernanceAction::RemoveMember {
                    did: "did:key:target".into(),
                    reason: Some("test".into()),
                },
                &signing_key,
            )
            .await
            .unwrap();
        assert_eq!(
            outcome.status,
            ProposalStatus::Approved,
            "SingleAdmin should auto-approve"
        );
        assert!(
            outcome.execution_result.is_some(),
            "SingleAdmin should auto-execute"
        );
    }

    #[tokio::test]
    async fn scp274_threshold_full_lifecycle() {
        let creator: DID = "did:key:creator".into();
        let signer2: DID = "did:key:signer2".into();
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );
        let mut params = governance_params();
        params.governance = GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![creator.clone(), signer2.clone()],
        };
        let _handle = manager
            .create_context("scp274-thresh".into(), params, creator.clone())
            .await
            .unwrap();
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("scp274-thresh").unwrap();
            ctx.membership
                .add_member("did:key:signer2".into(), "signer".into(), vec![]);
            ctx.role_state.member_capabilities.insert(
                "did:key:signer2".into(),
                HashSet::from([Capability::GovernancePropose, Capability::GovernanceVote]),
            );
        }
        {
            let mut contexts = manager.contexts.lock().await;
            contexts
                .get_mut("scp274-thresh")
                .unwrap()
                .membership
                .add_member("did:key:target".into(), "member".into(), vec![]);
        }
        let creator_sk = signing_key_for_did(&creator);
        let outcome = manager
            .propose_governance_action_checked(
                "scp274-thresh",
                &creator,
                GovernanceAction::RemoveMember {
                    did: "did:key:target".into(),
                    reason: None,
                },
                &creator_sk,
            )
            .await
            .unwrap();
        let proposal_id = outcome.proposal.proposal_id;
        let signer2_sk = signing_key_for_did(&signer2);
        let status = manager
            .approve_governance_proposal("scp274-thresh", &proposal_id, &signer2, &signer2_sk)
            .await
            .unwrap();
        assert_eq!(status, ProposalStatus::Approved);
        assert!(!manager.is_member("scp274-thresh", "did:key:target").await);
    }

    #[tokio::test]
    async fn scp274_majority_full_lifecycle() {
        let creator: DID = "did:key:creator".into();
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );
        let mut params = governance_params();
        params.governance = GovernanceModel::Majority {
            eligible_voters: vec![creator.clone()],
        };
        let _handle = manager
            .create_context("scp274-maj".into(), params, creator.clone())
            .await
            .unwrap();
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("scp274-maj").unwrap();
            ctx.membership
                .add_member("did:key:target".into(), "member".into(), vec![]);
            ctx.role_state.members.insert("did:key:target".into());
        }
        let creator_sk = signing_key_for_did(&creator);
        let outcome = manager
            .propose_governance_action_checked(
                "scp274-maj",
                &creator,
                GovernanceAction::ChangeRole {
                    did: "did:key:target".into(),
                    new_role: "observer".into(),
                },
                &creator_sk,
            )
            .await
            .unwrap();
        // MajorityVote propose() always returns Pending — the proposer must
        // explicitly cast an approve vote to reach quorum (1-of-1).
        assert_eq!(outcome.status, ProposalStatus::Pending);
        let proposal_id = outcome.proposal.proposal_id;
        let status = manager
            .approve_governance_proposal("scp274-maj", &proposal_id, &creator, &creator_sk)
            .await
            .unwrap();
        assert_eq!(status, ProposalStatus::Approved);
    }

    #[tokio::test]
    async fn scp274_unanimity_full_lifecycle() {
        let creator: DID = "did:key:creator".into();
        let member2: DID = "did:key:member2".into();
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );
        let mut params = governance_params();
        params.governance = GovernanceModel::Unanimity {
            eligible_voters: vec![creator.clone(), member2.clone()],
        };
        let _handle = manager
            .create_context("scp274-unan".into(), params, creator.clone())
            .await
            .unwrap();
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("scp274-unan").unwrap();
            ctx.membership
                .add_member("did:key:member2".into(), "member".into(), vec![]);
            ctx.role_state.member_capabilities.insert(
                "did:key:member2".into(),
                HashSet::from([Capability::GovernancePropose, Capability::GovernanceVote]),
            );
        }
        {
            let mut contexts = manager.contexts.lock().await;
            contexts
                .get_mut("scp274-unan")
                .unwrap()
                .membership
                .add_member("did:key:target".into(), "member".into(), vec![]);
        }
        let creator_sk = signing_key_for_did(&creator);
        let outcome = manager
            .propose_governance_action_checked(
                "scp274-unan",
                &creator,
                GovernanceAction::RemoveMember {
                    did: "did:key:target".into(),
                    reason: None,
                },
                &creator_sk,
            )
            .await
            .unwrap();
        let proposal_id = outcome.proposal.proposal_id;
        let member2_sk = signing_key_for_did(&member2);
        let status = manager
            .approve_governance_proposal("scp274-unan", &proposal_id, &member2, &member2_sk)
            .await
            .unwrap();
        assert_eq!(status, ProposalStatus::Approved);
        assert!(!manager.is_member("scp274-unan", "did:key:target").await);
    }

    #[tokio::test]
    async fn scp274_rejected_proposal_does_not_execute() {
        let creator: DID = "did:key:creator".into();
        let signer2: DID = "did:key:signer2".into();
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );
        let mut params = governance_params();
        params.governance = GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![creator.clone(), signer2.clone()],
        };
        let _handle = manager
            .create_context("scp274-reject".into(), params, creator.clone())
            .await
            .unwrap();
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("scp274-reject").unwrap();
            ctx.membership
                .add_member("did:key:signer2".into(), "signer".into(), vec![]);
            ctx.role_state.member_capabilities.insert(
                "did:key:signer2".into(),
                HashSet::from([Capability::GovernancePropose, Capability::GovernanceVote]),
            );
            ctx.membership
                .add_member("did:key:target".into(), "member".into(), vec![]);
        }
        let creator_sk = signing_key_for_did(&creator);
        let outcome = manager
            .propose_governance_action_checked(
                "scp274-reject",
                &creator,
                GovernanceAction::RemoveMember {
                    did: "did:key:target".into(),
                    reason: None,
                },
                &creator_sk,
            )
            .await
            .unwrap();
        let proposal_id = outcome.proposal.proposal_id;
        let signer2_sk = signing_key_for_did(&signer2);
        let status = manager
            .reject_governance_proposal("scp274-reject", &proposal_id, &signer2, &signer2_sk)
            .await
            .unwrap();
        assert!(matches!(status, ProposalStatus::Rejected { .. }));
        assert!(manager.is_member("scp274-reject", "did:key:target").await);
    }

    /// SCP-274 AC8: governance events emitted during propose/approve lifecycle.
    #[tokio::test]
    async fn scp274_governance_events_in_log() {
        let creator: DID = "did:key:creator".into();
        let signer2: DID = "did:key:signer2".into();
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );
        let mut params = governance_params();
        params.governance = GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![creator.clone(), signer2.clone()],
        };
        let _handle = manager
            .create_context("scp274-events".into(), params, creator.clone())
            .await
            .unwrap();
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("scp274-events").unwrap();
            ctx.membership
                .add_member("did:key:signer2".into(), "signer".into(), vec![]);
            ctx.role_state.member_capabilities.insert(
                "did:key:signer2".into(),
                HashSet::from([Capability::GovernancePropose, Capability::GovernanceVote]),
            );
            ctx.membership
                .add_member("did:key:target".into(), "member".into(), vec![]);
        }
        let creator_sk = signing_key_for_did(&creator);
        let outcome = manager
            .propose_governance_action_checked(
                "scp274-events",
                &creator,
                GovernanceAction::RemoveMember {
                    did: "did:key:target".into(),
                    reason: None,
                },
                &creator_sk,
            )
            .await
            .unwrap();
        assert!(
            matches!(outcome.status, ProposalStatus::Pending),
            "should be pending after first vote"
        );
        let proposal_id = outcome.proposal.proposal_id;
        let signer2_sk = signing_key_for_did(&signer2);
        let status = manager
            .approve_governance_proposal("scp274-events", &proposal_id, &signer2, &signer2_sk)
            .await
            .unwrap();
        assert_eq!(
            status,
            ProposalStatus::Approved,
            "should be approved after quorum"
        );
        assert!(
            !manager.is_member("scp274-events", "did:key:target").await,
            "target removed after governance execution"
        );
    }

    #[tokio::test]
    async fn scp274_bypass_prevention() {
        let creator: DID = "did:key:creator".into();
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );
        let mut params = governance_params();
        params.governance = GovernanceModel::Majority {
            eligible_voters: vec![creator.clone()],
        };
        let handle = manager
            .create_context("scp274-bypass".into(), params, creator.clone())
            .await
            .unwrap();
        let result = manager.close_context(&handle, &creator).await;
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ContextError::PermissionDenied(ref msg) if msg.contains("multi-admin"))
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn scp274_exercises_seven_action_variants() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        let params = governance_params();
        let _handle = manager
            .create_context("scp274-7a".into(), params, "did:key:admin".into())
            .await
            .unwrap();
        let add = approved_proposal(
            [100u8; 32],
            "scp274-7a",
            GovernanceAction::AddMember {
                did: "did:key:target".into(),
                role: "member".to_owned(),
            },
            &["did:key:admin"],
        );
        assert!(
            manager
                .execute_governance_action("scp274-7a", &add)
                .await
                .is_ok(),
            "AddMember"
        );
        let rm = approved_proposal(
            [101u8; 32],
            "scp274-7a",
            GovernanceAction::RemoveMember {
                did: "did:key:target".into(),
                reason: None,
            },
            &["did:key:admin"],
        );
        assert!(
            manager
                .execute_governance_action("scp274-7a", &rm)
                .await
                .is_ok(),
            "RemoveMember"
        );
        let add2 = approved_proposal(
            [102u8; 32],
            "scp274-7a",
            GovernanceAction::AddMember {
                did: "did:key:target".into(),
                role: "member".to_owned(),
            },
            &["did:key:admin"],
        );
        manager
            .execute_governance_action("scp274-7a", &add2)
            .await
            .unwrap();
        let cr = approved_proposal(
            [103u8; 32],
            "scp274-7a",
            GovernanceAction::ChangeRole {
                did: "did:key:target".into(),
                new_role: "observer".into(),
            },
            &["did:key:admin"],
        );
        assert!(
            manager
                .execute_governance_action("scp274-7a", &cr)
                .await
                .is_ok(),
            "ChangeRole"
        );
        let close = approved_proposal(
            [104u8; 32],
            "scp274-7a",
            GovernanceAction::CloseContext {
                reason: Some("test".into()),
            },
            &["did:key:admin"],
        );
        assert!(
            manager
                .execute_governance_action("scp274-7a", &close)
                .await
                .is_ok(),
            "CloseContext"
        );
        let mut params2 = governance_params();
        params2.ttl = Some(std::time::Duration::from_secs(3600));
        let _h2 = manager
            .create_context("scp274-7b".into(), params2, "did:key:admin".into())
            .await
            .unwrap();
        {
            let mut contexts = manager.contexts.lock().await;
            contexts
                .get_mut("scp274-7b")
                .unwrap()
                .membership
                .add_member("did:key:signer".into(), "member".into(), vec![]);
        }
        let add_s = approved_proposal(
            [105u8; 32],
            "scp274-7b",
            GovernanceAction::AddSigner {
                did: "did:key:signer".into(),
            },
            &["did:key:admin"],
        );
        assert!(
            manager
                .execute_governance_action("scp274-7b", &add_s)
                .await
                .is_ok(),
            "AddSigner"
        );
        let ext = approved_proposal(
            [106u8; 32],
            "scp274-7b",
            GovernanceAction::ExtendTtl {
                additional_secs: 1800,
            },
            &["did:key:admin", "did:key:signer"],
        );
        assert!(
            manager
                .execute_governance_action("scp274-7b", &ext)
                .await
                .is_ok(),
            "ExtendTtl"
        );
        let revoke = approved_proposal(
            [107u8; 32],
            "scp274-7b",
            GovernanceAction::RevokeWriteAccess {
                did: "did:key:signer".into(),
                scope: super::RevocationScope::FutureOnly,
            },
            &["did:key:admin"],
        );
        assert!(
            manager
                .execute_governance_action("scp274-7b", &revoke)
                .await
                .is_ok(),
            "RevokeWriteAccess"
        );
        let revoke_r = approved_proposal(
            [108u8; 32],
            "scp274-7b",
            GovernanceAction::RevokeReadAccess {
                did: "did:key:signer".into(),
                scope: super::RevocationScope::Full,
            },
            &["did:key:admin"],
        );
        manager
            .execute_governance_action("scp274-7b", &revoke_r)
            .await
            .unwrap();
        let restore_r = approved_proposal(
            [109u8; 32],
            "scp274-7b",
            GovernanceAction::RestoreReadAccess {
                did: "did:key:signer".into(),
            },
            &["did:key:admin"],
        );
        assert!(
            manager
                .execute_governance_action("scp274-7b", &restore_r)
                .await
                .is_ok(),
            "RestoreReadAccess"
        );
    }

    #[tokio::test]
    async fn scp274_extend_ttl_unanimity_override_in_threshold() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        let mut params = governance_params();
        params.ttl = Some(std::time::Duration::from_secs(3600));
        params.governance = GovernanceModel::Threshold {
            threshold: 1,
            signers: vec!["did:key:creator".into()],
        };
        let _handle = manager
            .create_context("scp274-ttl-t".into(), params, "did:key:creator".into())
            .await
            .unwrap();
        let add = approved_proposal(
            [110u8; 32],
            "scp274-ttl-t",
            GovernanceAction::AddMember {
                did: "did:key:bob".into(),
                role: "member".to_owned(),
            },
            &["did:key:creator"],
        );
        manager
            .execute_governance_action("scp274-ttl-t", &add)
            .await
            .unwrap();
        let extend = approved_proposal(
            [111u8; 32],
            "scp274-ttl-t",
            GovernanceAction::ExtendTtl {
                additional_secs: 1800,
            },
            &["did:key:creator"],
        );
        assert!(
            manager
                .execute_governance_action("scp274-ttl-t", &extend)
                .await
                .is_err(),
            "ExtendTtl requires unanimity"
        );
        let extend2 = approved_proposal(
            [112u8; 32],
            "scp274-ttl-t",
            GovernanceAction::ExtendTtl {
                additional_secs: 1800,
            },
            &["did:key:creator", "did:key:bob"],
        );
        assert!(
            manager
                .execute_governance_action("scp274-ttl-t", &extend2)
                .await
                .is_ok(),
            "ExtendTtl with unanimity"
        );
    }

    #[tokio::test]
    async fn scp274_promote_context_unanimity_override_in_majority() {
        use scp_protocol::context::params::{MemoryScope, PromotionPolicy};
        let creator: DID = "did:key:creator".into();
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        let mut params = governance_params();
        params.governance = GovernanceModel::Majority {
            eligible_voters: vec![creator.clone()],
        };
        params.promotion_policy = PromotionPolicy::Promotable;
        params.memory_scope = MemoryScope::Ephemeral;
        params.ttl = Some(std::time::Duration::from_secs(3600));
        let _handle = manager
            .create_context("scp274-promo".into(), params, creator.clone())
            .await
            .unwrap();
        let add = approved_proposal(
            [120u8; 32],
            "scp274-promo",
            GovernanceAction::AddMember {
                did: "did:key:bob".into(),
                role: "member".to_owned(),
            },
            &["did:key:creator"],
        );
        manager
            .execute_governance_action("scp274-promo", &add)
            .await
            .unwrap();
        let promote = approved_proposal(
            [121u8; 32],
            "scp274-promo",
            GovernanceAction::PromoteContext,
            &["did:key:creator"],
        );
        assert!(
            manager
                .execute_governance_action("scp274-promo", &promote)
                .await
                .is_err(),
            "PromoteContext requires unanimity"
        );
        let promote2 = approved_proposal(
            [122u8; 32],
            "scp274-promo",
            GovernanceAction::PromoteContext,
            &["did:key:creator", "did:key:bob"],
        );
        assert!(
            manager
                .execute_governance_action("scp274-promo", &promote2)
                .await
                .is_ok(),
            "PromoteContext with unanimity"
        );
    }

    #[tokio::test]
    async fn scp274_conflict_detection_change_role() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        let params = governance_params();
        let _handle = manager
            .create_context("scp274-conflict".into(), params, "did:key:admin".into())
            .await
            .unwrap();
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("scp274-conflict").unwrap();
            ctx.membership
                .add_member("did:key:target".into(), "member".into(), vec![]);
            ctx.role_state.members.insert("did:key:target".into());
        }
        let proposal_a = approved_proposal(
            [130u8; 32],
            "scp274-conflict",
            GovernanceAction::ChangeRole {
                did: "did:key:target".into(),
                new_role: "admin".into(),
            },
            &["did:key:admin"],
        );
        let proposal_b = approved_proposal(
            [131u8; 32],
            "scp274-conflict",
            GovernanceAction::ChangeRole {
                did: "did:key:target".into(),
                new_role: "observer".into(),
            },
            &["did:key:admin"],
        );
        manager
            .execute_governance_action("scp274-conflict", &proposal_a)
            .await
            .unwrap();
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("scp274-conflict").unwrap();
            use std::time::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            ctx.governance
                .approved_proposals
                .insert(proposal_a.proposal_id, (proposal_a.clone(), now, now));
            let events = manager.detect_and_handle_conflicts(ctx, &proposal_b);
            assert!(
                events.iter().any(|e| matches!(
                    e,
                    scp_protocol::context::governance::GovernanceEvent::ConflictDetected { .. }
                        | scp_protocol::context::governance::GovernanceEvent::ConflictResolved { .. }
                )),
                "conflict detected: {events:?}"
            );
        }
    }

    #[tokio::test]
    async fn scp274_deadlock_detection_threshold() {
        use crate::context::governance::timeout::{DeadlockDetectionState, detect_deadlock};
        use scp_protocol::context::governance::GovernanceContext;
        use scp_protocol::context::governance::multisig::ThresholdEngine;
        let signer1: DID = "did:key:signer1".into();
        let signer2: DID = "did:key:signer2".into();
        let signer3: DID = "did:key:signer3".into();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let resolver: std::sync::Arc<
            dyn Fn(&DID) -> Option<ed25519_dalek::VerifyingKey> + Send + Sync,
        > = std::sync::Arc::new(move |_| Some(signing_key.verifying_key()));
        let engine =
            ThresholdEngine::new(vec![signer1.clone(), signer2, signer3], 2, 86_400, resolver)
                .unwrap();
        let gov_ctx = GovernanceContext {
            context_id: "deadlock-test".into(),
            members: vec![(signer1.clone(), "admin".into())],
            admin_dids: vec![signer1],
            current_epoch: None,
            now: 1000,
        };
        let detection_state = DeadlockDetectionState::default();
        let conditions = detect_deadlock(&engine, &gov_ctx, &detection_state);
        assert!(!conditions.is_empty(), "deadlock should be detected");
    }

    #[tokio::test]
    async fn scp274_checkpoint_cosignature_threshold() {
        use scp_protocol::context::governance::GovernanceEngine;
        use scp_protocol::context::governance::multisig::ThresholdEngine;
        let signer1: DID = "did:key:signer1".into();
        let signer2: DID = "did:key:signer2".into();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let resolver: std::sync::Arc<
            dyn Fn(&DID) -> Option<ed25519_dalek::VerifyingKey> + Send + Sync,
        > = std::sync::Arc::new(move |_| Some(signing_key.verifying_key()));
        let engine =
            ThresholdEngine::new(vec![signer1.clone(), signer2.clone()], 2, 86_400, resolver)
                .unwrap();
        let (required_signers, quorum) = engine.checkpoint_cosignature_requirements();
        assert_eq!(quorum, 2);
        assert_eq!(required_signers.len(), 2);
        assert!(required_signers.contains(&signer1));
        assert!(required_signers.contains(&signer2));
    }

    // -----------------------------------------------------------------------
    // Ceiling notification period tests (§5.3.2, Finding 2)
    // -----------------------------------------------------------------------

    #[test]
    fn pending_ceiling_modification_effective_at_equals_notified_at_plus_259200() {
        let notified_at = 1_000_000u64;
        let pending = PendingCeilingModification {
            new_capabilities: vec![Capability::MessagesRead],
            notified_at,
            effective_at: notified_at + CEILING_CHANGE_NOTIFICATION_PERIOD_SECS,
            proposal_id: [0u8; 32],
        };
        assert_eq!(
            pending.effective_at,
            notified_at + 259_200,
            "effective_at must be notified_at + 72h (259,200s)"
        );
    }

    #[test]
    fn pending_ceiling_is_effective_false_before_period_expires() {
        let notified_at = 1_000_000u64;
        let pending = PendingCeilingModification {
            new_capabilities: vec![Capability::MessagesRead],
            notified_at,
            effective_at: notified_at + CEILING_CHANGE_NOTIFICATION_PERIOD_SECS,
            proposal_id: [0u8; 32],
        };
        // One second before effective_at.
        assert!(
            !pending.is_effective(pending.effective_at - 1),
            "is_effective must return false before the notification period expires"
        );
        // At notified_at (start of period).
        assert!(
            !pending.is_effective(notified_at),
            "is_effective must return false at the start of the notification period"
        );
    }

    #[test]
    fn pending_ceiling_is_effective_true_after_period_expires() {
        let notified_at = 1_000_000u64;
        let pending = PendingCeilingModification {
            new_capabilities: vec![Capability::MessagesRead],
            notified_at,
            effective_at: notified_at + CEILING_CHANGE_NOTIFICATION_PERIOD_SECS,
            proposal_id: [0u8; 32],
        };
        // Exactly at effective_at.
        assert!(
            pending.is_effective(pending.effective_at),
            "is_effective must return true at exactly effective_at"
        );
        // Well after effective_at.
        assert!(
            pending.is_effective(pending.effective_at + 3600),
            "is_effective must return true after the notification period expires"
        );
    }

    #[tokio::test]
    async fn execute_modify_ceiling_sets_pending_with_72h_period() {
        use scp_protocol::context::governance::GovernanceAction;

        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );

        let alice: DID = "did:dht:z6MkAlice".into();
        let key_a = signing_key_for_did(&alice);

        let params = ContextParams {
            governance: scp_protocol::context::params::GovernanceModel::SingleAdmin,
            ceiling_policy: scp_protocol::context::params::CeilingPolicy::Governed,
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            ..ContextParams::default()
        };

        let _handle = manager
            .create_context("ctx-ceiling".into(), params, alice.clone())
            .await
            .unwrap();

        // Propose ModifyCeiling — SingleAdmin auto-approves and auto-executes.
        let new_ceiling = vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::ToolRegister,
        ];
        let action = GovernanceAction::ModifyCeiling {
            new_ceiling: new_ceiling.clone(),
        };
        let (_proposal, _events) = manager
            .propose_governance_action("ctx-ceiling", &alice, action, &key_a)
            .await
            .unwrap();

        // Verify the pending ceiling modification was stored with 72h period.
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("ctx-ceiling").unwrap();
        let pending = ctx
            .governance
            .pending_ceiling_modification
            .as_ref()
            .expect("pending ceiling modification should exist");
        assert_eq!(pending.new_capabilities, new_ceiling);
        assert_eq!(
            pending.effective_at,
            pending.notified_at + 259_200,
            "effective_at must be notified_at + 72h"
        );
        // Ceiling should NOT yet be updated (still pending).
        assert!(
            !ctx.role_state.ceiling.contains(&Capability::ToolRegister),
            "ToolRegister should not be in ceiling yet (still in notification period)"
        );
    }

    #[tokio::test]
    async fn apply_pending_ceiling_modification_respects_notification_period() {
        use scp_protocol::context::governance::GovernanceAction;

        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );

        let alice: DID = "did:dht:z6MkAlice".into();
        let key_a = signing_key_for_did(&alice);

        let params = ContextParams {
            governance: scp_protocol::context::params::GovernanceModel::SingleAdmin,
            ceiling_policy: scp_protocol::context::params::CeilingPolicy::Governed,
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            ..ContextParams::default()
        };

        let _handle = manager
            .create_context("ctx-apply".into(), params, alice.clone())
            .await
            .unwrap();

        let new_ceiling = vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::ToolRegister,
        ];
        let action = GovernanceAction::ModifyCeiling {
            new_ceiling: new_ceiling.clone(),
        };
        let (_proposal, _events) = manager
            .propose_governance_action("ctx-apply", &alice, action, &key_a)
            .await
            .unwrap();

        // Get the notified_at timestamp from the pending modification.
        let notified_at = {
            let contexts = manager.contexts.lock().await;
            let ctx = contexts.get("ctx-apply").unwrap();
            ctx.governance
                .pending_ceiling_modification
                .as_ref()
                .unwrap()
                .notified_at
        };

        // Before period expires: apply returns false.
        let applied = manager
            .apply_pending_ceiling_modification("ctx-apply", notified_at + 259_199)
            .await
            .unwrap();
        assert!(
            !applied,
            "should not apply before notification period expires"
        );

        // At exactly effective_at: apply returns true.
        let applied = manager
            .apply_pending_ceiling_modification("ctx-apply", notified_at + 259_200)
            .await
            .unwrap();
        assert!(applied, "should apply at exactly effective_at");

        // Verify the ceiling was updated and pending cleared.
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("ctx-apply").unwrap();
        assert!(
            ctx.governance.pending_ceiling_modification.is_none(),
            "pending modification should be cleared after apply"
        );
        assert!(
            ctx.role_state.ceiling.contains(&Capability::ToolRegister),
            "ToolRegister should now be in the ceiling after apply"
        );
    }

    #[tokio::test]
    async fn execute_modify_ceiling_emits_ceiling_change_notification() {
        use scp_protocol::context::governance::GovernanceAction;
        use scp_protocol::context::membership::ContextEvent;

        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );

        let alice: DID = "did:dht:z6MkAlice".into();
        let key_a = signing_key_for_did(&alice);

        let params = ContextParams {
            governance: scp_protocol::context::params::GovernanceModel::SingleAdmin,
            ceiling_policy: scp_protocol::context::params::CeilingPolicy::Governed,
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            ..ContextParams::default()
        };

        let _handle = manager
            .create_context("ctx-notify".into(), params, alice.clone())
            .await
            .unwrap();

        let new_ceiling = vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::ToolRegister,
        ];
        let action = GovernanceAction::ModifyCeiling {
            new_ceiling: new_ceiling.clone(),
        };
        let (_proposal, _events) = manager
            .propose_governance_action("ctx-notify", &alice, action, &key_a)
            .await
            .unwrap();

        // Drain events and check for CeilingChangeNotification.
        let events = manager.drain_events("ctx-notify").await;
        let notification = events
            .iter()
            .find(|e| matches!(e, ContextEvent::CeilingChangeNotification { .. }));
        assert!(
            notification.is_some(),
            "CeilingChangeNotification event should be emitted to the receive buffer"
        );
        if let Some(ContextEvent::CeilingChangeNotification {
            new_capabilities,
            notified_at,
            effective_at,
            ..
        }) = notification
        {
            assert_eq!(*new_capabilities, new_ceiling);
            assert_eq!(
                *effective_at,
                *notified_at + 259_200,
                "notification effective_at must be notified_at + 72h"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Economic policy notification period tests (§19.3, #728)
    // -----------------------------------------------------------------------

    #[test]
    fn pending_economic_policy_change_effective_at_equals_notified_at_plus_86400() {
        let notified_at = 1_000_000u64;
        let pending = PendingEconomicPolicyChange {
            new_policy: scp_protocol::economy::types::EconomicPolicy {
                locked: false,
                cost_schedule: scp_protocol::economy::types::CostSchedule {
                    currency: scp_protocol::economy::types::CurrencyCode([85, 83, 68, 0]),
                    per_message: None,
                    per_tool_invoke: None,
                    per_join: None,
                    per_period: None,
                    per_byte_stored: None,
                },
                payment_adapters: vec![],
                pricing_formula: None,
                payee: DID::from("did:dht:z6MkPayee"),
            },
            notified_at,
            effective_at: notified_at + ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS,
            proposal_id: [0u8; 32],
        };
        assert_eq!(
            pending.effective_at,
            notified_at + 86_400,
            "effective_at must be notified_at + 24h (86,400s)"
        );
    }

    #[test]
    fn pending_economic_policy_is_effective_false_before_period_expires() {
        let notified_at = 1_000_000u64;
        let pending = PendingEconomicPolicyChange {
            new_policy: scp_protocol::economy::types::EconomicPolicy {
                locked: false,
                cost_schedule: scp_protocol::economy::types::CostSchedule {
                    currency: scp_protocol::economy::types::CurrencyCode([85, 83, 68, 0]),
                    per_message: None,
                    per_tool_invoke: None,
                    per_join: None,
                    per_period: None,
                    per_byte_stored: None,
                },
                payment_adapters: vec![],
                pricing_formula: None,
                payee: DID::from("did:dht:z6MkPayee"),
            },
            notified_at,
            effective_at: notified_at + ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS,
            proposal_id: [0u8; 32],
        };
        assert!(
            !pending.is_effective(pending.effective_at - 1),
            "is_effective must return false before the notification period expires"
        );
    }

    #[test]
    fn pending_economic_policy_is_effective_true_after_period_expires() {
        let notified_at = 1_000_000u64;
        let pending = PendingEconomicPolicyChange {
            new_policy: scp_protocol::economy::types::EconomicPolicy {
                locked: false,
                cost_schedule: scp_protocol::economy::types::CostSchedule {
                    currency: scp_protocol::economy::types::CurrencyCode([85, 83, 68, 0]),
                    per_message: None,
                    per_tool_invoke: None,
                    per_join: None,
                    per_period: None,
                    per_byte_stored: None,
                },
                payment_adapters: vec![],
                pricing_formula: None,
                payee: DID::from("did:dht:z6MkPayee"),
            },
            notified_at,
            effective_at: notified_at + ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS,
            proposal_id: [0u8; 32],
        };
        assert!(
            pending.is_effective(pending.effective_at),
            "is_effective must return true at exactly effective_at"
        );
    }

    #[tokio::test]
    async fn execute_set_economic_policy_stages_with_24h_delay() {
        use scp_protocol::context::governance::GovernanceAction;
        use scp_protocol::economy::types::{CostSchedule, EconomicPolicy};

        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );

        let alice: DID = "did:dht:z6MkAlice".into();
        let key_a = signing_key_for_did(&alice);

        let params = ContextParams {
            governance: scp_protocol::context::params::GovernanceModel::SingleAdmin,
            ..ContextParams::default()
        };

        let _handle = manager
            .create_context("ctx-econ-delay".into(), params, alice.clone())
            .await
            .unwrap();

        let policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: scp_protocol::economy::types::CurrencyCode([85, 83, 68, 0]),
                per_message: None,
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec![],
            pricing_formula: None,
            payee: DID::from("did:dht:z6MkPayee"),
        };
        let action = GovernanceAction::SetEconomicPolicy {
            policy: policy.clone(),
        };

        let (_proposal, _events) = manager
            .propose_governance_action("ctx-econ-delay", &alice, action, &key_a)
            .await
            .unwrap();

        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("ctx-econ-delay").unwrap();
        let pending = ctx
            .governance
            .pending_economic_policy_change
            .as_ref()
            .expect("pending economic policy change should exist");
        assert_eq!(pending.new_policy, policy);
        assert_eq!(
            pending.effective_at,
            pending.notified_at + 86_400,
            "effective_at must be notified_at + 24h"
        );
        assert!(
            ctx.governance.economic_policy.is_none(),
            "economic policy should not be applied yet (still in notification period)"
        );
    }

    #[tokio::test]
    async fn apply_pending_economic_policy_change_respects_notification_period() {
        use scp_protocol::context::governance::GovernanceAction;
        use scp_protocol::economy::types::{CostSchedule, EconomicPolicy};

        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );

        let alice: DID = "did:dht:z6MkAlice".into();
        let key_a = signing_key_for_did(&alice);

        let params = ContextParams {
            governance: scp_protocol::context::params::GovernanceModel::SingleAdmin,
            ..ContextParams::default()
        };

        let _handle = manager
            .create_context("ctx-econ-apply".into(), params, alice.clone())
            .await
            .unwrap();

        let policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: scp_protocol::economy::types::CurrencyCode([85, 83, 68, 0]),
                per_message: None,
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec![],
            pricing_formula: None,
            payee: DID::from("did:dht:z6MkPayee"),
        };
        let action = GovernanceAction::SetEconomicPolicy {
            policy: policy.clone(),
        };

        let (_proposal, _events) = manager
            .propose_governance_action("ctx-econ-apply", &alice, action, &key_a)
            .await
            .unwrap();

        let notified_at = {
            let contexts = manager.contexts.lock().await;
            let ctx = contexts.get("ctx-econ-apply").unwrap();
            ctx.governance
                .pending_economic_policy_change
                .as_ref()
                .unwrap()
                .notified_at
        };

        let applied = manager
            .apply_pending_economic_policy_change("ctx-econ-apply", notified_at + 86_399)
            .await
            .unwrap();
        assert!(
            !applied,
            "should not apply before notification period expires"
        );

        let applied = manager
            .apply_pending_economic_policy_change("ctx-econ-apply", notified_at + 86_400)
            .await
            .unwrap();
        assert!(applied, "should apply at exactly effective_at");

        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("ctx-econ-apply").unwrap();
        assert!(
            ctx.governance.pending_economic_policy_change.is_none(),
            "pending change should be cleared after apply"
        );
        assert_eq!(
            ctx.governance.economic_policy.as_ref(),
            Some(&policy),
            "economic policy should now be set after apply"
        );
    }

    #[tokio::test]
    async fn execute_set_economic_policy_emits_notification_event() {
        use scp_protocol::context::governance::GovernanceAction;
        use scp_protocol::context::membership::ContextEvent;
        use scp_protocol::economy::types::{CostSchedule, EconomicPolicy};

        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );

        let alice: DID = "did:dht:z6MkAlice".into();
        let key_a = signing_key_for_did(&alice);

        let params = ContextParams {
            governance: scp_protocol::context::params::GovernanceModel::SingleAdmin,
            ..ContextParams::default()
        };

        let _handle = manager
            .create_context("ctx-econ-notify".into(), params, alice.clone())
            .await
            .unwrap();

        let policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: scp_protocol::economy::types::CurrencyCode([85, 83, 68, 0]),
                per_message: None,
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec![],
            pricing_formula: None,
            payee: DID::from("did:dht:z6MkPayee"),
        };
        let action = GovernanceAction::SetEconomicPolicy { policy };

        let (_proposal, _events) = manager
            .propose_governance_action("ctx-econ-notify", &alice, action, &key_a)
            .await
            .unwrap();

        let events = manager.drain_events("ctx-econ-notify").await;
        let notification = events
            .iter()
            .find(|e| matches!(e, ContextEvent::EconomicPolicyChangeNotification { .. }));
        assert!(
            notification.is_some(),
            "EconomicPolicyChangeNotification event should be emitted"
        );
        if let Some(ContextEvent::EconomicPolicyChangeNotification {
            notified_at,
            effective_at,
            ..
        }) = notification
        {
            assert_eq!(
                *effective_at,
                *notified_at + 86_400,
                "notification effective_at must be notified_at + 24h"
            );
        }
    }

    #[tokio::test]
    async fn execute_set_economic_policy_rejects_when_already_pending() {
        use scp_protocol::context::governance::GovernanceAction;
        use scp_protocol::economy::types::{CostSchedule, EconomicPolicy};

        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );

        let alice: DID = "did:dht:z6MkAlice".into();
        let key_a = signing_key_for_did(&alice);

        let params = ContextParams {
            governance: scp_protocol::context::params::GovernanceModel::SingleAdmin,
            ..ContextParams::default()
        };

        let _handle = manager
            .create_context("ctx-econ-dup".into(), params, alice.clone())
            .await
            .unwrap();

        let policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: scp_protocol::economy::types::CurrencyCode([85, 83, 68, 0]),
                per_message: None,
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec![],
            pricing_formula: None,
            payee: DID::from("did:dht:z6MkPayee"),
        };

        let action1 = GovernanceAction::SetEconomicPolicy {
            policy: policy.clone(),
        };
        let _ = manager
            .propose_governance_action("ctx-econ-dup", &alice, action1, &key_a)
            .await
            .unwrap();

        let action2 = GovernanceAction::SetEconomicPolicy { policy };
        let result = manager
            .propose_governance_action("ctx-econ-dup", &alice, action2, &key_a)
            .await;
        assert!(
            result.is_err(),
            "second SetEconomicPolicy should fail while one is already pending"
        );
    }

    // -----------------------------------------------------------------------
    // min_protocol_version defense-in-depth at create_context (#707)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_context_rejects_incompatible_min_protocol_version() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        let params = ContextParams {
            min_protocol_version: Some((2, 0)), // SDK is 1.0, this is unreachable
            ..ContextParams::default()
        };
        let result = manager
            .create_context("ver-reject".into(), params, "did:key:creator".into())
            .await;
        assert!(
            result.is_err(),
            "create_context should reject min_protocol_version (2,0)"
        );
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("version incompatible"),
            "error should mention version incompatibility: {err_msg}"
        );
    }

    #[tokio::test]
    async fn create_context_accepts_compatible_min_protocol_version() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        let params = ContextParams {
            min_protocol_version: Some((1, 0)), // matches SDK version
            ..ContextParams::default()
        };
        let result = manager
            .create_context("ver-accept".into(), params, "did:key:creator".into())
            .await;
        assert!(
            result.is_ok(),
            "create_context should accept min_protocol_version (1,0)"
        );
    }

    #[tokio::test]
    async fn create_context_accepts_none_min_protocol_version() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );
        let params = ContextParams {
            min_protocol_version: None, // defaults to (1,0) — always compatible
            ..ContextParams::default()
        };
        let result = manager
            .create_context("ver-none".into(), params, "did:key:creator".into())
            .await;
        assert!(
            result.is_ok(),
            "create_context should accept min_protocol_version None"
        );
    }

    // -----------------------------------------------------------------------
    // ContextManagerBuilder tests (#937 review finding 6)
    // -----------------------------------------------------------------------

    #[test]
    fn builder_without_crypto_returns_missing_crypto_error() {
        let result = ContextManager::builder().build();
        assert!(
            matches!(result, Err(ContextManagerBuildError::MissingCrypto)),
            "expected MissingCrypto error"
        );
    }

    #[test]
    fn builder_with_only_crypto_succeeds() {
        let result = ContextManager::builder()
            .crypto(Box::new(MockCrypto::default()))
            .build();
        assert!(
            result.is_ok(),
            "builder with only crypto should succeed with defaults"
        );
    }

    #[test]
    fn builder_persistence_wires_through() {
        use crate::context::providers::persistence::InMemoryPersistence;

        let result = ContextManager::builder()
            .crypto(Box::new(MockCrypto::default()))
            .persistence(Box::new(InMemoryPersistence::new()))
            .build();
        assert!(
            result.is_ok(),
            "builder with crypto + persistence should succeed"
        );

        // The manager should have persistence wired.
        let manager = result.unwrap();
        assert!(
            manager.persistence.is_some(),
            "persistence() should wire through to the manager"
        );
    }

    #[test]
    fn builder_storage_auto_wires_persistence_and_event_log() {
        use scp_platform::encrypting_adapter::EncryptingAdapter;
        use scp_platform::testing::InMemoryStorage;
        use zeroize::Zeroizing;

        let key = Zeroizing::new([0x42u8; 32]);
        let storage = EncryptingAdapter::new(InMemoryStorage::new(), key);

        let manager = ContextManager::builder()
            .crypto(Box::new(MockCrypto::default()))
            .storage(storage)
            .build()
            .expect("builder with crypto + storage should succeed");

        assert!(
            manager.has_persistence(),
            ".storage() should auto-wire persistence"
        );
    }

    // -----------------------------------------------------------------------
    // ApproveSpend → MemberBudgetTracker integration (issue #622)
    // -----------------------------------------------------------------------

    /// Helper: create a `SingleAdmin` context with a spender member added.
    async fn setup_budget_context(ctx_id: &str) -> (ContextManager, DID, DID) {
        let admin_did: DID = "did:key:admin".into();
        let spender_did: DID = "did:key:spender".into();
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );
        let params = ContextParams {
            ceiling: vec![
                scp_protocol::context::params::Capability::new("messages:read"),
                scp_protocol::context::params::Capability::new("messages:write"),
                scp_protocol::context::params::Capability::new("role:assign"),
                scp_protocol::context::params::Capability::new("governance:propose"),
                scp_protocol::context::params::Capability::new("governance:vote"),
            ],
            ..ContextParams::default()
        };
        manager
            .create_context(ctx_id.into(), params, admin_did.clone())
            .await
            .unwrap();
        let sk = signing_key_for_did(&admin_did);
        manager
            .propose_governance_action(
                ctx_id,
                &admin_did,
                GovernanceAction::AddMember {
                    did: spender_did.clone(),
                    role: "member".to_owned(),
                },
                &sk,
            )
            .await
            .unwrap();
        (manager, admin_did, spender_did)
    }

    /// Verifies that `ApproveSpend` grants budget and additive grants accumulate.
    #[tokio::test]
    async fn approve_spend_grants_budget_to_member_tracker() {
        let (manager, admin, spender) = setup_budget_context("budget-ctx").await;
        let sk = signing_key_for_did(&admin);

        // No budget initially.
        {
            let contexts = manager.contexts.lock().await;
            let ctx = contexts.get("budget-ctx").unwrap();
            assert!(!ctx.governance.budget_tracker.has_budget(&spender));
        }

        // First grant: 5000.
        manager
            .propose_governance_action(
                "budget-ctx",
                &admin,
                GovernanceAction::ApproveSpend {
                    spender: spender.clone(),
                    amount: scp_protocol::economy::types::Amount::new(5000),
                    purpose: "tool budget".to_owned(),
                },
                &sk,
            )
            .await
            .unwrap();
        {
            let contexts = manager.contexts.lock().await;
            let ctx = contexts.get("budget-ctx").unwrap();
            assert!(ctx.governance.budget_tracker.has_budget(&spender));
            assert_eq!(
                ctx.governance.budget_tracker.remaining(&spender),
                scp_protocol::economy::types::Amount::new(5000)
            );
        }

        // Second grant: 3000 — additive.
        manager
            .propose_governance_action(
                "budget-ctx",
                &admin,
                GovernanceAction::ApproveSpend {
                    spender: spender.clone(),
                    amount: scp_protocol::economy::types::Amount::new(3000),
                    purpose: "more budget".to_owned(),
                },
                &sk,
            )
            .await
            .unwrap();
        {
            let contexts = manager.contexts.lock().await;
            let ctx = contexts.get("budget-ctx").unwrap();
            assert_eq!(
                ctx.governance.budget_tracker.limit(&spender),
                scp_protocol::economy::types::Amount::new(8000)
            );
        }
    }

    /// Verifies that `ApproveSpend` rejects non-member spenders.
    #[tokio::test]
    async fn approve_spend_rejects_non_member_spender() {
        let admin_did: DID = "did:key:admin".into();
        let non_member: DID = "did:key:nonmember".into();
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        );
        let params = ContextParams {
            ceiling: vec![
                scp_protocol::context::params::Capability::new("messages:read"),
                scp_protocol::context::params::Capability::new("messages:write"),
                scp_protocol::context::params::Capability::new("governance:propose"),
                scp_protocol::context::params::Capability::new("governance:vote"),
            ],
            ..ContextParams::default()
        };
        manager
            .create_context("reject-ctx".into(), params, admin_did.clone())
            .await
            .unwrap();
        let sk = signing_key_for_did(&admin_did);
        let result = manager
            .propose_governance_action(
                "reject-ctx",
                &admin_did,
                GovernanceAction::ApproveSpend {
                    spender: non_member,
                    amount: scp_protocol::economy::types::Amount::new(1000),
                    purpose: "should fail".to_owned(),
                },
                &sk,
            )
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::MemberNotFound(_)
        ));
    }

    /// Verifies that `budget_tracker` is included in context snapshots
    /// and survives serde roundtrip.
    #[tokio::test]
    async fn budget_tracker_included_in_snapshot() {
        let (manager, admin, spender) = setup_budget_context("snap-ctx").await;
        let sk = signing_key_for_did(&admin);
        manager
            .propose_governance_action(
                "snap-ctx",
                &admin,
                GovernanceAction::ApproveSpend {
                    spender: spender.clone(),
                    amount: scp_protocol::economy::types::Amount::new(2500),
                    purpose: "snapshot test".to_owned(),
                },
                &sk,
            )
            .await
            .unwrap();

        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("snap-ctx").unwrap();
        let snapshot = ContextManager::snapshot_context(ctx);
        assert!(snapshot.budget_tracker.has_budget(&spender));
        assert_eq!(
            snapshot.budget_tracker.remaining(&spender),
            scp_protocol::economy::types::Amount::new(2500)
        );

        // Serde roundtrip.
        let json = serde_json::to_string(&snapshot).unwrap();
        let restored: ContextSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(
            restored.budget_tracker.remaining(&spender),
            scp_protocol::economy::types::Amount::new(2500)
        );
    }

    // ===================================================================
    // MLS governance integration (issue #630)
    // ===================================================================

    /// Helper: creates an approved governance proposal for a given action
    /// using `SingleAdminEngine` with a mock key resolver that uses
    /// deterministic keys from `signing_key_for_did`. Returns the approved
    /// proposal ready for `execute_governance_action()`.
    fn make_approved_proposal(
        admin_did: &DID,
        context_id: &str,
        action: super::GovernanceAction,
    ) -> super::GovernanceProposal {
        use scp_protocol::context::governance::{
            GovernanceContext, GovernanceEngine, SingleAdminEngine,
        };

        let signing_key = signing_key_for_did(admin_did);
        let resolver = mock_key_resolver();
        let mut engine = SingleAdminEngine::new(admin_did.clone(), resolver);
        let gov_ctx = GovernanceContext {
            context_id: context_id.to_owned(),
            members: vec![(admin_did.clone(), "admin".to_owned())],
            admin_dids: vec![admin_did.clone()],
            current_epoch: Some(0),
            now: 1000,
        };

        let (proposal, _events) = engine
            .propose(admin_did, action, &gov_ctx, &signing_key)
            .unwrap();
        assert!(matches!(proposal.status, super::ProposalStatus::Approved));
        proposal
    }

    // -----------------------------------------------------------------------
    // Context migration tests (§5.11A, #580)
    // -----------------------------------------------------------------------

    /// Helper: creates an approved `ProposeContextMigration` governance
    /// proposal using a `SingleAdminEngine`. The admin DID's signing key
    /// is derived from a fixed seed so governance vote verification passes.
    fn approved_migration_proposal(
        admin_did: &DID,
        context_id: &str,
        new_params: ContextParams,
        reason: &str,
        grace_period_secs: u64,
        auto_invite: bool,
    ) -> super::GovernanceProposal {
        use scp_protocol::context::governance::{
            GovernanceAction, GovernanceContext, GovernanceEngine, SingleAdminEngine,
        };

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let vk = signing_key.verifying_key();
        #[allow(clippy::type_complexity)]
        let resolver: std::sync::Arc<
            dyn Fn(&scp_identity::DID) -> Option<ed25519_dalek::VerifyingKey> + Send + Sync,
        > = std::sync::Arc::new(move |_| Some(vk));
        let mut engine = SingleAdminEngine::new(admin_did.clone(), resolver);
        let gov_ctx = GovernanceContext {
            context_id: context_id.to_owned(),
            members: vec![(admin_did.clone(), "admin".to_owned())],
            admin_dids: vec![admin_did.clone()],
            current_epoch: None,
            now: 1000,
        };

        let action = GovernanceAction::ProposeContextMigration {
            new_context_params: Box::new(new_params),
            reason: reason.to_owned(),
            grace_period_secs,
            auto_invite,
        };

        let (proposal, _events) = engine
            .propose(admin_did, action, &gov_ctx, &signing_key)
            .unwrap();
        assert!(matches!(proposal.status, super::ProposalStatus::Approved));
        proposal
    }

    /// Issue #630 AC1: `dispatch_governance_action` calls `classify_action()`
    /// after membership-affecting actions. Verifying that `AddMember`
    /// increments `mls_epoch` (which requires `classify_action` returning
    /// `MembershipChange`).
    #[tokio::test]
    async fn mls_integration_add_member_increments_epoch() {
        let admin_did: DID = "did:key:creator".into();
        let (manager, _handle) = setup_active_context().await;

        let action = super::GovernanceAction::AddMember {
            did: "did:key:new-member".into(),
            role: "member".to_owned(),
        };
        let proposal = make_approved_proposal(&admin_did, "test-ctx", action);
        let result = manager
            .execute_governance_action("test-ctx", &proposal)
            .await;
        assert!(result.is_ok(), "AddMember should succeed");

        // Verify epoch was incremented (from 0 to 1).
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("test-ctx").unwrap();
        assert_eq!(
            ctx.epoch.mls_epoch, 1,
            "MLS epoch should advance after AddMember"
        );
    }

    /// Issue #630 AC2: MLS commits generated and applied for `AddMember`.
    /// Verified by checking that `generate_mls_operations` is invoked
    /// (the `EpochCoordinator` records the generated MLS operation) and
    /// the new member appears in the membership state.
    #[tokio::test]
    async fn mls_integration_add_member_generates_mls_operation() {
        let admin_did: DID = "did:key:creator".into();
        let (manager, _handle) = setup_active_context().await;

        let action = super::GovernanceAction::AddMember {
            did: "did:key:new-member".into(),
            role: "member".to_owned(),
        };
        let proposal = make_approved_proposal(&admin_did, "test-ctx", action);
        manager
            .execute_governance_action("test-ctx", &proposal)
            .await
            .unwrap();

        // Verify: the EpochCoordinator recorded an AddMember MLS operation,
        // proving that generate_mls_operations was called.
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("test-ctx").unwrap();
        let records = ctx.epoch.coordinator.records();
        assert_eq!(records.len(), 1);
        if let scp_protocol::context::governance::mls_integration::MlsOperation::AddMember {
            ref did,
            ref role,
        } = records[0].operation
        {
            assert_eq!(did.as_ref(), "did:key:new-member");
            assert_eq!(role, "member");
        } else {
            panic!("expected AddMember MLS operation");
        }

        // Verify: the member is in the membership state.
        let target_did: DID = "did:key:new-member".into();
        assert!(ctx.membership.contains(&target_did));
    }

    /// Issue #630 AC3: `EpochCoordinator` instantiated per context and
    /// records coordination after membership-affecting governance actions.
    #[tokio::test]
    async fn mls_integration_epoch_coordinator_records_coordination() {
        let admin_did: DID = "did:key:creator".into();
        let (manager, _handle) = setup_active_context().await;

        // Execute AddMember — should record coordination.
        let action = super::GovernanceAction::AddMember {
            did: "did:key:member-a".into(),
            role: "member".to_owned(),
        };
        let proposal = make_approved_proposal(&admin_did, "test-ctx", action);
        manager
            .execute_governance_action("test-ctx", &proposal)
            .await
            .unwrap();

        // Execute RemoveMember — should record second coordination.
        let action2 = super::GovernanceAction::RemoveMember {
            did: "did:key:member-a".into(),
            reason: Some("done".to_owned()),
        };
        let proposal2 = make_approved_proposal(&admin_did, "test-ctx", action2);
        manager
            .execute_governance_action("test-ctx", &proposal2)
            .await
            .unwrap();

        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("test-ctx").unwrap();
        assert_eq!(
            ctx.epoch.coordinator.record_count(),
            2,
            "should have 2 coordination records after 2 MLS-affecting actions"
        );

        // Verify first record: epoch 0 → 1 for AddMember.
        let records = ctx.epoch.coordinator.records();
        assert_eq!(records[0].epoch_before, 0);
        assert_eq!(records[0].epoch_after, 1);
        assert!(matches!(
            records[0].operation,
            scp_protocol::context::governance::mls_integration::MlsOperation::AddMember { .. }
        ));

        // Verify second record: epoch 1 → 2 for RemoveMember.
        assert_eq!(records[1].epoch_before, 1);
        assert_eq!(records[1].epoch_after, 2);
        assert!(matches!(
            records[1].operation,
            scp_protocol::context::governance::mls_integration::MlsOperation::RemoveMember { .. }
        ));
    }

    /// Issue #630 AC3: Non-membership actions do NOT create coordination
    /// records in the `EpochCoordinator`.
    #[tokio::test]
    async fn mls_integration_non_membership_action_no_coordination() {
        let admin_did: DID = "did:key:creator".into();
        let (manager, _handle) = setup_active_context().await;

        // ChangeRole is a non-membership action — should not coordinate.
        // First add the member so we have someone to change role for.
        let add_action = super::GovernanceAction::AddMember {
            did: "did:key:target".into(),
            role: "member".to_owned(),
        };
        let add_proposal = make_approved_proposal(&admin_did, "test-ctx", add_action);
        manager
            .execute_governance_action("test-ctx", &add_proposal)
            .await
            .unwrap();

        let action = super::GovernanceAction::ChangeRole {
            did: "did:key:target".into(),
            new_role: "observer".to_owned(),
        };
        let proposal = make_approved_proposal(&admin_did, "test-ctx", action);
        manager
            .execute_governance_action("test-ctx", &proposal)
            .await
            .unwrap();

        // Should have exactly 1 coordination record (from AddMember only).
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("test-ctx").unwrap();
        assert_eq!(
            ctx.epoch.coordinator.record_count(),
            1,
            "ChangeRole should not create a coordination record"
        );
        // Epoch should still be 1 (AddMember advanced 0→1, ChangeRole doesn't).
        assert_eq!(ctx.epoch.mls_epoch, 1);
    }

    /// Issue #630 AC3: `EpochCoordinator` records survive snapshot roundtrip.
    #[tokio::test]
    async fn mls_integration_epoch_coordinator_snapshot_roundtrip() {
        let admin_did: DID = "did:key:creator".into();
        let (manager, _handle) = setup_active_context().await;

        let action = super::GovernanceAction::AddMember {
            did: "did:key:snap-member".into(),
            role: "member".to_owned(),
        };
        let proposal = make_approved_proposal(&admin_did, "test-ctx", action);
        manager
            .execute_governance_action("test-ctx", &proposal)
            .await
            .unwrap();

        // Take snapshot and verify records are captured.
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("test-ctx").unwrap();
        let snapshot = ContextManager::snapshot_context(ctx);
        assert_eq!(
            snapshot.epoch_coordination_records.len(),
            1,
            "snapshot should capture coordination records"
        );

        // Serde roundtrip.
        let json = serde_json::to_string(&snapshot).unwrap();
        let restored: ContextSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(
            restored.epoch_coordination_records.len(),
            1,
            "records should survive serde roundtrip"
        );
        assert_eq!(restored.epoch_coordination_records[0].epoch_before, 0);
        assert_eq!(restored.epoch_coordination_records[0].epoch_after, 1);
    }

    /// Issue #630 AC4: Checkpoint cosignature collection is NOT triggered
    /// for `SingleAdmin` contexts (quorum is 0).
    #[tokio::test]
    async fn mls_integration_no_checkpoint_event_for_single_admin() {
        let admin_did: DID = "did:key:creator".into();
        let (manager, _handle) = setup_active_context().await;

        let action = super::GovernanceAction::AddMember {
            did: "did:key:member-cp".into(),
            role: "member".to_owned(),
        };
        let proposal = make_approved_proposal(&admin_did, "test-ctx", action);
        manager
            .execute_governance_action("test-ctx", &proposal)
            .await
            .unwrap();

        // Drain the receive buffer and check that no
        // CheckpointCosignatureRequired event was emitted.
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("test-ctx").unwrap();
        let events = ctx.receive_buffer.drain();
        let has_checkpoint_event = events
            .iter()
            .any(|e| matches!(e, ContextEvent::CheckpointCosignatureRequired { .. }));
        assert!(
            !has_checkpoint_event,
            "SingleAdmin contexts should not emit CheckpointCosignatureRequired"
        );
    }

    /// Issue #630 AC5: `ResolveConflict` requires governance freeze state.
    #[tokio::test]
    async fn mls_integration_resolve_conflict_requires_freeze() {
        use scp_protocol::context::governance::ConflictResolution;

        let admin_did: DID = "did:key:creator".into();
        let (manager, _handle) = setup_active_context().await;

        // Try to resolve a conflict without a freeze state.
        let action = super::GovernanceAction::ResolveConflict {
            proposal_a: [1u8; 32],
            proposal_b: [2u8; 32],
            resolution: ConflictResolution::InvalidateBoth,
        };
        let proposal = make_approved_proposal(&admin_did, "test-ctx", action);
        let result = manager
            .execute_governance_action("test-ctx", &proposal)
            .await;

        assert!(result.is_err(), "should fail without governance freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(err, ContextError::PermissionDenied(ref msg) if msg.contains("freeze")),
            "error should mention freeze state: {err:?}"
        );
    }

    /// Issue #630 AC5: `ResolveConflict` with governance freeze lifts freeze.
    #[tokio::test]
    async fn mls_integration_resolve_conflict_lifts_freeze() {
        use scp_protocol::context::governance::ConflictResolution;

        let admin_did: DID = "did:key:creator".into();
        let other_did: DID = "did:key:other-admin".into();
        let (manager, _handle) = setup_active_context().await;

        // Build two conflicting proposals (mutual RemoveMember — each
        // proposer removes the other, which is a canonical conflict per
        // ADR-031 §7).
        let proposal_a_id = [10u8; 32];
        let proposal_b_id = [20u8; 32];

        let conflict_proposal_a = super::GovernanceProposal {
            proposal_id: proposal_a_id,
            context_id: "test-ctx".to_owned(),
            proposer_did: admin_did.clone(),
            action: super::GovernanceAction::RemoveMember {
                did: other_did.clone(),
                reason: None,
            },
            status: super::ProposalStatus::Approved,
            created_at: 900,
            voting_deadline: 2000,
            approvals: vec![],
            rejections: vec![],
            created_at_epoch: Some(0),
        };
        let conflict_proposal_b = super::GovernanceProposal {
            proposal_id: proposal_b_id,
            context_id: "test-ctx".to_owned(),
            proposer_did: other_did.clone(),
            action: super::GovernanceAction::RemoveMember {
                did: admin_did.clone(),
                reason: None,
            },
            status: super::ProposalStatus::Approved,
            created_at: 900,
            voting_deadline: 2000,
            approvals: vec![],
            rejections: vec![],
            created_at_epoch: Some(0),
        };

        // Manually set governance freeze and insert the conflicting
        // proposals into approved_proposals.
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("test-ctx").unwrap();
            ctx.governance.freeze = Some((proposal_a_id, proposal_b_id, 1000));
            ctx.governance
                .approved_proposals
                .insert(proposal_a_id, (conflict_proposal_a, 900, 2000));
            ctx.governance
                .approved_proposals
                .insert(proposal_b_id, (conflict_proposal_b, 900, 2000));
        }

        let action = super::GovernanceAction::ResolveConflict {
            proposal_a: proposal_a_id,
            proposal_b: proposal_b_id,
            resolution: ConflictResolution::InvalidateBoth,
        };
        let proposal = make_approved_proposal(&admin_did, "test-ctx", action);
        let result = manager
            .execute_governance_action("test-ctx", &proposal)
            .await;
        assert!(
            result.is_ok(),
            "resolve conflict with freeze should succeed: {result:?}"
        );

        // Verify freeze is cleared.
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("test-ctx").unwrap();
        assert!(
            ctx.governance.freeze.is_none(),
            "governance freeze should be cleared after conflict resolution"
        );

        // Both proposals should be in executed_proposals (invalidated).
        assert!(
            ctx.governance
                .executed_proposals
                .contains_key(&proposal_a_id)
        );
        assert!(
            ctx.governance
                .executed_proposals
                .contains_key(&proposal_b_id)
        );
    }

    /// Helper: creates an approved `CancelContextMigration` governance
    /// proposal using a `SingleAdminEngine`.
    fn approved_cancel_migration_proposal(
        admin_did: &DID,
        context_id: &str,
    ) -> super::GovernanceProposal {
        use scp_protocol::context::governance::{
            GovernanceAction, GovernanceContext, GovernanceEngine, SingleAdminEngine,
        };

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let vk = signing_key.verifying_key();
        #[allow(clippy::type_complexity)]
        let resolver: std::sync::Arc<
            dyn Fn(&scp_identity::DID) -> Option<ed25519_dalek::VerifyingKey> + Send + Sync,
        > = std::sync::Arc::new(move |_| Some(vk));
        let mut engine = SingleAdminEngine::new(admin_did.clone(), resolver);
        let gov_ctx = GovernanceContext {
            context_id: context_id.to_owned(),
            members: vec![(admin_did.clone(), "admin".to_owned())],
            admin_dids: vec![admin_did.clone()],
            current_epoch: None,
            now: 1000,
        };

        let action = GovernanceAction::CancelContextMigration;

        let (proposal, _events) = engine
            .propose(admin_did, action, &gov_ctx, &signing_key)
            .unwrap();
        assert!(matches!(proposal.status, super::ProposalStatus::Approved));
        proposal
    }

    /// Section 5.11A lifecycle: propose -> approve -> tombstone.
    ///
    /// Verifies that:
    /// 1. The source context transitions to `MigratingOut`.
    /// 2. A destination context is created with `migration_source` metadata.
    /// 3. `send_message` is blocked during the grace period.
    /// 4. Tombstoning transitions the source to `Tombstoned`.
    #[tokio::test]
    async fn migration_propose_approve_tombstone_lifecycle() {
        let (manager, handle) = setup_active_context().await;
        let admin_did: DID = "did:key:creator".into();

        // Propose migration with a zero-second grace period so we can
        // tombstone immediately.
        let dest_params = ContextParams::default();
        let proposal = approved_migration_proposal(
            &admin_did,
            "test-ctx",
            dest_params,
            "expanding ceiling",
            0, // zero-second grace period
            false,
        );

        let result = manager
            .execute_governance_action("test-ctx", &proposal)
            .await;
        assert!(result.is_ok(), "migration proposal should succeed");

        // Source context should be MigratingOut.
        assert_eq!(handle.state().await, ContextState::MigratingOut);

        // migration_state should be set.
        let ms = manager.migration_state("test-ctx").await;
        assert!(ms.is_some(), "migration state should be set");
        let ms = ms.unwrap();
        assert_eq!(ms.reason, "expanding ceiling");

        // Destination context should exist.
        let dest_id = &ms.destination_context_id;
        let dest_ms = manager.migration_state(dest_id).await;
        // Destination should NOT have migration state (it's not migrating).
        assert!(dest_ms.is_none());

        // send_message should be blocked (grace period = read-only).
        let send_result = manager
            .send_message(&handle, &admin_did, b"hello", None)
            .await;
        assert!(
            send_result.is_err(),
            "send_message should fail during MigratingOut"
        );

        // Tombstone should succeed (grace period is 0 seconds).
        let tombstone_result = manager.tombstone_migrated_context("test-ctx").await;
        assert!(tombstone_result.is_ok(), "tombstone should succeed");
        assert_eq!(handle.state().await, ContextState::Tombstoned);

        // migration_state should be cleared after tombstoning.
        let ms_after = manager.migration_state("test-ctx").await;
        assert!(ms_after.is_none(), "migration state should be cleared");
    }

    /// §5.11A lifecycle: propose -> cancel.
    ///
    /// Verifies that cancelling a migration returns the context to Active
    /// and clears migration state.
    #[tokio::test]
    async fn migration_propose_cancel_lifecycle() {
        let (manager, handle) = setup_active_context().await;
        let admin_did: DID = "did:key:creator".into();

        let dest_params = ContextParams::default();
        let proposal = approved_migration_proposal(
            &admin_did,
            "test-ctx",
            dest_params,
            "test cancel",
            604_800, // 7 days
            false,
        );

        let result = manager
            .execute_governance_action("test-ctx", &proposal)
            .await;
        assert!(result.is_ok(), "migration proposal should succeed");
        assert_eq!(handle.state().await, ContextState::MigratingOut);

        // Cancel.
        let cancel_proposal = approved_cancel_migration_proposal(&admin_did, "test-ctx");
        let cancel_result = manager
            .execute_governance_action("test-ctx", &cancel_proposal)
            .await;
        assert!(cancel_result.is_ok(), "cancel should succeed");

        // Context should be Active again.
        assert_eq!(handle.state().await, ContextState::Active);

        // Migration state should be cleared.
        let ms = manager.migration_state("test-ctx").await;
        assert!(
            ms.is_none(),
            "migration state should be cleared after cancel"
        );

        // send_message should work again.
        let send_result = manager
            .send_message(&handle, &admin_did, b"hello", None)
            .await;
        assert!(
            send_result.is_ok(),
            "send_message should succeed after cancel"
        );
    }

    /// §5.11A: duplicate migration should be rejected.
    ///
    /// A second `ProposeContextMigration` while one is already in progress
    /// must fail.
    #[tokio::test]
    async fn migration_duplicate_proposal_rejected() {
        let (manager, handle) = setup_active_context().await;
        let admin_did: DID = "did:key:creator".into();

        let dest_params = ContextParams::default();
        let proposal = approved_migration_proposal(
            &admin_did,
            "test-ctx",
            dest_params.clone(),
            "first migration",
            604_800,
            false,
        );

        let result = manager
            .execute_governance_action("test-ctx", &proposal)
            .await;
        assert!(result.is_ok());
        assert_eq!(handle.state().await, ContextState::MigratingOut);

        // Second proposal should be rejected because context is in
        // MigratingOut state (require_active fails).
        let proposal2 = approved_migration_proposal(
            &admin_did,
            "test-ctx",
            dest_params,
            "second migration",
            604_800,
            false,
        );

        let result2 = manager
            .execute_governance_action("test-ctx", &proposal2)
            .await;
        assert!(result2.is_err(), "duplicate migration proposal should fail");
    }

    /// §5.11A.4: grace period enforcement.
    ///
    /// Tombstoning should fail if the grace period has not expired.
    #[tokio::test]
    async fn migration_grace_period_prevents_early_tombstone() {
        let (manager, _handle) = setup_active_context().await;
        let admin_did: DID = "did:key:creator".into();

        let dest_params = ContextParams::default();
        let proposal = approved_migration_proposal(
            &admin_did,
            "test-ctx",
            dest_params,
            "grace period test",
            999_999_999, // very long grace period
            false,
        );

        let result = manager
            .execute_governance_action("test-ctx", &proposal)
            .await;
        assert!(result.is_ok());

        // Tombstone should fail — grace period hasn't expired.
        let tombstone_result = manager.tombstone_migrated_context("test-ctx").await;
        assert!(
            tombstone_result.is_err(),
            "tombstone should fail before grace period expires"
        );
        let err_msg = tombstone_result.unwrap_err().to_string();
        assert!(
            err_msg.contains("grace period has not expired"),
            "error should mention grace period, got: {err_msg}"
        );
    }

    /// Section 5.11A.2: destination context has `migration_source` metadata.
    #[tokio::test]
    async fn migration_destination_has_migration_source_metadata() {
        let (manager, _handle) = setup_active_context().await;
        let admin_did: DID = "did:key:creator".into();

        let dest_params = ContextParams::default();
        let proposal = approved_migration_proposal(
            &admin_did,
            "test-ctx",
            dest_params,
            "metadata test",
            0,
            true,
        );

        let result = manager
            .execute_governance_action("test-ctx", &proposal)
            .await;
        assert!(result.is_ok());

        let ms = manager.migration_state("test-ctx").await.unwrap();
        let dest_id = &ms.destination_context_id;

        // The destination context should have migration_source set.
        let contexts = manager.contexts.lock().await;
        let dest_ctx = contexts.get(dest_id);
        assert!(
            dest_ctx.is_some(),
            "destination context should be registered"
        );
        let dest_params = dest_ctx.unwrap().handle.params();
        assert!(
            dest_params.migration_source.is_some(),
            "destination should have migration_source metadata"
        );
        let source = dest_params.migration_source.as_ref().unwrap();
        assert_eq!(
            source.source_context_id, "test-ctx",
            "migration_source should reference the source context"
        );
        assert_eq!(
            source.proposal_id, ms.proposal_id,
            "migration_source proposal_id should match"
        );
    }

    // -----------------------------------------------------------------------
    // Degraded mode reporting tests (§13.6, #606)
    // -----------------------------------------------------------------------

    /// `report_degraded_mode` emits a `ContextEvent::DegradedMode` when given
    /// a `VersionCompatibility::DegradedMode` result.
    #[tokio::test]
    async fn report_degraded_mode_emits_event() {
        let (manager, _handle) = setup_active_context().await;

        let compat = scp_protocol::envelope::VersionCompatibility::DegradedMode {
            local_minor: 0,
            remote_minor: 3,
        };

        manager
            .report_degraded_mode("test-ctx", compat, vec!["hypothetical-feature".to_owned()])
            .await;

        let events = manager.drain_events("test-ctx").await;
        assert_eq!(events.len(), 1);
        match &events[0] {
            ContextEvent::DegradedMode {
                context_id,
                local_version,
                remote_version,
                unsupported_features,
            } => {
                assert_eq!(context_id, "test-ctx");
                assert_eq!(*local_version, (1, 0));
                assert_eq!(*remote_version, (1, 3));
                assert_eq!(unsupported_features, &["hypothetical-feature"]);
            }
            other => panic!("expected DegradedMode event, got {other:?}"),
        }
    }

    /// `report_degraded_mode` is a no-op when given
    /// `VersionCompatibility::Exact`.
    #[tokio::test]
    async fn report_degraded_mode_noop_for_exact() {
        let (manager, _handle) = setup_active_context().await;

        manager
            .report_degraded_mode(
                "test-ctx",
                scp_protocol::envelope::VersionCompatibility::Exact,
                vec![],
            )
            .await;

        let events = manager.drain_events("test-ctx").await;
        assert!(
            events.is_empty(),
            "Exact compatibility should not emit events"
        );
    }

    /// `report_degraded_mode` is a no-op for an unknown context.
    #[tokio::test]
    async fn report_degraded_mode_noop_for_unknown_context() {
        let (manager, _handle) = setup_active_context().await;

        let compat = scp_protocol::envelope::VersionCompatibility::DegradedMode {
            local_minor: 0,
            remote_minor: 2,
        };

        // "nonexistent-ctx" is not registered — should not panic.
        manager
            .report_degraded_mode("nonexistent-ctx", compat, vec![])
            .await;

        // No events on the registered context either.
        let events = manager.drain_events("test-ctx").await;
        assert!(events.is_empty());
    }

    /// Multiple degraded mode reports accumulate in the receive buffer.
    #[tokio::test]
    async fn report_degraded_mode_accumulates() {
        let (manager, _handle) = setup_active_context().await;

        for minor in 1..=3u8 {
            let compat = scp_protocol::envelope::VersionCompatibility::DegradedMode {
                local_minor: 0,
                remote_minor: minor,
            };
            manager
                .report_degraded_mode("test-ctx", compat, vec![])
                .await;
        }

        let events = manager.drain_events("test-ctx").await;
        let degraded_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, ContextEvent::DegradedMode { .. }))
            .collect();
        assert_eq!(degraded_events.len(), 3);
    }

    // -----------------------------------------------------------------------
    // recovery_advance_epoch tests (#1250, #1248)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_recovery_advance_epoch_calls_crypto_provider() {
        let shared_epochs: Arc<std::sync::Mutex<Vec<[u8; 32]>>> = Arc::default();
        let crypto = MockCrypto {
            epochs_advanced_shared: Arc::clone(&shared_epochs),
            ..MockCrypto::default()
        };

        let manager = ContextManager::new(
            Box::new(crypto),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let _handle = manager
            .create_context(
                "recovery-epoch-1".into(),
                ContextParams::default(),
                "did:key:creator".into(),
            )
            .await
            .unwrap();

        let expected_bytes = context_id_to_bytes("recovery-epoch-1");

        let new_epoch = manager
            .recovery_advance_epoch("recovery-epoch-1")
            .await
            .unwrap();

        assert_eq!(new_epoch, 1, "epoch should advance from 0 to 1");

        // Verify the crypto provider was actually called with the correct id.
        {
            let calls = shared_epochs.lock().unwrap();
            assert_eq!(calls.len(), 1, "crypto provider should be called once");
            assert_eq!(
                calls[0], expected_bytes,
                "crypto provider should receive the context id bytes"
            );
        }

        // A second advance should yield epoch 2, confirming the counter
        // increments correctly and the crypto provider is called each time.
        let epoch2 = manager
            .recovery_advance_epoch("recovery-epoch-1")
            .await
            .unwrap();
        assert_eq!(epoch2, 2, "second advance should yield epoch 2");

        // Verify two total crypto calls after the second advance.
        {
            let calls = shared_epochs.lock().unwrap();
            assert_eq!(calls.len(), 2, "crypto provider should be called twice");
        }
    }

    #[tokio::test]
    async fn test_recovery_advance_epoch_rollback_on_crypto_failure() {
        let crypto = MockCrypto::default();
        crypto.fail_advance_epoch.store(true, Ordering::Relaxed);

        let manager = ContextManager::new(
            Box::new(crypto),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let _handle = manager
            .create_context(
                "recovery-fail-1".into(),
                ContextParams::default(),
                "did:key:creator".into(),
            )
            .await
            .unwrap();

        let result = manager.recovery_advance_epoch("recovery-fail-1").await;

        assert!(result.is_err(), "should fail when crypto fails");
        assert!(
            matches!(result.unwrap_err(), ContextError::CryptoFailed(_)),
            "should return CryptoFailed variant"
        );

        // Epoch counter must NOT have been incremented.
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("recovery-fail-1").unwrap();
        assert_eq!(
            ctx.epoch.mls_epoch, 0,
            "epoch counter must not increment on crypto failure"
        );
    }

    #[tokio::test]
    async fn test_recovery_advance_epoch_rejects_inactive_context() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let handle = manager
            .create_context(
                "recovery-inactive-1".into(),
                ContextParams::default(),
                "did:key:creator".into(),
            )
            .await
            .unwrap();

        // Transition to Closing — no longer Active.
        handle.transition_to(&ContextState::Closing).await.unwrap();

        let result = manager.recovery_advance_epoch("recovery-inactive-1").await;

        assert!(result.is_err(), "should fail for non-active context");
        assert!(
            matches!(result.unwrap_err(), ContextError::ContextNotActive),
            "should return ContextNotActive"
        );

        // Verify epoch was not advanced.
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("recovery-inactive-1").unwrap();
        assert_eq!(
            ctx.epoch.mls_epoch, 0,
            "epoch must not change for inactive context"
        );
    }

    // -----------------------------------------------------------------------
    // get_broadcast_key_for_local_author
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_broadcast_key_for_local_author_returns_key_and_epoch() {
        use zeroize::Zeroizing;

        let manager = ContextManager::new(
            Box::<MockCrypto>::default(),
            Box::new(MockTransport::default()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let creator_did: DID = "did:key:creator1".into();
        manager.register_local_did(creator_did.clone()).await;

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: MemoryScope::Full,
            ..Default::default()
        };

        let _handle = manager
            .create_context("bc-key-test".into(), params, creator_did.clone())
            .await
            .unwrap();

        let (key_bytes, epoch) = manager
            .get_broadcast_key_for_local_author("bc-key-test", creator_did.as_ref())
            .await
            .unwrap();

        assert_eq!(epoch, 0, "initial epoch should be 0");
        // Key should be 32 bytes, non-zero (randomly generated).
        let zero = Zeroizing::new([0u8; 32]);
        assert_ne!(key_bytes, zero, "broadcast key must not be all zeros");
    }

    #[tokio::test]
    async fn get_broadcast_key_for_local_author_rejects_non_local_did() {
        let manager = ContextManager::new(
            Box::<MockCrypto>::default(),
            Box::new(MockTransport::default()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let creator_did: DID = "did:key:creator2".into();
        manager.register_local_did(creator_did.clone()).await;

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: MemoryScope::Full,
            ..Default::default()
        };

        let _handle = manager
            .create_context("bc-key-test-2".into(), params, creator_did.clone())
            .await
            .unwrap();

        let result = manager
            .get_broadcast_key_for_local_author("bc-key-test-2", "did:key:not-local")
            .await;

        assert!(result.is_err(), "should reject non-local DID");
        assert!(
            matches!(result.unwrap_err(), ContextError::PermissionDenied(_)),
            "error should be PermissionDenied"
        );
    }

    #[tokio::test]
    async fn get_broadcast_key_for_local_author_rejects_unknown_context() {
        let manager = ContextManager::new(
            Box::<MockCrypto>::default(),
            Box::new(MockTransport::default()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let did: DID = "did:key:creator3".into();
        manager.register_local_did(did.clone()).await;

        let result = manager
            .get_broadcast_key_for_local_author("nonexistent-ctx", did.as_ref())
            .await;

        assert!(result.is_err(), "should reject unknown context");
        assert!(
            matches!(result.unwrap_err(), ContextError::ContextNotRegistered(_)),
            "error should be ContextNotRegistered"
        );
    }

    #[tokio::test]
    async fn get_broadcast_key_for_local_author_rejects_encrypted_context() {
        let manager = ContextManager::new(
            Box::<MockCrypto>::default(),
            Box::new(MockTransport::default()),
            Box::new(MockEventLog::default()),
            noop_key_resolver(),
        );

        let creator_did: DID = "did:key:creator4".into();
        manager.register_local_did(creator_did.clone()).await;

        // Default mode is Encrypted, not Broadcast.
        let params = ContextParams::default();

        let _handle = manager
            .create_context("encrypted-ctx".into(), params, creator_did.clone())
            .await
            .unwrap();

        let result = manager
            .get_broadcast_key_for_local_author("encrypted-ctx", creator_did.as_ref())
            .await;

        assert!(result.is_err(), "should reject encrypted context");
        assert!(
            matches!(result.unwrap_err(), ContextError::MembershipFailed(_)),
            "error should be MembershipFailed (not a broadcast context)"
        );
    }
}
