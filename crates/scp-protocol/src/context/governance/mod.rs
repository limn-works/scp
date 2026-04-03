//! Governance interface contract for SCP contexts (ADR-031).
//!
//! Every context declares a governance model at creation time. All governance
//! models implement the [`GovernanceEngine`] trait, which defines the
//! three-method contract: [`propose`](GovernanceEngine::propose),
//! [`approve`](GovernanceEngine::approve), and
//! [`reject`](GovernanceEngine::reject).
//!
//! Proposals follow a state machine lifecycle:
//! `Pending -> Approved | Rejected | Expired | Cancelled | Invalidated`.
//! The [`ProposalStatus`] enum encodes these states. Transitions are enforced
//! by the governance engine -- callers cannot set status directly.
//!
//! This module provides:
//!
//! - [`GovernanceEngine`] -- The pluggable governance trait (object-safe,
//!   `Send + Sync`).
//! - [`GovernanceAction`] -- Typed proposal variants covering role changes,
//!   membership changes, settings changes, ceiling expansion, and interface
//!   decisions per spec section 5.9.
//! - [`GovernanceProposal`] -- A proposal with lifecycle tracking.
//! - [`ProposalStatus`] -- The proposal state machine.
//! - [`GovernanceContext`] -- Read-only snapshot provided to the engine.
//! - [`GovernanceModelConfig`] -- Model selection enum set at context creation.
//! - [`SingleAdminEngine`] -- Phase 2 baseline: single-admin auto-approve.
//! - [`GovernanceEvent`] -- Events recorded in the Merkle log for auditability.
//! - [`multisig::ThresholdEngine`] -- M-of-N threshold governance (ADR-031 §4b).
//! - [`unanimity::UnanimityEngine`] -- Unanimity governance (ADR-031 §4d).
//!
//! # Exit-as-veto
//!
//! Per spec section 9.2.1, members can leave during a voting window as a form
//! of veto. The governance engine does not prevent departure -- it only tracks
//! votes. Departure handling (vote removal, quorum recalculation) is the
//! responsibility of the `ContextManager`.
//!
//! # Pluggability
//!
//! Different governance models implement the same [`GovernanceEngine`] trait.
//! The trait is object-safe for dynamic dispatch via `Box<dyn GovernanceEngine>`.
//! `ThresholdEngine` (Phase 6, ADR-031 §4b) is in [`multisig`].
//! `UnanimityEngine` (Phase 6, ADR-031 §4d) is in [`unanimity`].
//!
//! See ADR-031 in `.docs/adrs/phase-6.md` for the full specification.

pub mod majority;
pub mod mls_integration;
pub mod multisig;
pub mod unanimity;

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::params::{Capability, ContextParams, ToolRegistration};
use super::roles::ToolId;
use super::tools::interface::ToolInterface;
use crate::economy::types::{Amount, EconomicPolicy};
use scp_event_log::{ContextId, Ed25519Signature};
use scp_primitives::DID;

// ---------------------------------------------------------------------------
// KeyResolver
// ---------------------------------------------------------------------------

/// Resolves a voter's DID to their Ed25519 verifying key.
///
/// Governance engines use this to verify vote signatures against the voter's
/// actual public key (derived from their DID), rather than trusting the
/// signing key provided by the caller. This prevents forged votes where an
/// attacker supplies a valid DID but signs with a different key.
///
/// Returns `None` if the DID cannot be resolved (e.g., non-did:dht method
/// with no fallback, or unknown DID).
pub type KeyResolver = Arc<dyn Fn(&DID) -> Option<ed25519_dalek::VerifyingKey> + Send + Sync>;

// ---------------------------------------------------------------------------
// ProposalId
// ---------------------------------------------------------------------------

/// Unique identifier for a governance proposal.
///
/// Computed as `SHA-256("SCP-PROPOSAL-V1:" || len(context_id) || context_id
///   || len(proposer_did) || proposer_did || len(action_bytes) || action_bytes
///   || timestamp_BE)`.
/// Variable-length fields are prefixed with their length as a 4-byte big-endian
/// u32 to prevent field-boundary ambiguity. The domain separator prevents
/// cross-protocol hash confusion.
/// Deterministic for identical inputs, collision-resistant across contexts.
pub type ProposalId = [u8; 32];

/// Compute a deterministic proposal ID from its components.
///
/// Uses SHA-256 with a domain separator and length-prefixed variable-length
/// fields. Fixed-width fields (timestamp) need no prefix.
///
/// **Canonicalization:** The `action_bytes` parameter MUST be produced by
/// RFC 8785 JCS (via `crate::jcs::to_vec`). JCS is used — not
/// `MessagePack` — because `GovernanceAction` is a complex enum whose
/// serialized form must be deterministic across all SDK implementations
/// (Rust, Python, TypeScript, Kotlin, Swift). `MessagePack` has no canonical
/// form standard. This is consistent with all other cross-implementation
/// canonical hashing in the protocol: handle tool signing (§22), app
/// declarations (§8), DID documents (§18), and
/// `ParentGovernanceConfig::content_hash()` in nesting.rs. See §9.5.2.
#[must_use]
pub fn compute_proposal_id(
    context_id: &str,
    proposer_did: &DID,
    action_bytes: &[u8],
    timestamp: u64,
) -> ProposalId {
    let mut hasher = Sha256::new();
    hasher.update(b"SCP-PROPOSAL-V1:");
    // Length-prefix closure for variable-length fields. Field values (DIDs,
    // context IDs) are short strings; truncation is not a concern.
    #[allow(clippy::cast_possible_truncation)]
    let length_prefix = |hasher: &mut Sha256, bytes: &[u8]| {
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    };
    length_prefix(&mut hasher, context_id.as_bytes());
    length_prefix(&mut hasher, proposer_did.as_ref().as_bytes());
    length_prefix(&mut hasher, action_bytes);
    hasher.update(timestamp.to_be_bytes());
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

// ---------------------------------------------------------------------------
// Vote signing
// ---------------------------------------------------------------------------

/// Domain separator prepended to the vote hash input to prevent
/// cross-protocol signature confusion. Because the same Ed25519 key may be
/// used for multiple signing purposes (envelope, UCAN, DID auth, votes),
/// a unique prefix ensures that a signature produced for one purpose can
/// never be replayed as valid in another.
const VOTE_DOMAIN_SEPARATOR: &[u8] = b"SCP-VOTE-V1:";

/// Computes the canonical hash over vote fields for signing.
///
/// Uses SHA-256 with a domain separator and length-prefixed fields:
/// ```text
/// SHA-256(VOTE_DOMAIN_SEPARATOR
///         || proposal_id (32 bytes, fixed-length)
///         || len(voter_did) as u32 BE || voter_did
///         || len(vote_json) as u32 BE || vote_json
///         || timestamp BE)
/// ```
///
/// `proposal_id` is included first (after the domain separator) to bind
/// the vote signature to a specific proposal, preventing cross-proposal
/// replay attacks.
///
/// Length prefixes prevent ambiguity when concatenating variable-length fields.
#[allow(clippy::similar_names)] // voter_did_bytes vs vote_type_bytes are semantically distinct
fn compute_vote_hash(
    proposal_id: &ProposalId,
    voter_did: &str,
    vote: &VoteType,
    timestamp: u64,
) -> Result<Vec<u8>, GovernanceError> {
    // RFC 8785 JCS canonical serialization for cross-implementation
    // deterministic vote hashing (§9.5.2). Both vote_type and action_bytes
    // (in compute_proposal_id) use JCS — not MessagePack — for canonical
    // hashing. See compute_proposal_id() doc comment for full rationale.
    let vote_type_bytes = crate::jcs::to_vec(vote).map_err(GovernanceError::SerializationFailed)?;

    let voter_did_bytes = voter_did.as_bytes();

    let mut hasher = Sha256::new();
    hasher.update(VOTE_DOMAIN_SEPARATOR);
    // Proposal ID (32-byte SHA-256 hash, fixed-length — no length prefix needed).
    hasher.update(proposal_id);
    // Length-prefixed voter DID.
    #[allow(clippy::cast_possible_truncation)] // DID strings are always < 4 GiB
    let voter_len = voter_did_bytes.len() as u32;
    hasher.update(voter_len.to_be_bytes());
    hasher.update(voter_did_bytes);
    // Length-prefixed vote type.
    #[allow(clippy::cast_possible_truncation)] // serialized VoteType is a few bytes
    let vote_len = vote_type_bytes.len() as u32;
    hasher.update(vote_len.to_be_bytes());
    hasher.update(&vote_type_bytes);
    // Timestamp.
    hasher.update(timestamp.to_be_bytes());
    Ok(hasher.finalize().to_vec())
}

/// Creates a signed vote with a real Ed25519 signature.
///
/// Computes a canonical hash over `(proposal_id, voter_did, vote, timestamp)`
/// with a `SCP-VOTE-V1:` domain separator and length-prefixed fields, then
/// signs it with the provided Ed25519 signing key. The `proposal_id` binds
/// the signature to a specific proposal, preventing cross-proposal replay.
///
/// # Errors
///
/// Returns [`GovernanceError::SerializationFailed`] if the vote type cannot
/// be serialized.
pub fn sign_vote(
    proposal_id: &ProposalId,
    vote: &VoteType,
    voter_did: &str,
    timestamp: u64,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<SignedVote, GovernanceError> {
    let hash = compute_vote_hash(proposal_id, voter_did, vote, timestamp)?;
    let signature = signing_key.sign(&hash);

    Ok(SignedVote {
        voter_did: DID::from(voter_did),
        vote: vote.clone(),
        timestamp,
        signature: signature.to_bytes().to_vec(),
    })
}

/// Verifies the Ed25519 signature on a signed vote.
///
/// Recomputes the canonical hash from the vote's fields using the same
/// domain separator and layout as [`sign_vote`], then verifies the
/// signature against the provided public key.
///
/// # Errors
///
/// Returns [`GovernanceError::VerificationFailed`] if:
/// - The signature bytes are not exactly 64 bytes.
/// - The signature does not match the recomputed hash.
/// - The vote type cannot be serialized for hash recomputation.
pub fn verify_vote(
    proposal_id: &ProposalId,
    vote: &SignedVote,
    voter_public_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), GovernanceError> {
    let hash = compute_vote_hash(
        proposal_id,
        vote.voter_did.as_ref(),
        &vote.vote,
        vote.timestamp,
    )?;

    let sig_bytes: [u8; 64] = vote.signature.as_slice().try_into().map_err(|_| {
        GovernanceError::VerificationFailed(format!(
            "signature must be 64 bytes, got {}",
            vote.signature.len()
        ))
    })?;

    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    voter_public_key
        .verify_strict(&hash, &signature)
        .map_err(|e| GovernanceError::VerificationFailed(e.to_string()))
}

/// Verifies all vote signatures in a governance proposal.
///
/// Checks every vote in the proposal's `approvals` and `rejections` lists
/// against the corresponding voter's public key. This function should be
/// called after deserializing a proposal from untrusted input (persistence
/// or network sync) to ensure that no vote signatures have been tampered
/// with.
///
/// The `key_resolver` closure maps a voter's DID to their Ed25519 verifying
/// key. If a voter's key cannot be resolved, that vote is treated as
/// unverifiable and an error is returned.
///
/// # Errors
///
/// Returns [`GovernanceError::VerificationFailed`] if any vote signature is
/// invalid, or if a voter's public key cannot be resolved.
pub fn verify_proposal_votes<F>(
    proposal: &GovernanceProposal,
    key_resolver: F,
) -> Result<(), GovernanceError>
where
    F: Fn(&DID) -> Option<ed25519_dalek::VerifyingKey>,
{
    for vote in &proposal.approvals {
        let vk = key_resolver(&vote.voter_did).ok_or_else(|| {
            GovernanceError::VerificationFailed(format!(
                "cannot resolve public key for voter {}",
                vote.voter_did
            ))
        })?;
        verify_vote(&proposal.proposal_id, vote, &vk)?;
    }

    for vote in &proposal.rejections {
        let vk = key_resolver(&vote.voter_did).ok_or_else(|| {
            GovernanceError::VerificationFailed(format!(
                "cannot resolve public key for voter {}",
                vote.voter_did
            ))
        })?;
        verify_vote(&proposal.proposal_id, vote, &vk)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// GovernanceAction
// ---------------------------------------------------------------------------

/// Scope of cryptographic access revocation (§5.9, ADR-031).
///
/// Determines whether revocation targets read access, write access, or both.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessScope {
    /// Revoke read access only.
    Read,
    /// Revoke write access only.
    Write,
    /// Revoke both read and write access.
    Both,
}

// ---------------------------------------------------------------------------
// PruningPolicy (ADR-030 §6)
// ---------------------------------------------------------------------------

/// Time-based pruning configuration (ADR-030 §2a).
///
/// Protocol minimum: 30 days (2,592,000 seconds). Contexts may set higher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeBasedPolicy {
    /// Minimum age (seconds) before an event becomes prunable.
    pub retention_secs: u64,
}

/// Size-based pruning configuration (ADR-030 §2b).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizeBasedPolicy {
    /// Maximum number of events to retain locally.
    pub max_event_count: u64,
    /// Maximum total storage bytes for event log data.
    pub max_storage_bytes: u64,
}

/// Event-type retention multipliers (ADR-030 §2c).
///
/// Structural events (governance, membership) are retained longer than
/// operational events (messages, tool invocations).
///
/// Multipliers are expressed in basis points where 10000 = 1.0x multiplier.
/// E.g. 30000 = 3.0x.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventTypeRetention {
    /// Basis points where 10000 = 1.0x multiplier. E.g. 30000 = 3.0x.
    /// Default: 30000 (3.0x).
    pub structural_retention_multiplier: u32,
    /// Basis points where 10000 = 1.0x multiplier. E.g. 30000 = 3.0x.
    /// Default: 10000 (1.0x).
    pub operational_retention_multiplier: u32,
}

/// Checkpoint creation schedule (ADR-030 §3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointSchedule {
    /// Create a checkpoint every N events. Default: 10,000.
    pub event_interval: u64,
    /// Create a checkpoint every N seconds. Default: 86,400 (24 hours).
    pub time_interval_secs: u64,
    /// Minimum events since last checkpoint before a new one is created.
    /// Default: 100.
    pub min_events_since_last: u64,
}

// ---------------------------------------------------------------------------
// Checkpoint cosignature types (ADR-031 §9)
// ---------------------------------------------------------------------------

/// A cosigned checkpoint from a governance quorum member (ADR-031 §9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CosignedCheckpoint {
    /// The DID of the signer.
    pub signer_did: DID,
    /// Ed25519 signature over the checkpoint hash (64 bytes).
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Attestation status for a checkpoint (ADR-031 §9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckpointAttestationStatus {
    /// Checkpoint has full governance quorum cosignatures.
    FullyAttested,
    /// Checkpoint valid with creator's signature only (insufficient cosignatures).
    PartiallyAttested,
}

/// Context checkpoint with governance cosignatures (ADR-031 §9, ADR-030 §1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextCheckpoint {
    /// Sequence number in the event log.
    pub checkpoint_seq: u64,
    /// Merkle root at this sequence number.
    pub merkle_root: [u8; 32],
    /// Number of events included in this checkpoint.
    pub event_count: u64,
    /// Hash of the last event before this checkpoint.
    pub last_event_hash: [u8; 32],
    /// Deterministic hash of the context state snapshot.
    pub state_snapshot_hash: [u8; 32],
    /// Timestamp when checkpoint was created.
    pub created_at: u64,
    /// Creator's DID and signature.
    pub creator_did: DID,
    /// Creator's Ed25519 signature over checkpoint data (64 bytes).
    #[serde(with = "serde_bytes")]
    pub creator_signature: Vec<u8>,
    /// Governance quorum cosignatures (ADR-031 §9).
    /// Empty for `SingleAdmin` contexts, populated for multi-admin contexts.
    pub cosignatures: Vec<CosignedCheckpoint>,
    /// Attestation status based on cosignature quorum.
    pub attestation_status: CheckpointAttestationStatus,
}

/// Pruning policy for a context's event log (ADR-030 §6).
///
/// Set at context creation or modified via governance. Included in
/// publicly visible metadata (§5.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruningPolicy {
    /// Time-based pruning. `None` = no time-based pruning.
    pub time_based: Option<TimeBasedPolicy>,
    /// Size-based pruning. `None` = no size-based pruning.
    pub size_based: Option<SizeBasedPolicy>,
    /// Event-type retention multipliers.
    pub event_type_retention: EventTypeRetention,
    /// Checkpoint creation schedule.
    pub checkpoint_schedule: CheckpointSchedule,
    /// Whether members may request full log history from peers.
    pub allow_full_history_requests: bool,
}

impl Default for PruningPolicy {
    fn default() -> Self {
        Self {
            time_based: None,
            size_based: None,
            event_type_retention: EventTypeRetention {
                structural_retention_multiplier: 30_000,
                operational_retention_multiplier: 10_000,
            },
            checkpoint_schedule: CheckpointSchedule {
                event_interval: 10_000,
                time_interval_secs: 86_400,
                min_events_since_last: 100,
            },
            allow_full_history_requests: true,
        }
    }
}

// ---------------------------------------------------------------------------
// ConflictResolution (ADR-031 §7)
// ---------------------------------------------------------------------------

/// Governance-level conflict resolution for simultaneous-commit scenarios
/// (ADR-031 §7).
///
/// When two conflicting proposals land at the same event log sequence,
/// governance enters a freeze. A `ResolveConflict` action with this payload
/// specifies how to lift the freeze.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConflictResolution {
    /// Accept one proposal, invalidate the other.
    AcceptProposal {
        /// The winning proposal ID.
        winner_id: ProposalId,
    },
    /// Invalidate both proposals, return to pre-proposal state.
    InvalidateBoth,
}

// ---------------------------------------------------------------------------
// Deadlock recovery types (ADR-031 §10)
// ---------------------------------------------------------------------------

/// Actions that can be taken during deadlock recovery (ADR-031 §10).
///
/// These modify governance parameters without changing the model type.
/// Used by `ReconfigureGovernance`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceReconfigAction {
    /// Remove an inactive signer (Threshold model).
    RemoveInactiveSigner {
        /// The DID of the inactive signer.
        did: DID,
    },
    /// Reduce the threshold (Threshold model). New value must be
    /// >= 1 and <= remaining active signers.
    ReduceThreshold {
        /// The new threshold value.
        new_threshold: u32,
    },
}

/// Justification for a deadlock recovery action (ADR-031 §10).
///
/// Attached to `ReconfigureGovernance` to record evidence of deadlock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadlockJustification {
    /// DIDs that are unavailable.
    pub unavailable_dids: Vec<DID>,
    /// Evidence of unavailability: (DID, consecutive missed voting windows).
    pub missed_windows: Vec<(DID, u32)>,
    /// Timestamp of deadlock detection (Unix seconds).
    pub detected_at: u64,
}

// ---------------------------------------------------------------------------
// GovernanceAction
// ---------------------------------------------------------------------------

/// Typed governance actions (ADR-031 §2). Every governance change is one of
/// these variants.
///
/// The governance engine evaluates proposals containing these actions. This
/// covers: membership, roles, settings, ceiling, content access, tool
/// interfaces, pruning, conflict resolution, and deadlock recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceAction {
    /// Add a member to the context with a specified role.
    AddMember {
        /// The DID of the member to add.
        did: DID,
        /// The role to assign to the new member.
        role: String,
    },
    /// MLS ejection — irreversible, governance only.
    Eject {
        /// The DID of the member to eject.
        did: DID,
        /// Optional reason for ejection.
        reason: Option<String>,
    },
    /// Change a member's role.
    ChangeRole {
        /// The DID of the member whose role is changing.
        did: DID,
        /// The new role to assign.
        new_role: String,
    },
    /// Register a new tool in the context.
    RegisterTool {
        /// The full tool registration descriptor.
        registration: Box<ToolRegistration>,
    },
    /// Remove a tool from the context.
    RemoveTool {
        /// The identifier of the tool to remove.
        tool_id: ToolId,
    },
    /// Modify the capability ceiling (only if `ceiling_policy` is `Governed`).
    ModifyCeiling {
        /// The new capability ceiling to apply.
        new_ceiling: Vec<Capability>,
    },
    /// Close the context.
    CloseContext {
        /// Optional reason for closure.
        reason: Option<String>,
    },
    /// Extend context TTL (requires unanimous consent per spec section 5.10).
    ExtendTtl {
        /// Additional seconds to add to the context TTL.
        additional_secs: u64,
    },
    /// Transfer single-admin authority (`SingleAdmin` model only).
    TransferAdmin {
        /// The DID of the new admin.
        new_admin: DID,
    },
    /// Create a child context (spec section 5.13).
    CreateChildContext {
        /// The parameters for the child context.
        params: Box<ContextParams>,
    },
    /// Suspend specific capabilities for a member (application-level gate block).
    SuspendMember {
        /// The DID of the member whose capabilities are suspended.
        did: DID,
        /// The capabilities to suspend.
        capabilities: Vec<Capability>,
    },
    /// Cryptographic revocation — destroy keys. Forward-restore only.
    Revoke {
        /// The DID whose access is revoked.
        did: DID,
        /// The scope of access to revoke (read, write, or both).
        access: AccessScope,
    },
    /// Restore suspended capabilities or forward-restore after revocation.
    RestoreAccess {
        /// The DID whose access is restored.
        did: DID,
        /// The capabilities to restore.
        capabilities: Vec<Capability>,
    },
    /// Modify the context's event log pruning policy (ADR-030 §6).
    ModifyPruningPolicy {
        /// The new pruning policy to apply.
        new_policy: PruningPolicy,
    },
    /// Add a signer to the threshold set (Threshold model only, ADR-031 §4b).
    AddSigner {
        /// The DID of the new signer.
        did: DID,
    },
    /// Remove a signer from the threshold set (Threshold model only, ADR-031 §4b).
    RemoveSigner {
        /// The DID of the signer to remove.
        did: DID,
    },
    /// Modify the threshold value (Threshold model only, ADR-031 §4b).
    ///
    /// New value must be >= 1 and <= the number of signers.
    ModifyThreshold {
        /// The new threshold value.
        new_threshold: u32,
    },
    /// Establish a tool interface with another context (§6.2).
    EstablishToolInterface {
        /// The tool interface to establish.
        interface: ToolInterface,
    },
    /// Governance-triggered member reset (ADR-029, Tier 3).
    ///
    /// Forces a group state reset for the target member. Invalidates any
    /// pending proposals. The member must re-sync after the reset.
    ResetMember {
        /// The DID of the member to reset.
        did: DID,
        /// Reason for the reset.
        reason: String,
    },
    /// Resolve a governance conflict (ADR-031 §7).
    ///
    /// Used when two conflicting proposals land at the same event log
    /// sequence. Exempt from governance freeze — this is the designated
    /// mechanism for lifting the freeze.
    ResolveConflict {
        /// The first conflicting proposal ID.
        proposal_a: ProposalId,
        /// The second conflicting proposal ID.
        proposal_b: ProposalId,
        /// How to resolve the conflict.
        resolution: ConflictResolution,
    },
    /// Promote a context from ephemeral to persistent (§5.10).
    ///
    /// Requires unanimous consent from ALL current members regardless of
    /// governance model — protocol-level override enforced by
    /// `ContextManager`.
    PromoteContext,
    /// Context-wide content key rotation (§9.17, ADR-038).
    ///
    /// Not DID-targeted — rotates keys for all members. Use after compromise
    /// detection, bulk revocations, or periodic key hygiene.
    RotateContentKeys {
        /// Optional reason for the rotation.
        reason: Option<String>,
    },
    /// Deadlock recovery: modify governance parameters without changing model
    /// type (ADR-031 §10).
    ///
    /// Uses fallback quorum (majority-of-active) regardless of original
    /// governance model. 48-hour voting window.
    ReconfigureGovernance {
        /// The reconfiguration actions to apply.
        changes: Vec<GovernanceReconfigAction>,
        /// Justification for the deadlock recovery.
        justification: DeadlockJustification,
    },
    /// Set or update the context's economic policy (§19.3, ADR-033).
    ///
    /// Requires the economic policy to not be locked. If the new policy has
    /// `locked: true`, the policy becomes immutable after this action.
    SetEconomicPolicy {
        /// The new economic policy to apply.
        policy: EconomicPolicy,
    },
    /// Approve a spending authorization for a member (§19.5, ADR-033).
    ///
    /// Grants the specified member permission to spend up to `amount` in the
    /// context's currency. The `purpose` field documents the reason for the
    /// spend authorization.
    ApproveSpend {
        /// The DID of the member authorized to spend.
        spender: DID,
        /// The maximum amount authorized.
        amount: Amount,
        /// Human-readable purpose for the spending authorization.
        purpose: String,
    },
    /// Lock the context's economic policy, making it immutable (§19.3).
    ///
    /// Once locked, the economic policy cannot be changed through governance.
    /// The lock is itself immutable: once set, it cannot be reverted.
    /// Requires an economic policy to already be set on the context.
    LockEconomicPolicy,
    /// Propose migrating this context to a new destination context (§5.11A).
    ///
    /// On approval, the source context enters a read-only grace period.
    /// If `auto_invite` is true, the initiating admin sends bulk invitations
    /// to all current members. Members accept or decline individually.
    ProposeContextMigration {
        /// Parameters for the destination context.
        new_context_params: Box<ContextParams>,
        /// Human-readable migration rationale.
        reason: String,
        /// Grace period duration in seconds. RECOMMENDED: 604,800 (7 days).
        grace_period_secs: u64,
        /// Whether to bulk-invite all current members to the destination.
        auto_invite: bool,
    },
    /// Cancel an in-progress context migration (§5.11A).
    ///
    /// Only valid while the source context is in `MigratingOut` state
    /// (during the grace period). Returns the context to `Active`.
    CancelContextMigration,
}

impl GovernanceAction {
    /// Returns the variant name as a static string for logging and event summaries.
    #[must_use]
    pub const fn variant_name(&self) -> &'static str {
        match self {
            Self::AddMember { .. } => "AddMember",
            Self::Eject { .. } => "Eject",
            Self::ChangeRole { .. } => "ChangeRole",
            Self::RegisterTool { .. } => "RegisterTool",
            Self::RemoveTool { .. } => "RemoveTool",
            Self::ModifyCeiling { .. } => "ModifyCeiling",
            Self::CloseContext { .. } => "CloseContext",
            Self::ExtendTtl { .. } => "ExtendTtl",
            Self::TransferAdmin { .. } => "TransferAdmin",
            Self::CreateChildContext { .. } => "CreateChildContext",
            Self::SuspendMember { .. } => "SuspendMember",
            Self::Revoke { .. } => "Revoke",
            Self::RestoreAccess { .. } => "RestoreAccess",
            Self::ModifyPruningPolicy { .. } => "ModifyPruningPolicy",
            Self::AddSigner { .. } => "AddSigner",
            Self::RemoveSigner { .. } => "RemoveSigner",
            Self::ModifyThreshold { .. } => "ModifyThreshold",
            Self::EstablishToolInterface { .. } => "EstablishToolInterface",
            Self::ResetMember { .. } => "ResetMember",
            Self::ResolveConflict { .. } => "ResolveConflict",
            Self::PromoteContext => "PromoteContext",
            Self::RotateContentKeys { .. } => "RotateContentKeys",
            Self::ReconfigureGovernance { .. } => "ReconfigureGovernance",
            Self::SetEconomicPolicy { .. } => "SetEconomicPolicy",
            Self::ApproveSpend { .. } => "ApproveSpend",
            Self::LockEconomicPolicy => "LockEconomicPolicy",
            Self::ProposeContextMigration { .. } => "ProposeContextMigration",
            Self::CancelContextMigration => "CancelContextMigration",
        }
    }

    /// Returns the target DID for actions that operate on a specific member.
    ///
    /// This is used to populate structured event payloads so that consequence
    /// triggers (e.g., `WarningCount`) and participation records can identify
    /// who was targeted by a governance action without relying on opaque
    /// byte-level payload conventions.
    #[must_use]
    pub const fn target_did(&self) -> Option<&DID> {
        match self {
            Self::AddMember { did, .. }
            | Self::Eject { did, .. }
            | Self::ChangeRole { did, .. }
            | Self::SuspendMember { did, .. }
            | Self::Revoke { did, .. }
            | Self::RestoreAccess { did, .. }
            | Self::ResetMember { did, .. }
            | Self::AddSigner { did }
            | Self::RemoveSigner { did } => Some(did),
            Self::TransferAdmin { new_admin } => Some(new_admin),
            Self::ApproveSpend { spender, .. } => Some(spender),
            Self::RegisterTool { .. }
            | Self::RemoveTool { .. }
            | Self::ModifyCeiling { .. }
            | Self::CloseContext { .. }
            | Self::ExtendTtl { .. }
            | Self::CreateChildContext { .. }
            | Self::ModifyPruningPolicy { .. }
            | Self::ModifyThreshold { .. }
            | Self::EstablishToolInterface { .. }
            | Self::ResolveConflict { .. }
            | Self::PromoteContext
            | Self::RotateContentKeys { .. }
            | Self::ReconfigureGovernance { .. }
            | Self::SetEconomicPolicy { .. }
            | Self::LockEconomicPolicy
            | Self::ProposeContextMigration { .. }
            | Self::CancelContextMigration => None,
        }
    }
}

// ---------------------------------------------------------------------------
// VoteType / SignedVote
// ---------------------------------------------------------------------------

/// The type of vote cast on a proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteType {
    /// Approval vote.
    Approve,
    /// Rejection vote.
    Reject,
}

/// A signed vote on a governance proposal.
///
/// Each vote records who voted, what they voted, when, and their Ed25519
/// signature over the vote content for verifiability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedVote {
    /// The DID of the voter.
    pub voter_did: DID,
    /// The vote type (approve or reject).
    pub vote: VoteType,
    /// Unix timestamp (seconds) when the vote was cast.
    pub timestamp: u64,
    /// Ed25519 signature over the vote content.
    pub signature: Ed25519Signature,
}

// ---------------------------------------------------------------------------
// RejectionReason
// ---------------------------------------------------------------------------

/// Reason a proposal was rejected.
///
/// Different governance models produce different rejection reasons. The
/// single-admin model uses `AdminRejected`. Multi-admin models use the
/// model-specific variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectionReason {
    /// The single admin explicitly rejected (`SingleAdmin` model).
    AdminRejected,
    /// Majority of voters rejected (Majority model).
    MajorityRejected,
    /// Any single voter rejected (Unanimity model).
    UnanimityBroken {
        /// The DID of the voter who broke unanimity.
        rejector: DID,
    },
    /// Threshold of rejections reached, making approval impossible
    /// (Threshold model: rejections > signers - threshold).
    ApprovalImpossible,
    /// Insufficient participation within voting window (Majority model).
    InsufficientParticipation,
}

// ---------------------------------------------------------------------------
// ProposalStatus
// ---------------------------------------------------------------------------

/// The lifecycle status of a governance proposal.
///
/// State machine: `Pending -> Approved | Rejected | Expired | Cancelled | Invalidated`.
/// Only `Pending` proposals accept votes. All other states are terminal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    /// Proposal is open for voting.
    Pending,
    /// Proposal reached quorum and was approved. The action will be executed.
    Approved,
    /// Proposal was rejected (explicit rejection or failed to reach quorum).
    Rejected {
        /// The specific reason the proposal was rejected.
        reason: RejectionReason,
    },
    /// Proposal expired before reaching quorum.
    Expired,
    /// Proposal was cancelled by the proposer before resolution.
    Cancelled,
    /// Proposal was invalidated (e.g., epoch reset, proposer removed).
    Invalidated {
        /// Human-readable reason for invalidation.
        reason: String,
    },
}

impl ProposalStatus {
    /// Returns `true` if the proposal is still accepting votes.
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Returns `true` if the proposal has reached a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        !self.is_pending()
    }
}

// ---------------------------------------------------------------------------
// GovernanceProposal
// ---------------------------------------------------------------------------

/// A governance proposal with full lifecycle tracking.
///
/// Created by [`GovernanceEngine::propose`], stored in the event log and in
/// the protocol repository for active tracking. The proposal tracks all votes and
/// the current status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceProposal {
    /// Unique proposal identifier (SHA-256 of components).
    pub proposal_id: ProposalId,
    /// The context this proposal belongs to.
    pub context_id: ContextId,
    /// The DID of the proposer.
    pub proposer_did: DID,
    /// The governance action being proposed.
    pub action: GovernanceAction,
    /// Current lifecycle status.
    ///
    /// **Invariant:** When `status` is [`ProposalStatus::Approved`], all vote
    /// signatures in [`approvals`](Self::approvals) have been cryptographically
    /// verified against the voter's DID-resolved public key via the engine's
    /// [`KeyResolver`]. Code that receives an `Approved` proposal can trust
    /// that every approval vote is authentic — no further signature checks
    /// are needed.
    pub status: ProposalStatus,
    /// Unix timestamp (seconds) when the proposal was created.
    pub created_at: u64,
    /// Unix timestamp (seconds) after which the proposal expires.
    pub voting_deadline: u64,
    /// Approval votes collected so far.
    pub approvals: Vec<SignedVote>,
    /// Rejection votes collected so far.
    pub rejections: Vec<SignedVote>,
    /// MLS epoch at which the proposal was created. Proposals are valid only
    /// for the epoch in which they were created and subsequent epochs. If the
    /// group resets (ADR-029 Tier 3), pending proposals are invalidated.
    pub created_at_epoch: Option<u64>,
}

// ---------------------------------------------------------------------------
// GovernanceModelConfig
// ---------------------------------------------------------------------------

/// Governance model selection. Set at context creation, immutable thereafter.
///
/// Included in context metadata (spec section 5.7) -- visible before opt-in.
/// Changing the governance model requires creating a new context.
///
/// Uses `u32` basis points for `min_participation_bps` (ADR-031) so this
/// type derives `Eq`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GovernanceModelConfig {
    /// Single admin holds all governance authority. Phase 2 baseline.
    /// The creator is the initial (and only) admin. Admin transfer is
    /// a governance action that replaces the admin DID.
    SingleAdmin {
        /// The DID of the sole administrator.
        admin_did: DID,
    },

    /// M-of-N threshold approval. A fixed set of designated signers;
    /// a proposal passes when at least `threshold` of them approve.
    Threshold {
        /// The set of DIDs authorized to vote.
        signers: Vec<DID>,
        /// Minimum number of approvals required (`1 <= threshold <= signers.len()`).
        threshold: u32,
        /// Voting window in seconds. Default: `86_400` (24 hours).
        voting_window_secs: u64,
    },

    /// Majority vote among all context members holding `GovernanceVote`
    /// capability. Proposal passes when approvals > 50% of eligible voters.
    Majority {
        /// Voting window in seconds. Default: `86_400` (24 hours).
        voting_window_secs: u64,
        /// Minimum participation in basis points (1–10000, where 10000 = 100%).
        /// Default: `5000` (50%). Per ADR-031.
        min_participation_bps: u32,
    },

    /// Unanimity among all context members holding `GovernanceVote`
    /// capability. Every eligible voter must approve. A single rejection
    /// defeats the proposal immediately.
    Unanimity {
        /// Voting window in seconds. Default: `172_800` (48 hours).
        voting_window_secs: u64,
    },
}

// ---------------------------------------------------------------------------
// GovernanceContext
// ---------------------------------------------------------------------------

/// Read-only context snapshot provided to the governance engine.
///
/// The engine never mutates context state directly -- it returns decisions
/// that the `ContextManager` executes.
#[derive(Debug, Clone)]
pub struct GovernanceContext {
    /// The context identifier.
    pub context_id: ContextId,
    /// Current members and their role names.
    pub members: Vec<(DID, String)>,
    /// DIDs currently holding admin authority.
    pub admin_dids: Vec<DID>,
    /// Current MLS epoch, if applicable.
    pub current_epoch: Option<u64>,
    /// Current unix timestamp (seconds).
    pub now: u64,
}

// ---------------------------------------------------------------------------
// GovernanceError
// ---------------------------------------------------------------------------

/// Errors produced by governance operations.
#[derive(Debug, thiserror::Error)]
pub enum GovernanceError {
    /// The proposer is not the admin (`SingleAdmin` model).
    #[error("proposer is not the admin")]
    NotAdmin,

    /// The voter is not eligible to vote on this proposal.
    #[error("voter is not eligible: {0}")]
    NotEligible(String),

    /// The proposal was not found.
    #[error("proposal not found: {id}")]
    ProposalNotFound {
        /// Hex-encoded proposal ID.
        id: String,
    },

    /// The proposal is not in a state that accepts votes.
    #[error("proposal is not pending (current status: {status})")]
    ProposalNotPending {
        /// Human-readable current status.
        status: String,
    },

    /// The voter has already voted on this proposal.
    #[error("voter has already voted on this proposal")]
    AlreadyVoted,

    /// Serialization of the governance action failed.
    #[error("serialization failed: {0}")]
    SerializationFailed(String),

    /// A proposal with this ID already exists.
    #[error("duplicate proposal: {0}")]
    DuplicateProposal(String),

    /// The governance model configuration is invalid.
    #[error("invalid governance config: {0}")]
    InvalidConfig(String),

    /// The voting window has expired for this proposal.
    #[error("voting window has expired for proposal: {id}")]
    VotingWindowExpired {
        /// Hex-encoded proposal ID.
        id: String,
    },

    /// The requested operation is not supported by this governance model.
    #[error("operation not supported: {0}")]
    OperationNotSupported(String),

    /// Vote signing failed.
    #[error("vote signing failed: {0}")]
    SigningFailed(String),

    /// Vote signature verification failed.
    #[error("vote verification failed: {0}")]
    VerificationFailed(String),

    /// A vote signature failed cryptographic verification against the voter's
    /// DID-resolved public key.
    ///
    /// This means the signature was not produced by the key associated with
    /// the claimed voter DID — the vote is forged or corrupted.
    #[error("invalid vote signature: voter {voter_did} on proposal {proposal_id}")]
    InvalidSignature {
        /// The DID of the voter whose signature failed verification.
        voter_did: String,
        /// Hex-encoded proposal ID the vote was for.
        proposal_id: String,
    },

    /// The voter's DID could not be resolved to a public key.
    ///
    /// The key resolver returned `None` for this DID, meaning the voter's
    /// identity cannot be verified. The vote is rejected.
    #[error("unknown voter: cannot resolve public key for DID {did}")]
    UnknownVoter {
        /// The unresolvable DID.
        did: String,
    },
}

// ---------------------------------------------------------------------------
// GovernanceEvent
// ---------------------------------------------------------------------------

/// Events emitted by governance operations for recording in the Merkle log.
///
/// Every governance action produces one or more events that are appended to
/// the context's event log, providing a complete audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceEvent {
    /// A new proposal was created.
    ProposalCreated {
        /// Unique identifier for the proposal.
        proposal_id: ProposalId,
        /// The DID of the member who proposed the action.
        proposer_did: DID,
        /// The governance action being proposed.
        action: Box<GovernanceAction>,
        /// Unix timestamp (seconds) when voting closes.
        voting_deadline: u64,
    },
    /// A vote was cast on a proposal.
    VoteCast {
        /// The proposal being voted on.
        proposal_id: ProposalId,
        /// The DID of the voter.
        voter_did: DID,
        /// Whether the vote is an approval or rejection.
        vote: VoteType,
    },
    /// A vote was withdrawn from a proposal.
    VoteWithdrawn {
        /// The proposal from which the vote was withdrawn.
        proposal_id: ProposalId,
        /// The DID of the voter who withdrew.
        voter_did: DID,
    },
    /// A proposal was resolved (approved, rejected, expired, etc.).
    ProposalResolved {
        /// The proposal that was resolved.
        proposal_id: ProposalId,
        /// The terminal status the proposal reached.
        status: ProposalStatus,
    },
    /// Deadlock recovery was triggered (ADR-031 §10).
    ///
    /// Logged when a `ReconfigureGovernance` proposal is approved via
    /// fallback quorum (majority-of-active). Records the justification
    /// and the governance parameter changes applied.
    DeadlockRecovery {
        /// The justification for triggering deadlock recovery.
        justification: DeadlockJustification,
        /// The governance parameter changes applied.
        changes: Vec<GovernanceReconfigAction>,
    },
    /// A simultaneous governance conflict was detected (ADR-031 §7).
    ///
    /// Logged when two conflicting proposals land at the same event log
    /// sequence, triggering a governance freeze state.
    ConflictDetected {
        /// The first conflicting proposal.
        proposal_a: ProposalId,
        /// The second conflicting proposal.
        proposal_b: ProposalId,
    },
    /// A governance conflict was resolved (ADR-031 §7).
    ///
    /// Logged when a sequential conflict is resolved (lower sequence wins)
    /// or when a `ResolveConflict` action is executed.
    ConflictResolved {
        /// The proposal that won the conflict.
        winner_id: ProposalId,
        /// The proposal that lost the conflict.
        loser_id: ProposalId,
    },
    /// A governance action was successfully executed (ADR-031 §8).
    ///
    /// Emitted after every successful governance action execution in
    /// `execute_governance_action`. Records the proposal ID, the action
    /// that was executed, the DID of the executor (proposer), and the
    /// resulting MLS epoch (if applicable). This is the 8th governance
    /// event type per PRD SCP-269/SCP-270.
    GovernanceActionExecuted {
        /// The proposal that was executed.
        proposal_id: ProposalId,
        /// The governance action that was executed.
        action: Box<GovernanceAction>,
        /// The DID of the executor (proposer of the approved proposal).
        executor_did: DID,
        /// The MLS epoch after execution, if applicable.
        resulting_epoch: Option<u64>,
    },
}

// ---------------------------------------------------------------------------
// GovernanceEngine trait
// ---------------------------------------------------------------------------

/// The pluggable governance interface. All governance models implement this trait.
///
/// The trait is object-safe to enable dynamic dispatch via `Box<dyn GovernanceEngine>`.
/// The `ContextManager` delegates all governance
/// decisions to the engine.
///
/// # Contract
///
/// - `propose()` creates a new proposal. In single-admin mode, this
///   simultaneously approves it. In multi-admin modes, it opens voting.
/// - `approve()` casts an approval vote on a pending proposal.
/// - `reject()` casts a rejection vote on a pending proposal.
/// - All methods return the resulting events for Merkle log recording.
pub trait GovernanceEngine: Send + Sync {
    /// Submit a new governance proposal. Returns the proposal and events.
    ///
    /// The proposer must hold `GovernancePropose` capability (UCAN-validated).
    /// In single-admin mode, the proposal is auto-approved if the proposer is
    /// the admin. The signing key is used to produce an Ed25519 signature over
    /// the proposer's implicit approval vote.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceError`] if the proposer lacks authority (e.g.,
    /// `NotAdmin` in single-admin mode) or if serialization fails.
    fn propose(
        &mut self,
        proposer: &DID,
        action: GovernanceAction,
        context: &GovernanceContext,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(GovernanceProposal, Vec<GovernanceEvent>), GovernanceError>;

    /// Cast an approval vote on a pending proposal.
    ///
    /// The voter must hold `GovernanceVote` capability (UCAN-validated).
    /// The signing key produces an Ed25519 signature over the vote content.
    /// Returns the updated proposal status and any events produced.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceError`] if the proposal is not found, the voter is
    /// not eligible, or the voter has already voted.
    fn approve(
        &mut self,
        proposal_id: &ProposalId,
        voter: &DID,
        context: &GovernanceContext,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError>;

    /// Cast a rejection vote on a pending proposal.
    ///
    /// The voter must hold `GovernanceVote` capability (UCAN-validated).
    /// The signing key produces an Ed25519 signature over the vote content.
    /// Returns the updated proposal status and any events produced.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceError`] if the proposal is not found, the voter is
    /// not eligible, or the voter has already voted.
    fn reject(
        &mut self,
        proposal_id: &ProposalId,
        voter: &DID,
        context: &GovernanceContext,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError>;

    /// Withdraw a previously cast vote on a pending proposal.
    ///
    /// The voter must have already voted on this proposal. The vote is removed,
    /// allowing the voter to re-vote (change from approve to reject or vice
    /// versa). Only valid while the proposal is `Pending`.
    ///
    /// # Default implementation
    ///
    /// Returns [`GovernanceError::OperationNotSupported`] for engines that do
    /// not support vote withdrawal (e.g., `SingleAdminEngine`).
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceError`] if the proposal is not found, not pending,
    /// or the voter has not voted.
    fn withdraw_vote(
        &mut self,
        proposal_id: &ProposalId,
        voter: &DID,
        context: &GovernanceContext,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError> {
        let _ = (proposal_id, voter, context);
        Err(GovernanceError::OperationNotSupported(
            "withdraw_vote is not supported by this governance model".to_owned(),
        ))
    }

    /// Resolve a pending proposal based on current vote tallies and time.
    ///
    /// Checks whether the proposal has reached quorum (approved), become
    /// impossible to approve (rejected), or expired past the voting deadline.
    /// Returns the resulting status and any events that should be recorded.
    ///
    /// # Default implementation
    ///
    /// Returns [`GovernanceError::OperationNotSupported`] for engines that do
    /// not support explicit resolution (e.g., `SingleAdminEngine` where
    /// proposals are resolved immediately on creation).
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceError`] if the proposal is not found or already
    /// resolved.
    fn resolve(
        &mut self,
        proposal_id: &ProposalId,
        context: &GovernanceContext,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError> {
        let _ = (proposal_id, context);
        Err(GovernanceError::OperationNotSupported(
            "resolve is not supported by this governance model".to_owned(),
        ))
    }

    /// Return the governance model configuration for metadata publication.
    fn model_config(&self) -> GovernanceModelConfig;

    /// Return the set of DIDs eligible to vote on proposals in this model.
    fn eligible_voters(&self, context: &GovernanceContext) -> Vec<DID>;

    /// Look up a proposal by ID. Returns `None` if not found.
    fn get_proposal(&self, proposal_id: &ProposalId) -> Option<&GovernanceProposal>;

    /// List all proposals tracked by this engine (pending and resolved).
    ///
    /// Returns cloned proposals. Engines only track proposals in memory;
    /// for durable access, proposals should be queried from the event log.
    fn list_proposals(&self) -> Vec<GovernanceProposal>;

    /// Return the IDs of all pending proposals.
    ///
    /// Used by the governance timeout task to find proposals that may need
    /// timeout processing.
    fn pending_proposal_ids(&self) -> Vec<ProposalId>;

    /// Remove a voter's vote from a pending proposal due to departure.
    ///
    /// When an eligible voter leaves the context, their vote is removed from
    /// the tally. This may change the resolution (ADR-031 §5). Returns the
    /// updated status and any events produced by automatic resolution.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceError`] if the proposal cannot be found or
    /// the voter state is invalid.
    ///
    /// # Default implementation
    ///
    /// Returns `Ok(None)` for engines that do not support voter departure
    /// handling (e.g., `SingleAdminEngine`).
    fn remove_departed_voter(
        &mut self,
        proposal_id: &ProposalId,
        voter: &DID,
        context: &GovernanceContext,
    ) -> Result<(Option<ProposalStatus>, Vec<GovernanceEvent>), GovernanceError> {
        let _ = (proposal_id, voter, context);
        Ok((None, Vec::new()))
    }

    /// Invalidate a pending proposal.
    ///
    /// Used for proposer departure and epoch reset scenarios (ADR-031 §5).
    /// Transitions a `Pending` proposal to `Invalidated` with the given reason.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceError`] if the proposal cannot be found or is
    /// not in `Pending` status.
    fn invalidate_proposal(
        &mut self,
        proposal_id: &ProposalId,
        reason: String,
    ) -> Result<Vec<GovernanceEvent>, GovernanceError>;

    /// Get checkpoint cosignature requirements for this governance model (ADR-031 §9).
    ///
    /// Returns the set of DIDs that must cosign checkpoints and the minimum
    /// number of cosignatures required for full attestation.
    ///
    /// # Returns
    ///
    /// Returns `(required_signers, minimum_count)`:
    /// - `required_signers`: Vec of DIDs eligible to cosign checkpoints
    /// - `minimum_count`: Minimum cosignatures needed for `FullyAttested` status
    ///
    /// For `SingleAdmin`: returns `(vec![], 0)` (no cosignatures required)
    /// For Threshold: returns `(signers, threshold)`
    /// For Majority: returns `(eligible_voters, ceil(voters * 0.5) + 1)`
    /// For Unanimity: returns `(eligible_voters, eligible_voters.len())`
    fn checkpoint_cosignature_requirements(&self) -> (Vec<DID>, usize);

    /// Validate a checkpoint cosignature collection (ADR-031 §9).
    ///
    /// Verifies that cosignatures meet this governance model's requirements.
    /// Returns the appropriate attestation status.
    ///
    /// # Parameters
    ///
    /// - `cosignatures`: Collected cosignatures for the checkpoint
    /// - `checkpoint_hash`: The checkpoint hash that was signed
    ///
    /// # Returns
    ///
    /// Returns `CheckpointAttestationStatus`:
    /// - `FullyAttested`: Required cosignature quorum reached
    /// - `PartiallyAttested`: Insufficient cosignatures but creator signature valid
    ///
    /// # Errors
    ///
    /// Returns `GovernanceError` if signature verification fails or invalid signers.
    fn validate_checkpoint_cosignatures(
        &self,
        cosignatures: &[CosignedCheckpoint],
        checkpoint_hash: &[u8; 32],
    ) -> Result<CheckpointAttestationStatus, GovernanceError>;
}

// ---------------------------------------------------------------------------
// SingleAdminEngine
// ---------------------------------------------------------------------------

/// Single-admin governance engine (Phase 2 baseline from ADR-008).
///
/// The admin's `propose()` call simultaneously creates and approves the
/// proposal. The `approve()`/`reject()` methods return "not eligible" for
/// non-admin callers and are no-ops for the admin (proposal is already resolved).
///
/// This preserves backward compatibility with Phase 2 behavior -- single-admin
/// governance is immediate and serialized through one DID.
pub struct SingleAdminEngine {
    /// The admin DID.
    admin_did: DID,
    /// Active and resolved proposals, keyed by proposal ID.
    proposals: HashMap<ProposalId, GovernanceProposal>,
    /// Resolves voter DIDs to their Ed25519 verifying keys for signature
    /// verification.
    key_resolver: KeyResolver,
}

impl SingleAdminEngine {
    /// Creates a new single-admin governance engine.
    ///
    /// The provided DID is the sole governance authority. The `key_resolver`
    /// maps DIDs to Ed25519 verifying keys for vote signature verification.
    #[must_use]
    pub fn new(admin_did: DID, key_resolver: KeyResolver) -> Self {
        Self {
            admin_did,
            proposals: HashMap::new(),
            key_resolver,
        }
    }

    /// Returns a reference to the admin DID.
    #[must_use]
    pub const fn admin_did(&self) -> &DID {
        &self.admin_did
    }

    /// Transfer admin authority to a new DID.
    ///
    /// This is called by the `ContextManager` after a `TransferAdmin` proposal
    /// is approved. It does not go through the proposal lifecycle -- the
    /// transfer IS the result of an approved proposal.
    pub fn transfer_admin(&mut self, new_admin: DID) {
        self.admin_did = new_admin;
    }
}

impl GovernanceEngine for SingleAdminEngine {
    fn propose(
        &mut self,
        proposer: &DID,
        action: GovernanceAction,
        context: &GovernanceContext,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(GovernanceProposal, Vec<GovernanceEvent>), GovernanceError> {
        // Only the admin can propose in single-admin mode.
        if *proposer != self.admin_did {
            return Err(GovernanceError::NotAdmin);
        }

        // RFC 8785 JCS canonical serialization for cross-implementation
        // deterministic proposal ID computation (§9.5.2). JCS (not
        // MessagePack) because GovernanceAction is a complex enum that must
        // hash identically across all SDK languages. See
        // compute_proposal_id() doc comment.
        let action_bytes =
            crate::jcs::to_vec(&action).map_err(GovernanceError::SerializationFailed)?;

        let proposal_id =
            compute_proposal_id(&context.context_id, proposer, &action_bytes, context.now);

        // Reject duplicate proposals before constructing events.
        if self.proposals.contains_key(&proposal_id) {
            return Err(GovernanceError::DuplicateProposal(hex::encode(proposal_id)));
        }

        // Sign the proposer's implicit approval vote.
        let admin_vote = sign_vote(
            &proposal_id,
            &VoteType::Approve,
            proposer.as_ref(),
            context.now,
            signing_key,
        )?;

        // Verify the admin's vote signature against their DID-resolved key.
        let resolved_key =
            (self.key_resolver)(proposer).ok_or_else(|| GovernanceError::UnknownVoter {
                did: proposer.to_string(),
            })?;
        verify_vote(&proposal_id, &admin_vote, &resolved_key).map_err(|_| {
            GovernanceError::InvalidSignature {
                voter_did: proposer.to_string(),
                proposal_id: hex::encode(proposal_id),
            }
        })?;

        // In single-admin mode, the proposal is immediately approved.
        let proposal = GovernanceProposal {
            proposal_id,
            context_id: context.context_id.clone(),
            proposer_did: proposer.clone(),
            action: action.clone(),
            status: ProposalStatus::Approved,
            created_at: context.now,
            voting_deadline: context.now, // Immediate resolution.
            approvals: vec![admin_vote],
            rejections: Vec::new(),
            created_at_epoch: context.current_epoch,
        };

        let events = vec![
            GovernanceEvent::ProposalCreated {
                proposal_id,
                proposer_did: proposer.clone(),
                action: Box::new(action),
                voting_deadline: context.now,
            },
            GovernanceEvent::VoteCast {
                proposal_id,
                voter_did: proposer.clone(),
                vote: VoteType::Approve,
            },
            GovernanceEvent::ProposalResolved {
                proposal_id,
                status: ProposalStatus::Approved,
            },
        ];

        self.proposals.insert(proposal_id, proposal.clone());

        Ok((proposal, events))
    }

    fn approve(
        &mut self,
        proposal_id: &ProposalId,
        voter: &DID,
        _context: &GovernanceContext,
        _signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError> {
        let proposal =
            self.proposals
                .get(proposal_id)
                .ok_or_else(|| GovernanceError::ProposalNotFound {
                    id: hex::encode(proposal_id),
                })?;

        // In single-admin mode, only the admin can interact.
        if *voter != self.admin_did {
            return Err(GovernanceError::NotEligible(
                "only the admin can act in single-admin governance".to_owned(),
            ));
        }

        // Proposal is already resolved; return current status (no-op).
        Ok((proposal.status.clone(), Vec::new()))
    }

    fn reject(
        &mut self,
        proposal_id: &ProposalId,
        voter: &DID,
        _context: &GovernanceContext,
        _signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError> {
        let proposal =
            self.proposals
                .get(proposal_id)
                .ok_or_else(|| GovernanceError::ProposalNotFound {
                    id: hex::encode(proposal_id),
                })?;

        // In single-admin mode, only the admin can interact.
        if *voter != self.admin_did {
            return Err(GovernanceError::NotEligible(
                "only the admin can act in single-admin governance".to_owned(),
            ));
        }

        // Proposal is already resolved; return current status (no-op).
        Ok((proposal.status.clone(), Vec::new()))
    }

    fn model_config(&self) -> GovernanceModelConfig {
        GovernanceModelConfig::SingleAdmin {
            admin_did: self.admin_did.clone(),
        }
    }

    fn eligible_voters(&self, _context: &GovernanceContext) -> Vec<DID> {
        vec![self.admin_did.clone()]
    }

    fn get_proposal(&self, proposal_id: &ProposalId) -> Option<&GovernanceProposal> {
        self.proposals.get(proposal_id)
    }

    fn list_proposals(&self) -> Vec<GovernanceProposal> {
        self.proposals.values().cloned().collect()
    }

    fn pending_proposal_ids(&self) -> Vec<ProposalId> {
        self.proposals
            .iter()
            .filter(|(_, p)| p.status.is_pending())
            .map(|(id, _)| *id)
            .collect()
    }

    fn invalidate_proposal(
        &mut self,
        proposal_id: &ProposalId,
        reason: String,
    ) -> Result<Vec<GovernanceEvent>, GovernanceError> {
        let proposal = self.proposals.get_mut(proposal_id).ok_or_else(|| {
            GovernanceError::ProposalNotFound {
                id: hex::encode(proposal_id),
            }
        })?;
        if !proposal.status.is_pending() {
            return Err(GovernanceError::ProposalNotPending {
                status: format!("{:?}", proposal.status),
            });
        }
        proposal.status = ProposalStatus::Invalidated {
            reason: reason.clone(),
        };
        Ok(vec![GovernanceEvent::ProposalResolved {
            proposal_id: *proposal_id,
            status: ProposalStatus::Invalidated { reason },
        }])
    }

    fn checkpoint_cosignature_requirements(&self) -> (Vec<DID>, usize) {
        // SingleAdmin: admin signature only, no cosignatures required (ADR-031 §9)
        (Vec::new(), 0)
    }

    fn validate_checkpoint_cosignatures(
        &self,
        cosignatures: &[CosignedCheckpoint],
        _checkpoint_hash: &[u8; 32],
    ) -> Result<CheckpointAttestationStatus, GovernanceError> {
        // SingleAdmin: cosignatures should be empty, always FullyAttested with admin signature
        if cosignatures.is_empty() {
            Ok(CheckpointAttestationStatus::FullyAttested)
        } else {
            Err(GovernanceError::NotEligible(format!(
                "SingleAdmin checkpoints must have empty cosignatures, found {}",
                cosignatures.len()
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// Conflict Detection
// ---------------------------------------------------------------------------

/// Detects if two governance actions conflict with each other (ADR-031 §7).
///
/// Two approved proposals are considered conflicting if they cannot both be
/// executed without creating an inconsistent context state. This function
/// implements the conflict detection rules from ADR-031 section 7.
///
/// # Conflict types detected:
/// - Mutual `Eject` proposals (each targeting the other's proposer)
/// - Competing `ChangeRole` proposals for the same DID with different roles
/// - Competing `ModifyCeiling` proposals with different ceiling sets
/// - `Eject` + `ChangeRole` for the same DID
/// - `Revoke` + `RestoreAccess` for the same DID
/// - Multiple `Revoke` for same DID with different scopes
/// - Multiple `SuspendMember` for same DID
/// - `SuspendMember` + `RestoreAccess` for same DID
///
/// # Arguments
/// * `action_a` - The first governance action
/// * `proposer_a` - The DID of the proposer of `action_a`
/// * `action_b` - The second governance action
/// * `proposer_b` - The DID of the proposer of `action_b`
///
/// # Returns
/// `true` if the actions conflict, `false` otherwise.
#[must_use]
pub fn actions_conflict(
    action_a: &GovernanceAction,
    proposer_a: &DID,
    action_b: &GovernanceAction,
    proposer_b: &DID,
) -> bool {
    use GovernanceAction::{
        AddSigner, ChangeRole, Eject, ModifyCeiling, ModifyPruningPolicy, ModifyThreshold,
        ReconfigureGovernance, RemoveSigner, RestoreAccess, Revoke, RotateContentKeys,
        SuspendMember,
    };

    // Canonical conflict matrix. The sync module's `actions_conflict`
    // delegates here for offline-merge conflict detection (ADR-029 / ADR-031).

    match (action_a, action_b) {
        // Competing ChangeRole proposals for the same DID with different roles
        (
            ChangeRole {
                did: did_a,
                new_role: role_a,
            },
            ChangeRole {
                did: did_b,
                new_role: role_b,
            },
        ) => did_a == did_b && role_a != role_b,

        // Any two concurrent modifications to the same global context property
        // conflict — the values may or may not differ, but concurrent
        // modification is unsafe (ADR-031 §7).
        (ModifyCeiling { .. }, ModifyCeiling { .. })
        | (ModifyThreshold { .. }, ModifyThreshold { .. })
        | (ModifyPruningPolicy { .. }, ModifyPruningPolicy { .. })
        | (ReconfigureGovernance { .. }, ReconfigureGovernance { .. })
        // Concurrent context-wide key rotations conflict (global property mutation).
        | (RotateContentKeys { .. }, RotateContentKeys { .. }) => true,

        // Two concurrent ejections of the same member conflict (ADR-031 §7:
        // concurrent modifications to the same membership state).
        // Also catches mutual ejection (each proposer ejects the other).
        (Eject { did: did_a, .. }, Eject { did: did_b, .. }) => {
            did_a == did_b || (did_a == proposer_b && did_b == proposer_a)
        }

        // Eject + role change for the same DID.
        // Two concurrent revocations targeting the same DID conflict (scope may
        // differ, but concurrent modification is unsafe — ADR-031 §7).
        // Revoke and RestoreAccess for the same DID also conflict (contradictory
        // intent on the same member's access state). SuspendMember targeting
        // the same DID also conflicts with itself and with RestoreAccess.
        (Eject { did: did_a, .. }, ChangeRole { did: did_b, .. })
        | (ChangeRole { did: did_a, .. }, Eject { did: did_b, .. })
        | (Revoke { did: did_a, .. }, Revoke { did: did_b, .. })
        | (SuspendMember { did: did_a, .. }, SuspendMember { did: did_b, .. })
        | (Revoke { did: did_a, .. }, RestoreAccess { did: did_b, .. })
        | (RestoreAccess { did: did_a, .. }, Revoke { did: did_b, .. })
        | (SuspendMember { did: did_a, .. }, RestoreAccess { did: did_b, .. })
        | (RestoreAccess { did: did_a, .. }, SuspendMember { did: did_b, .. })
        | (RestoreAccess { did: did_a, .. }, RestoreAccess { did: did_b, .. }) => did_a == did_b,

        // AddSigner and RemoveSigner for the same DID conflict.
        (AddSigner { did: add_did }, RemoveSigner { did: remove_did })
        | (RemoveSigner { did: remove_did }, AddSigner { did: add_did }) => add_did == remove_did,

        // All other action pairs are non-conflicting.
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]
mod tests {
    use super::majority::MajorityVoteEngine;
    use super::multisig::ThresholdEngine;
    use super::unanimity::UnanimityEngine;
    use super::*;

    fn alice() -> DID {
        DID::from("did:dht:z6MkAlice")
    }

    fn bob() -> DID {
        DID::from("did:dht:z6MkBob")
    }

    fn carol() -> DID {
        DID::from("did:dht:z6MkCarol")
    }

    /// Returns a deterministic signing key for use in governance tests.
    ///
    /// The seed is arbitrary -- tests only care that the key is valid,
    /// not that it corresponds to a real DID.
    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[1u8; 32])
    }

    /// Returns a second deterministic signing key (different from
    /// [`test_signing_key`]) for multi-party test scenarios.
    fn test_signing_key_2() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[2u8; 32])
    }

    /// Returns the signing key for the given seed byte (deterministic).
    fn sk_for(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    /// Signs `data` with the signing key seeded by `seed` and returns the
    /// signature bytes as a `Vec<u8>`.
    fn sign_with(seed: u8, data: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        sk_for(seed).sign(data).to_bytes().to_vec()
    }

    /// Mock key resolver that maps test DIDs to their corresponding signing
    /// key's verifying key. Alice -> [1u8;32], Bob -> [2u8;32], etc.
    fn mock_resolver() -> KeyResolver {
        Arc::new(|did: &DID| {
            let did_str: &str = did.as_ref();
            match did_str {
                "did:dht:z6MkAlice" => Some(sk_for(1).verifying_key()),
                "did:dht:z6MkBob" => Some(sk_for(2).verifying_key()),
                "did:dht:z6MkCarol" => Some(sk_for(3).verifying_key()),
                "did:dht:z6MkCharlie" => Some(sk_for(4).verifying_key()),
                "did:dht:z6MkDavid" => Some(sk_for(5).verifying_key()),
                "did:dht:z6MkEve" => Some(sk_for(6).verifying_key()),
                _ => None,
            }
        })
    }

    fn test_context(admin: &DID) -> GovernanceContext {
        GovernanceContext {
            context_id: "ctx-test-001".to_owned(),
            members: vec![
                (admin.clone(), "admin".to_owned()),
                (bob(), "member".to_owned()),
                (carol(), "member".to_owned()),
            ],
            admin_dids: vec![admin.clone()],
            current_epoch: Some(1),
            now: 1_700_000_000,
        }
    }

    // -----------------------------------------------------------------------
    // AccessScope serialization roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn access_scope_read_roundtrip() {
        let scope = AccessScope::Read;
        let json = serde_json::to_string(&scope).unwrap();
        let deserialized: AccessScope = serde_json::from_str(&json).unwrap();
        assert_eq!(scope, deserialized);
    }

    #[test]
    fn access_scope_write_roundtrip() {
        let scope = AccessScope::Write;
        let json = serde_json::to_string(&scope).unwrap();
        let deserialized: AccessScope = serde_json::from_str(&json).unwrap();
        assert_eq!(scope, deserialized);
    }

    #[test]
    fn access_scope_both_roundtrip() {
        let scope = AccessScope::Both;
        let json = serde_json::to_string(&scope).unwrap();
        let deserialized: AccessScope = serde_json::from_str(&json).unwrap();
        assert_eq!(scope, deserialized);
    }

    #[test]
    fn access_scope_variants_are_distinct() {
        assert_ne!(AccessScope::Read, AccessScope::Write);
        assert_ne!(AccessScope::Read, AccessScope::Both);
        assert_ne!(AccessScope::Write, AccessScope::Both);
    }

    // -----------------------------------------------------------------------
    // ProposalStatus tests
    // -----------------------------------------------------------------------

    #[test]
    fn proposal_status_pending_is_not_terminal() {
        assert!(ProposalStatus::Pending.is_pending());
        assert!(!ProposalStatus::Pending.is_terminal());
    }

    #[test]
    fn proposal_status_approved_is_terminal() {
        assert!(ProposalStatus::Approved.is_terminal());
        assert!(!ProposalStatus::Approved.is_pending());
    }

    #[test]
    fn proposal_status_rejected_is_terminal() {
        let status = ProposalStatus::Rejected {
            reason: RejectionReason::AdminRejected,
        };
        assert!(status.is_terminal());
        assert!(!status.is_pending());
    }

    #[test]
    fn proposal_status_expired_is_terminal() {
        assert!(ProposalStatus::Expired.is_terminal());
    }

    #[test]
    fn proposal_status_cancelled_is_terminal() {
        assert!(ProposalStatus::Cancelled.is_terminal());
    }

    #[test]
    fn proposal_status_invalidated_is_terminal() {
        let status = ProposalStatus::Invalidated {
            reason: "epoch reset".to_owned(),
        };
        assert!(status.is_terminal());
    }

    // -----------------------------------------------------------------------
    // ProposalStatus serialization
    // -----------------------------------------------------------------------

    #[test]
    fn proposal_status_serialization_roundtrip() {
        let statuses = vec![
            ProposalStatus::Pending,
            ProposalStatus::Approved,
            ProposalStatus::Rejected {
                reason: RejectionReason::AdminRejected,
            },
            ProposalStatus::Rejected {
                reason: RejectionReason::MajorityRejected,
            },
            ProposalStatus::Rejected {
                reason: RejectionReason::UnanimityBroken { rejector: bob() },
            },
            ProposalStatus::Rejected {
                reason: RejectionReason::ApprovalImpossible,
            },
            ProposalStatus::Rejected {
                reason: RejectionReason::InsufficientParticipation,
            },
            ProposalStatus::Expired,
            ProposalStatus::Cancelled,
            ProposalStatus::Invalidated {
                reason: "test".to_owned(),
            },
        ];

        for status in &statuses {
            let json = serde_json::to_string(status).expect("serialize");
            let deserialized: ProposalStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&deserialized, status);
        }
    }

    // -----------------------------------------------------------------------
    // GovernanceAction serialization
    // -----------------------------------------------------------------------

    /// Returns all 28 `GovernanceAction` variants for serialization testing.
    /// Split into two helpers to stay within the function line limit.
    fn all_governance_actions() -> Vec<GovernanceAction> {
        let mut actions = governance_actions_core();
        actions.extend(governance_actions_extended());
        actions
    }

    /// Core governance actions (membership, tools, settings, access control).
    fn governance_actions_core() -> Vec<GovernanceAction> {
        vec![
            GovernanceAction::AddMember {
                did: bob(),
                role: "member".to_owned(),
            },
            GovernanceAction::Eject {
                did: bob(),
                reason: Some("inactive".to_owned()),
            },
            GovernanceAction::ChangeRole {
                did: bob(),
                new_role: "observer".to_owned(),
            },
            GovernanceAction::RegisterTool {
                registration: Box::new(ToolRegistration {
                    tool_id: "search".to_owned(),
                    name: "search".to_owned(),
                    description: "Search tool".to_owned(),
                    schema: crate::context::tools::ToolSchema {
                        input_schema: serde_json::json!({"type": "object"}),
                        output_schema: serde_json::json!({"type": "object"}),
                    },
                    implementation_hash: [0u8; 32],
                    test_vectors: vec![],
                    operator_did: "did:dht:z6MkTestOperator".into(),
                    cost: None,
                    registered_at: 0,
                    signature: Vec::new(),
                }),
            },
            GovernanceAction::RemoveTool {
                tool_id: "search".to_owned(),
            },
            GovernanceAction::ModifyCeiling {
                new_ceiling: vec![Capability::MessagesRead],
            },
            GovernanceAction::CloseContext {
                reason: Some("done".to_owned()),
            },
            GovernanceAction::ExtendTtl {
                additional_secs: 3600,
            },
            GovernanceAction::TransferAdmin { new_admin: bob() },
            GovernanceAction::CreateChildContext {
                params: Box::new(ContextParams::default()),
            },
            GovernanceAction::SuspendMember {
                did: bob(),
                capabilities: vec![Capability::MessagesWrite],
            },
            GovernanceAction::Revoke {
                did: bob(),
                access: AccessScope::Both,
            },
            GovernanceAction::RestoreAccess {
                did: bob(),
                capabilities: vec![Capability::MessagesRead, Capability::MessagesWrite],
            },
            GovernanceAction::ModifyPruningPolicy {
                new_policy: PruningPolicy::default(),
            },
        ]
    }

    /// Extended governance actions (signers, interfaces, structural,
    /// content access, economic).
    fn governance_actions_extended() -> Vec<GovernanceAction> {
        use crate::context::tools::interface::ToolInterface;

        vec![
            GovernanceAction::AddSigner { did: carol() },
            GovernanceAction::RemoveSigner { did: carol() },
            GovernanceAction::ModifyThreshold { new_threshold: 2 },
            GovernanceAction::EstablishToolInterface {
                interface: ToolInterface {
                    source_context: "ctx-src".to_owned(),
                    target_context: "ctx-tgt".to_owned(),
                    tool_id: "tool-1".to_owned(),
                    rate_limit: None,
                    per_caller_rate_limit: None,
                    approved_by_source: true,
                    approved_by_target: false,
                    outbound_policy: None,
                    inbound_policy: None,
                },
            },
            GovernanceAction::ResetMember {
                did: bob(),
                reason: "group state corruption".to_owned(),
            },
            GovernanceAction::ResolveConflict {
                proposal_a: [1u8; 32],
                proposal_b: [2u8; 32],
                resolution: ConflictResolution::AcceptProposal {
                    winner_id: [1u8; 32],
                },
            },
            GovernanceAction::PromoteContext,
            GovernanceAction::RotateContentKeys {
                reason: Some("periodic hygiene".to_owned()),
            },
            GovernanceAction::ReconfigureGovernance {
                changes: vec![
                    GovernanceReconfigAction::RemoveInactiveSigner { did: carol() },
                    GovernanceReconfigAction::ReduceThreshold { new_threshold: 1 },
                ],
                justification: DeadlockJustification {
                    unavailable_dids: vec![carol()],
                    missed_windows: vec![(carol(), 5)],
                    detected_at: 1_700_000_000,
                },
            },
            GovernanceAction::SetEconomicPolicy {
                policy: crate::economy::types::EconomicPolicy {
                    locked: false,
                    cost_schedule: crate::economy::types::CostSchedule {
                        currency: crate::economy::types::CurrencyCode::from("USD"),
                        per_message: Some(Amount::new(1)),
                        per_tool_invoke: None,
                        per_join: None,
                        per_period: None,
                        per_byte_stored: None,
                    },
                    payment_adapters: vec![],
                    pricing_formula: None,
                    payee: DID::from("did:dht:z6MkPayee"),
                },
            },
            GovernanceAction::ApproveSpend {
                spender: bob(),
                amount: Amount::new(1000),
                purpose: "tool costs".to_owned(),
            },
            GovernanceAction::LockEconomicPolicy,
            GovernanceAction::ProposeContextMigration {
                new_context_params: Box::new(crate::context::params::ContextParams::default()),
                reason: "protocol upgrade".to_owned(),
                grace_period_secs: 604_800,
                auto_invite: true,
            },
            GovernanceAction::CancelContextMigration,
        ]
    }

    #[test]
    fn governance_action_serialization_roundtrip() {
        let actions = all_governance_actions();

        // Verify all 28 variants are covered.
        assert_eq!(
            actions.len(),
            28,
            "all GovernanceAction variants must be tested"
        );

        for action in &actions {
            let json = serde_json::to_string(action).expect("serialize");
            let deserialized: GovernanceAction = serde_json::from_str(&json).expect("deserialize");
            let json2 = serde_json::to_string(&deserialized).expect("re-serialize");
            assert_eq!(json, json2, "round-trip mismatch for action");
        }
    }

    // -----------------------------------------------------------------------
    // GovernanceModelConfig serialization
    // -----------------------------------------------------------------------

    #[test]
    fn governance_model_config_serialization_roundtrip() {
        let configs = vec![
            GovernanceModelConfig::SingleAdmin { admin_did: alice() },
            GovernanceModelConfig::Threshold {
                signers: vec![alice(), bob(), carol()],
                threshold: 2,
                voting_window_secs: 86_400,
            },
            GovernanceModelConfig::Majority {
                voting_window_secs: 86_400,
                min_participation_bps: 5000,
            },
            GovernanceModelConfig::Unanimity {
                voting_window_secs: 172_800,
            },
        ];

        for config in &configs {
            let json = serde_json::to_string(config).expect("serialize");
            let deserialized: GovernanceModelConfig =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&deserialized, config);
        }
    }

    // -----------------------------------------------------------------------
    // GovernanceEvent serialization
    // -----------------------------------------------------------------------

    #[test]
    fn governance_event_serialization_roundtrip() {
        let events = vec![
            GovernanceEvent::ProposalCreated {
                proposal_id: [1u8; 32],
                proposer_did: alice(),
                action: Box::new(GovernanceAction::AddMember {
                    did: bob(),
                    role: "member".to_owned(),
                }),
                voting_deadline: 1_700_000_000,
            },
            GovernanceEvent::VoteCast {
                proposal_id: [1u8; 32],
                voter_did: alice(),
                vote: VoteType::Approve,
            },
            GovernanceEvent::ProposalResolved {
                proposal_id: [1u8; 32],
                status: ProposalStatus::Approved,
            },
        ];

        for event in &events {
            let json = serde_json::to_string(event).expect("serialize");
            let _deserialized: GovernanceEvent = serde_json::from_str(&json).expect("deserialize");
        }
    }

    // -----------------------------------------------------------------------
    // SingleAdminEngine: propose auto-approves for admin
    // -----------------------------------------------------------------------

    #[test]
    fn single_admin_propose_auto_approves() {
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);

        let action = GovernanceAction::AddMember {
            did: DID::from("did:dht:z6MkDave"),
            role: "member".to_owned(),
        };

        let (proposal, events) = engine
            .propose(&admin, action, &ctx, &test_signing_key())
            .expect("propose");

        // Proposal should be immediately approved.
        assert_eq!(proposal.status, ProposalStatus::Approved);
        assert_eq!(proposal.proposer_did, admin);
        assert_eq!(proposal.context_id, "ctx-test-001");
        assert_eq!(proposal.approvals.len(), 1);
        assert_eq!(proposal.approvals[0].voter_did, admin);
        assert!(proposal.rejections.is_empty());
        assert_eq!(proposal.created_at_epoch, Some(1));

        // Three events: created, vote cast, resolved.
        assert_eq!(events.len(), 3);
        assert!(matches!(events[0], GovernanceEvent::ProposalCreated { .. }));
        assert!(matches!(events[1], GovernanceEvent::VoteCast { .. }));
        assert!(matches!(
            events[2],
            GovernanceEvent::ProposalResolved { .. }
        ));

        // Verify the resolved event has Approved status.
        if let GovernanceEvent::ProposalResolved { status, .. } = &events[2] {
            assert_eq!(status, &ProposalStatus::Approved);
        } else {
            panic!("expected ProposalResolved event");
        }
    }

    // -----------------------------------------------------------------------
    // SingleAdminEngine: non-admin cannot propose
    // -----------------------------------------------------------------------

    #[test]
    fn single_admin_non_admin_cannot_propose() {
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);

        let action = GovernanceAction::AddMember {
            did: DID::from("did:dht:z6MkDave"),
            role: "member".to_owned(),
        };

        let result = engine.propose(&bob(), action, &ctx, &test_signing_key_2());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GovernanceError::NotAdmin));
    }

    // -----------------------------------------------------------------------
    // SingleAdminEngine: approve is no-op for admin
    // -----------------------------------------------------------------------

    #[test]
    fn single_admin_approve_is_noop_for_admin() {
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);

        let action = GovernanceAction::CloseContext { reason: None };
        let (proposal, _) = engine
            .propose(&admin, action, &ctx, &test_signing_key())
            .expect("propose");

        // Approve on an already-approved proposal returns the current status.
        let (status, events) = engine
            .approve(&proposal.proposal_id, &admin, &ctx, &test_signing_key())
            .expect("approve");
        assert_eq!(status, ProposalStatus::Approved);
        assert!(events.is_empty(), "no-op should produce no events");
    }

    // -----------------------------------------------------------------------
    // SingleAdminEngine: reject is no-op for admin
    // -----------------------------------------------------------------------

    #[test]
    fn single_admin_reject_is_noop_for_admin() {
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);

        let action = GovernanceAction::CloseContext { reason: None };
        let (proposal, _) = engine
            .propose(&admin, action, &ctx, &test_signing_key())
            .expect("propose");

        let (status, events) = engine
            .reject(&proposal.proposal_id, &admin, &ctx, &test_signing_key())
            .expect("reject");
        assert_eq!(status, ProposalStatus::Approved);
        assert!(events.is_empty());
    }

    // -----------------------------------------------------------------------
    // SingleAdminEngine: non-admin cannot approve
    // -----------------------------------------------------------------------

    #[test]
    fn single_admin_non_admin_cannot_approve() {
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);

        let action = GovernanceAction::CloseContext { reason: None };
        let (proposal, _) = engine
            .propose(&admin, action, &ctx, &test_signing_key())
            .expect("propose");

        let result = engine.approve(&proposal.proposal_id, &bob(), &ctx, &test_signing_key_2());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::NotEligible(_)
        ));
    }

    // -----------------------------------------------------------------------
    // SingleAdminEngine: non-admin cannot reject
    // -----------------------------------------------------------------------

    #[test]
    fn single_admin_non_admin_cannot_reject() {
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);

        let action = GovernanceAction::CloseContext { reason: None };
        let (proposal, _) = engine
            .propose(&admin, action, &ctx, &test_signing_key())
            .expect("propose");

        let result = engine.reject(&proposal.proposal_id, &bob(), &ctx, &test_signing_key_2());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::NotEligible(_)
        ));
    }

    // -----------------------------------------------------------------------
    // SingleAdminEngine: approve/reject with unknown proposal ID
    // -----------------------------------------------------------------------

    #[test]
    fn single_admin_approve_unknown_proposal() {
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);
        let fake_id = [0u8; 32];

        let result = engine.approve(&fake_id, &admin, &ctx, &test_signing_key());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotFound { .. }
        ));
    }

    #[test]
    fn single_admin_reject_unknown_proposal() {
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);
        let fake_id = [0u8; 32];

        let result = engine.reject(&fake_id, &admin, &ctx, &test_signing_key());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotFound { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // SingleAdminEngine: model_config returns correct variant
    // -----------------------------------------------------------------------

    #[test]
    fn single_admin_model_config() {
        let admin = alice();
        let engine = SingleAdminEngine::new(admin.clone(), mock_resolver());

        let config = engine.model_config();
        assert_eq!(
            config,
            GovernanceModelConfig::SingleAdmin { admin_did: admin }
        );
    }

    // -----------------------------------------------------------------------
    // SingleAdminEngine: eligible_voters returns only admin
    // -----------------------------------------------------------------------

    #[test]
    fn single_admin_eligible_voters() {
        let admin = alice();
        let engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);

        let voters = engine.eligible_voters(&ctx);
        assert_eq!(voters, vec![admin]);
    }

    // -----------------------------------------------------------------------
    // SingleAdminEngine: get_proposal returns stored proposal
    // -----------------------------------------------------------------------

    #[test]
    fn single_admin_get_proposal() {
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);

        let action = GovernanceAction::AddMember {
            did: bob(),
            role: "member".to_owned(),
        };

        let (proposal, _) = engine
            .propose(&admin, action, &ctx, &test_signing_key())
            .expect("propose");
        let stored = engine.get_proposal(&proposal.proposal_id);
        assert!(stored.is_some());
        assert_eq!(stored.unwrap().proposal_id, proposal.proposal_id);
    }

    #[test]
    fn single_admin_get_proposal_not_found() {
        let admin = alice();
        let engine = SingleAdminEngine::new(admin, mock_resolver());
        let fake_id = [0u8; 32];
        assert!(engine.get_proposal(&fake_id).is_none());
    }

    // -----------------------------------------------------------------------
    // SingleAdminEngine: admin transfer
    // -----------------------------------------------------------------------

    #[test]
    fn single_admin_transfer_admin() {
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);

        // Propose transfer.
        let action = GovernanceAction::TransferAdmin { new_admin: bob() };
        let (proposal, _) = engine
            .propose(&admin, action, &ctx, &test_signing_key())
            .expect("propose");
        assert_eq!(proposal.status, ProposalStatus::Approved);

        // Execute the transfer.
        engine.transfer_admin(bob());

        // New admin should be Bob.
        assert_eq!(engine.admin_did(), &bob());
        assert_eq!(
            engine.model_config(),
            GovernanceModelConfig::SingleAdmin { admin_did: bob() }
        );

        // Alice can no longer propose.
        let action = GovernanceAction::CloseContext { reason: None };
        let result = engine.propose(&admin, action, &ctx, &test_signing_key());
        assert!(matches!(result.unwrap_err(), GovernanceError::NotAdmin));

        // Bob can propose.
        let action = GovernanceAction::CloseContext { reason: None };
        let result = engine.propose(&bob(), action, &ctx, &test_signing_key_2());
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // SingleAdminEngine: multiple proposals produce distinct IDs
    // -----------------------------------------------------------------------

    #[test]
    fn single_admin_distinct_proposal_ids() {
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());

        let ctx1 = GovernanceContext {
            context_id: "ctx-1".to_owned(),
            members: vec![(admin.clone(), "admin".to_owned())],
            admin_dids: vec![admin.clone()],
            current_epoch: Some(1),
            now: 1_000,
        };

        let ctx2 = GovernanceContext {
            context_id: "ctx-1".to_owned(),
            members: vec![(admin.clone(), "admin".to_owned())],
            admin_dids: vec![admin.clone()],
            current_epoch: Some(1),
            now: 1_001, // Different timestamp.
        };

        let action1 = GovernanceAction::CloseContext { reason: None };
        let action2 = GovernanceAction::CloseContext { reason: None };

        let sk = test_signing_key();
        let (p1, _) = engine
            .propose(&admin, action1, &ctx1, &sk)
            .expect("propose 1");
        let (p2, _) = engine
            .propose(&admin, action2, &ctx2, &sk)
            .expect("propose 2");

        assert_ne!(p1.proposal_id, p2.proposal_id);
    }

    // -----------------------------------------------------------------------
    // SingleAdminEngine: all GovernanceAction variants can be proposed
    // -----------------------------------------------------------------------

    #[test]
    fn single_admin_propose_all_action_variants() {
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);

        let actions: Vec<GovernanceAction> = vec![
            GovernanceAction::AddMember {
                did: DID::from("did:dht:z6MkDave"),
                role: "member".to_owned(),
            },
            GovernanceAction::Eject {
                did: bob(),
                reason: None,
            },
            GovernanceAction::ChangeRole {
                did: bob(),
                new_role: "observer".to_owned(),
            },
            GovernanceAction::RegisterTool {
                registration: Box::new(ToolRegistration {
                    tool_id: "calc".to_owned(),
                    name: "calc".to_owned(),
                    description: "Calculator tool".to_owned(),
                    schema: crate::context::tools::ToolSchema {
                        input_schema: serde_json::json!({"type": "object"}),
                        output_schema: serde_json::json!({"type": "object"}),
                    },
                    implementation_hash: [0u8; 32],
                    test_vectors: vec![],
                    operator_did: "did:dht:z6MkTestOperator".into(),
                    cost: None,
                    registered_at: 0,
                    signature: Vec::new(),
                }),
            },
            GovernanceAction::RemoveTool {
                tool_id: "calc".to_owned(),
            },
            GovernanceAction::ModifyCeiling {
                new_ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            },
            GovernanceAction::CloseContext {
                reason: Some("done".to_owned()),
            },
            GovernanceAction::ExtendTtl {
                additional_secs: 7200,
            },
            GovernanceAction::TransferAdmin { new_admin: carol() },
            GovernanceAction::CreateChildContext {
                params: Box::new(ContextParams::default()),
            },
            GovernanceAction::SetEconomicPolicy {
                policy: crate::economy::types::EconomicPolicy {
                    locked: false,
                    cost_schedule: crate::economy::types::CostSchedule {
                        currency: crate::economy::types::CurrencyCode::from("USD"),
                        per_message: Some(crate::economy::types::Amount::new(1)),
                        per_tool_invoke: None,
                        per_join: None,
                        per_period: None,
                        per_byte_stored: None,
                    },
                    payment_adapters: vec![],
                    pricing_formula: None,
                    payee: DID::from("did:dht:z6MkPayee"),
                },
            },
            GovernanceAction::ApproveSpend {
                spender: bob(),
                amount: Amount::new(1000),
                purpose: "tool costs".to_owned(),
            },
            GovernanceAction::LockEconomicPolicy,
        ];

        let sk = test_signing_key();
        for (i, action) in actions.into_iter().enumerate() {
            // Use different timestamps to get distinct proposal IDs.
            let mut ctx_i = ctx.clone();
            ctx_i.now = 1_700_000_000 + i as u64;

            let (proposal, events) = engine
                .propose(&admin, action, &ctx_i, &sk)
                .unwrap_or_else(|e| panic!("propose action {i} failed: {e}"));

            assert_eq!(proposal.status, ProposalStatus::Approved);
            assert_eq!(events.len(), 3);
        }
    }

    // -----------------------------------------------------------------------
    // GovernanceEngine is object-safe (compile-time check)
    // -----------------------------------------------------------------------

    #[test]
    fn governance_engine_is_object_safe() {
        fn assert_object_safe(_: &dyn GovernanceEngine) {}
        let admin = alice();
        let engine = SingleAdminEngine::new(admin, mock_resolver());
        assert_object_safe(&engine);
    }

    // -----------------------------------------------------------------------
    // SingleAdminEngine is Send + Sync (compile-time check)
    // -----------------------------------------------------------------------

    #[test]
    fn single_admin_engine_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SingleAdminEngine>();
    }

    // -----------------------------------------------------------------------
    // Proposal lifecycle state machine enforcement via SingleAdmin
    // -----------------------------------------------------------------------

    #[test]
    fn proposal_lifecycle_state_machine_single_admin() {
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);

        // 1. Propose -> immediately Approved (state: Pending -> Approved).
        let action = GovernanceAction::AddMember {
            did: DID::from("did:dht:z6MkDave"),
            role: "member".to_owned(),
        };
        let (proposal, events) = engine
            .propose(&admin, action, &ctx, &test_signing_key())
            .expect("propose");

        // Verify the events trace the full lifecycle.
        assert!(matches!(
            &events[0],
            GovernanceEvent::ProposalCreated { .. }
        ));
        assert!(matches!(&events[1], GovernanceEvent::VoteCast { .. }));
        assert!(matches!(
            &events[2],
            GovernanceEvent::ProposalResolved {
                status: ProposalStatus::Approved,
                ..
            }
        ));

        // 2. Subsequent approve/reject on resolved proposal are no-ops.
        let (status, events) = engine
            .approve(&proposal.proposal_id, &admin, &ctx, &test_signing_key())
            .expect("approve");
        assert_eq!(status, ProposalStatus::Approved);
        assert!(events.is_empty());

        let (status, events) = engine
            .reject(&proposal.proposal_id, &admin, &ctx, &test_signing_key())
            .expect("reject");
        assert_eq!(status, ProposalStatus::Approved);
        assert!(events.is_empty());
    }

    // -----------------------------------------------------------------------
    // compute_proposal_id is deterministic
    // -----------------------------------------------------------------------

    #[test]
    fn compute_proposal_id_deterministic() {
        let id1 = compute_proposal_id("ctx-1", &alice(), b"action", 1000);
        let id2 = compute_proposal_id("ctx-1", &alice(), b"action", 1000);
        assert_eq!(id1, id2);
    }

    #[test]
    fn compute_proposal_id_different_inputs() {
        let id1 = compute_proposal_id("ctx-1", &alice(), b"action", 1000);
        let id2 = compute_proposal_id("ctx-2", &alice(), b"action", 1000);
        let id3 = compute_proposal_id("ctx-1", &bob(), b"action", 1000);
        let id4 = compute_proposal_id("ctx-1", &alice(), b"other", 1000);
        let id5 = compute_proposal_id("ctx-1", &alice(), b"action", 1001);

        assert_ne!(id1, id2);
        assert_ne!(id1, id3);
        assert_ne!(id1, id4);
        assert_ne!(id1, id5);
    }

    // -----------------------------------------------------------------------
    // GovernanceError display messages
    // -----------------------------------------------------------------------

    #[test]
    fn governance_error_display() {
        assert_eq!(
            format!("{}", GovernanceError::NotAdmin),
            "proposer is not the admin"
        );

        assert_eq!(
            format!(
                "{}",
                GovernanceError::NotEligible("not a signer".to_owned())
            ),
            "voter is not eligible: not a signer"
        );

        assert_eq!(
            format!(
                "{}",
                GovernanceError::ProposalNotFound {
                    id: "abcd".to_owned()
                }
            ),
            "proposal not found: abcd"
        );

        assert_eq!(
            format!(
                "{}",
                GovernanceError::ProposalNotPending {
                    status: "Approved".to_owned()
                }
            ),
            "proposal is not pending (current status: Approved)"
        );

        assert_eq!(
            format!("{}", GovernanceError::AlreadyVoted),
            "voter has already voted on this proposal"
        );

        assert_eq!(
            format!(
                "{}",
                GovernanceError::VotingWindowExpired {
                    id: "abcd".to_owned()
                }
            ),
            "voting window has expired for proposal: abcd"
        );

        assert_eq!(
            format!(
                "{}",
                GovernanceError::OperationNotSupported("test op".to_owned())
            ),
            "operation not supported: test op"
        );
    }

    // -----------------------------------------------------------------------
    // Merkle log recording: events are structured and auditable
    // -----------------------------------------------------------------------

    #[test]
    fn governance_events_are_serializable_for_merkle_log() {
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);

        let action = GovernanceAction::ChangeRole {
            did: bob(),
            new_role: "observer".to_owned(),
        };

        let (_, events) = engine
            .propose(&admin, action, &ctx, &test_signing_key())
            .expect("propose");

        // All events must serialize to bytes for Merkle tree hashing.
        for event in &events {
            let bytes = serde_json::to_vec(event).expect("event should serialize");
            assert!(!bytes.is_empty(), "serialized event must not be empty");

            // Verify round-trip: bytes -> GovernanceEvent.
            let _roundtrip: GovernanceEvent =
                serde_json::from_slice(&bytes).expect("event should deserialize");
        }
    }

    // -----------------------------------------------------------------------
    // GovernanceProposal serialization
    // -----------------------------------------------------------------------

    #[test]
    fn governance_proposal_serialization_roundtrip() {
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);

        let action = GovernanceAction::AddMember {
            did: bob(),
            role: "member".to_owned(),
        };

        let (proposal, _) = engine
            .propose(&admin, action, &ctx, &test_signing_key())
            .expect("propose");

        let json = serde_json::to_string(&proposal).expect("serialize proposal");
        let deserialized: GovernanceProposal =
            serde_json::from_str(&json).expect("deserialize proposal");

        assert_eq!(deserialized.proposal_id, proposal.proposal_id);
        assert_eq!(deserialized.context_id, proposal.context_id);
        assert_eq!(deserialized.proposer_did, proposal.proposer_did);
        assert_eq!(deserialized.status, proposal.status);
        assert_eq!(deserialized.created_at, proposal.created_at);
        assert_eq!(deserialized.voting_deadline, proposal.voting_deadline);
        assert_eq!(deserialized.created_at_epoch, proposal.created_at_epoch);
    }

    // -----------------------------------------------------------------------
    // sign_vote / verify_vote
    // -----------------------------------------------------------------------

    #[test]
    fn sign_vote_produces_64_byte_signature() {
        let sk = test_signing_key();
        let sv = sign_vote(
            &[0u8; 32],
            &VoteType::Approve,
            "did:dht:z6MkAlice",
            1_700_000_000,
            &sk,
        )
        .expect("sign_vote");

        assert_eq!(sv.signature.len(), 64);
        assert_eq!(sv.voter_did, alice());
        assert_eq!(sv.vote, VoteType::Approve);
        assert_eq!(sv.timestamp, 1_700_000_000);
    }

    #[test]
    fn verify_vote_accepts_valid_signature() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();

        let sv = sign_vote(
            &[0u8; 32],
            &VoteType::Approve,
            "did:dht:z6MkAlice",
            1_700_000_000,
            &sk,
        )
        .expect("sign_vote");
        verify_vote(&[0u8; 32], &sv, &vk).expect("verify_vote should succeed");
    }

    #[test]
    fn verify_vote_rejects_wrong_key() {
        let sk = test_signing_key();
        let wrong_vk = test_signing_key_2().verifying_key();

        let sv = sign_vote(
            &[0u8; 32],
            &VoteType::Approve,
            "did:dht:z6MkAlice",
            1_700_000_000,
            &sk,
        )
        .expect("sign_vote");
        let result = verify_vote(&[0u8; 32], &sv, &wrong_vk);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::VerificationFailed(_)
        ));
    }

    #[test]
    fn verify_vote_rejects_tampered_voter_did() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();

        let mut sv = sign_vote(
            &[0u8; 32],
            &VoteType::Approve,
            "did:dht:z6MkAlice",
            1_700_000_000,
            &sk,
        )
        .expect("sign_vote");
        sv.voter_did = bob();

        let result = verify_vote(&[0u8; 32], &sv, &vk);
        assert!(result.is_err());
    }

    #[test]
    fn verify_vote_rejects_tampered_vote_type() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();

        let mut sv = sign_vote(
            &[0u8; 32],
            &VoteType::Approve,
            "did:dht:z6MkAlice",
            1_700_000_000,
            &sk,
        )
        .expect("sign_vote");
        sv.vote = VoteType::Reject;

        let result = verify_vote(&[0u8; 32], &sv, &vk);
        assert!(result.is_err());
    }

    #[test]
    fn verify_vote_rejects_tampered_timestamp() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();

        let mut sv = sign_vote(
            &[0u8; 32],
            &VoteType::Approve,
            "did:dht:z6MkAlice",
            1_700_000_000,
            &sk,
        )
        .expect("sign_vote");
        sv.timestamp = 1_700_000_001;

        let result = verify_vote(&[0u8; 32], &sv, &vk);
        assert!(result.is_err());
    }

    #[test]
    fn verify_vote_rejects_empty_signature() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();

        let mut sv = sign_vote(
            &[0u8; 32],
            &VoteType::Approve,
            "did:dht:z6MkAlice",
            1_700_000_000,
            &sk,
        )
        .expect("sign_vote");
        sv.signature = Vec::new();

        let result = verify_vote(&[0u8; 32], &sv, &vk);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::VerificationFailed(_)
        ));
    }

    #[test]
    fn sign_vote_is_deterministic() {
        let sk = test_signing_key();
        let sv1 = sign_vote(
            &[0u8; 32],
            &VoteType::Approve,
            "did:dht:z6MkAlice",
            1_700_000_000,
            &sk,
        )
        .expect("sign_vote");
        let sv2 = sign_vote(
            &[0u8; 32],
            &VoteType::Approve,
            "did:dht:z6MkAlice",
            1_700_000_000,
            &sk,
        )
        .expect("sign_vote");
        assert_eq!(sv1.signature, sv2.signature);
    }

    #[test]
    fn sign_vote_different_inputs_produce_different_signatures() {
        let sk = test_signing_key();
        let sv1 = sign_vote(
            &[0u8; 32],
            &VoteType::Approve,
            "did:dht:z6MkAlice",
            1_700_000_000,
            &sk,
        )
        .expect("sign_vote");
        let sv2 = sign_vote(
            &[0u8; 32],
            &VoteType::Reject,
            "did:dht:z6MkAlice",
            1_700_000_000,
            &sk,
        )
        .expect("sign_vote");
        let sv3 = sign_vote(
            &[0u8; 32],
            &VoteType::Approve,
            "did:dht:z6MkBob",
            1_700_000_000,
            &sk,
        )
        .expect("sign_vote");
        let sv4 = sign_vote(
            &[0u8; 32],
            &VoteType::Approve,
            "did:dht:z6MkAlice",
            1_700_000_001,
            &sk,
        )
        .expect("sign_vote");

        assert_ne!(sv1.signature, sv2.signature);
        assert_ne!(sv1.signature, sv3.signature);
        assert_ne!(sv1.signature, sv4.signature);
    }

    #[test]
    fn propose_produces_verifiable_vote() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);

        let action = GovernanceAction::CloseContext { reason: None };
        let (proposal, _) = engine.propose(&admin, action, &ctx, &sk).expect("propose");

        // The admin's implicit approval should have a verifiable signature.
        assert_eq!(proposal.approvals.len(), 1);
        let vote = &proposal.approvals[0];
        assert_eq!(vote.signature.len(), 64);
        verify_vote(&proposal.proposal_id, vote, &vk)
            .expect("vote produced by propose should be verifiable");
    }

    // -----------------------------------------------------------------------
    // verify_proposal_votes
    // -----------------------------------------------------------------------

    #[test]
    fn verify_proposal_votes_accepts_valid_proposal() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);

        let action = GovernanceAction::CloseContext { reason: None };
        let (proposal, _) = engine.propose(&admin, action, &ctx, &sk).expect("propose");

        // All votes should verify successfully.
        verify_proposal_votes(&proposal, |did| if *did == admin { Some(vk) } else { None })
            .expect("valid proposal should pass vote verification");
    }

    #[test]
    fn verify_proposal_votes_rejects_tampered_signature() {
        let sk = test_signing_key();
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);

        let action = GovernanceAction::CloseContext { reason: None };
        let (mut proposal, _) = engine.propose(&admin, action, &ctx, &sk).expect("propose");

        // Tamper with the vote signature.
        proposal.approvals[0].signature[0] ^= 0xff;

        let vk = sk.verifying_key();
        let result =
            verify_proposal_votes(&proposal, |did| if *did == admin { Some(vk) } else { None });

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::VerificationFailed(_)
        ));
    }

    #[test]
    fn verify_proposal_votes_rejects_unknown_voter_key() {
        let sk = test_signing_key();
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);

        let action = GovernanceAction::CloseContext { reason: None };
        let (proposal, _) = engine.propose(&admin, action, &ctx, &sk).expect("propose");

        // Key resolver returns None for all DIDs -- simulates unresolvable key.
        let result = verify_proposal_votes(&proposal, |_did| None);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::VerificationFailed(_)
        ));
    }

    #[test]
    fn verify_proposal_votes_rejects_wrong_key() {
        let sk = test_signing_key();
        let wrong_vk = test_signing_key_2().verifying_key();
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);

        let action = GovernanceAction::CloseContext { reason: None };
        let (proposal, _) = engine.propose(&admin, action, &ctx, &sk).expect("propose");

        // Resolve all voters to the wrong key.
        let result = verify_proposal_votes(&proposal, |_did| Some(wrong_vk));

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::VerificationFailed(_)
        ));
    }

    #[test]
    fn verify_proposal_votes_rejects_tampered_vote_type_in_deserialized_proposal() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);

        let action = GovernanceAction::CloseContext { reason: None };
        let (proposal, _) = engine.propose(&admin, action, &ctx, &sk).expect("propose");

        // Serialize and deserialize the proposal (simulates persistence/sync).
        let json = serde_json::to_string(&proposal).expect("serialize");
        let mut deserialized: GovernanceProposal =
            serde_json::from_str(&json).expect("deserialize");

        // Tamper with the vote type after deserialization.
        deserialized.approvals[0].vote = VoteType::Reject;

        let result =
            verify_proposal_votes(
                &deserialized,
                |did| {
                    if *did == admin { Some(vk) } else { None }
                },
            );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::VerificationFailed(_)
        ));
    }

    // -----------------------------------------------------------------------
    // Economic governance action tests — SingleAdmin (§19.3, ADR-033, #334)
    // -----------------------------------------------------------------------

    fn test_economic_policy() -> EconomicPolicy {
        EconomicPolicy {
            locked: false,
            cost_schedule: crate::economy::types::CostSchedule {
                currency: crate::economy::types::CurrencyCode::from("USD"),
                per_message: Some(Amount::new(10)),
                per_tool_invoke: Some(Amount::new(50)),
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec!["x402".to_owned()],
            pricing_formula: None,
            payee: DID::from("did:dht:z6MkPayee"),
        }
    }

    #[test]
    fn single_admin_set_economic_policy() {
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);
        let sk = test_signing_key();

        let action = GovernanceAction::SetEconomicPolicy {
            policy: test_economic_policy(),
        };

        let (proposal, events) = engine.propose(&admin, action, &ctx, &sk).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Approved);
        assert_eq!(events.len(), 3); // Created, VoteCast, Resolved
    }

    #[test]
    fn single_admin_approve_spend() {
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);
        let sk = test_signing_key();

        let action = GovernanceAction::ApproveSpend {
            spender: bob(),
            amount: Amount::new(5000),
            purpose: "tool invocation budget".to_owned(),
        };

        let (proposal, events) = engine.propose(&admin, action, &ctx, &sk).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Approved);
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn single_admin_lock_economic_policy() {
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone(), mock_resolver());
        let ctx = test_context(&admin);
        let sk = test_signing_key();

        let action = GovernanceAction::LockEconomicPolicy;

        let (proposal, events) = engine.propose(&admin, action, &ctx, &sk).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Approved);
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn single_admin_checkpoint_cosignature_requirements() {
        let admin = alice();
        let engine = SingleAdminEngine::new(admin, mock_resolver());

        let (required_signers, minimum_count) = engine.checkpoint_cosignature_requirements();
        assert_eq!(required_signers.len(), 0);
        assert_eq!(minimum_count, 0);
    }

    #[test]
    fn single_admin_checkpoint_empty_cosignatures() {
        let admin = alice();
        let engine = SingleAdminEngine::new(admin, mock_resolver());

        let checkpoint_hash = [0u8; 32];
        let cosignatures = vec![];

        let status = engine
            .validate_checkpoint_cosignatures(&cosignatures, &checkpoint_hash)
            .unwrap();
        assert_eq!(status, CheckpointAttestationStatus::FullyAttested);
    }

    #[test]
    fn single_admin_checkpoint_rejects_cosignatures() {
        let admin = alice();
        let engine = SingleAdminEngine::new(admin, mock_resolver());

        let checkpoint_hash = [0u8; 32];
        let cosignatures = vec![CosignedCheckpoint {
            signer_did: bob(),
            signature: vec![0u8; 64],
        }];

        let result = engine.validate_checkpoint_cosignatures(&cosignatures, &checkpoint_hash);
        assert!(result.is_err());
        match result.unwrap_err() {
            GovernanceError::NotEligible(msg) => {
                assert!(msg.contains("SingleAdmin checkpoints must have empty cosignatures"));
            }
            _ => panic!("Expected InvalidSigner error"),
        }
    }

    #[test]
    fn threshold_checkpoint_cosignature_requirements() {
        let signers = vec![alice(), bob(), charlie()];
        let threshold = 2;
        let engine =
            ThresholdEngine::new(signers.clone(), threshold, 86_400, mock_resolver()).unwrap();

        let (required_signers, minimum_count) = engine.checkpoint_cosignature_requirements();
        assert_eq!(required_signers, signers);
        assert_eq!(minimum_count, 2);
    }

    #[test]
    fn threshold_checkpoint_fully_attested() {
        let signers = vec![alice(), bob(), charlie()];
        let threshold = 2;
        let engine = ThresholdEngine::new(signers, threshold, 86_400, mock_resolver()).unwrap();

        let checkpoint_hash = [1u8; 32];
        let cosignatures = vec![
            CosignedCheckpoint {
                signer_did: alice(),
                signature: sign_with(1, &checkpoint_hash),
            },
            CosignedCheckpoint {
                signer_did: bob(),
                signature: sign_with(2, &checkpoint_hash),
            },
        ];

        let status = engine
            .validate_checkpoint_cosignatures(&cosignatures, &checkpoint_hash)
            .unwrap();
        assert_eq!(status, CheckpointAttestationStatus::FullyAttested);
    }

    #[test]
    fn threshold_checkpoint_partially_attested() {
        let signers = vec![alice(), bob(), charlie()];
        let threshold = 2;
        let engine = ThresholdEngine::new(signers, threshold, 86_400, mock_resolver()).unwrap();

        let checkpoint_hash = [1u8; 32];
        let cosignatures = vec![CosignedCheckpoint {
            signer_did: alice(),
            signature: sign_with(1, &checkpoint_hash),
        }];

        let status = engine
            .validate_checkpoint_cosignatures(&cosignatures, &checkpoint_hash)
            .unwrap();
        assert_eq!(status, CheckpointAttestationStatus::PartiallyAttested);
    }

    #[test]
    fn majority_checkpoint_cosignature_requirements() {
        let voters = vec![alice(), bob(), charlie(), david(), eve()]; // 5 voters
        let engine =
            MajorityVoteEngine::new(voters.clone(), 86_400, 5000, mock_resolver()).unwrap();

        let (required_signers, minimum_count) = engine.checkpoint_cosignature_requirements();
        assert_eq!(required_signers, voters);
        assert_eq!(minimum_count, 3); // (5 / 2) + 1 = 3
    }

    #[test]
    fn majority_checkpoint_fully_attested() {
        let voters = vec![alice(), bob(), charlie(), david(), eve()];
        let engine = MajorityVoteEngine::new(voters, 86_400, 5000, mock_resolver()).unwrap();

        let checkpoint_hash = [1u8; 32];
        let cosignatures = vec![
            CosignedCheckpoint {
                signer_did: alice(),
                signature: sign_with(1, &checkpoint_hash),
            },
            CosignedCheckpoint {
                signer_did: bob(),
                signature: sign_with(2, &checkpoint_hash),
            },
            CosignedCheckpoint {
                signer_did: charlie(),
                signature: sign_with(4, &checkpoint_hash), // charlie = seed 4
            },
        ];

        let status = engine
            .validate_checkpoint_cosignatures(&cosignatures, &checkpoint_hash)
            .unwrap();
        assert_eq!(status, CheckpointAttestationStatus::FullyAttested);
    }

    #[test]
    fn majority_checkpoint_partially_attested() {
        let voters = vec![alice(), bob(), charlie(), david(), eve()];
        let engine = MajorityVoteEngine::new(voters, 86_400, 5000, mock_resolver()).unwrap();

        let checkpoint_hash = [1u8; 32];
        let cosignatures = vec![
            CosignedCheckpoint {
                signer_did: alice(),
                signature: sign_with(1, &checkpoint_hash),
            },
            CosignedCheckpoint {
                signer_did: bob(),
                signature: sign_with(2, &checkpoint_hash),
            },
        ];

        let status = engine
            .validate_checkpoint_cosignatures(&cosignatures, &checkpoint_hash)
            .unwrap();
        assert_eq!(status, CheckpointAttestationStatus::PartiallyAttested);
    }

    #[test]
    fn unanimity_checkpoint_cosignature_requirements() {
        let voters = vec![alice(), bob(), charlie()];
        let engine = UnanimityEngine::new(voters.clone(), 172_800, mock_resolver()).unwrap();

        let (required_signers, minimum_count) = engine.checkpoint_cosignature_requirements();
        assert_eq!(required_signers, voters);
        assert_eq!(minimum_count, 3); // All voters
    }

    #[test]
    fn unanimity_checkpoint_fully_attested() {
        let voters = vec![alice(), bob(), charlie()];
        let engine = UnanimityEngine::new(voters, 172_800, mock_resolver()).unwrap();

        let checkpoint_hash = [1u8; 32];
        let cosignatures = vec![
            CosignedCheckpoint {
                signer_did: alice(),
                signature: sign_with(1, &checkpoint_hash),
            },
            CosignedCheckpoint {
                signer_did: bob(),
                signature: sign_with(2, &checkpoint_hash),
            },
            CosignedCheckpoint {
                signer_did: charlie(),
                signature: sign_with(4, &checkpoint_hash), // charlie = seed 4
            },
        ];

        let status = engine
            .validate_checkpoint_cosignatures(&cosignatures, &checkpoint_hash)
            .unwrap();
        assert_eq!(status, CheckpointAttestationStatus::FullyAttested);
    }

    #[test]
    fn unanimity_checkpoint_partially_attested() {
        let voters = vec![alice(), bob(), charlie()];
        let engine = UnanimityEngine::new(voters, 172_800, mock_resolver()).unwrap();

        let checkpoint_hash = [1u8; 32];
        let cosignatures = vec![
            CosignedCheckpoint {
                signer_did: alice(),
                signature: sign_with(1, &checkpoint_hash),
            },
            CosignedCheckpoint {
                signer_did: bob(),
                signature: sign_with(2, &checkpoint_hash),
            },
            // Missing charlie() - not unanimous
        ];

        let status = engine
            .validate_checkpoint_cosignatures(&cosignatures, &checkpoint_hash)
            .unwrap();
        assert_eq!(status, CheckpointAttestationStatus::PartiallyAttested);
    }

    fn charlie() -> DID {
        DID::from("did:dht:z6MkCharlie")
    }

    fn david() -> DID {
        DID::from("did:dht:z6MkDavid")
    }

    fn eve() -> DID {
        DID::from("did:dht:z6MkEve")
    }
}
