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
//! responsibility of the [`ContextManager`](super::manager::ContextManager).
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

use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::params::{Capability, ContextParams, ToolRegistration};
use super::roles::ToolId;
use crate::event_log::{ContextId, Ed25519Signature};
use crate::identity::DID;

// ---------------------------------------------------------------------------
// ProposalId
// ---------------------------------------------------------------------------

/// Unique identifier for a governance proposal.
///
/// Computed as `SHA-256(context_id || proposer_did || action_cbor || timestamp)`.
/// Deterministic for identical inputs, collision-resistant across contexts.
pub type ProposalId = [u8; 32];

/// Compute a deterministic proposal ID from its components.
///
/// Uses SHA-256 over the concatenation of context ID, proposer DID, serialized
/// action bytes, and timestamp (big-endian u64).
pub(crate) fn compute_proposal_id(
    context_id: &str,
    proposer_did: &DID,
    action_bytes: &[u8],
    timestamp: u64,
) -> ProposalId {
    let mut hasher = Sha256::new();
    hasher.update(context_id.as_bytes());
    hasher.update(proposer_did.as_ref().as_bytes());
    hasher.update(action_bytes);
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
///         || len(voter_did) as u32 BE || voter_did
///         || len(vote_json) as u32 BE || vote_json
///         || timestamp BE)
/// ```
///
/// Length prefixes prevent ambiguity when concatenating variable-length fields.
#[allow(clippy::similar_names)] // voter_did_bytes vs vote_type_bytes are semantically distinct
fn compute_vote_hash(
    voter_did: &str,
    vote: &VoteType,
    timestamp: u64,
) -> Result<Vec<u8>, GovernanceError> {
    let vote_type_bytes = serde_json::to_vec(vote)
        .map_err(|e| GovernanceError::SerializationFailed(e.to_string()))?;

    let voter_did_bytes = voter_did.as_bytes();

    let mut hasher = Sha256::new();
    hasher.update(VOTE_DOMAIN_SEPARATOR);
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
/// Computes a canonical hash over `(voter_did, vote, timestamp)` with a
/// `SCP-VOTE-V1:` domain separator and length-prefixed fields, then signs
/// it with the provided Ed25519 signing key.
///
/// # Errors
///
/// Returns [`GovernanceError::SerializationFailed`] if the vote type cannot
/// be serialized.
pub fn sign_vote(
    vote: &VoteType,
    voter_did: &str,
    timestamp: u64,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<SignedVote, GovernanceError> {
    let hash = compute_vote_hash(voter_did, vote, timestamp)?;
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
    vote: &SignedVote,
    voter_public_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), GovernanceError> {
    let hash = compute_vote_hash(vote.voter_did.as_ref(), &vote.vote, vote.timestamp)?;

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

// ---------------------------------------------------------------------------
// GovernanceAction
// ---------------------------------------------------------------------------

/// Typed governance actions. Every governance change is one of these variants.
///
/// The governance engine evaluates proposals containing these actions. This
/// covers: role changes, membership changes, settings changes, ceiling
/// expansion, and interface decisions per spec section 5.9.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceAction {
    /// Add a member to the context with a specified role.
    AddMember { did: DID, role: String },
    /// Remove a member from the context.
    RemoveMember { did: DID, reason: Option<String> },
    /// Change a member's role.
    ChangeRole { did: DID, new_role: String },
    /// Register a new tool in the context.
    RegisterTool { registration: ToolRegistration },
    /// Remove a tool from the context.
    RemoveTool { tool_id: ToolId },
    /// Modify the capability ceiling (only if `ceiling_policy` is `Governed`).
    ModifyCeiling { new_ceiling: Vec<Capability> },
    /// Close the context.
    CloseContext { reason: Option<String> },
    /// Extend context TTL (requires unanimous consent per spec section 5.10).
    ExtendTtl { additional_secs: u64 },
    /// Transfer single-admin authority (`SingleAdmin` model only).
    TransferAdmin { new_admin: DID },
    /// Create a child context (spec section 5.13).
    CreateChildContext { params: Box<ContextParams> },
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
    UnanimityBroken { rejector: DID },
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
    Rejected { reason: RejectionReason },
    /// Proposal expired before reaching quorum.
    Expired,
    /// Proposal was cancelled by the proposer before resolution.
    Cancelled,
    /// Proposal was invalidated (e.g., epoch reset, proposer removed).
    Invalidated { reason: String },
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
/// the protocol store for active tracking. The proposal tracks all votes and
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
/// Note: `PartialEq` only (not `Eq`) because `Majority::min_participation`
/// is `f64`, which does not implement `Eq`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GovernanceModelConfig {
    /// Single admin holds all governance authority. Phase 2 baseline.
    /// The creator is the initial (and only) admin. Admin transfer is
    /// a governance action that replaces the admin DID.
    SingleAdmin { admin_did: DID },

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
        /// Minimum participation threshold as a fraction (0.0 to 1.0).
        min_participation: f64,
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
/// that the [`ContextManager`](super::manager::ContextManager) executes.
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
        proposal_id: ProposalId,
        proposer_did: DID,
        action: GovernanceAction,
        voting_deadline: u64,
    },
    /// A vote was cast on a proposal.
    VoteCast {
        proposal_id: ProposalId,
        voter_did: DID,
        vote: VoteType,
    },
    /// A vote was withdrawn from a proposal.
    VoteWithdrawn {
        proposal_id: ProposalId,
        voter_did: DID,
    },
    /// A proposal was resolved (approved, rejected, expired, etc.).
    ProposalResolved {
        proposal_id: ProposalId,
        status: ProposalStatus,
    },
}

// ---------------------------------------------------------------------------
// GovernanceEngine trait
// ---------------------------------------------------------------------------

/// The pluggable governance interface. All governance models implement this trait.
///
/// The trait is object-safe to enable dynamic dispatch via `Box<dyn GovernanceEngine>`.
/// The [`ContextManager`](super::manager::ContextManager) delegates all governance
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
}

impl SingleAdminEngine {
    /// Creates a new single-admin governance engine.
    ///
    /// The provided DID is the sole governance authority.
    #[must_use]
    pub fn new(admin_did: DID) -> Self {
        Self {
            admin_did,
            proposals: HashMap::new(),
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

        // Serialize action for ID computation.
        let action_bytes = serde_json::to_vec(&action)
            .map_err(|e| GovernanceError::SerializationFailed(e.to_string()))?;

        let proposal_id =
            compute_proposal_id(&context.context_id, proposer, &action_bytes, context.now);

        // Reject duplicate proposals before constructing events.
        if self.proposals.contains_key(&proposal_id) {
            return Err(GovernanceError::DuplicateProposal(hex_encode(&proposal_id)));
        }

        // Sign the proposer's implicit approval vote.
        let admin_vote = sign_vote(
            &VoteType::Approve,
            proposer.as_ref(),
            context.now,
            signing_key,
        )?;

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
                action,
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
                    id: hex_encode(proposal_id),
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
                    id: hex_encode(proposal_id),
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
}

// ---------------------------------------------------------------------------
// Hex encoding helper
// ---------------------------------------------------------------------------

/// Encode bytes as lowercase hex string for error messages.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
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

    #[test]
    fn governance_action_serialization_roundtrip() {
        let actions = vec![
            GovernanceAction::AddMember {
                did: bob(),
                role: "member".to_owned(),
            },
            GovernanceAction::RemoveMember {
                did: bob(),
                reason: Some("inactive".to_owned()),
            },
            GovernanceAction::ChangeRole {
                did: bob(),
                new_role: "observer".to_owned(),
            },
            GovernanceAction::RegisterTool {
                registration: ToolRegistration {
                    name: "search".to_owned(),
                },
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
        ];

        for action in &actions {
            let json = serde_json::to_string(action).expect("serialize");
            // Verify it deserializes without error (round-trip validates serde).
            let _deserialized: GovernanceAction = serde_json::from_str(&json).expect("deserialize");
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
                min_participation: 0.5,
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
                action: GovernanceAction::AddMember {
                    did: bob(),
                    role: "member".to_owned(),
                },
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
        let mut engine = SingleAdminEngine::new(admin.clone());
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
        let mut engine = SingleAdminEngine::new(admin.clone());
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
        let mut engine = SingleAdminEngine::new(admin.clone());
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
        let mut engine = SingleAdminEngine::new(admin.clone());
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
        let mut engine = SingleAdminEngine::new(admin.clone());
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
        let mut engine = SingleAdminEngine::new(admin.clone());
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
        let mut engine = SingleAdminEngine::new(admin.clone());
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
        let mut engine = SingleAdminEngine::new(admin.clone());
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
        let engine = SingleAdminEngine::new(admin.clone());

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
        let engine = SingleAdminEngine::new(admin.clone());
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
        let mut engine = SingleAdminEngine::new(admin.clone());
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
        let engine = SingleAdminEngine::new(admin);
        let fake_id = [0u8; 32];
        assert!(engine.get_proposal(&fake_id).is_none());
    }

    // -----------------------------------------------------------------------
    // SingleAdminEngine: admin transfer
    // -----------------------------------------------------------------------

    #[test]
    fn single_admin_transfer_admin() {
        let admin = alice();
        let mut engine = SingleAdminEngine::new(admin.clone());
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
        let mut engine = SingleAdminEngine::new(admin.clone());

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
        let mut engine = SingleAdminEngine::new(admin.clone());
        let ctx = test_context(&admin);

        let actions: Vec<GovernanceAction> = vec![
            GovernanceAction::AddMember {
                did: DID::from("did:dht:z6MkDave"),
                role: "member".to_owned(),
            },
            GovernanceAction::RemoveMember {
                did: bob(),
                reason: None,
            },
            GovernanceAction::ChangeRole {
                did: bob(),
                new_role: "observer".to_owned(),
            },
            GovernanceAction::RegisterTool {
                registration: ToolRegistration {
                    name: "calc".to_owned(),
                },
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
        let engine = SingleAdminEngine::new(admin);
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
        let mut engine = SingleAdminEngine::new(admin.clone());
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
        let mut engine = SingleAdminEngine::new(admin.clone());
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
        let mut engine = SingleAdminEngine::new(admin.clone());
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
    // hex encoding helper
    // -----------------------------------------------------------------------

    #[test]
    fn hex_encode_produces_correct_output() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0x0a]), "00ff0a");
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    // -----------------------------------------------------------------------
    // sign_vote / verify_vote
    // -----------------------------------------------------------------------

    #[test]
    fn sign_vote_produces_64_byte_signature() {
        let sk = test_signing_key();
        let sv = sign_vote(&VoteType::Approve, "did:dht:z6MkAlice", 1_700_000_000, &sk)
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

        let sv = sign_vote(&VoteType::Approve, "did:dht:z6MkAlice", 1_700_000_000, &sk)
            .expect("sign_vote");
        verify_vote(&sv, &vk).expect("verify_vote should succeed");
    }

    #[test]
    fn verify_vote_rejects_wrong_key() {
        let sk = test_signing_key();
        let wrong_vk = test_signing_key_2().verifying_key();

        let sv = sign_vote(&VoteType::Approve, "did:dht:z6MkAlice", 1_700_000_000, &sk)
            .expect("sign_vote");
        let result = verify_vote(&sv, &wrong_vk);
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

        let mut sv = sign_vote(&VoteType::Approve, "did:dht:z6MkAlice", 1_700_000_000, &sk)
            .expect("sign_vote");
        sv.voter_did = bob();

        let result = verify_vote(&sv, &vk);
        assert!(result.is_err());
    }

    #[test]
    fn verify_vote_rejects_tampered_vote_type() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();

        let mut sv = sign_vote(&VoteType::Approve, "did:dht:z6MkAlice", 1_700_000_000, &sk)
            .expect("sign_vote");
        sv.vote = VoteType::Reject;

        let result = verify_vote(&sv, &vk);
        assert!(result.is_err());
    }

    #[test]
    fn verify_vote_rejects_tampered_timestamp() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();

        let mut sv = sign_vote(&VoteType::Approve, "did:dht:z6MkAlice", 1_700_000_000, &sk)
            .expect("sign_vote");
        sv.timestamp = 1_700_000_001;

        let result = verify_vote(&sv, &vk);
        assert!(result.is_err());
    }

    #[test]
    fn verify_vote_rejects_empty_signature() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();

        let mut sv = sign_vote(&VoteType::Approve, "did:dht:z6MkAlice", 1_700_000_000, &sk)
            .expect("sign_vote");
        sv.signature = Vec::new();

        let result = verify_vote(&sv, &vk);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::VerificationFailed(_)
        ));
    }

    #[test]
    fn sign_vote_is_deterministic() {
        let sk = test_signing_key();
        let sv1 = sign_vote(&VoteType::Approve, "did:dht:z6MkAlice", 1_700_000_000, &sk)
            .expect("sign_vote");
        let sv2 = sign_vote(&VoteType::Approve, "did:dht:z6MkAlice", 1_700_000_000, &sk)
            .expect("sign_vote");
        assert_eq!(sv1.signature, sv2.signature);
    }

    #[test]
    fn sign_vote_different_inputs_produce_different_signatures() {
        let sk = test_signing_key();
        let sv1 = sign_vote(&VoteType::Approve, "did:dht:z6MkAlice", 1_700_000_000, &sk)
            .expect("sign_vote");
        let sv2 = sign_vote(&VoteType::Reject, "did:dht:z6MkAlice", 1_700_000_000, &sk)
            .expect("sign_vote");
        let sv3 = sign_vote(&VoteType::Approve, "did:dht:z6MkBob", 1_700_000_000, &sk)
            .expect("sign_vote");
        let sv4 = sign_vote(&VoteType::Approve, "did:dht:z6MkAlice", 1_700_000_001, &sk)
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
        let mut engine = SingleAdminEngine::new(admin.clone());
        let ctx = test_context(&admin);

        let action = GovernanceAction::CloseContext { reason: None };
        let (proposal, _) = engine.propose(&admin, action, &ctx, &sk).expect("propose");

        // The admin's implicit approval should have a verifiable signature.
        assert_eq!(proposal.approvals.len(), 1);
        let vote = &proposal.approvals[0];
        assert_eq!(vote.signature.len(), 64);
        verify_vote(vote, &vk).expect("vote produced by propose should be verifiable");
    }
}
