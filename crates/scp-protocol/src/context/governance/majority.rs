//! Majority vote governance engine (ADR-031, section 4c).
//!
//! Implements the [`GovernanceEngine`] trait for majority-vote governance.
//! A proposal passes when:
//! 1. Quorum is met: `votes_cast * 10_000 / eligible_voters >= min_participation_bps`.
//! 2. Approvals exceed 50% of votes cast: `approvals > votes_cast / 2`.
//!
//! Abstentions (not voting) do not count toward or against the majority --
//! only explicit approve/reject votes are tallied. The quorum threshold
//! (`min_participation_bps`) prevents low-turnout approvals.
//!
//! # Early resolution
//!
//! - If `approvals > eligible / 2`, the proposal is approved immediately
//!   (a majority of all eligible voters have approved -- further votes
//!   cannot change the outcome).
//! - If `rejections >= (eligible + 1) / 2`, the proposal is rejected
//!   immediately (approval is mathematically impossible).
//!
//! # Timeout
//!
//! When `context.now >= voting_deadline`:
//! - If quorum is not met: `Rejected { InsufficientParticipation }`.
//! - If quorum is met and `approvals > rejections`: `Approved`.
//! - If quorum is met and `approvals <= rejections`: `Rejected { MajorityRejected }`.
//!
//! See `.docs/adrs/phase-6.md` ADR-031 section 4c for the full specification.

use std::collections::{HashMap, HashSet};

use super::{
    CheckpointAttestationStatus, CosignedCheckpoint, GovernanceAction, GovernanceContext,
    GovernanceEngine, GovernanceError, GovernanceEvent, GovernanceModelConfig, GovernanceProposal,
    KeyResolver, ProposalId, ProposalStatus, RejectionReason, VoteType, compute_proposal_id,
    sign_vote, verify_vote,
};
use scp_primitives::{DID, SigningKeyId};

// ---------------------------------------------------------------------------
// MajorityVoteEngine
// ---------------------------------------------------------------------------

/// Majority vote governance engine (ADR-031).
///
/// Each eligible voter (all context members) gets exactly one vote.
/// A proposal passes when quorum is met AND approvals exceed 50% of
/// votes cast.
///
/// # Configuration
///
/// - `eligible_voters`: The set of DIDs eligible to vote, frozen at engine
///   creation (or updated externally by the `ContextManager` when membership
///   changes).
/// - `voting_window_secs`: Duration in seconds for the voting window.
/// - `min_participation_bps`: Minimum participation in basis points (1–10000),
///   where 10000 = 100%. Per ADR-031: u32 basis points so `GovernanceModelConfig`
///   derives `Eq`.
pub struct MajorityVoteEngine {
    /// The set of DIDs eligible to vote on proposals.
    eligible_voter_dids: Vec<DID>,
    /// Duration of the voting window in seconds.
    voting_window_secs: u64,
    /// Minimum participation in basis points (1–10000, where 10000 = 100%).
    min_participation_bps: u32,
    /// Active and resolved proposals, keyed by proposal ID.
    proposals: HashMap<ProposalId, GovernanceProposal>,
    /// Resolves voter DIDs to their Ed25519 verifying keys for signature
    /// verification.
    key_resolver: KeyResolver,
}

impl std::fmt::Debug for MajorityVoteEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MajorityVoteEngine")
            .field("eligible_voter_dids", &self.eligible_voter_dids)
            .field("voting_window_secs", &self.voting_window_secs)
            .field("min_participation_bps", &self.min_participation_bps)
            .field("proposals", &self.proposals)
            .field("key_resolver", &"<fn>")
            .finish()
    }
}

impl MajorityVoteEngine {
    /// Creates a new majority vote governance engine.
    ///
    /// # Arguments
    ///
    /// - `eligible_voters`: DIDs eligible to vote. Must be non-empty.
    /// - `voting_window_secs`: Voting window duration in seconds.
    ///   Must be in `[300, 604_800]` (5 minutes to 7 days).
    /// - `min_participation_bps`: Minimum participation in basis points.
    ///   Must be in `(0, 10000]` (where 10000 = 100%).
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceError::InvalidConfig`] if any parameter is out
    /// of range.
    pub fn new(
        eligible_voters: Vec<DID>,
        voting_window_secs: u64,
        min_participation_bps: u32,
        key_resolver: KeyResolver,
    ) -> Result<Self, GovernanceError> {
        if eligible_voters.is_empty() {
            return Err(GovernanceError::InvalidConfig(
                "eligible voters must be non-empty".to_owned(),
            ));
        }
        if !(300..=604_800).contains(&voting_window_secs) {
            return Err(GovernanceError::InvalidConfig(format!(
                "voting_window_secs must be in [300, 604800], got {voting_window_secs}"
            )));
        }
        if min_participation_bps == 0 || min_participation_bps > 10_000 {
            return Err(GovernanceError::InvalidConfig(format!(
                "min_participation_bps must be in (0, 10000], got {min_participation_bps}"
            )));
        }

        Ok(Self {
            eligible_voter_dids: eligible_voters,
            voting_window_secs,
            min_participation_bps,
            proposals: HashMap::new(),
            key_resolver,
        })
    }

    /// Returns the minimum participation threshold in basis points (1–10000).
    #[must_use]
    pub const fn min_participation_bps(&self) -> u32 {
        self.min_participation_bps
    }

    /// Returns the voting window duration in seconds.
    #[must_use]
    pub const fn voting_window_secs(&self) -> u64 {
        self.voting_window_secs
    }

    /// Withdraw a previously cast vote (approval or rejection).
    ///
    /// Only the original voter can withdraw. Only valid while the proposal
    /// is `Pending` and the voting deadline has not passed.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceError`] if the proposal is not found, not pending,
    /// the voter is not eligible, or the voter has not voted.
    pub fn withdraw_vote(
        &mut self,
        proposal_id: &ProposalId,
        voter: &DID,
        context: &GovernanceContext,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError> {
        // Verify voter is eligible.
        if !self.eligible_voter_dids.contains(voter) {
            return Err(GovernanceError::NotEligible(format!(
                "{voter} is not an eligible voter"
            )));
        }

        let proposal = self.proposals.get_mut(proposal_id).ok_or_else(|| {
            GovernanceError::ProposalNotFound {
                id: hex::encode(proposal_id),
            }
        })?;

        // Only pending proposals accept vote withdrawal.
        if !proposal.status.is_pending() {
            return Err(GovernanceError::ProposalNotPending {
                status: format!("{:?}", proposal.status),
            });
        }

        // Check deadline.
        if context.now >= proposal.voting_deadline {
            return Err(GovernanceError::ProposalNotPending {
                status: "voting deadline passed".to_owned(),
            });
        }

        // Remove the vote from approvals or rejections.
        let approval_pos = proposal
            .approvals
            .iter()
            .position(|v| v.voter_did == *voter);
        let rejection_pos = proposal
            .rejections
            .iter()
            .position(|v| v.voter_did == *voter);

        if let Some(pos) = approval_pos {
            proposal.approvals.remove(pos);
        } else if let Some(pos) = rejection_pos {
            proposal.rejections.remove(pos);
        } else {
            return Err(GovernanceError::NotEligible(format!(
                "{voter} has not voted on this proposal"
            )));
        }

        let events = vec![GovernanceEvent::VoteWithdrawn {
            proposal_id: *proposal_id,
            voter_did: voter.clone(),
        }];

        Ok((proposal.status.clone(), events))
    }

    /// Check whether a proposal has reached resolution.
    ///
    /// Called after each vote and periodically by the SDK. Evaluates
    /// the current vote tallies against the majority and quorum rules,
    /// and checks for deadline expiry.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceError::ProposalNotFound`] if the proposal
    /// does not exist.
    pub fn resolve(
        &mut self,
        proposal_id: &ProposalId,
        context: &GovernanceContext,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError> {
        let proposal = self.proposals.get_mut(proposal_id).ok_or_else(|| {
            GovernanceError::ProposalNotFound {
                id: hex::encode(proposal_id),
            }
        })?;

        // Already resolved -- return current status.
        if proposal.status.is_terminal() {
            return Ok((proposal.status.clone(), Vec::new()));
        }

        let eligible = self.eligible_voter_dids.len();
        let approvals = proposal.approvals.len();
        let rejections = proposal.rejections.len();
        let participation = approvals + rejections;

        // Early approval: absolute majority of all eligible voters approved.
        // approvals > eligible / 2 (integer math: approvals * 2 > eligible).
        if approvals * 2 > eligible {
            proposal.status = ProposalStatus::Approved;
            let events = vec![GovernanceEvent::ProposalResolved {
                proposal_id: *proposal_id,
                status: ProposalStatus::Approved,
            }];
            return Ok((proposal.status.clone(), events));
        }

        // Early rejection: enough rejections that approval is impossible.
        // rejections >= ceil(eligible / 2)
        // i.e., remaining possible approvals cannot exceed 50%.
        let rejection_threshold = eligible.div_ceil(2);
        if rejections >= rejection_threshold {
            let status = ProposalStatus::Rejected {
                reason: RejectionReason::MajorityRejected,
            };
            proposal.status = status.clone();
            let events = vec![GovernanceEvent::ProposalResolved {
                proposal_id: *proposal_id,
                status,
            }];
            return Ok((proposal.status.clone(), events));
        }

        // Deadline check.
        if context.now >= proposal.voting_deadline {
            // Check quorum using integer basis-point arithmetic (ADR-031).
            // participation * 10_000 / eligible gives participation in basis points.
            let participation_bps = participation.saturating_mul(10_000) / eligible;
            if participation_bps < self.min_participation_bps as usize {
                let status = ProposalStatus::Rejected {
                    reason: RejectionReason::InsufficientParticipation,
                };
                proposal.status = status.clone();
                let events = vec![GovernanceEvent::ProposalResolved {
                    proposal_id: *proposal_id,
                    status,
                }];
                return Ok((proposal.status.clone(), events));
            }

            // Quorum met -- majority of votes cast decides.
            if approvals > rejections {
                proposal.status = ProposalStatus::Approved;
                let events = vec![GovernanceEvent::ProposalResolved {
                    proposal_id: *proposal_id,
                    status: ProposalStatus::Approved,
                }];
                return Ok((proposal.status.clone(), events));
            }

            // approvals <= rejections (tie goes to rejection).
            let status = ProposalStatus::Rejected {
                reason: RejectionReason::MajorityRejected,
            };
            proposal.status = status.clone();
            let events = vec![GovernanceEvent::ProposalResolved {
                proposal_id: *proposal_id,
                status,
            }];
            return Ok((proposal.status.clone(), events));
        }

        // Still pending -- no resolution yet.
        Ok((ProposalStatus::Pending, Vec::new()))
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Check if a voter has already voted (approve or reject) on a proposal.
    fn has_voted(proposal: &GovernanceProposal, voter: &DID) -> bool {
        proposal.approvals.iter().any(|v| v.voter_did == *voter)
            || proposal.rejections.iter().any(|v| v.voter_did == *voter)
    }

    /// Run the pre-vote guard checks.
    ///
    /// This is the portion that MUST run **before** any signing or signature
    /// verification on the signed path, so that a double vote is caught as
    /// `AlreadyVoted` regardless of which key signed the second attempt, and an
    /// ineligible voter is rejected as `NotEligible` rather than
    /// `InvalidSignature`. The checks and their error variants match the
    /// original pre-refactor `approve`/`reject` exactly: eligibility
    /// (`NotEligible`), proposal existence (`ProposalNotFound`), pending state
    /// (`ProposalNotPending`), then the deadline branch.
    ///
    /// Majority-specific subtlety: a past-deadline vote does **not** error.
    /// Exactly as the original control flow, it auto-resolves the proposal via
    /// `resolve()` **without recording a vote and without signing**, returning
    /// the resolution as [`PrecheckOutcome::Resolved`](super::PrecheckOutcome::Resolved)
    /// so the caller short-circuits. The single-vote dedup (`AlreadyVoted`) is
    /// only evaluated when the deadline has **not** passed — matching the
    /// original `!expired && Self::has_voted(..)` guard. Takes `&mut self`
    /// because the early-resolve transitions proposal state.
    fn precheck_vote(
        &mut self,
        proposal_id: &ProposalId,
        voter: &DID,
        context: &GovernanceContext,
    ) -> Result<super::PrecheckOutcome, GovernanceError> {
        // Verify voter is eligible.
        if !self.eligible_voter_dids.contains(voter) {
            return Err(GovernanceError::NotEligible(format!(
                "{voter} is not an eligible voter"
            )));
        }

        // Validate preconditions with an immutable borrow. We store a flag
        // for deadline expiry so we can call self.resolve() after the borrow
        // ends (resolve needs &mut self).
        let past_deadline = {
            let proposal = self.proposals.get(proposal_id).ok_or_else(|| {
                GovernanceError::ProposalNotFound {
                    id: hex::encode(proposal_id),
                }
            })?;

            if !proposal.status.is_pending() {
                return Err(GovernanceError::ProposalNotPending {
                    status: format!("{:?}", proposal.status),
                });
            }

            let expired = context.now >= proposal.voting_deadline;
            if !expired && Self::has_voted(proposal, voter) {
                return Err(GovernanceError::AlreadyVoted);
            }
            expired
        };

        // Handle deadline expiry (self.resolve needs &mut self). Auto-resolve
        // WITHOUT recording a vote or signing — the caller returns this result.
        if past_deadline {
            return Ok(super::PrecheckOutcome::Resolved(
                self.resolve(proposal_id, context)?,
            ));
        }

        Ok(super::PrecheckOutcome::Proceed)
    }

    /// Record an already-checked, already-verified vote and run the inline
    /// early-resolution.
    ///
    /// Runs **after** `precheck_vote` (and, on the signed path, after signature
    /// verification): pushes the vote into `approvals`/`rejections`, emits the
    /// `VoteCast` event, and applies the inline early-resolution
    /// (`approvals * 2 > eligible` for an approval, `rejections >=
    /// eligible.div_ceil(2)` for a rejection). No unverified vote ever reaches
    /// this point on the signed path — the keyless
    /// [`TrustedVoteIngest`](super::TrustedVoteIngest) path supplies an
    /// empty-signature vote by contract. The deadline has already been handled
    /// by `precheck_vote`, so the proposal here is guaranteed not past-deadline.
    fn push_and_resolve(
        &mut self,
        proposal_id: &ProposalId,
        voter: &DID,
        signed_vote: super::SignedVote,
        vote: VoteType,
        _context: &GovernanceContext,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError> {
        let eligible = self.eligible_voter_dids.len();

        // Capture the vote discriminant before moving `vote` into the VoteCast
        // event below, so we only consume the value once (the original
        // approve/reject paths each handled a single, statically-known variant).
        let is_approve = matches!(vote, VoteType::Approve);

        let proposal = self.proposals.get_mut(proposal_id).ok_or_else(|| {
            GovernanceError::ProposalNotFound {
                id: hex::encode(proposal_id),
            }
        })?;

        if is_approve {
            proposal.approvals.push(signed_vote);
        } else {
            proposal.rejections.push(signed_vote);
        }

        let mut events = vec![GovernanceEvent::VoteCast {
            proposal_id: *proposal_id,
            voter_did: voter.clone(),
            vote,
        }];

        // Check for early resolution after recording the vote.
        if is_approve {
            // Early approval: absolute majority of all eligible voters.
            let approvals = proposal.approvals.len();
            if approvals * 2 > eligible {
                proposal.status = ProposalStatus::Approved;
                events.push(GovernanceEvent::ProposalResolved {
                    proposal_id: *proposal_id,
                    status: ProposalStatus::Approved,
                });
            }
        } else {
            // Early rejection: enough rejections to make approval impossible.
            let rejections = proposal.rejections.len();
            let rejection_threshold = eligible.div_ceil(2);
            if rejections >= rejection_threshold {
                let status = ProposalStatus::Rejected {
                    reason: RejectionReason::MajorityRejected,
                };
                proposal.status = status.clone();
                events.push(GovernanceEvent::ProposalResolved {
                    proposal_id: *proposal_id,
                    status,
                });
            }
        }

        Ok((proposal.status.clone(), events))
    }
}

// ---------------------------------------------------------------------------
// GovernanceEngine implementation
// ---------------------------------------------------------------------------

impl GovernanceEngine for MajorityVoteEngine {
    fn propose(
        &mut self,
        proposer: &DID,
        action: GovernanceAction,
        context: &GovernanceContext,
        _signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(GovernanceProposal, Vec<GovernanceEvent>), GovernanceError> {
        // Any eligible voter can propose in majority model.
        if !self.eligible_voter_dids.contains(proposer) {
            return Err(GovernanceError::NotEligible(format!(
                "{proposer} is not an eligible voter"
            )));
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

        // Reject duplicate proposals.
        if self.proposals.contains_key(&proposal_id) {
            return Err(GovernanceError::DuplicateProposal(hex::encode(proposal_id)));
        }

        let voting_deadline = context.now + self.voting_window_secs;

        let proposal = GovernanceProposal {
            proposal_id,
            context_id: context.context_id.clone(),
            proposer_did: proposer.clone(),
            action: action.clone(),
            status: ProposalStatus::Pending,
            created_at: context.now,
            voting_deadline,
            approvals: Vec::new(),
            rejections: Vec::new(),
            created_at_epoch: context.current_epoch,
        };

        let events = vec![GovernanceEvent::ProposalCreated {
            proposal_id,
            proposer_did: proposer.clone(),
            action: Box::new(action),
            voting_deadline,
        }];

        self.proposals.insert(proposal_id, proposal.clone());

        Ok((proposal, events))
    }

    fn approve(
        &mut self,
        proposal_id: &ProposalId,
        voter: &DID,
        context: &GovernanceContext,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError> {
        // Guards run BEFORE sign/verify: a double vote must be caught as
        // AlreadyVoted (and an ineligible voter as NotEligible) regardless of
        // which key signed the attempt. Majority additionally short-circuits a
        // past-deadline vote by auto-resolving WITHOUT recording a vote or
        // signing — exactly as the original control flow did.
        match self.precheck_vote(proposal_id, voter, context)? {
            super::PrecheckOutcome::Proceed => {}
            super::PrecheckOutcome::Resolved(resolution) => return Ok(resolution),
        }

        // Build and sign the vote.
        let signed_vote = sign_vote(
            proposal_id,
            &VoteType::Approve,
            voter.as_ref(),
            context.now,
            signing_key,
        )?;

        // Verify the vote signature against the voter's DID-resolved key.
        // This MUST stay strictly before push_and_resolve: the signed path
        // counts a vote only after its signature is verified.
        let resolved_key = (self.key_resolver)(voter, SigningKeyId::Active).ok_or_else(|| {
            GovernanceError::UnknownVoter {
                did: voter.to_string(),
            }
        })?;
        verify_vote(proposal_id, &signed_vote, &resolved_key).map_err(|_| {
            GovernanceError::InvalidSignature {
                voter_did: voter.to_string(),
                proposal_id: hex::encode(proposal_id),
            }
        })?;

        self.push_and_resolve(proposal_id, voter, signed_vote, VoteType::Approve, context)
    }

    fn reject(
        &mut self,
        proposal_id: &ProposalId,
        voter: &DID,
        context: &GovernanceContext,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError> {
        // Guards run BEFORE sign/verify (see `approve`).
        match self.precheck_vote(proposal_id, voter, context)? {
            super::PrecheckOutcome::Proceed => {}
            super::PrecheckOutcome::Resolved(resolution) => return Ok(resolution),
        }

        // Build and sign the rejection vote.
        let signed_vote = sign_vote(
            proposal_id,
            &VoteType::Reject,
            voter.as_ref(),
            context.now,
            signing_key,
        )?;

        // Verify the vote signature against the voter's DID-resolved key.
        // This MUST stay strictly before push_and_resolve: the signed path
        // counts a vote only after its signature is verified.
        let resolved_key = (self.key_resolver)(voter, SigningKeyId::Active).ok_or_else(|| {
            GovernanceError::UnknownVoter {
                did: voter.to_string(),
            }
        })?;
        verify_vote(proposal_id, &signed_vote, &resolved_key).map_err(|_| {
            GovernanceError::InvalidSignature {
                voter_did: voter.to_string(),
                proposal_id: hex::encode(proposal_id),
            }
        })?;

        self.push_and_resolve(proposal_id, voter, signed_vote, VoteType::Reject, context)
    }

    fn resolve(
        &mut self,
        proposal_id: &ProposalId,
        context: &GovernanceContext,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError> {
        self.resolve(proposal_id, context)
    }

    fn model_config(&self) -> GovernanceModelConfig {
        GovernanceModelConfig::Majority {
            voting_window_secs: self.voting_window_secs,
            min_participation_bps: self.min_participation_bps,
        }
    }

    fn eligible_voters(&self, _context: &GovernanceContext) -> Vec<DID> {
        self.eligible_voter_dids.clone()
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

    fn remove_departed_voter(
        &mut self,
        proposal_id: &ProposalId,
        voter: &DID,
        context: &GovernanceContext,
    ) -> Result<(Option<ProposalStatus>, Vec<GovernanceEvent>), GovernanceError> {
        let proposal = self.proposals.get_mut(proposal_id).ok_or_else(|| {
            GovernanceError::ProposalNotFound {
                id: hex::encode(proposal_id),
            }
        })?;
        if !proposal.status.is_pending() {
            return Ok((None, Vec::new()));
        }
        let had_vote = proposal.approvals.iter().any(|v| v.voter_did == *voter)
            || proposal.rejections.iter().any(|v| v.voter_did == *voter);
        if had_vote {
            proposal.approvals.retain(|v| v.voter_did != *voter);
            proposal.rejections.retain(|v| v.voter_did != *voter);
        }
        self.eligible_voter_dids.retain(|d| d != voter);
        let (status, events) = self.resolve(proposal_id, context)?;
        if status.is_terminal() {
            Ok((Some(status), events))
        } else {
            Ok((None, events))
        }
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
        // Majority: require >50% cosignatures from eligible voters (ADR-031 §9)
        let majority_count = (self.eligible_voter_dids.len() / 2) + 1;
        (self.eligible_voter_dids.clone(), majority_count)
    }

    fn validate_checkpoint_cosignatures(
        &self,
        cosignatures: &[CosignedCheckpoint],
        checkpoint_hash: &[u8; 32],
    ) -> Result<CheckpointAttestationStatus, GovernanceError> {
        // Verify all cosignatures are from eligible voters and valid
        let mut valid_cosignatures = 0;
        let mut seen_signers = HashSet::new();
        for cosig in cosignatures {
            if !self.eligible_voter_dids.contains(&cosig.signer_did) {
                return Err(GovernanceError::NotEligible(format!(
                    "Cosigner {} not in eligible voter set",
                    cosig.signer_did
                )));
            }

            if !seen_signers.insert(&cosig.signer_did) {
                return Err(GovernanceError::NotEligible(format!(
                    "duplicate cosignature from {}",
                    cosig.signer_did
                )));
            }

            // Get public key for this voter
            let Some(verifying_key) = (self.key_resolver)(&cosig.signer_did, SigningKeyId::Active)
            else {
                return Err(GovernanceError::NotEligible(format!(
                    "Cannot resolve public key for cosigner {}",
                    cosig.signer_did
                )));
            };

            // Verify signature
            let sig_bytes: [u8; 64] = cosig.signature.as_slice().try_into().map_err(|_| {
                GovernanceError::VerificationFailed("invalid signature length".to_string())
            })?;
            let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            verifying_key
                .verify_strict(checkpoint_hash, &signature)
                .map_err(|e| GovernanceError::VerificationFailed(e.to_string()))?;

            valid_cosignatures += 1;
        }

        // Check if we have majority (>50%) for full attestation
        let majority_count = (self.eligible_voter_dids.len() / 2) + 1;
        if valid_cosignatures >= majority_count {
            Ok(CheckpointAttestationStatus::FullyAttested)
        } else {
            Ok(CheckpointAttestationStatus::PartiallyAttested)
        }
    }
}

// ---------------------------------------------------------------------------
// TrustedVoteIngest implementation (ADR-034 keyless path)
// ---------------------------------------------------------------------------

impl super::TrustedVoteIngest for MajorityVoteEngine {
    fn ingest_proposal(&mut self, proposal: GovernanceProposal) -> Result<(), GovernanceError> {
        // Keyless seed (ADR-034): the proposer must be in the frozen eligible
        // voter set, and the proposal_id must be new. The proposal — including
        // its status and accumulated votes — is stored VERBATIM; no re-tally, no
        // signature verification (see the TrustedVoteIngest::ingest_proposal
        // contract).
        if !self.eligible_voter_dids.contains(&proposal.proposer_did) {
            return Err(GovernanceError::NotEligible(
                "proposer is not in the eligible voter set".to_owned(),
            ));
        }
        if self.proposals.contains_key(&proposal.proposal_id) {
            return Err(GovernanceError::DuplicateProposal(hex::encode(
                proposal.proposal_id,
            )));
        }
        self.proposals.insert(proposal.proposal_id, proposal);
        Ok(())
    }

    fn ingest_approve(
        &mut self,
        proposal_id: &ProposalId,
        voter: &DID,
        context: &GovernanceContext,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError> {
        // Keyless: run the same guards, then push an empty-signature vote
        // through the same tally as the signed path. No sign_vote, no
        // verify_vote — the caller is responsible for authenticating the vote
        // out-of-band (see the TrustedVoteIngest contract). A past-deadline
        // ingest short-circuits to the auto-resolution from precheck.
        match self.precheck_vote(proposal_id, voter, context)? {
            super::PrecheckOutcome::Proceed => {}
            super::PrecheckOutcome::Resolved(resolution) => return Ok(resolution),
        }
        let signed_vote = super::build_unsigned_vote(voter, VoteType::Approve, context.now);
        self.push_and_resolve(proposal_id, voter, signed_vote, VoteType::Approve, context)
    }

    fn ingest_reject(
        &mut self,
        proposal_id: &ProposalId,
        voter: &DID,
        context: &GovernanceContext,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError> {
        match self.precheck_vote(proposal_id, voter, context)? {
            super::PrecheckOutcome::Proceed => {}
            super::PrecheckOutcome::Resolved(resolution) => return Ok(resolution),
        }
        let signed_vote = super::build_unsigned_vote(voter, VoteType::Reject, context.now);
        self.push_and_resolve(proposal_id, voter, signed_vote, VoteType::Reject, context)
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
    // Test helpers
    // -----------------------------------------------------------------------

    fn alice() -> DID {
        DID::from("did:dht:z6MkAlice")
    }

    fn bob() -> DID {
        DID::from("did:dht:z6MkBob")
    }

    fn carol() -> DID {
        DID::from("did:dht:z6MkCarol")
    }

    fn dave() -> DID {
        DID::from("did:dht:z6MkDave")
    }

    fn eve() -> DID {
        DID::from("did:dht:z6MkEve")
    }

    fn all_five() -> Vec<DID> {
        vec![alice(), bob(), carol(), dave(), eve()]
    }

    fn sk_alice() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[1u8; 32])
    }

    fn sk_bob() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[2u8; 32])
    }

    fn sk_carol() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[3u8; 32])
    }

    fn sk_dave() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[4u8; 32])
    }

    #[allow(dead_code)] // Available for tests involving eve as a voter.
    fn sk_eve() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[5u8; 32])
    }

    /// Mock key resolver that maps test DIDs to their corresponding signing
    /// key's verifying key.
    fn mock_resolver() -> KeyResolver {
        use std::sync::Arc;
        Arc::new(|did: &DID, _kid: SigningKeyId| {
            let did_str: &str = did.as_ref();
            match did_str {
                "did:dht:z6MkAlice" => {
                    Some(ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]).verifying_key())
                }
                "did:dht:z6MkBob" => {
                    Some(ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]).verifying_key())
                }
                "did:dht:z6MkCarol" => {
                    Some(ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]).verifying_key())
                }
                "did:dht:z6MkDave" => {
                    Some(ed25519_dalek::SigningKey::from_bytes(&[4u8; 32]).verifying_key())
                }
                "did:dht:z6MkEve" => {
                    Some(ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key())
                }
                _ => None,
            }
        })
    }

    fn three_voters() -> Vec<DID> {
        vec![alice(), bob(), carol()]
    }

    /// Create a governance context with the given voters as members.
    fn test_context(voters: &[DID], now: u64) -> GovernanceContext {
        GovernanceContext {
            context_id: "ctx-majority-test".to_owned(),
            members: voters
                .iter()
                .map(|d| (d.clone(), "member".to_owned()))
                .collect(),
            admin_dids: vec![voters[0].clone()],
            current_epoch: Some(1),
            now,
        }
    }

    /// Standard voting window: 24 hours.
    const WINDOW: u64 = 86_400;
    /// Standard start time.
    const T0: u64 = 1_700_000_000;

    fn default_engine(voters: Vec<DID>) -> MajorityVoteEngine {
        MajorityVoteEngine::new(voters, WINDOW, 5000, mock_resolver()).expect("valid config")
    }

    fn propose_add_member(
        engine: &mut MajorityVoteEngine,
        proposer: &DID,
        ctx: &GovernanceContext,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> GovernanceProposal {
        let action = GovernanceAction::AddMember {
            did: DID::from("did:dht:z6MkNewbie"),
            role: "member".to_owned(),
        };
        let (proposal, _) = engine
            .propose(proposer, action, ctx, signing_key)
            .expect("propose");
        proposal
    }

    // -----------------------------------------------------------------------
    // Construction / configuration validation
    // -----------------------------------------------------------------------

    #[test]
    fn new_valid_config() {
        let engine = MajorityVoteEngine::new(three_voters(), WINDOW, 5000, mock_resolver());
        assert!(engine.is_ok());
        let engine = engine.unwrap();
        assert_eq!(engine.voting_window_secs(), WINDOW);
        assert_eq!(engine.min_participation_bps(), 5000);
    }

    #[test]
    fn new_rejects_empty_voters() {
        let result = MajorityVoteEngine::new(vec![], WINDOW, 5000, mock_resolver());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::InvalidConfig(_)
        ));
    }

    #[test]
    fn new_rejects_voting_window_too_short() {
        let result = MajorityVoteEngine::new(three_voters(), 299, 5000, mock_resolver());
        assert!(result.is_err());
    }

    #[test]
    fn new_rejects_voting_window_too_long() {
        let result = MajorityVoteEngine::new(three_voters(), 604_801, 5000, mock_resolver());
        assert!(result.is_err());
    }

    #[test]
    fn new_accepts_boundary_voting_windows() {
        assert!(MajorityVoteEngine::new(three_voters(), 300, 5000, mock_resolver()).is_ok());
        assert!(MajorityVoteEngine::new(three_voters(), 604_800, 5000, mock_resolver()).is_ok());
    }

    #[test]
    fn new_rejects_zero_participation() {
        let result = MajorityVoteEngine::new(three_voters(), WINDOW, 0, mock_resolver());
        assert!(result.is_err());
    }

    #[test]
    fn new_rejects_participation_above_10000() {
        let result = MajorityVoteEngine::new(three_voters(), WINDOW, 10_001, mock_resolver());
        assert!(result.is_err());
    }

    #[test]
    fn new_accepts_participation_of_10000() {
        assert!(MajorityVoteEngine::new(three_voters(), WINDOW, 10_000, mock_resolver()).is_ok());
    }

    #[test]
    fn new_accepts_small_participation() {
        assert!(MajorityVoteEngine::new(three_voters(), WINDOW, 100, mock_resolver()).is_ok());
    }

    // -----------------------------------------------------------------------
    // Proposal creation
    // -----------------------------------------------------------------------

    #[test]
    fn propose_creates_pending_proposal() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        assert_eq!(proposal.status, ProposalStatus::Pending);
        assert_eq!(proposal.proposer_did, alice());
        assert_eq!(proposal.context_id, "ctx-majority-test");
        assert!(proposal.approvals.is_empty());
        assert!(proposal.rejections.is_empty());
        assert_eq!(proposal.voting_deadline, T0 + WINDOW);
        assert_eq!(proposal.created_at_epoch, Some(1));
    }

    #[test]
    fn propose_emits_created_event() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let action = GovernanceAction::CloseContext { reason: None };
        let (_, events) = engine
            .propose(&alice(), action, &ctx, &sk_alice())
            .expect("propose");

        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0],
            GovernanceEvent::ProposalCreated { voting_deadline, .. } if *voting_deadline == T0 + WINDOW
        ));
    }

    #[test]
    fn propose_rejects_non_eligible_voter() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let action = GovernanceAction::CloseContext { reason: None };

        let result = engine.propose(&dave(), action, &ctx, &sk_dave());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::NotEligible(_)
        ));
    }

    #[test]
    fn propose_rejects_duplicate_proposal() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let action = GovernanceAction::CloseContext { reason: None };

        let _ = engine
            .propose(&alice(), action.clone(), &ctx, &sk_alice())
            .expect("first propose");
        let result = engine.propose(&alice(), action, &ctx, &sk_alice());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::DuplicateProposal(_)
        ));
    }

    #[test]
    fn propose_different_timestamps_produce_different_ids() {
        let mut engine = default_engine(three_voters());
        let ctx1 = test_context(&three_voters(), T0);
        let ctx2 = test_context(&three_voters(), T0 + 1);
        let action1 = GovernanceAction::CloseContext { reason: None };
        let action2 = GovernanceAction::CloseContext { reason: None };

        let (p1, _) = engine
            .propose(&alice(), action1, &ctx1, &sk_alice())
            .expect("propose 1");
        let (p2, _) = engine
            .propose(&alice(), action2, &ctx2, &sk_alice())
            .expect("propose 2");
        assert_ne!(p1.proposal_id, p2.proposal_id);
    }

    // -----------------------------------------------------------------------
    // Approve / Reject basics
    // -----------------------------------------------------------------------

    #[test]
    fn approve_records_vote() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        let (status, events) = engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .expect("approve");

        assert_eq!(status, ProposalStatus::Pending);
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0],
            GovernanceEvent::VoteCast {
                vote: VoteType::Approve,
                ..
            }
        ));

        let stored = engine.get_proposal(&proposal.proposal_id).unwrap();
        assert_eq!(stored.approvals.len(), 1);
        assert_eq!(stored.approvals[0].voter_did, alice());
    }

    #[test]
    fn reject_records_vote() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        let (status, events) = engine
            .reject(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .expect("reject");

        assert_eq!(status, ProposalStatus::Pending);
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0],
            GovernanceEvent::VoteCast {
                vote: VoteType::Reject,
                ..
            }
        ));

        let stored = engine.get_proposal(&proposal.proposal_id).unwrap();
        assert_eq!(stored.rejections.len(), 1);
    }

    #[test]
    fn approve_rejects_non_eligible_voter() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        let result = engine.approve(&proposal.proposal_id, &dave(), &ctx, &sk_dave());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::NotEligible(_)
        ));
    }

    #[test]
    fn reject_rejects_non_eligible_voter() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        let result = engine.reject(&proposal.proposal_id, &dave(), &ctx, &sk_dave());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::NotEligible(_)
        ));
    }

    #[test]
    fn approve_rejects_unknown_proposal() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let fake_id = [0u8; 32];

        let result = engine.approve(&fake_id, &alice(), &ctx, &sk_alice());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotFound { .. }
        ));
    }

    #[test]
    fn reject_rejects_unknown_proposal() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let fake_id = [0u8; 32];

        let result = engine.reject(&fake_id, &alice(), &ctx, &sk_alice());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotFound { .. }
        ));
    }

    #[test]
    fn approve_rejects_double_vote() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .expect("first approve");
        let result = engine.approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice());
        assert!(matches!(result.unwrap_err(), GovernanceError::AlreadyVoted));
    }

    #[test]
    fn reject_rejects_double_vote() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .reject(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .expect("first reject");
        let result = engine.reject(&proposal.proposal_id, &alice(), &ctx, &sk_alice());
        assert!(matches!(result.unwrap_err(), GovernanceError::AlreadyVoted));
    }

    #[test]
    fn cannot_approve_and_reject_same_proposal() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .expect("approve");
        let result = engine.reject(&proposal.proposal_id, &alice(), &ctx, &sk_alice());
        assert!(matches!(result.unwrap_err(), GovernanceError::AlreadyVoted));
    }

    // -----------------------------------------------------------------------
    // Majority calculation: 3 voters
    // -----------------------------------------------------------------------

    #[test]
    fn majority_of_three_requires_two_approvals() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        // First approval -- still pending.
        let (status, _) = engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .expect("alice approves");
        assert_eq!(status, ProposalStatus::Pending);

        // Second approval -- majority reached (2 > 3/2).
        let (status, events) = engine
            .approve(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .expect("bob approves");
        assert_eq!(status, ProposalStatus::Approved);
        assert_eq!(events.len(), 2); // VoteCast + ProposalResolved
        assert!(matches!(
            &events[1],
            GovernanceEvent::ProposalResolved {
                status: ProposalStatus::Approved,
                ..
            }
        ));
    }

    // -----------------------------------------------------------------------
    // Majority calculation: 5 voters
    // -----------------------------------------------------------------------

    #[test]
    fn majority_of_five_requires_three_approvals() {
        let voters = all_five();
        let mut engine = default_engine(voters.clone());
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        // Two approvals -- not enough.
        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        let (status, _) = engine
            .approve(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .unwrap();
        assert_eq!(status, ProposalStatus::Pending);

        // Third approval -- majority (3 > 5/2 = 2.5).
        let (status, _) = engine
            .approve(&proposal.proposal_id, &carol(), &ctx, &sk_carol())
            .unwrap();
        assert_eq!(status, ProposalStatus::Approved);
    }

    // -----------------------------------------------------------------------
    // Early rejection
    // -----------------------------------------------------------------------

    #[test]
    fn early_rejection_when_approval_impossible_three_voters() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        // 1 rejection -- not yet impossible (could still get 2 approvals from bob, carol).
        let (status, _) = engine
            .reject(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        assert_eq!(status, ProposalStatus::Pending);

        // 2 rejections -- approval impossible. ceil(3/2) = 2 rejections needed.
        let (status, events) = engine
            .reject(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .unwrap();
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::MajorityRejected
            }
        );
        assert!(events.len() >= 2); // VoteCast + ProposalResolved
    }

    #[test]
    fn early_rejection_when_approval_impossible_five_voters() {
        let voters = all_five();
        let mut engine = default_engine(voters.clone());
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        // 3 rejections needed for 5 voters: ceil(5/2) = 3.
        engine
            .reject(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        engine
            .reject(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .unwrap();
        let (status, _) = engine
            .reject(&proposal.proposal_id, &carol(), &ctx, &sk_carol())
            .unwrap();
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::MajorityRejected
            }
        );
    }

    // -----------------------------------------------------------------------
    // Quorum / participation threshold
    // -----------------------------------------------------------------------

    #[test]
    fn quorum_met_approves_at_deadline() {
        let voters = all_five();
        // min_participation_bps = 4000 (40%, i.e. 2 of 5 must vote).
        let mut engine =
            MajorityVoteEngine::new(voters.clone(), WINDOW, 4000, mock_resolver()).unwrap();
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        // 2 approvals, 0 rejections. Quorum: 2*10000/5 = 4000 >= 4000.
        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        engine
            .approve(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .unwrap();

        // Before deadline -- still pending (2 is not > 5/2 = 2.5).
        let (status, _) = engine.resolve(&proposal.proposal_id, &ctx).unwrap();
        assert_eq!(status, ProposalStatus::Pending);

        // At deadline -- should approve.
        let ctx_deadline = test_context(&voters, T0 + WINDOW + 1);
        let (status, _) = engine
            .resolve(&proposal.proposal_id, &ctx_deadline)
            .unwrap();
        assert_eq!(status, ProposalStatus::Approved);
    }

    #[test]
    fn quorum_not_met_rejects_at_deadline() {
        let voters = all_five();
        // min_participation_bps = 5000 (50%, i.e. 3 of 5 must vote).
        let mut engine = default_engine(voters.clone());
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        // Only 2 votes cast (2*10000/5 = 4000 < 5000).
        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        engine
            .reject(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .unwrap();

        let ctx_deadline = test_context(&voters, T0 + WINDOW + 1);
        let (status, _) = engine
            .resolve(&proposal.proposal_id, &ctx_deadline)
            .unwrap();
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::InsufficientParticipation
            }
        );
    }

    #[test]
    fn quorum_met_rejections_win_at_deadline() {
        let voters = all_five();
        let mut engine = default_engine(voters.clone());
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        // 1 approve, 2 reject. Quorum met (3*10000/5 = 6000 >= 5000).
        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        engine
            .reject(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .unwrap();
        engine
            .reject(&proposal.proposal_id, &carol(), &ctx, &sk_carol())
            .unwrap();

        let ctx_deadline = test_context(&voters, T0 + WINDOW + 1);
        let (status, _) = engine
            .resolve(&proposal.proposal_id, &ctx_deadline)
            .unwrap();
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::MajorityRejected
            }
        );
    }

    #[test]
    fn basis_points_quorum_met_5_of_10() {
        // Acceptance criterion: 5 of 10 members voted with min_participation_bps=5000 -> quorum met.
        let voters: Vec<DID> = (0..10)
            .map(|i| DID::from(format!("did:dht:z6MkVoter{i}")))
            .collect();
        // Dynamic resolver for z6MkVoter{i} -> signing key [i + 10; 32]
        let voter_resolver: KeyResolver = {
            use std::sync::Arc;
            Arc::new(|did: &DID, _kid: SigningKeyId| {
                let s: &str = did.as_ref();
                let idx: u8 = s.strip_prefix("did:dht:z6MkVoter")?.parse().ok()?;
                Some(ed25519_dalek::SigningKey::from_bytes(&[idx + 10; 32]).verifying_key())
            })
        };
        let mut engine =
            MajorityVoteEngine::new(voters.clone(), WINDOW, 5000, voter_resolver).unwrap();
        let ctx = test_context(&voters, T0);

        let action = GovernanceAction::AddMember {
            did: DID::from("did:dht:z6MkNewbie"),
            role: "member".to_owned(),
        };
        let sks: Vec<ed25519_dalek::SigningKey> = (0..10)
            .map(|i| ed25519_dalek::SigningKey::from_bytes(&[i + 10; 32]))
            .collect();
        let (proposal, _) = engine.propose(&voters[0], action, &ctx, &sks[0]).unwrap();

        // 5 approvals out of 10 eligible.
        for i in 0..5 {
            engine
                .approve(&proposal.proposal_id, &voters[i], &ctx, &sks[i])
                .unwrap();
        }

        // At deadline: 5*10000/10 = 5000 >= 5000 -> quorum met, 5 > 0 -> approved.
        let ctx_deadline = test_context(&voters, T0 + WINDOW + 1);
        let (status, _) = engine
            .resolve(&proposal.proposal_id, &ctx_deadline)
            .unwrap();
        assert_eq!(status, ProposalStatus::Approved);
    }

    #[test]
    fn basis_points_quorum_not_met_4_of_10() {
        // Acceptance criterion: 4 of 10 members voted with min_participation_bps=5000 -> quorum NOT met.
        let voters: Vec<DID> = (0..10)
            .map(|i| DID::from(format!("did:dht:z6MkVoter{i}")))
            .collect();
        // Dynamic resolver for z6MkVoter{i} -> signing key [i + 10; 32]
        let voter_resolver: KeyResolver = {
            use std::sync::Arc;
            Arc::new(|did: &DID, _kid: SigningKeyId| {
                let s: &str = did.as_ref();
                let idx: u8 = s.strip_prefix("did:dht:z6MkVoter")?.parse().ok()?;
                Some(ed25519_dalek::SigningKey::from_bytes(&[idx + 10; 32]).verifying_key())
            })
        };
        let mut engine =
            MajorityVoteEngine::new(voters.clone(), WINDOW, 5000, voter_resolver).unwrap();
        let ctx = test_context(&voters, T0);

        let action = GovernanceAction::AddMember {
            did: DID::from("did:dht:z6MkNewbie"),
            role: "member".to_owned(),
        };
        let sks: Vec<ed25519_dalek::SigningKey> = (0..10)
            .map(|i| ed25519_dalek::SigningKey::from_bytes(&[i + 10; 32]))
            .collect();
        let (proposal, _) = engine.propose(&voters[0], action, &ctx, &sks[0]).unwrap();

        // 4 approvals out of 10 eligible.
        for i in 0..4 {
            engine
                .approve(&proposal.proposal_id, &voters[i], &ctx, &sks[i])
                .unwrap();
        }

        // At deadline: 4*10000/10 = 4000 < 5000 -> quorum NOT met.
        let ctx_deadline = test_context(&voters, T0 + WINDOW + 1);
        let (status, _) = engine
            .resolve(&proposal.proposal_id, &ctx_deadline)
            .unwrap();
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::InsufficientParticipation
            }
        );
    }

    #[test]
    fn tie_goes_to_rejection_at_deadline() {
        let voters = vec![alice(), bob(), carol(), dave()]; // 4 voters
        let mut engine =
            MajorityVoteEngine::new(voters.clone(), WINDOW, 5000, mock_resolver()).unwrap();
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        // 2 approvals, 2 rejections. Quorum met (4*10000/4 = 10000 >= 5000).
        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        engine
            .approve(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .unwrap();
        engine
            .reject(&proposal.proposal_id, &carol(), &ctx, &sk_carol())
            .unwrap();
        engine
            .reject(&proposal.proposal_id, &dave(), &ctx, &sk_dave())
            .unwrap();

        let ctx_deadline = test_context(&voters, T0 + WINDOW + 1);
        let (status, _) = engine
            .resolve(&proposal.proposal_id, &ctx_deadline)
            .unwrap();
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::MajorityRejected
            }
        );
    }

    // -----------------------------------------------------------------------
    // Abstentions
    // -----------------------------------------------------------------------

    #[test]
    fn abstentions_do_not_count_toward_majority() {
        // 5 voters, quorum 4000 bps (40%, 2 must vote), 2 approve, 3 abstain.
        let voters = all_five();
        let mut engine =
            MajorityVoteEngine::new(voters.clone(), WINDOW, 4000, mock_resolver()).unwrap();
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        engine
            .approve(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .unwrap();

        // At deadline: 2 votes cast, quorum met (2*10000/5=4000>=4000), 2 approvals > 0 rejections.
        let ctx_deadline = test_context(&voters, T0 + WINDOW + 1);
        let (status, _) = engine
            .resolve(&proposal.proposal_id, &ctx_deadline)
            .unwrap();
        assert_eq!(status, ProposalStatus::Approved);
    }

    #[test]
    fn single_vote_can_pass_with_low_quorum() {
        // 5 voters, quorum 2000 bps (20%, 1 must vote).
        let voters = all_five();
        let mut engine =
            MajorityVoteEngine::new(voters.clone(), WINDOW, 2000, mock_resolver()).unwrap();
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();

        let ctx_deadline = test_context(&voters, T0 + WINDOW + 1);
        let (status, _) = engine
            .resolve(&proposal.proposal_id, &ctx_deadline)
            .unwrap();
        assert_eq!(status, ProposalStatus::Approved);
    }

    // -----------------------------------------------------------------------
    // Timeout / deadline handling
    // -----------------------------------------------------------------------

    #[test]
    fn approve_past_deadline_triggers_resolve() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();

        // Try to approve past deadline.
        let ctx_late = test_context(&three_voters(), T0 + WINDOW + 1);
        let (status, _) = engine
            .approve(&proposal.proposal_id, &bob(), &ctx_late, &sk_bob())
            .unwrap();
        // 1 vote / 3 eligible = 3333 bps < 5000 quorum -> InsufficientParticipation.
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::InsufficientParticipation
            }
        );
    }

    #[test]
    fn reject_past_deadline_triggers_resolve() {
        // Use 5 voters so 2 approvals don't trigger early resolution (need > 2.5).
        let voters = all_five();
        let mut engine = default_engine(voters.clone());
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        engine
            .approve(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .unwrap();
        engine
            .reject(&proposal.proposal_id, &carol(), &ctx, &sk_carol())
            .unwrap();

        // Try to reject past deadline. 3*10000/5 = 6000 >= 5000 quorum.
        // 2 approvals > 1 rejection -> Approved.
        let ctx_late = test_context(&voters, T0 + WINDOW + 1);
        let (status, _) = engine
            .reject(&proposal.proposal_id, &dave(), &ctx_late, &sk_dave())
            .unwrap();
        assert_eq!(status, ProposalStatus::Approved);
    }

    #[test]
    fn resolve_on_already_resolved_is_noop() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        engine
            .approve(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .unwrap();

        // Already approved. Resolve again should be a no-op.
        let (status, events) = engine.resolve(&proposal.proposal_id, &ctx).unwrap();
        assert_eq!(status, ProposalStatus::Approved);
        assert!(events.is_empty());
    }

    #[test]
    fn resolve_unknown_proposal_returns_error() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let fake_id = [0u8; 32];

        let result = engine.resolve(&fake_id, &ctx);
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotFound { .. }
        ));
    }

    #[test]
    fn no_votes_at_deadline_rejects_insufficient_participation() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        let ctx_deadline = test_context(&three_voters(), T0 + WINDOW + 1);
        let (status, _) = engine
            .resolve(&proposal.proposal_id, &ctx_deadline)
            .unwrap();
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::InsufficientParticipation
            }
        );
    }

    // -----------------------------------------------------------------------
    // Vote withdrawal
    // -----------------------------------------------------------------------

    #[test]
    fn withdraw_approval_vote() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        assert_eq!(
            engine
                .get_proposal(&proposal.proposal_id)
                .unwrap()
                .approvals
                .len(),
            1
        );

        let (status, events) = engine
            .withdraw_vote(&proposal.proposal_id, &alice(), &ctx)
            .unwrap();
        assert_eq!(status, ProposalStatus::Pending);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], GovernanceEvent::VoteWithdrawn { .. }));
        assert_eq!(
            engine
                .get_proposal(&proposal.proposal_id)
                .unwrap()
                .approvals
                .len(),
            0
        );
    }

    #[test]
    fn withdraw_rejection_vote() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .reject(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        assert_eq!(
            engine
                .get_proposal(&proposal.proposal_id)
                .unwrap()
                .rejections
                .len(),
            1
        );

        let (_, _) = engine
            .withdraw_vote(&proposal.proposal_id, &alice(), &ctx)
            .unwrap();
        assert_eq!(
            engine
                .get_proposal(&proposal.proposal_id)
                .unwrap()
                .rejections
                .len(),
            0
        );
    }

    #[test]
    fn withdraw_allows_re_vote() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        // Alice approves, then withdraws, then rejects.
        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        engine
            .withdraw_vote(&proposal.proposal_id, &alice(), &ctx)
            .unwrap();
        engine
            .reject(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();

        let stored = engine.get_proposal(&proposal.proposal_id).unwrap();
        assert!(stored.approvals.is_empty());
        assert_eq!(stored.rejections.len(), 1);
        assert_eq!(stored.rejections[0].voter_did, alice());
    }

    #[test]
    fn withdraw_rejects_non_voter() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        // Bob hasn't voted.
        let result = engine.withdraw_vote(&proposal.proposal_id, &bob(), &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn withdraw_rejects_non_eligible() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        let result = engine.withdraw_vote(&proposal.proposal_id, &dave(), &ctx);
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::NotEligible(_)
        ));
    }

    #[test]
    fn withdraw_rejects_resolved_proposal() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        engine
            .approve(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .unwrap();
        // Now approved.

        let result = engine.withdraw_vote(&proposal.proposal_id, &alice(), &ctx);
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotPending { .. }
        ));
    }

    #[test]
    fn withdraw_rejects_unknown_proposal() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let fake_id = [0u8; 32];

        let result = engine.withdraw_vote(&fake_id, &alice(), &ctx);
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotFound { .. }
        ));
    }

    #[test]
    fn withdraw_rejects_past_deadline() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();

        let ctx_late = test_context(&three_voters(), T0 + WINDOW + 1);
        let result = engine.withdraw_vote(&proposal.proposal_id, &alice(), &ctx_late);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Cannot vote on resolved proposals
    // -----------------------------------------------------------------------

    #[test]
    fn approve_on_resolved_proposal_errors() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        engine
            .approve(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .unwrap();
        // Now approved.

        let result = engine.approve(&proposal.proposal_id, &carol(), &ctx, &sk_carol());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotPending { .. }
        ));
    }

    #[test]
    fn reject_on_resolved_proposal_errors() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        engine
            .approve(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .unwrap();

        let result = engine.reject(&proposal.proposal_id, &carol(), &ctx, &sk_carol());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotPending { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // model_config / eligible_voters / get_proposal
    // -----------------------------------------------------------------------

    #[test]
    fn model_config_returns_majority() {
        let engine = default_engine(three_voters());
        let config = engine.model_config();
        assert_eq!(
            config,
            GovernanceModelConfig::Majority {
                voting_window_secs: WINDOW,
                min_participation_bps: 5000,
            }
        );
    }

    #[test]
    fn eligible_voters_returns_configured_set() {
        let voters = three_voters();
        let engine = default_engine(voters.clone());
        let ctx = test_context(&voters, T0);

        let eligible = engine.eligible_voters(&ctx);
        assert_eq!(eligible, voters);
    }

    #[test]
    fn get_proposal_returns_stored_proposal() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        let stored = engine.get_proposal(&proposal.proposal_id);
        assert!(stored.is_some());
        assert_eq!(stored.unwrap().proposal_id, proposal.proposal_id);
    }

    #[test]
    fn get_proposal_not_found() {
        let engine = default_engine(three_voters());
        assert!(engine.get_proposal(&[0u8; 32]).is_none());
    }

    // -----------------------------------------------------------------------
    // Send + Sync compile-time check
    // -----------------------------------------------------------------------

    #[test]
    fn majority_vote_engine_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MajorityVoteEngine>();
    }

    // -----------------------------------------------------------------------
    // Object safety compile-time check
    // -----------------------------------------------------------------------

    #[test]
    fn majority_vote_engine_is_object_safe() {
        fn assert_object_safe(_: &dyn GovernanceEngine) {}
        let engine = default_engine(three_voters());
        assert_object_safe(&engine);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn single_voter_approves_immediately() {
        let voters = vec![alice()];
        let mut engine =
            MajorityVoteEngine::new(voters.clone(), WINDOW, 10_000, mock_resolver()).unwrap();
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        // 1 approval out of 1 voter -> immediate majority.
        let (status, _) = engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        assert_eq!(status, ProposalStatus::Approved);
    }

    #[test]
    fn single_voter_rejects_immediately() {
        let voters = vec![alice()];
        let mut engine =
            MajorityVoteEngine::new(voters.clone(), WINDOW, 10_000, mock_resolver()).unwrap();
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        // 1 rejection out of 1 voter -> approval impossible.
        let (status, _) = engine
            .reject(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::MajorityRejected
            }
        );
    }

    #[test]
    fn two_voters_need_both_to_approve_without_deadline() {
        // 2 voters: 1 approval is not > 2/2 = 1 (needs to be strictly greater).
        let voters = vec![alice(), bob()];
        let mut engine =
            MajorityVoteEngine::new(voters.clone(), WINDOW, 5000, mock_resolver()).unwrap();
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        let (status, _) = engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        // 1 * 2 = 2 > 2? No -> still pending.
        assert_eq!(status, ProposalStatus::Pending);

        // Second approval: 2 * 2 = 4 > 2? Yes -> approved.
        let (status, _) = engine
            .approve(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .unwrap();
        assert_eq!(status, ProposalStatus::Approved);
    }

    #[test]
    fn two_voters_one_approve_one_abstain_passes_at_deadline_with_low_quorum() {
        let voters = vec![alice(), bob()];
        let mut engine =
            MajorityVoteEngine::new(voters.clone(), WINDOW, 5000, mock_resolver()).unwrap();
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        // Bob abstains. At deadline: 1*10000/2 = 5000 >= 5000 quorum, 1 > 0.
        let ctx_deadline = test_context(&voters, T0 + WINDOW + 1);
        let (status, _) = engine
            .resolve(&proposal.proposal_id, &ctx_deadline)
            .unwrap();
        assert_eq!(status, ProposalStatus::Approved);
    }

    #[test]
    fn even_voters_early_rejection_threshold() {
        // 4 voters: rejection threshold = ceil(4/2) = 2.
        let voters = vec![alice(), bob(), carol(), dave()];
        let mut engine = default_engine(voters.clone());
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .reject(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        let (status, _) = engine
            .reject(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .unwrap();
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::MajorityRejected
            }
        );
    }

    #[test]
    fn all_action_variants_proposable() {
        let mut engine = default_engine(three_voters());

        let actions: Vec<GovernanceAction> = vec![
            GovernanceAction::AddMember {
                did: dave(),
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
            GovernanceAction::CloseContext {
                reason: Some("done".to_owned()),
            },
            GovernanceAction::ExtendTtl {
                additional_secs: 3600,
            },
        ];

        for (i, action) in actions.into_iter().enumerate() {
            let ctx = test_context(&three_voters(), T0 + i as u64);
            let (proposal, events) = engine
                .propose(&alice(), action, &ctx, &sk_alice())
                .unwrap_or_else(|e| panic!("propose action {i} failed: {e}"));
            assert_eq!(proposal.status, ProposalStatus::Pending);
            assert_eq!(events.len(), 1);
        }
    }

    // -----------------------------------------------------------------------
    // GovernanceEvent audit trail
    // -----------------------------------------------------------------------

    #[test]
    fn full_lifecycle_produces_auditable_events() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let action = GovernanceAction::AddMember {
            did: dave(),
            role: "member".to_owned(),
        };
        let (proposal, create_events) =
            engine.propose(&alice(), action, &ctx, &sk_alice()).unwrap();
        assert_eq!(create_events.len(), 1);
        assert!(matches!(
            &create_events[0],
            GovernanceEvent::ProposalCreated { .. }
        ));

        let (_, vote_events) = engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        assert_eq!(vote_events.len(), 1);
        assert!(matches!(
            &vote_events[0],
            GovernanceEvent::VoteCast {
                vote: VoteType::Approve,
                ..
            }
        ));

        let (_, resolve_events) = engine
            .approve(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .unwrap();
        assert_eq!(resolve_events.len(), 2);
        assert!(matches!(
            &resolve_events[0],
            GovernanceEvent::VoteCast { .. }
        ));
        assert!(matches!(
            &resolve_events[1],
            GovernanceEvent::ProposalResolved {
                status: ProposalStatus::Approved,
                ..
            }
        ));

        // All events must serialize for Merkle log.
        let all_events: Vec<&GovernanceEvent> = create_events
            .iter()
            .chain(vote_events.iter())
            .chain(resolve_events.iter())
            .collect();
        for event in all_events {
            let bytes = serde_json::to_vec(event).expect("event should serialize");
            assert!(!bytes.is_empty());
        }
    }

    #[test]
    fn resolve_still_pending_before_deadline_no_events() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        // No votes, before deadline.
        let (status, events) = engine.resolve(&proposal.proposal_id, &ctx).unwrap();
        assert_eq!(status, ProposalStatus::Pending);
        assert!(events.is_empty());
    }

    #[test]
    fn full_participation_quorum_not_met_rejects() {
        // min_participation_bps = 10000 (100%) with 5 voters. 2 approvals won't
        // trigger early resolution (need > 2.5), so we can test quorum at deadline.
        let voters = all_five();
        let mut engine =
            MajorityVoteEngine::new(voters.clone(), WINDOW, 10_000, mock_resolver()).unwrap();
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        engine
            .approve(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .unwrap();
        // 2 of 5 voted, 3 abstain. Quorum: 2*10000/5 = 4000 < 10000.
        let ctx_deadline = test_context(&voters, T0 + WINDOW + 1);
        let (status, _) = engine
            .resolve(&proposal.proposal_id, &ctx_deadline)
            .unwrap();
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::InsufficientParticipation
            }
        );
    }

    #[test]
    fn full_participation_all_approve() {
        let voters = three_voters();
        let mut engine =
            MajorityVoteEngine::new(voters.clone(), WINDOW, 10_000, mock_resolver()).unwrap();
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        // 2 of 3 approved -> early majority resolution.
        let (status, _) = engine
            .approve(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .unwrap();
        assert_eq!(status, ProposalStatus::Approved);
    }

    // -----------------------------------------------------------------------
    // verify_vote integration (defense-in-depth)
    // -----------------------------------------------------------------------

    #[test]
    fn approve_produces_verifiable_votes() {
        use crate::context::governance::verify_vote;

        let voters = three_voters();
        let mut engine = default_engine(voters.clone());
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();

        let p = engine.get_proposal(&proposal.proposal_id).unwrap();
        assert_eq!(p.approvals.len(), 1);
        verify_vote(
            &proposal.proposal_id,
            &p.approvals[0],
            &sk_alice().verifying_key(),
        )
        .expect("vote recorded by approve() should be verifiable");
    }

    #[test]
    fn reject_produces_verifiable_votes() {
        use crate::context::governance::verify_vote;

        let voters = three_voters();
        let mut engine = default_engine(voters.clone());
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .reject(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .unwrap();

        let p = engine.get_proposal(&proposal.proposal_id).unwrap();
        assert_eq!(p.rejections.len(), 1);
        verify_vote(
            &proposal.proposal_id,
            &p.rejections[0],
            &sk_bob().verifying_key(),
        )
        .expect("vote recorded by reject() should be verifiable");
    }

    #[test]
    fn tampered_vote_signature_rejected_by_verify_proposal_votes() {
        use crate::context::governance::verify_proposal_votes;

        let voters = three_voters();
        let mut engine = default_engine(voters.clone());
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();

        // Serialize and deserialize to simulate persistence/sync boundary.
        let p = engine.get_proposal(&proposal.proposal_id).unwrap();
        let json = serde_json::to_string(p).unwrap();
        let mut deserialized: GovernanceProposal = serde_json::from_str(&json).unwrap();

        // Tamper with the vote signature.
        deserialized.approvals[0].signature[0] ^= 0xff;

        let result = verify_proposal_votes(&deserialized, |did| {
            if *did == alice() {
                Some(sk_alice().verifying_key())
            } else {
                None
            }
        });

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::VerificationFailed(_)
        ));
    }

    // -----------------------------------------------------------------------
    // Vote signature verification via key_resolver (#357)
    // -----------------------------------------------------------------------

    #[test]
    fn unknown_voter_did_rejected_by_resolver() {
        // AC: construct a MajorityVoteEngine with a mock resolver, submit a
        // vote for an unknown DID (resolver returns None), verify
        // GovernanceError::UnknownVoter is returned.
        //
        // Dave is in the eligible voters but NOT in the resolver.
        let resolver_without_dave: KeyResolver = {
            use std::sync::Arc;
            Arc::new(|did: &DID, _kid: SigningKeyId| {
                let did_str: &str = did.as_ref();
                match did_str {
                    "did:dht:z6MkAlice" => {
                        Some(ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]).verifying_key())
                    }
                    "did:dht:z6MkBob" => {
                        Some(ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]).verifying_key())
                    }
                    "did:dht:z6MkCarol" => {
                        Some(ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]).verifying_key())
                    }
                    _ => None,
                }
            })
        };

        let voters = vec![alice(), bob(), carol(), dave()];
        let mut engine =
            MajorityVoteEngine::new(voters.clone(), WINDOW, 5000, resolver_without_dave)
                .expect("valid config");
        let ctx = test_context(&voters, T0);

        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        // Alice approves (resolver knows Alice).
        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .expect("alice approve ok");

        // Dave tries to approve but resolver returns None for Dave.
        let result = engine.approve(&proposal.proposal_id, &dave(), &ctx, &sk_dave());
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), GovernanceError::UnknownVoter { .. }),
            "expected UnknownVoter error for unresolvable DID"
        );
    }

    #[test]
    fn forged_vote_rejected_by_resolver() {
        // AC: submit a vote with a forged signature (wrong key).
        let voters = three_voters();
        let mut engine = default_engine(voters.clone());
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        // Alice approves with the correct key.
        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .expect("alice approve ok");

        // Bob tries to approve with Carol's key (forgery).
        let result = engine.approve(&proposal.proposal_id, &bob(), &ctx, &sk_carol());
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                GovernanceError::InvalidSignature { .. }
            ),
            "expected InvalidSignature for forged vote"
        );
    }

    // -----------------------------------------------------------------------
    // Economic governance action tests — MajorityVote (#334)
    // -----------------------------------------------------------------------

    #[test]
    fn majority_set_economic_policy() {
        let voters = vec![alice(), bob(), carol()];
        let mut engine = MajorityVoteEngine::new(voters.clone(), 86_400, 5000, mock_resolver())
            .expect("valid config");
        let ctx = test_context(&voters, 1_700_000_000);

        let action = GovernanceAction::SetEconomicPolicy {
            policy: crate::economy::types::EconomicPolicy {
                locked: false,
                cost_schedule: crate::economy::types::CostSchedule {
                    currency: crate::economy::types::CurrencyCode::from("USD"),
                    per_message: Some(crate::economy::types::Amount::new(10)),
                    per_tool_invoke: None,
                    per_join: None,
                    per_period: None,
                    per_byte_stored: None,
                },
                payment_adapters: vec![],
                pricing_formula: None,
                payee: DID::from("did:dht:z6MkPayee"),
            },
        };

        let (proposal, events) = engine.propose(&alice(), action, &ctx, &sk_alice()).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Pending);
        assert_eq!(events.len(), 1); // ProposalCreated
    }

    #[test]
    fn majority_approve_spend() {
        let voters = vec![alice(), bob()];
        let mut engine = MajorityVoteEngine::new(voters.clone(), 86_400, 5000, mock_resolver())
            .expect("valid config");
        let ctx = test_context(&voters, 1_700_000_000);

        let action = GovernanceAction::ApproveSpend {
            spender: bob(),
            amount: crate::economy::types::Amount::new(5000),
            purpose: "tool budget".to_owned(),
        };

        let (proposal, _) = engine.propose(&alice(), action, &ctx, &sk_alice()).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Pending);
    }

    #[test]
    fn majority_lock_economic_policy() {
        let voters = vec![alice(), bob()];
        let mut engine = MajorityVoteEngine::new(voters.clone(), 86_400, 5000, mock_resolver())
            .expect("valid config");
        let ctx = test_context(&voters, 1_700_000_000);

        let action = GovernanceAction::LockEconomicPolicy;

        let (proposal, _) = engine.propose(&alice(), action, &ctx, &sk_alice()).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Pending);
    }

    // -----------------------------------------------------------------------
    // TrustedVoteIngest (keyless, ADR-034) — Majority
    // -----------------------------------------------------------------------

    use crate::context::governance::TrustedVoteIngest;

    #[test]
    fn ingest_approve_reaches_absolute_majority() {
        // 3 voters: two ingested approvals -> absolute majority (2*2 > 3) ->
        // Approved. (Majority does not auto-count the proposer.)
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());
        let pid = proposal.proposal_id;

        let (status, _) = engine.ingest_approve(&pid, &alice(), &ctx).expect("ingest");
        assert_eq!(status, ProposalStatus::Pending);

        let (status, events) = engine.ingest_approve(&pid, &bob(), &ctx).expect("ingest");
        assert_eq!(status, ProposalStatus::Approved);
        assert_eq!(events.len(), 2); // VoteCast + ProposalResolved

        // Recorded ingested votes carry empty signatures.
        let p = engine.get_proposal(&pid).expect("found");
        assert_eq!(p.approvals.len(), 2);
        assert!(p.approvals[0].signature.is_empty());
        assert!(p.approvals[1].signature.is_empty());
    }

    #[test]
    fn ingest_stays_pending_below_majority() {
        // 5 voters: two ingested approvals is not an absolute majority
        // (2*2 = 4, not > 5) and the deadline has not passed -> Pending.
        let voters = all_five();
        let mut engine = default_engine(voters.clone());
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());
        let pid = proposal.proposal_id;

        engine.ingest_approve(&pid, &alice(), &ctx).expect("ingest");
        let (status, _) = engine.ingest_approve(&pid, &bob(), &ctx).expect("ingest");
        assert_eq!(status, ProposalStatus::Pending);
    }

    #[test]
    fn ingest_reject_reaches_early_rejection() {
        // 3 voters: two ingested rejections >= ceil(3/2) = 2 -> early rejection.
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());
        let pid = proposal.proposal_id;

        let (status, _) = engine.ingest_reject(&pid, &alice(), &ctx).expect("ingest");
        assert_eq!(status, ProposalStatus::Pending);

        let (status, _) = engine.ingest_reject(&pid, &bob(), &ctx).expect("ingest");
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::MajorityRejected
            }
        );
    }

    #[test]
    fn ingest_tallies_against_frozen_eligible_set() {
        // The engine's frozen eligible_voter_dids is the denominator regardless
        // of any external membership notion. The engine is frozen at 3 voters;
        // the GovernanceContext lists a DIFFERENT (larger) membership. Two
        // ingested approvals still reach absolute majority of the FROZEN set
        // (2*2 > 3), proving the context membership is not consulted.
        let mut engine = default_engine(three_voters());
        // Context advertises five members, but the engine's frozen set is three.
        let ctx = test_context(&all_five(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());
        let pid = proposal.proposal_id;

        engine.ingest_approve(&pid, &alice(), &ctx).expect("ingest");
        let (status, _) = engine.ingest_approve(&pid, &bob(), &ctx).expect("ingest");
        // Would still be pending if the denominator were 5 (4 !> 5); Approved
        // confirms the frozen denominator of 3 is used.
        assert_eq!(status, ProposalStatus::Approved);
    }

    #[test]
    fn ingest_approve_rejects_non_eligible() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        // Dave is not in the frozen eligible voter set.
        let result = engine.ingest_approve(&proposal.proposal_id, &dave(), &ctx);
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::NotEligible(_)
        ));
    }

    #[test]
    fn ingest_approve_rejects_already_voted() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());
        let pid = proposal.proposal_id;

        engine.ingest_approve(&pid, &alice(), &ctx).expect("ingest");
        let result = engine.ingest_approve(&pid, &alice(), &ctx);
        assert!(matches!(result.unwrap_err(), GovernanceError::AlreadyVoted));
    }

    #[test]
    fn ingest_approve_rejects_terminal_proposal() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());
        let pid = proposal.proposal_id;

        // Drive to Approved (2 of 3).
        engine.ingest_approve(&pid, &alice(), &ctx).expect("ingest");
        let (status, _) = engine.ingest_approve(&pid, &bob(), &ctx).expect("ingest");
        assert_eq!(status, ProposalStatus::Approved);

        let result = engine.ingest_approve(&pid, &carol(), &ctx);
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotPending { .. }
        ));
    }

    #[test]
    fn ingest_approve_past_deadline_triggers_resolve() {
        // Mirrors approve_past_deadline_triggers_resolve for the keyless path:
        // a post-deadline ingest defers to resolve(). One vote / 3 eligible =
        // 3333 bps < 5000 quorum -> InsufficientParticipation.
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());
        let pid = proposal.proposal_id;

        engine.ingest_approve(&pid, &alice(), &ctx).expect("ingest");

        let ctx_late = test_context(&three_voters(), T0 + WINDOW + 1);
        let (status, _) = engine
            .ingest_approve(&pid, &bob(), &ctx_late)
            .expect("resolve");
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::InsufficientParticipation
            }
        );
    }

    #[test]
    fn ingest_and_signed_paths_reach_identical_status() {
        let ctx = test_context(&three_voters(), T0);

        // Signed path: alice + bob approve -> absolute majority -> Approved.
        let mut signed = default_engine(three_voters());
        let sp = propose_add_member(&mut signed, &alice(), &ctx, &sk_alice());
        signed
            .approve(&sp.proposal_id, &alice(), &ctx, &sk_alice())
            .expect("approve");
        let (signed_status, _) = signed
            .approve(&sp.proposal_id, &bob(), &ctx, &sk_bob())
            .expect("approve");

        // Ingest path: same sequence, keyless.
        let mut ingested = default_engine(three_voters());
        let ip = propose_add_member(&mut ingested, &alice(), &ctx, &sk_alice());
        ingested
            .ingest_approve(&ip.proposal_id, &alice(), &ctx)
            .expect("ingest");
        let (ingest_status, _) = ingested
            .ingest_approve(&ip.proposal_id, &bob(), &ctx)
            .expect("ingest");

        assert_eq!(signed_status, ingest_status);
        assert_eq!(signed_status, ProposalStatus::Approved);
    }

    // -----------------------------------------------------------------------
    // Guard ordering: dedup and eligibility precede signature verification.
    //
    // Mirrors the scp-runtime agent-binding scenario at the engine layer:
    // the guards (NotEligible / AlreadyVoted) MUST run BEFORE sign/verify so a
    // double vote is caught as a double vote regardless of which key signed it,
    // and an ineligible voter is rejected as NotEligible rather than
    // InvalidSignature.
    // -----------------------------------------------------------------------

    #[test]
    fn second_vote_same_did_different_key_is_already_voted_not_invalid_sig() {
        // Three eligible voters: a single approval keeps the proposal Pending
        // (1 * 2 > 3 is false), so the dedup guard is exercised on the second
        // vote rather than being short-circuited by early resolution. Bob's DID
        // resolves to sk_bob only; his second attempt uses a different (wrong)
        // key (sk_carol). The AlreadyVoted dedup must fire before signature
        // verification.
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());
        let pid = proposal.proposal_id;

        // First vote: valid (sk_bob matches the resolver's entry for bob).
        let (status, _) = engine.approve(&pid, &bob(), &ctx, &sk_bob()).expect("ok");
        assert_eq!(
            status,
            ProposalStatus::Pending,
            "1 approval of 3 stays pending"
        );

        // Second vote: same DID, different (wrong) signing key.
        let result = engine.approve(&pid, &bob(), &ctx, &sk_carol());
        assert!(
            matches!(result.unwrap_err(), GovernanceError::AlreadyVoted),
            "dedup must precede signature verification (expected AlreadyVoted, not InvalidSignature)"
        );
    }

    #[test]
    fn ineligible_voter_with_invalid_sig_is_not_eligible_not_invalid_sig() {
        // Dave is NOT an eligible voter. He votes with a key that does not
        // match his DID-resolved key. The eligibility check (NotEligible) must
        // run before signature verification.
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        // Dave is not eligible; sign with a mismatched key (sk_carol).
        let result = engine.approve(&proposal.proposal_id, &dave(), &ctx, &sk_carol());
        assert!(
            matches!(result.unwrap_err(), GovernanceError::NotEligible(_)),
            "eligibility must precede signature verification (expected NotEligible)"
        );
    }

    // -----------------------------------------------------------------------
    // ingest_proposal: keyless seed (ADR-034)
    // -----------------------------------------------------------------------

    fn make_unsigned_proposal(
        proposer: &DID,
        ctx: &GovernanceContext,
        status: ProposalStatus,
    ) -> GovernanceProposal {
        let action = GovernanceAction::AddMember {
            did: DID::from("did:dht:z6MkNewbie"),
            role: "member".to_owned(),
        };
        let action_bytes = crate::jcs::to_vec(&action).expect("jcs");
        let proposal_id = crate::context::governance::compute_proposal_id(
            &ctx.context_id,
            proposer,
            &action_bytes,
            ctx.now,
        );
        GovernanceProposal {
            proposal_id,
            context_id: ctx.context_id.clone(),
            proposer_did: proposer.clone(),
            action,
            status,
            created_at: ctx.now,
            voting_deadline: ctx.now + WINDOW,
            approvals: vec![crate::context::governance::build_unsigned_vote(
                proposer,
                VoteType::Approve,
                ctx.now,
            )],
            rejections: Vec::new(),
            created_at_epoch: ctx.current_epoch,
        }
    }

    #[test]
    fn ingest_proposal_then_ingest_approve_reaches_quorum() {
        // 3 voters: seeded proposal carries alice's approval (1); bob's keyless
        // approval makes 2 of 3 -> absolute majority -> Approved.
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = make_unsigned_proposal(&alice(), &ctx, ProposalStatus::Pending);
        let pid = proposal.proposal_id;

        engine.ingest_proposal(proposal).expect("seed ok");
        let (status, _) = engine.ingest_approve(&pid, &bob(), &ctx).expect("ingest");
        assert_eq!(status, ProposalStatus::Approved);
    }

    #[test]
    fn ingest_proposal_preserves_terminal_status() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = make_unsigned_proposal(&alice(), &ctx, ProposalStatus::Approved);
        let pid = proposal.proposal_id;

        engine.ingest_proposal(proposal).expect("seed ok");
        let result = engine.ingest_approve(&pid, &bob(), &ctx);
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotPending { .. }
        ));
    }

    #[test]
    fn ingest_proposal_rejects_non_eligible_proposer() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        // Dave is not in the frozen eligible voter set.
        let proposal = make_unsigned_proposal(&dave(), &ctx, ProposalStatus::Pending);
        let result = engine.ingest_proposal(proposal);
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::NotEligible(_)
        ));
    }

    #[test]
    fn ingest_proposal_rejects_duplicate_id() {
        let mut engine = default_engine(three_voters());
        let ctx = test_context(&three_voters(), T0);
        let proposal = make_unsigned_proposal(&alice(), &ctx, ProposalStatus::Pending);
        let dup = proposal.clone();
        engine.ingest_proposal(proposal).expect("first seed ok");
        let result = engine.ingest_proposal(dup);
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::DuplicateProposal(_)
        ));
    }
}
