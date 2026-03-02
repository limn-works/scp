//! Majority vote governance engine (ADR-031, section 4c).
//!
//! Implements the [`GovernanceEngine`] trait for majority-vote governance.
//! A proposal passes when:
//! 1. Quorum is met: `votes_cast / eligible_voters >= min_participation`.
//! 2. Approvals exceed 50% of votes cast: `approvals > votes_cast / 2`.
//!
//! Abstentions (not voting) do not count toward or against the majority --
//! only explicit approve/reject votes are tallied. The quorum threshold
//! (`min_participation`) prevents low-turnout approvals.
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
//! When `context.now > voting_deadline`:
//! - If quorum is not met: `Rejected { InsufficientParticipation }`.
//! - If quorum is met and `approvals > rejections`: `Approved`.
//! - If quorum is met and `approvals <= rejections`: `Rejected { MajorityRejected }`.
//!
//! See `.docs/adrs/phase-6.md` ADR-031 section 4c for the full specification.

use std::collections::HashMap;

use super::{
    GovernanceAction, GovernanceContext, GovernanceEngine, GovernanceError, GovernanceEvent,
    GovernanceModelConfig, GovernanceProposal, ProposalId, ProposalStatus, RejectionReason,
    VoteType, compute_proposal_id, hex_encode, sign_vote,
};
use crate::identity::DID;

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
/// - `min_participation`: Fraction (0.0, 1.0] of eligible voters that must
///   cast a vote for the proposal to be valid.
#[derive(Debug)]
pub struct MajorityVoteEngine {
    /// The set of DIDs eligible to vote on proposals.
    eligible_voter_dids: Vec<DID>,
    /// Duration of the voting window in seconds.
    voting_window_secs: u64,
    /// Minimum participation fraction (0.0, 1.0].
    min_participation: f64,
    /// Active and resolved proposals, keyed by proposal ID.
    proposals: HashMap<ProposalId, GovernanceProposal>,
}

impl MajorityVoteEngine {
    /// Creates a new majority vote governance engine.
    ///
    /// # Arguments
    ///
    /// - `eligible_voters`: DIDs eligible to vote. Must be non-empty.
    /// - `voting_window_secs`: Voting window duration in seconds.
    ///   Must be in `[300, 604_800]` (5 minutes to 7 days).
    /// - `min_participation`: Minimum participation fraction.
    ///   Must be in `(0.0, 1.0]`.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceError::InvalidConfig`] if any parameter is out
    /// of range.
    pub fn new(
        eligible_voters: Vec<DID>,
        voting_window_secs: u64,
        min_participation: f64,
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
        if min_participation <= 0.0 || min_participation > 1.0 {
            return Err(GovernanceError::InvalidConfig(format!(
                "min_participation must be in (0.0, 1.0], got {min_participation}"
            )));
        }

        Ok(Self {
            eligible_voter_dids: eligible_voters,
            voting_window_secs,
            min_participation,
            proposals: HashMap::new(),
        })
    }

    /// Returns the minimum participation fraction.
    #[must_use]
    pub const fn min_participation(&self) -> f64 {
        self.min_participation
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
                id: hex_encode(proposal_id),
            }
        })?;

        // Only pending proposals accept vote withdrawal.
        if !proposal.status.is_pending() {
            return Err(GovernanceError::ProposalNotPending {
                status: format!("{:?}", proposal.status),
            });
        }

        // Check deadline.
        if context.now > proposal.voting_deadline {
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
                id: hex_encode(proposal_id),
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
        if context.now > proposal.voting_deadline {
            // Check quorum. Precision loss is acceptable here -- voter counts
            // will never approach 2^52 where f64 mantissa saturates.
            #[allow(clippy::cast_precision_loss)]
            let participation_fraction = participation as f64 / eligible as f64;
            if participation_fraction < self.min_participation {
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

        // Serialize action for ID computation.
        let action_bytes = serde_json::to_vec(&action)
            .map_err(|e| GovernanceError::SerializationFailed(e.to_string()))?;

        let proposal_id =
            compute_proposal_id(&context.context_id, proposer, &action_bytes, context.now);

        // Reject duplicate proposals.
        if self.proposals.contains_key(&proposal_id) {
            return Err(GovernanceError::DuplicateProposal(hex_encode(&proposal_id)));
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
            action,
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
                    id: hex_encode(proposal_id),
                }
            })?;

            if !proposal.status.is_pending() {
                return Err(GovernanceError::ProposalNotPending {
                    status: format!("{:?}", proposal.status),
                });
            }

            let expired = context.now > proposal.voting_deadline;
            if !expired && Self::has_voted(proposal, voter) {
                return Err(GovernanceError::AlreadyVoted);
            }
            expired
        };

        // Handle deadline expiry (self.resolve needs &mut self).
        if past_deadline {
            return self.resolve(proposal_id, context);
        }

        // Record the signed vote. Get mutable reference for mutation.
        let signed_vote = sign_vote(proposal_id, &VoteType::Approve, voter.as_ref(), context.now, signing_key)?;

        let proposal = self.proposals.get_mut(proposal_id).ok_or_else(|| {
            GovernanceError::ProposalNotFound {
                id: hex_encode(proposal_id),
            }
        })?;

        proposal.approvals.push(signed_vote);

        let mut events = vec![GovernanceEvent::VoteCast {
            proposal_id: *proposal_id,
            voter_did: voter.clone(),
            vote: VoteType::Approve,
        }];

        // Check for early resolution after recording the vote.
        let eligible = self.eligible_voter_dids.len();
        let approvals = proposal.approvals.len();

        // Early approval: absolute majority of all eligible voters.
        if approvals * 2 > eligible {
            proposal.status = ProposalStatus::Approved;
            events.push(GovernanceEvent::ProposalResolved {
                proposal_id: *proposal_id,
                status: ProposalStatus::Approved,
            });
        }

        Ok((proposal.status.clone(), events))
    }

    fn reject(
        &mut self,
        proposal_id: &ProposalId,
        voter: &DID,
        context: &GovernanceContext,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError> {
        // Verify voter is eligible.
        if !self.eligible_voter_dids.contains(voter) {
            return Err(GovernanceError::NotEligible(format!(
                "{voter} is not an eligible voter"
            )));
        }

        // Validate preconditions with an immutable borrow. Store deadline
        // flag so we can call self.resolve() after the borrow ends.
        let past_deadline = {
            let proposal = self.proposals.get(proposal_id).ok_or_else(|| {
                GovernanceError::ProposalNotFound {
                    id: hex_encode(proposal_id),
                }
            })?;

            if !proposal.status.is_pending() {
                return Err(GovernanceError::ProposalNotPending {
                    status: format!("{:?}", proposal.status),
                });
            }

            let expired = context.now > proposal.voting_deadline;
            if !expired && Self::has_voted(proposal, voter) {
                return Err(GovernanceError::AlreadyVoted);
            }
            expired
        };

        // Handle deadline expiry (self.resolve needs &mut self).
        if past_deadline {
            return self.resolve(proposal_id, context);
        }

        // Record the signed vote. Get mutable reference for mutation.
        let signed_vote = sign_vote(proposal_id, &VoteType::Reject, voter.as_ref(), context.now, signing_key)?;

        let proposal = self.proposals.get_mut(proposal_id).ok_or_else(|| {
            GovernanceError::ProposalNotFound {
                id: hex_encode(proposal_id),
            }
        })?;

        proposal.rejections.push(signed_vote);

        let mut events = vec![GovernanceEvent::VoteCast {
            proposal_id: *proposal_id,
            voter_did: voter.clone(),
            vote: VoteType::Reject,
        }];

        // Check for early rejection: enough rejections to make approval impossible.
        let eligible = self.eligible_voter_dids.len();
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

        Ok((proposal.status.clone(), events))
    }

    fn model_config(&self) -> GovernanceModelConfig {
        GovernanceModelConfig::Majority {
            voting_window_secs: self.voting_window_secs,
            min_participation: self.min_participation,
        }
    }

    fn eligible_voters(&self, _context: &GovernanceContext) -> Vec<DID> {
        self.eligible_voter_dids.clone()
    }

    fn get_proposal(&self, proposal_id: &ProposalId) -> Option<&GovernanceProposal> {
        self.proposals.get(proposal_id)
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
        MajorityVoteEngine::new(voters, WINDOW, 0.5).expect("valid config")
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
        let engine = MajorityVoteEngine::new(three_voters(), WINDOW, 0.5);
        assert!(engine.is_ok());
        let engine = engine.unwrap();
        assert_eq!(engine.voting_window_secs(), WINDOW);
        assert!((engine.min_participation() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn new_rejects_empty_voters() {
        let result = MajorityVoteEngine::new(vec![], WINDOW, 0.5);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::InvalidConfig(_)
        ));
    }

    #[test]
    fn new_rejects_voting_window_too_short() {
        let result = MajorityVoteEngine::new(three_voters(), 299, 0.5);
        assert!(result.is_err());
    }

    #[test]
    fn new_rejects_voting_window_too_long() {
        let result = MajorityVoteEngine::new(three_voters(), 604_801, 0.5);
        assert!(result.is_err());
    }

    #[test]
    fn new_accepts_boundary_voting_windows() {
        assert!(MajorityVoteEngine::new(three_voters(), 300, 0.5).is_ok());
        assert!(MajorityVoteEngine::new(three_voters(), 604_800, 0.5).is_ok());
    }

    #[test]
    fn new_rejects_zero_participation() {
        let result = MajorityVoteEngine::new(three_voters(), WINDOW, 0.0);
        assert!(result.is_err());
    }

    #[test]
    fn new_rejects_negative_participation() {
        let result = MajorityVoteEngine::new(three_voters(), WINDOW, -0.1);
        assert!(result.is_err());
    }

    #[test]
    fn new_rejects_participation_above_one() {
        let result = MajorityVoteEngine::new(three_voters(), WINDOW, 1.01);
        assert!(result.is_err());
    }

    #[test]
    fn new_accepts_participation_of_one() {
        assert!(MajorityVoteEngine::new(three_voters(), WINDOW, 1.0).is_ok());
    }

    #[test]
    fn new_accepts_small_participation() {
        assert!(MajorityVoteEngine::new(three_voters(), WINDOW, 0.01).is_ok());
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
        // min_participation = 0.4 (2 of 5 must vote).
        let mut engine = MajorityVoteEngine::new(voters.clone(), WINDOW, 0.4).unwrap();
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        // 2 approvals, 0 rejections. Quorum: 2/5 = 0.4 >= 0.4.
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
        // min_participation = 0.5 (3 of 5 must vote).
        let mut engine = default_engine(voters.clone());
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        // Only 2 votes cast (2/5 = 0.4 < 0.5).
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

        // 1 approve, 2 reject. Quorum met (3/5 = 0.6 >= 0.5).
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
    fn tie_goes_to_rejection_at_deadline() {
        let voters = vec![alice(), bob(), carol(), dave()]; // 4 voters
        let mut engine = MajorityVoteEngine::new(voters.clone(), WINDOW, 0.5).unwrap();
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        // 2 approvals, 2 rejections. Quorum met (4/4 = 1.0 >= 0.5).
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
        // 5 voters, quorum 0.4 (2 must vote), 2 approve, 3 abstain.
        let voters = all_five();
        let mut engine = MajorityVoteEngine::new(voters.clone(), WINDOW, 0.4).unwrap();
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        engine
            .approve(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .unwrap();

        // At deadline: 2 votes cast, quorum met (2/5=0.4>=0.4), 2 approvals > 0 rejections.
        let ctx_deadline = test_context(&voters, T0 + WINDOW + 1);
        let (status, _) = engine
            .resolve(&proposal.proposal_id, &ctx_deadline)
            .unwrap();
        assert_eq!(status, ProposalStatus::Approved);
    }

    #[test]
    fn single_vote_can_pass_with_low_quorum() {
        // 5 voters, quorum 0.2 (1 must vote).
        let voters = all_five();
        let mut engine = MajorityVoteEngine::new(voters.clone(), WINDOW, 0.2).unwrap();
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
        // 1 vote / 3 eligible = 0.33 < 0.5 quorum -> InsufficientParticipation.
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

        // Try to reject past deadline. 3 votes cast / 5 eligible = 0.6 >= 0.5 quorum.
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
                min_participation: 0.5,
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
        let mut engine = MajorityVoteEngine::new(voters.clone(), WINDOW, 1.0).unwrap();
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
        let mut engine = MajorityVoteEngine::new(voters.clone(), WINDOW, 1.0).unwrap();
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
        let mut engine = MajorityVoteEngine::new(voters.clone(), WINDOW, 0.5).unwrap();
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
        let mut engine = MajorityVoteEngine::new(voters.clone(), WINDOW, 0.5).unwrap();
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        // Bob abstains. At deadline: 1 vote cast, quorum 1/2 = 0.5 >= 0.5, 1 > 0.
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
        // min_participation = 1.0 with 5 voters. 2 approvals won't trigger early
        // resolution (need > 2.5), so we can test quorum at deadline.
        let voters = all_five();
        let mut engine = MajorityVoteEngine::new(voters.clone(), WINDOW, 1.0).unwrap();
        let ctx = test_context(&voters, T0);
        let proposal = propose_add_member(&mut engine, &alice(), &ctx, &sk_alice());

        engine
            .approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice())
            .unwrap();
        engine
            .approve(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .unwrap();
        // 2 of 5 voted, 3 abstain. Quorum: 2/5 = 0.4 < 1.0.
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
        let mut engine = MajorityVoteEngine::new(voters.clone(), WINDOW, 1.0).unwrap();
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
}
