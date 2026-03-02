//! Unanimity governance engine (ADR-031 section 4d).
//!
//! Every eligible voter must approve for a proposal to pass. A single
//! rejection vetoes the proposal immediately, setting its status to
//! [`Rejected { UnanimityBroken }`](super::RejectionReason::UnanimityBroken).
//!
//! # Resolution rules
//!
//! After each vote, `resolve()` checks:
//!
//! 1. All required voters have approved -> [`Approved`](super::ProposalStatus::Approved).
//! 2. Any required voter has rejected -> [`Rejected { UnanimityBroken }`](super::RejectionReason::UnanimityBroken).
//! 3. `now >= voting_deadline` and not all have voted -> [`Expired`](super::ProposalStatus::Expired).
//!
//! # Deadline enforcement
//!
//! `approve()`, `reject()`, and `withdraw_vote()` all reject calls after the
//! voting deadline. This prevents late votes from racing against expiry.
//!
//! # Deadlock detection and recovery
//!
//! Unanimity is inherently susceptible to deadlock: if any required voter is
//! unavailable, the proposal can never reach approval. The voting deadline
//! serves as the deadlock recovery mechanism -- when the deadline passes
//! without all votes collected, `resolve()` transitions the proposal to
//! `Expired`, unblocking the context for new proposals.

use std::collections::HashMap;

use super::{
    GovernanceAction, GovernanceContext, GovernanceEngine, GovernanceError, GovernanceEvent,
    GovernanceModelConfig, GovernanceProposal, ProposalId, ProposalStatus, RejectionReason,
    VoteType, compute_proposal_id, sign_vote,
};
use crate::identity::DID;

// ---------------------------------------------------------------------------
// UnanimityEngine
// ---------------------------------------------------------------------------

/// Unanimity governance engine.
///
/// A fixed set of required voters; a proposal passes only when **every** one
/// of them approves. A single rejection vetoes the proposal immediately.
/// Implements [`GovernanceEngine`] for use via `Box<dyn GovernanceEngine>`.
#[derive(Debug)]
pub struct UnanimityEngine {
    /// The set of DIDs required to vote (all must approve).
    voters: Vec<DID>,
    /// Voting window in seconds applied to new proposals.
    voting_window_secs: u64,
    /// Active and resolved proposals, keyed by proposal ID.
    proposals: HashMap<ProposalId, GovernanceProposal>,
}

impl UnanimityEngine {
    /// Creates a new unanimity governance engine.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceError::InvalidConfig`] if:
    /// - `voters` is empty.
    /// - `voting_window_secs` is outside `[300, 604_800]` (5 min to 7 days).
    pub fn new(voters: Vec<DID>, voting_window_secs: u64) -> Result<Self, GovernanceError> {
        if voters.is_empty() {
            return Err(GovernanceError::InvalidConfig(
                "voters must be non-empty".to_owned(),
            ));
        }
        if !(300..=604_800).contains(&voting_window_secs) {
            return Err(GovernanceError::InvalidConfig(format!(
                "voting_window_secs must be in [300, 604800], got {voting_window_secs}"
            )));
        }

        Ok(Self {
            voters,
            voting_window_secs,
            proposals: HashMap::new(),
        })
    }

    /// Returns a reference to the voter set.
    #[must_use]
    pub fn voters(&self) -> &[DID] {
        &self.voters
    }

    /// Returns the voting window in seconds.
    #[must_use]
    pub const fn voting_window_secs(&self) -> u64 {
        self.voting_window_secs
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Check whether the voter is in the required voter set.
    fn is_voter(&self, did: &DID) -> bool {
        self.voters.iter().any(|v| v == did)
    }

    /// Check whether the voter has already voted (approve or reject) on the proposal.
    fn has_voted(proposal: &GovernanceProposal, voter: &DID) -> bool {
        proposal.approvals.iter().any(|v| v.voter_did == *voter)
            || proposal.rejections.iter().any(|v| v.voter_did == *voter)
    }

    /// Evaluate the current vote tallies against the unanimity resolution rules.
    ///
    /// Returns `Some(status)` if the proposal should transition, or `None`
    /// if it remains `Pending`.
    fn evaluate_resolution(
        &self,
        proposal: &GovernanceProposal,
        now: u64,
    ) -> Option<ProposalStatus> {
        let voter_count = self.voters.len();

        // Rule 1: all required voters have approved.
        if proposal.approvals.len() == voter_count {
            return Some(ProposalStatus::Approved);
        }

        // Rule 2: any voter has rejected -> unanimity broken.
        if let Some(rejection) = proposal.rejections.first() {
            return Some(ProposalStatus::Rejected {
                reason: RejectionReason::UnanimityBroken {
                    rejector: rejection.voter_did.clone(),
                },
            });
        }

        // Rule 3: voting window expired without all votes.
        if now >= proposal.voting_deadline {
            return Some(ProposalStatus::Expired);
        }

        None
    }

    /// Internal resolve implementation: evaluates and transitions the proposal.
    ///
    /// Returns the resulting status and any events that should be recorded
    /// in the Merkle log.
    fn resolve_proposal(
        &mut self,
        proposal_id: &ProposalId,
        now: u64,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError> {
        let proposal =
            self.proposals
                .get(proposal_id)
                .ok_or_else(|| GovernanceError::ProposalNotFound {
                    id: hex::encode(proposal_id),
                })?;

        // Already terminal -- nothing to do.
        if proposal.status.is_terminal() {
            return Ok((proposal.status.clone(), Vec::new()));
        }

        let Some(new_status) = self.evaluate_resolution(proposal, now) else {
            // Still pending, no events.
            return Ok((ProposalStatus::Pending, Vec::new()));
        };

        // Transition the proposal. Key is guaranteed present because we
        // just looked it up via `get()` above and hold `&mut self`.
        if let Some(proposal_mut) = self.proposals.get_mut(proposal_id) {
            proposal_mut.status = new_status.clone();
        }

        let events = vec![GovernanceEvent::ProposalResolved {
            proposal_id: *proposal_id,
            status: new_status.clone(),
        }];

        Ok((new_status, events))
    }
}

// ---------------------------------------------------------------------------
// GovernanceEngine implementation
// ---------------------------------------------------------------------------

impl GovernanceEngine for UnanimityEngine {
    fn propose(
        &mut self,
        proposer: &DID,
        action: GovernanceAction,
        context: &GovernanceContext,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(GovernanceProposal, Vec<GovernanceEvent>), GovernanceError> {
        // Only voters can propose.
        if !self.is_voter(proposer) {
            return Err(GovernanceError::NotEligible(
                "proposer is not in the voter set".to_owned(),
            ));
        }

        // Serialize action for ID computation.
        let action_bytes = serde_json::to_vec(&action)
            .map_err(|e| GovernanceError::SerializationFailed(e.to_string()))?;

        let proposal_id =
            compute_proposal_id(&context.context_id, proposer, &action_bytes, context.now);

        // Reject duplicate proposals.
        if self.proposals.contains_key(&proposal_id) {
            return Err(GovernanceError::DuplicateProposal(hex::encode(proposal_id)));
        }

        let voting_deadline = context.now + self.voting_window_secs;

        // The proposer's vote counts as the first approval.
        let proposer_vote = sign_vote(
            &proposal_id,
            &VoteType::Approve,
            proposer.as_ref(),
            context.now,
            signing_key,
        )?;

        let proposal = GovernanceProposal {
            proposal_id,
            context_id: context.context_id.clone(),
            proposer_did: proposer.clone(),
            action: action.clone(),
            status: ProposalStatus::Pending,
            created_at: context.now,
            voting_deadline,
            approvals: vec![proposer_vote],
            rejections: Vec::new(),
            created_at_epoch: context.current_epoch,
        };

        let mut events = vec![
            GovernanceEvent::ProposalCreated {
                proposal_id,
                proposer_did: proposer.clone(),
                action,
                voting_deadline,
            },
            GovernanceEvent::VoteCast {
                proposal_id,
                voter_did: proposer.clone(),
                vote: VoteType::Approve,
            },
        ];

        self.proposals.insert(proposal_id, proposal);

        // Check if the proposer's vote alone meets unanimity (single-voter case).
        let (status, resolve_events) = self.resolve_proposal(&proposal_id, context.now)?;
        events.extend(resolve_events);

        // Re-fetch proposal after possible status change. Key is guaranteed
        // present because we inserted it above and hold `&mut self`.
        let Some(proposal) = self.proposals.get(&proposal_id).cloned() else {
            return Err(GovernanceError::ProposalNotFound {
                id: hex::encode(proposal_id),
            });
        };

        debug_assert!(
            proposal.status == status,
            "proposal status mismatch after resolve"
        );

        Ok((proposal, events))
    }

    fn approve(
        &mut self,
        proposal_id: &ProposalId,
        voter: &DID,
        context: &GovernanceContext,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError> {
        // Voter must be in the voter set.
        if !self.is_voter(voter) {
            return Err(GovernanceError::NotEligible(
                "voter is not in the voter set".to_owned(),
            ));
        }

        let proposal =
            self.proposals
                .get(proposal_id)
                .ok_or_else(|| GovernanceError::ProposalNotFound {
                    id: hex::encode(proposal_id),
                })?;

        // Must be pending.
        if !proposal.status.is_pending() {
            return Err(GovernanceError::ProposalNotPending {
                status: format!("{:?}", proposal.status),
            });
        }

        // Deadline guard -- reject votes after the voting window.
        if context.now >= proposal.voting_deadline {
            return Err(GovernanceError::VotingWindowExpired {
                id: hex::encode(proposal_id),
            });
        }

        // Must not have already voted.
        if Self::has_voted(proposal, voter) {
            return Err(GovernanceError::AlreadyVoted);
        }

        // Record the signed vote.
        let vote = sign_vote(
            proposal_id,
            &VoteType::Approve,
            voter.as_ref(),
            context.now,
            signing_key,
        )?;

        // Key is guaranteed present because we just looked it up via `get()` above.
        if let Some(proposal_mut) = self.proposals.get_mut(proposal_id) {
            proposal_mut.approvals.push(vote);
        }

        let mut events = vec![GovernanceEvent::VoteCast {
            proposal_id: *proposal_id,
            voter_did: voter.clone(),
            vote: VoteType::Approve,
        }];

        // Resolve after vote.
        let (status, resolve_events) = self.resolve_proposal(proposal_id, context.now)?;
        events.extend(resolve_events);

        Ok((status, events))
    }

    fn reject(
        &mut self,
        proposal_id: &ProposalId,
        voter: &DID,
        context: &GovernanceContext,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError> {
        // Voter must be in the voter set.
        if !self.is_voter(voter) {
            return Err(GovernanceError::NotEligible(
                "voter is not in the voter set".to_owned(),
            ));
        }

        let proposal =
            self.proposals
                .get(proposal_id)
                .ok_or_else(|| GovernanceError::ProposalNotFound {
                    id: hex::encode(proposal_id),
                })?;

        // Must be pending.
        if !proposal.status.is_pending() {
            return Err(GovernanceError::ProposalNotPending {
                status: format!("{:?}", proposal.status),
            });
        }

        // Deadline guard -- reject votes after the voting window.
        if context.now >= proposal.voting_deadline {
            return Err(GovernanceError::VotingWindowExpired {
                id: hex::encode(proposal_id),
            });
        }

        // Must not have already voted.
        if Self::has_voted(proposal, voter) {
            return Err(GovernanceError::AlreadyVoted);
        }

        // Record the signed rejection vote.
        let vote = sign_vote(
            proposal_id,
            &VoteType::Reject,
            voter.as_ref(),
            context.now,
            signing_key,
        )?;

        // Key is guaranteed present because we just looked it up via `get()` above.
        if let Some(proposal_mut) = self.proposals.get_mut(proposal_id) {
            proposal_mut.rejections.push(vote);
        }

        let mut events = vec![GovernanceEvent::VoteCast {
            proposal_id: *proposal_id,
            voter_did: voter.clone(),
            vote: VoteType::Reject,
        }];

        // Resolve after vote -- single rejection triggers immediate veto.
        let (status, resolve_events) = self.resolve_proposal(proposal_id, context.now)?;
        events.extend(resolve_events);

        Ok((status, events))
    }

    fn withdraw_vote(
        &mut self,
        proposal_id: &ProposalId,
        voter: &DID,
        context: &GovernanceContext,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError> {
        // Voter must be in the voter set.
        if !self.is_voter(voter) {
            return Err(GovernanceError::NotEligible(
                "voter is not in the voter set".to_owned(),
            ));
        }

        let proposal =
            self.proposals
                .get(proposal_id)
                .ok_or_else(|| GovernanceError::ProposalNotFound {
                    id: hex::encode(proposal_id),
                })?;

        // Must be pending.
        if !proposal.status.is_pending() {
            return Err(GovernanceError::ProposalNotPending {
                status: format!("{:?}", proposal.status),
            });
        }

        // Deadline guard: cannot withdraw after voting window.
        if context.now >= proposal.voting_deadline {
            return Err(GovernanceError::VotingWindowExpired {
                id: hex::encode(proposal_id),
            });
        }

        // Must have voted to withdraw.
        if !Self::has_voted(proposal, voter) {
            return Err(GovernanceError::NotEligible(
                "voter has not voted on this proposal".to_owned(),
            ));
        }

        // Remove the vote from whichever list it's in. Key is guaranteed
        // present because we just looked it up via `get()` above.
        if let Some(proposal_mut) = self.proposals.get_mut(proposal_id) {
            proposal_mut.approvals.retain(|v| v.voter_did != *voter);
            proposal_mut.rejections.retain(|v| v.voter_did != *voter);
        }

        // Withdrawal does not trigger resolution -- voter may re-vote.
        Ok((ProposalStatus::Pending, Vec::new()))
    }

    fn resolve(
        &mut self,
        proposal_id: &ProposalId,
        context: &GovernanceContext,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError> {
        self.resolve_proposal(proposal_id, context.now)
    }

    fn model_config(&self) -> GovernanceModelConfig {
        GovernanceModelConfig::Unanimity {
            voting_window_secs: self.voting_window_secs,
        }
    }

    fn eligible_voters(&self, _context: &GovernanceContext) -> Vec<DID> {
        self.voters.clone()
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

    fn sk_eve() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[5u8; 32])
    }

    /// Create a test context at a given timestamp.
    fn test_context_at(now: u64) -> GovernanceContext {
        GovernanceContext {
            context_id: "ctx-unanimity-001".to_owned(),
            members: vec![
                (alice(), "admin".to_owned()),
                (bob(), "member".to_owned()),
                (carol(), "member".to_owned()),
            ],
            admin_dids: vec![alice()],
            current_epoch: Some(1),
            now,
        }
    }

    fn test_context() -> GovernanceContext {
        test_context_at(1_700_000_000)
    }

    fn default_action() -> GovernanceAction {
        GovernanceAction::AddMember {
            did: dave(),
            role: "member".to_owned(),
        }
    }

    // -----------------------------------------------------------------------
    // Construction validation
    // -----------------------------------------------------------------------

    #[test]
    fn new_rejects_empty_voters() {
        let result = UnanimityEngine::new(vec![], 86_400);
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::InvalidConfig(_)
        ));
    }

    #[test]
    fn new_rejects_window_too_short() {
        let result = UnanimityEngine::new(vec![alice()], 299);
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::InvalidConfig(_)
        ));
    }

    #[test]
    fn new_rejects_window_too_long() {
        let result = UnanimityEngine::new(vec![alice()], 604_801);
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::InvalidConfig(_)
        ));
    }

    #[test]
    fn new_accepts_valid_config() {
        let engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid config");
        assert_eq!(engine.voters().len(), 3);
        assert_eq!(engine.voting_window_secs(), 86_400);
    }

    #[test]
    fn new_accepts_minimum_window() {
        let engine = UnanimityEngine::new(vec![alice()], 300).expect("valid config");
        assert_eq!(engine.voting_window_secs(), 300);
    }

    #[test]
    fn new_accepts_maximum_window() {
        let engine = UnanimityEngine::new(vec![alice()], 604_800).expect("valid config");
        assert_eq!(engine.voting_window_secs(), 604_800);
    }

    // -----------------------------------------------------------------------
    // Propose: creates pending proposal with proposer's approval
    // -----------------------------------------------------------------------

    #[test]
    fn propose_creates_pending_with_first_approval() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, events) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");

        // Proposal should be pending (3 voters, only 1 approval so far).
        assert_eq!(proposal.status, ProposalStatus::Pending);
        assert_eq!(proposal.approvals.len(), 1);
        assert_eq!(proposal.approvals[0].voter_did, alice());
        assert!(proposal.rejections.is_empty());
        assert_eq!(proposal.voting_deadline, ctx.now + 86_400);

        // Events: ProposalCreated + VoteCast (no resolve yet).
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], GovernanceEvent::ProposalCreated { .. }));
        assert!(matches!(events[1], GovernanceEvent::VoteCast { .. }));
    }

    #[test]
    fn propose_single_voter_auto_resolves() {
        let mut engine = UnanimityEngine::new(vec![alice()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, events) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");

        // 1-of-1: proposer's approval meets unanimity immediately.
        assert_eq!(proposal.status, ProposalStatus::Approved);
        assert_eq!(events.len(), 3); // Created + VoteCast + Resolved
        assert!(matches!(
            events[2],
            GovernanceEvent::ProposalResolved {
                status: ProposalStatus::Approved,
                ..
            }
        ));
    }

    #[test]
    fn propose_rejects_non_voter() {
        let mut engine = UnanimityEngine::new(vec![alice(), bob()], 86_400).expect("valid");
        let ctx = test_context();

        let result = engine.propose(&dave(), default_action(), &ctx, &sk_dave());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::NotEligible(_)
        ));
    }

    #[test]
    fn propose_rejects_duplicate() {
        let mut engine = UnanimityEngine::new(vec![alice(), bob()], 86_400).expect("valid");
        let ctx = test_context();

        let _ = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let result = engine.propose(&alice(), default_action(), &ctx, &sk_alice());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::DuplicateProposal(_)
        ));
    }

    // -----------------------------------------------------------------------
    // Approve: all voters approve -> Approved (unanimity)
    // -----------------------------------------------------------------------

    #[test]
    fn approve_all_voters_reaches_unanimity() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Bob approves -> 2 of 3 -> still pending.
        let (status, events) = engine.approve(&pid, &bob(), &ctx, &sk_bob()).expect("ok");
        assert_eq!(status, ProposalStatus::Pending);
        assert_eq!(events.len(), 1); // VoteCast only, no resolve

        // Carol approves -> 3 of 3 -> Approved.
        let (status, events) = engine
            .approve(&pid, &carol(), &ctx, &sk_carol())
            .expect("ok");
        assert_eq!(status, ProposalStatus::Approved);
        assert_eq!(events.len(), 2); // VoteCast + Resolved
        assert!(matches!(
            events[1],
            GovernanceEvent::ProposalResolved {
                status: ProposalStatus::Approved,
                ..
            }
        ));
    }

    #[test]
    fn approve_rejects_non_voter() {
        let mut engine = UnanimityEngine::new(vec![alice(), bob()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let result = engine.approve(&proposal.proposal_id, &dave(), &ctx, &sk_dave());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::NotEligible(_)
        ));
    }

    #[test]
    fn approve_rejects_duplicate_vote() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        // Alice already voted (as proposer).
        let result = engine.approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice());
        assert!(matches!(result.unwrap_err(), GovernanceError::AlreadyVoted));
    }

    #[test]
    fn approve_rejects_on_resolved_proposal() {
        let mut engine = UnanimityEngine::new(vec![alice()], 86_400).expect("valid");
        let ctx = test_context();

        // Single voter -> auto-approved.
        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let result = engine.approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotPending { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Reject: single rejection vetoes immediately (unanimity broken)
    // -----------------------------------------------------------------------

    #[test]
    fn reject_single_vote_vetoes_proposal() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Bob rejects -> unanimity broken immediately.
        let (status, events) = engine.reject(&pid, &bob(), &ctx, &sk_bob()).expect("ok");
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::UnanimityBroken { rejector: bob() }
            }
        );
        // Events: VoteCast + Resolved.
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], GovernanceEvent::VoteCast { .. }));
        assert!(matches!(
            &events[1],
            GovernanceEvent::ProposalResolved {
                status: ProposalStatus::Rejected { reason: RejectionReason::UnanimityBroken { rejector } },
                ..
            } if *rejector == bob()
        ));
    }

    #[test]
    fn reject_after_some_approvals_still_vetoes() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Bob approves -> 2 of 3.
        let (status, _) = engine.approve(&pid, &bob(), &ctx, &sk_bob()).expect("ok");
        assert_eq!(status, ProposalStatus::Pending);

        // Carol rejects -> unanimity broken despite 2 approvals.
        let (status, _) = engine
            .reject(&pid, &carol(), &ctx, &sk_carol())
            .expect("ok");
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::UnanimityBroken { rejector: carol() }
            }
        );
    }

    #[test]
    fn reject_rejects_non_voter() {
        let mut engine = UnanimityEngine::new(vec![alice(), bob()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let result = engine.reject(&proposal.proposal_id, &dave(), &ctx, &sk_dave());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::NotEligible(_)
        ));
    }

    #[test]
    fn reject_rejects_duplicate_vote() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        // Alice already voted (as proposer); trying to reject should fail.
        let result = engine.reject(&proposal.proposal_id, &alice(), &ctx, &sk_alice());
        assert!(matches!(result.unwrap_err(), GovernanceError::AlreadyVoted));
    }

    #[test]
    fn reject_on_resolved_proposal_fails() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Bob rejects -> vetoed.
        engine.reject(&pid, &bob(), &ctx, &sk_bob()).expect("ok");

        // Carol tries to reject on already-resolved proposal.
        let result = engine.reject(&pid, &carol(), &ctx, &sk_carol());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotPending { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Deadline enforcement: votes rejected after voting deadline
    // -----------------------------------------------------------------------

    #[test]
    fn approve_rejected_after_deadline() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        let expired_ctx = test_context_at(ctx.now + 86_400);

        let result = engine.approve(&pid, &bob(), &expired_ctx, &sk_bob());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::VotingWindowExpired { .. }
        ));
    }

    #[test]
    fn reject_rejected_after_deadline() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        let expired_ctx = test_context_at(ctx.now + 86_400);

        let result = engine.reject(&pid, &bob(), &expired_ctx, &sk_bob());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::VotingWindowExpired { .. }
        ));
    }

    #[test]
    fn approve_accepted_just_before_deadline() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // One second before deadline should still work.
        let just_before = test_context_at(ctx.now + 86_400 - 1);

        let result = engine.approve(&pid, &bob(), &just_before, &sk_bob());
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Deadlock detection: resolve() after deadline expires proposal
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_expires_proposal_after_deadline() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Advance time past the deadline.
        let expired_ctx = test_context_at(ctx.now + 86_400);

        let (status, events) = engine.resolve(&pid, &expired_ctx).expect("ok");
        assert_eq!(status, ProposalStatus::Expired);

        // Must produce a ProposalResolved event for Merkle log recording.
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0],
            GovernanceEvent::ProposalResolved {
                status: ProposalStatus::Expired,
                ..
            }
        ));
    }

    #[test]
    fn resolve_no_events_when_still_pending() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Same time -- not expired, not enough votes.
        let (status, events) = engine.resolve(&pid, &ctx).expect("ok");
        assert_eq!(status, ProposalStatus::Pending);
        assert!(events.is_empty());
    }

    #[test]
    fn resolve_returns_terminal_status_with_no_events_for_already_resolved() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Bob rejects -> vetoed.
        engine.reject(&pid, &bob(), &ctx, &sk_bob()).expect("ok");

        // Resolve again on already-resolved proposal.
        let (status, events) = engine.resolve(&pid, &ctx).expect("ok");
        assert!(matches!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::UnanimityBroken { .. }
            }
        ));
        assert!(events.is_empty(), "no events for already-terminal proposal");
    }

    #[test]
    fn resolve_partial_votes_at_deadline_expires() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Bob approves -> 2 of 3.
        engine.approve(&pid, &bob(), &ctx, &sk_bob()).expect("ok");

        // Carol never votes. Deadline passes.
        let expired_ctx = test_context_at(ctx.now + 86_400);
        let (status, events) = engine.resolve(&pid, &expired_ctx).expect("ok");
        assert_eq!(status, ProposalStatus::Expired);
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn resolve_unknown_proposal_returns_error() {
        let mut engine = UnanimityEngine::new(vec![alice(), bob()], 86_400).expect("valid");
        let ctx = test_context();
        let fake_id = [0u8; 32];

        let result = engine.resolve(&fake_id, &ctx);
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotFound { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Vote withdrawal
    // -----------------------------------------------------------------------

    #[test]
    fn withdraw_vote_allows_revote() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Alice withdraws her approval.
        let (status, _) = engine.withdraw_vote(&pid, &alice(), &ctx).expect("ok");
        assert_eq!(status, ProposalStatus::Pending);

        // Verify the vote is gone.
        let p = engine.get_proposal(&pid).expect("found");
        assert!(p.approvals.is_empty());

        // Alice can now re-vote (as a rejection this time).
        let (status, _) = engine
            .reject(&pid, &alice(), &ctx, &sk_alice())
            .expect("ok");
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::UnanimityBroken { rejector: alice() }
            }
        );
    }

    #[test]
    fn withdraw_rejection_allows_revote_as_approval() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Note: rejection normally vetoes immediately, but we test withdrawal
        // on approval then re-approve to exercise the path. Let's withdraw
        // Alice's approval, reject, then withdraw the rejection, then approve.
        engine.withdraw_vote(&pid, &alice(), &ctx).expect("ok");

        // The proposal is still pending (no votes).
        let p = engine.get_proposal(&pid).expect("found");
        assert!(p.approvals.is_empty());
        assert!(p.rejections.is_empty());

        // Alice re-approves.
        let (status, _) = engine
            .approve(&pid, &alice(), &ctx, &sk_alice())
            .expect("ok");
        assert_eq!(status, ProposalStatus::Pending);
    }

    #[test]
    fn withdraw_vote_rejects_non_voter() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Bob hasn't voted yet.
        let result = engine.withdraw_vote(&pid, &bob(), &ctx);
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::NotEligible(_)
        ));
    }

    #[test]
    fn withdraw_vote_rejects_non_member() {
        let mut engine = UnanimityEngine::new(vec![alice(), bob()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let result = engine.withdraw_vote(&proposal.proposal_id, &dave(), &ctx);
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::NotEligible(_)
        ));
    }

    #[test]
    fn withdraw_vote_rejects_after_deadline() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        let expired_ctx = test_context_at(ctx.now + 86_400);
        let result = engine.withdraw_vote(&pid, &alice(), &expired_ctx);
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::VotingWindowExpired { .. }
        ));
    }

    #[test]
    fn withdraw_vote_rejects_on_resolved_proposal() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Bob rejects -> vetoed.
        engine.reject(&pid, &bob(), &ctx, &sk_bob()).expect("ok");

        // Cannot withdraw on resolved proposal.
        let result = engine.withdraw_vote(&pid, &alice(), &ctx);
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotPending { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Trait object compatibility (Send + Sync, Box<dyn GovernanceEngine>)
    // -----------------------------------------------------------------------

    #[test]
    fn unanimity_engine_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<UnanimityEngine>();
    }

    #[test]
    fn withdraw_vote_accessible_via_trait() {
        let engine = UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let mut boxed: Box<dyn GovernanceEngine> = Box::new(engine);
        let ctx = test_context();

        let (proposal, _) = boxed
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // withdraw_vote is callable through the trait object.
        let result = boxed.withdraw_vote(&pid, &alice(), &ctx);
        assert!(result.is_ok());

        let (status, _) = result.unwrap();
        assert_eq!(status, ProposalStatus::Pending);
    }

    #[test]
    fn resolve_accessible_via_trait() {
        let engine = UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let mut boxed: Box<dyn GovernanceEngine> = Box::new(engine);
        let ctx = test_context();

        let (proposal, _) = boxed
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // resolve is callable through the trait object.
        let result = boxed.resolve(&pid, &ctx);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // model_config and eligible_voters
    // -----------------------------------------------------------------------

    #[test]
    fn model_config_returns_unanimity_variant() {
        let engine = UnanimityEngine::new(vec![alice(), bob()], 172_800).expect("valid");
        let config = engine.model_config();
        assert_eq!(
            config,
            GovernanceModelConfig::Unanimity {
                voting_window_secs: 172_800,
            }
        );
    }

    #[test]
    fn eligible_voters_returns_voter_set() {
        let engine = UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();
        let voters = engine.eligible_voters(&ctx);
        assert_eq!(voters, vec![alice(), bob(), carol()]);
    }

    // -----------------------------------------------------------------------
    // Unknown proposal ID
    // -----------------------------------------------------------------------

    #[test]
    fn approve_unknown_proposal() {
        let mut engine = UnanimityEngine::new(vec![alice(), bob()], 86_400).expect("valid");
        let ctx = test_context();
        let fake_id = [0u8; 32];

        let result = engine.approve(&fake_id, &alice(), &ctx, &sk_alice());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotFound { .. }
        ));
    }

    #[test]
    fn reject_unknown_proposal() {
        let mut engine = UnanimityEngine::new(vec![alice(), bob()], 86_400).expect("valid");
        let ctx = test_context();
        let fake_id = [0u8; 32];

        let result = engine.reject(&fake_id, &alice(), &ctx, &sk_alice());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotFound { .. }
        ));
    }

    #[test]
    fn withdraw_vote_unknown_proposal() {
        let mut engine = UnanimityEngine::new(vec![alice(), bob()], 86_400).expect("valid");
        let ctx = test_context();
        let fake_id = [0u8; 32];

        let result = engine.withdraw_vote(&fake_id, &alice(), &ctx);
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotFound { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Full lifecycle tests
    // -----------------------------------------------------------------------

    #[test]
    fn full_lifecycle_3_of_3_unanimous_approval() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        // 1. Alice proposes (counts as first approval).
        let (proposal, create_events) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        assert_eq!(proposal.status, ProposalStatus::Pending);
        assert_eq!(create_events.len(), 2); // Created + VoteCast

        // 2. Bob approves.
        let (status, approve_events) = engine
            .approve(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .expect("ok");
        assert_eq!(status, ProposalStatus::Pending);
        assert_eq!(approve_events.len(), 1); // VoteCast only

        // 3. Carol approves -> unanimity.
        let (status, final_events) = engine
            .approve(&proposal.proposal_id, &carol(), &ctx, &sk_carol())
            .expect("ok");
        assert_eq!(status, ProposalStatus::Approved);
        assert_eq!(final_events.len(), 2); // VoteCast + Resolved

        // 4. Verify stored proposal.
        let stored = engine.get_proposal(&proposal.proposal_id).expect("found");
        assert_eq!(stored.status, ProposalStatus::Approved);
        assert_eq!(stored.approvals.len(), 3);
        assert!(stored.rejections.is_empty());
    }

    #[test]
    fn full_lifecycle_veto_by_single_rejection() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Bob rejects -> immediate veto.
        let (status, _) = engine.reject(&pid, &bob(), &ctx, &sk_bob()).expect("ok");
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::UnanimityBroken { rejector: bob() }
            }
        );

        // Carol cannot vote on resolved proposal.
        let result = engine.approve(&pid, &carol(), &ctx, &sk_carol());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotPending { .. }
        ));

        // Verify stored proposal.
        let stored = engine.get_proposal(&pid).expect("found");
        assert!(stored.status.is_terminal());
        assert_eq!(stored.rejections.len(), 1);
        assert_eq!(stored.rejections[0].voter_did, bob());
    }

    #[test]
    fn full_lifecycle_expiry() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Advance time past deadline.
        let expired_ctx = test_context_at(ctx.now + 86_400);

        // resolve() triggers expiry (deadlock recovery).
        let (status, events) = engine.resolve(&pid, &expired_ctx).expect("ok");
        assert_eq!(status, ProposalStatus::Expired);
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn full_lifecycle_withdraw_and_revote() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Bob approves.
        engine.approve(&pid, &bob(), &ctx, &sk_bob()).expect("ok");

        // Bob changes mind: withdraw, then reject.
        engine.withdraw_vote(&pid, &bob(), &ctx).expect("ok");
        let p = engine.get_proposal(&pid).expect("found");
        assert_eq!(p.approvals.len(), 1); // Only Alice's approval remains.

        let (status, _) = engine.reject(&pid, &bob(), &ctx, &sk_bob()).expect("ok");
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::UnanimityBroken { rejector: bob() }
            }
        );
    }

    // -----------------------------------------------------------------------
    // Five-voter scenarios
    // -----------------------------------------------------------------------

    #[test]
    fn five_voters_all_approve() {
        let voters = vec![alice(), bob(), carol(), dave(), eve()];
        let mut engine = UnanimityEngine::new(voters, 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        engine.approve(&pid, &bob(), &ctx, &sk_bob()).expect("ok");
        engine
            .approve(&pid, &carol(), &ctx, &sk_carol())
            .expect("ok");
        engine.approve(&pid, &dave(), &ctx, &sk_dave()).expect("ok");
        let (status, _) = engine.approve(&pid, &eve(), &ctx, &sk_eve()).expect("ok");

        assert_eq!(status, ProposalStatus::Approved);
    }

    #[test]
    fn five_voters_one_rejects_after_three_approvals() {
        let voters = vec![alice(), bob(), carol(), dave(), eve()];
        let mut engine = UnanimityEngine::new(voters, 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        engine.approve(&pid, &bob(), &ctx, &sk_bob()).expect("ok");
        engine
            .approve(&pid, &carol(), &ctx, &sk_carol())
            .expect("ok");

        // Dave rejects despite 3 approvals so far.
        let (status, _) = engine.reject(&pid, &dave(), &ctx, &sk_dave()).expect("ok");
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::UnanimityBroken { rejector: dave() }
            }
        );
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn get_proposal_returns_none_for_missing() {
        let engine = UnanimityEngine::new(vec![alice(), bob()], 86_400).expect("valid");
        let fake_id = [0u8; 32];
        assert!(engine.get_proposal(&fake_id).is_none());
    }

    #[test]
    fn proposal_records_correct_epoch() {
        let mut engine = UnanimityEngine::new(vec![alice(), bob()], 86_400).expect("valid");
        let mut ctx = test_context();
        ctx.current_epoch = Some(42);

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        assert_eq!(proposal.created_at_epoch, Some(42));
    }

    #[test]
    fn proposal_events_contain_correct_voting_deadline() {
        let mut engine = UnanimityEngine::new(vec![alice(), bob()], 3600).expect("valid");
        let ctx = test_context();

        let (_, events) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");

        match &events[0] {
            GovernanceEvent::ProposalCreated {
                voting_deadline, ..
            } => {
                assert_eq!(*voting_deadline, ctx.now + 3600);
            }
            _ => panic!("expected ProposalCreated event"),
        }
    }

    #[test]
    fn two_voters_both_must_approve() {
        let mut engine = UnanimityEngine::new(vec![alice(), bob()], 86_400).expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Only Alice has approved (as proposer) -> still pending.
        assert_eq!(proposal.status, ProposalStatus::Pending);

        // Bob approves -> 2 of 2 -> unanimity.
        let (status, _) = engine.approve(&pid, &bob(), &ctx, &sk_bob()).expect("ok");
        assert_eq!(status, ProposalStatus::Approved);
    }
}
