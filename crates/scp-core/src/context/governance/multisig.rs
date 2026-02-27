//! Multi-sig (M-of-N threshold) governance engine (ADR-031 section 4b).
//!
//! Implements [`GovernanceEngine`] for the `Threshold` governance model.
//! A fixed set of designated signers vote on proposals; a proposal passes
//! when at least `threshold` (M) of the `signers` (N) approve.
//!
//! # Resolution rules
//!
//! After every vote, [`ThresholdEngine::resolve`] checks:
//!
//! - **Approved**: `approvals.len() >= threshold`.
//! - **Rejected (impossible)**: `rejections.len() > signers.len() - threshold`
//!   (mathematically impossible to reach threshold).
//! - **Expired**: `now > voting_deadline` and neither condition met.
//!
//! # Vote semantics
//!
//! - Votes are order-independent -- the Mth approval resolves the proposal
//!   regardless of arrival order.
//! - Only DIDs in the `signers` set can vote.
//! - A signer can withdraw their vote while the proposal is `Pending` via
//!   [`ThresholdEngine::withdraw_vote`].
//! - Each signer casts at most one active vote (approve or reject) at a time.
//!
//! # UCAN authorization
//!
//! The proposer must hold the `GovernancePropose` capability and voters must
//! hold the `GovernanceVote` capability. Authorization validation is performed
//! by the caller (typically the `ContextManager`) before invoking engine
//! methods. The engine validates structural eligibility (signer set membership).
//!
//! # Merkle log recording
//!
//! Every operation returns a `Vec<GovernanceEvent>` for the caller to append
//! to the context's event log (Merkle log). Events cover: proposal creation,
//! vote cast, vote withdrawal, and proposal resolution.
//!
//! See ADR-031 in `.docs/adrs/phase-6.md` for the full specification.

use std::collections::HashMap;

use super::{
    compute_proposal_id, hex_encode, GovernanceAction, GovernanceContext, GovernanceEngine,
    GovernanceError, GovernanceEvent, GovernanceModelConfig, GovernanceProposal, ProposalId,
    ProposalStatus, RejectionReason, SignedVote, VoteType,
};
use crate::identity::DID;

// ---------------------------------------------------------------------------
// Configuration constants (ADR-031 section 2)
// ---------------------------------------------------------------------------

/// Minimum allowed voting window (5 minutes).
const MIN_VOTING_WINDOW_SECS: u64 = 300;

/// Maximum allowed voting window (7 days).
const MAX_VOTING_WINDOW_SECS: u64 = 604_800;

/// Default voting window (24 hours).
const DEFAULT_VOTING_WINDOW_SECS: u64 = 86_400;

// ---------------------------------------------------------------------------
// ThresholdEngine
// ---------------------------------------------------------------------------

/// Multi-sig (M-of-N) governance engine (ADR-031 section 4b).
///
/// A fixed set of `signers` vote on governance proposals. A proposal is
/// approved when at least `threshold` signers approve. The signer set and
/// threshold are configured at context creation and encoded in
/// [`GovernanceModelConfig::Threshold`].
///
/// # Construction
///
/// Use [`ThresholdEngine::new`] to create an engine, which validates the
/// configuration constraints:
///
/// - `signers` must be non-empty.
/// - `threshold` must be in `[1, signers.len()]`.
/// - `voting_window_secs` must be in `[300, 604_800]`.
///
/// # Thread safety
///
/// `ThresholdEngine` is `Send + Sync` (all fields are owned, `HashMap` is
/// `Send + Sync` when keys and values are).
#[derive(Debug)]
pub struct ThresholdEngine {
    /// The set of DIDs authorized to vote.
    signers: Vec<DID>,
    /// Minimum number of approvals required.
    threshold: u32,
    /// Voting window in seconds.
    voting_window_secs: u64,
    /// Active and resolved proposals, keyed by proposal ID.
    proposals: HashMap<ProposalId, GovernanceProposal>,
}

impl ThresholdEngine {
    /// Creates a new threshold governance engine.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceError::InvalidConfig`] if:
    /// - `signers` is empty.
    /// - `threshold` is zero or exceeds `signers.len()`.
    /// - `voting_window_secs` is outside `[300, 604_800]`.
    /// - `signers` contains duplicates.
    pub fn new(
        signers: Vec<DID>,
        threshold: u32,
        voting_window_secs: u64,
    ) -> Result<Self, GovernanceError> {
        Self::validate_config(&signers, threshold, voting_window_secs)?;
        Ok(Self {
            signers,
            threshold,
            voting_window_secs,
            proposals: HashMap::new(),
        })
    }

    /// Creates a threshold engine with the default voting window (24 hours).
    ///
    /// # Errors
    ///
    /// Same as [`ThresholdEngine::new`].
    pub fn with_default_window(
        signers: Vec<DID>,
        threshold: u32,
    ) -> Result<Self, GovernanceError> {
        Self::new(signers, threshold, DEFAULT_VOTING_WINDOW_SECS)
    }

    /// Returns a reference to the signer set.
    #[must_use]
    pub fn signers(&self) -> &[DID] {
        &self.signers
    }

    /// Returns the approval threshold.
    #[must_use]
    pub const fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Returns the voting window in seconds.
    #[must_use]
    pub const fn voting_window_secs(&self) -> u64 {
        self.voting_window_secs
    }

    /// Withdraw a previously cast vote (approval or rejection).
    ///
    /// Only the original voter can withdraw their vote. Only valid while the
    /// proposal is `Pending`. Returns the updated proposal status and events
    /// for Merkle log recording.
    ///
    /// Per ADR-031 section 4b: "A signer can withdraw their vote and re-vote
    /// (changing from approve to reject or vice versa) while the proposal is
    /// Pending."
    ///
    /// # Errors
    ///
    /// - [`GovernanceError::ProposalNotFound`] if no proposal with `proposal_id` exists.
    /// - [`GovernanceError::ProposalNotPending`] if the proposal has already resolved.
    /// - [`GovernanceError::NotEligible`] if the voter has no active vote to withdraw.
    pub fn withdraw_vote(
        &mut self,
        proposal_id: &ProposalId,
        voter: &DID,
        _context: &GovernanceContext,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError> {
        let proposal = self.proposals.get_mut(proposal_id).ok_or_else(|| {
            GovernanceError::ProposalNotFound {
                id: hex_encode(proposal_id),
            }
        })?;

        if !proposal.status.is_pending() {
            return Err(GovernanceError::ProposalNotPending {
                status: format!("{:?}", proposal.status),
            });
        }

        // Remove the voter's vote from approvals or rejections.
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
            return Err(GovernanceError::NotEligible(
                "voter has no active vote to withdraw".to_owned(),
            ));
        }

        let events = vec![GovernanceEvent::VoteWithdrawn {
            proposal_id: *proposal_id,
            voter_did: voter.clone(),
        }];

        Ok((proposal.status.clone(), events))
    }

    /// Check whether a proposal has reached resolution.
    ///
    /// Called after each vote and periodically by the SDK's timeout task.
    /// Transitions the proposal to `Approved`, `Rejected`, or `Expired`
    /// based on the current vote tally and the voting deadline.
    ///
    /// # Errors
    ///
    /// - [`GovernanceError::ProposalNotFound`] if no proposal with `proposal_id` exists.
    pub fn resolve(
        &mut self,
        proposal_id: &ProposalId,
        context: &GovernanceContext,
    ) -> Result<ProposalStatus, GovernanceError> {
        let signers_count = self.signers.len();
        let threshold = self.threshold;

        let proposal = self.proposals.get_mut(proposal_id).ok_or_else(|| {
            GovernanceError::ProposalNotFound {
                id: hex_encode(proposal_id),
            }
        })?;

        if !proposal.status.is_pending() {
            return Ok(proposal.status.clone());
        }

        let approvals = proposal.approvals.len();
        let rejections = proposal.rejections.len();

        // Check if threshold is met.
        if approvals >= threshold as usize {
            proposal.status = ProposalStatus::Approved;
        }
        // Check if approval is mathematically impossible.
        // If rejections > signers - threshold, even if all remaining signers
        // approve, the threshold cannot be reached.
        else if rejections > signers_count - threshold as usize {
            proposal.status = ProposalStatus::Rejected {
                reason: RejectionReason::ApprovalImpossible,
            };
        }
        // Check if voting window has expired.
        else if context.now > proposal.voting_deadline {
            proposal.status = ProposalStatus::Expired;
        }

        Ok(proposal.status.clone())
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Validate configuration constraints per ADR-031 section 2.
    fn validate_config(
        signers: &[DID],
        threshold: u32,
        voting_window_secs: u64,
    ) -> Result<(), GovernanceError> {
        if signers.is_empty() {
            return Err(GovernanceError::InvalidConfig(
                "signers must be non-empty".to_owned(),
            ));
        }

        if threshold == 0 {
            return Err(GovernanceError::InvalidConfig(
                "threshold must be at least 1".to_owned(),
            ));
        }

        if (threshold as usize) > signers.len() {
            return Err(GovernanceError::InvalidConfig(format!(
                "threshold ({threshold}) exceeds signer count ({})",
                signers.len()
            )));
        }

        if voting_window_secs < MIN_VOTING_WINDOW_SECS {
            return Err(GovernanceError::InvalidConfig(format!(
                "voting_window_secs ({voting_window_secs}) is below minimum ({MIN_VOTING_WINDOW_SECS})"
            )));
        }

        if voting_window_secs > MAX_VOTING_WINDOW_SECS {
            return Err(GovernanceError::InvalidConfig(format!(
                "voting_window_secs ({voting_window_secs}) exceeds maximum ({MAX_VOTING_WINDOW_SECS})"
            )));
        }

        // Check for duplicate signers.
        let mut seen = std::collections::HashSet::new();
        for signer in signers {
            if !seen.insert(signer) {
                return Err(GovernanceError::InvalidConfig(format!(
                    "duplicate signer: {signer}"
                )));
            }
        }

        Ok(())
    }

    /// Returns `true` if the given DID is in the signer set.
    fn is_signer(&self, did: &DID) -> bool {
        self.signers.iter().any(|s| s == did)
    }

    /// Returns `true` if the voter already has an active vote on the proposal.
    fn has_voted(proposal: &GovernanceProposal, voter: &DID) -> bool {
        proposal.approvals.iter().any(|v| v.voter_did == *voter)
            || proposal.rejections.iter().any(|v| v.voter_did == *voter)
    }

    /// Attempt to resolve a proposal after a vote was cast. Returns resolution
    /// events if the proposal transitions to a terminal state.
    fn try_resolve_after_vote(
        &mut self,
        proposal_id: &ProposalId,
        context: &GovernanceContext,
    ) -> Vec<GovernanceEvent> {
        let signers_count = self.signers.len();
        let threshold = self.threshold as usize;

        let Some(proposal) = self.proposals.get_mut(proposal_id) else {
            return Vec::new();
        };

        if !proposal.status.is_pending() {
            return Vec::new();
        }

        let approvals = proposal.approvals.len();
        let rejections = proposal.rejections.len();

        let new_status = if approvals >= threshold {
            Some(ProposalStatus::Approved)
        } else if rejections > signers_count - threshold {
            Some(ProposalStatus::Rejected {
                reason: RejectionReason::ApprovalImpossible,
            })
        } else if context.now > proposal.voting_deadline {
            Some(ProposalStatus::Expired)
        } else {
            None
        };

        if let Some(status) = new_status {
            proposal.status = status.clone();
            return vec![GovernanceEvent::ProposalResolved {
                proposal_id: *proposal_id,
                status,
            }];
        }

        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// GovernanceEngine implementation
// ---------------------------------------------------------------------------

impl GovernanceEngine for ThresholdEngine {
    fn propose(
        &mut self,
        proposer: &DID,
        action: GovernanceAction,
        context: &GovernanceContext,
    ) -> Result<(GovernanceProposal, Vec<GovernanceEvent>), GovernanceError> {
        // Structural eligibility: proposer must be in the signer set.
        // UCAN `GovernancePropose` capability validation is the caller's
        // responsibility (per ADR-031 section 6).
        if !self.is_signer(proposer) {
            return Err(GovernanceError::NotEligible(
                "proposer is not in the signer set".to_owned(),
            ));
        }

        // Serialize action for ID computation.
        let action_bytes = serde_json::to_vec(&action)
            .map_err(|e| GovernanceError::SerializationFailed(e.to_string()))?;

        let proposal_id = compute_proposal_id(
            &context.context_id,
            proposer,
            &action_bytes,
            context.now,
        );

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
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError> {
        // Structural eligibility: voter must be in the signer set.
        if !self.is_signer(voter) {
            return Err(GovernanceError::NotEligible(
                "voter is not in the signer set".to_owned(),
            ));
        }

        // Get mutable access for validation and vote insertion in one borrow.
        let proposal = self.proposals.get_mut(proposal_id).ok_or_else(|| {
            GovernanceError::ProposalNotFound {
                id: hex_encode(proposal_id),
            }
        })?;

        if !proposal.status.is_pending() {
            return Err(GovernanceError::ProposalNotPending {
                status: format!("{:?}", proposal.status),
            });
        }

        // Check for duplicate vote.
        if Self::has_voted(proposal, voter) {
            return Err(GovernanceError::AlreadyVoted);
        }

        // Cast the vote.
        proposal.approvals.push(SignedVote {
            voter_did: voter.clone(),
            vote: VoteType::Approve,
            timestamp: context.now,
            signature: Vec::new(), // Signature validation deferred to UCAN layer.
        });

        let mut events = vec![GovernanceEvent::VoteCast {
            proposal_id: *proposal_id,
            voter_did: voter.clone(),
            vote: VoteType::Approve,
        }];

        // Try to resolve after the vote.
        let resolution_events = self.try_resolve_after_vote(proposal_id, context);
        events.extend(resolution_events);

        let status = self
            .proposals
            .get(proposal_id)
            .map_or(ProposalStatus::Pending, |p| p.status.clone());

        Ok((status, events))
    }

    fn reject(
        &mut self,
        proposal_id: &ProposalId,
        voter: &DID,
        context: &GovernanceContext,
    ) -> Result<(ProposalStatus, Vec<GovernanceEvent>), GovernanceError> {
        // Structural eligibility: voter must be in the signer set.
        if !self.is_signer(voter) {
            return Err(GovernanceError::NotEligible(
                "voter is not in the signer set".to_owned(),
            ));
        }

        // Get mutable access for validation and vote insertion in one borrow.
        let proposal = self.proposals.get_mut(proposal_id).ok_or_else(|| {
            GovernanceError::ProposalNotFound {
                id: hex_encode(proposal_id),
            }
        })?;

        if !proposal.status.is_pending() {
            return Err(GovernanceError::ProposalNotPending {
                status: format!("{:?}", proposal.status),
            });
        }

        // Check for duplicate vote.
        if Self::has_voted(proposal, voter) {
            return Err(GovernanceError::AlreadyVoted);
        }

        // Cast the rejection vote.
        proposal.rejections.push(SignedVote {
            voter_did: voter.clone(),
            vote: VoteType::Reject,
            timestamp: context.now,
            signature: Vec::new(), // Signature validation deferred to UCAN layer.
        });

        let mut events = vec![GovernanceEvent::VoteCast {
            proposal_id: *proposal_id,
            voter_did: voter.clone(),
            vote: VoteType::Reject,
        }];

        // Try to resolve after the vote.
        let resolution_events = self.try_resolve_after_vote(proposal_id, context);
        events.extend(resolution_events);

        let status = self
            .proposals
            .get(proposal_id)
            .map_or(ProposalStatus::Pending, |p| p.status.clone());

        Ok((status, events))
    }

    fn model_config(&self) -> GovernanceModelConfig {
        GovernanceModelConfig::Threshold {
            signers: self.signers.clone(),
            threshold: self.threshold,
            voting_window_secs: self.voting_window_secs,
        }
    }

    fn eligible_voters(&self, _context: &GovernanceContext) -> Vec<DID> {
        self.signers.clone()
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

    fn signers_3() -> Vec<DID> {
        vec![alice(), bob(), carol()]
    }

    fn signers_5() -> Vec<DID> {
        vec![alice(), bob(), carol(), dave(), eve()]
    }

    /// Create a governance context with the given members as signers.
    fn threshold_context(signers: &[DID], now: u64) -> GovernanceContext {
        GovernanceContext {
            context_id: "ctx-threshold-001".to_owned(),
            members: signers
                .iter()
                .map(|d| (d.clone(), "signer".to_owned()))
                .collect(),
            admin_dids: signers.to_vec(),
            current_epoch: Some(1),
            now,
        }
    }

    fn add_member_action() -> GovernanceAction {
        GovernanceAction::AddMember {
            did: DID::from("did:dht:z6MkNewMember"),
            role: "member".to_owned(),
        }
    }

    fn close_context_action() -> GovernanceAction {
        GovernanceAction::CloseContext {
            reason: Some("test closure".to_owned()),
        }
    }

    // -----------------------------------------------------------------------
    // Construction and validation
    // -----------------------------------------------------------------------

    #[test]
    fn new_valid_2_of_3() {
        let engine = ThresholdEngine::new(signers_3(), 2, 86_400);
        assert!(engine.is_ok());
        let engine = engine.unwrap();
        assert_eq!(engine.threshold(), 2);
        assert_eq!(engine.signers().len(), 3);
        assert_eq!(engine.voting_window_secs(), 86_400);
    }

    #[test]
    fn new_valid_1_of_1() {
        let engine = ThresholdEngine::new(vec![alice()], 1, 300);
        assert!(engine.is_ok());
    }

    #[test]
    fn new_valid_n_of_n() {
        let engine = ThresholdEngine::new(signers_3(), 3, 86_400);
        assert!(engine.is_ok());
    }

    #[test]
    fn new_rejects_empty_signers() {
        let result = ThresholdEngine::new(vec![], 1, 86_400);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GovernanceError::InvalidConfig(_)));
    }

    #[test]
    fn new_rejects_zero_threshold() {
        let result = ThresholdEngine::new(signers_3(), 0, 86_400);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GovernanceError::InvalidConfig(_)));
    }

    #[test]
    fn new_rejects_threshold_exceeds_signers() {
        let result = ThresholdEngine::new(signers_3(), 4, 86_400);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, GovernanceError::InvalidConfig(_)));
        if let GovernanceError::InvalidConfig(msg) = &err {
            assert!(msg.contains("threshold (4) exceeds signer count (3)"));
        }
    }

    #[test]
    fn new_rejects_voting_window_too_short() {
        let result = ThresholdEngine::new(signers_3(), 2, 299);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GovernanceError::InvalidConfig(_)));
    }

    #[test]
    fn new_rejects_voting_window_too_long() {
        let result = ThresholdEngine::new(signers_3(), 2, 604_801);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GovernanceError::InvalidConfig(_)));
    }

    #[test]
    fn new_rejects_duplicate_signers() {
        let result = ThresholdEngine::new(vec![alice(), alice(), bob()], 2, 86_400);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, GovernanceError::InvalidConfig(_)));
        if let GovernanceError::InvalidConfig(msg) = &err {
            assert!(msg.contains("duplicate signer"));
        }
    }

    #[test]
    fn with_default_window_uses_24h() {
        let engine = ThresholdEngine::with_default_window(signers_3(), 2).unwrap();
        assert_eq!(engine.voting_window_secs(), DEFAULT_VOTING_WINDOW_SECS);
    }

    // -----------------------------------------------------------------------
    // Proposal creation
    // -----------------------------------------------------------------------

    #[test]
    fn propose_creates_pending_proposal() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, events) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();

        assert_eq!(proposal.status, ProposalStatus::Pending);
        assert_eq!(proposal.proposer_did, alice());
        assert_eq!(proposal.context_id, "ctx-threshold-001");
        assert!(proposal.approvals.is_empty());
        assert!(proposal.rejections.is_empty());
        assert_eq!(proposal.created_at, 1_700_000_000);
        assert_eq!(proposal.voting_deadline, 1_700_000_000 + 86_400);
        assert_eq!(proposal.created_at_epoch, Some(1));

        // One event: ProposalCreated.
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], GovernanceEvent::ProposalCreated { .. }));
    }

    #[test]
    fn propose_rejects_non_signer() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let outsider = DID::from("did:dht:z6MkOutsider");
        let result = engine.propose(&outsider, add_member_action(), &ctx);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GovernanceError::NotEligible(_)));
    }

    #[test]
    fn propose_rejects_duplicate() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let _ = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let result = engine.propose(&alice(), add_member_action(), &ctx);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GovernanceError::DuplicateProposal(_)));
    }

    // -----------------------------------------------------------------------
    // Threshold counting (2-of-3)
    // -----------------------------------------------------------------------

    #[test]
    fn threshold_2_of_3_approved_with_two_approvals() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        // First approval -- still pending.
        let (status, events) = engine.approve(&pid, &alice(), &ctx).unwrap();
        assert_eq!(status, ProposalStatus::Pending);
        assert_eq!(events.len(), 1); // VoteCast only, no resolution.

        // Second approval -- reaches threshold.
        let (status, events) = engine.approve(&pid, &bob(), &ctx).unwrap();
        assert_eq!(status, ProposalStatus::Approved);
        assert_eq!(events.len(), 2); // VoteCast + ProposalResolved.
        assert!(matches!(events[0], GovernanceEvent::VoteCast { .. }));
        assert!(matches!(
            events[1],
            GovernanceEvent::ProposalResolved {
                status: ProposalStatus::Approved,
                ..
            }
        ));

        // Verify proposal state.
        let proposal = engine.get_proposal(&pid).unwrap();
        assert_eq!(proposal.approvals.len(), 2);
        assert_eq!(proposal.status, ProposalStatus::Approved);
    }

    #[test]
    fn threshold_2_of_3_order_independent() {
        // Verify that any 2 of the 3 signers can approve, regardless of order.
        for pair in &[(1, 2), (0, 2), (0, 1)] {
            let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
            let ctx = threshold_context(&signers_3(), 1_700_000_000);
            let signers = signers_3();

            let (proposal, _) = engine
                .propose(&signers[pair.0], add_member_action(), &ctx)
                .unwrap();
            let pid = proposal.proposal_id;

            engine.approve(&pid, &signers[pair.0], &ctx).unwrap();
            let (status, _) = engine.approve(&pid, &signers[pair.1], &ctx).unwrap();
            assert_eq!(status, ProposalStatus::Approved);
        }
    }

    #[test]
    fn threshold_3_of_5_requires_exactly_three() {
        let mut engine = ThresholdEngine::new(signers_5(), 3, 86_400).unwrap();
        let ctx = threshold_context(&signers_5(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        // Two approvals -- still pending.
        engine.approve(&pid, &alice(), &ctx).unwrap();
        let (status, _) = engine.approve(&pid, &bob(), &ctx).unwrap();
        assert_eq!(status, ProposalStatus::Pending);

        // Third approval -- threshold reached.
        let (status, _) = engine.approve(&pid, &carol(), &ctx).unwrap();
        assert_eq!(status, ProposalStatus::Approved);
    }

    #[test]
    fn threshold_1_of_1_immediate_on_single_approval() {
        let mut engine = ThresholdEngine::new(vec![alice()], 1, 300).unwrap();
        let ctx = threshold_context(&[alice()], 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        let (status, events) = engine.approve(&pid, &alice(), &ctx).unwrap();
        assert_eq!(status, ProposalStatus::Approved);
        assert_eq!(events.len(), 2); // VoteCast + ProposalResolved.
    }

    // -----------------------------------------------------------------------
    // Rejection / approval impossible
    // -----------------------------------------------------------------------

    #[test]
    fn threshold_2_of_3_rejection_makes_approval_impossible() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        // Two rejections out of 3 signers: approval is impossible
        // (rejections=2 > signers(3) - threshold(2) = 1).
        engine.reject(&pid, &alice(), &ctx).unwrap();
        let (status, events) = engine.reject(&pid, &bob(), &ctx).unwrap();

        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::ApprovalImpossible,
            }
        );
        assert_eq!(events.len(), 2); // VoteCast + ProposalResolved.
    }

    #[test]
    fn threshold_3_of_5_approval_impossible_with_three_rejections() {
        let mut engine = ThresholdEngine::new(signers_5(), 3, 86_400).unwrap();
        let ctx = threshold_context(&signers_5(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        // 3 rejections: rejections(3) > signers(5) - threshold(3) = 2.
        engine.reject(&pid, &alice(), &ctx).unwrap();
        engine.reject(&pid, &bob(), &ctx).unwrap();
        let (status, _) = engine.reject(&pid, &carol(), &ctx).unwrap();

        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::ApprovalImpossible,
            }
        );
    }

    #[test]
    fn threshold_2_of_3_single_rejection_does_not_block() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        // One rejection -- approval still possible (rejections=1, needed > 1).
        let (status, _) = engine.reject(&pid, &carol(), &ctx).unwrap();
        assert_eq!(status, ProposalStatus::Pending);

        // Two approvals -- threshold reached despite the rejection.
        engine.approve(&pid, &alice(), &ctx).unwrap();
        let (status, _) = engine.approve(&pid, &bob(), &ctx).unwrap();
        assert_eq!(status, ProposalStatus::Approved);
    }

    // -----------------------------------------------------------------------
    // Timeout / expiry
    // -----------------------------------------------------------------------

    #[test]
    fn proposal_expires_after_voting_deadline() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx_start = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, _) = engine
            .propose(&alice(), add_member_action(), &ctx_start)
            .unwrap();
        let pid = proposal.proposal_id;

        // One approval, not enough.
        engine.approve(&pid, &alice(), &ctx_start).unwrap();

        // Advance time past the voting deadline.
        let ctx_expired = threshold_context(&signers_3(), 1_700_000_000 + 86_401);
        let status = engine.resolve(&pid, &ctx_expired).unwrap();
        assert_eq!(status, ProposalStatus::Expired);
    }

    #[test]
    fn proposal_does_not_expire_before_deadline() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        // Check at exactly the deadline -- should still be pending (deadline is exclusive).
        let ctx_at_deadline = threshold_context(&signers_3(), 1_700_000_000 + 86_400);
        let status = engine.resolve(&pid, &ctx_at_deadline).unwrap();
        assert_eq!(status, ProposalStatus::Pending);
    }

    #[test]
    fn resolve_returns_terminal_status_without_change() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        engine.approve(&pid, &alice(), &ctx).unwrap();
        engine.approve(&pid, &bob(), &ctx).unwrap();

        // Already approved; resolve should return Approved without side effects.
        let status = engine.resolve(&pid, &ctx).unwrap();
        assert_eq!(status, ProposalStatus::Approved);
    }

    // -----------------------------------------------------------------------
    // Vote withdrawal
    // -----------------------------------------------------------------------

    #[test]
    fn withdraw_approval_before_threshold() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        // Alice approves.
        engine.approve(&pid, &alice(), &ctx).unwrap();
        assert_eq!(engine.get_proposal(&pid).unwrap().approvals.len(), 1);

        // Alice withdraws.
        let (status, events) = engine.withdraw_vote(&pid, &alice(), &ctx).unwrap();
        assert_eq!(status, ProposalStatus::Pending);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], GovernanceEvent::VoteWithdrawn { .. }));
        assert_eq!(engine.get_proposal(&pid).unwrap().approvals.len(), 0);
    }

    #[test]
    fn withdraw_rejection() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        // Alice rejects.
        engine.reject(&pid, &alice(), &ctx).unwrap();
        assert_eq!(engine.get_proposal(&pid).unwrap().rejections.len(), 1);

        // Alice withdraws the rejection.
        let (status, _) = engine.withdraw_vote(&pid, &alice(), &ctx).unwrap();
        assert_eq!(status, ProposalStatus::Pending);
        assert_eq!(engine.get_proposal(&pid).unwrap().rejections.len(), 0);
    }

    #[test]
    fn withdraw_and_revote() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        // Alice rejects, then withdraws, then approves.
        engine.reject(&pid, &alice(), &ctx).unwrap();
        engine.withdraw_vote(&pid, &alice(), &ctx).unwrap();
        engine.approve(&pid, &alice(), &ctx).unwrap();

        let proposal = engine.get_proposal(&pid).unwrap();
        assert_eq!(proposal.approvals.len(), 1);
        assert_eq!(proposal.rejections.len(), 0);
        assert_eq!(proposal.approvals[0].voter_did, alice());
    }

    #[test]
    fn withdraw_fails_on_resolved_proposal() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        // Approve to resolution.
        engine.approve(&pid, &alice(), &ctx).unwrap();
        engine.approve(&pid, &bob(), &ctx).unwrap();

        // Attempt withdrawal on resolved proposal.
        let result = engine.withdraw_vote(&pid, &alice(), &ctx);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotPending { .. }
        ));
    }

    #[test]
    fn withdraw_fails_when_no_vote_cast() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        // Alice hasn't voted; withdrawal should fail.
        let result = engine.withdraw_vote(&pid, &alice(), &ctx);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::NotEligible(_)
        ));
    }

    // -----------------------------------------------------------------------
    // Duplicate vote prevention
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_approval_rejected() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        engine.approve(&pid, &alice(), &ctx).unwrap();
        let result = engine.approve(&pid, &alice(), &ctx);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GovernanceError::AlreadyVoted));
    }

    #[test]
    fn duplicate_rejection_rejected() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        engine.reject(&pid, &alice(), &ctx).unwrap();
        let result = engine.reject(&pid, &alice(), &ctx);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GovernanceError::AlreadyVoted));
    }

    #[test]
    fn approve_then_reject_rejected_as_already_voted() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        engine.approve(&pid, &alice(), &ctx).unwrap();
        let result = engine.reject(&pid, &alice(), &ctx);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GovernanceError::AlreadyVoted));
    }

    // -----------------------------------------------------------------------
    // Non-signer cannot vote
    // -----------------------------------------------------------------------

    #[test]
    fn non_signer_cannot_approve() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        let outsider = DID::from("did:dht:z6MkOutsider");
        let result = engine.approve(&pid, &outsider, &ctx);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GovernanceError::NotEligible(_)));
    }

    #[test]
    fn non_signer_cannot_reject() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        let outsider = DID::from("did:dht:z6MkOutsider");
        let result = engine.reject(&pid, &outsider, &ctx);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GovernanceError::NotEligible(_)));
    }

    // -----------------------------------------------------------------------
    // Voting on non-existent or already-resolved proposals
    // -----------------------------------------------------------------------

    #[test]
    fn approve_nonexistent_proposal() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let fake_id = [0u8; 32];
        let result = engine.approve(&fake_id, &alice(), &ctx);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotFound { .. }
        ));
    }

    #[test]
    fn approve_resolved_proposal_fails() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        engine.approve(&pid, &alice(), &ctx).unwrap();
        engine.approve(&pid, &bob(), &ctx).unwrap(); // Approved.

        let result = engine.approve(&pid, &carol(), &ctx);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotPending { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // model_config and eligible_voters
    // -----------------------------------------------------------------------

    #[test]
    fn model_config_returns_threshold_config() {
        let engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let config = engine.model_config();

        assert_eq!(
            config,
            GovernanceModelConfig::Threshold {
                signers: signers_3(),
                threshold: 2,
                voting_window_secs: 86_400,
            }
        );
    }

    #[test]
    fn eligible_voters_returns_signer_set() {
        let engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let voters = engine.eligible_voters(&ctx);
        assert_eq!(voters, signers_3());
    }

    // -----------------------------------------------------------------------
    // get_proposal
    // -----------------------------------------------------------------------

    #[test]
    fn get_proposal_returns_none_for_unknown() {
        let engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        assert!(engine.get_proposal(&[0u8; 32]).is_none());
    }

    #[test]
    fn get_proposal_returns_proposal_after_creation() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        let retrieved = engine.get_proposal(&pid);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().proposer_did, alice());
    }

    // -----------------------------------------------------------------------
    // Merkle log event recording
    // -----------------------------------------------------------------------

    #[test]
    fn full_lifecycle_produces_correct_events() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        // Propose.
        let (proposal, create_events) = engine
            .propose(&alice(), add_member_action(), &ctx)
            .unwrap();
        let pid = proposal.proposal_id;
        assert_eq!(create_events.len(), 1);
        assert!(matches!(
            &create_events[0],
            GovernanceEvent::ProposalCreated { proposer_did, .. } if *proposer_did == alice()
        ));

        // First approval.
        let (_, approve1_events) = engine.approve(&pid, &alice(), &ctx).unwrap();
        assert_eq!(approve1_events.len(), 1);
        assert!(matches!(
            &approve1_events[0],
            GovernanceEvent::VoteCast { voter_did, vote: VoteType::Approve, .. }
            if *voter_did == alice()
        ));

        // Second approval (resolves).
        let (_, approve2_events) = engine.approve(&pid, &bob(), &ctx).unwrap();
        assert_eq!(approve2_events.len(), 2);
        assert!(matches!(
            &approve2_events[0],
            GovernanceEvent::VoteCast { voter_did, vote: VoteType::Approve, .. }
            if *voter_did == bob()
        ));
        assert!(matches!(
            &approve2_events[1],
            GovernanceEvent::ProposalResolved { status: ProposalStatus::Approved, .. }
        ));
    }

    #[test]
    fn withdrawal_event_recorded_in_merkle_log() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        engine.approve(&pid, &alice(), &ctx).unwrap();
        let (_, events) = engine.withdraw_vote(&pid, &alice(), &ctx).unwrap();

        assert_eq!(events.len(), 1);
        if let GovernanceEvent::VoteWithdrawn {
            proposal_id,
            voter_did,
        } = &events[0]
        {
            assert_eq!(proposal_id, &pid);
            assert_eq!(voter_did, &alice());
        } else {
            panic!("expected VoteWithdrawn event");
        }
    }

    // -----------------------------------------------------------------------
    // Multiple concurrent proposals
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_proposals_tracked_independently() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (p1, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let (p2, _) = engine
            .propose(&bob(), close_context_action(), &ctx)
            .unwrap();

        let pid1 = p1.proposal_id;
        let pid2 = p2.proposal_id;

        // Approve p1 fully.
        engine.approve(&pid1, &alice(), &ctx).unwrap();
        engine.approve(&pid1, &bob(), &ctx).unwrap();

        // p2 should still be pending.
        let proposal2 = engine.get_proposal(&pid2).unwrap();
        assert_eq!(proposal2.status, ProposalStatus::Pending);

        // Reject p2 to impossibility.
        engine.reject(&pid2, &alice(), &ctx).unwrap();
        let (status, _) = engine.reject(&pid2, &bob(), &ctx).unwrap();
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::ApprovalImpossible,
            }
        );
    }

    // -----------------------------------------------------------------------
    // Edge case: mixed approve/reject with threshold math
    // -----------------------------------------------------------------------

    #[test]
    fn threshold_3_of_5_mixed_votes() {
        let mut engine = ThresholdEngine::new(signers_5(), 3, 86_400).unwrap();
        let ctx = threshold_context(&signers_5(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        // 2 rejections (out of 5 signers, threshold 3):
        // rejections(2) <= signers(5) - threshold(3) = 2, so NOT impossible yet.
        engine.reject(&pid, &dave(), &ctx).unwrap();
        let (status, _) = engine.reject(&pid, &eve(), &ctx).unwrap();
        assert_eq!(status, ProposalStatus::Pending);

        // But if we add one more rejection:
        // rejections(3) > signers(5) - threshold(3) = 2 => impossible.
        let (status, _) = engine.reject(&pid, &carol(), &ctx).unwrap();
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::ApprovalImpossible,
            }
        );
    }

    #[test]
    fn threshold_2_of_3_approve_despite_rejection() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        // Carol rejects (1 rejection <= 3-2=1, so not impossible).
        engine.reject(&pid, &carol(), &ctx).unwrap();

        // Alice and Bob approve -- threshold met.
        engine.approve(&pid, &alice(), &ctx).unwrap();
        let (status, _) = engine.approve(&pid, &bob(), &ctx).unwrap();
        assert_eq!(status, ProposalStatus::Approved);
    }

    // -----------------------------------------------------------------------
    // Governance event serialization roundtrip for VoteWithdrawn
    // -----------------------------------------------------------------------

    #[test]
    fn vote_withdrawn_event_serialization_roundtrip() {
        let event = GovernanceEvent::VoteWithdrawn {
            proposal_id: [42u8; 32],
            voter_did: alice(),
        };

        let json = serde_json::to_string(&event).expect("serialize");
        let deserialized: GovernanceEvent =
            serde_json::from_str(&json).expect("deserialize");

        if let GovernanceEvent::VoteWithdrawn {
            proposal_id,
            voter_did,
        } = &deserialized
        {
            assert_eq!(proposal_id, &[42u8; 32]);
            assert_eq!(voter_did, &alice());
        } else {
            panic!("expected VoteWithdrawn variant after deserialization");
        }
    }

    // -----------------------------------------------------------------------
    // Resolve on non-existent proposal
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_nonexistent_proposal_returns_error() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let fake_id = [0u8; 32];
        let result = engine.resolve(&fake_id, &ctx);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotFound { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Boundary: voting window limits
    // -----------------------------------------------------------------------

    #[test]
    fn min_voting_window_accepted() {
        let engine = ThresholdEngine::new(signers_3(), 2, MIN_VOTING_WINDOW_SECS);
        assert!(engine.is_ok());
    }

    #[test]
    fn max_voting_window_accepted() {
        let engine = ThresholdEngine::new(signers_3(), 2, MAX_VOTING_WINDOW_SECS);
        assert!(engine.is_ok());
    }

    // -----------------------------------------------------------------------
    // Withdrawal and re-vote changes outcome
    // -----------------------------------------------------------------------

    #[test]
    fn withdrawal_prevents_threshold_from_being_reached() {
        let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
        let ctx = threshold_context(&signers_3(), 1_700_000_000);

        let (proposal, _) = engine.propose(&alice(), add_member_action(), &ctx).unwrap();
        let pid = proposal.proposal_id;

        // Alice approves, then withdraws -- only Bob's approval won't suffice.
        engine.approve(&pid, &alice(), &ctx).unwrap();
        engine.withdraw_vote(&pid, &alice(), &ctx).unwrap();
        engine.approve(&pid, &bob(), &ctx).unwrap();

        let proposal = engine.get_proposal(&pid).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Pending);
        assert_eq!(proposal.approvals.len(), 1); // Only Bob.
    }

    // -----------------------------------------------------------------------
    // All governance action types can be proposed
    // -----------------------------------------------------------------------

    #[test]
    fn all_action_types_can_be_proposed() {
        let actions: Vec<GovernanceAction> = vec![
            GovernanceAction::AddMember {
                did: DID::from("did:dht:z6MkNew"),
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
            let mut engine = ThresholdEngine::new(signers_3(), 2, 86_400).unwrap();
            // Use different timestamps to avoid duplicate proposal IDs.
            let ctx = threshold_context(&signers_3(), 1_700_000_000 + i as u64);

            let result = engine.propose(&alice(), action, &ctx);
            assert!(result.is_ok(), "failed to propose action variant {i}");
        }
    }
}
