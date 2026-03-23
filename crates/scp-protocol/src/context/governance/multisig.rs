//! M-of-N threshold governance engine (ADR-031 section 4b).
//!
//! A proposal passes when at least `threshold` of the designated `signers`
//! approve. Votes are order-independent. Vote withdrawal is permitted while
//! the proposal is [`Pending`](super::ProposalStatus::Pending). Proposals
//! that do not reach quorum within the voting window expire.
//!
//! # Resolution rules
//!
//! After each vote, `resolve()` checks:
//!
//! 1. `approvals.len() >= threshold` -> [`Approved`](super::ProposalStatus::Approved).
//! 2. `rejections.len() > signers.len() - threshold` -> approval is
//!    mathematically impossible ->
//!    [`Rejected { ApprovalImpossible }`](super::RejectionReason::ApprovalImpossible).
//! 3. `now >= voting_deadline` and neither condition met ->
//!    [`Expired`](super::ProposalStatus::Expired).
//!
//! # Deadline enforcement
//!
//! `approve()`, `reject()`, and `withdraw_vote()` all reject calls after the
//! voting deadline. This prevents late votes from racing against expiry.

use std::collections::{HashMap, HashSet};

use super::{
    CheckpointAttestationStatus, CosignedCheckpoint, GovernanceAction, GovernanceContext,
    GovernanceEngine, GovernanceError, GovernanceEvent, GovernanceModelConfig, GovernanceProposal,
    KeyResolver, ProposalId, ProposalStatus, RejectionReason, VoteType, compute_proposal_id,
    sign_vote, verify_vote,
};
use scp_primitives::DID;

// ---------------------------------------------------------------------------
// ThresholdEngine
// ---------------------------------------------------------------------------

/// M-of-N threshold governance engine.
///
/// A fixed set of designated signers; a proposal passes when at least
/// `threshold` of them approve. Implements [`GovernanceEngine`] for use
/// via `Box<dyn GovernanceEngine>`.
pub struct ThresholdEngine {
    /// The set of DIDs authorized to vote.
    signers: Vec<DID>,
    /// Minimum number of approvals required (`1 <= threshold <= signers.len()`).
    threshold: u32,
    /// Voting window in seconds applied to new proposals.
    voting_window_secs: u64,
    /// Active and resolved proposals, keyed by proposal ID.
    proposals: HashMap<ProposalId, GovernanceProposal>,
    /// Resolves voter DIDs to their Ed25519 verifying keys for signature
    /// verification.
    key_resolver: KeyResolver,
}

impl std::fmt::Debug for ThresholdEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThresholdEngine")
            .field("signers", &self.signers)
            .field("threshold", &self.threshold)
            .field("voting_window_secs", &self.voting_window_secs)
            .field("proposals", &self.proposals)
            .field("key_resolver", &"<fn>")
            .finish()
    }
}

impl ThresholdEngine {
    /// Creates a new threshold governance engine.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceError::InvalidConfig`] if:
    /// - `signers` is empty.
    /// - `threshold` is 0 or greater than `signers.len()`.
    /// - `voting_window_secs` is outside `[300, 604_800]` (5 min to 7 days).
    pub fn new(
        signers: Vec<DID>,
        threshold: u32,
        voting_window_secs: u64,
        key_resolver: KeyResolver,
    ) -> Result<Self, GovernanceError> {
        if signers.is_empty() {
            return Err(GovernanceError::InvalidConfig(
                "signers must be non-empty".to_owned(),
            ));
        }
        // signers.len() bounded by realistic member counts (<< u32::MAX).
        #[allow(clippy::cast_possible_truncation)]
        if threshold == 0 || threshold > signers.len() as u32 {
            return Err(GovernanceError::InvalidConfig(format!(
                "threshold must be in [1, {}], got {threshold}",
                signers.len()
            )));
        }
        if !(300..=604_800).contains(&voting_window_secs) {
            return Err(GovernanceError::InvalidConfig(format!(
                "voting_window_secs must be in [300, 604800], got {voting_window_secs}"
            )));
        }

        Ok(Self {
            signers,
            threshold,
            voting_window_secs,
            proposals: HashMap::new(),
            key_resolver,
        })
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

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Check whether the voter is in the signer set.
    fn is_signer(&self, did: &DID) -> bool {
        self.signers.iter().any(|s| s == did)
    }

    /// Check whether the voter has already voted (approve or reject) on the proposal.
    fn has_voted(proposal: &GovernanceProposal, voter: &DID) -> bool {
        proposal.approvals.iter().any(|v| v.voter_did == *voter)
            || proposal.rejections.iter().any(|v| v.voter_did == *voter)
    }

    /// Evaluate the current vote tallies against the resolution rules.
    ///
    /// Returns `Some(status)` if the proposal should transition, or `None`
    /// if it remains `Pending`.
    #[allow(clippy::cast_possible_truncation)] // vote counts bounded by signer set size
    const fn evaluate_resolution(
        &self,
        proposal: &GovernanceProposal,
        now: u64,
    ) -> Option<ProposalStatus> {
        let approvals = proposal.approvals.len() as u32;
        let rejections = proposal.rejections.len() as u32;
        let signer_count = self.signers.len() as u32;

        // Rule 1: threshold reached.
        if approvals >= self.threshold {
            return Some(ProposalStatus::Approved);
        }

        // Rule 2: approval mathematically impossible.
        if rejections > signer_count.saturating_sub(self.threshold) {
            return Some(ProposalStatus::Rejected {
                reason: RejectionReason::ApprovalImpossible,
            });
        }

        // Rule 3: voting window expired.
        if now >= proposal.voting_deadline {
            return Some(ProposalStatus::Expired);
        }

        None
    }

    /// Internal resolve implementation: evaluates and transitions the proposal.
    ///
    /// Returns the resulting status and any events that should be recorded
    /// in the Merkle log (Bug 2 fix: resolve returns events alongside status).
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

impl GovernanceEngine for ThresholdEngine {
    fn propose(
        &mut self,
        proposer: &DID,
        action: GovernanceAction,
        context: &GovernanceContext,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(GovernanceProposal, Vec<GovernanceEvent>), GovernanceError> {
        // Only signers can propose.
        if !self.is_signer(proposer) {
            return Err(GovernanceError::NotEligible(
                "proposer is not in the signer set".to_owned(),
            ));
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

        // The proposer's vote counts as the first approval.
        let proposer_vote = sign_vote(
            &proposal_id,
            &VoteType::Approve,
            proposer.as_ref(),
            context.now,
            signing_key,
        )?;

        // Verify the proposer's vote signature against their DID-resolved key.
        let resolved_key =
            (self.key_resolver)(proposer).ok_or_else(|| GovernanceError::UnknownVoter {
                did: proposer.to_string(),
            })?;
        verify_vote(&proposal_id, &proposer_vote, &resolved_key).map_err(|_| {
            GovernanceError::InvalidSignature {
                voter_did: proposer.to_string(),
                proposal_id: hex::encode(proposal_id),
            }
        })?;

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
                action: Box::new(action),
                voting_deadline,
            },
            GovernanceEvent::VoteCast {
                proposal_id,
                voter_did: proposer.clone(),
                vote: VoteType::Approve,
            },
        ];

        self.proposals.insert(proposal_id, proposal);

        // Check if the proposer's vote alone meets the threshold (e.g., 1-of-N).
        let (status, resolve_events) = self.resolve_proposal(&proposal_id, context.now)?;
        events.extend(resolve_events);

        // Re-fetch proposal after possible status change. Key is guaranteed
        // present because we inserted it above and hold `&mut self`.
        let Some(proposal) = self.proposals.get(&proposal_id).cloned() else {
            return Err(GovernanceError::ProposalNotFound {
                id: hex::encode(proposal_id),
            });
        };

        // Sanity: if resolved, the proposal status should match.
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
        // Voter must be a signer.
        if !self.is_signer(voter) {
            return Err(GovernanceError::NotEligible(
                "voter is not in the signer set".to_owned(),
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

        // Bug 1 fix: deadline guard -- reject votes after the voting window.
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

        // Verify the vote signature against the voter's DID-resolved key.
        let resolved_key =
            (self.key_resolver)(voter).ok_or_else(|| GovernanceError::UnknownVoter {
                did: voter.to_string(),
            })?;
        verify_vote(proposal_id, &vote, &resolved_key).map_err(|_| {
            GovernanceError::InvalidSignature {
                voter_did: voter.to_string(),
                proposal_id: hex::encode(proposal_id),
            }
        })?;

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
        // Voter must be a signer.
        if !self.is_signer(voter) {
            return Err(GovernanceError::NotEligible(
                "voter is not in the signer set".to_owned(),
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

        // Bug 1 fix: deadline guard -- reject votes after the voting window.
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

        // Verify the vote signature against the voter's DID-resolved key.
        let resolved_key =
            (self.key_resolver)(voter).ok_or_else(|| GovernanceError::UnknownVoter {
                did: voter.to_string(),
            })?;
        verify_vote(proposal_id, &vote, &resolved_key).map_err(|_| {
            GovernanceError::InvalidSignature {
                voter_did: voter.to_string(),
                proposal_id: hex::encode(proposal_id),
            }
        })?;

        // Key is guaranteed present because we just looked it up via `get()` above.
        if let Some(proposal_mut) = self.proposals.get_mut(proposal_id) {
            proposal_mut.rejections.push(vote);
        }

        let mut events = vec![GovernanceEvent::VoteCast {
            proposal_id: *proposal_id,
            voter_did: voter.clone(),
            vote: VoteType::Reject,
        }];

        // Resolve after vote.
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
        // Voter must be a signer.
        if !self.is_signer(voter) {
            return Err(GovernanceError::NotEligible(
                "voter is not in the signer set".to_owned(),
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
        self.signers.retain(|d| d != voter);
        // Re-resolve after vote removal.
        let (status, events) = self.resolve_proposal(proposal_id, context.now)?;
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
        // Threshold: require M-of-N cosignatures from designated signers (ADR-031 §9)
        (self.signers.clone(), self.threshold as usize)
    }

    fn validate_checkpoint_cosignatures(
        &self,
        cosignatures: &[CosignedCheckpoint],
        checkpoint_hash: &[u8; 32],
    ) -> Result<CheckpointAttestationStatus, GovernanceError> {
        // Verify all cosignatures are from designated signers and valid
        let mut valid_cosignatures = 0;
        let mut seen_signers = HashSet::new();
        for cosig in cosignatures {
            if !self.signers.contains(&cosig.signer_did) {
                return Err(GovernanceError::NotEligible(format!(
                    "Cosigner {} not in signer set",
                    cosig.signer_did
                )));
            }

            if !seen_signers.insert(&cosig.signer_did) {
                return Err(GovernanceError::NotEligible(format!(
                    "duplicate cosignature from {}",
                    cosig.signer_did
                )));
            }

            // Get public key for this signer
            let Some(verifying_key) = (self.key_resolver)(&cosig.signer_did) else {
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

        // Check if we have threshold for full attestation
        if valid_cosignatures >= self.threshold as usize {
            Ok(CheckpointAttestationStatus::FullyAttested)
        } else {
            Ok(CheckpointAttestationStatus::PartiallyAttested)
        }
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

    fn sk_alice() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[1u8; 32])
    }

    fn sk_bob() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[2u8; 32])
    }

    fn sk_carol() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[3u8; 32])
    }

    /// Mock key resolver that maps test DIDs to their corresponding signing
    /// key's verifying key.
    fn mock_resolver() -> KeyResolver {
        use std::sync::Arc;
        Arc::new(|did: &DID| {
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
                _ => None,
            }
        })
    }

    fn sk_dave() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[4u8; 32])
    }

    /// Create a test context at a given timestamp.
    fn test_context_at(now: u64) -> GovernanceContext {
        GovernanceContext {
            context_id: "ctx-multisig-001".to_owned(),
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
    fn new_rejects_empty_signers() {
        let result = ThresholdEngine::new(vec![], 1, 86_400, mock_resolver());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::InvalidConfig(_)
        ));
    }

    #[test]
    fn new_rejects_zero_threshold() {
        let result = ThresholdEngine::new(vec![alice()], 0, 86_400, mock_resolver());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::InvalidConfig(_)
        ));
    }

    #[test]
    fn new_rejects_threshold_exceeding_signers() {
        let result = ThresholdEngine::new(vec![alice(), bob()], 3, 86_400, mock_resolver());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::InvalidConfig(_)
        ));
    }

    #[test]
    fn new_rejects_window_too_short() {
        let result = ThresholdEngine::new(vec![alice()], 1, 299, mock_resolver());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::InvalidConfig(_)
        ));
    }

    #[test]
    fn new_rejects_window_too_long() {
        let result = ThresholdEngine::new(vec![alice()], 1, 604_801, mock_resolver());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::InvalidConfig(_)
        ));
    }

    #[test]
    fn new_accepts_valid_config() {
        let engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid config");
        assert_eq!(engine.signers().len(), 3);
        assert_eq!(engine.threshold(), 2);
        assert_eq!(engine.voting_window_secs(), 86_400);
    }

    // -----------------------------------------------------------------------
    // Propose creates pending proposal with proposer's approval
    // -----------------------------------------------------------------------

    #[test]
    fn propose_creates_pending_with_first_approval() {
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
        let ctx = test_context();

        let (proposal, events) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");

        // Proposal should be pending (2-of-3, only 1 approval so far).
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
    fn propose_1_of_n_auto_resolves() {
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 1, 86_400, mock_resolver())
                .expect("valid");
        let ctx = test_context();

        let (proposal, events) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");

        // 1-of-3: proposer's approval meets threshold immediately.
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
    fn propose_rejects_non_signer() {
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob()], 2, 86_400, mock_resolver()).expect("valid");
        let ctx = test_context();

        let result = engine.propose(&dave(), default_action(), &ctx, &sk_dave());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::NotEligible(_)
        ));
    }

    // -----------------------------------------------------------------------
    // Approve reaches threshold -> Approved
    // -----------------------------------------------------------------------

    #[test]
    fn approve_reaches_threshold() {
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Bob approves -> 2 of 3 -> Approved.
        let (status, events) = engine.approve(&pid, &bob(), &ctx, &sk_bob()).expect("ok");
        assert_eq!(status, ProposalStatus::Approved);
        assert_eq!(events.len(), 2); // VoteCast + Resolved
        assert!(matches!(events[0], GovernanceEvent::VoteCast { .. }));
        assert!(matches!(
            events[1],
            GovernanceEvent::ProposalResolved {
                status: ProposalStatus::Approved,
                ..
            }
        ));
    }

    #[test]
    fn approve_rejects_non_signer() {
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob()], 2, 86_400, mock_resolver()).expect("valid");
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
            ThresholdEngine::new(vec![alice(), bob(), carol()], 3, 86_400, mock_resolver())
                .expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let result = engine.approve(&proposal.proposal_id, &alice(), &ctx, &sk_alice());
        assert!(matches!(result.unwrap_err(), GovernanceError::AlreadyVoted));
    }

    // -----------------------------------------------------------------------
    // Reject makes approval impossible -> Rejected
    // -----------------------------------------------------------------------

    #[test]
    fn reject_makes_approval_impossible() {
        // 2-of-3: if 2 reject, approval is impossible (rejections > 3 - 2 = 1).
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Bob rejects: 1 rejection, not impossible yet (1 > 1 is false).
        let (status, _) = engine.reject(&pid, &bob(), &ctx, &sk_bob()).expect("ok");
        assert_eq!(status, ProposalStatus::Pending);

        // Carol rejects: 2 rejections > 3 - 2 = 1 -> ApprovalImpossible.
        let (status, events) = engine
            .reject(&pid, &carol(), &ctx, &sk_carol())
            .expect("ok");
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::ApprovalImpossible
            }
        );
        // Events: VoteCast + Resolved.
        assert_eq!(events.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Bug 1 tests: votes rejected after voting deadline
    // -----------------------------------------------------------------------

    #[test]
    fn approve_rejected_after_deadline() {
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Advance time past the deadline.
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
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Advance time past the deadline.
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
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
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
    // Bug 2 tests: resolve() produces events for timeout transitions
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_produces_expired_event() {
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
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
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
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
    fn resolve_returns_status_and_events_for_already_terminal() {
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Bob approves -> Approved.
        engine.approve(&pid, &bob(), &ctx, &sk_bob()).expect("ok");

        // Resolve again on already-approved proposal.
        let (status, events) = engine.resolve(&pid, &ctx).expect("ok");
        assert_eq!(status, ProposalStatus::Approved);
        assert!(events.is_empty(), "no events for already-terminal proposal");
    }

    // -----------------------------------------------------------------------
    // Bug 3 tests: withdraw_vote() and resolve() accessible via trait
    // -----------------------------------------------------------------------

    #[test]
    fn withdraw_vote_accessible_via_trait() {
        let engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
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
        let engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
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

    #[test]
    fn default_trait_impls_return_unsupported_for_single_admin() {
        use super::super::SingleAdminEngine;

        let mut engine: Box<dyn GovernanceEngine> =
            Box::new(SingleAdminEngine::new(alice(), mock_resolver()));
        let ctx = test_context();

        let action = GovernanceAction::CloseContext { reason: None };
        let (proposal, _) = engine
            .propose(&alice(), action, &ctx, &sk_alice())
            .expect("ok");

        // SingleAdminEngine uses default trait impls which return OperationNotSupported.
        let result = engine.withdraw_vote(&proposal.proposal_id, &alice(), &ctx);
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::OperationNotSupported(_)
        ));

        let result = engine.resolve(&proposal.proposal_id, &ctx);
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::OperationNotSupported(_)
        ));
    }

    // -----------------------------------------------------------------------
    // Vote withdrawal
    // -----------------------------------------------------------------------

    #[test]
    fn withdraw_vote_allows_revote() {
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
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
        assert_eq!(status, ProposalStatus::Pending);
    }

    #[test]
    fn withdraw_vote_rejects_non_voter() {
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
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
    fn withdraw_vote_rejects_after_deadline() {
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
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

    // -----------------------------------------------------------------------
    // model_config and eligible_voters
    // -----------------------------------------------------------------------

    #[test]
    fn model_config_returns_threshold_variant() {
        let engine =
            ThresholdEngine::new(vec![alice(), bob()], 2, 86_400, mock_resolver()).expect("valid");
        let config = engine.model_config();
        assert_eq!(
            config,
            GovernanceModelConfig::Threshold {
                signers: vec![alice(), bob()],
                threshold: 2,
                voting_window_secs: 86_400,
            }
        );
    }

    #[test]
    fn eligible_voters_returns_signers() {
        let engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
        let ctx = test_context();
        let voters = engine.eligible_voters(&ctx);
        assert_eq!(voters, vec![alice(), bob(), carol()]);
    }

    // -----------------------------------------------------------------------
    // ThresholdEngine is Send + Sync
    // -----------------------------------------------------------------------

    #[test]
    fn threshold_engine_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ThresholdEngine>();
    }

    // -----------------------------------------------------------------------
    // Duplicate proposal rejected
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_proposal_rejected() {
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob()], 2, 86_400, mock_resolver()).expect("valid");
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
    // Unknown proposal ID
    // -----------------------------------------------------------------------

    #[test]
    fn approve_unknown_proposal() {
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob()], 2, 86_400, mock_resolver()).expect("valid");
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
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob()], 2, 86_400, mock_resolver()).expect("valid");
        let ctx = test_context();
        let fake_id = [0u8; 32];

        let result = engine.reject(&fake_id, &alice(), &ctx, &sk_alice());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotFound { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Full lifecycle: propose -> approve -> approved
    // -----------------------------------------------------------------------

    #[test]
    fn full_lifecycle_2_of_3_approval() {
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
        let ctx = test_context();

        // 1. Alice proposes (counts as first approval).
        let (proposal, create_events) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        assert_eq!(proposal.status, ProposalStatus::Pending);
        assert_eq!(create_events.len(), 2); // Created + VoteCast

        // 2. Bob approves -> reaches threshold.
        let (status, approve_events) = engine
            .approve(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .expect("ok");
        assert_eq!(status, ProposalStatus::Approved);
        assert_eq!(approve_events.len(), 2); // VoteCast + Resolved

        // 3. Carol trying to approve on resolved proposal -> error.
        let result = engine.approve(&proposal.proposal_id, &carol(), &ctx, &sk_carol());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotPending { .. }
        ));

        // 4. Verify stored proposal.
        let stored = engine.get_proposal(&proposal.proposal_id).expect("found");
        assert_eq!(stored.status, ProposalStatus::Approved);
        assert_eq!(stored.approvals.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Full lifecycle: propose -> reject -> impossible
    // -----------------------------------------------------------------------

    #[test]
    fn full_lifecycle_2_of_3_rejection() {
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Bob rejects.
        let (status, _) = engine.reject(&pid, &bob(), &ctx, &sk_bob()).expect("ok");
        assert_eq!(status, ProposalStatus::Pending);

        // Carol rejects -> 2 rejections > 3-2=1 -> impossible.
        let (status, _) = engine
            .reject(&pid, &carol(), &ctx, &sk_carol())
            .expect("ok");
        assert_eq!(
            status,
            ProposalStatus::Rejected {
                reason: RejectionReason::ApprovalImpossible
            }
        );
    }

    // -----------------------------------------------------------------------
    // Full lifecycle: propose -> expire
    // -----------------------------------------------------------------------

    #[test]
    fn full_lifecycle_expiry() {
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");
        let pid = proposal.proposal_id;

        // Advance time past deadline.
        let expired_ctx = test_context_at(ctx.now + 86_400);

        // resolve() triggers expiry.
        let (status, events) = engine.resolve(&pid, &expired_ctx).expect("ok");
        assert_eq!(status, ProposalStatus::Expired);
        assert_eq!(events.len(), 1);
    }

    // -----------------------------------------------------------------------
    // verify_vote integration (defense-in-depth)
    // -----------------------------------------------------------------------

    #[test]
    fn propose_produces_verifiable_proposer_vote() {
        use crate::context::governance::verify_vote;

        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");

        // Proposer's implicit approval should be verifiable.
        assert_eq!(proposal.approvals.len(), 1);
        verify_vote(
            &proposal.proposal_id,
            &proposal.approvals[0],
            &sk_alice().verifying_key(),
        )
        .expect("proposer's vote should be verifiable");
    }

    #[test]
    fn approve_produces_verifiable_votes() {
        use crate::context::governance::verify_vote;

        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");

        engine
            .approve(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .expect("ok");

        let p = engine.get_proposal(&proposal.proposal_id).unwrap();
        assert_eq!(p.approvals.len(), 2);
        verify_vote(
            &proposal.proposal_id,
            &p.approvals[1],
            &sk_bob().verifying_key(),
        )
        .expect("vote recorded by approve() should be verifiable");
    }

    #[test]
    fn tampered_vote_signature_rejected_by_verify_proposal_votes() {
        use crate::context::governance::verify_proposal_votes;

        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("ok");

        engine
            .approve(&proposal.proposal_id, &bob(), &ctx, &sk_bob())
            .expect("ok");

        // Serialize and deserialize to simulate persistence/sync boundary.
        let p = engine.get_proposal(&proposal.proposal_id).unwrap();
        let json = serde_json::to_string(p).unwrap();
        let mut deserialized: GovernanceProposal = serde_json::from_str(&json).unwrap();

        // Tamper with bob's vote signature.
        deserialized.approvals[1].signature[0] ^= 0xff;

        let result = verify_proposal_votes(&deserialized, |did| {
            if *did == alice() {
                Some(sk_alice().verifying_key())
            } else if *did == bob() {
                Some(sk_bob().verifying_key())
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
    fn valid_vote_signature_is_recorded() {
        // AC: construct a ThresholdEngine with a mock resolver, submit a vote
        // with a valid signature from a known key, verify it is recorded.
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("propose ok");
        let pid = proposal.proposal_id;

        // Bob's signing key matches the resolver's entry for Bob.
        let (status, events) = engine
            .approve(&pid, &bob(), &ctx, &sk_bob())
            .expect("approve ok");

        // Vote should be recorded and proposal approved (2-of-3).
        assert_eq!(status, ProposalStatus::Approved);
        assert!(!events.is_empty());

        let p = engine.get_proposal(&pid).expect("found");
        assert_eq!(p.approvals.len(), 2);
        assert_eq!(p.approvals[1].voter_did, bob());
    }

    #[test]
    fn forged_vote_signature_rejected() {
        // AC: construct a ThresholdEngine with a mock resolver, submit a vote
        // with a forged signature (wrong key), verify InvalidSignature returned
        // and no vote is recorded.
        //
        // The resolver maps Bob to sk_bob's verifying key ([2u8;32]),
        // but we sign with Carol's key ([3u8;32]) while claiming to be Bob.
        // This simulates a forgery: correct DID, wrong signing key.
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("propose ok");
        let pid = proposal.proposal_id;

        // Sign Bob's vote with Carol's key (forgery).
        let result = engine.approve(&pid, &bob(), &ctx, &sk_carol());
        assert!(result.is_err(), "forged signature should be rejected");
        assert!(
            matches!(
                result.unwrap_err(),
                GovernanceError::InvalidSignature { .. }
            ),
            "expected InvalidSignature error"
        );

        // No vote should have been recorded.
        let p = engine.get_proposal(&pid).expect("found");
        assert_eq!(p.approvals.len(), 1, "only proposer's vote should exist");
        assert_eq!(p.approvals[0].voter_did, alice());
    }

    #[test]
    fn unknown_voter_did_rejected() {
        // AC (from MajorityVoteEngine, but testing ThresholdEngine too):
        // submit a vote for an unknown DID (resolver returns None),
        // verify UnknownVoter is returned.
        //
        // Dave is in the signer set but NOT in the resolver.
        let resolver_without_dave: KeyResolver = {
            use std::sync::Arc;
            Arc::new(|did: &DID| {
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

        let mut engine = ThresholdEngine::new(
            vec![alice(), bob(), carol(), dave()],
            2,
            86_400,
            resolver_without_dave,
        )
        .expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("propose ok");
        let pid = proposal.proposal_id;

        let result = engine.approve(&pid, &dave(), &ctx, &sk_dave());
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), GovernanceError::UnknownVoter { .. }),
            "expected UnknownVoter error"
        );
    }

    #[test]
    fn e2e_valid_votes_reach_approved_forged_vote_does_not() {
        // AC: end-to-end — create a proposal via ThresholdEngine, collect valid
        // votes to reach quorum, verify proposal reaches Approved; repeat with
        // one forged vote substituted, verify proposal does NOT reach Approved.

        // Part 1: valid votes reach Approved.
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");
        let ctx = test_context();

        let (proposal, _) = engine
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("propose ok");
        let pid = proposal.proposal_id;

        let (status, _) = engine
            .approve(&pid, &bob(), &ctx, &sk_bob())
            .expect("approve ok");
        assert_eq!(
            status,
            ProposalStatus::Approved,
            "valid votes should reach Approved"
        );

        // Part 2: forged vote prevents Approved.
        let mut engine2 =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 86_400, mock_resolver())
                .expect("valid");

        let (proposal2, _) = engine2
            .propose(&alice(), default_action(), &ctx, &sk_alice())
            .expect("propose ok");
        let pid2 = proposal2.proposal_id;

        // Bob tries to vote with Carol's signing key (forgery).
        let result = engine2.approve(&pid2, &bob(), &ctx, &sk_carol());
        assert!(result.is_err(), "forged vote should fail");

        // Proposal should still be Pending (only Alice's proposer vote exists).
        let p = engine2.get_proposal(&pid2).expect("found");
        assert_eq!(p.status, ProposalStatus::Pending);
        assert_eq!(p.approvals.len(), 1, "only proposer's vote");
    }

    // -----------------------------------------------------------------------
    // Economic governance action tests — Threshold (#334)
    // -----------------------------------------------------------------------

    #[test]
    fn threshold_set_economic_policy() {
        let signers = vec![alice(), bob()];
        let mut engine =
            ThresholdEngine::new(signers, 2, 86_400, mock_resolver()).expect("valid config");
        let ctx = test_context_at(1_700_000_000);

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

        let (proposal, _) = engine.propose(&alice(), action, &ctx, &sk_alice()).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Pending);
    }

    #[test]
    fn threshold_approve_spend() {
        let signers = vec![alice(), bob()];
        let mut engine =
            ThresholdEngine::new(signers, 2, 86_400, mock_resolver()).expect("valid config");
        let ctx = test_context_at(1_700_000_000);

        let action = GovernanceAction::ApproveSpend {
            spender: alice(),
            amount: crate::economy::types::Amount::new(1000),
            purpose: "tool costs".to_owned(),
        };

        let (proposal, _) = engine.propose(&alice(), action, &ctx, &sk_alice()).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Pending);
    }

    #[test]
    fn threshold_lock_economic_policy() {
        let signers = vec![alice(), bob()];
        let mut engine =
            ThresholdEngine::new(signers, 2, 86_400, mock_resolver()).expect("valid config");
        let ctx = test_context_at(1_700_000_000);

        let action = GovernanceAction::LockEconomicPolicy;

        let (proposal, _) = engine.propose(&alice(), action, &ctx, &sk_alice()).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Pending);
    }
}
