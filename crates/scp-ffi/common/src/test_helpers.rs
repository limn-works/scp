//! Shared test fixtures for FFI bridge tests.
//!
//! Gated behind the `testing` feature so these helpers are available to all
//! bridge crates (`scp-ffi`, `scp-ffi-napi`, `scp-ffi-uniffi`) via
//! `[dev-dependencies] scp-ffi-common = { ..., features = ["testing"] }`.

use scp_core::context::governance::{
    GovernanceAction, GovernanceProposal, ProposalStatus, SignedVote, VoteType,
};
use scp_did::DID;

/// Build a [`GovernanceProposal`] in `Approved` status with a single approval
/// vote.  Used across bridge test suites to drive governance execution without
/// a full voting round-trip.
#[must_use]
pub fn approved_proposal(
    pid: [u8; 32],
    context_id: &str,
    action: GovernanceAction,
    approver_did: &str,
) -> GovernanceProposal {
    GovernanceProposal {
        proposal_id: pid,
        context_id: context_id.into(),
        proposer_did: DID(approver_did.to_owned()),
        action,
        status: ProposalStatus::Approved,
        created_at: 1000,
        voting_deadline: 2000,
        approvals: vec![SignedVote {
            voter_did: DID(approver_did.to_owned()),
            vote: VoteType::Approve,
            timestamp: 1000,
            signature: vec![0u8; 64],
        }],
        rejections: Vec::new(),
        created_at_epoch: None,
    }
}
