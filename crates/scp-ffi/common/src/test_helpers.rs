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

/// The `bridgeTarget` the fixture's accepted bridge entry carries.
pub const FIXTURE_BRIDGE_TARGET: [u8; 32] = [0x42; 32];

/// The `serviceEndpoint`s of the entries [`document_with_rejected_services`]
/// keeps, in record order.
pub const FIXTURE_ACCEPTED_ENDPOINTS: [&str; 2] = [
    "wss://bridge.example.com/scp/v1",
    "wss://relay.example.com/scp/v1",
];

/// A DID document deserialized from a record mixing entries §18.2.1 accepts
/// and rejects.
///
/// The record holds a tier 3 bridge `SCPRelay` entry carrying
/// [`FIXTURE_BRIDGE_TARGET`], an `SCPRelay` entry whose URL carries a query,
/// a non-relay entry that carries `bridgeTarget`, and a plain `SCPRelay`
/// entry (`18-addressability-and-deployment.md` §18.2.1). Deserializing
/// drops the two rejected entries, so bridge projections must show only the
/// two accepted ones.
///
/// # Panics
///
/// Panics if the record does not serialize or deserialize.
#[must_use]
#[allow(clippy::expect_used)] // test fixture over a fixed record
pub fn document_with_rejected_services() -> scp_did::DidDocument {
    let did = "did:dht:zFixtureRejectedServices";
    let entry = |n: &str, ty: &str, endpoint: &str, bridge_target| scp_did::Service {
        id: format!("{did}#{n}"),
        service_type: ty.to_owned(),
        service_endpoint: endpoint.to_owned(),
        bridge_target,
    };
    let record = scp_did::DidDocument {
        context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
        id: did.to_owned(),
        verification_method: Vec::new(),
        authentication: Vec::new(),
        assertion_method: Vec::new(),
        also_known_as: Vec::new(),
        service: vec![
            entry(
                "scp-relay-1",
                "SCPRelay",
                FIXTURE_ACCEPTED_ENDPOINTS[0],
                Some(FIXTURE_BRIDGE_TARGET),
            ),
            entry(
                "scp-relay-2",
                "SCPRelay",
                "wss://query.example.com/scp/v1?bridge_target=00",
                None,
            ),
            entry(
                "pre-rotation",
                "PreRotationCommitment",
                "sha256:00",
                Some(FIXTURE_BRIDGE_TARGET),
            ),
            entry(
                "scp-relay-3",
                "SCPRelay",
                FIXTURE_ACCEPTED_ENDPOINTS[1],
                None,
            ),
        ],
    };
    assert_eq!(record.service.len(), 4);
    let json = record.to_json().expect("the record serializes");
    scp_did::DidDocument::from_json(&json).expect("the record deserializes")
}
