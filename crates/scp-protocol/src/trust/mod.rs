//! Trust engine types for SCP (Four-Layer Evaluation).
//!
//! Pure protocol types and submodule declarations. Async modules remain in
//! scp-runtime.

pub mod admission;
pub mod aggregate;
pub mod attestation;
pub mod capability_registry;
pub mod capability_uri;
pub mod challenge;
pub mod consequence;
pub mod custody_violation;
pub mod participation;
pub mod renewal;
pub mod sybil;

// Re-exports for backward compatibility.
pub use attestation::{
    Attestation, AttestationEvidence, DidPublicKeyResolver, IdentityDidPublicKeyResolver,
    RevocationStatus, verify_attestation, verify_attestation_with_revocation,
};
pub use capability_uri::{CapabilityUri, CapabilityUriError};
pub use challenge::{
    ChallengeRequest, ChallengeResponse, ChallengeSigner, ChallengeType, ChallengeVerification,
    issue_challenge, verify_challenge_response,
};
pub use custody_violation::{
    ActionCategory, CounterAttestation, CustodyViolationError, CustodyViolationType,
    ScpCustodyViolationAttestation, classify_action, enforce_category_a,
};
pub use participation::{
    ParticipationFact, ParticipationFacts, ParticipationInput, ParticipationProfile,
    ParticipationRecord, ParticipationThreshold, RequireParticipation,
    compute_participation_record, produce_participation_profile,
};
pub use sybil::{
    EarnedCapacityLevel, FreshnessWeight, IdentityDepthAssessment, TrustSignal,
    TrustSignalCategory, evaluate_earned_capacity,
};

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use scp_primitives::DID;

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

/// A tool identifier string.
///
/// Matches the `ToolId` type alias in `context::roles`, but redefined here
/// to avoid coupling the trust module to the context module's internals.
pub type ToolId = String;

// ---------------------------------------------------------------------------
// TrustError
// ---------------------------------------------------------------------------

/// Errors produced by trust engine operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum TrustError {
    /// No events found for the specified subject DID in the event log.
    #[error("no events found for subject DID: {did}")]
    NoEventsForSubject {
        /// The DID that was not found.
        did: String,
    },

    /// The event log is empty.
    #[error("event log is empty")]
    EmptyEventLog,

    /// A participation record computation failed due to invalid event data.
    #[error("invalid event data at sequence {sequence}: {reason}")]
    InvalidEventData {
        /// The sequence number of the problematic event.
        sequence: u64,
        /// Human-readable description of the issue.
        reason: String,
    },

    /// The attestation's Ed25519 signature is invalid.
    #[error("attestation {attestation_id}: signature invalid: {reason}")]
    AttestationSignatureInvalid {
        /// The attestation ID.
        attestation_id: String,
        /// Human-readable description of the failure.
        reason: String,
    },

    /// The attestation has expired.
    #[error("attestation {attestation_id}: expired at {expired_at}")]
    AttestationExpired {
        /// The attestation ID.
        attestation_id: String,
        /// Unix timestamp (seconds) when the attestation expired.
        expired_at: u64,
    },

    /// The attestation has been revoked.
    #[error("attestation {attestation_id}: revoked at {revoked_at}")]
    AttestationRevoked {
        /// The attestation ID.
        attestation_id: String,
        /// Unix timestamp (seconds) when the attestation was revoked.
        revoked_at: u64,
    },

    /// The attestation's `revoked_by` DID does not match the issuer.
    ///
    /// Per §7.4.1, only the issuer can revoke their own attestation.
    #[error(
        "attestation {attestation_id}: revoked_by '{revoked_by}' does not match issuer '{issuer}'"
    )]
    AttestationRevocationInvalid {
        /// The attestation ID.
        attestation_id: String,
        /// The DID that claims to have revoked the attestation.
        revoked_by: String,
        /// The attestation's issuer DID.
        issuer: String,
    },

    /// The attestation evidence is missing or invalid.
    #[error("attestation {attestation_id}: evidence invalid: {reason}")]
    AttestationEvidenceInvalid {
        /// The attestation ID.
        attestation_id: String,
        /// Human-readable description of the evidence issue.
        reason: String,
    },

    /// The challenge response's ID does not match the challenge request.
    #[error("challenge ID mismatch: expected {expected}, got {got}")]
    ChallengeIdMismatch {
        /// The expected challenge ID (from the request).
        expected: String,
        /// The actual challenge ID (from the response).
        got: String,
    },

    /// The challenge responder is not the challenged subject.
    #[error("challenge responder mismatch: expected {expected}, got {got}")]
    ChallengeResponderMismatch {
        /// The expected responder DID (the `subject_did` from the request).
        expected: String,
        /// The actual responder DID (from the response).
        got: String,
    },

    /// The challenge response was completed after the timeout window.
    #[error(
        "challenge {challenge_id}: timed out (timeout {timeout_secs}s, completed at \
         {completed_at})"
    )]
    ChallengeTimeout {
        /// The challenge ID.
        challenge_id: String,
        /// The timeout in seconds.
        timeout_secs: u64,
        /// The timestamp when the response was completed.
        completed_at: u64,
    },

    /// The challenge response's Ed25519 signature is invalid.
    #[error("challenge {challenge_id}: signature invalid: {reason}")]
    ChallengeSignatureInvalid {
        /// The challenge ID.
        challenge_id: String,
        /// Human-readable description of the failure.
        reason: String,
    },

    /// Signing a challenge request failed.
    #[error("challenge signing failed: {reason}")]
    ChallengeSigningFailed {
        /// Human-readable description of the failure.
        reason: String,
    },

    /// The challenge type URI is not a known protocol capability and is not
    /// DID-scoped.
    #[error("unknown challenge capability URI: {uri}")]
    UnknownChallengeCapability {
        /// The unrecognized URI string.
        uri: String,
    },

    /// The challenge parameters do not conform to the capability's parameter
    /// schema.
    #[error("invalid challenge parameters for {uri}: {reason}")]
    InvalidChallengeParameters {
        /// The capability URI whose schema was violated.
        uri: String,
        /// Human-readable description of the validation failure.
        reason: String,
    },

    /// The capability URI refers to a system capability (`scp:system:*`),
    /// which is a protocol feature flag and not challenge-testable.
    #[error(
        "system capability '{uri}' is not challengeable — system capabilities are feature flags, not testable capabilities"
    )]
    NotChallengeable {
        /// The system capability URI that was rejected.
        uri: String,
    },

    /// The challenge request's Ed25519 signature is invalid, indicating the
    /// request may have been tampered with (e.g., extended timeout, changed
    /// `subject_did`).
    #[error("challenge request signature invalid: {reason}")]
    ChallengeRequestSignatureInvalid {
        /// Human-readable description of the failure.
        reason: String,
    },

    /// The requested DID is not a member of the context.
    #[error("DID is not a member of this context: {did}")]
    NotAMember {
        /// The DID that is not a member.
        did: String,
    },

    /// The member has not opted in to participation profile publication.
    #[error("member has not opted in to participation profile publication: {did}")]
    NotOptedIn {
        /// The DID that has not opted in.
        did: String,
    },

    /// The trust store is unavailable or a storage operation failed.
    #[error("store error: {reason}")]
    StoreError {
        /// Human-readable description of the storage failure.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// AttestationType
// ---------------------------------------------------------------------------

/// Attestation type variants (ADR-017).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttestationType {
    /// Links an identity to an external identifier.
    IdentityLink,
    /// Delegates a capability to another DID.
    CapabilityDelegation,
    /// Attests to the integrity of a tool.
    ToolIntegrity,
    /// Attests to an agent's capability.
    AgentCapability,
    /// A general endorsement.
    Endorsement,
    /// Assigns a role to a DID.
    RoleAssignment,
    /// Endorses a context.
    ContextEndorsement,
    /// Witnesses participation facts.
    ParticipationWitness,
}

/// Returns a stable numeric tag for each attestation type variant.
#[must_use]
pub const fn attestation_type_tag(at: &AttestationType) -> u16 {
    match at {
        AttestationType::IdentityLink => 0,
        AttestationType::CapabilityDelegation => 1,
        AttestationType::ToolIntegrity => 2,
        AttestationType::AgentCapability => 3,
        AttestationType::Endorsement => 4,
        AttestationType::RoleAssignment => 5,
        AttestationType::ContextEndorsement => 6,
        AttestationType::ParticipationWitness => 7,
    }
}

// ---------------------------------------------------------------------------
// Supporting types for ParticipationRecord
// ---------------------------------------------------------------------------

/// Summary of a governance action (by or against a participant).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceActionSummary {
    /// Unix timestamp (seconds) when the action occurred.
    pub timestamp: u64,
    /// The DID of the actor who performed the governance action.
    pub actor_did: DID,
    /// The DID of the target of the governance action (if different from actor).
    pub target_did: Option<DID>,
    /// The sequence number of the event in the log.
    pub event_sequence: u64,
}

/// A role transition event for a participant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleTransition {
    /// Unix timestamp (seconds) when the role change occurred.
    pub timestamp: u64,
    /// The sequence number of the event in the log.
    pub event_sequence: u64,
    /// The DID of the actor who assigned the role.
    pub assigned_by: DID,
}

/// Reference to an attestation event in the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationReference {
    /// Unix timestamp (seconds) when the attestation was recorded.
    pub timestamp: u64,
    /// The sequence number of the event in the log.
    pub event_sequence: u64,
    /// The DID of the actor who created the attestation event.
    pub actor_did: DID,
}

// ---------------------------------------------------------------------------
// TrustInput
// ---------------------------------------------------------------------------

/// Aggregated trust inputs for agent-level evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustInput {
    /// Verified attestations (Layer 3).
    pub verified_attestations: Vec<attestation::Attestation>,

    /// Participation profile (Layer 2).
    pub participation_record: participation::ParticipationRecord,

    /// Challenge-response results (Layer 3).
    pub challenge_results: Vec<challenge::ChallengeVerification>,

    /// Declared consequence rules (Layer 4).
    pub consequence_structure: Vec<consequence::ConsequenceRule>,

    /// Threshold counts per attestation type: `(met, required)`.
    pub threshold_counts: HashMap<AttestationType, (u32, u32)>,
}
