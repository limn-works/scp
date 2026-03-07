//! Trust engine module for SCP (Four-Layer Evaluation).
//!
//! The trust engine provides validated inputs for agent-level evaluation -- it
//! does not produce trust "scores." Trust is contextual (protocol tenet): each
//! agent's evaluation logic consumes verifiable facts according to its own
//! criteria.
//!
//! # Architecture
//!
//! The trust engine implements Layers 2-4 of the trust model:
//!
//! - **Layer 2 (Participation):** [`ParticipationRecord`] computed locally from
//!   event logs. Two agents may compute different records from different event
//!   log views -- this is correct behavior, not a bug.
//! - **Layer 3 (Attestation):** [`Attestation`] verification with common
//!   envelope format. [`verify_attestation`] checks signatures, evidence,
//!   expiry, and revocation. [`check_attestation_freshness`] evaluates renewal
//!   intervals. [`check_threshold_attestation`] checks N-of-M requirements
//!   with independence scoring.
//! - **Layer 3 (Challenge-Response):** [`ChallengeRequest`] /
//!   [`ChallengeResponse`] for capability verification.
//!   [`verify_challenge_response`] verifies response signatures and
//!   distinguishes self-attested vs challenge-verified in metadata. See
//!   [`challenge`] module.
//! - **Layer 4 (Consequence):** [`ConsequenceRule`] declared at context creation
//!   and protocol-enforced. See [`consequence`] module.
//!
//! [`TrustInput`] aggregates all layers for agent-level evaluation.
//!
//! See ADR-017 in `.docs/adrs/phase-4.md`.
//!
//! # Types
//!
//! - [`TrustInput`] -- Aggregated trust inputs for agent-level evaluation.
//! - [`TrustError`] -- Error type for trust engine operations.
//! - [`ParticipationRecord`] -- Verifiable facts computed from context event logs.
//! - [`GovernanceActionSummary`] -- Summary of a governance action.
//! - [`RoleTransition`] -- A role change event.
//! - [`Attestation`] -- Common attestation envelope (ADR-017, section 7.4.1).
//! - [`AttestationType`] -- Attestation type variants.
//! - [`AttestationEvidence`] -- Evidence supporting an attestation.
//! - [`RevocationStatus`] -- Revocation status of an attestation.
//! - [`FreshnessStatus`] -- Result of freshness evaluation.
//! - [`ThresholdRequirement`] -- N-of-M threshold requirement.
//! - [`ThresholdResult`] -- Result of threshold attestation check.
//! - [`AttestationReference`] -- Reference to an attestation in the event log.
//! - [`ChallengeRequest`] -- Challenge request for capability verification.
//! - [`ChallengeResponse`] -- Response to a challenge request.
//! - [`ChallengeVerification`] -- Result of verifying a challenge response.
//! - [`CapabilityUri`] -- Validated agent capability URI (ADR-041).
//! - [`CapabilityUriError`] -- Error type for capability URI parsing.
//! - [`RegistryEntry`] -- Metadata for a registered protocol capability.
//! - [`ChallengeType`] -- URI-based challenge types (unified with `CapabilityUri`).
//! - [`VerificationMethod`] -- Self-attested vs challenge-verified.
//! - [`ChallengeSigner`] -- Trait for signing challenge requests.
//! - [`RenewalError`] -- Error type for attestation renewal.
//! - [`RenewalChecker`] -- Trait for platform-specific renewal scheduling.
//! - [`DefaultRenewalChecker`] -- Default renewal checker implementation.
//! - [`ActionCategory`] -- Classification of a protocol action (Category A or B).
//! - [`CustodyViolationType`] -- Unambiguous custody violation categories.
//! - [`ScpCustodyViolationAttestation`] -- Permanent violation record.
//! - [`CounterAttestation`] -- Counter-evidence for reputation restoration.
//! - [`CustodyViolationError`] -- Validation errors for custody violation types.
//! - [`CustodyViolationResult`] -- Result of a Category A enforcement check.
//! - [`ParticipationFact`] -- Participation fact categories for admission (§7.3.2.1).
//! - [`ParticipationThreshold`] -- Comparison operators for admission thresholds.
//! - [`RequireParticipation`] -- Participation admission requirement.
//! - [`ParticipationProfile`] -- Context-hosted signed participation attestation.

pub mod admission;
pub mod aggregate;
pub mod attestation;
pub mod capability_registry;
pub mod capability_uri;
pub mod challenge;
pub mod consequence;
pub mod custody_violation;
pub(crate) mod participation;
pub mod renewal;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use scp_identity::DID;

// Re-export all public types from submodules.
pub use admission::{
    AdmissionError, CapabilityRequirement, VerificationLevel, check_capability_requirements,
};
pub use attestation::{
    Attestation, AttestationEvidence, AttestorInfo, DidPublicKeyResolver, FreshnessStatus,
    IdentityDidPublicKeyResolver, RevocationStatus, ThresholdRequirement, ThresholdResult,
    check_attestation_freshness, check_threshold_attestation, verify_attestation,
};
pub use capability_registry::{
    CapabilityRegistryError, RegistryEntry, is_known_protocol_capability,
    is_known_system_capability, lookup_protocol_capability, lookup_system_capability,
    validate_capability_uri,
};
pub use capability_uri::{CapabilityUri, CapabilityUriError};
// ParticipationRecord and compute_participation_record are not part of
// the public API. The module is pub(crate); the testing feature gate
// re-exports compute_participation_record for integration tests.
pub use challenge::{
    ChallengeRequest, ChallengeResponse, ChallengeSigner, ChallengeType, ChallengeVerification,
    VerificationMethod, issue_challenge, verify_challenge_response,
};
pub use consequence::{
    ConsequenceAction, ConsequenceEvidence, ConsequenceRule, ConsequenceTrigger,
    TriggeredConsequence, evaluate_consequence_rules,
};
pub use custody_violation::{
    ActionCategory, CounterAttestation, CustodyViolationError, CustodyViolationResult,
    CustodyViolationType, ScpCustodyViolationAttestation, classify_action, enforce_category_a,
};
#[cfg(feature = "testing")]
pub use participation::compute_participation_record;
pub use participation::{
    ParticipationFact, ParticipationProfile, ParticipationRecord, ParticipationThreshold,
    RequireParticipation,
};
pub use renewal::{DefaultRenewalChecker, RenewalChecker, RenewalError, renew_attestation};

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
#[derive(Debug, thiserror::Error)]
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
    #[error("system capability '{uri}' is not challengeable — system capabilities are feature flags, not testable capabilities")]
    NotChallengeable {
        /// The system capability URI that was rejected.
        uri: String,
    },
}

// ---------------------------------------------------------------------------
// AttestationType
// ---------------------------------------------------------------------------

/// Attestation type variants (ADR-017).
///
/// Each variant represents a category of attestation that can be issued,
/// verified, and used in threshold checks. The type determines what evidence
/// is expected and how the attestation contributes to trust evaluation.
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
///
/// Used in canonical hash computation. The tag values are protocol constants
/// and must never change. Follows the same pattern as `event_type_tag` in
/// `event_log/tree.rs`.
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

// ConsequenceRule is now defined in consequence.rs and re-exported above.
// ChallengeRequest and ChallengeResponse are now defined in challenge.rs and
// re-exported above.

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
///
/// This struct collects all verifiable facts from the trust engine's four
/// layers into a single value that agents consume for their own trust
/// evaluation logic. The trust engine does not produce trust "scores" --
/// each agent applies its own criteria.
///
/// See ADR-017 in `.docs/adrs/phase-4.md`.
#[derive(Debug, Clone)]
pub struct TrustInput {
    /// Verified attestations (Layer 3). Each attestation has been signature-
    /// verified and checked for expiry and revocation.
    pub verified_attestations: Vec<Attestation>,

    /// Participation profile (Layer 2). Computed from the local view of the
    /// event log for the subject DID.
    pub participation_record: ParticipationRecord,

    /// Challenge-response results (Layer 3). Each entry is a verified
    /// challenge-response pair with metadata distinguishing self-attested
    /// vs challenge-verified capabilities.
    pub challenge_results: Vec<ChallengeVerification>,

    /// Declared consequence rules (Layer 4). These are the rules declared at
    /// context creation that govern enforcement actions.
    pub consequence_structure: Vec<ConsequenceRule>,

    /// Threshold counts per attestation type: `(met, required)`.
    ///
    /// For each attestation type, records how many attestations of that type
    /// have been verified (`met`) out of how many are required (`required`).
    pub threshold_counts: HashMap<AttestationType, (u32, u32)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// All `AttestationType` variants, kept in sync via exhaustive match.
    const ALL_ATTESTATION_TYPES: [AttestationType; 8] = [
        AttestationType::IdentityLink,
        AttestationType::CapabilityDelegation,
        AttestationType::ToolIntegrity,
        AttestationType::AgentCapability,
        AttestationType::Endorsement,
        AttestationType::RoleAssignment,
        AttestationType::ContextEndorsement,
        AttestationType::ParticipationWitness,
    ];

    #[test]
    fn attestation_type_tag_returns_unique_values() {
        let mut seen = HashSet::new();
        for variant in &ALL_ATTESTATION_TYPES {
            let tag = attestation_type_tag(variant);
            assert!(
                seen.insert(tag),
                "duplicate attestation_type_tag value {tag} for {variant:?}"
            );
        }
    }

    #[test]
    fn attestation_type_tag_is_exhaustive() {
        // This test documents intent: the const fn match is already
        // exhaustive by Rust's type system, but this verifies all 8
        // variants are covered and produce values in the expected range.
        for (i, variant) in ALL_ATTESTATION_TYPES.iter().enumerate() {
            let tag = attestation_type_tag(variant);
            assert!(
                (tag as usize) < ALL_ATTESTATION_TYPES.len(),
                "attestation_type_tag({variant:?}) = {tag}, expected < {}",
                ALL_ATTESTATION_TYPES.len()
            );
            assert_eq!(
                tag as usize, i,
                "attestation_type_tag({variant:?}) = {tag}, expected {i}"
            );
        }
    }
}
