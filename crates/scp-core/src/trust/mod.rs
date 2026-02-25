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
//! - **Layer 2 (Behavioral):** [`BehavioralRecord`] computed locally from event
//!   logs. Two agents may compute different records from different event log
//!   views -- this is correct behavior, not a bug.
//! - **Layer 3 (Attestation):** [`Attestation`] verification with common
//!   envelope format. [`verify_attestation`] checks signatures, evidence,
//!   expiry, and revocation. [`check_attestation_freshness`] evaluates renewal
//!   intervals. [`check_threshold_attestation`] checks N-of-M requirements
//!   with independence scoring.
//! - **Layer 3 (Challenge-Response):** [`ChallengeRequest`] /
//!   [`ChallengeResponse`] for capability verification. *(Placeholder --
//!   SCP-063)*
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
//! - [`BehavioralRecord`] -- Verifiable facts computed from context event logs.
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
//!
//! Placeholder types (to be fleshed out in future stories):
//! - [`ChallengeRequest`], [`ChallengeResponse`] -- SCP-063

pub mod attestation;
pub mod behavioral;
pub mod consequence;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::event_log::DID;

// Re-export all public types from submodules.
pub use attestation::{
    Attestation, AttestationEvidence, AttestorInfo, DidPublicKeyResolver, FreshnessStatus,
    RevocationStatus, ThresholdRequirement, ThresholdResult, check_attestation_freshness,
    check_threshold_attestation, verify_attestation,
};
pub use behavioral::{BehavioralRecord, compute_behavioral_record};
pub use consequence::{
    ConsequenceAction, ConsequenceEvidence, ConsequenceRule, ConsequenceTrigger,
    TriggeredConsequence, evaluate_consequence_rules,
};

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

    /// A behavioral record computation failed due to invalid event data.
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
    /// Witnesses behavioral facts.
    BehavioralWitness,
}

// ---------------------------------------------------------------------------
// Placeholder types for future submodules
// ---------------------------------------------------------------------------

/// A challenge request for capability verification (ADR-017).
///
/// Placeholder -- will be fully implemented in SCP-063.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    /// Unique challenge identifier.
    pub challenge_id: String,
    /// DID of the challenger.
    pub challenger_did: DID,
    /// DID of the subject being challenged.
    pub subject_did: DID,
    /// Unix timestamp (seconds) when the challenge was created.
    pub created_at: u64,
}

/// A challenge response (ADR-017).
///
/// Placeholder -- will be fully implemented in SCP-063.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// The challenge ID this responds to.
    pub challenge_id: String,
    /// DID of the responder.
    pub responder_did: DID,
    /// Unix timestamp (seconds) when the response was completed.
    pub completed_at: u64,
}

// ConsequenceRule is now defined in consequence.rs and re-exported above.

// ---------------------------------------------------------------------------
// Supporting types for BehavioralRecord
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

    /// Behavioral record (Layer 2). Computed from the local view of the
    /// event log for the subject DID.
    pub behavioral_record: BehavioralRecord,

    /// Challenge-response results (Layer 3). Each pair contains the original
    /// request and the verified response.
    pub challenge_results: Vec<(ChallengeRequest, ChallengeResponse)>,

    /// Declared consequence rules (Layer 4). These are the rules declared at
    /// context creation that govern enforcement actions.
    pub consequence_structure: Vec<ConsequenceRule>,

    /// Threshold counts per attestation type: `(met, required)`.
    ///
    /// For each attestation type, records how many attestations of that type
    /// have been verified (`met`) out of how many are required (`required`).
    pub threshold_counts: HashMap<AttestationType, (u32, u32)>,
}
