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
//!   envelope format. *(Placeholder -- SCP-062)*
//! - **Layer 3 (Challenge-Response):** [`ChallengeRequest`] /
//!   [`ChallengeResponse`] for capability verification. *(Placeholder --
//!   SCP-063)*
//! - **Layer 4 (Consequence):** [`ConsequenceRule`] declared at context creation
//!   and protocol-enforced. *(Placeholder -- SCP-064)*
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
//! - [`AttestationReference`] -- Reference to an attestation in the event log.
//!
//! Placeholder types (to be fleshed out in future stories):
//! - [`Attestation`], [`AttestationType`] -- SCP-062
//! - [`ChallengeRequest`], [`ChallengeResponse`] -- SCP-063
//! - [`ConsequenceRule`] -- SCP-064

pub mod behavioral;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::event_log::DID;

// Re-export all public types from submodules.
pub use behavioral::{BehavioralRecord, compute_behavioral_record};

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
}

// ---------------------------------------------------------------------------
// Placeholder types for future submodules
// ---------------------------------------------------------------------------

/// Common attestation envelope (ADR-017, Spec section 7.4.1).
///
/// Placeholder -- will be fully implemented in SCP-062.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// Unique attestation identifier.
    pub id: String,
    /// The type of attestation.
    pub attestation_type: AttestationType,
    /// DID of the attestation issuer.
    pub issuer: DID,
    /// DID of the attestation subject.
    pub subject: DID,
    /// Unix timestamp (seconds) when the attestation was issued.
    pub issued_at: u64,
    /// Optional expiry timestamp (seconds).
    pub expires_at: Option<u64>,
}

/// Attestation type variants (ADR-017).
///
/// Placeholder -- will be fully implemented in SCP-062.
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

/// A declared consequence rule (ADR-017).
///
/// Consequences are part of the opt-in contract -- visible before joining,
/// protocol-enforced, verifiable. No hidden penalties.
///
/// Placeholder -- will be fully implemented in SCP-064.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsequenceRule {
    /// Human-readable description of what triggers this consequence.
    pub trigger_description: String,
    /// Human-readable description of the consequence action.
    pub action_description: String,
    /// Numeric threshold that triggers the consequence.
    pub threshold: u64,
}

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
