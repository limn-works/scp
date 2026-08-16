//! Trust engine types for SCP (Four-Layer Evaluation).
//!
//! Pure protocol types and submodule declarations. Async modules remain in
//! scp-runtime.

pub mod admission;
pub mod aggregate;
pub mod attestation;
pub mod capability_registry;
pub mod capability_uri;
pub mod caveats;
pub mod challenge;
pub mod consequence;
pub mod custody_violation;
pub mod participation;
pub mod renewal;
pub mod sybil;
pub mod ucan;

// Re-exports for backward compatibility.
pub use admission::{
    AdmissionError, CapabilityRequirement, VerificationLevel, check_capability_requirements,
};
pub use attestation::{
    Attestation, AttestationEvidence, DidPublicKeyResolver, IdentityDidPublicKeyResolver,
    RevocationStatus, canonical_attestation_bytes, verify_attestation,
    verify_attestation_with_revocation,
};
pub use capability_uri::{CapabilityUri, CapabilityUriError};
pub use caveats::{
    AttenuationViolation, CAVEAT_MINT_LIMIT_EXCEEDED_CODE, CaveatMintError, CaveatSerError,
    CheckInvocationError, DaysOfWeekMask, HoursOfDayMask, InvocationCaveats,
    MAX_INPUT_SCHEMA_BYTES, MAX_INPUT_SCHEMA_DEPTH, MAX_LIST_ENTRIES, MAX_POPULATED_CAVEATS,
    MAX_RATE_WINDOW_SECS, MaskWidthError, RateWindow, assert_mask_widths,
};
pub use challenge::{
    ChallengeRequest, ChallengeResponse, ChallengeSigner, ChallengeType, ChallengeVerification,
    canonical_challenge_verification_bytes, issue_challenge, verify_challenge_response,
    verify_challenge_verification,
};
pub use custody_violation::{
    ActionCategory, COUNTER_ATTESTATION_DOMAIN, CUSTODY_VIOLATION_DOMAIN, CounterAttestation,
    CustodyViolationError, CustodyViolationResult, CustodyViolationType,
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
pub use ucan::outlet_kind_for_stem;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use scp_did::DID;

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

/// A outlet identifier string.
///
/// Matches the `OutletId` type alias in `context::roles`, but redefined here
/// to avoid coupling the trust module to the context module's internals.
pub type OutletId = String;

// ---------------------------------------------------------------------------
// CaveatKind
// ---------------------------------------------------------------------------

/// The three counter-bearing §7.3.8 invocation caveats — the caveats whose
/// enforcement requires durable per-`(context, ucan_cid)` accounting rather
/// than a stateless local check.
///
/// The stateless caveats (`amount_max_per_call`, `allowed_adapters`,
/// `allowed_target_dids`, `input_schema`, and the time-box / origin fields)
/// are checked synchronously by
/// [`InvocationCaveats::check_invocation_local`](crate::trust::caveats::InvocationCaveats::check_invocation_local)
/// and are NOT modeled here — they consume no counter capacity.
///
/// Each variant maps to a stable wire slug via [`Self::as_str`]; the slugs are
/// the §7.3.8 caveat field names (`maxCalls`, `amountMaxCumulative`,
/// `rateWindow`) so error envelopes and persisted diagnostics name the caveat
/// that fired unambiguously across every SDK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CaveatKind {
    /// Absolute invocation cap (`max_calls`). Every admitted invocation
    /// consumes one unit of capacity.
    MaxCalls,
    /// Cumulative economic ceiling (`amount_max_cumulative`). Each invocation
    /// consumes its computed cost.
    AmountCumulative,
    /// Sliding-window rate cap (`rate_window`). Admission depends on the count
    /// of timestamps already inside the active window, not on any amount.
    RateWindow,
}

impl CaveatKind {
    /// Returns the stable §7.3.8 wire slug for this caveat kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MaxCalls => "maxCalls",
            Self::AmountCumulative => "amountMaxCumulative",
            Self::RateWindow => "rateWindow",
        }
    }
}

impl std::fmt::Display for CaveatKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

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

    /// The challenge response's `completed_at` falls outside the acceptable
    /// freshness window: either older than the timeout, or implausibly far in
    /// the future relative to the verifier's clock (clock-skew bound).
    #[error(
        "challenge {challenge_id}: outside freshness window (timeout {timeout_secs}s, completed at \
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

    /// Constructing the canonical signing/verification bytes for a
    /// caller-supplied credential failed (e.g. evidence / claim / revocation
    /// serialization or the canonical hash itself).
    ///
    /// Purpose-built so the verify-on-ingest rejection allowlist
    /// (`is_verification_rejection`) can be keyed on a variant that NO
    /// infrastructure path ever produces — a credential whose own bytes cannot
    /// be canonicalized cannot be authenticated, so it is a REJECTION of that one
    /// entry (drop it), never a transient backend fault (which uses
    /// [`TrustError::StoreError`]). Keeping this distinct from
    /// [`TrustError::InvalidEventData`] / [`TrustError::ChallengeSigningFailed`]
    /// makes the rejection set closed by construction: those variants are no
    /// longer overloaded to mean "drop one entry".
    #[error("canonicalization failed: {reason}")]
    CanonicalizationFailed {
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

    /// The challenge verification record's verifier Ed25519 signature is
    /// invalid, indicating a forged or tampered `passed`/`score` trust signal.
    /// The verifier signature binds every consumed field (`passed`, `score`,
    /// `expires_at`, `subject_did`, `verifier_did`, `capability_uri`), so a
    /// failure here means the record cannot be trusted as a verifier's claim.
    #[error("challenge verification {verification_id}: verifier signature invalid: {reason}")]
    ChallengeVerificationSignatureInvalid {
        /// The verification record ID.
        verification_id: String,
        /// Human-readable description of the failure.
        reason: String,
    },

    /// The challenge verification record has expired (`expires_at <= now`).
    /// Challenges are repeatable (spec §7.3.4); an expired verification must be
    /// re-challenged and MUST NOT be consumed as a current trust signal.
    #[error("challenge verification {verification_id}: expired at {expires_at} (now {now})")]
    ChallengeVerificationExpired {
        /// The verification record ID.
        verification_id: String,
        /// The Unix timestamp (seconds) at which the verification expired.
        expires_at: u64,
        /// The current Unix timestamp (seconds) at evaluation.
        now: u64,
    },

    /// The challenge verification record is not bound to the context it is being
    /// ingested/consumed under. A verifier-signed result for context A (or a
    /// context-agnostic `None` result) MUST NOT be replayed into context B's
    /// aggregation — `context_id` is a signed field, so the binding is
    /// cryptographically authentic but must still match the target context.
    #[error(
        "challenge verification {verification_id}: context mismatch (record {record_context:?}, expected {expected_context})"
    )]
    ChallengeContextMismatch {
        /// The verification record ID.
        verification_id: String,
        /// The `context_id` carried by the record (`None` if context-agnostic).
        record_context: Option<String>,
        /// The target context the record is being consumed under.
        expected_context: String,
    },

    /// The challenge verification record's signed `subject_did` does not match
    /// the subject it is being aggregated/checked for. `subject_did` is part of
    /// the canonical preimage, so the binding is cryptographically authentic; a
    /// genuine, in-context, unexpired result minted for subject A MUST NOT be
    /// counted toward subject B's trust signal or admission. This closes
    /// cross-subject attribution by construction at the verify site, rather than
    /// relying on the store key alone.
    #[error(
        "challenge verification {verification_id}: subject mismatch (record {record_subject}, expected {expected_subject})"
    )]
    ChallengeSubjectMismatch {
        /// The verification record ID.
        verification_id: String,
        /// The signed `subject_did` carried by the record.
        record_subject: String,
        /// The subject the record is being consumed for.
        expected_subject: String,
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
    /// Attests to the integrity of a outlet.
    OutletIntegrity,
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
        AttestationType::OutletIntegrity => 2,
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

/// Reference to a credential-layer attestation (§7.4) for a subject.
///
/// NOT an event-log entry: there is no attestation event type and attestations
/// are never context-log leaves (§7.3.2). This references the credential-layer
/// artifact, sourced from the subject's accessible attestations, not the Merkle
/// log — so `event_sequence` carries no log position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationReference {
    /// Unix timestamp (seconds) when the attestation was issued (or last
    /// renewed).
    pub timestamp: u64,
    /// Always `0`: attestations are credential-layer artifacts, not event-log
    /// leaves, so they carry no log sequence number.
    pub event_sequence: u64,
    /// The DID of the attestation issuer (§7.4).
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
