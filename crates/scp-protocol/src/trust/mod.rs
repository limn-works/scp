//! Trust engine types for SCP (Four-Layer Evaluation).
//!
//! Pure protocol types and submodule declarations. Async modules remain in
//! scp-runtime.

pub mod admission;
pub mod aggregate;
pub mod attestation;
pub mod capability_definition;
pub mod capability_registry;
pub mod capability_uri;
pub mod caveats;
pub mod challenge;
#[cfg(test)]
mod challenge_fixtures;
pub mod consequence;
pub mod custody_violation;
pub mod identifier;
mod language_tag;
pub mod participation;
pub mod renewal;
pub mod schema_gate;
pub mod sybil;
pub mod ucan;

// Re-exports for backward compatibility.
pub use admission::{
    AdmissionCheck, AdmissionError, CapabilityRequirement, CapabilityRequirements,
    RawCapabilityRequirement, RetryCap, VerificationLevel, check_capability_requirements,
};
pub use attestation::{
    ActiveKeyResolver, Attestation, AttestationEvidence, RevocationStatus,
    canonical_attestation_bytes, verify_attestation,
};
// The DID-string key fixture is not an `#active` resolution, so its re-export
// carries the same `testing` gate as its definition.
#[cfg(any(test, feature = "testing"))]
pub use attestation::IdentityDidPublicKeyResolver;
pub use capability_definition::{
    CapabilityDefinition, CapabilityDefinitionSource, DefinitionError, ProtocolOnlyDefinitions,
    SignedCapabilityDefinition,
};
pub use capability_registry::{ChallengeStandard, MinCases};
pub use capability_uri::{CapabilityUri, CapabilityUriError};
pub use caveats::{
    AttenuationViolation, CAVEAT_MINT_LIMIT_EXCEEDED_CODE, CaveatMintError, CaveatSerError,
    CheckInvocationError, DaysOfWeekMask, HoursOfDayMask, InvocationCaveats,
    MAX_INPUT_SCHEMA_BYTES, MAX_INPUT_SCHEMA_DEPTH, MAX_LIST_ENTRIES, MAX_POPULATED_CAVEATS,
    MAX_RATE_WINDOW_SECS, MaskWidthError, RateWindow, assert_mask_widths,
};
pub use challenge::{
    AnswerKey, AttemptLedgerView, AuthenticatedResponse, CHALLENGE_CLOCK_SKEW_SECS,
    CHALLENGE_GRADING_BUDGET_SECS, CHALLENGE_LEASE_MARGIN_SECS, CaseResult, ChallengeCase,
    ChallengeClosure, ChallengePolicy, ChallengeRequest, ChallengeResponse, ChallengeType,
    ChallengeVerification, ExpectedOutput, GradeOutcome, MAX_CAPABILITY_DESCRIPTION_BYTES,
    MAX_CAPABILITY_REQUIREMENTS_PER_CONTEXT, MAX_CHALLENGE_JSON_DEPTH,
    MAX_CHALLENGE_RESPONSE_BYTES, MAX_CHALLENGE_SCHEMA_BYTES, MAX_CHALLENGE_WINDOW_SECS,
    MAX_TRUSTED_VERIFIERS_PER_REQUIREMENT, MAX_VERIFICATION_VALIDITY_SECS, NewChallenge,
    PolicyPick, TOTAL_WEIGHT_BPS, TestCase, TestOutput, UnsignedChallengeRequest,
    UnsignedChallengeResponse, UnsignedChallengeVerification, authenticate_challenge_response,
    canonical_challenge_request_bytes, canonical_challenge_response_bytes,
    canonical_challenge_verification_bytes, challenge_request_signing_digest,
    challenge_request_unsigned, challenge_response_signing_digest, challenge_response_unsigned,
    challenge_suite_digest, challenge_verification_id, challenge_verification_signing_digest,
    challenge_verification_unsigned, check_attempt, check_challenge_json_bounds, grade,
    min_category_cases, verify_challenge_verification,
};
#[cfg(any(test, feature = "testing"))]
pub use challenge::{ChallengeSigner, issue_challenge};
pub use custody_violation::{
    ActionCategory, COUNTER_ATTESTATION_DOMAIN, CUSTODY_VIOLATION_DOMAIN, CounterAttestation,
    CustodyViolationError, CustodyViolationResult, CustodyViolationType,
    ScpCustodyViolationAttestation, classify_action, enforce_category_a,
};
pub use identifier::CanonicalIdentifier;
#[cfg(any(test, feature = "testing"))]
pub use participation::produce_participation_profile;
pub use participation::{
    ParticipationFact, ParticipationFacts, ParticipationInput, ParticipationProfile,
    ParticipationRecord, ParticipationThreshold, RequireParticipation,
    UnsignedParticipationProfile, compute_participation_record, participation_profile_unsigned,
};
pub use schema_gate::{SchemaGate, SchemaVerdict};
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

/// Which capacity a [`TrustError::GradingCapacityExhausted`] refusal ran out
/// of (spec 07 §7.3.4 step 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GradingCapacityCause {
    /// Every grading permit of the challenger is held.
    GradingPermits,
    /// The evaluator context's rate limit refused an evaluator call before
    /// the evaluator ran.
    EvaluatorRateLimit,
    /// The evaluator context's budget refused an evaluator call before the
    /// evaluator ran.
    EvaluatorBudget,
}

impl GradingCapacityCause {
    /// The cause's stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GradingPermits => "grading_permits",
            Self::EvaluatorRateLimit => "evaluator_rate_limit",
            Self::EvaluatorBudget => "evaluator_budget",
        }
    }
}

impl std::fmt::Display for GradingCapacityCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

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

    /// The challenge responder is not the challenged subject.
    #[error("challenge responder mismatch: expected {expected}, got {got}")]
    ChallengeResponderMismatch {
        /// The expected responder DID (the `subject` from the request).
        expected: String,
        /// The actual responder DID (from the response).
        got: String,
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
    /// ([`TrustError::is_record_rejection`]) can be keyed on a variant that NO
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
    /// identifier-scoped.
    #[error("unknown challenge capability URI: {uri}")]
    UnknownChallengeCapability {
        /// The unrecognized URI string.
        uri: String,
    },

    /// The challenge's test cases break a suite rule of spec 07 §7.3.4: the
    /// list is empty, a `test_id` repeats, the weights do not sum to 10000, an
    /// `input` or `expected` breaks the I-JSON numeric constraint, or a
    /// `multilingual/v1` `category` is not a well-formed BCP 47 tag.
    #[error("invalid challenge suite: {reason}")]
    InvalidChallengeSuite {
        /// Which rule the suite breaks.
        reason: String,
    },

    /// A challenge for a protocol capability URI carries fewer test cases than
    /// its standard's minimum (spec 07 §7.3.4.3).
    #[error(
        "challenge for {uri} carries {supplied} test cases{}, below the standard's minimum of {minimum}",
        category.as_deref().map(|c| format!(" in category '{c}'")).unwrap_or_default()
    )]
    ChallengeSuiteBelowMinimum {
        /// The protocol capability URI.
        uri: String,
        /// The standard's minimum: for the whole request, or per `category`.
        minimum: u32,
        /// How many cases the request carries (in `category`, when set).
        supplied: u32,
        /// The deficient category, when the standard counts per `category`
        /// (`multilingual/v1`); `None` when it counts the whole request.
        category: Option<String>,
    },

    /// The caller asked to check a response to a request another verifier
    /// issued: the request's signed `verifier` is not the caller.
    #[error("challenge verifier mismatch: request names {expected}, caller is {got}")]
    ChallengeVerifierMismatch {
        /// The request's signed `verifier`.
        expected: String,
        /// The verifier the caller passed.
        got: String,
    },

    /// The record's `verification_id` is not the spec 07 §7.3.4 derivation
    /// from its signed `verifier`, `subject`, `capability_uri`, `challenge_id`,
    /// `attempt` and `timestamp`.
    #[error("challenge verification {verification_id}: not the derived id {expected}")]
    ChallengeVerificationIdMismatch {
        /// The record's `verification_id` (lowercase hex).
        verification_id: String,
        /// The derived id (lowercase hex).
        expected: String,
    },

    /// The record's `expires_at` exceeds its `timestamp` by more than the
    /// 90-day maximum of spec 07 §7.3.4.
    #[error(
        "challenge verification {verification_id}: validity {validity_secs}s exceeds the maximum {max_secs}s"
    )]
    ChallengeVerificationValidityTooLong {
        /// The record's `verification_id` (lowercase hex).
        verification_id: String,
        /// `expires_at - timestamp`, in seconds.
        validity_secs: u64,
        /// The maximum validity, in seconds (90 days).
        max_secs: u64,
    },

    /// The record's `timestamp` is later than the verifier's clock plus the
    /// clock-skew tolerance of `09-security-model.md` §9.14 (spec 07 §7.3.4).
    /// Without this bound a record stamped years ahead would pass the 90-day
    /// validity cap and stay unexpired for years.
    #[error(
        "challenge verification {verification_id}: timestamp {timestamp} is later than now {now} plus the {skew_secs}s clock-skew tolerance"
    )]
    ChallengeVerificationFromFuture {
        /// The record's `verification_id` (lowercase hex).
        verification_id: String,
        /// The record's `timestamp`, in Unix seconds.
        timestamp: u64,
        /// The verifier's clock, in Unix seconds.
        now: u64,
        /// The clock-skew tolerance, in seconds (5 minutes).
        skew_secs: u64,
    },

    /// A public key could not be resolved because every resolution layer was
    /// unreachable. This is an infrastructure fault, not a judgement on the
    /// credential being verified: a caller retries, and a verify-on-ingest
    /// loop propagates it instead of dropping the credential
    /// ([`TrustError::is_record_rejection`] is `false`).
    #[error("key resolution unavailable for {did}: {reason}")]
    KeyResolutionUnavailable {
        /// The DID whose key could not be resolved.
        did: String,
        /// Why every layer was unreachable.
        reason: String,
    },

    /// The capability URI names a standard whose pass condition cannot be
    /// computed from the subject's outputs (spec 07 §7.3.4.7), or a system
    /// capability (`scp:system:*`), which is a feature flag and not a tested
    /// capability (ADR-041). Refused at creation and at consumption.
    #[error("capability '{uri}' is not gradable from outputs")]
    StandardNotGradable {
        /// The refused capability URI.
        uri: String,
    },

    /// The challenge request's Ed25519 signature is invalid, indicating the
    /// request may have been tampered with (e.g., extended timeout, changed
    /// `subject`).
    #[error("challenge request signature invalid: {reason}")]
    ChallengeRequestSignatureInvalid {
        /// Human-readable description of the failure.
        reason: String,
    },

    /// The challenge verification record's verifier Ed25519 signature is
    /// invalid, indicating a forged or tampered `passed`/`score` trust signal.
    /// The verifier signature binds every consumed field (`passed`, `score`,
    /// `expires_at`, `subject`, `verifier`, `capability_uri`, `suite_digest`), so a
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
    /// ingested/consumed under. A verifier-signed result for context A MUST NOT be replayed into context B's
    /// aggregation — `context_id` is a signed field, so the binding is
    /// cryptographically authentic but must still match the target context.
    #[error(
        "challenge verification {verification_id}: context mismatch (record {record_context}, expected {expected_context})"
    )]
    ChallengeContextMismatch {
        /// The verification record ID.
        verification_id: String,
        /// The `context_id` the record signs.
        record_context: String,
        /// The target context the record is being consumed under.
        expected_context: String,
    },

    /// The challenge verification record's signed `subject` does not match
    /// the subject it is being aggregated/checked for. `subject` is part of
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
        /// The signed `subject` carried by the record.
        record_subject: String,
        /// The subject the record is being consumed for.
        expected_subject: String,
    },

    /// An identifier is not the canonical encoding of its key (spec 07
    /// §7.3.4 "Identifiers"): a padding alias of a did:dht key, or a form the
    /// protocol does not accept.
    #[error("non-canonical identifier {identifier:?}: {reason}")]
    NonCanonicalIdentifier {
        /// The identifier as received.
        identifier: String,
        /// Why it is not canonical.
        reason: String,
    },

    /// The verifier and the subject decode to the same key (spec 07 §7.3.4
    /// steps 1 and 5(i)).
    #[error("challenge verifier and subject are the same identity: {identifier}")]
    SelfChallenge {
        /// The identifier both fields name.
        identifier: String,
    },

    /// No capability definition can be obtained for the URI (spec 07
    /// §7.3.4.6). This reports an outage, not a judgment on the subject.
    #[error("capability definition unavailable for {uri}")]
    CapabilityDefinitionUnavailable {
        /// The capability URI.
        uri: String,
    },

    /// Two validly signed definitions for one URI differ (spec 07 §7.3.4.6).
    #[error("capability definition equivocation for {uri}")]
    DefinitionEquivocation {
        /// The capability URI.
        uri: String,
    },

    /// A signed policy value lies outside the capability definition's limits
    /// or the protocol bounds (spec 07 §7.3.4 steps 1, 5(f) and 5(g)).
    #[error("challenge policy outside the definition of {uri}: {reason}")]
    PolicyOutsideDefinition {
        /// The capability URI.
        uri: String,
        /// Which limit the value breaks.
        reason: String,
    },

    /// A `SchemaMatch` schema is not admissible (spec 07 §7.3.4 step 1).
    #[error("test case {test_id:?}: schema rejected: {reason}")]
    SchemaRejected {
        /// The test case carrying the schema.
        test_id: String,
        /// Which admission rule the schema breaks.
        reason: String,
    },

    /// The challenge window `expires_at - created_at` is zero, above
    /// `MAX_CHALLENGE_WINDOW_SECS`, shorter than the cooldown, or overflows
    /// (spec 07 §7.3.4 step 1).
    #[error(
        "challenge window of {window_secs}s must be positive, at least the cooldown of {cooldown_secs}s and at most {max_secs}s"
    )]
    ChallengeWindowInvalid {
        /// The requested window, in seconds.
        window_secs: u64,
        /// The request's `cooldown_secs`, the shortest window allowed.
        cooldown_secs: u64,
        /// `MAX_CHALLENGE_WINDOW_SECS`.
        max_secs: u64,
    },

    /// The challenger's last challenge to this subject for this capability
    /// is still inside its window, closed or not (spec 07 §7.3.4 step 1).
    /// The caller may create a new one at `expires_at`.
    #[error(
        "challenge {challenge_id} to this subject for this capability is open until {expires_at}"
    )]
    ChallengeWindowOpen {
        /// The open challenge (lowercase hex).
        challenge_id: String,
        /// Its `expires_at`, the first Unix second a new challenge is accepted.
        expires_at: u64,
    },

    /// The grading time is at or before the request's `created_at` (spec 07
    /// §7.3.4 step 3, the attempt check). The window opens strictly after
    /// `created_at`, so the caller may resubmit the same attempt at
    /// `retry_at`.
    #[error(
        "challenge {challenge_id}: now {now} is not after created_at {created_at}; retry at {retry_at}"
    )]
    ChallengeNotYetGradable {
        /// The challenge id (lowercase hex).
        challenge_id: String,
        /// The clock reading, in Unix seconds.
        now: u64,
        /// The request's `created_at`.
        created_at: u64,
        /// `created_at + 1`, the first second the attempt may be graded.
        retry_at: u64,
    },

    /// The time is outside the challenge window (spec 07 §7.3.4 step 2), or
    /// a grading time is at or after `expires_at` (step 3).
    #[error(
        "challenge {challenge_id}: now {now} is not strictly inside the window ({created_at}, {expires_at})"
    )]
    ChallengeExpired {
        /// The challenge id (lowercase hex).
        challenge_id: String,
        /// The clock reading, in Unix seconds.
        now: u64,
        /// The request's `created_at`.
        created_at: u64,
        /// The request's `expires_at`.
        expires_at: u64,
    },

    /// The challenge is closed after a pass or its last allowed attempt.
    #[error("challenge {challenge_id}: closed")]
    ChallengeClosed {
        /// The challenge id (lowercase hex).
        challenge_id: String,
    },

    /// The attempt is not the last graded attempt plus one.
    #[error("challenge {challenge_id}: attempt {attempt} is out of order (expected {expected})")]
    AttemptOutOfOrder {
        /// The challenge id (lowercase hex).
        challenge_id: String,
        /// The attempt submitted.
        attempt: u32,
        /// The only attempt the challenger accepts next.
        expected: u32,
    },

    /// The attempt exceeds `1 + max_retries`.
    #[error("challenge {challenge_id}: attempt {attempt} exceeds {allowed} allowed attempts")]
    RetriesExhausted {
        /// The challenge id (lowercase hex).
        challenge_id: String,
        /// The attempt submitted.
        attempt: u32,
        /// `1 + max_retries`.
        allowed: u64,
    },

    /// The cooldown since the later of the last graded attempt and the last
    /// grading fault has not passed.
    #[error("challenge {challenge_id}: cooldown active, retry at {retry_after}")]
    CooldownActive {
        /// The challenge id (lowercase hex).
        challenge_id: String,
        /// The first Unix second at which the next attempt is accepted.
        retry_after: u64,
    },

    /// The response does not answer the request: another `challenge_id` or
    /// `request_digest`, or outputs that do not match the cases one for one
    /// and in order (spec 07 §7.3.4 step 3).
    #[error("challenge {challenge_id}: response does not match the request: {reason}")]
    OutputsMismatch {
        /// The request's challenge id (lowercase hex).
        challenge_id: String,
        /// What does not match.
        reason: String,
    },

    /// A response exceeds `MAX_CHALLENGE_RESPONSE_BYTES` or
    /// `MAX_CHALLENGE_JSON_DEPTH` (spec 07 §7.3.4 steps 2 and 3).
    #[error("challenge response too large: {reason}")]
    ResponseTooLarge {
        /// Which bound the response breaks.
        reason: String,
    },

    /// The challenger refused to open a challenge: its ledger already holds
    /// `MAX_OPEN_CHALLENGES_PER_CHALLENGER` open challenges (spec 09
    /// §9.18.C).
    #[error("challenger {challenger} cannot open a challenge: {open} challenges are open")]
    ChallengeNotOpen {
        /// The challenger.
        challenger: String,
        /// How many challenges its ledger holds open.
        open: usize,
    },

    /// The challenger's ledger holds no live challenge with this id, request
    /// digest and subject (spec 07 §7.3.4 step 3).
    #[error("challenge {challenge_id}: unknown to this challenger")]
    UnknownChallenge {
        /// The challenge id (lowercase hex).
        challenge_id: String,
    },

    /// Another grading of this challenge holds a live lease (spec 07 §7.3.4
    /// step 3).
    #[error("challenge {challenge_id}: another grading is in progress")]
    GradingInProgress {
        /// The challenge id (lowercase hex).
        challenge_id: String,
    },

    /// The grading lease this commit or fault names was replaced or released
    /// (spec 07 §7.3.4 step 4); nothing was written.
    #[error("challenge {challenge_id}: the grading lease was lost")]
    GradingLeaseLost {
        /// The challenge id (lowercase hex).
        challenge_id: String,
    },

    /// The challenger cannot grade now (spec 07 §7.3.4 step 3): every one
    /// of its `MAX_CONCURRENT_GRADINGS_PER_CHALLENGER` grading permits is
    /// held (spec 09 §9.18.C), or the evaluator context's reserve step
    /// refused an evaluator call on its rate limit or budget. The challenger
    /// recorded neither an attempt nor a fault, so the subject may resubmit
    /// the same attempt at once.
    #[error("challenger {challenger} cannot grade now: {cause}")]
    GradingCapacityExhausted {
        /// The challenger.
        challenger: String,
        /// Which capacity ran out.
        cause: GradingCapacityCause,
    },

    /// A `CustomEval` evaluator cannot run: its outlet is unregistered, it
    /// has no handler, or the challenger may not call it (spec 07 §7.3.4
    /// steps 1 and 3). A challenger fault, never an attempt.
    #[error("evaluator outlet {outlet_id} in context {context_id} is unavailable: {reason}")]
    EvaluatorUnavailable {
        /// The evaluator context.
        context_id: String,
        /// The evaluator outlet.
        outlet_id: String,
        /// Why it cannot run.
        reason: String,
    },

    /// The record's `timestamp` lies outside its signed challenge window
    /// (spec 07 §7.3.4 step 5(c)).
    #[error(
        "challenge verification {verification_id}: timestamp {timestamp} not strictly inside the challenge window ({created_at}, {expires_at})"
    )]
    ChallengeVerificationOutsideWindow {
        /// The record's `verification_id` (lowercase hex).
        verification_id: String,
        /// The record's `timestamp`.
        timestamp: u64,
        /// The record's `challenge_created_at`.
        created_at: u64,
        /// The record's `challenge_expires_at`.
        expires_at: u64,
    },

    /// The record's result fields contradict each other (spec 07 §7.3.4
    /// step 5(h)): `passed` is not `score >= pass_threshold_bps`, `score`
    /// exceeds 10000, or `pass_count` exceeds `test_count`.
    #[error("challenge verification {verification_id}: inconsistent result: {reason}")]
    ChallengeVerificationInconsistent {
        /// The record's `verification_id` (lowercase hex).
        verification_id: String,
        /// Which relation fails.
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

impl TrustError {
    /// Reports whether this error rejects the one credential being verified,
    /// as opposed to a fault in the machinery verifying it.
    ///
    /// `true` means the caller-supplied record is itself invalid (a bad
    /// signature, expired, revoked, a malformed revocation or evidence, the
    /// wrong context or subject, an underived id, an over-long validity, a
    /// timestamp beyond the clock-skew tolerance, or
    /// bytes that cannot be canonicalized): a verify-on-ingest or read-path
    /// loop drops that record and continues. `false` means an infrastructure
    /// fault (store failure, unreachable key resolution) or an error no record
    /// check produces: the loop propagates it, because dropping every record
    /// on a transient fault would zero a subject's trust without signal.
    ///
    /// The match names every variant with no wildcard arm, so a new variant
    /// does not compile until it is classified here.
    #[must_use]
    pub const fn is_record_rejection(&self) -> bool {
        match self {
            Self::AttestationSignatureInvalid { .. }
            | Self::AttestationExpired { .. }
            | Self::AttestationRevoked { .. }
            | Self::AttestationRevocationInvalid { .. }
            | Self::AttestationEvidenceInvalid { .. }
            | Self::ChallengeVerificationSignatureInvalid { .. }
            | Self::ChallengeVerificationExpired { .. }
            | Self::ChallengeContextMismatch { .. }
            | Self::ChallengeSubjectMismatch { .. }
            | Self::ChallengeVerificationIdMismatch { .. }
            | Self::ChallengeVerificationValidityTooLong { .. }
            | Self::ChallengeVerificationFromFuture { .. }
            | Self::ChallengeVerificationOutsideWindow { .. }
            | Self::ChallengeVerificationInconsistent { .. }
            | Self::NonCanonicalIdentifier { .. }
            | Self::SelfChallenge { .. }
            // A record naming a URI no standard or identifier defines is
            // itself invalid; an unreachable definition is not (below).
            | Self::UnknownChallengeCapability { .. }
            | Self::StandardNotGradable { .. }
            | Self::PolicyOutsideDefinition { .. }
            | Self::DefinitionEquivocation { .. }
            | Self::CanonicalizationFailed { .. } => true,
            // `InvalidEventData` and `ChallengeSigningFailed` are excluded on
            // purpose: no record-verification path raises them, so treating
            // them as rejections would swallow an unrelated fault.
            Self::NoEventsForSubject { .. }
            | Self::EmptyEventLog
            | Self::InvalidEventData { .. }
            | Self::ChallengeResponderMismatch { .. }
            | Self::ChallengeSignatureInvalid { .. }
            | Self::ChallengeSigningFailed { .. }
            | Self::InvalidChallengeSuite { .. }
            | Self::ChallengeSuiteBelowMinimum { .. }
            | Self::ChallengeRequestSignatureInvalid { .. }
            | Self::ChallengeVerifierMismatch { .. }
            // An unobtainable definition is an outage, not a judgment on the
            // record (spec 07 §7.3.4.6), so the loop propagates it.
            | Self::CapabilityDefinitionUnavailable { .. }
            | Self::SchemaRejected { .. }
            | Self::ChallengeWindowInvalid { .. }
            | Self::ChallengeNotYetGradable { .. }
            | Self::ChallengeExpired { .. }
            | Self::ChallengeClosed { .. }
            | Self::AttemptOutOfOrder { .. }
            | Self::RetriesExhausted { .. }
            | Self::CooldownActive { .. }
            | Self::ChallengeWindowOpen { .. }
            | Self::OutputsMismatch { .. }
            | Self::ResponseTooLarge { .. }
            | Self::ChallengeNotOpen { .. }
            | Self::UnknownChallenge { .. }
            | Self::GradingInProgress { .. }
            | Self::GradingLeaseLost { .. }
            | Self::GradingCapacityExhausted { .. }
            | Self::EvaluatorUnavailable { .. }
            | Self::KeyResolutionUnavailable { .. }
            | Self::NotAMember { .. }
            | Self::NotOptedIn { .. }
            | Self::StoreError { .. } => false,
        }
    }
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

    /// Threshold counts per attestation type: `(valid, required)`.
    ///
    /// A first element is `ThresholdResult::valid_count` — how many attestors
    /// an aggregation admitted — not `ThresholdResult::met`. Spec §7.3.5
    /// admits an attestor only when that attestor's attestation names an
    /// evaluated subject, names that attestor as its own issuer, carries a
    /// verifying signature, and carries a DID no admitted attestor already
    /// used. A threshold is met when a first element reaches a second AND an
    /// independence score reaches its own threshold; this pair carries no
    /// independence score, so a consumer that needs a met-or-not verdict calls
    /// [`check_threshold_attestation`](attestation::check_threshold_attestation)
    /// directly.
    pub threshold_counts: HashMap<AttestationType, (u32, u32)>,
}
