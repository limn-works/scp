//! napi-rs bridge for trust engine operations.
//!
//! Per-bridge-instance (`_on`) implementations consumed by the corresponding
//! methods on [`crate::scp::Scp`]. The free-function wrappers that routed
//! through the process-global default bridge instance were deleted.
//!
//! See ADR-017 in `.docs/adrs/phase-4.md`.

use scp_ffi_common::error_codes as codes;
use std::sync::Arc;

use napi_derive::napi;

use crate::error::ScpNapiError;
use crate::runtime::NapiBridgeInstance;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Trust score query result.
#[napi(object)]
pub struct NapiTrustScoreResult {
    /// Number of message events attributed to the DID.
    pub message_count: i64,
    /// Number of governance action events attributed to the DID.
    pub governance_count: i64,
    /// Normalized composite score (0.0–1.0).
    pub composite_score: f64,
}

/// Attestation verification result.
#[napi(object)]
pub struct NapiAttestationVerificationResult {
    /// Whether the attestation is valid.
    pub valid: bool,
    /// Chain depth (1 for single attestation).
    pub chain_depth: i32,
    /// Error message if verification failed, empty string if valid.
    pub error_message: String,
}

/// Challenge creation result.
#[napi(object)]
pub struct NapiChallengeResult {
    /// The unique challenge ID (UUID v4).
    pub challenge_id: String,
    /// The serialized challenge request (JSON).
    pub challenge_json: String,
}

/// Structured participation facts (§7.3.2) for a subject DID in a context.
///
/// The scalar projection of scp-core's `ParticipationRecord`, produced by
/// `Scp.participationRecord`. Counts are flattened ONCE in the shared Rust core
/// (`ParticipationFacts`) so TypeScript RECEIVES the facts rather than
/// re-aggregating event-log collections — eliminating cross-binding divergence
/// by construction. `u64` counts/timestamps are surfaced as napi `i64` (JS
/// number; lossless for these ranges, matching `NapiTrustScoreResult`);
/// booleans/strings map directly. See ADR-017.
#[napi(object)]
pub struct NapiParticipationRecord {
    /// The DID whose participation is summarized.
    pub subject_did: String,
    /// Total seconds of context participation (§7.3.2).
    pub participation_duration_secs: i64,
    /// Count of governance actions taken against this identity.
    pub governance_actions_against: i64,
    /// Count of governance actions initiated by this identity.
    pub governance_actions_by: i64,
    /// Total tool invocations across all tool types.
    pub tool_invocation_count: i64,
    /// Whether `tool_invocation_count` is anchored in the canonical Merkle log
    /// (`false` until ADR-051; consumers MUST NOT treat it as Merkle-proven).
    pub tool_invocation_count_anchored: bool,
    /// Number of contexts created by the subject.
    pub context_creation_count: i64,
    /// Number of role transitions for the subject.
    pub role_progression_count: i64,
    /// Number of accessible, currently-valid credential-layer attestations
    /// (§7.4) for the subject. Verifier-relative.
    pub attestation_count: i64,
    /// Whether `attestation_count` is anchored in / verifiable against a context
    /// Merkle root. Always `false` — credential-layer, verifier-relative (§7.4),
    /// never a context-event-log count (§7.3.2). Parallel of
    /// `tool_invocation_count_anchored`.
    pub attestation_count_anchored: bool,
    /// Unix timestamp (seconds) when the record was computed.
    pub computed_at: i64,
    /// Merkle root (hex) of the event log at computation time.
    pub event_log_root: String,
}

impl From<&scp_core::trust::ParticipationFacts> for NapiParticipationRecord {
    #[allow(clippy::cast_possible_wrap)] // counts/timestamps are well within i64::MAX; documented
    fn from(f: &scp_core::trust::ParticipationFacts) -> Self {
        Self {
            subject_did: f.subject_did.to_string(),
            participation_duration_secs: f.participation_duration_secs as i64,
            governance_actions_against: f.governance_actions_against as i64,
            governance_actions_by: f.governance_actions_by as i64,
            tool_invocation_count: f.tool_invocation_count as i64,
            tool_invocation_count_anchored: f.tool_invocation_count_anchored,
            context_creation_count: f.context_creation_count as i64,
            role_progression_count: f.role_progression_count as i64,
            attestation_count: f.attestation_count as i64,
            attestation_count_anchored: f.attestation_count_anchored,
            computed_at: f.computed_at as i64,
            event_log_root: hex::encode(f.event_log_root),
        }
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn validation_error(msg: &str) -> napi::Error {
    napi::Error::from(ScpNapiError::Validation {
        message: msg.to_owned(),
        code: codes::VALID_7010.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`trust_query_score`].
pub(crate) fn trust_query_score_on(
    bi: &NapiBridgeInstance,
    did: String,
    context_id: String,
) -> napi::Result<NapiTrustScoreResult> {
    if did.is_empty() {
        return Err(validation_error("DID must not be empty"));
    }
    if context_id.is_empty() {
        return Err(validation_error("context_id must not be empty"));
    }

    let (message_count, governance_count) =
        crate::runtime::query_trust_event_counts(bi, &context_id, &did);

    let total = message_count + governance_count;
    #[allow(clippy::cast_precision_loss)]
    let composite_score = (1.0 + total as f64).log10().min(1.0);

    #[allow(clippy::cast_possible_wrap)]
    Ok(NapiTrustScoreResult {
        message_count: message_count as i64,
        governance_count: governance_count as i64,
        composite_score,
    })
}

/// Per-bridge-instance implementation of `trust_verify_attestation`.
///
/// Pure verification — the bridge instance is unused but accepted for API
/// symmetry with the other `_on` helpers in this module.
pub(crate) fn trust_verify_attestation_on(
    _bi: &NapiBridgeInstance,
    attestation_json: String,
) -> napi::Result<NapiAttestationVerificationResult> {
    let attestation: scp_core::trust::Attestation = serde_json::from_str(&attestation_json)
        .map_err(|e| validation_error(&format!("failed to parse attestation JSON: {e}")))?;

    let resolver = scp_core::trust::IdentityDidPublicKeyResolver;
    let clock = scp_identity::cache::SystemClock;

    match scp_core::trust::verify_attestation(&attestation, &resolver, &clock) {
        Ok(()) => Ok(NapiAttestationVerificationResult {
            valid: true,
            chain_depth: 1,
            error_message: String::new(),
        }),
        Err(e) => Ok(NapiAttestationVerificationResult {
            valid: false,
            chain_depth: 0,
            error_message: format!("{e}"),
        }),
    }
}

/// Per-bridge-instance implementation of `trust_create_challenge`.
///
/// Pure construction — the bridge instance is unused but accepted for API
/// symmetry with the other `_on` helpers in this module.
pub(crate) fn trust_create_challenge_on(
    _bi: &NapiBridgeInstance,
    target_did: String,
) -> napi::Result<NapiChallengeResult> {
    if target_did.is_empty() {
        return Err(validation_error("target DID must not be empty"));
    }

    struct EphemeralSigner(ed25519_dalek::SigningKey);
    impl scp_core::trust::ChallengeSigner for EphemeralSigner {
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>, scp_core::trust::TrustError> {
            use ed25519_dalek::Signer;
            let sig = self.0.sign(data);
            Ok(sig.to_bytes().to_vec())
        }
    }

    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let signer = EphemeralSigner(signing_key);

    let request = scp_core::trust::issue_challenge(
        "did:key:ephemeral-challenger".into(),
        target_did.into(),
        scp_core::trust::ChallengeType::schema_validation(),
        "scp:capability:schema-validation/v1".to_string(),
        serde_json::json!({}),
        std::time::Duration::from_mins(5),
        &signer,
    )
    .map_err(|e| validation_error(&format!("challenge creation failed: {e}")))?;

    let challenge_json = serde_json::to_string(&request)
        .map_err(|e| validation_error(&format!("failed to serialize challenge: {e}")))?;

    Ok(NapiChallengeResult {
        challenge_id: request.challenge_id,
        challenge_json,
    })
}

/// Per-bridge-instance implementation of `trust_verify_response`.
///
/// Pure verification — the bridge instance is unused but accepted for API
/// symmetry with the other `_on` helpers in this module.
pub(crate) fn trust_verify_response_on(
    _bi: &NapiBridgeInstance,
    challenge_json: String,
    response_json: String,
) -> napi::Result<bool> {
    let request: scp_core::trust::ChallengeRequest = serde_json::from_str(&challenge_json)
        .map_err(|e| validation_error(&format!("failed to parse challenge JSON: {e}")))?;

    let response: scp_core::trust::ChallengeResponse = serde_json::from_str(&response_json)
        .map_err(|e| validation_error(&format!("failed to parse response JSON: {e}")))?;

    let resolver = scp_core::trust::IdentityDidPublicKeyResolver;
    let clock = scp_identity::cache::SystemClock;

    struct EphemeralSigner(ed25519_dalek::SigningKey);
    impl scp_core::trust::ChallengeSigner for EphemeralSigner {
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>, scp_core::trust::TrustError> {
            use ed25519_dalek::Signer;
            let sig = self.0.sign(data);
            Ok(sig.to_bytes().to_vec())
        }
    }

    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let signer = EphemeralSigner(signing_key);

    Ok(scp_core::trust::verify_challenge_response(
        &request, &response, &resolver, &clock, &signer, None,
    )
    .is_ok())
}

// ---------------------------------------------------------------------------
// verify_participation_requirements (SCP-BA-004)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of `verify_participation_requirements`.
///
/// Pure verification — the bridge instance is unused but accepted for API
/// symmetry with the other `_on` helpers in this module.
///
/// `expected_subject` is the DID of the agent being admitted: only profiles
/// whose signed `subject_did` equals it contribute to any accounting, closing
/// cross-subject participation-profile replay.
pub(crate) fn verify_participation_requirements_on(
    _bi: &NapiBridgeInstance,
    expected_subject: String,
    requirements_json: String,
    profile_json: String,
) -> napi::Result<()> {
    // Full DID-format validation (matching the PyO3 reference bridge), not just a
    // non-empty check, so all native bridges reject malformed ids identically.
    scp_ffi_common::validate::validate_did(&expected_subject)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let requirements: Vec<scp_core::trust::RequireParticipation> =
        serde_json::from_str(&requirements_json).map_err(|e| {
            validation_error(&format!(
                "failed to parse participation requirements JSON: {e}"
            ))
        })?;

    let profiles: Vec<scp_core::trust::ParticipationProfile> = serde_json::from_str(&profile_json)
        .map_err(|e| {
            validation_error(&format!("failed to parse participation profiles JSON: {e}"))
        })?;

    // Fail-closed clock: a pre-epoch host clock is an unrecoverable environment
    // failure and must not silently read as time 0, which would make every
    // participation statement appear maximally fresh and bypass `max_age_secs`.
    // Matches the SystemClock invariant used on the verify-on-ingest path.
    let current_time = scp_primitives::Clock::now_secs(&scp_primitives::SystemClock);

    scp_core::trust::verify_participation_requirements(
        current_time,
        &expected_subject,
        &requirements,
        &profiles,
    )
    .map_err(|e| validation_error(&format!("participation admission verification failed: {e}")))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// check_capability_requirements (§7.3.4.4, SCP-ACR-008)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of `check_capability_requirements`.
///
/// Verifies that an agent meets a context's capability requirements for
/// admission. Pure verification — the bridge instance is unused (the production
/// `IdentityDidPublicKeyResolver` is stateless) but accepted for API symmetry
/// with the other `_on` helpers in this module.
///
/// `subject_did` is the DID of the agent being admitted and `context_id` the
/// context: a `ChallengeVerification` only satisfies a requirement when its
/// signed `subject_did`/`context_id` equal these values, closing cross-subject
/// and cross-context attribution. Authenticity is not authorization — a passing
/// challenge-verification check does not establish verifier legitimacy (see spec
/// §7.3.4.4).
pub(crate) fn check_capability_requirements_on(
    _bi: &NapiBridgeInstance,
    context_id: String,
    subject_did: String,
    requirements_json: String,
    agent_capabilities_json: String,
    challenge_verifications_json: String,
) -> napi::Result<()> {
    // Full DID-format validation (matching the PyO3 reference bridge), not just a
    // non-empty check, so all native bridges reject malformed ids identically.
    scp_ffi_common::validate::validate_did(&subject_did)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let requirements: Vec<scp_core::trust::CapabilityRequirement> =
        serde_json::from_str(&requirements_json).map_err(|e| {
            validation_error(&format!(
                "failed to parse capability requirements JSON: {e}"
            ))
        })?;

    let agent_capabilities: Vec<scp_core::trust::CapabilityUri> =
        serde_json::from_str(&agent_capabilities_json).map_err(|e| {
            validation_error(&format!("failed to parse agent capabilities JSON: {e}"))
        })?;

    let challenge_verifications: Vec<scp_core::trust::ChallengeVerification> =
        serde_json::from_str(&challenge_verifications_json).map_err(|e| {
            validation_error(&format!(
                "failed to parse challenge verifications JSON: {e}"
            ))
        })?;

    let resolver = scp_core::trust::IdentityDidPublicKeyResolver;
    let clock = scp_identity::cache::SystemClock;

    scp_core::trust::check_capability_requirements(
        &requirements,
        &agent_capabilities,
        &challenge_verifications,
        &context_id,
        &subject_did,
        &resolver,
        &clock,
    )
    .map_err(|e| validation_error(&format!("capability admission verification failed: {e}")))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// aggregate_trust_input (§7.3)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`aggregate_trust_input`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn aggregate_trust_input_on(
    bi: &NapiBridgeInstance,
    context_id: String,
    subject_did: String,
    events_json: String,
    merkle_root_json: String,
    consequence_rules_json: String,
    threshold_requirements_json: String,
    attestor_sets_json: String,
    cached_attestations_json: String,
    challenge_results_json: String,
) -> napi::Result<String> {
    if context_id.is_empty() {
        return Err(validation_error("context_id must not be empty"));
    }
    if subject_did.is_empty() {
        return Err(validation_error("subject DID must not be empty"));
    }

    let events: Vec<scp_event_log::Event> = serde_json::from_str(&events_json)
        .map_err(|e| validation_error(&format!("failed to parse events JSON: {e}")))?;

    let merkle_root_vec: Vec<u8> = serde_json::from_str(&merkle_root_json)
        .map_err(|e| validation_error(&format!("failed to parse merkle_root JSON: {e}")))?;
    let merkle_root: [u8; 32] = merkle_root_vec.try_into().map_err(|v: Vec<u8>| {
        validation_error(&format!(
            "merkle_root must be exactly 32 bytes, got {}",
            v.len()
        ))
    })?;

    let consequence_rules: Vec<scp_core::trust::ConsequenceRule> =
        serde_json::from_str(&consequence_rules_json).map_err(|e| {
            validation_error(&format!("failed to parse consequence_rules JSON: {e}"))
        })?;

    let threshold_requirements: std::collections::HashMap<
        scp_core::trust::AttestationType,
        scp_core::trust::ThresholdRequirement,
    > = serde_json::from_str(&threshold_requirements_json).map_err(|e| {
        validation_error(&format!("failed to parse threshold_requirements JSON: {e}"))
    })?;

    let attestor_sets: std::collections::HashMap<
        scp_core::trust::AttestationType,
        Vec<scp_core::trust::AttestorInfo>,
    > = serde_json::from_str(&attestor_sets_json)
        .map_err(|e| validation_error(&format!("failed to parse attestor_sets JSON: {e}")))?;

    let cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation> =
        serde_json::from_str(&cached_attestations_json).map_err(|e| {
            validation_error(&format!("failed to parse cached_attestations JSON: {e}"))
        })?;

    let challenge_results: Vec<scp_core::trust::ChallengeVerification> =
        serde_json::from_str(&challenge_results_json).map_err(|e| {
            validation_error(&format!("failed to parse challenge_results JSON: {e}"))
        })?;

    // Route trust aggregation through this bridge instance's
    // `ProtocolRepoVariant` so SQLite-backed bridges store trust
    // attestations in the same SQLCipher database as context snapshots and
    // event log entries. Per-bridge dispatch cannot be `None` — each
    // `NapiBridgeInstance` owns a concrete variant from construction, so
    // the split-brain failure mode main's `Option` guarded against
    // (trust writes silently landing in an ephemeral store while
    // context/event-log writes landed in SQLCipher) is structurally
    // unreachable.
    match crate::runtime::protocol_repository(bi) {
        crate::runtime::ProtocolRepoVariant::InMemory(repo) => {
            let handle = crate::runtime().handle().clone();
            let bridge =
                scp_core::trust::ProtocolRepositoryTrustBridge::new(Arc::clone(repo), handle);
            scp_ffi_common::trust_store::populate_and_aggregate(
                bridge,
                &context_id,
                &subject_did,
                cached_attestations,
                &challenge_results,
                &events,
                merkle_root,
                &consequence_rules,
                &threshold_requirements,
                &attestor_sets,
            )
            .map_err(|e| validation_error(&e.to_string()))
        }
        crate::runtime::ProtocolRepoVariant::Sqlite(repo) => {
            let handle = crate::runtime().handle().clone();
            let bridge =
                scp_core::trust::ProtocolRepositoryTrustBridge::new(Arc::clone(repo), handle);
            scp_ffi_common::trust_store::populate_and_aggregate(
                bridge,
                &context_id,
                &subject_did,
                cached_attestations,
                &challenge_results,
                &events,
                merkle_root,
                &consequence_rules,
                &threshold_requirements,
                &attestor_sets,
            )
            .map_err(|e| validation_error(&e.to_string()))
        }
    }
}

/// Per-instance participation-record computation (§7.3.2) for `subject_did` in
/// `context_id`.
///
/// Sources the subject's accessible, currently-valid attestations from THIS
/// instance's `ProtocolRepository` variant (populating any caller-supplied
/// `cached_attestations_json` first, exactly as `aggregate_trust_input_on`
/// does) — the REAL credential-layer source, not `&[]`. The shared Supervisor
/// gathers the FULL event log + Merkle root for every other fact. Returns the
/// flattened typed record so the SDK never re-aggregates.
/// Builds a `ProtocolRepositoryTrustBridge` over the concrete backend behind a
/// [`ProtocolRepoVariant`] arm and reads back the subject's verified
/// attestations. Single source of truth for the per-backend
/// attestation-sourcing path: both `ProtocolRepoVariant` arms route through this
/// one generic body (mirroring the `PyO3` bridge's `run_verified_attestations`).
/// The match remains pure type dispatch because each variant holds a distinct
/// concrete `ProtocolRepository<S>`.
fn run_verified_attestations<S: scp_platform::traits::Storage + 'static>(
    repo: &Arc<scp_core::store::ProtocolRepository<S>>,
    context_id: &str,
    subject_did: &str,
    cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation>,
) -> Result<Vec<scp_core::trust::attestation::Attestation>, scp_core::trust::TrustError> {
    let handle = crate::runtime().handle().clone();
    let bridge = scp_core::trust::ProtocolRepositoryTrustBridge::new(Arc::clone(repo), handle);
    scp_ffi_common::trust_store::verified_attestations(
        bridge,
        context_id,
        subject_did,
        cached_attestations,
    )
}

pub(crate) fn participation_record_on(
    bi: &NapiBridgeInstance,
    context_id: String,
    subject_did: String,
    cached_attestations_json: String,
) -> napi::Result<NapiParticipationRecord> {
    // Full format validation (matching the PyO3 reference bridge), not just a
    // non-empty check, so all native bridges reject malformed ids identically.
    scp_ffi_common::validate::validate_context_id(&context_id)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    scp_ffi_common::validate::validate_did(&subject_did)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation> =
        serde_json::from_str(&cached_attestations_json).map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("failed to parse cached_attestations JSON: {e}"),
                code: codes::VALID_7059.to_owned(),
            })
        })?;

    // Source verified attestations from this instance's `ProtocolRepository`
    // (same backend as context/event-log writes). Both variants route through
    // the single generic `run_verified_attestations` helper.
    let verified = match crate::runtime::protocol_repository(bi) {
        crate::runtime::ProtocolRepoVariant::InMemory(repo) => {
            run_verified_attestations(repo, &context_id, &subject_did, cached_attestations)
        }
        crate::runtime::ProtocolRepoVariant::Sqlite(repo) => {
            run_verified_attestations(repo, &context_id, &subject_did, cached_attestations)
        }
    }
    // An error from `verified_attestations` is an INFRA fault (trust-store read,
    // signature-verification infrastructure) — NOT caller-input validation. Code
    // it as a context-layer fault (CTX_2000), consistent with the generic-failure
    // arm of `participation_record` below, and keep it propagating (fail-closed):
    // it must never be folded into the empty-log CTX_2076 path.
    .map_err(|e| {
        napi::Error::from(ScpNapiError::Context {
            message: e.to_string(),
            code: codes::CTX_2000.to_owned(),
        })
    })?;

    let record = crate::runtime::supervisor(bi)?
        .participation_record(&context_id, &subject_did, &verified)
        .map_err(|e| {
            // Empty-log → dedicated CTX_2076 so SDKs branch on the code, not the
            // message; genuine failures stay on the generic CTX_2000.
            let code = match e {
                scp_core::context::ContextError::NoParticipationFacts { .. } => codes::CTX_2076,
                _ => codes::CTX_2000,
            };
            napi::Error::from(ScpNapiError::Context {
                message: e.to_string(),
                code: code.to_owned(),
            })
        })?;

    let facts = scp_core::trust::ParticipationFacts::from(&record);
    Ok(NapiParticipationRecord::from(&facts))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::runtime::NapiBridgeInstance;

    fn test_bi() -> NapiBridgeInstance {
        NapiBridgeInstance::new_napi()
    }

    #[test]
    fn trust_query_score_validates_empty_did() {
        let bi = test_bi();
        let result = trust_query_score_on(&bi, String::new(), "ctx".to_owned());
        assert!(result.is_err());
    }

    #[test]
    fn trust_query_score_validates_empty_context() {
        let bi = test_bi();
        let result = trust_query_score_on(&bi, "did:key:test".to_owned(), String::new());
        assert!(result.is_err());
    }

    #[test]
    fn trust_query_score_returns_zeros_for_unknown_context() {
        let bi = test_bi();
        let result =
            trust_query_score_on(&bi, "did:key:test".to_owned(), "nonexistent-ctx".to_owned());
        assert!(result.is_ok());
        let score = result.unwrap();
        assert_eq!(score.message_count, 0);
        assert_eq!(score.governance_count, 0);
    }

    #[test]
    fn trust_create_challenge_validates_empty_did() {
        let bi = test_bi();
        let result = trust_create_challenge_on(&bi, String::new());
        assert!(result.is_err());
    }

    #[test]
    fn trust_create_challenge_succeeds() {
        let bi = test_bi();
        let result = trust_create_challenge_on(&bi, "did:key:target".to_owned());
        assert!(result.is_ok());
        let challenge = result.unwrap();
        assert!(!challenge.challenge_id.is_empty());
        assert!(!challenge.challenge_json.is_empty());
    }

    #[test]
    fn trust_verify_attestation_rejects_invalid_json() {
        let bi = test_bi();
        let result = trust_verify_attestation_on(&bi, "not json".to_owned());
        assert!(result.is_err());
    }

    #[test]
    fn trust_verify_response_rejects_invalid_json() {
        let bi = test_bi();
        let result = trust_verify_response_on(&bi, "bad".to_owned(), "bad".to_owned());
        assert!(result.is_err());
    }

    #[test]
    fn verify_participation_requirements_rejects_invalid_profile_json() {
        // Malformed JSON in the PROFILE position (now the 3rd arg).
        let bi = test_bi();
        let result = verify_participation_requirements_on(
            &bi,
            "did:key:alice".to_owned(),
            "[]".to_owned(),
            "not json".to_owned(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn verify_participation_requirements_rejects_invalid_requirements_json() {
        // Malformed JSON in the REQUIREMENTS position (now the 2nd arg).
        let bi = test_bi();
        let result = verify_participation_requirements_on(
            &bi,
            "did:key:alice".to_owned(),
            "not json".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn verify_participation_requirements_empty_inputs_succeeds() {
        let bi = test_bi();
        let result = verify_participation_requirements_on(
            &bi,
            "did:key:alice".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn verify_participation_requirements_rejects_empty_subject() {
        let bi = test_bi();
        let result = verify_participation_requirements_on(
            &bi,
            String::new(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn verify_participation_requirements_rejects_malformed_subject() {
        // Parity with the PyO3 reference bridge: `expected_subject` gets full
        // DID-format validation, not just a non-empty check.
        let bi = test_bi();
        let result = verify_participation_requirements_on(
            &bi,
            "not-a-did".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
    }

    // -- check_capability_requirements (§7.3.4.4, SCP-ACR-008) --

    #[test]
    fn check_capability_requirements_rejects_invalid_requirements_json() {
        let bi = test_bi();
        let result = check_capability_requirements_on(
            &bi,
            "ctx-1".to_owned(),
            "did:key:alice".to_owned(),
            "not json".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn check_capability_requirements_rejects_invalid_capabilities_json() {
        let bi = test_bi();
        let result = check_capability_requirements_on(
            &bi,
            "ctx-1".to_owned(),
            "did:key:alice".to_owned(),
            "[]".to_owned(),
            "not json".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn check_capability_requirements_rejects_invalid_verifications_json() {
        let bi = test_bi();
        let result = check_capability_requirements_on(
            &bi,
            "ctx-1".to_owned(),
            "did:key:alice".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
            "not json".to_owned(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn check_capability_requirements_empty_inputs_succeeds() {
        let bi = test_bi();
        let result = check_capability_requirements_on(
            &bi,
            "ctx-1".to_owned(),
            "did:key:alice".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn check_capability_requirements_rejects_empty_subject() {
        let bi = test_bi();
        let result = check_capability_requirements_on(
            &bi,
            "ctx-1".to_owned(),
            String::new(),
            "[]".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn check_capability_requirements_rejects_malformed_subject() {
        let bi = test_bi();
        let result = check_capability_requirements_on(
            &bi,
            "ctx-1".to_owned(),
            "not-a-did".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn check_capability_requirements_self_attested_present_succeeds() {
        // A SelfAttested requirement is satisfied by a declared capability — no
        // challenge verification (and thus no signature check) is needed.
        let bi = test_bi();
        let requirements = r#"[{"capability":"scp:capability:schema-validation/v1","verification_level":"SelfAttested"}]"#;
        let capabilities = r#"["scp:capability:schema-validation/v1"]"#;
        let result = check_capability_requirements_on(
            &bi,
            "ctx-1".to_owned(),
            "did:key:alice".to_owned(),
            requirements.to_owned(),
            capabilities.to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn check_capability_requirements_self_attested_missing_fails() {
        let bi = test_bi();
        let requirements = r#"[{"capability":"scp:capability:schema-validation/v1","verification_level":"SelfAttested"}]"#;
        let result = check_capability_requirements_on(
            &bi,
            "ctx-1".to_owned(),
            "did:key:alice".to_owned(),
            requirements.to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
    }

    /// Builds a genuinely verifier-signed `ChallengeVerification` JSON array
    /// bound to `subject_did`/`context_id`, far-future expiry, verifier DID
    /// derived from a fixed key (did:dht:z, offline-resolvable by the production
    /// `IdentityDidPublicKeyResolver`).
    fn signed_cv_json(uri: &str, subject_did: &str, context_id: &str) -> String {
        use ed25519_dalek::{Signer, SigningKey};

        let verifier_key = SigningKey::from_bytes(&[9u8; 32]);
        let verifier_pub = verifier_key.verifying_key().to_bytes();
        let verifier_did = scp_primitives::did_dht_from_public_key(&verifier_pub);
        let cap: scp_core::trust::CapabilityUri = uri.parse().unwrap();

        let mut cv = scp_core::trust::ChallengeVerification {
            verification_id: "bridge-test-challenge".to_owned(),
            verifier_did,
            subject_did: subject_did.into(),
            capability_uri: uri.to_owned(),
            challenge_type: scp_core::trust::ChallengeType::Uri(cap.clone()),
            verification_method: scp_core::trust::VerificationMethod::ChallengeVerified {
                challenge_type: scp_core::trust::ChallengeType::Uri(cap),
            },
            passed: true,
            score: None,
            test_count: 1,
            pass_count: 1,
            result: serde_json::Value::Bool(true),
            completed_at: 1_700_000_000,
            verified_at: 1_700_000_000,
            expires_at: 4_000_000_000,
            context_id: Some(context_id.to_owned()),
            verifier_signature: Vec::new(),
        };
        let canonical = scp_core::trust::canonical_challenge_verification_bytes(&cv).unwrap();
        cv.verifier_signature = verifier_key.sign(&canonical).to_bytes().to_vec();
        serde_json::to_string(&vec![cv]).unwrap()
    }

    #[test]
    fn check_capability_requirements_challenge_verified_happy_path() {
        let bi = test_bi();
        let uri = "scp:capability:prompt-injection-resistance/v1";
        let subject = "did:dht:zResponder";
        let ctx = "ctx-admission";
        let requirements =
            format!(r#"[{{"capability":"{uri}","verification_level":"ChallengeVerified"}}]"#);
        let cvs = signed_cv_json(uri, subject, ctx);
        let result = check_capability_requirements_on(
            &bi,
            ctx.to_owned(),
            subject.to_owned(),
            requirements,
            "[]".to_owned(),
            cvs,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn check_capability_requirements_rejects_cross_subject_replay() {
        let bi = test_bi();
        let uri = "scp:capability:prompt-injection-resistance/v1";
        let ctx = "ctx-admission";
        let requirements =
            format!(r#"[{{"capability":"{uri}","verification_level":"ChallengeVerified"}}]"#);
        let cvs = signed_cv_json(uri, "did:dht:zVictim", ctx);
        let result = check_capability_requirements_on(
            &bi,
            ctx.to_owned(),
            "did:dht:zAttacker".to_owned(),
            requirements,
            "[]".to_owned(),
            cvs,
        );
        assert!(result.is_err());
    }

    #[test]
    fn check_capability_requirements_rejects_cross_context_replay() {
        let bi = test_bi();
        let uri = "scp:capability:prompt-injection-resistance/v1";
        let subject = "did:dht:zResponder";
        let requirements =
            format!(r#"[{{"capability":"{uri}","verification_level":"ChallengeVerified"}}]"#);
        let cvs = signed_cv_json(uri, subject, "ctx-other");
        let result = check_capability_requirements_on(
            &bi,
            "ctx-admission".to_owned(),
            subject.to_owned(),
            requirements,
            "[]".to_owned(),
            cvs,
        );
        assert!(result.is_err());
    }

    #[test]
    fn aggregate_trust_input_rejects_empty_context() {
        let bi = test_bi();
        let result = aggregate_trust_input_on(
            &bi,
            String::new(),
            "did:key:test".to_owned(),
            "[]".to_owned(),
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_events_json() {
        let bi = test_bi();
        let result = aggregate_trust_input_on(
            &bi,
            "ctx-1".to_owned(),
            "did:key:test".to_owned(),
            "not json".to_owned(),
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn participation_record_rejects_empty_context() {
        let bi = test_bi();
        let result = participation_record_on(
            &bi,
            String::new(),
            "did:key:test".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn participation_record_rejects_empty_did() {
        let bi = test_bi();
        let result =
            participation_record_on(&bi, "ctx-1".to_owned(), String::new(), "[]".to_owned());
        assert!(result.is_err());
    }

    #[test]
    fn participation_record_rejects_invalid_attestations_json() {
        let bi = test_bi();
        let result = participation_record_on(
            &bi,
            "ctx-1".to_owned(),
            "did:key:test".to_owned(),
            "not json".to_owned(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn participation_record_rejects_malformed_did() {
        // Format validation (not just non-empty) matches the PyO3 reference
        // bridge: a non-empty but malformed DID is rejected.
        let bi = test_bi();
        let result = participation_record_on(
            &bi,
            "ctx-1".to_owned(),
            "not-a-did".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
    }

    /// The typed `NapiParticipationRecord` surfaces every flattened fact from
    /// the shared `ParticipationFacts` projection (i64-widened) with identical
    /// values.
    #[test]
    fn participation_record_view_exposes_all_facts() {
        let facts = scp_core::trust::ParticipationFacts {
            subject_did: "did:key:bob".into(),
            participation_duration_secs: 300,
            governance_actions_against: 1,
            governance_actions_by: 2,
            tool_invocation_count: 5,
            tool_invocation_count_anchored: false,
            context_creation_count: 1,
            role_progression_count: 3,
            attestation_count: 2,
            attestation_count_anchored: false,
            computed_at: 42,
            event_log_root: [7u8; 32],
        };
        let view = NapiParticipationRecord::from(&facts);
        assert_eq!(view.subject_did, "did:key:bob");
        assert_eq!(view.participation_duration_secs, 300);
        assert_eq!(view.governance_actions_against, 1);
        assert_eq!(view.governance_actions_by, 2);
        assert_eq!(view.tool_invocation_count, 5);
        assert!(!view.tool_invocation_count_anchored);
        assert_eq!(view.context_creation_count, 1);
        assert_eq!(view.role_progression_count, 3);
        assert_eq!(view.attestation_count, 2);
        assert!(!view.attestation_count_anchored);
        assert_eq!(view.computed_at, 42);
        assert_eq!(view.event_log_root, hex::encode([7u8; 32]));
    }
}
