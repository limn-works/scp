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
#[derive(Debug)]
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
#[derive(Debug)]
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
#[derive(Debug)]
pub struct NapiChallengeResult {
    /// The challenge id: lowercase hex of its 32 random bytes.
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
#[derive(Debug)]
pub struct NapiParticipationRecord {
    /// The DID whose participation is summarized.
    pub subject_did: String,
    /// Total seconds of context participation (§7.3.2).
    pub participation_duration_secs: i64,
    /// Count of governance actions taken against this identity.
    pub governance_actions_against: i64,
    /// Count of governance actions initiated by this identity.
    pub governance_actions_by: i64,
    /// Total outlet invocations across all outlet types.
    pub outlet_invocation_count: i64,
    /// Whether `outlet_invocation_count` is anchored in the canonical Merkle log
    /// (`false` until ADR-051; consumers MUST NOT treat it as Merkle-proven).
    pub outlet_invocation_count_anchored: bool,
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
    /// `outlet_invocation_count_anchored`.
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
            outlet_invocation_count: f.outlet_invocation_count as i64,
            outlet_invocation_count_anchored: f.outlet_invocation_count_anchored,
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

/// Builds a bridge validation error carrying the explicit `SCP-VALID-*` code
/// the UniFFI/PyO3 bridges emit for the same logical failure case (e.g. the
/// per-case `check_capability_requirements` codes `VALID_7073`..=`VALID_7077`,
/// or the `verify_participation_requirements` codes `VALID_7030`/`VALID_7031`/
/// `VALID_7032`), so a TypeScript caller can branch on the same code a
/// Python/Swift/Kotlin caller sees.
fn coded_validation_error(msg: &str, code: &str) -> napi::Error {
    napi::Error::from(ScpNapiError::Validation {
        message: msg.to_owned(),
        code: code.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`Scp::trust_query_score`](crate::scp::Scp::trust_query_score).
pub(crate) fn trust_query_score_on(
    bi: &NapiBridgeInstance,
    did: String,
    context_id: String,
) -> napi::Result<NapiTrustScoreResult> {
    // Per-argument codes match the UniFFI bridge (invalid DID → VALID_7010,
    // invalid context id → VALID_7011) so the same logical failure carries
    // the same code on every native bridge.
    if did.is_empty() {
        return Err(coded_validation_error(
            "DID must not be empty",
            codes::VALID_7010,
        ));
    }
    if context_id.is_empty() {
        return Err(coded_validation_error(
            "context_id must not be empty",
            codes::VALID_7011,
        ));
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
    // VALID_7012 matches the UniFFI bridge's code for malformed attestation
    // JSON so the same logical failure carries the same code on every bridge.
    let attestation: scp_core::trust::Attestation = serde_json::from_str(&attestation_json)
        .map_err(|e| {
            coded_validation_error(
                &format!("failed to parse attestation JSON: {e}"),
                codes::VALID_7012,
            )
        })?;

    let resolver = scp_core::trust::IdentityDidPublicKeyResolver;
    let clock = scp_clock::SystemClock;

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

/// Maps a shared challenge-operation failure to its bridge error:
/// `test_cases_json` that does not parse is `VALID_7002`, a protocol refusal
/// takes the `TrustError` mapping, and a signer failure the `ContextError`
/// mapping.
fn challenge_op_error(e: scp_ffi_common::challenge::ChallengeOpError) -> napi::Error {
    use scp_ffi_common::challenge::ChallengeOpError;
    match e {
        ChallengeOpError::MalformedTestCases(reason) => coded_validation_error(
            &format!("failed to parse test_cases_json: {reason}"),
            codes::VALID_7002,
        ),
        ChallengeOpError::Trust(e) => napi::Error::from(ScpNapiError::from(e)),
        ChallengeOpError::Sign(e) => napi::Error::from(ScpNapiError::from(e)),
    }
}

/// Resolves `verifier` to the custody signer over its `#active` key. An
/// identity this instance does not host fails with `SCP-IDENT-1001`.
async fn verifier_signer(
    bi: &NapiBridgeInstance,
    verifier: &str,
) -> napi::Result<scp_core::context::actor::signer::CommandSigner> {
    let (custody, active_handle) = crate::runtime::with_identity(bi, verifier, |entry| {
        Ok((entry.custody.clone(), entry.identity.active_signing_key))
    })
    .map_err(napi::Error::from)?;
    scp_ffi_common::signer::identity_command_signer(custody, active_handle)
        .await
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))
}

/// Per-bridge-instance implementation of `trust_create_challenge`
/// (spec 07 §7.3.4, ADR-017).
///
/// Builds a challenge from the challenger-written `test_cases_json` (a JSON
/// array of `TestCase`) and signs it with `verifier`'s `#active` key through
/// custody. A protocol capability URI with fewer cases than its standard's
/// minimum fails with `SCP-VALID-7039`; malformed `test_cases_json` with
/// `SCP-VALID-7002`.
pub(crate) async fn trust_create_challenge_on(
    bi: &NapiBridgeInstance,
    verifier: String,
    subject: String,
    capability_uri: String,
    test_cases_json: String,
    timeout_secs: u32,
) -> napi::Result<NapiChallengeResult> {
    // VALID_7013 for an invalid verifier or subject DID, on every bridge.
    scp_ffi_common::validate::validate_did(&verifier)
        .map_err(|e| coded_validation_error(&e.message, codes::VALID_7013))?;
    scp_ffi_common::validate::validate_did(&subject)
        .map_err(|e| coded_validation_error(&e.message, codes::VALID_7013))?;
    let signer = verifier_signer(bi, &verifier).await?;

    let request = scp_ffi_common::challenge::create_challenge(
        &signer,
        verifier.into(),
        subject.into(),
        capability_uri,
        &test_cases_json,
        timeout_secs,
    )
    .await
    .map_err(challenge_op_error)?;

    let challenge_json = serde_json::to_string(&request).map_err(|e| {
        coded_validation_error(
            &format!("failed to serialize challenge: {e}"),
            codes::VALID_7015,
        )
    })?;

    Ok(NapiChallengeResult {
        challenge_id: hex::encode(request.challenge_id),
        challenge_json,
    })
}

/// Per-bridge-instance implementation of `trust_verify_response`
/// (spec 07 §7.3.4, ADR-017).
///
/// Checks the subject's response against the request through this instance's
/// DID resolver and returns the `ChallengeVerification` JSON signed with
/// `verifier`'s `#active` key. A rejected response fails with
/// `SCP-VALID-7003`; an instance with no DID resolver with `SCP-IDENT-1033`.
pub(crate) async fn trust_verify_response_on(
    bi: &NapiBridgeInstance,
    verifier: String,
    challenge_json: String,
    response_json: String,
    context_id: String,
) -> napi::Result<String> {
    scp_ffi_common::validate::validate_did(&verifier)
        .map_err(|e| coded_validation_error(&e.message, codes::VALID_7013))?;
    if context_id.is_empty() {
        return Err(coded_validation_error(
            "context_id must not be empty",
            codes::VALID_7011,
        ));
    }
    // VALID_7016 (challenge position) / VALID_7017 (response position) match
    // the UniFFI bridge's per-case codes for malformed JSON.
    let request: scp_core::trust::ChallengeRequest = serde_json::from_str(&challenge_json)
        .map_err(|e| {
            coded_validation_error(
                &format!("failed to parse challenge JSON: {e}"),
                codes::VALID_7016,
            )
        })?;
    let response: scp_core::trust::ChallengeResponse = serde_json::from_str(&response_json)
        .map_err(|e| {
            coded_validation_error(
                &format!("failed to parse response JSON: {e}"),
                codes::VALID_7017,
            )
        })?;

    let resolver =
        crate::runtime::did_resolver(bi)
            .cloned()
            .ok_or_else(|| ScpNapiError::Identity {
                message: "DID resolver not initialized — create an identity with \
                      identityCreate before calling trustVerifyResponse"
                    .to_owned(),
                code: codes::IDENT_1033.to_owned(),
            })?;
    let signer = verifier_signer(bi, &verifier).await?;

    let record = scp_ffi_common::challenge::verify_response_and_sign(
        &signer,
        resolver,
        verifier.into(),
        request,
        response,
        context_id,
    )
    .await
    .map_err(challenge_op_error)?;

    serde_json::to_string(&record).map_err(|e| {
        coded_validation_error(
            &format!("failed to serialize challenge verification: {e}"),
            codes::VALID_7015,
        )
    })
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

    // Per-case codes match the UniFFI bridge: malformed requirements JSON →
    // VALID_7031, malformed profiles JSON → VALID_7030, failed admission
    // check → VALID_7032 (below).
    let requirements: Vec<scp_core::trust::RequireParticipation> =
        serde_json::from_str(&requirements_json).map_err(|e| {
            coded_validation_error(
                &format!("failed to parse participation requirements JSON: {e}"),
                codes::VALID_7031,
            )
        })?;

    let profiles: Vec<scp_core::trust::ParticipationProfile> = serde_json::from_str(&profile_json)
        .map_err(|e| {
            coded_validation_error(
                &format!("failed to parse participation profiles JSON: {e}"),
                codes::VALID_7030,
            )
        })?;

    // Fail-closed clock: a pre-epoch host clock is an unrecoverable environment
    // failure and must not silently read as time 0, which would make every
    // participation statement appear maximally fresh and bypass `max_age_secs`.
    // Matches the SystemClock invariant used on the verify-on-ingest path.
    let current_time = scp_clock::Clock::now_secs(&scp_clock::SystemClock);

    scp_core::trust::verify_participation_requirements(
        current_time,
        &expected_subject,
        &requirements,
        &profiles,
    )
    .map_err(|e| {
        coded_validation_error(
            &format!("participation admission verification failed: {e}"),
            codes::VALID_7032,
        )
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// check_capability_requirements (§7.3.4.4, SCP-ACR-008)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of `check_capability_requirements`.
///
/// Verifies that an agent meets a context's capability requirements for
/// admission. Each record's signature is checked against the verifier's
/// `#active` key, resolved through `bi`'s DID resolver; with none, a supplied
/// record fails closed with `SCP-IDENT-1033`. The lookup blocks the calling
/// thread.
///
/// `subject_did` is the DID of the agent being admitted and `context_id` the
/// context: a `ChallengeVerification` only satisfies a requirement when its
/// signed `subject_did`/`context_id` equal these values, closing cross-subject
/// and cross-context attribution. Authenticity is not authorization — a passing
/// challenge-verification check does not establish verifier legitimacy (see spec
/// §7.3.4.4).
pub(crate) fn check_capability_requirements_on(
    bi: &NapiBridgeInstance,
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
            coded_validation_error(
                &format!("failed to parse capability requirements JSON: {e}"),
                codes::VALID_7073,
            )
        })?;

    let agent_capabilities: Vec<scp_core::trust::CapabilityUri> =
        serde_json::from_str(&agent_capabilities_json).map_err(|e| {
            coded_validation_error(
                &format!("failed to parse agent capabilities JSON: {e}"),
                codes::VALID_7074,
            )
        })?;

    let challenge_verifications: Vec<scp_core::trust::ChallengeVerification> =
        serde_json::from_str(&challenge_verifications_json).map_err(|e| {
            coded_validation_error(
                &format!("failed to parse challenge verifications JSON: {e}"),
                codes::VALID_7075,
            )
        })?;

    // Records are signed with the verifier's `#active` key, which only the
    // instance's DID resolver reads; without one, a supplied record fails
    // closed with SCP-IDENT-1033.
    let resolver = scp_ffi_common::instance_challenge_resolver(crate::runtime::did_resolver(bi));
    let clock = scp_clock::SystemClock;

    scp_core::trust::check_capability_requirements(
        &requirements,
        &agent_capabilities,
        &challenge_verifications,
        &context_id,
        &subject_did,
        resolver,
        &clock,
    )
    .map_err(|e| {
        // Mirror the UniFFI bridge's per-variant code mapping so all native
        // bridges surface identical per-variant 707x codes for the same failure
        // case: empty subject → 7077; missing capability / verification-required
        // → 7076.
        let code = match e {
            scp_core::trust::AdmissionError::EmptySubjectDid => codes::VALID_7077,
            scp_core::trust::AdmissionError::MissingCapability { .. }
            | scp_core::trust::AdmissionError::VerificationRequired { .. } => codes::VALID_7076,
            scp_core::trust::AdmissionError::VerificationUnavailable { .. } => codes::IDENT_1033,
        };
        coded_validation_error(
            &format!("capability admission verification failed: {e}"),
            code,
        )
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// aggregate_trust_input (§7.3)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`Scp::aggregate_trust_input`](crate::scp::Scp::aggregate_trust_input).
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
    // Per-argument codes match the UniFFI bridge's `aggregate_trust_input`
    // (context id → VALID_7040, subject DID → VALID_7041, then one code per
    // JSON input, VALID_7042..=VALID_7049) so the same logical failure
    // carries the same code on every native bridge.
    if context_id.is_empty() {
        return Err(coded_validation_error(
            "context_id must not be empty",
            codes::VALID_7040,
        ));
    }
    if subject_did.is_empty() {
        return Err(coded_validation_error(
            "subject DID must not be empty",
            codes::VALID_7041,
        ));
    }

    let events: Vec<scp_event_log::Event> = serde_json::from_str(&events_json).map_err(|e| {
        coded_validation_error(
            &format!("failed to parse events JSON: {e}"),
            codes::VALID_7042,
        )
    })?;

    let merkle_root_vec: Vec<u8> = serde_json::from_str(&merkle_root_json).map_err(|e| {
        coded_validation_error(
            &format!("failed to parse merkle_root JSON: {e}"),
            codes::VALID_7043,
        )
    })?;
    let merkle_root: [u8; 32] = merkle_root_vec.try_into().map_err(|v: Vec<u8>| {
        coded_validation_error(
            &format!("merkle_root must be exactly 32 bytes, got {}", v.len()),
            codes::VALID_7044,
        )
    })?;

    let consequence_rules: Vec<scp_core::trust::ConsequenceRule> =
        serde_json::from_str(&consequence_rules_json).map_err(|e| {
            coded_validation_error(
                &format!("failed to parse consequence_rules JSON: {e}"),
                codes::VALID_7045,
            )
        })?;

    let threshold_requirements: std::collections::HashMap<
        scp_core::trust::AttestationType,
        scp_core::trust::ThresholdRequirement,
    > = serde_json::from_str(&threshold_requirements_json).map_err(|e| {
        coded_validation_error(
            &format!("failed to parse threshold_requirements JSON: {e}"),
            codes::VALID_7046,
        )
    })?;

    let attestor_sets: std::collections::HashMap<
        scp_core::trust::AttestationType,
        Vec<scp_core::trust::AttestorInfo>,
    > = serde_json::from_str(&attestor_sets_json).map_err(|e| {
        coded_validation_error(
            &format!("failed to parse attestor_sets JSON: {e}"),
            codes::VALID_7047,
        )
    })?;

    let cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation> =
        serde_json::from_str(&cached_attestations_json).map_err(|e| {
            coded_validation_error(
                &format!("failed to parse cached_attestations JSON: {e}"),
                codes::VALID_7048,
            )
        })?;

    let challenge_results: Vec<scp_core::trust::ChallengeVerification> =
        serde_json::from_str(&challenge_results_json).map_err(|e| {
            coded_validation_error(
                &format!("failed to parse challenge_results JSON: {e}"),
                codes::VALID_7049,
            )
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
                scp_ffi_common::instance_challenge_resolver(crate::runtime::did_resolver(bi)),
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
            .map_err(|e| {
                // VALID_7052 mirrors the UniFFI bridge's code for a failed
                // trust aggregation.
                coded_validation_error(&e.to_string(), codes::VALID_7052)
            })
        }
        crate::runtime::ProtocolRepoVariant::Sqlite(repo) => {
            let handle = crate::runtime().handle().clone();
            let bridge =
                scp_core::trust::ProtocolRepositoryTrustBridge::new(Arc::clone(repo), handle);
            scp_ffi_common::trust_store::populate_and_aggregate(
                bridge,
                scp_ffi_common::instance_challenge_resolver(crate::runtime::did_resolver(bi)),
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
            .map_err(|e| {
                // VALID_7052 mirrors the UniFFI bridge's code for a failed
                // trust aggregation.
                coded_validation_error(&e.to_string(), codes::VALID_7052)
            })
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
/// [`ProtocolRepoVariant`](scp_ffi_common::bridge_runtime::ProtocolRepoVariant) arm and reads back the subject's verified
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
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7010),
            "expected {}, got: {msg}",
            codes::VALID_7010
        );
    }

    #[test]
    fn trust_query_score_validates_empty_context() {
        let bi = test_bi();
        let result = trust_query_score_on(&bi, "did:key:test".to_owned(), String::new());
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7011),
            "expected {}, got: {msg}",
            codes::VALID_7011
        );
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

    // -----------------------------------------------------------------
    // trust_create_challenge / trust_verify_response (spec 07 §7.3.4)
    // -----------------------------------------------------------------

    const SCHEMA_URI: &str = "scp:capability:schema-validation/v1";

    /// `n` exact-match cases whose weights sum to 10000, as JSON.
    fn test_cases_json(n: usize) -> String {
        let weight = 10_000 / n;
        let cases: Vec<scp_core::trust::TestCase> = (0..n)
            .map(|i| scp_core::trust::TestCase {
                test_id: format!("t{i}"),
                input: serde_json::json!({ "i": i }),
                expected: scp_core::trust::ExpectedOutput::ExactMatch {
                    value: serde_json::json!({ "ok": true }),
                },
                category: "basic".to_owned(),
                weight: u32::try_from(if i == 0 {
                    10_000 - weight * (n - 1)
                } else {
                    weight
                })
                .unwrap(),
            })
            .collect();
        serde_json::to_string(&cases).unwrap()
    }

    fn assert_code<T: std::fmt::Debug>(result: napi::Result<T>, code: &str) {
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains(code), "expected {code}, got: {msg}");
    }

    /// A request that parses, for the response-position parse test.
    fn parseable_challenge_json() -> String {
        let key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let verifier = scp_did::did_dht_from_public_key(&key.verifying_key().to_bytes());
        let cases: Vec<scp_core::trust::TestCase> =
            serde_json::from_str(&test_cases_json(20)).unwrap();
        let request = scp_core::trust::challenge_request_unsigned(
            verifier.clone(),
            verifier,
            SCHEMA_URI.to_owned(),
            cases,
            300,
        )
        .unwrap()
        .with_verifier_signature(vec![0; 64]);
        serde_json::to_string(&request).unwrap()
    }

    const VALID_DID: &str = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    #[tokio::test]
    async fn trust_create_challenge_rejects_empty_subject_did() {
        let bi = test_bi();
        let result = trust_create_challenge_on(
            &bi,
            VALID_DID.to_owned(),
            String::new(),
            SCHEMA_URI.to_owned(),
            test_cases_json(20),
            300,
        )
        .await;
        assert_code(result, codes::VALID_7013);
    }

    #[tokio::test]
    async fn trust_verify_response_rejects_invalid_challenge_json() {
        // Malformed JSON in the CHALLENGE position.
        let bi = test_bi();
        let result = trust_verify_response_on(
            &bi,
            VALID_DID.to_owned(),
            "bad".to_owned(),
            "bad".to_owned(),
            "ctx".to_owned(),
        )
        .await;
        assert_code(result, codes::VALID_7016);
    }

    #[tokio::test]
    async fn trust_verify_response_rejects_invalid_response_json() {
        // The challenge parses, so the failure is attributed to the response.
        let bi = test_bi();
        let result = trust_verify_response_on(
            &bi,
            VALID_DID.to_owned(),
            parseable_challenge_json(),
            "bad".to_owned(),
            "ctx".to_owned(),
        )
        .await;
        assert_code(result, codes::VALID_7017);
    }

    #[tokio::test]
    async fn trust_verify_response_without_resolver_is_ident_1033() {
        let bi = test_bi();
        assert!(crate::runtime::did_resolver(&bi).is_none());
        let result = trust_verify_response_on(
            &bi,
            VALID_DID.to_owned(),
            parseable_challenge_json(),
            r#"{"challenge_id":"00","responder_did":"did:dht:x","result":{},"completed_at":0,"signature":[]}"#
                .to_owned(),
            "ctx".to_owned(),
        )
        .await;
        assert_code(result, codes::IDENT_1033);
    }

    #[cfg(feature = "testing")]
    mod challenge_live {
        use super::*;
        use scp_platform::traits::KeyCustody as _;

        /// Installs a resolver over a caller-retained in-memory DHT on `bi`.
        fn install_resolver(bi: &NapiBridgeInstance) -> Arc<scp_dht::InMemoryDhtClient> {
            let dht_client = Arc::new(scp_dht::InMemoryDhtClient::new());
            let resolver = Arc::new(scp_identity::DualLayerResolver::new(
                Arc::new(scp_identity::NoOpRelayQuerier),
                Arc::clone(&dht_client),
                Arc::new(scp_identity::DidCache::new()),
                Vec::new(),
            ));
            crate::runtime::init_did_resolver(bi, resolver, tokio::runtime::Handle::current());
            dht_client
        }

        /// Publishes `who`'s DID document into `dht_client`, signed by its
        /// identity key.
        async fn publish(
            who: &crate::identity::NapiIdentity,
            dht_client: &Arc<scp_dht::InMemoryDhtClient>,
        ) {
            use scp_dht::DhtClient as _;
            let inner = &who.inner;
            let identity = inner.scp_identity.as_ref().unwrap();
            let doc_json = inner.document.as_ref().unwrap().to_json().unwrap();
            let custody = inner.in_memory_custody.as_ref().unwrap();
            let public_key = scp_identity::extract_public_key(&identity.did).unwrap();
            let signable = scp_dht::bep44_signable(doc_json.as_bytes(), 1);
            let signature: [u8; 64] = custody
                .sign(&identity.identity_key, &signable)
                .await
                .unwrap()
                .into_bytes()
                .try_into()
                .unwrap();
            dht_client
                .publish(&public_key, &signature, doc_json.as_bytes(), 1)
                .await
                .unwrap();
        }

        async fn identity(scp: &crate::scp::Scp) -> crate::identity::NapiIdentity {
            scp.identity_create("in_memory".to_owned(), None)
                .await
                .unwrap()
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn trust_create_challenge_below_minimum_is_valid_7039() {
            let scp = crate::scp::Scp::new_in_memory_for_test();
            let v = identity(&scp).await;
            let result = trust_create_challenge_on(
                &scp.inner,
                v.inner.did.clone(),
                v.inner.did.clone(),
                SCHEMA_URI.to_owned(),
                test_cases_json(19),
                300,
            )
            .await;
            assert_code(result, codes::VALID_7039);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn trust_create_challenge_rejects_malformed_test_cases_json() {
            let scp = crate::scp::Scp::new_in_memory_for_test();
            let v = identity(&scp).await;
            let result = trust_create_challenge_on(
                &scp.inner,
                v.inner.did.clone(),
                v.inner.did.clone(),
                SCHEMA_URI.to_owned(),
                r#"{"not":"an array"}"#.to_owned(),
                300,
            )
            .await;
            assert_code(result, codes::VALID_7002);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn trust_create_challenge_destroyed_key_is_crypto_4006() {
            let scp = crate::scp::Scp::new_in_memory_for_test();
            let v = identity(&scp).await;
            let identity = v.inner.scp_identity.as_ref().unwrap();
            v.inner
                .in_memory_custody
                .as_ref()
                .unwrap()
                .destroy_key(&identity.active_signing_key)
                .await
                .unwrap();
            let result = trust_create_challenge_on(
                &scp.inner,
                v.inner.did.clone(),
                v.inner.did.clone(),
                SCHEMA_URI.to_owned(),
                test_cases_json(20),
                300,
            )
            .await;
            assert_code(result, codes::CRYPTO_4006);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[allow(clippy::too_many_lines)]
        async fn trust_create_then_verify_round_trip_with_production_resolver() {
            let scp = crate::scp::Scp::new_in_memory_for_test();
            let dht = install_resolver(&scp.inner);
            let v = identity(&scp).await;
            let s = identity(&scp).await;
            publish(&v, &dht).await;
            publish(&s, &dht).await;
            let v_id = v.inner.scp_identity.as_ref().unwrap();
            let s_id = s.inner.scp_identity.as_ref().unwrap();
            // `#0` and `#active` differ, so only an `#active` lookup verifies.
            assert_ne!(v_id.identity_key, v_id.active_signing_key);
            assert_ne!(s_id.identity_key, s_id.active_signing_key);

            let created = trust_create_challenge_on(
                &scp.inner,
                v.inner.did.clone(),
                s.inner.did.clone(),
                SCHEMA_URI.to_owned(),
                test_cases_json(20),
                300,
            )
            .await
            .unwrap();
            assert_eq!(created.challenge_id.len(), 64);
            assert_eq!(created.challenge_id, created.challenge_id.to_lowercase());

            let mut response = scp_core::trust::ChallengeResponse {
                challenge_id: created.challenge_id.clone(),
                responder_did: s.inner.did.clone().into(),
                result: serde_json::json!({
                    "passed": true, "score": 10_000, "test_count": 20, "pass_count": 20
                }),
                completed_at: scp_clock::Clock::now_secs(&scp_clock::SystemClock),
                signature: Vec::new(),
            };
            let bytes = scp_core::trust::canonical_challenge_response_bytes(&response).unwrap();
            response.signature = s
                .inner
                .in_memory_custody
                .as_ref()
                .unwrap()
                .sign(&s_id.active_signing_key, &bytes)
                .await
                .unwrap()
                .into_bytes();

            let record_json = trust_verify_response_on(
                &scp.inner,
                v.inner.did.clone(),
                created.challenge_json,
                serde_json::to_string(&response).unwrap(),
                "ctx-e2e".to_owned(),
            )
            .await
            .unwrap();
            let record: scp_core::trust::ChallengeVerification =
                serde_json::from_str(&record_json).unwrap();

            let resolver = Arc::clone(crate::runtime::did_resolver(&scp.inner).unwrap());
            let subject = s.inner.did.clone();
            let checked = record.clone();
            let verified = tokio::task::spawn_blocking(move || {
                let instance = scp_core::trust::verify_challenge_verification(
                    &checked,
                    resolver.as_ref(),
                    "ctx-e2e",
                    &subject,
                    &scp_clock::SystemClock,
                );
                // Negative: the `#0` key does not verify the record.
                let identity_key = scp_core::trust::verify_challenge_verification(
                    &checked,
                    &scp_core::trust::IdentityDidPublicKeyResolver,
                    "ctx-e2e",
                    &subject,
                    &scp_clock::SystemClock,
                );
                (instance, identity_key)
            })
            .await
            .unwrap();
            verified.0.unwrap();
            assert!(
                matches!(
                    verified.1,
                    Err(scp_core::trust::TrustError::ChallengeVerificationSignatureInvalid { .. })
                ),
                "{:?}",
                verified.1
            );

            // The record admits the subject.
            let requirements = vec![scp_core::trust::CapabilityRequirement {
                capability: SCHEMA_URI.parse().unwrap(),
                verification_level: scp_core::trust::VerificationLevel::ChallengeVerified,
            }];
            let bi = Arc::clone(&scp.inner);
            let subject = s.inner.did.clone();
            tokio::task::spawn_blocking(move || {
                check_capability_requirements_on(
                    &bi,
                    "ctx-e2e".to_owned(),
                    subject,
                    serde_json::to_string(&requirements).unwrap(),
                    "[]".to_owned(),
                    format!("[{record_json}]"),
                )
            })
            .await
            .unwrap()
            .unwrap();
        }

        /// Which key signs a test `ChallengeVerification`.
        enum CvSigner {
            /// The verifier's `#active` key, through its custody.
            Active,
            /// The verifier's self-certifying identity key `#0`, through its
            /// custody.
            IdentityKey,
            /// A key unrelated to the verifier's DID.
            Unrelated,
        }

        /// A record over `subject` in `context_id`, signed over its digest with
        /// `verifier`'s `#active` key.
        async fn signed_record_json(
            verifier: &crate::identity::NapiIdentity,
            subject: &str,
            context_id: &str,
        ) -> String {
            signed_record_json_by(verifier, &CvSigner::Active, subject, context_id).await
        }

        /// A record issued by `verifier` over `subject` in `context_id`,
        /// signed over its digest by `signer`.
        async fn signed_record_json_by(
            verifier: &crate::identity::NapiIdentity,
            signer: &CvSigner,
            subject: &str,
            context_id: &str,
        ) -> String {
            let v_id = verifier.inner.scp_identity.as_ref().unwrap();
            let verifier_did: scp_did::DID = v_id.did.clone().into();
            let subject: scp_did::DID = subject.into();
            let timestamp = scp_clock::Clock::now_secs(&scp_clock::SystemClock);
            let mut record = scp_core::trust::ChallengeVerification {
                verification_id: scp_core::trust::challenge_verification_id(
                    &verifier_did,
                    &subject,
                    SCHEMA_URI,
                    timestamp,
                )
                .unwrap(),
                verifier: verifier_did,
                subject,
                capability_uri: SCHEMA_URI.to_owned(),
                suite_digest: [0; 32],
                passed: true,
                score: None,
                test_count: 20,
                pass_count: 20,
                timestamp,
                expires_at: timestamp + 86_400,
                context_id: Some(context_id.to_owned()),
                verifier_signature: Vec::new(),
                verification_method: scp_core::trust::VerificationMethod::ChallengeVerified {
                    challenge_type: scp_core::trust::ChallengeType::Uri(
                        SCHEMA_URI.parse().unwrap(),
                    ),
                },
                result: serde_json::Value::Null,
                completed_at: timestamp,
            };
            let digest = scp_core::trust::challenge_verification_signing_digest(&record).unwrap();
            let custody = verifier.inner.in_memory_custody.as_ref().unwrap();
            record.verifier_signature = match signer {
                CvSigner::Active => custody
                    .sign(&v_id.active_signing_key, &digest)
                    .await
                    .unwrap()
                    .into_bytes(),
                CvSigner::IdentityKey => custody
                    .sign(&v_id.identity_key, &digest)
                    .await
                    .unwrap()
                    .into_bytes(),
                CvSigner::Unrelated => {
                    use ed25519_dalek::Signer;
                    ed25519_dalek::SigningKey::from_bytes(&[42; 32])
                        .sign(&digest)
                        .to_bytes()
                        .to_vec()
                }
            };
            serde_json::to_string(&vec![record]).unwrap()
        }

        /// Runs the admission check for `subject` in `context_id` on a
        /// blocking thread (the instance resolver blocks).
        async fn admit(
            bi: &Arc<NapiBridgeInstance>,
            subject: &str,
            context_id: &str,
            records_json: String,
        ) -> napi::Result<()> {
            let bi = Arc::clone(bi);
            let (subject, context_id) = (subject.to_owned(), context_id.to_owned());
            tokio::task::spawn_blocking(move || {
                check_capability_requirements_on(
                    &bi,
                    context_id,
                    subject,
                    format!(
                        r#"[{{"capability":"{SCHEMA_URI}","verification_level":"ChallengeVerified"}}]"#
                    ),
                    "[]".to_owned(),
                    records_json,
                )
            })
            .await
            .unwrap()
        }

        /// A record signed by the verifier's `#active` key, which differs from
        /// `#0`, is admitted through the instance resolver; the same record
        /// signed by an unrelated key or by `#0` is dropped.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn check_capability_requirements_admits_only_active_key_records() {
            let scp = crate::scp::Scp::new_in_memory_for_test();
            let dht = install_resolver(&scp.inner);
            let v = identity(&scp).await;
            publish(&v, &dht).await;
            let v_id = v.inner.scp_identity.as_ref().unwrap();
            assert_ne!(v_id.identity_key, v_id.active_signing_key);

            let active =
                signed_record_json_by(&v, &CvSigner::Active, VALID_DID, "ctx-admission").await;
            admit(&scp.inner, VALID_DID, "ctx-admission", active)
                .await
                .unwrap();
            for signer in [CvSigner::Unrelated, CvSigner::IdentityKey] {
                let record = signed_record_json_by(&v, &signer, VALID_DID, "ctx-admission").await;
                assert_code(
                    admit(&scp.inner, VALID_DID, "ctx-admission", record).await,
                    codes::VALID_7076,
                );
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn check_capability_requirements_binds_subject_and_context() {
            let scp = crate::scp::Scp::new_in_memory_for_test();
            let dht = install_resolver(&scp.inner);
            let v = identity(&scp).await;
            publish(&v, &dht).await;
            let (victim, attacker) = (VALID_DID, "did:dht:zAttacker");

            // Control: the record admits its own subject in its own context.
            let record = signed_record_json(&v, victim, "ctx-admission").await;
            admit(&scp.inner, victim, "ctx-admission", record.clone())
                .await
                .unwrap();
            // Cross-subject replay.
            assert_code(
                admit(&scp.inner, attacker, "ctx-admission", record.clone()).await,
                codes::VALID_7076,
            );
            // Cross-context replay.
            assert_code(
                admit(&scp.inner, victim, "ctx-other", record).await,
                codes::VALID_7076,
            );
        }
    }

    #[test]
    fn trust_verify_attestation_rejects_invalid_json() {
        let bi = test_bi();
        let result = trust_verify_attestation_on(&bi, "not json".to_owned());
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7012),
            "expected {}, got: {msg}",
            codes::VALID_7012
        );
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
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7030),
            "expected {}, got: {msg}",
            codes::VALID_7030
        );
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
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7031),
            "expected {}, got: {msg}",
            codes::VALID_7031
        );
    }

    #[test]
    fn verify_participation_requirements_unmet_requirement_fails_with_admission_code() {
        // A requirement with no satisfying profiles fails the admission check
        // itself (not JSON parsing), which carries its own per-case code.
        let bi = test_bi();
        let requirements = r#"[{"fact":"ParticipationDuration","threshold":{"AtLeast":1},"max_age_secs":3600,"min_contexts":0}]"#;
        let result = verify_participation_requirements_on(
            &bi,
            "did:key:alice".to_owned(),
            requirements.to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7032),
            "expected {}, got: {msg}",
            codes::VALID_7032
        );
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
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7000),
            "expected {}, got: {msg}",
            codes::VALID_7000
        );
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
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7073),
            "error should contain SCP-VALID-7073, got: {msg}"
        );
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
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7074),
            "error should contain SCP-VALID-7074, got: {msg}"
        );
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
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7075),
            "error should contain SCP-VALID-7075, got: {msg}"
        );
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
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7076),
            "error should contain SCP-VALID-7076, got: {msg}"
        );
    }

    /// A record whose verifier key this instance cannot resolve: with no DID
    /// resolver initialized, a supplied record fails closed with
    /// SCP-IDENT-1033 instead of being dropped or admitted.
    #[test]
    fn check_capability_requirements_record_without_resolver_is_ident_1033() {
        let bi = test_bi();
        let uri = "scp:capability:prompt-injection-resistance/v1";
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let verifier = scp_did::did_dht_from_public_key(&key.verifying_key().to_bytes());
        let subject: scp_did::DID = VALID_DID.into();
        let record = scp_core::trust::ChallengeVerification {
            verification_id: scp_core::trust::challenge_verification_id(
                &verifier,
                &subject,
                uri,
                1_700_000_000,
            )
            .unwrap(),
            verifier,
            subject,
            capability_uri: uri.to_owned(),
            suite_digest: [0; 32],
            passed: true,
            score: None,
            test_count: 1,
            pass_count: 1,
            timestamp: 1_700_000_000,
            expires_at: 1_700_086_400,
            context_id: Some("ctx".to_owned()),
            verifier_signature: vec![0; 64],
            verification_method: scp_core::trust::VerificationMethod::ChallengeVerified {
                challenge_type: scp_core::trust::ChallengeType::Uri(uri.parse().unwrap()),
            },
            result: serde_json::Value::Null,
            completed_at: 1_700_000_000,
        };
        let result = check_capability_requirements_on(
            &bi,
            "ctx".to_owned(),
            VALID_DID.to_owned(),
            format!(r#"[{{"capability":"{uri}","verification_level":"ChallengeVerified"}}]"#),
            "[]".to_owned(),
            serde_json::to_string(&vec![record]).unwrap(),
        );
        assert_code(result, codes::IDENT_1033);
        // Control: with no record to check, no resolver is needed and the
        // missing verification is the failure.
        let result = check_capability_requirements_on(
            &bi,
            "ctx".to_owned(),
            VALID_DID.to_owned(),
            format!(r#"[{{"capability":"{uri}","verification_level":"ChallengeVerified"}}]"#),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert_code(result, codes::VALID_7076);
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
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7040),
            "expected {}, got: {msg}",
            codes::VALID_7040
        );
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
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7042),
            "expected {}, got: {msg}",
            codes::VALID_7042
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_empty_did() {
        let bi = test_bi();
        let result = aggregate_trust_input_on(
            &bi,
            "ctx-1".to_owned(),
            String::new(),
            "[]".to_owned(),
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7041),
            "expected {}, got: {msg}",
            codes::VALID_7041
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_merkle_root_json() {
        let bi = test_bi();
        let result = aggregate_trust_input_on(
            &bi,
            "ctx-1".to_owned(),
            "did:key:test".to_owned(),
            "[]".to_owned(),
            "not json".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7043),
            "expected {}, got: {msg}",
            codes::VALID_7043
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_wrong_length_merkle_root() {
        let bi = test_bi();
        let result = aggregate_trust_input_on(
            &bi,
            "ctx-1".to_owned(),
            "did:key:test".to_owned(),
            "[]".to_owned(),
            "[0,0,0]".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7044),
            "expected {}, got: {msg}",
            codes::VALID_7044
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_consequence_rules_json() {
        let bi = test_bi();
        let result = aggregate_trust_input_on(
            &bi,
            "ctx-1".to_owned(),
            "did:key:test".to_owned(),
            "[]".to_owned(),
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]".to_owned(),
            "not json".to_owned(),
            "{}".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7045),
            "expected {}, got: {msg}",
            codes::VALID_7045
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_threshold_requirements_json() {
        let bi = test_bi();
        let result = aggregate_trust_input_on(
            &bi,
            "ctx-1".to_owned(),
            "did:key:test".to_owned(),
            "[]".to_owned(),
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]".to_owned(),
            "[]".to_owned(),
            "not json".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7046),
            "expected {}, got: {msg}",
            codes::VALID_7046
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_attestor_sets_json() {
        let bi = test_bi();
        let result = aggregate_trust_input_on(
            &bi,
            "ctx-1".to_owned(),
            "did:key:test".to_owned(),
            "[]".to_owned(),
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
            "not json".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7047),
            "expected {}, got: {msg}",
            codes::VALID_7047
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_cached_attestations_json() {
        let bi = test_bi();
        let result = aggregate_trust_input_on(
            &bi,
            "ctx-1".to_owned(),
            "did:key:test".to_owned(),
            "[]".to_owned(),
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
            "{}".to_owned(),
            "not json".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7048),
            "expected {}, got: {msg}",
            codes::VALID_7048
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_challenge_results_json() {
        let bi = test_bi();
        let result = aggregate_trust_input_on(
            &bi,
            "ctx-1".to_owned(),
            "did:key:test".to_owned(),
            "[]".to_owned(),
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            "not json".to_owned(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(codes::VALID_7049),
            "expected {}, got: {msg}",
            codes::VALID_7049
        );
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
            outlet_invocation_count: 5,
            outlet_invocation_count_anchored: false,
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
        assert_eq!(view.outlet_invocation_count, 5);
        assert!(!view.outlet_invocation_count_anchored);
        assert_eq!(view.context_creation_count, 1);
        assert_eq!(view.role_progression_count, 3);
        assert_eq!(view.attestation_count, 2);
        assert!(!view.attestation_count_anchored);
        assert_eq!(view.computed_at, 42);
        assert_eq!(view.event_log_root, hex::encode([7u8; 32]));
    }
}
