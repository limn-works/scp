//! `PyO3` bridge functions for the SCP trust engine.
//!
//! Exposes trust engine operations to Python. Stateful operations are methods
//! on the `SCP` class; pure helpers remain as free `#[pyfunction]` exports.
//!
//! Pure helpers (no bridge state):
//!
//! - [`py_verify_participation_requirements`] — Verify participation profiles
//!   against admission requirements.
//!
//! `SCP` methods (bridge-state accessors):
//!
//! - `PyScp::trust_verify_attestation` — Verify an attestation, including
//!   this instance's revocation list for the context.
//! - `PyScp::trust_query_score` — Query participation-based trust data for a DID.
//! - `PyScp::trust_create_challenge` — Create a challenge request signed by the
//!   verifier identity's `#active` key.
//! - `PyScp::trust_verify_response` — Verify a challenge response and return
//!   the record signed by the verifier identity's `#active` key.
//! - `PyScp::aggregate_trust_input` — Aggregate all trust engine layers into
//!   a single [`TrustInput`](scp_core::trust::TrustInput) for agent-level
//!   evaluation.
//!
//! Migrated from flat `#[pyfunction]` exports to `#[pymethods] impl PyScp`
//! methods in Phase 4 PR 4 sub-slice E.
//!
//! The trust engine does not produce trust "scores" — it provides verifiable
//! facts (participation records, attestation verification results, challenge
//! verification results) that agents consume for their own trust evaluation
//! logic. The `composite_score` field in the query result is a normalized
//! summary for convenience, not an authoritative trust judgment.
//!
//! See ADR-017 in `.docs/adrs/phase-4.md`.

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyDict;
use scp_ffi_common::error_codes as codes;

use crate::runtime::PyBridgeInstance;
use crate::types::encode_hex;

// ---------------------------------------------------------------------------
// Coded-error helper — cross-bridge error-code parity
// ---------------------------------------------------------------------------

/// Builds a bridge validation error carrying the specific `SCP-VALID-*` code
/// the UniFFI/NAPI bridges emit for the same logical failure case, so a
/// Python caller can branch on the same `.code` a Swift/Kotlin/TypeScript
/// caller sees (e.g. the per-case `verify_participation_requirements` codes
/// `VALID_7030`/`VALID_7031`/`VALID_7032`, or the trust-helper codes
/// `VALID_7012..=VALID_7017`).
fn coded_validation_error(message: String, code: &str) -> crate::error::ScpPyError {
    crate::error::ScpPyError::ValidationError {
        message,
        code: code.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// trust_query_score — per-bridge helper used by PyScp method
// ---------------------------------------------------------------------------

/// Queries participation-based trust data for a DID within a context on the
/// given bridge instance.
fn trust_query_score_impl(
    bi: &PyBridgeInstance,
    py: Python<'_>,
    did: &str,
    context_id: &str,
) -> PyResult<Py<PyDict>> {
    // Per-argument codes match the UniFFI bridge (invalid DID → VALID_7010,
    // invalid context id → VALID_7011) so the same logical failure carries
    // the same code on every native bridge. The PyO3 boundary additionally
    // rejects malformed (non-empty) values under the same per-argument code.
    scp_ffi_common::validate::validate_did(did)
        .map_err(|e| coded_validation_error(e.message, codes::VALID_7010))?;
    scp_ffi_common::validate::validate_context_id(context_id)
        .map_err(|e| coded_validation_error(e.message, codes::VALID_7011))?;

    // Query the runtime registry for event counts. The event log stores leaf
    // hashes (Merkle tree), not full events. The runtime registry tracks
    // per-context event metadata sufficient for participation summaries.
    let (message_count, governance_count) =
        crate::runtime::query_trust_event_counts(bi, context_id, did);

    // Compute a normalized composite score. This is a convenience metric:
    // log2(1 + total_events) / 10, capped at 1.0.
    let total = message_count + governance_count;
    #[allow(clippy::cast_precision_loss)]
    let composite = (1.0 + total as f64).log10().min(1.0);

    let dict = PyDict::new(py);
    dict.set_item("message_count", message_count)?;
    dict.set_item("governance_count", governance_count)?;
    dict.set_item("composite_score", composite)?;

    Ok(dict.into())
}

// ---------------------------------------------------------------------------
// trust_verify_attestation
// ---------------------------------------------------------------------------

/// Verifies one attestation against this instance's revocation list for
/// `context_id`, on the instance's configured storage.
///
/// Returns a dict with `valid` (bool), `chain_depth` (int, 1 when valid and 0
/// otherwise), and `error` (the rejection's message, or `None` when valid). A
/// rejection is a property of the attestation; a storage fault is not, and
/// raises instead of reading as `valid: False`.
///
/// # Errors
///
/// `VALID_7011` for a malformed `context_id`, `VALID_7012` for malformed JSON,
/// `VALID_7005` when this instance has no storage provider (the verification
/// cannot read a revocation list, so it fails closed), and `VALID_7052` when
/// the revocation list cannot be read.
fn trust_verify_attestation_impl(
    bi: &PyBridgeInstance,
    py: Python<'_>,
    context_id: &str,
    attestation_json: &str,
) -> PyResult<Py<PyDict>> {
    use crate::runtime::StorageProvider;
    use scp_ffi_common::trust_store::AttestationVerdict;

    scp_ffi_common::validate::validate_context_id(context_id)
        .map_err(|e| coded_validation_error(e.message, codes::VALID_7011))?;
    let attestation: scp_core::trust::Attestation = serde_json::from_str(attestation_json)
        .map_err(|e| {
            coded_validation_error(
                format!("failed to parse attestation JSON: {e}"),
                codes::VALID_7012,
            )
        })?;
    let provider = crate::runtime::get_storage(bi).map_err(|_| {
        coded_validation_error(
            "bridge storage not initialized — attestation verification cannot read \
             this instance's revocation list (bridge init bug)"
                .to_owned(),
            codes::VALID_7005,
        )
    })?;
    let handle = crate::runtime()?.handle().clone();
    // The store read blocks on the runtime, so it runs without the GIL.
    let verdict = py.allow_threads(|| match provider {
        StorageProvider::InMemoryEncrypted(storage) => {
            run_verify_attestation(Arc::clone(storage), handle, context_id, &attestation)
        }
        StorageProvider::Sqlite(storage) => {
            run_verify_attestation(Arc::clone(storage), handle, context_id, &attestation)
        }
    });
    let verdict = verdict.map_err(|e| coded_validation_error(e.to_string(), codes::VALID_7052))?;

    let dict = PyDict::new(py);
    match verdict {
        AttestationVerdict::Valid => {
            dict.set_item("valid", true)?;
            dict.set_item("chain_depth", 1)?;
            dict.set_item("error", py.None())?;
        }
        AttestationVerdict::Rejected(reason) => {
            dict.set_item("valid", false)?;
            dict.set_item("chain_depth", 0)?;
            dict.set_item("error", reason.to_string())?;
        }
    }
    Ok(dict.into())
}

/// Builds a `ProtocolRepositoryTrustBridge` over the concrete encrypted backend
/// and verifies one attestation against its revocation list, with the
/// production DID-key resolver and clock.
fn run_verify_attestation<S: scp_platform::EncryptedStorage + 'static>(
    storage: Arc<S>,
    handle: tokio::runtime::Handle,
    context_id: &str,
    attestation: &scp_core::trust::Attestation,
) -> Result<scp_ffi_common::trust_store::AttestationVerdict, scp_core::trust::TrustError> {
    let repo = Arc::new(scp_core::store::ProtocolRepository::new(storage));
    let bridge = scp_core::trust::ProtocolRepositoryTrustBridge::new(repo, handle);
    scp_ffi_common::trust_store::verify_attestation_in_context(
        &bridge,
        context_id,
        attestation,
        &scp_core::trust::IdentityDidPublicKeyResolver,
        &scp_clock::SystemClock,
    )
}

// ---------------------------------------------------------------------------
// trust_create_challenge / trust_verify_response (spec 07 §7.3.4, ADR-017)
// ---------------------------------------------------------------------------

/// Maps a shared challenge-operation failure to the bridge error, with the
/// same code on every bridge.
fn challenge_op_error(e: scp_ffi_common::challenge::ChallengeOpError) -> PyErr {
    use scp_ffi_common::challenge::ChallengeOpError;
    match e {
        e @ ChallengeOpError::MalformedJson { .. } => {
            coded_validation_error(e.to_string(), codes::VALID_7002).into()
        }
        ChallengeOpError::Trust(e) => crate::error::ScpPyError::from(e).into(),
        ChallengeOpError::Sign(e) => crate::error::ScpPyError::from(e).into(),
    }
}

/// Implementation of `PyScp::trust_create_challenge`.
///
/// Builds a challenge from the challenger-written `test_cases_json` (a JSON
/// array of `TestCase`) and signs it with `verifier`'s `#active` key through
/// custody. Returns a dict with `challenge_id` (lowercase hex of its 32
/// random bytes) and `challenge_json` (the signed `ChallengeRequest`).
fn trust_create_challenge_impl(
    bi: &PyBridgeInstance,
    py: Python<'_>,
    verifier: &str,
    subject: &str,
    capability_uri: &str,
    test_cases_json: &str,
    timeout_secs: u32,
) -> PyResult<Py<PyDict>> {
    // VALID_7013 for an invalid verifier or subject DID, on every bridge.
    scp_ffi_common::validate::validate_did(verifier)
        .map_err(|e| coded_validation_error(e.message, codes::VALID_7013))?;
    scp_ffi_common::validate::validate_did(subject)
        .map_err(|e| coded_validation_error(e.message, codes::VALID_7013))?;
    let signer = crate::context::resolve_signer(py, bi, verifier)?;

    let request = crate::actor_wait::block_on_released(
        py,
        scp_ffi_common::challenge::create_challenge(
            &signer,
            verifier.into(),
            subject.into(),
            capability_uri.to_owned(),
            test_cases_json,
            timeout_secs,
        ),
    )?
    .map_err(challenge_op_error)?;

    let challenge_json = serde_json::to_string(&request).map_err(|e| {
        coded_validation_error(
            format!("failed to serialize challenge: {e}"),
            codes::VALID_7015,
        )
    })?;

    let dict = PyDict::new(py);
    dict.set_item("challenge_id", hex::encode(request.challenge_id))?;
    dict.set_item("challenge_json", &challenge_json)?;
    Ok(dict.into())
}

/// Implementation of `PyScp::trust_verify_response`.
///
/// Checks the subject's response against the request through this instance's
/// DID resolver and returns the `ChallengeVerification` JSON signed with
/// `verifier`'s `#active` key.
fn trust_verify_response_impl(
    bi: &PyBridgeInstance,
    py: Python<'_>,
    verifier: &str,
    challenge_json: &str,
    response_json: &str,
    context_id: &str,
) -> PyResult<String> {
    scp_ffi_common::validate::validate_did(verifier)
        .map_err(|e| coded_validation_error(e.message, codes::VALID_7013))?;
    if context_id.is_empty() {
        return Err(coded_validation_error(
            "context_id must not be empty".to_owned(),
            codes::VALID_7011,
        )
        .into());
    }
    let inputs = scp_ffi_common::challenge::VerifyInputs::decode(challenge_json, response_json)
        .map_err(challenge_op_error)?;
    let resolver = crate::runtime::did_resolver(bi).cloned().ok_or_else(|| {
        crate::error::ScpPyError::IdentityError {
            message: "DID resolver not initialized — create an identity with \
                      identity_create before calling trust_verify_response"
                .to_owned(),
            code: codes::IDENT_1033.to_owned(),
        }
    })?;
    let signer = crate::context::resolve_signer(py, bi, verifier)?;

    let record = crate::actor_wait::block_on_released(
        py,
        scp_ffi_common::challenge::verify_response_and_sign(
            &signer,
            resolver,
            verifier.into(),
            inputs,
            context_id.to_owned(),
        ),
    )?
    .map_err(challenge_op_error)?;

    serde_json::to_string(&record).map_err(|e| {
        coded_validation_error(
            format!("failed to serialize challenge verification: {e}"),
            codes::VALID_7015,
        )
        .into()
    })
}

// ---------------------------------------------------------------------------
// verify_participation_requirements (SCP-BA-004)
// ---------------------------------------------------------------------------

/// Verifies participation profiles against admission requirements, bound to the
/// agent being admitted.
///
/// Inputs:
/// - `expected_subject`: the DID of the agent being admitted. Only profiles
///   whose signed `subject_did` equals this value contribute to any threshold,
///   freshness, or distinct-signer accounting — a victim's genuine profiles
///   cannot be replayed to admit a different agent (cross-subject replay).
/// - `requirements_json`: JSON array of `RequireParticipation` objects.
/// - `profile_json`: JSON array of `ParticipationProfile` objects.
///
/// Uses the current system time for freshness checks. Returns `Ok(())` on
/// success — success is indicated by returning without exception. Raises
/// `ScpError` with a diagnostic message if any requirement fails or if the JSON
/// is malformed.
///
/// See §7.3.2.1.
///
/// # Errors
///
/// Returns `ValidationError` with a per-case code matching the UniFFI/NAPI
/// bridges: `VALID_7000` for an invalid `expected_subject` DID, `VALID_7031`
/// for malformed requirements JSON, `VALID_7030` for malformed profiles JSON,
/// and `VALID_7032` if participation admission verification fails (with the
/// specific failure reason from `ParticipationAdmissionError`).
#[pyfunction]
#[pyo3(name = "verify_participation_requirements")]
pub fn py_verify_participation_requirements(
    expected_subject: &str,
    requirements_json: &str,
    profile_json: &str,
) -> PyResult<()> {
    // VALID_7000 matches the UniFFI/NAPI bridges, which route this same
    // check through the shared `scp_ffi_common::validate::ValidationError`
    // conversion (generic validation code).
    scp_ffi_common::validate::validate_did(expected_subject)
        .map_err(|e| coded_validation_error(e.message, codes::VALID_7000))?;

    let requirements: Vec<scp_core::trust::RequireParticipation> =
        serde_json::from_str(requirements_json).map_err(|e| {
            coded_validation_error(
                format!("failed to parse participation requirements JSON: {e}"),
                codes::VALID_7031,
            )
        })?;

    let profiles: Vec<scp_core::trust::ParticipationProfile> = serde_json::from_str(profile_json)
        .map_err(|e| {
        coded_validation_error(
            format!("failed to parse participation profiles JSON: {e}"),
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
        expected_subject,
        &requirements,
        &profiles,
    )
    .map_err(|e| {
        // VALID_7032 mirrors the UniFFI bridge's code for a failed
        // participation admission check, so every native bridge surfaces the
        // identical code for the same logical failure.
        coded_validation_error(
            format!("participation admission verification failed: {e}"),
            codes::VALID_7032,
        )
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// aggregate_trust_input (§7.3)
// ---------------------------------------------------------------------------

/// Aggregates all trust engine layers into a single `TrustInput` for
/// agent-level evaluation.
///
/// Accepts all inputs as JSON strings and returns the aggregated `TrustInput`
/// as a JSON string. Uses the `BridgeInstance` storage provider for persistent
/// trust data when initialized (trust data survives across calls and restarts);
/// falls back to an ephemeral in-memory store otherwise.
///
/// # Errors
///
/// Returns `ScpError` if any JSON input is malformed or if aggregation fails.
///
/// See ADR-017 acceptance criterion 9, spec §7.3.
#[allow(clippy::too_many_arguments)]
fn aggregate_trust_input_impl(
    bi: &PyBridgeInstance,
    context_id: &str,
    subject_did: &str,
    events_json: &str,
    merkle_root_json: &str,
    consequence_rules_json: &str,
    threshold_requirements_json: &str,
    attestor_sets_json: &str,
    cached_attestations_json: &str,
    challenge_results_json: &str,
) -> PyResult<String> {
    // Per-argument codes match the UniFFI bridge's `aggregate_trust_input`
    // (context id → VALID_7040, subject DID → VALID_7041, then one code per
    // JSON input, VALID_7042..=VALID_7049) so the same logical failure
    // carries the same code on every native bridge. The PyO3 boundary
    // additionally rejects malformed (non-empty) ids under the same
    // per-argument code.
    scp_ffi_common::validate::validate_context_id(context_id)
        .map_err(|e| coded_validation_error(e.message, codes::VALID_7040))?;
    scp_ffi_common::validate::validate_did(subject_did)
        .map_err(|e| coded_validation_error(e.message, codes::VALID_7041))?;

    // Parse all JSON inputs.
    let events: Vec<scp_event_log::Event> = serde_json::from_str(events_json).map_err(|e| {
        coded_validation_error(
            format!("failed to parse events JSON: {e}"),
            codes::VALID_7042,
        )
    })?;

    let merkle_root_vec: Vec<u8> = serde_json::from_str(merkle_root_json).map_err(|e| {
        coded_validation_error(
            format!("failed to parse merkle_root JSON: {e}"),
            codes::VALID_7043,
        )
    })?;
    let merkle_root: [u8; 32] = merkle_root_vec.try_into().map_err(|v: Vec<u8>| {
        coded_validation_error(
            format!("merkle_root must be exactly 32 bytes, got {}", v.len()),
            codes::VALID_7044,
        )
    })?;

    let consequence_rules: Vec<scp_core::trust::ConsequenceRule> =
        serde_json::from_str(consequence_rules_json).map_err(|e| {
            coded_validation_error(
                format!("failed to parse consequence_rules JSON: {e}"),
                codes::VALID_7045,
            )
        })?;

    let threshold_requirements: std::collections::HashMap<
        scp_core::trust::AttestationType,
        scp_core::trust::ThresholdRequirement,
    > = serde_json::from_str(threshold_requirements_json).map_err(|e| {
        coded_validation_error(
            format!("failed to parse threshold_requirements JSON: {e}"),
            codes::VALID_7046,
        )
    })?;

    let attestor_sets: std::collections::HashMap<
        scp_core::trust::AttestationType,
        Vec<scp_core::trust::AttestorInfo>,
    > = serde_json::from_str(attestor_sets_json).map_err(|e| {
        coded_validation_error(
            format!("failed to parse attestor_sets JSON: {e}"),
            codes::VALID_7047,
        )
    })?;

    let cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation> =
        serde_json::from_str(cached_attestations_json).map_err(|e| {
            coded_validation_error(
                format!("failed to parse cached_attestations JSON: {e}"),
                codes::VALID_7048,
            )
        })?;

    let challenge_results: Vec<scp_core::trust::ChallengeVerification> =
        serde_json::from_str(challenge_results_json).map_err(|e| {
            coded_validation_error(
                format!("failed to parse challenge_results JSON: {e}"),
                codes::VALID_7049,
            )
        })?;

    aggregate_with_storage(
        bi,
        context_id,
        subject_did,
        cached_attestations,
        &challenge_results,
        &events,
        merkle_root,
        &consequence_rules,
        &threshold_requirements,
        &attestor_sets,
    )
}

/// Dispatches `populate_and_aggregate` to the active storage backend.
///
/// If the `BridgeInstance` storage provider is initialized, builds a
/// `ProtocolRepositoryTrustBridge` over the concrete storage backend
/// (`InMemoryEncrypted` or `Sqlite`) so cached attestations, revocation
/// states, and challenge results survive process restarts.
/// Otherwise falls back to an ephemeral in-memory store.
#[allow(clippy::too_many_arguments)]
fn aggregate_with_storage(
    bi: &PyBridgeInstance,
    context_id: &str,
    subject_did: &str,
    cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation>,
    challenge_results: &[scp_core::trust::ChallengeVerification],
    events: &[scp_event_log::Event],
    merkle_root: [u8; 32],
    consequence_rules: &[scp_core::trust::ConsequenceRule],
    threshold_requirements: &std::collections::HashMap<
        scp_core::trust::AttestationType,
        scp_core::trust::ThresholdRequirement,
    >,
    attestor_sets: &std::collections::HashMap<
        scp_core::trust::AttestationType,
        Vec<scp_core::trust::AttestorInfo>,
    >,
) -> PyResult<String> {
    use crate::runtime::StorageProvider;
    // Surface storage-not-initialized as an init bug, not a silent fallback.
    // The former path swapped in an ephemeral `InMemoryFfiTrustStore` so
    // aggregations against a `SCP({storage: sqlite})` caller's configured
    // SQLCipher store invisibly landed in an empty ephemeral store. See
    // `with_storage_py`.
    let provider = crate::runtime::get_storage(bi).map_err(|_| {
        coded_validation_error(
            "bridge storage not initialized — trust aggregation is \
             unreachable until this PyBridgeInstance has allocated its \
             storage provider (bridge init bug)"
                .to_owned(),
            codes::VALID_7005,
        )
    })?;
    let handle = crate::runtime()?.handle().clone();
    // The aggregation logic lives ONCE in `run_aggregation` (generic over the
    // concrete `EncryptedStorage` backend). The match is pure type dispatch: the
    // sealed `EncryptedStorage` bound on `ProtocolRepository::new` cannot be
    // satisfied by the `StorageProvider` enum itself (the marker trait lives in
    // `scp-platform`), so the concrete `Arc<S>` must be recovered per variant.
    // Both arms route through the single generic body — no duplicated logic.
    let inputs = AggregationInputs {
        // The instance resolver verifies each challenge record's `#active`
        // signature; without one, a supplied record fails closed.
        challenge_resolver: scp_ffi_common::instance_challenge_resolver(
            crate::runtime::did_resolver(bi),
        ),
        context_id,
        subject_did,
        cached_attestations,
        challenge_results,
        events,
        merkle_root,
        consequence_rules,
        threshold_requirements,
        attestor_sets,
    };
    let result = match provider {
        StorageProvider::InMemoryEncrypted(storage) => {
            run_aggregation(Arc::clone(storage), handle, inputs)
        }
        StorageProvider::Sqlite(storage) => run_aggregation(Arc::clone(storage), handle, inputs),
    };
    // VALID_7052 mirrors the UniFFI bridge's code for a failed trust
    // aggregation, so every native bridge surfaces the identical code for
    // the same logical failure.
    result.map_err(|e| coded_validation_error(e.to_string(), codes::VALID_7052).into())
}

/// Owned + borrowed inputs for [`run_aggregation`], grouped to keep the generic
/// helper's signature manageable.
struct AggregationInputs<'a> {
    challenge_resolver: &'a dyn scp_core::trust::attestation::DidPublicKeyResolver,
    context_id: &'a str,
    subject_did: &'a str,
    cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation>,
    challenge_results: &'a [scp_core::trust::ChallengeVerification],
    events: &'a [scp_event_log::Event],
    merkle_root: [u8; 32],
    consequence_rules: &'a [scp_core::trust::ConsequenceRule],
    threshold_requirements: &'a std::collections::HashMap<
        scp_core::trust::AttestationType,
        scp_core::trust::ThresholdRequirement,
    >,
    attestor_sets: &'a std::collections::HashMap<
        scp_core::trust::AttestationType,
        Vec<scp_core::trust::AttestorInfo>,
    >,
}

/// Builds a `ProtocolRepositoryTrustBridge` over the concrete encrypted backend
/// and runs `populate_and_aggregate`. Single source of truth for the per-backend
/// aggregation path (both `StorageProvider` variants route through this).
fn run_aggregation<S: scp_platform::EncryptedStorage + 'static>(
    storage: Arc<S>,
    handle: tokio::runtime::Handle,
    inputs: AggregationInputs<'_>,
) -> Result<String, scp_core::trust::TrustError> {
    let repo = Arc::new(scp_core::store::ProtocolRepository::new(storage));
    let bridge = scp_core::trust::ProtocolRepositoryTrustBridge::new(repo, handle);
    scp_ffi_common::trust_store::populate_and_aggregate(
        bridge,
        inputs.challenge_resolver,
        inputs.context_id,
        inputs.subject_did,
        inputs.cached_attestations,
        inputs.challenge_results,
        inputs.events,
        inputs.merkle_root,
        inputs.consequence_rules,
        inputs.threshold_requirements,
        inputs.attestor_sets,
    )
}

// ---------------------------------------------------------------------------
// PyParticipationRecord
// ---------------------------------------------------------------------------

/// Structured participation facts (§7.3.2) for a subject DID in a context.
///
/// The scalar projection of scp-core's
/// [`ParticipationRecord`](scp_core::trust::ParticipationRecord), produced by
/// [`PyScp::participation_record`](crate::scp::PyScp::participation_record). Counts are flattened ONCE in the shared Rust
/// core (`ParticipationFacts`) so Python RECEIVES the facts rather than
/// re-aggregating event-log collections — eliminating cross-binding divergence
/// by construction.
///
/// See `scp_core::trust::ParticipationFacts` and ADR-017.
#[pyclass(name = "ParticipationRecord")]
#[derive(Debug, Clone)]
pub struct PyParticipationRecord {
    /// The DID whose participation is summarized.
    #[pyo3(get)]
    pub subject_did: String,
    /// Total seconds of context participation (§7.3.2).
    #[pyo3(get)]
    pub participation_duration_secs: u64,
    /// Count of governance actions taken against this identity (projected
    /// `target_did` is the subject).
    #[pyo3(get)]
    pub governance_actions_against: u64,
    /// Count of governance actions initiated by this identity.
    #[pyo3(get)]
    pub governance_actions_by: u64,
    /// Total outlet invocations across all outlet types.
    #[pyo3(get)]
    pub outlet_invocation_count: u64,
    /// Whether `outlet_invocation_count` is anchored in the canonical Merkle log.
    /// `false` until ADR-051 makes `OutletInvoked` a convergent leaf (§7.3.2) —
    /// consumers MUST NOT treat the count as Merkle-proven while this is `false`.
    #[pyo3(get)]
    pub outlet_invocation_count_anchored: bool,
    /// Number of contexts created by the subject (`ChildContextCreated`).
    #[pyo3(get)]
    pub context_creation_count: u64,
    /// Number of role transitions for the subject.
    #[pyo3(get)]
    pub role_progression_count: u64,
    /// Number of accessible, currently-valid credential-layer attestations
    /// (§7.4) for the subject. Verifier-relative.
    #[pyo3(get)]
    pub attestation_count: u64,
    /// Whether `attestation_count` is anchored in / verifiable against a context
    /// Merkle root. Always `false` — it is a credential-layer, verifier-relative
    /// fact (§7.4), never a context-event-log count (§7.3.2). The parallel of
    /// `outlet_invocation_count_anchored`, surfaced so the non-anchored nature is
    /// mechanically visible.
    #[pyo3(get)]
    pub attestation_count_anchored: bool,
    /// Unix timestamp (seconds) when the record was computed.
    #[pyo3(get)]
    pub computed_at: u64,
    /// Merkle root (hex) of the event log at computation time.
    #[pyo3(get)]
    pub event_log_root: String,
}

impl From<&scp_core::trust::ParticipationFacts> for PyParticipationRecord {
    fn from(f: &scp_core::trust::ParticipationFacts) -> Self {
        Self {
            subject_did: f.subject_did.to_string(),
            participation_duration_secs: f.participation_duration_secs,
            governance_actions_against: f.governance_actions_against,
            governance_actions_by: f.governance_actions_by,
            outlet_invocation_count: f.outlet_invocation_count,
            outlet_invocation_count_anchored: f.outlet_invocation_count_anchored,
            context_creation_count: f.context_creation_count,
            role_progression_count: f.role_progression_count,
            attestation_count: f.attestation_count,
            attestation_count_anchored: f.attestation_count_anchored,
            computed_at: f.computed_at,
            event_log_root: encode_hex(&f.event_log_root),
        }
    }
}

#[pymethods]
impl PyParticipationRecord {
    fn __repr__(&self) -> String {
        format!(
            "ParticipationRecord(subject_did={}, participation_duration_secs={}, \
             governance_actions_against={}, governance_actions_by={}, \
             outlet_invocation_count={}, outlet_invocation_count_anchored={}, \
             context_creation_count={}, role_progression_count={}, \
             attestation_count={}, attestation_count_anchored={})",
            self.subject_did,
            self.participation_duration_secs,
            self.governance_actions_against,
            self.governance_actions_by,
            self.outlet_invocation_count,
            self.outlet_invocation_count_anchored,
            self.context_creation_count,
            self.role_progression_count,
            self.attestation_count,
            self.attestation_count_anchored,
        )
    }
}

/// Sources the subject's verified attestations from this bridge instance's
/// persistent trust store, then computes the participation record via the
/// shared Supervisor.
///
/// Mirrors `aggregate_with_storage`'s attestation handling: caller-supplied
/// `cached_attestations` are populated into the bridge's
/// `ProtocolRepositoryTrustBridge` over the concrete storage backend, and the
/// subject's accessible, currently-valid attestations are read back via
/// `get_verified_attestations` — the REAL credential-layer source, not `&[]`.
/// Those attestations feed `attestation_count` (§7.4); the Supervisor gathers
/// the full event log + Merkle root for every other fact.
fn participation_record_impl(
    bi: &crate::runtime::PyBridgeInstance,
    context_id: &str,
    subject_did: &str,
    cached_attestations_json: &str,
) -> PyResult<PyParticipationRecord> {
    use crate::runtime::StorageProvider;

    // VALID_7000 matches the UniFFI/NAPI bridges, which route these same
    // checks through the shared `scp_ffi_common::validate::ValidationError`
    // conversion (generic validation code).
    scp_ffi_common::validate::validate_context_id(context_id)
        .map_err(|e| coded_validation_error(e.message, codes::VALID_7000))?;
    scp_ffi_common::validate::validate_did(subject_did)
        .map_err(|e| coded_validation_error(e.message, codes::VALID_7000))?;

    let cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation> =
        serde_json::from_str(cached_attestations_json).map_err(|e| {
            coded_validation_error(
                format!("failed to parse cached_attestations JSON: {e}"),
                codes::VALID_7059,
            )
        })?;

    // Source verified attestations from this instance's persistent trust store
    // (same backend as context/event-log writes). The sourcing
    // logic lives ONCE in `run_verified_attestations` (generic over the concrete
    // `EncryptedStorage` backend); the match is pure type dispatch because the
    // sealed `EncryptedStorage` bound cannot be satisfied by the `StorageProvider`
    // enum itself. Both arms route through the single generic body.
    let provider = crate::runtime::get_storage(bi)?;
    let handle = crate::runtime()?.handle().clone();
    let verified = match provider {
        StorageProvider::InMemoryEncrypted(storage) => run_verified_attestations(
            Arc::clone(storage),
            handle,
            context_id,
            subject_did,
            cached_attestations,
        ),
        StorageProvider::Sqlite(storage) => run_verified_attestations(
            Arc::clone(storage),
            handle,
            context_id,
            subject_did,
            cached_attestations,
        ),
    }
    // An error from `verified_attestations` is an INFRA fault (trust-store read,
    // signature-verification infrastructure) — NOT a caller-input validation
    // error. Code it as a context-layer fault (CTX_2000), consistent with the
    // generic-failure arm of `participation_record` below, and keep it propagating
    // (fail-closed): it must never be folded into the empty-log CTX_2076 path.
    .map_err(|e| crate::error::ScpPyError::ContextError {
        message: e.to_string(),
        code: scp_ffi_common::error_codes::CTX_2000.to_owned(),
    })?;

    let record = crate::runtime::supervisor(bi)?
        .participation_record(context_id, subject_did, &verified)
        // Map the empty-log condition to its dedicated, stable code (CTX_2076) so
        // SDKs can branch on "no recorded participation facts" without string-
        // matching; genuine failures stay on the generic context code (CTX_2000),
        // matching NAPI/UniFFI. `ScpPyError::context` would emit CTX_2001,
        // diverging from the other bridges for the same condition.
        .map_err(|e| {
            let code = match e {
                scp_core::context::ContextError::NoParticipationFacts { .. } => {
                    scp_ffi_common::error_codes::CTX_2076
                }
                _ => scp_ffi_common::error_codes::CTX_2000,
            };
            crate::error::ScpPyError::ContextError {
                message: e.to_string(),
                code: code.to_owned(),
            }
        })?;

    let facts = scp_core::trust::ParticipationFacts::from(&record);
    Ok(PyParticipationRecord::from(&facts))
}

/// Builds a `ProtocolRepositoryTrustBridge` over the concrete encrypted backend
/// and reads back the subject's verified attestations. Single source of truth for
/// the per-backend attestation-sourcing path (both `StorageProvider` variants
/// route through this).
fn run_verified_attestations<S: scp_platform::EncryptedStorage + 'static>(
    storage: Arc<S>,
    handle: tokio::runtime::Handle,
    context_id: &str,
    subject_did: &str,
    cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation>,
) -> Result<Vec<scp_core::trust::attestation::Attestation>, scp_core::trust::TrustError> {
    let repo = Arc::new(scp_core::store::ProtocolRepository::new(storage));
    let bridge = scp_core::trust::ProtocolRepositoryTrustBridge::new(repo, handle);
    scp_ffi_common::trust_store::verified_attestations(
        bridge,
        context_id,
        subject_did,
        cached_attestations,
    )
}

// ---------------------------------------------------------------------------
// PyScp methods — migrated from #[pyfunction] exports (Phase 4 PR 4).
// ---------------------------------------------------------------------------

#[pymethods]
impl crate::scp::PyScp {
    /// Queries participation-based trust data for a DID within a context.
    ///
    /// Returns a dict with:
    /// - `message_count` (int): Number of `MessageSent` events by this DID.
    /// - `governance_count` (int): Number of `GovernanceAction` events by this DID.
    /// - `composite_score` (float): Normalized summary (0.0–1.0) based on
    ///   participation count. This is a convenience metric, not an authoritative
    ///   trust judgment — agents should evaluate the raw counts per their own
    ///   criteria.
    ///
    /// The data is derived from the event log via the participation record
    /// computation (Layer 2 of the four-layer trust model).
    ///
    /// # Errors
    ///
    /// Returns `ScpError` if input validation fails.
    /// Verifies an attestation's signature, evidence, expiry, its own
    /// revocation status, and this instance's revocation list for
    /// `context_id`.
    ///
    /// See `trust_verify_attestation_impl` for the result and error codes.
    ///
    /// # Errors
    ///
    /// Returns `ScpError` for malformed input, a missing storage provider, or
    /// an unreadable revocation list.
    #[pyo3(name = "trust_verify_attestation")]
    pub fn trust_verify_attestation(
        &self,
        py: Python<'_>,
        context_id: &str,
        attestation_json: &str,
    ) -> PyResult<Py<PyDict>> {
        let bi = &*self.inner;
        trust_verify_attestation_impl(bi, py, context_id, attestation_json)
    }

    #[pyo3(name = "trust_query_score")]
    pub fn trust_query_score(
        &self,
        py: Python<'_>,
        did: &str,
        context_id: &str,
    ) -> PyResult<Py<PyDict>> {
        let bi = &*self.inner;
        trust_query_score_impl(bi, py, did, context_id)
    }

    /// Creates a challenge request for capability verification (spec 07
    /// §7.3.4).
    ///
    /// `verifier` is the DID of an identity hosted on this instance; the
    /// request is signed with its `#active` key through custody.
    /// `test_cases_json` is the challenger-written JSON array of test cases.
    ///
    /// Returns a dict with `challenge_id` (lowercase hex of its 32 random
    /// bytes) and `challenge_json` (the signed `ChallengeRequest`).
    ///
    /// # Errors
    ///
    /// - `SCP-VALID-7013` for an invalid verifier or subject DID.
    /// - `SCP-VALID-7002` for malformed `test_cases_json`.
    /// - `SCP-VALID-7039` when a protocol capability URI carries fewer cases
    ///   than its standard's minimum; `SCP-VALID-7003` for any other refusal.
    /// - The identity registry's error when `verifier` is not hosted here, and
    ///   the custody error when signing fails (`SCP-CRYPTO-4006` for a
    ///   destroyed key).
    #[pyo3(
        name = "trust_create_challenge",
        signature = (verifier, subject, capability_uri, test_cases_json, timeout_secs = 300)
    )]
    pub fn trust_create_challenge(
        &self,
        py: Python<'_>,
        verifier: &str,
        subject: &str,
        capability_uri: &str,
        test_cases_json: &str,
        timeout_secs: u32,
    ) -> PyResult<Py<PyDict>> {
        trust_create_challenge_impl(
            &self.inner,
            py,
            verifier,
            subject,
            capability_uri,
            test_cases_json,
            timeout_secs,
        )
    }

    /// Verifies a challenge response and returns the signed
    /// `ChallengeVerification` JSON (spec 07 §7.3.4).
    ///
    /// The request and response signatures are checked through this
    /// instance's DID resolver; the record is bound to `context_id` and signed
    /// with `verifier`'s `#active` key through custody.
    ///
    /// # Errors
    ///
    /// - `SCP-VALID-7013` for an invalid verifier DID, `SCP-VALID-7011` for an
    ///   empty `context_id`.
    /// - `SCP-VALID-7002` for a malformed challenge or response
    ///   JSON.
    /// - `SCP-IDENT-1033` when this instance has no DID resolver.
    /// - `SCP-VALID-7003` when the response is refused.
    /// - The identity registry's error when `verifier` is not hosted here, and
    ///   the custody error when signing fails.
    #[pyo3(name = "trust_verify_response")]
    pub fn trust_verify_response(
        &self,
        py: Python<'_>,
        verifier: &str,
        challenge_json: &str,
        response_json: &str,
        context_id: &str,
    ) -> PyResult<String> {
        trust_verify_response_impl(
            &self.inner,
            py,
            verifier,
            challenge_json,
            response_json,
            context_id,
        )
    }

    /// Verifies that an agent meets a context's capability requirements for
    /// admission, bound to the agent and context being admitted (spec 07
    /// §7.3.4.4).
    ///
    /// Inputs:
    /// - `context_id`: the context the agent is being admitted to. A challenge
    ///   verification only satisfies a requirement when its signed
    ///   `context_id` equals this value.
    /// - `subject_did`: the DID of the agent being admitted. Only challenge
    ///   verifications whose signed `subject` equals this value can satisfy a
    ///   requirement (cross-subject attribution is rejected).
    /// - `requirements_json`: JSON array of `CapabilityRequirement` objects.
    /// - `agent_capabilities_json`: JSON array of capability-URI strings the
    ///   agent self-attests.
    /// - `challenge_verifications_json`: JSON array of `ChallengeVerification`
    ///   records; each counts only if its signature verifies against the
    ///   verifier's `#active` key, resolved through this instance's DID
    ///   resolver, and it is in-context, in-subject, passed and unexpired.
    ///
    /// Returns `None` on success. The GIL is released while the resolver
    /// runs.
    ///
    /// SECURITY (verifier legitimacy): a passing `ChallengeVerified` check
    /// proves the verifier's signature, NOT that the verifier is trusted.
    /// Establish verifier legitimacy separately (spec §7.3.4.4 / §7.4).
    ///
    /// # Errors
    ///
    /// - `SCP-VALID-7000` for an invalid `subject_did`.
    /// - `SCP-VALID-7073` / `7074` / `7075` for malformed requirements,
    ///   agent-capabilities or challenge-verifications JSON.
    /// - `SCP-VALID-7076` when a requirement is unmet, `SCP-VALID-7077` for an
    ///   empty subject.
    /// - `SCP-IDENT-1033` when a record must be verified and this instance has
    ///   no DID resolver, or its backend is unreachable.
    #[pyo3(name = "check_capability_requirements")]
    pub fn check_capability_requirements(
        &self,
        py: Python<'_>,
        context_id: &str,
        subject_did: &str,
        requirements_json: &str,
        agent_capabilities_json: &str,
        challenge_verifications_json: &str,
    ) -> PyResult<()> {
        // VALID_7000 matches the UniFFI/NAPI bridges, which route this same
        // check through the shared `ValidationError` conversion.
        scp_ffi_common::validate::validate_did(subject_did)
            .map_err(|e| coded_validation_error(e.message, codes::VALID_7000))?;

        let requirements: Vec<scp_core::trust::CapabilityRequirement> =
            serde_json::from_str(requirements_json).map_err(|e| {
                coded_validation_error(
                    format!("failed to parse capability requirements JSON: {e}"),
                    codes::VALID_7073,
                )
            })?;

        let agent_capabilities: Vec<scp_core::trust::CapabilityUri> =
            serde_json::from_str(agent_capabilities_json).map_err(|e| {
                coded_validation_error(
                    format!("failed to parse agent capabilities JSON: {e}"),
                    codes::VALID_7074,
                )
            })?;

        let challenge_verifications: Vec<scp_core::trust::ChallengeVerification> =
            serde_json::from_str(challenge_verifications_json).map_err(|e| {
                coded_validation_error(
                    format!("failed to parse challenge verifications JSON: {e}"),
                    codes::VALID_7075,
                )
            })?;

        let bi = &*self.inner;
        let clock = scp_clock::SystemClock;

        // The resolver blocks on DID resolution, so the GIL is released.
        py.allow_threads(|| {
            // Records are signed with the verifier's `#active` key, which only
            // this instance's DID resolver reads; without one, a supplied
            // record fails closed with SCP-IDENT-1033.
            let resolver =
                scp_ffi_common::instance_challenge_resolver(crate::runtime::did_resolver(bi));
            scp_core::trust::check_capability_requirements(
                &requirements,
                &agent_capabilities,
                &challenge_verifications,
                context_id,
                subject_did,
                resolver,
                &clock,
            )
        })
        .map_err(|e| {
            // Every native bridge maps each variant to the same code and
            // error class.
            let message = format!("capability admission verification failed: {e}");
            match e {
                scp_core::trust::AdmissionError::EmptySubjectDid => {
                    coded_validation_error(message, codes::VALID_7077)
                }
                scp_core::trust::AdmissionError::MissingCapability { .. }
                | scp_core::trust::AdmissionError::VerificationRequired { .. } => {
                    coded_validation_error(message, codes::VALID_7076)
                }
                scp_core::trust::AdmissionError::VerificationUnavailable { .. } => {
                    crate::error::ScpPyError::IdentityError {
                        message,
                        code: codes::IDENT_1033.to_owned(),
                    }
                }
            }
        })?;

        Ok(())
    }

    /// Aggregates all trust engine layers into a single `TrustInput` for
    /// agent-level evaluation.
    ///
    /// Accepts all inputs as JSON strings and returns the aggregated `TrustInput`
    /// as a JSON string. Uses the `BridgeInstance` storage provider for persistent
    /// trust data when initialized (trust data survives across calls and restarts);
    /// falls back to an ephemeral in-memory store otherwise.
    ///
    /// # Errors
    ///
    /// Returns `ScpError` if any JSON input is malformed or if aggregation fails.
    ///
    /// See ADR-017 acceptance criterion 9, spec §7.3.
    #[pyo3(name = "aggregate_trust_input")]
    #[allow(clippy::too_many_arguments)]
    pub fn aggregate_trust_input(
        &self,
        context_id: &str,
        subject_did: &str,
        events_json: &str,
        merkle_root_json: &str,
        consequence_rules_json: &str,
        threshold_requirements_json: &str,
        attestor_sets_json: &str,
        cached_attestations_json: &str,
        challenge_results_json: &str,
    ) -> PyResult<String> {
        let bi = &*self.inner;
        aggregate_trust_input_impl(
            bi,
            context_id,
            subject_did,
            events_json,
            merkle_root_json,
            consequence_rules_json,
            threshold_requirements_json,
            attestor_sets_json,
            cached_attestations_json,
            challenge_results_json,
        )
    }

    /// Computes the structured participation record (§7.3.2) for `subject_did`
    /// in `context_id`.
    ///
    /// The bridge sources the subject's accessible, currently-valid attestations
    /// from this instance's persistent trust store (populating any
    /// caller-supplied `cached_attestations_json` first, exactly as
    /// `aggregate_trust_input` does), and the shared Supervisor gathers the FULL
    /// event log to derive every other fact. Returns a typed
    /// [`PyParticipationRecord`] — the SDK receives the flattened facts and never
    /// re-aggregates event-log collections.
    ///
    /// # Errors
    ///
    /// Returns `ScpError` if validation fails, `cached_attestations_json` is
    /// malformed, storage is uninitialized, or the record computation fails
    /// (e.g. an empty event log).
    ///
    /// See ADR-017 and spec §7.3.2.
    #[pyo3(name = "participation_record", signature = (context_id, subject_did, cached_attestations_json="[]"))]
    pub fn participation_record(
        &self,
        context_id: &str,
        subject_did: &str,
        cached_attestations_json: &str,
    ) -> PyResult<PyParticipationRecord> {
        let bi = &*self.inner;
        participation_record_impl(bi, context_id, subject_did, cached_attestations_json)
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers trust engine bridge free functions with the Python module.
///
/// Post-migration (Phase 4 PR 4 sub-slice E), stateful trust operations
/// (`trust_query_score`, `aggregate_trust_input`) are exposed as methods on
/// `SCP`, as are the challenge operations, which sign through an identity
/// hosted on the instance, capability requirement verification, which
/// resolves verifier keys through the instance's DID resolver, and
/// `trust_verify_attestation`, which reads the instance's revocation list.
/// Only the pure participation requirement verification helper remains as a
/// free `#[pyfunction]` export.
pub fn register_trust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyParticipationRecord>()?;
    m.add_function(wrap_pyfunction!(py_verify_participation_requirements, m)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn default_scp() -> crate::scp::PyScp {
        crate::scp::PyScp::new_in_memory_for_test()
    }

    #[test]
    fn trust_query_score_validates_did() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            // Empty DID should fail validation.
            let result = default_scp().trust_query_score(py, "", "ctx-1");
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(scp_ffi_common::error_codes::VALID_7010),
                "expected {}, got: {err_str}",
                scp_ffi_common::error_codes::VALID_7010
            );
        });
    }

    #[test]
    fn trust_query_score_validates_context_id() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            // Empty context ID should fail validation.
            let result = default_scp().trust_query_score(py, "did:key:test", "");
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(scp_ffi_common::error_codes::VALID_7011),
                "expected {}, got: {err_str}",
                scp_ffi_common::error_codes::VALID_7011
            );
        });
    }

    #[test]
    fn trust_query_score_returns_valid_dict() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = default_scp().trust_query_score(py, "did:key:test", "ctx-valid");
            assert!(result.is_ok());
            let dict = result.unwrap();
            let dict_ref = dict.bind(py);
            assert!(dict_ref.get_item("message_count").unwrap().is_some());
            assert!(dict_ref.get_item("governance_count").unwrap().is_some());
            assert!(dict_ref.get_item("composite_score").unwrap().is_some());
        });
    }

    #[test]
    fn trust_verify_attestation_rejects_invalid_json() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = default_scp().trust_verify_attestation(py, "ctx-valid", "not valid json");
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(scp_ffi_common::error_codes::VALID_7012),
                "expected {}, got: {err_str}",
                scp_ffi_common::error_codes::VALID_7012
            );
        });
    }

    const SCHEMA_URI: &str = "scp:capability:schema-validation/v1";
    const VALID_DID: &str = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    /// `n` exact-match test cases whose weights sum to 10000.
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

    fn assert_code<T: std::fmt::Debug>(result: PyResult<T>, code: &str) {
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
            verifier,
            VALID_DID.into(),
            SCHEMA_URI.to_owned(),
            cases,
            300,
        )
        .unwrap()
        .with_verifier_signature(vec![0; 64]);
        serde_json::to_string(&request).unwrap()
    }

    #[test]
    fn trust_create_challenge_rejects_empty_subject_did() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result =
                default_scp().trust_create_challenge(py, VALID_DID, "", SCHEMA_URI, "[]", 300);
            assert_code(result, codes::VALID_7013);
        });
    }

    #[test]
    fn trust_verify_response_rejects_invalid_challenge_json() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = default_scp().trust_verify_response(py, VALID_DID, "bad", "bad", "ctx");
            assert_code(result, codes::VALID_7002);
        });
    }

    #[test]
    fn trust_verify_response_rejects_invalid_response_json() {
        // The challenge parses, so the failure is attributed to the response.
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = default_scp().trust_verify_response(
                py,
                VALID_DID,
                &parseable_challenge_json(),
                "bad",
                "ctx",
            );
            assert_code(result, codes::VALID_7002);
        });
    }

    #[test]
    fn trust_verify_response_rejects_empty_context_id() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = default_scp().trust_verify_response(
                py,
                VALID_DID,
                &parseable_challenge_json(),
                "{}",
                "",
            );
            assert_code(result, codes::VALID_7011);
        });
    }

    #[test]
    fn trust_verify_response_without_resolver_is_ident_1033() {
        // A fresh instance has no DID resolver until an identity is created.
        pyo3::prepare_freethreaded_python();
        let response = serde_json::json!({
            "challenge_id": "00".repeat(32),
            "responder_did": VALID_DID,
            "result": {},
            "completed_at": 0,
            "signature": [],
        })
        .to_string();
        Python::with_gil(|py| {
            let result = default_scp().trust_verify_response(
                py,
                VALID_DID,
                &parseable_challenge_json(),
                &response,
                "ctx",
            );
            assert_code(result, codes::IDENT_1033);
        });
    }

    #[cfg(feature = "testing")]
    mod challenge_live {
        use scp_platform::KeyCustody as _;

        use super::*;

        /// The custody and `(identity, #active)` key handles of `did`.
        fn keys(
            scp: &crate::scp::PyScp,
            did: &str,
        ) -> (
            Arc<crate::custody::FfiKeyCustody>,
            scp_platform::KeyHandle,
            scp_platform::KeyHandle,
        ) {
            crate::runtime::with_identity(&scp.inner, did, |entry| {
                Ok((
                    Arc::clone(&entry.custody),
                    entry.identity.identity_key,
                    entry.identity.active_signing_key,
                ))
            })
            .unwrap()
        }

        fn identity(py: Python<'_>, scp: &crate::scp::PyScp) -> String {
            scp.identity_create(py, "in_memory", None)
                .unwrap()
                .did()
                .to_owned()
        }

        #[test]
        fn trust_create_challenge_below_minimum_is_valid_7039() {
            pyo3::prepare_freethreaded_python();
            crate::init_runtime().ok();
            Python::with_gil(|py| {
                let scp = default_scp();
                let v = identity(py, &scp);
                let result =
                    scp.trust_create_challenge(py, &v, &v, SCHEMA_URI, &test_cases_json(19), 300);
                assert_code(result, codes::VALID_7039);
            });
        }

        #[test]
        fn trust_create_challenge_rejects_malformed_test_cases_json() {
            pyo3::prepare_freethreaded_python();
            crate::init_runtime().ok();
            Python::with_gil(|py| {
                let scp = default_scp();
                let v = identity(py, &scp);
                let result = scp.trust_create_challenge(
                    py,
                    &v,
                    &v,
                    SCHEMA_URI,
                    r#"{"not":"an array"}"#,
                    300,
                );
                assert_code(result, codes::VALID_7002);
            });
        }

        #[test]
        fn trust_create_challenge_destroyed_key_is_crypto_4006() {
            pyo3::prepare_freethreaded_python();
            crate::init_runtime().ok();
            Python::with_gil(|py| {
                let scp = default_scp();
                let v = identity(py, &scp);
                let (custody, _, active) = keys(&scp, &v);
                crate::runtime()
                    .unwrap()
                    .block_on(custody.destroy_key(&active))
                    .unwrap();
                let result =
                    scp.trust_create_challenge(py, &v, &v, SCHEMA_URI, &test_cases_json(20), 300);
                assert_code(result, codes::CRYPTO_4006);
            });
        }

        #[test]
        fn trust_create_then_verify_round_trip_with_production_resolver() {
            pyo3::prepare_freethreaded_python();
            crate::init_runtime().ok();
            let rt = crate::runtime().unwrap();
            Python::with_gil(|py| {
                let scp = default_scp();
                let v = identity(py, &scp);
                let s = identity(py, &scp);
                let (_, v_identity, v_active) = keys(&scp, &v);
                let (s_custody, s_identity, s_active) = keys(&scp, &s);
                // `#0` and `#active` differ, so only an `#active` lookup verifies.
                assert_ne!(v_identity, v_active);
                assert_ne!(s_identity, s_active);

                let created = scp
                    .trust_create_challenge(py, &v, &s, SCHEMA_URI, &test_cases_json(20), 300)
                    .unwrap();
                let created = created.bind(py);
                let challenge_id: String = created
                    .get_item("challenge_id")
                    .unwrap()
                    .unwrap()
                    .extract()
                    .unwrap();
                let challenge_json: String = created
                    .get_item("challenge_json")
                    .unwrap()
                    .unwrap()
                    .extract()
                    .unwrap();
                assert_eq!(challenge_id.len(), 64);
                assert_eq!(challenge_id, challenge_id.to_lowercase());

                let mut response = scp_core::trust::ChallengeResponse {
                    challenge_id,
                    responder_did: s.as_str().into(),
                    result: serde_json::json!({
                        "passed": true, "score": 10_000, "test_count": 20, "pass_count": 20
                    }),
                    completed_at: scp_clock::Clock::now_secs(&scp_clock::SystemClock),
                    signature: Vec::new(),
                };
                let bytes = scp_core::trust::canonical_challenge_response_bytes(&response).unwrap();
                response.signature = rt
                    .block_on(s_custody.sign(&s_active, &bytes))
                    .unwrap()
                    .into_bytes();

                let record_json = scp
                    .trust_verify_response(
                        py,
                        &v,
                        &challenge_json,
                        &serde_json::to_string(&response).unwrap(),
                        "ctx-e2e",
                    )
                    .unwrap();
                let record: scp_core::trust::ChallengeVerification =
                    serde_json::from_str(&record_json).unwrap();
                assert_eq!(record.subject, s);

                let resolver = crate::runtime::did_resolver(&scp.inner).unwrap();
                scp_core::trust::verify_challenge_verification(
                    &record,
                    resolver.as_ref(),
                    "ctx-e2e",
                    &s,
                    &scp_clock::SystemClock,
                )
                .unwrap();
                // Negative: the `#0` key does not verify the record.
                let identity_key = scp_core::trust::verify_challenge_verification(
                    &record,
                    &scp_core::trust::IdentityDidPublicKeyResolver,
                    "ctx-e2e",
                    &s,
                    &scp_clock::SystemClock,
                );
                assert!(
                    matches!(
                        identity_key,
                        Err(
                            scp_core::trust::TrustError::ChallengeVerificationSignatureInvalid { .. }
                        )
                    ),
                    "{identity_key:?}"
                );
            });
        }
    }

    #[test]
    fn verify_participation_requirements_rejects_invalid_profile_json() {
        // Malformed JSON in the PROFILE position (now the 3rd arg).
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|_py| {
            let result = py_verify_participation_requirements("did:key:alice", "[]", "not json");
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(scp_ffi_common::error_codes::VALID_7030),
                "expected {}, got: {err_str}",
                scp_ffi_common::error_codes::VALID_7030
            );
        });
    }

    #[test]
    fn verify_participation_requirements_rejects_invalid_requirements_json() {
        // Malformed JSON in the REQUIREMENTS position (now the 2nd arg).
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|_py| {
            let result = py_verify_participation_requirements("did:key:alice", "not json", "[]");
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(scp_ffi_common::error_codes::VALID_7031),
                "expected {}, got: {err_str}",
                scp_ffi_common::error_codes::VALID_7031
            );
        });
    }

    #[test]
    fn verify_participation_requirements_empty_inputs_succeeds() {
        // Empty requirements = no constraints = always passes.
        let result = py_verify_participation_requirements("did:key:alice", "[]", "[]");
        assert!(result.is_ok());
    }

    #[test]
    fn verify_participation_requirements_rejects_invalid_subject() {
        // A malformed subject DID is rejected at the FFI boundary.
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|_py| {
            let result = py_verify_participation_requirements("not-a-did", "[]", "[]");
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(scp_ffi_common::error_codes::VALID_7000),
                "expected {}, got: {err_str}",
                scp_ffi_common::error_codes::VALID_7000
            );
        });
    }

    #[test]
    fn verify_participation_requirements_unmet_requirement_fails_with_admission_code() {
        // A requirement with no satisfying profiles fails the admission check
        // itself (not JSON parsing), which carries its own per-case code.
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|_py| {
            let requirements = r#"[{"fact":"ParticipationDuration","threshold":{"AtLeast":1},"max_age_secs":3600,"min_contexts":0}]"#;
            let result = py_verify_participation_requirements("did:key:alice", requirements, "[]");
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(scp_ffi_common::error_codes::VALID_7032),
                "expected {}, got: {err_str}",
                scp_ffi_common::error_codes::VALID_7032
            );
        });
    }

    // -- check_capability_requirements (§7.3.4.4, SCP-ACR-008) --

    #[test]
    fn check_capability_requirements_rejects_invalid_requirements_json() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = default_scp().check_capability_requirements(
                py,
                "ctx-1",
                "did:key:alice",
                "not json",
                "[]",
                "[]",
            );
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(scp_ffi_common::error_codes::VALID_7073),
                "error should contain SCP-VALID-7073, got: {err_str}"
            );
        });
    }

    #[test]
    fn check_capability_requirements_rejects_invalid_capabilities_json() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = default_scp().check_capability_requirements(
                py,
                "ctx-1",
                "did:key:alice",
                "[]",
                "not json",
                "[]",
            );
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(scp_ffi_common::error_codes::VALID_7074),
                "error should contain SCP-VALID-7074, got: {err_str}"
            );
        });
    }

    #[test]
    fn check_capability_requirements_rejects_invalid_verifications_json() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = default_scp().check_capability_requirements(
                py,
                "ctx-1",
                "did:key:alice",
                "[]",
                "[]",
                "not json",
            );
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(scp_ffi_common::error_codes::VALID_7075),
                "error should contain SCP-VALID-7075, got: {err_str}"
            );
        });
    }

    #[test]
    fn check_capability_requirements_empty_inputs_succeeds() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            // No requirements = no constraints = always passes.
            let result = default_scp().check_capability_requirements(
                py,
                "ctx-1",
                "did:key:alice",
                "[]",
                "[]",
                "[]",
            );
            assert!(result.is_ok());
        });
    }

    #[test]
    fn check_capability_requirements_rejects_malformed_subject() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = default_scp().check_capability_requirements(
                py,
                "ctx-1",
                "not-a-did",
                "[]",
                "[]",
                "[]",
            );
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(scp_ffi_common::error_codes::VALID_7000),
                "expected {}, got: {err_str}",
                scp_ffi_common::error_codes::VALID_7000
            );
        });
    }

    #[test]
    fn check_capability_requirements_rejects_empty_subject() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            // An empty subject is rejected at the FFI boundary (validate_did).
            let result =
                default_scp().check_capability_requirements(py, "ctx-1", "", "[]", "[]", "[]");
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(scp_ffi_common::error_codes::VALID_7000),
                "expected {}, got: {err_str}",
                scp_ffi_common::error_codes::VALID_7000
            );
        });
    }

    #[test]
    fn check_capability_requirements_self_attested_present_succeeds() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            // A SelfAttested requirement is satisfied by a declared capability — no
            // challenge verification (and thus no signature check) is needed.
            let requirements = r#"[{"capability":"scp:capability:schema-validation/v1","verification_level":"SelfAttested"}]"#;
            let capabilities = r#"["scp:capability:schema-validation/v1"]"#;
            let result = default_scp().check_capability_requirements(
                py,
                "ctx-1",
                "did:key:alice",
                requirements,
                capabilities,
                "[]",
            );
            assert!(result.is_ok());
        });
    }

    #[test]
    fn check_capability_requirements_self_attested_missing_fails() {
        // A SelfAttested requirement with no matching declared capability and no
        // verification record fails as an admission (runtime) error.
        let requirements = r#"[{"capability":"scp:capability:schema-validation/v1","verification_level":"SelfAttested"}]"#;
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = default_scp().check_capability_requirements(
                py,
                "ctx-1",
                "did:key:alice",
                requirements,
                "[]",
                "[]",
            );
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(scp_ffi_common::error_codes::VALID_7076),
                "error should contain SCP-VALID-7076, got: {err_str}"
            );
        });
    }

    /// Capability admission through an identity hosted on the instance, so
    /// the instance DID resolver reads the verifier's `#active` key.
    #[cfg(feature = "testing")]
    mod capability_live {
        use scp_platform::KeyCustody as _;

        use super::*;

        const CHALLENGE_URI: &str = "scp:capability:prompt-injection-resistance/v1";

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

        fn identity(py: Python<'_>, scp: &crate::scp::PyScp) -> String {
            scp.identity_create(py, "in_memory", None)
                .unwrap()
                .did()
                .to_owned()
        }

        fn requirement_json() -> String {
            format!(
                r#"[{{"capability":"{CHALLENGE_URI}","verification_level":"ChallengeVerified"}}]"#
            )
        }

        /// A `ChallengeVerification` JSON array issued by `verifier` (an
        /// identity hosted on `scp`), bound to `subject_did`/`context_id` with
        /// a one-day expiry, and signed by `signer`.
        fn signed_cv_json(
            scp: &crate::scp::PyScp,
            verifier: &str,
            signer: &CvSigner,
            subject_did: &str,
            context_id: &str,
        ) -> String {
            let verifier_did: scp_did::DID = verifier.into();
            let cap: scp_core::trust::CapabilityUri = CHALLENGE_URI.parse().unwrap();
            let subject: scp_did::DID = subject_did.into();
            let timestamp = scp_clock::Clock::now_secs(&scp_clock::SystemClock);
            let mut cv = scp_core::trust::ChallengeVerification {
                verification_id: scp_core::trust::challenge_verification_id(
                    &verifier_did,
                    &subject,
                    CHALLENGE_URI,
                    timestamp,
                )
                .unwrap(),
                verifier: verifier_did,
                subject,
                capability_uri: CHALLENGE_URI.to_owned(),
                suite_digest: [0; 32],
                passed: true,
                score: None,
                test_count: 1,
                pass_count: 1,
                timestamp,
                expires_at: timestamp + 86_400,
                context_id: Some(context_id.to_owned()),
                verifier_signature: Vec::new(),
                verification_method: scp_core::trust::VerificationMethod::ChallengeVerified {
                    challenge_type: scp_core::trust::ChallengeType::Uri(cap),
                },
                result: serde_json::Value::Bool(true),
                completed_at: timestamp,
            };
            let digest = scp_core::trust::challenge_verification_signing_digest(&cv).unwrap();
            let (custody, identity_key, active_key) =
                crate::runtime::with_identity(&scp.inner, verifier, |entry| {
                    Ok((
                        Arc::clone(&entry.custody),
                        entry.identity.identity_key,
                        entry.identity.active_signing_key,
                    ))
                })
                .unwrap();
            assert_ne!(identity_key, active_key);
            let rt = crate::runtime().unwrap();
            cv.verifier_signature = match signer {
                CvSigner::Active => rt
                    .block_on(custody.sign(&active_key, &digest))
                    .unwrap()
                    .into_bytes(),
                CvSigner::IdentityKey => rt
                    .block_on(custody.sign(&identity_key, &digest))
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
            serde_json::to_string(&vec![cv]).unwrap()
        }

        /// A record signed by the verifier's `#active` key, which differs from
        /// `#0`, is admitted through the instance resolver.
        #[test]
        fn check_capability_requirements_admits_active_key_record() {
            pyo3::prepare_freethreaded_python();
            crate::init_runtime().ok();
            Python::with_gil(|py| {
                let scp = default_scp();
                let v = identity(py, &scp);
                let cvs = signed_cv_json(&scp, &v, &CvSigner::Active, VALID_DID, "ctx-admission");
                scp.check_capability_requirements(
                    py,
                    "ctx-admission",
                    VALID_DID,
                    &requirement_json(),
                    "[]",
                    &cvs,
                )
                .unwrap();
            });
        }

        /// A record signed by a key unrelated to the verifier's DID, or by its
        /// `#0` identity key, is dropped, so the requirement is unmet.
        #[test]
        fn check_capability_requirements_rejects_unrelated_and_identity_key_records() {
            pyo3::prepare_freethreaded_python();
            crate::init_runtime().ok();
            Python::with_gil(|py| {
                let scp = default_scp();
                let v = identity(py, &scp);
                for signer in [CvSigner::Unrelated, CvSigner::IdentityKey] {
                    let cvs = signed_cv_json(&scp, &v, &signer, VALID_DID, "ctx-admission");
                    let result = scp.check_capability_requirements(
                        py,
                        "ctx-admission",
                        VALID_DID,
                        &requirement_json(),
                        "[]",
                        &cvs,
                    );
                    assert_code(result, codes::VALID_7076);
                }
            });
        }

        /// An instance with no DID resolver fails closed on a supplied record.
        #[test]
        fn check_capability_requirements_without_resolver_is_ident_1033() {
            pyo3::prepare_freethreaded_python();
            crate::init_runtime().ok();
            Python::with_gil(|py| {
                let other = default_scp();
                let v = identity(py, &other);
                let cvs = signed_cv_json(&other, &v, &CvSigner::Active, VALID_DID, "ctx-admission");
                let scp = default_scp();
                assert!(crate::runtime::did_resolver(&scp.inner).is_none());
                let result = scp.check_capability_requirements(
                    py,
                    "ctx-admission",
                    VALID_DID,
                    &requirement_json(),
                    "[]",
                    &cvs,
                );
                assert_code(result, codes::IDENT_1033);
            });
        }

        #[test]
        fn check_capability_requirements_rejects_cross_subject_replay() {
            pyo3::prepare_freethreaded_python();
            crate::init_runtime().ok();
            Python::with_gil(|py| {
                let scp = default_scp();
                let v = identity(py, &scp);
                let cvs = signed_cv_json(
                    &scp,
                    &v,
                    &CvSigner::Active,
                    "did:dht:zVictim",
                    "ctx-admission",
                );
                let result = scp.check_capability_requirements(
                    py,
                    "ctx-admission",
                    "did:dht:zAttacker",
                    &requirement_json(),
                    "[]",
                    &cvs,
                );
                assert_code(result, codes::VALID_7076);
            });
        }

        #[test]
        fn check_capability_requirements_rejects_cross_context_replay() {
            pyo3::prepare_freethreaded_python();
            crate::init_runtime().ok();
            Python::with_gil(|py| {
                let scp = default_scp();
                let v = identity(py, &scp);
                let cvs = signed_cv_json(&scp, &v, &CvSigner::Active, VALID_DID, "ctx-other");
                let result = scp.check_capability_requirements(
                    py,
                    "ctx-admission",
                    VALID_DID,
                    &requirement_json(),
                    "[]",
                    &cvs,
                );
                assert_code(result, codes::VALID_7076);
            });
        }
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_events_json() {
        let result = default_scp().aggregate_trust_input(
            "ctx-1",
            "did:key:test",
            "not json",
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
            "[]",
            "{}",
            "{}",
            "[]",
            "[]",
        );
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7042),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7042
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_wrong_merkle_root_length() {
        let result = default_scp().aggregate_trust_input(
            "ctx-1",
            "did:key:test",
            "[]",
            "[0,0,0]",
            "[]",
            "{}",
            "{}",
            "[]",
            "[]",
        );
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7044),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7044
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_empty_did() {
        let result = default_scp().aggregate_trust_input(
            "ctx-1",
            "",
            "[]",
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
            "[]",
            "{}",
            "{}",
            "[]",
            "[]",
        );
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7041),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7041
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_empty_context() {
        pyo3::prepare_freethreaded_python();
        let result = default_scp().aggregate_trust_input(
            "",
            "did:key:test",
            "[]",
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
            "[]",
            "{}",
            "{}",
            "[]",
            "[]",
        );
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7040),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7040
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_merkle_root_json() {
        pyo3::prepare_freethreaded_python();
        let result = default_scp().aggregate_trust_input(
            "ctx-1",
            "did:key:test",
            "[]",
            "not json",
            "[]",
            "{}",
            "{}",
            "[]",
            "[]",
        );
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7043),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7043
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_consequence_rules_json() {
        pyo3::prepare_freethreaded_python();
        let result = default_scp().aggregate_trust_input(
            "ctx-1",
            "did:key:test",
            "[]",
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
            "not json",
            "{}",
            "{}",
            "[]",
            "[]",
        );
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7045),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7045
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_threshold_requirements_json() {
        pyo3::prepare_freethreaded_python();
        let result = default_scp().aggregate_trust_input(
            "ctx-1",
            "did:key:test",
            "[]",
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
            "[]",
            "not json",
            "{}",
            "[]",
            "[]",
        );
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7046),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7046
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_attestor_sets_json() {
        pyo3::prepare_freethreaded_python();
        let result = default_scp().aggregate_trust_input(
            "ctx-1",
            "did:key:test",
            "[]",
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
            "[]",
            "{}",
            "not json",
            "[]",
            "[]",
        );
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7047),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7047
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_cached_attestations_json() {
        pyo3::prepare_freethreaded_python();
        let result = default_scp().aggregate_trust_input(
            "ctx-1",
            "did:key:test",
            "[]",
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
            "[]",
            "{}",
            "{}",
            "not json",
            "[]",
        );
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7048),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7048
        );
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_challenge_results_json() {
        pyo3::prepare_freethreaded_python();
        let result = default_scp().aggregate_trust_input(
            "ctx-1",
            "did:key:test",
            "[]",
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
            "[]",
            "{}",
            "{}",
            "[]",
            "not json",
        );
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7049),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7049
        );
    }

    #[test]
    fn participation_record_validates_context_id() {
        pyo3::prepare_freethreaded_python();
        let result = default_scp().participation_record("", "did:key:test", "[]");
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7000),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7000
        );
    }

    #[test]
    fn participation_record_validates_did() {
        pyo3::prepare_freethreaded_python();
        let result = default_scp().participation_record("ctx-1", "not-a-did", "[]");
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7000),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7000
        );
    }

    #[test]
    fn participation_record_rejects_invalid_attestations_json() {
        pyo3::prepare_freethreaded_python();
        let result = default_scp().participation_record("ctx-1", "did:key:test", "not json");
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains(scp_ffi_common::error_codes::VALID_7059),
            "expected {}, got: {err_str}",
            scp_ffi_common::error_codes::VALID_7059
        );
    }

    /// The typed `PyParticipationRecord` surfaces every flattened fact from the
    /// shared `ParticipationFacts` projection with byte-identical values.
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
        let view = PyParticipationRecord::from(&facts);
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
        assert_eq!(view.event_log_root, encode_hex(&[7u8; 32]));
    }
}
