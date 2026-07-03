//! `PyO3` bridge functions for the SCP trust engine.
//!
//! Exposes trust engine operations to Python. Stateful operations are methods
//! on the `SCP` class; pure helpers remain as free `#[pyfunction]` exports.
//!
//! Pure helpers (no bridge state):
//!
//! - [`py_trust_verify_attestation`] — Verify an attestation's signature and
//!   validity.
//! - [`py_trust_create_challenge`] — Create a challenge request for capability
//!   verification.
//! - [`py_trust_verify_response`] — Verify a challenge response.
//! - [`py_verify_participation_requirements`] — Verify participation profiles
//!   against admission requirements.
//!
//! `SCP` methods (bridge-state accessors):
//!
//! - `PyScp::trust_query_score` — Query participation-based trust data for a DID.
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

use crate::runtime::PyBridgeInstance;
use crate::types::encode_hex;
use crate::validate;

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
    validate::validate_did(did)?;
    validate::validate_context_id(context_id)?;

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

/// Verifies an attestation's Ed25519 signature, evidence, expiry, and
/// revocation status.
///
/// Accepts the attestation as a JSON string and returns a dict with:
/// - `valid` (bool): Whether verification succeeded.
/// - `chain_depth` (int): 1 for a single attestation (chain depth tracking
///   requires the full attestation graph, which is deferred to the
///   attestation store integration).
/// - `error` (Optional[str]): Error message if verification failed, `None`
///   if valid.
///
/// Uses the production `IdentityDidPublicKeyResolver` for DID key
/// resolution.
///
/// # Errors
///
/// Returns `ScpError` if the JSON is malformed or cannot be parsed.
#[pyfunction]
#[pyo3(name = "trust_verify_attestation")]
pub fn py_trust_verify_attestation(py: Python<'_>, attestation_json: &str) -> PyResult<Py<PyDict>> {
    let attestation: scp_core::trust::Attestation = serde_json::from_str(attestation_json)
        .map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "failed to parse attestation JSON: {e}"
            ))
        })?;

    let resolver = scp_core::trust::IdentityDidPublicKeyResolver;
    let clock = scp_clock::SystemClock;

    let dict = PyDict::new(py);
    match scp_core::trust::verify_attestation(&attestation, &resolver, &clock) {
        Ok(()) => {
            dict.set_item("valid", true)?;
            dict.set_item("chain_depth", 1)?;
            dict.set_item("error", py.None())?;
        }
        Err(e) => {
            dict.set_item("valid", false)?;
            dict.set_item("chain_depth", 0)?;
            dict.set_item("error", format!("{e}"))?;
        }
    }

    Ok(dict.into())
}

// ---------------------------------------------------------------------------
// trust_create_challenge
// ---------------------------------------------------------------------------

/// Creates a challenge request for capability verification.
///
/// Returns a dict with:
/// - `challenge_id` (str): The unique challenge ID (UUID v4).
/// - `challenge_json` (str): The full serialized challenge request (JSON).
///
/// The caller must provide signing capability. For this bridge function, a
/// random ephemeral key is generated for signing. Production callers should
/// use the identity's active signing key via the custody provider.
///
/// # Errors
///
/// Returns `ScpError` if input validation or signing fails.
#[pyfunction]
#[pyo3(name = "trust_create_challenge")]
pub fn py_trust_create_challenge(py: Python<'_>, target_did: &str) -> PyResult<Py<PyDict>> {
    validate::validate_did(target_did)?;

    struct EphemeralSigner(ed25519_dalek::SigningKey);
    impl scp_core::trust::ChallengeSigner for EphemeralSigner {
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>, scp_core::trust::TrustError> {
            use ed25519_dalek::Signer;
            let sig = self.0.sign(data);
            Ok(sig.to_bytes().to_vec())
        }
    }

    // Generate an ephemeral signing key for the challenge request.
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let signer = EphemeralSigner(signing_key);
    let challenger_did = "did:key:ephemeral-challenger";

    let request = scp_core::trust::issue_challenge(
        challenger_did.into(),
        target_did.into(),
        scp_core::trust::ChallengeType::schema_validation(),
        "scp:capability:schema-validation/v1".to_owned(),
        serde_json::json!({}),
        std::time::Duration::from_mins(5),
        &signer,
    )
    .map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("challenge creation failed: {e}"))
    })?;

    let challenge_json = serde_json::to_string(&request).map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("failed to serialize challenge: {e}"))
    })?;

    let dict = PyDict::new(py);
    dict.set_item("challenge_id", &request.challenge_id)?;
    dict.set_item("challenge_json", &challenge_json)?;

    Ok(dict.into())
}

// ---------------------------------------------------------------------------
// trust_verify_response
// ---------------------------------------------------------------------------

/// Verifies a challenge response against its original challenge request.
///
/// Both `challenge_json` and `response_json` are JSON strings. Returns `True`
/// if the response is valid (correct responder, within timeout, valid
/// signature), `False` otherwise.
///
/// Uses the production `IdentityDidPublicKeyResolver` for DID key
/// resolution.
///
/// # Errors
///
/// Returns `ScpError` if the JSON is malformed.
#[pyfunction]
#[pyo3(name = "trust_verify_response")]
pub fn py_trust_verify_response(challenge_json: &str, response_json: &str) -> PyResult<bool> {
    let request: scp_core::trust::ChallengeRequest =
        serde_json::from_str(challenge_json).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("failed to parse challenge JSON: {e}"))
        })?;

    let response: scp_core::trust::ChallengeResponse = serde_json::from_str(response_json)
        .map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("failed to parse response JSON: {e}"))
        })?;

    let resolver = scp_core::trust::IdentityDidPublicKeyResolver;
    let clock = scp_clock::SystemClock;

    struct EphemeralVerifierSigner(ed25519_dalek::SigningKey);
    impl scp_core::trust::ChallengeSigner for EphemeralVerifierSigner {
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>, scp_core::trust::TrustError> {
            use ed25519_dalek::Signer;
            let sig = self.0.sign(data);
            Ok(sig.to_bytes().to_vec())
        }
    }
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifier_signer = EphemeralVerifierSigner(signing_key);

    Ok(scp_core::trust::verify_challenge_response(
        &request,
        &response,
        &resolver,
        &clock,
        &verifier_signer,
        None,
    )
    .is_ok())
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
/// Returns `PyValueError` if JSON parsing fails, or `PyRuntimeError` if
/// participation admission verification fails (with the specific failure
/// reason from `ParticipationAdmissionError`).
#[pyfunction]
#[pyo3(name = "verify_participation_requirements")]
pub fn py_verify_participation_requirements(
    expected_subject: &str,
    requirements_json: &str,
    profile_json: &str,
) -> PyResult<()> {
    validate::validate_did(expected_subject)?;

    let requirements: Vec<scp_core::trust::RequireParticipation> =
        serde_json::from_str(requirements_json).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "failed to parse participation requirements JSON: {e}"
            ))
        })?;

    let profiles: Vec<scp_core::trust::ParticipationProfile> = serde_json::from_str(profile_json)
        .map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "failed to parse participation profiles JSON: {e}"
        ))
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
        pyo3::exceptions::PyRuntimeError::new_err(format!(
            "participation admission verification failed: {e}"
        ))
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// check_capability_requirements (§7.3.4.4, SCP-ACR-008)
// ---------------------------------------------------------------------------

/// Verifies that an agent meets a context's capability requirements for
/// admission, bound to the agent and context being admitted.
///
/// Inputs (all JSON except the two DID/context ids):
/// - `context_id`: the context the agent is being admitted to. A challenge
///   verification only satisfies a requirement when its signed `context_id`
///   equals this value.
/// - `subject_did`: the DID of the agent being admitted. Only challenge
///   verifications whose signed `subject_did` equals this value can satisfy a
///   requirement — a genuine result minted for another subject MUST NOT admit
///   this agent (cross-subject attribution).
/// - `requirements_json`: JSON array of `CapabilityRequirement` objects.
/// - `agent_capabilities_json`: JSON array of capability-URI strings the agent
///   self-attests.
/// - `challenge_verifications_json`: JSON array of `ChallengeVerification`
///   records; each is signature-verified against `resolver`/`clock` and only
///   counts if authentic, in-context, in-subject, passed, and unexpired.
///
/// Uses the production `IdentityDidPublicKeyResolver` for verifier-DID key
/// resolution and the fail-closed system clock for expiry. Returns `Ok(())` on
/// success — success is indicated by returning without exception. Raises
/// `ScpError` with a diagnostic message if any requirement is unmet or if the
/// JSON is malformed.
///
/// SECURITY (verifier legitimacy): a passing `ChallengeVerified` check proves
/// the verifier's signature is authentic and bound to this subject/context, NOT
/// that the verifier is authorized/trusted. A `verifier_did` is self-certifying;
/// establish verifier legitimacy separately (see spec §7.3.4.4 / §7.4).
///
/// See spec §7.3.4.4.
///
/// # Errors
///
/// Returns `PyValueError` if any JSON input is malformed or `subject_did` is
/// not a valid DID, or `PyRuntimeError` if an admission requirement is unmet
/// (with the specific reason from `AdmissionError`).
#[pyfunction]
#[pyo3(name = "check_capability_requirements")]
pub fn py_check_capability_requirements(
    context_id: &str,
    subject_did: &str,
    requirements_json: &str,
    agent_capabilities_json: &str,
    challenge_verifications_json: &str,
) -> PyResult<()> {
    validate::validate_did(subject_did)?;

    let requirements: Vec<scp_core::trust::CapabilityRequirement> =
        serde_json::from_str(requirements_json).map_err(|e| {
            crate::error::ScpPyError::ValidationError {
                message: format!("failed to parse capability requirements JSON: {e}"),
                code: scp_ffi_common::error_codes::VALID_7073.to_owned(),
            }
        })?;

    let agent_capabilities: Vec<scp_core::trust::CapabilityUri> =
        serde_json::from_str(agent_capabilities_json).map_err(|e| {
            crate::error::ScpPyError::ValidationError {
                message: format!("failed to parse agent capabilities JSON: {e}"),
                code: scp_ffi_common::error_codes::VALID_7074.to_owned(),
            }
        })?;

    let challenge_verifications: Vec<scp_core::trust::ChallengeVerification> =
        serde_json::from_str(challenge_verifications_json).map_err(|e| {
            crate::error::ScpPyError::ValidationError {
                message: format!("failed to parse challenge verifications JSON: {e}"),
                code: scp_ffi_common::error_codes::VALID_7075.to_owned(),
            }
        })?;

    let resolver = scp_core::trust::IdentityDidPublicKeyResolver;
    let clock = scp_identity::cache::SystemClock;

    scp_core::trust::check_capability_requirements(
        &requirements,
        &agent_capabilities,
        &challenge_verifications,
        context_id,
        subject_did,
        &resolver,
        &clock,
    )
    .map_err(|e| {
        // Mirror the UniFFI/NAPI bridges' per-variant code mapping so every
        // native bridge surfaces an identical `SCP-VALID-707x` for the same
        // failure case: empty subject → 7077; missing capability /
        // verification-required → 7076.
        let code = match e {
            scp_core::trust::AdmissionError::EmptySubjectDid => {
                scp_ffi_common::error_codes::VALID_7077
            }
            scp_core::trust::AdmissionError::MissingCapability { .. }
            | scp_core::trust::AdmissionError::VerificationRequired { .. } => {
                scp_ffi_common::error_codes::VALID_7076
            }
        };
        crate::error::ScpPyError::ValidationError {
            message: format!("capability admission verification failed: {e}"),
            code: code.to_owned(),
        }
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
    validate::validate_context_id(context_id)?;
    validate::validate_did(subject_did)?;

    // Parse all JSON inputs.
    let events: Vec<scp_event_log::Event> = serde_json::from_str(events_json).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("failed to parse events JSON: {e}"))
    })?;

    let merkle_root_vec: Vec<u8> = serde_json::from_str(merkle_root_json).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("failed to parse merkle_root JSON: {e}"))
    })?;
    let merkle_root: [u8; 32] = merkle_root_vec.try_into().map_err(|v: Vec<u8>| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "merkle_root must be exactly 32 bytes, got {}",
            v.len()
        ))
    })?;

    let consequence_rules: Vec<scp_core::trust::ConsequenceRule> =
        serde_json::from_str(consequence_rules_json).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "failed to parse consequence_rules JSON: {e}"
            ))
        })?;

    let threshold_requirements: std::collections::HashMap<
        scp_core::trust::AttestationType,
        scp_core::trust::ThresholdRequirement,
    > = serde_json::from_str(threshold_requirements_json).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "failed to parse threshold_requirements JSON: {e}"
        ))
    })?;

    let attestor_sets: std::collections::HashMap<
        scp_core::trust::AttestationType,
        Vec<scp_core::trust::AttestorInfo>,
    > = serde_json::from_str(attestor_sets_json).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("failed to parse attestor_sets JSON: {e}"))
    })?;

    let cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation> =
        serde_json::from_str(cached_attestations_json).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "failed to parse cached_attestations JSON: {e}"
            ))
        })?;

    let challenge_results: Vec<scp_core::trust::ChallengeVerification> =
        serde_json::from_str(challenge_results_json).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "failed to parse challenge_results JSON: {e}"
            ))
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
        pyo3::exceptions::PyValueError::new_err(format!(
            "{}: bridge storage not initialized — trust aggregation is \
             unreachable until this PyBridgeInstance has allocated its \
             storage provider (bridge init bug)",
            scp_ffi_common::error_codes::VALID_7005
        ))
    })?;
    let handle = crate::runtime()?.handle().clone();
    // The aggregation logic lives ONCE in `run_aggregation` (generic over the
    // concrete `EncryptedStorage` backend). The match is pure type dispatch: the
    // sealed `EncryptedStorage` bound on `ProtocolRepository::new` cannot be
    // satisfied by the `StorageProvider` enum itself (the marker trait lives in
    // `scp-platform`), so the concrete `Arc<S>` must be recovered per variant.
    // Both arms route through the single generic body — no duplicated logic.
    let inputs = AggregationInputs {
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
    result.map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

/// Owned + borrowed inputs for [`run_aggregation`], grouped to keep the generic
/// helper's signature manageable.
struct AggregationInputs<'a> {
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
/// [`PyScp::participation_record`]. Counts are flattened ONCE in the shared Rust
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
    /// Total tool invocations across all tool types.
    #[pyo3(get)]
    pub tool_invocation_count: u64,
    /// Whether `tool_invocation_count` is anchored in the canonical Merkle log.
    /// `false` until ADR-051 makes `ToolInvoked` a convergent leaf (§7.3.2) —
    /// consumers MUST NOT treat the count as Merkle-proven while this is `false`.
    #[pyo3(get)]
    pub tool_invocation_count_anchored: bool,
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
    /// `tool_invocation_count_anchored`, surfaced so the non-anchored nature is
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
            tool_invocation_count: f.tool_invocation_count,
            tool_invocation_count_anchored: f.tool_invocation_count_anchored,
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
             tool_invocation_count={}, tool_invocation_count_anchored={}, \
             context_creation_count={}, role_progression_count={}, \
             attestation_count={}, attestation_count_anchored={})",
            self.subject_did,
            self.participation_duration_secs,
            self.governance_actions_against,
            self.governance_actions_by,
            self.tool_invocation_count,
            self.tool_invocation_count_anchored,
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

    validate::validate_context_id(context_id)?;
    validate::validate_did(subject_did)?;

    let cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation> =
        serde_json::from_str(cached_attestations_json).map_err(|e| {
            crate::error::ScpPyError::ValidationError {
                message: format!("failed to parse cached_attestations JSON: {e}"),
                code: scp_ffi_common::error_codes::VALID_7059.to_owned(),
            }
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
/// `SCP`. Only pure helpers (attestation verification, challenge creation,
/// response verification, participation requirement verification) remain as
/// free `#[pyfunction]` exports.
pub fn register_trust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyParticipationRecord>()?;
    m.add_function(wrap_pyfunction!(py_trust_verify_attestation, m)?)?;
    m.add_function(wrap_pyfunction!(py_trust_create_challenge, m)?)?;
    m.add_function(wrap_pyfunction!(py_trust_verify_response, m)?)?;
    m.add_function(wrap_pyfunction!(py_verify_participation_requirements, m)?)?;
    m.add_function(wrap_pyfunction!(py_check_capability_requirements, m)?)?;
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
        });
    }

    #[test]
    fn trust_query_score_validates_context_id() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            // Empty context ID should fail validation.
            let result = default_scp().trust_query_score(py, "did:key:test", "");
            assert!(result.is_err());
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
            let result = py_trust_verify_attestation(py, "not valid json");
            assert!(result.is_err());
        });
    }

    #[test]
    fn trust_create_challenge_validates_did() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = py_trust_create_challenge(py, "");
            assert!(result.is_err());
        });
    }

    #[test]
    fn trust_create_challenge_returns_valid_dict() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = py_trust_create_challenge(py, "did:key:target");
            assert!(result.is_ok());
            let dict = result.unwrap();
            let dict_ref = dict.bind(py);
            assert!(dict_ref.get_item("challenge_id").unwrap().is_some());
            assert!(dict_ref.get_item("challenge_json").unwrap().is_some());
        });
    }

    #[test]
    fn trust_verify_response_rejects_invalid_json() {
        let result = py_trust_verify_response("bad", "bad");
        assert!(result.is_err());
    }

    #[test]
    fn verify_participation_requirements_rejects_invalid_profile_json() {
        // Malformed JSON in the PROFILE position (now the 3rd arg).
        let result = py_verify_participation_requirements("did:key:alice", "[]", "not json");
        assert!(result.is_err());
    }

    #[test]
    fn verify_participation_requirements_rejects_invalid_requirements_json() {
        // Malformed JSON in the REQUIREMENTS position (now the 2nd arg).
        let result = py_verify_participation_requirements("did:key:alice", "not json", "[]");
        assert!(result.is_err());
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
        let result = py_verify_participation_requirements("not-a-did", "[]", "[]");
        assert!(result.is_err());
    }

    // -- check_capability_requirements (§7.3.4.4, SCP-ACR-008) --

    #[test]
    fn check_capability_requirements_rejects_invalid_requirements_json() {
        Python::with_gil(|_py| {
            let result =
                py_check_capability_requirements("ctx-1", "did:key:alice", "not json", "[]", "[]");
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
        Python::with_gil(|_py| {
            let result =
                py_check_capability_requirements("ctx-1", "did:key:alice", "[]", "not json", "[]");
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
        Python::with_gil(|_py| {
            let result =
                py_check_capability_requirements("ctx-1", "did:key:alice", "[]", "[]", "not json");
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
        // No requirements = no constraints = always passes.
        let result = py_check_capability_requirements("ctx-1", "did:key:alice", "[]", "[]", "[]");
        assert!(result.is_ok());
    }

    #[test]
    fn check_capability_requirements_rejects_malformed_subject() {
        let result = py_check_capability_requirements("ctx-1", "not-a-did", "[]", "[]", "[]");
        assert!(result.is_err());
    }

    #[test]
    fn check_capability_requirements_rejects_empty_subject() {
        // An empty subject is rejected at the FFI boundary (validate_did).
        let result = py_check_capability_requirements("ctx-1", "", "[]", "[]", "[]");
        assert!(result.is_err());
    }

    #[test]
    fn check_capability_requirements_self_attested_present_succeeds() {
        // A SelfAttested requirement is satisfied by a declared capability — no
        // challenge verification (and thus no signature check) is needed.
        let requirements = r#"[{"capability":"scp:capability:schema-validation/v1","verification_level":"SelfAttested"}]"#;
        let capabilities = r#"["scp:capability:schema-validation/v1"]"#;
        let result = py_check_capability_requirements(
            "ctx-1",
            "did:key:alice",
            requirements,
            capabilities,
            "[]",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn check_capability_requirements_self_attested_missing_fails() {
        // A SelfAttested requirement with no matching declared capability and no
        // verification record fails as an admission (runtime) error.
        let requirements = r#"[{"capability":"scp:capability:schema-validation/v1","verification_level":"SelfAttested"}]"#;
        Python::with_gil(|_py| {
            let result = py_check_capability_requirements(
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

    /// Builds a genuinely verifier-signed `ChallengeVerification` JSON array
    /// (single record) bound to `subject_did`/`context_id`, with a far-future
    /// expiry so it survives the production `SystemClock`. The verifier DID is
    /// derived from a fixed key so the production `IdentityDidPublicKeyResolver`
    /// (did:dht:z, offline-resolvable) authenticates the signature.
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
        let uri = "scp:capability:prompt-injection-resistance/v1";
        let subject = "did:dht:zResponder";
        let ctx = "ctx-admission";
        let requirements =
            format!(r#"[{{"capability":"{uri}","verification_level":"ChallengeVerified"}}]"#);
        let cvs = signed_cv_json(uri, subject, ctx);
        let result = py_check_capability_requirements(ctx, subject, &requirements, "[]", &cvs);
        assert!(result.is_ok());
    }

    #[test]
    fn check_capability_requirements_rejects_cross_subject_replay() {
        // The verification is genuinely signed, but for a DIFFERENT subject.
        let uri = "scp:capability:prompt-injection-resistance/v1";
        let ctx = "ctx-admission";
        let requirements =
            format!(r#"[{{"capability":"{uri}","verification_level":"ChallengeVerified"}}]"#);
        let cvs = signed_cv_json(uri, "did:dht:zVictim", ctx);
        let result =
            py_check_capability_requirements(ctx, "did:dht:zAttacker", &requirements, "[]", &cvs);
        assert!(result.is_err());
    }

    #[test]
    fn check_capability_requirements_rejects_cross_context_replay() {
        // The verification is genuinely signed, but bound to a DIFFERENT context.
        let uri = "scp:capability:prompt-injection-resistance/v1";
        let subject = "did:dht:zResponder";
        let requirements =
            format!(r#"[{{"capability":"{uri}","verification_level":"ChallengeVerified"}}]"#);
        let cvs = signed_cv_json(uri, subject, "ctx-other");
        let result =
            py_check_capability_requirements("ctx-admission", subject, &requirements, "[]", &cvs);
        assert!(result.is_err());
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
    }

    #[test]
    fn participation_record_validates_context_id() {
        let result = default_scp().participation_record("", "did:key:test", "[]");
        assert!(result.is_err());
    }

    #[test]
    fn participation_record_validates_did() {
        let result = default_scp().participation_record("ctx-1", "not-a-did", "[]");
        assert!(result.is_err());
    }

    #[test]
    fn participation_record_rejects_invalid_attestations_json() {
        let result = default_scp().participation_record("ctx-1", "did:key:test", "not json");
        assert!(result.is_err());
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
            tool_invocation_count: 5,
            tool_invocation_count_anchored: false,
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
        assert_eq!(view.tool_invocation_count, 5);
        assert!(!view.tool_invocation_count_anchored);
        assert_eq!(view.context_creation_count, 1);
        assert_eq!(view.role_progression_count, 3);
        assert_eq!(view.attestation_count, 2);
        assert!(!view.attestation_count_anchored);
        assert_eq!(view.computed_at, 42);
        assert_eq!(view.event_log_root, encode_hex(&[7u8; 32]));
    }
}
