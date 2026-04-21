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
//! methods in Phase 4 PR 4 sub-slice E (#1549).
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
use scp_ffi_common::trust_store::InMemoryFfiTrustStore;

use crate::runtime::PyBridgeInstance;
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
    let clock = scp_identity::cache::SystemClock;

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
    let clock = scp_identity::cache::SystemClock;

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

/// Verifies participation profiles against admission requirements.
///
/// Both inputs are JSON strings:
/// - `profile_json`: JSON array of `ParticipationProfile` objects.
/// - `requirements_json`: JSON array of `RequireParticipation` objects.
///
/// Uses the current system time for freshness checks. Returns `Ok(true)` on
/// success. The Python SDK wrapper discards the return value — success is
/// indicated by returning without exception. Raises `ScpError` with a
/// diagnostic message if any requirement fails or if the JSON is malformed.
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
    profile_json: &str,
    requirements_json: &str,
) -> PyResult<bool> {
    let profiles: Vec<scp_core::trust::ParticipationProfile> = serde_json::from_str(profile_json)
        .map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "failed to parse participation profiles JSON: {e}"
        ))
    })?;

    let requirements: Vec<scp_core::trust::RequireParticipation> =
        serde_json::from_str(requirements_json).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "failed to parse participation requirements JSON: {e}"
            ))
        })?;

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    scp_core::trust::verify_participation_requirements(current_time, &requirements, &profiles)
        .map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "participation admission verification failed: {e}"
            ))
        })?;

    Ok(true)
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
/// falls back to an ephemeral in-memory store otherwise. See issue #502.
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
/// states, and challenge results survive process restarts (issue #502).
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
    let Ok(provider) = crate::runtime::get_storage(bi) else {
        return scp_ffi_common::trust_store::populate_and_aggregate(
            InMemoryFfiTrustStore::new(),
            context_id,
            subject_did,
            cached_attestations,
            challenge_results,
            events,
            merkle_root,
            consequence_rules,
            threshold_requirements,
            attestor_sets,
        )
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()));
    };
    let handle = crate::runtime()?.handle().clone();
    match provider {
        StorageProvider::InMemoryEncrypted(storage) => {
            let repo = Arc::new(scp_core::store::ProtocolRepository::new(Arc::clone(
                storage,
            )));
            let bridge = scp_core::trust::ProtocolRepositoryTrustBridge::new(repo, handle);
            scp_ffi_common::trust_store::populate_and_aggregate(
                bridge,
                context_id,
                subject_did,
                cached_attestations,
                challenge_results,
                events,
                merkle_root,
                consequence_rules,
                threshold_requirements,
                attestor_sets,
            )
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
        }
        StorageProvider::Sqlite(storage) => {
            let repo = Arc::new(scp_core::store::ProtocolRepository::new(Arc::clone(
                storage,
            )));
            let bridge = scp_core::trust::ProtocolRepositoryTrustBridge::new(repo, handle);
            scp_ffi_common::trust_store::populate_and_aggregate(
                bridge,
                context_id,
                subject_did,
                cached_attestations,
                challenge_results,
                events,
                merkle_root,
                consequence_rules,
                threshold_requirements,
                attestor_sets,
            )
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
        }
    }
}

// ---------------------------------------------------------------------------
// PyScp methods — migrated from #[pyfunction] exports (Phase 4 PR 4, #1549).
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
    /// falls back to an ephemeral in-memory store otherwise. See issue #502.
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
    m.add_function(wrap_pyfunction!(py_trust_verify_attestation, m)?)?;
    m.add_function(wrap_pyfunction!(py_trust_create_challenge, m)?)?;
    m.add_function(wrap_pyfunction!(py_trust_verify_response, m)?)?;
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
        crate::scp::PyScp::new()
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
        let result = py_verify_participation_requirements("not json", "[]");
        assert!(result.is_err());
    }

    #[test]
    fn verify_participation_requirements_rejects_invalid_requirements_json() {
        let result = py_verify_participation_requirements("[]", "not json");
        assert!(result.is_err());
    }

    #[test]
    fn verify_participation_requirements_empty_inputs_succeeds() {
        // Empty requirements = no constraints = always passes.
        let result = py_verify_participation_requirements("[]", "[]");
        assert!(result.is_ok());
        assert!(result.unwrap());
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
}
