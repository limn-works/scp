//! `PyO3` bridge functions for the SCP trust engine.
//!
//! Exposes trust engine operations to Python:
//!
//! - [`py_trust_query_score`] — Query participation-based trust data for a DID.
//! - [`py_trust_verify_attestation`] — Verify an attestation's signature and
//!   validity.
//! - [`py_trust_create_challenge`] — Create a challenge request for capability
//!   verification.
//! - [`py_trust_verify_response`] — Verify a challenge response.
//!
//! The trust engine does not produce trust "scores" — it provides verifiable
//! facts (participation records, attestation verification results, challenge
//! verification results) that agents consume for their own trust evaluation
//! logic. The `composite_score` field in the query result is a normalized
//! summary for convenience, not an authoritative trust judgment.
//!
//! See ADR-017 in `.docs/adrs/phase-4.md`.

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::validate;

// ---------------------------------------------------------------------------
// trust_query_score
// ---------------------------------------------------------------------------

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
/// computation (Layer 2 of the four-layer trust model). Two agents may compute
/// different records from different event log views — this is correct behavior
/// per the protocol design.
///
/// # Errors
///
/// Returns `ScpError` if input validation fails.
#[pyfunction]
#[pyo3(name = "trust_query_score")]
pub fn py_trust_query_score(py: Python<'_>, did: &str, context_id: &str) -> PyResult<Py<PyDict>> {
    validate::validate_did(did)?;
    validate::validate_context_id(context_id)?;

    // Query the runtime registry for event counts. The event log stores leaf
    // hashes (Merkle tree), not full events. The runtime registry tracks
    // per-context event metadata sufficient for participation summaries.
    let (message_count, governance_count) =
        crate::runtime::query_trust_event_counts(context_id, did);

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
/// Uses the production [`IdentityDidPublicKeyResolver`] for DID key
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
        serde_json::json!({}),
        std::time::Duration::from_secs(300),
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
/// Uses the production [`IdentityDidPublicKeyResolver`] for DID key
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

    Ok(scp_core::trust::verify_challenge_response(&request, &response, &resolver, &clock).is_ok())
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers trust engine bridge functions with the Python module.
pub fn register_trust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_trust_query_score, m)?)?;
    m.add_function(wrap_pyfunction!(py_trust_verify_attestation, m)?)?;
    m.add_function(wrap_pyfunction!(py_trust_create_challenge, m)?)?;
    m.add_function(wrap_pyfunction!(py_trust_verify_response, m)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn trust_query_score_validates_did() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            // Empty DID should fail validation.
            let result = py_trust_query_score(py, "", "ctx-1");
            assert!(result.is_err());
        });
    }

    #[test]
    fn trust_query_score_validates_context_id() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            // Empty context ID should fail validation.
            let result = py_trust_query_score(py, "did:key:test", "");
            assert!(result.is_err());
        });
    }

    #[test]
    fn trust_query_score_returns_valid_dict() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = py_trust_query_score(py, "did:key:test", "ctx-valid");
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
}
