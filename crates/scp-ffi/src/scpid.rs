//! `PyO3` bridge functions for SCPID authentication (§3.11).
//!
//! Exposes SCPID challenge generation and signing to Python:
//!
//! - [`py_scpid_challenge`] — Generate an SCPID challenge for a relying party.
//! - [`py_scpid_sign`] — Sign an SCPID challenge with a registered identity's key.
//!
//! See spec §3.11 and the `scp-core` `scpid` module.

use std::time::Duration;

use pyo3::prelude::*;

use scp_core::identity::{ScpIdChallenge, scpid_challenge, scpid_sign};
use scp_identity::SigningKeyId;

use crate::error::ScpPyError;
use crate::runtime::with_identity;

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Generates an SCPID challenge for the given audience (§3.11.8).
///
/// Returns the challenge as a JSON string containing `protocol`, `nonce`,
/// `audience`, `issued_at`, and `expires_at` fields.
///
/// # Arguments
///
/// * `audience` — URI identifying the relying party (e.g., `"https://app.example.com"`).
/// * `ttl_seconds` — Challenge validity window in seconds (1–300).
///
/// # Errors
///
/// Raises `ValidationError` if `audience` is empty, exceeds 2048 bytes,
/// or `ttl_seconds` is 0 or exceeds 300.
#[pyfunction]
#[pyo3(name = "scpid_challenge")]
// ttl_seconds is u64 to match the `Duration::from_secs` parameter type.
// NAPI/WASM bridges use u32 (idiomatic for JS/WASM; max valid TTL is 300s).
pub fn py_scpid_challenge(audience: String, ttl_seconds: u64) -> PyResult<String> {
    let challenge = scpid_challenge(&audience, Duration::from_secs(ttl_seconds)).map_err(|e| {
        ScpPyError::ValidationError {
            message: e.to_string(),
            code: "SCP-IDENT-1038".to_string(),
        }
    })?;

    serde_json::to_string(&challenge).map_err(|e| {
        ScpPyError::IdentityError {
            message: format!("failed to serialize SCPID challenge: {e}"),
            code: "SCP-IDENT-1037".to_string(),
        }
        .into()
    })
}

/// Signs an SCPID challenge with a registered identity's key (§3.11.3).
///
/// Looks up the identity by DID in the global registry, selects the
/// appropriate signing key (`#active` or `#agent`), and produces a signed
/// SCPID response as a JSON string.
///
/// # Arguments
///
/// * `did` — The signer's DID (must be registered via `py_identity_create`).
/// * `signing_key_id` — `"#active"` or `"#agent"`.
/// * `challenge_json` — JSON string of the challenge (from [`py_scpid_challenge`]).
///
/// # Errors
///
/// Raises `IdentityError` if the DID is not registered.
/// Raises `ValidationError` if `signing_key_id` is invalid or the challenge
/// JSON is malformed.
/// Raises `IdentityError` if the signing operation fails.
#[pyfunction]
#[pyo3(name = "scpid_sign")]
pub fn py_scpid_sign(
    py: Python<'_>,
    did: String,
    signing_key_id: String,
    challenge_json: String,
) -> PyResult<String> {
    let key_id = parse_signing_key_id(&signing_key_id)?;

    let challenge: ScpIdChallenge =
        serde_json::from_str(&challenge_json).map_err(|e| ScpPyError::ValidationError {
            message: format!("invalid challenge JSON: {e}"),
            code: "SCP-IDENT-1038".to_string(),
        })?;

    let rt = crate::runtime()?;

    Ok(py.allow_threads(|| {
        with_identity(&did, |entry| {
            let key_handle =
                match key_id {
                    SigningKeyId::Active => entry.identity.active_signing_key,
                    SigningKeyId::Agent => entry.identity.agent_signing_key.ok_or_else(|| {
                        ScpPyError::IdentityError {
                            message: format!(
                                "identity '{did}' has no agent signing key — \
                             create one with py_identity_add_agent_key first"
                            ),
                            code: "SCP-IDENT-1034".to_string(),
                        }
                    })?,
                };

            let response = rt.block_on(scpid_sign(
                entry.custody.as_ref(),
                &key_handle,
                &did,
                key_id,
                &challenge,
            ));

            let response = response.map_err(|e| ScpPyError::IdentityError {
                message: e.to_string(),
                code: "SCP-IDENT-1037".to_string(),
            })?;

            serde_json::to_string(&response).map_err(|e| ScpPyError::IdentityError {
                message: format!("failed to serialize SCPID response: {e}"),
                code: "SCP-IDENT-1037".to_string(),
            })
        })
    })?)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parses a signing key ID string (`"#active"` or `"#agent"`) into a
/// [`SigningKeyId`] enum.
fn parse_signing_key_id(s: &str) -> PyResult<SigningKeyId> {
    match s {
        "#active" => Ok(SigningKeyId::Active),
        "#agent" => Ok(SigningKeyId::Agent),
        other => Err(ScpPyError::ValidationError {
            message: format!("invalid signing_key_id '{other}': expected '#active' or '#agent'"),
            code: "SCP-IDENT-1034".to_string(),
        }
        .into()),
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers SCPID bridge functions on the `_scp_core` module.
///
/// # Errors
///
/// Returns `PyErr` if registration fails.
pub fn register_scpid(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_scpid_challenge, m)?)?;
    m.add_function(wrap_pyfunction!(py_scpid_sign, m)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn challenge_returns_valid_json() {
        let json = py_scpid_challenge("https://example.com".to_owned(), 60).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["protocol"], "scpid/1.0");
        assert_eq!(v["audience"], "https://example.com");
        assert!(v["nonce"].is_string());
        assert!(v["issued_at"].is_u64());
        assert!(v["expires_at"].is_u64());
    }

    #[test]
    fn challenge_rejects_zero_ttl() {
        let result = py_scpid_challenge("https://example.com".to_owned(), 0);
        assert!(result.is_err());
    }

    #[test]
    fn challenge_rejects_excessive_ttl() {
        let result = py_scpid_challenge("https://example.com".to_owned(), 301);
        assert!(result.is_err());
    }

    #[test]
    fn challenge_rejects_empty_audience() {
        let result = py_scpid_challenge(String::new(), 60);
        assert!(result.is_err());
    }

    #[test]
    fn parse_signing_key_id_valid() {
        assert_eq!(
            parse_signing_key_id("#active").unwrap(),
            SigningKeyId::Active
        );
        assert_eq!(parse_signing_key_id("#agent").unwrap(), SigningKeyId::Agent);
    }

    #[test]
    fn parse_signing_key_id_invalid() {
        assert!(parse_signing_key_id("active").is_err());
        assert!(parse_signing_key_id("#owner").is_err());
        assert!(parse_signing_key_id("").is_err());
    }
}
