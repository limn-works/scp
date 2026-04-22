//! `PyO3` bridge functions for SCPID authentication (§3.11).
//!
//! Exposes SCPID challenge generation, signing, and verification to Python
//! as methods on the `SCP` class:
//!
//! - `PyScp::scpid_challenge` — Generate an SCPID challenge for a relying party.
//! - `PyScp::scpid_sign` — Sign an SCPID challenge with a registered identity's key.
//! - `PyScp::scpid_verify` — Verify a signed SCPID response (relying-party side).
//!
//! Migrated from flat `#[pyfunction]` exports to `#[pymethods] impl PyScp`
//! methods in Phase 4 PR 4 sub-slice C (#1549).
//!
//! See spec §3.11 and the `scp-core` `scpid` module.

use scp_ffi_common::error_codes as codes;
use std::time::Duration;

use pyo3::prelude::*;

use scp_core::identity::{
    ScpIdChallenge, ScpIdResponse, scpid_challenge, scpid_sign, scpid_verify,
};
use scp_identity::SigningKeyId;

use crate::error::ScpPyError;
use crate::runtime::with_identity;

// ---------------------------------------------------------------------------
// PyScp methods — migrated from #[pyfunction] exports (Phase 4 PR 4, #1549).
// ---------------------------------------------------------------------------

#[pymethods]
impl crate::scp::PyScp {
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
    // ttl_seconds is u64 to match the `Duration::from_secs` parameter type.
    // NAPI/WASM bridges use u32 (idiomatic for JS/WASM; max valid TTL is 300s).
    pub fn scpid_challenge(&self, audience: String, ttl_seconds: u64) -> PyResult<String> {
        let challenge =
            scpid_challenge(&audience, Duration::from_secs(ttl_seconds)).map_err(|e| {
                ScpPyError::ValidationError {
                    message: e.to_string(),
                    code: codes::IDENT_1038.to_string(),
                }
            })?;

        serde_json::to_string(&challenge).map_err(|e| {
            ScpPyError::IdentityError {
                message: format!("failed to serialize SCPID challenge: {e}"),
                code: codes::IDENT_1037.to_string(),
            }
            .into()
        })
    }

    /// Signs an SCPID challenge with a registered identity's key (§3.11.3).
    ///
    /// Looks up the identity by DID in this bridge's registry, selects the
    /// appropriate signing key (`#active` or `#agent`), and produces a
    /// signed SCPID response as a JSON string.
    ///
    /// # Arguments
    ///
    /// * `did` — The signer's DID (must be registered via `identity_create`).
    /// * `signing_key_id` — `"#active"` or `"#agent"`.
    /// * `challenge_json` — JSON string of the challenge (from `PyScp::scpid_challenge`).
    /// * `signed_at_override` — Optional Unix-millisecond timestamp used in
    ///   place of the current wall clock. **Only accepted when scp-core is
    ///   built with the `testing` feature**; attempts to supply a value on
    ///   production builds are rejected. Drives the cross-bridge parity
    ///   harness (ADR-046) so two bridges signing the same challenge under
    ///   the same seed produce byte-identical signatures.
    ///
    /// # Errors
    ///
    /// Raises `IdentityError` if the DID is not registered.
    /// Raises `ValidationError` if `signing_key_id` is invalid, the challenge
    /// JSON is malformed, or `signed_at_override` is supplied on a
    /// non-testing build / outside the challenge window.
    /// Raises `IdentityError` if the signing operation fails.
    #[pyo3(signature = (did, signing_key_id, challenge_json, signed_at_override = None))]
    pub fn scpid_sign(
        &self,
        py: Python<'_>,
        did: String,
        signing_key_id: String,
        challenge_json: String,
        signed_at_override: Option<u64>,
    ) -> PyResult<String> {
        let bi = &*self.inner;
        // Reject `signed_at_override` on non-testing builds: the override is a
        // parity-harness affordance, not a production API.
        #[cfg(not(feature = "testing"))]
        if signed_at_override.is_some() {
            return Err(ScpPyError::ValidationError {
                message:
                    "signed_at_override requires the scp-core `testing` feature — not available in production builds"
                        .to_string(),
                code: codes::VALID_7007.to_string(),
            }
            .into());
        }
        let key_id = parse_signing_key_id(&signing_key_id)?;

        let challenge: ScpIdChallenge =
            serde_json::from_str(&challenge_json).map_err(|e| ScpPyError::ValidationError {
                message: format!("invalid challenge JSON: {e}"),
                code: codes::IDENT_1038.to_string(),
            })?;

        let rt = crate::runtime()?;

        Ok(py.allow_threads(|| {
            with_identity(bi, &did, |entry| {
                let key_handle = match key_id {
                    SigningKeyId::Active => entry.identity.active_signing_key,
                    SigningKeyId::Agent => entry.identity.agent_signing_key.ok_or_else(|| {
                        ScpPyError::IdentityError {
                            message: format!(
                                "identity '{did}' has no agent signing key — \
                             create one with identity_add_agent_key first"
                            ),
                            code: codes::IDENT_1034.to_string(),
                        }
                    })?,
                };

                let response = rt.block_on(scpid_sign(
                    entry.custody.as_ref(),
                    &key_handle,
                    &did,
                    key_id,
                    &challenge,
                    signed_at_override,
                ));

                let response = response.map_err(|e| ScpPyError::IdentityError {
                    message: e.to_string(),
                    code: codes::IDENT_1037.to_string(),
                })?;

                serde_json::to_string(&response).map_err(|e| ScpPyError::IdentityError {
                    message: format!("failed to serialize SCPID response: {e}"),
                    code: codes::IDENT_1037.to_string(),
                })
            })
        })?)
    }

    /// Verifies a signed SCPID response against the original challenge (§3.11.4).
    ///
    /// Resolves the signer's DID document via the production DID resolver on
    /// this instance (initialized during `identity_create`), then runs the
    /// 11-step verification pipeline from `scp-core`. Returns the
    /// `ScpIdAuthentication` result as a JSON string on success.
    ///
    /// # Arguments
    ///
    /// * `response_json` — JSON string of the signed response (from `scpid_sign`).
    /// * `challenge_json` — JSON string of the original challenge (from `scpid_challenge`).
    ///
    /// # Errors
    ///
    /// Raises `IdentityError` if the DID resolver is not initialized (no identity
    /// created yet).
    /// Raises `ValidationError` if either JSON string is malformed.
    /// Raises `IdentityError` if DID resolution fails, the signature is invalid,
    /// the challenge has expired, or any other verification step fails.
    pub fn scpid_verify(
        &self,
        py: Python<'_>,
        response_json: String,
        challenge_json: String,
    ) -> PyResult<String> {
        let bi = &*self.inner;
        let response: ScpIdResponse =
            serde_json::from_str(&response_json).map_err(|e| ScpPyError::ValidationError {
                message: format!("invalid response JSON: {e}"),
                code: codes::IDENT_1038.to_string(),
            })?;

        let challenge: ScpIdChallenge =
            serde_json::from_str(&challenge_json).map_err(|e| ScpPyError::ValidationError {
                message: format!("invalid challenge JSON: {e}"),
                code: codes::IDENT_1038.to_string(),
            })?;

        let rt = crate::runtime()?;

        py.allow_threads(|| {
            let resolver =
                crate::runtime::did_resolver(bi).ok_or_else(|| ScpPyError::IdentityError {
                    message: "DID resolver not initialized — create an identity with \
                              identity_create before calling scpid_verify"
                        .to_string(),
                    code: codes::IDENT_1033.to_string(),
                })?;

            let auth = rt
                .block_on(scpid_verify(resolver.as_ref(), &response, &challenge))
                .map_err(|e| ScpPyError::IdentityError {
                    message: e.to_string(),
                    code: scpid_error_code(&e).to_string(),
                })?;

            serde_json::to_string(&auth).map_err(|e| {
                ScpPyError::IdentityError {
                    message: format!("failed to serialize SCPID authentication: {e}"),
                    code: codes::IDENT_1037.to_string(),
                }
                .into()
            })
        })
    }
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
            code: codes::IDENT_1034.to_string(),
        }
        .into()),
    }
}

/// Maps an [`ScpIdError`] variant to its canonical SCP error code.
const fn scpid_error_code(e: &scp_core::identity::ScpIdError) -> &'static str {
    use scp_core::identity::ScpIdError;
    match e {
        ScpIdError::ChallengeExpired => codes::IDENT_1030,
        ScpIdError::AudienceMismatch => codes::IDENT_1031,
        ScpIdError::TimestampInvalid => codes::IDENT_1032,
        ScpIdError::DidResolutionFailed(_) => codes::IDENT_1033,
        ScpIdError::KeyNotAuthorized => codes::IDENT_1034,
        ScpIdError::SignatureInvalid => codes::IDENT_1035,
        ScpIdError::DidDocumentStale => codes::IDENT_1036,
        ScpIdError::SigningFailed(_) => codes::IDENT_1037,
        ScpIdError::InvalidInput(_) => codes::IDENT_1038,
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers SCPID bridge helpers on the `_scp_core` module.
///
/// Post-migration (Phase 4 PR 4 sub-slice C) SCPID operations are exposed
/// as methods on `SCP` (see the `#[pymethods]` block above) and registered
/// automatically with the class. This function is retained to preserve the
/// module-init call sequence; it is currently a no-op.
///
/// # Errors
///
/// Returns `PyErr` if registration fails.
pub const fn register_scpid(_m: &Bound<'_, PyModule>) -> PyResult<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use scp_ffi_common::error_codes as codes;
    use std::sync::Arc;

    use scp_identity::resolver::DualLayerResolver;
    use scp_identity::{DidCache, InMemoryDhtClient, NoOpRelayQuerier};

    fn default_scp() -> crate::scp::PyScp {
        crate::scp::PyScp::new()
    }

    #[test]
    fn challenge_returns_valid_json() {
        pyo3::prepare_freethreaded_python();
        let scp = default_scp();
        let json = scp
            .scpid_challenge("https://example.com".to_owned(), 60)
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["protocol"], "scpid/1.0");
        assert_eq!(v["audience"], "https://example.com");
        assert!(v["nonce"].is_string());
        assert!(v["issued_at"].is_u64());
        assert!(v["expires_at"].is_u64());
    }

    #[test]
    fn challenge_rejects_zero_ttl() {
        pyo3::prepare_freethreaded_python();
        let scp = default_scp();
        let result = scp.scpid_challenge("https://example.com".to_owned(), 0);
        assert!(result.is_err());
    }

    #[test]
    fn challenge_rejects_excessive_ttl() {
        pyo3::prepare_freethreaded_python();
        let scp = default_scp();
        let result = scp.scpid_challenge("https://example.com".to_owned(), 301);
        assert!(result.is_err());
    }

    #[test]
    fn challenge_rejects_empty_audience() {
        pyo3::prepare_freethreaded_python();
        let scp = default_scp();
        let result = scp.scpid_challenge(String::new(), 60);
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

    #[test]
    fn scpid_error_code_maps_all_variants() {
        use scp_core::identity::ScpIdError;

        assert_eq!(
            scpid_error_code(&ScpIdError::ChallengeExpired),
            codes::IDENT_1030
        );
        assert_eq!(
            scpid_error_code(&ScpIdError::AudienceMismatch),
            codes::IDENT_1031
        );
        assert_eq!(
            scpid_error_code(&ScpIdError::TimestampInvalid),
            codes::IDENT_1032
        );
        assert_eq!(
            scpid_error_code(&ScpIdError::DidResolutionFailed("test".to_owned())),
            codes::IDENT_1033
        );
        assert_eq!(
            scpid_error_code(&ScpIdError::KeyNotAuthorized),
            codes::IDENT_1034
        );
        assert_eq!(
            scpid_error_code(&ScpIdError::SignatureInvalid),
            codes::IDENT_1035
        );
        assert_eq!(
            scpid_error_code(&ScpIdError::DidDocumentStale),
            codes::IDENT_1036
        );
        assert_eq!(
            scpid_error_code(&ScpIdError::SigningFailed("test".to_owned())),
            codes::IDENT_1037
        );
        assert_eq!(
            scpid_error_code(&ScpIdError::InvalidInput("test".to_owned())),
            codes::IDENT_1038
        );
    }

    /// Sign→verify roundtrip using the `IdentityBackedDidResolver` (the same
    /// type used by the bridge function). Proves that the resolver impl
    /// added for SCPID verification correctly delegates to the underlying
    /// async resolve function.
    #[tokio::test]
    async fn sign_verify_roundtrip_via_identity_backed_resolver() {
        use scp_identity::DidMethod;

        let dht_client = Arc::new(InMemoryDhtClient::new());
        let custody = Arc::new(scp_platform::testing::InMemoryKeyCustody::new());

        // Create a DidDht with a signer so we can publish the DID document.
        let sign_fn = scp_identity::DidDht::<InMemoryDhtClient, scp_identity::cache::SystemClock>::make_sign_fn(Arc::clone(&custody));
        let dht = scp_identity::DidDht::with_client_and_signer(
            Arc::clone(&dht_client),
            Arc::new(DidCache::new()),
            sign_fn,
        );
        let (identity, doc) = dht.create(custody.as_ref()).await.unwrap();

        // Publish the document to the shared DHT so the resolver can find it.
        dht.publish(&identity, &doc).await.unwrap();

        // Challenge.
        let challenge =
            scp_core::identity::scpid_challenge("https://example.com", Duration::from_mins(2))
                .unwrap();

        // Sign.
        let response = scp_core::identity::scpid_sign(
            custody.as_ref(),
            &identity.active_signing_key,
            &identity.did,
            SigningKeyId::Active,
            &challenge,
            None,
        )
        .await
        .unwrap();

        // Verify using IdentityBackedDidResolver — the same type the bridge
        // function uses via the BridgeInstance DID resolver. This validates that the
        // `scp_identity::resolver::DidResolver` impl on
        // `IdentityBackedDidResolver` works end-to-end.
        let dual = DualLayerResolver::new(
            Arc::new(NoOpRelayQuerier),
            dht_client,
            Arc::new(DidCache::new()),
            Vec::new(),
        );
        let resolver = scp_ffi_common::IdentityBackedDidResolver::new(
            Arc::new(dual),
            tokio::runtime::Handle::current(),
        );
        let auth = scpid_verify(&resolver, &response, &challenge)
            .await
            .unwrap();

        assert_eq!(auth.did, identity.did);
        assert_eq!(auth.signing_key_id, SigningKeyId::Active);
    }

    /// Exercises the bridge `scpid_verify` error path with malformed JSON.
    /// The bridge function cannot be called with valid data in unit tests
    /// (requires `PyO3` GIL + `BridgeInstance` DID resolver initialization),
    /// but we can verify it returns the correct error code for invalid input.
    #[test]
    fn scpid_verify_rejects_malformed_response_json() {
        pyo3::prepare_freethreaded_python();
        let result = Python::with_gil(|py| {
            let scp = default_scp();
            scp.scpid_verify(py, "not valid json".to_owned(), "{}".to_owned())
        });
        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains(codes::IDENT_1038),
            "expected SCP-IDENT-1038 in error, got: {err_str}"
        );
    }

    /// Exercises the bridge `scpid_verify` error path with malformed
    /// challenge JSON (valid response JSON, invalid challenge).
    #[test]
    fn scpid_verify_rejects_malformed_challenge_json() {
        pyo3::prepare_freethreaded_python();
        // Provide valid ScpIdResponse JSON structure but invalid challenge.
        let response_json = serde_json::json!({
            "protocol": "scpid/1.0",
            "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "audience": "https://example.com",
            "did": "did:dht:ztest",
            "signing_key_id": "Active",
            "signature": "AAAA",
            "issued_at": 1_000_000_000_u64,
            "expires_at": 2_000_000_000_u64,
        });
        let result = Python::with_gil(|py| {
            let scp = default_scp();
            scp.scpid_verify(
                py,
                serde_json::to_string(&response_json).unwrap(),
                "not valid json".to_owned(),
            )
        });
        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains(codes::IDENT_1038),
            "expected SCP-IDENT-1038 in error, got: {err_str}"
        );
    }
}
