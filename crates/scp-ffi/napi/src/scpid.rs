//! napi-rs bridge for SCPID authentication (§3.11).
//!
//! Exposes SCPID challenge generation, signing, and verification to Node.js/Bun:
//!
//! - `scpid_challenge` — Generate an SCPID challenge for a relying party.
//! - `scpid_sign` — Sign an SCPID challenge with a registered identity's key.
//! - [`scpid_verify`] — Verify a signed SCPID response (relying-party side).
//!
//! See spec §3.11 and the `scp-core` `scpid` module.

use scp_ffi_common::error_codes as codes;
use std::time::Duration;

use napi_derive::napi;

#[cfg(feature = "allow_in_memory_custody")]
use scp_core::identity::scpid_sign as core_sign;
use scp_core::identity::{
    ScpIdChallenge, ScpIdResponse, scpid_challenge as core_challenge, scpid_verify as core_verify,
};
#[cfg(feature = "allow_in_memory_custody")]
use scp_identity::SigningKeyId;

use crate::error::ScpNapiError;

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Generates an SCPID challenge for the given audience (§3.11.8).
///
/// Returns the challenge as a JSON string containing `protocol`, `nonce`,
/// `audience`, `issued_at`, and `expires_at` fields.
///
/// # JS usage
///
/// ```js
/// const challengeJson = scpidChallenge("https://app.example.com", 120);
/// ```
#[napi]
// ttl_seconds is u32 — idiomatic for JS platforms (max valid TTL is 300s).
// PyO3/UniFFI bridges use u64 to match `Duration::from_secs` parameter type.
pub fn scpid_challenge(audience: String, ttl_seconds: u32) -> napi::Result<String> {
    let challenge = core_challenge(&audience, Duration::from_secs(u64::from(ttl_seconds)))
        .map_err(|e| ScpNapiError::Validation {
            message: e.to_string(),
            code: codes::IDENT_1038.to_owned(),
        })?;

    serde_json::to_string(&challenge).map_err(|e| {
        napi::Error::from(ScpNapiError::Identity {
            message: format!("failed to serialize SCPID challenge: {e}"),
            code: codes::IDENT_1037.to_owned(),
        })
    })
}

/// Signs an SCPID challenge with a registered identity's key (§3.11.3).
///
/// Looks up the identity by DID in the global registry, selects the
/// appropriate signing key (`#active` or `#agent`), and produces a signed
/// SCPID response as a JSON string.
///
/// # JS usage
///
/// ```js
/// const responseJson = await scpidSign(did, "#active", challengeJson);
/// ```
#[napi]
#[cfg(feature = "allow_in_memory_custody")]
pub fn scpid_sign(
    did: String,
    signing_key_id: String,
    challenge_json: String,
) -> napi::Result<String> {
    let key_id = parse_signing_key_id(&signing_key_id)?;

    let challenge: ScpIdChallenge =
        serde_json::from_str(&challenge_json).map_err(|e| ScpNapiError::Validation {
            message: format!("invalid challenge JSON: {e}"),
            code: codes::IDENT_1038.to_owned(),
        })?;

    Ok(crate::runtime::with_identity(&did, |entry| {
        let key_handle = match key_id {
            SigningKeyId::Active => entry.identity.active_signing_key,
            SigningKeyId::Agent => {
                entry
                    .identity
                    .agent_signing_key
                    .ok_or_else(|| ScpNapiError::Identity {
                        message: format!(
                            "identity '{did}' has no agent signing key — \
                         create one with identityAddAgentKey first"
                        ),
                        code: codes::IDENT_1034.to_owned(),
                    })?
            }
        };

        let rt = crate::runtime();
        let response = rt.block_on(core_sign(
            &entry.custody.0,
            &key_handle,
            &did,
            key_id,
            &challenge,
        ));

        let response = response.map_err(|e| ScpNapiError::Identity {
            message: e.to_string(),
            code: codes::IDENT_1037.to_owned(),
        })?;

        serde_json::to_string(&response).map_err(|e| ScpNapiError::Identity {
            message: format!("failed to serialize SCPID response: {e}"),
            code: codes::IDENT_1037.to_owned(),
        })
    })?)
}

/// Verifies a signed SCPID response against the original challenge (§3.11.4).
///
/// Resolves the signer's DID document via the global production DID resolver
/// (initialized during `identityCreate`), then runs the 11-step verification
/// pipeline from `scp-core`. Returns the `ScpIdAuthentication` result as a
/// JSON string on success.
///
/// # JS usage
///
/// ```js
/// const authJson = scpidVerify(responseJson, challengeJson);
/// ```
#[napi]
pub fn scpid_verify(response_json: String, challenge_json: String) -> napi::Result<String> {
    let response: ScpIdResponse =
        serde_json::from_str(&response_json).map_err(|e| ScpNapiError::Validation {
            message: format!("invalid response JSON: {e}"),
            code: codes::IDENT_1038.to_owned(),
        })?;

    let challenge: ScpIdChallenge =
        serde_json::from_str(&challenge_json).map_err(|e| ScpNapiError::Validation {
            message: format!("invalid challenge JSON: {e}"),
            code: codes::IDENT_1038.to_owned(),
        })?;

    let resolver = crate::runtime::did_resolver().ok_or_else(|| ScpNapiError::Identity {
        message: "DID resolver not initialized — create an identity with \
                      identityCreate before calling scpidVerify"
            .to_owned(),
        code: codes::IDENT_1033.to_owned(),
    })?;

    let rt = crate::runtime();
    let auth = rt
        .block_on(core_verify(resolver.as_ref(), &response, &challenge))
        .map_err(|e| ScpNapiError::Identity {
            message: e.to_string(),
            code: scpid_error_code(&e).to_owned(),
        })?;

    serde_json::to_string(&auth).map_err(|e| {
        napi::Error::from(ScpNapiError::Identity {
            message: format!("failed to serialize SCPID authentication: {e}"),
            code: codes::IDENT_1037.to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parses a signing key ID string (`"#active"` or `"#agent"`) into a
/// [`SigningKeyId`] enum.
#[cfg(feature = "allow_in_memory_custody")]
fn parse_signing_key_id(s: &str) -> napi::Result<SigningKeyId> {
    match s {
        "#active" => Ok(SigningKeyId::Active),
        "#agent" => Ok(SigningKeyId::Agent),
        other => Err(napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid signing_key_id '{other}': expected '#active' or '#agent'"),
            code: codes::IDENT_1034.to_owned(),
        })),
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

    #[test]
    fn challenge_returns_valid_json() {
        let json = scpid_challenge("https://example.com".to_owned(), 60).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["protocol"], "scpid/1.0");
        assert_eq!(v["audience"], "https://example.com");
        assert!(v["nonce"].is_string());
        assert!(v["issued_at"].is_u64());
        assert!(v["expires_at"].is_u64());
    }

    #[test]
    fn challenge_rejects_zero_ttl() {
        let result = scpid_challenge("https://example.com".to_owned(), 0);
        assert!(result.is_err());
    }

    #[test]
    fn challenge_rejects_excessive_ttl() {
        let result = scpid_challenge("https://example.com".to_owned(), 301);
        assert!(result.is_err());
    }

    #[test]
    fn challenge_rejects_empty_audience() {
        let result = scpid_challenge(String::new(), 60);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "allow_in_memory_custody")]
    fn parse_signing_key_id_valid() {
        assert_eq!(
            parse_signing_key_id("#active").unwrap(),
            SigningKeyId::Active
        );
        assert_eq!(parse_signing_key_id("#agent").unwrap(), SigningKeyId::Agent);
    }

    #[test]
    #[cfg(feature = "allow_in_memory_custody")]
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

    /// Bridge `scpid_verify` rejects malformed response JSON with the
    /// correct error code before attempting DID resolution.
    #[test]
    fn scpid_verify_rejects_malformed_response_json() {
        let result = scpid_verify("not valid json".to_owned(), "{}".to_owned());
        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains(codes::IDENT_1038),
            "expected SCP-IDENT-1038, got: {err_str}"
        );
    }

    /// Bridge `scpid_verify` rejects malformed challenge JSON with the
    /// correct error code (response JSON parses, challenge does not).
    #[test]
    fn scpid_verify_rejects_malformed_challenge_json() {
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
        let result = scpid_verify(
            serde_json::to_string(&response_json).unwrap(),
            "not valid json".to_owned(),
        );
        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains(codes::IDENT_1038),
            "expected SCP-IDENT-1038, got: {err_str}"
        );
    }

    /// Sign→verify roundtrip using the `IdentityBackedDidResolver` (the same
    /// type used by the bridge function). Proves that the resolver impl
    /// works end-to-end for SCPID verification.
    #[tokio::test]
    #[cfg(feature = "allow_in_memory_custody")]
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
            scp_core::identity::scpid_challenge("https://example.com", Duration::from_secs(120))
                .unwrap();

        // Sign.
        let response = scp_core::identity::scpid_sign(
            custody.as_ref(),
            &identity.active_signing_key,
            &identity.did,
            SigningKeyId::Active,
            &challenge,
        )
        .await
        .unwrap();

        // Verify using IdentityBackedDidResolver — the same type the bridge
        // function uses via the global DID_RESOLVER.
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
        let auth = core_verify(&resolver, &response, &challenge).await.unwrap();

        assert_eq!(auth.did, identity.did);
        assert_eq!(auth.signing_key_id, SigningKeyId::Active);
    }
}
