//! napi-rs bridge for SCPID authentication (§3.11).
//!
//! Exposes SCPID challenge generation and signing to Node.js/Bun:
//!
//! - [`scpid_challenge`] — Generate an SCPID challenge for a relying party.
//! - [`scpid_sign`] — Sign an SCPID challenge with a registered identity's key.
//!
//! See spec §3.11 and the `scp-core` `scpid` module.

use std::time::Duration;

use napi_derive::napi;

use scp_core::identity::{
    ScpIdChallenge, scpid_challenge as core_challenge, scpid_sign as core_sign,
};
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
            code: "SCP-IDENT-1038".to_owned(),
        })?;

    serde_json::to_string(&challenge).map_err(|e| {
        napi::Error::from(ScpNapiError::Identity {
            message: format!("failed to serialize SCPID challenge: {e}"),
            code: "SCP-IDENT-1037".to_owned(),
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
            code: "SCP-IDENT-1038".to_owned(),
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
                        code: "SCP-IDENT-1034".to_owned(),
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
            code: "SCP-IDENT-1037".to_owned(),
        })?;

        serde_json::to_string(&response).map_err(|e| ScpNapiError::Identity {
            message: format!("failed to serialize SCPID response: {e}"),
            code: "SCP-IDENT-1037".to_owned(),
        })
    })?)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parses a signing key ID string (`"#active"` or `"#agent"`) into a
/// [`SigningKeyId`] enum.
fn parse_signing_key_id(s: &str) -> napi::Result<SigningKeyId> {
    match s {
        "#active" => Ok(SigningKeyId::Active),
        "#agent" => Ok(SigningKeyId::Agent),
        other => Err(napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid signing_key_id '{other}': expected '#active' or '#agent'"),
            code: "SCP-IDENT-1034".to_owned(),
        })),
    }
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
