//! WASM bridge for SCPID authentication (§3.11).
//!
//! Uses pure types from `scp_protocol::identity::scpid` and the canonical hash
//! from `scp_protocol::crypto::canonical` — no local reimplementations needed.
//! Only the WASM-specific bridge glue (`#[wasm_bindgen]` functions, JS error
//! mapping, WASM time/CSPRNG) remains local.
//!
//! - `scpid_challenge` — Generate an SCPID challenge for a relying party.
//! - `scpid_sign` — Sign an SCPID challenge with a registered identity's key.
//!
//! **`scpid_verify` is NOT exposed in the WASM bridge.** Verification requires
//! a network-capable `DidResolver` to resolve the signer's DID document from
//! the DHT. The WASM environment cannot perform direct DHT queries (no raw UDP
//! sockets), and the tokio multi-thread runtime required by `DualLayerResolver`
//! is unavailable per ADR-034. Verification should be performed server-side
//! via the PyO3 or NAPI bridges, or in a native mobile app via the UniFFI
//! bridge.
//!
//! See spec §3.11 and the `scp-runtime` `scpid` module for the canonical
//! async implementation.

use scp_ffi_common::error_codes as codes;
use scp_protocol::crypto::canonical::{CanonicalField, canonical_hash};
use scp_protocol::identity::SigningKeyId;
use scp_protocol::identity::scpid::{
    SCPID_DOMAIN_SEPARATOR, SCPID_PROTOCOL_VERSION, ScpIdChallenge, ScpIdResponse,
};
use wasm_bindgen::prelude::*;

use crate::error::ScpWasmError;

/// Maximum TTL in milliseconds (300 seconds per §3.11.2).
const MAX_TTL_MS: u64 = 300_000;

/// Maximum audience string length in bytes.
const MAX_AUDIENCE_BYTES: usize = 2048;

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Generates an SCPID challenge for the given audience (§3.11.8).
///
/// Returns the challenge as a JSON string. The nonce is a 32-byte CSPRNG
/// value encoded as 64 lowercase hex characters.
///
/// # Errors
///
/// Returns `JsError` if `audience` is empty, exceeds 2048 bytes,
/// `ttl_seconds` is 0 or exceeds 300, or CSPRNG fails.
///
/// # JS usage
///
/// ```js
/// const challengeJson = scpid_challenge("https://app.example.com", 120);
/// ```
#[wasm_bindgen]
// ttl_seconds is u32 — idiomatic for WASM platforms (max valid TTL is 300s).
// PyO3/UniFFI bridges use u64 to match `Duration::from_secs` parameter type.
pub fn scpid_challenge(audience: String, ttl_seconds: u32) -> Result<String, JsError> {
    let ttl_ms = u64::from(ttl_seconds) * 1000;

    if ttl_ms == 0 {
        return Err(ScpWasmError::Validation {
            message: "TTL must be greater than zero".to_owned(),
            code: codes::IDENT_1038.to_owned(),
        }
        .into_js());
    }

    if ttl_ms > MAX_TTL_MS {
        return Err(ScpWasmError::Validation {
            message: "TTL exceeds 300 seconds".to_owned(),
            code: codes::IDENT_1038.to_owned(),
        }
        .into_js());
    }

    if audience.is_empty() {
        return Err(ScpWasmError::Validation {
            message: "audience must not be empty".to_owned(),
            code: codes::IDENT_1038.to_owned(),
        }
        .into_js());
    }

    if audience.len() > MAX_AUDIENCE_BYTES {
        return Err(ScpWasmError::Validation {
            message: "audience exceeds 2048 bytes".to_owned(),
            code: codes::IDENT_1038.to_owned(),
        }
        .into_js());
    }

    // Generate 32-byte CSPRNG nonce.
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).map_err(|e| {
        ScpWasmError::Identity {
            message: format!("CSPRNG failure: {e}"),
            code: codes::IDENT_1037.to_owned(),
        }
        .into_js()
    })?;

    let now_ms = crate::time::now_ms_u64();
    let expires_at = now_ms + ttl_ms;

    let challenge = ScpIdChallenge {
        protocol: SCPID_PROTOCOL_VERSION.to_owned(),
        nonce,
        audience,
        issued_at: now_ms,
        expires_at,
    };

    serde_json::to_string(&challenge).map_err(|e| {
        ScpWasmError::Identity {
            message: format!("failed to serialize SCPID challenge: {e}"),
            code: codes::IDENT_1037.to_owned(),
        }
        .into_js()
    })
}

/// Signs an SCPID challenge with a registered identity's key (§3.11.3).
///
/// Looks up the identity by DID in the WASM-local identity registry,
/// selects the appropriate signing key (`#active` or `#agent`), computes
/// the canonical hash per §3.11.3, signs it with Ed25519, and returns
/// the SCPID response as a JSON string.
///
/// # Errors
///
/// Returns `JsError` if `signing_key_id` is invalid, the challenge JSON
/// is malformed, the challenge has expired, the DID is not registered,
/// or the signing operation fails.
///
/// # JS usage
///
/// ```js
/// const responseJson = scpid_sign(did, "#active", challengeJson);
/// ```
#[wasm_bindgen]
pub fn scpid_sign(
    did: String,
    signing_key_id: String,
    challenge_json: String,
) -> Result<String, JsError> {
    // Validate signing_key_id.
    let (key_fragment, key_id) = match signing_key_id.as_str() {
        "#active" => ("#active", SigningKeyId::Active),
        "#agent" => ("#agent", SigningKeyId::Agent),
        other => {
            return Err(ScpWasmError::Validation {
                message: format!(
                    "invalid signing_key_id '{other}': expected '#active' or '#agent'"
                ),
                code: codes::IDENT_1034.to_owned(),
            }
            .into_js());
        }
    };

    // Parse the challenge JSON (scp-protocol types handle hex serde automatically).
    let challenge: ScpIdChallenge = serde_json::from_str(&challenge_json).map_err(|e| {
        ScpWasmError::Validation {
            message: format!("invalid challenge JSON: {e}"),
            code: codes::IDENT_1038.to_owned(),
        }
        .into_js()
    })?;

    // Validate protocol.
    if challenge.protocol != SCPID_PROTOCOL_VERSION {
        return Err(ScpWasmError::Validation {
            message: format!(
                "unsupported protocol: {}, expected {SCPID_PROTOCOL_VERSION}",
                challenge.protocol
            ),
            code: codes::IDENT_1038.to_owned(),
        }
        .into_js());
    }

    // Check challenge expiry.
    let now_ms = crate::time::now_ms_u64();
    if now_ms > challenge.expires_at {
        return Err(ScpWasmError::Identity {
            message: "challenge expired".to_owned(),
            code: codes::IDENT_1030.to_owned(),
        }
        .into_js());
    }

    // Validate DID is not empty.
    if did.is_empty() {
        return Err(ScpWasmError::Validation {
            message: "DID must not be empty".to_owned(),
            code: codes::IDENT_1038.to_owned(),
        }
        .into_js());
    }

    let signed_at = now_ms;

    // Build canonical hash (§3.11.3) using scp-protocol's canonical_hash.
    let hash = canonical_hash(
        SCPID_DOMAIN_SEPARATOR,
        &[
            CanonicalField::VarBytes(did.as_bytes()),
            CanonicalField::VarBytes(key_fragment.as_bytes()),
            CanonicalField::Fixed32(&challenge.nonce),
            CanonicalField::VarBytes(challenge.audience.as_bytes()),
            CanonicalField::U64(signed_at),
        ],
    )
    .map_err(|e| {
        ScpWasmError::Identity {
            message: format!("canonical hash failed: {e}"),
            code: codes::IDENT_1037.to_owned(),
        }
        .into_js()
    })?;

    // Sign the canonical hash via the identity helper.
    let signature = crate::identity::sign_with_identity(&did, key_fragment, &hash)
        .map_err(ScpWasmError::into_js)?;

    let response = ScpIdResponse {
        protocol: SCPID_PROTOCOL_VERSION.to_owned(),
        did,
        signing_key_id: key_id,
        nonce: challenge.nonce,
        audience: challenge.audience,
        signed_at,
        signature,
    };

    serde_json::to_string(&response).map_err(|e| {
        ScpWasmError::Identity {
            message: format!("failed to serialize SCPID response: {e}"),
            code: codes::IDENT_1037.to_owned(),
        }
        .into_js()
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn canonical_hash_golden_vector() {
        // Must match the golden vector in scp-runtime/src/identity/scpid.rs.
        let hash = canonical_hash(
            SCPID_DOMAIN_SEPARATOR,
            &[
                CanonicalField::VarBytes(b"did:dht:z6MkTest"),
                CanonicalField::VarBytes(b"#active"),
                CanonicalField::Fixed32(&[0xAAu8; 32]),
                CanonicalField::VarBytes(b"https://example.com"),
                CanonicalField::U64(1_709_654_400_000),
            ],
        )
        .unwrap();
        assert_eq!(
            hex::encode(hash),
            "7552b8e3b0e1654593e956c1429d479eda0524bc6cdc863b142d5909471b57e0"
        );
    }

    #[test]
    fn challenge_rejects_zero_ttl() {
        // Validate via parse, not wasm-bindgen (no JS runtime in tests).
        assert!(validate_ttl(0).is_err());
    }

    #[test]
    fn challenge_rejects_excessive_ttl() {
        assert!(validate_ttl(301).is_err());
    }

    #[test]
    fn challenge_rejects_empty_audience() {
        assert!(validate_audience("").is_err());
    }

    #[test]
    fn challenge_accepts_valid_inputs() {
        assert!(validate_ttl(60).is_ok());
        assert!(validate_ttl(300).is_ok());
        assert!(validate_audience("https://example.com").is_ok());
    }

    #[test]
    fn parse_signing_key_id_valid() {
        assert!(matches!(validate_signing_key_id("#active"), Ok(())));
        assert!(matches!(validate_signing_key_id("#agent"), Ok(())));
    }

    #[test]
    fn parse_signing_key_id_invalid() {
        assert!(validate_signing_key_id("active").is_err());
        assert!(validate_signing_key_id("#owner").is_err());
        assert!(validate_signing_key_id("").is_err());
    }

    // Internal validation helpers for testing without wasm-bindgen runtime.
    fn validate_ttl(ttl_seconds: u32) -> Result<(), String> {
        let ttl_ms = u64::from(ttl_seconds) * 1000;
        if ttl_ms == 0 {
            return Err("TTL must be greater than zero".to_owned());
        }
        if ttl_ms > MAX_TTL_MS {
            return Err("TTL exceeds 300 seconds".to_owned());
        }
        Ok(())
    }

    fn validate_audience(audience: &str) -> Result<(), String> {
        if audience.is_empty() {
            return Err("audience must not be empty".to_owned());
        }
        if audience.len() > MAX_AUDIENCE_BYTES {
            return Err("audience exceeds 2048 bytes".to_owned());
        }
        Ok(())
    }

    fn validate_signing_key_id(s: &str) -> Result<(), String> {
        match s {
            "#active" | "#agent" => Ok(()),
            other => Err(format!("invalid signing_key_id '{other}'")),
        }
    }
}
