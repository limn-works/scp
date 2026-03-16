//! WASM bridge for SCPID authentication (§3.11).
//!
//! Re-implements SCPID challenge generation and signing locally because the
//! WASM bridge cannot depend on `scp-core` (tokio multi-thread requirement,
//! see ADR-034). The algorithms are pure crypto (SHA-256, Ed25519) with no
//! network I/O, so they translate directly to WASM.
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
//! See spec §3.11 and the `scp-core` `scpid` module for the canonical
//! implementation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

use crate::error::ScpWasmError;

// ---------------------------------------------------------------------------
// Constants (must match scp-core/src/identity/scpid.rs)
// ---------------------------------------------------------------------------

/// Protocol version string for SCPID (§3.11.2).
const SCPID_PROTOCOL_VERSION: &str = "scpid/1.0";

/// Domain separator for SCPID signed content (§3.11.3, §9.18.2).
const SCPID_DOMAIN_SEPARATOR: &str = "SCP-DID-AUTH-V1:";

/// Maximum TTL in milliseconds (300 seconds per §3.11.2).
const MAX_TTL_MS: u64 = 300_000;

/// Maximum audience string length in bytes.
const MAX_AUDIENCE_BYTES: usize = 2048;

// ---------------------------------------------------------------------------
// Wire types (mirror scp-core but without scp-core dependency)
// ---------------------------------------------------------------------------

/// SCPID challenge — local mirror of `scp_core::identity::ScpIdChallenge`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScpIdChallenge {
    protocol: String,
    nonce: String, // hex-encoded on wire
    audience: String,
    issued_at: u64,
    expires_at: u64,
}

/// SCPID response — local mirror of `scp_core::identity::ScpIdResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScpIdResponse {
    protocol: String,
    did: String,
    signing_key_id: String,
    nonce: String, // hex-encoded on wire
    audience: String,
    signed_at: u64,
    signature: String, // hex-encoded on wire
}

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
            code: "SCP-IDENT-1038".to_owned(),
        }
        .into_js());
    }

    if ttl_ms > MAX_TTL_MS {
        return Err(ScpWasmError::Validation {
            message: "TTL exceeds 300 seconds".to_owned(),
            code: "SCP-IDENT-1038".to_owned(),
        }
        .into_js());
    }

    if audience.is_empty() {
        return Err(ScpWasmError::Validation {
            message: "audience must not be empty".to_owned(),
            code: "SCP-IDENT-1038".to_owned(),
        }
        .into_js());
    }

    if audience.len() > MAX_AUDIENCE_BYTES {
        return Err(ScpWasmError::Validation {
            message: "audience exceeds 2048 bytes".to_owned(),
            code: "SCP-IDENT-1038".to_owned(),
        }
        .into_js());
    }

    // Generate 32-byte CSPRNG nonce.
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).map_err(|e| {
        ScpWasmError::Identity {
            message: format!("CSPRNG failure: {e}"),
            code: "SCP-IDENT-1037".to_owned(),
        }
        .into_js()
    })?;

    let now_ms = crate::time::now_ms_u64();
    let expires_at = now_ms + ttl_ms;

    let challenge = ScpIdChallenge {
        protocol: SCPID_PROTOCOL_VERSION.to_owned(),
        nonce: hex::encode(nonce),
        audience,
        issued_at: now_ms,
        expires_at,
    };

    serde_json::to_string(&challenge).map_err(|e| {
        ScpWasmError::Identity {
            message: format!("failed to serialize SCPID challenge: {e}"),
            code: "SCP-IDENT-1037".to_owned(),
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
    let key_fragment = match signing_key_id.as_str() {
        "#active" | "#agent" => signing_key_id.as_str(),
        other => {
            return Err(ScpWasmError::Validation {
                message: format!(
                    "invalid signing_key_id '{other}': expected '#active' or '#agent'"
                ),
                code: "SCP-IDENT-1034".to_owned(),
            }
            .into_js());
        }
    };

    // Parse the challenge JSON.
    let challenge: ScpIdChallenge = serde_json::from_str(&challenge_json).map_err(|e| {
        ScpWasmError::Validation {
            message: format!("invalid challenge JSON: {e}"),
            code: "SCP-IDENT-1038".to_owned(),
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
            code: "SCP-IDENT-1038".to_owned(),
        }
        .into_js());
    }

    // Parse the nonce from hex.
    let nonce_bytes: [u8; 32] = hex::decode(&challenge.nonce)
        .map_err(|e| {
            ScpWasmError::Validation {
                message: format!("invalid nonce hex: {e}"),
                code: "SCP-IDENT-1038".to_owned(),
            }
            .into_js()
        })?
        .try_into()
        .map_err(|_| {
            ScpWasmError::Validation {
                message: "nonce must be exactly 32 bytes (64 hex chars)".to_owned(),
                code: "SCP-IDENT-1038".to_owned(),
            }
            .into_js()
        })?;

    // Check challenge expiry.
    let now_ms = crate::time::now_ms_u64();
    if now_ms > challenge.expires_at {
        return Err(ScpWasmError::Identity {
            message: "challenge expired".to_owned(),
            code: "SCP-IDENT-1030".to_owned(),
        }
        .into_js());
    }

    // Validate DID is not empty.
    if did.is_empty() {
        return Err(ScpWasmError::Validation {
            message: "DID must not be empty".to_owned(),
            code: "SCP-IDENT-1038".to_owned(),
        }
        .into_js());
    }

    let signed_at = now_ms;

    // Build canonical hash (§3.11.3):
    //   SHA-256(
    //       "SCP-DID-AUTH-V1:"
    //       || BE32(len(did))           || did
    //       || BE32(len(signing_key_id)) || signing_key_id
    //       || nonce (32 bytes raw)
    //       || BE32(len(audience))       || audience
    //       || signed_at as u64 BE
    //   )
    let hash = scpid_canonical_hash(
        &did,
        key_fragment,
        &nonce_bytes,
        &challenge.audience,
        signed_at,
    );

    // Sign the canonical hash via the identity helper.
    let signature_bytes = crate::identity::sign_with_identity(&did, key_fragment, &hash)
        .map_err(ScpWasmError::into_js)?;

    let response = ScpIdResponse {
        protocol: SCPID_PROTOCOL_VERSION.to_owned(),
        did,
        signing_key_id: key_fragment.to_owned(),
        nonce: challenge.nonce,
        audience: challenge.audience,
        signed_at,
        signature: hex::encode(signature_bytes),
    };

    serde_json::to_string(&response).map_err(|e| {
        ScpWasmError::Identity {
            message: format!("failed to serialize SCPID response: {e}"),
            code: "SCP-IDENT-1037".to_owned(),
        }
        .into_js()
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Computes the canonical hash for SCPID signing per §3.11.3.
///
/// This is a WASM-local reimplementation of `scp_core::crypto::canonical::canonical_hash`
/// with the SCPID-specific field ordering. Must produce identical output to the
/// `scp-core` implementation for cross-bridge interoperability.
#[allow(clippy::cast_possible_truncation)] // VarBytes uses u32 length prefix; all inputs are bounded
fn scpid_canonical_hash(
    did: &str,
    signing_key_id: &str,
    nonce: &[u8; 32],
    audience: &str,
    signed_at: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Domain separator.
    hasher.update(SCPID_DOMAIN_SEPARATOR.as_bytes());

    // VarBytes(did).
    hasher.update((did.len() as u32).to_be_bytes());
    hasher.update(did.as_bytes());

    // VarBytes(signing_key_id).
    hasher.update((signing_key_id.len() as u32).to_be_bytes());
    hasher.update(signing_key_id.as_bytes());

    // Fixed32(nonce).
    hasher.update(nonce);

    // VarBytes(audience).
    hasher.update((audience.len() as u32).to_be_bytes());
    hasher.update(audience.as_bytes());

    // U64(signed_at).
    hasher.update(signed_at.to_be_bytes());

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
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
        // Must match the golden vector in scp-core/src/identity/scpid.rs.
        let hash = scpid_canonical_hash(
            "did:dht:z6MkTest",
            "#active",
            &[0xAAu8; 32],
            "https://example.com",
            1_709_654_400_000,
        );
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
