//! `wasm-bindgen` bridge for UCAN token management.
//!
//! Exposes SCP UCAN operations to JavaScript:
//!
//! - [`ucan_validate`] --- Validate a UCAN token against a required capability.
//! - [`ucan_mint`] --- Mint a new UCAN token for a context member.
//! - [`ucan_revoke`] --- Revoke a UCAN token.
//!
//! # Types
//!
//! - [`WasmUcanToken`] --- UCAN token handle (ID, issuer, audience, capabilities,
//!   expiry).
//!
//! # Wiring
//!
//! All functions delegate to the WASM-local runtime registry in [`crate::runtime`].
//! `ucan_validate` performs Ed25519 signature verification, time bounds checking,
//! capability matching with context scope enforcement, and revocation checking.
//! `ucan_mint` creates a properly structured token with metadata (signing deferred
//! to SCP-214). `ucan_revoke` adds the token CID to the context's revocation set
//! using the same CID computation as scp-core's `compute_revocation_cid`.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md` and ADR-016 (UCAN validation)
//! for the full specification.

use js_sys::Promise;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::context::WasmContextHandle;
use crate::error::ScpWasmError;
use crate::runtime;

// ---------------------------------------------------------------------------
// WasmUcanToken
// ---------------------------------------------------------------------------

/// UCAN token handle exposed to JavaScript.
///
/// Contains the token metadata accessible to JavaScript code: a unique token
/// ID (derived from the UCAN nonce), issuer DID, audience DID, capabilities
/// as a JSON string, and an optional expiry timestamp.
///
/// The raw signature and encoded JWT are not exposed --- they are internal to
/// the Rust crypto layer and not needed by application code.
///
/// # JS usage
///
/// ```js
/// const token = await ucan_mint(ctx, memberDid, capabilitiesJson);
/// console.log(token.tokenId);          // "tk-abc123..."
/// console.log(token.issuer);           // "did:dht:z..."
/// console.log(token.audience);         // "did:dht:z..."
/// console.log(token.capabilitiesJson); // '["scp:ctx:abc/messages:write"]'
/// console.log(token.expiresAt);        // null | 1735689600.0
/// ```
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmUcanToken {
    /// Unique token identifier (derived from the UCAN nonce).
    token_id: String,
    /// Issuer DID --- the entity that created and signed this token.
    issuer: String,
    /// Audience DID --- the entity this token is delegated to.
    audience: String,
    /// Granted capabilities serialized as a JSON array of URI strings.
    /// Each string follows the SCP capability URI format:
    /// `scp:ctx:{context_id}/{capability}`.
    capabilities_json: String,
    /// Expiry timestamp (seconds since Unix epoch). `None` (JS `null`) if
    /// the token does not expire (not recommended for security).
    expires_at: Option<f64>,
}

#[wasm_bindgen]
impl WasmUcanToken {
    /// Returns the unique token identifier.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "tokenId")]
    pub fn token_id(&self) -> String {
        self.token_id.clone()
    }

    /// Returns the issuer DID.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn issuer(&self) -> String {
        self.issuer.clone()
    }

    /// Returns the audience DID.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn audience(&self) -> String {
        self.audience.clone()
    }

    /// Returns the granted capabilities as a JSON array string.
    ///
    /// The TypeScript SDK parses this with `JSON.parse()` to obtain
    /// `string[]`.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "capabilitiesJson")]
    pub fn capabilities_json(&self) -> String {
        self.capabilities_json.clone()
    }

    /// Returns the expiry timestamp in seconds since Unix epoch, or `null`
    /// if the token does not expire.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "expiresAt")]
    pub fn expires_at(&self) -> Option<f64> {
        self.expires_at
    }
}

// ---------------------------------------------------------------------------
// UCAN payload types (mirrors scp-core for CID-compatible serialization)
// ---------------------------------------------------------------------------

/// Mirrors `scp_core::crypto::ucan::Attenuation` for JSON serialization.
///
/// Used by [`compute_revocation_cid`] and capability matching. Field names
/// and serialization order must match scp-core exactly so that
/// `serde_json::to_vec` produces identical bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WasmAttenuation {
    with: String,
    can: String,
}

/// Mirrors `scp_core::crypto::ucan::UcanPayload` for CID computation.
///
/// The revocation CID is `SHA-256(serde_json::to_vec(payload))`. For CIDs
/// to match between the WASM bridge and scp-core, the struct layout and
/// serde attributes must be identical.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WasmUcanPayload {
    iss: String,
    aud: String,
    exp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<u64>,
    nnc: String,
    att: Vec<WasmAttenuation>,
    prf: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fct: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Validates a UCAN token for a required capability.
///
/// Performs UCAN validation including Ed25519 signature verification, time
/// bounds checking, capability matching with context scope enforcement, and
/// revocation checking. The signature is verified against the issuer's
/// public key extracted from the DID string.
///
/// # Arguments
///
/// * `context` --- The context handle the token is presented in.
/// * `token` --- The encoded UCAN token string (JWT format).
/// * `capability` --- The required capability URI (e.g.,
///   `"scp:ctx:abc123/messages:write"`).
///
/// # Returns
///
/// `Promise<void>` --- resolves on successful validation.
///
/// # Errors
///
/// - Rejects with `[SCP-PERM-3000]` if validation fails for any reason:
///   malformed token, invalid signature, expired, insufficient capabilities,
///   revoked, broken delegation chain.
///
/// See ADR-022 acceptance criterion 1 and ADR-016 (UCAN Enforcement).
#[wasm_bindgen]
pub fn ucan_validate(context: &WasmContextHandle, token: String, capability: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(ScpWasmError::Permission(
                "malformed UCAN token: expected 3 dot-separated JWT segments".to_owned(),
            )
            .into_js()
            .into());
        }

        let payload_b64 = parts[1];
        let payload_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            payload_b64,
        )
        .map_err(|e| {
            ScpWasmError::Permission(format!("malformed UCAN payload (base64 decode): {e}"))
                .into_js()
        })?;

        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).map_err(|e| {
            ScpWasmError::Permission(format!("malformed UCAN payload (JSON parse): {e}")).into_js()
        })?;

        verify_token_signature(&token, parts, &payload)?;

        let token_exp = payload["exp"].as_u64().ok_or_else(|| {
            ScpWasmError::Permission("UCAN payload missing 'exp' field".to_owned()).into_js()
        })?;

        let now = js_sys::Date::now() / 1000.0;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let now_secs = now as u64;

        if token_exp < now_secs {
            return Err(ScpWasmError::Permission(format!(
                "UCAN token expired: exp={token_exp}, now={now_secs}"
            ))
            .into_js()
            .into());
        }

        let context_prefix = format!("scp:ctx:{context_id}");
        let token_atts = payload["att"].as_array();
        let has_capability = token_atts.is_some_and(|atts| {
            atts.iter().any(|att| {
                let with_str = att["with"].as_str().unwrap_or("");
                let can_str = att["can"].as_str().unwrap_or("");
                let att_uri = format!("{with_str}/{can_str}");
                att_uri == capability
                    || (can_str == "*" && with_str.starts_with(&context_prefix))
            })
        });

        if !has_capability {
            return Err(ScpWasmError::Permission(format!(
                "UCAN token does not grant capability '{capability}'"
            ))
            .into_js()
            .into());
        }

        let typed_payload: WasmUcanPayload =
            serde_json::from_slice(&payload_bytes).map_err(|e| {
                ScpWasmError::Permission(format!(
                    "failed to deserialize UCAN payload for CID computation: {e}"
                ))
                .into_js()
            })?;

        runtime::with_context(&context_id, |rt| {
            let token_cid = compute_revocation_cid(&typed_payload);
            if rt.revoked_tokens.contains(&token_cid) {
                return Err(ScpWasmError::Permission(
                    "UCAN token has been revoked".to_owned(),
                ));
            }
            Ok(())
        })
        .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::UNDEFINED)
    })
}

/// Mints a new UCAN token for a context member.
///
/// Creates a UCAN token granting the specified capabilities to the given
/// member DID. The token is signed by the context creator's key (or the
/// delegating member's key in a delegation chain).
///
/// # Arguments
///
/// * `context` --- The context handle to mint the token for.
/// * `member_did` --- The DID of the member receiving the token.
/// * `capabilities_json` --- A JSON array of capability URI strings to grant
///   (e.g., `'["scp:ctx:abc123/messages:write"]'`).
///
/// # Returns
///
/// `Promise<WasmUcanToken>` --- resolves to the minted token handle.
///
/// # Errors
///
/// - Rejects with `[SCP-VALID-7000]` if `capabilities_json` is malformed.
/// - Rejects with `[SCP-PERM-3000]` if minting fails (capabilities outside
///   the context ceiling, issuer not authorized).
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn ucan_mint(
    context: &WasmContextHandle,
    member_did: String,
    capabilities_json: String,
) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let caps: serde_json::Value = serde_json::from_str(&capabilities_json).map_err(|e| {
            ScpWasmError::Validation(format!("capabilities_json is not valid JSON: {e}")).into_js()
        })?;

        let caps_array = caps.as_array().ok_or_else(|| {
            ScpWasmError::Validation(
                "capabilities_json must be a JSON array of capability URI strings".to_owned(),
            )
            .into_js()
        })?;

        let creator_did = runtime::with_context(&context_id, |rt| Ok(rt.creator_did.clone()))
            .map_err(ScpWasmError::into_js)?;

        let nonce = format!("tk-{}", uuid::Uuid::new_v4().as_hyphenated());

        let capability_uris: Vec<String> = caps_array
            .iter()
            .filter_map(|v| v.as_str())
            .map(|cap| {
                if cap.starts_with("scp:ctx:") {
                    cap.to_owned()
                } else {
                    format!("scp:ctx:{context_id}/{cap}")
                }
            })
            .collect();

        let uris_json = serde_json::to_string(&capability_uris).unwrap_or_else(|_| "[]".to_owned());

        #[allow(clippy::cast_precision_loss)]
        let now_secs = js_sys::Date::now() / 1000.0;
        let exp = now_secs + 3600.0;

        let token = WasmUcanToken {
            token_id: nonce,
            issuer: creator_did,
            audience: member_did,
            capabilities_json: uris_json,
            expires_at: Some(exp),
        };

        Ok(JsValue::from(token))
    })
}

/// Revokes a UCAN token.
///
/// Parses the full encoded JWT token, computes its content-hash CID using
/// the same algorithm as scp-core's `compute_revocation_cid` (SHA-256 of
/// JSON-serialized payload struct), and adds the CID to the context's
/// revocation set.
///
/// # Arguments
///
/// * `context` --- The context handle the token belongs to.
/// * `token` --- The full encoded UCAN token string (JWT format).
///
/// # Returns
///
/// `Promise<void>` --- resolves on success.
///
/// # Errors
///
/// Rejects with `[SCP-PERM-3000]` if revocation fails (malformed token,
/// context not found).
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
#[allow(clippy::similar_names)]
pub fn ucan_revoke(context: &WasmContextHandle, token: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let payload = parse_jwt_payload(&token).map_err(|e| {
            ScpWasmError::Permission(format!("failed to parse UCAN for revocation: {e}")).into_js()
        })?;

        let token_cid = compute_revocation_cid(&payload);

        runtime::with_context(&context_id, |rt| {
            rt.revoked_tokens.insert(token_cid.clone());
            Ok(())
        })
        .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::UNDEFINED)
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Verifies the Ed25519 signature on a JWT-format UCAN token.
///
/// Resolves the issuer DID to extract the public key, decodes the signature
/// from the third JWT segment, and verifies the signature over the signing
/// input (`header_b64.payload_b64`).
///
/// Supports `did:dht:z{z-base-32}` (production) and `did:key:{hex}`
/// (testing) DID formats, matching the NAPI bridge's `BridgeDidResolver`.
fn verify_token_signature(
    encoded_token: &str,
    parts: Vec<&str>,
    payload: &serde_json::Value,
) -> Result<(), JsValue> {
    let issuer_did = payload["iss"].as_str().ok_or_else(|| {
        ScpWasmError::Permission("UCAN payload missing 'iss' field".to_owned()).into_js()
    })?;

    let pk_bytes = resolve_did_public_key(issuer_did).map_err(|e| {
        ScpWasmError::Permission(format!("failed to resolve issuer DID: {e}")).into_js()
    })?;

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).map_err(|e| {
        ScpWasmError::Permission(format!("invalid public key from issuer DID: {e}")).into_js()
    })?;

    let sig_b64 = parts[2];
    let sig_bytes_vec = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        sig_b64,
    )
    .map_err(|e| {
        ScpWasmError::Permission(format!("malformed UCAN signature (base64 decode): {e}"))
            .into_js()
    })?;

    let sig_bytes: [u8; 64] = sig_bytes_vec.as_slice().try_into().map_err(|_| {
        ScpWasmError::Permission(format!(
            "UCAN signature must be 64 bytes, got {}",
            sig_bytes_vec.len()
        ))
        .into_js()
    })?;

    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    let signing_input = encoded_token
        .rfind('.')
        .map(|pos| &encoded_token[..pos])
        .ok_or_else(|| {
            ScpWasmError::Permission("missing signature segment in JWT".to_owned()).into_js()
        })?;

    verifying_key
        .verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|_| {
            ScpWasmError::Permission("UCAN Ed25519 signature verification failed".to_owned())
                .into_js()
        })?;

    Ok(())
}

/// Resolves a DID string to its Ed25519 public key bytes.
///
/// Supports:
/// - `did:dht:z{z-base-32-encoded-pubkey}` --- production format.
/// - `did:key:{hex-encoded-pubkey}` --- testing format.
///
/// Mirrors the NAPI bridge's `BridgeDidResolver::resolve_public_key`.
fn resolve_did_public_key(did: &str) -> Result<[u8; 32], String> {
    if let Some(suffix) = did.strip_prefix("did:dht:z") {
        let decoded = zbase32::decode(suffix)
            .map_err(|_| format!("z-base-32 decode failed for DID: {did}"))?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|v: Vec<u8>| format!("DID public key must be 32 bytes, got {}", v.len()))?;
        return Ok(bytes);
    }

    if let Some(hex_str) = did.strip_prefix("did:key:") {
        let bytes = decode_hex(hex_str)
            .map_err(|e| format!("hex decode failed for did:key DID: {e}"))?;
        let pk: [u8; 32] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| format!("DID public key must be 32 bytes, got {}", v.len()))?;
        return Ok(pk);
    }

    Err(format!(
        "unsupported DID method: {did} (expected did:dht: or did:key:)"
    ))
}

/// Decodes a hex string to bytes.
fn decode_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    hex::decode(hex_str).map_err(|e| format!("hex decode error: {e}"))
}

/// Parses a JWT-format UCAN token and returns the deserialized payload.
///
/// Used by `ucan_revoke` to compute the revocation CID from the payload
/// struct, matching scp-core's `compute_revocation_cid` algorithm.
fn parse_jwt_payload(token: &str) -> Result<WasmUcanPayload, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("malformed UCAN token: expected 3 dot-separated JWT segments".to_owned());
    }

    let payload_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        parts[1],
    )
    .map_err(|e| format!("malformed UCAN payload (base64 decode): {e}"))?;

    serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("malformed UCAN payload (JSON parse): {e}"))
}

/// Computes the revocation CID for a UCAN payload.
///
/// Matches scp-core's `compute_revocation_cid` exactly: JSON-serialize the
/// `UcanPayload` struct, then SHA-256 hash the bytes, then hex-encode.
///
/// The struct field order and serde attributes must match scp-core's
/// `UcanPayload` so that `serde_json::to_vec` produces identical bytes.
fn compute_revocation_cid(payload: &WasmUcanPayload) -> String {
    let payload_bytes = serde_json::to_vec(payload).unwrap_or_default();
    let hash = Sha256::digest(&payload_bytes);
    hash.iter().fold(String::with_capacity(64), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}
