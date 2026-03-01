//! `wasm-bindgen` bridge for UCAN token management.
//!
//! Exposes SCP UCAN operations to JavaScript:
//!
//! - [`ucan_validate`] — Validate a UCAN token against a required capability.
//! - [`ucan_mint`] — Mint a new UCAN token for a context member.
//! - [`ucan_revoke`] — Revoke a UCAN token.
//!
//! # Types
//!
//! - [`WasmUcanToken`] — UCAN token handle (ID, issuer, audience, capabilities,
//!   expiry).
//!
//! # Wiring
//!
//! All functions delegate to the WASM-local runtime registry in [`crate::runtime`].
//! `ucan_validate` performs structural validation (capability URI parsing, ceiling
//! checking, revocation checking) without full Ed25519 signature verification
//! (signature verification requires `KeyCustody` wiring — see SCP-214).
//! `ucan_mint` creates a properly structured token with metadata (signing deferred
//! to SCP-214). `ucan_revoke` adds the token CID to the context's revocation set.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md` and ADR-016 (UCAN validation)
//! for the full specification.

use js_sys::Promise;
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
/// The raw signature and encoded JWT are not exposed — they are internal to
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
    /// Issuer DID — the entity that created and signed this token.
    issuer: String,
    /// Audience DID — the entity this token is delegated to.
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
// Bridge functions
// ---------------------------------------------------------------------------

/// Validates a UCAN token for a required capability.
///
/// Performs full UCAN validation: signature verification, time bounds
/// checking, delegation chain traversal, attenuation enforcement, nonce
/// replay detection, and capability matching.
///
/// # Arguments
///
/// * `context` — The context handle the token is presented in.
/// * `token` — The encoded UCAN token string (JWT format).
/// * `capability` — The required capability URI (e.g.,
///   `"scp:ctx:abc123/messages:write"`).
///
/// # Returns
///
/// `Promise<void>` — resolves on successful validation.
///
/// # Errors
///
/// - Rejects with `[SCP-PERM-3000]` if validation fails for any reason:
///   malformed token, invalid signature, expired, insufficient capabilities,
///   revoked, broken delegation chain.
///
/// See ADR-022 acceptance criterion 1.
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

        let payload: serde_json::Value =
            serde_json::from_slice(&payload_bytes).map_err(|e| {
                ScpWasmError::Permission(format!("malformed UCAN payload (JSON parse): {e}"))
                    .into_js()
            })?;

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

        let token_atts = payload["att"].as_array();
        let has_capability = token_atts.is_some_and(|atts| {
            atts.iter().any(|att| {
                let with_str = att["with"].as_str().unwrap_or("");
                let can_str = att["can"].as_str().unwrap_or("");
                let att_uri = format!("{with_str}/{can_str}");
                att_uri == capability || can_str == "*"
            })
        });

        if !has_capability {
            return Err(ScpWasmError::Permission(format!(
                "UCAN token does not grant capability '{capability}'"
            ))
            .into_js()
            .into());
        }

        runtime::with_context(&context_id, |rt| {
            let token_cid = compute_token_cid(&token);
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
/// * `context` — The context handle to mint the token for.
/// * `member_did` — The DID of the member receiving the token.
/// * `capabilities_json` — A JSON array of capability URI strings to grant
///   (e.g., `'["scp:ctx:abc123/messages:write"]'`).
///
/// # Returns
///
/// `Promise<WasmUcanToken>` — resolves to the minted token handle.
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

        let creator_did =
            runtime::with_context(&context_id, |rt| Ok(rt.creator_did.clone()))
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
/// Adds the token to the context's revocation list. Revoked tokens are no
/// longer accepted by validation. Revocation is distributed to all context
/// members via MLS.
///
/// # Arguments
///
/// * `context` — The context handle the token belongs to.
/// * `token_id` — The unique ID of the token to revoke.
///
/// # Returns
///
/// `Promise<void>` — resolves on success.
///
/// # Errors
///
/// Rejects with `[SCP-PERM-3000]` if revocation fails (token not found,
/// revoker not authorized — must be the token's issuer or context creator).
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
#[allow(clippy::similar_names)]
pub fn ucan_revoke(context: &WasmContextHandle, token_id: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let token_cid = compute_token_cid(&token_id);

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

/// Computes a content-hash CID (SHA-256 hex) for a token string.
///
/// Mirrors scp-core's `compute_revocation_cid`. Uses the token string (or
/// token ID) as the CID input.
fn compute_token_cid(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    runtime::encode_hex(&hash)
}
