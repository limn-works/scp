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
//! # Bridge stub behavior
//!
//! All functions are bridge stubs returning typed errors. The full UCAN
//! protocol (signature verification, delegation chain traversal, attenuation
//! enforcement, nonce replay detection) is implemented in scp-core/crypto/ucan
//! and will be connected in a future story when WASM-compatible scp-core
//! bindings are available.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md` and ADR-016 (UCAN validation)
//! for the full specification.

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::context::WasmContextHandle;
use crate::error::ScpWasmError;

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
/// - Rejects with `[SCP-PERM-3002]` if validation fails for any reason:
///   malformed token, invalid signature, expired, insufficient capabilities,
///   revoked, broken delegation chain.
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn ucan_validate(context: &WasmContextHandle, token: String, capability: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let _ = (context_id, token, capability);

        Err(ScpWasmError::Permission {
            message: "not yet connected to runtime — UCAN validation requires a live context \
                      handle wired to scp-core"
                .to_owned(),
            code: "SCP-PERM-3002".to_owned(),
        }
        .into_js()
        .into())
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
/// - Rejects with `[SCP-PERM-3004]` if minting fails (capabilities outside
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
        // Validate that capabilities_json is a valid JSON array.
        let caps: serde_json::Value = serde_json::from_str(&capabilities_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("capabilities_json is not valid JSON: {e}"),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
        })?;

        if !caps.is_array() {
            return Err(ScpWasmError::Validation {
                message: "capabilities_json must be a JSON array of capability URI strings"
                    .to_owned(),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
            .into());
        }

        let _ = (context_id, member_did);

        Err(ScpWasmError::Permission {
            message: "not yet connected to runtime — UCAN minting requires a live context \
                      handle wired to scp-core"
                .to_owned(),
            code: "SCP-PERM-3004".to_owned(),
        }
        .into_js()
        .into())
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
/// Rejects with `[SCP-PERM-3006]` if revocation fails (token not found,
/// revoker not authorized — must be the token's issuer or context creator).
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn ucan_revoke(context: &WasmContextHandle, token_id: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let _ = (context_id, token_id);

        Err(ScpWasmError::Permission {
            message: "not yet connected to runtime — UCAN revocation requires a live context \
                      handle wired to scp-core"
                .to_owned(),
            code: "SCP-PERM-3006".to_owned(),
        }
        .into_js()
        .into())
    })
}
