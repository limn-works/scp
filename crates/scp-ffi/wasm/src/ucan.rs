//! `wasm-bindgen` bridge for UCAN token management.
//!
//! Validation, nonce tracking, and revocation all delegate to
//! [`WasmContextManager`](crate::manager::WasmContextManager) for state
//! management. The 11-step UCAN validation pipeline delegates to
//! `scp_protocol::crypto::ucan::validate::validate_ucan` using the
//! extract-validate-writeback pattern (extract state from manager,
//! build trait impls, call validate, write back nonce).
//!
//! See ADR-034 in `.docs/adrs/phase-4.md` and issue #389.

use scp_ffi_common::error_codes as codes;
use std::collections::HashSet;

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use scp_protocol::context::roles::default_ceiling;
use scp_protocol::crypto::ucan::revoke::compute_revocation_cid;
use scp_protocol::crypto::ucan::validate::{
    DidResolver, InMemoryProofResolver, InMemoryRevocationChecker,
    NonceTracker as ValidationNonceTracker, ValidationContext, parse_ucan, validate_ucan,
};
use scp_protocol::crypto::ucan::{CapabilityUri, UcanError, UcanToken};

use scp_ffi_common::validate::{validate_capability_uri, validate_did, validate_ucan_token};

use crate::context::WasmContextHandle;
use crate::error::ScpWasmError;
use crate::manager::with_manager;

// ---------------------------------------------------------------------------
// WASM trait adapters for scp-protocol validation
// ---------------------------------------------------------------------------

/// WASM [`DidResolver`] adapter that resolves DID public keys using the
/// WASM identity registry.
///
/// For local identities, delegates to `crate::identity::resolve_verification_method_key`.
/// For remote DIDs, falls back to DID-embedded key extraction from the DID
/// string itself (works for `did:dht:z{zbase32}` DIDs).
struct WasmDidResolver;

impl DidResolver for WasmDidResolver {
    fn resolve_public_key(&self, did: &str) -> Result<[u8; 32], UcanError> {
        // Try the identity registry first (local DIDs).
        if let Ok(pk) = crate::identity::resolve_verification_method_key(did, "#active") {
            return Ok(pk);
        }
        // Fall back to DID-embedded key extraction for remote DIDs.
        resolve_did_embedded_key(did)
    }

    fn resolve_public_key_by_kid(&self, did: &str, kid: &str) -> Result<[u8; 32], UcanError> {
        // Try the identity registry first — it has both #active and #agent keys.
        if let Ok(pk) = crate::identity::resolve_verification_method_key(did, kid) {
            return Ok(pk);
        }
        // For #active, fall back to DID-embedded key extraction (remote DIDs).
        if kid == "#active" {
            return resolve_did_embedded_key(did);
        }
        Err(UcanError::MalformedToken(format!(
            "verification method '{kid}' not found on DID '{did}'"
        )))
    }
}

/// Extracts the Ed25519 public key embedded in a `did:dht:z{zbase32}` DID string.
///
/// This is used for remote DIDs that are not in the local identity registry.
fn resolve_did_embedded_key(did: &str) -> Result<[u8; 32], UcanError> {
    if let Some(suffix) = did.strip_prefix("did:dht:z") {
        let decoded = zbase32_decode(suffix).map_err(|e| {
            UcanError::MalformedToken(format!("z-base-32 decode failed for DID {did}: {e}"))
        })?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
            UcanError::MalformedToken(format!("DID public key must be 32 bytes, got {}", v.len()))
        })?;
        return Ok(bytes);
    }

    #[cfg(any(test, feature = "testing"))]
    if let Some(hex_str) = did.strip_prefix("did:key:") {
        let bytes = decode_hex(hex_str).map_err(|e| {
            UcanError::MalformedToken(format!("hex decode failed for did:key DID: {e}"))
        })?;
        let pk: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            UcanError::MalformedToken(format!("DID public key must be 32 bytes, got {}", v.len()))
        })?;
        return Ok(pk);
    }

    Err(UcanError::MalformedToken(format!(
        "unsupported DID method: {did} (expected did:dht:)"
    )))
}

/// WASM [`NonceTracker`](ValidationNonceTracker) adapter using pre-extracted
/// nonce state.
///
/// Performs format validation, freshness checks, and replay detection.
/// The nonce is NOT recorded here — writeback to `WasmContextManager` happens
/// after validation succeeds (extract-validate-writeback pattern).
struct WasmNonceTracker {
    /// Pre-extracted set of seen nonces from `WasmContextManager`.
    seen_nonces: HashSet<String>,
    /// Whether a new nonce was validated (for writeback).
    validated_nonce: Option<String>,
}

impl WasmNonceTracker {
    fn new(seen_nonces: HashSet<String>) -> Self {
        Self {
            seen_nonces,
            validated_nonce: None,
        }
    }
}

/// Nonce freshness tolerance: 5 minutes in milliseconds (spec section 9.14).
///
/// Duplicates `scp_protocol::crypto::ucan::nonce::NONCE_FRESHNESS_TOLERANCE_MS`
/// and `scp_protocol::crypto::ucan::validate::NONCE_FRESHNESS_TOLERANCE_MS`
/// (both `const`, not `pub`). If the upstream value changes, this must be
/// updated in lockstep.
const NONCE_FRESHNESS_TOLERANCE_MS: u64 = 5 * 60 * 1000;

impl ValidationNonceTracker for WasmNonceTracker {
    fn check_replay(&self, nonce: &str, _token_expiry: u64) -> Result<(), UcanError> {
        // 1. Format: split into timestamp and hex suffix.
        if nonce.is_empty() {
            return Err(UcanError::NonceFormatInvalid("nonce is empty".to_owned()));
        }

        let (ts_part, hex_part) = nonce.split_once('-').ok_or_else(|| {
            UcanError::NonceFormatInvalid(format!("missing '-' separator in nonce: {nonce}"))
        })?;

        let nonce_millis: u64 = ts_part.parse().map_err(|_| {
            UcanError::NonceFormatInvalid(format!("non-numeric timestamp in nonce: {ts_part}"))
        })?;

        if hex_part.len() != 32 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(UcanError::NonceFormatInvalid(format!(
                "invalid hex suffix in nonce (expected 32 hex chars): {hex_part}"
            )));
        }

        // 2. Freshness: timestamp within now +/- 5 minutes.
        let now = crate::time::now_ms_u64();

        if nonce_millis.saturating_add(NONCE_FRESHNESS_TOLERANCE_MS) < now {
            return Err(UcanError::NonceTooOld(nonce.to_owned()));
        }

        if nonce_millis > now.saturating_add(NONCE_FRESHNESS_TOLERANCE_MS) {
            return Err(UcanError::NonceFuture(nonce.to_owned()));
        }

        // 3. Replay check.
        if self.seen_nonces.contains(nonce) {
            return Err(UcanError::NonceReused(nonce.to_owned()));
        }

        Ok(())
    }

    fn record(&mut self, nonce: &str, token_expiry: u64) -> Result<(), UcanError> {
        // Defensive re-check before committing (H11 split-phase protocol).
        self.check_replay(nonce, token_expiry)?;

        // Stage for writeback — don't insert into seen_nonces directly, as
        // the real recording happens via WasmContextManager::ucan_record_nonce
        // (extract-validate-writeback pattern).
        self.validated_nonce = Some(nonce.to_owned());

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Proof CID computation helper
// ---------------------------------------------------------------------------

/// Computes a proof CID as `"bafyrei" + hex-encoded SHA-256` of the raw
/// encoded JWT string. This format matches how SCP UCAN tokens reference
/// proofs in their `prf` field.
fn compute_proof_cid(encoded_token: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(encoded_token.as_bytes());
    let hex = hash.iter().fold(String::with_capacity(64), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    });
    format!("bafyrei{hex}")
}

// ---------------------------------------------------------------------------
// z-base-32 / hex helpers (needed for DID-embedded key extraction)
// ---------------------------------------------------------------------------

fn zbase32_decode(input: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

    let mut lookup = [255u8; 128];
    for (i, &c) in ALPHABET.iter().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        {
            lookup[c as usize] = i as u8;
        }
    }

    let mut bits: u64 = 0;
    let mut bit_count: u32 = 0;
    let mut output = Vec::new();

    for &c in input.as_bytes() {
        if c >= 128 || lookup[c as usize] == 255 {
            return Err(format!("invalid z-base-32 character: {}", c as char));
        }
        bits = (bits << 5) | u64::from(lookup[c as usize]);
        bit_count += 5;
        while bit_count >= 8 {
            bit_count -= 8;
            #[allow(clippy::cast_possible_truncation)]
            output.push((bits >> bit_count) as u8);
            bits &= (1u64 << bit_count) - 1;
        }
    }

    Ok(output)
}

#[cfg(any(test, feature = "testing"))]
fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err(format!("hex string has odd length: {}", hex.len()));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        let byte =
            u8::from_str_radix(byte_str, 16).map_err(|e| format!("hex decode error: {e}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

use crate::time::WasmClock;

// ---------------------------------------------------------------------------
// WasmUcanToken
// ---------------------------------------------------------------------------

/// UCAN token handle exposed to JavaScript.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmUcanToken {
    token_id: String,
    issuer: String,
    audience: String,
    capabilities_json: String,
    expires_at: Option<f64>,
}

#[wasm_bindgen]
impl WasmUcanToken {
    /// Returns the token ID (SHA-256 CID of the encoded JWT).
    #[must_use]
    #[wasm_bindgen(getter, js_name = "tokenId")]
    pub fn token_id(&self) -> String {
        self.token_id.clone()
    }

    /// Returns the issuer DID of the token.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn issuer(&self) -> String {
        self.issuer.clone()
    }

    /// Returns the audience DID of the token.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn audience(&self) -> String {
        self.audience.clone()
    }

    /// Returns the token's capabilities as a JSON string.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "capabilitiesJson")]
    pub fn capabilities_json(&self) -> String {
        self.capabilities_json.clone()
    }

    /// Returns the token expiration as seconds since the Unix epoch, or `undefined`.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "expiresAt")]
    pub fn expires_at(&self) -> Option<f64> {
        self.expires_at
    }
}

// ---------------------------------------------------------------------------
// Extract-validate-writeback helper
// ---------------------------------------------------------------------------

/// Extracts UCAN validation state from `WasmContextManager` and calls
/// `scp_protocol::crypto::ucan::validate::validate_ucan`.
///
/// Implements the extract-validate-writeback pattern:
/// 1. **EXTRACT** — Pull ceiling, `creator_did`, `revoked_cids` from manager.
/// 2. **BUILD** — Create trait impls (DID resolver, nonce tracker, etc.).
/// 3. **CALL** — Call `validate_ucan()` from scp-protocol.
/// 4. **WRITEBACK** — Record the validated nonce in the manager.
fn run_validate_ucan(
    context_id: &str,
    token: &UcanToken,
    required_capability: &CapabilityUri,
    expected_aud_did: &str,
    proof_tokens: Option<&[String]>,
) -> Result<(), String> {
    // 1. EXTRACT state from WasmContextManager.
    let (ceiling, creator_did, revoked_cids) =
        with_manager(|mgr| mgr.ucan_context_state(context_id)).map_err(|e| e.to_string())?;

    // When the ceiling is empty, apply the default ceiling instead of skipping
    // enforcement entirely — matching the NAPI and UniFFI bridges (#1495, #1419).
    let effective_ceiling = if ceiling.is_empty() {
        default_ceiling().to_ucan_string_set()
    } else {
        ceiling
    };

    // 2. BUILD trait impls from extracted state.
    let did_resolver = WasmDidResolver;

    // Extract seen nonces as a HashSet (keys only).
    let seen_nonces_set: HashSet<String> =
        with_manager(|mgr| mgr.ucan_seen_nonce_keys(context_id)).map_err(|e| e.to_string())?;

    let mut nonce_tracker = WasmNonceTracker::new(seen_nonces_set);

    let mut revocation_checker = InMemoryRevocationChecker::new();
    revocation_checker.revoked = revoked_cids;

    // Build proof resolver from provided proof tokens.
    let mut proof_resolver = InMemoryProofResolver::new();
    if let Some(proofs) = proof_tokens {
        for encoded in proofs {
            let parsed = parse_ucan(encoded).map_err(|e| e.to_string())?;
            let cid = compute_proof_cid(encoded);
            proof_resolver.proofs.insert(cid, parsed);
        }
    }

    let clock = WasmClock;

    // 3. CALL validate_ucan from scp-protocol.
    let mut ctx = ValidationContext {
        did_resolver: &did_resolver,
        nonce_tracker: &mut nonce_tracker,
        revocation_checker: &revocation_checker,
        proof_resolver: &proof_resolver,
        ceiling: &effective_ceiling,
        context_creator_did: &creator_did,
        presenting_agent_did: expected_aud_did,
        clock_skew_tolerance_secs:
            scp_protocol::crypto::ucan::validate::DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
        clock: &clock,
    };

    validate_ucan(token, required_capability, &mut ctx).map_err(|e| e.to_string())?;

    // 4. WRITEBACK — record the validated nonce in the manager.
    // The nonce was validated by the tracker but not persisted yet.
    // We use WasmContextManager::ucan_record_nonce for the actual persistence.
    if nonce_tracker.validated_nonce.is_some() {
        with_manager(|mgr| mgr.ucan_record_nonce(context_id, &token.payload.nnc))
            .map_err(|e| e.to_string())?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Validates a UCAN token for a required capability.
///
/// Performs the full 11-step UCAN validation pipeline from ADR-016, delegating
/// to `scp_protocol::crypto::ucan::validate::validate_ucan` via the
/// extract-validate-writeback pattern.
///
/// State operations (nonce tracking, revocation lists, ceiling) are
/// extracted from `WasmContextManager`, validation runs against in-memory
/// trait impls, and new nonces are written back after success.
#[wasm_bindgen]
pub fn ucan_validate(
    context: &WasmContextHandle,
    token: String,
    capability: String,
    expected_aud_did: String,
    proof_tokens_json: Option<String>,
) -> Promise {
    if let Err(e) = validate_ucan_token(&token) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    if let Err(e) = validate_capability_uri(&capability) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    if let Err(e) = validate_did(&expected_aud_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = context.context_id();

    future_to_promise(async move {
        let parsed = parse_ucan(&token).map_err(|e| {
            // Route UCAN error classification through the shared mapping
            // in `scp_ffi_common::ucan_errors` so all four bridges stay
            // in lockstep (`OP_UCAN_VALIDATE_MALFORMED` pins this code).
            let code = scp_ffi_common::ucan_errors::ucan_error_code(&e).to_owned();
            ScpWasmError::Permission {
                message: format!("malformed token: {e}"),
                code,
            }
            .into_js()
        })?;

        let proof_tokens: Option<Vec<String>> = match proof_tokens_json {
            Some(json_str) => {
                let arr: Vec<String> = serde_json::from_str(&json_str).map_err(|e| {
                    ScpWasmError::Validation {
                        message: format!(
                            "proof_tokens_json is not a valid JSON array of strings: {e}"
                        ),
                        code: codes::VALID_7000.to_owned(),
                    }
                    .into_js()
                })?;
                Some(arr)
            }
            None => None,
        };

        let required_capability: CapabilityUri = capability.parse().map_err(|e: UcanError| {
            ScpWasmError::Permission {
                message: format!("invalid capability URI: {e}"),
                code: codes::PERM_3000.to_owned(),
            }
            .into_js()
        })?;

        run_validate_ucan(
            &context_id,
            &parsed,
            &required_capability,
            &expected_aud_did,
            proof_tokens.as_deref(),
        )
        .map_err(|e| {
            ScpWasmError::Permission {
                message: e,
                code: codes::PERM_3000.to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::UNDEFINED)
    })
}

/// Mints a new UCAN token for a context member.
///
/// UCAN minting requires key custody (`WebCrypto`) which is only available
/// on the JS side. Always returns `SCP-PERM-3000` — use the TypeScript SDK
/// wrapper's `mintUcan()` method which signs via `SubtleCrypto`.
///
/// # Errors
///
/// Always returns `SCP-PERM-3000` since UCAN minting requires JS-side key custody.
///
/// See ADR-016 criterion 3.
#[wasm_bindgen]
pub fn ucan_mint(
    _context: &WasmContextHandle,
    _member_did: String,
    _capabilities_json: String,
    _proofs_json: Option<String>,
) -> Promise {
    future_to_promise(async {
        Err(ScpWasmError::Permission {
            message: "UCAN minting requires JS-side key custody (WebCrypto) — use the TypeScript \
                      SDK wrapper's mintUcan() method which signs via SubtleCrypto"
                .to_owned(),
            code: codes::PERM_3000.to_owned(),
        }
        .into_js()
        .into())
    })
}

/// Delegates a UCAN token to another member.
///
/// UCAN delegation requires key custody (`WebCrypto`) which is only available
/// on the JS side. Always returns `SCP-PERM-3000` — use the TypeScript SDK
/// wrapper's `delegateUcan()` method which signs via `SubtleCrypto`.
///
/// See ADR-016 criterion 4.
#[wasm_bindgen]
pub fn ucan_delegate(
    _context: &WasmContextHandle,
    _delegator_did: String,
    _delegatee_did: String,
    _parent_token: String,
    _capabilities_json: String,
) -> Promise {
    future_to_promise(async {
        Err(ScpWasmError::Permission {
            message: "UCAN delegation requires JS-side key custody (WebCrypto) — use the \
                      TypeScript SDK wrapper's delegateUcan() method which signs via SubtleCrypto"
                .to_owned(),
            code: codes::PERM_3000.to_owned(),
        }
        .into_js()
        .into())
    })
}

/// Validates a UCAN token for tool invocation authorization (WASM bridge).
///
/// Extracts capability from the token and verifies it includes `tool_invoke`
/// permission for the given `tool_id`. Uses scp-protocol's full 11-step UCAN
/// validation pipeline via extract-validate-writeback.
///
/// See spec §6.2, §8, ADR-016, and issue #319.
///
/// # Errors
///
/// Returns `(message, code)` where `message` is the human-readable failure
/// reason and `code` is the canonical `SCP-…` error code. UCAN parse errors
/// are routed through `scp_ffi_common::ucan_errors::ucan_error_code` so the
/// classification stays in lockstep with the other three bridges
/// (`OP_UCAN_VALIDATE_MALFORMED` parity gate). Non-parse failures (capability
/// URI, validation-pipeline, state lookup) return the caller's fallback code
/// as `None` — the caller decides which code envelope to wrap them in.
pub fn validate_tool_ucan_wasm(
    context_id: &str,
    tool_id: &str,
    token: &str,
    identity_did: &str,
) -> Result<(), (String, Option<&'static str>)> {
    let parsed = parse_ucan(token).map_err(|e| {
        // Route UCAN error classification through the shared mapping in
        // `scp_ffi_common::ucan_errors` (single-point-of-change contract
        // — today this maps to `PERM_3001`, but future refinements flow
        // from the helper rather than each parse site hardcoding it).
        let code = scp_ffi_common::ucan_errors::ucan_error_code(&e);
        (format!("malformed UCAN token: {e}"), Some(code))
    })?;

    // Build the required capability URI: scp:ctx:{context_id}/tool_invoke:{tool_id}
    let required_capability_str = format!("scp:ctx:{context_id}/tool_invoke:{tool_id}");
    let required_capability: CapabilityUri =
        required_capability_str.parse().map_err(|e: UcanError| {
            // Capability-URI parse failures share the same `UcanError`
            // classification surface as token parse failures, so route
            // them through the same helper for consistency.
            let code = scp_ffi_common::ucan_errors::ucan_error_code(&e);
            (format!("invalid capability URI: {e}"), Some(code))
        })?;

    run_validate_ucan(
        context_id,
        &parsed,
        &required_capability,
        identity_did,
        None,
    )
    .map_err(|msg| (msg, None))
}

/// Revokes a UCAN token with authorization checking.
///
/// Performs the UCAN revocation flow (ADR-016, subset per ADR-034):
///
/// 1. **Parse** -- Extracts the issuer DID from the token for authorization.
/// 2. **Authorization** -- Verifies the revoker is the token's issuer or the
///    context creator. Rejects unauthorized revocation attempts.
/// 3. **Local revocation** -- Computes the revocation CID from the full JWT
///    string (SHA-256 hex, via `scp_protocol::crypto::ucan::revoke::compute_revocation_cid`)
///    and delegates to `WasmContextManager::ucan_revoke` which adds it to
///    the context's revocation list and appends a `UcanRevoked` event to the
///    event log.
///
/// WASM uses a subset of the full pipeline per ADR-034: no MLS distribution
/// (WASM has no transport layer). Authorization is enforced locally.
///
/// # Arguments
///
/// * `context` — The context the token belongs to.
/// * `token` — The full encoded JWT string of the token to revoke.
/// * `revoker_did` — The DID of the entity requesting the revocation.
///
/// Closes #499.
#[wasm_bindgen]
pub fn ucan_revoke(context: &WasmContextHandle, token: String, revoker_did: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        validate_ucan_token(&token).map_err(|e| {
            JsValue::from(
                ScpWasmError::Validation {
                    message: e.to_string(),
                    code: codes::VALID_7010.to_owned(),
                }
                .into_js(),
            )
        })?;
        validate_did(&revoker_did).map_err(|e| {
            JsValue::from(
                ScpWasmError::Validation {
                    message: e.to_string(),
                    code: codes::VALID_7011.to_owned(),
                }
                .into_js(),
            )
        })?;

        // Parse the token to extract the issuer DID for authorization.
        // Route UCAN error classification through the shared mapping in
        // `scp_ffi_common::ucan_errors` so all four bridges stay in
        // lockstep (single-point-of-change contract — today this maps
        // to `PERM_3001`, but future refinements flow from the helper
        // rather than each parse site re-hardcoding the code).
        let parsed = parse_ucan(&token).map_err(|e| {
            let code = scp_ffi_common::ucan_errors::ucan_error_code(&e).to_owned();
            JsValue::from(
                ScpWasmError::Permission {
                    message: format!("malformed UCAN token: {e}"),
                    code,
                }
                .into_js(),
            )
        })?;

        // Authorization check: revoker must be issuer or context creator.
        let creator_did = with_manager(|mgr| {
            let (_, creator, _) = mgr.ucan_context_state(&context_id)?;
            Ok(creator)
        })
        .map_err(|e| JsValue::from(e.into_js()))?;

        if revoker_did != parsed.payload.iss && revoker_did != creator_did {
            return Err(JsValue::from(
                ScpWasmError::Permission {
                    message: format!(
                        "revoker '{}' is neither the token issuer ('{}') nor the context creator ('{}')",
                        revoker_did, parsed.payload.iss, creator_did
                    ),
                    code: codes::PERM_3008.to_owned(),
                }
                .into_js(),
            ));
        }

        // Compute the revocation CID from the full JWT string — uses
        // scp-protocol's compute_revocation_cid (hex-encoded SHA-256).
        let token_cid = compute_revocation_cid(&token);

        with_manager(|mgr| mgr.ucan_revoke(&context_id, &token_cid, &revoker_did))
            .map_err(|e| JsValue::from(e.into_js()))?;

        Ok(JsValue::UNDEFINED)
    })
}

// ---------------------------------------------------------------------------
// Tests (non-WASM target only — unit tests for pure-logic functions)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use scp_protocol::crypto::ucan::{Attenuation, UcanHeader, UcanPayload};
    use scp_protocol::trust::custody_violation::{ActionCategory, classify_action};
    use std::collections::HashSet;

    // -----------------------------------------------------------------------
    // extract_key_scope — tests use scp-protocol types directly
    // -----------------------------------------------------------------------

    /// Helper: extract key scope from a `UcanPayload` (mirrors
    /// scp-protocol's `extract_key_scope`, which is private).
    fn extract_key_scope(payload: &UcanPayload) -> Option<String> {
        payload
            .fct
            .as_ref()
            .and_then(|fct| fct.get("scp_key_scope"))
            .and_then(|v| v.as_str())
            .map(String::from)
    }

    #[test]
    fn extract_key_scope_returns_scope_when_present() {
        let payload = UcanPayload {
            iss: "did:dht:z6MkTest".to_owned(),
            aud: "did:dht:z6MkTest".to_owned(),
            exp: 0,
            nbf: None,
            nnc: String::new(),
            att: vec![],
            prf: vec![],
            fct: Some(serde_json::json!({"scp_key_scope": "#agent"})),
        };
        assert_eq!(extract_key_scope(&payload), Some("#agent".to_owned()));
    }

    #[test]
    fn extract_key_scope_returns_none_when_absent() {
        let payload = UcanPayload {
            iss: "did:dht:z6MkTest".to_owned(),
            aud: "did:dht:z6MkTest".to_owned(),
            exp: 0,
            nbf: None,
            nnc: String::new(),
            att: vec![],
            prf: vec![],
            fct: None,
        };
        assert_eq!(extract_key_scope(&payload), None);
    }

    #[test]
    fn extract_key_scope_returns_none_when_fct_has_no_key_scope() {
        let payload = UcanPayload {
            iss: "did:dht:z6MkTest".to_owned(),
            aud: "did:dht:z6MkTest".to_owned(),
            exp: 0,
            nbf: None,
            nnc: String::new(),
            att: vec![],
            prf: vec![],
            fct: Some(serde_json::json!({"other_fact": "value"})),
        };
        assert_eq!(extract_key_scope(&payload), None);
    }

    #[test]
    fn extract_key_scope_returns_none_when_scope_is_not_string() {
        let payload = UcanPayload {
            iss: "did:dht:z6MkTest".to_owned(),
            aud: "did:dht:z6MkTest".to_owned(),
            exp: 0,
            nbf: None,
            nnc: String::new(),
            att: vec![],
            prf: vec![],
            fct: Some(serde_json::json!({"scp_key_scope": 42})),
        };
        assert_eq!(extract_key_scope(&payload), None);
    }

    // -----------------------------------------------------------------------
    // UcanHeader serialization round-trip (uses scp-protocol types)
    // -----------------------------------------------------------------------

    #[test]
    fn ucan_header_kid_round_trip() -> Result<(), String> {
        let header = UcanHeader::with_kid("#agent".to_owned());
        let json = serde_json::to_string(&header).map_err(|e| e.to_string())?;
        assert!(json.contains("\"kid\":\"#agent\""));
        let parsed: UcanHeader = serde_json::from_str(&json).map_err(|e| e.to_string())?;
        assert_eq!(parsed.kid, Some("#agent".to_owned()));
        Ok(())
    }

    #[test]
    fn ucan_header_kid_absent_round_trip() -> Result<(), String> {
        let header = UcanHeader::new();
        let json = serde_json::to_string(&header).map_err(|e| e.to_string())?;
        assert!(!json.contains("kid"));
        let parsed: UcanHeader = serde_json::from_str(&json).map_err(|e| e.to_string())?;
        assert_eq!(parsed.kid, None);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // parse_ucan extracts kid from header (uses scp-protocol parse_ucan)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_ucan_extracts_kid_from_header() {
        let header = UcanHeader::with_kid("#agent".to_owned());
        let payload = UcanPayload {
            iss: "did:dht:z6MkTest".to_owned(),
            aud: "did:dht:z6MkOther".to_owned(),
            exp: 9_999_999_999,
            nbf: None,
            nnc: "test-nonce".to_owned(),
            att: vec![],
            prf: vec![],
            fct: None,
        };
        let header_json = serde_json::to_vec(&header).unwrap();
        let payload_json = serde_json::to_vec(&payload).unwrap();
        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
        let sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let jwt = format!("{header_b64}.{payload_b64}.{sig_b64}");

        let parsed = parse_ucan(&jwt).unwrap();
        assert_eq!(parsed.header.kid, Some("#agent".to_owned()));
    }

    #[test]
    fn parse_ucan_kid_none_when_absent() {
        let header = UcanHeader::new();
        let payload = UcanPayload {
            iss: "did:dht:z6MkTest".to_owned(),
            aud: "did:dht:z6MkOther".to_owned(),
            exp: 9_999_999_999,
            nbf: None,
            nnc: "test-nonce".to_owned(),
            att: vec![],
            prf: vec![],
            fct: None,
        };
        let header_json = serde_json::to_vec(&header).unwrap();
        let payload_json = serde_json::to_vec(&payload).unwrap();
        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
        let sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let jwt = format!("{header_b64}.{payload_b64}.{sig_b64}");

        let parsed = parse_ucan(&jwt).unwrap();
        assert_eq!(parsed.header.kid, None);
    }

    // -----------------------------------------------------------------------
    // Category A enforcement — uses scp-protocol's classify_action
    // -----------------------------------------------------------------------

    /// Category A resource types — tested via scp-protocol's `classify_action`.
    const CATEGORY_A_RESOURCES: &[&str] = &[
        "did_document",
        "verification_method",
        "identity",
        "pre_rotation",
        "service",
        "relay_config",
        "did_migration",
        "key_management",
    ];

    #[test]
    fn classify_action_correctly_identifies_category_a() {
        for resource in CATEGORY_A_RESOURCES {
            assert_eq!(
                classify_action(resource),
                ActionCategory::CategoryA,
                "resource '{resource}' should be Category A"
            );
        }
    }

    #[test]
    fn classify_action_category_b_for_standard_capabilities() {
        let category_b = [
            "messages",
            "tool_invoke",
            "member",
            "role",
            "context",
            "governance",
        ];
        for resource in &category_b {
            assert_eq!(
                classify_action(resource),
                ActionCategory::CategoryB,
                "resource '{resource}' should be Category B"
            );
        }
    }

    // -----------------------------------------------------------------------
    // CapabilityUri::matches() wildcard action (uses scp-protocol types)
    // -----------------------------------------------------------------------

    #[test]
    fn capability_matches_wildcard_action_grants_specific() {
        let granted = CapabilityUri::new("ctx-1", "tool_invoke", "*");
        let required = CapabilityUri::new("ctx-1", "tool_invoke", "calculator");
        assert!(
            granted.matches(&required),
            "wildcard action '*' should match specific action 'calculator'"
        );
    }

    #[test]
    fn capability_matches_wildcard_action_does_not_cross_resources() {
        let granted = CapabilityUri::new("ctx-1", "tool_invoke", "*");
        let required = CapabilityUri::new("ctx-1", "messages", "write");
        assert!(
            !granted.matches(&required),
            "wildcard on tool_invoke must not match messages resource"
        );
    }

    #[test]
    fn capability_matches_specific_does_not_satisfy_wildcard_requirement() {
        let granted = CapabilityUri::new("ctx-1", "tool_invoke", "calculator");
        let required = CapabilityUri::new("ctx-1", "tool_invoke", "*");
        assert!(
            !granted.matches(&required),
            "specific grant must not satisfy wildcard requirement"
        );
    }

    // -----------------------------------------------------------------------
    // Ceiling: default_ceiling from scp-protocol
    // -----------------------------------------------------------------------

    #[test]
    fn default_ceiling_contains_expected_capabilities() {
        let ceiling = default_ceiling().to_ucan_string_set();
        assert!(ceiling.contains("messages:read"), "missing messages:read");
        assert!(ceiling.contains("messages:write"), "missing messages:write");
        assert!(ceiling.contains("tool:register"), "missing tool:register");
        assert!(ceiling.contains("tool_invoke:*"), "missing tool_invoke:*");
        assert!(ceiling.contains("role:assign"), "missing role:assign");
        assert!(ceiling.contains("member:invite"), "missing member:invite");
        assert!(ceiling.contains("member:remove"), "missing member:remove");
        assert!(
            ceiling.contains("governance:propose"),
            "missing governance:propose"
        );
        assert!(
            ceiling.contains("governance:vote"),
            "missing governance:vote"
        );
        assert!(ceiling.contains("context:close"), "missing context:close");
    }

    // -----------------------------------------------------------------------
    // Ceiling wildcard fallback (uses scp-protocol's CapabilityUri)
    // -----------------------------------------------------------------------

    #[test]
    fn ceiling_wildcard_fallback_allows_specific_action() {
        let cap = CapabilityUri::new("ctx-1", "tool_invoke", "calculator");
        let ceiling: HashSet<String> = HashSet::from(["tool_invoke:*".to_owned()]);
        assert!(
            cap.is_within_ceiling(&ceiling),
            "ceiling with 'tool_invoke:*' should cover 'tool_invoke:calculator'"
        );
    }

    #[test]
    fn ceiling_wildcard_does_not_cross_resources() {
        let cap = CapabilityUri::new("ctx-1", "messages", "write");
        let ceiling: HashSet<String> = HashSet::from(["tool_invoke:*".to_owned()]);
        assert!(
            !cap.is_within_ceiling(&ceiling),
            "ceiling with 'tool_invoke:*' should not cover 'messages:write'"
        );
    }

    // -----------------------------------------------------------------------
    // Revocation CID — uses scp-protocol's compute_revocation_cid
    // -----------------------------------------------------------------------

    #[test]
    fn compute_revocation_cid_is_hex_sha256() {
        use sha2::{Digest, Sha256};
        let token = "header.payload.signature";
        let cid = compute_revocation_cid(token);
        let expected_hash = Sha256::digest(token.as_bytes());
        let expected_hex = expected_hash
            .iter()
            .fold(String::with_capacity(64), |mut acc, b| {
                use std::fmt::Write;
                let _ = write!(acc, "{b:02x}");
                acc
            });
        assert_eq!(cid, expected_hex);
    }

    // -----------------------------------------------------------------------
    // Proof CID — bafyrei prefix
    // -----------------------------------------------------------------------

    #[test]
    fn compute_proof_cid_has_bafyrei_prefix() {
        let token = "header.payload.signature";
        let cid = compute_proof_cid(token);
        assert!(
            cid.starts_with("bafyrei"),
            "proof CID must start with 'bafyrei'"
        );
        // The rest should be hex SHA-256 (64 chars)
        assert_eq!(cid.len(), 7 + 64, "bafyrei + 64 hex chars");
    }

    // -----------------------------------------------------------------------
    // E2E integration tests: real Ed25519 signatures
    //
    // These tests exercise the full scp-protocol validate_ucan pipeline with
    // real cryptographic operations (no empty signatures). They register
    // identities with agent keys in the WASM identity registry and produce
    // properly signed JWTs.
    //
    // Category A rejection fires at step 6b, before the time-dependent steps
    // (9: nonce, 11: time bounds), so these tests run on native targets
    // without requiring the WASM time module.
    //
    // See issue #1012.
    // -----------------------------------------------------------------------

    /// Helper: build a signed UCAN JWT from header/payload using the given
    /// signing key. Returns the encoded JWT string.
    fn build_signed_ucan(
        header: &UcanHeader,
        payload: &UcanPayload,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> String {
        use ed25519_dalek::Signer;

        let header_json = serde_json::to_vec(header).expect("header serialization");
        let payload_json = serde_json::to_vec(payload).expect("payload serialization");
        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        format!("{signing_input}.{sig_b64}")
    }

    /// Helper: verify Ed25519 signature of a parsed token using the WASM
    /// DID resolver, without running the full validation pipeline.
    fn verify_token_signature(token: &UcanToken) -> Result<(), String> {
        let resolver = WasmDidResolver;
        let pk_bytes = match &token.header.kid {
            Some(kid) => resolver
                .resolve_public_key_by_kid(&token.payload.iss, kid)
                .map_err(|e| e.to_string())?,
            None => resolver
                .resolve_public_key(&token.payload.iss)
                .map_err(|e| e.to_string())?,
        };

        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| format!("invalid public key: {e}"))?;

        let signing_input = token
            .encoded
            .rfind('.')
            .map(|pos| &token.encoded[..pos])
            .ok_or_else(|| "missing signature segment".to_owned())?;

        let sig_bytes: [u8; 64] =
            token.signature.as_slice().try_into().map_err(|_| {
                format!("signature must be 64 bytes, got {}", token.signature.len())
            })?;

        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        verifying_key
            .verify_strict(signing_input.as_bytes(), &signature)
            .map_err(|_| "signature verification failed".to_owned())
    }

    /// Helper: run the full scp-protocol validation pipeline with pre-extracted
    /// state (for tests that don't have a `WasmContextManager`).
    fn validate_with_extracted_state(
        token: &UcanToken,
        capability: &str,
        expected_aud_did: &str,
        ceiling: &HashSet<String>,
        creator_did: &str,
        revoked_cids: &HashSet<String>,
        proof_tokens: Option<&[String]>,
    ) -> Result<(), String> {
        let effective_ceiling = if ceiling.is_empty() {
            default_ceiling().to_ucan_string_set()
        } else {
            ceiling.clone()
        };

        let did_resolver = WasmDidResolver;
        let mut nonce_tracker = WasmNonceTracker::new(HashSet::new());
        let mut revocation_checker = InMemoryRevocationChecker::new();
        revocation_checker.revoked = revoked_cids.clone();

        let mut proof_resolver = InMemoryProofResolver::new();
        if let Some(proofs) = proof_tokens {
            for encoded in proofs {
                let parsed = parse_ucan(encoded).map_err(|e| e.to_string())?;
                let cid = compute_proof_cid(encoded);
                proof_resolver.proofs.insert(cid, parsed);
            }
        }

        let required_capability: CapabilityUri =
            capability.parse().map_err(|e: UcanError| e.to_string())?;

        let clock = WasmClock;

        let mut ctx = ValidationContext {
            did_resolver: &did_resolver,
            nonce_tracker: &mut nonce_tracker,
            revocation_checker: &revocation_checker,
            proof_resolver: &proof_resolver,
            ceiling: &effective_ceiling,
            context_creator_did: creator_did,
            presenting_agent_did: expected_aud_did,
            clock_skew_tolerance_secs:
                scp_protocol::crypto::ucan::validate::DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
            clock: &clock,
        };

        validate_ucan(token, &required_capability, &mut ctx).map_err(|e| e.to_string())
    }

    #[test]
    fn e2e_agent_signed_category_a_rejected_after_real_signature_verification() {
        crate::identity::test_helpers::cleanup_identity_registry();

        let (did, _identity_key, _active_key, agent_key) =
            crate::identity::test_helpers::register_identity_with_agent_key();

        let context_id = "test-ctx-e2e-catA";
        let header = UcanHeader::with_kid("#agent".to_owned());
        let payload = UcanPayload {
            iss: did.clone(),
            aud: did.clone(),
            exp: 9_999_999_999,
            nbf: None,
            nnc: "unused-nonce".to_owned(),
            att: vec![Attenuation {
                with: format!("scp:ctx:{context_id}/did_document:update"),
                can: "update".to_owned(),
            }],
            prf: vec![],
            fct: Some(serde_json::json!({"scp_key_scope": "#agent"})),
        };

        let jwt = build_signed_ucan(&header, &payload, &agent_key);
        let parsed = parse_ucan(&jwt).expect("JWT should parse");
        verify_token_signature(&parsed).expect("real Ed25519 signature must verify");

        let result = validate_with_extracted_state(
            &parsed,
            &format!("scp:ctx:{context_id}/did_document:update"),
            &did,
            &HashSet::new(),
            &did,
            &HashSet::new(),
            None,
        );

        assert!(
            result.is_err(),
            "Category A capability from #agent must be rejected"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("Category A") || err.contains("category a") || err.contains("CategoryA"),
            "expected Category A violation error, got: {err}"
        );
    }

    #[test]
    fn e2e_agent_signed_category_b_passes_signature_and_category_a_check() {
        crate::identity::test_helpers::cleanup_identity_registry();

        let (did, _identity_key, _active_key, agent_key) =
            crate::identity::test_helpers::register_identity_with_agent_key();

        let context_id = "test-ctx-e2e-catB";
        let header = UcanHeader::with_kid("#agent".to_owned());
        let payload = UcanPayload {
            iss: did.clone(),
            aud: did.clone(),
            exp: 9_999_999_999,
            nbf: None,
            nnc: "unused-nonce".to_owned(),
            att: vec![Attenuation {
                with: format!("scp:ctx:{context_id}/messages:write"),
                can: "write".to_owned(),
            }],
            prf: vec![],
            fct: Some(serde_json::json!({"scp_key_scope": "#agent"})),
        };

        let jwt = build_signed_ucan(&header, &payload, &agent_key);
        let parsed = parse_ucan(&jwt).expect("JWT should parse");
        verify_token_signature(&parsed).expect("real Ed25519 signature must verify");

        let result = validate_with_extracted_state(
            &parsed,
            &format!("scp:ctx:{context_id}/messages:write"),
            &did,
            &HashSet::new(),
            &did,
            &HashSet::new(),
            None,
        );

        // The pipeline should fail at step 9 (nonce format), NOT at step 6b.
        assert!(
            result.is_err(),
            "pipeline should fail at nonce validation (step 9)"
        );
        let err = result.unwrap_err();
        assert!(
            !err.to_lowercase().contains("category a"),
            "Category B capability should pass Category A check, but got: {err}"
        );
        assert!(
            err.to_lowercase().contains("nonce"),
            "expected nonce validation error (step 9), got: {err}"
        );
    }

    #[test]
    fn e2e_active_key_signed_category_a_passes_category_a_check() {
        crate::identity::test_helpers::cleanup_identity_registry();

        let (did, _identity_key, active_key, _agent_key) =
            crate::identity::test_helpers::register_identity_with_agent_key();

        let context_id = "test-ctx-e2e-active";
        let header = UcanHeader::with_kid("#active".to_owned());
        let payload = UcanPayload {
            iss: did.clone(),
            aud: did.clone(),
            exp: 9_999_999_999,
            nbf: None,
            nnc: "unused-nonce".to_owned(),
            att: vec![Attenuation {
                with: format!("scp:ctx:{context_id}/did_document:update"),
                can: "update".to_owned(),
            }],
            prf: vec![],
            fct: Some(serde_json::json!({"scp_key_scope": "#active"})),
        };

        // Sign with the distinct `#active` key (spec §3.2.1); the
        // verifier resolves `kid: "#active"` to this key. Signing with
        // `identity_key` (`#0`) here would produce a signature the
        // verifier rejects — which is the whole point of the two-key
        // model becoming a type-enforced invariant in `IdentityRecord`.
        let jwt = build_signed_ucan(&header, &payload, &active_key);
        let parsed = parse_ucan(&jwt).expect("JWT should parse");
        verify_token_signature(&parsed).expect("real Ed25519 signature must verify");

        // Pipeline should pass Category A (step 6b) because #active is allowed.
        // It will fail later at nonce validation (step 9).
        let ceiling: HashSet<String> = std::iter::once("did_document:update".to_owned()).collect();
        let result = validate_with_extracted_state(
            &parsed,
            &format!("scp:ctx:{context_id}/did_document:update"),
            &did,
            &ceiling,
            &did,
            &HashSet::new(),
            None,
        );

        assert!(result.is_err(), "pipeline should fail at nonce validation");
        let err = result.unwrap_err();
        assert!(
            !err.to_lowercase().contains("category a"),
            "#active key should pass Category A check, but got: {err}"
        );
        assert!(
            err.to_lowercase().contains("nonce"),
            "expected nonce validation error (step 9), got: {err}"
        );
    }

    #[test]
    fn e2e_invalid_signature_rejected_before_category_a() {
        crate::identity::test_helpers::cleanup_identity_registry();

        let (did, _identity_key, _active_key, agent_key) =
            crate::identity::test_helpers::register_identity_with_agent_key();

        let context_id = "test-ctx-e2e-badsig";
        let header = UcanHeader::with_kid("#agent".to_owned());
        let payload = UcanPayload {
            iss: did.clone(),
            aud: did.clone(),
            exp: 9_999_999_999,
            nbf: None,
            nnc: "unused-nonce".to_owned(),
            att: vec![Attenuation {
                with: format!("scp:ctx:{context_id}/did_document:update"),
                can: "update".to_owned(),
            }],
            prf: vec![],
            fct: Some(serde_json::json!({"scp_key_scope": "#agent"})),
        };

        let jwt = build_signed_ucan(&header, &payload, &agent_key);
        let parts: Vec<&str> = jwt.split('.').collect();
        let mut sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        sig_bytes[63] ^= 0xff;
        let corrupted_sig = URL_SAFE_NO_PAD.encode(&sig_bytes);
        let tampered_jwt = format!("{}.{}.{}", parts[0], parts[1], corrupted_sig);

        let parsed = parse_ucan(&tampered_jwt).expect("JWT should parse (format is valid)");

        let result = validate_with_extracted_state(
            &parsed,
            &format!("scp:ctx:{context_id}/did_document:update"),
            &did,
            &HashSet::new(),
            &did,
            &HashSet::new(),
            None,
        );

        assert!(result.is_err(), "tampered signature must be rejected");
        let err = result.unwrap_err();
        assert!(
            err.to_lowercase().contains("signature"),
            "expected signature error at step 2, got: {err}"
        );
    }

    #[test]
    fn e2e_all_category_a_resources_rejected_for_agent_key() {
        crate::identity::test_helpers::cleanup_identity_registry();

        let (did, _identity_key, _active_key, agent_key) =
            crate::identity::test_helpers::register_identity_with_agent_key();

        let context_id = "test-ctx-e2e-allcatA";

        for resource in CATEGORY_A_RESOURCES {
            let capability = format!("scp:ctx:{context_id}/{resource}:update");
            let header = UcanHeader::with_kid("#agent".to_owned());
            let payload = UcanPayload {
                iss: did.clone(),
                aud: did.clone(),
                exp: 9_999_999_999,
                nbf: None,
                nnc: "unused-nonce".to_owned(),
                att: vec![Attenuation {
                    with: capability.clone(),
                    can: "update".to_owned(),
                }],
                prf: vec![],
                fct: Some(serde_json::json!({"scp_key_scope": "#agent"})),
            };

            let jwt = build_signed_ucan(&header, &payload, &agent_key);
            let parsed = parse_ucan(&jwt).unwrap();

            verify_token_signature(&parsed)
                .unwrap_or_else(|e| panic!("signature must verify for resource '{resource}': {e}"));

            let result = validate_with_extracted_state(
                &parsed,
                &capability,
                &did,
                &HashSet::new(),
                &did,
                &HashSet::new(),
                None,
            );

            assert!(
                result.is_err(),
                "Category A resource '{resource}' must be rejected for #agent"
            );
            let err = result.unwrap_err();
            assert!(
                err.contains("Category A") || err.contains("CategoryA"),
                "expected Category A violation for '{resource}', got: {err}"
            );
        }
    }
}
