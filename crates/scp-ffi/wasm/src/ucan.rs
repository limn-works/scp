//! `wasm-bindgen` bridge for UCAN token management.
//!
//! Validation, nonce tracking, and revocation all delegate to
//! [`WasmContextManager`](crate::manager::WasmContextManager) for state
//! management. The 11-step UCAN validation pipeline is implemented in this
//! module (mirroring `scp-core/crypto/ucan/validate.rs`) because it requires
//! Ed25519 signature verification and delegation chain traversal which are
//! algorithm-level operations, not state management.
//!
//! See ADR-034 in `.docs/adrs/phase-4.md` and issue #389.

use std::collections::{HashMap, HashSet};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use js_sys::Promise;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use scp_ffi_common::validate::{validate_capability_uri, validate_did, validate_ucan_token};

use crate::context::WasmContextHandle;
use crate::error::ScpWasmError;
use crate::manager::with_manager;

/// Maximum token lifetime: 24 hours in seconds (spec section 9.5).
const MAX_EXPIRY_SECS: u64 = 24 * 60 * 60;

/// Maximum delegation chain depth to prevent infinite loops.
const MAX_CHAIN_DEPTH: usize = 32;

// ---------------------------------------------------------------------------
// UCAN data structures (mirrors scp-core/crypto/ucan/mod.rs)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UcanHeader {
    alg: String,
    typ: String,
    ucv: String,
}

impl UcanHeader {
    fn validate(&self) -> Result<(), String> {
        if self.alg != "EdDSA" {
            return Err(format!(
                "unsupported algorithm: expected EdDSA, got {}",
                self.alg
            ));
        }
        if self.ucv != "0.10.0" {
            return Err(format!(
                "unsupported UCAN version: expected 0.10.0, got {}",
                self.ucv
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Attenuation {
    with: String,
    can: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UcanPayload {
    iss: String,
    aud: String,
    exp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<u64>,
    nnc: String,
    att: Vec<Attenuation>,
    prf: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fct: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
struct ParsedUcanToken {
    header: UcanHeader,
    payload: UcanPayload,
    signature: Vec<u8>,
    encoded: String,
}

// ---------------------------------------------------------------------------
// Capability URI parsing (mirrors scp-core/crypto/ucan/capability.rs)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapabilityUri {
    context_id: Option<String>,
    resource: String,
    action: String,
}

impl CapabilityUri {
    fn parse(s: &str) -> Result<Self, String> {
        let rest = s
            .strip_prefix("scp:ctx:")
            .ok_or_else(|| format!("missing 'scp:ctx:' prefix in '{s}'"))?;

        let (ctx_part, capability_part) = rest
            .split_once('/')
            .ok_or_else(|| format!("missing '/' separator in '{s}'"))?;

        if ctx_part.is_empty() {
            return Err(format!("empty context ID in '{s}'"));
        }

        let context_id = if ctx_part == "*" {
            None
        } else {
            Some(ctx_part.to_owned())
        };

        let (resource, action) = capability_part
            .split_once(':')
            .ok_or_else(|| format!("missing ':' separator in capability '{s}'"))?;

        if resource.is_empty() {
            return Err(format!("empty resource in '{s}'"));
        }
        if action.is_empty() {
            return Err(format!("empty action in '{s}'"));
        }

        Ok(Self {
            context_id,
            resource: resource.to_owned(),
            action: action.to_owned(),
        })
    }

    fn capability_name(&self) -> String {
        format!("{}:{}", self.resource, self.action)
    }

    fn matches(&self, required: &Self) -> bool {
        if self.resource != required.resource || self.action != required.action {
            return false;
        }
        match (&self.context_id, &required.context_id) {
            (None, _) => true,
            (Some(granted), Some(req)) => granted == req,
            (Some(_), None) => false,
        }
    }

    fn matches_context_scope(with_str: &str, context_id: &str) -> bool {
        let context_prefix = format!("scp:ctx:{context_id}");
        with_str == context_prefix || with_str.starts_with(&format!("{context_prefix}/"))
    }
}

// ---------------------------------------------------------------------------
// UCAN parsing
// ---------------------------------------------------------------------------

fn parse_ucan(encoded: &str) -> Result<ParsedUcanToken, String> {
    let parts: Vec<&str> = encoded.split('.').collect();
    if parts.len() != 3 {
        return Err(format!("expected 3 JWT segments, got {}", parts.len()));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| format!("header base64url decode failed: {e}"))?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| format!("payload base64url decode failed: {e}"))?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| format!("signature base64url decode failed: {e}"))?;

    let header: UcanHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| format!("header deserialization failed: {e}"))?;

    let payload: UcanPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("payload deserialization failed: {e}"))?;

    header.validate()?;

    Ok(ParsedUcanToken {
        header,
        payload,
        signature: sig_bytes,
        encoded: encoded.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Revocation CID computation
// ---------------------------------------------------------------------------

/// Computes a revocation CID as the hex-encoded SHA-256 hash of the raw
/// encoded JWT string. This MUST match the algorithm in
/// `scp-core::crypto::ucan::revoke::compute_revocation_cid`.
fn compute_revocation_cid(encoded_token: &str) -> String {
    let hash = Sha256::digest(encoded_token.as_bytes());
    hash.iter().fold(String::with_capacity(64), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

// ---------------------------------------------------------------------------
// Ed25519 signature verification
// ---------------------------------------------------------------------------

fn resolve_public_key(did: &str) -> Result<[u8; 32], String> {
    if let Some(suffix) = did.strip_prefix("did:dht:z") {
        let decoded = zbase32_decode(suffix)
            .map_err(|e| format!("z-base-32 decode failed for DID {did}: {e}"))?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|v: Vec<u8>| format!("DID public key must be 32 bytes, got {}", v.len()))?;
        return Ok(bytes);
    }

    #[cfg(any(test, feature = "testing"))]
    if let Some(hex_str) = did.strip_prefix("did:key:") {
        let bytes =
            decode_hex(hex_str).map_err(|e| format!("hex decode failed for did:key DID: {e}"))?;
        let pk: [u8; 32] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| format!("DID public key must be 32 bytes, got {}", v.len()))?;
        return Ok(pk);
    }

    Err(format!("unsupported DID method: {did} (expected did:dht:)"))
}

fn verify_signature(token: &ParsedUcanToken) -> Result<(), String> {
    let pk_bytes = resolve_public_key(&token.payload.iss)?;

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| format!("invalid public key: {e}"))?;

    let signing_input = token
        .encoded
        .rfind('.')
        .map(|pos| &token.encoded[..pos])
        .ok_or_else(|| "missing signature segment".to_owned())?;

    let sig_bytes: [u8; 64] = token
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| format!("signature must be 64 bytes, got {}", token.signature.len()))?;

    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|_| "signature verification failed".to_owned())
}

// ---------------------------------------------------------------------------
// Hex / zbase32 helpers
// ---------------------------------------------------------------------------

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

fn encode_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

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

// ---------------------------------------------------------------------------
// Full 11-step validation pipeline (delegates state ops to WasmContextManager)
// ---------------------------------------------------------------------------

/// Parameters for the 11-step UCAN validation pipeline.
struct UcanValidationParams<'a> {
    token: &'a ParsedUcanToken,
    capability: &'a str,
    context_id: &'a str,
    expected_aud_did: &'a str,
    proof_tokens: Option<&'a [String]>,
    ceiling: &'a HashSet<String>,
    creator_did: &'a str,
    revoked_cids: &'a HashSet<String>,
}

#[allow(clippy::too_many_lines)]
fn validate_ucan_full(params: &UcanValidationParams<'_>) -> Result<(), String> {
    let UcanValidationParams {
        token,
        capability,
        context_id,
        expected_aud_did,
        proof_tokens,
        ceiling,
        creator_did,
        revoked_cids,
    } = params;
    // Step 1: Parse -- already done. Validate header.
    token.header.validate()?;

    // Step 2: Signature verification.
    verify_signature(token)?;

    // Step 3 + Step 4: Delegation chain verification -> root issuer must be creator.
    let root_issuer = verify_delegation_chain(token, *proof_tokens, revoked_cids)?;

    if root_issuer != *creator_did {
        return Err(format!(
            "invalid issuer: expected {creator_did}, got {root_issuer}"
        ));
    }

    // Step 5: Audience DID validation (RED-105 related).
    if token.payload.aud != *expected_aud_did {
        return Err(format!(
            "audience mismatch: expected {expected_aud_did}, got {}",
            token.payload.aud
        ));
    }

    // Step 6: Capability match with prefix-collision protection (RED-105 fix).
    let required_cap = CapabilityUri::parse(capability)?;

    let granted_caps: Vec<CapabilityUri> = token
        .payload
        .att
        .iter()
        .map(|att| {
            if !CapabilityUri::matches_context_scope(&att.with, context_id) {
                return Err(format!(
                    "capability '{}' does not match context '{context_id}' (prefix collision prevented)",
                    att.with
                ));
            }
            CapabilityUri::parse(&att.with)
                .map_err(|e| format!("unparseable capability URI in attestation: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let matched = granted_caps.iter().any(|cap| cap.matches(&required_cap));
    if !matched {
        return Err(format!("capability not granted: {capability}"));
    }

    // Step 7: Attenuation enforcement.
    if !token.payload.prf.is_empty() {
        verify_attenuation(token, *proof_tokens)?;
    }

    // Step 8: Capability ceiling check.
    let cap_name = required_cap.capability_name();
    if !ceiling.is_empty() && !ceiling.contains(&cap_name) {
        return Err(format!("capability outside ceiling: {cap_name}"));
    }

    // Step 9: Nonce replay detection — delegated to WasmContextManager.
    if token.payload.nnc.is_empty() {
        return Err("nonce is empty".to_owned());
    }
    with_manager(|mgr| mgr.ucan_record_nonce(context_id, &token.payload.nnc))
        .map_err(|e| e.to_string())?;

    // Step 10: Revocation check.
    let revocation_cid = compute_revocation_cid(&token.encoded);
    if revoked_cids.contains(&revocation_cid) {
        return Err(format!("token revoked: {revocation_cid}"));
    }

    // Step 11: Time bounds (expiry + not-before).
    verify_time_bounds(token)?;

    Ok(())
}

fn verify_time_bounds(token: &ParsedUcanToken) -> Result<(), String> {
    let now = now_secs();

    if let Some(nbf) = token.payload.nbf {
        if now < nbf {
            return Err("token not yet valid (nbf > now)".to_owned());
        }
        if nbf >= token.payload.exp {
            return Err(format!(
                "invalid time range: nbf ({nbf}) must be less than exp ({})",
                token.payload.exp
            ));
        }
    }

    if now >= token.payload.exp {
        return Err("token expired".to_owned());
    }

    if token.payload.exp > now + MAX_EXPIRY_SECS {
        return Err(format!(
            "expiry too far in the future: {}s exceeds 24h maximum",
            token.payload.exp - now
        ));
    }

    Ok(())
}

fn verify_delegation_chain(
    token: &ParsedUcanToken,
    proof_tokens: Option<&[String]>,
    revoked_cids: &HashSet<String>,
) -> Result<String, String> {
    if token.payload.prf.is_empty() {
        return Ok(token.payload.iss.clone());
    }

    let proofs = proof_tokens.unwrap_or(&[]);

    let mut proof_map: HashMap<String, ParsedUcanToken> = HashMap::new();
    for encoded in proofs {
        let parsed = parse_ucan(encoded)?;
        let cid = compute_token_cid(encoded);
        proof_map.insert(cid, parsed);
    }

    let mut seen_issuers = HashSet::new();
    seen_issuers.insert(token.payload.iss.clone());

    verify_chain_recursive(token, &proof_map, revoked_cids, 0, &mut seen_issuers)
}

fn verify_chain_recursive(
    token: &ParsedUcanToken,
    proof_map: &HashMap<String, ParsedUcanToken>,
    revoked_cids: &HashSet<String>,
    depth: usize,
    seen_issuers: &mut HashSet<String>,
) -> Result<String, String> {
    if depth > MAX_CHAIN_DEPTH {
        return Err("delegation chain too deep".to_owned());
    }

    if token.payload.prf.is_empty() {
        verify_signature(token)?;
        return Ok(token.payload.iss.clone());
    }

    let mut root_issuer = None;
    for proof_cid in &token.payload.prf {
        let parent = proof_map
            .get(proof_cid)
            .ok_or_else(|| format!("delegation chain broken: proof CID not found: {proof_cid}"))?;

        if !seen_issuers.insert(parent.payload.iss.clone()) {
            return Err(format!(
                "circular delegation detected: issuer '{}' appears multiple times in the delegation chain",
                parent.payload.iss
            ));
        }

        verify_signature(parent)?;

        if parent.payload.aud != token.payload.iss {
            return Err(format!(
                "delegation chain broken: parent aud '{}' does not match child iss '{}'",
                parent.payload.aud, token.payload.iss
            ));
        }

        verify_time_bounds(parent)?;

        let parent_revocation_cid = compute_revocation_cid(&parent.encoded);
        if revoked_cids.contains(&parent_revocation_cid) {
            return Err(format!("token revoked: {parent_revocation_cid}"));
        }

        let found_root =
            verify_chain_recursive(parent, proof_map, revoked_cids, depth + 1, seen_issuers)?;

        if let Some(ref existing_root) = root_issuer {
            if *existing_root != found_root {
                return Err(format!(
                    "divergent root issuers: '{existing_root}' and '{found_root}'"
                ));
            }
        } else {
            root_issuer = Some(found_root);
        }
    }

    root_issuer.ok_or_else(|| "delegation chain empty".to_owned())
}

fn verify_attenuation(
    token: &ParsedUcanToken,
    proof_tokens: Option<&[String]>,
) -> Result<(), String> {
    let proofs = proof_tokens.unwrap_or(&[]);

    let mut proof_map: HashMap<String, ParsedUcanToken> = HashMap::new();
    for encoded in proofs {
        let parsed = parse_ucan(encoded)?;
        let cid = compute_token_cid(encoded);
        proof_map.insert(cid, parsed);
    }

    for proof_cid in &token.payload.prf {
        let parent = proof_map
            .get(proof_cid)
            .ok_or_else(|| format!("attenuation check failed: proof CID not found: {proof_cid}"))?;

        let parent_caps: Vec<CapabilityUri> = parent
            .payload
            .att
            .iter()
            .map(|att| {
                CapabilityUri::parse(&att.with)
                    .map_err(|e| format!("unparseable capability URI in parent attestation: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        for child_att in &token.payload.att {
            let child_cap = CapabilityUri::parse(&child_att.with)
                .map_err(|e| format!("unparseable child capability: {e}"))?;

            let is_subset = parent_caps
                .iter()
                .any(|parent_cap| parent_cap.matches(&child_cap));
            if !is_subset {
                return Err(format!(
                    "attenuation violation: child capability '{}' not granted by parent",
                    child_att.with
                ));
            }
        }
    }

    Ok(())
}

fn compute_token_cid(encoded: &str) -> String {
    let hash = Sha256::digest(encoded.as_bytes());
    format!("bafyrei{}", encode_hex(&hash))
}

fn now_secs() -> u64 {
    let now = js_sys::Date::now();
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    {
        (now / 1000.0) as u64
    }
}

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
    #[must_use]
    #[wasm_bindgen(getter, js_name = "tokenId")]
    pub fn token_id(&self) -> String {
        self.token_id.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn issuer(&self) -> String {
        self.issuer.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn audience(&self) -> String {
        self.audience.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = "capabilitiesJson")]
    pub fn capabilities_json(&self) -> String {
        self.capabilities_json.clone()
    }

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
/// Performs the full 11-step UCAN validation pipeline from ADR-016.
/// State operations (nonce tracking, revocation lists, ceiling) are
/// delegated to `WasmContextManager`.
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
            ScpWasmError::Permission {
                message: format!("malformed token: {e}"),
                code: "SCP-PERM-3000".to_owned(),
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
                        code: "SCP-VALID-7000".to_owned(),
                    }
                    .into_js()
                })?;
                Some(arr)
            }
            None => None,
        };

        // Read ceiling, creator_did, and revoked CIDs from WasmContextManager.
        let (ceiling, creator_did, _seen_nonces, revoked_cids) =
            with_manager(|mgr| mgr.ucan_context_state(&context_id)).map_err(|e| {
                ScpWasmError::Permission {
                    message: e.to_string(),
                    code: "SCP-PERM-3000".to_owned(),
                }
                .into_js()
            })?;

        validate_ucan_full(&UcanValidationParams {
            token: &parsed,
            capability: &capability,
            context_id: &context_id,
            expected_aud_did: &expected_aud_did,
            proof_tokens: proof_tokens.as_deref(),
            ceiling: &ceiling,
            creator_did: &creator_did,
            revoked_cids: &revoked_cids,
        })
        .map_err(|e| {
            ScpWasmError::Permission {
                message: e,
                code: "SCP-PERM-3000".to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::UNDEFINED)
    })
}

/// Mints a new UCAN token for a context member.
///
/// Validates capability URIs and returns an error since UCAN minting
/// requires key custody (`WebCrypto`), which is managed by the TypeScript SDK.
/// The bridge validates inputs; the TS wrapper signs.
#[wasm_bindgen]
pub fn ucan_mint(
    context: &WasmContextHandle,
    member_did: String,
    capabilities_json: String,
) -> Promise {
    if let Err(e) = validate_did(&member_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = context.context_id();
    future_to_promise(async move {
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

        let cap_strings: Vec<String> = caps
            .as_array()
            .ok_or_else(|| {
                ScpWasmError::Validation {
                    message: "capabilities_json must be a JSON array".to_owned(),
                    code: "SCP-VALID-7000".to_owned(),
                }
                .into_js()
            })?
            .iter()
            .map(|v: &serde_json::Value| {
                v.as_str().map(str::to_owned).ok_or_else(|| {
                    ScpWasmError::Validation {
                        message: format!("invalid capability: expected string, got {v}"),
                        code: "SCP-VALID-7000".to_owned(),
                    }
                    .into_js()
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        for cap in &cap_strings {
            CapabilityUri::parse(cap).map_err(|e| {
                ScpWasmError::Validation {
                    message: format!("invalid capability URI '{cap}': {e}"),
                    code: "SCP-VALID-7000".to_owned(),
                }
                .into_js()
            })?;
        }

        // Verify context exists and member is valid.
        with_manager(|mgr| {
            if !mgr.has_context(&context_id) {
                return Err(ScpWasmError::Context {
                    message: format!("context '{context_id}' not found"),
                    code: "SCP-CTX-2001".to_owned(),
                });
            }
            Ok(())
        })
        .map_err(ScpWasmError::into_js)?;

        let _ = member_did;

        // UCAN minting requires key custody (WebCrypto), which is managed by
        // the TypeScript SDK wrapper. The bridge validates inputs; the TS
        // wrapper signs the token using SubtleCrypto.
        Err(ScpWasmError::Permission {
            message: "UCAN minting requires JS-side key custody (WebCrypto) — use the TypeScript \
                      SDK wrapper's mintUcan() method which signs via SubtleCrypto"
                .to_owned(),
            code: "SCP-PERM-3000".to_owned(),
        }
        .into_js()
        .into())
    })
}

/// Validates a UCAN token for tool invocation authorization (WASM bridge).
///
/// Extracts capability from the token and verifies it includes `tool_invoke`
/// permission for the given `tool_id`. Uses the WASM-local 11-step UCAN
/// validation pipeline.
///
/// See spec §6.2, §8, ADR-016, and issue #319.
///
/// # Errors
///
/// Returns an error string if the UCAN token is malformed, the context state
/// cannot be retrieved, or the 11-step validation pipeline rejects the token.
pub fn validate_tool_ucan_wasm(
    context_id: &str,
    tool_id: &str,
    token: &str,
    identity_did: &str,
) -> Result<(), String> {
    let parsed = parse_ucan(token).map_err(|e| format!("malformed UCAN token: {e}"))?;

    // Build the required capability URI: scp:ctx:{context_id}/tool_invoke:{tool_id}
    let required_capability = format!("scp:ctx:{context_id}/tool_invoke:{tool_id}");

    // Read ceiling, creator_did, and revoked CIDs from WasmContextManager.
    let (ceiling, creator_did, _seen_nonces, revoked_cids) =
        with_manager(|mgr| mgr.ucan_context_state(context_id))
            .map_err(|e| format!("failed to get UCAN context state: {e}"))?;

    validate_ucan_full(&UcanValidationParams {
        token: &parsed,
        capability: &required_capability,
        context_id,
        expected_aud_did: identity_did,
        proof_tokens: None,
        ceiling: &ceiling,
        creator_did: &creator_did,
        revoked_cids: &revoked_cids,
    })
}

/// Revokes a UCAN token.
///
/// Delegates to `WasmContextManager::ucan_revoke`. Computes the revocation
/// CID from the full JWT string (SHA-256 hex) and adds it to the context's
/// revocation list. This MUST use `compute_revocation_cid` (not
/// `compute_token_cid`) to match the format used in `ucan_validate` step 10.
#[wasm_bindgen]
pub fn ucan_revoke(context: &WasmContextHandle, token: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        // Compute the revocation CID from the full JWT string — matches
        // validation step 10.
        let token_cid = compute_revocation_cid(&token);

        with_manager(|mgr| mgr.ucan_revoke(&context_id, &token_cid))
            .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::UNDEFINED)
    })
}
