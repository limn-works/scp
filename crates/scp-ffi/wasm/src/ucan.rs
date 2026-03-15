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

/// Nonce freshness tolerance: 5 minutes in milliseconds (spec section 9.14).
/// Matches native `NonceTracker::NONCE_FRESHNESS_TOLERANCE_MS`.
const NONCE_FRESHNESS_TOLERANCE_MS: u64 = 5 * 60 * 1000;

/// Maximum delegation chain depth to prevent infinite loops.
const MAX_CHAIN_DEPTH: usize = 32;

/// Clock skew tolerance in seconds (spec section 9.14). Accommodates NTP
/// desynchronization between issuer and validator in distributed deployments.
/// Must match `scp-core::crypto::ucan::validate::DEFAULT_CLOCK_SKEW_TOLERANCE_SECS`.
const CLOCK_SKEW_TOLERANCE_SECS: u64 = 300;

/// Category A resource types — the closed set of UCAN capability resource
/// types that modify the DID document (ADR-039).
///
/// Must match `scp-core::trust::custody_violation::CATEGORY_A_RESOURCES`.
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

// ---------------------------------------------------------------------------
// UCAN data structures (mirrors scp-core/crypto/ucan/mod.rs)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UcanHeader {
    alg: String,
    typ: String,
    ucv: String,
    /// Optional Key ID per RFC 7515 (ADR-039). Identifies which verification
    /// method on the issuer's DID document signed this token. Values are
    /// verification method fragment identifiers: `"#active"` for the human
    /// signing key, `"#agent"` for the agent signing key. When absent,
    /// verifiers default to `#active`.
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
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

/// Resolves a specific verification method key by `kid` fragment identifier
/// (ADR-039, SCP-AB-013). Dispatches to the identity registry for kid-specific
/// resolution, falling back to DID-embedded key resolution for `#active`.
///
/// Must match `scp-core::crypto::ucan::validate::DidResolver::resolve_public_key_by_kid`.
fn resolve_public_key_by_kid(did: &str, kid: &str) -> Result<[u8; 32], String> {
    // Try the identity registry first — it has both #active and #agent keys.
    match crate::identity::resolve_verification_method_key(did, kid) {
        Ok(pk) => return Ok(pk),
        Err(_) if kid == "#active" => {
            // Fall through to DID-embedded key extraction for #active when the
            // DID is not in the local registry (e.g., remote DIDs).
        }
        Err(e) => return Err(e),
    }

    // For #active, fall back to extracting the key from the DID string itself
    // (works for remote DIDs not in the local registry).
    resolve_public_key(did)
}

fn verify_signature(token: &ParsedUcanToken) -> Result<(), String> {
    // When kid is present in the header, resolve the specific verification
    // method from the DID document (ADR-039, SCP-AB-013).
    let pk_bytes = match &token.header.kid {
        Some(kid) => resolve_public_key_by_kid(&token.payload.iss, kid)?,
        None => resolve_public_key(&token.payload.iss)?,
    };

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
// Steps 5a/5b: Key scope validation (ADR-039, SCP-AB-013)
// ---------------------------------------------------------------------------

/// Extracts the `scp_key_scope` value from a UCAN payload's facts.
///
/// Returns `Some(scope)` if `fct.scp_key_scope` exists and is a string,
/// `None` otherwise (backward compatibility — legacy tokens without key
/// scope skip step 5b).
///
/// Must match `scp-core::crypto::ucan::validate::extract_key_scope`.
fn extract_key_scope(payload: &UcanPayload) -> Option<String> {
    payload
        .fct
        .as_ref()
        .and_then(|fct| fct.get("scp_key_scope"))
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Validates key scope constraints on a UCAN token (steps 5a and 5b).
///
/// - **Step 5a (self-delegation):** If `iss == aud` and no `scp_key_scope`
///   is present in `fct`, the token is rejected. Self-delegation is only
///   meaningful when scoping to a specific verification method.
///
/// - **Step 5b (key scope match):** If `fct.scp_key_scope` is present, the
///   `kid` header (defaulting to `#active` when absent) must match the
///   declared scope.
///
/// Must match `scp-core::crypto::ucan::validate::validate_key_scope`.
fn validate_key_scope(token: &ParsedUcanToken) -> Result<(), String> {
    let key_scope = extract_key_scope(&token.payload);

    // Step 5a: Self-delegation without key_scope is a safety violation.
    if token.payload.iss == token.payload.aud && key_scope.is_none() {
        return Err(
            "self-delegation (iss == aud) without scp_key_scope is not permitted".to_owned(),
        );
    }

    // Step 5b: If key_scope is present, verify kid matches.
    if let Some(ref scope) = key_scope {
        let actual_kid = token.header.kid.as_deref().unwrap_or("#active");
        if actual_kid != scope {
            return Err(format!(
                "key scope mismatch: token declares scp_key_scope '{scope}' but kid is '{actual_kid}'"
            ));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 6b: Category A enforcement (ADR-039)
// ---------------------------------------------------------------------------

/// Enforces Category A restrictions on a UCAN token (ADR-039 Enforcement
/// Stack layer 3).
///
/// If the token is signed by `#agent` (indicated by the `kid` header field)
/// and any granted capability is a Category A action (DID document
/// modification), the token is rejected.
///
/// Must match `scp-core::crypto::ucan::validate::enforce_ucan_category_a`.
fn enforce_ucan_category_a(
    token: &ParsedUcanToken,
    granted_caps: &[CapabilityUri],
) -> Result<(), String> {
    let kid_str = token.header.kid.as_deref().unwrap_or("#active");

    // Only #active and #agent are valid UCAN signing keys.
    // Unknown kid values are rejected fail-closed.
    let is_agent = match kid_str {
        "#active" => false,
        "#agent" => true,
        _ => {
            return Err(format!("unrecognized signing key ID (kid): {kid_str}"));
        }
    };

    if !is_agent {
        return Ok(());
    }

    for cap in granted_caps {
        if CATEGORY_A_RESOURCES.contains(&cap.resource.as_str()) {
            return Err(format!(
                "Category A violation: agent key (#agent) cannot grant '{}' capability",
                cap.capability_name()
            ));
        }
    }

    Ok(())
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

    // Steps 5a/5b: Key scope validation (ADR-039, SCP-AB-013).
    // Rejects self-delegation without key_scope and key_scope/kid mismatches.
    validate_key_scope(token)?;

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

    // Step 6b: Category A enforcement (ADR-039 Enforcement Stack layer 3).
    // If the token is signed by #agent, reject any Category A capabilities
    // (DID document modifications, pre-rotation, identity migration).
    enforce_ucan_category_a(token, &granted_caps)?;

    // Step 7: Attenuation enforcement.
    if !token.payload.prf.is_empty() {
        verify_attenuation(token, *proof_tokens)?;
    }

    // Step 8: Capability ceiling check.
    let cap_name = required_cap.capability_name();
    if !ceiling.is_empty() && !ceiling.contains(&cap_name) {
        return Err(format!("capability outside ceiling: {cap_name}"));
    }

    // Step 9: Nonce validation and replay detection.
    //
    // Mirrors scp-core's `NonceTracker::check_and_record` (ADR-016 §7.2):
    //   1. Format: `{unix_millis}-{32_hex_chars}`
    //   2. Freshness: timestamp within now +/- 5 minutes (spec §9.14)
    //   3. Uniqueness: not previously seen (delegated to WasmContextManager)
    validate_nonce_format_and_freshness(&token.payload.nnc)?;
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
    // Check nbf < exp first — a token with nbf >= exp is inherently invalid
    // regardless of the current time or tolerance.
    if let Some(nbf) = token.payload.nbf
        && nbf >= token.payload.exp
    {
        return Err(format!(
            "invalid time range: nbf ({nbf}) must be less than exp ({})",
            token.payload.exp
        ));
    }

    let now = now_secs();

    // exp check with tolerance: allow tokens that expired within the tolerance
    // window. `exp + tolerance <= now` means the token is expired beyond the
    // tolerance. Must match scp-core's `verify_expiry` logic.
    if token.payload.exp + CLOCK_SKEW_TOLERANCE_SECS <= now {
        return Err("token expired".to_owned());
    }

    // ExpiryTooFar check — no tolerance applied. This bounds the maximum token
    // lifetime; clock drift doesn't justify longer-lived tokens.
    if token.payload.exp > now + MAX_EXPIRY_SECS {
        return Err(format!(
            "expiry too far in the future: {}s exceeds 24h maximum",
            token.payload.exp - now
        ));
    }

    // nbf check with tolerance: allow tokens whose not-before is slightly in
    // the future (within tolerance). Uses saturating subtraction to avoid
    // underflow when nbf < tolerance. Must match scp-core's logic.
    if let Some(nbf) = token.payload.nbf
        && nbf.saturating_sub(CLOCK_SKEW_TOLERANCE_SECS) > now
    {
        return Err("token not yet valid (nbf > now)".to_owned());
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

        // Verify parent's aud matches this token's iss.
        // Must match scp-core's verify_chain_recursive ordering.
        if parent.payload.aud != token.payload.iss {
            return Err(format!(
                "delegation chain broken: parent aud '{}' does not match child iss '{}'",
                parent.payload.aud, token.payload.iss
            ));
        }

        // Steps 5a/5b: Validate key scope on parent token (ADR-039, SCP-AB-013).
        // An attacker could craft a parent with iss==aud and no key_scope that
        // would pass chain checks if only the presented token were validated.
        validate_key_scope(parent)?;

        verify_signature(parent)?;

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
    crate::time::now_secs()
}

/// Validates UCAN nonce format and freshness, matching scp-core's
/// `NonceTracker::check_and_record` (steps 1–2).
///
/// Format: `{unix_millis_timestamp}-{32_hex_chars}` (ADR-016 §7.2).
/// Freshness: timestamp within now +/- 5 minutes (spec §9.14).
///
/// Uniqueness (step 3) is handled separately by `WasmContextManager::ucan_record_nonce`.
fn validate_nonce_format_and_freshness(nonce: &str) -> Result<(), String> {
    if nonce.is_empty() {
        return Err("nonce is empty".to_owned());
    }

    // 1. Format: split into timestamp and hex suffix.
    let (ts_part, hex_part) = nonce
        .split_once('-')
        .ok_or_else(|| format!("nonce format invalid: missing '-' separator in '{nonce}'"))?;

    let nonce_millis: u64 = ts_part
        .parse()
        .map_err(|_| format!("nonce format invalid: non-numeric timestamp in '{ts_part}'"))?;

    if hex_part.len() != 32 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "nonce format invalid: expected 32 hex chars suffix, got '{hex_part}'"
        ));
    }

    // 2. Freshness: timestamp within now +/- 5 minutes.
    let now = crate::time::now_ms_u64();

    if nonce_millis.saturating_add(NONCE_FRESHNESS_TOLERANCE_MS) < now {
        return Err(format!("nonce too old: {nonce}"));
    }

    if nonce_millis > now.saturating_add(NONCE_FRESHNESS_TOLERANCE_MS) {
        return Err(format!("nonce too far in the future: {nonce}"));
    }

    Ok(())
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
        let (ceiling, creator_did, revoked_cids) =
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
///
/// # Errors
///
/// Returns `SCP-VALID-7000` if `member_did` fails [`validate_did`]
/// (empty, malformed `did:{method}:{id}` format, or control characters),
/// or if `capabilities_json` is not a valid JSON array of capability URI
/// strings.
///
/// Returns `SCP-CTX-2001` if the context is not found.
///
/// Returns `SCP-PERM-3000` since UCAN minting requires JS-side key custody.
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
    let (ceiling, creator_did, revoked_cids) =
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

/// Revokes a UCAN token with authorization checking.
///
/// Performs the UCAN revocation flow (ADR-016, subset per ADR-034):
///
/// 1. **Parse** -- Extracts the issuer DID from the token for authorization.
/// 2. **Authorization** -- Verifies the revoker is the token's issuer or the
///    context creator. Rejects unauthorized revocation attempts.
/// 3. **Local revocation** -- Computes the revocation CID from the full JWT
///    string (SHA-256 hex) and delegates to `WasmContextManager::ucan_revoke`
///    which adds it to the context's revocation list and appends a
///    `UcanRevoked` event to the event log.
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
                    code: "SCP-VALID-7010".to_owned(),
                }
                .into_js(),
            )
        })?;
        validate_did(&revoker_did).map_err(|e| {
            JsValue::from(
                ScpWasmError::Validation {
                    message: e.to_string(),
                    code: "SCP-VALID-7011".to_owned(),
                }
                .into_js(),
            )
        })?;

        // Parse the token to extract the issuer DID for authorization.
        let parsed = parse_ucan(&token).map_err(|e| {
            JsValue::from(
                ScpWasmError::Permission {
                    message: format!("malformed UCAN token: {e}"),
                    code: "SCP-PERM-3001".to_owned(),
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
                    code: "SCP-PERM-3008".to_owned(),
                }
                .into_js(),
            ));
        }

        // Compute the revocation CID from the full JWT string — matches
        // validation step 10.
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

    // -----------------------------------------------------------------------
    // extract_key_scope
    // -----------------------------------------------------------------------

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
    // Step 5a: Self-delegation rejection
    // -----------------------------------------------------------------------

    #[test]
    fn validate_key_scope_rejects_self_delegation_without_scope() {
        let token = ParsedUcanToken {
            header: UcanHeader {
                alg: "EdDSA".to_owned(),
                typ: "JWT".to_owned(),
                ucv: "0.10.0".to_owned(),
                kid: None,
            },
            payload: UcanPayload {
                iss: "did:dht:z6MkSame".to_owned(),
                aud: "did:dht:z6MkSame".to_owned(),
                exp: 9_999_999_999,
                nbf: None,
                nnc: "test".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![],
            encoded: String::new(),
        };
        let result = validate_key_scope(&token);
        assert!(result.is_err());
        let err = result.err().unwrap_or_default();
        assert!(
            err.contains("self-delegation"),
            "expected self-delegation error, got: {err}"
        );
    }

    #[test]
    fn validate_key_scope_accepts_self_delegation_with_scope() {
        let token = ParsedUcanToken {
            header: UcanHeader {
                alg: "EdDSA".to_owned(),
                typ: "JWT".to_owned(),
                ucv: "0.10.0".to_owned(),
                kid: Some("#agent".to_owned()),
            },
            payload: UcanPayload {
                iss: "did:dht:z6MkSame".to_owned(),
                aud: "did:dht:z6MkSame".to_owned(),
                exp: 9_999_999_999,
                nbf: None,
                nnc: "test".to_owned(),
                att: vec![],
                prf: vec![],
                fct: Some(serde_json::json!({"scp_key_scope": "#agent"})),
            },
            signature: vec![],
            encoded: String::new(),
        };
        let result = validate_key_scope(&token);
        assert!(
            result.is_ok(),
            "self-delegation with key_scope should be accepted: {result:?}"
        );
    }

    #[test]
    fn validate_key_scope_accepts_different_iss_aud_without_scope() {
        let token = ParsedUcanToken {
            header: UcanHeader {
                alg: "EdDSA".to_owned(),
                typ: "JWT".to_owned(),
                ucv: "0.10.0".to_owned(),
                kid: None,
            },
            payload: UcanPayload {
                iss: "did:dht:z6MkIssuer".to_owned(),
                aud: "did:dht:z6MkAudience".to_owned(),
                exp: 9_999_999_999,
                nbf: None,
                nnc: "test".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![],
            encoded: String::new(),
        };
        let result = validate_key_scope(&token);
        assert!(
            result.is_ok(),
            "different iss/aud without scope should be accepted: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Step 5b: Key scope / kid mismatch
    // -----------------------------------------------------------------------

    #[test]
    fn validate_key_scope_rejects_kid_scope_mismatch() {
        let token = ParsedUcanToken {
            header: UcanHeader {
                alg: "EdDSA".to_owned(),
                typ: "JWT".to_owned(),
                ucv: "0.10.0".to_owned(),
                kid: Some("#active".to_owned()),
            },
            payload: UcanPayload {
                iss: "did:dht:z6MkSame".to_owned(),
                aud: "did:dht:z6MkSame".to_owned(),
                exp: 9_999_999_999,
                nbf: None,
                nnc: "test".to_owned(),
                att: vec![],
                prf: vec![],
                fct: Some(serde_json::json!({"scp_key_scope": "#agent"})),
            },
            signature: vec![],
            encoded: String::new(),
        };
        let result = validate_key_scope(&token);
        assert!(result.is_err());
        let err = result.err().unwrap_or_default();
        assert!(
            err.contains("key scope mismatch"),
            "expected key scope mismatch error, got: {err}"
        );
    }

    #[test]
    fn validate_key_scope_defaults_kid_to_active() {
        // kid absent, scope declares #active — should match (default kid = #active)
        let token = ParsedUcanToken {
            header: UcanHeader {
                alg: "EdDSA".to_owned(),
                typ: "JWT".to_owned(),
                ucv: "0.10.0".to_owned(),
                kid: None,
            },
            payload: UcanPayload {
                iss: "did:dht:z6MkSame".to_owned(),
                aud: "did:dht:z6MkSame".to_owned(),
                exp: 9_999_999_999,
                nbf: None,
                nnc: "test".to_owned(),
                att: vec![],
                prf: vec![],
                fct: Some(serde_json::json!({"scp_key_scope": "#active"})),
            },
            signature: vec![],
            encoded: String::new(),
        };
        let result = validate_key_scope(&token);
        assert!(
            result.is_ok(),
            "kid defaults to #active, matching scope: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Step 6b: Category A enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn enforce_category_a_rejects_agent_with_did_document_cap() {
        let token = ParsedUcanToken {
            header: UcanHeader {
                alg: "EdDSA".to_owned(),
                typ: "JWT".to_owned(),
                ucv: "0.10.0".to_owned(),
                kid: Some("#agent".to_owned()),
            },
            payload: UcanPayload {
                iss: "did:dht:z6MkTest".to_owned(),
                aud: "did:dht:z6MkOther".to_owned(),
                exp: 9_999_999_999,
                nbf: None,
                nnc: "test".to_owned(),
                att: vec![Attenuation {
                    with: "scp:ctx:ctx-1/did_document:update".to_owned(),
                    can: "update".to_owned(),
                }],
                prf: vec![],
                fct: None,
            },
            signature: vec![],
            encoded: String::new(),
        };
        let caps = vec![CapabilityUri {
            context_id: Some("ctx-1".to_owned()),
            resource: "did_document".to_owned(),
            action: "update".to_owned(),
        }];
        let result = enforce_ucan_category_a(&token, &caps);
        assert!(result.is_err());
        let err = result.err().unwrap_or_default();
        assert!(
            err.contains("Category A violation"),
            "expected Category A violation, got: {err}"
        );
    }

    #[test]
    fn enforce_category_a_allows_active_with_did_document_cap() {
        let token = ParsedUcanToken {
            header: UcanHeader {
                alg: "EdDSA".to_owned(),
                typ: "JWT".to_owned(),
                ucv: "0.10.0".to_owned(),
                kid: Some("#active".to_owned()),
            },
            payload: UcanPayload {
                iss: "did:dht:z6MkTest".to_owned(),
                aud: "did:dht:z6MkOther".to_owned(),
                exp: 9_999_999_999,
                nbf: None,
                nnc: "test".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![],
            encoded: String::new(),
        };
        let caps = vec![CapabilityUri {
            context_id: Some("ctx-1".to_owned()),
            resource: "did_document".to_owned(),
            action: "update".to_owned(),
        }];
        let result = enforce_ucan_category_a(&token, &caps);
        assert!(
            result.is_ok(),
            "#active key should be allowed Category A: {result:?}"
        );
    }

    #[test]
    fn enforce_category_a_allows_agent_with_category_b() {
        let token = ParsedUcanToken {
            header: UcanHeader {
                alg: "EdDSA".to_owned(),
                typ: "JWT".to_owned(),
                ucv: "0.10.0".to_owned(),
                kid: Some("#agent".to_owned()),
            },
            payload: UcanPayload {
                iss: "did:dht:z6MkTest".to_owned(),
                aud: "did:dht:z6MkOther".to_owned(),
                exp: 9_999_999_999,
                nbf: None,
                nnc: "test".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![],
            encoded: String::new(),
        };
        let caps = vec![CapabilityUri {
            context_id: Some("ctx-1".to_owned()),
            resource: "messages".to_owned(),
            action: "write".to_owned(),
        }];
        let result = enforce_ucan_category_a(&token, &caps);
        assert!(
            result.is_ok(),
            "#agent key should be allowed Category B: {result:?}"
        );
    }

    #[test]
    fn enforce_category_a_rejects_unknown_kid() {
        let token = ParsedUcanToken {
            header: UcanHeader {
                alg: "EdDSA".to_owned(),
                typ: "JWT".to_owned(),
                ucv: "0.10.0".to_owned(),
                kid: Some("#unknown".to_owned()),
            },
            payload: UcanPayload {
                iss: "did:dht:z6MkTest".to_owned(),
                aud: "did:dht:z6MkOther".to_owned(),
                exp: 9_999_999_999,
                nbf: None,
                nnc: "test".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![],
            encoded: String::new(),
        };
        let caps = vec![CapabilityUri {
            context_id: Some("ctx-1".to_owned()),
            resource: "messages".to_owned(),
            action: "write".to_owned(),
        }];
        let result = enforce_ucan_category_a(&token, &caps);
        assert!(result.is_err());
        let err = result.err().unwrap_or_default();
        assert!(
            err.contains("unrecognized signing key ID"),
            "expected unrecognized kid error, got: {err}"
        );
    }

    #[test]
    fn enforce_category_a_defaults_kid_to_active() {
        // kid absent → defaults to #active → Category A allowed
        let token = ParsedUcanToken {
            header: UcanHeader {
                alg: "EdDSA".to_owned(),
                typ: "JWT".to_owned(),
                ucv: "0.10.0".to_owned(),
                kid: None,
            },
            payload: UcanPayload {
                iss: "did:dht:z6MkTest".to_owned(),
                aud: "did:dht:z6MkOther".to_owned(),
                exp: 9_999_999_999,
                nbf: None,
                nnc: "test".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![],
            encoded: String::new(),
        };
        let caps = vec![CapabilityUri {
            context_id: Some("ctx-1".to_owned()),
            resource: "did_document".to_owned(),
            action: "update".to_owned(),
        }];
        let result = enforce_ucan_category_a(&token, &caps);
        assert!(
            result.is_ok(),
            "absent kid defaults to #active, Category A allowed: {result:?}"
        );
    }

    #[test]
    fn enforce_category_a_checks_all_resource_types() {
        for resource in CATEGORY_A_RESOURCES {
            let token = ParsedUcanToken {
                header: UcanHeader {
                    alg: "EdDSA".to_owned(),
                    typ: "JWT".to_owned(),
                    ucv: "0.10.0".to_owned(),
                    kid: Some("#agent".to_owned()),
                },
                payload: UcanPayload {
                    iss: "did:dht:z6MkTest".to_owned(),
                    aud: "did:dht:z6MkOther".to_owned(),
                    exp: 9_999_999_999,
                    nbf: None,
                    nnc: "test".to_owned(),
                    att: vec![],
                    prf: vec![],
                    fct: None,
                },
                signature: vec![],
                encoded: String::new(),
            };
            let caps = vec![CapabilityUri {
                context_id: Some("ctx-1".to_owned()),
                resource: (*resource).to_owned(),
                action: "modify".to_owned(),
            }];
            let result = enforce_ucan_category_a(&token, &caps);
            assert!(
                result.is_err(),
                "Category A resource '{resource}' must be rejected for #agent"
            );
        }
    }

    // -----------------------------------------------------------------------
    // UcanHeader kid serialization round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn ucan_header_kid_round_trip() -> Result<(), String> {
        let header = UcanHeader {
            alg: "EdDSA".to_owned(),
            typ: "JWT".to_owned(),
            ucv: "0.10.0".to_owned(),
            kid: Some("#agent".to_owned()),
        };
        let json = serde_json::to_string(&header).map_err(|e| e.to_string())?;
        assert!(json.contains("\"kid\":\"#agent\""));
        let parsed: UcanHeader = serde_json::from_str(&json).map_err(|e| e.to_string())?;
        assert_eq!(parsed.kid, Some("#agent".to_owned()));
        Ok(())
    }

    #[test]
    fn ucan_header_kid_absent_round_trip() -> Result<(), String> {
        let header = UcanHeader {
            alg: "EdDSA".to_owned(),
            typ: "JWT".to_owned(),
            ucv: "0.10.0".to_owned(),
            kid: None,
        };
        let json = serde_json::to_string(&header).map_err(|e| e.to_string())?;
        assert!(!json.contains("kid"));
        let parsed: UcanHeader = serde_json::from_str(&json).map_err(|e| e.to_string())?;
        assert_eq!(parsed.kid, None);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // parse_ucan now extracts kid from header
    // -----------------------------------------------------------------------

    #[test]
    fn parse_ucan_extracts_kid_from_header() -> Result<(), String> {
        let header = UcanHeader {
            alg: "EdDSA".to_owned(),
            typ: "JWT".to_owned(),
            ucv: "0.10.0".to_owned(),
            kid: Some("#agent".to_owned()),
        };
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
        let header_json = serde_json::to_vec(&header).map_err(|e| e.to_string())?;
        let payload_json = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
        // Use a dummy signature (64 zero bytes)
        let sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let jwt = format!("{header_b64}.{payload_b64}.{sig_b64}");

        let parsed = parse_ucan(&jwt)?;
        assert_eq!(parsed.header.kid, Some("#agent".to_owned()));
        Ok(())
    }

    #[test]
    fn parse_ucan_kid_none_when_absent() -> Result<(), String> {
        let header = UcanHeader {
            alg: "EdDSA".to_owned(),
            typ: "JWT".to_owned(),
            ucv: "0.10.0".to_owned(),
            kid: None,
        };
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
        let header_json = serde_json::to_vec(&header).map_err(|e| e.to_string())?;
        let payload_json = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
        let sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let jwt = format!("{header_b64}.{payload_b64}.{sig_b64}");

        let parsed = parse_ucan(&jwt)?;
        assert_eq!(parsed.header.kid, None);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // E2E integration tests: real Ed25519 signatures through validate_ucan_full
    //
    // These tests exercise the full validate_ucan_full pipeline with real
    // cryptographic operations (no empty signatures). They register identities
    // with agent keys in the WASM identity registry and produce properly
    // signed JWTs.
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

    #[test]
    fn e2e_agent_signed_category_a_rejected_after_real_signature_verification() {
        // Setup: register an identity with a separate agent key.
        crate::identity::test_helpers::cleanup_identity_registry();

        let (did, _identity_key, agent_key) =
            crate::identity::test_helpers::register_identity_with_agent_key();

        // Build a UCAN signed by the agent key (#agent) granting a Category A
        // capability (did_document:update). This is a self-delegation scenario
        // (iss == aud) with scp_key_scope to satisfy step 5a.
        let context_id = "test-ctx-e2e-catA";
        let header = UcanHeader {
            alg: "EdDSA".to_owned(),
            typ: "JWT".to_owned(),
            ucv: "0.10.0".to_owned(),
            kid: Some("#agent".to_owned()),
        };
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

        // Verify the signature is valid independently (step 2 must pass).
        let parsed = parse_ucan(&jwt).expect("JWT should parse");
        verify_signature(&parsed).expect("real Ed25519 signature must verify");

        // Now run the full pipeline — expect Category A rejection at step 6b.
        let result = validate_ucan_full(&UcanValidationParams {
            token: &parsed,
            capability: &format!("scp:ctx:{context_id}/did_document:update"),
            context_id,
            expected_aud_did: &did,
            proof_tokens: None,
            ceiling: &HashSet::new(),
            creator_did: &did,
            revoked_cids: &HashSet::new(),
        });

        assert!(
            result.is_err(),
            "Category A capability from #agent must be rejected"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("Category A violation"),
            "expected Category A violation error, got: {err}"
        );
        assert!(
            err.contains("did_document:update"),
            "error should name the offending capability, got: {err}"
        );
    }

    #[test]
    fn e2e_agent_signed_category_b_passes_signature_and_category_a_check() {
        // Setup: register an identity with a separate agent key.
        crate::identity::test_helpers::cleanup_identity_registry();

        let (did, _identity_key, agent_key) =
            crate::identity::test_helpers::register_identity_with_agent_key();

        // Build a UCAN signed by the agent key granting a Category B
        // (non-identity) capability. This should pass steps 1-6b.
        let context_id = "test-ctx-e2e-catB";
        let header = UcanHeader {
            alg: "EdDSA".to_owned(),
            typ: "JWT".to_owned(),
            ucv: "0.10.0".to_owned(),
            kid: Some("#agent".to_owned()),
        };
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

        // Verify the signature independently.
        let parsed = parse_ucan(&jwt).expect("JWT should parse");
        verify_signature(&parsed).expect("real Ed25519 signature must verify");

        // Run the pipeline — it should pass steps 1-6b (signature + Category A)
        // then fail at step 9 (nonce validation) because the nonce format is
        // intentionally invalid. This proves the pipeline reached past step 6b
        // (Category A check passed for a Category B capability).
        let result = validate_ucan_full(&UcanValidationParams {
            token: &parsed,
            capability: &format!("scp:ctx:{context_id}/messages:write"),
            context_id,
            expected_aud_did: &did,
            proof_tokens: None,
            ceiling: &HashSet::new(),
            creator_did: &did,
            revoked_cids: &HashSet::new(),
        });

        // The pipeline should fail at step 9 (nonce format), NOT at step 6b.
        assert!(
            result.is_err(),
            "pipeline should fail at nonce validation (step 9)"
        );
        let err = result.unwrap_err();
        assert!(
            !err.contains("Category A"),
            "Category B capability should pass Category A check, but got: {err}"
        );
        assert!(
            err.contains("nonce"),
            "expected nonce validation error (step 9), got: {err}"
        );
    }

    #[test]
    fn e2e_active_key_signed_category_a_passes_category_a_check() {
        // Setup: register identity. The #active key (identity key) should be
        // allowed to grant Category A capabilities.
        crate::identity::test_helpers::cleanup_identity_registry();

        let (did, identity_key, _agent_key) =
            crate::identity::test_helpers::register_identity_with_agent_key();

        let context_id = "test-ctx-e2e-active";
        let header = UcanHeader {
            alg: "EdDSA".to_owned(),
            typ: "JWT".to_owned(),
            ucv: "0.10.0".to_owned(),
            kid: Some("#active".to_owned()),
        };
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

        let jwt = build_signed_ucan(&header, &payload, &identity_key);

        let parsed = parse_ucan(&jwt).expect("JWT should parse");
        verify_signature(&parsed).expect("real Ed25519 signature must verify");

        // Pipeline should pass Category A (step 6b) because #active is allowed.
        // It will fail later at nonce validation (step 9).
        let result = validate_ucan_full(&UcanValidationParams {
            token: &parsed,
            capability: &format!("scp:ctx:{context_id}/did_document:update"),
            context_id,
            expected_aud_did: &did,
            proof_tokens: None,
            ceiling: &HashSet::new(),
            creator_did: &did,
            revoked_cids: &HashSet::new(),
        });

        assert!(result.is_err(), "pipeline should fail at nonce validation");
        let err = result.unwrap_err();
        assert!(
            !err.contains("Category A"),
            "#active key should pass Category A check, but got: {err}"
        );
        assert!(
            err.contains("nonce"),
            "expected nonce validation error (step 9), got: {err}"
        );
    }

    #[test]
    fn e2e_invalid_signature_rejected_before_category_a() {
        // Verify that a tampered signature is caught at step 2 (before
        // Category A at step 6b). This proves the pipeline does real crypto.
        crate::identity::test_helpers::cleanup_identity_registry();

        let (did, _identity_key, agent_key) =
            crate::identity::test_helpers::register_identity_with_agent_key();

        let context_id = "test-ctx-e2e-badsig";
        let header = UcanHeader {
            alg: "EdDSA".to_owned(),
            typ: "JWT".to_owned(),
            ucv: "0.10.0".to_owned(),
            kid: Some("#agent".to_owned()),
        };
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

        // Sign with the agent key, then corrupt the signature.
        let jwt = build_signed_ucan(&header, &payload, &agent_key);
        let parts: Vec<&str> = jwt.split('.').collect();
        // Replace last byte of signature with a different value.
        let mut sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        sig_bytes[63] ^= 0xff; // flip all bits of last byte
        let corrupted_sig = URL_SAFE_NO_PAD.encode(&sig_bytes);
        let tampered_jwt = format!("{}.{}.{}", parts[0], parts[1], corrupted_sig);

        let parsed = parse_ucan(&tampered_jwt).expect("JWT should parse (format is valid)");

        let result = validate_ucan_full(&UcanValidationParams {
            token: &parsed,
            capability: &format!("scp:ctx:{context_id}/did_document:update"),
            context_id,
            expected_aud_did: &did,
            proof_tokens: None,
            ceiling: &HashSet::new(),
            creator_did: &did,
            revoked_cids: &HashSet::new(),
        });

        assert!(result.is_err(), "tampered signature must be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("signature verification failed"),
            "expected signature error at step 2, got: {err}"
        );
    }

    #[test]
    fn e2e_all_category_a_resources_rejected_for_agent_key() {
        // Exhaustively verify every Category A resource type is rejected
        // when the token is signed by #agent with real cryptography.
        crate::identity::test_helpers::cleanup_identity_registry();

        let (did, _identity_key, agent_key) =
            crate::identity::test_helpers::register_identity_with_agent_key();

        let context_id = "test-ctx-e2e-allcatA";

        for resource in CATEGORY_A_RESOURCES {
            let capability = format!("scp:ctx:{context_id}/{resource}:update");
            let header = UcanHeader {
                alg: "EdDSA".to_owned(),
                typ: "JWT".to_owned(),
                ucv: "0.10.0".to_owned(),
                kid: Some("#agent".to_owned()),
            };
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

            // Real signature must verify (step 2).
            verify_signature(&parsed)
                .unwrap_or_else(|e| panic!("signature must verify for resource '{resource}': {e}"));

            // Full pipeline must reject at step 6b.
            let result = validate_ucan_full(&UcanValidationParams {
                token: &parsed,
                capability: &capability,
                context_id,
                expected_aud_did: &did,
                proof_tokens: None,
                ceiling: &HashSet::new(),
                creator_did: &did,
                revoked_cids: &HashSet::new(),
            });

            assert!(
                result.is_err(),
                "Category A resource '{resource}' must be rejected for #agent"
            );
            let err = result.unwrap_err();
            assert!(
                err.contains("Category A violation"),
                "expected Category A violation for '{resource}', got: {err}"
            );
        }
    }
}
