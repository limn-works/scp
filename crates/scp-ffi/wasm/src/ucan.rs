//! `wasm-bindgen` bridge for UCAN token management.
//!
//! Exposes SCP UCAN operations to JavaScript:
//!
//! - [`ucan_validate`] -- Validate a UCAN token against a required capability.
//! - [`ucan_mint`] -- Mint a new UCAN token for a context member.
//! - [`ucan_revoke`] -- Revoke a UCAN token.
//!
//! # Types
//!
//! - [`WasmUcanToken`] -- UCAN token handle (ID, issuer, audience, capabilities,
//!   expiry).
//!
//! # WASM-local validation
//!
//! Because scp-core depends on `tokio = { features = ["full"] }` which cannot
//! compile to `wasm32-unknown-unknown`, this module re-implements the 11-step
//! UCAN validation pipeline from ADR-016 locally. The implementation mirrors
//! `scp-core/crypto/ucan/validate.rs` with the same security semantics:
//!
//! 1. **Parse** -- Decode JWT-format UCAN token (3 base64url segments).
//! 2. **Signature** -- Verify Ed25519 signature via `ed25519-dalek`.
//! 3. **Delegation chain** -- Verify proof chain integrity, aud/iss linkage.
//! 4. **Root issuer** -- Verify root token's `iss` is the context creator.
//! 5. **Audience** -- Verify `aud` matches the expected audience DID.
//! 6. **Capability match** -- Verify `att` includes required capability.
//! 7. **Attenuation** -- Verify delegations narrow or preserve (child <= parent).
//! 8. **Ceiling** -- Verify capability is within context ceiling.
//! 9. **Nonce replay** -- Check+insert nonce in per-context tracker.
//! 10. **Revocation** -- Verify token CID not in revocation list.
//! 11. **Time bounds** -- Verify `exp > now`, `nbf <= now`, `exp <= now + 24h`.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md` and ADR-016 (UCAN validation)
//! for the full specification.

use std::collections::{HashMap, HashSet};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use js_sys::Promise;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::context::WasmContextHandle;
use crate::error::ScpWasmError;

/// Maximum token lifetime: 24 hours in seconds (spec section 9.5).
const MAX_EXPIRY_SECS: u64 = 24 * 60 * 60;

/// Maximum delegation chain depth to prevent infinite loops.
const MAX_CHAIN_DEPTH: usize = 32;

// ---------------------------------------------------------------------------
// UCAN data structures (mirrors scp-core/crypto/ucan/mod.rs)
// ---------------------------------------------------------------------------

/// JWT header for a UCAN token.
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

/// A single capability grant within a UCAN token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Attenuation {
    with: String,
    can: String,
}

/// Claims payload for a UCAN token.
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

/// A complete parsed UCAN token.
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

/// A parsed SCP capability URI: `scp:ctx:{context_id}/{resource}:{action}`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CapabilityUri {
    /// `None` for wildcard (`*`).
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

    /// Returns the `{resource}:{action}` string for ceiling checking.
    fn capability_name(&self) -> String {
        format!("{}:{}", self.resource, self.action)
    }

    /// Returns true if this granted capability matches the required capability.
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

    /// Checks context match with trailing-slash protection (RED-105 fix).
    ///
    /// Prevents prefix collision: token for `ctx-100` must NOT grant access
    /// to `ctx-10`. The `with` string must either be an exact match for the
    /// context prefix or start with `{context_prefix}/`.
    fn matches_context_scope(with_str: &str, context_id: &str) -> bool {
        let context_prefix = format!("scp:ctx:{context_id}");
        with_str == context_prefix || with_str.starts_with(&format!("{context_prefix}/"))
    }
}

// ---------------------------------------------------------------------------
// UCAN parsing
// ---------------------------------------------------------------------------

/// Parses a JWT-encoded UCAN token string.
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
// Revocation CID computation (mirrors scp-core/crypto/ucan/revoke.rs)
// ---------------------------------------------------------------------------

/// Computes the revocation CID as the hex-encoded SHA-256 hash of the
/// JSON-serialized UCAN payload.
///
/// # Errors
///
/// Returns `Err` on serialization failure instead of silently producing a
/// fallback/constant CID (security-reviewer MEDIUM fix).
fn compute_revocation_cid(payload: &UcanPayload) -> Result<String, String> {
    let payload_bytes = serde_json::to_vec(payload)
        .map_err(|e| format!("revocation CID serialization failed: {e}"))?;
    let hash = Sha256::digest(&payload_bytes);
    let hex = hash.iter().fold(String::with_capacity(64), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    });
    Ok(hex)
}

// ---------------------------------------------------------------------------
// Ed25519 signature verification
// ---------------------------------------------------------------------------

/// Resolves a DID string to its Ed25519 public key bytes.
fn resolve_public_key(did: &str) -> Result<[u8; 32], String> {
    // did:dht:z{z-base-32-encoded-pubkey}
    if let Some(suffix) = did.strip_prefix("did:dht:z") {
        let decoded = zbase32_decode(suffix)
            .map_err(|e| format!("z-base-32 decode failed for DID {did}: {e}"))?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|v: Vec<u8>| format!("DID public key must be 32 bytes, got {}", v.len()))?;
        return Ok(bytes);
    }

    // did:key:{hex} is a non-standard test convenience. Gated behind the
    // `testing` feature (or #[cfg(test)]) to prevent acceptance in release
    // builds. See: https://github.com/limn-works/scp/issues/128
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

/// Verifies the Ed25519 signature over `base64url(header).base64url(payload)`.
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

/// Minimal z-base-32 decoder. Decodes z-base-32 strings as used in did:dht.
///
/// z-base-32 uses the alphabet `ybndrfg8ejkmcpqxot1uwisza345h769`.
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
// Per-context UCAN runtime state
// ---------------------------------------------------------------------------

/// Per-context state for UCAN validation in the WASM bridge.
///
/// Since scp-core cannot compile to WASM, we maintain our own runtime state
/// for nonce tracking, revocation lists, and capability ceilings.
struct WasmUcanContextState {
    /// Nonce replay tracker: set of seen nonce strings.
    seen_nonces: HashSet<String>,
    /// Revocation list: set of revoked token CIDs.
    revoked_cids: HashSet<String>,
    /// Capability ceiling as `{resource}:{action}` strings.
    ceiling: HashSet<String>,
    /// Context creator DID.
    creator_did: String,
}

/// Global registry of per-context UCAN state.
///
/// In WASM (single-threaded), a `RefCell` would suffice, but we use a
/// simple static mutable pattern gated by `std::sync::Mutex` for safety.
/// WASM is inherently single-threaded, so contention is not a concern.
static UCAN_STATE: std::sync::Mutex<Option<HashMap<String, WasmUcanContextState>>> =
    std::sync::Mutex::new(None);

/// Ensures the global UCAN state map is initialized and runs a closure
/// against the per-context state entry.
fn with_ucan_state<F, T>(context_id: &str, f: F) -> Result<T, String>
where
    F: FnOnce(&mut WasmUcanContextState) -> Result<T, String>,
{
    let map = &mut *UCAN_STATE
        .lock()
        .map_err(|e| format!("UCAN state lock poisoned: {e}"))?;
    let map = map.get_or_insert_with(HashMap::new);
    let state = map
        .entry(context_id.to_owned())
        .or_insert_with(|| WasmUcanContextState {
            seen_nonces: HashSet::new(),
            revoked_cids: HashSet::new(),
            ceiling: HashSet::new(),
            creator_did: String::new(),
        });
    f(state)
}

/// Initializes or updates UCAN state for a context from its handle metadata.
fn sync_context_state(context: &WasmContextHandle) {
    let context_id = context.context_id();
    let creator_did = context.creator_did();
    let ceiling_arr = context.ceiling();
    let mut ceiling_set = HashSet::new();
    for i in 0..ceiling_arr.length() {
        if let Some(s) = ceiling_arr.get(i).as_string() {
            ceiling_set.insert(s);
        }
    }

    let result = UCAN_STATE.lock();
    if let Ok(mut guard) = result {
        let map = guard.get_or_insert_with(HashMap::new);
        let state = map
            .entry(context_id)
            .or_insert_with(|| WasmUcanContextState {
                seen_nonces: HashSet::new(),
                revoked_cids: HashSet::new(),
                ceiling: HashSet::new(),
                creator_did: String::new(),
            });
        state.creator_did = creator_did;
        state.ceiling = ceiling_set;
    }
}

// ---------------------------------------------------------------------------
// Full 11-step validation pipeline
// ---------------------------------------------------------------------------

/// Performs the full 11-step UCAN validation pipeline.
///
/// # Arguments
///
/// * `token` -- Parsed UCAN token.
/// * `capability` -- Required capability URI string.
/// * `context_id` -- Context ID for scoping.
/// * `expected_aud_did` -- Expected audience DID.
/// * `proof_tokens` -- Optional encoded proof token strings for delegation.
/// * `ceiling` -- Context capability ceiling.
/// * `creator_did` -- Context creator DID.
fn validate_ucan_full(
    token: &ParsedUcanToken,
    capability: &str,
    context_id: &str,
    expected_aud_did: &str,
    proof_tokens: Option<&[String]>,
    ceiling: &HashSet<String>,
    creator_did: &str,
) -> Result<(), String> {
    // Step 1: Parse -- already done. Validate header.
    token.header.validate()?;

    // Step 2: Signature verification.
    verify_signature(token)?;

    // Step 3 + Step 4: Delegation chain verification -> root issuer must be creator.
    // Read revoked CIDs from per-context state for parent token revocation checks.
    let revoked_cids = with_ucan_state(context_id, |state| Ok(state.revoked_cids.clone()))?;
    let root_issuer = verify_delegation_chain(token, proof_tokens, &revoked_cids)?;

    if root_issuer != creator_did {
        return Err(format!(
            "invalid issuer: expected {creator_did}, got {root_issuer}"
        ));
    }

    // Step 5: Audience DID validation (RED-105 related, new parameter).
    if token.payload.aud != expected_aud_did {
        return Err(format!(
            "audience mismatch: expected {expected_aud_did}, got {}",
            token.payload.aud
        ));
    }

    // Step 6: Capability match with prefix-collision protection (RED-105 fix).
    let required_cap = CapabilityUri::parse(capability)?;

    // SECURITY: fail-closed -- any unparseable attestation URI rejects the entire token.
    let granted_caps: Vec<CapabilityUri> = token
        .payload
        .att
        .iter()
        .map(|att| {
            // RED-105: validate context scope with trailing-slash protection
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

    // Check that at least one granted cap matches the required cap.
    let matched = granted_caps.iter().any(|cap| cap.matches(&required_cap));
    if !matched {
        return Err(format!("capability not granted: {capability}"));
    }

    // Step 7: Attenuation enforcement -- child capabilities must be subset of parent's.
    if !token.payload.prf.is_empty() {
        verify_attenuation(token, proof_tokens)?;
    }

    // Step 8: Capability ceiling check.
    let cap_name = required_cap.capability_name();
    if !ceiling.is_empty() && !ceiling.contains(&cap_name) {
        return Err(format!("capability outside ceiling: {cap_name}"));
    }

    // Step 9: Nonce replay detection.
    with_ucan_state(context_id, |state| {
        if token.payload.nnc.is_empty() {
            return Err("nonce is empty".to_owned());
        }
        if state.seen_nonces.contains(&token.payload.nnc) {
            return Err(format!("nonce reused: {}", token.payload.nnc));
        }
        state.seen_nonces.insert(token.payload.nnc.clone());
        Ok(())
    })?;

    // Step 10: Revocation check.
    let revocation_cid = compute_revocation_cid(&token.payload)?;
    with_ucan_state(context_id, |state| {
        if state.revoked_cids.contains(&revocation_cid) {
            return Err(format!("token revoked: {revocation_cid}"));
        }
        Ok(())
    })?;

    // Step 11: Time bounds (expiry + not-before).
    verify_time_bounds(token)?;

    Ok(())
}

/// Step 11: Verify expiry and not-before time bounds.
fn verify_time_bounds(token: &ParsedUcanToken) -> Result<(), String> {
    let now = now_secs();

    // Check not-before (nbf).
    if let Some(nbf) = token.payload.nbf {
        if now < nbf {
            return Err("token not yet valid (nbf > now)".to_owned());
        }
        // nbf must be before exp.
        if nbf >= token.payload.exp {
            return Err(format!(
                "invalid time range: nbf ({nbf}) must be less than exp ({})",
                token.payload.exp
            ));
        }
    }

    // Check expiry.
    if now >= token.payload.exp {
        return Err("token expired".to_owned());
    }

    // Check max lifetime (24h).
    if token.payload.exp > now + MAX_EXPIRY_SECS {
        return Err(format!(
            "expiry too far in the future: {}s exceeds 24h maximum",
            token.payload.exp - now
        ));
    }

    Ok(())
}

/// Step 3: Verify delegation chain integrity. Returns root issuer DID.
fn verify_delegation_chain(
    token: &ParsedUcanToken,
    proof_tokens: Option<&[String]>,
    revoked_cids: &HashSet<String>,
) -> Result<String, String> {
    if token.payload.prf.is_empty() {
        // Root token -- issuer IS the root.
        return Ok(token.payload.iss.clone());
    }

    let proofs = proof_tokens.unwrap_or(&[]);

    // Build proof map: CID -> ParsedUcanToken
    let mut proof_map: HashMap<String, ParsedUcanToken> = HashMap::new();
    for encoded in proofs {
        let parsed = parse_ucan(encoded)?;
        let cid = compute_token_cid(encoded);
        proof_map.insert(cid, parsed);
    }

    // Initialize seen_issuers with the current token's issuer to detect cycles.
    let mut seen_issuers = HashSet::new();
    seen_issuers.insert(token.payload.iss.clone());

    // Walk the chain from current token upward.
    verify_chain_recursive(token, &proof_map, revoked_cids, 0, &mut seen_issuers)
}

/// Recursively verifies the delegation chain.
///
/// Per spec section 7.2, every token in the delegation chain must be valid:
/// not expired, not revoked, and properly signed. An expired or revoked
/// parent invalidates the entire delegation.
///
/// `seen_issuers` tracks all issuer DIDs encountered during the chain walk
/// to detect circular delegations (e.g., A->B->A). This mirrors scp-core's
/// `verify_chain_recursive` in `validate.rs:636-668`.
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
        // Root token.
        verify_signature(token)?;
        return Ok(token.payload.iss.clone());
    }

    // Resolve and verify each proof.
    let mut root_issuer = None;
    for proof_cid in &token.payload.prf {
        let parent = proof_map
            .get(proof_cid)
            .ok_or_else(|| format!("delegation chain broken: proof CID not found: {proof_cid}"))?;

        // Circular delegation detection: if the parent's issuer has already
        // been seen in the chain, we have a cycle.
        if !seen_issuers.insert(parent.payload.iss.clone()) {
            return Err(format!(
                "circular delegation detected: issuer '{}' appears multiple times in the delegation chain",
                parent.payload.iss
            ));
        }

        // Verify parent signature.
        verify_signature(parent)?;

        // Verify aud/iss linkage: parent.aud must equal child.iss.
        if parent.payload.aud != token.payload.iss {
            return Err(format!(
                "delegation chain broken: parent aud '{}' does not match child iss '{}'",
                parent.payload.aud, token.payload.iss
            ));
        }

        // Verify parent token has not expired (spec 7.2).
        verify_time_bounds(parent)?;

        // Verify parent token has not been revoked (spec 7.2).
        let parent_revocation_cid = compute_revocation_cid(&parent.payload)?;
        if revoked_cids.contains(&parent_revocation_cid) {
            return Err(format!("token revoked: {parent_revocation_cid}"));
        }

        // Recurse up the chain.
        let issuer =
            verify_chain_recursive(parent, proof_map, revoked_cids, depth + 1, seen_issuers)?;
        root_issuer = Some(issuer);
    }

    root_issuer.ok_or_else(|| "delegation chain empty".to_owned())
}

/// Step 7: Attenuation enforcement -- child capabilities must be subset of parent's.
fn verify_attenuation(
    token: &ParsedUcanToken,
    proof_tokens: Option<&[String]>,
) -> Result<(), String> {
    let proofs = proof_tokens.unwrap_or(&[]);

    // Build proof map.
    let mut proof_map: HashMap<String, ParsedUcanToken> = HashMap::new();
    for encoded in proofs {
        let parsed = parse_ucan(encoded)?;
        let cid = compute_token_cid(encoded);
        proof_map.insert(cid, parsed);
    }

    // For each proof in the chain, verify child capabilities are subset of parent.
    for proof_cid in &token.payload.prf {
        let parent = proof_map
            .get(proof_cid)
            .ok_or_else(|| format!("attenuation check failed: proof CID not found: {proof_cid}"))?;

        // Parse parent capabilities.
        // SECURITY: fail-closed -- any unparseable parent capability URI rejects the chain.
        let parent_caps: Vec<CapabilityUri> = parent
            .payload
            .att
            .iter()
            .map(|att| {
                CapabilityUri::parse(&att.with)
                    .map_err(|e| format!("unparseable capability URI in parent attestation: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Every child capability must be matched by at least one parent capability.
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

/// Computes the CID of a token as the hex-encoded SHA-256 of the encoded JWT string.
fn compute_token_cid(encoded: &str) -> String {
    let hash = Sha256::digest(encoded.as_bytes());
    format!("bafyrei{}", encode_hex(&hash))
}

/// Returns the current Unix timestamp in seconds.
fn now_secs() -> u64 {
    let now = js_sys::Date::now();
    // js_sys::Date::now() returns milliseconds since epoch as f64.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    {
        (now / 1000.0) as u64
    }
}

// ---------------------------------------------------------------------------
// WasmUcanToken
// ---------------------------------------------------------------------------

/// UCAN token handle exposed to JavaScript.
///
/// Contains the token metadata accessible to JavaScript code: a unique token
/// ID (derived from the UCAN nonce), issuer DID, audience DID, capabilities
/// as a JSON string, and an optional expiry timestamp.
///
/// The raw signature and encoded JWT are not exposed -- they are internal to
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
    /// Issuer DID -- the entity that created and signed this token.
    issuer: String,
    /// Audience DID -- the entity this token is delegated to.
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
/// Performs the full 11-step UCAN validation pipeline from ADR-016:
///
/// 1. **Parse** -- Decode JWT-format UCAN token (3 base64url segments).
/// 2. **Signature** -- Verify Ed25519 signature via `ed25519-dalek`.
/// 3. **Delegation chain** -- Verify proof chain integrity, aud/iss linkage.
/// 4. **Root issuer** -- Verify root token's `iss` is the context creator.
/// 5. **Audience** -- Verify `aud` matches the expected audience DID.
/// 6. **Capability match** -- Verify `att` includes required capability
///    (with trailing-slash prefix-collision protection per RED-105).
/// 7. **Attenuation** -- Verify delegations narrow or preserve (child <= parent).
/// 8. **Ceiling** -- Verify capability is within context ceiling.
/// 9. **Nonce replay** -- Check+insert nonce in per-context tracker.
/// 10. **Revocation** -- Verify token CID not in revocation list.
/// 11. **Time bounds** -- Verify `exp > now`, `nbf <= now`, `exp <= now + 24h`.
///
/// # Arguments
///
/// * `context` -- The context handle the token is presented in.
/// * `token` -- The encoded UCAN token string (JWT format).
/// * `capability` -- The required capability URI (e.g.,
///   `"scp:ctx:abc123/messages:write"`).
/// * `expected_aud_did` -- The DID of the expected audience (the agent
///   presenting the token). Required for audience validation (step 5).
/// * `proof_tokens_json` -- Optional JSON array of encoded parent UCAN token
///   strings for delegation chain verification. Required when validating
///   delegated tokens with non-empty proof chains.
///
/// # Returns
///
/// `Promise<void>` -- resolves on successful validation.
///
/// # Errors
///
/// - Rejects with `[SCP-PERM-3000]` if validation fails for any reason:
///   malformed token, invalid signature, expired, insufficient capabilities,
///   revoked, broken delegation chain, audience mismatch, nonce replay,
///   capability outside ceiling, or time bounds violation.
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn ucan_validate(
    context: &WasmContextHandle,
    token: String,
    capability: String,
    expected_aud_did: String,
    proof_tokens_json: Option<String>,
) -> Promise {
    let context_id = context.context_id();

    // Sync context state from handle before validation.
    sync_context_state(context);

    future_to_promise(async move {
        // Parse the token.
        let parsed = parse_ucan(&token).map_err(|e| {
            ScpWasmError::Permission {
                message: format!("malformed token: {e}"),
                code: "SCP-PERM-3000".to_owned(),
            }
            .into_js()
        })?;

        // Parse optional proof tokens.
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

        // Read ceiling and creator_did from state.
        let (ceiling, creator_did) = with_ucan_state(&context_id, |state| {
            Ok((state.ceiling.clone(), state.creator_did.clone()))
        })
        .map_err(|e| {
            ScpWasmError::Permission {
                message: e,
                code: "SCP-PERM-3000".to_owned(),
            }
            .into_js()
        })?;

        // Run full 11-step validation.
        validate_ucan_full(
            &parsed,
            &capability,
            &context_id,
            &expected_aud_did,
            proof_tokens.as_deref(),
            &ceiling,
            &creator_did,
        )
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
/// Creates a UCAN token granting the specified capabilities to the given
/// member DID. The token is signed by the context creator's key (or the
/// delegating member's key in a delegation chain).
///
/// # Arguments
///
/// * `context` -- The context handle to mint the token for.
/// * `member_did` -- The DID of the member receiving the token.
/// * `capabilities_json` -- A JSON array of capability URI strings to grant
///   (e.g., `'["scp:ctx:abc123/messages:write"]'`).
///
/// # Returns
///
/// `Promise<WasmUcanToken>` -- resolves to the minted token handle.
///
/// # Errors
///
/// - Rejects with `[SCP-VALID-7000]` if `capabilities_json` is malformed
///   or contains non-string entries (white-hat P1 fix: non-string entries
///   are rejected, not silently dropped).
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

        // Fix #3 (white-hat P1): error on non-string capability entries instead of
        // silently dropping them via filter_map.
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

        let _ = (context_id, member_did);

        // Validate each capability URI is parseable.
        for cap in &cap_strings {
            CapabilityUri::parse(cap).map_err(|e| {
                ScpWasmError::Validation {
                    message: format!("invalid capability URI '{cap}': {e}"),
                    code: "SCP-VALID-7000".to_owned(),
                }
                .into_js()
            })?;
        }

        Err(ScpWasmError::Permission {
            message: "not yet connected to runtime -- UCAN minting requires a live context handle \
                      wired to scp-core"
                .to_owned(),
            code: "SCP-PERM-3000".to_owned(),
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
/// * `context` -- The context handle the token belongs to.
/// * `token` -- The full encoded JWT string of the token to revoke.
///
/// # Returns
///
/// `Promise<void>` -- resolves on success.
///
/// # Errors
///
/// Rejects with `[SCP-PERM-3000]` if revocation fails (token not found,
/// revoker not authorized -- must be the token's issuer or context creator).
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn ucan_revoke(context: &WasmContextHandle, token: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let _ = (context_id, token);

        Err(ScpWasmError::Permission {
            message:
                "not yet connected to runtime -- UCAN revocation requires a live context handle \
                      wired to scp-core"
                    .to_owned(),
            code: "SCP-PERM-3000".to_owned(),
        }
        .into_js()
        .into())
    })
}
