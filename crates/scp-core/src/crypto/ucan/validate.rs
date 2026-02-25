//! UCAN token validation for SCP.
//!
//! Implements the 11-step UCAN validation pipeline specified by ADR-016 in
//! `.docs/adrs/phase-3.md`. Every protocol action in an SCP context requires a
//! valid UCAN token; this module is the enforcement point.
//!
//! # Validation steps
//!
//! 1. **Parse** — Decode JWT-format UCAN token.
//! 2. **Signature** — Verify Ed25519 signature.
//! 3. **Chain** — Verify delegation chain integrity.
//! 4. **Root issuer** — Verify root token's `iss` is the context creator.
//! 5. **Audience** — Verify `aud` matches the presenting agent.
//! 6. **Capability match** — Verify `att` includes required capability.
//! 7. **Attenuation** — Verify delegations narrow or preserve.
//! 8. **Ceiling** — Verify capability is within context ceiling.
//! 9. **Nonce** — Validate format, freshness, uniqueness.
//! 10. **Revocation** — Verify token CID not in revocation list.
//! 11. **Expiry** — Verify `exp > now` and `nbf <= now`.
//!
//! See ADR-009 acceptance criterion 4 and ADR-016 acceptance criterion 2.

use std::collections::HashSet;
use std::hash::BuildHasher;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::Verifier;

use super::capability::{CapabilityUri, check_capability_match, verify_ceiling_compliance};
use super::mint::compute_cid;
use super::{UcanError, UcanHeader, UcanPayload, UcanToken};

/// Maximum token lifetime: 24 hours in seconds (spec section 9.5).
const MAX_EXPIRY_SECS: u64 = 24 * 60 * 60;

/// Nonce freshness tolerance: 5 minutes in milliseconds (spec section 9.14).
const NONCE_FRESHNESS_TOLERANCE_MS: u128 = 5 * 60 * 1000;

/// Maximum delegation chain depth to prevent infinite loops.
const MAX_CHAIN_DEPTH: usize = 32;

// ---------------------------------------------------------------------------
// Trait abstractions for external state
// ---------------------------------------------------------------------------

/// Resolves a DID string to its Ed25519 public key bytes.
///
/// Implementations look up the public key for a given DID. For testing, this
/// can be a simple in-memory map. For production, this resolves DIDs via the
/// DHT or a local cache.
pub trait DidResolver {
    /// Resolves a DID to its Ed25519 public key (32 bytes).
    ///
    /// # Errors
    ///
    /// Returns [`UcanError::MalformedToken`] if the DID cannot be resolved.
    fn resolve_public_key(&self, did: &str) -> Result<[u8; 32], UcanError>;
}

/// Tracks nonces to prevent replay attacks.
///
/// Implementations record seen nonces and reject duplicates. The nonce format
/// is `{unix_millis_timestamp}-{16_random_bytes_hex}`.
///
/// See ADR-016 acceptance criterion 6 (nonce tracker).
pub trait NonceTracker {
    /// Validates nonce format and freshness, checks for replay, and records
    /// the nonce if new.
    ///
    /// # Errors
    ///
    /// Returns [`UcanError::NonceFormatInvalid`] if the nonce format is wrong.
    /// Returns [`UcanError::NonceTooOld`] if the timestamp is too far in the past.
    /// Returns [`UcanError::NonceFuture`] if the timestamp is too far in the future.
    /// Returns [`UcanError::NonceReused`] if the nonce has been seen before.
    fn check_and_record(&mut self, nonce: &str, token_expiry: u64) -> Result<(), UcanError>;
}

/// Checks whether a token has been revoked.
///
/// Implementations maintain a set of revoked token CIDs (content identifiers).
pub trait RevocationChecker {
    /// Returns `true` if the given token CID has been revoked.
    fn is_revoked(&self, token_cid: &str) -> bool;
}

/// Resolves a proof CID to a parent UCAN token.
///
/// Used for delegation chain verification (step 3). Implementations look up
/// previously-stored UCAN tokens by their content identifier (CID).
pub trait ProofResolver {
    /// Resolves a proof CID to a parent UCAN token.
    ///
    /// # Errors
    ///
    /// Returns [`UcanError::DelegationChainBroken`] if the proof cannot be resolved.
    fn resolve_proof(&self, cid: &str) -> Result<UcanToken, UcanError>;
}

// ---------------------------------------------------------------------------
// In-memory implementations for testing and Phase 2
// ---------------------------------------------------------------------------

/// In-memory [`DidResolver`] backed by a `HashMap`.
///
/// Maps DID strings to Ed25519 public key bytes. Useful for testing.
pub struct InMemoryDidResolver {
    /// Map of DID string to 32-byte Ed25519 public key.
    pub keys: std::collections::HashMap<String, [u8; 32]>,
}

impl DidResolver for InMemoryDidResolver {
    fn resolve_public_key(&self, did: &str) -> Result<[u8; 32], UcanError> {
        self.keys
            .get(did)
            .copied()
            .ok_or_else(|| UcanError::MalformedToken(format!("DID not found: {did}")))
    }
}

/// In-memory [`NonceTracker`] backed by a `HashMap`.
///
/// Records seen nonces with timestamps and expiry for replay prevention.
/// Validates nonce format (`{unix_millis}-{32_hex_chars}`), freshness
/// (timestamp within +/- 5 minutes of now), and uniqueness.
///
/// See ADR-016 acceptance criterion 6.
pub struct InMemoryNonceTracker {
    /// Map of nonce -> (`first_seen_timestamp_secs`, `token_expiry_secs`).
    seen: std::collections::HashMap<String, (u64, u64)>,
}

impl InMemoryNonceTracker {
    /// Creates a new empty nonce tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: std::collections::HashMap::new(),
        }
    }
}

impl Default for InMemoryNonceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceTracker for InMemoryNonceTracker {
    fn check_and_record(&mut self, nonce: &str, token_expiry: u64) -> Result<(), UcanError> {
        // Validate nonce format: {unix_millis}-{32_hex_chars}
        let (ts_part, hex_part) = nonce.split_once('-').ok_or_else(|| {
            UcanError::NonceFormatInvalid(format!("missing '-' separator in nonce: {nonce}"))
        })?;

        let nonce_millis: u128 = ts_part.parse().map_err(|_| {
            UcanError::NonceFormatInvalid(format!("non-numeric timestamp in nonce: {ts_part}"))
        })?;

        // Hex suffix must be exactly 32 hex characters (16 bytes).
        if hex_part.len() != 32 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(UcanError::NonceFormatInvalid(format!(
                "invalid hex suffix in nonce (expected 32 hex chars): {hex_part}"
            )));
        }

        // Freshness check: timestamp within now +/- 5 minutes.
        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        if nonce_millis + NONCE_FRESHNESS_TOLERANCE_MS < now_millis {
            return Err(UcanError::NonceTooOld(nonce.to_owned()));
        }

        if nonce_millis > now_millis + NONCE_FRESHNESS_TOLERANCE_MS {
            return Err(UcanError::NonceFuture(nonce.to_owned()));
        }

        // Replay check.
        if self.seen.contains_key(nonce) {
            return Err(UcanError::NonceReused(nonce.to_owned()));
        }

        // Record the nonce.
        #[allow(clippy::cast_possible_truncation)]
        // u128 millis / 1000 fits u64 until year 584 billion
        let now_secs = (now_millis / 1000) as u64;
        self.seen.insert(nonce.to_owned(), (now_secs, token_expiry));

        Ok(())
    }
}

/// In-memory [`RevocationChecker`] backed by a `HashSet`.
pub struct InMemoryRevocationChecker {
    /// Set of revoked token CIDs.
    pub revoked: HashSet<String>,
}

impl InMemoryRevocationChecker {
    /// Creates a new empty revocation checker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            revoked: HashSet::new(),
        }
    }
}

impl Default for InMemoryRevocationChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl RevocationChecker for InMemoryRevocationChecker {
    fn is_revoked(&self, token_cid: &str) -> bool {
        self.revoked.contains(token_cid)
    }
}

/// No-op [`ProofResolver`] for Phase 2 (root tokens only, no delegation chains).
pub struct NoOpProofResolver;

impl ProofResolver for NoOpProofResolver {
    fn resolve_proof(&self, cid: &str) -> Result<UcanToken, UcanError> {
        Err(UcanError::DelegationChainBroken(format!(
            "proof resolution not implemented in Phase 2: {cid}"
        )))
    }
}

/// In-memory [`ProofResolver`] backed by a `HashMap`.
///
/// Maps proof CIDs to their corresponding [`UcanToken`]s. Used for testing
/// and for delegation chain verification.
pub struct InMemoryProofResolver {
    /// Map of proof CID to the resolved UCAN token.
    pub proofs: std::collections::HashMap<String, UcanToken>,
}

impl InMemoryProofResolver {
    /// Creates a new empty proof resolver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            proofs: std::collections::HashMap::new(),
        }
    }
}

impl Default for InMemoryProofResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ProofResolver for InMemoryProofResolver {
    fn resolve_proof(&self, cid: &str) -> Result<UcanToken, UcanError> {
        self.proofs
            .get(cid)
            .cloned()
            .ok_or_else(|| UcanError::DelegationChainBroken(format!("proof CID not found: {cid}")))
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parses a JWT-encoded UCAN token string into a [`UcanToken`].
///
/// Decodes the three base64url-encoded segments (header, payload, signature)
/// and deserializes the JSON header and payload.
///
/// # Errors
///
/// Returns [`UcanError::MalformedToken`] if the token does not have exactly
/// three segments or if base64url decoding fails.
/// Returns [`UcanError::DeserializationFailed`] if JSON deserialization fails.
/// Returns [`UcanError::UnsupportedAlgorithm`] or [`UcanError::UnsupportedVersion`]
/// if the header fields are invalid.
pub fn parse_ucan(encoded: &str) -> Result<UcanToken, UcanError> {
    let parts: Vec<&str> = encoded.split('.').collect();
    if parts.len() != 3 {
        return Err(UcanError::MalformedToken(format!(
            "expected 3 JWT segments, got {}",
            parts.len()
        )));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| UcanError::MalformedToken(format!("header base64url decode failed: {e}")))?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| UcanError::MalformedToken(format!("payload base64url decode failed: {e}")))?;

    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|e| {
        UcanError::MalformedToken(format!("signature base64url decode failed: {e}"))
    })?;

    let header: UcanHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| UcanError::DeserializationFailed(format!("header: {e}")))?;

    let payload: UcanPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| UcanError::DeserializationFailed(format!("payload: {e}")))?;

    // Validate header fields.
    header.validate()?;

    Ok(UcanToken {
        header,
        payload,
        signature: sig_bytes,
        encoded: encoded.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Validation context
// ---------------------------------------------------------------------------

/// Context for UCAN validation, providing all external state needed by the
/// 11-step pipeline.
///
/// Each field corresponds to a validation step that requires external state:
/// DID resolution, nonce tracking, revocation checking, proof resolution,
/// capability ceiling, context creator DID, and presenting agent DID.
pub struct ValidationContext<'a, D, N, R, P, S: BuildHasher> {
    /// DID resolver for public key lookup (steps 2, 3).
    pub did_resolver: &'a D,
    /// Nonce tracker for replay prevention (step 9).
    pub nonce_tracker: &'a mut N,
    /// Revocation checker (step 10).
    pub revocation_checker: &'a R,
    /// Proof resolver for delegation chains (step 3).
    pub proof_resolver: &'a P,
    /// Context's immutable capability ceiling (step 8).
    pub ceiling: &'a HashSet<String, S>,
    /// Context creator's DID (step 4 — root issuer verification).
    pub context_creator_did: &'a str,
    /// Presenting agent's DID (step 5 — audience verification).
    pub presenting_agent_did: &'a str,
}

// ---------------------------------------------------------------------------
// Main validation function
// ---------------------------------------------------------------------------

/// Returns the current Unix timestamp in seconds.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Validates a UCAN token using the 11-step pipeline from ADR-016.
///
/// This is the core enforcement point for SCP capability authorization. Every
/// protocol action calls this function with the token and required capability
/// before proceeding.
///
/// # Steps
///
/// 1. Parse JWT-format UCAN token.
/// 2. Verify Ed25519 signature over `base64url(header).base64url(payload)`.
/// 3. Chain verification (delegation proofs) — recurse to root.
/// 4. Verify root issuer is context creator DID.
/// 5. Verify audience matches presenting agent DID.
/// 6. Verify token's `att` includes required capability.
/// 7. Attenuation verification (delegation narrows only).
/// 8. Verify capability is within context ceiling.
/// 9. Nonce validation (format, freshness, uniqueness).
/// 10. Revocation check (token CID not in revocation list).
/// 11. Expiry verification (`exp > now`, `nbf <= now`, `exp <= now + 24h`).
///
/// # Errors
///
/// Returns a specific [`UcanError`] variant indicating which step failed.
///
/// See ADR-016 acceptance criterion 2.
pub fn validate_ucan<D, N, R, P, S>(
    token: &UcanToken,
    required_capability: &CapabilityUri,
    ctx: &mut ValidationContext<'_, D, N, R, P, S>,
) -> Result<(), UcanError>
where
    D: DidResolver,
    N: NonceTracker,
    R: RevocationChecker,
    P: ProofResolver,
    S: BuildHasher,
{
    // Step 1: Parse — already done (token is pre-parsed). Validate header.
    token.header.validate()?;

    // Step 2: Signature verification.
    verify_signature(token, ctx.did_resolver)?;

    // Step 3: Chain verification (delegation proofs).
    // Verifies signatures on all parent tokens, aud/iss linkage, and
    // returns the root issuer DID.
    let root_issuer = verify_delegation_chain(token, ctx.did_resolver, ctx.proof_resolver)?;

    // Step 4: Root issuer — verify root token's iss is context creator.
    if root_issuer != ctx.context_creator_did {
        return Err(UcanError::InvalidIssuer {
            expected: ctx.context_creator_did.to_owned(),
            actual: root_issuer,
        });
    }

    // Step 5: Audience — verify aud matches presenting agent.
    if token.payload.aud != ctx.presenting_agent_did {
        return Err(UcanError::AudienceMismatch {
            expected: ctx.presenting_agent_did.to_owned(),
            actual: token.payload.aud.clone(),
        });
    }

    // Step 6: Capability match — verify att includes required capability.
    // SECURITY: fail-closed — any unparseable attestation URI rejects the entire token.
    let granted_caps: Vec<CapabilityUri> = token
        .payload
        .att
        .iter()
        .map(|att| {
            att.with.parse::<CapabilityUri>().map_err(|_| {
                UcanError::MalformedToken(format!(
                    "unparseable capability URI in attestation: {}",
                    att.with
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    check_capability_match(&granted_caps, required_capability)?;

    // Step 7: Attenuation — verify delegations narrow or preserve.
    // For root tokens (empty prf), this is a no-op.
    if !token.payload.prf.is_empty() {
        verify_attenuation(token, ctx.proof_resolver)?;
    }

    // Step 8: Ceiling — verify capability is within context ceiling.
    verify_ceiling_compliance(std::slice::from_ref(required_capability), ctx.ceiling)?;

    // Step 9: Nonce — validate format, freshness, uniqueness.
    ctx.nonce_tracker
        .check_and_record(&token.payload.nnc, token.payload.exp)?;

    // Step 10: Revocation — verify token CID not revoked.
    let token_cid = compute_cid(token);
    if ctx.revocation_checker.is_revoked(&token_cid) {
        return Err(UcanError::TokenRevoked(token_cid));
    }

    // Step 11: Expiry — verify exp > now and nbf <= now.
    verify_expiry(token)?;

    Ok(())
}

/// Validates a pre-parsed UCAN token without nonce tracking or revocation
/// checks.
///
/// This is a lighter-weight validation suitable for cases where the caller
/// manages nonce tracking and revocation externally, or for quick signature
/// and structure checks.
///
/// Performs steps 1, 2, 4, 5, 6, 8, and 11 of the 11-step pipeline.
///
/// # Errors
///
/// Returns a specific [`UcanError`] variant indicating which step failed.
pub fn validate_ucan_stateless<D, S>(
    token: &UcanToken,
    required_capability: &CapabilityUri,
    did_resolver: &D,
    ceiling: &HashSet<String, S>,
    context_creator_did: &str,
    presenting_agent_did: &str,
) -> Result<(), UcanError>
where
    D: DidResolver,
    S: BuildHasher,
{
    // Step 1: Header validation.
    token.header.validate()?;

    // Step 2: Signature.
    verify_signature(token, did_resolver)?;

    // Step 4: Root issuer.
    if token.payload.iss != context_creator_did {
        return Err(UcanError::InvalidIssuer {
            expected: context_creator_did.to_owned(),
            actual: token.payload.iss.clone(),
        });
    }

    // Step 5: Audience.
    if token.payload.aud != presenting_agent_did {
        return Err(UcanError::AudienceMismatch {
            expected: presenting_agent_did.to_owned(),
            actual: token.payload.aud.clone(),
        });
    }

    // Step 6: Capability match.
    // SECURITY: fail-closed — any unparseable attestation URI rejects the entire token.
    let granted_caps: Vec<CapabilityUri> = token
        .payload
        .att
        .iter()
        .map(|att| {
            att.with.parse::<CapabilityUri>().map_err(|_| {
                UcanError::MalformedToken(format!(
                    "unparseable capability URI in attestation: {}",
                    att.with
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    check_capability_match(&granted_caps, required_capability)?;

    // Step 8: Ceiling.
    verify_ceiling_compliance(std::slice::from_ref(required_capability), ceiling)?;

    // Step 11: Expiry.
    verify_expiry(token)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Individual validation steps
// ---------------------------------------------------------------------------

/// Step 2: Verify the Ed25519 signature over `base64url(header).base64url(payload)`.
///
/// # Errors
///
/// Returns [`UcanError::SignatureInvalid`] if the signature does not verify.
/// Returns [`UcanError::MalformedToken`] if the DID cannot be resolved or
/// the public key / signature bytes are malformed.
fn verify_signature(token: &UcanToken, did_resolver: &impl DidResolver) -> Result<(), UcanError> {
    let pk_bytes = did_resolver.resolve_public_key(&token.payload.iss)?;

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| UcanError::MalformedToken(format!("invalid public key: {e}")))?;

    // Extract signing input from encoded token: everything before the last '.'
    let signing_input = token
        .encoded
        .rfind('.')
        .map(|pos| &token.encoded[..pos])
        .ok_or_else(|| UcanError::MalformedToken("missing signature segment".to_owned()))?;

    let sig_bytes: [u8; 64] = token.signature.as_slice().try_into().map_err(|_| {
        UcanError::MalformedToken(format!(
            "signature must be 64 bytes, got {}",
            token.signature.len()
        ))
    })?;

    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| UcanError::SignatureInvalid)
}

/// Step 3: Verify delegation chain integrity.
///
/// For each proof CID in `prf`, resolves the parent UCAN, verifies its
/// signature, and verifies that the parent's `aud` matches this token's `iss`.
/// Recurses up the chain until reaching a root token (empty `prf`).
///
/// Returns the root issuer DID (the `iss` of the root token at the top of the
/// chain). For root tokens (empty `prf`), returns the token's own `iss`.
///
/// # Errors
///
/// Returns [`UcanError::DelegationChainBroken`] if any link is invalid.
/// Returns [`UcanError::SignatureInvalid`] if any parent signature is invalid.
fn verify_delegation_chain(
    token: &UcanToken,
    did_resolver: &impl DidResolver,
    proof_resolver: &impl ProofResolver,
) -> Result<String, UcanError> {
    if token.payload.prf.is_empty() {
        return Ok(token.payload.iss.clone());
    }

    verify_chain_recursive(token, did_resolver, proof_resolver, 0)
}

/// Recursive helper for delegation chain verification.
///
/// Walks the proof chain from child to root, verifying signatures and
/// `aud`/`iss` linkage at each step. Returns the root issuer DID.
fn verify_chain_recursive(
    token: &UcanToken,
    did_resolver: &impl DidResolver,
    proof_resolver: &impl ProofResolver,
    depth: usize,
) -> Result<String, UcanError> {
    if depth > MAX_CHAIN_DEPTH {
        return Err(UcanError::DelegationChainBroken(
            "delegation chain exceeds maximum depth".to_owned(),
        ));
    }

    // For root tokens (no proofs), the issuer is the root.
    if token.payload.prf.is_empty() {
        return Ok(token.payload.iss.clone());
    }

    // Track the root issuer found. All proof chains must converge to the same root.
    let mut root_issuer: Option<String> = None;

    for proof_cid in &token.payload.prf {
        let parent = proof_resolver.resolve_proof(proof_cid)?;

        // Verify parent's aud matches this token's iss.
        if parent.payload.aud != token.payload.iss {
            return Err(UcanError::DelegationChainBroken(format!(
                "parent aud '{}' does not match child iss '{}'",
                parent.payload.aud, token.payload.iss
            )));
        }

        // Verify parent's signature.
        verify_signature(&parent, did_resolver)?;

        // Recurse to find the root.
        let found_root = verify_chain_recursive(&parent, did_resolver, proof_resolver, depth + 1)?;

        // All proof chains must converge to the same root issuer.
        if let Some(ref existing_root) = root_issuer {
            if *existing_root != found_root {
                return Err(UcanError::DelegationChainBroken(format!(
                    "divergent root issuers: '{existing_root}' and '{found_root}'"
                )));
            }
        } else {
            root_issuer = Some(found_root);
        }
    }

    root_issuer.ok_or_else(|| {
        UcanError::DelegationChainBroken("empty proof chain with no root issuer".to_owned())
    })
}

/// Step 7: Verify attenuation — each delegation narrows or preserves capabilities.
///
/// A child token cannot grant capabilities that its parent does not have.
/// For root tokens (empty `prf`), this is a no-op.
///
/// # Errors
///
/// Returns [`UcanError::AttenuationViolation`] if a child widens capabilities.
fn verify_attenuation(
    token: &UcanToken,
    proof_resolver: &impl ProofResolver,
) -> Result<(), UcanError> {
    for proof_cid in &token.payload.prf {
        let parent = proof_resolver.resolve_proof(proof_cid)?;

        // Parse parent capabilities.
        // SECURITY: fail-closed — any unparseable parent attestation URI rejects the chain.
        let parent_caps: Vec<CapabilityUri> = parent
            .payload
            .att
            .iter()
            .map(|att| {
                att.with.parse::<CapabilityUri>().map_err(|_| {
                    UcanError::MalformedToken(format!(
                        "unparseable capability URI in parent attestation: {}",
                        att.with
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Verify every child capability is granted by a parent capability.
        for child_att in &token.payload.att {
            let child_cap: CapabilityUri = child_att
                .with
                .parse()
                .map_err(|e: UcanError| UcanError::AttenuationViolation(e.to_string()))?;

            let granted = parent_caps.iter().any(|p| p.matches(&child_cap));
            if !granted {
                return Err(UcanError::AttenuationViolation(format!(
                    "child capability '{}' not granted by parent",
                    child_att.with
                )));
            }
        }
    }
    Ok(())
}

/// Step 11: Verify token expiry.
///
/// Checks that:
/// - `exp > now` (not expired)
/// - `exp <= now + 24h` (not too far in the future)
/// - `nbf <= now` (if present, the token is already valid)
///
/// # Errors
///
/// Returns [`UcanError::TokenExpired`] if the token has expired.
/// Returns [`UcanError::ExpiryTooFar`] if `exp` exceeds now + 24 hours.
/// Returns [`UcanError::TokenNotYetValid`] if `nbf > now`.
fn verify_expiry(token: &UcanToken) -> Result<(), UcanError> {
    let now = now_secs();

    if token.payload.exp <= now {
        return Err(UcanError::TokenExpired);
    }

    if token.payload.exp > now + MAX_EXPIRY_SECS {
        return Err(UcanError::ExpiryTooFar(token.payload.exp));
    }

    if let Some(nbf) = token.payload.nbf
        && nbf > now
    {
        return Err(UcanError::TokenNotYetValid);
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::crypto::ucan::mint::{MintParams, compute_cid, mint_ucan};
    use scp_platform::testing::InMemoryKeyCustody;
    use scp_platform::traits::{KeyCustody, KeyType};

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Create an `InMemoryKeyCustody`, generate an Ed25519 key, return the
    /// custody, handle, DID string, and raw public key bytes.
    async fn setup_identity() -> (
        InMemoryKeyCustody,
        scp_platform::traits::KeyHandle,
        String,
        [u8; 32],
    ) {
        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let pubkey = custody.public_key(&handle).await.unwrap();
        let pk_bytes: [u8; 32] = pubkey.as_bytes().try_into().unwrap();
        let did = format!("did:dht:z{}", zbase32::encode(pubkey.as_bytes()));
        (custody, handle, did, pk_bytes)
    }

    /// Build a [`ValidationContext`] with in-memory implementations and
    /// [`NoOpProofResolver`].
    fn build_context<'a, S: BuildHasher>(
        did_resolver: &'a InMemoryDidResolver,
        nonce_tracker: &'a mut InMemoryNonceTracker,
        revocation_checker: &'a InMemoryRevocationChecker,
        ceiling: &'a HashSet<String, S>,
        context_creator_did: &'a str,
        presenting_agent_did: &'a str,
    ) -> ValidationContext<
        'a,
        InMemoryDidResolver,
        InMemoryNonceTracker,
        InMemoryRevocationChecker,
        NoOpProofResolver,
        S,
    > {
        ValidationContext {
            did_resolver,
            nonce_tracker,
            revocation_checker,
            proof_resolver: &NoOpProofResolver,
            ceiling,
            context_creator_did,
            presenting_agent_did,
        }
    }

    /// Build a [`ValidationContext`] with an [`InMemoryProofResolver`] for
    /// delegation chain tests.
    fn build_context_with_proofs<'a, S: BuildHasher>(
        did_resolver: &'a InMemoryDidResolver,
        nonce_tracker: &'a mut InMemoryNonceTracker,
        revocation_checker: &'a InMemoryRevocationChecker,
        proof_resolver: &'a InMemoryProofResolver,
        ceiling: &'a HashSet<String, S>,
        context_creator_did: &'a str,
        presenting_agent_did: &'a str,
    ) -> ValidationContext<
        'a,
        InMemoryDidResolver,
        InMemoryNonceTracker,
        InMemoryRevocationChecker,
        InMemoryProofResolver,
        S,
    > {
        ValidationContext {
            did_resolver,
            nonce_tracker,
            revocation_checker,
            proof_resolver,
            ceiling,
            context_creator_did,
            presenting_agent_did,
        }
    }

    fn default_ceiling() -> HashSet<String> {
        [
            "messages:read".to_owned(),
            "messages:write".to_owned(),
            "tool_invoke:assistant".to_owned(),
            "member:invite".to_owned(),
            "role:assign".to_owned(),
            "context:close".to_owned(),
        ]
        .into_iter()
        .collect()
    }

    // -----------------------------------------------------------------------
    // Step 1: Parse
    // -----------------------------------------------------------------------

    #[test]
    fn parse_ucan_rejects_too_few_segments() {
        let result = parse_ucan("only.two");
        assert!(matches!(result, Err(UcanError::MalformedToken(_))));
    }

    #[test]
    fn parse_ucan_rejects_too_many_segments() {
        let result = parse_ucan("a.b.c.d");
        assert!(matches!(result, Err(UcanError::MalformedToken(_))));
    }

    #[test]
    fn parse_ucan_rejects_invalid_base64() {
        let result = parse_ucan("!!!.@@@.###");
        assert!(matches!(result, Err(UcanError::MalformedToken(_))));
    }

    // -----------------------------------------------------------------------
    // Step 2: Signature verification
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn validate_ucan_accepts_valid_token() {
        let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-test",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();

        let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &ceiling,
            &issuer_did,
            "did:dht:z6MkMember",
        );

        let result = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(result.is_ok(), "valid token must pass: {result:?}");
    }

    #[tokio::test]
    async fn validate_ucan_rejects_tampered_signature() {
        let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-test",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let mut token = mint_ucan(&params, &custody).await.unwrap();

        // Tamper with the signature.
        token.signature[0] ^= 0xFF;
        // Also update the encoded string with the tampered sig.
        let parts: Vec<&str> = token.encoded.split('.').collect();
        let tampered_sig_b64 = URL_SAFE_NO_PAD.encode(&token.signature);
        token.encoded = format!("{}.{}.{}", parts[0], parts[1], tampered_sig_b64);

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();

        let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &ceiling,
            &issuer_did,
            "did:dht:z6MkMember",
        );

        let result = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(
            matches!(result, Err(UcanError::SignatureInvalid)),
            "tampered signature must be rejected: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Step 3: Delegation chain verification
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn validate_ucan_accepts_delegated_token() {
        use crate::crypto::ucan::Attenuation;
        use crate::crypto::ucan::mint::DelegateParams;

        // Creator (root issuer)
        let (custody_creator, key_creator, creator_did, pk_creator) = setup_identity().await;
        // Delegator (receives from creator, delegates to agent)
        let (custody_delegator, key_delegator, delegator_did, pk_delegator) =
            setup_identity().await;
        // Agent (final audience)
        let (_custody_agent, _key_agent, agent_did, _pk_agent) = setup_identity().await;

        let caps = vec!["messages:write".to_owned(), "messages:read".to_owned()];

        // Creator mints root token to delegator.
        let root_token = mint_ucan(
            &MintParams {
                issuer_did: &creator_did,
                issuer_key: &key_creator,
                audience_did: &delegator_did,
                context_id: "ctx-chain",
                capabilities: &caps,
                lifetime_secs: 3600,
                not_before: None,
                proofs: vec![],
                facts: None,
            },
            &custody_creator,
        )
        .await
        .unwrap();

        let root_cid = compute_cid(&root_token);

        // Delegator delegates to agent (narrowing to just write).
        let delegated_token = crate::crypto::ucan::mint::delegate_ucan(
            &DelegateParams {
                parent_token: &root_token,
                delegator_did: &delegator_did,
                delegator_key: &key_delegator,
                delegatee_did: &agent_did,
                attenuated_capabilities: &[Attenuation {
                    with: "scp:ctx:ctx-chain/messages:write".to_owned(),
                    can: "write".to_owned(),
                }],
                lifetime_secs: 1800,
                facts: None,
            },
            &custody_delegator,
        )
        .await
        .unwrap();

        // Build resolver with both keys.
        let resolver = InMemoryDidResolver {
            keys: [
                (creator_did.clone(), pk_creator),
                (delegator_did.clone(), pk_delegator),
            ]
            .into_iter()
            .collect(),
        };

        let proof_resolver = InMemoryProofResolver {
            proofs: std::collections::HashMap::from([(root_cid, root_token)]),
        };

        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-chain", "messages", "write");

        let mut ctx = build_context_with_proofs(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
            &ceiling,
            &creator_did,
            &agent_did,
        );

        let result = validate_ucan(&delegated_token, &required_cap, &mut ctx);
        assert!(
            result.is_ok(),
            "delegated token must pass validation: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_ucan_rejects_broken_chain_aud_iss_mismatch() {
        let (custody_creator, key_creator, creator_did, pk_creator) = setup_identity().await;
        let (_custody_a, _key_a, did_a, _pk_a) = setup_identity().await;
        let (custody_b, key_b, did_b, pk_b) = setup_identity().await;
        let (_custody_agent, _key_agent, agent_did, _pk_agent) = setup_identity().await;

        let caps = vec!["messages:write".to_owned()];

        // Root token: creator -> A.
        let root_token = mint_ucan(
            &MintParams {
                issuer_did: &creator_did,
                issuer_key: &key_creator,
                audience_did: &did_a,
                context_id: "ctx-chain",
                capabilities: &caps,
                lifetime_secs: 3600,
                not_before: None,
                proofs: vec![],
                facts: None,
            },
            &custody_creator,
        )
        .await
        .unwrap();

        let root_cid = compute_cid(&root_token);

        // B tries to delegate from root_token, but root_token.aud = A, not B.
        // Manually construct a bad token by minting with proofs.
        let bad_delegated = mint_ucan(
            &MintParams {
                issuer_did: &did_b,
                issuer_key: &key_b,
                audience_did: &agent_did,
                context_id: "ctx-chain",
                capabilities: &caps,
                lifetime_secs: 1800,
                not_before: None,
                proofs: vec![root_cid.clone()],
                facts: None,
            },
            &custody_b,
        )
        .await
        .unwrap();

        let resolver = InMemoryDidResolver {
            keys: [(creator_did.clone(), pk_creator), (did_b.clone(), pk_b)]
                .into_iter()
                .collect(),
        };

        let proof_resolver = InMemoryProofResolver {
            proofs: std::collections::HashMap::from([(root_cid, root_token)]),
        };

        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-chain", "messages", "write");

        let mut ctx = build_context_with_proofs(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
            &ceiling,
            &creator_did,
            &agent_did,
        );

        let result = validate_ucan(&bad_delegated, &required_cap, &mut ctx);
        assert!(
            matches!(result, Err(UcanError::DelegationChainBroken(_))),
            "broken chain (aud/iss mismatch) must be rejected: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_ucan_rejects_unresolvable_proof() {
        let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
        let caps = vec!["messages:write".to_owned()];

        // Mint a token with a non-existent proof CID.
        let token = mint_ucan(
            &MintParams {
                issuer_did: &issuer_did,
                issuer_key: &key_handle,
                audience_did: "did:dht:z6MkMember",
                context_id: "ctx-test",
                capabilities: &caps,
                lifetime_secs: 3600,
                not_before: None,
                proofs: vec!["bafyrei-nonexistent".to_owned()],
                facts: None,
            },
            &custody,
        )
        .await
        .unwrap();

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        };

        let proof_resolver = InMemoryProofResolver::new();

        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

        let mut ctx = build_context_with_proofs(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
            &ceiling,
            &issuer_did,
            "did:dht:z6MkMember",
        );

        let result = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(
            matches!(result, Err(UcanError::DelegationChainBroken(_))),
            "unresolvable proof CID must be rejected: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Step 4: Root issuer
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn validate_ucan_rejects_wrong_issuer() {
        let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-test",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();

        let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

        // Use a different context creator DID.
        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &ceiling,
            "did:dht:z6MkWrongCreator",
            "did:dht:z6MkMember",
        );

        let result = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(
            matches!(result, Err(UcanError::InvalidIssuer { .. })),
            "wrong issuer must be rejected: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_ucan_rejects_wrong_root_issuer_in_chain() {
        use crate::crypto::ucan::Attenuation;
        use crate::crypto::ucan::mint::DelegateParams;

        // Non-creator mints the root. The context creator is different.
        let (custody_non_creator, key_non_creator, non_creator_did, pk_non_creator) =
            setup_identity().await;
        let (custody_delegator, key_delegator, delegator_did, pk_delegator) =
            setup_identity().await;
        let (_custody_agent, _key_agent, agent_did, _pk_agent) = setup_identity().await;

        let caps = vec!["messages:write".to_owned()];

        // Root token: non_creator -> delegator.
        let root_token = mint_ucan(
            &MintParams {
                issuer_did: &non_creator_did,
                issuer_key: &key_non_creator,
                audience_did: &delegator_did,
                context_id: "ctx-chain",
                capabilities: &caps,
                lifetime_secs: 3600,
                not_before: None,
                proofs: vec![],
                facts: None,
            },
            &custody_non_creator,
        )
        .await
        .unwrap();

        let root_cid = compute_cid(&root_token);

        // Delegator -> agent.
        let delegated_token = crate::crypto::ucan::mint::delegate_ucan(
            &DelegateParams {
                parent_token: &root_token,
                delegator_did: &delegator_did,
                delegator_key: &key_delegator,
                delegatee_did: &agent_did,
                attenuated_capabilities: &[Attenuation {
                    with: "scp:ctx:ctx-chain/messages:write".to_owned(),
                    can: "write".to_owned(),
                }],
                lifetime_secs: 1800,
                facts: None,
            },
            &custody_delegator,
        )
        .await
        .unwrap();

        let resolver = InMemoryDidResolver {
            keys: [
                (non_creator_did.clone(), pk_non_creator),
                (delegator_did.clone(), pk_delegator),
            ]
            .into_iter()
            .collect(),
        };

        let proof_resolver = InMemoryProofResolver {
            proofs: std::collections::HashMap::from([(root_cid, root_token)]),
        };

        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-chain", "messages", "write");

        // The context creator is "did:dht:z6MkRealCreator" -- not non_creator.
        let mut ctx = build_context_with_proofs(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
            &ceiling,
            "did:dht:z6MkRealCreator",
            &agent_did,
        );

        let result = validate_ucan(&delegated_token, &required_cap, &mut ctx);
        assert!(
            matches!(result, Err(UcanError::InvalidIssuer { .. })),
            "wrong root issuer in chain must be rejected: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Step 5: Audience
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn validate_ucan_rejects_audience_mismatch() {
        let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-test",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();

        let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

        // Use a different presenting agent DID.
        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &ceiling,
            &issuer_did,
            "did:dht:z6MkWrongAgent",
        );

        let result = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(
            matches!(result, Err(UcanError::AudienceMismatch { .. })),
            "audience mismatch must be rejected: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Step 6: Capability match
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn validate_ucan_rejects_missing_capability() {
        let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
        let caps = vec!["messages:read".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-test",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();

        // Request a capability the token does NOT grant.
        let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &ceiling,
            &issuer_did,
            "did:dht:z6MkMember",
        );

        let result = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(
            matches!(result, Err(UcanError::CapabilityNotGranted(_))),
            "missing capability must be rejected: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_ucan_accepts_wildcard_capability_grant() {
        let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;

        // Mint with wildcard context_id "*" to produce scp:ctx:*/messages:write.
        let caps = vec!["messages:write".to_owned()];
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "*",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        // Verify the attenuation uses wildcard context.
        assert_eq!(token.payload.att[0].with, "scp:ctx:*/messages:write");

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();

        // Request specific context capability -- wildcard should match.
        let required_cap = CapabilityUri::new("ctx-specific", "messages", "write");

        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &ceiling,
            &issuer_did,
            "did:dht:z6MkMember",
        );

        let result = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(
            result.is_ok(),
            "wildcard capability must match specific context: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Step 7: Attenuation verification
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn validate_ucan_rejects_widened_capabilities_in_delegation() {
        // Creator grants read-only. Delegator tries to delegate write.
        let (custody_creator, key_creator, creator_did, pk_creator) = setup_identity().await;
        let (custody_delegator, key_delegator, delegator_did, pk_delegator) =
            setup_identity().await;
        let (_custody_agent, _key_agent, agent_did, _pk_agent) = setup_identity().await;

        let caps = vec!["messages:read".to_owned()]; // Only read.

        // Root token: creator -> delegator (read only).
        let root_token = mint_ucan(
            &MintParams {
                issuer_did: &creator_did,
                issuer_key: &key_creator,
                audience_did: &delegator_did,
                context_id: "ctx-att",
                capabilities: &caps,
                lifetime_secs: 3600,
                not_before: None,
                proofs: vec![],
                facts: None,
            },
            &custody_creator,
        )
        .await
        .unwrap();

        let root_cid = compute_cid(&root_token);

        // Manually construct a delegated token that WIDENS to write.
        // (delegate_ucan would reject this, so we mint directly with proofs.)
        let bad_token = mint_ucan(
            &MintParams {
                issuer_did: &delegator_did,
                issuer_key: &key_delegator,
                audience_did: &agent_did,
                context_id: "ctx-att",
                capabilities: &["messages:write".to_owned()], // Widened!
                lifetime_secs: 1800,
                not_before: None,
                proofs: vec![root_cid.clone()],
                facts: None,
            },
            &custody_delegator,
        )
        .await
        .unwrap();

        let resolver = InMemoryDidResolver {
            keys: [
                (creator_did.clone(), pk_creator),
                (delegator_did.clone(), pk_delegator),
            ]
            .into_iter()
            .collect(),
        };

        let proof_resolver = InMemoryProofResolver {
            proofs: std::collections::HashMap::from([(root_cid, root_token)]),
        };

        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-att", "messages", "write");

        let mut ctx = build_context_with_proofs(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
            &ceiling,
            &creator_did,
            &agent_did,
        );

        let result = validate_ucan(&bad_token, &required_cap, &mut ctx);
        assert!(
            matches!(result, Err(UcanError::AttenuationViolation(_))),
            "widened delegation must be rejected: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Step 8: Ceiling
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn validate_ucan_rejects_capability_outside_ceiling() {
        let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
        let caps = vec!["context:close".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-test",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();

        // Ceiling does NOT include context:close.
        let ceiling: HashSet<String> = ["messages:read".to_owned(), "messages:write".to_owned()]
            .into_iter()
            .collect();

        let required_cap = CapabilityUri::new("ctx-test", "context", "close");

        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &ceiling,
            &issuer_did,
            "did:dht:z6MkMember",
        );

        let result = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(
            matches!(result, Err(UcanError::CapabilityOutsideCeiling(_))),
            "capability outside ceiling must be rejected: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Step 9: Nonce
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn validate_ucan_rejects_nonce_replay() {
        let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-nonce",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-nonce", "messages", "write");

        // First validation should succeed.
        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &ceiling,
            &issuer_did,
            "did:dht:z6MkMember",
        );
        let result = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(result.is_ok(), "first validation must pass: {result:?}");

        // Second validation with same token should fail (nonce replay).
        let mut ctx2 = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &ceiling,
            &issuer_did,
            "did:dht:z6MkMember",
        );
        let result2 = validate_ucan(&token, &required_cap, &mut ctx2);
        assert!(
            matches!(result2, Err(UcanError::NonceReused(_))),
            "nonce replay must be rejected: {result2:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Step 10: Revocation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn validate_ucan_rejects_revoked_token() {
        let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-test",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();

        // Add the token's CID to the revocation list.
        let mut revocation_checker = InMemoryRevocationChecker::new();
        revocation_checker.revoked.insert(compute_cid(&token));

        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &ceiling,
            &issuer_did,
            "did:dht:z6MkMember",
        );

        let result = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(
            matches!(result, Err(UcanError::TokenRevoked(_))),
            "revoked token must be rejected: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_ucan_revocation_uses_compute_cid() {
        let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-cid",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();
        let token_cid = compute_cid(&token);

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();

        // Revoke using compute_cid.
        let mut revocation_checker = InMemoryRevocationChecker::new();
        revocation_checker.revoked.insert(token_cid.clone());

        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-cid", "messages", "write");

        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &ceiling,
            &issuer_did,
            "did:dht:z6MkMember",
        );

        let result = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(
            matches!(result, Err(UcanError::TokenRevoked(ref cid)) if cid == &token_cid),
            "token revoked by compute_cid must be rejected: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Step 11: Expiry
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn validate_ucan_rejects_expired_token() {
        let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-test",
            capabilities: &caps,
            lifetime_secs: 1, // Very short lifetime.
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        // Wait for the token to expire.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();

        let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &ceiling,
            &issuer_did,
            "did:dht:z6MkMember",
        );

        let result = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(
            matches!(result, Err(UcanError::TokenExpired)),
            "expired token must be rejected: {result:?}"
        );
    }

    #[test]
    fn verify_expiry_rejects_token_with_exp_beyond_24h() {
        let now = now_secs();
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".to_owned(),
                aud: "did:dht:z6MkMember".to_owned(),
                exp: now + MAX_EXPIRY_SECS + 3600, // 25 hours from now
                nbf: None,
                nnc: "1234567890000-aabbccdd11223344aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };

        let result = verify_expiry(&token);
        assert!(
            matches!(result, Err(UcanError::ExpiryTooFar(_))),
            "exp beyond 24h must be rejected: {result:?}"
        );
    }

    #[test]
    fn verify_expiry_rejects_already_expired() {
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".to_owned(),
                aud: "did:dht:z6MkMember".to_owned(),
                exp: 1, // Long expired.
                nbf: None,
                nnc: "1234567890000-aabbccdd11223344aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };

        let result = verify_expiry(&token);
        assert!(matches!(result, Err(UcanError::TokenExpired)));
    }

    #[test]
    fn verify_expiry_rejects_not_yet_valid() {
        let now = now_secs();
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".to_owned(),
                aud: "did:dht:z6MkMember".to_owned(),
                exp: now + 3600,
                nbf: Some(now + 7200), // Not valid for 2 hours.
                nnc: "1234567890000-aabbccdd11223344aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };

        let result = verify_expiry(&token);
        assert!(matches!(result, Err(UcanError::TokenNotYetValid)));
    }

    #[test]
    fn verify_expiry_accepts_valid_token() {
        let now = now_secs();
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".to_owned(),
                aud: "did:dht:z6MkMember".to_owned(),
                exp: now + 3600,
                nbf: Some(now - 60),
                nnc: "1234567890000-aabbccdd11223344aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };

        assert!(verify_expiry(&token).is_ok());
    }

    // -----------------------------------------------------------------------
    // Nonce tracker tests
    // -----------------------------------------------------------------------

    #[test]
    fn nonce_tracker_rejects_reused_nonce() {
        let mut tracker = InMemoryNonceTracker::new();
        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();

        let nonce = format!("{now_millis}-aabbccdd11223344aabbccdd11223344");
        let expiry = now_secs() + 3600;

        assert!(tracker.check_and_record(&nonce, expiry).is_ok());
        let result = tracker.check_and_record(&nonce, expiry);
        assert!(
            matches!(result, Err(UcanError::NonceReused(_))),
            "reused nonce must be rejected: {result:?}"
        );
    }

    #[test]
    fn nonce_tracker_rejects_malformed_nonce() {
        let mut tracker = InMemoryNonceTracker::new();
        let expiry = now_secs() + 3600;

        // No separator.
        let result = tracker.check_and_record("nohyphen", expiry);
        assert!(matches!(result, Err(UcanError::NonceFormatInvalid(_))));

        // Non-numeric timestamp.
        let result =
            tracker.check_and_record("notanumber-aabbccdd11223344aabbccdd11223344", expiry);
        assert!(matches!(result, Err(UcanError::NonceFormatInvalid(_))));

        // Hex suffix too short.
        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let result = tracker.check_and_record(&format!("{now_millis}-aabb"), expiry);
        assert!(matches!(result, Err(UcanError::NonceFormatInvalid(_))));
    }

    // -----------------------------------------------------------------------
    // Parse + validate roundtrip
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn parse_and_validate_roundtrip() {
        let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-roundtrip",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let minted = mint_ucan(&params, &custody).await.unwrap();

        // Parse the encoded token back.
        let parsed = parse_ucan(&minted.encoded).unwrap();
        assert_eq!(parsed.header, minted.header);
        assert_eq!(parsed.payload, minted.payload);
        assert_eq!(parsed.signature, minted.signature);

        // Validate the parsed token.
        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();

        let required_cap = CapabilityUri::new("ctx-roundtrip", "messages", "write");

        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &ceiling,
            &issuer_did,
            "did:dht:z6MkMember",
        );

        assert!(validate_ucan(&parsed, &required_cap, &mut ctx).is_ok());
    }

    // -----------------------------------------------------------------------
    // Stateless validation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn validate_ucan_stateless_accepts_valid_token() {
        let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-stateless",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        };
        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-stateless", "messages", "write");

        let result = validate_ucan_stateless(
            &token,
            &required_cap,
            &resolver,
            &ceiling,
            &issuer_did,
            "did:dht:z6MkMember",
        );
        assert!(
            result.is_ok(),
            "stateless validation should pass: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Full pipeline: mint -> delegate -> parse -> validate
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn full_pipeline_mint_delegate_parse_validate() {
        use crate::crypto::ucan::Attenuation;
        use crate::crypto::ucan::mint::DelegateParams;

        let (custody_creator, key_creator, creator_did, pk_creator) = setup_identity().await;
        let (custody_delegator, key_delegator, delegator_did, pk_delegator) =
            setup_identity().await;

        let caps = vec![
            "messages:write".to_owned(),
            "messages:read".to_owned(),
            "tool_invoke:assistant".to_owned(),
        ];

        // Creator mints root.
        let root_token = mint_ucan(
            &MintParams {
                issuer_did: &creator_did,
                issuer_key: &key_creator,
                audience_did: &delegator_did,
                context_id: "ctx-full",
                capabilities: &caps,
                lifetime_secs: 3600,
                not_before: None,
                proofs: vec![],
                facts: None,
            },
            &custody_creator,
        )
        .await
        .unwrap();

        let root_cid = compute_cid(&root_token);

        // Delegator narrows to read + write.
        let delegated = crate::crypto::ucan::mint::delegate_ucan(
            &DelegateParams {
                parent_token: &root_token,
                delegator_did: &delegator_did,
                delegator_key: &key_delegator,
                delegatee_did: "did:dht:z6MkAgent",
                attenuated_capabilities: &[
                    Attenuation {
                        with: "scp:ctx:ctx-full/messages:write".to_owned(),
                        can: "write".to_owned(),
                    },
                    Attenuation {
                        with: "scp:ctx:ctx-full/messages:read".to_owned(),
                        can: "read".to_owned(),
                    },
                ],
                lifetime_secs: 1800,
                facts: None,
            },
            &custody_delegator,
        )
        .await
        .unwrap();

        // Parse from encoded form.
        let parsed = parse_ucan(&delegated.encoded).unwrap();
        assert_eq!(parsed.payload.iss, delegator_did);
        assert_eq!(parsed.payload.aud, "did:dht:z6MkAgent");
        assert_eq!(parsed.payload.att.len(), 2);

        // Validate.
        let resolver = InMemoryDidResolver {
            keys: [
                (creator_did.clone(), pk_creator),
                (delegator_did.clone(), pk_delegator),
            ]
            .into_iter()
            .collect(),
        };

        let proof_resolver = InMemoryProofResolver {
            proofs: std::collections::HashMap::from([(root_cid, root_token)]),
        };

        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-full", "messages", "write");

        let mut ctx = build_context_with_proofs(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
            &ceiling,
            &creator_did,
            "did:dht:z6MkAgent",
        );

        let result = validate_ucan(&parsed, &required_cap, &mut ctx);
        assert!(
            result.is_ok(),
            "full pipeline (mint -> delegate -> parse -> validate) must pass: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // InMemoryProofResolver tests
    // -----------------------------------------------------------------------

    #[test]
    fn in_memory_proof_resolver_rejects_missing_cid() {
        let resolver = InMemoryProofResolver::new();
        let result = resolver.resolve_proof("bafyrei-missing");
        assert!(matches!(result, Err(UcanError::DelegationChainBroken(_))));
    }

    #[test]
    fn in_memory_proof_resolver_returns_stored_token() {
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".to_owned(),
                aud: "did:dht:z6MkMember".to_owned(),
                exp: 1_700_000_000,
                nbf: None,
                nnc: "1234567890000-aabbccdd11223344aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: "test.encoded.token".to_owned(),
        };

        let mut proof_resolver = InMemoryProofResolver::new();
        proof_resolver
            .proofs
            .insert("bafyrei-test".to_owned(), token.clone());

        let result = proof_resolver.resolve_proof("bafyrei-test").unwrap();
        assert_eq!(result, token);
    }
}
