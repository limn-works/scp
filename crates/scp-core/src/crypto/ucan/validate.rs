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
//!    5a. **Self-delegation** — Reject `iss == aud` unless `scp_key_scope` present (ADR-039).
//!    5b. **Key scope** — If `fct.scp_key_scope` present, verify signing key matches scope (ADR-039).
//! 6. **Capability match** — Verify `att` includes required capability.
//!    6b. **Category A enforcement** — If `kid` is `#agent`, reject Category A capabilities (ADR-039).
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

use scp_identity::SigningKeyId;
use scp_primitives::Clock;

use super::capability::{CapabilityUri, check_capability_match, verify_ceiling_compliance};
use super::revoke::compute_revocation_cid;
use super::{UcanError, UcanHeader, UcanPayload, UcanToken};
use crate::trust::custody_violation::{ActionCategory, classify_action};

/// Maximum token lifetime: 24 hours in seconds (spec section 9.5).
const MAX_EXPIRY_SECS: u64 = 24 * 60 * 60;

/// Default clock skew tolerance: 5 minutes in seconds (spec section 9.14).
///
/// Applied to `exp` and `nbf` checks in `verify_expiry` to accommodate
/// NTP desynchronization between issuer and validator in distributed
/// deployments.
pub const DEFAULT_CLOCK_SKEW_TOLERANCE_SECS: u64 = 5 * 60;

/// Nonce freshness tolerance: 5 minutes in milliseconds (spec section 9.14).
#[cfg(test)]
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
///
/// The `resolve_public_key_by_kid` method supports ADR-039's shared-DID model
/// where a single DID has multiple verification methods (`#active`, `#agent`).
/// When a UCAN header includes a `kid` field, the validator uses this method
/// to resolve the specific verification method's public key.
pub trait DidResolver {
    /// Resolves a DID to its Ed25519 public key (32 bytes).
    ///
    /// Returns the default (`#active`) public key for the DID.
    ///
    /// # Errors
    ///
    /// Returns [`UcanError::MalformedToken`] if the DID cannot be resolved.
    fn resolve_public_key(&self, did: &str) -> Result<[u8; 32], UcanError>;

    /// Resolves a specific verification method on a DID document by `kid`
    /// (Key ID) fragment identifier (ADR-039, SCP-AB-013).
    ///
    /// The `kid` is a verification method fragment identifier such as
    /// `"#active"` or `"#agent"`. Implementations should look up the
    /// verification method matching this fragment on the DID document and
    /// return its Ed25519 public key bytes.
    ///
    /// The default implementation falls back to [`DidResolver::resolve_public_key`] when
    /// `kid` is `"#active"` (the default key), making this backward-compatible
    /// with existing implementations that only support single-key DIDs.
    ///
    /// # Errors
    ///
    /// Returns [`UcanError::MalformedToken`] if the DID or verification
    /// method cannot be resolved.
    fn resolve_public_key_by_kid(&self, did: &str, kid: &str) -> Result<[u8; 32], UcanError> {
        if kid == "#active" {
            self.resolve_public_key(did)
        } else {
            Err(UcanError::MalformedToken(format!(
                "verification method '{kid}' not found on DID '{did}' \
                 (default resolver only supports #active)"
            )))
        }
    }
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

/// In-memory [`DidResolver`] backed by `HashMap`s.
///
/// Maps DID strings to Ed25519 public key bytes. Supports both default key
/// resolution and `kid`-based resolution for shared-DID models (ADR-039).
pub struct InMemoryDidResolver {
    /// Map of DID string to 32-byte Ed25519 public key (default / `#active`).
    pub keys: std::collections::HashMap<String, [u8; 32]>,
    /// Map of `(DID, kid)` to 32-byte Ed25519 public key for specific
    /// verification methods (e.g., `#agent`). Used by
    /// [`DidResolver::resolve_public_key_by_kid`] when `kid` is not `#active`.
    pub kid_keys: std::collections::HashMap<(String, String), [u8; 32]>,
}

impl InMemoryDidResolver {
    /// Creates a new resolver with the given default keys and no kid-specific keys.
    #[must_use]
    pub fn from_keys(keys: std::collections::HashMap<String, [u8; 32]>) -> Self {
        Self {
            keys,
            kid_keys: std::collections::HashMap::new(),
        }
    }
}

impl DidResolver for InMemoryDidResolver {
    fn resolve_public_key(&self, did: &str) -> Result<[u8; 32], UcanError> {
        self.keys
            .get(did)
            .copied()
            .ok_or_else(|| UcanError::MalformedToken(format!("DID not found: {did}")))
    }

    fn resolve_public_key_by_kid(&self, did: &str, kid: &str) -> Result<[u8; 32], UcanError> {
        // First check kid_keys for an explicit entry.
        if let Some(pk) = self.kid_keys.get(&(did.to_owned(), kid.to_owned())) {
            return Ok(*pk);
        }
        // Fall back: if kid is #active, use the default key.
        if kid == "#active" {
            return self.resolve_public_key(did);
        }
        Err(UcanError::MalformedToken(format!(
            "verification method '{kid}' not found on DID '{did}'"
        )))
    }
}

/// In-memory [`NonceTracker`] backed by a `HashMap`.
///
/// Records seen nonces with timestamps and expiry for replay prevention.
/// Validates nonce format (`{unix_millis}-{32_hex_chars}`), freshness
/// (timestamp within +/- 5 minutes of now), and uniqueness.
///
/// Restricted to test builds — production code should use
/// [`nonce::NonceTracker`](super::nonce::NonceTracker) which provides
/// per-context scoping, capacity limits, and automatic pruning.
///
/// See ADR-016 acceptance criterion 6.
#[cfg(test)]
pub(crate) struct InMemoryNonceTracker {
    /// Map of nonce -> (`first_seen_timestamp_secs`, `token_expiry_secs`).
    seen: std::collections::HashMap<String, (u64, u64)>,
}

#[cfg(test)]
impl InMemoryNonceTracker {
    /// Creates a new empty nonce tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: std::collections::HashMap::new(),
        }
    }
}

#[cfg(test)]
impl Default for InMemoryNonceTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
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
        let now_millis = u128::from(scp_primitives::SystemClock.now_millis());

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
    /// Clock skew tolerance in seconds for `exp`/`nbf` checks (step 11).
    ///
    /// Accommodates NTP desynchronization between issuer and validator in
    /// distributed deployments. Defaults to
    /// [`DEFAULT_CLOCK_SKEW_TOLERANCE_SECS`] (5 minutes, per spec section
    /// 9.14).
    ///
    /// - `exp` check: token accepted if `exp + tolerance >= now`
    /// - `nbf` check: token accepted if `nbf - tolerance <= now`
    pub clock_skew_tolerance_secs: u64,
    /// Clock for time-dependent checks (steps 3, 11).
    ///
    /// Accepts `&dyn Clock` to support both production ([`SystemClock`]) and
    /// test ([`TestClock`]) clocks.
    ///
    /// [`SystemClock`]: scp_primitives::SystemClock
    /// [`TestClock`]: scp_primitives::TestClock
    pub clock: &'a dyn Clock,
}

// ---------------------------------------------------------------------------
// Main validation function
// ---------------------------------------------------------------------------

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
    // Verifies signatures, expiry, revocation, and aud/iss linkage on all
    // parent tokens. Returns the root issuer DID.
    let root_issuer = verify_delegation_chain(
        token,
        ctx.did_resolver,
        ctx.proof_resolver,
        ctx.revocation_checker,
        ctx.clock_skew_tolerance_secs,
        ctx.clock,
    )?;

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

    // Steps 5a/5b: Key scope validation (ADR-039, SCP-AB-013).
    // Rejects self-delegation without key_scope and key_scope/kid mismatches.
    validate_key_scope(token)?;

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

    // Step 6b: Category A enforcement (ADR-039 Enforcement Stack layer 3).
    // If the token is signed by #agent, reject any Category A capabilities
    // (DID document modifications, pre-rotation, identity migration).
    enforce_ucan_category_a(token, &granted_caps)?;

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
    // Uses the revocation CID (SHA-256 of the raw encoded JWT) to match
    // the format used by revoke_ucan.
    let revocation_cid = compute_revocation_cid(&token.encoded);
    if ctx.revocation_checker.is_revoked(&revocation_cid) {
        return Err(UcanError::TokenRevoked(revocation_cid));
    }

    // Step 11: Expiry — verify exp > now and nbf <= now (with clock skew
    // tolerance).
    verify_expiry(token, ctx.clock_skew_tolerance_secs, ctx.clock)?;

    Ok(())
}

/// Validates a pre-parsed UCAN token without nonce tracking or revocation
/// checks.
///
/// This is a lighter-weight validation suitable for cases where the caller
/// manages nonce tracking and revocation externally, or for quick signature
/// and structure checks.
///
/// Performs steps 1, 2, 4, 5, 5a, 5b, 6, 6b, 8, and 11 of the 11-step pipeline.
/// Steps 5a (self-delegation without key scope) and 5b (key scope / kid
/// mismatch) are enforced via [`validate_key_scope`]. Step 6b (Category A
/// enforcement) rejects agent-signed tokens granting Category A capabilities.
///
/// # Errors
///
/// Returns a specific [`UcanError`] variant indicating which step failed.
#[cfg(test)]
pub(crate) fn validate_ucan_stateless<D, S>(
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

    // Steps 5a/5b: Key scope validation (ADR-039, SCP-AB-013).
    validate_key_scope(token)?;

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

    // Step 6b: Category A enforcement (ADR-039).
    enforce_ucan_category_a(token, &granted_caps)?;

    // Step 8: Ceiling.
    verify_ceiling_compliance(std::slice::from_ref(required_capability), ceiling)?;

    // Step 11: Expiry (with default clock skew tolerance, system clock).
    verify_expiry(
        token,
        DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
        &scp_primitives::SystemClock,
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Individual validation steps
// ---------------------------------------------------------------------------

/// Extracts the `scp_key_scope` value from a UCAN payload's facts.
///
/// Returns `Some(scope)` if `fct.scp_key_scope` exists and is a string,
/// `None` otherwise (backward compatibility — legacy tokens without key
/// scope skip step 5b).
///
/// See ADR-039 and SCP-AB-013.
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
/// This function enforces two ADR-039 / SCP-AB-013 rules:
///
/// - **Step 5a (self-delegation):** If `iss == aud` and no `scp_key_scope`
///   is present in `fct`, the token is rejected with
///   [`UcanError::SelfDelegationWithoutKeyScope`]. Self-delegation is only
///   meaningful when scoping to a specific verification method.
///
/// - **Step 5b (key scope match):** If `fct.scp_key_scope` is present, the
///   `kid` header (defaulting to `#active` when absent) must match the
///   declared scope. Mismatch yields [`UcanError::KeyScopeMismatch`].
///
/// This function is called on both the presented token and on every parent
/// token in the delegation chain, ensuring an attacker cannot smuggle an
/// invalid self-delegation or key scope mismatch into a parent.
///
/// # Errors
///
/// Returns [`UcanError::SelfDelegationWithoutKeyScope`] or
/// [`UcanError::KeyScopeMismatch`] on violation.
fn validate_key_scope(token: &UcanToken) -> Result<(), UcanError> {
    let key_scope = extract_key_scope(&token.payload);

    // Step 5a: Self-delegation without key_scope is a safety violation.
    if token.payload.iss == token.payload.aud && key_scope.is_none() {
        return Err(UcanError::SelfDelegationWithoutKeyScope);
    }

    // Step 5b: If key_scope is present, verify kid matches.
    if let Some(ref scope) = key_scope {
        let actual_kid = token.header.kid.as_deref().unwrap_or("#active");
        if actual_kid != scope {
            return Err(UcanError::KeyScopeMismatch {
                expected_scope: scope.clone(),
                actual_kid: actual_kid.to_owned(),
            });
        }
    }

    Ok(())
}

/// Step 6b: Enforces Category A restrictions on a UCAN token (ADR-039
/// Enforcement Stack layer 3).
///
/// If the token is signed by `#agent` (indicated by the `kid` header field)
/// and any granted capability is a Category A action, the token is rejected
/// with [`UcanError::CategoryAViolation`].
///
/// This is a network-level enforcement point: non-conformant SDKs can produce
/// these signatures but they cannot propagate through the network.
///
/// # Arguments
///
/// * `token` - The parsed UCAN token (reads `kid` from the header).
/// * `granted_caps` - The parsed capability URIs from the token's attestations.
///
/// # Errors
///
/// Returns [`UcanError::CategoryAViolation`] if any capability is Category A
/// and the signing key is `#agent`.
fn enforce_ucan_category_a(
    token: &UcanToken,
    granted_caps: &[CapabilityUri],
) -> Result<(), UcanError> {
    let kid_str = token.header.kid.as_deref().unwrap_or("#active");

    // Parse kid to SigningKeyId. Only #active and #agent are valid UCAN signing
    // keys. Unknown kid values are rejected fail-closed.
    let signing_key_id = match kid_str {
        "#active" => SigningKeyId::Active,
        "#agent" => SigningKeyId::Agent,
        _ => {
            return Err(UcanError::MalformedToken(format!(
                "unrecognized signing key ID (kid): {kid_str}"
            )));
        }
    };

    if signing_key_id != SigningKeyId::Agent {
        return Ok(());
    }

    for cap in granted_caps {
        if classify_action(cap.resource()) == ActionCategory::CategoryA {
            return Err(UcanError::CategoryAViolation {
                action: cap.capability_name(),
                kid: kid_str.to_owned(),
            });
        }
    }

    Ok(())
}

/// Step 2: Verify the Ed25519 signature over `base64url(header).base64url(payload)`.
///
/// When the token header includes a `kid` field (ADR-039), the public key is
/// resolved from the specific verification method on the issuer's DID document.
/// Otherwise, the default (`#active`) key is used.
///
/// # Errors
///
/// Returns [`UcanError::SignatureInvalid`] if the signature does not verify.
/// Returns [`UcanError::MalformedToken`] if the DID cannot be resolved or
/// the public key / signature bytes are malformed.
fn verify_signature(token: &UcanToken, did_resolver: &impl DidResolver) -> Result<(), UcanError> {
    // When kid is present in the header, resolve the specific verification
    // method from the DID document (ADR-039, SCP-AB-013).
    let pk_bytes = match &token.header.kid {
        Some(kid) => did_resolver.resolve_public_key_by_kid(&token.payload.iss, kid)?,
        None => did_resolver.resolve_public_key(&token.payload.iss)?,
    };

    // Extract signing input from encoded token: everything before the last '.'
    let signing_input = token
        .encoded
        .rfind('.')
        .map(|pos| &token.encoded[..pos])
        .ok_or_else(|| UcanError::MalformedToken("missing signature segment".to_owned()))?;

    crate::crypto::ed25519::verify_ed25519_signature(
        &pk_bytes,
        signing_input.as_bytes(),
        &token.signature,
    )
    .map_err(|_| UcanError::SignatureInvalid)
}

/// Step 3: Verify delegation chain integrity.
///
/// For each proof CID in `prf`, resolves the parent UCAN, verifies its
/// signature, and verifies that the parent's `aud` matches this token's `iss`.
/// Recurses up the chain until reaching a root token (empty `prf`).
///
/// Each parent token is also checked for expiry and revocation (spec section
/// 7.2): an expired or revoked parent invalidates the entire chain.
///
/// Returns the root issuer DID (the `iss` of the root token at the top of the
/// chain). For root tokens (empty `prf`), returns the token's own `iss`.
///
/// # Errors
///
/// Returns [`UcanError::DelegationChainBroken`] if any link is invalid.
/// Returns [`UcanError::CircularDelegation`] if the chain contains a cycle.
/// Returns [`UcanError::SignatureInvalid`] if any parent signature is invalid.
/// Returns [`UcanError::DelegationChainBroken`] (wrapping the original error)
/// if any parent token has expired, is not yet valid, has an invalid time
/// range, has an expiry too far in the future, or has been revoked.  This
/// wrapping allows downstream classifiers to distinguish parent-token failures
/// from leaf-token failures (see issue #1026).
fn verify_delegation_chain(
    token: &UcanToken,
    did_resolver: &impl DidResolver,
    proof_resolver: &impl ProofResolver,
    revocation_checker: &impl RevocationChecker,
    clock_skew_tolerance_secs: u64,
    clock: &dyn Clock,
) -> Result<String, UcanError> {
    if token.payload.prf.is_empty() {
        return Ok(token.payload.iss.clone());
    }

    let mut seen_issuers = HashSet::new();
    seen_issuers.insert(token.payload.iss.clone());
    verify_chain_recursive(
        token,
        did_resolver,
        proof_resolver,
        revocation_checker,
        0,
        &mut seen_issuers,
        clock_skew_tolerance_secs,
        clock,
    )
}

/// Recursive helper for delegation chain verification.
///
/// Walks the proof chain from child to root, verifying signatures, expiry,
/// revocation, and `aud`/`iss` linkage at each step. Returns the root issuer
/// DID.
///
/// Per spec section 7.2, every token in the delegation chain must be valid:
/// not expired, not revoked, and properly signed. An expired or revoked
/// parent invalidates the entire delegation.
///
/// `seen_issuers` tracks all issuer DIDs encountered during the chain walk
/// to detect circular delegations (e.g., A->B->A).
#[allow(clippy::too_many_arguments)]
fn verify_chain_recursive(
    token: &UcanToken,
    did_resolver: &impl DidResolver,
    proof_resolver: &impl ProofResolver,
    revocation_checker: &impl RevocationChecker,
    depth: usize,
    seen_issuers: &mut HashSet<String>,
    clock_skew_tolerance_secs: u64,
    clock: &dyn Clock,
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

        // Circular delegation detection: if the parent's issuer has already
        // been seen in the chain, we have a cycle.
        if !seen_issuers.insert(parent.payload.iss.clone()) {
            return Err(UcanError::CircularDelegation(format!(
                "issuer '{}' appears multiple times in the delegation chain",
                parent.payload.iss
            )));
        }

        // Verify parent's aud matches this token's iss.
        if parent.payload.aud != token.payload.iss {
            return Err(UcanError::DelegationChainBroken(format!(
                "parent aud '{}' does not match child iss '{}'",
                parent.payload.aud, token.payload.iss
            )));
        }

        // Steps 5a/5b: Validate key scope on parent token (ADR-039, SCP-AB-013).
        // An attacker could craft a parent with iss==aud and no key_scope that
        // would pass chain checks if only the presented token were validated.
        validate_key_scope(&parent)?;

        // Verify parent's signature.
        verify_signature(&parent, did_resolver)?;

        // Verify parent token has not expired (spec 7.2).
        // Wrap expiry errors as DelegationChainBroken so downstream classifiers
        // (e.g. Python _classify_ucan_error) can distinguish parent-token failures
        // from leaf-token failures.  Without this, TokenExpired from a parent is
        // indistinguishable from TokenExpired on the leaf, causing optimistic
        // reporting of checks that never ran on the leaf (see issue #1026).
        verify_expiry(&parent, clock_skew_tolerance_secs, clock)
            .map_err(|e| UcanError::DelegationChainBroken(format!("parent token failed: {e}")))?;

        // Verify parent token has not been revoked (spec 7.2).
        // Same wrapping rationale as expiry above (issue #1026).
        let parent_revocation_cid = compute_revocation_cid(&parent.encoded);
        if revocation_checker.is_revoked(&parent_revocation_cid) {
            return Err(UcanError::DelegationChainBroken(format!(
                "parent token failed: token revoked: {parent_revocation_cid}"
            )));
        }

        // Recurse to find the root.
        let found_root = verify_chain_recursive(
            &parent,
            did_resolver,
            proof_resolver,
            revocation_checker,
            depth + 1,
            seen_issuers,
            clock_skew_tolerance_secs,
            clock,
        )?;

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

/// Step 11: Verify token expiry with clock skew tolerance.
///
/// Checks that:
/// - `nbf < exp` (if present, the time range is valid)
/// - `exp + tolerance > now` (not expired, accounting for clock drift)
/// - `exp <= now + 24h` (not too far in the future -- tolerance not applied)
/// - `nbf - tolerance <= now` (if present, the token is already valid,
///   accounting for clock drift)
///
/// The `clock_skew_tolerance_secs` parameter accommodates NTP
/// desynchronization between issuer and validator in distributed deployments
/// (spec section 9.14). A tolerance of 0 disables clock drift handling.
///
/// Note: The `ExpiryTooFar` check does NOT include tolerance. Tolerance is
/// only applied to the leniency direction (accepting slightly expired or
/// slightly future tokens), not to extending the maximum allowed lifetime.
///
/// # Errors
///
/// Returns [`UcanError::InvalidTimeRange`] if `nbf >= exp`.
/// Returns [`UcanError::TokenExpired`] if the token has expired beyond tolerance.
/// Returns [`UcanError::ExpiryTooFar`] if `exp` exceeds now + 24 hours.
/// Returns [`UcanError::TokenNotYetValid`] if `nbf > now + tolerance`.
fn verify_expiry(
    token: &UcanToken,
    clock_skew_tolerance_secs: u64,
    clock: &dyn Clock,
) -> Result<(), UcanError> {
    // Check nbf < exp first — a token with nbf >= exp is inherently invalid
    // regardless of the current time or tolerance.
    if let Some(nbf) = token.payload.nbf
        && nbf >= token.payload.exp
    {
        return Err(UcanError::InvalidTimeRange {
            nbf,
            exp: token.payload.exp,
        });
    }

    let now = clock.now_secs();

    // exp check with tolerance: allow tokens that expired within the
    // tolerance window. `exp + tolerance > now` is equivalent to
    // `exp > now - tolerance` but avoids underflow when now < tolerance.
    if token.payload.exp + clock_skew_tolerance_secs <= now {
        return Err(UcanError::TokenExpired);
    }

    // ExpiryTooFar check — no tolerance applied. This bounds the maximum
    // token lifetime; clock drift doesn't justify longer-lived tokens.
    if token.payload.exp > now + MAX_EXPIRY_SECS {
        return Err(UcanError::ExpiryTooFar(token.payload.exp));
    }

    // nbf check with tolerance: allow tokens whose not-before is slightly
    // in the future (within tolerance). Uses saturating subtraction to avoid
    // underflow when nbf < tolerance.
    if let Some(nbf) = token.payload.nbf
        && nbf.saturating_sub(clock_skew_tolerance_secs) > now
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
    use scp_primitives::Clock;

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

    /// Production system clock for tests that validate against real time.
    static SYSTEM_CLOCK: scp_primitives::SystemClock = scp_primitives::SystemClock;

    /// Build a [`ValidationContext`] with in-memory implementations.
    fn build_context<'a, S: BuildHasher>(
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
            clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
            clock: &SYSTEM_CLOCK,
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
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
            kid_keys: std::collections::HashMap::new(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let proof_resolver = InMemoryProofResolver::new();
        let ceiling = default_ceiling();

        let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
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
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let mut token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Tamper with the signature.
        token.signature[0] ^= 0xFF;
        // Also update the encoded string with the tampered sig.
        let parts: Vec<&str> = token.encoded.split('.').collect();
        let tampered_sig_b64 = URL_SAFE_NO_PAD.encode(&token.signature);
        token.encoded = format!("{}.{}.{}", parts[0], parts[1], tampered_sig_b64);

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
            kid_keys: std::collections::HashMap::new(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let proof_resolver = InMemoryProofResolver::new();
        let ceiling = default_ceiling();

        let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

        let mut ctx = build_context(
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
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
            },
            &custody_creator,
            &scp_primitives::SystemClock,
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
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
            },
            &custody_delegator,
            &scp_primitives::SystemClock,
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
            kid_keys: std::collections::HashMap::new(),
        };

        let proof_resolver = InMemoryProofResolver {
            proofs: std::collections::HashMap::from([(root_cid, root_token)]),
        };

        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-chain", "messages", "write");

        let mut ctx = build_context(
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
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
            },
            &custody_creator,
            &scp_primitives::SystemClock,
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
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
            },
            &custody_b,
            &scp_primitives::SystemClock,
        )
        .await
        .unwrap();

        let resolver = InMemoryDidResolver {
            keys: [(creator_did.clone(), pk_creator), (did_b.clone(), pk_b)]
                .into_iter()
                .collect(),
            kid_keys: std::collections::HashMap::new(),
        };

        let proof_resolver = InMemoryProofResolver {
            proofs: std::collections::HashMap::from([(root_cid, root_token)]),
        };

        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-chain", "messages", "write");

        let mut ctx = build_context(
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
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
            },
            &custody,
            &scp_primitives::SystemClock,
        )
        .await
        .unwrap();

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
            kid_keys: std::collections::HashMap::new(),
        };

        let proof_resolver = InMemoryProofResolver::new();

        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

        let mut ctx = build_context(
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
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
            kid_keys: std::collections::HashMap::new(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let proof_resolver = InMemoryProofResolver::new();
        let ceiling = default_ceiling();

        let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

        // Use a different context creator DID.
        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
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
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
            },
            &custody_non_creator,
            &scp_primitives::SystemClock,
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
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
            },
            &custody_delegator,
            &scp_primitives::SystemClock,
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
            kid_keys: std::collections::HashMap::new(),
        };

        let proof_resolver = InMemoryProofResolver {
            proofs: std::collections::HashMap::from([(root_cid, root_token)]),
        };

        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-chain", "messages", "write");

        // The context creator is "did:dht:z6MkRealCreator" -- not non_creator.
        let mut ctx = build_context(
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
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
            kid_keys: std::collections::HashMap::new(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let proof_resolver = InMemoryProofResolver::new();
        let ceiling = default_ceiling();

        let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

        // Use a different presenting agent DID.
        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
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
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
            kid_keys: std::collections::HashMap::new(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let proof_resolver = InMemoryProofResolver::new();
        let ceiling = default_ceiling();

        // Request a capability the token does NOT grant.
        let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

        let mut ctx = build_context(
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
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Verify the attenuation uses wildcard context.
        assert_eq!(token.payload.att[0].with, "scp:ctx:*/messages:write");

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
            kid_keys: std::collections::HashMap::new(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let proof_resolver = InMemoryProofResolver::new();
        let ceiling = default_ceiling();

        // Request specific context capability -- wildcard should match.
        let required_cap = CapabilityUri::new("ctx-specific", "messages", "write");

        let mut ctx = build_context(
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
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
            },
            &custody_creator,
            &scp_primitives::SystemClock,
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
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
            },
            &custody_delegator,
            &scp_primitives::SystemClock,
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
            kid_keys: std::collections::HashMap::new(),
        };

        let proof_resolver = InMemoryProofResolver {
            proofs: std::collections::HashMap::from([(root_cid, root_token)]),
        };

        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-att", "messages", "write");

        let mut ctx = build_context(
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
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
            kid_keys: std::collections::HashMap::new(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let proof_resolver = InMemoryProofResolver::new();

        // Ceiling does NOT include context:close.
        let ceiling: HashSet<String> = ["messages:read".to_owned(), "messages:write".to_owned()]
            .into_iter()
            .collect();

        let required_cap = CapabilityUri::new("ctx-test", "context", "close");

        let mut ctx = build_context(
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
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
            kid_keys: std::collections::HashMap::new(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let proof_resolver = InMemoryProofResolver::new();
        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-nonce", "messages", "write");

        // First validation should succeed.
        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
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
            &proof_resolver,
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
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
            kid_keys: std::collections::HashMap::new(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();

        // Add the token's revocation CID (SHA-256 of raw encoded JWT) to the
        // revocation list.
        let mut revocation_checker = InMemoryRevocationChecker::new();
        revocation_checker
            .revoked
            .insert(compute_revocation_cid(&token.encoded));

        let proof_resolver = InMemoryProofResolver::new();
        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

        let mut ctx = build_context(
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
            matches!(result, Err(UcanError::TokenRevoked(_))),
            "revoked token must be rejected: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_ucan_revocation_uses_content_hash_cid() {
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
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();
        let revocation_cid = compute_revocation_cid(&token.encoded);

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
            kid_keys: std::collections::HashMap::new(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();

        // Revoke using content-hash CID (SHA-256 of raw encoded JWT).
        let mut revocation_checker = InMemoryRevocationChecker::new();
        revocation_checker.revoked.insert(revocation_cid.clone());

        let proof_resolver = InMemoryProofResolver::new();
        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-cid", "messages", "write");

        let mut ctx = build_context(
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
            matches!(result, Err(UcanError::TokenRevoked(ref cid)) if cid == &revocation_cid),
            "token revoked by content-hash CID must be rejected: {result:?}"
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
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Wait for the token to expire.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
            kid_keys: std::collections::HashMap::new(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let proof_resolver = InMemoryProofResolver::new();
        let ceiling = default_ceiling();

        let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
            &ceiling,
            &issuer_did,
            "did:dht:z6MkMember",
        );
        // Use zero tolerance so the 2-second expiry is detected.
        ctx.clock_skew_tolerance_secs = 0;

        let result = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(
            matches!(result, Err(UcanError::TokenExpired)),
            "expired token must be rejected: {result:?}"
        );
    }

    #[test]
    fn verify_expiry_rejects_token_with_exp_beyond_24h() {
        let now = scp_primitives::SystemClock.now_secs();
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".into(),
                aud: "did:dht:z6MkMember".into(),
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

        let result = verify_expiry(&token, 0, &SYSTEM_CLOCK);
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
                iss: "did:dht:z6MkCreator".into(),
                aud: "did:dht:z6MkMember".into(),
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

        let result = verify_expiry(&token, 0, &SYSTEM_CLOCK);
        assert!(matches!(result, Err(UcanError::TokenExpired)));
    }

    #[test]
    fn verify_expiry_rejects_not_yet_valid() {
        let now = scp_primitives::SystemClock.now_secs();
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".to_owned(),
                aud: "did:dht:z6MkMember".to_owned(),
                exp: now + 7200,
                nbf: Some(now + 3600), // nbf < exp, but nbf > now (not yet valid).
                nnc: "1234567890000-aabbccdd11223344aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };

        let result = verify_expiry(&token, 0, &SYSTEM_CLOCK);
        assert!(matches!(result, Err(UcanError::TokenNotYetValid)));
    }

    #[test]
    fn verify_expiry_accepts_valid_token() {
        let now = scp_primitives::SystemClock.now_secs();
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".into(),
                aud: "did:dht:z6MkMember".into(),
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

        assert!(verify_expiry(&token, 0, &SYSTEM_CLOCK).is_ok());
    }

    #[test]
    fn verify_expiry_rejects_nbf_greater_than_exp() {
        let now = scp_primitives::SystemClock.now_secs();
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".to_owned(),
                aud: "did:dht:z6MkMember".to_owned(),
                exp: now + 3600,
                nbf: Some(now + 7200), // nbf > exp
                nnc: "1234567890000-aabbccdd11223344aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };

        let result = verify_expiry(&token, 0, &SYSTEM_CLOCK);
        assert!(
            matches!(result, Err(UcanError::InvalidTimeRange { nbf, exp }) if nbf == now + 7200 && exp == now + 3600),
            "nbf > exp must return InvalidTimeRange: {result:?}"
        );
    }

    #[test]
    fn verify_expiry_rejects_nbf_equal_to_exp() {
        let now = scp_primitives::SystemClock.now_secs();
        let exp_time = now + 3600;
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".to_owned(),
                aud: "did:dht:z6MkMember".to_owned(),
                exp: exp_time,
                nbf: Some(exp_time), // nbf == exp
                nnc: "1234567890000-aabbccdd11223344aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };

        let result = verify_expiry(&token, 0, &SYSTEM_CLOCK);
        assert!(
            matches!(result, Err(UcanError::InvalidTimeRange { .. })),
            "nbf == exp must return InvalidTimeRange: {result:?}"
        );
    }

    #[test]
    fn verify_expiry_accepts_nbf_less_than_exp() {
        let now = scp_primitives::SystemClock.now_secs();
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".to_owned(),
                aud: "did:dht:z6MkMember".to_owned(),
                exp: now + 3600,
                nbf: Some(now - 60), // nbf < exp and nbf <= now
                nnc: "1234567890000-aabbccdd11223344aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };

        assert!(
            verify_expiry(&token, 0, &SYSTEM_CLOCK).is_ok(),
            "nbf < exp must pass time range validation"
        );
    }

    // -----------------------------------------------------------------------
    // Nonce tracker tests
    // -----------------------------------------------------------------------

    #[test]
    fn nonce_tracker_rejects_reused_nonce() {
        let mut tracker = InMemoryNonceTracker::new();
        let now_millis = scp_primitives::SystemClock.now_millis();

        let nonce = format!("{now_millis}-aabbccdd11223344aabbccdd11223344");
        let expiry = scp_primitives::SystemClock.now_secs() + 3600;

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
        let expiry = scp_primitives::SystemClock.now_secs() + 3600;

        // No separator.
        let result = tracker.check_and_record("nohyphen", expiry);
        assert!(matches!(result, Err(UcanError::NonceFormatInvalid(_))));

        // Non-numeric timestamp.
        let result =
            tracker.check_and_record("notanumber-aabbccdd11223344aabbccdd11223344", expiry);
        assert!(matches!(result, Err(UcanError::NonceFormatInvalid(_))));

        // Hex suffix too short.
        let now_millis = scp_primitives::SystemClock.now_millis();
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
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let minted = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Parse the encoded token back.
        let parsed = parse_ucan(&minted.encoded).unwrap();
        assert_eq!(parsed.header, minted.header);
        assert_eq!(parsed.payload, minted.payload);
        assert_eq!(parsed.signature, minted.signature);

        // Validate the parsed token.
        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
            kid_keys: std::collections::HashMap::new(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let proof_resolver = InMemoryProofResolver::new();
        let ceiling = default_ceiling();

        let required_cap = CapabilityUri::new("ctx-roundtrip", "messages", "write");

        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
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
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
            kid_keys: std::collections::HashMap::new(),
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
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
            },
            &custody_creator,
            &scp_primitives::SystemClock,
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
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
            },
            &custody_delegator,
            &scp_primitives::SystemClock,
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
            kid_keys: std::collections::HashMap::new(),
        };

        let proof_resolver = InMemoryProofResolver {
            proofs: std::collections::HashMap::from([(root_cid, root_token)]),
        };

        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-full", "messages", "write");

        let mut ctx = build_context(
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
                iss: "did:dht:z6MkCreator".into(),
                aud: "did:dht:z6MkMember".into(),
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

    // -----------------------------------------------------------------------
    // Clock error / epoch-0 bypass prevention (SCP-173)
    // -----------------------------------------------------------------------

    /// Verify that `scp_primitives::time::now_secs()` returns `Ok` on a normal system
    /// (Result signature works correctly after the `unwrap_or_default()` removal).
    #[test]
    fn now_secs_returns_ok_on_normal_system() {
        let result = scp_primitives::time::now_secs();
        assert!(
            result.is_ok(),
            "now_secs() should succeed on a normal system"
        );
        assert!(
            result.unwrap() > 0,
            "current time should be after Unix epoch"
        );
    }

    /// A UCAN with exp=0 and nbf=0 must be rejected. Before the clock-error
    /// fix, `unwrap_or_default()` would produce `Duration::ZERO` if the system
    /// clock returned an error, making `now == 0`. That would cause `exp <= now`
    /// to be `0 <= 0` (expired) but more critically, `nbf <= now` would be
    /// `0 <= 0` (valid). With exp=1 and nbf=0, the token would pass all checks.
    ///
    /// This test verifies that epoch-0 tokens are always rejected on a
    /// correctly-running system (where now >> 0), and that `now_secs()` no
    /// longer defaults to zero.
    #[test]
    fn verify_expiry_rejects_epoch_zero_token() {
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".into(),
                aud: "did:dht:z6MkMember".into(),
                exp: 0,
                nbf: Some(0),
                nnc: "0000000000000-aabbccdd11223344aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };

        let result = verify_expiry(&token, 0, &SYSTEM_CLOCK);
        // nbf == exp triggers InvalidTimeRange before TokenExpired.
        assert!(
            matches!(result, Err(UcanError::InvalidTimeRange { nbf: 0, exp: 0 })),
            "epoch-0 token with nbf==exp must be rejected as InvalidTimeRange: {result:?}"
        );
    }

    /// A UCAN with exp=1 and nbf=0 must still be rejected. Before the fix,
    /// if `now_secs()` defaulted to 0 on clock error, `exp (1) > now (0)`
    /// would pass, and `nbf (0) <= now (0)` would also pass — a full bypass.
    /// With the fix, `now_secs()` returns `ClockError` on failure, and on
    /// normal systems now >> 0 so exp=1 is expired.
    #[test]
    fn verify_expiry_rejects_near_epoch_token() {
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".into(),
                aud: "did:dht:z6MkMember".into(),
                exp: 1,
                nbf: Some(0),
                nnc: "0000000000000-aabbccdd11223344aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };

        let result = verify_expiry(&token, 0, &SYSTEM_CLOCK);
        assert!(
            matches!(result, Err(UcanError::TokenExpired)),
            "near-epoch token (exp=1) must be rejected: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Circular delegation detection (SCP-191)
    // -----------------------------------------------------------------------

    /// Helper: mint a UCAN token with default options for chain tests.
    async fn mint_chain_token(
        issuer_did: &str,
        issuer_key: &scp_platform::traits::KeyHandle,
        audience_did: &str,
        context_id: &str,
        caps: &[String],
        proofs: Vec<String>,
        custody: &InMemoryKeyCustody,
    ) -> UcanToken {
        mint_ucan(
            &MintParams {
                issuer_did,
                issuer_key,
                audience_did,
                context_id,
                capabilities: caps,
                lifetime_secs: 3600,
                not_before: None,
                proofs,
                facts: None,
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
            },
            custody,
            &SYSTEM_CLOCK,
        )
        .await
        .unwrap()
    }

    /// A->B->C->A cycle must be rejected with `CircularDelegation`.
    #[tokio::test]
    async fn validate_ucan_rejects_circular_delegation_a_b_c_a() {
        let (custody_a, key_a, did_a, pk_a) = setup_identity().await;
        let (custody_b, key_b, did_b, pk_b) = setup_identity().await;
        let (custody_c, key_c, did_c, pk_c) = setup_identity().await;

        let caps = vec!["messages:write".to_owned()];

        let token_a_to_b = mint_chain_token(
            &did_a,
            &key_a,
            &did_b,
            "ctx-cycle",
            &caps,
            vec![],
            &custody_a,
        )
        .await;
        let cid_a_to_b = compute_cid(&token_a_to_b);

        let token_b_to_c = mint_chain_token(
            &did_b,
            &key_b,
            &did_c,
            "ctx-cycle",
            &caps,
            vec![cid_a_to_b.clone()],
            &custody_b,
        )
        .await;
        let cid_b_to_c = compute_cid(&token_b_to_c);

        let token_c_to_a = mint_chain_token(
            &did_c,
            &key_c,
            &did_a,
            "ctx-cycle",
            &caps,
            vec![cid_b_to_c.clone()],
            &custody_c,
        )
        .await;
        let cid_c_to_a = compute_cid(&token_c_to_a);

        let token_presenting = mint_chain_token(
            &did_a,
            &key_a,
            "did:dht:z6MkPresenter",
            "ctx-cycle",
            &caps,
            vec![cid_c_to_a.clone()],
            &custody_a,
        )
        .await;

        let resolver = InMemoryDidResolver {
            keys: [
                (did_a.clone(), pk_a),
                (did_b.clone(), pk_b),
                (did_c.clone(), pk_c),
            ]
            .into_iter()
            .collect(),
            kid_keys: std::collections::HashMap::new(),
        };

        let proof_resolver = InMemoryProofResolver {
            proofs: std::collections::HashMap::from([
                (cid_a_to_b, token_a_to_b),
                (cid_b_to_c, token_b_to_c),
                (cid_c_to_a, token_c_to_a),
            ]),
        };

        let revocation_checker = InMemoryRevocationChecker::new();
        let result = verify_delegation_chain(
            &token_presenting,
            &resolver,
            &proof_resolver,
            &revocation_checker,
            DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
            &SYSTEM_CLOCK,
        );
        assert!(
            matches!(result, Err(UcanError::CircularDelegation(_))),
            "A->B->C->A cycle must be rejected with CircularDelegation: {result:?}"
        );
    }

    /// A->B->C (no cycle) must pass chain verification.
    #[tokio::test]
    async fn validate_ucan_accepts_linear_chain_a_b_c() {
        use crate::crypto::ucan::Attenuation;
        use crate::crypto::ucan::mint::DelegateParams;

        let (custody_a, key_a, did_a, pk_a) = setup_identity().await;
        let (custody_b, key_b, did_b, pk_b) = setup_identity().await;
        let (_custody_c, _key_c, did_c, _pk_c) = setup_identity().await;

        let caps = vec!["messages:write".to_owned()];

        let root_token = mint_ucan(
            &MintParams {
                issuer_did: &did_a,
                issuer_key: &key_a,
                audience_did: &did_b,
                context_id: "ctx-linear",
                capabilities: &caps,
                lifetime_secs: 3600,
                not_before: None,
                proofs: vec![],
                facts: None,
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
            },
            &custody_a,
            &SYSTEM_CLOCK,
        )
        .await
        .unwrap();
        let root_cid = compute_cid(&root_token);

        let delegated_token = crate::crypto::ucan::mint::delegate_ucan(
            &DelegateParams {
                parent_token: &root_token,
                delegator_did: &did_b,
                delegator_key: &key_b,
                delegatee_did: &did_c,
                attenuated_capabilities: &[Attenuation {
                    with: "scp:ctx:ctx-linear/messages:write".to_owned(),
                    can: "write".to_owned(),
                }],
                lifetime_secs: 1800,
                facts: None,
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
            },
            &custody_b,
            &scp_primitives::SystemClock,
        )
        .await
        .unwrap();

        let resolver = InMemoryDidResolver {
            keys: [(did_a.clone(), pk_a), (did_b.clone(), pk_b)]
                .into_iter()
                .collect(),
            kid_keys: std::collections::HashMap::new(),
        };

        let proof_resolver = InMemoryProofResolver {
            proofs: std::collections::HashMap::from([(root_cid, root_token)]),
        };

        let revocation_checker = InMemoryRevocationChecker::new();
        let result = verify_delegation_chain(
            &delegated_token,
            &resolver,
            &proof_resolver,
            &revocation_checker,
            DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
            &SYSTEM_CLOCK,
        );
        assert!(result.is_ok(), "linear chain A->B->C must pass: {result:?}");
        assert_eq!(result.unwrap(), did_a);
    }

    /// Self-delegation A->A must be rejected with `CircularDelegation`.
    ///
    /// Note: `mint_ucan` now rejects self-delegation without `key_scope` at
    /// mint time (ADR-039), so we construct the invalid token manually to
    /// verify the validation layer also catches it independently.
    #[tokio::test]
    async fn validate_ucan_rejects_self_delegation_a_to_a() {
        let (custody_a, key_a, did_a, pk_a) = setup_identity().await;

        // Manually build a self-delegation root token (iss == aud, no key_scope)
        // bypassing mint_ucan which would now reject this.
        let now = scp_primitives::SystemClock.now_secs();
        let root_header = UcanHeader::new();
        let root_payload = UcanPayload {
            iss: did_a.clone(),
            aud: did_a.clone(),
            exp: now + 3600,
            nbf: None,
            nnc: crate::crypto::ucan::nonce::generate_nonce(&scp_primitives::SystemClock),
            att: vec![crate::crypto::ucan::Attenuation {
                with: "scp:ctx:ctx-self/messages:write".to_owned(),
                can: "write".to_owned(),
            }],
            prf: vec![],
            fct: None,
        };
        let header_json = serde_json::to_vec(&root_header).unwrap();
        let payload_json = serde_json::to_vec(&root_payload).unwrap();
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&header_json);
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload_json);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = custody_a
            .sign(&key_a, signing_input.as_bytes())
            .await
            .unwrap();
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.as_bytes());
        let root_encoded = format!("{signing_input}.{sig_b64}");
        let root_token = UcanToken {
            header: root_header,
            payload: root_payload,
            signature: sig.into_bytes(),
            encoded: root_encoded,
        };
        let root_cid = compute_cid(&root_token);

        // Build a child token from did_a -> someone, referencing the self-delegation root.
        let child_header = UcanHeader::new();
        let child_payload = UcanPayload {
            iss: did_a.clone(),
            aud: "did:dht:z6MkSomeone".to_owned(),
            exp: now + 3600,
            nbf: None,
            nnc: crate::crypto::ucan::nonce::generate_nonce(&scp_primitives::SystemClock),
            att: vec![crate::crypto::ucan::Attenuation {
                with: "scp:ctx:ctx-self/messages:write".to_owned(),
                can: "write".to_owned(),
            }],
            prf: vec![root_cid.clone()],
            fct: None,
        };
        let child_header_json = serde_json::to_vec(&child_header).unwrap();
        let child_payload_json = serde_json::to_vec(&child_payload).unwrap();
        let child_header_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&child_header_json);
        let child_payload_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&child_payload_json);
        let child_signing_input = format!("{child_header_b64}.{child_payload_b64}");
        let child_sig = custody_a
            .sign(&key_a, child_signing_input.as_bytes())
            .await
            .unwrap();
        let child_sig_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(child_sig.as_bytes());
        let child_encoded = format!("{child_signing_input}.{child_sig_b64}");
        let child_token = UcanToken {
            header: child_header,
            payload: child_payload,
            signature: child_sig.into_bytes(),
            encoded: child_encoded,
        };

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((did_a.clone(), pk_a)).collect(),
            kid_keys: std::collections::HashMap::new(),
        };

        let proof_resolver = InMemoryProofResolver {
            proofs: std::collections::HashMap::from([(root_cid, root_token)]),
        };

        let revocation_checker = InMemoryRevocationChecker::new();
        let result = verify_delegation_chain(
            &child_token,
            &resolver,
            &proof_resolver,
            &revocation_checker,
            DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
            &SYSTEM_CLOCK,
        );
        assert!(
            matches!(result, Err(UcanError::CircularDelegation(_))),
            "self-delegation A->A must be rejected with CircularDelegation: {result:?}"
        );
    }

    /// `MAX_CHAIN_DEPTH` guard still terminates excessively long chains.
    #[test]
    fn verify_chain_recursive_rejects_excessive_depth() {
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkA".into(),
                aud: "did:dht:z6MkB".into(),
                exp: scp_primitives::SystemClock.now_secs() + 3600,
                nbf: None,
                nnc: "1234567890000-aabbccdd11223344aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec!["bafyrei-some-proof".to_owned()],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };

        let resolver = InMemoryDidResolver {
            keys: std::collections::HashMap::new(),
            kid_keys: std::collections::HashMap::new(),
        };
        let proof_resolver = InMemoryProofResolver::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let mut seen = HashSet::new();

        let result = verify_chain_recursive(
            &token,
            &resolver,
            &proof_resolver,
            &revocation_checker,
            MAX_CHAIN_DEPTH + 1,
            &mut seen,
            DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
            &SYSTEM_CLOCK,
        );

        assert!(
            matches!(result, Err(UcanError::DelegationChainBroken(ref msg)) if msg.contains("maximum depth")),
            "chain exceeding MAX_CHAIN_DEPTH must be rejected: {result:?}"
        );
    }

    /// `CircularDelegation` error displays correctly.
    #[test]
    fn circular_delegation_error_display() {
        let err = UcanError::CircularDelegation(
            "issuer 'did:dht:z6MkA' appears multiple times".to_owned(),
        );
        assert_eq!(
            err.to_string(),
            "circular delegation detected: issuer 'did:dht:z6MkA' appears multiple times"
        );
    }

    // -----------------------------------------------------------------------
    // Clock drift tolerance tests (issue #107)
    // -----------------------------------------------------------------------

    /// A token that expired 30 seconds ago should be accepted with the default
    /// 5-minute tolerance (300 seconds).
    #[test]
    fn verify_expiry_tolerates_recently_expired_token() {
        let now = scp_primitives::SystemClock.now_secs();
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".into(),
                aud: "did:dht:z6MkMember".into(),
                exp: now - 30, // Expired 30 seconds ago.
                nbf: None,
                nnc: "1234567890000-aabbccdd11223344aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };

        // With 300s tolerance: exp (now - 30) + 300 = now + 270 > now. Accepted.
        assert!(
            verify_expiry(&token, DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, &SYSTEM_CLOCK).is_ok(),
            "token expired 30s ago must be accepted with 5-min tolerance"
        );

        // With 0 tolerance: exp (now - 30) + 0 <= now. Rejected.
        assert!(
            matches!(
                verify_expiry(&token, 0, &SYSTEM_CLOCK),
                Err(UcanError::TokenExpired)
            ),
            "token expired 30s ago must be rejected with 0 tolerance"
        );
    }

    /// A token that expired 6 minutes ago should be rejected even with the
    /// default 5-minute tolerance.
    #[test]
    fn verify_expiry_rejects_token_expired_beyond_tolerance() {
        let now = scp_primitives::SystemClock.now_secs();
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".into(),
                aud: "did:dht:z6MkMember".into(),
                exp: now - 360, // Expired 6 minutes ago.
                nbf: None,
                nnc: "1234567890000-aabbccdd11223344aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };

        // exp (now - 360) + 300 = now - 60 <= now. Rejected.
        assert!(
            matches!(
                verify_expiry(&token, DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, &SYSTEM_CLOCK),
                Err(UcanError::TokenExpired)
            ),
            "token expired 6 min ago must be rejected even with 5-min tolerance"
        );
    }

    /// A token with nbf 30 seconds in the future should be accepted with the
    /// default 5-minute tolerance.
    #[test]
    fn verify_expiry_tolerates_slightly_future_nbf() {
        let now = scp_primitives::SystemClock.now_secs();
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".into(),
                aud: "did:dht:z6MkMember".into(),
                exp: now + 3600,
                nbf: Some(now + 30), // nbf 30 seconds from now.
                nnc: "1234567890000-aabbccdd11223344aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };

        // With 300s tolerance: nbf (now + 30) - 300 = now - 270 <= now. Accepted.
        assert!(
            verify_expiry(&token, DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, &SYSTEM_CLOCK).is_ok(),
            "nbf 30s in the future must be accepted with 5-min tolerance"
        );

        // With 0 tolerance: nbf (now + 30) - 0 = now + 30 > now. Rejected.
        assert!(
            matches!(
                verify_expiry(&token, 0, &SYSTEM_CLOCK),
                Err(UcanError::TokenNotYetValid)
            ),
            "nbf 30s in the future must be rejected with 0 tolerance"
        );
    }

    /// A token with nbf 6 minutes in the future should be rejected even with
    /// the default 5-minute tolerance.
    #[test]
    fn verify_expiry_rejects_nbf_beyond_tolerance() {
        let now = scp_primitives::SystemClock.now_secs();
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".into(),
                aud: "did:dht:z6MkMember".into(),
                exp: now + 7200,
                nbf: Some(now + 360), // nbf 6 minutes from now.
                nnc: "1234567890000-aabbccdd11223344aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };

        // nbf (now + 360) - 300 = now + 60 > now. Rejected.
        assert!(
            matches!(
                verify_expiry(&token, DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, &SYSTEM_CLOCK),
                Err(UcanError::TokenNotYetValid)
            ),
            "nbf 6 min in the future must be rejected even with 5-min tolerance"
        );
    }

    /// The expiry-too-far check must NOT include tolerance. A token with exp
    /// exactly at the 24h limit is valid; tolerance doesn't extend this bound.
    #[test]
    fn verify_expiry_too_far_ignores_tolerance() {
        let now = scp_primitives::SystemClock.now_secs();
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".into(),
                aud: "did:dht:z6MkMember".into(),
                exp: now + MAX_EXPIRY_SECS + 1, // 1 second beyond 24h limit.
                nbf: None,
                nnc: "1234567890000-aabbccdd11223344aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };

        // Even with large tolerance, ExpiryTooFar is not affected.
        assert!(
            matches!(
                verify_expiry(&token, DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, &SYSTEM_CLOCK),
                Err(UcanError::ExpiryTooFar(_))
            ),
            "exp beyond 24h must be rejected regardless of tolerance"
        );
    }

    /// The `InvalidTimeRange` check (nbf >= exp) must be independent of
    /// tolerance. It is a structural token error, not a clock drift issue.
    #[test]
    fn verify_expiry_invalid_time_range_ignores_tolerance() {
        let now = scp_primitives::SystemClock.now_secs();
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".into(),
                aud: "did:dht:z6MkMember".into(),
                exp: now + 3600,
                nbf: Some(now + 7200), // nbf > exp -- structural error.
                nnc: "1234567890000-aabbccdd11223344aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };

        // Even with large tolerance, InvalidTimeRange fires first.
        assert!(
            matches!(
                verify_expiry(&token, DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, &SYSTEM_CLOCK),
                Err(UcanError::InvalidTimeRange { .. })
            ),
            "nbf > exp must return InvalidTimeRange regardless of tolerance"
        );
    }

    /// Verify that a token exactly at the tolerance boundary for expiry is
    /// rejected. `exp + tolerance == now` means `exp + tolerance <= now`, so
    /// it's expired.
    #[test]
    fn verify_expiry_boundary_expired_at_exact_tolerance() {
        let now = scp_primitives::SystemClock.now_secs();
        let tolerance = 60u64;
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".into(),
                aud: "did:dht:z6MkMember".into(),
                exp: now - tolerance, // exp + tolerance == now.
                nbf: None,
                nnc: "1234567890000-aabbccdd11223344aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };

        // exp + tolerance == now. Uses `<=` so this is rejected.
        assert!(
            matches!(
                verify_expiry(&token, tolerance, &SYSTEM_CLOCK),
                Err(UcanError::TokenExpired)
            ),
            "token at exact tolerance boundary must be rejected"
        );
    }

    /// Verify that the default constant matches the expected 5-minute value.
    #[test]
    fn default_clock_skew_tolerance_is_five_minutes() {
        assert_eq!(DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, 300);
    }

    // -----------------------------------------------------------------------
    // Step 5a: Self-delegation safety check (SCP-AB-013)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn validate_ucan_rejects_self_delegation_without_key_scope() {
        // iss == aud without scp_key_scope must be rejected at validation level.
        // mint_ucan now also rejects this at mint time, so we construct the
        // invalid token manually to verify the validation layer independently.
        let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;

        let now = scp_primitives::SystemClock.now_secs();
        let header = UcanHeader::new();
        let payload = UcanPayload {
            iss: issuer_did.clone(),
            aud: issuer_did.clone(),
            exp: now + 3600,
            nbf: None,
            nnc: crate::crypto::ucan::nonce::generate_nonce(&scp_primitives::SystemClock),
            att: vec![crate::crypto::ucan::Attenuation {
                with: "scp:ctx:ctx-self/messages:write".to_owned(),
                can: "write".to_owned(),
            }],
            prf: vec![],
            fct: None,
        };
        let header_json = serde_json::to_vec(&header).unwrap();
        let payload_json = serde_json::to_vec(&payload).unwrap();
        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = custody
            .sign(&key_handle, signing_input.as_bytes())
            .await
            .unwrap();
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_bytes());
        let encoded = format!("{signing_input}.{sig_b64}");
        let token = UcanToken {
            header,
            payload,
            signature: sig.into_bytes(),
            encoded,
        };

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
            kid_keys: std::collections::HashMap::new(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let proof_resolver = InMemoryProofResolver::new();
        let ceiling = default_ceiling();

        let required_cap = CapabilityUri::new("ctx-self", "messages", "write");

        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
            &ceiling,
            &issuer_did,
            &issuer_did, // presenting agent is the same DID
        );

        let result = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(
            matches!(result, Err(UcanError::SelfDelegationWithoutKeyScope)),
            "iss == aud without key_scope must be rejected: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_ucan_accepts_self_delegation_with_key_scope() {
        // iss == aud WITH scp_key_scope must be accepted.
        let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
        let caps = vec!["messages:write".to_owned()];

        // Mint a self-delegation token with key_scope.
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: &issuer_did, // self-delegation
            context_id: "ctx-self",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#active".to_owned()),
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // The default key IS the #active key, so register it under both
        // the default and the kid_keys paths.
        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
            kid_keys: std::iter::once(((issuer_did.clone(), "#active".to_owned()), pk_bytes))
                .collect(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let proof_resolver = InMemoryProofResolver::new();
        let ceiling = default_ceiling();

        let required_cap = CapabilityUri::new("ctx-self", "messages", "write");

        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
            &ceiling,
            &issuer_did,
            &issuer_did, // presenting agent is the same DID
        );

        let result = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(
            result.is_ok(),
            "iss == aud with key_scope must be accepted: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Step 5b: Key scope verification (SCP-AB-013)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn validate_ucan_accepts_matching_key_scope() {
        // Token with key_scope="#agent", signed by #agent key -> accepted.
        let (custody, _key_active, issuer_did, pk_active) = setup_identity().await;

        // Generate a second key pair for the agent key.
        let agent_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let agent_pubkey = custody.public_key(&agent_key).await.unwrap();
        let pk_agent: [u8; 32] = agent_pubkey.as_bytes().try_into().unwrap();

        let caps = vec!["messages:write".to_owned()];

        // Mint a token with key_scope="#agent", signed by the agent key.
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &agent_key,    // Signed by agent key
            audience_did: &issuer_did, // self-delegation
            context_id: "ctx-scope",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // kid should be "#agent" in the header.
        assert_eq!(token.header.kid, Some("#agent".to_owned()));

        // Register the agent key under the kid_keys resolver.
        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_active)).collect(),
            kid_keys: std::iter::once(((issuer_did.clone(), "#agent".to_owned()), pk_agent))
                .collect(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let proof_resolver = InMemoryProofResolver::new();
        let ceiling = default_ceiling();

        let required_cap = CapabilityUri::new("ctx-scope", "messages", "write");

        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
            &ceiling,
            &issuer_did,
            &issuer_did, // self-delegation
        );

        let result = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(
            result.is_ok(),
            "matching key_scope (#agent signed by #agent) must pass: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_ucan_rejects_mismatched_key_scope() {
        // Token declares key_scope="#agent" but was signed by #active key.
        // The token's kid header will say "#agent" (set by mint), but the
        // signature was actually made by the #active key. When the validator
        // resolves #agent's public key and tries to verify, it will fail
        // because a different key signed it.
        let (custody, key_active, issuer_did, pk_active) = setup_identity().await;

        // Generate a separate agent keypair.
        let agent_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let agent_pubkey = custody.public_key(&agent_key).await.unwrap();
        let pk_agent: [u8; 32] = agent_pubkey.as_bytes().try_into().unwrap();

        let caps = vec!["messages:write".to_owned()];

        // Mint with key_scope="#agent" but sign with the ACTIVE key.
        // This creates a token where kid="#agent" but the signature is from
        // the #active key -- a mismatch that the validator must catch.
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_active, // WRONG key: signing with #active
            audience_did: &issuer_did,
            context_id: "ctx-scope",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#agent".to_owned()), // Says #agent
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Register both keys. The #agent key is different from #active.
        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_active)).collect(),
            kid_keys: std::iter::once((
                (issuer_did.clone(), "#agent".to_owned()),
                pk_agent, // Different from the key that actually signed
            ))
            .collect(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let proof_resolver = InMemoryProofResolver::new();
        let ceiling = default_ceiling();

        let required_cap = CapabilityUri::new("ctx-scope", "messages", "write");

        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
            &ceiling,
            &issuer_did,
            &issuer_did,
        );

        let result = validate_ucan(&token, &required_cap, &mut ctx);
        // The signature verification (step 2) will fail because kid="#agent"
        // causes the validator to resolve the #agent public key, which doesn't
        // match the signature made by the #active key.
        assert!(
            matches!(result, Err(UcanError::SignatureInvalid)),
            "token signed by wrong key must fail signature verification: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_ucan_rejects_scope_kid_mismatch_in_facts() {
        // Token where kid="#active" but fct.scp_key_scope="#agent".
        // This tests step 5b specifically: the scope declared in facts
        // doesn't match the kid in the header.
        let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
        let caps = vec!["messages:write".to_owned()];

        // We need to construct a token where kid="#active" but
        // fct.scp_key_scope="#agent". The mint function always sets
        // scp_key_scope from key_scope, so we must manually construct
        // a tampered token.
        //
        // Strategy: mint with key_scope="#active" (so kid="#active",
        // scp_key_scope="#active"), then re-sign with scp_key_scope
        // changed to "#agent".
        let base_params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: &issuer_did,
            context_id: "ctx-scope",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#active".to_owned()),
            signing_key_id: None,
            ceiling: None,
        };

        let base_token = mint_ucan(&base_params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Tamper: change fct.scp_key_scope to "#agent" while keeping
        // kid="#active".
        let mut tampered_payload = base_token.payload.clone();
        if let Some(ref mut fct) = tampered_payload.fct
            && let Some(obj) = fct.as_object_mut()
        {
            obj.insert(
                "scp_key_scope".to_owned(),
                serde_json::Value::String("#agent".to_owned()),
            );
        }

        // Re-encode and re-sign the tampered payload.
        let header_json = serde_json::to_vec(&base_token.header).unwrap();
        let payload_json = serde_json::to_vec(&tampered_payload).unwrap();
        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
        let signing_input = format!("{header_b64}.{payload_b64}");

        let sig = custody
            .sign(&key_handle, signing_input.as_bytes())
            .await
            .unwrap();

        let sig_bytes = sig.into_bytes();
        let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes);
        let encoded = format!("{signing_input}.{sig_b64}");

        let tampered_token = UcanToken {
            header: base_token.header.clone(), // kid="#active"
            payload: tampered_payload,         // fct.scp_key_scope="#agent"
            signature: sig_bytes,
            encoded,
        };

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
            kid_keys: std::iter::once(((issuer_did.clone(), "#active".to_owned()), pk_bytes))
                .collect(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let proof_resolver = InMemoryProofResolver::new();
        let ceiling = default_ceiling();

        let required_cap = CapabilityUri::new("ctx-scope", "messages", "write");

        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
            &ceiling,
            &issuer_did,
            &issuer_did,
        );

        let result = validate_ucan(&tampered_token, &required_cap, &mut ctx);
        assert!(
            matches!(
                result,
                Err(UcanError::KeyScopeMismatch {
                    ref expected_scope,
                    ref actual_kid,
                }) if expected_scope == "#agent" && actual_kid == "#active"
            ),
            "kid/scope mismatch must return KeyScopeMismatch: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_ucan_skips_key_scope_check_when_absent() {
        // Token without scp_key_scope in facts: step 5b is skipped.
        // This is the backward-compatibility case.
        let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-compat",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None, // No key scope: legacy token
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
            kid_keys: std::collections::HashMap::new(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let proof_resolver = InMemoryProofResolver::new();
        let ceiling = default_ceiling();

        let required_cap = CapabilityUri::new("ctx-compat", "messages", "write");

        let mut ctx = build_context(
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
            result.is_ok(),
            "token without key_scope must pass (backward compat): {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_ucan_scoped_ucan_cannot_be_exercised_by_wrong_key() {
        // End-to-end: mint a UCAN scoped to #agent, but present it with a
        // resolver that maps #agent to a different key than what signed it.
        // This verifies that a scoped UCAN cannot be exercised by the wrong key.
        let (custody, key_handle, issuer_did, pk_active) = setup_identity().await;

        // Generate a different key that represents the "real" agent key.
        let real_agent_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let real_agent_pubkey = custody.public_key(&real_agent_key).await.unwrap();
        let pk_real_agent: [u8; 32] = real_agent_pubkey.as_bytes().try_into().unwrap();

        let caps = vec!["messages:write".to_owned()];

        // Mint with key_scope="#agent" signed by the active key (not the real agent key).
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle, // #active key signing
            audience_did: &issuer_did,
            context_id: "ctx-wrong",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // The resolver maps #agent to the REAL agent key (different from #active).
        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_active)).collect(),
            kid_keys: std::iter::once((
                (issuer_did.clone(), "#agent".to_owned()),
                pk_real_agent, // Different from the key that actually signed
            ))
            .collect(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let proof_resolver = InMemoryProofResolver::new();
        let ceiling = default_ceiling();

        let required_cap = CapabilityUri::new("ctx-wrong", "messages", "write");

        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
            &ceiling,
            &issuer_did,
            &issuer_did,
        );

        let result = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(
            matches!(result, Err(UcanError::SignatureInvalid)),
            "scoped UCAN exercised by wrong key must fail: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // extract_key_scope unit tests
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
    // Steps 5a/5b applied to parent tokens in delegation chain (SCP-AB-013)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn chain_rejects_parent_self_delegation_without_key_scope() {
        // A parent token with iss==aud and no key_scope should be rejected.
        //
        // Note: In the current chain walk, the circular delegation detector
        // fires first because parent.iss == parent.aud == child.iss (required
        // for aud/iss linkage). The validate_key_scope check provides
        // defense-in-depth — if the circular delegation check were ever
        // relaxed or reordered, this would become the primary guard.
        //
        // We verify that the chain is rejected (either SelfDelegationWithoutKeyScope
        // or CircularDelegation) — both are correct rejections.

        let (custody_creator, key_creator, creator_did, pk_creator) = setup_identity().await;
        let (_custody_agent, _key_agent, agent_did, _pk_agent) = setup_identity().await;

        let now = scp_primitives::SystemClock.now_secs();
        let caps = vec!["messages:write".to_owned()];

        // Manually construct a parent token where iss==aud and no key_scope.
        let parent_header = UcanHeader::new();
        let parent_payload = UcanPayload {
            iss: creator_did.clone(),
            aud: creator_did.clone(), // iss == aud, no key_scope
            exp: now + 3600,
            nbf: None,
            nnc: crate::crypto::ucan::nonce::generate_nonce(&scp_primitives::SystemClock),
            att: vec![crate::crypto::ucan::Attenuation {
                with: "scp:ctx:ctx-chain/messages:write".to_owned(),
                can: "write".to_owned(),
            }],
            prf: vec![],
            fct: None, // No key_scope — invalid self-delegation
        };
        let parent_header_json = serde_json::to_vec(&parent_header).unwrap();
        let parent_payload_json = serde_json::to_vec(&parent_payload).unwrap();
        let parent_header_b64 = URL_SAFE_NO_PAD.encode(&parent_header_json);
        let parent_payload_b64 = URL_SAFE_NO_PAD.encode(&parent_payload_json);
        let parent_signing_input = format!("{parent_header_b64}.{parent_payload_b64}");
        let parent_sig = custody_creator
            .sign(&key_creator, parent_signing_input.as_bytes())
            .await
            .unwrap();
        let parent_sig_b64 = URL_SAFE_NO_PAD.encode(parent_sig.as_bytes());
        let parent_encoded = format!("{parent_signing_input}.{parent_sig_b64}");
        let parent_token = UcanToken {
            header: parent_header,
            payload: parent_payload,
            signature: parent_sig.into_bytes(),
            encoded: parent_encoded,
        };

        let parent_cid = crate::crypto::ucan::mint::compute_cid(&parent_token);

        // Child from creator_did -> agent_did, referencing the malformed parent.
        let child_params = MintParams {
            issuer_did: &creator_did,
            issuer_key: &key_creator,
            audience_did: &agent_did,
            context_id: "ctx-chain",
            capabilities: &caps,
            lifetime_secs: 1800,
            not_before: None,
            proofs: vec![parent_cid.clone()],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };
        let child_token = mint_ucan(
            &child_params,
            &custody_creator,
            &scp_primitives::SystemClock,
        )
        .await
        .unwrap();

        let resolver = InMemoryDidResolver {
            keys: std::iter::once((creator_did.clone(), pk_creator)).collect(),
            kid_keys: std::collections::HashMap::new(),
        };
        let proof_resolver = InMemoryProofResolver {
            proofs: std::iter::once((parent_cid, parent_token)).collect(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-chain", "messages", "write");

        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
            &ceiling,
            &creator_did,
            &agent_did,
        );

        let result = validate_ucan(&child_token, &required_cap, &mut ctx);
        // Either CircularDelegation (fires first due to iss tracking) or
        // SelfDelegationWithoutKeyScope (defense-in-depth). Both are correct
        // rejections of this invalid chain.
        assert!(
            matches!(
                result,
                Err(UcanError::CircularDelegation(_) | UcanError::SelfDelegationWithoutKeyScope,)
            ),
            "parent with iss==aud and no key_scope must be rejected: {result:?}"
        );
    }

    /// Also verify `validate_key_scope` directly catches the self-delegation case,
    /// independent of chain machinery.
    #[test]
    fn validate_key_scope_rejects_self_delegation_without_scope() {
        let token = UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:zSameDid".to_owned(),
                aud: "did:dht:zSameDid".to_owned(),
                exp: 0,
                nbf: None,
                nnc: String::new(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![],
            encoded: String::new(),
        };
        assert!(matches!(
            validate_key_scope(&token),
            Err(UcanError::SelfDelegationWithoutKeyScope)
        ));
    }

    #[test]
    fn validate_key_scope_rejects_kid_scope_mismatch() {
        let token = UcanToken {
            header: UcanHeader::new(), // kid = None → defaults to "#active"
            payload: UcanPayload {
                iss: "did:dht:zIssuer".to_owned(),
                aud: "did:dht:zAudience".to_owned(),
                exp: 0,
                nbf: None,
                nnc: String::new(),
                att: vec![],
                prf: vec![],
                fct: Some(serde_json::json!({"scp_key_scope": "#agent"})),
            },
            signature: vec![],
            encoded: String::new(),
        };
        assert!(matches!(
            validate_key_scope(&token),
            Err(UcanError::KeyScopeMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn chain_rejects_parent_key_scope_kid_mismatch() {
        // A parent token (iss != aud) with fct.scp_key_scope="#agent" but
        // kid="#active" must cause the chain to be rejected with
        // KeyScopeMismatch. This is the primary exploit path that was not
        // caught before adding validate_key_scope to verify_chain_recursive.

        // Three identities: creator (root), delegator (middle), agent (leaf).
        let (custody_creator, key_creator, creator_did, pk_creator) = setup_identity().await;
        let (custody_delegator, key_delegator, delegator_did, pk_delegator) =
            setup_identity().await;
        let (_custody_agent, _key_agent, agent_did, _pk_agent) = setup_identity().await;

        let now = scp_primitives::SystemClock.now_secs();
        let caps = vec!["messages:write".to_owned()];

        // Parent: creator -> delegator, with a key_scope/kid mismatch.
        // kid is absent (defaults to #active), but scp_key_scope says #agent.
        let parent_header = UcanHeader::new(); // kid = None → "#active"
        let parent_payload = UcanPayload {
            iss: creator_did.clone(),
            aud: delegator_did.clone(), // iss != aud, normal delegation
            exp: now + 3600,
            nbf: None,
            nnc: crate::crypto::ucan::nonce::generate_nonce(&scp_primitives::SystemClock),
            att: vec![crate::crypto::ucan::Attenuation {
                with: "scp:ctx:ctx-chain/messages:write".to_owned(),
                can: "write".to_owned(),
            }],
            prf: vec![],
            fct: Some(serde_json::json!({"scp_key_scope": "#agent"})), // Mismatch!
        };
        let parent_header_json = serde_json::to_vec(&parent_header).unwrap();
        let parent_payload_json = serde_json::to_vec(&parent_payload).unwrap();
        let parent_header_b64 = URL_SAFE_NO_PAD.encode(&parent_header_json);
        let parent_payload_b64 = URL_SAFE_NO_PAD.encode(&parent_payload_json);
        let parent_signing_input = format!("{parent_header_b64}.{parent_payload_b64}");
        let parent_sig = custody_creator
            .sign(&key_creator, parent_signing_input.as_bytes())
            .await
            .unwrap();
        let parent_sig_b64 = URL_SAFE_NO_PAD.encode(parent_sig.as_bytes());
        let parent_encoded = format!("{parent_signing_input}.{parent_sig_b64}");
        let parent_token = UcanToken {
            header: parent_header,
            payload: parent_payload,
            signature: parent_sig.into_bytes(),
            encoded: parent_encoded,
        };

        let parent_cid = crate::crypto::ucan::mint::compute_cid(&parent_token);

        // Child: delegator -> agent, referencing the malformed parent.
        let child_params = MintParams {
            issuer_did: &delegator_did,
            issuer_key: &key_delegator,
            audience_did: &agent_did,
            context_id: "ctx-chain",
            capabilities: &caps,
            lifetime_secs: 1800,
            not_before: None,
            proofs: vec![parent_cid.clone()],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };
        let child_token = mint_ucan(
            &child_params,
            &custody_delegator,
            &scp_primitives::SystemClock,
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
            kid_keys: std::collections::HashMap::new(),
        };
        let proof_resolver = InMemoryProofResolver {
            proofs: std::iter::once((parent_cid, parent_token)).collect(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-chain", "messages", "write");

        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
            &ceiling,
            &creator_did,
            &agent_did,
        );

        let result = validate_ucan(&child_token, &required_cap, &mut ctx);
        assert!(
            matches!(
                result,
                Err(UcanError::KeyScopeMismatch {
                    expected_scope: _,
                    actual_kid: _
                })
            ),
            "parent with key_scope/kid mismatch must be rejected: {result:?}"
        );
    }

    #[tokio::test]
    async fn chain_accepts_parent_with_valid_key_scope() {
        // A parent token with a valid key_scope (matching kid) must be accepted
        // in the delegation chain.

        // Three identities: creator (root), delegator (middle), agent (leaf).
        let (custody_creator, key_creator, creator_did, pk_creator) = setup_identity().await;
        let (custody_delegator, key_delegator, delegator_did, pk_delegator) =
            setup_identity().await;
        let (_custody_agent, _key_agent, agent_did, _pk_agent) = setup_identity().await;

        let now = scp_primitives::SystemClock.now_secs();

        // Parent: creator -> delegator, with valid key_scope="#active" and
        // kid="#active" (matching).
        let mut parent_header = UcanHeader::new();
        parent_header.kid = Some("#active".to_owned());
        let parent_payload = UcanPayload {
            iss: creator_did.clone(),
            aud: delegator_did.clone(),
            exp: now + 3600,
            nbf: None,
            nnc: crate::crypto::ucan::nonce::generate_nonce(&scp_primitives::SystemClock),
            att: vec![crate::crypto::ucan::Attenuation {
                with: "scp:ctx:ctx-chain/messages:write".to_owned(),
                can: "write".to_owned(),
            }],
            prf: vec![],
            fct: Some(serde_json::json!({"scp_key_scope": "#active"})),
        };
        let parent_header_json = serde_json::to_vec(&parent_header).unwrap();
        let parent_payload_json = serde_json::to_vec(&parent_payload).unwrap();
        let parent_header_b64 = URL_SAFE_NO_PAD.encode(&parent_header_json);
        let parent_payload_b64 = URL_SAFE_NO_PAD.encode(&parent_payload_json);
        let parent_signing_input = format!("{parent_header_b64}.{parent_payload_b64}");
        let parent_sig = custody_creator
            .sign(&key_creator, parent_signing_input.as_bytes())
            .await
            .unwrap();
        let parent_sig_b64 = URL_SAFE_NO_PAD.encode(parent_sig.as_bytes());
        let parent_encoded = format!("{parent_signing_input}.{parent_sig_b64}");
        let parent_token = UcanToken {
            header: parent_header,
            payload: parent_payload,
            signature: parent_sig.into_bytes(),
            encoded: parent_encoded,
        };

        let parent_cid = crate::crypto::ucan::mint::compute_cid(&parent_token);

        // Child: delegator -> agent, referencing the well-formed parent.
        let child_params = MintParams {
            issuer_did: &delegator_did,
            issuer_key: &key_delegator,
            audience_did: &agent_did,
            context_id: "ctx-chain",
            capabilities: &["messages:write".to_owned()],
            lifetime_secs: 1800,
            not_before: None,
            proofs: vec![parent_cid.clone()],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };
        let child_token = mint_ucan(
            &child_params,
            &custody_delegator,
            &scp_primitives::SystemClock,
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
            kid_keys: std::iter::once(((creator_did.clone(), "#active".to_owned()), pk_creator))
                .collect(),
        };
        let proof_resolver = InMemoryProofResolver {
            proofs: std::iter::once((parent_cid, parent_token)).collect(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let ceiling = default_ceiling();
        let required_cap = CapabilityUri::new("ctx-chain", "messages", "write");

        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
            &ceiling,
            &creator_did,
            &agent_did,
        );

        let result = validate_ucan(&child_token, &required_cap, &mut ctx);
        assert!(
            result.is_ok(),
            "chain with validly scoped parent must be accepted: {result:?}"
        );
    }
}
