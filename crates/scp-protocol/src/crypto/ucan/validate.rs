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
//! 8. **Ceiling** — Verify every granted capability is within context ceiling.
//! 9. **Nonce** — Validate format, freshness, uniqueness.
//! 10. **Revocation** — Verify token CID not in revocation list.
//! 11. **Expiry** — Verify `exp > now` and `nbf <= now`.
//!
//! See ADR-009 acceptance criterion 4 and ADR-016 acceptance criterion 2.

use std::collections::HashSet;
use std::hash::BuildHasher;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use scp_clock::Clock;
use scp_did::SigningKeyId;

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
///
/// Independent knob: the sibling skew tolerances in `envelope::validation`,
/// `trust::challenge`, and `trust::participation` share this §9.14 5-minute
/// default but are deliberately kept as distinct constants, not unified — each
/// governs its own subsystem and may diverge if that subsystem's requirements do.
pub const DEFAULT_CLOCK_SKEW_TOLERANCE_SECS: u64 = 5 * 60;

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
///
/// The trait is split into two phases to prevent nonce-burn denial-of-service
/// attacks (H11): `check_replay` is called early — before the budget gate —
/// so that a budget-rejected request cannot consume tracker capacity. `record`
/// is called only after all gates pass, atomically committing the nonce.
pub trait NonceTracker {
    /// Validates nonce format and freshness, and checks for replay.
    ///
    /// This is a **read-only** probe — it does NOT record the nonce. Callers
    /// MUST call [`record`](NonceTracker::record) after all downstream gates
    /// pass to prevent nonce-burn denial-of-service: a request rejected by
    /// the budget gate must not exhaust tracker capacity.
    ///
    /// # Errors
    ///
    /// Returns [`UcanError::NonceFormatInvalid`] if the nonce format is wrong.
    /// Returns [`UcanError::NonceTooOld`] if the timestamp is too far in the past.
    /// Returns [`UcanError::NonceFuture`] if the timestamp is too far in the future.
    /// Returns [`UcanError::NonceReused`] if the nonce has been seen before.
    fn check_replay(&self, nonce: &str, token_expiry: u64) -> Result<(), UcanError>;

    /// Records the nonce after all validation gates pass.
    ///
    /// Implementations SHOULD defensively re-run the replay check inside
    /// `record` to guard against races in concurrent callers, then insert the
    /// nonce into the seen-set.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`check_replay`](NonceTracker::check_replay)
    /// if the defensive re-check fails (e.g., because another caller raced to
    /// record the same nonce between the `check_replay` and `record` calls).
    fn record(&mut self, nonce: &str, token_expiry: u64) -> Result<(), UcanError>;

    /// Convenience method that calls [`check_replay`](NonceTracker::check_replay)
    /// and then [`record`](NonceTracker::record) in one step.
    ///
    /// Use this when the check and record happen at the same decision point
    /// (e.g., in validation paths that don't need to split the two phases).
    ///
    /// # Errors
    ///
    /// Returns the same errors as `check_replay` or `record`.
    fn check_and_record(&mut self, nonce: &str, token_expiry: u64) -> Result<(), UcanError> {
        self.check_replay(nonce, token_expiry)?;
        self.record(nonce, token_expiry)
    }
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
#[cfg(any(test, feature = "testing"))]
pub struct InMemoryNonceTracker {
    /// Map of nonce -> (`first_seen_timestamp_secs`, `token_expiry_secs`).
    seen: std::collections::HashMap<String, (u64, u64)>,
}

#[cfg(any(test, feature = "testing"))]
impl InMemoryNonceTracker {
    /// Creates a new empty nonce tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: std::collections::HashMap::new(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl Default for InMemoryNonceTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "testing"))]
impl NonceTracker for InMemoryNonceTracker {
    fn check_replay(&self, nonce: &str, _token_expiry: u64) -> Result<(), UcanError> {
        /// 5 minutes in milliseconds — mirrors `nonce::NONCE_FRESHNESS_TOLERANCE_MS`.
        const NONCE_FRESHNESS_TOLERANCE_MS: u128 = 5 * 60 * 1000;
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
        let now_millis = u128::from(scp_clock::SystemClock.now_millis());

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

        Ok(())
    }

    fn record(&mut self, nonce: &str, token_expiry: u64) -> Result<(), UcanError> {
        // Defensive re-check before inserting.
        self.check_replay(nonce, token_expiry)?;

        // Record the nonce.
        let now_millis = u128::from(scp_clock::SystemClock.now_millis());
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

/// Parses a token's attestation set (`att`) into capability URIs.
///
/// This is the shared step-6 parse used by both [`validate_ucan`] (the
/// enforcing gate) and [`evaluate_ucan`] (the diagnostic). Keeping it in one
/// place ensures the two pipelines can never drift on how attestations are
/// parsed.
///
/// SECURITY: fail-closed — any single unparseable attestation URI rejects the
/// entire token. There is no `filter_map`/`ok()` that could silently drop a
/// malformed attestation and let it escape a downstream check (e.g. the
/// all-attestation ceiling check, step 8).
///
/// # Errors
///
/// Returns [`UcanError::MalformedToken`] if any attestation URI cannot be
/// parsed into a [`CapabilityUri`].
fn parse_granted_caps(token: &UcanToken) -> Result<Vec<CapabilityUri>, UcanError> {
    token
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
        .collect()
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
    /// [`SystemClock`]: scp_clock::SystemClock
    /// [`TestClock`]: scp_clock::TestClock
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
/// 8. Verify every granted capability (the full `att` set) is within the
///    context ceiling — not only the invoked capability (spec §7.2.1 step 8).
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
    verify_root_issuer(&root_issuer, ctx.context_creator_did)?;

    // Step 5: Audience — verify aud matches presenting agent.
    verify_audience(token, ctx.presenting_agent_did)?;

    // Steps 5a/5b: Key scope validation (ADR-039, SCP-AB-013).
    // Rejects self-delegation without key_scope and key_scope/kid mismatches.
    validate_key_scope(token)?;

    // Step 6: Capability match — verify att includes required capability.
    // SECURITY: fail-closed — any unparseable attestation URI rejects the entire token.
    let granted_caps = parse_granted_caps(token)?;
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

    // Step 8: Ceiling — verify EVERY capability the token grants is within the
    // context's immutable capability ceiling, not only the invoked capability
    // (spec §7.2.1 step 8). A token carrying any out-of-ceiling attestation is
    // rejected even if the invoked capability is itself within the ceiling.
    // `granted_caps` is the full parsed `att` set built in step 6; this makes
    // step 8 consistent with step 6b (which already iterates all attestations).
    verify_ceiling_compliance(&granted_caps, ctx.ceiling)?;

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

// ---------------------------------------------------------------------------
// Structured, side-effect-free evaluation
// ---------------------------------------------------------------------------

/// A structured, per-stage summary of a UCAN token's validity.
///
/// Produced by [`evaluate_ucan`], this is the diagnostic counterpart to the
/// fail-closed [`validate_ucan`] gate. It collapses the 11-step pipeline into
/// six boolean fields suitable for surfacing a trust signal to an SDK consumer
/// without enforcing (or mutating) anything.
///
/// # Dependency ordering
///
/// The pipeline is strictly ordered: each stage only runs if every prior stage
/// passed. A field is `true` only if its stage ran *and* passed; every field
/// for a stage at or after the first failure is `false` (those stages never
/// ran, so nothing is known to be valid). This mirrors the short-circuit
/// behavior of [`validate_ucan`].
///
/// # Side-effect freedom
///
/// Unlike [`validate_ucan`], evaluating a token records NO state — in
/// particular the nonce is probed read-only (via
/// [`NonceTracker::check_replay`]), never recorded. [`evaluate_ucan`] is safe
/// to call repeatedly on the same token without consuming its nonce.
///
/// # Diagnostic accuracy caveats
///
/// Because this mirrors the enforcing pipeline's stage boundaries exactly, two
/// consequences are worth surfacing to any consumer that acts on the fields:
///
/// - `signatures_valid` covers the WHOLE delegation chain, not just the leaf
///   signature. Chain verification (step 3) validates every parent's signature,
///   expiry, and revocation, so an otherwise-valid leaf whose *parent* is
///   expired or revoked reports `signatures_valid: false` — not
///   `time_bounds_valid: false` / `not_revoked: false` (those two fields
///   reflect only the leaf token).
/// - The result is a point-in-time snapshot and is NOT a promise that a
///   subsequent [`validate_ucan`] will accept the token. `nonce_valid: true`
///   and `not_revoked: true` can both flip to a rejection at enforcement time
///   if, between the two calls, the nonce is recorded by another request or the
///   token is revoked. Treat the booleans as a diagnostic signal, never as a
///   pre-flight success guarantee.
//
// Six independent per-stage outcome flags is the mandated public shape of this
// diagnostic result (one boolean per pipeline stage group). These are pure data
// — not behavior-selecting flags — so a state machine / two-variant enums (what
// `struct_excessive_bools` suggests) would obscure, not clarify, the API and
// break the flat named-field shape the SDK trust signal consumes.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityValidation {
    /// Step 1: the token parsed and its header validated, and the attestation
    /// set parsed into capability URIs.
    pub tokens_valid: bool,
    /// Steps 2-7: signature, delegation chain, root issuer, audience, key
    /// scope, capability grant-match, Category-A enforcement, and attenuation
    /// all passed. The capability grant-match (step 6) only runs when
    /// `evaluate_ucan` is called with a challenge capability (`Some`); in
    /// intrinsic-validity mode (`None`) it is skipped, so this field reflects
    /// only the structural checks (steps 2-5b, 6b, 7).
    pub signatures_valid: bool,
    /// Step 8 (all-attestation ceiling): every capability the token grants (the
    /// full `att` set) is within the context's immutable capability ceiling
    /// (spec §7.2.1 step 8). This check is over the token's OWN `att` set and is
    /// independent of any challenge capability. When `evaluate_ucan` was called
    /// with a challenge capability (`Some`), reaching this stage already implies
    /// the step-6 invoked-capability grant-match passed (it runs inside the
    /// `signatures_valid` stage), so a `true` here additionally means the
    /// invoked capability is granted. When called with `None` (intrinsic-validity
    /// mode), grant-match is skipped, so a `true` means only that no attestation
    /// exceeds the ceiling.
    pub within_ceiling: bool,
    /// Step 9: the nonce format, freshness, and uniqueness checks passed
    /// (probed read-only — the nonce is NOT recorded).
    pub nonce_valid: bool,
    /// Step 10: the token's revocation CID is not on the context revocation
    /// list.
    pub not_revoked: bool,
    /// Step 11: `exp`/`nbf` time bounds are valid (within clock-skew
    /// tolerance).
    pub time_bounds_valid: bool,
}

impl CapabilityValidation {
    /// An all-`false` result — used as the starting point and returned when a
    /// stage fails (every later stage is left `false` because it never ran).
    const NONE: Self = Self {
        tokens_valid: false,
        signatures_valid: false,
        within_ceiling: false,
        nonce_valid: false,
        not_revoked: false,
        time_bounds_valid: false,
    };
}

/// Evaluates a UCAN token against the 11-step pipeline and returns a structured
/// [`CapabilityValidation`] summary instead of failing at the first error.
///
/// This is the diagnostic, **side-effect-free** counterpart to
/// [`validate_ucan`]. It is intended for SDK trust signals: a caller can show a
/// per-stage breakdown of why a token is (or is not) acceptable without
/// enforcing the result and — critically — without consuming the token's nonce.
///
/// # Relationship to [`validate_ucan`]
///
/// - It calls the EXACT same sub-checks as [`validate_ucan`] (signature,
///   delegation chain, issuer/audience, key scope, grant-match, Category-A,
///   attenuation, all-attestation ceiling, revocation, expiry). No validation
///   logic is duplicated.
/// - The nonce step uses [`NonceTracker::check_replay`] (read-only). It NEVER
///   calls [`NonceTracker::record`] / [`NonceTracker::check_and_record`], so
///   the tracker is never mutated. Hence `ctx` is taken by shared reference.
/// - Stages run in pipeline order and short-circuit: the returned struct sets
///   a field `true` only for stages that ran and passed; the first failing
///   stage and everything after it are `false`.
///
/// # Capability challenge (`required_capability`)
///
/// This argument is OPTIONAL — it is what distinguishes the two diagnostic
/// modes:
///
/// - `None`: evaluate the token's INTRINSIC validity only. The step-6
///   invoked-capability grant-match (`check_capability_match`) is SKIPPED
///   entirely — no specific capability is being challenged. The
///   `signatures_valid` stage then reflects only the structural checks (steps
///   2-5b, 6b, 7); `within_ceiling` still reflects the all-attestation ceiling
///   check (step 8) over the token's OWN `att` set, which does not depend on any
///   challenge capability. This is the mode the SDK trust signal uses: a
///   participant's tokens are evaluated for general validity with no concrete
///   capability to challenge.
/// - `Some(c)`: additionally require that the token grants `c` (step-6
///   grant-match against `c`). Behavior is IDENTICAL to the historical
///   mandatory-capability contract: a token whose `att` set does not grant `c`
///   fails the `signatures_valid` stage, exactly as before.
///
/// In BOTH modes the result remains fail-closed: `None` never makes a genuinely
/// invalid token report valid (every other check still runs), and `Some(c)`
/// with a non-granted `c` behaves exactly as it always has. The only difference
/// `None` makes is to omit the grant-match concern — it never flips a bool to
/// `true` that would otherwise be `false`.
///
/// Note the enforcing gate [`validate_ucan`] keeps a MANDATORY
/// `required_capability` — only this read-only diagnostic admits `None`.
///
/// # Returns
///
/// Always returns a [`CapabilityValidation`] — it never returns an error, even
/// for a token that fails every check. A token that cannot be parsed into the
/// required inputs yields `tokens_valid: false` with all later fields `false`.
#[must_use]
pub fn evaluate_ucan<D, N, R, P, S>(
    token: &UcanToken,
    required_capability: Option<&CapabilityUri>,
    ctx: &ValidationContext<'_, D, N, R, P, S>,
) -> CapabilityValidation
where
    D: DidResolver,
    N: NonceTracker,
    R: RevocationChecker,
    P: ProofResolver,
    S: BuildHasher,
{
    let mut result = CapabilityValidation::NONE;

    // Step 1: Parse — token is pre-parsed; validate the header and parse the
    // attestation set into capability URIs (fail-closed on any unparseable
    // URI, exactly as validate_ucan's step 6).
    if token.header.validate().is_err() {
        return result;
    }
    let Ok(granted_caps) = parse_granted_caps(token) else {
        return result;
    };
    result.tokens_valid = true;

    // Steps 2-7: signature, delegation chain + root issuer, audience, key
    // scope, grant-match, Category-A, attenuation. Any failure stops here.
    let sigs_ok = (|| -> Result<(), UcanError> {
        // Step 2: signature.
        verify_signature(token, ctx.did_resolver)?;

        // Step 3: delegation chain (returns the root issuer DID).
        let root_issuer = verify_delegation_chain(
            token,
            ctx.did_resolver,
            ctx.proof_resolver,
            ctx.revocation_checker,
            ctx.clock_skew_tolerance_secs,
            ctx.clock,
        )?;

        // Step 4: root issuer is the context creator.
        verify_root_issuer(&root_issuer, ctx.context_creator_did)?;

        // Step 5: audience matches the presenting agent.
        verify_audience(token, ctx.presenting_agent_did)?;

        // Steps 5a/5b: key scope.
        validate_key_scope(token)?;

        // Step 6: capability grant-match (the invoked capability). SKIPPED when
        // no challenge capability is supplied (`None`) — the intrinsic-validity
        // diagnostic mode. Omitting this check never flips any field to `true`
        // that another check would set `false`: every other stage still runs,
        // and `within_ceiling` (step 8) is the independent all-attestation
        // ceiling check over the token's own `att` set.
        if let Some(required) = required_capability {
            check_capability_match(&granted_caps, required)?;
        }

        // Step 6b: Category-A enforcement.
        enforce_ucan_category_a(token, &granted_caps)?;

        // Step 7: attenuation (no-op for root tokens).
        if !token.payload.prf.is_empty() {
            verify_attenuation(token, ctx.proof_resolver)?;
        }

        Ok(())
    })()
    .is_ok();
    if !sigs_ok {
        return result;
    }
    result.signatures_valid = true;

    // Step 8: within_ceiling is the all-attestation ceiling check (spec §7.2.1
    // step 8) over the token's OWN `att` set — independent of any challenge
    // capability. When a challenge capability WAS supplied (`Some`), the step-6
    // invoked-capability grant-match already passed above (inside the
    // signatures stage), so a `true` here additionally implies the invoked
    // capability is granted. When `None`, only the all-att ceiling is asserted.
    if verify_ceiling_compliance(&granted_caps, ctx.ceiling).is_err() {
        return result;
    }
    result.within_ceiling = true;

    // Step 9: nonce — READ-ONLY probe. This must never record the nonce, so
    // evaluate_ucan is safe to call repeatedly on the same token.
    if ctx
        .nonce_tracker
        .check_replay(&token.payload.nnc, token.payload.exp)
        .is_err()
    {
        return result;
    }
    result.nonce_valid = true;

    // Step 10: revocation.
    let revocation_cid = compute_revocation_cid(&token.encoded);
    if ctx.revocation_checker.is_revoked(&revocation_cid) {
        return result;
    }
    result.not_revoked = true;

    // Step 11: expiry / not-before bounds.
    if verify_expiry(token, ctx.clock_skew_tolerance_secs, ctx.clock).is_ok() {
        result.time_bounds_valid = true;
    }

    result
}

// ---------------------------------------------------------------------------
// Individual validation steps
// ---------------------------------------------------------------------------

/// Step 4: Verify the delegation chain's root issuer is the context creator.
///
/// Shared by [`validate_ucan`] and [`evaluate_ucan`] so the root-issuer rule
/// cannot drift between the enforcing gate and the diagnostic.
///
/// # Errors
///
/// Returns [`UcanError::InvalidIssuer`] if `root_issuer` is not the context
/// creator DID.
fn verify_root_issuer(root_issuer: &str, context_creator_did: &str) -> Result<(), UcanError> {
    if root_issuer != context_creator_did {
        return Err(UcanError::InvalidIssuer {
            expected: context_creator_did.to_owned(),
            actual: root_issuer.to_owned(),
        });
    }
    Ok(())
}

/// Step 5: Verify the token's audience matches the presenting agent.
///
/// Shared by [`validate_ucan`] and [`evaluate_ucan`] so the audience rule
/// cannot drift between the enforcing gate and the diagnostic.
///
/// # Errors
///
/// Returns [`UcanError::AudienceMismatch`] if `token.payload.aud` is not the
/// presenting agent DID.
fn verify_audience(token: &UcanToken, presenting_agent_did: &str) -> Result<(), UcanError> {
    if token.payload.aud != presenting_agent_did {
        return Err(UcanError::AudienceMismatch {
            expected: presenting_agent_did.to_owned(),
            actual: token.payload.aud.clone(),
        });
    }
    Ok(())
}

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
pub(super) fn validate_key_scope(token: &UcanToken) -> Result<(), UcanError> {
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

    // Parse kid to SigningKeyId via the canonical fragment decoder. Only
    // #active and #agent are valid UCAN signing keys; `from_fragment` returns
    // `None` for anything else, which we reject fail-closed (identical behavior
    // to the prior hand-rolled match).
    let Some(signing_key_id) = SigningKeyId::from_fragment(kid_str) else {
        return Err(UcanError::MalformedToken(format!(
            "unrecognized signing key ID (kid): {kid_str}"
        )));
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
pub(super) fn verify_signature(
    token: &UcanToken,
    did_resolver: &impl DidResolver,
) -> Result<(), UcanError> {
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

    scp_crypto::verify_ed25519_signature(&pk_bytes, signing_input.as_bytes(), &token.signature)
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
pub(super) fn verify_delegation_chain(
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
pub(super) fn verify_expiry(
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

// ---------------------------------------------------------------------------
// Tests — async tests requiring scp-runtime (mint_ucan, delegate_ucan,
// compute_cid) have been moved to
// crates/scp-runtime/tests/ucan_validate_integration.rs
// ---------------------------------------------------------------------------
