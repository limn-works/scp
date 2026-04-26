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

use scp_primitives::Clock;
use scp_primitives::SigningKeyId;

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

        Ok(())
    }

    fn record(&mut self, nonce: &str, token_expiry: u64) -> Result<(), UcanError> {
        // Defensive re-check before inserting.
        self.check_replay(nonce, token_expiry)?;

        // Record the nonce.
        let now_millis = u128::from(scp_primitives::SystemClock.now_millis());
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
// CaveatResolver — SCP-OUT-021
// ---------------------------------------------------------------------------
//
// Spec §7.3.8 places `InvocationCaveats` in the UCAN `nb` ("not-before" /
// attestation) field. The protocol surface keeps caveats decoupled from
// `UcanPayload` so caveat-bearing tokens can interoperate with the existing
// 11-step pipeline without forcing every legacy caller to declare an empty
// caveats object. Instead, validation looks caveats up via this resolver
// keyed by the encoded JWT — a token-side handle the resolver implementation
// chooses how to interpret (CID lookup, in-memory map, etc.).
//
// `verify_attenuation` calls `parent.caveats.narrow(&child.caveats)?` at
// every delegation edge where BOTH parent and child carry caveats. When
// either side returns `None`, the narrow rule degenerates to the legacy
// behaviour (capability-only attenuation): `None` parent means the parent
// imposed no caveat-level constraint, and `None` child means the child
// inherits the parent's constraint by reference (the existing protocol
// behaviour for tokens that pre-date OUT-018/019). A `None`-parent with a
// `Some`-child IS still subject to `narrow()` because narrow itself
// enforces the §7.3.8 "child may introduce a bound where parent had none"
// rule with `parent.caveats == InvocationCaveats::empty()` semantically.

/// Resolves the [`InvocationCaveats`] (§7.3.8) carried by a UCAN token.
///
/// Each implementation chooses how it associates caveats with tokens — the
/// canonical wire location is the UCAN `nb` field (§7.3.8), but validation
/// only requires a deterministic look-up keyed by `&UcanToken`. The default
/// implementation [`NoCaveatResolver`] returns `None` for every token,
/// preserving backward-compatible behaviour for callers that have not yet
/// minted caveat-bearing delegations.
///
/// Returning `Some(_)` opts the token into Step 7b (attenuation) and Step
/// 11b (time-box) caveat enforcement. Returning `None` skips both steps
/// for that token specifically; tokens in the same chain that DO carry
/// caveats are still checked.
///
/// **`Send + Sync` bound.** The resolver is held inside
/// [`ValidationContext`] as `&dyn CaveatResolver`. Several FFI bridges
/// build a `ValidationContext` inside an `async` task whose future is
/// later awaited from a `Send`-only executor (napi, uniffi). The
/// `Send + Sync` super-bound makes such futures `Send` without
/// per-call-site adapters.
pub trait CaveatResolver: Send + Sync {
    /// Resolves the [`InvocationCaveats`] for the given token, or returns
    /// `None` if the token carries no caveat-level constraints.
    fn resolve_caveats(
        &self,
        token: &UcanToken,
    ) -> Option<crate::trust::caveats::InvocationCaveats>;
}

/// A [`CaveatResolver`] that returns `None` for every token. The default
/// resolver — preserves pre-SCP-OUT-021 behaviour where every token is
/// treated as caveat-free at the protocol layer.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoCaveatResolver;

impl CaveatResolver for NoCaveatResolver {
    fn resolve_caveats(
        &self,
        _token: &UcanToken,
    ) -> Option<crate::trust::caveats::InvocationCaveats> {
        None
    }
}

/// In-memory [`CaveatResolver`] keyed by encoded JWT string.
///
/// Used by tests and by adapters that pre-compute caveats out-of-band
/// (e.g., during a transient envelope rewrite) rather than reading from
/// the `nb` field.
///
/// Map values are owned [`InvocationCaveats`] records — the resolver
/// returns clones so the validation pipeline can take an owned snapshot
/// without holding a borrow on the resolver across recursive chain walks.
pub struct InMemoryCaveatResolver {
    /// Map of `UcanToken::encoded` → [`InvocationCaveats`].
    pub caveats: std::collections::HashMap<String, crate::trust::caveats::InvocationCaveats>,
}

impl InMemoryCaveatResolver {
    /// Creates an empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            caveats: std::collections::HashMap::new(),
        }
    }

    /// Inserts caveats for the given encoded UCAN string.
    pub fn insert(
        &mut self,
        encoded: impl Into<String>,
        caveats: crate::trust::caveats::InvocationCaveats,
    ) {
        self.caveats.insert(encoded.into(), caveats);
    }
}

impl Default for InMemoryCaveatResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl CaveatResolver for InMemoryCaveatResolver {
    fn resolve_caveats(
        &self,
        token: &UcanToken,
    ) -> Option<crate::trust::caveats::InvocationCaveats> {
        self.caveats.get(&token.encoded).cloned()
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
/// capability ceiling, context creator DID, presenting agent DID, and
/// (SCP-OUT-021) caveat resolution for Step 7b / Step 11b.
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
    /// Clock for time-dependent checks (steps 3, 11, and 11b).
    ///
    /// Accepts `&dyn Clock` to support both production ([`SystemClock`]) and
    /// test ([`TestClock`]) clocks.
    ///
    /// [`SystemClock`]: scp_primitives::SystemClock
    /// [`TestClock`]: scp_primitives::TestClock
    pub clock: &'a dyn Clock,
    /// SCP-OUT-021: caveat resolver for Step 7b (attenuation) and Step 11b
    /// (time-box) checks. Tokens for which this resolver returns `None`
    /// skip both caveat steps; tokens that resolve to `Some(caveats)` go
    /// through `caveats.narrow(child)` at every delegation edge and the
    /// time-box check after Step 11.
    ///
    /// Stored as `&dyn CaveatResolver` so the field is type-erased — the
    /// generic parameters of `ValidationContext` track the four other
    /// resolvers, and adding a fifth generic for the caveat resolver would
    /// be a wide breaking change for every test rig that constructs a
    /// `ValidationContext`. Type erasure here is local to the validation
    /// pipeline and incurs no runtime cost on the `None` path because
    /// `NoCaveatResolver`'s `resolve_caveats` is a constant `None` return
    /// the optimizer inlines.
    pub caveat_resolver: &'a dyn CaveatResolver,
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

    // Step 7 + 7b: Attenuation — verify delegations narrow or preserve.
    // For root tokens (empty prf), Step 7 is a no-op; Step 7b (caveat
    // narrow) is also a no-op for roots because there is no parent
    // delegation to compare against.
    //
    // SCP-OUT-021: Step 7b extends the existing capability-subset check
    // with a per-field caveat narrow. The resolver decides which tokens
    // carry caveats; tokens with no caveats fall back to Step 7 alone.
    if !token.payload.prf.is_empty() {
        verify_attenuation(token, ctx.proof_resolver, ctx.caveat_resolver)?;
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

    // Step 11b (SCP-OUT-021): caveat time-box. After exp/nbf, the
    // validator checks the presenting token's `valid_from` /
    // `valid_until` / `hours_of_day` / `days_of_week` per §7.3.8 — these
    // are tighter than the UCAN-level `nbf` / `exp` and bind the
    // delegation to a window narrower than the token's lifetime.
    //
    // Only the presenting (leaf) token's caveats gate Step 11b — parent
    // caveats already had their time-box checked when those tokens were
    // presented at their own delegation site, and Step 7b has already
    // guaranteed child time-box bounds are no looser than parent.
    if let Some(caveats) = ctx.caveat_resolver.resolve_caveats(token) {
        verify_caveat_time_box(&caveats, ctx.clock)?;
    }

    Ok(())
}

/// SCP-OUT-021 Step 11b — verify the four time-box caveats against the
/// current clock value:
///
/// - `valid_from <= now` (caveat's "tighter `nbf`")
/// - `valid_until >= now` (caveat's "tighter `exp`")
/// - `hours_of_day & (1 << current_utc_hour) != 0` — bit `n` set means
///   UTC hour `n` is allowed.
/// - `days_of_week & (1 << current_utc_weekday) != 0` — bit 0 = Sunday,
///   bit 6 = Saturday.
///
/// Absent (`None`) caveats are unconstrained; only present-and-violated
/// caveats fail.
///
/// Clock skew is intentionally NOT applied here. §7.3.8 specifies the
/// time-box caveats as runtime gates — they fire at the *moment* of
/// invocation rather than at token mint or expiry, so a "5 minutes ago"
/// invocation that was outside the allowed hour is still an invocation
/// outside the allowed hour. NTP drift on the validator's side cannot
/// admit invocations that the operator's policy forbids.
///
/// # Errors
///
/// Returns [`UcanError::CaveatTimeBoxViolation`] with a slug-friendly
/// reason on the first failed check.
fn verify_caveat_time_box(
    caveats: &crate::trust::caveats::InvocationCaveats,
    clock: &dyn Clock,
) -> Result<(), UcanError> {
    let now = clock.now_secs();

    if let Some(valid_from) = caveats.valid_from
        && now < valid_from
    {
        return Err(UcanError::CaveatTimeBoxViolation(format!(
            "valid_from: now={now} < valid_from={valid_from}"
        )));
    }
    if let Some(valid_until) = caveats.valid_until
        && now > valid_until
    {
        return Err(UcanError::CaveatTimeBoxViolation(format!(
            "valid_until: now={now} > valid_until={valid_until}"
        )));
    }

    if let Some(hours_mask) = caveats.hours_of_day {
        // UTC hour 0..=23 from `now` (Unix seconds). The arithmetic is
        // exact: `(now / 3600) % 24` is the UTC hour-of-day with no
        // calendar awareness, matching the spec's "current_utc_hour"
        // shorthand.
        #[allow(clippy::cast_possible_truncation)]
        let current_hour = ((now / 3600) % 24) as u8;
        if !hours_mask.contains_hour(current_hour) {
            return Err(UcanError::CaveatTimeBoxViolation(format!(
                "hours_of_day: current_utc_hour={current_hour} not in mask 0x{:08x}",
                hours_mask.bits()
            )));
        }
    }

    if let Some(days_mask) = caveats.days_of_week {
        // 1970-01-01 was a Thursday (weekday=4 with Sun=0). Each Unix
        // day shifts weekday forward by 1.
        #[allow(clippy::cast_possible_truncation)]
        let current_weekday = (((now / 86_400) + 4) % 7) as u8;
        if !days_mask.contains_day(current_weekday) {
            return Err(UcanError::CaveatTimeBoxViolation(format!(
                "days_of_week: current_utc_weekday={current_weekday} not in mask 0x{:02x}",
                days_mask.bits()
            )));
        }
    }

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

/// Step 7 + 7b: Verify attenuation — each delegation narrows or preserves
/// capabilities, and (SCP-OUT-021) per-field invocation caveats narrow
/// per §7.3.8 attenuation rules.
///
/// A child token cannot grant capabilities that its parent does not have.
/// For root tokens (empty `prf`), Step 7 is a no-op and Step 7b is
/// unreachable (the caller skips this function for empty `prf`).
///
/// **Step 7b (caveat narrow).** Whenever the resolver returns
/// `Some(caveats)` for BOTH the parent and the child, the function calls
/// `parent_caveats.narrow(&child_caveats)`. Any
/// [`AttenuationViolation`](crate::trust::caveats::AttenuationViolation)
/// is wrapped into [`UcanError::CaveatAttenuationViolation`] so SDK
/// callers can pattern-match the structured violation. When the resolver
/// returns `None` for either side, only Step 7 runs at that edge — this
/// preserves backward compatibility for tokens that pre-date OUT-018/019
/// (no caveat-bearing `nb` field) and is the documented contract of
/// [`CaveatResolver`].
///
/// # Errors
///
/// Returns [`UcanError::AttenuationViolation`] if a child widens
/// capabilities (Step 7) and
/// [`UcanError::CaveatAttenuationViolation`] if a child violates a
/// caveat narrowing rule at any field (Step 7b).
fn verify_attenuation(
    token: &UcanToken,
    proof_resolver: &impl ProofResolver,
    caveat_resolver: &dyn CaveatResolver,
) -> Result<(), UcanError> {
    // SCP-OUT-021 Step 7b: pre-resolve the child's caveats once outside
    // the parent loop. The narrow rule is applied at every parent edge so
    // we need the same child snapshot for each comparison.
    let child_caveats = caveat_resolver.resolve_caveats(token);

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

        // Step 7: Verify every child capability is granted by a parent capability.
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

        // SCP-OUT-021 Step 7b: caveat narrow at this parent edge. Run
        // only when both parent and child carry caveats — see
        // [`CaveatResolver`] module docs for the `None`-handling
        // contract.
        if let (Some(parent_caveats), Some(child_caveats)) =
            (caveat_resolver.resolve_caveats(&parent), &child_caveats)
        {
            parent_caveats
                .narrow(child_caveats)
                .map_err(UcanError::CaveatAttenuationViolation)?;
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
//
// SCP-OUT-021 unit tests below exercise Steps 7b (caveat narrow) and 11b
// (caveat time-box) using synthetic tokens (no real signatures); they call
// `verify_attenuation` and `verify_caveat_time_box` directly because both
// helpers are crate-visible and the caveat-specific failure modes are
// independent of signature/expiry/revocation logic.
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::match_wildcard_for_single_variants,
    clippy::type_complexity
)]
mod tests {
    use super::*;
    use crate::crypto::ucan::{Attenuation, UcanHeader, UcanPayload, UcanToken};
    use crate::economy::types::Amount;
    use crate::trust::caveats::{AttenuationViolation, InvocationCaveats};

    /// Builds a synthetic token with the given encoded string, attestation
    /// URIs, and proofs. The signature is empty — these tests exercise
    /// Step 7b / 11b which never inspect the signature.
    fn synthetic_token(encoded: &str, atts: &[&str], proofs: &[&str]) -> UcanToken {
        UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:example:issuer".to_owned(),
                aud: "did:example:audience".to_owned(),
                exp: 2_000_000_000,
                nbf: None,
                nnc: "0-00000000000000000000000000000000".to_owned(),
                att: atts
                    .iter()
                    .map(|s| Attenuation {
                        with: (*s).to_owned(),
                        can: "*".to_owned(),
                    })
                    .collect(),
                prf: proofs.iter().map(|s| (*s).to_owned()).collect(),
                fct: None,
            },
            signature: Vec::new(),
            encoded: encoded.to_owned(),
        }
    }

    // -----------------------------------------------------------------------
    // Step 7b: verify_attenuation rejects widened caveats
    // -----------------------------------------------------------------------

    /// AC: delegation with widened `amount_max_per_call` is rejected at
    /// Step 7b — the child raised the parent's `amount_max_per_call`.
    #[test]
    fn step_7b_rejects_widened_amount_max_per_call() {
        let parent = synthetic_token("PARENT", &["scp:ctx:abc/outlet_call:assistant"], &[]);
        let child = synthetic_token("CHILD", &["scp:ctx:abc/outlet_call:assistant"], &["PARENT"]);

        let mut proof_resolver = InMemoryProofResolver::new();
        proof_resolver.proofs.insert("PARENT".to_owned(), parent);

        let mut caveat_resolver = InMemoryCaveatResolver::new();
        // Parent caps amount at 100; child tries to cap at 200 — widening.
        caveat_resolver.insert(
            "PARENT",
            InvocationCaveats {
                amount_max_per_call: Some(Amount::new(100)),
                origin_kind: Some(crate::context::outlets::OutletKind::Action),
                ..InvocationCaveats::empty()
            },
        );
        caveat_resolver.insert(
            "CHILD",
            InvocationCaveats {
                amount_max_per_call: Some(Amount::new(200)),
                origin_kind: Some(crate::context::outlets::OutletKind::Action),
                ..InvocationCaveats::empty()
            },
        );

        let err = verify_attenuation(&child, &proof_resolver, &caveat_resolver)
            .expect_err("widened amount_max_per_call must reject");
        match err {
            UcanError::CaveatAttenuationViolation(AttenuationViolation::AmountWidened {
                ..
            }) => {}
            other => panic!("expected CaveatAttenuationViolation::AmountWidened, got {other:?}"),
        }
    }

    /// Sanity: verify_attenuation with NoCaveatResolver still applies the
    /// pre-existing capability-subset check (no regression for legacy
    /// tokens).
    #[test]
    fn step_7b_no_caveats_preserves_legacy_capability_check() {
        let parent = synthetic_token("PARENT", &["scp:ctx:abc/outlet_call:assistant"], &[]);
        let child = synthetic_token("CHILD", &["scp:ctx:abc/outlet_call:assistant"], &["PARENT"]);

        let mut proof_resolver = InMemoryProofResolver::new();
        proof_resolver.proofs.insert("PARENT".to_owned(), parent);

        // No caveats anywhere — legacy capability-only path.
        verify_attenuation(&child, &proof_resolver, &NoCaveatResolver)
            .expect("matching capabilities pass under NoCaveatResolver");
    }

    // -----------------------------------------------------------------------
    // Step 11b: verify_caveat_time_box hours_of_day
    // -----------------------------------------------------------------------

    /// AC: invocation during a disallowed hour is rejected at Step 11b.
    #[test]
    fn step_11b_rejects_invocation_during_disallowed_hour() {
        // 1970-01-01T12:00:00Z — UTC hour 12.
        let now_at_hour_12: u64 = 12 * 3600;
        let clock = scp_primitives::TestClock::new(now_at_hour_12);

        // Allow only hour 13 (bit 13 set) — bit 12 is clear.
        let mask = crate::trust::caveats::HoursOfDayMask::from_bits(1u32 << 13).unwrap();
        let caveats = InvocationCaveats {
            hours_of_day: Some(mask),
            ..InvocationCaveats::empty()
        };

        let err = verify_caveat_time_box(&caveats, &clock)
            .expect_err("hour-12 invocation must reject when only hour 13 is allowed");
        match err {
            UcanError::CaveatTimeBoxViolation(reason) => {
                assert!(reason.contains("hours_of_day"), "reason: {reason}");
            }
            other => panic!("expected CaveatTimeBoxViolation, got {other:?}"),
        }
    }

    #[test]
    fn step_11b_admits_invocation_during_allowed_hour() {
        let now_at_hour_12: u64 = 12 * 3600;
        let clock = scp_primitives::TestClock::new(now_at_hour_12);

        // Allow hour 12.
        let mask = crate::trust::caveats::HoursOfDayMask::from_bits(1u32 << 12).unwrap();
        let caveats = InvocationCaveats {
            hours_of_day: Some(mask),
            ..InvocationCaveats::empty()
        };

        verify_caveat_time_box(&caveats, &clock).expect("hour 12 allowed");
    }

    #[test]
    fn step_11b_rejects_before_valid_from() {
        let clock = scp_primitives::TestClock::new(1_000);
        let caveats = InvocationCaveats {
            valid_from: Some(2_000),
            ..InvocationCaveats::empty()
        };
        let err = verify_caveat_time_box(&caveats, &clock).expect_err("before valid_from");
        match err {
            UcanError::CaveatTimeBoxViolation(reason) => {
                assert!(reason.contains("valid_from"), "reason: {reason}");
            }
            other => panic!("expected CaveatTimeBoxViolation, got {other:?}"),
        }
    }

    #[test]
    fn step_11b_rejects_after_valid_until() {
        let clock = scp_primitives::TestClock::new(3_000);
        let caveats = InvocationCaveats {
            valid_until: Some(2_000),
            ..InvocationCaveats::empty()
        };
        let err = verify_caveat_time_box(&caveats, &clock).expect_err("after valid_until");
        match err {
            UcanError::CaveatTimeBoxViolation(reason) => {
                assert!(reason.contains("valid_until"), "reason: {reason}");
            }
            other => panic!("expected CaveatTimeBoxViolation, got {other:?}"),
        }
    }

    #[test]
    fn step_11b_rejects_disallowed_weekday() {
        // 1970-01-01 was a Thursday (weekday 4 with Sun=0).
        let clock = scp_primitives::TestClock::new(0);
        // Allow only Sunday (bit 0).
        let mask = crate::trust::caveats::DaysOfWeekMask::from_bits(0b0000_0001).unwrap();
        let caveats = InvocationCaveats {
            days_of_week: Some(mask),
            ..InvocationCaveats::empty()
        };
        let err = verify_caveat_time_box(&caveats, &clock).expect_err("Thursday rejected");
        match err {
            UcanError::CaveatTimeBoxViolation(reason) => {
                assert!(reason.contains("days_of_week"), "reason: {reason}");
            }
            other => panic!("expected CaveatTimeBoxViolation, got {other:?}"),
        }
    }
}
