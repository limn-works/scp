#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! Deep UCAN validation fuzz target (Tier 4).
//!
//! Strategy: generate a structurally valid, correctly-signed UCAN token using
//! a fixed Ed25519 keypair derived from a hardcoded seed, then feed it through
//! `validate_ucan` with a fuzz-controlled validation context.
//!
//! Security invariants verified:
//! - I1: `validate_ucan` never panics on any input.
//! - I3: Expired tokens (`exp + skew_tolerance <= now`) are always rejected.
//! - Revocation: revoked tokens (CID in revocation set) are always rejected.
//!
//! Not exercised here:
//! - I7 (ceiling): `FUZZ_CAPABILITY` is always within the ceiling, so ceiling
//!   rejection is never triggered. A dedicated target would fuzz the capability
//!   string against a fixed ceiling to exercise I7.
//! - I8 (chain depth): `prf = vec![]` (no delegation chain), so the depth
//!   limit is never approached. A dedicated target would build multi-hop chains.

use std::collections::HashSet;

use arbitrary::Arbitrary;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;
use scp_fuzz::FixedClock;
use scp_clock::Clock;
use scp_protocol::crypto::ucan::capability::CapabilityUri;
use scp_protocol::crypto::ucan::revoke::compute_revocation_cid;
use scp_protocol::crypto::ucan::validate::{
    DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, InMemoryDidResolver, InMemoryNonceTracker,
    InMemoryProofResolver, InMemoryRevocationChecker, ValidationContext, validate_ucan,
};
use scp_protocol::crypto::ucan::{Attenuation, UcanHeader, UcanPayload, UcanToken};

// ---------------------------------------------------------------------------
// Fixed test identity (deterministic, never used in production)
// ---------------------------------------------------------------------------

/// Hardcoded Ed25519 seed for the fuzz target. Produces a deterministic
/// signing keypair that never changes between fuzzer runs, enabling corpus
/// reuse across versions.
const FUZZ_SEED: [u8; 32] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];

/// DID for the fuzz issuer (did:key with fuzz keypair's public key, hex-encoded).
/// In production, DID resolution is over the DHT — here we use a test DID.
const FUZZ_ISSUER_DID: &str = "did:dht:fuzz-issuer";
const FUZZ_AUDIENCE_DID: &str = "did:dht:fuzz-audience";
const FUZZ_CONTEXT_ID: &str = "fuzz-ctx-001";

/// The capability the token always grants. Fixed to `messages:write` so it is
/// always within the ceiling (which also contains `messages:write`). Fuzzing
/// the capability string added no value: the ceiling check rejected arbitrary
/// bytes, preventing the revocation and expiry invariant paths from being
/// exercised.
const FUZZ_CAPABILITY: &str = "messages:write";

// ---------------------------------------------------------------------------
// Fuzz-controlled validation parameters
// ---------------------------------------------------------------------------

/// Fuzz-controlled parameters for the validation context.
///
/// The token is always correctly signed; only the context (clock, ceiling,
/// revocation) is fuzzed. This exercises the validation pipeline gates.
#[derive(Debug, Arbitrary)]
struct FuzzValidationInput {
    /// Whether the token should appear to be expired
    /// (`exp + skew_tolerance <= now`).
    expired: bool,
    /// Lifetime of the token in seconds (capped to 24h for validity).
    lifetime_secs: u8,
    /// Whether to mark the token as revoked.
    revoked: bool,
}

/// Build a correctly-signed UCAN token using the fuzz keypair.
///
/// The nonce timestamp is pinned to real wall time so that
/// `InMemoryNonceTracker::check_replay` (which uses `SystemClock` internally)
/// accepts the nonce regardless of `expired` or `revoked` state. The expiry
/// path is controlled by `expired` only.
fn build_signed_token(
    signing_key: &SigningKey,
    expired: bool,
    lifetime_secs: u64,
) -> UcanToken {
    let header = UcanHeader::new();

    // Pin `now_secs` to real wall time so the nonce freshness check passes.
    // (InMemoryNonceTracker uses SystemClock internally.)
    let now_secs = scp_clock::SystemClock.now_secs();

    let exp = if expired {
        // Must satisfy `exp + DEFAULT_CLOCK_SKEW_TOLERANCE_SECS <= now_secs`
        // to be rejected by `verify_expiry`. Subtracting tolerance + 1 ensures
        // the token is outside the skew window.
        now_secs.saturating_sub(DEFAULT_CLOCK_SKEW_TOLERANCE_SECS + 1)
    } else {
        // Use a lifetime > clock skew tolerance to avoid spurious expiry
        // on the positive-case assertion if validation crosses a second
        // boundary. The fuzzer still controls whether the token is "expired"
        // via the boolean above; this only affects the unexpired case.
        now_secs.saturating_add(lifetime_secs.max(DEFAULT_CLOCK_SKEW_TOLERANCE_SECS + 2))
    };

    // Nonce: {unix_millis}-{32_hex_chars}. Timestamp uses real wall time so
    // the freshness window in `check_replay` is satisfied.
    let nonce = format!(
        "{}-deadbeefcafe1234deadbeefcafe1234",
        scp_clock::SystemClock.now_millis()
    );

    let payload = UcanPayload {
        iss: FUZZ_ISSUER_DID.to_owned(),
        aud: FUZZ_AUDIENCE_DID.to_owned(),
        exp,
        nbf: None,
        nnc: nonce,
        att: vec![Attenuation {
            with: format!("scp:ctx:{FUZZ_CONTEXT_ID}/{FUZZ_CAPABILITY}"),
            can: "*".to_owned(),
        }],
        prf: vec![],
        fct: None,
    };

    let header_json = serde_json::to_string(&header).expect("header serialization must succeed");
    let payload_json = serde_json::to_string(&payload).expect("payload serialization must succeed");

    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");

    let sig: ed25519_dalek::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let encoded = format!("{signing_input}.{sig_b64}");

    UcanToken {
        header,
        payload,
        signature: sig.to_bytes().to_vec(),
        encoded,
    }
}

fuzz_target!(|input: FuzzValidationInput| {
    // Build the fixed signing keypair.
    let signing_key = SigningKey::from_bytes(&FUZZ_SEED);
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes: [u8; 32] = verifying_key.to_bytes();

    // Cap lifetime to 24h (86400s) to stay within protocol limits.
    let lifetime_secs = u64::from(input.lifetime_secs).min(86400);

    // Clock used by the ValidationContext. Pinned to real wall time so that
    // the expiry check (`exp + tolerance <= now`) sees a stable `now`.
    let now_secs = scp_clock::SystemClock.now_secs();
    let clock = FixedClock(now_secs);

    let token = build_signed_token(&signing_key, input.expired, lifetime_secs);

    // Build an in-memory DID resolver with the fuzz issuer's public key.
    let mut resolver_keys = std::collections::HashMap::new();
    resolver_keys.insert(FUZZ_ISSUER_DID.to_owned(), public_key_bytes);
    let did_resolver = InMemoryDidResolver::from_keys(resolver_keys);

    let mut nonce_tracker = InMemoryNonceTracker::new();

    // Optionally mark the token as revoked.
    // `compute_revocation_cid` produces bare hex SHA-256 — no prefix.
    let mut rev_checker = InMemoryRevocationChecker::new();
    if input.revoked {
        let cid = compute_revocation_cid(&token.encoded);
        rev_checker.revoked.insert(cid);
    }

    let proof_resolver = InMemoryProofResolver::new();

    // Ceiling entries use `capability_name()` format: `"{resource}:{action}"`.
    // `verify_ceiling_compliance` compares `required_cap.capability_name()`
    // against this set — not the full `scp:ctx:…` URI form.
    let mut ceiling: HashSet<String> = HashSet::new();
    ceiling.insert("messages:write".to_owned());
    ceiling.insert("messages:read".to_owned());

    let required_cap = CapabilityUri::new(FUZZ_CONTEXT_ID, "messages", "write");

    let mut ctx = ValidationContext {
        did_resolver: &did_resolver,
        nonce_tracker: &mut nonce_tracker,
        revocation_checker: &rev_checker,
        proof_resolver: &proof_resolver,
        ceiling: &ceiling,
        context_creator_did: FUZZ_ISSUER_DID,
        presenting_agent_did: FUZZ_AUDIENCE_DID,
        clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
        clock: &clock,
    };

    // I1: must not panic on any input.
    let result = validate_ucan(&token, &required_cap, &mut ctx);

    // I3: expired tokens MUST be rejected.
    // `verify_expiry` rejects when `exp + clock_skew_tolerance_secs <= now`.
    if input.expired {
        assert!(
            result.is_err(),
            "security invariant I3 violated: expired token accepted by validate_ucan"
        );
    }

    // Revocation invariant: revoked tokens MUST be rejected.
    if input.revoked {
        assert!(
            result.is_err(),
            "security invariant (revocation) violated: revoked token accepted by validate_ucan"
        );
    }

    // Positive case: a correctly signed, non-expired, non-revoked token MUST
    // be accepted. This catches regressions where the validation pipeline
    // starts incorrectly rejecting valid tokens.
    if !input.expired && !input.revoked {
        assert!(
            result.is_ok(),
            "regression: valid non-expired non-revoked token was rejected by \
             validate_ucan: {result:?}"
        );
    }
});
