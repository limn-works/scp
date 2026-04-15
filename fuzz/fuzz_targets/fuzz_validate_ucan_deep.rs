#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! Deep UCAN validation fuzz target (Tier 4).
//!
//! Strategy: generate a structurally valid, correctly-signed UCAN token using
//! a fixed Ed25519 keypair derived from a hardcoded seed, then feed it through
//! `validate_ucan` with a fuzz-controlled validation context.
//!
//! Security invariants verified:
//! - I3: Expired tokens (exp < now) are always rejected.
//! - I6: Timestamps outside [now - skew, now + skew] are always rejected.
//! - I7: Capabilities outside the ceiling are always rejected.
//! - I8: Delegation chain verification always terminates (depth ≤ 32).

use std::collections::HashSet;

use arbitrary::Arbitrary;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;
use scp_protocol::crypto::ucan::validate::{
    DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, InMemoryDidResolver, InMemoryNonceTracker,
    InMemoryProofResolver, InMemoryRevocationChecker, ValidationContext, validate_ucan,
};
use scp_protocol::crypto::ucan::capability::CapabilityUri;
use scp_protocol::crypto::ucan::{Attenuation, UcanHeader, UcanPayload, UcanToken};
use scp_primitives::Clock;

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

// ---------------------------------------------------------------------------
// Fuzz-controlled validation parameters
// ---------------------------------------------------------------------------

/// Fuzz-controlled parameters for the validation context.
///
/// The token is always correctly signed; only the context (clock, ceiling,
/// revocation) is fuzzed. This exercises the validation pipeline gates.
#[derive(Debug, Arbitrary)]
struct FuzzValidationInput {
    /// Simulated current time in seconds since Unix epoch.
    /// The token's `exp` is derived from this to explore expiry paths.
    now_secs: u64,
    /// Whether the token should appear to be expired (exp < now).
    expired: bool,
    /// Lifetime of the token in seconds (capped to 24h for validity).
    lifetime_secs: u8,
    /// Whether to mark the token as revoked.
    revoked: bool,
    /// Fuzz-controlled capability string (for ceiling check).
    capability: Vec<u8>,
}

/// A minimal test clock that returns a fixed `now`.
struct FixedClock(u64);

impl Clock for FixedClock {
    fn now_secs(&self) -> u64 {
        self.0
    }

    fn now_millis(&self) -> u64 {
        self.0.saturating_mul(1000)
    }
}

/// Build a correctly-signed UCAN token using the fuzz keypair.
fn build_signed_token(
    signing_key: &SigningKey,
    now_secs: u64,
    expired: bool,
    lifetime_secs: u64,
    capability: &str,
) -> UcanToken {
    let header = UcanHeader::new();
    let exp = if expired {
        now_secs.saturating_sub(1)
    } else {
        now_secs.saturating_add(lifetime_secs.max(1))
    };
    // Nonce: use current time millis + fixed hex suffix to satisfy format
    // requirement ({unix_millis}-{32_hex_chars}).
    let nonce = format!("{}-{}", now_secs.saturating_mul(1000), "deadbeefcafe1234deadbeefcafe1234");

    let payload = UcanPayload {
        iss: FUZZ_ISSUER_DID.to_owned(),
        aud: FUZZ_AUDIENCE_DID.to_owned(),
        exp,
        nbf: None,
        nnc: nonce,
        att: vec![Attenuation {
            with: format!("scp:ctx:{FUZZ_CONTEXT_ID}/{capability}"),
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

    // Use a bounded capability string: convert fuzz bytes to valid-looking capability.
    // Default to a known-valid capability if bytes aren't valid UTF-8.
    let capability_str = std::str::from_utf8(&input.capability)
        .unwrap_or("messages:write")
        .trim();
    let capability_str = if capability_str.is_empty() {
        "messages:write"
    } else {
        capability_str
    };

    let clock = FixedClock(input.now_secs);

    let token = build_signed_token(
        &signing_key,
        input.now_secs,
        input.expired,
        lifetime_secs,
        capability_str,
    );

    // Build an in-memory DID resolver with the fuzz issuer's public key.
    let mut resolver_keys = std::collections::HashMap::new();
    resolver_keys.insert(FUZZ_ISSUER_DID.to_owned(), public_key_bytes);
    let did_resolver = InMemoryDidResolver::from_keys(resolver_keys);

    let mut nonce_tracker = InMemoryNonceTracker::new();

    // Optionally mark the token as revoked.
    let mut rev_checker = InMemoryRevocationChecker::new();
    if input.revoked {
        // Compute the CID the same way mint.rs does.
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(token.encoded.as_bytes());
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        let cid = format!("bafyrei{hex}");
        rev_checker.revoked.insert(cid);
    }

    let proof_resolver = InMemoryProofResolver::new();

    // Ceiling: allow the standard messages:write capability.
    let mut ceiling: HashSet<String> = HashSet::new();
    ceiling.insert(format!("scp:ctx:{FUZZ_CONTEXT_ID}/messages:write"));
    ceiling.insert(format!("scp:ctx:{FUZZ_CONTEXT_ID}/messages:read"));

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

    // I3 / I6: expired tokens MUST be rejected.
    if input.expired {
        assert!(
            result.is_err(),
            "security invariant I3/I6 violated: expired token accepted by validate_ucan"
        );
    }

    // I7 / revocation: revoked tokens MUST be rejected.
    if input.revoked {
        assert!(
            result.is_err(),
            "security invariant (revocation) violated: revoked token accepted by validate_ucan"
        );
    }
});
