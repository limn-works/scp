//! SCPID — DID authentication for external services (§3.11).
//!
//! Pure wire types (`ScpIdChallenge`, `ScpIdResponse`, `ScpIdAuthentication`,
//! `ScpIdError`) and protocol constants live in `scp_protocol::identity::scpid`
//! and are re-exported here for backward compatibility.
//!
//! This module retains the async/runtime-dependent functions:
//! - [`scpid_challenge`] — challenge generation with CSPRNG nonce
//! - [`scpid_sign`] — client-side challenge signing via key custody
//! - [`scpid_verify`] — relying-party 11-step verification (§3.11.4)

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::RngCore;
use subtle::ConstantTimeEq;

use scp_crypto::verify_ed25519_signature;
use scp_did::{SigningKeyId, VerificationRelationship};
use scp_identity::resolver::DidResolver;
use scp_platform::traits::{KeyCustody, KeyHandle};
use scp_protocol::crypto::canonical::{CanonicalField, canonical_hash};

// Re-export pure types from scp-protocol for backward compatibility.
pub use scp_protocol::identity::scpid::{
    SCPID_DOMAIN_SEPARATOR, SCPID_PROTOCOL_VERSION, ScpIdAuthentication, ScpIdChallenge,
    ScpIdError, ScpIdResponse,
};

/// Maximum TTL for an SCPID challenge in milliseconds (§3.11.2: MUST NOT exceed 300 seconds).
const MAX_TTL_MS: u64 = 300_000;

/// Maximum audience string length in bytes.
const MAX_AUDIENCE_BYTES: usize = 2048;

// ---------------------------------------------------------------------------
// Challenge generation
// ---------------------------------------------------------------------------

/// Generate an SCPID challenge for the given audience (§3.11.8).
///
/// Generates a 32-byte CSPRNG nonce, sets `issued_at` to the current time
/// in milliseconds, and computes `expires_at` from the TTL.
///
/// # Errors
///
/// Returns [`ScpIdError::InvalidInput`] if:
/// - `ttl` is zero
/// - `ttl` exceeds 300 seconds (§3.11.2 constraint)
/// - `audience` is empty (not a valid URI per RFC 3986)
/// - `audience` exceeds 2048 bytes
pub fn scpid_challenge(audience: &str, ttl: Duration) -> Result<ScpIdChallenge, ScpIdError> {
    // TTL is bounded to 300 000 ms, so u128→u64 truncation cannot occur,
    // but we use saturating conversion to keep clippy happy without #[allow].
    let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);

    if ttl_ms == 0 {
        return Err(ScpIdError::InvalidInput(
            "TTL must be greater than zero".to_owned(),
        ));
    }

    if ttl_ms > MAX_TTL_MS {
        return Err(ScpIdError::InvalidInput(
            "TTL exceeds 300 seconds".to_owned(),
        ));
    }

    if audience.is_empty() {
        return Err(ScpIdError::InvalidInput(
            "audience must not be empty".to_owned(),
        ));
    }

    if audience.len() > MAX_AUDIENCE_BYTES {
        return Err(ScpIdError::InvalidInput(
            "audience exceeds 2048 bytes".to_owned(),
        ));
    }

    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ScpIdError::InvalidInput(format!("system clock error: {e}")))?
        .as_millis();
    let issued_at = u64::try_from(now_ms)
        .map_err(|_| ScpIdError::InvalidInput("system clock overflow".to_owned()))?;

    let expires_at = issued_at + ttl_ms;

    Ok(ScpIdChallenge {
        protocol: SCPID_PROTOCOL_VERSION.to_owned(),
        nonce,
        audience: audience.to_owned(),
        issued_at,
        expires_at,
    })
}

// ---------------------------------------------------------------------------
// Client-side signing
// ---------------------------------------------------------------------------

/// Sign an SCPID challenge, producing an [`ScpIdResponse`] (§3.11.3).
///
/// Constructs the canonical hash specified in §3.11.3 and signs it with the
/// caller's Ed25519 key via [`KeyCustody`]. The `signed_at` timestamp is set
/// to the current time in milliseconds, unless `signed_at_override` is
/// supplied (testing-only; see below).
///
/// # Arguments
///
/// * `signed_at_override` — When `Some(ts_ms)`, use the provided millisecond
///   timestamp for `signed_at` instead of `SystemTime::now()`. Intended for
///   the cross-bridge parity harness (ADR-046) so that two bridges signing
///   the same challenge with the same seed produce byte-identical
///   signatures. The override must still fall within the challenge window
///   `[issued_at, expires_at]`. Pass `None` in production callers.
///
/// # Errors
///
/// Returns [`ScpIdError::ChallengeExpired`] if the challenge has already
/// expired. Returns [`ScpIdError::InvalidInput`] if the protocol version
/// is unsupported, the system clock is before the Unix epoch, or the
/// supplied `signed_at_override` is outside the challenge window. Returns
/// [`ScpIdError::SigningFailed`] if the custody operation fails.
pub async fn scpid_sign(
    custody: &impl KeyCustody,
    signing_key: &KeyHandle,
    did: &str,
    signing_key_id: SigningKeyId,
    challenge: &ScpIdChallenge,
    signed_at_override: Option<u64>,
) -> Result<ScpIdResponse, ScpIdError> {
    // Reject empty DID (consistent with audience validation in scpid_challenge).
    if did.is_empty() {
        return Err(ScpIdError::InvalidInput("DID must not be empty".to_owned()));
    }

    // Reject expired challenges (fail fast). Real wall-clock is used even
    // when `signed_at_override` is supplied — we never allow the override
    // to bypass the challenge-expiry check for wall-clock time.
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ScpIdError::InvalidInput(format!("system clock error: {e}")))?
        .as_millis();
    let now_ms = u64::try_from(now_ms)
        .map_err(|_| ScpIdError::InvalidInput("system clock overflow".to_owned()))?;

    if now_ms > challenge.expires_at {
        return Err(ScpIdError::ChallengeExpired);
    }

    // Validate protocol.
    if challenge.protocol != SCPID_PROTOCOL_VERSION {
        return Err(ScpIdError::InvalidInput(format!(
            "unsupported protocol: {}, expected {SCPID_PROTOCOL_VERSION}",
            challenge.protocol
        )));
    }

    // Resolve `signed_at`: use the override if supplied, otherwise the
    // current wall-clock time. The override must still fall within the
    // challenge window `[issued_at, expires_at]` to produce a response a
    // relying-party would accept.
    //
    // `signed_at_override` is a parity-harness affordance (ADR-046),
    // gated behind `feature = "testing"` at the runtime layer so direct
    // consumers (scp-mcp, scp-node, scp-media, scp-transport, rust-
    // client scaffolds) cannot supply it in production builds. The FFI
    // bridges layer their own rejection for defence-in-depth (see
    // `scp-ffi/src/scpid.rs`, `scp-ffi/napi/src/scpid.rs`,
    // `scp-ffi/uniffi/src/bridge.rs`).
    #[cfg(not(feature = "testing"))]
    if signed_at_override.is_some() {
        return Err(ScpIdError::InvalidInput(
            "signed_at_override requires the scp-runtime `testing` feature — \
             not available in production builds"
                .to_owned(),
        ));
    }
    let signed_at = if let Some(override_ms) = signed_at_override {
        if override_ms < challenge.issued_at || override_ms > challenge.expires_at {
            return Err(ScpIdError::InvalidInput(format!(
                "signed_at_override {override_ms} outside challenge window \
                 [{issued_at}, {expires_at}]",
                issued_at = challenge.issued_at,
                expires_at = challenge.expires_at,
            )));
        }
        override_ms
    } else {
        now_ms
    };

    // Build canonical hash (§3.11.3):
    //   SHA-256(
    //       "SCP-DID-AUTH-V1:"
    //       || BE32(len(did))           || did
    //       || BE32(len(signing_key_id)) || signing_key_id
    //       || nonce (32 bytes raw)
    //       || BE32(len(audience))       || audience
    //       || signed_at as u64 BE
    //   )
    let hash = canonical_hash(
        SCPID_DOMAIN_SEPARATOR,
        &[
            CanonicalField::VarBytes(did.as_bytes()),
            CanonicalField::VarBytes(signing_key_id.as_fragment().as_bytes()),
            CanonicalField::Fixed32(&challenge.nonce),
            CanonicalField::VarBytes(challenge.audience.as_bytes()),
            CanonicalField::U64(signed_at),
        ],
    )
    .map_err(|e| ScpIdError::SigningFailed(format!("canonical hash failed: {e}")))?;

    // Sign via KeyCustody.
    let signature = custody
        .sign(signing_key, &hash)
        .await
        .map_err(|e| ScpIdError::SigningFailed(e.to_string()))?;

    // Convert to [u8; 64].
    let sig_bytes: [u8; 64] = signature.into_bytes().try_into().map_err(|v: Vec<u8>| {
        ScpIdError::SigningFailed(format!(
            "expected 64-byte Ed25519 signature, got {} bytes",
            v.len()
        ))
    })?;

    Ok(ScpIdResponse {
        protocol: SCPID_PROTOCOL_VERSION.to_owned(),
        did: did.to_owned(),
        signing_key_id,
        nonce: challenge.nonce,
        audience: challenge.audience.clone(),
        signed_at,
        signature: sig_bytes,
    })
}

// ---------------------------------------------------------------------------
// Relying-party verification (§3.11.4)
// ---------------------------------------------------------------------------

/// Verify an SCPID response against the original challenge (§3.11.4).
///
/// Implements the full 11-step verification procedure:
///
/// 1. Parse (already done — typed inputs).
/// 2. Constant-time nonce match.
/// 3. Constant-time audience match.
/// 4. Timestamp window validation.
/// 5. DID resolution via dual-layer resolver.
/// 6. Public key extraction from DID document verification methods.
/// 7. Signing key ID validation (`#active` or `#agent`).
/// 8. Authentication relationship check.
/// 9. Canonical hash reconstruction.
/// 10. Ed25519 strict signature verification.
/// 11. Return authenticated identity.
///
/// DID document freshness (the 300s requirement from §3.11.4 step 5c) is
/// enforced by the resolver's cache policy, not by this function.
///
/// # Caller Responsibilities
///
/// - The relying party **must** track issued nonces and reject duplicates
///   per §3.11.6.  This function verifies that the response nonce matches
///   the challenge nonce, but it does not consume or invalidate the nonce.
///
/// # Errors
///
/// Returns the appropriate [`ScpIdError`] variant for each verification
/// failure per the error table in §3.11.4.
pub async fn scpid_verify(
    resolver: &impl DidResolver,
    response: &ScpIdResponse,
    challenge: &ScpIdChallenge,
) -> Result<ScpIdAuthentication, ScpIdError> {
    // Step 0: Validate protocol version.
    if response.protocol != SCPID_PROTOCOL_VERSION {
        return Err(ScpIdError::InvalidInput(format!(
            "unsupported protocol: {}, expected {SCPID_PROTOCOL_VERSION}",
            response.protocol
        )));
    }

    // Step 2: Constant-time nonce comparison (replay prevention).
    if !bool::from(response.nonce.ct_eq(&challenge.nonce)) {
        return Err(ScpIdError::ChallengeExpired);
    }

    // Step 3: Constant-time audience comparison (defense in depth).
    if !bool::from(
        response
            .audience
            .as_bytes()
            .ct_eq(challenge.audience.as_bytes()),
    ) {
        return Err(ScpIdError::AudienceMismatch);
    }

    // Step 4: Timestamp window validation.
    //   - signed_at must be within [issued_at, expires_at]
    //   - current time must be <= expires_at
    if response.signed_at < challenge.issued_at || response.signed_at > challenge.expires_at {
        return Err(ScpIdError::TimestampInvalid);
    }

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ScpIdError::InvalidInput(format!("system clock error: {e}")))?
        .as_millis();
    let now_ms = u64::try_from(now_ms)
        .map_err(|_| ScpIdError::InvalidInput("system clock overflow".to_owned()))?;

    if now_ms > challenge.expires_at {
        return Err(ScpIdError::TimestampInvalid);
    }

    // Step 5: Resolve the DID document.
    let did_result = resolver
        .resolve(&response.did)
        .await
        .map_err(|e| ScpIdError::DidResolutionFailed(e.to_string()))?
        .ok_or_else(|| {
            ScpIdError::DidResolutionFailed(format!("DID not found: {}", response.did))
        })?;

    let doc = &did_result.document;

    // A resolver answers with a document, and step 11 authenticates the caller
    // as the holder of a method on `response.did`, so the two have to name one
    // identity. `signing_key_for` reads `{doc.id}#{fragment}` — it cannot check
    // which DID a caller asked for — and the code this replaced built its
    // identifier from `response.did`, which tied them implicitly. This states
    // the tie.
    //
    // A shipped resolver already makes a mismatch unreachable: `verify_relay_record`
    // checks a BEP44 signature against the key the requested DID encodes, and
    // `verify_self_certification` requires `{doc.id}#0` to carry that same key.
    // This check does not depend on either one running.
    if doc.id != response.did {
        return Err(ScpIdError::DidResolutionFailed(format!(
            "resolved DID document describes {}, not the DID {} a caller authenticated as",
            doc.id, response.did
        )));
    }

    // Steps 6, 7, and 8 in one call to the crate that owns a DID document.
    //
    // `signing_key_for` reads a key out of `doc` under four document facts, and
    // the last two are the ones this function used to check by hand:
    //
    // - Step 6 extracts a key from the method `{doc.id}#{fragment}` names. Two
    //   facts this function did not check ride along: a `type` of
    //   `Ed25519VerificationKey2020`, since decoding `publicKeyMultibase` alone
    //   cannot separate a signing key from a key-agreement key, and a
    //   `controller` equal to the document's own DID, since SCP defines no
    //   delegation letting another DID sign as this one. A repeated identifier
    //   supplies nothing either, because W3C DID Core §5.3.1 requires an
    //   identifier to be unique and array position must never decide which key
    //   verifies. This function selected the first of two matches.
    // - Step 7 admits `#active` and `#agent` and rejects every other value.
    //   `SigningKeyId` has exactly those two variants, so `response`'s own type
    //   decides it and no runtime check adds anything.
    // - Step 8 requires `doc.authentication` to reference that method.
    //
    // Error mapping follows §3.11.4's table, which this function's previous
    // hand-rolled steps already followed: a method a document does not
    // authorize is `KEY_NOT_AUTHORIZED`, and a `publicKeyMultibase` value that
    // does not decode means the document itself is unreadable, which is
    // `DID_RESOLUTION_FAILED`. `signing_key_for` separates the two —
    // `UnusableVerificationMethod` for the authorization facts,
    // `InvalidDidFormat` for a decode failure — so no distinction an operator
    // reads in a server-side log collapses here. §3.11.4's error-response
    // guidance still tells a relying party to return one generic failure to an
    // untrusted client rather than either code.
    let public_key_bytes = doc
        .signing_key_for(
            response.signing_key_id,
            VerificationRelationship::Authentication,
        )
        .map_err(|error| match error {
            scp_did::DidError::UnusableVerificationMethod { .. } => ScpIdError::KeyNotAuthorized,
            other => {
                ScpIdError::DidResolutionFailed(format!("failed to decode public key: {other}"))
            }
        })?;

    // Step 9: Reconstruct the canonical hash (same construction as scpid_sign).
    let hash = canonical_hash(
        SCPID_DOMAIN_SEPARATOR,
        &[
            CanonicalField::VarBytes(response.did.as_bytes()),
            CanonicalField::VarBytes(response.signing_key_id.as_fragment().as_bytes()),
            CanonicalField::Fixed32(&response.nonce),
            CanonicalField::VarBytes(response.audience.as_bytes()),
            CanonicalField::U64(response.signed_at),
        ],
    )
    .map_err(|e| ScpIdError::SigningFailed(format!("canonical hash failed: {e}")))?;

    // Step 10: Verify Ed25519 signature (strict mode — rejects small-order points).
    verify_ed25519_signature(&public_key_bytes, &hash, &response.signature)
        .map_err(|_| ScpIdError::SignatureInvalid)?;

    // Step 11: All checks pass — return authenticated identity.
    Ok(ScpIdAuthentication {
        did: response.did.clone(),
        signing_key_id: response.signing_key_id,
        signed_at: response.signed_at,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_protocol::crypto::canonical::{CanonicalField, canonical_hash};

    #[test]
    fn test_challenge_generation() {
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(1))
            .expect("challenge generation should succeed");

        assert_eq!(challenge.protocol, "scpid/1.0");
        assert_eq!(challenge.audience, "https://example.com");
        assert_eq!(challenge.expires_at, challenge.issued_at + 60_000);
        // Nonce should not be all zeros (overwhelmingly unlikely from CSPRNG).
        assert_ne!(challenge.nonce, [0u8; 32]);
    }

    #[test]
    fn test_challenge_json_roundtrip() {
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(2))
            .expect("challenge generation should succeed");

        let json = serde_json::to_string(&challenge).expect("serialize should succeed");

        // The nonce should be 64 lowercase hex chars in the JSON.
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse JSON");
        let nonce_str = v["nonce"].as_str().expect("nonce should be a string");
        assert_eq!(nonce_str.len(), 64);
        assert!(
            nonce_str.chars().all(|c| c.is_ascii_hexdigit()),
            "nonce should be hex"
        );
        // Lowercase check.
        assert_eq!(nonce_str, nonce_str.to_lowercase());

        let roundtripped: ScpIdChallenge =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(roundtripped.nonce, challenge.nonce);
        assert_eq!(roundtripped.audience, challenge.audience);
        assert_eq!(roundtripped.issued_at, challenge.issued_at);
        assert_eq!(roundtripped.expires_at, challenge.expires_at);
        assert_eq!(roundtripped.protocol, challenge.protocol);
    }

    #[test]
    fn test_response_json_roundtrip() {
        let nonce = [0xBBu8; 32];
        let signature = [0xCCu8; 64];

        let response = ScpIdResponse {
            protocol: SCPID_PROTOCOL_VERSION.to_owned(),
            did: "did:dht:z6MkTest".to_owned(),
            signing_key_id: SigningKeyId::Active,
            nonce,
            audience: "https://example.com".to_owned(),
            signed_at: 1_709_654_400_000,
            signature,
        };

        let json = serde_json::to_string(&response).expect("serialize");
        let roundtripped: ScpIdResponse = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(roundtripped.did, response.did);
        assert_eq!(roundtripped.signing_key_id, response.signing_key_id);
        assert_eq!(roundtripped.nonce, response.nonce);
        assert_eq!(roundtripped.audience, response.audience);
        assert_eq!(roundtripped.signed_at, response.signed_at);
        assert_eq!(roundtripped.signature, response.signature);
        assert_eq!(roundtripped.protocol, response.protocol);

        // Verify hex encoding in JSON.
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse JSON");
        assert_eq!(v["nonce"].as_str().expect("nonce str").len(), 64);
        assert_eq!(v["signature"].as_str().expect("sig str").len(), 128);
        assert_eq!(v["signing_key_id"].as_str().expect("key id"), "#active");
    }

    #[test]
    fn test_ttl_rejection() {
        let result = scpid_challenge("https://example.com", Duration::from_secs(301));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ScpIdError::InvalidInput(ref msg) if msg.contains("TTL exceeds 300 seconds")),
            "expected InvalidInput with TTL message, got: {err}"
        );
    }

    #[test]
    fn test_ttl_boundary_exactly_300() {
        // Exactly 300 seconds should succeed.
        let result = scpid_challenge("https://example.com", Duration::from_mins(5));
        assert!(result.is_ok());
    }

    #[test]
    fn test_ttl_boundary_300_plus_millis() {
        // 300.001 seconds (300_001 ms) should fail — exceeds MAX_TTL_MS.
        let result = scpid_challenge("https://example.com", Duration::from_millis(300_001));
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_ttl_rejection() {
        let result = scpid_challenge("https://example.com", Duration::from_secs(0));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ScpIdError::InvalidInput(ref msg) if msg.contains("TTL must be greater than zero")),
            "expected InvalidInput with zero TTL message, got: {err}"
        );
    }

    #[test]
    fn test_audience_length_rejection() {
        let long_audience = "x".repeat(2049);
        let result = scpid_challenge(&long_audience, Duration::from_mins(1));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ScpIdError::InvalidInput(ref msg) if msg.contains("audience exceeds 2048 bytes")),
            "expected InvalidInput with audience message, got: {err}"
        );
    }

    #[test]
    fn test_audience_boundary_exactly_2048() {
        let audience = "x".repeat(2048);
        let result = scpid_challenge(&audience, Duration::from_mins(1));
        assert!(result.is_ok());
    }

    #[test]
    fn test_protocol_field() {
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(1))
            .expect("challenge generation should succeed");
        assert_eq!(challenge.protocol, "scpid/1.0");
    }

    #[test]
    fn test_invalid_protocol_rejected_on_deser() {
        // Protocol validation happens at deserialization time —
        // reject unrecognized protocol versions immediately.
        let json = r#"{
            "protocol": "wrong/2.0",
            "nonce": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "audience": "https://example.com",
            "issued_at": 1709654400000,
            "expires_at": 1709654700000
        }"#;
        let result = serde_json::from_str::<ScpIdChallenge>(json);
        assert!(
            result.is_err(),
            "should reject wrong protocol on deserialization"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("unsupported SCPID protocol version"),
            "error should mention unsupported protocol version, got: {err_msg}"
        );
    }

    #[test]
    fn test_invalid_protocol_rejected_on_response_deser() {
        // Protocol validation also applies to ScpIdResponse deserialization.
        let json = r##"{
            "protocol": "wrong/2.0",
            "did": "did:dht:z6MkTest",
            "signing_key_id": "#active",
            "nonce": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "audience": "https://example.com",
            "signed_at": 1709654400000,
            "signature": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        }"##;
        let result = serde_json::from_str::<ScpIdResponse>(json);
        assert!(
            result.is_err(),
            "should reject wrong protocol on response deser"
        );
    }

    #[test]
    fn test_empty_audience_rejection() {
        let result = scpid_challenge("", Duration::from_mins(1));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ScpIdError::InvalidInput(ref msg) if msg.contains("audience must not be empty")),
            "expected InvalidInput with empty audience message, got: {err}"
        );
    }

    #[test]
    fn test_golden_vector_canonical_hash() {
        // Golden test vector for SCPID signed content (§3.11.3).
        //
        // Inputs:
        //   did            = "did:dht:z6MkTest"
        //   signing_key_id = "#active" (SigningKeyId::Active)
        //   nonce          = 0xAA repeated 32 times
        //   audience       = "https://example.com"
        //   signed_at      = 1709654400000 (milliseconds per §3.11.2)
        //
        // Construction per §3.11.3:
        //   SHA-256(
        //       "SCP-DID-AUTH-V1:"
        //       || BE32(len("did:dht:z6MkTest")) || "did:dht:z6MkTest"
        //       || BE32(len("#active"))           || "#active"
        //       || nonce (32 bytes raw, no prefix)
        //       || BE32(len("https://example.com")) || "https://example.com"
        //       || signed_at as u64 BE
        //   )
        let did = "did:dht:z6MkTest";
        let signing_key_id = SigningKeyId::Active;
        let nonce = [0xAAu8; 32];
        let audience = "https://example.com";
        let signed_at: u64 = 1_709_654_400_000;

        let hash = canonical_hash(
            SCPID_DOMAIN_SEPARATOR,
            &[
                CanonicalField::VarBytes(did.as_bytes()),
                CanonicalField::VarBytes(signing_key_id.as_fragment().as_bytes()),
                CanonicalField::Fixed32(&nonce),
                CanonicalField::VarBytes(audience.as_bytes()),
                CanonicalField::U64(signed_at),
            ],
        )
        .unwrap();

        // Independently computed expected value (verified with Python):
        //   import hashlib, struct
        //   def lp(b): return struct.pack('>I', len(b)) + b
        //   nonce = bytes([0xAA] * 32)
        //   data = (b'SCP-DID-AUTH-V1:'
        //     + lp(b'did:dht:z6MkTest')
        //     + lp(b'#active')
        //     + nonce
        //     + lp(b'https://example.com')
        //     + struct.pack('>Q', 1709654400000))
        //   print(hashlib.sha256(data).hexdigest())
        assert_eq!(
            hex::encode(hash),
            "7552b8e3b0e1654593e956c1429d479eda0524bc6cdc863b142d5909471b57e0"
        );
    }

    // -----------------------------------------------------------------------
    // scpid_sign tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_scpid_sign_roundtrip() {
        use ed25519_dalek::Verifier;
        use scp_platform::KeyType;
        use scp_platform::testing::InMemoryKeyCustody;

        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let pubkey = custody.public_key(&handle).await.unwrap();

        let challenge = scpid_challenge("https://example.com", Duration::from_mins(2)).unwrap();

        let response = scpid_sign(
            &custody,
            &handle,
            "did:dht:z6MkTest",
            SigningKeyId::Active,
            &challenge,
            None,
        )
        .await
        .unwrap();

        // Verify all fields are populated correctly.
        assert_eq!(response.protocol, SCPID_PROTOCOL_VERSION);
        assert_eq!(response.did, "did:dht:z6MkTest");
        assert_eq!(response.signing_key_id, SigningKeyId::Active);
        assert_eq!(response.nonce, challenge.nonce);
        assert_eq!(response.audience, "https://example.com");
        assert!(response.signed_at >= challenge.issued_at);
        assert!(response.signed_at <= challenge.expires_at);

        // Manually recompute the canonical hash and verify the signature.
        let hash = canonical_hash(
            SCPID_DOMAIN_SEPARATOR,
            &[
                CanonicalField::VarBytes(b"did:dht:z6MkTest"),
                CanonicalField::VarBytes(SigningKeyId::Active.as_fragment().as_bytes()),
                CanonicalField::Fixed32(&response.nonce),
                CanonicalField::VarBytes(b"https://example.com"),
                CanonicalField::U64(response.signed_at),
            ],
        )
        .unwrap();

        let pk_bytes: [u8; 32] = pubkey.as_bytes().try_into().unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&response.signature);
        verifying_key
            .verify(&hash, &signature)
            .expect("signature should verify against recomputed canonical hash");
    }

    #[tokio::test]
    async fn test_scpid_sign_with_agent_key() {
        use ed25519_dalek::Verifier;
        use scp_platform::KeyType;
        use scp_platform::testing::InMemoryKeyCustody;

        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let pubkey = custody.public_key(&handle).await.unwrap();

        let challenge =
            scpid_challenge("https://agent-service.example.com", Duration::from_mins(1)).unwrap();

        let response = scpid_sign(
            &custody,
            &handle,
            "did:dht:z6MkAgent",
            SigningKeyId::Agent,
            &challenge,
            None,
        )
        .await
        .unwrap();

        assert_eq!(response.signing_key_id, SigningKeyId::Agent);
        assert_eq!(response.did, "did:dht:z6MkAgent");

        // Verify the signature with #agent fragment in the hash.
        let hash = canonical_hash(
            SCPID_DOMAIN_SEPARATOR,
            &[
                CanonicalField::VarBytes(b"did:dht:z6MkAgent"),
                CanonicalField::VarBytes(SigningKeyId::Agent.as_fragment().as_bytes()),
                CanonicalField::Fixed32(&response.nonce),
                CanonicalField::VarBytes(b"https://agent-service.example.com"),
                CanonicalField::U64(response.signed_at),
            ],
        )
        .unwrap();

        let pk_bytes: [u8; 32] = pubkey.as_bytes().try_into().unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&response.signature);
        verifying_key
            .verify(&hash, &signature)
            .expect("agent-signed response should verify");
    }

    #[tokio::test]
    async fn test_scpid_sign_expired_challenge() {
        use scp_platform::KeyType;
        use scp_platform::testing::InMemoryKeyCustody;

        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        // Create a challenge with 1ms TTL.
        let challenge = scpid_challenge("https://example.com", Duration::from_millis(1)).unwrap();

        // Sleep long enough for the challenge to expire.
        tokio::time::sleep(Duration::from_millis(10)).await;

        let result = scpid_sign(
            &custody,
            &handle,
            "did:dht:z6MkTest",
            SigningKeyId::Active,
            &challenge,
            None,
        )
        .await;

        assert!(
            matches!(result, Err(ScpIdError::ChallengeExpired)),
            "expected ChallengeExpired, got: {result:?}"
        );
    }

    /// Byte-exact signature determinism under the `signed_at_override`
    /// testing affordance (ADR-046 parity harness). Two `scpid_sign`
    /// calls with the same seeded
    /// custody, same signing-key handle, same DID + challenge, and the
    /// same override timestamp MUST produce byte-identical signatures.
    /// Any drift (RNG/timestamp/canonical-hash) breaks cross-bridge
    /// parity and this test catches it at the scp-runtime layer.
    ///
    /// Gated on `feature = "testing"`: `signed_at_override` is only
    /// honoured under that feature (the production guard above rejects it),
    /// so this test exercises the seam only when the seam is active.
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn test_scpid_sign_override_is_byte_deterministic() {
        use scp_platform::testing::InMemoryKeyCustody;

        // Two fresh custodies with the same seed so `generate_keypair`
        // returns byte-identical handles + keys across both.
        let seed = [0x7bu8; 32];
        let custody_a = InMemoryKeyCustody::from_seed_bytes(seed);
        let custody_b = InMemoryKeyCustody::from_seed_bytes(seed);

        let _id_a = custody_a
            .generate_keypair(scp_platform::KeyType::Ed25519)
            .await
            .unwrap();
        let active_a = custody_a
            .generate_keypair(scp_platform::KeyType::Ed25519)
            .await
            .unwrap();
        let _id_b = custody_b
            .generate_keypair(scp_platform::KeyType::Ed25519)
            .await
            .unwrap();
        let active_b = custody_b
            .generate_keypair(scp_platform::KeyType::Ed25519)
            .await
            .unwrap();

        // Issue a fresh challenge so wall-clock expiry doesn't trip the
        // expiry check — the `signed_at_override` deliberately does NOT
        // bypass challenge expiry, only `signed_at` in the canonical
        // hash. Use a fixed override timestamp inside the window so the
        // output is still byte-deterministic across the two runs.
        let now_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        let challenge = ScpIdChallenge {
            protocol: SCPID_PROTOCOL_VERSION.to_owned(),
            nonce: [0xAAu8; 32],
            audience: "https://parity-test.example.com".to_owned(),
            issued_at: now_ms,
            expires_at: now_ms + 60_000,
        };
        // Pin the override to a stable value within the window so both
        // sign calls produce byte-identical canonical hashes.
        let override_ts: u64 = now_ms + 1_000;

        let resp_a = scpid_sign(
            &custody_a,
            &active_a,
            "did:dht:zparitytest",
            SigningKeyId::Active,
            &challenge,
            Some(override_ts),
        )
        .await
        .unwrap();

        let resp_b = scpid_sign(
            &custody_b,
            &active_b,
            "did:dht:zparitytest",
            SigningKeyId::Active,
            &challenge,
            Some(override_ts),
        )
        .await
        .unwrap();

        assert_eq!(
            resp_a.signature, resp_b.signature,
            "scpid_sign must be deterministic under shared seed + override"
        );
        assert_eq!(
            resp_a.signed_at, override_ts,
            "signed_at must equal the override when supplied"
        );
    }

    /// Prints the expected byte-exact SCPID signature for the cross-
    /// bridge parity harness (ADR-046 op `sign_message`). Run with:
    ///
    /// ```sh
    /// DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))") \
    ///     cargo test -p scp-runtime --lib \
    ///     identity::scpid::tests::print_parity_sign_golden_value \
    ///     -- --ignored --nocapture
    /// ```
    ///
    /// The parity harness pins this exact signature — if you change the
    /// seed, canonical-hash construction, or SCPID key sequence, this
    /// test is the source of truth for the replacement golden value.
    ///
    /// Inputs: `seed = [0x7b; 32]`, DID = `did:dht:zjerxoow…` (derived
    /// from `seed[0..32]`), `active_key` bytes = `seed[32..64]`,
    /// `audience = "https://parity-test.example.com"`, `nonce = [0xAA; 32]`,
    /// `signed_at = 1_700_000_000_000`. Challenge `issued_at` /
    /// `expires_at` must straddle the override; the harness sets them
    /// to `override_ts` and `override_ts + 60_000` respectively.
    #[cfg(feature = "testing")]
    #[tokio::test]
    #[ignore = "golden-value print — run with --ignored --nocapture"]
    async fn print_parity_sign_golden_value() {
        use scp_platform::testing::InMemoryKeyCustody;

        let seed = [0x7bu8; 32];
        let custody = InMemoryKeyCustody::from_seed_bytes(seed);
        let _id = custody
            .generate_keypair(scp_platform::KeyType::Ed25519)
            .await
            .unwrap();
        let active = custody
            .generate_keypair(scp_platform::KeyType::Ed25519)
            .await
            .unwrap();

        // Derive the DID from the identity key — this matches the
        // EXPECTED_SEEDED_DID the parity harness pins.
        let did = "did:dht:zjerxoow7gsm8suaqfsc86txbreganh7chorzwwh4crbh7imbdhgy";
        // Use a fixed override timestamp plus a far-future `expires_at`
        // so (a) the override stays within the challenge window and
        // (b) `now_ms > expires_at` never trips the expiry check.
        // Both the parity harness AND this golden-value print must use
        // identical values — drift between them would break the gate.
        let override_ts: u64 = 1_700_000_000_000; // pinned SCPID signed_at
        let challenge = ScpIdChallenge {
            protocol: SCPID_PROTOCOL_VERSION.to_owned(),
            nonce: [0xAAu8; 32],
            audience: "https://parity-test.example.com".to_owned(),
            issued_at: override_ts,
            expires_at: 9_999_999_999_000, // year 2286 — effectively never expires
        };
        let resp = scpid_sign(
            &custody,
            &active,
            did,
            SigningKeyId::Active,
            &challenge,
            Some(override_ts),
        )
        .await
        .unwrap();
        println!(
            "EXPECTED_SEEDED_SIGNATURE_HEX = \"{}\"",
            hex::encode(resp.signature)
        );
    }

    /// Override outside the challenge window is rejected to prevent the
    /// parity affordance from being weaponised as a way to forge
    /// out-of-window responses.
    ///
    /// Gated on `feature = "testing"`: this asserts the in-window check on
    /// `signed_at_override`, which is only reachable when the seam is
    /// active (the production guard above rejects any override outright).
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn test_scpid_sign_override_rejects_out_of_window() {
        use scp_platform::testing::InMemoryKeyCustody;

        let custody = InMemoryKeyCustody::new();
        let handle = custody
            .generate_keypair(scp_platform::KeyType::Ed25519)
            .await
            .unwrap();
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(1)).unwrap();

        let too_early = scpid_sign(
            &custody,
            &handle,
            "did:dht:zfoo",
            SigningKeyId::Active,
            &challenge,
            Some(challenge.issued_at.saturating_sub(1)),
        )
        .await;
        assert!(
            matches!(too_early, Err(ScpIdError::InvalidInput(ref m)) if m.contains("outside challenge window")),
            "override before issued_at must be rejected, got: {too_early:?}"
        );

        let too_late = scpid_sign(
            &custody,
            &handle,
            "did:dht:zfoo",
            SigningKeyId::Active,
            &challenge,
            Some(challenge.expires_at + 1),
        )
        .await;
        assert!(
            matches!(too_late, Err(ScpIdError::InvalidInput(ref m)) if m.contains("outside challenge window")),
            "override after expires_at must be rejected, got: {too_late:?}"
        );
    }

    #[tokio::test]
    async fn test_scpid_sign_empty_did_rejected() {
        use scp_platform::KeyType;
        use scp_platform::testing::InMemoryKeyCustody;

        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(1)).unwrap();

        let result = scpid_sign(
            &custody,
            &handle,
            "",
            SigningKeyId::Active,
            &challenge,
            None,
        )
        .await;
        assert!(
            matches!(result, Err(ScpIdError::InvalidInput(ref msg)) if msg.contains("DID must not be empty")),
            "expected InvalidInput with empty DID message, got: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // scpid_verify tests
    // -----------------------------------------------------------------------

    /// Test DID resolver that returns a pre-configured `DidDocument` wrapped
    /// in a `ResolvedDidDocument`. Implements `scp_identity::resolver::DidResolver`.
    struct TestDidResolver {
        document: Option<scp_did::DidDocument>,
        /// When `true`, `resolve()` returns `Err(...)` instead of `Ok(...)`.
        fail: bool,
    }

    impl TestDidResolver {
        fn with_document(doc: scp_did::DidDocument) -> Self {
            Self {
                document: Some(doc),
                fail: false,
            }
        }

        fn not_found() -> Self {
            Self {
                document: None,
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                document: None,
                fail: true,
            }
        }
    }

    impl scp_identity::resolver::DidResolver for TestDidResolver {
        fn resolve(
            &self,
            _did: &str,
        ) -> impl Future<
            Output = Result<
                Option<scp_identity::resolver::ResolvedDidDocument>,
                scp_identity::IdentityError,
            >,
        > + Send {
            let result = if self.fail {
                Err(scp_identity::IdentityError::DhtResolveFailed(
                    "test resolver failure".to_owned(),
                ))
            } else {
                Ok(self
                    .document
                    .clone()
                    .map(|doc| scp_identity::resolver::ResolvedDidDocument {
                        document: doc,
                        seq: 1,
                        source: scp_identity::resolver::ResolutionSource::Cache,
                    }))
            };
            async move { result }
        }
    }

    /// Helper: generates a keypair, signs an SCPID challenge, and returns the
    /// response along with the public key bytes and DID document.
    async fn sign_and_build_doc(
        did: &str,
        signing_key_id: SigningKeyId,
        challenge: &ScpIdChallenge,
    ) -> (ScpIdResponse, scp_did::DidDocument) {
        use scp_platform::KeyType;
        use scp_platform::testing::InMemoryKeyCustody;

        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let pubkey = custody.public_key(&handle).await.unwrap();
        let pk_bytes: [u8; 32] = pubkey.as_bytes().try_into().unwrap();

        let response = scpid_sign(&custody, &handle, did, signing_key_id, challenge, None)
            .await
            .unwrap();

        // Build a DID document with the signing key in the correct VM slot.
        let doc = match signing_key_id {
            SigningKeyId::Active => scp_did::DidDocument::new_with_agent_key(
                did, &[0u8; 32], // identity key (not used for SCPID)
                &pk_bytes, &[0u8; 32], // pre-rotation commitment (not used for SCPID)
                None,
            ),
            SigningKeyId::Agent => scp_did::DidDocument::new_with_agent_key(
                did,
                &[0u8; 32],
                &[1u8; 32], // different active key
                &[0u8; 32],
                Some(&pk_bytes),
            ),
        };

        (response, doc)
    }

    #[tokio::test]
    async fn test_scpid_sign_then_verify_roundtrip_active() {
        let did = "did:dht:z6MkTest";
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(2)).unwrap();
        let (response, doc) = sign_and_build_doc(did, SigningKeyId::Active, &challenge).await;

        let resolver = TestDidResolver::with_document(doc);
        let auth = scpid_verify(&resolver, &response, &challenge)
            .await
            .expect("verification should succeed");

        assert_eq!(auth.did, did);
        assert_eq!(auth.signing_key_id, SigningKeyId::Active);
        assert_eq!(auth.signed_at, response.signed_at);
    }

    #[tokio::test]
    async fn test_scpid_sign_then_verify_roundtrip_agent() {
        let did = "did:dht:z6MkAgent";
        let challenge =
            scpid_challenge("https://agent-service.example.com", Duration::from_mins(1)).unwrap();
        let (response, doc) = sign_and_build_doc(did, SigningKeyId::Agent, &challenge).await;

        let resolver = TestDidResolver::with_document(doc);
        let auth = scpid_verify(&resolver, &response, &challenge)
            .await
            .expect("agent verification should succeed");

        assert_eq!(auth.did, did);
        assert_eq!(auth.signing_key_id, SigningKeyId::Agent);
    }

    #[tokio::test]
    async fn test_scpid_verify_nonce_mismatch() {
        let did = "did:dht:z6MkTest";
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(2)).unwrap();
        let (mut response, doc) = sign_and_build_doc(did, SigningKeyId::Active, &challenge).await;

        // Tamper with the nonce in the response.
        response.nonce[0] ^= 0xFF;

        let resolver = TestDidResolver::with_document(doc);
        let result = scpid_verify(&resolver, &response, &challenge).await;
        assert!(
            matches!(result, Err(ScpIdError::ChallengeExpired)),
            "expected ChallengeExpired for nonce mismatch, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_scpid_verify_audience_mismatch() {
        let did = "did:dht:z6MkTest";
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(2)).unwrap();
        let (mut response, doc) = sign_and_build_doc(did, SigningKeyId::Active, &challenge).await;

        // Tamper with the audience in the response.
        response.audience = "https://evil.com".to_owned();

        let resolver = TestDidResolver::with_document(doc);
        let result = scpid_verify(&resolver, &response, &challenge).await;
        assert!(
            matches!(result, Err(ScpIdError::AudienceMismatch)),
            "expected AudienceMismatch, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_scpid_verify_expired_challenge() {
        let did = "did:dht:z6MkTest";
        // Use a short but sufficient TTL so sign can succeed before expiry.
        let challenge = scpid_challenge("https://example.com", Duration::from_millis(50)).unwrap();
        let (response, doc) = sign_and_build_doc(did, SigningKeyId::Active, &challenge).await;

        // Wait for the challenge to expire.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let resolver = TestDidResolver::with_document(doc);
        let result = scpid_verify(&resolver, &response, &challenge).await;
        assert!(
            matches!(result, Err(ScpIdError::TimestampInvalid)),
            "expected TimestampInvalid for expired challenge, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_scpid_verify_signed_at_before_issued_at() {
        let did = "did:dht:z6MkTest";
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(2)).unwrap();
        let (mut response, doc) = sign_and_build_doc(did, SigningKeyId::Active, &challenge).await;

        // Set signed_at before issued_at.
        response.signed_at = challenge.issued_at - 1;

        let resolver = TestDidResolver::with_document(doc);
        let result = scpid_verify(&resolver, &response, &challenge).await;
        assert!(
            matches!(result, Err(ScpIdError::TimestampInvalid)),
            "expected TimestampInvalid for signed_at < issued_at, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_scpid_verify_signed_at_after_expires_at() {
        let did = "did:dht:z6MkTest";
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(2)).unwrap();
        let (mut response, doc) = sign_and_build_doc(did, SigningKeyId::Active, &challenge).await;

        // Set signed_at after expires_at.
        response.signed_at = challenge.expires_at + 1;

        let resolver = TestDidResolver::with_document(doc);
        let result = scpid_verify(&resolver, &response, &challenge).await;
        assert!(
            matches!(result, Err(ScpIdError::TimestampInvalid)),
            "expected TimestampInvalid for signed_at > expires_at, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_scpid_verify_did_not_found() {
        let did = "did:dht:z6MkTest";
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(2)).unwrap();
        let (response, _doc) = sign_and_build_doc(did, SigningKeyId::Active, &challenge).await;

        let resolver = TestDidResolver::not_found();
        let result = scpid_verify(&resolver, &response, &challenge).await;
        assert!(
            matches!(result, Err(ScpIdError::DidResolutionFailed(_))),
            "expected DidResolutionFailed, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_scpid_verify_did_resolution_error() {
        let did = "did:dht:z6MkTest";
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(2)).unwrap();
        let (response, _doc) = sign_and_build_doc(did, SigningKeyId::Active, &challenge).await;

        let resolver = TestDidResolver::failing();
        let result = scpid_verify(&resolver, &response, &challenge).await;
        assert!(
            matches!(result, Err(ScpIdError::DidResolutionFailed(_))),
            "expected DidResolutionFailed, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_scpid_verify_wrong_signing_key() {
        let did = "did:dht:z6MkTest";
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(2)).unwrap();
        let (response, _doc) = sign_and_build_doc(did, SigningKeyId::Active, &challenge).await;

        // Build a DID document with a DIFFERENT but VALID Ed25519
        // public key in the #active slot. `decode_multibase_key`
        // enforces curve-point validity, so the wrong key must still
        // decompress — otherwise the test trips that gate instead of
        // exercising the signature-mismatch path it's named for.
        let wrong_identity_pk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng)
            .verifying_key()
            .to_bytes();
        let wrong_active_pk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng)
            .verifying_key()
            .to_bytes();
        let wrong_doc = scp_did::DidDocument::new_with_agent_key(
            did,
            &wrong_identity_pk,
            &wrong_active_pk,
            &[0u8; 32],
            None,
        );

        let resolver = TestDidResolver::with_document(wrong_doc);
        let result = scpid_verify(&resolver, &response, &challenge).await;
        assert!(
            matches!(result, Err(ScpIdError::SignatureInvalid)),
            "expected SignatureInvalid for wrong key, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_scpid_verify_invalid_signature() {
        let did = "did:dht:z6MkTest";
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(2)).unwrap();
        let (mut response, doc) = sign_and_build_doc(did, SigningKeyId::Active, &challenge).await;

        // Tamper with the signature.
        response.signature[0] ^= 0xFF;

        let resolver = TestDidResolver::with_document(doc);
        let result = scpid_verify(&resolver, &response, &challenge).await;
        assert!(
            matches!(result, Err(ScpIdError::SignatureInvalid)),
            "expected SignatureInvalid for tampered signature, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_scpid_verify_key_not_in_authentication() {
        let did = "did:dht:z6MkTest";
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(2)).unwrap();
        let (response, mut doc) = sign_and_build_doc(did, SigningKeyId::Active, &challenge).await;

        // Remove #active from the authentication relationship.
        doc.authentication.clear();

        let resolver = TestDidResolver::with_document(doc);
        let result = scpid_verify(&resolver, &response, &challenge).await;
        assert!(
            matches!(result, Err(ScpIdError::KeyNotAuthorized)),
            "expected KeyNotAuthorized when key not in authentication, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_scpid_verify_vm_not_found() {
        let did = "did:dht:z6MkTest";
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(2)).unwrap();
        let (response, mut doc) = sign_and_build_doc(did, SigningKeyId::Active, &challenge).await;

        // Remove all verification methods except #0.
        doc.verification_method
            .retain(|vm| !vm.id.ends_with("#active"));

        let resolver = TestDidResolver::with_document(doc);
        let result = scpid_verify(&resolver, &response, &challenge).await;
        assert!(
            matches!(result, Err(ScpIdError::KeyNotAuthorized)),
            "expected KeyNotAuthorized when VM not found, got: {result:?}"
        );
    }

    /// A method declaring a key-agreement suite supplies no signing key.
    ///
    /// Decoding `publicKeyMultibase` alone cannot tell an Ed25519 signing key
    /// from an X25519 key-agreement key, so step 6 reads `type`. This function
    /// read no `type` before it delegated to `signing_key_for`.
    #[tokio::test]
    async fn test_scpid_verify_rejects_a_method_declaring_another_suite() {
        let did = "did:dht:z6MkTest";
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(2)).unwrap();
        let (response, mut doc) = sign_and_build_doc(did, SigningKeyId::Active, &challenge).await;

        let active_id = format!("{did}#active");
        for vm in &mut doc.verification_method {
            if vm.id == active_id {
                vm.method_type = "X25519KeyAgreementKey2020".to_owned();
            }
        }

        let resolver = TestDidResolver::with_document(doc);
        let result = scpid_verify(&resolver, &response, &challenge).await;
        assert!(
            matches!(result, Err(ScpIdError::KeyNotAuthorized)),
            "a key-agreement method must supply no signing key, got: {result:?}"
        );
    }

    /// A method naming another DID as controller supplies no key.
    ///
    /// SCP defines no delegation letting another DID sign as this one, so step
    /// 6 reads `controller`. This function read no `controller` before it
    /// delegated to `signing_key_for`.
    #[tokio::test]
    async fn test_scpid_verify_rejects_a_method_another_did_controls() {
        let did = "did:dht:z6MkTest";
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(2)).unwrap();
        let (response, mut doc) = sign_and_build_doc(did, SigningKeyId::Active, &challenge).await;

        let active_id = format!("{did}#active");
        for vm in &mut doc.verification_method {
            if vm.id == active_id {
                vm.controller = "did:dht:z6MkSomeoneElse".to_owned();
            }
        }

        let resolver = TestDidResolver::with_document(doc);
        let result = scpid_verify(&resolver, &response, &challenge).await;
        assert!(
            matches!(result, Err(ScpIdError::KeyNotAuthorized)),
            "a method another DID controls must supply no key, got: {result:?}"
        );
    }

    /// A resolver answering with a document that describes another DID is
    /// rejected, so authentication cannot report a caller as the holder of a
    /// method on one DID while reading a method on another.
    #[tokio::test]
    async fn test_scpid_verify_rejects_a_document_describing_another_did() {
        let did = "did:dht:z6MkTest";
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(2)).unwrap();
        let (response, mut doc) = sign_and_build_doc(did, SigningKeyId::Active, &challenge).await;

        // Rename the document and every method it identifies, so each method
        // still carries its own controller and only `doc.id` differs from the
        // DID a caller authenticated as.
        let other_did = "did:dht:z6MkSomeoneElse";
        for vm in &mut doc.verification_method {
            vm.id = vm.id.replace(did, other_did);
            vm.controller = other_did.to_owned();
        }
        doc.authentication = doc
            .authentication
            .iter()
            .map(|reference| reference.replace(did, other_did))
            .collect();
        doc.id = other_did.to_owned();

        let resolver = TestDidResolver::with_document(doc);
        let result = scpid_verify(&resolver, &response, &challenge).await;
        assert!(
            matches!(result, Err(ScpIdError::DidResolutionFailed(_))),
            "a document describing another DID must not authenticate, got: {result:?}"
        );
    }

    /// A `publicKeyMultibase` value that does not decode reports
    /// `DID_RESOLUTION_FAILED` rather than `KEY_NOT_AUTHORIZED`, because the
    /// document is unreadable rather than the method unauthorized. §3.11.4's
    /// error table separates the two, and an operator reads that separation in
    /// a server-side log.
    #[tokio::test]
    async fn test_scpid_verify_reports_a_decode_failure_as_a_resolution_failure() {
        let did = "did:dht:z6MkTest";
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(2)).unwrap();
        let (response, mut doc) = sign_and_build_doc(did, SigningKeyId::Active, &challenge).await;

        let active_id = format!("{did}#active");
        for vm in &mut doc.verification_method {
            if vm.id == active_id {
                // A multibase value that carries no `z` base58btc prefix.
                vm.public_key_multibase = "not-multibase".to_owned();
            }
        }

        let resolver = TestDidResolver::with_document(doc);
        let result = scpid_verify(&resolver, &response, &challenge).await;
        assert!(
            matches!(result, Err(ScpIdError::DidResolutionFailed(_))),
            "an undecodable key must report a resolution failure, got: {result:?}"
        );
    }

    /// A document carrying two methods under one identifier supplies no key.
    ///
    /// W3C DID Core §5.3.1 requires an identifier to be unique in a document,
    /// so array position must never decide which key verifies. This function
    /// selected the first of two matches before it delegated to
    /// `signing_key_for`, so an attacker who prepended a decoy `#active`
    /// entry chose the verifying key.
    #[tokio::test]
    async fn test_scpid_verify_rejects_a_repeated_identifier() {
        let did = "did:dht:z6MkTest";
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(2)).unwrap();
        let (response, mut doc) = sign_and_build_doc(did, SigningKeyId::Active, &challenge).await;

        let active_id = format!("{did}#active");
        let decoy = doc
            .verification_method
            .iter()
            .find(|vm| vm.id == active_id)
            .cloned()
            .expect("the signed document publishes #active");
        doc.verification_method.insert(0, decoy);

        let resolver = TestDidResolver::with_document(doc);
        let result = scpid_verify(&resolver, &response, &challenge).await;
        assert!(
            matches!(result, Err(ScpIdError::KeyNotAuthorized)),
            "a repeated identifier must supply no key, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_scpid_verify_wrong_protocol() {
        let did = "did:dht:z6MkTest";
        let challenge = scpid_challenge("https://example.com", Duration::from_mins(2)).unwrap();
        let (mut response, doc) = sign_and_build_doc(did, SigningKeyId::Active, &challenge).await;

        // Mutate the protocol field directly (deserialization would reject it,
        // but the field is pub so we can set it post-construction).
        response.protocol = "scpid/2.0".to_owned();

        let resolver = TestDidResolver::with_document(doc);
        let result = scpid_verify(&resolver, &response, &challenge).await;
        assert!(
            matches!(result, Err(ScpIdError::InvalidInput(ref msg)) if msg.contains("unsupported protocol")),
            "expected InvalidInput for wrong protocol version, got: {result:?}"
        );
    }
}
