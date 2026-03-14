//! SCPID — DID authentication for external services (§3.11).
//!
//! Provides wire types and challenge generation for the SCPID protocol,
//! which lets DID holders authenticate to relying parties outside of SCP
//! contexts. Analogous to "Sign in with Ethereum" (EIP-4361) but simpler:
//! no blockchain state, no gas — the DID document is the identity provider.
//!
//! This module implements:
//! - [`ScpIdChallenge`] — issued by the relying party
//! - [`ScpIdResponse`] — signed by the client
//! - [`ScpIdAuthentication`] — result of successful verification
//! - [`scpid_challenge`] — challenge generation with CSPRNG nonce
//!
//! Signing (`scpid_sign`) and verification (`scpid_verify`) require async
//! key custody / DID resolution and live in separate modules.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::identity::SigningKeyId;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from SCPID authentication operations.
///
/// Error codes follow the `SCP-IDENT-103x` range defined in §3.11.4.
#[derive(Debug, thiserror::Error)]
pub enum ScpIdError {
    /// Nonce unknown, mismatched, or expired.
    #[error("challenge expired or nonce mismatch (SCP-IDENT-1030)")]
    ChallengeExpired,

    /// Audience URI does not match the issued challenge.
    #[error("audience mismatch (SCP-IDENT-1031)")]
    AudienceMismatch,

    /// `signed_at` outside challenge window or challenge expired.
    #[error("timestamp invalid (SCP-IDENT-1032)")]
    TimestampInvalid,

    /// DID resolution failed (DHT lookup or relay query).
    #[error("DID resolution failed (SCP-IDENT-1033): {0}")]
    DidResolutionFailed(String),

    /// `signing_key_id` not `#active`/`#agent` or not in `authentication`.
    #[error("signing key not authorized (SCP-IDENT-1034)")]
    KeyNotAuthorized,

    /// Ed25519 signature verification failed.
    #[error("signature invalid (SCP-IDENT-1035)")]
    SignatureInvalid,

    /// DID document older than 300 seconds and refresh failed.
    #[error("DID document stale (SCP-IDENT-1036)")]
    DidDocumentStale,

    /// Key custody or signing operation failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// Input validation failure (TTL too large, audience too long, etc.).
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

// ---------------------------------------------------------------------------
// Hex serde helpers
// ---------------------------------------------------------------------------

/// Serde helper for `[u8; 32]` fields serialized as 64-char lowercase hex.
mod hex_serde_32 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| serde::de::Error::custom("expected exactly 32 bytes (64 hex chars)"))
    }
}

/// Serde helper for `[u8; 64]` fields serialized as 128-char lowercase hex.
mod hex_serde_64 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        <[u8; 64]>::try_from(bytes.as_slice())
            .map_err(|_| serde::de::Error::custom("expected exactly 64 bytes (128 hex chars)"))
    }
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// SCPID challenge issued by a relying party (§3.11.2).
///
/// Contains a CSPRNG nonce, audience binding, and validity window.
/// Serialized as JSON for transport; the relying party chooses the
/// transport (HTTP, WebSocket, QR code, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScpIdChallenge {
    /// Protocol identifier and version: `"scpid/1.0"`.
    pub protocol: String,

    /// 32-byte CSPRNG nonce for replay prevention (hex-encoded on wire).
    #[serde(with = "hex_serde_32")]
    pub nonce: [u8; 32],

    /// URI identifying the relying party (e.g., `"https://app.example.com"`).
    pub audience: String,

    /// Unix timestamp (seconds) when the challenge was created.
    pub issued_at: u64,

    /// Unix timestamp (seconds) when the challenge expires.
    pub expires_at: u64,
}

/// SCPID response signed by the client (§3.11.3).
///
/// Contains the client's DID, signing key selection, echoed challenge
/// fields, and the Ed25519 signature over the canonical hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScpIdResponse {
    /// Protocol identifier and version: `"scpid/1.0"`.
    pub protocol: String,

    /// The signer's DID (e.g., `"did:dht:z6Mk..."`).
    pub did: String,

    /// Which verification method signed: `#active` (human) or `#agent` (agent).
    pub signing_key_id: SigningKeyId,

    /// Echo of the challenge nonce (hex-encoded on wire).
    #[serde(with = "hex_serde_32")]
    pub nonce: [u8; 32],

    /// Echo of the challenge audience URI.
    pub audience: String,

    /// Unix timestamp (seconds) when the client signed.
    pub signed_at: u64,

    /// Ed25519 signature over the canonical hash (hex-encoded on wire).
    #[serde(with = "hex_serde_64")]
    pub signature: [u8; 64],
}

/// Result of a successful SCPID verification (§3.11.4 step 11).
///
/// Returned by `scpid_verify` when all 11 verification steps pass.
/// Does not include the `protocol` field — that is a wire-format concern,
/// not an authentication result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScpIdAuthentication {
    /// The authenticated DID.
    pub did: String,

    /// Which verification method produced the signature.
    pub signing_key_id: SigningKeyId,

    /// Unix timestamp (seconds) when the client signed.
    pub signed_at: u64,
}

// ---------------------------------------------------------------------------
// Protocol constant
// ---------------------------------------------------------------------------

/// The protocol version string included in challenge and response wire formats.
pub const SCPID_PROTOCOL_VERSION: &str = "scpid/1.0";

/// Maximum TTL for an SCPID challenge (§3.11.2: MUST NOT exceed 300 seconds).
const MAX_TTL_SECS: u64 = 300;

/// Maximum audience string length in bytes.
const MAX_AUDIENCE_BYTES: usize = 2048;

// ---------------------------------------------------------------------------
// Challenge generation
// ---------------------------------------------------------------------------

/// Generate an SCPID challenge for the given audience (§3.11.8).
///
/// Generates a 32-byte CSPRNG nonce, sets `issued_at` to the current time,
/// and computes `expires_at` from the TTL.
///
/// # Errors
///
/// Returns [`ScpIdError::InvalidInput`] if:
/// - `ttl` exceeds 300 seconds (§3.11.2 constraint)
/// - `audience` exceeds 2048 bytes
pub fn scpid_challenge(audience: &str, ttl: Duration) -> Result<ScpIdChallenge, ScpIdError> {
    if ttl.as_secs() > MAX_TTL_SECS || (ttl.as_secs() == MAX_TTL_SECS && ttl.subsec_nanos() > 0) {
        return Err(ScpIdError::InvalidInput(
            "TTL exceeds 300 seconds".to_owned(),
        ));
    }

    if audience.len() > MAX_AUDIENCE_BYTES {
        return Err(ScpIdError::InvalidInput(
            "audience exceeds 2048 bytes".to_owned(),
        ));
    }

    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ScpIdError::InvalidInput(format!("system clock error: {e}")))?
        .as_secs();

    let expires_at = issued_at + ttl.as_secs();

    Ok(ScpIdChallenge {
        protocol: SCPID_PROTOCOL_VERSION.to_owned(),
        nonce,
        audience: audience.to_owned(),
        issued_at,
        expires_at,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::crypto::canonical::{CanonicalField, canonical_hash};

    #[test]
    fn test_challenge_generation() {
        let challenge = scpid_challenge("https://example.com", Duration::from_secs(60))
            .expect("challenge generation should succeed");

        assert_eq!(challenge.protocol, "scpid/1.0");
        assert_eq!(challenge.audience, "https://example.com");
        assert_eq!(challenge.expires_at, challenge.issued_at + 60);
        // Nonce should not be all zeros (overwhelmingly unlikely from CSPRNG).
        assert_ne!(challenge.nonce, [0u8; 32]);
    }

    #[test]
    fn test_challenge_json_roundtrip() {
        let challenge = scpid_challenge("https://example.com", Duration::from_secs(120))
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
            signed_at: 1_709_654_400,
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
        let result = scpid_challenge("https://example.com", Duration::from_secs(300));
        assert!(result.is_ok());
    }

    #[test]
    fn test_ttl_boundary_300_plus_nanos() {
        // 300 seconds + 1 nanosecond should fail.
        let result = scpid_challenge(
            "https://example.com",
            Duration::from_secs(300) + Duration::from_nanos(1),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_audience_length_rejection() {
        let long_audience = "x".repeat(2049);
        let result = scpid_challenge(&long_audience, Duration::from_secs(60));
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
        let result = scpid_challenge(&audience, Duration::from_secs(60));
        assert!(result.is_ok());
    }

    #[test]
    fn test_protocol_field() {
        let challenge = scpid_challenge("https://example.com", Duration::from_secs(60))
            .expect("challenge generation should succeed");
        assert_eq!(challenge.protocol, "scpid/1.0");
    }

    #[test]
    fn test_invalid_protocol_not_validated_at_deser() {
        // The protocol field is not validated at deserialization time.
        // Validation happens in scpid_sign / scpid_verify (§3.11.5:
        // "Relying parties MUST reject responses with unrecognized protocol versions").
        let json = r#"{
            "protocol": "wrong/2.0",
            "nonce": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "audience": "https://example.com",
            "issued_at": 1709654400,
            "expires_at": 1709654700
        }"#;
        let challenge: ScpIdChallenge =
            serde_json::from_str(json).expect("should deserialize despite wrong protocol");
        assert_eq!(challenge.protocol, "wrong/2.0");
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
        //   signed_at      = 1709654400
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
        let signed_at: u64 = 1_709_654_400;

        let hash = canonical_hash(
            "SCP-DID-AUTH-V1:",
            &[
                CanonicalField::VarBytes(did.as_bytes()),
                CanonicalField::VarBytes(signing_key_id.as_fragment().as_bytes()),
                CanonicalField::Fixed32(&nonce),
                CanonicalField::VarBytes(audience.as_bytes()),
                CanonicalField::U64(signed_at),
            ],
        );

        // Independently computed expected value (verified with Python):
        //   import hashlib, struct
        //   def lp(b): return struct.pack('>I', len(b)) + b
        //   nonce = bytes([0xAA] * 32)
        //   data = (b'SCP-DID-AUTH-V1:'
        //     + lp(b'did:dht:z6MkTest')
        //     + lp(b'#active')
        //     + nonce
        //     + lp(b'https://example.com')
        //     + struct.pack('>Q', 1709654400))
        //   print(hashlib.sha256(data).hexdigest())
        assert_eq!(
            hex::encode(hash),
            "c6a90aa317513f9c8c683ba5bf1ad8c3296edacc68ec5a6ee6ffffedab46c8b7"
        );
    }
}
