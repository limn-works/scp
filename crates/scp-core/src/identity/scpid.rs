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

use crate::crypto::canonical::{CanonicalField, canonical_hash};
use crate::identity::SigningKeyId;
use scp_platform::traits::{KeyCustody, KeyHandle};

// ---------------------------------------------------------------------------
// Protocol-field deserialization validator
// ---------------------------------------------------------------------------

/// Deserialize the `protocol` field, rejecting values that are not
/// [`SCPID_PROTOCOL_VERSION`].  Used via `#[serde(deserialize_with)]` on
/// both [`ScpIdChallenge`] and [`ScpIdResponse`].
fn deserialize_protocol<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s != SCPID_PROTOCOL_VERSION {
        return Err(serde::de::Error::custom(format!(
            "unsupported SCPID protocol version: {s}, expected {SCPID_PROTOCOL_VERSION}"
        )));
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from SCPID authentication operations.
///
/// Error codes follow the `SCP-IDENT-1030` through `SCP-IDENT-1038` range defined in §3.11.4.
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
    #[error("signing failed (SCP-IDENT-1037): {0}")]
    SigningFailed(String),

    /// Input validation failure (TTL too large, audience too long, etc.).
    #[error("invalid input (SCP-IDENT-1038): {0}")]
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
    /// Rejected on deserialization if not equal to [`SCPID_PROTOCOL_VERSION`].
    #[serde(deserialize_with = "deserialize_protocol")]
    pub protocol: String,

    /// 32-byte CSPRNG nonce for replay prevention (hex-encoded on wire).
    #[serde(with = "hex_serde_32")]
    pub nonce: [u8; 32],

    /// URI identifying the relying party (e.g., `"https://app.example.com"`).
    pub audience: String,

    /// Unix timestamp (milliseconds) when the challenge was created (§3.11.2).
    pub issued_at: u64,

    /// Unix timestamp (milliseconds) when the challenge expires (§3.11.2).
    pub expires_at: u64,
}

/// SCPID response signed by the client (§3.11.3).
///
/// Contains the client's DID, signing key selection, echoed challenge
/// fields, and the Ed25519 signature over the canonical hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScpIdResponse {
    /// Protocol identifier and version: `"scpid/1.0"`.
    /// Rejected on deserialization if not equal to [`SCPID_PROTOCOL_VERSION`].
    #[serde(deserialize_with = "deserialize_protocol")]
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

    /// Unix timestamp (milliseconds) when the client signed (§3.11.3).
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

    /// Unix timestamp (milliseconds) when the client signed (§3.11.3).
    pub signed_at: u64,
}

// ---------------------------------------------------------------------------
// Protocol constant
// ---------------------------------------------------------------------------

/// The protocol version string included in challenge and response wire formats.
pub const SCPID_PROTOCOL_VERSION: &str = "scpid/1.0";

/// Domain separator for SCPID signed content (§3.11.3, §9.18.2).
pub const SCPID_DOMAIN_SEPARATOR: &str = "SCP-DID-AUTH-V1:";

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
/// to the current time in milliseconds.
///
/// # Errors
///
/// Returns [`ScpIdError::ChallengeExpired`] if the challenge has already
/// expired. Returns [`ScpIdError::InvalidInput`] if the protocol version
/// is unsupported or the system clock is before the Unix epoch. Returns
/// [`ScpIdError::SigningFailed`] if the custody operation fails.
pub async fn scpid_sign(
    custody: &impl KeyCustody,
    signing_key: &KeyHandle,
    did: &str,
    signing_key_id: SigningKeyId,
    challenge: &ScpIdChallenge,
) -> Result<ScpIdResponse, ScpIdError> {
    // Reject empty DID (consistent with audience validation in scpid_challenge).
    if did.is_empty() {
        return Err(ScpIdError::InvalidInput("DID must not be empty".to_owned()));
    }

    // Reject expired challenges (fail fast).
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

    let signed_at = now_ms;

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
    );

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
        assert_eq!(challenge.expires_at, challenge.issued_at + 60_000);
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
        let result = scpid_challenge("https://example.com", Duration::from_secs(300));
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
        let result = scpid_challenge("", Duration::from_secs(60));
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

        let challenge = scpid_challenge("https://example.com", Duration::from_secs(120)).unwrap();

        let response = scpid_sign(
            &custody,
            &handle,
            "did:dht:z6MkTest",
            SigningKeyId::Active,
            &challenge,
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
        );

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
            scpid_challenge("https://agent-service.example.com", Duration::from_secs(60)).unwrap();

        let response = scpid_sign(
            &custody,
            &handle,
            "did:dht:z6MkAgent",
            SigningKeyId::Agent,
            &challenge,
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
        );

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
        )
        .await;

        assert!(
            matches!(result, Err(ScpIdError::ChallengeExpired)),
            "expected ChallengeExpired, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_scpid_sign_empty_did_rejected() {
        use scp_platform::KeyType;
        use scp_platform::testing::InMemoryKeyCustody;

        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let challenge = scpid_challenge("https://example.com", Duration::from_secs(60)).unwrap();

        let result = scpid_sign(&custody, &handle, "", SigningKeyId::Active, &challenge).await;
        assert!(
            matches!(result, Err(ScpIdError::InvalidInput(ref msg)) if msg.contains("DID must not be empty")),
            "expected InvalidInput with empty DID message, got: {result:?}"
        );
    }
}
