//! SCPID — pure wire types and constants for DID authentication (§3.11).
//!
//! This module contains the protocol-level types for SCPID authentication:
//! - [`ScpIdChallenge`] — issued by the relying party
//! - [`ScpIdResponse`] — signed by the client
//! - [`ScpIdAuthentication`] — result of successful verification
//! - [`ScpIdError`] — error type for SCPID operations
//! - [`SCPID_PROTOCOL_VERSION`] / [`SCPID_DOMAIN_SEPARATOR`] — protocol constants
//!
//! Async functions (`scpid_sign`, `scpid_verify`, `scpid_challenge`) remain in
//! `scp-runtime` because they depend on `KeyCustody`, `DidResolver`, and system
//! time / CSPRNG.

use serde::{Deserialize, Serialize};

use scp_did::SigningKeyId;

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
pub mod hex_serde_32 {

    use serde::{self, Deserialize, Deserializer, Serializer};

    /// Serialize `[u8; 32]` as a 64-character lowercase hex string.
    ///
    /// # Errors
    ///
    /// Returns the serializer's error type on serialization failure.
    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    /// Deserialize a 64-character hex string into `[u8; 32]`.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error if the input is not valid hex or
    /// does not decode to exactly 32 bytes.
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
pub mod hex_serde_64 {

    use serde::{self, Deserialize, Deserializer, Serializer};

    /// Serialize `[u8; 64]` as a 128-character lowercase hex string.
    ///
    /// # Errors
    ///
    /// Returns the serializer's error type on serialization failure.
    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    /// Deserialize a 128-character hex string into `[u8; 64]`.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error if the input is not valid hex or
    /// does not decode to exactly 64 bytes.
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
// Protocol constants
// ---------------------------------------------------------------------------

/// The protocol version string included in challenge and response wire formats.
pub const SCPID_PROTOCOL_VERSION: &str = "scpid/1.0";

/// Domain separator for SCPID signed content (§3.11.3, §9.18.2).
pub const SCPID_DOMAIN_SEPARATOR: &str = "SCP-DID-AUTH-V1:";
