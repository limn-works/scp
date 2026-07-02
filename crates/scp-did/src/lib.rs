#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! The DID data model for SCP — the single wasm-safe home for identity types.
//!
//! This crate owns the DID **data model**: the [`DID`] newtype, the
//! [`SigningKeyId`] enum, [`extract_public_key_from_did`], and the W3C DID
//! Document types ([`DidDocument`], [`VerificationMethod`], rotation/migration
//! proofs, and the key-custody/identity-link [`attestation`] types). These are
//! pure synchronous value types with zero async dependencies, so they compile
//! to `wasm32-unknown-unknown` for the in-browser SCP client (ADR-057).
//!
//! The **native** identity subsystem — DHT resolution, publication, the
//! `DidMethod` trait, and lifecycle management — lives in `scp-identity`, which
//! imports this data model. See ADR-057's Amendment (2026-06-30) for the crate
//! topology.

pub mod attestation;
pub mod document;

pub use document::{
    DidDocument, DidError, DidRotationEvent, MigrationProof, PreRotationProof, Service,
    VerificationMethod, decode_multibase_key,
};

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// DID newtype (SCP-187)
// ---------------------------------------------------------------------------

/// Decentralized Identifier string (e.g., `"did:dht:z6Mk..."`).
///
/// A newtype wrapper around `String` providing type safety across the SCP
/// codebase. Replaces the independent `type DID = String` aliases that were
/// previously scattered across modules.
///
/// Implements `Deref<Target = str>` for ergonomic access to `&str` methods,
/// `Borrow<str>` for `HashMap`/`HashSet` lookups with `&str` keys, and
/// `#[serde(transparent)]` for zero-overhead JSON serialization.
///
/// See SCP-187 in `.docs/prds/prd.json`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DID(pub String);

impl std::ops::Deref for DID {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for DID {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for DID {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for DID {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl PartialEq<str> for DID {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for DID {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for DID {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl std::borrow::Borrow<str> for DID {
    fn borrow(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// DID public key extraction
// ---------------------------------------------------------------------------

/// Extracts the Ed25519 public key bytes from a DID string.
///
/// Supports `did:dht:z<z-base-32>` format (production). The `did:key:<hex>`
/// test convenience format is only accepted when compiled with `#[cfg(test)]`
/// or the `testing` feature to prevent non-standard DID acceptance in release
/// builds. See: <https://github.com/limn-works/scp/issues/128>
///
/// # Errors
///
/// Returns an error string if the DID format is unsupported,
/// if z-base-32/hex decoding fails, or if the decoded key is not exactly
/// 32 bytes.
pub fn extract_public_key_from_did(did: &str) -> Result<[u8; 32], String> {
    // Support did:dht:z<z-base-32> format.
    if let Some(suffix) = did.strip_prefix("did:dht:z") {
        let decoded = zbase32::decode(suffix)
            .map_err(|_| format!("z-base-32 decode failed for DID: {did}"))?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|v: Vec<u8>| format!("DID public key must be 32 bytes, got {}", v.len()))?;
        return Ok(bytes);
    }

    // did:key:{hex} is a non-standard test convenience. Gated behind the
    // `testing` feature (or #[cfg(test)]) to prevent acceptance in release
    // builds. See: https://github.com/limn-works/scp/issues/128
    #[cfg(any(test, feature = "testing"))]
    if let Some(hex_str) = did.strip_prefix("did:key:") {
        let decoded = hex::decode(hex_str).map_err(|e| format!("hex decode error: {e}"))?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|v: Vec<u8>| format!("DID public key must be 32 bytes, got {}", v.len()))?;
        return Ok(bytes);
    }

    Err(format!("unsupported DID format: {did}"))
}

/// Constructs a `did:dht:z<z-base-32>` DID from a 32-byte Ed25519 public key.
///
/// This is the inverse of [`extract_public_key_from_did`] for the `did:dht`
/// method and the single canonical place to encode a `did:dht` from a raw key,
/// replacing ad-hoc `format!("did:dht:z{}", zbase32::encode(..))` call sites.
/// It is the production encoding and needs no feature gate.
#[must_use]
pub fn did_dht_from_public_key(public_key: &[u8; 32]) -> DID {
    DID(format!("did:dht:z{}", zbase32::encode(public_key)))
}

// ---------------------------------------------------------------------------
// SigningKeyId (ADR-039)
// ---------------------------------------------------------------------------

/// Identifies which verification method signed an action.
///
/// Used in `ScpCredential`, `InnerEnvelope`, and `SenderKeyEpochAdvance` to
/// indicate whether the `#active` (human) or `#agent` (agent software) signing
/// key produced a signature. Verifiers resolve the correct public key from the
/// sender's DID document using this field.
///
/// Wire-serializes as `"#active"` / `"#agent"` for JSON interoperability.
///
/// See ADR-039 in `.docs/adrs/phase-1.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigningKeyId {
    /// The human's active signing key (`#active` verification method).
    Active,
    /// The agent's signing key (`#agent` verification method).
    Agent,
}

impl SigningKeyId {
    /// Returns the full DID document fragment reference (e.g., `"#active"` or `"#agent"`).
    ///
    /// This is the canonical string representation used in serialization,
    /// display, and hash preimages.
    #[must_use]
    pub const fn as_fragment(&self) -> &'static str {
        match self {
            Self::Active => "#active",
            Self::Agent => "#agent",
        }
    }

    /// Alias for [`as_fragment`](Self::as_fragment).
    #[must_use]
    pub const fn fragment_ref(&self) -> &'static str {
        self.as_fragment()
    }

    /// Returns the bare fragment name without the `#` prefix (e.g., `"active"` or `"agent"`).
    #[must_use]
    pub const fn fragment(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Agent => "agent",
        }
    }

    /// Returns the canonical byte representation for inclusion in hash
    /// preimages.
    ///
    /// This is the UTF-8 encoding of [`as_fragment`](Self::as_fragment).
    #[must_use]
    pub const fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::Active => b"#active",
            Self::Agent => b"#agent",
        }
    }

    /// Parses a DID document verification-method fragment reference
    /// (`"#active"` / `"#agent"`) into the corresponding [`SigningKeyId`].
    ///
    /// The exact inverse of [`as_fragment`](Self::as_fragment). Returns `None`
    /// for any unrecognized fragment. This is the single canonical string →
    /// enum decoder; the `Deserialize` impl and every kid-parsing call site
    /// should route through it so the permitted set stays closed in one place.
    #[must_use]
    pub fn from_fragment(fragment: &str) -> Option<Self> {
        match fragment {
            "#active" => Some(Self::Active),
            "#agent" => Some(Self::Agent),
            _ => None,
        }
    }
}

impl Default for SigningKeyId {
    /// Defaults to [`SigningKeyId::Active`] for backward compatibility with
    /// envelopes and protocol messages created before agent binding (ADR-039).
    fn default() -> Self {
        Self::Active
    }
}

impl fmt::Display for SigningKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_fragment())
    }
}

impl Serialize for SigningKeyId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_fragment())
    }
}

impl<'de> Deserialize<'de> for SigningKeyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_fragment(&s).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "unknown SigningKeyId: {s}, expected \"#active\" or \"#agent\""
            ))
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::clone_on_copy)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // SigningKeyId tests (moved from scp-identity)
    // -----------------------------------------------------------------------

    #[test]
    fn signing_key_id_fragment() {
        assert_eq!(SigningKeyId::Active.fragment(), "active");
        assert_eq!(SigningKeyId::Agent.fragment(), "agent");
    }

    #[test]
    fn signing_key_id_fragment_ref() {
        assert_eq!(SigningKeyId::Active.fragment_ref(), "#active");
        assert_eq!(SigningKeyId::Agent.fragment_ref(), "#agent");
    }

    #[test]
    fn signing_key_id_from_fragment_roundtrips_and_rejects_unknown() {
        // Exact inverse of `as_fragment` for the two known verification methods.
        for kid in [SigningKeyId::Active, SigningKeyId::Agent] {
            assert_eq!(SigningKeyId::from_fragment(kid.as_fragment()), Some(kid));
        }
        // Unrecognized fragments (including the bare names without `#`) are
        // rejected — the permitted set is closed.
        assert_eq!(SigningKeyId::from_fragment("active"), None);
        assert_eq!(SigningKeyId::from_fragment("agent"), None);
        assert_eq!(SigningKeyId::from_fragment("#0"), None);
        assert_eq!(SigningKeyId::from_fragment("#unknown"), None);
        assert_eq!(SigningKeyId::from_fragment(""), None);
    }

    #[test]
    fn signing_key_id_display() {
        assert_eq!(format!("{}", SigningKeyId::Active), "#active");
        assert_eq!(format!("{}", SigningKeyId::Agent), "#agent");
    }

    #[test]
    fn signing_key_id_serialize() {
        let active_json = serde_json::to_string(&SigningKeyId::Active).unwrap();
        assert_eq!(active_json, "\"#active\"");

        let agent_json = serde_json::to_string(&SigningKeyId::Agent).unwrap();
        assert_eq!(agent_json, "\"#agent\"");
    }

    #[test]
    fn signing_key_id_deserialize() {
        let active: SigningKeyId = serde_json::from_str("\"#active\"").unwrap();
        assert_eq!(active, SigningKeyId::Active);

        let agent: SigningKeyId = serde_json::from_str("\"#agent\"").unwrap();
        assert_eq!(agent, SigningKeyId::Agent);
    }

    #[test]
    fn signing_key_id_deserialize_unknown() {
        let result = serde_json::from_str::<SigningKeyId>("\"#unknown\"");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown SigningKeyId"),
            "error should mention unknown SigningKeyId, got: {err}"
        );
    }

    #[test]
    fn signing_key_id_roundtrip() {
        for key_id in [SigningKeyId::Active, SigningKeyId::Agent] {
            let json = serde_json::to_string(&key_id).unwrap();
            let parsed: SigningKeyId = serde_json::from_str(&json).unwrap();
            assert_eq!(key_id, parsed);
        }
    }

    #[test]
    fn signing_key_id_equality() {
        assert_eq!(SigningKeyId::Active, SigningKeyId::Active);
        assert_eq!(SigningKeyId::Agent, SigningKeyId::Agent);
        assert_ne!(SigningKeyId::Active, SigningKeyId::Agent);
    }

    #[test]
    fn signing_key_id_copy_clone() {
        let original = SigningKeyId::Agent;
        let copied = original;
        let cloned = original.clone();
        assert_eq!(original, copied);
        assert_eq!(original, cloned);
    }

    // -----------------------------------------------------------------------
    // SigningKeyId JSON known values
    // -----------------------------------------------------------------------

    #[test]
    fn signing_key_id_json_known_values() {
        assert_eq!(
            serde_json::to_string(&SigningKeyId::Active).unwrap(),
            "\"#active\""
        );
        assert_eq!(
            serde_json::to_string(&SigningKeyId::Agent).unwrap(),
            "\"#agent\""
        );
    }

    // -----------------------------------------------------------------------
    // SigningKeyId MessagePack roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn signing_key_id_msgpack_roundtrip() {
        for key_id in [SigningKeyId::Active, SigningKeyId::Agent] {
            let bytes = rmp_serde::to_vec(&key_id).unwrap();
            let parsed: SigningKeyId = rmp_serde::from_slice(&bytes).unwrap();
            assert_eq!(key_id, parsed);
        }
    }

    // -----------------------------------------------------------------------
    // DID tests
    // -----------------------------------------------------------------------

    #[test]
    fn did_transparent_serde_roundtrip() {
        let did = DID("did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_owned());
        let json = serde_json::to_string(&did).unwrap();
        // Transparent serde: serializes as a plain string, not {"0":"..."}
        assert_eq!(
            json,
            "\"did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK\""
        );
        let parsed: DID = serde_json::from_str(&json).unwrap();
        assert_eq!(did, parsed);
    }

    #[test]
    fn did_msgpack_roundtrip() {
        let did = DID("did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_owned());
        let bytes = rmp_serde::to_vec(&did).unwrap();
        let parsed: DID = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(did, parsed);
    }

    #[test]
    fn did_deref_and_display() {
        let did = DID("did:dht:test".to_owned());
        // Deref to &str
        assert_eq!(&*did, "did:dht:test");
        // AsRef<str>
        assert_eq!(did.as_ref(), "did:dht:test");
        // Display
        assert_eq!(format!("{did}"), "did:dht:test");
    }

    #[test]
    fn did_from_conversions() {
        let from_string = DID::from("did:dht:abc".to_owned());
        let from_str = DID::from("did:dht:abc");
        assert_eq!(from_string, from_str);
    }

    #[test]
    fn did_partial_eq_variants() {
        let did = DID("did:dht:xyz".to_owned());
        assert_eq!(did, *"did:dht:xyz");
        assert_eq!(did, "did:dht:xyz");
        assert_eq!(did, "did:dht:xyz".to_owned());
    }

    #[test]
    fn did_borrow_str() {
        use std::borrow::Borrow;
        let did = DID("did:dht:borrow".to_owned());
        let borrowed: &str = did.borrow();
        assert_eq!(borrowed, "did:dht:borrow");
    }

    // -----------------------------------------------------------------------
    // extract_public_key_from_did tests
    // -----------------------------------------------------------------------

    #[test]
    fn extract_public_key_from_valid_did_dht() {
        // Roundtrip: encode a known 32-byte key as z-base-32, wrap in
        // did:dht:z prefix, extract, compare.
        let key: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let encoded = zbase32::encode(&key);
        let did = format!("did:dht:z{encoded}");
        let extracted = extract_public_key_from_did(&did).unwrap();
        assert_eq!(extracted, key);
    }

    #[test]
    fn extract_public_key_rejects_invalid_prefix() {
        let result = extract_public_key_from_did("did:web:example.com");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("unsupported DID format"),
            "expected unsupported DID format error, got: {err}"
        );
    }

    #[test]
    fn extract_public_key_rejects_invalid_zbase32() {
        // 'l' is not valid z-base-32
        let result = extract_public_key_from_did("did:dht:z!!!invalid!!!");
        assert!(result.is_err());
    }

    #[test]
    fn extract_public_key_rejects_wrong_length() {
        // Encode only 16 bytes (not 32)
        let short_key: [u8; 16] = [0x42; 16];
        let encoded = zbase32::encode(&short_key);
        let did = format!("did:dht:z{encoded}");
        let result = extract_public_key_from_did(&did);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("32 bytes"),
            "expected 32-byte length error, got: {err}"
        );
    }

    // did:key:{hex} is only available under #[cfg(test)] or feature = "testing"
    #[test]
    fn extract_public_key_from_did_key_hex() {
        let key: [u8; 32] = [0xAB; 32];
        let hex_str = hex::encode(key);
        let did = format!("did:key:{hex_str}");
        let extracted = extract_public_key_from_did(&did).unwrap();
        assert_eq!(extracted, key);
    }

    #[test]
    fn extract_public_key_from_did_key_invalid_hex() {
        let result = extract_public_key_from_did("did:key:not-valid-hex");
        assert!(result.is_err());
    }
}
