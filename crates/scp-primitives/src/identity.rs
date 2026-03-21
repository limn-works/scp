//! Identity primitives shared across the SCP workspace.
//!
//! This module defines the [`DID`] newtype and [`SigningKeyId`] enum — pure
//! value types with zero async dependencies. They live in `scp-primitives`
//! (the leaf crate) so that `scp-event-log` and future crates like
//! `scp-protocol` can use them without pulling in `scp-identity`'s tokio
//! dependency.
//!
//! `scp-identity` re-exports both types for backward compatibility.

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
        match s.as_str() {
            "#active" => Ok(Self::Active),
            "#agent" => Ok(Self::Agent),
            other => Err(serde::de::Error::custom(format!(
                "unknown SigningKeyId: {other}, expected \"#active\" or \"#agent\""
            ))),
        }
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
}
