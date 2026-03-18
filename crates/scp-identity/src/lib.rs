#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Decentralized identity (DID) management for SCP.
//!
//! This module implements decentralized identity (DID) creation, verification,
//! and document management for the SCP protocol. The primary DID method is
//! `did:dht`, which uses the `BitTorrent` Mainline DHT for resolution and the
//! Ed25519 public key as the self-certifying identifier.
//!
//! # Architecture
//!
//! - [`ScpIdentity`] — The identity handle containing key handles, DID string,
//!   and pre-rotation commitment.
//! - [`DidMethod`] — Abstract trait enabling DID method swaps (e.g., `did:web`
//!   fallback) without changing calling code.
//! - [`DidDht`] — The `did:dht` implementation of [`DidMethod`].
//! - [`DidDocument`] — W3C DID Document JSON-LD construction and serialization.
//!
//! # Key Separation
//!
//! SCP separates four key roles (three verification methods per ADR-039):
//! 1. **Identity Key (`#0`)** — Derives the DID string. Highest-security custody
//!    (hardware-backed). Used only for DID document updates. Never rotates.
//! 2. **Active Signing Key (`#active`)** — Human's operational key. Used for MLS,
//!    envelopes, UCANs. Rotatable via Layer 1 rotation.
//! 3. **Agent Signing Key (`#agent`)** — Optional. Software-held key for autonomous
//!    agent operations. Rotatable independently. Generated only when agent
//!    delegation is needed. See ADR-039.
//! 4. **Pre-Rotation Key** — Cold/offline custody. Provides the commitment
//!    for identity migration.
//!
//! See ADR-003 and ADR-039 in `.docs/adrs/phase-1.md` for the full design.

pub mod attestation;
pub mod cache;
pub mod dht;
pub mod dht_client;
pub mod document;
pub mod republish;
pub mod resolution;
pub mod resolver;

pub use attestation::{
    AttestationPlatform, IdentityLinkPlatform, KeyCustodyModel, Platform, PlatformAttestation,
    ScpIdentityLinkService, ScpKeyCustodyAttestation, UnknownPlatformError,
};
pub use cache::{DidCache, DidResolutionResult, Staleness};
pub use dht::{
    DidDht, InMemorySequenceStore, PostResolveHook, SequenceStore, decode_multibase_key,
    did_from_ed25519_public_key, extract_public_key, verify_bep44_signature, verify_migration,
    verify_self_certification,
};
// SigningKeyId is defined in this module and exported directly.
pub use dht_client::{DhtClient, InMemoryDhtClient};
#[cfg(feature = "production-dht")]
pub use dht_client::{PkarrDhtClient, PkarrDhtClientBuilder};
pub use document::{DidDocument, DidRotationEvent, MigrationProof, PreRotationProof};
pub use republish::RepublishManager;
pub use resolution::{
    InMemoryRelayQuerier, RelayQuerier, RelayQueryRecord, RelayResolveResult, did_routing_id,
    relay_resolve,
};
pub use resolver::{
    DidResolver, DualLayerHealingPublisher, DualLayerResolver, HealingPublisher, MultiRelayQuerier,
    NoOpHealer, NoOpRelayQuerier, ResolutionSource, ResolvedDidDocument, StaleLayer,
};

use serde::{Deserialize, Serialize};
use std::fmt;

use scp_platform::traits::{KeyCustody, KeyHandle};

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

impl std::fmt::Display for DID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

/// An SCP identity containing the DID string, key handles, and pre-rotation
/// commitment.
///
/// Key material never leaves the [`KeyCustody`] boundary — only opaque
/// [`KeyHandle`]s are stored here. The pre-rotation commitment is the SHA-256
/// hash of the pre-rotation key's public key bytes, published in the DID
/// document as a `PreRotationCommitment` service.
///
/// See ADR-003 acceptance criterion 1 and ADR-039 for the full construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScpIdentity {
    /// `did:dht` Identity Key (`#0`). Derives the DID string. Stored in
    /// highest-security custody (Secure Enclave, HSM). Used ONLY for DID
    /// document updates and signing pre-rotation commitments. NEVER for MLS,
    /// envelopes, or UCANs.
    pub identity_key: KeyHandle,

    /// Current Active Signing Key (`#active`). A verification method in the
    /// DID document. Used for MLS credentials, inner envelope signatures, UCAN
    /// issuance. Rotatable via `rotate_active_key` (DID string stays the same).
    pub active_signing_key: KeyHandle,

    /// Optional Agent Signing Key (`#agent`). Software-held key for autonomous
    /// agent operations. `None` when no agent is delegated. Rotatable
    /// independently of `#active`. See ADR-039.
    pub agent_signing_key: Option<KeyHandle>,

    /// SHA-256 hash of the next Identity Key's public key.
    /// Published in DID document as a `PreRotationCommitment` service.
    pub pre_rotation_commitment: [u8; 32],

    /// The DID string: `did:dht:z<z-base-32(identity_key.public)>`.
    pub did: String,
}

/// Errors produced by identity operations.
///
/// Covers key generation failures, encoding errors, DID verification
/// failures, and DHT publish/resolve errors. Platform-level key custody
/// errors are wrapped via the `Platform` variant.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// A platform key custody operation failed.
    #[error("platform error: {0}")]
    Platform(#[from] scp_platform::PlatformError),

    /// The DID string has an invalid format.
    #[error("invalid DID format: {0}")]
    InvalidDidFormat(String),

    /// z-base-32 decoding failed.
    #[error("z-base-32 decode error: {0}")]
    ZBase32DecodeError(String),

    /// DID document serialization failed.
    #[error("document serialization error: {0}")]
    DocumentSerializationError(String),

    /// Publishing a DID document to the DHT failed.
    #[error("DHT publish failed: {0}")]
    DhtPublishFailed(String),

    /// Resolving a DID from the DHT failed.
    #[error("DHT resolve failed: {0}")]
    DhtResolveFailed(String),

    /// BEP44 signature verification failed on a resolved DHT record.
    #[error("BEP44 signature verification failed: {0}")]
    Bep44SignatureInvalid(String),

    /// Self-certification check failed: the public key in the resolved
    /// document does not match the z-base-32 decoded DID suffix.
    #[error("self-certification failed: {0}")]
    SelfCertificationFailed(String),

    /// The resolved DID document could not be deserialized.
    #[error("DID document deserialization error: {0}")]
    DocumentDeserializationError(String),

    /// The DID was not found on the DHT.
    #[error("DID not found on DHT: {0}")]
    DhtNotFound(String),

    /// Migration verification failed.
    #[error("migration verification failed: {0}")]
    MigrationVerificationFailed(String),

    /// Key rotation failed.
    #[error("key rotation failed: {0}")]
    KeyRotationFailed(String),

    /// An invalid relay URL was provided (must use wss:// scheme and /scp/v1 path).
    #[error("invalid relay URL: {0}")]
    InvalidRelayUrl(String),

    /// Publishing a DID document to an SCP relay failed.
    #[error("relay publish failed: {0}")]
    RelayPublishFailed(String),

    /// Querying an SCP relay for a DID document failed.
    #[error("relay query failed: {0}")]
    RelayQueryFailed(String),

    /// The resolved document has a stale sequence number (lower than last known).
    #[error("stale sequence number: received {received}, last known {last_known}")]
    StaleSequenceNumber {
        /// The sequence number in the received document.
        received: u64,
        /// The last known sequence number for this DID.
        last_known: u64,
    },

    /// An `#agent` verification method already exists in the DID document.
    #[error("agent key already exists in DID document")]
    AgentKeyAlreadyExists,

    /// No `#agent` verification method exists in the DID document.
    #[error("no agent key exists in DID document")]
    AgentKeyNotFound,

    /// The DID document contains multiple `#agent` verification methods.
    #[error("DID document contains {count} #agent verification methods, expected at most 1")]
    MultipleAgentKeys {
        /// The number of `#agent` VMs found.
        count: usize,
    },

    /// Too many retired agent keys in the DID document.
    #[error("too many retired agent keys: found {count}, maximum is {max}")]
    TooManyRetiredAgentKeys {
        /// The number of retired agent keys found.
        count: usize,
        /// The maximum allowed.
        max: usize,
    },
}

/// Abstract trait for DID method implementations.
///
/// Enables swapping between `did:dht` (primary) and `did:web` (contingency
/// fallback) without changing calling code. See ADR-003 acceptance criterion 6.
///
/// # Implementors
///
/// - [`DidDht`] — Primary implementation using the `BitTorrent` Mainline DHT.
///
/// # Async Methods
///
/// All methods are async because production implementations may involve
/// network I/O (DHT publish/resolve) or hardware security module access.
pub trait DidMethod: Send + Sync {
    /// Creates a new identity with three Ed25519 keypairs.
    ///
    /// Generates the Identity Key, Active Signing Key, and Pre-Rotation Key
    /// via the provided [`KeyCustody`] implementation. Returns the
    /// [`ScpIdentity`] handle and the constructed [`DidDocument`].
    ///
    /// See ADR-003 acceptance criterion 1.
    fn create(
        &self,
        key_custody: &impl KeyCustody,
    ) -> impl Future<Output = Result<(ScpIdentity, DidDocument), IdentityError>> + Send;

    /// Verifies that a DID string is self-certifying for the given public key.
    ///
    /// Decodes the z-base-32 suffix of the DID and compares it to the provided
    /// public key bytes. This is a local operation with no network I/O.
    ///
    /// See ADR-003 acceptance criterion 5.
    fn verify(&self, did_string: &str, public_key: &[u8]) -> bool;

    /// Publishes a DID document to the underlying DID infrastructure.
    ///
    /// For `did:dht`, this publishes to the Mainline DHT as a BEP44 signed
    /// mutable item. See ADR-003 acceptance criterion 2.
    ///
    /// **Note:** This method is defined in the trait for completeness but is
    /// implemented in story SCP-007, not SCP-006.
    fn publish(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
    ) -> impl Future<Output = Result<(), IdentityError>> + Send;

    /// Resolves a DID string to its DID document via the underlying infrastructure.
    ///
    /// For `did:dht`, this performs a Mainline DHT lookup. See ADR-003
    /// acceptance criterion 3.
    ///
    /// **Note:** This method is defined in the trait for completeness but is
    /// implemented in story SCP-007, not SCP-006.
    fn resolve(
        &self,
        did_string: &str,
    ) -> impl Future<Output = Result<DidDocument, IdentityError>> + Send;

    /// Rotates the active signing key for an identity.
    ///
    /// Generates a new Active Signing Key, updates the DID document, and
    /// publishes the update. See ADR-003 acceptance criterion 4a.
    ///
    /// **Note:** This method is defined in the trait for completeness but is
    /// implemented in story SCP-008, not SCP-006.
    fn rotate(
        &self,
        identity: &ScpIdentity,
        key_custody: &impl KeyCustody,
    ) -> impl Future<Output = Result<(ScpIdentity, DidDocument), IdentityError>> + Send;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::clone_on_copy)]
mod tests {
    use super::*;

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
}
