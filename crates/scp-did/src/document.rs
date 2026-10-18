//! DID Document construction, serialization, and verification method management.
//!
//! Implements the W3C DID Document JSON-LD format for `did:dht` identities.
//! The document contains up to three verification methods following the
//! shared-DID identity model (ADR-039):
//!
//! - `#0` — Identity Key (Ed25519, hardware-backed, never rotates, derives DID)
//! - `#active` — Human Signing Key (Ed25519, rotatable via Layer 1 rotation)
//! - `#agent` — Agent Signing Key (Ed25519, optional, rotatable independently)
//!
//! Authentication and assertion method references include `#active` always,
//! and `#agent` when present. Service entries include `PreRotationCommitment`
//! and optionally `SCPRelay`.
//!
//! # Key Rotation Support (SCP-008, ADR-039)
//!
//! The document supports key rotation through:
//! - [`DidDocument::retire_active_key`] — Retires the current `#active` key and
//!   adds a new one (Layer 1 rotation).
//! - [`DidDocument::add_agent_key`] — Adds an `#agent` verification method.
//! - [`DidDocument::remove_agent_key`] — Removes the `#agent` verification method.
//! - [`DidDocument::rotate_agent_key`] — Rotates `#agent`, retaining bounded
//!   retired keys (`#retired-agent-{sequence}`).
//! - [`DidDocument::set_also_known_as`] — Sets the `alsoKnownAs` field for
//!   identity migration (Layer 2 rotation).
//! - [`DidRotationEvent`], [`MigrationProof`], [`PreRotationProof`] — Structs for
//!   distributing and verifying identity migrations.
//!
//! # Validation
//!
//! [`DidDocument::validate_agent_keys`] enforces the structural constraint:
//! at most one `#agent` verification method per document. Verifiers call this
//! on any resolved document.
//!
//! See ADR-003 and ADR-039 in `.docs/adrs/phase-1.md`.

use super::attestation::{IdentityLinkServiceEntry, ScpKeyCustodyAttestation};
use crate::relay_url::{BridgeEndpoint, RelayEndpoint, RelayEntryUrlError};
use serde::{Deserialize, Deserializer, Serialize};

/// Synchronous, wasm-safe errors produced by the DID-document, verification-
/// method, attestation, and multibase-decoding closure (ADR-057).
///
/// These variants live in `scp-did` — the single wasm-safe home for the DID
/// data model — because the types that construct them ([`DidDocument`], the DID
/// [`VerificationMethod`], [`super::attestation`], and
/// [`decode_multibase_key`]) must compile to `wasm32-unknown-unknown` to back
/// the in-browser client (ADR-057). `scp-identity`'s `IdentityError`, which
/// also carries `tokio`/`scp-platform`-coupled custody and DHT variants,
/// `#[from]`-wraps this type, so every `scp_identity` consumer compiles
/// unchanged.
///
/// Only the variants the DID data model actually constructs live here. The
/// async/custody/DHT/relay variants stay in `scp_identity::IdentityError`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DidError {
    /// The DID string (or a multibase key payload) has an invalid format.
    #[error("invalid DID format: {0}")]
    InvalidDidFormat(String),

    /// DID document serialization failed.
    #[error("document serialization error: {0}")]
    DocumentSerializationError(String),

    /// The resolved DID document (or an embedded service entry) could not be
    /// deserialized.
    #[error("DID document deserialization error: {0}")]
    DocumentDeserializationError(String),

    /// A relay URL fails `18-addressability-and-deployment.md` §18.2.1: it
    /// has no `09-security-model.md` §9.18.2 canonical form, its canonical
    /// path does not end in `/scp/v1`, or it names a bridge relay over `ws`.
    #[error("invalid relay URL {url:?}: {reason}")]
    InvalidRelayUrl {
        /// The rejected URL with any user information removed.
        url: String,
        /// Which rule the URL fails.
        reason: RelayEntryUrlError,
    },

    /// A relay entry's `bridgeTarget` equals `SHA-256(0x00)`, the bytes
    /// `03-identity.md` §3.10.13 signs for an absent `bridgeTarget`, which
    /// §18.2.1 forbids as a present value.
    #[error("bridgeTarget equals SHA-256(0x00), the absent-value encoding")]
    AbsentSentinelBridgeTarget,

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
}

/// Custom serde helpers for hex-encoded fixed-size byte arrays.
///
/// Wire format is a lowercase hex string. Hex is the project-wide
/// convention for cryptographic byte material (signatures, public keys,
/// hashes): ~50% smaller on the wire than the `serde_bytes` JSON-array
/// form, human-readable in logs, trivially copy-pasteable, and decodes
/// in one call. Deserialization validates the exact byte count.
///
/// `serde`'s `with = "..."` attribute resolves a *module path* and
/// cannot pass type parameters, so the const-generic core lives here
/// and thin per-size submodules (`array64`, `array32`) instantiate it.
/// Apply via `#[serde(with = "serde_hex_array::array64")]` etc.
mod serde_hex_array {
    use serde::{Deserialize, Deserializer, Serializer};

    fn serialize_impl<const N: usize, S>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    fn deserialize_impl<'de, const N: usize, D>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let v =
            hex::decode(&s).map_err(|e| serde::de::Error::custom(format!("invalid hex: {e}")))?;
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected {N}-byte field, got {} bytes", v.len()))
        })
    }

    pub mod array64 {
        use super::{deserialize_impl, serialize_impl};
        use serde::{Deserializer, Serializer};

        pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
            serialize_impl::<64, S>(bytes, s)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
            deserialize_impl::<64, D>(d)
        }
    }

    pub mod array32 {
        use super::{deserialize_impl, serialize_impl};
        use serde::{Deserializer, Serializer};

        pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
            serialize_impl::<32, S>(bytes, s)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
            deserialize_impl::<32, D>(d)
        }
    }

    /// An optional 32-byte field whose only spelling is 64 lowercase hex
    /// digits (`18-addressability-and-deployment.md` §18.2.1 `bridgeTarget`).
    ///
    /// `hex::decode` also accepts uppercase, so the spelling is checked byte
    /// by byte before decoding ([`lower_hex32`]). A present key must hold a
    /// string: `null` fails, and an absent key is `None` through
    /// `#[serde(default)]`. A [`super::DidDocument`] does not read its
    /// entries through this: its deserializer drops an entry whose
    /// `bridgeTarget` this rejects and keeps the document.
    pub mod option32_lower {
        use serde::{Deserialize, Deserializer, Serializer};

        // serde's `serialize_with` passes `&Option<T>`, so the reference is
        // fixed by the attribute and cannot be `Option<&T>`.
        #[allow(clippy::ref_option)]
        pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
            match v {
                Some(bytes) => s.serialize_str(&hex::encode(bytes)),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
            let text = String::deserialize(d)?;
            super::lower_hex32(&text)
                .map(Some)
                .ok_or_else(|| serde::de::Error::custom(super::MALFORMED_BRIDGE_TARGET))
        }
    }

    /// Why a `bridgeTarget` string is not 64 lowercase hex digits.
    pub const MALFORMED_BRIDGE_TARGET: &str =
        "bridgeTarget must be exactly 64 lowercase hex digits";

    /// Decodes `text` when it is exactly 64 lowercase hex digits.
    pub fn lower_hex32(text: &str) -> Option<[u8; 32]> {
        if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return None;
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(text, &mut out).ok()?;
        Some(out)
    }
}

/// A W3C DID Document for an SCP identity.
///
/// Contains verification methods, authentication references, assertion method
/// references, and services as specified by ADR-003 and ADR-039. The document
/// is JSON-serializable via `serde_json`.
///
/// # Structure (ADR-039 Three-VM Model)
///
/// - Verification method `#0`: the Identity Key (Ed25519). Hardware-backed.
///   Used only for DID document updates and pre-rotation commitments.
/// - Verification method `#active`: the Human Signing Key (Ed25519). Used for
///   MLS credentials, inner envelope signatures, and UCAN issuance.
/// - Verification method `#agent` (optional): the Agent Signing Key (Ed25519).
///   Software-held key for autonomous agent operations. Added only when agent
///   delegation is needed.
/// - `authentication` and `assertionMethod` reference `#active`, and `#agent`
///   when present.
/// - `PreRotationCommitment` service publishes the SHA-256 commitment of the
///   next identity key's public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DidDocument {
    /// The JSON-LD context URIs.
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// The DID string that this document describes.
    pub id: String,

    /// Verification methods embedded in this document.
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,

    /// References to verification methods authorized for authentication.
    pub authentication: Vec<String>,

    /// References to verification methods authorized for assertion (signing).
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,

    /// Alternate identifiers for this DID subject.
    ///
    /// Used during identity migration (Layer 2 rotation) to link the old DID
    /// to the new DID. The old DID document's `alsoKnownAs` points to the new
    /// DID string, creating a verifiable forwarding record.
    ///
    /// See ADR-003 acceptance criterion 4b.
    #[serde(rename = "alsoKnownAs", default, skip_serializing_if = "Vec::is_empty")]
    pub also_known_as: Vec<String>,

    /// Services associated with this DID (e.g., `PreRotationCommitment`).
    ///
    /// Deserializing drops every entry `18-addressability-and-deployment.md`
    /// §18.2.1 rejects and keeps the document, so a resolved document never
    /// holds one.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_accepted_services"
    )]
    pub service: Vec<Service>,
}

/// A verification method within a DID Document.
///
/// Represents an Ed25519 public key in `Ed25519VerificationKey2020` format
/// with `publicKeyMultibase` encoding (`z` prefix + base58btc).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationMethod {
    /// The full URI of this verification method (e.g., `did:dht:z...#0`).
    pub id: String,

    /// The type of verification method.
    #[serde(rename = "type")]
    pub method_type: String,

    /// The DID that controls this verification method.
    pub controller: String,

    /// The public key encoded as a multibase string.
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

/// A service entry within a DID Document.
///
/// A [`DidDocument`] read from JSON or `MessagePack` holds no entry
/// `18-addressability-and-deployment.md` §18.2.1 rejects; its deserializer
/// drops each one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Service {
    /// The full URI of this service (e.g., `did:dht:z...#pre-rotation`).
    pub id: String,

    /// The service type (e.g., `PreRotationCommitment`).
    #[serde(rename = "type")]
    pub service_type: String,

    /// The service endpoint (e.g., `sha256:<hex>`).
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,

    /// A tier 3 bridge entry's routing target (§18.2.1 `bridgeTarget`): the
    /// identity routing ID the bridge relay forwards to. Only an `SCPRelay`
    /// entry carries it. A [`DidDocument`]'s deserializer drops an entry whose
    /// value is not 64 lowercase hex digits, is `null`, equals
    /// [`ABSENT_BRIDGE_TARGET`], sits on an entry of another type, or sits on
    /// an entry whose URL is not `wss` (§10.12.7), and keeps the document.
    #[serde(
        rename = "bridgeTarget",
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_hex_array::option32_lower"
    )]
    pub bridge_target: Option<[u8; 32]>,
}

/// `SHA-256(0x00)`, the 32 trailing bytes of an `SCPRelay` entry that names no
/// `bridgeTarget`.
///
/// `03-identity.md` §3.10.13 reads these bytes there as "no target", and
/// §18.2.1 forbids a writer to name them as a target, so they decode one way.
pub const ABSENT_BRIDGE_TARGET: [u8; 32] = [
    0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98, 0x9c, 0xa5, 0x44, 0xe6, 0xbb, 0x78, 0x0a, 0x2c,
    0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76, 0x85, 0x11, 0xa3, 0x06, 0x17, 0xaf, 0xa0, 0x1d,
];

/// A tier 3 bridge entry's routing target: 32 bytes other than
/// [`ABSENT_BRIDGE_TARGET`] (§18.2.1).
///
/// [`BridgeTarget::new`] is the only constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BridgeTarget([u8; 32]);

impl BridgeTarget {
    /// Accepts `bytes` as a bridge target.
    ///
    /// # Errors
    ///
    /// [`DidError::AbsentSentinelBridgeTarget`] when `bytes` equals
    /// [`ABSENT_BRIDGE_TARGET`], which §3.10.13 reads as "no target".
    pub fn new(bytes: [u8; 32]) -> Result<Self, DidError> {
        if bytes == ABSENT_BRIDGE_TARGET {
            Err(DidError::AbsentSentinelBridgeTarget)
        } else {
            Ok(Self(bytes))
        }
    }

    /// The 32 target bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// One `SCPRelay` entry a reader accepts under §18.2.1.
///
/// `18-addressability-and-deployment.md` §18.2.1 requires a relay URL with a
/// §9.18.2 canonical form whose path ends in `/scp/v1`, and allows an optional
/// tier 3 `bridgeTarget` that is not [`ABSENT_BRIDGE_TARGET`] on a `wss` bridge
/// relay URL (§10.12.7). [`RelayService::direct`] and [`RelayService::bridge`]
/// build one from values that already passed those rules, so neither fails.
/// The URL is the canonical form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayService {
    endpoint: RelayEndpoint,
    bridge_target: Option<BridgeTarget>,
}

impl RelayService {
    /// An entry routing to the relay at `endpoint`, with no `bridgeTarget`.
    #[must_use]
    pub const fn direct(endpoint: RelayEndpoint) -> Self {
        Self {
            endpoint,
            bridge_target: None,
        }
    }

    /// A tier 3 bridge entry: the bridge relay's URL and the routing ID it
    /// forwards to (§10.12.4, §18.2.1).
    #[must_use]
    pub fn bridge(endpoint: BridgeEndpoint, target: BridgeTarget) -> Self {
        Self {
            endpoint: endpoint.into_endpoint(),
            bridge_target: Some(target),
        }
    }

    /// The relay URL, in its §9.18.2 canonical form.
    #[must_use]
    pub fn url(&self) -> &str {
        self.endpoint.as_str()
    }

    /// The relay endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &RelayEndpoint {
        &self.endpoint
    }

    /// The tier 3 bridge routing target, or `None` for a relay that is not a
    /// bridge.
    #[must_use]
    pub fn bridge_target(&self) -> Option<[u8; 32]> {
        self.bridge_target.map(BridgeTarget::to_bytes)
    }

    /// Validates an `SCPRelay` entry's URL and target as a reader does.
    fn from_parts(url: &str, bridge_target: Option<[u8; 32]>) -> Result<Self, DidError> {
        let endpoint = RelayEndpoint::new(url)?;
        match bridge_target {
            None => Ok(Self::direct(endpoint)),
            Some(bytes) => Ok(Self::bridge(
                BridgeEndpoint::from_endpoint(endpoint)?,
                BridgeTarget::new(bytes)?,
            )),
        }
    }

    /// The service entry for this relay, numbered `n` within `did`.
    fn entry(&self, did: &str, n: usize) -> Service {
        Service {
            id: format!("{did}#scp-relay-{n}"),
            service_type: SCP_RELAY_SERVICE_TYPE.to_owned(),
            service_endpoint: self.url().to_owned(),
            bridge_target: self.bridge_target(),
        }
    }
}

/// A service entry as a document holds it before §18.2.1 is applied.
///
/// `bridgeTarget` is read in any form, so that a malformed value rejects the
/// entry and not the document.
#[derive(Deserialize)]
struct RawService {
    id: String,
    #[serde(rename = "type")]
    service_type: String,
    #[serde(rename = "serviceEndpoint")]
    service_endpoint: String,
    #[serde(rename = "bridgeTarget", default)]
    bridge_target: RawBridgeTarget,
}

/// A `bridgeTarget` key as written: absent, or present with its 32 bytes or
/// the reason its value is not 64 lowercase hex digits.
#[derive(Default)]
enum RawBridgeTarget {
    #[default]
    Absent,
    Present(Result<[u8; 32], &'static str>),
}

impl<'de> Deserialize<'de> for RawBridgeTarget {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(RawBridgeTargetVisitor)
    }
}

/// Reads a present `bridgeTarget` of any type, consuming a nested value whole
/// so the rest of the entry still parses.
struct RawBridgeTargetVisitor;

impl<'de> serde::de::Visitor<'de> for RawBridgeTargetVisitor {
    type Value = RawBridgeTarget;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a bridgeTarget value")
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(RawBridgeTarget::Present(
            serde_hex_array::lower_hex32(v).ok_or(serde_hex_array::MALFORMED_BRIDGE_TARGET),
        ))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(RawBridgeTarget::Present(Err("bridgeTarget is null")))
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        self.visit_unit()
    }

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(not_a_string())
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(not_a_string())
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(not_a_string())
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(not_a_string())
    }

    fn visit_bytes<E: serde::de::Error>(self, _: &[u8]) -> Result<Self::Value, E> {
        Ok(not_a_string())
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
        Ok(not_a_string())
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        while map
            .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
            .is_some()
        {}
        Ok(not_a_string())
    }
}

const fn not_a_string() -> RawBridgeTarget {
    RawBridgeTarget::Present(Err("bridgeTarget is not a string"))
}

/// Why §18.2.1 rejects a service entry.
///
/// Its `Display` escapes every string the entry supplied.
enum EntryRejection {
    /// An entry of a type other than `SCPRelay` carries `bridgeTarget`.
    BridgeTargetOnNonRelay,
    /// The `bridgeTarget` value is not 64 lowercase hex digits.
    MalformedBridgeTarget(&'static str),
    /// The `SCPRelay` entry's URL or target fails [`RelayService`].
    Relay(DidError),
}

impl std::fmt::Display for EntryRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BridgeTargetOnNonRelay => {
                f.write_str("bridgeTarget on an entry that is not SCPRelay")
            }
            Self::MalformedBridgeTarget(why) => f.write_str(why),
            Self::Relay(e) => write!(f, "{e}"),
        }
    }
}

impl RawService {
    /// Why §18.2.1 rejects the entry, or the bytes of its accepted
    /// `bridgeTarget`.
    fn rejection(&self) -> Result<Option<[u8; 32]>, EntryRejection> {
        let is_relay = self.service_type == SCP_RELAY_SERVICE_TYPE;
        let bridge_target = match &self.bridge_target {
            RawBridgeTarget::Absent => None,
            RawBridgeTarget::Present(_) if !is_relay => {
                return Err(EntryRejection::BridgeTargetOnNonRelay);
            }
            RawBridgeTarget::Present(Err(why)) => {
                return Err(EntryRejection::MalformedBridgeTarget(why));
            }
            RawBridgeTarget::Present(Ok(bytes)) => Some(*bytes),
        };
        if is_relay {
            RelayService::from_parts(&self.service_endpoint, bridge_target)
                .map_err(EntryRejection::Relay)?;
        }
        Ok(bridge_target)
    }

    /// The entry, or `None` after logging why §18.2.1 rejects it. The log
    /// escapes every string the entry supplied.
    fn accept(self) -> Option<Service> {
        match self.rejection() {
            Ok(bridge_target) => Some(Service {
                id: self.id,
                service_type: self.service_type,
                service_endpoint: self.service_endpoint,
                bridge_target,
            }),
            Err(reason) => {
                tracing::warn!(
                    entry = ?self.id,
                    service_type = ?self.service_type,
                    %reason,
                    "dropping a service entry that 18-addressability-and-deployment.md §18.2.1 rejects"
                );
                None
            }
        }
    }
}

/// Deserializes [`DidDocument::service`], dropping each entry §18.2.1 rejects
/// and keeping the others in order. Each drop is logged once.
fn deserialize_accepted_services<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Vec<Service>, D::Error> {
    let raw = Vec::<RawService>::deserialize(d)?;
    Ok(raw.into_iter().filter_map(RawService::accept).collect())
}

/// The W3C DID Document JSON-LD context URI.
const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";

/// The Ed25519 verification key suite context URI.
const ED25519_CONTEXT: &str = "https://w3id.org/security/suites/ed25519-2020/v1";

/// The verification method type string for Ed25519 keys.
const ED25519_VERIFICATION_KEY_TYPE: &str = "Ed25519VerificationKey2020";

/// The service type string for `SCPRelay` entries (§18.2.1).
pub const SCP_RELAY_SERVICE_TYPE: &str = "SCPRelay";

/// The service type string for `SCPBroadcastContext` entries (§18.2.2).
///
/// Broadcast contexts with `discoverable: true` publish a service entry of
/// this type in the creator's DID document. The service endpoint encodes
/// the context ID and relay URLs:
///
///   `scp:context:<context_id_hex>?relay=<url1>&relay=<url2>`
const SCP_BROADCAST_CONTEXT_SERVICE_TYPE: &str = "SCPBroadcastContext";

/// The service type string for `ScpDeviceAttestation` entries (§9.3).
///
/// Device attestation tokens (Apple App Attest, Android Play Integrity) are
/// stored as DID document service entries. The protocol carries the proofs;
/// contexts interpret them. See issue #362.
const DEVICE_ATTESTATION_SERVICE_TYPE: &str = "ScpDeviceAttestation";

/// The fragment identifier for device attestation service entries.
const DEVICE_ATTESTATION_FRAGMENT: &str = "device-attestation";

/// Maximum number of retired agent keys to retain in a DID document.
///
/// When rotating the `#agent` key, older retired keys beyond this limit are
/// pruned to bound document size. Per ADR-039, this is set to 2.
const MAX_RETIRED_AGENT_KEYS: usize = 2;

/// The service type string for `ScpIdentityLinkAttestation` entries (§3.5.3).
const IDENTITY_LINK_ATTESTATION_SERVICE_TYPE: &str = "ScpIdentityLinkAttestation";

/// Maximum number of identity link attestation service entries per DID document (§3.5.3).
/// Unified at 64 across the DID document layer and all FFI bridge attestation stores.
const MAX_IDENTITY_LINK_ATTESTATIONS: usize = 64;

impl DidDocument {
    /// Constructs a new DID Document for an SCP identity.
    ///
    /// Creates a document with the `#0` (Identity Key) and `#active` (Human
    /// Signing Key) verification methods. If `agent_public_key` is provided,
    /// a third `#agent` verification method is added per ADR-039.
    ///
    /// # Arguments
    ///
    /// * `did` - The DID string (e.g., `did:dht:z...`).
    /// * `identity_public_key` - The raw 32-byte Ed25519 Identity Key public key.
    /// * `active_public_key` - The raw 32-byte Ed25519 Active Signing Key public key.
    /// * `pre_rotation_commitment` - The 32-byte SHA-256 commitment of the
    ///   pre-rotation key's public key.
    #[must_use]
    pub fn new(
        did: &str,
        identity_public_key: &[u8],
        active_public_key: &[u8],
        pre_rotation_commitment: &[u8; 32],
    ) -> Self {
        Self::new_with_agent_key(
            did,
            identity_public_key,
            active_public_key,
            pre_rotation_commitment,
            None,
        )
    }

    /// Constructs a new DID Document with an optional agent key.
    ///
    /// When `agent_public_key` is `Some`, adds an `#agent` verification method
    /// and includes it in the `authentication` and `assertionMethod` arrays.
    ///
    /// # Arguments
    ///
    /// * `did` - The DID string (e.g., `did:dht:z...`).
    /// * `identity_public_key` - The raw 32-byte Ed25519 Identity Key public key.
    /// * `active_public_key` - The raw 32-byte Ed25519 Active Signing Key public key.
    /// * `pre_rotation_commitment` - The 32-byte SHA-256 commitment of the
    ///   pre-rotation key's public key.
    /// * `agent_public_key` - Optional raw 32-byte Ed25519 Agent Signing Key
    ///   public key. See ADR-039.
    #[must_use]
    pub fn new_with_agent_key(
        did: &str,
        identity_public_key: &[u8],
        active_public_key: &[u8],
        pre_rotation_commitment: &[u8; 32],
        agent_public_key: Option<&[u8]>,
    ) -> Self {
        let identity_vm = VerificationMethod {
            id: format!("{did}#0"),
            method_type: ED25519_VERIFICATION_KEY_TYPE.to_owned(),
            controller: did.to_owned(),
            public_key_multibase: multibase_encode(identity_public_key),
        };

        let active_vm = VerificationMethod {
            id: format!("{did}#active"),
            method_type: ED25519_VERIFICATION_KEY_TYPE.to_owned(),
            controller: did.to_owned(),
            public_key_multibase: multibase_encode(active_public_key),
        };

        let mut verification_methods = vec![identity_vm, active_vm];
        let mut authentication = vec![format!("{did}#active")];
        let mut assertion_method = vec![format!("{did}#active")];

        if let Some(agent_key) = agent_public_key {
            let agent_vm = VerificationMethod {
                id: format!("{did}#agent"),
                method_type: ED25519_VERIFICATION_KEY_TYPE.to_owned(),
                controller: did.to_owned(),
                public_key_multibase: multibase_encode(agent_key),
            };
            verification_methods.push(agent_vm);
            authentication.push(format!("{did}#agent"));
            assertion_method.push(format!("{did}#agent"));
        }

        let pre_rotation_service = Service {
            id: format!("{did}#pre-rotation"),
            service_type: "PreRotationCommitment".to_owned(),
            service_endpoint: format!("sha256:{}", hex::encode(pre_rotation_commitment)),
            bridge_target: None,
        };

        Self {
            context: vec![DID_CONTEXT.to_owned(), ED25519_CONTEXT.to_owned()],
            id: did.to_owned(),
            verification_method: verification_methods,
            authentication,
            assertion_method,
            also_known_as: Vec::new(),
            service: vec![pre_rotation_service],
        }
    }

    /// Serializes the DID Document to a JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails (should not happen for a
    /// well-formed document).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserializes a DID Document from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed or missing required fields.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Returns the verification method with the given fragment (e.g., `"#0"` or `"#active"`).
    #[must_use]
    pub fn verification_method_by_fragment(&self, fragment: &str) -> Option<&VerificationMethod> {
        let suffix = format!("#{fragment}");
        self.verification_method
            .iter()
            .find(|vm| vm.id.ends_with(&suffix))
    }

    /// Returns the `PreRotationCommitment` service, if present.
    #[must_use]
    pub fn pre_rotation_service(&self) -> Option<&Service> {
        self.service
            .iter()
            .find(|s| s.service_type == "PreRotationCommitment")
    }

    /// Adds an `SCPRelay` service entry to this DID document.
    ///
    /// [`RelayService`] already satisfies §18.2.1, so this cannot fail.
    /// Multiple relay entries are allowed for suppression resistance
    /// (§18.2.3). Entries preserve insertion order — the first entry is the
    /// preferred relay.
    pub fn add_relay_service(&mut self, relay: &RelayService) {
        let entry = relay.entry(&self.id, self.relay_entry_count() + 1);
        self.service.push(entry);
    }

    /// Makes `relay` the preferred relay (§18.2.3): rewrites the first
    /// `SCPRelay` entry's `serviceEndpoint` and `bridgeTarget` to `relay`'s,
    /// keeping its `id` and position, or inserts `relay`'s entry when the
    /// document has no `SCPRelay` entry.
    ///
    /// Keying on position, not on an address, makes a repeated call with one
    /// `relay` a no-op and keeps a retried rewrite from appending a duplicate.
    /// Moving from a bridge entry to a direct one clears `bridgeTarget`.
    pub fn set_preferred_relay(&mut self, relay: &RelayService) {
        match self
            .service
            .iter_mut()
            .find(|s| s.service_type == SCP_RELAY_SERVICE_TYPE)
        {
            Some(entry) => {
                relay.url().clone_into(&mut entry.service_endpoint);
                entry.bridge_target = relay.bridge_target();
            }
            None => self.insert_preferred_relay(relay),
        }
    }

    /// Inserts `relay`'s entry ahead of every existing `SCPRelay` entry, so it
    /// becomes the preferred relay (§18.2.3) and the other relays keep their
    /// order, entries and `id`s.
    ///
    /// The new entry's `id` is `<did>#scp-relay-<n>` with `n` one more than the
    /// number of relay entries already present; existing `id`s are left alone,
    /// because third parties may reference them.
    pub fn insert_preferred_relay(&mut self, relay: &RelayService) {
        let insert_at = self
            .service
            .iter()
            .position(|s| s.service_type == SCP_RELAY_SERVICE_TYPE)
            .unwrap_or(self.service.len());
        let entry = relay.entry(&self.id, self.relay_entry_count() + 1);
        self.service.insert(insert_at, entry);
    }

    /// The number of `SCPRelay` entries, valid or not.
    fn relay_entry_count(&self) -> usize {
        self.service
            .iter()
            .filter(|s| s.service_type == SCP_RELAY_SERVICE_TYPE)
            .count()
    }

    /// The `SCPRelay` entries a reader accepts under §18.2.1, in record order.
    ///
    /// The first entry is the preferred relay per §18.2.3. A deserialized
    /// document holds no rejected entry; an `SCPRelay` entry a caller pushed
    /// onto [`Self::service`] in memory that fails §18.2.1 is left out and
    /// logged, and the remaining entries keep their order.
    #[must_use]
    pub fn relay_services(&self) -> Vec<RelayService> {
        self.service
            .iter()
            .filter(|s| s.service_type == SCP_RELAY_SERVICE_TYPE)
            .filter_map(|s| match RelayService::from_parts(&s.service_endpoint, s.bridge_target) {
                Ok(relay) => Some(relay),
                Err(e) => {
                    tracing::warn!(
                        did = ?self.id,
                        entry = ?s.id,
                        error = ?e,
                        "skipping SCPRelay entry that 18-addressability-and-deployment.md §18.2.1 rejects"
                    );
                    None
                }
            })
            .collect()
    }

    /// The URLs of the entries [`Self::relay_services`] accepts, in record
    /// order.
    #[must_use]
    pub fn relay_service_urls(&self) -> Vec<String> {
        self.relay_services()
            .into_iter()
            .map(|relay| relay.url().to_owned())
            .collect()
    }

    /// Replaces all `SCPRelay` service entries with the given relays.
    ///
    /// Removes any existing `SCPRelay` entries and adds one entry per relay,
    /// in order. Non-relay services (e.g., `PreRotationCommitment`) are
    /// preserved. Each [`RelayService`] already satisfies §18.2.1, so the
    /// replacement cannot fail part-way.
    ///
    /// This is used during relay list updates (§18.5) to atomically replace the
    /// relay set before republishing with an incremented BEP44 sequence number
    /// (§9.6.3).
    pub fn set_relay_services(&mut self, relays: &[RelayService]) {
        self.service
            .retain(|s| s.service_type != SCP_RELAY_SERVICE_TYPE);
        for (i, relay) in relays.iter().enumerate() {
            let entry = relay.entry(&self.id, i + 1);
            self.service.push(entry);
        }
    }

    // -----------------------------------------------------------------------
    // SCPBroadcastContext service entries (§18.2.2, §5.14.11)
    // -----------------------------------------------------------------------

    /// Adds an `SCPBroadcastContext` service entry for a discoverable broadcast
    /// context.
    ///
    /// The service endpoint encodes the context ID and relay URLs:
    ///
    ///   `scp:context:<context_id_hex>?relay=<url1>&relay=<url2>`
    ///
    /// If a service entry for this `context_id` already exists, this method is
    /// a no-op (duplicate prevention).
    ///
    /// # Arguments
    ///
    /// * `context_id` -- Hex-encoded context identifier.
    /// * `relay_urls` -- Relay URLs where the context is reachable.
    pub fn add_broadcast_context_service(&mut self, context_id: &str, relay_urls: &[String]) {
        use std::fmt::Write as _;

        // Duplicate check: skip if context_id already has a service entry.
        let already_exists = self.service.iter().any(|s| {
            s.service_type == SCP_BROADCAST_CONTEXT_SERVICE_TYPE
                && s.service_endpoint
                    .contains(&format!("scp:context:{context_id}"))
        });
        if already_exists {
            return;
        }

        // Build endpoint: scp:context:<id>?relay=<url1>&relay=<url2>
        let mut endpoint = format!("scp:context:{context_id}");
        for (i, url) in relay_urls.iter().enumerate() {
            let separator = if i == 0 { '?' } else { '&' };
            let encoded = url.replace(':', "%3A").replace('/', "%2F");
            let _ = write!(endpoint, "{separator}relay={encoded}");
        }

        let bc_count = self
            .service
            .iter()
            .filter(|s| s.service_type == SCP_BROADCAST_CONTEXT_SERVICE_TYPE)
            .count();

        let service = Service {
            id: format!("{}#scp-broadcast-ctx-{}", self.id, bc_count + 1),
            service_type: SCP_BROADCAST_CONTEXT_SERVICE_TYPE.to_owned(),
            service_endpoint: endpoint,
            bridge_target: None,
        };

        self.service.push(service);
    }

    /// Removes the `SCPBroadcastContext` service entry for the given context ID.
    ///
    /// Returns `true` if an entry was removed, `false` if no matching entry
    /// existed.
    pub fn remove_broadcast_context_service(&mut self, context_id: &str) -> bool {
        let needle = format!("scp:context:{context_id}");
        let before = self.service.len();
        self.service.retain(|s| {
            !(s.service_type == SCP_BROADCAST_CONTEXT_SERVICE_TYPE
                && s.service_endpoint.contains(&needle))
        });
        self.service.len() < before
    }

    /// Returns all `SCPBroadcastContext` entries as `(context_id, relay_urls)` pairs.
    ///
    /// Parses each `SCPBroadcastContext` service endpoint to extract the context
    /// ID and relay URLs. Entries with malformed endpoints are silently skipped.
    #[must_use]
    pub fn broadcast_context_entries(&self) -> Vec<(String, Vec<String>)> {
        self.service
            .iter()
            .filter(|s| s.service_type == SCP_BROADCAST_CONTEXT_SERVICE_TYPE)
            .filter_map(|s| parse_broadcast_context_endpoint(&s.service_endpoint))
            .collect()
    }

    // Device attestation service (§9.3, #362)
    // -----------------------------------------------------------------------

    /// Adds a `ScpDeviceAttestation` service entry containing the attestation
    /// token bytes encoded as hex.
    ///
    /// If a `ScpDeviceAttestation` service entry already exists, it is replaced.
    /// The service entry ID uses the format `{did}#device-attestation`.
    ///
    /// See §9.3 and issue #362.
    pub fn add_device_attestation(&mut self, token_bytes: &[u8]) {
        // Remove any existing device attestation entry.
        self.service
            .retain(|s| s.service_type != DEVICE_ATTESTATION_SERVICE_TYPE);

        let service = Service {
            id: format!("{}#{DEVICE_ATTESTATION_FRAGMENT}", self.id),
            service_type: DEVICE_ATTESTATION_SERVICE_TYPE.to_owned(),
            service_endpoint: {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(token_bytes)
            },
            bridge_target: None,
        };
        self.service.push(service);
    }

    /// Removes the `ScpDeviceAttestation` service entry, if present.
    pub fn remove_device_attestation(&mut self) {
        self.service
            .retain(|s| s.service_type != DEVICE_ATTESTATION_SERVICE_TYPE);
    }

    /// Returns the key custody attestation from this DID document, if present.
    ///
    /// Searches the service entries for one with type `ScpKeyCustodyAttestation`
    /// and parses the attestation data from its endpoint. Returns `None` if no
    /// custody attestation service entry exists.
    ///
    /// Absence of attestation is a valid state — it signals that the DID owner
    /// has not declared their key custody model (ADR-039 Layer 4).
    ///
    /// # Errors
    ///
    /// Returns [`DidError::DocumentDeserializationError`] if a custody
    /// attestation service entry exists but contains invalid data.
    pub fn custody_attestation(&self) -> Result<Option<ScpKeyCustodyAttestation>, DidError> {
        let entry = self
            .service
            .iter()
            .find(|s| s.service_type == "ScpKeyCustodyAttestation");

        entry.map_or(Ok(None), |service| {
            ScpKeyCustodyAttestation::from_service_entry(service).map(Some)
        })
    }

    /// Sets or replaces the key custody attestation in this DID document.
    ///
    /// Adds a service entry with type `ScpKeyCustodyAttestation` containing the
    /// attestation data. If an existing custody attestation entry exists, it is
    /// replaced. Other service entries are preserved.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::DocumentSerializationError`] if the attestation
    /// cannot be serialized (should not happen for well-formed data).
    pub fn set_custody_attestation(
        &mut self,
        attestation: &ScpKeyCustodyAttestation,
    ) -> Result<(), DidError> {
        // Remove any existing custody attestation entry.
        self.service
            .retain(|s| s.service_type != "ScpKeyCustodyAttestation");

        // Add the new entry.
        let service = attestation.to_service_entry(&self.id)?;
        self.service.push(service);
        Ok(())
    }

    // Identity link attestation service entries (§3.5.3)
    // -----------------------------------------------------------------------

    /// Returns all identity link attestation service entries in this DID document.
    ///
    /// Parses each service entry of type `ScpIdentityLinkAttestation` and returns
    /// the platform, attestation ID, and index. Entries that fail to parse are
    /// silently skipped (defensive — avoids rejecting the entire document for one
    /// malformed entry).
    #[must_use]
    pub fn identity_link_attestations(&self) -> Vec<IdentityLinkServiceEntry> {
        self.service
            .iter()
            .filter(|s| s.service_type == IDENTITY_LINK_ATTESTATION_SERVICE_TYPE)
            .filter_map(|s| IdentityLinkServiceEntry::from_service_entry(s).ok())
            .collect()
    }

    /// Sets or adds an identity link attestation service entry (§3.5.3).
    ///
    /// If an entry for the same platform and attestation ID already exists, it is
    /// replaced. Otherwise a new entry is appended. The index is computed as the
    /// next available index for the given platform among existing entries.
    ///
    /// # Arguments
    ///
    /// * `platform` - Platform identifier from the provider registry (§3.5.1).
    /// * `attestation_id` - Hex-encoded deterministic attestation ID (§3.5.2).
    ///
    /// # Errors
    ///
    /// Returns [`DidError::DocumentSerializationError`] if adding this entry
    /// would exceed the maximum of 10 identity link attestation entries (§3.5.3).
    pub fn set_identity_link_attestation(
        &mut self,
        platform: &str,
        attestation_id: &str,
    ) -> Result<(), DidError> {
        // Check if an entry with this exact attestation_id already exists — replace it.
        let existing_pos = self.service.iter().position(|s| {
            s.service_type == IDENTITY_LINK_ATTESTATION_SERVICE_TYPE
                && s.service_endpoint == attestation_id
        });

        if let Some(pos) = existing_pos {
            // Parse the existing entry to preserve its index.
            let existing = IdentityLinkServiceEntry::from_service_entry(&self.service[pos]).ok();
            let index = existing.map_or(0, |e| e.index);
            self.service[pos] = IdentityLinkServiceEntry::to_service_entry(
                &self.id,
                platform,
                attestation_id,
                index,
            );
            return Ok(());
        }

        // Count existing identity link entries to enforce the limit.
        let current_count = self
            .service
            .iter()
            .filter(|s| s.service_type == IDENTITY_LINK_ATTESTATION_SERVICE_TYPE)
            .count();

        if current_count >= MAX_IDENTITY_LINK_ATTESTATIONS {
            return Err(DidError::DocumentSerializationError(format!(
                "maximum of {MAX_IDENTITY_LINK_ATTESTATIONS} identity link attestation entries exceeded"
            )));
        }

        // Compute the next index for this platform.
        let index = self
            .service
            .iter()
            .filter(|s| s.service_type == IDENTITY_LINK_ATTESTATION_SERVICE_TYPE)
            .filter_map(|s| IdentityLinkServiceEntry::from_service_entry(s).ok())
            .filter(|e| e.platform == platform)
            .map(|e| e.index)
            .max()
            .map_or(0, |max_idx| max_idx + 1);

        let entry =
            IdentityLinkServiceEntry::to_service_entry(&self.id, platform, attestation_id, index);
        self.service.push(entry);
        Ok(())
    }

    /// Removes an identity link attestation service entry by attestation ID.
    ///
    /// Returns `true` if an entry was removed, `false` if no matching entry
    /// was found.
    pub fn remove_identity_link_attestation(&mut self, attestation_id: &str) -> bool {
        let before = self.service.len();
        self.service.retain(|s| {
            !(s.service_type == IDENTITY_LINK_ATTESTATION_SERVICE_TYPE
                && s.service_endpoint == attestation_id)
        });
        self.service.len() < before
    }

    /// Returns the number of identity link attestation service entries.
    #[must_use]
    pub fn identity_link_attestation_count(&self) -> usize {
        self.service
            .iter()
            .filter(|s| s.service_type == IDENTITY_LINK_ATTESTATION_SERVICE_TYPE)
            .count()
    }

    /// Returns the device attestation token from this DID document, if present.
    ///
    /// Searches the service entries for one with type `ScpDeviceAttestation`
    /// and returns the raw attestation token bytes decoded from the base64
    /// service endpoint. Returns `None` if no device attestation service entry
    /// exists.
    ///
    /// Device attestation is a self-asserted Sybil resistance signal (§9.3).
    /// Contexts MAY require device attestation for admission via `ContextParams`.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::DocumentDeserializationError`] if a device
    /// attestation service entry exists but the endpoint cannot be base64-decoded.
    pub fn device_attestation_token(&self) -> Result<Option<Vec<u8>>, DidError> {
        use base64::Engine;

        let entry = self
            .service
            .iter()
            .find(|s| s.service_type == DEVICE_ATTESTATION_SERVICE_TYPE);

        match entry {
            None => Ok(None),
            Some(service) => {
                let token_bytes = base64::engine::general_purpose::STANDARD
                    .decode(&service.service_endpoint)
                    .map_err(|e| {
                        DidError::DocumentDeserializationError(format!(
                            "failed to decode device attestation token from base64: {e}"
                        ))
                    })?;
                Ok(Some(token_bytes))
            }
        }
    }

    /// Sets or replaces the device attestation token in this DID document.
    ///
    /// Adds a service entry with type `ScpDeviceAttestation` containing the
    /// attestation token bytes encoded as base64 in the `serviceEndpoint`.
    /// If an existing device attestation entry exists, it is replaced. Other
    /// service entries are preserved.
    ///
    /// The token is produced by `DeviceAttestation::attest()` from the
    /// `scp-platform` crate. The protocol does not prescribe interpretation --
    /// contexts MAY require device attestation for admission (§9.3).
    ///
    /// # Arguments
    ///
    /// * `token` - Raw attestation token bytes from a `DeviceAttestation` implementation.
    pub fn set_device_attestation_token(&mut self, token: &[u8]) {
        use base64::Engine;

        // Remove any existing device attestation entry.
        self.service
            .retain(|s| s.service_type != DEVICE_ATTESTATION_SERVICE_TYPE);

        let endpoint = base64::engine::general_purpose::STANDARD.encode(token);
        let service = Service {
            id: format!("{}#device-attestation", self.id),
            service_type: DEVICE_ATTESTATION_SERVICE_TYPE.to_owned(),
            service_endpoint: endpoint,
            bridge_target: None,
        };
        self.service.push(service);
    }

    /// Returns `true` if this DID document contains a device attestation service entry.
    #[must_use]
    pub fn has_device_attestation(&self) -> bool {
        self.service
            .iter()
            .any(|s| s.service_type == DEVICE_ATTESTATION_SERVICE_TYPE)
    }

    /// Retires the current active signing key and installs a new one.
    ///
    /// This is used during Layer 1 key rotation (`rotate_active_key`).
    /// The old active key is moved to `#retired-{sequence}` and the new key
    /// becomes `#active`. Authentication and assertion method references are
    /// updated to point to the new active key.
    ///
    /// # Arguments
    ///
    /// * `new_active_public_key` - The raw 32-byte Ed25519 public key for the
    ///   new active signing key.
    /// * `sequence` - The rotation sequence number, used to name the retired key
    ///   fragment (e.g., `#retired-1`).
    pub fn retire_active_key(&mut self, new_active_public_key: &[u8], sequence: u64) {
        let did = &self.id;

        // Find the current #active verification method and rename it to #retired-{sequence}.
        for vm in &mut self.verification_method {
            if vm.id.ends_with("#active") {
                let retired_fragment = format!("retired-{sequence}");
                vm.id = format!("{did}#{retired_fragment}");
            }
        }

        // Add the new active verification method.
        let new_active_vm = VerificationMethod {
            id: format!("{did}#active"),
            method_type: ED25519_VERIFICATION_KEY_TYPE.to_owned(),
            controller: did.to_owned(),
            public_key_multibase: multibase_encode(new_active_public_key),
        };
        self.verification_method.push(new_active_vm);

        // Update authentication and assertionMethod to reference the new #active key.
        // Preserve the #agent reference if present (ADR-039).
        self.authentication = vec![format!("{did}#active")];
        self.assertion_method = vec![format!("{did}#active")];
        if self.has_agent_key() {
            self.authentication.push(format!("{did}#agent"));
            self.assertion_method.push(format!("{did}#agent"));
        }
    }

    /// Sets the `alsoKnownAs` field to point to a new DID.
    ///
    /// Used during Layer 2 identity migration to create a forwarding record
    /// from the old DID to the new DID.
    pub fn set_also_known_as(&mut self, new_did: &str) {
        self.also_known_as = vec![new_did.to_owned()];
    }

    /// Retires the `#active` and `#agent` operational keys for a
    /// migrated identity (spec §9.12, "compromise recovery").
    ///
    /// Removes both verification methods from `verification_method`
    /// and from the `authentication` / `assertion_method` arrays.
    /// `#0` (Identity Key) and any `#retired-*` / `#retired-agent-*`
    /// entries from prior Layer-1 rotations are preserved — `#0`
    /// continues to authorize `alsoKnownAs` republishes, and the
    /// retired-key history remains auditable.
    ///
    /// Used by `DidDht::migrate_identity` (in the downstream `scp-identity`
    /// crate) when republishing the
    /// OLD DID document with `alsoKnownAs` pointing at the new
    /// identity. After migration the OLD document's purpose is
    /// forwarding only; leaving `#active` / `#agent` listed as
    /// current verification methods would let a verifier resolving
    /// the OLD doc still treat those keys as authoritative even
    /// though their private bytes have been destroyed in custody
    /// (step 7b).
    pub fn retire_operational_keys_for_migration(&mut self) {
        // Remove `#active` and `#agent` verification methods.
        // Retired entries (`#retired-*`, `#retired-agent-*`) remain.
        //
        // Exact-fragment match (not `ends_with`) so a hypothetical
        // future fragment like `#secondary-active` or
        // `#auxiliary-agent` is not silently swept along with the
        // operational keys. Today the spec defines only `#0`,
        // `#active`, `#agent`, `#retired-N`, and `#retired-agent-N`,
        // so this is forward-compat hardening rather than a bug fix
        // against current data.
        self.verification_method.retain(|vm| {
            let frag = vm.id.rsplit('#').next().unwrap_or("");
            frag != "active" && frag != "agent"
        });
        self.authentication.retain(|reference| {
            let frag = reference.rsplit('#').next().unwrap_or("");
            frag != "active" && frag != "agent"
        });
        self.assertion_method.retain(|reference| {
            let frag = reference.rsplit('#').next().unwrap_or("");
            frag != "active" && frag != "agent"
        });
    }

    // --- Agent key management (ADR-039) ---

    /// Returns `true` if this document contains an `#agent` verification method.
    #[must_use]
    pub fn has_agent_key(&self) -> bool {
        self.verification_method
            .iter()
            .any(|vm| vm.id.ends_with("#agent"))
    }

    /// Returns the `#agent` verification method, if present.
    #[must_use]
    pub fn agent_verification_method(&self) -> Option<&VerificationMethod> {
        self.verification_method_by_fragment("agent")
    }

    /// Adds an `#agent` verification method to this document.
    ///
    /// The agent key is added to `authentication` and `assertionMethod`
    /// relationship arrays. Fails if an `#agent` VM already exists.
    ///
    /// Only `#0` (Identity Key) can authorize this operation — enforcement is
    /// at the signing/verification layer, not in this method.
    ///
    /// See ADR-039 acceptance criterion 4.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::AgentKeyAlreadyExists`] if an `#agent` VM
    /// is already present.
    pub fn add_agent_key(&mut self, public_key: &[u8]) -> Result<(), DidError> {
        if self.has_agent_key() {
            return Err(DidError::AgentKeyAlreadyExists);
        }

        let did = &self.id;
        let agent_vm = VerificationMethod {
            id: format!("{did}#agent"),
            method_type: ED25519_VERIFICATION_KEY_TYPE.to_owned(),
            controller: did.to_owned(),
            public_key_multibase: multibase_encode(public_key),
        };

        self.verification_method.push(agent_vm);
        self.authentication.push(format!("{did}#agent"));
        self.assertion_method.push(format!("{did}#agent"));

        Ok(())
    }

    /// Removes the `#agent` verification method from this document.
    ///
    /// Also removes `#agent` from `authentication` and `assertionMethod`
    /// arrays. Fails if no `#agent` VM exists. Does NOT remove retired agent
    /// keys (`#retired-agent-*`).
    ///
    /// Only `#0` (Identity Key) can authorize this operation — enforcement is
    /// at the signing/verification layer, not in this method.
    ///
    /// See ADR-039 acceptance criterion 4.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::AgentKeyNotFound`] if no `#agent` VM exists.
    pub fn remove_agent_key(&mut self) -> Result<(), DidError> {
        if !self.has_agent_key() {
            return Err(DidError::AgentKeyNotFound);
        }

        self.verification_method
            .retain(|vm| !vm.id.ends_with("#agent"));
        self.authentication
            .retain(|ref_id| !ref_id.ends_with("#agent"));
        self.assertion_method
            .retain(|ref_id| !ref_id.ends_with("#agent"));

        Ok(())
    }

    /// Rotates the `#agent` verification method, retaining the old key as a
    /// retired key.
    ///
    /// The old `#agent` key is renamed to `#retired-agent-{sequence}`. At most
    /// 2 retired agent keys are retained; older ones are pruned (bounded
    /// retention). The new key becomes `#agent`.
    ///
    /// Only `#0` (Identity Key) can authorize this operation — enforcement is
    /// at the signing/verification layer, not in this method.
    ///
    /// See ADR-039 acceptance criterion 4.
    ///
    /// # Arguments
    ///
    /// * `new_public_key` - The raw 32-byte Ed25519 public key for the new
    ///   agent signing key.
    /// * `sequence` - The rotation sequence number, used to name the retired
    ///   key fragment (e.g., `#retired-agent-1`).
    ///
    /// # Errors
    ///
    /// Returns [`DidError::AgentKeyNotFound`] if no `#agent` VM exists.
    pub fn rotate_agent_key(
        &mut self,
        new_public_key: &[u8],
        sequence: u64,
    ) -> Result<(), DidError> {
        if !self.has_agent_key() {
            return Err(DidError::AgentKeyNotFound);
        }

        let did = &self.id;

        // Rename current #agent to #retired-agent-{sequence}.
        for vm in &mut self.verification_method {
            if vm.id.ends_with("#agent") {
                vm.id = format!("{did}#retired-agent-{sequence}");
            }
        }

        // Add the new #agent verification method.
        let new_agent_vm = VerificationMethod {
            id: format!("{did}#agent"),
            method_type: ED25519_VERIFICATION_KEY_TYPE.to_owned(),
            controller: did.to_owned(),
            public_key_multibase: multibase_encode(new_public_key),
        };
        self.verification_method.push(new_agent_vm);

        // Prune retired agent keys to at most MAX_RETIRED_AGENT_KEYS.
        self.prune_retired_agent_keys();

        // authentication and assertionMethod already reference #agent by
        // fragment, so no update needed — the new VM takes over the reference.

        Ok(())
    }

    /// Validates that this document has at most one `#agent` verification method.
    ///
    /// Verifiers MUST call this on any resolved DID document per ADR-039
    /// structural constraint.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::MultipleAgentKeys`] if more than one `#agent`
    /// VM is found.
    pub fn validate_agent_keys(&self) -> Result<(), DidError> {
        let agent_count = self
            .verification_method
            .iter()
            .filter(|vm| vm.id.ends_with("#agent"))
            .count();

        if agent_count > 1 {
            return Err(DidError::MultipleAgentKeys { count: agent_count });
        }

        Ok(())
    }

    /// Returns the number of retired agent keys (`#retired-agent-*`) in this
    /// document.
    #[must_use]
    pub fn retired_agent_key_count(&self) -> usize {
        self.verification_method
            .iter()
            .filter(|vm| {
                // Match #retired-agent-{N} but not #retired-{N} (which are
                // retired active keys from retire_active_key).
                let Some(fragment) = vm.id.rsplit_once('#').map(|(_, f)| f) else {
                    return false;
                };
                fragment.starts_with("retired-agent-")
            })
            .count()
    }

    /// Prunes retired agent keys to at most [`MAX_RETIRED_AGENT_KEYS`],
    /// keeping the most recent (highest sequence number).
    fn prune_retired_agent_keys(&mut self) {
        // Collect (index, sequence) pairs for retired agent keys.
        let mut retired: Vec<(usize, u64)> = self
            .verification_method
            .iter()
            .enumerate()
            .filter_map(|(i, vm)| {
                let fragment = vm.id.rsplit_once('#').map(|(_, f)| f)?;
                let seq_str = fragment.strip_prefix("retired-agent-")?;
                let seq: u64 = seq_str.parse().ok()?;
                Some((i, seq))
            })
            .collect();

        if retired.len() <= MAX_RETIRED_AGENT_KEYS {
            return;
        }

        // Sort by sequence descending — keep the highest.
        retired.sort_by_key(|entry| std::cmp::Reverse(entry.1));

        // Indices to remove (the ones beyond the retention limit).
        let mut remove_indices: Vec<usize> = retired[MAX_RETIRED_AGENT_KEYS..]
            .iter()
            .map(|(i, _)| *i)
            .collect();

        // Sort descending so removal doesn't shift earlier indices.
        remove_indices.sort_unstable_by(|a, b| b.cmp(a));
        for idx in remove_indices {
            self.verification_method.remove(idx);
        }
    }
}

/// A DID rotation event distributed to all active contexts during identity
/// migration (Layer 2 rotation).
///
/// Contains the old and new DID strings, cryptographic proofs of the migration,
/// and a timestamp. Context participants use `verify_migration` to verify the
/// proofs before accepting the new DID.
///
/// See ADR-003 acceptance criterion 4b.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DidRotationEvent {
    /// The DID being migrated from.
    pub old_did: String,
    /// The new DID being migrated to.
    pub new_did: String,
    /// Cryptographic proof that the old Identity Key authorized the migration.
    pub migration_proof: MigrationProof,
    /// Optional pre-rotation proof for STRONG assurance.
    /// If present, verifies that the new Identity Key was pre-committed in the
    /// old DID document's `PreRotationCommitment` service.
    pub pre_rotation_proof: Option<PreRotationProof>,
    /// Unix timestamp (seconds) when the rotation occurred.
    pub rotated_at: u64,
}

/// Proof that the old Identity Key authorized a migration to a new DID.
///
/// The signature covers
/// `SHA-256(DOMAIN_MIGRATION_V1 || u32_be(len(old_did)) || old_did ||
/// u32_be(len(new_did)) || new_did || u64_be(rotated_at))` and is signed
/// by the old Identity Key. Length prefixes (u32 big-endian for the
/// variable-length DID strings and the implicit u64 big-endian width of
/// `rotated_at`) prevent concatenation ambiguity between adjacent
/// variable-length fields. This provides MODERATE assurance that the
/// migration was authorized by the DID owner. The `DOMAIN_MIGRATION_V1`
/// domain separator prevents cross-protocol signature confusion.
///
/// See ADR-003 acceptance criterion 4c.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationProof {
    /// Ed25519 signature of
    /// `SHA-256(DOMAIN_MIGRATION_V1 || u32_be(len(old_did)) || old_did ||
    /// u32_be(len(new_did)) || new_did || u64_be(rotated_at))` signed by
    /// the old Identity Key. Must be exactly 64 bytes (Ed25519). Wire
    /// format: lowercase hex string.
    #[serde(with = "serde_hex_array::array64")]
    pub signature: [u8; 64],
    /// The old Identity Key's public bytes, for verification without resolving
    /// the old DID document. Wire format: lowercase hex string.
    #[serde(with = "serde_hex_array::array32")]
    pub old_public_key: [u8; 32],
}

/// Pre-rotation proof providing STRONG assurance for identity migration.
///
/// Verifies that the new Identity Key was pre-committed in the old DID
/// document's `PreRotationCommitment` service: `SHA-256(revealed_key)` must
/// equal the `commitment` from the service endpoint.
///
/// See ADR-003 acceptance criterion 4c.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreRotationProof {
    /// The commitment published in the old DID document's
    /// `PreRotationCommitment` service (`sha256:<hex>`). Wire format:
    /// lowercase hex string.
    #[serde(with = "serde_hex_array::array32")]
    pub commitment: [u8; 32],
    /// The new Identity Key public bytes. `SHA-256(this)` must equal
    /// `commitment`. Wire format: lowercase hex string.
    #[serde(with = "serde_hex_array::array32")]
    pub revealed_key: [u8; 32],
}

/// Encodes raw bytes as a multibase string with `z` (base58btc) prefix.
///
/// Uses the `z` prefix per the Multibase specification for base58btc encoding.
fn multibase_encode(bytes: &[u8]) -> String {
    // Multibase `z` prefix indicates base58btc encoding.
    // We use a simple base58 implementation inline to avoid adding a dependency.
    format!("z{}", base58btc_encode(bytes))
}

/// Base58btc encoding (Bitcoin alphabet) via the `bs58` crate.
fn base58btc_encode(input: &[u8]) -> String {
    bs58::encode(input).into_string()
}

/// Decodes a multibase-encoded public key (z-prefix = base58btc).
///
/// Beyond the encoding check, the decoded 32-byte payload is validated
/// as an Ed25519 Edwards-curve point via
/// `ed25519_dalek::VerifyingKey::from_bytes`. This rejects non-curve
/// payloads only (ZIP-215 rules) — low-order / small-subgroup points
/// are NOT rejected here; they are caught at signature verification
/// time via `verify_strict`. Matches the `from_did`
/// curve-point gate so both decoding entry points behave consistently.
///
/// # Errors
///
/// Returns [`DidError::InvalidDidFormat`] if the key is not properly
/// base58btc encoded, not exactly 32 bytes, or does not decompress to a
/// valid Ed25519 Edwards-curve point.
pub fn decode_multibase_key(encoded: &str) -> Result<[u8; 32], DidError> {
    let b58_str = encoded.strip_prefix('z').ok_or_else(|| {
        DidError::InvalidDidFormat("multibase key must start with 'z' (base58btc)".to_owned())
    })?;

    let decoded = base58btc_decode(b58_str)
        .map_err(|e| DidError::InvalidDidFormat(format!("base58btc decode failed: {e}")))?;

    let decoded_array: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
        DidError::InvalidDidFormat(format!("expected 32-byte key, got {} bytes", v.len()))
    })?;

    // Curve-point validation: `ed25519_dalek::VerifyingKey::from_bytes`
    // rejects byte strings that don't decompress to an Edwards-curve
    // point (ZIP-215 rules). Low-order / small-subgroup points are NOT
    // rejected here — they are caught at signature verification time
    // via `verify_strict`. Matches the `from_did_inner` gate so
    // both decoding entry points reject non-curve payloads early.
    ed25519_dalek::VerifyingKey::from_bytes(&decoded_array).map_err(|e| {
        DidError::InvalidDidFormat(format!(
            "multibase key payload is not a valid Ed25519 public key: {e}"
        ))
    })?;

    Ok(decoded_array)
}

/// Base58btc decoding (Bitcoin alphabet) via the `bs58` crate.
///
/// Inverse of the `base58btc_encode` function above.
fn base58btc_decode(input: &str) -> Result<Vec<u8>, String> {
    bs58::decode(input)
        .into_vec()
        .map_err(|e| format!("base58btc decode error: {e}"))
}

/// Parses an `SCPBroadcastContext` service endpoint string into
/// `(context_id, relay_urls)`.
///
/// Expected format: `scp:context:<context_id>?relay=<url1>&relay=<url2>`
///
/// Returns `None` if the format is invalid.
fn parse_broadcast_context_endpoint(endpoint: &str) -> Option<(String, Vec<String>)> {
    let rest = endpoint.strip_prefix("scp:context:")?;

    // Split on '?' to separate context_id from query parameters.
    let (context_id, query) = match rest.split_once('?') {
        Some((id, q)) => (id, q),
        None => (rest, ""),
    };

    if context_id.is_empty() {
        return None;
    }

    let mut relay_urls = Vec::new();
    if !query.is_empty() {
        for param in query.split('&') {
            if let Some(value) = param.strip_prefix("relay=") {
                let decoded = value.replace("%3A", ":").replace("%2F", "/");
                relay_urls.push(decoded);
            }
        }
    }

    Some((context_id.to_owned(), relay_urls))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use crate::relay_url::RelayUrlError;

    #[test]
    fn document_has_correct_structure() {
        let did = "did:dht:zTestDid123";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let commitment = [3u8; 32];

        let doc = DidDocument::new(did, &identity_pk, &active_pk, &commitment);

        assert_eq!(doc.id, did);
        assert_eq!(doc.context.len(), 2);
        assert_eq!(doc.verification_method.len(), 2);
        assert_eq!(doc.authentication, vec![format!("{did}#active")]);
        assert_eq!(doc.assertion_method, vec![format!("{did}#active")]);
        assert_eq!(doc.service.len(), 1);

        // Identity Key is #0
        let vm0 = doc.verification_method_by_fragment("0").unwrap();
        assert_eq!(vm0.id, format!("{did}#0"));
        assert_eq!(vm0.controller, did);
        assert!(vm0.public_key_multibase.starts_with('z'));

        // Active Key is #active
        let vm_active = doc.verification_method_by_fragment("active").unwrap();
        assert_eq!(vm_active.id, format!("{did}#active"));
        assert_eq!(vm_active.controller, did);
        assert!(vm_active.public_key_multibase.starts_with('z'));

        // Pre-rotation service
        let svc = doc.pre_rotation_service().unwrap();
        assert_eq!(svc.service_type, "PreRotationCommitment");
        assert!(svc.service_endpoint.starts_with("sha256:"));
    }

    #[test]
    fn document_json_roundtrip() {
        let did = "did:dht:zTestRoundtrip";
        let identity_pk = [10u8; 32];
        let active_pk = [20u8; 32];
        let commitment = [30u8; 32];

        let doc = DidDocument::new(did, &identity_pk, &active_pk, &commitment);
        let json = doc.to_json().unwrap();
        let parsed = DidDocument::from_json(&json).unwrap();

        assert_eq!(doc, parsed);
    }

    #[test]
    fn multibase_encode_starts_with_z() {
        let bytes = [1u8; 32];
        let encoded = multibase_encode(&bytes);
        assert!(encoded.starts_with('z'));
    }

    #[test]
    fn base58btc_encode_handles_empty_input() {
        assert_eq!(base58btc_encode(&[]), "");
    }

    #[test]
    fn base58btc_encode_handles_leading_zeros() {
        // Leading zero bytes map to '1' characters in base58.
        let input = [0, 0, 1];
        let encoded = base58btc_encode(&input);
        assert!(encoded.starts_with("11"));
    }

    #[test]
    fn base58btc_encode_known_vector() {
        // "Hello World" in base58btc (Bitcoin alphabet) is "JxF12TrwUP45BMd".
        assert_eq!(base58btc_encode(b"Hello World"), "JxF12TrwUP45BMd");
    }

    #[test]
    fn base58btc_encode_single_byte() {
        // 0x00 encodes to "1", 0x01 encodes to "2", etc.
        assert_eq!(base58btc_encode(&[0x00]), "1");
        assert_eq!(base58btc_encode(&[0x01]), "2");
    }

    // --- SCPRelay tests (SCP-140, SCP-328) ---

    fn relay(url: &str) -> RelayService {
        RelayService::direct(RelayEndpoint::new(url).unwrap())
    }

    fn bridge(url: &str, target: [u8; 32]) -> RelayService {
        RelayService::bridge(
            BridgeEndpoint::new(url).unwrap(),
            BridgeTarget::new(target).unwrap(),
        )
    }

    fn relay_doc(did: &str) -> DidDocument {
        DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32])
    }

    /// A raw `SCPRelay` entry that bypasses `RelayService`, as a resolved
    /// record written by another implementation can hold.
    fn raw_relay_entry(did: &str, n: usize, url: &str, bridge_target: Option<[u8; 32]>) -> Service {
        Service {
            id: format!("{did}#scp-relay-{n}"),
            service_type: "SCPRelay".to_owned(),
            service_endpoint: url.to_owned(),
            bridge_target,
        }
    }

    /// The reason of a [`DidError::InvalidRelayUrl`], or `None` for any other
    /// result.
    fn url_reason<T>(result: &Result<T, DidError>) -> Option<RelayEntryUrlError> {
        match result {
            Err(DidError::InvalidRelayUrl { reason, .. }) => Some(*reason),
            _ => None,
        }
    }

    const BRIDGE_URL: &str = "wss://bridge.example.com/scp/v1";
    const TARGET: [u8; 32] = [0xab; 32];

    #[test]
    fn mixed_services_roundtrip() {
        let mut doc = relay_doc("did:dht:zMixedServices");
        doc.add_relay_service(&relay("wss://relay1.example.com/scp/v1"));
        doc.add_relay_service(&relay("wss://relay2.example.com/scp/v1"));

        // Should have PreRotationCommitment + 2 SCPRelay entries.
        assert_eq!(doc.service.len(), 3);

        let json = doc.to_json().unwrap();
        let parsed = DidDocument::from_json(&json).unwrap();
        assert_eq!(doc, parsed);
        assert!(parsed.pre_rotation_service().is_some());
        assert_eq!(parsed.relay_service_urls().len(), 2);
    }

    #[test]
    fn relay_service_urls_filters_correctly() {
        let mut doc = relay_doc("did:dht:zRelayFilter");
        doc.add_relay_service(&relay("wss://relay.example.com/scp/v1"));

        assert_eq!(doc.relay_service_urls(), ["wss://relay.example.com/scp/v1"]);
        // The pre-rotation entry is not a relay entry.
        assert!(doc.pre_rotation_service().is_some());
    }

    #[test]
    fn relay_endpoint_accepts_ws_address_literal() {
        for url in [
            "ws://192.0.2.7:8080/scp/v1",
            "ws://[2001:db8::1]:9000/scp/v1",
            "wss://relay.example.com/scp/v1",
        ] {
            let relay = relay(url);
            assert_eq!(relay.url(), url);
            assert_eq!(relay.bridge_target(), None);
        }
        for url in [
            "http://relay.example.com/scp/v1",
            "https://relay.example.com/scp/v1",
        ] {
            assert_eq!(
                url_reason(&RelayEndpoint::new(url)),
                Some(RelayEntryUrlError::Canonical(
                    RelayUrlError::UnsupportedScheme
                )),
                "{url}"
            );
        }
    }

    #[test]
    fn relay_endpoint_holds_the_canonical_form() {
        let endpoint = RelayEndpoint::new("WSS://Relay.Example.com:443/scp/v1/").unwrap();
        assert_eq!(endpoint.as_str(), "wss://relay.example.com/scp/v1");
        assert_eq!(
            endpoint,
            RelayEndpoint::new("wss://relay.example.com/scp/v1").unwrap()
        );
    }

    #[test]
    fn relay_endpoint_new_rejects_a_path_without_scp_v1() {
        // `wss://scp/v1` has host `scp` and path `/v1`: the whole string ends
        // in `/scp/v1`, but its path does not.
        for url in [
            "wss://relay.example.com/other",
            "wss://relay.example.com",
            "wss://scp/v1",
        ] {
            assert_eq!(
                url_reason(&RelayEndpoint::new(url)),
                Some(RelayEntryUrlError::PathNotScpV1),
                "{url}"
            );
        }
        // A trailing `/` canonicalizes away, so the path still ends in /scp/v1.
        assert!(RelayEndpoint::new("wss://relay.example.com/scp/v1/").is_ok());
    }

    #[test]
    fn relay_endpoint_new_rejects_query_fragment_and_userinfo() {
        let query = format!("{BRIDGE_URL}?bridge_target={}", "ab".repeat(32));
        for (url, want) in [
            (query.as_str(), RelayUrlError::QueryOrFragment),
            (
                "wss://bridge.example.com/scp/v1#x",
                RelayUrlError::QueryOrFragment,
            ),
            ("wss://u@h/scp/v1", RelayUrlError::UserInfo),
        ] {
            assert_eq!(
                url_reason(&RelayEndpoint::new(url)),
                Some(RelayEntryUrlError::Canonical(want)),
                "{url}"
            );
        }
        // The error never repeats user information.
        let err = RelayEndpoint::new("wss://user:secret@h.example/scp/v1").unwrap_err();
        let DidError::InvalidRelayUrl { url, .. } = &err else {
            panic!("{err:?}");
        };
        assert_eq!(url, "wss://h.example/scp/v1");
        assert!(!err.to_string().contains("secret"), "{err}");
    }

    #[test]
    fn invalid_relay_url_error_escapes_control_characters() {
        let err =
            RelayEndpoint::new("wss://relay.example.com/scp/v1\n\u{1b}[31mforged").unwrap_err();
        let shown = err.to_string();
        assert!(
            !shown.contains('\n') && !shown.contains('\u{1b}'),
            "{shown:?}"
        );
    }

    #[test]
    fn bridge_endpoint_rejects_plaintext_ws() {
        assert_eq!(
            url_reason(&BridgeEndpoint::new("ws://bridge.example.com/scp/v1")),
            Some(RelayEntryUrlError::PlaintextBridge)
        );
        assert_eq!(
            url_reason(&BridgeEndpoint::new("ws://192.0.2.7:8080/scp/v1")),
            Some(RelayEntryUrlError::PlaintextBridge)
        );
        assert_eq!(
            BridgeEndpoint::new(BRIDGE_URL).unwrap().as_str(),
            BRIDGE_URL
        );

        // A resolved ws:// entry carrying a target is dropped; the record stays.
        let did = "did:dht:zPlainBridge";
        let mut doc = relay_doc(did);
        doc.service.push(raw_relay_entry(
            did,
            1,
            "ws://bridge.example.com/scp/v1",
            Some(TARGET),
        ));
        doc.add_relay_service(&relay("wss://plain.example.com/scp/v1"));
        let parsed = DidDocument::from_json(&doc.to_json().unwrap()).unwrap();
        // The parse drops the entry itself (§18.2.1, §10.12.7), so no reader
        // of `service` sees it.
        assert!(
            !parsed
                .service
                .iter()
                .any(|s| s.service_endpoint == "ws://bridge.example.com/scp/v1"),
            "{:?}",
            parsed.service
        );
        assert_eq!(
            parsed.relay_services(),
            [relay("wss://plain.example.com/scp/v1")]
        );
    }

    #[test]
    fn bridge_target_new_rejects_the_absent_sentinel() {
        use sha2::{Digest, Sha256};
        let sentinel: [u8; 32] = Sha256::digest([0u8]).into();
        assert_eq!(ABSENT_BRIDGE_TARGET, sentinel);

        assert_eq!(
            BridgeTarget::new(sentinel),
            Err(DidError::AbsentSentinelBridgeTarget)
        );
        assert_eq!(BridgeTarget::new(TARGET).unwrap().to_bytes(), TARGET);

        // A resolved record carrying the sentinel loses that entry and keeps
        // its other entries.
        let did = "did:dht:zSentinel";
        let mut doc = relay_doc(did);
        doc.service
            .push(raw_relay_entry(did, 1, BRIDGE_URL, Some(sentinel)));
        doc.add_relay_service(&relay("wss://plain.example.com/scp/v1"));
        let parsed = DidDocument::from_json(&doc.to_json().unwrap()).unwrap();
        assert_eq!(
            parsed.relay_services(),
            [relay("wss://plain.example.com/scp/v1")]
        );
        assert!(
            parsed
                .service
                .iter()
                .all(|s| s.bridge_target != Some(sentinel))
        );
        assert!(parsed.pre_rotation_service().is_some());
    }

    #[test]
    fn bridge_relay_service_round_trips_through_json() {
        let did = "did:dht:zBridgeRoundTrip";
        let mut doc = relay_doc(did);
        let plain = relay("wss://plain.example.com/scp/v1");
        let bridge = bridge(BRIDGE_URL, TARGET);
        doc.add_relay_service(&plain);
        doc.add_relay_service(&bridge);

        let json = doc.to_json().unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let entries: Vec<&serde_json::Value> = value["service"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["type"] == "SCPRelay")
            .collect();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].get("bridgeTarget").is_none());
        assert_eq!(entries[1]["serviceEndpoint"], BRIDGE_URL);
        assert_eq!(entries[1]["bridgeTarget"], "ab".repeat(32));

        let parsed = DidDocument::from_json(&json).unwrap();
        assert_eq!(parsed, doc);
        assert_eq!(parsed.relay_services(), [plain, bridge]);
    }

    #[test]
    fn bridge_target_rejects_uppercase_wrong_length_and_non_hex() {
        let did = "did:dht:zBadSpelling";
        let mut doc = relay_doc(did);
        doc.add_relay_service(&relay("wss://first.example.com/scp/v1"));
        doc.add_relay_service(&bridge(BRIDGE_URL, TARGET));
        doc.add_relay_service(&relay("wss://third.example.com/scp/v1"));
        let good = doc.to_json().unwrap();
        let good_hex = "ab".repeat(32);
        assert_eq!(DidDocument::from_json(&good).unwrap(), doc);

        for bad in [
            format!("\"{}\"", "ab".repeat(31)),
            format!("\"{}\"", "AB".repeat(32)),
            format!("\"{}\"", "ab".repeat(33)),
            format!("\"{}\"", "zz".repeat(32)),
            "null".to_owned(),
            "171".to_owned(),
            "[\"ab\", {\"x\": [1, 2]}]".to_owned(),
            "{\"hex\": \"ab\"}".to_owned(),
        ] {
            let json = good.replace(&format!("\"{good_hex}\""), &bad);
            assert_ne!(json, good);
            let parsed = DidDocument::from_json(&json).unwrap_or_else(|e| panic!("{bad}: {e}"));
            assert_eq!(
                parsed.relay_service_urls(),
                [
                    "wss://first.example.com/scp/v1",
                    "wss://third.example.com/scp/v1"
                ],
                "{bad}"
            );
            assert_eq!(parsed.service.len(), 3, "{bad}");
            assert!(parsed.pre_rotation_service().is_some(), "{bad}");
        }
    }

    #[test]
    fn relay_services_skips_an_entry_whose_url_carries_bridge_target() {
        let did = "did:dht:zQueryEntry";
        let mut doc = relay_doc(did);
        doc.add_relay_service(&relay("wss://first.example.com/scp/v1"));
        let query = format!("{BRIDGE_URL}?bridge_target={}", "ab".repeat(32));
        doc.service.push(raw_relay_entry(did, 2, &query, None));
        doc.add_relay_service(&relay("wss://third.example.com/scp/v1"));

        // An in-memory document still holds the entry, and relay_services()
        // leaves it out.
        assert_eq!(
            doc.relay_services(),
            [
                relay("wss://first.example.com/scp/v1"),
                relay("wss://third.example.com/scp/v1")
            ]
        );

        // Deserializing drops it and keeps the record.
        let parsed = DidDocument::from_json(&doc.to_json().unwrap()).unwrap();
        assert_eq!(parsed.service.len(), 3, "pre-rotation plus two relays");
        assert_eq!(
            parsed.relay_service_urls(),
            [
                "wss://first.example.com/scp/v1",
                "wss://third.example.com/scp/v1"
            ]
        );
        assert!(parsed.service.iter().all(|s| s.service_endpoint != query));
    }

    /// One row per service type with a typed accessor: an entry of that type
    /// carrying `bridgeTarget` is dropped at deserialization, the accessor
    /// reports nothing, and the record's other entries remain.
    #[test]
    fn bridge_target_on_a_non_relay_entry_drops_the_entry() {
        use crate::attestation::{KeyCustodyModel, Platform, ScpKeyCustodyAttestation};

        type Absent = fn(&DidDocument) -> bool;
        let rows: [(&str, Absent); 5] = [
            ("PreRotationCommitment", |d| {
                d.pre_rotation_service().is_none()
            }),
            ("SCPBroadcastContext", |d| {
                d.broadcast_context_entries().is_empty()
            }),
            ("ScpKeyCustodyAttestation", |d| {
                d.custody_attestation().unwrap().is_none()
            }),
            ("ScpIdentityLinkAttestation", |d| {
                d.identity_link_attestations().is_empty()
                    && d.identity_link_attestation_count() == 0
            }),
            ("ScpDeviceAttestation", |d| {
                !d.has_device_attestation() && d.device_attestation_token().unwrap().is_none()
            }),
        ];

        let did = "did:dht:zNonRelayTarget";
        let mut doc = relay_doc(did);
        doc.add_relay_service(&relay("wss://relay.example.com/scp/v1"));
        doc.add_broadcast_context_service("c0ffee", &["wss://relay.example.com/scp/v1".to_owned()]);
        doc.set_custody_attestation(&ScpKeyCustodyAttestation {
            active_key_custody: KeyCustodyModel::HardwareBiometric,
            agent_key_custody: None,
            platform: Platform::Ios,
            platform_attestation: None,
            created_at: 1_700_000_000,
        })
        .unwrap();
        doc.set_identity_link_attestation("github.com", "abc123")
            .unwrap();
        doc.set_device_attestation_token(b"token");
        let clean = DidDocument::from_json(&doc.to_json().unwrap()).unwrap();
        for (service_type, absent) in rows {
            assert!(
                !absent(&clean),
                "{service_type}: the fixture must carry the entry"
            );
        }

        for (service_type, absent) in rows {
            let mut value: serde_json::Value =
                serde_json::from_str(&doc.to_json().unwrap()).unwrap();
            let mut tagged = 0;
            for entry in value["service"].as_array_mut().unwrap() {
                if entry["type"] == service_type {
                    entry["bridgeTarget"] = serde_json::Value::String("ab".repeat(32));
                    tagged += 1;
                }
            }
            assert_eq!(tagged, 1, "{service_type}");

            let parsed = DidDocument::from_json(&value.to_string()).unwrap();
            assert!(
                absent(&parsed),
                "{service_type}: the accessor still reads the entry"
            );
            assert!(
                parsed
                    .service
                    .iter()
                    .all(|s| s.service_type != service_type),
                "{service_type}"
            );
            assert_eq!(
                parsed.service.len(),
                clean.service.len() - 1,
                "{service_type}"
            );
            assert_eq!(
                parsed.relay_service_urls(),
                ["wss://relay.example.com/scp/v1"],
                "{service_type}"
            );
        }
    }

    #[test]
    fn a_rejected_entry_is_dropped_from_a_messagepack_document() {
        let did = "did:dht:zMsgpack";
        let mut doc = relay_doc(did);
        doc.add_relay_service(&bridge(BRIDGE_URL, TARGET));
        doc.service.push(raw_relay_entry(
            did,
            2,
            BRIDGE_URL,
            Some(ABSENT_BRIDGE_TARGET),
        ));
        let bytes = rmp_serde::to_vec_named(&doc).unwrap();
        let parsed: DidDocument = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(parsed.relay_services(), [bridge(BRIDGE_URL, TARGET)]);
        assert_eq!(parsed.service.len(), 2);
    }

    #[test]
    fn set_preferred_relay_repoints_the_first_relay_entry() {
        let did = "did:dht:zPreferred";
        let mut doc = relay_doc(did);
        // With no relay entry, the relay is inserted.
        doc.set_preferred_relay(&bridge(BRIDGE_URL, TARGET));
        assert_eq!(doc.relay_services(), [bridge(BRIDGE_URL, TARGET)]);
        doc.add_relay_service(&relay("wss://second.example.com/scp/v1"));

        // A move to a direct relay rewrites the first entry in place and
        // clears its bridgeTarget; the id and the second entry stay.
        doc.set_preferred_relay(&relay("ws://192.0.2.7:8080/scp/v1"));
        let first = doc
            .service
            .iter()
            .find(|s| s.service_type == SCP_RELAY_SERVICE_TYPE)
            .unwrap();
        assert_eq!(first.id, format!("{did}#scp-relay-1"));
        assert_eq!(first.bridge_target, None);
        assert_eq!(
            doc.relay_services(),
            [
                relay("ws://192.0.2.7:8080/scp/v1"),
                relay("wss://second.example.com/scp/v1")
            ]
        );

        // Repeating the call changes nothing.
        let before = doc.clone();
        doc.set_preferred_relay(&relay("ws://192.0.2.7:8080/scp/v1"));
        assert_eq!(doc, before);
    }

    #[test]
    fn insert_preferred_relay_goes_ahead_of_existing_relays() {
        let did = "did:dht:zInsert";
        let mut doc = relay_doc(did);
        doc.add_relay_service(&relay("wss://callers.example.com/scp/v1"));
        doc.insert_preferred_relay(&bridge(BRIDGE_URL, TARGET));
        assert_eq!(
            doc.relay_services(),
            [
                bridge(BRIDGE_URL, TARGET),
                relay("wss://callers.example.com/scp/v1")
            ]
        );
        let ids: Vec<&str> = doc
            .service
            .iter()
            .filter(|s| s.service_type == SCP_RELAY_SERVICE_TYPE)
            .map(|s| s.id.as_str())
            .collect();
        assert_eq!(
            ids,
            [format!("{did}#scp-relay-2"), format!("{did}#scp-relay-1")]
        );
    }

    #[test]
    fn multiple_relay_entries_preserve_insertion_order() {
        let did = "did:dht:zOrderTest";
        let mut doc = relay_doc(did);
        doc.add_relay_service(&relay("wss://preferred.example.com/scp/v1"));
        doc.add_relay_service(&relay("wss://secondary.example.com/scp/v1"));
        doc.add_relay_service(&relay("wss://tertiary.example.com/scp/v1"));

        // First entry = preferred relay per §18.2.3.
        assert_eq!(
            doc.relay_service_urls(),
            [
                "wss://preferred.example.com/scp/v1",
                "wss://secondary.example.com/scp/v1",
                "wss://tertiary.example.com/scp/v1"
            ]
        );

        let ids: Vec<&str> = doc
            .service
            .iter()
            .filter(|s| s.service_type == "SCPRelay")
            .map(|s| s.id.as_str())
            .collect();
        assert_eq!(
            ids,
            [
                format!("{did}#scp-relay-1"),
                format!("{did}#scp-relay-2"),
                format!("{did}#scp-relay-3")
            ]
        );
    }

    #[test]
    fn scp_relay_is_distinct_from_other_service_types() {
        let mut doc = relay_doc("did:dht:zDistinct");
        doc.add_relay_service(&relay("wss://relay.example.com/scp/v1"));

        let relay_svc = doc
            .service
            .iter()
            .find(|s| s.service_type == "SCPRelay")
            .unwrap();
        let pre_rot_svc = doc.pre_rotation_service().unwrap();
        assert_ne!(relay_svc.service_type, pre_rot_svc.service_type);
        assert_eq!(pre_rot_svc.service_type, "PreRotationCommitment");

        let json = doc.to_json().unwrap();
        assert!(json.contains("\"SCPRelay\""));
        assert!(json.contains("\"PreRotationCommitment\""));
    }

    // --- set_relay_services tests (SCP-141) ---

    #[test]
    fn set_relay_services_replaces_existing_relay_entries() {
        let mut doc = relay_doc("did:dht:zSetRelay");
        doc.add_relay_service(&relay("wss://old-relay.example.com/scp/v1"));

        let bridge = bridge(BRIDGE_URL, TARGET);
        doc.set_relay_services(&[relay("wss://new1.example.com/scp/v1"), bridge.clone()]);

        assert_eq!(
            doc.relay_services(),
            [relay("wss://new1.example.com/scp/v1"), bridge]
        );
        assert!(doc.pre_rotation_service().is_some());
    }

    #[test]
    fn set_relay_services_with_empty_removes_all() {
        let mut doc = relay_doc("did:dht:zSetEmpty");
        doc.add_relay_service(&relay("wss://relay.example.com/scp/v1"));

        doc.set_relay_services(&[]);
        assert!(doc.relay_service_urls().is_empty());
        // Only PreRotationCommitment remains.
        assert_eq!(doc.service.len(), 1);
        assert!(doc.pre_rotation_service().is_some());
    }

    // --- MigrationProof.signature [u8; 64] hex-string tests ---

    /// Helper: build a JSON object for `MigrationProof` with a signature
    /// of the given byte length, hex-encoded. The `old_public_key` is
    /// always a valid 32-byte array (hex-encoded).
    fn migration_proof_json_with_sig_len(byte_len: usize) -> String {
        let sig_bytes: Vec<u8> = (0..byte_len).map(|i| (i % 256) as u8).collect();
        let pk_bytes: Vec<u8> = (0..32).map(|_| 1u8).collect();
        format!(
            r#"{{"signature":"{}","old_public_key":"{}"}}"#,
            hex::encode(&sig_bytes),
            hex::encode(&pk_bytes)
        )
    }

    #[test]
    fn migration_proof_64_byte_signature_accepted() {
        let json = migration_proof_json_with_sig_len(64);
        let proof: MigrationProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof.signature.len(), 64);
        for (i, &b) in proof.signature.iter().enumerate() {
            assert_eq!(b, (i % 256) as u8);
        }
    }

    #[test]
    fn migration_proof_63_byte_signature_rejected() {
        let json = migration_proof_json_with_sig_len(63);
        let result = serde_json::from_str::<MigrationProof>(&json);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("64-byte"),
            "error should mention 64-byte, got: {err_msg}"
        );
    }

    #[test]
    fn migration_proof_65_byte_signature_rejected() {
        let json = migration_proof_json_with_sig_len(65);
        let result = serde_json::from_str::<MigrationProof>(&json);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("64-byte"),
            "error should mention 64-byte, got: {err_msg}"
        );
    }

    #[test]
    fn migration_proof_invalid_hex_rejected() {
        // Non-hex character in signature.
        let json = r#"{"signature":"zzzz","old_public_key":"01010101010101010101010101010101010101010101010101010101010101"}"#;
        let result = serde_json::from_str::<MigrationProof>(json);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("invalid hex"),
            "error should mention invalid hex, got: {err_msg}"
        );
    }

    #[test]
    fn migration_proof_signature_json_roundtrip() {
        let proof = MigrationProof {
            signature: [0xAA; 64],
            old_public_key: [0xBB; 32],
        };
        let json = serde_json::to_string(&proof).unwrap();
        // Wire format must be hex strings, not byte arrays.
        assert!(json.contains("\"aaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(json.contains("\"bbbbbbbbbbbbbbbb"));
        assert!(!json.contains('['));
        let parsed: MigrationProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, parsed);
    }

    #[test]
    fn pre_rotation_proof_json_roundtrip() {
        let proof = PreRotationProof {
            commitment: [0xCC; 32],
            revealed_key: [0xDD; 32],
        };
        let json = serde_json::to_string(&proof).unwrap();
        // Wire format must be hex strings.
        assert!(json.contains("\"cccccccccccccccc"));
        assert!(json.contains("\"dddddddddddddddd"));
        let parsed: PreRotationProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, parsed);
    }

    // --- Agent key tests (ADR-039, SCP-AB-008) ---

    #[test]
    fn document_with_agent_key_has_three_vms() {
        let did = "did:dht:zAgentDoc";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let agent_pk = [3u8; 32];
        let commitment = [4u8; 32];

        let doc = DidDocument::new_with_agent_key(
            did,
            &identity_pk,
            &active_pk,
            &commitment,
            Some(&agent_pk),
        );

        // 3 verification methods: #0, #active, #agent
        assert_eq!(doc.verification_method.len(), 3);

        let vm0 = doc.verification_method_by_fragment("0").unwrap();
        assert_eq!(vm0.id, format!("{did}#0"));

        let vm_active = doc.verification_method_by_fragment("active").unwrap();
        assert_eq!(vm_active.id, format!("{did}#active"));

        let vm_agent = doc.verification_method_by_fragment("agent").unwrap();
        assert_eq!(vm_agent.id, format!("{did}#agent"));
        assert_eq!(vm_agent.controller, did);
        assert!(vm_agent.public_key_multibase.starts_with('z'));

        // #active and #agent in authentication and assertionMethod
        assert_eq!(doc.authentication.len(), 2);
        assert!(doc.authentication.contains(&format!("{did}#active")));
        assert!(doc.authentication.contains(&format!("{did}#agent")));

        assert_eq!(doc.assertion_method.len(), 2);
        assert!(doc.assertion_method.contains(&format!("{did}#active")));
        assert!(doc.assertion_method.contains(&format!("{did}#agent")));

        // has_agent_key and agent_verification_method
        assert!(doc.has_agent_key());
        assert!(doc.agent_verification_method().is_some());

        // validation passes
        doc.validate_agent_keys().unwrap();
    }

    #[test]
    fn document_without_agent_key_has_two_vms() {
        let did = "did:dht:zNoAgent";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let commitment = [3u8; 32];

        // Using new() (backward compat)
        let doc = DidDocument::new(did, &identity_pk, &active_pk, &commitment);

        assert_eq!(doc.verification_method.len(), 2);
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.assertion_method.len(), 1);
        assert!(!doc.has_agent_key());
        assert!(doc.agent_verification_method().is_none());
        doc.validate_agent_keys().unwrap();

        // Also test new_with_agent_key with None
        let doc2 =
            DidDocument::new_with_agent_key(did, &identity_pk, &active_pk, &commitment, None);
        assert_eq!(doc, doc2);
    }

    #[test]
    fn add_agent_key_to_existing_document() {
        let did = "did:dht:zAddAgent";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let commitment = [3u8; 32];
        let agent_pk = [4u8; 32];

        let mut doc = DidDocument::new(did, &identity_pk, &active_pk, &commitment);
        assert!(!doc.has_agent_key());

        doc.add_agent_key(&agent_pk).unwrap();

        assert!(doc.has_agent_key());
        assert_eq!(doc.verification_method.len(), 3);
        assert_eq!(doc.authentication.len(), 2);
        assert_eq!(doc.assertion_method.len(), 2);

        let vm_agent = doc.verification_method_by_fragment("agent").unwrap();
        assert_eq!(vm_agent.id, format!("{did}#agent"));
        assert_eq!(vm_agent.method_type, "Ed25519VerificationKey2020");

        doc.validate_agent_keys().unwrap();
    }

    #[test]
    fn add_agent_key_fails_when_already_exists() {
        let did = "did:dht:zDuplicateAgent";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let commitment = [3u8; 32];
        let agent_pk = [4u8; 32];

        let mut doc = DidDocument::new(did, &identity_pk, &active_pk, &commitment);
        doc.add_agent_key(&agent_pk).unwrap();

        let result = doc.add_agent_key(&[5u8; 32]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("already exists"),
            "error should mention already exists, got: {err}"
        );
    }

    #[test]
    fn remove_agent_key() {
        let did = "did:dht:zRemoveAgent";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let agent_pk = [3u8; 32];
        let commitment = [4u8; 32];

        let mut doc = DidDocument::new_with_agent_key(
            did,
            &identity_pk,
            &active_pk,
            &commitment,
            Some(&agent_pk),
        );
        assert!(doc.has_agent_key());

        doc.remove_agent_key().unwrap();

        assert!(!doc.has_agent_key());
        assert_eq!(doc.verification_method.len(), 2);
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.assertion_method.len(), 1);
        assert!(!doc.authentication.iter().any(|r| r.ends_with("#agent")));
        assert!(!doc.assertion_method.iter().any(|r| r.ends_with("#agent")));
    }

    #[test]
    fn remove_agent_key_fails_when_none_exists() {
        let did = "did:dht:zNoAgentRemove";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let commitment = [3u8; 32];

        let mut doc = DidDocument::new(did, &identity_pk, &active_pk, &commitment);

        let result = doc.remove_agent_key();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("no agent key"),
            "error should mention no agent key, got: {err}"
        );
    }

    #[test]
    fn rotate_agent_key_retires_old_key() {
        let did = "did:dht:zRotateAgent";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let original_agent_pk = [3u8; 32];
        let new_agent_pk = [4u8; 32];
        let commitment = [5u8; 32];

        let mut doc = DidDocument::new_with_agent_key(
            did,
            &identity_pk,
            &active_pk,
            &commitment,
            Some(&original_agent_pk),
        );

        doc.rotate_agent_key(&new_agent_pk, 1).unwrap();

        // New #agent should exist
        assert!(doc.has_agent_key());
        let vm_agent = doc.verification_method_by_fragment("agent").unwrap();
        assert_eq!(vm_agent.id, format!("{did}#agent"));

        // Old key should be retired
        let vm_retired = doc
            .verification_method_by_fragment("retired-agent-1")
            .unwrap();
        assert_eq!(vm_retired.id, format!("{did}#retired-agent-1"));

        // The new agent key should have a different public key than the retired one
        assert_ne!(
            vm_agent.public_key_multibase,
            vm_retired.public_key_multibase
        );

        assert_eq!(doc.retired_agent_key_count(), 1);
        doc.validate_agent_keys().unwrap();
    }

    #[test]
    fn rotate_agent_key_bounded_retention() {
        let did = "did:dht:zBoundedRetire";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let commitment = [5u8; 32];

        let mut doc = DidDocument::new_with_agent_key(
            did,
            &identity_pk,
            &active_pk,
            &commitment,
            Some(&[10u8; 32]),
        );

        // Rotate 3 times: should retain at most 2 retired keys
        doc.rotate_agent_key(&[11u8; 32], 1).unwrap();
        assert_eq!(doc.retired_agent_key_count(), 1);

        doc.rotate_agent_key(&[12u8; 32], 2).unwrap();
        assert_eq!(doc.retired_agent_key_count(), 2);

        doc.rotate_agent_key(&[13u8; 32], 3).unwrap();
        // Should be pruned to 2 (the 2 most recent: sequences 2 and 3)
        assert_eq!(doc.retired_agent_key_count(), 2);

        // Verify the most recent retired keys are retained
        assert!(
            doc.verification_method_by_fragment("retired-agent-3")
                .is_some()
        );
        assert!(
            doc.verification_method_by_fragment("retired-agent-2")
                .is_some()
        );
        // Oldest should be pruned
        assert!(
            doc.verification_method_by_fragment("retired-agent-1")
                .is_none()
        );

        // One more rotation
        doc.rotate_agent_key(&[14u8; 32], 4).unwrap();
        assert_eq!(doc.retired_agent_key_count(), 2);
        assert!(
            doc.verification_method_by_fragment("retired-agent-4")
                .is_some()
        );
        assert!(
            doc.verification_method_by_fragment("retired-agent-3")
                .is_some()
        );
        assert!(
            doc.verification_method_by_fragment("retired-agent-2")
                .is_none()
        );

        doc.validate_agent_keys().unwrap();
    }

    #[test]
    fn rotate_agent_key_fails_when_none_exists() {
        let did = "did:dht:zNoAgentRotate";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let commitment = [3u8; 32];

        let mut doc = DidDocument::new(did, &identity_pk, &active_pk, &commitment);

        let result = doc.rotate_agent_key(&[4u8; 32], 1);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("no agent key"),
            "error should mention no agent key, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_multiple_agent_vms() {
        let did = "did:dht:zMultiAgent";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let commitment = [3u8; 32];

        let mut doc = DidDocument::new(did, &identity_pk, &active_pk, &commitment);

        // Manually inject two #agent VMs (bypassing add_agent_key guard)
        doc.verification_method.push(VerificationMethod {
            id: format!("{did}#agent"),
            method_type: "Ed25519VerificationKey2020".to_owned(),
            controller: did.to_owned(),
            public_key_multibase: "zAAA".to_owned(),
        });
        doc.verification_method.push(VerificationMethod {
            id: format!("{did}#agent"),
            method_type: "Ed25519VerificationKey2020".to_owned(),
            controller: did.to_owned(),
            public_key_multibase: "zBBB".to_owned(),
        });

        let result = doc.validate_agent_keys();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("2 #agent"),
            "error should mention 2 #agent VMs, got: {err}"
        );
    }

    #[test]
    fn agent_key_json_roundtrip_with_agent() {
        let did = "did:dht:zRoundtripAgent";
        let identity_pk = [10u8; 32];
        let active_pk = [20u8; 32];
        let agent_pk = [30u8; 32];
        let commitment = [40u8; 32];

        let doc = DidDocument::new_with_agent_key(
            did,
            &identity_pk,
            &active_pk,
            &commitment,
            Some(&agent_pk),
        );

        let json = doc.to_json().unwrap();
        let parsed = DidDocument::from_json(&json).unwrap();
        assert_eq!(doc, parsed);

        // Verify the agent VM survived roundtrip
        assert!(parsed.has_agent_key());
        assert_eq!(parsed.verification_method.len(), 3);
        assert_eq!(parsed.authentication.len(), 2);
        assert_eq!(parsed.assertion_method.len(), 2);
        parsed.validate_agent_keys().unwrap();
    }

    #[test]
    fn agent_key_json_roundtrip_without_agent() {
        let did = "did:dht:zRoundtripNoAgent";
        let identity_pk = [10u8; 32];
        let active_pk = [20u8; 32];
        let commitment = [30u8; 32];

        let doc = DidDocument::new(did, &identity_pk, &active_pk, &commitment);

        let json = doc.to_json().unwrap();
        let parsed = DidDocument::from_json(&json).unwrap();
        assert_eq!(doc, parsed);

        assert!(!parsed.has_agent_key());
        assert_eq!(parsed.verification_method.len(), 2);
        parsed.validate_agent_keys().unwrap();
    }

    #[test]
    fn agent_key_roundtrip_after_rotation() {
        let did = "did:dht:zRoundtripRotate";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let commitment = [5u8; 32];

        let mut doc = DidDocument::new_with_agent_key(
            did,
            &identity_pk,
            &active_pk,
            &commitment,
            Some(&[3u8; 32]),
        );
        doc.rotate_agent_key(&[4u8; 32], 1).unwrap();

        let json = doc.to_json().unwrap();
        let parsed = DidDocument::from_json(&json).unwrap();
        assert_eq!(doc, parsed);

        assert!(parsed.has_agent_key());
        assert_eq!(parsed.retired_agent_key_count(), 1);
        parsed.validate_agent_keys().unwrap();
    }

    #[test]
    fn add_remove_add_agent_key_cycle() {
        let did = "did:dht:zCycleAgent";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let commitment = [3u8; 32];

        let mut doc = DidDocument::new(did, &identity_pk, &active_pk, &commitment);

        // Add
        doc.add_agent_key(&[4u8; 32]).unwrap();
        assert!(doc.has_agent_key());

        // Remove
        doc.remove_agent_key().unwrap();
        assert!(!doc.has_agent_key());

        // Add again with different key
        doc.add_agent_key(&[5u8; 32]).unwrap();
        assert!(doc.has_agent_key());

        let vm_agent = doc.verification_method_by_fragment("agent").unwrap();
        assert_eq!(vm_agent.id, format!("{did}#agent"));
        doc.validate_agent_keys().unwrap();
    }

    // --- Custody attestation DID document integration tests (SCP-AB-018) ---

    #[test]
    fn did_document_without_attestation_returns_none() {
        let did = "did:dht:zNoAttestation";
        let doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        let attestation = doc.custody_attestation().unwrap();
        assert!(
            attestation.is_none(),
            "document without attestation should return None"
        );
    }

    #[test]
    fn did_document_set_and_get_custody_attestation() {
        use crate::attestation::{KeyCustodyModel, Platform, ScpKeyCustodyAttestation};

        let did = "did:dht:zWithAttestation";
        let mut doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        let attestation = ScpKeyCustodyAttestation {
            active_key_custody: KeyCustodyModel::HardwareBiometric,
            agent_key_custody: Some(KeyCustodyModel::Software),
            platform: Platform::Ios,
            platform_attestation: None,
            created_at: 1_700_000_000,
        };

        doc.set_custody_attestation(&attestation).unwrap();

        let retrieved = doc.custody_attestation().unwrap().unwrap();
        assert_eq!(retrieved, attestation);
    }

    #[test]
    fn did_document_set_custody_attestation_replaces_existing() {
        use crate::attestation::{KeyCustodyModel, Platform, ScpKeyCustodyAttestation};

        let did = "did:dht:zReplaceAttestation";
        let mut doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        let first = ScpKeyCustodyAttestation {
            active_key_custody: KeyCustodyModel::Software,
            agent_key_custody: None,
            platform: Platform::Desktop,
            platform_attestation: None,
            created_at: 1_700_000_000,
        };
        doc.set_custody_attestation(&first).unwrap();

        let second = ScpKeyCustodyAttestation {
            active_key_custody: KeyCustodyModel::HardwareBiometric,
            agent_key_custody: Some(KeyCustodyModel::HardwarePin),
            platform: Platform::Ios,
            platform_attestation: None,
            created_at: 1_700_000_001,
        };
        doc.set_custody_attestation(&second).unwrap();

        let attestation_count = doc
            .service
            .iter()
            .filter(|s| s.service_type == "ScpKeyCustodyAttestation")
            .count();
        assert_eq!(
            attestation_count, 1,
            "should have exactly one custody attestation entry"
        );

        let retrieved = doc.custody_attestation().unwrap().unwrap();
        assert_eq!(retrieved, second);
    }

    #[test]
    fn did_document_custody_attestation_preserves_other_services() {
        use crate::attestation::{KeyCustodyModel, Platform, ScpKeyCustodyAttestation};

        let did = "did:dht:zPreserveServices";
        let mut doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        doc.add_relay_service(&relay("wss://relay.example.com/scp/v1"));

        let attestation = ScpKeyCustodyAttestation {
            active_key_custody: KeyCustodyModel::HardwareBiometric,
            agent_key_custody: None,
            platform: Platform::Ios,
            platform_attestation: None,
            created_at: 1_700_000_000,
        };
        doc.set_custody_attestation(&attestation).unwrap();

        // Should have: PreRotationCommitment + SCPRelay + ScpKeyCustodyAttestation.
        assert_eq!(doc.service.len(), 3);
        assert!(doc.pre_rotation_service().is_some());
        assert_eq!(doc.relay_service_urls().len(), 1);
        assert!(doc.custody_attestation().unwrap().is_some());
    }

    #[test]
    fn did_document_custody_attestation_survives_json_roundtrip() {
        use crate::attestation::{
            AttestationPlatform, KeyCustodyModel, Platform, PlatformAttestation,
            ScpKeyCustodyAttestation,
        };

        let did = "did:dht:zJsonRoundtrip";
        let mut doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        let attestation = ScpKeyCustodyAttestation {
            active_key_custody: KeyCustodyModel::HardwareBiometric,
            agent_key_custody: Some(KeyCustodyModel::Software),
            platform: Platform::Ios,
            platform_attestation: Some(PlatformAttestation {
                platform: AttestationPlatform::AppleAppAttest,
                proof: vec![0xCA, 0xFE, 0xBA, 0xBE],
            }),
            created_at: 1_700_000_000,
        };
        doc.set_custody_attestation(&attestation).unwrap();

        let json = doc.to_json().unwrap();
        let parsed = DidDocument::from_json(&json).unwrap();

        let retrieved = parsed.custody_attestation().unwrap().unwrap();
        assert_eq!(retrieved, attestation);
    }

    // -----------------------------------------------------------------------
    // Device attestation service entry tests (#362)
    // -----------------------------------------------------------------------

    #[test]
    fn add_device_attestation_creates_service_entry() {
        let did = "did:dht:zDevAttest1";
        let mut doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        assert!(doc.device_attestation_token().unwrap().is_none());

        doc.add_device_attestation(&[0xCA, 0xFE, 0xBA, 0xBE]);

        let svc = doc
            .service
            .iter()
            .find(|s| s.service_type == "ScpDeviceAttestation")
            .expect("service entry should exist");
        assert_eq!(svc.id, format!("{did}#device-attestation"));
        assert_eq!(svc.service_type, "ScpDeviceAttestation");
    }

    #[test]
    fn device_attestation_token_roundtrip() {
        let did = "did:dht:zDevAttest2";
        let mut doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let token = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03];

        doc.add_device_attestation(&token);
        let retrieved = doc.device_attestation_token().unwrap().unwrap();
        assert_eq!(retrieved, token);
    }

    #[test]
    fn device_attestation_absent_returns_none() {
        let did = "did:dht:zDevAttest3";
        let doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        assert!(doc.device_attestation_token().unwrap().is_none());
    }

    #[test]
    fn device_attestation_survives_json_roundtrip() {
        let did = "did:dht:zDevAttest4";
        let mut doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let token = vec![0x01, 0x02, 0x03, 0x04, 0x05];

        doc.add_device_attestation(&token);
        let json = doc.to_json().unwrap();
        let parsed = DidDocument::from_json(&json).unwrap();

        let retrieved = parsed.device_attestation_token().unwrap().unwrap();
        assert_eq!(retrieved, token);
    }

    #[test]
    fn add_device_attestation_replaces_existing() {
        let did = "did:dht:zDevAttest5";
        let mut doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        doc.add_device_attestation(&[0x01]);
        doc.add_device_attestation(&[0x02]);

        let count = doc
            .service
            .iter()
            .filter(|s| s.service_type == "ScpDeviceAttestation")
            .count();
        assert_eq!(count, 1, "should have exactly one device attestation entry");

        let retrieved = doc.device_attestation_token().unwrap().unwrap();
        assert_eq!(retrieved, vec![0x02]);
    }

    #[test]
    fn remove_device_attestation_clears_entry() {
        let did = "did:dht:zDevAttest6";
        let mut doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        doc.add_device_attestation(&[0x01, 0x02]);
        assert!(doc.device_attestation_token().unwrap().is_some());

        doc.remove_device_attestation();
        assert!(doc.device_attestation_token().unwrap().is_none());
    }

    #[test]
    fn device_attestation_tampered_token_decode_fails() {
        let did = "did:dht:zDevAttest7";
        let mut doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        doc.add_device_attestation(&[0x01]);

        // Tamper with the service endpoint to have invalid base64.
        let svc = doc
            .service
            .iter_mut()
            .find(|s| s.service_type == "ScpDeviceAttestation")
            .unwrap();
        svc.service_endpoint = "!!!not-valid-base64!!!".to_owned();

        let result = doc.device_attestation_token();
        assert!(result.is_err());
    }

    // --- Identity link attestation DID document integration tests (§3.5.3) ---

    #[test]
    fn identity_link_empty_document_returns_empty_list() {
        let doc = DidDocument::new("did:dht:zIdLink1", &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        assert!(doc.identity_link_attestations().is_empty());
        assert_eq!(doc.identity_link_attestation_count(), 0);
    }

    #[test]
    fn identity_link_set_and_get() {
        let mut doc = DidDocument::new("did:dht:zIdLink2", &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        doc.set_identity_link_attestation("github.com", "abc123")
            .unwrap();

        let entries = doc.identity_link_attestations();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].platform, "github.com");
        assert_eq!(entries[0].attestation_id, "abc123");
        assert_eq!(entries[0].index, 0);
    }

    #[test]
    fn identity_link_multiple_platforms() {
        let mut doc = DidDocument::new("did:dht:zIdLink3", &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        doc.set_identity_link_attestation("github.com", "aaa")
            .unwrap();
        doc.set_identity_link_attestation("x.com", "bbb").unwrap();
        doc.set_identity_link_attestation("google.com", "ccc")
            .unwrap();

        assert_eq!(doc.identity_link_attestation_count(), 3);
        let entries = doc.identity_link_attestations();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn identity_link_same_platform_increments_index() {
        let mut doc = DidDocument::new("did:dht:zIdLink4", &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        doc.set_identity_link_attestation("mastodon:mastodon.social", "aaa")
            .unwrap();
        doc.set_identity_link_attestation("mastodon:mastodon.social", "bbb")
            .unwrap();

        let entries = doc.identity_link_attestations();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].index, 0);
        assert_eq!(entries[1].index, 1);
    }

    #[test]
    fn identity_link_replace_same_attestation_id() {
        let mut doc = DidDocument::new("did:dht:zIdLink5", &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        doc.set_identity_link_attestation("github.com", "abc123")
            .unwrap();
        // Setting the same attestation ID should replace, not add.
        doc.set_identity_link_attestation("github.com", "abc123")
            .unwrap();

        assert_eq!(doc.identity_link_attestation_count(), 1);
    }

    #[test]
    fn identity_link_remove() {
        let mut doc = DidDocument::new("did:dht:zIdLink6", &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        doc.set_identity_link_attestation("github.com", "abc123")
            .unwrap();
        assert_eq!(doc.identity_link_attestation_count(), 1);

        let removed = doc.remove_identity_link_attestation("abc123");
        assert!(removed);
        assert_eq!(doc.identity_link_attestation_count(), 0);
    }

    #[test]
    fn identity_link_remove_nonexistent_returns_false() {
        let mut doc = DidDocument::new("did:dht:zIdLink7", &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        let removed = doc.remove_identity_link_attestation("nonexistent");
        assert!(!removed);
    }

    #[test]
    fn identity_link_max_limit_enforced() {
        let mut doc = DidDocument::new("did:dht:zIdLink8", &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        // Add 64 entries (the maximum).
        for i in 0..64 {
            doc.set_identity_link_attestation(&format!("platform-{i}.com"), &format!("attest-{i}"))
                .unwrap();
        }
        assert_eq!(doc.identity_link_attestation_count(), 64);

        // The 65th should fail.
        let result = doc.set_identity_link_attestation("one-too-many.com", "attest-64");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("maximum of 64"));
    }

    #[test]
    fn identity_link_preserves_other_services() {
        let mut doc = DidDocument::new("did:dht:zIdLink9", &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        doc.add_relay_service(&relay("wss://relay.example.com/scp/v1"));

        doc.set_identity_link_attestation("github.com", "abc123")
            .unwrap();

        // Should have: PreRotationCommitment + SCPRelay + identity link.
        assert_eq!(doc.service.len(), 3);
        assert!(doc.pre_rotation_service().is_some());
        assert_eq!(doc.relay_service_urls().len(), 1);
        assert_eq!(doc.identity_link_attestation_count(), 1);
    }

    #[test]
    fn identity_link_survives_json_roundtrip() {
        let mut doc = DidDocument::new("did:dht:zIdLink10", &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        doc.set_identity_link_attestation("github.com", "abc123")
            .unwrap();
        doc.set_identity_link_attestation("x.com", "def456")
            .unwrap();

        let json = doc.to_json().unwrap();
        let parsed = DidDocument::from_json(&json).unwrap();

        let entries = parsed.identity_link_attestations();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].platform, "github.com");
        assert_eq!(entries[0].attestation_id, "abc123");
        assert_eq!(entries[1].platform, "x.com");
        assert_eq!(entries[1].attestation_id, "def456");
    }

    /// `retire_operational_keys_for_migration` MUST use exact-fragment
    /// match so a hypothetical future fragment like `#secondary-active`
    /// or `#auxiliary-agent` is not silently swept along with the
    /// operational keys. Today the spec defines only `#0`, `#active`,
    /// `#agent`, `#retired-N`, and `#retired-agent-N`; this test is
    /// forward-compat hardening.
    #[test]
    fn retire_operational_keys_for_migration_preserves_unrelated_fragments() {
        let did = "did:dht:zRetireExact";
        let mut doc = DidDocument::new(did, &[7u8; 32], &[8u8; 32], &[9u8; 32]);

        // Inject a synthetic `#secondary-active` VM (the suffix
        // `active` would have matched the old `ends_with("#active")`
        // filter even though the fragment is `secondary-active`).
        doc.verification_method.push(VerificationMethod {
            id: format!("{did}#secondary-active"),
            method_type: ED25519_VERIFICATION_KEY_TYPE.to_owned(),
            controller: did.to_owned(),
            public_key_multibase: format!("z{}", base58btc_encode(&[11u8; 32])),
        });
        // Also reference it from authentication so the per-array
        // filter is exercised.
        doc.authentication.push(format!("{did}#secondary-active"));
        doc.assertion_method.push(format!("{did}#secondary-active"));

        // Sanity: before retire, all four VMs and refs are present.
        assert!(
            doc.verification_method
                .iter()
                .any(|vm| vm.id == format!("{did}#0"))
        );
        assert!(
            doc.verification_method
                .iter()
                .any(|vm| vm.id == format!("{did}#active"))
        );
        assert!(
            doc.verification_method
                .iter()
                .any(|vm| vm.id == format!("{did}#secondary-active"))
        );

        doc.retire_operational_keys_for_migration();

        // `#0` and `#secondary-active` MUST remain. `#active` MUST go.
        let frags: Vec<String> = doc
            .verification_method
            .iter()
            .map(|vm| vm.id.clone())
            .collect();
        assert!(
            frags.contains(&format!("{did}#0")),
            "#0 must be retained; got: {frags:?}"
        );
        assert!(
            frags.contains(&format!("{did}#secondary-active")),
            "#secondary-active must NOT be swept by exact-fragment retire; got: {frags:?}"
        );
        assert!(
            !frags.contains(&format!("{did}#active")),
            "#active must be removed; got: {frags:?}"
        );
        assert!(
            !frags.contains(&format!("{did}#agent")),
            "#agent (if present) must be removed; got: {frags:?}"
        );

        // Reference arrays: `#secondary-active` retained, `#active` removed.
        assert!(
            doc.authentication
                .contains(&format!("{did}#secondary-active")),
            "authentication must retain #secondary-active; got: {:?}",
            doc.authentication
        );
        assert!(
            !doc.authentication.contains(&format!("{did}#active")),
            "authentication must drop #active; got: {:?}",
            doc.authentication
        );
        assert!(
            doc.assertion_method
                .contains(&format!("{did}#secondary-active")),
            "assertionMethod must retain #secondary-active; got: {:?}",
            doc.assertion_method
        );
        assert!(
            !doc.assertion_method.contains(&format!("{did}#active")),
            "assertionMethod must drop #active; got: {:?}",
            doc.assertion_method
        );
    }

    // --- decode_multibase_key / base58btc_decode (moved from scp-identity::dht
    //     per ADR-057 Slice 1a; these test the inverse of base58btc_encode) ---

    #[test]
    fn base58btc_decode_roundtrip() {
        let original = [42u8; 32];
        // Use the document module's encode (via the multibase_encode path).
        let encoded = DidDocument::new("did:dht:zTest", &original, &[0u8; 32], &[0u8; 32]);
        let vm = encoded.verification_method_by_fragment("0").unwrap();
        let decoded = decode_multibase_key(&vm.public_key_multibase).unwrap();
        assert_eq!(decoded, original);
    }

    /// `decode_multibase_key` MUST reject payloads that don't decompress
    /// to a valid Ed25519 Edwards-curve point. ed25519-dalek's
    /// `from_bytes` enforces ZIP-215 curve-point decompression. About
    /// half of random 32-byte strings fail this check, so we search for
    /// one rather than hardcoding a specific value. Matches the
    /// `from_did_rejects_non_ed25519_curve_point` guard so
    /// both decoding entry points reject non-curve payloads early.
    #[test]
    fn decode_multibase_key_rejects_non_curve_point() {
        use rand::RngCore;

        // Search for a 32-byte payload that fails Ed25519 decompression.
        let non_curve_bytes: [u8; 32] = {
            let mut found: Option<[u8; 32]> = None;
            for _ in 0..512 {
                let mut candidate = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut candidate);
                if ed25519_dalek::VerifyingKey::from_bytes(&candidate).is_err() {
                    found = Some(candidate);
                    break;
                }
            }
            found.expect(
                "should find a non-curve 32-byte payload within 512 tries (~50% rejection rate)",
            )
        };

        // base58btc-encode the non-curve payload and prefix with `z`
        // (matches the on-the-wire multibase form).
        let encoded = format!("z{}", bs58::encode(&non_curve_bytes).into_string());

        let err = decode_multibase_key(&encoded).expect_err("non-curve payload must be rejected");
        match err {
            DidError::InvalidDidFormat(msg) => {
                assert!(
                    msg.contains("not a valid Ed25519 public key"),
                    "expected curve-point error message; got: {msg}"
                );
            }
            other => panic!("expected InvalidDidFormat, got: {other:?}"),
        }
    }

    #[test]
    fn base58btc_decode_known_vector() {
        // "JxF12TrwUP45BMd" is the base58btc encoding of "Hello World".
        let decoded = base58btc_decode("JxF12TrwUP45BMd").unwrap();
        assert_eq!(decoded, b"Hello World");
    }

    #[test]
    fn base58btc_decode_leading_ones() {
        // Leading '1' characters map to leading zero bytes.
        let decoded = base58btc_decode("112").unwrap();
        assert_eq!(decoded, vec![0x00, 0x00, 0x01]);
    }

    #[test]
    fn base58btc_decode_empty_input() {
        let decoded = base58btc_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn base58btc_decode_rejects_invalid_characters() {
        // '0', 'O', 'I', 'l' are not in the Bitcoin base58 alphabet.
        assert!(base58btc_decode("0OIl").is_err());
    }

    #[test]
    fn base58btc_roundtrip_32_byte_key() {
        // Direct roundtrip: encode with bs58, then decode with our function.
        let key = [0xABu8; 32];
        let encoded = bs58::encode(&key).into_string();
        let decoded = base58btc_decode(&encoded).unwrap();
        assert_eq!(decoded, key);
    }
}
