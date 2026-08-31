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

use std::fmt;

use super::attestation::{IdentityLinkServiceEntry, ScpKeyCustodyAttestation};
use crate::SigningKeyId;
use serde::{Deserialize, Serialize};

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

    /// An invalid relay URL was provided (must use wss:// scheme and /scp/v1 path).
    #[error("invalid relay URL: {0}")]
    InvalidRelayUrl(String),

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

    /// A verification method a caller asked for supplies no usable key.
    ///
    /// Covers an absent method, a repeated identifier, a method declaring
    /// another suite, a method naming another controller, and a method a
    /// requested verification relationship does not reference.
    #[error("#{fragment} verification method of {did} is unusable: {reason}")]
    UnusableVerificationMethod {
        /// Fragment a caller asked for, without a leading `#`.
        fragment: String,
        /// DID whose document a caller read.
        did: String,
        /// What disqualified that method.
        reason: String,
    },
}

/// Verification relationship a DID document declares over a key (W3C DID Core
/// §5.3).
///
/// A relationship states what a document authorizes a key to do, so a verifier
/// names one rather than treating every listed key as usable for every purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerificationRelationship {
    /// `assertionMethod` — signing a statement about a subject, which covers
    /// event-log entries, credentials, attestations, and governance votes.
    Assertion,
    /// `authentication` — proving control of a DID to a challenger, which
    /// covers bridge and service login tokens.
    Authentication,
}

impl fmt::Display for VerificationRelationship {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Assertion => "assertionMethod",
            Self::Authentication => "authentication",
        })
    }
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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

/// A key a Layer 1 rotation moved aside, which still verifies a content
/// signature this document's subject produced before that rotation.
///
/// [`DidDocument::historical_assertion_keys`] returns one of these per retired
/// verification method a document still carries. §23.13 paragraph 1 of the sync
/// spec states the rule that makes such a key usable: an event-log leaf records
/// what an actor did at the sequence it occupies, so a later rotation does not
/// retroactively unmake that authorship.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalAssertionKey {
    /// Fragment identifying the method, without a leading `#` — for example
    /// `retired-1` or `retired-agent-2`.
    ///
    /// A caller reports this string when a key rejects a signature, so an
    /// operator reading a log sees which method a verifier tried.
    pub fragment: String,

    /// Which holder signed with this key before an owner rotated it out.
    ///
    /// [`SigningKeyId::Active`] for a `retired-{n}` fragment and
    /// [`SigningKeyId::Agent`] for a `retired-agent-{n}` fragment. ADR-039
    /// gives `#active` and `#agent` distinct holders — a human and agent
    /// software — and a rotation moves a key between identifiers without moving
    /// it between holders, so a verifier reports the same holder it would have
    /// reported before the rotation.
    pub holder: SigningKeyId,

    /// The rotation sequence the fragment carries: `2` for `retired-2`.
    ///
    /// A rotation assigns this from the DID document's own monotone publish
    /// sequence (`DidMethod::rotate_active_key` and `rotate_agent_key` in
    /// `scp-identity`), so a higher value names a more recent retirement.
    /// [`DidDocument::historical_assertion_keys`] orders by it, most recent
    /// first, and applies no bound against it — see that method's retention
    /// note for why a read-side bound would revoke rather than protect.
    pub sequence: u64,

    /// The raw 32-byte Ed25519 public key the method publishes.
    pub public_key: [u8; 32],
}

/// A service entry within a DID Document.
///
/// Used for the `PreRotationCommitment` service that publishes the SHA-256
/// hash of the next identity key's public key.
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
}

/// The W3C DID Document JSON-LD context URI.
const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";

/// The Ed25519 verification key suite context URI.
const ED25519_CONTEXT: &str = "https://w3id.org/security/suites/ed25519-2020/v1";

/// Type string every Ed25519 verification method in a DID document carries.
///
/// A verifier that resolves a signing key compares this value against
/// [`VerificationMethod::method_type`], so a method declaring some other
/// suite never supplies an Ed25519 signature key.
pub const ED25519_VERIFICATION_KEY_TYPE: &str = "Ed25519VerificationKey2020";

/// Fragment naming the Identity Key verification method (ADR-039).
///
/// A `did:dht` string is z-base-32 of this key, which is what lets a reader
/// check a document against the DID it claims to describe.
const IDENTITY_KEY_FRAGMENT: &str = "0";

/// The service type string for `SCPRelay` entries (§18.2.1).
const SCP_RELAY_SERVICE_TYPE: &str = "SCPRelay";

/// The service type string for `SCPBroadcastContext` entries (§18.2.2).
///
/// Broadcast contexts with `discoverable: true` publish a service entry of
/// this type in the creator's DID document. The service endpoint encodes
/// the context ID and relay URLs:
///
///   `scp:context:<context_id_hex>?relay=<url1>&relay=<url2>`
const SCP_BROADCAST_CONTEXT_SERVICE_TYPE: &str = "SCPBroadcastContext";

/// The required URL scheme for `SCPRelay` entries.
const SCP_RELAY_SCHEME: &str = "wss://";

/// The required path suffix for `SCPRelay` entries.
const SCP_RELAY_PATH: &str = "/scp/v1";

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

/// Fragment prefix [`DidDocument::retire_active_key`] writes ahead of a rotation
/// sequence, producing `retired-{sequence}` (ADR-003, DID creation, item 4a).
const RETIRED_ACTIVE_FRAGMENT_PREFIX: &str = "retired-";

/// Fragment prefix [`DidDocument::rotate_agent_key`] writes ahead of a rotation
/// sequence, producing `retired-agent-{sequence}` (ADR-039).
///
/// Longer than [`RETIRED_ACTIVE_FRAGMENT_PREFIX`] and sharing its opening
/// characters, so a classifier tests this one first.
const RETIRED_AGENT_FRAGMENT_PREFIX: &str = "retired-agent-";

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

    /// Returns a verification method this document identifies as
    /// `{self.id}#{fragment}` — for example `"0"`, `"active"`, or `"agent"`.
    ///
    /// A verification method qualifies when its `id` equals this document's own
    /// DID followed by `#` and `fragment`. A method some other DID identifies —
    /// `did:dht:zSOMEONEELSE#active` inside this document — never qualifies, and
    /// neither does a longer fragment that merely ends in a requested one,
    /// such as `#retired-1#active`.
    ///
    /// Returns `None` when no method carries that identifier, and also when two
    /// or more do: W3C DID Core §5.3.1 requires a verification method
    /// identifier to be unique within a document, so a repeated identifier
    /// leaves a reader no way to say which key a document meant. Every caller
    /// of this method resolves a key for signature verification, and picking
    /// one of two candidates by array position would let document order decide
    /// which signature verifies.
    #[must_use]
    pub fn verification_method_by_fragment(&self, fragment: &str) -> Option<&VerificationMethod> {
        let method_id = self.verification_method_id(fragment);
        let mut matches = self
            .verification_method
            .iter()
            .filter(|vm| vm.id == method_id);
        let first = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(first)
    }

    /// Returns an identifier this document assigns a verification method with
    /// a given fragment: `{self.id}#{fragment}`.
    #[must_use]
    pub fn verification_method_id(&self, fragment: &str) -> String {
        format!("{}#{}", self.id, fragment)
    }

    /// Resolves the Identity Key this document publishes as `{self.id}#0`.
    ///
    /// A reader calls this to check what a document *is*, never to authorize
    /// what a signer *did*: a `did:dht` string is z-base-32 of an Identity Key
    /// (§3.8 and §9.6.1 of the identity spec), so comparing this key against
    /// that string tells a reader whether a document describes the identity it
    /// claims. ADR-039's key-property table marks `#0` "Signs operational
    /// actions: No", and §9.7.4 confines it to DID document updates plus
    /// pre-rotation commitments, so no signature-verification path resolves a
    /// key through this function.
    ///
    /// A caller resolving a key that must verify a signature calls
    /// [`signing_key_for`](Self::signing_key_for), which takes a
    /// [`SigningKeyId`] and a [`VerificationRelationship`] and reads the
    /// document's own relationship array. This function and `signing_key_for`
    /// are the two ways this type resolves a key, and each pins its fragment,
    /// because both call sites that took a fragment string asked a document for
    /// a key it never authorized: a rotated `#retired-{n}` method keeps its
    /// type and its controller, so type and controller alone admit a key an
    /// owner already withdrew.
    ///
    /// A caller can still read [`verification_method`](Self::verification_method)
    /// directly and decode a [`publicKeyMultibase`](VerificationMethod::public_key_multibase)
    /// value with [`decode_multibase_key`], which is how a serializer and a
    /// custody-consistency check reach a method. Neither of those two
    /// operations verifies a signature. A caller that composes them to verify
    /// one gets no relationship check and none of the three facts below, so a
    /// reviewer treats that composition as the defect this pair of methods
    /// exists to prevent.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::UnusableVerificationMethod`] when `#0` is absent,
    /// repeated, declares a type other than [`ED25519_VERIFICATION_KEY_TYPE`],
    /// or names a controller other than this document's own DID, and
    /// [`DidError::InvalidDidFormat`] when its `publicKeyMultibase` value does
    /// not decode to a 32-byte Ed25519 curve point.
    pub fn identity_key(&self) -> Result<[u8; 32], DidError> {
        self.verification_method_key(IDENTITY_KEY_FRAGMENT)
    }

    /// Resolves a public key from a verification method this document
    /// identifies as `{self.id}#{fragment}`, checking three document facts and
    /// no verification relationship.
    ///
    /// Private, because a relationship-free lookup by arbitrary fragment
    /// answers with a key a document never authorized for anything. The two
    /// public callers each fix the fragment and add their own gate:
    /// [`identity_key`](Self::identity_key) pins `#0` and treats the answer as
    /// a document fact rather than as an authorization, and
    /// [`signing_key_for`](Self::signing_key_for) pins a
    /// [`SigningKeyId`] and then requires a relationship array to reference the
    /// method.
    ///
    /// The three facts:
    ///
    /// - a method identifier equal to `{self.id}#{fragment}`, so a method some
    ///   other DID identifies inside this document supplies nothing (see
    ///   [`verification_method_by_fragment`](Self::verification_method_by_fragment),
    ///   which also rejects a repeated identifier);
    /// - a `type` of [`ED25519_VERIFICATION_KEY_TYPE`], since
    ///   `publicKeyMultibase` decoding alone cannot separate a signing key from
    ///   a key-agreement key;
    /// - a `controller` equal to this document's own DID, since SCP defines no
    ///   delegation letting another DID sign as this one.
    fn verification_method_key(&self, fragment: &str) -> Result<[u8; 32], DidError> {
        let unusable = |reason: String| DidError::UnusableVerificationMethod {
            fragment: fragment.to_owned(),
            did: self.id.clone(),
            reason,
        };

        let method = self
            .verification_method_by_fragment(fragment)
            .ok_or_else(|| unusable("no method carries that identifier exactly once".to_owned()))?;

        if method.method_type != ED25519_VERIFICATION_KEY_TYPE {
            return Err(unusable(format!(
                "method declares type {}, not {ED25519_VERIFICATION_KEY_TYPE}",
                method.method_type
            )));
        }

        if method.controller != self.id {
            return Err(unusable(format!(
                "method names controller {}, which is not this DID",
                method.controller
            )));
        }

        decode_multibase_key(&method.public_key_multibase)
    }

    /// Resolves a public key this document authorizes for `relationship`.
    ///
    /// Checks three document facts — an identifier equal to
    /// `{self.id}#{fragment}` carried exactly once, a `type` of
    /// [`ED25519_VERIFICATION_KEY_TYPE`], and a `controller` equal to this
    /// document's own DID — then requires a `relationship` array to reference
    /// that method. W3C DID Core §5.3 makes a verification relationship an
    /// authorization statement, so an owner withdrawing a reference withdraws
    /// that key's authority for that purpose while keeping it readable for
    /// audit.
    ///
    /// A [`SigningKeyId`] argument keeps `#0` out of reach: ADR-039 marks an
    /// Identity Key as signing no operational action, and §9.7.4 confines it to
    /// DID document updates plus pre-rotation commitments.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::UnusableVerificationMethod`] when a method fails any
    /// check above or when `relationship` does not reference it, and
    /// [`DidError::InvalidDidFormat`] when its key does not decode.
    pub fn signing_key_for(
        &self,
        signing_key_id: SigningKeyId,
        relationship: VerificationRelationship,
    ) -> Result<[u8; 32], DidError> {
        let fragment = signing_key_id.fragment();
        let key = self.verification_method_key(fragment)?;
        let method_id = self.verification_method_id(fragment);
        let references = match relationship {
            VerificationRelationship::Assertion => &self.assertion_method,
            VerificationRelationship::Authentication => &self.authentication,
        };

        if !references.contains(&method_id) {
            return Err(DidError::UnusableVerificationMethod {
                fragment: fragment.to_owned(),
                did: self.id.clone(),
                reason: format!("{relationship} omits {method_id}"),
            });
        }

        Ok(key)
    }

    /// Returns every retired key this document still carries that a verifier
    /// accepts for a content signature, ordered by holder and then by rotation
    /// sequence, most recent first: retired `#active` keys before retired
    /// `#agent` keys.
    ///
    /// A content signature is a statement about the past. §23.13 paragraph 1 of
    /// the sync spec accepts a retired method on an event-log leaf for that
    /// reason: a leaf records what an actor did at the sequence it occupies, and
    /// a later rotation must not retroactively unmake that authorship. §9.12 of
    /// the security-model spec states the matching hard rule — an owner revokes
    /// a compromised key by removing its method from `verification_method`
    /// entirely, and a method this document no longer carries is absent from
    /// this result.
    ///
    /// # Why this is separate from `signing_key_for`
    ///
    /// [`retire_active_key`](Self::retire_active_key) rebuilds `authentication`
    /// and `assertion_method` as `#active` plus `#agent`, so a retired method is
    /// referenced by neither array. Gating a historical-verification path on
    /// `assertion_method` membership therefore finds nothing, and
    /// [`signing_key_for`](Self::signing_key_for) takes a [`SigningKeyId`],
    /// which has two variants and can name no retired fragment. This method
    /// gates on document facts a rotation leaves intact instead. Keeping the two
    /// resolvers apart also keeps each call site honest about which duty it
    /// performs: a caller authenticating a live session calls `signing_key_for`
    /// and gets the relationship gate, and a caller verifying past authorship
    /// calls this method and gets the criterion below.
    ///
    /// # Which methods qualify
    ///
    /// **The criterion:** this document's own Layer 1 rotation produced the
    /// method. [`retire_active_key`](Self::retire_active_key) and
    /// [`rotate_agent_key`](Self::rotate_agent_key) are the only two operations
    /// that produce one, and each writes one identifier shape.
    ///
    /// **The three facts that decide it:**
    ///
    /// - an identifier equal to `{self.id}#retired-{n}` or
    ///   `{self.id}#retired-agent-{n}`, carried exactly once, where `{n}` is the
    ///   decimal rendering of a `u64` with no leading zero — the exact output of
    ///   the two rotation operations, so `#retired-01` and `#retired-x` name no
    ///   historical key;
    /// - a `type` of [`ED25519_VERIFICATION_KEY_TYPE`];
    /// - a `controller` equal to `{self.id}`.
    ///
    /// A method failing any of the three is absent from the result rather than
    /// reported as an error, because a document may carry a method some other
    /// DID identifies and that method supplies nothing here.
    ///
    /// # Retention bound — a write-side property, not a check performed here
    ///
    /// ADR-003, DID creation, item 4a states what retention a rotation applies,
    /// and [`rotate_agent_key`](Self::rotate_agent_key) prunes on the agent side
    /// when it runs. This method applies no bound of its own: it returns every
    /// retired method the document it is handed carries.
    ///
    /// A caller must not read a write-side retention rule as a bound on this
    /// result. A DID document is a record its own subject publishes, and a
    /// verifier reads it
    /// after it crosses a DHT that neither enforces nor attests how the
    /// document was produced. An owner who hand-writes fifty `#retired-{n}`
    /// methods publishes a document all three facts above admit, so the size of
    /// this result is a number the document's publisher chooses. Capping it
    /// here would not fix that — it would hand the same publisher a second
    /// lever, since freshly published high-sequence methods would displace the
    /// genuinely rotated ones and silently revoke them, which §9.12 of the
    /// security-model spec says only removal does. The criterion above needs a
    /// rotation a verifier can check, which a Layer 1 rotation does not
    /// currently produce. `.docs/specs/00-open-questions.md` carries that
    /// question.
    #[must_use]
    pub fn historical_assertion_keys(&self) -> Vec<HistoricalAssertionKey> {
        let mut fragments: Vec<(String, SigningKeyId, u64)> = self
            .verification_method
            .iter()
            .filter_map(|vm| {
                let fragment = vm.id.strip_prefix(&self.id)?.strip_prefix('#')?;
                let (holder, sequence) = Self::retired_fragment_sequence(fragment)?;
                Some((fragment.to_owned(), holder, sequence))
            })
            .collect();
        // Sort by fragment, not by the tuple: a fragment already decides a
        // holder and a sequence, so two entries sharing a fragment share both
        // and `dedup_by` collapses them. `verification_method_key` below then
        // rejects the survivor, because a repeated identifier fails the
        // exactly-once fact.
        fragments.sort_unstable_by(|(left, _, _), (right, _, _)| left.cmp(right));
        fragments.dedup_by(|(left, _, _), (right, _, _)| left == right);

        // Report retired `#active` keys before retired `#agent` keys, and the
        // most recent retirement of each kind first. `SigningKeyId` implements
        // no ordering, so the holder sorts through a `bool`. Sorting by
        // sequence rather than by the fragment string keeps `retired-10` after
        // `retired-2` instead of before it.
        fragments.sort_by_key(|(_, holder, sequence)| {
            (
                matches!(holder, SigningKeyId::Agent),
                std::cmp::Reverse(*sequence),
            )
        });

        fragments
            .into_iter()
            .filter_map(|(fragment, holder, sequence)| {
                let public_key = self.verification_method_key(&fragment).ok()?;
                Some(HistoricalAssertionKey {
                    fragment,
                    holder,
                    sequence,
                    public_key,
                })
            })
            .collect()
    }

    /// Classifies a bare fragment as a retired `#active` key, a retired
    /// `#agent` key, or neither, dropping the sequence
    /// [`retired_fragment_sequence`] reports.
    ///
    /// [`retired_fragment_sequence`]: Self::retired_fragment_sequence
    fn retired_fragment_holder(fragment: &str) -> Option<SigningKeyId> {
        Self::retired_fragment_sequence(fragment).map(|(holder, _)| holder)
    }

    /// Classifies a bare fragment as a retired `#active` key, a retired
    /// `#agent` key, or neither, and reports the rotation sequence its
    /// identifier carries.
    ///
    /// Tests the `retired-agent-` prefix first, because `retired-` is a prefix
    /// of it and would otherwise claim every retired agent fragment.
    fn retired_fragment_sequence(fragment: &str) -> Option<(SigningKeyId, u64)> {
        let (rest, holder) =
            if let Some(rest) = fragment.strip_prefix(RETIRED_AGENT_FRAGMENT_PREFIX) {
                (rest, SigningKeyId::Agent)
            } else {
                (
                    fragment.strip_prefix(RETIRED_ACTIVE_FRAGMENT_PREFIX)?,
                    SigningKeyId::Active,
                )
            };

        // A rotation writes `format!("{sequence}")` for a `u64`, which never
        // carries a sign, a leading zero, or leading whitespace. Requiring the
        // parsed value to render back to the same string admits exactly the
        // strings a rotation writes, so `retired-01` and `retired-+1` name no
        // historical key rather than aliasing one that exists.
        let sequence: u64 = rest.parse().ok()?;
        (sequence.to_string() == rest).then_some((holder, sequence))
    }

    /// Drops every retired key `holder` names beyond the `max` most recent,
    /// ordered by the rotation sequence its identifier carries.
    ///
    /// [`rotate_agent_key`](Self::rotate_agent_key) is the one caller, and
    /// ADR-003, DID creation, item 4a states the retention this enforces. A key
    /// this method drops is a key
    /// [`historical_assertion_keys`](Self::historical_assertion_keys) never
    /// returns again, so pruning decides how far back a reader can check
    /// authorship.
    ///
    /// [`retire_active_key`](Self::retire_active_key) calls nothing here, and
    /// item 4a as published states a cap for the `#active` side too — at most
    /// the 2 most recent retired active keys. This crate has never enforced
    /// that half, so a document keeps every `#retired-{sequence}` method its
    /// `#active` rotations wrote. `.docs/specs/00-open-questions.md` records
    /// the disagreement between item 4a and this code, and names the open pull
    /// request that deletes both caps.
    ///
    /// Identifies a method the way every other document-fact gate here does,
    /// by `{self.id}#{fragment}`, so a method some other DID identifies inside
    /// this document is left alone rather than pruned.
    fn prune_retired_keys(&mut self, holder: SigningKeyId, max: usize) {
        let did = self.id.clone();
        let mut retired: Vec<(usize, u64)> = self
            .verification_method
            .iter()
            .enumerate()
            .filter_map(|(index, vm)| {
                let fragment = vm.id.strip_prefix(&did)?.strip_prefix('#')?;
                let (fragment_holder, sequence) = Self::retired_fragment_sequence(fragment)?;
                (fragment_holder == holder).then_some((index, sequence))
            })
            .collect();

        if retired.len() <= max {
            return;
        }

        // Highest sequence first, so the tail past `max` is the oldest set.
        retired.sort_by_key(|entry| std::cmp::Reverse(entry.1));
        let mut remove_indices: Vec<usize> =
            retired[max..].iter().map(|(index, _)| *index).collect();
        // Descending, so removing one index never shifts another still pending.
        remove_indices.sort_unstable_by(|left, right| right.cmp(left));
        for index in remove_indices {
            self.verification_method.remove(index);
        }
    }

    /// Removes the verification method this document identifies as
    /// `{self.id}#{fragment}`, along with every `authentication` and
    /// `assertion_method` reference to it.
    ///
    /// This is the compromise-recovery act of §9.12 of the security-model spec.
    /// Rotation is soft — [`retire_active_key`](Self::retire_active_key) and
    /// [`rotate_agent_key`](Self::rotate_agent_key) retain the old key under a
    /// `#retired-*` identifier, and
    /// [`historical_assertion_keys`](Self::historical_assertion_keys) keeps
    /// returning it, so a content signature that key produced keeps verifying.
    /// Removal is hard: a method this document no longer carries verifies
    /// nothing, at any sequence, for any reader. An owner recovering from a key
    /// compromise removes the compromised method rather than retiring it.
    ///
    /// Returns `true` when it removed a method, and `false` when this document
    /// carried none under that identifier.
    ///
    /// A caller publishes the resulting document — signed by the Identity Key,
    /// per §9.12 step 1 — for the removal to reach any other reader.
    /// `scp_identity::DidDht` composes that step from three of its own
    /// operations: `rotate_active_key` or `rotate_agent_key` installs the
    /// replacement key and retains the compromised one under a `#retired-*`
    /// identifier, this method drops that identifier from the returned
    /// document — [`historical_assertion_keys`](Self::historical_assertion_keys)
    /// reports which identifier the rotation assigned — and
    /// `publish_document` signs the result with `#0` and writes
    /// it to the DHT. An owner who stops after the rotation has performed the
    /// soft act and left the compromised key signing content.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::UnusableVerificationMethod`] when `fragment` names
    /// the Identity Key (`0`). A `did:dht` string is z-base-32 of that key, so
    /// removing it leaves a document that self-certifies nothing and that every
    /// verifier rejects. §9.12 assigns Identity Key compromise to
    /// `migrate_identity` (ADR-003, DID creation, item 4b), which mints a new
    /// DID rather than editing this one.
    pub fn remove_verification_method(&mut self, fragment: &str) -> Result<bool, DidError> {
        // `SigningKeyId::as_fragment` renders `#active` and `Display` renders
        // the same, while `SigningKeyId::fragment` renders `active`, and
        // `verification_method_id` below builds `{id}#{fragment}` from the bare
        // form. Accepting one leading `#` makes both spellings name the same
        // method. Without this, `remove_verification_method(id.as_fragment())`
        // builds `{id}##active`, matches nothing, and answers `Ok(false)` — a
        // caller would read that as "already gone" while a compromised key
        // stayed in the document, on the one path §9.12 relies on.
        let fragment = fragment.strip_prefix('#').unwrap_or(fragment);

        if fragment == IDENTITY_KEY_FRAGMENT {
            return Err(DidError::UnusableVerificationMethod {
                fragment: fragment.to_owned(),
                did: self.id.clone(),
                reason: "an Identity Key is what a did:dht string encodes, so removing it \
                         leaves a document describing no identity; §9.12 of the \
                         security-model spec recovers an Identity Key compromise with \
                         migrate_identity"
                    .to_owned(),
            });
        }

        // An empty fragment reaches the same misreading the leading-`#` strip
        // above exists to prevent: `""` and `"#"` build `{id}#`, match nothing,
        // and answer `Ok(false)`, which a caller performing §9.12 compromise
        // recovery reads as "already gone".
        if fragment.is_empty() {
            return Err(DidError::UnusableVerificationMethod {
                fragment: fragment.to_owned(),
                did: self.id.clone(),
                reason: "a fragment names one method within this document and cannot be \
                         empty; pass `active`, `agent`, or a retired fragment \
                         `historical_assertion_keys` reports"
                    .to_owned(),
            });
        }

        // A fragment still carrying `#` is a full DID URL or a nested
        // identifier, never a fragment this document assigns. Answering
        // `Ok(false)` would report it as absent; it is unusable.
        if fragment.contains('#') {
            return Err(DidError::UnusableVerificationMethod {
                fragment: fragment.to_owned(),
                did: self.id.clone(),
                reason: "a fragment names one method within this document and carries no \
                         further '#'; pass `active`, `agent`, or a retired fragment \
                         `historical_assertion_keys` reports, not a full DID URL"
                    .to_owned(),
            });
        }

        let method_id = self.verification_method_id(fragment);
        let before = self.verification_method.len();
        self.verification_method.retain(|vm| vm.id != method_id);
        self.authentication
            .retain(|reference| *reference != method_id);
        self.assertion_method
            .retain(|reference| *reference != method_id);

        Ok(self.verification_method.len() != before)
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
    /// The URL must use the `wss://` scheme and end with the `/scp/v1` path,
    /// per §18.2.1. Multiple relay entries are allowed for suppression
    /// resistance (§18.2.3). Entries preserve insertion order — the first
    /// entry is the preferred relay.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::InvalidRelayUrl`] if the URL does not use
    /// `wss://` scheme or does not contain the `/scp/v1` path.
    pub fn add_relay_service(&mut self, url: &str) -> Result<(), DidError> {
        if !url.starts_with(SCP_RELAY_SCHEME) {
            return Err(DidError::InvalidRelayUrl(format!(
                "URL must use wss:// scheme, got: {url}"
            )));
        }
        if !url.ends_with(SCP_RELAY_PATH) {
            return Err(DidError::InvalidRelayUrl(format!(
                "URL must end with /scp/v1 path, got: {url}"
            )));
        }

        let relay_count = self
            .service
            .iter()
            .filter(|s| s.service_type == SCP_RELAY_SERVICE_TYPE)
            .count();

        let service = Service {
            id: format!("{}#scp-relay-{}", self.id, relay_count + 1),
            service_type: SCP_RELAY_SERVICE_TYPE.to_owned(),
            service_endpoint: url.to_owned(),
        };

        self.service.push(service);
        Ok(())
    }

    /// Returns all `SCPRelay` service endpoint URLs, in insertion order.
    ///
    /// The first entry is the preferred relay per §18.2.3. Only `SCPRelay`
    /// service entries are returned; other service types are filtered out.
    #[must_use]
    pub fn relay_service_urls(&self) -> Vec<String> {
        self.service
            .iter()
            .filter(|s| s.service_type == SCP_RELAY_SERVICE_TYPE)
            .map(|s| s.service_endpoint.clone())
            .collect()
    }

    /// Replaces all `SCPRelay` service entries with the given URLs.
    ///
    /// Removes any existing `SCPRelay` entries and adds new ones for each URL.
    /// Non-relay services (e.g., `PreRotationCommitment`) are preserved. Each
    /// URL is validated per §18.2.1 (`wss://` scheme, `/scp/v1` path).
    ///
    /// This is used during relay list updates (§18.5) to atomically replace the
    /// relay set before republishing with an incremented BEP44 sequence number
    /// (§9.6.3).
    ///
    /// # Errors
    ///
    /// Returns [`DidError::InvalidRelayUrl`] if any URL fails validation.
    /// On error, no entries are modified (all-or-nothing).
    pub fn set_relay_services(&mut self, urls: &[&str]) -> Result<(), DidError> {
        // Validate all URLs before modifying state (all-or-nothing).
        for url in urls {
            if !url.starts_with(SCP_RELAY_SCHEME) {
                return Err(DidError::InvalidRelayUrl(format!(
                    "URL must use wss:// scheme, got: {url}"
                )));
            }
            if !url.ends_with(SCP_RELAY_PATH) {
                return Err(DidError::InvalidRelayUrl(format!(
                    "URL must end with /scp/v1 path, got: {url}"
                )));
            }
        }

        // Remove existing SCPRelay entries.
        self.service
            .retain(|s| s.service_type != SCP_RELAY_SERVICE_TYPE);

        // Add new entries.
        for (i, url) in urls.iter().enumerate() {
            let service = Service {
                id: format!("{}#scp-relay-{}", self.id, i + 1),
                service_type: SCP_RELAY_SERVICE_TYPE.to_owned(),
                service_endpoint: (*url).to_owned(),
            };
            self.service.push(service);
        }

        Ok(())
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
    /// This is the **soft** act. It retains the old key under the
    /// `#retired-{sequence}` identifier, and §23.13 paragraph 1 of the sync spec
    /// accepts that retained method on an event-log leaf, so the old key keeps
    /// verifying content the owner already signed. An owner recovering from a
    /// compromise calls [`remove_verification_method`](Self::remove_verification_method)
    /// on the retired identifier instead, because §9.12 of the security-model
    /// spec assigns revocation of a content signature to removal alone.
    ///
    /// # Arguments
    ///
    /// * `new_active_public_key` - The raw 32-byte Ed25519 public key for the
    ///   new active signing key.
    /// * `sequence` - The rotation sequence number, used to name the retired key
    ///   fragment (e.g., `#retired-1`).
    pub fn retire_active_key(&mut self, new_active_public_key: &[u8], sequence: u64) {
        let did = &self.id;
        let active_id = format!("{did}#active");
        let retired_id = format!("{did}#retired-{sequence}");

        // Find this document's own #active verification method and rename it to
        // #retired-{sequence}. A method some other DID identifies is left alone.
        for vm in &mut self.verification_method {
            if vm.id == active_id {
                vm.id.clone_from(&retired_id);
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
    /// continues to authorize `alsoKnownAs` republishes, and every
    /// retained `#retired-*` method keeps verifying content: §23.13
    /// paragraph 1 of the sync spec accepts a retired method the
    /// resolved document still carries on an event-log leaf, so those
    /// entries verify a new signature and not only an audited history.
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
        // Whole-identifier match, matching every other operational-key
        // method on this type: a migrating document drops both keys
        // this DID owns, and leaves a method some other DID identifies
        // where a reader can still audit it. A longer fragment such as
        // `#secondary-active` survives for that same reason.
        let active_id = self.verification_method_id("active");
        let agent_id = self.verification_method_id("agent");
        let operational = [active_id, agent_id];
        self.verification_method
            .retain(|vm| !operational.contains(&vm.id));
        self.authentication
            .retain(|reference| !operational.contains(reference));
        self.assertion_method
            .retain(|reference| !operational.contains(reference));
    }

    // --- Agent key management (ADR-039) ---

    /// Returns `true` if this document contains an `#agent` verification method.
    #[must_use]
    pub fn has_agent_key(&self) -> bool {
        let agent_id = self.verification_method_id("agent");
        self.verification_method.iter().any(|vm| vm.id == agent_id)
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

        let agent_id = self.verification_method_id("agent");
        self.verification_method.retain(|vm| vm.id != agent_id);
        self.authentication.retain(|ref_id| *ref_id != agent_id);
        self.assertion_method.retain(|ref_id| *ref_id != agent_id);

        Ok(())
    }

    /// Rotates the `#agent` verification method, retaining the old key as a
    /// retired key.
    ///
    /// The old `#agent` key is renamed to `#retired-agent-{sequence}`. At most
    /// 2 retired agent keys are retained; older ones are pruned (bounded
    /// retention). The new key becomes `#agent`.
    ///
    /// This is the **soft** act. It retains the old key under the
    /// `#retired-agent-{sequence}` identifier, and §23.13 paragraph 1 of the
    /// sync spec accepts that retained method on an event-log leaf, so the old
    /// key keeps verifying content the owner already signed. An owner recovering
    /// from a compromise calls
    /// [`remove_verification_method`](Self::remove_verification_method) on the
    /// retired identifier instead, because §9.12 of the security-model spec
    /// assigns revocation of a content signature to removal alone.
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
    /// Returns [`DidError::MultipleAgentKeys`] when this document already
    /// carries `{self.id}#agent` more than once, and
    /// [`DidError::AgentKeyNotFound`] when it carries none.
    pub fn rotate_agent_key(
        &mut self,
        new_public_key: &[u8],
        sequence: u64,
    ) -> Result<(), DidError> {
        // Every reader rejects a repeated identifier, so a rotation must not
        // write one. The rename below moves every `{self.id}#agent` entry to
        // one `#retired-agent-{sequence}` identifier, so a document carrying
        // two of them would end with two entries under that identifier, and
        // `historical_assertion_keys` would then return neither — a silent
        // revocation §9.12 of the security-model spec assigns to
        // `remove_verification_method` alone.
        self.validate_agent_keys()?;
        if !self.has_agent_key() {
            return Err(DidError::AgentKeyNotFound);
        }

        let did = &self.id;

        // Rename this document's own #agent method to
        // #retired-agent-{sequence}. A method some other DID identifies is
        // left alone.
        let agent_id = format!("{did}#agent");
        let retired_id = format!("{did}#retired-agent-{sequence}");
        for vm in &mut self.verification_method {
            if vm.id == agent_id {
                vm.id.clone_from(&retired_id);
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
        self.prune_retired_keys(SigningKeyId::Agent, MAX_RETIRED_AGENT_KEYS);

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
        let agent_id = self.verification_method_id("agent");
        let agent_count = self
            .verification_method
            .iter()
            .filter(|vm| vm.id == agent_id)
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
                // Identify a method the way every other document-fact gate here
                // does, by `{self.id}#{fragment}`, and classify it the way
                // `historical_assertion_keys` does. Suffix-matching `#` counted
                // a method some other DID identifies inside this document, and
                // `starts_with` counted a non-canonical `retired-agent-007`
                // that no rotation writes and no verifier accepts — so this
                // count disagreed with the set it is read as measuring.
                vm.id
                    .strip_prefix(&self.id)
                    .and_then(|rest| rest.strip_prefix('#'))
                    .and_then(Self::retired_fragment_holder)
                    .is_some_and(|holder| matches!(holder, SigningKeyId::Agent))
            })
            .count()
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

    // -----------------------------------------------------------------------
    // Historical assertion keys (§23.13 ¶1 of the sync spec, §9.12 of the
    // security-model spec)
    // -----------------------------------------------------------------------

    /// Derives a valid Ed25519 curve point from a one-byte seed.
    ///
    /// `decode_multibase_key` runs `VerifyingKey::from_bytes`, so a filler
    /// array such as `[2u8; 32]` decompresses to no curve point and every
    /// key resolver rejects it.
    fn curve_point(seed: u8) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    /// Builds a document for `did` carrying `#0`, `#active`, and `#agent`.
    fn document_with_agent(did: &str) -> DidDocument {
        DidDocument::new_with_agent_key(
            did,
            &curve_point(1),
            &curve_point(2),
            &[3u8; 32],
            Some(&curve_point(4)),
        )
    }

    /// Builds a document for `did` carrying `#0` and `#active`.
    fn document_with_active(did: &str) -> DidDocument {
        DidDocument::new(did, &curve_point(1), &curve_point(2), &[3u8; 32])
    }

    /// A rotated `#active` key leaves `assertion_method` and stays verifiable
    /// as `retired-1`, reported under the holder it had before the rotation.
    #[test]
    fn historical_assertion_keys_returns_a_rotated_active_key_under_its_holder() {
        let did = "did:dht:zHistoricalActive";
        let mut doc = document_with_active(did);
        doc.retire_active_key(&curve_point(9), 1);

        assert!(
            !doc.assertion_method.contains(&format!("{did}#retired-1")),
            "a rotation leaves a retired method out of assertionMethod, which is \
             why signing_key_for cannot reach it"
        );

        let historical = doc.historical_assertion_keys();
        assert_eq!(historical.len(), 1, "one rotation retains one key");
        assert_eq!(historical[0].fragment, "retired-1");
        assert_eq!(historical[0].holder, SigningKeyId::Active);
        assert_eq!(historical[0].public_key, curve_point(2));
    }

    /// A rotated `#agent` key answers `SigningKeyId::Agent`, so a verifier keeps
    /// attributing its signatures to agent software rather than to a human
    /// (ADR-039).
    #[test]
    fn historical_assertion_keys_returns_a_rotated_agent_key_under_its_holder() {
        let did = "did:dht:zHistoricalAgent";
        let mut doc = document_with_agent(did);
        doc.rotate_agent_key(&curve_point(9), 1).unwrap();

        let historical = doc.historical_assertion_keys();
        assert_eq!(historical.len(), 1);
        assert_eq!(historical[0].fragment, "retired-agent-1");
        assert_eq!(
            historical[0].holder,
            SigningKeyId::Agent,
            "retired-agent-{{n}} carries the agent holder, not the active one"
        );
        assert_eq!(historical[0].public_key, curve_point(4));
    }

    /// Only the two identifier shapes a Layer 1 rotation writes qualify. A
    /// fragment that merely opens with `retired-` names no historical key.
    #[test]
    fn historical_assertion_keys_admits_only_the_two_rotation_identifier_shapes() {
        let did = "did:dht:zHistoricalShapes";
        let mut doc = document_with_active(did);

        for fragment in [
            "retired-01",
            "retired-x",
            "retired-",
            "retired-1x",
            "retired--1",
            "retired-agent-01",
            "retired-agent-",
            "retired_1",
            "retiredx-1",
        ] {
            doc.verification_method.push(VerificationMethod {
                id: format!("{did}#{fragment}"),
                method_type: ED25519_VERIFICATION_KEY_TYPE.to_owned(),
                controller: did.to_owned(),
                public_key_multibase: multibase_encode(&curve_point(7)),
            });
        }

        assert!(
            doc.historical_assertion_keys().is_empty(),
            "no rotation writes any of those identifiers"
        );
    }

    /// `retire_active_key` prunes nothing: four rotations leave four retired
    /// methods, and each one still supplies the key it published. This test
    /// pins the behavior this crate has always had. ADR-003, DID creation,
    /// item 4a states a cap of the 2 most recent retired active keys that this
    /// crate has never enforced, and `.docs/specs/00-open-questions.md` records
    /// that disagreement.
    #[test]
    fn retire_active_key_retains_every_retired_active_key_it_wrote() {
        let did = "did:dht:zActiveRetention";
        let mut doc = document_with_active(did);

        // Rotation `n` retires whatever `#active` held before it ran: rotation 1
        // retires the key `document_with_active` installed, and rotation `n`
        // above 1 retires the key rotation `n - 1` installed.
        let mut retired_by_rotation = vec![curve_point(2)];
        for sequence in 1..=4_u64 {
            let replacement = curve_point(20 + u8::try_from(sequence).unwrap());
            doc.retire_active_key(&replacement, sequence);
            retired_by_rotation.push(replacement);
        }

        let historical = doc.historical_assertion_keys();
        assert_eq!(
            historical
                .iter()
                .map(|key| key.sequence)
                .collect::<Vec<_>>(),
            vec![4, 3, 2, 1],
            "four rotations retain four retired active keys, most recent first"
        );
        for sequence in 1..=4_usize {
            let expected = retired_by_rotation[sequence - 1];
            assert!(
                historical
                    .iter()
                    .any(|key| key.sequence == sequence as u64 && key.public_key == expected),
                "retired-{sequence} still publishes the key that rotation retired"
            );
        }
    }

    /// A rotation writes the sequence into the identifier, so ordering by that
    /// sequence and ordering by the identifier string disagree. The reported
    /// order is the rotation order, most recent first.
    ///
    /// Sequences 1, 2, and 10 discriminate the two orderings. A two-element
    /// fixture of 2 and 10 does not: ascending fragment order and descending
    /// sequence order both report `retired-10` before `retired-2`, so such a
    /// fixture passes with the sequence sort deleted.
    #[test]
    fn historical_assertion_keys_orders_by_sequence_not_by_fragment_string() {
        let did = "did:dht:zSequenceOrder";
        let mut doc = document_with_active(did);
        doc.retire_active_key(&curve_point(30), 1);
        doc.retire_active_key(&curve_point(31), 2);
        doc.retire_active_key(&curve_point(32), 10);

        let historical = doc.historical_assertion_keys();
        assert_eq!(
            historical
                .iter()
                .map(|key| key.fragment.as_str())
                .collect::<Vec<_>>(),
            vec!["retired-10", "retired-2", "retired-1"],
            "the rotation sequence orders this result; ascending fragment order \
             would report retired-1 before retired-2"
        );
    }

    /// The reported order groups by holder before it orders by sequence:
    /// retired `#active` keys first, retired `#agent` keys after, each group
    /// most recent first. Deleting the holder half of the sort key interleaves
    /// the two groups by sequence and fails this test.
    #[test]
    fn historical_assertion_keys_reports_retired_active_keys_before_retired_agent_keys() {
        let did = "did:dht:zHolderOrder";
        let mut doc = document_with_agent(did);
        doc.retire_active_key(&curve_point(50), 3);
        doc.rotate_agent_key(&curve_point(51), 4)
            .expect("rotating an existing #agent key succeeds");

        let historical = doc.historical_assertion_keys();
        assert_eq!(
            historical
                .iter()
                .map(|key| (key.fragment.as_str(), key.holder))
                .collect::<Vec<_>>(),
            vec![
                ("retired-3", SigningKeyId::Active),
                ("retired-agent-4", SigningKeyId::Agent),
            ],
            "a retired #active key at a lower sequence still precedes a retired \
             #agent key at a higher one"
        );
    }

    /// `SigningKeyId::as_fragment` renders `#active` and `SigningKeyId::fragment`
    /// renders `active`. Both name one method, so both remove it. Before this,
    /// the `#`-carrying spelling built `{did}##active`, matched nothing, and
    /// answered `Ok(false)` — which a caller performing §9.12 compromise
    /// recovery would read as "already gone" while the key stayed published.
    #[test]
    fn remove_verification_method_accepts_both_fragment_spellings() {
        let did = "did:dht:zRemoveSpelling";

        for spelling in [
            SigningKeyId::Active.fragment(),
            SigningKeyId::Active.as_fragment(),
        ] {
            let mut doc = document_with_active(did);
            assert!(
                doc.remove_verification_method(spelling).unwrap(),
                "{spelling} names the #active method this document carries"
            );
            assert!(
                doc.signing_key_for(SigningKeyId::Active, VerificationRelationship::Assertion)
                    .is_err(),
                "a removed method resolves to no key under {spelling}"
            );
        }
    }

    /// A full DID URL is not a fragment this document assigns. Reporting it as
    /// absent would tell a caller the method is gone; it is unusable instead.
    #[test]
    fn remove_verification_method_refuses_a_fragment_carrying_a_further_hash() {
        let did = "did:dht:zRemoveDidUrl";
        let mut doc = document_with_active(did);

        let error = doc
            .remove_verification_method(&format!("{did}#active"))
            .expect_err("a DID URL names no fragment within this document");
        assert!(matches!(error, DidError::UnusableVerificationMethod { .. }));
        assert!(
            doc.signing_key_for(SigningKeyId::Active, VerificationRelationship::Assertion)
                .is_ok(),
            "the refusal removes nothing"
        );
    }

    /// An empty fragment names no method, and `Ok(false)` would report it as
    /// already removed — the misreading the leading-`#` strip exists to
    /// prevent. `"#"` strips to the same empty string.
    #[test]
    fn remove_verification_method_refuses_an_empty_fragment() {
        let did = "did:dht:zRemoveEmpty";

        for spelling in ["", "#"] {
            let mut doc = document_with_active(did);
            let error = doc
                .remove_verification_method(spelling)
                .expect_err("an empty fragment names no method in this document");
            assert!(
                matches!(error, DidError::UnusableVerificationMethod { .. }),
                "{spelling:?} must be unusable rather than absent"
            );
            assert!(
                doc.signing_key_for(SigningKeyId::Active, VerificationRelationship::Assertion)
                    .is_ok(),
                "the refusal removes nothing"
            );
        }
    }

    /// A rotation renames every `{did}#agent` entry to one
    /// `#retired-agent-{sequence}` identifier, so a document already carrying
    /// two of them would put two entries under that identifier and
    /// `historical_assertion_keys` would return neither. That is a revocation
    /// §9.12 of the security-model spec assigns to removal, so the rotation
    /// refuses the document instead of mutating it.
    #[test]
    fn rotate_agent_key_refuses_a_document_carrying_two_agent_methods() {
        let did = "did:dht:zTwoAgentMethods";
        let mut doc = document_with_agent(did);
        doc.verification_method.push(VerificationMethod {
            id: format!("{did}#agent"),
            method_type: ED25519_VERIFICATION_KEY_TYPE.to_owned(),
            controller: did.to_owned(),
            public_key_multibase: multibase_encode(&curve_point(60)),
        });

        let error = doc
            .rotate_agent_key(&curve_point(61), 1)
            .expect_err("a document carrying two #agent methods is malformed");
        assert!(matches!(error, DidError::MultipleAgentKeys { count: 2 }));
        assert!(
            doc.historical_assertion_keys().is_empty(),
            "the refusal writes no retired identifier"
        );
    }

    /// `retired_agent_key_count` is read as the measure of the ADR-003 item 4a
    /// bound, so it must count what `historical_assertion_keys` returns. A
    /// suffix match counted a method some other DID identifies inside this
    /// document, and a `starts_with` counted a non-canonical sequence no
    /// rotation writes — both inflate the count past the set it measures.
    #[test]
    fn retired_agent_key_count_counts_only_this_documents_canonical_retirements() {
        let did = "did:dht:zAgentCount";
        let other = "did:dht:zSomeoneElse";
        let mut doc = document_with_agent(did);
        doc.rotate_agent_key(&curve_point(40), 1)
            .expect("rotating an existing #agent key succeeds");

        for id in [
            format!("{other}#retired-agent-9"),
            format!("{did}#retired-agent-007"),
        ] {
            doc.verification_method.push(VerificationMethod {
                id,
                method_type: ED25519_VERIFICATION_KEY_TYPE.to_owned(),
                controller: did.to_owned(),
                public_key_multibase: multibase_encode(&curve_point(41)),
            });
        }

        assert_eq!(
            doc.retired_agent_key_count(),
            1,
            "a foreign identifier and a non-canonical sequence are not this \
             document's retirements"
        );
        assert_eq!(
            doc.retired_agent_key_count(),
            doc.historical_assertion_keys()
                .iter()
                .filter(|key| matches!(key.holder, SigningKeyId::Agent))
                .count(),
            "the count and the set it measures agree"
        );
    }

    /// The three document facts gate a retired method exactly as they gate a
    /// current one: another DID's identifier, another key suite, and another
    /// controller each supply nothing.
    #[test]
    fn historical_assertion_keys_rejects_a_method_failing_a_document_fact() {
        let did = "did:dht:zHistoricalFacts";
        let other = "did:dht:zSomeoneElse";
        let mut doc = document_with_active(did);

        // An identifier some other DID carries.
        doc.verification_method.push(VerificationMethod {
            id: format!("{other}#retired-1"),
            method_type: ED25519_VERIFICATION_KEY_TYPE.to_owned(),
            controller: other.to_owned(),
            public_key_multibase: multibase_encode(&curve_point(7)),
        });
        // This DID's identifier, another key suite.
        doc.verification_method.push(VerificationMethod {
            id: format!("{did}#retired-2"),
            method_type: "X25519KeyAgreementKey2020".to_owned(),
            controller: did.to_owned(),
            public_key_multibase: multibase_encode(&curve_point(7)),
        });
        // This DID's identifier, another controller.
        doc.verification_method.push(VerificationMethod {
            id: format!("{did}#retired-3"),
            method_type: ED25519_VERIFICATION_KEY_TYPE.to_owned(),
            controller: other.to_owned(),
            public_key_multibase: multibase_encode(&curve_point(7)),
        });
        // This DID's identifier, carried twice.
        for _ in 0..2 {
            doc.verification_method.push(VerificationMethod {
                id: format!("{did}#retired-4"),
                method_type: ED25519_VERIFICATION_KEY_TYPE.to_owned(),
                controller: did.to_owned(),
                public_key_multibase: multibase_encode(&curve_point(7)),
            });
        }

        assert!(
            doc.historical_assertion_keys().is_empty(),
            "each method fails one of the three document facts"
        );
    }

    /// Removing a method drops it from `verification_method` and from both
    /// relationship arrays, which is the §9.12 compromise-recovery act.
    #[test]
    fn remove_verification_method_drops_the_method_and_every_reference() {
        let did = "did:dht:zRemoveActive";
        let mut doc = document_with_agent(did);
        assert!(doc.assertion_method.contains(&format!("{did}#active")));

        assert!(doc.remove_verification_method("active").unwrap());

        assert!(doc.verification_method_by_fragment("active").is_none());
        assert!(!doc.authentication.contains(&format!("{did}#active")));
        assert!(!doc.assertion_method.contains(&format!("{did}#active")));
        assert!(
            doc.signing_key_for(SigningKeyId::Active, VerificationRelationship::Assertion)
                .is_err(),
            "a removed method supplies no key"
        );
    }

    /// Removing a retired method is what stops a compromised key verifying
    /// content, since a rotation on its own retains it.
    #[test]
    fn remove_verification_method_drops_a_retired_key_from_the_historical_set() {
        let did = "did:dht:zRemoveRetired";
        let mut doc = document_with_active(did);
        doc.retire_active_key(&curve_point(9), 1);
        assert_eq!(doc.historical_assertion_keys().len(), 1);

        assert!(doc.remove_verification_method("retired-1").unwrap());

        assert!(
            doc.historical_assertion_keys().is_empty(),
            "a removed method verifies nothing, at any sequence"
        );
    }

    /// Removing nothing reports `false` rather than an error.
    #[test]
    fn remove_verification_method_reports_false_for_an_absent_method() {
        let did = "did:dht:zRemoveAbsent";
        let mut doc = document_with_active(did);

        assert!(!doc.remove_verification_method("retired-7").unwrap());
    }

    /// `#0` is what a `did:dht` string encodes, so removing it would leave a
    /// document describing no identity. §9.12 sends an Identity Key compromise
    /// to `migrate_identity` instead.
    #[test]
    fn remove_verification_method_refuses_the_identity_key() {
        let did = "did:dht:zRemoveIdentity";
        let mut doc = document_with_active(did);

        let error = doc.remove_verification_method("0").unwrap_err();
        assert!(
            matches!(error, DidError::UnusableVerificationMethod { .. }),
            "expected UnusableVerificationMethod, got {error:?}"
        );
        assert!(
            doc.verification_method_by_fragment("0").is_some(),
            "a refused removal leaves the document untouched"
        );
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

    // --- SCPRelay tests (SCP-140) ---

    #[test]
    fn mixed_services_roundtrip() {
        let did = "did:dht:zMixedServices";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let commitment = [3u8; 32];

        let mut doc = DidDocument::new(did, &identity_pk, &active_pk, &commitment);
        doc.add_relay_service("wss://relay1.example.com/scp/v1")
            .unwrap();
        doc.add_relay_service("wss://relay2.example.com/scp/v1")
            .unwrap();

        // Should have PreRotationCommitment + 2 SCPRelay entries.
        assert_eq!(doc.service.len(), 3);

        // Roundtrip through JSON.
        let json = doc.to_json().unwrap();
        let parsed = DidDocument::from_json(&json).unwrap();
        assert_eq!(doc, parsed);

        // Verify service types survive roundtrip.
        assert!(parsed.pre_rotation_service().is_some());
        assert_eq!(parsed.relay_service_urls().len(), 2);
    }

    #[test]
    fn relay_service_urls_filters_correctly() {
        let did = "did:dht:zRelayFilter";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let commitment = [3u8; 32];

        let mut doc = DidDocument::new(did, &identity_pk, &active_pk, &commitment);
        doc.add_relay_service("wss://relay.example.com/scp/v1")
            .unwrap();

        let urls = doc.relay_service_urls();
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0], "wss://relay.example.com/scp/v1");

        // Pre-rotation service should NOT appear in relay URLs.
        assert!(doc.pre_rotation_service().is_some());
    }

    #[test]
    fn add_relay_service_rejects_non_wss_scheme() {
        let did = "did:dht:zInvalidScheme";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let commitment = [3u8; 32];

        let mut doc = DidDocument::new(did, &identity_pk, &active_pk, &commitment);

        // http:// should be rejected.
        let result = doc.add_relay_service("http://relay.example.com/scp/v1");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("wss://"));

        // ws:// should be rejected.
        let result = doc.add_relay_service("ws://relay.example.com/scp/v1");
        assert!(result.is_err());

        // https:// should be rejected.
        let result = doc.add_relay_service("https://relay.example.com/scp/v1");
        assert!(result.is_err());

        // No services added.
        assert_eq!(doc.relay_service_urls().len(), 0);
    }

    #[test]
    fn add_relay_service_rejects_invalid_path() {
        let did = "did:dht:zInvalidPath";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let commitment = [3u8; 32];

        let mut doc = DidDocument::new(did, &identity_pk, &active_pk, &commitment);

        // Missing /scp/v1 path.
        let result = doc.add_relay_service("wss://relay.example.com/other");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("/scp/v1"));

        // Root path.
        let result = doc.add_relay_service("wss://relay.example.com");
        assert!(result.is_err());

        // No services added.
        assert_eq!(doc.relay_service_urls().len(), 0);
    }

    #[test]
    fn multiple_relay_entries_preserve_insertion_order() {
        let did = "did:dht:zOrderTest";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let commitment = [3u8; 32];

        let mut doc = DidDocument::new(did, &identity_pk, &active_pk, &commitment);
        doc.add_relay_service("wss://preferred.example.com/scp/v1")
            .unwrap();
        doc.add_relay_service("wss://secondary.example.com/scp/v1")
            .unwrap();
        doc.add_relay_service("wss://tertiary.example.com/scp/v1")
            .unwrap();

        let urls = doc.relay_service_urls();
        assert_eq!(urls.len(), 3);
        // First entry = preferred relay per §18.2.3.
        assert_eq!(urls[0], "wss://preferred.example.com/scp/v1");
        assert_eq!(urls[1], "wss://secondary.example.com/scp/v1");
        assert_eq!(urls[2], "wss://tertiary.example.com/scp/v1");

        // Verify service IDs are sequential.
        let relay_services: Vec<_> = doc
            .service
            .iter()
            .filter(|s| s.service_type == "SCPRelay")
            .collect();
        assert_eq!(relay_services[0].id, format!("{did}#scp-relay-1"));
        assert_eq!(relay_services[1].id, format!("{did}#scp-relay-2"));
        assert_eq!(relay_services[2].id, format!("{did}#scp-relay-3"));
    }

    #[test]
    fn scp_relay_is_distinct_from_other_service_types() {
        let did = "did:dht:zDistinct";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let commitment = [3u8; 32];

        let mut doc = DidDocument::new(did, &identity_pk, &active_pk, &commitment);
        doc.add_relay_service("wss://relay.example.com/scp/v1")
            .unwrap();

        // Verify SCPRelay type string is distinct.
        let relay_svc = doc
            .service
            .iter()
            .find(|s| s.service_type == "SCPRelay")
            .unwrap();
        let pre_rot_svc = doc.pre_rotation_service().unwrap();

        assert_ne!(relay_svc.service_type, pre_rot_svc.service_type);
        assert_eq!(relay_svc.service_type, "SCPRelay");
        assert_eq!(pre_rot_svc.service_type, "PreRotationCommitment");

        // JSON serialization should show distinct type strings.
        let json = doc.to_json().unwrap();
        assert!(json.contains("\"SCPRelay\""));
        assert!(json.contains("\"PreRotationCommitment\""));
    }

    // --- set_relay_services tests (SCP-141) ---

    #[test]
    fn set_relay_services_replaces_existing_relay_entries() {
        let did = "did:dht:zSetRelay";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let commitment = [3u8; 32];

        let mut doc = DidDocument::new(did, &identity_pk, &active_pk, &commitment);

        // Add initial relay entries via add_relay_service.
        doc.add_relay_service("wss://old-relay.example.com/scp/v1")
            .unwrap();
        assert_eq!(doc.relay_service_urls().len(), 1);

        // Replace with set_relay_services.
        doc.set_relay_services(&[
            "wss://new1.example.com/scp/v1",
            "wss://new2.example.com/scp/v1",
        ])
        .unwrap();

        let urls = doc.relay_service_urls();
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0], "wss://new1.example.com/scp/v1");
        assert_eq!(urls[1], "wss://new2.example.com/scp/v1");

        // PreRotationCommitment should still be present.
        assert!(doc.pre_rotation_service().is_some());
    }

    #[test]
    fn set_relay_services_with_empty_removes_all() {
        let did = "did:dht:zSetEmpty";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let commitment = [3u8; 32];

        let mut doc = DidDocument::new(did, &identity_pk, &active_pk, &commitment);
        doc.add_relay_service("wss://relay.example.com/scp/v1")
            .unwrap();
        assert_eq!(doc.relay_service_urls().len(), 1);

        doc.set_relay_services(&[]).unwrap();
        assert!(doc.relay_service_urls().is_empty());

        // Only PreRotationCommitment should remain.
        assert_eq!(doc.service.len(), 1);
        assert!(doc.pre_rotation_service().is_some());
    }

    #[test]
    fn set_relay_services_validates_all_urls_before_modifying() {
        let did = "did:dht:zSetValidation";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let commitment = [3u8; 32];

        let mut doc = DidDocument::new(did, &identity_pk, &active_pk, &commitment);
        doc.add_relay_service("wss://existing.example.com/scp/v1")
            .unwrap();

        // One valid URL + one invalid URL. Should fail and not modify state.
        let result = doc.set_relay_services(&[
            "wss://valid.example.com/scp/v1",
            "http://invalid.example.com/scp/v1",
        ]);
        assert!(result.is_err());

        // Original relay entry should still be present (all-or-nothing).
        let urls = doc.relay_service_urls();
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0], "wss://existing.example.com/scp/v1");
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
        doc.add_relay_service("wss://relay.example.com/scp/v1")
            .unwrap();

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
        doc.add_relay_service("wss://relay.example.com/scp/v1")
            .unwrap();

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
