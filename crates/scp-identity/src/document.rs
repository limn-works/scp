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

use super::IdentityError;
use super::attestation::ScpKeyCustodyAttestation;
use serde::{Deserialize, Serialize};

/// Custom serde module for `[u8; 64]` fields.
///
/// Serde does not natively support arrays larger than 32 elements. This module
/// serializes `[u8; 64]` via `Vec<u8>` (leveraging `serde_bytes` for compact
/// binary representation) and validates the exact length on deserialization,
/// rejecting anything other than exactly 64 bytes.
mod serde_signature_64 {
    use serde::{self, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(bytes.as_slice(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 64-byte signature, got {} bytes", v.len()))
        })
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

/// The verification method type string for Ed25519 keys.
const ED25519_VERIFICATION_KEY_TYPE: &str = "Ed25519VerificationKey2020";

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
    /// The URL must use the `wss://` scheme and end with the `/scp/v1` path,
    /// per §18.2.1. Multiple relay entries are allowed for suppression
    /// resistance (§18.2.3). Entries preserve insertion order — the first
    /// entry is the preferred relay.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidRelayUrl`] if the URL does not use
    /// `wss://` scheme or does not contain the `/scp/v1` path.
    pub fn add_relay_service(&mut self, url: &str) -> Result<(), IdentityError> {
        if !url.starts_with(SCP_RELAY_SCHEME) {
            return Err(IdentityError::InvalidRelayUrl(format!(
                "URL must use wss:// scheme, got: {url}"
            )));
        }
        if !url.ends_with(SCP_RELAY_PATH) {
            return Err(IdentityError::InvalidRelayUrl(format!(
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
    /// Returns [`IdentityError::InvalidRelayUrl`] if any URL fails validation.
    /// On error, no entries are modified (all-or-nothing).
    pub fn set_relay_services(&mut self, urls: &[&str]) -> Result<(), IdentityError> {
        // Validate all URLs before modifying state (all-or-nothing).
        for url in urls {
            if !url.starts_with(SCP_RELAY_SCHEME) {
                return Err(IdentityError::InvalidRelayUrl(format!(
                    "URL must use wss:// scheme, got: {url}"
                )));
            }
            if !url.ends_with(SCP_RELAY_PATH) {
                return Err(IdentityError::InvalidRelayUrl(format!(
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
            service_endpoint: format!(
                "data:application/octet-stream;hex,{}",
                hex::encode(token_bytes)
            ),
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
    /// Returns [`IdentityError::DocumentDeserializationError`] if a custody
    /// attestation service entry exists but contains invalid data.
    pub fn custody_attestation(&self) -> Result<Option<ScpKeyCustodyAttestation>, IdentityError> {
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
    /// Returns [`IdentityError::DocumentSerializationError`] if the attestation
    /// cannot be serialized (should not happen for well-formed data).
    pub fn set_custody_attestation(
        &mut self,
        attestation: &ScpKeyCustodyAttestation,
    ) -> Result<(), IdentityError> {
        // Remove any existing custody attestation entry.
        self.service
            .retain(|s| s.service_type != "ScpKeyCustodyAttestation");

        // Add the new entry.
        let service = attestation.to_service_entry(&self.id)?;
        self.service.push(service);
        Ok(())
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
    /// Returns [`IdentityError::DocumentDeserializationError`] if a device
    /// attestation service entry exists but the endpoint cannot be base64-decoded.
    pub fn device_attestation_token(&self) -> Result<Option<Vec<u8>>, IdentityError> {
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
                        IdentityError::DocumentDeserializationError(format!(
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
    /// The token is produced by [`DeviceAttestation::attest()`] from the
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
    /// Returns [`IdentityError::AgentKeyAlreadyExists`] if an `#agent` VM
    /// is already present.
    pub fn add_agent_key(&mut self, public_key: &[u8]) -> Result<(), IdentityError> {
        if self.has_agent_key() {
            return Err(IdentityError::AgentKeyAlreadyExists);
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
    /// Returns [`IdentityError::AgentKeyNotFound`] if no `#agent` VM exists.
    pub fn remove_agent_key(&mut self) -> Result<(), IdentityError> {
        if !self.has_agent_key() {
            return Err(IdentityError::AgentKeyNotFound);
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
    /// Returns [`IdentityError::AgentKeyNotFound`] if no `#agent` VM exists.
    pub fn rotate_agent_key(
        &mut self,
        new_public_key: &[u8],
        sequence: u64,
    ) -> Result<(), IdentityError> {
        if !self.has_agent_key() {
            return Err(IdentityError::AgentKeyNotFound);
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
    /// Returns [`IdentityError::MultipleAgentKeys`] if more than one `#agent`
    /// VM is found.
    pub fn validate_agent_keys(&self) -> Result<(), IdentityError> {
        let agent_count = self
            .verification_method
            .iter()
            .filter(|vm| vm.id.ends_with("#agent"))
            .count();

        if agent_count > 1 {
            return Err(IdentityError::MultipleAgentKeys { count: agent_count });
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
        retired.sort_by(|a, b| b.1.cmp(&a.1));

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
/// and a timestamp. Context participants use [`verify_migration`] to verify the
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
/// The signature covers `SHA-256("SCP-MIGRATION-V1:" || old_did || new_did
/// || rotated_at)` and is signed by the old Identity Key. This provides
/// MODERATE assurance that the migration was authorized by the DID owner.
/// The `SCP-MIGRATION-V1:` domain separator prevents cross-protocol
/// signature confusion.
///
/// See ADR-003 acceptance criterion 4c.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationProof {
    /// Ed25519 signature of `SHA-256("SCP-MIGRATION-V1:" || old_did
    /// || new_did || rotated_at)` signed by the old Identity Key. Must be
    /// exactly 64 bytes (Ed25519).
    #[serde(with = "serde_signature_64")]
    pub signature: [u8; 64],
    /// The old Identity Key's public bytes, for verification without resolving
    /// the old DID document.
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
    /// `PreRotationCommitment` service (`sha256:<hex>`).
    pub commitment: [u8; 32],
    /// The new Identity Key public bytes. `SHA-256(this)` must equal
    /// `commitment`.
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

    // --- MigrationProof.signature [u8; 64] tests (SCP-202) ---

    /// Helper: build a JSON object for `MigrationProof` with a signature of
    /// the given length. The `old_public_key` is always a valid 32-byte array.
    fn migration_proof_json_with_sig_len(len: usize) -> String {
        let sig_array: Vec<String> = (0..len).map(|i| ((i % 256) as u8).to_string()).collect();
        let pk_array: Vec<String> = (0..32).map(|_| "1".to_owned()).collect();
        format!(
            r#"{{"signature":[{}],"old_public_key":[{}]}}"#,
            sig_array.join(","),
            pk_array.join(",")
        )
    }

    #[test]
    fn migration_proof_64_byte_signature_accepted() {
        let json = migration_proof_json_with_sig_len(64);
        let proof: MigrationProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof.signature.len(), 64);
        // Verify the bytes are correct.
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
    fn migration_proof_signature_json_roundtrip() {
        let proof = MigrationProof {
            signature: [0xAA; 64],
            old_public_key: [0xBB; 32],
        };
        let json = serde_json::to_string(&proof).unwrap();
        let parsed: MigrationProof = serde_json::from_str(&json).unwrap();
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

        // Tamper with the service endpoint to have invalid hex.
        let svc = doc
            .service
            .iter_mut()
            .find(|s| s.service_type == "ScpDeviceAttestation")
            .unwrap();
        svc.service_endpoint = "data:application/octet-stream;hex,ZZZZ".to_owned();

        let result = doc.device_attestation_token();
        assert!(result.is_err());
    }
}
