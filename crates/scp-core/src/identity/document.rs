//! DID Document construction, serialization, and verification method management.
//!
//! Implements the W3C DID Document JSON-LD format for `did:dht` identities.
//! The document contains verification methods (Identity Key `#0`, Active Signing
//! Key `#active`), authentication and assertion method references, and service
//! entries (`PreRotationCommitment`, `SCPRelay`).
//!
//! # Key Rotation Support (SCP-008)
//!
//! The document supports key rotation through:
//! - [`DidDocument::retire_active_key`] — Retires the current active key and adds
//!   a new one (Layer 1 rotation).
//! - [`DidDocument::set_also_known_as`] — Sets the `alsoKnownAs` field for
//!   identity migration (Layer 2 rotation).
//! - [`DidRotationEvent`], [`MigrationProof`], [`PreRotationProof`] — Structs for
//!   distributing and verifying identity migrations.
//!
//! See ADR-003 in `.docs/adrs/phase-1.md`.

use super::IdentityError;
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
/// references, and services as specified by ADR-003. The document is
/// JSON-serializable via `serde_json`.
///
/// # Structure
///
/// - Verification method `#0`: the Identity Key (Ed25519). Used only for DID
///   document updates and pre-rotation commitments.
/// - Verification method `#active`: the Active Signing Key (Ed25519). Used for
///   MLS credentials, inner envelope signatures, and UCAN issuance.
/// - `authentication` and `assertionMethod` reference `#active`.
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

/// The required URL scheme for `SCPRelay` entries.
const SCP_RELAY_SCHEME: &str = "wss://";

/// The required path suffix for `SCPRelay` entries.
const SCP_RELAY_PATH: &str = "/scp/v1";

impl DidDocument {
    /// Constructs a new DID Document for an SCP identity.
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

        let pre_rotation_service = Service {
            id: format!("{did}#pre-rotation"),
            service_type: "PreRotationCommitment".to_owned(),
            service_endpoint: format!("sha256:{}", hex_encode(pre_rotation_commitment)),
        };

        Self {
            context: vec![DID_CONTEXT.to_owned(), ED25519_CONTEXT.to_owned()],
            id: did.to_owned(),
            verification_method: vec![identity_vm, active_vm],
            authentication: vec![format!("{did}#active")],
            assertion_method: vec![format!("{did}#active")],
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
        self.authentication = vec![format!("{did}#active")];
        self.assertion_method = vec![format!("{did}#active")];
    }

    /// Sets the `alsoKnownAs` field to point to a new DID.
    ///
    /// Used during Layer 2 identity migration to create a forwarding record
    /// from the old DID to the new DID.
    pub fn set_also_known_as(&mut self, new_did: &str) {
        self.also_known_as = vec![new_did.to_owned()];
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
/// The signature covers `SHA-256(old_did || new_did || rotated_at)` and is
/// signed by the old Identity Key. This provides MODERATE assurance that the
/// migration was authorized by the DID owner.
///
/// See ADR-003 acceptance criterion 4c.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationProof {
    /// Ed25519 signature of `SHA-256(old_did || new_did || rotated_at)`
    /// signed by the old Identity Key. Must be exactly 64 bytes (Ed25519).
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

/// Encodes bytes as lowercase hexadecimal.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write;
        // write! to a String is infallible, but we must handle the Result
        // to satisfy clippy. The error case is unreachable for String.
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// Base58btc encoding (Bitcoin alphabet) via the `bs58` crate.
fn base58btc_encode(input: &[u8]) -> String {
    bs58::encode(input).into_string()
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
    fn hex_encode_produces_lowercase_hex() {
        let bytes = [0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(hex_encode(&bytes), "deadbeef");
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
}
