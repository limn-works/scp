//! DID Document construction, serialization, and verification method management.
//!
//! Implements the W3C DID Document JSON-LD format for `did:dht` identities.
//! The document contains verification methods (Identity Key `#0`, Active Signing
//! Key `#active`), authentication and assertion method references, and a
//! `PreRotationCommitment` service. See ADR-003 in `.docs/adrs/phase-1.md`.

use serde::{Deserialize, Serialize};

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

/// Base58btc encoding (Bitcoin alphabet).
///
/// This is a minimal implementation sufficient for encoding Ed25519 public keys
/// (32 bytes). Production deployments may replace this with a dedicated crate.
fn base58btc_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    if input.is_empty() {
        return String::new();
    }

    // Count leading zeros.
    let zero_count = input.iter().take_while(|&&b| b == 0).count();

    // Convert to base58 via repeated division.
    let mut digits: Vec<u8> = Vec::new();
    for &byte in input {
        let mut carry = u32::from(byte);
        for digit in &mut digits {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut result = String::with_capacity(zero_count + digits.len());

    // Leading '1' characters for each leading zero byte.
    for _ in 0..zero_count {
        result.push('1');
    }

    // Digits are in reverse order.
    for &d in digits.iter().rev() {
        result.push(ALPHABET[d as usize] as char);
    }

    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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
}
