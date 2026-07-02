//! SCP credential type for MLS `LeafNode` credential fields.
//!
//! The SCP credential wraps a DID (decentralized identifier), an optional
//! UCAN (User Controlled Authorization Network) token, and a signing key
//! identifier. This credential is serialized via `MessagePack` and stored as
//! an MLS `BasicCredential` identity payload. See ADR-001 and spec section
//! 9.7.1 for the credential design, and ADR-039 for the signing key model.

// DID-document types come from `scp-protocol` directly (Slice 1a moved them
// there for wasm32-safety), NOT from the tokio-coupled `scp-identity` — keeping
// `scp-mls` inside the ADR-057 mechanical fence. `SigningKeyId` is hosted in
// `scp-primitives`.
use scp_did::SigningKeyId;
use scp_did::{DidDocument, decode_multibase_key};
use serde::{Deserialize, Serialize};

use crate::error::MlsError;

/// Returns the default `SigningKeyId` (`Active`) for serde deserialization of
/// credentials that predate the `signing_key_id` field (backward compat).
const fn default_signing_key_id() -> SigningKeyId {
    SigningKeyId::Active
}

/// An SCP credential containing the participant's DID, optional UCAN token,
/// and signing key identifier.
///
/// This struct is serialized to `MessagePack` bytes and used as the identity
/// payload inside an MLS `BasicCredential`. Every MLS `LeafNode` in an SCP
/// context carries one of these credentials, binding the MLS group member to
/// their decentralized identity and indicating which verification method
/// (`#active` or `#agent`) signed the credential.
///
/// # Fields
///
/// - `did`: The participant's `did:dht` identifier (e.g., `"did:dht:z6Mk..."`).
/// - `ucan_token`: An optional UCAN authorization token that scopes the
///   participant's capabilities within the context. `None` for the group
///   creator at creation time (the creator implicitly has full capabilities).
/// - `signing_key_id`: Which DID document verification method (`#active` or
///   `#agent`) signed this credential. Defaults to `Active` for backward
///   compatibility with credentials serialized before this field existed.
///
/// # Serialization
///
/// Serialized via `rmp-serde` (`MessagePack`) for compact binary representation
/// suitable for embedding in MLS credentials.
///
/// # Backward Compatibility
///
/// Credentials serialized before the `signing_key_id` field was added will
/// deserialize successfully with `signing_key_id` defaulting to
/// `SigningKeyId::Active`. This is correct because all pre-ADR-039 credentials
/// were signed by the active key (there was no agent key concept).
///
/// See ADR-001 for the MLS wrapper design, spec section 9.7.1 for the
/// SCP-to-MLS concept mapping, and ADR-039 for the signing key model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScpCredential {
    /// The participant's decentralized identifier (DID).
    pub did: String,
    /// Optional UCAN authorization token scoping this participant's
    /// capabilities within the context.
    pub ucan_token: Option<String>,
    /// Which DID document verification method signed this credential.
    /// Defaults to `Active` for backward compatibility with pre-ADR-039
    /// credentials.
    #[serde(default = "default_signing_key_id")]
    pub signing_key_id: SigningKeyId,
}

impl ScpCredential {
    /// Creates a new SCP credential with the given DID, optional UCAN token,
    /// and signing key identifier.
    ///
    /// The DID must be a valid `did:dht` identifier starting with `"did:dht:z"`.
    ///
    /// # Arguments
    ///
    /// * `did` - The participant's `did:dht` identifier (must start with `"did:dht:z"`).
    /// * `ucan_token` - An optional UCAN authorization token.
    /// * `signing_key_id` - Which verification method (`#active` or `#agent`) signs
    ///   this credential.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::InvalidDidFormat`] if the DID does not start with
    /// `"did:dht:z"`.
    pub fn new(
        did: String,
        ucan_token: Option<String>,
        signing_key_id: SigningKeyId,
    ) -> Result<Self, MlsError> {
        // Production requires `did:dht:z*`. Under `cfg(test)` / `testing`
        // feature also accept `did:key:*` and `did:test:*` so the broad
        // test suite (previously trait-mocked via MockCrypto) continues
        // to work with the inherent `MlsCryptoProvider` API after ADR-049
        // commit 12c.9e.
        let accepted = did.starts_with("did:dht:z")
            || (cfg!(any(test, feature = "testing"))
                && (did.starts_with("did:test:") || did.starts_with("did:key:")));
        if !accepted {
            return Err(MlsError::InvalidDidFormat(did));
        }
        Ok(Self {
            did,
            ucan_token,
            signing_key_id,
        })
    }

    /// Serializes this credential to `MessagePack` bytes.
    ///
    /// The resulting bytes are suitable for use as the identity payload in an
    /// MLS `BasicCredential`.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::CredentialSerializationFailed`] if `MessagePack`
    /// serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MlsError> {
        rmp_serde::to_vec(self).map_err(|e| MlsError::CredentialSerializationFailed(e.to_string()))
    }

    /// Deserializes an SCP credential from `MessagePack` bytes.
    ///
    /// Handles both the current format (with `signing_key_id`) and the legacy
    /// format (without it, defaults to `SigningKeyId::Active`).
    ///
    /// # Arguments
    ///
    /// * `bytes` - `MessagePack`-encoded credential bytes, typically extracted
    ///   from an MLS `BasicCredential` identity payload.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::CredentialSerializationFailed`] if the bytes are
    /// not valid `MessagePack` or do not represent a valid [`ScpCredential`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MlsError> {
        rmp_serde::from_slice(bytes)
            .map_err(|e| MlsError::CredentialSerializationFailed(e.to_string()))
    }

    /// Resolves the signing public key bytes from a DID document based on
    /// this credential's [`signing_key_id`](Self::signing_key_id).
    ///
    /// - [`SigningKeyId::Active`] resolves the `#active` verification method.
    /// - [`SigningKeyId::Agent`] resolves the `#agent` verification method.
    ///
    /// The returned bytes are the raw 32-byte Ed25519 public key, decoded
    /// from the verification method's `publicKeyMultibase` field.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::InvalidCredential`] if:
    /// - The DID document does not contain the required verification method
    ///   (e.g., `#agent` is absent).
    /// - The public key multibase encoding is invalid or not 32 bytes.
    pub fn resolve_signing_key(&self, did_doc: &DidDocument) -> Result<[u8; 32], MlsError> {
        let fragment = self.signing_key_id.fragment();
        let vm = did_doc
            .verification_method_by_fragment(fragment)
            .ok_or_else(|| {
                MlsError::InvalidCredential(format!(
                    "DID document for {} has no #{fragment} verification method",
                    self.did
                ))
            })?;

        decode_multibase_key(&vm.public_key_multibase).map_err(|e| {
            MlsError::InvalidCredential(format!(
                "failed to decode #{fragment} public key from DID document: {e}"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn credential_roundtrip_with_ucan_active() {
        let cred = ScpCredential::new(
            "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
            Some("eyJhbGciOiJFZERTQSJ9.test-ucan-token".to_string()),
            SigningKeyId::Active,
        )
        .unwrap();
        let bytes = cred.to_bytes().unwrap();
        let decoded = ScpCredential::from_bytes(&bytes).unwrap();
        assert_eq!(cred, decoded);
        assert_eq!(decoded.signing_key_id, SigningKeyId::Active);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn credential_roundtrip_with_ucan_agent() {
        let cred = ScpCredential::new(
            "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
            Some("eyJhbGciOiJFZERTQSJ9.test-ucan-token".to_string()),
            SigningKeyId::Agent,
        )
        .unwrap();
        let bytes = cred.to_bytes().unwrap();
        let decoded = ScpCredential::from_bytes(&bytes).unwrap();
        assert_eq!(cred, decoded);
        assert_eq!(decoded.signing_key_id, SigningKeyId::Agent);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn credential_roundtrip_without_ucan() {
        let cred = ScpCredential::new(
            "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
            None,
            SigningKeyId::Active,
        )
        .unwrap();
        let bytes = cred.to_bytes().unwrap();
        let decoded = ScpCredential::from_bytes(&bytes).unwrap();
        assert_eq!(cred, decoded);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn credential_roundtrip_agent_without_ucan() {
        let cred = ScpCredential::new(
            "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
            None,
            SigningKeyId::Agent,
        )
        .unwrap();
        let bytes = cred.to_bytes().unwrap();
        let decoded = ScpCredential::from_bytes(&bytes).unwrap();
        assert_eq!(cred, decoded);
        assert_eq!(decoded.signing_key_id, SigningKeyId::Agent);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn backward_compat_old_format_defaults_to_active() {
        // Simulate the old format: a MessagePack map with only `did` and `ucan_token`.
        // Serialize a legacy-shaped struct without signing_key_id.
        #[derive(Serialize)]
        struct LegacyCredential {
            did: String,
            ucan_token: Option<String>,
        }
        let legacy = LegacyCredential {
            did: "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
            ucan_token: Some("test-ucan".to_string()),
        };
        let bytes = rmp_serde::to_vec(&legacy).unwrap();

        // Deserialize as the new ScpCredential — should default signing_key_id to Active.
        let decoded = ScpCredential::from_bytes(&bytes).unwrap();
        assert_eq!(
            decoded.did,
            "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
        assert_eq!(decoded.ucan_token.as_deref(), Some("test-ucan"));
        assert_eq!(
            decoded.signing_key_id,
            SigningKeyId::Active,
            "legacy credentials without signing_key_id must default to Active"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn backward_compat_old_format_no_ucan_defaults_to_active() {
        #[derive(Serialize)]
        struct LegacyCredential {
            did: String,
            ucan_token: Option<String>,
        }
        let legacy = LegacyCredential {
            did: "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
            ucan_token: None,
        };
        let bytes = rmp_serde::to_vec(&legacy).unwrap();

        let decoded = ScpCredential::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.ucan_token, None);
        assert_eq!(
            decoded.signing_key_id,
            SigningKeyId::Active,
            "legacy credentials without signing_key_id must default to Active"
        );
    }

    #[test]
    fn credential_from_invalid_bytes_returns_error() {
        let result = ScpCredential::from_bytes(&[0xff, 0xfe, 0xfd]);
        assert!(result.is_err());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn new_accepts_valid_did() {
        let cred = ScpCredential::new(
            "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
            None,
            SigningKeyId::Active,
        )
        .unwrap();
        assert_eq!(
            cred.did,
            "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
    }

    #[test]
    fn new_rejects_empty_did() {
        let result = ScpCredential::new(String::new(), None, SigningKeyId::Active);
        assert!(result.is_err());
    }

    #[test]
    fn new_rejects_wrong_method() {
        // Use a method rejected in ALL build configurations. Under
        // `cfg(test)`/`testing` the constructor also accepts `did:key:` and
        // `did:test:` (fixture convenience for the inherent
        // `MlsCryptoProvider` API), so the rejection test must use a method
        // outside that set — `did:web:` is rejected in test and production.
        let result = ScpCredential::new(
            "did:web:example.com".to_string(),
            None,
            SigningKeyId::Active,
        );
        assert!(result.is_err());
    }

    #[test]
    fn new_rejects_missing_z_prefix() {
        let result = ScpCredential::new("did:dht:abc123".to_string(), None, SigningKeyId::Active);
        assert!(result.is_err());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn signing_key_id_preserved_in_roundtrip() {
        for key_id in [SigningKeyId::Active, SigningKeyId::Agent] {
            let cred = ScpCredential::new(
                "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
                None,
                key_id,
            )
            .unwrap();
            let bytes = cred.to_bytes().unwrap();
            let decoded = ScpCredential::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.signing_key_id, key_id);
        }
    }

    // -----------------------------------------------------------------------
    // resolve_signing_key tests (SCP-AB-011 AC4-7)
    // -----------------------------------------------------------------------

    const TEST_DID: &str = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    /// Helper: generate a valid Ed25519 public key. `decode_multibase_key`
    /// enforces curve-point validity, so test fixtures cannot use
    /// arbitrary `[Nu8; 32]` byte patterns — they must be real public
    /// keys.
    fn fresh_ed25519_pub() -> [u8; 32] {
        ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng)
            .verifying_key()
            .to_bytes()
    }

    /// Helper: creates a DID document with `#active` and optionally `#agent` VMs.
    fn test_did_doc(active_key: &[u8; 32], agent_key: Option<&[u8; 32]>) -> DidDocument {
        // Identity key must also decompress to a valid Ed25519 point so
        // any future caller that decodes #0 doesn't trip the curve-point
        // check. `commitment` is just a SHA-256-shaped opaque value, no
        // curve constraint.
        let identity_key = fresh_ed25519_pub();
        let commitment = [0u8; 32];
        let mut doc = DidDocument::new(TEST_DID, &identity_key, active_key, &commitment);

        if let Some(agent_pk) = agent_key {
            let agent_vm = scp_did::VerificationMethod {
                id: format!("{TEST_DID}#agent"),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: TEST_DID.to_owned(),
                public_key_multibase: format!("z{}", bs58::encode(agent_pk).into_string()),
            };
            doc.verification_method.push(agent_vm);
        }

        doc
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn resolve_signing_key_active_returns_active_vm() {
        let active_key = fresh_ed25519_pub();
        let doc = test_did_doc(&active_key, None);

        let cred = ScpCredential::new(TEST_DID.to_string(), None, SigningKeyId::Active).unwrap();
        let resolved = cred.resolve_signing_key(&doc).unwrap();
        assert_eq!(resolved, active_key);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn resolve_signing_key_agent_returns_agent_vm() {
        let active_key = fresh_ed25519_pub();
        let agent_key = fresh_ed25519_pub();
        let doc = test_did_doc(&active_key, Some(&agent_key));

        let cred = ScpCredential::new(TEST_DID.to_string(), None, SigningKeyId::Agent).unwrap();
        let resolved = cred.resolve_signing_key(&doc).unwrap();
        assert_eq!(resolved, agent_key);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn resolve_signing_key_agent_missing_vm_returns_error() {
        let active_key = fresh_ed25519_pub();
        // No agent key in this document.
        let doc = test_did_doc(&active_key, None);

        let cred = ScpCredential::new(TEST_DID.to_string(), None, SigningKeyId::Agent).unwrap();
        let result = cred.resolve_signing_key(&doc);
        assert!(result.is_err(), "must error when #agent VM is absent");

        let err_msg = format!("{result:?}");
        assert!(
            err_msg.contains("#agent"),
            "error should mention #agent, got: {err_msg}"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn resolve_signing_key_active_with_agent_present_still_returns_active() {
        let active_key = fresh_ed25519_pub();
        let agent_key = fresh_ed25519_pub();
        let doc = test_did_doc(&active_key, Some(&agent_key));

        // Credential uses Active — should get the active key, not the agent key.
        let cred = ScpCredential::new(TEST_DID.to_string(), None, SigningKeyId::Active).unwrap();
        let resolved = cred.resolve_signing_key(&doc).unwrap();
        assert_eq!(resolved, active_key);
        assert_ne!(resolved, agent_key);
    }
}
