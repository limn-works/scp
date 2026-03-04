//! SCP credential type for MLS `LeafNode` credential fields.
//!
//! The SCP credential wraps a DID (decentralized identifier), an optional
//! UCAN (User Controlled Authorization Network) token, and a signing key
//! identifier. This credential is serialized via `MessagePack` and stored as
//! an MLS `BasicCredential` identity payload. See ADR-001 and spec section
//! 9.7.1 for the credential design, and ADR-039 for the signing key model.

use scp_identity::SigningKeyId;
use serde::{Deserialize, Serialize};

use super::error::MlsError;

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
        if !did.starts_with("did:dht:z") {
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
        let result = ScpCredential::new(
            "did:key:z6MkSomething".to_string(),
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
}
