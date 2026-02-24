//! SCP credential type for MLS `LeafNode` credential fields.
//!
//! The SCP credential wraps a DID (decentralized identifier) and an optional
//! UCAN (User Controlled Authorization Network) token. This credential is
//! serialized via `MessagePack` and stored as an MLS `BasicCredential` identity
//! payload. See ADR-001 and spec section 9.7.1 for the credential design.

use serde::{Deserialize, Serialize};

use super::error::MlsError;

/// An SCP credential containing the participant's DID and optional UCAN token.
///
/// This struct is serialized to `MessagePack` bytes and used as the identity
/// payload inside an MLS `BasicCredential`. Every MLS `LeafNode` in an SCP
/// context carries one of these credentials, binding the MLS group member to
/// their decentralized identity.
///
/// # Fields
///
/// - `did`: The participant's `did:dht` identifier (e.g., `"did:dht:z6Mk..."`).
/// - `ucan_token`: An optional UCAN authorization token that scopes the
///   participant's capabilities within the context. `None` for the group
///   creator at creation time (the creator implicitly has full capabilities).
///
/// # Serialization
///
/// Serialized via `rmp-serde` (`MessagePack`) for compact binary representation
/// suitable for embedding in MLS credentials.
///
/// See ADR-001 for the MLS wrapper design and spec section 9.7.1 for the
/// SCP-to-MLS concept mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScpCredential {
    /// The participant's decentralized identifier (DID).
    pub did: String,
    /// Optional UCAN authorization token scoping this participant's
    /// capabilities within the context.
    pub ucan_token: Option<String>,
}

impl ScpCredential {
    /// Creates a new SCP credential with the given DID and optional UCAN token.
    ///
    /// # Arguments
    ///
    /// * `did` - The participant's `did:dht` identifier.
    /// * `ucan_token` - An optional UCAN authorization token.
    #[must_use]
    pub const fn new(did: String, ucan_token: Option<String>) -> Self {
        Self { did, ucan_token }
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
    fn credential_roundtrip_with_ucan() {
        let cred = ScpCredential::new(
            "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
            Some("eyJhbGciOiJFZERTQSJ9.test-ucan-token".to_string()),
        );
        let bytes = cred.to_bytes().unwrap();
        let decoded = ScpCredential::from_bytes(&bytes).unwrap();
        assert_eq!(cred, decoded);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn credential_roundtrip_without_ucan() {
        let cred = ScpCredential::new(
            "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
            None,
        );
        let bytes = cred.to_bytes().unwrap();
        let decoded = ScpCredential::from_bytes(&bytes).unwrap();
        assert_eq!(cred, decoded);
    }

    #[test]
    fn credential_from_invalid_bytes_returns_error() {
        let result = ScpCredential::from_bytes(&[0xff, 0xfe, 0xfd]);
        assert!(result.is_err());
    }
}
