//! WASM-local SCP credential for MLS `LeafNode` identity payloads.
//!
//! Ports `scp_core::crypto::mls::credential::ScpCredential` into a
//! WASM-compatible form. Serialization uses `MessagePack` (`rmp-serde`)
//! for binary compatibility with scp-core credentials.
//!
//! See ADR-001 and spec section 9.7.1 for the credential design,
//! and ADR-039 for the signing key model.

use serde::{Deserialize, Serialize};

use super::error::WasmCryptoError;

/// Identifies which DID document verification method signed a credential.
///
/// Maps to `scp_identity::SigningKeyId`. Serialized as `"#active"` or
/// `"#agent"` via serde, matching the scp-core format for `MessagePack`
/// interoperability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmSigningKeyId {
    /// The `#active` verification method (human or primary key).
    #[serde(rename = "#active")]
    Active,
    /// The `#agent` verification method (agent key per ADR-039).
    #[serde(rename = "#agent")]
    Agent,
}

impl WasmSigningKeyId {
    /// Returns the DID document fragment for this signing key ID.
    #[must_use]
    pub const fn fragment(&self) -> &str {
        match self {
            Self::Active => "#active",
            Self::Agent => "#agent",
        }
    }
}

/// Returns the default `WasmSigningKeyId` (`Active`) for serde deserialization
/// of credentials that predate the `signing_key_id` field (backward compat).
const fn default_signing_key_id() -> WasmSigningKeyId {
    WasmSigningKeyId::Active
}

/// An SCP credential containing the participant's DID, optional UCAN token,
/// and signing key identifier.
///
/// This struct is serialized to `MessagePack` bytes and used as the identity
/// payload inside an MLS `BasicCredential`. The format is byte-compatible
/// with `scp_core::crypto::mls::credential::ScpCredential`.
///
/// See ADR-001 for the MLS wrapper design, spec section 9.7.1 for the
/// SCP-to-MLS concept mapping, and ADR-039 for the signing key model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmScpCredential {
    /// The participant's decentralized identifier (DID).
    pub did: String,
    /// Optional UCAN authorization token.
    pub ucan_token: Option<String>,
    /// Which DID document verification method signed this credential.
    #[serde(default = "default_signing_key_id")]
    pub signing_key_id: WasmSigningKeyId,
}

impl WasmScpCredential {
    /// Creates a new SCP credential with the given DID, optional UCAN token,
    /// and signing key identifier.
    ///
    /// The DID must be a valid `did:dht` identifier starting with `"did:dht:z"`.
    ///
    /// # Errors
    ///
    /// Returns [`WasmCryptoError::InvalidDidFormat`] if the DID does not start
    /// with `"did:dht:z"`.
    pub fn new(
        did: String,
        ucan_token: Option<String>,
        signing_key_id: WasmSigningKeyId,
    ) -> Result<Self, WasmCryptoError> {
        if !did.starts_with("did:dht:z") {
            return Err(WasmCryptoError::InvalidDidFormat(did));
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
    /// Returns [`WasmCryptoError::CredentialSerializationFailed`] if
    /// `MessagePack` serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, WasmCryptoError> {
        rmp_serde::to_vec(self)
            .map_err(|e| WasmCryptoError::CredentialSerializationFailed(e.to_string()))
    }

    /// Deserializes an SCP credential from `MessagePack` bytes.
    ///
    /// Handles both the current format (with `signing_key_id`) and the legacy
    /// format (without it, defaults to `WasmSigningKeyId::Active`).
    ///
    /// # Errors
    ///
    /// Returns [`WasmCryptoError::CredentialSerializationFailed`] if the
    /// bytes are not valid `MessagePack` or do not represent a valid credential.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WasmCryptoError> {
        rmp_serde::from_slice(bytes)
            .map_err(|e| WasmCryptoError::CredentialSerializationFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DID: &str = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    #[test]
    #[allow(clippy::unwrap_used)]
    fn credential_roundtrip_active() {
        let cred = WasmScpCredential::new(
            TEST_DID.to_string(),
            Some("eyJhbGciOiJFZERTQSJ9.test-ucan-token".to_string()),
            WasmSigningKeyId::Active,
        )
        .unwrap();
        let bytes = cred.to_bytes().unwrap();
        let decoded = WasmScpCredential::from_bytes(&bytes).unwrap();
        assert_eq!(cred, decoded);
        assert_eq!(decoded.signing_key_id, WasmSigningKeyId::Active);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn credential_roundtrip_agent() {
        let cred = WasmScpCredential::new(
            TEST_DID.to_string(),
            Some("eyJhbGciOiJFZERTQSJ9.test-ucan-token".to_string()),
            WasmSigningKeyId::Agent,
        )
        .unwrap();
        let bytes = cred.to_bytes().unwrap();
        let decoded = WasmScpCredential::from_bytes(&bytes).unwrap();
        assert_eq!(cred, decoded);
        assert_eq!(decoded.signing_key_id, WasmSigningKeyId::Agent);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn credential_roundtrip_without_ucan() {
        let cred =
            WasmScpCredential::new(TEST_DID.to_string(), None, WasmSigningKeyId::Active).unwrap();
        let bytes = cred.to_bytes().unwrap();
        let decoded = WasmScpCredential::from_bytes(&bytes).unwrap();
        assert_eq!(cred, decoded);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn backward_compat_old_format_defaults_to_active() {
        // Simulate legacy credential without signing_key_id.
        #[derive(Serialize)]
        struct LegacyCredential {
            did: String,
            ucan_token: Option<String>,
        }
        let legacy = LegacyCredential {
            did: TEST_DID.to_string(),
            ucan_token: Some("test-ucan".to_string()),
        };
        let bytes = rmp_serde::to_vec(&legacy).unwrap();
        let decoded = WasmScpCredential::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.did, TEST_DID);
        assert_eq!(decoded.signing_key_id, WasmSigningKeyId::Active);
    }

    #[test]
    fn credential_from_invalid_bytes_returns_error() {
        let result = WasmScpCredential::from_bytes(&[0xff, 0xfe, 0xfd]);
        assert!(result.is_err());
    }

    #[test]
    fn new_rejects_empty_did() {
        let result = WasmScpCredential::new(String::new(), None, WasmSigningKeyId::Active);
        assert!(result.is_err());
    }

    #[test]
    fn new_rejects_wrong_method() {
        let result = WasmScpCredential::new(
            "did:key:z6MkSomething".to_string(),
            None,
            WasmSigningKeyId::Active,
        );
        assert!(result.is_err());
    }

    #[test]
    fn new_rejects_missing_z_prefix() {
        let result =
            WasmScpCredential::new("did:dht:abc123".to_string(), None, WasmSigningKeyId::Active);
        assert!(result.is_err());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn signing_key_id_preserved_in_roundtrip() {
        for key_id in [WasmSigningKeyId::Active, WasmSigningKeyId::Agent] {
            let cred = WasmScpCredential::new(TEST_DID.to_string(), None, key_id).unwrap();
            let bytes = cred.to_bytes().unwrap();
            let decoded = WasmScpCredential::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.signing_key_id, key_id);
        }
    }
}
