//! SCP credential type for MLS `LeafNode` credential fields.
//!
//! [`ScpCredential`] bundles a DID string and UCAN token bytes into a
//! format compatible with `OpenMLS`'s [`Credential`] type. The credential
//! is serialized via `MessagePack` and stored as the identity payload of
//! a [`BasicCredential`], which `OpenMLS` treats as an opaque byte vector.
//!
//! See ADR-001 (credential contains the creator's DID and UCAN token,
//! spec section 9.7.1).
//!
//! [`Credential`]: openmls::prelude::Credential
//! [`BasicCredential`]: openmls::prelude::BasicCredential

use openmls::prelude::{BasicCredential, Credential, CredentialWithKey, SignaturePublicKey};
use serde::{Deserialize, Serialize};

use super::error::MlsError;

/// An SCP-specific credential containing a DID identifier and UCAN
/// authorization token.
///
/// This credential is embedded in MLS `LeafNode`s so that group members
/// can verify both the identity (DID) and authorization (UCAN) of every
/// participant. The DID traces the participant back to a human-controlled
/// identity, satisfying the "human accountability" tenet.
///
/// # Wire format
///
/// The credential is serialized to `MessagePack` and stored as the opaque
/// identity bytes of an `OpenMLS` [`BasicCredential`]. Other SCP clients
/// deserialize the identity bytes back into an `ScpCredential` after
/// extracting the `BasicCredential` from a `LeafNode`.
///
/// # Example
///
/// ```rust
/// use scp_core::crypto::mls::credential::ScpCredential;
///
/// let cred = ScpCredential::new(
///     "did:dht:z6MkExample".to_string(),
///     vec![0xCA, 0xFE],
/// );
/// assert_eq!(cred.did(), "did:dht:z6MkExample");
/// assert_eq!(cred.ucan_bytes(), &[0xCA, 0xFE]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScpCredential {
    /// The participant's decentralized identifier (e.g., `did:dht:z6Mk...`).
    did: String,
    /// UCAN authorization token bytes (CID-encoded or raw JWT).
    ucan: Vec<u8>,
}

impl ScpCredential {
    /// Creates a new SCP credential from a DID string and UCAN token bytes.
    #[must_use]
    pub const fn new(did: String, ucan: Vec<u8>) -> Self {
        Self { did, ucan }
    }

    /// Returns the DID string.
    #[must_use]
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Returns the UCAN token bytes.
    #[must_use]
    pub fn ucan_bytes(&self) -> &[u8] {
        &self.ucan
    }

    /// Serializes this credential into an `OpenMLS` [`Credential`].
    ///
    /// The credential is encoded as `MessagePack` bytes and wrapped in a
    /// [`BasicCredential`]. `OpenMLS` treats the identity payload as opaque
    /// bytes, so SCP-specific semantics are invisible to the MLS layer.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::Serialization`] if `MessagePack` encoding fails.
    pub fn to_openmls_credential(&self) -> Result<Credential, MlsError> {
        let serialized = rmp_serde::to_vec(self).map_err(|e| {
            MlsError::Serialization(format!("failed to serialize ScpCredential: {e}"))
        })?;
        let basic = BasicCredential::new(serialized);
        Ok(Credential::from(basic))
    }

    /// Deserializes an [`ScpCredential`] from an `OpenMLS` [`Credential`].
    ///
    /// Extracts the [`BasicCredential`] identity bytes and decodes them
    /// from `MessagePack`.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::Credential`] if the credential is not a
    /// `BasicCredential`, or [`MlsError::Serialization`] if decoding fails.
    pub fn from_openmls_credential(credential: &Credential) -> Result<Self, MlsError> {
        let basic = BasicCredential::try_from(credential.clone())
            .map_err(|e| MlsError::Credential(format!("expected BasicCredential, got: {e}")))?;
        rmp_serde::from_slice(basic.identity()).map_err(|e| {
            MlsError::Serialization(format!("failed to deserialize ScpCredential: {e}"))
        })
    }

    /// Bundles this credential with a signature public key into a
    /// [`CredentialWithKey`] suitable for MLS group operations.
    ///
    /// The `signature_key` should be the Ed25519 public key corresponding
    /// to the participant's active signing key.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::Serialization`] if the credential cannot be
    /// serialized to `MessagePack`.
    pub fn to_credential_with_key(
        &self,
        signature_key: &[u8],
    ) -> Result<CredentialWithKey, MlsError> {
        let credential = self.to_openmls_credential()?;
        Ok(CredentialWithKey {
            credential,
            signature_key: SignaturePublicKey::from(signature_key.to_vec()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn roundtrip_through_openmls_credential() {
        let original = ScpCredential::new(
            "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
            vec![0x01, 0x02, 0x03, 0x04],
        );

        let openmls_cred = original.to_openmls_credential().unwrap();
        let recovered = ScpCredential::from_openmls_credential(&openmls_cred).unwrap();

        assert_eq!(original, recovered);
        assert_eq!(recovered.did(), original.did());
        assert_eq!(recovered.ucan_bytes(), original.ucan_bytes());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn credential_with_key_contains_correct_public_key() {
        let cred = ScpCredential::new("did:dht:z6MkTest".to_string(), vec![0xAA]);
        let pub_key = [42u8; 32];

        let cwk = cred.to_credential_with_key(&pub_key).unwrap();

        let recovered = ScpCredential::from_openmls_credential(&cwk.credential).unwrap();
        assert_eq!(recovered.did(), "did:dht:z6MkTest");
    }

    #[test]
    fn empty_ucan_is_valid() {
        let cred = ScpCredential::new("did:dht:z6MkEmpty".to_string(), vec![]);
        assert!(cred.ucan_bytes().is_empty());
        assert!(cred.to_openmls_credential().is_ok());
    }
}
