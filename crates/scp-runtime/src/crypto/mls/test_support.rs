//! Test-only minting of attested `KeyPackages` through an [`MlsBackend`], with
//! the attestation signed by a local Ed25519 key in place of custody.
//!
//! Production mints through
//! [`mint_attested_key_package`](super::attestation_signer::mint_attested_key_package),
//! which signs with the owner's custody-backed `#active` key after checking
//! it against the owner's DID document. A test that needs a `KeyPackage` and
//! no resolver mints here.

use async_trait::async_trait;
use ed25519_dalek::{Signer as _, SigningKey};
use scp_mls::credential::ScpCredential;
use scp_mls::error::MlsError;

use super::backend::{GeneratedKeyPackage, MlsBackend};

/// Mints an attested `KeyPackage` through any [`MlsBackend`], for tests.
#[async_trait]
pub trait MintAttestedForTest {
    /// Mints a `KeyPackage` for `credential` with `wrapping_pubkey` as its
    /// `0xFF01`, its attestation signed by a fresh Ed25519 key.
    async fn mint_attested_for_test(
        &self,
        credential: &ScpCredential,
        wrapping_pubkey: &[u8; 65],
    ) -> Result<GeneratedKeyPackage, MlsError>;

    /// Mints a `KeyPackage` for `credential` with `wrapping_pubkey` as its
    /// `0xFF01`, its attestation signed by `identity_key`.
    async fn mint_attested_with_key_for_test(
        &self,
        credential: &ScpCredential,
        wrapping_pubkey: &[u8; 65],
        identity_key: &SigningKey,
    ) -> Result<GeneratedKeyPackage, MlsError>;
}

#[async_trait]
impl<B: MlsBackend + ?Sized> MintAttestedForTest for B {
    async fn mint_attested_for_test(
        &self,
        credential: &ScpCredential,
        wrapping_pubkey: &[u8; 65],
    ) -> Result<GeneratedKeyPackage, MlsError> {
        let identity_key = SigningKey::generate(&mut rand::rngs::OsRng);
        self.mint_attested_with_key_for_test(credential, wrapping_pubkey, &identity_key)
            .await
    }

    async fn mint_attested_with_key_for_test(
        &self,
        credential: &ScpCredential,
        wrapping_pubkey: &[u8; 65],
        identity_key: &SigningKey,
    ) -> Result<GeneratedKeyPackage, MlsError> {
        let draft = self
            .prepare_key_package(credential, wrapping_pubkey)
            .await?;
        let signature = identity_key.sign(&draft.signing_hash()).to_bytes();
        self.finish_key_package(draft, signature).await
    }
}
