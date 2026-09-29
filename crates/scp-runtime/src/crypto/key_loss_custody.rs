//! Test custody that loses a key at a chosen step, so each custody call in the
//! sender-key and access-key wire protocols can be driven to key-not-found.
//!
//! A destroyed signing key or wrapping key reaches a `sign` or `dh_agree` call
//! through plain [`InMemoryKeyCustody`]. Three calls cannot be reached that
//! way, because the protocol obtains or uses the key inside one function:
//! `generate_keypair` itself, `public_key` on the key `generate_keypair` just
//! returned, and `public_key` on the wrapping key after `dh_agree` used it.
//! [`KeyLoss`] names each of those steps.

use scp_platform::PlatformError;
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::{
    CustodyType, KeyCustody, KeyHandle, KeyType, PseudonymKeypair, PublicKey, SharedSecret,
    Signature,
};

/// The step at which [`KeyLossCustody`] loses a key.
#[derive(Debug, Clone, Copy)]
pub enum KeyLoss {
    /// `generate_keypair` reports [`PlatformError::KeyNotFound`].
    OnGenerate,
    /// `generate_keypair` destroys the key it created before returning its
    /// handle, so the next `public_key` on that handle is key-not-found.
    AfterGenerate,
    /// `dh_agree` destroys its key after agreeing, so the next `public_key`
    /// on that handle is key-not-found.
    AfterDhAgree,
}

/// [`InMemoryKeyCustody`] that loses a key at the step [`KeyLoss`] names and
/// otherwise delegates every call unchanged.
pub struct KeyLossCustody {
    pub inner: InMemoryKeyCustody,
    pub loss: KeyLoss,
}

impl KeyLossCustody {
    pub fn new(loss: KeyLoss) -> Self {
        Self {
            inner: InMemoryKeyCustody::new(),
            loss,
        }
    }
}

impl KeyCustody for KeyLossCustody {
    async fn generate_keypair(&self, key_type: KeyType) -> Result<KeyHandle, PlatformError> {
        match self.loss {
            KeyLoss::OnGenerate => Err(PlatformError::KeyNotFound),
            KeyLoss::AfterGenerate => {
                let handle = self.inner.generate_keypair(key_type).await?;
                self.inner.destroy_key(&handle).await?;
                Ok(handle)
            }
            KeyLoss::AfterDhAgree => self.inner.generate_keypair(key_type).await,
        }
    }

    async fn generate_identity_keypair(&self) -> Result<KeyHandle, PlatformError> {
        self.inner.generate_identity_keypair().await
    }

    async fn sign(&self, key: &KeyHandle, data: &[u8]) -> Result<Signature, PlatformError> {
        self.inner.sign(key, data).await
    }

    async fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, PlatformError> {
        self.inner.public_key(key).await
    }

    async fn destroy_key(&self, key: &KeyHandle) -> Result<(), PlatformError> {
        self.inner.destroy_key(key).await
    }

    async fn dh_agree(
        &self,
        key: &KeyHandle,
        peer_public: &[u8],
    ) -> Result<SharedSecret, PlatformError> {
        let shared = self.inner.dh_agree(key, peer_public).await?;
        if matches!(self.loss, KeyLoss::AfterDhAgree) {
            self.inner.destroy_key(key).await?;
        }
        Ok(shared)
    }

    async fn derive_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
    ) -> Result<PseudonymKeypair, PlatformError> {
        self.inner.derive_pseudonym(key, context_id).await
    }

    async fn derive_rotatable_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
        pseudonym_epoch: u64,
    ) -> Result<PseudonymKeypair, PlatformError> {
        self.inner
            .derive_rotatable_pseudonym(key, context_id, pseudonym_epoch)
            .await
    }

    async fn ed25519_to_x25519_agree(
        &self,
        ed25519_handle: &KeyHandle,
        peer_x25519_public: &[u8; 32],
    ) -> Result<SharedSecret, PlatformError> {
        self.inner
            .ed25519_to_x25519_agree(ed25519_handle, peer_x25519_public)
            .await
    }

    fn custody_type(&self, key: &KeyHandle) -> CustodyType {
        self.inner.custody_type(key)
    }
}
