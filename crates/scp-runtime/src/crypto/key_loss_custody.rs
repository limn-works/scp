//! Test custody that loses a key at a chosen step, so each custody call in the
//! sender-key and access-key wire protocols can be driven to key-not-found.
//!
//! A destroyed signing key reaches a `sign` call through plain
//! [`InMemoryKeyCustody`]. A wrapping key is loaded at an entry point, which
//! reads its public key from custody, so a key destroyed before an actor turn
//! agrees with it fails the load instead; [`KeyLoss::OnDhAgree`] fails the
//! agree itself, with the key still loaded. Four further calls cannot be
//! reached by destroying a key from outside, because the protocol obtains or
//! uses the key inside one function: `generate_keypair` itself, `public_key`
//! on the key `generate_keypair` just returned, and any call on the wrapping
//! key after `dh_agree` used it (an invitation open among them). [`KeyLoss`]
//! names each of those steps.

use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::{
    CustodyType, KeyCustody, KeyHandle, KeyType, Pseudonym, PublicKey, SharedSecret, Signature,
};
use scp_platform::{
    CustodyProbe, IndexedSignature, KeyEventSignError, KeyEventSigner, PlatformError,
    ProbeSignature, SigningChange,
};

/// The step at which [`KeyLossCustody`] loses a key.
#[derive(Debug, Clone, Copy)]
pub enum KeyLoss {
    /// `generate_keypair` and `generate_key_event_keypair` report
    /// [`PlatformError::KeyNotFound`].
    OnGenerate,
    /// `generate_keypair` and `generate_key_event_keypair` destroy the key
    /// they created before returning its handle, so the next call on that
    /// handle is key-not-found.
    AfterGenerate,
    /// `dh_agree` reports [`PlatformError::KeyNotFound`] without agreeing.
    OnDhAgree,
    /// `dh_agree` destroys its key after agreeing, so every later call on
    /// that handle (the next `dh_agree`, a reload's `public_key`) is
    /// key-not-found.
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

impl KeyLossCustody {
    /// Applies the generate-step loss to a key `minted` just created.
    async fn after_mint(
        &self,
        minted: Result<KeyHandle, PlatformError>,
    ) -> Result<KeyHandle, PlatformError> {
        let handle = minted?;
        if matches!(self.loss, KeyLoss::AfterGenerate) {
            self.inner.destroy_key(&handle).await?;
        }
        Ok(handle)
    }
}

impl KeyEventSigner for KeyLossCustody {
    type Member = KeyHandle;

    async fn sign_change(
        &self,
        member: &KeyHandle,
        change: &SigningChange,
    ) -> Result<IndexedSignature, KeyEventSignError> {
        self.inner.sign_change(member, change).await
    }

    async fn sign_probe(
        &self,
        member: &KeyHandle,
        probe: &CustodyProbe,
    ) -> Result<ProbeSignature, KeyEventSignError> {
        self.inner.sign_probe(member, probe).await
    }
}

impl KeyCustody for KeyLossCustody {
    async fn generate_keypair(&self, key_type: KeyType) -> Result<KeyHandle, PlatformError> {
        if matches!(self.loss, KeyLoss::OnGenerate) {
            return Err(PlatformError::KeyNotFound);
        }
        self.after_mint(self.inner.generate_keypair(key_type).await)
            .await
    }

    async fn generate_key_event_keypair(&self) -> Result<KeyHandle, PlatformError> {
        if matches!(self.loss, KeyLoss::OnGenerate) {
            return Err(PlatformError::KeyNotFound);
        }
        self.after_mint(self.inner.generate_key_event_keypair().await)
            .await
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
        if matches!(self.loss, KeyLoss::OnDhAgree) {
            return Err(PlatformError::KeyNotFound);
        }
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
    ) -> Result<Pseudonym, PlatformError> {
        self.inner.derive_pseudonym(key, context_id).await
    }

    async fn derive_rotatable_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
        pseudonym_epoch: u64,
    ) -> Result<Pseudonym, PlatformError> {
        self.inner
            .derive_rotatable_pseudonym(key, context_id, pseudonym_epoch)
            .await
    }

    fn custody_type(&self, key: &KeyHandle) -> CustodyType {
        self.inner.custody_type(key)
    }
}
