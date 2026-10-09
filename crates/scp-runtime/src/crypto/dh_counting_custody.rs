//! Test custody that counts `dh_agree` calls, so a round-trip test can prove
//! the access-key open path performs exactly one key agreement.

use std::sync::atomic::{AtomicUsize, Ordering};

use scp_platform::PlatformError;
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::{
    CustodyType, KeyCustody, KeyHandle, KeyType, PseudonymKeypair, PublicKey, SharedSecret,
    Signature,
};

/// [`InMemoryKeyCustody`] that counts [`KeyCustody::dh_agree`] calls and
/// otherwise delegates every call unchanged.
pub struct DhCountingCustody {
    pub inner: InMemoryKeyCustody,
    dh_calls: AtomicUsize,
}

impl DhCountingCustody {
    pub fn new() -> Self {
        Self {
            inner: InMemoryKeyCustody::new(),
            dh_calls: AtomicUsize::new(0),
        }
    }

    /// The number of `dh_agree` calls so far, whatever their outcome.
    pub fn dh_calls(&self) -> usize {
        self.dh_calls.load(Ordering::SeqCst)
    }
}

impl KeyCustody for DhCountingCustody {
    async fn generate_keypair(&self, key_type: KeyType) -> Result<KeyHandle, PlatformError> {
        self.inner.generate_keypair(key_type).await
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
        self.dh_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.dh_agree(key, peer_public).await
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
