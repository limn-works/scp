//! The two custody slots an [`IdentityConfig`](super::IdentityConfig) holds
//! (`03-identity.md` §3.10.10; `.docs/standards/construction.md`, the Slot
//! and Config vocabulary).
//!
//! Each slot erases its custody behind a private boxed-future trait, as
//! [`crate::push_verify`] erases its verifier: ADR-052's amendment admits
//! erasure for the creation-time custody slots, because they run at
//! creation, rotation, cosigning and abandonment and never on a storage read.
//! The erased traits stay private, and every public constructor is generic,
//! so no `dyn` type reaches the public API. Neither slot is the daily
//! `#active` signer (ADR-052, the erasure rule).

use std::sync::Arc;

use async_trait::async_trait;
use scp_platform::file::FileKeyCustody;
use scp_platform::{
    CustodyProbe, CustodyType, KeyCustody, KeyEventSignError, KeyEventSigner, KeyHandle, KeyType,
    NextSetCustody, NextSetCustodyError, NextSetKeyHandle, PlatformError, PreRotationCustodyKind,
    ProbeSignature, PublicKey,
};

/// The key-custody operations identity creation and abandonment run.
#[async_trait]
trait ErasableKeyCustody: Send + Sync {
    async fn generate_key_event_keypair(&self) -> Result<KeyHandle, PlatformError>;
    async fn generate_keypair(&self, key_type: KeyType) -> Result<KeyHandle, PlatformError>;
    async fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, PlatformError>;
    fn custody_type(&self, key: KeyHandle) -> CustodyType;
    async fn destroy_key(&self, key: &KeyHandle) -> Result<(), PlatformError>;
}

#[async_trait]
impl<K: KeyCustody + 'static> ErasableKeyCustody for K {
    async fn generate_key_event_keypair(&self) -> Result<KeyHandle, PlatformError> {
        KeyCustody::generate_key_event_keypair(self).await
    }

    async fn generate_keypair(&self, key_type: KeyType) -> Result<KeyHandle, PlatformError> {
        KeyCustody::generate_keypair(self, key_type).await
    }

    async fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, PlatformError> {
        KeyCustody::public_key(self, key).await
    }

    fn custody_type(&self, key: KeyHandle) -> CustodyType {
        KeyCustody::custody_type(self, &key)
    }

    async fn destroy_key(&self, key: &KeyHandle) -> Result<(), PlatformError> {
        KeyCustody::destroy_key(self, key).await
    }
}

/// The next-set custody operations identity creation and abandonment run.
#[async_trait]
trait ErasableNextSetCustody: Send + Sync {
    async fn generate(&self) -> Result<NextSetKeyHandle, NextSetCustodyError>;
    async fn reveal_public_key(
        &self,
        handle: &NextSetKeyHandle,
    ) -> Result<[u8; 33], NextSetCustodyError>;
    async fn sign_probe(
        &self,
        handle: &NextSetKeyHandle,
        probe: &CustodyProbe,
    ) -> Result<ProbeSignature, KeyEventSignError>;
    async fn destroy(&self, handle: &NextSetKeyHandle) -> Result<(), NextSetCustodyError>;
    fn custody_kind(&self) -> PreRotationCustodyKind;
}

#[async_trait]
impl<N: NextSetCustody + 'static> ErasableNextSetCustody for N {
    async fn generate(&self) -> Result<NextSetKeyHandle, NextSetCustodyError> {
        NextSetCustody::generate(self).await
    }

    async fn reveal_public_key(
        &self,
        handle: &NextSetKeyHandle,
    ) -> Result<[u8; 33], NextSetCustodyError> {
        NextSetCustody::reveal_public_key(self, handle).await
    }

    async fn sign_probe(
        &self,
        handle: &NextSetKeyHandle,
        probe: &CustodyProbe,
    ) -> Result<ProbeSignature, KeyEventSignError> {
        KeyEventSigner::sign_probe(self, handle, probe).await
    }

    async fn destroy(&self, handle: &NextSetKeyHandle) -> Result<(), NextSetCustodyError> {
        NextSetCustody::destroy(self, handle).await
    }

    fn custody_kind(&self) -> PreRotationCustodyKind {
        NextSetCustody::custody_kind(self)
    }
}

/// A [`KeyCustody`] whose concrete type is erased, for the
/// [`KeyCustodySlot::OsKeystore`] and [`KeyCustodySlot::Custom`] arms.
#[derive(Clone)]
pub struct ErasedKeyCustody(Arc<dyn ErasableKeyCustody>);

impl ErasedKeyCustody {
    /// Erases `custody`.
    #[must_use]
    pub fn new<K: KeyCustody + 'static>(custody: K) -> Self {
        Self(Arc::new(custody))
    }
}

/// A [`NextSetCustody`] whose concrete type is erased, for the
/// [`NextSetCustodySlot::Custom`] arm.
#[derive(Clone)]
pub struct ErasedNextSetCustody(Arc<dyn ErasableNextSetCustody>);

impl ErasedNextSetCustody {
    /// Erases `custody`.
    #[must_use]
    pub fn new<N: NextSetCustody + 'static>(custody: N) -> Self {
        Self(Arc::new(custody))
    }
}

/// The custody that holds an identity's root members and `#active` key
/// (`03-identity.md` §3.10.10; `.docs/standards/construction.md`, the three
/// `KeyCustodySlot` arms).
#[derive(Clone)]
pub enum KeyCustodySlot {
    /// The passphrase-encrypted file custody this crate names directly.
    EncryptedFile(Arc<FileKeyCustody>),
    /// A host OS keystore a bridge lowers its `KeyCustodyConfig::OsKeystore`
    /// provider to.
    OsKeystore(ErasedKeyCustody),
    /// A custody a Rust caller supplies.
    Custom(ErasedKeyCustody),
}

impl KeyCustodySlot {
    /// A [`Custom`](Self::Custom) slot over `custody`.
    #[must_use]
    pub fn custom<K: KeyCustody + 'static>(custody: K) -> Self {
        Self::Custom(ErasedKeyCustody::new(custody))
    }

    fn custody(&self) -> &dyn ErasableKeyCustody {
        match self {
            Self::EncryptedFile(custody) => custody.as_ref(),
            Self::OsKeystore(custody) | Self::Custom(custody) => custody.0.as_ref(),
        }
    }

    pub(super) async fn generate_key_event_keypair(&self) -> Result<KeyHandle, PlatformError> {
        self.custody().generate_key_event_keypair().await
    }

    pub(super) async fn generate_keypair(
        &self,
        key_type: KeyType,
    ) -> Result<KeyHandle, PlatformError> {
        self.custody().generate_keypair(key_type).await
    }

    pub(super) async fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, PlatformError> {
        self.custody().public_key(key).await
    }

    pub(super) fn custody_type(&self, key: KeyHandle) -> CustodyType {
        self.custody().custody_type(key)
    }

    pub(super) async fn destroy_key(&self, key: &KeyHandle) -> Result<(), PlatformError> {
        self.custody().destroy_key(key).await
    }
}

/// The custody that holds an identity's next-set members, apart from the
/// [`KeyCustodySlot`] (`09-security-model.md` §9.7.4.1 item 3;
/// `03-identity.md` §3.10.10).
///
/// The method the custody runs is the one its
/// [`custody_kind`](NextSetCustody::custody_kind) declares, so the caller
/// never declares a custody type beside it.
#[derive(Clone)]
pub enum NextSetCustodySlot {
    /// A next-set custody a Rust caller supplies, or one a bridge lowers its
    /// next-set custody config to.
    Custom(ErasedNextSetCustody),
}

impl NextSetCustodySlot {
    /// A [`Custom`](Self::Custom) slot over `custody`.
    #[must_use]
    pub fn custom<N: NextSetCustody + 'static>(custody: N) -> Self {
        Self::Custom(ErasedNextSetCustody::new(custody))
    }

    fn custody(&self) -> &dyn ErasableNextSetCustody {
        match self {
            Self::Custom(custody) => custody.0.as_ref(),
        }
    }

    pub(super) async fn generate(&self) -> Result<NextSetKeyHandle, NextSetCustodyError> {
        self.custody().generate().await
    }

    pub(super) async fn reveal_public_key(
        &self,
        handle: &NextSetKeyHandle,
    ) -> Result<[u8; 33], NextSetCustodyError> {
        self.custody().reveal_public_key(handle).await
    }

    pub(super) async fn sign_probe(
        &self,
        handle: &NextSetKeyHandle,
        probe: &CustodyProbe,
    ) -> Result<ProbeSignature, KeyEventSignError> {
        self.custody().sign_probe(handle, probe).await
    }

    pub(super) async fn destroy(
        &self,
        handle: &NextSetKeyHandle,
    ) -> Result<(), NextSetCustodyError> {
        self.custody().destroy(handle).await
    }

    pub(super) fn custody_kind(&self) -> PreRotationCustodyKind {
        self.custody().custody_kind()
    }
}
