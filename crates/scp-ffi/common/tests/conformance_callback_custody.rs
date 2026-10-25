//! Callback-custody conformance tests.
//!
//! Expands `key_custody_conformance!()` (spec §17.11) against the shared
//! callback flows in `scp_ffi_common::callback_custody`, driven by the
//! software `FakeHost` and backed by a custody record store. Each bridge's
//! `CallbackKeyCustody` is these flows with one closure per host callback, so
//! the 24 tests cover the rules every bridge shares, the key-event key's
//! (SCP-345) included.

#![cfg(all(feature = "custody", feature = "testing"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use scp_ffi_common::callback_custody::{
    self as flow, CallbackKeyRegistry, CustodyRecords, fake_host::FakeHost,
};
use scp_platform::traits::{
    CustodyType, KeyCustody, KeyHandle, KeyType, PublicKey, SharedSecret, Signature,
};
use scp_platform::{
    CustodyNamespace, CustodyProbe, IndexedSignature, KeyEventSignError, KeyEventSigner,
    PlatformError, ProbeSignature, Pseudonym, SigningChange, StorageCustodyRecordStore,
};

/// The callback flows over a fake host, as a bridge adapter wires them.
struct FakeHostCustody {
    host: FakeHost,
    registry: CallbackKeyRegistry,
}

impl FakeHostCustody {
    fn new() -> Self {
        let store = StorageCustodyRecordStore::new(
            scp_platform::in_memory::InMemoryStorage::new(),
            CustodyNamespace::from_bytes([0x5c; 16]),
        );
        Self {
            host: FakeHost::default(),
            registry: CallbackKeyRegistry::recorded(CustodyRecords::unleased(Arc::new(store))),
        }
    }
}

impl KeyEventSigner for FakeHostCustody {
    type Member = KeyHandle;

    async fn sign_change(
        &self,
        member: &KeyHandle,
        change: &SigningChange,
    ) -> Result<IndexedSignature, KeyEventSignError> {
        let h = &self.host;
        flow::sign_change(
            &self.registry,
            member,
            change,
            |id, data| async move { h.sign(&id, &data) },
            |id: String| async move { h.get_public_key(&id) },
        )
        .await
    }

    async fn sign_probe(
        &self,
        member: &KeyHandle,
        probe: &CustodyProbe,
    ) -> Result<ProbeSignature, KeyEventSignError> {
        let h = &self.host;
        flow::sign_probe(
            &self.registry,
            member,
            probe,
            |id, data| async move { h.sign(&id, &data) },
            |id: String| async move { h.get_public_key(&id) },
        )
        .await
    }
}

impl KeyCustody for FakeHostCustody {
    async fn generate_keypair(&self, key_type: KeyType) -> Result<KeyHandle, PlatformError> {
        let h = &self.host;
        flow::generate_operational(
            &self.registry,
            key_type,
            |t, r| async move { h.generate_keypair(t, r) },
            |id: String| async move { h.get_public_key(&id) },
            |id: String| async move { h.destroy_key(&id) },
        )
        .await
    }

    async fn generate_key_event_keypair(&self) -> Result<KeyHandle, PlatformError> {
        let h = &self.host;
        flow::generate_key_event(
            &self.registry,
            |t, r| async move { h.generate_keypair(t, r) },
            |id: String| async move { h.get_public_key(&id) },
            |id: String| async move { h.destroy_key(&id) },
        )
        .await
    }

    async fn generate_identity_keypair(&self) -> Result<KeyHandle, PlatformError> {
        let h = &self.host;
        flow::generate_identity(
            &self.registry,
            |t, r| async move { h.generate_keypair(t, r) },
            |id: String| async move { h.get_public_key(&id) },
            |id: String| async move { h.destroy_key(&id) },
        )
        .await
    }

    async fn sign(&self, key: &KeyHandle, data: &[u8]) -> Result<Signature, PlatformError> {
        let h = &self.host;
        flow::sign(
            &self.registry,
            key,
            data,
            |id, data| async move { h.sign(&id, &data) },
            |id: String| async move { h.get_public_key(&id) },
        )
        .await
    }

    async fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, PlatformError> {
        let h = &self.host;
        flow::public_key(&self.registry, key, |id: String| async move {
            h.get_public_key(&id)
        })
        .await
    }

    async fn destroy_key(&self, key: &KeyHandle) -> Result<(), PlatformError> {
        let h = &self.host;
        flow::destroy_key(&self.registry, key, |id: String| async move {
            h.destroy_key(&id)
        })
        .await
    }

    async fn dh_agree(
        &self,
        key: &KeyHandle,
        peer_public: &[u8],
    ) -> Result<SharedSecret, PlatformError> {
        let h = &self.host;
        flow::dh_agree(
            &self.registry,
            key,
            peer_public,
            |id, peer| async move { h.dh_agree(&id, &peer) },
            |id: String| async move { h.get_public_key(&id) },
        )
        .await
    }

    async fn derive_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
    ) -> Result<Pseudonym, PlatformError> {
        let h = &self.host;
        flow::derive_pseudonym(
            &self.registry,
            key,
            None,
            |id: String| async move { h.derive_pseudonym(&id, context_id, None) },
            |id: String| async move { h.get_public_key(&id) },
        )
        .await
    }

    async fn derive_rotatable_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
        pseudonym_epoch: u64,
    ) -> Result<Pseudonym, PlatformError> {
        let h = &self.host;
        flow::derive_pseudonym(
            &self.registry,
            key,
            Some(pseudonym_epoch),
            |id: String| async move { h.derive_pseudonym(&id, context_id, Some(pseudonym_epoch)) },
            |id: String| async move { h.get_public_key(&id) },
        )
        .await
    }

    fn custody_type(&self, _key: &KeyHandle) -> CustodyType {
        CustodyType::Software
    }
}

// No callback host imports seed bytes, so every bridge adapter refuses
// `import_ed25519_signing_key` as `Unsupported`, as this one does by the
// trait's default.
scp_testing::key_custody_conformance!(FakeHostCustody::new(), imports: false);
