//! Callback-custody conformance tests.
//!
//! Expands `key_custody_conformance!()` (spec §17.11) against the shared
//! callback flows in `scp_ffi_common::callback_custody`, driven by the
//! software `FakeHost` and backed by a custody record store. Each bridge's
//! `CallbackKeyCustody` is these flows with one closure per host callback, so
//! the 24 tests cover the rules every bridge shares, the key-event key's
//! (SCP-345) included. The `create_unwind` tests check, over the same flows,
//! that a create whose identity entry fails to persist destroys the keys it
//! minted (spec §17.3).

#![cfg(all(feature = "custody", feature = "testing"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use scp_ffi_common::callback_custody::{
    self as flow, CallbackKeyRegistry, CustodyRecords, fake_host::FakeHost,
};
use scp_platform::traits::{
    CustodyType, KeyCustody, KeyHandle, KeyType, PublicKey, SharedSecret, Signature,
};
use scp_platform::{
    CustodyProbe, IndexedSignature, KeyEventSignError, KeyEventSigner, PlatformError,
    ProbeSignature, Pseudonym, SigningChange,
};

/// The callback flows over a fake host, as a bridge adapter wires them.
struct FakeHostCustody {
    host: FakeHost,
    registry: CallbackKeyRegistry,
    /// When set, every host destroy fails with a custody error.
    refuse_destroy: std::sync::atomic::AtomicBool,
}

impl FakeHostCustody {
    fn new() -> Self {
        // A table of its own: no other adapter holds the namespace.
        let (_, records) =
            CustodyRecords::open_alone(scp_platform::in_memory::InMemoryStorage::new(), [0x5c; 16]);
        Self {
            host: FakeHost::default(),
            registry: CallbackKeyRegistry::recorded(records),
            refuse_destroy: std::sync::atomic::AtomicBool::new(false),
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

    /// The pre-rotation seed a bridge adapter mints locally, never through
    /// the host; a fixed seed suffices for these tests.
    async fn generate_ephemeral_ed25519_seed(
        &self,
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, PlatformError> {
        Ok(zeroize::Zeroizing::new([0x42; 32]))
    }

    async fn destroy_key(&self, key: &KeyHandle) -> Result<(), PlatformError> {
        let h = &self.host;
        let refuse = self
            .refuse_destroy
            .load(std::sync::atomic::Ordering::SeqCst);
        flow::destroy_key(&self.registry, key, |id: String| async move {
            if refuse {
                return Err(PlatformError::CustodyError(
                    "host refused destroy".to_owned(),
                ));
            }
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

#[cfg(feature = "resolvers")]
mod create_unwind {
    use std::sync::Arc;

    use scp_did::DidDocument;
    use scp_ffi_common::callback_identity::{CallbackIdentityError, write_created_entry};
    use scp_identity::{DidMethod, dht::ScpIdentity};
    use scp_platform::Storage;
    use scp_platform::testing::InMemoryPreRotationCustody;

    use super::*;

    /// Storage whose every operation fails, standing in for a write the
    /// instance storage refuses.
    struct RefusingStorage;

    impl Storage for RefusingStorage {
        async fn store(&self, _: &str, _: &[u8]) -> Result<(), PlatformError> {
            Err(PlatformError::StorageError("refused".to_owned()))
        }
        async fn retrieve(&self, _: &str) -> Result<Option<Vec<u8>>, PlatformError> {
            Err(PlatformError::StorageError("refused".to_owned()))
        }
        async fn delete(&self, _: &str) -> Result<(), PlatformError> {
            Err(PlatformError::StorageError("refused".to_owned()))
        }
        async fn list_keys(&self, _: &str) -> Result<Vec<String>, PlatformError> {
            Err(PlatformError::StorageError("refused".to_owned()))
        }
        async fn delete_prefix(&self, _: &str) -> Result<u64, PlatformError> {
            Err(PlatformError::StorageError("refused".to_owned()))
        }
        async fn exists(&self, _: &str) -> Result<bool, PlatformError> {
            Err(PlatformError::StorageError("refused".to_owned()))
        }
    }

    async fn minted(custody: &FakeHostCustody, with_agent_key: bool) -> (ScpIdentity, DidDocument) {
        let dht = scp_identity::DidDht::with_client(Arc::new(scp_dht::InMemoryDhtClient::new()));
        let pre_rotation = InMemoryPreRotationCustody::new();
        let (identity, document, _) = if with_agent_key {
            dht.create_with_agent_key(custody, &pre_rotation).await
        } else {
            dht.create(custody, &pre_rotation).await
        }
        .unwrap();
        (identity, document)
    }

    fn minted_keys(identity: &ScpIdentity) -> Vec<KeyHandle> {
        [
            Some(identity.identity_key),
            Some(identity.active_signing_key),
            identity.agent_signing_key,
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    /// A failed entry write destroys every key the create minted, on the
    /// host and in the custody records, and returns the write's error.
    #[tokio::test]
    async fn a_failed_entry_write_destroys_every_minted_key() {
        for with_agent_key in [false, true] {
            let custody = FakeHostCustody::new();
            let (identity, document) = minted(&custody, with_agent_key).await;
            let keys = minted_keys(&identity);
            assert_eq!(keys.len(), if with_agent_key { 3 } else { 2 });
            assert_eq!(custody.host.calls("destroy_key"), 0);

            let e = write_created_entry(
                Some(&RefusingStorage),
                &custody,
                [9; 16],
                &identity,
                &document,
            )
            .await
            .unwrap_err();
            assert!(matches!(e, CallbackIdentityError::Storage(_)), "{e:?}");
            assert_eq!(custody.host.calls("destroy_key"), keys.len());
            for key in keys {
                assert!(matches!(
                    custody.public_key(&key).await,
                    Err(PlatformError::KeyNotFound)
                ));
            }
        }
    }

    /// Storage that stopped persisting fails the create the same way, and
    /// destroys the minted keys too.
    #[tokio::test]
    async fn absent_storage_destroys_every_minted_key() {
        let custody = FakeHostCustody::new();
        let (identity, document) = minted(&custody, false).await;
        let e = write_created_entry::<RefusingStorage, _>(
            None, &custody, [9; 16], &identity, &document,
        )
        .await
        .unwrap_err();
        assert!(e.is_storage_selection());
        assert_eq!(custody.host.calls("destroy_key"), 2);
    }

    /// A destroy that fails too is reported with the key it left, under the
    /// write's own code, never swallowed.
    #[tokio::test]
    async fn a_failed_destroy_names_the_orphaned_keys() {
        let custody = FakeHostCustody::new();
        let (identity, document) = minted(&custody, true).await;
        custody
            .refuse_destroy
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let e = write_created_entry(
            Some(&RefusingStorage),
            &custody,
            [9; 16],
            &identity,
            &document,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&e, CallbackIdentityError::KeysOrphaned { cause, .. }
                if matches!(**cause, CallbackIdentityError::Storage(_))),
            "expected KeysOrphaned over a storage failure, got {e:?}"
        );
        if let CallbackIdentityError::KeysOrphaned { cause, orphaned } = &e {
            assert_eq!(e.code(), cause.code());
            let left: Vec<KeyHandle> = orphaned.iter().map(|(key, _)| *key).collect();
            let mut expected = minted_keys(&identity);
            expected.reverse();
            assert_eq!(left, expected);
        }
        assert!(
            e.to_string()
                .contains(&identity.identity_key.id().to_string())
        );
    }

    /// The write that succeeds destroys nothing.
    #[tokio::test]
    async fn a_written_entry_destroys_nothing() {
        let custody = FakeHostCustody::new();
        let (identity, document) = minted(&custody, true).await;
        write_created_entry(
            Some(&scp_platform::in_memory::InMemoryStorage::new()),
            &custody,
            [9; 16],
            &identity,
            &document,
        )
        .await
        .unwrap();
        assert_eq!(custody.host.calls("destroy_key"), 0);
    }
}
