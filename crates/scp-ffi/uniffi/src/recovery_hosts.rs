//! The `UniFFI` host impls of the store set's synced members.
//!
//! Sources: `09-security-model.md` §9.7.4.2 R10, ADR-054 §Assertion-arm and
//! store-set host interfaces, SCP-311.
//!
//! [`ForeignSyncedStore`] and [`ForeignCredentialBlob`] adapt a foreign
//! [`SyncedStoreProvider`] and [`CredentialBlobProvider`] to the host traits
//! of [`scp_ffi_common::callback_store`], whose members hold every rule for
//! trusting a host answer. This module only converts types: a thrown
//! [`ScpError`] becomes a [`HostStoreFailure`] carrying its text, never an
//! absent value and never a landed write.

use std::sync::Arc;

use scp_ffi_common::callback_store::{
    BlobWrite, CredentialBlobHost, HostStoreFailure, SyncedStoreHost,
};
use scp_platform::CredentialId;

use crate::{BlobWriteOutcome, CredentialBlobProvider, ScpError, SyncedStoreProvider};

fn host_failure(error: &ScpError) -> HostStoreFailure {
    HostStoreFailure {
        cause: error.to_string(),
    }
}

/// A foreign [`SyncedStoreProvider`] as the platform-account member's host.
pub struct ForeignSyncedStore {
    provider: Arc<dyn SyncedStoreProvider>,
}

impl ForeignSyncedStore {
    /// Wraps the host's provider.
    #[must_use]
    pub fn new(provider: Arc<dyn SyncedStoreProvider>) -> Self {
        Self { provider }
    }
}

impl std::fmt::Debug for ForeignSyncedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForeignSyncedStore").finish_non_exhaustive()
    }
}

impl SyncedStoreHost for ForeignSyncedStore {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, HostStoreFailure> {
        self.provider
            .get(key.to_owned())
            .await
            .map_err(|error| host_failure(&error))
    }

    async fn put(&self, key: &str, value: &[u8]) -> Result<(), HostStoreFailure> {
        self.provider
            .put(key.to_owned(), value.to_vec())
            .await
            .map_err(|error| host_failure(&error))
    }
}

/// A foreign [`CredentialBlobProvider`] as the `largeBlob` member's host.
pub struct ForeignCredentialBlob {
    provider: Arc<dyn CredentialBlobProvider>,
}

impl ForeignCredentialBlob {
    /// Wraps the host's provider.
    #[must_use]
    pub fn new(provider: Arc<dyn CredentialBlobProvider>) -> Self {
        Self { provider }
    }
}

impl std::fmt::Debug for ForeignCredentialBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForeignCredentialBlob")
            .finish_non_exhaustive()
    }
}

/// The platform fact the host reported, carried over one to one; the
/// member maps it to its clearing act.
fn blob_write(outcome: BlobWriteOutcome) -> BlobWrite {
    match outcome {
        BlobWriteOutcome::Landed => BlobWrite::Landed,
        BlobWriteOutcome::NotWritten => BlobWrite::NotWritten,
        BlobWriteOutcome::NoOutput => BlobWrite::NoOutput,
        BlobWriteOutcome::VerificationDeclined { cause } => {
            BlobWrite::VerificationDeclined { cause }
        }
    }
}

impl CredentialBlobHost for ForeignCredentialBlob {
    async fn read_blob(
        &self,
        credential_id: &CredentialId,
    ) -> Result<Option<Vec<u8>>, HostStoreFailure> {
        self.provider
            .read_blob(credential_id.as_bytes().to_vec())
            .await
            .map_err(|error| host_failure(&error))
    }

    async fn write_blob(
        &self,
        credential_id: &CredentialId,
        entry: &[u8],
    ) -> Result<BlobWrite, HostStoreFailure> {
        let outcome = self
            .provider
            .write_blob(credential_id.as_bytes().to_vec(), entry.to_vec())
            .await
            .map_err(|error| host_failure(&error))?;
        Ok(blob_write(outcome))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::future::Future;
    use std::pin::pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll, Waker};

    use scp_ffi_common::callback_store::{CredentialBlobMember, SyncedStoreMember};
    use scp_ffi_common::error_codes::STORAGE_8016;
    use scp_platform::{
        LargeBlobClearingAct, LargeBlobNotLanded, MemberRead, NotReachedCause, RecoveryHandleStore,
        StoreEntry, StoreWriteFailure,
    };

    use super::*;

    /// The code ADR-054 names for a store-set host that cannot answer.
    const CODE: &str = STORAGE_8016;

    fn run<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
                return output;
            }
        }
    }

    fn thrown() -> ScpError {
        ScpError::Storage {
            msg: "keychain item locked".to_owned(),
            code: CODE.to_owned(),
        }
    }

    fn credential() -> CredentialId {
        CredentialId::new(vec![0xc1; 64]).unwrap()
    }

    /// A Rust stand-in for a foreign synced store: it answers `get` from a
    /// script and records each `put`.
    struct ScriptedSynced {
        get: Mutex<Result<Option<Vec<u8>>, ScpError>>,
        put: Mutex<Result<(), ScpError>>,
        puts: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl ScriptedSynced {
        fn new(get: Result<Option<Vec<u8>>, ScpError>, put: Result<(), ScpError>) -> Self {
            Self {
                get: Mutex::new(get),
                put: Mutex::new(put),
                puts: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl SyncedStoreProvider for ScriptedSynced {
        async fn get(&self, _key: String) -> Result<Option<Vec<u8>>, ScpError> {
            self.get.lock().unwrap().clone()
        }

        async fn put(&self, key: String, value: Vec<u8>) -> Result<(), ScpError> {
            self.puts.lock().unwrap().push((key, value));
            self.put.lock().unwrap().clone()
        }
    }

    /// A Rust stand-in for a foreign `largeBlob` host.
    struct ScriptedBlob {
        read: Mutex<Result<Option<Vec<u8>>, ScpError>>,
        write: Mutex<Result<BlobWriteOutcome, ScpError>>,
        credentials: Mutex<Vec<Vec<u8>>>,
    }

    impl ScriptedBlob {
        fn new(
            read: Result<Option<Vec<u8>>, ScpError>,
            write: Result<BlobWriteOutcome, ScpError>,
        ) -> Self {
            Self {
                read: Mutex::new(read),
                write: Mutex::new(write),
                credentials: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl CredentialBlobProvider for ScriptedBlob {
        async fn read_blob(&self, credential_id: Vec<u8>) -> Result<Option<Vec<u8>>, ScpError> {
            self.credentials.lock().unwrap().push(credential_id);
            self.read.lock().unwrap().clone()
        }

        async fn write_blob(
            &self,
            credential_id: Vec<u8>,
            _entry: Vec<u8>,
        ) -> Result<BlobWriteOutcome, ScpError> {
            self.credentials.lock().unwrap().push(credential_id);
            self.write.lock().unwrap().clone()
        }
    }

    fn synced_member(provider: ScriptedSynced) -> SyncedStoreMember<ForeignSyncedStore> {
        SyncedStoreMember::new(ForeignSyncedStore::new(Arc::new(provider)))
    }

    fn blob_member(provider: Arc<ScriptedBlob>) -> CredentialBlobMember<ForeignCredentialBlob> {
        CredentialBlobMember::new(ForeignCredentialBlob::new(provider))
    }

    /// A thrown `ScpError` reaches the member as the host's failure with the
    /// error's own text, on a read and on a write.
    #[test]
    fn uniffi_hosts_map_scp_error() {
        let text = thrown().to_string();
        assert!(text.contains(CODE), "{text}");
        let member = synced_member(ScriptedSynced::new(Err(thrown()), Err(thrown())));
        assert_eq!(
            run(member.read_entry(&credential())),
            MemberRead::NotReached(NotReachedCause::Unreachable {
                cause: text.clone()
            })
        );
        assert_eq!(
            run(member.write_entry(&credential(), &StoreEntry::EMPTY)),
            Err(StoreWriteFailure { cause: text })
        );
    }

    /// Mutant: a thrown `get` mapped to `nil`. `nil` reads as empty and a
    /// throw reads as not reached.
    #[test]
    fn uniffi_synced_get_none_vs_throw() {
        let absent = synced_member(ScriptedSynced::new(Ok(None), Ok(())));
        assert_eq!(
            run(absent.read_entry(&credential())),
            MemberRead::ReachedEmpty
        );
        let throws = synced_member(ScriptedSynced::new(Err(thrown()), Ok(())));
        assert!(matches!(
            run(throws.read_entry(&credential())),
            MemberRead::NotReached(NotReachedCause::Unreachable { .. })
        ));
    }

    /// A `put` that the host answers carries the member's key and bytes.
    #[test]
    fn uniffi_synced_put_passes_key_and_bytes() {
        let provider = Arc::new(ScriptedSynced::new(Ok(None), Ok(())));
        let member = SyncedStoreMember::new(ForeignSyncedStore::new(
            Arc::clone(&provider) as Arc<dyn SyncedStoreProvider>
        ));
        run(member.write_entry(&credential(), &StoreEntry::EMPTY)).unwrap();
        assert_eq!(
            *provider.puts.lock().unwrap(),
            vec![(credential().entry_key(), vec![0x00])]
        );
    }

    /// Mutant: a thrown `read_blob` mapped to `nil`. `nil` reads as empty and
    /// a throw reads as not reached; each call names the credential passed.
    #[test]
    fn uniffi_blob_read_none_vs_throw() {
        let absent = Arc::new(ScriptedBlob::new(Ok(None), Ok(BlobWriteOutcome::Landed)));
        assert_eq!(
            run(blob_member(Arc::clone(&absent)).read_entry(&credential())),
            MemberRead::ReachedEmpty
        );
        assert_eq!(
            *absent.credentials.lock().unwrap(),
            vec![credential().as_bytes().to_vec()]
        );
        let throws = Arc::new(ScriptedBlob::new(
            Err(thrown()),
            Ok(BlobWriteOutcome::Landed),
        ));
        assert_eq!(
            run(blob_member(throws).read_entry(&credential())),
            MemberRead::NotReached(NotReachedCause::Unreachable {
                cause: thrown().to_string()
            })
        );
    }

    /// Mutant: a thrown `write_blob` mapped to `Landed`. It reaches the set
    /// as a write that did not land, cleared by a retry.
    #[test]
    fn uniffi_blob_write_throw_is_not_landed() {
        let throws = Arc::new(ScriptedBlob::new(Ok(None), Err(thrown())));
        assert_eq!(
            run(blob_member(throws).write_entry(&credential(), &StoreEntry::EMPTY)),
            Err(LargeBlobNotLanded {
                cause: Some(thrown().to_string()),
                clears_by: LargeBlobClearingAct::RetryVerification,
            })
        );
    }

    /// Each `BlobWriteOutcome` fact reaches the member unchanged, and the
    /// member maps it to the act R10 names: `NotWritten` to removing the
    /// consuming credential, `NoOutput` and a declined gesture to a retry.
    /// Mutants: any two facts swapped in `blob_write`; `NotWritten` mapped to
    /// a retry.
    #[test]
    fn uniffi_blob_outcome_maps_to_its_act() {
        let landed = Arc::new(ScriptedBlob::new(Ok(None), Ok(BlobWriteOutcome::Landed)));
        assert_eq!(
            run(blob_member(landed).write_entry(&credential(), &StoreEntry::EMPTY)),
            Ok(())
        );
        let cases = [
            (
                BlobWriteOutcome::NotWritten,
                None,
                LargeBlobClearingAct::RemoveConsumingCredential,
            ),
            (
                BlobWriteOutcome::NoOutput,
                None,
                LargeBlobClearingAct::RetryVerification,
            ),
            (
                BlobWriteOutcome::VerificationDeclined { cause: None },
                None,
                LargeBlobClearingAct::RetryVerification,
            ),
            (
                BlobWriteOutcome::VerificationDeclined {
                    cause: Some("cancelled".to_owned()),
                },
                Some("cancelled".to_owned()),
                LargeBlobClearingAct::RetryVerification,
            ),
        ];
        for (outcome, cause, clears_by) in cases {
            let provider = Arc::new(ScriptedBlob::new(Ok(None), Ok(outcome)));
            assert_eq!(
                run(blob_member(provider).write_entry(&credential(), &StoreEntry::EMPTY)),
                Err(LargeBlobNotLanded { cause, clears_by })
            );
        }
    }
}
