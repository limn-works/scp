//! The two synced members of a credential's store set, over host callbacks.
//!
//! Sources: `09-security-model.md` §9.7.4.2 R10, `17-persistence-and-storage.md`
//! §17.8, ADR-054 §Assertion-arm and store-set host interfaces, SCP-311.
//!
//! - [`SyncedStoreMember`] is the platform-account member over a host's
//!   synced key-value store (`SyncedStoreProvider` in the `UniFFI` bridge). It
//!   holds the entry, the [`StoreSetRecord`] and the signed events.
//! - [`CredentialBlobMember`] is the credential's `largeBlob` member over a
//!   host's `largeBlob` reads and writes (`CredentialBlobProvider`). It holds
//!   the entry alone.
//!
//! Each member is generic over a small host trait, which the bridge
//! implements over its callback object, so every rule for trusting a host
//! answer lives here once and is tested over Rust fakes. The host never
//! forms a key and never reads the bytes it stores: the member forms every
//! key from the credential and encodes every value.
//!
//! Neither member holds a credential. Each call keys on the credential the
//! [`StoreSet`](scp_platform::StoreSet) passes from its own lease, so a member
//! cannot read or write the store of a credential other than its set's.
//!
//! Every read either member makes returns the platform's current value and
//! never a cache (ADR-054 §Assertion-arm and store-set host interfaces, the
//! freshness rule).
//!
//! What a member does not decide: whether it exists on the host (the
//! caller's [`PlatformAccountSlot`](scp_platform::PlatformAccountSlot)
//! states it), whether a platform write read back equal (the store set reads
//! each one back), and what a `largeBlob` write that did not land does to the
//! ceremony (the store set decides). What a member does decide: the act that
//! clears a `largeBlob` write that did not land, from the platform facts the
//! host reports ([`BlobWrite`]), so no host picks an act.

use std::fmt;
use std::future::Future;
use std::sync::Arc;

use scp_platform::{
    CredentialId, EntrySource, LargeBlobClearingAct, LargeBlobNotLanded, MemberRead,
    NotReachedCause, RecordDecodeError, RecoveryEventStore, RecoveryHandleStore,
    RecoveryRecordStore, StoreEntry, StoreSetRecord, StoreWriteFailure, check_event_length,
    decode_entry, decode_store_set_record, encode_entry, encode_store_set_record,
};

#[cfg(test)]
mod tests;

/// A host call that failed: the host threw instead of answering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostStoreFailure {
    /// The error text the host threw.
    pub cause: String,
}

impl fmt::Display for HostStoreFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.cause)
    }
}

impl std::error::Error for HostStoreFailure {}

/// A host's synced key-value store: the store through which the platform
/// account syncs the pre-rotation credential (the Apple row of the
/// `09-security-model.md` §9.7.4.2 R10 platform-account host table).
///
/// The host contract (ADR-054): `get` answers `Ok(None)` only where the
/// platform reports the item absent and fails on every other platform
/// failure; `put` returns only after the platform reports the item stored.
/// `get` follows ADR-054's freshness rule: it returns the platform's current
/// value, read from the platform store on that call, and never a cache.
pub trait SyncedStoreHost: Send + Sync {
    /// The bytes stored under `key`, or `None` where the platform reports
    /// the item absent.
    fn get(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, HostStoreFailure>> + Send;

    /// Stores `value` under `key`, replacing any value there.
    fn put(
        &self,
        key: &str,
        value: &[u8],
    ) -> impl Future<Output = Result<(), HostStoreFailure>> + Send;
}

/// What the platform reported for a `largeBlob` write the host answered.
/// The host reports a platform fact and never a clearing act; the
/// [`CredentialBlobMember`] maps each fact to the act (ADR-054).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlobWrite {
    /// The platform reported `largeBlob: { written: true }`.
    Landed,
    /// The platform reported `largeBlob: { written: false }` with no error:
    /// the authenticator's large-blob array at capacity, cleared by
    /// [`LargeBlobClearingAct::RemoveConsumingCredential`].
    NotWritten,
    /// The assertion returned no `largeBlob` output: a client that did not
    /// process the extension, cleared by
    /// [`LargeBlobClearingAct::RetryVerification`].
    NoOutput,
    /// The user declined or cancelled the verification gesture, cleared by
    /// [`LargeBlobClearingAct::RetryVerification`].
    VerificationDeclined {
        /// The cause the platform reported, where it reported one.
        cause: Option<String>,
    },
}

impl BlobWrite {
    /// The R10 rule (`09-security-model.md` §9.7.4.2, ADR-054): the act that
    /// clears each write that did not land.
    fn landed(self) -> Result<(), LargeBlobNotLanded> {
        let (cause, clears_by) = match self {
            Self::Landed => return Ok(()),
            Self::NotWritten => (None, LargeBlobClearingAct::RemoveConsumingCredential),
            Self::NoOutput => (None, LargeBlobClearingAct::RetryVerification),
            Self::VerificationDeclined { cause } => {
                (cause, LargeBlobClearingAct::RetryVerification)
            }
        };
        Err(LargeBlobNotLanded { cause, clears_by })
    }
}

/// A host's reach into one credential's `WebAuthn` `largeBlob` store.
///
/// The host contract (ADR-054): `write_blob` answers [`BlobWrite::Landed`]
/// only where the platform reports `written: true`, and a `largeBlob` output
/// the platform does not return is [`BlobWrite::NoOutput`]; `read_blob`
/// answers `Ok(None)` only where the platform reports the store holds
/// nothing. The host passes the bytes through unread, and reads and writes
/// the store of `credential_id` and no other. `read_blob` follows ADR-054's
/// freshness rule: it returns the platform's current value, read through a
/// `largeBlob` read assertion on that call, and never a cache or the bytes of
/// the host's last write.
pub trait CredentialBlobHost: Send + Sync {
    /// The bytes `credential_id`'s `largeBlob` store holds, or `None`.
    fn read_blob(
        &self,
        credential_id: &CredentialId,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, HostStoreFailure>> + Send;

    /// Writes `entry` into `credential_id`'s `largeBlob` store.
    fn write_blob(
        &self,
        credential_id: &CredentialId,
        entry: &[u8],
    ) -> impl Future<Output = Result<BlobWrite, HostStoreFailure>> + Send;
}

impl<H: SyncedStoreHost + ?Sized> SyncedStoreHost for Arc<H> {
    fn get(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, HostStoreFailure>> + Send {
        (**self).get(key)
    }

    fn put(
        &self,
        key: &str,
        value: &[u8],
    ) -> impl Future<Output = Result<(), HostStoreFailure>> + Send {
        (**self).put(key, value)
    }
}

impl<H: CredentialBlobHost + ?Sized> CredentialBlobHost for Arc<H> {
    fn read_blob(
        &self,
        credential_id: &CredentialId,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, HostStoreFailure>> + Send {
        (**self).read_blob(credential_id)
    }

    fn write_blob(
        &self,
        credential_id: &CredentialId,
        entry: &[u8],
    ) -> impl Future<Output = Result<BlobWrite, HostStoreFailure>> + Send {
        (**self).write_blob(credential_id, entry)
    }
}

/// Maps a host's read answer to a member read: absent bytes and bytes that
/// decode to nothing (the entry `0x00`) are empty; bytes that do not decode
/// and a host failure are a member not reached, never an empty one.
fn decoded<T>(
    answer: Result<Option<Vec<u8>>, HostStoreFailure>,
    decode: impl FnOnce(&[u8]) -> Result<Option<T>, RecordDecodeError>,
) -> MemberRead<T> {
    match answer {
        Ok(None) => MemberRead::ReachedEmpty,
        Ok(Some(bytes)) => match decode(&bytes) {
            Ok(Some(value)) => MemberRead::Reached(value),
            Ok(None) => MemberRead::ReachedEmpty,
            Err(error) => MemberRead::NotReached(NotReachedCause::Undecodable(error)),
        },
        Err(failure) => MemberRead::NotReached(NotReachedCause::Unreachable {
            cause: failure.cause,
        }),
    }
}

/// An entry read from a synced member, where bit 2 is refused (§17.8).
fn synced_entry(bytes: &[u8]) -> Result<Option<StoreEntry>, RecordDecodeError> {
    decode_entry(bytes, EntrySource::Synced)
}

// ---------------------------------------------------------------------------
// The platform-account member
// ---------------------------------------------------------------------------

/// The platform-account member over a host's synced store.
///
/// It holds the credential's entry, its [`StoreSetRecord`] and each signed
/// event under `recovery/{sha256_hex(credential_id)}/`
/// (`17-persistence-and-storage.md` §17.3 and §17.8). It never writes the
/// `largeBlob` skip bit, which the store set strips before every synced
/// write, and reads an entry that carries it as bytes that do not decode.
#[derive(Debug)]
pub struct SyncedStoreMember<H> {
    host: H,
}

impl<H: SyncedStoreHost> SyncedStoreMember<H> {
    /// The member over `host`.
    #[must_use]
    pub const fn new(host: H) -> Self {
        Self { host }
    }

    async fn put(&self, key: &str, bytes: &[u8]) -> Result<(), StoreWriteFailure> {
        self.host
            .put(key, bytes)
            .await
            .map_err(|failure| StoreWriteFailure {
                cause: failure.cause,
            })
    }
}

impl<H: SyncedStoreHost> RecoveryHandleStore for SyncedStoreMember<H> {
    type WriteFailure = StoreWriteFailure;

    async fn read_entry(&self, credential_id: &CredentialId) -> MemberRead<StoreEntry> {
        decoded(
            self.host.get(&credential_id.entry_key()).await,
            synced_entry,
        )
    }

    async fn write_entry(
        &self,
        credential_id: &CredentialId,
        entry: &StoreEntry,
    ) -> Result<(), StoreWriteFailure> {
        self.put(&credential_id.entry_key(), &encode_entry(entry))
            .await
    }
}

impl<H: SyncedStoreHost> RecoveryEventStore for SyncedStoreMember<H> {
    async fn read_event(
        &self,
        credential_id: &CredentialId,
        event_digest: &[u8; 32],
    ) -> MemberRead<Vec<u8>> {
        let answer = self.host.get(&credential_id.event_key(event_digest)).await;
        decoded(answer, |bytes| {
            check_event_length(bytes).map(|()| Some(bytes.to_vec()))
        })
    }

    async fn write_event(
        &self,
        credential_id: &CredentialId,
        event_digest: &[u8; 32],
        event: &[u8],
    ) -> Result<(), StoreWriteFailure> {
        self.put(&credential_id.event_key(event_digest), event)
            .await
    }
}

impl<H: SyncedStoreHost> RecoveryRecordStore for SyncedStoreMember<H> {
    async fn read_record(&self, credential_id: &CredentialId) -> MemberRead<StoreSetRecord> {
        decoded(self.host.get(&credential_id.record_key()).await, |bytes| {
            decode_store_set_record(bytes).map(Some)
        })
    }

    async fn write_record(
        &self,
        credential_id: &CredentialId,
        record: &StoreSetRecord,
    ) -> Result<(), StoreWriteFailure> {
        self.put(
            &credential_id.record_key(),
            &encode_store_set_record(record),
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// The largeBlob member
// ---------------------------------------------------------------------------

/// The credential's `largeBlob` member over a host's `largeBlob` reads and
/// writes. It holds the §17.8 entry record and nothing else.
///
/// Every write that did not land, and every write the host failed to
/// answer, is [`LargeBlobNotLanded`] with the act this member maps from the
/// platform fact ([`BlobWrite`]): a thrown write is never a landed one, and
/// names [`LargeBlobClearingAct::RetryVerification`] with the host's error
/// text as the cause (ADR-054).
#[derive(Debug)]
pub struct CredentialBlobMember<H> {
    host: H,
}

impl<H: CredentialBlobHost> CredentialBlobMember<H> {
    /// The member over `host`.
    #[must_use]
    pub const fn new(host: H) -> Self {
        Self { host }
    }
}

impl<H: CredentialBlobHost> RecoveryHandleStore for CredentialBlobMember<H> {
    type WriteFailure = LargeBlobNotLanded;

    async fn read_entry(&self, credential_id: &CredentialId) -> MemberRead<StoreEntry> {
        decoded(self.host.read_blob(credential_id).await, synced_entry)
    }

    async fn write_entry(
        &self,
        credential_id: &CredentialId,
        entry: &StoreEntry,
    ) -> Result<(), LargeBlobNotLanded> {
        match self
            .host
            .write_blob(credential_id, &encode_entry(entry))
            .await
        {
            Ok(outcome) => outcome.landed(),
            Err(failure) => Err(LargeBlobNotLanded {
                cause: Some(failure.cause),
                clears_by: LargeBlobClearingAct::RetryVerification,
            }),
        }
    }
}
