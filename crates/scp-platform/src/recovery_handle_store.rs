//! The store set a pending recovery handle lives in
//! (`09-security-model.md` §9.7.4.2 R10, `17-persistence-and-storage.md`
//! §17.8; SCP-311).
//!
//! A pre-rotation credential keys one store set. Its members are the
//! platform-account synced store, the credential's `WebAuthn` `largeBlob` store
//! and the SDK's own local store. Every member holds one entry, which is the
//! `largeBlob` record of §17.8: a flags byte, then a [`RecoveryHandle`] and a
//! [`LastRevealMarker`] where the flags name them. The SDK's local store and
//! the platform-account member also hold the [`StoreSetRecord`] and the signed
//! events, each event keyed on its preimage digest.
//!
//! [`StoreSet`] enforces R10's membership rules over the members a device
//! reaches:
//!
//! - the record is written once, at credential creation, and the running
//!   profile never changes its platform-account entry;
//! - a recorded member the device does not reach, or whose bytes do not
//!   decode, refuses the read with
//!   [`RecoveryStoreError::StorePartiallyUnreadable`];
//! - a failed platform-account write returns
//!   [`RecoveryStoreError::PlatformAccountWriteFailed`] and keeps the member;
//! - a `largeBlob` write that lands adds that member, and one that does not
//!   land returns [`LargeBlobWrite::NotLanded`] and removes that member alone.

use std::convert::Infallible;
use std::future::Future;

use scp_did::Identifier;
use scp_kel::constants::MAX_EVENT_BYTES;
use sha2::{Digest as _, Sha256};

use crate::{EncryptedStorage, MaybeSend};

#[cfg(test)]
mod tests;

/// The encoded width of a [`RecoveryHandle`] (`09-security-model.md`
/// §9.18.17).
///
/// One discriminant byte, the 32-byte identifier, the one-byte
/// [`RecoveryPhase`] and the 32-byte preimage digest of the composed event.
pub const RECOVERY_HANDLE_BYTES: usize = 66;

/// The encoded width of a [`LastRevealMarker`] (`09-security-model.md`
/// §9.18.17): the 32-byte identifier, the 8-byte big-endian sequence and the
/// 32-byte preimage digest.
pub const LAST_REVEAL_MARKER_BYTES: usize = 72;

/// The longest `WebAuthn` credential identifier, in bytes (`WebAuthn` Level 3
/// §4, "Credential ID": at most 1,023 bytes).
pub const MAX_CREDENTIAL_ID_BYTES: usize = 1023;

/// The `largeBlob` record's flag bit that says a handle follows (§17.8).
const FLAG_HANDLE: u8 = 0b0000_0001;
/// The `largeBlob` record's flag bit that says a marker follows (§17.8).
const FLAG_MARKER: u8 = 0b0000_0010;
/// The `StoreSetRecord` layout version (§17.8).
const STORE_SET_RECORD_VERSION: u8 = 0x01;
/// The `StoreSetRecord` bytes before the credential identifier: version,
/// platform-account byte, `largeBlob` byte and the 2-byte length.
const STORE_SET_RECORD_HEADER_BYTES: usize = 5;

// ---------------------------------------------------------------------------
// Value types
// ---------------------------------------------------------------------------

/// Where a reveal-authorized ceremony stands (`09-security-model.md`
/// §9.7.4.2 R10). The encoded byte is the declaration index, from `0x00`
/// (`17-persistence-and-storage.md` §17.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RecoveryPhase {
    /// The SDK composed the event and holds its preimage.
    Composed = 0x00,
    /// The custody signed the event.
    Signed = 0x01,
    /// The SDK sent the publish.
    PublishSent = 0x02,
    /// The publish was confirmed.
    Confirmed = 0x03,
    /// The confirm check found an illegality failure (R3) in the signed
    /// event, so the handle no longer blocks a reveal.
    Discarded = 0x04,
    /// The device adopted a chain R6 ranks above the chain carrying the
    /// event, so the handle no longer blocks a reveal.
    Lost = 0x05,
}

impl RecoveryPhase {
    /// Every phase, in declaration and byte order.
    pub const ALL: [Self; 6] = [
        Self::Composed,
        Self::Signed,
        Self::PublishSent,
        Self::Confirmed,
        Self::Discarded,
        Self::Lost,
    ];

    const fn to_byte(self) -> u8 {
        self as u8
    }

    const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::Composed),
            0x01 => Some(Self::Signed),
            0x02 => Some(Self::PublishSent),
            0x03 => Some(Self::Confirmed),
            0x04 => Some(Self::Discarded),
            0x05 => Some(Self::Lost),
            _ => None,
        }
    }
}

/// A pending reveal-authorized ceremony (`09-security-model.md` §9.7.4.2
/// R10).
///
/// The variant is the continuation, so `Abandons` has no next-set field
/// by construction. The handle never carries the composed preimage or the
/// signed event; those sit in the store set keyed on `event_digest`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecoveryHandle {
    /// The event fixes the next commitment. Discriminant byte `0x00`.
    FixesCommitment {
        /// The identity's 32-byte identifier.
        identifier: Identifier,
        /// Where the ceremony stands.
        phase: RecoveryPhase,
        /// The preimage digest of the composed event.
        event_digest: [u8; 32],
    },
    /// The event declares abandonment. Discriminant byte `0x01`.
    Abandons {
        /// The identity's 32-byte identifier.
        identifier: Identifier,
        /// Where the ceremony stands.
        phase: RecoveryPhase,
        /// The preimage digest of the composed event.
        event_digest: [u8; 32],
    },
}

impl RecoveryHandle {
    const FIXES_COMMITMENT: u8 = 0x00;
    const ABANDONS: u8 = 0x01;

    /// The identity's identifier.
    #[must_use]
    pub const fn identifier(&self) -> Identifier {
        match self {
            Self::FixesCommitment { identifier, .. } | Self::Abandons { identifier, .. } => {
                *identifier
            }
        }
    }

    /// Where the ceremony stands.
    #[must_use]
    pub const fn phase(&self) -> RecoveryPhase {
        match self {
            Self::FixesCommitment { phase, .. } | Self::Abandons { phase, .. } => *phase,
        }
    }

    /// The preimage digest of the composed event.
    #[must_use]
    pub const fn event_digest(&self) -> [u8; 32] {
        match self {
            Self::FixesCommitment { event_digest, .. } | Self::Abandons { event_digest, .. } => {
                *event_digest
            }
        }
    }

    /// The same handle at `phase`.
    #[must_use]
    pub const fn with_phase(self, phase: RecoveryPhase) -> Self {
        match self {
            Self::FixesCommitment {
                identifier,
                event_digest,
                ..
            } => Self::FixesCommitment {
                identifier,
                phase,
                event_digest,
            },
            Self::Abandons {
                identifier,
                event_digest,
                ..
            } => Self::Abandons {
                identifier,
                phase,
                event_digest,
            },
        }
    }
}

/// The identifier, sequence and preimage digest of the last reveal-authorized
/// event a completed ceremony published (`09-security-model.md` §9.7.4.2 R10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LastRevealMarker {
    /// The identity's identifier.
    pub identifier: Identifier,
    /// The event's sequence number.
    pub sequence: u64,
    /// The event's preimage digest.
    pub event_digest: [u8; 32],
}

/// The members a credential's store set can have (`09-security-model.md`
/// §9.7.4.2 R10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CredentialStore {
    /// The store through which the platform account syncs the credential.
    PlatformAccount,
    /// The credential's `WebAuthn` `largeBlob` store.
    LargeBlob,
    /// The SDK's own local store.
    SdkLocal,
}

/// A `WebAuthn` credential identifier: 1 to [`MAX_CREDENTIAL_ID_BYTES`] bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CredentialId(Vec<u8>);

impl CredentialId {
    /// Validates `bytes` as a credential identifier.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialIdError::Empty`] for zero bytes and
    /// [`CredentialIdError::TooLong`] above [`MAX_CREDENTIAL_ID_BYTES`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, CredentialIdError> {
        if bytes.is_empty() {
            return Err(CredentialIdError::Empty);
        }
        if bytes.len() > MAX_CREDENTIAL_ID_BYTES {
            return Err(CredentialIdError::TooLong { len: bytes.len() });
        }
        Ok(Self(bytes))
    }

    /// The identifier's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The lowercase hex SHA-256 of the identifier: the component that keys
    /// the credential's entries in the SDK's local store
    /// (`17-persistence-and-storage.md` §17.3).
    fn storage_component(&self) -> String {
        hex_lower(&Sha256::digest(&self.0))
    }
}

/// Why bytes are not a [`CredentialId`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CredentialIdError {
    /// The identifier has no bytes.
    #[error("a credential identifier has at least one byte")]
    Empty,
    /// The identifier exceeds the `WebAuthn` bound.
    #[error("a credential identifier of {len} bytes exceeds {MAX_CREDENTIAL_ID_BYTES}")]
    TooLong {
        /// The refused length.
        len: usize,
    },
}

/// Why a host has no platform-account member (`09-security-model.md`
/// §9.7.4.2 R10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PlatformAccountAbsence {
    /// The credential syncs through a store no data API of the host reaches.
    NoDataApiToCredentialSyncStore,
    /// The host holds no platform credential.
    NoPlatformCredential,
}

/// The platform-account entry of a [`StoreSetRecord`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PlatformAccountMember {
    /// The platform-account member exists.
    Present,
    /// The platform-account member does not exist, for the given reason.
    Absent(PlatformAccountAbsence),
}

/// The `largeBlob` entry of a [`StoreSetRecord`]: whether a `largeBlob` write
/// landed at the credential's designation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LargeBlobMembership {
    /// The last `largeBlob` write landed, so the store is a member.
    Member,
    /// No `largeBlob` write has landed, or the last one did not land.
    NotMember,
}

/// Which members a credential's store set has (`17-persistence-and-storage.md`
/// §17.8), written at credential creation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StoreSetRecord {
    /// The pre-rotation credential the record is keyed on.
    pub credential_id: CredentialId,
    /// The platform-account entry, fixed at creation.
    pub platform_account: PlatformAccountMember,
    /// The `largeBlob` entry, which only a `largeBlob` write changes.
    pub large_blob: LargeBlobMembership,
}

/// What one member holds: the §17.8 `largeBlob` record with at least one flag
/// set. A record with no flag set reads as [`MemberRead::ReachedEmpty`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StoreEntry {
    /// A pending handle and no marker.
    Handle(RecoveryHandle),
    /// A marker and no pending handle.
    Marker(LastRevealMarker),
    /// A pending handle beside the marker of the previous ceremony.
    HandleAndMarker {
        /// The pending handle.
        handle: RecoveryHandle,
        /// The previous ceremony's marker.
        marker: LastRevealMarker,
    },
}

impl StoreEntry {
    /// The pending handle, where the entry holds one.
    #[must_use]
    pub const fn handle(&self) -> Option<RecoveryHandle> {
        match self {
            Self::Handle(handle) | Self::HandleAndMarker { handle, .. } => Some(*handle),
            Self::Marker(_) => None,
        }
    }

    /// The last-reveal marker, where the entry holds one.
    #[must_use]
    pub const fn marker(&self) -> Option<LastRevealMarker> {
        match self {
            Self::Marker(marker) | Self::HandleAndMarker { marker, .. } => Some(*marker),
            Self::Handle(_) => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Reads, writes and errors
// ---------------------------------------------------------------------------

/// One member's answer to a read: it holds a value, it holds none, or the
/// SDK did not reach it. Bytes that do not decode are not reached
/// (`09-security-model.md` §9.7.4.2 R10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemberRead<T> {
    /// The member answered with a value.
    Reached(T),
    /// The member answered and holds no value.
    ReachedEmpty,
    /// The SDK did not reach the member.
    NotReached(NotReachedCause),
}

/// Why the SDK did not reach a member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotReachedCause {
    /// The member's store failed to answer.
    Unreachable {
        /// The cause the store reported.
        cause: String,
    },
    /// The member answered with bytes that do not decode.
    Undecodable(RecordDecodeError),
    /// This device has no handle on a member the record names.
    NoStoreOnDevice,
}

/// Why stored bytes do not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecordDecodeError {
    /// The bytes have the wrong length for their layout.
    #[error("{actual} bytes where the layout names {expected}")]
    WrongLength {
        /// The length the layout names.
        expected: usize,
        /// The length read.
        actual: usize,
    },
    /// A `RecoveryHandle` discriminant byte names no variant.
    #[error("unknown recovery-handle variant byte {0:#04x}")]
    UnknownVariant(u8),
    /// A `RecoveryPhase` byte names no phase.
    #[error("unknown recovery phase byte {0:#04x}")]
    UnknownPhase(u8),
    /// A `largeBlob` record sets a flag bit other than bits 0 and 1.
    #[error("largeBlob record flags {0:#04x} set a reserved bit")]
    UnknownFlags(u8),
    /// A `StoreSetRecord` names an unknown layout version.
    #[error("unknown store-set record version {0:#04x}")]
    UnknownVersion(u8),
    /// A `StoreSetRecord` platform-account byte names no entry.
    #[error("unknown platform-account byte {0:#04x}")]
    UnknownPlatformAccount(u8),
    /// A `StoreSetRecord` `largeBlob` byte names no entry.
    #[error("unknown largeBlob membership byte {0:#04x}")]
    UnknownLargeBlobMembership(u8),
    /// A `StoreSetRecord` credential identifier length is 0 or above 1,023.
    #[error("credential identifier length {0} is outside 1..=1023")]
    CredentialIdLength(usize),
    /// A stored signed event is empty or exceeds `MAX_EVENT_BYTES`.
    #[error("a stored event of {0} bytes is outside 1..=MAX_EVENT_BYTES")]
    EventLength(usize),
}

/// A write to the SDK's local store or the platform-account member that did
/// not complete.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("store write failed: {cause}")]
pub struct StoreWriteFailure {
    /// The cause the store reported.
    pub cause: String,
}

/// The act that clears a `largeBlob` write that did not land
/// (`09-security-model.md` §9.7.4.2 R10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LargeBlobClearingAct {
    /// The user declined the verification gesture; a retry clears it.
    RetryVerification,
    /// The authenticator's large-blob array is at capacity; removing the
    /// credential that consumed it, through the authenticator's own CTAP 2.1
    /// credential management, clears it. The SDK names this act and does not
    /// perform it.
    RemoveConsumingCredential,
}

/// A `largeBlob` write that did not land.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("largeBlob write did not land ({clears_by:?})")]
pub struct LargeBlobNotLanded {
    /// The cause where the platform reports one; `largeBlob: { written:
    /// false }` reports none.
    pub cause: Option<String>,
    /// The act that clears the condition.
    pub clears_by: LargeBlobClearingAct,
}

/// What an entry write did at the `largeBlob` member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LargeBlobWrite {
    /// The write landed, so the `largeBlob` store is a member.
    Landed,
    /// The write did not land, so the `largeBlob` store is no longer a
    /// member.
    NotLanded {
        /// The cause where the platform reports one.
        cause: Option<String>,
        /// The act that clears the condition.
        clears_by: LargeBlobClearingAct,
    },
    /// This device reaches no `largeBlob` store and the record names none.
    NoStore,
}

/// A refusal over the store set (`09-security-model.md` §9.7.4.2 R10).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryStoreError {
    /// A write to the platform-account member failed. The member stays in the
    /// record and the reveal is refused.
    #[error("platform-account write failed: {cause}")]
    PlatformAccountWriteFailed {
        /// The cause the platform reported.
        cause: String,
    },
    /// A write to the SDK's local store failed.
    #[error("SDK local store write failed: {cause}")]
    SdkLocalWriteFailed {
        /// The cause the store reported.
        cause: String,
    },
    /// The SDK did not reach a member the record names. The SDK maps this to
    /// `IdentityError::StorePartiallyUnreadable` (SCP-IDENT-1108).
    #[error("store set partially unreadable: {store:?} not reached ({cause:?})")]
    StorePartiallyUnreadable {
        /// The member not reached.
        store: CredentialStore,
        /// Why it was not reached.
        cause: NotReachedCause,
    },
    /// Neither the local store nor the platform-account member holds a
    /// record for the credential.
    #[error("no store-set record for the credential")]
    RecordMissing,
    /// A record for the credential exists and differs from the one creation
    /// would write; the record is written once.
    #[error("a different store-set record already exists for the credential")]
    RecordAlreadyWritten,
    /// The record read under the credential's key names another credential.
    #[error("the store-set record names another credential")]
    RecordCredentialMismatch,
    /// A signed event to store is empty or exceeds `MAX_EVENT_BYTES`.
    #[error("a signed event of {len} bytes is outside 1..=MAX_EVENT_BYTES")]
    EventLength {
        /// The refused length.
        len: usize,
    },
}

// ---------------------------------------------------------------------------
// Member traits
// ---------------------------------------------------------------------------

/// One member of a credential's store set: it holds the credential's entry.
///
/// A member is bound to one credential when it is built, so no method takes
/// the credential. Futures are `Send` on native targets and unbounded on
/// `wasm32`, so a browser member can implement the trait.
pub trait RecoveryHandleStore {
    /// What a write that does not complete reports.
    type WriteFailure: MaybeSend;

    /// Reads the member's entry.
    fn read_entry(&self) -> impl Future<Output = MemberRead<StoreEntry>> + MaybeSend;

    /// Replaces the member's entry with `entry`.
    fn write_entry(
        &self,
        entry: &StoreEntry,
    ) -> impl Future<Output = Result<(), Self::WriteFailure>> + MaybeSend;
}

/// A member that also holds the [`StoreSetRecord`] and the signed events:
/// the SDK's local store and the platform-account member
/// (`17-persistence-and-storage.md` §17.8). A `largeBlob` store holds neither.
pub trait RecoveryRecordStore: RecoveryHandleStore {
    /// Reads the credential's store-set record.
    fn read_record(&self) -> impl Future<Output = MemberRead<StoreSetRecord>> + MaybeSend;

    /// Replaces the credential's store-set record.
    fn write_record(
        &self,
        record: &StoreSetRecord,
    ) -> impl Future<Output = Result<(), Self::WriteFailure>> + MaybeSend;

    /// Reads the signed event keyed on `event_digest`.
    fn read_event(
        &self,
        event_digest: &[u8; 32],
    ) -> impl Future<Output = MemberRead<Vec<u8>>> + MaybeSend;

    /// Stores `event` under `event_digest`. The caller has checked its length.
    fn write_event(
        &self,
        event_digest: &[u8; 32],
        event: &[u8],
    ) -> impl Future<Output = Result<(), Self::WriteFailure>> + MaybeSend;
}

/// `Sync` on every target but `wasm32`, and no bound on `wasm32`.
///
/// It lets a [`StoreSet`] future be `Send` on native targets, as
/// [`MaybeSend`] does for a member's own futures, while a browser member,
/// which is not `Sync`, still fits the set.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSync: Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Sync + ?Sized> MaybeSync for T {}

/// `Sync` on every target but `wasm32`, and no bound on `wasm32`.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSync {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSync for T {}

/// The platform-account member type of a host that has none.
///
/// It wraps [`Infallible`], so no value of it exists and a
/// [`PlatformAccountSlot::Present`] of it cannot be built.
#[derive(Debug)]
pub struct NoPlatformAccount(Infallible);

impl RecoveryHandleStore for NoPlatformAccount {
    type WriteFailure = StoreWriteFailure;

    async fn read_entry(&self) -> MemberRead<StoreEntry> {
        match self.0 {}
    }

    async fn write_entry(&self, _entry: &StoreEntry) -> Result<(), StoreWriteFailure> {
        match self.0 {}
    }
}

impl RecoveryRecordStore for NoPlatformAccount {
    async fn read_record(&self) -> MemberRead<StoreSetRecord> {
        match self.0 {}
    }

    async fn write_record(&self, _record: &StoreSetRecord) -> Result<(), StoreWriteFailure> {
        match self.0 {}
    }

    async fn read_event(&self, _event_digest: &[u8; 32]) -> MemberRead<Vec<u8>> {
        match self.0 {}
    }

    async fn write_event(
        &self,
        _event_digest: &[u8; 32],
        _event: &[u8],
    ) -> Result<(), StoreWriteFailure> {
        match self.0 {}
    }
}

/// The `largeBlob` member type of a device that reaches no `largeBlob` store.
///
/// It wraps [`Infallible`], so no value of it exists and only `None` fills a
/// slot of it.
#[derive(Debug)]
pub struct NoLargeBlob(Infallible);

impl RecoveryHandleStore for NoLargeBlob {
    type WriteFailure = LargeBlobNotLanded;

    async fn read_entry(&self) -> MemberRead<StoreEntry> {
        match self.0 {}
    }

    async fn write_entry(&self, _entry: &StoreEntry) -> Result<(), LargeBlobNotLanded> {
        match self.0 {}
    }
}

// ---------------------------------------------------------------------------
// The SDK's local store
// ---------------------------------------------------------------------------

/// The SDK's own local store as a store-set member, over injected encrypted
/// storage.
///
/// It holds the entry, the record and the signed events under
/// `recovery/{sha256_hex(credential_id)}/` (`17-persistence-and-storage.md`
/// §17.3).
#[derive(Debug)]
pub struct SdkLocalMember<S: EncryptedStorage> {
    storage: S,
    prefix: String,
}

impl<S: EncryptedStorage> SdkLocalMember<S> {
    /// Binds `storage` to `credential_id`'s entries.
    #[must_use]
    pub fn new(storage: S, credential_id: &CredentialId) -> Self {
        Self {
            storage,
            prefix: format!("recovery/{}", credential_id.storage_component()),
        }
    }

    fn entry_key(&self) -> String {
        format!("{}/entry", self.prefix)
    }

    fn record_key(&self) -> String {
        format!("{}/record", self.prefix)
    }

    fn event_key(&self, event_digest: &[u8; 32]) -> String {
        format!("{}/event/{}", self.prefix, hex_lower(event_digest))
    }

    async fn read_decoded<T>(
        &self,
        key: &str,
        decode: impl FnOnce(&[u8]) -> Result<Option<T>, RecordDecodeError> + Send,
    ) -> MemberRead<T> {
        match self.storage.retrieve(key).await {
            Ok(None) => MemberRead::ReachedEmpty,
            Ok(Some(bytes)) => match decode(&bytes) {
                Ok(Some(value)) => MemberRead::Reached(value),
                Ok(None) => MemberRead::ReachedEmpty,
                Err(error) => MemberRead::NotReached(NotReachedCause::Undecodable(error)),
            },
            Err(error) => MemberRead::NotReached(NotReachedCause::Unreachable {
                cause: error.to_string(),
            }),
        }
    }

    async fn store(&self, key: &str, bytes: &[u8]) -> Result<(), StoreWriteFailure> {
        self.storage
            .store(key, bytes)
            .await
            .map_err(|error| StoreWriteFailure {
                cause: error.to_string(),
            })
    }
}

impl<S: EncryptedStorage> RecoveryHandleStore for SdkLocalMember<S> {
    type WriteFailure = StoreWriteFailure;

    async fn read_entry(&self) -> MemberRead<StoreEntry> {
        self.read_decoded(&self.entry_key(), decode_entry_record)
            .await
    }

    async fn write_entry(&self, entry: &StoreEntry) -> Result<(), StoreWriteFailure> {
        self.store(&self.entry_key(), &encode_entry_record(entry))
            .await
    }
}

impl<S: EncryptedStorage> RecoveryRecordStore for SdkLocalMember<S> {
    async fn read_record(&self) -> MemberRead<StoreSetRecord> {
        self.read_decoded(&self.record_key(), |bytes| {
            decode_store_set_record(bytes).map(Some)
        })
        .await
    }

    async fn write_record(&self, record: &StoreSetRecord) -> Result<(), StoreWriteFailure> {
        self.store(&self.record_key(), &encode_store_set_record(record))
            .await
    }

    async fn read_event(&self, event_digest: &[u8; 32]) -> MemberRead<Vec<u8>> {
        self.read_decoded(&self.event_key(event_digest), |bytes| {
            check_event_length(bytes).map(|()| Some(bytes.to_vec()))
        })
        .await
    }

    async fn write_event(
        &self,
        event_digest: &[u8; 32],
        event: &[u8],
    ) -> Result<(), StoreWriteFailure> {
        self.store(&self.event_key(event_digest), event).await
    }
}

// ---------------------------------------------------------------------------
// The store set
// ---------------------------------------------------------------------------

/// The platform-account member as this device holds it.
#[derive(Debug)]
pub enum PlatformAccountSlot<P> {
    /// The host gives the SDK a data API into the credential's sync store.
    Present(P),
    /// The host has no platform-account member, for the given reason.
    Absent(PlatformAccountAbsence),
}

/// The members a device reaches for one credential.
#[derive(Debug)]
pub struct StoreSetMembers<L, P, B> {
    /// The SDK's own local store, which every device has.
    pub sdk_local: L,
    /// The platform-account member, or why the host has none.
    pub platform_account: PlatformAccountSlot<P>,
    /// The credential's `largeBlob` store, where the device reaches one.
    pub large_blob: Option<B>,
}

/// What each recorded member holds, read in one pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetRead {
    /// One entry per recorded member, the local store first.
    pub per_store: Vec<StoreRead>,
}

/// What one recorded member holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreRead {
    /// The member.
    pub store: CredentialStore,
    /// Its entry, or `None` where it holds none.
    pub entry: Option<StoreEntry>,
}

/// A credential's store set: the members a device reaches, governed by the
/// credential's [`StoreSetRecord`] (`09-security-model.md` §9.7.4.2 R10).
#[derive(Debug)]
pub struct StoreSet<L, P, B> {
    members: StoreSetMembers<L, P, B>,
    record: StoreSetRecord,
}

impl<L, P, B> StoreSet<L, P, B>
where
    L: RecoveryRecordStore<WriteFailure = StoreWriteFailure> + MaybeSync,
    P: RecoveryRecordStore<WriteFailure = StoreWriteFailure> + MaybeSync,
    B: RecoveryHandleStore<WriteFailure = LargeBlobNotLanded> + MaybeSync,
{
    /// Writes the credential's record at credential creation, to the local
    /// store and, where present, to the platform-account member. The
    /// platform-account entry comes from `members`; the `largeBlob` entry
    /// starts as [`LargeBlobMembership::NotMember`], because only a landed
    /// write adds that member. A repeated call with the same members writes
    /// the same record again, so a creation interrupted between the two
    /// writes completes on retry.
    ///
    /// # Errors
    ///
    /// - [`RecoveryStoreError::RecordAlreadyWritten`] where the local store
    ///   holds a different record for the credential.
    /// - [`RecoveryStoreError::StorePartiallyUnreadable`] where the local
    ///   store does not answer.
    /// - [`RecoveryStoreError::SdkLocalWriteFailed`] and
    ///   [`RecoveryStoreError::PlatformAccountWriteFailed`] where a write
    ///   fails.
    pub async fn create(
        members: StoreSetMembers<L, P, B>,
        credential_id: CredentialId,
    ) -> Result<Self, RecoveryStoreError> {
        let record = StoreSetRecord {
            credential_id,
            platform_account: match &members.platform_account {
                PlatformAccountSlot::Present(_) => PlatformAccountMember::Present,
                PlatformAccountSlot::Absent(reason) => PlatformAccountMember::Absent(*reason),
            },
            large_blob: LargeBlobMembership::NotMember,
        };
        match members.sdk_local.read_record().await {
            MemberRead::ReachedEmpty => {}
            MemberRead::Reached(existing) if existing == record => {}
            MemberRead::Reached(_) => return Err(RecoveryStoreError::RecordAlreadyWritten),
            MemberRead::NotReached(cause) => {
                return Err(RecoveryStoreError::StorePartiallyUnreadable {
                    store: CredentialStore::SdkLocal,
                    cause,
                });
            }
        }
        let set = Self { members, record };
        set.persist_record().await?;
        Ok(set)
    }

    /// Opens the credential's store set from its record. The local store's
    /// record governs. Where the local store holds none, the platform-account
    /// member's copy is read and written into the local store unchanged, so a
    /// second device that syncs the credential adopts the record creation
    /// wrote.
    ///
    /// # Errors
    ///
    /// - [`RecoveryStoreError::RecordMissing`] where no reached store holds
    ///   a record.
    /// - [`RecoveryStoreError::RecordCredentialMismatch`] where the record
    ///   names another credential.
    /// - [`RecoveryStoreError::StorePartiallyUnreadable`] where the local
    ///   store does not answer, or holds no record and the platform-account
    ///   member does not answer.
    /// - [`RecoveryStoreError::SdkLocalWriteFailed`] where adopting the
    ///   platform-account copy fails.
    pub async fn open(
        members: StoreSetMembers<L, P, B>,
        credential_id: &CredentialId,
    ) -> Result<Self, RecoveryStoreError> {
        let record = match members.sdk_local.read_record().await {
            MemberRead::Reached(record) => record,
            MemberRead::NotReached(cause) => {
                return Err(RecoveryStoreError::StorePartiallyUnreadable {
                    store: CredentialStore::SdkLocal,
                    cause,
                });
            }
            MemberRead::ReachedEmpty => {
                let PlatformAccountSlot::Present(platform) = &members.platform_account else {
                    return Err(RecoveryStoreError::RecordMissing);
                };
                let record = match platform.read_record().await {
                    MemberRead::Reached(record) => record,
                    MemberRead::ReachedEmpty => return Err(RecoveryStoreError::RecordMissing),
                    MemberRead::NotReached(cause) => {
                        return Err(RecoveryStoreError::StorePartiallyUnreadable {
                            store: CredentialStore::PlatformAccount,
                            cause,
                        });
                    }
                };
                if record.credential_id != *credential_id {
                    return Err(RecoveryStoreError::RecordCredentialMismatch);
                }
                members
                    .sdk_local
                    .write_record(&record)
                    .await
                    .map_err(|failure| RecoveryStoreError::SdkLocalWriteFailed {
                        cause: failure.cause,
                    })?;
                record
            }
        };
        if record.credential_id != *credential_id {
            return Err(RecoveryStoreError::RecordCredentialMismatch);
        }
        Ok(Self { members, record })
    }

    /// The credential's record as this set holds it.
    #[must_use]
    pub const fn record(&self) -> &StoreSetRecord {
        &self.record
    }

    /// Reads every recorded member's entry. A member the record names
    /// governs the read whatever profile this device runs: a recorded
    /// platform-account member is read where the host now reports none, and
    /// an unrecorded one is not read.
    ///
    /// # Errors
    ///
    /// [`RecoveryStoreError::StorePartiallyUnreadable`] where any recorded
    /// member is not reached, including bytes that do not decode and a member
    /// this device has no handle on. A partial read is indistinguishable from
    /// an empty one, so no entry is returned.
    pub async fn read_entries(&self) -> Result<SetRead, RecoveryStoreError> {
        let mut per_store = Vec::with_capacity(3);
        per_store.push(StoreRead {
            store: CredentialStore::SdkLocal,
            entry: reached_entry(
                CredentialStore::SdkLocal,
                self.members.sdk_local.read_entry().await,
            )?,
        });
        if let Some(platform) = self.recorded_platform_account()? {
            per_store.push(StoreRead {
                store: CredentialStore::PlatformAccount,
                entry: reached_entry(
                    CredentialStore::PlatformAccount,
                    platform.read_entry().await,
                )?,
            });
        }
        if let Some(large_blob) = self.recorded_large_blob()? {
            per_store.push(StoreRead {
                store: CredentialStore::LargeBlob,
                entry: reached_entry(CredentialStore::LargeBlob, large_blob.read_entry().await)?,
            });
        }
        Ok(SetRead { per_store })
    }

    /// Writes `entry` to the local store, then to the recorded
    /// platform-account member, then to the device's `largeBlob` store. A
    /// landed `largeBlob` write adds that member to the record and one that
    /// does not land removes it; the changed record is written to the local
    /// store and the recorded platform-account member. No other outcome
    /// changes the record.
    ///
    /// # Errors
    ///
    /// - [`RecoveryStoreError::StorePartiallyUnreadable`] before any write,
    ///   where the device has no handle on a recorded member.
    /// - [`RecoveryStoreError::SdkLocalWriteFailed`] where a local write
    ///   fails.
    /// - [`RecoveryStoreError::PlatformAccountWriteFailed`] where a
    ///   platform-account write fails; the member stays in the record.
    pub async fn write_entry(
        &mut self,
        entry: &StoreEntry,
    ) -> Result<LargeBlobWrite, RecoveryStoreError> {
        let platform = self.recorded_platform_account()?;
        self.recorded_large_blob()?;
        self.members
            .sdk_local
            .write_entry(entry)
            .await
            .map_err(sdk_local_failed)?;
        if let Some(platform) = platform {
            platform
                .write_entry(entry)
                .await
                .map_err(platform_account_failed)?;
        }
        let Some(large_blob) = &self.members.large_blob else {
            return Ok(LargeBlobWrite::NoStore);
        };
        let (membership, outcome) = match large_blob.write_entry(entry).await {
            Ok(()) => (LargeBlobMembership::Member, LargeBlobWrite::Landed),
            Err(not_landed) => (
                LargeBlobMembership::NotMember,
                LargeBlobWrite::NotLanded {
                    cause: not_landed.cause,
                    clears_by: not_landed.clears_by,
                },
            ),
        };
        if membership != self.record.large_blob {
            // The local record governs, so this set adopts the change once
            // the local write lands, whatever the platform-account write does.
            let updated = StoreSetRecord {
                large_blob: membership,
                ..self.record.clone()
            };
            self.members
                .sdk_local
                .write_record(&updated)
                .await
                .map_err(sdk_local_failed)?;
            self.record = updated;
            if let Some(platform) = self.recorded_platform_account()? {
                platform
                    .write_record(&self.record)
                    .await
                    .map_err(platform_account_failed)?;
            }
        }
        Ok(outcome)
    }

    /// Stores a signed event under `event_digest` in the local store and in
    /// the recorded platform-account member. A `largeBlob` store never holds
    /// an event.
    ///
    /// # Errors
    ///
    /// - [`RecoveryStoreError::EventLength`] where `event` is empty or
    ///   exceeds `MAX_EVENT_BYTES`.
    /// - [`RecoveryStoreError::StorePartiallyUnreadable`] where the device
    ///   has no handle on a recorded platform-account member.
    /// - [`RecoveryStoreError::SdkLocalWriteFailed`] and
    ///   [`RecoveryStoreError::PlatformAccountWriteFailed`] where a write
    ///   fails.
    pub async fn write_event(
        &self,
        event_digest: &[u8; 32],
        event: &[u8],
    ) -> Result<(), RecoveryStoreError> {
        check_event_length(event)
            .map_err(|_| RecoveryStoreError::EventLength { len: event.len() })?;
        let platform = self.recorded_platform_account()?;
        self.members
            .sdk_local
            .write_event(event_digest, event)
            .await
            .map_err(sdk_local_failed)?;
        if let Some(platform) = platform {
            platform
                .write_event(event_digest, event)
                .await
                .map_err(platform_account_failed)?;
        }
        Ok(())
    }

    /// Reads the signed event keyed on `event_digest` from the local store,
    /// or from the platform-account member where the local store holds none.
    /// `Ok(None)` means every store answered and none holds the event.
    ///
    /// # Errors
    ///
    /// [`RecoveryStoreError::StorePartiallyUnreadable`] where no store
    /// returned the event and a store that might hold it was not reached.
    pub async fn read_event(
        &self,
        event_digest: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, RecoveryStoreError> {
        let local_miss = match self.members.sdk_local.read_event(event_digest).await {
            MemberRead::Reached(event) => return Ok(Some(event)),
            MemberRead::ReachedEmpty => None,
            MemberRead::NotReached(cause) => Some(RecoveryStoreError::StorePartiallyUnreadable {
                store: CredentialStore::SdkLocal,
                cause,
            }),
        };
        let platform_miss = match &self.members.platform_account {
            PlatformAccountSlot::Present(platform) => {
                match platform.read_event(event_digest).await {
                    MemberRead::Reached(event) => return Ok(Some(event)),
                    MemberRead::ReachedEmpty => None,
                    MemberRead::NotReached(cause) => {
                        Some(RecoveryStoreError::StorePartiallyUnreadable {
                            store: CredentialStore::PlatformAccount,
                            cause,
                        })
                    }
                }
            }
            PlatformAccountSlot::Absent(_) => None,
        };
        local_miss.or(platform_miss).map_or(Ok(None), Err)
    }

    /// The platform-account member to read and write: `Some` where the
    /// record names it, `None` where the record names its absence.
    const fn recorded_platform_account(&self) -> Result<Option<&P>, RecoveryStoreError> {
        match (self.record.platform_account, &self.members.platform_account) {
            (PlatformAccountMember::Absent(_), _) => Ok(None),
            (PlatformAccountMember::Present, PlatformAccountSlot::Present(platform)) => {
                Ok(Some(platform))
            }
            (PlatformAccountMember::Present, PlatformAccountSlot::Absent(_)) => {
                Err(no_store_on_device(CredentialStore::PlatformAccount))
            }
        }
    }

    /// The `largeBlob` member to read: `Some` where the record names it.
    const fn recorded_large_blob(&self) -> Result<Option<&B>, RecoveryStoreError> {
        match (self.record.large_blob, &self.members.large_blob) {
            (LargeBlobMembership::NotMember, _) => Ok(None),
            (LargeBlobMembership::Member, Some(large_blob)) => Ok(Some(large_blob)),
            (LargeBlobMembership::Member, None) => {
                Err(no_store_on_device(CredentialStore::LargeBlob))
            }
        }
    }

    /// Writes the record to the local store, then to the recorded
    /// platform-account member.
    async fn persist_record(&self) -> Result<(), RecoveryStoreError> {
        let platform = self.recorded_platform_account()?;
        self.members
            .sdk_local
            .write_record(&self.record)
            .await
            .map_err(sdk_local_failed)?;
        if let Some(platform) = platform {
            platform
                .write_record(&self.record)
                .await
                .map_err(platform_account_failed)?;
        }
        Ok(())
    }
}

fn reached_entry(
    store: CredentialStore,
    read: MemberRead<StoreEntry>,
) -> Result<Option<StoreEntry>, RecoveryStoreError> {
    match read {
        MemberRead::Reached(entry) => Ok(Some(entry)),
        MemberRead::ReachedEmpty => Ok(None),
        MemberRead::NotReached(cause) => {
            Err(RecoveryStoreError::StorePartiallyUnreadable { store, cause })
        }
    }
}

const fn no_store_on_device(store: CredentialStore) -> RecoveryStoreError {
    RecoveryStoreError::StorePartiallyUnreadable {
        store,
        cause: NotReachedCause::NoStoreOnDevice,
    }
}

fn sdk_local_failed(failure: StoreWriteFailure) -> RecoveryStoreError {
    RecoveryStoreError::SdkLocalWriteFailed {
        cause: failure.cause,
    }
}

fn platform_account_failed(failure: StoreWriteFailure) -> RecoveryStoreError {
    RecoveryStoreError::PlatformAccountWriteFailed {
        cause: failure.cause,
    }
}

// ---------------------------------------------------------------------------
// Codecs
// ---------------------------------------------------------------------------

/// Encodes `handle` at [`RECOVERY_HANDLE_BYTES`]: discriminant ‖ identifier ‖
/// phase ‖ event digest.
pub(crate) fn encode_handle(handle: &RecoveryHandle) -> [u8; RECOVERY_HANDLE_BYTES] {
    let mut out = [0u8; RECOVERY_HANDLE_BYTES];
    out[0] = match handle {
        RecoveryHandle::FixesCommitment { .. } => RecoveryHandle::FIXES_COMMITMENT,
        RecoveryHandle::Abandons { .. } => RecoveryHandle::ABANDONS,
    };
    out[1..33].copy_from_slice(handle.identifier().as_bytes());
    out[33] = handle.phase().to_byte();
    out[34..66].copy_from_slice(&handle.event_digest());
    out
}

/// Decodes exactly [`RECOVERY_HANDLE_BYTES`] bytes as a handle.
pub(crate) fn decode_handle(bytes: &[u8]) -> Result<RecoveryHandle, RecordDecodeError> {
    let bytes: &[u8; RECOVERY_HANDLE_BYTES] =
        bytes
            .try_into()
            .map_err(|_| RecordDecodeError::WrongLength {
                expected: RECOVERY_HANDLE_BYTES,
                actual: bytes.len(),
            })?;
    let (variant, rest) = bytes.split_at(1);
    let (identifier, rest) = rest.split_at(32);
    let (phase, digest) = rest.split_at(1);
    let identifier = Identifier::from_bytes(array32(identifier));
    let phase =
        RecoveryPhase::from_byte(phase[0]).ok_or(RecordDecodeError::UnknownPhase(phase[0]))?;
    let event_digest = array32(digest);
    match variant[0] {
        RecoveryHandle::FIXES_COMMITMENT => Ok(RecoveryHandle::FixesCommitment {
            identifier,
            phase,
            event_digest,
        }),
        RecoveryHandle::ABANDONS => Ok(RecoveryHandle::Abandons {
            identifier,
            phase,
            event_digest,
        }),
        other => Err(RecordDecodeError::UnknownVariant(other)),
    }
}

/// Encodes `marker` at [`LAST_REVEAL_MARKER_BYTES`]: identifier ‖ sequence
/// (big-endian) ‖ event digest.
pub(crate) fn encode_marker(marker: &LastRevealMarker) -> [u8; LAST_REVEAL_MARKER_BYTES] {
    let mut out = [0u8; LAST_REVEAL_MARKER_BYTES];
    out[0..32].copy_from_slice(marker.identifier.as_bytes());
    out[32..40].copy_from_slice(&marker.sequence.to_be_bytes());
    out[40..72].copy_from_slice(&marker.event_digest);
    out
}

/// Decodes exactly [`LAST_REVEAL_MARKER_BYTES`] bytes as a marker.
pub(crate) fn decode_marker(bytes: &[u8]) -> Result<LastRevealMarker, RecordDecodeError> {
    let bytes: &[u8; LAST_REVEAL_MARKER_BYTES] =
        bytes
            .try_into()
            .map_err(|_| RecordDecodeError::WrongLength {
                expected: LAST_REVEAL_MARKER_BYTES,
                actual: bytes.len(),
            })?;
    let (identifier, rest) = bytes.split_at(32);
    let (sequence, digest) = rest.split_at(8);
    let mut sequence_bytes = [0u8; 8];
    sequence_bytes.copy_from_slice(sequence);
    Ok(LastRevealMarker {
        identifier: Identifier::from_bytes(array32(identifier)),
        sequence: u64::from_be_bytes(sequence_bytes),
        event_digest: array32(digest),
    })
}

/// Encodes `entry` as the §17.8 `largeBlob` record: flags ‖ handle? ‖
/// marker?.
pub(crate) fn encode_entry_record(entry: &StoreEntry) -> Vec<u8> {
    let handle = entry.handle();
    let marker = entry.marker();
    let mut flags = 0u8;
    if handle.is_some() {
        flags |= FLAG_HANDLE;
    }
    if marker.is_some() {
        flags |= FLAG_MARKER;
    }
    let mut out = Vec::with_capacity(1 + RECOVERY_HANDLE_BYTES + LAST_REVEAL_MARKER_BYTES);
    out.push(flags);
    if let Some(handle) = handle {
        out.extend_from_slice(&encode_handle(&handle));
    }
    if let Some(marker) = marker {
        out.extend_from_slice(&encode_marker(&marker));
    }
    out
}

/// Decodes a §17.8 `largeBlob` record. `Ok(None)` is a record with no flag
/// set. Refuses a reserved flag bit and a length other than the one the
/// flags name (1, 67, 73 or 139 bytes).
pub(crate) fn decode_entry_record(bytes: &[u8]) -> Result<Option<StoreEntry>, RecordDecodeError> {
    let Some((&flags, body)) = bytes.split_first() else {
        return Err(RecordDecodeError::WrongLength {
            expected: 1,
            actual: 0,
        });
    };
    if flags & !(FLAG_HANDLE | FLAG_MARKER) != 0 {
        return Err(RecordDecodeError::UnknownFlags(flags));
    }
    let has_handle = flags & FLAG_HANDLE != 0;
    let has_marker = flags & FLAG_MARKER != 0;
    let handle_len = if has_handle { RECOVERY_HANDLE_BYTES } else { 0 };
    let marker_len = if has_marker {
        LAST_REVEAL_MARKER_BYTES
    } else {
        0
    };
    if body.len() != handle_len + marker_len {
        return Err(RecordDecodeError::WrongLength {
            expected: 1 + handle_len + marker_len,
            actual: bytes.len(),
        });
    }
    let (handle_bytes, marker_bytes) = body.split_at(handle_len);
    let handle = if has_handle {
        Some(decode_handle(handle_bytes)?)
    } else {
        None
    };
    let marker = if has_marker {
        Some(decode_marker(marker_bytes)?)
    } else {
        None
    };
    Ok(match (handle, marker) {
        (None, None) => None,
        (Some(handle), None) => Some(StoreEntry::Handle(handle)),
        (None, Some(marker)) => Some(StoreEntry::Marker(marker)),
        (Some(handle), Some(marker)) => Some(StoreEntry::HandleAndMarker { handle, marker }),
    })
}

/// Encodes `record` (§17.8): version `0x01` ‖ platform-account byte ‖
/// `largeBlob` byte ‖ credential identifier length (u16 big-endian) ‖
/// credential identifier.
pub(crate) fn encode_store_set_record(record: &StoreSetRecord) -> Vec<u8> {
    let id = record.credential_id.as_bytes();
    let mut out = Vec::with_capacity(STORE_SET_RECORD_HEADER_BYTES + id.len());
    out.push(STORE_SET_RECORD_VERSION);
    out.push(match record.platform_account {
        PlatformAccountMember::Present => 0x00,
        PlatformAccountMember::Absent(PlatformAccountAbsence::NoDataApiToCredentialSyncStore) => {
            0x01
        }
        PlatformAccountMember::Absent(PlatformAccountAbsence::NoPlatformCredential) => 0x02,
    });
    out.push(match record.large_blob {
        LargeBlobMembership::NotMember => 0x00,
        LargeBlobMembership::Member => 0x01,
    });
    // `CredentialId` bounds the length at 1,023, so the low two bytes of the
    // big-endian length are the whole length.
    let len = id.len().to_be_bytes();
    out.extend_from_slice(&len[len.len() - 2..]);
    out.extend_from_slice(id);
    out
}

/// Decodes a §17.8 `StoreSetRecord`, refusing an unknown version, platform
/// byte or `largeBlob` byte, a credential identifier length outside
/// 1..=1023, and a total length other than the one the header names.
pub(crate) fn decode_store_set_record(bytes: &[u8]) -> Result<StoreSetRecord, RecordDecodeError> {
    let Some((header, id)) = bytes.split_first_chunk::<STORE_SET_RECORD_HEADER_BYTES>() else {
        return Err(RecordDecodeError::WrongLength {
            expected: STORE_SET_RECORD_HEADER_BYTES,
            actual: bytes.len(),
        });
    };
    let [version, platform, large_blob, len_hi, len_lo] = *header;
    if version != STORE_SET_RECORD_VERSION {
        return Err(RecordDecodeError::UnknownVersion(version));
    }
    let platform_account = match platform {
        0x00 => PlatformAccountMember::Present,
        0x01 => {
            PlatformAccountMember::Absent(PlatformAccountAbsence::NoDataApiToCredentialSyncStore)
        }
        0x02 => PlatformAccountMember::Absent(PlatformAccountAbsence::NoPlatformCredential),
        other => return Err(RecordDecodeError::UnknownPlatformAccount(other)),
    };
    let large_blob = match large_blob {
        0x00 => LargeBlobMembership::NotMember,
        0x01 => LargeBlobMembership::Member,
        other => return Err(RecordDecodeError::UnknownLargeBlobMembership(other)),
    };
    let id_len = usize::from(u16::from_be_bytes([len_hi, len_lo]));
    if id_len == 0 || id_len > MAX_CREDENTIAL_ID_BYTES {
        return Err(RecordDecodeError::CredentialIdLength(id_len));
    }
    if id.len() != id_len {
        return Err(RecordDecodeError::WrongLength {
            expected: STORE_SET_RECORD_HEADER_BYTES + id_len,
            actual: bytes.len(),
        });
    }
    let credential_id = CredentialId::new(id.to_vec())
        .map_err(|_| RecordDecodeError::CredentialIdLength(id_len))?;
    Ok(StoreSetRecord {
        credential_id,
        platform_account,
        large_blob,
    })
}

/// Refuses an empty event and one above `MAX_EVENT_BYTES`.
fn check_event_length(event: &[u8]) -> Result<(), RecordDecodeError> {
    let within = u32::try_from(event.len()).is_ok_and(|len| len <= MAX_EVENT_BYTES);
    if event.is_empty() || !within {
        return Err(RecordDecodeError::EventLength(event.len()));
    }
    Ok(())
}

/// Copies a 32-byte slice the caller has already split to width.
const fn array32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    out
}

/// Lowercase hex of `bytes`.
fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}
