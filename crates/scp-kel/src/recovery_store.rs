//! The store set a pending recovery handle lives in
//! (`09-security-model.md` §9.7.4.2 R10, `17-persistence-and-storage.md`
//! §17.3 and §17.8; SCP-311).
//!
//! A pre-rotation credential keys one store set. Its possible members are the
//! platform-account synced store, the credential's `WebAuthn` `largeBlob`
//! store and the SDK's own local store. Every member holds one entry: a flags
//! byte, then a [`RecoveryHandle`] and a [`LastRevealMarker`] where the flags
//! name them. The platform-account member and the SDK's local store also hold
//! the signed events, each keyed on its preimage digest, and the
//! platform-account member alone holds the [`StoreSetRecord`].
//!
//! Membership follows the credential and the host, never one device's cache:
//!
//! - where the host gives the platform-account member, the record in that
//!   member says whether the `largeBlob` store is a member, and every
//!   operation reads it afresh;
//! - where the host gives none, there is no record, and the `largeBlob` store
//!   is a member exactly where a read of it returns a handle or a marker;
//! - a device that holds a `largeBlob` handle reads that store on every
//!   operation, whatever the record says.
//!
//! [`StoreSet`] offers no raw entry write. A ceremony moves through five
//! transitions — [`StoreSet::compose`], [`StoreSet::hold`],
//! [`StoreSet::advance`], [`StoreSet::complete`] and [`StoreSet::remove`] —
//! each of which reads every store it reaches, computes every member's merge
//! from those reads before its first write, and writes the platform-account
//! member, then the `largeBlob` store, then the local store, then the record.
//! A phase only moves forward, a handle another ceremony holds live is never
//! replaced, and a marker is replaced only by one of equal or higher sequence.

use std::convert::Infallible;
use std::future::Future;

use scp_did::Identifier;
use sha2::{Digest as _, Sha256};

use crate::constants::MAX_EVENT_BYTES;
use crate::key_event_signer::MaybeSend;

#[cfg(test)]
mod tests;

/// The encoded width of a [`RecoveryHandle`] (`09-security-model.md` §9.18.17).
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

/// Entry flag bit 0: a handle follows (§17.8).
const FLAG_HANDLE: u8 = 0b0000_0001;
/// Entry flag bit 1: a marker follows (§17.8).
const FLAG_MARKER: u8 = 0b0000_0010;
/// Entry flag bit 2, set only in the SDK's own store: the handle's
/// composition did not land in the `largeBlob` store (§17.8).
const FLAG_LARGE_BLOB_SKIPPED: u8 = 0b0000_0100;
/// The `StoreSetRecord` layout version (§17.8).
const STORE_SET_RECORD_VERSION: u8 = 0x01;
/// The `StoreSetRecord` bytes before the credential identifier: version,
/// `largeBlob` byte and the 2-byte length (§17.8).
const STORE_SET_RECORD_HEADER_BYTES: usize = 4;

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

    /// The phase's rank in the merge: `Composed` 0, `Signed` 1,
    /// `PublishSent` 2, `Confirmed` 3, and `Discarded` and `Lost` 4. A merge
    /// never moves a stored phase to a lower rank.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Composed => 0,
            Self::Signed => 1,
            Self::PublishSent => 2,
            Self::Confirmed => 3,
            Self::Discarded | Self::Lost => 4,
        }
    }

    /// Whether a handle at this phase still blocks a reveal: `Composed`
    /// through `Confirmed`.
    #[must_use]
    pub const fn is_pending(self) -> bool {
        self.rank() <= 3
    }

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

/// Which continuation a reveal-authorized event carries: the
/// [`RecoveryHandle`] variant without its fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RevealKind {
    /// The event fixes the next commitment.
    FixesCommitment,
    /// The event declares abandonment.
    Abandons,
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

    /// Builds the handle of `kind` for `identifier` at `phase`.
    #[must_use]
    pub const fn new(
        kind: RevealKind,
        identifier: Identifier,
        phase: RecoveryPhase,
        event_digest: [u8; 32],
    ) -> Self {
        match kind {
            RevealKind::FixesCommitment => Self::FixesCommitment {
                identifier,
                phase,
                event_digest,
            },
            RevealKind::Abandons => Self::Abandons {
                identifier,
                phase,
                event_digest,
            },
        }
    }

    /// The handle's continuation.
    #[must_use]
    pub const fn kind(&self) -> RevealKind {
        match self {
            Self::FixesCommitment { .. } => RevealKind::FixesCommitment,
            Self::Abandons { .. } => RevealKind::Abandons,
        }
    }

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
        Self::new(self.kind(), self.identifier(), phase, self.event_digest())
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

    /// The key of the credential's entry in a member,
    /// `recovery/{sha256_hex(credential_id)}/entry`
    /// (`17-persistence-and-storage.md` §17.3).
    #[must_use]
    pub fn entry_key(&self) -> String {
        format!("{}/entry", self.storage_prefix())
    }

    /// The key of the credential's [`StoreSetRecord`] in the
    /// platform-account member, `recovery/{sha256_hex(credential_id)}/record`
    /// (`17-persistence-and-storage.md` §17.8).
    #[must_use]
    pub fn record_key(&self) -> String {
        format!("{}/record", self.storage_prefix())
    }

    /// The key of the signed event whose preimage digest is `event_digest`,
    /// `recovery/{sha256_hex(credential_id)}/event/{hex(event_digest)}`
    /// (`17-persistence-and-storage.md` §17.3).
    #[must_use]
    pub fn event_key(&self, event_digest: &[u8; 32]) -> String {
        format!(
            "{}/event/{}",
            self.storage_prefix(),
            hex_lower(event_digest)
        )
    }

    /// `recovery/{sha256_hex(credential_id)}`: SHA-256 of the identifier as
    /// 64 lowercase hex characters, so an identifier of any permitted length
    /// yields a fixed-length key component.
    fn storage_prefix(&self) -> String {
        format!("recovery/{}", hex_lower(&Sha256::digest(&self.0)))
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
/// §9.7.4.2 R10, the `platform-account-member` host table).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PlatformAccountAbsence {
    /// The credential syncs through a store no data API of the host reaches.
    NoDataApiToCredentialSyncStore,
    /// The host holds no platform credential.
    NoPlatformCredential,
}

/// The `largeBlob` entry of a [`StoreSetRecord`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LargeBlobMembership {
    /// The credential's `largeBlob` store is a member.
    Member,
    /// The credential's `largeBlob` store is not a member.
    NotMember,
}

/// Whether the credential's `largeBlob` store is a member (§17.8).
///
/// It is written into the platform-account member at credential creation
/// where that member exists (`17-persistence-and-storage.md` §17.8). No other
/// store holds it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StoreSetRecord {
    /// The pre-rotation credential the record is keyed on.
    pub credential_id: CredentialId,
    /// Whether the `largeBlob` store is a member.
    pub large_blob: LargeBlobMembership,
}

/// One member's entry (§17.8): an optional handle, an optional marker, and,
/// in the SDK's own store only, the bit that says the handle's composition
/// did not land in the `largeBlob` store.
///
/// The skip bit exists only beside a handle: every constructor that sets it
/// takes the handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StoreEntry {
    handle: Option<RecoveryHandle>,
    marker: Option<LastRevealMarker>,
    large_blob_skipped: bool,
}

impl StoreEntry {
    /// The entry holding neither value, encoded as the one byte `0x00`.
    pub const EMPTY: Self = Self {
        handle: None,
        marker: None,
        large_blob_skipped: false,
    };

    /// An entry holding `handle` and `marker`, with the skip bit clear.
    #[must_use]
    pub const fn new(handle: Option<RecoveryHandle>, marker: Option<LastRevealMarker>) -> Self {
        Self {
            handle,
            marker,
            large_blob_skipped: false,
        }
    }

    /// An entry of the SDK's own store holding `handle` whose composition
    /// did not land in the `largeBlob` store.
    #[must_use]
    pub const fn large_blob_skipped(
        handle: RecoveryHandle,
        marker: Option<LastRevealMarker>,
    ) -> Self {
        Self {
            handle: Some(handle),
            marker,
            large_blob_skipped: true,
        }
    }

    /// The pending handle, where the entry holds one.
    #[must_use]
    pub const fn handle(&self) -> Option<RecoveryHandle> {
        self.handle
    }

    /// The last-reveal marker, where the entry holds one.
    #[must_use]
    pub const fn marker(&self) -> Option<LastRevealMarker> {
        self.marker
    }

    /// Whether the handle's composition did not land in the `largeBlob`
    /// store. Only the SDK's own store carries it.
    #[must_use]
    pub const fn is_large_blob_skipped(&self) -> bool {
        self.large_blob_skipped
    }

    /// Whether the entry holds neither a handle nor a marker.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.handle.is_none() && self.marker.is_none()
    }

    /// Whether the entry's handle names `event_digest`.
    fn holds(&self, event_digest: &[u8; 32]) -> bool {
        self.handle
            .is_some_and(|handle| handle.event_digest() == *event_digest)
    }

    /// The same entry with the skip bit clear.
    const fn without_skip(self) -> Self {
        Self::new(self.handle, self.marker)
    }
}

/// Which store an entry's bytes came from, which decides whether bit 2 may
/// be set (§17.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EntrySource {
    /// The SDK's own local store, the one store that carries bit 2.
    SdkLocal,
    /// The platform-account member or a `largeBlob` store.
    Synced,
}

// ---------------------------------------------------------------------------
// Reads, errors and reports
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
    /// This device has no handle on a member the set has.
    NoStoreOnDevice,
    /// The platform-account member holds no store-set record: the device is
    /// signed into another account, has not synced, or the credential was
    /// never created there.
    HoldsNoRecord,
    /// The member's entry names another identity's handle or marker.
    ForeignIdentity,
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
    /// An entry sets one of flag bits 3 to 7.
    #[error("entry flags {0:#04x} set a reserved bit")]
    UnknownFlags(u8),
    /// An entry sets bit 2 without bit 0.
    #[error("entry flags {0:#04x} set the largeBlob skip bit without a handle")]
    SkipWithoutHandle(u8),
    /// An entry read from a synced member sets bit 2, which only the SDK's
    /// own store carries.
    #[error("a synced member's entry sets the largeBlob skip bit")]
    SkipInSyncedMember,
    /// A `StoreSetRecord` names an unknown layout version.
    #[error("unknown store-set record version {0:#04x}")]
    UnknownVersion(u8),
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

/// A refusal or stop over the store set (`09-security-model.md` §9.7.4.2
/// R10).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryStoreError {
    /// The SDK did not reach a member of the set. The SDK maps this to
    /// `IdentityError::StorePartiallyUnreadable` (SCP-IDENT-1108).
    #[error("store set partially unreadable: {store:?} not reached ({cause:?})")]
    StorePartiallyUnreadable {
        /// The member not reached.
        store: CredentialStore,
        /// Why it was not reached.
        cause: NotReachedCause,
    },
    /// Creation found a record naming another credential under the
    /// credential's key; the record is written once.
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
    /// A store holds a pending handle, or the composition's own digest, so
    /// the SDK composes no reveal (R10, one reveal at a time).
    #[error("a reveal is already pending for the identity")]
    RevealAlreadyPending,
    /// A member holds another ceremony's pending handle, which this
    /// transition never replaces.
    #[error("a member holds another ceremony's pending handle")]
    ForeignHandle,
    /// The stores' last-reveal markers differ from the marker the ceremony
    /// read (R10, the last-reveal rule).
    #[error("the last-reveal marker moved since the ceremony read it")]
    MarkerMoved,
    /// The ceremony's handle is gone from a store that held it, is at
    /// `Discarded` or `Lost`, or sits beside another pending handle (R10's
    /// re-read).
    #[error("the ceremony's handle is gone, terminal, or beside another pending handle")]
    HandleGone,
    /// An abort found the handle past `Composed` or the signed event in a
    /// store (R10, Abort).
    #[error("a signed reveal exists and is unpublished")]
    SignedRevealUnpublished,
    /// The removal basis does not permit removing the handle at its phase.
    #[error("the handle's phase does not permit this removal")]
    PhaseNotRemovable,
    /// Another writer on this device holds the credential's store set.
    #[error("another writer holds the credential's store set")]
    SetInUse,
    /// A write to the platform-account member failed. The member stays in
    /// the set and the ceremony stops.
    #[error("platform-account write failed: {cause}")]
    PlatformAccountWriteFailed {
        /// The cause the platform reported.
        cause: String,
    },
    /// A `largeBlob` write that stops the ceremony did not land (R10).
    #[error("largeBlob write did not land and stops the ceremony ({clears_by:?})")]
    LargeBlobStopped {
        /// The cause where the platform reports one.
        cause: Option<String>,
        /// The act that clears the condition.
        clears_by: LargeBlobClearingAct,
    },
    /// A write to the SDK's local store failed.
    #[error("SDK local store write failed: {cause}")]
    SdkLocalWriteFailed {
        /// The cause the store reported.
        cause: String,
    },
}

/// What a transition did at the platform-account member, the SDK's local
/// store, or the record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemberWrite {
    /// The host has no platform-account member, so there is nothing to write.
    NotInSet,
    /// The merge changed nothing, so no write was made.
    Unchanged,
    /// The write was made and read back equal.
    Written,
    /// The write failed, or read back different.
    Failed {
        /// The cause the store reported.
        cause: String,
    },
    /// An earlier stop ended the transition before this write.
    NotAttempted,
}

/// What a transition did at the `largeBlob` store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LargeBlobWrite {
    /// This device holds no `largeBlob` handle.
    NoStore,
    /// The store was not read, so it was not written: a host with the
    /// platform-account member records it as not a member and the read
    /// failed.
    Unread {
        /// Why the read failed.
        cause: NotReachedCause,
    },
    /// The merge changed nothing, so no write was made.
    Unchanged,
    /// The write landed.
    Landed,
    /// The write did not land.
    NotLanded {
        /// The cause where the platform reports one.
        cause: Option<String>,
        /// The act that clears the condition.
        clears_by: LargeBlobClearingAct,
    },
    /// An earlier stop ended the transition before this write.
    NotAttempted,
}

/// What [`StoreSet::compose`], [`StoreSet::hold`] or [`StoreSet::advance`]
/// did at each store. A `largeBlob` write that did not land is surfaced here
/// even where it does not stop the ceremony.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct WriteReport {
    /// The platform-account member.
    pub platform_account: MemberWrite,
    /// The `largeBlob` store.
    pub large_blob: LargeBlobWrite,
    /// The SDK's local store.
    pub sdk_local: MemberWrite,
    /// The platform-account record, where the `largeBlob` membership changed.
    pub record: MemberWrite,
    stop: Option<RecoveryStoreError>,
}

impl WriteReport {
    /// Whether the transition completed.
    ///
    /// # Errors
    ///
    /// The stop that ended it: [`RecoveryStoreError::PlatformAccountWriteFailed`],
    /// [`RecoveryStoreError::LargeBlobStopped`] or
    /// [`RecoveryStoreError::SdkLocalWriteFailed`].
    pub fn completed(&self) -> Result<(), RecoveryStoreError> {
        self.stop.clone().map_or(Ok(()), Err)
    }
}

/// Why one member did not take a removal or a marker write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemovalCause {
    /// The `largeBlob` write did not land.
    NotLanded {
        /// The cause where the platform reports one.
        cause: Option<String>,
        /// The act that clears the condition.
        clears_by: LargeBlobClearingAct,
    },
    /// The write failed, or read back different.
    Failed {
        /// The cause the store reported.
        cause: String,
    },
    /// The member's handle is at a phase the removal basis does not remove.
    PhaseNotRemovable,
    /// The `largeBlob` store was not read, so it was not written.
    Unread(NotReachedCause),
}

/// One member's outcome of [`StoreSet::remove`] or [`StoreSet::complete`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberRemoval {
    /// The member.
    pub store: CredentialStore,
    /// Why the member did not take the write, or `None` where it did or
    /// already held the result.
    pub cause: Option<RemovalCause>,
}

impl MemberRemoval {
    /// Whether the member holds the result.
    #[must_use]
    pub const fn removed(&self) -> bool {
        self.cause.is_none()
    }
}

/// What [`StoreSet::remove`] or [`StoreSet::complete`] did. Both try every
/// member, so no failure stops them.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct RemovalReport {
    /// One outcome per member the device reaches, in write order.
    pub per_store: Vec<MemberRemoval>,
    /// The platform-account record, where the `largeBlob` membership changed.
    pub record: MemberWrite,
}

/// What every store a device reaches held, read in one pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetRead {
    per_store: Vec<StoreRead>,
    handles: Vec<RecoveryHandle>,
    max_markers: Vec<LastRevealMarker>,
}

impl SetRead {
    /// Every pending handle: each digest at its merged phase where that
    /// phase is `Composed` to `Confirmed` and no store's marker names it.
    /// Empty only where every store answered and none holds a pending handle.
    #[must_use]
    pub fn pending(&self) -> Vec<RecoveryHandle> {
        self.handles
            .iter()
            .filter(|handle| {
                handle.phase().is_pending()
                    && !self
                        .max_markers_all()
                        .any(|marker| marker.event_digest == handle.event_digest())
            })
            .copied()
            .collect()
    }

    /// Every digest any store holds a handle for, each at its merged phase:
    /// the highest-ranked phase any store holds.
    #[must_use]
    pub fn handles(&self) -> &[RecoveryHandle] {
        &self.handles
    }

    /// The distinct markers of the highest sequence any store holds: the
    /// marker a ceremony passes as its basis. Empty only where no store
    /// holds a marker. Two entries mean two markers of one sequence, which
    /// R10's last-reveal rule resolves and [`StoreSet::complete`] converges.
    #[must_use]
    pub fn max_markers(&self) -> &[LastRevealMarker] {
        &self.max_markers
    }

    /// Each store's own entry, in the order platform account, `largeBlob`,
    /// local.
    #[must_use]
    pub fn per_store(&self) -> &[StoreRead] {
        &self.per_store
    }

    fn max_markers_all(&self) -> impl Iterator<Item = &LastRevealMarker> {
        self.per_store
            .iter()
            .filter_map(|read| read.entry.marker.as_ref())
    }
}

/// What one store held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreRead {
    /// The store.
    pub store: CredentialStore,
    /// Its entry; [`StoreEntry::EMPTY`] where it holds none.
    pub entry: StoreEntry,
    /// Whether the store is a member: always for the local store and the
    /// platform-account member; for `largeBlob`, where the record names it
    /// or, on a host without a record, where it holds a handle or a marker.
    pub member: bool,
}

/// Where a ceremony's handle moves (`09-security-model.md` §9.7.4.2 R10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdvanceTarget {
    /// The custody signed the event.
    Signed,
    /// The SDK sent the publish.
    PublishSent,
    /// The publish was confirmed.
    Confirmed,
    /// The confirm check found an illegality failure.
    Discarded,
    /// The device adopted a chain R6 ranks above the event's chain.
    Lost,
}

impl AdvanceTarget {
    /// The phase the handle moves to.
    #[must_use]
    pub const fn phase(self) -> RecoveryPhase {
        match self {
            Self::Signed => RecoveryPhase::Signed,
            Self::PublishSent => RecoveryPhase::PublishSent,
            Self::Confirmed => RecoveryPhase::Confirmed,
            Self::Discarded => RecoveryPhase::Discarded,
            Self::Lost => RecoveryPhase::Lost,
        }
    }
}

/// Why a handle is removed (`09-security-model.md` §9.7.4.2 R10, Abort).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RemovalBasis {
    /// `abort_recovery` at `Composed`.
    AbortAtComposed,
    /// The handle is at `Discarded` or `Lost`.
    Terminal,
    /// The device's adopted log carries the event the handle names.
    Adopted,
    /// The controller declared the composing device destroyed.
    Destroyed,
}

/// A cosigner's authority to write a composer's `Composed` handle.
///
/// It is bound to the event's digest (`09-security-model.md` §9.7.4.2 R10,
/// the cosigner clause). The ceremony layer builds it from the cosigner
/// record it persisted for that digest before it signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CosignHold {
    kind: RevealKind,
    event_digest: [u8; 32],
}

impl CosignHold {
    /// The hold for the event of `kind` whose preimage digest is
    /// `event_digest`, as the cosigner record names it.
    #[must_use]
    pub const fn from_cosigner_record(kind: RevealKind, event_digest: [u8; 32]) -> Self {
        Self { kind, event_digest }
    }
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

    /// Reads the member's entry. An absent value and the one byte `0x00`
    /// both read as [`MemberRead::ReachedEmpty`].
    fn read_entry(&self) -> impl Future<Output = MemberRead<StoreEntry>> + MaybeSend;

    /// Replaces the member's entry with `entry`.
    fn write_entry(
        &self,
        entry: &StoreEntry,
    ) -> impl Future<Output = Result<(), Self::WriteFailure>> + MaybeSend;
}

/// A member that also holds signed events: the SDK's local store and the
/// platform-account member (`17-persistence-and-storage.md` §17.8). A
/// `largeBlob` store holds none.
pub trait RecoveryEventStore: RecoveryHandleStore {
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

/// The platform-account member, which alone holds the [`StoreSetRecord`].
pub trait RecoveryRecordStore: RecoveryEventStore {
    /// Reads the credential's store-set record.
    fn read_record(&self) -> impl Future<Output = MemberRead<StoreSetRecord>> + MaybeSend;

    /// Replaces the credential's store-set record.
    fn write_record(
        &self,
        record: &StoreSetRecord,
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

/// The one-writer lease on a credential's store set on this device.
///
/// It is keyed on `(credential_id, identifier)`. A [`StoreSet`] takes its
/// credential and identity from the lease, so the two cannot disagree, and
/// holds the lease for its whole life.
pub trait SetLease {
    /// The pre-rotation credential the set is keyed on.
    fn credential_id(&self) -> &CredentialId;

    /// The identity whose handles and markers the set holds.
    fn identifier(&self) -> Identifier;
}

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

impl RecoveryEventStore for NoPlatformAccount {
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

impl RecoveryRecordStore for NoPlatformAccount {
    async fn read_record(&self) -> MemberRead<StoreSetRecord> {
        match self.0 {}
    }

    async fn write_record(&self, _record: &StoreSetRecord) -> Result<(), StoreWriteFailure> {
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
// Membership
// ---------------------------------------------------------------------------

/// The platform-account member as this device holds it, per the host table
/// of `09-security-model.md` §9.7.4.2 R10.
#[derive(Debug)]
pub enum PlatformAccountSlot<P> {
    /// The host's row gives the member and this device holds a handle on it.
    Present(P),
    /// The host's row gives the member and this device holds no handle on
    /// it, so every operation refuses.
    PresentWithoutHandle,
    /// The host's row gives no member, for the given reason.
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

/// What the `largeBlob` store gave the step-3 read.
#[derive(Clone, Debug, PartialEq, Eq)]
enum BlobRead {
    /// This device holds no `largeBlob` handle.
    NoHandle,
    /// A host with the platform-account member records the store as not a
    /// member, and the read failed.
    Unread(NotReachedCause),
    /// The store answered.
    Read(StoreEntry),
}

/// Step 2 and step 3 of an operation: the record, where the host has one,
/// and every store's entry.
#[derive(Clone, Debug)]
struct Snapshot {
    /// `Some` on a host whose row gives the platform-account member.
    record: Option<StoreSetRecord>,
    /// `Some` on a host whose row gives the platform-account member.
    platform: Option<StoreEntry>,
    blob: BlobRead,
    local: StoreEntry,
}

impl Snapshot {
    /// Every entry read, in the order platform account, `largeBlob`, local.
    fn entries(&self) -> impl Iterator<Item = &StoreEntry> {
        let blob = match &self.blob {
            BlobRead::Read(entry) => Some(entry),
            BlobRead::NoHandle | BlobRead::Unread(_) => None,
        };
        self.platform
            .iter()
            .chain(blob)
            .chain(std::iter::once(&self.local))
    }

    /// The highest-ranked phase any store holds for `event_digest`. At a tie
    /// of rank 4 the higher phase byte is reported.
    fn merged_phase(&self, event_digest: &[u8; 32]) -> Option<RecoveryPhase> {
        self.entries()
            .filter_map(|entry| entry.handle)
            .filter(|handle| handle.event_digest() == *event_digest)
            .map(|handle| handle.phase())
            .max_by_key(|phase| (phase.rank(), phase.to_byte()))
    }

    /// Whether any store's marker names `event_digest`.
    fn marker_names(&self, event_digest: &[u8; 32]) -> bool {
        self.entries()
            .filter_map(|entry| entry.marker)
            .any(|marker| marker.event_digest == *event_digest)
    }

    /// Whether `event_digest` is live: its merged phase is `Composed` to
    /// `Confirmed` and no store's marker names it.
    fn is_live(&self, event_digest: &[u8; 32]) -> bool {
        self.merged_phase(event_digest)
            .is_some_and(RecoveryPhase::is_pending)
            && !self.marker_names(event_digest)
    }

    /// Whether any store holds a live handle.
    fn any_live(&self) -> bool {
        self.entries()
            .filter_map(|entry| entry.handle)
            .any(|handle| self.is_live(&handle.event_digest()))
    }

    /// Whether any store holds a handle naming `event_digest`.
    fn any_holds(&self, event_digest: &[u8; 32]) -> bool {
        self.entries().any(|entry| entry.holds(event_digest))
    }

    /// The distinct markers of the highest sequence any store holds.
    fn max_markers(&self) -> Vec<LastRevealMarker> {
        let markers: Vec<LastRevealMarker> =
            self.entries().filter_map(|entry| entry.marker).collect();
        let Some(top) = markers.iter().map(|marker| marker.sequence).max() else {
            return Vec::new();
        };
        let mut out: Vec<LastRevealMarker> = Vec::new();
        for marker in markers {
            if marker.sequence == top && !out.contains(&marker) {
                out.push(marker);
            }
        }
        out
    }

    /// Whether the stores' highest-sequence markers are exactly `basis`: one
    /// marker equal to it, or none where `basis` is `None`.
    fn basis_holds(&self, basis: Option<&LastRevealMarker>) -> bool {
        let top = self.max_markers();
        basis.map_or(top.is_empty(), |basis| {
            !top.is_empty() && top.iter().all(|marker| marker == basis)
        })
    }

    /// The ceremony's basis for `event_digest`: the marker the entry holding
    /// its handle carries, the local store's first. A composition writes its
    /// basis into every entry it writes.
    fn ceremony_basis(&self, event_digest: &[u8; 32]) -> Option<LastRevealMarker> {
        if self.local.holds(event_digest) {
            return self.local.marker;
        }
        self.entries()
            .find(|entry| entry.holds(event_digest))
            .and_then(|entry| entry.marker)
    }

    /// Whether the `largeBlob` store is a member.
    fn blob_is_member(&self) -> bool {
        match (&self.record, &self.blob) {
            (Some(record), _) => record.large_blob == LargeBlobMembership::Member,
            (None, BlobRead::Read(entry)) => !entry.is_empty(),
            (None, BlobRead::NoHandle | BlobRead::Unread(_)) => false,
        }
    }

    /// Whether the local entry holds `event_digest` with the skip bit set.
    fn local_skipped(&self, event_digest: &[u8; 32]) -> bool {
        self.local.holds(event_digest) && self.local.large_blob_skipped
    }

    /// The handle `event_digest` names, at its merged phase.
    fn merged_handle(&self, event_digest: &[u8; 32]) -> Option<RecoveryHandle> {
        let phase = self.merged_phase(event_digest)?;
        self.entries()
            .filter_map(|entry| entry.handle)
            .find(|handle| handle.event_digest() == *event_digest)
            .map(|handle| handle.with_phase(phase))
    }

    /// Every digest any store holds, each at its merged phase, in first-seen
    /// order.
    fn merged_handles(&self) -> Vec<RecoveryHandle> {
        let mut out: Vec<RecoveryHandle> = Vec::new();
        for handle in self.entries().filter_map(|entry| entry.handle) {
            let digest = handle.event_digest();
            if out.iter().all(|seen| seen.event_digest() != digest)
                && let Some(merged) = self.merged_handle(&digest)
            {
                out.push(merged);
            }
        }
        out
    }
}

/// The change one transition makes, as the pure merge reads it.
#[derive(Clone, Copy, Debug)]
enum Change {
    Compose {
        handle: RecoveryHandle,
        basis: Option<LastRevealMarker>,
    },
    Hold {
        handle: RecoveryHandle,
        basis: Option<LastRevealMarker>,
    },
    Advance {
        event_digest: [u8; 32],
        target: AdvanceTarget,
    },
    Complete {
        marker: LastRevealMarker,
    },
    Remove {
        event_digest: [u8; 32],
        basis: RemovalBasis,
    },
}

/// One member's merge: the entry to write, or `None` where the member
/// already holds the result.
type Merge = Option<StoreEntry>;

/// Whether a removal may take the handle from a member, judged at the
/// higher of the member's own rank and the merged rank.
const fn removable(basis: RemovalBasis, own: RecoveryPhase, merged: Option<RecoveryPhase>) -> bool {
    let effective = match merged {
        Some(merged) if merged.rank() > own.rank() => merged.rank(),
        _ => own.rank(),
    };
    match basis {
        RemovalBasis::AbortAtComposed => effective == 0,
        RemovalBasis::Terminal => effective == 4,
        RemovalBasis::Adopted | RemovalBasis::Destroyed => true,
    }
}

/// The merge of `change` into the entry `store` holds (§2.3 of the
/// redesign; `17-persistence-and-storage.md` §17.8, "How a member's entry is
/// written"). Every set-level precondition has passed before this runs.
fn merge(
    change: Change,
    store: CredentialStore,
    entry: &StoreEntry,
    snapshot: &Snapshot,
) -> Result<Merge, RecoveryStoreError> {
    let written = match change {
        Change::Compose { handle, basis } => Some(StoreEntry::new(Some(handle), basis)),
        Change::Hold { handle, basis } => match entry.handle {
            Some(held) if held.event_digest() == handle.event_digest() => None,
            Some(held) if snapshot.is_live(&held.event_digest()) => {
                return Err(RecoveryStoreError::ForeignHandle);
            }
            _ => Some(StoreEntry::new(Some(handle), basis)),
        },
        Change::Advance {
            event_digest,
            target,
        } => merge_advance(store, entry, snapshot, event_digest, target)?,
        Change::Complete { marker } => merge_complete(entry, marker)?,
        Change::Remove { event_digest, .. } => {
            if entry.holds(&event_digest) {
                Some(StoreEntry::new(None, entry.marker))
            } else {
                None
            }
        }
    };
    Ok(written.filter(|written| written != entry))
}

fn merge_advance(
    store: CredentialStore,
    entry: &StoreEntry,
    snapshot: &Snapshot,
    event_digest: [u8; 32],
    target: AdvanceTarget,
) -> Result<Merge, RecoveryStoreError> {
    let phase = target.phase();
    match entry.handle {
        Some(held) if held.event_digest() == event_digest => {
            if held.phase().rank() >= phase.rank() {
                Ok(None)
            } else {
                Ok(Some(StoreEntry {
                    handle: Some(held.with_phase(phase)),
                    ..*entry
                }))
            }
        }
        Some(held) if snapshot.is_live(&held.event_digest()) => {
            Err(RecoveryStoreError::ForeignHandle)
        }
        _ if !phase.is_pending() => Ok(None),
        _ => match store {
            // The SDK's own store of a device other than the composer never
            // held the handle, and no other device writes it, so its lack of
            // the handle says nothing about another device's abort.
            CredentialStore::SdkLocal => Ok(None),
            CredentialStore::PlatformAccount => Err(RecoveryStoreError::HandleGone),
            CredentialStore::LargeBlob => {
                let recorded_not_member = snapshot
                    .record
                    .as_ref()
                    .is_some_and(|record| record.large_blob == LargeBlobMembership::NotMember);
                if recorded_not_member {
                    return Ok(None);
                }
                if !snapshot.local_skipped(&event_digest) {
                    return Err(RecoveryStoreError::HandleGone);
                }
                // The composition never reached this store, so no other
                // device's abort can be undone here; the write is made only
                // where no other ceremony completed since this one read its
                // basis.
                let basis = snapshot.ceremony_basis(&event_digest);
                if !snapshot.basis_holds(basis.as_ref()) {
                    return Err(RecoveryStoreError::MarkerMoved);
                }
                let handle = snapshot
                    .merged_handle(&event_digest)
                    .ok_or(RecoveryStoreError::HandleGone)?
                    .with_phase(phase);
                Ok(Some(StoreEntry::new(Some(handle), entry.marker)))
            }
        },
    }
}

fn merge_complete(
    entry: &StoreEntry,
    marker: LastRevealMarker,
) -> Result<Merge, RecoveryStoreError> {
    let next_marker = match entry.marker {
        Some(held) if held == marker => held,
        Some(held) if held.sequence > marker.sequence => {
            return Err(RecoveryStoreError::MarkerMoved);
        }
        _ => marker,
    };
    let keeps_handle = !entry.holds(&marker.event_digest);
    Ok(Some(StoreEntry {
        handle: entry.handle.filter(|_| keeps_handle),
        marker: Some(next_marker),
        large_blob_skipped: entry.large_blob_skipped && keeps_handle,
    }))
}

/// The writes one transition plans, computed before the first write.
#[derive(Clone, Copy, Debug)]
struct Planned {
    platform: Merge,
    blob: Merge,
    local: Merge,
    /// Per-member removal refusals (`RemovalBasis` judged per member).
    platform_refused: bool,
    blob_refused: bool,
    local_refused: bool,
}

/// How a transition treats a write that fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Policy {
    /// `compose`: may set the skip bit, stops per R10.
    Compose,
    /// `hold`: stops per R10, never sets the skip bit.
    Hold,
    /// `advance`: stops at a `Composed → Signed` `largeBlob` write that
    /// does not land where the store held the handle.
    Advance {
        event_digest: [u8; 32],
        to_signed: bool,
    },
}

// ---------------------------------------------------------------------------
// The store set
// ---------------------------------------------------------------------------

/// A credential's store set: the members a device reaches, the host's row,
/// and the lease that makes this the device's one writer
/// (`09-security-model.md` §9.7.4.2 R10).
///
/// The set caches nothing: every operation reads the record, where the host
/// has one, and every store it reaches afresh.
#[derive(Debug)]
pub struct StoreSet<L, P, B, G> {
    members: StoreSetMembers<L, P, B>,
    lease: G,
}

impl<L, P, B, G> StoreSet<L, P, B, G>
where
    L: RecoveryEventStore<WriteFailure = StoreWriteFailure> + MaybeSync,
    P: RecoveryRecordStore<WriteFailure = StoreWriteFailure> + MaybeSync,
    B: RecoveryHandleStore<WriteFailure = LargeBlobNotLanded> + MaybeSync,
    G: SetLease + MaybeSync,
{
    /// Writes the credential's record at credential creation, where the
    /// host's row gives the platform-account member, and opens the set.
    /// Where that member holds a record naming the credential, it writes
    /// nothing; where the host has no such member, it writes nothing. The
    /// record starts at [`LargeBlobMembership::NotMember`], because only a
    /// landed write adds that store.
    ///
    /// # Errors
    ///
    /// - [`RecoveryStoreError::RecordAlreadyWritten`] where the member holds
    ///   a record naming another credential.
    /// - [`RecoveryStoreError::StorePartiallyUnreadable`] where the member
    ///   does not answer, or the device holds no handle on it.
    /// - [`RecoveryStoreError::PlatformAccountWriteFailed`] where the write
    ///   fails or reads back different.
    pub async fn create(
        members: StoreSetMembers<L, P, B>,
        lease: G,
    ) -> Result<Self, RecoveryStoreError> {
        let set = Self { members, lease };
        let platform = match &set.members.platform_account {
            PlatformAccountSlot::Absent(_) => return Ok(set),
            PlatformAccountSlot::PresentWithoutHandle => {
                return Err(unreadable(
                    CredentialStore::PlatformAccount,
                    NotReachedCause::NoStoreOnDevice,
                ));
            }
            PlatformAccountSlot::Present(platform) => platform,
        };
        match platform.read_record().await {
            MemberRead::Reached(existing) => {
                if existing.credential_id == *set.lease.credential_id() {
                    return Ok(set);
                }
                return Err(RecoveryStoreError::RecordAlreadyWritten);
            }
            MemberRead::NotReached(cause) => {
                return Err(unreadable(CredentialStore::PlatformAccount, cause));
            }
            MemberRead::ReachedEmpty => {}
        }
        let record = StoreSetRecord {
            credential_id: set.lease.credential_id().clone(),
            large_blob: LargeBlobMembership::NotMember,
        };
        write_record_checked(platform, &record)
            .await
            .map_err(|cause| RecoveryStoreError::PlatformAccountWriteFailed { cause })?;
        Ok(set)
    }

    /// Opens the credential's store set. It reads the record where the
    /// host's row gives the platform-account member, writes nothing, and
    /// keeps nothing it read: every later operation reads afresh.
    ///
    /// # Errors
    ///
    /// Every refusal [`Self::read_set`]'s membership step returns:
    /// [`RecoveryStoreError::StorePartiallyUnreadable`] with
    /// [`NotReachedCause::HoldsNoRecord`], [`NotReachedCause::NoStoreOnDevice`]
    /// or the member's own cause, and
    /// [`RecoveryStoreError::RecordCredentialMismatch`].
    pub async fn open(
        members: StoreSetMembers<L, P, B>,
        lease: G,
    ) -> Result<Self, RecoveryStoreError> {
        let set = Self { members, lease };
        set.resolve_record().await?;
        Ok(set)
    }

    /// Reads every store the device reaches.
    ///
    /// # Errors
    ///
    /// [`RecoveryStoreError::StorePartiallyUnreadable`] where a member is
    /// not reached, including bytes that do not decode and an entry naming
    /// another identity, and [`RecoveryStoreError::RecordCredentialMismatch`].
    /// A partial read is indistinguishable from an empty one, so no entry is
    /// returned.
    pub async fn read_set(&self) -> Result<SetRead, RecoveryStoreError> {
        let snapshot = self.snapshot().await?;
        let mut per_store = Vec::with_capacity(3);
        if let Some(entry) = snapshot.platform {
            per_store.push(StoreRead {
                store: CredentialStore::PlatformAccount,
                entry,
                member: true,
            });
        }
        if let BlobRead::Read(entry) = snapshot.blob {
            per_store.push(StoreRead {
                store: CredentialStore::LargeBlob,
                entry,
                member: snapshot.blob_is_member(),
            });
        }
        per_store.push(StoreRead {
            store: CredentialStore::SdkLocal,
            entry: snapshot.local,
            member: true,
        });
        Ok(SetRead {
            per_store,
            handles: snapshot.merged_handles(),
            max_markers: snapshot.max_markers(),
        })
    }

    /// The re-read before signing and before publishing (R10): confirms that
    /// `event_digest` is the one pending handle, at `Composed` to
    /// `Confirmed`, held by every member that must hold it, and that no
    /// other ceremony completed since this one read its basis. Returns the
    /// handle at its merged phase.
    ///
    /// # Errors
    ///
    /// - [`RecoveryStoreError::HandleGone`] where the handle is gone from a
    ///   member, is at `Discarded` or `Lost`, a marker names it, or another
    ///   handle is pending.
    /// - [`RecoveryStoreError::MarkerMoved`] where the stores'
    ///   highest-sequence markers differ from the ceremony's basis.
    /// - Every refusal of [`Self::read_set`].
    pub async fn confirm_pending(
        &self,
        event_digest: &[u8; 32],
    ) -> Result<RecoveryHandle, RecoveryStoreError> {
        let snapshot = self.snapshot().await?;
        if !snapshot.is_live(event_digest) {
            return Err(RecoveryStoreError::HandleGone);
        }
        let other_live = snapshot
            .entries()
            .filter_map(|entry| entry.handle)
            .any(|handle| {
                handle.event_digest() != *event_digest && snapshot.is_live(&handle.event_digest())
            });
        if other_live {
            return Err(RecoveryStoreError::HandleGone);
        }
        let basis = snapshot.ceremony_basis(event_digest);
        if !snapshot.basis_holds(basis.as_ref()) {
            return Err(RecoveryStoreError::MarkerMoved);
        }
        if snapshot
            .platform
            .is_some_and(|entry| !entry.holds(event_digest))
        {
            return Err(RecoveryStoreError::HandleGone);
        }
        if let BlobRead::Read(entry) = &snapshot.blob {
            // The store must hold the handle where it is a member, or where
            // this device's composition landed there (skip bit clear): an
            // empty store then means another device removed it.
            let composed_here = snapshot.local.holds(event_digest)
                && !snapshot.local.large_blob_skipped
                && snapshot.record.is_none();
            if (snapshot.blob_is_member() || composed_here) && !entry.holds(event_digest) {
                return Err(RecoveryStoreError::HandleGone);
            }
        }
        snapshot
            .merged_handle(event_digest)
            .ok_or(RecoveryStoreError::HandleGone)
    }

    /// Writes the `Composed` handle of a new ceremony into every store, once
    /// per digest. `basis` is the highest-sequence marker the ceremony ran
    /// R10's last-reveal and consumed-commitment rules against, and is
    /// written into every entry beside the handle.
    ///
    /// # Errors
    ///
    /// Refusals, before any write:
    /// - [`RecoveryStoreError::MarkerMoved`] where the stores'
    ///   highest-sequence markers are not exactly `basis`;
    /// - [`RecoveryStoreError::RevealAlreadyPending`] where any store holds
    ///   a pending handle or any handle naming `event_digest`;
    /// - every refusal of [`Self::read_set`].
    ///
    /// A stop after a write is in the report's [`WriteReport::completed`].
    pub async fn compose(
        &mut self,
        kind: RevealKind,
        event_digest: [u8; 32],
        basis: Option<LastRevealMarker>,
    ) -> Result<WriteReport, RecoveryStoreError> {
        let snapshot = self.snapshot().await?;
        if !snapshot.basis_holds(basis.as_ref()) {
            return Err(RecoveryStoreError::MarkerMoved);
        }
        if snapshot.any_live() || snapshot.any_holds(&event_digest) {
            return Err(RecoveryStoreError::RevealAlreadyPending);
        }
        let handle = RecoveryHandle::new(
            kind,
            self.lease.identifier(),
            RecoveryPhase::Composed,
            event_digest,
        );
        let planned = plan(&snapshot, Change::Compose { handle, basis })?;
        Ok(self
            .execute_report(&snapshot, &planned, Policy::Compose)
            .await)
    }

    /// A cosigner's write of the composer's `Composed` handle into its own
    /// store set before it signs (R10, the cosigner clause). A member that
    /// holds the digest at any phase keeps it.
    ///
    /// # Errors
    ///
    /// Refusals, before any write:
    /// - [`RecoveryStoreError::MarkerMoved`] as for [`Self::compose`];
    /// - [`RecoveryStoreError::ForeignHandle`] where a member holds another
    ///   pending handle;
    /// - every refusal of [`Self::read_set`].
    pub async fn hold(
        &mut self,
        token: CosignHold,
        basis: Option<LastRevealMarker>,
    ) -> Result<WriteReport, RecoveryStoreError> {
        let snapshot = self.snapshot().await?;
        if !snapshot.basis_holds(basis.as_ref()) {
            return Err(RecoveryStoreError::MarkerMoved);
        }
        let handle = RecoveryHandle::new(
            token.kind,
            self.lease.identifier(),
            RecoveryPhase::Composed,
            token.event_digest,
        );
        let planned = plan(&snapshot, Change::Hold { handle, basis })?;
        Ok(self.execute_report(&snapshot, &planned, Policy::Hold).await)
    }

    /// Moves the handle naming `event_digest` to `target` in every store. A
    /// phase never moves to a lower rank, so a retry changes nothing.
    ///
    /// # Errors
    ///
    /// Refusals, before any write:
    /// - [`RecoveryStoreError::HandleGone`] where no store holds the handle,
    ///   or a store that must hold it does not, for a target from `Signed`
    ///   to `Confirmed`;
    /// - [`RecoveryStoreError::ForeignHandle`] where a member holds another
    ///   pending handle;
    /// - [`RecoveryStoreError::MarkerMoved`] where a `largeBlob` store the
    ///   composition skipped would take the handle and another ceremony
    ///   completed since this one read its basis;
    /// - every refusal of [`Self::read_set`].
    pub async fn advance(
        &mut self,
        event_digest: [u8; 32],
        target: AdvanceTarget,
    ) -> Result<WriteReport, RecoveryStoreError> {
        let snapshot = self.snapshot().await?;
        if target.phase().is_pending() && !snapshot.any_holds(&event_digest) {
            return Err(RecoveryStoreError::HandleGone);
        }
        let planned = plan(
            &snapshot,
            Change::Advance {
                event_digest,
                target,
            },
        )?;
        let to_signed = target == AdvanceTarget::Signed;
        Ok(self
            .execute_report(
                &snapshot,
                &planned,
                Policy::Advance {
                    event_digest,
                    to_signed,
                },
            )
            .await)
    }

    /// Writes the last-reveal marker of the completed ceremony whose event
    /// has `sequence` and `event_digest`, and drops the handle naming that
    /// digest. A marker is replaced only by one of equal or higher sequence;
    /// a handle naming another digest is kept. Every member is tried.
    ///
    /// # Errors
    ///
    /// Refusals, before any write:
    /// - [`RecoveryStoreError::MarkerMoved`] where a store holds a marker of
    ///   higher sequence;
    /// - every refusal of [`Self::read_set`].
    pub async fn complete(
        &mut self,
        sequence: u64,
        event_digest: [u8; 32],
    ) -> Result<RemovalReport, RecoveryStoreError> {
        let snapshot = self.snapshot().await?;
        let marker = LastRevealMarker {
            identifier: self.lease.identifier(),
            sequence,
            event_digest,
        };
        let planned = plan(&snapshot, Change::Complete { marker })?;
        Ok(self.execute_removal(&snapshot, &planned).await)
    }

    /// Removes the handle naming `event_digest` from every member, keeping
    /// each member's marker. Every member is tried; a member that holds no
    /// such handle reports it removed.
    ///
    /// # Errors
    ///
    /// Refusals, before any write:
    /// - [`RecoveryStoreError::SignedRevealUnpublished`] for
    ///   [`RemovalBasis::AbortAtComposed`] where the merged phase is
    ///   `Signed` to `Confirmed` or a store holds the signed event;
    /// - [`RecoveryStoreError::PhaseNotRemovable`] for
    ///   [`RemovalBasis::AbortAtComposed`] at `Discarded` or `Lost`, and for
    ///   [`RemovalBasis::Terminal`] below them;
    /// - every refusal of [`Self::read_set`] and [`Self::read_event`].
    pub async fn remove(
        &mut self,
        event_digest: [u8; 32],
        basis: RemovalBasis,
    ) -> Result<RemovalReport, RecoveryStoreError> {
        let snapshot = self.snapshot().await?;
        let merged = snapshot.merged_phase(&event_digest);
        match (basis, merged) {
            (_, None) | (RemovalBasis::Adopted | RemovalBasis::Destroyed, _) => {}
            (RemovalBasis::AbortAtComposed, Some(phase)) => match phase.rank() {
                0 => {
                    if self.read_event(&event_digest).await?.is_some() {
                        return Err(RecoveryStoreError::SignedRevealUnpublished);
                    }
                }
                4 => return Err(RecoveryStoreError::PhaseNotRemovable),
                _ => return Err(RecoveryStoreError::SignedRevealUnpublished),
            },
            (RemovalBasis::Terminal, Some(phase)) => {
                if phase.rank() != 4 {
                    return Err(RecoveryStoreError::PhaseNotRemovable);
                }
            }
        }
        let planned = plan(
            &snapshot,
            Change::Remove {
                event_digest,
                basis,
            },
        )?;
        Ok(self.execute_removal(&snapshot, &planned).await)
    }

    /// Stores a signed event under `event_digest` in the platform-account
    /// member, where the host has one, then in the local store. A
    /// `largeBlob` store never holds an event. Each write is read back.
    ///
    /// # Errors
    ///
    /// - [`RecoveryStoreError::EventLength`] where `event` is empty or
    ///   exceeds `MAX_EVENT_BYTES`.
    /// - The membership refusals of [`Self::open`].
    /// - [`RecoveryStoreError::PlatformAccountWriteFailed`] and
    ///   [`RecoveryStoreError::SdkLocalWriteFailed`] where a write fails.
    pub async fn write_event(
        &self,
        event_digest: &[u8; 32],
        event: &[u8],
    ) -> Result<(), RecoveryStoreError> {
        check_event_length(event)
            .map_err(|_| RecoveryStoreError::EventLength { len: event.len() })?;
        if let Some((platform, _)) = self.resolve_record().await? {
            write_event_checked(platform, event_digest, event)
                .await
                .map_err(|cause| RecoveryStoreError::PlatformAccountWriteFailed { cause })?;
        }
        write_event_checked(&self.members.sdk_local, event_digest, event)
            .await
            .map_err(|cause| RecoveryStoreError::SdkLocalWriteFailed { cause })
    }

    /// Reads the signed event keyed on `event_digest` from the local store,
    /// or from the platform-account member, after the membership step.
    /// `Ok(None)` means every store answered and none holds the event.
    ///
    /// # Errors
    ///
    /// The membership refusals of [`Self::open`], and
    /// [`RecoveryStoreError::StorePartiallyUnreadable`] where no store
    /// returned the event and a store that might hold it was not reached.
    pub async fn read_event(
        &self,
        event_digest: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, RecoveryStoreError> {
        let platform = self.resolve_record().await?.map(|(platform, _)| platform);
        let local_miss = match self.members.sdk_local.read_event(event_digest).await {
            MemberRead::Reached(event) => return Ok(Some(event)),
            MemberRead::ReachedEmpty => None,
            MemberRead::NotReached(cause) => Some(unreadable(CredentialStore::SdkLocal, cause)),
        };
        let platform_miss = match platform {
            Some(platform) => match platform.read_event(event_digest).await {
                MemberRead::Reached(event) => return Ok(Some(event)),
                MemberRead::ReachedEmpty => None,
                MemberRead::NotReached(cause) => {
                    Some(unreadable(CredentialStore::PlatformAccount, cause))
                }
            },
            None => None,
        };
        local_miss.or(platform_miss).map_or(Ok(None), Err)
    }

    // -----------------------------------------------------------------------
    // Steps 2 and 3
    // -----------------------------------------------------------------------

    /// Step 2: the platform-account member and its record, where the host's
    /// row gives one; `None` on a host without it.
    async fn resolve_record(&self) -> Result<Option<(&P, StoreSetRecord)>, RecoveryStoreError> {
        let platform = match &self.members.platform_account {
            PlatformAccountSlot::Absent(_) => return Ok(None),
            PlatformAccountSlot::PresentWithoutHandle => {
                return Err(unreadable(
                    CredentialStore::PlatformAccount,
                    NotReachedCause::NoStoreOnDevice,
                ));
            }
            PlatformAccountSlot::Present(platform) => platform,
        };
        let record = match platform.read_record().await {
            MemberRead::Reached(record) => record,
            MemberRead::ReachedEmpty => {
                return Err(unreadable(
                    CredentialStore::PlatformAccount,
                    NotReachedCause::HoldsNoRecord,
                ));
            }
            MemberRead::NotReached(cause) => {
                return Err(unreadable(CredentialStore::PlatformAccount, cause));
            }
        };
        if record.credential_id != *self.lease.credential_id() {
            return Err(RecoveryStoreError::RecordCredentialMismatch);
        }
        if record.large_blob == LargeBlobMembership::Member && self.members.large_blob.is_none() {
            return Err(unreadable(
                CredentialStore::LargeBlob,
                NotReachedCause::NoStoreOnDevice,
            ));
        }
        Ok(Some((platform, record)))
    }

    /// Steps 2 and 3: membership, then every store's entry, read in the
    /// order platform account, `largeBlob`, local.
    async fn snapshot(&self) -> Result<Snapshot, RecoveryStoreError> {
        let identifier = self.lease.identifier();
        let resolved = self.resolve_record().await?;
        let platform = match &resolved {
            Some((platform, _)) => Some(checked_entry(
                CredentialStore::PlatformAccount,
                platform.read_entry().await,
                identifier,
                EntrySource::Synced,
            )?),
            None => None,
        };
        let record = resolved.map(|(_, record)| record);
        let blob = match &self.members.large_blob {
            None => BlobRead::NoHandle,
            Some(large_blob) => match checked_entry(
                CredentialStore::LargeBlob,
                large_blob.read_entry().await,
                identifier,
                EntrySource::Synced,
            ) {
                Ok(entry) => BlobRead::Read(entry),
                // A host with a record tolerates a failed read of a store it
                // records as not a member; every other failure refuses.
                Err(RecoveryStoreError::StorePartiallyUnreadable { cause, .. })
                    if record.as_ref().is_some_and(|record| {
                        record.large_blob == LargeBlobMembership::NotMember
                    }) =>
                {
                    BlobRead::Unread(cause)
                }
                Err(error) => return Err(error),
            },
        };
        let local = checked_entry(
            CredentialStore::SdkLocal,
            self.members.sdk_local.read_entry().await,
            identifier,
            EntrySource::SdkLocal,
        )?;
        Ok(Snapshot {
            record,
            platform,
            blob,
            local,
        })
    }

    // -----------------------------------------------------------------------
    // Steps 5 and 6
    // -----------------------------------------------------------------------

    /// Writes the planned entries for `compose`, `hold` or `advance`, in the
    /// order platform account, `largeBlob`, local, record, applying R10's
    /// stops.
    async fn execute_report(
        &self,
        snapshot: &Snapshot,
        planned: &Planned,
        policy: Policy,
    ) -> WriteReport {
        let mut report = WriteReport {
            platform_account: MemberWrite::NotInSet,
            large_blob: LargeBlobWrite::NotAttempted,
            sdk_local: MemberWrite::NotAttempted,
            record: MemberWrite::NotAttempted,
            stop: None,
        };
        report.platform_account = self.write_platform(snapshot, planned.platform).await;
        if let MemberWrite::Failed { cause } = &report.platform_account {
            report.stop = Some(RecoveryStoreError::PlatformAccountWriteFailed {
                cause: cause.clone(),
            });
            return report;
        }
        report.large_blob = self.write_blob(snapshot, planned.blob).await;
        let mut local = planned.local;
        let mut membership = snapshot.record.as_ref().map(|record| record.large_blob);
        match &report.large_blob {
            LargeBlobWrite::NotLanded { cause, clears_by } => {
                let blob_held = match &snapshot.blob {
                    BlobRead::Read(entry) => entry,
                    BlobRead::NoHandle | BlobRead::Unread(_) => &StoreEntry::EMPTY,
                };
                let stop = match policy {
                    Policy::Compose | Policy::Hold if snapshot.record.is_some() => {
                        membership = Some(LargeBlobMembership::NotMember);
                        false
                    }
                    Policy::Compose | Policy::Hold if !blob_held.is_empty() => true,
                    Policy::Compose => {
                        local = local.map(|entry| {
                            entry.handle.map_or(entry, |handle| {
                                StoreEntry::large_blob_skipped(handle, entry.marker)
                            })
                        });
                        false
                    }
                    Policy::Advance {
                        event_digest,
                        to_signed,
                    } => to_signed && blob_held.holds(&event_digest),
                    Policy::Hold => false,
                };
                if stop {
                    report.stop = Some(RecoveryStoreError::LargeBlobStopped {
                        cause: cause.clone(),
                        clears_by: *clears_by,
                    });
                    return report;
                }
            }
            outcome => {
                if landed_evidence(outcome, &snapshot.blob) {
                    membership = membership.map(|_| LargeBlobMembership::Member);
                    if let Policy::Advance { event_digest, .. } = policy {
                        local = clear_skip(snapshot, local, &event_digest);
                    }
                }
            }
        }
        report.sdk_local = write_local(&self.members.sdk_local, local).await;
        if let MemberWrite::Failed { cause } = &report.sdk_local {
            report.stop = Some(RecoveryStoreError::SdkLocalWriteFailed {
                cause: cause.clone(),
            });
            return report;
        }
        report.record = self.write_membership(snapshot, membership).await;
        if let MemberWrite::Failed { cause } = &report.record {
            report.stop = Some(RecoveryStoreError::PlatformAccountWriteFailed {
                cause: cause.clone(),
            });
        }
        report
    }

    /// Writes the planned entries for `complete` or `remove`, trying every
    /// member.
    async fn execute_removal(&self, snapshot: &Snapshot, planned: &Planned) -> RemovalReport {
        let mut per_store = Vec::with_capacity(3);
        let mut membership = snapshot.record.as_ref().map(|record| record.large_blob);
        if snapshot.platform.is_some() {
            let cause = if planned.platform_refused {
                Some(RemovalCause::PhaseNotRemovable)
            } else {
                member_cause(self.write_platform(snapshot, planned.platform).await)
            };
            per_store.push(MemberRemoval {
                store: CredentialStore::PlatformAccount,
                cause,
            });
        }
        if !matches!(snapshot.blob, BlobRead::NoHandle) {
            let cause = if planned.blob_refused {
                Some(RemovalCause::PhaseNotRemovable)
            } else {
                let outcome = self.write_blob(snapshot, planned.blob).await;
                if landed_evidence(&outcome, &snapshot.blob) {
                    membership = membership.map(|_| LargeBlobMembership::Member);
                }
                match outcome {
                    LargeBlobWrite::NotLanded { cause, clears_by } => {
                        Some(RemovalCause::NotLanded { cause, clears_by })
                    }
                    LargeBlobWrite::Unread { cause } => Some(RemovalCause::Unread(cause)),
                    LargeBlobWrite::NoStore
                    | LargeBlobWrite::Unchanged
                    | LargeBlobWrite::Landed
                    | LargeBlobWrite::NotAttempted => None,
                }
            };
            per_store.push(MemberRemoval {
                store: CredentialStore::LargeBlob,
                cause,
            });
        }
        let cause = if planned.local_refused {
            Some(RemovalCause::PhaseNotRemovable)
        } else {
            member_cause(write_local(&self.members.sdk_local, planned.local).await)
        };
        per_store.push(MemberRemoval {
            store: CredentialStore::SdkLocal,
            cause,
        });
        let record = self.write_membership(snapshot, membership).await;
        RemovalReport { per_store, record }
    }

    async fn write_platform(&self, snapshot: &Snapshot, merge: Merge) -> MemberWrite {
        let PlatformAccountSlot::Present(platform) = &self.members.platform_account else {
            return MemberWrite::NotInSet;
        };
        if snapshot.platform.is_none() {
            return MemberWrite::NotInSet;
        }
        let Some(entry) = merge else {
            return MemberWrite::Unchanged;
        };
        match write_entry_checked(platform, &entry.without_skip(), EntrySource::Synced).await {
            Ok(()) => MemberWrite::Written,
            Err(cause) => MemberWrite::Failed { cause },
        }
    }

    async fn write_blob(&self, snapshot: &Snapshot, merge: Merge) -> LargeBlobWrite {
        let Some(large_blob) = &self.members.large_blob else {
            return LargeBlobWrite::NoStore;
        };
        match &snapshot.blob {
            BlobRead::NoHandle => return LargeBlobWrite::NoStore,
            BlobRead::Unread(cause) => {
                return LargeBlobWrite::Unread {
                    cause: cause.clone(),
                };
            }
            BlobRead::Read(_) => {}
        }
        let Some(entry) = merge else {
            return LargeBlobWrite::Unchanged;
        };
        match large_blob.write_entry(&entry.without_skip()).await {
            Ok(()) => LargeBlobWrite::Landed,
            Err(not_landed) => LargeBlobWrite::NotLanded {
                cause: not_landed.cause,
                clears_by: not_landed.clears_by,
            },
        }
    }

    /// Step 6: where the host has a record and the `largeBlob` membership
    /// changed, writes the record against a fresh read.
    async fn write_membership(
        &self,
        snapshot: &Snapshot,
        membership: Option<LargeBlobMembership>,
    ) -> MemberWrite {
        let (Some(current), Some(target)) = (&snapshot.record, membership) else {
            return MemberWrite::NotInSet;
        };
        if current.large_blob == target {
            return MemberWrite::Unchanged;
        }
        let PlatformAccountSlot::Present(platform) = &self.members.platform_account else {
            return MemberWrite::NotInSet;
        };
        match platform.read_record().await {
            MemberRead::Reached(fresh) if fresh.credential_id == *self.lease.credential_id() => {
                if fresh.large_blob == target {
                    return MemberWrite::Unchanged;
                }
            }
            MemberRead::Reached(_) => {
                return MemberWrite::Failed {
                    cause: "the record names another credential".to_owned(),
                };
            }
            MemberRead::ReachedEmpty => {
                return MemberWrite::Failed {
                    cause: "the platform-account member holds no record".to_owned(),
                };
            }
            MemberRead::NotReached(cause) => {
                return MemberWrite::Failed {
                    cause: format!("record read failed: {cause:?}"),
                };
            }
        }
        let record = StoreSetRecord {
            credential_id: current.credential_id.clone(),
            large_blob: target,
        };
        match write_record_checked(platform, &record).await {
            Ok(()) => MemberWrite::Written,
            Err(cause) => MemberWrite::Failed { cause },
        }
    }
}

/// Every member's merge for `change`, computed from the step-3 reads before
/// the first write. A merge refusal refuses the transition.
fn plan(snapshot: &Snapshot, change: Change) -> Result<Planned, RecoveryStoreError> {
    let refused = |entry: &StoreEntry| match change {
        Change::Remove {
            event_digest,
            basis,
        } => entry.handle.is_some_and(|handle| {
            handle.event_digest() == event_digest
                && !removable(basis, handle.phase(), snapshot.merged_phase(&event_digest))
        }),
        Change::Compose { .. }
        | Change::Hold { .. }
        | Change::Advance { .. }
        | Change::Complete { .. } => false,
    };
    let platform = match &snapshot.platform {
        Some(entry) => merge(change, CredentialStore::PlatformAccount, entry, snapshot)?,
        None => None,
    };
    let (blob, blob_refused) = match &snapshot.blob {
        BlobRead::Read(entry) => (
            merge(change, CredentialStore::LargeBlob, entry, snapshot)?,
            refused(entry),
        ),
        BlobRead::NoHandle | BlobRead::Unread(_) => (None, false),
    };
    let local = merge(change, CredentialStore::SdkLocal, &snapshot.local, snapshot)?;
    Ok(Planned {
        platform,
        blob,
        local,
        platform_refused: snapshot.platform.as_ref().is_some_and(&refused),
        blob_refused,
        local_refused: refused(&snapshot.local),
    })
}

/// Whether a `largeBlob` outcome shows the store holds a landed write: a
/// write that landed, or an unchanged store whose entry holds a handle or a
/// marker. An empty store that took no write shows nothing.
const fn landed_evidence(outcome: &LargeBlobWrite, read: &BlobRead) -> bool {
    match outcome {
        LargeBlobWrite::Landed => true,
        LargeBlobWrite::Unchanged => matches!(read, BlobRead::Read(entry) if !entry.is_empty()),
        LargeBlobWrite::NoStore
        | LargeBlobWrite::Unread { .. }
        | LargeBlobWrite::NotLanded { .. }
        | LargeBlobWrite::NotAttempted => false,
    }
}

/// Clears the local skip bit for `event_digest` once the handle has landed
/// in the `largeBlob` store.
fn clear_skip(snapshot: &Snapshot, local: Merge, event_digest: &[u8; 32]) -> Merge {
    match local {
        Some(entry) if entry.holds(event_digest) => Some(entry.without_skip()),
        Some(entry) => Some(entry),
        None if snapshot.local_skipped(event_digest) => Some(snapshot.local.without_skip()),
        None => None,
    }
}

fn member_cause(write: MemberWrite) -> Option<RemovalCause> {
    match write {
        MemberWrite::Failed { cause } => Some(RemovalCause::Failed { cause }),
        MemberWrite::NotInSet
        | MemberWrite::Unchanged
        | MemberWrite::Written
        | MemberWrite::NotAttempted => None,
    }
}

async fn write_local<L>(local: &L, merge: Merge) -> MemberWrite
where
    L: RecoveryHandleStore<WriteFailure = StoreWriteFailure> + MaybeSync,
{
    let Some(entry) = merge else {
        return MemberWrite::Unchanged;
    };
    match write_entry_checked(local, &entry, EntrySource::SdkLocal).await {
        Ok(()) => MemberWrite::Written,
        Err(cause) => MemberWrite::Failed { cause },
    }
}

/// Writes `entry` and reads it back; a different read-back is a failure.
async fn write_entry_checked<M>(
    member: &M,
    entry: &StoreEntry,
    source: EntrySource,
) -> Result<(), String>
where
    M: RecoveryHandleStore<WriteFailure = StoreWriteFailure> + MaybeSync,
{
    member
        .write_entry(entry)
        .await
        .map_err(|failure| failure.cause)?;
    let read_back = match member.read_entry().await {
        MemberRead::Reached(read) => read,
        MemberRead::ReachedEmpty => StoreEntry::EMPTY,
        MemberRead::NotReached(cause) => return Err(format!("read-back failed: {cause:?}")),
    };
    let expected = match source {
        EntrySource::SdkLocal => *entry,
        EntrySource::Synced => entry.without_skip(),
    };
    if read_back == expected {
        Ok(())
    } else {
        Err("the entry read back differs from the entry written".to_owned())
    }
}

async fn write_event_checked<M>(
    member: &M,
    event_digest: &[u8; 32],
    event: &[u8],
) -> Result<(), String>
where
    M: RecoveryEventStore<WriteFailure = StoreWriteFailure> + MaybeSync,
{
    member
        .write_event(event_digest, event)
        .await
        .map_err(|failure| failure.cause)?;
    match member.read_event(event_digest).await {
        MemberRead::Reached(read) if read == event => Ok(()),
        MemberRead::Reached(_) | MemberRead::ReachedEmpty => {
            Err("the event read back differs from the event written".to_owned())
        }
        MemberRead::NotReached(cause) => Err(format!("read-back failed: {cause:?}")),
    }
}

async fn write_record_checked<P>(platform: &P, record: &StoreSetRecord) -> Result<(), String>
where
    P: RecoveryRecordStore<WriteFailure = StoreWriteFailure> + MaybeSync,
{
    platform
        .write_record(record)
        .await
        .map_err(|failure| failure.cause)?;
    match platform.read_record().await {
        MemberRead::Reached(read) if read == *record => Ok(()),
        MemberRead::Reached(_) | MemberRead::ReachedEmpty => {
            Err("the record read back differs from the record written".to_owned())
        }
        MemberRead::NotReached(cause) => Err(format!("read-back failed: {cause:?}")),
    }
}

/// A member's read, as the set takes it: an empty read is
/// [`StoreEntry::EMPTY`]; a read naming another identity, or a synced
/// member's entry carrying the skip bit, is a member not reached.
fn checked_entry(
    store: CredentialStore,
    read: MemberRead<StoreEntry>,
    identifier: Identifier,
    source: EntrySource,
) -> Result<StoreEntry, RecoveryStoreError> {
    let entry = match read {
        MemberRead::Reached(entry) => entry,
        MemberRead::ReachedEmpty => return Ok(StoreEntry::EMPTY),
        MemberRead::NotReached(cause) => return Err(unreadable(store, cause)),
    };
    if source == EntrySource::Synced && entry.large_blob_skipped {
        return Err(unreadable(
            store,
            NotReachedCause::Undecodable(RecordDecodeError::SkipInSyncedMember),
        ));
    }
    let foreign = entry
        .handle
        .is_some_and(|handle| handle.identifier() != identifier)
        || entry
            .marker
            .is_some_and(|marker| marker.identifier != identifier);
    if foreign {
        return Err(unreadable(store, NotReachedCause::ForeignIdentity));
    }
    Ok(entry)
}

const fn unreadable(store: CredentialStore, cause: NotReachedCause) -> RecoveryStoreError {
    RecoveryStoreError::StorePartiallyUnreadable { store, cause }
}

// ---------------------------------------------------------------------------
// Codecs
// ---------------------------------------------------------------------------

/// Encodes `handle` at [`RECOVERY_HANDLE_BYTES`]: discriminant ‖ identifier ‖
/// phase ‖ event digest.
#[must_use]
pub fn encode_handle(handle: &RecoveryHandle) -> [u8; RECOVERY_HANDLE_BYTES] {
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
///
/// # Errors
///
/// A wrong length, an unknown discriminant or an unknown phase byte.
pub fn decode_handle(bytes: &[u8]) -> Result<RecoveryHandle, RecordDecodeError> {
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
    let kind = match variant[0] {
        RecoveryHandle::FIXES_COMMITMENT => RevealKind::FixesCommitment,
        RecoveryHandle::ABANDONS => RevealKind::Abandons,
        other => return Err(RecordDecodeError::UnknownVariant(other)),
    };
    Ok(RecoveryHandle::new(
        kind,
        identifier,
        phase,
        array32(digest),
    ))
}

/// Encodes `marker` at [`LAST_REVEAL_MARKER_BYTES`]: identifier ‖ sequence
/// (big-endian) ‖ event digest.
#[must_use]
pub fn encode_marker(marker: &LastRevealMarker) -> [u8; LAST_REVEAL_MARKER_BYTES] {
    let mut out = [0u8; LAST_REVEAL_MARKER_BYTES];
    out[0..32].copy_from_slice(marker.identifier.as_bytes());
    out[32..40].copy_from_slice(&marker.sequence.to_be_bytes());
    out[40..72].copy_from_slice(&marker.event_digest);
    out
}

/// Decodes exactly [`LAST_REVEAL_MARKER_BYTES`] bytes as a marker.
///
/// # Errors
///
/// A wrong length.
pub fn decode_marker(bytes: &[u8]) -> Result<LastRevealMarker, RecordDecodeError> {
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

/// Encodes `entry` as the §17.8 entry record: flags ‖ handle? ‖ marker?.
/// [`StoreEntry::EMPTY`] encodes as the one byte `0x00`.
#[must_use]
pub fn encode_entry(entry: &StoreEntry) -> Vec<u8> {
    let mut flags = 0u8;
    if entry.handle.is_some() {
        flags |= FLAG_HANDLE;
    }
    if entry.marker.is_some() {
        flags |= FLAG_MARKER;
    }
    if entry.large_blob_skipped {
        flags |= FLAG_LARGE_BLOB_SKIPPED;
    }
    let mut out = Vec::with_capacity(1 + RECOVERY_HANDLE_BYTES + LAST_REVEAL_MARKER_BYTES);
    out.push(flags);
    if let Some(handle) = entry.handle {
        out.extend_from_slice(&encode_handle(&handle));
    }
    if let Some(marker) = entry.marker {
        out.extend_from_slice(&encode_marker(&marker));
    }
    out
}

/// Decodes a §17.8 entry record read from `source`. `Ok(None)` is the one
/// byte `0x00`.
///
/// # Errors
///
/// Any of flag bits 3 to 7, bit 2 without bit 0, bit 2 in an entry from a
/// synced member, a length other than the 1, 67, 73 or 139 bytes bits 0 and
/// 1 name, and an unknown discriminant or phase byte.
pub fn decode_entry(
    bytes: &[u8],
    source: EntrySource,
) -> Result<Option<StoreEntry>, RecordDecodeError> {
    let Some((&flags, body)) = bytes.split_first() else {
        return Err(RecordDecodeError::WrongLength {
            expected: 1,
            actual: 0,
        });
    };
    if flags & !(FLAG_HANDLE | FLAG_MARKER | FLAG_LARGE_BLOB_SKIPPED) != 0 {
        return Err(RecordDecodeError::UnknownFlags(flags));
    }
    let has_handle = flags & FLAG_HANDLE != 0;
    let has_marker = flags & FLAG_MARKER != 0;
    let skipped = flags & FLAG_LARGE_BLOB_SKIPPED != 0;
    if skipped && !has_handle {
        return Err(RecordDecodeError::SkipWithoutHandle(flags));
    }
    if skipped && source == EntrySource::Synced {
        return Err(RecordDecodeError::SkipInSyncedMember);
    }
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
    Ok(Some(StoreEntry {
        handle,
        marker,
        large_blob_skipped: skipped,
    })
    .filter(|entry| !entry.is_empty()))
}

/// Encodes `record` (§17.8): version `0x01` ‖ `largeBlob` byte ‖ credential
/// identifier length (u16 big-endian) ‖ credential identifier.
#[must_use]
pub fn encode_store_set_record(record: &StoreSetRecord) -> Vec<u8> {
    let id = record.credential_id.as_bytes();
    let mut out = Vec::with_capacity(STORE_SET_RECORD_HEADER_BYTES + id.len());
    out.push(STORE_SET_RECORD_VERSION);
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

/// Decodes a §17.8 `StoreSetRecord`.
///
/// # Errors
///
/// An unknown version or `largeBlob` byte, a credential identifier length
/// outside 1..=1023, and a total length other than `4 + id_len`.
pub fn decode_store_set_record(bytes: &[u8]) -> Result<StoreSetRecord, RecordDecodeError> {
    let Some((header, id)) = bytes.split_first_chunk::<STORE_SET_RECORD_HEADER_BYTES>() else {
        return Err(RecordDecodeError::WrongLength {
            expected: STORE_SET_RECORD_HEADER_BYTES,
            actual: bytes.len(),
        });
    };
    let [version, large_blob, len_hi, len_lo] = *header;
    if version != STORE_SET_RECORD_VERSION {
        return Err(RecordDecodeError::UnknownVersion(version));
    }
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
        large_blob,
    })
}

/// Refuses an empty event and one above `MAX_EVENT_BYTES`.
///
/// # Errors
///
/// [`RecordDecodeError::EventLength`] outside 1..=`MAX_EVENT_BYTES`.
pub fn check_event_length(event: &[u8]) -> Result<(), RecordDecodeError> {
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
