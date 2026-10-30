//! Tests for the synced store-set members over host fakes.
//!
//! Sources: `09-security-model.md` §9.7.4.2 R10,
//! `17-persistence-and-storage.md` §17.8, SCP-311 acceptance criterion 2.
//! The codecs and the set's own
//! rules are tested in `scp_kel::recovery_store`; these tests cover what the
//! member's mapping of a host answer decides, run through a real
//! [`StoreSet`] where the set's outcome depends on it.

use std::collections::HashMap;
use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use scp_did::Identifier;
use scp_platform::{
    CredentialStore, LargeBlobMembership, LargeBlobWrite, LastRevealMarker, MemberWrite,
    PlatformAccountSlot, RecoveryHandle, RecoveryLease, RecoveryLeases, RecoveryPhase,
    RecoveryStoreError, RevealKind, StoreSet, StoreSetMembers,
};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// `MAX_EVENT_BYTES` (`09-security-model.md` §9.18.17).
const MAX_EVENT: usize = 65_536;

/// SHA-256 of 64 bytes of `0xc1`, as lowercase hex.
const C1_COMPONENT: &str = "4891e00a13c5813f53b9e832a034ece86ff4dd143dd876287c830949e0f31115";

/// The error text a faulted fake throws.
const THROWN: &str = "host threw: keychain item locked";

const D1: [u8; 32] = [0xd1; 32];

/// Drives a future whose doubles never pend.
fn run<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn credential() -> Result<CredentialId, Box<dyn std::error::Error>> {
    Ok(CredentialId::new(vec![0xc1; 64])?)
}

const fn identifier() -> Identifier {
    Identifier::from_bytes([0x07; 32])
}

fn lease(leases: &RecoveryLeases) -> Result<RecoveryLease, Box<dyn std::error::Error>> {
    Ok(leases.acquire(credential()?, identifier())?)
}

fn handle(phase: RecoveryPhase) -> RecoveryHandle {
    RecoveryHandle::new(RevealKind::FixesCommitment, identifier(), phase, D1)
}

const fn marker() -> LastRevealMarker {
    LastRevealMarker {
        identifier: identifier(),
        sequence: 3,
        event_digest: [0x33; 32],
    }
}

/// The 139-byte entry: a handle and a marker.
fn full_entry(phase: RecoveryPhase) -> StoreEntry {
    StoreEntry::new(Some(handle(phase)), Some(marker()))
}

fn thrown() -> HostStoreFailure {
    HostStoreFailure {
        cause: THROWN.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

/// A synced store: a map, with switches that make a `get` of one key, every
/// `put`, or a `put` that stores all but the last byte, fail.
#[derive(Default)]
struct MapHost {
    map: Mutex<HashMap<String, Vec<u8>>>,
    fail_get_key: Mutex<Option<String>>,
    fail_puts: AtomicBool,
    truncate_puts: AtomicBool,
    puts: Mutex<Vec<String>>,
}

impl MapHost {
    fn raw(&self, key: &str) -> Option<Vec<u8>> {
        lock(&self.map).get(key).cloned()
    }

    fn set_raw(&self, key: &str, bytes: &[u8]) {
        lock(&self.map).insert(key.to_owned(), bytes.to_vec());
    }

    fn keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = lock(&self.map).keys().cloned().collect();
        keys.sort();
        keys
    }

    fn fail_get(&self, key: &str) {
        *lock(&self.fail_get_key) = Some(key.to_owned());
    }
}

impl SyncedStoreHost for MapHost {
    fn get(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, HostStoreFailure>> + Send {
        let answer = if lock(&self.fail_get_key).as_deref() == Some(key) {
            Err(thrown())
        } else {
            Ok(self.raw(key))
        };
        std::future::ready(answer)
    }

    fn put(
        &self,
        key: &str,
        value: &[u8],
    ) -> impl Future<Output = Result<(), HostStoreFailure>> + Send {
        lock(&self.puts).push(key.to_owned());
        let answer = if self.fail_puts.load(Ordering::SeqCst) {
            Err(thrown())
        } else {
            let kept = if self.truncate_puts.load(Ordering::SeqCst) {
                &value[..value.len().saturating_sub(1)]
            } else {
                value
            };
            self.set_raw(key, kept);
            Ok(())
        };
        std::future::ready(answer)
    }
}

/// What the next `write_blob` answers.
#[derive(Clone, Debug)]
enum NextBlobWrite {
    Land,
    /// A platform fact other than `Landed`.
    Report(BlobWrite),
    Throw,
}

/// A `largeBlob` slot for one credential, recording each call's credential.
struct BlobSlot {
    bytes: Mutex<Option<Vec<u8>>>,
    fail_reads: AtomicBool,
    next_write: Mutex<NextBlobWrite>,
    credentials: Mutex<Vec<CredentialId>>,
    written: Mutex<Vec<Vec<u8>>>,
}

impl Default for BlobSlot {
    fn default() -> Self {
        Self {
            bytes: Mutex::new(None),
            fail_reads: AtomicBool::new(false),
            next_write: Mutex::new(NextBlobWrite::Land),
            credentials: Mutex::new(Vec::new()),
            written: Mutex::new(Vec::new()),
        }
    }
}

impl BlobSlot {
    fn set_raw(&self, bytes: Option<&[u8]>) {
        *lock(&self.bytes) = bytes.map(<[u8]>::to_vec);
    }

    fn answer_next(&self, next: NextBlobWrite) {
        *lock(&self.next_write) = next;
    }
}

impl CredentialBlobHost for BlobSlot {
    fn read_blob(
        &self,
        credential_id: &CredentialId,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, HostStoreFailure>> + Send {
        lock(&self.credentials).push(credential_id.clone());
        let answer = if self.fail_reads.load(Ordering::SeqCst) {
            Err(thrown())
        } else {
            Ok(lock(&self.bytes).clone())
        };
        std::future::ready(answer)
    }

    fn write_blob(
        &self,
        credential_id: &CredentialId,
        entry: &[u8],
    ) -> impl Future<Output = Result<BlobWrite, HostStoreFailure>> + Send {
        lock(&self.credentials).push(credential_id.clone());
        let next = lock(&self.next_write).clone();
        let answer = match next {
            NextBlobWrite::Land => {
                lock(&self.written).push(entry.to_vec());
                *lock(&self.bytes) = Some(entry.to_vec());
                Ok(BlobWrite::Landed)
            }
            NextBlobWrite::Report(fact) => Ok(fact),
            NextBlobWrite::Throw => Err(thrown()),
        };
        std::future::ready(answer)
    }
}

/// The SDK's local store, for the sets these tests open: a map that decodes
/// its entry as the local store does.
#[derive(Clone, Default)]
struct LocalMap {
    map: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl RecoveryHandleStore for LocalMap {
    type WriteFailure = StoreWriteFailure;

    async fn read_entry(&self, credential_id: &CredentialId) -> MemberRead<StoreEntry> {
        let key = credential_id.entry_key();
        decoded(Ok(lock(&self.map).get(&key).cloned()), |bytes| {
            decode_entry(bytes, EntrySource::SdkLocal)
        })
    }

    async fn write_entry(
        &self,
        credential_id: &CredentialId,
        entry: &StoreEntry,
    ) -> Result<(), StoreWriteFailure> {
        lock(&self.map).insert(credential_id.entry_key(), encode_entry(entry));
        Ok(())
    }
}

impl RecoveryEventStore for LocalMap {
    async fn read_event(
        &self,
        credential_id: &CredentialId,
        event_digest: &[u8; 32],
    ) -> MemberRead<Vec<u8>> {
        lock(&self.map)
            .get(&credential_id.event_key(event_digest))
            .cloned()
            .map_or(MemberRead::ReachedEmpty, MemberRead::Reached)
    }

    async fn write_event(
        &self,
        credential_id: &CredentialId,
        event_digest: &[u8; 32],
        event: &[u8],
    ) -> Result<(), StoreWriteFailure> {
        lock(&self.map).insert(credential_id.event_key(event_digest), event.to_vec());
        Ok(())
    }
}

type PresentSet = StoreSet<
    LocalMap,
    SyncedStoreMember<Arc<MapHost>>,
    CredentialBlobMember<Arc<BlobSlot>>,
    RecoveryLease,
>;

/// A device on the Apple row: the platform-account member over `platform`
/// and, where given, the `largeBlob` member over `blob`.
struct Device {
    leases: RecoveryLeases,
    local: LocalMap,
    platform: Arc<MapHost>,
    blob: Option<Arc<BlobSlot>>,
}

impl Device {
    fn new(blob: bool) -> Self {
        Self {
            leases: RecoveryLeases::new(),
            local: LocalMap::default(),
            platform: Arc::new(MapHost::default()),
            blob: blob.then(|| Arc::new(BlobSlot::default())),
        }
    }

    fn members(
        &self,
    ) -> StoreSetMembers<
        LocalMap,
        SyncedStoreMember<Arc<MapHost>>,
        CredentialBlobMember<Arc<BlobSlot>>,
    > {
        StoreSetMembers {
            sdk_local: self.local.clone(),
            platform_account: PlatformAccountSlot::Present(SyncedStoreMember::new(Arc::clone(
                &self.platform,
            ))),
            large_blob: self
                .blob
                .as_ref()
                .map(|blob| CredentialBlobMember::new(Arc::clone(blob))),
        }
    }

    fn create(&self) -> Result<PresentSet, Box<dyn std::error::Error>> {
        let lease = lease(&self.leases)?;
        Ok(run(StoreSet::create(self.members(), lease))?)
    }

    fn open(&self) -> Result<PresentSet, RecoveryStoreError> {
        let lease = lease(&self.leases).map_err(|e| RecoveryStoreError::SdkLocalWriteFailed {
            cause: e.to_string(),
        })?;
        run(StoreSet::open(self.members(), lease))
    }
}

fn synced_member(host: &Arc<MapHost>) -> SyncedStoreMember<Arc<MapHost>> {
    SyncedStoreMember::new(Arc::clone(host))
}

fn blob_member(slot: &Arc<BlobSlot>) -> CredentialBlobMember<Arc<BlobSlot>> {
    CredentialBlobMember::new(Arc::clone(slot))
}

fn compose(set: &mut PresentSet) -> Result<scp_platform::WriteReport, RecoveryStoreError> {
    run(set.compose(RevealKind::FixesCommitment, D1, None))
}

// ---------------------------------------------------------------------------
// SyncedStoreMember
// ---------------------------------------------------------------------------

/// A 139-byte entry, the record and a `MAX_EVENT_BYTES` event round-trip
/// through the member, and through a store set on the Apple row.
#[test]
fn synced_member_round_trips_entry_record_and_max_event() -> TestResult {
    let host = Arc::new(MapHost::default());
    let member = synced_member(&host);
    let entry = full_entry(RecoveryPhase::Signed);
    run(member.write_entry(&credential()?, &entry))?;
    assert_eq!(
        host.raw(&credential()?.entry_key()).map(|b| b.len()),
        Some(139)
    );
    assert_eq!(
        run(member.read_entry(&credential()?)),
        MemberRead::Reached(entry)
    );
    let record = StoreSetRecord {
        credential_id: credential()?,
        large_blob: LargeBlobMembership::Member,
    };
    run(member.write_record(&credential()?, &record))?;
    assert_eq!(
        run(member.read_record(&credential()?)),
        MemberRead::Reached(record)
    );

    let device = Device::new(false);
    let mut set = device.create()?;
    compose(&mut set)?.completed()?;
    let event = vec![0xe5; MAX_EVENT];
    run(set.write_event(&D1, &event))?;
    assert_eq!(
        device.platform.raw(&credential()?.event_key(&D1)),
        Some(event.clone())
    );
    drop(set);
    let reopened = device.open()?;
    assert_eq!(run(reopened.read_event(&D1))?, Some(event));
    Ok(())
}

/// A host that stores 65,535 bytes of a 65,536-byte event fails the set's
/// read-back, so the platform write fails.
#[test]
fn synced_member_truncating_host_fails_read_back() -> TestResult {
    let device = Device::new(false);
    let set = device.create()?;
    device.platform.truncate_puts.store(true, Ordering::SeqCst);
    let written = run(set.write_event(&D1, &vec![0xe5; MAX_EVENT]));
    assert!(
        matches!(
            written,
            Err(RecoveryStoreError::PlatformAccountWriteFailed { .. })
        ),
        "{written:?}"
    );
    assert_eq!(
        device
            .platform
            .raw(&credential()?.event_key(&D1))
            .map(|b| b.len()),
        Some(MAX_EVENT - 1)
    );
    Ok(())
}

/// Mutant: the record stored under the entry key. The host sees exactly the
/// three keys §17.3 and §17.8 name, formed from the hashed credential.
#[test]
fn synced_member_forms_credential_keys() -> TestResult {
    let host = Arc::new(MapHost::default());
    let member = synced_member(&host);
    run(member.write_entry(&credential()?, &full_entry(RecoveryPhase::Composed)))?;
    let record = StoreSetRecord {
        credential_id: credential()?,
        large_blob: LargeBlobMembership::NotMember,
    };
    run(member.write_record(&credential()?, &record))?;
    run(member.write_event(&credential()?, &[0x22; 32], b"signed event"))?;
    let entry_key = format!("recovery/{C1_COMPONENT}/entry");
    let record_key = format!("recovery/{C1_COMPONENT}/record");
    let event_key = format!("recovery/{C1_COMPONENT}/event/{}", "22".repeat(32));
    assert_eq!(
        host.keys(),
        vec![entry_key.clone(), event_key.clone(), record_key.clone()]
    );
    assert_eq!(
        host.raw(&record_key),
        Some(encode_store_set_record(&record))
    );
    assert_eq!(
        host.raw(&entry_key),
        Some(encode_entry(&full_entry(RecoveryPhase::Composed)))
    );
    assert_eq!(host.raw(&event_key), Some(b"signed event".to_vec()));
    Ok(())
}

/// Mutant: a host `get` failure read as empty. The entry `get` fails while
/// the record reads fine, so an empty read would let `compose` write; the
/// set refuses with the member not reached and the host's own cause.
#[test]
fn synced_member_get_error_is_unreachable_not_empty() -> TestResult {
    let device = Device::new(false);
    drop(device.create()?);
    device.platform.fail_get(&credential()?.entry_key());
    let mut set = device.open()?;
    assert_eq!(
        compose(&mut set).err(),
        Some(RecoveryStoreError::StorePartiallyUnreadable {
            store: CredentialStore::PlatformAccount,
            cause: NotReachedCause::Unreachable {
                cause: THROWN.to_owned()
            },
        })
    );
    assert_eq!(device.platform.raw(&credential()?.entry_key()), None);
    Ok(())
}

/// Mutant: a synced entry decoded as the local store's. Flags `0x05` (a
/// handle and the skip bit) do not decode at the member.
#[test]
fn synced_member_skip_bit_entry_is_undecodable() -> TestResult {
    let host = Arc::new(MapHost::default());
    let member = synced_member(&host);
    let skipped = StoreEntry::large_blob_skipped(handle(RecoveryPhase::Composed), None);
    let bytes = encode_entry(&skipped);
    assert_eq!(bytes.first(), Some(&0x05));
    host.set_raw(&credential()?.entry_key(), &bytes);
    assert_eq!(
        run(member.read_entry(&credential()?)),
        MemberRead::NotReached(NotReachedCause::Undecodable(
            RecordDecodeError::SkipInSyncedMember
        ))
    );
    Ok(())
}

/// Mutant: the event length check skipped on read. An empty stored event
/// and one of `MAX_EVENT_BYTES + 1` bytes do not decode.
#[test]
fn synced_member_event_out_of_range_is_undecodable() -> TestResult {
    let host = Arc::new(MapHost::default());
    let member = synced_member(&host);
    for len in [0, MAX_EVENT + 1] {
        host.set_raw(&credential()?.event_key(&D1), &vec![0xe5; len]);
        assert_eq!(
            run(member.read_event(&credential()?, &D1)),
            MemberRead::NotReached(NotReachedCause::Undecodable(
                RecordDecodeError::EventLength(len)
            ))
        );
    }
    Ok(())
}

/// A record of an unknown version does not decode.
#[test]
fn synced_member_bad_record_is_undecodable() -> TestResult {
    let host = Arc::new(MapHost::default());
    let member = synced_member(&host);
    let mut bytes = encode_store_set_record(&StoreSetRecord {
        credential_id: credential()?,
        large_blob: LargeBlobMembership::NotMember,
    });
    if let Some(version) = bytes.first_mut() {
        *version = 0x02;
    }
    host.set_raw(&credential()?.record_key(), &bytes);
    assert_eq!(
        run(member.read_record(&credential()?)),
        MemberRead::NotReached(NotReachedCause::Undecodable(
            RecordDecodeError::UnknownVersion(0x02)
        ))
    );
    Ok(())
}

/// Mutant: a thrown `put` swallowed. Every member write carries the host's
/// own error text, and the set refuses `compose` with that text and keeps
/// the member: the next open still reaches it.
#[test]
fn synced_member_put_error_is_store_write_failure() -> TestResult {
    let host = Arc::new(MapHost::default());
    let member = synced_member(&host);
    host.fail_puts.store(true, Ordering::SeqCst);
    let failure = Err(StoreWriteFailure {
        cause: THROWN.to_owned(),
    });
    assert_eq!(
        run(member.write_entry(&credential()?, &StoreEntry::EMPTY)),
        failure
    );
    assert_eq!(
        run(member.write_event(&credential()?, &D1, b"event")),
        failure
    );
    let record = StoreSetRecord {
        credential_id: credential()?,
        large_blob: LargeBlobMembership::NotMember,
    };
    assert_eq!(run(member.write_record(&credential()?, &record)), failure);

    let device = Device::new(false);
    let mut set = device.create()?;
    device.platform.fail_puts.store(true, Ordering::SeqCst);
    let report = compose(&mut set)?;
    assert_eq!(
        report.platform_account,
        MemberWrite::Failed {
            cause: THROWN.to_owned()
        }
    );
    assert_eq!(
        report.completed().err(),
        Some(RecoveryStoreError::PlatformAccountWriteFailed {
            cause: THROWN.to_owned()
        })
    );
    drop(set);
    device.platform.fail_puts.store(false, Ordering::SeqCst);
    let reopened = device.open()?;
    assert!(run(reopened.read_set())?.pending().is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------
// CredentialBlobMember
// ---------------------------------------------------------------------------

/// A 139-byte entry round-trips, and a handle whose phase byte differs does
/// not compare equal to it.
#[test]
fn blob_member_round_trips_handle_and_marker() -> TestResult {
    let slot = Arc::new(BlobSlot::default());
    let member = blob_member(&slot);
    let entry = full_entry(RecoveryPhase::Composed);
    run(member.write_entry(&credential()?, &entry))?;
    assert_eq!(lock(&slot.written).first().map(Vec::len), Some(139));
    let read = run(member.read_entry(&credential()?));
    assert_eq!(read, MemberRead::Reached(entry));
    assert_ne!(read, MemberRead::Reached(full_entry(RecoveryPhase::Signed)));
    Ok(())
}

/// Mutant: the `largeBlob` entry decoded as the local store's. Flags `0x05`
/// do not decode.
#[test]
fn blob_member_refuses_skip_bit() -> TestResult {
    let slot = Arc::new(BlobSlot::default());
    let member = blob_member(&slot);
    let skipped = StoreEntry::large_blob_skipped(handle(RecoveryPhase::Composed), None);
    slot.set_raw(Some(&encode_entry(&skipped)));
    assert_eq!(
        run(member.read_entry(&credential()?)),
        MemberRead::NotReached(NotReachedCause::Undecodable(
            RecordDecodeError::SkipInSyncedMember
        ))
    );
    Ok(())
}

/// Mutant: the entry `0x00` read as a reached empty entry value. No bytes
/// and the one byte `0x00` both read as empty.
#[test]
fn blob_member_empty_reads() -> TestResult {
    let slot = Arc::new(BlobSlot::default());
    let member = blob_member(&slot);
    assert_eq!(
        run(member.read_entry(&credential()?)),
        MemberRead::ReachedEmpty
    );
    slot.set_raw(Some(&[0x00]));
    assert_eq!(
        run(member.read_entry(&credential()?)),
        MemberRead::ReachedEmpty
    );
    Ok(())
}

/// Mutant: a thrown `read_blob` read as empty.
#[test]
fn blob_member_read_error_is_unreachable() -> TestResult {
    let slot = Arc::new(BlobSlot::default());
    let member = blob_member(&slot);
    slot.fail_reads.store(true, Ordering::SeqCst);
    assert_eq!(
        run(member.read_entry(&credential()?)),
        MemberRead::NotReached(NotReachedCause::Unreachable {
            cause: THROWN.to_owned()
        })
    );
    Ok(())
}

/// The R10 rule maps each platform fact to its act, and the host names no
/// act (ADR-054). Mutants: `NotWritten` mapped to `RetryVerification`;
/// `NoOutput` or a declined gesture mapped to `RemoveConsumingCredential`; a
/// declined gesture's cause dropped; any fact read as landed.
#[test]
fn blob_member_maps_each_platform_fact_to_its_act() -> TestResult {
    let slot = Arc::new(BlobSlot::default());
    let member = blob_member(&slot);
    let cases = [
        (
            BlobWrite::NotWritten,
            None,
            LargeBlobClearingAct::RemoveConsumingCredential,
        ),
        (
            BlobWrite::NoOutput,
            None,
            LargeBlobClearingAct::RetryVerification,
        ),
        (
            BlobWrite::VerificationDeclined { cause: None },
            None,
            LargeBlobClearingAct::RetryVerification,
        ),
        (
            BlobWrite::VerificationDeclined {
                cause: Some("user cancelled".to_owned()),
            },
            Some("user cancelled".to_owned()),
            LargeBlobClearingAct::RetryVerification,
        ),
    ];
    for (fact, cause, clears_by) in cases {
        slot.answer_next(NextBlobWrite::Report(fact));
        assert_eq!(
            run(member.write_entry(&credential()?, &StoreEntry::EMPTY)),
            Err(LargeBlobNotLanded { cause, clears_by })
        );
    }
    slot.answer_next(NextBlobWrite::Report(BlobWrite::Landed));
    assert_eq!(
        run(member.write_entry(&credential()?, &StoreEntry::EMPTY)),
        Ok(())
    );
    Ok(())
}

/// Mutant: a thrown `write_blob` read as landed. It is not landed, cleared
/// by a retry, with the host's text as the cause.
#[test]
fn blob_member_thrown_write_is_not_landed() -> TestResult {
    let slot = Arc::new(BlobSlot::default());
    let member = blob_member(&slot);
    slot.answer_next(NextBlobWrite::Throw);
    assert_eq!(
        run(member.write_entry(&credential()?, &full_entry(RecoveryPhase::Composed))),
        Err(LargeBlobNotLanded {
            cause: Some(THROWN.to_owned()),
            clears_by: LargeBlobClearingAct::RetryVerification,
        })
    );
    Ok(())
}

/// The host receives the encoded entry and the lease's credential on every
/// call.
#[test]
fn blob_member_passes_entry_bytes_and_credential() -> TestResult {
    let slot = Arc::new(BlobSlot::default());
    let member = blob_member(&slot);
    let entry = full_entry(RecoveryPhase::Composed);
    run(member.write_entry(&credential()?, &entry))?;
    let _ = run(member.read_entry(&credential()?));
    assert_eq!(*lock(&slot.written), vec![encode_entry(&entry)]);
    assert_eq!(*lock(&slot.credentials), vec![credential()?, credential()?]);
    Ok(())
}

/// On the Apple row, a `largeBlob` write that does not land at compose
/// removes that member alone: the platform-account member holds the handle,
/// the record keeps the store out of the set, and the ceremony continues.
#[test]
fn large_blob_not_landed_over_real_member_removes_only_blob() -> TestResult {
    let device = Device::new(true);
    let mut set = device.create()?;
    if let Some(blob) = &device.blob {
        blob.answer_next(NextBlobWrite::Report(BlobWrite::NotWritten));
    }
    let report = compose(&mut set)?;
    assert_eq!(report.platform_account, MemberWrite::Written);
    assert_eq!(
        report.large_blob,
        LargeBlobWrite::NotLanded {
            cause: None,
            clears_by: LargeBlobClearingAct::RemoveConsumingCredential,
        }
    );
    report.completed()?;
    let entry = device
        .platform
        .raw(&credential()?.entry_key())
        .ok_or("no platform entry")?;
    assert_eq!(
        decode_entry(&entry, EntrySource::Synced)?.and_then(|e| e.handle()),
        Some(handle(RecoveryPhase::Composed))
    );
    let record = device
        .platform
        .raw(&credential()?.record_key())
        .ok_or("no record")?;
    assert_eq!(
        decode_store_set_record(&record)?.large_blob,
        LargeBlobMembership::NotMember
    );
    Ok(())
}

/// On a host without the platform-account member, the `largeBlob` member
/// joins a set and the host sees the lease's credential.
#[test]
fn blob_member_fits_an_absent_host_set() -> TestResult {
    let leases = RecoveryLeases::new();
    let lease = lease(&leases)?;
    let slot = Arc::new(BlobSlot::default());
    let members: StoreSetMembers<LocalMap, scp_platform::NoPlatformAccount, _> = StoreSetMembers {
        sdk_local: LocalMap::default(),
        platform_account: PlatformAccountSlot::Absent(
            scp_platform::PlatformAccountAbsence::NoDataApiToCredentialSyncStore,
        ),
        large_blob: Some(CredentialBlobMember::new(Arc::clone(&slot))),
    };
    let mut set = run(StoreSet::create(members, lease))?;
    run(set.compose(RevealKind::FixesCommitment, D1, None))?.completed()?;
    assert_eq!(lock(&slot.credentials).first(), Some(&credential()?));
    Ok(())
}

/// A member holds no credential: every call it makes keys on the credential
/// the set passes from its own lease. Members built before any lease exists
/// read and write only the store of the set's credential. Mutant: the set
/// passes a credential other than its lease's.
#[test]
fn members_key_on_the_credential_of_the_sets_lease() -> TestResult {
    let device = Device::new(true);
    let other = CredentialId::new(vec![0xc2; 64])?;
    let lease = device.leases.acquire(other.clone(), identifier())?;
    let mut set = run(StoreSet::create(device.members(), lease))?;
    compose(&mut set)?.completed()?;
    assert!(device.platform.raw(&other.entry_key()).is_some());
    assert!(device.platform.raw(&other.record_key()).is_some());
    assert_eq!(device.platform.raw(&credential()?.entry_key()), None);
    let blob = device.blob.as_ref().ok_or("no blob slot")?;
    let seen = lock(&blob.credentials).clone();
    assert!(!seen.is_empty());
    assert!(seen.iter().all(|c| *c == other), "{seen:?}");
    Ok(())
}
