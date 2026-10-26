//! Tests for the store set (`09-security-model.md` §9.7.4.2 R10,
//! `17-persistence-and-storage.md` §17.3 and §17.8; SCP-311).
//!
//! Each test names the mutant it kills: a change to the code under test that
//! turns it red. The doubles model what a real member does that a map does
//! not: a stale read (`freeze`), a write acknowledged and lost
//! (`drop_next_write`), a device signed into another account
//! (`switch_account`), a `largeBlob` write that does not land, an evicted
//! `largeBlob` entry, and another device's write landing between this
//! device's read and its write (`before_write`). Hosts are a parameter:
//! `Apple` has the platform-account member, `Android` has none.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Hook = Box<dyn FnOnce() + Send>;

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

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ID: Identifier = Identifier::from_bytes([0x07; 32]);
const FOREIGN: Identifier = Identifier::from_bytes([0x08; 32]);
const D1: [u8; 32] = [0x11; 32];
const D2: [u8; 32] = [0x22; 32];
const D9: [u8; 32] = [0x99; 32];

fn credential() -> CredentialId {
    CredentialId(vec![0xc1; 64])
}

const fn h(digest: [u8; 32], phase: RecoveryPhase) -> RecoveryHandle {
    RecoveryHandle::new(RevealKind::FixesCommitment, ID, phase, digest)
}

const fn m(sequence: u64, digest: [u8; 32]) -> LastRevealMarker {
    LastRevealMarker {
        identifier: ID,
        sequence,
        event_digest: digest,
    }
}

const fn entry(handle: Option<RecoveryHandle>, marker: Option<LastRevealMarker>) -> StoreEntry {
    StoreEntry::new(handle, marker)
}

const fn token(digest: [u8; 32]) -> CosignHold {
    CosignHold::from_cosigner_record(RevealKind::FixesCommitment, digest)
}

fn record(large_blob: LargeBlobMembership) -> StoreSetRecord {
    StoreSetRecord {
        credential_id: credential(),
        large_blob,
    }
}

/// The phase every store holds for `digest`, in the order the store list
/// names.
fn phase_in(entry: Option<StoreEntry>, digest: [u8; 32]) -> Option<RecoveryPhase> {
    entry
        .and_then(|entry| entry.handle())
        .filter(|handle| handle.event_digest() == digest)
        .map(|handle| handle.phase())
}

// ---------------------------------------------------------------------------
// Doubles
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum KeyKind {
    Record,
    Entry,
    Event,
}

/// A synced or local store: one key-value map per account, and the store's
/// faults, which every device's view meets.
#[derive(Default)]
struct Db {
    accounts: Mutex<HashMap<u32, HashMap<String, Vec<u8>>>>,
    fail_read: Mutex<HashSet<KeyKind>>,
    fail_write: Mutex<HashSet<KeyKind>>,
    drop_next_write: AtomicBool,
    writes: AtomicUsize,
}

/// One device's view of a store: the account it is signed into, a stale
/// snapshot it may read, and a write another device lands just before this
/// device's next write.
struct View {
    source: EntrySource,
    account: Mutex<u32>,
    frozen: Mutex<Option<HashMap<String, Vec<u8>>>>,
    before_write: Mutex<Option<Hook>>,
}

/// A local store or a platform-account member.
#[derive(Clone)]
struct ScriptedStore {
    db: Arc<Db>,
    view: Arc<View>,
    credential: CredentialId,
}

impl ScriptedStore {
    fn new(source: EntrySource) -> Self {
        Self::over(Arc::new(Db::default()), source)
    }

    fn over(db: Arc<Db>, source: EntrySource) -> Self {
        Self {
            db,
            view: Arc::new(View {
                source,
                account: Mutex::new(0),
                frozen: Mutex::new(None),
                before_write: Mutex::new(None),
            }),
            credential: credential(),
        }
    }

    /// Another device's view of the same store.
    fn shared_db(&self) -> Self {
        Self::over(Arc::clone(&self.db), self.view.source)
    }

    fn fail_read(&self, kind: KeyKind) {
        lock(&self.db.fail_read).insert(kind);
    }

    fn fail_write(&self, kind: KeyKind) {
        lock(&self.db.fail_write).insert(kind);
    }

    fn heal(&self) {
        lock(&self.db.fail_read).clear();
        lock(&self.db.fail_write).clear();
    }

    /// Reads return the database as it is now until `thaw`.
    fn freeze(&self) {
        let snapshot = self.current();
        *lock(&self.view.frozen) = Some(snapshot);
    }

    fn thaw(&self) {
        *lock(&self.view.frozen) = None;
    }

    fn drop_next_write(&self) {
        self.db.drop_next_write.store(true, Ordering::SeqCst);
    }

    fn before_write(&self, hook: impl FnOnce() + Send + 'static) {
        *lock(&self.view.before_write) = Some(Box::new(hook));
    }

    /// The device signs into an account that holds nothing.
    fn switch_account(&self) {
        *lock(&self.view.account) += 1;
    }

    fn writes(&self) -> usize {
        self.db.writes.load(Ordering::SeqCst)
    }

    fn current(&self) -> HashMap<String, Vec<u8>> {
        let account = *lock(&self.view.account);
        lock(&self.db.accounts)
            .get(&account)
            .cloned()
            .unwrap_or_default()
    }

    fn raw(&self, key: &str) -> Option<Vec<u8>> {
        let frozen = lock(&self.view.frozen).clone();
        frozen.unwrap_or_else(|| self.current()).get(key).cloned()
    }

    fn put_raw(&self, key: &str, bytes: Vec<u8>) {
        let account = *lock(&self.view.account);
        lock(&self.db.accounts)
            .entry(account)
            .or_default()
            .insert(key.to_owned(), bytes);
    }

    fn entry(&self) -> Option<StoreEntry> {
        let bytes = self.raw(&self.credential.entry_key())?;
        decode_entry(&bytes, self.view.source).ok().flatten()
    }

    fn put_entry(&self, entry: &StoreEntry) {
        self.put_raw(&self.credential.entry_key(), encode_entry(entry));
    }

    fn record(&self) -> Option<StoreSetRecord> {
        let bytes = self.raw(&self.credential.record_key())?;
        decode_store_set_record(&bytes).ok()
    }

    fn put_record(&self, record: &StoreSetRecord) {
        self.put_raw(
            &self.credential.record_key(),
            encode_store_set_record(record),
        );
    }

    fn read<T>(
        &self,
        kind: KeyKind,
        key: &str,
        decode: impl FnOnce(&[u8]) -> Result<Option<T>, RecordDecodeError>,
    ) -> MemberRead<T> {
        if lock(&self.db.fail_read).contains(&kind) {
            return MemberRead::NotReached(NotReachedCause::Unreachable {
                cause: "injected read failure".to_owned(),
            });
        }
        self.raw(key)
            .map_or(MemberRead::ReachedEmpty, |bytes| match decode(&bytes) {
                Ok(Some(value)) => MemberRead::Reached(value),
                Ok(None) => MemberRead::ReachedEmpty,
                Err(error) => MemberRead::NotReached(NotReachedCause::Undecodable(error)),
            })
    }

    fn write(&self, kind: KeyKind, key: &str, bytes: Vec<u8>) -> Result<(), StoreWriteFailure> {
        let hook = lock(&self.view.before_write).take();
        if let Some(hook) = hook {
            hook();
        }
        if lock(&self.db.fail_write).contains(&kind) {
            return Err(StoreWriteFailure {
                cause: "injected write failure".to_owned(),
            });
        }
        if self.db.drop_next_write.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        self.db.writes.fetch_add(1, Ordering::SeqCst);
        self.put_raw(key, bytes);
        Ok(())
    }
}

impl RecoveryHandleStore for ScriptedStore {
    type WriteFailure = StoreWriteFailure;

    async fn read_entry(&self) -> MemberRead<StoreEntry> {
        let source = self.view.source;
        self.read(KeyKind::Entry, &self.credential.entry_key(), |bytes| {
            decode_entry(bytes, source)
        })
    }

    async fn write_entry(&self, entry: &StoreEntry) -> Result<(), StoreWriteFailure> {
        self.write(
            KeyKind::Entry,
            &self.credential.entry_key(),
            encode_entry(entry),
        )
    }
}

impl RecoveryEventStore for ScriptedStore {
    async fn read_event(&self, event_digest: &[u8; 32]) -> MemberRead<Vec<u8>> {
        self.read(
            KeyKind::Event,
            &self.credential.event_key(event_digest),
            |bytes| check_event_length(bytes).map(|()| Some(bytes.to_vec())),
        )
    }

    async fn write_event(
        &self,
        event_digest: &[u8; 32],
        event: &[u8],
    ) -> Result<(), StoreWriteFailure> {
        self.write(
            KeyKind::Event,
            &self.credential.event_key(event_digest),
            event.to_vec(),
        )
    }
}

impl RecoveryRecordStore for ScriptedStore {
    async fn read_record(&self) -> MemberRead<StoreSetRecord> {
        self.read(KeyKind::Record, &self.credential.record_key(), |bytes| {
            decode_store_set_record(bytes).map(Some)
        })
    }

    async fn write_record(&self, record: &StoreSetRecord) -> Result<(), StoreWriteFailure> {
        self.write(
            KeyKind::Record,
            &self.credential.record_key(),
            encode_store_set_record(record),
        )
    }
}

/// The credential's `largeBlob` store: one value every device shares, and
/// the store's faults.
#[derive(Default)]
struct BlobDb {
    bytes: Mutex<Option<Vec<u8>>>,
    not_landed_next: Mutex<Option<LargeBlobClearingAct>>,
    fail_read: AtomicBool,
    writes: AtomicUsize,
}

/// One device's handle on the `largeBlob` store.
#[derive(Default)]
struct BlobView {
    before_write: Mutex<Option<Hook>>,
}

#[derive(Clone, Default)]
struct ScriptedBlob {
    db: Arc<BlobDb>,
    view: Arc<BlobView>,
}

impl ScriptedBlob {
    /// Another device's handle on the same `largeBlob` store.
    fn shared(&self) -> Self {
        Self {
            db: Arc::clone(&self.db),
            view: Arc::new(BlobView::default()),
        }
    }

    fn not_landed_next(&self, clears_by: LargeBlobClearingAct) {
        *lock(&self.db.not_landed_next) = Some(clears_by);
    }

    fn fail_read(&self, on: bool) {
        self.db.fail_read.store(on, Ordering::SeqCst);
    }

    fn before_write(&self, hook: impl FnOnce() + Send + 'static) {
        *lock(&self.view.before_write) = Some(Box::new(hook));
    }

    /// The authenticator drops the entry.
    fn evict(&self) {
        *lock(&self.db.bytes) = None;
    }

    /// The store holds `entry`, as another device's landed write left it.
    fn serve(&self, entry: &StoreEntry) {
        *lock(&self.db.bytes) = Some(encode_entry(entry));
    }

    fn bytes(&self) -> Option<Vec<u8>> {
        lock(&self.db.bytes).clone()
    }

    fn entry(&self) -> Option<StoreEntry> {
        decode_entry(&self.bytes()?, EntrySource::Synced)
            .ok()
            .flatten()
    }

    fn writes(&self) -> usize {
        self.db.writes.load(Ordering::SeqCst)
    }
}

impl RecoveryHandleStore for ScriptedBlob {
    type WriteFailure = LargeBlobNotLanded;

    async fn read_entry(&self) -> MemberRead<StoreEntry> {
        if self.db.fail_read.load(Ordering::SeqCst) {
            return MemberRead::NotReached(NotReachedCause::Unreachable {
                cause: "injected largeBlob read failure".to_owned(),
            });
        }
        self.bytes().map_or(MemberRead::ReachedEmpty, |bytes| {
            match decode_entry(&bytes, EntrySource::Synced) {
                Ok(Some(entry)) => MemberRead::Reached(entry),
                Ok(None) => MemberRead::ReachedEmpty,
                Err(error) => MemberRead::NotReached(NotReachedCause::Undecodable(error)),
            }
        })
    }

    async fn write_entry(&self, entry: &StoreEntry) -> Result<(), LargeBlobNotLanded> {
        let hook = lock(&self.view.before_write).take();
        if let Some(hook) = hook {
            hook();
        }
        let not_landed = lock(&self.db.not_landed_next).take();
        if let Some(clears_by) = not_landed {
            return Err(LargeBlobNotLanded {
                cause: None,
                clears_by,
            });
        }
        self.db.writes.fetch_add(1, Ordering::SeqCst);
        *lock(&self.db.bytes) = Some(encode_entry(entry));
        Ok(())
    }
}

struct TestLease {
    credential: CredentialId,
    identifier: Identifier,
}

impl SetLease for TestLease {
    fn credential_id(&self) -> &CredentialId {
        &self.credential
    }

    fn identifier(&self) -> Identifier {
        self.identifier
    }
}

fn lease() -> TestLease {
    TestLease {
        credential: credential(),
        identifier: ID,
    }
}

type Set = StoreSet<ScriptedStore, ScriptedStore, ScriptedBlob, TestLease>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Host {
    /// The host's row gives the platform-account member.
    Apple,
    /// The host's row gives none.
    Android,
}

const HOSTS: [Host; 2] = [Host::Apple, Host::Android];

/// The stores one credential has across every device.
struct World {
    host: Host,
    platform: ScriptedStore,
    blob: ScriptedBlob,
}

/// One device: its own local store and its own handles on the shared stores.
struct Device {
    host: Host,
    local: ScriptedStore,
    platform: ScriptedStore,
    blob: Option<ScriptedBlob>,
    platform_handle: bool,
}

impl World {
    fn new(host: Host) -> Self {
        Self {
            host,
            platform: ScriptedStore::new(EntrySource::Synced),
            blob: ScriptedBlob::default(),
        }
    }

    fn device(&self) -> Device {
        Device {
            host: self.host,
            local: ScriptedStore::new(EntrySource::SdkLocal),
            platform: self.platform.shared_db(),
            blob: Some(self.blob.shared()),
            platform_handle: true,
        }
    }

    fn device_without_blob(&self) -> Device {
        Device {
            blob: None,
            ..self.device()
        }
    }

    /// A device on an `Apple` world whose first device created the record.
    fn created(host: Host) -> Result<(Self, Device), RecoveryStoreError> {
        let world = Self::new(host);
        let device = world.device();
        drop(device.create()?);
        Ok((world, device))
    }
}

impl Device {
    fn members(&self) -> StoreSetMembers<ScriptedStore, ScriptedStore, ScriptedBlob> {
        let platform_account = match (self.host, self.platform_handle) {
            (Host::Apple, true) => PlatformAccountSlot::Present(self.platform.clone()),
            (Host::Apple, false) => PlatformAccountSlot::PresentWithoutHandle,
            (Host::Android, _) => {
                PlatformAccountSlot::Absent(PlatformAccountAbsence::NoDataApiToCredentialSyncStore)
            }
        };
        StoreSetMembers {
            sdk_local: self.local.clone(),
            platform_account,
            large_blob: self.blob.clone(),
        }
    }

    fn create(&self) -> Result<Set, RecoveryStoreError> {
        run(StoreSet::create(self.members(), lease()))
    }

    fn open(&self) -> Result<Set, RecoveryStoreError> {
        run(StoreSet::open(self.members(), lease()))
    }

    fn blob(&self) -> Result<&ScriptedBlob, String> {
        self.blob
            .as_ref()
            .ok_or_else(|| "device has no blob".to_owned())
    }
}

/// Composes `digest` with `basis` and expects the ceremony to continue.
fn compose(set: &mut Set, digest: [u8; 32], basis: Option<LastRevealMarker>) -> TestResult {
    run(set.compose(RevealKind::FixesCommitment, digest, basis))?.completed()?;
    Ok(())
}

fn advance(set: &mut Set, digest: [u8; 32], target: AdvanceTarget) -> TestResult {
    run(set.advance(digest, target))?.completed()?;
    Ok(())
}

/// Runs a whole ceremony for `digest` and completes it at `sequence`.
fn ceremony(
    set: &mut Set,
    digest: [u8; 32],
    basis: Option<LastRevealMarker>,
    sequence: u64,
) -> TestResult {
    compose(set, digest, basis)?;
    advance(set, digest, AdvanceTarget::Signed)?;
    advance(set, digest, AdvanceTarget::PublishSent)?;
    advance(set, digest, AdvanceTarget::Confirmed)?;
    let report = run(set.complete(sequence, digest))?;
    assert!(
        report.per_store.iter().all(MemberRemoval::removed),
        "{report:?}"
    );
    Ok(())
}

fn unreadable(store: CredentialStore, cause: NotReachedCause) -> RecoveryStoreError {
    RecoveryStoreError::StorePartiallyUnreadable { store, cause }
}

fn injected(store: CredentialStore) -> RecoveryStoreError {
    unreadable(
        store,
        NotReachedCause::Unreachable {
            cause: "injected read failure".to_owned(),
        },
    )
}

// ---------------------------------------------------------------------------
// Codecs (mutants I and K, and the decoder refusals)
// ---------------------------------------------------------------------------

/// Mutant I: swap the `largeBlob` byte values.
#[test]
fn store_set_record_has_fixed_bytes() -> TestResult {
    let member = encode_store_set_record(&record(LargeBlobMembership::Member));
    assert_eq!(member[..4], [0x01, 0x01, 0x00, 0x40]);
    assert_eq!(&member[4..], &[0xc1; 64][..]);
    let not_member = encode_store_set_record(&record(LargeBlobMembership::NotMember));
    assert_eq!(not_member[..4], [0x01, 0x00, 0x00, 0x40]);
    assert_eq!(
        decode_store_set_record(&member)?,
        record(LargeBlobMembership::Member)
    );
    assert_eq!(
        decode_store_set_record(&not_member)?,
        record(LargeBlobMembership::NotMember)
    );
    Ok(())
}

#[test]
fn store_set_record_decoder_refuses_every_malformed_input() {
    let good = encode_store_set_record(&record(LargeBlobMembership::Member));
    let mut version = good.clone();
    version[0] = 0x02;
    assert_eq!(
        decode_store_set_record(&version),
        Err(RecordDecodeError::UnknownVersion(0x02))
    );
    let mut large_blob = good.clone();
    large_blob[1] = 0x02;
    assert_eq!(
        decode_store_set_record(&large_blob),
        Err(RecordDecodeError::UnknownLargeBlobMembership(0x02))
    );
    assert_eq!(
        decode_store_set_record(&[0x01, 0x00, 0x00, 0x00]),
        Err(RecordDecodeError::CredentialIdLength(0))
    );
    let mut too_long = vec![0x01, 0x00, 0x04, 0x00];
    too_long.extend_from_slice(&[0xaa; 1024]);
    assert_eq!(
        decode_store_set_record(&too_long),
        Err(RecordDecodeError::CredentialIdLength(1024))
    );
    assert_eq!(
        decode_store_set_record(&good[..67]),
        Err(RecordDecodeError::WrongLength {
            expected: 68,
            actual: 67
        })
    );
    let mut long = good;
    long.push(0x00);
    assert_eq!(
        decode_store_set_record(&long),
        Err(RecordDecodeError::WrongLength {
            expected: 68,
            actual: 69
        })
    );
    assert_eq!(
        decode_store_set_record(&[0x01, 0x01]),
        Err(RecordDecodeError::WrongLength {
            expected: 4,
            actual: 2
        })
    );
}

/// Mutant K: a raw identifier in the key.
#[test]
fn keys_are_the_hashed_credential() {
    let component = "4891e00a13c5813f53b9e832a034ece86ff4dd143dd876287c830949e0f31115";
    let credential = credential();
    assert_eq!(
        credential.entry_key(),
        format!("recovery/{component}/entry")
    );
    assert_eq!(
        credential.record_key(),
        format!("recovery/{component}/record")
    );
    assert_eq!(
        credential.event_key(&[0xab; 32]),
        format!("recovery/{component}/event/{}", "ab".repeat(32))
    );
}

#[test]
fn credential_id_is_bounded() {
    assert_eq!(CredentialId::new(Vec::new()), Err(CredentialIdError::Empty));
    assert_eq!(
        CredentialId::new(vec![0; 1024]),
        Err(CredentialIdError::TooLong { len: 1024 })
    );
    assert!(CredentialId::new(vec![0; 1023]).is_ok());
}

#[test]
fn handle_and_marker_have_fixed_bytes() -> TestResult {
    let handle = RecoveryHandle::new(RevealKind::Abandons, ID, RecoveryPhase::PublishSent, D1);
    let bytes = encode_handle(&handle);
    assert_eq!(bytes[0], 0x01);
    assert_eq!(bytes[1..33], [0x07; 32]);
    assert_eq!(bytes[33], 0x02);
    assert_eq!(bytes[34..], [0x11; 32]);
    assert_eq!(decode_handle(&bytes)?, handle);
    let marker = m(0x0102_0304_0506_0708, D2);
    let bytes = encode_marker(&marker);
    assert_eq!(bytes[32..40], [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(decode_marker(&bytes)?, marker);
    let mut variant = encode_handle(&handle);
    variant[0] = 0x02;
    assert_eq!(
        decode_handle(&variant),
        Err(RecordDecodeError::UnknownVariant(0x02))
    );
    let mut phase = encode_handle(&handle);
    phase[33] = 0x06;
    assert_eq!(
        decode_handle(&phase),
        Err(RecordDecodeError::UnknownPhase(0x06))
    );
    assert_eq!(
        decode_handle(&[0; 65]),
        Err(RecordDecodeError::WrongLength {
            expected: 66,
            actual: 65
        })
    );
    Ok(())
}

#[test]
fn entry_encodes_flags_and_round_trips() -> TestResult {
    assert_eq!(encode_entry(&StoreEntry::EMPTY), vec![0x00]);
    assert_eq!(decode_entry(&[0x00], EntrySource::Synced)?, None);
    let handle = h(D1, RecoveryPhase::Signed);
    let marker = m(4, D2);
    for (stored, flags, len) in [
        (entry(Some(handle), None), 0x01, 67),
        (entry(None, Some(marker)), 0x02, 73),
        (entry(Some(handle), Some(marker)), 0x03, 139),
    ] {
        let bytes = encode_entry(&stored);
        assert_eq!((bytes[0], bytes.len()), (flags, len));
        assert_eq!(decode_entry(&bytes, EntrySource::Synced)?, Some(stored));
    }
    let skipped = StoreEntry::large_blob_skipped(handle, Some(marker));
    let bytes = encode_entry(&skipped);
    assert_eq!(bytes[0], 0x07);
    assert_eq!(decode_entry(&bytes, EntrySource::SdkLocal)?, Some(skipped));
    Ok(())
}

/// L2: bit 2 in a synced member's entry does not decode, and the reserved
/// bits, bit 2 without a handle and every wrong length refuse.
#[test]
fn entry_decoder_refuses_every_malformed_input() {
    let handle = h(D1, RecoveryPhase::Composed);
    let skipped = encode_entry(&StoreEntry::large_blob_skipped(handle, None));
    assert_eq!(
        decode_entry(&skipped, EntrySource::Synced),
        Err(RecordDecodeError::SkipInSyncedMember)
    );
    assert_eq!(
        decode_entry(&[0x04], EntrySource::SdkLocal),
        Err(RecordDecodeError::SkipWithoutHandle(0x04))
    );
    for flags in [0x08, 0x10, 0x80] {
        assert_eq!(
            decode_entry(&[flags], EntrySource::SdkLocal),
            Err(RecordDecodeError::UnknownFlags(flags))
        );
    }
    assert_eq!(
        decode_entry(&[], EntrySource::SdkLocal),
        Err(RecordDecodeError::WrongLength {
            expected: 1,
            actual: 0
        })
    );
    let mut long = encode_entry(&entry(Some(handle), None));
    long.push(0);
    assert_eq!(
        decode_entry(&long, EntrySource::SdkLocal),
        Err(RecordDecodeError::WrongLength {
            expected: 67,
            actual: 68
        })
    );
    assert_eq!(
        decode_entry(&[0x03; 100], EntrySource::SdkLocal),
        Err(RecordDecodeError::WrongLength {
            expected: 139,
            actual: 100
        })
    );
}

#[test]
fn event_length_is_bounded() {
    assert_eq!(
        check_event_length(&[]),
        Err(RecordDecodeError::EventLength(0))
    );
    assert_eq!(check_event_length(&vec![0; 65_536]), Ok(()));
    assert_eq!(
        check_event_length(&vec![0; 65_537]),
        Err(RecordDecodeError::EventLength(65_537))
    );
}

// ---------------------------------------------------------------------------
// Membership (mutants A, E, F′, G, H′, M1, M2, M8, M10, M14, M20)
// ---------------------------------------------------------------------------

/// Mutant A: drop the `largeBlob` handle check. The record names the store
/// and this device holds no handle on it, so every operation refuses.
#[test]
fn record_names_large_blob_and_device_has_no_handle() -> TestResult {
    let (world, _) = World::created(Host::Apple)?;
    world
        .platform
        .put_record(&record(LargeBlobMembership::Member));
    let device = world.device_without_blob();
    let expected = unreadable(CredentialStore::LargeBlob, NotReachedCause::NoStoreOnDevice);
    assert_eq!(device.open().err(), Some(expected.clone()));
    world
        .platform
        .put_record(&record(LargeBlobMembership::NotMember));
    let mut set = device.open()?;
    world
        .platform
        .put_record(&record(LargeBlobMembership::Member));
    assert_eq!(
        run(set.compose(RevealKind::FixesCommitment, D1, None)).err(),
        Some(expected)
    );
    assert_eq!(world.platform.entry(), None);
    Ok(())
}

/// The host gives the member and the device holds no handle on it.
#[test]
fn present_without_handle_refuses() {
    let world = World::new(Host::Apple);
    let device = Device {
        platform_handle: false,
        ..world.device()
    };
    let expected = unreadable(
        CredentialStore::PlatformAccount,
        NotReachedCause::NoStoreOnDevice,
    );
    assert_eq!(device.create().err(), Some(expected.clone()));
    assert_eq!(device.open().err(), Some(expected));
}

/// Mutant E: drop the credential check on the record.
#[test]
fn foreign_record_refuses() -> TestResult {
    let world = World::new(Host::Apple);
    world.platform.put_record(&StoreSetRecord {
        credential_id: CredentialId::new(vec![0xd2; 16])?,
        large_blob: LargeBlobMembership::NotMember,
    });
    let device = world.device();
    assert_eq!(
        device.open().err(),
        Some(RecoveryStoreError::RecordCredentialMismatch)
    );
    assert_eq!(
        device.create().err(),
        Some(RecoveryStoreError::RecordAlreadyWritten)
    );
    Ok(())
}

/// Mutant F′: an `Absent`-host `largeBlob` read that fails is read as empty.
#[test]
fn absent_host_large_blob_read_failure_refuses() -> TestResult {
    let world = World::new(Host::Android);
    let device = world.device();
    let mut set = device.open()?;
    device.blob()?.fail_read(true);
    let expected = unreadable(
        CredentialStore::LargeBlob,
        NotReachedCause::Unreachable {
            cause: "injected largeBlob read failure".to_owned(),
        },
    );
    assert_eq!(run(set.read_set()).err(), Some(expected.clone()));
    assert_eq!(
        run(set.compose(RevealKind::FixesCommitment, D1, None)).err(),
        Some(expected)
    );
    assert_eq!(device.local.entry(), None);
    Ok(())
}

/// A `Present` host tolerates a failed read of a store its record names as
/// not a member, and never writes that store.
#[test]
fn present_host_ignores_unreadable_non_member_blob() -> TestResult {
    let (_, device) = World::created(Host::Apple)?;
    let mut set = device.open()?;
    device.blob()?.fail_read(true);
    let report = run(set.compose(RevealKind::FixesCommitment, D1, None))?;
    report.completed()?;
    assert!(
        matches!(report.large_blob, LargeBlobWrite::Unread { .. }),
        "{report:?}"
    );
    assert_eq!(device.blob()?.writes(), 0);
    assert_eq!(
        phase_in(device.local.entry(), D1),
        Some(RecoveryPhase::Composed)
    );
    Ok(())
}

/// Mutant G: platform `NotReached` becomes `HoldsNoRecord` or `None`.
#[test]
fn platform_record_read_failure_is_unreachable() -> TestResult {
    let (world, device) = World::created(Host::Apple)?;
    let set = device.open()?;
    world.platform.fail_read(KeyKind::Record);
    assert_eq!(
        device.open().err(),
        Some(injected(CredentialStore::PlatformAccount))
    );
    assert_eq!(
        run(set.read_set()).err(),
        Some(injected(CredentialStore::PlatformAccount))
    );
    Ok(())
}

/// Mutant H′: `create` treats platform `NotReached` as empty.
#[test]
fn create_refuses_an_unreached_record_and_writes_nothing() {
    let world = World::new(Host::Apple);
    world.platform.fail_read(KeyKind::Record);
    assert_eq!(
        world.device().create().err(),
        Some(injected(CredentialStore::PlatformAccount))
    );
    assert_eq!(world.platform.writes(), 0);
    world.platform.heal();
    assert_eq!(world.platform.record(), None);
}

/// `create` writes `NotMember` once; on a host without the member it writes
/// nothing.
#[test]
fn create_writes_the_record_only_where_the_member_exists() -> TestResult {
    let (world, _) = World::created(Host::Apple)?;
    assert_eq!(
        world.platform.record(),
        Some(record(LargeBlobMembership::NotMember))
    );
    let android = World::new(Host::Android);
    let device = android.device();
    drop(device.create()?);
    assert_eq!(android.platform.writes() + device.local.writes(), 0);
    Ok(())
}

/// Mutant M10: `create` clobbers an existing record.
#[test]
fn create_keeps_an_existing_member_record() -> TestResult {
    let (world, first) = World::created(Host::Apple)?;
    compose(&mut first.open()?, D1, None)?;
    assert_eq!(
        world.platform.record(),
        Some(record(LargeBlobMembership::Member))
    );
    let writes = world.platform.writes();
    drop(world.device().create()?);
    assert_eq!(
        world.platform.record(),
        Some(record(LargeBlobMembership::Member))
    );
    assert_eq!(world.platform.writes(), writes);
    Ok(())
}

/// Mutant M1: restore any record cache. One open set sees every membership
/// change another device makes, in both directions.
#[test]
fn membership_is_read_afresh_on_every_operation() -> TestResult {
    let (world, a) = World::created(Host::Apple)?;
    let b = world.device_without_blob();
    let mut set_a = a.open()?;
    let set_b = b.open()?;
    assert!(run(set_b.read_set())?.pending().is_empty());
    ceremony(&mut set_a, D1, None, 1)?;
    assert_eq!(
        world.platform.record(),
        Some(record(LargeBlobMembership::Member))
    );
    assert_eq!(
        run(set_b.read_set()).err(),
        Some(unreadable(
            CredentialStore::LargeBlob,
            NotReachedCause::NoStoreOnDevice
        ))
    );
    a.blob()?
        .not_landed_next(LargeBlobClearingAct::RetryVerification);
    compose(&mut set_a, D2, Some(m(1, D1)))?;
    assert_eq!(
        world.platform.record(),
        Some(record(LargeBlobMembership::NotMember))
    );
    let read = run(set_b.read_set())?;
    assert_eq!(read.pending(), vec![h(D2, RecoveryPhase::Composed)]);
    Ok(())
}

/// Mutant M2: read `largeBlob` only where a record names it. On a host
/// without the member, a second device reads the first device's handle in
/// the shared `largeBlob` store and composes nothing.
#[test]
fn absent_host_second_device_reads_the_shared_large_blob() -> TestResult {
    let world = World::new(Host::Android);
    compose(&mut world.device().open()?, D1, None)?;
    let b = world.device();
    let mut set_b = b.open()?;
    assert_eq!(
        run(set_b.compose(RevealKind::FixesCommitment, D2, None)).err(),
        Some(RecoveryStoreError::RevealAlreadyPending)
    );
    assert_eq!(b.local.entry(), None);
    assert_eq!(
        phase_in(world.blob.entry(), D1),
        Some(RecoveryPhase::Composed)
    );
    Ok(())
}

/// Mutant M8: `HoldsNoRecord` is read as empty.
#[test]
fn account_switch_refuses_with_holds_no_record() -> TestResult {
    let (_, device) = World::created(Host::Apple)?;
    let set = device.open()?;
    device.platform.switch_account();
    assert_eq!(
        run(set.read_set()).err(),
        Some(unreadable(
            CredentialStore::PlatformAccount,
            NotReachedCause::HoldsNoRecord
        ))
    );
    Ok(())
}

/// Mutant M14: no identity check.
#[test]
fn an_entry_naming_another_identity_is_not_reached() -> TestResult {
    let world = World::new(Host::Android);
    let device = world.device();
    let set = device.open()?;
    world.blob.serve(&entry(
        Some(RecoveryHandle::new(
            RevealKind::FixesCommitment,
            FOREIGN,
            RecoveryPhase::Composed,
            D1,
        )),
        None,
    ));
    let expected = unreadable(CredentialStore::LargeBlob, NotReachedCause::ForeignIdentity);
    assert_eq!(run(set.read_set()).err(), Some(expected));
    world.blob.evict();
    device.local.put_entry(&entry(
        None,
        Some(LastRevealMarker {
            identifier: FOREIGN,
            ..m(1, D1)
        }),
    ));
    assert_eq!(
        run(set.read_set()).err(),
        Some(unreadable(
            CredentialStore::SdkLocal,
            NotReachedCause::ForeignIdentity
        ))
    );
    Ok(())
}

/// L2 at the set: a synced member whose bytes set the skip bit is not
/// reached.
#[test]
fn a_synced_entry_with_the_skip_bit_is_not_reached() -> TestResult {
    let world = World::new(Host::Android);
    let set = world.device().open()?;
    *lock(&world.blob.db.bytes) = Some(encode_entry(&StoreEntry::large_blob_skipped(
        h(D1, RecoveryPhase::Composed),
        None,
    )));
    assert_eq!(
        run(set.read_set()).err(),
        Some(unreadable(
            CredentialStore::LargeBlob,
            NotReachedCause::Undecodable(RecordDecodeError::SkipInSyncedMember)
        ))
    );
    Ok(())
}

/// Mutant M20: keep requiring a local record on a host without the member.
/// A second device, the creating device after a reinstall, and a browser
/// after clearing its storage each open and compose.
#[test]
fn absent_host_devices_without_local_state_compose() -> TestResult {
    for scenario in ["second device", "reinstall", "browser cleared"] {
        let world = World::new(Host::Android);
        let creator = world.device();
        drop(creator.create()?);
        ceremony(&mut creator.open()?, D1, None, 1)?;
        let device = match scenario {
            "second device" => world.device(),
            _ => Device {
                local: ScriptedStore::new(EntrySource::SdkLocal),
                ..creator
            },
        };
        let mut set = device.open()?;
        compose(&mut set, D2, Some(m(1, D1)))?;
        assert_eq!(
            device.local.entry(),
            Some(entry(Some(h(D2, RecoveryPhase::Composed)), Some(m(1, D1)))),
            "{scenario}"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Reads (mutants D, J, M9, M17)
// ---------------------------------------------------------------------------

/// Mutant D: `read_event` turns platform `NotReached` into `None`.
#[test]
fn read_event_refuses_an_unreached_platform_member() -> TestResult {
    let (world, device) = World::created(Host::Apple)?;
    let set = device.open()?;
    world.platform.fail_read(KeyKind::Event);
    assert_eq!(
        run(set.read_event(&D1)).err(),
        Some(injected(CredentialStore::PlatformAccount))
    );
    Ok(())
}

/// Mutant M9: `read_event` reads the device's slot instead of the
/// membership step. Where the record the member holds refuses (the account
/// holds no record, or it names a `largeBlob` store this device has no
/// handle on), `read_event` refuses even though the local store answers
/// empty. It returns the platform copy where the local store has none, and
/// on a host without the member it answers from the local store alone.
#[test]
fn read_event_goes_through_membership() -> TestResult {
    let (world, device) = World::created(Host::Apple)?;
    let set = device.open()?;
    run(set.write_event(&D1, b"signed"))?;
    let other = world.device_without_blob();
    let other_set = other.open()?;
    assert_eq!(run(other_set.read_event(&D1))?, Some(b"signed".to_vec()));
    world
        .platform
        .put_record(&record(LargeBlobMembership::Member));
    assert_eq!(
        run(other_set.read_event(&D2)),
        Err(unreadable(
            CredentialStore::LargeBlob,
            NotReachedCause::NoStoreOnDevice
        ))
    );
    other.platform.switch_account();
    assert_eq!(
        run(other_set.read_event(&D2)),
        Err(unreadable(
            CredentialStore::PlatformAccount,
            NotReachedCause::HoldsNoRecord
        ))
    );
    let android = World::new(Host::Android);
    let device = android.device();
    let set = device.open()?;
    android.platform.fail_read(KeyKind::Event);
    assert_eq!(run(set.read_event(&D1))?, None);
    device
        .local
        .put_raw(&credential().event_key(&D1), b"local".to_vec());
    assert_eq!(run(set.read_event(&D1))?, Some(b"local".to_vec()));
    Ok(())
}

/// `write_event` refuses a length outside 1..=`MAX_EVENT_BYTES` and
/// stores the event in the platform-account member and the local store.
#[test]
fn write_event_checks_length_and_reaches_both_event_stores() -> TestResult {
    let (world, device) = World::created(Host::Apple)?;
    let set = device.open()?;
    assert_eq!(
        run(set.write_event(&D1, &[])),
        Err(RecoveryStoreError::EventLength { len: 0 })
    );
    assert_eq!(
        run(set.write_event(&D1, &vec![0; 65_537])),
        Err(RecoveryStoreError::EventLength { len: 65_537 })
    );
    run(set.write_event(&D1, &vec![0; 65_536]))?;
    let key = credential().event_key(&D1);
    assert_eq!(world.platform.raw(&key).map(|e| e.len()), Some(65_536));
    assert_eq!(device.local.raw(&key).map(|e| e.len()), Some(65_536));
    world.platform.fail_write(KeyKind::Event);
    assert!(matches!(
        run(set.write_event(&D2, b"e")),
        Err(RecoveryStoreError::PlatformAccountWriteFailed { .. })
    ));
    assert_eq!(device.local.raw(&credential().event_key(&D2)), None);
    Ok(())
}

/// Mutant J: every per-store read returns the local entry. A write the
/// platform acknowledged and lost is caught by its read-back, and an
/// evicted `largeBlob` entry is read as the store holds it.
#[test]
fn each_store_is_read_for_itself() -> TestResult {
    let (world, device) = World::created(Host::Apple)?;
    let mut set = device.open()?;
    world.platform.drop_next_write();
    let report = run(set.compose(RevealKind::FixesCommitment, D1, None))?;
    assert!(matches!(
        report.completed(),
        Err(RecoveryStoreError::PlatformAccountWriteFailed { .. })
    ));
    assert_eq!(world.platform.entry(), None);
    assert_eq!(world.blob.entry(), None);
    assert_eq!(device.local.entry(), None);

    let android = World::new(Host::Android);
    let device = android.device();
    let mut set = device.open()?;
    compose(&mut set, D1, None)?;
    android.blob.evict();
    let read = run(set.read_set())?;
    let per_store: Vec<(CredentialStore, Option<RecoveryPhase>, bool)> = read
        .per_store()
        .iter()
        .map(|read| (read.store, phase_in(Some(read.entry), D1), read.member))
        .collect();
    assert_eq!(
        per_store,
        vec![
            (CredentialStore::LargeBlob, None, false),
            (
                CredentialStore::SdkLocal,
                Some(RecoveryPhase::Composed),
                true
            ),
        ]
    );
    assert_eq!(
        run(set.confirm_pending(&D1)),
        Err(RecoveryStoreError::HandleGone)
    );
    Ok(())
}

/// Mutant M17: `confirm_pending` accepts `Lost`. Another device moves the
/// handle to `Lost` between this device's confirm check and its pre-publish
/// re-read.
#[test]
fn confirm_pending_refuses_a_handle_another_device_lost() -> TestResult {
    for host in HOSTS {
        let (world, a) = World::created(host)?;
        let mut set_a = a.open()?;
        compose(&mut set_a, D1, None)?;
        advance(&mut set_a, D1, AdvanceTarget::Signed)?;
        assert_eq!(
            run(set_a.confirm_pending(&D1))?,
            h(D1, RecoveryPhase::Signed)
        );
        advance(&mut world.device().open()?, D1, AdvanceTarget::Lost)?;
        assert_eq!(
            run(set_a.confirm_pending(&D1)),
            Err(RecoveryStoreError::HandleGone),
            "{host:?}"
        );
    }
    Ok(())
}

/// `confirm_pending` refuses beside another pending handle, and `pending`
/// reports each digest at its merged phase.
#[test]
fn confirm_pending_refuses_beside_another_pending_handle() -> TestResult {
    let (world, device) = World::created(Host::Apple)?;
    let mut set = device.open()?;
    compose(&mut set, D1, None)?;
    world
        .blob
        .serve(&entry(Some(h(D2, RecoveryPhase::Composed)), None));
    assert_eq!(
        run(set.confirm_pending(&D1)),
        Err(RecoveryStoreError::HandleGone)
    );
    let pending = run(set.read_set())?.pending();
    assert_eq!(
        pending,
        vec![
            h(D1, RecoveryPhase::Composed),
            h(D2, RecoveryPhase::Composed)
        ]
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// compose and hold (mutants B, C′, M4, M12, M15, M22, M25, M27, M28, M31)
// ---------------------------------------------------------------------------

/// Mutant B: discard the record-write error during a membership flip.
#[test]
fn record_write_failure_during_a_flip_stops() -> TestResult {
    let (world, device) = World::created(Host::Apple)?;
    let mut set = device.open()?;
    world.platform.fail_write(KeyKind::Record);
    let report = run(set.compose(RevealKind::FixesCommitment, D1, None))?;
    assert_eq!(
        report.completed(),
        Err(RecoveryStoreError::PlatformAccountWriteFailed {
            cause: "injected write failure".to_owned()
        })
    );
    assert_eq!(
        world.platform.record(),
        Some(record(LargeBlobMembership::NotMember))
    );
    Ok(())
}

/// Mutant C′: discard the local entry-write error.
#[test]
fn local_write_failure_stops() -> TestResult {
    for host in HOSTS {
        let (_, device) = World::created(host)?;
        let mut set = device.open()?;
        device.local.fail_write(KeyKind::Entry);
        let report = run(set.compose(RevealKind::FixesCommitment, D1, None))?;
        assert_eq!(
            report.completed(),
            Err(RecoveryStoreError::SdkLocalWriteFailed {
                cause: "injected write failure".to_owned()
            }),
            "{host:?}"
        );
        assert_eq!(report.record, MemberWrite::NotAttempted);
    }
    Ok(())
}

/// Mutant M4: allow a live handle another device composed to be
/// overwritten. Another device's composition lands after this device opened
/// its set; this device's `compose` refuses before any write.
#[test]
fn compose_refuses_beside_another_devices_live_handle() -> TestResult {
    for host in HOSTS {
        let (world, a) = World::created(host)?;
        let mut set_a = a.open()?;
        compose(&mut world.device().open()?, D2, None)?;
        let blob_writes = world.blob.writes();
        assert_eq!(
            run(set_a.compose(RevealKind::FixesCommitment, D1, None)).err(),
            Some(RecoveryStoreError::RevealAlreadyPending),
            "{host:?}"
        );
        assert_eq!(
            phase_in(world.blob.entry(), D2),
            Some(RecoveryPhase::Composed)
        );
        assert_eq!(world.blob.writes(), blob_writes);
        assert_eq!(a.local.entry(), None);
    }
    Ok(())
}

/// Mutant M25: `compose` accepts the same digest twice. The first
/// composition is terminal, so only the digest rule refuses the second.
#[test]
fn compose_refuses_a_digest_any_store_holds() -> TestResult {
    let (_, device) = World::created(Host::Apple)?;
    let mut set = device.open()?;
    compose(&mut set, D1, None)?;
    advance(&mut set, D1, AdvanceTarget::Discarded)?;
    assert_eq!(
        run(set.compose(RevealKind::FixesCommitment, D1, None)).err(),
        Some(RecoveryStoreError::RevealAlreadyPending)
    );
    Ok(())
}

/// Mutant M15: drop the `basis` check. P1's interleaving: A composes `d1`
/// and stops before its local write; B aborts `d1`, composes `d2`, and
/// completes it; A's second `compose(d1)` refuses.
#[test]
fn compose_refuses_where_the_marker_moved() -> TestResult {
    let (world, a) = World::created(Host::Apple)?;
    let mut set_a = a.open()?;
    a.local.fail_write(KeyKind::Entry);
    assert!(
        run(set_a.compose(RevealKind::FixesCommitment, D1, None))?
            .completed()
            .is_err()
    );
    a.local.heal();
    let mut set_b = world.device().open()?;
    let removal = run(set_b.remove(D1, RemovalBasis::AbortAtComposed))?;
    assert!(
        removal.per_store.iter().all(MemberRemoval::removed),
        "{removal:?}"
    );
    ceremony(&mut set_b, D2, None, 1)?;
    assert_eq!(
        run(set_a.compose(RevealKind::FixesCommitment, D1, None)).err(),
        Some(RecoveryStoreError::MarkerMoved)
    );
    assert_eq!(a.local.entry(), None);
    Ok(())
}

/// Mutant M22 and M28's second test: on a host without the member, a
/// `compose` whose `largeBlob` write does not land stops where the store
/// held a handle or a marker, before the local write.
#[test]
fn absent_host_compose_stops_on_a_store_with_evidence() -> TestResult {
    let world = World::new(Host::Android);
    world.blob.serve(&entry(None, Some(m(1, D9))));
    let device = world.device();
    let mut set = device.open()?;
    world
        .blob
        .not_landed_next(LargeBlobClearingAct::RemoveConsumingCredential);
    let report = run(set.compose(RevealKind::FixesCommitment, D1, Some(m(1, D9))))?;
    assert_eq!(
        report.completed(),
        Err(RecoveryStoreError::LargeBlobStopped {
            cause: None,
            clears_by: LargeBlobClearingAct::RemoveConsumingCredential
        })
    );
    assert_eq!(report.sdk_local, MemberWrite::NotAttempted);
    assert_eq!(device.local.entry(), None);
    Ok(())
}

/// Mutant M28: an `Absent`-host `compose` stops on an empty store that does
/// not land. It continues local-only with the skip bit set.
#[test]
fn absent_host_compose_skips_an_empty_store() -> TestResult {
    let world = World::new(Host::Android);
    let device = world.device();
    let mut set = device.open()?;
    world
        .blob
        .not_landed_next(LargeBlobClearingAct::RetryVerification);
    let report = run(set.compose(RevealKind::FixesCommitment, D1, None))?;
    report.completed()?;
    assert!(matches!(
        report.large_blob,
        LargeBlobWrite::NotLanded { .. }
    ));
    let local = device.local.entry().ok_or("no local entry")?;
    assert!(local.is_large_blob_skipped());
    assert_eq!(local.handle(), Some(h(D1, RecoveryPhase::Composed)));
    assert_eq!(world.blob.bytes(), None);
    Ok(())
}

/// A `Present`-host `compose` whose `largeBlob` write does not land drops
/// the store from the set and continues, and never sets the skip bit.
#[test]
fn present_host_compose_drops_a_store_that_does_not_land() -> TestResult {
    let (world, device) = World::created(Host::Apple)?;
    world
        .platform
        .put_record(&record(LargeBlobMembership::Member));
    let mut set = device.open()?;
    world
        .blob
        .not_landed_next(LargeBlobClearingAct::RetryVerification);
    run(set.compose(RevealKind::FixesCommitment, D1, None))?.completed()?;
    assert_eq!(
        world.platform.record(),
        Some(record(LargeBlobMembership::NotMember))
    );
    let local = device.local.entry().ok_or("no local entry")?;
    assert!(!local.is_large_blob_skipped());
    Ok(())
}

/// Mutant M12: an unchanged store holding the entry is not counted as
/// landed. A crash after the `largeBlob` write leaves the record at
/// `NotMember`; the retry finds the store holding the entry and records it.
#[test]
fn a_retry_after_a_crash_records_the_landed_store() -> TestResult {
    let (world, device) = World::created(Host::Apple)?;
    let mut set = device.open()?;
    world.platform.fail_write(KeyKind::Record);
    assert!(
        run(set.compose(RevealKind::FixesCommitment, D1, None))?
            .completed()
            .is_err()
    );
    world.platform.heal();
    device.local.fail_write(KeyKind::Entry);
    assert!(
        run(set.advance(D1, AdvanceTarget::Signed))?
            .completed()
            .is_err()
    );
    device.local.heal();
    assert_eq!(
        world.platform.record(),
        Some(record(LargeBlobMembership::NotMember))
    );
    assert_eq!(
        phase_in(world.blob.entry(), D1),
        Some(RecoveryPhase::Signed)
    );
    let report = run(set.advance(D1, AdvanceTarget::Signed))?;
    report.completed()?;
    assert_eq!(report.large_blob, LargeBlobWrite::Unchanged);
    assert_eq!(
        world.platform.record(),
        Some(record(LargeBlobMembership::Member))
    );
    Ok(())
}

/// Mutant M27: `hold` writes over `d` at `Signed`.
#[test]
fn hold_keeps_the_digest_at_any_phase() -> TestResult {
    for host in HOSTS {
        let (world, device) = World::created(host)?;
        let mut set = device.open()?;
        run(set.hold(token(D1), None))?.completed()?;
        assert_eq!(
            phase_in(world.blob.entry(), D1),
            Some(RecoveryPhase::Composed)
        );
        advance(&mut set, D1, AdvanceTarget::Signed)?;
        let report = run(set.hold(token(D1), None))?;
        report.completed()?;
        assert_eq!(report.sdk_local, MemberWrite::Unchanged, "{host:?}");
        assert_eq!(
            phase_in(device.local.entry(), D1),
            Some(RecoveryPhase::Signed)
        );
        assert_eq!(
            phase_in(world.blob.entry(), D1),
            Some(RecoveryPhase::Signed)
        );
    }
    Ok(())
}

/// `hold` refuses beside another live handle and where the marker moved.
#[test]
fn hold_refuses_a_foreign_live_handle_and_a_moved_marker() -> TestResult {
    let (world, device) = World::created(Host::Apple)?;
    let mut set = device.open()?;
    world
        .blob
        .serve(&entry(Some(h(D2, RecoveryPhase::Signed)), Some(m(1, D9))));
    world.platform.put_entry(&entry(None, Some(m(1, D9))));
    device.local.put_entry(&entry(None, Some(m(1, D9))));
    assert_eq!(
        run(set.hold(token(D1), None)).err(),
        Some(RecoveryStoreError::MarkerMoved)
    );
    assert_eq!(
        run(set.hold(token(D1), Some(m(1, D9)))).err(),
        Some(RecoveryStoreError::ForeignHandle)
    );
    Ok(())
}

/// Mutant M31: liveness judged per stored copy. One store holds `d'` at
/// `Composed` and another at `Lost`: `d'` is dead, so `compose` proceeds
/// and `hold` overwrites it.
#[test]
fn liveness_is_judged_on_the_merged_phase() -> TestResult {
    for hold in [false, true] {
        let (world, device) = World::created(Host::Apple)?;
        world
            .platform
            .put_entry(&entry(Some(h(D9, RecoveryPhase::Composed)), None));
        world
            .blob
            .serve(&entry(Some(h(D9, RecoveryPhase::Lost)), None));
        let mut set = device.open()?;
        let report = if hold {
            run(set.hold(token(D1), None))?
        } else {
            run(set.compose(RevealKind::FixesCommitment, D1, None))?
        };
        report.completed()?;
        assert_eq!(
            phase_in(world.platform.entry(), D1),
            Some(RecoveryPhase::Composed),
            "hold: {hold}"
        );
        assert_eq!(
            phase_in(world.blob.entry(), D1),
            Some(RecoveryPhase::Composed)
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// advance (mutants M3, M5, M11, M21, M24, M29, M30, M32)
// ---------------------------------------------------------------------------

/// Mutant M3: allow a phase to move backward.
#[test]
fn a_phase_never_moves_backward() -> TestResult {
    for host in HOSTS {
        let (world, device) = World::created(host)?;
        let mut set = device.open()?;
        compose(&mut set, D1, None)?;
        advance(&mut set, D1, AdvanceTarget::PublishSent)?;
        let report = run(set.advance(D1, AdvanceTarget::Signed))?;
        report.completed()?;
        assert_eq!(report.sdk_local, MemberWrite::Unchanged);
        for stored in [device.local.entry(), world.blob.entry()] {
            assert_eq!(
                phase_in(stored, D1),
                Some(RecoveryPhase::PublishSent),
                "{host:?}"
            );
        }
    }
    Ok(())
}

/// Mutant M5: write local first. A failed platform write stops the
/// transition before the local store moves.
#[test]
fn platform_failure_stops_before_the_local_write() -> TestResult {
    let (world, device) = World::created(Host::Apple)?;
    let mut set = device.open()?;
    compose(&mut set, D1, None)?;
    world.platform.fail_write(KeyKind::Entry);
    let report = run(set.advance(D1, AdvanceTarget::Signed))?;
    assert!(matches!(
        report.completed(),
        Err(RecoveryStoreError::PlatformAccountWriteFailed { .. })
    ));
    assert_eq!(
        phase_in(device.local.entry(), D1),
        Some(RecoveryPhase::Composed)
    );
    assert_eq!(
        phase_in(world.blob.entry(), D1),
        Some(RecoveryPhase::Composed)
    );
    Ok(())
}

/// Mutant M11: a `Composed → Signed` write that does not land where the
/// store held the handle removes the member. The member stays, the
/// ceremony stops, and the local store says `Composed`.
#[test]
fn signed_write_that_does_not_land_stops_and_keeps_the_member() -> TestResult {
    for host in HOSTS {
        let (world, device) = World::created(host)?;
        let mut set = device.open()?;
        compose(&mut set, D1, None)?;
        world
            .blob
            .not_landed_next(LargeBlobClearingAct::RetryVerification);
        let report = run(set.advance(D1, AdvanceTarget::Signed))?;
        assert_eq!(
            report.completed(),
            Err(RecoveryStoreError::LargeBlobStopped {
                cause: None,
                clears_by: LargeBlobClearingAct::RetryVerification
            }),
            "{host:?}"
        );
        assert_eq!(
            phase_in(device.local.entry(), D1),
            Some(RecoveryPhase::Composed)
        );
        if host == Host::Apple {
            assert_eq!(
                world.platform.record(),
                Some(record(LargeBlobMembership::Member))
            );
        }
        advance(&mut set, D1, AdvanceTarget::Signed)?;
        assert_eq!(
            phase_in(world.blob.entry(), D1),
            Some(RecoveryPhase::Signed)
        );
    }
    Ok(())
}

/// Mutant M21: a `NotLanded` after `Signed`, or on `complete`, stops. The
/// ceremony continues and the report surfaces the failure.
#[test]
fn later_large_blob_failures_are_surfaced_and_continue() -> TestResult {
    for host in HOSTS {
        let (world, device) = World::created(host)?;
        let mut set = device.open()?;
        compose(&mut set, D1, None)?;
        advance(&mut set, D1, AdvanceTarget::Signed)?;
        world
            .blob
            .not_landed_next(LargeBlobClearingAct::RetryVerification);
        let report = run(set.advance(D1, AdvanceTarget::PublishSent))?;
        report.completed()?;
        assert!(
            matches!(report.large_blob, LargeBlobWrite::NotLanded { .. }),
            "{host:?}"
        );
        assert_eq!(
            phase_in(device.local.entry(), D1),
            Some(RecoveryPhase::PublishSent)
        );
        world
            .blob
            .not_landed_next(LargeBlobClearingAct::RetryVerification);
        let removal = run(set.complete(1, D1))?;
        let causes: Vec<(CredentialStore, bool)> = removal
            .per_store
            .iter()
            .map(|member| (member.store, member.removed()))
            .collect();
        assert!(
            causes.contains(&(CredentialStore::LargeBlob, false)),
            "{removal:?}"
        );
        assert!(
            causes.contains(&(CredentialStore::SdkLocal, true)),
            "{removal:?}"
        );
        assert_eq!(device.local.entry(), Some(entry(None, Some(m(1, D1)))));
    }
    Ok(())
}

/// Mutant M24: a retried `advance(Discarded)` returns `HandleGone` from a
/// member that lacks the handle.
#[test]
fn terminal_advance_on_a_member_without_the_handle_is_unchanged() -> TestResult {
    let world = World::new(Host::Android);
    let device = world.device();
    let mut set = device.open()?;
    compose(&mut set, D1, None)?;
    advance(&mut set, D1, AdvanceTarget::Discarded)?;
    world.blob.evict();
    let report = run(set.advance(D1, AdvanceTarget::Discarded))?;
    report.completed()?;
    assert_eq!(report.large_blob, LargeBlobWrite::Unchanged);
    assert_eq!(world.blob.bytes(), None);
    Ok(())
}

/// `advance` refuses where no store holds the handle, and beside another
/// live handle.
#[test]
fn advance_refuses_a_gone_or_foreign_handle() -> TestResult {
    let (world, device) = World::created(Host::Apple)?;
    let mut set = device.open()?;
    assert_eq!(
        run(set.advance(D1, AdvanceTarget::Signed)).err(),
        Some(RecoveryStoreError::HandleGone)
    );
    compose(&mut set, D1, None)?;
    world
        .platform
        .put_entry(&entry(Some(h(D2, RecoveryPhase::Composed)), None));
    assert_eq!(
        run(set.advance(D1, AdvanceTarget::Signed)).err(),
        Some(RecoveryStoreError::ForeignHandle)
    );
    Ok(())
}

/// Mutant M29 and L1: `advance` ignores the skip bit. After a skipped
/// composition, `advance(Signed)` writes the handle into the store, and the
/// landed write clears the local skip bit.
#[test]
fn signed_write_fills_a_skipped_store_and_clears_the_bit() -> TestResult {
    let world = World::new(Host::Android);
    let device = world.device();
    let mut set = device.open()?;
    world
        .blob
        .not_landed_next(LargeBlobClearingAct::RetryVerification);
    compose(&mut set, D1, None)?;
    let report = run(set.advance(D1, AdvanceTarget::Signed))?;
    report.completed()?;
    assert_eq!(report.large_blob, LargeBlobWrite::Landed);
    assert_eq!(
        phase_in(world.blob.entry(), D1),
        Some(RecoveryPhase::Signed)
    );
    let local = device.local.entry().ok_or("no local entry")?;
    assert!(!local.is_large_blob_skipped());
    assert_eq!(local.handle(), Some(h(D1, RecoveryPhase::Signed)));
    assert_eq!(run(set.confirm_pending(&D1))?, h(D1, RecoveryPhase::Signed));
    Ok(())
}

/// Mutant M30: `advance` re-adds the handle into an empty store the
/// composition reached. Another device aborts; the composer's
/// `advance(Signed)` refuses and the store stays `[0x00]`.
#[test]
fn signed_write_does_not_undo_another_devices_abort() -> TestResult {
    let world = World::new(Host::Android);
    let a = world.device();
    let mut set_a = a.open()?;
    compose(&mut set_a, D1, None)?;
    let removal = run(world
        .device()
        .open()?
        .remove(D1, RemovalBasis::AbortAtComposed))?;
    assert!(removal.per_store.iter().all(MemberRemoval::removed));
    assert_eq!(world.blob.bytes(), Some(vec![0x00]));
    assert_eq!(
        run(set_a.advance(D1, AdvanceTarget::Signed)).err(),
        Some(RecoveryStoreError::HandleGone)
    );
    assert_eq!(world.blob.bytes(), Some(vec![0x00]));
    assert_eq!(phase_in(a.local.entry(), D1), Some(RecoveryPhase::Composed));
    Ok(())
}

/// Mutant M32: the skip-bit write ignores the marker. Q1's interleaving:
/// X's composition skips the empty store; Y composes, publishes and
/// completes a reveal there; X's `advance(Signed)` and its re-read refuse.
#[test]
fn skipped_store_write_refuses_where_another_reveal_completed() -> TestResult {
    let world = World::new(Host::Android);
    let x = world.device();
    let mut set_x = x.open()?;
    world
        .blob
        .not_landed_next(LargeBlobClearingAct::RetryVerification);
    compose(&mut set_x, D1, None)?;
    ceremony(&mut world.device().open()?, D2, None, 1)?;
    assert_eq!(world.blob.entry(), Some(entry(None, Some(m(1, D2)))));
    assert_eq!(
        run(set_x.advance(D1, AdvanceTarget::Signed)).err(),
        Some(RecoveryStoreError::MarkerMoved)
    );
    assert_eq!(
        run(set_x.confirm_pending(&D1)),
        Err(RecoveryStoreError::MarkerMoved)
    );
    assert_eq!(world.blob.entry(), Some(entry(None, Some(m(1, D2)))));
    Ok(())
}

// ---------------------------------------------------------------------------
// complete and remove (mutants M6, M16, M18, M19)
// ---------------------------------------------------------------------------

/// Mutant M6: removal stops at the first failure. Every member is tried.
#[test]
fn removal_tries_every_member() -> TestResult {
    let (world, device) = World::created(Host::Apple)?;
    let mut set = device.open()?;
    compose(&mut set, D1, None)?;
    world.platform.fail_write(KeyKind::Entry);
    let removal = run(set.remove(D1, RemovalBasis::AbortAtComposed))?;
    assert_eq!(
        removal.per_store,
        vec![
            MemberRemoval {
                store: CredentialStore::PlatformAccount,
                cause: Some(RemovalCause::Failed {
                    cause: "injected write failure".to_owned()
                }),
            },
            MemberRemoval {
                store: CredentialStore::LargeBlob,
                cause: None,
            },
            MemberRemoval {
                store: CredentialStore::SdkLocal,
                cause: None,
            },
        ]
    );
    assert_eq!(world.blob.bytes(), Some(vec![0x00]));
    assert_eq!(device.local.entry(), None);
    assert_eq!(
        phase_in(world.platform.entry(), D1),
        Some(RecoveryPhase::Composed)
    );
    Ok(())
}

/// Abort refuses past `Composed` and where a store holds the signed event;
/// a terminal removal refuses below `Discarded`.
#[test]
fn removal_bases_refuse_the_wrong_phase() -> TestResult {
    let (_, device) = World::created(Host::Apple)?;
    let mut set = device.open()?;
    compose(&mut set, D1, None)?;
    assert_eq!(
        run(set.remove(D1, RemovalBasis::Terminal)).err(),
        Some(RecoveryStoreError::PhaseNotRemovable)
    );
    run(set.write_event(&D1, b"signed"))?;
    assert_eq!(
        run(set.remove(D1, RemovalBasis::AbortAtComposed)).err(),
        Some(RecoveryStoreError::SignedRevealUnpublished)
    );
    advance(&mut set, D1, AdvanceTarget::Signed)?;
    assert_eq!(
        run(set.remove(D1, RemovalBasis::AbortAtComposed)).err(),
        Some(RecoveryStoreError::SignedRevealUnpublished)
    );
    advance(&mut set, D1, AdvanceTarget::Lost)?;
    assert_eq!(
        run(set.remove(D1, RemovalBasis::AbortAtComposed)).err(),
        Some(RecoveryStoreError::PhaseNotRemovable)
    );
    let removal = run(set.remove(D1, RemovalBasis::Terminal))?;
    assert!(removal.per_store.iter().all(MemberRemoval::removed));
    let removal = run(set.remove(D9, RemovalBasis::Terminal))?;
    assert!(removal.per_store.iter().all(MemberRemoval::removed));
    Ok(())
}

/// Mutant M16: the per-member check ignores the merged phase. P3: a
/// terminal advance lands everywhere but `largeBlob`, which stays at
/// `Signed`; the terminal removal still empties every member.
#[test]
fn terminal_removal_judges_each_member_at_the_merged_phase() -> TestResult {
    let (world, device) = World::created(Host::Apple)?;
    let mut set = device.open()?;
    compose(&mut set, D1, None)?;
    advance(&mut set, D1, AdvanceTarget::Signed)?;
    world
        .blob
        .not_landed_next(LargeBlobClearingAct::RetryVerification);
    run(set.advance(D1, AdvanceTarget::Discarded))?.completed()?;
    assert_eq!(
        phase_in(world.blob.entry(), D1),
        Some(RecoveryPhase::Signed)
    );
    let removal = run(set.remove(D1, RemovalBasis::Terminal))?;
    assert!(
        removal.per_store.iter().all(MemberRemoval::removed),
        "{removal:?}"
    );
    assert_eq!(world.platform.entry(), None);
    assert_eq!(world.blob.entry(), None);
    assert_eq!(device.local.entry(), None);
    Ok(())
}

/// Mutant M18: `complete` refuses an equal-sequence marker. The illegality
/// branch completes a second reveal at the sequence a marker already holds.
#[test]
fn complete_takes_an_equal_sequence_and_refuses_a_lower_one() -> TestResult {
    for host in HOSTS {
        let (world, device) = World::created(host)?;
        let mut set = device.open()?;
        world.blob.serve(&entry(None, Some(m(5, D9))));
        device.local.put_entry(&entry(
            Some(h(D1, RecoveryPhase::Confirmed)),
            Some(m(5, D9)),
        ));
        let removal = run(set.complete(5, D1))?;
        assert!(
            removal.per_store.iter().all(MemberRemoval::removed),
            "{host:?}"
        );
        assert_eq!(world.blob.entry(), Some(entry(None, Some(m(5, D1)))));
        assert_eq!(device.local.entry(), Some(entry(None, Some(m(5, D1)))));
        assert_eq!(
            run(set.complete(4, D2)).err(),
            Some(RecoveryStoreError::MarkerMoved)
        );
    }
    Ok(())
}

/// `complete` keeps a handle naming another digest.
#[test]
fn complete_keeps_another_ceremonys_handle() -> TestResult {
    let (world, device) = World::created(Host::Apple)?;
    let mut set = device.open()?;
    world
        .blob
        .serve(&entry(Some(h(D2, RecoveryPhase::Composed)), None));
    let _ = run(set.complete(1, D1))?;
    assert_eq!(
        world.blob.entry(),
        Some(entry(Some(h(D2, RecoveryPhase::Composed)), Some(m(1, D1))))
    );
    Ok(())
}

/// Mutant M19: an empty read counts as landed. A removal that changes
/// nothing in an empty `largeBlob` store leaves the record at `NotMember`.
#[test]
fn an_empty_store_is_not_evidence_of_a_landed_write() -> TestResult {
    let (world, device) = World::created(Host::Apple)?;
    let mut set = device.open()?;
    let removal = run(set.remove(D9, RemovalBasis::Adopted))?;
    assert_eq!(removal.record, MemberWrite::Unchanged);
    assert_eq!(
        world.platform.record(),
        Some(record(LargeBlobMembership::NotMember))
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Residuals: these document what the rule does not close and are not
// must-fail tests (09-security-model.md §9.7.4.2 R10, "What the rule does
// not close").
// ---------------------------------------------------------------------------

/// Residual (ii): a write merged against a read that predates another
/// device's landed write overwrites it.
#[test]
fn residual_ii_lost_update() -> TestResult {
    let (world, a) = World::created(Host::Apple)?;
    let mut set_a = a.open()?;
    let platform = world.platform.shared_db();
    let blob = world.blob.shared();
    a.platform.before_write(move || {
        platform.put_entry(&entry(Some(h(D2, RecoveryPhase::Composed)), None));
        blob.serve(&entry(Some(h(D2, RecoveryPhase::Composed)), None));
    });
    compose(&mut set_a, D1, None)?;
    assert_eq!(phase_in(world.platform.entry(), D2), None);
    assert_eq!(
        phase_in(world.blob.entry(), D1),
        Some(RecoveryPhase::Composed)
    );
    Ok(())
}

/// Residual (iv): a `largeBlob` write lost after it landed hides the
/// ceremony from a device that reads only that store.
#[test]
fn residual_iv_evicted_write() -> TestResult {
    let world = World::new(Host::Android);
    compose(&mut world.device().open()?, D1, None)?;
    world.blob.evict();
    compose(&mut world.device().open()?, D2, None)?;
    assert_eq!(
        phase_in(world.blob.entry(), D2),
        Some(RecoveryPhase::Composed)
    );
    Ok(())
}

/// Residual (vi), case (ii) on a skipped store: Y's composition lands after
/// X's `advance(Signed)` read the store empty, so X's write overwrites it.
#[test]
fn residual_vi_skipped_store_lost_update() -> TestResult {
    let world = World::new(Host::Android);
    let x = world.device();
    let mut set_x = x.open()?;
    world
        .blob
        .not_landed_next(LargeBlobClearingAct::RetryVerification);
    compose(&mut set_x, D1, None)?;
    let y = world.device();
    y.local
        .put_entry(&entry(Some(h(D2, RecoveryPhase::Composed)), None));
    let blob = world.blob.shared();
    x.blob()?.before_write(move || {
        blob.serve(&entry(Some(h(D2, RecoveryPhase::Composed)), None));
    });
    advance(&mut set_x, D1, AdvanceTarget::Signed)?;
    assert_eq!(
        phase_in(world.blob.entry(), D1),
        Some(RecoveryPhase::Signed)
    );
    assert_eq!(
        run(y.open()?.confirm_pending(&D2)),
        Err(RecoveryStoreError::HandleGone)
    );
    Ok(())
}

/// Stale reads: a frozen platform view hides a later write until it thaws.
#[test]
fn a_stale_platform_read_is_merged_as_read() -> TestResult {
    let (world, a) = World::created(Host::Apple)?;
    let b = world.device_without_blob();
    let set_b = b.open()?;
    b.platform.freeze();
    compose(&mut a.open()?, D1, None)?;
    assert!(run(set_b.read_set())?.pending().is_empty());
    b.platform.thaw();
    assert_eq!(
        run(set_b.read_set()).err(),
        Some(unreadable(
            CredentialStore::LargeBlob,
            NotReachedCause::NoStoreOnDevice
        ))
    );
    Ok(())
}
