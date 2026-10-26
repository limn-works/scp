//! Tests for the store set (`09-security-model.md` §9.7.4.2 R10,
//! `17-persistence-and-storage.md` §17.8; SCP-311). Each membership rule has
//! a test that fails when the rule is removed, and each codec refusal has a
//! must-fail input.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::*;
use crate::PlatformError;
use crate::traits::Storage;

type TestResult = Result<(), Box<dyn std::error::Error>>;

// ---------------------------------------------------------------------------
// Doubles
// ---------------------------------------------------------------------------

/// A test-only encrypted storage: a map with switches that make reads or
/// writes fail and that truncate a stored event by one byte on read.
#[derive(Default)]
struct TestStorage {
    map: Mutex<HashMap<String, Vec<u8>>>,
    fail_reads: AtomicBool,
    fail_writes: AtomicBool,
    truncate_events: AtomicBool,
}

impl TestStorage {
    fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn raw(&self, suffix: &str) -> Option<Vec<u8>> {
        let map = self.map.lock().ok()?;
        map.iter()
            .find(|(key, _)| key.ends_with(suffix))
            .map(|(_, value)| value.clone())
    }

    fn set_raw(&self, suffix: &str, bytes: Vec<u8>) -> Result<(), String> {
        let mut map = self.map.lock().map_err(|e| e.to_string())?;
        let key = map
            .keys()
            .find(|key| key.ends_with(suffix))
            .cloned()
            .ok_or_else(|| format!("no key ends with {suffix}"))?;
        map.insert(key, bytes);
        drop(map);
        Ok(())
    }

    fn key_count(&self) -> usize {
        self.map.lock().map_or(0, |map| map.len())
    }

    fn fault(flag: &AtomicBool, what: &str) -> Result<(), PlatformError> {
        if flag.load(Ordering::SeqCst) {
            return Err(PlatformError::StorageError(format!(
                "injected {what} failure"
            )));
        }
        Ok(())
    }
}

impl crate::encrypted::private::Sealed for TestStorage {}
impl EncryptedStorage for TestStorage {}

impl Storage for TestStorage {
    fn store(
        &self,
        key: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let result = Self::fault(&self.fail_writes, "write").and_then(|()| {
            self.map
                .lock()
                .map_err(|e| PlatformError::StorageError(e.to_string()))
                .map(|mut map| {
                    map.insert(key.to_owned(), data.to_vec());
                })
        });
        std::future::ready(result)
    }

    fn retrieve(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, PlatformError>> + Send {
        let result = Self::fault(&self.fail_reads, "read").and_then(|()| {
            let mut value = self
                .map
                .lock()
                .map_err(|e| PlatformError::StorageError(e.to_string()))?
                .get(key)
                .cloned();
            if self.truncate_events.load(Ordering::SeqCst)
                && key.contains("/event/")
                && let Some(bytes) = value.as_mut()
            {
                bytes.pop();
            }
            Ok(value)
        });
        std::future::ready(result)
    }

    fn delete(&self, key: &str) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let result = self
            .map
            .lock()
            .map_err(|e| PlatformError::StorageError(e.to_string()))
            .map(|mut map| {
                map.remove(key);
            });
        std::future::ready(result)
    }

    fn list_keys(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<String>, PlatformError>> + Send {
        let result = self
            .map
            .lock()
            .map_err(|e| PlatformError::StorageError(e.to_string()))
            .map(|map| {
                let mut keys: Vec<String> = map
                    .keys()
                    .filter(|k| k.starts_with(prefix))
                    .cloned()
                    .collect();
                keys.sort();
                keys
            });
        std::future::ready(result)
    }

    fn delete_prefix(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<u64, PlatformError>> + Send {
        let result = self
            .map
            .lock()
            .map_err(|e| PlatformError::StorageError(e.to_string()))
            .map(|mut map| {
                let before = map.len();
                map.retain(|k, _| !k.starts_with(prefix));
                u64::try_from(before - map.len()).unwrap_or(u64::MAX)
            });
        std::future::ready(result)
    }

    fn exists(&self, key: &str) -> impl Future<Output = Result<bool, PlatformError>> + Send {
        let result = self
            .map
            .lock()
            .map_err(|e| PlatformError::StorageError(e.to_string()))
            .map(|map| map.contains_key(key));
        std::future::ready(result)
    }
}

/// A test-only `largeBlob` member: one record, a switch that makes reads
/// fail, and the outcome the next write reports.
#[derive(Default)]
struct FakeLargeBlob {
    record: Mutex<Option<Vec<u8>>>,
    fail_reads: AtomicBool,
    not_landed: Mutex<Option<LargeBlobNotLanded>>,
}

impl FakeLargeBlob {
    fn refuse_next_writes(&self, not_landed: LargeBlobNotLanded) -> Result<(), String> {
        *self.not_landed.lock().map_err(|e| e.to_string())? = Some(not_landed);
        Ok(())
    }

    fn set_raw(&self, bytes: Vec<u8>) -> Result<(), String> {
        *self.record.lock().map_err(|e| e.to_string())? = Some(bytes);
        Ok(())
    }

    fn raw(&self) -> Option<Vec<u8>> {
        self.record.lock().ok()?.clone()
    }
}

impl RecoveryHandleStore for Arc<FakeLargeBlob> {
    type WriteFailure = LargeBlobNotLanded;

    fn read_entry(&self) -> impl Future<Output = MemberRead<StoreEntry>> + MaybeSend {
        let read = if self.fail_reads.load(Ordering::SeqCst) {
            MemberRead::NotReached(NotReachedCause::Unreachable {
                cause: "authenticator absent".to_owned(),
            })
        } else {
            self.raw().map_or(
                MemberRead::ReachedEmpty,
                |bytes| match decode_entry_record(&bytes) {
                    Ok(Some(entry)) => MemberRead::Reached(entry),
                    Ok(None) => MemberRead::ReachedEmpty,
                    Err(error) => MemberRead::NotReached(NotReachedCause::Undecodable(error)),
                },
            )
        };
        std::future::ready(read)
    }

    fn write_entry(
        &self,
        entry: &StoreEntry,
    ) -> impl Future<Output = Result<(), LargeBlobNotLanded>> + MaybeSend {
        let refusal = self.not_landed.lock().ok().and_then(|guard| guard.clone());
        let result = refusal.map_or_else(
            || {
                self.record
                    .lock()
                    .map(|mut record| *record = Some(encode_entry_record(entry)))
                    .map_err(|e| LargeBlobNotLanded {
                        cause: Some(e.to_string()),
                        clears_by: LargeBlobClearingAct::RetryVerification,
                    })
            },
            Err,
        );
        std::future::ready(result)
    }
}

type Local = SdkLocalMember<Arc<TestStorage>>;
type Members = StoreSetMembers<Local, Local, Arc<FakeLargeBlob>>;
type Set = StoreSet<Local, Local, Arc<FakeLargeBlob>>;

/// One device's handles on a credential's stores, kept so a test can tamper
/// with them and build the members again.
struct Device {
    credential: CredentialId,
    local: Arc<TestStorage>,
    platform: Option<Arc<TestStorage>>,
    platform_absence: PlatformAccountAbsence,
    large_blob: Option<Arc<FakeLargeBlob>>,
}

impl Device {
    fn new(platform: bool, large_blob: bool) -> Result<Self, CredentialIdError> {
        Ok(Self {
            credential: credential(0xc1)?,
            local: TestStorage::shared(),
            platform: platform.then(TestStorage::shared),
            platform_absence: PlatformAccountAbsence::NoDataApiToCredentialSyncStore,
            large_blob: large_blob.then(|| Arc::new(FakeLargeBlob::default())),
        })
    }

    fn members(&self) -> Members {
        StoreSetMembers {
            sdk_local: SdkLocalMember::new(Arc::clone(&self.local), &self.credential),
            platform_account: self.platform.as_ref().map_or(
                PlatformAccountSlot::Absent(self.platform_absence),
                |storage| {
                    PlatformAccountSlot::Present(SdkLocalMember::new(
                        Arc::clone(storage),
                        &self.credential,
                    ))
                },
            ),
            large_blob: self.large_blob.clone(),
        }
    }

    async fn create(&self) -> Result<Set, RecoveryStoreError> {
        StoreSet::create(self.members(), self.credential.clone()).await
    }

    async fn open(&self) -> Result<Set, RecoveryStoreError> {
        StoreSet::open(self.members(), &self.credential).await
    }

    fn platform_storage(&self) -> Result<&Arc<TestStorage>, String> {
        self.platform
            .as_ref()
            .ok_or_else(|| "device has no platform-account member".to_owned())
    }

    fn large_blob(&self) -> Result<&Arc<FakeLargeBlob>, String> {
        self.large_blob
            .as_ref()
            .ok_or_else(|| "device has no largeBlob store".to_owned())
    }
}

fn credential(fill: u8) -> Result<CredentialId, CredentialIdError> {
    CredentialId::new(vec![fill; 64])
}

fn handle(phase: RecoveryPhase) -> RecoveryHandle {
    RecoveryHandle::FixesCommitment {
        identifier: Identifier::from_bytes([0x11; 32]),
        phase,
        event_digest: [0x22; 32],
    }
}

fn marker() -> LastRevealMarker {
    LastRevealMarker {
        identifier: Identifier::from_bytes([0x11; 32]),
        sequence: 0x0102_0304_0506_0708,
        event_digest: [0x33; 32],
    }
}

fn entry() -> StoreEntry {
    StoreEntry::HandleAndMarker {
        handle: handle(RecoveryPhase::Signed),
        marker: marker(),
    }
}

fn max_event() -> Result<Vec<u8>, std::num::TryFromIntError> {
    let len = usize::try_from(MAX_EVENT_BYTES)?;
    Ok((0..len).map(|i| (i % 251).to_le_bytes()[0]).collect())
}

fn not_landed() -> LargeBlobNotLanded {
    LargeBlobNotLanded {
        cause: Some("NotAllowedError".to_owned()),
        clears_by: LargeBlobClearingAct::RetryVerification,
    }
}

fn unreadable(error: &RecoveryStoreError) -> Option<(CredentialStore, &NotReachedCause)> {
    match error {
        RecoveryStoreError::StorePartiallyUnreadable { store, cause } => Some((*store, cause)),
        _ => None,
    }
}

fn stores(read: &SetRead) -> Vec<CredentialStore> {
    read.per_store.iter().map(|r| r.store).collect()
}

// ---------------------------------------------------------------------------
// Codecs
// ---------------------------------------------------------------------------

#[test]
fn handle_codec_round_trips_every_phase() -> TestResult {
    for (index, phase) in RecoveryPhase::ALL.into_iter().enumerate() {
        let fixes = handle(phase);
        let abandons = RecoveryHandle::Abandons {
            identifier: Identifier::from_bytes([0x44; 32]),
            phase,
            event_digest: [0x55; 32],
        };
        for (discriminant, value) in [(0x00u8, fixes), (0x01u8, abandons)] {
            let bytes = encode_handle(&value);
            assert_eq!(bytes.len(), RECOVERY_HANDLE_BYTES);
            assert_eq!(bytes[0], discriminant);
            assert_eq!(usize::from(bytes[33]), index);
            assert_eq!(&bytes[1..33], value.identifier().as_bytes());
            assert_eq!(bytes[34..66], value.event_digest());
            assert_eq!(decode_handle(&bytes)?, value);
        }
    }
    Ok(())
}

#[test]
fn handle_decode_refuses_malformed_bytes() {
    let good = encode_handle(&handle(RecoveryPhase::Composed));
    assert_eq!(
        decode_handle(&good[..65]),
        Err(RecordDecodeError::WrongLength {
            expected: 66,
            actual: 65
        })
    );
    let mut trailing = good.to_vec();
    trailing.push(0);
    assert_eq!(
        decode_handle(&trailing),
        Err(RecordDecodeError::WrongLength {
            expected: 66,
            actual: 67
        })
    );
    let mut variant = good;
    variant[0] = 0x02;
    assert_eq!(
        decode_handle(&variant),
        Err(RecordDecodeError::UnknownVariant(0x02))
    );
    let mut phase = good;
    phase[33] = 0x06;
    assert_eq!(
        decode_handle(&phase),
        Err(RecordDecodeError::UnknownPhase(0x06))
    );
}

#[test]
fn marker_decode_refuses_71_and_73_bytes() -> TestResult {
    let bytes = encode_marker(&marker());
    assert_eq!(bytes.len(), LAST_REVEAL_MARKER_BYTES);
    assert_eq!(bytes[32..40], [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(decode_marker(&bytes)?, marker());
    assert_eq!(
        decode_marker(&bytes[..71]),
        Err(RecordDecodeError::WrongLength {
            expected: 72,
            actual: 71
        })
    );
    let mut long = bytes.to_vec();
    long.push(0);
    assert_eq!(
        decode_marker(&long),
        Err(RecordDecodeError::WrongLength {
            expected: 72,
            actual: 73
        })
    );
    Ok(())
}

#[test]
fn large_blob_record_round_trips_each_flag_combination() -> TestResult {
    let cases = [
        (StoreEntry::Handle(handle(RecoveryPhase::Lost)), 0b01, 67),
        (StoreEntry::Marker(marker()), 0b10, 73),
        (entry(), 0b11, 139),
    ];
    for (value, flags, len) in cases {
        let bytes = encode_entry_record(&value);
        assert_eq!((bytes[0], bytes.len()), (flags, len));
        assert_eq!(decode_entry_record(&bytes)?, Some(value));
    }
    assert_eq!(decode_entry_record(&[0])?, None);
    Ok(())
}

#[test]
fn large_blob_record_refuses_unknown_flag_bits() {
    let mut bytes = encode_entry_record(&entry());
    for bit in 2..8 {
        bytes[0] = 0b11 | (1 << bit);
        assert_eq!(
            decode_entry_record(&bytes),
            Err(RecordDecodeError::UnknownFlags(bytes[0]))
        );
    }
}

#[test]
fn large_blob_record_refuses_length_other_than_flags_name() {
    let full = encode_entry_record(&entry());
    assert!(decode_entry_record(&[]).is_err());
    // Each flags value with one byte too few and one byte too many.
    for (flags, len) in [(0b00u8, 1usize), (0b01, 67), (0b10, 73), (0b11, 139)] {
        for wrong in [len - 1, len + 1] {
            let mut bytes = vec![0u8; wrong];
            if let Some(first) = bytes.first_mut() {
                *first = flags;
            }
            let shared = wrong.min(full.len());
            if wrong > 1 {
                bytes[1..shared].copy_from_slice(&full[1..shared]);
            }
            assert!(
                matches!(
                    decode_entry_record(&bytes),
                    Err(RecordDecodeError::WrongLength { .. })
                ),
                "flags {flags:#04b} at {wrong} bytes decoded"
            );
        }
    }
}

#[test]
fn store_set_record_round_trips_and_refuses_malformed_bytes() -> TestResult {
    for platform_account in [
        PlatformAccountMember::Present,
        PlatformAccountMember::Absent(PlatformAccountAbsence::NoDataApiToCredentialSyncStore),
        PlatformAccountMember::Absent(PlatformAccountAbsence::NoPlatformCredential),
    ] {
        for large_blob in [LargeBlobMembership::Member, LargeBlobMembership::NotMember] {
            let record = StoreSetRecord {
                credential_id: CredentialId::new(vec![7; MAX_CREDENTIAL_ID_BYTES])?,
                platform_account,
                large_blob,
            };
            assert_eq!(
                decode_store_set_record(&encode_store_set_record(&record))?,
                record
            );
        }
    }
    let good = encode_store_set_record(&StoreSetRecord {
        credential_id: credential(9)?,
        platform_account: PlatformAccountMember::Present,
        large_blob: LargeBlobMembership::NotMember,
    });
    let with = |index: usize, byte: u8| {
        let mut bytes = good.clone();
        bytes[index] = byte;
        decode_store_set_record(&bytes)
    };
    assert_eq!(with(0, 0x02), Err(RecordDecodeError::UnknownVersion(0x02)));
    assert_eq!(
        with(1, 0x03),
        Err(RecordDecodeError::UnknownPlatformAccount(0x03))
    );
    assert_eq!(
        with(2, 0x02),
        Err(RecordDecodeError::UnknownLargeBlobMembership(0x02))
    );
    let mut zero = good.clone();
    zero[3..5].copy_from_slice(&[0, 0]);
    assert_eq!(
        decode_store_set_record(&zero),
        Err(RecordDecodeError::CredentialIdLength(0))
    );
    let mut too_long = good.clone();
    too_long[3..5].copy_from_slice(&1024u16.to_be_bytes());
    assert_eq!(
        decode_store_set_record(&too_long),
        Err(RecordDecodeError::CredentialIdLength(1024))
    );
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(matches!(
        decode_store_set_record(&trailing),
        Err(RecordDecodeError::WrongLength { .. })
    ));
    assert!(matches!(
        decode_store_set_record(&good[..good.len() - 1]),
        Err(RecordDecodeError::WrongLength { .. })
    ));
    assert!(matches!(
        decode_store_set_record(&good[..4]),
        Err(RecordDecodeError::WrongLength { .. })
    ));
    Ok(())
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

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sdk_local_round_trips() -> TestResult {
    let storage = TestStorage::shared();
    let member = SdkLocalMember::new(Arc::clone(&storage), &credential(1)?);
    let event = max_event()?;
    let record = StoreSetRecord {
        credential_id: credential(1)?,
        platform_account: PlatformAccountMember::Absent(
            PlatformAccountAbsence::NoPlatformCredential,
        ),
        large_blob: LargeBlobMembership::NotMember,
    };
    assert_eq!(member.read_entry().await, MemberRead::ReachedEmpty);
    member.write_entry(&entry()).await?;
    member.write_record(&record).await?;
    member.write_event(&[0x22; 32], &event).await?;
    assert_eq!(member.read_entry().await, MemberRead::Reached(entry()));
    assert_eq!(member.read_record().await, MemberRead::Reached(record));
    assert_eq!(
        member.read_event(&[0x22; 32]).await,
        MemberRead::Reached(event)
    );
    assert_eq!(
        member.read_event(&[0x23; 32]).await,
        MemberRead::ReachedEmpty
    );

    // Must fail: a handle whose phase byte is flipped reads back unequal.
    let mut tampered = storage.raw("/entry").ok_or("no entry")?;
    tampered[1 + 33] = RecoveryPhase::Confirmed.to_byte();
    storage.set_raw("/entry", tampered)?;
    assert_ne!(member.read_entry().await, MemberRead::Reached(entry()));
    Ok(())
}

#[tokio::test]
async fn sdk_local_keys_each_credential_apart() -> TestResult {
    let storage = TestStorage::shared();
    let first = SdkLocalMember::new(Arc::clone(&storage), &credential(1)?);
    let second = SdkLocalMember::new(Arc::clone(&storage), &credential(2)?);
    first.write_entry(&entry()).await?;
    assert_eq!(second.read_entry().await, MemberRead::ReachedEmpty);
    assert_eq!(storage.key_count(), 1);
    Ok(())
}

#[tokio::test]
async fn undecodable_bytes_read_as_not_reached() -> TestResult {
    let device = Device::new(false, false)?;
    let mut set = device.create().await?;
    set.write_entry(&entry()).await?;
    device.local.set_raw("/entry", vec![0b0000_0100])?;
    let local = SdkLocalMember::new(Arc::clone(&device.local), &device.credential);
    assert_eq!(
        local.read_entry().await,
        MemberRead::NotReached(NotReachedCause::Undecodable(
            RecordDecodeError::UnknownFlags(0b0000_0100)
        ))
    );
    let refusal = set
        .read_entries()
        .await
        .err()
        .ok_or("undecodable entry was read")?;
    assert!(matches!(
        unreadable(&refusal),
        Some((CredentialStore::SdkLocal, NotReachedCause::Undecodable(_)))
    ));

    // An oversize stored event is undecodable too.
    let oversize = vec![0u8; usize::try_from(MAX_EVENT_BYTES)? + 1];
    local.write_event(&[9; 32], &oversize).await?;
    assert!(matches!(
        local.read_event(&[9; 32]).await,
        MemberRead::NotReached(NotReachedCause::Undecodable(
            RecordDecodeError::EventLength(_)
        ))
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Membership rules
// ---------------------------------------------------------------------------

#[tokio::test]
async fn platform_account_round_trips_handle_marker_and_event() -> TestResult {
    let device = Device::new(true, false)?;
    let mut set = device.create().await?;
    let event = max_event()?;
    set.write_entry(&entry()).await?;
    set.write_event(&[0x22; 32], &event).await?;

    let platform = SdkLocalMember::new(Arc::clone(device.platform_storage()?), &device.credential);
    assert_eq!(platform.read_entry().await, MemberRead::Reached(entry()));
    assert_eq!(
        platform.read_event(&[0x22; 32]).await,
        MemberRead::Reached(event.clone())
    );
    let read = set.read_entries().await?;
    assert_eq!(
        stores(&read),
        [CredentialStore::SdkLocal, CredentialStore::PlatformAccount]
    );
    assert!(read.per_store.iter().all(|r| r.entry == Some(entry())));

    // Must fail: a member that returns the event one byte short (65,535
    // bytes) fails the comparison.
    device
        .platform_storage()?
        .truncate_events
        .store(true, Ordering::SeqCst);
    let MemberRead::Reached(short) = platform.read_event(&[0x22; 32]).await else {
        return Err("truncated event not reached".into());
    };
    assert_eq!(short.len(), 65_535);
    assert_ne!(short, event);
    Ok(())
}

#[tokio::test]
async fn large_blob_round_trips_handle_and_marker() -> TestResult {
    let device = Device::new(false, true)?;
    let mut set = device.create().await?;
    assert_eq!(set.record().large_blob, LargeBlobMembership::NotMember);
    assert_eq!(set.write_entry(&entry()).await?, LargeBlobWrite::Landed);
    assert_eq!(set.record().large_blob, LargeBlobMembership::Member);
    let read = set.read_entries().await?;
    assert_eq!(
        stores(&read),
        [CredentialStore::SdkLocal, CredentialStore::LargeBlob]
    );
    assert!(read.per_store.iter().all(|r| r.entry == Some(entry())));
    // The record that added the member is the one a reopened set reads.
    assert_eq!(
        device.open().await?.record().large_blob,
        LargeBlobMembership::Member
    );

    // Must fail: a record with flag bit 2 set is refused.
    let mut bytes = device.large_blob()?.raw().ok_or("no largeBlob record")?;
    bytes[0] |= 0b100;
    device.large_blob()?.set_raw(bytes)?;
    let refusal = set
        .read_entries()
        .await
        .err()
        .ok_or("bit 2 record was read")?;
    assert_eq!(
        unreadable(&refusal),
        Some((
            CredentialStore::LargeBlob,
            &NotReachedCause::Undecodable(RecordDecodeError::UnknownFlags(0b111))
        ))
    );
    Ok(())
}

#[tokio::test]
async fn large_blob_write_not_landed_removes_only_that_member() -> TestResult {
    let device = Device::new(true, true)?;
    let mut set = device.create().await?;
    assert_eq!(set.write_entry(&entry()).await?, LargeBlobWrite::Landed);
    device
        .large_blob()?
        .refuse_next_writes(LargeBlobNotLanded {
            cause: None,
            clears_by: LargeBlobClearingAct::RemoveConsumingCredential,
        })?;
    let next = StoreEntry::Handle(handle(RecoveryPhase::PublishSent));
    assert_eq!(
        set.write_entry(&next).await?,
        LargeBlobWrite::NotLanded {
            cause: None,
            clears_by: LargeBlobClearingAct::RemoveConsumingCredential,
        }
    );
    let expected = StoreSetRecord {
        credential_id: device.credential.clone(),
        platform_account: PlatformAccountMember::Present,
        large_blob: LargeBlobMembership::NotMember,
    };
    assert_eq!(set.record(), &expected);
    // Both record copies carry the removal.
    let platform = SdkLocalMember::new(Arc::clone(device.platform_storage()?), &device.credential);
    assert_eq!(
        platform.read_record().await,
        MemberRead::Reached(expected.clone())
    );
    assert_eq!(device.open().await?.record(), &expected);
    // The next read set is the local store and the platform account; the
    // largeBlob store, unreachable now, no longer refuses the read.
    device
        .large_blob()?
        .fail_reads
        .store(true, Ordering::SeqCst);
    let read = set.read_entries().await?;
    assert_eq!(
        stores(&read),
        [CredentialStore::SdkLocal, CredentialStore::PlatformAccount]
    );
    assert!(read.per_store.iter().all(|r| r.entry == Some(next)));
    Ok(())
}

#[tokio::test]
async fn large_blob_write_not_landed_reports_cause_and_clearing_act() -> TestResult {
    let device = Device::new(false, true)?;
    let mut set = device.create().await?;
    device.large_blob()?.refuse_next_writes(not_landed())?;
    assert_eq!(
        set.write_entry(&entry()).await?,
        LargeBlobWrite::NotLanded {
            cause: Some("NotAllowedError".to_owned()),
            clears_by: LargeBlobClearingAct::RetryVerification,
        }
    );
    assert_eq!(set.record().large_blob, LargeBlobMembership::NotMember);
    Ok(())
}

#[tokio::test]
async fn platform_account_write_failure_refuses_and_keeps_member() -> TestResult {
    let device = Device::new(true, true)?;
    let mut set = device.create().await?;
    // A first write lands everywhere, so the failing write below changes no
    // membership and the only platform write it makes is the entry itself.
    assert_eq!(set.write_entry(&entry()).await?, LargeBlobWrite::Landed);
    device
        .platform_storage()?
        .fail_writes
        .store(true, Ordering::SeqCst);

    let next = StoreEntry::Marker(marker());
    let refusal = set
        .write_entry(&next)
        .await
        .err()
        .ok_or("write was accepted")?;
    assert_eq!(
        refusal,
        RecoveryStoreError::PlatformAccountWriteFailed {
            cause: "storage error: injected write failure".to_owned()
        }
    );
    let refusal = set
        .write_event(&[1; 32], &[1, 2, 3])
        .await
        .err()
        .ok_or("event write was accepted")?;
    assert!(matches!(
        refusal,
        RecoveryStoreError::PlatformAccountWriteFailed { .. }
    ));
    assert_eq!(
        set.record().platform_account,
        PlatformAccountMember::Present
    );
    assert_eq!(
        device.open().await?.record().platform_account,
        PlatformAccountMember::Present
    );
    // The member is still read once its store recovers.
    device
        .platform_storage()?
        .fail_writes
        .store(false, Ordering::SeqCst);
    let read = set.read_entries().await?;
    assert!(stores(&read).contains(&CredentialStore::PlatformAccount));
    Ok(())
}

#[tokio::test]
async fn unreachable_recorded_member_returns_store_partially_unreadable() -> TestResult {
    let device = Device::new(true, true)?;
    let mut set = device.create().await?;
    set.write_entry(&entry()).await?;
    assert!(set.read_entries().await.is_ok());

    // Must fail: a recorded Present platform account whose read is not
    // reached refuses, though the other members answer.
    device
        .platform_storage()?
        .fail_reads
        .store(true, Ordering::SeqCst);
    let refusal = set
        .read_entries()
        .await
        .err()
        .ok_or("partial read accepted")?;
    assert!(matches!(
        unreadable(&refusal),
        Some((
            CredentialStore::PlatformAccount,
            NotReachedCause::Unreachable { .. }
        ))
    ));
    device
        .platform_storage()?
        .fail_reads
        .store(false, Ordering::SeqCst);

    // A recorded largeBlob member that does not answer refuses too.
    device
        .large_blob()?
        .fail_reads
        .store(true, Ordering::SeqCst);
    let refusal = set
        .read_entries()
        .await
        .err()
        .ok_or("partial read accepted")?;
    assert!(matches!(
        unreadable(&refusal),
        Some((
            CredentialStore::LargeBlob,
            NotReachedCause::Unreachable { .. }
        ))
    ));
    Ok(())
}

#[tokio::test]
async fn recorded_member_this_device_lacks_refuses_reads_and_writes() -> TestResult {
    let creator = Device::new(true, true)?;
    let mut set = creator.create().await?;
    set.write_entry(&entry()).await?;

    // The same stores, reached from a profile with no platform-account
    // member and no largeBlob store.
    let lacking = Device {
        credential: creator.credential.clone(),
        local: Arc::clone(&creator.local),
        platform: None,
        platform_absence: PlatformAccountAbsence::NoDataApiToCredentialSyncStore,
        large_blob: None,
    };
    let mut opened = lacking.open().await?;
    assert_eq!(opened.record(), set.record());
    let refusal = opened
        .read_entries()
        .await
        .err()
        .ok_or("partial read accepted")?;
    assert_eq!(
        unreadable(&refusal),
        Some((
            CredentialStore::PlatformAccount,
            &NotReachedCause::NoStoreOnDevice
        ))
    );
    let refusal = opened
        .write_entry(&entry())
        .await
        .err()
        .ok_or("write accepted")?;
    assert_eq!(
        unreadable(&refusal),
        Some((
            CredentialStore::PlatformAccount,
            &NotReachedCause::NoStoreOnDevice
        ))
    );

    // With the platform account reached, the missing largeBlob store refuses.
    let no_blob = Device {
        platform: creator.platform.clone(),
        ..lacking
    };
    let refusal = no_blob
        .open()
        .await?
        .read_entries()
        .await
        .err()
        .ok_or("partial read accepted")?;
    assert_eq!(
        unreadable(&refusal),
        Some((
            CredentialStore::LargeBlob,
            &NotReachedCause::NoStoreOnDevice
        ))
    );
    Ok(())
}

#[tokio::test]
async fn running_profile_never_changes_record() -> TestResult {
    let mut headless = Device::new(false, false)?;
    headless.platform_absence = PlatformAccountAbsence::NoPlatformCredential;
    let created = headless.create().await?;
    let recorded = created.record().clone();
    assert_eq!(
        recorded.platform_account,
        PlatformAccountMember::Absent(PlatformAccountAbsence::NoPlatformCredential)
    );

    // A later SDK on a profile that has a platform-account member opens the
    // same local store: the record stands and the member is never written.
    let later = Device {
        platform: Some(TestStorage::shared()),
        ..headless
    };
    let mut set = later.open().await?;
    assert_eq!(set.record(), &recorded);
    set.write_entry(&entry()).await?;
    set.write_event(&[1; 32], &[1]).await?;
    assert_eq!(
        stores(&set.read_entries().await?),
        [CredentialStore::SdkLocal]
    );
    assert_eq!(later.platform_storage()?.key_count(), 0);

    // Creation again under the new profile is refused: the record is
    // written once.
    assert_eq!(
        later.create().await.err(),
        Some(RecoveryStoreError::RecordAlreadyWritten)
    );
    Ok(())
}

#[tokio::test]
async fn create_writes_record_to_local_and_platform_and_retries_cleanly() -> TestResult {
    let device = Device::new(true, false)?;
    device
        .platform_storage()?
        .fail_writes
        .store(true, Ordering::SeqCst);
    assert!(matches!(
        device.create().await.err(),
        Some(RecoveryStoreError::PlatformAccountWriteFailed { .. })
    ));
    device
        .platform_storage()?
        .fail_writes
        .store(false, Ordering::SeqCst);
    let set = device.create().await?;
    let platform = SdkLocalMember::new(Arc::clone(device.platform_storage()?), &device.credential);
    assert_eq!(
        platform.read_record().await,
        MemberRead::Reached(set.record().clone())
    );
    Ok(())
}

#[tokio::test]
async fn open_adopts_platform_record_on_a_second_device() -> TestResult {
    let first = Device::new(true, false)?;
    let created = first.create().await?;
    let second = Device {
        credential: first.credential.clone(),
        local: TestStorage::shared(),
        platform: first.platform.clone(),
        platform_absence: first.platform_absence,
        large_blob: None,
    };
    let opened = second.open().await?;
    assert_eq!(opened.record(), created.record());
    let local = SdkLocalMember::new(Arc::clone(&second.local), &second.credential);
    assert_eq!(
        local.read_record().await,
        MemberRead::Reached(created.record().clone())
    );
    Ok(())
}

#[tokio::test]
async fn open_refuses_missing_and_foreign_records() -> TestResult {
    let device = Device::new(true, false)?;
    assert_eq!(
        device.open().await.err(),
        Some(RecoveryStoreError::RecordMissing)
    );

    // A record stored under this credential's key that names another
    // credential is refused.
    let local = SdkLocalMember::new(Arc::clone(&device.local), &device.credential);
    local
        .write_record(&StoreSetRecord {
            credential_id: credential(0xee)?,
            platform_account: PlatformAccountMember::Present,
            large_blob: LargeBlobMembership::NotMember,
        })
        .await?;
    assert_eq!(
        device.open().await.err(),
        Some(RecoveryStoreError::RecordCredentialMismatch)
    );

    // A local store that does not answer refuses the open.
    device.local.fail_reads.store(true, Ordering::SeqCst);
    assert!(matches!(
        device.open().await.err().as_ref().and_then(unreadable),
        Some((
            CredentialStore::SdkLocal,
            NotReachedCause::Unreachable { .. }
        ))
    ));
    Ok(())
}

#[tokio::test]
async fn write_event_refuses_empty_and_oversize_events() -> TestResult {
    let device = Device::new(false, false)?;
    let set = device.create().await?;
    let oversize = usize::try_from(MAX_EVENT_BYTES)? + 1;
    assert_eq!(
        set.write_event(&[1; 32], &[]).await,
        Err(RecoveryStoreError::EventLength { len: 0 })
    );
    assert_eq!(
        set.write_event(&[1; 32], &vec![0; oversize]).await,
        Err(RecoveryStoreError::EventLength { len: oversize })
    );
    assert_eq!(set.read_event(&[1; 32]).await, Ok(None));
    Ok(())
}

#[tokio::test]
async fn read_event_falls_back_to_platform_and_refuses_an_unanswered_miss() -> TestResult {
    let device = Device::new(true, false)?;
    let set = device.create().await?;
    let platform = SdkLocalMember::new(Arc::clone(device.platform_storage()?), &device.credential);
    platform.write_event(&[5; 32], &[5, 5]).await?;
    assert_eq!(set.read_event(&[5; 32]).await, Ok(Some(vec![5, 5])));

    // The local store does not answer and the platform account holds no
    // event: the miss is not reported as absence.
    device.local.fail_reads.store(true, Ordering::SeqCst);
    let refusal = set
        .read_event(&[6; 32])
        .await
        .err()
        .ok_or("miss reported as absent")?;
    assert!(matches!(
        unreadable(&refusal),
        Some((
            CredentialStore::SdkLocal,
            NotReachedCause::Unreachable { .. }
        ))
    ));
    Ok(())
}

#[tokio::test]
async fn sdk_local_write_failure_is_typed() -> TestResult {
    let device = Device::new(false, false)?;
    let mut set = device.create().await?;
    device.local.fail_writes.store(true, Ordering::SeqCst);
    assert!(matches!(
        set.write_entry(&entry()).await,
        Err(RecoveryStoreError::SdkLocalWriteFailed { .. })
    ));
    assert!(matches!(
        set.write_event(&[1; 32], &[1]).await,
        Err(RecoveryStoreError::SdkLocalWriteFailed { .. })
    ));
    Ok(())
}
