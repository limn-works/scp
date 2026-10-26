//! Tests for the SDK's local store-set member and the one-writer lease
//! (`09-security-model.md` §9.7.4.2 R10, `17-persistence-and-storage.md`
//! §17.3 and §17.8; SCP-311). The store set's own rules are tested in
//! `scp_kel::recovery_store`.

use std::collections::HashMap;
use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use scp_kel::recovery_store::{
    LastRevealMarker, NoLargeBlob, NoPlatformAccount, PlatformAccountAbsence, PlatformAccountSlot,
    RecoveryHandle, RecoveryPhase, RevealKind, StoreSet, StoreSetMembers,
};

use super::*;
use crate::PlatformError;
use crate::traits::Storage;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// SHA-256 of 64 bytes of `0xc1`, as lowercase hex.
const C1_COMPONENT: &str = "4891e00a13c5813f53b9e832a034ece86ff4dd143dd876287c830949e0f31115";

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

/// A test-only encrypted storage: a map with switches that make reads or
/// writes fail.
#[derive(Default)]
struct TestStorage {
    map: Mutex<HashMap<String, Vec<u8>>>,
    fail_reads: AtomicBool,
    fail_writes: AtomicBool,
}

impl TestStorage {
    fn raw(&self, key: &str) -> Option<Vec<u8>> {
        self.map.lock().ok()?.get(key).cloned()
    }

    fn set_raw(&self, key: &str, bytes: &[u8]) -> Result<(), String> {
        self.map
            .lock()
            .map_err(|e| e.to_string())?
            .insert(key.to_owned(), bytes.to_vec());
        Ok(())
    }

    fn keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self
            .map
            .lock()
            .map(|map| map.keys().cloned().collect())
            .unwrap_or_default();
        keys.sort();
        keys
    }

    fn fault(flag: &AtomicBool, what: &str) -> Result<(), PlatformError> {
        if flag.load(Ordering::SeqCst) {
            return Err(PlatformError::StorageError(format!(
                "injected {what} failure"
            )));
        }
        Ok(())
    }

    fn locked(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, Vec<u8>>>, PlatformError> {
        self.map
            .lock()
            .map_err(|e| PlatformError::StorageError(e.to_string()))
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
            self.locked().map(|mut map| {
                map.insert(key.to_owned(), data.to_vec());
            })
        });
        std::future::ready(result)
    }

    fn retrieve(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, PlatformError>> + Send {
        let result = Self::fault(&self.fail_reads, "read")
            .and_then(|()| self.locked().map(|map| map.get(key).cloned()));
        std::future::ready(result)
    }

    fn delete(&self, key: &str) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let result = self.locked().map(|mut map| {
            map.remove(key);
        });
        std::future::ready(result)
    }

    fn list_keys(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<String>, PlatformError>> + Send {
        let result = self.locked().map(|map| {
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
        let result = self.locked().map(|mut map| {
            let before = map.len();
            map.retain(|k, _| !k.starts_with(prefix));
            u64::try_from(before - map.len()).unwrap_or(u64::MAX)
        });
        std::future::ready(result)
    }

    fn exists(&self, key: &str) -> impl Future<Output = Result<bool, PlatformError>> + Send {
        let result = self.locked().map(|map| map.contains_key(key));
        std::future::ready(result)
    }
}

fn credential() -> Result<CredentialId, Box<dyn std::error::Error>> {
    Ok(CredentialId::new(vec![0xc1; 64])?)
}

const fn identifier() -> Identifier {
    Identifier::from_bytes([0x07; 32])
}

fn handle(digest: u8, phase: RecoveryPhase) -> RecoveryHandle {
    RecoveryHandle::new(
        RevealKind::FixesCommitment,
        identifier(),
        phase,
        [digest; 32],
    )
}

const fn marker(sequence: u64, digest: u8) -> LastRevealMarker {
    LastRevealMarker {
        identifier: identifier(),
        sequence,
        event_digest: [digest; 32],
    }
}

// ---------------------------------------------------------------------------
// SdkLocalMember
// ---------------------------------------------------------------------------

/// Mutant K: a raw identifier in the key. The entry and the event sit under
/// `recovery/{sha256_hex(credential_id)}/` and nowhere else, and the local
/// member writes no record.
#[test]
fn local_member_keys_are_the_hashed_credential() -> TestResult {
    let storage = Arc::new(TestStorage::default());
    let member = SdkLocalMember::new(Arc::clone(&storage), &credential()?);
    let entry = StoreEntry::new(Some(handle(0x11, RecoveryPhase::Composed)), None);
    run(member.write_entry(&entry))?;
    run(member.write_event(&[0x22; 32], b"signed event"))?;
    let entry_key = format!("recovery/{C1_COMPONENT}/entry");
    let event_key = format!("recovery/{C1_COMPONENT}/event/{}", "22".repeat(32));
    assert_eq!(storage.keys(), vec![entry_key.clone(), event_key]);
    assert_eq!(storage.raw(&entry_key), Some(encode_entry(&entry)));
    Ok(())
}

/// The skip bit is the local store's alone, so the local member reads it
/// back; a missing key and the one byte `0x00` both read as empty.
#[test]
fn local_member_round_trips_the_skip_bit_and_reads_empty() -> TestResult {
    let storage = Arc::new(TestStorage::default());
    let member = SdkLocalMember::new(Arc::clone(&storage), &credential()?);
    assert_eq!(run(member.read_entry()), MemberRead::ReachedEmpty);
    let skipped = StoreEntry::large_blob_skipped(
        handle(0x11, RecoveryPhase::Composed),
        Some(marker(3, 0x33)),
    );
    run(member.write_entry(&skipped))?;
    assert_eq!(run(member.read_entry()), MemberRead::Reached(skipped));
    storage.set_raw(&credential()?.entry_key(), &[0x00])?;
    assert_eq!(run(member.read_entry()), MemberRead::ReachedEmpty);
    Ok(())
}

/// A storage failure is a member not reached, never an empty read, and a
/// write failure carries the storage's cause.
#[test]
fn local_member_storage_failures_are_typed() -> TestResult {
    let storage = Arc::new(TestStorage::default());
    let member = SdkLocalMember::new(Arc::clone(&storage), &credential()?);
    storage.fail_reads.store(true, Ordering::SeqCst);
    let read = run(member.read_entry());
    let MemberRead::NotReached(NotReachedCause::Unreachable { cause }) = read else {
        return Err(format!("expected Unreachable, got {read:?}").into());
    };
    assert!(cause.contains("injected read failure"), "{cause}");
    storage.fail_reads.store(false, Ordering::SeqCst);
    storage.fail_writes.store(true, Ordering::SeqCst);
    let written = run(member.write_entry(&StoreEntry::EMPTY));
    let Err(StoreWriteFailure { cause }) = written else {
        return Err(format!("expected a write failure, got {written:?}").into());
    };
    assert!(cause.contains("injected write failure"), "{cause}");
    Ok(())
}

/// Stored bytes that do not decode, and a stored event outside
/// 1..=`MAX_EVENT_BYTES`, read as not reached.
#[test]
fn local_member_refuses_undecodable_bytes() -> TestResult {
    let storage = Arc::new(TestStorage::default());
    let credential = credential()?;
    let member = SdkLocalMember::new(Arc::clone(&storage), &credential);
    storage.set_raw(&credential.entry_key(), &[0x08])?;
    assert_eq!(
        run(member.read_entry()),
        MemberRead::NotReached(NotReachedCause::Undecodable(
            RecordDecodeError::UnknownFlags(0x08)
        ))
    );
    storage.set_raw(&credential.event_key(&[0x22; 32]), &[])?;
    assert_eq!(
        run(member.read_event(&[0x22; 32])),
        MemberRead::NotReached(NotReachedCause::Undecodable(
            RecordDecodeError::EventLength(0)
        ))
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// RecoveryLeases
// ---------------------------------------------------------------------------

/// Mutant M13: no lease. A second lease on the pair is refused while the
/// first is held, and released when it drops; another identity on the same
/// credential takes its own lease.
#[test]
fn a_second_lease_on_the_pair_is_refused_until_the_first_drops() -> TestResult {
    let leases = RecoveryLeases::new();
    let first = leases.acquire(credential()?, identifier())?;
    assert!(matches!(
        leases.acquire(credential()?, identifier()),
        Err(RecoveryStoreError::SetInUse)
    ));
    let other_identity = leases.acquire(credential()?, Identifier::from_bytes([0x08; 32]))?;
    assert_eq!(
        other_identity.identifier(),
        Identifier::from_bytes([0x08; 32])
    );
    drop(first);
    let again = leases.acquire(credential()?, identifier())?;
    assert_eq!(again.credential_id(), &credential()?);
    Ok(())
}

/// Mutant M23: the lease keyed on the storage instance. Two storage
/// instances over one database, each behind its own `SdkLocalMember`, share
/// the registry injected for that database, so the second store set cannot
/// open while the first holds the lease.
#[test]
fn two_storage_instances_over_one_database_share_the_lease() -> TestResult {
    let database = Arc::new(TestStorage::default());
    let leases_for_db = RecoveryLeases::new();
    let first = run(StoreSet::open(
        local_only(Arc::clone(&database))?,
        leases_for_db.acquire(credential()?, identifier())?,
    ))?;
    let second_instance = Arc::clone(&database);
    assert!(matches!(
        leases_for_db.acquire(credential()?, identifier()),
        Err(RecoveryStoreError::SetInUse)
    ));
    drop(first);
    let second = run(StoreSet::open(
        local_only(second_instance)?,
        leases_for_db.acquire(credential()?, identifier())?,
    ))?;
    assert!(run(second.read_set())?.pending().is_empty());
    Ok(())
}

/// A store set over the SDK's local member alone composes, and the entry
/// lands under the credential's key.
#[test]
fn a_local_only_set_composes_through_the_local_member() -> TestResult {
    let database = Arc::new(TestStorage::default());
    let leases = RecoveryLeases::new();
    let mut set = run(StoreSet::open(
        local_only(Arc::clone(&database))?,
        leases.acquire(credential()?, identifier())?,
    ))?;
    let report = run(set.compose(RevealKind::Abandons, [0x44; 32], None))?;
    report.completed()?;
    let expected = StoreEntry::new(
        Some(RecoveryHandle::new(
            RevealKind::Abandons,
            identifier(),
            RecoveryPhase::Composed,
            [0x44; 32],
        )),
        None,
    );
    assert_eq!(
        database.raw(&format!("recovery/{C1_COMPONENT}/entry")),
        Some(encode_entry(&expected))
    );
    Ok(())
}

type LocalOnly = StoreSetMembers<SdkLocalMember<Arc<TestStorage>>, NoPlatformAccount, NoLargeBlob>;

fn local_only(storage: Arc<TestStorage>) -> Result<LocalOnly, Box<dyn std::error::Error>> {
    Ok(StoreSetMembers {
        sdk_local: SdkLocalMember::new(storage, &credential()?),
        platform_account: PlatformAccountSlot::Absent(
            PlatformAccountAbsence::NoDataApiToCredentialSyncStore,
        ),
        large_blob: None,
    })
}
