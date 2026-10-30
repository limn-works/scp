//! Tests for `Identity::create`, `Identity::abandon_pending`,
//! `Identity::unfinished` and `Identity::abandon_unfinished`
//! (`03-identity.md` §3.10.10; SCP-006 AC1–5, 9, 15, 17–22).

#![cfg(test)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use scp_did::{CustodyProfile, CustodyType, FixedCommitment, Identifier, KeyCondition, KeyRole};
use scp_kel::{
    CheckStep, Continuation, CustodyProbe, EventKind, IndexedSignature, KeyEventSignError,
    KeyEventSigner, ProbeSignature, SignatureForm, SigningChange, decode_preimage,
};
use scp_platform::encrypting_adapter::EncryptingAdapter;
use scp_platform::in_memory::InMemoryStorage;
use scp_platform::sqlite::SqliteStorage;
use scp_platform::testing::{InMemoryKeyCustody, InMemoryNextSetCustody};
use scp_platform::{
    BackupArtifact, BackupRequest, CustodyType as PlatformCustodyType, KeyCustody, KeyHandle,
    KeyType, NextSetCustody, NextSetCustodyError, NextSetKeyHandle, PlatformError,
    PreRotationCustodyKind, Pseudonym, PublicKey, RestoreMaterial, SharedSecret, Signature,
    Storage,
};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;
use zeroize::Zeroizing;

use super::super::device_record::{EventRef, read_device_record, write_device_record};
use super::*;
use crate::kel::{
    KeptComposition, KeyCustodySlot, ListedOperator, NextSetCustodySlot, RecordLock,
    UndestroyedKey, Unfinished, WitnessChoice, WitnessDesignation, WitnessWarning,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Store = Arc<EncryptingAdapter<InMemoryStorage>>;

const SEPARATOR: &[u8] = b"SCP-KEL-EVENT-V1:";

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the recording custodies saw, and the faults a test injects.
#[derive(Default)]
struct Rec {
    calls: Mutex<Vec<&'static str>>,
    keys: Mutex<Vec<KeyHandle>>,
    keys_destroyed: Mutex<Vec<KeyHandle>>,
    next: Mutex<Vec<NextSetKeyHandle>>,
    next_destroyed: Mutex<Vec<NextSetKeyHandle>>,
    revealed: Mutex<Option<[u8; 33]>>,
    key_types: Mutex<Vec<KeyType>>,
    fail_key_event_generate: AtomicBool,
    fail_active_generate: AtomicBool,
    panic_active_generate: AtomicBool,
    fail_key_destroy: AtomicBool,
    fail_next_destroy: AtomicBool,
    /// `#0` reports `PlatformCustodyType::Hardware` while set.
    hardware_root: AtomicBool,
    hardware: Mutex<Vec<KeyHandle>>,
    probe_with_other_key: AtomicBool,
    hold_generate: AtomicBool,
    generated: Notify,
    release: Notify,
    /// `#active`'s generation never returns while set, and notifies
    /// `active_held` before it mints anything.
    hold_active_generate: AtomicBool,
    active_held: Notify,
}

impl Rec {
    fn call(&self, name: &'static str) {
        lock(&self.calls).push(name);
    }

    fn calls(&self) -> Vec<&'static str> {
        lock(&self.calls).clone()
    }

    fn count(&self, name: &str) -> usize {
        lock(&self.calls)
            .iter()
            .filter(|call| **call == name)
            .count()
    }

    fn generate_calls(&self) -> usize {
        self.count("generate")
            + self.count("generate_keypair")
            + self.count("generate_key_event_keypair")
    }

    fn live_keys(&self) -> usize {
        let destroyed = lock(&self.keys_destroyed);
        lock(&self.keys)
            .iter()
            .filter(|key| !destroyed.contains(key))
            .count()
    }

    fn live_next(&self) -> usize {
        let destroyed = lock(&self.next_destroyed);
        lock(&self.next)
            .iter()
            .filter(|key| !destroyed.contains(key))
            .count()
    }

    fn live(&self) -> usize {
        self.live_keys() + self.live_next()
    }
}

/// An in-memory key custody that records each call.
struct RecordingKeyCustody {
    inner: InMemoryKeyCustody,
    rec: Arc<Rec>,
}

impl KeyEventSigner for RecordingKeyCustody {
    type Member = KeyHandle;

    async fn sign_change(
        &self,
        member: &KeyHandle,
        change: &SigningChange,
    ) -> Result<IndexedSignature, KeyEventSignError> {
        self.inner.sign_change(member, change).await
    }

    async fn sign_probe(
        &self,
        member: &KeyHandle,
        probe: &CustodyProbe,
    ) -> Result<ProbeSignature, KeyEventSignError> {
        self.inner.sign_probe(member, probe).await
    }
}

impl KeyCustody for RecordingKeyCustody {
    async fn generate_keypair(&self, key_type: KeyType) -> Result<KeyHandle, PlatformError> {
        self.rec.call("generate_keypair");
        lock(&self.rec.key_types).push(key_type);
        assert!(
            !self.rec.panic_active_generate.load(Ordering::SeqCst),
            "injected panic generating #active"
        );
        if self.rec.fail_active_generate.load(Ordering::SeqCst) {
            return Err(PlatformError::StorageError("injected".to_owned()));
        }
        if self.rec.hold_active_generate.load(Ordering::SeqCst) {
            self.rec.active_held.notify_one();
            std::future::pending::<()>().await;
        }
        let key = self.inner.generate_keypair(key_type).await?;
        lock(&self.rec.keys).push(key);
        Ok(key)
    }

    async fn generate_key_event_keypair(&self) -> Result<KeyHandle, PlatformError> {
        self.rec.call("generate_key_event_keypair");
        if self.rec.fail_key_event_generate.load(Ordering::SeqCst) {
            return Err(PlatformError::StorageError("injected".to_owned()));
        }
        let key = self.inner.generate_key_event_keypair().await?;
        lock(&self.rec.keys).push(key);
        if self.rec.hardware_root.load(Ordering::SeqCst) {
            lock(&self.rec.hardware).push(key);
        }
        Ok(key)
    }

    async fn generate_identity_keypair(&self) -> Result<KeyHandle, PlatformError> {
        self.rec.call("generate_identity_keypair");
        self.inner.generate_identity_keypair().await
    }

    async fn sign(&self, key: &KeyHandle, data: &[u8]) -> Result<Signature, PlatformError> {
        self.inner.sign(key, data).await
    }

    async fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, PlatformError> {
        self.inner.public_key(key).await
    }

    async fn destroy_key(&self, key: &KeyHandle) -> Result<(), PlatformError> {
        self.rec.call("destroy_key");
        if self.rec.fail_key_destroy.load(Ordering::SeqCst) {
            return Err(PlatformError::StorageError("injected".to_owned()));
        }
        self.inner.destroy_key(key).await?;
        lock(&self.rec.keys_destroyed).push(*key);
        Ok(())
    }

    async fn dh_agree(
        &self,
        key: &KeyHandle,
        peer_public: &[u8],
    ) -> Result<SharedSecret, PlatformError> {
        self.inner.dh_agree(key, peer_public).await
    }

    async fn derive_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
    ) -> Result<Pseudonym, PlatformError> {
        self.inner.derive_pseudonym(key, context_id).await
    }

    async fn derive_rotatable_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
        pseudonym_epoch: u64,
    ) -> Result<Pseudonym, PlatformError> {
        self.inner
            .derive_rotatable_pseudonym(key, context_id, pseudonym_epoch)
            .await
    }

    fn custody_type(&self, key: &KeyHandle) -> PlatformCustodyType {
        if lock(&self.rec.hardware).contains(key) {
            return PlatformCustodyType::Hardware;
        }
        self.inner.custody_type(key)
    }
}

/// An in-memory next-set custody that records each call and reports
/// `kind`.
struct RecordingNextSetCustody {
    inner: InMemoryNextSetCustody,
    rec: Arc<Rec>,
    kind: PreRotationCustodyKind,
}

impl KeyEventSigner for RecordingNextSetCustody {
    type Member = NextSetKeyHandle;

    async fn sign_change(
        &self,
        member: &NextSetKeyHandle,
        change: &SigningChange,
    ) -> Result<IndexedSignature, KeyEventSignError> {
        self.inner.sign_change(member, change).await
    }

    async fn sign_probe(
        &self,
        member: &NextSetKeyHandle,
        probe: &CustodyProbe,
    ) -> Result<ProbeSignature, KeyEventSignError> {
        self.rec.call("sign_probe");
        if self.rec.probe_with_other_key.load(Ordering::SeqCst) {
            let other = self
                .inner
                .generate()
                .await
                .map_err(|_| KeyEventSignError::MemberNotFound)?;
            let signature = self.inner.sign_probe(&other, probe).await;
            let _destroyed = self.inner.destroy(&other).await;
            return signature;
        }
        self.inner.sign_probe(member, probe).await
    }
}

impl NextSetCustody for RecordingNextSetCustody {
    async fn generate(&self) -> Result<NextSetKeyHandle, NextSetCustodyError> {
        self.rec.call("generate");
        let handle = self.inner.generate().await?;
        lock(&self.rec.next).push(handle);
        self.rec.generated.notify_one();
        if self.rec.hold_generate.load(Ordering::SeqCst) {
            self.rec.release.notified().await;
        }
        Ok(handle)
    }

    async fn reveal_public_key(
        &self,
        handle: &NextSetKeyHandle,
    ) -> Result<[u8; 33], NextSetCustodyError> {
        self.rec.call("reveal_public_key");
        let point = self.inner.reveal_public_key(handle).await?;
        *lock(&self.rec.revealed) = Some(point);
        Ok(point)
    }

    async fn destroy(&self, handle: &NextSetKeyHandle) -> Result<(), NextSetCustodyError> {
        self.rec.call("destroy");
        if self.rec.fail_next_destroy.load(Ordering::SeqCst) {
            return Err(NextSetCustodyError::Unavailable("injected".to_owned()));
        }
        self.inner.destroy(handle).await?;
        lock(&self.rec.next_destroyed).push(*handle);
        Ok(())
    }

    async fn seal_backup(
        &self,
        handle: &NextSetKeyHandle,
        request: BackupRequest,
    ) -> Result<BackupArtifact, NextSetCustodyError> {
        self.inner.seal_backup(handle, request).await
    }

    async fn restore(
        &self,
        material: RestoreMaterial,
        expected_commitment: [u8; 32],
    ) -> Result<NextSetKeyHandle, NextSetCustodyError> {
        self.inner.restore(material, expected_commitment).await
    }

    fn custody_kind(&self) -> PreRotationCustodyKind {
        self.kind
    }
}

fn store() -> Store {
    Arc::new(EncryptingAdapter::new(
        InMemoryStorage::new(),
        Zeroizing::new([3; 32]),
    ))
}

fn config_over<S: scp_platform::EncryptedStorage + Clone>(
    rec: &Arc<Rec>,
    kind: PreRotationCustodyKind,
    profile: CustodyProfile,
    persistence: S,
) -> IdentityConfig<S> {
    IdentityConfig {
        custody: KeyCustodySlot::custom(RecordingKeyCustody {
            inner: InMemoryKeyCustody::new(),
            rec: Arc::clone(rec),
        }),
        next_set_custody: NextSetCustodySlot::custom(RecordingNextSetCustody {
            inner: InMemoryNextSetCustody::new(),
            rec: Arc::clone(rec),
            kind,
        }),
        persistence,
        profile,
        witnesses: WitnessChoice::NoWitness,
        record_lock: RecordLock::new(),
    }
}

/// A config whose next-set custody declares `Passkey` on `Desktop`, which
/// the profile offers.
fn desktop(rec: &Arc<Rec>) -> IdentityConfig<Store> {
    config_over(
        rec,
        PreRotationCustodyKind::PlatformCloudKeyStore,
        CustodyProfile::Desktop,
        store(),
    )
}

fn plan(members: Vec<(u8, SignatureForm)>) -> SignerPlan {
    SignerPlan::Groups {
        reveal: GroupSigners { members: vec![] },
        installed_root: GroupSigners { members },
        standing_root: GroupSigners { members: vec![] },
    }
}

fn one_root() -> SignerPlan {
    plan(vec![(0, SignatureForm::Raw)])
}

fn pending_of(outcome: EventOutcome) -> PendingEvent {
    match outcome {
        EventOutcome::AwaitingSignatures(pending) => pending,
    }
}

async fn created<S: scp_platform::EncryptedStorage + Clone + 'static>(
    config: IdentityConfig<S>,
) -> Result<(Identity<S>, PendingEvent), Box<dyn std::error::Error>> {
    let Created {
        identity, outcome, ..
    } = Identity::create(config, one_root()).await?;
    Ok((identity, pending_of(outcome)))
}

async fn eventually(what: &str, done: impl Fn() -> bool + Send + Sync) -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .map_err(|_| format!("timed out waiting for {what}"))?;
    Ok(())
}

async fn records<S: Storage>(store: &S) -> Result<Vec<String>, PlatformError> {
    store.list_keys("identity/").await
}

/// Waits until `store` holds `count` identity records.
async fn records_reach<S: Storage>(store: &S, count: usize) -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match records(store).await {
                Ok(keys) if keys.len() == count => return Ok(()),
                Ok(_) => tokio::time::sleep(Duration::from_millis(2)).await,
                Err(error) => return Err(error),
            }
        }
    })
    .await
    .map_err(|_| format!("timed out waiting for {count} records"))??;
    Ok(())
}

/// Waits until `store` holds one device record and no creation record.
async fn device_record_alone<S: Storage>(store: &S) -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match records(store).await {
                Ok(keys) if keys.len() == 1 && keys[0].ends_with("/device_state") => {
                    return Ok(());
                }
                Ok(_) => tokio::time::sleep(Duration::from_millis(2)).await,
                Err(error) => return Err(error),
            }
        }
    })
    .await
    .map_err(|_| "timed out waiting for the device record alone")??;
    Ok(())
}

// AC1, AC2.
#[tokio::test]
async fn create_groups_returns_awaiting_signatures() -> TestResult {
    let rec = Arc::new(Rec::default());
    let (identity, pending) = created(desktop(&rec)).await?;
    assert_eq!(
        rec.calls(),
        [
            "generate",
            "reveal_public_key",
            "sign_probe",
            "generate_key_event_keypair",
            "generate_keypair",
        ]
    );
    assert_eq!(*lock(&rec.key_types), [KeyType::P256Signing], "#active");
    assert_eq!(rec.live_keys(), 2, "#0 and #active");
    assert_eq!(rec.live_next(), 1, "one next-set member");
    assert_eq!(pending.identifier, *identity.identifier());
    assert!(pending.chain.is_empty());
    assert_eq!(pending.event_digest, sha256(&[&pending.preimage]));
    Ok(())
}

// AC1: a failure after the next-set member exists destroys it.
#[tokio::test]
async fn a_root_generation_failure_destroys_the_next_set_member() -> TestResult {
    let rec = Arc::new(Rec::default());
    rec.fail_key_event_generate.store(true, Ordering::SeqCst);
    let config = desktop(&rec);
    let store = config.persistence.clone();
    let error = Identity::create(config, one_root())
        .await
        .err()
        .ok_or("create succeeded")?
        .error;
    assert_eq!(error, IdentityError::CustodySigningFailed);
    assert_eq!(rec.count("destroy"), 1);
    assert_eq!(rec.live(), 0);
    assert!(records(&store).await?.is_empty());
    Ok(())
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

// AC3.
#[tokio::test]
async fn the_commitment_hashes_the_revealed_compressed_point() -> TestResult {
    let rec = Arc::new(Rec::default());
    let (identity, pending) = created(desktop(&rec)).await?;
    let point = lock(&rec.revealed).ok_or("nothing revealed")?;
    let expected = sha256(&[b"SCP-PREROTATION-COMMITMENT-V1:", &point]);
    let standing = &identity.scp_identity().pre_rotation_commitment;
    assert_eq!(standing.commitments.len(), 1);
    assert_eq!(standing.commitments[0].commitment, expected);
    assert_eq!(standing.commitments[0].custody_type, CustodyType::Passkey);
    assert_eq!(standing.next_threshold, 1);
    let fields = pending
        .preimage
        .strip_prefix(SEPARATOR)
        .ok_or("no separator")?;
    let decoded = decode_preimage(fields)?;
    assert_eq!(
        decoded.preimage().continuation,
        Some(Continuation::FixesCommitment(standing.clone()))
    );
    Ok(())
}

// AC4.
#[tokio::test]
async fn the_identifier_hashes_the_signed_preimage() -> TestResult {
    let rec = Arc::new(Rec::default());
    let (identity, pending) = created(desktop(&rec)).await?;
    let expected = Identifier::from_bytes(sha256(&[b"SCP-KEL-ID-V1:", &pending.preimage]));
    assert_eq!(*identity.identifier(), expected);
    // A verifier derives the same identifier from the bytes it decodes.
    let fields = pending
        .preimage
        .strip_prefix(SEPARATOR)
        .ok_or("no separator")?;
    assert_eq!(
        scp_kel::derive_identifier(decode_preimage(fields)?.preimage())?,
        expected
    );
    Ok(())
}

// AC5.
#[tokio::test]
async fn the_inception_carries_the_snapshot() -> TestResult {
    let rec = Arc::new(Rec::default());
    let config = desktop(&rec);
    let (identity, pending) = created(config.clone()).await?;
    let keys = identity.scp_identity();
    let root_point = <[u8; 33]>::try_from(
        config
            .custody
            .public_key(&keys.identity_key)
            .await?
            .as_bytes(),
    )?;
    let active_point = <[u8; 33]>::try_from(
        config
            .custody
            .public_key(&keys.active_signing_key)
            .await?
            .as_bytes(),
    )?;
    let fields = pending
        .preimage
        .strip_prefix(SEPARATOR)
        .ok_or("no separator")?;
    let decoded = decode_preimage(fields)?;
    let event = decoded.preimage();
    assert_eq!(event.kind, EventKind::Inception);
    assert_eq!(event.identifier, Identifier::ZERO);
    assert_eq!(event.sequence, 0);
    assert_eq!(event.predecessor_digest, [0; 32]);
    assert_eq!(event.standing_root, None);
    assert_eq!(
        event.signer_groups,
        [scp_kel::SignerGroup {
            indices: vec![0],
            forms: vec![SignatureForm::Raw],
        }]
    );
    assert!(event.revealed_keys.is_empty());
    let root_set = event.installed_root_set.as_ref().ok_or("no root set")?;
    assert_eq!(root_set.members, [root_point]);
    assert_eq!(root_set.threshold, 1);
    assert!(event.seals.is_empty());
    let state = event.key_state.as_ref().ok_or("no key state")?;
    assert_eq!(state.root_threshold, 1);
    assert!(state.witnesses.is_empty());
    assert_eq!(
        state.witnessing_interval,
        scp_kel::constants::DEFAULT_WITNESSING_INTERVAL
    );
    assert_eq!(state.service_key_role, KeyRole::Active);
    assert_eq!(state.delegator, Identifier::ZERO);
    let software = PlatformCustodyType::InMemory.key_entry_custody_type();
    assert_eq!(
        state.keys,
        [
            current_entry(root_point, KeyRole::RootMember, software),
            current_entry(active_point, KeyRole::Active, software),
        ]
    );
    assert!(
        state
            .keys
            .iter()
            .all(|key| key.condition == KeyCondition::Current)
    );
    Ok(())
}

// AC5: an interval under the floor is refused at step 8.
#[test]
fn an_interval_of_299_is_refused_at_content() -> TestResult {
    let point = scp_crypto::p256::P256SecretKey::from_scalar_bytes(&[7; 32])?
        .public_key()
        .to_compressed();
    let encoded = inception_preimage(&InceptionDraft {
        root: current_entry(point, KeyRole::RootMember, CustodyType::Software),
        active: current_entry(point, KeyRole::Active, CustodyType::Software),
        root_form: SignatureForm::Raw,
        commitment: FixedCommitment {
            commitments: vec![scp_did::CommitmentEntry {
                commitment: [1; 32],
                custody_type: CustodyType::Passkey,
                key_algorithm: scp_did::KeyAlgorithm::EcdsaP256Sha256,
            }],
            next_threshold: 1,
        },
        witnesses: vec![],
        witnessing_interval: 299,
    })?;
    let refusal = SigningChange::inception(&encoded.signed_preimage())
        .err()
        .ok_or("an interval of 299 passed")?;
    assert_eq!(
        IdentityError::from(refusal),
        IdentityError::IllegalKeyEvent {
            stage: CheckStep::Content
        }
    );
    Ok(())
}

// Each plan refusal comes before any key.
#[tokio::test]
async fn plan_refusals_mint_no_key() -> TestResult {
    let raw = SignatureForm::Raw;
    let cases = [
        (SignerPlan::ThisSdk, IdentityError::SignatureSetIncomplete),
        (plan(vec![]), IdentityError::SignatureSetIncomplete),
        (plan(vec![(1, raw)]), IdentityError::SignatureSetIncomplete),
        (
            SignerPlan::Groups {
                reveal: GroupSigners {
                    members: vec![(0, raw)],
                },
                installed_root: GroupSigners {
                    members: vec![(0, raw)],
                },
                standing_root: GroupSigners { members: vec![] },
            },
            IdentityError::SignatureSetIncomplete,
        ),
        (
            SignerPlan::Groups {
                reveal: GroupSigners { members: vec![] },
                installed_root: GroupSigners {
                    members: vec![(0, raw)],
                },
                standing_root: GroupSigners {
                    members: vec![(0, raw)],
                },
            },
            IdentityError::SignatureSetIncomplete,
        ),
        (
            plan(vec![(0, raw), (1, raw)]),
            IdentityError::ThresholdAdmitsDisjointQuorums,
        ),
    ];
    for (signers, expected) in cases {
        let rec = Arc::new(Rec::default());
        let error = Identity::create(desktop(&rec), signers.clone())
            .await
            .err()
            .ok_or("create succeeded")?
            .error;
        assert_eq!(error, expected, "{signers:?}");
        assert_eq!(rec.generate_calls(), 0, "{signers:?}");
    }
    assert_eq!(
        IdentityError::ThresholdAdmitsDisjointQuorums.code(),
        "SCP-IDENT-1115"
    );
    Ok(())
}

// AC15: the shipped build offers no method on Headless, so create refuses
// with 1100 before any key.
#[tokio::test]
async fn create_fails_closed_without_independent_substrate() -> TestResult {
    for kind in [
        PreRotationCustodyKind::PlatformCloudKeyStore,
        PreRotationCustodyKind::InMemory,
        PreRotationCustodyKind::EncryptedOfflineBackup,
        PreRotationCustodyKind::HardwareSecurityKey,
    ] {
        let rec = Arc::new(Rec::default());
        let config = config_over(&rec, kind, CustodyProfile::Headless, store());
        let error = Identity::create(config, one_root())
            .await
            .err()
            .ok_or("create succeeded on Headless")?
            .error;
        assert_eq!(error, IdentityError::NoIndependentSubstrate, "{kind:?}");
        assert_eq!(error.code(), "SCP-IDENT-1100");
        assert_eq!(rec.generate_calls(), 0, "{kind:?}");
    }
    Ok(())
}

// Q-A1: a method the profile does not admit, where another method is
// offered there, gives 1121 before any key.
#[tokio::test]
async fn a_method_not_offered_where_another_is_gives_1121() -> TestResult {
    for kind in [
        PreRotationCustodyKind::InMemory,
        PreRotationCustodyKind::Callback,
        PreRotationCustodyKind::SecondaryDeviceEnclave,
        PreRotationCustodyKind::PaperBackupBip39,
    ] {
        let rec = Arc::new(Rec::default());
        let config = config_over(&rec, kind, CustodyProfile::Desktop, store());
        let error = Identity::create(config, one_root())
            .await
            .err()
            .ok_or("create succeeded")?
            .error;
        assert_eq!(error, IdentityError::MethodNotOfferedOnProfile, "{kind:?}");
        assert_eq!(error.code(), "SCP-IDENT-1121");
        assert_eq!(rec.generate_calls(), 0, "{kind:?}");
    }
    Ok(())
}

// The offer check reads the profile: Passkey on Headless is never the floor.
#[test]
fn the_offer_check_follows_the_profile() {
    let passkey = PreRotationCustodyKind::PlatformCloudKeyStore;
    assert_eq!(
        check_offer(passkey, &CustodyProfile::Desktop),
        Ok(CustodyType::Passkey)
    );
    assert_eq!(
        check_offer(passkey, &CustodyProfile::Mobile),
        Ok(CustodyType::Passkey)
    );
    assert!(check_offer(passkey, &CustodyProfile::Headless).is_err());
    // A conforming hardware token is admitted while this build ships none,
    // because the caller supplied the custody.
    assert_eq!(
        check_offer(
            PreRotationCustodyKind::HardwareSecurityKey,
            &CustodyProfile::Desktop
        ),
        Ok(CustodyType::Fido2Token)
    );
}

// AC9.
#[tokio::test]
async fn scp_identity_holds_handles_and_the_commitment_list() -> TestResult {
    let rec = Arc::new(Rec::default());
    let (identity, _) = created(desktop(&rec)).await?;
    let ScpIdentity {
        identity_key,
        active_signing_key,
        pre_rotation_commitment,
        identifier,
    } = identity.scp_identity().clone();
    let pre_rotation_commitment: FixedCommitment = pre_rotation_commitment;
    assert_ne!(identity_key, active_signing_key);
    assert_eq!(pre_rotation_commitment.commitments.len(), 1);
    assert_eq!(identifier, *identity.identifier());
    Ok(())
}

// AC17.
#[tokio::test]
async fn a_probe_signed_by_another_key_gives_1111() -> TestResult {
    let rec = Arc::new(Rec::default());
    rec.probe_with_other_key.store(true, Ordering::SeqCst);
    let config = desktop(&rec);
    let store = config.persistence.clone();
    let error = Identity::create(config, one_root())
        .await
        .err()
        .ok_or("create succeeded")?
        .error;
    assert_eq!(error, IdentityError::CustodySigningFailed);
    assert_eq!(rec.count("generate_key_event_keypair"), 0);
    assert_eq!(rec.count("generate_keypair"), 0);
    assert_eq!(rec.live_next(), 0, "the member is destroyed");
    assert!(records(&store).await?.is_empty());
    Ok(())
}

// AC18.
#[tokio::test]
async fn create_persists_kept_composition_before_returning() -> TestResult {
    let rec = Arc::new(Rec::default());
    let config = desktop(&rec);
    let store = config.persistence.clone();
    let (identity, pending) = created(config).await?;
    let record = read_device_record(&store, identity.identifier())
        .await?
        .ok_or("no device record")?;
    let keys = identity.scp_identity();
    assert_eq!(record.root, [(0, keys.identity_key)]);
    assert_eq!(record.active, Some(keys.active_signing_key));
    assert_eq!(record.next, lock(&rec.next).clone());
    assert_eq!(
        record.kept,
        [EventRef {
            identifier: pending.identifier,
            sequence: 0,
            event_digest: pending.event_digest,
        }]
    );
    assert!(record.pending.is_empty());
    Ok(())
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        Self(std::env::temp_dir().join(format!(
            "scp-identity-{name}-{}-{nanos}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        )))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}

fn sqlite(dir: &TempDir) -> Result<Arc<EncryptingAdapter<SqliteStorage>>, PlatformError> {
    Ok(Arc::new(EncryptingAdapter::new(
        SqliteStorage::new(&dir.0, &[9; 32])?,
        Zeroizing::new([4; 32]),
    )))
}

// AC18.
#[tokio::test]
async fn device_record_written_by_create_is_read_by_a_second_writer() -> TestResult {
    let dir = TempDir::new("two-writer");
    let rec = Arc::new(Rec::default());
    let a = config_over(
        &rec,
        PreRotationCustodyKind::PlatformCloudKeyStore,
        CustodyProfile::Desktop,
        sqlite(&dir)?,
    );
    let custody = a.custody.clone();
    let next_set_custody = a.next_set_custody.clone();
    let record_lock = a.record_lock.clone();
    let Created {
        identity, outcome, ..
    } = Identity::create(a, one_root()).await?;
    let pending = pending_of(outcome);
    drop(identity);

    let b = IdentityConfig {
        custody: custody.clone(),
        next_set_custody: next_set_custody.clone(),
        persistence: sqlite(&dir)?,
        profile: CustodyProfile::Desktop,
        witnesses: WitnessChoice::NoWitness,
        record_lock,
    };
    Identity::abandon_pending(&b, &pending).await?;
    assert_eq!(rec.live(), 0);
    drop(b);

    let c = sqlite(&dir)?;
    assert!(read_device_record(&c, &pending.identifier).await?.is_none());
    assert!(records(&c).await?.is_empty());
    Ok(())
}

// AC19.
#[tokio::test]
async fn abandon_pending_destroys_every_key_then_refuses() -> TestResult {
    let rec = Arc::new(Rec::default());
    let config = desktop(&rec);
    let (_identity, pending) = created(config.clone()).await?;
    assert_eq!(rec.live(), 3);
    Identity::abandon_pending(&config, &pending).await?;
    assert_eq!(rec.count("destroy"), 1);
    assert_eq!(rec.count("destroy_key"), 2);
    assert_eq!(rec.live(), 0);
    assert!(records(&config.persistence).await?.is_empty());
    let again = Identity::abandon_pending(&config, &pending)
        .await
        .err()
        .ok_or("second abandon succeeded")?;
    assert_eq!(
        again,
        IdentityError::NoPendingSignature {
            event_digest: pending.event_digest
        }
    );
    assert_eq!(again.code(), "SCP-IDENT-1120");
    Ok(())
}

// AC19.
#[tokio::test]
async fn a_failed_destroy_keeps_the_record() -> TestResult {
    let rec = Arc::new(Rec::default());
    let config = desktop(&rec);
    let (identity, pending) = created(config.clone()).await?;
    rec.fail_key_destroy.store(true, Ordering::SeqCst);
    let error = Identity::abandon_pending(&config, &pending)
        .await
        .err()
        .ok_or("abandon succeeded")?;
    assert_eq!(error, IdentityError::CustodySigningFailed);
    let record = read_device_record(&config.persistence, identity.identifier())
        .await?
        .ok_or("the record is gone")?;
    assert_eq!(record.kept.len(), 1);
    rec.fail_key_destroy.store(false, Ordering::SeqCst);
    Identity::abandon_pending(&config, &pending).await?;
    assert_eq!(rec.live(), 0);
    Ok(())
}

// AC19.
#[tokio::test]
async fn an_unknown_digest_gives_1120() -> TestResult {
    let rec = Arc::new(Rec::default());
    let config = desktop(&rec);
    let (_identity, pending) = created(config.clone()).await?;
    let mut unknown = pending.clone();
    unknown.event_digest[0] ^= 0x01;
    let error = Identity::abandon_pending(&config, &unknown)
        .await
        .err()
        .ok_or("abandon succeeded")?;
    assert_eq!(
        error,
        IdentityError::NoPendingSignature {
            event_digest: unknown.event_digest
        }
    );
    assert_eq!(rec.count("destroy") + rec.count("destroy_key"), 0);
    assert_eq!(rec.live(), 3);
    let mut other = pending;
    other.identifier = Identifier::from_bytes([5; 32]);
    assert!(matches!(
        Identity::abandon_pending(&config, &other).await,
        Err(IdentityError::NoPendingSignature { .. })
    ));
    Ok(())
}

// AC20: a caller that drops `create` while the next-set member is being
// generated leaves no key and no record.
#[tokio::test]
async fn dropping_create_during_generate_destroys_every_key() -> TestResult {
    let rec = Arc::new(Rec::default());
    rec.hold_generate.store(true, Ordering::SeqCst);
    let config = desktop(&rec);
    let store = config.persistence.clone();
    let mut create = Box::pin(Identity::create(config, one_root()));
    tokio::select! {
        biased;
        () = rec.generated.notified() => {}
        _ = &mut create => return Err("create finished before generate returned".into()),
    }
    drop(create);
    rec.release.notify_one();
    eventually("the composition to be abandoned", || {
        rec.count("destroy_key") == 2 && rec.live() == 0
    })
    .await?;
    records_reach(&store, 0).await?;
    assert_eq!(rec.count("destroy"), 1);
    Ok(())
}

// AC20 (call A): a result the task sent but nobody took is abandoned too.
#[tokio::test]
async fn dropping_create_after_the_send_destroys_every_key() -> TestResult {
    let rec = Arc::new(Rec::default());
    rec.hold_generate.store(true, Ordering::SeqCst);
    let config = desktop(&rec);
    let store = config.persistence.clone();
    let mut create = Box::pin(Identity::create(config, one_root()));
    tokio::select! {
        biased;
        () = rec.generated.notified() => {}
        _ = &mut create => return Err("create finished before generate returned".into()),
    }
    rec.release.notify_one();
    // The in-memory store never yields, so once the device record alone
    // remains the task has run past its last await and sent its result into
    // the join handle.
    device_record_alone(&store).await?;
    assert_eq!(rec.live(), 3);
    drop(create);
    eventually("the composition to be abandoned", || rec.live() == 0).await?;
    records_reach(&store, 0).await?;
    assert_eq!(rec.count("destroy"), 1);
    assert_eq!(rec.count("destroy_key"), 2);
    Ok(())
}

// AC19: a `PendingSignatureRecord`, or a `KeptComposition` past the
// inception, is removed from the record and destroys no key.
#[tokio::test]
async fn abandoning_a_signed_or_later_event_rewrites_the_record() -> TestResult {
    let rec = Arc::new(Rec::default());
    let config = desktop(&rec);
    let (identity, inception) = created(config.clone()).await?;
    let id = *identity.identifier();
    let signed = EventRef {
        identifier: id,
        sequence: 1,
        event_digest: [0x51; 32],
    };
    let later = EventRef {
        identifier: id,
        sequence: 2,
        event_digest: [0x52; 32],
    };
    let mut record = read_device_record(&config.persistence, &id)
        .await?
        .ok_or("no device record")?;
    record.pending.push(signed);
    record.kept.push(later);
    write_device_record(&config.persistence, &id, &record).await?;

    for target in [signed, later] {
        let event = PendingEvent {
            identifier: id,
            preimage: vec![],
            event_digest: target.event_digest,
            chain: vec![],
        };
        Identity::abandon_pending(&config, &event).await?;
    }
    let left = read_device_record(&config.persistence, &id)
        .await?
        .ok_or("the record is gone")?;
    assert!(left.pending.is_empty());
    assert_eq!(left.kept.len(), 1);
    assert_eq!(left.kept[0].event_digest, inception.event_digest);
    assert_eq!(rec.count("destroy") + rec.count("destroy_key"), 0);
    assert_eq!(rec.live(), 3);
    Ok(())
}

// AC19: a device that signed its own inception holds a
// `PendingSignatureRecord` for it; abandoning the inception then removes
// both entries and destroys no key, because the released signature can
// complete the event (`17-persistence-and-storage.md` §17.3).
#[tokio::test]
async fn abandoning_a_signed_inception_destroys_no_key() -> TestResult {
    let rec = Arc::new(Rec::default());
    let config = desktop(&rec);
    let (identity, inception) = created(config.clone()).await?;
    let id = *identity.identifier();
    let mut record = read_device_record(&config.persistence, &id)
        .await?
        .ok_or("no device record")?;
    record.pending.push(EventRef {
        identifier: id,
        sequence: 0,
        event_digest: inception.event_digest,
    });
    write_device_record(&config.persistence, &id, &record).await?;

    Identity::abandon_pending(&config, &inception).await?;
    assert_eq!(rec.count("destroy") + rec.count("destroy_key"), 0);
    assert_eq!(rec.live(), 3);
    let left = read_device_record(&config.persistence, &id)
        .await?
        .ok_or("the record naming the keys is gone")?;
    assert!(left.kept.is_empty() && left.pending.is_empty());
    assert_eq!(left.next, record.next);
    assert_eq!(left.root, record.root);
    assert_eq!(left.active, record.active);
    assert!(matches!(
        Identity::abandon_pending(&config, &inception).await,
        Err(IdentityError::NoPendingSignature { .. })
    ));
    assert_eq!(rec.live(), 3);
    Ok(())
}

// The offer check runs before the plan check: Headless with `ThisSdk`
// gives 1100, not the plan's refusal.
#[tokio::test]
async fn the_offer_check_runs_before_the_plan_check() -> TestResult {
    let rec = Arc::new(Rec::default());
    let config = config_over(
        &rec,
        PreRotationCustodyKind::PlatformCloudKeyStore,
        CustodyProfile::Headless,
        store(),
    );
    let error = Identity::create(config, SignerPlan::ThisSdk)
        .await
        .err()
        .ok_or("create succeeded")?;
    assert_eq!(error.error, IdentityError::NoIndependentSubstrate);
    assert_eq!(error.cleanup, None);
    assert_eq!(rec.generate_calls(), 0);
    Ok(())
}

/// A store that yields on every call, so tasks interleave between a read and
/// a write, and fails the put whose ordinal `fail_put` names, once.
#[derive(Clone)]
struct FaultStore {
    inner: Arc<InMemoryStorage>,
    puts: Arc<AtomicUsize>,
    fail_put: Arc<AtomicUsize>,
}

impl Storage for FaultStore {
    async fn store(&self, key: &str, data: &[u8]) -> Result<(), PlatformError> {
        let put = self.puts.fetch_add(1, Ordering::SeqCst) + 1;
        tokio::task::yield_now().await;
        if put == self.fail_put.load(Ordering::SeqCst) {
            return Err(PlatformError::StorageError("injected".to_owned()));
        }
        self.inner.store(key, data).await
    }

    async fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, PlatformError> {
        tokio::task::yield_now().await;
        self.inner.retrieve(key).await
    }

    async fn delete(&self, key: &str) -> Result<(), PlatformError> {
        tokio::task::yield_now().await;
        self.inner.delete(key).await
    }

    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, PlatformError> {
        self.inner.list_keys(prefix).await
    }

    async fn delete_prefix(&self, prefix: &str) -> Result<u64, PlatformError> {
        self.inner.delete_prefix(prefix).await
    }

    async fn exists(&self, key: &str) -> Result<bool, PlatformError> {
        self.inner.exists(key).await
    }
}

type FaultStored = Arc<EncryptingAdapter<FaultStore>>;

fn fault_store() -> (FaultStore, FaultStored) {
    let faults = FaultStore {
        inner: Arc::new(InMemoryStorage::new()),
        puts: Arc::new(AtomicUsize::new(0)),
        fail_put: Arc::new(AtomicUsize::new(0)),
    };
    let store = Arc::new(EncryptingAdapter::new(
        faults.clone(),
        Zeroizing::new([3; 32]),
    ));
    (faults, store)
}

fn desktop_over<S: scp_platform::EncryptedStorage + Clone>(
    rec: &Arc<Rec>,
    persistence: S,
) -> IdentityConfig<S> {
    config_over(
        rec,
        PreRotationCustodyKind::PlatformCloudKeyStore,
        CustodyProfile::Desktop,
        persistence,
    )
}

// AC21: the creation record exists before the first key, and `unfinished`
// lists it while the composition runs.
#[tokio::test]
async fn the_creation_record_precedes_the_first_key() -> TestResult {
    let rec = Arc::new(Rec::default());
    rec.hold_generate.store(true, Ordering::SeqCst);
    let config = desktop(&rec);
    let store = config.persistence.clone();
    let task = tokio::spawn(Identity::create(config.clone(), one_root()));
    rec.generated.notified().await;
    let listed = Identity::unfinished(&config).await?;
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert!(matches!(listed[0], Unfinished::Creation(_)), "{listed:?}");
    assert_eq!(records(&store).await?.len(), 1);
    rec.release.notify_one();
    let Created { identity, .. } = task.await??;
    // The device record supersedes the creation record.
    assert_eq!(records(&store).await?.len(), 1);
    assert_eq!(
        Identity::unfinished(&config).await?,
        [Unfinished::Composition(KeptComposition {
            identifier: *identity.identifier(),
            sequence: 0,
            event_digest: read_device_record(&store, identity.identifier())
                .await?
                .ok_or("no device record")?
                .kept[0]
                .event_digest,
        })]
    );
    Ok(())
}

// AC21: a put that fails at any step leaves no key and no record.
#[tokio::test]
async fn a_failed_put_at_each_step_leaves_no_key_and_no_record() -> TestResult {
    // A clean create puts the empty creation record, one rewrite per key,
    // and the device record.
    let rec = Arc::new(Rec::default());
    let (faults, store) = fault_store();
    created(desktop_over(&rec, store)).await?;
    assert_eq!(faults.puts.load(Ordering::SeqCst), 5);

    for put in 1..=5 {
        let rec = Arc::new(Rec::default());
        let (faults, store) = fault_store();
        faults.fail_put.store(put, Ordering::SeqCst);
        let error = Identity::create(desktop_over(&rec, store.clone()), one_root())
            .await
            .err()
            .ok_or("create succeeded")?;
        assert_eq!(error.error, IdentityError::PersistFailed, "put {put}");
        assert_eq!(error.cleanup, None, "put {put}");
        assert_eq!(rec.live(), 0, "put {put}");
        assert!(records(&store).await?.is_empty(), "put {put}");
    }
    Ok(())
}

// AC21: `abandon_unfinished` on a creation still running makes it clean up
// after itself.
#[tokio::test]
async fn abandoning_a_running_creation_stops_it() -> TestResult {
    let rec = Arc::new(Rec::default());
    rec.hold_generate.store(true, Ordering::SeqCst);
    let config = desktop(&rec);
    let store = config.persistence.clone();
    let task = tokio::spawn(Identity::create(config.clone(), one_root()));
    rec.generated.notified().await;
    let listed = Identity::unfinished(&config).await?;
    let [creation] = listed.as_slice() else {
        return Err(format!("{listed:?}").into());
    };
    Identity::abandon_unfinished(&config, creation).await?;
    rec.release.notify_one();
    let error = task.await?.err().ok_or("create succeeded")?;
    assert_eq!(error.error, IdentityError::PersistFailed);
    assert_eq!(error.cleanup, None);
    assert_eq!(rec.live(), 0);
    assert!(records(&store).await?.is_empty());
    let again = Identity::abandon_unfinished(&config, creation)
        .await
        .err()
        .ok_or("a second abandon succeeded")?;
    assert_eq!(again, IdentityError::NoUnfinishedCreation);
    assert_eq!(again.code(), "SCP-IDENT-1122");
    Ok(())
}

// AC21: a cleanup that fails to destroy keys reports every one, the creation
// record names them, and `abandon_unfinished` destroys them.
#[tokio::test]
async fn a_failed_cleanup_is_listed_and_abandoned() -> TestResult {
    let rec = Arc::new(Rec::default());
    rec.fail_active_generate.store(true, Ordering::SeqCst);
    rec.fail_next_destroy.store(true, Ordering::SeqCst);
    rec.fail_key_destroy.store(true, Ordering::SeqCst);
    let config = desktop(&rec);
    let error = Identity::create(config.clone(), one_root())
        .await
        .err()
        .ok_or("create succeeded")?;
    assert_eq!(error.error, IdentityError::CustodySigningFailed);
    let Some(CleanupFailure::Incomplete {
        creation,
        undestroyed,
    }) = error.cleanup.map(|cleanup| *cleanup)
    else {
        return Err("the cleanup reported no incomplete cleanup".into());
    };
    let next = *lock(&rec.next).first().ok_or("no next-set member")?;
    let root = *lock(&rec.keys).first().ok_or("no #0")?;
    assert_eq!(
        undestroyed,
        [
            UndestroyedKey::NextSetMember(next),
            UndestroyedKey::Key(root)
        ]
    );
    let creation = Unfinished::Creation(creation);
    assert_eq!(Identity::unfinished(&config).await?, [creation]);

    rec.fail_next_destroy.store(false, Ordering::SeqCst);
    let partial = Identity::abandon_unfinished(&config, &creation)
        .await
        .err()
        .ok_or("abandon succeeded")?;
    assert_eq!(partial, IdentityError::CustodySigningFailed);
    assert_eq!(rec.live_next(), 0, "every handle is attempted");
    assert_eq!(Identity::unfinished(&config).await?, [creation]);

    rec.fail_key_destroy.store(false, Ordering::SeqCst);
    Identity::abandon_unfinished(&config, &creation).await?;
    assert_eq!(rec.live(), 0);
    assert!(records(&config.persistence).await?.is_empty());
    assert!(Identity::unfinished(&config).await?.is_empty());
    Ok(())
}

/// Polls `F` with `handle` entered, so every task `F` spawns lands on that
/// runtime while the test's own runtime drives `F`.
struct SpawnOn<F> {
    handle: tokio::runtime::Handle,
    future: std::pin::Pin<Box<F>>,
}

impl<F: Future> Future for SpawnOn<F> {
    type Output = F::Output;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<F::Output> {
        let _entered = self.handle.clone().enter();
        self.future.as_mut().poll(cx)
    }
}

// AC21: a runtime that shuts down mid-create cancels the task before any
// cleanup runs. `create` then reports every minted key as possibly live,
// never an empty list, and `unfinished` lists the creation that names them.
#[tokio::test]
async fn a_cancelled_create_reports_every_minted_key() -> TestResult {
    let rec = Arc::new(Rec::default());
    rec.hold_active_generate.store(true, Ordering::SeqCst);
    let config = desktop(&rec);
    // `create` spawns its composition onto `doomed`, which shuts down while
    // `#active`'s generation is held, so the composition is cancelled.
    let doomed = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()?;
    let mut create = SpawnOn {
        handle: doomed.handle().clone(),
        future: Box::pin(Identity::create(config.clone(), one_root())),
    };
    tokio::select! {
        biased;
        () = rec.active_held.notified() => {}
        _ = &mut create => return Err("create finished before #active".into()),
    }
    doomed.shutdown_background();

    let error = create.await.err().ok_or("create succeeded")?;
    assert_eq!(error.error, IdentityError::PersistFailed);
    let Some(CleanupFailure::NotAttempted {
        creation,
        composition,
        minted,
    }) = error.cleanup.map(|cleanup| *cleanup)
    else {
        return Err("the cancelled create did not report NotAttempted".into());
    };
    let next = *lock(&rec.next).first().ok_or("no next-set member")?;
    let root = *lock(&rec.keys).first().ok_or("no #0")?;
    assert_eq!(composition, None);
    assert_eq!(
        minted,
        [
            UndestroyedKey::NextSetMember(next),
            UndestroyedKey::Key(root)
        ]
    );
    assert_eq!(rec.live(), 2);
    let listed = Unfinished::Creation(creation);
    assert_eq!(Identity::unfinished(&config).await?, [listed]);
    Identity::abandon_unfinished(&config, &listed).await?;
    assert_eq!(rec.live(), 0);
    assert!(records(&config.persistence).await?.is_empty());
    Ok(())
}

// AC21: a composition whose abandon failed is listed, and
// `abandon_unfinished` finishes it.
#[tokio::test]
async fn a_kept_composition_is_listed_and_abandoned() -> TestResult {
    let rec = Arc::new(Rec::default());
    let config = desktop(&rec);
    let (identity, pending) = created(config.clone()).await?;
    rec.fail_key_destroy.store(true, Ordering::SeqCst);
    assert!(Identity::abandon_pending(&config, &pending).await.is_err());
    let kept = Unfinished::Composition(KeptComposition {
        identifier: *identity.identifier(),
        sequence: 0,
        event_digest: pending.event_digest,
    });
    assert_eq!(Identity::unfinished(&config).await?, [kept]);
    rec.fail_key_destroy.store(false, Ordering::SeqCst);
    Identity::abandon_unfinished(&config, &kept).await?;
    assert_eq!(rec.live(), 0);
    assert!(records(&config.persistence).await?.is_empty());
    Ok(())
}

// A panic in the composition destroys every minted key, then resumes.
#[tokio::test]
async fn a_panic_in_the_composition_destroys_every_key() -> TestResult {
    let rec = Arc::new(Rec::default());
    rec.panic_active_generate.store(true, Ordering::SeqCst);
    let config = desktop(&rec);
    let store = config.persistence.clone();
    let join = tokio::spawn(Identity::create(config, one_root()))
        .await
        .err()
        .ok_or("create returned")?;
    assert!(join.is_panic());
    assert_eq!(rec.count("destroy"), 1);
    assert_eq!(rec.count("destroy_key"), 1);
    assert_eq!(rec.live(), 0);
    assert!(records(&store).await?.is_empty());
    Ok(())
}

// A FIDO2 next-set custody's commitment entry declares `Fido2Token`.
#[tokio::test]
async fn a_fido2_commitment_declares_fido2_token() -> TestResult {
    let rec = Arc::new(Rec::default());
    let config = config_over(
        &rec,
        PreRotationCustodyKind::HardwareSecurityKey,
        CustodyProfile::Desktop,
        store(),
    );
    let (identity, pending) = created(config).await?;
    let standing = &identity.scp_identity().pre_rotation_commitment;
    assert_eq!(
        standing.commitments[0].custody_type,
        CustodyType::Fido2Token
    );
    let fields = pending
        .preimage
        .strip_prefix(SEPARATOR)
        .ok_or("no separator")?;
    assert_eq!(
        decode_preimage(fields)?.preimage().continuation,
        Some(Continuation::FixesCommitment(standing.clone()))
    );
    Ok(())
}

// Each key entry declares its own key's custody type.
#[tokio::test]
async fn each_key_entry_declares_its_own_custody_type() -> TestResult {
    let rec = Arc::new(Rec::default());
    rec.hardware_root.store(true, Ordering::SeqCst);
    let (_identity, pending) = created(desktop(&rec)).await?;
    let fields = pending
        .preimage
        .strip_prefix(SEPARATOR)
        .ok_or("no separator")?;
    let decoded = decode_preimage(fields)?;
    let state = decoded
        .preimage()
        .key_state
        .as_ref()
        .ok_or("no key state")?;
    assert_eq!(
        state.keys[0].custody_type,
        PlatformCustodyType::Hardware.key_entry_custody_type()
    );
    assert_eq!(state.keys[1].custody_type, CustodyType::Software);
    Ok(())
}

// AC19: a next-set destroy that fails still lets every other key go, and a
// retry counts the keys already destroyed as destroyed.
#[tokio::test]
async fn a_partial_destroy_failure_then_a_retry_destroys_every_key() -> TestResult {
    let rec = Arc::new(Rec::default());
    let config = desktop(&rec);
    let (identity, pending) = created(config.clone()).await?;
    rec.fail_next_destroy.store(true, Ordering::SeqCst);
    let error = Identity::abandon_pending(&config, &pending)
        .await
        .err()
        .ok_or("abandon succeeded")?;
    assert_eq!(error, IdentityError::CustodySigningFailed);
    assert_eq!(rec.live_keys(), 0, "#0 and #active are destroyed");
    assert_eq!(rec.live_next(), 1);
    assert!(
        read_device_record(&config.persistence, identity.identifier())
            .await?
            .is_some()
    );
    rec.fail_next_destroy.store(false, Ordering::SeqCst);
    Identity::abandon_pending(&config, &pending).await?;
    assert_eq!(rec.live(), 0);
    assert!(records(&config.persistence).await?.is_empty());
    Ok(())
}

// A key its custody no longer holds counts as destroyed.
#[tokio::test]
async fn a_key_destroyed_beforehand_counts_as_destroyed() -> TestResult {
    let rec = Arc::new(Rec::default());
    let config = desktop(&rec);
    let (identity, pending) = created(config.clone()).await?;
    config
        .custody
        .destroy_key(&identity.scp_identity().identity_key)
        .await?;
    let next = *lock(&rec.next).first().ok_or("no next-set member")?;
    config.next_set_custody.destroy(&next).await?;
    Identity::abandon_pending(&config, &pending).await?;
    assert_eq!(rec.live(), 0);
    assert!(records(&config.persistence).await?.is_empty());
    Ok(())
}

/// The state two `TwinNextSet` custodies share: every handle either issues
/// is an alias of one key, so two creates over seeded key custodies derive
/// one identifier.
#[derive(Default)]
struct Twins {
    inner: InMemoryNextSetCustody,
    source: tokio::sync::Mutex<Option<NextSetKeyHandle>>,
    aliases: Mutex<Vec<u64>>,
    next_alias: AtomicU64,
}

struct TwinNextSet(Arc<Twins>);

impl TwinNextSet {
    async fn source(&self, handle: &NextSetKeyHandle) -> Option<NextSetKeyHandle> {
        if !lock(&self.0.aliases).contains(&handle.id()) {
            return None;
        }
        *self.0.source.lock().await
    }
}

impl KeyEventSigner for TwinNextSet {
    type Member = NextSetKeyHandle;

    async fn sign_change(
        &self,
        member: &NextSetKeyHandle,
        change: &SigningChange,
    ) -> Result<IndexedSignature, KeyEventSignError> {
        let source = self
            .source(member)
            .await
            .ok_or(KeyEventSignError::MemberNotFound)?;
        self.0.inner.sign_change(&source, change).await
    }

    async fn sign_probe(
        &self,
        member: &NextSetKeyHandle,
        probe: &CustodyProbe,
    ) -> Result<ProbeSignature, KeyEventSignError> {
        let source = self
            .source(member)
            .await
            .ok_or(KeyEventSignError::MemberNotFound)?;
        self.0.inner.sign_probe(&source, probe).await
    }
}

impl NextSetCustody for TwinNextSet {
    async fn generate(&self) -> Result<NextSetKeyHandle, NextSetCustodyError> {
        let mut source = self.0.source.lock().await;
        if source.is_none() {
            *source = Some(self.0.inner.generate().await?);
        }
        drop(source);
        let alias = 1000 + self.0.next_alias.fetch_add(1, Ordering::SeqCst);
        lock(&self.0.aliases).push(alias);
        Ok(NextSetKeyHandle::new(alias))
    }

    async fn reveal_public_key(
        &self,
        handle: &NextSetKeyHandle,
    ) -> Result<[u8; 33], NextSetCustodyError> {
        let source = self
            .source(handle)
            .await
            .ok_or(NextSetCustodyError::HandleNotFound)?;
        self.0.inner.reveal_public_key(&source).await
    }

    async fn destroy(&self, handle: &NextSetKeyHandle) -> Result<(), NextSetCustodyError> {
        let mut aliases = lock(&self.0.aliases);
        let index = aliases
            .iter()
            .position(|alias| *alias == handle.id())
            .ok_or(NextSetCustodyError::HandleNotFound)?;
        aliases.remove(index);
        drop(aliases);
        Ok(())
    }

    async fn seal_backup(
        &self,
        _handle: &NextSetKeyHandle,
        _request: BackupRequest,
    ) -> Result<BackupArtifact, NextSetCustodyError> {
        Err(NextSetCustodyError::Unavailable("twin".to_owned()))
    }

    async fn restore(
        &self,
        _material: RestoreMaterial,
        _expected_commitment: [u8; 32],
    ) -> Result<NextSetKeyHandle, NextSetCustodyError> {
        Err(NextSetCustodyError::Unavailable("twin".to_owned()))
    }

    fn custody_kind(&self) -> PreRotationCustodyKind {
        PreRotationCustodyKind::PlatformCloudKeyStore
    }
}

fn twin_config(
    rec: &Arc<Rec>,
    twins: &Arc<Twins>,
    persistence: Store,
    record_lock: RecordLock,
) -> IdentityConfig<Store> {
    IdentityConfig {
        custody: KeyCustodySlot::custom(RecordingKeyCustody {
            inner: InMemoryKeyCustody::from_seed_bytes([8; 32]),
            rec: Arc::clone(rec),
        }),
        next_set_custody: NextSetCustodySlot::custom(TwinNextSet(Arc::clone(twins))),
        persistence,
        profile: CustodyProfile::Desktop,
        witnesses: WitnessChoice::NoWitness,
        record_lock,
    }
}

// A create that derives an identifier a device record already names never
// overwrites that record, and destroys its own keys.
#[tokio::test]
async fn create_never_overwrites_an_existing_device_record() -> TestResult {
    let twins = Arc::new(Twins::default());
    let store = store();
    let record_lock = RecordLock::new();
    let first = Arc::new(Rec::default());
    let (identity, _) = created(twin_config(
        &first,
        &twins,
        store.clone(),
        record_lock.clone(),
    ))
    .await?;
    let before = read_device_record(&store, identity.identifier()).await?;

    let second = Arc::new(Rec::default());
    let error = Identity::create(
        twin_config(&second, &twins, store.clone(), record_lock),
        one_root(),
    )
    .await
    .err()
    .ok_or("the second create succeeded")?;
    assert_eq!(error.error, IdentityError::PersistFailed);
    assert_eq!(error.cleanup, None);
    assert_eq!(
        read_device_record(&store, identity.identifier()).await?,
        before
    );
    assert_eq!(second.live_keys(), 0);
    assert_eq!(first.live_keys(), 2);
    assert_eq!(records(&store).await?.len(), 1);
    Ok(())
}

// Two abandons of one identity's events in one process lose no update.
#[tokio::test]
async fn concurrent_abandons_lose_no_update() -> TestResult {
    let rec = Arc::new(Rec::default());
    let (_faults, store) = fault_store();
    let config = desktop_over(&rec, store);
    let (identity, inception) = created(config.clone()).await?;
    let id = *identity.identifier();
    let mut record = read_device_record(&config.persistence, &id)
        .await?
        .ok_or("no device record")?;
    let events: Vec<PendingEvent> = [0x61, 0x62]
        .into_iter()
        .zip(1..)
        .map(|(byte, sequence)| {
            record.kept.push(EventRef {
                identifier: id,
                sequence,
                event_digest: [byte; 32],
            });
            PendingEvent {
                identifier: id,
                preimage: vec![],
                event_digest: [byte; 32],
                chain: vec![],
            }
        })
        .collect();
    write_device_record(&config.persistence, &id, &record).await?;
    let (a, b) = tokio::join!(
        Identity::abandon_pending(&config, &events[0]),
        Identity::abandon_pending(&config, &events[1]),
    );
    a?;
    b?;
    let left = read_device_record(&config.persistence, &id)
        .await?
        .ok_or("the record is gone")?;
    assert_eq!(left.kept.len(), 1, "{:?}", left.kept);
    assert_eq!(left.kept[0].event_digest, inception.event_digest);
    Ok(())
}

// Abandoning the inception while another entry remains removes only the
// inception's entries and destroys no key.
#[tokio::test]
async fn abandoning_the_inception_beside_another_entry_keeps_that_entry() -> TestResult {
    let rec = Arc::new(Rec::default());
    let config = desktop(&rec);
    let (identity, inception) = created(config.clone()).await?;
    let id = *identity.identifier();
    let other = EventRef {
        identifier: id,
        sequence: 1,
        event_digest: [0x71; 32],
    };
    let mut record = read_device_record(&config.persistence, &id)
        .await?
        .ok_or("no device record")?;
    record.pending.push(other);
    let signed_inception = record.kept[0];
    record.pending.push(signed_inception);
    write_device_record(&config.persistence, &id, &record).await?;
    Identity::abandon_pending(&config, &inception).await?;
    let left = read_device_record(&config.persistence, &id)
        .await?
        .ok_or("the record is gone")?;
    assert!(left.kept.is_empty());
    assert_eq!(left.pending, [other]);
    assert_eq!(rec.count("destroy") + rec.count("destroy_key"), 0);
    assert_eq!(rec.live(), 3);
    Ok(())
}

fn operator(byte: u8) -> Identifier {
    Identifier::from_bytes([byte; 32])
}

fn listed(byte: u8) -> ListedOperator {
    ListedOperator {
        operator: operator(byte),
        key: [byte; 33],
    }
}

// AC22: the inception carries the chosen witness set, and `create` reports
// the warning the choice earns.
#[tokio::test]
async fn the_inception_carries_the_witness_set() -> TestResult {
    let cases = [
        (
            WitnessChoice::CommunityDefault {
                listed: vec![listed(1), listed(2)],
            },
            vec![operator(1), operator(2)],
            None,
        ),
        (
            WitnessChoice::Designated {
                witnesses: vec![
                    WitnessDesignation {
                        operator: operator(1),
                        key: [1; 33],
                    },
                    WitnessDesignation {
                        operator: operator(3),
                        key: [3; 33],
                    },
                ],
                listed: vec![listed(1)],
            },
            vec![operator(1), operator(3)],
            Some(WitnessWarning::UnlistedOperators(vec![operator(3)])),
        ),
        (
            WitnessChoice::NoWitness,
            vec![],
            Some(WitnessWarning::NoWitness),
        ),
    ];
    for (choice, set, warning) in cases {
        let rec = Arc::new(Rec::default());
        let mut config = desktop(&rec);
        config.witnesses = choice;
        let Created {
            outcome,
            witness_warning,
            ..
        } = Identity::create(config, one_root()).await?;
        assert_eq!(witness_warning, warning);
        let pending = pending_of(outcome);
        let fields = pending
            .preimage
            .strip_prefix(SEPARATOR)
            .ok_or("no separator")?;
        let decoded = decode_preimage(fields)?;
        let state = decoded
            .preimage()
            .key_state
            .as_ref()
            .ok_or("no key state")?;
        assert_eq!(state.witnesses, set);
    }
    Ok(())
}

// AC22: a designated set that repeats an operator is refused before any key.
#[tokio::test]
async fn a_repeated_designated_witness_is_refused_before_any_key() -> TestResult {
    let rec = Arc::new(Rec::default());
    let mut config = desktop(&rec);
    let twice = WitnessDesignation {
        operator: operator(1),
        key: [1; 33],
    };
    config.witnesses = WitnessChoice::Designated {
        witnesses: vec![twice, twice],
        listed: vec![listed(1)],
    };
    let error = Identity::create(config, one_root())
        .await
        .err()
        .ok_or("create succeeded")?;
    assert_eq!(
        error.error,
        IdentityError::IllegalKeyEvent {
            stage: CheckStep::Content
        }
    );
    assert_eq!(rec.generate_calls(), 0);
    Ok(())
}
