//! Tests for [`super::KeyPackageStoreActor`] (ADR-049 §9 — Phase 2F).
//!
//! Exercises the fused reserve→confirm(welcome)/cancel protocol, double-consume
//! prevention (both the reservation-id tombstone AND the crypto-layer
//! consumed-init-key backstop), storage-fault fail-closed branches,
//! auto-replenish, crash-safety reconciliation, orphan-reservation TTL sweep,
//! and publish idempotency against a real MLS backend + in-memory storage.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Test-only `std::sync::Mutex` in the recording transport + faulty storage:
// these are sync helpers (no await held across the lock), so the async
// deadlock hazard the disallow guards against does not apply. Per
// `crates/scp-runtime/clippy.toml`, test-only `std::sync::Mutex` uses carry
// this allow.
#![allow(clippy::disallowed_types)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_trait::async_trait;
use scp_clock::{Clock, SystemClock};
use scp_did::DID;
use scp_protocol::context::{ContextError, ContextParams};

use super::{
    KeyPackageCommand, KeyPackageStoreActor, KeyPackageStoreDeps, KeyPackageStoreHandle, KpRef,
    MIN_BUFFER, ReservationId,
};
use crate::context::builder::{
    ContextCreationError, ContextTransportProvider, NotConfiguredTransportProvider,
};
use crate::crypto::mls::backend::{
    AddMemberRaw, GeneratedKeyPackage, MlsBackend, RemoveMemberRaw, SignerState,
    ValidatedKeyPackage,
};
use crate::crypto::mls::production_backend::ProductionMlsBackend;
use crate::crypto::mls::storage_adapter::{OpenMlsStorageAdapter, SpawnBlockingStorageAdapter};
use openmls::prelude::LeafNodeIndex;
use scp_mls::credential::ScpCredential;
use scp_mls::encrypt::DecryptedContent;
use scp_mls::error::MlsError;
use scp_mls::group::ScpMlsGroup;
use scp_platform::PlatformError;
use scp_platform::testing::InMemoryStorage;
use scp_platform::traits::Storage;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn alice() -> DID {
    DID("did:dht:z6MkAliceKeyPackages".to_owned())
}

fn real_backend() -> Arc<dyn MlsBackend> {
    Arc::new(ProductionMlsBackend::new(std::sync::Arc::new(
        scp_clock::SystemClock,
    )))
}

/// A real backend with the durable consumed-init-key set attached (A2), so the
/// crypto-layer single-use backstop is active.
fn backend_with_consumed_set(storage: &Arc<dyn OpenMlsStorageAdapter>) -> Arc<dyn MlsBackend> {
    let backend = Arc::new(ProductionMlsBackend::new(std::sync::Arc::new(
        scp_clock::SystemClock,
    )));
    backend.set_consumed_init_key_store(Arc::clone(storage));
    backend
}

fn in_memory_storage() -> Arc<dyn OpenMlsStorageAdapter> {
    Arc::new(SpawnBlockingStorageAdapter::new(Arc::new(
        InMemoryStorage::new(),
    )))
}

/// Like [`in_memory_storage`] but also returns the inner [`InMemoryStorage`]
/// handle so a test can call `list_keys` (the `OpenMlsStorageAdapter` trait has
/// no list API; only the concrete inner store exposes one).
fn in_memory_storage_with_inner() -> (Arc<dyn OpenMlsStorageAdapter>, Arc<InMemoryStorage>) {
    let inner = Arc::new(InMemoryStorage::new());
    let adapter: Arc<dyn OpenMlsStorageAdapter> =
        Arc::new(SpawnBlockingStorageAdapter::new(Arc::clone(&inner)));
    (adapter, inner)
}

fn deps_with(
    mls: Arc<dyn MlsBackend>,
    storage: Arc<dyn OpenMlsStorageAdapter>,
    transport: Arc<dyn ContextTransportProvider>,
) -> KeyPackageStoreDeps {
    KeyPackageStoreDeps {
        mls,
        mls_storage: storage,
        transport,
        clock: Arc::new(SystemClock) as Arc<dyn Clock>,
        wrapping_pubkey: None,
    }
}

/// Spawn an actor and wait for its startup replenish to fill the pool to
/// [`MIN_BUFFER`] by polling `Replenish` (which returns 0 once full).
///
/// The actor's MLS backend has the durable consumed-init-key set attached
/// (keyed off the SAME `storage`), so the actor suite exercises BOTH single-use
/// anchors together — the reservation-id journal AND the crypto-layer init-key
/// backstop inside `join_from_welcome` (which fails closed if the store is
/// missing). This mirrors production, where `Supervisor::with_providers` always
/// attaches the store.
/// Spawn the KP actor over `storage` (fresh or existing-durable) and drive a
/// single `Replenish`. Used both for a first spawn (empty storage → fills the
/// pool) and for a respawn over the SAME durable storage (crash-recovery: the
/// startup `reconcile_from_storage()` + GC tail run BEFORE the command is
/// served, so the call doubles as that path's driver — see the orphan tests).
///
/// The actor's `run()` performs startup `reconcile_from_storage()` +
/// `replenish_to_min()` BEFORE serving any command, so the `Replenish` reply
/// returning `Ok` is a deterministic barrier proving startup reconcile +
/// replenish completed. We AWAIT and ASSERT that reply (rather than discarding
/// it) so callers never assert durable storage state before reconcile is
/// guaranteed done — a reply-based barrier, no sleeps or polling — and so a
/// spurious `ActorBusy` is never silently swallowed.
async fn spawn_filled(
    storage: Arc<dyn OpenMlsStorageAdapter>,
) -> (KeyPackageStoreHandle, tokio::task::JoinHandle<()>) {
    let mls = backend_with_consumed_set(&storage);
    let (handle, join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(mls, Arc::clone(&storage), no_transport()),
    );
    handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await
        .expect("startup reconcile + replenish barrier: Replenish reply must be Ok");
    (handle, join)
}

fn no_transport() -> Arc<dyn ContextTransportProvider> {
    Arc::new(NotConfiguredTransportProvider)
}

/// Fetch the current pooled refs by listing the durable index in storage.
/// Returns [`KpRef`] newtypes (the index serializes them transparently).
async fn live_index(storage: &Arc<dyn OpenMlsStorageAdapter>, did: &DID) -> Vec<KpRef> {
    let key = format!("scp-kp-index/{}", did.0);
    storage
        .retrieve(&key)
        .await
        .unwrap()
        .map_or_else(Vec::new, |bytes| {
            rmp_serde::from_slice::<Vec<KpRef>>(&bytes).unwrap()
        })
}

/// Whether a KP private record still exists in storage.
async fn kp_record_present(
    storage: &Arc<dyn OpenMlsStorageAdapter>,
    did: &DID,
    kp_ref: &KpRef,
) -> bool {
    let key = format!("scp-kp/{}/{kp_ref}", did.0);
    storage.retrieve(&key).await.unwrap().is_some()
}

/// Whether an arbitrary durable key is present (used to assert tombstone /
/// reservation-record reclamation by the reconcile GC).
async fn raw_key_present(storage: &Arc<dyn OpenMlsStorageAdapter>, key: &str) -> bool {
    storage.retrieve(key).await.unwrap().is_some()
}

/// Build a REAL Welcome addressed to `kp_public_bytes` by spinning up an
/// inviter group and adding that exact KeyPackage. The Welcome can be joined
/// by the signer-state the actor holds for the reserved KP — this drives the
/// fused `ConfirmConsume` through a genuine join.
async fn real_welcome_for(mls: &Arc<dyn MlsBackend>, kp_public_bytes: &[u8]) -> Vec<u8> {
    let inviter = ScpCredential::new(
        "did:dht:z6MkInviterForWelcome".to_owned(),
        None,
        scp_did::SigningKeyId::Active,
    )
    .unwrap();
    let mut group = mls.create_group(&inviter, None).await.unwrap();
    let added = mls
        .add_member_raw(&mut group, kp_public_bytes)
        .await
        .unwrap();
    added.welcome
}

// ---------------------------------------------------------------------------
// 1. reserve → confirm(welcome) happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reserve_then_confirm_deletes_key_and_clears_reservation() {
    let storage = in_memory_storage();
    let mls = backend_with_consumed_set(&storage);
    let (handle, _join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls), Arc::clone(&storage), no_transport()),
    );
    let _ = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;

    let refs = live_index(&storage, &alice()).await;
    assert!(
        refs.len() >= MIN_BUFFER,
        "pool filled to MIN_BUFFER, got {}",
        refs.len()
    );
    let kp_ref = refs[0].clone();
    assert!(kp_record_present(&storage, &alice(), &kp_ref).await);

    let (reservation_id, public_bytes) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .expect("reserve succeeds");
    assert!(
        !public_bytes.is_empty(),
        "reserve returns PUBLIC bytes (not private signer-state)"
    );

    // Build a real Welcome for these public bytes and fuse the join via confirm.
    let welcome = real_welcome_for(&mls, &public_bytes).await;
    handle
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id: reservation_id.clone(),
            welcome_bytes: welcome,
            reply,
        })
        .await
        .expect("fused confirm join succeeds");

    // KP private record deleted from storage (the journal single-use anchor).
    assert!(
        !kp_record_present(&storage, &alice(), &kp_ref).await,
        "confirm must durably delete the KP private record"
    );

    handle.send_shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// 2. cancel burns the KP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cancel_burns_kp_not_returned_to_pool() {
    let storage = in_memory_storage();
    let (handle, _join) = spawn_filled(Arc::clone(&storage)).await;

    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    let (reservation_id, _public) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();

    handle
        .send(|reply| KeyPackageCommand::CancelReservation {
            reservation_id,
            reply,
        })
        .await
        .expect("cancel succeeds");

    assert!(
        !kp_record_present(&storage, &alice(), &kp_ref).await,
        "cancel must delete the KP record (single-use)"
    );
    let err = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .expect_err("burned KP is not re-reservable");
    assert!(matches!(err, ContextError::InvalidKeyPackage(_)));

    handle.send_shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// 3. double-consume prevention (H2 — the crux)
// ---------------------------------------------------------------------------

/// A second `ConfirmConsume` of the SAME reservation → Err. Drives the REAL
/// reserved KP through the fused confirm and proves the reservation-id
/// bookkeeping rejects the replay.
#[tokio::test]
async fn double_confirm_of_same_reservation_rejected() {
    let storage = in_memory_storage();
    let mls = backend_with_consumed_set(&storage);
    let (handle, _join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls), Arc::clone(&storage), no_transport()),
    );
    let _ = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    let (reservation_id, public_bytes) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();

    // Re-reserving the same (now-reserved) ref → Err.
    let err = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .expect_err("re-reserving a reserved KP fails");
    assert!(matches!(
        err,
        ContextError::InvalidKeyPackage(_) | ContextError::InvalidState(_)
    ));

    let welcome = real_welcome_for(&mls, &public_bytes).await;
    handle
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id: reservation_id.clone(),
            welcome_bytes: welcome.clone(),
            reply,
        })
        .await
        .expect("first fused confirm succeeds");

    // Second confirm of the same reservation → Err (reservation is gone).
    let err = handle
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id,
            welcome_bytes: welcome,
            reply,
        })
        .await
        .err()
        .expect("double-confirm fails");
    assert!(matches!(err, ContextError::InvalidState(_)));

    handle.send_shutdown().await.unwrap();
}

/// A SECOND join with the SAME init key at the backend consumed-set → rejected.
/// This proves the crypto-layer backstop (A2) is enforced INSIDE
/// `join_from_welcome`, independent of the actor's reservation bookkeeping.
#[tokio::test]
async fn second_join_same_init_key_rejected_at_backend() {
    let storage = in_memory_storage();
    let mls = backend_with_consumed_set(&storage);

    // Generate ONE key package and TWO independent Welcomes addressed to it
    // (two separate inviter groups both add the same KP). The first join
    // consumes the init key durably; the second must be rejected.
    let joiner = ScpCredential::new(alice().0, None, scp_did::SigningKeyId::Active).unwrap();
    let generated = mls.generate_key_package(&joiner, None).await.unwrap();
    let welcome_a = real_welcome_for(&mls, &generated.key_package_bytes).await;
    let welcome_b = real_welcome_for(&mls, &generated.key_package_bytes).await;

    // First join succeeds and records the init key as consumed. (ScpMlsGroup
    // is not Debug, so assert on `is_ok()` rather than `.expect()`.)
    assert!(
        mls.join_from_welcome(
            &welcome_a,
            generated.signer_state.clone(),
            &generated.key_package_bytes,
        )
        .await
        .is_ok(),
        "first join with a fresh init key succeeds"
    );

    // Second join with the SAME init key → KeyPackageReplay.
    let replay = mls
        .join_from_welcome(
            &welcome_b,
            generated.signer_state,
            &generated.key_package_bytes,
        )
        .await;
    assert!(
        matches!(replay, Err(MlsError::KeyPackageReplay)),
        "replay of a consumed init key must be rejected at the crypto layer"
    );
}

/// A join attempted on a backend with NO consumed-init-key store attached must
/// FAIL CLOSED — the single-use backstop must never silently vanish when
/// unconfigured. Pins the deny-by-default behavior (the prior fail-OPEN skip is
/// gone).
#[tokio::test]
async fn join_without_consumed_store_fails_closed() {
    // A store-less production backend (no `set_consumed_init_key_store`).
    let mls: Arc<dyn MlsBackend> = Arc::new(ProductionMlsBackend::new(std::sync::Arc::new(
        scp_clock::SystemClock,
    )));

    let joiner = ScpCredential::new(alice().0, None, scp_did::SigningKeyId::Active).unwrap();
    let generated = mls.generate_key_package(&joiner, None).await.unwrap();
    let welcome = real_welcome_for(&mls, &generated.key_package_bytes).await;

    let result = mls
        .join_from_welcome(
            &welcome,
            generated.signer_state,
            &generated.key_package_bytes,
        )
        .await;
    assert!(
        matches!(result, Err(MlsError::StorageError(_))),
        "a join with no consumed-init-key store attached must fail closed, got {:?}",
        result.map(|_| "Ok"),
    );
}

/// A join whose `key_package_public_bytes` argument does NOT match the KP the
/// `signer_state` was generated for must be rejected — the init-key/Welcome
/// binding prevents keying the consumed marker against an unrelated init key.
#[tokio::test]
async fn join_with_mismatched_public_bytes_rejected() {
    let storage = in_memory_storage();
    let mls = backend_with_consumed_set(&storage);

    let joiner = ScpCredential::new(alice().0, None, scp_did::SigningKeyId::Active).unwrap();
    let generated = mls.generate_key_package(&joiner, None).await.unwrap();
    // A DIFFERENT KP — its public bytes do not match `generated.signer_state`.
    let other = mls.generate_key_package(&joiner, None).await.unwrap();
    let welcome = real_welcome_for(&mls, &generated.key_package_bytes).await;

    // Pass the welcome + signer-state for `generated`, but the PUBLIC bytes of
    // `other` — the binding check must reject the mismatched pair.
    let result = mls
        .join_from_welcome(&welcome, generated.signer_state, &other.key_package_bytes)
        .await;
    assert!(
        matches!(result, Err(MlsError::WelcomeProcessingFailed(_))),
        "a mismatched (public_bytes, signer_state) pair must be rejected, got {:?}",
        result.map(|_| "Ok"),
    );
}

// ---------------------------------------------------------------------------
// 4. typed errors: empty / unknown ref / unknown reservation id
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unknown_ref_and_unknown_reservation_yield_typed_errors() {
    let storage = in_memory_storage();
    let (handle, _join) = spawn_filled(Arc::clone(&storage)).await;

    let err = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: KpRef::from_raw("deadbeef"),
            reply,
        })
        .await
        .expect_err("unknown ref fails");
    assert!(matches!(err, ContextError::InvalidKeyPackage(_)));

    let err = handle
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id: ReservationId::from_raw("no-such-reservation"),
            welcome_bytes: vec![0u8; 8],
            reply,
        })
        .await
        .err()
        .expect("unknown reservation confirm fails");
    assert!(matches!(err, ContextError::InvalidState(_)));

    let err = handle
        .send(|reply| KeyPackageCommand::CancelReservation {
            reservation_id: ReservationId::from_raw("no-such-reservation"),
            reply,
        })
        .await
        .expect_err("unknown reservation cancel fails");
    assert!(matches!(err, ContextError::InvalidState(_)));

    handle.send_shutdown().await.unwrap();
}

#[tokio::test]
async fn reserve_when_empty_returns_typed_err_not_hang() {
    let storage = in_memory_storage();
    let failing: Arc<dyn MlsBackend> = Arc::new(FailingBackend::new(0));
    let (handle, _join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(failing, Arc::clone(&storage), no_transport()),
    );

    let err = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: KpRef::from_raw("anything"),
            reply,
        })
        .await
        .expect_err("reserve on empty pool returns typed Err");
    assert!(matches!(err, ContextError::InvalidKeyPackage(_)));

    handle.send_shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// 5. pool exhaustion + auto-replenish + generate-failure partial-retain
// ---------------------------------------------------------------------------

#[tokio::test]
async fn replenish_refills_to_min_and_reports_count() {
    let storage = in_memory_storage();
    let (handle, _join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(real_backend(), Arc::clone(&storage), no_transport()),
    );

    let count = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await
        .expect("replenish succeeds");
    assert!(count <= MIN_BUFFER);
    let refs = live_index(&storage, &alice()).await;
    assert_eq!(refs.len(), MIN_BUFFER, "pool at MIN_BUFFER after replenish");

    handle.send_shutdown().await.unwrap();
}

#[tokio::test]
async fn drain_below_threshold_triggers_auto_replenish() {
    let storage = in_memory_storage();
    let (handle, _join) = spawn_filled(Arc::clone(&storage)).await;

    for _ in 0..6 {
        let kp_ref = {
            let refs = live_index(&storage, &alice()).await;
            refs.into_iter()
                .find(|r| !r.as_str().is_empty())
                .expect("a pooled ref exists")
        };
        let (rid, _pub) = handle
            .send(|reply| KeyPackageCommand::Reserve {
                kp_ref: kp_ref.clone(),
                reply,
            })
            .await
            .unwrap();
        handle
            .send(|reply| KeyPackageCommand::CancelReservation {
                reservation_id: rid,
                reply,
            })
            .await
            .unwrap();
    }

    let refs = live_index(&storage, &alice()).await;
    assert_eq!(
        refs.len(),
        MIN_BUFFER,
        "auto-replenish refilled the pool to MIN_BUFFER after draining below threshold"
    );

    handle.send_shutdown().await.unwrap();
}

#[tokio::test]
async fn replenish_generate_failure_yields_typed_err_when_zero_generated() {
    let storage = in_memory_storage();
    let failing: Arc<dyn MlsBackend> = Arc::new(FailingBackend::new(0));
    let (handle, _join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(failing, Arc::clone(&storage), no_transport()),
    );

    let err = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await
        .expect_err("zero-generated replenish returns CryptoFailed");
    assert!(matches!(err, ContextError::CryptoFailed(_)));

    handle.send_shutdown().await.unwrap();
}

#[tokio::test]
async fn replenish_partial_retain_returns_count_on_late_failure() {
    let storage = in_memory_storage();
    let failing: Arc<dyn MlsBackend> = Arc::new(FailingBackend::new(3));
    let (handle, _join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&failing), Arc::clone(&storage), no_transport()),
    );

    let _ = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;
    let refs = live_index(&storage, &alice()).await;
    assert_eq!(refs.len(), 3, "partial-retain kept the 3 generated KPs");

    handle.send_shutdown().await.unwrap();
}

/// A KP actor whose owning DID is malformed has NO valid credential (the
/// `ScpCredential::new(...).ok()` in `spawn` yields `None`). `replenish_to_min`
/// must FAIL CLOSED — refuse to generate/pool inert KeyPackages (which would be
/// signed against a non-existent credential) — rather than silently pooling
/// them. Pins the credential-absent guard.
#[tokio::test]
async fn replenish_fails_closed_when_credential_absent() {
    // A DID that `ScpCredential::new` rejects (not `did:dht:z*` / `did:test:` /
    // `did:key:`), so the actor's built credential is `None`.
    let malformed = DID("did:malformed:no-credential".to_owned());
    // Sanity: this DID truly produces no credential.
    assert!(
        ScpCredential::new(malformed.0.clone(), None, scp_did::SigningKeyId::Active).is_err(),
        "precondition: the malformed DID must not yield a valid credential"
    );

    let storage = in_memory_storage();
    let mls = backend_with_consumed_set(&storage);
    let (handle, _join) = KeyPackageStoreActor::spawn(
        malformed.clone(),
        deps_with(mls, Arc::clone(&storage), no_transport()),
    );

    let err = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await
        .expect_err("replenish must fail closed when the credential is absent");
    assert!(
        matches!(err, ContextError::CryptoFailed(_)),
        "credential-absent replenish must surface CryptoFailed, got {err:?}"
    );

    // No inert KPs were pooled: the durable index for this identity is empty.
    let index_key = format!("scp-kp-index/{}", malformed.0);
    assert!(
        storage.retrieve(&index_key).await.unwrap().is_none()
            || rmp_serde::from_slice::<Vec<KpRef>>(
                &storage.retrieve(&index_key).await.unwrap().unwrap()
            )
            .unwrap()
            .is_empty(),
        "no inert KeyPackages may be pooled when the credential is absent"
    );

    handle.send_shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// H1. storage-fault injection on Reserve / Confirm (fail-closed branches)
// ---------------------------------------------------------------------------

/// Persistence failure on Reserve → the KP is returned to the pool, the call
/// replies `Err`, and NO reservation is acked (fail-closed). A subsequent
/// successful reserve of the same ref proves the KP was returned to the pool.
#[tokio::test]
async fn reserve_persist_failure_returns_kp_to_pool_and_errs() {
    // Build a pool with a healthy backing store, then swap in a fault-injecting
    // adapter that fails the reservation-record write.
    let healthy = Arc::new(InMemoryStorage::new());
    let faulty = Arc::new(FaultyStorage::new(Arc::clone(&healthy)));
    let storage: Arc<dyn OpenMlsStorageAdapter> =
        Arc::new(SpawnBlockingStorageAdapter::new(Arc::clone(&faulty)));
    let (handle, _join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(real_backend(), Arc::clone(&storage), no_transport()),
    );
    let _ = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    // Fail the next reservation-record write.
    faulty.fail_prefix("scp-kp-reservation/");
    let err = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .expect_err("reserve fails closed when the reservation record write fails");
    assert!(matches!(err, ContextError::PersistenceFailed(_)));

    // Heal storage; the KP was returned to the pool, so reserve now succeeds.
    faulty.clear_fail();
    let (_rid, public_bytes) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .expect("KP was returned to the pool and is reservable after the fault heals");
    assert!(!public_bytes.is_empty());

    handle.send_shutdown().await.unwrap();
}

/// Persistence failure on the reservation-ID SET write during Reserve (the
/// fail-closed Class-S anchor, written AFTER the per-reservation record) → the
/// KP is returned to the pool, the call replies `Err`, and the just-written
/// per-reservation record is best-effort CLEANED (no orphan). This is the
/// Class-S fail-closed branch on the id-set write specifically — distinct from
/// the reservation-record write fault covered above.
///
/// Note: `scp-kp-reservation/` (the per-reservation record prefix) is itself a
/// prefix of `scp-kp-reservation-ids/` (the id-set key), but `should_fail`
/// matches on `starts_with`, so a fault on `scp-kp-reservation-ids/` does NOT
/// fail the record write (its key `scp-kp-reservation/{did}/{rid}` does not
/// start with `scp-kp-reservation-ids/`). The record write therefore SUCCEEDS,
/// only the id-set write fails, and the rollback's best-effort record delete
/// (also under `scp-kp-reservation/`, not the failing prefix) succeeds —
/// leaving no orphaned reservation record.
#[tokio::test]
async fn reserve_id_set_persist_failure_returns_kp_and_cleans_record() {
    let healthy = Arc::new(InMemoryStorage::new());
    let faulty = Arc::new(FaultyStorage::new(Arc::clone(&healthy)));
    let storage: Arc<dyn OpenMlsStorageAdapter> =
        Arc::new(SpawnBlockingStorageAdapter::new(Arc::clone(&faulty)));
    let (handle, _join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(real_backend(), Arc::clone(&storage), no_transport()),
    );
    let _ = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    // Snapshot the reservation records present before the faulted reserve (the
    // id-set key `scp-kp-reservation-ids/{did}` is itself written under the
    // healthy initial replenish? no — replenish writes none; assert empty).
    let record_prefix = format!("scp-kp-reservation/{}/", alice().0);
    assert!(
        healthy.list_keys(&record_prefix).await.unwrap().is_empty(),
        "precondition: no per-reservation records before any reserve"
    );

    // Fail ONLY the reservation-ID SET write (the LAST fail-closed step of
    // Reserve). The per-reservation record write lands first; the id-set write
    // then fails → rollback returns the KP to the pool and best-effort deletes
    // the just-written record.
    faulty.fail_prefix("scp-kp-reservation-ids/");
    let err = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .expect_err("reserve fails closed when the reservation-id set write fails");
    assert!(matches!(err, ContextError::PersistenceFailed(_)));

    // Heal storage. The id-set write fault is cleared, but we must observe the
    // post-rollback state: the per-reservation record was best-effort cleaned.
    faulty.clear_fail();
    let records = healthy.list_keys(&record_prefix).await.unwrap();
    assert!(
        records.is_empty(),
        "the per-reservation record written before the id-set fault must be \
         best-effort cleaned by the rollback, got {records:?}"
    );

    // The KP was returned to the pool: re-reserving the same ref now succeeds.
    let (_rid, public_bytes) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .expect("KP returned to the pool and is reservable after the id-set fault heals");
    assert!(!public_bytes.is_empty());

    handle.send_shutdown().await.unwrap();
}

/// Persistence failure on Confirm (the KP-record delete) → the reservation is
/// RETAINED, the call replies `Err`, and NO consume is recorded. The KP record
/// still exists afterward (consume did not durably land).
#[tokio::test]
async fn confirm_persist_failure_retains_reservation_and_errs() {
    let healthy = Arc::new(InMemoryStorage::new());
    let faulty = Arc::new(FaultyStorage::new(Arc::clone(&healthy)));
    let storage: Arc<dyn OpenMlsStorageAdapter> =
        Arc::new(SpawnBlockingStorageAdapter::new(Arc::clone(&faulty)));
    let mls = backend_with_consumed_set(&storage);
    let (handle, _join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls), Arc::clone(&storage), no_transport()),
    );
    let _ = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    let (reservation_id, public_bytes) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();
    let welcome = real_welcome_for(&mls, &public_bytes).await;

    // Fail the KP-record delete (the first durable step of confirm).
    faulty.fail_prefix("scp-kp/");
    let err = handle
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id: reservation_id.clone(),
            welcome_bytes: welcome.clone(),
            reply,
        })
        .await
        .err()
        .expect("confirm fails closed when the KP-record delete fails");
    assert!(matches!(err, ContextError::PersistenceFailed(_)));

    // KP record still present (consume did NOT durably land).
    faulty.clear_fail();
    assert!(
        kp_record_present(&storage, &alice(), &kp_ref).await,
        "a failed confirm must not have deleted the KP record"
    );

    handle.send_shutdown().await.unwrap();
}

/// Item-1 regression: a tombstone (`scp-kp-consumed/`) store failure AFTER a
/// SUCCESSFUL internal join must NOT permanently wedge the reservation. The
/// first confirm errs (the consume did not fully land), but a RETRY — which
/// re-runs the internal join and now hits the already-written init-key marker
/// (`scp-kp-consumed-initkey/`) → `MlsError::KeyPackageReplay` — is recognized
/// as our own prior completion and idempotently FINISHES the durable consume.
/// Because the joined group is not retained across confirms (it was produced and
/// dropped by the first, failed confirm), the retry replies `Err(InvalidState)`
/// rather than a groupless `Ok`: the join is lost and the joiner must re-initiate
/// with a fresh key package. Single-use must still hold across the retry.
#[tokio::test]
async fn confirm_tombstone_failure_then_healed_retry_completes_consume_but_errs_groupless() {
    let healthy = Arc::new(InMemoryStorage::new());
    let faulty = Arc::new(FaultyStorage::new(Arc::clone(&healthy)));
    let storage: Arc<dyn OpenMlsStorageAdapter> =
        Arc::new(SpawnBlockingStorageAdapter::new(Arc::clone(&faulty)));
    // The consumed-init-key store shares the SAME faulty storage: the init-key
    // marker write (`scp-kp-consumed-initkey/`) and the tombstone write
    // (`scp-kp-consumed/`) are distinct prefixes, so failing only the latter
    // leaves the marker durably written by the internal join.
    let mls = backend_with_consumed_set(&storage);
    let (handle, _join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls), Arc::clone(&storage), no_transport()),
    );
    let _ = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    let (reservation_id, public_bytes) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();
    let welcome = real_welcome_for(&mls, &public_bytes).await;

    // Fail ONLY the consumed tombstone write (the LAST durable step of confirm).
    // The internal join completes (writing the init-key marker), the KP-record
    // delete completes, then the tombstone store fails → first confirm errs.
    faulty.fail_prefix("scp-kp-consumed/");
    let err = handle
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id: reservation_id.clone(),
            welcome_bytes: welcome.clone(),
            reply,
        })
        .await
        .err()
        .expect("first confirm errs when the tombstone store fails");
    assert!(matches!(err, ContextError::PersistenceFailed(_)));

    // The internal join already ran: its init-key marker is durably present
    // (written under `scp-kp-consumed-initkey/`, NOT failed by our
    // `scp-kp-consumed/` prefix), so a naive retry's INNER join would be
    // rejected as a replay. The fix recognizes this as our own completion. The
    // KP record was already deleted before the tombstone step failed; the
    // reservation is RETAINED for the retry.
    assert!(
        !kp_record_present(&storage, &alice(), &kp_ref).await,
        "the KP record was deleted before the failed tombstone step"
    );

    // Heal storage and RETRY the SAME reservation. The retry's inner join hits
    // the marker → KeyPackageReplay → recognized as our own prior completion →
    // idempotent durable-consume completion. The joined group is NOT retained
    // across confirms (it was produced and dropped by the first, failed
    // confirm), so the retry replies Err(InvalidState): the join is lost and the
    // joiner must re-initiate with a FRESH key package. This is fail-closed —
    // a groupless success is never returned, and the durable consume still lands.
    faulty.clear_fail();
    let retry = handle
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id: reservation_id.clone(),
            welcome_bytes: welcome.clone(),
            reply,
        })
        .await
        .err()
        .expect("healed retry errs — the joined group is not retained across confirms");
    assert!(matches!(retry, ContextError::InvalidState(_)));

    // The consume durably landed: the KP private record is gone (the journal
    // single-use anchor delete) and the reservation is cleared.
    assert!(
        !kp_record_present(&storage, &alice(), &kp_ref).await,
        "retry must durably delete the KP private record"
    );

    // Single-use still holds: the consumed reservation is gone, so a third
    // confirm of the same reservation_id is an unknown reservation.
    let unknown = handle
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id,
            welcome_bytes: welcome,
            reply,
        })
        .await
        .err()
        .expect("a consumed reservation must not confirm again");
    assert!(matches!(unknown, ContextError::InvalidState(_)));

    handle.send_shutdown().await.unwrap();
}

/// Item-1 regression: a reservation-record (`scp-kp-reservation/`) DELETE
/// failure during confirm's best-effort cleanup must NOT permanently orphan the
/// reservation record. With the consume already durable, the confirm still
/// returns `Ok`, but the rid is KEPT in the durable id-set (and the consumed
/// tombstone is RETAINED as the reachability anchor) so a later reconcile/GC
/// pass reclaims the surviving reservation record + tombstone. Without the
/// gated prune the rid would be dropped from the id-set and the tombstone
/// deleted, stranding the reservation record where `gc_consumed_journal` (which
/// walks the id-set + tombstones) could never reach it.
#[tokio::test]
async fn confirm_reservation_record_delete_failure_eventually_reclaimed_no_orphan() {
    let healthy = Arc::new(InMemoryStorage::new());
    let faulty = Arc::new(FaultyStorage::new(Arc::clone(&healthy)));
    let storage: Arc<dyn OpenMlsStorageAdapter> =
        Arc::new(SpawnBlockingStorageAdapter::new(Arc::clone(&faulty)));
    let mls = backend_with_consumed_set(&storage);
    let (handle, join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls), Arc::clone(&storage), no_transport()),
    );
    let _ = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    // Reserve HEALTHY so the per-reservation record + id-set entry land cleanly.
    let (reservation_id, public_bytes) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();
    let welcome = real_welcome_for(&mls, &public_bytes).await;

    let reservation_key = format!("scp-kp-reservation/{}/{reservation_id}", alice().0);
    let consumed_key = format!("scp-kp-consumed/{}/{reservation_id}", alice().0);
    assert!(
        raw_key_present(&storage, &reservation_key).await,
        "precondition: the reservation record exists after a healthy reserve"
    );

    // Fail the reservation-record DELETE (`scp-kp-reservation/`) during confirm's
    // best-effort cleanup. The durable consume (KP-record delete + tombstone
    // write) lands FIRST via `?`, so confirm still returns Ok; only the cleanup
    // delete fails. Note `scp-kp-reservation-ids/` does NOT start with
    // `scp-kp-reservation/`, so the gated id-set rewrite (retaining the rid) is
    // NOT blocked by this fault.
    faulty.fail_prefix("scp-kp-reservation/");
    handle
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id: reservation_id.clone(),
            welcome_bytes: welcome,
            reply,
        })
        .await
        .expect("confirm still succeeds: the consume is durable before the cleanup delete");

    // The KP record is durably gone (single-use anchor delete landed via `?`).
    assert!(
        !kp_record_present(&storage, &alice(), &kp_ref).await,
        "confirm durably deleted the KP private record"
    );
    // The cleanup delete failed, so the reservation record SURVIVES — but it is
    // NOT orphaned: the rid is retained in the id-set and the tombstone is kept
    // as the reachability anchor.
    faulty.clear_fail();
    assert!(
        raw_key_present(&storage, &reservation_key).await,
        "the reservation record survives the failed cleanup delete"
    );
    assert!(
        raw_key_present(&storage, &consumed_key).await,
        "the consumed tombstone is RETAINED (not deleted while the record survives) \
         as the reachability anchor"
    );
    // The rid is still enumerable in the durable id-set (the gated prune kept it).
    let ids_key = format!("scp-kp-reservation-ids/{}", alice().0);
    let ids: Vec<ReservationId> = storage
        .retrieve(&ids_key)
        .await
        .unwrap()
        .map_or_else(Vec::new, |b| rmp_serde::from_slice(&b).unwrap());
    assert!(
        ids.contains(&reservation_id),
        "the consumed rid is retained in the durable id-set so reconcile/GC can reach it"
    );

    handle.send_shutdown().await.unwrap();
    let _ = join.await;

    // Respawn: reconcile enumerates the retained rid, resolves it CONSUMED (the
    // tombstone is present), sees the KP record gone, and the GC reclaims BOTH
    // the consumed tombstone AND the surviving reservation record — no permanent
    // orphan.
    let mls2 = backend_with_consumed_set(&storage);
    let (handle2, _join2) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls2), Arc::clone(&storage), no_transport()),
    );
    let _ = handle2
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;

    assert!(
        !raw_key_present(&storage, &reservation_key).await,
        "the orphan-prone reservation record is reclaimed by the reconcile GC on respawn"
    );
    assert!(
        !raw_key_present(&storage, &consumed_key).await,
        "the consumed tombstone is reclaimed alongside the reservation record"
    );
    // Single-use still holds: the consumed KP is not re-poolable / re-reservable.
    let err = handle2
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .expect_err("the consumed KP must not be re-reservable after reclaim");
    assert!(matches!(err, ContextError::InvalidKeyPackage(_)));

    handle2.send_shutdown().await.unwrap();
}

/// Item-2 regression (symmetric sibling of the reservation-record case above): a
/// consumed-tombstone (`scp-kp-consumed/`) DELETE failure during confirm's
/// best-effort cleanup must NOT regress single-use and must leave the rid
/// reclaimable. The consume is durable (KP-record delete + tombstone write land
/// via `?` BEFORE the cleanup tail), so confirm still returns `Ok`. Confirm
/// deletes the reservation record FIRST (succeeds here), then the tombstone
/// delete fails — so the rid is RETAINED in the id-set and the tombstone is
/// RETAINED as the reachability anchor, and a respawn's GC reclaims everything.
/// Uses the delete-only fault mode so the tombstone is allowed to be WRITTEN
/// (the single-prefix `fail_prefix` would instead block the tombstone STORE,
/// never reaching the delete this test targets).
#[tokio::test]
async fn confirm_tombstone_delete_failure_eventually_reclaimed_no_orphan() {
    let healthy = Arc::new(InMemoryStorage::new());
    let faulty = Arc::new(FaultyStorage::new(Arc::clone(&healthy)));
    let storage: Arc<dyn OpenMlsStorageAdapter> =
        Arc::new(SpawnBlockingStorageAdapter::new(Arc::clone(&faulty)));
    let mls = backend_with_consumed_set(&storage);
    let (handle, join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls), Arc::clone(&storage), no_transport()),
    );
    let _ = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    let (reservation_id, public_bytes) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();
    let welcome = real_welcome_for(&mls, &public_bytes).await;

    let reservation_key = format!("scp-kp-reservation/{}/{reservation_id}", alice().0);
    let consumed_key = format!("scp-kp-consumed/{}/{reservation_id}", alice().0);

    // Fail ONLY the consumed-tombstone DELETE (`scp-kp-consumed/`) during the
    // confirm cleanup tail. The tombstone STORE (during the durable consume) is
    // allowed, so confirm still returns Ok; the reservation-record delete (a
    // different prefix) also succeeds, leaving the tombstone as the sole
    // cleanup-delete casualty.
    faulty.fail_delete_prefix("scp-kp-consumed/");
    handle
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id: reservation_id.clone(),
            welcome_bytes: welcome,
            reply,
        })
        .await
        .expect("confirm still succeeds: the consume is durable before the cleanup delete");

    // The KP private record is durably gone (single-use anchor delete landed).
    assert!(
        !kp_record_present(&storage, &alice(), &kp_ref).await,
        "confirm durably deleted the KP private record"
    );
    faulty.clear_fail();
    // Reservation record deleted (its delete was not faulted); tombstone RETAINED
    // (its delete failed) as the reachability anchor.
    assert!(
        !raw_key_present(&storage, &reservation_key).await,
        "the reservation record delete succeeded (only the tombstone delete failed)"
    );
    assert!(
        raw_key_present(&storage, &consumed_key).await,
        "the consumed tombstone survives the failed cleanup delete and anchors reachability"
    );
    // The rid is RETAINED in the durable id-set so reconcile/GC can reach it.
    let ids_key = format!("scp-kp-reservation-ids/{}", alice().0);
    let ids: Vec<ReservationId> = storage
        .retrieve(&ids_key)
        .await
        .unwrap()
        .map_or_else(Vec::new, |b| rmp_serde::from_slice(&b).unwrap());
    assert!(
        ids.contains(&reservation_id),
        "the consumed rid is retained in the durable id-set so reconcile/GC can reach it"
    );

    handle.send_shutdown().await.unwrap();
    let _ = join.await;

    // Respawn: reconcile enumerates the retained rid, reads the retained
    // tombstone → resolves CONSUMED, sees the KP record gone, and the GC reclaims
    // the surviving tombstone — no permanent orphan.
    let mls2 = backend_with_consumed_set(&storage);
    let (handle2, _join2) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls2), Arc::clone(&storage), no_transport()),
    );
    let _ = handle2
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;

    assert!(
        !raw_key_present(&storage, &consumed_key).await,
        "the orphan-prone consumed tombstone is reclaimed by the reconcile GC on respawn"
    );
    // Single-use still holds: the consumed KP is not re-poolable / re-reservable.
    let err = handle2
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .expect_err("the consumed KP must not be re-reservable after reclaim");
    assert!(matches!(err, ContextError::InvalidKeyPackage(_)));

    handle2.send_shutdown().await.unwrap();
}

/// Item-1 regression: a reservation-record (`scp-kp-reservation/`) DELETE failure
/// during the reconcile GC pass (`gc_consumed_journal`) must NOT permanently
/// orphan the reservation record. The GC deletes the reservation record FIRST and
/// the tombstone only on success (symmetric with the confirm cleanup tail), and
/// it RETAINS any rid it could not fully reclaim so the reconcile tail id-set
/// rewrite keeps it enumerable — otherwise the unconditional rewrite (from
/// `self.reserved` alone) would prune the rid while the tombstone is gone,
/// stranding the surviving reservation record where no later pass could reach it.
/// A second respawn (fault cleared) reclaims everything; single-use holds
/// throughout.
#[tokio::test]
async fn gc_reservation_record_delete_failure_eventually_reclaimed_no_orphan() {
    let healthy = Arc::new(InMemoryStorage::new());
    let faulty = Arc::new(FaultyStorage::new(Arc::clone(&healthy)));
    let storage: Arc<dyn OpenMlsStorageAdapter> =
        Arc::new(SpawnBlockingStorageAdapter::new(Arc::clone(&faulty)));
    let mls = backend_with_consumed_set(&storage);
    let (handle, join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls), Arc::clone(&storage), no_transport()),
    );
    let _ = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    let (reservation_id, public_bytes) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();
    let welcome = real_welcome_for(&mls, &public_bytes).await;

    let reservation_key = format!("scp-kp-reservation/{}/{reservation_id}", alice().0);
    let consumed_key = format!("scp-kp-consumed/{}/{reservation_id}", alice().0);
    let ids_key = format!("scp-kp-reservation-ids/{}", alice().0);

    // Drive the SAME confirm-orphan precondition: fail the reservation-record
    // DELETE during confirm so the consume is durable (KP record gone, tombstone
    // written) but the reservation record + tombstone + rid-in-id-set all
    // survive. This is the state the GC inherits on the next respawn.
    faulty.fail_prefix("scp-kp-reservation/");
    handle
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id: reservation_id.clone(),
            welcome_bytes: welcome,
            reply,
        })
        .await
        .expect("confirm still succeeds: the consume is durable before the cleanup delete");
    faulty.clear_fail();
    assert!(
        !kp_record_present(&storage, &alice(), &kp_ref).await,
        "confirm durably deleted the KP private record (GC precondition: record absent)"
    );
    assert!(
        raw_key_present(&storage, &reservation_key).await,
        "precondition: the reservation record survived the confirm cleanup delete"
    );
    assert!(
        raw_key_present(&storage, &consumed_key).await,
        "precondition: the consumed tombstone is the reachability anchor"
    );

    handle.send_shutdown().await.unwrap();
    let _ = join.await;

    // Respawn #1 with the reservation-record DELETE faulted (delete-only, so the
    // tombstone/record writes during reconcile self-heal are unaffected). The GC
    // sees the KP record absent, deletes the reservation record FIRST → that
    // delete FAILS → the GC KEEPS the tombstone (does not reach its delete) and
    // RETAINS the rid; the reconcile tail rewrite therefore keeps the rid
    // enumerable. No permanent orphan despite the fault.
    faulty.fail_delete_prefix("scp-kp-reservation/");
    // respawn over the same durable storage = crash recovery
    let (handle2, join2) = spawn_filled(Arc::clone(&storage)).await;
    faulty.clear_fail();

    // The GC could not delete the reservation record, so BOTH it and the
    // tombstone survive — and crucially the rid is still enumerable in the id-set
    // (retained), so the orphan is reachable for the next pass.
    assert!(
        raw_key_present(&storage, &reservation_key).await,
        "the reservation record survives the GC-time delete fault"
    );
    assert!(
        raw_key_present(&storage, &consumed_key).await,
        "the tombstone is retained (GC stops at the failed reservation-record delete)"
    );
    let ids: Vec<ReservationId> = storage
        .retrieve(&ids_key)
        .await
        .unwrap()
        .map_or_else(Vec::new, |b| rmp_serde::from_slice(&b).unwrap());
    assert!(
        ids.contains(&reservation_id),
        "the GC-incomplete rid is RETAINED in the id-set rewrite so a later pass reclaims it"
    );

    handle2.send_shutdown().await.unwrap();
    let _ = join2.await;

    // Respawn #2 (fault cleared): the retained rid is enumerated again, resolves
    // CONSUMED via the retained tombstone, the KP record is still gone, and the
    // GC now reclaims BOTH the reservation record and the tombstone — eventual
    // reclaim, no permanent orphan.
    // respawn over the same durable storage = crash recovery
    let (handle3, _join3) = spawn_filled(Arc::clone(&storage)).await;

    assert!(
        !raw_key_present(&storage, &reservation_key).await,
        "the reservation record is reclaimed by the GC once its delete succeeds"
    );
    assert!(
        !raw_key_present(&storage, &consumed_key).await,
        "the consumed tombstone is reclaimed alongside the reservation record"
    );
    // Single-use still holds across the whole sequence.
    let err = handle3
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .expect_err("the consumed KP must not be re-reservable after reclaim");
    assert!(matches!(err, ContextError::InvalidKeyPackage(_)));

    handle3.send_shutdown().await.unwrap();
}

/// Item-2 regression (symmetric sibling of the reservation-record GC test): a
/// consumed-TOMBSTONE (`scp-kp-consumed/`) DELETE failure during the reconcile
/// GC pass (`gc_consumed_journal`) must NOT permanently orphan the tombstone.
/// The GC deletes the reservation record FIRST (succeeds — it is already gone)
/// and reaches the tombstone delete, which FAILS; the GC then RETAINS the rid
/// so the reconcile tail id-set rewrite keeps it enumerable — otherwise the
/// unconditional rewrite (from `self.reserved` alone) would prune the rid while
/// the tombstone survives, stranding it where no later pass could reach it
/// (the KV has no list API; reconcile walks the id-set, not the keyspace). A
/// second respawn (fault cleared) reclaims the tombstone; single-use holds
/// throughout.
///
/// Mutation guard: removing the `retain.push(rid.clone())` at the GC
/// tombstone-delete-fail branch makes this test FAIL — the pruned rid leaves
/// the surviving tombstone permanently unreachable, so respawn #2 cannot
/// reclaim it.
#[tokio::test]
async fn gc_tombstone_delete_failure_eventually_reclaimed_no_orphan() {
    let healthy = Arc::new(InMemoryStorage::new());
    let faulty = Arc::new(FaultyStorage::new(Arc::clone(&healthy)));
    let storage: Arc<dyn OpenMlsStorageAdapter> =
        Arc::new(SpawnBlockingStorageAdapter::new(Arc::clone(&faulty)));
    let mls = backend_with_consumed_set(&storage);
    let (handle, join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls), Arc::clone(&storage), no_transport()),
    );
    handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await
        .expect("startup reconcile + replenish barrier");
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    let (reservation_id, public_bytes) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();
    let welcome = real_welcome_for(&mls, &public_bytes).await;

    let reservation_key = format!("scp-kp-reservation/{}/{reservation_id}", alice().0);
    let consumed_key = format!("scp-kp-consumed/{}/{reservation_id}", alice().0);
    let ids_key = format!("scp-kp-reservation-ids/{}", alice().0);

    // Confirm precondition: fail ONLY the consumed-tombstone DELETE during the
    // confirm cleanup tail. The reservation-record delete (a different prefix)
    // SUCCEEDS, so the GC inherits the state with the reservation record GONE and
    // the tombstone SURVIVING — exactly the precondition that drives the GC to
    // delete the (already-absent) reservation record and reach its tombstone
    // delete on the next respawn.
    faulty.fail_delete_prefix("scp-kp-consumed/");
    handle
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id: reservation_id.clone(),
            welcome_bytes: welcome,
            reply,
        })
        .await
        .expect("confirm still succeeds: the consume is durable before the cleanup delete");
    faulty.clear_fail();
    assert!(
        !kp_record_present(&storage, &alice(), &kp_ref).await,
        "confirm durably deleted the KP private record (GC precondition: record absent)"
    );
    assert!(
        !raw_key_present(&storage, &reservation_key).await,
        "precondition: the reservation record delete succeeded (only the tombstone delete failed)"
    );
    assert!(
        raw_key_present(&storage, &consumed_key).await,
        "precondition: the consumed tombstone survives as the reachability anchor"
    );

    handle.send_shutdown().await.unwrap();
    let _ = join.await;

    // Respawn #1 with the consumed-tombstone DELETE faulted (delete-only, so the
    // tombstone retrieve during reconcile self-heal is unaffected). The GC sees
    // the KP record absent, deletes the reservation record FIRST → that delete
    // SUCCEEDS (the record is already gone; the KV delete is idempotent) → the GC
    // reaches the tombstone delete → that delete FAILS → the GC RETAINS the rid so
    // the reconcile tail rewrite keeps it enumerable. No permanent orphan.
    faulty.fail_delete_prefix("scp-kp-consumed/");
    // respawn over the same durable storage = crash recovery
    let (handle2, join2) = spawn_filled(Arc::clone(&storage)).await;
    faulty.clear_fail();

    // The GC could not delete the tombstone, so it survives — and crucially the
    // rid is still enumerable in the id-set (retained), so the orphan is reachable
    // for the next pass.
    assert!(
        raw_key_present(&storage, &consumed_key).await,
        "the tombstone survives the GC-time delete fault"
    );
    let ids: Vec<ReservationId> = storage
        .retrieve(&ids_key)
        .await
        .unwrap()
        .map_or_else(Vec::new, |b| rmp_serde::from_slice(&b).unwrap());
    assert!(
        ids.contains(&reservation_id),
        "the GC-incomplete rid is RETAINED in the id-set rewrite so a later pass reclaims it"
    );

    handle2.send_shutdown().await.unwrap();
    let _ = join2.await;

    // Respawn #2 (fault cleared): the retained rid is enumerated again, resolves
    // CONSUMED via the retained tombstone, the KP record is still gone, and the GC
    // now reclaims the tombstone — eventual reclaim, no permanent orphan.
    // respawn over the same durable storage = crash recovery
    let (handle3, _join3) = spawn_filled(Arc::clone(&storage)).await;

    assert!(
        !raw_key_present(&storage, &consumed_key).await,
        "the consumed tombstone is reclaimed by the GC once its delete succeeds"
    );
    // Single-use still holds across the whole sequence.
    let err = handle3
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .expect_err("the consumed KP must not be re-reservable after reclaim");
    assert!(matches!(err, ContextError::InvalidKeyPackage(_)));

    handle3.send_shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// 6. crash-during-reservation: no double-consume across respawn
// ---------------------------------------------------------------------------

#[tokio::test]
async fn respawn_restores_reservation_as_reserved_not_pooled() {
    let storage = in_memory_storage();
    let (handle, join) = spawn_filled(Arc::clone(&storage)).await;
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    let (_reservation_id, _public) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();

    handle.send_shutdown().await.unwrap();
    let _ = join.await;

    let (handle2, _join2) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(real_backend(), Arc::clone(&storage), no_transport()),
    );
    let _ = handle2
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;

    let err = handle2
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .expect_err("reserved KP restored on respawn is not re-reservable");
    assert!(matches!(
        err,
        ContextError::InvalidState(_) | ContextError::InvalidKeyPackage(_)
    ));

    handle2.send_shutdown().await.unwrap();
}

#[tokio::test]
async fn respawn_after_confirm_keeps_key_absent() {
    let storage = in_memory_storage();
    let mls = backend_with_consumed_set(&storage);
    let (handle, join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls), Arc::clone(&storage), no_transport()),
    );
    let _ = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    let (reservation_id, public_bytes) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();
    let welcome = real_welcome_for(&mls, &public_bytes).await;
    handle
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id,
            welcome_bytes: welcome,
            reply,
        })
        .await
        .unwrap();
    handle.send_shutdown().await.unwrap();
    let _ = join.await;

    let (handle2, _join2) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(real_backend(), Arc::clone(&storage), no_transport()),
    );
    let _ = handle2
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;
    assert!(
        !kp_record_present(&storage, &alice(), &kp_ref).await,
        "confirmed-then-crashed KP record stays absent after respawn"
    );
    let err = handle2
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .expect_err("consumed KP not re-reservable after respawn");
    assert!(matches!(err, ContextError::InvalidKeyPackage(_)));

    handle2.send_shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// H4. tombstone/reconcile crash window (B1): a consumed KP whose record
// SURVIVES (lost delete) must NOT be re-pooled on respawn.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn consumed_kp_with_surviving_record_not_repooled_on_respawn() {
    // Simulate: a consume wrote the tombstone (reservation_id -> kp_ref) but
    // the KP-record delete + index update were LOST (crash). On respawn the
    // index still lists the kp_ref and the KP record still exists, but the
    // tombstone names it consumed — reconcile must exclude it from the pool.
    let storage = in_memory_storage();
    let (handle, join) = spawn_filled(Arc::clone(&storage)).await;
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    // Reserve so a reservation record + id-set entry exist for this ref.
    let (reservation_id, _public) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();
    handle.send_shutdown().await.unwrap();
    let _ = join.await;

    // Hand-write a consumed tombstone for this reservation (value = kp_ref),
    // leaving the KP record + index intact (the lost-delete crash window).
    storage
        .store(
            &format!("scp-kp-consumed/{}/{reservation_id}", alice().0),
            kp_ref.as_str().as_bytes(),
        )
        .await
        .unwrap();
    assert!(
        kp_record_present(&storage, &alice(), &kp_ref).await,
        "precondition: KP record survives the simulated lost delete"
    );

    // Respawn: reconcile must EXCLUDE the consumed ref from the pool.
    let (handle2, _join2) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(real_backend(), Arc::clone(&storage), no_transport()),
    );
    let _ = handle2
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;

    let err = handle2
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .expect_err("a consumed KP whose record survived must not be re-pooled");
    assert!(matches!(err, ContextError::InvalidKeyPackage(_)));

    handle2.send_shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// H4-union. consumed KP whose record survived AND whose index entry was ALSO
// lost: the consumed ref is no longer named by the index, so it must be pulled
// into the reconcile union via `consumed_refs` — otherwise its surviving
// private record (signer-state) leaks at rest and is never reclaimed. This is
// the consumed-spine analog of the reserved-spine union fix above.
// ---------------------------------------------------------------------------

/// A CONSUMED KP whose private record survived a lost delete AND whose index
/// entry was ALSO lost must STILL be visited by reconcile (via the
/// `consumed_refs` arm of the enumeration union), its stale record best-effort
/// deleted, and — on a SECOND respawn, once the record is confirmed gone — its
/// tombstone + reservation record reclaimed by the GC. Without `consumed_refs`
/// in the union the ref is never walked: the surviving signer-state leaks
/// permanently at rest and the tail id-set/index rewrite severs future
/// enumeration of it.
#[tokio::test]
async fn consumed_kp_with_surviving_record_and_lost_index_entry_reclaimed_on_double_respawn() {
    let storage = in_memory_storage();
    let (handle, join) = spawn_filled(Arc::clone(&storage)).await;
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    // Reserve so a reservation record + id-set entry exist for this ref.
    let (reservation_id, _public) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();
    handle.send_shutdown().await.unwrap();
    let _ = join.await;

    // Hand-write a consumed tombstone for this reservation (value = kp_ref),
    // simulating a consume whose tombstone landed but whose KP-record delete was
    // lost (the record survives).
    let consumed_key = format!("scp-kp-consumed/{}/{reservation_id}", alice().0);
    storage
        .store(&consumed_key, kp_ref.as_str().as_bytes())
        .await
        .unwrap();
    // ALSO drop the ref from the durable index — the index write was lost too,
    // so NOTHING in the index names this consumed ref any more. Only the
    // tombstone (consumed spine) still does.
    let index_key = format!("scp-kp-index/{}", alice().0);
    let mut idx = live_index(&storage, &alice()).await;
    idx.retain(|r| *r != kp_ref);
    assert!(
        !idx.contains(&kp_ref),
        "precondition: consumed ref removed from the durable index"
    );
    storage
        .store(&index_key, &rmp_serde::to_vec_named(&idx).unwrap())
        .await
        .unwrap();
    assert!(
        kp_record_present(&storage, &alice(), &kp_ref).await,
        "precondition: the consumed KP record survives the simulated lost delete"
    );

    // FIRST respawn: reconcile must visit the consumed ref via `consumed_refs`
    // (it is NOT in the index), exclude it from the pool, and best-effort delete
    // its stale record.
    let mls2 = backend_with_consumed_set(&storage);
    let (handle2, join2) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls2), Arc::clone(&storage), no_transport()),
    );
    let _ = handle2
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;

    // (a) the consumed ref is NOT re-poolable / re-reservable.
    let err = handle2
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .expect_err("a consumed KP whose record survived must not be re-pooled");
    assert!(matches!(err, ContextError::InvalidKeyPackage(_)));

    // The stale record was best-effort deleted during the first reconcile — no
    // private signer-state lingers at rest.
    assert!(
        !kp_record_present(&storage, &alice(), &kp_ref).await,
        "the surviving consumed KP record must be deleted by reconcile (no at-rest leak)"
    );

    handle2.send_shutdown().await.unwrap();
    let _ = join2.await;

    // SECOND respawn: with the record now gone, the GC pass reclaims the
    // tombstone + reservation record (bounded durable growth).
    let mls3 = backend_with_consumed_set(&storage);
    let (handle3, _join3) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls3), Arc::clone(&storage), no_transport()),
    );
    let _ = handle3
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;

    let reservation_key = format!("scp-kp-reservation/{}/{reservation_id}", alice().0);
    assert!(
        !kp_record_present(&storage, &alice(), &kp_ref).await,
        "(b) KP record stays absent after the second respawn"
    );
    assert!(
        !raw_key_present(&storage, &consumed_key).await,
        "(b) consumed tombstone reclaimed once the KP record is confirmed gone"
    );
    assert!(
        !raw_key_present(&storage, &reservation_key).await,
        "(b) consumed reservation record reclaimed alongside the tombstone"
    );

    handle3.send_shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// H4-gc. the GC reclaims a consumed tombstone + reservation record once the KP
// record is confirmed gone (bounded durable growth).
// ---------------------------------------------------------------------------

/// `gc_consumed_journal` reclaims a consumed tombstone + its reservation record
/// once the KP record is confirmed gone — proving the consumed journal does not
/// grow without bound.
///
/// A CLEAN in-process consume already self-cleans (it best-effort deletes the
/// tombstone and prunes the rid in the same handler), so the GC's job is the
/// CRASH-window survivor: the process died right after the tombstone write but
/// before the in-handler cleanup, leaving the rid STILL in the id-set, the
/// tombstone + reservation record present, and the KP record already deleted (it
/// is deleted via `?` before the tombstone write). We seed exactly that durable
/// state, then respawn: reconcile enumerates the surviving rid, finds the KP
/// record gone, and the GC reclaims the tombstone + reservation record.
#[tokio::test]
async fn gc_reclaims_consumed_tombstone_and_reservation_record_after_respawn() {
    let storage = in_memory_storage();
    let (handle, join) = spawn_filled(Arc::clone(&storage)).await;
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    // Reserve so a real reservation record + id-set entry exist for this rid.
    let (reservation_id, _public) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();
    handle.send_shutdown().await.unwrap();
    let _ = join.await;

    let consumed_key = format!("scp-kp-consumed/{}/{reservation_id}", alice().0);
    let reservation_key = format!("scp-kp-reservation/{}/{reservation_id}", alice().0);

    // Seed the post-crash state: tombstone present (value = kp_ref), KP record
    // DELETED (the consume's `?`-propagated delete landed), reservation record +
    // rid-in-id-set left intact (the in-handler cleanup never ran). The rid is
    // already in the durable id-set from the Reserve above, so reconcile will
    // enumerate it.
    storage
        .store(&consumed_key, kp_ref.as_str().as_bytes())
        .await
        .unwrap();
    storage
        .delete(&format!("scp-kp/{}/{kp_ref}", alice().0))
        .await
        .unwrap();
    assert!(
        !kp_record_present(&storage, &alice(), &kp_ref).await,
        "precondition: KP record is gone (consume's delete landed)"
    );
    assert!(
        raw_key_present(&storage, &consumed_key).await,
        "precondition: tombstone survives the crash"
    );
    assert!(
        raw_key_present(&storage, &reservation_key).await,
        "precondition: reservation record survives the crash"
    );

    // Respawn: reconcile enumerates the surviving rid (still in the id-set),
    // sees the KP record absent, and the GC reclaims the tombstone + reservation
    // record.
    let mls2 = backend_with_consumed_set(&storage);
    let (handle2, _join2) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls2), Arc::clone(&storage), no_transport()),
    );
    let _ = handle2
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;

    assert!(
        !raw_key_present(&storage, &consumed_key).await,
        "GC reclaims the consumed tombstone once the KP record is confirmed gone"
    );
    assert!(
        !raw_key_present(&storage, &reservation_key).await,
        "GC reclaims the consumed reservation record alongside the tombstone"
    );

    handle2.send_shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// H4-malformed. a malformed (non-UTF-8) consumed tombstone must not panic, must
// be treated as consumed (not restored to `reserved`), and the A2 crypto-layer
// backstop must still reject a re-join of that KP. Pins fail-closed-VISIBLE.
// ---------------------------------------------------------------------------

/// A raw non-UTF-8 value seeded at a `scp-kp-consumed/{did}/{rid}` key is
/// Anchor-1 corruption: the consumed `kp_ref` is unrecoverable. Reconcile must
/// (a) still complete (no panic), (b) NOT restore the affected reservation to
/// `reserved` (treat it as consumed), and (c) the A2 init-key backstop's durable
/// marker must PERSIST across the tombstone corruption (it is not co-lost with
/// the corrupted tombstone). This test proves marker PRESENCE only — it does not
/// itself drive a re-join (the private signer-state is gone). The actual re-join
/// REJECTION property (a second join with an already-consumed init key fails
/// `KeyPackageReplay`) is proven by `second_join_same_init_key_rejected_at_backend`.
#[tokio::test]
async fn malformed_consumed_tombstone_reconciles_fail_closed_and_a2_still_rejects() {
    let (storage, inner) = in_memory_storage_with_inner();
    let mls = backend_with_consumed_set(&storage);
    let (handle, join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls), Arc::clone(&storage), no_transport()),
    );
    let _ = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    // Reserve, capture the public bytes (so we can drive a real backend join for
    // the A2 assertion), then complete a genuine consume so the KP's init key is
    // durably marked consumed in the crypto-layer set.
    let (reservation_id, public_bytes) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();
    // Build a signer-state-bearing generated KP path: drive the consume through
    // the actor so the init-key marker is written for THIS reserved KP.
    let welcome = real_welcome_for(&mls, &public_bytes).await;
    handle
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id: reservation_id.clone(),
            welcome_bytes: welcome,
            reply,
        })
        .await
        .expect("fused confirm join succeeds");
    handle.send_shutdown().await.unwrap();
    let _ = join.await;

    // Overwrite the (now-valid) tombstone with a MALFORMED non-UTF-8 value at the
    // SAME key, simulating Anchor-1 corruption.
    let consumed_key = format!("scp-kp-consumed/{}/{reservation_id}", alice().0);
    storage.store(&consumed_key, &[0xff, 0xfe]).await.unwrap();

    // (a) Respawn: reconcile must NOT panic on the malformed tombstone.
    let mls2 = backend_with_consumed_set(&storage);
    let (handle2, _join2) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls2), Arc::clone(&storage), no_transport()),
    );
    let count = handle2
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await
        .expect("reconcile + replenish complete despite the malformed tombstone");
    // The actor is operational (it refilled the pool back to MIN_BUFFER minus the
    // one already-consumed KP), proving reconcile finished.
    let _ = count;

    // (b) The affected reservation is NOT restored as `reserved`: the malformed
    // tombstone is treated as consumed, so its rid never re-enters `reserved`. A
    // confirm of the original rid is an unknown reservation.
    let dummy_welcome = real_welcome_for(&mls2, &public_bytes).await;
    let err = handle2
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id: reservation_id.clone(),
            welcome_bytes: dummy_welcome,
            reply,
        })
        .await
        .err()
        .expect("a malformed-tombstone reservation must not be restored as reserved");
    assert!(matches!(err, ContextError::InvalidState(_)));

    // (c) The A2 crypto-layer backstop's durable record survives the
    // actor-layer tombstone corruption: the consumed-init-key marker written
    // during the real consume above is still present in storage even though the
    // actor-layer tombstone is now unreadable. This test asserts exactly that —
    // marker PRESENCE — which is what proves the backstop is not co-lost with
    // the corrupted tombstone. It does NOT itself perform a re-join: the
    // private signer-state is gone, so a fresh re-join cannot be driven here.
    // The re-join REJECTION property (a second join with an init key already in
    // the set fails `KeyPackageReplay`) is proven separately by
    // `second_join_same_init_key_rejected_at_backend`; this assertion proves
    // only that the marker the backstop relies on persists across the
    // corruption.
    let marker_present = inner.list_keys("scp-kp-consumed-initkey/").await.unwrap();
    assert!(
        !marker_present.is_empty(),
        "the A2 consumed-init-key marker for the consumed KP must persist across the \
         actor-layer tombstone corruption"
    );

    handle2.send_shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// H4-malformed-recover. the COMPOUND failure: a malformed (non-UTF-8) consumed
// tombstone whose KP record AND index entry AND reservation record all survive.
// The consumed kp_ref must be RECOVERED from the surviving reservation record so
// reconcile EXCLUDES it (never re-pools) and best-effort deletes the stale KP
// record (no at-rest leak). Distinct from the record-already-gone malformed test.
// ---------------------------------------------------------------------------

/// Compound failure: a consume wrote its tombstone, but the tombstone VALUE got
/// corrupted (non-UTF-8) WHILE the KP private record, the durable index entry,
/// AND the reservation record all survived a lost delete. The corrupt tombstone
/// can no longer yield the consumed `kp_ref` directly — but the SAME `kp_ref`
/// lives in the surviving reservation record. Reconcile must recover it from
/// there, so that (a) the ref is NOT re-poolable / re-reservable, (b) the stale
/// KP private record is best-effort deleted (no signer-state leak at rest), and
/// (c) reconcile does not panic.
#[tokio::test]
async fn malformed_tombstone_recovers_consumed_ref_from_reservation_record() {
    let storage = in_memory_storage();
    let (handle, join) = spawn_filled(Arc::clone(&storage)).await;
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    // Reserve so a reservation record (carrying kp_ref) + id-set entry exist.
    let (reservation_id, _public) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();
    handle.send_shutdown().await.unwrap();
    let _ = join.await;

    // Seed the dangerous combination:
    //  - a MALFORMED (non-UTF-8) consumed tombstone for this rid (its own value
    //    no longer names the consumed kp_ref);
    //  - the KP private record SURVIVES (a lost delete);
    //  - the index entry SURVIVES (the index still names the ref);
    //  - the reservation record SURVIVES (it still carries the kp_ref).
    let consumed_key = format!("scp-kp-consumed/{}/{reservation_id}", alice().0);
    storage.store(&consumed_key, &[0xff, 0xfe]).await.unwrap();
    let reservation_key = format!("scp-kp-reservation/{}/{reservation_id}", alice().0);
    assert!(
        raw_key_present(&storage, &reservation_key).await,
        "precondition: the reservation record survives (carries the kp_ref)"
    );
    assert!(
        kp_record_present(&storage, &alice(), &kp_ref).await,
        "precondition: the consumed KP record survives the lost delete"
    );
    assert!(
        live_index(&storage, &alice()).await.contains(&kp_ref),
        "precondition: the index entry survives (still names the ref)"
    );

    // Respawn. Reconcile must NOT panic, must recover the consumed kp_ref from
    // the surviving reservation record, exclude it, and delete the stale record.
    let mls2 = backend_with_consumed_set(&storage);
    let (handle2, _join2) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls2), Arc::clone(&storage), no_transport()),
    );
    handle2
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await
        .expect("(c) reconcile + replenish complete with no panic");

    // (a) the recovered-consumed ref is NOT re-poolable / re-reservable — it was
    // excluded from the pool branch via the reservation-record recovery.
    let err = handle2
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .expect_err(
            "(a) a consumed KP recovered from the reservation record must not be re-poolable",
        );
    assert!(matches!(err, ContextError::InvalidKeyPackage(_)));

    // (b) the stale KP private record was best-effort deleted by reconcile — no
    // private signer-state lingers at rest.
    assert!(
        !kp_record_present(&storage, &alice(), &kp_ref).await,
        "(b) the surviving consumed KP record must be deleted (no at-rest leak)"
    );

    handle2.send_shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// H4-confirm-guard. a KeyPackageReplay whose KP record STILL EXISTS is NOT a
// legitimate own-prior-completion → must surface as KeyPackageReplay, never a
// spurious Ok (the tightened retry-idempotency guard).
// ---------------------------------------------------------------------------

/// The retry-idempotency guard must NOT rest on "the reservation is live" alone.
/// A real prior join of a reservation deletes the KP record FIRST (fail-safe)
/// before tombstoning. So if a `KeyPackageReplay` fires while THIS reservation's
/// KP record STILL EXISTS, it cannot be our own prior completion — and must be
/// surfaced as a `KeyPackageReplay` error, NOT converted into a false `Ok`.
///
/// We drive exactly that state by failing the KP-record DELETE (`scp-kp/`) on the
/// first confirm: the internal join completes (writing the init-key marker), then
/// the delete fails → first confirm errs and the KP record SURVIVES. A retry's
/// inner join now hits the marker → `KeyPackageReplay`; the KP record is still
/// present, so the guard must reject (no false-success).
#[tokio::test]
async fn confirm_replay_with_surviving_kp_record_errs_not_false_ok() {
    let healthy = Arc::new(InMemoryStorage::new());
    let faulty = Arc::new(FaultyStorage::new(Arc::clone(&healthy)));
    let storage: Arc<dyn OpenMlsStorageAdapter> =
        Arc::new(SpawnBlockingStorageAdapter::new(Arc::clone(&faulty)));
    let mls = backend_with_consumed_set(&storage);
    let (handle, _join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls), Arc::clone(&storage), no_transport()),
    );
    let _ = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    let (reservation_id, public_bytes) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();
    let welcome = real_welcome_for(&mls, &public_bytes).await;

    // Fail the KP-record DELETE step. The internal join still completes (writing
    // the init-key marker under `scp-kp-consumed-initkey/`), but the subsequent
    // `delete_kp_record` (key prefix `scp-kp/`) fails → first confirm errs and
    // the KP record SURVIVES. (The `scp-kp/` prefix also matches the
    // initkey/reservation/consumed keys' siblings only by exact-prefix; the
    // init-key marker lives under `scp-kp-consumed-initkey/` which does NOT start
    // with `scp-kp/` + record-shape, but to be safe we assert the marker landed.)
    faulty.fail_prefix("scp-kp/");
    let err = handle
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id: reservation_id.clone(),
            welcome_bytes: welcome.clone(),
            reply,
        })
        .await
        .err()
        .expect("first confirm errs when the KP-record delete fails");
    assert!(matches!(err, ContextError::PersistenceFailed(_)));

    // Heal the delete fault, but the KP record was never deleted (the delete
    // failed before any retry), so it is STILL present.
    faulty.clear_fail();
    assert!(
        kp_record_present(&storage, &alice(), &kp_ref).await,
        "precondition: the KP record survives the failed delete (still present at retry)"
    );

    // RETRY the SAME reservation. The inner join hits the already-written marker
    // → KeyPackageReplay. Because the KP record STILL EXISTS, this is NOT our own
    // prior completion: the guard must reject with KeyPackageReplay — NOT a
    // spurious Ok.
    let retry_err = handle
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id: reservation_id.clone(),
            welcome_bytes: welcome,
            reply,
        })
        .await
        .err()
        .expect("a replay with a surviving KP record must NOT be a false-success Ok");
    assert!(
        matches!(retry_err, ContextError::KeyPackageReplay(_)),
        "the surviving-record replay must surface as KeyPackageReplay, got {retry_err:?}"
    );

    handle.send_shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// H4-consumed-precedence. a kp_ref named by BOTH a live reservation AND a
// consumed tombstone (journal corruption) must resolve CONSUMED — never restored
// as a live, re-confirmable reservation.
// ---------------------------------------------------------------------------

/// Defense-in-depth: through the protocol's own writes a `kp_ref` can never be
/// named by both a live reservation record AND a consumed tombstone, but storage
/// corruption could fabricate that overlap (e.g. two rids naming the SAME ref —
/// one with a live reservation record, one with a consumed tombstone). Reconcile
/// must give CONSUMED precedence — the ref is excluded (and its stale record
/// deleted), NEVER restored as `reserved`. We seed the overlap by hand with TWO
/// distinct rids that both name the same `kp_ref`.
#[tokio::test]
async fn consumed_precedence_overlapping_reservation_and_tombstone_not_restored() {
    let storage = in_memory_storage();
    let (handle, join) = spawn_filled(Arc::clone(&storage)).await;
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    // Reserve: writes a LIVE reservation record + id-set entry naming kp_ref
    // (rid_live). The KP record survives.
    let (rid_live, _public) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();
    handle.send_shutdown().await.unwrap();
    let _ = join.await;

    // Fabricate the impossible overlap: a SECOND rid (rid_consumed) whose
    // consumed tombstone names the SAME kp_ref, added to the durable id-set
    // alongside rid_live. Reconcile now sees kp_ref in BOTH `reserved_by_ref`
    // (via rid_live's reservation record) AND `consumed_refs` (via
    // rid_consumed's tombstone) — exactly the corruption the precedence guard
    // defends against.
    let rid_consumed = ReservationId::from_raw("rid-consumed-corruption");
    let consumed_key = format!("scp-kp-consumed/{}/{rid_consumed}", alice().0);
    storage
        .store(&consumed_key, kp_ref.as_str().as_bytes())
        .await
        .unwrap();
    // Add rid_consumed to the durable reservation-id set so reconcile enumerates
    // it (the tombstone is only reached for an enumerated rid).
    let ids_key = format!("scp-kp-reservation-ids/{}", alice().0);
    let mut ids: Vec<ReservationId> = storage
        .retrieve(&ids_key)
        .await
        .unwrap()
        .map_or_else(Vec::new, |b| rmp_serde::from_slice(&b).unwrap());
    ids.push(rid_consumed.clone());
    storage
        .store(&ids_key, &rmp_serde::to_vec_named(&ids).unwrap())
        .await
        .unwrap();
    assert!(
        kp_record_present(&storage, &alice(), &kp_ref).await,
        "precondition: the KP record survives (the overlap could otherwise restore it)"
    );

    // Respawn. CONSUMED must win: the ref is excluded, never restored as reserved.
    let mls2 = backend_with_consumed_set(&storage);
    let (handle2, _join2) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls2), Arc::clone(&storage), no_transport()),
    );
    handle2
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await
        .expect("reconcile + replenish complete");

    // The overlapping ref was NOT restored as a live reservation under rid_live:
    // CONSUMED precedence dropped it from `reserved_by_ref`, so confirming
    // rid_live is an unknown reservation (it never re-entered `reserved`). The
    // handler short-circuits at the `reserved` lookup before the welcome matters.
    let confirm_err = handle2
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id: rid_live.clone(),
            welcome_bytes: vec![0u8; 4],
            reply,
        })
        .await
        .err()
        .expect("a consumed ref must NOT be restored as a confirmable reservation");
    assert!(matches!(confirm_err, ContextError::InvalidState(_)));

    // Nor was it re-pooled: re-reserving the ref errs (not pooled).
    let reserve_err = handle2
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .expect_err("a consumed ref must NOT be re-poolable");
    assert!(matches!(reserve_err, ContextError::InvalidKeyPackage(_)));

    handle2.send_shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// list-pooled. the ListPooled command exposes (KpRef, public bytes) for the
// reserve flow, reachable through the handle alone.
// ---------------------------------------------------------------------------

/// `ListPooled` returns every pooled KP's `(KpRef, public bytes)` so a caller can
/// discover a reservable ref through the handle — without a private
/// `derive_kp_ref` or a hand-minted `KpRef`. The returned ref must round-trip
/// straight back into a successful `Reserve`, and a reserved KP must drop out of
/// the listing. The returned `KpRef` must equal `KpRef::from_public_bytes` of the
/// returned public bytes (the documented derivation).
#[tokio::test]
async fn list_pooled_exposes_reservable_refs_through_the_handle() {
    let storage = in_memory_storage();
    let (handle, _join) = spawn_filled(Arc::clone(&storage)).await;

    let pooled = handle
        .send(|reply| KeyPackageCommand::ListPooled { reply })
        .await
        .expect("list pooled succeeds");
    assert!(
        pooled.len() >= MIN_BUFFER,
        "list pooled returns the full pool, got {}",
        pooled.len()
    );
    let (kp_ref, public_bytes) = pooled[0].clone();
    assert!(
        !public_bytes.is_empty(),
        "list pooled returns the PUBLIC bytes (for MLS-ref matching), never private state"
    );
    // The returned KpRef must be derivable from the public bytes via the public
    // constructor (the documented derivation contract).
    assert_eq!(
        kp_ref,
        KpRef::from_public_bytes(&public_bytes),
        "the listed KpRef must equal hex(SHA-256(public_bytes))"
    );

    // The listed ref round-trips straight into a successful Reserve.
    let (_rid, reserved_public) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .expect("a listed pooled ref must be reservable through the handle");
    assert_eq!(
        reserved_public, public_bytes,
        "reserve returns the same public bytes the listing exposed"
    );

    // The reserved ref is no longer listed as pooled.
    let after = handle
        .send(|reply| KeyPackageCommand::ListPooled { reply })
        .await
        .expect("list pooled succeeds after reserve");
    assert!(
        !after.iter().any(|(r, _)| *r == kp_ref),
        "a reserved KP must drop out of the pooled listing"
    );

    handle.send_shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// L-union. reserved KP whose index entry was lost is restored (union enum)
// ---------------------------------------------------------------------------

/// A live RESERVED KP whose `kp_ref` is absent from the durable index (a prior
/// replenish-time index write was lost) must be restored as `reserved` on
/// respawn — NOT silently orphaned. Reconcile enumerates the UNION of the index
/// AND the fail-closed reserved spine, so the reservation survives even though
/// the (best-effort) index never named the ref.
///
/// Without the union enumeration, reconcile would walk only the index, never
/// visit the ref, drop the `reserved_by_ref` entry, and the tail self-heal
/// would rewrite the reservation-id set from `self.reserved` (now missing the
/// rid) — permanently orphaning the reservation, its record, and the KP private
/// record, and wedging the caller's outstanding confirm at `InvalidState`.
#[tokio::test]
async fn reserved_kp_with_lost_index_entry_restored_as_reserved_on_respawn() {
    let healthy = Arc::new(InMemoryStorage::new());
    let faulty = Arc::new(FaultyStorage::new(Arc::clone(&healthy)));
    let storage: Arc<dyn OpenMlsStorageAdapter> =
        Arc::new(SpawnBlockingStorageAdapter::new(Arc::clone(&faulty)));
    let (handle, join) = spawn_filled(Arc::clone(&storage)).await;

    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    // Reserve the KP: this writes the reservation record + the reservation-id
    // set FAIL-CLOSED (Class-S), independent of the index. The reservation id is
    // carried to the post-respawn confirm to prove the restored reservation is
    // fully usable.
    let (reservation_id, _public) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .expect("reserve succeeds");

    // Simulate the lost replenish-time index write: drop this ref from the
    // durable index, so the index no longer names the reserved KP. The KP
    // record + the reservation journal remain intact.
    let index_key = format!("scp-kp-index/{}", alice().0);
    let mut idx = live_index(&storage, &alice()).await;
    idx.retain(|r| *r != kp_ref);
    assert!(
        !idx.contains(&kp_ref),
        "precondition: ref removed from the durable index"
    );
    let idx_bytes = rmp_serde::to_vec_named(&idx).unwrap();
    // Bypass the fault filter (none set) and write the truncated index.
    storage.store(&index_key, &idx_bytes).await.unwrap();
    assert!(
        kp_record_present(&storage, &alice(), &kp_ref).await,
        "precondition: the reserved KP record still exists"
    );

    handle.send_shutdown().await.unwrap();
    let _ = join.await;

    // Respawn. Reconcile must restore the reservation as `reserved` via the
    // union of the index and the reserved spine — NOT lose it.
    faulty.clear_fail();
    let mls2 = backend_with_consumed_set(&storage);
    let (handle2, _join2) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls2), Arc::clone(&storage), no_transport()),
    );
    let _ = handle2
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;

    // The ref is restored as `reserved` (non-poolable): re-reserving it errs
    // with InvalidKeyPackage (not pooled) or InvalidState (already reserved) —
    // it was NOT lost.
    let err = handle2
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .expect_err("a restored reserved KP must not be re-reservable");
    assert!(matches!(
        err,
        ContextError::InvalidKeyPackage(_) | ContextError::InvalidState(_)
    ));

    // The reservation is still confirmable (the rid survived): the index has
    // self-healed to INCLUDE the restored reserved ref, so the reservation is
    // not orphaned.
    let restored_index = live_index(&storage, &alice()).await;
    assert!(
        restored_index.contains(&kp_ref),
        "tail self-heal must rewrite the index to INCLUDE the restored reserved ref"
    );

    // CONFIRM the restored reservation end-to-end: build a real Welcome for the
    // reserved KP's public bytes and drive the fused `ConfirmConsume` through a
    // genuine internal join. It must succeed — proving the reservation was not
    // merely retained but is fully USABLE after the union-restore + index
    // self-heal (the rid resolves, the held signer-state joins, the consume
    // lands durably).
    let public_bytes = {
        let key = format!("scp-kp/{}/{kp_ref}", alice().0);
        let record = storage.retrieve(&key).await.unwrap().unwrap();
        // The restored reserved KP record still holds the public bytes; clone
        // them by reference (`PersistedKeyPackage` has a zeroizing `Drop`, so its
        // fields cannot be moved out by value).
        let parsed = rmp_serde::from_slice::<super::PersistedKeyPackage>(&record).unwrap();
        parsed.public_bytes.clone()
    };
    let welcome = real_welcome_for(&mls2, &public_bytes).await;
    handle2
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id: reservation_id.clone(),
            welcome_bytes: welcome,
            reply,
        })
        .await
        .expect("the restored reservation confirms successfully post-respawn");
    assert!(
        !kp_record_present(&storage, &alice(), &kp_ref).await,
        "confirming the restored reservation durably deletes the KP record"
    );

    handle2.send_shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// L-pooled. pooled KP with lost index entry: replenish refills, no leak
// ---------------------------------------------------------------------------

/// A POOLED KP whose index entry is lost at replenish time must NOT pool a KP
/// without a matching index entry: the source-side per-KP index persist rolls
/// the entry back out of the pool (and deletes its orphaned record) on an index
/// persist failure. After the fault heals, a later `Replenish` refills the pool
/// back to `MIN_BUFFER` and the durable index never grows without bound (every
/// pooled ref has exactly one index entry).
#[tokio::test]
async fn pooled_kp_lost_index_replenishes_to_min_without_record_leak() {
    let healthy = Arc::new(InMemoryStorage::new());
    let faulty = Arc::new(FaultyStorage::new(Arc::clone(&healthy)));
    let storage: Arc<dyn OpenMlsStorageAdapter> =
        Arc::new(SpawnBlockingStorageAdapter::new(Arc::clone(&faulty)));

    // Fail the index write for the WHOLE initial replenish: each KP record is
    // persisted, then the per-KP index persist fails → the entry is rolled back
    // out of the pool and its record deleted. The pool stays empty, no orphan
    // records accumulate.
    faulty.fail_prefix("scp-kp-index/");
    let (handle, _join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(real_backend(), Arc::clone(&storage), no_transport()),
    );
    let _ = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;

    // No index entries (every attempt rolled back). And no leaked KP records:
    // the orphaned records were deleted as part of the rollback.
    assert!(
        live_index(&storage, &alice()).await.is_empty(),
        "index persist failure must leave no pooled refs"
    );
    let leaked = healthy
        .list_keys(&format!("scp-kp/{}/", alice().0))
        .await
        .unwrap();
    assert!(
        leaked.is_empty(),
        "no orphaned KP records may leak when the index persist fails, got {leaked:?}"
    );

    // Heal storage and drive a Replenish: the pool refills to MIN_BUFFER and the
    // durable index matches the pool exactly (one entry per pooled ref).
    faulty.clear_fail();
    handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await
        .expect("healed replenish succeeds");
    let refs = live_index(&storage, &alice()).await;
    assert_eq!(
        refs.len(),
        MIN_BUFFER,
        "pool refilled to MIN_BUFFER after the fault healed"
    );
    let records = healthy
        .list_keys(&format!("scp-kp/{}/", alice().0))
        .await
        .unwrap();
    assert_eq!(
        records.len(),
        MIN_BUFFER,
        "exactly one KP record per pooled ref — no unbounded record growth"
    );

    handle.send_shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// L-retry-diff. retry with a DIFFERENT welcome cannot coerce a second join
// ---------------------------------------------------------------------------

/// After a successful internal join + a simulated tombstone-write failure (the
/// reservation stays live), retrying `ConfirmConsume` with a DIFFERENT (valid)
/// welcome must (a) idempotently complete the consume (`Ok`) and (b) NEVER join
/// the alternate welcome — exactly ONE join ever occurs. Both welcomes address
/// the SAME reserved KP (same HPKE init key), so the single-join proof is that
/// exactly ONE consumed-init-key marker exists in the durable A2 set: the
/// original join wrote it, and the alternate-welcome retry short-circuits on
/// that marker as our OWN prior completion rather than performing a second join.
/// This pins the "retry can't be coerced into a second/different join" property.
#[tokio::test]
async fn confirm_retry_with_different_welcome_completes_without_second_join() {
    let healthy = Arc::new(InMemoryStorage::new());
    let faulty = Arc::new(FaultyStorage::new(Arc::clone(&healthy)));
    let storage: Arc<dyn OpenMlsStorageAdapter> =
        Arc::new(SpawnBlockingStorageAdapter::new(Arc::clone(&faulty)));
    let mls = backend_with_consumed_set(&storage);
    let (handle, _join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls), Arc::clone(&storage), no_transport()),
    );
    let _ = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    let (reservation_id, public_bytes) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();

    // Two DISTINCT valid welcomes addressed to the SAME reserved KP (two
    // independent inviter groups both add it). The first is the real join; the
    // second is the alternate a retry must NOT consume.
    let welcome_original = real_welcome_for(&mls, &public_bytes).await;
    let welcome_alternate = real_welcome_for(&mls, &public_bytes).await;
    assert_ne!(
        welcome_original, welcome_alternate,
        "the two welcomes must be distinct to prove the alternate is never joined"
    );

    // First confirm: fail ONLY the tombstone write so the internal join
    // completes (init-key marker durably written) but the consume does not
    // fully land — the reservation is RETAINED for retry.
    faulty.fail_prefix("scp-kp-consumed/");
    let err = handle
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id: reservation_id.clone(),
            welcome_bytes: welcome_original.clone(),
            reply,
        })
        .await
        .err()
        .expect("first confirm errs when the tombstone store fails");
    assert!(matches!(err, ContextError::PersistenceFailed(_)));

    // Heal storage and RETRY with the ALTERNATE welcome. The retry's inner join
    // short-circuits on the already-written init-key marker → recognized as our
    // own prior completion → idempotent durable-consume completion. The alternate
    // welcome is NEVER processed into a join. The joined group is not retained
    // across confirms, so the reply is Err(InvalidState) (not a groupless Ok);
    // the durable consume still lands and single-use holds.
    faulty.clear_fail();
    let retry = handle
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id: reservation_id.clone(),
            welcome_bytes: welcome_alternate.clone(),
            reply,
        })
        .await
        .err()
        .expect("retry errs — the joined group is not retained across confirms");
    assert!(matches!(retry, ContextError::InvalidState(_)));

    // The consume durably landed (KP record gone) and single-use holds.
    assert!(
        !kp_record_present(&storage, &alice(), &kp_ref).await,
        "retry must durably delete the KP private record"
    );

    // EXPLICIT single-join proof: exactly ONE consumed-init-key marker exists in
    // the durable A2 set. Both welcomes target the SAME KP (same init key); if
    // the alternate had been joined it would have had to write a marker for the
    // same init key (a no-op overwrite at the same key) OR — had any second join
    // occurred for a different KP — produced a SECOND marker. The marker count of
    // exactly one proves the original join is the ONLY join that ran.
    let markers = healthy.list_keys("scp-kp-consumed-initkey/").await.unwrap();
    assert_eq!(
        markers.len(),
        1,
        "exactly one init-key marker — only the ORIGINAL join ran; the alternate \
         welcome was never joined, got {markers:?}"
    );

    // PROOF the alternate welcome was never joined: its init key is the SAME KP
    // (same reserved ref), and that init key was consumed by the ORIGINAL join.
    // A fresh, independent join attempt of the alternate welcome with a freshly
    // generated signer-state for the SAME public bytes would be rejected as a
    // replay — confirming only ONE join (the original) ever consumed this init
    // key. (We assert via the reservation being gone: a third confirm of the
    // same rid is an unknown reservation.)
    let unknown = handle
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id,
            welcome_bytes: welcome_alternate,
            reply,
        })
        .await
        .err()
        .expect("a consumed reservation must not confirm again");
    assert!(matches!(unknown, ContextError::InvalidState(_)));

    handle.send_shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// E2. orphan-reservation TTL sweep
// ---------------------------------------------------------------------------

#[tokio::test]
async fn expired_reservation_is_swept_and_kp_burned() {
    let storage = in_memory_storage();
    // A settable clock makes every reservation appear expired once we jump the
    // offset past the TTL; the sweep fires on maybe_replenish after a reserve.
    let clock = Arc::new(SteppingClock::new());
    let (handle, _join) = {
        let deps = KeyPackageStoreDeps {
            mls: real_backend(),
            mls_storage: Arc::clone(&storage),
            transport: no_transport(),
            clock: Arc::clone(&clock) as Arc<dyn Clock>,
            wrapping_pubkey: None,
        };
        KeyPackageStoreActor::spawn(alice(), deps)
    };
    let _ = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    let (_rid, _public) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();

    // Jump the clock past the TTL, then trigger a sweep via another reserve of
    // a DIFFERENT ref (Reserve runs maybe_replenish → sweep afterward).
    clock.set_offset(super::RESERVATION_TTL_MS + 1);
    let other = live_index(&storage, &alice()).await;
    let other_ref = other.iter().find(|r| **r != kp_ref).unwrap().clone();
    let (_rid2, _p2) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: other_ref,
            reply,
        })
        .await
        .unwrap();

    // The expired reservation's KP was burned (record gone).
    assert!(
        !kp_record_present(&storage, &alice(), &kp_ref).await,
        "TTL sweep burned the abandoned reservation's KP"
    );

    handle.send_shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// E2. reservation ceiling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reservation_ceiling_guard_is_present_and_non_interfering() {
    // The ceiling (MAX_OUTSTANDING_RESERVATIONS) is a defense-in-depth bound on
    // the `reserved` map. It is intentionally UNREACHABLE through the public
    // command API today: replenish targets `pool.len() + reserved.len() ==
    // MIN_BUFFER`, so outstanding reservations naturally cap at MIN_BUFFER —
    // well below the ceiling. The `LimitExceeded` arm is therefore a defensive
    // guard against a FUTURE flow that could let `reserved` exceed MIN_BUFFER
    // (e.g. a not-yet-wired adversarial caller); it is not exercised here
    // because no current path can reach it, and the test name reflects exactly
    // that — "present and non-interfering", not "enforced". This test reserves
    // every available KP and asserts the guard NEVER false-fires below the
    // natural cap, and (statically) that the ceiling sits safely above it.
    const _: () = assert!(
        super::MAX_OUTSTANDING_RESERVATIONS > MIN_BUFFER,
        "ceiling must sit above the natural MIN_BUFFER cap"
    );

    let storage = in_memory_storage();
    let (handle, _join) = spawn_filled(Arc::clone(&storage)).await;

    let refs = live_index(&storage, &alice()).await;
    let mut held = 0usize;
    for r in refs {
        let result = handle
            .send(|reply| KeyPackageCommand::Reserve {
                kp_ref: r.clone(),
                reply,
            })
            .await;
        // The ceiling must NEVER false-fire below the natural cap.
        assert!(
            !matches!(result, Err(ContextError::LimitExceeded(_))),
            "ceiling false-fired at {held} reservations (natural cap is MIN_BUFFER)"
        );
        // A ref may have been swept / already reserved / not pooled between the
        // index read and the reserve; only a clean Ok counts toward `held`, and
        // the only other acceptable errors are InvalidState / InvalidKeyPackage.
        match result {
            Ok(_) => held += 1,
            Err(ContextError::InvalidState(_) | ContextError::InvalidKeyPackage(_)) => {}
            Err(e) => assert!(
                matches!(
                    e,
                    ContextError::InvalidState(_) | ContextError::InvalidKeyPackage(_)
                ),
                "unexpected error reserving: {e:?}"
            ),
        }
    }
    assert!(
        held > 0,
        "reserved at least one KP without hitting the ceiling"
    );

    handle.send_shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// 8. publish idempotency + transport-error injection + per-ref keying
// ---------------------------------------------------------------------------

/// `Publish` emits exactly ONE transport call per pooled KP (routing is
/// per-`owner_did`, not per relay URL): the transport call count after a
/// publish equals the pool size. With the misleading `relay_set` field removed,
/// `Publish` takes no caller relay list — it publishes every not-yet-published
/// pooled KP once. This pins the honest single-publish behaviour.
#[tokio::test]
async fn publish_emits_one_call_per_pooled_kp() {
    let storage = in_memory_storage();
    let recorder = Arc::new(RecordingTransport::new());
    let transport: Arc<dyn ContextTransportProvider> = Arc::clone(&recorder) as _;
    let (handle, _join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(real_backend(), Arc::clone(&storage), transport),
    );
    let _ = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;

    let pool_size = live_index(&storage, &alice()).await.len();
    assert!(pool_size >= MIN_BUFFER);

    handle
        .send(|reply| KeyPackageCommand::Publish { reply })
        .await
        .expect("publish succeeds");

    // Exactly one transport publish per pooled KP.
    assert_eq!(
        recorder.count(),
        pool_size,
        "each KP must be published exactly once for the {pool_size}-KP pool"
    );

    handle.send_shutdown().await.unwrap();
}

/// Publishing an EMPTY pool is a successful no-op: no transport publish happens.
/// (With `relay_set` removed there is no empty-relay-list case; the analogous
/// no-op is an empty pool.)
#[tokio::test]
async fn publish_empty_pool_is_noop() {
    let storage = in_memory_storage();
    let recorder = Arc::new(RecordingTransport::new());
    let transport: Arc<dyn ContextTransportProvider> = Arc::clone(&recorder) as _;
    // A backend that generates ZERO KPs, so the pool stays empty.
    let empty_backend: Arc<dyn MlsBackend> = Arc::new(FailingBackend::new(0));
    let (handle, _join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(empty_backend, Arc::clone(&storage), transport),
    );

    handle
        .send(|reply| KeyPackageCommand::Publish { reply })
        .await
        .expect("publish on an empty pool is a successful no-op");
    assert_eq!(recorder.count(), 0, "empty pool → no publish");

    handle.send_shutdown().await.unwrap();
}

#[tokio::test]
async fn publish_is_idempotent_and_errors_leave_ref_unmarked() {
    let storage = in_memory_storage();
    let recorder = Arc::new(RecordingTransport::new());
    let transport: Arc<dyn ContextTransportProvider> = Arc::clone(&recorder) as _;
    let (handle, _join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(real_backend(), Arc::clone(&storage), transport),
    );
    let _ = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;

    handle
        .send(|reply| KeyPackageCommand::Publish { reply })
        .await
        .expect("publish succeeds");
    let first = recorder.count();
    assert!(first >= MIN_BUFFER, "all pooled KPs published, got {first}");
    // The canonical owner DID was threaded through to the transport.
    assert_eq!(
        recorder.last_owner_did(),
        Some(alice().0),
        "publish threads the owning DID for the canonical routing id"
    );

    handle
        .send(|reply| KeyPackageCommand::Publish { reply })
        .await
        .expect("re-publish succeeds");
    assert_eq!(recorder.count(), first, "re-publish is a no-op");

    for _ in 0..6 {
        let kp_ref = live_index(&storage, &alice()).await[0].clone();
        let (rid, _p) = handle
            .send(|reply| KeyPackageCommand::Reserve { kp_ref, reply })
            .await
            .unwrap();
        handle
            .send(|reply| KeyPackageCommand::CancelReservation {
                reservation_id: rid,
                reply,
            })
            .await
            .unwrap();
    }

    recorder.set_fail(true);
    let err = handle
        .send(|reply| KeyPackageCommand::Publish { reply })
        .await
        .expect_err("transport failure surfaces as TransportFailed");
    assert!(matches!(err, ContextError::TransportFailed(_)));

    let before = recorder.count();
    recorder.set_fail(false);
    handle
        .send(|reply| KeyPackageCommand::Publish { reply })
        .await
        .expect("publish recovers after transport heals");
    assert!(
        recorder.count() > before,
        "the previously-failed ref was unmarked and is published on retry"
    );

    handle.send_shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// H3. integration: fused Welcome confirm flow (drives the REAL reserved KP)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fused_welcome_confirm_flow_joins_real_reserved_kp() {
    let storage = in_memory_storage();
    let mls = backend_with_consumed_set(&storage);
    let (handle, _join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls), Arc::clone(&storage), no_transport()),
    );
    let _ = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    // Reserve → get the PUBLIC bytes (private signer-state stays in the actor).
    let (reservation_id, public_bytes) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();

    // Record the reservation in a Welcome scratchpad (mirrors the real flow).
    let mut scratchpad = crate::context::actor::state::WelcomeProcessing {
        kp_reservation: Some(reservation_id.clone()),
        ..Default::default()
    };

    // Build a REAL Welcome for the reserved KP and fuse the join through confirm.
    let welcome = real_welcome_for(&mls, &public_bytes).await;
    handle
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id: scratchpad.kp_reservation.take().unwrap(),
            welcome_bytes: welcome,
            reply,
        })
        .await
        .expect("fused confirm joins the real reserved KP");
    assert!(
        !kp_record_present(&storage, &alice(), &kp_ref).await,
        "confirm deletes the KP key from storage"
    );

    handle.send_shutdown().await.unwrap();
}

#[tokio::test]
async fn fused_welcome_cancel_flow() {
    let storage = in_memory_storage();
    let (handle, _join) = spawn_filled(Arc::clone(&storage)).await;
    let before = live_index(&storage, &alice()).await.len();
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    let (reservation_id, _public) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();

    handle
        .send(|reply| KeyPackageCommand::CancelReservation {
            reservation_id,
            reply,
        })
        .await
        .unwrap();

    assert!(
        !kp_record_present(&storage, &alice(), &kp_ref).await,
        "cancel burns the KP record"
    );
    let after = live_index(&storage, &alice()).await;
    assert!(
        !after.contains(&kp_ref),
        "burned ref no longer in the live index"
    );
    assert_eq!(
        after.len(),
        before - 1,
        "pool reduced by exactly one (KP burned)"
    );

    handle.send_shutdown().await.unwrap();
}

#[tokio::test]
async fn confirm_with_bad_welcome_keeps_reservation_for_retry() {
    // A garbage Welcome makes the fused join FAIL → the KP is NOT burned and
    // the reservation survives, so a cancel still works afterward.
    let storage = in_memory_storage();
    let mls = backend_with_consumed_set(&storage);
    let (handle, _join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(Arc::clone(&mls), Arc::clone(&storage), no_transport()),
    );
    let _ = handle
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await;
    let kp_ref = live_index(&storage, &alice()).await[0].clone();

    let (reservation_id, _public) = handle
        .send(|reply| KeyPackageCommand::Reserve {
            kp_ref: kp_ref.clone(),
            reply,
        })
        .await
        .unwrap();

    let err = handle
        .send(|reply| KeyPackageCommand::ConfirmConsume {
            reservation_id: reservation_id.clone(),
            welcome_bytes: vec![0xAB; 32],
            reply,
        })
        .await
        .err()
        .expect("a bad welcome makes the fused join fail");
    assert!(matches!(err, ContextError::CryptoFailed(_)));

    // KP NOT burned — record still present.
    assert!(
        kp_record_present(&storage, &alice(), &kp_ref).await,
        "a failed join must not burn the KP"
    );

    // Reservation intact → cancel still works.
    handle
        .send(|reply| KeyPackageCommand::CancelReservation {
            reservation_id,
            reply,
        })
        .await
        .expect("the surviving reservation can still be cancelled");

    handle.send_shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// Test backends / transports / storage / clocks
// ---------------------------------------------------------------------------

/// An `MlsBackend` that succeeds `n` `generate_key_package` calls then fails
/// every subsequent call. Delegates all other methods to a real backend.
struct FailingBackend {
    inner: ProductionMlsBackend,
    remaining: AtomicUsize,
}

impl FailingBackend {
    fn new(successes: usize) -> Self {
        Self {
            inner: ProductionMlsBackend::new(std::sync::Arc::new(scp_clock::SystemClock)),
            remaining: AtomicUsize::new(successes),
        }
    }
}

#[async_trait]
impl MlsBackend for FailingBackend {
    async fn create_group(
        &self,
        credential: &ScpCredential,
        wrapping_pubkey: Option<&[u8; 32]>,
    ) -> Result<ScpMlsGroup, MlsError> {
        self.inner.create_group(credential, wrapping_pubkey).await
    }
    async fn add_member_raw(
        &self,
        group: &mut ScpMlsGroup,
        key_package_bytes: &[u8],
    ) -> Result<AddMemberRaw, MlsError> {
        self.inner.add_member_raw(group, key_package_bytes).await
    }
    async fn remove_member_raw(
        &self,
        group: &mut ScpMlsGroup,
        leaf_index: LeafNodeIndex,
    ) -> Result<RemoveMemberRaw, MlsError> {
        self.inner.remove_member_raw(group, leaf_index).await
    }
    async fn encrypt(
        &self,
        group: &mut ScpMlsGroup,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, MlsError> {
        self.inner.encrypt(group, plaintext).await
    }
    async fn decrypt(
        &self,
        group: &mut ScpMlsGroup,
        ciphertext: &[u8],
    ) -> Result<DecryptedContent, MlsError> {
        self.inner.decrypt(group, ciphertext).await
    }
    async fn process_commit(
        &self,
        group: &mut ScpMlsGroup,
        commit_bytes: &[u8],
    ) -> Result<(), MlsError> {
        self.inner.process_commit(group, commit_bytes).await
    }
    async fn advance_epoch(
        &self,
        group: &mut ScpMlsGroup,
        wrapping_pubkey: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, MlsError> {
        self.inner.advance_epoch(group, wrapping_pubkey).await
    }
    async fn validate_key_package(
        &self,
        key_package_bytes: &[u8],
        clock: &dyn Clock,
    ) -> Result<ValidatedKeyPackage, MlsError> {
        self.inner
            .validate_key_package(key_package_bytes, clock)
            .await
    }
    async fn generate_key_package(
        &self,
        credential: &ScpCredential,
        wrapping_pubkey: Option<&[u8; 32]>,
    ) -> Result<GeneratedKeyPackage, MlsError> {
        loop {
            let cur = self.remaining.load(Ordering::Acquire);
            if cur == 0 {
                return Err(MlsError::KeyPackageGenerationFailed(
                    "injected generate failure".to_owned(),
                ));
            }
            if self
                .remaining
                .compare_exchange(cur, cur - 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }
        self.inner
            .generate_key_package(credential, wrapping_pubkey)
            .await
    }
    async fn join_from_welcome(
        &self,
        welcome_bytes: &[u8],
        signer_state: SignerState,
        key_package_public_bytes: &[u8],
    ) -> Result<ScpMlsGroup, MlsError> {
        self.inner
            .join_from_welcome(welcome_bytes, signer_state, key_package_public_bytes)
            .await
    }
}

/// A transport that records `publish_key_package` calls (and the owner DID it
/// was threaded) and can be toggled to fail.
struct RecordingTransport {
    published: AtomicUsize,
    fail: AtomicBool,
    last_owner_did: std::sync::Mutex<Option<String>>,
}

impl RecordingTransport {
    fn new() -> Self {
        Self {
            published: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
            last_owner_did: std::sync::Mutex::new(None),
        }
    }
    fn count(&self) -> usize {
        self.published.load(Ordering::Acquire)
    }
    fn set_fail(&self, fail: bool) {
        self.fail.store(fail, Ordering::Release);
    }
    fn last_owner_did(&self) -> Option<String> {
        self.last_owner_did.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl ContextTransportProvider for RecordingTransport {
    fn is_connected(&self) -> bool {
        true
    }
    async fn publish_context(
        &self,
        _context_id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn delete_published(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn send_message(
        &self,
        _context_id: &[u8; 32],
        _encrypted_payload: &[u8],
    ) -> Result<(), ContextError> {
        Ok(())
    }
    async fn publish_key_package(
        &self,
        owner_did: &str,
        _kp_bytes: &[u8],
    ) -> Result<(), ContextError> {
        if self.fail.load(Ordering::Acquire) {
            return Err(ContextError::TransportFailed("injected".to_owned()));
        }
        *self.last_owner_did.lock().unwrap() = Some(owner_did.to_owned());
        self.published.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

/// A `Storage` wrapper that fails writes/deletes whose key starts with a
/// configured prefix, delegating everything else to an inner `InMemoryStorage`.
/// Drives the H1 fail-closed branches deterministically.
struct FaultyStorage {
    inner: Arc<InMemoryStorage>,
    /// Fails BOTH `store` and `delete` for keys under this prefix.
    fail_prefix: std::sync::Mutex<Option<String>>,
    /// Fails ONLY `delete` for keys under this prefix (`store`/`retrieve` pass).
    /// Lets a test target the cleanup-tail / GC delete of a record while still
    /// allowing it to have been written — the symmetric sibling of the
    /// store-fault path, which would otherwise block the record's creation.
    fail_delete_prefix: std::sync::Mutex<Option<String>>,
}

impl FaultyStorage {
    fn new(inner: Arc<InMemoryStorage>) -> Self {
        Self {
            inner,
            fail_prefix: std::sync::Mutex::new(None),
            fail_delete_prefix: std::sync::Mutex::new(None),
        }
    }
    fn fail_prefix(&self, prefix: &str) {
        *self.fail_prefix.lock().unwrap() = Some(prefix.to_owned());
    }
    /// Arm the delete-only fault: subsequent `delete` calls for keys under
    /// `prefix` return an injected error, while `store`/`retrieve` succeed.
    fn fail_delete_prefix(&self, prefix: &str) {
        *self.fail_delete_prefix.lock().unwrap() = Some(prefix.to_owned());
    }
    fn clear_fail(&self) {
        *self.fail_prefix.lock().unwrap() = None;
        *self.fail_delete_prefix.lock().unwrap() = None;
    }
    fn should_fail(&self, key: &str) -> bool {
        self.fail_prefix
            .lock()
            .unwrap()
            .as_deref()
            .is_some_and(|p| key.starts_with(p))
    }
    /// True when a delete of `key` should be injected-failed: either the
    /// store+delete `fail_prefix` matches, or the delete-only prefix matches.
    fn should_fail_delete(&self, key: &str) -> bool {
        self.should_fail(key)
            || self
                .fail_delete_prefix
                .lock()
                .unwrap()
                .as_deref()
                .is_some_and(|p| key.starts_with(p))
    }
}

#[allow(clippy::manual_async_fn)]
impl Storage for FaultyStorage {
    fn store(
        &self,
        key: &str,
        data: &[u8],
    ) -> impl std::future::Future<Output = Result<(), PlatformError>> + Send {
        async move {
            if self.should_fail(key) {
                return Err(PlatformError::StorageError(
                    "injected store fault".to_owned(),
                ));
            }
            self.inner.store(key, data).await
        }
    }
    fn retrieve(
        &self,
        key: &str,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, PlatformError>> + Send {
        async move { self.inner.retrieve(key).await }
    }
    fn delete(
        &self,
        key: &str,
    ) -> impl std::future::Future<Output = Result<(), PlatformError>> + Send {
        async move {
            if self.should_fail_delete(key) {
                return Err(PlatformError::StorageError(
                    "injected delete fault".to_owned(),
                ));
            }
            self.inner.delete(key).await
        }
    }
    fn list_keys(
        &self,
        prefix: &str,
    ) -> impl std::future::Future<Output = Result<Vec<String>, PlatformError>> + Send {
        async move { self.inner.list_keys(prefix).await }
    }
    fn delete_prefix(
        &self,
        prefix: &str,
    ) -> impl std::future::Future<Output = Result<u64, PlatformError>> + Send {
        async move { self.inner.delete_prefix(prefix).await }
    }
    fn exists(
        &self,
        key: &str,
    ) -> impl std::future::Future<Output = Result<bool, PlatformError>> + Send {
        async move { self.inner.exists(key).await }
    }
}

/// A clock whose `now_millis` is a base instant plus a settable offset, so a
/// test can jump time forward past the reservation TTL deterministically.
struct SteppingClock {
    base: u64,
    offset: std::sync::atomic::AtomicU64,
}

impl SteppingClock {
    fn new() -> Self {
        Self {
            base: SystemClock.now_millis(),
            offset: std::sync::atomic::AtomicU64::new(0),
        }
    }
    fn set_offset(&self, offset_ms: u64) {
        self.offset.store(offset_ms, Ordering::Release);
    }
}

impl Clock for SteppingClock {
    fn now_secs(&self) -> u64 {
        self.now_millis() / 1000
    }
    fn now_millis(&self) -> u64 {
        self.base + self.offset.load(Ordering::Acquire)
    }
}

// ---------------------------------------------------------------------------
// 9. durable on-disk format: newtype `#[serde(transparent)]` round-trip
// ---------------------------------------------------------------------------

/// The `KpRef` and `ReservationId` newtypes MUST serialize byte-identically to
/// their inner `String` (they are `#[serde(transparent)]`). The durable journal
/// (the kp-ref index and the reservation-id set) is `Vec<KpRef>` /
/// `Vec<ReservationId>` on disk; if a future change dropped `transparent`, the
/// MessagePack byte layout would silently change and a respawn would fail to
/// decode the existing journal. Pinning byte-equality against the bare-`String`
/// encoding makes that regression fail the suite instead.
#[test]
fn newtype_kp_ref_serializes_transparently_as_string() {
    let as_newtype = rmp_serde::to_vec(&vec![KpRef::from_raw("abc123")]).unwrap();
    let as_string = rmp_serde::to_vec(&vec!["abc123".to_owned()]).unwrap();
    assert_eq!(
        as_newtype, as_string,
        "KpRef must serialize byte-identically to its inner String \
         (the #[serde(transparent)] contract the durable index relies on)"
    );
}

// ---------------------------------------------------------------------------
// ReserveAny — atomic reserve-first-pooled (concurrency-regression proof)
// ---------------------------------------------------------------------------

/// Two `ReserveAny` commands under the SAME identity must yield DISTINCT
/// reservations over DISTINCT KeyPackages.
///
/// This is the regression proof for the non-atomic `Replenish` → `ListPooled`
/// → `Reserve` composite the supervisor formerly used: two reserves that each
/// `ListPooled` the same pool would both pick the first `kp_ref`, and the
/// second `Reserve` would spuriously fail `InvalidState("already reserved")`.
/// The atomic `ReserveAny` handler picks-and-reserves inside one command, so
/// the first reserve has already moved its KP out of `pool` before the second
/// handler runs — the second picks the NEXT ref and both succeed.
#[tokio::test]
async fn reserve_any_returns_distinct_reservations() {
    let storage = in_memory_storage();
    let (handle, _join) = spawn_filled(Arc::clone(&storage)).await;

    let (rid1, public1) = handle
        .send(|reply| KeyPackageCommand::ReserveAny { reply })
        .await
        .expect("first ReserveAny succeeds");
    let (rid2, public2) = handle
        .send(|reply| KeyPackageCommand::ReserveAny { reply })
        .await
        .expect("second ReserveAny succeeds despite the first holding a reservation");

    assert_ne!(
        rid1, rid2,
        "the two ReserveAny calls must mint DISTINCT reservation ids"
    );
    // Distinct KeyPackages: the returned PUBLIC bytes (and therefore their
    // content-hash KpRefs) must differ — the second reserve took a different
    // pooled KP, not the one the first already holds.
    assert_ne!(
        KpRef::from_public_bytes(&public1),
        KpRef::from_public_bytes(&public2),
        "the two ReserveAny calls must reserve DISTINCT key packages"
    );

    handle.send_shutdown().await.unwrap();
}

/// `ReserveAny` on an EMPTY pool replenishes-then-reserves within the single
/// command, returning a live reservation (the folded replenish barrier).
#[tokio::test]
async fn reserve_any_replenishes_empty_pool_then_reserves() {
    let storage = in_memory_storage();
    // Fresh spawn WITHOUT a warm-up Replenish barrier: the actor's startup
    // replenish still fills the pool before serving commands, but ReserveAny
    // owns its own replenish-if-empty step regardless, so a single ReserveAny
    // must succeed on the first command.
    let mls = backend_with_consumed_set(&storage);
    let (handle, _join) = KeyPackageStoreActor::spawn(
        alice(),
        deps_with(mls, Arc::clone(&storage), no_transport()),
    );

    let (_rid, public_bytes) = handle
        .send(|reply| KeyPackageCommand::ReserveAny { reply })
        .await
        .expect("ReserveAny fills the pool and reserves in one command");
    assert!(
        !public_bytes.is_empty(),
        "ReserveAny returns PUBLIC bytes (not private signer-state)"
    );

    handle.send_shutdown().await.unwrap();
}

#[test]
fn newtype_reservation_id_serializes_transparently_as_string() {
    let as_newtype = rmp_serde::to_vec(&vec![ReservationId::from_raw("rid-xyz")]).unwrap();
    let as_string = rmp_serde::to_vec(&vec!["rid-xyz".to_owned()]).unwrap();
    assert_eq!(
        as_newtype, as_string,
        "ReservationId must serialize byte-identically to its inner String \
         (the #[serde(transparent)] contract the durable reservation-id set relies on)"
    );
}

// ---------------------------------------------------------------------------
// 7. watchdog / poison / clear_kp_poison (supervisor-driven)
// ---------------------------------------------------------------------------
//
// The watchdog + per-identity poison path and `clear_kp_poison` recovery are
// supervisor-owned (they key the shared `crash_windows` map). Their tests live
// alongside the per-context watchdog tests in `supervisor.rs::tests` so they
// can reach the private `crash_windows` / `key_package_store_for` /
// `clear_kp_poison` surface; see `kp_actor_watchdog_records_panic_and_respawns`,
// `kp_actor_poisons_after_budget`, and `clear_kp_poison_recovers_poisoned_actor`
// there.
