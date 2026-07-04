//! Snapshot / restore of participant state through the injected `Storage`
//! backend (ADR-057 T2).
//!
//! Proves the read path that closes the T2 gap: after a two-party exchange, a
//! *fresh* client built over the SAME storage backend (as a browser tab would
//! reconstruct itself against its `IndexedDB` on reopen) restores its contexts
//! and pending joins from durable storage **in its constructor** and resumes
//! participating — decrypting a message sent after the restore and sending one
//! the peer decrypts. It also covers the fail-closed contract: a corrupt,
//! truncated, foreign-owned, or unreadable snapshot fails the whole construction,
//! and forward secrecy (close deletes the durable state).

// Integration tests assert on happy-path results; `expect`/`panic!` make the
// failure messages legible. The workspace denies these in production code.
#![allow(clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use scp_client::{ClientError, LocalSigner, MemoryStorage, ScpClient, Storage};
use scp_clock::{Clock, TestClock};
use scp_protocol::context::membership::ContextEvent;

const CTX: &str = "ctx-adr057-t2-snapshot-restore";
const ALICE_DID: &str = "did:key:z6MkAliceT2SnapshotRestoreFixtureAAAAAAAAA";
const BOB_DID: &str = "did:key:z6MkBobT2SnapshotRestoreFixtureBBBBBBBBBBBBB";

/// Builds a client for `did` over the given (shared) storage and a fixed clock,
/// restoring whatever the storage holds for that identity (the constructor is the
/// restore path).
fn client_over(did: &str, storage: Arc<dyn Storage>, now_secs: u64) -> ScpClient {
    let signer = Arc::new(LocalSigner::active(did));
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(now_secs));
    ScpClient::new(signer, storage, clock).expect("construct/restore client")
}

/// Drives Alice (creator) and Bob (joiner) through create / add / join / key
/// exchange so both hold a converged two-member context with no messages yet.
/// Returns the two clients (Bob built over the caller's shared storage).
fn converged_pair(bob_storage: Arc<dyn Storage>) -> (ScpClient, ScpClient) {
    let alice_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let mut alice = client_over(ALICE_DID, alice_storage, 1_700_000_000);
    let mut bob = client_over(BOB_DID, bob_storage, 1_650_000_000);

    alice.create_context(CTX).expect("alice creates");
    let bob_kp = bob
        .generate_key_package_for_join(CTX)
        .expect("bob key package");
    let add = alice.add_member(CTX, &bob_kp).expect("alice adds bob");
    bob.join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.members)
        .expect("bob joins");

    // Out-of-band sender-key exchange (the ADR-057 MISSING SEAM).
    let alice_sk = alice.local_sender_key_bytes(CTX).expect("alice sk");
    let bob_sk = bob.local_sender_key_bytes(CTX).expect("bob sk");
    bob.install_sender_key(CTX, ALICE_DID, alice_sk)
        .expect("bob installs alice sk");
    alice
        .install_sender_key(CTX, BOB_DID, bob_sk)
        .expect("alice installs bob sk");

    (alice, bob)
}

#[test]
fn restore_resumes_a_converged_context_from_storage() {
    let bob_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let (mut alice, mut bob) = converged_pair(Arc::clone(&bob_storage));

    // Alice sends; Bob receives (mutating + persisting Bob's snapshot) but does
    // NOT drain — the buffered plaintext must survive the restore.
    let pre = alice
        .send_message(CTX, b"before restore")
        .expect("alice sends");
    let was_app = bob
        .receive_message(CTX, &pre.ciphertext, pre.committer_timestamp_secs)
        .expect("bob receives");
    assert!(was_app);

    let expected_root = bob.event_log_root(CTX).expect("bob root");
    let expected_leaves = bob.event_log_leaf_count(CTX).expect("bob leaves");
    let expected_epoch = bob.mls_epoch(CTX).expect("bob epoch");
    let expected_members = {
        let mut m = bob.member_dids(CTX).expect("bob members");
        m.sort();
        m
    };
    drop(bob); // The tab closes; only the durable storage survives.

    // A fresh client (the reopened tab) over Bob's identity + the SAME storage.
    // The constructor restores the converged context.
    let mut bob2 = client_over(BOB_DID, Arc::clone(&bob_storage), 1_650_000_099);

    // Restored state matches what Bob held before the tab closed.
    let mut members = bob2.member_dids(CTX).expect("restored members");
    members.sort();
    assert_eq!(members, expected_members);
    assert_eq!(
        bob2.event_log_root(CTX),
        Some(expected_root),
        "restored event-log root matches"
    );
    assert_eq!(bob2.event_log_leaf_count(CTX), Some(expected_leaves));
    assert_eq!(bob2.mls_epoch(CTX).expect("restored epoch"), expected_epoch);

    // The undrained buffered message survived the round-trip and is delivered
    // exactly once.
    let buffered = bob2.drain_events(CTX).expect("bob2 drains buffered");
    assert_eq!(
        buffered.len(),
        1,
        "the pre-restore buffered message survives"
    );
    match &buffered[0] {
        ContextEvent::MessageReceived {
            sender_did,
            payload,
        } => {
            assert_eq!(sender_did.0, ALICE_DID);
            assert_eq!(payload.as_slice(), b"before restore");
        }
        other => panic!("expected the buffered MessageReceived, got {other:?}"),
    }
    assert!(
        bob2.drain_events(CTX).expect("second drain").is_empty(),
        "the buffered message is delivered exactly once"
    );

    // Replaying the PRE-restore ciphertext must still be rejected — the MLS
    // ratchet that already consumed it is persisted and advanced.
    assert!(
        bob2.receive_message(CTX, &pre.ciphertext, pre.committer_timestamp_secs)
            .is_err(),
        "a pre-restore ciphertext replay is rejected after restore"
    );

    // The restored client can DECRYPT a message Alice sends after the restore.
    let send2 = alice
        .send_message(CTX, b"after restore")
        .expect("alice sends 2");
    let was_app = bob2
        .receive_message(CTX, &send2.ciphertext, send2.committer_timestamp_secs)
        .expect("bob2 receives");
    assert!(was_app);
    let events = bob2.drain_events(CTX).expect("bob2 drains");
    assert_eq!(events.len(), 1);
    match &events[0] {
        ContextEvent::MessageReceived {
            sender_did,
            payload,
        } => {
            assert_eq!(sender_did.0, ALICE_DID);
            assert_eq!(payload.as_slice(), b"after restore");
        }
        other => panic!("expected MessageReceived, got {other:?}"),
    }

    // And it can SEND a message Alice decrypts — proving the send-side crypto and
    // the restored per-member sequence counters work.
    let send3 = bob2
        .send_message(CTX, b"from restored bob")
        .expect("bob2 sends");
    let was_app = alice
        .receive_message(CTX, &send3.ciphertext, send3.committer_timestamp_secs)
        .expect("alice receives from restored bob");
    assert!(was_app);
    let alice_events = alice.drain_events(CTX).expect("alice drains");
    assert_eq!(alice_events.len(), 1);
    match &alice_events[0] {
        ContextEvent::MessageReceived {
            sender_did,
            payload,
        } => {
            assert_eq!(sender_did.0, BOB_DID);
            assert_eq!(payload.as_slice(), b"from restored bob");
        }
        other => panic!("expected MessageReceived, got {other:?}"),
    }
}

#[test]
fn pending_join_completes_after_restore() {
    // Bob generates a key package (persisting the private pending material) and
    // the tab closes BEFORE joining. A reopened tab restores the pending material
    // and completes the join.
    let bob_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let alice_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let mut alice = client_over(ALICE_DID, alice_storage, 1_700_000_000);
    alice.create_context(CTX).expect("alice creates");

    let bob_kp = {
        let mut bob = client_over(BOB_DID, Arc::clone(&bob_storage), 1_650_000_000);
        let kp = bob
            .generate_key_package_for_join(CTX)
            .expect("bob key package");
        drop(bob); // tab closes before joining
        kp
    };

    // Alice adds Bob from the published key package.
    let add = alice.add_member(CTX, &bob_kp).expect("alice adds bob");

    // The reopened tab restores the pending material and joins with it.
    let mut bob2 = client_over(BOB_DID, Arc::clone(&bob_storage), 1_650_000_050);
    bob2.join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.members)
        .expect("restored bob completes the join");

    let mut members = bob2.member_dids(CTX).expect("members");
    members.sort();
    assert_eq!(members, vec![ALICE_DID.to_owned(), BOB_DID.to_owned()]);
    assert_eq!(
        bob2.event_log_root(CTX),
        alice.event_log_root(CTX),
        "joiner converged to the adder's root"
    );
}

#[test]
fn restore_of_absent_store_is_a_fresh_client() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let client = client_over(BOB_DID, storage, 1_650_000_000);
    assert!(
        client.member_dids(CTX).is_none(),
        "an empty store yields a fresh client with no contexts"
    );
}

// ---------------------------------------------------------------------------
// Fail-closed restore (construction fails; nothing installed)
// ---------------------------------------------------------------------------

/// The read-side fault a [`FaultOnGet`] injects for keys containing its marker.
enum GetFault {
    /// Replace the value with fixed bytes (a corrupt / non-MessagePack blob).
    Corrupt(Vec<u8>),
    /// Truncate the value to half its length (a torn/truncated blob).
    Truncate,
    /// Return a backend I/O error (an access fault, distinct from absence).
    Fail,
    /// Report the key absent even though `list_keys` still lists it (a vanished
    /// key — a concurrent delete / backend inconsistency).
    Vanish,
}

/// Wraps a storage, applying `fault` to reads of any key containing `marker`.
/// Every other access (and every read of a non-marker key) delegates unchanged.
struct FaultOnGet {
    inner: Arc<dyn Storage>,
    marker: String,
    fault: GetFault,
}

impl Storage for FaultOnGet {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        if key.contains(&self.marker) {
            return match &self.fault {
                GetFault::Fail => Err("injected backend read failure".to_owned()),
                GetFault::Vanish => Ok(None),
                GetFault::Corrupt(replacement) => {
                    Ok(self.inner.get(key)?.map(|_| replacement.clone()))
                }
                GetFault::Truncate => Ok(self
                    .inner
                    .get(key)?
                    .map(|orig| orig[..orig.len() / 2].to_vec())),
            };
        }
        self.inner.get(key)
    }
    fn put(&self, key: &str, value: Vec<u8>) -> Result<(), String> {
        self.inner.put(key, value)
    }
    fn delete(&self, key: &str) -> Result<(), String> {
        self.inner.delete(key)
    }
    fn list_keys(&self, prefix: &str) -> Result<Vec<String>, String> {
        self.inner.list_keys(prefix)
    }
}

/// Wraps a storage whose `put` fails once a flag is set — to exercise a
/// persistence failure mid-op.
struct GatedFailOnPut {
    inner: Arc<dyn Storage>,
    fail: AtomicBool,
}

impl GatedFailOnPut {
    fn new(inner: Arc<dyn Storage>) -> Self {
        Self {
            inner,
            fail: AtomicBool::new(false),
        }
    }
    fn arm(&self) {
        self.fail.store(true, Ordering::SeqCst);
    }
}

impl Storage for GatedFailOnPut {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        self.inner.get(key)
    }
    fn put(&self, key: &str, value: Vec<u8>) -> Result<(), String> {
        if self.fail.load(Ordering::SeqCst) {
            return Err("injected backend write failure".to_owned());
        }
        self.inner.put(key, value)
    }
    fn delete(&self, key: &str) -> Result<(), String> {
        self.inner.delete(key)
    }
    fn list_keys(&self, prefix: &str) -> Result<Vec<String>, String> {
        self.inner.list_keys(prefix)
    }
}

/// Persists one converged context to `underlying` (as Bob) and returns the store.
fn persisted_single_context() -> Arc<dyn Storage> {
    let underlying: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let (_alice, _bob) = converged_pair(Arc::clone(&underlying));
    underlying
}

/// Attempts to construct a client for `did` over `storage`, returning the error.
/// (`ScpClient` is deliberately not `Debug`, so `expect_err` is unavailable.)
fn expect_construction_error_as(did: &str, storage: Arc<dyn Storage>) -> ClientError {
    let signer = Arc::new(LocalSigner::active(did));
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(1_650_000_100));
    match ScpClient::new(signer, storage, clock) {
        Ok(_) => panic!("construction must fail closed"),
        Err(e) => e,
    }
}

/// Attempts to construct a Bob client over `storage`, returning the error.
fn expect_construction_error(storage: Arc<dyn Storage>) -> ClientError {
    expect_construction_error_as(BOB_DID, storage)
}

#[test]
fn corrupt_blob_fails_construction_closed() {
    let underlying = persisted_single_context();
    let corrupting: Arc<dyn Storage> = Arc::new(FaultOnGet {
        inner: underlying,
        marker: "scp-client/ctx/".to_owned(),
        fault: GetFault::Corrupt(vec![0xFF; 16]), // non-empty, non-MessagePack
    });
    assert!(matches!(
        expect_construction_error(corrupting),
        ClientError::StorageCorrupt(_)
    ));
}

#[test]
fn truncated_blob_fails_construction_closed() {
    let underlying = persisted_single_context();
    let truncating: Arc<dyn Storage> = Arc::new(FaultOnGet {
        inner: underlying,
        marker: "scp-client/ctx/".to_owned(),
        fault: GetFault::Truncate,
    });
    assert!(matches!(
        expect_construction_error(truncating),
        ClientError::StorageCorrupt(_)
    ));
}

#[test]
fn owner_mismatch_fails_construction_closed() {
    // The store holds a context owned by Bob; a client for a DIFFERENT identity
    // must refuse to restore it.
    let underlying = persisted_single_context();
    let err = expect_construction_error_as(ALICE_DID, underlying); // not the owner (Bob)
    assert!(matches!(err, ClientError::StorageIdentityMismatch(_)));
}

#[test]
fn failing_backend_read_fails_construction_closed() {
    let underlying = persisted_single_context();
    let failing: Arc<dyn Storage> = Arc::new(FaultOnGet {
        inner: underlying,
        marker: "scp-client/ctx/".to_owned(),
        fault: GetFault::Fail,
    });
    assert!(matches!(
        expect_construction_error(failing),
        ClientError::StorageBackend(_)
    ));
}

#[test]
fn vanishing_listed_key_fails_construction_closed() {
    let underlying = persisted_single_context();
    let vanishing: Arc<dyn Storage> = Arc::new(FaultOnGet {
        inner: underlying,
        marker: "scp-client/ctx/".to_owned(),
        fault: GetFault::Vanish,
    });
    assert!(matches!(
        expect_construction_error(vanishing),
        ClientError::StorageBackend(_)
    ));
}

#[test]
fn one_of_two_corrupt_contexts_fails_whole_construction() {
    // Persist two independent contexts (as Bob), then corrupt exactly one blob.
    let underlying: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let ctx_good = "ctx-atomic-good";
    let ctx_bad = "ctx-atomic-corrupt";
    {
        let mut b = client_over(BOB_DID, Arc::clone(&underlying), 1_650_000_000);
        b.create_context(ctx_good).expect("create good");
        b.create_context(ctx_bad).expect("create corrupt");
    }

    let corrupting: Arc<dyn Storage> = Arc::new(FaultOnGet {
        inner: Arc::clone(&underlying),
        marker: ctx_bad.to_owned(),
        fault: GetFault::Corrupt(vec![0xFF; 16]),
    });
    // The whole construction fails — NEITHER context is installed (there is no
    // half-restored client to observe, so a retry can't hit ContextAlreadyExists).
    assert!(matches!(
        expect_construction_error(corrupting),
        ClientError::StorageCorrupt(_)
    ));
}

#[test]
fn failing_put_during_send_poisons_context_and_reconstruction_recovers() {
    let gated = Arc::new(GatedFailOnPut::new(Arc::new(MemoryStorage::new())));
    let storage: Arc<dyn Storage> = Arc::clone(&gated) as Arc<dyn Storage>;
    let mut alice = client_over(ALICE_DID, storage, 1_700_000_000);
    alice.create_context(CTX).expect("alice creates");
    // The last DURABLE state is the post-create snapshot (one ContextCreated leaf).
    let durable_root = alice.event_log_root(CTX).expect("post-create root");

    // Arm the failure; the send's post-mutation persist `put` now fails.
    gated.arm();
    let result = alice.send_message(CTX, b"never persisted");
    // A typed storage error — and, being `Err`, it carries NO ciphertext the
    // caller could transmit for a message whose state was not durably recorded.
    assert!(
        matches!(result, Err(ClientError::StorageBackend(_))),
        "a failed persist surfaces as a typed StorageBackend error with no SendOutput"
    );

    // The failed persist POISONED the context: the in-memory MLS ratchet advanced
    // (irreversibly) but the durable snapshot did not, so the two have diverged. A
    // SECOND send must refuse the diverged context rather than hand out another
    // ciphertext that would fork Alice's Merkle root from the group's.
    let second = alice.send_message(CTX, b"after poison");
    assert!(
        matches!(second, Err(ClientError::ContextPoisoned { .. })),
        "a poisoned context rejects further sends with the ContextPoisoned terminal"
    );
    // A pure observer reports the poisoned context as absent (it must not hand back
    // the misleading advanced-but-undurable root).
    assert!(
        alice.event_log_root(CTX).is_none(),
        "a poisoned context reports as absent to pure observers"
    );
    drop(alice); // discard the poisoned client, as the error directs.

    // Reconstruction from the SAME storage yields a WORKING, UNPOISONED context at
    // the last durable snapshot (post-create) — a restored context is unpoisoned by
    // construction. (`gated` is still armed, but reconstruction only reads.)
    let alice2 = client_over(
        ALICE_DID,
        Arc::clone(&gated) as Arc<dyn Storage>,
        1_700_000_050,
    );
    assert_eq!(
        alice2.event_log_root(CTX),
        Some(durable_root),
        "reconstructed root matches the last durable snapshot, not the lost send"
    );
    assert!(
        alice2.mls_epoch(CTX).is_ok(),
        "the reconstructed context is unpoisoned and usable (mls_epoch does not raise ContextPoisoned)"
    );
    assert_eq!(
        alice2.event_log_leaf_count(CTX),
        Some(1),
        "the reconstructed log holds only the durably-recorded ContextCreated leaf"
    );
}

#[test]
fn context_ids_lists_restored_contexts_sorted() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    {
        let mut b = client_over(BOB_DID, Arc::clone(&storage), 1_650_000_000);
        b.create_context("ctx-b-two").expect("create 2");
        b.create_context("ctx-a-one").expect("create 1");
        assert_eq!(
            b.context_ids(),
            vec!["ctx-a-one".to_owned(), "ctx-b-two".to_owned()],
            "context_ids is sorted"
        );
    }
    // A reopened tab restores both contexts and can enumerate them (without this,
    // a fresh client would hold its restored conversations but expose no listing).
    let b2 = client_over(BOB_DID, Arc::clone(&storage), 1_650_000_050);
    assert_eq!(
        b2.context_ids(),
        vec!["ctx-a-one".to_owned(), "ctx-b-two".to_owned()],
        "the reopened tab lists both restored contexts"
    );
}

#[test]
fn context_snapshot_under_mismatched_key_fails_construction_closed() {
    // A snapshot captured for context A, then stored under context B's key (a key
    // collision / backend bug). Restore enumerates key B but the blob's embedded
    // id is A → the whole construction fails closed as corrupt/mislabeled.
    let src: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    {
        let mut b = client_over(BOB_DID, Arc::clone(&src), 1_650_000_000);
        b.create_context("ctx-embedded-A").expect("create A");
    }
    let blob = src
        .get("scp-client/ctx/ctx-embedded-A")
        .expect("read ok")
        .expect("blob present");
    let tampered: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    tampered
        .put("scp-client/ctx/ctx-embedded-B", blob)
        .expect("put under mismatched key");
    assert!(matches!(
        expect_construction_error(tampered),
        ClientError::StorageCorrupt(_)
    ));
}

/// Generates and persists Bob's pending-join material for `ctx` into a fresh
/// store, then returns the raw pending blob (bound to Bob's DID + `ctx`).
fn bob_pending_blob(ctx: &str) -> Vec<u8> {
    let store: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let mut bob = client_over(BOB_DID, Arc::clone(&store), 1_650_000_000);
    bob.generate_key_package_for_join(ctx)
        .expect("bob key package");
    store
        .get(&format!("scp-client/pending/{ctx}"))
        .expect("read ok")
        .expect("pending blob present")
}

#[test]
fn cross_identity_pending_swap_fails_construction_closed() {
    // A pending blob generated by Bob, dropped into a store a DIFFERENT identity
    // (Alice) constructs over. The blob is bound to Bob's DID, so Alice must refuse
    // it — otherwise a swapped blob would drive Alice into a group under Bob's leaf
    // credential.
    let blob = bob_pending_blob("ctx-pending-x");
    let store: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    store
        .put("scp-client/pending/ctx-pending-x", blob)
        .expect("put");
    let err = expect_construction_error_as(ALICE_DID, store); // Alice, not the owner (Bob)
    assert!(matches!(err, ClientError::StorageIdentityMismatch(_)));
}

#[test]
fn cross_context_pending_swap_fails_construction_closed() {
    // A pending blob bound to context A, placed under context B's pending key. Even
    // the correct identity (Bob) must refuse it: the embedded context id disagrees
    // with the storage-key-derived one, so the key package is not for this context.
    let blob = bob_pending_blob("ctx-pending-A");
    let store: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    store
        .put("scp-client/pending/ctx-pending-B", blob)
        .expect("put under mismatched context key");
    assert!(matches!(
        expect_construction_error(store), // Bob (correct identity), wrong context key
        ClientError::StorageCorrupt(_)
    ));
}

#[test]
fn close_deletes_durable_state_forward_secrecy() {
    let bob_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let (_alice, mut bob) = converged_pair(Arc::clone(&bob_storage));
    bob.close_context(CTX).expect("bob closes");
    drop(bob);

    // A fresh client over the same storage finds nothing to restore — the closed
    // context is not resurrected (forward secrecy).
    let bob2 = client_over(BOB_DID, Arc::clone(&bob_storage), 1_650_000_100);
    assert!(
        bob2.member_dids(CTX).is_none(),
        "the closed context's snapshot was deleted and is not restored"
    );
}
