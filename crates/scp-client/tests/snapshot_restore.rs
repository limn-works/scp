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
//!
//! ADR-057 transport slice: `ScpClient::new` now takes an injected `RelaySink`, a
//! send fans out over that sink (returning `()`, not the ciphertext) to the
//! announced peer pseudonyms, and a snapshot is **v4** — it persists the
//! §9.10.4 peer-pseudonym registry so a restored client can address its peers
//! again, while re-deriving its OWN pseudonym from the restored MLS key and
//! re-subscribing in the constructor. Delivery here uses the realistic relay
//! mock (`tests/common`): a send publishes a frame the test extracts from the
//! relay's publish log (`last_app_ciphertext`) and feeds to the peer's
//! `receive_message`, exactly as the in-tab §9.16 distribution model does.

// Integration tests assert on happy-path results; `expect`/`panic!` make the
// failure messages legible. The workspace denies these in production code.
#![allow(clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use scp_client::{
    ClientError, ContextStatus, LocalSigner, MemoryStorage, RelaySink, ScpClient, Storage,
};
use scp_clock::{Clock, SystemClock, TestClock};
use scp_protocol::context::context_routing_id;
use scp_protocol::context::membership::ContextEvent;

mod common;
use common::*;

const CTX: &str = "ctx-adr057-t2-snapshot-restore";
const ALICE_DID: &str = "did:key:z6MkAliceT2SnapshotRestoreFixtureAAAAAAAAA";
const BOB_DID: &str = "did:key:z6MkBobT2SnapshotRestoreFixtureBBBBBBBBBBBBB";

/// A real-time clock seed with a small distinct offset (seconds).
///
/// Seeded from `SystemClock.now_secs()` rather than a fixed past epoch so every
/// minted `KeyPackage` `Lifetime` stays valid against openmls's un-injectable
/// internal (real) clock (ADR-057 §Prereq-1 test-clock realism). The small
/// offsets keep the two members' clocks distinct (and model a few seconds
/// elapsing across a disconnect/reconnect) while staying well inside openmls's
/// acceptance window; convergence rides on transported timestamps, not clock
/// magnitude.
fn seed(offset: u64) -> u64 {
    SystemClock.now_secs() + offset
}

/// A throwaway [`RelaySink`] for the fail-closed construction tests: restore on
/// construct fails before any frame is sent, so the sink is never exercised. (A
/// successfully-constructed client re-subscribes through it best-effort; the
/// swallowed subscribe is harmless — those tests never send.)
struct NullSink;

impl RelaySink for NullSink {
    fn send(&self, _frame: Vec<u8>) -> Result<(), String> {
        Ok(())
    }
}

/// Builds a client for `did` over the given (shared) storage and a fixed clock,
/// connected to `relay`, restoring whatever the storage holds for that identity
/// (the constructor is the restore path).
fn client_over(relay: &Relay, did: &str, storage: Arc<dyn Storage>, now_secs: u64) -> ScpClient {
    party_over(relay, did, storage, now_secs).client
}

/// Like [`client_over`], but returns the whole [`Party`] (keeping its relay
/// connection id alongside the client) so the caller can extract a send's
/// published ciphertext from the relay for delivery to a peer. Use this when the
/// restored (or freshly built) client must SEND afterwards.
fn party_over(relay: &Relay, did: &str, storage: Arc<dyn Storage>, now_secs: u64) -> Party {
    let signer = Arc::new(LocalSigner::active(did));
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(now_secs));
    relay.party_with(signer, storage, clock)
}

/// Extracts the inner MLS ciphertext of the last app-data `PUBLISH` `conn`
/// published to `relay` — the exact wire bytes a peer's `receive_message`
/// consumes. App data fans out to peer pseudonyms, so this filters out the shared
/// announcement channel. Drains the relay's publish log.
fn last_app_ciphertext(relay: &Relay, conn: ConnId, ctx: &str) -> Vec<u8> {
    relay
        .drain_publish_log()
        .into_iter()
        .rev()
        .find(|p| p.conn == conn && p.routing_id != context_routing_id(ctx))
        .expect("an app-data PUBLISH from this connection")
        .inner_ciphertext()
}

/// Drives Alice (creator) and Bob (joiner) through create / add / join / key
/// exchange over CALLER-SUPPLIED storage backends and a shared `relay`, so both
/// hold a converged two-member context with populated peer-pseudonym registries
/// and no messages yet. Buffers and the relay publish log are drained before
/// return, so callers start from a clean baseline.
///
/// Each side keeps its relay connection id in the returned [`Party`], so a caller
/// can extract a send's published ciphertext (`last_app_ciphertext`) and feed it
/// to the other side's `receive_message` — the in-tab §9.16 distribution model.
fn converge(
    relay: &Relay,
    alice_storage: Arc<dyn Storage>,
    alice_now: u64,
    bob_storage: Arc<dyn Storage>,
    bob_now: u64,
) -> (Party, Party) {
    let mut alice = party_over(relay, ALICE_DID, alice_storage, alice_now);
    let mut bob = party_over(relay, BOB_DID, bob_storage, bob_now);

    alice.client.create_context(CTX).expect("alice creates");
    let bob_kp = bob
        .client
        .generate_key_package_for_join(CTX)
        .expect("bob key package");
    let add = alice
        .client
        .add_member(CTX, &bob_kp)
        .expect("alice adds bob");
    let bob_join_dists = bob
        .client
        .join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
        .expect("bob joins");

    // In-tab §9.16 distribution: Alice's add sealed her key to Bob; Bob's join
    // sealed his key to Alice. Route each DIRECTLY to its target's
    // receive_message (never over the relay, which carries only app data +
    // announcements).
    for d in &add.sender_key_distributions {
        assert_eq!(d.target_did, BOB_DID);
        bob.client
            .receive_message(CTX, &d.ciphertext)
            .expect("bob installs alice's key");
    }
    for d in &bob_join_dists {
        assert_eq!(d.target_did, ALICE_DID);
        alice
            .client
            .receive_message(CTX, &d.ciphertext)
            .expect("alice installs bob's key");
    }

    // Pump the §9.10.4 reciprocal-announce mesh to quiescence so both
    // peer-pseudonym registries populate — the prerequisite for app-data fan-out
    // (an empty registry in a >1-member context is a retryable
    // `PseudonymRegistryEmpty`).
    relay.pump(&mut [&mut alice, &mut bob]);

    // Clean baseline: drop the bootstrap `PseudonymAnnounced` events and every
    // recorded PUBLISH so callers start from an empty buffer and publish log.
    let _ = alice.client.drain_events(CTX);
    let _ = bob.client.drain_events(CTX);
    let _ = relay.drain_publish_log();

    (alice, bob)
}

/// Convenience over [`converge`]: Alice on a fresh in-memory store, Bob on the
/// caller's shared storage (so the caller can drop Bob and reopen over it).
fn converged_pair(relay: &Relay, bob_storage: Arc<dyn Storage>) -> (Party, Party) {
    converge(
        relay,
        Arc::new(MemoryStorage::new()),
        seed(0),
        bob_storage,
        seed(100),
    )
}

#[test]
#[allow(clippy::too_many_lines)] // one end-to-end restore scenario, read top-to-bottom
fn restore_resumes_a_converged_context_from_storage() {
    let relay = Relay::new();
    let bob_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let (mut alice, mut bob) = converged_pair(&relay, Arc::clone(&bob_storage));

    // Alice sends; the fan-out publishes one frame whose inner ciphertext the test
    // extracts and feeds to Bob's receive_message (mutating + persisting Bob's
    // snapshot) but does NOT drain — the buffered plaintext must survive the
    // restore. `pre` is retained to prove the replay rejection after restore.
    alice
        .client
        .send_message(CTX, b"before restore")
        .expect("alice sends");
    let pre = last_app_ciphertext(&relay, alice.conn, CTX);
    let received = bob.client.receive_message(CTX, &pre).expect("bob receives");
    assert!(received.application);

    let expected_root = bob.client.event_log_root(CTX).expect("bob root");
    let expected_leaves = bob.client.event_log_leaf_count(CTX).expect("bob leaves");
    let expected_epoch = bob.client.mls_epoch(CTX).expect("bob epoch");
    let expected_members = {
        let mut m = bob.client.member_dids(CTX).expect("bob members");
        m.sort();
        m
    };
    drop(bob); // The tab closes; only the durable storage survives.

    // A fresh client (the reopened tab) over Bob's identity + the SAME storage.
    // The constructor restores the converged context (and re-derives Bob's
    // pseudonym + re-subscribes; the v4 snapshot restored his peer registry).
    let mut bob2 = party_over(&relay, BOB_DID, Arc::clone(&bob_storage), seed(199));

    // Restored state matches what Bob held before the tab closed.
    let mut members = bob2.client.member_dids(CTX).expect("restored members");
    members.sort();
    assert_eq!(members, expected_members);
    assert_eq!(
        bob2.client.event_log_root(CTX),
        Some(expected_root),
        "restored event-log root matches"
    );
    assert_eq!(bob2.client.event_log_leaf_count(CTX), Some(expected_leaves));
    assert_eq!(
        bob2.client.mls_epoch(CTX).expect("restored epoch"),
        expected_epoch
    );

    // The undrained buffered message survived the round-trip and is delivered
    // exactly once. (The bootstrap `PseudonymAnnounced` events were drained by
    // `converge`, so only the one buffered `MessageReceived` round-trips.)
    let buffered = bob2.client.drain_events(CTX).expect("bob2 drains buffered");
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
        bob2.client
            .drain_events(CTX)
            .expect("second drain")
            .is_empty(),
        "the buffered message is delivered exactly once"
    );

    // Replaying the PRE-restore ciphertext must still be rejected — the MLS
    // ratchet that already consumed it is persisted and advanced.
    assert!(
        bob2.client.receive_message(CTX, &pre).is_err(),
        "a pre-restore ciphertext replay is rejected after restore"
    );

    // The restored client can DECRYPT a message Alice sends after the restore.
    alice
        .client
        .send_message(CTX, b"after restore")
        .expect("alice sends 2");
    let send2 = last_app_ciphertext(&relay, alice.conn, CTX);
    let received = bob2
        .client
        .receive_message(CTX, &send2)
        .expect("bob2 receives");
    assert!(received.application);
    let events = bob2.client.drain_events(CTX).expect("bob2 drains");
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

    // And it can SEND a message Alice decrypts — proving the send-side crypto,
    // the restored per-member sequence counters, AND the restored peer-pseudonym
    // registry (without which the fan-out would be `PseudonymRegistryEmpty`) work.
    bob2.client
        .send_message(CTX, b"from restored bob")
        .expect("bob2 sends");
    let send3 = last_app_ciphertext(&relay, bob2.conn, CTX);
    let received = alice
        .client
        .receive_message(CTX, &send3)
        .expect("alice receives from restored bob");
    assert!(received.application);
    // Alice's buffer now holds her own two sends (`before restore`, `after
    // restore`) as local `MessageSent` history plus Bob's `MessageReceived`, in
    // FIFO order — a send buffers the sender's own history (ADR-011: it is not a
    // convergent leaf). The received message is the last entry.
    let alice_events = alice.client.drain_events(CTX).expect("alice drains");
    assert_eq!(
        alice_events.len(),
        3,
        "Alice's own two sends plus Bob's received message are buffered"
    );
    assert!(
        matches!(
            &alice_events[0],
            ContextEvent::MessageSent { sender_did, payload, .. }
                if sender_did.0 == ALICE_DID && payload.as_slice() == b"before restore"
        ),
        "first buffered event is Alice's own first send"
    );
    assert!(
        matches!(
            &alice_events[1],
            ContextEvent::MessageSent { sender_did, payload, .. }
                if sender_did.0 == ALICE_DID && payload.as_slice() == b"after restore"
        ),
        "second buffered event is Alice's own second send"
    );
    match &alice_events[2] {
        ContextEvent::MessageReceived {
            sender_did,
            payload,
        } => {
            assert_eq!(sender_did.0, BOB_DID);
            assert_eq!(payload.as_slice(), b"from restored bob");
        }
        other => panic!("expected MessageReceived last, got {other:?}"),
    }
}

#[test]
fn buffer_with_sent_and_received_round_trips_through_restore() {
    // ADR-057 T3: the driver now buffers a sender's own `MessageSent` local
    // history alongside received `MessageReceived` messages (neither is a
    // convergent leaf — ADR-011). A client that has both SENT and RECEIVED without
    // draining must restore BOTH from its snapshot's variant-aware buffer.
    let relay = Relay::new();
    let bob_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let (mut alice, mut bob) = converged_pair(&relay, Arc::clone(&bob_storage));

    // Bob sends (buffers his own MessageSent); Alice consumes it so her ratchet
    // stays usable. Then Alice sends and Bob receives (buffers a MessageReceived).
    // Bob drains neither.
    bob.client
        .send_message(CTX, b"bob's own send")
        .expect("bob sends");
    let bob_ct = last_app_ciphertext(&relay, bob.conn, CTX);
    alice
        .client
        .receive_message(CTX, &bob_ct)
        .expect("alice receives bob");
    alice
        .client
        .send_message(CTX, b"alice to bob")
        .expect("alice sends");
    let alice_ct = last_app_ciphertext(&relay, alice.conn, CTX);
    bob.client
        .receive_message(CTX, &alice_ct)
        .expect("bob receives alice");
    drop(bob); // tab closes with an undrained Sent + Received in the buffer.

    // A reopened tab restores both buffered events, in FIFO order.
    let mut bob2 = client_over(&relay, BOB_DID, Arc::clone(&bob_storage), seed(199));
    let drained = bob2.drain_events(CTX).expect("bob2 drains");
    assert_eq!(
        drained.len(),
        2,
        "both the sender's MessageSent and the received MessageReceived survive"
    );
    match &drained[0] {
        ContextEvent::MessageSent {
            sender_did,
            payload,
            ..
        } => {
            assert_eq!(sender_did.0, BOB_DID, "Bob's own send is first");
            assert_eq!(payload.as_slice(), b"bob's own send");
        }
        other => panic!("expected the buffered MessageSent first, got {other:?}"),
    }
    match &drained[1] {
        ContextEvent::MessageReceived {
            sender_did,
            payload,
        } => {
            assert_eq!(sender_did.0, ALICE_DID, "Alice's message is second");
            assert_eq!(payload.as_slice(), b"alice to bob");
        }
        other => panic!("expected the buffered MessageReceived second, got {other:?}"),
    }
}

#[test]
fn pending_join_completes_after_restore() {
    // Bob generates a key package (persisting the private pending material) and
    // the tab closes BEFORE joining. A reopened tab restores the pending material
    // and completes the join.
    let relay = Relay::new();
    let bob_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let alice_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let mut alice = client_over(&relay, ALICE_DID, alice_storage, seed(0));
    alice.create_context(CTX).expect("alice creates");

    let bob_kp = {
        let mut bob = client_over(&relay, BOB_DID, Arc::clone(&bob_storage), seed(100));
        let kp = bob
            .generate_key_package_for_join(CTX)
            .expect("bob key package");
        drop(bob); // tab closes before joining
        kp
    };

    // Alice adds Bob from the published key package.
    let add = alice.add_member(CTX, &bob_kp).expect("alice adds bob");

    // The reopened tab restores the pending material and joins with it.
    let mut bob2 = client_over(&relay, BOB_DID, Arc::clone(&bob_storage), seed(150));
    bob2.join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
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
    let relay = Relay::new();
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let client = client_over(&relay, BOB_DID, storage, seed(100));
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
    let relay = Relay::new();
    let underlying: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let (_alice, _bob) = converged_pair(&relay, Arc::clone(&underlying));
    underlying
}

/// Attempts to construct a client for `did` over `storage`, returning the error.
/// (`ScpClient` is deliberately not `Debug`, so `expect_err` is unavailable.)
fn expect_construction_error_as(did: &str, storage: Arc<dyn Storage>) -> ClientError {
    let signer = Arc::new(LocalSigner::active(did));
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(seed(200)));
    // The injected sink is irrelevant: restore-on-construct fails before any
    // frame is sent. A throwaway null sink satisfies the signature.
    match ScpClient::new(signer, storage, clock, Arc::new(NullSink)) {
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
        let relay = Relay::new();
        let mut b = client_over(&relay, BOB_DID, Arc::clone(&underlying), seed(100));
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
    // A failing post-send persist must poison a LIVE context, and reconstruction
    // from the same storage must recover an UNPOISONED context at the last durable
    // snapshot. Under the ADR-057 transport slice a send only reaches the persist
    // (and so can fail it) when it has an announced peer to fan out to — a lone
    // member's app-data send is a no-op (no addressee, no ratchet advance). So the
    // sender (Alice, on the gated store) is converged with a peer (Bob) first; the
    // gate is armed only afterwards, so convergence's writes succeed and the FIRST
    // armed write is the send's post-mutation persist.
    let relay = Relay::new();
    let gated = Arc::new(GatedFailOnPut::new(Arc::new(MemoryStorage::new())));
    let (mut alice, _bob) = converge(
        &relay,
        Arc::clone(&gated) as Arc<dyn Storage>,
        seed(0),
        Arc::new(MemoryStorage::new()),
        seed(100),
    );
    // The last DURABLE state is the converged snapshot (ContextCreated +
    // MemberJoined leaves, and the peer registry).
    let durable_root = alice
        .client
        .event_log_root(CTX)
        .expect("converged root is durable");
    let durable_leaves = alice
        .client
        .event_log_leaf_count(CTX)
        .expect("converged leaf count is durable");

    // Arm the failure; the send's post-mutation persist `put` now fails.
    gated.arm();
    let result = alice.client.send_message(CTX, b"never persisted");
    // A typed storage error — and, being `Err`, it fanned out NO frame the caller
    // could transmit for a message whose state was not durably recorded (the
    // ratchet is persisted BEFORE any PUBLISH, so a persist failure precedes the
    // fan-out entirely).
    assert!(
        matches!(result, Err(ClientError::StorageBackend(_))),
        "a failed persist surfaces as a typed StorageBackend error and no fan-out"
    );

    // The failed persist POISONED the context: the in-memory MLS ratchet advanced
    // (irreversibly) but the durable snapshot did not, so the two have diverged. A
    // SECOND send must refuse the diverged context rather than hand out another
    // ciphertext that would fork Alice's Merkle root from the group's.
    let second = alice.client.send_message(CTX, b"after poison");
    assert!(
        matches!(second, Err(ClientError::ContextPoisoned { .. })),
        "a poisoned context rejects further sends with the ContextPoisoned terminal"
    );
    // A pure observer reports the poisoned context as absent (it must not hand back
    // the misleading advanced-but-undurable root).
    assert!(
        alice.client.event_log_root(CTX).is_none(),
        "a poisoned context reports as absent to pure observers"
    );
    drop(alice); // discard the poisoned client, as the error directs.

    // Reconstruction from the SAME storage yields a WORKING, UNPOISONED context at
    // the last durable snapshot (post-convergence) — a restored context is
    // unpoisoned by construction. (`gated` is still armed, but reconstruction only
    // reads.)
    let alice2 = client_over(
        &relay,
        ALICE_DID,
        Arc::clone(&gated) as Arc<dyn Storage>,
        seed(50),
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
        Some(durable_leaves),
        "the reconstructed log holds only the durably-recorded leaves, not the lost send"
    );
}

#[test]
fn context_ids_lists_restored_contexts_sorted() {
    let relay = Relay::new();
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    {
        let mut b = client_over(&relay, BOB_DID, Arc::clone(&storage), seed(100));
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
    let b2 = client_over(&relay, BOB_DID, Arc::clone(&storage), seed(150));
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
        let relay = Relay::new();
        let mut b = client_over(&relay, BOB_DID, Arc::clone(&src), seed(100));
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
    let relay = Relay::new();
    let store: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let mut bob = client_over(&relay, BOB_DID, Arc::clone(&store), seed(100));
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
fn context_status_reports_live_poisoned_and_absent() {
    // The non-throwing predicate distinguishes all three states, unlike the
    // `Option` observers (which collapse poisoned into `None`). Alice is converged
    // with a peer so her send has an addressee (a lone send is a no-op that could
    // not poison); the gate arms only after convergence.
    let relay = Relay::new();
    let gated = Arc::new(GatedFailOnPut::new(Arc::new(MemoryStorage::new())));
    let (mut alice, _bob) = converge(
        &relay,
        Arc::clone(&gated) as Arc<dyn Storage>,
        seed(0),
        Arc::new(MemoryStorage::new()),
        seed(100),
    );

    // Absent: a context that was never created/joined.
    assert_eq!(
        alice.client.context_status("ctx-never-existed"),
        ContextStatus::Absent
    );

    // Live: converged and healthy.
    assert_eq!(alice.client.context_status(CTX), ContextStatus::Live);

    // Poisoned: a persist that fails after the in-memory state advanced diverges
    // durable vs live state.
    gated.arm();
    let _ = alice.client.send_message(CTX, b"never persisted");
    assert_eq!(
        alice.client.context_status(CTX),
        ContextStatus::Poisoned,
        "a failed persist flips the status to Poisoned"
    );
    // A poisoned context is still HELD (listed) even though the Option observers
    // report it as absent — context_status is the way to tell the two apart.
    assert!(alice.client.context_ids().contains(&CTX.to_owned()));
    assert!(alice.client.member_dids(CTX).is_none());
}

#[test]
fn closing_a_poisoned_context_forfeits_recovery() {
    // The ABANDON path: closing a poisoned context deletes its durable snapshot, so
    // a reconstructed client finds it ABSENT — recovery is permanently forfeited
    // (contrast the RECOVER path in
    // `failing_put_during_send_poisons_context_and_reconstruction_recovers`, which
    // does NOT close and so keeps the durable snapshot). Alice is converged with a
    // peer so her send has an addressee; the gate arms only after convergence.
    let relay = Relay::new();
    let gated = Arc::new(GatedFailOnPut::new(Arc::new(MemoryStorage::new())));
    let (mut alice, _bob) = converge(
        &relay,
        Arc::clone(&gated) as Arc<dyn Storage>,
        seed(0),
        Arc::new(MemoryStorage::new()),
        seed(100),
    );

    // Poison the context via a failing post-send persist.
    gated.arm();
    let send = alice.client.send_message(CTX, b"never persisted");
    assert!(matches!(send, Err(ClientError::StorageBackend(_))));
    assert_eq!(alice.client.context_status(CTX), ContextStatus::Poisoned);

    // Close (ABANDON) succeeds: it bypasses the poison guard, and the durable
    // deletes delegate through the gate (which only fails `put`, not `delete`).
    alice
        .client
        .close_context(CTX)
        .expect("close of a poisoned context succeeds");
    assert_eq!(
        alice.client.context_status(CTX),
        ContextStatus::Absent,
        "the closed context is dropped from memory"
    );
    drop(alice);

    // Reconstruction from the SAME storage finds nothing — close deleted the last
    // durable snapshot, so the context cannot be recovered.
    let alice2 = client_over(
        &relay,
        ALICE_DID,
        Arc::clone(&gated) as Arc<dyn Storage>,
        seed(50),
    );
    assert_eq!(
        alice2.context_status(CTX),
        ContextStatus::Absent,
        "closing the poisoned context permanently forfeited its durable snapshot"
    );
}

#[test]
fn close_deletes_durable_state_forward_secrecy() {
    let relay = Relay::new();
    let bob_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let (_alice, mut bob) = converged_pair(&relay, Arc::clone(&bob_storage));
    bob.client.close_context(CTX).expect("bob closes");
    drop(bob);

    // A fresh client over the same storage finds nothing to restore — the closed
    // context is not resurrected (forward secrecy).
    let bob2 = client_over(&relay, BOB_DID, Arc::clone(&bob_storage), seed(200));
    assert!(
        bob2.member_dids(CTX).is_none(),
        "the closed context's snapshot was deleted and is not restored"
    );
}
