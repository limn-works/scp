//! Adversarial / fail-closed coverage for the single-threaded SCP participant
//! driver (ADR-057 Slice 2/3).
//!
//! The happy-path tests (`two_party_exchange.rs`, `multi_party_convergence.rs`,
//! `sender_key_distribution.rs`) prove convergence works; the crypto-layer unit
//! tests in `crypto_state.rs` prove the §9.16 replay/ceiling/failed-decrypt
//! invariants at the `ContextCryptoState` level. This file drives the
//! [`ScpClient`] *public* receive/state paths under hostile or degenerate input
//! and asserts each fails **closed**.
//!
//! # The load-bearing property: no mutation on rejection
//!
//! Every "fails closed" assertion here checks that **observable state is
//! UNCHANGED**, not merely that an error was returned. A driver that errored
//! *after* half-advancing its MLS epoch, membership set, event-log leaf count, or
//! Merkle root would be a §9.9.3 divergence bug (the receiver's root drifts from
//! the honest committer's) even though it "returned an error". So each adversarial
//! case snapshots the full observable context state — MLS epoch, membership,
//! event-log leaf count, Merkle root, and the per-leaf hashes — *before* the
//! hostile input and asserts byte-for-byte equality *after*, plus that no phantom
//! receive event was buffered. Where the replay floor is the property under test,
//! it is probed behaviourally (a subsequent honest message still decrypts / a
//! genuine replay is still rejected), since the sender-key floor is internal state.
//!
//! # How hostile wire bytes are manufactured
//!
//! ADR-057 Slice 2 deliberately gives the participant `ScpClient` no op that emits
//! malformed or foreign wire bytes. To manufacture exactly the bytes a hostile
//! relay / foreign group could put on the wire, some tests drive a SEPARATE
//! `ScpClient` as the adversary (its own group) while the client under test is the
//! honest receiver.
//!
//! # Current-API notes
//!
//! `ScpClient::new` is fallible (restore-on-construct). `send_message` returns the
//! raw ciphertext (an application message is not a convergent leaf — ADR-011 — so
//! it carries no transported timestamp), and `receive_message(ctx, &ct)` takes
//! ONLY the ciphertext; the convergent committer timestamp rides in the add-Commit
//! AAD (ADR-057 T3), never a caller parameter. Sender keys are distributed IN-TAB
//! over the management-message channel (`sender_key_distributions`), delivered via
//! `receive_message` — there is no `install_sender_key` op. Clocks are seeded from
//! the real clock (not a fixed past epoch) so every minted `KeyPackage` `Lifetime`
//! stays valid against openmls's un-injectable internal clock (ADR-057 §Prereq-1).

// Integration tests assert on results; `expect`/`panic!`/`unwrap` make the
// failure messages legible. The workspace denies these in production code.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use scp_client::{ClientError, EVENT_BUFFER_CAP, LocalSigner, MemoryStorage, ScpClient, Storage};
use scp_clock::{Clock, SystemClock, TestClock};
use scp_protocol::context::membership::ContextEvent;

const CTX: &str = "ctx-adr057-driver-adversarial";
const ALICE_DID: &str = "did:key:z6MkAliceDriverAdversarialFixtureAAAAAAAAAA";
const BOB_DID: &str = "did:key:z6MkBobDriverAdversarialFixtureBBBBBBBBBBBB";
const CAROL_DID: &str = "did:key:z6MkCarolDriverAdversarialFixtureCCCCCCCCCC";

/// Builds a fresh client for `did` over a real-time-seeded clock.
fn client_for(did: &str, now_secs: u64) -> ScpClient {
    let signer = Arc::new(LocalSigner::active(did));
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(now_secs));
    // A fresh store restores nothing, so construction cannot fail here.
    ScpClient::new(signer, storage, clock).expect("construct fresh client")
}

/// Builds a client for `did` over a CALLER-SUPPLIED storage handle. When the
/// store already holds this identity's snapshots or pending-join blobs, the
/// constructor restores them (ADR-057 T2) — the reconstruct-from-durable recovery
/// path a failed join relies on.
fn client_for_with_storage(did: &str, storage: Arc<dyn Storage>, now_secs: u64) -> ScpClient {
    let signer = Arc::new(LocalSigner::active(did));
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(now_secs));
    ScpClient::new(signer, storage, clock).expect("construct/restore client")
}

/// A snapshot of the full observable per-context driver state, used to assert
/// that a fail-closed path left EVERYTHING unchanged (not just returned an
/// error). Captures every axis a divergence bug could move.
#[derive(Debug, PartialEq, Eq)]
struct StateSnapshot {
    mls_epoch: u64,
    members: Vec<String>,
    leaf_count: Option<u64>,
    root: Option<[u8; 32]>,
    leaf_hashes: Option<Vec<[u8; 32]>>,
}

impl StateSnapshot {
    /// Captures the driver's observable state for `context_id`. Members are
    /// sorted so the comparison is order-insensitive.
    fn capture(client: &ScpClient, context_id: &str) -> Self {
        let mut members = client.member_dids(context_id).unwrap_or_default();
        members.sort();
        Self {
            mls_epoch: client.mls_epoch(context_id).unwrap_or(u64::MAX),
            members,
            leaf_count: client.event_log_leaf_count(context_id),
            root: client.event_log_root(context_id),
            leaf_hashes: client.event_log_leaf_hashes(context_id),
        }
    }
}

/// Builds Alice (creator) and Bob (joined), converged, with sender keys
/// exchanged both ways IN-TAB so application messages decrypt each direction.
/// Returns both clients ready for a two-party exchange.
fn converged_pair() -> (ScpClient, ScpClient) {
    let base = SystemClock.now_secs();
    let mut alice = client_for(ALICE_DID, base);
    // A deliberately different local clock: convergence must not depend on the
    // two members' clocks agreeing.
    let mut bob = client_for(BOB_DID, base + 100);

    alice.create_context(CTX).expect("Alice creates");
    let bob_kp = bob
        .generate_key_package_for_join(CTX)
        .expect("Bob key package");
    let add = alice.add_member(CTX, &bob_kp).expect("Alice adds Bob");
    let bob_dists = bob
        .join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
        .expect("Bob joins");

    // Deliver the in-tab sender-key distributions both ways (Alice→Bob from the
    // add; Bob→Alice from the join) through `receive_message`.
    for d in &add.sender_key_distributions {
        assert_eq!(d.target_did, BOB_DID);
        bob.receive_message(CTX, &d.ciphertext)
            .expect("Bob installs Alice's sender key");
    }
    for d in &bob_dists {
        assert_eq!(d.target_did, ALICE_DID);
        alice
            .receive_message(CTX, &d.ciphertext)
            .expect("Alice installs Bob's sender key");
    }
    (alice, bob)
}

// ===========================================================================
// 1. Foreign-group MLS frame rejected without mutation
// ===========================================================================

#[test]
fn foreign_group_frame_is_rejected_without_mutation() {
    // A ciphertext that IS a well-formed MLS frame but was produced by a DIFFERENT
    // MLS group (so it decrypts under none of Bob's group keys) must be rejected
    // with NO state mutation — distinct from the undecodable-bytes path (test 10).
    let (_alice, mut bob) = converged_pair();

    // A completely separate context/group Bob is not a member of. Its application
    // ciphertext is a valid MLS frame for THAT group, foreign to Bob's. A
    // sole-member group can still encrypt an application message to itself (the
    // creator's own sender key is seeded at creation).
    let mut mallory = client_for(CAROL_DID, SystemClock.now_secs());
    mallory
        .create_context("ctx-foreign-group")
        .expect("Mallory creates a foreign group");
    let foreign = mallory
        .send_message("ctx-foreign-group", b"not for Bob")
        .expect("Mallory sends in her own group");

    let before = StateSnapshot::capture(&bob, CTX);
    let err = bob
        .receive_message(CTX, &foreign)
        .expect_err("a foreign-group MLS frame must be rejected");
    assert!(
        matches!(err, ClientError::Mls(_)),
        "a foreign-group MLS frame fails at the MLS decrypt layer, got: {err:?}"
    );
    assert_eq!(
        StateSnapshot::capture(&bob, CTX),
        before,
        "a rejected foreign-group ciphertext must leave epoch, membership, leaf \
         count, root, and leaf hashes UNCHANGED"
    );
    assert!(
        bob.drain_events(CTX).expect("drain").is_empty(),
        "no receive event is buffered for a rejected foreign ciphertext"
    );
}

// ===========================================================================
// 2. Operations on an unknown context error cleanly (no panic)
// ===========================================================================

#[test]
fn operations_on_unknown_context_error_cleanly_no_panic() {
    // Every fallible op that names a context the client does not hold must return
    // UnknownContext (a clean error), never panic; the infallible observers return
    // None. This is the "not a member / unknown context" fail-closed path.
    const MISSING: &str = "ctx-never-created";
    let mut client = client_for(ALICE_DID, SystemClock.now_secs());

    macro_rules! assert_unknown {
        ($e:expr, $what:literal) => {{
            match $e {
                Err(ClientError::UnknownContext(id)) => {
                    assert_eq!(id, MISSING, concat!($what, ": names the missing context"));
                }
                other => panic!(concat!($what, ": expected UnknownContext, got {:?}"), other),
            }
        }};
    }

    assert_unknown!(client.send_message(MISSING, b"hi"), "send_message");
    assert_unknown!(
        client.receive_message(MISSING, &[0u8; 32]),
        "receive_message"
    );
    assert_unknown!(client.drain_events(MISSING), "drain_events");
    assert_unknown!(client.close_context(MISSING), "close_context");
    assert_unknown!(client.mls_epoch(MISSING), "mls_epoch");
    assert_unknown!(client.rotate_sender_key(MISSING), "rotate_sender_key");

    // The infallible observers return None (not a panic) for a missing context.
    assert_eq!(client.member_dids(MISSING), None);
    assert_eq!(client.event_log_root(MISSING), None);
    assert_eq!(client.event_log_leaf_count(MISSING), None);
    assert_eq!(client.event_log_leaf_hashes(MISSING), None);
}

// ===========================================================================
// 3. Re-creating an existing context preserves the first
// ===========================================================================

#[test]
fn create_context_twice_errors_and_preserves_the_first() {
    // Re-creating an existing context must fail closed without disturbing the
    // established context's state (no silent re-init that would wipe the log or
    // rotate group keys under a live context).
    let mut alice = client_for(ALICE_DID, SystemClock.now_secs());
    alice.create_context(CTX).expect("first create");
    let before = StateSnapshot::capture(&alice, CTX);

    match alice.create_context(CTX) {
        Err(ClientError::ContextAlreadyExists(id)) => assert_eq!(id, CTX),
        other => panic!("expected ContextAlreadyExists, got {other:?}"),
    }
    assert_eq!(
        StateSnapshot::capture(&alice, CTX),
        before,
        "a rejected duplicate create must not re-initialize the live context"
    );
}

// ===========================================================================
// 4. Replay floor survives a failed decrypt (driver level)
// ===========================================================================

#[test]
fn replay_floor_survives_a_failed_decrypt_at_the_driver() {
    // A FAILED decrypt (here: a message from a sender whose key Bob has not yet
    // installed) must NOT advance Bob's replay floor NOR mutate observable state.
    // Proven behaviourally: after installing the key, forward receive still works
    // (the failed decrypt did not wedge the receive path), and a genuine replay of
    // an accepted message is still rejected.
    let base = SystemClock.now_secs();
    let mut alice = client_for(ALICE_DID, base);
    let mut bob = client_for(BOB_DID, base + 100);

    alice.create_context(CTX).expect("Alice creates");
    let bob_kp = bob
        .generate_key_package_for_join(CTX)
        .expect("Bob key package");
    let add = alice.add_member(CTX, &bob_kp).expect("Alice adds Bob");
    let _bob_dists = bob
        .join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
        .expect("Bob joins");
    // NOTE: Bob has NOT yet installed Alice's sender key (the add distribution is
    // held below), so the first application message fails at the inner layer.

    let before = StateSnapshot::capture(&bob, CTX);
    let msg1 = alice.send_message(CTX, b"first attempt").expect("send 1");
    assert!(
        bob.receive_message(CTX, &msg1).is_err(),
        "no installed sender key for Alice → the inner sender-layer decrypt fails"
    );
    assert_eq!(
        StateSnapshot::capture(&bob, CTX),
        before,
        "a failed decrypt must not mutate epoch, membership, or the event log"
    );
    assert!(
        bob.drain_events(CTX).expect("drain").is_empty(),
        "a failed decrypt buffers no receive event"
    );

    // Now deliver Alice's key (the held add distribution) and a fresh message
    // decrypts — the earlier failure did not corrupt or wedge Bob's receive state.
    assert_eq!(add.sender_key_distributions.len(), 1);
    bob.receive_message(CTX, &add.sender_key_distributions[0].ciphertext)
        .expect("Bob installs Alice's key");
    let msg2 = alice.send_message(CTX, b"second attempt").expect("send 2");
    assert!(
        bob.receive_message(CTX, &msg2)
            .expect("now decrypts")
            .application,
        "after installing the key the message decrypts — the floor was not wedged"
    );

    // A genuine replay of the accepted message is rejected — the floor advanced on
    // the SUCCESSFUL decrypt, not on the earlier failure.
    assert!(
        bob.receive_message(CTX, &msg2).is_err(),
        "replaying the accepted message is rejected"
    );
}

// ===========================================================================
// 5. Out-of-order event-log replay is rejected fail-closed (no half-built context)
// ===========================================================================

#[test]
fn out_of_order_event_log_replay_is_rejected_fail_closed() {
    // The join path replays the adder's event-log stream through the canonical
    // chain-validating append. Handing it an OUT-OF-ORDER stream (a leaf whose
    // sequence/prev_hash does not chain onto the current head) must fail closed —
    // consistent with convergence-by-replay, which requires the stream in order —
    // and Bob must NOT be left holding a half-built context.
    let base = SystemClock.now_secs();
    let mut alice = client_for(ALICE_DID, base);
    let mut bob = client_for(BOB_DID, base + 100);

    alice.create_context(CTX).expect("Alice creates");
    let bob_kp = bob
        .generate_key_package_for_join(CTX)
        .expect("Bob key package");
    let add = alice.add_member(CTX, &bob_kp).expect("Alice adds Bob");
    assert_eq!(add.event_log.len(), 2, "ContextCreated + MemberJoined");

    // Corrupt the ordering: swap the two leaves so sequence 1 arrives before
    // sequence 0. The chain-validating append must reject it, and the join fails.
    let mut reordered = add.event_log.clone();
    reordered.swap(0, 1);

    let err = bob
        .join_context_encrypted(CTX, &add.welcome, &reordered, &add.wrapping_keys)
        .expect_err("an out-of-order replay stream must be rejected");
    assert!(
        matches!(err, ClientError::EventLog(_)),
        "an out-of-order leaf fails the chain-validating append, got: {err:?}"
    );

    // Fail-closed: Bob holds no half-built context from the rejected join.
    assert_eq!(
        bob.member_dids(CTX),
        None,
        "a rejected out-of-order join must leave Bob holding NO context (no \
         partially-replayed log)"
    );
    assert_eq!(bob.event_log_root(CTX), None);
    assert_eq!(bob.event_log_leaf_count(CTX), None);
}

// ===========================================================================
// 6. Receive-buffer eviction at capacity without corruption
// ===========================================================================

#[test]
fn receive_buffer_evicts_oldest_at_capacity_without_corrupting_state() {
    // The pull-based receive buffer is FIFO-capped at EVENT_BUFFER_CAP so a slow
    // drainer cannot grow memory without bound. Overflowing it must evict the
    // OLDEST event (not the newest), hold exactly CAP events, and leave the
    // canonical convergent event log intact — an application message is NOT a
    // convergent leaf (ADR-011), so the log stays at its 2 membership leaves no
    // matter how many messages flow. CAP is imported from the crate (not a magic
    // literal) so this test tracks the real cap if it ever changes.
    const EXTRA: usize = 5;
    let cap = EVENT_BUFFER_CAP;

    let (mut alice, mut bob) = converged_pair();

    // Baseline: both converged on 2 membership leaves with equal roots.
    let leaves_before = bob.event_log_leaf_count(CTX).expect("count");
    assert_eq!(leaves_before, 2, "ContextCreated + MemberJoined");
    let root_before = bob.event_log_root(CTX).expect("root");

    let total = cap + EXTRA;
    let first_payload = b"msg-0".to_vec();
    let last_payload = format!("msg-{}", total - 1).into_bytes();
    for i in 0..total {
        let payload = format!("msg-{i}").into_bytes();
        let ct = alice.send_message(CTX, &payload).expect("alice sends");
        // Bob receives every message but NEVER drains — the buffer must self-cap.
        assert!(
            bob.receive_message(CTX, &ct)
                .expect("bob receives")
                .application,
            "each is an application message"
        );
    }

    // The canonical event log recorded NO new leaf (application messages are
    // excluded from the convergent Merkle log — the cap bounds the UNDRAINED
    // receive buffer, never the log).
    assert_eq!(
        bob.event_log_leaf_count(CTX),
        Some(leaves_before),
        "received application messages append no convergent leaf"
    );

    // The buffer holds exactly EVENT_BUFFER_CAP events (the EXTRA oldest evicted).
    let drained = bob.drain_events(CTX).expect("drain");
    assert_eq!(
        drained.len(),
        cap,
        "the receive buffer is capped at EVENT_BUFFER_CAP; overflow evicts oldest"
    );

    // The OLDEST (first) message was evicted; the NEWEST (last) survived — FIFO.
    let contains = |needle: &[u8]| {
        drained.iter().any(|e| {
            matches!(e, ContextEvent::MessageReceived { payload, .. } if payload.as_slice() == needle)
        })
    };
    assert!(
        !contains(&first_payload),
        "the oldest buffered event was evicted at capacity"
    );
    assert!(
        contains(&last_payload),
        "the newest event survived — eviction is FIFO (oldest-first)"
    );

    // Convergence intact despite eviction: the convergent log/root never moved.
    assert_eq!(
        bob.event_log_root(CTX),
        Some(root_before),
        "buffer eviction does not corrupt the convergent event-log root"
    );
    assert_eq!(
        alice.event_log_root(CTX),
        bob.event_log_root(CTX),
        "Alice and Bob still agree after the flood"
    );
}

// ===========================================================================
// 7. Operations after close error cleanly; close destroys the in-memory group
// ===========================================================================

#[test]
fn operations_after_close_error_cleanly_and_close_destroys_the_group() {
    // Closing a context destroys its MLS group (forward secrecy — ADR-057
    // lose-device-lose-history). After close, every op naming that context must
    // return a clean UnknownContext error (never panic), and the group must be
    // truly gone (not merely hidden) — Alice can no longer process inbound traffic
    // for it.
    let (mut alice, mut bob) = converged_pair();

    // A message Bob sends BEFORE Alice closes — used to prove Alice's group is
    // genuinely destroyed after close (she can no longer process it).
    let pre_close = bob
        .send_message(CTX, b"sent before Alice closes")
        .expect("Bob sends");

    alice.close_context(CTX).expect("Alice closes");

    // The context is gone: observers report absence, not stale data.
    assert_eq!(
        alice.member_dids(CTX),
        None,
        "after close the context is absent"
    );
    assert_eq!(alice.event_log_root(CTX), None);
    assert_eq!(alice.event_log_leaf_count(CTX), None);
    assert!(!alice.context_ids().contains(&CTX.to_owned()));

    // Every fallible op errors cleanly (UnknownContext), no panic — including a
    // receive of the pre-close ciphertext, proving the group is truly destroyed.
    assert!(matches!(
        alice.send_message(CTX, b"after close"),
        Err(ClientError::UnknownContext(_))
    ));
    assert!(matches!(
        alice.receive_message(CTX, &pre_close),
        Err(ClientError::UnknownContext(_))
    ));
    assert!(matches!(
        alice.drain_events(CTX),
        Err(ClientError::UnknownContext(_))
    ));
    assert!(matches!(
        alice.mls_epoch(CTX),
        Err(ClientError::UnknownContext(_))
    ));

    // Closing again is a clean error, not a double-free panic.
    assert!(matches!(
        alice.close_context(CTX),
        Err(ClientError::UnknownContext(_))
    ));
}

// ===========================================================================
// 8. Pending-join material is single-use (consumed, not left dangling)
// ===========================================================================

#[test]
fn successful_join_consumes_pending_material_no_reuse() {
    // `generate_key_package_for_join` retains private join material (signer +
    // provider + wrapping keypair) keyed by context id, consumed by
    // `join_context_encrypted`. A SUCCESSFUL join must CONSUME that material so it
    // cannot be silently reused into a second, resurrected context — the retained
    // private half is not left dangling and usable a second time.
    let base = SystemClock.now_secs();
    let mut alice = client_for(ALICE_DID, base);
    let mut bob = client_for(BOB_DID, base + 100);
    alice.create_context(CTX).expect("Alice creates");

    let bob_kp = bob
        .generate_key_package_for_join(CTX)
        .expect("Bob key package");
    let add = alice.add_member(CTX, &bob_kp).expect("Alice adds Bob");
    bob.join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
        .expect("Bob joins");

    // A second join for the SAME context id short-circuits on the already-held
    // context guard.
    match bob.join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys) {
        Err(ClientError::ContextAlreadyExists(_)) => {}
        other => panic!("expected ContextAlreadyExists on re-join, got {other:?}"),
    }

    // Close CTX (clearing residual state), then attempt a join for CTX with NO
    // fresh key-package generation. The prior material was consumed by the first
    // join, so nothing is pending: the join fails with the no-pending-material
    // Driver error, NOT a silent success reusing stale key material.
    bob.close_context(CTX).expect("Bob closes CTX");
    match bob.join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys) {
        Err(ClientError::NoPendingJoinMaterial { context_id }) => assert_eq!(
            context_id, CTX,
            "the join reports absent pending material for the named context"
        ),
        other => panic!(
            "expected NoPendingJoinMaterial (material was consumed and not left \
             dangling), got {other:?}"
        ),
    }
}

// ===========================================================================
// 9. Close clears pending join material (abandoned join leaks nothing)
// ===========================================================================

#[test]
fn close_context_clears_pending_join_material() {
    // close_context must drop any pending join material keyed by that context, so
    // an abandoned join leaves no retained private MLS key material and no dangling
    // entry usable later. After generating join material and then closing that
    // context's slot, a join attempt finds nothing pending.
    const CTX_JOIN: &str = "ctx-adr057-pending-cleanup-target";
    let mut carol = client_for(CAROL_DID, SystemClock.now_secs());

    // Carol creates a context under this id so close_context has a context to
    // remove, then generates (and abandons) join material keyed by that id.
    carol
        .create_context(CTX_JOIN)
        .expect("Carol creates the slot");
    let _abandoned = carol
        .generate_key_package_for_join(CTX_JOIN)
        .expect("Carol generates (then abandons) join material");

    // Close drops both the context AND its pending join material.
    carol
        .close_context(CTX_JOIN)
        .expect("Carol closes the slot");

    // A join now finds no pending material — the abandoned private key material was
    // cleared by close, not left dangling to be replayed.
    match carol.join_context_encrypted(CTX_JOIN, &[], &[], &[]) {
        Err(ClientError::NoPendingJoinMaterial { context_id }) => assert_eq!(
            context_id, CTX_JOIN,
            "close must have cleared the pending material for the named context"
        ),
        other => panic!("expected NoPendingJoinMaterial after close, got {other:?}"),
    }
}

// ===========================================================================
// 10. Malformed / truncated ciphertext leaves the replay floor intact
// ===========================================================================

#[test]
fn malformed_or_truncated_ciphertext_leaves_replay_floor_intact() {
    // A garbage / truncated / empty blob is not a decodable MLS wire frame, so
    // `receive_message` must error at the MLS-deserialize/decrypt boundary BEFORE
    // touching the event log, membership, epoch, or replay floor. Proven by a
    // subsequent HONEST message still decrypting (the malformed inputs neither
    // advanced the floor nor wedged the receive path).
    let (mut alice, mut bob) = converged_pair();

    // Settle Bob's state with one honest message first.
    let honest = alice
        .send_message(CTX, b"honest before attack")
        .expect("send");
    assert!(
        bob.receive_message(CTX, &honest)
            .expect("bob receives honest")
            .application
    );
    let _ = bob.drain_events(CTX);

    let before = StateSnapshot::capture(&bob, CTX);

    // (a) A pile of bytes that is not a valid MLS wire frame.
    let garbage = vec![0xADu8; 24];
    let err = bob
        .receive_message(CTX, &garbage)
        .expect_err("malformed ciphertext must be rejected");
    assert!(
        matches!(err, ClientError::Mls(_) | ClientError::Codec(_)),
        "a non-decodable frame surfaces as an MLS/codec error, got: {err:?}"
    );

    // (b) An EMPTY buffer (degenerate truncation).
    assert!(
        bob.receive_message(CTX, &[]).is_err(),
        "an empty ciphertext is rejected"
    );

    // (c) A prefix-truncated copy of a real ciphertext (valid framing, cut short).
    let real = alice
        .send_message(CTX, b"a real message to truncate")
        .expect("send");
    let truncated = &real[..real.len() / 2];
    assert!(
        bob.receive_message(CTX, truncated).is_err(),
        "a truncated ciphertext is rejected"
    );

    // None of the malformed inputs mutated any observable state.
    assert_eq!(
        StateSnapshot::capture(&bob, CTX),
        before,
        "rejected malformed/truncated ciphertexts must leave epoch, membership, \
         leaf count, root, and leaf hashes UNCHANGED"
    );
    assert!(
        bob.drain_events(CTX).expect("drain").is_empty(),
        "no phantom receive event was buffered for a rejected ciphertext"
    );

    // The replay floor is intact: a fresh honest message from Alice still decrypts
    // (the malformed inputs did not advance the floor past it). Note `real` above
    // was consumed by Alice's send ratchet as a distinct message; send a NEW one.
    let after_attack = alice
        .send_message(CTX, b"honest after attack")
        .expect("send");
    assert!(
        bob.receive_message(CTX, &after_attack)
            .expect("post-attack honest message decrypts")
            .application,
        "an honest message still decrypts — the malformed inputs left the replay \
         floor and receive path intact"
    );
}

// ===========================================================================
// 11. Malformed / foreign KeyPackage → add_member is rejected without mutation
// ===========================================================================

#[test]
fn malformed_key_package_add_member_is_rejected_without_mutation() {
    // The ADDER-SIDE dual of the out-of-order-replay test (5): hostile INPUT to
    // `add_member`, not to `receive`/`join`. A garbage or wrong-wire-type
    // KeyPackage must be rejected at the `KeyPackageIn` deserialize boundary —
    // which `add_member` runs BEFORE it takes the mutable context borrow — so the
    // adder's full state (epoch, membership, leaf count, root, per-leaf hashes) is
    // left byte-for-byte identical. A half-applied add (epoch advanced, or a phantom
    // MemberJoined leaf appended) under a rejected KeyPackage would be a §9.9.3
    // divergence bug even though an error was returned.
    let base = SystemClock.now_secs();
    let mut alice = client_for(ALICE_DID, base);
    let mut bob = client_for(BOB_DID, base + 100);
    alice.create_context(CTX).expect("Alice creates");

    // Establish a richer two-member state so the no-mutation assertion covers a
    // populated log/membership, not just a fresh context.
    let bob_kp = bob
        .generate_key_package_for_join(CTX)
        .expect("Bob key package");
    let add = alice.add_member(CTX, &bob_kp).expect("Alice adds Bob");
    bob.join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
        .expect("Bob joins");

    let before = StateSnapshot::capture(&alice, CTX);

    // (a) Pure garbage — not a decodable MLS/TLS wire object at all.
    let garbage = vec![0xABu8; 40];
    let err = alice
        .add_member(CTX, &garbage)
        .expect_err("a garbage KeyPackage must be rejected");
    assert!(
        matches!(err, ClientError::Codec(_) | ClientError::Mls(_)),
        "a non-decodable KeyPackage fails at the codec/MLS boundary, got: {err:?}"
    );
    assert_eq!(
        StateSnapshot::capture(&alice, CTX),
        before,
        "a rejected garbage KeyPackage must leave the adder's epoch, membership, \
         leaf count, root, and leaf hashes UNCHANGED"
    );

    // (b) A VALID MLS wire object of the WRONG TYPE: the add's own Welcome bytes
    // are a well-formed `MlsMessage`, but `KeyPackageIn` deserialization rejects
    // them (a Welcome is not a KeyPackage). This exercises the "foreign / wrong
    // wire object" adder input distinct from raw garbage.
    let err = alice
        .add_member(CTX, &add.welcome)
        .expect_err("a foreign (wrong-type) MLS object must be rejected as a KeyPackage");
    assert!(
        matches!(err, ClientError::Codec(_) | ClientError::Mls(_)),
        "a wrong-type MLS wire object fails the KeyPackage deserialize, got: {err:?}"
    );
    assert_eq!(
        StateSnapshot::capture(&alice, CTX),
        before,
        "a rejected wrong-type KeyPackage must leave the adder's state UNCHANGED"
    );

    // (c) An empty buffer (degenerate truncation).
    assert!(
        alice.add_member(CTX, &[]).is_err(),
        "an empty KeyPackage is rejected"
    );
    assert_eq!(
        StateSnapshot::capture(&alice, CTX),
        before,
        "a rejected empty KeyPackage must leave the adder's state UNCHANGED"
    );
}

// ===========================================================================
// 12. Malformed / foreign Welcome → join leaves NO half-built context
// ===========================================================================

#[test]
fn malformed_welcome_join_leaves_no_half_built_context() {
    // The joiner-side input dual: a bad/foreign Welcome handed to
    // `join_context_encrypted` must fail closed with Bob holding NO context at all —
    // no partially-built MLS group, no partially-replayed event log, no membership
    // directory. A half-built context would be worse than none: it could emit
    // ciphertext / leaves no peer shares.
    let base = SystemClock.now_secs();
    let mut alice = client_for(ALICE_DID, base);
    let mut bob = client_for(BOB_DID, base + 100);
    alice.create_context(CTX).expect("Alice creates");

    let bob_kp = bob
        .generate_key_package_for_join(CTX)
        .expect("Bob key package");
    // A real add so the transported event log + wrapping keys are genuine; ONLY the
    // Welcome is hostile, isolating the Welcome-processing failure.
    let add = alice.add_member(CTX, &bob_kp).expect("Alice adds Bob");

    let garbage_welcome = vec![0xEEu8; 48];
    let err = bob
        .join_context_encrypted(CTX, &garbage_welcome, &add.event_log, &add.wrapping_keys)
        .expect_err("a malformed Welcome must be rejected");
    assert!(
        matches!(err, ClientError::Mls(_)),
        "a non-decodable Welcome fails at the MLS Welcome-processing layer, got: {err:?}"
    );

    // Fail-closed: Bob holds NO half-built context.
    assert_eq!(
        bob.member_dids(CTX),
        None,
        "a rejected Welcome must leave Bob holding NO context"
    );
    assert_eq!(bob.event_log_root(CTX), None);
    assert_eq!(bob.event_log_leaf_count(CTX), None);
    assert_eq!(bob.event_log_leaf_hashes(CTX), None);
}

// ===========================================================================
// 13. A failed join CONSUMES the in-memory pending material (single-use per
//     attempt); recovery is via reconstruct-from-durable, not in-memory reuse
// ===========================================================================

#[test]
fn failed_join_consumes_pending_and_recovers_only_via_reconstruct() {
    // CONTRACT PIN for the single-use-per-attempt join contract documented on
    // `join_context_encrypted` (see its in-body note; ADR-057 T2 / Snapshot v3). Two
    // properties: (1) a failed join on a bad Welcome BURNS the in-memory pending, so a
    // second in-tab attempt — even with a GOOD Welcome — gets `NoPendingJoinMaterial`,
    // not a silent retry; and (2) recovery is via the PRISTINE durable pending blob a
    // failed join never deletes: reconstructing the client over the same storage
    // restores it and the join then succeeds.
    let base = SystemClock.now_secs();
    let mut alice = client_for(ALICE_DID, base);
    // Bob over a SHARED storage handle so a reconstructed client can restore the
    // durable pending blob the failed join leaves intact.
    let bob_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let mut bob = client_for_with_storage(BOB_DID, Arc::clone(&bob_storage), base + 100);

    alice.create_context(CTX).expect("Alice creates");
    let bob_kp = bob
        .generate_key_package_for_join(CTX)
        .expect("Bob key package"); // persists the durable pending blob
    let add = alice.add_member(CTX, &bob_kp).expect("Alice adds Bob"); // a GOOD Welcome

    // First attempt: a BAD Welcome (real event log + wrapping keys). It fails at
    // Welcome processing AFTER the in-memory pending was removed.
    let garbage_welcome = vec![0xEEu8; 48];
    let err = bob
        .join_context_encrypted(CTX, &garbage_welcome, &add.event_log, &add.wrapping_keys)
        .expect_err("the bad Welcome must be rejected");
    assert!(
        matches!(err, ClientError::Mls(_)),
        "bad Welcome, got: {err:?}"
    );
    assert_eq!(
        bob.member_dids(CTX),
        None,
        "the failed join left no half-built context"
    );

    // Second in-tab attempt with the GOOD Welcome: the in-memory pending was CONSUMED
    // by the first attempt, so this reports absent pending material — NOT a retry.
    match bob.join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys) {
        Err(ClientError::NoPendingJoinMaterial { context_id }) => assert_eq!(
            context_id, CTX,
            "the failed join burned the in-memory pending material (single-use per \
             attempt)"
        ),
        other => panic!(
            "expected NoPendingJoinMaterial on the second in-tab attempt (the first \
             attempt consumed the live pending material), got {other:?}"
        ),
    }

    // RECOVERY — the documented path: a fresh client over Bob's SAME storage restores
    // the still-durable pending blob (the failed join never deleted it) and the join
    // now SUCCEEDS with the good Welcome. This proves the burned prekey was not
    // permanently lost — reconstruct-from-durable is the retry seam.
    drop(bob);
    let mut bob2 = client_for_with_storage(BOB_DID, Arc::clone(&bob_storage), base + 150);
    // The reconstructed client is not yet a member; the pending material was restored.
    assert_eq!(
        bob2.member_dids(CTX),
        None,
        "the reconstructed client has not joined yet"
    );
    bob2.join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
        .expect("reconstruct-from-durable restores pending material; the join succeeds");
    let mut members = bob2.member_dids(CTX).expect("bob2 is now a member");
    members.sort();
    assert_eq!(
        members,
        vec![ALICE_DID.to_owned(), BOB_DID.to_owned()],
        "the recovered join converged Bob into the two-member context"
    );
    assert_eq!(
        bob2.event_log_root(CTX),
        alice.event_log_root(CTX),
        "the recovered join replayed Alice's log to the same Merkle root"
    );
}

// ===========================================================================
// 14. A misdirected sender-key distribution (sealed to another member) is
//     rejected without mutation
// ===========================================================================

#[test]
fn misdirected_sender_key_distribution_is_rejected_without_mutation() {
    // A §9.16 sender-key distribution is HPKE-sealed to ONE member's stable wrapping
    // key; `target_did` is only an in-tab delivery hint. Delivering a distribution
    // sealed for Carol to the WRONG member (Bob) must fail closed at the HPKE-open
    // step (Bob's wrapping secret cannot open a seal made for Carol's key) and leave
    // NO OBSERVABLE state change — no installed sender key, no leaf, no buffered
    // event, no epoch/membership/root move. (The rejection happens AFTER the outer
    // MLS frame is decrypted, so Bob's inbound MLS ratchet advances in memory; that
    // is internal, un-persisted, and not part of the convergent/observable state the
    // snapshot captures — the point under test is that the misdirected seal installs
    // no key and forks no log.)
    let (mut alice, mut bob) = converged_pair();

    // Alice adds Carol; Bob (bystander) processes the add-Commit so he reaches the
    // post-add epoch at which Alice's distributions were sealed.
    let mut carol = client_for(CAROL_DID, SystemClock.now_secs() + 200);
    let carol_kp = carol
        .generate_key_package_for_join(CTX)
        .expect("Carol key package");
    let add_carol = alice.add_member(CTX, &carol_kp).expect("Alice adds Carol");
    carol
        .join_context_encrypted(
            CTX,
            &add_carol.welcome,
            &add_carol.event_log,
            &add_carol.wrapping_keys,
        )
        .expect("Carol joins");
    bob.receive_message(CTX, &add_carol.commit)
        .expect("Bob processes the add-Carol Commit");
    let _ = bob.drain_events(CTX); // clear any buffered events from the commit processing

    // Alice's own add-seal targets Carol (sealed to Carol's wrapping key).
    assert_eq!(add_carol.sender_key_distributions.len(), 1);
    let alice_to_carol = &add_carol.sender_key_distributions[0];
    assert_eq!(
        alice_to_carol.target_did, CAROL_DID,
        "Alice's add-seal is addressed to Carol"
    );

    // Snapshot Bob's post-Commit state, then MISDIRECT Alice→Carol's seal to Bob.
    let before = StateSnapshot::capture(&bob, CTX);
    let err = bob
        .receive_message(CTX, &alice_to_carol.ciphertext)
        .expect_err("a distribution sealed to Carol must not open under Bob's key");
    // The outer MLS frame decrypts (Bob is at the sealing epoch), so the rejection is
    // specifically the inner HPKE-open failing under Bob's wrapping secret — a
    // sender-key-layer error, NOT an MLS-layer one. Asserting the precise variant
    // proves the misdirection was caught at the intended layer (a vague MLS error
    // could mean Bob simply couldn't decrypt the frame, making the test vacuous).
    assert!(
        matches!(err, ClientError::SenderKey(_)),
        "the misdirected seal fails at the HPKE-open (sender-key) layer, got: {err:?}"
    );
    assert_eq!(
        StateSnapshot::capture(&bob, CTX),
        before,
        "a rejected misdirected distribution must leave epoch, membership, leaf \
         count, root, and leaf hashes UNCHANGED"
    );
    assert!(
        bob.drain_events(CTX).expect("drain").is_empty(),
        "a rejected misdirected distribution buffers no event"
    );

    // Bob's PEER sender-key store is internal — `StateSnapshot` does not capture it and
    // there is no public observer — so we cannot directly read that no wrong key was
    // installed. The evidence is instead two-fold: (a) the rejection surfaced as
    // `ClientError::SenderKey(_)`, a failure at the HPKE-open step, which runs BEFORE
    // any key-install step, so no key can have been adopted from the misdirected seal;
    // and (b) this probe confirms the receive path is not wedged and Alice's existing
    // sender key (installed during `converged_pair`) still decrypts. Together these are
    // the rejection-POINT (open-before-install) plus a non-wedging probe — NOT a direct
    // read of the store's contents.
    let honest = alice
        .send_message(CTX, b"honest after misdirection")
        .expect("Alice sends");
    assert!(
        bob.receive_message(CTX, &honest)
            .expect("Bob still decrypts Alice's message")
            .application,
        "the misdirected distribution installed no key and did not wedge Bob's \
         receive path"
    );
}
