//! Adversarial / fail-closed coverage for the single-threaded SCP participant
//! driver (ADR-057 Slice 2/3, transport slice).
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
//! Merkle root would be a §9.9.3 divergence bug even though it "returned an error".
//! So each adversarial case snapshots the full observable context state — MLS
//! epoch, membership, event-log leaf count, Merkle root, and per-leaf hashes —
//! *before* the hostile input and asserts byte-for-byte equality *after*, plus that
//! no phantom receive event was buffered.
//!
//! # Transport-slice notes (ADR-057) — recovering the wire ciphertext
//!
//! `send_message` no longer returns the ciphertext: it fans the message out over
//! the injected [`RelaySink`](scp_client::RelaySink) as relay `PUBLISH` frames. The
//! `common` [`Relay`](common::Relay) mock records those; the adversarial tests
//! recover the inner MLS ciphertext from the recorded app-data `PUBLISH` via
//! [`common::PublishRecord::inner_ciphertext`] (which decodes the wire
//! `OuterEnvelope` and returns its `encrypted_blob`) and feed it to
//! `receive_message` — possibly tampered — exactly the hostile-relay wire bytes the
//! old tests fabricated. The [`app_ciphertext`] helper drains the relay's publish
//! log and picks the app-data frame (the one NOT on the shared announcement
//! `context_routing_id`). An app-data send needs the peer registry populated first
//! (else `PseudonymRegistryEmpty`), so senders are wired via
//! [`common::connect_two`], which exchanges §9.16 sender keys AND — via the
//! reciprocal-announce cascade pumped to quiescence — populates both pseudonym
//! registries. A LONE member cannot send (fan-out is a no-op), so the "foreign
//! group" adversary is a genuine 2-member group on a SEPARATE relay.

// Integration tests assert on results; `expect`/`panic!`/`unwrap` make the
// failure messages legible. The workspace denies these in production code.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use common::{ConnId, Party, Relay, connect_two};
use scp_client::{ClientError, EVENT_BUFFER_CAP, LocalSigner, MemoryStorage, ScpClient, Storage};
use scp_clock::{Clock, SystemClock, TestClock};
use scp_protocol::context::context_routing_id;
use scp_protocol::context::membership::ContextEvent;

const CTX: &str = "ctx-adr057-driver-adversarial";
const ALICE_DID: &str = "did:key:z6MkAliceDriverAdversarialFixtureAAAAAAAAAA";
const BOB_DID: &str = "did:key:z6MkBobDriverAdversarialFixtureBBBBBBBBBBBB";
const CAROL_DID: &str = "did:key:z6MkCarolDriverAdversarialFixtureCCCCCCCCCC";
const DAVE_DID: &str = "did:key:z6MkDaveDriverAdversarialFixtureDDDDDDDDDDDD";

/// Recovers the inner MLS ciphertext of the single app-data `PUBLISH` a
/// `send_message` fanned out over `relay` from connection `conn`.
///
/// App data is fanned to peer pseudonyms, NEVER to the shared announcement
/// `context_routing_id`, so the app-data frame is the recorded `PUBLISH` whose
/// routing id is not the shared channel. [`common::PublishRecord::inner_ciphertext`]
/// decodes the wire `OuterEnvelope` and returns its `encrypted_blob` — the exact
/// inner MLS frame the old tests captured via `last_ciphertext`. Drains the log, so
/// call it once per send.
fn app_ciphertext(relay: &Relay, conn: ConnId, ctx: &str) -> Vec<u8> {
    relay
        .drain_publish_log()
        .into_iter()
        .find(|p| p.conn == conn && p.routing_id != context_routing_id(ctx))
        .expect("an app-data PUBLISH was fanned out")
        .inner_ciphertext()
}

/// A snapshot of the full observable per-context driver state, used to assert
/// that a fail-closed path left EVERYTHING unchanged (not just returned an error).
#[derive(Debug, PartialEq, Eq)]
struct StateSnapshot {
    mls_epoch: u64,
    members: Vec<String>,
    leaf_count: Option<u64>,
    root: Option<[u8; 32]>,
    leaf_hashes: Option<Vec<[u8; 32]>>,
}

impl StateSnapshot {
    /// Captures the driver's observable state for `context_id`. Members are sorted
    /// so the comparison is order-insensitive.
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

/// Builds Alice (creator) and Bob (joined) over a fresh relay, converged, with
/// sender keys exchanged both ways AND both pseudonym registries populated, so
/// application messages decrypt AND fan out each direction. Returns the shared
/// relay plus each party (client + relay connection id).
fn converged_pair() -> (Relay, Party, Party) {
    let relay = Relay::new();
    let (alice, bob) = connect_two(&relay, CTX, ALICE_DID, BOB_DID);
    (relay, alice, bob)
}

/// One well-formed application MLS ciphertext from a DIFFERENT group (foreign to
/// `CTX`). A lone member cannot send (fan-out is a no-op), so the foreign group is
/// a genuine 2-member context on a SEPARATE relay; its creator's send produces the
/// frame, recovered from that relay's publish log.
fn foreign_group_ciphertext() -> Vec<u8> {
    let relay = Relay::new();
    let (mut mallory, _dave) = connect_two(&relay, "ctx-foreign-group", CAROL_DID, DAVE_DID);
    mallory
        .client
        .send_message("ctx-foreign-group", b"not for Bob")
        .expect("Mallory sends in her own group");
    app_ciphertext(&relay, mallory.conn, "ctx-foreign-group")
}

// ===========================================================================
// 1. Foreign-group MLS frame rejected without mutation
// ===========================================================================

#[test]
fn foreign_group_frame_is_rejected_without_mutation() {
    // A ciphertext that IS a well-formed MLS frame but was produced by a DIFFERENT
    // MLS group (so it decrypts under none of Bob's group keys) must be rejected
    // with NO state mutation — distinct from the undecodable-bytes path (test 10).
    let (_relay, _alice, mut bob) = converged_pair();

    let foreign = foreign_group_ciphertext();

    let before = StateSnapshot::capture(&bob.client, CTX);
    let err = bob
        .client
        .receive_message(CTX, &foreign)
        .expect_err("a foreign-group MLS frame must be rejected");
    assert!(
        matches!(err, ClientError::Mls(_)),
        "a foreign-group MLS frame fails at the MLS decrypt layer, got: {err:?}"
    );
    assert_eq!(
        StateSnapshot::capture(&bob.client, CTX),
        before,
        "a rejected foreign-group ciphertext must leave epoch, membership, leaf \
         count, root, and leaf hashes UNCHANGED"
    );
    assert!(
        bob.client.drain_events(CTX).expect("drain").is_empty(),
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
    let relay = Relay::new();
    let mut party = relay.new_party(ALICE_DID, 0);
    let client = &mut party.client;

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
    let relay = Relay::new();
    let mut alice = relay.new_party(ALICE_DID, 0);
    alice.client.create_context(CTX).expect("first create");
    let before = StateSnapshot::capture(&alice.client, CTX);

    match alice.client.create_context(CTX) {
        Err(ClientError::ContextAlreadyExists(id)) => assert_eq!(id, CTX),
        other => panic!("expected ContextAlreadyExists, got {other:?}"),
    }
    assert_eq!(
        StateSnapshot::capture(&alice.client, CTX),
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
    // Proven behaviourally: after installing the key, forward receive still works,
    // and a genuine replay of an accepted message is still rejected.
    //
    // Asymmetric setup: Alice must be able to SEND (so she needs BOB's pseudonym,
    // which requires BOB's sender key on Alice's side) but Bob must LACK ALICE's
    // sender key (the property under test — his inner decrypt fails). So we install
    // Bob→Alice and pump Bob's announcement to Alice ONLY, but deliberately HOLD the
    // Alice→Bob distribution. Pumping only Alice keeps Bob from ever processing
    // Alice's reciprocal announcement (which he could not decrypt without her key).
    let relay = Relay::new();
    let mut alice = relay.new_party(ALICE_DID, 0);
    let mut bob = relay.new_party(BOB_DID, 100);

    alice.client.create_context(CTX).expect("Alice creates");
    let bob_kp = bob
        .client
        .generate_key_package_for_join(CTX)
        .expect("Bob key package");
    let add = alice
        .client
        .add_member(CTX, &bob_kp)
        .expect("Alice adds Bob");
    let bob_dists = bob
        .client
        .join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
        .expect("Bob joins");
    // Install Bob's key on Alice + pump Bob's announcement so Alice learns Bob's
    // pseudonym and can send. Bob still LACKS Alice's key (the add's Alice→Bob
    // distribution is held) and is NOT pumped, so he never processes Alice's
    // reciprocal announcement.
    alice
        .client
        .receive_message(CTX, &bob_dists[0].ciphertext)
        .expect("Alice installs Bob's key");
    relay.pump(&mut [&mut alice]);
    let _ = alice.client.drain_events(CTX);
    let _ = relay.drain_publish_log();

    let before = StateSnapshot::capture(&bob.client, CTX);
    alice
        .client
        .send_message(CTX, b"first attempt")
        .expect("send 1");
    let msg1 = app_ciphertext(&relay, alice.conn, CTX);
    assert!(
        bob.client.receive_message(CTX, &msg1).is_err(),
        "no installed sender key for Alice → the inner sender-layer decrypt fails"
    );
    assert_eq!(
        StateSnapshot::capture(&bob.client, CTX),
        before,
        "a failed decrypt must not mutate epoch, membership, or the event log"
    );
    assert!(
        bob.client.drain_events(CTX).expect("drain").is_empty(),
        "a failed decrypt buffers no receive event"
    );

    // Now deliver Alice's key (the held add distribution) and a fresh message
    // decrypts — the earlier failure did not corrupt or wedge Bob's receive state.
    assert_eq!(add.sender_key_distributions.len(), 1);
    bob.client
        .receive_message(CTX, &add.sender_key_distributions[0].ciphertext)
        .expect("Bob installs Alice's key");
    alice
        .client
        .send_message(CTX, b"second attempt")
        .expect("send 2");
    let msg2 = app_ciphertext(&relay, alice.conn, CTX);
    assert!(
        bob.client
            .receive_message(CTX, &msg2)
            .expect("now decrypts")
            .application,
        "after installing the key the message decrypts — the floor was not wedged"
    );

    // A genuine replay of the accepted message is rejected — the floor advanced on
    // the SUCCESSFUL decrypt, not on the earlier failure.
    assert!(
        bob.client.receive_message(CTX, &msg2).is_err(),
        "replaying the accepted message is rejected"
    );
}

// ===========================================================================
// 5. Out-of-order event-log replay is rejected fail-closed (no half-built context)
// ===========================================================================

#[test]
fn out_of_order_event_log_replay_is_rejected_fail_closed() {
    // The join path replays the adder's event-log stream through the canonical
    // chain-validating append. Handing it an OUT-OF-ORDER stream must fail closed,
    // and Bob must NOT be left holding a half-built context.
    let relay = Relay::new();
    let mut alice = relay.new_party(ALICE_DID, 0);
    let mut bob = relay.new_party(BOB_DID, 100);

    alice.client.create_context(CTX).expect("Alice creates");
    let bob_kp = bob
        .client
        .generate_key_package_for_join(CTX)
        .expect("Bob key package");
    let add = alice
        .client
        .add_member(CTX, &bob_kp)
        .expect("Alice adds Bob");
    assert_eq!(add.event_log.len(), 2, "ContextCreated + MemberJoined");

    // Corrupt the ordering: swap the two leaves so sequence 1 arrives before
    // sequence 0. The chain-validating append must reject it, and the join fails.
    let mut reordered = add.event_log.clone();
    reordered.swap(0, 1);

    let err = bob
        .client
        .join_context_encrypted(CTX, &add.welcome, &reordered, &add.wrapping_keys)
        .expect_err("an out-of-order replay stream must be rejected");
    assert!(
        matches!(err, ClientError::EventLog(_)),
        "an out-of-order leaf fails the chain-validating append, got: {err:?}"
    );

    // Fail-closed: Bob holds no half-built context from the rejected join.
    assert_eq!(
        bob.client.member_dids(CTX),
        None,
        "a rejected out-of-order join must leave Bob holding NO context (no \
         partially-replayed log)"
    );
    assert_eq!(bob.client.event_log_root(CTX), None);
    assert_eq!(bob.client.event_log_leaf_count(CTX), None);
}

// ===========================================================================
// 6. Receive-buffer eviction at capacity without corruption
// ===========================================================================

#[test]
fn receive_buffer_evicts_oldest_at_capacity_without_corrupting_state() {
    // The pull-based receive buffer is FIFO-capped at EVENT_BUFFER_CAP so a slow
    // drainer cannot grow memory without bound. Overflowing it must evict the
    // OLDEST event, hold exactly CAP events, and leave the canonical convergent
    // event log intact — an application message is NOT a convergent leaf (ADR-011).
    const EXTRA: usize = 5;
    let cap = EVENT_BUFFER_CAP;

    let (relay, mut alice, mut bob) = converged_pair();

    // Baseline: both converged on 2 membership leaves with equal roots.
    let leaves_before = bob.client.event_log_leaf_count(CTX).expect("count");
    assert_eq!(leaves_before, 2, "ContextCreated + MemberJoined");
    let root_before = bob.client.event_log_root(CTX).expect("root");

    let total = cap + EXTRA;
    let first_payload = b"msg-0".to_vec();
    let last_payload = format!("msg-{}", total - 1).into_bytes();
    for i in 0..total {
        let payload = format!("msg-{i}").into_bytes();
        alice
            .client
            .send_message(CTX, &payload)
            .expect("alice sends");
        let ct = app_ciphertext(&relay, alice.conn, CTX);
        // Bob receives every message but NEVER drains — the buffer must self-cap.
        assert!(
            bob.client
                .receive_message(CTX, &ct)
                .expect("bob receives")
                .application,
            "each is an application message"
        );
    }

    // The canonical event log recorded NO new leaf (application messages are
    // excluded from the convergent Merkle log — the cap bounds the UNDRAINED
    // receive buffer, never the log).
    assert_eq!(
        bob.client.event_log_leaf_count(CTX),
        Some(leaves_before),
        "received application messages append no convergent leaf"
    );

    // The buffer holds exactly EVENT_BUFFER_CAP events (the EXTRA oldest evicted).
    let drained = bob.client.drain_events(CTX).expect("drain");
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
        bob.client.event_log_root(CTX),
        Some(root_before),
        "buffer eviction does not corrupt the convergent event-log root"
    );
    assert_eq!(
        alice.client.event_log_root(CTX),
        bob.client.event_log_root(CTX),
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
    // truly gone — Alice can no longer process inbound traffic for it.
    let (relay, mut alice, mut bob) = converged_pair();

    // A message Bob sends BEFORE Alice closes — used to prove Alice's group is
    // genuinely destroyed after close (she can no longer process it).
    bob.client
        .send_message(CTX, b"sent before Alice closes")
        .expect("Bob sends");
    let pre_close = app_ciphertext(&relay, bob.conn, CTX);

    alice.client.close_context(CTX).expect("Alice closes");

    // The context is gone: observers report absence, not stale data.
    assert_eq!(
        alice.client.member_dids(CTX),
        None,
        "after close the context is absent"
    );
    assert_eq!(alice.client.event_log_root(CTX), None);
    assert_eq!(alice.client.event_log_leaf_count(CTX), None);
    assert!(!alice.client.context_ids().contains(&CTX.to_owned()));

    // Every fallible op errors cleanly (UnknownContext), no panic — including a
    // receive of the pre-close ciphertext, proving the group is truly destroyed.
    assert!(matches!(
        alice.client.send_message(CTX, b"after close"),
        Err(ClientError::UnknownContext(_))
    ));
    assert!(matches!(
        alice.client.receive_message(CTX, &pre_close),
        Err(ClientError::UnknownContext(_))
    ));
    assert!(matches!(
        alice.client.drain_events(CTX),
        Err(ClientError::UnknownContext(_))
    ));
    assert!(matches!(
        alice.client.mls_epoch(CTX),
        Err(ClientError::UnknownContext(_))
    ));

    // Closing again is a clean error, not a double-free panic.
    assert!(matches!(
        alice.client.close_context(CTX),
        Err(ClientError::UnknownContext(_))
    ));
}

// ===========================================================================
// 8. Pending-join material is single-use (consumed, not left dangling)
// ===========================================================================

#[test]
fn successful_join_consumes_pending_material_no_reuse() {
    // A SUCCESSFUL join must CONSUME the retained private join material so it cannot
    // be silently reused into a second, resurrected context.
    let relay = Relay::new();
    let mut alice = relay.new_party(ALICE_DID, 0);
    let mut bob = relay.new_party(BOB_DID, 100);
    alice.client.create_context(CTX).expect("Alice creates");

    let bob_kp = bob
        .client
        .generate_key_package_for_join(CTX)
        .expect("Bob key package");
    let add = alice
        .client
        .add_member(CTX, &bob_kp)
        .expect("Alice adds Bob");
    bob.client
        .join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
        .expect("Bob joins");

    // A second join for the SAME context id short-circuits on the already-held guard.
    match bob
        .client
        .join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
    {
        Err(ClientError::ContextAlreadyExists(_)) => {}
        other => panic!("expected ContextAlreadyExists on re-join, got {other:?}"),
    }

    // Close CTX, then attempt a join with NO fresh key-package generation. The prior
    // material was consumed by the first join, so nothing is pending.
    bob.client.close_context(CTX).expect("Bob closes CTX");
    match bob
        .client
        .join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
    {
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
    // close_context must drop any pending join material keyed by that context.
    const CTX_JOIN: &str = "ctx-adr057-pending-cleanup-target";
    let relay = Relay::new();
    let mut carol = relay.new_party(CAROL_DID, 0);

    carol
        .client
        .create_context(CTX_JOIN)
        .expect("Carol creates the slot");
    let _abandoned = carol
        .client
        .generate_key_package_for_join(CTX_JOIN)
        .expect("Carol generates (then abandons) join material");

    // Close drops both the context AND its pending join material.
    carol
        .client
        .close_context(CTX_JOIN)
        .expect("Carol closes the slot");

    // A join now finds no pending material — the abandoned private key material was
    // cleared by close, not left dangling to be replayed.
    match carol.client.join_context_encrypted(CTX_JOIN, &[], &[], &[]) {
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
    // touching the event log, membership, epoch, or replay floor.
    let (relay, mut alice, mut bob) = converged_pair();

    // Settle Bob's state with one honest message first.
    alice
        .client
        .send_message(CTX, b"honest before attack")
        .expect("send");
    let honest = app_ciphertext(&relay, alice.conn, CTX);
    assert!(
        bob.client
            .receive_message(CTX, &honest)
            .expect("bob receives honest")
            .application
    );
    let _ = bob.client.drain_events(CTX);

    let before = StateSnapshot::capture(&bob.client, CTX);

    // (a) A pile of bytes that is not a valid MLS wire frame.
    let garbage = vec![0xADu8; 24];
    let err = bob
        .client
        .receive_message(CTX, &garbage)
        .expect_err("malformed ciphertext must be rejected");
    assert!(
        matches!(err, ClientError::Mls(_) | ClientError::Codec(_)),
        "a non-decodable frame surfaces as an MLS/codec error, got: {err:?}"
    );

    // (b) An EMPTY buffer (degenerate truncation).
    assert!(
        bob.client.receive_message(CTX, &[]).is_err(),
        "an empty ciphertext is rejected"
    );

    // (c) A prefix-truncated copy of a real ciphertext (valid framing, cut short).
    alice
        .client
        .send_message(CTX, b"a real message to truncate")
        .expect("send");
    let real = app_ciphertext(&relay, alice.conn, CTX);
    let truncated = &real[..real.len() / 2];
    assert!(
        bob.client.receive_message(CTX, truncated).is_err(),
        "a truncated ciphertext is rejected"
    );

    // None of the malformed inputs mutated any observable state.
    assert_eq!(
        StateSnapshot::capture(&bob.client, CTX),
        before,
        "rejected malformed/truncated ciphertexts must leave epoch, membership, \
         leaf count, root, and leaf hashes UNCHANGED"
    );
    assert!(
        bob.client.drain_events(CTX).expect("drain").is_empty(),
        "no phantom receive event was buffered for a rejected ciphertext"
    );

    // The replay floor is intact: a fresh honest message from Alice still decrypts.
    alice
        .client
        .send_message(CTX, b"honest after attack")
        .expect("send");
    let after_attack = app_ciphertext(&relay, alice.conn, CTX);
    assert!(
        bob.client
            .receive_message(CTX, &after_attack)
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
    // Hostile INPUT to `add_member`: a garbage or wrong-wire-type KeyPackage must be
    // rejected at the `KeyPackageIn` deserialize boundary — BEFORE the mutable
    // context borrow — so the adder's full state is left byte-for-byte identical.
    let relay = Relay::new();
    let mut alice = relay.new_party(ALICE_DID, 0);
    let mut bob = relay.new_party(BOB_DID, 100);
    alice.client.create_context(CTX).expect("Alice creates");

    let bob_kp = bob
        .client
        .generate_key_package_for_join(CTX)
        .expect("Bob key package");
    let add = alice
        .client
        .add_member(CTX, &bob_kp)
        .expect("Alice adds Bob");
    bob.client
        .join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
        .expect("Bob joins");

    let before = StateSnapshot::capture(&alice.client, CTX);

    // (a) Pure garbage — not a decodable MLS/TLS wire object at all.
    let garbage = vec![0xABu8; 40];
    let err = alice
        .client
        .add_member(CTX, &garbage)
        .expect_err("a garbage KeyPackage must be rejected");
    assert!(
        matches!(err, ClientError::Codec(_) | ClientError::Mls(_)),
        "a non-decodable KeyPackage fails at the codec/MLS boundary, got: {err:?}"
    );
    assert_eq!(
        StateSnapshot::capture(&alice.client, CTX),
        before,
        "a rejected garbage KeyPackage must leave the adder's epoch, membership, \
         leaf count, root, and leaf hashes UNCHANGED"
    );

    // (b) A VALID MLS wire object of the WRONG TYPE: the add's own Welcome bytes.
    let err = alice
        .client
        .add_member(CTX, &add.welcome)
        .expect_err("a foreign (wrong-type) MLS object must be rejected as a KeyPackage");
    assert!(
        matches!(err, ClientError::Codec(_) | ClientError::Mls(_)),
        "a wrong-type MLS wire object fails the KeyPackage deserialize, got: {err:?}"
    );
    assert_eq!(
        StateSnapshot::capture(&alice.client, CTX),
        before,
        "a rejected wrong-type KeyPackage must leave the adder's state UNCHANGED"
    );

    // (c) An empty buffer (degenerate truncation).
    assert!(
        alice.client.add_member(CTX, &[]).is_err(),
        "an empty KeyPackage is rejected"
    );
    assert_eq!(
        StateSnapshot::capture(&alice.client, CTX),
        before,
        "a rejected empty KeyPackage must leave the adder's state UNCHANGED"
    );
}

// ===========================================================================
// 12. Malformed / foreign Welcome → join leaves NO half-built context
// ===========================================================================

#[test]
fn malformed_welcome_join_leaves_no_half_built_context() {
    // A bad/foreign Welcome handed to `join_context_encrypted` must fail closed with
    // Bob holding NO context at all.
    let relay = Relay::new();
    let mut alice = relay.new_party(ALICE_DID, 0);
    let mut bob = relay.new_party(BOB_DID, 100);
    alice.client.create_context(CTX).expect("Alice creates");

    let bob_kp = bob
        .client
        .generate_key_package_for_join(CTX)
        .expect("Bob key package");
    let add = alice
        .client
        .add_member(CTX, &bob_kp)
        .expect("Alice adds Bob");

    let garbage_welcome = vec![0xEEu8; 48];
    let err = bob
        .client
        .join_context_encrypted(CTX, &garbage_welcome, &add.event_log, &add.wrapping_keys)
        .expect_err("a malformed Welcome must be rejected");
    assert!(
        matches!(err, ClientError::Mls(_)),
        "a non-decodable Welcome fails at the MLS Welcome-processing layer, got: {err:?}"
    );

    // Fail-closed: Bob holds NO half-built context.
    assert_eq!(
        bob.client.member_dids(CTX),
        None,
        "a rejected Welcome must leave Bob holding NO context"
    );
    assert_eq!(bob.client.event_log_root(CTX), None);
    assert_eq!(bob.client.event_log_leaf_count(CTX), None);
    assert_eq!(bob.client.event_log_leaf_hashes(CTX), None);
}

// ===========================================================================
// 13. A failed join CONSUMES the in-memory pending material (single-use per
//     attempt); recovery is via reconstruct-from-durable, not in-memory reuse
// ===========================================================================

#[test]
fn failed_join_consumes_pending_and_recovers_only_via_reconstruct() {
    // (1) a failed join on a bad Welcome BURNS the in-memory pending, so a second
    // in-tab attempt gets `NoPendingJoinMaterial`; (2) recovery is via the PRISTINE
    // durable pending blob a failed join never deletes.
    let base = SystemClock.now_secs();
    let relay = Relay::new();
    let mut alice = relay.new_party(ALICE_DID, 0);
    // Bob over a CALLER-SUPPLIED storage handle, shared with the reconstructed
    // client below (the reconstruct-from-durable recovery path ADR-057 T2).
    let bob_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let bob_signer = Arc::new(LocalSigner::active(BOB_DID));
    let bob_clock: Arc<dyn Clock> = Arc::new(TestClock::new(base + 100));
    let mut bob = relay.party_with(bob_signer, Arc::clone(&bob_storage), bob_clock);

    alice.client.create_context(CTX).expect("Alice creates");
    let bob_kp = bob
        .client
        .generate_key_package_for_join(CTX)
        .expect("Bob key package"); // persists the durable pending blob
    let add = alice
        .client
        .add_member(CTX, &bob_kp)
        .expect("Alice adds Bob"); // a GOOD Welcome

    // First attempt: a BAD Welcome. It fails at Welcome processing AFTER the
    // in-memory pending was removed.
    let garbage_welcome = vec![0xEEu8; 48];
    let err = bob
        .client
        .join_context_encrypted(CTX, &garbage_welcome, &add.event_log, &add.wrapping_keys)
        .expect_err("the bad Welcome must be rejected");
    assert!(
        matches!(err, ClientError::Mls(_)),
        "bad Welcome, got: {err:?}"
    );
    assert_eq!(
        bob.client.member_dids(CTX),
        None,
        "the failed join left no half-built context"
    );

    // Second in-tab attempt with the GOOD Welcome: the in-memory pending was
    // CONSUMED, so this reports absent pending material — NOT a retry.
    match bob
        .client
        .join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
    {
        Err(ClientError::NoPendingJoinMaterial { context_id }) => assert_eq!(
            context_id, CTX,
            "the failed join burned the in-memory pending material (single-use per \
             attempt)"
        ),
        other => {
            panic!("expected NoPendingJoinMaterial on the second in-tab attempt, got {other:?}")
        }
    }

    // RECOVERY: a fresh client over Bob's SAME storage restores the still-durable
    // pending blob and the join now SUCCEEDS with the good Welcome.
    drop(bob);
    let recovered_signer = Arc::new(LocalSigner::active(BOB_DID));
    let recovered_clock: Arc<dyn Clock> = Arc::new(TestClock::new(base + 150));
    let mut bob2 = relay.party_with(recovered_signer, Arc::clone(&bob_storage), recovered_clock);
    assert_eq!(
        bob2.client.member_dids(CTX),
        None,
        "the reconstructed client has not joined yet"
    );
    bob2.client
        .join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
        .expect("reconstruct-from-durable restores pending material; the join succeeds");
    let mut members = bob2.client.member_dids(CTX).expect("bob2 is now a member");
    members.sort();
    assert_eq!(
        members,
        vec![ALICE_DID.to_owned(), BOB_DID.to_owned()],
        "the recovered join converged Bob into the two-member context"
    );
    assert_eq!(
        bob2.client.event_log_root(CTX),
        alice.client.event_log_root(CTX),
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
    // step and leave NO OBSERVABLE state change.
    let (relay, mut alice, mut bob) = converged_pair();

    // Alice adds Carol; Bob (bystander) processes the add-Commit so he reaches the
    // post-add epoch at which Alice's distributions were sealed.
    let mut carol = relay.new_party(CAROL_DID, 200);
    let carol_kp = carol
        .client
        .generate_key_package_for_join(CTX)
        .expect("Carol key package");
    let add_carol = alice
        .client
        .add_member(CTX, &carol_kp)
        .expect("Alice adds Carol");
    carol
        .client
        .join_context_encrypted(
            CTX,
            &add_carol.welcome,
            &add_carol.event_log,
            &add_carol.wrapping_keys,
        )
        .expect("Carol joins");
    bob.client
        .receive_message(CTX, &add_carol.commit)
        .expect("Bob processes the add-Carol Commit");
    let _ = bob.client.drain_events(CTX); // clear any buffered events from the commit processing
    let _ = relay.drain_publish_log(); // clear Alice's add re-announce frame

    // Alice's own add-seal targets Carol (sealed to Carol's wrapping key).
    assert_eq!(add_carol.sender_key_distributions.len(), 1);
    let alice_to_carol = &add_carol.sender_key_distributions[0];
    assert_eq!(
        alice_to_carol.target_did, CAROL_DID,
        "Alice's add-seal is addressed to Carol"
    );

    // Snapshot Bob's post-Commit state, then MISDIRECT Alice→Carol's seal to Bob.
    let before = StateSnapshot::capture(&bob.client, CTX);
    let err = bob
        .client
        .receive_message(CTX, &alice_to_carol.ciphertext)
        .expect_err("a distribution sealed to Carol must not open under Bob's key");
    // The outer MLS frame decrypts (Bob is at the sealing epoch), so the rejection is
    // specifically the inner HPKE-open failing under Bob's wrapping secret — a
    // sender-key-layer error, NOT an MLS-layer one.
    assert!(
        matches!(err, ClientError::SenderKey(_)),
        "the misdirected seal fails at the HPKE-open (sender-key) layer, got: {err:?}"
    );
    assert_eq!(
        StateSnapshot::capture(&bob.client, CTX),
        before,
        "a rejected misdirected distribution must leave epoch, membership, leaf \
         count, root, and leaf hashes UNCHANGED"
    );
    assert!(
        bob.client.drain_events(CTX).expect("drain").is_empty(),
        "a rejected misdirected distribution buffers no event"
    );

    // Non-wedging probe: Alice's existing sender key (installed during the connect)
    // still decrypts an honest message — the misdirected seal installed no key and
    // did not wedge Bob's receive path. (Alice fans this out to Bob's pseudonym,
    // which Alice already knows; Carol was NOT pumped, so the send addresses Bob.)
    alice
        .client
        .send_message(CTX, b"honest after misdirection")
        .expect("Alice sends");
    let honest = app_ciphertext(&relay, alice.conn, CTX);
    assert!(
        bob.client
            .receive_message(CTX, &honest)
            .expect("Bob still decrypts Alice's message")
            .application,
        "the misdirected distribution installed no key and did not wedge Bob's \
         receive path"
    );
}
