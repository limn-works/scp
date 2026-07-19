//! Two-participant end-to-end message exchange over the single-threaded SCP
//! participant driver (ADR-057 Slice 2, transport slice).
//!
//! This is the Slice-2 milestone test: it drives two `ScpClient`s — Alice
//! (creator) and Bob (joiner) — through the full participant message path with
//! NO tokio, NO actors, NO `scp-runtime`. Everything runs synchronously on one
//! thread over the REALISTIC in-memory relay mock (`tests/common`): each client's
//! injected `RelaySink` forwards its `SUBSCRIBE`/`PUBLISH` frames into the shared
//! `Relay`, and `Relay::pump` delivers the queued `BLOB`s back into each party's
//! `handle_relay_frame` — iteratively until quiescent, so the §9.10.4
//! reciprocal-announce cascade completes exactly as it would over a live relay.
//!
//! It proves three properties:
//! 1. **End-to-end exchange works single-threaded over `scp-mls`** — Bob
//!    recovers Alice's exact plaintext through the §9.16 double-encryption
//!    pipeline, fanned out over the relay (ADR-057 transport slice).
//! 2. **Membership-log convergence by shared code, unperturbed by messages** —
//!    after the joiner replays the adder's log, both members hold a byte-identical
//!    membership sequence [`ContextCreated`, `MemberJoined`] (every leaf hash AND
//!    the Merkle root match), the §9.9.3 convergence property. This holds because
//!    both sides run the same `scp-event-log` append logic over the same
//!    committer-assigned inputs (committer DID + the convergent timestamp bound
//!    into the add-Commit's authenticated MLS AAD and adopted verbatim from the
//!    verified frame, ADR-057), even though their local clocks deliberately
//!    differ. A subsequent application-message exchange leaves this log and its
//!    root **unchanged** — `MessageSent` is excluded from the convergent Merkle
//!    log (ADR-011 exclusion taxonomy §2), so it is local history, not a leaf.
//! 3. **Pull-based buffers** — Bob drains a `MessageReceived` and Alice drains
//!    her own `MessageSent`, each carrying the (decrypted) plaintext.

// Integration tests assert on happy-path results; `expect`/`panic!` make the
// failure messages legible. The workspace denies these in production code.
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use common::{Relay, RelayExt};
use scp_protocol::context::context_routing_id;
use scp_protocol::context::membership::ContextEvent;

const CTX: &str = "ctx-adr057-slice2-two-party";
const ALICE_DID: &str = "did:key:z6MkAlice2PartyExchangeFixtureKeyAAAAAAAAAA";
const BOB_DID: &str = "did:key:z6MkBob2PartyExchangeFixtureKeyBBBBBBBBBBBB";

#[test]
#[allow(clippy::too_many_lines)] // one end-to-end two-party scenario, read top-to-bottom
fn two_party_message_exchange_end_to_end() {
    // `relay.new_party` seeds each client's fixed clock from real `now` + the given
    // offset, so every minted KeyPackage `Lifetime` stays valid against openmls's
    // un-injectable internal (real) clock (ADR-057 §Prereq-1 test-clock realism);
    // a fixed past epoch would produce already-expired KeyPackages. Bob gets a
    // DIFFERENT offset (a small distinct value) to prove convergence does not
    // depend on the two members' clocks agreeing — only on the convergent
    // timestamp that travels with each message.
    let relay = Relay::new();

    // --- Alice creates the context (MLS group + first event-log leaf). ---
    let mut alice = relay.new_party(ALICE_DID, 0);
    alice
        .client
        .create_context(CTX)
        .expect("Alice creates the context");

    assert_eq!(
        alice.client.member_dids(CTX).as_deref(),
        Some(&[ALICE_DID.to_owned()][..])
    );
    assert_eq!(
        alice.client.event_log_leaf_count(CTX),
        Some(1),
        "creation appends exactly the ContextCreated leaf"
    );

    // --- Bob generates a KeyPackage for joining and hands the public bytes to
    // Alice (the matching private join material stays inside Bob's client). ---
    let mut bob = relay.new_party(BOB_DID, 100);
    let bob_key_package = bob
        .client
        .generate_key_package_for_join(CTX)
        .expect("Bob generates a key package");

    // --- Alice adds Bob → Commit (existing members) + Welcome (Bob) + a
    // MemberJoined leaf. The convergent committer timestamp rides on the
    // returned output. `add_member` does NOT announce (new semantics — the mesh
    // completes via joiner-seed + reciprocal, pumped below). ---
    let add = alice
        .client
        .add_member(CTX, &bob_key_package)
        .expect("Alice adds Bob");

    let mut alice_members = alice.client.member_dids(CTX).expect("alice has members");
    alice_members.sort();
    assert_eq!(
        alice_members,
        vec![ALICE_DID.to_owned(), BOB_DID.to_owned()]
    );
    assert_eq!(alice.client.event_log_leaf_count(CTX), Some(2));

    // --- Bob joins from the Welcome and replays Alice's full prior log, so his
    // log reconstructs byte-identically (§7.3.1 context-state import). In a
    // two-member group Alice's Commit has no existing recipient to process. The
    // join returns Bob's sender-key distributions (Bob → each existing member)
    // and announces Bob's pseudonym over the relay (the reciprocal-announce seed). ---
    let bob_distributions = bob
        .client
        .join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
        .expect("Bob joins from the Welcome");

    assert_eq!(
        bob.client.event_log_leaf_count(CTX),
        Some(2),
        "Bob replayed Alice's log: ContextCreated + MemberJoined"
    );
    assert_eq!(
        bob.client.event_log_root(CTX),
        alice.client.event_log_root(CTX),
        "after replay, Bob's root equals Alice's (full-log convergence)"
    );

    // --- In-tab sender-key distribution (§9.16.1/§9.16.2): NO out-of-band
    // exchange. Alice's add sealed her key to Bob; Bob's join sealed his key to
    // Alice. Each distribution is delivered DIRECTLY to its target's
    // receive_message (not over the relay — the transport slice routes app data
    // + pseudonym announcements, not sender-key distributions), which HPKE-opens
    // and installs it. ---
    assert_eq!(add.sender_key_distributions.len(), 1, "Alice → Bob");
    assert_eq!(add.sender_key_distributions[0].target_did, BOB_DID);
    let bob_install = bob
        .client
        .receive_message(CTX, &add.sender_key_distributions[0].ciphertext)
        .expect("Bob installs Alice's sender key from the distribution");
    assert!(
        !bob_install.application,
        "a sender-key distribution is not an application message"
    );
    assert!(
        bob_install.sender_key_distributions.is_empty(),
        "installing a key triggers no further distribution"
    );

    assert_eq!(bob_distributions.len(), 1, "Bob → Alice");
    assert_eq!(bob_distributions[0].target_did, ALICE_DID);
    let alice_install = alice
        .client
        .receive_message(CTX, &bob_distributions[0].ciphertext)
        .expect("Alice installs Bob's sender key from the distribution");
    assert!(!alice_install.application);
    assert!(alice_install.sender_key_distributions.is_empty());

    // --- Pump the reciprocal-announce cascade to quiescence so both peer
    // registries populate: app-data `send_message` in a multi-member context
    // fans out ONLY to announced peers (an empty registry fails closed). Bob's
    // join-announce (captured over the relay above) reaches Alice, who records it
    // and reciprocates; Bob then records Alice. Both sender keys are installed, so
    // every announcement decrypts at its intended audience. ---
    relay.pump(&mut [&mut alice, &mut bob]);
    // Drain the resulting PseudonymAnnounced events + residual publish records so
    // the message exchange below is the ONLY thing each buffer carries.
    let _ = alice.client.drain_events(CTX);
    let _ = bob.client.drain_events(CTX);
    let _ = relay.drain_publish_log();

    // === The convergent membership log is now settled: both members hold
    // [ContextCreated, MemberJoined] (2 leaves) with equal roots. Capture that
    // baseline — the message exchange below must NOT change it, because an
    // application message is NOT a convergent leaf (ADR-011 exclusion taxonomy §2:
    // `MessageSent` is per-author with no total delivery order). ===
    let alice_root_before = alice.client.event_log_root(CTX).expect("alice root");
    let bob_root_before = bob.client.event_log_root(CTX).expect("bob root");
    assert_eq!(alice.client.event_log_leaf_count(CTX), Some(2));
    assert_eq!(bob.client.event_log_leaf_count(CTX), Some(2));
    assert_eq!(
        alice_root_before, bob_root_before,
        "the membership log converged before any message"
    );

    // --- Alice sends an application message: sender-layer encrypt + plain MLS
    // encrypt (no AAD — ADR-011), then fan out over the relay as one `PUBLISH`
    // per announced peer (here: Bob). The message is recorded as Alice's local
    // `MessageSent` history (buffered for drain), NOT as a convergent leaf, so
    // `send_message` returns `()` and the event log is unchanged. ---
    let plaintext = b"hello from Alice over a single-threaded SCP client";
    alice
        .client
        .send_message(CTX, plaintext)
        .expect("Alice sends");

    assert_eq!(
        alice.client.event_log_leaf_count(CTX),
        Some(2),
        "a send stamps NO convergent leaf: Alice's log stays at created + joined"
    );
    assert_eq!(
        alice.client.event_log_root(CTX),
        Some(alice_root_before),
        "a send leaves the Merkle root unchanged (MessageSent is excluded from the log)"
    );

    // Alice's app-data send fanned out exactly one PUBLISH to Bob's pseudonym (one
    // announced peer), and NEVER to the shared announcement channel.
    let app_publish_count = relay
        .drain_publish_log()
        .into_iter()
        .filter(|p| p.conn == alice.conn && p.routing_id != context_routing_id(CTX))
        .count();
    assert_eq!(
        app_publish_count, 1,
        "Alice's app-data send fanned out exactly one PUBLISH to Bob's pseudonym"
    );

    // --- Bob receives + decrypts by pumping Alice's queued PUBLISH into his
    // `handle_relay_frame` as a relay BLOB. This buffers a MessageReceived
    // (local history), NOT a convergent leaf, so Bob's event log is likewise
    // unchanged. ---
    relay.pump(&mut [&mut alice, &mut bob]);

    assert_eq!(
        bob.client.event_log_leaf_count(CTX),
        Some(2),
        "a received message stamps NO convergent leaf: Bob's log stays at created + joined"
    );
    assert_eq!(
        bob.client.event_log_root(CTX),
        Some(bob_root_before),
        "a received message leaves Bob's Merkle root unchanged"
    );

    // --- The message surfaces via the pull-based buffers: Bob drains the
    // MessageReceived (an application message that decrypted under Alice's
    // installed sender key), and Alice drains her own MessageSent local history.
    // Announcements were drained above, so each buffer carries exactly one. ---
    let events = bob.client.drain_events(CTX).expect("Bob drains events");
    assert_eq!(events.len(), 1, "exactly one received event is buffered");
    match &events[0] {
        ContextEvent::MessageReceived {
            sender_did,
            payload,
        } => {
            assert_eq!(sender_did.0, ALICE_DID, "the sender DID is Alice");
            assert_eq!(
                payload.as_slice(),
                plaintext,
                "Bob recovered Alice's exact plaintext"
            );
        }
        other => panic!("expected MessageReceived, got {other:?}"),
    }
    // Draining again yields nothing (pull-based, FIFO, consumed).
    assert!(
        bob.client
            .drain_events(CTX)
            .expect("re-drain ok")
            .is_empty()
    );

    let sent_events = alice
        .client
        .drain_events(CTX)
        .expect("Alice drains her own send");
    assert_eq!(sent_events.len(), 1, "Alice buffered her own MessageSent");
    match &sent_events[0] {
        ContextEvent::MessageSent {
            sender_did,
            sequence_number,
            payload,
        } => {
            assert_eq!(sender_did.0, ALICE_DID, "the sender DID is Alice");
            // Alice's per-sender sequence counter is drawn by EVERY fan-out,
            // including the §9.10.4 RECIPROCAL pseudonym announcement Alice emitted
            // when she learned Bob during the pump above (which consumed sequence 0).
            // So her first app-data `MessageSent` is sequence 1 — the counter is
            // monotonic across announcements + app data.
            assert_eq!(
                *sequence_number, 1,
                "Alice's first app-data send is sequence 1 (the reciprocal announcement took 0)"
            );
            assert_eq!(payload.as_slice(), plaintext, "Alice's own sent plaintext");
        }
        other => panic!("expected MessageSent, got {other:?}"),
    }

    // === Convergence (§9.9.3): after the exchange, Alice and Bob still hold the
    // identical membership sequence [ContextCreated, MemberJoined] — the message
    // did not perturb it — so their leaf hashes are byte-identical AND their
    // Merkle roots are equal, despite their local clocks differing. ===
    let alice_leaves = alice
        .client
        .event_log_leaf_hashes(CTX)
        .expect("alice leaves");
    let bob_leaves = bob.client.event_log_leaf_hashes(CTX).expect("bob leaves");

    assert_eq!(alice_leaves.len(), 2, "Alice: created + joined");
    assert_eq!(bob_leaves.len(), 2, "Bob: created + joined");
    assert_eq!(
        alice_leaves, bob_leaves,
        "every leaf hash is byte-identical across both members (convergence)"
    );
    assert_eq!(
        alice.client.event_log_root(CTX),
        bob.client.event_log_root(CTX),
        "the Merkle roots converge byte-for-byte (§9.9.3)"
    );

    // --- Close tears down crypto state on both sides. ---
    alice.client.close_context(CTX).expect("Alice closes");
    bob.client.close_context(CTX).expect("Bob closes");
    assert_eq!(
        alice.client.member_dids(CTX),
        None,
        "context is gone after close"
    );
}
