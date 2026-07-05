//! Two-participant end-to-end message exchange over the single-threaded SCP
//! participant driver (ADR-057 Slice 2).
//!
//! This is the Slice-2 milestone test: it drives two `ScpClient`s — Alice
//! (creator) and Bob (joiner) — through the full participant message path with
//! NO tokio, NO actors, NO `scp-runtime`. Everything runs synchronously on one
//! thread; the "relay" is the test harness handing one client's output bytes
//! directly to the other's input.
//!
//! It proves three properties:
//! 1. **End-to-end exchange works single-threaded over `scp-mls`** — Bob
//!    recovers Alice's exact plaintext through the §9.16 double-encryption
//!    pipeline.
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

use std::sync::Arc;

use scp_client::{LocalSigner, MemoryStorage, ScpClient, Storage};
use scp_clock::{Clock, SystemClock, TestClock};
use scp_protocol::context::membership::ContextEvent;

const CTX: &str = "ctx-adr057-slice2-two-party";
const ALICE_DID: &str = "did:key:z6MkAlice2PartyExchangeFixtureKeyAAAAAAAAAA";
const BOB_DID: &str = "did:key:z6MkBob2PartyExchangeFixtureKeyBBBBBBBBBBBB";

/// Builds a fresh client for `did` over a fixed-time clock. Each member's own
/// leaf timestamps come from its clock, and the convergent timestamp that must
/// match across members is bound into the message's authenticated AAD (so the
/// two clocks need not agree — but fixing them keeps the fixture deterministic).
fn client_for(did: &str, now_secs: u64) -> ScpClient {
    let signer = Arc::new(LocalSigner::active(did));
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(now_secs));
    // A fresh store restores nothing, so construction cannot fail here.
    ScpClient::new(signer, storage, clock).expect("construct fresh client")
}

#[test]
#[allow(clippy::too_many_lines)] // one end-to-end two-party scenario, read top-to-bottom
fn two_party_message_exchange_end_to_end() {
    // Seed from real now so every minted KeyPackage `Lifetime` stays valid
    // against openmls's un-injectable internal (real) clock (ADR-057 §Prereq-1
    // test-clock realism); a fixed past epoch would produce already-expired
    // KeyPackages.
    let base = SystemClock.now_secs();
    let alice_clock = base;
    // Deliberately give Bob a DIFFERENT local clock (a small distinct offset) to
    // prove convergence does not depend on the two members' clocks agreeing —
    // only on the convergent timestamp that travels with each message.
    let bob_clock = base + 100;

    // --- Alice creates the context (MLS group + first event-log leaf). ---
    let mut alice = client_for(ALICE_DID, alice_clock);
    alice
        .create_context(CTX)
        .expect("Alice creates the context");

    assert_eq!(
        alice.member_dids(CTX).as_deref(),
        Some(&[ALICE_DID.to_owned()][..])
    );
    assert_eq!(
        alice.event_log_leaf_count(CTX),
        Some(1),
        "creation appends exactly the ContextCreated leaf"
    );

    // --- Bob generates a KeyPackage for joining and hands the public bytes to
    // Alice (the matching private join material stays inside Bob's client). ---
    let mut bob = client_for(BOB_DID, bob_clock);
    let bob_key_package = bob
        .generate_key_package_for_join(CTX)
        .expect("Bob generates a key package");

    // --- Alice adds Bob → Commit (existing members) + Welcome (Bob) + a
    // MemberJoined leaf. The convergent committer timestamp rides on the
    // returned output. ---
    let add = alice
        .add_member(CTX, &bob_key_package)
        .expect("Alice adds Bob");

    let mut alice_members = alice.member_dids(CTX).expect("alice has members");
    alice_members.sort();
    assert_eq!(
        alice_members,
        vec![ALICE_DID.to_owned(), BOB_DID.to_owned()]
    );
    assert_eq!(alice.event_log_leaf_count(CTX), Some(2));

    // --- Bob joins from the Welcome and replays Alice's full prior log, so his
    // log reconstructs byte-identically (§7.3.1 context-state import). In a
    // two-member group Alice's Commit has no existing recipient to process. ---
    bob.join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.members)
        .expect("Bob joins from the Welcome");

    assert_eq!(
        bob.event_log_leaf_count(CTX),
        Some(2),
        "Bob replayed Alice's log: ContextCreated + MemberJoined"
    );
    assert_eq!(
        bob.event_log_root(CTX),
        alice.event_log_root(CTX),
        "after replay, Bob's root equals Alice's (full-log convergence)"
    );

    // --- Out-of-band sender-key exchange (the MISSING SEAM documented in the
    // crate root): the driver has no in-tab sender-key distribution path, so the
    // harness hands each side the other's sender key directly. ---
    let alice_sk = alice.local_sender_key_bytes(CTX).expect("alice sender key");
    let bob_sk = bob.local_sender_key_bytes(CTX).expect("bob sender key");
    bob.install_sender_key(CTX, ALICE_DID, alice_sk)
        .expect("Bob installs Alice's sender key");
    alice
        .install_sender_key(CTX, BOB_DID, bob_sk)
        .expect("Alice installs Bob's sender key");

    // === The convergent membership log is now settled: both members hold
    // [ContextCreated, MemberJoined] (2 leaves) with equal roots. Capture that
    // baseline — the message exchange below must NOT change it, because an
    // application message is NOT a convergent leaf (ADR-011 exclusion taxonomy §2:
    // `MessageSent` is per-author with no total delivery order). ===
    let alice_root_before = alice.event_log_root(CTX).expect("alice root");
    let bob_root_before = bob.event_log_root(CTX).expect("bob root");
    assert_eq!(alice.event_log_leaf_count(CTX), Some(2));
    assert_eq!(bob.event_log_leaf_count(CTX), Some(2));
    assert_eq!(
        alice_root_before, bob_root_before,
        "the membership log converged before any message"
    );

    // --- Alice sends an application message: sender-layer encrypt + plain MLS
    // encrypt (no AAD — ADR-011). The message is recorded as Alice's local
    // `MessageSent` history (buffered for drain), NOT as a convergent leaf, so the
    // returned value is just the ciphertext bytes and the event log is unchanged. ---
    let plaintext = b"hello from Alice over a single-threaded SCP client";
    let ciphertext = alice.send_message(CTX, plaintext).expect("Alice sends");

    assert_eq!(
        alice.event_log_leaf_count(CTX),
        Some(2),
        "a send stamps NO convergent leaf: Alice's log stays at created + joined"
    );
    assert_eq!(
        alice.event_log_root(CTX),
        Some(alice_root_before),
        "a send leaves the Merkle root unchanged (MessageSent is excluded from the log)"
    );

    // --- Bob receives + decrypts. This buffers a MessageReceived (local history),
    // NOT a convergent leaf, so Bob's event log is likewise unchanged. ---
    let was_application = bob
        .receive_message(CTX, &ciphertext)
        .expect("Bob receives the message");
    assert!(was_application, "Alice's send is an application message");

    assert_eq!(
        bob.event_log_leaf_count(CTX),
        Some(2),
        "a received message stamps NO convergent leaf: Bob's log stays at created + joined"
    );
    assert_eq!(
        bob.event_log_root(CTX),
        Some(bob_root_before),
        "a received message leaves Bob's Merkle root unchanged"
    );

    // --- The message surfaces via the pull-based buffers: Bob drains the
    // MessageReceived, and Alice drains her own MessageSent local history. ---
    let events = bob.drain_events(CTX).expect("Bob drains events");
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
    assert!(bob.drain_events(CTX).expect("re-drain ok").is_empty());

    let sent_events = alice.drain_events(CTX).expect("Alice drains her own send");
    assert_eq!(sent_events.len(), 1, "Alice buffered her own MessageSent");
    match &sent_events[0] {
        ContextEvent::MessageSent {
            sender_did,
            sequence_number,
            payload,
        } => {
            assert_eq!(sender_did.0, ALICE_DID, "the sender DID is Alice");
            assert_eq!(*sequence_number, 0, "Alice's first send is sequence 0");
            assert_eq!(payload.as_slice(), plaintext, "Alice's own sent plaintext");
        }
        other => panic!("expected MessageSent, got {other:?}"),
    }

    // === Convergence (§9.9.3): after the exchange, Alice and Bob still hold the
    // identical membership sequence [ContextCreated, MemberJoined] — the message
    // did not perturb it — so their leaf hashes are byte-identical AND their
    // Merkle roots are equal, despite their local clocks differing. ===
    let alice_leaves = alice.event_log_leaf_hashes(CTX).expect("alice leaves");
    let bob_leaves = bob.event_log_leaf_hashes(CTX).expect("bob leaves");

    assert_eq!(alice_leaves.len(), 2, "Alice: created + joined");
    assert_eq!(bob_leaves.len(), 2, "Bob: created + joined");
    assert_eq!(
        alice_leaves, bob_leaves,
        "every leaf hash is byte-identical across both members (convergence)"
    );
    assert_eq!(
        alice.event_log_root(CTX),
        bob.event_log_root(CTX),
        "the Merkle roots converge byte-for-byte (§9.9.3)"
    );

    // --- Close tears down crypto state on both sides. ---
    alice.close_context(CTX).expect("Alice closes");
    bob.close_context(CTX).expect("Bob closes");
    assert_eq!(alice.member_dids(CTX), None, "context is gone after close");
}
