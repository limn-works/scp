//! Multi-party event-log convergence over the single-threaded SCP participant
//! driver (ADR-057 Slice 2), with application-message delivery over the REALISTIC
//! relay mock (`tests/common`) — the shipped relay's subscribe-timing, self-echo,
//! and reciprocal-announce semantics (ADR-057 transport slice).
//!
//! SCP contexts are inherently multi-party. This test exercises the property a
//! 2-party test cannot: when an EXISTING member processes an MLS Commit that
//! ADDS a new member, that existing member must append the identical convergent
//! `MemberJoined` leaf the committer appended and the new joiner replayed — so
//! all three members' event-log Merkle roots and membership sets converge.
//!
//! It proves two things the 2-party test left unproven:
//!
//! 1. **Existing-member add-Commit convergence** — Alice creates, adds Bob,
//!    then adds Carol. Bob (an existing member, not the committer, not the
//!    joiner) processes Alice's add-Carol Commit and converges his event-log
//!    root + membership to Alice's and Carol's, adopting the committer's
//!    authenticated `MemberJoined` timestamp **verbatim** (ADR-057). This is the
//!    regression test for the multi-party divergence bug: pre-fix, Bob's Control
//!    arm dropped the add and his log/membership permanently diverged.
//!
//! 2. **Application messages do NOT perturb the convergent log** — a reciprocal
//!    Bob → Alice/Carol send. `MessageSent` is excluded from the convergent
//!    Merkle log (ADR-011 exclusion taxonomy §2: per-author, no total delivery
//!    order), so a send stamps no leaf on any member: every member's root is
//!    unchanged by the exchange, while the plaintext still delivers via the
//!    pull-based buffers. Convergence is a property of the membership log alone.
//!
//! Membership-log convergence (adds/joins/commits + the §9.16 sender-key
//! distributions that seal them) is unaffected by the transport change and is
//! still driven directly through the returned structs. Only application-message
//! DELIVERY moved onto the relay: `send_message` now fans out relay `PUBLISH`
//! frames to each peer's pseudonym instead of returning a ciphertext, so a send
//! requires the recipients' pseudonyms in the sender's registry (populated by
//! pumping the §9.10.4 reciprocal-announce mesh to quiescence with
//! [`Relay::pump`]), and receipt is observed by pumping the relay and draining the
//! recipient's buffers. The §9.16 sender-key distributions are still delivered
//! DIRECTLY via `receive_message` (the out-of-band model — never over the relay,
//! which carries only app data + announcements).

// Integration tests assert on happy-path results; `expect`/`panic!` make the
// failure messages legible. The workspace denies these in production code.
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use scp_client::{ClientError, ContextStatus, ScpClient, SenderKeyDistribution};
use scp_clock::{Clock, SystemClock};
use scp_protocol::context::context_routing_id;
use scp_protocol::context::membership::ContextEvent;

const CTX: &str = "ctx-adr057-slice2-multi-party";
const ALICE_DID: &str = "did:key:z6MkAliceMultiPartyFixtureKeyAAAAAAAAAAAAAA";
const BOB_DID: &str = "did:key:z6MkBobMultiPartyFixtureKeyBBBBBBBBBBBBBBBB";
const CAROL_DID: &str = "did:key:z6MkCarolMultiPartyFixtureKeyCCCCCCCCCCCCCC";

// Distinct per-member clock offsets applied to a shared real-time base. Kept
// small (seconds) so every minted KeyPackage `Lifetime` stays valid against
// openmls's un-injectable internal (real) clock, while remaining pairwise
// distinct — the convergence property depends only on the clocks *differing*,
// not on their magnitude (ADR-057 §Prereq-1 test-clock realism). `Relay::new_party`
// seeds each clock from `SystemClock.now_secs()` (instead of a fixed past epoch),
// keeping the minted KeyPackages inside openmls's acceptance window at test time.
const ALICE_OFFSET: u64 = 0;
const BOB_OFFSET: u64 = 100;
const CAROL_OFFSET: u64 = 200;

/// Routes each in-tab sender-key distribution to its target client and asserts
/// the install is a no-op receive (no application payload, no cascade). This is
/// the real §9.16.1/§9.16.2 distribution path — delivered DIRECTLY via
/// `receive_message` (not over the relay, which carries only app data +
/// announcements). There is no out-of-band exchange (`install_sender_key` /
/// `local_sender_key_bytes` no longer exist on `ScpClient`).
fn deliver3(
    dists: &[SenderKeyDistribution],
    alice: &mut ScpClient,
    bob: &mut ScpClient,
    carol: &mut ScpClient,
) {
    for d in dists {
        let out = match d.target_did.as_str() {
            ALICE_DID => alice.receive_message(CTX, &d.ciphertext),
            BOB_DID => bob.receive_message(CTX, &d.ciphertext),
            CAROL_DID => carol.receive_message(CTX, &d.ciphertext),
            other => panic!("unexpected distribution target {other}"),
        }
        .expect("install distribution");
        assert!(
            !out.application,
            "a sender-key distribution is not an application message"
        );
        assert!(
            out.sender_key_distributions.is_empty(),
            "installing a distribution triggers no further distribution"
        );
    }
}

/// Extracts the inner MLS ciphertext of the last app-data `PUBLISH` `conn`
/// published to `relay` — the exact wire bytes a peer's `receive_message`
/// consumes. App data fans out to peer pseudonyms, so it filters out the shared
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

#[test]
#[allow(clippy::too_many_lines)] // one end-to-end three-party scenario, read top-to-bottom
fn three_party_add_commit_converges_across_all_members() {
    // Three deliberately different local clocks: convergence must NOT depend on
    // them agreeing — only on the convergent timestamp transported with each
    // commit/message.
    let relay = Relay::new();
    let mut alice = relay.new_party(ALICE_DID, ALICE_OFFSET);
    let mut bob = relay.new_party(BOB_DID, BOB_OFFSET);
    let mut carol = relay.new_party(CAROL_DID, CAROL_OFFSET);

    // --- Alice creates the context. ---
    alice.client.create_context(CTX).expect("Alice creates");

    // --- Alice adds Bob. Bob joins via the Welcome + replay. The add seals
    // Alice's sender key to Bob; the join seals Bob's key to Alice — route both. ---
    let bob_kp = bob
        .client
        .generate_key_package_for_join(CTX)
        .expect("Bob key package");
    let add_bob = alice
        .client
        .add_member(CTX, &bob_kp)
        .expect("Alice adds Bob");
    let bob_join_dists = bob
        .client
        .join_context_encrypted(
            CTX,
            &add_bob.welcome,
            &add_bob.event_log,
            &add_bob.wrapping_keys,
        )
        .expect("Bob joins");
    deliver3(
        &add_bob.sender_key_distributions,
        &mut alice.client,
        &mut bob.client,
        &mut carol.client,
    );
    deliver3(
        &bob_join_dists,
        &mut alice.client,
        &mut bob.client,
        &mut carol.client,
    );

    assert_eq!(
        bob.client.event_log_root(CTX),
        alice.client.event_log_root(CTX),
        "after the first add, Bob converges to Alice"
    );

    // Complete the epoch-1 (Alice+Bob) reciprocal-announce mesh BEFORE the next
    // add advances the MLS epoch: a §9.16 announcement sealed at this epoch is a
    // dead frame once its recipient ratchets past it (MLS forward secrecy), so the
    // pump must consume the queued join-announcements now. Draining the bootstrap
    // `PseudonymAnnounced` events + the publish log leaves a clean baseline.
    relay.pump(&mut [&mut alice, &mut bob]);
    let _ = alice.client.drain_events(CTX);
    let _ = bob.client.drain_events(CTX);
    let _ = relay.drain_publish_log();

    // --- Alice adds Carol. This is the multi-party case: Alice's add-Carol
    // Commit must be processed by the EXISTING member Bob, who has to append the
    // identical MemberJoined(Carol) leaf — not silently drop it. ---
    let carol_kp = carol
        .client
        .generate_key_package_for_join(CTX)
        .expect("Carol key package");
    let add_carol = alice
        .client
        .add_member(CTX, &carol_kp)
        .expect("Alice adds Carol");

    // Carol joins from the Welcome, replaying Alice's full log (which now
    // includes both MemberJoined leaves). The join seals Carol's key to every
    // existing member (Alice + Bob).
    let carol_join_dists = carol
        .client
        .join_context_encrypted(
            CTX,
            &add_carol.welcome,
            &add_carol.event_log,
            &add_carol.wrapping_keys,
        )
        .expect("Carol joins");

    // Bob (existing member) processes Alice's add-Carol Commit. The convergent
    // committer timestamp is bound into the Commit's authenticated AAD (ADR-057),
    // so Bob recovers it from the verified frame — no separate value is
    // transported. `application` is `false` (no application payload), but its side
    // effects — appending the convergent MemberJoined leaf, recording Carol, AND
    // sealing Bob's OWN sender key to Carol (the bystander re-distribution,
    // INVARIANT 2) — are what make Bob converge and let Carol decrypt Bob. (The
    // Commit is delivered directly, not over the relay, which carries only app
    // data + announcements.)
    let bob_recv = bob
        .client
        .receive_message(CTX, &add_carol.commit)
        .expect("Bob processes the add-Carol commit");
    assert!(
        !bob_recv.application,
        "an add-Commit carries no application payload"
    );
    assert_eq!(
        bob_recv.sender_key_distributions.len(),
        1,
        "the bystander seals its own key to the newly-added member (INVARIANT 2)"
    );
    assert_eq!(bob_recv.sender_key_distributions[0].target_did, CAROL_DID);

    // Every member is now at the post-add MLS epoch (Alice via the add, Carol via
    // the Welcome, Bob via the Commit), so the epoch-N distributions all decrypt.
    // (A distribution is an MLS application frame bound to the epoch it was sealed
    // at; deliver only AFTER the recipient reached that epoch.)
    deliver3(
        &add_carol.sender_key_distributions,
        &mut alice.client,
        &mut bob.client,
        &mut carol.client,
    );
    deliver3(
        &carol_join_dists,
        &mut alice.client,
        &mut bob.client,
        &mut carol.client,
    );
    deliver3(
        &bob_recv.sender_key_distributions,
        &mut alice.client,
        &mut bob.client,
        &mut carol.client,
    );

    // === All three members converge: identical leaf count, identical leaf
    // hashes, identical Merkle root, identical membership set. ===
    assert_eq!(
        alice.client.event_log_leaf_count(CTX),
        Some(3),
        "Alice: ContextCreated + MemberJoined(Bob) + MemberJoined(Carol)"
    );
    assert_eq!(
        bob.client.event_log_leaf_count(CTX),
        Some(3),
        "Bob converged to 3 leaves after processing the add-Carol commit"
    );
    assert_eq!(
        carol.client.event_log_leaf_count(CTX),
        Some(3),
        "Carol replayed all 3 leaves"
    );

    let alice_root = alice.client.event_log_root(CTX).expect("alice root");
    let bob_root = bob.client.event_log_root(CTX).expect("bob root");
    let carol_root = carol.client.event_log_root(CTX).expect("carol root");
    assert_eq!(alice_root, bob_root, "Alice and Bob roots converge");
    assert_eq!(alice_root, carol_root, "Alice and Carol roots converge");

    let alice_leaves = alice
        .client
        .event_log_leaf_hashes(CTX)
        .expect("alice leaves");
    let bob_leaves = bob.client.event_log_leaf_hashes(CTX).expect("bob leaves");
    let carol_leaves = carol
        .client
        .event_log_leaf_hashes(CTX)
        .expect("carol leaves");
    assert_eq!(
        alice_leaves, bob_leaves,
        "every leaf hash is byte-identical between Alice and Bob"
    );
    assert_eq!(
        alice_leaves, carol_leaves,
        "every leaf hash is byte-identical between Alice and Carol"
    );

    // Membership sets converge (order-insensitive).
    let mut alice_members = alice.client.member_dids(CTX).expect("alice members");
    let mut bob_members = bob.client.member_dids(CTX).expect("bob members");
    let mut carol_members = carol.client.member_dids(CTX).expect("carol members");
    alice_members.sort();
    bob_members.sort();
    carol_members.sort();
    let expected = {
        let mut v = vec![
            ALICE_DID.to_owned(),
            BOB_DID.to_owned(),
            CAROL_DID.to_owned(),
        ];
        v.sort();
        v
    };
    assert_eq!(alice_members, expected, "Alice sees all three members");
    assert_eq!(
        bob_members, expected,
        "Bob's membership converged to all three"
    );
    assert_eq!(carol_members, expected, "Carol sees all three members");

    // === In-tab distribution is now complete: every member holds every peer's
    // §9.16 sender key, delivered ONLY over the wrapping-key extension mesh above
    // (no out-of-band exchange). Now pump the §9.10.4 announcements so Alice's peer
    // registry holds Bob + Carol — a prerequisite for the fan-out send: a
    // multi-member app-data send requires the recipients' pseudonyms in the
    // sender's registry (else `PseudonymRegistryEmpty`). A message Alice sends then
    // fans out to BOTH Bob and Carol and decrypts under the distributed key at
    // each. Draining every buffer + the publish log leaves a clean baseline. ===
    relay.pump(&mut [&mut alice, &mut bob, &mut carol]);
    let _ = alice.client.drain_events(CTX);
    let _ = bob.client.drain_events(CTX);
    let _ = carol.client.drain_events(CTX);
    let _ = relay.drain_publish_log();

    alice
        .client
        .send_message(CTX, b"post-convergence chatter")
        .expect("Alice sends");
    // The fan-out published one frame per peer; pump the relay so each peer
    // receives only the frame addressed to its pseudonym.
    relay.pump(&mut [&mut alice, &mut bob, &mut carol]);

    // Both recipients recovered Alice's exact plaintext via the pull buffers — the
    // socket-path equivalent of the old `receive_message(..).application` assertion:
    // a `MessageReceived` only surfaces on a successful application-frame decrypt
    // under the distributed sender key.
    for (who, client) in [("Bob", &mut bob.client), ("Carol", &mut carol.client)] {
        let drained = client.drain_events(CTX).expect("drain");
        assert_eq!(
            drained.len(),
            1,
            "{who} buffered exactly one received message"
        );
        match &drained[0] {
            ContextEvent::MessageReceived {
                sender_did,
                payload,
            } => {
                assert_eq!(sender_did.0, ALICE_DID);
                assert_eq!(payload.as_slice(), b"post-convergence chatter");
            }
            other => panic!("{who}: expected MessageReceived, got {other:?}"),
        }
    }

    // A subsequent application message must NOT perturb any member's convergent
    // log: `MessageSent` is excluded from the Merkle log (ADR-011), so every
    // member's leaf count and root are unchanged after a send + its receives.
    assert_eq!(
        alice.client.event_log_leaf_count(CTX),
        Some(3),
        "send stamps no leaf"
    );
    assert_eq!(
        bob.client.event_log_leaf_count(CTX),
        Some(3),
        "receive stamps no leaf"
    );
    assert_eq!(
        carol.client.event_log_leaf_count(CTX),
        Some(3),
        "receive stamps no leaf"
    );
    assert_eq!(
        alice.client.event_log_root(CTX),
        Some(alice_root),
        "a send leaves every member's Merkle root unchanged"
    );
    assert_eq!(bob.client.event_log_root(CTX), Some(bob_root));
    assert_eq!(carol.client.event_log_root(CTX), Some(carol_root));
}

#[test]
#[allow(clippy::too_many_lines)] // one end-to-end three-party scenario, read top-to-bottom
fn reciprocal_send_does_not_perturb_the_convergent_log() {
    // Distinct clocks across all three members. A reciprocal Bob → Alice/Carol
    // send must NOT change any member's convergent Merkle log: `MessageSent` is
    // excluded from that log (ADR-011 exclusion taxonomy §2), so the message is
    // local history, delivered via the pull-based buffers, not a leaf. This is the
    // corrected T3 property: the send-side event-log convergence the pre-reframe
    // test asserted was itself a §9.9.3 violation (per-author, no total order).
    let relay = Relay::new();
    let mut alice = relay.new_party(ALICE_DID, ALICE_OFFSET);
    let mut bob = relay.new_party(BOB_DID, BOB_OFFSET);
    let mut carol = relay.new_party(CAROL_DID, CAROL_OFFSET);

    alice.client.create_context(CTX).expect("Alice creates");

    let bob_kp = bob
        .client
        .generate_key_package_for_join(CTX)
        .expect("Bob key package");
    let add_bob = alice
        .client
        .add_member(CTX, &bob_kp)
        .expect("Alice adds Bob");
    let bob_join_dists = bob
        .client
        .join_context_encrypted(
            CTX,
            &add_bob.welcome,
            &add_bob.event_log,
            &add_bob.wrapping_keys,
        )
        .expect("Bob joins");
    deliver3(
        &add_bob.sender_key_distributions,
        &mut alice.client,
        &mut bob.client,
        &mut carol.client,
    );
    deliver3(
        &bob_join_dists,
        &mut alice.client,
        &mut bob.client,
        &mut carol.client,
    );

    // Complete the epoch-1 announce mesh before advancing the epoch (see the
    // sibling test): a §9.16 announcement sealed here is dead once its recipient
    // ratchets past it. Drain to a clean baseline.
    relay.pump(&mut [&mut alice, &mut bob]);
    let _ = alice.client.drain_events(CTX);
    let _ = bob.client.drain_events(CTX);
    let _ = relay.drain_publish_log();

    let carol_kp = carol
        .client
        .generate_key_package_for_join(CTX)
        .expect("Carol key package");
    let add_carol = alice
        .client
        .add_member(CTX, &carol_kp)
        .expect("Alice adds Carol");
    let carol_join_dists = carol
        .client
        .join_context_encrypted(
            CTX,
            &add_carol.welcome,
            &add_carol.event_log,
            &add_carol.wrapping_keys,
        )
        .expect("Carol joins");
    let bob_recv = bob
        .client
        .receive_message(CTX, &add_carol.commit)
        .expect("Bob processes the add-Carol commit");
    // Deliver only after every member reached the post-add epoch (see the sibling
    // test for why: a distribution is bound to the epoch it was sealed at).
    deliver3(
        &add_carol.sender_key_distributions,
        &mut alice.client,
        &mut bob.client,
        &mut carol.client,
    );
    deliver3(
        &carol_join_dists,
        &mut alice.client,
        &mut bob.client,
        &mut carol.client,
    );
    deliver3(
        &bob_recv.sender_key_distributions,
        &mut alice.client,
        &mut bob.client,
        &mut carol.client,
    );

    // All three converge on the membership log before any application message:
    // [ContextCreated, MemberJoined(Bob), MemberJoined(Carol)] = 3 leaves.
    let alice_root = alice.client.event_log_root(CTX).expect("alice root");
    assert_eq!(
        alice_root,
        bob.client.event_log_root(CTX).expect("bob root")
    );
    assert_eq!(
        alice_root,
        carol.client.event_log_root(CTX).expect("carol root")
    );
    assert_eq!(alice.client.event_log_leaf_count(CTX), Some(3));

    // Pump the §9.10.4 announcements so Bob's registry holds Alice + Carol — the
    // prerequisite for his fan-out send below. Drain to a clean baseline.
    relay.pump(&mut [&mut alice, &mut bob, &mut carol]);
    let _ = alice.client.drain_events(CTX);
    let _ = bob.client.drain_events(CTX);
    let _ = carol.client.drain_events(CTX);
    let _ = relay.drain_publish_log();

    // --- BOB sends (plain-encrypted; no AAD, no leaf). Every member holds Bob's
    // sender key via the in-tab distribution mesh above, and Bob's registry holds
    // both peers, so the send fans out to Alice and Carol. ---
    let plaintext = b"hello from Bob, not a convergent leaf";
    bob.client.send_message(CTX, plaintext).expect("Bob sends");
    // Pump Bob's fan-out (one frame per peer) into Alice and Carol.
    relay.pump(&mut [&mut alice, &mut bob, &mut carol]);

    // NO member's log changed: the send stamped no leaf on Bob, and the receives
    // stamped no leaf on Alice/Carol. Every root is exactly the pre-send root.
    assert_eq!(
        alice.client.event_log_leaf_count(CTX),
        Some(3),
        "still created + joined(Bob) + joined(Carol) — the message is not a leaf"
    );
    assert_eq!(bob.client.event_log_leaf_count(CTX), Some(3));
    assert_eq!(carol.client.event_log_leaf_count(CTX), Some(3));
    assert_eq!(
        alice.client.event_log_root(CTX),
        Some(alice_root),
        "Alice's root is unchanged by receiving a message"
    );
    assert_eq!(
        bob.client.event_log_root(CTX),
        Some(alice_root),
        "Bob's root unchanged by sending"
    );
    assert_eq!(carol.client.event_log_root(CTX), Some(alice_root));

    // Alice and Carol each recovered Bob's exact plaintext via the pull buffers
    // (the socket-path equivalent of the old `receive_message(..).application`
    // assertion — a `MessageReceived` only surfaces on a successful application
    // decrypt under Bob's distributed sender key).
    let alice_events = alice.client.drain_events(CTX).expect("alice drains");
    assert_eq!(alice_events.len(), 1);
    match &alice_events[0] {
        ContextEvent::MessageReceived {
            sender_did,
            payload,
        } => {
            assert_eq!(sender_did.0, BOB_DID, "sender is Bob");
            assert_eq!(payload.as_slice(), plaintext);
        }
        other => panic!("expected MessageReceived, got {other:?}"),
    }
    let carol_events = carol.client.drain_events(CTX).expect("carol drains");
    assert_eq!(carol_events.len(), 1);
    match &carol_events[0] {
        ContextEvent::MessageReceived {
            sender_did,
            payload,
        } => {
            assert_eq!(sender_did.0, BOB_DID, "sender is Bob");
            assert_eq!(payload.as_slice(), plaintext);
        }
        other => panic!("expected MessageReceived, got {other:?}"),
    }

    // Bob drained his own MessageSent.
    let bob_events = bob.client.drain_events(CTX).expect("bob drains own send");
    assert_eq!(bob_events.len(), 1);
    match &bob_events[0] {
        ContextEvent::MessageSent {
            sender_did,
            payload,
            ..
        } => {
            assert_eq!(sender_did.0, BOB_DID, "Bob's own send");
            assert_eq!(payload.as_slice(), plaintext);
        }
        other => panic!("expected MessageSent, got {other:?}"),
    }
}

#[test]
#[allow(clippy::too_many_lines)] // one end-to-end raw-group remove scenario, read top-to-bottom
fn remove_commit_is_rejected_fail_closed_without_skew() {
    // The regression test for Fix 1: a Remove-bearing Commit must be rejected by
    // `receive_message` AND must leave the receiver's MLS group + SCP membership +
    // event log mutually consistent (pre-remove). `scp-mls` now inspects the
    // staged commit's Remove proposals and drops the StagedCommit WITHOUT merging,
    // so the MLS epoch never half-advances while the SCP membership/log stay put.
    //
    // ADR-057 Slice 2 deliberately gives the participant `ScpClient` NO remove op
    // (there is no convergent removal-leaf transport yet). To manufacture the very
    // Remove-bearing Commit the driver must reject, this test drives ALICE as a
    // raw `scp-mls` group (a dev-dependency) — exactly the wire bytes a hostile or
    // out-of-scope committer could put on the wire — while BOB is a real
    // `ScpClient` whose `receive_message` is the unit under test.
    use ed25519_dalek::SigningKey;
    use openmls::prelude::{BasicCredential, KeyPackageIn};
    use rand::rngs::OsRng;
    use scp_did::SigningKeyId;
    use scp_mls::group::{
        add_member, add_member_with_convergent_timestamp, create_group, remove_member,
    };
    use scp_mls::{ScpCredential, SignatureKeyPair, mint_key_package_for_testing};
    use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

    // The raw Alice group and Bob's client share a real-time base so every
    // KeyPackage `Lifetime` stays valid against openmls's internal (real) clock
    // and the hardened SCP checks (ADR-057 §Prereq-1). The raw group uses
    // `SystemClock` directly; Bob's client (via `Relay::new_party`) uses a TestClock
    // seeded from the same real-time base.
    let base = SystemClock.now_secs();
    let alice_cred = ScpCredential::new(ALICE_DID.to_owned(), None, SigningKeyId::Active)
        .expect("alice credential");
    let mut alice_group = create_group(&alice_cred, &SystemClock).expect("Alice's raw MLS group");

    let relay = Relay::new();
    let mut bob = relay.new_party(BOB_DID, BOB_OFFSET);

    // Bob's ScpClient mints its join KeyPackage (private half retained inside the
    // client). Alice (raw group) adds Bob from that KeyPackage and Bob joins via
    // the resulting Welcome, starting from an empty replay log.
    let bob_kp_bytes = bob
        .client
        .generate_key_package_for_join(CTX)
        .expect("Bob key package");
    let bob_kp_in = KeyPackageIn::tls_deserialize(&mut &*bob_kp_bytes).expect("bob kp deserialize");
    let add_bob = add_member(&mut alice_group, bob_kp_in, &SystemClock).expect("Alice adds Bob");
    let bob_welcome = add_bob
        .welcome
        .tls_serialize_detached()
        .expect("welcome bytes");
    // Alice is a RAW scp-mls group (not a client), so there is no wrapping-key
    // directory to transport — Bob joins with an empty directory. This test drives
    // the remove-rejection path, not sender-key distribution, so Bob never needs
    // Alice's sender key.
    bob.client
        .join_context_encrypted(CTX, &bob_welcome, &[], &[])
        .expect("Bob joins Alice's raw group");

    // Alice (raw group) adds Carol — a raw `scp-mls` member that exists only so
    // Alice has someone to remove. Bob applies the add-Carol Commit through his
    // ScpClient so Bob and Alice share the post-add epoch and Bob records Carol.
    let carol_cred = ScpCredential::new(CAROL_DID.to_owned(), None, SigningKeyId::Active)
        .expect("carol credential");
    // Carol's KeyPackage must publish a wrapping key, or Bob's add-Carol receive
    // is rejected pre-merge (ADR-057 sender-key distribution INVARIANT 3) before it
    // can reach the remove scenario.
    let (carol_bundle, _carol_signer, _carol_provider): (_, SignatureKeyPair, _) =
        mint_key_package_for_testing(
            &carol_cred,
            &[0xCC_u8; 32],
            &SystemClock,
            &SigningKey::generate(&mut OsRng),
        )
        .expect("carol key package");
    let carol_kp_in = KeyPackageIn::tls_deserialize(
        &mut &*carol_bundle
            .key_package()
            .tls_serialize_detached()
            .expect("carol kp bytes"),
    )
    .expect("carol kp deserialize");
    // The add path converges + appends a MemberJoined leaf on Bob, so the raw
    // Commit must carry a convergent-timestamp AAD (ADR-057) that Bob adopts
    // verbatim: he recovers it from the verified AAD, with no receiver-side
    // clock verdict on the value.
    let add_carol =
        add_member_with_convergent_timestamp(&mut alice_group, carol_kp_in, &SystemClock, base)
            .expect("Alice adds Carol");
    let add_carol_commit = add_carol
        .commit
        .tls_serialize_detached()
        .expect("add-carol commit bytes");
    bob.client
        .receive_message(CTX, &add_carol_commit)
        .expect("Bob processes the add-Carol commit");

    // Snapshot Bob's pre-remove state: MLS epoch, SCP membership, log leaf count,
    // and Merkle root. After the rejected remove these must ALL be unchanged.
    let bob_epoch_before = bob.client.mls_epoch(CTX).expect("bob epoch");
    let bob_leaf_count_before = bob.client.event_log_leaf_count(CTX);
    let bob_root_before = bob.client.event_log_root(CTX);
    let mut bob_members_before = bob.client.member_dids(CTX).expect("bob members");
    bob_members_before.sort();
    assert!(
        bob_members_before.contains(&CAROL_DID.to_owned()),
        "pre-remove: Carol is in Bob's membership set"
    );

    // Alice (raw group) builds a Commit removing Carol by her leaf index.
    let carol_leaf = alice_group
        .members()
        .expect("alice members")
        .into_iter()
        .find(|m| {
            BasicCredential::try_from(m.credential.clone())
                .ok()
                .and_then(|basic| ScpCredential::from_bytes(basic.identity()).ok())
                .is_some_and(|cred| cred.did == CAROL_DID)
        })
        .map(|m| m.index)
        .expect("Carol's leaf index");
    let remove_carol = remove_member(&mut alice_group, carol_leaf).expect("Alice removes Carol");
    let remove_carol_commit = remove_carol
        .commit
        .tls_serialize_detached()
        .expect("remove-carol commit bytes");

    // Bob receives the remove Commit. `scp-mls` decides the Remove-refusal BEFORE
    // the AAD check, so the raw (AAD-less) remove Commit is still rejected as
    // UnsupportedMembershipChange — never as a missing timestamp.
    let result = bob.client.receive_message(CTX, &remove_carol_commit);

    // (1) FAIL-LOUD: the driver surfaces UnsupportedMembershipChange naming Carol.
    match result {
        Err(ClientError::UnsupportedMembershipChange(msg)) => {
            assert!(
                msg.contains(CAROL_DID),
                "the error must name the removed member, got: {msg}"
            );
        }
        other => panic!("expected UnsupportedMembershipChange, got {other:?}"),
    }

    // (2) NO SKEW: Bob's MLS group did NOT half-advance — the Remove-bearing
    // Commit was dropped BEFORE `merge_staged_commit`, so the MLS epoch is
    // exactly what it was before. This is the crux of Fix 1: pre-fix the group
    // merged (epoch advanced, Carol evicted from the tree) and only then errored,
    // leaving MLS ahead of the SCP layer.
    assert_eq!(
        bob.client.mls_epoch(CTX).expect("bob epoch after"),
        bob_epoch_before,
        "a rejected remove must NOT advance Bob's MLS epoch (no half-merge)"
    );

    // (3) NO SKEW: Bob's SCP membership set is unchanged (Carol still listed —
    // the driver did not evict her, since it never applied the Commit).
    let mut bob_members_after = bob.client.member_dids(CTX).expect("bob members after");
    bob_members_after.sort();
    assert_eq!(
        bob_members_after, bob_members_before,
        "a rejected remove must NOT mutate Bob's SCP membership set"
    );

    // (4) NO SKEW: Bob's event log is unchanged (same leaf count, same root) —
    // no membership leaf was appended or dropped.
    assert_eq!(
        bob.client.event_log_leaf_count(CTX),
        bob_leaf_count_before,
        "a rejected remove must NOT change Bob's event-log leaf count"
    );
    assert_eq!(
        bob.client.event_log_root(CTX),
        bob_root_before,
        "a rejected remove must NOT change Bob's event-log Merkle root"
    );

    // The four no-skew assertions above prove the crux of Fix 1: MLS state and
    // SCP state are LEFT MUTUALLY CONSISTENT (both pre-remove), because the
    // Remove-bearing Commit was dropped before `merge_staged_commit` rather than
    // merged-then-errored. (That the group also stays *encryptable* on its
    // unchanged epoch after a rejected remove is proven at the MLS layer by the
    // `scp-mls` unit test `decrypt_with_membership_changes_rejects_remove_without_merging`.)
}

#[test]
fn tampered_ciphertext_is_rejected_and_stamps_no_leaf() {
    // A hostile relay flips a byte of a valid application-message ciphertext. The
    // AEAD tag fails, so the receiver's decrypt errors and — as for any received
    // application message — NO convergent leaf is stamped; the context is
    // untouched and stays usable.
    //
    // `connect_two` wires a fully-connected 2-party context (MLS group shared,
    // §9.16 sender keys exchanged both ways, both pseudonym registries populated),
    // draining buffers and the publish log so we start clean.
    let relay = Relay::new();
    let (mut alice, mut bob) = connect_two(&relay, CTX, ALICE_DID, BOB_DID);

    let bob_leaf_before = bob.client.event_log_leaf_count(CTX);
    let bob_root_before = bob.client.event_log_root(CTX);

    // Alice's send fans out one relay PUBLISH to Bob's pseudonym; recover the inner
    // MLS ciphertext from the captured wire frame (the exact bytes Bob's decrypt
    // consumes), tamper it, and feed it to `receive_message` directly — the same
    // adversarial delivery the pre-transport test performed on the returned
    // ciphertext.
    alice
        .client
        .send_message(CTX, b"tamper target")
        .expect("alice sends");
    let mut ciphertext = last_app_ciphertext(&relay, alice.conn, CTX);
    // Flip the last byte (corrupts the AEAD tag covering the AAD + payload).
    if let Some(byte) = ciphertext.last_mut() {
        *byte ^= 0xFF;
    }
    assert!(
        bob.client.receive_message(CTX, &ciphertext).is_err(),
        "a tampered ciphertext must be rejected, not silently accepted"
    );
    assert_eq!(
        bob.client.event_log_leaf_count(CTX),
        bob_leaf_before,
        "a tampered ciphertext stamps NO leaf"
    );
    assert_eq!(
        bob.client.event_log_root(CTX),
        bob_root_before,
        "a tampered ciphertext leaves the event-log root unchanged"
    );
    assert_eq!(
        bob.client.context_status(CTX),
        ContextStatus::Live,
        "the context stays Live after a tampered-ciphertext rejection"
    );
}
