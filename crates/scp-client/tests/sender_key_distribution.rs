//! In-tab HPKE sender-key distribution over the MLS `scp_wrapping_key` extension
//! (ADR-057, §9.16.1/§9.16.2).
//!
//! This is the distribution milestone test: members share their §9.16 sender keys
//! **in-tab**, sealed to peers' stable wrapping keys and delivered as
//! MLS-authenticated management messages — there is NO out-of-band exchange. The
//! deleted seam (`install_sender_key` / `local_sender_key_bytes`) is gone; this
//! file never references it (grep it to confirm), proving the mesh is
//! self-sufficient.
//!
//! It proves the topologically-complete push mesh (all three triggers), the
//! management-vs-application disjointness, the fail-closed missing-wrapping-key
//! guard (INVARIANT 3), and that the wrapping keypair + directory survive a
//! snapshot round-trip (INVARIANT 5).
//!
//! Sender-key distributions are still delivered DIRECTLY to a target's
//! `receive_message` (they are management messages, not app data — the ADR-057
//! transport slice routes app data + pseudonym announcements over the relay, not
//! distributions). The pseudonym-announce mesh and the final application-message
//! decrypt checks go over the REALISTIC relay mock (`tests/common`): a member
//! `send_message`/announce fans out as relay `PUBLISH` frames, and `Relay::pump`
//! delivers the queued `BLOB`s into each peer's `handle_relay_frame` — iteratively
//! until the §9.10.4 reciprocal-announce cascade quiesces.

// Integration tests assert on happy-path results; `expect`/`panic!` make the
// failure messages legible. The workspace denies these in production code.
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::{Party, Relay, RelayExt};
use scp_client::{LocalSigner, MemoryStorage, ScpClient, SenderKeyDistribution, Storage};
use scp_clock::{Clock, SystemClock, TestClock};
use scp_protocol::context::context_routing_id;
use scp_protocol::context::membership::ContextEvent;

const CTX: &str = "ctx-adr057-sender-key-distribution";
const ALICE_DID: &str = "did:key:z6MkAliceSenderKeyDistFixtureAAAAAAAAAAAAA";
const BOB_DID: &str = "did:key:z6MkBobSenderKeyDistFixtureBBBBBBBBBBBBBBBB";
const CAROL_DID: &str = "did:key:z6MkCarolSenderKeyDistFixtureCCCCCCCCCCCCC";

/// Routes each distribution to its target client (by DID) and asserts the install
/// is a no-op receive. Delivering a distribution only decrypts if the recipient is
/// at the epoch it was sealed at — callers deliver after every member has reached
/// that epoch. Distributions are delivered DIRECTLY (not over the relay).
fn deliver(
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
            "a distribution is not an application message"
        );
        assert!(out.sender_key_distributions.is_empty());
    }
}

/// Asserts `sender` can send a message that both peers decrypt to `plaintext`,
/// draining the buffers so the state is clean for the next hop. The send fans out
/// over the relay to every announced peer; `Relay::pump` delivers those frames
/// into each peer's `handle_relay_frame`, and a successful `MessageReceived`
/// decrypt confirms the peer holds the sender's distributed key.
fn assert_decrypts_at_both(
    relay: &Relay,
    sender: &mut Party,
    plaintext: &[u8],
    a: (&str, &mut Party),
    b: (&str, &mut Party),
) {
    let (who_a, party_a) = a;
    let (who_b, party_b) = b;
    sender.client.send_message(CTX, plaintext).expect("send");
    relay.pump(&mut [&mut *sender, &mut *party_a, &mut *party_b]);
    for (who, party) in [(who_a, &mut *party_a), (who_b, &mut *party_b)] {
        let drained = party.client.drain_events(CTX).expect("drain");
        assert_eq!(drained.len(), 1, "{who} buffered one message");
        match &drained[0] {
            ContextEvent::MessageReceived { payload, .. } => {
                assert_eq!(
                    payload.as_slice(),
                    plaintext,
                    "{who} recovered the plaintext (decrypts under the distributed key)"
                );
            }
            other => panic!("{who}: expected MessageReceived, got {other:?}"),
        }
    }
    // The sender buffered its own MessageSent — drain it so its buffer is clean.
    let _ = sender
        .client
        .drain_events(CTX)
        .expect("sender drains own send");
}

#[test]
#[allow(clippy::too_many_lines)] // one end-to-end three-party mesh, read top-to-bottom
fn three_party_bob_adds_carol_full_mesh_via_extension_only() {
    let relay = Relay::new();
    let mut alice = relay.new_party(ALICE_DID, 0);
    let mut bob = relay.new_party(BOB_DID, 100);
    let mut carol = relay.new_party(CAROL_DID, 200);

    alice.client.create_context(CTX).expect("alice creates");

    // --- Round 1: Alice adds Bob (epoch 1). Deliver both directions. ---
    let bob_kp = bob
        .client
        .generate_key_package_for_join(CTX)
        .expect("bob kp");
    let add_bob = alice
        .client
        .add_member(CTX, &bob_kp)
        .expect("alice adds bob");
    let bob_join = bob
        .client
        .join_context_encrypted(
            CTX,
            &add_bob.welcome,
            &add_bob.event_log,
            &add_bob.wrapping_keys,
        )
        .expect("bob joins");
    deliver(
        &add_bob.sender_key_distributions,
        &mut alice.client,
        &mut bob.client,
        &mut carol.client,
    );
    deliver(
        &bob_join,
        &mut alice.client,
        &mut bob.client,
        &mut carol.client,
    );

    // Pump the epoch-1 pseudonym-announce cascade while both are STILL at epoch 1,
    // so each learns the other (Bob's join-announce → Alice reciprocates → Bob
    // records Alice → quiescent) and the epoch-1 frames are consumed before the
    // epoch-2 round — a member that has advanced cannot decrypt an announcement
    // sealed at an earlier epoch. Registries persist across epochs (the pseudonym
    // is derived from the stable signing key, epoch-free).
    relay.pump(&mut [&mut alice, &mut bob]);
    let _ = alice.client.drain_events(CTX);
    let _ = bob.client.drain_events(CTX);
    let _ = relay.drain_publish_log();

    // --- Round 2: BOB adds Carol (epoch 2). Alice is the BYSTANDER (INVARIANT 2:
    // Alice must seal her key to Carol when she processes Bob's Commit). ---
    let carol_kp = carol
        .client
        .generate_key_package_for_join(CTX)
        .expect("carol kp");
    let add_carol = bob
        .client
        .add_member(CTX, &carol_kp)
        .expect("bob adds carol");
    assert_eq!(
        add_carol.sender_key_distributions.len(),
        1,
        "the adder (Bob) seals his key to the joiner (Carol)"
    );
    assert_eq!(add_carol.sender_key_distributions[0].target_did, CAROL_DID);

    let carol_join = carol
        .client
        .join_context_encrypted(
            CTX,
            &add_carol.welcome,
            &add_carol.event_log,
            &add_carol.wrapping_keys,
        )
        .expect("carol joins");

    // Alice (bystander) processes Bob's add-Carol Commit → converges + seals her
    // key to Carol (the make-or-break third trigger). This also re-announces
    // Alice's pseudonym at epoch 2.
    let alice_recv = alice
        .client
        .receive_message(CTX, &add_carol.commit)
        .expect("alice processes bob's add-carol commit");
    assert!(!alice_recv.application);
    assert_eq!(
        alice_recv.sender_key_distributions.len(),
        1,
        "the bystander (Alice) seals her key to the newly-added member (INVARIANT 2)"
    );
    assert_eq!(alice_recv.sender_key_distributions[0].target_did, CAROL_DID);

    // Membership has converged: capture the root NOW; the distribution round and
    // the message exchange below must NOT change it (distributions/messages are
    // not convergent leaves).
    let converged_root = alice.client.event_log_root(CTX).expect("root");
    assert_eq!(bob.client.event_log_root(CTX), Some(converged_root));
    assert_eq!(carol.client.event_log_root(CTX), Some(converged_root));
    assert_eq!(alice.client.event_log_leaf_count(CTX), Some(3));

    // Every member is now at epoch 2 — deliver every epoch-2 distribution.
    deliver(
        &add_carol.sender_key_distributions,
        &mut alice.client,
        &mut bob.client,
        &mut carol.client,
    );
    deliver(
        &carol_join,
        &mut alice.client,
        &mut bob.client,
        &mut carol.client,
    );
    deliver(
        &alice_recv.sender_key_distributions,
        &mut alice.client,
        &mut bob.client,
        &mut carol.client,
    );

    // Pump the epoch-2 pseudonym-announce cascade so every peer registry is
    // complete (Alice↔Bob learned each other at epoch 1; now everyone learns
    // Carol via her join-announce, Alice re-announces at epoch 2, and reciprocals
    // complete the mesh). Every announcement is sealed at epoch 2 — the epoch-1
    // frames were consumed in round 1 — and every peer holds every sender key
    // (delivered above), so each frame decrypts at the current epoch.
    relay.pump(&mut [&mut alice, &mut bob, &mut carol]);
    // Clear the resulting PseudonymAnnounced events + publish records so the
    // message mesh below starts from a clean slate.
    let _ = alice.client.drain_events(CTX);
    let _ = bob.client.drain_events(CTX);
    let _ = carol.client.drain_events(CTX);
    let _ = relay.drain_publish_log();

    // === FULL MESH: every member can send a message every other member decrypts,
    // with keys delivered ONLY over the wrapping-key extension mesh and the
    // messages fanned out over the relay. ===
    assert_decrypts_at_both(
        &relay,
        &mut alice,
        b"from alice",
        (BOB_DID, &mut bob),
        (CAROL_DID, &mut carol),
    );
    assert_decrypts_at_both(
        &relay,
        &mut bob,
        b"from bob",
        (ALICE_DID, &mut alice),
        (CAROL_DID, &mut carol),
    );
    assert_decrypts_at_both(
        &relay,
        &mut carol,
        b"from carol",
        (ALICE_DID, &mut alice),
        (BOB_DID, &mut bob),
    );

    // The convergent event-log root is unchanged by the entire distribution +
    // message round (INVARIANT 4: distributions ride outside the convergent log).
    assert_eq!(
        alice.client.event_log_root(CTX),
        Some(converged_root),
        "the event-log root is unchanged across the distribution round"
    );
    assert_eq!(bob.client.event_log_root(CTX), Some(converged_root));
    assert_eq!(carol.client.event_log_root(CTX), Some(converged_root));
    assert_eq!(
        alice.client.event_log_leaf_count(CTX),
        Some(3),
        "still 3 membership leaves"
    );
}

#[test]
fn receiving_a_distribution_stamps_no_event_and_no_leaf() {
    // Disjointness at the driver level: receiving a sender-key distribution
    // (a management message) returns `application == false`, buffers NO
    // ContextEvent for drain_events, and appends NO event-log leaf.
    let relay = Relay::new();
    let mut alice = relay.new_party(ALICE_DID, 0);
    let mut bob = relay.new_party(BOB_DID, 100);

    alice.client.create_context(CTX).expect("alice creates");
    let bob_kp = bob
        .client
        .generate_key_package_for_join(CTX)
        .expect("bob kp");
    let add = alice
        .client
        .add_member(CTX, &bob_kp)
        .expect("alice adds bob");
    let bob_join = bob
        .client
        .join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
        .expect("bob joins");

    let leaf_before = bob.client.event_log_leaf_count(CTX);
    let root_before = bob.client.event_log_root(CTX);

    // Deliver Alice's distribution to Bob.
    assert_eq!(add.sender_key_distributions.len(), 1);
    let out = bob
        .client
        .receive_message(CTX, &add.sender_key_distributions[0].ciphertext)
        .expect("bob installs alice's key");
    assert!(
        !out.application,
        "a distribution is not an application message"
    );
    assert!(out.sender_key_distributions.is_empty());

    // No leaf, same root, and drain_events yields nothing (no ContextEvent).
    assert_eq!(
        bob.client.event_log_leaf_count(CTX),
        leaf_before,
        "no leaf appended"
    );
    assert_eq!(
        bob.client.event_log_root(CTX),
        root_before,
        "root unchanged"
    );
    assert!(
        bob.client.drain_events(CTX).expect("drain").is_empty(),
        "a distribution buffers no ContextEvent"
    );

    // Alice, in turn, installs Bob's join distribution — also a no-op receive.
    assert_eq!(bob_join.len(), 1);
    let out = alice
        .client
        .receive_message(CTX, &bob_join[0].ciphertext)
        .expect("alice installs bob's key");
    assert!(!out.application);
    assert!(
        alice.client.drain_events(CTX).expect("drain").is_empty(),
        "a distribution buffers no ContextEvent on Alice either"
    );
}

#[test]
fn add_with_missing_wrapping_extension_is_rejected_fail_closed() {
    // ADR-057 sender-key distribution INVARIANT 3: an add whose KeyPackage leaf
    // carries no scp_wrapping_key extension must be rejected — a member no peer can
    // HPKE-seal a sender key to must not be admitted. The driver always publishes a
    // wrapping key, so this crafts a PLAIN KeyPackage via raw `scp-mls` (a
    // dev-dependency) to exercise the guard.
    use scp_did::SigningKeyId;
    use scp_mls::ScpCredential;
    use scp_mls::group::generate_key_package;
    use tls_codec::Serialize as _;

    let relay = Relay::new();
    let mut alice = relay.new_party(ALICE_DID, 0);
    alice.client.create_context(CTX).expect("alice creates");

    // A plain KeyPackage with NO wrapping extension.
    let bob_cred =
        ScpCredential::new(BOB_DID.to_owned(), None, SigningKeyId::Active).expect("bob credential");
    let (bundle, _signer, _provider) =
        generate_key_package(&bob_cred, &SystemClock).expect("plain key package");
    let plain_kp = bundle
        .key_package()
        .tls_serialize_detached()
        .expect("kp bytes");

    let err = alice
        .client
        .add_member(CTX, &plain_kp)
        .expect_err("an add with no wrapping key must be rejected fail-closed");
    let msg = format!("{err}");
    assert!(
        msg.contains("scp_wrapping_key"),
        "the error must name the missing wrapping extension, got: {msg}"
    );

    // The context is untouched — the rejected add stamped no membership leaf.
    assert_eq!(
        alice.client.member_dids(CTX).as_deref(),
        Some(&[ALICE_DID.to_owned()][..]),
        "a rejected add must not add a member"
    );
    assert_eq!(
        alice.client.event_log_leaf_count(CTX),
        Some(1),
        "no MemberJoined leaf"
    );
}

#[test]
#[allow(clippy::too_many_lines)] // one end-to-end restore + rotation scenario
fn snapshot_v3_persists_wrapping_and_directory_for_post_restore_distribution() {
    // INVARIANT 5: the stable wrapping keypair + the member-wrapping-key directory
    // survive a snapshot round-trip. Proof: after a converged pair, Bob's tab
    // closes; a reopened tab restores and (a) decrypts a message Alice sends under
    // the already-installed key, and (b) HPKE-opens a ROTATED key Alice
    // re-distributes — which only succeeds if Bob's wrapping SECRET survived — then
    // decrypts a message under the rotated key. Alice's sends fan out over the
    // relay; `Relay::pump` delivers them into the restored client's
    // `handle_relay_frame` (the restored client re-subscribes to its
    // restore-stable pseudonym on construction).
    let relay = Relay::new();
    let bob_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let mut alice = relay.new_party(ALICE_DID, 0);

    // Bob over caller-supplied (shared, restorable) storage.
    let mut bob = {
        let signer = Arc::new(LocalSigner::active(BOB_DID));
        let clock: Arc<dyn Clock> = Arc::new(TestClock::new(SystemClock.now_secs() + 100));
        relay.party_with(signer, Arc::clone(&bob_storage), clock)
    };

    alice.client.create_context(CTX).expect("alice creates");
    let bob_kp = bob
        .client
        .generate_key_package_for_join(CTX)
        .expect("bob kp");
    let add = alice
        .client
        .add_member(CTX, &bob_kp)
        .expect("alice adds bob");
    let bob_join = bob
        .client
        .join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
        .expect("bob joins");
    // Deliver both directions (epoch 1) — distributions go directly.
    bob.client
        .receive_message(CTX, &add.sender_key_distributions[0].ciphertext)
        .expect("bob installs alice's key");
    alice
        .client
        .receive_message(CTX, &bob_join[0].ciphertext)
        .expect("alice installs bob's key");

    // Pump the pseudonym-announce cascade so Alice's peer registry knows Bob's
    // (epoch-free, restore-stable) pseudonym — app-data sends fan out only to
    // announced peers. Drain the resulting events + publish records so the sends
    // below are isolated.
    relay.pump(&mut [&mut alice, &mut bob]);
    let _ = alice.client.drain_events(CTX);
    let _ = bob.client.drain_events(CTX);
    let _ = relay.drain_publish_log();

    drop(bob); // Bob's tab closes; only durable storage survives.

    // Reopen: the constructor restores Bob's converged context (incl. the wrapping
    // keypair + directory + the installed sender-key store) and re-subscribes to
    // his restore-stable pseudonym, so Alice's fan-out reaches him.
    let mut bob2 = {
        let signer = Arc::new(LocalSigner::active(BOB_DID));
        let clock: Arc<dyn Clock> = Arc::new(TestClock::new(SystemClock.now_secs() + 150));
        relay.party_with(signer, Arc::clone(&bob_storage), clock)
    };

    // (a) The restored client decrypts a message under the already-installed key.
    // Alice's send fans out over the relay to Bob's pseudonym; pump it in.
    alice
        .client
        .send_message(CTX, b"before rotation")
        .expect("alice sends");
    let app_publish_count = relay
        .drain_publish_log()
        .into_iter()
        .filter(|p| p.conn == alice.conn && p.routing_id != context_routing_id(CTX))
        .count();
    assert_eq!(
        app_publish_count, 1,
        "one PUBLISH fanned out to Bob's pseudonym"
    );
    relay.pump(&mut [&mut alice, &mut bob2]);
    let events = bob2.client.drain_events(CTX).expect("drain");
    assert_eq!(
        events.len(),
        1,
        "restored client buffered one message (decrypts under the installed key)"
    );
    match &events[0] {
        ContextEvent::MessageReceived { payload, .. } => {
            assert_eq!(payload.as_slice(), b"before rotation");
        }
        other => panic!("expected MessageReceived, got {other:?}"),
    }

    // (b) Alice rotates her sender key and re-distributes it. Bob2 HPKE-opens the
    // rotated key — only possible if its wrapping SECRET survived the restore —
    // then decrypts a message under the rotated key. The rotation distribution is
    // delivered DIRECTLY (a management message), like every other distribution.
    let rotations = alice.client.rotate_sender_key(CTX).expect("alice rotates");
    assert_eq!(rotations.len(), 1, "one distribution to Bob");
    assert_eq!(rotations[0].target_did, BOB_DID);
    let out = bob2
        .client
        .receive_message(CTX, &rotations[0].ciphertext)
        .expect("bob2 installs the rotated key (wrapping secret survived restore)");
    assert!(!out.application);

    alice
        .client
        .send_message(CTX, b"after rotation")
        .expect("alice sends 2");
    let app_publish_count = relay
        .drain_publish_log()
        .into_iter()
        .filter(|p| p.conn == alice.conn && p.routing_id != context_routing_id(CTX))
        .count();
    assert_eq!(
        app_publish_count, 1,
        "one PUBLISH fanned out under the rotated key"
    );
    relay.pump(&mut [&mut alice, &mut bob2]);
    let drained = bob2.client.drain_events(CTX).expect("drain");
    assert_eq!(drained.len(), 1);
    match &drained[0] {
        ContextEvent::MessageReceived { payload, .. } => {
            assert_eq!(
                payload.as_slice(),
                b"after rotation",
                "restored client decrypts under the rotated key"
            );
        }
        other => panic!("expected MessageReceived, got {other:?}"),
    }
}
