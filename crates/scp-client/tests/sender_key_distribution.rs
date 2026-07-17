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
//! transport slice routes app data + pseudonym announcements over the socket, not
//! distributions). The final application-message decrypt checks now go over the
//! injected `Socket`: `send_message` returns `()` and fans the message out as
//! relay `PUBLISH` frames, which the harness routes into each peer's
//! `handle_relay_frame`.

// Integration tests assert on happy-path results; `expect`/`panic!` make the
// failure messages legible. The workspace denies these in production code.
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::{CaptureSocket, Party, client_with, new_party, publish_to_blob, route_publishes};
use scp_client::{LocalSigner, MemoryStorage, ScpClient, SenderKeyDistribution, Storage};
use scp_clock::{Clock, SystemClock, TestClock};
use scp_protocol::context::membership::ContextEvent;

const CTX: &str = "ctx-adr057-sender-key-distribution";
const ALICE_DID: &str = "did:key:z6MkAliceSenderKeyDistFixtureAAAAAAAAAAAAA";
const BOB_DID: &str = "did:key:z6MkBobSenderKeyDistFixtureBBBBBBBBBBBBBBBB";
const CAROL_DID: &str = "did:key:z6MkCarolSenderKeyDistFixtureCCCCCCCCCCCCC";

/// Routes each distribution to its target client (by DID) and asserts the install
/// is a no-op receive. Delivering a distribution only decrypts if the recipient is
/// at the epoch it was sealed at — callers deliver after every member has reached
/// that epoch. Distributions are delivered DIRECTLY (not over the socket).
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

/// Delivers every captured `PUBLISH` frame in `from` to EACH receiver's
/// `handle_relay_frame` (each receiver keeps the frame addressed to its own
/// pseudonym and drops the rest). Unlike [`route_publishes`], which drains a
/// socket into a SINGLE peer, this fans one send's frames out to multiple peers —
/// the fan-out addressing an app-data `send_message` produces (one identical blob
/// per announced peer pseudonym). Drains the socket.
fn route_to_all(from: &CaptureSocket, receivers: &mut [&mut ScpClient]) {
    let frames = from.take_frames();
    for receiver in receivers {
        for frame in &frames {
            if let Some(blob) = publish_to_blob(frame) {
                receiver
                    .handle_relay_frame(&blob)
                    .expect("deliver relay blob");
            }
        }
    }
}

/// Asserts `sender` can send a message that both peers decrypt to `plaintext`,
/// draining the buffers so the state is clean for the next hop. The send fans out
/// over the socket to every announced peer; the harness routes those frames into
/// each peer's `handle_relay_frame`, and a successful `MessageReceived` decrypt
/// confirms the peer holds the sender's distributed key.
fn assert_decrypts_at_both(
    sender: &mut Party,
    plaintext: &[u8],
    a: (&str, &mut ScpClient),
    b: (&str, &mut ScpClient),
) {
    sender.client.send_message(CTX, plaintext).expect("send");
    let (who_a, client_a) = a;
    let (who_b, client_b) = b;
    route_to_all(&sender.socket, &mut [client_a, client_b]);
    for (who, client) in [(who_a, client_a), (who_b, client_b)] {
        let drained = client.drain_events(CTX).expect("drain");
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
    let mut alice = new_party(ALICE_DID, 0);
    let mut bob = new_party(BOB_DID, 100);
    let mut carol = new_party(CAROL_DID, 200);

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

    // Pump the epoch-1 pseudonym announcements Alice and Bob captured while both
    // are STILL at epoch 1, so each learns the other (and the epoch-1 frames are
    // drained before the epoch-2 round — a member that has advanced cannot decrypt
    // an announcement sealed at an earlier epoch). Registries persist across
    // epochs (the pseudonym is derived from the stable signing key, epoch-free).
    route_publishes(&alice.socket, &mut bob.client);
    route_publishes(&bob.socket, &mut alice.client);
    let _ = alice.client.drain_events(CTX);
    let _ = bob.client.drain_events(CTX);

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

    // Pump the epoch-2 pseudonym announcements so every peer registry is complete
    // (Alice↔Bob learned each other at epoch 1; now everyone learns Carol, and
    // Carol learns Alice + Bob). Each socket now carries ONLY its epoch-2
    // announcement — the epoch-1 frames were drained in round 1 — so every routed
    // frame decrypts at the current epoch. Fan each announcement out to the other
    // two members.
    route_to_all(&carol.socket, &mut [&mut alice.client, &mut bob.client]);
    route_to_all(&alice.socket, &mut [&mut bob.client, &mut carol.client]);
    route_to_all(&bob.socket, &mut [&mut alice.client, &mut carol.client]);
    // Clear the resulting PseudonymAnnounced events + any residual frames so the
    // message mesh below starts from a clean slate.
    let _ = alice.client.drain_events(CTX);
    let _ = bob.client.drain_events(CTX);
    let _ = carol.client.drain_events(CTX);
    let _ = alice.socket.take_frames();
    let _ = bob.socket.take_frames();
    let _ = carol.socket.take_frames();

    // === FULL MESH: every member can send a message every other member decrypts,
    // with keys delivered ONLY over the wrapping-key extension mesh and the
    // messages fanned out over the injected socket. ===
    assert_decrypts_at_both(
        &mut alice,
        b"from alice",
        (BOB_DID, &mut bob.client),
        (CAROL_DID, &mut carol.client),
    );
    assert_decrypts_at_both(
        &mut bob,
        b"from bob",
        (ALICE_DID, &mut alice.client),
        (CAROL_DID, &mut carol.client),
    );
    assert_decrypts_at_both(
        &mut carol,
        b"from carol",
        (ALICE_DID, &mut alice.client),
        (BOB_DID, &mut bob.client),
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
    let mut alice = new_party(ALICE_DID, 0);
    let mut bob = new_party(BOB_DID, 100);

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

    let mut alice = new_party(ALICE_DID, 0);
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
    // socket; the harness routes them into the restored client's
    // `handle_relay_frame`.
    let bob_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let mut alice = new_party(ALICE_DID, 0);

    // Bob over caller-supplied (shared, restorable) storage + his own socket.
    let bob_socket = CaptureSocket::new();
    let mut bob = {
        let signer = Arc::new(LocalSigner::active(BOB_DID));
        let clock: Arc<dyn Clock> = Arc::new(TestClock::new(SystemClock.now_secs() + 100));
        client_with(signer, Arc::clone(&bob_storage), clock, bob_socket.clone())
    };

    alice.client.create_context(CTX).expect("alice creates");
    let bob_kp = bob.generate_key_package_for_join(CTX).expect("bob kp");
    let add = alice
        .client
        .add_member(CTX, &bob_kp)
        .expect("alice adds bob");
    let bob_join = bob
        .join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
        .expect("bob joins");
    // Deliver both directions (epoch 1) — distributions go directly.
    bob.receive_message(CTX, &add.sender_key_distributions[0].ciphertext)
        .expect("bob installs alice's key");
    alice
        .client
        .receive_message(CTX, &bob_join[0].ciphertext)
        .expect("alice installs bob's key");

    // Pump Bob's pseudonym announcement to Alice so Alice's peer registry knows
    // Bob's (epoch-free, restore-stable) pseudonym — app-data sends fan out only to
    // announced peers. Drain Alice's resulting event + both sockets so the sends
    // below are isolated.
    route_publishes(&bob_socket, &mut alice.client);
    let _ = alice.client.drain_events(CTX);
    let _ = alice.socket.take_frames();
    let _ = bob_socket.take_frames();

    drop(bob); // Bob's tab closes; only durable storage survives.

    // Reopen: the constructor restores Bob's converged context (incl. the wrapping
    // keypair + directory + the installed sender-key store) and re-subscribes to
    // his restore-stable pseudonym, so Alice's fan-out reaches him.
    let mut bob2 = {
        let signer = Arc::new(LocalSigner::active(BOB_DID));
        let clock: Arc<dyn Clock> = Arc::new(TestClock::new(SystemClock.now_secs() + 150));
        client_with(
            signer,
            Arc::clone(&bob_storage),
            clock,
            CaptureSocket::new(),
        )
    };

    // (a) The restored client decrypts a message under the already-installed key.
    // Alice's send fans out over the socket to Bob's pseudonym; route it in.
    alice
        .client
        .send_message(CTX, b"before rotation")
        .expect("alice sends");
    let delivered = route_publishes(&alice.socket, &mut bob2);
    assert_eq!(delivered, 1, "one PUBLISH fanned out to Bob's pseudonym");
    let events = bob2.drain_events(CTX).expect("drain");
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
        .receive_message(CTX, &rotations[0].ciphertext)
        .expect("bob2 installs the rotated key (wrapping secret survived restore)");
    assert!(!out.application);

    alice
        .client
        .send_message(CTX, b"after rotation")
        .expect("alice sends 2");
    let delivered = route_publishes(&alice.socket, &mut bob2);
    assert_eq!(delivered, 1, "one PUBLISH fanned out under the rotated key");
    let drained = bob2.drain_events(CTX).expect("drain");
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
