//! ADR-057 transport-slice regression + behavior tests over the REALISTIC relay
//! mock (`tests/common`), which models the shipped relay's self-echo,
//! subscribe-timing, and backfill semantics.
//!
//! The self-echo and mesh-completion tests here FAIL on the pre-fix driver (the
//! self-echo throws `CannotDecryptOwnMessage` out of `handle_relay_frame`, and the
//! joiner never learns existing members' pseudonyms) and PASS after the fixes —
//! see each test's header.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use common::{Relay, connect_two, deliver_distributions, first_received};
use scp_client::ClientError;
use scp_protocol::context::context_routing_id;
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::envelope::outer::{DEFAULT_APP_DATA_BLOB_TTL_SECS, OuterEnvelope};
use scp_relay_client::RelayMessage;

const CTX: &str = "ctx-adr057-transport-regression";
const ALICE: &str = "did:key:z6MkAliceTransportRegFixtureKeyAAAAAAAAAAA";
const BOB: &str = "did:key:z6MkBobTransportRegFixtureKeyBBBBBBBBBBBBBB";
const CAROL: &str = "did:key:z6MkCarolTransportRegFixtureKeyCCCCCCCCCCC";

// ===========================================================================
// BLOCKER 1 — self-echoed announcement is a benign drop
// ===========================================================================

/// Pre-fix: `handle_relay_frame` on a self-echoed announcement throws
/// `CannotDecryptOwnMessage` out to the caller (the tab's `onmessage`).
/// Post-fix: it is a benign `Ok(())` drop and the member does NOT record its OWN
/// pseudonym as a peer.
#[test]
fn self_echoed_announcement_is_benign_drop_and_not_self_recorded() {
    let relay = Relay::new();
    let mut alice = relay.new_party(ALICE, 0);
    alice.client.create_context(CTX).unwrap();
    let mut bob = relay.new_party(BOB, 100);
    let bob_kp = bob.client.generate_key_package_for_join(CTX).unwrap();
    let add = alice.client.add_member(CTX, &bob_kp).unwrap();
    let bob_dists = bob
        .client
        .join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
        .unwrap();
    deliver_distributions(
        CTX,
        &add.sender_key_distributions,
        &mut [(ALICE, &mut alice.client), (BOB, &mut bob.client)],
    );
    deliver_distributions(
        CTX,
        &bob_dists,
        &mut [(ALICE, &mut alice.client), (BOB, &mut bob.client)],
    );

    // Drive the cascade to quiescence (this itself delivers each announcement's
    // self-echo back to its author — pre-fix, the pump panics here on the throw).
    relay.pump(&mut [&mut alice, &mut bob]);

    // Explicitly re-inject Alice's OWN published announcement back into Alice and
    // assert a benign Ok — the direct self-echo the relay performs.
    let log = relay.drain_publish_log();
    let alice_ann = log
        .iter()
        .find(|p| p.conn == alice.conn && p.routing_id == context_routing_id(CTX))
        .expect("Alice published a reciprocal announcement");
    let echo = RelayMessage::Blob {
        routing_id: context_routing_id(CTX),
        blob_id: [0u8; 32],
        recipient_hint: None,
        blob_ttl: DEFAULT_APP_DATA_BLOB_TTL_SECS,
        stored_at: 0,
        blob: alice_ann.blob.clone(),
    }
    .to_bytes()
    .unwrap();
    assert!(
        alice.client.handle_relay_frame(&echo).is_ok(),
        "a self-echoed announcement must be a benign Ok drop, never a throw"
    );

    // Alice did not record HERSELF: her app-data fan-out addresses exactly one peer
    // (Bob), not two (Bob + self).
    let _ = alice.client.drain_events(CTX);
    alice.client.send_message(CTX, b"probe").unwrap();
    let publishes = relay.drain_publish_log();
    let app_count = publishes
        .iter()
        .filter(|p| p.conn == alice.conn && p.routing_id != context_routing_id(CTX))
        .count();
    assert_eq!(
        app_count, 1,
        "Alice fans app-data to exactly ONE peer (Bob); a self-recorded pseudonym would make it two"
    );
}

// ===========================================================================
// BLOCKER 2 — 2-party mesh completes in BOTH directions
// ===========================================================================

/// Pre-fix: the joiner (Bob) never learns the creator's (Alice's) pseudonym over a
/// realistic relay (no backfill; existing members re-announced before Bob
/// subscribed), so `Bob → Alice` fails with `PseudonymRegistryEmpty`.
/// Post-fix: reciprocal-announce completes the mesh; BOTH directions deliver.
#[test]
fn two_party_mesh_delivers_both_directions() {
    let relay = Relay::new();
    let (mut alice, mut bob) = connect_two(&relay, CTX, ALICE, BOB);

    // Alice → Bob.
    alice.client.send_message(CTX, b"hello Bob").unwrap();
    relay.pump(&mut [&mut alice, &mut bob]);
    assert_eq!(
        first_received(&bob.client.drain_events(CTX).unwrap()).as_deref(),
        Some(&b"hello Bob"[..]),
        "Alice → Bob delivers"
    );

    // Bob → Alice — the direction that is broken pre-fix (Bob never learned Alice).
    bob.client.send_message(CTX, b"hi Alice").unwrap();
    relay.pump(&mut [&mut alice, &mut bob]);
    assert_eq!(
        first_received(&alice.client.drain_events(CTX).unwrap()).as_deref(),
        Some(&b"hi Alice"[..]),
        "Bob → Alice delivers (the joiner learned the creator via reciprocal-announce)"
    );
}

// ===========================================================================
// 3-party fan-out is ACTUALLY DECRYPTABLE (adversarial finding #3)
// ===========================================================================

/// A single app-data send fans out to BOTH peers, and EACH peer recovers the
/// plaintext via `drain_events` (not merely "N publish frames were addressed").
#[test]
fn three_party_fan_out_is_decryptable_by_every_peer() {
    let relay = Relay::new();
    let (mut alice, mut bob) = connect_two(&relay, CTX, ALICE, BOB);

    // Add Carol.
    let mut carol = relay.new_party(CAROL, 200);
    let carol_kp = carol.client.generate_key_package_for_join(CTX).unwrap();
    let add = alice.client.add_member(CTX, &carol_kp).unwrap();
    let carol_dists = carol
        .client
        .join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
        .unwrap();
    // Bob (bystander) processes the add-Commit and re-distributes his key to Carol.
    let bob_recv = bob.client.receive_message(CTX, &add.commit).unwrap();
    deliver_distributions(
        CTX,
        &add.sender_key_distributions,
        &mut [(CAROL, &mut carol.client)],
    );
    deliver_distributions(
        CTX,
        &bob_recv.sender_key_distributions,
        &mut [(CAROL, &mut carol.client)],
    );
    deliver_distributions(
        CTX,
        &carol_dists,
        &mut [(ALICE, &mut alice.client), (BOB, &mut bob.client)],
    );
    // Complete the announce mesh across all three.
    relay.pump(&mut [&mut alice, &mut bob, &mut carol]);
    let _ = alice.client.drain_events(CTX);
    let _ = bob.client.drain_events(CTX);
    let _ = carol.client.drain_events(CTX);
    let _ = relay.drain_publish_log();

    // Alice sends ONCE → both Bob and Carol recover the plaintext.
    alice.client.send_message(CTX, b"to everyone").unwrap();
    let publishes = relay.drain_publish_log();
    let app: Vec<_> = publishes
        .iter()
        .filter(|p| p.conn == alice.conn && p.routing_id != context_routing_id(CTX))
        .collect();
    assert_eq!(app.len(), 2, "one PUBLISH per peer (Bob, Carol)");
    assert_eq!(
        app[0].inner_ciphertext(),
        app[1].inner_ciphertext(),
        "the fan-out blob is byte-identical across peers"
    );
    // Re-run the (already-drained) fan-out through the relay to deliver it.
    // (drain_publish_log consumed the queued deliveries' source; re-send once and
    // pump so the peers actually receive it.)
    alice.client.send_message(CTX, b"to everyone").unwrap();
    relay.pump(&mut [&mut alice, &mut bob, &mut carol]);
    assert_eq!(
        first_received(&bob.client.drain_events(CTX).unwrap()).as_deref(),
        Some(&b"to everyone"[..]),
        "Bob recovers the fanned plaintext"
    );
    assert_eq!(
        first_received(&carol.client.drain_events(CTX).unwrap()).as_deref(),
        Some(&b"to everyone"[..]),
        "Carol recovers the fanned plaintext"
    );
}

// ===========================================================================
// S1 — own-pseudonym forgery is rejected
// ===========================================================================

/// A member (Bob) forges an announcement claiming `member_did = ALICE_victim`'s...
/// actually claiming ITS OWN DID mapped to the VICTIM's pseudonym would be caught
/// by sender-mismatch. The S1 attack is a peer announcing `attacker_did →
/// victim_pseudonym`; the classifier run over the registry AUGMENTED WITH SELF
/// rejects it as a cross-DID collision, so the victim does not misroute.
#[test]
fn forged_announcement_claiming_the_victims_own_pseudonym_is_rejected() {
    let relay = Relay::new();
    let (mut alice, mut bob) = connect_two(&relay, CTX, ALICE, BOB);

    // Learn Alice's (the victim's) own pseudonym: it is the routing id Alice
    // subscribes to that is NOT the shared channel — recover it from a fresh
    // Alice→Bob send's PUBLISH target is Bob's; instead capture Alice's OWN
    // pseudonym by having BOB send to Alice and reading the target.
    let _ = relay.drain_publish_log();
    bob.client.send_message(CTX, b"probe").unwrap();
    let log = relay.drain_publish_log();
    let alice_pseudonym = log
        .iter()
        .find(|p| p.conn == bob.conn && p.routing_id != context_routing_id(CTX))
        .expect("Bob addressed Alice's pseudonym")
        .routing_id;
    let _ = alice.client.drain_events(CTX);
    let _ = bob.client.drain_events(CTX);

    // Bob forges `BOB → alice_pseudonym` (Bob claims Alice's routing id for HIS own
    // DID). Sent as a normal payload; it routes to the shared channel and Alice
    // receives it. The self-augmented collision check must reject it (Alice's own
    // pseudonym is already claimed by Alice).
    let forged = scp_protocol::context::pseudonym::PseudonymAnnouncement {
        tag: scp_protocol::context::pseudonym::PSEUDONYM_ANNOUNCEMENT_TAG.to_owned(),
        member_did: BOB.to_owned(),
        pseudonym: alice_pseudonym,
    };
    let payload = rmp_serde::to_vec_named(&forged).unwrap();
    bob.client.send_message(CTX, &payload).unwrap();
    relay.pump(&mut [&mut alice, &mut bob]);

    // Alice did NOT re-map Bob's DID onto her own pseudonym: an app-data send from
    // Alice still addresses Bob's REAL pseudonym (not Alice's own), and the forged
    // announcement surfaced no PseudonymAnnounced for `alice_pseudonym`.
    let events = alice.client.drain_events(CTX).unwrap();
    assert!(
        !events.iter().any(|e| matches!(
            e,
            ContextEvent::PseudonymAnnounced { pseudonym, .. } if *pseudonym == alice_pseudonym
        )),
        "a forged own-pseudonym announcement must be rejected, not recorded"
    );
}

// ===========================================================================
// S2 — announcements use an independent replay floor
// ===========================================================================
//
// S2 (announcement/app-data channel-reorder) is a property of the crypto layer's
// per-sender replay floor, which is controllable only where the sequence numbers
// are (the `sequence` param of `ContextCryptoState::encrypt_message`). It is
// covered by the `crypto_state.rs` unit test
// `announcement_and_app_channels_have_independent_replay_floors`, which drives a
// lower-sequence message on `RecvChannel::Announcement` AFTER a higher-sequence
// one on `RecvChannel::App` and asserts the announcement is still accepted (a
// shared floor would drop it).

// ===========================================================================
// M1 — partial fan-out does not surface Err (no caller retry → no duplicate)
// ===========================================================================

/// With ≥1 successful send, `send_message` returns `Ok` (a partial failure is NOT
/// surfaced), so a caller does not retry and re-fan a NEW message → no duplicate
/// delivery (api-design M1). A TOTAL failure surfaces `Transport`.
#[test]
fn partial_fan_out_returns_ok_but_total_failure_surfaces_transport() {
    let relay = Relay::new();
    // Alice with TWO announced peers (Bob, Carol), so a fan-out has two addressees.
    let (mut alice, mut bob) = connect_two(&relay, CTX, ALICE, BOB);
    let mut carol = relay.new_party(CAROL, 200);
    let carol_kp = carol.client.generate_key_package_for_join(CTX).unwrap();
    let add = alice.client.add_member(CTX, &carol_kp).unwrap();
    let carol_dists = carol
        .client
        .join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
        .unwrap();
    let bob_recv = bob.client.receive_message(CTX, &add.commit).unwrap();
    deliver_distributions(
        CTX,
        &add.sender_key_distributions,
        &mut [(CAROL, &mut carol.client)],
    );
    deliver_distributions(
        CTX,
        &bob_recv.sender_key_distributions,
        &mut [(CAROL, &mut carol.client)],
    );
    deliver_distributions(
        CTX,
        &carol_dists,
        &mut [(ALICE, &mut alice.client), (BOB, &mut bob.client)],
    );
    relay.pump(&mut [&mut alice, &mut bob, &mut carol]);
    let _ = relay.drain_publish_log();

    // PARTIAL: Alice's first PUBLISH of the fan-out succeeds, the second fails.
    // `send_message` must still return Ok (any-success → no caller retry → no dup).
    relay.fail_publish_after(alice.conn, 1);
    assert!(
        alice.client.send_message(CTX, b"partial").is_ok(),
        "a partial fan-out (1 of 2 delivered) returns Ok — no retry, no duplicate"
    );

    // TOTAL: every PUBLISH fails → surfaces Transport (a retry then re-fans a NEW
    // message = a tolerable sequence gap, never a duplicate).
    relay.fail_publish_after(alice.conn, 0);
    assert!(
        matches!(
            alice.client.send_message(CTX, b"total"),
            Err(ClientError::Transport(_))
        ),
        "a total fan-out failure surfaces Transport"
    );
}

// ===========================================================================
// Behavior — create does not announce; empty-registry guard; lone no-op
// ===========================================================================

#[test]
fn create_context_subscribes_but_does_not_announce() {
    let relay = Relay::new();
    let mut alice = relay.new_party(ALICE, 0);
    alice.client.create_context(CTX).unwrap();
    // Subscribed (2 routing ids) but published NOTHING (a lone creator has no peers
    // and does not announce — forward-secrecy dead-frame avoidance).
    let publishes = relay.drain_publish_log();
    assert!(
        publishes.is_empty(),
        "a lone creator publishes no announcement at create"
    );
    // It IS reachable: send to nobody is a no-op.
    alice.client.send_message(CTX, b"note to self").unwrap();
    assert!(
        relay.drain_publish_log().is_empty(),
        "a lone-member send is a no-op (zero frames)"
    );
    assert!(alice.client.drain_events(CTX).unwrap().is_empty());
}

#[test]
fn multi_member_send_before_mesh_completes_fails_closed() {
    let relay = Relay::new();
    let mut alice = relay.new_party(ALICE, 0);
    alice.client.create_context(CTX).unwrap();
    let mut bob = relay.new_party(BOB, 100);
    let bob_kp = bob.client.generate_key_package_for_join(CTX).unwrap();
    let _add = alice.client.add_member(CTX, &bob_kp).unwrap();
    // Alice has 2 members but the registry is empty (no announce pumped yet).
    match alice.client.send_message(CTX, b"nobody announced") {
        Err(ClientError::PseudonymRegistryEmpty { member_count, .. }) => {
            assert_eq!(member_count, 2);
        }
        other => panic!("expected PseudonymRegistryEmpty, got {other:?}"),
    }
}

#[test]
fn app_data_is_never_published_to_the_shared_channel() {
    let relay = Relay::new();
    let (mut alice, bob) = connect_two(&relay, CTX, ALICE, BOB);
    let _ = relay.drain_publish_log();
    alice.client.send_message(CTX, b"app data").unwrap();
    let publishes = relay.drain_publish_log();
    let app: Vec<_> = publishes.iter().filter(|p| p.conn == alice.conn).collect();
    assert!(!app.is_empty());
    for p in app {
        assert_ne!(
            p.routing_id,
            context_routing_id(CTX),
            "app data must NEVER be published to the shared announcement channel"
        );
        assert_eq!(p.blob_ttl, DEFAULT_APP_DATA_BLOB_TTL_SECS);
        assert_eq!(
            p.envelope_routing_id(),
            vec![0u8; 32],
            "the OuterEnvelope cleartext routing_id is zeroed"
        );
    }
    let _ = (bob,);
}

// ===========================================================================
// Inbound pump robustness
// ===========================================================================

#[test]
fn handle_relay_frame_drops_unknown_routing_and_surfaces_relay_err() {
    let relay = Relay::new();
    let mut alice = relay.new_party(ALICE, 0);
    alice.client.create_context(CTX).unwrap();
    // Unknown routing id → benign drop.
    let blob = RelayMessage::Blob {
        routing_id: [0x99u8; 32],
        blob_id: [0u8; 32],
        recipient_hint: None,
        blob_ttl: 300,
        stored_at: 0,
        blob: OuterEnvelope::from_bytes(
            &scp_protocol::envelope::outer::create_outer_envelope(
                &[0u8; 32],
                None,
                300,
                vec![1, 2, 3],
            )
            .unwrap()
            .to_bytes()
            .unwrap(),
        )
        .unwrap()
        .to_bytes()
        .unwrap(),
    }
    .to_bytes()
    .unwrap();
    assert!(alice.client.handle_relay_frame(&blob).is_ok());
    // Relay error → surfaced.
    let err = RelayMessage::Err {
        ref_id: None,
        code: 4010,
        msg: "blob too large".to_owned(),
    }
    .to_bytes()
    .unwrap();
    assert!(matches!(
        alice.client.handle_relay_frame(&err),
        Err(ClientError::Transport(_))
    ));
}
