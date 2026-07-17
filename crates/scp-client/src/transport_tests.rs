//! End-to-end unit tests for the ADR-057 transport slice: the injected `Socket`
//! outbound port, the §9.10.4 pseudonym fan-out, and the announce/ingest mesh.
//!
//! These drive TWO in-process [`ScpClient`]s over the crate's `#[cfg(test)]`
//! loopback [`Socket`](crate::socket::loopback::LoopbackSocket), routing captured
//! relay `PUBLISH` frames back into a peer's [`ScpClient::handle_relay_frame`] as
//! relay `BLOB`s (the "dumb pipe" a real relay is). Everything is synchronous —
//! no tokio, no real relay.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use scp_clock::{Clock, SystemClock, TestClock};
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::pseudonym::{PSEUDONYM_ANNOUNCEMENT_TAG, PseudonymAnnouncement};
use scp_protocol::context::{broadcast_routing_id, context_routing_id};
use scp_protocol::envelope::outer::{DEFAULT_APP_DATA_BLOB_TTL_SECS, OuterEnvelope};
use scp_relay_client::{ClientMessage, RelayMessage};

use crate::signer::LocalSigner;
use crate::socket::loopback::LoopbackSocket;
use crate::storage::{MemoryStorage, Storage};
use crate::{ClientError, ScpClient};

const CTX: &str = "ctx-adr057-transport-slice";
const ALICE: &str = "did:key:z6MkAliceTransportSliceFixtureKeyAAAAAAAAA";
const BOB: &str = "did:key:z6MkBobTransportSliceFixtureKeyBBBBBBBBBBBB";
const CAROL: &str = "did:key:z6MkCarolTransportSliceFixtureKeyCCCCCCCCC";

/// A client plus a handle to its loopback socket (so a test can inspect/route the
/// frames it published).
struct Party {
    client: ScpClient,
    socket: LoopbackSocket,
}

/// Builds a fresh client over a fixed clock and an in-memory store, with a
/// loopback socket. Seeds the clock from real `now` so minted `KeyPackage`
/// `Lifetime`s stay valid against openmls's un-injectable internal clock.
fn new_party(did: &str, offset: u64) -> Party {
    let socket = LoopbackSocket::new();
    let signer = Arc::new(LocalSigner::active(did));
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(SystemClock.now_secs() + offset));
    let client = ScpClient::new(signer, storage, clock, Arc::new(socket.clone()))
        .expect("construct fresh client");
    Party { client, socket }
}

/// Every captured `PUBLISH` frame, decoded to `(relay routing_id, decoded
/// OuterEnvelope)`. Drains the socket. `SUBSCRIBE` frames are filtered out.
fn drain_publishes(socket: &LoopbackSocket) -> Vec<([u8; 32], OuterEnvelope)> {
    socket
        .take_frames()
        .into_iter()
        .filter_map(|frame| match ClientMessage::from_bytes(&frame).unwrap() {
            ClientMessage::Publish {
                routing_id, blob, ..
            } => Some((routing_id, OuterEnvelope::from_bytes(&blob).unwrap())),
            _ => None,
        })
        .collect()
}

/// Every captured `SUBSCRIBE` `routing_id` (drains the socket).
fn drain_subscribes(socket: &LoopbackSocket) -> Vec<[u8; 32]> {
    socket
        .take_frames()
        .into_iter()
        .filter_map(|frame| match ClientMessage::from_bytes(&frame).unwrap() {
            ClientMessage::Subscribe { routing_id, .. } => Some(routing_id),
            _ => None,
        })
        .collect()
}

/// Converts a captured `PUBLISH` frame into the relay `BLOB` frame a peer's
/// `handle_relay_frame` consumes (the relay forwarding the blob to a subscriber).
fn publish_to_blob(publish_frame: &[u8]) -> Option<Vec<u8>> {
    match ClientMessage::from_bytes(publish_frame).ok()? {
        ClientMessage::Publish {
            routing_id,
            recipient_hint,
            blob_ttl,
            blob,
            ..
        } => RelayMessage::Blob {
            routing_id,
            blob_id: [0u8; 32],
            recipient_hint,
            blob_ttl,
            stored_at: 0,
            blob,
        }
        .to_bytes()
        .ok(),
        _ => None,
    }
}

/// Drains every `PUBLISH` `from` captured and delivers each as a relay `BLOB`
/// into `to` via `handle_relay_frame`. Returns the number of `PUBLISH` frames
/// delivered.
fn route_publishes(from: &LoopbackSocket, to: &mut ScpClient) -> usize {
    let frames = from.take_frames();
    let mut delivered = 0;
    for frame in frames {
        if let Some(blob) = publish_to_blob(&frame) {
            to.handle_relay_frame(&blob).expect("deliver relay blob");
            delivered += 1;
        }
    }
    delivered
}

/// Drives Alice (creator) + Bob (joiner) to a fully-connected state: MLS group
/// shared, sender keys exchanged both ways, and both pseudonym registries
/// populated (each has pumped the other's announcement). Returns both parties
/// with their socket buffers DRAINED and ready.
fn connect_alice_and_bob() -> (Party, Party) {
    let mut alice = new_party(ALICE, 0);
    alice.client.create_context(CTX).unwrap();

    let mut bob = new_party(BOB, 100);
    let bob_kp = bob.client.generate_key_package_for_join(CTX).unwrap();

    let add = alice.client.add_member(CTX, &bob_kp).unwrap();
    let bob_dists = bob
        .client
        .join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
        .unwrap();

    // Exchange §9.16 sender keys (delivered out-of-band via receive_message, the
    // existing in-tab distribution model — the transport slice routes app data +
    // announcements, not sender-key distributions).
    bob.client
        .receive_message(CTX, &add.sender_key_distributions[0].ciphertext)
        .unwrap();
    alice
        .client
        .receive_message(CTX, &bob_dists[0].ciphertext)
        .unwrap();

    // Pump each side's announcement to the other so both registries populate.
    route_publishes(&alice.socket, &mut bob.client);
    route_publishes(&bob.socket, &mut alice.client);

    // Clear any residual buffered events (e.g. PseudonymAnnounced) + captured
    // frames so callers start from a clean slate.
    let _ = alice.client.drain_events(CTX);
    let _ = bob.client.drain_events(CTX);
    let _ = alice.socket.take_frames();
    let _ = bob.socket.take_frames();

    (alice, bob)
}

/// Finds the first `MessageReceived` in a drained event list and returns its
/// payload.
fn first_received(events: &[ContextEvent]) -> Option<Vec<u8>> {
    events.iter().find_map(|e| match e {
        ContextEvent::MessageReceived { payload, .. } => Some(payload.clone()),
        _ => None,
    })
}

// ---------------------------------------------------------------------------
// Local-pseudonym derivation (via the driver)
// ---------------------------------------------------------------------------

#[test]
fn create_context_derives_and_subscribes_but_does_not_announce() {
    let mut alice = new_party(ALICE, 0);
    alice.client.create_context(CTX).unwrap();

    // Two SUBSCRIBEs (local pseudonym + shared announcement channel), NO PUBLISH
    // (a lone creator has no audience; it re-announces on add).
    let subs = drain_subscribes(&alice.socket);
    assert_eq!(
        subs.len(),
        2,
        "create subscribes to exactly two routing ids"
    );
    assert!(
        subs.contains(&context_routing_id(CTX)),
        "subscribes to the shared announcement channel"
    );
    // The other subscription is the local pseudonym (a non-reserved value).
    let local = *subs
        .iter()
        .find(|s| **s != context_routing_id(CTX))
        .unwrap();
    assert_ne!(local, [0u8; 32]);
    assert_ne!(local, broadcast_routing_id(CTX));
    // No PUBLISH at creation.
    assert!(
        drain_publishes(&alice.socket).is_empty(),
        "a lone creator publishes no announcement"
    );
}

#[test]
fn local_pseudonym_is_stable_across_restore() {
    // The driver re-derives the same local pseudonym from the restored MLS key, so
    // it re-subscribes to the SAME routing id after a reopen.
    let socket = LoopbackSocket::new();
    let signer = Arc::new(LocalSigner::active(ALICE));
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(SystemClock.now_secs()));

    let mut first = ScpClient::new(
        Arc::clone(&signer) as _,
        Arc::clone(&storage),
        Arc::clone(&clock),
        Arc::new(socket.clone()),
    )
    .unwrap();
    first.create_context(CTX).unwrap();
    let mut before: Vec<[u8; 32]> = drain_subscribes(&socket);
    before.sort_unstable();
    drop(first);

    // Reopen over the same storage.
    let socket2 = LoopbackSocket::new();
    let _second = ScpClient::new(signer, storage, clock, Arc::new(socket2.clone())).unwrap();
    let mut after: Vec<[u8; 32]> = drain_subscribes(&socket2);
    after.sort_unstable();

    assert_eq!(
        before, after,
        "restore re-derives the same pseudonym and re-subscribes to the same routing ids"
    );
}

// ---------------------------------------------------------------------------
// Announce
// ---------------------------------------------------------------------------

#[test]
fn add_member_announces_exactly_one_publish_to_the_shared_channel() {
    let mut alice = new_party(ALICE, 0);
    alice.client.create_context(CTX).unwrap();
    let _ = alice.socket.take_frames(); // clear create's subscribes

    let mut bob = new_party(BOB, 100);
    let bob_kp = bob.client.generate_key_package_for_join(CTX).unwrap();
    let _add = alice.client.add_member(CTX, &bob_kp).unwrap();

    let publishes = drain_publishes(&alice.socket);
    assert_eq!(
        publishes.len(),
        1,
        "add_member re-announces with exactly one PUBLISH"
    );
    let (routing_id, envelope) = &publishes[0];
    assert_eq!(
        *routing_id,
        context_routing_id(CTX),
        "an announcement is published to the shared context routing id ONLY"
    );
    assert_eq!(
        envelope.routing_id,
        vec![0u8; 32],
        "the outer envelope's cleartext routing_id is zeroed (§9.10.4 privacy)"
    );
    assert_eq!(envelope.blob_ttl, DEFAULT_APP_DATA_BLOB_TTL_SECS);
}

// ---------------------------------------------------------------------------
// Round-trip (both directions)
// ---------------------------------------------------------------------------

#[test]
fn two_party_app_data_round_trip_over_the_socket() {
    let (mut alice, mut bob) = connect_alice_and_bob();

    // Alice → Bob.
    alice.client.send_message(CTX, b"hello Bob").unwrap();
    let delivered = route_publishes(&alice.socket, &mut bob.client);
    assert_eq!(delivered, 1, "one PUBLISH to Bob's single pseudonym");
    let bob_events = bob.client.drain_events(CTX).unwrap();
    assert_eq!(
        first_received(&bob_events).as_deref(),
        Some(&b"hello Bob"[..]),
        "Bob recovers Alice's plaintext"
    );

    // Bob → Alice (reverse direction).
    bob.client.send_message(CTX, b"hi Alice").unwrap();
    route_publishes(&bob.socket, &mut alice.client);
    let alice_events = alice.client.drain_events(CTX).unwrap();
    assert_eq!(
        first_received(&alice_events).as_deref(),
        Some(&b"hi Alice"[..]),
        "Alice recovers Bob's plaintext (reverse direction)"
    );
}

#[test]
fn app_data_is_never_published_to_the_shared_context_routing_id() {
    let (mut alice, _bob) = connect_alice_and_bob();
    alice.client.send_message(CTX, b"app data").unwrap();
    let publishes = drain_publishes(&alice.socket);
    assert!(!publishes.is_empty(), "app data produced a PUBLISH");
    for (routing_id, _) in &publishes {
        assert_ne!(
            *routing_id,
            context_routing_id(CTX),
            "app data must NEVER be published to the shared announcement channel"
        );
    }
}

// ---------------------------------------------------------------------------
// Fan-out addressing (N peers ⇒ N identical PUBLISH frames)
// ---------------------------------------------------------------------------

#[test]
fn fan_out_addresses_every_announced_peer_with_an_identical_blob() {
    // Alice + Bob + Carol. Alice sends once; the fan-out must produce two PUBLISH
    // frames (one per peer pseudonym), byte-identical blob, zeroed envelope routing.
    let mut alice = new_party(ALICE, 0);
    alice.client.create_context(CTX).unwrap();

    // Add Bob.
    let mut bob = new_party(BOB, 100);
    let bob_kp = bob.client.generate_key_package_for_join(CTX).unwrap();
    let add_bob = alice.client.add_member(CTX, &bob_kp).unwrap();
    let bob_dists = bob
        .client
        .join_context_encrypted(
            CTX,
            &add_bob.welcome,
            &add_bob.event_log,
            &add_bob.wrapping_keys,
        )
        .unwrap();
    bob.client
        .receive_message(CTX, &add_bob.sender_key_distributions[0].ciphertext)
        .unwrap();
    alice
        .client
        .receive_message(CTX, &bob_dists[0].ciphertext)
        .unwrap();

    // Add Carol. Bob is a bystander: he processes the add-Commit and its
    // distributions so all three share keys.
    let mut carol = new_party(CAROL, 200);
    let carol_kp = carol.client.generate_key_package_for_join(CTX).unwrap();
    let add_carol = alice.client.add_member(CTX, &carol_kp).unwrap();
    let carol_dists = carol
        .client
        .join_context_encrypted(
            CTX,
            &add_carol.welcome,
            &add_carol.event_log,
            &add_carol.wrapping_keys,
        )
        .unwrap();
    // Bob processes Alice's add-Carol commit (advances his epoch + re-distributes +
    // re-announces).
    let bob_recv = bob.client.receive_message(CTX, &add_carol.commit).unwrap();
    // Deliver everyone's Carol-directed sender keys to Carol.
    carol
        .client
        .receive_message(CTX, &add_carol.sender_key_distributions[0].ciphertext)
        .unwrap();
    for dist in &bob_recv.sender_key_distributions {
        carol.client.receive_message(CTX, &dist.ciphertext).unwrap();
    }
    // Carol seals to Alice + Bob.
    for dist in &carol_dists {
        if dist.target_did == ALICE {
            alice.client.receive_message(CTX, &dist.ciphertext).unwrap();
        } else if dist.target_did == BOB {
            bob.client.receive_message(CTX, &dist.ciphertext).unwrap();
        }
    }

    // Pump all announcements so Alice learns both Bob and Carol.
    route_publishes(&bob.socket, &mut alice.client);
    route_publishes(&carol.socket, &mut alice.client);
    // (Alice's own re-announces are captured in alice.socket; drain them so the
    // send below is the only thing we inspect.)
    let _ = alice.socket.take_frames();

    // Alice sends once → fan out to BOTH peers.
    alice.client.send_message(CTX, b"to everyone").unwrap();
    let publishes = drain_publishes(&alice.socket);
    assert_eq!(
        publishes.len(),
        2,
        "one PUBLISH per announced peer (Bob, Carol)"
    );
    let blob0 = &publishes[0].1.encrypted_blob;
    let blob1 = &publishes[1].1.encrypted_blob;
    assert_eq!(
        blob0, blob1,
        "the fan-out blob is byte-identical across peers"
    );
    let mut targets: Vec<[u8; 32]> = publishes.iter().map(|(rid, _)| *rid).collect();
    targets.sort_unstable();
    assert_ne!(
        targets[0], targets[1],
        "the two peer routing ids are distinct"
    );
    for (rid, env) in &publishes {
        assert_ne!(*rid, context_routing_id(CTX), "never the shared channel");
        assert_eq!(env.routing_id, vec![0u8; 32], "zeroed envelope routing");
        assert_eq!(env.blob_ttl, DEFAULT_APP_DATA_BLOB_TTL_SECS);
    }
}

// ---------------------------------------------------------------------------
// Empty-registry guard
// ---------------------------------------------------------------------------

#[test]
fn multi_member_empty_registry_send_fails_closed() {
    // Alice adds Bob but the announcements are NOT pumped, so Alice's peer registry
    // is empty. An app-data send must fail with PseudonymRegistryEmpty (retryable),
    // BEFORE advancing the ratchet — never silently drop.
    let mut alice = new_party(ALICE, 0);
    alice.client.create_context(CTX).unwrap();
    let mut bob = new_party(BOB, 100);
    let bob_kp = bob.client.generate_key_package_for_join(CTX).unwrap();
    let _add = alice.client.add_member(CTX, &bob_kp).unwrap();
    let _ = alice.socket.take_frames();

    match alice.client.send_message(CTX, b"nobody announced") {
        Err(ClientError::PseudonymRegistryEmpty {
            context_id,
            member_count,
        }) => {
            assert_eq!(context_id, CTX);
            assert_eq!(member_count, 2);
        }
        other => panic!("expected PseudonymRegistryEmpty, got {other:?}"),
    }
    assert!(
        drain_publishes(&alice.socket).is_empty(),
        "a failed send publishes nothing"
    );
    // The ratchet did not advance: no MessageSent buffered.
    assert!(
        alice.client.drain_events(CTX).unwrap().is_empty(),
        "a registry-empty failure buffers no MessageSent"
    );
}

#[test]
fn lone_member_send_is_a_noop() {
    // A lone creator (no peers) sending app data is a silent no-op: zero frames,
    // Ok(()), no MessageSent.
    let mut alice = new_party(ALICE, 0);
    alice.client.create_context(CTX).unwrap();
    let _ = alice.socket.take_frames();

    alice.client.send_message(CTX, b"note to self").unwrap();
    assert!(
        drain_publishes(&alice.socket).is_empty(),
        "a lone-member send produces zero frames"
    );
    assert!(
        alice.client.drain_events(CTX).unwrap().is_empty(),
        "a lone-member no-op buffers no MessageSent"
    );
}

// ---------------------------------------------------------------------------
// Classify wiring via receive_message
// ---------------------------------------------------------------------------

#[test]
fn accepted_announcement_records_peer_and_emits_event_not_message() {
    // The connect helper already pumped Bob's announcement into Alice. Assert Alice
    // learned Bob's pseudonym (an app-data send now fans out to it) and that a
    // freshly-pumped announcement surfaces PseudonymAnnounced, not MessageReceived.
    let mut alice = new_party(ALICE, 0);
    alice.client.create_context(CTX).unwrap();
    let mut bob = new_party(BOB, 100);
    let bob_kp = bob.client.generate_key_package_for_join(CTX).unwrap();
    let add = alice.client.add_member(CTX, &bob_kp).unwrap();
    let bob_dists = bob
        .client
        .join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.wrapping_keys)
        .unwrap();
    bob.client
        .receive_message(CTX, &add.sender_key_distributions[0].ciphertext)
        .unwrap();
    alice
        .client
        .receive_message(CTX, &bob_dists[0].ciphertext)
        .unwrap();
    let _ = alice.client.drain_events(CTX);

    // Deliver Bob's announcement to Alice.
    route_publishes(&bob.socket, &mut alice.client);
    let events = alice.client.drain_events(CTX).unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ContextEvent::PseudonymAnnounced { member_did, .. } if member_did.0 == BOB)),
        "an accepted announcement emits PseudonymAnnounced for the announcer"
    );
    assert!(
        first_received(&events).is_none(),
        "an announcement is NOT surfaced as a MessageReceived"
    );
}

#[test]
fn forged_announcement_sender_mismatch_is_dropped() {
    // A member cannot announce a pseudonym under a DIFFERENT member's DID: the
    // classify sender-mismatch guard drops it (no registry insert, no event).
    let (mut alice, mut bob) = connect_alice_and_bob();

    // Bob crafts an announcement claiming to be Alice, and sends it as a normal
    // app-data payload (which routes to Alice's pseudonym). Alice must drop it.
    let forged = PseudonymAnnouncement {
        tag: PSEUDONYM_ANNOUNCEMENT_TAG.to_owned(),
        member_did: ALICE.to_owned(), // forged: Bob is the real sender
        pseudonym: [0x42u8; 32],
    };
    let payload = rmp_serde::to_vec_named(&forged).unwrap();
    // Bob sends it. is_pseudonym_announcement_payload → routes to the shared
    // channel, so Alice (subscribed there) receives it, but classify rejects it
    // because the MLS sender (Bob) != claimed member_did (Alice).
    bob.client.send_message(CTX, &payload).unwrap();
    route_publishes(&bob.socket, &mut alice.client);

    let events = alice.client.drain_events(CTX).unwrap();
    assert!(
        !events.iter().any(|e| matches!(
            e,
            ContextEvent::PseudonymAnnounced { pseudonym, .. } if *pseudonym == [0x42u8; 32]
        )),
        "a forged (sender-mismatch) announcement must be dropped, not recorded"
    );
    assert!(
        first_received(&events).is_none(),
        "a rejected announcement is not surfaced as a message either"
    );
}

// ---------------------------------------------------------------------------
// Inbound pump robustness
// ---------------------------------------------------------------------------

#[test]
fn handle_relay_frame_drops_unknown_routing_id() {
    let mut alice = new_party(ALICE, 0);
    alice.client.create_context(CTX).unwrap();
    // A BLOB on a routing id Alice does not track is dropped (not an error).
    let blob = RelayMessage::Blob {
        routing_id: [0x99u8; 32],
        blob_id: [0u8; 32],
        recipient_hint: None,
        blob_ttl: DEFAULT_APP_DATA_BLOB_TTL_SECS,
        stored_at: 0,
        blob: vec![1, 2, 3],
    }
    .to_bytes()
    .unwrap();
    assert!(
        alice.client.handle_relay_frame(&blob).is_ok(),
        "an unknown routing id is dropped, not an error"
    );
}

#[test]
fn handle_relay_frame_surfaces_relay_error() {
    let mut alice = new_party(ALICE, 0);
    alice.client.create_context(CTX).unwrap();
    let err_frame = RelayMessage::Err {
        ref_id: None,
        code: 4010,
        msg: "blob too large".to_owned(),
    }
    .to_bytes()
    .unwrap();
    assert!(matches!(
        alice.client.handle_relay_frame(&err_frame),
        Err(ClientError::Transport(_))
    ));
}
