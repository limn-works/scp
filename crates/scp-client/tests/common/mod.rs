//! Shared harness for the ADR-057 transport-slice integration tests.
//!
//! Provides a loopback [`Socket`] that captures every relay `ClientMessage` frame
//! the driver publishes, plus helpers to route captured `PUBLISH` frames back into
//! a peer's [`ScpClient::handle_relay_frame`] as relay `BLOB`s (the "dumb pipe" a
//! real relay is) and to extract the inner MLS ciphertext from a captured frame
//! (for the adversarial tests that tamper with it).
//!
//! Every integration test builds its clients over this harness — there is no real
//! relay and no tokio; delivery is synchronous and test-controlled.

#![allow(dead_code)] // not every integration test uses every helper

use std::sync::{Arc, Mutex};

use scp_client::{LocalSigner, MemoryStorage, ScpClient, Socket, Storage};
use scp_clock::{Clock, SystemClock, TestClock};
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::envelope::outer::OuterEnvelope;
use scp_relay_client::{ClientMessage, RelayMessage};

/// A loopback socket recording every frame the driver publishes, in order. Cheap
/// to clone (an `Arc` handle over the shared buffer): hold one handle to inspect
/// frames while the driver holds another as its injected `Arc<dyn Socket>`.
#[derive(Clone, Default)]
pub struct CaptureSocket {
    frames: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl CaptureSocket {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drains and returns every captured frame in insertion order.
    #[allow(clippy::expect_used)]
    pub fn take_frames(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.frames.lock().expect("capture frame lock"))
    }
}

impl Socket for CaptureSocket {
    #[allow(clippy::expect_used)]
    fn send(&self, frame: Vec<u8>) -> Result<(), String> {
        self.frames.lock().expect("capture frame lock").push(frame);
        Ok(())
    }
}

/// A client plus a handle to its capture socket.
pub struct Party {
    pub client: ScpClient,
    pub socket: CaptureSocket,
}

/// Builds a fresh client over a fixed clock (seeded from real `now` + `offset`, so
/// minted `KeyPackage` `Lifetime`s stay valid against openmls's un-injectable
/// internal clock) and an in-memory store, with a capture socket.
#[allow(clippy::expect_used)]
#[must_use]
pub fn new_party(did: &str, offset: u64) -> Party {
    let socket = CaptureSocket::new();
    let signer = Arc::new(LocalSigner::active(did));
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(SystemClock.now_secs() + offset));
    let client = ScpClient::new(signer, storage, clock, Arc::new(socket.clone()))
        .expect("construct fresh client");
    Party { client, socket }
}

/// Builds a client over CALLER-SUPPLIED dependencies (for tests that need to share
/// a storage backend across a restore, or inject a failing storage). Returns the
/// client; the caller keeps its own socket handle.
#[allow(clippy::expect_used)]
#[must_use]
pub fn client_with(
    signer: Arc<LocalSigner>,
    storage: Arc<dyn Storage>,
    clock: Arc<dyn Clock>,
    socket: CaptureSocket,
) -> ScpClient {
    ScpClient::new(signer, storage, clock, Arc::new(socket)).expect("construct client")
}

/// Converts a captured `PUBLISH` frame into the relay `BLOB` frame a peer's
/// `handle_relay_frame` consumes. `None` for a non-`PUBLISH` frame (e.g. a
/// `SUBSCRIBE`).
#[allow(clippy::expect_used)]
#[must_use]
pub fn publish_to_blob(publish_frame: &[u8]) -> Option<Vec<u8>> {
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

/// Drains every `PUBLISH` `from` captured and delivers each as a relay `BLOB` into
/// `to` via `handle_relay_frame`. Returns the number delivered. Panics if delivery
/// errors (the tests want a loud failure on an unexpected relay-path error).
#[allow(clippy::expect_used)]
pub fn route_publishes(from: &CaptureSocket, to: &mut ScpClient) -> usize {
    let mut delivered = 0;
    for frame in from.take_frames() {
        if let Some(blob) = publish_to_blob(&frame) {
            to.handle_relay_frame(&blob).expect("deliver relay blob");
            delivered += 1;
        }
    }
    delivered
}

/// The inner MLS ciphertext of the LAST captured `PUBLISH` frame — decoded from its
/// `OuterEnvelope`. For adversarial tests that tamper with the wire ciphertext.
/// Drains the socket.
#[allow(clippy::expect_used)]
#[must_use]
pub fn last_ciphertext(socket: &CaptureSocket) -> Vec<u8> {
    socket
        .take_frames()
        .into_iter()
        .rev()
        .find_map(|frame| match ClientMessage::from_bytes(&frame).ok()? {
            ClientMessage::Publish { blob, .. } => {
                Some(OuterEnvelope::from_bytes(&blob).ok()?.encrypted_blob)
            }
            _ => None,
        })
        .expect("a PUBLISH frame was captured")
}

/// All `(routing_id, inner_ciphertext)` pairs from the captured `PUBLISH` frames.
/// Drains the socket.
#[allow(clippy::expect_used)]
#[must_use]
pub fn published_ciphertexts(socket: &CaptureSocket) -> Vec<([u8; 32], Vec<u8>)> {
    socket
        .take_frames()
        .into_iter()
        .filter_map(|frame| match ClientMessage::from_bytes(&frame).ok()? {
            ClientMessage::Publish {
                routing_id, blob, ..
            } => Some((
                routing_id,
                OuterEnvelope::from_bytes(&blob).ok()?.encrypted_blob,
            )),
            _ => None,
        })
        .collect()
}

/// The first `MessageReceived` payload in a drained event list, if any.
#[must_use]
pub fn first_received(events: &[ContextEvent]) -> Option<Vec<u8>> {
    events.iter().find_map(|e| match e {
        ContextEvent::MessageReceived { payload, .. } => Some(payload.clone()),
        _ => None,
    })
}

/// Connects Alice (creator) and Bob (joiner) into a fully wired 2-party context:
/// MLS group shared, §9.16 sender keys exchanged both ways, and both pseudonym
/// registries populated (each pumped the other's announcement). Buffers and socket
/// frames are DRAINED before return, so callers start clean.
///
/// `ctx` is the context id; `alice_did` / `bob_did` the identities.
#[allow(clippy::expect_used)]
#[must_use]
pub fn connect_two(ctx: &str, alice_did: &str, bob_did: &str) -> (Party, Party) {
    let mut alice = new_party(alice_did, 0);
    alice.client.create_context(ctx).expect("alice creates");

    let mut bob = new_party(bob_did, 100);
    let bob_kp = bob
        .client
        .generate_key_package_for_join(ctx)
        .expect("bob key package");
    let add = alice
        .client
        .add_member(ctx, &bob_kp)
        .expect("alice adds bob");
    let bob_dists = bob
        .client
        .join_context_encrypted(ctx, &add.welcome, &add.event_log, &add.wrapping_keys)
        .expect("bob joins");

    // Exchange §9.16 sender keys out-of-band (the in-tab distribution model).
    bob.client
        .receive_message(ctx, &add.sender_key_distributions[0].ciphertext)
        .expect("bob installs alice key");
    alice
        .client
        .receive_message(ctx, &bob_dists[0].ciphertext)
        .expect("alice installs bob key");

    // Pump each side's announcement to the other so both registries populate.
    route_publishes(&alice.socket, &mut bob.client);
    route_publishes(&bob.socket, &mut alice.client);

    let _ = alice.client.drain_events(ctx);
    let _ = bob.client.drain_events(ctx);
    let _ = alice.socket.take_frames();
    let _ = bob.socket.take_frames();
    (alice, bob)
}

/// Sends `plaintext` from `from` and routes the resulting fan-out into `to`,
/// returning `to`'s drained events. A convenience for the common
/// send→route→drain triple.
#[allow(clippy::expect_used)]
pub fn send_and_route(
    ctx: &str,
    from: &mut Party,
    to: &mut ScpClient,
    plaintext: &[u8],
) -> Vec<ContextEvent> {
    from.client.send_message(ctx, plaintext).expect("send");
    route_publishes(&from.socket, to);
    to.drain_events(ctx).expect("drain")
}
