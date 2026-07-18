//! Realistic in-memory relay mock for the ADR-057 transport-slice integration
//! tests.
//!
//! This models the **shipped** relay's client-facing semantics faithfully — the
//! properties the earlier naive loopback ignored and that hid two blockers:
//!
//! - a **subscription table** (`routing_id → subscribers`), populated by
//!   `SUBSCRIBE` frames, so a `PUBLISH` reaches only those subscribed AT PUBLISH
//!   TIME (subscribe-before-publish timing — `scp-transport/src/relay/subscription.rs`);
//! - delivery of a `PUBLISH` to **ALL current subscribers of its routing id,
//!   INCLUDING the publisher** — the relay has no publisher exclusion
//!   (`deliver_to_subscribers`), so a member receives the echo of its own
//!   announcement on the shared `context_routing_id` it publishes to and
//!   subscribes to (the **self-echo** the driver must drop benignly);
//! - **backfill on `since: Some`** only — stored blobs newer than `since` are
//!   delivered on subscribe; with `since: None` (what the client uses) there is NO
//!   backfill (`scp-transport/src/webtransport/session.rs`).
//!
//! Each [`Party`] owns a connection into the shared [`Relay`]; the client's
//! injected [`RelaySink`] forwards its `SUBSCRIBE`/`PUBLISH` frames into the relay,
//! and [`Relay::pump`] delivers queued `BLOB`s back into each party's
//! `handle_relay_frame` **iteratively until quiescent**, so the reciprocal-announce
//! cascade (§9.10.4 mesh completion) runs to completion exactly as it would over a
//! live relay.

#![allow(dead_code)] // not every integration test uses every helper
#![allow(clippy::significant_drop_tightening)] // test-harness Mutex; early-drop restructuring adds noise, not value

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use scp_client::{LocalSigner, MemoryStorage, RelaySink, ScpClient, Storage};
use scp_clock::{Clock, SystemClock, TestClock};
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::envelope::outer::OuterEnvelope;
use scp_relay_client::{ClientMessage, RelayMessage};

/// A relay connection id (one per client).
pub type ConnId = u64;

/// A blob the relay stored (for `since:Some` backfill) + who published it.
#[derive(Clone)]
struct StoredBlob {
    routing_id: [u8; 32],
    blob_id: [u8; 32],
    recipient_hint: Option<[u8; 32]>,
    blob_ttl: u32,
    stored_at: u64,
    blob: Vec<u8>,
}

/// A record of one `PUBLISH` for test assertions.
#[derive(Clone)]
pub struct PublishRecord {
    pub conn: ConnId,
    pub routing_id: [u8; 32],
    pub blob_ttl: u32,
    /// The wire `OuterEnvelope` bytes (the `blob` field of the `PUBLISH`).
    pub blob: Vec<u8>,
}

impl PublishRecord {
    /// The inner MLS ciphertext (the `OuterEnvelope.encrypted_blob`) — for the
    /// adversarial tests that tamper with the wire ciphertext.
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn inner_ciphertext(&self) -> Vec<u8> {
        OuterEnvelope::from_bytes(&self.blob)
            .expect("PUBLISH blob is an OuterEnvelope")
            .encrypted_blob
    }

    /// The `OuterEnvelope`'s cleartext `routing_id` (must be zeroed — §9.10.4).
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn envelope_routing_id(&self) -> Vec<u8> {
        OuterEnvelope::from_bytes(&self.blob)
            .expect("PUBLISH blob is an OuterEnvelope")
            .routing_id
    }
}

#[derive(Default)]
struct RelayState {
    /// `routing_id` → connections currently subscribed (subscribe-time membership).
    subscriptions: HashMap<[u8; 32], Vec<ConnId>>,
    /// `routing_id` → stored blobs, for `since:Some` backfill.
    stored: HashMap<[u8; 32], Vec<StoredBlob>>,
    /// Per-connection inbound queue of serialized `RelayMessage` frames.
    queues: HashMap<ConnId, VecDeque<Vec<u8>>>,
    /// Every `PUBLISH` seen, in order — for test assertions.
    publish_log: Vec<PublishRecord>,
    /// Per-connection: fail a conn's `PUBLISH` sends after this many succeed (for
    /// the M1 partial-fan-out test). `SUBSCRIBE`s always succeed.
    fail_publish_after: HashMap<ConnId, usize>,
    /// Per-connection: FAIL every `send` (SUBSCRIBE and PUBLISH alike) until the
    /// connection's total send count reaches this threshold — modelling a sink
    /// whose WebSocket is still closed during context entry, so the entry-time
    /// best-effort SUBSCRIBEs are silently dropped (P0 resubscribe test). A later
    /// `resubscribe_all` re-drives them once the socket is open.
    fail_send_until: HashMap<ConnId, usize>,
    /// Per-connection total `send` attempts (drives `fail_send_until`).
    send_attempts: HashMap<ConnId, usize>,
    /// Per-connection count of `PUBLISH` sends attempted (drives `fail_publish_after`).
    publish_attempts: HashMap<ConnId, usize>,
    next_conn: ConnId,
    /// Monotonic `stored_at` + `blob_id` source.
    clock: u64,
}

/// A faithful in-memory relay shared across all [`Party`]s in a test.
#[derive(Clone)]
pub struct Relay {
    state: Arc<Mutex<RelayState>>,
}

impl Default for Relay {
    fn default() -> Self {
        Self::new()
    }
}

impl Relay {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(RelayState::default())),
        }
    }

    /// Allocates a new connection + its injected [`RelaySink`].
    #[allow(clippy::expect_used)]
    fn connect(&self) -> (ConnId, Arc<dyn RelaySink>) {
        let mut st = self.state.lock().expect("relay lock");
        let conn = st.next_conn;
        st.next_conn += 1;
        st.queues.entry(conn).or_default();
        let sink = RelayConn {
            conn,
            state: Arc::clone(&self.state),
        };
        (conn, Arc::new(sink))
    }

    /// Builds a fresh [`Party`] connected to this relay, over a fixed clock seeded
    /// from real `now + offset` (so minted `KeyPackage` `Lifetime`s stay valid
    /// against openmls's un-injectable internal clock) and an in-memory store.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn new_party(&self, did: &str, offset: u64) -> Party {
        let (conn, sink) = self.connect();
        let signer = Arc::new(LocalSigner::active(did));
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let clock: Arc<dyn Clock> = Arc::new(TestClock::new(SystemClock.now_secs() + offset));
        let client = ScpClient::new(signer, storage, clock, sink).expect("construct client");
        Party { client, conn }
    }

    /// Builds a [`Party`] over CALLER-SUPPLIED deps (for restore/poison tests that
    /// share a storage handle or inject a failing store), connected to this relay.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn party_with(
        &self,
        signer: Arc<LocalSigner>,
        storage: Arc<dyn Storage>,
        clock: Arc<dyn Clock>,
    ) -> Party {
        let (conn, sink) = self.connect();
        let client = ScpClient::new(signer, storage, clock, sink).expect("construct client");
        Party { client, conn }
    }

    /// Drains this relay's per-connection queues into the given parties'
    /// `handle_relay_frame`, **iteratively until quiescent** — so a receive that
    /// triggers a reciprocal `PUBLISH` (which enqueues more `BLOB`s) is itself
    /// pumped, running the §9.10.4 announce cascade to completion. Panics on a
    /// `handle_relay_frame` error (tests want a loud failure on an unexpected
    /// relay-path error) or if the cascade fails to converge within a generous
    /// bound (a non-converging reciprocal cascade is a bug).
    #[allow(clippy::expect_used)]
    pub fn pump(&self, parties: &mut [&mut Party]) {
        // A converged mesh quiesces in O(members) rounds; bound generously so a
        // real non-convergence fails loudly instead of hanging.
        let max_rounds = 64 + parties.len() * parties.len() * 4;
        for _ in 0..max_rounds {
            let mut delivered_any = false;
            for party in parties.iter_mut() {
                loop {
                    // Take ONE frame with the lock held, then RELEASE before calling
                    // handle_relay_frame (which re-locks to publish reciprocals).
                    let frame = {
                        let mut st = self.state.lock().expect("relay lock");
                        st.queues.get_mut(&party.conn).and_then(VecDeque::pop_front)
                    };
                    let Some(frame) = frame else { break };
                    delivered_any = true;
                    party
                        .client
                        .handle_relay_frame(&frame)
                        .expect("handle_relay_frame");
                }
            }
            if !delivered_any {
                return; // quiescent
            }
        }
        panic!("relay pump did not converge within the round bound (reciprocal cascade bug?)");
    }

    /// Drains and returns every recorded `PUBLISH` in order (for assertions).
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn drain_publish_log(&self) -> Vec<PublishRecord> {
        std::mem::take(&mut self.state.lock().expect("relay lock").publish_log)
    }

    /// The number of frames currently queued for `conn` (undelivered).
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn queued(&self, conn: ConnId) -> usize {
        self.state
            .lock()
            .expect("relay lock")
            .queues
            .get(&conn)
            .map_or(0, VecDeque::len)
    }

    /// Makes `conn`'s NEXT `n` `PUBLISH` sends succeed and every one after that
    /// FAIL (a partial fan-out — M1). Resets the attempt counter so `n` is relative
    /// to this call, not to publishes already made during setup. `SUBSCRIBE`s are
    /// unaffected.
    #[allow(clippy::expect_used)]
    pub fn fail_publish_after(&self, conn: ConnId, n: usize) {
        let mut st = self.state.lock().expect("relay lock");
        st.fail_publish_after.insert(conn, n);
        st.publish_attempts.insert(conn, 0);
    }

    /// Makes EVERY `send` on `conn` (SUBSCRIBE and PUBLISH) FAIL until the
    /// connection has attempted `n` sends, then succeed — modelling a sink whose
    /// WebSocket is still closed during context entry (the entry-time best-effort
    /// SUBSCRIBEs are dropped), then opens. Drives the P0 `resubscribe_all` test.
    #[allow(clippy::expect_used)]
    pub fn fail_send_until(&self, conn: ConnId, n: usize) {
        let mut st = self.state.lock().expect("relay lock");
        st.fail_send_until.insert(conn, n);
        st.send_attempts.insert(conn, 0);
    }

    /// Publishes a blob to `routing_id` from an EXTERNAL peer (a synthetic
    /// connection), fanning it out through the subscription table exactly like a
    /// real `PUBLISH` — so it reaches a conn ONLY if that conn is currently
    /// subscribed to `routing_id`. Models another member publishing while the
    /// subscribe timing is under test (P0 resubscribe). Returns nothing; assert
    /// delivery via [`Self::queued`] or by pumping.
    #[allow(clippy::expect_used)]
    pub fn external_publish(&self, routing_id: [u8; 32], blob: Vec<u8>) {
        // A reserved conn id no `Party` is allocated (ids count up from 0).
        const EXTERNAL_CONN: ConnId = ConnId::MAX;
        let mut st = self.state.lock().expect("relay lock");
        st.apply(
            EXTERNAL_CONN,
            ClientMessage::Publish {
                ref_id: None,
                routing_id,
                recipient_hint: None,
                blob_ttl: 300,
                blob,
            },
        );
    }

    /// Injects a raw `RelayMessage::Blob` frame directly into `conn`'s queue,
    /// bypassing the subscription table — for adversarial tests that deliver a
    /// crafted/foreign/tampered blob to a specific victim.
    #[allow(clippy::expect_used)]
    pub fn inject_blob(&self, conn: ConnId, routing_id: [u8; 32], blob: Vec<u8>) {
        let frame = RelayMessage::Blob {
            routing_id,
            blob_id: [0u8; 32],
            recipient_hint: None,
            blob_ttl: 300,
            stored_at: 0,
            blob,
        }
        .to_bytes()
        .expect("serialize injected blob");
        self.state
            .lock()
            .expect("relay lock")
            .queues
            .entry(conn)
            .or_default()
            .push_back(frame);
    }
}

impl RelayState {
    /// Applies a client's outbound `ClientMessage` (from a [`RelayConn`] send).
    fn apply(&mut self, conn: ConnId, msg: ClientMessage) {
        match msg {
            ClientMessage::Subscribe {
                routing_id, since, ..
            } => {
                let subs = self.subscriptions.entry(routing_id).or_default();
                if !subs.contains(&conn) {
                    subs.push(conn);
                }
                // Backfill on `since: Some` only (the relay's session semantics).
                if let Some(since) = since {
                    let backfill: Vec<StoredBlob> = self
                        .stored
                        .get(&routing_id)
                        .map(|blobs| {
                            blobs
                                .iter()
                                .filter(|b| b.stored_at > since)
                                .cloned()
                                .collect()
                        })
                        .unwrap_or_default();
                    for b in backfill {
                        self.enqueue_blob(conn, &b);
                    }
                }
            }
            ClientMessage::Publish {
                routing_id,
                recipient_hint,
                blob_ttl,
                blob,
                ..
            } => {
                self.clock += 1;
                let mut blob_id = [0u8; 32];
                blob_id[..8].copy_from_slice(&self.clock.to_be_bytes());
                let stored = StoredBlob {
                    routing_id,
                    blob_id,
                    recipient_hint,
                    blob_ttl,
                    stored_at: self.clock,
                    blob: blob.clone(),
                };
                self.publish_log.push(PublishRecord {
                    conn,
                    routing_id,
                    blob_ttl,
                    blob,
                });
                self.stored
                    .entry(routing_id)
                    .or_default()
                    .push(stored.clone());
                // Deliver to ALL current subscribers INCLUDING the publisher (no
                // publisher exclusion — the self-echo the relay actually performs).
                let subs = self
                    .subscriptions
                    .get(&routing_id)
                    .cloned()
                    .unwrap_or_default();
                for sub in subs {
                    self.enqueue_blob(sub, &stored);
                }
            }
            // The driver never sends these; ignore.
            ClientMessage::Unsubscribe { .. }
            | ClientMessage::Query { .. }
            | ClientMessage::Delete { .. }
            | ClientMessage::Ack { .. }
            | ClientMessage::Ping { .. }
            | ClientMessage::BridgeRegister { .. }
            | ClientMessage::BridgeData { .. } => {}
        }
    }

    #[allow(clippy::expect_used)]
    fn enqueue_blob(&mut self, conn: ConnId, b: &StoredBlob) {
        let frame = RelayMessage::Blob {
            routing_id: b.routing_id,
            blob_id: b.blob_id,
            recipient_hint: b.recipient_hint,
            blob_ttl: b.blob_ttl,
            stored_at: b.stored_at,
            blob: b.blob.clone(),
        }
        .to_bytes()
        .expect("serialize blob");
        self.queues.entry(conn).or_default().push_back(frame);
    }
}

/// The injected [`RelaySink`] for one connection: forwards the client's outbound
/// `ClientMessage` frames into the shared [`Relay`].
struct RelayConn {
    conn: ConnId,
    state: Arc<Mutex<RelayState>>,
}

impl RelaySink for RelayConn {
    fn send(&self, frame: Vec<u8>) -> Result<(), String> {
        let msg = ClientMessage::from_bytes(&frame).map_err(|e| format!("relay decode: {e}"))?;
        let mut st = self.state.lock().map_err(|e| format!("relay lock: {e}"))?;
        // Simulated closed-socket-during-entry (P0): every send fails until the
        // conn has attempted `fail_send_until` sends, modelling a WebSocket that is
        // not yet open. The count advances even on the failed attempts so the sink
        // "opens" after the threshold.
        {
            let attempt = {
                let n = st.send_attempts.entry(self.conn).or_default();
                *n += 1;
                *n
            };
            if let Some(&threshold) = st.fail_send_until.get(&self.conn)
                && attempt <= threshold
            {
                return Err("simulated closed socket".to_owned());
            }
        }
        // Simulated partial-fan-out failure (M1): a conn's PUBLISHes fail after its
        // configured limit. SUBSCRIBEs always succeed.
        if matches!(msg, ClientMessage::Publish { .. }) {
            let attempt = {
                let n = st.publish_attempts.entry(self.conn).or_default();
                *n += 1;
                *n
            };
            if let Some(&limit) = st.fail_publish_after.get(&self.conn)
                && attempt > limit
            {
                return Err("simulated publish failure".to_owned());
            }
        }
        st.apply(self.conn, msg);
        Ok(())
    }
}

/// A client plus its relay connection id.
pub struct Party {
    pub client: ScpClient,
    pub conn: ConnId,
}

/// The first `MessageReceived` payload in a drained event list, if any.
#[must_use]
pub fn first_received(events: &[ContextEvent]) -> Option<Vec<u8>> {
    events.iter().find_map(|e| match e {
        ContextEvent::MessageReceived { payload, .. } => Some(payload.clone()),
        _ => None,
    })
}

/// Delivers the in-tab §9.16 sender-key distributions to their targets (directly
/// via `receive_message`, the out-of-band model — not over the relay). Maps
/// `target_did` to the matching party.
#[allow(clippy::expect_used)]
pub fn deliver_distributions(
    ctx: &str,
    dists: &[scp_client::SenderKeyDistribution],
    parties: &mut [(&str, &mut ScpClient)],
) {
    for d in dists {
        for (did, client) in parties.iter_mut() {
            if *did == d.target_did {
                client
                    .receive_message(ctx, &d.ciphertext)
                    .expect("install sender-key distribution");
            }
        }
    }
}

/// Connects Alice (creator) + Bob (joiner) into a fully-wired 2-party context over
/// the realistic relay: MLS group shared, §9.16 sender keys exchanged both ways,
/// and — via the reciprocal-announce cascade pumped to quiescence — BOTH pseudonym
/// registries populated. Both parties' buffers are drained before return.
#[allow(clippy::expect_used)]
#[must_use]
pub fn connect_two(relay: &Relay, ctx: &str, alice_did: &str, bob_did: &str) -> (Party, Party) {
    let mut alice = relay.new_party(alice_did, 0);
    alice.client.create_context(ctx).expect("alice creates");

    let mut bob = relay.new_party(bob_did, 100);
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

    // Exchange §9.16 sender keys out-of-band, THEN pump the announce cascade (Bob's
    // join-announce → Alice reciprocates → Bob reciprocates → quiescent).
    deliver_distributions(
        ctx,
        &add.sender_key_distributions,
        &mut [(alice_did, &mut alice.client), (bob_did, &mut bob.client)],
    );
    deliver_distributions(
        ctx,
        &bob_dists,
        &mut [(alice_did, &mut alice.client), (bob_did, &mut bob.client)],
    );
    relay.pump(&mut [&mut alice, &mut bob]);

    let _ = alice.client.drain_events(ctx);
    let _ = bob.client.drain_events(ctx);
    let _ = relay.drain_publish_log();
    (alice, bob)
}
