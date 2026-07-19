//! Faithful in-memory relay mock for the ADR-057 transport-slice integration
//! tests — the SINGLE source of the relay-fidelity anchor shared by the
//! `scp-client` and `scp-client-wasm` test suites.
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
//! Each suite owns its own client construction and orchestration and wires a
//! [`RelaySink`] from [`Relay::connect`] into its client; [`Relay::pump`] delivers
//! queued `BLOB`s back into each party's relay-frame handler **iteratively until
//! quiescent** through the [`RelayParty`] trait, so the reciprocal-announce cascade
//! (§9.10.4 mesh completion) runs to completion exactly as it would over a live
//! relay — driving either `ScpClient` (native driver) or `WasmScpClient`
//! (`#[wasm_bindgen]` surface) with ONE relay model.

// Test-support crate: it ships nothing (referenced only as a dev-dependency) and
// wants LOUD failures — the pump panics on an unexpected relay-path error or a
// non-converging cascade (both are bugs), and the wire-decode helpers `expect`
// on inputs the tests construct.
#![allow(clippy::expect_used, clippy::panic)]
// The helpers `expect` on internal invariants (lock acquisition, test-constructed
// wire bytes) and `pump`'s panic-on-non-convergence is documented in prose; formal
// per-method `# Panics` scaffolding is disproportionate noise for a test harness
// (the origin test binaries this crate single-sources were exempt from the lint).
#![allow(clippy::missing_panics_doc)]
// Test-harness Mutex; early-drop restructuring adds noise, not value.
#![allow(clippy::significant_drop_tightening)]

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use scp_client::RelaySink;
use scp_protocol::envelope::outer::OuterEnvelope;
use scp_relay_client::{ClientMessage, RelayMessage};

/// A relay connection id (one per client).
pub type ConnId = u64;

/// A party the [`Relay`] can drive: it owns a relay connection id and accepts a
/// delivered frame into its relay-frame handler.
///
/// Implemented by each suite's client wrapper (`ScpClient` in `scp-client`,
/// `WasmScpClient` in `scp-client-wasm`) so that ONE [`Relay::pump`] drives either
/// surface. `deliver` returns `Err(String)` on a handler error so the pump can
/// fail loudly — a relay-path error in these tests is a bug.
pub trait RelayParty {
    /// This party's relay connection id (the queue key the pump drains).
    fn conn_id(&self) -> ConnId;
    /// Deliver one queued relay frame into this party's relay-frame handler.
    ///
    /// # Errors
    /// Returns the handler's error rendered as a string; the pump panics on it.
    fn deliver(&mut self, frame: Vec<u8>) -> Result<(), String>;
}

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
    /// The connection that published this frame.
    pub conn: ConnId,
    /// The cleartext relay `routing_id` the frame was published to.
    pub routing_id: [u8; 32],
    /// The relay-storage TTL (seconds) the publish requested.
    pub blob_ttl: u32,
    /// The wire `OuterEnvelope` bytes (the `blob` field of the `PUBLISH`).
    pub blob: Vec<u8>,
}

impl PublishRecord {
    /// The inner MLS ciphertext (the `OuterEnvelope.encrypted_blob`) — for the
    /// adversarial tests that tamper with the wire ciphertext.
    #[must_use]
    pub fn inner_ciphertext(&self) -> Vec<u8> {
        OuterEnvelope::from_bytes(&self.blob)
            .expect("PUBLISH blob is an OuterEnvelope")
            .encrypted_blob
    }

    /// The `OuterEnvelope`'s cleartext `routing_id` (must be zeroed — §9.10.4).
    #[must_use]
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

/// A faithful in-memory relay shared across all parties in a test.
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
    /// A fresh empty relay.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(RelayState::default())),
        }
    }

    /// Allocates a new connection + its injected [`RelaySink`]. Each suite wires
    /// the returned sink into a freshly-constructed client (`ScpClient` /
    /// `WasmScpClient`) and pairs the returned [`ConnId`] with it.
    #[must_use]
    pub fn connect(&self) -> (ConnId, Arc<dyn RelaySink>) {
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

    /// Drains this relay's per-connection queues into the given parties'
    /// relay-frame handlers, **iteratively until quiescent** — so a receive that
    /// triggers a reciprocal `PUBLISH` (which enqueues more `BLOB`s) is itself
    /// pumped, running the §9.10.4 announce cascade to completion. Panics on a
    /// handler error (tests want a loud failure on an unexpected relay-path error)
    /// or if the cascade fails to converge within a generous bound (a
    /// non-converging reciprocal cascade is a bug).
    pub fn pump<P: RelayParty>(&self, parties: &mut [&mut P]) {
        // A converged mesh quiesces in O(members) rounds; bound generously so a
        // real non-convergence fails loudly instead of hanging.
        let max_rounds = 64 + parties.len() * parties.len() * 4;
        for _ in 0..max_rounds {
            let mut delivered_any = false;
            for party in parties.iter_mut() {
                let conn = party.conn_id();
                loop {
                    // Take ONE frame with the lock held, then RELEASE before calling
                    // the handler (which re-locks to publish reciprocals).
                    let frame = {
                        let mut st = self.state.lock().expect("relay lock");
                        st.queues.get_mut(&conn).and_then(VecDeque::pop_front)
                    };
                    let Some(frame) = frame else { break };
                    delivered_any = true;
                    party.deliver(frame).expect("handle_relay_frame");
                }
            }
            if !delivered_any {
                return; // quiescent
            }
        }
        panic!("relay pump did not converge within the round bound (reciprocal cascade bug?)");
    }

    /// Drains and returns every recorded `PUBLISH` in order (for assertions).
    #[must_use]
    pub fn drain_publish_log(&self) -> Vec<PublishRecord> {
        std::mem::take(&mut self.state.lock().expect("relay lock").publish_log)
    }

    /// The number of frames currently queued for `conn` (undelivered).
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
    pub fn fail_publish_after(&self, conn: ConnId, n: usize) {
        let mut st = self.state.lock().expect("relay lock");
        st.fail_publish_after.insert(conn, n);
        st.publish_attempts.insert(conn, 0);
    }

    /// Makes EVERY `send` on `conn` (SUBSCRIBE and PUBLISH) FAIL until the
    /// connection has attempted `n` sends, then succeed — modelling a sink whose
    /// WebSocket is still closed during context entry (the entry-time best-effort
    /// SUBSCRIBEs are dropped), then opens. Drives the P0 `resubscribe_all` test.
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
    pub fn external_publish(&self, routing_id: [u8; 32], blob: Vec<u8>) {
        // A reserved conn id no party is allocated (ids count up from 0).
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
