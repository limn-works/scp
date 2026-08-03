//! WebSocket client for the SCP native relay.
//!
//! [`NativeRelayClient`] manages the WebSocket connection lifecycle to an SCP
//! native relay: connect, reconnect with exponential backoff, PING keepalive,
//! and message send/receive. It translates between [`ClientMessage`] /
//! [`RelayMessage`] and the WebSocket binary frame wire format.
//!
//! The client is designed to be used by [`NativeRelayAdapter`] (in
//! `adapter.rs`) which maps the [`TransportAdapter`] trait onto this client.
//!
//! # Connection recovery
//!
//! On abnormal close, the client reconnects with exponential backoff and
//! random jitter (up to 25% of each delay) to prevent thundering herd
//! when multiple clients reconnect after a relay failure: ~1s, ~2s, ~4s,
//! ~8s, ~16s, ~30s cap (each with jitter). Uses the shared
//! [`ReconnectBackoff`](crate::backoff::ReconnectBackoff) implementation.
//! On reconnect, the adapter re-issues SUBSCRIBE for each routing ID with
//! `since = last_stored_at - 5s` overlap. The client deduplicates received
//! blobs via `blob_id`.
//!
//! See ADR-004 in `.docs/adrs/phase-1.md` for the full specification.
//!
//! [`NativeRelayAdapter`]: super::adapter::NativeRelayAdapter
//! [`TransportAdapter`]: crate::TransportAdapter

use scp_clock::Clock;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use futures::{SinkExt, StreamExt};
use rand::RngCore;
use scp_core::envelope::OuterEnvelope;

use tokio::sync::{Mutex, RwLock, mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;

use zeroize::Zeroizing;

use crate::backoff::ReconnectBackoff;
use crate::error::TransportError;
use crate::subscription::TransportSubscriptionMap;
use scp_relay_client::{ClientMessage, RelayMessage};

/// Keepalive interval: client sends PING every 30 seconds.
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum number of reconnection attempts before giving up.
///
/// With exponential backoff (1s, 2s, 4s, 8s, 16s, 30s cap), 6 attempts
/// cover the same range as the previous fixed backoff steps but with
/// random jitter on each delay to prevent thundering herd (BLACK-001).
#[allow(dead_code)]
const MAX_RECONNECT_ATTEMPTS: u32 = 6;

/// Overlap subtracted from local receive time for reconnect backfill (5 seconds).
///
/// Used by [`NativeRelayClient::reconnect`] on connection loss.
#[allow(dead_code)]
const RECONNECT_OVERLAP: Duration = Duration::from_secs(5);

/// Maximum acceptable deviation between relay-provided `stored_at` and local
/// wall-clock time (60 seconds). Deviations beyond this threshold are logged as
/// warnings because they may indicate a malicious relay backdating or
/// forward-dating timestamps.
#[allow(dead_code)]
const RELAY_TIMESTAMP_DEVIATION_THRESHOLD_SECS: u64 = 60;

/// Maximum number of entries in the deduplication LRU cache.
///
/// Blob IDs older than this window are evicted, bounding memory usage to
/// approximately 320 KiB (10,000 x 32 bytes). This is sufficient for typical
/// reconnect overlap windows while preventing unbounded growth in long-lived
/// connections (#1466).
const DEDUP_CACHE_CAPACITY: usize = 10_000;

/// A pending request waiting for a relay response keyed by `ref_id`.
struct PendingRequest {
    tx: oneshot::Sender<RelayMessage>,
}

/// Internal message type for subscription channels.
///
/// Wraps [`RelayMessage`] and adds internal-only signals (e.g.,
/// [`Reconnected`](SubscriptionMessage::Reconnected)) that do not exist in the
/// wire protocol but are needed by the adapter's stream translation layer.
#[derive(Debug, Clone)]
pub enum SubscriptionMessage {
    /// A relay message received from the wire.
    Relay(RelayMessage),
    /// The client reconnected to the relay. Subscribers should expect
    /// possible duplicate envelopes from the overlap window.
    Reconnected,
    /// A received blob's content did not match its declared `blob_id`.
    ///
    /// The relay provided a `blob_id` (SHA-256 hash) that does not match
    /// `SHA-256(blob)`, indicating a malicious or buggy relay.
    BlobIntegrityError {
        /// The `blob_id` declared by the relay (hex-encoded).
        expected: String,
        /// The SHA-256 hash of the actual blob content (hex-encoded).
        actual: String,
    },
}

/// Subscription state tracked for reconnection recovery.
///
/// Stored as the value type in the [`TransportSubscriptionMap`]; the routing
/// ID is the map key, not duplicated here.
///
/// `Clone` is required because [`TransportSubscriptionMap::snapshot`] returns
/// owned `(RoutingId, V)` pairs (used by [`NativeRelayClient::reconnect`]).
/// Snapshots may yield one final clone of the sender that delivers a message
/// after the caller has invoked `unsubscribe` -- receivers tolerate this in
/// the same way `mpsc::Receiver` already tolerates the close race.
#[derive(Debug, Clone)]
struct SubscriptionState {
    /// The last relay-provided `stored_at` timestamp (untrusted metadata, used
    /// only for logging/diagnostics -- never for security decisions).
    last_stored_at: Option<u64>,
    /// Local monotonic time when the most recent message was received for this
    /// subscription. Used for reconnection window calculations instead of
    /// relay-provided `stored_at` to prevent malicious relays from manipulating
    /// the reconnect window.
    last_local_receive: Option<Instant>,
    /// Channel for pushing subscription messages to the stream.
    tx: mpsc::Sender<SubscriptionMessage>,
    /// When `true`, BLOB messages routed to this subscription bypass the
    /// client-global `seen_blob_ids` dedup LRU — neither checked against it nor
    /// committed to it.
    ///
    /// Set only by the one-shot raw public-record QUERY path
    /// ([`NativeRelayClient::query_raw`], §3.10.4). The dedup LRU is a
    /// live-subscription redelivery guard: it suppresses a blob the client has
    /// already delivered once (e.g. after a reconnect). A one-shot DID-record
    /// resolution needs every candidate on every call, so applying the dedup
    /// there would drop the genuine record on the second resolution of an
    /// unchanged DID — the bug this flag closes. Ordinary `subscribe`/`query`
    /// leave it `false` and keep the dedup.
    bypass_dedup: bool,
}

/// Shared inner state of the WebSocket client.
struct ClientInner {
    /// Pending request-response pairs keyed by `ref_id`.
    pending: HashMap<String, PendingRequest>,
    /// Next `ref_id` counter for generating unique request IDs.
    next_ref_id: u64,
    /// LRU cache of blob IDs already seen (for deduplication on reconnect).
    ///
    /// Bounded to [`DEDUP_CACHE_CAPACITY`] entries to prevent unbounded memory
    /// growth in long-lived connections. Oldest entries are evicted when the
    /// cache is full.
    seen_blob_ids: lru::LruCache<[u8; 32], ()>,
    /// Whether the client is currently connected.
    connected: bool,
}

/// WebSocket client for the SCP native relay.
///
/// Manages the connection lifecycle including keepalive PINGs and
/// reconnection with exponential backoff + jitter. Send operations use
/// request-response correlation via `ref_id`. Subscription streams
/// are delivered via channels.
///
/// # Thread safety
///
/// The client is `Send + Sync` and safe to use from multiple tasks.
/// Internal state is protected by `RwLock` and `Mutex`.
/// # Cloning
///
/// `NativeRelayClient` is cheaply cloneable -- most fields are `Arc`-wrapped.
/// Clones share the same underlying WebSocket connection, state, and
/// background tasks. This is used internally by
/// [`NativeRelayAdapter::start_cover_traffic`] to give the background cover
/// traffic task a handle to the connection without requiring `Arc<Self>` at
/// the adapter level.
///
/// [`NativeRelayAdapter::start_cover_traffic`]: super::adapter::NativeRelayAdapter::start_cover_traffic
#[derive(Clone)]
pub struct NativeRelayClient {
    /// The relay URL (e.g., `ws://127.0.0.1:9000/scp/v1`).
    url: String,
    /// Optional bearer token for `Authorization: Bearer <token>` header.
    ///
    /// When `Some`, the token is included in the WebSocket upgrade request
    /// headers. Used for connecting to relay endpoints that require
    /// authentication (e.g., bridge token on `ApplicationNode` relays).
    bearer_token: Option<Arc<Zeroizing<String>>>,
    /// Shared mutable inner state.
    inner: Arc<RwLock<ClientInner>>,
    /// Active subscriptions keyed by routing ID.
    ///
    /// Lives as a sibling of [`ClientInner`] (rather than a field within it)
    /// because [`TransportSubscriptionMap`] manages its own internal lock;
    /// nesting it inside `RwLock<ClientInner>` would double-lock.
    subscriptions: Arc<TransportSubscriptionMap<SubscriptionState>>,
    /// The WebSocket sink (write half), protected by a mutex for exclusive
    /// write access across concurrent callers.
    ws_sink: Arc<Mutex<Option<WsSink>>>,
    /// Handle to the background reader task (for shutdown).
    reader_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Handle to the keepalive task (for shutdown).
    keepalive_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Shutdown signal sender.
    shutdown_tx: Arc<Mutex<Option<tokio::sync::broadcast::Sender<()>>>>,
}

/// Type alias for the WebSocket write half.
type WsSink = futures::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    Message,
>;

/// Type alias for the WebSocket read half.
type WsSource = futures::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
>;

/// RAII cleanup for a one-shot QUERY's temporary subscription and pending
/// terminator entry.
///
/// A one-shot QUERY (`query` / `query_raw`) registers a temporary subscription
/// keyed by `routing_id` (for BLOB delivery) plus a `pending` oneshot keyed by
/// `ref_id` (for the terminal `query_complete` / `Err`). There are `.await`
/// points between registration and cleanup — the sink write and the collect
/// loop — so an inline `remove` at the end is skipped whenever the future is
/// dropped mid-flight. The composer wraps each per-relay `query` in a 5s
/// timeout and drops the future on expiry, so mid-flight drop is the COMMON
/// case, not a corner case.
///
/// A leaked `routing_id` subscription is the dangerous one: the next
/// `query_raw` for that DID hits the "already subscribed" early-return and
/// fails permanently until reconnect, and leaks accumulate toward the global
/// subscription cap (`MAX_TRANSPORT_SUBSCRIPTIONS`). This guard removes it on
/// EVERY exit — happy path, error, deadline, and external cancellation.
///
/// The `pending` entry is removed best-effort via a non-blocking `try_write`
/// (Drop cannot `.await`). A residual entry is harmless: `ref_id` is monotonic
/// so it can never collide, and it self-cleans when the relay's terminal
/// message (which carries this `ref_id`) reaches `dispatch_relay_message`, or on
/// reconnect.
struct QueryScopeGuard {
    subscriptions: Arc<TransportSubscriptionMap<SubscriptionState>>,
    inner: Arc<RwLock<ClientInner>>,
    rid: crate::traits::RoutingId,
    ref_id: String,
}

impl Drop for QueryScopeGuard {
    fn drop(&mut self) {
        // Total, synchronous removal of the collision-causing resource.
        self.subscriptions.remove(&self.rid);
        // Best-effort, non-blocking removal of the pending terminator entry.
        if let Ok(mut state) = self.inner.try_write() {
            state.pending.remove(&self.ref_id);
        }
    }
}

impl NativeRelayClient {
    /// Creates a new client targeting the given relay URL and immediately
    /// connects.
    ///
    /// The URL should be of the form `ws://host:port/scp/v1` or
    /// `wss://host:port/scp/v1`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionFailed`] if the initial connection
    /// cannot be established.
    pub async fn connect(url: &str) -> Result<Self, TransportError> {
        Self::connect_with_bearer(url, None).await
    }

    /// Creates a new client targeting the given relay URL with an optional
    /// bearer token and immediately connects.
    ///
    /// When `bearer_token` is `Some`, the token is included as an
    /// `Authorization: Bearer <token>` header in the WebSocket upgrade
    /// request. This is required for connecting to relay endpoints that
    /// enforce bridge token authentication (e.g., `ApplicationNode` relays).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionFailed`] if the initial connection
    /// cannot be established (including authentication rejection).
    pub async fn connect_with_bearer(
        url: &str,
        bearer_token: Option<Zeroizing<String>>,
    ) -> Result<Self, TransportError> {
        let inner = Arc::new(RwLock::new(ClientInner {
            pending: HashMap::new(),
            next_ref_id: 1,
            seen_blob_ids: lru::LruCache::new(
                NonZeroUsize::new(DEDUP_CACHE_CAPACITY).unwrap_or(NonZeroUsize::MIN),
            ),
            connected: false,
        }));

        let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

        let client = Self {
            url: url.to_string(),
            bearer_token: bearer_token.map(Arc::new),
            inner,
            subscriptions: Arc::new(TransportSubscriptionMap::new()),
            ws_sink: Arc::new(Mutex::new(None)),
            reader_handle: Arc::new(Mutex::new(None)),
            keepalive_handle: Arc::new(Mutex::new(None)),
            shutdown_tx: Arc::new(Mutex::new(Some(shutdown_tx))),
        };

        client.establish_connection().await?;
        Ok(client)
    }

    /// Establishes (or re-establishes) the WebSocket connection.
    ///
    /// When a bearer token is configured, builds an `http::Request` with the
    /// `Authorization: Bearer <token>` header before upgrading the connection.
    async fn establish_connection(&self) -> Result<(), TransportError> {
        let (ws_stream, _response) = if let Some(ref token) = self.bearer_token {
            use tokio_tungstenite::tungstenite::client::IntoClientRequest;

            let mut request = self
                .url
                .as_str()
                .into_client_request()
                .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
            request.headers_mut().insert(
                "Authorization",
                format!("Bearer {}", token.as_str()).parse().map_err(
                    |_: tokio_tungstenite::tungstenite::http::header::InvalidHeaderValue| {
                        TransportError::ConnectionFailed(
                            "bearer token contains characters not valid in HTTP header values"
                                .to_string(),
                        )
                    },
                )?,
            );
            tokio_tungstenite::connect_async(request)
                .await
                .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?
        } else {
            tokio_tungstenite::connect_async(&self.url)
                .await
                .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?
        };

        let (sink, source) = ws_stream.split();

        *self.ws_sink.lock().await = Some(sink);
        self.inner.write().await.connected = true;

        // Get shutdown receivers for the background tasks.
        let shutdown_rx = {
            let guard = self.shutdown_tx.lock().await;
            guard
                .as_ref()
                .map(tokio::sync::broadcast::Sender::subscribe)
                .ok_or_else(|| TransportError::ConnectionFailed("client shut down".to_string()))?
        };

        let keepalive_shutdown_rx = {
            let guard = self.shutdown_tx.lock().await;
            guard
                .as_ref()
                .map(tokio::sync::broadcast::Sender::subscribe)
                .ok_or_else(|| TransportError::ConnectionFailed("client shut down".to_string()))?
        };

        // Spawn the reader task.
        let reader_handle = tokio::spawn(Self::reader_loop(
            source,
            Arc::clone(&self.inner),
            Arc::clone(&self.subscriptions),
            shutdown_rx,
        ));
        *self.reader_handle.lock().await = Some(reader_handle);

        // Spawn the keepalive task.
        let keepalive_handle = tokio::spawn(Self::keepalive_loop(
            Arc::clone(&self.ws_sink),
            Arc::clone(&self.inner),
            keepalive_shutdown_rx,
        ));
        *self.keepalive_handle.lock().await = Some(keepalive_handle);

        Ok(())
    }

    /// Background task that reads from the WebSocket and dispatches relay
    /// messages to pending requests or subscription channels.
    #[tracing::instrument(skip_all)]
    async fn reader_loop(
        mut source: WsSource,
        inner: Arc<RwLock<ClientInner>>,
        subscriptions: Arc<TransportSubscriptionMap<SubscriptionState>>,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                msg_opt = source.next() => {
                    let Some(msg_result) = msg_opt else {
                        inner.write().await.connected = false;
                        break;
                    };

                    let Ok(msg) = msg_result else {
                        inner.write().await.connected = false;
                        break;
                    };

                    match msg {
                        Message::Binary(data) => {
                            if let Ok(relay_msg) = RelayMessage::from_bytes(&data) {
                                Self::dispatch_relay_message(&inner, &subscriptions, relay_msg).await;
                            }
                        }
                        Message::Close(_) => {
                            inner.write().await.connected = false;
                            break;
                        }
                        // Ignore non-binary frames (text, ping, pong handled by
                        // tungstenite automatically).
                        _ => {}
                    }
                }
                () = async { let _ = shutdown_rx.recv().await; } => {
                    break;
                }
            }
        }
    }

    /// Dispatches a relay message to the appropriate pending request or
    /// subscription channel.
    async fn dispatch_relay_message(
        inner: &Arc<RwLock<ClientInner>>,
        subscriptions: &Arc<TransportSubscriptionMap<SubscriptionState>>,
        msg: RelayMessage,
    ) {
        match &msg {
            // OK and ERR responses are correlated by `ref_id`.
            RelayMessage::Ok { ref_id, .. } | RelayMessage::Err { ref_id, .. } => {
                if let Some(ref_id_str) = ref_id {
                    let mut state = inner.write().await;
                    if let Some(pending) = state.pending.remove(ref_id_str) {
                        let _ = pending.tx.send(msg);
                    }
                }
            }

            // BLOB messages are delivered to the subscription channel for the
            // matching routing ID. The reader_loop is single-task, so a stalled
            // `tx.send().await` here also stalls subsequent BLOB and OK dispatch.
            RelayMessage::Blob {
                routing_id,
                blob_id,
                blob,
                stored_at,
                ..
            } => {
                // Verify blob integrity: SHA-256(blob) must match relay-provided blob_id.
                let computed_hash = *crate::traits::BlobId::from_sha256(blob).as_bytes();
                if computed_hash != *blob_id {
                    let expected = hex::encode(blob_id);
                    let actual = hex::encode(computed_hash);
                    tracing::warn!(
                        expected = %expected,
                        actual = %actual,
                        "blob integrity check failed: SHA-256(blob) does not match \
                         relay-provided blob_id; possible malicious relay"
                    );

                    // Emit BlobIntegrityError to the subscription channel if one exists.
                    let maybe_tx = subscriptions
                        .with(&crate::traits::RoutingId::new(*routing_id), |sub| {
                            sub.tx.clone()
                        });
                    if let Some(tx) = maybe_tx {
                        let _ = tx
                            .send(SubscriptionMessage::BlobIntegrityError { expected, actual })
                            .await;
                    }
                    return;
                }

                let receive_time = Instant::now();
                let rid = crate::traits::RoutingId::new(*routing_id);

                // Peek whether this routing_id is a dedup-bypassing (one-shot raw
                // public-record QUERY) subscription BEFORE the dedup check. This
                // is a read-only lookup that commits nothing, so it does not
                // perturb the commit-after-success ordering below. A missing
                // subscription defaults to `false` (the dedup applies), matching
                // the ordinary subscribe/query path.
                let bypass_dedup = subscriptions
                    .with(&rid, |sub| sub.bypass_dedup)
                    .unwrap_or(false);

                // 1. Deduplication check (read-only, no commit yet).
                //    Dedup-cache poisoning defense: check dedup first
                //    (read-locked, no commit), then check subscription
                //    presence below, then send, then commit dedup ONLY
                //    after a successful send to a present subscriber.
                //    Committing dedup before the subscriber check would
                //    let unsolicited routing_ids evict legitimate dedup
                //    entries, suppressing legitimate post-resubscribe
                //    redelivery for those entries. The load-bearing
                //    invariant is the step ordering (commit-after-success),
                //    not the lock kind.
                if !bypass_dedup {
                    let state = inner.read().await;
                    if state.seen_blob_ids.contains(blob_id) {
                        return;
                    }
                }

                // 2. Plausibility check: warn if relay timestamp deviates
                //    significantly from local wall-clock time. Independent of
                //    dedup; runs whether or not the routing_id is subscribed.
                {
                    let local_now = scp_clock::SystemClock.now_secs();
                    let deviation = local_now.abs_diff(*stored_at);
                    if deviation > RELAY_TIMESTAMP_DEVIATION_THRESHOLD_SECS {
                        tracing::warn!(
                            relay_stored_at = *stored_at,
                            local_time = local_now,
                            deviation_secs = deviation,
                            "relay stored_at deviates from local time by more \
                             than {RELAY_TIMESTAMP_DEVIATION_THRESHOLD_SECS}s; \
                             possible malicious relay"
                        );
                    }
                }

                // 3. Mutate subscription state and clone its sender. If no
                //    subscription exists for this routing_id, return WITHOUT
                //    committing the dedup mark. Returning without committing
                //    means a future legitimate redelivery (e.g. after an
                //    unsubscribe-then-resubscribe race) is still deliverable.
                let maybe_tx = subscriptions.with_mut(&rid, |sub| {
                    // Record local monotonic receive time for reconnection
                    // window calculations (immune to relay timestamp
                    // manipulation).
                    sub.last_local_receive = Some(receive_time);
                    // Update relay-provided `stored_at` as untrusted metadata
                    // (informational/logging only).
                    if sub.last_stored_at.is_none_or(|prev| *stored_at > prev) {
                        sub.last_stored_at = Some(*stored_at);
                    }
                    sub.tx.clone()
                });

                let Some(tx) = maybe_tx else {
                    // No subscriber: do not pollute the dedup cache so future
                    // redelivery for this blob_id remains possible.
                    return;
                };

                // 4. Send outside any lock. A slow or stalled subscriber here
                //    blocks the reader_loop (see the note on the BLOB arm),
                //    but does not contend with `inner.write()`-holders such
                //    as `send_request`'s pending-map mutation.
                //
                //    On `Err`: the receiver was dropped between `with_mut`
                //    (which cloned the sender) and `tx.send`. We must NOT
                //    commit dedup -- a future redelivery (e.g. after
                //    resubscribe) for this `blob_id` must remain deliverable.
                let blob_id_copy = *blob_id;
                if tx.send(SubscriptionMessage::Relay(msg)).await.is_ok() && !bypass_dedup {
                    // Commit dedup only for ordinary subscriptions. A raw-query
                    // (bypass) subscription must never seed the LRU: seeding it
                    // would suppress the genuine record on a later live
                    // subscription or repeat resolution (§3.10.4).
                    //
                    // Double-check guards the static dispatch_relay_message helper when
                    // invoked concurrently from tests; the production reader_loop is single-task.
                    let mut state = inner.write().await;
                    if !state.seen_blob_ids.contains(&blob_id_copy) {
                        state.seen_blob_ids.put(blob_id_copy, ());
                    }
                }
            }

            // EVENT messages (`backfill_complete`, `query_complete`).
            RelayMessage::Event { ref_id, .. } => {
                // If this event has a `ref_id`, check pending requests first.
                if let Some(ref_id_str) = ref_id {
                    let mut state = inner.write().await;
                    if let Some(pending) = state.pending.remove(ref_id_str) {
                        let _ = pending.tx.send(msg);
                        return;
                    }
                    drop(state);
                }

                // Broadcast event to all subscriptions. Snapshot senders first
                // so the map's read lock is dropped before each `send().await`.
                let snap = subscriptions.snapshot();
                for (_rid, sub) in snap {
                    let _ = sub.tx.send(SubscriptionMessage::Relay(msg.clone())).await;
                }
            }

            // PONG is handled silently (keepalive acknowledged).
            // BRIDGE_DATA is forwarded to the bridge service layer (if present);
            // the native relay client does not handle bridge data directly.
            RelayMessage::Pong { .. } | RelayMessage::BridgeData { .. } => {}
        }
    }

    /// Background task that sends PING every 30 seconds for keepalive.
    async fn keepalive_loop(
        ws_sink: Arc<Mutex<Option<WsSink>>>,
        inner: Arc<RwLock<ClientInner>>,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) {
        let mut interval = tokio::time::interval(PING_INTERVAL);
        // Skip the first immediate tick.
        interval.tick().await;

        loop {
            tokio::select! {
                () = async { interval.tick().await; } => {
                    if !inner.read().await.connected {
                        break;
                    }

                    let ts = scp_clock::SystemClock.now_secs();

                    let ping = ClientMessage::Ping { ts };
                    if let Ok(bytes) = ping.to_bytes() {
                        let mut sink_guard = ws_sink.lock().await;
                        if let Some(sink) = sink_guard.as_mut() {
                            let _ = sink.send(Message::Binary(bytes)).await;
                        }
                    }
                }
                () = async { let _ = shutdown_rx.recv().await; } => {
                    break;
                }
            }
        }
    }

    /// Sends a client message and waits for the correlated relay response.
    ///
    /// Assigns a unique `ref_id` to the message for request-response
    /// correlation. Returns the relay's response message.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if the client is not connected.
    /// Returns [`TransportError::SendFailed`] if the WebSocket send fails.
    /// Returns [`TransportError::Timeout`] if no response is received within
    /// 30 seconds.
    #[tracing::instrument(skip_all)]
    pub async fn send_request(
        &self,
        mut msg: ClientMessage,
    ) -> Result<RelayMessage, TransportError> {
        let ref_id = {
            let mut state = self.inner.write().await;
            if !state.connected {
                return Err(TransportError::NotConnected);
            }
            let id = format!("r-{}", state.next_ref_id);
            state.next_ref_id += 1;
            id
        };

        // Assign the `ref_id` to the message.
        assign_ref_id(&mut msg, &ref_id);

        // Register the pending request.
        let (tx, rx) = oneshot::channel();
        self.inner
            .write()
            .await
            .pending
            .insert(ref_id.clone(), PendingRequest { tx });

        // Serialize and send.
        let bytes = msg
            .to_bytes()
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        self.ws_sink
            .lock()
            .await
            .as_mut()
            .ok_or(TransportError::NotConnected)?
            .send(Message::Binary(bytes))
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        // Wait for the response with timeout.
        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(msg)) => Ok(msg),
            Ok(Err(_)) => Err(TransportError::SendFailed(
                "response channel closed".to_string(),
            )),
            Err(_) => {
                // Timeout: remove the pending entry so the oneshot sender is
                // dropped and memory is not leaked.
                self.inner.write().await.pending.remove(&ref_id);
                Err(TransportError::Timeout)
            }
        }
    }

    /// Registers a subscription for a routing ID.
    ///
    /// Sends a SUBSCRIBE message to the relay and registers the subscription
    /// channel for receiving BLOB and EVENT messages.
    ///
    /// Returns a receiver channel that yields relay messages for this
    /// subscription.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if the client is not connected.
    /// Returns [`TransportError::SubscriptionFailed`] if the relay responds
    /// with an error.
    pub async fn subscribe(
        &self,
        routing_id: &[u8; 32],
        since: Option<u64>,
    ) -> Result<mpsc::Receiver<SubscriptionMessage>, TransportError> {
        let (tx, rx) = mpsc::channel(256);

        let rid = crate::traits::RoutingId::new(*routing_id);

        // Register subscription state before sending to avoid race conditions.
        // Use `insert` (not `insert_or_replace`): a duplicate routing ID
        // surfaces as an error rather than silently overwriting (and leaking
        // the prior subscriber's `mpsc::Sender`).
        self.subscriptions
            .insert(
                rid,
                SubscriptionState {
                    last_stored_at: None,
                    last_local_receive: None,
                    tx,
                    bypass_dedup: false,
                },
            )
            .map_err(|e| TransportError::SubscriptionFailed(e.to_string()))?;

        let msg = ClientMessage::Subscribe {
            ref_id: None,
            routing_id: *routing_id,
            since,
        };

        let response = self.send_request(msg).await.map_err(|e| {
            self.subscriptions.remove(&rid);
            TransportError::SubscriptionFailed(e.to_string())
        })?;

        match response {
            RelayMessage::Ok { .. } => Ok(rx),
            RelayMessage::Err { code, msg, .. } => {
                self.subscriptions.remove(&rid);
                Err(TransportError::SubscriptionFailed(format!(
                    "relay error {code}: {msg}"
                )))
            }
            _ => {
                self.subscriptions.remove(&rid);
                Err(TransportError::SubscriptionFailed(
                    "unexpected response to SUBSCRIBE".to_string(),
                ))
            }
        }
    }

    /// Removes a subscription for a routing ID.
    ///
    /// Sends an UNSUBSCRIBE message to the relay and removes the subscription
    /// from the internal registry.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if the client is not connected.
    pub async fn unsubscribe(&self, routing_id: &[u8; 32]) -> Result<(), TransportError> {
        let msg = ClientMessage::Unsubscribe {
            ref_id: None,
            routing_id: *routing_id,
        };

        let response = self.send_request(msg).await?;

        // Remove subscription regardless of response.
        self.subscriptions
            .remove(&crate::traits::RoutingId::new(*routing_id));

        match response {
            RelayMessage::Err { code, msg, .. } => Err(TransportError::SendFailed(format!(
                "relay error {code}: {msg}"
            ))),
            _ => Ok(()),
        }
    }

    /// Sends a QUERY command and collects results.
    ///
    /// When a live subscription already exists for `routing_id`, the QUERY is
    /// sent via [`send_request`](Self::send_request) and results flow through
    /// that subscription (this returns an empty vec). Otherwise it collects over
    /// a temporary subscription via [`send_query_collect_blobs`](Self::send_query_collect_blobs),
    /// terminating on the `ref_id`-correlated `query_complete` (not a deadline),
    /// and decodes each blob as an [`OuterEnvelope`] (undecodable blobs dropped).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if the client is not connected.
    /// Returns [`TransportError::SendFailed`] if the relay responds with an
    /// error.
    pub async fn query(
        &self,
        routing_id: &[u8; 32],
        since: Option<u64>,
    ) -> Result<Vec<OuterEnvelope>, TransportError> {
        let rid = crate::traits::RoutingId::new(*routing_id);

        // Check if there's already an active subscription for this `routing_id`.
        if self.subscriptions.contains(&rid) {
            // When there's an active subscription, just send the QUERY.
            // Results will be delivered through the existing subscription.
            let msg = ClientMessage::Query {
                ref_id: None,
                routing_id: *routing_id,
                since,
                limit: None,
            };
            let _response = self.send_request(msg).await?;
            return Ok(Vec::new());
        }

        // Temp-subscription path: collect raw blobs — terminated by the
        // ref_id-correlated `query_complete` (not a deadline) — then decode each
        // as an `OuterEnvelope`, discarding any that fail to deserialize.
        let blobs = self
            .send_query_collect_blobs(routing_id, since, None, false)
            .await?;
        Ok(blobs
            .iter()
            .filter_map(|blob| OuterEnvelope::from_bytes(blob).ok())
            .collect())
    }

    /// Publishes a raw public-record blob at `routing_id` via PUBLISH (§3.10.2).
    ///
    /// Unlike [`send`](crate::native::NativeRelayAdapter) via
    /// [`send_request`](Self::send_request) with an [`OuterEnvelope`], the blob is
    /// arbitrary already-authenticated bytes (a DID-record frame, §9.10.12). No
    /// `recipient_hint` is set — a public record has no encrypted recipient.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if the client is not connected,
    /// or [`TransportError::SendFailed`] if the relay responds with an error.
    pub async fn publish_raw(
        &self,
        routing_id: &[u8; 32],
        blob_ttl: u64,
        blob: Vec<u8>,
    ) -> Result<(), TransportError> {
        // The wire `blob_ttl` is a u32 (seconds); the public API takes u64 to
        // match the identity-layer RelayPublisher. A DID record's 7-day TTL
        // (604800) fits comfortably; reject an out-of-range value loudly rather
        // than silently truncating.
        let blob_ttl = u32::try_from(blob_ttl).map_err(|_| {
            TransportError::SendFailed(format!("blob_ttl {blob_ttl} exceeds u32 wire limit"))
        })?;

        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: *routing_id,
            recipient_hint: None,
            blob_ttl,
            blob,
        };

        let response = self.send_request(msg).await?;

        match response {
            RelayMessage::Ok { .. } => Ok(()),
            RelayMessage::Err { code, msg, .. } => Err(TransportError::SendFailed(format!(
                "relay error {code}: {msg}"
            ))),
            _ => Err(TransportError::ProtocolError(
                "unexpected response to PUBLISH (raw)".to_string(),
            )),
        }
    }

    /// Sends a QUERY for raw public-record blobs and collects the blob bytes,
    /// bypassing the `OuterEnvelope` codec AND the `seen_blob_ids` dedup LRU
    /// (§3.10.2/§3.10.4).
    ///
    /// Registers a temporary dedup-bypassing subscription, sends QUERY with the
    /// given `limit` (§3.10.2 uses N=16), and collects up to `limit` BLOB
    /// payloads, terminating on the `ref_id`-correlated `query_complete` (or a
    /// relay `Err`), not a wall-clock deadline. The blobs are returned
    /// unverified — the caller decodes and BEP44-verifies each one.
    ///
    /// A DID `routing_id` is derived as `SHA-256("scp:did:" || did)` (§3.10.2),
    /// a domain disjoint from context routing IDs, so an existing live
    /// subscription at this `routing_id` is a collision, not a legitimate
    /// overlap: this fails loudly rather than silently returning the live
    /// subscription's dedup-filtered stream.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if the client is not connected,
    /// [`TransportError::SubscriptionFailed`] if a subscription already exists
    /// for this routing ID, or [`TransportError::SendFailed`] if the relay
    /// responds with an error.
    pub async fn query_raw(
        &self,
        routing_id: &[u8; 32],
        since: Option<u64>,
        limit: u32,
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        let rid = crate::traits::RoutingId::new(*routing_id);

        if self.subscriptions.contains(&rid) {
            return Err(TransportError::SubscriptionFailed(
                "query_raw: routing_id already has an active subscription".to_string(),
            ));
        }

        self.send_query_collect_blobs(routing_id, since, Some(limit), true)
            .await
    }

    /// Sends a QUERY and collects the returned raw blob payloads over a
    /// temporary subscription, terminating on the `ref_id`-correlated terminal
    /// response — the shared core of [`query`](Self::query) and
    /// [`query_raw`](Self::query_raw).
    ///
    /// # Why this does not use [`send_request`](Self::send_request)
    ///
    /// A QUERY's ONLY `ref_id`-bearing response is the terminal
    /// `EVENT { ref_id, "query_complete" }` (BLOB messages carry no `ref_id`).
    /// `send_request` registers a `pending[ref_id]` oneshot and consumes exactly
    /// that terminal event — [`dispatch_relay_message`](Self::dispatch_relay_message)
    /// routes a `ref_id`-matched EVENT to `pending` and returns BEFORE
    /// broadcasting it to the routing-ID subscription. So if the collect loop
    /// waited for `query_complete` on the subscription channel it would NEVER see
    /// it and would run to a deadline (and be cancelled by the composer's 5s
    /// per-relay timeout, yielding zero candidates). Instead this method
    /// registers the `pending` oneshot ITSELF and `select!`s the collect loop on
    /// both the subscription channel (blobs) and that oneshot (the terminator),
    /// breaking on the terminator.
    ///
    /// `bypass_dedup` selects whether delivered blobs pass through the
    /// `seen_blob_ids` LRU (`false` = normal `query` semantics; `true` = the raw
    /// one-shot public-record path, which must observe every candidate on every
    /// call). `limit` caps the collected blobs (defensive against a relay that
    /// ignores the wire `limit`); `None` collects until the terminator.
    ///
    /// A [`QueryScopeGuard`] removes the temporary subscription and the pending
    /// entry on every exit — including external cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if not connected,
    /// [`TransportError::SubscriptionFailed`] on a routing-ID collision, or
    /// [`TransportError::SendFailed`] on a serialize/write failure or a relay
    /// `Err` response to the QUERY.
    async fn send_query_collect_blobs(
        &self,
        routing_id: &[u8; 32],
        since: Option<u64>,
        limit: Option<u32>,
        bypass_dedup: bool,
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        let rid = crate::traits::RoutingId::new(*routing_id);

        // Assign the ref_id and register the terminator oneshot FIRST, under one
        // write lock, so there is no `.await` between reserving the ref_id and
        // arming the guard. A disconnected client short-circuits before anything
        // is inserted.
        let (term_tx, mut term_rx) = oneshot::channel::<RelayMessage>();
        let ref_id = {
            let mut state = self.inner.write().await;
            if !state.connected {
                return Err(TransportError::NotConnected);
            }
            let id = format!("r-{}", state.next_ref_id);
            state.next_ref_id += 1;
            state
                .pending
                .insert(id.clone(), PendingRequest { tx: term_tx });
            id
        };

        // Register the temporary BLOB-delivery subscription. On a collision, roll
        // back the pending entry we just reserved (no guard armed yet).
        let (tx, mut rx) = mpsc::channel::<SubscriptionMessage>(256);
        if let Err(e) = self.subscriptions.insert(
            rid,
            SubscriptionState {
                last_stored_at: None,
                last_local_receive: None,
                tx,
                bypass_dedup,
            },
        ) {
            self.inner.write().await.pending.remove(&ref_id);
            return Err(TransportError::SubscriptionFailed(e.to_string()));
        }

        // From here every exit (happy, error, deadline, cancellation) cleans up
        // both the subscription and the pending entry.
        let _guard = QueryScopeGuard {
            subscriptions: Arc::clone(&self.subscriptions),
            inner: Arc::clone(&self.inner),
            rid,
            ref_id: ref_id.clone(),
        };

        // Serialize and send the QUERY frame directly (NOT via send_request,
        // which would consume the terminal query_complete).
        let mut msg = ClientMessage::Query {
            ref_id: None,
            routing_id: *routing_id,
            since,
            limit,
        };
        assign_ref_id(&mut msg, &ref_id);
        let bytes = msg
            .to_bytes()
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        self.ws_sink
            .lock()
            .await
            .as_mut()
            .ok_or(TransportError::NotConnected)?
            .send(Message::Binary(bytes))
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        // Collect BLOB payloads, terminating on the ref_id-correlated
        // query_complete/Err. The deadline is a backstop for a relay that never
        // sends a terminator, not the normal exit.
        let mut blobs: Vec<Vec<u8>> = Vec::new();
        let cap = limit.map(|l| l as usize);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

        loop {
            if cap.is_some_and(|c| blobs.len() >= c) {
                break;
            }
            tokio::select! {
                // `biased`: drain buffered blobs before observing the terminator,
                // so a simultaneously-ready terminator never causes us to skip a
                // blob already in the channel (the post-terminator drain below is
                // a further belt-and-suspenders).
                biased;
                msg_opt = rx.recv() => {
                    match msg_opt {
                        Some(SubscriptionMessage::Relay(RelayMessage::Blob { blob, .. })) => {
                            blobs.push(blob);
                        }
                        // Any other subscription message on the raw path is ignored.
                        Some(_) => {}
                        // Channel closed (client shutting down): stop.
                        None => break,
                    }
                }
                term = &mut term_rx => {
                    match term {
                        Ok(RelayMessage::Err { code, msg, .. }) => {
                            return Err(TransportError::SendFailed(format!(
                                "relay error {code}: {msg}"
                            )));
                        }
                        // query_complete (or any other terminal response for this
                        // ref_id): drain blobs already delivered, then stop.
                        // SAFETY of the drain: this relies on the `biased` select
                        // above — `rx` is polled first every iteration, so the
                        // terminator arm is only reached once `rx` is empty, and
                        // the single-task in-order reader has already enqueued every
                        // blob before it sends the terminator. The drain is thus a
                        // belt-and-suspenders sweep of an already-empty channel. If
                        // `biased` is ever removed, this `try_recv` (which stops at
                        // the first non-Blob message) could drop a trailing blob —
                        // keep the two coupled.
                        Ok(_) => {
                            while let Ok(SubscriptionMessage::Relay(RelayMessage::Blob {
                                blob,
                                ..
                            })) = rx.try_recv()
                            {
                                blobs.push(blob);
                                if cap.is_some_and(|c| blobs.len() >= c) {
                                    break;
                                }
                            }
                            break;
                        }
                        // The oneshot sender was dropped without delivering a
                        // terminal response (the pending entry was removed — e.g.
                        // a `send_request` timeout elsewhere reclaimed it, or the
                        // reader task ended). Defensive fallback: stop with what we
                        // have. (`reconnect` re-subscribes but does not bulk-clear
                        // `pending`, so it is not the trigger here.)
                        Err(_) => break,
                    }
                }
                () = tokio::time::sleep_until(deadline) => {
                    break;
                }
            }
        }

        Ok(blobs)
    }

    /// Returns whether the client is currently connected.
    #[allow(dead_code)]
    pub async fn is_connected(&self) -> bool {
        self.inner.read().await.connected
    }

    /// Attempts reconnection with exponential backoff.
    ///
    /// After successfully reconnecting, re-issues SUBSCRIBE for all active
    /// subscriptions with `since = last_stored_at - 5s` overlap.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionFailed`] if reconnection fails
    /// after exhausting all backoff steps.
    #[allow(dead_code)]
    pub async fn reconnect(&self) -> Result<(), TransportError> {
        // Cancel existing background tasks.
        if let Some(tx) = self.shutdown_tx.lock().await.as_ref() {
            let _ = tx.send(());
        }

        // Close existing sink.
        let taken_sink = self.ws_sink.lock().await.take();
        if let Some(mut sink) = taken_sink {
            let _ = sink.close().await;
        }

        // Create new shutdown channel.
        {
            let (new_tx, _) = tokio::sync::broadcast::channel::<()>(1);
            *self.shutdown_tx.lock().await = Some(new_tx);
        }

        // Try reconnecting with exponential backoff + jitter.
        // Uses ReconnectBackoff (shared with QUIC) to add random jitter
        // (up to 25% of each delay) preventing thundering herd when
        // multiple clients reconnect after a relay failure (BLACK-001).
        let mut backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
        let mut last_err = None;
        while backoff.attempts() < MAX_RECONNECT_ATTEMPTS {
            let delay = backoff.next_delay();
            tokio::time::sleep(delay).await;

            match self.establish_connection().await {
                Ok(()) => {
                    // Single snapshot reused for both re-subscribe and the
                    // post-reconnect Reconnected notification, avoiding two
                    // independent walks of the map.
                    let snap: Vec<_> = self
                        .subscriptions
                        .snapshot()
                        .into_iter()
                        .map(|(rid, s)| (rid, s.last_local_receive, s.tx))
                        .collect();

                    // Re-subscribe to all active routing IDs first so any
                    // backfill begins flowing before we notify subscribers.
                    for (rid, last_local_receive, _tx) in &snap {
                        // Use local receive time (immune to relay timestamp
                        // manipulation) to compute the reconnect window.
                        let since = last_local_receive.map(|instant| {
                            let elapsed = instant.elapsed();
                            let now_unix = scp_clock::SystemClock.now_secs();
                            now_unix
                                .saturating_sub(elapsed.as_secs())
                                .saturating_sub(RECONNECT_OVERLAP.as_secs())
                        });

                        let msg = ClientMessage::Subscribe {
                            ref_id: None,
                            routing_id: *rid.as_bytes(),
                            since,
                        };

                        // Best-effort: if re-subscribe fails, the subscription
                        // is still tracked and will be retried on next reconnect.
                        let _ = self.send_request(msg).await;
                    }

                    // Notify all active subscriptions that a reconnection
                    // occurred so the adapter can emit
                    // `TransportEvent::Reconnected`. Reuses the same snapshot
                    // taken above; the senders are already cloned out of the
                    // map's read lock.
                    //
                    // A subscription may be unsubscribed between the snapshot
                    // and this loop; the contains() check below skips those
                    // entries on the common path. A small TOCTOU window
                    // remains between the contains() check and tx.send().await
                    // -- receivers must tolerate one final `Reconnected` after
                    // `unsubscribe` returns, the same way they tolerate one
                    // final `Relay(...)` per the SubscriptionState::Clone
                    // documentation above.
                    for (rid, _last_local_receive, tx) in snap {
                        if !self.subscriptions.contains(&rid) {
                            continue;
                        }
                        let _ = tx.send(SubscriptionMessage::Reconnected).await;
                    }

                    return Ok(());
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            TransportError::ConnectionFailed(
                "reconnection failed after all backoff steps".to_string(),
            )
        }))
    }

    /// Clears the deduplication cache. Useful after a successful reconnect
    /// when the overlap window has passed.
    #[allow(dead_code)]
    pub async fn clear_dedup_set(&self) {
        self.inner.write().await.seen_blob_ids.clear();
    }

    /// Returns the number of entries in the pending request map.
    ///
    /// Exposed for testing to verify cleanup on timeout.
    #[cfg(test)]
    async fn pending_len(&self) -> usize {
        self.inner.read().await.pending.len()
    }

    /// Sends a cover traffic payload as a PUBLISH with a random routing ID
    /// and 60-second TTL (spec §9.10.6).
    ///
    /// The random routing ID ensures the dummy is unroutable (no subscriber
    /// exists for it), so it is silently discarded by the relay after TTL
    /// expiry. The 60-second TTL minimizes relay-side storage cost while
    /// keeping the message alive long enough to be indistinguishable from
    /// short-lived real traffic.
    pub async fn send_cover_traffic(&self, payload: Vec<u8>) -> Result<(), TransportError> {
        let mut routing_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut routing_id);

        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id,
            recipient_hint: None,
            blob_ttl: 60,
            blob: payload,
        };

        let response = self.send_request(msg).await?;

        match response {
            RelayMessage::Err { code, msg, .. } => Err(TransportError::SendFailed(format!(
                "cover traffic relay error {code}: {msg}"
            ))),
            _ => Ok(()),
        }
    }
}

/// Assigns a `ref_id` to a [`ClientMessage`] for request-response correlation.
fn assign_ref_id(msg: &mut ClientMessage, ref_id: &str) {
    match msg {
        ClientMessage::Publish { ref_id: r, .. }
        | ClientMessage::Subscribe { ref_id: r, .. }
        | ClientMessage::Unsubscribe { ref_id: r, .. }
        | ClientMessage::Query { ref_id: r, .. }
        | ClientMessage::Delete { ref_id: r, .. }
        | ClientMessage::BridgeRegister { ref_id: r, .. }
        | ClientMessage::BridgeData { ref_id: r, .. } => {
            *r = Some(ref_id.to_string());
        }
        ClientMessage::Ack { .. } | ClientMessage::Ping { .. } => {
            // ACK and PING don't have `ref_id` fields in the protocol.
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn assign_ref_id_sets_publish_ref_id() {
        let mut msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: [0xAA; 32],
            recipient_hint: None,
            blob_ttl: 3600,
            blob: vec![0x01],
        };
        assign_ref_id(&mut msg, "test-1");
        match msg {
            ClientMessage::Publish { ref_id, .. } => {
                assert_eq!(ref_id, Some("test-1".to_string()));
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn assign_ref_id_sets_subscribe_ref_id() {
        let mut msg = ClientMessage::Subscribe {
            ref_id: None,
            routing_id: [0xBB; 32],
            since: None,
        };
        assign_ref_id(&mut msg, "test-2");
        match msg {
            ClientMessage::Subscribe { ref_id, .. } => {
                assert_eq!(ref_id, Some("test-2".to_string()));
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn assign_ref_id_does_not_modify_ping() {
        let mut msg = ClientMessage::Ping { ts: 42 };
        assign_ref_id(&mut msg, "test-3");
        assert_eq!(msg, ClientMessage::Ping { ts: 42 });
    }

    #[test]
    fn assign_ref_id_does_not_modify_ack() {
        let mut msg = ClientMessage::Ack {
            blob_id: [0xCC; 32],
        };
        assign_ref_id(&mut msg, "test-4");
        match msg {
            ClientMessage::Ack { blob_id } => {
                assert_eq!(blob_id, [0xCC; 32]);
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn backoff_uses_jittered_exponential() {
        // Verify the WebSocket client uses ReconnectBackoff (with jitter)
        // instead of fixed deterministic backoff steps.
        let mut backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));

        // First delay: 1s + up to 25% jitter.
        let d1 = backoff.next_delay();
        assert!(d1 >= Duration::from_secs(1));
        assert!(d1 <= Duration::from_millis(1250));

        // Second delay: 2s + jitter (doubled from 1s).
        let d2 = backoff.next_delay();
        assert!(d2 >= Duration::from_secs(2));
        assert!(d2 <= Duration::from_millis(2500));

        // Delays should be monotonically increasing (ignoring jitter variance).
        assert!(d2 > d1);
    }

    #[test]
    fn backoff_cap_is_30_seconds() {
        let mut backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
        // Exhaust to cap: 1, 2, 4, 8, 16, 30, 30, 30...
        for _ in 0..10 {
            let _ = backoff.next_delay();
        }
        // After many iterations, the base delay is capped at 30s.
        assert_eq!(backoff.current_delay(), Duration::from_secs(30));
    }

    #[test]
    fn max_reconnect_attempts_matches_legacy_step_count() {
        // The old BACKOFF_STEPS had 6 entries. Ensure the new constant
        // preserves the same number of reconnection attempts.
        assert_eq!(MAX_RECONNECT_ATTEMPTS, 6);
    }

    #[test]
    fn reconnect_overlap_is_5_seconds() {
        assert_eq!(RECONNECT_OVERLAP.as_secs(), 5);
    }

    // -----------------------------------------------------------------------
    // Blob integrity verification tests (SCP-193)
    // -----------------------------------------------------------------------

    /// Helper: creates a `ClientInner` and a sibling subscription map with a
    /// subscription registered for the given routing ID. Returns the inner
    /// state, the subscriptions map, and the subscription receiver.
    fn setup_inner_with_subscription(
        routing_id: [u8; 32],
    ) -> (
        Arc<RwLock<ClientInner>>,
        Arc<TransportSubscriptionMap<SubscriptionState>>,
        mpsc::Receiver<SubscriptionMessage>,
    ) {
        let (tx, rx) = mpsc::channel(16);
        let inner = Arc::new(RwLock::new(ClientInner {
            pending: HashMap::new(),
            next_ref_id: 1,
            seen_blob_ids: lru::LruCache::new(
                NonZeroUsize::new(DEDUP_CACHE_CAPACITY).unwrap_or(NonZeroUsize::MIN),
            ),
            connected: true,
        }));
        let subscriptions = Arc::new(TransportSubscriptionMap::<SubscriptionState>::new());
        subscriptions
            .insert(
                crate::traits::RoutingId::new(routing_id),
                SubscriptionState {
                    last_stored_at: None,
                    last_local_receive: None,
                    tx,
                    bypass_dedup: false,
                },
            )
            .unwrap();
        (inner, subscriptions, rx)
    }

    /// Helper: like [`setup_inner_with_subscription`] but registers the
    /// subscription with `bypass_dedup: true` — the one-shot raw public-record
    /// QUERY shape (§3.10.4).
    fn setup_inner_with_bypass_subscription(
        routing_id: [u8; 32],
    ) -> (
        Arc<RwLock<ClientInner>>,
        Arc<TransportSubscriptionMap<SubscriptionState>>,
        mpsc::Receiver<SubscriptionMessage>,
    ) {
        let (tx, rx) = mpsc::channel(16);
        let inner = Arc::new(RwLock::new(ClientInner {
            pending: HashMap::new(),
            next_ref_id: 1,
            seen_blob_ids: lru::LruCache::new(
                NonZeroUsize::new(DEDUP_CACHE_CAPACITY).unwrap_or(NonZeroUsize::MIN),
            ),
            connected: true,
        }));
        let subscriptions = Arc::new(TransportSubscriptionMap::<SubscriptionState>::new());
        subscriptions
            .insert(
                crate::traits::RoutingId::new(routing_id),
                SubscriptionState {
                    last_stored_at: None,
                    last_local_receive: None,
                    tx,
                    bypass_dedup: true,
                },
            )
            .unwrap();
        (inner, subscriptions, rx)
    }

    /// A dedup-bypassing (raw-query) subscription receives the SAME blob on a
    /// repeat dispatch — the genuine record is NOT dropped on the second
    /// resolution of an unchanged DID — and the `blob_id` is NEVER committed to
    /// the `seen_blob_ids` LRU (§3.10.2 limit-N shadow-defeat, §3.10.4). This is
    /// the regression guard for the dedup bug the raw path fixes: an ordinary
    /// subscription would drop the second delivery (see
    /// `dispatch_blob_with_correct_hash_accepted`, which asserts the LRU IS
    /// seeded).
    #[tokio::test]
    async fn raw_query_subscription_bypasses_dedup_on_repeat() {
        let routing_id = [0xDD; 32];
        let blob_data = vec![0x0A, 0x0B, 0x0C];
        let blob_id = sha256(&blob_data);
        let (inner, subscriptions, mut rx) = setup_inner_with_bypass_subscription(routing_id);

        let make_msg = || RelayMessage::Blob {
            routing_id,
            blob_id,
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 1_700_000_000,
            blob: blob_data.clone(),
        };

        // First delivery.
        NativeRelayClient::dispatch_relay_message(&inner, &subscriptions, make_msg()).await;
        // Second delivery of the SAME blob_id (a repeat resolution).
        NativeRelayClient::dispatch_relay_message(&inner, &subscriptions, make_msg()).await;

        // BOTH deliveries arrive — dedup did not suppress the repeat.
        for attempt in 0..2 {
            let received = rx.try_recv().unwrap_or_else(|e| {
                panic!("delivery {attempt} missing (dedup wrongly applied): {e}")
            });
            assert!(
                matches!(
                    received,
                    SubscriptionMessage::Relay(RelayMessage::Blob { .. })
                ),
                "expected Relay(Blob), got {received:?}"
            );
        }

        // The blob_id must NOT have been committed to the dedup LRU.
        assert!(
            !inner.read().await.seen_blob_ids.contains(&blob_id),
            "raw-query path must never seed the dedup LRU"
        );
    }

    /// Computes SHA-256 of the given data, returning a 32-byte array.
    fn sha256(data: &[u8]) -> [u8; 32] {
        *crate::traits::BlobId::from_sha256(data).as_bytes()
    }

    #[tokio::test]
    async fn dispatch_blob_with_correct_hash_accepted() {
        let routing_id = [0xAA; 32];
        let blob_data = vec![0x01, 0x02, 0x03];
        let correct_blob_id = sha256(&blob_data);
        let (inner, subscriptions, mut rx) = setup_inner_with_subscription(routing_id);

        let msg = RelayMessage::Blob {
            routing_id,
            blob_id: correct_blob_id,
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 1_700_000_000,
            blob: blob_data,
        };

        NativeRelayClient::dispatch_relay_message(&inner, &subscriptions, msg.clone()).await;

        // The blob should be delivered to the subscription channel.
        let received = rx.try_recv().unwrap();
        assert!(
            matches!(
                received,
                SubscriptionMessage::Relay(RelayMessage::Blob { .. })
            ),
            "expected Relay(Blob), got {received:?}"
        );

        // The blob_id should be in the dedup set.
        assert!(inner.read().await.seen_blob_ids.contains(&correct_blob_id));
    }

    #[tokio::test]
    async fn dispatch_blob_with_tampered_content_rejected() {
        let routing_id = [0xBB; 32];
        let original_blob = vec![0x01, 0x02, 0x03];
        let original_blob_id = sha256(&original_blob);
        let tampered_blob = vec![0xFF, 0xFE, 0xFD]; // Different content.
        let (inner, subscriptions, mut rx) = setup_inner_with_subscription(routing_id);

        let msg = RelayMessage::Blob {
            routing_id,
            blob_id: original_blob_id, // Hash of original, not tampered.
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 1_700_000_000,
            blob: tampered_blob,
        };

        NativeRelayClient::dispatch_relay_message(&inner, &subscriptions, msg).await;

        // Should receive a BlobIntegrityError, not a Blob.
        let received = rx.try_recv().unwrap();
        assert!(
            matches!(received, SubscriptionMessage::BlobIntegrityError { .. }),
            "expected BlobIntegrityError, got {received:?}"
        );

        // The blob_id should NOT be in the dedup set (tampered blob rejected).
        assert!(!inner.read().await.seen_blob_ids.contains(&original_blob_id));
    }

    #[tokio::test]
    async fn dispatch_empty_blob_with_correct_hash_accepted() {
        let routing_id = [0xCC; 32];
        let empty_blob: Vec<u8> = vec![];
        let correct_blob_id = sha256(&empty_blob);
        let (inner, subscriptions, mut rx) = setup_inner_with_subscription(routing_id);

        let msg = RelayMessage::Blob {
            routing_id,
            blob_id: correct_blob_id,
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 1_700_000_000,
            blob: empty_blob,
        };

        NativeRelayClient::dispatch_relay_message(&inner, &subscriptions, msg).await;

        // Empty blob with correct hash should be accepted.
        let received = rx.try_recv().unwrap();
        assert!(
            matches!(
                received,
                SubscriptionMessage::Relay(RelayMessage::Blob { .. })
            ),
            "expected Relay(Blob), got {received:?}"
        );

        assert!(inner.read().await.seen_blob_ids.contains(&correct_blob_id));
    }

    /// Regression: a BLOB delivered for a `routing_id` we have no
    /// subscription for must NOT poison the dedup LRU. The early return
    /// at step 3 (`with_mut` returns `None`) means we never reach the
    /// commit step.
    #[tokio::test]
    async fn dedup_not_committed_for_unsubscribed_routing_id() {
        // Subscribe routing_id A.
        let routing_id_a = [0xAAu8; 32];
        let routing_id_b = [0xBBu8; 32];
        let (inner, subscriptions, mut rx) = setup_inner_with_subscription(routing_id_a);

        // Build a well-formed BLOB for routing_id B (NOT subscribed) with a
        // payload chosen so that the same payload would also be valid on A.
        let blob_payload = vec![0x01u8, 0x02, 0x03, 0x04];
        let blob_id = sha256(&blob_payload);

        let msg_for_b = RelayMessage::Blob {
            routing_id: routing_id_b,
            blob_id,
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 1_700_000_000,
            blob: blob_payload.clone(),
        };

        NativeRelayClient::dispatch_relay_message(&inner, &subscriptions, msg_for_b).await;

        // The unsolicited BLOB must NOT have committed to dedup -- there
        // was no subscriber for routing_id B, so we never made it past
        // step 3 (the `with_mut` early return) into the commit step.
        assert!(
            !inner.read().await.seen_blob_ids.contains(&blob_id),
            "unsolicited routing_id must not pollute dedup cache"
        );

        // A's subscriber must not have received B's BLOB.
        assert!(
            rx.try_recv().is_err(),
            "subscriber for routing_id A must not receive a BLOB addressed to B"
        );

        // Now an identical BLOB (same blob_id) for routing_id A. Because
        // dedup was not poisoned by the prior delivery, this must reach
        // A's subscription channel.
        let msg_for_a = RelayMessage::Blob {
            routing_id: routing_id_a,
            blob_id,
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 1_700_000_000,
            blob: blob_payload,
        };

        NativeRelayClient::dispatch_relay_message(&inner, &subscriptions, msg_for_a).await;

        let received = rx.try_recv().unwrap();
        assert!(
            matches!(
                received,
                SubscriptionMessage::Relay(RelayMessage::Blob { .. })
            ),
            "expected Relay(Blob) for routing_id A, got {received:?}"
        );

        // After successful delivery, dedup commits.
        assert!(inner.read().await.seen_blob_ids.contains(&blob_id));
    }

    /// Regression for the unsubscribe-during-dispatch race: if `with_mut`
    /// finds a live subscription and clones its sender but the receiver is
    /// dropped before `tx.send().await` completes, the dispatcher must
    /// commit the dedup mark only when the send succeeds. Otherwise a
    /// future resubscribe-then-redelivery for the same `blob_id` would be
    /// silently suppressed.
    #[tokio::test]
    async fn dedup_not_committed_when_send_fails_after_unsubscribe() {
        let routing_id = [0xCDu8; 32];

        // Subscriber A is registered with a live (tx, rx) pair. Drop rx
        // immediately: the subscription entry is still present in the map
        // (with_mut will find it and clone tx), but the next
        // tx.send().await will return Err.
        let (inner, subscriptions, rx_a) = setup_inner_with_subscription(routing_id);
        drop(rx_a);

        // Build a well-formed BLOB for the still-mapped routing_id.
        let blob_payload = vec![0x10u8, 0x11, 0x12, 0x13];
        let blob_id = sha256(&blob_payload);

        let msg = RelayMessage::Blob {
            routing_id,
            blob_id,
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 1_700_000_000,
            blob: blob_payload.clone(),
        };

        NativeRelayClient::dispatch_relay_message(&inner, &subscriptions, msg).await;

        // The send failed (rx dropped), so the dedup mark must NOT have
        // been committed. This is the load-bearing assertion: pre-fix
        // (dedup committed before send) this would be `true`.
        assert!(
            !inner.read().await.seen_blob_ids.contains(&blob_id),
            "dedup must not commit when tx.send fails after unsubscribe"
        );

        // Resubscribe: fresh (tx, rx) pair under the same routing_id.
        // First clear the existing subscription entry, then insert a
        // fresh one (insert rejects duplicates).
        subscriptions.remove(&crate::traits::RoutingId::new(routing_id));
        let (tx_a2, mut rx_a2) = mpsc::channel::<SubscriptionMessage>(16);
        subscriptions
            .insert(
                crate::traits::RoutingId::new(routing_id),
                SubscriptionState {
                    last_stored_at: None,
                    last_local_receive: None,
                    tx: tx_a2,
                    bypass_dedup: false,
                },
            )
            .unwrap();

        // Redeliver the SAME blob_id. If the dedup mark had been
        // poisoned by the prior failed send, the dispatcher would
        // early-return at step 1 and the new subscriber would never
        // see the message.
        let msg2 = RelayMessage::Blob {
            routing_id,
            blob_id,
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 1_700_000_000,
            blob: blob_payload,
        };
        NativeRelayClient::dispatch_relay_message(&inner, &subscriptions, msg2).await;

        // Robust against future async refactors that decouple `tx.send().await`
        // completion from the rest of dispatch: wait on the channel rather
        // than `try_recv`.
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx_a2.recv())
            .await
            .expect("timeout waiting for redelivery")
            .expect("channel closed before redelivery");
        assert!(
            matches!(
                received,
                SubscriptionMessage::Relay(RelayMessage::Blob { .. })
            ),
            "fresh subscriber must receive the redelivered BLOB; \
             got {received:?}. Dedup was poisoned by the prior failed send."
        );

        // After the successful delivery, dedup now commits.
        assert!(inner.read().await.seen_blob_ids.contains(&blob_id));
    }

    // -----------------------------------------------------------------------
    // Pending request timeout cleanup tests (SCP-196)
    // -----------------------------------------------------------------------

    /// Starts a WebSocket server that accepts connections and upgrades them
    /// but never sends any response messages, causing client requests to
    /// time out.
    async fn start_silent_ws_server() -> String {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("ws://{addr}/scp/v1");

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let ws = tokio_tungstenite::accept_async(stream).await;
                    if let Ok(ws) = ws {
                        // Hold the connection open, read frames but never
                        // send responses.
                        let (_sink, mut source) = ws.split();
                        while source.next().await.is_some() {}
                    }
                });
            }
        });

        url
    }

    #[tokio::test(start_paused = true)]
    async fn send_request_timeout_cleans_pending_map() {
        let url = start_silent_ws_server().await;

        // Resume time briefly to allow the TCP/WS handshake to complete.
        tokio::time::resume();
        let client: &'static NativeRelayClient =
            Box::leak(Box::new(NativeRelayClient::connect(&url).await.unwrap()));
        tokio::time::pause();

        assert_eq!(client.pending_len().await, 0);

        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: [0xAA; 32],
            recipient_hint: None,
            blob_ttl: 3600,
            blob: vec![0x01],
        };

        let result = tokio::spawn(async move { client.send_request(msg).await });

        // Advance past the 30-second timeout.
        tokio::time::advance(Duration::from_secs(31)).await;

        let err = result.await.unwrap().unwrap_err();
        assert!(
            matches!(err, TransportError::Timeout),
            "expected Timeout, got {err:?}"
        );

        // The pending map must be empty after the timeout cleans up.
        assert_eq!(client.pending_len().await, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn pending_map_does_not_grow_under_repeated_timeouts() {
        let url = start_silent_ws_server().await;

        tokio::time::resume();
        let client: &'static NativeRelayClient =
            Box::leak(Box::new(NativeRelayClient::connect(&url).await.unwrap()));
        tokio::time::pause();

        for i in 0u8..10 {
            let msg = ClientMessage::Publish {
                ref_id: None,
                routing_id: [i; 32],
                recipient_hint: None,
                blob_ttl: 3600,
                blob: vec![i],
            };

            let result = tokio::spawn(async move { client.send_request(msg).await });

            tokio::time::advance(Duration::from_secs(31)).await;

            let err = result.await.unwrap().unwrap_err();
            assert!(
                matches!(err, TransportError::Timeout),
                "iteration {i}: expected Timeout, got {err:?}"
            );

            // After each timeout the map must be empty.
            assert_eq!(
                client.pending_len().await,
                0,
                "iteration {i}: pending map leaked"
            );
        }

        // Final check: no residual entries.
        assert_eq!(client.pending_len().await, 0);
    }

    #[tokio::test]
    async fn send_request_success_still_works() {
        use crate::native::server::{RelayConfig, RelayServer};
        use crate::native::storage::BlobStorageBackend;
        use std::net::SocketAddr;
        use std::sync::Arc;

        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();
        let url = format!("ws://{addr}/scp/v1");

        let client = NativeRelayClient::connect(&url).await.unwrap();
        assert_eq!(client.pending_len().await, 0);

        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: [0xAA; 32],
            recipient_hint: None,
            blob_ttl: 3600,
            blob: vec![0xDE, 0xAD],
        };

        let response = client.send_request(msg).await.unwrap();
        assert!(
            matches!(response, RelayMessage::Ok { .. }),
            "expected Ok, got {response:?}"
        );

        // Pending map must be empty after successful response.
        assert_eq!(client.pending_len().await, 0);
    }

    #[tokio::test]
    async fn subscribe_twice_to_same_routing_id_returns_error() {
        use crate::native::server::{RelayConfig, RelayServer};
        use crate::native::storage::BlobStorageBackend;
        use std::net::SocketAddr;
        use std::sync::Arc;

        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();
        let url = format!("ws://{addr}/scp/v1");

        let client = NativeRelayClient::connect(&url).await.unwrap();

        let routing_id = [0x77u8; 32];

        // First subscribe should succeed.
        let _rx1 = client
            .subscribe(&routing_id, None)
            .await
            .expect("first subscribe should succeed");

        // Second subscribe to the same routing ID must fail with
        // SubscriptionFailed -- the underlying TransportSubscriptionMap
        // surfaces duplicates rather than silently overwriting.
        let err = client
            .subscribe(&routing_id, None)
            .await
            .expect_err("second subscribe should fail");
        assert!(
            matches!(err, TransportError::SubscriptionFailed(_)),
            "expected SubscriptionFailed, got {err:?}"
        );

        // The first subscriber's receiver is still live (rx1 above), so
        // the original subscription remains active. A third subscribe
        // would still fail for the same reason.
        let err2 = client
            .subscribe(&routing_id, None)
            .await
            .expect_err("third subscribe should still fail");
        assert!(
            matches!(err2, TransportError::SubscriptionFailed(_)),
            "expected SubscriptionFailed on third attempt, got {err2:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Raw-blob path end-to-end tests (SCP-RELAYRES-002)
    //
    // These drive the REAL `NativeRelayClient::query_raw` / `publish_raw` over a
    // WebSocket against an in-process relay — the coverage that the unit-level
    // `MockRawAdapter` tests (in `native::relay_querier`) cannot provide, because
    // the mock bypasses `send_request`, the wire, and the collect loop entirely.
    // The CRITICAL these guard against: a QUERY's only ref_id-bearing response
    // is the terminal `query_complete`, which must terminate the collect loop.
    // -----------------------------------------------------------------------

    /// Starts an in-process WebSocket relay that maps each inbound
    /// [`ClientMessage`] to a scripted sequence of [`RelayMessage`] responses.
    /// Used to exercise client control-flow that the real relay cannot easily
    /// drive (a relay that floods more blobs than the QUERY `limit`, or returns
    /// an unexpected response shape).
    async fn start_scripted_relay<F>(handler: F) -> String
    where
        F: Fn(&ClientMessage) -> Vec<RelayMessage> + Send + Sync + 'static,
    {
        use tokio::net::TcpListener;

        let handler = Arc::new(handler);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("ws://{addr}/scp/v1");

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let handler = Arc::clone(&handler);
                tokio::spawn(async move {
                    let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                        return;
                    };
                    let (mut sink, mut source) = ws.split();
                    while let Some(Ok(frame)) = source.next().await {
                        let bytes = match frame {
                            Message::Binary(b) => b,
                            Message::Close(_) => break,
                            _ => continue,
                        };
                        let Ok(msg) = ClientMessage::from_bytes(&bytes) else {
                            continue;
                        };
                        for resp in handler(&msg) {
                            if let Ok(rb) = resp.to_bytes() {
                                let _ = sink.send(Message::Binary(rb)).await;
                            }
                        }
                    }
                });
            }
        });

        url
    }

    /// Builds a deterministic, decodable DID-record frame's raw bytes.
    fn did_frame(seq: u64, value: &[u8]) -> Vec<u8> {
        scp_protocol::envelope::did_record::DidRecordV1::try_new(
            [0xAB; 32],
            seq,
            [0xCD; 64],
            value.to_vec(),
        )
        .unwrap()
        .encode()
    }

    /// CRITICAL regression (SCP-RELAYRES-002): `publish_raw` then `query_raw`
    /// against a REAL in-process relay returns ALL published frames and
    /// terminates on `query_complete` — promptly, NOT on the 30s deadline (and
    /// well under the composer's 5s per-relay timeout). Before the fix,
    /// `send_request` consumed the ref_id-bearing `query_complete` and the
    /// collect loop ran to its deadline, so the composer cancelled it and every
    /// normal resolution yielded zero candidates.
    #[tokio::test]
    async fn query_raw_e2e_returns_all_frames_and_completes_promptly() {
        use crate::native::server::{DidRecordValidation, Relay, RelayConfig};
        use crate::native::storage::BlobStorageBackend;
        use std::net::SocketAddr;

        // This test exercises the CLIENT's multi-candidate collection over
        // NON-validating storage (the frames use dummy key/signature bytes —
        // exactly what a validating relay would reject). A validating relay
        // collapses a DID routing_id to a single slot (SCP-RELAYRES-003), which
        // is a separate, relay-side property; here we want the relay to keep and
        // return every published blob so the client's sift path is exercised.
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            delivery_jitter_ms: 0,
            did_record_validation: DidRecordValidation::Disabled,
            ..RelayConfig::default()
        };
        let (_shutdown, addr) = Relay::start(config, BlobStorageBackend::in_memory())
            .await
            .unwrap();
        let url = format!("ws://{addr}/scp/v1");
        let client = NativeRelayClient::connect(&url).await.unwrap();

        let routing_id = [0x11; 32];
        let frames = vec![
            did_frame(1, b"doc-one"),
            did_frame(2, b"doc-two"),
            did_frame(3, b"doc-three"),
        ];
        for frame in &frames {
            client
                .publish_raw(&routing_id, 3600, frame.clone())
                .await
                .expect("publish_raw succeeds");
        }

        let start = tokio::time::Instant::now();
        let mut got = client
            .query_raw(&routing_id, None, 16)
            .await
            .expect("query_raw succeeds");
        let elapsed = start.elapsed();

        assert_eq!(got.len(), 3, "all three published frames returned");
        let mut want = frames;
        got.sort();
        want.sort();
        assert_eq!(got, want, "returned blobs are byte-identical to published");
        assert!(
            elapsed < Duration::from_secs(2),
            "query_raw must complete on query_complete, not the deadline; took {elapsed:?}"
        );
    }

    /// Dedup-bypass end-to-end (and observability of `bypass_dedup: true` at the
    /// `query_raw` entry point): querying the SAME unchanged DID twice returns
    /// the record BOTH times. If `query_raw` registered `bypass_dedup: false`,
    /// the first query would seed `seen_blob_ids` and the second would return
    /// empty. This behavioral test fails if the flag is silently flipped.
    #[tokio::test]
    async fn query_raw_twice_same_did_returns_record_both_times() {
        use crate::native::server::{DidRecordValidation, Relay, RelayConfig};
        use crate::native::storage::BlobStorageBackend;
        use std::net::SocketAddr;

        // Client-side dedup-bypass behavior over NON-validating storage (the
        // dummy-signature frame is not relay-valid). See the sibling test above.
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            delivery_jitter_ms: 0,
            did_record_validation: DidRecordValidation::Disabled,
            ..RelayConfig::default()
        };
        let (_shutdown, addr) = Relay::start(config, BlobStorageBackend::in_memory())
            .await
            .unwrap();
        let url = format!("ws://{addr}/scp/v1");
        let client = NativeRelayClient::connect(&url).await.unwrap();

        let routing_id = [0x22; 32];
        client
            .publish_raw(&routing_id, 3600, did_frame(7, b"stable-doc"))
            .await
            .unwrap();

        let first = client.query_raw(&routing_id, None, 16).await.unwrap();
        assert_eq!(first.len(), 1, "first resolution returns the record");
        let second = client.query_raw(&routing_id, None, 16).await.unwrap();
        assert_eq!(
            second.len(),
            1,
            "second resolution of the unchanged DID must STILL return it \
             (dedup bypassed); a bypass_dedup:false regression makes this empty"
        );
        assert_eq!(first, second);
    }

    /// Control-flow: a `routing_id` that already has a live subscription makes
    /// `query_raw` fail loudly with `SubscriptionFailed` (collision), never
    /// silently borrow the live subscription's dedup-filtered stream.
    #[tokio::test]
    async fn query_raw_collision_returns_subscription_failed() {
        use crate::native::server::{Relay, RelayConfig};
        use crate::native::storage::BlobStorageBackend;
        use std::net::SocketAddr;

        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let (_shutdown, addr) = Relay::start(config, BlobStorageBackend::in_memory())
            .await
            .unwrap();
        let url = format!("ws://{addr}/scp/v1");
        let client = NativeRelayClient::connect(&url).await.unwrap();

        let routing_id = [0x33; 32];
        let _rx = client.subscribe(&routing_id, None).await.unwrap();

        let err = client
            .query_raw(&routing_id, None, 16)
            .await
            .expect_err("query_raw on a subscribed routing_id must fail");
        assert!(
            matches!(err, TransportError::SubscriptionFailed(_)),
            "expected SubscriptionFailed, got {err:?}"
        );
    }

    /// Control-flow: the client-side `limit` cap holds even against a relay that
    /// IGNORES the wire `limit` and floods more blobs (a non-validating/foreign
    /// transport). The scripted relay returns 5 blobs regardless of the request;
    /// `query_raw(limit = 2)` must collect exactly 2.
    #[tokio::test]
    async fn query_raw_caps_collected_blobs_at_limit() {
        let url = start_scripted_relay(|msg| match msg {
            ClientMessage::Publish { ref_id, .. } => vec![RelayMessage::Ok {
                ref_id: ref_id.clone(),
                blob_id: None,
            }],
            ClientMessage::Query {
                ref_id, routing_id, ..
            } => {
                let mut out: Vec<RelayMessage> = (0..5u8)
                    .map(|i| {
                        let blob = vec![i; 8];
                        let blob_id = *crate::traits::BlobId::from_sha256(&blob).as_bytes();
                        RelayMessage::Blob {
                            routing_id: *routing_id,
                            blob_id,
                            recipient_hint: None,
                            blob_ttl: 3600,
                            stored_at: 1_700_000_000,
                            blob,
                        }
                    })
                    .collect();
                out.push(RelayMessage::Event {
                    ref_id: ref_id.clone(),
                    event_type: "query_complete".to_string(),
                });
                out
            }
            _ => Vec::new(),
        })
        .await;

        let client = NativeRelayClient::connect(&url).await.unwrap();
        let got = client.query_raw(&[0x44; 32], None, 2).await.unwrap();
        assert_eq!(
            got.len(),
            2,
            "client must cap at the requested limit even when the relay floods"
        );
    }

    /// RAII cleanup (SCP-RELAYRES-002 HIGH): a `query_raw` future dropped
    /// mid-flight (the composer cancels each per-relay query at 5s) must NOT leak
    /// its temporary subscription. The scripted relay sends a blob but NEVER
    /// `query_complete`, so `query_raw` blocks; we cancel it via a short timeout,
    /// then issue a SECOND `query_raw` for the SAME `routing_id`. If the first
    /// leaked its subscription, the second returns `SubscriptionFailed`
    /// immediately (a fast `Ok(Err(..))`); with the RAII guard it instead gets
    /// past the collision check and blocks again (a timeout `Err`).
    #[tokio::test]
    async fn query_raw_cancellation_cleans_up_subscription() {
        let url = start_scripted_relay(|msg| match msg {
            // Return a single blob but deliberately OMIT query_complete, so the
            // collect loop never terminates on its own.
            ClientMessage::Query { routing_id, .. } => {
                let blob = vec![0xEE; 8];
                let blob_id = *crate::traits::BlobId::from_sha256(&blob).as_bytes();
                vec![RelayMessage::Blob {
                    routing_id: *routing_id,
                    blob_id,
                    recipient_hint: None,
                    blob_ttl: 3600,
                    stored_at: 1_700_000_000,
                    blob,
                }]
            }
            _ => Vec::new(),
        })
        .await;
        let client = NativeRelayClient::connect(&url).await.unwrap();
        let routing_id = [0x88; 32];

        // First query_raw: blocks (no query_complete). Cancel it via timeout.
        let first = tokio::time::timeout(
            Duration::from_millis(300),
            client.query_raw(&routing_id, None, 16),
        )
        .await;
        assert!(
            first.is_err(),
            "first query_raw should be cancelled (relay never sends query_complete)"
        );

        // Second query_raw for the SAME routing_id must NOT collide — the
        // cancelled first must have removed its subscription. If it leaked, this
        // returns SubscriptionFailed immediately (Ok(Err)), so the timeout would
        // resolve as Ok, not Err.
        let second = tokio::time::timeout(
            Duration::from_millis(300),
            client.query_raw(&routing_id, None, 16),
        )
        .await;
        assert!(
            second.is_err(),
            "second query_raw must get past the collision check (proving cleanup); \
             a leaked subscription would make it return SubscriptionFailed immediately"
        );
    }

    /// `publish_raw` rejects a `blob_ttl` that overflows the u32 wire field
    /// before touching the sink (a connected client still fails closed).
    #[tokio::test]
    async fn publish_raw_rejects_overflowing_ttl() {
        let url = start_silent_ws_server().await;
        let client = NativeRelayClient::connect(&url).await.unwrap();

        let err = client
            .publish_raw(&[0x55; 32], u64::from(u32::MAX) + 1, vec![1, 2, 3])
            .await
            .expect_err("overflowing blob_ttl must be rejected");
        // Assert the specific overflow message, not merely the SendFailed
        // variant: the u32 guard fires before any send (the silent server never
        // responds), so isolating the message proves the overflow branch — a
        // regression removing the guard would surface a different error, not
        // this one.
        assert!(
            matches!(&err, TransportError::SendFailed(msg) if msg.contains("exceeds u32 wire limit")),
            "expected SendFailed(\"…exceeds u32 wire limit\") for overflowing ttl, got {err:?}"
        );
    }

    /// `publish_raw` maps a relay `ERR` response to `SendFailed`.
    #[tokio::test]
    async fn publish_raw_maps_relay_err() {
        let url = start_scripted_relay(|msg| match msg {
            ClientMessage::Publish { ref_id, .. } => vec![RelayMessage::Err {
                ref_id: ref_id.clone(),
                code: 4001,
                msg: "rejected".to_string(),
            }],
            _ => Vec::new(),
        })
        .await;
        let client = NativeRelayClient::connect(&url).await.unwrap();

        let err = client
            .publish_raw(&[0x66; 32], 3600, vec![9, 9, 9])
            .await
            .expect_err("relay ERR must surface");
        assert!(
            matches!(err, TransportError::SendFailed(_)),
            "expected SendFailed, got {err:?}"
        );
    }

    /// `publish_raw` maps an unexpected (non-Ok/non-Err) relay response to
    /// `ProtocolError`. A ref_id-bearing EVENT is routed to the pending request
    /// by dispatch, so `send_request` returns it and `publish_raw`'s catch-all
    /// arm fires.
    #[tokio::test]
    async fn publish_raw_maps_unexpected_response() {
        let url = start_scripted_relay(|msg| match msg {
            ClientMessage::Publish { ref_id, .. } => vec![RelayMessage::Event {
                ref_id: ref_id.clone(),
                event_type: "unexpected".to_string(),
            }],
            _ => Vec::new(),
        })
        .await;
        let client = NativeRelayClient::connect(&url).await.unwrap();

        let err = client
            .publish_raw(&[0x77; 32], 3600, vec![1])
            .await
            .expect_err("unexpected response must surface");
        assert!(
            matches!(err, TransportError::ProtocolError(_)),
            "expected ProtocolError, got {err:?}"
        );
    }
}
