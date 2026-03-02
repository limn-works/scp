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
//! On abnormal close, the client reconnects with exponential backoff:
//! 1s, 2s, 4s, 8s, 16s, 30s cap. On reconnect, the adapter re-issues
//! SUBSCRIBE for each routing ID with `since = last_stored_at - 5s` overlap.
//! The client deduplicates received blobs via `blob_id`.
//!
//! See ADR-004 in `.docs/adrs/phase-1.md` for the full specification.
//!
//! [`NativeRelayAdapter`]: super::adapter::NativeRelayAdapter
//! [`TransportAdapter`]: crate::TransportAdapter

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use futures::{SinkExt, StreamExt};
use scp_core::envelope::OuterEnvelope;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;

use super::protocol::{ClientMessage, RelayMessage};
use crate::error::TransportError;

/// Keepalive interval: client sends PING every 30 seconds.
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// Backoff durations for reconnection: 1s, 2s, 4s, 8s, 16s, 30s cap.
///
/// Used by [`NativeRelayClient::reconnect`] on connection loss.
#[allow(dead_code)]
const BACKOFF_STEPS: &[Duration] = &[
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
    Duration::from_secs(30),
];

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
#[derive(Debug, Clone)]
struct SubscriptionState {
    /// The routing ID this subscription is for (used during reconnection).
    #[allow(dead_code)]
    routing_id: [u8; 32],
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
}

/// Shared inner state of the WebSocket client.
struct ClientInner {
    /// Pending request-response pairs keyed by `ref_id`.
    pending: HashMap<String, PendingRequest>,
    /// Next `ref_id` counter for generating unique request IDs.
    next_ref_id: u64,
    /// Active subscriptions keyed by routing ID.
    subscriptions: HashMap<[u8; 32], SubscriptionState>,
    /// Set of blob IDs already seen (for deduplication on reconnect).
    seen_blob_ids: HashSet<[u8; 32]>,
    /// Whether the client is currently connected.
    connected: bool,
}

/// WebSocket client for the SCP native relay.
///
/// Manages the connection lifecycle including keepalive PINGs and
/// reconnection with exponential backoff. Send operations use
/// request-response correlation via `ref_id`. Subscription streams
/// are delivered via channels.
///
/// # Thread safety
///
/// The client is `Send + Sync` and safe to use from multiple tasks.
/// Internal state is protected by `RwLock` and `Mutex`.
pub struct NativeRelayClient {
    /// The relay URL (e.g., `ws://127.0.0.1:9000/scp/v1`).
    url: String,
    /// Shared mutable inner state.
    inner: Arc<RwLock<ClientInner>>,
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
        let inner = Arc::new(RwLock::new(ClientInner {
            pending: HashMap::new(),
            next_ref_id: 1,
            subscriptions: HashMap::new(),
            seen_blob_ids: HashSet::new(),
            connected: false,
        }));

        let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

        let client = Self {
            url: url.to_string(),
            inner,
            ws_sink: Arc::new(Mutex::new(None)),
            reader_handle: Arc::new(Mutex::new(None)),
            keepalive_handle: Arc::new(Mutex::new(None)),
            shutdown_tx: Arc::new(Mutex::new(Some(shutdown_tx))),
        };

        client.establish_connection().await?;
        Ok(client)
    }

    /// Establishes (or re-establishes) the WebSocket connection.
    async fn establish_connection(&self) -> Result<(), TransportError> {
        let (ws_stream, _response) = tokio_tungstenite::connect_async(&self.url)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

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
    async fn reader_loop(
        mut source: WsSource,
        inner: Arc<RwLock<ClientInner>>,
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
                                Self::dispatch_relay_message(&inner, relay_msg).await;
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
    async fn dispatch_relay_message(inner: &Arc<RwLock<ClientInner>>, msg: RelayMessage) {
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
            // matching routing ID.
            RelayMessage::Blob {
                routing_id,
                blob_id,
                blob,
                stored_at,
                ..
            } => {
                // Verify blob integrity: SHA-256(blob) must match relay-provided blob_id.
                let computed_hash: [u8; 32] = Sha256::digest(blob).into();
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
                    let maybe_tx = inner
                        .read()
                        .await
                        .subscriptions
                        .get(routing_id)
                        .map(|sub| sub.tx.clone());
                    if let Some(tx) = maybe_tx {
                        let _ = tx
                            .send(SubscriptionMessage::BlobIntegrityError { expected, actual })
                            .await;
                    }
                    return;
                }

                let receive_time = Instant::now();
                let mut state = inner.write().await;

                // Deduplication: skip if we've already seen this `blob_id`.
                if !state.seen_blob_ids.insert(*blob_id) {
                    return;
                }

                if let Some(sub) = state.subscriptions.get_mut(routing_id) {
                    // Record local monotonic receive time for reconnection
                    // window calculations (immune to relay timestamp
                    // manipulation).
                    sub.last_local_receive = Some(receive_time);

                    // Update relay-provided `stored_at` as untrusted metadata
                    // (informational/logging only).
                    if sub.last_stored_at.is_none_or(|prev| *stored_at > prev) {
                        sub.last_stored_at = Some(*stored_at);
                    }

                    // Plausibility check: warn if relay timestamp deviates
                    // significantly from local wall-clock time.
                    if let Ok(local_now) = scp_core::time::now_secs() {
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

                    let _ = sub.tx.send(SubscriptionMessage::Relay(msg)).await;
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

                // Broadcast event to all subscriptions.
                let state = inner.read().await;
                for sub in state.subscriptions.values() {
                    let _ = sub.tx.send(SubscriptionMessage::Relay(msg.clone())).await;
                }
            }

            // PONG is handled silently (keepalive acknowledged).
            RelayMessage::Pong { .. } => {}
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

                    let Ok(ts) = scp_core::time::now_secs() else {
                        // Clock unavailable — skip this ping cycle.
                        continue;
                    };

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

        // Register subscription state before sending to avoid race conditions.
        self.inner.write().await.subscriptions.insert(
            *routing_id,
            SubscriptionState {
                routing_id: *routing_id,
                last_stored_at: None,
                last_local_receive: None,
                tx,
            },
        );

        let msg = ClientMessage::Subscribe {
            ref_id: None,
            routing_id: *routing_id,
            since,
        };

        let response = self.send_request(msg).await.map_err(|e| {
            let inner = Arc::clone(&self.inner);
            let rid = *routing_id;
            tokio::spawn(async move {
                inner.write().await.subscriptions.remove(&rid);
            });
            TransportError::SubscriptionFailed(e.to_string())
        })?;

        match response {
            RelayMessage::Ok { .. } => Ok(rx),
            RelayMessage::Err { code, msg, .. } => {
                self.inner.write().await.subscriptions.remove(routing_id);
                Err(TransportError::SubscriptionFailed(format!(
                    "relay error {code}: {msg}"
                )))
            }
            _ => {
                self.inner.write().await.subscriptions.remove(routing_id);
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
        self.inner.write().await.subscriptions.remove(routing_id);

        match response {
            RelayMessage::Err { code, msg, .. } => Err(TransportError::SendFailed(format!(
                "relay error {code}: {msg}"
            ))),
            _ => Ok(()),
        }
    }

    /// Sends a QUERY command and collects results.
    ///
    /// Registers a temporary subscription channel, sends QUERY, and collects
    /// BLOB messages until `query_complete` EVENT or timeout.
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
        // Check if there's already an active subscription for this `routing_id`.
        if self
            .inner
            .read()
            .await
            .subscriptions
            .contains_key(routing_id)
        {
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

        let (tx, mut rx) = mpsc::channel::<SubscriptionMessage>(256);

        // Register a temporary subscription for receiving BLOB messages.
        self.inner.write().await.subscriptions.insert(
            *routing_id,
            SubscriptionState {
                routing_id: *routing_id,
                last_stored_at: None,
                last_local_receive: None,
                tx,
            },
        );

        // Send the QUERY command.
        let msg = ClientMessage::Query {
            ref_id: None,
            routing_id: *routing_id,
            since,
            limit: None,
        };

        let response = self.send_request(msg).await.inspect_err(|_| {
            let inner = Arc::clone(&self.inner);
            let rid = *routing_id;
            tokio::spawn(async move {
                inner.write().await.subscriptions.remove(&rid);
            });
        })?;

        if let RelayMessage::Err { code, msg, .. } = &response {
            self.inner.write().await.subscriptions.remove(routing_id);
            return Err(TransportError::SendFailed(format!(
                "relay error {code}: {msg}"
            )));
        }

        // Collect BLOB messages until `query_complete` or timeout.
        let mut envelopes = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

        loop {
            tokio::select! {
                msg_opt = rx.recv() => {
                    match msg_opt {
                        Some(SubscriptionMessage::Relay(
                            RelayMessage::Blob { blob, .. },
                        )) => {
                            if let Ok(env) = OuterEnvelope::from_bytes(&blob) {
                                envelopes.push(env);
                            }
                        }
                        Some(SubscriptionMessage::Relay(
                            RelayMessage::Event { event_type, .. },
                        )) if event_type == "query_complete" => {
                            break;
                        }
                        None => break,
                        _ => {}
                    }
                }
                () = tokio::time::sleep_until(deadline) => {
                    break;
                }
            }
        }

        // Clean up temporary subscription.
        self.inner.write().await.subscriptions.remove(routing_id);

        Ok(envelopes)
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

        // Try reconnecting with exponential backoff.
        let mut last_err = None;
        for delay in BACKOFF_STEPS {
            tokio::time::sleep(*delay).await;

            match self.establish_connection().await {
                Ok(()) => {
                    // Re-subscribe to all active routing IDs.
                    let subs_snapshot: Vec<_> = self
                        .inner
                        .read()
                        .await
                        .subscriptions
                        .values()
                        .map(|s| (s.routing_id, s.last_local_receive))
                        .collect();

                    for (routing_id, last_local_receive) in subs_snapshot {
                        // Use local receive time (immune to relay timestamp
                        // manipulation) to compute the reconnect window.
                        let since = last_local_receive.and_then(|instant| {
                            let elapsed = instant.elapsed();
                            let now_unix = scp_core::time::now_secs().ok()?;
                            Some(
                                now_unix
                                    .saturating_sub(elapsed.as_secs())
                                    .saturating_sub(RECONNECT_OVERLAP.as_secs()),
                            )
                        });

                        let msg = ClientMessage::Subscribe {
                            ref_id: None,
                            routing_id,
                            since,
                        };

                        // Best-effort: if re-subscribe fails, the subscription
                        // is still tracked and will be retried on next reconnect.
                        let _ = self.send_request(msg).await;
                    }

                    // Notify all active subscriptions that a reconnection
                    // occurred so the adapter can emit
                    // `TransportEvent::Reconnected`.
                    let state = self.inner.read().await;
                    for sub in state.subscriptions.values() {
                        let _ = sub.tx.send(SubscriptionMessage::Reconnected).await;
                    }
                    drop(state);

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

    /// Returns a snapshot of the current subscription routing IDs.
    #[allow(dead_code)]
    pub async fn active_subscriptions(&self) -> Vec<[u8; 32]> {
        self.inner
            .read()
            .await
            .subscriptions
            .keys()
            .copied()
            .collect()
    }

    /// Clears the deduplication set. Useful after a successful reconnect
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
}

/// Assigns a `ref_id` to a [`ClientMessage`] for request-response correlation.
fn assign_ref_id(msg: &mut ClientMessage, ref_id: &str) {
    match msg {
        ClientMessage::Publish { ref_id: r, .. }
        | ClientMessage::Subscribe { ref_id: r, .. }
        | ClientMessage::Unsubscribe { ref_id: r, .. }
        | ClientMessage::Query { ref_id: r, .. }
        | ClientMessage::Delete { ref_id: r, .. } => {
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
    fn backoff_steps_are_monotonically_increasing() {
        for window in BACKOFF_STEPS.windows(2) {
            assert!(window[1] > window[0]);
        }
    }

    #[test]
    fn backoff_cap_is_30_seconds() {
        let last = BACKOFF_STEPS.last().unwrap();
        assert_eq!(*last, Duration::from_secs(30));
    }

    #[test]
    fn reconnect_overlap_is_5_seconds() {
        assert_eq!(RECONNECT_OVERLAP.as_secs(), 5);
    }

    // -----------------------------------------------------------------------
    // Blob integrity verification tests (SCP-193)
    // -----------------------------------------------------------------------

    /// Helper: creates a `ClientInner` with a subscription for the given
    /// routing ID, returning the inner state and the subscription receiver.
    fn setup_inner_with_subscription(
        routing_id: [u8; 32],
    ) -> (
        Arc<RwLock<ClientInner>>,
        mpsc::Receiver<SubscriptionMessage>,
    ) {
        let (tx, rx) = mpsc::channel(16);
        let inner = Arc::new(RwLock::new(ClientInner {
            pending: HashMap::new(),
            next_ref_id: 1,
            subscriptions: HashMap::from([(
                routing_id,
                SubscriptionState {
                    routing_id,
                    last_stored_at: None,
                    last_local_receive: None,
                    tx,
                },
            )]),
            seen_blob_ids: HashSet::new(),
            connected: true,
        }));
        (inner, rx)
    }

    /// Computes SHA-256 of the given data, returning a 32-byte array.
    fn sha256(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    #[tokio::test]
    async fn dispatch_blob_with_correct_hash_accepted() {
        let routing_id = [0xAA; 32];
        let blob_data = vec![0x01, 0x02, 0x03];
        let correct_blob_id = sha256(&blob_data);
        let (inner, mut rx) = setup_inner_with_subscription(routing_id);

        let msg = RelayMessage::Blob {
            routing_id,
            blob_id: correct_blob_id,
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 1_700_000_000,
            blob: blob_data,
        };

        NativeRelayClient::dispatch_relay_message(&inner, msg.clone()).await;

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
        let (inner, mut rx) = setup_inner_with_subscription(routing_id);

        let msg = RelayMessage::Blob {
            routing_id,
            blob_id: original_blob_id, // Hash of original, not tampered.
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 1_700_000_000,
            blob: tampered_blob,
        };

        NativeRelayClient::dispatch_relay_message(&inner, msg).await;

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
        let (inner, mut rx) = setup_inner_with_subscription(routing_id);

        let msg = RelayMessage::Blob {
            routing_id,
            blob_id: correct_blob_id,
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 1_700_000_000,
            blob: empty_blob,
        };

        NativeRelayClient::dispatch_relay_message(&inner, msg).await;

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
        use crate::native::storage::InMemoryBlobStorage;
        use std::net::SocketAddr;

        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = InMemoryBlobStorage::new();
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
}
