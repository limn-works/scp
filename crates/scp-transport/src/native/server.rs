//! SCP native relay server.
//!
//! A WebSocket-based store-and-forward relay that accepts opaque blobs, holds
//! them for a TTL, delivers to subscribers, and deletes on expiry or request.
//! The relay is a dumb pipe -- it cannot read, forge, or modify encrypted
//! content.
//!
//! # Usage
//!
//! ```rust,no_run
//! use scp_transport::native::server::{RelayConfig, RelayServer};
//! use scp_transport::native::storage::InMemoryBlobStorage;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let config = RelayConfig::default();
//! let storage = InMemoryBlobStorage::new();
//! let server = RelayServer::new(config, storage);
//! server.run().await?;
//! # Ok(())
//! # }
//! ```
//!
//! See ADR-004 in `.docs/adrs/phase-1.md` for the full specification.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, mpsc};
use tokio_tungstenite::tungstenite::Message;

use super::error::code;
use super::protocol::{
    ClientMessage, DEFAULT_QUERY_LIMIT, MAX_BLOB_SIZE, MAX_BLOB_TTL, MAX_QUERY_LIMIT, MIN_BLOB_TTL,
    RelayMessage,
};
use super::storage::{BlobStorage, StoredBlob};

/// Configuration for the relay server.
///
/// All fields have sensible defaults matching the ADR-004 specification.
/// Use [`RelayConfig::default()`] for standard configuration.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Address to bind the WebSocket listener to.
    pub bind_addr: SocketAddr,
    /// Maximum blob size in bytes (default: 262144 / 256 KB).
    pub max_blob_size: usize,
    /// Maximum blob TTL in seconds (default: 604800 / 7 days).
    pub max_blob_ttl: u32,
    /// Maximum concurrent subscriptions per WebSocket connection (default: 100).
    pub max_subscriptions_per_connection: usize,
    /// Maximum QUERY limit (default: 1000).
    pub max_query_limit: u32,
    /// Interval for the TTL expiry background task (default: 10 seconds).
    pub ttl_check_interval: Duration,
    /// Maximum concurrent WebSocket connections from a single IP address (default: 10).
    pub max_connections_per_ip: usize,
    /// Maximum total concurrent WebSocket connections across all IPs (default: 1000).
    pub max_total_connections: usize,
    /// Maximum PUBLISH operations per second per IP address (default: 100).
    pub rate_limit_publishes_per_second: u32,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 9000)),
            max_blob_size: MAX_BLOB_SIZE,
            max_blob_ttl: MAX_BLOB_TTL,
            max_subscriptions_per_connection: 100,
            max_query_limit: MAX_QUERY_LIMIT,
            ttl_check_interval: Duration::from_secs(10),
            max_connections_per_ip: 10,
            max_total_connections: 1000,
            rate_limit_publishes_per_second: 100,
        }
    }
}

/// The subscription registry: `routing_id -> Vec<SubscriberEntry>`.
type SubscriptionRegistry = Arc<RwLock<HashMap<[u8; 32], Vec<SubscriberEntry>>>>;

/// An entry in the subscription registry.
struct SubscriberEntry {
    /// Unique ID for this connection (to allow targeted removal).
    connection_id: u64,
    /// Channel for pushing relay messages to this subscriber.
    tx: mpsc::Sender<RelayMessage>,
}

/// Per-IP connection counter, shared across all connection handlers.
type ConnectionTracker = Arc<RwLock<HashMap<IpAddr, usize>>>;

/// Per-IP token-bucket rate limiter for publish operations.
///
/// Each bucket tracks remaining tokens and the last refill time. Tokens are
/// replenished lazily on each check rather than via a background task.
#[derive(Debug)]
struct RateLimitBucket {
    /// Remaining tokens in this bucket.
    tokens: f64,
    /// Last time tokens were refilled.
    last_refill: Instant,
}

/// Shared rate limiter state mapping IP addresses to their token buckets.
type PublishRateLimiter = Arc<tokio::sync::Mutex<HashMap<IpAddr, RateLimitBucket>>>;

/// The SCP native relay server.
///
/// Accepts WebSocket connections, processes client messages, and manages
/// blob storage and subscriptions. The relay never inspects blob contents --
/// it is a dumb store-and-forward pipe.
///
/// # Type parameter
///
/// `S` is the blob storage backend. Phase 1 uses [`InMemoryBlobStorage`].
pub struct RelayServer<S: BlobStorage> {
    config: RelayConfig,
    storage: Arc<S>,
    subscriptions: SubscriptionRegistry,
    next_connection_id: Arc<std::sync::atomic::AtomicU64>,
    /// Tracks active connection count per IP address.
    connection_tracker: ConnectionTracker,
    /// Per-IP publish rate limiter (token bucket).
    publish_rate_limiter: PublishRateLimiter,
}

impl<S: BlobStorage + 'static> RelayServer<S> {
    /// Creates a new relay server with the given configuration and storage.
    #[must_use]
    pub fn new(config: RelayConfig, storage: S) -> Self {
        Self {
            config,
            storage: Arc::new(storage),
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            next_connection_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            connection_tracker: Arc::new(RwLock::new(HashMap::new())),
            publish_rate_limiter: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Runs the relay server, listening for WebSocket connections.
    ///
    /// This method blocks until the server encounters a fatal error.
    /// Each incoming connection is handled in a separate tokio task.
    ///
    /// A background task runs on `config.ttl_check_interval` to purge
    /// expired blobs from storage.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::BindFailed`] if the server cannot bind to
    /// the configured address.
    pub async fn run(&self) -> Result<(), RelayError> {
        let listener = TcpListener::bind(self.config.bind_addr)
            .await
            .map_err(|e| RelayError::BindFailed(e.to_string()))?;

        // Spawn the TTL expiry background task.
        let storage_for_ttl = Arc::clone(&self.storage);
        let ttl_interval = self.config.ttl_check_interval;
        tokio::spawn(async move {
            ttl_expiry_task(storage_for_ttl, ttl_interval).await;
        });

        loop {
            let (stream, addr) = listener
                .accept()
                .await
                .map_err(|e| RelayError::AcceptFailed(e.to_string()))?;

            let ip = addr.ip();

            // Enforce connection limits before upgrading to WebSocket.
            {
                let tracker = self.connection_tracker.read().await;
                let total: usize = tracker.values().sum();
                if total >= self.config.max_total_connections {
                    tracing::warn!(
                        ip = %ip,
                        total_connections = total,
                        limit = self.config.max_total_connections,
                        "rejecting connection: max total connections reached"
                    );
                    drop(stream);
                    continue;
                }
                let ip_count = tracker.get(&ip).copied().unwrap_or(0);
                if ip_count >= self.config.max_connections_per_ip {
                    tracing::warn!(
                        ip = %ip,
                        ip_connections = ip_count,
                        limit = self.config.max_connections_per_ip,
                        "rejecting connection: max connections per IP reached"
                    );
                    drop(stream);
                    continue;
                }
            }

            // Register this connection.
            {
                let mut tracker = self.connection_tracker.write().await;
                *tracker.entry(ip).or_insert(0) += 1;
            }

            let conn_id = self
                .next_connection_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let storage = Arc::clone(&self.storage);
            let subscriptions = Arc::clone(&self.subscriptions);
            let config = self.config.clone();
            let conn_tracker = Arc::clone(&self.connection_tracker);
            let rate_limiter = Arc::clone(&self.publish_rate_limiter);

            tokio::spawn(async move {
                if let Err(_e) = handle_connection(
                    stream,
                    conn_id,
                    ip,
                    storage,
                    subscriptions,
                    config,
                    rate_limiter,
                )
                .await
                {
                    // Connection handler errors are expected (client disconnect, etc.).
                }
                // Decrement connection count on disconnect.
                decrement_connection(&conn_tracker, ip).await;
            });
        }
    }

    /// Starts the relay server and returns the local address it bound to.
    ///
    /// Unlike [`run`](Self::run), this method returns immediately after
    /// binding and spawns the accept loop in a background task. Useful
    /// for tests that need the bound address.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::BindFailed`] if the server cannot bind to
    /// the configured address.
    pub async fn start(&self) -> Result<SocketAddr, RelayError> {
        let listener = TcpListener::bind(self.config.bind_addr)
            .await
            .map_err(|e| RelayError::BindFailed(e.to_string()))?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| RelayError::BindFailed(e.to_string()))?;

        // Spawn the TTL expiry background task.
        let storage_for_ttl = Arc::clone(&self.storage);
        let ttl_interval = self.config.ttl_check_interval;
        tokio::spawn(async move {
            ttl_expiry_task(storage_for_ttl, ttl_interval).await;
        });

        let storage = Arc::clone(&self.storage);
        let subscriptions = Arc::clone(&self.subscriptions);
        let config = self.config.clone();
        let next_id = Arc::clone(&self.next_connection_id);
        let conn_tracker = Arc::clone(&self.connection_tracker);
        let rate_limiter = Arc::clone(&self.publish_rate_limiter);

        tokio::spawn(async move {
            loop {
                let Ok((stream, addr)) = listener.accept().await else {
                    break;
                };

                let ip = addr.ip();

                // Enforce connection limits.
                {
                    let tracker = conn_tracker.read().await;
                    let total: usize = tracker.values().sum();
                    if total >= config.max_total_connections {
                        tracing::warn!(
                            ip = %ip,
                            total_connections = total,
                            limit = config.max_total_connections,
                            "rejecting connection: max total connections reached"
                        );
                        drop(stream);
                        continue;
                    }
                    let ip_count = tracker.get(&ip).copied().unwrap_or(0);
                    if ip_count >= config.max_connections_per_ip {
                        tracing::warn!(
                            ip = %ip,
                            ip_connections = ip_count,
                            limit = config.max_connections_per_ip,
                            "rejecting connection: max connections per IP reached"
                        );
                        drop(stream);
                        continue;
                    }
                }

                // Register this connection.
                {
                    let mut tracker = conn_tracker.write().await;
                    *tracker.entry(ip).or_insert(0) += 1;
                }

                let conn_id = next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let storage = Arc::clone(&storage);
                let subscriptions = Arc::clone(&subscriptions);
                let config = config.clone();
                let conn_tracker = Arc::clone(&conn_tracker);
                let rate_limiter = Arc::clone(&rate_limiter);

                tokio::spawn(async move {
                    let _ = handle_connection(
                        stream,
                        conn_id,
                        ip,
                        storage,
                        subscriptions,
                        config,
                        rate_limiter,
                    )
                    .await;
                    // Decrement connection count on disconnect.
                    decrement_connection(&conn_tracker, ip).await;
                });
            }
        });

        Ok(local_addr)
    }
}

/// Relay server errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RelayError {
    /// The server could not bind to the configured address.
    #[error("bind failed: {0}")]
    BindFailed(String),

    /// The server could not accept a connection.
    #[error("accept failed: {0}")]
    AcceptFailed(String),
}

/// Background task that periodically purges expired blobs.
async fn ttl_expiry_task<S: BlobStorage>(storage: Arc<S>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        let _ = storage.purge_expired().await;
    }
}

/// Connection-level error type for internal use.
#[derive(Debug, thiserror::Error)]
enum ConnectionError {
    #[error("websocket error: {0}")]
    WebSocket(String),
}

/// Decrements the per-IP connection count when a connection is dropped.
async fn decrement_connection(tracker: &ConnectionTracker, ip: IpAddr) {
    let mut t = tracker.write().await;
    if let Some(count) = t.get_mut(&ip) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            t.remove(&ip);
        }
    }
}

/// Checks whether a publish is allowed under the per-IP token-bucket rate
/// limit. Returns `true` if the publish should proceed, `false` if rate-limited.
async fn check_publish_rate_limit(
    rate_limiter: &PublishRateLimiter,
    ip: IpAddr,
    rate: u32,
) -> bool {
    let mut limiter = rate_limiter.lock().await;
    let now = Instant::now();
    let bucket = limiter.entry(ip).or_insert_with(|| RateLimitBucket {
        tokens: f64::from(rate),
        last_refill: now,
    });

    // Refill tokens based on elapsed time.
    let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
    bucket.tokens = (bucket.tokens + elapsed * f64::from(rate)).min(f64::from(rate));
    bucket.last_refill = now;

    if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0;
        true
    } else {
        false
    }
}

/// Handles a single WebSocket connection.
#[allow(clippy::too_many_arguments)]
async fn handle_connection<S: BlobStorage + 'static>(
    stream: TcpStream,
    connection_id: u64,
    ip: IpAddr,
    storage: Arc<S>,
    subscriptions: SubscriptionRegistry,
    config: RelayConfig,
    rate_limiter: PublishRateLimiter,
) -> Result<(), ConnectionError> {
    let ws_stream = tokio_tungstenite::accept_async(stream)
        .await
        .map_err(|e| ConnectionError::WebSocket(e.to_string()))?;

    let (mut ws_sink, mut ws_source) = ws_stream.split();

    // Channel for sending relay messages back to this client.
    let (tx, mut rx) = mpsc::channel::<RelayMessage>(256);

    // Track this connection's subscriptions for cleanup.
    let my_subscriptions: Arc<RwLock<HashSet<[u8; 32]>>> = Arc::new(RwLock::new(HashSet::new()));

    // Spawn a task to forward relay messages from the channel to the WebSocket.
    let forward_handle = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let Ok(bytes) = msg.to_bytes() else {
                continue;
            };
            if ws_sink.send(Message::Binary(bytes)).await.is_err() {
                break;
            }
        }
    });

    // Process incoming messages.
    while let Some(msg_result) = ws_source.next().await {
        let msg = match msg_result {
            Ok(m) => m,
            Err(_e) => break,
        };

        match msg {
            Message::Binary(data) => {
                let Ok(client_msg) = ClientMessage::from_bytes(&data) else {
                    let err_msg = RelayMessage::Err {
                        ref_id: None,
                        code: code::INVALID_MESSAGE,
                        msg: "failed to deserialize message".to_string(),
                    };
                    let _ = tx.send(err_msg).await;
                    continue;
                };

                handle_client_message(
                    &client_msg,
                    connection_id,
                    ip,
                    &tx,
                    &storage,
                    &subscriptions,
                    &my_subscriptions,
                    &config,
                    &rate_limiter,
                )
                .await;
            }
            Message::Close(_) => break,
            Message::Ping(_) => {
                // WebSocket-level pings (opcode 0x9) are handled automatically
                // by tungstenite. Nothing to do here -- just avoid breaking the loop.
            }
            _ => {
                // Text frames and other types are not supported.
                let err_msg = RelayMessage::Err {
                    ref_id: None,
                    code: code::INVALID_MESSAGE,
                    msg: "expected binary frame".to_string(),
                };
                let _ = tx.send(err_msg).await;
            }
        }
    }

    // Cleanup: remove this connection's subscriptions.
    // Collect the routing IDs under a read lock, then acquire the write lock
    // only for the brief mutation -- minimises contention on the registry.
    let routing_ids: Vec<[u8; 32]> = {
        let my_subs = my_subscriptions.read().await;
        my_subs.iter().copied().collect()
    };
    if !routing_ids.is_empty() {
        let mut registry = subscriptions.write().await;
        for routing_id in &routing_ids {
            if let Some(entries) = registry.get_mut(routing_id) {
                entries.retain(|e| e.connection_id != connection_id);
                if entries.is_empty() {
                    registry.remove(routing_id);
                }
            }
        }
    }

    // Drop the sender to signal the forward task to stop.
    drop(tx);
    let _ = forward_handle.await;

    Ok(())
}

/// Dispatches a client message to the appropriate handler.
#[allow(clippy::too_many_arguments)]
async fn handle_client_message<S: BlobStorage>(
    msg: &ClientMessage,
    connection_id: u64,
    ip: IpAddr,
    tx: &mpsc::Sender<RelayMessage>,
    storage: &Arc<S>,
    subscriptions: &SubscriptionRegistry,
    my_subscriptions: &Arc<RwLock<HashSet<[u8; 32]>>>,
    config: &RelayConfig,
    rate_limiter: &PublishRateLimiter,
) {
    match msg {
        ClientMessage::Publish {
            ref_id,
            routing_id,
            recipient_hint,
            blob_ttl,
            blob,
        } => {
            handle_publish(
                ref_id.clone(),
                *routing_id,
                *recipient_hint,
                *blob_ttl,
                blob,
                ip,
                tx,
                storage,
                subscriptions,
                config,
                rate_limiter,
            )
            .await;
        }
        ClientMessage::Subscribe {
            ref_id,
            routing_id,
            since,
        } => {
            handle_subscribe(
                ref_id.clone(),
                *routing_id,
                *since,
                connection_id,
                tx,
                storage,
                subscriptions,
                my_subscriptions,
                config,
            )
            .await;
        }
        ClientMessage::Unsubscribe { ref_id, routing_id } => {
            handle_unsubscribe(
                ref_id.clone(),
                *routing_id,
                connection_id,
                tx,
                subscriptions,
                my_subscriptions,
            )
            .await;
        }
        ClientMessage::Query {
            ref_id,
            routing_id,
            since,
            limit,
        } => {
            handle_query(
                ref_id.clone(),
                *routing_id,
                *since,
                *limit,
                tx,
                storage,
                config,
            )
            .await;
        }
        ClientMessage::Delete { ref_id, blob_id } => {
            handle_delete(ref_id.clone(), *blob_id, tx, storage).await;
        }
        ClientMessage::Ack { .. } => {
            // ACK is fire-and-forget. No response.
        }
        ClientMessage::Ping { ts } => {
            let pong = RelayMessage::Pong { ts: *ts };
            let _ = tx.send(pong).await;
        }
    }
}

/// Handles a PUBLISH operation.
#[allow(clippy::too_many_arguments)]
async fn handle_publish<S: BlobStorage>(
    ref_id: Option<String>,
    routing_id: [u8; 32],
    recipient_hint: Option<[u8; 32]>,
    blob_ttl: u32,
    blob: &[u8],
    ip: IpAddr,
    tx: &mpsc::Sender<RelayMessage>,
    storage: &Arc<S>,
    subscriptions: &SubscriptionRegistry,
    config: &RelayConfig,
    rate_limiter: &PublishRateLimiter,
) {
    // Check rate limit.
    if !check_publish_rate_limit(rate_limiter, ip, config.rate_limit_publishes_per_second).await {
        tracing::warn!(ip = %ip, "publish rate limit exceeded");
        let err = RelayMessage::Err {
            ref_id,
            code: code::RATE_LIMITED,
            msg: "publish rate limit exceeded".to_string(),
        };
        let _ = tx.send(err).await;
        return;
    }

    // Validate blob size.
    if blob.is_empty() || blob.len() > config.max_blob_size {
        let err = RelayMessage::Err {
            ref_id,
            code: code::BLOB_TOO_LARGE,
            msg: format!(
                "blob must be 1-{} bytes, got {}",
                config.max_blob_size,
                blob.len()
            ),
        };
        let _ = tx.send(err).await;
        return;
    }

    // Validate TTL.
    if blob_ttl < MIN_BLOB_TTL || blob_ttl > config.max_blob_ttl {
        let err = RelayMessage::Err {
            ref_id,
            code: code::TTL_TOO_LONG,
            msg: format!(
                "blob_ttl must be {}-{}, got {}",
                MIN_BLOB_TTL, config.max_blob_ttl, blob_ttl
            ),
        };
        let _ = tx.send(err).await;
        return;
    }

    // Compute blob_id = SHA-256(blob).
    let blob_id = {
        let mut hasher = Sha256::new();
        hasher.update(blob);
        let hash = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&hash);
        id
    };

    // Store the blob.
    let stored = match storage
        .store(routing_id, blob_id, recipient_hint, blob_ttl, blob.to_vec())
        .await
    {
        Ok(s) => s,
        Err(e) => {
            let err = RelayMessage::Err {
                ref_id,
                code: code::STORAGE_FULL,
                msg: e.to_string(),
            };
            let _ = tx.send(err).await;
            return;
        }
    };

    // Deliver to active subscribers. The return value tracks failed sends
    // (logged inside the function) for suppression detection.
    let _failed_deliveries = deliver_to_subscribers(&stored, subscriptions).await;

    // Respond with OK + blob_id.
    let ok = RelayMessage::Ok {
        ref_id,
        blob_id: Some(blob_id),
    };
    let _ = tx.send(ok).await;
}

/// Delivers a stored blob to matching subscribers.
///
/// Returns the number of delivery failures (subscribers whose channel was
/// full or closed). A non-zero count indicates potential selective message
/// suppression if a relay artificially fills a target's buffer.
#[allow(clippy::significant_drop_tightening)]
async fn deliver_to_subscribers(stored: &StoredBlob, subscriptions: &SubscriptionRegistry) -> u64 {
    let registry = subscriptions.read().await;

    let Some(entries) = registry.get(&stored.routing_id) else {
        return 0;
    };

    let blob_msg = RelayMessage::Blob {
        routing_id: stored.routing_id,
        blob_id: stored.blob_id,
        recipient_hint: stored.recipient_hint,
        blob_ttl: stored.blob_ttl,
        stored_at: stored.stored_at,
        blob: stored.blob.clone(),
    };

    let mut failed = 0u64;
    for entry in entries {
        // Send to subscriber; if the channel is full or closed, track the failure.
        if let Err(e) = entry.tx.try_send(blob_msg.clone()) {
            failed += 1;
            tracing::warn!(
                connection_id = entry.connection_id,
                blob_id = ?stored.blob_id,
                error = %e,
                failed_count = failed,
                total_subscribers = entries.len(),
                "failed to deliver blob to subscriber (channel full or closed) — \
                 possible selective suppression vector"
            );
        }
    }

    if failed > 0 {
        tracing::warn!(
            blob_id = ?stored.blob_id,
            routing_id = ?stored.routing_id,
            failed_deliveries = failed,
            total_subscribers = entries.len(),
            "blob delivery incomplete: {failed}/{} subscribers received the blob",
            entries.len()
        );
    }

    failed
}

/// Handles a SUBSCRIBE operation.
#[allow(clippy::too_many_arguments, clippy::significant_drop_tightening)]
async fn handle_subscribe<S: BlobStorage>(
    ref_id: Option<String>,
    routing_id: [u8; 32],
    since: Option<u64>,
    connection_id: u64,
    tx: &mpsc::Sender<RelayMessage>,
    storage: &Arc<S>,
    subscriptions: &SubscriptionRegistry,
    my_subscriptions: &Arc<RwLock<HashSet<[u8; 32]>>>,
    config: &RelayConfig,
) {
    // Check subscription limit.
    {
        let my_subs = my_subscriptions.read().await;
        if my_subs.len() >= config.max_subscriptions_per_connection {
            let err = RelayMessage::Err {
                ref_id,
                code: code::TOO_MANY_SUBSCRIPTIONS,
                msg: format!(
                    "maximum {} subscriptions per connection",
                    config.max_subscriptions_per_connection
                ),
            };
            let _ = tx.send(err).await;
            return;
        }
    }

    // Register the subscription.
    {
        let mut registry = subscriptions.write().await;
        let entries = registry.entry(routing_id).or_default();
        // Remove any existing subscription from this connection for this routing_id.
        entries.retain(|e| e.connection_id != connection_id);
        entries.push(SubscriberEntry {
            connection_id,
            tx: tx.clone(),
        });
    }

    {
        let mut my_subs = my_subscriptions.write().await;
        my_subs.insert(routing_id);
    }

    // Send OK response.
    let ok = RelayMessage::Ok {
        ref_id: ref_id.clone(),
        blob_id: None,
    };
    let _ = tx.send(ok).await;

    // Backfill if `since` is provided.
    if let Some(since_ts) = since {
        let blobs = storage
            .query(&routing_id, Some(since_ts), MAX_QUERY_LIMIT)
            .await;

        if let Ok(blobs) = blobs {
            for stored in blobs {
                let blob_msg = RelayMessage::Blob {
                    routing_id: stored.routing_id,
                    blob_id: stored.blob_id,
                    recipient_hint: stored.recipient_hint,
                    blob_ttl: stored.blob_ttl,
                    stored_at: stored.stored_at,
                    blob: stored.blob,
                };
                let _ = tx.send(blob_msg).await;
            }
        }

        // Emit backfill_complete event.
        let event = RelayMessage::Event {
            ref_id,
            event_type: "backfill_complete".to_string(),
        };
        let _ = tx.send(event).await;
    }
}

/// Handles an UNSUBSCRIBE operation.
async fn handle_unsubscribe(
    ref_id: Option<String>,
    routing_id: [u8; 32],
    connection_id: u64,
    tx: &mpsc::Sender<RelayMessage>,
    subscriptions: &SubscriptionRegistry,
    my_subscriptions: &Arc<RwLock<HashSet<[u8; 32]>>>,
) {
    // Remove from the registry.
    {
        let mut registry = subscriptions.write().await;
        if let Some(entries) = registry.get_mut(&routing_id) {
            entries.retain(|e| e.connection_id != connection_id);
            if entries.is_empty() {
                registry.remove(&routing_id);
            }
        }
    }

    {
        let mut my_subs = my_subscriptions.write().await;
        my_subs.remove(&routing_id);
    }

    let ok = RelayMessage::Ok {
        ref_id,
        blob_id: None,
    };
    let _ = tx.send(ok).await;
}

/// Handles a QUERY operation.
async fn handle_query<S: BlobStorage>(
    ref_id: Option<String>,
    routing_id: [u8; 32],
    since: Option<u64>,
    limit: Option<u32>,
    tx: &mpsc::Sender<RelayMessage>,
    storage: &Arc<S>,
    config: &RelayConfig,
) {
    let effective_limit = limit.unwrap_or(DEFAULT_QUERY_LIMIT);

    // Validate limit.
    if effective_limit == 0 || effective_limit > config.max_query_limit {
        let err = RelayMessage::Err {
            ref_id,
            code: code::LIMIT_EXCEEDED,
            msg: format!(
                "limit must be 1-{}, got {}",
                config.max_query_limit, effective_limit
            ),
        };
        let _ = tx.send(err).await;
        return;
    }

    let blobs = match storage.query(&routing_id, since, effective_limit).await {
        Ok(b) => b,
        Err(e) => {
            let err = RelayMessage::Err {
                ref_id,
                code: code::INTERNAL_ERROR,
                msg: e.to_string(),
            };
            let _ = tx.send(err).await;
            return;
        }
    };

    for stored in &blobs {
        let blob_msg = RelayMessage::Blob {
            routing_id: stored.routing_id,
            blob_id: stored.blob_id,
            recipient_hint: stored.recipient_hint,
            blob_ttl: stored.blob_ttl,
            stored_at: stored.stored_at,
            blob: stored.blob.clone(),
        };
        let _ = tx.send(blob_msg).await;
    }

    // Emit query_complete event.
    let event = RelayMessage::Event {
        ref_id,
        event_type: "query_complete".to_string(),
    };
    let _ = tx.send(event).await;
}

/// Handles a DELETE operation.
async fn handle_delete<S: BlobStorage>(
    ref_id: Option<String>,
    blob_id: [u8; 32],
    tx: &mpsc::Sender<RelayMessage>,
    storage: &Arc<S>,
) {
    // Best-effort deletion -- always return OK.
    let _ = storage.delete(&blob_id).await;

    let ok = RelayMessage::Ok {
        ref_id,
        blob_id: None,
    };
    let _ = tx.send(ok).await;
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]
mod tests {
    use super::*;
    use crate::native::storage::InMemoryBlobStorage;
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::connect_async;

    /// Helper: create a test server on a random port and return the address.
    async fn start_test_server() -> SocketAddr {
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            ..RelayConfig::default()
        };
        let storage = InMemoryBlobStorage::new();
        let server = RelayServer::new(config, storage);
        server.start().await.unwrap()
    }

    /// Helper: connect a WebSocket client to the given address.
    async fn connect_client(
        addr: SocketAddr,
    ) -> (
        futures::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            Message,
        >,
        futures::stream::SplitStream<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
        >,
    ) {
        let url = format!("ws://{addr}/scp/v1");
        let (ws_stream, _) = connect_async(&url).await.unwrap();
        ws_stream.split()
    }

    /// Helper: send a client message and return the raw bytes.
    async fn send_msg(
        sink: &mut futures::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            Message,
        >,
        msg: &ClientMessage,
    ) {
        let bytes = msg.to_bytes().unwrap();
        sink.send(Message::Binary(bytes)).await.unwrap();
    }

    /// Helper: receive and deserialize the next relay message.
    async fn recv_msg(
        stream: &mut futures::stream::SplitStream<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
        >,
    ) -> RelayMessage {
        let timeout = tokio::time::timeout(Duration::from_secs(5), stream.next()).await;
        let msg = timeout.unwrap().unwrap().unwrap();
        match msg {
            Message::Binary(data) => RelayMessage::from_bytes(&data).unwrap(),
            other => panic!("expected binary frame, got {other:?}"),
        }
    }

    /// Helper: receive relay message with a short timeout, returns None on timeout.
    async fn recv_msg_timeout(
        stream: &mut futures::stream::SplitStream<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
        >,
        duration: Duration,
    ) -> Option<RelayMessage> {
        let timeout = tokio::time::timeout(duration, stream.next()).await;
        match timeout {
            Ok(Some(Ok(Message::Binary(data)))) => Some(RelayMessage::from_bytes(&data).unwrap()),
            _ => None,
        }
    }

    #[tokio::test]
    async fn ping_returns_pong_with_same_timestamp() {
        let addr = start_test_server().await;
        let (mut sink, mut stream) = connect_client(addr).await;

        let ping = ClientMessage::Ping { ts: 12345 };
        send_msg(&mut sink, &ping).await;

        let reply = recv_msg(&mut stream).await;
        assert_eq!(reply, RelayMessage::Pong { ts: 12345 });
    }

    #[tokio::test]
    async fn publish_returns_ok_with_blob_id() {
        let addr = start_test_server().await;
        let (mut sink, mut stream) = connect_client(addr).await;

        let blob_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let expected_blob_id = {
            let mut hasher = Sha256::new();
            hasher.update(&blob_data);
            let hash = hasher.finalize();
            let mut id = [0u8; 32];
            id.copy_from_slice(&hash);
            id
        };

        let publish = ClientMessage::Publish {
            ref_id: Some("pub-1".to_string()),
            routing_id: [0xAA; 32],
            recipient_hint: None,
            blob_ttl: 3600,
            blob: blob_data,
        };
        send_msg(&mut sink, &publish).await;

        let reply = recv_msg(&mut stream).await;
        assert_eq!(
            reply,
            RelayMessage::Ok {
                ref_id: Some("pub-1".to_string()),
                blob_id: Some(expected_blob_id),
            }
        );
    }

    #[tokio::test]
    async fn publish_then_subscribe_receives_blob() {
        let addr = start_test_server().await;
        let routing_id = [0xAA; 32];
        let blob_data = vec![1, 2, 3, 4, 5];

        // Client 1: publish a blob.
        let (mut sink1, mut stream1) = connect_client(addr).await;
        let publish = ClientMessage::Publish {
            ref_id: Some("pub-1".to_string()),
            routing_id,
            recipient_hint: None,
            blob_ttl: 3600,
            blob: blob_data.clone(),
        };
        send_msg(&mut sink1, &publish).await;
        let _ = recv_msg(&mut stream1).await; // OK response

        // Client 2: subscribe and request backfill since timestamp 0.
        let (mut sink2, mut stream2) = connect_client(addr).await;
        let subscribe = ClientMessage::Subscribe {
            ref_id: Some("sub-1".to_string()),
            routing_id,
            since: Some(0),
        };
        send_msg(&mut sink2, &subscribe).await;

        // Expect: OK, then BLOB (backfill), then EVENT (backfill_complete).
        let ok = recv_msg(&mut stream2).await;
        assert!(matches!(ok, RelayMessage::Ok { .. }));

        let blob = recv_msg(&mut stream2).await;
        match &blob {
            RelayMessage::Blob {
                routing_id: rid,
                blob: data,
                ..
            } => {
                assert_eq!(rid, &routing_id);
                assert_eq!(data, &blob_data);
            }
            other => panic!("expected BLOB, got {other:?}"),
        }

        let event = recv_msg(&mut stream2).await;
        match &event {
            RelayMessage::Event {
                event_type, ref_id, ..
            } => {
                assert_eq!(event_type, "backfill_complete");
                assert_eq!(ref_id, &Some("sub-1".to_string()));
            }
            other => panic!("expected EVENT, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn subscribe_then_publish_delivers_live() {
        let addr = start_test_server().await;
        let routing_id = [0xBB; 32];
        let blob_data = vec![10, 20, 30];

        // Client 1: subscribe first (no since, so no backfill).
        let (mut sink1, mut stream1) = connect_client(addr).await;
        let subscribe = ClientMessage::Subscribe {
            ref_id: Some("sub-1".to_string()),
            routing_id,
            since: None,
        };
        send_msg(&mut sink1, &subscribe).await;
        let ok = recv_msg(&mut stream1).await;
        assert!(matches!(ok, RelayMessage::Ok { .. }));

        // Client 2: publish.
        let (mut sink2, mut stream2) = connect_client(addr).await;
        let publish = ClientMessage::Publish {
            ref_id: Some("pub-1".to_string()),
            routing_id,
            recipient_hint: None,
            blob_ttl: 3600,
            blob: blob_data.clone(),
        };
        send_msg(&mut sink2, &publish).await;
        let _ = recv_msg(&mut stream2).await; // OK response

        // Client 1 should receive the blob.
        let blob = recv_msg(&mut stream1).await;
        match &blob {
            RelayMessage::Blob {
                routing_id: rid,
                blob: data,
                ..
            } => {
                assert_eq!(rid, &routing_id);
                assert_eq!(data, &blob_data);
            }
            other => panic!("expected BLOB, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unsubscribe_stops_delivery() {
        let addr = start_test_server().await;
        let routing_id = [0xCC; 32];

        // Subscribe.
        let (mut sink, mut stream) = connect_client(addr).await;
        let subscribe = ClientMessage::Subscribe {
            ref_id: None,
            routing_id,
            since: None,
        };
        send_msg(&mut sink, &subscribe).await;
        let _ = recv_msg(&mut stream).await; // OK

        // Unsubscribe.
        let unsubscribe = ClientMessage::Unsubscribe {
            ref_id: None,
            routing_id,
        };
        send_msg(&mut sink, &unsubscribe).await;
        let _ = recv_msg(&mut stream).await; // OK

        // Publish on a different client -- subscriber should NOT receive.
        let (mut sink2, mut stream2) = connect_client(addr).await;
        let publish = ClientMessage::Publish {
            ref_id: None,
            routing_id,
            recipient_hint: None,
            blob_ttl: 3600,
            blob: vec![99],
        };
        send_msg(&mut sink2, &publish).await;
        let _ = recv_msg(&mut stream2).await; // OK

        // The first client should not receive anything.
        let result = recv_msg_timeout(&mut stream, Duration::from_millis(200)).await;
        assert!(result.is_none(), "should not receive after unsubscribe");
    }

    #[tokio::test]
    async fn query_returns_blobs_and_query_complete() {
        let addr = start_test_server().await;
        let routing_id = [0xDD; 32];

        // Publish two blobs.
        let (mut sink, mut stream) = connect_client(addr).await;
        for i in 0u8..2 {
            let publish = ClientMessage::Publish {
                ref_id: None,
                routing_id,
                recipient_hint: None,
                blob_ttl: 3600,
                blob: vec![i; 10],
            };
            send_msg(&mut sink, &publish).await;
            let _ = recv_msg(&mut stream).await; // OK
        }

        // Query.
        let query = ClientMessage::Query {
            ref_id: Some("q-1".to_string()),
            routing_id,
            since: None,
            limit: None,
        };
        send_msg(&mut sink, &query).await;

        // Expect 2 BLOBs + 1 EVENT(query_complete).
        let blob1 = recv_msg(&mut stream).await;
        assert!(matches!(blob1, RelayMessage::Blob { .. }));

        let blob2 = recv_msg(&mut stream).await;
        assert!(matches!(blob2, RelayMessage::Blob { .. }));

        let event = recv_msg(&mut stream).await;
        match &event {
            RelayMessage::Event { event_type, ref_id } => {
                assert_eq!(event_type, "query_complete");
                assert_eq!(ref_id, &Some("q-1".to_string()));
            }
            other => panic!("expected EVENT, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn delete_removes_blob() {
        let addr = start_test_server().await;
        let routing_id = [0xEE; 32];
        let blob_data = vec![42; 10];

        // Publish.
        let (mut sink, mut stream) = connect_client(addr).await;
        let publish = ClientMessage::Publish {
            ref_id: None,
            routing_id,
            recipient_hint: None,
            blob_ttl: 3600,
            blob: blob_data.clone(),
        };
        send_msg(&mut sink, &publish).await;

        let ok = recv_msg(&mut stream).await;
        let blob_id = match ok {
            RelayMessage::Ok { blob_id, .. } => blob_id.unwrap(),
            other => panic!("expected OK, got {other:?}"),
        };

        // Delete.
        let delete = ClientMessage::Delete {
            ref_id: Some("del-1".to_string()),
            blob_id,
        };
        send_msg(&mut sink, &delete).await;
        let ok = recv_msg(&mut stream).await;
        assert!(matches!(ok, RelayMessage::Ok { .. }));

        // Query should return no blobs.
        let query = ClientMessage::Query {
            ref_id: Some("q-1".to_string()),
            routing_id,
            since: None,
            limit: None,
        };
        send_msg(&mut sink, &query).await;

        // Should get query_complete immediately (no blobs).
        let event = recv_msg(&mut stream).await;
        assert!(matches!(
            event,
            RelayMessage::Event {
                event_type,
                ..
            } if event_type == "query_complete"
        ));
    }

    #[tokio::test]
    async fn ack_is_fire_and_forget() {
        let addr = start_test_server().await;
        let (mut sink, mut stream) = connect_client(addr).await;

        let ack = ClientMessage::Ack {
            blob_id: [0xFF; 32],
        };
        send_msg(&mut sink, &ack).await;

        // ACK has no response. Send a PING to verify the connection is alive.
        let ping = ClientMessage::Ping { ts: 999 };
        send_msg(&mut sink, &ping).await;

        let reply = recv_msg(&mut stream).await;
        assert_eq!(reply, RelayMessage::Pong { ts: 999 });
    }

    #[tokio::test]
    async fn publish_blob_too_large_returns_error() {
        let addr = start_test_server().await;
        let (mut sink, mut stream) = connect_client(addr).await;

        let publish = ClientMessage::Publish {
            ref_id: Some("big".to_string()),
            routing_id: [0x00; 32],
            recipient_hint: None,
            blob_ttl: 60,
            blob: vec![0x00; MAX_BLOB_SIZE + 1],
        };
        send_msg(&mut sink, &publish).await;

        let reply = recv_msg(&mut stream).await;
        match reply {
            RelayMessage::Err { code, .. } => {
                assert_eq!(code, code::BLOB_TOO_LARGE);
            }
            other => panic!("expected ERR, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn publish_empty_blob_returns_error() {
        let addr = start_test_server().await;
        let (mut sink, mut stream) = connect_client(addr).await;

        let publish = ClientMessage::Publish {
            ref_id: Some("empty".to_string()),
            routing_id: [0x00; 32],
            recipient_hint: None,
            blob_ttl: 60,
            blob: vec![],
        };
        send_msg(&mut sink, &publish).await;

        let reply = recv_msg(&mut stream).await;
        match reply {
            RelayMessage::Err { code, .. } => {
                assert_eq!(code, code::BLOB_TOO_LARGE);
            }
            other => panic!("expected ERR, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn publish_ttl_too_long_returns_error() {
        let addr = start_test_server().await;
        let (mut sink, mut stream) = connect_client(addr).await;

        let publish = ClientMessage::Publish {
            ref_id: Some("ttl".to_string()),
            routing_id: [0x00; 32],
            recipient_hint: None,
            blob_ttl: MAX_BLOB_TTL + 1,
            blob: vec![1],
        };
        send_msg(&mut sink, &publish).await;

        let reply = recv_msg(&mut stream).await;
        match reply {
            RelayMessage::Err { code, .. } => {
                assert_eq!(code, code::TTL_TOO_LONG);
            }
            other => panic!("expected ERR, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn publish_ttl_zero_returns_error() {
        let addr = start_test_server().await;
        let (mut sink, mut stream) = connect_client(addr).await;

        let publish = ClientMessage::Publish {
            ref_id: Some("ttl0".to_string()),
            routing_id: [0x00; 32],
            recipient_hint: None,
            blob_ttl: 0,
            blob: vec![1],
        };
        send_msg(&mut sink, &publish).await;

        let reply = recv_msg(&mut stream).await;
        match reply {
            RelayMessage::Err { code, .. } => {
                assert_eq!(code, code::TTL_TOO_LONG);
            }
            other => panic!("expected ERR, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn multiplexed_subscriptions_on_single_connection() {
        let addr = start_test_server().await;
        let routing_id_a = [0xAA; 32];
        let routing_id_b = [0xBB; 32];

        // Subscribe to both routing_ids on one connection.
        let (mut sink, mut stream) = connect_client(addr).await;
        let sub_a = ClientMessage::Subscribe {
            ref_id: None,
            routing_id: routing_id_a,
            since: None,
        };
        send_msg(&mut sink, &sub_a).await;
        let _ = recv_msg(&mut stream).await; // OK

        let sub_b = ClientMessage::Subscribe {
            ref_id: None,
            routing_id: routing_id_b,
            since: None,
        };
        send_msg(&mut sink, &sub_b).await;
        let _ = recv_msg(&mut stream).await; // OK

        // Publish to routing_id_a.
        let (mut sink2, mut stream2) = connect_client(addr).await;
        let pub_a = ClientMessage::Publish {
            ref_id: None,
            routing_id: routing_id_a,
            recipient_hint: None,
            blob_ttl: 3600,
            blob: vec![1],
        };
        send_msg(&mut sink2, &pub_a).await;
        let _ = recv_msg(&mut stream2).await; // OK

        // Publish to routing_id_b.
        let pub_b = ClientMessage::Publish {
            ref_id: None,
            routing_id: routing_id_b,
            recipient_hint: None,
            blob_ttl: 3600,
            blob: vec![2],
        };
        send_msg(&mut sink2, &pub_b).await;
        let _ = recv_msg(&mut stream2).await; // OK

        // The subscriber should receive both blobs.
        let msg1 = recv_msg(&mut stream).await;
        let msg2 = recv_msg(&mut stream).await;

        let mut received_routing_ids = vec![];
        for msg in [&msg1, &msg2] {
            match msg {
                RelayMessage::Blob { routing_id, .. } => {
                    received_routing_ids.push(*routing_id);
                }
                other => panic!("expected BLOB, got {other:?}"),
            }
        }

        assert!(received_routing_ids.contains(&routing_id_a));
        assert!(received_routing_ids.contains(&routing_id_b));
    }

    #[tokio::test]
    async fn subscribe_with_since_backfills_oldest_first() {
        let addr = start_test_server().await;
        let routing_id = [0xFF; 32];

        // Publish 3 blobs.
        let (mut sink, mut stream) = connect_client(addr).await;
        let mut expected_order = vec![];
        for i in 0u8..3 {
            let data = vec![i; 10];
            let blob_id = {
                let mut hasher = Sha256::new();
                hasher.update(&data);
                let hash = hasher.finalize();
                let mut id = [0u8; 32];
                id.copy_from_slice(&hash);
                id
            };
            let publish = ClientMessage::Publish {
                ref_id: None,
                routing_id,
                recipient_hint: None,
                blob_ttl: 3600,
                blob: data,
            };
            send_msg(&mut sink, &publish).await;
            let _ = recv_msg(&mut stream).await; // OK
            expected_order.push(blob_id);
        }

        // Subscribe with since=0 to get backfill.
        let (mut sink2, mut stream2) = connect_client(addr).await;
        let subscribe = ClientMessage::Subscribe {
            ref_id: None,
            routing_id,
            since: Some(0),
        };
        send_msg(&mut sink2, &subscribe).await;
        let _ = recv_msg(&mut stream2).await; // OK

        // Should receive 3 blobs in oldest-first order.
        let mut received_ids = vec![];
        for _ in 0..3 {
            let msg = recv_msg(&mut stream2).await;
            match msg {
                RelayMessage::Blob { blob_id, .. } => {
                    received_ids.push(blob_id);
                }
                other => panic!("expected BLOB, got {other:?}"),
            }
        }

        // Verify order matches publication order (oldest first).
        assert_eq!(received_ids, expected_order);

        // backfill_complete event.
        let event = recv_msg(&mut stream2).await;
        assert!(matches!(
            event,
            RelayMessage::Event { event_type, .. } if event_type == "backfill_complete"
        ));
    }

    #[tokio::test]
    async fn query_with_limit_respects_limit() {
        let addr = start_test_server().await;
        let routing_id = [0x11; 32];

        // Publish 5 blobs.
        let (mut sink, mut stream) = connect_client(addr).await;
        for i in 0u8..5 {
            let publish = ClientMessage::Publish {
                ref_id: None,
                routing_id,
                recipient_hint: None,
                blob_ttl: 3600,
                blob: vec![i; 10],
            };
            send_msg(&mut sink, &publish).await;
            let _ = recv_msg(&mut stream).await; // OK
        }

        // Query with limit=2.
        let query = ClientMessage::Query {
            ref_id: Some("q-lim".to_string()),
            routing_id,
            since: None,
            limit: Some(2),
        };
        send_msg(&mut sink, &query).await;

        // Should receive exactly 2 blobs + query_complete.
        let blob1 = recv_msg(&mut stream).await;
        assert!(matches!(blob1, RelayMessage::Blob { .. }));

        let blob2 = recv_msg(&mut stream).await;
        assert!(matches!(blob2, RelayMessage::Blob { .. }));

        let event = recv_msg(&mut stream).await;
        assert!(matches!(
            event,
            RelayMessage::Event { event_type, .. } if event_type == "query_complete"
        ));
    }

    #[tokio::test]
    async fn invalid_message_returns_error() {
        let addr = start_test_server().await;
        let (mut sink, mut stream) = connect_client(addr).await;

        // Send garbage binary data.
        sink.send(Message::Binary(vec![0xFF, 0xFE, 0xFD]))
            .await
            .unwrap();

        let reply = recv_msg(&mut stream).await;
        match reply {
            RelayMessage::Err { code, .. } => {
                assert_eq!(code, code::INVALID_MESSAGE);
            }
            other => panic!("expected ERR, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ttl_expiry_removes_expired_blobs() {
        // Use a very short TTL check interval.
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(50),
            ..RelayConfig::default()
        };
        let storage = InMemoryBlobStorage::new();
        let server = RelayServer::new(config, storage);
        let addr = server.start().await.unwrap();

        let routing_id = [0x22; 32];

        // Publish with a short TTL.
        let (mut sink, mut stream) = connect_client(addr).await;
        let publish = ClientMessage::Publish {
            ref_id: None,
            routing_id,
            recipient_hint: None,
            blob_ttl: 1, // 1 second TTL
            blob: vec![1, 2, 3],
        };
        send_msg(&mut sink, &publish).await;
        let _ = recv_msg(&mut stream).await; // OK

        // Wait for TTL to expire and background task to purge.
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Query should return no blobs.
        let query = ClientMessage::Query {
            ref_id: Some("q-ttl".to_string()),
            routing_id,
            since: None,
            limit: None,
        };
        send_msg(&mut sink, &query).await;

        // Should get query_complete immediately (no blobs after expiry).
        let event = recv_msg(&mut stream).await;
        assert!(
            matches!(
                &event,
                RelayMessage::Event { event_type, .. } if event_type == "query_complete"
            ),
            "expected query_complete after TTL expiry, got {event:?}"
        );
    }

    #[tokio::test]
    async fn max_connections_per_ip_rejects_excess() {
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            max_connections_per_ip: 2,
            max_total_connections: 100,
            ttl_check_interval: Duration::from_millis(100),
            ..RelayConfig::default()
        };
        let storage = InMemoryBlobStorage::new();
        let server = RelayServer::new(config, storage);
        let addr = server.start().await.unwrap();

        // Open 2 connections (at the limit).
        let (_sink1, _stream1) = connect_client(addr).await;
        let (_sink2, _stream2) = connect_client(addr).await;

        // Allow the server to register the connections.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The 3rd connection should be rejected (TCP accepted but WS will fail).
        let url = format!("ws://{addr}/scp/v1");
        let result = tokio::time::timeout(Duration::from_secs(2), connect_async(&url)).await;
        // Connection should either fail or timeout -- the server drops the stream.
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "3rd connection should be rejected when max_connections_per_ip is 2"
        );
    }

    #[tokio::test]
    async fn max_total_connections_rejects_excess() {
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            max_connections_per_ip: 100,
            max_total_connections: 2,
            ttl_check_interval: Duration::from_millis(100),
            ..RelayConfig::default()
        };
        let storage = InMemoryBlobStorage::new();
        let server = RelayServer::new(config, storage);
        let addr = server.start().await.unwrap();

        // Open 2 connections (at the total limit).
        let (_sink1, _stream1) = connect_client(addr).await;
        let (_sink2, _stream2) = connect_client(addr).await;

        // Allow the server to register the connections.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The 3rd connection should be rejected.
        let url = format!("ws://{addr}/scp/v1");
        let result = tokio::time::timeout(Duration::from_secs(2), connect_async(&url)).await;
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "3rd connection should be rejected when max_total_connections is 2"
        );
    }

    #[tokio::test]
    async fn publish_rate_limit_rejects_excess() {
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            rate_limit_publishes_per_second: 2,
            ttl_check_interval: Duration::from_millis(100),
            ..RelayConfig::default()
        };
        let storage = InMemoryBlobStorage::new();
        let server = RelayServer::new(config, storage);
        let addr = server.start().await.unwrap();

        let (mut sink, mut stream) = connect_client(addr).await;
        let routing_id = [0xAA; 32];

        // Send 2 publishes (should succeed -- 2 tokens available).
        for i in 0u8..2 {
            let publish = ClientMessage::Publish {
                ref_id: Some(format!("p-{i}")),
                routing_id,
                recipient_hint: None,
                blob_ttl: 3600,
                blob: vec![i; 10],
            };
            send_msg(&mut sink, &publish).await;
            let reply = recv_msg(&mut stream).await;
            assert!(
                matches!(reply, RelayMessage::Ok { .. }),
                "publish {i} should succeed, got {reply:?}"
            );
        }

        // The 3rd publish should be rate-limited.
        let publish = ClientMessage::Publish {
            ref_id: Some("p-excess".to_string()),
            routing_id,
            recipient_hint: None,
            blob_ttl: 3600,
            blob: vec![99; 10],
        };
        send_msg(&mut sink, &publish).await;
        let reply = recv_msg(&mut stream).await;
        match reply {
            RelayMessage::Err { code: c, .. } => {
                assert_eq!(c, code::RATE_LIMITED);
            }
            other => panic!("expected RATE_LIMITED error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn storage_full_returns_error() {
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            ..RelayConfig::default()
        };
        // Storage with capacity of 2.
        let storage = InMemoryBlobStorage::with_capacity(2);
        let server = RelayServer::new(config, storage);
        let addr = server.start().await.unwrap();

        let (mut sink, mut stream) = connect_client(addr).await;
        let routing_id = [0xAA; 32];

        // Fill storage to capacity.
        for i in 0u8..2 {
            let publish = ClientMessage::Publish {
                ref_id: Some(format!("p-{i}")),
                routing_id,
                recipient_hint: None,
                blob_ttl: 3600,
                blob: vec![i; 10],
            };
            send_msg(&mut sink, &publish).await;
            let reply = recv_msg(&mut stream).await;
            assert!(
                matches!(reply, RelayMessage::Ok { .. }),
                "publish {i} should succeed"
            );
        }

        // The 3rd publish should get STORAGE_FULL.
        let publish = ClientMessage::Publish {
            ref_id: Some("p-full".to_string()),
            routing_id,
            recipient_hint: None,
            blob_ttl: 3600,
            blob: vec![99; 10],
        };
        send_msg(&mut sink, &publish).await;
        let reply = recv_msg(&mut stream).await;
        match reply {
            RelayMessage::Err { code: c, .. } => {
                assert_eq!(c, code::STORAGE_FULL);
            }
            other => panic!("expected STORAGE_FULL error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn connection_freed_after_disconnect() {
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            max_connections_per_ip: 1,
            max_total_connections: 100,
            ttl_check_interval: Duration::from_millis(100),
            ..RelayConfig::default()
        };
        let storage = InMemoryBlobStorage::new();
        let server = RelayServer::new(config, storage);
        let addr = server.start().await.unwrap();

        // Open a connection and verify it works.
        {
            let (mut sink, mut stream) = connect_client(addr).await;
            let ping = ClientMessage::Ping { ts: 1 };
            send_msg(&mut sink, &ping).await;
            let reply = recv_msg(&mut stream).await;
            assert_eq!(reply, RelayMessage::Pong { ts: 1 });

            // Close the connection by dropping sink/stream.
            drop(sink);
            drop(stream);
        }

        // Wait for the server to notice the disconnect and decrement the counter.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // A new connection should now succeed (slot freed).
        let (mut sink2, mut stream2) = connect_client(addr).await;
        let ping = ClientMessage::Ping { ts: 2 };
        send_msg(&mut sink2, &ping).await;
        let reply = recv_msg(&mut stream2).await;
        assert_eq!(reply, RelayMessage::Pong { ts: 2 });
    }
}
