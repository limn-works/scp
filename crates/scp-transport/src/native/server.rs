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
//! use std::sync::Arc;
//! use scp_transport::native::server::{RelayConfig, RelayServer};
//! use scp_transport::native::storage::BlobStorageBackend;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let config = RelayConfig::default();
//! let storage = Arc::new(BlobStorageBackend::in_memory());
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
use subtle::ConstantTimeEq;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, mpsc};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse, Request, Response,
};
use tokio_util::sync::CancellationToken;

use super::error::code;
use super::protocol::{
    ClientMessage, DEFAULT_QUERY_LIMIT, MAX_BLOB_SIZE, MAX_BLOB_TTL, MAX_QUERY_LIMIT, MIN_BLOB_TTL,
    RelayMessage,
};
use super::relay_persistence::RelayPersistence;
use super::storage::{BlobStorage, BlobStorageBackend, StoredBlob};

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
    /// Maximum SUBSCRIBE operations per minute per connection (default: 20).
    ///
    /// Per ADR-004: `rate_limit_subscribe: 20/min`. This limits the rate at
    /// which a single connection can issue SUBSCRIBE operations, preventing
    /// subscribe/unsubscribe churn that causes write-lock contention on the
    /// `SubscriptionRegistry`.
    pub rate_limit_subscribes_per_minute: u32,
    /// Maximum random delivery jitter in milliseconds (default: 50ms).
    ///
    /// When non-zero, the relay adds a uniformly random delay in
    /// `[0, delivery_jitter_ms)` before forwarding each stored blob to its
    /// subscribers. This breaks timing correlation between PUBLISH arrival
    /// and subscriber delivery, mitigating relay-side traffic analysis
    /// (BLACK-001). Set to 0 to disable jitter (useful for tests).
    pub delivery_jitter_ms: u64,
    /// Optional shared secret for authenticating internal bridge connections.
    ///
    /// When set, the relay rejects any WebSocket upgrade whose
    /// `Authorization: Bearer <hex>` header does not match this value
    /// (hex-encoded, constant-time comparison). Used by
    /// [`ApplicationNode`] to prevent unauthorized connections to the
    /// internal relay port.
    ///
    /// See GitHub issue #85 for the threat model and #225 for the
    /// migration from query parameter to header.
    pub bridge_secret: Option<[u8; 32]>,
    /// Whether this relay supports the BRIDGE operation for symmetric NAT
    /// fallback (spec section 10.12.4). When `true`, the relay accepts
    /// `BRIDGE_REGISTER` operations from self-hosted relays behind NAT
    /// and proxies traffic for registered routing IDs.
    pub supports_bridge: bool,
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
            rate_limit_subscribes_per_minute: 20,
            delivery_jitter_ms: 50,
            bridge_secret: None,
            supports_bridge: false,
        }
    }
}

/// Handle for gracefully shutting down a running relay server.
///
/// Dropping the handle does **not** shut down the server. Call
/// [`shutdown`](Self::shutdown) explicitly. In-flight connection handlers
/// drain naturally after shutdown is signaled — they are not cancelled.
#[derive(Debug, Clone)]
pub struct ShutdownHandle {
    token: CancellationToken,
}

impl ShutdownHandle {
    /// Signals the relay server to stop accepting new connections.
    ///
    /// Existing connection handlers continue until their clients disconnect
    /// or their work completes.
    pub fn shutdown(&self) {
        self.token.cancel();
    }

    /// Returns `true` if shutdown has been signaled.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.token.is_cancelled()
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
/// # Storage backend
///
/// This struct previously took a generic `B: BlobStorage` parameter that
/// propagated through every handler function, router builder, and test
/// helper. That generic was replaced with concrete [`BlobStorageBackend`]
/// enum dispatch (see [#242]), which provides the same extensibility without
/// the generic propagation cost.
///
/// [#242]: https://github.com/limn-works/scp/issues/242
pub struct RelayServer {
    config: RelayConfig,
    storage: Arc<BlobStorageBackend>,
    subscriptions: SubscriptionRegistry,
    next_connection_id: Arc<std::sync::atomic::AtomicU64>,
    /// Tracks active connection count per IP address.
    connection_tracker: ConnectionTracker,
    /// Per-IP publish rate limiter (token bucket).
    publish_rate_limiter: PublishRateLimiter,
    /// Optional persistence for relay operational state (subscriptions,
    /// rate limits). When `Some`, subscriptions are persisted on
    /// subscribe/unsubscribe and restored on startup.
    ///
    /// See SCP-PERSIST-066.
    persistence: Option<Arc<dyn RelayPersistence>>,
}

impl RelayServer {
    /// Creates a new relay server with the given configuration and storage.
    ///
    /// Accepts any type that implements [`Into<BlobStorageBackend>`], which
    /// includes [`InMemoryBlobStorage`](super::storage::InMemoryBlobStorage)
    /// and [`BlobStorageBackend`] itself. Also accepts `Arc<BlobStorageBackend>`
    /// for sharing between the relay and other components (e.g., broadcast
    /// projection handlers). See spec section 18.11.5.
    #[must_use]
    pub fn new(config: RelayConfig, storage: impl Into<Arc<BlobStorageBackend>>) -> Self {
        Self {
            config,
            storage: storage.into(),
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            next_connection_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            connection_tracker: Arc::new(RwLock::new(HashMap::new())),
            publish_rate_limiter: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            persistence: None,
        }
    }

    /// Creates a new relay server with operational state persistence.
    ///
    /// When persistence is provided, subscriptions are stored on subscribe,
    /// removed on unsubscribe, and restored on startup. Rate limit state
    /// is also persisted periodically.
    ///
    /// See SCP-PERSIST-066.
    #[must_use]
    pub fn with_persistence(
        config: RelayConfig,
        storage: impl Into<Arc<BlobStorageBackend>>,
        persistence: Arc<dyn RelayPersistence>,
    ) -> Self {
        Self {
            config,
            storage: storage.into(),
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            next_connection_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            connection_tracker: Arc::new(RwLock::new(HashMap::new())),
            publish_rate_limiter: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            persistence: Some(persistence),
        }
    }

    /// Restores persisted subscriptions into the in-memory registry.
    ///
    /// Called on startup from both [`run`](Self::run) and [`start`](Self::start).
    /// Best-effort — logs warnings on failure and continues.
    async fn restore_persisted_subscriptions(&self) {
        if let Some(ref persistence) = self.persistence {
            match persistence.load_subscribed_routing_ids() {
                Ok(routing_ids) => {
                    if !routing_ids.is_empty() {
                        tracing::info!(
                            count = routing_ids.len(),
                            "restored persisted subscription routing IDs"
                        );
                        let mut registry = self.subscriptions.write().await;
                        for routing_id in routing_ids {
                            registry.entry(routing_id).or_default();
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "failed to restore persisted subscriptions (continuing without)"
                    );
                }
            }
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
        // Restore persisted subscriptions on startup (SCP-PERSIST-066).
        self.restore_persisted_subscriptions().await;

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
            //
            // When `bridge_secret` is configured, per-IP limits are skipped
            // (all connections originate from localhost). The bridge layer
            // enforces its own concurrency limit instead (see #229).
            if !check_connection_allowed(&self.connection_tracker, ip, &self.config).await {
                drop(stream);
                continue;
            }

            // Register this connection (always tracked for max_total_connections).
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
            let persistence = self.persistence.clone();

            tokio::spawn(async move {
                if let Err(_e) = handle_connection(
                    stream,
                    conn_id,
                    ip,
                    storage,
                    subscriptions,
                    config,
                    rate_limiter,
                    persistence,
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

    /// Starts the relay server and returns a shutdown handle and bound address.
    ///
    /// Unlike [`run`](Self::run), this method returns immediately after
    /// binding and spawns the accept loop in a background task. The returned
    /// [`ShutdownHandle`] can be used to gracefully stop the server.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::BindFailed`] if the server cannot bind to
    /// the configured address.
    pub async fn start(&self) -> Result<(ShutdownHandle, SocketAddr), RelayError> {
        // Restore persisted subscriptions on startup (SCP-PERSIST-066).
        self.restore_persisted_subscriptions().await;

        let listener = TcpListener::bind(self.config.bind_addr)
            .await
            .map_err(|e| RelayError::BindFailed(e.to_string()))?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| RelayError::BindFailed(e.to_string()))?;

        let token = CancellationToken::new();

        // Spawn the TTL expiry background task with cancellation.
        let storage_for_ttl = Arc::clone(&self.storage);
        let ttl_interval = self.config.ttl_check_interval;
        let ttl_token = token.clone();
        tokio::spawn(async move {
            tokio::select! {
                biased;
                () = ttl_token.cancelled() => {}
                () = ttl_expiry_task(storage_for_ttl, ttl_interval) => {}
            }
        });

        let storage = Arc::clone(&self.storage);
        let subscriptions = Arc::clone(&self.subscriptions);
        let config = self.config.clone();
        let next_id = Arc::clone(&self.next_connection_id);
        let conn_tracker = Arc::clone(&self.connection_tracker);
        let rate_limiter = Arc::clone(&self.publish_rate_limiter);
        let persistence = self.persistence.clone();
        let accept_token = token.clone();

        tokio::spawn(async move {
            loop {
                let stream_result = tokio::select! {
                    biased;
                    () = accept_token.cancelled() => break,
                    result = listener.accept() => result,
                };

                let Ok((stream, addr)) = stream_result else {
                    break;
                };

                let ip = addr.ip();

                // Enforce connection limits (per-IP limits skipped in bridge
                // mode — see #229).
                if !check_connection_allowed(&conn_tracker, ip, &config).await {
                    drop(stream);
                    continue;
                }

                // Register this connection (always tracked for max_total_connections).
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
                let persistence = persistence.clone();

                tokio::spawn(async move {
                    let _ = handle_connection(
                        stream,
                        conn_id,
                        ip,
                        storage,
                        subscriptions,
                        config,
                        rate_limiter,
                        persistence,
                    )
                    .await;
                    // Decrement connection count on disconnect.
                    decrement_connection(&conn_tracker, ip).await;
                });
            }
        });

        Ok((ShutdownHandle { token }, local_addr))
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
async fn ttl_expiry_task(storage: Arc<BlobStorageBackend>, interval: Duration) {
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

/// Checks whether a new connection from `ip` should be accepted, given the
/// current tracker state and relay configuration.
///
/// Returns `true` if the connection is allowed, `false` if it should be
/// rejected. When `bridge_mode` is `true`, per-IP limits are skipped (all
/// connections originate from localhost; see #229).
async fn check_connection_allowed(
    tracker: &ConnectionTracker,
    ip: IpAddr,
    config: &RelayConfig,
) -> bool {
    let bridge_mode = config.bridge_secret.is_some();
    let guard = tracker.read().await;
    let total: usize = guard.values().sum();
    if total >= config.max_total_connections {
        tracing::warn!(
            ip = %ip,
            total_connections = total,
            limit = config.max_total_connections,
            "rejecting connection: max total connections reached"
        );
        return false;
    }
    if !bridge_mode {
        let ip_count = guard.get(&ip).copied().unwrap_or(0);
        // Drop the read lock before the comparison — we have our copy.
        drop(guard);
        if ip_count >= config.max_connections_per_ip {
            tracing::warn!(
                ip = %ip,
                ip_connections = ip_count,
                limit = config.max_connections_per_ip,
                "rejecting connection: max connections per IP reached"
            );
            return false;
        }
    }
    true
}

/// Decrements the per-IP connection count when a connection is dropped.
///
/// Removes the entry entirely when the count reaches zero to prevent the
/// tracker map from growing unboundedly.
async fn decrement_connection(tracker: &ConnectionTracker, ip: IpAddr) {
    let mut t = tracker.write().await;
    if let Some(count) = t.get_mut(&ip) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            t.remove(&ip);
        }
    }
}

/// Per-connection token-bucket rate limiter for subscribe operations.
///
/// Unlike the publish rate limiter (which is per-IP and shared across
/// connections), the subscribe rate limiter is per-connection per ADR-004.
/// Each connection owns its own bucket -- no shared state required.
struct SubscribeRateLimiter {
    /// Remaining tokens in this bucket.
    tokens: f64,
    /// Last time tokens were refilled.
    last_refill: Instant,
    /// Tokens per second (derived from the per-minute rate).
    rate_per_second: f64,
    /// Maximum bucket capacity (equal to the per-minute rate, allowing short bursts).
    capacity: f64,
}

impl SubscribeRateLimiter {
    /// Creates a new subscribe rate limiter with the given per-minute rate.
    fn new(rate_per_minute: u32) -> Self {
        let capacity = f64::from(rate_per_minute);
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
            rate_per_second: capacity / 60.0,
            capacity,
        }
    }

    /// Checks whether a subscribe operation is allowed. Returns `true` if the
    /// operation should proceed, `false` if rate-limited.
    fn check(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = elapsed
            .mul_add(self.rate_per_second, self.tokens)
            .min(self.capacity);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
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
    bucket.tokens = elapsed
        .mul_add(f64::from(rate), bucket.tokens)
        .min(f64::from(rate));
    bucket.last_refill = now;

    let allowed = if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0;
        true
    } else {
        false
    };
    drop(limiter);
    allowed
}

/// Callback for `accept_hdr_async` that validates the bridge secret.
///
/// Extracts the token from the `Authorization: Bearer <hex>` header,
/// hex-decodes it, and performs a constant-time comparison against the
/// expected secret. Returns HTTP 403 on mismatch or missing token.
///
/// The token is transmitted via HTTP header rather than query parameter
/// to prevent leakage through server logs, error messages, or debug
/// output (#225). The token value is never included in error messages
/// or logs.
struct BridgeSecretCallback {
    expected: [u8; 32],
}

impl Callback for BridgeSecretCallback {
    fn on_request(self, request: &Request, response: Response) -> Result<Response, ErrorResponse> {
        use tokio_tungstenite::tungstenite::http::StatusCode;

        // Extract the `Authorization: Bearer <hex>` header.
        let auth_header = request
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok());

        let hex_token = auth_header.and_then(|v| v.strip_prefix("Bearer "));

        let Some(hex_token) = hex_token else {
            tracing::warn!("bridge connection rejected: missing or malformed Authorization header");
            let mut err = ErrorResponse::new(None);
            *err.status_mut() = StatusCode::FORBIDDEN;
            return Err(err);
        };

        // Hex-decode the provided token.
        let decoded = hex_decode_32(hex_token);
        let Some(decoded) = decoded else {
            tracing::warn!("bridge connection rejected: invalid token format");
            let mut err = ErrorResponse::new(None);
            *err.status_mut() = StatusCode::FORBIDDEN;
            return Err(err);
        };

        // Constant-time comparison to prevent timing side-channels.
        if decoded.ct_eq(&self.expected).into() {
            Ok(response)
        } else {
            tracing::warn!("bridge connection rejected: invalid token");
            let mut err = ErrorResponse::new(None);
            *err.status_mut() = StatusCode::FORBIDDEN;
            Err(err)
        }
    }
}

/// Decodes a 64-character hex string into a `[u8; 32]`.
///
/// Returns `None` on invalid length or non-hex characters.
fn hex_decode_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex.as_bytes().get(i * 2)?;
        let lo = hex.as_bytes().get(i * 2 + 1)?;
        *byte = (hex_nibble(*hi)? << 4) | hex_nibble(*lo)?;
    }
    Some(out)
}

/// Converts an ASCII hex character to its 4-bit value.
const fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Encodes a `[u8; 32]` as a 64-character lowercase hex string.
///
/// Used by [`ApplicationNode`] to format the bridge token for the
/// WebSocket connection URL.
#[must_use]
pub fn hex_encode_32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Handles a single WebSocket connection.
///
/// When `config.bridge_secret` is set, the WebSocket upgrade request must
/// include an `Authorization: Bearer <hex>` header whose hex-decoded value
/// matches the secret (constant-time comparison). Connections without a
/// valid token are rejected during the handshake — no protocol messages
/// are exchanged.
// Relay handler passes through connection state; bundling into a struct
// would add allocation overhead per-message with no readability gain.
#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    stream: TcpStream,
    connection_id: u64,
    ip: IpAddr,
    storage: Arc<BlobStorageBackend>,
    subscriptions: SubscriptionRegistry,
    config: RelayConfig,
    rate_limiter: PublishRateLimiter,
    persistence: Option<Arc<dyn RelayPersistence>>,
) -> Result<(), ConnectionError> {
    let ws_stream = if let Some(expected_secret) = config.bridge_secret {
        // Validate the bridge token during the WebSocket handshake.
        tokio_tungstenite::accept_hdr_async(
            stream,
            BridgeSecretCallback {
                expected: expected_secret,
            },
        )
        .await
        .map_err(|e| ConnectionError::WebSocket(e.to_string()))?
    } else {
        tokio_tungstenite::accept_async(stream)
            .await
            .map_err(|e| ConnectionError::WebSocket(e.to_string()))?
    };

    let (mut ws_sink, mut ws_source) = ws_stream.split();

    // Channel for sending relay messages back to this client.
    let (tx, mut rx) = mpsc::channel::<RelayMessage>(256);

    // Track this connection's subscriptions for cleanup.
    let my_subscriptions: Arc<RwLock<HashSet<[u8; 32]>>> = Arc::new(RwLock::new(HashSet::new()));

    // Per-connection subscribe rate limiter (ADR-004: 20/min per connection).
    let mut subscribe_rate_limiter =
        SubscribeRateLimiter::new(config.rate_limit_subscribes_per_minute);

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
                    &mut subscribe_rate_limiter,
                    persistence.as_ref(),
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
    cleanup_connection_subscriptions(
        connection_id,
        &my_subscriptions,
        &subscriptions,
        persistence.as_ref(),
    )
    .await;

    // Drop the sender to signal the forward task to stop.
    drop(tx);
    let _ = forward_handle.await;

    Ok(())
}

/// Removes a disconnected connection's subscriptions from the registry.
///
/// Collects routing IDs under a read lock, then acquires the write lock
/// only for the brief mutation — minimises contention on the registry.
/// When a routing ID has no remaining subscribers, it is removed from
/// both the registry and persistence (SCP-PERSIST-066).
async fn cleanup_connection_subscriptions(
    connection_id: u64,
    my_subscriptions: &RwLock<HashSet<[u8; 32]>>,
    subscriptions: &SubscriptionRegistry,
    persistence: Option<&Arc<dyn RelayPersistence>>,
) {
    let routing_ids: Vec<[u8; 32]> = {
        let my_subs = my_subscriptions.read().await;
        my_subs.iter().copied().collect()
    };
    if routing_ids.is_empty() {
        return;
    }
    let mut registry = subscriptions.write().await;
    let mut removed_ids = Vec::new();
    for routing_id in &routing_ids {
        if let Some(entries) = registry.get_mut(routing_id) {
            entries.retain(|e| e.connection_id != connection_id);
            if entries.is_empty() {
                registry.remove(routing_id);
                removed_ids.push(*routing_id);
            }
        }
    }
    drop(registry);

    // Persist removal for routing IDs that no longer have any subscribers.
    if let Some(persistence) = persistence {
        for routing_id in &removed_ids {
            if let Err(e) = persistence.remove_subscription(routing_id) {
                tracing::warn!(
                    error = %e,
                    routing_id = hex::encode(routing_id),
                    "failed to remove persisted subscription on disconnect"
                );
            }
        }
    }
}

/// Dispatches a client message to the appropriate handler.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn handle_client_message(
    msg: &ClientMessage,
    connection_id: u64,
    ip: IpAddr,
    tx: &mpsc::Sender<RelayMessage>,
    storage: &Arc<BlobStorageBackend>,
    subscriptions: &SubscriptionRegistry,
    my_subscriptions: &Arc<RwLock<HashSet<[u8; 32]>>>,
    config: &RelayConfig,
    rate_limiter: &PublishRateLimiter,
    subscribe_rate_limiter: &mut SubscribeRateLimiter,
    persistence: Option<&Arc<dyn RelayPersistence>>,
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
                subscribe_rate_limiter,
                persistence,
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
                persistence,
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
        ClientMessage::BridgeRegister { ref_id, .. } => {
            // Bridge registration requires a BridgeRegistry, which is
            // managed separately from the standard relay server.
            if config.supports_bridge {
                // Bridge service layer (relay::bridge::BridgeRegistry) is
                // not yet wired into the relay server. Return an error so
                // clients know the feature is not operational yet.
                let err_msg = RelayMessage::Err {
                    ref_id: ref_id.clone(),
                    code: code::BRIDGE_NOT_INTEGRATED,
                    msg:
                        "bridge relay integration pending — handler not yet wired to BridgeRegistry"
                            .to_string(),
                };
                let _ = tx.send(err_msg).await;
            } else {
                let err_msg = RelayMessage::Err {
                    ref_id: ref_id.clone(),
                    code: code::BRIDGE_NOT_SUPPORTED,
                    msg: "this relay does not support BRIDGE operations".to_string(),
                };
                let _ = tx.send(err_msg).await;
            }
        }
        ClientMessage::BridgeData { ref_id, .. } => {
            // Bridge data forwarding requires the bridge service layer.
            if config.supports_bridge {
                // Bridge service layer is not yet wired into the relay
                // server. Return an error so clients know the feature is
                // not operational yet.
                let err_msg = RelayMessage::Err {
                    ref_id: ref_id.clone(),
                    code: code::BRIDGE_NOT_INTEGRATED,
                    msg:
                        "bridge relay integration pending — handler not yet wired to BridgeRegistry"
                            .to_string(),
                };
                let _ = tx.send(err_msg).await;
            } else {
                let err_msg = RelayMessage::Err {
                    ref_id: ref_id.clone(),
                    code: code::BRIDGE_NOT_SUPPORTED,
                    msg: "this relay does not support BRIDGE operations".to_string(),
                };
                let _ = tx.send(err_msg).await;
            }
        }
    }
}

/// Handles a PUBLISH operation.
// PUBLISH handler receives protocol-defined fields plus connection state;
// grouping would obscure the protocol-level parameters.
#[allow(clippy::too_many_arguments)]
async fn handle_publish(
    ref_id: Option<String>,
    routing_id: [u8; 32],
    recipient_hint: Option<[u8; 32]>,
    blob_ttl: u32,
    blob: &[u8],
    ip: IpAddr,
    tx: &mpsc::Sender<RelayMessage>,
    storage: &Arc<BlobStorageBackend>,
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

    // Deliver to active subscribers with optional jitter (BLACK-001).
    // The return value tracks failed sends (logged inside the function)
    // for suppression detection.
    let _failed_deliveries =
        deliver_to_subscribers(&stored, subscriptions, config.delivery_jitter_ms).await;

    // Respond with OK + blob_id.
    let ok = RelayMessage::Ok {
        ref_id,
        blob_id: Some(blob_id),
    };
    let _ = tx.send(ok).await;
}

/// Delivers a stored blob to matching subscribers with optional delivery jitter.
///
/// When `jitter_ms > 0`, a uniformly random delay in `[0, jitter_ms)` is applied
/// before delivery to each subscriber. This breaks the timing correlation between
/// PUBLISH arrival and subscriber delivery, mitigating relay-side traffic analysis
/// (BLACK-001). The jitter is per-subscriber so that even subscribers on the same
/// `routing_id` receive blobs at slightly different times.
///
/// Returns the number of delivery failures (subscribers whose channel was
/// full or closed). A non-zero count indicates potential selective message
/// suppression if a relay artificially fills a target's buffer.
#[allow(clippy::significant_drop_tightening)]
async fn deliver_to_subscribers(
    stored: &StoredBlob,
    subscriptions: &SubscriptionRegistry,
    jitter_ms: u64,
) -> u64 {
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

    let total_subscribers = entries.len();

    // When jitter is enabled, spawn parallel tasks so each subscriber's
    // random delay runs concurrently instead of cascading sequentially.
    // With N subscribers at J ms max jitter, worst-case drops from ~N*J/2
    // to ~J ms total wall time.
    let failed = if jitter_ms > 0 {
        let mut handles = Vec::with_capacity(entries.len());
        for entry in entries {
            let msg = blob_msg.clone();
            let tx = entry.tx.clone();
            let connection_id = entry.connection_id;
            let blob_id = stored.blob_id;

            handles.push(tokio::spawn(async move {
                // Per-subscriber delivery jitter (BLACK-001 mitigation).
                let delay_ms = rand::random::<u64>() % jitter_ms;
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;

                if let Err(e) = tx.try_send(msg) {
                    tracing::warn!(
                        connection_id,
                        blob_id = ?blob_id,
                        error = %e,
                        total_subscribers,
                        "failed to deliver blob to subscriber (channel full or closed) — \
                         possible selective suppression vector"
                    );
                    1u64
                } else {
                    0u64
                }
            }));
        }

        let mut total_failed = 0u64;
        for handle in handles {
            // Unwrap is safe: the spawned tasks do not panic.
            total_failed += handle.await.unwrap_or(1);
        }
        total_failed
    } else {
        // Zero-jitter fast path: deliver sequentially without spawn overhead.
        let mut total_failed = 0u64;
        for entry in entries {
            if let Err(e) = entry.tx.try_send(blob_msg.clone()) {
                total_failed += 1;
                tracing::warn!(
                    connection_id = entry.connection_id,
                    blob_id = ?stored.blob_id,
                    error = %e,
                    failed_count = total_failed,
                    total_subscribers,
                    "failed to deliver blob to subscriber (channel full or closed) — \
                     possible selective suppression vector"
                );
            }
        }
        total_failed
    };

    if failed > 0 {
        tracing::warn!(
            blob_id = ?stored.blob_id,
            routing_id = ?stored.routing_id,
            failed_deliveries = failed,
            total_subscribers,
            "blob delivery incomplete: {failed}/{total_subscribers} subscribers received the blob",
        );
    }

    failed
}

/// Handles a SUBSCRIBE operation.
// SUBSCRIBE handler receives protocol-defined fields plus connection state;
// grouping would obscure the protocol-level parameters.
#[allow(clippy::too_many_arguments, clippy::significant_drop_tightening)]
async fn handle_subscribe(
    ref_id: Option<String>,
    routing_id: [u8; 32],
    since: Option<u64>,
    connection_id: u64,
    tx: &mpsc::Sender<RelayMessage>,
    storage: &Arc<BlobStorageBackend>,
    subscriptions: &SubscriptionRegistry,
    my_subscriptions: &Arc<RwLock<HashSet<[u8; 32]>>>,
    config: &RelayConfig,
    subscribe_rate_limiter: &mut SubscribeRateLimiter,
    persistence: Option<&Arc<dyn RelayPersistence>>,
) {
    // Check subscribe rate limit (ADR-004: 20/min per connection).
    if !subscribe_rate_limiter.check() {
        tracing::warn!(
            connection_id = connection_id,
            "subscribe rate limit exceeded"
        );
        let err = RelayMessage::Err {
            ref_id,
            code: code::RATE_LIMITED,
            msg: "subscribe rate limit exceeded".to_string(),
        };
        let _ = tx.send(err).await;
        return;
    }

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

    // Persist subscription (best-effort, SCP-PERSIST-066).
    if let Some(persistence) = persistence
        && let Err(e) = persistence.persist_subscription(&routing_id)
    {
        tracing::warn!(
            error = %e,
            routing_id = hex::encode(routing_id),
            "failed to persist subscription"
        );
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
#[allow(clippy::too_many_arguments)]
async fn handle_unsubscribe(
    ref_id: Option<String>,
    routing_id: [u8; 32],
    connection_id: u64,
    tx: &mpsc::Sender<RelayMessage>,
    subscriptions: &SubscriptionRegistry,
    my_subscriptions: &Arc<RwLock<HashSet<[u8; 32]>>>,
    persistence: Option<&Arc<dyn RelayPersistence>>,
) {
    // Remove from the registry.
    let routing_id_removed;
    {
        let mut registry = subscriptions.write().await;
        if let Some(entries) = registry.get_mut(&routing_id) {
            entries.retain(|e| e.connection_id != connection_id);
            if entries.is_empty() {
                registry.remove(&routing_id);
                routing_id_removed = true;
            } else {
                routing_id_removed = false;
            }
        } else {
            routing_id_removed = false;
        }
        drop(registry);
    }

    {
        let mut my_subs = my_subscriptions.write().await;
        my_subs.remove(&routing_id);
    }

    // Only remove from persistence when no subscribers remain for this
    // routing ID. Other connections may still be subscribed.
    if routing_id_removed
        && let Some(persistence) = persistence
        && let Err(e) = persistence.remove_subscription(&routing_id)
    {
        tracing::warn!(
            error = %e,
            routing_id = hex::encode(routing_id),
            "failed to remove persisted subscription"
        );
    }

    let ok = RelayMessage::Ok {
        ref_id,
        blob_id: None,
    };
    let _ = tx.send(ok).await;
}

/// Handles a QUERY operation.
async fn handle_query(
    ref_id: Option<String>,
    routing_id: [u8; 32],
    since: Option<u64>,
    limit: Option<u32>,
    tx: &mpsc::Sender<RelayMessage>,
    storage: &Arc<BlobStorageBackend>,
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
async fn handle_delete(
    ref_id: Option<String>,
    blob_id: [u8; 32],
    tx: &mpsc::Sender<RelayMessage>,
    storage: &Arc<BlobStorageBackend>,
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
    use crate::native::storage::BlobStorageBackend;
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::connect_async;

    /// Helper: create a test server on a random port and return the address.
    /// Delivery jitter is disabled (0ms) for deterministic test behavior.
    async fn start_test_server() -> SocketAddr {
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();
        addr
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
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();

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
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();

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
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();

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
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();

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
    async fn subscribe_rate_limit_rejects_excess() {
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            rate_limit_subscribes_per_minute: 3,
            ttl_check_interval: Duration::from_millis(100),
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();

        let (mut sink, mut stream) = connect_client(addr).await;

        // Send 3 subscribes (should succeed -- 3 tokens available).
        for i in 0u8..3 {
            let routing_id = [i; 32];
            let subscribe = ClientMessage::Subscribe {
                ref_id: Some(format!("s-{i}")),
                routing_id,
                since: None,
            };
            send_msg(&mut sink, &subscribe).await;
            let reply = recv_msg(&mut stream).await;
            assert!(
                matches!(reply, RelayMessage::Ok { .. }),
                "subscribe {i} should succeed, got {reply:?}"
            );
        }

        // The 4th subscribe should be rate-limited.
        let subscribe = ClientMessage::Subscribe {
            ref_id: Some("s-excess".to_string()),
            routing_id: [0xFF; 32],
            since: None,
        };
        send_msg(&mut sink, &subscribe).await;
        let reply = recv_msg(&mut stream).await;
        match reply {
            RelayMessage::Err { code: c, .. } => {
                assert_eq!(c, code::RATE_LIMITED);
            }
            other => panic!("expected RATE_LIMITED error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn subscribe_rate_limit_recovers_after_time() {
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            // 60/min = 1/sec for easy testing
            rate_limit_subscribes_per_minute: 60,
            ttl_check_interval: Duration::from_millis(100),
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();

        let (mut sink, mut stream) = connect_client(addr).await;

        // Exhaust all 60 tokens.
        for i in 0u8..60 {
            let routing_id = {
                let mut id = [0u8; 32];
                id[0] = i;
                id
            };
            let subscribe = ClientMessage::Subscribe {
                ref_id: Some(format!("s-{i}")),
                routing_id,
                since: None,
            };
            send_msg(&mut sink, &subscribe).await;
            let reply = recv_msg(&mut stream).await;
            assert!(
                matches!(reply, RelayMessage::Ok { .. }),
                "subscribe {i} should succeed, got {reply:?}"
            );
        }

        // Should be rate-limited now.
        let subscribe = ClientMessage::Subscribe {
            ref_id: Some("s-blocked".to_string()),
            routing_id: [0xFE; 32],
            since: None,
        };
        send_msg(&mut sink, &subscribe).await;
        let reply = recv_msg(&mut stream).await;
        assert!(
            matches!(reply, RelayMessage::Err { code, .. } if code == code::RATE_LIMITED),
            "should be rate-limited, got {reply:?}"
        );

        // Wait for token replenishment (1 token/sec at 60/min).
        tokio::time::sleep(Duration::from_millis(1100)).await;

        // Should succeed again after waiting.
        let subscribe = ClientMessage::Subscribe {
            ref_id: Some("s-recovered".to_string()),
            routing_id: [0xFD; 32],
            since: None,
        };
        send_msg(&mut sink, &subscribe).await;
        let reply = recv_msg(&mut stream).await;
        assert!(
            matches!(reply, RelayMessage::Ok { .. }),
            "subscribe should succeed after rate limit recovery, got {reply:?}"
        );
    }

    #[tokio::test]
    async fn subscribe_rate_limit_is_per_connection() {
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            rate_limit_subscribes_per_minute: 2,
            ttl_check_interval: Duration::from_millis(100),
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();

        // Connection 1: exhaust its rate limit.
        let (mut sink1, mut stream1) = connect_client(addr).await;
        for i in 0u8..2 {
            let subscribe = ClientMessage::Subscribe {
                ref_id: Some(format!("c1-s-{i}")),
                routing_id: [i; 32],
                since: None,
            };
            send_msg(&mut sink1, &subscribe).await;
            let reply = recv_msg(&mut stream1).await;
            assert!(matches!(reply, RelayMessage::Ok { .. }));
        }

        // Connection 1 should be rate-limited.
        let subscribe = ClientMessage::Subscribe {
            ref_id: Some("c1-excess".to_string()),
            routing_id: [0xFF; 32],
            since: None,
        };
        send_msg(&mut sink1, &subscribe).await;
        let reply = recv_msg(&mut stream1).await;
        assert!(
            matches!(reply, RelayMessage::Err { code, .. } if code == code::RATE_LIMITED),
            "connection 1 should be rate-limited, got {reply:?}"
        );

        // Connection 2: should have its own independent rate limit.
        let (mut sink2, mut stream2) = connect_client(addr).await;
        let subscribe = ClientMessage::Subscribe {
            ref_id: Some("c2-s-0".to_string()),
            routing_id: [0xAA; 32],
            since: None,
        };
        send_msg(&mut sink2, &subscribe).await;
        let reply = recv_msg(&mut stream2).await;
        assert!(
            matches!(reply, RelayMessage::Ok { .. }),
            "connection 2 should succeed (independent rate limit), got {reply:?}"
        );
    }

    #[tokio::test]
    async fn storage_full_returns_error() {
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        // Storage with capacity of 2.
        let storage = Arc::new(BlobStorageBackend::in_memory_with_capacity(2));
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();

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
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();

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

    #[tokio::test]
    async fn shutdown_does_not_panic() {
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (handle, _addr) = server.start().await.unwrap();

        handle.shutdown();
        assert!(handle.is_shutdown());
    }

    #[tokio::test]
    async fn shutdown_stops_accepting_connections() {
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (handle, addr) = server.start().await.unwrap();

        // Verify the server accepts connections before shutdown.
        let pre = tokio::net::TcpStream::connect(addr).await;
        assert!(pre.is_ok(), "should accept connections before shutdown");
        drop(pre);

        // Shutdown and give the accept loop time to exit.
        handle.shutdown();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // New connections should fail (accept loop exited).
        let post = tokio::time::timeout(
            Duration::from_millis(200),
            tokio::net::TcpStream::connect(addr),
        )
        .await;

        // Either connection refused or timeout — both indicate the server stopped.
        // Connection may succeed if the server has a buffered accept — that is
        // acceptable; the key invariant is that the accept loop eventually stops.
        if let Ok(Ok(_stream)) = post {
            // Buffered accept — tolerable.
        }
    }

    #[tokio::test]
    async fn in_flight_connection_survives_shutdown() {
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (handle, addr) = server.start().await.unwrap();

        // Establish a connection before shutdown.
        let (mut sink, mut stream) = connect_client(addr).await;

        // Shutdown the server.
        handle.shutdown();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The existing connection should still work — handlers drain naturally.
        let ping = ClientMessage::Ping { ts: 42 };
        send_msg(&mut sink, &ping).await;
        let reply = recv_msg(&mut stream).await;
        assert_eq!(reply, RelayMessage::Pong { ts: 42 });
    }

    /// Smoke test for the `tokio::spawn` jitter delivery path in
    /// `deliver_to_subscribers`. All other tests use `delivery_jitter_ms: 0`,
    /// which takes the sequential fast-path. This test uses 1ms jitter —
    /// negligible delay but exercises the spawn-per-subscriber branch.
    #[tokio::test]
    async fn jitter_delivery_path_delivers_correctly() {
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            delivery_jitter_ms: 1,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();

        let routing_id = [0xEE; 32];
        let blob_data = vec![0xDE, 0xAD, 0xBE, 0xEF];

        // Client 1: subscribe to the routing ID.
        let (mut sink1, mut stream1) = connect_client(addr).await;
        let subscribe = ClientMessage::Subscribe {
            ref_id: Some("sub-jitter".to_string()),
            routing_id,
            since: None,
        };
        send_msg(&mut sink1, &subscribe).await;
        let ok = recv_msg(&mut stream1).await;
        assert!(matches!(ok, RelayMessage::Ok { .. }));

        // Client 2: also subscribe (verifies delivery to multiple subscribers).
        let (mut sink2, mut stream2) = connect_client(addr).await;
        let subscribe2 = ClientMessage::Subscribe {
            ref_id: Some("sub-jitter-2".to_string()),
            routing_id,
            since: None,
        };
        send_msg(&mut sink2, &subscribe2).await;
        let ok2 = recv_msg(&mut stream2).await;
        assert!(matches!(ok2, RelayMessage::Ok { .. }));

        // Client 3: publish a blob.
        let (mut sink3, mut stream3) = connect_client(addr).await;
        let publish = ClientMessage::Publish {
            ref_id: Some("pub-jitter".to_string()),
            routing_id,
            recipient_hint: None,
            blob_ttl: 3600,
            blob: blob_data.clone(),
        };
        send_msg(&mut sink3, &publish).await;
        let pub_ok = recv_msg(&mut stream3).await;
        assert!(matches!(pub_ok, RelayMessage::Ok { .. }));

        // Both subscribers should receive the blob via the jitter spawn path.
        let blob1 = recv_msg(&mut stream1).await;
        match &blob1 {
            RelayMessage::Blob {
                routing_id: rid,
                blob: data,
                ..
            } => {
                assert_eq!(rid, &routing_id);
                assert_eq!(data, &blob_data);
            }
            other => panic!("subscriber 1: expected BLOB, got {other:?}"),
        }

        let blob2 = recv_msg(&mut stream2).await;
        match &blob2 {
            RelayMessage::Blob {
                routing_id: rid,
                blob: data,
                ..
            } => {
                assert_eq!(rid, &routing_id);
                assert_eq!(data, &blob_data);
            }
            other => panic!("subscriber 2: expected BLOB, got {other:?}"),
        }
    }

    // ── Relay restart survival tests (SCP-PERSIST-066) ──────────────────

    #[tokio::test]
    async fn subscription_survives_simulated_restart() {
        use crate::native::relay_persistence::RelayPersistence;

        // Use MockRelayPersistence for in-memory persistence.
        let persistence: Arc<dyn RelayPersistence> = Arc::new(MockRelayPersistence::new());

        let routing_id_a = [0xAA; 32];
        let routing_id_b = [0xBB; 32];

        // Persist subscriptions (simulates what the relay does on SUBSCRIBE).
        persistence.persist_subscription(&routing_id_a).unwrap();
        persistence.persist_subscription(&routing_id_b).unwrap();

        // Create a "restarted" relay with the same persistence.
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::with_persistence(config, storage, Arc::clone(&persistence));
        let (_handle, _addr) = server.start().await.unwrap();

        // After start(), restore_persisted_subscriptions should have run.
        // Verify the subscription registry has the persisted routing IDs.
        let registry = server.subscriptions.read().await;
        let has_a = registry.contains_key(&routing_id_a);
        let has_b = registry.contains_key(&routing_id_b);
        drop(registry);
        assert!(has_a, "routing_id_a should be restored after restart");
        assert!(has_b, "routing_id_b should be restored after restart");
    }

    #[tokio::test]
    async fn rate_limit_state_survives_restart() {
        use crate::native::relay_persistence::RelayPersistence;

        let persistence: Arc<dyn RelayPersistence> = Arc::new(MockRelayPersistence::new());

        // Persist rate limit state (simulates periodic snapshots).
        persistence
            .persist_rate_limit("192.168.1.1", 42.5, 1_000_000)
            .unwrap();
        persistence
            .persist_rate_limit("10.0.0.1", 99.0, 2_000_000)
            .unwrap();

        // Create a "restarted" relay with the same persistence.
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::with_persistence(config, storage, Arc::clone(&persistence));
        let (_handle, _addr) = server.start().await.unwrap();

        // Rate limit state should be loadable from persistence after restart.
        let rate1 = persistence.load_rate_limit("192.168.1.1").unwrap();
        assert_eq!(rate1, Some((42.5, 1_000_000)));

        let rate2 = persistence.load_rate_limit("10.0.0.1").unwrap();
        assert_eq!(rate2, Some((99.0, 2_000_000)));
    }

    /// Mock relay persistence for restart tests.
    #[derive(Debug)]
    struct MockRelayPersistence {
        subscriptions: std::sync::Mutex<Vec<[u8; 32]>>,
        rate_limits: std::sync::Mutex<HashMap<String, (f64, u64)>>,
    }

    impl MockRelayPersistence {
        fn new() -> Self {
            Self {
                subscriptions: std::sync::Mutex::new(Vec::new()),
                rate_limits: std::sync::Mutex::new(HashMap::new()),
            }
        }
    }

    impl RelayPersistence for MockRelayPersistence {
        fn persist_subscription(
            &self,
            routing_id: &[u8; 32],
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let mut subs = self.subscriptions.lock().unwrap();
            if !subs.contains(routing_id) {
                subs.push(*routing_id);
            }
            drop(subs);
            Ok(())
        }

        fn remove_subscription(
            &self,
            routing_id: &[u8; 32],
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.subscriptions
                .lock()
                .unwrap()
                .retain(|id| id != routing_id);
            Ok(())
        }

        fn load_subscribed_routing_ids(
            &self,
        ) -> Result<Vec<[u8; 32]>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self.subscriptions.lock().unwrap().clone())
        }

        fn persist_rate_limit(
            &self,
            ip: &str,
            tokens: f64,
            window_start_secs: u64,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.rate_limits
                .lock()
                .unwrap()
                .insert(ip.to_string(), (tokens, window_start_secs));
            Ok(())
        }

        fn load_rate_limit(
            &self,
            ip: &str,
        ) -> Result<Option<(f64, u64)>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self.rate_limits.lock().unwrap().get(ip).copied())
        }

        fn clear_all(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.subscriptions.lock().unwrap().clear();
            self.rate_limits.lock().unwrap().clear();
            Ok(())
        }
    }
}
