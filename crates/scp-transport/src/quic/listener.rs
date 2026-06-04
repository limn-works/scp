//! Relay-side QUIC listener for SCP.
//!
//! Accepts QUIC connections alongside the existing WebSocket transport using
//! ALPN negotiation. Per-stream operations (PUBLISH, SUBSCRIBE, QUERY, DELETE)
//! are dispatched to shared relay logic. The subscription registry and blob
//! storage backend are shared between WebSocket and QUIC handlers -- a
//! subscription created via QUIC is visible to WebSocket queries and vice
//! versa.
//!
//! # QUIC stream model
//!
//! Each SCP operation maps to a QUIC bidirectional stream:
//!
//! | Operation   | Lifecycle                                                     |
//! |-------------|---------------------------------------------------------------|
//! | PUBLISH     | Open stream -> send PUBLISH -> receive OK/ERR -> close        |
//! | SUBSCRIBE   | Open stream -> send SUBSCRIBE -> receive BLOBs until close    |
//! | QUERY       | Open stream -> send QUERY -> receive BLOBs + EVENT -> close   |
//! | DELETE      | Open stream -> send DELETE -> receive OK/ERR -> close          |
//!
//! Responses are scoped to their stream, so `ref_id` is unnecessary (though
//! it MAY still be included for logging/debugging per section 10.14.1).
//!
//! # ALPN
//!
//! The QUIC listener uses ALPN protocol identifier `scp/1` to distinguish
//! SCP QUIC connections from other protocols on the same port.
//!
//! # Shared state
//!
//! The QUIC listener shares the same `SubscriptionRegistry` and `BlobStorage`
//! backend as the WebSocket server. This is achieved by accepting `Arc`-wrapped
//! instances of both at construction time.
//!
//! See:
//! - Section 10.14.3 in `.docs/specs/10-infrastructure-and-self-hosting.md`
//! - ADR-037 in `.docs/adrs/phase-2.md`
//! - SCP-257 in `.docs/prds/transport-expansion.json`

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use quinn::{Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::{RwLock, mpsc};
use tokio_util::sync::CancellationToken;

use crate::native::error::code;
use crate::native::protocol::{
    ClientMessage, DEFAULT_QUERY_LIMIT, MAX_BLOB_SIZE, MAX_BLOB_TTL, MAX_QUERY_LIMIT, MIN_BLOB_TTL,
    RelayMessage,
};
use crate::native::storage::BlobStorage;
use crate::relay::rate_limit::{self, ConnectionTracker, PublishRateLimiter, SubscribeRateLimiter};
use crate::relay::subscription::{self, SubscriptionRegistry};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// ALPN protocol identifier for SCP over QUIC.
pub const SCP_ALPN: &[u8] = b"scp/1";

/// Default maximum concurrent QUIC connections from a single IP address.
const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 10;

/// Default maximum total concurrent QUIC connections across all IPs.
const DEFAULT_MAX_TOTAL_CONNECTIONS: usize = 1000;

/// Default maximum subscriptions per QUIC connection.
const DEFAULT_MAX_SUBSCRIPTIONS_PER_CONNECTION: usize = 100;

/// Default maximum PUBLISH operations per second per IP address.
const DEFAULT_RATE_LIMIT_PUBLISHES_PER_SECOND: u32 = 100;

/// Default maximum random delivery jitter in milliseconds.
const DEFAULT_DELIVERY_JITTER_MS: u64 = 50;

/// Default maximum SUBSCRIBE operations per minute per connection.
const DEFAULT_RATE_LIMIT_SUBSCRIBES_PER_MINUTE: u32 = 20;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the relay-side QUIC listener.
///
/// All fields have sensible defaults matching the WebSocket relay's
/// [`RelayConfig`](crate::native::server::RelayConfig) counterparts.
#[derive(Debug, Clone)]
pub struct QuicListenerConfig {
    /// Address to bind the QUIC listener to (UDP).
    pub bind_addr: SocketAddr,
    /// Maximum blob size in bytes (default: 262144 / 256 KB).
    pub max_blob_size: usize,
    /// Maximum blob TTL in seconds (default: 604800 / 7 days).
    pub max_blob_ttl: u32,
    /// Maximum concurrent subscriptions per QUIC connection (default: 100).
    pub max_subscriptions_per_connection: usize,
    /// Maximum QUERY limit (default: 1000).
    pub max_query_limit: u32,
    /// Maximum concurrent QUIC connections from a single IP address (default: 10).
    pub max_connections_per_ip: usize,
    /// Maximum total concurrent QUIC connections across all IPs (default: 1000).
    pub max_total_connections: usize,
    /// Maximum PUBLISH operations per second per IP address (default: 100).
    pub rate_limit_publishes_per_second: u32,
    /// Maximum SUBSCRIBE operations per minute per connection (default: 20).
    pub rate_limit_subscribes_per_minute: u32,
    /// Maximum random delivery jitter in milliseconds (default: 50ms).
    ///
    /// When non-zero, the relay adds a uniformly random delay before
    /// forwarding each stored blob to subscribers (BLACK-001 mitigation).
    /// Set to 0 to disable jitter (useful for tests).
    pub delivery_jitter_ms: u64,
}

impl Default for QuicListenerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 9443)),
            max_blob_size: MAX_BLOB_SIZE,
            max_blob_ttl: MAX_BLOB_TTL,
            max_subscriptions_per_connection: DEFAULT_MAX_SUBSCRIPTIONS_PER_CONNECTION,
            max_query_limit: MAX_QUERY_LIMIT,
            max_connections_per_ip: DEFAULT_MAX_CONNECTIONS_PER_IP,
            max_total_connections: DEFAULT_MAX_TOTAL_CONNECTIONS,
            rate_limit_publishes_per_second: DEFAULT_RATE_LIMIT_PUBLISHES_PER_SECOND,
            rate_limit_subscribes_per_minute: DEFAULT_RATE_LIMIT_SUBSCRIBES_PER_MINUTE,
            delivery_jitter_ms: DEFAULT_DELIVERY_JITTER_MS,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during QUIC listener operation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum QuicListenerError {
    /// The listener could not bind to the configured address.
    #[error("bind failed: {0}")]
    BindFailed(String),

    /// TLS configuration error.
    #[error("TLS configuration error: {0}")]
    TlsError(String),

    /// The listener could not accept a connection.
    #[error("accept failed: {0}")]
    AcceptFailed(String),
}

// ---------------------------------------------------------------------------
// QuicListener
// ---------------------------------------------------------------------------

/// Handle for gracefully shutting down a running QUIC listener.
///
/// Dropping the handle does **not** shut down the listener. Call
/// [`shutdown`](Self::shutdown) explicitly.
#[derive(Debug, Clone)]
pub struct QuicShutdownHandle {
    token: CancellationToken,
}

impl QuicShutdownHandle {
    /// Signals the QUIC listener to stop accepting new connections.
    pub fn shutdown(&self) {
        self.token.cancel();
    }

    /// Returns `true` if shutdown has been signaled.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.token.is_cancelled()
    }
}

/// Relay-side QUIC listener that accepts QUIC connections alongside WebSocket.
///
/// The listener accepts QUIC connections using ALPN negotiation with the
/// `scp/1` protocol identifier. Each incoming bidirectional stream is treated
/// as a single SCP operation (PUBLISH, SUBSCRIBE, QUERY, or DELETE). The
/// subscription registry and blob storage are shared with the WebSocket
/// server.
///
/// # Type parameter
///
/// `S` is the blob storage backend, shared with the WebSocket relay server.
pub struct QuicListener<S: BlobStorage> {
    config: QuicListenerConfig,
    storage: Arc<S>,
    subscriptions: SubscriptionRegistry,
    connection_tracker: ConnectionTracker,
    publish_rate_limiter: PublishRateLimiter,
}

impl<S: BlobStorage + 'static> QuicListener<S> {
    /// Creates a new QUIC listener with the given configuration and shared state.
    ///
    /// The `storage`, `subscriptions`, `publish_rate_limiter`, and
    /// `connection_tracker` are shared with the WebSocket relay server and
    /// UDP/DTLS listener, enabling cross-transport message delivery and
    /// unified rate limiting (ADR-037 AC3, spec §10.14.3).
    #[must_use]
    pub const fn new(
        config: QuicListenerConfig,
        storage: Arc<S>,
        subscriptions: SubscriptionRegistry,
        publish_rate_limiter: PublishRateLimiter,
        connection_tracker: ConnectionTracker,
    ) -> Self {
        Self {
            config,
            storage,
            subscriptions,
            connection_tracker,
            publish_rate_limiter,
        }
    }

    /// Starts the QUIC listener and returns a shutdown handle and bound address.
    ///
    /// The listener is spawned in a background tokio task. Use the returned
    /// [`QuicShutdownHandle`] to gracefully stop the listener.
    ///
    /// # Arguments
    ///
    /// * `server_config` -- A pre-configured [`quinn::ServerConfig`] with TLS
    ///   certificates and ALPN set. Use [`build_server_config`] to create one
    ///   from DER-encoded certificates and keys.
    ///
    /// # Errors
    ///
    /// Returns [`QuicListenerError::BindFailed`] if the listener cannot bind
    /// to the configured UDP address.
    pub fn start(
        &self,
        server_config: ServerConfig,
    ) -> Result<(QuicShutdownHandle, SocketAddr), QuicListenerError> {
        let endpoint = Endpoint::server(server_config, self.config.bind_addr)
            .map_err(|e| QuicListenerError::BindFailed(e.to_string()))?;

        let local_addr = endpoint
            .local_addr()
            .map_err(|e| QuicListenerError::BindFailed(e.to_string()))?;

        let token = CancellationToken::new();
        let accept_token = token.clone();
        let cleanup_token = token.clone();

        let storage = Arc::clone(&self.storage);
        let subscriptions = Arc::clone(&self.subscriptions);
        let config = self.config.clone();
        let conn_tracker = Arc::clone(&self.connection_tracker);
        let rate_limiter = self.publish_rate_limiter.clone();

        tokio::spawn(async move {
            accept_loop(
                endpoint,
                accept_token,
                storage,
                subscriptions,
                config,
                conn_tracker,
                rate_limiter,
            )
            .await;
        });

        // Periodic cleanup of stale rate-limiter buckets (shared across transports).
        let cleanup_rate_limiter = self.publish_rate_limiter.clone();
        tokio::spawn(async move {
            cleanup_rate_limiter
                .cleanup_loop(
                    Duration::from_mins(1),
                    Duration::from_secs(90),
                    cleanup_token,
                )
                .await;
        });

        Ok((QuicShutdownHandle { token }, local_addr))
    }
}

/// Builds a [`quinn::ServerConfig`] from DER-encoded certificates and private key.
///
/// Configures ALPN with [`SCP_ALPN`] and sets transport parameters suitable
/// for SCP relay usage (keepalive, idle timeout, stream limits).
///
/// # Errors
///
/// Returns [`QuicListenerError::TlsError`] if the TLS configuration is invalid.
pub fn build_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, QuicListenerError> {
    // Pin the ring crypto provider explicitly rather than relying on the
    // process default. When a binary links both the `ring` and `aws-lc-rs`
    // rustls providers (e.g. via aws-sdk / reqwest pulling aws-lc-rs alongside
    // our ring backend), `ServerConfig::builder()` has no unambiguous default
    // and panics. SCP is ring-only, so name the provider directly.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| QuicListenerError::TlsError(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| QuicListenerError::TlsError(e.to_string()))?;

    tls_config.alpn_protocols = vec![SCP_ALPN.to_vec()];

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|e| QuicListenerError::TlsError(e.to_string()))?;

    let mut transport_config = quinn::TransportConfig::default();
    // Keep connections alive with QUIC native PING frames (replaces
    // application-level PING/PONG per section 10.14.2).
    transport_config.keep_alive_interval(Some(Duration::from_secs(15)));
    // Idle timeout: connections without activity are closed after 90 seconds.
    let idle_timeout = quinn::IdleTimeout::try_from(Duration::from_secs(90))
        .map_err(|e| QuicListenerError::TlsError(format!("idle timeout: {e}")))?;
    transport_config.max_idle_timeout(Some(idle_timeout));
    // Allow enough concurrent bidirectional streams for heavy usage.
    transport_config.max_concurrent_bidi_streams(256u32.into());

    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
    server_config.transport_config(Arc::new(transport_config));

    Ok(server_config)
}

/// Generates a self-signed certificate and builds a [`quinn::ServerConfig`].
///
/// Intended for development and testing. Production deployments should use
/// properly issued certificates via [`build_server_config`].
///
/// # Errors
///
/// Returns [`QuicListenerError::TlsError`] if certificate generation fails.
pub fn build_self_signed_server_config() -> Result<ServerConfig, QuicListenerError> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| QuicListenerError::TlsError(e.to_string()))?;

    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    build_server_config(vec![cert_der], PrivateKeyDer::Pkcs8(key_der))
}

// ---------------------------------------------------------------------------
// Accept loop
// ---------------------------------------------------------------------------

/// Main accept loop for the QUIC listener.
#[allow(clippy::too_many_arguments)]
async fn accept_loop<S: BlobStorage + 'static>(
    endpoint: Endpoint,
    cancel: CancellationToken,
    storage: Arc<S>,
    subscriptions: SubscriptionRegistry,
    config: QuicListenerConfig,
    conn_tracker: ConnectionTracker,
    rate_limiter: PublishRateLimiter,
) {
    loop {
        let incoming = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                // Graceful shutdown: close the endpoint so no new connections
                // are accepted. In-flight handlers drain naturally.
                endpoint.close(0u32.into(), b"shutdown");
                break;
            }
            incoming = endpoint.accept() => incoming,
        };

        let Some(incoming) = incoming else {
            // Endpoint is closed.
            break;
        };

        let remote_addr = incoming.remote_address();
        let ip = remote_addr.ip();

        // Enforce connection limits and register in one atomic write-lock
        // block to eliminate the TOCTOU window between the check and the
        // increment that existed when separate read and write locks were used.
        let accept = {
            let mut tracker = conn_tracker.write().await;
            let total: usize = tracker.values().sum();
            if total >= config.max_total_connections {
                tracing::warn!(
                    ip = %ip,
                    total_connections = total,
                    limit = config.max_total_connections,
                    "QUIC: rejecting connection — max total connections reached"
                );
                false
            } else {
                let ip_count = tracker.get(&ip).copied().unwrap_or(0);
                if ip_count >= config.max_connections_per_ip {
                    tracing::warn!(
                        ip = %ip,
                        ip_connections = ip_count,
                        limit = config.max_connections_per_ip,
                        "QUIC: rejecting connection — max connections per IP reached"
                    );
                    false
                } else {
                    *tracker.entry(ip).or_insert(0) += 1;
                    true
                }
            }
        };

        if !accept {
            incoming.refuse();
            continue;
        }

        let conn_id = subscription::next_owner_id();
        let storage = Arc::clone(&storage);
        let subscriptions = Arc::clone(&subscriptions);
        let config = config.clone();
        let conn_tracker = Arc::clone(&conn_tracker);
        let rate_limiter = rate_limiter.clone();

        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    handle_connection(
                        connection,
                        conn_id,
                        ip,
                        storage,
                        subscriptions,
                        config,
                        rate_limiter,
                    )
                    .await;
                }
                Err(e) => {
                    tracing::debug!(
                        ip = %ip,
                        error = %e,
                        "QUIC: connection handshake failed"
                    );
                }
            }
            // Decrement connection count on disconnect.
            rate_limit::unregister_connection(&conn_tracker, ip).await;
        });
    }
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

/// Handles a single QUIC connection, accepting bidirectional streams.
///
/// Each stream is a single SCP operation. The connection handler spawns a
/// new task per stream. SUBSCRIBE streams are long-lived; all others are
/// short-lived (open -> exchange -> close).
#[allow(clippy::too_many_arguments)]
async fn handle_connection<S: BlobStorage + 'static>(
    connection: quinn::Connection,
    connection_id: u64,
    ip: IpAddr,
    storage: Arc<S>,
    subscriptions: SubscriptionRegistry,
    config: QuicListenerConfig,
    rate_limiter: PublishRateLimiter,
) {
    // Track this connection's subscriptions for cleanup on disconnect.
    let my_subscriptions: Arc<RwLock<HashSet<[u8; 32]>>> = Arc::new(RwLock::new(HashSet::new()));
    let subscribe_rate_limiter = Arc::new(tokio::sync::Mutex::new(SubscribeRateLimiter::new(
        config.rate_limit_subscribes_per_minute,
    )));

    loop {
        let stream = match connection.accept_bi().await {
            Ok(stream) => stream,
            Err(
                quinn::ConnectionError::ApplicationClosed(_)
                | quinn::ConnectionError::LocallyClosed,
            ) => break,
            Err(e) => {
                tracing::debug!(
                    connection_id = connection_id,
                    error = %e,
                    "QUIC: connection error while accepting stream"
                );
                break;
            }
        };

        let storage = Arc::clone(&storage);
        let subscriptions = Arc::clone(&subscriptions);
        let config = config.clone();
        let rate_limiter = rate_limiter.clone();
        let my_subs = Arc::clone(&my_subscriptions);
        let sub_rate_limiter = Arc::clone(&subscribe_rate_limiter);

        tokio::spawn(async move {
            if let Err(e) = handle_stream(
                stream,
                connection_id,
                ip,
                storage,
                subscriptions,
                my_subs,
                config,
                rate_limiter,
                sub_rate_limiter,
            )
            .await
            {
                tracing::debug!(
                    connection_id = connection_id,
                    error = %e,
                    "QUIC: stream handler error"
                );
            }
        });
    }

    // Cleanup: remove this connection's subscriptions from the registry.
    let routing_ids: Vec<[u8; 32]> = {
        let my_subs = my_subscriptions.read().await;
        my_subs.iter().copied().collect()
    };
    if !routing_ids.is_empty() {
        let mut registry = subscriptions.write().await;
        for routing_id in &routing_ids {
            if let Some(entries) = registry.get_mut(routing_id) {
                entries.retain(|e| e.owner_id != connection_id);
                if entries.is_empty() {
                    registry.remove(routing_id);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Stream handler
// ---------------------------------------------------------------------------

/// Connection-level stream error type.
#[derive(Debug, thiserror::Error)]
enum StreamError {
    #[error("read error: {0}")]
    Read(String),
    #[error("write error: {0}")]
    Write(String),
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// Maximum message size we will read from a single stream frame (1 MB).
///
/// This is generous enough to handle the largest valid PUBLISH (256 KB blob +
/// overhead) with margin. Messages larger than this are rejected.
const MAX_STREAM_MESSAGE_SIZE: usize = 1_048_576;

/// Handles a single bidirectional QUIC stream.
///
/// Reads the client message from the stream, dispatches it to the appropriate
/// handler, writes the response(s) back on the same stream, then closes.
/// SUBSCRIBE streams remain open for long-lived delivery.
#[allow(clippy::too_many_arguments)]
async fn handle_stream<S: BlobStorage + 'static>(
    (send, recv): (SendStream, RecvStream),
    connection_id: u64,
    ip: IpAddr,
    storage: Arc<S>,
    subscriptions: SubscriptionRegistry,
    my_subscriptions: Arc<RwLock<HashSet<[u8; 32]>>>,
    config: QuicListenerConfig,
    rate_limiter: PublishRateLimiter,
    subscribe_rate_limiter: Arc<tokio::sync::Mutex<SubscribeRateLimiter>>,
) -> Result<(), StreamError> {
    // Read the initial client message from the stream.
    let client_msg = read_client_message(recv).await?;

    match client_msg {
        ClientMessage::Publish {
            ref_id,
            routing_id,
            recipient_hint,
            blob_ttl,
            blob,
        } => {
            handle_publish(
                send,
                ref_id,
                routing_id,
                recipient_hint,
                blob_ttl,
                &blob,
                ip,
                &storage,
                &subscriptions,
                &config,
                &rate_limiter,
            )
            .await
        }
        ClientMessage::Subscribe {
            ref_id,
            routing_id,
            since,
        } => {
            handle_subscribe(
                send,
                ref_id,
                routing_id,
                since,
                connection_id,
                &storage,
                &subscriptions,
                &my_subscriptions,
                &config,
                &subscribe_rate_limiter,
            )
            .await
        }
        ClientMessage::Query {
            ref_id,
            routing_id,
            since,
            limit,
        } => handle_query(send, ref_id, routing_id, since, limit, &storage, &config).await,
        ClientMessage::Delete { ref_id, blob_id } => {
            handle_delete(send, ref_id, blob_id, &storage).await
        }
        ClientMessage::Ping { ts } => handle_ping(send, ts).await,
        ClientMessage::Unsubscribe { ref_id, routing_id } => {
            handle_unsubscribe(
                send,
                ref_id,
                routing_id,
                connection_id,
                &subscriptions,
                &my_subscriptions,
            )
            .await
        }
        ClientMessage::Ack { .. } => {
            // ACK is fire-and-forget. Close the stream silently.
            Ok(())
        }
        ClientMessage::BridgeRegister { ref_id, .. } | ClientMessage::BridgeData { ref_id, .. } => {
            let err = RelayMessage::Err {
                ref_id,
                code: code::BRIDGE_NOT_SUPPORTED,
                msg: "bridge operations not supported over QUIC".to_string(),
            };
            write_relay_message(&mut { send }, &err).await?;
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Stream I/O helpers
// ---------------------------------------------------------------------------

/// Reads a complete client message from a QUIC receive stream.
///
/// Uses a length-prefixed frame: 4 bytes big-endian length, then the
/// `MessagePack` payload. This is necessary because QUIC streams are byte
/// streams, not message-oriented like WebSocket frames.
async fn read_client_message(mut recv: RecvStream) -> Result<ClientMessage, StreamError> {
    // Read the 4-byte length prefix.
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| StreamError::Read(e.to_string()))?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;

    if msg_len == 0 || msg_len > MAX_STREAM_MESSAGE_SIZE {
        return Err(StreamError::Protocol(format!(
            "invalid message length: {msg_len} (max: {MAX_STREAM_MESSAGE_SIZE})"
        )));
    }

    // Read the payload.
    let mut buf = vec![0u8; msg_len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| StreamError::Read(e.to_string()))?;

    // Drop the deserializer's Display string: rmp_serde can embed excerpts of
    // the attacker-controlled malformed MessagePack bytes, which would then be
    // logged at the stream-handler error site (error = %e). Keep a static
    // description so no input bytes reach the relay's logs.
    ClientMessage::from_bytes(&buf)
        .map_err(|_| StreamError::Protocol("failed to deserialize message".to_string()))
}

/// Writes a relay message to a QUIC send stream.
///
/// Uses the same length-prefixed frame format: 4 bytes big-endian length,
/// then the `MessagePack` payload.
async fn write_relay_message(send: &mut SendStream, msg: &RelayMessage) -> Result<(), StreamError> {
    let payload = msg
        .to_bytes()
        .map_err(|e| StreamError::Write(e.to_string()))?;

    // CRYPTO-013: enforce the same frame size limit on writes as on reads
    // to prevent asymmetric behaviour where the relay sends frames larger
    // than clients are willing to accept.
    if payload.len() > MAX_STREAM_MESSAGE_SIZE {
        return Err(StreamError::Write(format!(
            "relay message exceeds maximum frame size: {} > {MAX_STREAM_MESSAGE_SIZE}",
            payload.len()
        )));
    }

    let len = u32::try_from(payload.len())
        .map_err(|_| StreamError::Write("message too large for length prefix".to_string()))?;

    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| StreamError::Write(e.to_string()))?;
    send.write_all(&payload)
        .await
        .map_err(|e| StreamError::Write(e.to_string()))?;

    Ok(())
}

/// Writes a relay message and then finishes (closes) the send stream.
async fn write_and_finish(mut send: SendStream, msg: &RelayMessage) -> Result<(), StreamError> {
    write_relay_message(&mut send, msg).await?;
    send.finish()
        .map_err(|e| StreamError::Write(e.to_string()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Operation handlers
// ---------------------------------------------------------------------------

/// Handles a PUBLISH operation on a QUIC stream.
#[allow(clippy::too_many_arguments)]
async fn handle_publish<S: BlobStorage>(
    send: SendStream,
    ref_id: Option<String>,
    routing_id: [u8; 32],
    recipient_hint: Option<[u8; 32]>,
    blob_ttl: u32,
    blob: &[u8],
    ip: IpAddr,
    storage: &Arc<S>,
    subscriptions: &SubscriptionRegistry,
    config: &QuicListenerConfig,
    rate_limiter: &PublishRateLimiter,
) -> Result<(), StreamError> {
    // Check rate limit.
    if !rate_limiter.check(ip).await {
        tracing::warn!(ip = %ip, "QUIC: publish rate limit exceeded");
        let err = RelayMessage::Err {
            ref_id,
            code: code::RATE_LIMITED,
            msg: "publish rate limit exceeded".to_string(),
        };
        return write_and_finish(send, &err).await;
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
        return write_and_finish(send, &err).await;
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
        return write_and_finish(send, &err).await;
    }

    // Compute blob_id = SHA-256(blob).
    let blob_id = *crate::traits::BlobId::from_sha256(blob).as_bytes();

    // Store the blob.
    let stored = match storage
        .store(routing_id, blob_id, recipient_hint, blob_ttl, blob.to_vec())
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, "QUIC: blob store failed");
            let err = RelayMessage::Err {
                ref_id,
                code: code::STORAGE_FULL,
                msg: "internal error".to_owned(),
            };
            return write_and_finish(send, &err).await;
        }
    };

    // Deliver to active subscribers with optional jitter (BLACK-001).
    let _failed_deliveries =
        subscription::deliver_to_subscribers(&stored, subscriptions, config.delivery_jitter_ms)
            .await;

    // Respond with OK + blob_id.
    let ok = RelayMessage::Ok {
        ref_id,
        blob_id: Some(blob_id),
    };
    write_and_finish(send, &ok).await
}

/// Handles a SUBSCRIBE operation on a QUIC stream.
///
/// The stream remains open for long-lived blob delivery. BLOBs are pushed
/// to the subscriber via the stream until the stream is closed or the
/// connection is dropped.
#[allow(clippy::too_many_arguments)]
async fn handle_subscribe<S: BlobStorage>(
    mut send: SendStream,
    ref_id: Option<String>,
    routing_id: [u8; 32],
    since: Option<u64>,
    connection_id: u64,
    storage: &Arc<S>,
    subscriptions: &SubscriptionRegistry,
    my_subscriptions: &Arc<RwLock<HashSet<[u8; 32]>>>,
    config: &QuicListenerConfig,
    subscribe_rate_limiter: &Arc<tokio::sync::Mutex<SubscribeRateLimiter>>,
) -> Result<(), StreamError> {
    // Check subscribe rate limit.
    {
        let mut limiter = subscribe_rate_limiter.lock().await;
        if !limiter.check() {
            tracing::warn!(
                connection_id = connection_id,
                "QUIC: subscribe rate limit exceeded"
            );
            let err = RelayMessage::Err {
                ref_id,
                code: code::RATE_LIMITED,
                msg: "subscribe rate limit exceeded".to_string(),
            };
            return write_and_finish(send, &err).await;
        }
    }

    // Create a channel for receiving blobs destined for this subscriber.
    let (tx, mut rx) = mpsc::channel::<RelayMessage>(256);

    // Check subscription limit and insert under a single write lock to
    // prevent TOCTOU between limit check and insertion.
    {
        let mut my_subs = my_subscriptions.write().await;
        if my_subs.len() >= config.max_subscriptions_per_connection {
            let err = RelayMessage::Err {
                ref_id,
                code: code::TOO_MANY_SUBSCRIPTIONS,
                msg: format!(
                    "maximum {} subscriptions per connection",
                    config.max_subscriptions_per_connection
                ),
            };
            return write_and_finish(send, &err).await;
        }
        my_subs.insert(routing_id);
    }

    // Register the subscription in the shared registry (SEC-006: enforces
    // global + per-routing-ID limits).
    if let Err(reason) =
        subscription::register_subscriber(subscriptions, routing_id, connection_id, tx.clone())
            .await
    {
        // Undo the my_subscriptions insertion.
        let mut my_subs = my_subscriptions.write().await;
        my_subs.remove(&routing_id);
        drop(my_subs);

        tracing::warn!(
            connection_id,
            routing_id = ?routing_id,
            reason = %reason,
            "subscription registry capacity exceeded"
        );
        let err = RelayMessage::Err {
            ref_id,
            code: code::TOO_MANY_SUBSCRIPTIONS,
            msg: reason,
        };
        return write_and_finish(send, &err).await;
    }

    // Send OK response.
    let ok = RelayMessage::Ok {
        ref_id: ref_id.clone(),
        blob_id: None,
    };
    write_relay_message(&mut send, &ok).await?;

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
                write_relay_message(&mut send, &blob_msg).await?;
            }
        }

        // Emit backfill_complete event.
        let event = RelayMessage::Event {
            ref_id,
            event_type: "backfill_complete".to_string(),
        };
        write_relay_message(&mut send, &event).await?;
    }

    // Long-lived delivery loop: forward blobs from the channel to the stream.
    while let Some(msg) = rx.recv().await {
        if write_relay_message(&mut send, &msg).await.is_err() {
            break;
        }
    }

    // Stream closed -- cleanup is handled at the connection level when the
    // connection handler detects the close and removes subscriptions.
    Ok(())
}

/// Handles an UNSUBSCRIBE operation on a QUIC stream.
async fn handle_unsubscribe(
    send: SendStream,
    ref_id: Option<String>,
    routing_id: [u8; 32],
    connection_id: u64,
    subscriptions: &SubscriptionRegistry,
    my_subscriptions: &Arc<RwLock<HashSet<[u8; 32]>>>,
) -> Result<(), StreamError> {
    // Remove from the registry.
    {
        let mut registry = subscriptions.write().await;
        if let Some(entries) = registry.get_mut(&routing_id) {
            entries.retain(|e| e.owner_id != connection_id);
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
    write_and_finish(send, &ok).await
}

/// Handles a QUERY operation on a QUIC stream.
async fn handle_query<S: BlobStorage>(
    mut send: SendStream,
    ref_id: Option<String>,
    routing_id: [u8; 32],
    since: Option<u64>,
    limit: Option<u32>,
    storage: &Arc<S>,
    config: &QuicListenerConfig,
) -> Result<(), StreamError> {
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
        return write_and_finish(send, &err).await;
    }

    let blobs = match storage.query(&routing_id, since, effective_limit).await {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(error = %e, "QUIC: blob query failed");
            let err = RelayMessage::Err {
                ref_id,
                code: code::INTERNAL_ERROR,
                msg: "internal error".to_owned(),
            };
            return write_and_finish(send, &err).await;
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
        write_relay_message(&mut send, &blob_msg).await?;
    }

    // Emit query_complete event.
    let event = RelayMessage::Event {
        ref_id,
        event_type: "query_complete".to_string(),
    };
    write_and_finish(send, &event).await
}

/// Handles a DELETE operation on a QUIC stream.
async fn handle_delete<S: BlobStorage>(
    send: SendStream,
    ref_id: Option<String>,
    blob_id: [u8; 32],
    storage: &Arc<S>,
) -> Result<(), StreamError> {
    // Best-effort deletion.
    let _ = storage.delete(&blob_id).await;

    let ok = RelayMessage::Ok {
        ref_id,
        blob_id: None,
    };
    write_and_finish(send, &ok).await
}

/// Handles a PING on a QUIC stream. Returns PONG and closes.
///
/// Note: QUIC has native keepalive so application-level PING/PONG is not
/// required (section 10.14.2). This handler exists for protocol completeness.
async fn handle_ping(send: SendStream, ts: u64) -> Result<(), StreamError> {
    let pong = RelayMessage::Pong { ts };
    write_and_finish(send, &pong).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
    use quinn::ClientConfig;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    /// Helper: build a self-signed server config for testing.
    fn test_server_config() -> (ServerConfig, Vec<CertificateDer<'static>>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert);
        let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let server_config =
            build_server_config(vec![cert_der.clone()], PrivateKeyDer::Pkcs8(key_der)).unwrap();
        (server_config, vec![cert_der])
    }

    /// Helper: build a quinn client config that trusts the test server cert.
    fn test_client_config(server_certs: &[CertificateDer<'static>]) -> ClientConfig {
        let mut root_store = rustls::RootCertStore::empty();
        for cert in server_certs {
            root_store.add(cert.clone()).unwrap();
        }

        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        tls_config.alpn_protocols = vec![SCP_ALPN.to_vec()];

        let quic_client_config =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).unwrap();
        ClientConfig::new(Arc::new(quic_client_config))
    }

    /// Helper: start a test QUIC listener and return the address and certs.
    fn start_test_listener() -> (
        QuicShutdownHandle,
        SocketAddr,
        Vec<CertificateDer<'static>>,
        Arc<InMemoryBlobStorage>,
        SubscriptionRegistry,
    ) {
        let (server_config, certs) = test_server_config();
        let storage = Arc::new(InMemoryBlobStorage::new());
        let subscriptions = subscription::new_registry();
        let publish_rate_limiter = PublishRateLimiter::new(100);
        let connection_tracker = rate_limit::new_connection_tracker();

        let config = QuicListenerConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            delivery_jitter_ms: 0,
            ..QuicListenerConfig::default()
        };

        let listener = QuicListener::new(
            config,
            Arc::clone(&storage),
            Arc::clone(&subscriptions),
            publish_rate_limiter,
            connection_tracker,
        );
        let (handle, addr) = listener.start(server_config).unwrap();

        (handle, addr, certs, storage, subscriptions)
    }

    /// Helper: connect a QUIC client to the test listener.
    async fn connect_client(
        addr: SocketAddr,
        certs: &[CertificateDer<'static>],
    ) -> quinn::Connection {
        let client_config = test_client_config(certs);
        let mut endpoint = Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        endpoint.set_default_client_config(client_config);

        endpoint.connect(addr, "localhost").unwrap().await.unwrap()
    }

    /// Helper: send a client message on a QUIC stream and read the response.
    async fn send_and_recv(
        connection: &quinn::Connection,
        msg: &ClientMessage,
    ) -> Vec<RelayMessage> {
        let (mut send, recv) = connection.open_bi().await.unwrap();

        let payload = msg.to_bytes().unwrap();
        let len = u32::try_from(payload.len()).unwrap();
        send.write_all(&len.to_be_bytes()).await.unwrap();
        send.write_all(&payload).await.unwrap();
        send.finish().unwrap();

        read_all_responses(recv).await
    }

    /// Helper: read all length-prefixed messages from a receive stream.
    async fn read_all_responses(mut recv: quinn::RecvStream) -> Vec<RelayMessage> {
        let mut messages = Vec::new();
        loop {
            let mut len_buf = [0u8; 4];
            match recv.read_exact(&mut len_buf).await {
                Ok(()) => {}
                Err(_) => break,
            }
            let msg_len = u32::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; msg_len];
            if recv.read_exact(&mut buf).await.is_err() {
                break;
            }
            match RelayMessage::from_bytes(&buf) {
                Ok(msg) => messages.push(msg),
                Err(_) => break,
            }
        }
        messages
    }

    // -----------------------------------------------------------------------
    // Unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn quic_listener_config_default_values() {
        let config = QuicListenerConfig::default();
        assert_eq!(config.bind_addr, SocketAddr::from(([127, 0, 0, 1], 9443)));
        assert_eq!(config.max_blob_size, MAX_BLOB_SIZE);
        assert_eq!(config.max_blob_ttl, MAX_BLOB_TTL);
        assert_eq!(config.max_subscriptions_per_connection, 100);
        assert_eq!(config.max_query_limit, MAX_QUERY_LIMIT);
        assert_eq!(config.max_connections_per_ip, 10);
        assert_eq!(config.max_total_connections, 1000);
        assert_eq!(config.rate_limit_publishes_per_second, 100);
        assert_eq!(config.rate_limit_subscribes_per_minute, 20);
        assert_eq!(config.delivery_jitter_ms, 50);
    }

    #[test]
    fn alpn_protocol_identifier() {
        assert_eq!(SCP_ALPN, b"scp/1");
    }

    #[test]
    fn quic_listener_error_display() {
        let err = QuicListenerError::BindFailed("address in use".to_string());
        assert_eq!(err.to_string(), "bind failed: address in use");

        let err = QuicListenerError::TlsError("bad cert".to_string());
        assert_eq!(err.to_string(), "TLS configuration error: bad cert");

        let err = QuicListenerError::AcceptFailed("timeout".to_string());
        assert_eq!(err.to_string(), "accept failed: timeout");
    }

    #[test]
    fn subscribe_rate_limiter_allows_initial_burst() {
        let mut limiter = SubscribeRateLimiter::new(20);
        // Should allow at least 20 operations initially (full capacity).
        for _ in 0..20 {
            assert!(limiter.check(), "should allow up to capacity");
        }
        // 21st should be rate-limited.
        assert!(!limiter.check(), "should rate-limit beyond capacity");
    }

    #[test]
    fn shutdown_handle_semantics() {
        let token = CancellationToken::new();
        let handle = QuicShutdownHandle { token };
        assert!(!handle.is_shutdown());
        handle.shutdown();
        assert!(handle.is_shutdown());
    }

    #[test]
    fn build_self_signed_server_config_succeeds() {
        let result = build_self_signed_server_config();
        assert!(result.is_ok(), "self-signed config should succeed");
    }

    // -----------------------------------------------------------------------
    // Integration tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn quic_listener_starts_and_accepts_connection() {
        let (handle, addr, certs, _storage, _subs) = start_test_listener();

        let connection = connect_client(addr, &certs).await;
        assert_eq!(connection.remote_address(), addr);

        connection.close(0u32.into(), b"done");
        handle.shutdown();
    }

    #[tokio::test]
    async fn quic_publish_and_ok_response() {
        let (handle, addr, certs, _storage, _subs) = start_test_listener();
        let connection = connect_client(addr, &certs).await;

        let routing_id = [1u8; 32];
        let blob = vec![42u8; 100];
        let msg = ClientMessage::Publish {
            ref_id: Some("test-1".to_string()),
            routing_id,
            recipient_hint: None,
            blob_ttl: 3600,
            blob: blob.clone(),
        };

        let responses = send_and_recv(&connection, &msg).await;
        assert_eq!(responses.len(), 1);
        match &responses[0] {
            RelayMessage::Ok { ref_id, blob_id } => {
                assert_eq!(ref_id.as_deref(), Some("test-1"));
                assert!(blob_id.is_some(), "PUBLISH OK should include blob_id");
                // Verify blob_id is SHA-256 of the blob.
                let expected_id = {
                    let mut hasher = Sha256::new();
                    hasher.update(&blob);
                    let hash = hasher.finalize();
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&hash);
                    id
                };
                assert_eq!(blob_id.unwrap(), expected_id);
            }
            other => panic!("expected OK, got {other:?}"),
        }

        connection.close(0u32.into(), b"done");
        handle.shutdown();
    }

    #[tokio::test]
    async fn quic_query_returns_published_blobs() {
        let (handle, addr, certs, _storage, _subs) = start_test_listener();
        let connection = connect_client(addr, &certs).await;

        let routing_id = [2u8; 32];

        // Publish a blob.
        let publish = ClientMessage::Publish {
            ref_id: None,
            routing_id,
            recipient_hint: None,
            blob_ttl: 3600,
            blob: vec![99u8; 50],
        };
        let _ = send_and_recv(&connection, &publish).await;

        // Query for it.
        let query = ClientMessage::Query {
            ref_id: Some("q-1".to_string()),
            routing_id,
            since: None,
            limit: None,
        };
        let responses = send_and_recv(&connection, &query).await;

        // Should get at least BLOB + EVENT(query_complete).
        assert!(
            responses.len() >= 2,
            "expected BLOB + query_complete, got {} messages",
            responses.len()
        );

        // Last message should be query_complete.
        match responses.last().unwrap() {
            RelayMessage::Event {
                ref_id, event_type, ..
            } => {
                assert_eq!(ref_id.as_deref(), Some("q-1"));
                assert_eq!(event_type, "query_complete");
            }
            other => panic!("expected EVENT(query_complete), got {other:?}"),
        }

        // First message should be BLOB.
        match &responses[0] {
            RelayMessage::Blob {
                routing_id: rid,
                blob,
                ..
            } => {
                assert_eq!(rid, &routing_id);
                assert_eq!(blob.len(), 50);
            }
            other => panic!("expected BLOB, got {other:?}"),
        }

        connection.close(0u32.into(), b"done");
        handle.shutdown();
    }

    #[tokio::test]
    async fn quic_delete_returns_ok() {
        let (handle, addr, certs, _storage, _subs) = start_test_listener();
        let connection = connect_client(addr, &certs).await;

        let blob_id = [3u8; 32];
        let delete = ClientMessage::Delete {
            ref_id: Some("d-1".to_string()),
            blob_id,
        };

        let responses = send_and_recv(&connection, &delete).await;
        assert_eq!(responses.len(), 1);
        match &responses[0] {
            RelayMessage::Ok { ref_id, blob_id } => {
                assert_eq!(ref_id.as_deref(), Some("d-1"));
                assert!(blob_id.is_none());
            }
            other => panic!("expected OK, got {other:?}"),
        }

        connection.close(0u32.into(), b"done");
        handle.shutdown();
    }

    #[tokio::test]
    async fn quic_ping_returns_pong() {
        let (handle, addr, certs, _storage, _subs) = start_test_listener();
        let connection = connect_client(addr, &certs).await;

        let ping = ClientMessage::Ping { ts: 1_234_567_890 };
        let responses = send_and_recv(&connection, &ping).await;

        assert_eq!(responses.len(), 1);
        match &responses[0] {
            RelayMessage::Pong { ts } => {
                assert_eq!(*ts, 1_234_567_890);
            }
            other => panic!("expected PONG, got {other:?}"),
        }

        connection.close(0u32.into(), b"done");
        handle.shutdown();
    }

    #[tokio::test]
    async fn quic_publish_validates_blob_size() {
        let (handle, addr, certs, _storage, _subs) = start_test_listener();
        let connection = connect_client(addr, &certs).await;

        // Empty blob should be rejected.
        let msg = ClientMessage::Publish {
            ref_id: Some("size-1".to_string()),
            routing_id: [4u8; 32],
            recipient_hint: None,
            blob_ttl: 3600,
            blob: vec![],
        };

        let responses = send_and_recv(&connection, &msg).await;
        assert_eq!(responses.len(), 1);
        match &responses[0] {
            RelayMessage::Err {
                code: c, ref_id, ..
            } => {
                assert_eq!(*c, code::BLOB_TOO_LARGE);
                assert_eq!(ref_id.as_deref(), Some("size-1"));
            }
            other => panic!("expected ERR, got {other:?}"),
        }

        connection.close(0u32.into(), b"done");
        handle.shutdown();
    }

    #[tokio::test]
    async fn quic_publish_validates_ttl() {
        let (handle, addr, certs, _storage, _subs) = start_test_listener();
        let connection = connect_client(addr, &certs).await;

        // TTL of 0 should be rejected.
        let msg = ClientMessage::Publish {
            ref_id: Some("ttl-1".to_string()),
            routing_id: [5u8; 32],
            recipient_hint: None,
            blob_ttl: 0,
            blob: vec![1u8; 10],
        };

        let responses = send_and_recv(&connection, &msg).await;
        assert_eq!(responses.len(), 1);
        match &responses[0] {
            RelayMessage::Err {
                code: c, ref_id, ..
            } => {
                assert_eq!(*c, code::TTL_TOO_LONG);
                assert_eq!(ref_id.as_deref(), Some("ttl-1"));
            }
            other => panic!("expected ERR, got {other:?}"),
        }

        connection.close(0u32.into(), b"done");
        handle.shutdown();
    }

    #[tokio::test]
    async fn quic_query_validates_limit() {
        let (handle, addr, certs, _storage, _subs) = start_test_listener();
        let connection = connect_client(addr, &certs).await;

        let query = ClientMessage::Query {
            ref_id: Some("lim-1".to_string()),
            routing_id: [6u8; 32],
            since: None,
            limit: Some(0),
        };

        let responses = send_and_recv(&connection, &query).await;
        assert_eq!(responses.len(), 1);
        match &responses[0] {
            RelayMessage::Err {
                code: c, ref_id, ..
            } => {
                assert_eq!(*c, code::LIMIT_EXCEEDED);
                assert_eq!(ref_id.as_deref(), Some("lim-1"));
            }
            other => panic!("expected ERR, got {other:?}"),
        }

        connection.close(0u32.into(), b"done");
        handle.shutdown();
    }

    #[tokio::test]
    async fn quic_subscribe_and_receive_published_blob() {
        let (handle, addr, certs, _storage, _subs) = start_test_listener();

        // Connect subscriber.
        let sub_conn = connect_client(addr, &certs).await;

        let routing_id = [7u8; 32];

        // Open a subscribe stream.
        let (mut sub_send, sub_recv) = sub_conn.open_bi().await.unwrap();
        let subscribe_msg = ClientMessage::Subscribe {
            ref_id: Some("sub-1".to_string()),
            routing_id,
            since: None,
        };
        let payload = subscribe_msg.to_bytes().unwrap();
        let len = u32::try_from(payload.len()).unwrap();
        sub_send.write_all(&len.to_be_bytes()).await.unwrap();
        sub_send.write_all(&payload).await.unwrap();
        // Do NOT finish — subscribe stream stays open.

        // Read the OK response.
        let mut len_buf = [0u8; 4];
        let mut sub_recv = sub_recv;
        sub_recv.read_exact(&mut len_buf).await.unwrap();
        let msg_len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; msg_len];
        sub_recv.read_exact(&mut buf).await.unwrap();
        let ok_msg = RelayMessage::from_bytes(&buf).unwrap();
        match &ok_msg {
            RelayMessage::Ok { ref_id, .. } => {
                assert_eq!(ref_id.as_deref(), Some("sub-1"));
            }
            other => panic!("expected OK, got {other:?}"),
        }

        // Give the subscription time to register.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Connect a publisher and publish a blob.
        let pub_conn = connect_client(addr, &certs).await;
        let publish_msg = ClientMessage::Publish {
            ref_id: None,
            routing_id,
            recipient_hint: None,
            blob_ttl: 3600,
            blob: vec![88u8; 20],
        };
        let pub_responses = send_and_recv(&pub_conn, &publish_msg).await;
        assert_eq!(pub_responses.len(), 1);
        assert!(matches!(&pub_responses[0], RelayMessage::Ok { .. }));

        // Read the delivered BLOB from the subscribe stream.
        let mut len_buf = [0u8; 4];
        let read_result =
            tokio::time::timeout(Duration::from_secs(5), sub_recv.read_exact(&mut len_buf)).await;
        assert!(read_result.is_ok(), "timed out waiting for BLOB delivery");
        read_result.unwrap().unwrap();
        let msg_len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; msg_len];
        sub_recv.read_exact(&mut buf).await.unwrap();
        let blob_msg = RelayMessage::from_bytes(&buf).unwrap();

        match &blob_msg {
            RelayMessage::Blob {
                routing_id: rid,
                blob,
                ..
            } => {
                assert_eq!(rid, &routing_id);
                assert_eq!(blob, &vec![88u8; 20]);
            }
            other => panic!("expected BLOB, got {other:?}"),
        }

        pub_conn.close(0u32.into(), b"done");
        sub_conn.close(0u32.into(), b"done");
        handle.shutdown();
    }

    #[tokio::test]
    async fn quic_unsubscribe_stops_delivery() {
        let (handle, addr, certs, _storage, _subs) = start_test_listener();
        let connection = connect_client(addr, &certs).await;

        let routing_id = [8u8; 32];

        // Subscribe.
        let subscribe_msg = ClientMessage::Subscribe {
            ref_id: None,
            routing_id,
            since: None,
        };

        // Open subscribe stream, send subscribe, read OK.
        let (mut sub_send, mut sub_recv) = connection.open_bi().await.unwrap();
        let payload = subscribe_msg.to_bytes().unwrap();
        let len = u32::try_from(payload.len()).unwrap();
        sub_send.write_all(&len.to_be_bytes()).await.unwrap();
        sub_send.write_all(&payload).await.unwrap();

        let mut len_buf = [0u8; 4];
        sub_recv.read_exact(&mut len_buf).await.unwrap();
        let msg_len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; msg_len];
        sub_recv.read_exact(&mut buf).await.unwrap();
        assert!(matches!(
            RelayMessage::from_bytes(&buf).unwrap(),
            RelayMessage::Ok { .. }
        ));

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Now unsubscribe on a separate stream.
        let unsub = ClientMessage::Unsubscribe {
            ref_id: Some("unsub-1".to_string()),
            routing_id,
        };
        let responses = send_and_recv(&connection, &unsub).await;
        assert_eq!(responses.len(), 1);
        assert!(matches!(&responses[0], RelayMessage::Ok { .. }));

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Publish a blob -- it should NOT be delivered to the unsubscribed stream.
        let publish_msg = ClientMessage::Publish {
            ref_id: None,
            routing_id,
            recipient_hint: None,
            blob_ttl: 3600,
            blob: vec![77u8; 10],
        };
        let _ = send_and_recv(&connection, &publish_msg).await;

        // Try to read from the subscribe stream -- should timeout (no delivery).
        let mut len_buf = [0u8; 4];
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            sub_recv.read_exact(&mut len_buf),
        )
        .await;
        assert!(
            result.is_err(),
            "expected timeout — blob should not be delivered after unsubscribe"
        );

        connection.close(0u32.into(), b"done");
        handle.shutdown();
    }

    #[tokio::test]
    async fn quic_shared_subscription_registry_with_external() {
        // Verify that the subscription registry is truly shared by checking
        // that subscriptions registered via the QUIC listener are visible
        // from the shared registry reference.
        let (handle, addr, certs, _storage, subs) = start_test_listener();
        let connection = connect_client(addr, &certs).await;

        let routing_id = [9u8; 32];

        // Subscribe via QUIC.
        let (mut sub_send, mut sub_recv) = connection.open_bi().await.unwrap();
        let subscribe_msg = ClientMessage::Subscribe {
            ref_id: None,
            routing_id,
            since: None,
        };
        let payload = subscribe_msg.to_bytes().unwrap();
        let len = u32::try_from(payload.len()).unwrap();
        sub_send.write_all(&len.to_be_bytes()).await.unwrap();
        sub_send.write_all(&payload).await.unwrap();

        // Read OK.
        let mut len_buf = [0u8; 4];
        sub_recv.read_exact(&mut len_buf).await.unwrap();
        let msg_len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; msg_len];
        sub_recv.read_exact(&mut buf).await.unwrap();
        assert!(matches!(
            RelayMessage::from_bytes(&buf).unwrap(),
            RelayMessage::Ok { .. }
        ));

        tokio::time::sleep(Duration::from_millis(50)).await;

        // The shared registry should now contain the subscription.
        {
            let registry = subs.read().await;
            assert!(
                registry.contains_key(&routing_id),
                "subscription should be visible in the shared registry"
            );
            let entries = registry.get(&routing_id).unwrap();
            assert_eq!(entries.len(), 1);
            drop(registry);
        }

        connection.close(0u32.into(), b"done");
        handle.shutdown();
    }

    #[tokio::test]
    async fn quic_multiple_concurrent_streams() {
        let (handle, addr, certs, _storage, _subs) = start_test_listener();
        let connection = connect_client(addr, &certs).await;

        // Open multiple streams concurrently and verify all succeed.
        let mut handles = Vec::new();
        for i in 0u8..5 {
            let conn = connection.clone();
            handles.push(tokio::spawn(async move {
                let msg = ClientMessage::Ping { ts: u64::from(i) };
                let responses = send_and_recv(&conn, &msg).await;
                assert_eq!(responses.len(), 1);
                match &responses[0] {
                    RelayMessage::Pong { ts } => assert_eq!(*ts, u64::from(i)),
                    other => panic!("expected PONG, got {other:?}"),
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        connection.close(0u32.into(), b"done");
        handle.shutdown();
    }

    #[tokio::test]
    async fn quic_graceful_shutdown() {
        let (handle, addr, certs, _storage, _subs) = start_test_listener();
        let connection = connect_client(addr, &certs).await;

        // Verify it works before shutdown.
        let ping = ClientMessage::Ping { ts: 1 };
        let responses = send_and_recv(&connection, &ping).await;
        assert_eq!(responses.len(), 1);

        // Shutdown the listener.
        handle.shutdown();
        assert!(handle.is_shutdown());

        // Wait for shutdown to propagate.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The existing connection may still work briefly (graceful drain).
        // New connections should eventually fail.
        connection.close(0u32.into(), b"done");
    }

    #[tokio::test]
    async fn quic_subscribe_with_backfill() {
        let (handle, addr, certs, _storage, _subs) = start_test_listener();
        let connection = connect_client(addr, &certs).await;

        let routing_id = [10u8; 32];

        // Publish a blob first.
        let publish_msg = ClientMessage::Publish {
            ref_id: None,
            routing_id,
            recipient_hint: None,
            blob_ttl: 3600,
            blob: vec![55u8; 30],
        };
        let _ = send_and_recv(&connection, &publish_msg).await;

        // Subscribe with since=0 (should backfill).
        let (mut sub_send, mut sub_recv) = connection.open_bi().await.unwrap();
        let subscribe_msg = ClientMessage::Subscribe {
            ref_id: Some("bf-1".to_string()),
            routing_id,
            since: Some(0),
        };
        let payload = subscribe_msg.to_bytes().unwrap();
        let len = u32::try_from(payload.len()).unwrap();
        sub_send.write_all(&len.to_be_bytes()).await.unwrap();
        sub_send.write_all(&payload).await.unwrap();

        // Read OK.
        let mut len_buf = [0u8; 4];
        sub_recv.read_exact(&mut len_buf).await.unwrap();
        let msg_len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; msg_len];
        sub_recv.read_exact(&mut buf).await.unwrap();
        assert!(matches!(
            RelayMessage::from_bytes(&buf).unwrap(),
            RelayMessage::Ok { .. }
        ));

        // Read the backfilled BLOB.
        let mut len_buf = [0u8; 4];
        let result =
            tokio::time::timeout(Duration::from_secs(5), sub_recv.read_exact(&mut len_buf)).await;
        assert!(result.is_ok(), "timed out waiting for backfill BLOB");
        result.unwrap().unwrap();
        let msg_len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; msg_len];
        sub_recv.read_exact(&mut buf).await.unwrap();
        let msg = RelayMessage::from_bytes(&buf).unwrap();
        assert!(matches!(msg, RelayMessage::Blob { .. }));

        // Read backfill_complete event.
        let mut len_buf = [0u8; 4];
        let result =
            tokio::time::timeout(Duration::from_secs(5), sub_recv.read_exact(&mut len_buf)).await;
        assert!(result.is_ok(), "timed out waiting for backfill_complete");
        result.unwrap().unwrap();
        let msg_len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; msg_len];
        sub_recv.read_exact(&mut buf).await.unwrap();
        let msg = RelayMessage::from_bytes(&buf).unwrap();
        match msg {
            RelayMessage::Event { event_type, .. } => {
                assert_eq!(event_type, "backfill_complete");
            }
            other => panic!("expected EVENT(backfill_complete), got {other:?}"),
        }

        connection.close(0u32.into(), b"done");
        handle.shutdown();
    }

    #[tokio::test]
    async fn quic_publish_stored_in_shared_storage() {
        let (handle, addr, certs, storage, _subs) = start_test_listener();
        let connection = connect_client(addr, &certs).await;

        let routing_id = [11u8; 32];
        let blob_data = vec![42u8; 64];

        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id,
            recipient_hint: None,
            blob_ttl: 3600,
            blob: blob_data.clone(),
        };

        let responses = send_and_recv(&connection, &msg).await;
        assert_eq!(responses.len(), 1);

        // Verify the blob is in the shared storage.
        let blobs = storage.query(&routing_id, None, 100).await.unwrap();
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].blob, blob_data);

        connection.close(0u32.into(), b"done");
        handle.shutdown();
    }
}
