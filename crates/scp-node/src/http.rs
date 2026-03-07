//! HTTP routing for [`ApplicationNode`].
//!
//! Provides axum routers for `.well-known/scp` and `/scp/v1` WebSocket
//! upgrade, plus the `serve()` method that merges application routes with
//! SCP routes on a single HTTPS listener.
//!
//! See spec section 18.6.2 for the SDK surface.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use futures::{SinkExt, StreamExt};
use tokio::sync::{RwLock, Semaphore};
use tokio_util::sync::CancellationToken;
use tower_http::cors::{AllowOrigin, CorsLayer};
use zeroize::Zeroizing;

use scp_platform::traits::Storage;
use scp_transport::native::server::RelayConfig as TransportRelayConfig;
use scp_transport::native::storage::BlobStorageBackend;
use scp_transport::relay::rate_limit::PublishRateLimiter;

use crate::tls;

use crate::projection::ProjectedContext;
use crate::well_known::well_known_handler;
use crate::{ApplicationNode, NodeError};

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Registered broadcast context for `.well-known/scp` generation.
///
/// Stored in [`NodeState`] and read on each `.well-known/scp` request.
#[derive(Debug, Clone)]
pub struct BroadcastContext {
    /// Context ID (hex-encoded).
    pub id: String,
    /// Human-readable name (advisory).
    pub name: Option<String>,
}

/// Shared state accessible by axum handlers.
///
/// Contains the node's identity information, registered broadcast
/// contexts, dev API configuration, and blob storage reference.
/// Read on every `.well-known/scp` request to generate the response
/// dynamically (spec section 18.6.4).
///
/// Blob storage uses [`BlobStorageBackend`] (enum dispatch), shared between
/// the relay server and projection handlers via `Arc` (spec section 18.11.5).
pub struct NodeState {
    /// The operator's DID string.
    pub(crate) did: String,
    /// The relay URL (e.g., `wss://example.com/scp/v1`).
    pub(crate) relay_url: String,
    /// Registered broadcast contexts, keyed by lowercase hex context ID.
    /// Modified via [`ApplicationNode::register_broadcast_context`].
    pub(crate) broadcast_contexts: RwLock<HashMap<String, BroadcastContext>>,
    /// The relay server's bound address for WebSocket bridge connections.
    pub(crate) relay_addr: SocketAddr,
    /// Shared secret for authenticating internal bridge connections.
    ///
    /// Generated at startup and included as an `Authorization: Bearer`
    /// header when the axum handler connects to the internal relay. The
    /// relay validates this token during the WebSocket handshake
    /// (defense-in-depth, #85). Moved from query parameter to header to
    /// prevent leakage via server logs or error messages (#225).
    /// Wrapped in `Zeroizing` so the secret is zeroed on drop.
    pub(crate) bridge_secret: Zeroizing<[u8; 32]>,
    /// Bearer token for the dev API (`scp_local_token_<32 hex chars>`).
    ///
    /// `Some` when `local_api()` was called on the builder, `None` otherwise.
    /// See spec section 18.10.2.
    pub(crate) dev_token: Option<String>,
    /// Bind address for the dev API server.
    ///
    /// `Some` when `local_api()` was called on the builder, `None` otherwise.
    /// See spec section 18.10.2.
    pub(crate) dev_bind_addr: Option<SocketAddr>,
    /// Registry of broadcast contexts whose messages are projected (decrypted
    /// and served) by this node's HTTP endpoints. Keyed by routing ID.
    ///
    /// See spec section 18.11.5.
    pub(crate) projected_contexts: RwLock<HashMap<[u8; 32], ProjectedContext>>,
    /// Shared blob storage instance, used by both the relay server and
    /// projection handlers to read stored blobs.
    ///
    /// See spec section 18.11.5.
    pub(crate) blob_storage: Arc<BlobStorageBackend>,
    /// Relay operational parameters exposed in `.well-known/scp`
    /// `relay_config` (spec section 18.3.3).
    pub(crate) relay_config: TransportRelayConfig,
    /// The instant the node was started, used to compute uptime for the
    /// dev API health endpoint (spec section 18.10.3).
    pub(crate) start_time: Instant,
    /// Bind address for the public HTTP server used by [`ApplicationNode::serve`].
    ///
    /// Separate from `relay_addr` (the relay's internal listener) to avoid
    /// double-binding the same port (#224). Defaults to `0.0.0.0:8443`.
    pub(crate) http_bind_addr: SocketAddr,
    /// Shared cancellation token for graceful shutdown of both the public
    /// HTTPS listener and the dev API listener. Cancelled by
    /// [`ApplicationNode::shutdown`].
    ///
    /// See SCP-245 action item: "Ensure graceful shutdown of dev API
    /// listener alongside main server."
    pub(crate) shutdown_token: CancellationToken,
    /// CORS allowed origins for public endpoints (`.well-known/scp`,
    /// broadcast projection). `None` means permissive (`*`); `Some(list)`
    /// restricts to exactly those origins.
    ///
    /// See issue #231.
    pub(crate) cors_origins: Option<Vec<String>>,
    /// Per-IP token-bucket rate limiter for broadcast projection endpoints.
    ///
    /// Limits the request rate from each source IP to prevent abuse of the
    /// public, unauthenticated projection endpoints that perform crypto
    /// decryption and blob reads per request. Returns HTTP 429 when exceeded.
    ///
    /// Configurable via `SCP_NODE_PROJECTION_RATE_LIMIT` (default 60 req/s).
    /// See spec section 18.11.6.
    pub(crate) projection_rate_limiter: PublishRateLimiter,
    /// TLS configuration for the public HTTPS listener.
    ///
    /// When `Some`, [`ApplicationNode::serve`] terminates TLS using
    /// [`tokio_rustls::TlsAcceptor`] before passing connections to axum.
    /// When `None` (no-domain mode or explicit opt-out), the listener serves
    /// plain HTTP/WS (spec section 10.12.8).
    ///
    /// Built from [`tls::CertificateData`] during [`ApplicationNodeBuilder::build`]
    /// via [`tls::build_reloadable_tls_config`] (spec section 18.6.3).
    pub(crate) tls_config: Option<Arc<rustls::ServerConfig>>,
    /// The TLS certificate resolver for ACME hot-reload.
    ///
    /// When `Some`, the ACME renewal loop can call [`CertResolver::update`]
    /// to hot-swap certificates without restarting the server.
    /// When `None` (no-domain mode), ACME is not active.
    ///
    /// See spec section 18.6.3 (auto-renewal).
    pub(crate) cert_resolver: Option<Arc<crate::tls::CertResolver>>,
    /// Shared ACME challenge map (token → key authorization).
    ///
    /// Mounted in [`serve()`](crate::ApplicationNode::serve) at
    /// `GET /.well-known/acme-challenge/{token}` so that ACME renewal
    /// challenges can be served without restarting the server (issue #305).
    /// When `None` (no-domain or self-signed mode), no challenge router is
    /// mounted.
    pub(crate) acme_challenges: Option<Arc<RwLock<HashMap<String, String>>>>,
}

// ---------------------------------------------------------------------------
// CORS layer construction
// ---------------------------------------------------------------------------

/// Constructs a [`CorsLayer`] from the node's CORS configuration.
///
/// - `None` origins: permissive (`Access-Control-Allow-Origin: *`).
/// - `Some(list)`: restricts to exactly the listed origins.
///
/// Applied to public endpoints (`.well-known/scp`, broadcast projection)
/// so browser-based JavaScript / WASM clients can read responses cross-origin
/// (issue #231). Not applied to the WebSocket relay endpoint (WebSocket
/// upgrades have their own origin mechanism) or the dev API (localhost-only).
pub fn build_cors_layer(origins: &Option<Vec<String>>) -> CorsLayer {
    let allow_origin = origins.as_ref().map_or_else(AllowOrigin::any, |list| {
        let parsed: Vec<axum::http::HeaderValue> = list
            .iter()
            .filter_map(|o| {
                o.parse().map_or_else(
                    |_| {
                        tracing::warn!(
                            origin = %o,
                            "ignoring invalid CORS origin; \
                             this may make endpoints more permissive than intended"
                        );
                        None
                    },
                    Some,
                )
            })
            .collect();
        AllowOrigin::list(parsed)
    });
    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods([axum::http::Method::GET, axum::http::Method::OPTIONS])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::IF_NONE_MATCH,
        ])
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Idle timeout for bridge WebSocket connections (5 minutes).
///
/// If no data flows in either direction for this duration, the bridge
/// connection is closed. This prevents stale connections from holding
/// resources indefinitely (#229).
const BRIDGE_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// Router constructors
// ---------------------------------------------------------------------------

/// Returns an axum [`Router`] serving `GET /.well-known/scp`.
///
/// The handler dynamically generates the `.well-known/scp` JSON document
/// from the provided [`NodeState`]. See spec section 18.3.
pub fn well_known_router(state: Arc<NodeState>) -> Router {
    Router::new()
        .route("/.well-known/scp", get(well_known_handler))
        .with_state(state)
}

/// Returns an axum [`Router`] handling WebSocket upgrade at `/scp/v1`.
///
/// Incoming WebSocket connections are bridged to the node's internal
/// relay server. The axum handler upgrades the HTTP connection to
/// WebSocket, then connects to the relay on localhost and forwards
/// frames bidirectionally.
///
/// An `Arc<Semaphore>` caps concurrent bridge connections to
/// `max_total_connections` from the relay config. The permit is acquired
/// before the HTTP 101 upgrade and held inside the `on_upgrade` closure
/// for the entire WebSocket connection lifetime — ensuring the semaphore
/// accurately tracks active connections, not just in-flight upgrade
/// requests (#229).
pub fn relay_router(state: Arc<NodeState>) -> Router {
    let bridge_semaphore = Arc::new(Semaphore::new(state.relay_config.max_total_connections));
    Router::new()
        .route("/scp/v1", get(ws_upgrade_handler))
        .with_state((state, bridge_semaphore))
}

/// Axum handler for WebSocket upgrade at `/scp/v1`.
///
/// Acquires a semaphore permit before upgrading; the permit is moved into
/// the `on_upgrade` closure so it is held for the entire WebSocket
/// connection lifetime. If the HTTP 101 upgrade never completes, axum
/// drops the response — which drops the closure and releases the permit.
/// Returns 503 Service Unavailable when the bridge is at capacity.
async fn ws_upgrade_handler(
    ws: WebSocketUpgrade,
    State((state, sem)): State<(Arc<NodeState>, Arc<Semaphore>)>,
) -> impl IntoResponse {
    let Ok(permit) = sem.try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let relay_addr = state.relay_addr;
    // Clone the Zeroizing wrapper so the bridge task's copy is also zeroed
    // on drop. Avoids leaving bare secret bytes on the stack/heap.
    let bridge_secret = state.bridge_secret.clone();
    // Move the permit into the closure — it is released when the closure
    // is dropped, either after the bridge ends or if the upgrade fails.
    ws.on_upgrade(move |socket| async move {
        let _permit = permit; // bind to ensure drop at end of scope
        relay_bridge(socket, relay_addr, bridge_secret).await;
    })
    .into_response()
}

/// Bridges an axum WebSocket to the internal relay server.
///
/// Connects to the relay at `relay_addr` with the bridge secret included
/// as an `Authorization: Bearer <hex>` header, then forwards frames in
/// both directions until either side closes or the connection is idle for
/// [`BRIDGE_IDLE_TIMEOUT`]. Sends explicit WebSocket close frames on
/// both sides when the bridge terminates.
///
/// The secret is transmitted via HTTP header rather than query parameter
/// to prevent leakage through server logs, error messages, or debug
/// output (#225).
///
/// The idle timeout resets only on data frames (Text/Binary), not on
/// Ping/Pong control frames. This prevents an attacker from keeping
/// connections alive indefinitely by sending pings without real data
/// (#229).
async fn relay_bridge(
    axum_ws: WebSocket,
    relay_addr: SocketAddr,
    bridge_secret: Zeroizing<[u8; 32]>,
) {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let token_hex = scp_transport::native::server::hex_encode_32(&bridge_secret);
    let url = format!("ws://{relay_addr}/");
    let mut request = match url.into_client_request() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                addr = %relay_addr,
                error = %e,
                "failed to build WebSocket request for internal relay bridge"
            );
            return;
        }
    };
    // Safety: the token is a 64-char lowercase hex string — always valid
    // as an HTTP header value. `parse()` only fails on non-visible ASCII
    // or control characters, which hex digits never contain.
    let Ok(header_value) = format!("Bearer {token_hex}").parse() else {
        tracing::error!("bridge token produced invalid HTTP header value");
        return;
    };
    request.headers_mut().insert("Authorization", header_value);
    let relay_conn = tokio_tungstenite::connect_async(request).await;

    let Ok((relay_ws, _)) = relay_conn else {
        tracing::error!(
            addr = %relay_addr,
            "failed to connect to internal relay for WebSocket bridge"
        );
        return;
    };

    let (mut relay_sink, mut relay_source) = relay_ws.split();
    let (mut axum_sink, mut axum_source) = axum_ws.split();

    // Idle timeout: resets only on data frames (Text/Binary), not control frames.
    let idle_timeout = tokio::time::sleep(BRIDGE_IDLE_TIMEOUT);
    tokio::pin!(idle_timeout);

    loop {
        tokio::select! {
            msg = StreamExt::next(&mut axum_source) => {
                match msg {
                    Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                    Some(Ok(msg)) => {
                        let relay_msg = match msg {
                            Message::Text(t) => {
                                idle_timeout.as_mut().reset(tokio::time::Instant::now() + BRIDGE_IDLE_TIMEOUT);
                                tokio_tungstenite::tungstenite::Message::Text(t.to_string())
                            }
                            Message::Binary(b) => {
                                idle_timeout.as_mut().reset(tokio::time::Instant::now() + BRIDGE_IDLE_TIMEOUT);
                                tokio_tungstenite::tungstenite::Message::Binary(b.to_vec())
                            }
                            Message::Ping(p) => tokio_tungstenite::tungstenite::Message::Ping(p.to_vec()),
                            Message::Pong(p) => tokio_tungstenite::tungstenite::Message::Pong(p.to_vec()),
                            Message::Close(_) => break,
                        };
                        if let Err(e) = SinkExt::send(&mut relay_sink, relay_msg).await {
                            tracing::debug!(
                                direction = "client->relay",
                                error = %e,
                                "bridge forwarding failed"
                            );
                            break;
                        }
                    }
                }
            }
            msg = StreamExt::next(&mut relay_source) => {
                match msg {
                    Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_)) | Err(_)) | None => break,
                    Some(Ok(msg)) => {
                        let axum_msg = match msg {
                            tokio_tungstenite::tungstenite::Message::Text(t) => {
                                idle_timeout.as_mut().reset(tokio::time::Instant::now() + BRIDGE_IDLE_TIMEOUT);
                                Message::Text(t.into())
                            }
                            tokio_tungstenite::tungstenite::Message::Binary(b) => {
                                idle_timeout.as_mut().reset(tokio::time::Instant::now() + BRIDGE_IDLE_TIMEOUT);
                                Message::Binary(b.into())
                            }
                            tokio_tungstenite::tungstenite::Message::Ping(p) => Message::Ping(p.into()),
                            tokio_tungstenite::tungstenite::Message::Pong(p) => Message::Pong(p.into()),
                            tokio_tungstenite::tungstenite::Message::Close(_) => break,
                            tokio_tungstenite::tungstenite::Message::Frame(_) => continue,
                        };
                        if let Err(e) = SinkExt::send(&mut axum_sink, axum_msg).await {
                            tracing::debug!(
                                direction = "relay->client",
                                error = %e,
                                "bridge forwarding failed"
                            );
                            break;
                        }
                    }
                }
            }
            () = &mut idle_timeout => {
                tracing::debug!("bridge connection idle timeout reached");
                break;
            }
        }
    }

    // Send explicit close frames (best-effort, ignore errors on close).
    // SplitSink::drop() does NOT send close frames in tokio-tungstenite 0.24.
    let _ = SinkExt::close(&mut relay_sink).await;
    let _ = SinkExt::close(&mut axum_sink).await;
}

// ---------------------------------------------------------------------------
// ApplicationNode HTTP methods
// ---------------------------------------------------------------------------

impl<S: Storage + Send + Sync + 'static> ApplicationNode<S> {
    /// Returns an axum [`Router`] serving `GET /.well-known/scp`.
    ///
    /// The response is dynamically generated from the node's current state:
    /// DID, relay URL, and registered broadcast contexts. Content-Type is
    /// `application/json` (provided by axum's `Json` extractor).
    ///
    /// See spec section 18.3.
    #[must_use = "returns the well-known router, which must be mounted into an axum application"]
    pub fn well_known_router(&self) -> Router {
        well_known_router(Arc::clone(&self.state))
    }

    /// Returns an axum [`Router`] handling WebSocket upgrade at `/scp/v1`.
    ///
    /// Incoming connections are bridged to the node's internal relay server.
    ///
    /// See spec section 18.6.2.
    #[must_use = "returns the relay router, which must be mounted into an axum application"]
    pub fn relay_router(&self) -> Router {
        relay_router(Arc::clone(&self.state))
    }

    /// Returns an axum [`Router`] serving broadcast projection endpoints.
    ///
    /// Includes:
    /// - `GET /scp/broadcast/<routing_id>/feed` -- recent messages feed
    /// - `GET /scp/broadcast/<routing_id>/messages/<blob_id>` -- single message
    ///
    /// These are **public endpoints** with no authentication middleware --
    /// broadcast content is intended for broad distribution (spec section
    /// 18.11.6).
    ///
    /// Served on the public HTTPS port alongside `.well-known/scp` and
    /// `/scp/v1`.
    ///
    /// See spec section 18.11.8.
    #[must_use = "returns the projection router, which must be mounted into an axum application"]
    pub fn broadcast_projection_router(&self) -> Router {
        crate::projection::broadcast_projection_router(Arc::clone(&self.state))
    }

    /// Returns the dev API router if the dev API is enabled.
    ///
    /// Returns `Some(Router)` when [`ApplicationNodeBuilder::local_api`] was
    /// called (i.e., a dev token was generated), `None` otherwise. The
    /// returned router includes all `/scp/dev/v1/*` routes with bearer token
    /// middleware applied.
    ///
    /// See spec section 18.10.5.
    #[must_use = "returns the dev API router, which must be served on a separate listener"]
    pub fn dev_router(&self) -> Option<Router> {
        let token = self.state.dev_token.clone()?;
        Some(crate::dev_api::dev_router(Arc::clone(&self.state), token))
    }

    /// Takes ownership of the node and starts serving HTTP traffic.
    ///
    /// Binds HTTPS (or plain HTTP when TLS is not configured) on the
    /// configured address, merging:
    ///
    /// 1. Application-provided routes (`app_router`)
    /// 2. `.well-known/scp` route
    /// 3. `/scp/v1` WebSocket upgrade route
    /// 4. `/scp/broadcast/*` broadcast projection routes
    ///
    /// SCP routes take precedence for `/.well-known/scp`, `/scp/v1`, and
    /// `/scp/broadcast/*`. All other paths route to `app_router`.
    ///
    /// ## TLS termination
    ///
    /// When a TLS configuration was provisioned during
    /// [`ApplicationNodeBuilder::build`] (domain mode with successful ACME or
    /// injected TLS provider), `serve()` terminates TLS using
    /// [`tokio_rustls::TlsAcceptor`] and serves HTTPS/WSS. When no TLS
    /// configuration is present (no-domain mode, or TLS provisioning opted
    /// out), `serve()` falls back to plain HTTP/WS. See spec section 18.6.3.
    ///
    /// ## Dev API
    ///
    /// When the dev API is configured (via [`ApplicationNodeBuilder::local_api`]),
    /// a separate tokio task is spawned to serve the dev API on the configured
    /// address. The dev API listener runs concurrently with the public
    /// listener. When the dev API is not configured, `serve()` behaves exactly
    /// as before -- no additional listener is spawned. The dev API always
    /// uses plain HTTP (it is bound to loopback only).
    ///
    /// ## HTTP/3
    ///
    /// When the `http3` feature is enabled and an [`Http3Config`] is provided
    /// via [`ApplicationNodeBuilder::http3`], an HTTP/3 listener is started
    /// on a separate QUIC endpoint. All HTTP/1.1 and HTTP/2 responses include
    /// an `Alt-Svc` header advertising the HTTP/3 endpoint (spec section
    /// 10.15.1).
    ///
    /// ## Graceful shutdown
    ///
    /// The `shutdown` future is awaited as a graceful shutdown signal: when
    /// it completes, the server stops accepting new connections, drains
    /// in-flight requests, cancels the internal shutdown token (stopping
    /// the dev API listener if running), and shuts down the relay server.
    /// The node is consumed -- callers do not need to call
    /// [`ApplicationNode::shutdown`] separately.
    ///
    /// If the dev API task exits early (e.g., bind failure), the shutdown
    /// token is cancelled and the error is propagated. Likewise, if the
    /// main server exits first, the dev API task is cancelled via the
    /// shutdown token and aborted.
    ///
    /// See spec sections 18.6.3, 18.10.5, and 18.11.8.
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::Serve`] if either server cannot bind or
    /// encounters a fatal I/O error.
    pub async fn serve(
        self,
        app_router: Router,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), NodeError> {
        spawn_projection_rate_limit_cleanup(
            self.state.projection_rate_limiter.clone(),
            self.state.shutdown_token.clone(),
        );

        let cors = build_cors_layer(&self.state.cors_origins);

        // Apply CORS to public endpoints only. The WebSocket relay endpoint
        // uses its own origin mechanism; the dev API is localhost-only.
        let well_known = well_known_router(Arc::clone(&self.state)).layer(cors.clone());
        let relay_rt = relay_router(Arc::clone(&self.state));
        let projection =
            crate::projection::broadcast_projection_router(Arc::clone(&self.state)).layer(cors);

        // Extract dev API configuration before building the merged router.
        let dev_router = {
            let token = self.state.dev_token.clone();
            token.map(|t| crate::dev_api::dev_router(Arc::clone(&self.state), t))
        };
        let dev_bind_addr = self.state.dev_bind_addr;
        let tls_config = self.state.tls_config.clone();
        #[cfg(feature = "http3")]
        let http3_config = self.http3_config;

        let relay = self.relay;
        let state = self.state;

        // SCP routes take precedence: merge them last so they override
        // any conflicting paths in app_router. ACME challenge router is
        // included for renewal support (issue #305).
        let merged = build_merged_router(
            app_router,
            well_known,
            relay_rt,
            projection,
            state.acme_challenges.as_ref(),
        );

        let dev_api_handle = spawn_dev_api(dev_router, dev_bind_addr, state.shutdown_token.clone());

        // Spawn HTTP/3 listener when configured (spec section 10.15.1).
        #[cfg(feature = "http3")]
        if let Some(http3_config) = http3_config {
            spawn_http3_listener(http3_config, &state);
        }

        let bind_addr = state.http_bind_addr;

        let listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .map_err(|e| NodeError::Serve(e.to_string()))?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| NodeError::Serve(e.to_string()))?;

        // Wire the caller-provided shutdown future to the node's cancellation token.
        let shutdown_token = state.shutdown_token.clone();
        let token = shutdown_token.clone();
        tokio::spawn(async move {
            shutdown.await;
            token.cancel();
        });

        // Branch: TLS-terminated HTTPS or plain HTTP.
        let main_server: std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), NodeError>> + Send>,
        > = if let Some(tls_cfg) = tls_config {
            tracing::info!(
                addr = %local_addr, scheme = "HTTPS",
                "application node server started (TLS active)"
            );
            Box::pin(tls::serve_tls(
                listener,
                tls_cfg,
                merged,
                shutdown_token.clone(),
            ))
        } else {
            tracing::info!(
                addr = %local_addr, scheme = "HTTP",
                "application node server started (plain HTTP, broadcast projection endpoints active)"
            );
            let token = shutdown_token.clone();
            Box::pin(async move {
                axum::serve(listener, merged)
                    .with_graceful_shutdown(token.cancelled_owned())
                    .await
                    .map_err(|e| NodeError::Serve(e.to_string()))
            })
        };

        // If a dev API task is running, select! on both: if either exits
        // early we propagate the result. This ensures a dev API bind
        // failure doesn't go unnoticed while the main server keeps running.
        let result = match dev_api_handle {
            Some(handle) => {
                tokio::pin!(handle);
                tokio::select! {
                    result = main_server => {
                        // Main server exited — cancel shutdown token so the
                        // dev API task also drains, then abort its handle.
                        state.shutdown_token.cancel();
                        handle.abort();
                        result
                    }
                    result = &mut handle => {
                        // Dev API exited early — cancel shutdown token so the
                        // main server also drains.
                        state.shutdown_token.cancel();
                        // JoinError (task panic/cancel) or NodeError from inner.
                        match result {
                            Ok(inner) => inner,
                            Err(join_err) => {
                                Err(NodeError::Serve(
                                    format!("dev API task failed: {join_err}")
                                ))
                            }
                        }
                    }
                }
            }
            None => main_server.await,
        };

        // Graceful shutdown: cancel the shutdown token (idempotent if
        // already cancelled above) and stop the relay server. This ensures
        // callers don't need to call shutdown() separately.
        state.shutdown_token.cancel();
        relay.shutdown_handle.shutdown();
        tracing::info!("application node shut down");

        result
    }
}

// ---------------------------------------------------------------------------
// Dev API spawning (extracted for clippy::too_many_lines)
// ---------------------------------------------------------------------------

/// Builds the merged axum router for `serve()`, combining SCP protocol
/// routes (well-known, relay, projection, ACME challenges) with the
/// application router. Extracted from `serve()` for clippy line limits.
fn build_merged_router(
    app_router: Router,
    well_known: Router,
    relay_rt: Router,
    projection: Router,
    acme_challenges: Option<&Arc<RwLock<HashMap<String, String>>>>,
) -> Router {
    let merged = app_router
        .merge(well_known)
        .merge(relay_rt)
        .merge(projection);

    // Mount ACME challenge router for renewal challenges (issue #305).
    // Serves `GET /.well-known/acme-challenge/{token}` so the ACME CA can
    // validate domain ownership during certificate renewal.
    if let Some(challenges) = acme_challenges {
        merged.merge(tls::acme_challenge_router(Arc::clone(challenges)))
    } else {
        merged
    }
}

/// Spawns the dev API listener if configured.
///
/// Returns a `JoinHandle` so the caller can detect early exit (e.g., bind
/// failure) and propagate the error. Dev API always uses plain HTTP
/// (loopback-only, spec section 18.10.5).
fn spawn_dev_api(
    dev_router: Option<Router>,
    dev_bind_addr: Option<SocketAddr>,
    shutdown_token: CancellationToken,
) -> Option<tokio::task::JoinHandle<Result<(), NodeError>>> {
    let (Some(dev_router), Some(dev_addr)) = (dev_router, dev_bind_addr) else {
        return None;
    };
    Some(tokio::spawn(async move {
        let dev_listener = tokio::net::TcpListener::bind(dev_addr).await.map_err(|e| {
            NodeError::Serve(format!("failed to bind dev API server on {dev_addr}: {e}"))
        })?;
        let local_addr = dev_listener.local_addr().unwrap_or(dev_addr);
        tracing::info!(addr = %local_addr, "dev API server started");

        axum::serve(dev_listener, dev_router)
            .with_graceful_shutdown(shutdown_token.cancelled_owned())
            .await
            .map_err(|e| NodeError::Serve(format!("dev API server error: {e}")))
    }))
}

// ---------------------------------------------------------------------------
// Projection rate limiter cleanup (extracted for clippy::too_many_lines)
// ---------------------------------------------------------------------------

/// Spawns the background cleanup loop for the projection rate limiter.
///
/// Evicts stale per-IP token buckets every 60 seconds (buckets idle for more
/// than 300 seconds). Runs until `shutdown_token` is cancelled.
fn spawn_projection_rate_limit_cleanup(
    limiter: PublishRateLimiter,
    shutdown_token: CancellationToken,
) {
    tokio::spawn(async move {
        limiter
            .cleanup_loop(
                Duration::from_secs(60),
                Duration::from_secs(300),
                shutdown_token,
            )
            .await;
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::time::Instant;

    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    use scp_transport::native::storage::BlobStorageBackend;

    use super::*;

    /// Creates a minimal `NodeState` for CORS tests.
    fn test_state(cors_origins: Option<Vec<String>>) -> Arc<NodeState> {
        Arc::new(NodeState {
            did: "did:dht:cors_test".to_owned(),
            relay_url: "wss://localhost/scp/v1".to_owned(),
            broadcast_contexts: RwLock::new(HashMap::new()),
            relay_addr: "127.0.0.1:9000".parse::<SocketAddr>().unwrap(),
            bridge_secret: Zeroizing::new([0u8; 32]),
            dev_token: None,
            dev_bind_addr: None,
            projected_contexts: RwLock::new(HashMap::new()),
            blob_storage: Arc::new(BlobStorageBackend::default()),
            relay_config: scp_transport::native::server::RelayConfig::default(),
            start_time: Instant::now(),
            http_bind_addr: SocketAddr::from(([0, 0, 0, 0], 8443)),
            shutdown_token: CancellationToken::new(),
            cors_origins,
            projection_rate_limiter: scp_transport::relay::rate_limit::PublishRateLimiter::new(
                1000,
            ),
            tls_config: None,
            cert_resolver: None,
            acme_challenges: None,
        })
    }

    #[tokio::test]
    async fn cors_permissive_well_known_returns_wildcard_origin() {
        let state = test_state(None);
        let cors = build_cors_layer(&state.cors_origins);
        let router = well_known_router(state).layer(cors);

        let req = Request::builder()
            .uri("/.well-known/scp")
            .header("Origin", "https://example.com")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let acao = resp
            .headers()
            .get("access-control-allow-origin")
            .expect("should have ACAO header")
            .to_str()
            .unwrap();
        assert_eq!(acao, "*", "permissive mode should return wildcard origin");
    }

    #[tokio::test]
    async fn cors_restricted_well_known_allows_matching_origin() {
        let origins = Some(vec!["https://allowed.example".to_owned()]);
        let state = test_state(origins);
        let cors = build_cors_layer(&state.cors_origins);
        let router = well_known_router(state).layer(cors);

        let req = Request::builder()
            .uri("/.well-known/scp")
            .header("Origin", "https://allowed.example")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let acao = resp
            .headers()
            .get("access-control-allow-origin")
            .expect("should have ACAO header for allowed origin")
            .to_str()
            .unwrap();
        assert_eq!(acao, "https://allowed.example");
    }

    #[tokio::test]
    async fn cors_restricted_well_known_rejects_non_matching_origin() {
        let origins = Some(vec!["https://allowed.example".to_owned()]);
        let state = test_state(origins);
        let cors = build_cors_layer(&state.cors_origins);
        let router = well_known_router(state).layer(cors);

        let req = Request::builder()
            .uri("/.well-known/scp")
            .header("Origin", "https://evil.example")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        // The response should succeed (CORS doesn't block the response,
        // it omits the ACAO header so the browser rejects it client-side).
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers().get("access-control-allow-origin").is_none(),
            "non-matching origin should NOT receive ACAO header"
        );
    }

    #[tokio::test]
    async fn cors_preflight_options_returns_200() {
        let state = test_state(None);
        let cors = build_cors_layer(&state.cors_origins);
        let router = well_known_router(state).layer(cors);

        let req = Request::builder()
            .method(Method::OPTIONS)
            .uri("/.well-known/scp")
            .header("Origin", "https://example.com")
            .header("Access-Control-Request-Method", "GET")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let acao = resp
            .headers()
            .get("access-control-allow-origin")
            .expect("preflight should include ACAO")
            .to_str()
            .unwrap();
        assert_eq!(acao, "*");

        let methods = resp
            .headers()
            .get("access-control-allow-methods")
            .expect("preflight should include allow-methods")
            .to_str()
            .unwrap();
        assert!(methods.contains("GET"), "should allow GET method");
    }
}

/// Spawns the HTTP/3 listener in a background task (spec §10.15.1).
///
/// Extracted from [`ApplicationNode::serve`] to keep the `serve()` method
/// within the clippy line limit. Creates a `RequestHandler` that
/// serves the full `.well-known/scp` document (same as the Axum handler)
/// over HTTP/3 and returns 404 for all other paths.
///
/// The handler holds an `Arc<NodeState>` so it can build the same
/// complete document that the HTTP/1.1+HTTP/2 handler serves, including
/// relay_config, contexts, handles, and transports (SCP-264).
#[cfg(feature = "http3")]
fn spawn_http3_listener(http3_config: scp_transport::http3::Http3Config, state: &Arc<NodeState>) {
    use scp_transport::http3::Http3Server;
    use scp_transport::http3::adapter::RequestHandler;

    struct H3RequestHandler {
        state: Arc<NodeState>,
        rt: tokio::runtime::Handle,
    }

    impl RequestHandler for H3RequestHandler {
        fn handle(
            &self,
            method: &str,
            uri: &str,
            _headers: &[(String, String)],
        ) -> axum::http::Response<Vec<u8>> {
            if method == "GET" && uri == "/.well-known/scp" {
                // Build the full WellKnownScp document using the same
                // function as the Axum handler, ensuring identical
                // responses across transports.
                let doc = self
                    .rt
                    .block_on(crate::well_known::build_well_known_scp(&self.state));
                let body_bytes = serde_json::to_vec(&doc).unwrap_or_default();
                axum::http::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(body_bytes)
                    .unwrap_or_else(|_| axum::http::Response::new(b"internal error".to_vec()))
            } else {
                axum::http::Response::builder()
                    .status(404)
                    .body(b"not found".to_vec())
                    .unwrap_or_else(|_| axum::http::Response::new(Vec::new()))
            }
        }
    }

    let handler: Arc<dyn RequestHandler> = Arc::new(H3RequestHandler {
        state: Arc::clone(state),
        rt: tokio::runtime::Handle::current(),
    });

    tokio::spawn(async move {
        let mut server = Http3Server::new(http3_config, handler);
        match server.bind() {
            Ok(addr) => {
                tracing::info!(addr = %addr, "HTTP/3 server started");
                if let Err(e) = server.serve().await {
                    tracing::error!(error = %e, "HTTP/3 server exited with error");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to bind HTTP/3 server");
            }
        }
    });
}
