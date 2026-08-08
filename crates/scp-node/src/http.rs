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
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
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
use scp_transport::relay::rate_limit::{ConnectionTracker, PublishRateLimiter};
use scp_transport::relay::subscription::SubscriptionRegistry;

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
    /// `Some` when `NodeConfig::local_api` was set, `None` otherwise.
    /// See spec section 18.10.2.
    pub(crate) dev_token: Option<String>,
    /// Bind address for the dev API server.
    ///
    /// `Some` when `NodeConfig::local_api` was set, `None` otherwise.
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
    /// Cache of recently validated UCAN tokens for projection endpoints.
    ///
    /// Amortizes Ed25519 signature verification cost across repeated
    /// requests with the same token. Entries expire after 60 seconds.
    /// Separate from the projected context registry so validation can
    /// proceed without a write lock on the registry.
    ///
    /// Uses `std::sync::RwLock` (not tokio) because the critical sections
    /// are short (`HashMap` lookups/inserts, no async I/O) and the cache
    /// is accessed from synchronous validation functions called within
    /// async handlers.
    ///
    /// See spec section 18.11.6.
    pub(crate) projection_ucan_cache: std::sync::RwLock<crate::projection::ProjectionUcanCache>,
    /// TLS configuration for the public HTTPS listener.
    ///
    /// When `Some`, [`ApplicationNode::serve`] terminates TLS using
    /// [`tokio_rustls::TlsAcceptor`] before passing connections to axum.
    /// When `None` (no-domain mode or explicit opt-out), the listener serves
    /// plain HTTP/WS (spec section 10.12.8).
    ///
    /// Built from [`tls::CertificateData`] during [`Node::start`](crate::Node::start)
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
    /// The operator's DID document — the node's live slot, NOT a build-time
    /// copy.
    ///
    /// Used by the dev API identity endpoint to return the full document
    /// (spec section 18.10.3). A NAT tier change (§10.12.1) re-points the
    /// document's `SCPRelay` service endpoint and re-publishes it; holding a
    /// `DidDocument` by value here made that endpoint serve the pre-change
    /// relay URL for the rest of the node's life. The slot is shared with the
    /// tier re-evaluation task, so the endpoint cannot read a stale document.
    /// See [`NodeDidDocument`](crate::NodeDidDocument).
    pub(crate) did_document: crate::NodeDidDocument,
    /// Shared connection tracker from the relay server.
    ///
    /// Tracks active connections per IP address across all transports.
    /// Used by the dev API health and relay status endpoints to report
    /// real connection counts (spec section 18.10.3).
    pub(crate) connection_tracker: ConnectionTracker,
    /// Shared subscription registry from the relay server.
    ///
    /// Maps routing IDs to subscriber entries. Used by the dev API
    /// context endpoint to report real subscriber counts (spec section 18.10.3).
    pub(crate) subscription_registry: SubscriptionRegistry,
    /// Shared ACME challenge map (token → key authorization).
    ///
    /// Mounted in [`serve()`](crate::ApplicationNode::serve) at
    /// `GET /.well-known/acme-challenge/{token}` so that ACME renewal
    /// challenges can be served without restarting the server (issue #305).
    /// When `None` (no-domain or self-signed mode), no challenge router is
    /// mounted.
    pub(crate) acme_challenges: Option<Arc<RwLock<HashMap<String, String>>>>,

    /// Hostname-to-routing-id index for virtual host routing.
    ///
    /// Maps lowercase hostnames (no port) to routing IDs so that incoming
    /// requests with a matching `Host` header are internally rewritten to
    /// the corresponding `/scp/broadcast/<routing_id_hex>/site/<path>` route.
    /// Populated by `enable_broadcast_projection_with_site()` and depopulated
    /// by `disable_broadcast_projection()`.
    ///
    /// LOCK ORDERING: Always acquire `projected_contexts` before `hostname_index`.
    /// Read locks on `hostname_index` must be dropped before accessing `projected_contexts`.
    pub(crate) hostname_index: RwLock<HashMap<String, [u8; 32]>>,

    /// Default site routing ID for origin-root serving in `--self-host` mode.
    ///
    /// When `Some`, the virtual-host fallback serves bare-path requests
    /// (`GET /`, `GET /style.css`, `GET /<anything>`) from this routing ID's
    /// projected site whenever the request's `Host` header does not match any
    /// entry in [`hostname_index`](Self::hostname_index). This lets a single
    /// deployed self-host site be reached at the origin root (and via raw IP,
    /// where no `Host` matches), so a browser loading the embedded
    /// `index.html` resolves its root-absolute `/style.css` and `/app.js`
    /// references (§10.12.11). The routing ID is `SHA-256(context_id)` — the
    /// same value the explicit `/scp/broadcast/<rid>/site/...` route uses.
    ///
    /// `None` for the Full surface and for any node that has not designated a
    /// default site, in which case the fallback behaves exactly as before
    /// (404 on an unmatched host). Set once after the self-host deploy via
    /// [`ApplicationNode::set_default_site_routing_id`].
    ///
    /// Uses `std::sync::RwLock` (not tokio): it is written once after deploy
    /// and read in the synchronous tail of the async fallback handler, where
    /// the critical section is a single `Option` copy with no `.await`.
    pub(crate) default_site_routing_id: std::sync::RwLock<Option<[u8; 32]>>,

    /// Shared state for bridge shadow operations.
    ///
    /// Holds per-context shadow registries and sender key stores for the
    /// bridge shadow creation endpoint (`POST /v1/scp/bridge/shadow`).
    /// See SCP-BCH-002.
    pub(crate) bridge_state: Arc<crate::bridge_handlers::BridgeState>,

    /// Production bridge lookup for bridge auth middleware (spec section 12.10.2).
    ///
    /// When `Some`, the bridge router is wrapped with [`bridge_auth_middleware`]
    /// and [`webhook_auth_middleware`] using this lookup. When `None` (e.g., in
    /// tests or when bridges are not configured), the bridge router is mounted
    /// without authentication.
    pub(crate) bridge_lookup: Option<Arc<dyn crate::bridge_auth::BridgeLookup>>,

    /// Shared PUBLISH rate limiter from the relay server.
    ///
    /// Cloned from the WebSocket relay so the QUIC listener enforces the same
    /// per-IP PUBLISH budget across both transports (unified rate limiting,
    /// ADR-037 AC3, spec §10.14.3). Only present when the `quic` feature is
    /// enabled, since it is consumed exclusively by the QUIC listener.
    #[cfg(feature = "quic")]
    pub(crate) publish_rate_limiter: PublishRateLimiter,

    /// Shared DID-record slot index from the relay server.
    ///
    /// Cloned from the WebSocket relay so the QUIC listener enforces DID-record
    /// slot-exclusivity over the SAME claimed-slot index as WebSocket (§3.10.2,
    /// ADR-004, SCP-RELAYRES-003). Without sharing this, a QUIC PUBLISH would
    /// bypass the registry and co-locate junk with the genuine slot in the shared
    /// blob store. Only present when the `quic` feature is enabled, since it is
    /// consumed exclusively by the QUIC listener.
    #[cfg(feature = "quic")]
    pub(crate) did_slot_registry: scp_transport::native::did_slot::DidSlotRegistry,

    /// Pre-built QUIC server config for the relay-side QUIC listener.
    ///
    /// `Some` only in domain mode with a provisioned TLS certificate: the same
    /// certificate that terminates WSS also authenticates QUIC, so the relay
    /// cert covers both protocols (spec §10.14.3 item 1). `None` in no-domain
    /// mode (plaintext `ws://`, no certificate) — QUIC requires TLS and is not
    /// served there.
    ///
    /// When `Some`, [`ApplicationNode::serve`] starts a [`QuicListener`] bound
    /// to UDP on the same port as the WebSocket TCP listener, sharing this
    /// node's [`SubscriptionRegistry`], [`BlobStorageBackend`], and
    /// [`ConnectionTracker`] (spec §10.14.3 item 2: cross-transport delivery).
    ///
    /// [`QuicListener`]: scp_transport::quic::listener::QuicListener
    #[cfg(feature = "quic")]
    pub(crate) quic_server_config: Option<quinn::ServerConfig>,

    /// Whether the relay-side QUIC listener actually bound and started.
    ///
    /// Set to `true` by [`ApplicationNode::serve`] only after
    /// [`spawn_quic_listener`] reports a successful UDP bind, and stays `false`
    /// if the bind fails (port held, permission denied) or no
    /// [`quic_server_config`](Self::quic_server_config) is present. This is the
    /// value `.well-known/scp` reads to decide whether to advertise `"quic"`, so
    /// the advertisement reflects the *running* listener — not merely that the
    /// config was built. Closes the advertise-but-don't-serve gap for the
    /// bind-failure case (spec §10.14.3 item 1).
    #[cfg(feature = "quic")]
    pub(crate) quic_listening: std::sync::atomic::AtomicBool,
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
const BRIDGE_IDLE_TIMEOUT: Duration = Duration::from_mins(5);

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

    /// Returns an axum [`Router`] serving bridge endpoints.
    ///
    /// Includes `POST /v1/scp/bridge/shadow` for shadow identity creation.
    /// Requires bridge authentication middleware to be applied by the caller.
    ///
    /// See SCP-BCH-002 and spec section 12.10.
    #[must_use = "returns the bridge router, which must be mounted into an axum application"]
    pub fn bridge_router(&self) -> Router {
        crate::bridge_handlers::bridge_router(Arc::clone(&self.state.bridge_state))
    }

    /// Returns the dev API router if the dev API is enabled.
    ///
    /// Returns `Some(Router)` when `NodeConfig::local_api` was set (i.e., a
    /// dev token was generated), `None` otherwise. The
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
    /// `Node::start` (domain mode with successful ACME or
    /// injected TLS provider), `serve()` terminates TLS using
    /// [`tokio_rustls::TlsAcceptor`] and serves HTTPS/WSS. When no TLS
    /// configuration is present (no-domain mode, or TLS provisioning opted
    /// out), `serve()` falls back to plain HTTP/WS. See spec section 18.6.3.
    ///
    /// ## Dev API
    ///
    /// When the dev API is configured (via `NodeConfig::local_api`),
    /// a separate tokio task is spawned to serve the dev API on the configured
    /// address. The dev API listener runs concurrently with the public
    /// listener. When the dev API is not configured, `serve()` behaves exactly
    /// as before -- no additional listener is spawned. The dev API always
    /// uses plain HTTP (it is bound to loopback only).
    ///
    /// ## HTTP/3
    ///
    /// When the `http3` feature is enabled and an `Http3Config` is provided
    /// via `NodeConfig::http3`, an HTTP/3 listener is started
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
        self.serve_with_surface(app_router, crate::PublicSurface::Full, shutdown)
            .await
    }

    /// Like [`serve`](Self::serve) but restricts the public HTTP surface to
    /// the requested [`PublicSurface`](crate::PublicSurface).
    ///
    /// [`PublicSurface::Full`](crate::PublicSurface::Full) is identical to
    /// [`serve`](Self::serve). [`PublicSurface::SelfHost`](crate::PublicSurface::SelfHost)
    /// exposes ONLY the read-only website projection surface on the public
    /// bind — the relay upgrade (`/scp/v1`) and bridge routes
    /// (`/v1/scp/bridge/*`) are not mounted, so anonymous internet clients
    /// cannot reach the node's loopback relay or bridge through the public
    /// listener (§10.12.8).
    ///
    /// TLS termination, the dev API listener, and the HTTP/3 listener behave
    /// exactly as in [`serve`](Self::serve); the only difference is which SCP
    /// routes are merged onto the public listener.
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::Serve`] if either server cannot bind or
    /// encounters a fatal I/O error.
    pub async fn serve_with_surface(
        self,
        app_router: Router,
        surface: crate::PublicSurface,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), NodeError> {
        spawn_projection_rate_limit_cleanup(
            self.state.projection_rate_limiter.clone(),
            self.state.shutdown_token.clone(),
        );

        // Build the merged router for the requested public surface.
        let merged = self.build_scp_router_with_surface(app_router, surface);

        let dev_router = self
            .state
            .dev_token
            .clone()
            .map(|t| crate::dev_api::dev_router(Arc::clone(&self.state), t));
        let dev_bind_addr = self.state.dev_bind_addr;
        let tls_config = self.state.tls_config.clone();
        #[cfg(feature = "http3")]
        let http3_config = self.http3_config;

        let relay = self.relay;
        let state = self.state;

        let dev_api_handle = spawn_dev_api(dev_router, dev_bind_addr, state.shutdown_token.clone());

        // Spawn HTTP/3 listener when configured (spec section 10.15.1).
        #[cfg(feature = "http3")]
        if let Some(http3_config) = http3_config {
            spawn_http3_listener(http3_config, &state);
        }

        let listener = tokio::net::TcpListener::bind(state.http_bind_addr)
            .await
            .map_err(|e| NodeError::Serve(e.to_string()))?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| NodeError::Serve(e.to_string()))?;

        // Start the relay-side QUIC listener on the SAME port as the WebSocket
        // TCP listener, but UDP (spec §10.14.3 item 1). We start it after the
        // TCP bind so that, when `http_bind_addr` requests an OS-assigned port
        // (port 0), QUIC binds the *actual* bound port rather than a second,
        // unrelated OS-assigned port. Shares subscription + blob state with the
        // WebSocket relay (spec §10.14.3 item 2). No-op without the `quic`
        // feature or in no-domain mode (no TLS certificate).
        #[cfg(feature = "quic")]
        {
            // The bind is synchronous (it completes before `start()` returns),
            // so the flag is settled before the server future below is awaited
            // and before the first `.well-known/scp` request can be served.
            let started = spawn_quic_listener(&state, local_addr.port());
            state
                .quic_listening
                .store(started, std::sync::atomic::Ordering::Release);
        }
        let shutdown_token = state.shutdown_token.clone();
        let token = shutdown_token.clone();
        tokio::spawn(async move {
            shutdown.await;
            token.cancel();
        });

        let main_server = build_main_server(
            listener,
            merged,
            tls_config,
            shutdown_token.clone(),
            local_addr,
        );

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

/// Builds the bridge and webhook routers with appropriate auth middleware.
///
/// JWT-authenticated bridge routes use `bridge_auth_middleware_dyn` (Bearer
/// token). The webhook route uses `webhook_auth_middleware_dyn`
/// (`X-SCP-Signature` header). When no `BridgeLookup` is configured (dev
/// mode), both are mounted without authentication.
///
/// See spec section 12.10.2.
pub(crate) fn build_bridge_routers(
    bridge_state: &Arc<crate::bridge_handlers::BridgeState>,
    bridge_lookup: Option<&Arc<dyn crate::bridge_auth::BridgeLookup>>,
) -> (Router, Router) {
    let bridge = {
        let base = crate::bridge_handlers::bridge_router(Arc::clone(bridge_state));
        if let Some(lookup) = bridge_lookup {
            base.layer(axum::middleware::from_fn_with_state(
                Arc::clone(lookup),
                crate::bridge_auth::bridge_auth_middleware_dyn,
            ))
        } else {
            base
        }
    };
    let bridge_webhook = {
        let base = crate::bridge_handlers::bridge_webhook_router(Arc::clone(bridge_state));
        if let Some(lookup) = bridge_lookup {
            base.layer(axum::middleware::from_fn_with_state(
                Arc::clone(lookup),
                crate::bridge_auth::webhook_auth_middleware_dyn,
            ))
        } else {
            base
        }
    };
    (bridge, bridge_webhook)
}

/// Builds the merged axum router for `serve()`, combining SCP protocol
/// routes (well-known, relay, projection, ACME challenges) with the
/// application router. Extracted from `serve()` for clippy line limits.
///
/// Virtual host routing is implemented via a fallback handler that checks
/// incoming `Host` headers against registered site hostnames and internally
/// dispatches to the projection site handler. This runs *before* the default
/// 404, catching requests that did not match any explicit route.
///
/// **Note:** In axum 0.8, `Router::layer()` runs *after* routing and cannot
/// rewrite request URIs. Virtual host routing therefore uses `Router::fallback`
/// instead of middleware.
pub(crate) fn build_merged_router(
    app_router: Router,
    well_known: Router,
    relay_rt: Router,
    projection: Router,
    bridge: Router,
    bridge_webhook: Router,
    state: &Arc<NodeState>,
) -> Router {
    let merged = app_router
        .merge(well_known)
        .merge(relay_rt)
        .merge(projection)
        .merge(bridge)
        .merge(bridge_webhook);

    finalize_router(merged, state)
}

/// Builds the restricted public router for `--self-host` mode.
///
/// Mounts ONLY the read-only website surface: the caller's `app_router`,
/// `.well-known/scp`, the broadcast projection endpoints (`/scp/broadcast/*`,
/// including `/feed`, `/messages`, and `/site/*`), any configured ACME
/// challenge routes, and the virtual-host fallback. It deliberately does NOT
/// merge the relay upgrade router (`/scp/v1`) nor the bridge routers
/// (`/v1/scp/bridge/*`).
///
/// This is the security seam for §10.12.8: in self-host mode the node's own
/// loopback relay is reached in-process over `127.0.0.1` (the relay's listener
/// stays loopback), so the relay upgrade/bridge must never be exposed on the
/// public bind. An external client hitting `/scp/v1` or `/v1/scp/bridge/*` on
/// the self-host public listener therefore falls through to the virtual-host
/// fallback and receives 404 (no registered hostname matches those paths),
/// while the website projection routes serve normally.
///
/// **Caller note:** whatever `app_router` is passed IS exposed on the public
/// self-host bind. The self-host serve path
/// ([`serve_background_with_surface_tls`](crate::ApplicationNode::serve_background_with_surface_tls))
/// passes an EMPTY app router (`axum::Router::new()`), so the self-host surface
/// exposes NO app routes — in particular it does NOT expose `/metrics`. This is
/// deliberate: the self-host bind is a public, unauthenticated surface, and
/// unauthenticated Prometheus metrics there would leak operational detail. Do
/// not merge any sensitive, mutating, or operational routes into `app_router`
/// for the self-host surface.
pub(crate) fn build_self_host_router(
    app_router: Router,
    well_known: Router,
    projection: Router,
    state: &Arc<NodeState>,
) -> Router {
    let merged = app_router.merge(well_known).merge(projection);

    finalize_router(merged, state)
}

/// Mounts the ACME challenge router (when configured) and installs the
/// virtual-host fallback. Shared by [`build_merged_router`] and
/// [`build_self_host_router`] so both surfaces use the identical,
/// path-traversal-safe fallback.
fn finalize_router(merged: Router, state: &Arc<NodeState>) -> Router {
    // Mount ACME challenge router for renewal challenges (issue #305).
    // Serves `GET /.well-known/acme-challenge/{token}` so the ACME CA can
    // validate domain ownership during certificate renewal.
    let merged = if let Some(challenges) = &state.acme_challenges {
        merged.merge(tls::acme_challenge_router(Arc::clone(challenges)))
    } else {
        merged
    };

    // Virtual host fallback: when no explicit route matches, check if the
    // Host header maps to a registered site hostname. If so, internally
    // rewrite the URI and dispatch to the projection site handler.
    let vhost_state = Arc::clone(state);
    merged.fallback(move |req: axum::extract::Request| {
        virtual_host_fallback(req, Arc::clone(&vhost_state))
    })
}

/// Virtual host routing fallback.
///
/// Called for requests that did not match any explicit route. Reads the
/// `Host` header, strips the port, lowercases it, and looks it up in
/// [`NodeState::hostname_index`]. If a match is found, dispatches directly
/// to [`site_handler`](crate::projection::site_handler) with the resolved
/// routing ID and original request path.
///
/// If no match is found, returns 404.
///
/// **Security:** This is an internal dispatch only — no HTTP redirect is
/// issued. The dispatched path passes through `ContentPath` validation in
/// `site_handler`, which prevents path traversal.
///
/// CORS headers are intentionally not applied — virtual host sites are served
/// same-origin. Cross-origin access should use the explicit `/scp/broadcast/`
/// routes which include CORS.
async fn virtual_host_fallback(
    req: axum::extract::Request,
    state: Arc<NodeState>,
) -> axum::response::Response {
    // site_handler only serves GET content; reject other methods early
    // (before rate limiter check, to avoid wasting tokens).
    if req.method() != axum::http::Method::GET && req.method() != axum::http::Method::HEAD {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Enforce the same per-IP rate limit that protects the explicit
    // `/scp/broadcast/` projection routes. Without this, virtual-host
    // requests would bypass `projection_rate_limit_middleware`.
    let remote_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map_or(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            |ci| ci.0.ip(),
        );
    if !state.projection_rate_limiter.check(remote_ip).await {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }

    // Extract the Host header value. A missing/invalid Host header is not
    // fatal: it simply means no hostname can match, so we fall straight through
    // to the default-site lookup below (which serves the single self-host site
    // at the origin root, including raw-IP access where no Host matches).
    let host_value = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok());

    // Resolve the routing ID: first by Host header against the hostname index;
    // if that misses (or there is no usable Host), fall back to the default
    // site routing ID when one is configured (§10.12.11 origin-root serving).
    let routing_id = match host_value {
        Some(host_raw) => {
            // Strip port and lowercase.
            // IPv6 bracket notation (e.g., "[::1]:8080") requires finding the
            // closing bracket first; plain hostnames/IPv4 just split on ':'.
            let hostname = if host_raw.starts_with('[') {
                // IPv6 bracket notation: find closing bracket
                host_raw.find(']').map_or(host_raw, |i| &host_raw[..=i])
            } else {
                // IPv4 or plain hostname: strip optional ":port"
                host_raw.split(':').next().unwrap_or(host_raw)
            }
            .to_ascii_lowercase();

            let index = state.hostname_index.read().await;
            index.get(&hostname).copied()
        }
        None => None,
    };

    // Default-site fallback: when no hostname matched, serve the single
    // designated self-host site (set after deploy). This is what makes
    // `GET /`, `GET /style.css`, and raw-IP access resolve to the deployed
    // context at the origin root. `site_handler` maps an empty/`/` path to the
    // site's `index_path` and runs full `ContentPath` traversal protection,
    // decryption, ETag, and CSP — identical to the explicit site route.
    let routing_id = routing_id.or_else(|| {
        // Recover from a poisoned lock rather than swallowing it to `None`: the
        // stored value is a plain `Option<[u8; 32]>` with no invariant a panic
        // could corrupt, and silently disabling origin-root serving on poison
        // would 404 the whole site. Mirrors the setter's poison recovery.
        let guard = state
            .default_site_routing_id
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard
    });

    let Some(routing_id) = routing_id else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let routing_id_hex = crate::projection::hex_encode(&routing_id);

    // Extract the original path and strip leading '/'.
    let original_path = req.uri().path();
    let site_path = original_path
        .strip_prefix('/')
        .unwrap_or(original_path)
        .to_owned();

    // Dispatch directly to site_handler with the resolved routing ID and path.
    crate::projection::site_handler(
        State(state),
        Path((routing_id_hex, site_path)),
        req.headers().clone(),
    )
    .await
    .into_response()
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
// Main server construction (extracted for clippy::too_many_lines)
// ---------------------------------------------------------------------------

/// Builds the main server future, branching on TLS configuration.
///
/// Returns a boxed future that resolves when the server shuts down.
/// Extracted from `serve()` for clippy line limits.
fn build_main_server(
    listener: tokio::net::TcpListener,
    merged: Router,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    shutdown_token: CancellationToken,
    local_addr: SocketAddr,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), NodeError>> + Send>> {
    if let Some(tls_cfg) = tls_config {
        tracing::info!(
            addr = %local_addr, scheme = "HTTPS",
            "application node server started (TLS active)"
        );
        Box::pin(tls::serve_tls(listener, tls_cfg, merged, shutdown_token))
    } else {
        tracing::info!(
            addr = %local_addr, scheme = "HTTP",
            "application node server started (plain HTTP, broadcast projection endpoints active)"
        );
        Box::pin(async move {
            axum::serve(
                listener,
                merged.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_token.cancelled_owned())
            .await
            .map_err(|e| NodeError::Serve(e.to_string()))
        })
    }
}

// ---------------------------------------------------------------------------
// Projection rate limiter cleanup (extracted for clippy::too_many_lines)
// ---------------------------------------------------------------------------

/// Spawns the background cleanup loop for the projection rate limiter.
///
/// Evicts stale per-IP token buckets every 60 seconds (buckets idle for more
/// than 300 seconds). Runs until `shutdown_token` is cancelled.
pub(crate) fn spawn_projection_rate_limit_cleanup(
    limiter: PublishRateLimiter,
    shutdown_token: CancellationToken,
) {
    tokio::spawn(async move {
        limiter
            .cleanup_loop(
                Duration::from_mins(1),
                Duration::from_mins(5),
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
            blob_storage: Arc::new(BlobStorageBackend::in_memory()),
            relay_config: scp_transport::native::server::RelayConfig::default(),
            start_time: Instant::now(),
            http_bind_addr: SocketAddr::from(([0, 0, 0, 0], 8443)),
            shutdown_token: CancellationToken::new(),
            cors_origins,
            projection_rate_limiter: scp_transport::relay::rate_limit::PublishRateLimiter::new(
                1000,
            ),
            projection_ucan_cache: std::sync::RwLock::new(
                crate::projection::ProjectionUcanCache::new(),
            ),
            tls_config: None,
            cert_resolver: None,
            did_document: crate::NodeDidDocument::new(scp_did::DidDocument {
                context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
                id: "did:dht:cors_test".to_owned(),
                verification_method: vec![],
                authentication: vec![],
                assertion_method: vec![],
                also_known_as: vec![],
                service: vec![],
            }),
            connection_tracker: scp_transport::relay::rate_limit::new_connection_tracker(),
            subscription_registry: scp_transport::relay::subscription::new_registry(),
            acme_challenges: None,
            hostname_index: RwLock::new(HashMap::new()),
            default_site_routing_id: std::sync::RwLock::new(None),
            bridge_state: Arc::new(crate::bridge_handlers::BridgeState::new()),
            bridge_lookup: None,
            #[cfg(feature = "quic")]
            publish_rate_limiter: scp_transport::relay::rate_limit::PublishRateLimiter::new(100),
            #[cfg(feature = "quic")]
            did_slot_registry: scp_transport::native::did_slot::DidSlotRegistry::new(),
            #[cfg(feature = "quic")]
            quic_server_config: None,
            #[cfg(feature = "quic")]
            quic_listening: std::sync::atomic::AtomicBool::new(false),
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

// ---------------------------------------------------------------------------
// Virtual host routing tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod vhost_tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Instant;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tokio::sync::RwLock;
    use tower::ServiceExt;
    use zeroize::Zeroizing;

    use scp_core::context::broadcast::BroadcastAdmission;
    use scp_core::context::broadcast_content::{
        BROADCAST_CONTENT_VERSION, BroadcastContent, ContentMetadata, ContentPath, MimeType,
    };
    use scp_core::crypto::sender_keys::generate_broadcast_key;
    use scp_transport::native::storage::{BlobStorageBackend, InMemoryBlobStorage};

    use crate::http::NodeState;
    use crate::projection::test_helpers::{entry_for, store_content_blob};
    use crate::projection::{
        ProjectedContext, SiteConfig, broadcast_projection_router, hex_encode,
    };

    /// Creates a test `NodeState` with the given projected contexts, blob
    /// storage, and hostname index.
    fn test_state_with_vhost(
        projected: HashMap<[u8; 32], ProjectedContext>,
        storage: InMemoryBlobStorage,
        hostname_index: HashMap<String, [u8; 32]>,
    ) -> Arc<NodeState> {
        Arc::new(NodeState {
            did: "did:dht:vhost_test".to_owned(),
            relay_url: "wss://localhost/scp/v1".to_owned(),
            broadcast_contexts: RwLock::new(HashMap::new()),
            relay_addr: "127.0.0.1:9000".parse::<SocketAddr>().unwrap(),
            bridge_secret: Zeroizing::new([0u8; 32]),
            dev_token: None,
            dev_bind_addr: None,
            projected_contexts: RwLock::new(projected),
            blob_storage: Arc::new(BlobStorageBackend::from(storage)),
            relay_config: scp_transport::native::server::RelayConfig::default(),
            start_time: Instant::now(),
            http_bind_addr: SocketAddr::from(([0, 0, 0, 0], 8443)),
            shutdown_token: tokio_util::sync::CancellationToken::new(),
            cors_origins: None,
            projection_rate_limiter: scp_transport::relay::rate_limit::PublishRateLimiter::new(
                1000,
            ),
            projection_ucan_cache: std::sync::RwLock::new(
                crate::projection::ProjectionUcanCache::new(),
            ),
            tls_config: None,
            cert_resolver: None,
            did_document: crate::NodeDidDocument::new(scp_did::DidDocument {
                context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
                id: "did:dht:vhost_test".to_owned(),
                verification_method: vec![],
                authentication: vec![],
                assertion_method: vec![],
                also_known_as: vec![],
                service: vec![],
            }),
            connection_tracker: scp_transport::relay::rate_limit::new_connection_tracker(),
            subscription_registry: scp_transport::relay::subscription::new_registry(),
            acme_challenges: None,
            hostname_index: RwLock::new(hostname_index),
            default_site_routing_id: std::sync::RwLock::new(None),
            bridge_state: Arc::new(crate::bridge_handlers::BridgeState::new()),
            bridge_lookup: None,
            #[cfg(feature = "quic")]
            publish_rate_limiter: scp_transport::relay::rate_limit::PublishRateLimiter::new(100),
            #[cfg(feature = "quic")]
            did_slot_registry: scp_transport::native::did_slot::DidSlotRegistry::new(),
            #[cfg(feature = "quic")]
            quic_server_config: None,
            #[cfg(feature = "quic")]
            quic_listening: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Sets up a projected context with site config and a deployed index.html,
    /// returning (state, `routing_id`).
    async fn setup_site_context(hostname: &str, ctx_id: &str) -> (Arc<NodeState>, [u8; 32]) {
        let key = generate_broadcast_key("did:dht:alice");
        let mut projected =
            ProjectedContext::new(ctx_id, key.clone(), BroadcastAdmission::Open, None);
        projected.set_site_config(SiteConfig {
            hostname: hostname.to_owned(),
            ..SiteConfig::default()
        });
        let routing_id = *projected.routing_id();

        let storage = InMemoryBlobStorage::new();

        let content = BroadcastContent {
            version: BROADCAST_CONTENT_VERSION,
            metadata: ContentMetadata {
                path: Some(ContentPath::new("/index.html").unwrap()),
                content_type: Some(MimeType::new("text/html").unwrap()),
                deploy_id: Some("deploy-1".into()),
                etag: None,
                immutable: false,
            },
            body: b"<h1>Hello from vhost</h1>".to_vec(),
        };

        let blob_id = store_content_blob(&storage, routing_id, &key, &content).await;

        let path = ContentPath::new("/index.html").unwrap();
        let mut entries = HashMap::new();
        entries.insert(path, entry_for(blob_id, &content));
        projected.commit_deploy("deploy-1".into(), entries);

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let mut hostname_index = HashMap::new();
        hostname_index.insert(hostname.to_ascii_lowercase(), routing_id);

        let state = test_state_with_vhost(projected_map, storage, hostname_index);
        (state, routing_id)
    }

    /// Builds a router with virtual host fallback applied, matching the
    /// production `build_merged_router` behavior.
    fn build_vhost_router(state: &Arc<NodeState>) -> axum::Router {
        let projection = broadcast_projection_router(Arc::clone(state));
        let vhost_state = Arc::clone(state);
        projection.fallback(move |req: axum::extract::Request| {
            super::virtual_host_fallback(req, Arc::clone(&vhost_state))
        })
    }

    #[tokio::test]
    async fn vhost_routes_to_correct_context_content() {
        let (state, _routing_id) = setup_site_context("mysite.example.com", "vhost_ctx_1").await;
        let router = build_vhost_router(&state);

        // Request with Host header matching the registered hostname.
        let req = Request::builder()
            .uri("/index.html")
            .header("Host", "mysite.example.com")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"<h1>Hello from vhost</h1>");
    }

    #[tokio::test]
    async fn vhost_strips_port() {
        let (state, _routing_id) = setup_site_context("localhost", "vhost_port_ctx").await;
        let router = build_vhost_router(&state);

        // Host: localhost:8080 should match "localhost".
        let req = Request::builder()
            .uri("/index.html")
            .header("Host", "localhost:8080")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"<h1>Hello from vhost</h1>");
    }

    #[tokio::test]
    async fn vhost_case_insensitive() {
        let (state, _routing_id) = setup_site_context("localhost", "vhost_case_ctx").await;
        let router = build_vhost_router(&state);

        // Host: LOCALHOST should match "localhost".
        let req = Request::builder()
            .uri("/index.html")
            .header("Host", "LOCALHOST")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn vhost_unknown_host_falls_through() {
        let (state, _routing_id) =
            setup_site_context("mysite.example.com", "vhost_unknown_ctx").await;
        let router = build_vhost_router(&state);

        // Unknown hostname should fall through to normal routing (404).
        let req = Request::builder()
            .uri("/index.html")
            .header("Host", "unknown.example.com")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn vhost_no_cross_context_routing() {
        // Set up two contexts with different hostnames and different content.
        let key_a = generate_broadcast_key("did:dht:alice");
        let key_b = generate_broadcast_key("did:dht:bob");

        let ctx_id_a = "vhost_cross_a";
        let ctx_id_b = "vhost_cross_b";

        let mut projected_a =
            ProjectedContext::new(ctx_id_a, key_a.clone(), BroadcastAdmission::Open, None);
        projected_a.set_site_config(SiteConfig {
            hostname: "site-a.example.com".into(),
            ..SiteConfig::default()
        });
        let routing_id_a = *projected_a.routing_id();

        let mut projected_b =
            ProjectedContext::new(ctx_id_b, key_b.clone(), BroadcastAdmission::Open, None);
        projected_b.set_site_config(SiteConfig {
            hostname: "site-b.example.com".into(),
            ..SiteConfig::default()
        });
        let routing_id_b = *projected_b.routing_id();

        let storage = InMemoryBlobStorage::new();

        // Content for A: "Content A".
        let bc_a = BroadcastContent {
            version: BROADCAST_CONTENT_VERSION,
            metadata: ContentMetadata {
                path: Some(ContentPath::new("/index.html").unwrap()),
                content_type: Some(MimeType::new("text/html").unwrap()),
                deploy_id: Some("deploy-a".into()),
                etag: None,
                immutable: false,
            },
            body: b"Content A".to_vec(),
        };
        let blob_id_a = store_content_blob(&storage, routing_id_a, &key_a, &bc_a).await;
        let path_a = ContentPath::new("/index.html").unwrap();
        let mut entries_a = HashMap::new();
        entries_a.insert(path_a, entry_for(blob_id_a, &bc_a));
        projected_a.commit_deploy("deploy-a".into(), entries_a);

        // Content for B: "Content B".
        let bc_b = BroadcastContent {
            version: BROADCAST_CONTENT_VERSION,
            metadata: ContentMetadata {
                path: Some(ContentPath::new("/index.html").unwrap()),
                content_type: Some(MimeType::new("text/html").unwrap()),
                deploy_id: Some("deploy-b".into()),
                etag: None,
                immutable: false,
            },
            body: b"Content B".to_vec(),
        };
        let blob_id_b = store_content_blob(&storage, routing_id_b, &key_b, &bc_b).await;
        let path_b = ContentPath::new("/index.html").unwrap();
        let mut entries_b = HashMap::new();
        entries_b.insert(path_b, entry_for(blob_id_b, &bc_b));
        projected_b.commit_deploy("deploy-b".into(), entries_b);

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id_a, projected_a);
        projected_map.insert(routing_id_b, projected_b);

        let mut hostname_index = HashMap::new();
        hostname_index.insert("site-a.example.com".to_owned(), routing_id_a);
        hostname_index.insert("site-b.example.com".to_owned(), routing_id_b);

        let state = test_state_with_vhost(projected_map, storage, hostname_index);
        let router = build_vhost_router(&state);

        // Request to site-a should return "Content A".
        let req_a = Request::builder()
            .uri("/index.html")
            .header("Host", "site-a.example.com")
            .body(Body::empty())
            .unwrap();
        let resp_a = router.clone().oneshot(req_a).await.unwrap();
        assert_eq!(resp_a.status(), axum::http::StatusCode::OK);
        let body_a = resp_a.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_a.as_ref(), b"Content A");

        // Request to site-b should return "Content B".
        let req_b = Request::builder()
            .uri("/index.html")
            .header("Host", "site-b.example.com")
            .body(Body::empty())
            .unwrap();
        let resp_b = router.oneshot(req_b).await.unwrap();
        assert_eq!(resp_b.status(), axum::http::StatusCode::OK);
        let body_b = resp_b.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_b.as_ref(), b"Content B");
    }

    #[tokio::test]
    async fn vhost_path_traversal_attempt() {
        let (state, _routing_id) =
            setup_site_context("evil.example.com", "vhost_traversal_ctx").await;
        let router = build_vhost_router(&state);

        // Path traversal attempt: /../../../etc/passwd
        // The rewritten URI goes through site_handler which validates via
        // ContentPath, rejecting traversal.
        let req = Request::builder()
            .uri("/../../../etc/passwd")
            .header("Host", "evil.example.com")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        // ContentPath validation should reject this path and return 404.
        assert_ne!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn vhost_does_not_rewrite_scp_paths() {
        let (state, routing_id) =
            setup_site_context("mysite.example.com", "vhost_scp_path_ctx").await;
        let router = build_vhost_router(&state);

        // Explicit /scp/ paths should not be rewritten (would cause
        // double-rewriting). The explicit route should handle it directly.
        let routing_hex = hex_encode(&routing_id);
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/site/index.html"))
            .header("Host", "mysite.example.com")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        // Should still succeed because the explicit route handles it.
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn vhost_no_host_header_falls_through() {
        let (state, _routing_id) =
            setup_site_context("mysite.example.com", "vhost_no_host_ctx").await;
        let router = build_vhost_router(&state);

        // No Host header: should fall through (404 since no explicit route
        // matches "/index.html").
        let req = Request::builder()
            .uri("/index.html")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn vhost_root_path_maps_to_index() {
        let (state, _routing_id) = setup_site_context("mysite.example.com", "vhost_root_ctx").await;
        let router = build_vhost_router(&state);

        // Root path "/" should map to index.html via site_handler.
        let req = Request::builder()
            .uri("/")
            .header("Host", "mysite.example.com")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"<h1>Hello from vhost</h1>");
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
/// `relay_config`, contexts, handles, and transports (SCP-264).
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

    // Share the node's connection tracker so the HTTP/3 listener enforces the
    // same per-IP connection limits as the WebSocket and QUIC relay listeners
    // (spec §10.14.3 item 2: uniform cross-transport tracking).
    let connection_tracker = state.connection_tracker.clone();

    tokio::spawn(async move {
        let mut server = Http3Server::new(http3_config, handler);
        match server.bind() {
            Ok(addr) => {
                tracing::info!(addr = %addr, "HTTP/3 server started");
                if let Err(e) = server.serve(connection_tracker).await {
                    tracing::error!(error = %e, "HTTP/3 server exited with error");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to bind HTTP/3 server");
            }
        }
    });
}

/// Starts the relay-side QUIC listener when a QUIC server config is present.
///
/// The listener binds UDP on the **same port** as the WebSocket TCP listener
/// (`tcp_port`, the actually-bound port of the public TLS listener), so a relay
/// accepts QUIC and WebSocket on one TLS port (spec §10.14.3 item 1). It shares
/// this node's [`SubscriptionRegistry`], [`BlobStorageBackend`],
/// [`ConnectionTracker`], and PUBLISH rate limiter with the WebSocket relay, so
/// a QUIC subscriber receives blobs published over WebSocket and vice-versa
/// (spec §10.14.3 item 2).
///
/// Returns `true` if the listener was started, `false` otherwise (no config, or
/// bind failure — in which case the node degrades to WebSocket-only).
///
/// The listener's lifecycle is tied to `state.shutdown_token`: a small task
/// awaits cancellation and then signals the QUIC listener to stop, so
/// [`ApplicationNode::shutdown`] (and `serve()`'s graceful shutdown) stop both
/// transports together.
#[cfg(feature = "quic")]
fn spawn_quic_listener(state: &Arc<NodeState>, tcp_port: u16) -> bool {
    use scp_transport::quic::listener::{QuicListener, QuicListenerConfig};

    let Some(server_config) = state.quic_server_config.clone() else {
        return false;
    };

    // Bind UDP on the same interface and port as the public WebSocket/TLS
    // listener so both transports share one address (spec §10.14.3 item 1).
    let bind_addr = SocketAddr::new(state.http_bind_addr.ip(), tcp_port);

    // Mirror the relay's operational limits so QUIC and WebSocket enforce the
    // same policy.
    let rc = &state.relay_config;
    let config = QuicListenerConfig {
        bind_addr,
        max_blob_size: rc.max_blob_size,
        max_blob_ttl: rc.max_blob_ttl,
        max_subscriptions_per_connection: rc.max_subscriptions_per_connection,
        max_query_limit: rc.max_query_limit,
        max_connections_per_ip: rc.max_connections_per_ip,
        max_total_connections: rc.max_total_connections,
        rate_limit_publishes_per_second: rc.rate_limit_publishes_per_second,
        rate_limit_subscribes_per_minute: rc.rate_limit_subscribes_per_minute,
        delivery_jitter_ms: rc.delivery_jitter_ms,
        // Match the co-deployed WebSocket relay's DID-record validation mode so
        // slot-exclusivity is consistent across both transports on the shared
        // store (§3.10.2). The listener also shares the relay's slot registry
        // below — the two together honor one set of claimed slots.
        did_record_validation: rc.did_record_validation,
    };

    let listener = QuicListener::new(
        config,
        Arc::clone(&state.blob_storage),
        state.subscription_registry.clone(),
        state.publish_rate_limiter.clone(),
        state.connection_tracker.clone(),
        state.did_slot_registry.clone(),
    );

    match listener.start(server_config) {
        Ok((quic_handle, local_addr)) => {
            tracing::info!(addr = %local_addr, "relay QUIC listener started");
            // Bridge the node's cancellation token to the QUIC shutdown handle so
            // graceful shutdown stops both transports.
            let shutdown_token = state.shutdown_token.clone();
            tokio::spawn(async move {
                shutdown_token.cancelled().await;
                quic_handle.shutdown();
            });
            true
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to start relay QUIC listener — serving WebSocket only");
            false
        }
    }
}
