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
use std::time::Instant;

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use futures::{SinkExt, StreamExt};
use tokio::sync::RwLock;

use scp_platform::traits::Storage;
use scp_transport::native::server::RelayConfig as TransportRelayConfig;
use scp_transport::native::storage::{BlobStorage, InMemoryBlobStorage};

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
/// # Type parameter
///
/// `B` is the blob storage backend, shared between the relay server and
/// projection handlers via `Arc<B>` (spec section 18.11.5).
pub struct NodeState<B: BlobStorage = InMemoryBlobStorage> {
    /// The operator's DID string.
    pub(crate) did: String,
    /// The relay URL (e.g., `wss://example.com/scp/v1`).
    pub(crate) relay_url: String,
    /// Registered broadcast contexts. Modified via
    /// [`ApplicationNode::register_broadcast_context`].
    pub(crate) broadcast_contexts: RwLock<Vec<BroadcastContext>>,
    /// The relay server's bound address for WebSocket bridge connections.
    pub(crate) relay_addr: SocketAddr,
    /// Shared secret for authenticating internal bridge connections.
    ///
    /// Generated at startup and included as a query parameter when the
    /// axum handler connects to the internal relay. The relay validates
    /// this token during the WebSocket handshake (defense-in-depth, #85).
    pub(crate) bridge_secret: [u8; 32],
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
    pub(crate) blob_storage: Arc<B>,
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
}

// ---------------------------------------------------------------------------
// Router constructors
// ---------------------------------------------------------------------------

/// Returns an axum [`Router`] serving `GET /.well-known/scp`.
///
/// The handler dynamically generates the `.well-known/scp` JSON document
/// from the provided [`NodeState`]. See spec section 18.3.
pub fn well_known_router<B: BlobStorage + 'static>(state: Arc<NodeState<B>>) -> Router {
    Router::new()
        .route("/.well-known/scp", get(well_known_handler::<B>))
        .with_state(state)
}

/// Returns an axum [`Router`] handling WebSocket upgrade at `/scp/v1`.
///
/// Incoming WebSocket connections are bridged to the node's internal
/// relay server. The axum handler upgrades the HTTP connection to
/// WebSocket, then connects to the relay on localhost and forwards
/// frames bidirectionally.
pub fn relay_router<B: BlobStorage + 'static>(state: Arc<NodeState<B>>) -> Router {
    Router::new()
        .route("/scp/v1", get(ws_upgrade_handler::<B>))
        .with_state(state)
}

/// Axum handler for WebSocket upgrade at `/scp/v1`.
///
/// Bridges the incoming WebSocket connection to the node's internal
/// relay server by connecting to `relay_addr` on localhost, authenticated
/// with the bridge secret.
async fn ws_upgrade_handler<B: BlobStorage + 'static>(
    ws: WebSocketUpgrade,
    State(state): State<Arc<NodeState<B>>>,
) -> impl IntoResponse {
    let relay_addr = state.relay_addr;
    let bridge_secret = state.bridge_secret;
    ws.on_upgrade(move |socket| relay_bridge(socket, relay_addr, bridge_secret))
}

/// Bridges an axum WebSocket to the internal relay server.
///
/// Connects to the relay at `relay_addr` with the bridge secret included
/// as a `token` query parameter, then forwards frames in both directions
/// until either side closes. Sends explicit WebSocket close frames on
/// both sides when the bridge terminates.
async fn relay_bridge(axum_ws: WebSocket, relay_addr: SocketAddr, bridge_secret: [u8; 32]) {
    let token_hex = scp_transport::native::server::hex_encode_32(&bridge_secret);
    let url = format!("ws://{relay_addr}/?token={token_hex}");
    let relay_conn = tokio_tungstenite::connect_async(&url).await;

    let Ok((relay_ws, _)) = relay_conn else {
        tracing::error!(
            addr = %relay_addr,
            "failed to connect to internal relay for WebSocket bridge"
        );
        return;
    };

    let (relay_sink, mut relay_source) = relay_ws.split();
    let (axum_sink, mut axum_source) = axum_ws.split();

    // Wrap sinks in Arc<Mutex<>> so both forwarding tasks and the cleanup
    // code can access them. This is the minimal restructuring needed to
    // send explicit close frames after the select completes.
    let relay_sink = Arc::new(tokio::sync::Mutex::new(relay_sink));
    let axum_sink = Arc::new(tokio::sync::Mutex::new(axum_sink));

    let relay_sink_fwd = Arc::clone(&relay_sink);
    let axum_sink_fwd = Arc::clone(&axum_sink);

    // Forward: client (axum) -> relay
    let client_to_relay = async move {
        while let Some(Ok(msg)) = StreamExt::next(&mut axum_source).await {
            let relay_msg = match msg {
                Message::Text(t) => tokio_tungstenite::tungstenite::Message::Text(t.to_string()),
                Message::Binary(b) => tokio_tungstenite::tungstenite::Message::Binary(b.to_vec()),
                Message::Ping(p) => tokio_tungstenite::tungstenite::Message::Ping(p.to_vec()),
                Message::Pong(p) => tokio_tungstenite::tungstenite::Message::Pong(p.to_vec()),
                Message::Close(_) => return,
            };
            if let Err(e) = SinkExt::send(&mut *relay_sink_fwd.lock().await, relay_msg).await {
                tracing::debug!(
                    direction = "client->relay",
                    error = %e,
                    "bridge forwarding failed"
                );
                return;
            }
        }
    };

    // Forward: relay -> client (axum)
    let relay_to_client = async move {
        while let Some(Ok(msg)) = StreamExt::next(&mut relay_source).await {
            let axum_msg = match msg {
                tokio_tungstenite::tungstenite::Message::Text(t) => Message::Text(t.into()),
                tokio_tungstenite::tungstenite::Message::Binary(b) => Message::Binary(b.into()),
                tokio_tungstenite::tungstenite::Message::Ping(p) => Message::Ping(p.into()),
                tokio_tungstenite::tungstenite::Message::Pong(p) => Message::Pong(p.into()),
                tokio_tungstenite::tungstenite::Message::Close(_) => return,
                tokio_tungstenite::tungstenite::Message::Frame(_) => continue,
            };
            if let Err(e) = SinkExt::send(&mut *axum_sink_fwd.lock().await, axum_msg).await {
                tracing::debug!(
                    direction = "relay->client",
                    error = %e,
                    "bridge forwarding failed"
                );
                return;
            }
        }
    };

    // Run both directions concurrently; when either side finishes, close both
    // sinks with explicit WebSocket close frames. SplitSink::drop() does NOT
    // send close frames in tokio-tungstenite 0.24.
    tokio::select! {
        () = client_to_relay => {}
        () = relay_to_client => {}
    }

    // Send explicit close frames (best-effort, ignore errors on close).
    let _ = SinkExt::close(&mut *relay_sink.lock().await).await;
    let _ = SinkExt::close(&mut *axum_sink.lock().await).await;
}

// ---------------------------------------------------------------------------
// ApplicationNode HTTP methods
// ---------------------------------------------------------------------------

impl<S: Storage + Send + Sync + 'static, B: BlobStorage + 'static> ApplicationNode<S, B> {
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

    /// Binds HTTPS on the configured address, merging:
    ///
    /// 1. Application-provided routes (`app_router`)
    /// 2. `.well-known/scp` route
    /// 3. `/scp/v1` WebSocket upgrade route
    /// 4. `/scp/broadcast/*` broadcast projection routes
    ///
    /// SCP routes take precedence for `/.well-known/scp`, `/scp/v1`, and
    /// `/scp/broadcast/*`. All other paths route to `app_router`.
    ///
    /// This method consumes the node. Callers that need to retain access
    /// to the relay's [`ShutdownHandle`] should extract it before calling
    /// `serve` (via [`ApplicationNode::relay`]).
    ///
    /// When the dev API is configured (via [`ApplicationNodeBuilder::local_api`]),
    /// a separate tokio task is spawned to serve the dev API on the configured
    /// address. The dev API listener runs concurrently with the public HTTPS
    /// listener. When the dev API is not configured, `serve()` behaves exactly
    /// as before -- no additional listener is spawned.
    ///
    /// See spec sections 18.10.5 and 18.11.8.
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::Serve`] if the server cannot bind or encounters
    /// a fatal I/O error.
    pub async fn serve(self, app_router: Router) -> Result<(), NodeError> {
        let well_known = self.well_known_router();
        let relay = self.relay_router();
        let projection = self.broadcast_projection_router();

        // Extract dev API configuration before building the merged router.
        let dev_router = self.dev_router();
        let dev_bind_addr = self.state.dev_bind_addr;

        // SCP routes take precedence: merge them last so they override
        // any conflicting paths in app_router.
        let merged = app_router.merge(well_known).merge(relay).merge(projection);

        // Spawn the dev API listener if configured.
        if let (Some(dev_router), Some(dev_addr)) = (dev_router, dev_bind_addr) {
            tokio::spawn(async move {
                match tokio::net::TcpListener::bind(dev_addr).await {
                    Ok(dev_listener) => {
                        let local_addr = dev_listener.local_addr().unwrap_or(dev_addr);
                        tracing::info!(
                            addr = %local_addr,
                            "dev API server started"
                        );
                        if let Err(e) = axum::serve(dev_listener, dev_router).await {
                            tracing::error!(
                                error = %e,
                                "dev API server exited with error"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            addr = %dev_addr,
                            error = %e,
                            "failed to bind dev API server"
                        );
                    }
                }
            });
        }

        let bind_addr = self.state.http_bind_addr;

        let listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .map_err(|e| NodeError::Serve(e.to_string()))?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| NodeError::Serve(e.to_string()))?;

        tracing::info!(
            addr = %local_addr,
            "application node HTTP server started (broadcast projection endpoints active)"
        );

        axum::serve(listener, merged)
            .await
            .map_err(|e| NodeError::Serve(e.to_string()))?;

        Ok(())
    }
}
