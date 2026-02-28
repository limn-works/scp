//! HTTP routing for [`ApplicationNode`].
//!
//! Provides axum routers for `.well-known/scp` and `/scp/v1` WebSocket
//! upgrade, plus the `serve()` method that merges application routes with
//! SCP routes on a single HTTPS listener.
//!
//! See spec section 18.6.2 for the SDK surface.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use futures::{SinkExt, StreamExt};
use tokio::sync::RwLock;

use scp_platform::traits::Storage;

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
/// Contains the node's identity information and registered broadcast
/// contexts. Read on every `.well-known/scp` request to generate
/// the response dynamically (spec section 18.6.4).
pub struct NodeState {
    /// The operator's DID string.
    pub(crate) did: String,
    /// The relay URL (e.g., `wss://example.com/scp/v1`).
    pub(crate) relay_url: String,
    /// Registered broadcast contexts. Modified via
    /// [`ApplicationNode::register_broadcast_context`].
    pub(crate) broadcast_contexts: RwLock<Vec<BroadcastContext>>,
    /// The relay server's bound address for WebSocket bridge connections.
    pub(crate) relay_addr: SocketAddr,
}

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
pub fn relay_router(state: Arc<NodeState>) -> Router {
    Router::new()
        .route("/scp/v1", get(ws_upgrade_handler))
        .with_state(state)
}

/// Axum handler for WebSocket upgrade at `/scp/v1`.
///
/// Bridges the incoming WebSocket connection to the node's internal
/// relay server by connecting to `relay_addr` on localhost.
async fn ws_upgrade_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<NodeState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| relay_bridge(socket, state.relay_addr))
}

/// Bridges an axum WebSocket to the internal relay server.
///
/// Connects to the relay at `relay_addr`, then forwards frames in
/// both directions until either side closes. Sends explicit WebSocket
/// close frames on both sides when the bridge terminates.
async fn relay_bridge(axum_ws: WebSocket, relay_addr: SocketAddr) {
    let url = format!("ws://{relay_addr}");
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

    /// Binds HTTPS on the configured address, merging:
    ///
    /// 1. Application-provided routes (`app_router`)
    /// 2. `.well-known/scp` route
    /// 3. `/scp/v1` WebSocket upgrade route
    ///
    /// SCP routes take precedence for `/.well-known/scp` and `/scp/v1`.
    /// All other paths route to `app_router`.
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::Serve`] if the server cannot bind or encounters
    /// a fatal I/O error.
    pub async fn serve(self, app_router: Router) -> Result<(), NodeError> {
        let well_known = self.well_known_router();
        let relay = self.relay_router();

        // SCP routes take precedence: merge them last so they override
        // any conflicting paths in app_router.
        let merged = app_router.merge(well_known).merge(relay);

        let bind_addr = self.relay.bound_addr;

        let listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .map_err(|e| NodeError::Serve(e.to_string()))?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| NodeError::Serve(e.to_string()))?;

        tracing::info!(
            addr = %local_addr,
            "application node HTTP server started"
        );

        axum::serve(listener, merged)
            .await
            .map_err(|e| NodeError::Serve(e.to_string()))?;

        Ok(())
    }
}
