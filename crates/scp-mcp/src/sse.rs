//! SSE (Server-Sent Events) transport for the MCP server.
//!
//! Implements the MCP SSE transport mode: an HTTP server that serves an SSE
//! endpoint for server-to-client messages and a POST endpoint for
//! client-to-server JSON-RPC requests. This transport is suitable for remote
//! and web-based MCP integrations.
//!
//! ## Endpoints
//!
//! - `GET /sse` -- SSE stream for server-to-client messages (responses,
//!   notifications). The server sends an initial `endpoint` event with the
//!   POST URL, then streams `message` events containing JSON-RPC responses.
//!   Each event carries a sequential `id:` field so reconnecting clients can
//!   resume via the `Last-Event-ID` header.
//! - `POST /message` -- Accepts JSON-RPC requests from the client. Responses
//!   are delivered via the SSE stream, not in the HTTP response body.
//!
//! ## Reconnection
//!
//! The server assigns monotonically increasing IDs to every `message` event.
//! When a client reconnects with a `Last-Event-ID` header, events that were
//! broadcast after that ID are replayed from a bounded ring buffer before
//! live streaming resumes. The server also emits a `retry:` field so clients
//! respect a server-controlled reconnection interval.
//!
//! ## Keep-alive
//!
//! The SSE stream sends periodic comment-only keep-alive frames (`: keepalive`)
//! to prevent intermediate proxies from closing idle connections.
//!
//! ## Shutdown
//!
//! [`run_sse`] accepts a [`ShutdownHandle`] that signals the server to stop
//! accepting new connections. Existing SSE streams drain naturally.
//!
//! See ADR-015 in `.docs/adrs/phase-3.md` for the full design.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::{get, post};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, RwLock, broadcast};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tokio_util::sync::CancellationToken;

use crate::protocol::{
    JsonRpcError, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, PARSE_ERROR, RequestId,
};
use crate::server::{ContextProvider, McpServer};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Default retry interval (milliseconds) sent to SSE clients.
const DEFAULT_RETRY_MS: u64 = 3000;

/// Default capacity for the replay buffer (number of events retained).
const DEFAULT_REPLAY_CAPACITY: usize = 256;

/// Configuration for the SSE transport server.
#[derive(Debug, Clone)]
pub struct SseConfig {
    /// The address to bind the HTTP server to (e.g., `127.0.0.1:3000`).
    pub bind_addr: SocketAddr,

    /// Capacity of the broadcast channel for SSE messages.
    /// Defaults to 256.
    pub channel_capacity: usize,

    /// Retry interval in milliseconds sent to clients via the `retry:` field.
    /// Clients should wait this long before reconnecting after a dropped
    /// connection. Defaults to 3000 (3 seconds).
    pub retry_ms: u64,

    /// Maximum number of events retained in the replay buffer for
    /// reconnecting clients. Defaults to 256.
    pub replay_capacity: usize,

    /// Optional bearer token for authenticating SSE and message requests.
    /// When `Some(token)`, all requests to `/sse` and `/message` must include
    /// an `Authorization: Bearer <token>` header. Unauthenticated requests
    /// receive HTTP 401 Unauthorized. When `None`, no authentication is
    /// required (backwards compatible).
    pub auth_token: Option<String>,
}

impl SseConfig {
    /// Creates a new configuration with the given bind address.
    #[must_use]
    pub const fn new(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            channel_capacity: 256,
            retry_ms: DEFAULT_RETRY_MS,
            replay_capacity: DEFAULT_REPLAY_CAPACITY,
            auth_token: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from the SSE transport.
#[derive(Debug, thiserror::Error)]
pub enum SseError {
    /// An I/O error occurred starting or running the HTTP server.
    #[error("SSE server error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Shutdown handle
// ---------------------------------------------------------------------------

/// Handle for gracefully shutting down a running SSE server.
///
/// Dropping the handle does **not** shut down the server. Call
/// [`shutdown`](Self::shutdown) explicitly. Existing SSE streams drain
/// naturally after shutdown is signaled.
#[derive(Debug, Clone)]
pub struct ShutdownHandle {
    token: CancellationToken,
}

impl ShutdownHandle {
    /// Creates a new shutdown handle.
    #[must_use]
    pub fn new() -> Self {
        Self {
            token: CancellationToken::new(),
        }
    }

    /// Signals the SSE server to stop accepting new connections.
    pub fn shutdown(&self) {
        self.token.cancel();
    }

    /// Returns `true` if shutdown has been signaled.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.token.is_cancelled()
    }
}

impl Default for ShutdownHandle {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Replay buffer
// ---------------------------------------------------------------------------

/// A bounded ring buffer of recent SSE events for reconnection replay.
#[derive(Debug)]
struct ReplayBuffer {
    events: VecDeque<ReplayEntry>,
    capacity: usize,
}

/// A single entry in the replay buffer.
#[derive(Debug, Clone)]
struct ReplayEntry {
    id: u64,
    data: String,
}

impl ReplayBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            events: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn push(&mut self, id: u64, data: String) {
        if self.events.len() == self.capacity {
            self.events.pop_front();
        }
        self.events.push_back(ReplayEntry { id, data });
    }

    fn events_after(&self, last_id: u64) -> Vec<ReplayEntry> {
        self.events
            .iter()
            .filter(|e| e.id > last_id)
            .cloned()
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Shared state between the SSE endpoint and the POST endpoint.
pub(crate) struct AppState<P: ContextProvider> {
    /// The MCP server, protected by a mutex for concurrent access.
    server: Mutex<McpServer<P>>,
    /// Broadcast sender for SSE messages to connected clients.
    tx: broadcast::Sender<(u64, String)>,
    /// Monotonically increasing event ID counter.
    next_event_id: AtomicU64,
    /// Replay buffer for reconnecting clients.
    replay_buffer: RwLock<ReplayBuffer>,
    /// Retry interval in milliseconds sent to SSE clients.
    retry_ms: u64,
}

impl<P: ContextProvider> AppState<P> {
    /// Broadcasts a JSON payload to all connected SSE clients and records it
    /// in the replay buffer. Returns the assigned event ID.
    async fn broadcast(&self, data: String) -> u64 {
        let id = self.next_event_id.fetch_add(1, Ordering::Relaxed);
        self.replay_buffer.write().await.push(id, data.clone());
        let _ = self.tx.send((id, data));
        id
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Creates an axum [`Router`] for the SSE transport.
///
/// The router exposes:
/// - `GET /sse` -- SSE stream for server-to-client messages.
/// - `POST /message` -- Client-to-server JSON-RPC requests.
///
/// The returned router can be served with `axum::serve` or composed into a
/// larger application.
pub fn sse_router<P: ContextProvider + 'static>(
    server: McpServer<P>,
    config: &SseConfig,
) -> Router {
    let (tx, _rx) = broadcast::channel(config.channel_capacity);
    let state = Arc::new(AppState {
        server: Mutex::new(server),
        tx,
        next_event_id: AtomicU64::new(1),
        replay_buffer: RwLock::new(ReplayBuffer::new(config.replay_capacity)),
        retry_ms: config.retry_ms,
    });

    let router = Router::new()
        .route("/sse", get(sse_handler::<P>))
        .route("/message", post(message_handler::<P>))
        .with_state(state);

    if let Some(ref token) = config.auth_token {
        let expected = token.clone();
        router.layer(middleware::from_fn(move |req, next| {
            bearer_auth_middleware(req, next, expected.clone())
        }))
    } else {
        router
    }
}

/// Middleware that validates bearer token authentication.
///
/// Checks the `Authorization: Bearer <token>` header on incoming requests.
/// Returns HTTP 401 Unauthorized if the header is missing, malformed, or
/// contains the wrong token.
async fn bearer_auth_middleware(
    req: Request<Body>,
    next: Next,
    expected_token: String,
) -> impl IntoResponse {
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(value) if value.len() > 7 && value[..7].eq_ignore_ascii_case("bearer ") => {
            let provided = &value[7..];
            if bool::from(provided.as_bytes().ct_eq(expected_token.as_bytes())) {
                next.run(req).await.into_response()
            } else {
                StatusCode::UNAUTHORIZED.into_response()
            }
        }
        _ => StatusCode::UNAUTHORIZED.into_response(),
    }
}

/// Runs the MCP server as an SSE HTTP server.
///
/// Binds to the configured address and serves until the [`ShutdownHandle`] is
/// triggered or the process is terminated.
///
/// # Errors
///
/// Returns [`SseError`] if the server cannot bind or encounters an I/O error.
pub async fn run_sse<P: ContextProvider + 'static>(
    server: McpServer<P>,
    config: SseConfig,
    shutdown: ShutdownHandle,
) -> Result<(), SseError> {
    let router = sse_router(server, &config);

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    tracing::info!("MCP SSE server listening on {}", config.bind_addr);

    let token = shutdown.token.clone();
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            token.cancelled().await;
            tracing::info!("MCP SSE server shutting down");
        })
        .await
        .map_err(SseError::Io)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Parses the `Last-Event-ID` header value into a `u64`, returning `None` if
/// the header is absent or cannot be parsed.
fn parse_last_event_id(headers: &HeaderMap) -> Option<u64> {
    headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
}

/// SSE endpoint handler. Streams server-to-client messages.
///
/// Sends an initial `endpoint` event containing the POST URL for the client
/// to use, then (if the client sent a `Last-Event-ID` header) replays any
/// buffered events missed during the disconnection, and finally streams live
/// `message` events with JSON-RPC responses.
///
/// Each `message` event carries a sequential `id:` field and the stream
/// includes a `retry:` directive so clients use a server-controlled
/// reconnection interval.
async fn sse_handler<P: ContextProvider + 'static>(
    State(state): State<Arc<AppState<P>>>,
    headers: HeaderMap,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let last_event_id = parse_last_event_id(&headers);

    let endpoint_event = Event::default()
        .event("endpoint")
        .data("/message")
        .retry(Duration::from_millis(state.retry_ms));

    let replay_events: Vec<Result<Event, Infallible>> = if let Some(last_id) = last_event_id {
        tracing::debug!(last_id, "SSE client reconnecting");
        let buf = state.replay_buffer.read().await;
        buf.events_after(last_id)
            .into_iter()
            .map(|entry| {
                Ok(Event::default()
                    .event("message")
                    .id(entry.id.to_string())
                    .data(entry.data))
            })
            .collect()
    } else {
        Vec::new()
    };

    let rx = state.tx.subscribe();
    let message_stream = BroadcastStream::new(rx).filter_map(|result| {
        result
            .map(|(id, data)| {
                Ok(Event::default()
                    .event("message")
                    .id(id.to_string())
                    .data(data))
            })
            .ok()
    });

    let initial = tokio_stream::once(Ok(endpoint_event));
    let replay = tokio_stream::iter(replay_events);
    let stream = initial.chain(replay).chain(message_stream);

    Sse::new(stream).keep_alive(
        KeepAlive::default()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    )
}

/// POST endpoint handler. Receives JSON-RPC requests from the client.
///
/// Dispatches the request to the MCP server and sends the response via the
/// SSE broadcast channel. Returns `202 Accepted` to the HTTP client since
/// the actual response is delivered via SSE.
async fn message_handler<P: ContextProvider + 'static>(
    State(state): State<Arc<AppState<P>>>,
    body: String,
) -> impl IntoResponse {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return StatusCode::BAD_REQUEST;
    }

    let response = match parse_sse_incoming(trimmed) {
        Ok(SseIncoming::Request(req)) => {
            let mut server = state.server.lock().await;
            server.handle_request(&req)
        }
        Ok(SseIncoming::Notification(notif)) => {
            let synthetic_id = state.next_event_id.fetch_add(1, Ordering::SeqCst);
            let synthetic = JsonRpcRequest {
                jsonrpc: notif.jsonrpc,
                method: notif.method,
                params: notif.params,
                id: RequestId::Number(synthetic_id.cast_signed()),
            };
            let mut server = state.server.lock().await;
            server.handle_request(&synthetic);
            None
        }
        Err(err_response) => Some(*err_response),
    };

    if let Some(resp) = response
        && let Ok(json) = serde_json::to_string(&resp)
    {
        state.broadcast(json).await;
    }

    StatusCode::ACCEPTED
}

// ---------------------------------------------------------------------------
// Notification sending
// ---------------------------------------------------------------------------

/// Sends a JSON-RPC notification to all connected SSE clients.
///
/// This is used for server-initiated messages like
/// `notifications/tools/list_changed`.
///
/// Returns the number of receivers that received the message, or 0 if
/// serialization fails or no receivers are connected.
#[cfg(test)]
pub(crate) async fn send_notification<P: ContextProvider>(
    state: &Arc<AppState<P>>,
    notification: &JsonRpcNotification,
) -> usize {
    match serde_json::to_string(notification) {
        Ok(json) => {
            state.broadcast(json).await;
            state.tx.receiver_count()
        }
        Err(_) => 0,
    }
}

// ---------------------------------------------------------------------------
// Incoming message parsing (same logic as stdio)
// ---------------------------------------------------------------------------

/// Raw incoming JSON-RPC message.
#[derive(serde::Deserialize)]
struct RawSseIncoming {
    #[allow(dead_code)]
    jsonrpc: String,
    method: String,
    #[serde(default)]
    params: Option<serde_json::Value>,
    id: Option<serde_json::Value>,
}

#[derive(Debug)]
enum SseIncoming {
    Request(JsonRpcRequest),
    Notification(JsonRpcNotification),
}

fn parse_sse_incoming(body: &str) -> Result<SseIncoming, Box<JsonRpcResponse>> {
    let raw: RawSseIncoming = serde_json::from_str(body).map_err(|e| {
        Box::new(JsonRpcResponse::error(
            RequestId::Number(0),
            JsonRpcError {
                code: PARSE_ERROR,
                message: format!("failed to parse JSON-RPC message: {e}"),
                data: None,
            },
        ))
    })?;

    match raw.id {
        Some(id_val) => {
            let id: RequestId = serde_json::from_value(id_val).map_err(|e| {
                Box::new(JsonRpcResponse::error(
                    RequestId::Number(0),
                    JsonRpcError {
                        code: PARSE_ERROR,
                        message: format!("invalid request id: {e}"),
                        data: None,
                    },
                ))
            })?;
            Ok(SseIncoming::Request(JsonRpcRequest {
                jsonrpc: crate::protocol::JSONRPC_VERSION.to_owned(),
                method: raw.method,
                params: raw.params,
                id,
            }))
        }
        None => Ok(SseIncoming::Notification(JsonRpcNotification {
            jsonrpc: crate::protocol::JSONRPC_VERSION.to_owned(),
            method: raw.method,
            params: raw.params,
        })),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::protocol::{METHOD_INITIALIZE, METHOD_INITIALIZED, METHOD_PING};
    use crate::server::{ContextOutletInfo, MemberInfo};

    // -- Mock provider (same shape as stdio tests) ----------------------------

    struct MockProvider {
        contexts: Vec<String>,
        agent_did: String,
    }

    impl Default for MockProvider {
        fn default() -> Self {
            Self {
                contexts: vec!["ctx_a".to_owned()],
                agent_did: "did:dht:test".to_owned(),
            }
        }
    }

    impl ContextProvider for MockProvider {
        fn active_context_ids(&self) -> Vec<String> {
            self.contexts.clone()
        }
        fn agent_role(&self, _context_id: &str) -> Option<String> {
            Some("admin".to_owned())
        }
        fn agent_did(&self) -> &str {
            &self.agent_did
        }
        fn context_tools(&self, _context_id: &str) -> Vec<ContextOutletInfo> {
            Vec::new()
        }
        fn validate_capability(&self, _context_id: &str, _tool_name: &str) -> Result<(), String> {
            Ok(())
        }
        fn invoke_outlet_one_shot(
            &self,
            _context_id: &str,
            _outlet_id: &str,
            _arguments: serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            Ok(serde_json::json!({"status": "ok"}))
        }
        fn context_members(&self, _context_id: &str) -> Vec<MemberInfo> {
            Vec::new()
        }
        fn context_events(&self, _context_id: &str) -> serde_json::Value {
            serde_json::json!([])
        }
        fn subscribe_resource(&self, _uri: &str) -> Result<(), String> {
            Ok(())
        }
    }

    // -- Helper: create shared state for tests --------------------------------

    fn test_state() -> Arc<AppState<MockProvider>> {
        let server = McpServer::new(MockProvider::default());
        let (tx, _) = broadcast::channel(16);
        Arc::new(AppState {
            server: Mutex::new(server),
            tx,
            next_event_id: AtomicU64::new(1),
            replay_buffer: RwLock::new(ReplayBuffer::new(DEFAULT_REPLAY_CAPACITY)),
            retry_ms: DEFAULT_RETRY_MS,
        })
    }

    // -- parse_sse_incoming ---------------------------------------------------

    #[test]
    fn parse_sse_incoming_request() {
        let body = r#"{"jsonrpc":"2.0","method":"ping","id":1}"#;
        match parse_sse_incoming(body).unwrap() {
            SseIncoming::Request(req) => {
                assert_eq!(req.method, "ping");
                assert_eq!(req.id, RequestId::Number(1));
            }
            SseIncoming::Notification(_) => panic!("expected request"),
        }
    }

    #[test]
    fn parse_sse_incoming_notification() {
        let body = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        match parse_sse_incoming(body).unwrap() {
            SseIncoming::Notification(notif) => {
                assert_eq!(notif.method, "notifications/initialized");
            }
            SseIncoming::Request(_) => panic!("expected notification"),
        }
    }

    #[test]
    fn parse_sse_incoming_invalid_json() {
        let err = parse_sse_incoming("bad json").unwrap_err();
        assert!(err.error.is_some());
        assert_eq!(err.error.as_ref().unwrap().code, PARSE_ERROR);
    }

    // -- Router integration tests ---------------------------------------------

    #[tokio::test]
    async fn sse_router_builds_successfully() {
        let server = McpServer::new(MockProvider::default());
        let config = SseConfig::new("127.0.0.1:0".parse().unwrap());
        let _router = sse_router(server, &config);
    }

    #[tokio::test]
    async fn message_handler_processes_initialize() {
        let state = test_state();
        let mut rx = state.tx.subscribe();

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_INITIALIZE,
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test" }
            },
            "id": 1
        })
        .to_string();

        let response = match parse_sse_incoming(&body).unwrap() {
            SseIncoming::Request(req) => {
                let mut srv = state.server.lock().await;
                srv.handle_request(&req)
            }
            SseIncoming::Notification(_) => None,
        };

        assert!(response.is_some());
        let resp = response.unwrap();
        assert!(resp.result.is_some());
        assert_eq!(resp.id, RequestId::Number(1));

        let json = serde_json::to_string(&resp).unwrap();
        state.broadcast(json.clone()).await;

        let (_id, received) = rx.recv().await.unwrap();
        assert_eq!(received, json);
    }

    #[tokio::test]
    async fn message_handler_processes_ping() {
        let state = test_state();

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_PING,
            "id": 42
        })
        .to_string();

        let response = match parse_sse_incoming(&body).unwrap() {
            SseIncoming::Request(req) => {
                let mut srv = state.server.lock().await;
                srv.handle_request(&req)
            }
            SseIncoming::Notification(_) => None,
        };

        let resp = response.unwrap();
        assert!(resp.result.is_some());
        assert_eq!(resp.id, RequestId::Number(42));
    }

    #[tokio::test]
    async fn message_handler_handles_notification() {
        let state = test_state();

        let init_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_INITIALIZE,
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test" }
            },
            "id": 0
        })
        .to_string();
        if let SseIncoming::Request(req) = parse_sse_incoming(&init_body).unwrap() {
            let mut srv = state.server.lock().await;
            srv.handle_request(&req);
        }

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_INITIALIZED
        })
        .to_string();

        let result = match parse_sse_incoming(&body).unwrap() {
            SseIncoming::Request(req) => {
                let mut srv = state.server.lock().await;
                srv.handle_request(&req)
            }
            SseIncoming::Notification(notif) => {
                let synthetic_id = state.next_event_id.fetch_add(1, Ordering::SeqCst);
                let synthetic = JsonRpcRequest {
                    jsonrpc: notif.jsonrpc,
                    method: notif.method,
                    params: notif.params,
                    id: RequestId::Number(synthetic_id.cast_signed()),
                };
                let mut srv = state.server.lock().await;
                srv.handle_request(&synthetic);
                None
            }
        };

        assert!(result.is_none());
    }

    #[test]
    fn sse_config_defaults() {
        let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let config = SseConfig::new(addr);
        assert_eq!(config.bind_addr, addr);
        assert_eq!(config.channel_capacity, 256);
        assert_eq!(config.retry_ms, DEFAULT_RETRY_MS);
        assert_eq!(config.replay_capacity, DEFAULT_REPLAY_CAPACITY);
        assert!(config.auth_token.is_none());
    }

    #[tokio::test]
    async fn send_notification_broadcasts_to_receivers() {
        let state = test_state();
        let mut rx = state.tx.subscribe();

        let notif = McpServer::<MockProvider>::tools_list_changed_notification();
        let count = send_notification(&state, &notif).await;
        assert_eq!(count, 1);

        let (_id, received) = rx.recv().await.unwrap();
        let parsed: JsonRpcNotification = serde_json::from_str(&received).unwrap();
        assert_eq!(parsed.method, "notifications/tools/list_changed");
    }

    #[tokio::test]
    async fn send_notification_returns_zero_with_no_receivers() {
        let server = McpServer::new(MockProvider::default());
        let (tx, _) = broadcast::channel::<(u64, String)>(16);
        let state = Arc::new(AppState {
            server: Mutex::new(server),
            tx,
            next_event_id: AtomicU64::new(1),
            replay_buffer: RwLock::new(ReplayBuffer::new(DEFAULT_REPLAY_CAPACITY)),
            retry_ms: DEFAULT_RETRY_MS,
        });

        let notif = McpServer::<MockProvider>::tools_list_changed_notification();
        let count = send_notification(&state, &notif).await;
        assert_eq!(count, 0);
    }

    // -- Replay buffer --------------------------------------------------------

    #[test]
    fn replay_buffer_stores_and_retrieves() {
        let mut buf = ReplayBuffer::new(4);
        buf.push(1, "event-1".to_owned());
        buf.push(2, "event-2".to_owned());
        buf.push(3, "event-3".to_owned());

        let after_0 = buf.events_after(0);
        assert_eq!(after_0.len(), 3);
        assert_eq!(after_0[0].id, 1);
        assert_eq!(after_0[2].data, "event-3");

        let after_2 = buf.events_after(2);
        assert_eq!(after_2.len(), 1);
        assert_eq!(after_2[0].id, 3);

        let after_3 = buf.events_after(3);
        assert!(after_3.is_empty());
    }

    #[test]
    fn replay_buffer_evicts_oldest_when_full() {
        let mut buf = ReplayBuffer::new(2);
        buf.push(1, "a".to_owned());
        buf.push(2, "b".to_owned());
        buf.push(3, "c".to_owned());

        let all = buf.events_after(0);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, 2);
        assert_eq!(all[1].id, 3);
    }

    #[test]
    fn replay_buffer_empty() {
        let buf = ReplayBuffer::new(4);
        assert!(buf.events_after(0).is_empty());
    }

    // -- Broadcast with event IDs ---------------------------------------------

    #[tokio::test]
    async fn broadcast_assigns_sequential_ids() {
        let state = test_state();
        let mut rx = state.tx.subscribe();

        let id1 = state.broadcast("msg-1".to_owned()).await;
        let id2 = state.broadcast("msg-2".to_owned()).await;

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);

        let (recv_id1, recv_data1) = rx.recv().await.unwrap();
        let (recv_id2, recv_data2) = rx.recv().await.unwrap();
        assert_eq!(recv_id1, 1);
        assert_eq!(recv_data1, "msg-1");
        assert_eq!(recv_id2, 2);
        assert_eq!(recv_data2, "msg-2");
    }

    #[tokio::test]
    async fn broadcast_populates_replay_buffer() {
        let state = test_state();

        state.broadcast("first".to_owned()).await;
        state.broadcast("second".to_owned()).await;
        state.broadcast("third".to_owned()).await;

        let missed = state.replay_buffer.read().await.events_after(1);
        assert_eq!(missed.len(), 2);
        assert_eq!(missed[0].data, "second");
        assert_eq!(missed[1].data, "third");
    }

    // -- Last-Event-ID parsing ------------------------------------------------

    #[test]
    fn parse_last_event_id_valid() {
        let mut headers = HeaderMap::new();
        headers.insert("last-event-id", "42".parse().unwrap());
        assert_eq!(parse_last_event_id(&headers), Some(42));
    }

    #[test]
    fn parse_last_event_id_missing() {
        let headers = HeaderMap::new();
        assert_eq!(parse_last_event_id(&headers), None);
    }

    #[test]
    fn parse_last_event_id_non_numeric() {
        let mut headers = HeaderMap::new();
        headers.insert("last-event-id", "abc".parse().unwrap());
        assert_eq!(parse_last_event_id(&headers), None);
    }

    // -- Shutdown handle ------------------------------------------------------

    #[test]
    fn shutdown_handle_signals_correctly() {
        let handle = ShutdownHandle::new();
        assert!(!handle.is_shutdown());
        handle.shutdown();
        assert!(handle.is_shutdown());
    }

    #[test]
    fn shutdown_handle_default_is_not_shutdown() {
        let handle = ShutdownHandle::default();
        assert!(!handle.is_shutdown());
    }

    // -- run_sse with shutdown ------------------------------------------------

    #[tokio::test]
    async fn run_sse_shuts_down_on_signal() {
        let server = McpServer::new(MockProvider::default());
        let config = SseConfig::new("127.0.0.1:0".parse().unwrap());
        let handle = ShutdownHandle::new();

        let run_handle = handle.clone();
        let task = tokio::spawn(async move { run_sse(server, config, run_handle).await });

        tokio::time::sleep(Duration::from_millis(50)).await;
        handle.shutdown();

        let result = tokio::time::timeout(Duration::from_secs(5), task).await;
        assert!(result.is_ok(), "server should shut down within timeout");
        assert!(result.unwrap().unwrap().is_ok());
    }

    // -- Auth middleware -------------------------------------------------------

    #[tokio::test]
    async fn sse_router_with_auth_builds_successfully() {
        let server = McpServer::new(MockProvider::default());
        let mut config = SseConfig::new("127.0.0.1:0".parse().unwrap());
        config.auth_token = Some("secret-token".to_owned());
        let _router = sse_router(server, &config);
    }

    #[tokio::test]
    async fn sse_router_without_auth_builds_successfully() {
        let server = McpServer::new(MockProvider::default());
        let config = SseConfig::new("127.0.0.1:0".parse().unwrap());
        assert!(config.auth_token.is_none());
        let _router = sse_router(server, &config);
    }

    #[test]
    fn sse_config_with_auth_token() {
        let mut config = SseConfig::new("127.0.0.1:3000".parse().unwrap());
        config.auth_token = Some("my-secret".to_owned());
        assert_eq!(config.auth_token.as_deref(), Some("my-secret"));
    }

    // -- Auth middleware integration tests ------------------------------------

    /// Helper: build an authenticated router (`auth_token` = "test-secret").
    fn auth_router() -> Router {
        let server = McpServer::new(MockProvider::default());
        let mut config = SseConfig::new("127.0.0.1:0".parse().unwrap());
        config.auth_token = Some("test-secret".to_owned());
        sse_router(server, &config)
    }

    /// Helper: build an unauthenticated router (`auth_token` = None).
    fn noauth_router() -> Router {
        let server = McpServer::new(MockProvider::default());
        let config = SseConfig::new("127.0.0.1:0".parse().unwrap());
        sse_router(server, &config)
    }

    /// Helper: send a request through the router and return the status code.
    async fn request_status(router: Router, req: Request<Body>) -> StatusCode {
        use tower::ServiceExt;

        let response = router.oneshot(req).await.unwrap();
        response.status()
    }

    #[tokio::test]
    async fn auth_valid_bearer_sse_accepted() {
        let router = auth_router();
        let req = Request::builder()
            .uri("/sse")
            .header("Authorization", "Bearer test-secret")
            .body(Body::empty())
            .unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_valid_bearer_post_accepted() {
        let router = auth_router();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_PING,
            "id": 1
        })
        .to_string();

        let req = Request::builder()
            .method("POST")
            .uri("/message")
            .header("Authorization", "Bearer test-secret")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn auth_missing_bearer_sse_rejected() {
        let router = auth_router();
        let req = Request::builder().uri("/sse").body(Body::empty()).unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_missing_bearer_post_rejected() {
        let router = auth_router();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_PING,
            "id": 1
        })
        .to_string();

        let req = Request::builder()
            .method("POST")
            .uri("/message")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_wrong_bearer_sse_rejected() {
        let router = auth_router();
        let req = Request::builder()
            .uri("/sse")
            .header("Authorization", "Bearer wrong-token")
            .body(Body::empty())
            .unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_wrong_bearer_post_rejected() {
        let router = auth_router();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_PING,
            "id": 1
        })
        .to_string();

        let req = Request::builder()
            .method("POST")
            .uri("/message")
            .header("Authorization", "Bearer wrong-token")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_empty_bearer_rejected() {
        let router = auth_router();
        let req = Request::builder()
            .uri("/sse")
            .header("Authorization", "Bearer ")
            .body(Body::empty())
            .unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_malformed_header_rejected() {
        let router = auth_router();
        // "Basic" scheme instead of "Bearer"
        let req = Request::builder()
            .uri("/sse")
            .header("Authorization", "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_bearer_without_space_rejected() {
        let router = auth_router();
        // Missing space after "Bearer"
        let req = Request::builder()
            .uri("/sse")
            .header("Authorization", "Bearertest-secret")
            .body(Body::empty())
            .unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn noauth_allows_requests_without_header() {
        let router = noauth_router();
        // SSE endpoint should work without any auth header when auth is disabled
        let req = Request::builder().uri("/sse").body(Body::empty()).unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn noauth_post_allows_requests_without_header() {
        let router = noauth_router();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_PING,
            "id": 1
        })
        .to_string();

        let req = Request::builder()
            .method("POST")
            .uri("/message")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn auth_token_prefix_not_accepted() {
        let router = auth_router();
        // Token is "test-secret" but we send "test-secret-extended" -- should
        // fail because constant-time comparison requires exact match.
        let req = Request::builder()
            .uri("/sse")
            .header("Authorization", "Bearer test-secret-extended")
            .body(Body::empty())
            .unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_token_substring_not_accepted() {
        let router = auth_router();
        // Token is "test-secret" but we send "test-secre" (substring)
        let req = Request::builder()
            .uri("/sse")
            .header("Authorization", "Bearer test-secre")
            .body(Body::empty())
            .unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // -- Synthetic request IDs ------------------------------------------------

    #[tokio::test]
    async fn synthetic_notification_ids_are_unique() {
        let state = test_state();

        // Send two notifications and verify the counter advances
        let init_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_INITIALIZE,
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test" }
            },
            "id": 0
        })
        .to_string();
        if let SseIncoming::Request(req) = parse_sse_incoming(&init_body).unwrap() {
            let mut srv = state.server.lock().await;
            srv.handle_request(&req);
        }

        // First notification uses next_event_id (starts at 1)
        let id1 = state.next_event_id.load(Ordering::SeqCst);
        let notif_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_INITIALIZED
        })
        .to_string();
        if let SseIncoming::Notification(notif) = parse_sse_incoming(&notif_body).unwrap() {
            let synthetic_id = state.next_event_id.fetch_add(1, Ordering::SeqCst);
            assert_eq!(synthetic_id, id1);

            // Verify the ID is correctly assigned
            let request = JsonRpcRequest {
                jsonrpc: notif.jsonrpc,
                method: notif.method,
                params: notif.params,
                id: RequestId::Number(synthetic_id.cast_signed()),
            };
            assert_eq!(request.id, RequestId::Number(id1.cast_signed()));
        }

        // Second call produces a different ID
        let id2 = state.next_event_id.fetch_add(1, Ordering::SeqCst);
        assert_ne!(id1, id2);
    }
}
