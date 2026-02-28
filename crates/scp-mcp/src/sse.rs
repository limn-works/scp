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
//! - `POST /message` -- Accepts JSON-RPC requests from the client. Responses
//!   are delivered via the SSE stream, not in the HTTP response body.
//!
//! ## Keep-alive
//!
//! The SSE stream sends periodic comment-only keep-alive frames (`: keepalive`)
//! to prevent intermediate proxies from closing idle connections.
//!
//! See ADR-015 in `.docs/adrs/phase-3.md` for the full design.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::{get, post};
use tokio::sync::{Mutex, broadcast};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use crate::protocol::{
    JsonRpcError, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, PARSE_ERROR, RequestId,
};
use crate::server::{ContextProvider, McpServer};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the SSE transport server.
#[derive(Debug, Clone)]
pub struct SseConfig {
    /// The address to bind the HTTP server to (e.g., `127.0.0.1:3000`).
    pub bind_addr: SocketAddr,

    /// Capacity of the broadcast channel for SSE messages.
    /// Defaults to 256.
    pub channel_capacity: usize,
}

impl SseConfig {
    /// Creates a new configuration with the given bind address.
    #[must_use]
    pub const fn new(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            channel_capacity: 256,
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
// Shared state
// ---------------------------------------------------------------------------

/// Shared state between the SSE endpoint and the POST endpoint.
pub(crate) struct AppState<P: ContextProvider> {
    /// The MCP server, protected by a mutex for concurrent access.
    server: Mutex<McpServer<P>>,
    /// Broadcast sender for SSE messages to connected clients.
    tx: broadcast::Sender<String>,
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
    channel_capacity: usize,
) -> Router {
    let (tx, _rx) = broadcast::channel(channel_capacity);
    let state = Arc::new(AppState {
        server: Mutex::new(server),
        tx,
    });

    Router::new()
        .route("/sse", get(sse_handler::<P>))
        .route("/message", post(message_handler::<P>))
        .with_state(state)
}

/// Runs the MCP server as an SSE HTTP server.
///
/// Binds to the configured address and serves until the process is terminated.
///
/// # Errors
///
/// Returns [`SseError`] if the server cannot bind or encounters an I/O error.
pub async fn run_sse<P: ContextProvider + 'static>(
    server: McpServer<P>,
    config: SseConfig,
) -> Result<(), SseError> {
    let router = sse_router(server, config.channel_capacity);

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    tracing::info!("MCP SSE server listening on {}", config.bind_addr);
    axum::serve(listener, router).await.map_err(SseError::Io)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// SSE endpoint handler. Streams server-to-client messages.
///
/// Sends an initial `endpoint` event containing the POST URL for the client
/// to use, then streams `message` events with JSON-RPC responses.
async fn sse_handler<P: ContextProvider + 'static>(
    State(state): State<Arc<AppState<P>>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    // Send the POST endpoint URL as the first event.
    let endpoint_event = Event::default().event("endpoint").data("/message");

    let rx = state.tx.subscribe();
    let message_stream = BroadcastStream::new(rx).filter_map(|result| {
        result
            .map(|data| Ok(Event::default().event("message").data(data)))
            .ok()
    });

    // Prepend the endpoint event to the message stream.
    let initial = tokio_stream::once(Ok(endpoint_event));
    let stream = initial.chain(message_stream);

    Sse::new(stream).keep_alive(KeepAlive::default())
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

    // Parse the incoming message (request or notification).
    let response = match parse_sse_incoming(trimmed) {
        Ok(SseIncoming::Request(req)) => {
            let mut server = state.server.lock().await;
            server.handle_request(&req)
        }
        Ok(SseIncoming::Notification(notif)) => {
            // Handle notifications via synthetic request (same as stdio).
            let synthetic = JsonRpcRequest {
                jsonrpc: notif.jsonrpc,
                method: notif.method,
                params: notif.params,
                id: RequestId::Number(0),
            };
            let mut server = state.server.lock().await;
            server.handle_request(&synthetic);
            None
        }
        Err(err_response) => Some(*err_response),
    };

    // Send the response over the SSE channel.
    if let Some(resp) = response
        && let Ok(json) = serde_json::to_string(&resp) {
            // Ignore send errors (no receivers connected).
            let _ = state.tx.send(json);
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
pub(crate) fn send_notification<P: ContextProvider>(
    state: &Arc<AppState<P>>,
    notification: &JsonRpcNotification,
) -> usize {
    serde_json::to_string(notification).map_or(0, |json| state.tx.send(json).unwrap_or(0))
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
    use crate::server::{ContextToolInfo, MemberInfo};

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
        fn context_tools(&self, _context_id: &str) -> Vec<ContextToolInfo> {
            Vec::new()
        }
        fn validate_capability(&self, _context_id: &str, _tool_name: &str) -> Result<(), String> {
            Ok(())
        }
        fn invoke_tool(
            &self,
            _context_id: &str,
            _tool_name: &str,
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
        let _router = sse_router(server, 16);
        // If we get here without panic, the router was built successfully.
    }

    #[tokio::test]
    async fn message_handler_processes_initialize() {
        let server = McpServer::new(MockProvider::default());
        let (tx, mut rx) = broadcast::channel(16);
        let state = Arc::new(AppState {
            server: Mutex::new(server),
            tx,
        });

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

        // Simulate calling the message handler.
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

        // Send via broadcast.
        let json = serde_json::to_string(&resp).unwrap();
        let _ = state.tx.send(json.clone());

        // Verify broadcast received.
        let received = rx.recv().await.unwrap();
        assert_eq!(received, json);
    }

    #[tokio::test]
    async fn message_handler_processes_ping() {
        let server = McpServer::new(MockProvider::default());
        let (tx, _rx) = broadcast::channel(16);
        let state = Arc::new(AppState {
            server: Mutex::new(server),
            tx,
        });

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
        let server = McpServer::new(MockProvider::default());
        let (tx, _rx) = broadcast::channel(16);
        let state = Arc::new(AppState {
            server: Mutex::new(server),
            tx,
        });

        // Initialize the server first — the pre-init guard blocks everything
        // except `initialize` and `ping`.
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
                let synthetic = JsonRpcRequest {
                    jsonrpc: notif.jsonrpc,
                    method: notif.method,
                    params: notif.params,
                    id: RequestId::Number(0),
                };
                let mut srv = state.server.lock().await;
                srv.handle_request(&synthetic);
                None
            }
        };

        // Notifications produce no response.
        assert!(result.is_none());
    }

    #[test]
    fn sse_config_defaults() {
        let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let config = SseConfig::new(addr);
        assert_eq!(config.bind_addr, addr);
        assert_eq!(config.channel_capacity, 256);
    }

    #[tokio::test]
    async fn send_notification_broadcasts_to_receivers() {
        let server = McpServer::new(MockProvider::default());
        let (tx, mut rx) = broadcast::channel(16);
        let state = Arc::new(AppState {
            server: Mutex::new(server),
            tx,
        });

        let notif = McpServer::<MockProvider>::tools_list_changed_notification();
        let count = send_notification(&state, &notif);
        assert_eq!(count, 1); // One receiver (rx).

        let received = rx.recv().await.unwrap();
        let parsed: JsonRpcNotification = serde_json::from_str(&received).unwrap();
        assert_eq!(parsed.method, "notifications/tools/list_changed");
    }

    #[tokio::test]
    async fn send_notification_returns_zero_with_no_receivers() {
        let server = McpServer::new(MockProvider::default());
        let (tx, _) = broadcast::channel::<String>(16);
        let state = Arc::new(AppState {
            server: Mutex::new(server),
            tx,
        });

        let notif = McpServer::<MockProvider>::tools_list_changed_notification();
        // Drop all receivers first -- the channel was created without
        // persisting any rx handle. The underscore `_` means the rx from
        // the tuple was already dropped.
        let count = send_notification(&state, &notif);
        assert_eq!(count, 0);
    }
}
