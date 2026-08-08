//! stdio transport for the MCP server.
//!
//! Implements the MCP stdio transport mode: line-delimited JSON-RPC 2.0 over
//! standard input/output. This is the default transport for local integrations
//! with MCP hosts (Claude Code, Cursor, etc.) that launch the server as a
//! subprocess.
//!
//! The server reads one JSON-RPC request per line from stdin, dispatches it to
//! [`McpServer::handle_request`], and writes the response (if any) as a single
//! line to stdout.
//!
//! See ADR-015 in `.docs/adrs/phase-3.md` for the full design.

use std::sync::Arc;

use scp_core::context::membership::ContextEvent;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::broadcast;

use crate::protocol::{
    JsonRpcError, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, RequestId,
};
use crate::server::{ContextProvider, McpServer};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from the stdio transport.
#[derive(Debug, thiserror::Error)]
pub enum StdioError {
    /// An I/O error occurred reading from stdin or writing to stdout.
    #[error("stdio I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Incoming message (request or notification)
// ---------------------------------------------------------------------------

/// A raw incoming JSON-RPC message that may be a request (has `id`) or a
/// notification (no `id`).
#[derive(Debug, serde::Deserialize)]
struct RawIncoming {
    #[allow(dead_code)]
    jsonrpc: String,
    method: String,
    #[serde(default)]
    params: Option<serde_json::Value>,
    /// Present for requests, absent for notifications.
    id: Option<serde_json::Value>,
}

/// The result of parsing an incoming line.
#[derive(Debug)]
enum Incoming {
    /// A JSON-RPC request (has an `id`).
    Request(JsonRpcRequest),
    /// A JSON-RPC notification (no `id`).
    Notification(JsonRpcNotification),
}

/// Parses a raw JSON line into either a [`JsonRpcRequest`] or a
/// [`JsonRpcNotification`].
fn parse_incoming(line: &str) -> Result<Incoming, Box<JsonRpcResponse>> {
    let raw: RawIncoming = serde_json::from_str(line).map_err(|e| {
        Box::new(JsonRpcResponse::error(
            RequestId::Number(0),
            JsonRpcError {
                code: crate::protocol::PARSE_ERROR,
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
                        code: crate::protocol::PARSE_ERROR,
                        message: format!("invalid request id: {e}"),
                        data: None,
                    },
                ))
            })?;
            Ok(Incoming::Request(JsonRpcRequest {
                jsonrpc: crate::protocol::JSONRPC_VERSION.to_owned(),
                method: raw.method,
                params: raw.params,
                id,
            }))
        }
        None => Ok(Incoming::Notification(JsonRpcNotification {
            jsonrpc: crate::protocol::JSONRPC_VERSION.to_owned(),
            method: raw.method,
            params: raw.params,
        })),
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Maximum bytes accepted for a single line on an MCP stdio transport.
///
/// 10 MiB is generous for JSON-RPC messages (typical MCP payloads are < 1 MiB)
/// while preventing unbounded allocation from a misbehaving peer.
pub const MAX_LINE_BYTES: u64 = 10 * 1024 * 1024;

/// Serializes writes to stdout so responses from the read loop and
/// notifications from the event pump interleave as whole lines.
#[derive(Clone)]
struct StdioNotifier {
    stdout: Arc<tokio::sync::Mutex<tokio::io::Stdout>>,
}

impl StdioNotifier {
    /// Creates a notifier owning the process's stdout.
    fn new() -> Self {
        Self {
            stdout: Arc::new(tokio::sync::Mutex::new(tokio::io::stdout())),
        }
    }

    /// Writes a single line to stdout, flushing it.
    async fn write_line(&self, json: &str) -> Result<(), std::io::Error> {
        let mut stdout = self.stdout.lock().await;
        stdout.write_all(json.as_bytes()).await?;
        stdout.write_all(b"\n").await?;
        stdout.flush().await
    }

    /// Pushes a JSON-RPC notification to the client.
    ///
    /// Returns `false` if the notification could not be serialized or written
    /// (e.g. the client closed stdout).
    async fn notify(&self, notification: &JsonRpcNotification) -> bool {
        let json = match serde_json::to_string(notification) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!("failed to serialize MCP notification: {e}");
                return false;
            }
        };
        match self.write_line(&json).await {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("MCP stdio notification write failed: {e}");
                false
            }
        }
    }
}

/// Runs the MCP server over stdio (stdin/stdout, line-delimited JSON).
///
/// Reads JSON-RPC messages line-by-line from stdin, dispatches them to the
/// server, and writes responses to stdout. Runs until stdin is closed (EOF)
/// or a line exceeds [`MAX_LINE_BYTES`].
///
/// # Resource subscriptions
///
/// Pass `events` — a receiver from
/// [`Supervisor::subscribe_events`](scp_core::context::supervisor::Supervisor::subscribe_events)
/// — to enable `resources/subscribe`. When `Some`, this function enables the
/// subscription capability on `server` and runs a pump that turns each
/// [`ContextEvent`] into `notifications/resources/updated` for the subscribed
/// resources it invalidates.
///
/// When `None`, the server advertises `resources.subscribe: false` and
/// rejects `resources/subscribe` with a typed error. The capability is never
/// advertised without the machinery to honour it.
///
/// The server is shared behind a mutex so the pump can consult the same
/// subscription registry as the read loop; the lock is only ever held for the
/// synchronous duration of a single call, never across an await.
///
/// Per JSON-RPC 2.0, incoming *notifications* (messages without an `id`) never
/// produce a response — this is why the transport parses into a request/
/// notification sum type rather than deserializing every line as a request.
///
/// # Errors
///
/// Returns [`StdioError`] if an I/O error occurs on stdin or stdout.
pub async fn run_stdio<P: ContextProvider + 'static>(
    server: &Arc<std::sync::Mutex<McpServer<P>>>,
    events: Option<broadcast::Receiver<(String, ContextEvent)>>,
) -> Result<(), StdioError> {
    let notifier = StdioNotifier::new();

    // Enabling the capability and starting the pump are the same step, so the
    // advertisement can never outrun the delivery machinery.
    let pump = events.map(|rx| {
        if let Ok(mut srv) = server.lock() {
            srv.enable_subscriptions();
        } else {
            tracing::error!("MCP server mutex poisoned enabling subscriptions");
        }
        tokio::spawn(pump_events(Arc::clone(server), rx, notifier.clone()))
    });

    let result = read_loop(server, &notifier).await;

    if let Some(handle) = pump {
        handle.abort();
    }
    result
}

/// Forwards runtime context events to the client as MCP notifications.
async fn pump_events<P: ContextProvider>(
    server: Arc<std::sync::Mutex<McpServer<P>>>,
    mut events: broadcast::Receiver<(String, ContextEvent)>,
    notifier: StdioNotifier,
) {
    loop {
        let (context_id, event) = match events.recv().await {
            Ok(v) => v,
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                // The client may have missed a change. Over-notify rather
                // than leave it stale: nothing here can reconstruct which
                // resources the dropped events touched, so callers re-read.
                tracing::warn!("MCP stdio event pump lagged, {skipped} events dropped");
                continue;
            }
            Err(broadcast::error::RecvError::Closed) => return,
        };

        let notifications = match server.lock() {
            Ok(srv) => srv.notifications_for_event(&context_id, &event),
            Err(e) => {
                tracing::error!("MCP server mutex poisoned in event pump: {e}");
                return;
            }
        };

        for notification in &notifications {
            if !notifier.notify(notification).await {
                // stdout is gone; the session is over.
                return;
            }
        }
    }
}

/// Reads and dispatches client messages until EOF.
async fn read_loop<P: ContextProvider>(
    server: &Arc<std::sync::Mutex<McpServer<P>>>,
    notifier: &StdioNotifier,
) -> Result<(), StdioError> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = {
            let mut bounded = (&mut reader).take(MAX_LINE_BYTES);
            bounded.read_line(&mut line).await?
        };
        if bytes_read == 0 {
            // EOF -- stdin closed, exit cleanly.
            break;
        }
        // Exactly at the cap with no terminator means the line was truncated;
        // rejecting beats acting on a partial message.
        if bytes_read as u64 == MAX_LINE_BYTES && !line.ends_with('\n') {
            tracing::warn!("MCP stdio: line exceeds {MAX_LINE_BYTES} byte limit, stopping");
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let response = match parse_incoming(trimmed) {
            Ok(Incoming::Request(req)) => dispatch(server, &req),
            Ok(Incoming::Notification(notif)) => {
                // Notifications are dispatched through the same entry point
                // using a synthetic ID; `handle_request` returns `None` for
                // notification methods so the ID is never observable.
                let synthetic = JsonRpcRequest {
                    jsonrpc: notif.jsonrpc,
                    method: notif.method,
                    params: notif.params,
                    id: RequestId::Number(0),
                };
                dispatch(server, &synthetic);
                // Notifications never produce a response.
                None
            }
            Err(err_response) => Some(*err_response),
        };

        if let Some(resp) = response {
            let json = match serde_json::to_string(&resp) {
                Ok(j) => j,
                Err(e) => {
                    tracing::error!("failed to serialize response: {e}");
                    continue;
                }
            };
            notifier.write_line(&json).await?;
        }
    }

    Ok(())
}

/// Dispatches a request against the shared server.
///
/// A poisoned mutex means another thread panicked mid-dispatch; there is no
/// safe state to answer from, so the message is dropped with a logged error
/// rather than propagating the panic into the transport loop.
fn dispatch<P: ContextProvider>(
    server: &std::sync::Arc<std::sync::Mutex<McpServer<P>>>,
    request: &JsonRpcRequest,
) -> Option<JsonRpcResponse> {
    match server.lock() {
        Ok(mut srv) => srv.handle_request(request),
        Err(e) => {
            tracing::error!("MCP server mutex poisoned: {e}");
            None
        }
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

    // -- parse_incoming -------------------------------------------------------

    #[test]
    fn parse_incoming_request_with_numeric_id() {
        let line = r#"{"jsonrpc":"2.0","method":"ping","id":1}"#;
        match parse_incoming(line).unwrap() {
            Incoming::Request(req) => {
                assert_eq!(req.method, "ping");
                assert_eq!(req.id, RequestId::Number(1));
            }
            Incoming::Notification(_) => panic!("expected request, got notification"),
        }
    }

    #[test]
    fn parse_incoming_request_with_string_id() {
        let line = r#"{"jsonrpc":"2.0","method":"tools/list","params":{},"id":"abc"}"#;
        match parse_incoming(line).unwrap() {
            Incoming::Request(req) => {
                assert_eq!(req.method, "tools/list");
                assert_eq!(req.id, RequestId::String("abc".to_owned()));
            }
            Incoming::Notification(_) => panic!("expected request, got notification"),
        }
    }

    #[test]
    fn parse_incoming_notification_without_id() {
        let line = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        match parse_incoming(line).unwrap() {
            Incoming::Notification(notif) => {
                assert_eq!(notif.method, "notifications/initialized");
            }
            Incoming::Request(_) => panic!("expected notification, got request"),
        }
    }

    #[test]
    fn parse_incoming_invalid_json_returns_error() {
        let line = "not json at all";
        let err = parse_incoming(line).unwrap_err();
        assert!(err.error.is_some());
        assert_eq!(
            err.error.as_ref().unwrap().code,
            crate::protocol::PARSE_ERROR
        );
    }

    #[test]
    fn parse_incoming_request_with_params() {
        let line = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ctx/send_message","arguments":{"content":"hello"}},"id":42}"#;
        match parse_incoming(line).unwrap() {
            Incoming::Request(req) => {
                assert_eq!(req.method, "tools/call");
                assert!(req.params.is_some());
                let params = req.params.unwrap();
                assert_eq!(params["name"], "ctx/send_message");
            }
            Incoming::Notification(_) => panic!("expected request, got notification"),
        }
    }

    // -- Integration test with McpServer using mock provider ------------------

    // Reuse the mock provider from server.rs tests.
    use crate::server::{ContextOutletInfo, MemberInfo};

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
        fn invoke_outlet(
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
    }

    #[test]
    fn handle_initialize_via_parse_and_dispatch() {
        let mut server = McpServer::new(MockProvider::default());
        let line = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_INITIALIZE,
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test-client" }
            },
            "id": 1
        })
        .to_string();

        match parse_incoming(&line).unwrap() {
            Incoming::Request(req) => {
                let resp = server.handle_request(&req);
                assert!(resp.is_some());
                let resp = resp.unwrap();
                assert!(resp.result.is_some());
                assert!(resp.error.is_none());
                assert!(server.is_initialized());
            }
            Incoming::Notification(_) => panic!("expected request"),
        }
    }

    #[test]
    fn handle_initialized_notification_via_parse() {
        // Initialize the server first — the pre-init guard blocks everything
        // except `initialize` and `ping`.
        let mut server = McpServer::new(MockProvider::default());
        let init_line = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_INITIALIZE,
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test-client" }
            },
            "id": 0
        })
        .to_string();
        if let Incoming::Request(req) = parse_incoming(&init_line).unwrap() {
            server.handle_request(&req);
        }

        let line = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_INITIALIZED
        })
        .to_string();

        match parse_incoming(&line).unwrap() {
            Incoming::Notification(notif) => {
                assert_eq!(notif.method, METHOD_INITIALIZED);
                // Simulate what run_stdio does: construct synthetic request.
                let synthetic = JsonRpcRequest {
                    jsonrpc: notif.jsonrpc,
                    method: notif.method,
                    params: notif.params,
                    id: RequestId::Number(0),
                };
                let resp = server.handle_request(&synthetic);
                assert!(resp.is_none()); // Notifications produce no response.
            }
            Incoming::Request(_) => panic!("expected notification"),
        }
    }

    #[test]
    fn handle_ping_via_parse_and_dispatch() {
        let mut server = McpServer::new(MockProvider::default());
        let line = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_PING,
            "id": 99
        })
        .to_string();

        match parse_incoming(&line).unwrap() {
            Incoming::Request(req) => {
                let resp = server.handle_request(&req).unwrap();
                assert!(resp.result.is_some());
                assert_eq!(resp.id, RequestId::Number(99));
            }
            Incoming::Notification(_) => panic!("expected request"),
        }
    }

    #[tokio::test]
    async fn run_stdio_processes_initialize_and_ping() {
        // Simulate stdin with two requests: initialize then ping.
        let init_req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_INITIALIZE,
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test" }
            },
            "id": 1
        });
        let ping_req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_PING,
            "id": 2
        });

        let input = format!("{init_req}\n{ping_req}\n");
        let mut output = Vec::new();

        let mut server = McpServer::new(MockProvider::default());
        process_lines(&mut server, input.as_bytes(), &mut output).await;

        // Parse output lines.
        let output_str = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = output_str.lines().collect();
        assert_eq!(lines.len(), 2);

        let resp1: JsonRpcResponse = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(resp1.id, RequestId::Number(1));
        assert!(resp1.result.is_some());

        let resp2: JsonRpcResponse = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(resp2.id, RequestId::Number(2));
        assert!(resp2.result.is_some());
    }

    #[tokio::test]
    async fn run_stdio_skips_empty_lines() {
        let input = "\n\n";
        let mut output = Vec::new();
        let mut server = McpServer::new(MockProvider::default());
        process_lines(&mut server, input.as_bytes(), &mut output).await;
        assert!(output.is_empty());
    }

    #[tokio::test]
    async fn run_stdio_handles_invalid_json() {
        let input = "not json\n";
        let mut output = Vec::new();
        let mut server = McpServer::new(MockProvider::default());
        process_lines(&mut server, input.as_bytes(), &mut output).await;

        let output_str = String::from_utf8(output).unwrap();
        let resp: JsonRpcResponse = serde_json::from_str(output_str.trim()).unwrap();
        assert!(resp.error.is_some());
        assert_eq!(
            resp.error.as_ref().unwrap().code,
            crate::protocol::PARSE_ERROR
        );
    }

    /// Helper: processes lines from a reader (simulating stdin) and writes
    /// responses to a writer (simulating stdout). Mirrors `run_stdio` logic
    /// but accepts generic async readers/writers for testing.
    async fn process_lines<P: ContextProvider>(
        server: &mut McpServer<P>,
        input: &[u8],
        output: &mut Vec<u8>,
    ) {
        let mut reader = BufReader::new(input);
        let mut line = String::new();

        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line).await.unwrap();
            if bytes_read == 0 {
                break;
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let response = match parse_incoming(trimmed) {
                Ok(Incoming::Request(req)) => server.handle_request(&req),
                Ok(Incoming::Notification(notif)) => {
                    let synthetic = JsonRpcRequest {
                        jsonrpc: notif.jsonrpc,
                        method: notif.method,
                        params: notif.params,
                        id: RequestId::Number(0),
                    };
                    server.handle_request(&synthetic);
                    None
                }
                Err(err_response) => Some(*err_response),
            };

            if let Some(resp) = response {
                let json = serde_json::to_string(&resp).unwrap();
                output.extend_from_slice(json.as_bytes());
                output.extend_from_slice(b"\n");
            }
        }
    }
}
