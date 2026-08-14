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

use scp_core::context::membership::ContextEventEnvelope;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::broadcast;

use crate::protocol::{
    JsonRpcError, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, RequestId,
};
use crate::server::{ContextEventPump, ContextProvider, McpServer};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from the stdio transport.
#[derive(Debug, thiserror::Error)]
pub enum StdioError {
    /// An I/O error occurred reading from stdin or writing to stdout.
    #[error("stdio I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The server and pump handed to the transport are not a matched pair: a
    /// server that advertises `resources.subscribe` arrived without its pump, or
    /// an unwired server arrived with one. The two are produced together by
    /// [`McpServer::with_event_source`](crate::server::McpServer::with_event_source);
    /// this fails closed rather than serve an advertise-but-never-deliver lie
    /// (wired, no pump) or run a delivery loop the server never advertised
    /// (unwired, spare pump).
    #[error(
        "MCP stdio: server/pump mismatch (event_source_wired={wired}, pump_present={has_pump}); \
         a wired server must be driven with its pump and an unwired server must not be given one"
    )]
    PumpServerMismatch {
        /// Whether the server advertises `resources.subscribe`.
        wired: bool,
        /// Whether a pump was supplied.
        has_pump: bool,
    },
}

/// Aborts a spawned task when dropped.
///
/// The event pump is spawned as a detached [`tokio::task`]; a bare
/// [`JoinHandle`](tokio::task::JoinHandle) dropped without `abort()` *detaches*
/// the task rather than stopping it. Holding the handle in this guard makes the
/// abort run on **every** exit from [`serve_stdio`] — the normal return after
/// EOF *and* the case where a `tokio::select!` in a bridge drops the
/// `run_stdio` future mid-await when `mcp_server_stop` fires. Without it, the
/// pump would outlive the stopped server and keep writing JSON-RPC
/// notifications to stdout. [`run_sse`](crate::sse::run_sse) uses it for the
/// same reason.
pub(crate) struct AbortOnDrop(pub(crate) tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
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
/// `server` and `pump` are a **matched pair produced at construction**:
/// [`McpServer::with_event_source`](crate::server::McpServer::with_event_source)
/// (and the `with_optional_event_source` convenience) yield the wired server and
/// its [`ContextEventPump`] from one call. A wired server advertises
/// `resources.subscribe: true`; its pump turns each [`ContextEvent`] into
/// `notifications/resources/updated` for the subscribed resources it
/// invalidates. An unwired server ([`McpServer::new`](crate::server::McpServer::new))
/// advertises `resources.subscribe: false`, rejects `resources/subscribe`, and
/// has no pump (`None`).
///
/// The transport takes the two as *separate* arguments, so it MUST drive both.
/// It verifies the pairing at entry and fails closed with
/// [`StdioError::PumpServerMismatch`] if a wired server arrives without its pump
/// (an advertise-but-never-deliver lie) or an unwired server with one.
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
/// Returns [`StdioError::Io`] if an I/O error occurs on stdin or stdout, or
/// [`StdioError::PumpServerMismatch`] if `server` and `pump` are not a matched
/// pair.
pub async fn run_stdio<P: ContextProvider + 'static>(
    server: &Arc<std::sync::Mutex<McpServer<P>>>,
    pump: Option<ContextEventPump>,
) -> Result<(), StdioError> {
    serve_stdio(
        server,
        pump,
        BufReader::new(tokio::io::stdin()),
        StdioNotifier::new(),
    )
    .await
}

/// Spawns the event pump (if any) under an [`AbortOnDrop`] guard and runs the
/// read loop over `reader`, writing responses and pump notifications to
/// `channel`.
///
/// [`run_stdio`] binds `reader` to stdin and `channel` to stdout; tests bind
/// them to in-memory doubles so the *shipped* abort-on-cancel path — pump guard
/// and all — is the one under test rather than a copy.
///
/// The pump guard aborts the pump on **every** exit: the normal return after
/// EOF *and* the cancellation-drop when a bridge's `tokio::select!` drops this
/// future as `mcp_server_stop` fires. Dropping a bare `JoinHandle` only detaches
/// the task, so without the guard a stopped server would leave the pump running,
/// still writing notifications to stdout.
async fn serve_stdio<P, R, C>(
    server: &Arc<std::sync::Mutex<McpServer<P>>>,
    pump: Option<ContextEventPump>,
    reader: BufReader<R>,
    channel: C,
) -> Result<(), StdioError>
where
    P: ContextProvider + 'static,
    R: tokio::io::AsyncRead + Unpin + Send,
    C: ClientChannel,
{
    // Fail closed on a server/pump pairing the constructor could not have
    // produced: `event_source_wired` must hold exactly when a pump is present.
    // A wired server with no pump would advertise resources.subscribe with
    // nothing delivering; an unwired server with a spare pump would run a
    // delivery loop it never advertised. This catches multi-server mixups the
    // `#[must_use]` on `ContextEventPump` cannot — that only forces the pump to
    // be consumed *somewhere*, not driven with *its own* server. A poisoned
    // lock reads as unwired, which also fails closed when a pump is present.
    let wired = server.lock().is_ok_and(|srv| srv.event_source_wired());
    if wired != pump.is_some() {
        return Err(StdioError::PumpServerMismatch {
            wired,
            has_pump: pump.is_some(),
        });
    }

    let _pump_guard = pump.map(|pump| {
        AbortOnDrop(tokio::spawn(pump_events(
            Arc::clone(server),
            pump.into_receiver(),
            channel.clone(),
        )))
    });

    read_loop_from(server, reader, &channel).await
}

/// Forwards runtime context events to the client as MCP notifications.
async fn pump_events<P, C>(
    server: Arc<std::sync::Mutex<McpServer<P>>>,
    mut events: broadcast::Receiver<ContextEventEnvelope>,
    channel: C,
) where
    P: ContextProvider,
    C: ClientChannel,
{
    loop {
        let ContextEventEnvelope { context_id, event } = match events.recv().await {
            Ok(v) => v,
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                // The dropped events are gone; nothing can reconstruct which
                // resources they touched. Over-notify — one
                // resources/list_changed plus one resources/updated per
                // still-authorized subscription — so a lagged client re-reads,
                // exactly as the pump promises. Never fall silent.
                tracing::warn!("MCP stdio event pump lagged, {skipped} events dropped");
                let notifications = match server.lock() {
                    Ok(srv) => srv.lagged_resync_notifications(),
                    Err(e) => {
                        tracing::error!("MCP server mutex poisoned in event pump: {e}");
                        return;
                    }
                };
                for notification in &notifications {
                    if !channel.notify(notification).await {
                        // stdout is gone; the session is over.
                        return;
                    }
                }
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
            if !channel.notify(notification).await {
                // stdout is gone; the session is over.
                return;
            }
        }
    }
}

/// The server→client push surface for a stdio session: JSON-RPC response lines
/// from the read loop and notifications from the event pump share it so they
/// interleave as whole lines on one stdout.
///
/// Abstracted so [`serve_stdio`] — the loop that actually ships, pump guard and
/// all — can be driven over in-memory doubles in tests rather than
/// reimplemented there. `Clone + Send + Sync + 'static` is required because the
/// spawned pump task owns its own handle to the channel.
trait ClientChannel: Clone + Send + Sync + 'static {
    /// Writes one complete line, terminator included.
    fn write_line(
        &self,
        json: &str,
    ) -> impl std::future::Future<Output = std::io::Result<()>> + Send;

    /// Pushes a JSON-RPC notification, returning `false` if it could not be
    /// written (e.g. the client closed stdout).
    fn notify(
        &self,
        notification: &JsonRpcNotification,
    ) -> impl std::future::Future<Output = bool> + Send;
}

impl ClientChannel for StdioNotifier {
    async fn write_line(&self, json: &str) -> std::io::Result<()> {
        // `Self::` resolves to the inherent method (preferred over the trait
        // method of the same name), so this delegates rather than recurses.
        Self::write_line(self, json).await
    }

    async fn notify(&self, notification: &JsonRpcNotification) -> bool {
        Self::notify(self, notification).await
    }
}

/// The transport read loop, parameterized over its input and its response
/// channel.
///
/// [`serve_stdio`] binds it to stdin/stdout; tests bind it to in-memory doubles.
/// Keeping one body means the JSON-RPC notification handling, the
/// [`MAX_LINE_BYTES`] truncation guard and the dispatch path that ship are the
/// ones under test — a test-local reimplementation would verify a copy.
async fn read_loop_from<P, R, C>(
    server: &Arc<std::sync::Mutex<McpServer<P>>>,
    mut reader: BufReader<R>,
    channel: &C,
) -> Result<(), StdioError>
where
    P: ContextProvider,
    R: tokio::io::AsyncRead + Unpin + Send,
    C: ClientChannel,
{
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
            channel.write_line(&json).await?;
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
    use std::time::Duration;

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
        fn validate_resource_access(
            &self,
            _context_id: &str,
            _resource: crate::server::ResourceKind,
        ) -> Result<(), String> {
            Ok(())
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
        let server = shared_server();
        let output = process_lines(&server, input.as_bytes()).await;

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
        let server = shared_server();
        let output = process_lines(&server, b"\n\n").await;
        assert!(output.is_empty());
    }

    #[tokio::test]
    async fn run_stdio_handles_invalid_json() {
        let server = shared_server();
        let output = process_lines(&server, b"not json\n").await;

        let output_str = String::from_utf8(output).unwrap();
        let resp: JsonRpcResponse = serde_json::from_str(output_str.trim()).unwrap();
        assert!(resp.error.is_some());
        assert_eq!(
            resp.error.as_ref().unwrap().code,
            crate::protocol::PARSE_ERROR
        );
    }

    /// Per JSON-RPC 2.0 a *notification* never draws a response. This is the
    /// defect the three duplicated hand-rolled bridge loops had — they decoded
    /// every line as `JsonRpcRequest`, whose `id` is required, so the mandatory
    /// `notifications/initialized` handshake step drew an error response.
    ///
    /// This drives the shipped loop, not a copy of it.
    #[tokio::test]
    async fn read_loop_never_answers_a_notification() {
        let init = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_INITIALIZE,
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test" }
            },
            "id": 1
        });
        let initialized = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_INITIALIZED
        });

        let server = shared_server();
        let output = process_lines(&server, format!("{init}\n{initialized}\n").as_bytes()).await;

        let text = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "only `initialize` may draw a response, got: {text}"
        );
        let resp: JsonRpcResponse = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(resp.id, RequestId::Number(1));
        assert!(resp.error.is_none());
        assert!(server.lock().unwrap().is_initialized());
    }

    /// A line that hits `MAX_LINE_BYTES` with no terminator was truncated;
    /// acting on a partial message is worse than stopping. This path had no
    /// coverage at all.
    #[tokio::test]
    async fn read_loop_stops_on_a_truncated_over_long_line() {
        // A well-formed prefix, then an unterminated flood that trips the cap.
        let ping = serde_json::json!({"jsonrpc": "2.0", "method": METHOD_PING, "id": 7});
        let mut input = format!("{ping}\n").into_bytes();
        let flood = usize::try_from(MAX_LINE_BYTES).expect("cap fits in usize on test targets");
        input.extend(std::iter::repeat_n(b'x', flood));

        let server = shared_server();
        // `ping` is allowed pre-initialization, so the first line answers.
        let output = process_lines(&server, &input).await;

        let text = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "the truncated line must stop the loop, not be dispatched: {text}"
        );
        let resp: JsonRpcResponse = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(resp.id, RequestId::Number(7));
    }

    /// Drives the REAL `read_loop_from` — the loop `run_stdio` runs — over an
    /// in-memory reader, returning everything the loop wrote.
    ///
    /// The previous helper reimplemented the loop, so the JSON-RPC
    /// notification handling this crate claims to have fixed was verified
    /// against a copy of itself rather than against shipped code.
    async fn process_lines<P: ContextProvider>(
        server: &Arc<std::sync::Mutex<McpServer<P>>>,
        input: &[u8],
    ) -> Vec<u8> {
        let channel = VecSink::default();
        read_loop_from(server, BufReader::new(input), &channel)
            .await
            .expect("read loop must not error on in-memory input");
        channel.lines.lock().await.clone()
    }

    /// In-memory [`ClientChannel`] capturing response lines from the read loop
    /// and notifications from the event pump. `Clone` (via inner `Arc`s) lets
    /// the spawned pump own its own handle while a test observes the shared
    /// buffers.
    #[derive(Clone, Default)]
    struct VecSink {
        lines: Arc<tokio::sync::Mutex<Vec<u8>>>,
        notifications: Arc<tokio::sync::Mutex<Vec<String>>>,
    }

    impl ClientChannel for VecSink {
        async fn write_line(&self, json: &str) -> std::io::Result<()> {
            {
                let mut buf = self.lines.lock().await;
                buf.extend_from_slice(json.as_bytes());
                buf.push(b'\n');
            }
            Ok(())
        }

        async fn notify(&self, notification: &JsonRpcNotification) -> bool {
            if let Ok(json) = serde_json::to_string(notification) {
                self.notifications.lock().await.push(json);
            }
            true
        }
    }

    impl VecSink {
        /// The serialized notifications the pump has pushed so far.
        async fn notifications(&self) -> Vec<String> {
            self.notifications.lock().await.clone()
        }
    }

    /// Wraps a mock-backed server for the in-memory loop.
    fn shared_server() -> Arc<std::sync::Mutex<McpServer<MockProvider>>> {
        Arc::new(std::sync::Mutex::new(McpServer::new(
            MockProvider::default(),
        )))
    }

    /// Builds a *wired* server (advertising `resources.subscribe`) that has
    /// completed `initialize` and subscribed to `uri`, returning the event
    /// sender, the server, and the pump the transport must drive.
    fn wired_subscribed_server(
        uri: &str,
    ) -> (
        broadcast::Sender<ContextEventEnvelope>,
        McpServer<MockProvider>,
        ContextEventPump,
    ) {
        let (tx, rx) = broadcast::channel(16);
        let (mut server, pump) = McpServer::with_event_source(MockProvider::default(), rx);

        let init = JsonRpcRequest {
            jsonrpc: crate::protocol::JSONRPC_VERSION.to_owned(),
            method: METHOD_INITIALIZE.to_owned(),
            params: Some(serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test" }
            })),
            id: RequestId::Number(1),
        };
        assert!(server.handle_request(&init).unwrap().error.is_none());

        let sub = JsonRpcRequest {
            jsonrpc: crate::protocol::JSONRPC_VERSION.to_owned(),
            method: crate::protocol::METHOD_RESOURCES_SUBSCRIBE.to_owned(),
            params: Some(serde_json::json!({ "uri": uri })),
            id: RequestId::Number(2),
        };
        assert!(server.handle_request(&sub).unwrap().error.is_none());

        (tx, server, pump)
    }

    /// The HIGH-severity fix: stopping the server while stdin is still open must
    /// **abort** the event pump, not detach it. All three bridges wrap
    /// `run_stdio` in a `tokio::select!` that drops the future when
    /// `mcp_server_stop` fires; dropping a bare pump `JoinHandle` detaches the
    /// task, which kept running and kept writing `notifications/...` to stdout
    /// after the server stopped. The `AbortOnDrop` guard in `serve_stdio` closes
    /// that leak, and this test drives the shipped `serve_stdio` to prove it.
    #[tokio::test]
    async fn stopping_stdio_while_stdin_is_open_aborts_the_pump() {
        use scp_core::context::membership::ContextEvent;

        let (event_tx, server, pump) = wired_subscribed_server("scp://ctx_a/events");
        let server = Arc::new(std::sync::Mutex::new(server));
        let channel = VecSink::default();

        // A reader that never reaches EOF: stdin stays "open" so `serve_stdio`
        // only ends when its future is dropped — exactly what a bridge's
        // shutdown `select!` branch does. `keep_open` stays alive so the read
        // half pends forever instead of seeing EOF.
        let (keep_open, pending) = tokio::io::duplex(64);

        // Drive the SHIPPED serve loop on a task. Aborting the task drops the
        // `serve_stdio` future, the same drop the bridge `select!` performs.
        let serve = {
            let server = Arc::clone(&server);
            let channel = channel.clone();
            tokio::spawn(async move {
                let _ = serve_stdio(&server, Some(pump), BufReader::new(pending), channel).await;
            })
        };

        // Positive control: the live pump delivers a first event.
        event_tx
            .send(ContextEventEnvelope::new(
                "ctx_a".to_owned(),
                ContextEvent::ContentKeysRotated { reason: None },
            ))
            .expect("event send");

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let seen = channel
                .notifications()
                .await
                .iter()
                .any(|n| n.contains(crate::protocol::METHOD_RESOURCES_UPDATED));
            if seen {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the live pump never delivered the first event"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Stop the server mid-stream. Awaiting the aborted task guarantees the
        // `serve_stdio` future was dropped, so its `AbortOnDrop` guard has run.
        serve.abort();
        let _ = serve.await;
        tokio::task::yield_now().await;

        // The pump must now be dead: a fresh event produces nothing more.
        let before = channel.notifications().await.len();
        let _ = event_tx.send(ContextEventEnvelope::new(
            "ctx_a".to_owned(),
            ContextEvent::ContentKeysRotated { reason: None },
        ));
        tokio::time::sleep(Duration::from_millis(150)).await;
        let after = channel.notifications().await.len();
        assert_eq!(
            before, after,
            "the pump kept delivering after the server stopped — it was detached, not aborted"
        );

        drop(keep_open);
    }

    /// A wired server handed to the transport without its pump is the exact
    /// advertise-but-never-deliver lie the pairing guard must reject.
    #[tokio::test]
    async fn serve_stdio_rejects_a_wired_server_with_no_pump() {
        let (_tx, server, _pump) = wired_subscribed_server("scp://ctx_a/events");
        let server = Arc::new(std::sync::Mutex::new(server));
        // Drop the pump deliberately to model the desync (in real code the
        // `#[must_use]` would flag the drop; here we assert the transport also
        // fails closed).
        let err = serve_stdio(&server, None, BufReader::new(&b""[..]), VecSink::default())
            .await
            .expect_err("a wired server with no pump must be refused");
        assert!(
            matches!(
                err,
                StdioError::PumpServerMismatch {
                    wired: true,
                    has_pump: false
                }
            ),
            "expected PumpServerMismatch, got {err:?}"
        );
    }

    /// An unwired server handed a spare pump must also be refused — it would run
    /// a delivery loop the server never advertised.
    #[tokio::test]
    async fn serve_stdio_rejects_an_unwired_server_with_a_pump() {
        let (_tx, _wired, pump) = wired_subscribed_server("scp://ctx_a/events");
        let unwired = Arc::new(std::sync::Mutex::new(McpServer::new(
            MockProvider::default(),
        )));
        let err = serve_stdio(
            &unwired,
            Some(pump),
            BufReader::new(&b""[..]),
            VecSink::default(),
        )
        .await
        .expect_err("an unwired server with a pump must be refused");
        assert!(
            matches!(
                err,
                StdioError::PumpServerMismatch {
                    wired: false,
                    has_pump: true
                }
            ),
            "expected PumpServerMismatch, got {err:?}"
        );
    }
}
