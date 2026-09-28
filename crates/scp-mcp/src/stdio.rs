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
use crate::server::{ContextProvider, McpServer, McpServerForTransport};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from the stdio transport.
#[derive(Debug, thiserror::Error)]
pub enum StdioError {
    /// An I/O error occurred reading from stdin or writing to stdout.
    #[error("stdio I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A line reached [`MAX_LINE_BYTES`] without a terminator. The loop stops
    /// rather than act on a truncated message, and reports the stop as an
    /// error so a host cannot mistake it for the client closing stdin.
    #[error("stdio line exceeds the {limit} byte limit")]
    LineTooLong {
        /// The byte limit the line reached.
        limit: u64,
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

/// Reads a line from a blocking `reader` into `buf`, bounded to [`MAX_LINE_BYTES`].
///
/// Returns the number of bytes read (0 on EOF), like
/// [`std::io::BufRead::read_line`].
///
/// # Errors
///
/// Returns an error when the read fails, when the line reaches the limit
/// before a newline, or when the line is not UTF-8.
pub fn read_line_bounded<R: std::io::BufRead>(
    reader: &mut R,
    buf: &mut String,
) -> Result<usize, String> {
    use std::io::{BufRead, Read};
    let mut raw = Vec::new();
    // `Read` is implemented for `&mut R`, so `take` consumes the temporary
    // reference, not the reader itself.
    let mut bounded = (&mut *reader).take(MAX_LINE_BYTES);
    // Raw bytes first, as in `read_loop_from`: a cap that falls inside a
    // multibyte character must surface as the oversize line it is, not as a
    // decoding error.
    let n = BufRead::read_until(&mut bounded, b'\n', &mut raw)
        .map_err(|e| format!("read error: {e}"))?;
    // Exactly at the cap with no newline means the line was truncated; reject
    // it rather than return partial data.
    if n as u64 == MAX_LINE_BYTES && raw.last() != Some(&b'\n') {
        return Err(format!(
            "line exceeds {MAX_LINE_BYTES} byte limit — possible denial-of-service"
        ));
    }
    let line = std::str::from_utf8(&raw).map_err(|e| format!("read error: {e}"))?;
    buf.push_str(line);
    Ok(n)
}

/// Maximum number of lines a stdio client skips while it waits for the
/// response to one request. Bounds a peer that streams notifications forever.
pub const MAX_SKIPPED_LINES: usize = 1000;

/// Reads lines from a stdio MCP server's stdout until the response to the
/// request with `id` arrives, each line bounded by [`read_line_bounded`].
///
/// A server writes notifications (`tools/list_changed`,
/// `resources/updated`, ...) to the same stream at any time, and a response
/// under another id answers an earlier request whose call already failed.
/// Handing either to this call would shift every later reply by one, so both
/// are skipped, as are blank lines and server-initiated requests.
///
/// # Errors
///
/// Returns an error on EOF, on a read error or an over-long line, on a line
/// that is not JSON, on a line carrying this `id` that is not a valid
/// response, and after [`MAX_SKIPPED_LINES`] lines without the response.
pub fn read_response<R: std::io::BufRead>(
    reader: &mut R,
    id: &RequestId,
) -> Result<JsonRpcResponse, String> {
    for _ in 0..MAX_SKIPPED_LINES {
        let mut line = String::new();
        if read_line_bounded(reader, &mut line)? == 0 {
            return Err("server closed stdout (EOF) while waiting for response".to_owned());
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|e| format!("failed to parse response JSON: {e}"))?;
        // A notification has no id; a server-initiated request has a method.
        let Some(line_id) = value.get("id") else {
            continue;
        };
        if value.get("method").is_some() {
            continue;
        }
        let line_id: RequestId = match serde_json::from_value(line_id.clone()) {
            Ok(line_id) => line_id,
            Err(_) => continue,
        };
        if &line_id != id {
            continue;
        }
        return serde_json::from_value(value)
            .map_err(|e| format!("failed to parse response JSON: {e}"));
    }
    Err(format!(
        "no matching JSON-RPC response after {MAX_SKIPPED_LINES} lines"
    ))
}

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
    ///
    /// Named `_raw` (not `write_line`) so the [`ClientChannel`] trait impl below
    /// can delegate to it by name — non-recursion is structural, not a matter of
    /// inherent-vs-trait method-resolution order.
    async fn write_line_raw(&self, json: &str) -> Result<(), std::io::Error> {
        let mut stdout = self.stdout.lock().await;
        stdout.write_all(json.as_bytes()).await?;
        stdout.write_all(b"\n").await?;
        stdout.flush().await
    }

    /// Pushes a JSON-RPC notification to the client.
    ///
    /// Returns the I/O error if the notification could not be written (e.g.
    /// the client closed stdout), or an [`std::io::ErrorKind::InvalidData`]
    /// error if it could not be serialized. Named `_raw` for the same reason
    /// as [`Self::write_line_raw`].
    async fn notify_raw(&self, notification: &JsonRpcNotification) -> std::io::Result<()> {
        let json = serde_json::to_string(notification)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.write_line_raw(&json).await
    }
}

/// Runs the MCP server over stdio (stdin/stdout, line-delimited JSON).
///
/// Reads JSON-RPC messages line-by-line from stdin, dispatches them to the
/// server, and writes responses to stdout. Runs until stdin is closed (EOF),
/// which returns `Ok(())`, or until a line exceeds [`MAX_LINE_BYTES`], which
/// returns [`StdioError::LineTooLong`].
///
/// # Resource subscriptions
///
/// `server` is the single [`McpServerForTransport`] bundle
/// [`McpServer::with_optional_event_source`](crate::server::McpServer::with_optional_event_source)
/// produces: a wired server *and* its [`ContextEventPump`](crate::server::ContextEventPump) as one value, or an
/// unwired server alone. A wired server advertises `resources.subscribe: true`;
/// its pump turns each [`ContextEvent`] into `notifications/resources/updated`
/// for the subscribed resources it invalidates. An unwired server
/// ([`McpServer::new`](crate::server::McpServer::new)) advertises
/// `resources.subscribe: false`, rejects `resources/subscribe`, and has no pump.
///
/// The server's advertisement and its pump are one value, consumed atomically —
/// a wired server cannot be transported without its pump, so there is no runtime
/// pairing check to perform: the mismatch is unconstructable by type.
///
/// The server is shared behind a mutex so the pump can consult the same
/// subscription registry as the read loop. The lock is an async mutex and is
/// held across awaits on purpose: the read loop holds it across dispatch and the
/// awaited response write, and the pump holds it across reading the registry and
/// the awaited notification write. Releasing it before either write would let
/// the read loop acknowledge `resources/unsubscribe` for a URI and then let the
/// pump deliver a `notifications/resources/updated` for that URI which it
/// computed from the registry as it stood before the unsubscribe. The test
/// `unsubscribe_ack_never_precedes_a_notification_computed_before_it` fails if
/// the pump drops the guard before its write.
///
/// Per JSON-RPC 2.0, incoming *notifications* (messages without an `id`) never
/// produce a response — this is why the transport parses into a request/
/// notification sum type rather than deserializing every line as a request.
///
/// # Errors
///
/// Returns [`StdioError::Io`] if an I/O error occurs on stdin or stdout, or if
/// a line within the limit is not valid UTF-8. Returns
/// [`StdioError::LineTooLong`] if a line reaches [`MAX_LINE_BYTES`] without a
/// terminator; the check runs on the raw bytes before UTF-8 decoding, so a cap
/// that falls inside a multibyte character reports the same error.
pub async fn run_stdio<P: ContextProvider + 'static>(
    server: McpServerForTransport<P>,
) -> Result<(), StdioError> {
    serve_stdio(
        server,
        BufReader::new(tokio::io::stdin()),
        StdioNotifier::new(),
    )
    .await
}

/// Splits the [`McpServerForTransport`] bundle, spawns the event pump (if the
/// server is wired) under an [`AbortOnDrop`] guard, and runs the read loop over
/// `reader`, writing responses and pump notifications to `channel`.
///
/// [`run_stdio`] binds `reader` to stdin and `channel` to stdout; tests bind
/// them to in-memory doubles so the *shipped* abort-on-cancel path — pump guard
/// and all — is the one under test rather than a copy.
///
/// Consuming the bundle is what makes "advertised ⟺ pump present" hold by
/// construction: the pump travels *inside* the wired variant, so there is no
/// separate pump argument that could be paired with the wrong server and no
/// runtime pairing check to perform.
///
/// The pump guard aborts the pump on **every** exit: the normal return after
/// EOF *and* the cancellation-drop when a bridge's `tokio::select!` drops this
/// future as `mcp_server_stop` fires. Dropping a bare `JoinHandle` only detaches
/// the task, so without the guard a stopped server would leave the pump running,
/// still writing notifications to stdout.
async fn serve_stdio<P, R, C>(
    bundle: McpServerForTransport<P>,
    reader: BufReader<R>,
    channel: C,
) -> Result<(), StdioError>
where
    P: ContextProvider + 'static,
    R: tokio::io::AsyncRead + Unpin + Send,
    C: ClientChannel,
{
    // `Some(pump)` exactly when the server is wired — the bundle guarantees it,
    // so no pairing check is needed here.
    let (server, pump) = bundle.into_parts();
    // One async mutex orders the whole session: the read loop holds it across
    // dispatch AND the response write, and the pump holds it across computing a
    // notification AND writing it. A notification computed from the registry
    // therefore reaches stdout before any later request's response, so the
    // client never receives `resources/updated` for a URI after the
    // `resources/unsubscribe` acknowledgement for it — the same ordering
    // `sse::pump_events` gets by broadcasting under its server lock.
    let server = Arc::new(tokio::sync::Mutex::new(server));

    let _pump_guard = pump.map(|pump| {
        AbortOnDrop(tokio::spawn(pump_events(
            Arc::clone(&server),
            pump.into_receiver(),
            channel.clone(),
        )))
    });

    read_loop_from(&server, reader, &channel).await
}

/// Forwards runtime context events to the client as MCP notifications.
async fn pump_events<P, C>(
    server: Arc<tokio::sync::Mutex<McpServer<P>>>,
    mut events: broadcast::Receiver<(String, ContextEvent)>,
    channel: C,
) where
    P: ContextProvider,
    C: ClientChannel,
{
    loop {
        let (context_id, event) = match events.recv().await {
            Ok(v) => v,
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                // The dropped events are gone; nothing can reconstruct which
                // resources they touched. Over-notify — one
                // resources/list_changed plus one tools/list_changed (the
                // capability-filtered tool list may also have shifted) plus one
                // resources/updated per still-authorized subscription — so a
                // lagged client re-reads, exactly as the pump promises. Never
                // fall silent.
                tracing::warn!("MCP stdio event pump lagged, {skipped} events dropped");
                // Held across the writes: see `serve_stdio`.
                let srv = server.lock().await;
                for notification in &srv.lagged_resync_notifications() {
                    if let Err(e) = channel.notify(notification).await {
                        // stdout is gone; the session is over.
                        tracing::warn!("MCP stdio notification write failed: {e}");
                        return;
                    }
                }
                // Released only after the writes land: see `serve_stdio`.
                drop(srv);
                continue;
            }
            Err(broadcast::error::RecvError::Closed) => return,
        };

        // Held across the writes: see `serve_stdio`. Releasing it before the
        // write would let the read loop acknowledge a `resources/unsubscribe`
        // between this read of the registry and the delivery it authorized.
        let srv = server.lock().await;
        for notification in &srv.notifications_for_event(&context_id, &event) {
            if let Err(e) = channel.notify(notification).await {
                // stdout is gone; the session is over.
                tracing::warn!("MCP stdio notification write failed: {e}");
                return;
            }
        }
        drop(srv);
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

    /// Pushes a JSON-RPC notification, returning the error if it could not be
    /// serialized or written (e.g. the client closed stdout).
    fn notify(
        &self,
        notification: &JsonRpcNotification,
    ) -> impl std::future::Future<Output = std::io::Result<()>> + Send;
}

impl ClientChannel for StdioNotifier {
    async fn write_line(&self, json: &str) -> std::io::Result<()> {
        // Delegates to the differently-named inherent method, so non-recursion
        // is structural — it does not depend on inherent-vs-trait resolution
        // order the way a same-named `Self::write_line` would.
        self.write_line_raw(json).await
    }

    async fn notify(&self, notification: &JsonRpcNotification) -> std::io::Result<()> {
        self.notify_raw(notification).await
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
    server: &Arc<tokio::sync::Mutex<McpServer<P>>>,
    mut reader: BufReader<R>,
    channel: &C,
) -> Result<(), StdioError>
where
    P: ContextProvider,
    R: tokio::io::AsyncRead + Unpin + Send,
    C: ClientChannel,
{
    let mut raw = Vec::new();

    loop {
        raw.clear();
        // Raw bytes first: the cap check must run before UTF-8 decoding,
        // because a cap that falls inside a multibyte character would
        // otherwise surface as a decoding error rather than as the oversize
        // line it is.
        let bytes_read = {
            let mut bounded = (&mut reader).take(MAX_LINE_BYTES);
            bounded.read_until(b'\n', &mut raw).await?
        };
        if bytes_read == 0 {
            // EOF -- stdin closed, exit cleanly.
            break;
        }
        // Exactly at the cap with no terminator means the line was truncated;
        // rejecting beats acting on a partial message.
        if bytes_read as u64 == MAX_LINE_BYTES && raw.last() != Some(&b'\n') {
            tracing::warn!("MCP stdio: line exceeds {MAX_LINE_BYTES} byte limit, stopping");
            return Err(StdioError::LineTooLong {
                limit: MAX_LINE_BYTES,
            });
        }
        let line = std::str::from_utf8(&raw)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Held across dispatch and the response write: see `serve_stdio`.
        let mut srv = server.lock().await;
        let response = match parse_incoming(trimmed) {
            Ok(Incoming::Request(req)) => srv.handle_request(&req),
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
                srv.handle_request(&synthetic);
                // Notifications never produce a response.
                None
            }
            Err(err_response) => Some(*err_response),
        };

        if let Some(resp) = response {
            match serde_json::to_string(&resp) {
                Ok(json) => channel.write_line(&json).await?,
                Err(e) => tracing::error!("failed to serialize response: {e}"),
            }
        }
        // A `tools/call` queues the notifications its outlet run causes. They
        // go out after its response, under the same lock. A failed write is a
        // stdout failure like a failed response write, so it returns
        // `StdioError::Io` rather than the `Ok(())` that means stdin EOF.
        for notification in &srv.take_pending_notifications() {
            channel.notify(notification).await?;
        }
        // Released only after the response is on the wire: see `serve_stdio`.
        drop(srv);
    }

    Ok(())
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
    use crate::server::ContextEventPump;
    use crate::server::TransportBundle;

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
        fn active_context_ids(&self) -> Result<Vec<String>, String> {
            Ok(self.contexts.clone())
        }
        fn agent_role(&self, _context_id: &str) -> Result<Option<String>, String> {
            Ok(Some("admin".to_owned()))
        }
        fn agent_did(&self) -> &str {
            &self.agent_did
        }
        fn context_tools(&self, _context_id: &str) -> Result<Vec<ContextOutletInfo>, String> {
            Ok(Vec::new())
        }
        fn validate_capability(
            &self,
            _context_id: &str,
            _tool_name: &str,
            _check: crate::server::CapabilityCheck,
        ) -> Result<(), crate::server::AccessRefusal> {
            Ok(())
        }
        fn invoke_outlet(
            &self,
            _context_id: &str,
            _outlet_id: &str,
            _arguments: serde_json::Value,
        ) -> Result<serde_json::Value, crate::server::OutletInvokeError> {
            Ok(serde_json::json!({"status": "ok"}))
        }
        fn validate_resource_access(
            &self,
            _context_id: &str,
            _resource: crate::server::ResourceKind,
        ) -> Result<(), crate::server::AccessRefusal> {
            Ok(())
        }
        fn context_members(&self, _context_id: &str) -> Result<Vec<MemberInfo>, String> {
            Ok(Vec::new())
        }
        fn context_events(&self, _context_id: &str) -> Result<serde_json::Value, String> {
            Ok(serde_json::json!([]))
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
        assert!(server.lock().await.is_initialized());
    }

    /// A line that hits `MAX_LINE_BYTES` with no terminator was truncated;
    /// acting on a partial message is worse than stopping, and the stop is
    /// reported as `LineTooLong` so a host can tell it from a clean EOF.
    #[tokio::test]
    async fn read_loop_stops_on_a_truncated_over_long_line() {
        // A well-formed prefix, then an unterminated flood that trips the cap.
        let ping = serde_json::json!({"jsonrpc": "2.0", "method": METHOD_PING, "id": 7});
        let mut input = format!("{ping}\n").into_bytes();
        let flood = usize::try_from(MAX_LINE_BYTES).expect("cap fits in usize on test targets");
        input.extend(std::iter::repeat_n(b'x', flood));

        let server = shared_server();
        // `ping` is allowed pre-initialization, so the first line answers.
        let (result, output) = run_loop(&server, &input).await;
        assert!(
            matches!(result, Err(StdioError::LineTooLong { limit }) if limit == MAX_LINE_BYTES),
            "an over-long line must end the loop with LineTooLong, got {result:?}"
        );

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

    /// The cap is checked on raw bytes before UTF-8 decoding: a cap that falls
    /// inside a multibyte character is still an over-long line, not an I/O
    /// decoding error.
    #[tokio::test]
    async fn read_loop_reports_line_too_long_when_the_cap_splits_a_character() {
        let cap = usize::try_from(MAX_LINE_BYTES).expect("cap fits in usize on test targets");
        // Two ASCII bytes, then 3-byte characters: the cap lands mid-character
        // because `cap - 2` is not a multiple of 3.
        assert_ne!(
            (cap - 2) % 3,
            0,
            "the fixture must split a character at the cap"
        );
        let mut input = vec![b'x', b'x'];
        while input.len() <= cap {
            input.extend_from_slice("\u{20ac}".as_bytes());
        }

        let (result, output) = run_loop(&shared_server(), &input).await;
        assert!(
            matches!(result, Err(StdioError::LineTooLong { .. })),
            "a cap inside a multibyte character must report LineTooLong, got {result:?}"
        );
        assert!(
            output.is_empty(),
            "nothing may be dispatched from a truncated line"
        );
    }

    /// The blocking reader the stdio and SSE clients use checks the cap on raw
    /// bytes too: a cap inside a multibyte character reports the over-long
    /// line, not a UTF-8 decoding error.
    #[test]
    fn read_line_bounded_reports_line_too_long_when_the_cap_splits_a_character() {
        let cap = usize::try_from(MAX_LINE_BYTES).expect("cap fits in usize on test targets");
        let mut input = vec![b'x', b'x'];
        while input.len() <= cap {
            input.extend_from_slice("\u{20ac}".as_bytes());
        }
        let mut reader = std::io::Cursor::new(input);
        let mut buf = String::new();
        let err = read_line_bounded(&mut reader, &mut buf).expect_err("over-long line");
        assert!(err.contains("byte limit"), "got: {err}");
        assert!(buf.is_empty(), "no partial line may be returned");

        let mut reader = std::io::Cursor::new("h\u{e9}\nrest".as_bytes().to_vec());
        assert_eq!(read_line_bounded(&mut reader, &mut buf), Ok(4));
        assert_eq!(buf, "h\u{e9}\n");
    }

    /// The server writes notifications to stdout between responses, and a
    /// response under another id answers an earlier failed call: the client
    /// reader skips both and returns only the response to its own request,
    /// leaving the next line for the next call.
    #[test]
    fn read_response_skips_notifications_and_other_ids() {
        let line = |v: String| format!("{v}\n");
        let notify = |method| {
            line(
                serde_json::to_string(&JsonRpcNotification::new(method, None))
                    .expect("serialize notification"),
            )
        };
        let respond = |id: i64| {
            line(
                serde_json::to_string(&JsonRpcResponse::success(
                    RequestId::Number(id),
                    serde_json::json!({ "n": id }),
                ))
                .expect("serialize response"),
            )
        };
        let mut input = String::new();
        input.push_str(&notify(crate::protocol::METHOD_TOOLS_LIST_CHANGED));
        input.push_str(&respond(1));
        input.push('\n');
        input.push_str(&notify(crate::protocol::METHOD_RESOURCES_UPDATED));
        input.push_str(
            "{\"jsonrpc\":\"2.0\",\"method\":\"roots/list\",\"id\":2}\n",
        );
        input.push_str(&respond(2));
        input.push_str(&respond(3));
        let mut reader = std::io::Cursor::new(input.into_bytes());

        let first = read_response(&mut reader, &RequestId::Number(2)).expect("response 2");
        assert_eq!(first.id, RequestId::Number(2));
        assert_eq!(first.result, Some(serde_json::json!({ "n": 2 })));
        let second = read_response(&mut reader, &RequestId::Number(3)).expect("response 3");
        assert_eq!(second.result, Some(serde_json::json!({ "n": 3 })));
        let eof = read_response(&mut reader, &RequestId::Number(4)).expect_err("EOF");
        assert!(eof.contains("EOF"), "got: {eof}");
    }

    /// A line that is not JSON, or an over-long line, fails the call rather
    /// than being skipped as noise.
    #[test]
    fn read_response_rejects_garbage_and_over_long_lines() {
        let mut reader = std::io::Cursor::new(b"not json\n".to_vec());
        let err = read_response(&mut reader, &RequestId::Number(1)).expect_err("garbage");
        assert!(err.contains("parse"), "got: {err}");

        let cap = usize::try_from(MAX_LINE_BYTES).expect("cap fits in usize on test targets");
        let mut reader = std::io::Cursor::new(vec![b' '; cap + 1]);
        let err = read_response(&mut reader, &RequestId::Number(1)).expect_err("over-long");
        assert!(err.contains("byte limit"), "got: {err}");
    }

    /// Drives the REAL `read_loop_from` and returns its result with everything
    /// it wrote, for tests that assert on how the loop ended.
    async fn run_loop<P: ContextProvider>(
        server: &Arc<tokio::sync::Mutex<McpServer<P>>>,
        input: &[u8],
    ) -> (Result<(), StdioError>, Vec<u8>) {
        let channel = VecSink::default();
        let result = read_loop_from(server, BufReader::new(input), &channel).await;
        let output = channel.lines.lock().await.clone();
        (result, output)
    }

    /// Drives the REAL `read_loop_from` — the loop `run_stdio` runs — over an
    /// in-memory reader, returning everything the loop wrote.
    ///
    /// The previous helper reimplemented the loop, so the JSON-RPC
    /// notification handling this crate claims to have fixed was verified
    /// against a copy of itself rather than against shipped code.
    async fn process_lines<P: ContextProvider>(
        server: &Arc<tokio::sync::Mutex<McpServer<P>>>,
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

        async fn notify(&self, notification: &JsonRpcNotification) -> std::io::Result<()> {
            let json = serde_json::to_string(notification)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            self.notifications.lock().await.push(json);
            Ok(())
        }
    }

    impl VecSink {
        /// The serialized notifications the pump has pushed so far.
        async fn notifications(&self) -> Vec<String> {
            self.notifications.lock().await.clone()
        }
    }

    /// Wraps a mock-backed server for the in-memory loop.
    fn shared_server() -> Arc<tokio::sync::Mutex<McpServer<MockProvider>>> {
        Arc::new(tokio::sync::Mutex::new(McpServer::new(
            MockProvider::default(),
        )))
    }

    /// Builds a *wired* server (advertising `resources.subscribe`) that has
    /// completed `initialize` and subscribed to `uri`, returning the event
    /// sender, the server, and the pump the transport must drive.
    fn wired_subscribed_server(
        uri: &str,
    ) -> (
        broadcast::Sender<(String, ContextEvent)>,
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

    /// The read loop sends the notifications a `tools/call` queued, after the
    /// call's response. Without the drain, a subscriber to
    /// `scp://{ctx}/events` would not learn that the call appended to the log.
    #[tokio::test]
    async fn read_loop_sends_the_notifications_a_tools_call_queued() {
        let (_event_tx, server, _pump) = wired_subscribed_server("scp://ctx_a/events");
        let server = Arc::new(tokio::sync::Mutex::new(server));
        let call = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "ctx_a/send_message", "arguments": {"content": "hi"}},
            "id": 3
        });
        let channel = VecSink::default();
        read_loop_from(
            &server,
            BufReader::new(format!("{call}\n").as_bytes()),
            &channel,
        )
        .await
        .unwrap();

        let lines = channel.lines.lock().await.clone();
        let response: serde_json::Value = serde_json::from_slice(&lines).unwrap();
        assert!(response.get("error").is_none(), "{response}");
        let notifications = channel.notifications().await;
        assert!(
            notifications
                .iter()
                .any(|n| n.contains("notifications/resources/updated")
                    && n.contains("scp://ctx_a/events")),
            "{notifications:?}"
        );
        assert!(server.lock().await.take_pending_notifications().is_empty());
    }

    /// A channel whose response writes succeed and whose notification writes
    /// fail with `BrokenPipe`, as when the client closes stdout after the
    /// response reached the pipe buffer.
    #[derive(Clone, Default)]
    struct NotifyFailsSink {
        lines: Arc<tokio::sync::Mutex<Vec<u8>>>,
    }

    impl ClientChannel for NotifyFailsSink {
        async fn write_line(&self, json: &str) -> std::io::Result<()> {
            {
                let mut buf = self.lines.lock().await;
                buf.extend_from_slice(json.as_bytes());
                buf.push(b'\n');
            }
            Ok(())
        }

        async fn notify(&self, _notification: &JsonRpcNotification) -> std::io::Result<()> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
    }

    /// A failed write of a notification a `tools/call` queued is a stdout
    /// failure: the read loop returns `StdioError::Io`, as it does for a failed
    /// response write, and never the `Ok(())` that means stdin reached EOF.
    #[tokio::test]
    async fn read_loop_reports_a_failed_notification_write_as_io() {
        let (_event_tx, server, _pump) = wired_subscribed_server("scp://ctx_a/events");
        let server = Arc::new(tokio::sync::Mutex::new(server));
        let call = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "ctx_a/send_message", "arguments": {"content": "hi"}},
            "id": 3
        });
        let channel = NotifyFailsSink::default();
        let result = read_loop_from(
            &server,
            BufReader::new(format!("{call}\n").as_bytes()),
            &channel,
        )
        .await;

        assert!(
            !channel.lines.lock().await.is_empty(),
            "the response write must succeed before the notification write fails"
        );
        match result {
            Err(StdioError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe),
            other => panic!("expected StdioError::Io(BrokenPipe), got {other:?}"),
        }
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
        // The wired server and its pump travel to the transport as one bundle,
        // exactly as `run_stdio` receives them from `with_optional_event_source`.
        let bundle = McpServerForTransport(TransportBundle::Wired(server, pump));
        let channel = VecSink::default();

        // A reader that never reaches EOF: stdin stays "open" so `serve_stdio`
        // only ends when its future is dropped — exactly what a bridge's
        // shutdown `select!` branch does. `keep_open` stays alive so the read
        // half pends forever instead of seeing EOF.
        let (keep_open, pending) = tokio::io::duplex(64);

        // Drive the SHIPPED serve loop on a task. Aborting the task drops the
        // `serve_stdio` future, the same drop the bridge `select!` performs.
        let serve = {
            let channel = channel.clone();
            tokio::spawn(async move {
                let _ = serve_stdio(bundle, BufReader::new(pending), channel).await;
            })
        };

        // Positive control: the live pump delivers a first event.
        event_tx
            .send((
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
        let _ = event_tx.send((
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

    /// A [`ClientChannel`] that records every write in one ordered log and
    /// parks the first notification until the test releases it, so a test can
    /// hold the pump mid-write while the read loop handles a request.
    #[derive(Clone)]
    struct GatedSink {
        log: Arc<tokio::sync::Mutex<Vec<String>>>,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Semaphore>,
    }

    impl ClientChannel for GatedSink {
        async fn write_line(&self, json: &str) -> std::io::Result<()> {
            self.log.lock().await.push(json.to_owned());
            Ok(())
        }

        async fn notify(&self, notification: &JsonRpcNotification) -> std::io::Result<()> {
            self.entered.notify_one();
            self.release
                .acquire()
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?
                .forget();
            let json = serde_json::to_string(notification).expect("serialize");
            self.log.lock().await.push(json);
            Ok(())
        }
    }

    /// The pump computes a notification from the subscription registry and
    /// writes it; a `resources/unsubscribe` the read loop handles in between
    /// must not be acknowledged before that write lands. Otherwise the client
    /// receives `resources/updated` for a URI it was just told is unsubscribed.
    #[tokio::test]
    async fn unsubscribe_ack_never_precedes_a_notification_computed_before_it() {
        use scp_core::context::membership::ContextEvent;

        let uri = "scp://ctx_a/events";
        let (event_tx, server, pump) = wired_subscribed_server(uri);
        let server = Arc::new(tokio::sync::Mutex::new(server));
        let sink = GatedSink {
            log: Arc::default(),
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
        };

        let pump_task = tokio::spawn(pump_events(
            Arc::clone(&server),
            pump.into_receiver(),
            sink.clone(),
        ));
        event_tx
            .send((
                "ctx_a".to_owned(),
                ContextEvent::ContentKeysRotated { reason: None },
            ))
            .expect("event send");
        // The pump has read the registry and is parked inside its write.
        tokio::time::timeout(Duration::from_secs(5), sink.entered.notified())
            .await
            .expect("the pump never started writing the notification");

        let unsubscribe = serde_json::to_string(&JsonRpcRequest {
            jsonrpc: crate::protocol::JSONRPC_VERSION.to_owned(),
            method: crate::protocol::METHOD_RESOURCES_UNSUBSCRIBE.to_owned(),
            params: Some(serde_json::json!({ "uri": uri })),
            id: RequestId::Number(3),
        })
        .expect("serialize")
            + "\n";
        let read_loop = {
            let server = Arc::clone(&server);
            let sink = sink.clone();
            tokio::spawn(async move {
                read_loop_from(
                    &server,
                    BufReader::new(std::io::Cursor::new(unsubscribe.into_bytes())),
                    &sink,
                )
                .await
            })
        };
        // Give the read loop time to acknowledge the unsubscribe if nothing
        // orders it behind the pump's in-flight write.
        tokio::time::sleep(Duration::from_millis(150)).await;
        sink.release.add_permits(64);

        tokio::time::timeout(Duration::from_secs(5), read_loop)
            .await
            .expect("read loop did not finish")
            .expect("read loop task panicked")
            .expect("read loop must not error on in-memory input");
        // Let the released pump finish its write before reading the log.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !sink
            .log
            .lock()
            .await
            .iter()
            .any(|l| l.contains(crate::protocol::METHOD_RESOURCES_UPDATED))
        {
            assert!(
                std::time::Instant::now() < deadline,
                "the pump must deliver the notification it computed"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        pump_task.abort();

        let log = sink.log.lock().await.clone();
        let updated = log
            .iter()
            .position(|l| l.contains(crate::protocol::METHOD_RESOURCES_UPDATED))
            .expect("the pump must deliver the notification it computed");
        let ack = log
            .iter()
            .position(|l| l.contains("\"id\":3"))
            .expect("the unsubscribe must be acknowledged");
        assert!(
            updated < ack,
            "resources/updated was written after the unsubscribe acknowledgement: {log:?}"
        );
    }
}
