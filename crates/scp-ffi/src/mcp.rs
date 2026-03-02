//! `PyO3` bridge functions for MCP (Model Context Protocol) server and client.
//!
//! Exposes SCP MCP operations to Python:
//!
//! - [`py_mcp_serve`] -- Start an MCP server exposing SCP context tools.
//! - [`py_mcp_server_stop`] -- Stop a running MCP server.
//! - [`py_mcp_server_wait`] -- Block until the MCP server exits.
//! - [`py_mcp_server_info`] -- Return metadata about a running MCP server.
//! - [`py_mcp_client_connect_stdio`] -- Connect to an external MCP server via
//!   stdio.
//! - [`py_mcp_client_connect_sse`] -- Connect to an external MCP server via
//!   SSE.
//! - [`py_mcp_client_disconnect`] -- Disconnect from an external MCP server.
//! - [`py_mcp_client_info`] -- Return metadata about an active MCP client.
//! - [`py_mcp_client_list_tools`] -- List tools from an external MCP server.
//! - [`py_mcp_client_invoke`] -- Invoke an external MCP tool with provenance.
//! - [`py_mcp_load_contexts`] -- Load active contexts for a DID from a relay.
//!
//! The MCP bridge uses opaque string handles to track server and client
//! instances. Handles are stored in a global registry (similar to the
//! context runtime registry pattern).
//!
//! ## Architecture
//!
//! The bridge delegates to real `scp-mcp` implementations:
//!
//! - **Server side**: [`FfiBridgeProvider`] implements
//!   [`scp_mcp::server::ContextProvider`], reading tool registrations and
//!   context state from the scp-ffi runtime registry. The MCP server is run
//!   on the tokio runtime via [`scp_mcp::stdio::run_stdio`] or
//!   [`scp_mcp::sse::run_sse`].
//!
//! - **Client side**: [`StdioClientTransport`] implements
//!   [`scp_mcp::client::McpTransport`] by spawning a subprocess and
//!   communicating via line-delimited JSON-RPC over stdin/stdout. SSE
//!   client transport is managed via [`SseClientTransport`].
//!
//! See ADR-015 in `.docs/adrs/phase-3.md` for the full MCP adapter design.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};

use dashmap::DashMap;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use scp_mcp::allowlist;
use scp_mcp::client::{McpClient, McpTransport, SystemTimestamp};
use scp_mcp::protocol::{JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};
use scp_mcp::server::{ContextProvider, ContextToolInfo, McpServer, MemberInfo};

use crate::error::ScpPyError;
use crate::types::{json_to_py_dict, py_dict_to_json};
use crate::validate;

// ---------------------------------------------------------------------------
// Bounded read_line — prevents OOM from unbounded line reads
// ---------------------------------------------------------------------------

/// Maximum bytes to read for a single line from an MCP transport.
/// 10 MiB is generous for JSON-RPC messages (typical MCP responses are < 1 MiB)
/// while still preventing unbounded allocation from a malicious peer.
const MAX_LINE_BYTES: u64 = 10 * 1024 * 1024;

/// Read a line from `reader` into `buf`, bounded to [`MAX_LINE_BYTES`].
///
/// Returns the number of bytes read (0 on EOF), like [`BufRead::read_line`].
/// If the line exceeds the limit before a newline is found, returns an error.
fn read_line_bounded<R: BufRead>(reader: &mut R, buf: &mut String) -> Result<usize, String> {
    use std::io::Read;
    // `Read::take` consumes `self`, but `Read` is implemented for `&mut R`
    // so we pass `&mut *reader` which is `&mut R` — `take()` consumes the
    // temporary reference, not the reader itself.
    let mut bounded = (&mut *reader).take(MAX_LINE_BYTES);
    let n = bounded
        .read_line(buf)
        .map_err(|e| format!("read error: {e}"))?;
    // If we read exactly MAX_LINE_BYTES and there's no newline, the line
    // was truncated — reject it rather than silently returning partial data.
    if n as u64 == MAX_LINE_BYTES && !buf.ends_with('\n') {
        return Err(format!(
            "line exceeds {MAX_LINE_BYTES} byte limit — possible denial-of-service"
        ));
    }
    Ok(n)
}

// ---------------------------------------------------------------------------
// Stdio client transport
// ---------------------------------------------------------------------------

/// MCP client transport that communicates with a subprocess via stdin/stdout.
///
/// Spawns the given command, pipes stdin/stdout, and exchanges line-delimited
/// JSON-RPC messages synchronously. The subprocess's stderr is inherited by
/// the parent process for debugging.
struct StdioClientTransport {
    /// The subprocess handle, protected by a mutex for thread-safe access.
    /// Holds the child process, its stdin writer, and stdout reader.
    inner: Mutex<StdioTransportInner>,
}

/// Interior state for [`StdioClientTransport`], protected by a mutex.
struct StdioTransportInner {
    /// The spawned subprocess. Kept alive for the transport lifetime.
    /// Killed and reaped when the transport is dropped via [`Drop`].
    child: Child,
    /// Buffered writer to the subprocess's stdin.
    writer: std::io::BufWriter<std::process::ChildStdin>,
    /// Buffered reader from the subprocess's stdout.
    reader: BufReader<std::process::ChildStdout>,
}

impl StdioClientTransport {
    /// Spawns the given command and establishes JSON-RPC communication.
    ///
    /// # Errors
    ///
    /// Returns an error message if the subprocess fails to start.
    fn spawn(command: &[String]) -> Result<Self, String> {
        let (cmd, args) = command.split_first().ok_or("command list is empty")?;

        // Validate the command against the stdio allowlist (defense-in-depth).
        // Uses the validated basename for Command::new to prevent path bypass.
        let basename = allowlist::validate_command(cmd).map_err(|e| e.to_string())?;

        let mut child = Command::new(&basename)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("failed to spawn '{basename}': {e}"))?;

        let stdin = child
            .stdin
            .take()
            .ok_or("failed to capture subprocess stdin")?;
        let stdout = child
            .stdout
            .take()
            .ok_or("failed to capture subprocess stdout")?;

        let writer = std::io::BufWriter::new(stdin);
        let reader = BufReader::new(stdout);

        Ok(Self {
            inner: Mutex::new(StdioTransportInner {
                child,
                writer,
                reader,
            }),
        })
    }
}

/// Kills the subprocess and waits for it to exit on drop.
///
/// `std::process::Child::drop` does NOT kill the subprocess — it only closes
/// handles. Without this impl, dropped transports leak running subprocesses.
impl Drop for StdioClientTransport {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.inner.lock() {
            let _ = inner.child.kill();
            let _ = inner.child.wait();
        }
    }
}

impl McpTransport for StdioClientTransport {
    fn send_request(&self, request: &JsonRpcRequest) -> Result<JsonRpcResponse, String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| format!("transport lock poisoned: {e}"))?;

        // Serialize and write the request as a single line.
        let json = serde_json::to_string(request)
            .map_err(|e| format!("failed to serialize request: {e}"))?;
        inner
            .writer
            .write_all(json.as_bytes())
            .map_err(|e| format!("failed to write to subprocess stdin: {e}"))?;
        inner
            .writer
            .write_all(b"\n")
            .map_err(|e| format!("failed to write newline: {e}"))?;
        inner
            .writer
            .flush()
            .map_err(|e| format!("failed to flush subprocess stdin: {e}"))?;

        // Read the response as a single line from stdout.
        let mut line = String::new();
        let bytes_read = read_line_bounded(&mut inner.reader, &mut line)
            .map_err(|e| format!("failed to read from subprocess stdout: {e}"))?;
        drop(inner);

        if bytes_read == 0 {
            return Err("subprocess closed stdout (EOF)".to_owned());
        }

        serde_json::from_str(line.trim()).map_err(|e| format!("failed to parse response JSON: {e}"))
    }

    fn send_notification(&self, notification: &JsonRpcNotification) -> Result<(), String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| format!("transport lock poisoned: {e}"))?;

        let json = serde_json::to_string(notification)
            .map_err(|e| format!("failed to serialize notification: {e}"))?;
        inner
            .writer
            .write_all(json.as_bytes())
            .map_err(|e| format!("failed to write notification: {e}"))?;
        inner
            .writer
            .write_all(b"\n")
            .map_err(|e| format!("failed to write newline: {e}"))?;
        inner
            .writer
            .flush()
            .map_err(|e| format!("failed to flush notification: {e}"))?;
        drop(inner);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SSE client transport
// ---------------------------------------------------------------------------

/// MCP client transport that communicates via HTTP SSE.
///
/// Uses a background thread to read the SSE event stream and a synchronous
/// HTTP POST for sending requests. Responses are matched by request ID.
struct SseClientTransport {
    /// The SSE endpoint URL (e.g., `http://localhost:3000/sse`).
    _url: String,
    /// Sender for outgoing requests. The background thread reads responses.
    /// Using a channel-based approach for thread-safe request/response pairing.
    ///
    /// For now, SSE transport uses a synchronous HTTP approach: each
    /// `send_request` call opens a TCP connection, POSTs the request to
    /// the `/message` endpoint, then reads the SSE stream for the
    /// matching response. This is simpler than a persistent SSE
    /// connection but sufficient for the bridge layer.
    post_url: String,
    /// TCP stream for reading SSE events, protected by a mutex.
    sse_reader: Mutex<Option<BufReader<std::net::TcpStream>>>,
}

impl SseClientTransport {
    /// Connects to the SSE endpoint and establishes the transport.
    ///
    /// 1. Opens a TCP connection to the SSE endpoint.
    /// 2. Sends a GET request for the SSE stream.
    /// 3. Reads the initial `endpoint` event to learn the POST URL.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection or handshake fails.
    fn connect(url: &str) -> Result<Self, String> {
        if url.starts_with("https://") {
            return Err(
                "SSE transport does not support TLS; use http:// or add rustls dependency for HTTPS"
                    .to_owned(),
            );
        }

        // Parse the URL to extract host, port, and path.
        let (host, port, path) = parse_http_url(url)?;
        let addr = format!("{host}:{port}");

        // Connect and send GET request for SSE stream.
        let stream = std::net::TcpStream::connect(&addr)
            .map_err(|e| format!("failed to connect to {addr}: {e}"))?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .map_err(|e| format!("failed to set read timeout: {e}"))?;

        let mut writer = std::io::BufWriter::new(
            stream
                .try_clone()
                .map_err(|e| format!("failed to clone stream: {e}"))?,
        );

        // Send HTTP GET for SSE.
        let get_request = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Accept: text/event-stream\r\n\
             Connection: keep-alive\r\n\
             \r\n"
        );
        writer
            .write_all(get_request.as_bytes())
            .map_err(|e| format!("failed to send GET request: {e}"))?;
        writer
            .flush()
            .map_err(|e| format!("failed to flush GET request: {e}"))?;

        let mut reader = BufReader::new(stream);

        // Read the HTTP status line and validate.
        let mut status_line = String::new();
        let n = read_line_bounded(&mut reader, &mut status_line)
            .map_err(|e| format!("failed to read HTTP status line: {e}"))?;
        if n == 0 {
            return Err("connection closed before HTTP status line".to_owned());
        }
        // Parse "HTTP/1.1 200 OK" — extract the status code.
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        if !(200..300).contains(&status_code) {
            return Err(format!(
                "SSE endpoint returned HTTP {status_code}: {}",
                status_line.trim()
            ));
        }

        // Read remaining HTTP response headers.
        let mut header_line = String::new();
        loop {
            header_line.clear();
            let n = read_line_bounded(&mut reader, &mut header_line)
                .map_err(|e| format!("failed to read SSE headers: {e}"))?;
            if n == 0 {
                return Err("connection closed while reading SSE headers".to_owned());
            }
            if header_line.trim().is_empty() {
                break; // End of headers.
            }
        }

        // Read the initial `endpoint` SSE event to learn the POST URL.
        let post_path;
        loop {
            let mut event_line = String::new();
            let n = read_line_bounded(&mut reader, &mut event_line)
                .map_err(|e| format!("failed to read SSE event: {e}"))?;
            if n == 0 {
                return Err("connection closed while waiting for endpoint event".to_owned());
            }
            let trimmed = event_line.trim();
            if trimmed.starts_with("data:") {
                post_path = trimmed
                    .strip_prefix("data:")
                    .unwrap_or("")
                    .trim()
                    .to_owned();
                break;
            }
        }

        if post_path.is_empty() {
            return Err("SSE endpoint event did not contain a POST path".to_owned());
        }

        if post_path.bytes().any(|b| b < 0x20) {
            return Err("SSE endpoint path contains invalid control characters".to_owned());
        }

        // Build the full POST URL. Always http — HTTPS is rejected at entry.
        let post_url = format!("http://{host}:{port}{post_path}");

        Ok(Self {
            _url: url.to_owned(),
            post_url,
            sse_reader: Mutex::new(Some(reader)),
        })
    }
}

/// Maximum number of SSE events to scan for a matching JSON-RPC response.
/// If exceeded, the request fails. The TCP read timeout (30s) handles
/// individual read stalls; this bounds total non-matching events tolerated.
const MAX_SSE_EVENTS: usize = 1000;

impl McpTransport for SseClientTransport {
    #[allow(clippy::significant_drop_tightening)] // sse_reader MutexGuard is borrowed by reader across the entire loop.
    fn send_request(&self, request: &JsonRpcRequest) -> Result<JsonRpcResponse, String> {
        // Parse the POST URL.
        let (host, port, path) = parse_http_url(&self.post_url)?;
        let addr = format!("{host}:{port}");

        // Serialize the request.
        let body = serde_json::to_string(request)
            .map_err(|e| format!("failed to serialize request: {e}"))?;

        // Open a new TCP connection for the POST request.
        let stream = std::net::TcpStream::connect(&addr)
            .map_err(|e| format!("failed to connect to {addr}: {e}"))?;
        let mut writer = std::io::BufWriter::new(
            stream
                .try_clone()
                .map_err(|e| format!("failed to clone stream: {e}"))?,
        );

        // Send HTTP POST.
        let post_request = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            body.len()
        );
        writer
            .write_all(post_request.as_bytes())
            .map_err(|e| format!("failed to send POST request: {e}"))?;
        writer
            .write_all(body.as_bytes())
            .map_err(|e| format!("failed to write POST body: {e}"))?;
        writer
            .flush()
            .map_err(|e| format!("failed to flush POST: {e}"))?;

        // The SSE server returns 202 Accepted. The actual JSON-RPC response
        // comes via the SSE stream. Read it from the SSE reader.
        let mut sse_reader = self
            .sse_reader
            .lock()
            .map_err(|e| format!("SSE reader lock poisoned: {e}"))?;

        let reader = sse_reader.as_mut().ok_or("SSE connection is closed")?;

        // Read SSE events until we find a `message` event with our response.
        for _ in 0..MAX_SSE_EVENTS {
            let mut line = String::new();
            let n = read_line_bounded(reader, &mut line)
                .map_err(|e| format!("failed to read SSE event: {e}"))?;
            if n == 0 {
                return Err("SSE connection closed while waiting for response".to_owned());
            }
            let trimmed = line.trim();
            if trimmed.starts_with("data:") {
                let data = trimmed.strip_prefix("data:").unwrap_or("").trim();
                // Try to parse as a JSON-RPC response.
                if let Ok(response) = serde_json::from_str::<JsonRpcResponse>(data) {
                    return Ok(response);
                }
            }
        }
        Err(format!(
            "no matching JSON-RPC response after {MAX_SSE_EVENTS} SSE events"
        ))
    }

    fn send_notification(&self, notification: &JsonRpcNotification) -> Result<(), String> {
        // Parse the POST URL.
        let (host, port, path) = parse_http_url(&self.post_url)?;
        let addr = format!("{host}:{port}");

        let body = serde_json::to_string(notification)
            .map_err(|e| format!("failed to serialize notification: {e}"))?;

        let stream = std::net::TcpStream::connect(&addr)
            .map_err(|e| format!("failed to connect to {addr}: {e}"))?;
        let mut writer = std::io::BufWriter::new(stream);

        let post_request = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            body.len()
        );
        writer
            .write_all(post_request.as_bytes())
            .map_err(|e| format!("failed to send notification: {e}"))?;
        writer
            .write_all(body.as_bytes())
            .map_err(|e| format!("failed to write notification body: {e}"))?;
        writer
            .flush()
            .map_err(|e| format!("failed to flush notification: {e}"))?;

        Ok(())
    }
}

/// Parses an HTTP URL into (host, port, path).
fn parse_http_url(url: &str) -> Result<(String, u16, String), String> {
    let (scheme, rest) = if let Some(s) = url.strip_prefix("https://") {
        ("https", s)
    } else if let Some(s) = url.strip_prefix("http://") {
        ("http", s)
    } else {
        return Err(format!("unsupported URL scheme in '{url}'"));
    };

    // Reject control characters (CRLF injection defense).
    if rest.bytes().any(|b| b < 0x20) {
        return Err("URL contains invalid control characters".to_owned());
    }

    let default_port: u16 = if scheme == "https" { 443 } else { 80 };

    let (host_port, path) = rest
        .find('/')
        .map_or((rest, "/"), |i| (&rest[..i], &rest[i..]));

    let (host, port) = if let Some(colon_idx) = host_port.rfind(':') {
        let h = &host_port[..colon_idx];
        let p_str = &host_port[colon_idx + 1..];
        let p = p_str
            .parse::<u16>()
            .map_err(|e| format!("invalid port '{p_str}': {e}"))?;
        (h.to_owned(), p)
    } else {
        (host_port.to_owned(), default_port)
    };

    Ok((host, port, path.to_owned()))
}

// ---------------------------------------------------------------------------
// Client transport enum (for type-safe storage without trait objects)
// ---------------------------------------------------------------------------

/// Enum-based transport to avoid orphan rule issues with `Box<dyn McpTransport>`.
///
/// Since both [`StdioClientTransport`] and [`SseClientTransport`] are defined
/// in this module, and [`McpTransport`] is from `scp-mcp`, we cannot implement
/// `McpTransport` for `Box<dyn McpTransport>` due to orphan rules. This enum
/// dispatch avoids that problem.
enum ClientTransport {
    /// Stdio transport: subprocess with piped stdin/stdout.
    Stdio(StdioClientTransport),
    /// SSE transport: HTTP with Server-Sent Events.
    Sse(SseClientTransport),
}

impl McpTransport for ClientTransport {
    fn send_request(&self, request: &JsonRpcRequest) -> Result<JsonRpcResponse, String> {
        match self {
            Self::Stdio(t) => t.send_request(request),
            // Each variant dispatches to its own McpTransport impl with distinct
            // I/O behavior (subprocess stdio vs. HTTP SSE). Arms look identical
            // syntactically but resolve to different concrete implementations.
            #[allow(clippy::match_same_arms)]
            Self::Sse(t) => t.send_request(request),
        }
    }

    fn send_notification(&self, notification: &JsonRpcNotification) -> Result<(), String> {
        match self {
            Self::Stdio(t) => t.send_notification(notification),
            #[allow(clippy::match_same_arms)]
            Self::Sse(t) => t.send_notification(notification),
        }
    }
}

// ---------------------------------------------------------------------------
// FFI bridge context provider
// ---------------------------------------------------------------------------

/// Default tool handler execution timeout in milliseconds (30 seconds).
///
/// Matches [`scp_core::context::tools::DEFAULT_TIMEOUT_MS`]. If a registered
/// handler does not return within this duration, the invocation is aborted
/// with a timeout error. Configurable per-provider via
/// [`FfiBridgeProvider::tool_timeout_ms`].
const FFI_TOOL_TIMEOUT_MS: u64 = scp_core::context::tools::DEFAULT_TIMEOUT_MS as u64;

/// Implements [`ContextProvider`] by reading from the scp-ffi runtime registry.
///
/// Bridges the MCP server's context/tool queries to the live runtime state
/// managed by `crates/scp-ffi/src/runtime.rs`.
struct FfiBridgeProvider {
    /// The agent's DID.
    agent_did: String,
    /// The context IDs this provider serves.
    context_ids: Vec<String>,
    /// Maximum time (in milliseconds) to wait for a tool handler to complete.
    ///
    /// Defaults to [`FFI_TOOL_TIMEOUT_MS`] (30 seconds). If a registered
    /// handler blocks longer than this, the invocation returns an error
    /// instead of blocking indefinitely. See issue #123.
    tool_timeout_ms: u64,
}

impl ContextProvider for FfiBridgeProvider {
    fn active_context_ids(&self) -> Vec<String> {
        self.context_ids.clone()
    }

    fn agent_role(&self, context_id: &str) -> Option<String> {
        // Look up the agent's role assignment in the context's role state.
        crate::runtime::with_context(context_id, |rt| {
            let role = rt
                .role_state
                .assignments
                .get(&self.agent_did)
                .map(|assignment| assignment.role_name.clone());
            Ok(role)
        })
        .ok()
        .flatten()
    }

    fn agent_did(&self) -> &str {
        &self.agent_did
    }

    fn context_tools(&self, context_id: &str) -> Vec<ContextToolInfo> {
        crate::runtime::with_context(context_id, |rt| {
            let tools = rt
                .tool_registry
                .registrations()
                .map(|t| ContextToolInfo {
                    name: t.name.clone(),
                    description: Some(t.description.clone()),
                    input_schema: t.schema.input_schema.clone(),
                    output_schema: Some(t.schema.output_schema.clone()),
                    admin_only: false,
                })
                .collect();
            Ok(tools)
        })
        .unwrap_or_default()
    }

    fn validate_capability(&self, context_id: &str, tool_name: &str) -> Result<(), String> {
        // Defense-in-depth: check role-state capabilities in addition to the
        // UCAN layer. See §7.2 and ADR-010 for the dual-check design.
        crate::runtime::with_context(context_id, |rt| {
            if scp_core::context::tools::invoke::has_tool_invoke_capability(
                &rt.role_state,
                &self.agent_did,
                tool_name,
            ) {
                Ok(())
            } else {
                // Generic message for the wire — detailed info stays server-side.
                // The Err string propagates into a JSON-RPC error response via
                // McpServer::handle_tool_call (server.rs:430-435).
                tracing::warn!(
                    agent = %self.agent_did,
                    tool = %tool_name,
                    context = %context_id,
                    "capability check failed: agent lacks ToolInvoke capability"
                );
                Err(ScpPyError::ContextError(
                    "insufficient permissions to invoke tool".to_owned(),
                ))
            }
        })
        .map_err(|e| format!("{e}"))
    }

    fn invoke_tool(
        &self,
        context_id: &str,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        // Validates tool existence and input schema, then dispatches to a
        // registered handler if one exists. If no handler is registered, falls
        // back to echoing the validated input with metadata (schema-only mode).
        //
        // The handler dispatch is sync because ContextProvider::invoke_tool is
        // sync and Python handlers are GIL-bound (inherently sync). The async
        // invoke_tool in scp-core is for contexts where Rust itself executes
        // tools. See SCP-212, ADR-010, ADR-015.
        //
        // IMPORTANT: The handler Arc and output schema are extracted inside the
        // DashMap shard lock (via with_context), then the lock is released
        // BEFORE calling the handler. This prevents holding the shard lock
        // during Python GIL acquisition, which would block concurrent
        // same-context operations for the duration of the handler. See #122.
        //
        // Handler execution is bounded by `tool_timeout_ms` to prevent a
        // misbehaving handler from blocking the tokio runtime indefinitely.
        // Uses std::thread::spawn + mpsc::recv_timeout (sync timeout) because
        // ContextProvider::invoke_tool is a sync trait method. See issue #123.
        let timeout = std::time::Duration::from_millis(self.tool_timeout_ms);

        // Phase 1: Validate input and extract handler + output schema under
        // the DashMap shard lock. The lock is released when with_context
        // returns.
        let dispatch = crate::runtime::with_context(context_id, |rt| {
            let registration = rt.tool_registry.get(tool_name).ok_or_else(|| {
                ScpPyError::ContextError(format!(
                    "tool '{tool_name}' not found in context '{context_id}'"
                ))
            })?;

            // Validate input against the tool's input schema.
            scp_core::context::tools::schema::validate_value_against_schema(
                &arguments,
                &registration.schema.input_schema,
            )
            .map_err(|msg| {
                ScpPyError::ValidationError(format!(
                    "input validation failed for tool '{tool_name}': {msg}"
                ))
            })?;

            // Clone handler Arc and output schema so we can release the lock.
            Ok(rt
                .tool_handlers
                .get(tool_name)
                .map(|handler| (handler.clone(), registration.schema.output_schema.clone())))
        })
        .map_err(|e| format!("{e}"))?;

        // Phase 2: Execute handler OUTSIDE the DashMap shard lock so that
        // concurrent same-context operations are not blocked during Python
        // GIL acquisition and handler execution. Handler execution is
        // bounded by `tool_timeout_ms` (issue #123).
        match dispatch {
            Some((handler, output_schema)) => {
                // Run the handler on a dedicated thread with a timeout to
                // prevent indefinite blocking. The handler is Send + Sync
                // (Arc<dyn Fn>), so it is safe to move across threads.
                let (tx, rx) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    let result = handler(arguments);
                    // If the receiver has been dropped (timeout elapsed), the
                    // send will fail silently -- that is intentional.
                    let _ = tx.send(result);
                });

                let handler_result = rx.recv_timeout(timeout).map_err(|_| {
                    format!(
                        "tool handler for '{tool_name}' timed out after {}ms",
                        timeout.as_millis()
                    )
                })?;

                let output = handler_result
                    .map_err(|e| format!("tool handler for '{tool_name}' failed: {e}"))?;

                // Validate output against the tool's output schema (defense-in-depth).
                scp_core::context::tools::schema::validate_value_against_schema(
                    &output,
                    &output_schema,
                )
                .map_err(|msg| format!("output validation failed for tool '{tool_name}': {msg}"))?;

                Ok(output)
            }
            None => {
                // No handler registered -- fall back to echo mode.
                Ok(serde_json::json!({
                    "tool": tool_name,
                    "context": context_id,
                    "status": "validated",
                    "input_valid": true,
                    "validated_input": arguments,
                }))
            }
        }
    }

    fn context_members(&self, context_id: &str) -> Vec<MemberInfo> {
        crate::runtime::with_context(context_id, |rt| {
            let members = rt
                .role_state
                .members
                .iter()
                .map(|did| {
                    let role = rt
                        .role_state
                        .assignments
                        .get(did)
                        .map_or_else(|| "member".to_owned(), |a| a.role_name.clone());
                    MemberInfo {
                        did: did.clone(),
                        role,
                    }
                })
                .collect();
            Ok(members)
        })
        .unwrap_or_default()
    }

    fn context_events(&self, context_id: &str) -> serde_json::Value {
        // The EventLog stores Merkle tree hashes, not event payloads.
        // Return the event count and Merkle root as metadata.
        crate::runtime::with_context(context_id, |rt| {
            let leaf_count = rt.event_log.leaves().len();
            let root = scp_core::event_log::tree::root(&rt.event_log);
            Ok(serde_json::json!({
                "event_count": leaf_count,
                "merkle_root": crate::types::encode_hex(&root),
            }))
        })
        .unwrap_or_else(|_| serde_json::json!({ "event_count": 0 }))
    }

    fn subscribe_resource(&self, _uri: &str) -> Result<(), String> {
        // Resource subscriptions are not yet wired to the transport layer.
        // Accept the subscription silently.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MCP handle registries
// ---------------------------------------------------------------------------

/// State for an active MCP server instance.
struct McpServerState {
    /// The identity DID running this server.
    identity_did: String,
    /// The context IDs being served.
    context_ids: Vec<String>,
    /// The transport mode (stdio or sse).
    transport: String,
    /// Whether the server has been stopped.
    stopped: bool,
    /// The real MCP server, wrapped in Arc<Mutex> for thread-safe access
    /// from the transport task and bridge functions. Never read directly —
    /// kept alive as an ownership anchor (the transport task closure holds
    /// a clone of this Arc).
    #[allow(dead_code)] // Ownership anchor — dropping this Arc would stop the server.
    server: Arc<Mutex<McpServer<FfiBridgeProvider>>>,
    /// Shutdown signal sender. Dropping this signals the transport task to stop.
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// Handle to the tokio task running the transport. Used by `server_wait`.
    task_handle: Option<tokio::task::JoinHandle<()>>,
}

/// State for an active MCP client connection.
struct McpClientState {
    /// The transport mode (stdio or sse).
    transport: String,
    /// For stdio, the command used to spawn the subprocess.
    command: Option<Vec<String>>,
    /// For sse, the URL of the SSE endpoint.
    url: Option<String>,
    /// The real MCP client, connected and initialized.
    client: Arc<Mutex<McpClient<ClientTransport, SystemTimestamp>>>,
}

/// Global registry of MCP server instances.
static SERVER_REGISTRY: OnceLock<DashMap<String, McpServerState>> = OnceLock::new();

/// Global registry of MCP client instances.
static CLIENT_REGISTRY: OnceLock<DashMap<String, McpClientState>> = OnceLock::new();

fn server_registry() -> &'static DashMap<String, McpServerState> {
    SERVER_REGISTRY.get_or_init(DashMap::new)
}

fn client_registry() -> &'static DashMap<String, McpClientState> {
    CLIENT_REGISTRY.get_or_init(DashMap::new)
}

/// Generates a unique, unpredictable handle ID.
///
/// Delegates to [`crate::types::generate_random_id`] for the shared CSPRNG
/// pattern. MCP handles use prefixed IDs (e.g., `mcp-server-{hex}`) since
/// they are internal-only and never appear in `scp://` URIs.
fn generate_handle_id(prefix: &str) -> String {
    crate::types::generate_random_id(prefix)
}

// ---------------------------------------------------------------------------
// MCP server bridge functions
// ---------------------------------------------------------------------------

/// Starts an MCP server that exposes SCP context tools.
///
/// Creates an MCP server backed by a [`FfiBridgeProvider`] that reads tools
/// and context state from the scp-ffi runtime registry. For `"stdio"`
/// transport, the server processes JSON-RPC messages via a tokio task. For
/// `"sse"` transport, the server binds an HTTP server on a random port.
///
/// # Arguments
///
/// * `identity_did` -- The DID of the identity running the server.
/// * `context_ids` -- List of context IDs to expose.
/// * `transport` -- Transport mode: `"stdio"` or `"sse"`.
///
/// # Returns
///
/// An opaque server handle string for use with `py_mcp_server_stop` and
/// `py_mcp_server_wait`.
///
/// # Errors
///
/// Raises `TransportError` if the server fails to start.
///
/// See ADR-015: MCP server with context namespace mapping.
#[pyfunction]
#[pyo3(name = "py_mcp_serve")]
#[allow(clippy::needless_pass_by_value)] // PyO3 requires owned Vec for #[pyfunction] arguments.
#[allow(clippy::too_many_lines)] // MCP server startup with stdio/SSE transport dispatch is inherently verbose.
pub fn py_mcp_serve(
    identity_did: &str,
    context_ids: Vec<String>,
    transport: &str,
) -> PyResult<String> {
    validate::validate_did(identity_did)?;
    validate::validate_transport_mode(transport)?;
    for ctx_id in &context_ids {
        validate::validate_context_id(ctx_id)?;
    }

    // Validate that all context IDs are registered in the runtime.
    for ctx_id in &context_ids {
        crate::runtime::with_context(ctx_id, |_rt| Ok(())).map_err(|e| {
            ScpPyError::TransportError(format!("cannot serve context '{ctx_id}': {e}"))
        })?;
    }

    // Create the FfiBridgeProvider and McpServer.
    let provider = FfiBridgeProvider {
        agent_did: identity_did.to_owned(),
        context_ids: context_ids.clone(),
        tool_timeout_ms: FFI_TOOL_TIMEOUT_MS,
    };
    let server = McpServer::new(provider);
    let server = Arc::new(Mutex::new(server));

    // Create a shutdown channel.
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Start the transport task on the tokio runtime.
    let rt = crate::runtime()?;
    let server_clone = Arc::clone(&server);
    let transport_mode = transport.to_owned();
    let sse_agent_did = identity_did.to_owned();
    let sse_context_ids = context_ids.clone();

    let task_handle = rt.spawn(async move {
        match transport_mode.as_str() {
            "stdio" => {
                // Run the MCP server over stdio. The `run_stdio` function
                // processes stdin/stdout until EOF. We also listen for the
                // shutdown signal.
                tokio::select! {
                    _ = shutdown_rx => {
                        // Shutdown signal received -- exit cleanly.
                    }
                    () = async {
                        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

                        // The real `run_stdio` takes &mut McpServer by value.
                        // We need to run it with our Arc<Mutex> server.
                        // Since `run_stdio` processes stdin line by line, we
                        // replicate its logic here using the shared server.
                        let stdin = tokio::io::stdin();
                        let mut stdout = tokio::io::stdout();
                        let mut reader = tokio::io::BufReader::new(stdin);
                        let mut line = String::new();

                        loop {
                            line.clear();
                            match reader.read_line(&mut line).await {
                                Ok(0) | Err(_) => break, // EOF or read error
                                Ok(_) => {}
                            }
                            // Bound check after read — server-side stdin comes
                            // from the local parent process, not a remote peer,
                            // so the risk is lower. This guards against oversized
                            // payloads from a misbehaving MCP client.
                            if line.len() as u64 > MAX_LINE_BYTES {
                                break;
                            }

                            let trimmed = line.trim();
                            if trimmed.is_empty() {
                                continue;
                            }

                            // Parse and dispatch the request.
                            let response = {
                                let request: Result<scp_mcp::protocol::JsonRpcRequest, _> =
                                    serde_json::from_str(trimmed);
                                match request {
                                    Ok(req) => {
                                        server_clone
                                            .lock()
                                            .map_or(None, |mut srv| srv.handle_request(&req))
                                    }
                                    Err(e) => {
                                        Some(scp_mcp::protocol::JsonRpcResponse::error(
                                            scp_mcp::protocol::RequestId::Number(0),
                                            scp_mcp::protocol::JsonRpcError {
                                                code: scp_mcp::protocol::PARSE_ERROR,
                                                message: format!("failed to parse: {e}"),
                                                data: None,
                                            },
                                        ))
                                    }
                                }
                            };

                            if let Some(resp) = response
                                && let Ok(json) = serde_json::to_string(&resp) {
                                    let _ = stdout.write_all(json.as_bytes()).await;
                                    let _ = stdout.write_all(b"\n").await;
                                    let _ = stdout.flush().await;
                                }
                        }
                    } => {}
                }
            }
            "sse" => {
                // For SSE, run_sse takes ownership of the McpServer and
                // binds to a configurable address. We create a dedicated
                // server instance using the captured identity and context
                // IDs (avoids re-extracting from the mutex which would
                // create a stale-data race window).
                let provider = FfiBridgeProvider {
                    agent_did: sse_agent_did,
                    context_ids: sse_context_ids,
                    tool_timeout_ms: FFI_TOOL_TIMEOUT_MS,
                };
                let sse_server = McpServer::new(provider);
                let config =
                    scp_mcp::sse::SseConfig::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));

                // Create a ShutdownHandle for the SSE server. Wire the
                // oneshot shutdown_rx so that when py_mcp_server_stop sends
                // the signal, the SSE server also receives it via the
                // ShutdownHandle's CancellationToken.
                let sse_shutdown = scp_mcp::sse::ShutdownHandle::new();
                let sse_shutdown_trigger = sse_shutdown.clone();
                tokio::spawn(async move {
                    let _ = shutdown_rx.await;
                    sse_shutdown_trigger.shutdown();
                });

                let result = scp_mcp::sse::run_sse(sse_server, config, sse_shutdown).await;
                if let Err(e) = result {
                    tracing::error!("MCP SSE server error: {e}");
                }
            }
            _ => {} // Already validated above.
        }
    });

    // Create the server state and register it.
    let handle = generate_handle_id("mcp-server");
    let state = McpServerState {
        identity_did: identity_did.to_owned(),
        context_ids,
        transport: transport.to_owned(),
        stopped: false,
        server,
        shutdown_tx: Some(shutdown_tx),
        task_handle: Some(task_handle),
    };

    server_registry().insert(handle.clone(), state);

    Ok(handle)
}

/// Stops a running MCP server.
///
/// Sends a shutdown signal to the transport task and marks the server as
/// stopped. The transport task will exit after processing any in-flight
/// requests.
///
/// # Arguments
///
/// * `handle` -- The server handle returned by `py_mcp_serve`.
///
/// # Errors
///
/// Raises `TransportError` if the server is not found or already stopped.
#[pyfunction]
#[pyo3(name = "py_mcp_server_stop")]
pub fn py_mcp_server_stop(handle: &str) -> PyResult<()> {
    validate::validate_mcp_handle(handle)?;
    let mut entry = server_registry().get_mut(handle).ok_or_else(|| {
        ScpPyError::TransportError(format!("MCP server handle '{handle}' not found"))
    })?;

    if entry.stopped {
        return Err(ScpPyError::TransportError(format!(
            "MCP server '{handle}' is already stopped"
        ))
        .into());
    }

    entry.stopped = true;

    // Send the shutdown signal. Dropping the sender signals the receiver.
    if let Some(tx) = entry.shutdown_tx.take() {
        let _ = tx.send(());
    }
    drop(entry);

    Ok(())
}

/// Blocks until the MCP server exits.
///
/// For stdio transport, waits until stdin is closed (EOF) or the server is
/// stopped via [`py_mcp_server_stop`]. For SSE transport, waits until the
/// HTTP server is terminated.
///
/// # Arguments
///
/// * `handle` -- The server handle returned by `py_mcp_serve`.
///
/// # Errors
///
/// Raises `TransportError` if the server handle is not found.
#[pyfunction]
#[pyo3(name = "py_mcp_server_wait")]
pub fn py_mcp_server_wait(py: Python<'_>, handle: &str) -> PyResult<()> {
    validate::validate_mcp_handle(handle)?;
    // Extract the task handle if available.
    let task_handle = {
        let mut entry = server_registry().get_mut(handle).ok_or_else(|| {
            ScpPyError::TransportError(format!("MCP server handle '{handle}' not found"))
        })?;

        if entry.stopped && entry.task_handle.is_none() {
            return Ok(());
        }

        entry.task_handle.take()
    };

    // Block on the task handle if we have one.
    if let Some(task) = task_handle {
        let rt = crate::runtime()?;
        py.allow_threads(|| {
            rt.block_on(async {
                let _ = task.await;
            });
        });
    }

    Ok(())
}

/// Returns metadata about a running MCP server.
///
/// # Arguments
///
/// * `handle` -- The server handle returned by `py_mcp_serve`.
///
/// # Returns
///
/// A dict with keys: `identity_did`, `context_ids`, `transport`, `stopped`.
///
/// # Errors
///
/// Raises `TransportError` if the server handle is not found.
#[pyfunction]
#[pyo3(name = "py_mcp_server_info")]
pub fn py_mcp_server_info(py: Python<'_>, handle: &str) -> PyResult<PyObject> {
    validate::validate_mcp_handle(handle)?;
    let entry = server_registry().get(handle).ok_or_else(|| {
        ScpPyError::TransportError(format!("MCP server handle '{handle}' not found"))
    })?;

    let dict = PyDict::new(py);
    dict.set_item("identity_did", &entry.identity_did)?;
    dict.set_item("context_ids", &entry.context_ids)?;
    dict.set_item("transport", &entry.transport)?;
    dict.set_item("stopped", entry.stopped)?;
    drop(entry);
    Ok(dict.into())
}

/// Returns metadata about an active MCP client connection.
///
/// # Arguments
///
/// * `handle` -- The client handle returned by `py_mcp_client_connect_*`.
///
/// # Returns
///
/// A dict with keys: `transport`, `command` (nullable), `url` (nullable).
///
/// # Errors
///
/// Raises `TransportError` if the client handle is not found.
#[pyfunction]
#[pyo3(name = "py_mcp_client_info")]
pub fn py_mcp_client_info(py: Python<'_>, handle: &str) -> PyResult<PyObject> {
    validate::validate_mcp_handle(handle)?;
    let entry = client_registry().get(handle).ok_or_else(|| {
        ScpPyError::TransportError(format!("MCP client handle '{handle}' not found"))
    })?;

    let dict = PyDict::new(py);
    dict.set_item("transport", &entry.transport)?;
    dict.set_item("command", &entry.command)?;
    dict.set_item("url", &entry.url)?;
    drop(entry);
    Ok(dict.into())
}

// ---------------------------------------------------------------------------
// MCP client bridge functions
// ---------------------------------------------------------------------------

/// Connects to an external MCP server via stdio transport.
///
/// Spawns the given command as a subprocess and communicates via
/// line-delimited JSON over stdin/stdout. Performs the MCP initialize
/// handshake before returning.
///
/// # Arguments
///
/// * `command` -- The command and arguments to spawn (e.g.,
///   `["uvx", "some-mcp-server"]`).
///
/// # Returns
///
/// An opaque client handle string.
///
/// # Errors
///
/// Raises `TransportError` if the subprocess fails to start or the
/// MCP initialize handshake fails.
#[pyfunction]
#[pyo3(name = "py_mcp_client_connect_stdio")]
#[allow(clippy::needless_pass_by_value)] // PyO3 requires owned Vec for #[pyfunction] arguments.
pub fn py_mcp_client_connect_stdio(command: Vec<String>) -> PyResult<String> {
    if command.is_empty() {
        return Err(
            ScpPyError::ValidationError("command must be a non-empty list".to_owned()).into(),
        );
    }

    // Spawn the subprocess and create the transport.
    let transport = StdioClientTransport::spawn(&command)
        .map_err(|e| ScpPyError::TransportError(format!("failed to connect stdio client: {e}")))?;

    // Create the MCP client and perform the initialize handshake.
    let mut client = McpClient::new(ClientTransport::Stdio(transport));
    client
        .initialize()
        .map_err(|e| ScpPyError::TransportError(format!("MCP initialize handshake failed: {e}")))?;

    let handle = generate_handle_id("mcp-client");
    let state = McpClientState {
        transport: "stdio".to_owned(),
        command: Some(command),
        url: None,

        client: Arc::new(Mutex::new(client)),
    };

    client_registry().insert(handle.clone(), state);

    Ok(handle)
}

/// Connects to an external MCP server via SSE transport.
///
/// Connects to the given URL using HTTP with Server-Sent Events for
/// server-to-client messages and POST for client-to-server messages.
/// Performs the MCP initialize handshake before returning.
///
/// # Arguments
///
/// * `url` -- The URL of the SSE endpoint.
///
/// # Returns
///
/// An opaque client handle string.
///
/// # Errors
///
/// Raises `TransportError` if the connection or MCP handshake fails.
#[pyfunction]
#[pyo3(name = "py_mcp_client_connect_sse")]
pub fn py_mcp_client_connect_sse(url: &str) -> PyResult<String> {
    validate::validate_relay_url(url)?;

    // Connect to the SSE endpoint.
    let transport = SseClientTransport::connect(url)
        .map_err(|e| ScpPyError::TransportError(format!("failed to connect SSE client: {e}")))?;

    // Create the MCP client and perform the initialize handshake.
    let mut client = McpClient::new(ClientTransport::Sse(transport));
    client
        .initialize()
        .map_err(|e| ScpPyError::TransportError(format!("MCP initialize handshake failed: {e}")))?;

    let handle = generate_handle_id("mcp-client");
    let state = McpClientState {
        transport: "sse".to_owned(),
        command: None,
        url: Some(url.to_owned()),

        client: Arc::new(Mutex::new(client)),
    };

    client_registry().insert(handle.clone(), state);

    Ok(handle)
}

/// Disconnects from an external MCP server.
///
/// Removes the client from the registry and drops the transport connection.
/// For stdio clients, the subprocess is killed via `StdioClientTransport::drop`.
/// For SSE clients, the TCP connection is closed.
///
/// # Arguments
///
/// * `handle` -- The client handle returned by `py_mcp_client_connect_*`.
///
/// # Errors
///
/// Raises `TransportError` if the client handle is not found (e.g. already
/// disconnected or never connected).
#[pyfunction]
#[pyo3(name = "py_mcp_client_disconnect")]
pub fn py_mcp_client_disconnect(handle: &str) -> PyResult<()> {
    validate::validate_mcp_handle(handle)?;
    let (_, state) = client_registry().remove(handle).ok_or_else(|| {
        ScpPyError::TransportError(format!("MCP client handle '{handle}' not found"))
    })?;

    // Dropping `state` drops the Arc<Mutex<McpClient>>, which drops the
    // McpClient, which drops the ClientTransport. For stdio transports,
    // the Drop impl on StdioClientTransport kills and waits on the
    // subprocess, preventing resource leaks.
    drop(state);

    Ok(())
}

/// Lists available tools from an external MCP server.
///
/// Sends a `tools/list` JSON-RPC request to the connected MCP server and
/// returns the tool definitions as a list of Python dicts.
///
/// # Arguments
///
/// * `handle` -- The client handle returned by `py_mcp_client_connect_*`.
///
/// # Returns
///
/// A list of Python dicts, each with `name`, `description`, and
/// `inputSchema` keys.
///
/// # Errors
///
/// Raises `TransportError` if the client is not connected or the request
/// fails.
#[pyfunction]
#[pyo3(name = "py_mcp_client_list_tools")]
pub fn py_mcp_client_list_tools(py: Python<'_>, handle: &str) -> PyResult<PyObject> {
    validate::validate_mcp_handle(handle)?;
    let entry = client_registry().get(handle).ok_or_else(|| {
        ScpPyError::TransportError(format!("MCP client handle '{handle}' not found"))
    })?;

    // Send the real tools/list request via the MCP client.
    let client = Arc::clone(&entry.client);
    drop(entry); // Release the DashMap guard before blocking.

    let tools = {
        let client_guard = client
            .lock()
            .map_err(|e| ScpPyError::TransportError(format!("client lock poisoned: {e}")))?;
        client_guard
            .list_tools()
            .map_err(|e| ScpPyError::TransportError(format!("tools/list failed: {e}")))?
    };

    // Convert tool definitions to JSON array for Python.
    let tools_json: Vec<serde_json::Value> = tools
        .iter()
        .map(|t| {
            serde_json::json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
            })
        })
        .collect();

    json_to_py_dict(py, &serde_json::Value::Array(tools_json))
}

/// Invokes an external MCP tool with SCP provenance wrapping.
///
/// Sends a `tools/call` JSON-RPC request to the external MCP server and
/// wraps the result with provenance metadata recording the source tool,
/// invoking agent, context, and timestamp.
///
/// # Arguments
///
/// * `handle` -- The client handle returned by `py_mcp_client_connect_*`.
/// * `tool_name` -- The name of the external tool to invoke.
/// * `input` -- A Python dict of input parameters.
/// * `context_id` -- The SCP context ID for provenance tracking.
/// * `identity_did` -- The DID of the invoking identity.
///
/// # Returns
///
/// A Python dict with `content`, `is_error`, and `provenance` keys.
///
/// # Errors
///
/// Raises `TransportError` if the client is not connected or the
/// invocation fails.
#[pyfunction]
#[pyo3(name = "py_mcp_client_invoke")]
pub fn py_mcp_client_invoke(
    py: Python<'_>,
    handle: &str,
    tool_name: &str,
    input: &Bound<'_, PyDict>,
    context_id: &str,
    identity_did: &str,
) -> PyResult<PyObject> {
    validate::validate_mcp_handle(handle)?;
    validate::validate_tool_name(tool_name)?;
    validate::validate_context_id(context_id)?;
    validate::validate_did(identity_did)?;
    let entry = client_registry().get(handle).ok_or_else(|| {
        ScpPyError::TransportError(format!("MCP client handle '{handle}' not found"))
    })?;

    let client = Arc::clone(&entry.client);
    drop(entry); // Release the DashMap guard before Python object access.

    // Convert input to JSON.
    let input_json = py_dict_to_json(input)?;

    // Send the real tools/call request via the MCP client.
    let result = {
        let client_guard = client
            .lock()
            .map_err(|e| ScpPyError::TransportError(format!("client lock poisoned: {e}")))?;
        client_guard
            .invoke(tool_name, input_json, context_id, identity_did)
            .map_err(|e| ScpPyError::TransportError(format!("tools/call failed: {e}")))?
    };

    // Convert the McpToolResult to a Python dict.
    let content_json: Vec<serde_json::Value> = result
        .content
        .iter()
        .map(|c| serde_json::to_value(c).unwrap_or(serde_json::Value::Null))
        .collect();

    let result_json = serde_json::json!({
        "content": content_json,
        "is_error": result.is_error,
        "provenance": {
            "source": result.provenance.source,
            "invoked_by": result.provenance.invoked_by,
            "context": result.provenance.context,
            "timestamp": result.provenance.timestamp,
        },
    });

    json_to_py_dict(py, &result_json)
}

/// Loads active contexts for a DID, combining local registry and relay discovery.
///
/// Context discovery is **client-side** because the SCP relay is a dumb blob
/// store with no identity-to-context mapping. This function:
///
/// 1. Collects contexts from the local runtime registry (always available).
/// 2. Collects contexts from the known-contexts registry (SCP-213).
/// 3. If a relay connection is active, probes known routing IDs via QUERY
///    to determine which contexts have recent activity on the relay.
/// 4. Falls back gracefully to local-only when the relay is unreachable.
///
/// Results are deduplicated by context ID. Each result dict contains:
/// - `context_id` -- The context identifier.
/// - `source` -- `"local"`, `"relay"`, or `"local+relay"`.
/// - `creator_did` -- The context creator's DID (if available from runtime).
/// - `member_count` -- Number of members (if available from runtime).
/// - `tool_count` -- Number of registered tools (if available from runtime).
/// - `relay_active` -- `True` if the relay returned blobs for this context.
///
/// # Arguments
///
/// * `identity_did` -- The DID to look up contexts for.
/// * `relay_url` -- The relay URL to query (used as a hint; the active
///   transport connection is preferred if available).
///
/// # Returns
///
/// A list of context dicts. Returns an empty list if no contexts are found.
///
/// # Errors
///
/// Raises `TransportError` if the relay query fails fatally (transient
/// failures are handled by falling back to local-only).
///
/// See SCP-213, ADR-015 in `.docs/adrs/phase-3.md`.
#[pyfunction]
#[pyo3(name = "py_mcp_load_contexts")]
pub fn py_mcp_load_contexts(
    py: Python<'_>,
    identity_did: &str,
    _relay_url: &str,
) -> PyResult<Vec<PyObject>> {
    validate::validate_did(identity_did)?;
    // Step 1: Collect contexts from the local runtime registry.
    let local_context_ids = crate::runtime::context_ids_for_member(identity_did);

    // Step 2: Collect contexts from the known-contexts registry.
    let known = crate::runtime::known_contexts_for_member(identity_did);

    // Step 3: Probe relay for known routing IDs (if connected).
    let relay_active_set = probe_relay_for_known_contexts(&known);

    // Step 4: Build deduplicated result set.
    let mut seen = std::collections::HashSet::new();
    let mut results = Vec::new();

    // Add local contexts first.
    for ctx_id in &local_context_ids {
        seen.insert(ctx_id.clone());
        let dict = PyDict::new(py);
        dict.set_item("context_id", ctx_id)?;

        let relay_active = relay_active_set.contains(ctx_id);
        if relay_active {
            dict.set_item("source", "local+relay")?;
        } else {
            dict.set_item("source", "local")?;
        }
        dict.set_item("relay_active", relay_active)?;

        // Enrich with creator DID and member count from runtime state.
        if let Ok(info) = crate::runtime::with_context(ctx_id, |rt| {
            Ok((
                rt.creator_did.clone(),
                rt.role_state.members.len(),
                rt.tool_registry.len(),
            ))
        }) {
            dict.set_item("creator_did", info.0)?;
            dict.set_item("member_count", info.1)?;
            dict.set_item("tool_count", info.2)?;
        }

        results.push(dict.into());
    }

    // Add relay-only contexts (known but not in local registry).
    for (ctx_id, known_ctx) in &known {
        if seen.contains(ctx_id) {
            continue;
        }
        seen.insert(ctx_id.clone());
        let dict = PyDict::new(py);
        dict.set_item("context_id", ctx_id)?;

        let relay_active = relay_active_set.contains(ctx_id);
        dict.set_item("source", "relay")?;
        dict.set_item("relay_active", relay_active)?;
        dict.set_item("relay_url", &known_ctx.relay_url)?;

        results.push(dict.into());
    }

    Ok(results)
}

/// Probes the relay for activity on known context routing IDs.
///
/// For each known context, sends a QUERY with `limit=1` to check if any
/// blobs exist for that routing ID. Returns the set of context IDs that
/// have activity on the relay.
///
/// Falls back to an empty set if no relay connection is available or if
/// queries fail (graceful degradation).
fn probe_relay_for_known_contexts(
    known: &[(String, crate::runtime::KnownContext)],
) -> std::collections::HashSet<String> {
    use scp_transport::TransportAdapter;
    use scp_transport::traits::RoutingId;

    let mut active = std::collections::HashSet::new();

    if known.is_empty() {
        return active;
    }

    // Get the relay adapter. If none is connected, return empty set.
    let Ok(Some(adapter)) = crate::runtime::get_relay_connection() else {
        return active;
    };

    // Get the tokio runtime for blocking on async queries.
    let Ok(rt) = crate::runtime() else {
        return active;
    };

    // Probe each known context's routing ID on the relay.
    for (ctx_id, known_ctx) in known {
        let routing_id = RoutingId::new(known_ctx.routing_id);
        let query_result = rt.block_on(async {
            // Use query() from the TransportAdapter trait with limit-like
            // behavior: we only need to know if any blobs exist. The QUERY
            // message returns all matching blobs up to the default limit, but
            // we only check if the result is non-empty.
            adapter.query(&routing_id, None).await
        });

        match query_result {
            Ok(envelopes) if !envelopes.is_empty() => {
                active.insert(ctx_id.clone());
            }
            // Empty result (no activity) or query failure (relay error,
            // timeout, etc.) — skip gracefully; other contexts may succeed.
            _ => {}
        }
    }

    active
}

// ---------------------------------------------------------------------------
// Stdio allowlist error mapping
// ---------------------------------------------------------------------------

/// Maps [`AllowlistError`] to the appropriate [`ScpPyError`] variant.
///
/// Input-validation errors map to `ValidationError`. Runtime/policy errors
/// map to `TransportError`. Exhaustive match ensures new variants produce
/// a compile error instead of silently falling through.
#[allow(clippy::needless_pass_by_value)] // match on e consumes variants carrying String data.
fn allowlist_err(e: allowlist::AllowlistError) -> ScpPyError {
    use scp_mcp::allowlist::AllowlistError;
    let msg = e.to_string();
    match e {
        AllowlistError::EmptyEntry
        | AllowlistError::PathInEntry(_)
        | AllowlistError::NulInEntry(_)
        | AllowlistError::ControlCharInEntry(_)
        | AllowlistError::PathInCommand(_)
        | AllowlistError::InvalidCommand(_) => ScpPyError::ValidationError(msg),
        AllowlistError::NotAllowed { .. } | AllowlistError::LockPoisoned => {
            ScpPyError::TransportError(msg)
        }
    }
}

// ---------------------------------------------------------------------------
// Stdio allowlist configuration (PyO3)
// ---------------------------------------------------------------------------

/// Configures the MCP stdio subprocess allowlist.
///
/// By default, only well-known MCP server launchers are permitted (e.g.
/// `uvx`, `npx`, `node`, `python3`). Use this function to extend the list.
///
/// # Arguments
///
/// * `additional_binaries` -- Binary basenames to add to the default allowlist.
///
/// # Errors
///
/// Raises `ValidationError` if any entry is invalid (path, NUL, empty).
/// Raises `TransportError` if the allowlist lock is poisoned.
#[pyfunction]
#[pyo3(name = "py_mcp_configure_stdio_allowlist", signature = (additional_binaries=vec![]))]
#[allow(clippy::needless_pass_by_value)] // PyO3 requires owned Vec for #[pyfunction] arguments.
pub fn py_mcp_configure_stdio_allowlist(additional_binaries: Vec<String>) -> PyResult<()> {
    allowlist::configure(&additional_binaries).map_err(allowlist_err)?;
    Ok(())
}

/// Disable the stdio allowlist entirely (unrestricted mode).
///
/// # Safety
///
/// This allows **any** binary to be spawned as a subprocess. Only use when
/// the command source is fully trusted.
///
/// # Errors
///
/// Raises `TransportError` if the allowlist lock is poisoned.
#[pyfunction]
#[pyo3(name = "py_mcp_disable_stdio_allowlist")]
pub fn py_mcp_disable_stdio_allowlist() -> PyResult<()> {
    allowlist::disable_enforcement().map_err(allowlist_err)?;
    Ok(())
}

/// Reset the stdio allowlist to its default state.
///
/// Restores the default binaries and re-enables allowlist enforcement
/// (clears unrestricted mode).
///
/// # Errors
///
/// Raises `TransportError` if the allowlist lock is poisoned.
#[pyfunction]
#[pyo3(name = "py_mcp_reset_stdio_allowlist")]
pub fn py_mcp_reset_stdio_allowlist() -> PyResult<()> {
    allowlist::reset().map_err(allowlist_err)?;
    Ok(())
}

/// Return the current stdio allowlist state.
///
/// Returns a Python dict with keys:
/// - `"allowed"`: sorted list of allowed binary names
/// - `"unrestricted"`: bool indicating whether the allowlist is bypassed
///
/// # Errors
///
/// Raises `TransportError` if the allowlist lock is poisoned.
#[pyfunction]
#[pyo3(name = "py_mcp_get_stdio_allowlist")]
pub fn py_mcp_get_stdio_allowlist(py: Python<'_>) -> PyResult<PyObject> {
    let state = allowlist::get_state().map_err(allowlist_err)?;

    let dict = PyDict::new(py);
    dict.set_item("allowed", state.allowed)?;
    dict.set_item("unrestricted", state.unrestricted)?;
    Ok(dict.into())
}

// ---------------------------------------------------------------------------
// Tool handler registration
// ---------------------------------------------------------------------------

/// Registers a Python callable as the handler for a tool in a context.
///
/// The handler is called when the tool is invoked via MCP
/// (`FfiBridgeProvider::invoke_tool`). It receives the tool's validated
/// JSON input as a Python dict and must return a Python dict representing
/// the JSON output.
///
/// The tool must already be registered in the context's tool registry
/// (via `py_tool_register`) before a handler can be attached.
///
/// # Arguments
///
/// * `context_id` -- The context containing the tool.
/// * `tool_name` -- The tool ID to attach the handler to.
/// * `handler` -- A Python callable `(dict) -> dict`.
///
/// # Errors
///
/// Raises `ContextError` if the context or tool is not found.
///
/// See SCP-212 and ADR-010 for the handler registration design.
#[pyfunction]
#[pyo3(name = "mcp_register_tool_handler")]
#[allow(clippy::needless_pass_by_value)] // PyObject must be owned to clone_ref into the closure.
pub fn py_register_tool_handler(
    py: Python<'_>,
    context_id: &str,
    tool_name: &str,
    handler: PyObject,
) -> PyResult<()> {
    validate::validate_context_id(context_id)?;
    validate::validate_tool_name(tool_name)?;
    // Verify the handler is callable before storing it.
    if !handler.bind(py).is_callable() {
        return Err(ScpPyError::ValidationError("handler must be callable".to_owned()).into());
    }

    // Wrap the Python callable in a Rust closure that acquires the GIL,
    // converts JSON -> Python dict, calls the handler, and converts back.
    let handler_ref = handler.clone_ref(py);
    let rust_handler: crate::runtime::ToolHandler =
        std::sync::Arc::new(move |input: serde_json::Value| {
            Python::with_gil(|py| {
                // Convert serde_json::Value -> Python dict.
                let py_input = crate::types::json_to_py_dict(py, &input)
                    .map_err(|e| format!("failed to convert input to Python dict: {e}"))?;

                // Call the Python handler.
                let py_result = handler_ref
                    .call1(py, (py_input,))
                    .map_err(|e| format!("Python handler raised an exception: {e}"))?;

                // Convert Python result back to serde_json::Value.
                let result_dict = py_result
                    .downcast_bound::<PyDict>(py)
                    .map_err(|_| "tool handler must return a dict".to_owned())?;
                crate::types::py_dict_to_json(result_dict)
                    .map_err(|e| format!("failed to convert handler output to JSON: {e}"))
            })
        });

    crate::runtime::register_tool_handler(context_id, tool_name, rust_handler)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Registry statistics and cleanup (issue #108)
// ---------------------------------------------------------------------------

/// MCP-specific registry entry counts.
///
/// Returned by [`py_registry_stats`] alongside the core registry stats
/// for monitoring and debugging in long-running processes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct McpRegistryStats {
    /// Number of entries in the MCP server registry.
    servers: usize,
    /// Number of stopped servers still in the registry.
    stopped_servers: usize,
    /// Number of entries in the MCP client registry.
    clients: usize,
}

/// Returns MCP registry entry counts.
fn mcp_registry_stats() -> McpRegistryStats {
    let servers = server_registry().len();
    let stopped_servers = server_registry()
        .iter()
        .filter(|entry| entry.value().stopped)
        .count();
    let clients = client_registry().len();
    McpRegistryStats {
        servers,
        stopped_servers,
        clients,
    }
}

/// Removes stopped MCP server entries from the registry.
///
/// Returns the number of entries removed. Stopped servers (where
/// `py_mcp_server_stop` was called but the entry was not removed) are
/// cleaned up to prevent indefinite accumulation in long-running
/// processes.
fn cleanup_stopped_servers() -> usize {
    let mut removed = 0;
    let keys_to_remove: Vec<String> = server_registry()
        .iter()
        .filter(|entry| entry.value().stopped)
        .map(|entry| entry.key().clone())
        .collect();

    for key in keys_to_remove {
        if server_registry().remove(&key).is_some() {
            removed += 1;
        }
    }
    removed
}

/// Returns registry entry counts for all FFI registries.
///
/// Exposes the current entry counts for the context registry, identity
/// registry, known-contexts registry, MCP server registry, and MCP
/// client registry. Intended for monitoring and debugging in
/// long-running processes.
///
/// # Returns
///
/// A Python dict with keys: `contexts`, `known_contexts`, `identities`,
/// `relay_connected`, `mcp_servers`, `mcp_servers_stopped`, `mcp_clients`.
///
/// # Errors
///
/// Raises `TransportError` if the relay state lock is poisoned.
#[pyfunction]
#[pyo3(name = "py_registry_stats")]
pub fn py_registry_stats(py: Python<'_>) -> PyResult<PyObject> {
    let core_stats = crate::runtime::registry_stats()?;
    let mcp_stats = mcp_registry_stats();

    let dict = PyDict::new(py);
    dict.set_item("contexts", core_stats.contexts)?;
    dict.set_item("known_contexts", core_stats.known_contexts)?;
    dict.set_item("identities", core_stats.identities)?;
    dict.set_item("relay_connected", core_stats.relay_connected)?;
    dict.set_item("mcp_servers", mcp_stats.servers)?;
    dict.set_item("mcp_servers_stopped", mcp_stats.stopped_servers)?;
    dict.set_item("mcp_clients", mcp_stats.clients)?;
    Ok(dict.into())
}

/// Removes stale entries from all FFI registries.
///
/// Currently cleans up:
/// - Stopped MCP server entries (where `py_mcp_server_stop` was called but
///   the entry was never removed from the registry)
///
/// # Returns
///
/// A Python dict with keys: `mcp_servers_removed` (number of stopped
/// server entries cleaned up).
///
/// # Errors
///
/// Raises `TransportError` on internal errors.
#[pyfunction]
#[pyo3(name = "py_registry_cleanup")]
pub fn py_registry_cleanup(py: Python<'_>) -> PyResult<PyObject> {
    let servers_removed = cleanup_stopped_servers();

    let dict = PyDict::new(py);
    dict.set_item("mcp_servers_removed", servers_removed)?;
    Ok(dict.into())
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers MCP bridge functions on the `_scp_core` module.
///
/// Called from [`crate::_scp_core`] during module initialization.
///
/// # Errors
///
/// Returns `PyErr` if registration of functions fails.
pub fn register_mcp(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_mcp_serve, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_server_stop, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_server_wait, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_server_info, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_client_connect_stdio, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_client_connect_sse, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_client_disconnect, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_client_info, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_client_list_tools, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_client_invoke, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_load_contexts, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_configure_stdio_allowlist, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_disable_stdio_allowlist, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_reset_stdio_allowlist, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_get_stdio_allowlist, m)?)?;
    m.add_function(wrap_pyfunction!(py_register_tool_handler, m)?)?;
    m.add_function(wrap_pyfunction!(py_registry_stats, m)?)?;
    m.add_function(wrap_pyfunction!(py_registry_cleanup, m)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // URL parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_http_url_basic() {
        let (host, port, path) = parse_http_url("http://localhost:3000/sse").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 3000);
        assert_eq!(path, "/sse");
    }

    #[test]
    fn parse_http_url_default_port() {
        let (host, port, path) = parse_http_url("http://example.com/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/path");
    }

    #[test]
    fn parse_https_url_default_port() {
        let (host, port, path) = parse_http_url("https://example.com/api").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/api");
    }

    #[test]
    fn parse_http_url_no_path() {
        let (host, port, path) = parse_http_url("http://localhost:8080").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 8080);
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_http_url_unsupported_scheme() {
        let result = parse_http_url("ftp://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn parse_http_url_rejects_crlf_injection() {
        let result = parse_http_url("http://evil.com\r\nX-Injected: bad/path");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("control characters"),
            "should mention control characters in error"
        );
    }

    #[test]
    fn parse_http_url_rejects_null_byte() {
        let result = parse_http_url("http://evil.com\0/path");
        assert!(result.is_err());
    }

    #[test]
    fn sse_connect_rejects_https() {
        let result = SseClientTransport::connect("https://example.com/sse");
        match result {
            Err(msg) => assert!(msg.contains("TLS"), "should mention TLS in error: {msg}"),
            Ok(_) => panic!("expected error for https URL"),
        }
    }

    // -----------------------------------------------------------------------
    // ClientTransport enum dispatch
    // -----------------------------------------------------------------------

    // Note: These tests verify the enum dispatch compiles and routes
    // correctly. Full integration tests require a running MCP server
    // subprocess, which is tested via pytest with maturin develop.

    // -----------------------------------------------------------------------
    // FfiBridgeProvider
    // -----------------------------------------------------------------------

    #[test]
    fn ffi_bridge_provider_active_context_ids() {
        let provider = FfiBridgeProvider {
            agent_did: "did:dht:z6MkTest".to_owned(),
            context_ids: vec!["ctx-1".to_owned(), "ctx-2".to_owned()],
            tool_timeout_ms: FFI_TOOL_TIMEOUT_MS,
        };
        assert_eq!(
            provider.active_context_ids(),
            vec!["ctx-1".to_owned(), "ctx-2".to_owned()]
        );
    }

    #[test]
    fn ffi_bridge_provider_agent_did() {
        let provider = FfiBridgeProvider {
            agent_did: "did:dht:z6MkTest".to_owned(),
            context_ids: vec![],
            tool_timeout_ms: FFI_TOOL_TIMEOUT_MS,
        };
        assert_eq!(provider.agent_did(), "did:dht:z6MkTest");
    }

    #[test]
    fn ffi_bridge_provider_context_tools_empty_for_unknown_context() {
        let provider = FfiBridgeProvider {
            agent_did: "did:dht:z6MkTest".to_owned(),
            context_ids: vec!["nonexistent".to_owned()],
            tool_timeout_ms: FFI_TOOL_TIMEOUT_MS,
        };
        // Unknown context returns empty tool list (no panic).
        let tools = provider.context_tools("nonexistent");
        assert!(tools.is_empty());
    }

    // -----------------------------------------------------------------------
    // Helper: register a context with a tool for FfiBridgeProvider tests.
    // -----------------------------------------------------------------------

    /// Registers a context in the runtime registry and optionally adds a tool.
    /// Returns a unique context ID to avoid collisions with parallel tests.
    fn setup_test_context(creator_did: &str, with_tool: bool) -> String {
        // Use a unique context ID to avoid collisions across parallel tests.
        let ctx_id = crate::types::generate_random_id("test-mcp");
        crate::runtime::register_context(&ctx_id, creator_did).unwrap();

        if with_tool {
            crate::runtime::with_context(&ctx_id, |rt| {
                let registration = scp_core::context::tools::ToolRegistration {
                    tool_id: "calculator".to_owned(),
                    name: "Calculator".to_owned(),
                    description: "A simple calculator".to_owned(),
                    schema: scp_core::context::tools::ToolSchema {
                        input_schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "a": {"type": "number"},
                                "b": {"type": "number"}
                            },
                            "required": ["a", "b"]
                        }),
                        output_schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "result": {"type": "number"}
                            }
                        }),
                    },
                    implementation_hash: [0xAA; 32],
                    test_vectors: vec![],
                    operator_did: "did:dht:z6MkOperator".into(),
                    economic_metadata: None,
                };
                scp_core::context::tools::register_tool(
                    &mut rt.tool_registry,
                    &rt.role_state,
                    registration,
                    creator_did,
                )
                .map_err(|e| crate::error::ScpPyError::ContextError(format!("{e}")))?;
                Ok(())
            })
            .unwrap();
        }

        ctx_id
    }

    // -----------------------------------------------------------------------
    // FfiBridgeProvider::validate_capability — authorized (creator has all caps)
    // -----------------------------------------------------------------------

    #[test]
    fn ffi_bridge_provider_validate_capability_allows_authorized() {
        let creator = "did:dht:z6MkCreatorValCap";
        let ctx_id = setup_test_context(creator, true);

        let provider = FfiBridgeProvider {
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            tool_timeout_ms: FFI_TOOL_TIMEOUT_MS,
        };
        // Creator has ToolInvokeAll, so any tool name should pass.
        assert!(
            provider.validate_capability(&ctx_id, "calculator").is_ok(),
            "creator should be authorized to invoke tools"
        );

        crate::runtime::remove_context(&ctx_id);
    }

    // -----------------------------------------------------------------------
    // FfiBridgeProvider::validate_capability — rejects unauthorized
    // -----------------------------------------------------------------------

    #[test]
    fn ffi_bridge_provider_validate_capability_rejects_unauthorized() {
        let creator = "did:dht:z6MkCreatorValCapReject";
        let ctx_id = setup_test_context(creator, true);

        // Add a member with no ToolInvoke capability.
        let member = "did:dht:z6MkMemberNoInvoke";
        crate::runtime::with_context(&ctx_id, |rt| {
            rt.role_state.members.insert(member.to_owned());
            let mut caps = std::collections::HashSet::new();
            caps.insert(scp_core::context::roles::Capability::MessagesRead);
            rt.role_state
                .member_capabilities
                .insert(member.to_owned(), caps);
            Ok(())
        })
        .unwrap();

        let provider = FfiBridgeProvider {
            agent_did: member.to_owned(),
            context_ids: vec![ctx_id.clone()],
            tool_timeout_ms: FFI_TOOL_TIMEOUT_MS,
        };
        let result = provider.validate_capability(&ctx_id, "calculator");
        assert!(
            result.is_err(),
            "member without ToolInvoke should be rejected"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("insufficient permissions"),
            "error should be generic (no agent DID/tool/context leaked): {err}"
        );

        crate::runtime::remove_context(&ctx_id);
    }

    // -----------------------------------------------------------------------
    // FfiBridgeProvider::invoke_tool — echo fallback when no handler
    // -----------------------------------------------------------------------

    #[test]
    fn ffi_bridge_provider_invoke_tool_echo_fallback_without_handler() {
        let creator = "did:dht:z6MkCreatorInvokeTool";
        let ctx_id = setup_test_context(creator, true);

        let provider = FfiBridgeProvider {
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            tool_timeout_ms: FFI_TOOL_TIMEOUT_MS,
        };

        let input = serde_json::json!({"a": 3, "b": 4});
        let result = provider.invoke_tool(&ctx_id, "calculator", input.clone());
        assert!(result.is_ok(), "invoke_tool should succeed: {result:?}");

        let output = result.unwrap();
        assert_eq!(
            output["status"], "validated",
            "without handler, status should be 'validated' (echo mode)"
        );
        assert_eq!(output["tool"], "calculator");
        assert_eq!(output["context"], ctx_id);
        assert_eq!(output["input_valid"], true);
        assert_eq!(output["validated_input"], input);

        crate::runtime::remove_context(&ctx_id);
    }

    // -----------------------------------------------------------------------
    // FfiBridgeProvider::invoke_tool — rejects invalid schema input
    // -----------------------------------------------------------------------

    #[test]
    fn ffi_bridge_provider_invoke_tool_validates_schema() {
        let creator = "did:dht:z6MkCreatorSchemaVal";
        let ctx_id = setup_test_context(creator, true);

        let provider = FfiBridgeProvider {
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            tool_timeout_ms: FFI_TOOL_TIMEOUT_MS,
        };

        // Input schema requires an object with "a" and "b" as required fields.
        // Pass a string instead.
        let result =
            provider.invoke_tool(&ctx_id, "calculator", serde_json::json!("not an object"));
        assert!(result.is_err(), "invalid input should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("validation"),
            "error should mention validation: {err}"
        );

        // Pass an object missing required fields.
        let result = provider.invoke_tool(&ctx_id, "calculator", serde_json::json!({"a": 1}));
        assert!(
            result.is_err(),
            "input missing required field 'b' should be rejected"
        );

        // Pass valid input — should succeed.
        let result =
            provider.invoke_tool(&ctx_id, "calculator", serde_json::json!({"a": 1, "b": 2}));
        assert!(result.is_ok(), "valid input should succeed: {result:?}");

        crate::runtime::remove_context(&ctx_id);
    }

    // -----------------------------------------------------------------------
    // FfiBridgeProvider::invoke_tool — tool not found
    // -----------------------------------------------------------------------

    #[test]
    fn ffi_bridge_provider_invoke_tool_rejects_unknown_tool() {
        let creator = "did:dht:z6MkCreatorUnknownTool";
        let ctx_id = setup_test_context(creator, false);

        let provider = FfiBridgeProvider {
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            tool_timeout_ms: FFI_TOOL_TIMEOUT_MS,
        };

        let result = provider.invoke_tool(&ctx_id, "nonexistent", serde_json::json!({}));
        assert!(result.is_err(), "unknown tool should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("not found"),
            "error should mention tool not found: {err}"
        );

        crate::runtime::remove_context(&ctx_id);
    }

    // -----------------------------------------------------------------------
    // py_mcp_load_contexts — returns contexts from local runtime registry
    // -----------------------------------------------------------------------

    #[test]
    fn load_contexts_returns_local_contexts() {
        let creator = "did:dht:z6MkCreatorLoadCtx";
        let ctx_id = setup_test_context(creator, true);

        // Since py_mcp_load_contexts requires Python, we test the underlying
        // runtime function directly.
        let ids = crate::runtime::context_ids_for_member(creator);
        assert!(
            ids.contains(&ctx_id),
            "creator should be a member of the context"
        );

        // Non-member should not see the context.
        let other_ids = crate::runtime::context_ids_for_member("did:dht:z6MkNobody");
        assert!(
            !other_ids.contains(&ctx_id),
            "non-member should not see the context"
        );

        crate::runtime::remove_context(&ctx_id);
    }

    // -----------------------------------------------------------------------
    // Known context registry (SCP-213)
    // -----------------------------------------------------------------------

    #[test]
    fn known_context_registration_and_lookup() {
        let creator = "did:dht:z6MkCreatorKnownCtx";
        let ctx_id = crate::types::generate_random_id("known-ctx");
        let routing_id = [0xAA; 32];

        let known = crate::runtime::KnownContext {
            routing_id,
            relay_url: Some("ws://127.0.0.1:9000/scp/v1".to_owned()),
            member_did: creator.to_owned(),
            last_seen: 1_700_000_000,
        };

        crate::runtime::register_known_context(&ctx_id, known);

        // Should be discoverable by member DID.
        let found = crate::runtime::known_contexts_for_member(creator);
        assert!(
            found.iter().any(|(id, _)| id == &ctx_id),
            "known context should be found by member DID"
        );

        // Should not be found for a different DID.
        let not_found = crate::runtime::known_contexts_for_member("did:dht:z6MkSomeoneElse");
        assert!(
            !not_found.iter().any(|(id, _)| id == &ctx_id),
            "known context should not be found for a different DID"
        );

        // Cleanup: remove_context also removes from known-contexts.
        crate::runtime::remove_context(&ctx_id);
        let after_remove = crate::runtime::known_contexts_for_member(creator);
        assert!(
            !after_remove.iter().any(|(id, _)| id == &ctx_id),
            "known context should be removed after remove_context"
        );
    }

    #[test]
    fn probe_relay_with_no_connection_returns_empty() {
        // When no relay connection is active, probing should return an empty set.
        let known = vec![(
            "test-ctx".to_owned(),
            crate::runtime::KnownContext {
                routing_id: [0xBB; 32],
                relay_url: Some("ws://127.0.0.1:9000/scp/v1".to_owned()),
                member_did: "did:dht:z6MkTest".to_owned(),
                last_seen: 1_700_000_000,
            },
        )];

        let active = probe_relay_for_known_contexts(&known);
        assert!(
            active.is_empty(),
            "should return empty set when no relay is connected"
        );
    }

    #[test]
    fn probe_relay_with_empty_known_returns_empty() {
        let known: Vec<(String, crate::runtime::KnownContext)> = vec![];
        let active = probe_relay_for_known_contexts(&known);
        assert!(active.is_empty(), "should return empty set for empty input");
    }

    #[test]
    fn ffi_bridge_provider_subscribe_resource_accepts() {
        let provider = FfiBridgeProvider {
            agent_did: "did:dht:z6MkTest".to_owned(),
            context_ids: vec![],
            tool_timeout_ms: FFI_TOOL_TIMEOUT_MS,
        };
        assert!(provider.subscribe_resource("scp://ctx/events").is_ok());
    }

    // -----------------------------------------------------------------------
    // Tool handler registration and dispatch (SCP-212)
    // -----------------------------------------------------------------------

    #[test]
    fn register_tool_handler_and_invoke_dispatches_through_handler() {
        let creator = "did:dht:z6MkCreatorHandler";
        let ctx_id = setup_test_context(creator, true);

        // Register a Rust handler that adds two numbers (simulates a Python handler).
        let handler: crate::runtime::ToolHandler =
            std::sync::Arc::new(|input: serde_json::Value| {
                let a = input
                    .get("a")
                    .and_then(serde_json::Value::as_f64)
                    .ok_or_else(|| "missing 'a'".to_owned())?;
                let b = input
                    .get("b")
                    .and_then(serde_json::Value::as_f64)
                    .ok_or_else(|| "missing 'b'".to_owned())?;
                Ok(serde_json::json!({"result": a + b}))
            });

        crate::runtime::register_tool_handler(&ctx_id, "calculator", handler).unwrap();

        let provider = FfiBridgeProvider {
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            tool_timeout_ms: FFI_TOOL_TIMEOUT_MS,
        };

        let input = serde_json::json!({"a": 3, "b": 4});
        let result = provider.invoke_tool(&ctx_id, "calculator", input);
        assert!(result.is_ok(), "invoke_tool should succeed: {result:?}");

        let output = result.unwrap();
        // Handler returns computed output, not echoed input.
        assert_eq!(
            output,
            serde_json::json!({"result": 7.0}),
            "handler should compute a + b = 7"
        );
        // Should NOT have the echo-mode "status" field.
        assert!(
            output.get("status").is_none(),
            "handler output should not contain echo-mode 'status' field"
        );

        crate::runtime::remove_context(&ctx_id);
    }

    #[test]
    fn register_tool_handler_rejects_unregistered_tool() {
        let creator = "did:dht:z6MkCreatorHandlerReject";
        let ctx_id = setup_test_context(creator, false); // No tool registered.

        let handler: crate::runtime::ToolHandler =
            std::sync::Arc::new(|_input| Ok(serde_json::json!({})));

        let result = crate::runtime::register_tool_handler(&ctx_id, "nonexistent", handler);
        assert!(
            result.is_err(),
            "should reject handler for unregistered tool"
        );
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("not found"),
            "error should mention tool not found: {err}"
        );

        crate::runtime::remove_context(&ctx_id);
    }

    #[test]
    fn invoke_tool_with_handler_validates_output_schema() {
        let creator = "did:dht:z6MkCreatorOutVal";
        let ctx_id = setup_test_context(creator, true);

        // Register a handler that returns a string instead of an object
        // (violates the output schema which requires an object).
        let bad_handler: crate::runtime::ToolHandler =
            std::sync::Arc::new(|_input| Ok(serde_json::json!("not an object")));

        crate::runtime::register_tool_handler(&ctx_id, "calculator", bad_handler).unwrap();

        let provider = FfiBridgeProvider {
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            tool_timeout_ms: FFI_TOOL_TIMEOUT_MS,
        };

        let result =
            provider.invoke_tool(&ctx_id, "calculator", serde_json::json!({"a": 1, "b": 2}));
        assert!(
            result.is_err(),
            "handler returning invalid output should be rejected"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("output validation"),
            "error should mention output validation: {err}"
        );

        crate::runtime::remove_context(&ctx_id);
    }

    #[test]
    fn invoke_tool_handler_error_is_propagated() {
        let creator = "did:dht:z6MkCreatorHandlerErr";
        let ctx_id = setup_test_context(creator, true);

        // Register a handler that always fails.
        let failing_handler: crate::runtime::ToolHandler =
            std::sync::Arc::new(|_input| Err("computation exploded".to_owned()));

        crate::runtime::register_tool_handler(&ctx_id, "calculator", failing_handler).unwrap();

        let provider = FfiBridgeProvider {
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            tool_timeout_ms: FFI_TOOL_TIMEOUT_MS,
        };

        let result =
            provider.invoke_tool(&ctx_id, "calculator", serde_json::json!({"a": 1, "b": 2}));
        assert!(result.is_err(), "failing handler should propagate error");
        let err = result.unwrap_err();
        assert!(
            err.contains("computation exploded"),
            "error should contain handler error message: {err}"
        );

        crate::runtime::remove_context(&ctx_id);
    }

    // -----------------------------------------------------------------------
    // Tool handler execution timeout (issue #123)
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_tool_handler_timeout_produces_clear_error() {
        let creator = "did:dht:z6MkCreatorTimeout";
        let ctx_id = setup_test_context(creator, true);

        // Register a handler that blocks for 5 seconds (will be timed out).
        let blocking_handler: crate::runtime::ToolHandler = std::sync::Arc::new(|_input| {
            std::thread::sleep(std::time::Duration::from_secs(5));
            Ok(serde_json::json!({"result": 42}))
        });

        crate::runtime::register_tool_handler(&ctx_id, "calculator", blocking_handler).unwrap();

        let provider = FfiBridgeProvider {
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            tool_timeout_ms: 50, // 50ms — will expire before the 5s sleep.
        };

        let result =
            provider.invoke_tool(&ctx_id, "calculator", serde_json::json!({"a": 1, "b": 2}));
        assert!(result.is_err(), "blocking handler should be timed out");
        let err = result.unwrap_err();
        assert!(
            err.contains("timed out"),
            "error should mention timeout: {err}"
        );
        assert!(
            err.contains("50ms"),
            "error should include the timeout duration: {err}"
        );

        crate::runtime::remove_context(&ctx_id);
    }

    #[test]
    fn invoke_tool_handler_completes_within_timeout_succeeds() {
        let creator = "did:dht:z6MkCreatorTimeoutOk";
        let ctx_id = setup_test_context(creator, true);

        // Register a fast handler.
        let fast_handler: crate::runtime::ToolHandler =
            std::sync::Arc::new(|input: serde_json::Value| {
                let a = input
                    .get("a")
                    .and_then(serde_json::Value::as_f64)
                    .unwrap_or(0.0);
                let b = input
                    .get("b")
                    .and_then(serde_json::Value::as_f64)
                    .unwrap_or(0.0);
                Ok(serde_json::json!({"result": a + b}))
            });

        crate::runtime::register_tool_handler(&ctx_id, "calculator", fast_handler).unwrap();

        let provider = FfiBridgeProvider {
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            tool_timeout_ms: 5_000, // 5 seconds — plenty for an instant handler.
        };

        let result =
            provider.invoke_tool(&ctx_id, "calculator", serde_json::json!({"a": 3, "b": 4}));
        assert!(
            result.is_ok(),
            "fast handler should complete within timeout: {result:?}"
        );
        let output = result.unwrap();
        assert_eq!(
            output,
            serde_json::json!({"result": 7.0}),
            "handler output should be correct"
        );

        crate::runtime::remove_context(&ctx_id);
    }

    #[test]
    fn invoke_tool_handler_default_timeout_is_30s() {
        // Verify the default timeout constant matches scp-core.
        assert_eq!(
            FFI_TOOL_TIMEOUT_MS,
            u64::from(scp_core::context::tools::DEFAULT_TIMEOUT_MS),
            "FFI default timeout should match scp-core default"
        );
    }

    // -----------------------------------------------------------------------
    // StdioClientTransport
    // -----------------------------------------------------------------------

    #[test]
    fn stdio_client_transport_spawn_rejects_unlisted_command() {
        allowlist::reset().unwrap();
        let result = StdioClientTransport::spawn(&[
            "nonexistent_command_that_does_not_exist_12345".to_owned(),
        ]);
        match result {
            Err(msg) => assert!(
                msg.contains("allowlist"),
                "error should mention allowlist: {msg}"
            ),
            Ok(_) => panic!("expected rejection for unlisted command"),
        }
    }

    #[test]
    fn stdio_client_transport_empty_command() {
        let result = StdioClientTransport::spawn(&[]);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Registry statistics and cleanup (issue #108)
    // -----------------------------------------------------------------------

    #[test]
    fn mcp_registry_stats_returns_consistent_counts() {
        let stats = mcp_registry_stats();
        // Cannot assert exact values due to parallel tests, but structural
        // invariants must hold: stopped_servers can never exceed total servers.
        assert!(
            stats.stopped_servers <= stats.servers,
            "stopped_servers ({}) must be <= servers ({})",
            stats.stopped_servers,
            stats.servers
        );
        // Verify the struct is constructable and all fields are accessible.
        let _ = stats.clients;
    }

    #[test]
    fn cleanup_stopped_servers_removes_stopped_entries() {
        let creator = "did:dht:z6MkCreatorCleanup";
        let ctx_id = setup_test_context(creator, false);

        // Create a minimal server entry directly in the registry.
        let provider = FfiBridgeProvider {
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            tool_timeout_ms: FFI_TOOL_TIMEOUT_MS,
        };
        let server = McpServer::new(provider);
        let server = Arc::new(Mutex::new(server));
        let handle = generate_handle_id("mcp-server");

        server_registry().insert(
            handle.clone(),
            McpServerState {
                identity_did: creator.to_owned(),
                context_ids: vec![ctx_id.clone()],
                transport: "stdio".to_owned(),
                stopped: true, // Already stopped.
                server,
                shutdown_tx: None,
                task_handle: None,
            },
        );

        // Verify our entry is present before cleanup.
        assert!(
            server_registry().contains_key(&handle),
            "stopped server handle should be present before cleanup"
        );

        cleanup_stopped_servers();

        // The specific handle should be gone. We check by key rather than
        // by count because parallel tests may insert/remove other entries.
        assert!(
            !server_registry().contains_key(&handle),
            "stopped server handle should be removed after cleanup"
        );

        crate::runtime::remove_context(&ctx_id);
    }

    #[test]
    fn cleanup_stopped_servers_leaves_running_entries() {
        let creator = "did:dht:z6MkCreatorCleanupRunning";
        let ctx_id = setup_test_context(creator, false);

        let provider = FfiBridgeProvider {
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            tool_timeout_ms: FFI_TOOL_TIMEOUT_MS,
        };
        let server = McpServer::new(provider);
        let server = Arc::new(Mutex::new(server));
        let handle = generate_handle_id("mcp-server");

        server_registry().insert(
            handle.clone(),
            McpServerState {
                identity_did: creator.to_owned(),
                context_ids: vec![ctx_id.clone()],
                transport: "stdio".to_owned(),
                stopped: false, // Still running.
                server,
                shutdown_tx: None,
                task_handle: None,
            },
        );

        cleanup_stopped_servers();

        // Running server should still be present.
        assert!(
            server_registry().contains_key(&handle),
            "running server handle should NOT be removed"
        );

        // Cleanup: remove manually.
        server_registry().remove(&handle);
        crate::runtime::remove_context(&ctx_id);
    }

    #[test]
    fn core_registry_stats_includes_all_fields() {
        let stats = crate::runtime::registry_stats().unwrap();
        // Just verify the struct has the expected fields and doesn't panic.
        let _ = stats.contexts;
        let _ = stats.known_contexts;
        let _ = stats.identities;
        let _ = stats.relay_connected;
    }
}
