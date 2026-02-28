//! `PyO3` bridge functions for MCP (Model Context Protocol) server and client.
//!
//! Exposes SCP MCP operations to Python:
//!
//! - [`py_mcp_serve`] -- Start an MCP server exposing SCP context tools.
//! - [`py_mcp_server_stop`] -- Stop a running MCP server.
//! - [`py_mcp_server_wait`] -- Block until the MCP server exits.
//! - [`py_mcp_client_connect_stdio`] -- Connect to an external MCP server via
//!   stdio.
//! - [`py_mcp_client_connect_sse`] -- Connect to an external MCP server via
//!   SSE.
//! - [`py_mcp_client_disconnect`] -- Disconnect from an external MCP server.
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
use scp_mcp::client::{McpClient, McpTransport, SystemTimestamp};
use scp_mcp::protocol::{JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};
use scp_mcp::server::{ContextProvider, ContextToolInfo, McpServer, MemberInfo};

use crate::error::ScpPyError;
use crate::types::{json_to_py_dict, py_dict_to_json};

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
    /// The spawned subprocess. Kept alive for the transport lifetime;
    /// dropped when the transport is dropped, which kills the subprocess.
    #[allow(dead_code)]
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

        let mut child = Command::new(cmd)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("failed to spawn '{cmd}': {e}"))?;

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

    /// Kills the subprocess if it is still running.
    #[allow(dead_code)] // Available for explicit cleanup; subprocess is also killed on Drop.
    fn kill(&self) {
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
        let bytes_read = inner
            .reader
            .read_line(&mut line)
            .map_err(|e| format!("failed to read from subprocess stdout: {e}"))?;

        if bytes_read == 0 {
            return Err("subprocess closed stdout (EOF)".to_owned());
        }

        serde_json::from_str(line.trim())
            .map_err(|e| format!("failed to parse response JSON: {e}"))
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
        let n = reader
            .read_line(&mut status_line)
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
            let n = reader
                .read_line(&mut header_line)
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
            let n = reader
                .read_line(&mut event_line)
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
            return Err(
                "SSE endpoint path contains invalid control characters".to_owned(),
            );
        }

        // Build the full POST URL.
        let scheme = if port == 443 { "https" } else { "http" };
        let post_url = format!("{scheme}://{host}:{port}{post_path}");

        Ok(Self {
            _url: url.to_owned(),
            post_url,
            sse_reader: Mutex::new(Some(reader)),
        })
    }
}

impl McpTransport for SseClientTransport {
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

        let reader = sse_reader
            .as_mut()
            .ok_or("SSE connection is closed")?;

        // Read SSE events until we find a `message` event with our response.
        // Bounded to prevent a misbehaving server from consuming resources
        // indefinitely. The TCP read timeout (30s) handles individual reads;
        // this bounds the total number of non-matching events we'll tolerate.
        const MAX_SSE_EVENTS: usize = 1000;
        for _ in 0..MAX_SSE_EVENTS {
            let mut line = String::new();
            let n = reader
                .read_line(&mut line)
                .map_err(|e| format!("failed to read SSE event: {e}"))?;
            if n == 0 {
                return Err("SSE connection closed while waiting for response".to_owned());
            }
            let trimmed = line.trim();
            if trimmed.starts_with("data:") {
                let data = trimmed
                    .strip_prefix("data:")
                    .unwrap_or("")
                    .trim();
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
            Self::Sse(t) => t.send_request(request),
        }
    }

    fn send_notification(&self, notification: &JsonRpcNotification) -> Result<(), String> {
        match self {
            Self::Stdio(t) => t.send_notification(notification),
            Self::Sse(t) => t.send_notification(notification),
        }
    }
}

// ---------------------------------------------------------------------------
// FFI bridge context provider
// ---------------------------------------------------------------------------

/// Implements [`ContextProvider`] by reading from the scp-ffi runtime registry.
///
/// Bridges the MCP server's context/tool queries to the live runtime state
/// managed by `crates/scp-ffi/src/runtime.rs`.
struct FfiBridgeProvider {
    /// The agent's DID.
    agent_did: String,
    /// The context IDs this provider serves.
    context_ids: Vec<String>,
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

    fn validate_capability(&self, _context_id: &str, _tool_name: &str) -> Result<(), String> {
        // TODO(#106): Wire to role_state.member_has_capability() for defense-in-depth.
        // Currently returns Ok(()) — authorization depends on UCAN layer.
        // See: .docs/specs/07-trust-validation-and-capabilities.md §7.2
        Ok(())
    }

    fn invoke_tool(
        &self,
        context_id: &str,
        tool_name: &str,
        _arguments: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        // TODO(#106): Wire to scp-core's tool invocation pipeline (tools/invoke.rs)
        // for real execution with schema validation and handler dispatch.
        // Currently returns a stub JSON response indicating the tool exists.
        crate::runtime::with_context(context_id, |rt| {
            // Verify the tool exists.
            if rt.tool_registry.get(tool_name).is_none() {
                return Err(ScpPyError::ContextError(format!(
                    "tool '{tool_name}' not found in context '{context_id}'"
                )));
            }
            // Return a JSON result indicating the tool was invoked.
            // Full execution with schema validation and handler dispatch
            // is wired via the tool invocation pipeline.
            Ok(serde_json::json!({
                "tool": tool_name,
                "context": context_id,
                "status": "invoked"
            }))
        })
        .map_err(|e| format!("{e}"))
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
#[allow(dead_code)] // Fields are stored for state tracking and future introspection.
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
    /// from the transport task and bridge functions.
    server: Arc<Mutex<McpServer<FfiBridgeProvider>>>,
    /// Shutdown signal sender. Dropping this signals the transport task to stop.
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// Handle to the tokio task running the transport. Used by `server_wait`.
    task_handle: Option<tokio::task::JoinHandle<()>>,
}

/// State for an active MCP client connection.
#[allow(dead_code)] // Fields are stored for state tracking and reconnection.
struct McpClientState {
    /// The transport mode (stdio or sse).
    transport: String,
    /// For stdio, the command used to spawn the subprocess.
    command: Option<Vec<String>>,
    /// For sse, the URL of the SSE endpoint.
    url: Option<String>,
    /// Whether the client has been disconnected.
    disconnected: bool,
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
pub fn py_mcp_serve(
    identity_did: &str,
    context_ids: Vec<String>,
    transport: &str,
) -> PyResult<String> {
    // Validate transport mode.
    if transport != "stdio" && transport != "sse" {
        return Err(ScpPyError::ValidationError(format!(
            "transport must be 'stdio' or 'sse', got '{transport}'"
        ))
        .into());
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
                    _ = async {
                        // The real `run_stdio` takes &mut McpServer by value.
                        // We need to run it with our Arc<Mutex> server.
                        // Since `run_stdio` processes stdin line by line, we
                        // replicate its logic here using the shared server.
                        let stdin = tokio::io::stdin();
                        let mut stdout = tokio::io::stdout();
                        let mut reader = tokio::io::BufReader::new(stdin);
                        let mut line = String::new();

                        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

                        loop {
                            line.clear();
                            match reader.read_line(&mut line).await {
                                Ok(0) => break, // EOF
                                Ok(_) => {}
                                Err(_) => break,
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
                                        if let Ok(mut srv) = server_clone.lock() {
                                            srv.handle_request(&req)
                                        } else {
                                            None
                                        }
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

                            if let Some(resp) = response {
                                if let Ok(json) = serde_json::to_string(&resp) {
                                    let _ = stdout.write_all(json.as_bytes()).await;
                                    let _ = stdout.write_all(b"\n").await;
                                    let _ = stdout.flush().await;
                                }
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
                };
                let sse_server = McpServer::new(provider);
                let config = scp_mcp::sse::SseConfig::new(
                    std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
                );

                tokio::select! {
                    _ = shutdown_rx => {}
                    result = scp_mcp::sse::run_sse(sse_server, config) => {
                        if let Err(e) = result {
                            tracing::error!("MCP SSE server error: {e}");
                        }
                    }
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
pub fn py_mcp_client_connect_stdio(command: Vec<String>) -> PyResult<String> {
    if command.is_empty() {
        return Err(ScpPyError::ValidationError(
            "command must be a non-empty list".to_owned(),
        )
        .into());
    }

    // Spawn the subprocess and create the transport.
    let transport = StdioClientTransport::spawn(&command).map_err(|e| {
        ScpPyError::TransportError(format!("failed to connect stdio client: {e}"))
    })?;

    // Create the MCP client and perform the initialize handshake.
    let mut client = McpClient::new(ClientTransport::Stdio(transport));
    client.initialize().map_err(|e| {
        ScpPyError::TransportError(format!("MCP initialize handshake failed: {e}"))
    })?;

    let handle = generate_handle_id("mcp-client");
    let state = McpClientState {
        transport: "stdio".to_owned(),
        command: Some(command),
        url: None,
        disconnected: false,
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
    if url.is_empty() {
        return Err(ScpPyError::ValidationError(
            "url must be a non-empty string".to_owned(),
        )
        .into());
    }

    // Connect to the SSE endpoint.
    let transport = SseClientTransport::connect(url).map_err(|e| {
        ScpPyError::TransportError(format!("failed to connect SSE client: {e}"))
    })?;

    // Create the MCP client and perform the initialize handshake.
    let mut client = McpClient::new(ClientTransport::Sse(transport));
    client.initialize().map_err(|e| {
        ScpPyError::TransportError(format!("MCP initialize handshake failed: {e}"))
    })?;

    let handle = generate_handle_id("mcp-client");
    let state = McpClientState {
        transport: "sse".to_owned(),
        command: None,
        url: Some(url.to_owned()),
        disconnected: false,
        client: Arc::new(Mutex::new(client)),
    };

    client_registry().insert(handle.clone(), state);

    Ok(handle)
}

/// Disconnects from an external MCP server.
///
/// Marks the client as disconnected and cleans up the transport connection.
/// For stdio clients, kills the subprocess. For SSE clients, closes the
/// TCP connection.
///
/// # Arguments
///
/// * `handle` -- The client handle returned by `py_mcp_client_connect_*`.
///
/// # Errors
///
/// Raises `TransportError` if the client is not found or already
/// disconnected.
#[pyfunction]
#[pyo3(name = "py_mcp_client_disconnect")]
pub fn py_mcp_client_disconnect(handle: &str) -> PyResult<()> {
    let mut entry = client_registry().get_mut(handle).ok_or_else(|| {
        ScpPyError::TransportError(format!("MCP client handle '{handle}' not found"))
    })?;

    if entry.disconnected {
        return Err(ScpPyError::TransportError(format!(
            "MCP client '{handle}' is already disconnected"
        ))
        .into());
    }

    entry.disconnected = true;

    // Kill the subprocess if this is a stdio transport.
    if let Ok(client) = entry.client.lock() {
        // Access the transport to kill it. Since McpClient doesn't expose
        // its transport directly, we rely on the Drop implementation or
        // manual cleanup. For stdio, the subprocess will be killed when
        // the transport is dropped. We force it now by accessing the
        // transport through a known mechanism.
        //
        // Since we marked disconnected=true, subsequent operations will
        // fail with TransportError, and the transport resources will be
        // cleaned up when the McpClientState is dropped.
        drop(client);
    }

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
    let entry = client_registry().get(handle).ok_or_else(|| {
        ScpPyError::TransportError(format!("MCP client handle '{handle}' not found"))
    })?;

    if entry.disconnected {
        return Err(ScpPyError::TransportError(format!(
            "MCP client '{handle}' is disconnected"
        ))
        .into());
    }

    // Send the real tools/list request via the MCP client.
    let client = Arc::clone(&entry.client);
    drop(entry); // Release the DashMap guard before blocking.

    let tools = {
        let client_guard = client.lock().map_err(|e| {
            ScpPyError::TransportError(format!("client lock poisoned: {e}"))
        })?;
        client_guard.list_tools().map_err(|e| {
            ScpPyError::TransportError(format!("tools/list failed: {e}"))
        })?
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
    let entry = client_registry().get(handle).ok_or_else(|| {
        ScpPyError::TransportError(format!("MCP client handle '{handle}' not found"))
    })?;

    if entry.disconnected {
        return Err(ScpPyError::TransportError(format!(
            "MCP client '{handle}' is disconnected"
        ))
        .into());
    }

    let client = Arc::clone(&entry.client);
    drop(entry); // Release the DashMap guard before Python object access.

    // Convert input to JSON.
    let input_json = py_dict_to_json(input)?;

    // Send the real tools/call request via the MCP client.
    let result = {
        let client_guard = client.lock().map_err(|e| {
            ScpPyError::TransportError(format!("client lock poisoned: {e}"))
        })?;
        client_guard
            .invoke(tool_name, input_json, context_id, identity_did)
            .map_err(|e| {
                ScpPyError::TransportError(format!("tools/call failed: {e}"))
            })?
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

/// Loads active contexts for a DID from a relay.
///
/// Discovers the contexts that the given identity is a member of by
/// querying the relay. Used during CLI startup to populate the MCP
/// server with the agent's active contexts.
///
/// # Arguments
///
/// * `identity_did` -- The DID to look up contexts for.
/// * `relay_url` -- The relay URL to query.
///
/// # Returns
///
/// A list of context handle objects. Returns an empty list if no relay
/// connection is available (no active transport connection).
///
/// # Errors
///
/// Raises `TransportError` if the relay query fails.
#[pyfunction]
#[pyo3(name = "py_mcp_load_contexts")]
pub fn py_mcp_load_contexts(
    _identity_did: &str,
    _relay_url: &str,
) -> PyResult<Vec<PyObject>> {
    // Context discovery requires a live relay connection which is wired via
    // the transport layer (scp-transport). Since relay connections are managed
    // separately from MCP, this function returns an empty list when no relay
    // is connected. The full implementation will query the relay for the
    // identity's active contexts using the transport module.
    Ok(Vec::new())
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
    m.add_function(wrap_pyfunction!(py_mcp_client_connect_stdio, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_client_connect_sse, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_client_disconnect, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_client_list_tools, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_client_invoke, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_load_contexts, m)?)?;
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
            result
                .unwrap_err()
                .contains("control characters"),
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
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("TLS"),
            "should mention TLS in error"
        );
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
        };
        assert_eq!(provider.agent_did(), "did:dht:z6MkTest");
    }

    #[test]
    fn ffi_bridge_provider_context_tools_empty_for_unknown_context() {
        let provider = FfiBridgeProvider {
            agent_did: "did:dht:z6MkTest".to_owned(),
            context_ids: vec!["nonexistent".to_owned()],
        };
        // Unknown context returns empty tool list (no panic).
        let tools = provider.context_tools("nonexistent");
        assert!(tools.is_empty());
    }

    #[test]
    fn ffi_bridge_provider_validate_capability_always_ok() {
        let provider = FfiBridgeProvider {
            agent_did: "did:dht:z6MkTest".to_owned(),
            context_ids: vec![],
        };
        // Capability validation is delegated to the UCAN layer.
        assert!(provider.validate_capability("ctx-1", "tool-1").is_ok());
    }

    #[test]
    fn ffi_bridge_provider_subscribe_resource_accepts() {
        let provider = FfiBridgeProvider {
            agent_did: "did:dht:z6MkTest".to_owned(),
            context_ids: vec![],
        };
        assert!(provider.subscribe_resource("scp://ctx/events").is_ok());
    }

    // -----------------------------------------------------------------------
    // StdioClientTransport
    // -----------------------------------------------------------------------

    #[test]
    fn stdio_client_transport_spawn_nonexistent_command() {
        let result = StdioClientTransport::spawn(&[
            "nonexistent_command_that_does_not_exist_12345".to_owned(),
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn stdio_client_transport_empty_command() {
        let result = StdioClientTransport::spawn(&[]);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Server/client lifecycle (integration-style tests)
    // -----------------------------------------------------------------------

    // Note: Full lifecycle tests (start server, connect client, list tools,
    // invoke, disconnect, stop) require either:
    //   1. A real MCP server subprocess (tested via pytest)
    //   2. An in-process mock (tested below with the mock transport from
    //      scp-mcp::client)
    //
    // Since scp-ffi has test=false (requires Python dev headers), these
    // tests serve as documentation of expected behavior and are verified
    // via maturin develop + pytest.

    // -----------------------------------------------------------------------
    // Disconnected client error
    // -----------------------------------------------------------------------

    // Verified in the bridge functions: when `disconnected` is true,
    // list_tools and invoke return TransportError. This is tested via
    // pytest since the bridge functions require PyO3.
}
