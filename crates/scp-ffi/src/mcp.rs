//! `PyO3` bridge functions for MCP (Model Context Protocol) server and client.
//!
//! Exposes SCP MCP operations to Python:
//!
//! - `py_mcp_serve` -- Start an MCP server exposing SCP context outlets.
//! - `py_mcp_server_stop` -- Stop a running MCP server.
//! - `py_mcp_server_wait` -- Block until the MCP server exits.
//! - `py_mcp_server_info` -- Return metadata about a running MCP server.
//! - `py_mcp_client_connect_stdio` -- Connect to an external MCP server via
//!   stdio.
//! - `py_mcp_client_connect_sse` -- Connect to an external MCP server via
//!   SSE.
//! - `py_mcp_client_disconnect` -- Disconnect from an external MCP server.
//! - `py_mcp_client_info` -- Return metadata about an active MCP client.
//! - `py_mcp_client_list_tools` -- List outlets from an external MCP server.
//! - `py_mcp_client_invoke` -- Invoke an external MCP outlet with provenance.
//! - `py_mcp_load_contexts` -- Load active contexts for a DID from a relay.
//!
//! The MCP bridge uses opaque string handles to track server and client
//! instances. Handles are stored in a global registry (similar to the
//! context runtime registry pattern).
//!
//! ## Architecture
//!
//! The bridge delegates to real `scp-mcp` implementations:
//!
//! - **Server side**: `FfiBridgeProvider` implements
//!   [`scp_mcp::server::ContextProvider`], reading outlet registrations and
//!   context state from the scp-ffi runtime registry. The MCP server is run
//!   on the tokio runtime via [`scp_mcp::stdio::run_stdio`] or
//!   [`scp_mcp::sse::run_sse`].
//!
//! - **Client side**: `StdioClientTransport` implements
//!   [`scp_mcp::client::McpTransport`] by spawning a subprocess and
//!   communicating via line-delimited JSON-RPC over stdin/stdout. SSE
//!   client transport is managed via `SseClientTransport`.
//!
//! See ADR-015 in `.docs/adrs/phase-3.md` for the full MCP adapter design.

use scp_ffi_common::error_codes as codes;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use scp_mcp::allowlist;
use scp_mcp::client::{McpClient, McpTransport, SystemTimestamp};
use scp_mcp::protocol::{JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};
use scp_mcp::server::{ContextOutletInfo, ContextProvider, McpServer, MemberInfo};
use scp_platform::traits::Storage;

use crate::error::ScpPyError;
use crate::types::{json_to_py_dict, py_dict_to_json};
use crate::validate;

// ---------------------------------------------------------------------------
// Bounded read_line — prevents OOM from unbounded line reads
// ---------------------------------------------------------------------------

/// Maximum bytes to read for a single line from an MCP transport.
///
/// Re-exported from [`scp_mcp::stdio::MAX_LINE_BYTES`] rather than redeclared:
/// the client transport here and the server transport in `scp-mcp` frame the
/// same JSON-RPC line protocol, so a peer that is within the limit on one side
/// must be within it on the other. Three independent copies of the constant
/// could drift into exactly that asymmetry.
use scp_mcp::stdio::MAX_LINE_BYTES;

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
    fn spawn(
        allowlist: &Mutex<allowlist::StdioAllowlist>,
        command: &[String],
    ) -> Result<Self, String> {
        let (cmd, args) = command.split_first().ok_or("command list is empty")?;

        // Validate the command against the per-instance stdio allowlist
        // (defense-in-depth). Uses the validated basename for Command::new
        // to prevent path bypass. Hold the lock only across `validate_command`,
        // then drop before spawning the subprocess.
        let basename = {
            let guard = allowlist
                .lock()
                .map_err(|_| "stdio allowlist lock poisoned".to_owned())?;
            guard.validate_command(cmd).map_err(|e| e.to_string())?
        };

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

/// Default outlet handler execution timeout in milliseconds (30 seconds).
///
/// Matches [`scp_core::context::outlets::DEFAULT_TIMEOUT_MS`]. If a registered
/// handler does not return within this duration, the invocation is aborted
/// with a timeout error. Configurable per-provider via
/// [`FfiBridgeProvider::outlet_timeout_ms`].
const FFI_OUTLET_TIMEOUT_MS: u64 = scp_core::context::outlets::DEFAULT_TIMEOUT_MS as u64;

/// Implements [`ContextProvider`] by reading from the scp-ffi runtime registry.
///
/// Bridges the MCP server's context/outlet queries to the live runtime state
/// managed by `crates/scp-ffi/src/runtime.rs`.
struct FfiBridgeProvider {
    /// Weak reference to the bridge instance whose runtime registry this
    /// provider reads.
    ///
    /// # Why `Weak` and not `Arc` (#1549 round-2 bug-catcher)
    ///
    /// The provider is installed in an [`McpServer`] that lives inside a
    /// background task spawned on the shared tokio runtime
    /// (`RUNTIME.spawn(...)`). That task is NOT enrolled in the per-instance
    /// [`JoinSet`](scp_ffi_common::bridge_instance::CoreFields::task_handle)
    /// aborted by `emergency_cancel_tasks`, so it survives
    /// [`crate::runtime::PyBridgeInstance::drop`] unless the caller
    /// explicitly sends a shutdown via
    /// [`crate::scp::PyScp::py_mcp_server_stop`].
    ///
    /// If this field were `Arc<PyBridgeInstance>`, the server task would
    /// keep the instance alive forever when the caller forgets to
    /// `shutdown`. With `Weak`, callers that drop their last strong
    /// reference release `ContextManager`, identity registry, relay
    /// connection, and the rest of `BridgeInstance`'s state. Provider
    /// methods upgrade per call; once `None` is returned, they emit a
    /// stable error so the MCP server can propagate it to the peer.
    bi: std::sync::Weak<crate::runtime::PyBridgeInstance>,
    /// The agent's DID.
    agent_did: String,
    /// The context IDs this provider serves.
    context_ids: Vec<String>,
    /// Maximum time (in milliseconds) to wait for an outlet handler to complete.
    ///
    /// Defaults to [`FFI_OUTLET_TIMEOUT_MS`] (30 seconds). If a registered
    /// handler blocks longer than this, the invocation returns an error
    /// instead of blocking indefinitely. See issue #123.
    outlet_timeout_ms: u64,
    /// JWT-encoded UCAN token for outlet invocation authorization.
    ///
    /// When present, `validate_capability` runs the full 11-step ADR-016
    /// validation pipeline to verify the token grants `outlet_call:{outlet_name}`
    /// or `outlet_call:*` for the context. When absent, `validate_capability`
    /// rejects immediately (UCAN is required for outlet invocation).
    ///
    /// See spec §6.2, §8, ADR-016, and issue #319.
    agent_ucan_token: Option<String>,
    /// Optional proof tokens for UCAN delegation chain verification.
    ///
    /// When the `agent_ucan_token` is a delegated UCAN (non-empty `prf` field),
    /// the parent tokens must be provided here so the proof resolver can
    /// verify the delegation chain. Without these, delegated UCANs always fail.
    agent_proof_tokens: Option<Vec<String>>,
}

impl FfiBridgeProvider {
    /// Upgrades the stored [`Weak`] to a live [`Arc<PyBridgeInstance>`].
    ///
    /// Returns an error string if the bridge instance has been dropped.
    /// Callers MUST drop the returned `Arc` before the next `.await` so
    /// they do not pin the instance alive across suspension points.
    fn upgrade_bi(&self) -> Result<std::sync::Arc<crate::runtime::PyBridgeInstance>, String> {
        self.bi.upgrade().ok_or_else(|| {
            "bridge instance has been dropped — MCP provider cannot service request".to_owned()
        })
    }
}

impl ContextProvider for FfiBridgeProvider {
    fn active_context_ids(&self) -> Vec<String> {
        // Configured ∩ live: a context the agent has left is no longer served,
        // so its tools and resources drop out of `tools/list` and
        // `resources/list` without restarting the server (ADR-015 AC7).
        let Ok(bi) = self.upgrade_bi() else {
            return Vec::new();
        };
        self.context_ids
            .iter()
            .filter(|id| {
                crate::runtime::with_context(&bi, id, |rt| {
                    Ok(rt.role_state.members.contains(&self.agent_did))
                })
                .unwrap_or(false)
            })
            .cloned()
            .collect()
    }

    fn agent_role(&self, context_id: &str) -> Option<String> {
        // Look up the agent's role assignment in the context's role state.
        // Silently returns None if the bridge has been dropped — matches the
        // "unknown context" fallback semantics of this trait method.
        let bi = self.upgrade_bi().ok()?;
        crate::runtime::with_context(&bi, context_id, |rt| {
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

    fn context_tools(&self, context_id: &str) -> Vec<ContextOutletInfo> {
        // Returns empty if the bridge has been dropped — matches the
        // "unknown context" fallback semantics of this trait method.
        let Ok(bi) = self.upgrade_bi() else {
            return Vec::new();
        };
        crate::runtime::with_context(&bi, context_id, |rt| {
            let outlets = rt
                .outlet_registry
                .registrations()
                .map(|t| ContextOutletInfo {
                    name: t.name.clone(),
                    description: Some(t.description.clone()),
                    input_schema: t.schema.input_schema.clone(),
                    output_schema: Some(t.schema.output_schema.clone()),
                    admin_only: false,
                    // Carry the registry's authoritative §5.4.2 kind so the
                    // translator surfaces the correct `query.` / `call.` MCP
                    // tool-name prefix. `ContextOutletInfo.kind` is the canonical
                    // `scp_core::context::outlets::OutletKind` (re-exported by
                    // scp-mcp), so this is a direct move — never hardcode Action.
                    kind: t.kind,
                })
                .collect();
            Ok(outlets)
        })
        .unwrap_or_default()
    }

    fn validate_capability(&self, context_id: &str, outlet_name: &str) -> Result<(), String> {
        // Upgrade the bridge instance handle up-front so every check below
        // sees a stable `&PyBridgeInstance`. If the instance has been
        // dropped, fail fast with a deterministic error rather than
        // silently accepting the capability.
        let bi = self.upgrade_bi()?;
        // Primary check: UCAN token validation via the full 11-step ADR-016
        // pipeline. Verifies the token grants the outlet's kind-appropriate stem
        // — outlet_query:{outlet_name}/outlet_query:* for Query outlets,
        // outlet_call:{outlet_name}/outlet_call:* for Action outlets
        // (SCP-OUT-014, §5.4.2) — for this context.
        // See spec §6.2, §8, ADR-016, and issue #319.
        if let Some(ref token) = self.agent_ucan_token {
            // Build proof resolver from optional proof tokens (supports delegated UCANs).
            let proof_resolver =
                crate::ucan::build_proof_resolver_from_tokens(self.agent_proof_tokens.as_deref())
                    .map_err(|e| format!("failed to build proof resolver: {e}"))?;

            crate::runtime::with_context(&bi, context_id, |rt| {
                // SCP-OUT-014: select the split capability stem from the
                // outlet's registered kind — `outlet_query:{id}` for Query
                // outlets, `outlet_call:{id}` for Action outlets.
                let outlet_kind_for_ucan = rt
                    .outlet_registry
                    .get(outlet_name)
                    .map(|r| r.kind)
                    .ok_or_else(|| {
                        ScpPyError::ucan(format!(
                            "outlet '{outlet_name}' not registered in context '{context_id}'"
                        ))
                    })?;

                let production_resolver = crate::runtime::did_resolver(&bi);
                let did_resolver = crate::bridge_adapters::DispatchDidResolver::new(
                    production_resolver.map(std::convert::AsRef::as_ref),
                );
                let revocation_checker = crate::bridge_adapters::BridgeRevocationChecker {
                    revocation_list: &rt.revocation_list,
                };
                let mut nonce_adapter = crate::bridge_adapters::BridgeNonceTracker {
                    inner: &mut rt.nonce_tracker,
                };

                let mut ctx = scp_core::crypto::ucan::validate::ValidationContext {
                    did_resolver: &did_resolver,
                    nonce_tracker: &mut nonce_adapter,
                    revocation_checker: &revocation_checker,
                    proof_resolver: &proof_resolver,
                    ceiling: &rt.ceiling_strings,
                    context_creator_did: &rt.creator_did,
                    presenting_agent_did: &self.agent_did,
                    clock_skew_tolerance_secs:
                        scp_core::crypto::ucan::validate::DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
                    clock: &scp_clock::SystemClock,
                    // §5.4.5 HIGH-3 — outlet-invocation site resolves effective
                    // caveats from each token's `nb` field so §7.3.8 Step 7b
                    // (per-edge narrow) and Step 11b (time-box) run over the
                    // proof chain's VALIDATED-NARROWED caveat set. Generic
                    // validate/evaluate sites (ucan.rs) stay on `NoCaveatResolver`.
                    caveat_resolver: &scp_core::crypto::ucan::validate::TokenNbCaveatResolver,
                };

                scp_core::context::outlets::validate_outlet_invocation_ucan(
                    token,
                    context_id,
                    outlet_name,
                    outlet_kind_for_ucan,
                    &mut ctx,
                )
                .map_err(|e| {
                    tracing::warn!(
                        agent = %self.agent_did,
                        outlet = %outlet_name,
                        context = %context_id,
                        error = %e,
                        "UCAN validation failed for outlet invocation"
                    );
                    ScpPyError::ucan(format!(
                        "UCAN authorization failed for outlet '{outlet_name}': {e}"
                    ))
                })
            })
            .map_err(|e| format!("{e}"))?;
        } else {
            tracing::warn!(
                agent = %self.agent_did,
                outlet = %outlet_name,
                context = %context_id,
                "no UCAN token provided for outlet invocation — authorization bypass risk"
            );
            return Err("UCAN token required for outlet invocation — no token provided".to_owned());
        }

        // Defense-in-depth: check role-state capabilities in addition to the
        // UCAN layer. See §7.2 and ADR-010 for the dual-check design.
        crate::runtime::with_context(&bi, context_id, |rt| {
            // SCP-OUT-014: select the kind-appropriate split stem from the
            // outlet's registered kind — OutletQuery for Query outlets,
            // OutletCall for Action outlets (§5.4.2). The two stems are
            // independent, so a Query grant never authorizes an Action call and
            // vice versa. An outlet absent from the registry defaults to the
            // Action stem (the UCAN gate above already required registration).
            let outlet_kind = rt
                .outlet_registry
                .get(outlet_name)
                .map_or(scp_core::context::outlets::OutletKind::Action, |r| r.kind);
            if scp_core::context::outlets::invoke::has_outlet_invocation_capability(
                &rt.role_state,
                &self.agent_did,
                outlet_name,
                outlet_kind,
            ) {
                Ok(())
            } else {
                // Generic message for the wire — detailed info stays server-side.
                tracing::warn!(
                    agent = %self.agent_did,
                    outlet = %outlet_name,
                    context = %context_id,
                    "capability check failed: agent lacks the required outlet invocation capability"
                );
                Err(ScpPyError::context(
                    "insufficient permissions to invoke outlet",
                ))
            }
        })
        .map_err(|e| format!("{e}"))
    }

    #[allow(clippy::too_many_lines)] // Three-phase dispatch: validate + execute + emit event.
    fn invoke_outlet(
        &self,
        context_id: &str,
        outlet_name: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        // Validates outlet existence and input schema, then dispatches to a
        // registered handler if one exists. If no handler is registered, falls
        // back to echoing the validated input with metadata (schema-only mode).
        //
        // After successful invocation, appends a OutletInvokedEvent to the
        // context's event log per ADR-010 acceptance criterion 3.
        //
        // The handler dispatch is sync because ContextProvider::invoke_outlet is
        // sync and Python handlers are GIL-bound (inherently sync). The async
        // invoke_outlet in scp-core is for contexts where Rust itself executes
        // outlets. See SCP-212, ADR-010, ADR-015.
        //
        // IMPORTANT: The handler Arc and output schema are extracted inside the
        // DashMap shard lock (via with_context), then the lock is released
        // BEFORE calling the handler. This prevents holding the shard lock
        // during Python GIL acquisition, which would block concurrent
        // same-context operations for the duration of the handler. See #122.
        //
        // Handler execution is bounded by `outlet_timeout_ms` to prevent a
        // misbehaving handler from blocking the tokio runtime indefinitely.
        // Uses std::thread::spawn + mpsc::recv_timeout (sync timeout) because
        // ContextProvider::invoke_outlet is a sync trait method. See issue #123.
        //
        // KNOWN LIMITATION — thread leak on timeout: When `recv_timeout`
        // expires, the spawned `std::thread` continues running in the
        // background until the handler returns naturally. Rust threads
        // cannot be forcibly cancelled — there is no `pthread_cancel`
        // equivalent and `JoinHandle` has no `abort()`. The leaked thread
        // holds an `Arc<dyn Fn>` (the handler closure) and, for Python
        // handlers, will hold the GIL until the handler completes. However:
        //
        //   1. No DashMap shard locks are held during handler execution
        //      (two-phase design from #122), so the leaked thread does not
        //      block other context operations.
        //   2. The only contended resource is the Python GIL, which is
        //      released when the handler eventually returns.
        //   3. Cooperative cancellation (e.g., polling a CancellationToken)
        //      would require handler authors to interleave cancellation
        //      checks into their logic — an unreasonable API burden for an
        //      exceptional case.
        //   4. Timeouts are exceptional in well-behaved systems; the default
        //      `outlet_timeout_ms` is generous. Repeated timeouts indicate a
        //      broken handler, not a protocol issue.
        //
        // If this becomes a problem in practice, the mitigation path is
        // process-level isolation (subprocess handlers), not in-process
        // thread cancellation. See PR #170 review discussion.
        let start = std::time::Instant::now();
        let agent_did = self.agent_did.clone();
        let timeout = std::time::Duration::from_millis(self.outlet_timeout_ms);

        // Upgrade the bridge instance handle up-front. `invoke_outlet` is a
        // sync trait method, so the `Arc` we hold here has a well-defined
        // lifetime bounded by this function's return — it cannot survive
        // across an `await` and pin the instance alive (#1549 round-2).
        let bi = self.upgrade_bi()?;

        // Consume a hard-rate-limit token BEFORE dispatching the MCP
        // outlet invocation. This path — reachable from external MCP
        // clients — does not go through
        // `ContextManager::invoke_outlet_with_economy`; it dispatches
        // directly against the bridge-side outlet registry, so without
        // this hook an external client could burn relay capacity
        // regardless of the per-context rate limit.
        //
        // This trait method is sync but its callers vary:
        //   (a) `py_mcp_serve` stdio loop → `rt.spawn(async move …)`
        //       on either a multi-thread or current-thread runtime.
        //   (b) SSE async handler → multi-thread runtime.
        //   (c) Sync `#[test]` tests → no runtime.
        //
        // `try_consume_hard_rate_limit_from_any_context` dispatches
        // internally between `blocking_lock`, `block_in_place +
        // block_on`, or a dedicated `std::thread` with its own tiny
        // runtime depending on which regime the caller is in.
        let invoker_did_typed: scp_did::DID = agent_did.clone().into();
        let now_secs = scp_clock::Clock::now_secs(&scp_clock::SystemClock);
        let supervisor = crate::runtime::supervisor(&bi).map_err(|e| format!("{e}"))?;
        if !supervisor.try_consume_hard_rate_limit_from_any_context(
            context_id,
            &invoker_did_typed,
            now_secs,
        ) {
            return Err("SCP-ECON-12090: rate limit exceeded on outlet_invoke: \
                        hard rate limit exceeded for invoker"
                .to_owned());
        }
        // Helper that refunds the token on any failure path. Used by
        // every `return Err` below. Same runtime-agnostic dispatch
        // as the consume call above.
        let ctx_id_for_refund = context_id.to_owned();
        let refund = |e: String| -> String {
            supervisor
                .refund_hard_rate_limit_from_any_context(&ctx_id_for_refund, &invoker_did_typed);
            e
        };

        // Phase 1: Validate input and extract handler + output schema under
        // the DashMap shard lock. The lock is released when with_context
        // returns. Also compute input hash before dispatch (arguments may
        // be consumed by the handler).
        let (dispatch, input_hash) = crate::runtime::with_context(&bi, context_id, |rt| {
            let registration = rt.outlet_registry.get(outlet_name).ok_or_else(|| {
                ScpPyError::context(format!(
                    "outlet '{outlet_name}' not found in context '{context_id}'"
                ))
            })?;

            // Validate input against the outlet's input schema.
            scp_core::context::outlets::schema::validate_value_against_schema(
                &arguments,
                &registration.schema.input_schema,
            )
            .map_err(|msg| {
                ScpPyError::validation(format!(
                    "input validation failed for outlet '{outlet_name}': {msg}"
                ))
            })?;

            // Clone handler Arc and output schema so we can release the lock.
            // Compute input hash before dispatch (arguments may be consumed).
            let input_hash = scp_core::context::outlets::sha256_json(&arguments);

            Ok((
                rt.outlet_handlers
                    .get(outlet_name)
                    .map(|handler| (handler.clone(), registration.schema.output_schema.clone())),
                input_hash,
            ))
        })
        .map_err(|e| refund(format!("{e}")))?;

        // Phase 2: Execute handler OUTSIDE the DashMap shard lock so that
        // concurrent same-context operations are not blocked during Python
        // GIL acquisition and handler execution. Handler execution is
        // bounded by `outlet_timeout_ms` (issue #123).
        let output = match dispatch {
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
                    refund(format!(
                        "outlet handler for '{outlet_name}' timed out after {}ms",
                        timeout.as_millis()
                    ))
                })?;

                let output = handler_result.map_err(|e| {
                    refund(format!("outlet handler for '{outlet_name}' failed: {e}"))
                })?;

                // Validate output against the outlet's output schema (defense-in-depth).
                scp_core::context::outlets::schema::validate_value_against_schema(
                    &output,
                    &output_schema,
                )
                .map_err(|msg| {
                    refund(format!(
                        "output validation failed for outlet '{outlet_name}': {msg}"
                    ))
                })?;

                output
            }
            None => {
                // No handler registered -- fall back to echo mode.
                serde_json::json!({
                    "outlet": outlet_name,
                    "context": context_id,
                    "status": "validated",
                    "input_valid": true,
                    "validated_input": arguments,
                })
            }
        };

        // Phase 3: Append OutletInvokedEvent to the event log (ADR-010
        // criterion 3).
        //
        // SECURITY: unsigned event — uses `append_unsigned_event` because
        // `KeyCustody::sign()` is async and we are inside the tokio runtime
        // (block_on would panic). The event is chain-validated and Merkle-
        // committed but carries an empty signature. A compromised in-process
        // caller could inject fake OutletInvokedEvent entries. Migrate to signed
        // events via `append` once async FFI signing lands (SCP-214).
        // See: crates/scp-core/src/event_log/tree.rs::append_unsigned_event
        // See: .docs/lessons/unsigned-event-mcp-bridge.md
        #[allow(clippy::cast_possible_truncation)]
        let elapsed_ms = {
            let millis = start.elapsed().as_millis();
            if millis > u128::from(u64::MAX) {
                u64::MAX
            } else {
                millis as u64
            }
        };

        let output_hash = scp_core::context::outlets::sha256_json(&output);

        let outlet_event = scp_core::context::outlets::OutletInvokedEvent {
            request_id: uuid::Uuid::new_v4().to_string(),
            outlet_id: outlet_name.to_owned(),
            invoker_did: agent_did.clone().into(),
            status: scp_core::context::outlets::OutletStatus::Success,
            execution_time_ms: elapsed_ms,
            input_hash,
            output_hash: Some(output_hash),
            cost: None,
            // Non-streaming bridge invocation: degenerate/no-manifest
            // streaming-field defaults matching the lifecycle serde defaults.
            stream_chunk_count: 0,
            chunks_billed: 0,
            stream_manifest_hash: [0u8; 32],
            stream_terminal_status: scp_core::context::outlets::stream::StreamTerminalStatus::Ok,
            cancel_ack_seq: None,
            audit_anomaly: None,
        };

        let payload_data = serde_json::to_vec(&outlet_event).unwrap_or_default();

        let timestamp = scp_clock::Clock::now_secs(&scp_clock::SystemClock);

        // Re-acquire the DashMap lock briefly to append the event.
        // Returns (sequence, serialized_event_bytes) on success for
        // ProtocolRepository persistence (GitHub issue #303).
        let append_result = crate::runtime::with_context(&bi, context_id, |rt| {
            let sequence = scp_event_log::tree::event_count(&rt.event_log);
            let prev_hash = if rt.event_log.leaves().is_empty() {
                scp_event_log::tree::GENESIS_PREV_HASH
            } else {
                rt.event_log.leaves()[rt.event_log.leaves().len() - 1]
            };

            let event = scp_event_log::Event {
                event_type: scp_event_log::EventType::OutletInvoked,
                actor_did: agent_did.into(),
                timestamp,
                sequence,
                payload: scp_event_log::EventPayload {
                    data: payload_data.clone(),
                },
                prev_hash,
                signature: Vec::new(),
            };

            // Serialize the event for ProtocolRepository persistence.
            let event_bytes = rmp_serde::to_vec(&event)
                .map_err(|e| ScpPyError::context(format!("event serialization failed: {e}")))?;

            scp_event_log::tree::append_unsigned_event(&mut rt.event_log, &event)
                .map_err(|e| ScpPyError::context(e.to_string()))?;

            // Return the leaf hash (last appended leaf) for ProtocolRepository.
            let leaf_hash: [u8; 32] = rt.event_log.leaves()[rt.event_log.leaves().len() - 1];

            Ok((sequence, event_bytes, leaf_hash))
        });

        match append_result {
            Ok((sequence, event_bytes, _leaf_hash)) => {
                // Persist the event payload to storage (best-effort).
                // This enables py_event_log_query to return real events
                // instead of just a LogSummary (GitHub issue #303).
                //
                // Uses the Storage trait directly because the global storage
                // is Arc<EncryptingAdapter<InMemoryStorage>> and ProtocolRepository
                // requires an owned Storage impl. The key convention matches
                // ProtocolRepository's event_data_key format.
                if let Ok(storage) = crate::runtime::get_storage(&bi)
                    && let Ok(rt) = crate::runtime()
                {
                    let key = format!("context/{context_id}/event_data/{sequence:020}");
                    if let Err(e) = rt.block_on(storage.store(&key, &event_bytes)) {
                        tracing::warn!(
                            outlet = %outlet_name,
                            context = %context_id,
                            error = %e,
                            "failed to persist event payload to storage"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    outlet = %outlet_name,
                    context = %context_id,
                    error = %e,
                    "failed to append OutletInvokedEvent to event log"
                );
            }
        }

        Ok(output)
    }

    fn validate_resource_access(
        &self,
        context_id: &str,
        resource: scp_mcp::server::ResourceKind,
    ) -> Result<(), String> {
        use scp_core::context::roles::Capability;
        use scp_mcp::server::ResourceKind;

        let bi = self.upgrade_bi()?;
        crate::runtime::with_context(&bi, context_id, |rt| {
            // `Events` and `Members` require `messages:read`: per spec §5.3.1's
            // role table an `observer` — whose sole capability is
            // `messages:read` — "can see all content and membership", so that
            // grant is exactly the authority to read the event stream and the
            // roster.
            //
            // `Tools` carries no separate grant because its contents are the
            // capability-filtered tool list; an agent with no tool capabilities
            // reads `[]` rather than being denied. This is deliberately NOT a
            // `validate_capability("resource:tools")` call — that name resolves
            // to `Capability::Custom("resource:tools")`, which appears in no
            // ceiling and no role catalogue, so gating on it denied every
            // client on every bridge unconditionally.
            let permitted = match resource {
                ResourceKind::Events | ResourceKind::Members => rt
                    .role_state
                    .member_has_capability(&self.agent_did, &Capability::MessagesRead),
                ResourceKind::Tools => rt.role_state.members.contains(&self.agent_did),
            };
            if permitted {
                Ok(())
            } else {
                Err(ScpPyError::context(format!(
                    "agent lacks messages:read in context '{context_id}' — required to read \
                     scp://{context_id}/{}",
                    resource.uri_suffix()
                )))
            }
        })
        .map_err(|e| format!("{e}"))
    }

    fn context_members(&self, context_id: &str) -> Vec<MemberInfo> {
        // Returns empty if the bridge has been dropped — matches the
        // "unknown context" fallback semantics of this trait method.
        let Ok(bi) = self.upgrade_bi() else {
            return Vec::new();
        };
        crate::runtime::with_context(&bi, context_id, |rt| {
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
        // Falls back to zero-count JSON if the bridge has been dropped.
        let Ok(bi) = self.upgrade_bi() else {
            return serde_json::json!({ "event_count": 0 });
        };
        crate::runtime::with_context(&bi, context_id, |rt| {
            let leaf_count = rt.event_log.leaves().len();
            let root = scp_event_log::tree::root(&rt.event_log);
            Ok(serde_json::json!({
                "event_count": leaf_count,
                "merkle_root": crate::types::encode_hex(&root),
            }))
        })
        .unwrap_or_else(|_| serde_json::json!({ "event_count": 0 }))
    }
}

// ---------------------------------------------------------------------------
// MCP handle registries
// ---------------------------------------------------------------------------

/// State for an active MCP server instance.
pub(crate) struct McpServerState {
    /// The identity DID running this server.
    identity_did: String,
    /// The context IDs being served.
    context_ids: Vec<String>,
    /// The transport mode (stdio or sse).
    transport: String,
    /// Whether the server has been stopped.
    stopped: bool,
    /// Shutdown signal sender. Dropping this signals the transport task to stop.
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// Handle to the tokio task running the transport. Used by `server_wait`.
    task_handle: Option<tokio::task::JoinHandle<()>>,
}

/// State for an active MCP client connection.
pub(crate) struct McpClientState {
    /// The transport mode (stdio or sse).
    transport: String,
    /// For stdio, the command used to spawn the subprocess.
    command: Option<Vec<String>>,
    /// For sse, the URL of the SSE endpoint.
    url: Option<String>,
    /// The real MCP client, connected and initialized.
    client: Arc<Mutex<McpClient<ClientTransport, SystemTimestamp>>>,
}

// Phase D (#1695): `server_registry()` / `client_registry()` default-bridge
// shims and their `EMPTY_*_REGISTRY` fallback statics have been deleted.
// Callers must use the per-instance `server_registry_of(bi)` /
// `client_registry_of(bi)` accessors.

/// Returns a reference to the given bridge instance's MCP server registry.
fn server_registry_of(bi: &crate::runtime::PyBridgeInstance) -> &DashMap<String, McpServerState> {
    bi.mcp_server_registry().as_ref()
}

/// Returns a reference to the given bridge instance's MCP client registry.
fn client_registry_of(bi: &crate::runtime::PyBridgeInstance) -> &DashMap<String, McpClientState> {
    bi.mcp_client_registry().as_ref()
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

/// Starts an MCP server that exposes SCP context outlets.
///
/// Creates an MCP server backed by a `FfiBridgeProvider` that reads outlets
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
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_serve", signature = (identity_did, context_ids, transport, ucan_token=None))]
    #[allow(clippy::needless_pass_by_value)] // PyO3 requires owned Vec for method arguments.
    #[allow(clippy::too_many_lines)] // MCP server startup with stdio/SSE transport dispatch is inherently verbose.
    pub fn py_mcp_serve(
        &self,
        identity_did: &str,
        context_ids: Vec<String>,
        transport: &str,
        ucan_token: Option<String>,
    ) -> PyResult<String> {
        let bi = &*self.inner;
        let bi_arc = Arc::clone(&self.inner);
        validate::validate_did(identity_did)?;
        validate::validate_transport_mode(transport)?;
        for ctx_id in &context_ids {
            validate::validate_context_id(ctx_id)?;
        }

        // Validate that all context IDs are registered in the runtime.
        for ctx_id in &context_ids {
            crate::runtime::with_context(bi, ctx_id, |_rt| Ok(())).map_err(|e| {
                ScpPyError::transport(format!("cannot serve context '{ctx_id}': {e}"))
            })?;
        }

        // Create the FfiBridgeProvider and McpServer.
        //
        // #1549 round-2: hold the bridge instance as a `Weak`, not an
        // `Arc`. The MCP server task is spawned on the shared tokio
        // runtime (`rt.spawn(...)`) and is NOT enrolled in the
        // per-instance `JoinSet`, so an `Arc` would leak the
        // `PyBridgeInstance` (and with it `ContextManager`, identity
        // registry, relay connection) for the remainder of the process
        // when the caller drops `PyScp` without calling
        // `py_mcp_server_stop`. The task body additionally selects on
        // the instance's `cancel_token` so `emergency_cancel_tasks()`
        // from `Drop` can wake it between requests.
        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi_arc),
            agent_did: identity_did.to_owned(),
            context_ids: context_ids.clone(),
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: ucan_token,

            agent_proof_tokens: None,
        };

        // Create a shutdown channel.
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        // Start the transport task on the tokio runtime.
        let rt = crate::runtime()?;
        let transport_mode = transport.to_owned();
        // Capture the cancel token so the server task exits when the
        // instance is dropped, even if the caller never calls
        // `py_mcp_server_stop`. Cloning a `CancellationToken` does not
        // extend the instance's lifetime.
        let cancel_token = bi_arc.core.cancel_token();

        // Resource subscriptions are backed by the supervisor's context event
        // broadcast channel. Subscribe *before* spawning so no event emitted
        // between here and the transport loop starting is missed.
        //
        // `subscribe_events()` returns `None` only for a supervisor built
        // without the channel; production supervisors always enable it (see
        // `crate::runtime::build_supervisor`). When it is `None` the transport
        // advertises `resources.subscribe: false` and rejects
        // `resources/subscribe` — the capability is honestly absent rather
        // than accepted-and-never-delivered.
        // Absence degrades only this capability: the server still serves
        // `tools/*` and `resources/list|read`, and honestly advertises
        // `resources.subscribe: false`. Serving is NOT failed outright — that
        // would deny working functionality over an optional feature.
        let context_events = match crate::runtime::supervisor(bi) {
            Ok(supervisor) => supervisor.subscribe_events(),
            Err(e) => {
                tracing::warn!("MCP server: no supervisor attached ({e})");
                None
            }
        };
        if context_events.is_none() {
            tracing::warn!(
                "MCP server: no context event source — resource subscriptions \
                 will be advertised as unsupported and rejected if requested"
            );
        }

        // One call decides both halves: the server that advertises
        // `resources.subscribe` and the pump that honours it. There is no
        // setter that could desynchronize them, and only one server is built
        // per serve call — two servers over one event source would each
        // advertise subscriptions while only one had the pump.
        let (server, pump) = McpServer::with_optional_event_source(provider, context_events);

        let task_handle = rt.spawn(async move {
            match transport_mode.as_str() {
                "stdio" => {
                    let server = Arc::new(Mutex::new(server));
                    // Run the MCP server over stdio via the shared
                    // `scp_mcp::stdio::run_stdio` loop. It owns stdout so the
                    // response writer and the resource-subscription event pump
                    // interleave as whole lines, and it parses JSON-RPC
                    // notifications correctly (a bare `JsonRpcRequest` decode
                    // rejects them — they carry no `id`).
                    //
                    // We also listen for the shutdown signal AND the bridge
                    // instance's cancel token so `emergency_cancel_tasks()`
                    // from the instance's `Drop` impl can terminate this task
                    // even when the caller never invoked `py_mcp_server_stop`.
                    tokio::select! {
                        _ = shutdown_rx => {
                            // Shutdown signal received -- exit cleanly.
                        }
                        () = cancel_token.cancelled() => {
                            tracing::debug!(
                                "MCP stdio server task exiting — bridge instance cancelled"
                            );
                        }
                        result = scp_mcp::stdio::run_stdio(&server, pump) => {
                            if let Err(e) = result {
                                tracing::error!("MCP stdio server error: {e}");
                            }
                        }
                    }
                }
                "sse" => {
                    // `run_sse` takes ownership of the `McpServer` directly —
                    // no mutex wrapper, since the SSE transport owns it.
                    let config = scp_mcp::sse::SseConfig::new(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        0,
                    )));

                    // Create a ShutdownHandle for the SSE server. Wire both
                    // the oneshot shutdown_rx (py_mcp_server_stop) AND the
                    // bridge instance's cancel_token (emergency_cancel_tasks
                    // from Drop) so either signal tears down the SSE server.
                    // Without the cancel_token branch, a caller that drops
                    // `PyScp` without calling `py_mcp_server_stop` would
                    // leave this task running indefinitely and pin
                    // `PyBridgeInstance` state alive via the
                    // `McpServer`-held resources (#1549 round-2).
                    let sse_shutdown = scp_mcp::sse::ShutdownHandle::new();
                    let sse_shutdown_trigger = sse_shutdown.clone();
                    tokio::spawn(async move {
                        tokio::select! {
                            _ = shutdown_rx => {}
                            () = cancel_token.cancelled() => {}
                        }
                        sse_shutdown_trigger.shutdown();
                    });

                    let result = scp_mcp::sse::run_sse(server, config, sse_shutdown, pump).await;
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
            shutdown_tx: Some(shutdown_tx),
            task_handle: Some(task_handle),
        };

        server_registry_of(bi).insert(handle.clone(), state);

        Ok(handle)
    }
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
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_server_stop")]
    pub fn py_mcp_server_stop(&self, handle: &str) -> PyResult<()> {
        let bi = &*self.inner;
        validate::validate_mcp_handle(handle)?;
        let mut entry = server_registry_of(bi).get_mut(handle).ok_or_else(|| {
            ScpPyError::transport(format!("MCP server handle '{handle}' not found"))
        })?;

        if entry.stopped {
            return Err(
                ScpPyError::transport(format!("MCP server '{handle}' is already stopped")).into(),
            );
        }

        entry.stopped = true;

        // Send the shutdown signal. Dropping the sender signals the receiver.
        if let Some(tx) = entry.shutdown_tx.take() {
            let _ = tx.send(());
        }
        drop(entry);

        Ok(())
    }
}

/// Blocks until the MCP server exits.
///
/// For stdio transport, waits until stdin is closed (EOF) or the server is
/// stopped via `py_mcp_server_stop`. For SSE transport, waits until the
/// HTTP server is terminated.
///
/// # Arguments
///
/// * `handle` -- The server handle returned by `py_mcp_serve`.
///
/// # Errors
///
/// Raises `TransportError` if the server handle is not found.
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_server_wait")]
    pub fn py_mcp_server_wait(&self, py: Python<'_>, handle: &str) -> PyResult<()> {
        let bi = &*self.inner;
        validate::validate_mcp_handle(handle)?;
        // Extract the task handle if available.
        let task_handle = {
            let mut entry = server_registry_of(bi).get_mut(handle).ok_or_else(|| {
                ScpPyError::transport(format!("MCP server handle '{handle}' not found"))
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
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_server_info")]
    pub fn py_mcp_server_info(&self, py: Python<'_>, handle: &str) -> PyResult<PyObject> {
        let bi = &*self.inner;
        validate::validate_mcp_handle(handle)?;
        let entry = server_registry_of(bi).get(handle).ok_or_else(|| {
            ScpPyError::transport(format!("MCP server handle '{handle}' not found"))
        })?;

        let dict = PyDict::new(py);
        dict.set_item("identity_did", &entry.identity_did)?;
        dict.set_item("context_ids", &entry.context_ids)?;
        dict.set_item("transport", &entry.transport)?;
        dict.set_item("stopped", entry.stopped)?;
        drop(entry);
        Ok(dict.into())
    }
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
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_client_info")]
    pub fn py_mcp_client_info(&self, py: Python<'_>, handle: &str) -> PyResult<PyObject> {
        let bi = &*self.inner;
        validate::validate_mcp_handle(handle)?;
        let entry = client_registry_of(bi).get(handle).ok_or_else(|| {
            ScpPyError::transport(format!("MCP client handle '{handle}' not found"))
        })?;

        let dict = PyDict::new(py);
        dict.set_item("transport", &entry.transport)?;
        dict.set_item("command", &entry.command)?;
        dict.set_item("url", &entry.url)?;
        drop(entry);
        Ok(dict.into())
    }
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
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_client_connect_stdio")]
    #[allow(clippy::needless_pass_by_value)] // PyO3 requires owned Vec for method arguments.
    pub fn py_mcp_client_connect_stdio(&self, command: Vec<String>) -> PyResult<String> {
        let bi = &*self.inner;
        if command.is_empty() {
            return Err(
                ScpPyError::validation("command must be a non-empty list".to_owned()).into(),
            );
        }

        // Spawn the subprocess and create the transport. Allowlist is
        // per-instance (lives on `CoreFields::mcp_allowlist`).
        let transport = StdioClientTransport::spawn(bi.core.mcp_allowlist(), &command)
            .map_err(|e| ScpPyError::transport(format!("failed to connect stdio client: {e}")))?;

        // Create the MCP client and perform the initialize handshake.
        let mut client = McpClient::new(ClientTransport::Stdio(transport));
        client
            .initialize()
            .map_err(|e| ScpPyError::transport(format!("MCP initialize handshake failed: {e}")))?;

        let handle = generate_handle_id("mcp-client");
        let state = McpClientState {
            transport: "stdio".to_owned(),
            command: Some(command),
            url: None,

            client: Arc::new(Mutex::new(client)),
        };

        client_registry_of(bi).insert(handle.clone(), state);

        Ok(handle)
    }
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
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_client_connect_sse")]
    pub fn py_mcp_client_connect_sse(&self, url: &str) -> PyResult<String> {
        let bi = &*self.inner;
        validate::validate_relay_url(url)?;

        // Connect to the SSE endpoint.
        let transport = SseClientTransport::connect(url)
            .map_err(|e| ScpPyError::transport(format!("failed to connect SSE client: {e}")))?;

        // Create the MCP client and perform the initialize handshake.
        let mut client = McpClient::new(ClientTransport::Sse(transport));
        client
            .initialize()
            .map_err(|e| ScpPyError::transport(format!("MCP initialize handshake failed: {e}")))?;

        let handle = generate_handle_id("mcp-client");
        let state = McpClientState {
            transport: "sse".to_owned(),
            command: None,
            url: Some(url.to_owned()),

            client: Arc::new(Mutex::new(client)),
        };

        client_registry_of(bi).insert(handle.clone(), state);

        Ok(handle)
    }
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
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_client_disconnect")]
    pub fn py_mcp_client_disconnect(&self, handle: &str) -> PyResult<()> {
        let bi = &*self.inner;
        validate::validate_mcp_handle(handle)?;
        let (_, state) = client_registry_of(bi).remove(handle).ok_or_else(|| {
            ScpPyError::transport(format!("MCP client handle '{handle}' not found"))
        })?;

        // Dropping `state` drops the Arc<Mutex<McpClient>>, which drops the
        // McpClient, which drops the ClientTransport. For stdio transports,
        // the Drop impl on StdioClientTransport kills and waits on the
        // subprocess, preventing resource leaks.
        drop(state);

        Ok(())
    }
}

/// Lists available outlets from an external MCP server.
///
/// Sends a `tools/list` JSON-RPC request to the connected MCP server and
/// returns the outlet definitions as a list of Python dicts.
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
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_client_list_tools")]
    pub fn py_mcp_client_list_tools(&self, py: Python<'_>, handle: &str) -> PyResult<PyObject> {
        let bi = &*self.inner;
        validate::validate_mcp_handle(handle)?;
        let entry = client_registry_of(bi).get(handle).ok_or_else(|| {
            ScpPyError::transport(format!("MCP client handle '{handle}' not found"))
        })?;

        // Send the real tools/list request via the MCP client.
        let client = Arc::clone(&entry.client);
        drop(entry); // Release the DashMap guard before blocking.

        let outlets = {
            let client_guard = client
                .lock()
                .map_err(|e| ScpPyError::transport(format!("client lock poisoned: {e}")))?;
            client_guard
                .list_tools()
                .map_err(|e| ScpPyError::transport(format!("tools/list failed: {e}")))?
        };

        // Convert outlet definitions to JSON array for Python.
        let outlets_json: Vec<serde_json::Value> = outlets
            .iter()
            .map(|t| {
                serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.input_schema,
                })
            })
            .collect();

        json_to_py_dict(py, &serde_json::Value::Array(outlets_json))
    }
}

/// Invokes an external MCP outlet with SCP provenance wrapping.
///
/// Sends a `tools/call` JSON-RPC request to the external MCP server and
/// wraps the result with provenance metadata recording the source outlet,
/// invoking agent, context, and timestamp.
///
/// # Arguments
///
/// * `handle` -- The client handle returned by `py_mcp_client_connect_*`.
/// * `outlet_name` -- The name of the external outlet to invoke.
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
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_client_invoke")]
    pub fn py_mcp_client_invoke(
        &self,
        py: Python<'_>,
        handle: &str,
        outlet_name: &str,
        input: &Bound<'_, PyDict>,
        context_id: &str,
        identity_did: &str,
    ) -> PyResult<PyObject> {
        let bi = &*self.inner;
        validate::validate_mcp_handle(handle)?;
        validate::validate_outlet_name(outlet_name)?;
        validate::validate_context_id(context_id)?;
        validate::validate_did(identity_did)?;
        let entry = client_registry_of(bi).get(handle).ok_or_else(|| {
            ScpPyError::transport(format!("MCP client handle '{handle}' not found"))
        })?;

        let client = Arc::clone(&entry.client);
        drop(entry); // Release the DashMap guard before Python object access.

        // Convert input to JSON.
        let input_json = py_dict_to_json(input)?;

        // Send the real tools/call request via the MCP client.
        let result = {
            let client_guard = client
                .lock()
                .map_err(|e| ScpPyError::transport(format!("client lock poisoned: {e}")))?;
            client_guard
                .invoke(outlet_name, input_json, context_id, identity_did)
                .map_err(|e| ScpPyError::transport(format!("tools/call failed: {e}")))?
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
/// - `outlet_count` -- Number of registered outlets (if available from runtime).
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
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_load_contexts")]
    pub fn py_mcp_load_contexts(
        &self,
        py: Python<'_>,
        identity_did: &str,
        _relay_url: &str,
    ) -> PyResult<Vec<PyObject>> {
        let bi = &*self.inner;
        validate::validate_did(identity_did)?;
        // Step 1: Collect contexts from the local runtime registry.
        let local_context_ids = crate::runtime::context_ids_for_member(bi, identity_did);

        // Step 2: Collect contexts from the known-contexts registry.
        let known = crate::runtime::known_contexts_for_member_on(bi, identity_did);

        // Step 3: Probe relay for known routing IDs (if connected).
        let relay_active_set = probe_relay_for_known_contexts(bi, &known);

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
            if let Ok(info) = crate::runtime::with_context(bi, ctx_id, |rt| {
                Ok((
                    rt.creator_did.clone(),
                    rt.role_state.members.len(),
                    rt.outlet_registry.len(),
                ))
            }) {
                dict.set_item("creator_did", info.0)?;
                dict.set_item("member_count", info.1)?;
                dict.set_item("outlet_count", info.2)?;
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
    bi: &crate::runtime::PyBridgeInstance,
    known: &[(String, crate::runtime::KnownContext)],
) -> std::collections::HashSet<String> {
    use scp_transport::traits::RoutingId;

    let mut active = std::collections::HashSet::new();

    if known.is_empty() {
        return active;
    }

    // Check if a transport manager is available. If not, return empty set.
    if !crate::runtime::has_transport_manager(bi) {
        return active;
    }

    // Get the tokio runtime for blocking on async queries.
    let Ok(rt) = crate::runtime() else {
        return active;
    };

    // Probe each known context's routing ID on the relay via the
    // TransportManager. Uses manager.query() which delegates to the
    // first adapter (Phase 1 single-adapter mode).
    for (ctx_id, known_ctx) in known {
        let routing_id = RoutingId::new(known_ctx.routing_id);
        let query_result = crate::runtime::with_transport_manager(bi, |manager| {
            rt.block_on(manager.query(&routing_id, None)).map_err(|e| {
                crate::error::ScpPyError::transport(format!("relay probe failed: {e}"))
            })
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
///
/// Mutex poisoning is NOT modelled by `AllowlistError` — the allowlist
/// type is now per-instance and the mutex lives on `CoreFields`. Each call
/// site maps `PoisonError` to its own typed transport error before calling
/// into the allowlist.
// `clippy::match_same_arms` — the explicit wildcard arm at the end is intentional:
// `AllowlistError` is `#[non_exhaustive]`, so future variants must compile, and
// classifying them as a validation error fails closed. Folding the wildcard into
// the named OR-chain would erase that documentation.
#[allow(clippy::needless_pass_by_value, clippy::match_same_arms)]
fn allowlist_err(e: allowlist::AllowlistError) -> ScpPyError {
    use scp_mcp::allowlist::AllowlistError;
    let msg = e.to_string();
    match e {
        AllowlistError::EmptyEntry
        | AllowlistError::PathInEntry(_)
        | AllowlistError::NulInEntry(_)
        | AllowlistError::ControlCharInEntry(_)
        | AllowlistError::PathInCommand(_)
        | AllowlistError::InvalidCommand(_) => ScpPyError::ValidationError {
            message: msg,
            code: codes::VALID_7033.to_owned(),
        },
        AllowlistError::NotAllowed { .. } => ScpPyError::TransportError {
            message: msg,
            code: codes::TRANS_5030.to_owned(),
        },
        // `AllowlistError` is `#[non_exhaustive]` — fail closed for any
        // future variant by classifying as a validation error so an unknown
        // policy decision can never silently turn into a permissive
        // transport-success path.
        _ => ScpPyError::ValidationError {
            message: msg,
            code: codes::VALID_7033.to_owned(),
        },
    }
}

// ---------------------------------------------------------------------------
// Stdio allowlist configuration (PyO3, per-instance)
// ---------------------------------------------------------------------------

/// Maps a `PoisonError` from the per-instance allowlist mutex to a
/// transport-level [`ScpPyError`]. Uses `SCP-TRANS-5030` for cross-bridge
/// parity with NAPI / `UniFFI` — same code, same semantics, regardless of SDK.
fn allowlist_lock_poisoned() -> ScpPyError {
    ScpPyError::TransportError {
        message: "stdio allowlist lock poisoned".to_owned(),
        code: codes::TRANS_5030.to_owned(),
    }
}

/// Per-instance MCP stdio allowlist methods on [`PyScp`].
///
/// The allowlist is owned by `CoreFields::mcp_allowlist` (one per bridge
/// instance) — disabling enforcement on one `SCP` does not leak into another.
#[pymethods]
impl crate::scp::PyScp {
    /// Configures this instance's MCP stdio subprocess allowlist.
    ///
    /// By default, only well-known MCP server launchers are permitted (e.g.
    /// `uvx`, `npx`, `node`, `python3`). Call this method to extend the
    /// per-instance allow set.
    ///
    /// # Arguments
    ///
    /// * `additional_binaries` -- Binary basenames to add to the allowlist.
    ///
    /// # Errors
    ///
    /// Raises `ValidationError` if any entry is invalid (path, NUL, empty).
    /// Raises `TransportError` if the allowlist lock is poisoned.
    #[pyo3(name = "mcp_configure_stdio_allowlist", signature = (additional_binaries=vec![]))]
    #[allow(clippy::needless_pass_by_value)] // PyO3 requires owned Vec for method arguments.
    pub fn mcp_configure_stdio_allowlist(&self, additional_binaries: Vec<String>) -> PyResult<()> {
        let instance_id = self.inner.core.instance_id();
        self.inner
            .core
            .with_mcp_allowlist(|a| a.configure(&additional_binaries))
            .map_err(|_| allowlist_lock_poisoned())?
            .map_err(allowlist_err)?;
        tracing::info!(
            instance_id,
            added = ?additional_binaries,
            "MCP stdio allowlist extended"
        );
        Ok(())
    }

    /// Disable this instance's stdio allowlist entirely (unrestricted mode).
    ///
    /// # Safety
    ///
    /// This allows **any** binary to be spawned as a subprocess by THIS
    /// instance. Other `SCP` instances are unaffected. Only use when the
    /// command source is fully trusted.
    ///
    /// # Errors
    ///
    /// Raises `TransportError` if the allowlist lock is poisoned.
    #[pyo3(name = "mcp_disable_stdio_allowlist")]
    pub fn mcp_disable_stdio_allowlist(&self) -> PyResult<()> {
        let instance_id = self.inner.core.instance_id();
        self.inner
            .core
            .with_mcp_allowlist(|a| a.disable_enforcement(instance_id))
            .map_err(|_| allowlist_lock_poisoned())?;
        Ok(())
    }

    /// Reset this instance's stdio allowlist to its default state.
    ///
    /// Restores the default binaries and re-enables allowlist enforcement
    /// (clears unrestricted mode) for THIS instance only.
    ///
    /// # Errors
    ///
    /// Raises `TransportError` if the allowlist lock is poisoned.
    #[pyo3(name = "mcp_reset_stdio_allowlist")]
    pub fn mcp_reset_stdio_allowlist(&self) -> PyResult<()> {
        let instance_id = self.inner.core.instance_id();
        self.inner
            .core
            .with_mcp_allowlist(scp_mcp::allowlist::StdioAllowlist::reset)
            .map_err(|_| allowlist_lock_poisoned())?;
        tracing::info!(instance_id, "MCP stdio allowlist reset to defaults");
        Ok(())
    }

    /// Return the current stdio allowlist state for this instance.
    ///
    /// Returns a Python dict with keys:
    /// - `"allowed"`: sorted list of allowed binary names
    /// - `"unrestricted"`: bool indicating whether the allowlist is bypassed
    ///
    /// # Errors
    ///
    /// Raises `TransportError` if the allowlist lock is poisoned.
    #[pyo3(name = "mcp_get_stdio_allowlist")]
    pub fn mcp_get_stdio_allowlist(&self, py: Python<'_>) -> PyResult<PyObject> {
        let state = self
            .inner
            .core
            .with_mcp_allowlist(|a| a.snapshot())
            .map_err(|_| allowlist_lock_poisoned())?;

        let dict = PyDict::new(py);
        dict.set_item("allowed", state.allowed)?;
        dict.set_item("unrestricted", state.unrestricted)?;
        Ok(dict.into())
    }
}

// ---------------------------------------------------------------------------
// Outlet handler registration
// ---------------------------------------------------------------------------

/// Registers a Python callable as the handler for an outlet in a context.
///
/// The handler is called when the outlet is invoked via MCP
/// (`FfiBridgeProvider::invoke_outlet`). It receives the outlet's validated
/// JSON input as a Python dict and must return a Python dict representing
/// the JSON output.
///
/// The outlet must already be registered in the context's outlet registry
/// (via `py_outlet_register`) before a handler can be attached.
///
/// # Arguments
///
/// * `context_id` -- The context containing the outlet.
/// * `outlet_name` -- The outlet ID to attach the handler to.
/// * `handler` -- A Python callable `(dict) -> dict`.
///
/// # Errors
///
/// Raises `ContextError` if the context or outlet is not found.
///
/// See SCP-212 and ADR-010 for the handler registration design.
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "mcp_register_outlet_handler")]
    #[allow(clippy::needless_pass_by_value)] // PyObject must be owned to clone_ref into the closure.
    pub fn py_register_outlet_handler(
        &self,
        py: Python<'_>,
        context_id: &str,
        outlet_name: &str,
        handler: PyObject,
    ) -> PyResult<()> {
        let bi = &*self.inner;
        validate::validate_context_id(context_id)?;
        validate::validate_outlet_name(outlet_name)?;
        // Verify the handler is callable before storing it.
        if !handler.bind(py).is_callable() {
            return Err(ScpPyError::validation("handler must be callable".to_owned()).into());
        }

        // Wrap the Python callable in a Rust closure that acquires the GIL,
        // converts JSON -> Python dict, calls the handler, and converts back.
        let handler_ref = handler.clone_ref(py);
        let rust_handler: crate::runtime::OutletHandler =
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
                        .map_err(|_| "outlet handler must return a dict".to_owned())?;
                    crate::types::py_dict_to_json(result_dict)
                        .map_err(|e| format!("failed to convert handler output to JSON: {e}"))
                })
            });

        crate::runtime::register_outlet_handler(bi, context_id, outlet_name, rust_handler)?;
        Ok(())
    }
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

/// Returns MCP registry entry counts for the given bridge instance
/// (Phase 4 PR 4 sub-slice D).
fn mcp_registry_stats_for(bi: &crate::runtime::PyBridgeInstance) -> McpRegistryStats {
    let registry = server_registry_of(bi);
    let servers = registry.len();
    let stopped_servers = registry
        .iter()
        .filter(|entry| entry.value().stopped)
        .count();
    let clients = client_registry_of(bi).len();
    McpRegistryStats {
        servers,
        stopped_servers,
        clients,
    }
}

/// Removes stopped MCP server entries from the given bridge instance's
/// registry.
fn cleanup_stopped_servers_for(bi: &crate::runtime::PyBridgeInstance) -> usize {
    let registry = server_registry_of(bi);
    let mut removed = 0;
    let keys_to_remove: Vec<String> = registry
        .iter()
        .filter(|entry| entry.value().stopped)
        .map(|entry| entry.key().clone())
        .collect();

    for key in keys_to_remove {
        if registry.remove(&key).is_some() {
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
/// Raises `PyErr` if building the result dict fails.
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_registry_stats")]
    pub fn py_registry_stats(&self, py: Python<'_>) -> PyResult<PyObject> {
        let bi = &*self.inner;
        let core_stats = crate::runtime::registry_stats(bi);
        let mcp_stats = mcp_registry_stats_for(bi);

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
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_registry_cleanup")]
    pub fn py_registry_cleanup(&self, py: Python<'_>) -> PyResult<PyObject> {
        let bi = &*self.inner;
        let servers_removed = cleanup_stopped_servers_for(bi);

        let dict = PyDict::new(py);
        dict.set_item("mcp_servers_removed", servers_removed)?;
        Ok(dict.into())
    }
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
pub const fn register_mcp(_m: &Bound<'_, PyModule>) -> PyResult<()> {
    // All MCP operations — including the stdio allowlist — are
    // now methods on `SCP`. PyO3 registers `#[pymethods]` automatically with
    // the class, so this function has nothing to wire up here.
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Test helper: constructs a fresh bridge instance.
    /// Phase D (#1695) deleted the process-global default.
    fn __bi() -> std::sync::Arc<crate::runtime::PyBridgeInstance> {
        std::sync::Arc::new(crate::runtime::PyBridgeInstance::new_py())
    }

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
        // Hold the Arc alive for the duration of the test so the Weak
        // inside the provider upgrades successfully (#1549 round-2).
        let bi = __bi();
        let creator = "did:dht:z6MkTest";
        let live_a = setup_test_context(&bi, creator, false);
        let live_b = setup_test_context(&bi, creator, false);

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            // A third id the agent does not participate in: configuring a
            // context is not the same as being a member of it.
            context_ids: vec![live_a.clone(), live_b.clone(), "ctx-not-joined".to_owned()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        // ADR-015 AC7: the served set is configured ∩ live participation, so a
        // context the agent is not (or is no longer) a member of drops out
        // without restarting the server. A static snapshot of the configured
        // list could never satisfy that.
        assert_eq!(provider.active_context_ids(), vec![live_a, live_b]);
    }

    #[test]
    fn ffi_bridge_provider_agent_did() {
        let bi = __bi();
        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: "did:dht:z6MkTest".to_owned(),
            context_ids: vec![],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };
        assert_eq!(provider.agent_did(), "did:dht:z6MkTest");
    }

    #[test]
    fn ffi_bridge_provider_context_outlets_empty_for_unknown_context() {
        let bi = __bi();
        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: "did:dht:z6MkTest".to_owned(),
            context_ids: vec!["nonexistent".to_owned()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };
        // Unknown context returns empty outlet list (no panic).
        let outlets = provider.context_tools("nonexistent");
        assert!(outlets.is_empty());
    }

    // -----------------------------------------------------------------------
    // Helper: register a context with an outlet for FfiBridgeProvider tests.
    // -----------------------------------------------------------------------

    /// Registers a context in the runtime registry and optionally adds an outlet.
    /// Returns a unique context ID to avoid collisions with parallel tests.
    ///
    /// Callers must pass the same `bi` they use for subsequent registry lookups;
    /// each `PyBridgeInstance` has its own `instance_id` and context registry.
    fn setup_test_context(
        bi: &crate::runtime::PyBridgeInstance,
        creator_did: &str,
        with_outlet: bool,
    ) -> String {
        // Use a unique context ID to avoid collisions across parallel tests.
        let ctx_id = crate::types::generate_random_id("test-mcp");
        crate::runtime::register_context(bi, &ctx_id, creator_did, &[]).unwrap();

        if with_outlet {
            crate::runtime::with_context(bi, &ctx_id, |rt| {
                let registration = scp_core::context::outlets::OutletRegistration {
                    outlet_id: "calculator".to_owned(),
                    kind: scp_core::context::outlets::OutletKind::default(),
                    name: "Calculator".to_owned(),
                    description: "A simple calculator".to_owned(),
                    schema: scp_core::context::outlets::OutletSchema {
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
                        aggregate_schema: None,
                    },
                    implementation_hash: [0xAA; 32],
                    test_vectors: vec![],
                    operator_did: "did:dht:z6MkOperator".into(),
                    cost: None,
                    message_catalog: Vec::new(),
                    registered_at: 0,
                    signature: Vec::new(),
                };
                scp_core::context::outlets::register_outlet(
                    &mut rt.outlet_registry,
                    &rt.role_state,
                    registration,
                    creator_did,
                )
                .map_err(|e| crate::error::ScpPyError::context(format!("{e}")))?;
                Ok(())
            })
            .unwrap();
        }

        ctx_id
    }

    // -----------------------------------------------------------------------
    // FfiBridgeProvider::validate_capability — rejects missing UCAN (#319)
    // -----------------------------------------------------------------------

    #[test]
    fn ffi_bridge_provider_validate_capability_rejects_missing_ucan() {
        let creator = "did:dht:z6MkCreatorValCap";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };
        // Even the creator is rejected without a UCAN token.
        let result = provider.validate_capability(&ctx_id, "calculator");
        assert!(
            result.is_err(),
            "should reject when no UCAN token is provided"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("UCAN token required"),
            "error should mention UCAN requirement: {err}"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // FfiBridgeProvider::validate_capability — rejects unauthorized member
    // without UCAN token (#319)
    // -----------------------------------------------------------------------

    #[test]
    fn ffi_bridge_provider_validate_capability_rejects_unauthorized() {
        let creator = "did:dht:z6MkCreatorValCapReject";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        // Add a member with no OutletCall capability.
        let member = "did:dht:z6MkMemberNoInvoke";
        crate::runtime::with_context(&bi, &ctx_id, |rt| {
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
            bi: Arc::downgrade(&bi),
            agent_did: member.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };
        let result = provider.validate_capability(&ctx_id, "calculator");
        assert!(
            result.is_err(),
            "member without UCAN token should be rejected"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("UCAN token required"),
            "error should mention UCAN requirement: {err}"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // FfiBridgeProvider::validate_capability — kind-aware defense-in-depth gate
    // (SCP-OUT-014, §5.4.2). Proves the MCP bridge's role-state check reads the
    // outlet's registered kind from the runtime registry and dispatches to the
    // matching split stem: a Query outlet is DENIED to an OutletCall-only member
    // and ALLOWED to an OutletQuery-only member. This exercises the exact
    // registry-kind read + `has_outlet_invocation_capability` dispatch the fixed
    // gate at mcp.rs performs against real bridge state (registered outlet +
    // role_state). The full through-`validate_capability` path additionally
    // requires a valid 11-step UCAN token; that primary layer is covered by the
    // #319 UCAN tests, and the shared gate is covered end-to-end by the runtime
    // `invoke_query_session_*` test.
    #[test]
    #[allow(clippy::too_many_lines)] // End-to-end query-gate test: register + role-state + two-member gate assertions.
    fn ffi_bridge_provider_validate_capability_query_kind_selects_query_stem() {
        use scp_core::context::roles::Capability;

        let creator = "did:dht:z6MkCreatorQueryStem";
        let member = "did:dht:z6MkMemberQueryStem";
        let bi = __bi();
        // Register the context WITHOUT the default calculator outlet — we add a
        // Query-kind one explicitly below.
        let ctx_id = setup_test_context(&bi, creator, false);

        // Register a QUERY-kind outlet and add a member holding ONLY the
        // Action-class OutletCall grant.
        crate::runtime::with_context(&bi, &ctx_id, |rt| {
            let registration = scp_core::context::outlets::OutletRegistration {
                outlet_id: "lookup".to_owned(),
                kind: scp_core::context::outlets::OutletKind::Query,
                name: "Lookup".to_owned(),
                description: "A read-only lookup".to_owned(),
                schema: scp_core::context::outlets::OutletSchema {
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                            "limit": {"type": "number"}
                        }
                    }),
                    output_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "results": {"type": "array"}
                        }
                    }),
                    aggregate_schema: None,
                },
                implementation_hash: [0xAA; 32],
                test_vectors: vec![],
                operator_did: "did:dht:z6MkOperator".into(),
                cost: None,
                message_catalog: Vec::new(),
                registered_at: 0,
                signature: Vec::new(),
            };
            scp_core::context::outlets::register_outlet(
                &mut rt.outlet_registry,
                &rt.role_state,
                registration,
                creator,
            )
            .map_err(|e| crate::error::ScpPyError::context(format!("{e}")))?;

            rt.role_state.members.insert(member.to_owned());
            rt.role_state.member_capabilities.insert(
                member.to_owned(),
                std::iter::once(Capability::OutletCall("lookup".to_owned())).collect(),
            );
            Ok(())
        })
        .unwrap();

        // The MCP defense-in-depth gate reads the registered kind and dispatches
        // via `has_outlet_invocation_capability`. An OutletCall-only member is
        // DENIED on a Query outlet because the two stems are independent.
        let denied = crate::runtime::with_context(&bi, &ctx_id, |rt| {
            let kind = rt
                .outlet_registry
                .get("lookup")
                .map_or(scp_core::context::outlets::OutletKind::Action, |r| r.kind);
            assert_eq!(
                kind,
                scp_core::context::outlets::OutletKind::Query,
                "outlet must round-trip as Query through the bridge registry"
            );
            Ok(
                scp_core::context::outlets::invoke::has_outlet_invocation_capability(
                    &rt.role_state,
                    member,
                    "lookup",
                    kind,
                ),
            )
        })
        .unwrap();
        assert!(
            !denied,
            "Query outlet must be denied to a member holding only OutletCall"
        );

        // Grant the Query-class capability → ALLOWED.
        crate::runtime::with_context(&bi, &ctx_id, |rt| {
            rt.role_state
                .member_capabilities
                .get_mut(member)
                .unwrap()
                .insert(Capability::OutletQuery("lookup".to_owned()));
            Ok(())
        })
        .unwrap();
        let allowed = crate::runtime::with_context(&bi, &ctx_id, |rt| {
            let kind = rt
                .outlet_registry
                .get("lookup")
                .map_or(scp_core::context::outlets::OutletKind::Action, |r| r.kind);
            Ok(
                scp_core::context::outlets::invoke::has_outlet_invocation_capability(
                    &rt.role_state,
                    member,
                    "lookup",
                    kind,
                ),
            )
        })
        .unwrap();
        assert!(
            allowed,
            "Query outlet must be allowed once the member holds OutletQuery"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // FfiBridgeProvider::invoke_outlet — echo fallback when no handler
    // -----------------------------------------------------------------------

    #[test]
    fn ffi_bridge_provider_invoke_outlet_echo_fallback_without_handler() {
        let creator = "did:dht:z6MkCreatorInvokeOutlet";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        let input = serde_json::json!({"a": 3, "b": 4});
        let result = provider.invoke_outlet(&ctx_id, "calculator", input.clone());
        assert!(result.is_ok(), "invoke_outlet should succeed: {result:?}");

        let output = result.unwrap();
        assert_eq!(
            output["status"], "validated",
            "without handler, status should be 'validated' (echo mode)"
        );
        assert_eq!(output["outlet"], "calculator");
        assert_eq!(output["context"], ctx_id);
        assert_eq!(output["input_valid"], true);
        assert_eq!(output["validated_input"], input);

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // FfiBridgeProvider::invoke_outlet — appends OutletInvokedEvent to event log
    // (ADR-010 acceptance criterion 3, issue #120)
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_outlet_echo_mode_appends_outlet_invoked_event() {
        let creator = "did:dht:z6MkCreatorEventLog";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        // Verify the event log is initially empty.
        let initial_count = crate::runtime::with_context(&bi, &ctx_id, |rt| {
            Ok(scp_event_log::tree::event_count(&rt.event_log))
        })
        .unwrap();
        assert_eq!(initial_count, 0, "event log should start empty");

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        // Invoke in echo mode (no handler registered).
        let result =
            provider.invoke_outlet(&ctx_id, "calculator", serde_json::json!({"a": 1, "b": 2}));
        assert!(result.is_ok(), "invoke_outlet should succeed: {result:?}");

        // Verify the event log now has one event.
        let after_count = crate::runtime::with_context(&bi, &ctx_id, |rt| {
            Ok(scp_event_log::tree::event_count(&rt.event_log))
        })
        .unwrap();
        assert_eq!(
            after_count, 1,
            "event log should have 1 event after invocation"
        );

        // Invoke again to verify sequential appending.
        let result2 =
            provider.invoke_outlet(&ctx_id, "calculator", serde_json::json!({"a": 5, "b": 6}));
        assert!(result2.is_ok());

        let final_count = crate::runtime::with_context(&bi, &ctx_id, |rt| {
            Ok(scp_event_log::tree::event_count(&rt.event_log))
        })
        .unwrap();
        assert_eq!(
            final_count, 2,
            "event log should have 2 events after two invocations"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    #[test]
    fn invoke_outlet_with_handler_appends_outlet_invoked_event() {
        let creator = "did:dht:z6MkCreatorHandlerEventLog";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        // Register a handler.
        let handler: crate::runtime::OutletHandler =
            std::sync::Arc::new(|input: serde_json::Value| {
                let a = input["a"].as_f64().unwrap_or(0.0);
                let b = input["b"].as_f64().unwrap_or(0.0);
                Ok(serde_json::json!({"result": a + b}))
            });
        crate::runtime::register_outlet_handler(&bi, &ctx_id, "calculator", handler).unwrap();

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        let result =
            provider.invoke_outlet(&ctx_id, "calculator", serde_json::json!({"a": 10, "b": 20}));
        assert!(result.is_ok(), "invoke_outlet should succeed: {result:?}");
        assert_eq!(result.unwrap(), serde_json::json!({"result": 30.0}));

        // Verify event was logged.
        let count = crate::runtime::with_context(&bi, &ctx_id, |rt| {
            Ok(scp_event_log::tree::event_count(&rt.event_log))
        })
        .unwrap();
        assert_eq!(count, 1, "handler path should also append to event log");

        // Verify the merkle root is non-zero (tree was actually built).
        let root = crate::runtime::with_context(&bi, &ctx_id, |rt| {
            Ok(scp_event_log::tree::root(&rt.event_log))
        })
        .unwrap();
        assert_ne!(
            root, [0u8; 32],
            "merkle root should be non-zero after appending an event"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    #[test]
    fn invoke_outlet_error_does_not_append_event() {
        let creator = "did:dht:z6MkCreatorNoEventOnErr";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        // Invoke with invalid input (schema validation fails).
        let result =
            provider.invoke_outlet(&ctx_id, "calculator", serde_json::json!("not an object"));
        assert!(result.is_err(), "invalid input should be rejected");

        // Event log should still be empty (no event appended on error).
        let count = crate::runtime::with_context(&bi, &ctx_id, |rt| {
            Ok(scp_event_log::tree::event_count(&rt.event_log))
        })
        .unwrap();
        assert_eq!(
            count, 0,
            "event log should remain empty when invocation fails"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // FfiBridgeProvider::invoke_outlet — rejects invalid schema input
    // -----------------------------------------------------------------------

    #[test]
    fn ffi_bridge_provider_invoke_outlet_validates_schema() {
        let creator = "did:dht:z6MkCreatorSchemaVal";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        // Input schema requires an object with "a" and "b" as required fields.
        // Pass a string instead.
        let result =
            provider.invoke_outlet(&ctx_id, "calculator", serde_json::json!("not an object"));
        assert!(result.is_err(), "invalid input should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("validation"),
            "error should mention validation: {err}"
        );

        // Pass an object missing required fields.
        let result = provider.invoke_outlet(&ctx_id, "calculator", serde_json::json!({"a": 1}));
        assert!(
            result.is_err(),
            "input missing required field 'b' should be rejected"
        );

        // Pass valid input — should succeed.
        let result =
            provider.invoke_outlet(&ctx_id, "calculator", serde_json::json!({"a": 1, "b": 2}));
        assert!(result.is_ok(), "valid input should succeed: {result:?}");

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // FfiBridgeProvider::invoke_outlet — outlet not found
    // -----------------------------------------------------------------------

    #[test]
    fn ffi_bridge_provider_invoke_outlet_rejects_unknown_outlet() {
        let creator = "did:dht:z6MkCreatorUnknownOutlet";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, false);

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        let result = provider.invoke_outlet(&ctx_id, "nonexistent", serde_json::json!({}));
        assert!(result.is_err(), "unknown outlet should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("not found"),
            "error should mention outlet not found: {err}"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // py_mcp_load_contexts — returns contexts from local runtime registry
    // -----------------------------------------------------------------------

    #[test]
    fn load_contexts_returns_local_contexts() {
        let creator = "did:dht:z6MkCreatorLoadCtx";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        // Since py_mcp_load_contexts requires Python, we test the underlying
        // runtime function directly.
        let ids = crate::runtime::context_ids_for_member(&bi, creator);
        assert!(
            ids.contains(&ctx_id),
            "creator should be a member of the context"
        );

        // Non-member should not see the context.
        let other_ids = crate::runtime::context_ids_for_member(&bi, "did:dht:z6MkNobody");
        assert!(
            !other_ids.contains(&ctx_id),
            "non-member should not see the context"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // Known context registry (SCP-213)
    // -----------------------------------------------------------------------

    #[test]
    fn known_context_registration_and_lookup() {
        // BridgeInstance must exist for known-context registration.
        crate::runtime::init_context_manager_for_test(&__bi());

        let creator = "did:dht:z6MkCreatorKnownCtx";
        let ctx_id = crate::types::generate_random_id("known-ctx");
        let routing_id = [0xAA; 32];

        let known = crate::runtime::KnownContext {
            routing_id,
            relay_url: Some("ws://127.0.0.1:9000/scp/v1".to_owned()),
            member_did: creator.to_owned(),
            last_seen: 1_700_000_000,
        };

        let bi = __bi();
        crate::runtime::register_known_context_on(&bi, &ctx_id, known);

        // Should be discoverable by member DID.
        let found = crate::runtime::known_contexts_for_member_on(&bi, creator);
        assert!(
            found.iter().any(|(id, _)| id == &ctx_id),
            "known context should be found by member DID"
        );

        // Should not be found for a different DID.
        let not_found =
            crate::runtime::known_contexts_for_member_on(&bi, "did:dht:z6MkSomeoneElse");
        assert!(
            !not_found.iter().any(|(id, _)| id == &ctx_id),
            "known context should not be found for a different DID"
        );

        // Cleanup: remove_context also removes from known-contexts.
        crate::runtime::remove_context(&bi, &ctx_id);
        let after_remove = crate::runtime::known_contexts_for_member_on(&bi, creator);
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

        let active = probe_relay_for_known_contexts(&__bi(), &known);
        assert!(
            active.is_empty(),
            "should return empty set when no relay is connected"
        );
    }

    #[test]
    fn probe_relay_with_empty_known_returns_empty() {
        let known: Vec<(String, crate::runtime::KnownContext)> = vec![];
        let active = probe_relay_for_known_contexts(&__bi(), &known);
        assert!(active.is_empty(), "should return empty set for empty input");
    }

    // -----------------------------------------------------------------------
    // Outlet handler registration and dispatch (SCP-212)
    // -----------------------------------------------------------------------

    #[test]
    fn register_outlet_handler_and_invoke_dispatches_through_handler() {
        let creator = "did:dht:z6MkCreatorHandler";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        // Register a Rust handler that adds two numbers (simulates a Python handler).
        let handler: crate::runtime::OutletHandler =
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

        crate::runtime::register_outlet_handler(&bi, &ctx_id, "calculator", handler).unwrap();

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        let input = serde_json::json!({"a": 3, "b": 4});
        let result = provider.invoke_outlet(&ctx_id, "calculator", input);
        assert!(result.is_ok(), "invoke_outlet should succeed: {result:?}");

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

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    #[test]
    fn register_outlet_handler_rejects_unregistered_outlet() {
        let creator = "did:dht:z6MkCreatorHandlerReject";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, false); // No outlet registered.

        let handler: crate::runtime::OutletHandler =
            std::sync::Arc::new(|_input| Ok(serde_json::json!({})));

        let result = crate::runtime::register_outlet_handler(&bi, &ctx_id, "nonexistent", handler);
        assert!(
            result.is_err(),
            "should reject handler for unregistered outlet"
        );
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("not found"),
            "error should mention outlet not found: {err}"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    #[test]
    fn invoke_outlet_with_handler_validates_output_schema() {
        let creator = "did:dht:z6MkCreatorOutVal";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        // Register a handler that returns a string instead of an object
        // (violates the output schema which requires an object).
        let bad_handler: crate::runtime::OutletHandler =
            std::sync::Arc::new(|_input| Ok(serde_json::json!("not an object")));

        crate::runtime::register_outlet_handler(&bi, &ctx_id, "calculator", bad_handler).unwrap();

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        let result =
            provider.invoke_outlet(&ctx_id, "calculator", serde_json::json!({"a": 1, "b": 2}));
        assert!(
            result.is_err(),
            "handler returning invalid output should be rejected"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("output validation"),
            "error should mention output validation: {err}"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    #[test]
    fn invoke_outlet_handler_error_is_propagated() {
        let creator = "did:dht:z6MkCreatorHandlerErr";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        // Register a handler that always fails.
        let failing_handler: crate::runtime::OutletHandler =
            std::sync::Arc::new(|_input| Err("computation exploded".to_owned()));

        crate::runtime::register_outlet_handler(&bi, &ctx_id, "calculator", failing_handler)
            .unwrap();

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        let result =
            provider.invoke_outlet(&ctx_id, "calculator", serde_json::json!({"a": 1, "b": 2}));
        assert!(result.is_err(), "failing handler should propagate error");
        let err = result.unwrap_err();
        assert!(
            err.contains("computation exploded"),
            "error should contain handler error message: {err}"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // Outlet handler execution timeout (issue #123)
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_outlet_handler_timeout_produces_clear_error() {
        let creator = "did:dht:z6MkCreatorTimeout";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        // Register a handler that blocks for 5 seconds (will be timed out).
        let blocking_handler: crate::runtime::OutletHandler = std::sync::Arc::new(|_input| {
            std::thread::sleep(std::time::Duration::from_secs(5));
            Ok(serde_json::json!({"result": 42}))
        });

        crate::runtime::register_outlet_handler(&bi, &ctx_id, "calculator", blocking_handler)
            .unwrap();

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: 50, // 50ms — will expire before the 5s sleep.
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        let result =
            provider.invoke_outlet(&ctx_id, "calculator", serde_json::json!({"a": 1, "b": 2}));
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

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    #[test]
    fn invoke_outlet_handler_completes_within_timeout_succeeds() {
        let creator = "did:dht:z6MkCreatorTimeoutOk";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        // Register a fast handler.
        let fast_handler: crate::runtime::OutletHandler =
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

        crate::runtime::register_outlet_handler(&bi, &ctx_id, "calculator", fast_handler).unwrap();

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: 5_000, // 5 seconds — plenty for an instant handler.
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        let result =
            provider.invoke_outlet(&ctx_id, "calculator", serde_json::json!({"a": 3, "b": 4}));
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

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    #[test]
    fn invoke_outlet_handler_default_timeout_is_30s() {
        // Verify the default timeout constant matches scp-core.
        assert_eq!(
            FFI_OUTLET_TIMEOUT_MS,
            u64::from(scp_core::context::outlets::DEFAULT_TIMEOUT_MS),
            "FFI default timeout should match scp-core default"
        );
    }

    // -----------------------------------------------------------------------
    // StdioClientTransport
    // -----------------------------------------------------------------------

    #[test]
    fn stdio_client_transport_spawn_rejects_unlisted_command() {
        let allowlist = Mutex::new(allowlist::StdioAllowlist::new_with_defaults());
        let result = StdioClientTransport::spawn(
            &allowlist,
            &["nonexistent_command_that_does_not_exist_12345".to_owned()],
        );
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
        let allowlist = Mutex::new(allowlist::StdioAllowlist::new_with_defaults());
        let result = StdioClientTransport::spawn(&allowlist, &[]);
        assert!(result.is_err());
    }

    /// WU6: Two-instance regression test — disabling enforcement via the
    /// public `PyScp::mcp_disable_stdio_allowlist` method on one instance
    /// MUST NOT leak into another. Drives the public surface (not the
    /// internal `core.mcp_allowlist()` accessor) so the test catches a
    /// regression where the method silently locks the wrong mutex.
    #[test]
    fn allowlist_disable_does_not_leak_across_instances_pyo3() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let a = crate::scp::PyScp::new_in_memory_for_test();
            let b = crate::scp::PyScp::new_in_memory_for_test();

            a.mcp_disable_stdio_allowlist()
                .expect("disable on a should succeed");

            // `b` snapshot remains restricted (default allowlist, enforcement on).
            let b_dict_obj = b.mcp_get_stdio_allowlist(py).expect("snapshot b");
            let b_dict: &Bound<'_, PyDict> = b_dict_obj.bind(py).downcast().unwrap();
            let b_unrestricted: bool = b_dict
                .get_item("unrestricted")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            assert!(!b_unrestricted, "instance b must remain restricted");

            // Sanity: `a` is unrestricted via its own snapshot.
            let a_dict_obj = a.mcp_get_stdio_allowlist(py).expect("snapshot a");
            let a_dict: &Bound<'_, PyDict> = a_dict_obj.bind(py).downcast().unwrap();
            let a_unrestricted: bool = a_dict
                .get_item("unrestricted")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            assert!(a_unrestricted, "instance a must be unrestricted");
        });
    }

    /// WU6 supplement: `configure` on one instance must not bleed into
    /// another's allow set, exercised through the public `PyScp` method.
    #[test]
    fn allowlist_configure_does_not_leak_across_instances_pyo3() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let a = crate::scp::PyScp::new_in_memory_for_test();
            let b = crate::scp::PyScp::new_in_memory_for_test();

            a.mcp_configure_stdio_allowlist(vec!["custom-a".to_owned()])
                .expect("configure on a");

            let a_dict_obj = a.mcp_get_stdio_allowlist(py).expect("snapshot a");
            let a_dict: &Bound<'_, PyDict> = a_dict_obj.bind(py).downcast().unwrap();
            let a_allowed: Vec<String> = a_dict
                .get_item("allowed")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            assert!(a_allowed.contains(&"custom-a".to_owned()));

            let b_dict_obj = b.mcp_get_stdio_allowlist(py).expect("snapshot b");
            let b_dict: &Bound<'_, PyDict> = b_dict_obj.bind(py).downcast().unwrap();
            let b_allowed: Vec<String> = b_dict
                .get_item("allowed")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            assert!(
                !b_allowed.contains(&"custom-a".to_owned()),
                "instance b must not see a's custom binary",
            );
        });
    }

    // -----------------------------------------------------------------------
    // Registry statistics and cleanup (issue #108)
    // -----------------------------------------------------------------------

    #[test]
    fn mcp_registry_stats_returns_consistent_counts() {
        crate::runtime::init_context_manager_for_test(&__bi());
        let stats = mcp_registry_stats_for(&__bi());
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
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, false);

        // Create a minimal server entry directly in the registry.
        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };
        // The registry entry no longer holds the server (the transport task
        // owns it), so the provider is only built here to prove construction.
        drop(McpServer::new(provider));
        let handle = generate_handle_id("mcp-server");

        server_registry_of(&bi).insert(
            handle.clone(),
            McpServerState {
                identity_did: creator.to_owned(),
                context_ids: vec![ctx_id.clone()],
                transport: "stdio".to_owned(),
                stopped: true, // Already stopped.
                shutdown_tx: None,
                task_handle: None,
            },
        );

        // Verify our entry is present before cleanup.
        assert!(
            server_registry_of(&bi).contains_key(&handle),
            "stopped server handle should be present before cleanup"
        );

        cleanup_stopped_servers_for(&bi);

        // The specific handle should be gone. We check by key rather than
        // by count because parallel tests may insert/remove other entries.
        assert!(
            !server_registry_of(&bi).contains_key(&handle),
            "stopped server handle should be removed after cleanup"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    #[test]
    fn cleanup_stopped_servers_leaves_running_entries() {
        let creator = "did:dht:z6MkCreatorCleanupRunning";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, false);

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };
        // The registry entry no longer holds the server (the transport task
        // owns it), so the provider is only built here to prove construction.
        drop(McpServer::new(provider));
        let handle = generate_handle_id("mcp-server");

        server_registry_of(&bi).insert(
            handle.clone(),
            McpServerState {
                identity_did: creator.to_owned(),
                context_ids: vec![ctx_id.clone()],
                transport: "stdio".to_owned(),
                stopped: false, // Still running.
                shutdown_tx: None,
                task_handle: None,
            },
        );

        cleanup_stopped_servers_for(&bi);

        // Running server should still be present.
        assert!(
            server_registry_of(&bi).contains_key(&handle),
            "running server handle should NOT be removed"
        );

        // Cleanup: remove manually.
        server_registry_of(&bi).remove(&handle);
        crate::runtime::remove_context(&bi, &ctx_id);
    }

    #[test]
    fn core_registry_stats_includes_all_fields() {
        crate::runtime::init_context_manager_for_test(&__bi());
        let stats = crate::runtime::registry_stats(&__bi());
        // Just verify the struct has the expected fields and doesn't panic.
        let _ = stats.contexts;
        let _ = stats.known_contexts;
        let _ = stats.identities;
        let _ = stats.relay_connected;
    }

    // -----------------------------------------------------------------------
    // #1549 round-2 regression: FfiBridgeProvider must hold a `Weak`, not
    // an `Arc`, so the MCP server task cannot pin `PyBridgeInstance` alive
    // past the caller's last `Arc` drop.
    //
    // A direct unit assertion: the field type itself is `Weak`. When the
    // only strong reference is dropped, the provider's methods must not
    // panic, must return safe defaults for the "optional" methods, and
    // must return a clear error for the "required" methods.
    // -----------------------------------------------------------------------

    /// Struct-level proof: the `bi` field is `Weak<PyBridgeInstance>`.
    /// If someone reverts the type to `Arc`, this test stops compiling.
    #[test]
    fn ffi_bridge_provider_field_is_weak_not_arc() {
        let bi = __bi();
        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: "did:dht:z6MkTypeProof".to_owned(),
            context_ids: vec![],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,
            agent_proof_tokens: None,
        };
        // Compile-time assertion: the field is a `Weak`, so upgrade()
        // returns `Option`. If the field regresses to `Arc`, this line
        // fails to type-check.
        let _opt: Option<Arc<crate::runtime::PyBridgeInstance>> = provider.bi.upgrade();
    }

    /// Provider methods that degrade gracefully return safe defaults
    /// when the bridge instance has been dropped.
    #[test]
    fn ffi_bridge_provider_returns_safe_defaults_when_bridge_dropped() {
        let provider = {
            // Construct the provider against a short-lived Arc, then drop
            // the Arc so the provider's `Weak` can no longer upgrade.
            let bi = __bi();
            let p = FfiBridgeProvider {
                bi: Arc::downgrade(&bi),
                agent_did: "did:dht:z6MkDropped".to_owned(),
                context_ids: vec!["ctx-dropped".to_owned()],
                outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
                agent_ucan_token: None,
                agent_proof_tokens: None,
            };
            drop(bi);
            p
        };

        // upgrade_bi itself returns Err.
        assert!(
            provider.upgrade_bi().is_err(),
            "upgrade_bi must fail when the bridge has been dropped"
        );

        // agent_role: returns None.
        assert!(provider.agent_role("ctx-dropped").is_none());

        // context_tools: returns empty.
        assert!(provider.context_tools("ctx-dropped").is_empty());

        // context_members: returns empty.
        assert!(provider.context_members("ctx-dropped").is_empty());

        // context_events: returns zero-count JSON fallback.
        let events = provider.context_events("ctx-dropped");
        assert_eq!(
            events,
            serde_json::json!({ "event_count": 0 }),
            "context_events must emit the zero-count fallback"
        );

        // validate_capability: returns Err.
        let vc = provider.validate_capability("ctx-dropped", "anyoutlet");
        assert!(
            vc.is_err(),
            "validate_capability must reject when bridge is dropped"
        );
        assert!(
            vc.unwrap_err().contains("bridge instance has been dropped"),
            "error must mention the dropped bridge"
        );

        // active_context_ids: empty. It now resolves live participation
        // through the bridge, so a dropped instance means nothing is served —
        // which is the fail-closed answer: serving a context whose membership
        // can no longer be checked would be worse than serving none.
        assert!(
            provider.active_context_ids().is_empty(),
            "a dropped bridge must serve no contexts"
        );

        // agent_did is provider-local and does not touch the weak at all.
        assert_eq!(provider.agent_did(), "did:dht:z6MkDropped");
    }
}
