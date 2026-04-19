//! napi-rs bridge for MCP (Model Context Protocol) operations.
//!
//! Exposes MCP server and client operations to Node.js/Bun:
//!
//! - [`mcp_server_create`] — Start an MCP server exposing SCP context tools.
//! - [`mcp_server_stop`] — Stop a running MCP server.
//! - [`mcp_client_connect_stdio`] — Connect to an external MCP server via stdio.
//! - [`mcp_client_connect_sse`] — Connect to an external MCP server via SSE.
//! - [`mcp_client_disconnect`] — Disconnect from an external MCP server.
//! - [`mcp_client_list_tools`] — List tools from an external MCP server.
//! - [`mcp_client_invoke`] — Invoke an external MCP tool with SCP provenance.
//!
//! The MCP bridge uses opaque string handles to track server and client
//! instances in global registries (matching the `UniFFI` bridge pattern).
//!
//! See ADR-015 in `.docs/adrs/phase-3.md`.

use scp_ffi_common::error_codes as codes;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};

use dashmap::DashMap;
use napi_derive::napi;
use scp_mcp::allowlist;
use scp_mcp::client::{McpClient, McpTransport};
use scp_mcp::protocol::{JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};
use scp_mcp::server::ContextProvider;

use crate::error::ScpNapiError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum bytes per line from MCP transport (10 MiB). Prevents OOM from
/// unbounded line reads by a malicious or broken peer.
const MAX_LINE_BYTES: u64 = 10 * 1024 * 1024;

// ---------------------------------------------------------------------------
// NAPI types
// ---------------------------------------------------------------------------

/// Configuration for starting an MCP server.
#[napi(object)]
pub struct NapiMcpServerConfig {
    /// DID of the identity running the server.
    pub identity_did: String,
    /// Context IDs to expose via MCP.
    pub context_ids: Vec<String>,
    /// Transport mode: `"stdio"` or `"sse"`.
    pub transport: String,
}

/// Tool definition from an external MCP server.
#[napi(object)]
pub struct NapiMcpToolInfo {
    /// Tool name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// JSON Schema for tool input (as a JSON string).
    pub input_schema_json: String,
}

/// Result of invoking an external MCP tool with SCP provenance.
#[napi(object)]
pub struct NapiMcpInvokeResult {
    /// Tool output content as serialized JSON.
    pub content_json: String,
    /// Whether the tool call resulted in an error.
    pub is_error: bool,
    /// Source of the result, formatted as `"mcp:{tool_name}"`.
    pub source: String,
    /// DID of the invoking agent.
    pub invoked_by: String,
    /// SCP context ID for the invocation.
    pub context_id: String,
    /// Invocation timestamp (milliseconds since Unix epoch).
    pub timestamp: f64,
}

/// Opaque handle to an MCP server instance.
#[napi]
pub struct NapiMcpServerHandle {
    handle_id: String,
    /// `NapiBridgeInstance` id that minted this handle.
    pub(crate) instance_id: u64,
}

#[napi]
impl NapiMcpServerHandle {
    /// Returns the opaque handle ID.
    #[napi(getter)]
    #[must_use]
    pub fn handle_id(&self) -> String {
        self.handle_id.clone()
    }

    /// Returns the id of the `SCP` instance that minted this handle, as a
    /// base-10 string.
    #[napi(getter, js_name = "instanceId")]
    #[must_use]
    pub fn instance_id_js(&self) -> String {
        self.instance_id.to_string()
    }
}

impl Drop for NapiMcpServerHandle {
    fn drop(&mut self) {
        crate::decrement_handle_count();
    }
}

/// Opaque handle to an MCP client connection.
#[napi]
pub struct NapiMcpClientHandle {
    handle_id: String,
    /// `NapiBridgeInstance` id that minted this handle.
    pub(crate) instance_id: u64,
}

#[napi]
impl NapiMcpClientHandle {
    /// Returns the opaque handle ID.
    #[napi(getter)]
    #[must_use]
    pub fn handle_id(&self) -> String {
        self.handle_id.clone()
    }

    /// Returns the id of the `SCP` instance that minted this handle, as a
    /// base-10 string.
    #[napi(getter, js_name = "instanceId")]
    #[must_use]
    pub fn instance_id_js(&self) -> String {
        self.instance_id.to_string()
    }
}

impl Drop for NapiMcpClientHandle {
    fn drop(&mut self) {
        crate::decrement_handle_count();
    }
}

// ---------------------------------------------------------------------------
// Registries
// ---------------------------------------------------------------------------

/// Internal state for a running MCP server.
struct McpServerEntry {
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    _task_handle: tokio::task::JoinHandle<()>,
    stopped: bool,
}

/// Internal state for an active MCP client connection.
struct McpClientEntry {
    client: Mutex<McpClient<McpClientTransportWrapper>>,
}

fn mcp_server_registry() -> &'static DashMap<String, McpServerEntry> {
    static REGISTRY: OnceLock<DashMap<String, McpServerEntry>> = OnceLock::new();
    REGISTRY.get_or_init(DashMap::new)
}

fn mcp_client_registry() -> &'static DashMap<String, McpClientEntry> {
    static REGISTRY: OnceLock<DashMap<String, McpClientEntry>> = OnceLock::new();
    REGISTRY.get_or_init(DashMap::new)
}

fn mcp_handle_id(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

/// Clears both MCP server and client registries during shutdown.
///
/// Called by the shutdown hook registered in `crate::runtime::init_bridge_instance_empty`.
/// This ensures server shutdown senders and client connections are dropped,
/// allowing background tasks to terminate cleanly.
pub(crate) fn clear_registries() {
    mcp_server_registry().clear();
    mcp_client_registry().clear();
}

// ---------------------------------------------------------------------------
// Transport implementations
// ---------------------------------------------------------------------------

/// Transport wrapper that delegates to either stdio or SSE.
enum McpClientTransportWrapper {
    Stdio(StdioMcpTransport),
    Sse(SseMcpTransport),
}

impl McpTransport for McpClientTransportWrapper {
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

/// Stdio MCP transport: communicates with a subprocess via stdin/stdout.
struct StdioMcpTransport {
    inner: Mutex<StdioTransportInner>,
}

struct StdioTransportInner {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
}

impl StdioMcpTransport {
    fn spawn(command: &[String]) -> Result<Self, String> {
        let (cmd, args) = command
            .split_first()
            .ok_or_else(|| "command list is empty".to_owned())?;

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

        let stdin = child.stdin.take().ok_or("failed to capture child stdin")?;
        let stdout = child
            .stdout
            .take()
            .ok_or("failed to capture child stdout")?;
        let reader = BufReader::new(stdout);

        Ok(Self {
            inner: Mutex::new(StdioTransportInner {
                child,
                stdin,
                reader,
            }),
        })
    }
}

impl McpTransport for StdioMcpTransport {
    fn send_request(&self, request: &JsonRpcRequest) -> Result<JsonRpcResponse, String> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| format!("transport lock poisoned: {e}"))?;

        let json = serde_json::to_string(request).map_err(|e| format!("serialize error: {e}"))?;
        guard
            .stdin
            .write_all(json.as_bytes())
            .map_err(|e| format!("write error: {e}"))?;
        guard
            .stdin
            .write_all(b"\n")
            .map_err(|e| format!("write newline error: {e}"))?;
        guard
            .stdin
            .flush()
            .map_err(|e| format!("flush error: {e}"))?;

        // Read response line with bounded read to prevent OOM.
        let mut line = String::new();
        let n = {
            use std::io::Read;
            let mut bounded = (&mut guard.reader).take(MAX_LINE_BYTES);
            bounded
                .read_line(&mut line)
                .map_err(|e| format!("read error: {e}"))?
        };
        if n == 0 {
            return Err("EOF from subprocess".to_owned());
        }

        serde_json::from_str(line.trim()).map_err(|e| format!("parse error: {e}"))
    }

    fn send_notification(&self, notification: &JsonRpcNotification) -> Result<(), String> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| format!("transport lock poisoned: {e}"))?;

        let json =
            serde_json::to_string(notification).map_err(|e| format!("serialize error: {e}"))?;
        guard
            .stdin
            .write_all(json.as_bytes())
            .map_err(|e| format!("write error: {e}"))?;
        guard
            .stdin
            .write_all(b"\n")
            .map_err(|e| format!("write newline error: {e}"))?;
        guard
            .stdin
            .flush()
            .map_err(|e| format!("flush error: {e}"))?;

        Ok(())
    }
}

impl Drop for StdioMcpTransport {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.inner.lock() {
            let _ = guard.child.kill();
            let _ = guard.child.wait();
        }
    }
}

/// SSE MCP transport: communicates via HTTP with Server-Sent Events.
struct SseMcpTransport {
    _url: String,
}

impl SseMcpTransport {
    fn connect(url: &str) -> Self {
        Self {
            _url: url.to_owned(),
        }
    }
}

impl McpTransport for SseMcpTransport {
    fn send_request(&self, _request: &JsonRpcRequest) -> Result<JsonRpcResponse, String> {
        Err("SSE client transport not yet implemented for NAPI — use stdio transport".to_owned())
    }

    fn send_notification(&self, _notification: &JsonRpcNotification) -> Result<(), String> {
        Err("SSE client transport not yet implemented for NAPI — use stdio transport".to_owned())
    }
}

// ---------------------------------------------------------------------------
// MCP FFI bridge context provider
// ---------------------------------------------------------------------------

/// FFI bridge provider for the MCP server. Implements `ContextProvider` by
/// delegating to the context manager for tool and state queries.
struct McpNapiBridgeProvider {
    agent_did: String,
    context_ids: Vec<String>,
}

impl ContextProvider for McpNapiBridgeProvider {
    fn active_context_ids(&self) -> Vec<scp_mcp::namespace::ContextId> {
        self.context_ids.clone()
    }

    fn agent_role(&self, _context_id: &str) -> Option<String> {
        static WARN_ONCE: std::sync::Once = std::sync::Once::new();
        WARN_ONCE.call_once(|| {
            tracing::warn!(
                "McpNapiBridgeProvider::agent_role returns None — \
                 wire a production ContextProvider that resolves real roles \
                 from ContextManager before exposing MCP in production."
            );
        });
        None
    }

    fn agent_did(&self) -> &str {
        &self.agent_did
    }

    fn context_tools(&self, _context_id: &str) -> Vec<scp_mcp::server::ContextToolInfo> {
        Vec::new()
    }

    fn validate_capability(&self, _context_id: &str, _tool_name: &str) -> Result<(), String> {
        static WARN_ONCE: std::sync::Once = std::sync::Once::new();
        WARN_ONCE.call_once(|| {
            tracing::warn!(
                "McpNapiBridgeProvider::validate_capability returns error — \
                 wire a production ContextProvider that checks UCAN capabilities \
                 against the context's role state before exposing MCP in production."
            );
        });
        Err("capability validation not implemented — wire a production ContextProvider".to_owned())
    }

    fn invoke_tool(
        &self,
        _context_id: &str,
        _tool_name: &str,
        _arguments: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        Err(
            "tool invocation through MCP server requires ContextManager tool registry integration"
                .to_owned(),
        )
    }

    fn context_members(&self, _context_id: &str) -> Vec<scp_mcp::server::MemberInfo> {
        Vec::new()
    }

    fn context_events(&self, _context_id: &str) -> serde_json::Value {
        serde_json::Value::Array(Vec::new())
    }

    fn subscribe_resource(&self, _uri: &str) -> Result<(), String> {
        Err("resource subscriptions require full relay integration".to_owned())
    }
}

// ---------------------------------------------------------------------------
// MCP stdio server loop
// ---------------------------------------------------------------------------

async fn run_mcp_stdio_server(
    server: Arc<Mutex<scp_mcp::server::McpServer<McpNapiBridgeProvider>>>,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    tokio::select! {
        _ = shutdown_rx => {}
        () = async {
            let stdin = tokio::io::stdin();
            let mut stdout = tokio::io::stdout();
            let mut reader = tokio::io::BufReader::new(stdin);
            let mut line = String::new();

            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                if line.len() as u64 > MAX_LINE_BYTES {
                    break;
                }

                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                let response = {
                    let request: Result<scp_mcp::protocol::JsonRpcRequest, _> =
                        serde_json::from_str(trimmed);
                    match request {
                        Ok(req) => {
                            server
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
                    && let Ok(json) = serde_json::to_string(&resp)
                    && (stdout.write_all(json.as_bytes()).await.is_err()
                        || stdout.write_all(b"\n").await.is_err()
                        || stdout.flush().await.is_err())
                {
                    tracing::warn!("MCP stdio server: stdout write failed, stopping");
                    break;
                }
            }
        } => {}
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Starts an MCP server exposing SCP context tools.
///
/// # Returns
///
/// A `Promise<NapiMcpServerHandle>` for stopping the server.
#[napi]
#[allow(clippy::unused_async)]
pub async fn mcp_server_create(config: NapiMcpServerConfig) -> napi::Result<NapiMcpServerHandle> {
    if config.transport != "stdio" && config.transport != "sse" {
        return Err(ScpNapiError::Transport {
            message: format!(
                "unsupported MCP transport: {:?} — expected \"stdio\" or \"sse\"",
                config.transport
            ),
            code: codes::TRANS_5010.to_owned(),
        }
        .into());
    }

    if config.context_ids.is_empty() {
        return Err(ScpNapiError::Transport {
            message: "context_ids must not be empty".to_owned(),
            code: codes::TRANS_5011.to_owned(),
        }
        .into());
    }

    let provider = McpNapiBridgeProvider {
        agent_did: config.identity_did.clone(),
        context_ids: config.context_ids.clone(),
    };
    let server = scp_mcp::server::McpServer::new(provider);
    let server = Arc::new(Mutex::new(server));

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server_clone = Arc::clone(&server);
    let transport_mode = config.transport.clone();

    let task_handle = crate::runtime().spawn(async move {
        match transport_mode.as_str() {
            "stdio" => {
                run_mcp_stdio_server(server_clone, shutdown_rx).await;
            }
            "sse" => {
                let provider = McpNapiBridgeProvider {
                    agent_did: config.identity_did,
                    context_ids: config.context_ids,
                };
                let sse_server = scp_mcp::server::McpServer::new(provider);
                let sse_config =
                    scp_mcp::sse::SseConfig::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
                let sse_shutdown = scp_mcp::sse::ShutdownHandle::new();
                let sse_shutdown_trigger = sse_shutdown.clone();
                tokio::spawn(async move {
                    let _ = shutdown_rx.await;
                    sse_shutdown_trigger.shutdown();
                });
                let result = scp_mcp::sse::run_sse(sse_server, sse_config, sse_shutdown).await;
                if let Err(e) = result {
                    tracing::error!("MCP SSE server error: {e}");
                }
            }
            _ => {}
        }
    });

    let handle_id = mcp_handle_id("mcp-server");
    let entry = McpServerEntry {
        shutdown_tx: Some(shutdown_tx),
        _task_handle: task_handle,
        stopped: false,
    };

    mcp_server_registry().insert(handle_id.clone(), entry);
    crate::increment_handle_count();

    Ok(NapiMcpServerHandle {
        handle_id,
        instance_id: crate::runtime::default_instance_id()?,
    })
}

/// Stops a running MCP server.
#[napi]
#[allow(clippy::unused_async)]
pub async fn mcp_server_stop(handle: &NapiMcpServerHandle) -> napi::Result<()> {
    crate::napi_check_handle!(handle);
    let mut entry = mcp_server_registry()
        .get_mut(&handle.handle_id)
        .ok_or_else(|| {
            napi::Error::from(ScpNapiError::Transport {
                message: format!("MCP server handle '{}' not found", handle.handle_id),
                code: codes::TRANS_5012.to_owned(),
            })
        })?;

    if entry.stopped {
        return Err(ScpNapiError::Transport {
            message: format!("MCP server '{}' is already stopped", handle.handle_id),
            code: codes::TRANS_5013.to_owned(),
        }
        .into());
    }

    entry.stopped = true;
    if let Some(tx) = entry.shutdown_tx.take() {
        let _ = tx.send(());
    }

    // Release the mutable ref before removing (DashMap requires no outstanding refs).
    drop(entry);

    // Remove the server entry from the registry to prevent memory leak (#1165).
    mcp_server_registry().remove(&handle.handle_id);

    Ok(())
}

/// Connects to an external MCP server via stdio transport.
///
/// Spawns the given command as a subprocess, communicates via line-delimited
/// JSON over stdin/stdout, and performs the MCP initialize handshake.
#[napi]
#[allow(clippy::unused_async)]
pub async fn mcp_client_connect_stdio(command: Vec<String>) -> napi::Result<NapiMcpClientHandle> {
    if command.is_empty() {
        return Err(ScpNapiError::Transport {
            message: "command must be a non-empty list".to_owned(),
            code: codes::TRANS_5014.to_owned(),
        }
        .into());
    }

    let transport = StdioMcpTransport::spawn(&command).map_err(|e| {
        napi::Error::from(ScpNapiError::Transport {
            message: format!("failed to connect stdio MCP client: {e}"),
            code: codes::TRANS_5015.to_owned(),
        })
    })?;

    let mut client = McpClient::new(McpClientTransportWrapper::Stdio(transport));
    client.initialize().map_err(|e| {
        napi::Error::from(ScpNapiError::Transport {
            message: format!("MCP initialize handshake failed: {e}"),
            code: codes::TRANS_5016.to_owned(),
        })
    })?;

    let handle_id = mcp_handle_id("mcp-client");
    let entry = McpClientEntry {
        client: Mutex::new(client),
    };

    mcp_client_registry().insert(handle_id.clone(), entry);
    crate::increment_handle_count();

    Ok(NapiMcpClientHandle {
        handle_id,
        instance_id: crate::runtime::default_instance_id()?,
    })
}

/// Connects to an external MCP server via SSE transport.
#[napi]
#[allow(clippy::unused_async)]
pub async fn mcp_client_connect_sse(url: String) -> napi::Result<NapiMcpClientHandle> {
    let transport = SseMcpTransport::connect(&url);

    let mut client = McpClient::new(McpClientTransportWrapper::Sse(transport));
    client.initialize().map_err(|e| {
        napi::Error::from(ScpNapiError::Transport {
            message: format!("MCP initialize handshake failed: {e}"),
            code: codes::TRANS_5018.to_owned(),
        })
    })?;

    let handle_id = mcp_handle_id("mcp-client");
    let entry = McpClientEntry {
        client: Mutex::new(client),
    };

    mcp_client_registry().insert(handle_id.clone(), entry);
    crate::increment_handle_count();

    Ok(NapiMcpClientHandle {
        handle_id,
        instance_id: crate::runtime::default_instance_id()?,
    })
}

/// Disconnects from an external MCP server.
#[napi]
#[allow(clippy::unused_async)]
pub async fn mcp_client_disconnect(handle: &NapiMcpClientHandle) -> napi::Result<()> {
    crate::napi_check_handle!(handle);
    let removed = mcp_client_registry().remove(&handle.handle_id);
    if removed.is_none() {
        return Err(ScpNapiError::Transport {
            message: format!("MCP client handle '{}' not found", handle.handle_id),
            code: codes::TRANS_5019.to_owned(),
        }
        .into());
    }
    Ok(())
}

/// Lists available tools from an external MCP server.
#[napi]
#[allow(clippy::unused_async)]
pub async fn mcp_client_list_tools(
    handle: &NapiMcpClientHandle,
) -> napi::Result<Vec<NapiMcpToolInfo>> {
    crate::napi_check_handle!(handle);
    let entry = mcp_client_registry()
        .get(&handle.handle_id)
        .ok_or_else(|| {
            napi::Error::from(ScpNapiError::Transport {
                message: format!("MCP client handle '{}' not found", handle.handle_id),
                code: codes::TRANS_5020.to_owned(),
            })
        })?;

    let client_guard = entry.client.lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Transport {
            message: format!("client lock poisoned: {e}"),
            code: codes::TRANS_5021.to_owned(),
        })
    })?;

    let tools = client_guard.list_tools().map_err(|e| {
        napi::Error::from(ScpNapiError::Transport {
            message: format!("tools/list failed: {e}"),
            code: codes::TRANS_5022.to_owned(),
        })
    })?;

    Ok(tools
        .into_iter()
        .map(|t| NapiMcpToolInfo {
            name: t.name,
            description: t.description.unwrap_or_default(),
            input_schema_json: serde_json::to_string(&t.input_schema)
                .unwrap_or_else(|_| "{}".to_owned()),
        })
        .collect())
}

/// Invokes an external MCP tool with SCP provenance wrapping.
#[napi]
#[allow(clippy::unused_async)]
#[allow(clippy::needless_pass_by_value)]
pub async fn mcp_client_invoke(
    handle: &NapiMcpClientHandle,
    tool_name: String,
    input_json: String,
    context_id: String,
    invoker_did: String,
) -> napi::Result<NapiMcpInvokeResult> {
    crate::napi_check_handle!(handle);
    let entry = mcp_client_registry()
        .get(&handle.handle_id)
        .ok_or_else(|| {
            napi::Error::from(ScpNapiError::Transport {
                message: format!("MCP client handle '{}' not found", handle.handle_id),
                code: codes::TRANS_5023.to_owned(),
            })
        })?;

    let input: serde_json::Value = serde_json::from_str(&input_json).map_err(|e| {
        napi::Error::from(ScpNapiError::Transport {
            message: format!("invalid input JSON: {e}"),
            code: codes::VALID_7021.to_owned(),
        })
    })?;

    let client_guard = entry.client.lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Transport {
            message: format!("client lock poisoned: {e}"),
            code: codes::TRANS_5024.to_owned(),
        })
    })?;

    let result = client_guard
        .invoke(&tool_name, input, &context_id, &invoker_did)
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Transport {
                message: format!("tools/call failed: {e}"),
                code: codes::TRANS_5025.to_owned(),
            })
        })?;

    let content_json = serde_json::to_string(&result.content).unwrap_or_else(|_| "[]".to_owned());

    Ok(NapiMcpInvokeResult {
        content_json,
        is_error: result.is_error,
        source: result.provenance.source,
        invoked_by: result.provenance.invoked_by,
        context_id: result.provenance.context,
        // napi-rs uses f64 for numeric fields when crossing the JS boundary.
        // u64 timestamps must be cast to f64 — safe up to 2^53 (year 287396).
        #[allow(clippy::cast_precision_loss)]
        timestamp: result.provenance.timestamp as f64,
    })
}

// ---------------------------------------------------------------------------
// Stdio allowlist error mapping
// ---------------------------------------------------------------------------

/// Maps [`AllowlistError`] to the appropriate [`ScpNapiError`] variant.
///
/// Input-validation errors map to `Validation`. Runtime/policy errors
/// map to `Transport`. Exhaustive match ensures new variants produce
/// a compile error instead of silently falling through.
#[allow(clippy::needless_pass_by_value)]
fn allowlist_err(e: allowlist::AllowlistError) -> ScpNapiError {
    use scp_mcp::allowlist::AllowlistError;
    let msg = e.to_string();
    match e {
        AllowlistError::EmptyEntry
        | AllowlistError::PathInEntry(_)
        | AllowlistError::NulInEntry(_)
        | AllowlistError::ControlCharInEntry(_)
        | AllowlistError::PathInCommand(_)
        | AllowlistError::InvalidCommand(_) => ScpNapiError::Validation {
            message: msg,
            code: codes::VALID_7033.to_owned(),
        },
        AllowlistError::NotAllowed { .. } | AllowlistError::LockPoisoned => {
            ScpNapiError::Transport {
                message: msg,
                code: codes::TRANS_5030.to_owned(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Stdio allowlist configuration (NAPI)
// ---------------------------------------------------------------------------

/// Snapshot of the current stdio allowlist state.
#[napi(object)]
pub struct NapiAllowlistState {
    /// Sorted list of allowed binary basenames.
    pub allowed: Vec<String>,
    /// Whether the allowlist is bypassed entirely (unrestricted mode).
    pub unrestricted: bool,
}

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
/// Throws if any entry is invalid (contains a path, NUL byte, or is empty).
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn mcp_configure_stdio_allowlist(additional_binaries: Vec<String>) -> napi::Result<()> {
    allowlist::configure(&additional_binaries).map_err(|e| napi::Error::from(allowlist_err(e)))?;
    Ok(())
}

/// Disable the stdio allowlist entirely (unrestricted mode).
///
/// After calling this, **any** binary name may be spawned as a subprocess.
/// Only use when the command source is fully trusted.
///
/// # Errors
///
/// Throws if the allowlist lock is poisoned.
#[napi]
pub fn mcp_disable_stdio_allowlist() -> napi::Result<()> {
    allowlist::disable_enforcement().map_err(|e| napi::Error::from(allowlist_err(e)))?;
    Ok(())
}

/// Reset the stdio allowlist to its default state.
///
/// Restores the default binaries, removes any additions, and re-enables
/// enforcement (clears unrestricted mode).
///
/// # Errors
///
/// Throws if the allowlist lock is poisoned.
#[napi]
pub fn mcp_reset_stdio_allowlist() -> napi::Result<()> {
    allowlist::reset().map_err(|e| napi::Error::from(allowlist_err(e)))?;
    Ok(())
}

/// Return the current stdio allowlist state.
///
/// Returns an object with:
/// - `allowed`: sorted list of allowed binary names
/// - `unrestricted`: boolean indicating whether the allowlist is bypassed
///
/// # Errors
///
/// Throws if the allowlist lock is poisoned.
#[napi]
pub fn mcp_get_stdio_allowlist() -> napi::Result<NapiAllowlistState> {
    let state = allowlist::get_state().map_err(|e| napi::Error::from(allowlist_err(e)))?;
    Ok(NapiAllowlistState {
        allowed: state.allowed,
        unrestricted: state.unrestricted,
    })
}
