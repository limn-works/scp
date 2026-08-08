//! napi-rs bridge for MCP (Model Context Protocol) operations.
//!
//! Exposes MCP server and client operations to Node.js/Bun:
//!
//! - `mcp_server_create` — Start an MCP server exposing SCP context outlets.
//! - `mcp_server_stop` — Stop a running MCP server.
//! - `mcp_client_connect_stdio` — Connect to an external MCP server via stdio.
//! - `mcp_client_connect_sse` — Connect to an external MCP server via SSE.
//! - `mcp_client_disconnect` — Disconnect from an external MCP server.
//! - `mcp_client_list_tools` — List outlets from an external MCP server.
//! - `mcp_client_invoke` — Invoke an external MCP outlet with SCP provenance.
//!
//! The MCP bridge uses opaque string handles to track server and client
//! instances in global registries (matching the `UniFFI` bridge pattern).
//!
//! See ADR-015 in `.docs/adrs/phase-3.md`.

use scp_ffi_common::error_codes as codes;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use napi_derive::napi;
use scp_core::context::membership::ContextEvent;
use scp_mcp::allowlist;
use scp_mcp::client::{McpClient, McpTransport};
use scp_mcp::protocol::{JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};
use scp_mcp::server::ContextProvider;
use tokio::sync::broadcast;

use crate::error::ScpNapiError;
use crate::runtime::NapiBridgeInstance;

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

/// Outlet definition from an external MCP server.
#[napi(object)]
pub struct NapiMcpToolInfo {
    /// Outlet name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// JSON Schema for outlet input (as a JSON string).
    pub input_schema_json: String,
}

/// Result of invoking an external MCP outlet with SCP provenance.
#[napi(object)]
pub struct NapiMcpInvokeResult {
    /// Outlet output content as serialized JSON.
    pub content_json: String,
    /// Whether the outlet call resulted in an error.
    pub is_error: bool,
    /// Source of the result, formatted as `"mcp:{outlet_name}"`.
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
pub(crate) struct McpServerEntry {
    pub(crate) shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    pub(crate) _task_handle: tokio::task::JoinHandle<()>,
    pub(crate) stopped: bool,
}

/// Internal state for an active MCP client connection.
pub(crate) struct McpClientEntry {
    pub(crate) client: Mutex<McpClient<McpClientTransportWrapper>>,
}

// Phase D (#1695): EMPTY_*_REGISTRY fallbacks and the `mcp_*_registry()`
// default-bridge lookup helpers were deleted. All MCP paths route through
// `bi.mcp_server_registry()` / `bi.mcp_client_registry()` against an
// explicit `&NapiBridgeInstance`.

fn mcp_handle_id(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

// ---------------------------------------------------------------------------
// Transport implementations
// ---------------------------------------------------------------------------

/// Transport wrapper that delegates to either stdio or SSE.
pub(crate) enum McpClientTransportWrapper {
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
pub(crate) struct StdioMcpTransport {
    inner: Mutex<StdioTransportInner>,
}

struct StdioTransportInner {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
}

impl StdioMcpTransport {
    fn spawn(
        allowlist: &Mutex<allowlist::StdioAllowlist>,
        command: &[String],
    ) -> Result<Self, String> {
        let (cmd, args) = command
            .split_first()
            .ok_or_else(|| "command list is empty".to_owned())?;

        // Validate the command against the per-instance stdio allowlist
        // (defense-in-depth). Uses the validated basename for Command::new
        // to prevent path bypass. Hold the lock only across `validate_command`,
        // then drop before spawning.
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
pub(crate) struct SseMcpTransport {
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
/// delegating to the context manager for outlet and state queries.
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
                 from Supervisor before exposing MCP in production."
            );
        });
        None
    }

    fn agent_did(&self) -> &str {
        &self.agent_did
    }

    fn context_tools(&self, _context_id: &str) -> Vec<scp_mcp::server::ContextOutletInfo> {
        Vec::new()
    }

    fn validate_capability(&self, _context_id: &str, _outlet_name: &str) -> Result<(), String> {
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

    fn invoke_outlet(
        &self,
        _context_id: &str,
        _outlet_name: &str,
        _arguments: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        Err(
            "outlet invocation through MCP server requires Supervisor outlet registry integration"
                .to_owned(),
        )
    }

    fn context_members(&self, _context_id: &str) -> Vec<scp_mcp::server::MemberInfo> {
        Vec::new()
    }

    fn context_events(&self, _context_id: &str) -> serde_json::Value {
        serde_json::Value::Array(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// MCP stdio server loop
// ---------------------------------------------------------------------------

/// Runs the MCP server over stdio until the shutdown signal fires or stdin
/// reaches EOF.
///
/// The read loop, the stdout writer, and the resource-subscription event pump
/// all live in [`scp_mcp::stdio::run_stdio`]; this wrapper only owns the
/// shutdown arm. Sharing that loop is what keeps JSON-RPC *notification*
/// parsing correct (messages carrying no `id` never produce a response, and a
/// bare `JsonRpcRequest` decode rejects them) and keeps stdout serialized
/// between responses and subscription notifications.
///
/// `context_events` carries the honesty invariant: `Some` enables
/// `resources/subscribe` and starts the delivery pump in the same step, `None`
/// advertises `resources.subscribe: false` and rejects the request with a
/// typed error. The capability is never advertised without the machinery.
async fn run_mcp_stdio_server(
    server: Arc<Mutex<scp_mcp::server::McpServer<McpNapiBridgeProvider>>>,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    context_events: Option<broadcast::Receiver<(String, ContextEvent)>>,
) {
    tokio::select! {
        _ = shutdown_rx => {}
        result = scp_mcp::stdio::run_stdio(&server, context_events) => {
            if let Err(e) = result {
                tracing::error!("MCP stdio server error: {e}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`mcp_server_create`].
#[allow(clippy::unused_async)]
pub(crate) async fn mcp_server_create_on(
    bi: &NapiBridgeInstance,
    config: NapiMcpServerConfig,
) -> napi::Result<NapiMcpServerHandle> {
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

    // Resource subscriptions are backed by the supervisor's context event
    // broadcast channel. Subscribe *before* spawning so no event emitted
    // between here and the transport loop starting is missed.
    //
    // `subscribe_events()` returns `None` only for a supervisor built without
    // the channel; every NAPI supervisor path enables it (see
    // `crate::runtime::build_supervisor_arc`). When it is `None` the transport
    // advertises `resources.subscribe: false` and rejects
    // `resources/subscribe` — the capability is honestly absent rather than
    // accepted-and-never-delivered.
    // Absence degrades only this capability: the server still serves `tools/*`
    // and `resources/list|read`, and honestly advertises
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

    let task_handle = crate::runtime().spawn(async move {
        match transport_mode.as_str() {
            "stdio" => {
                run_mcp_stdio_server(server_clone, shutdown_rx, context_events).await;
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
                let result =
                    scp_mcp::sse::run_sse(sse_server, sse_config, sse_shutdown, context_events)
                        .await;
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

    bi.mcp_server_registry().insert(handle_id.clone(), entry);
    crate::increment_handle_count();

    Ok(NapiMcpServerHandle {
        handle_id,
        instance_id: bi.instance_id(),
    })
}

/// Per-bridge-instance implementation of [`mcp_server_stop`].
#[allow(clippy::unused_async)]
pub(crate) async fn mcp_server_stop_on(
    bi: &NapiBridgeInstance,
    handle: &NapiMcpServerHandle,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, handle);
    let mut entry = bi
        .mcp_server_registry()
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
    bi.mcp_server_registry().remove(&handle.handle_id);

    Ok(())
}

/// Per-bridge-instance implementation of [`mcp_client_connect_stdio`].
#[allow(clippy::unused_async)]
pub(crate) async fn mcp_client_connect_stdio_on(
    bi: &NapiBridgeInstance,
    command: Vec<String>,
) -> napi::Result<NapiMcpClientHandle> {
    if command.is_empty() {
        return Err(ScpNapiError::Transport {
            message: "command must be a non-empty list".to_owned(),
            code: codes::TRANS_5014.to_owned(),
        }
        .into());
    }

    let transport = StdioMcpTransport::spawn(bi.core.mcp_allowlist(), &command).map_err(|e| {
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

    bi.mcp_client_registry().insert(handle_id.clone(), entry);
    crate::increment_handle_count();

    Ok(NapiMcpClientHandle {
        handle_id,
        instance_id: bi.instance_id(),
    })
}

/// Per-bridge-instance implementation of [`mcp_client_connect_sse`].
#[allow(clippy::unused_async)]
pub(crate) async fn mcp_client_connect_sse_on(
    bi: &NapiBridgeInstance,
    url: String,
) -> napi::Result<NapiMcpClientHandle> {
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

    bi.mcp_client_registry().insert(handle_id.clone(), entry);
    crate::increment_handle_count();

    Ok(NapiMcpClientHandle {
        handle_id,
        instance_id: bi.instance_id(),
    })
}

/// Per-bridge-instance implementation of [`mcp_client_disconnect`].
#[allow(clippy::unused_async)]
pub(crate) async fn mcp_client_disconnect_on(
    bi: &NapiBridgeInstance,
    handle: &NapiMcpClientHandle,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, handle);
    let removed = bi.mcp_client_registry().remove(&handle.handle_id);
    if removed.is_none() {
        return Err(ScpNapiError::Transport {
            message: format!("MCP client handle '{}' not found", handle.handle_id),
            code: codes::TRANS_5019.to_owned(),
        }
        .into());
    }
    Ok(())
}

/// Per-bridge-instance implementation of [`mcp_client_list_tools`].
#[allow(clippy::unused_async)]
pub(crate) async fn mcp_client_list_tools_on(
    bi: &NapiBridgeInstance,
    handle: &NapiMcpClientHandle,
) -> napi::Result<Vec<NapiMcpToolInfo>> {
    crate::napi_check_handle!(&bi.core, handle);
    let entry = bi
        .mcp_client_registry()
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

    let outlets = client_guard.list_tools().map_err(|e| {
        napi::Error::from(ScpNapiError::Transport {
            message: format!("tools/list failed: {e}"),
            code: codes::TRANS_5022.to_owned(),
        })
    })?;

    Ok(outlets
        .into_iter()
        .map(|t| NapiMcpToolInfo {
            name: t.name,
            description: t.description.unwrap_or_default(),
            input_schema_json: serde_json::to_string(&t.input_schema)
                .unwrap_or_else(|_| "{}".to_owned()),
        })
        .collect())
}

/// Per-bridge-instance implementation of [`mcp_client_invoke`].
#[allow(clippy::unused_async)]
#[allow(clippy::needless_pass_by_value)]
pub(crate) async fn mcp_client_invoke_on(
    bi: &NapiBridgeInstance,
    handle: &NapiMcpClientHandle,
    outlet_name: String,
    input_json: String,
    context_id: String,
    invoker_did: String,
) -> napi::Result<NapiMcpInvokeResult> {
    crate::napi_check_handle!(&bi.core, handle);
    let entry = bi
        .mcp_client_registry()
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
        .invoke(&outlet_name, input, &context_id, &invoker_did)
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
///
/// Mutex poisoning is NOT modelled by `AllowlistError` — the allowlist
/// is now per-instance (`CoreFields::mcp_allowlist`). Each call site maps
/// `PoisonError` to its own typed transport error before invoking allowlist
/// methods.
// `clippy::match_same_arms` — the explicit wildcard arm at the end is intentional:
// `AllowlistError` is `#[non_exhaustive]`, so future variants must compile, and
// classifying them as a validation error fails closed. Folding the wildcard into
// the named OR-chain would erase that documentation.
#[allow(clippy::needless_pass_by_value, clippy::match_same_arms)]
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
        AllowlistError::NotAllowed { .. } => ScpNapiError::Transport {
            message: msg,
            code: codes::TRANS_5030.to_owned(),
        },
        // `AllowlistError` is `#[non_exhaustive]` — fail closed for any
        // future variant by classifying as a validation error rather than
        // letting an unknown policy decision become a permissive path.
        _ => ScpNapiError::Validation {
            message: msg,
            code: codes::VALID_7033.to_owned(),
        },
    }
}

/// Maps a `PoisonError` from the per-instance allowlist mutex to a NAPI
/// transport error.
fn allowlist_lock_poisoned() -> ScpNapiError {
    ScpNapiError::Transport {
        message: "stdio allowlist lock poisoned".to_owned(),
        code: codes::TRANS_5030.to_owned(),
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

/// Per-bridge-instance implementation of `mcp_configure_stdio_allowlist`.
///
/// Operates on `bi.core.mcp_allowlist()` — disabling enforcement or
/// extending the allow set on one `Scp` does NOT leak into another instance
/// (per-instance migration).
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn mcp_configure_stdio_allowlist_on(
    bi: &NapiBridgeInstance,
    additional_binaries: Vec<String>,
) -> napi::Result<()> {
    let instance_id = bi.core.instance_id();
    bi.core
        .with_mcp_allowlist(|a| a.configure(&additional_binaries))
        .map_err(|_| napi::Error::from(allowlist_lock_poisoned()))?
        .map_err(|e| napi::Error::from(allowlist_err(e)))?;
    tracing::info!(
        instance_id,
        added = ?additional_binaries,
        "MCP stdio allowlist extended"
    );
    Ok(())
}

/// Per-bridge-instance implementation of `mcp_disable_stdio_allowlist`.
///
/// Disables enforcement on THIS instance only. Other `Scp` instances are
/// unaffected.
pub(crate) fn mcp_disable_stdio_allowlist_on(bi: &NapiBridgeInstance) -> napi::Result<()> {
    let instance_id = bi.core.instance_id();
    bi.core
        .with_mcp_allowlist(|a| a.disable_enforcement(instance_id))
        .map_err(|_| napi::Error::from(allowlist_lock_poisoned()))?;
    Ok(())
}

/// Per-bridge-instance implementation of `mcp_reset_stdio_allowlist`.
///
/// Resets THIS instance's allowlist to defaults; does not affect peers.
pub(crate) fn mcp_reset_stdio_allowlist_on(bi: &NapiBridgeInstance) -> napi::Result<()> {
    let instance_id = bi.core.instance_id();
    bi.core
        .with_mcp_allowlist(scp_mcp::allowlist::StdioAllowlist::reset)
        .map_err(|_| napi::Error::from(allowlist_lock_poisoned()))?;
    tracing::info!(instance_id, "MCP stdio allowlist reset to defaults");
    Ok(())
}

/// Per-bridge-instance implementation of `mcp_get_stdio_allowlist`.
///
/// Returns a snapshot of THIS instance's allowlist.
pub(crate) fn mcp_get_stdio_allowlist_on(
    bi: &NapiBridgeInstance,
) -> napi::Result<NapiAllowlistState> {
    let state = bi
        .core
        .with_mcp_allowlist(|a| a.snapshot())
        .map_err(|_| napi::Error::from(allowlist_lock_poisoned()))?;
    Ok(NapiAllowlistState {
        allowed: state.allowed,
        unrestricted: state.unrestricted,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::runtime::NapiBridgeInstance;

    /// WU6: Two-instance regression test — disabling enforcement via the
    /// public `mcp_disable_stdio_allowlist_on` entry point on one instance
    /// MUST NOT leak into another. Drives the public surface so the test
    /// catches a regression where the helper silently locks the wrong
    /// mutex or fails to plumb `instance_id`.
    #[test]
    fn allowlist_disable_does_not_leak_across_instances_napi() {
        let a = NapiBridgeInstance::new_napi();
        let b = NapiBridgeInstance::new_napi();

        mcp_disable_stdio_allowlist_on(&a).expect("disable on a should succeed");

        // `b` snapshot remains restricted (default allowlist, enforcement on).
        let b_state = mcp_get_stdio_allowlist_on(&b).expect("snapshot b");
        assert!(
            !b_state.unrestricted,
            "instance b must remain restricted after a is disabled"
        );

        // Sanity: `a` reports unrestricted on its own snapshot.
        let a_state = mcp_get_stdio_allowlist_on(&a).expect("snapshot a");
        assert!(a_state.unrestricted);
    }

    /// WU6 supplement: `configure_on` on one instance must not bleed into
    /// another's allow set.
    #[test]
    fn allowlist_configure_does_not_leak_across_instances_napi() {
        let a = NapiBridgeInstance::new_napi();
        let b = NapiBridgeInstance::new_napi();

        mcp_configure_stdio_allowlist_on(&a, vec!["custom-a".to_owned()]).expect("configure on a");

        let a_state = mcp_get_stdio_allowlist_on(&a).expect("snapshot a");
        assert!(a_state.allowed.contains(&"custom-a".to_owned()));

        let b_state = mcp_get_stdio_allowlist_on(&b).expect("snapshot b");
        assert!(!b_state.allowed.contains(&"custom-a".to_owned()));
    }

    // -----------------------------------------------------------------------
    // Resource subscriptions (#1341)
    //
    // `McpNapiBridgeProvider::subscribe_resource` is gone: the capability is
    // no longer a provider concern. The transport owns it, and it is gated on
    // holding a real `Supervisor` event receiver. These tests assert that
    // honesty invariant from the NAPI side — advertisement and acceptance move
    // together, and a wired bridge actually yields a receiver.
    // -----------------------------------------------------------------------

    use scp_mcp::protocol::{
        JSONRPC_VERSION, METHOD_INITIALIZE, METHOD_NOT_FOUND, METHOD_RESOURCES_SUBSCRIBE,
        METHOD_RESOURCES_UPDATED, RequestId,
    };

    const SUB_CTX: &str = "ctx-subscribe-napi";
    const SUB_URI: &str = "scp://ctx-subscribe-napi/events";

    /// Builds an `McpServer` over the real NAPI bridge provider — the exact
    /// type `mcp_server_create_on` constructs.
    fn napi_mcp_server() -> scp_mcp::server::McpServer<McpNapiBridgeProvider> {
        scp_mcp::server::McpServer::new(McpNapiBridgeProvider {
            agent_did: "did:test:napi-mcp-subscribe".to_owned(),
            context_ids: vec![SUB_CTX.to_owned()],
        })
    }

    fn mcp_request(method: &str, params: serde_json::Value) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            method: method.to_owned(),
            params: Some(params),
            id: RequestId::Number(1),
        }
    }

    /// Completes the MCP handshake and returns the advertised
    /// `capabilities.resources.subscribe` flag.
    fn initialize_and_read_subscribe_flag(
        server: &mut scp_mcp::server::McpServer<McpNapiBridgeProvider>,
    ) -> bool {
        let response = server
            .handle_request(&mcp_request(
                METHOD_INITIALIZE,
                serde_json::json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": { "name": "napi-test" },
                }),
            ))
            .expect("initialize must produce a response");
        let result = response.result.expect("initialize must succeed");
        result["capabilities"]["resources"]["subscribe"]
            .as_bool()
            .expect("resources.subscribe must be advertised as a bool")
    }

    /// Negative half of #1341. With no event receiver wired — what
    /// `run_stdio(.., None)` / `run_sse(.., None)` produce when
    /// `Supervisor::subscribe_events()` yields `None` — the server must
    /// advertise `resources.subscribe: false` AND reject
    /// `resources/subscribe`. The replaced bridge behaviour advertised the
    /// capability and then answered the call from the provider, so a client
    /// could hold a subscription that would never fire.
    #[test]
    fn mcp_subscribe_rejected_when_no_event_source_wired_napi() {
        let mut server = napi_mcp_server();
        assert!(
            !server.subscriptions_enabled(),
            "a freshly constructed server must fail closed on subscriptions"
        );
        assert!(
            !initialize_and_read_subscribe_flag(&mut server),
            "an unwired server must advertise resources.subscribe: false"
        );

        let response = server
            .handle_request(&mcp_request(
                METHOD_RESOURCES_SUBSCRIBE,
                serde_json::json!({ "uri": SUB_URI }),
            ))
            .expect("resources/subscribe must produce a response");
        let error = response
            .error
            .expect("resources/subscribe must be rejected when no event source is wired");
        assert_eq!(
            error.code, METHOD_NOT_FOUND,
            "rejection must be a typed method-not-found, got: {error:?}"
        );
        assert!(
            !server.is_subscribed(SUB_URI),
            "a rejected subscribe must not register a subscription"
        );
    }

    /// Positive half of #1341. When `mcp_server_create_on` hands the transport
    /// a live receiver, `run_stdio` / `run_sse` call `enable_subscriptions()`
    /// (the call made directly here) in the same step that starts the pump.
    /// The server then advertises the capability, accepts the subscription,
    /// and `notifications_for_event` — the function the pump drives for each
    /// received `ContextEvent` — emits a real
    /// `notifications/resources/updated` for the subscribed URI.
    #[test]
    fn mcp_subscribe_delivers_notifications_when_event_source_wired_napi() {
        let mut server = napi_mcp_server();
        server.enable_subscriptions();
        assert!(
            initialize_and_read_subscribe_flag(&mut server),
            "a wired server must advertise resources.subscribe: true"
        );

        let response = server
            .handle_request(&mcp_request(
                METHOD_RESOURCES_SUBSCRIBE,
                serde_json::json!({ "uri": SUB_URI }),
            ))
            .expect("resources/subscribe must produce a response");
        assert!(
            response.error.is_none(),
            "subscribe must succeed on a wired server, got: {:?}",
            response.error
        );
        assert!(server.is_subscribed(SUB_URI));

        // `ContextEvent::Expired` invalidates the events/members/tools
        // resources, so the pump must push an update for the subscribed URI.
        let notifications = server.notifications_for_event(SUB_CTX, &ContextEvent::Expired);
        assert!(
            notifications.iter().any(|n| {
                n.method == METHOD_RESOURCES_UPDATED
                    && n.params
                        .as_ref()
                        .and_then(|p| p.get("uri"))
                        .and_then(serde_json::Value::as_str)
                        == Some(SUB_URI)
            }),
            "a subscribed resource must receive notifications/resources/updated, got: {notifications:?}"
        );
    }

    /// Wiring guard for #1341: `mcp_server_create_on` sources its receiver
    /// from `Supervisor::subscribe_events()`. Every NAPI supervisor path
    /// enables the broadcast channel (`build_supervisor_arc`), so that call
    /// must yield `Some` — were it to regress to `None`, a fully-wired bridge
    /// would silently downgrade to advertising `resources.subscribe: false`.
    #[test]
    fn supervisor_yields_context_event_receiver_for_mcp_napi() {
        let bi = NapiBridgeInstance::new_napi();
        crate::runtime::init_supervisor_for_test_on(&bi);

        let supervisor =
            crate::runtime::supervisor(&bi).expect("supervisor must be attached after init");
        assert!(
            supervisor.subscribe_events().is_some(),
            "the NAPI supervisor must expose a context event receiver so MCP \
             resource subscriptions are wired rather than advertised-and-dropped"
        );
    }

    /// A missing `Supervisor` degrades ONLY the subscription capability — it
    /// must not fail MCP serving outright.
    ///
    /// `tools/*` and `resources/list|read` are served from the FFI bridge
    /// state, not the supervisor, so denying them over an unavailable optional
    /// feature would be a regression. The honest outcome is
    /// `resources.subscribe: false` plus a typed rejection of
    /// `resources/subscribe` — never a silent accept.
    #[test]
    fn missing_supervisor_degrades_subscriptions_not_the_whole_server_napi() {
        let bi = NapiBridgeInstance::new_napi();

        // No supervisor attached: the event source resolves to `None` rather
        // than propagating an error out of MCP serve.
        assert!(
            crate::runtime::supervisor(&bi).is_err(),
            "precondition: this instance has no supervisor attached"
        );

        // The resolution `mcp_server_create_on` performs must yield `None`,
        // NOT propagate the error — that is what keeps serving alive. The
        // honest `subscribe: false` + typed rejection that follows from `None`
        // is covered by `mcp_subscribe_rejected_when_no_event_source_wired_napi`.
        let context_events = crate::runtime::supervisor(&bi)
            .ok()
            .and_then(|supervisor| supervisor.subscribe_events());
        assert!(
            context_events.is_none(),
            "an unattached supervisor must degrade to no event source"
        );
    }
}
