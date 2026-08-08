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
use scp_mcp::allowlist;
use scp_mcp::client::{McpClient, McpTransport};
use scp_mcp::protocol::{JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};
use scp_mcp::server::{ContextEventPump, ContextProvider};

use crate::error::ScpNapiError;
use crate::runtime::NapiBridgeInstance;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum bytes per line from MCP transport (10 MiB). Prevents OOM from
/// unbounded line reads by a malicious or broken peer.
///
/// Imported from `scp-mcp` rather than redeclared so the client and server
/// halves of the same line protocol cannot drift to different limits.
use scp_mcp::stdio::MAX_LINE_BYTES;

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

/// FFI bridge provider for the MCP server.
///
/// Implements `ContextProvider` by reading this bridge instance's per-context
/// UCAN state (role assignments, outlet registry, Merkle event log) — the same
/// state the `PyO3` reference bridge reads from `FfiBridgeState`. Before
/// #1341's follow-up every query method here returned an empty stand-in
/// (`Vec::new()` / `Array([])`), which the builder tenet forbids on a shipped
/// path: once the resource-authorization gap was closed those placeholders
/// would have become live, serving an empty roster and an empty event log as
/// if they were the real thing.
struct McpNapiBridgeProvider {
    /// Weak reference to the bridge instance whose registries this provider
    /// reads.
    ///
    /// `Weak`, not `Arc`, for the same reason as the `PyO3` and `UniFFI`
    /// providers (#1549 round-2): the MCP server task is spawned on the shared
    /// runtime and is not enrolled in the per-instance `JoinSet`, so an `Arc`
    /// would pin the whole `NapiBridgeInstance` alive for the process when a
    /// caller drops `Scp` without calling `mcpServerStop`.
    bi: std::sync::Weak<NapiBridgeInstance>,
    agent_did: String,
    context_ids: Vec<String>,
}

impl McpNapiBridgeProvider {
    /// Upgrades the stored [`std::sync::Weak`] to a live instance handle.
    fn upgrade_bi(&self) -> Result<Arc<NapiBridgeInstance>, String> {
        self.bi.upgrade().ok_or_else(|| {
            "bridge instance has been dropped — MCP provider cannot service request".to_owned()
        })
    }
}

impl ContextProvider for McpNapiBridgeProvider {
    fn active_context_ids(&self) -> Vec<scp_mcp::namespace::ContextId> {
        // Configured ∩ live: a context the agent has left is no longer served,
        // so its tools and resources disappear from `tools/list` and
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
        let bi = self.upgrade_bi().ok()?;
        crate::runtime::with_context(&bi, context_id, |rt| {
            Ok(rt
                .role_state
                .assignments
                .get(&self.agent_did)
                .map(|assignment| assignment.role_name.clone()))
        })
        .ok()
        .flatten()
    }

    fn agent_did(&self) -> &str {
        &self.agent_did
    }

    fn context_tools(&self, context_id: &str) -> Vec<scp_mcp::server::ContextOutletInfo> {
        let Ok(bi) = self.upgrade_bi() else {
            return Vec::new();
        };
        crate::runtime::with_context(&bi, context_id, |rt| {
            Ok(rt
                .outlet_registry
                .registrations()
                .map(|t| scp_mcp::server::ContextOutletInfo {
                    name: t.name.clone(),
                    description: Some(t.description.clone()),
                    input_schema: t.schema.input_schema.clone(),
                    output_schema: Some(t.schema.output_schema.clone()),
                    admin_only: false,
                    // Carry the registry's authoritative §5.4.2 kind so the
                    // translator surfaces the correct `query.` / `call.` MCP
                    // tool-name prefix — never hardcode Action.
                    kind: t.kind,
                })
                .collect())
        })
        .unwrap_or_default()
    }

    fn validate_capability(&self, context_id: &str, outlet_name: &str) -> Result<(), String> {
        let bi = self.upgrade_bi()?;
        crate::runtime::with_context(&bi, context_id, |rt| {
            // SCP-OUT-014 §5.4.2: the split stem is selected from the outlet's
            // registered kind — a Query grant never authorizes an Action call.
            // An outlet absent from the registry defaults to the Action stem
            // (the stricter of the two), so an unknown name fails closed.
            let kind = rt
                .outlet_registry
                .get(outlet_name)
                .map_or(scp_core::context::outlets::OutletKind::Action, |r| r.kind);
            if scp_core::context::outlets::invoke::has_outlet_invocation_capability(
                &rt.role_state,
                &self.agent_did,
                outlet_name,
                kind,
            ) {
                Ok(())
            } else {
                Err(ScpNapiError::Context {
                    message: "insufficient permissions to invoke outlet".to_owned(),
                    code: codes::TRANS_5012.to_owned(),
                })
            }
        })
        .map_err(|e| e.to_string())
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

    fn validate_resource_access(
        &self,
        context_id: &str,
        resource: scp_mcp::server::ResourceKind,
    ) -> Result<(), String> {
        let bi = self.upgrade_bi()?;
        resource_access_from_role_state(&bi, context_id, &self.agent_did, resource)
    }

    fn context_members(&self, context_id: &str) -> Vec<scp_mcp::server::MemberInfo> {
        let Ok(bi) = self.upgrade_bi() else {
            return Vec::new();
        };
        crate::runtime::with_context(&bi, context_id, |rt| {
            Ok(rt
                .role_state
                .members
                .iter()
                .map(|did| scp_mcp::server::MemberInfo {
                    did: did.clone(),
                    role: rt
                        .role_state
                        .assignments
                        .get(did)
                        .map_or_else(|| "member".to_owned(), |a| a.role_name.clone()),
                })
                .collect())
        })
        .unwrap_or_default()
    }

    fn context_events(&self, context_id: &str) -> serde_json::Value {
        // The EventLog stores Merkle tree leaf hashes, not event payloads.
        // Report count + root, matching the PyO3 and UniFFI bridges.
        let Ok(bi) = self.upgrade_bi() else {
            return serde_json::json!({ "event_count": 0 });
        };
        crate::runtime::with_context(&bi, context_id, |rt| {
            let leaf_count = rt.core.event_log.leaves().len();
            let root = scp_event_log::tree::root(&rt.core.event_log);
            Ok(serde_json::json!({
                "event_count": leaf_count,
                "merkle_root": hex::encode(root),
            }))
        })
        .unwrap_or_else(|_| serde_json::json!({ "event_count": 0 }))
    }
}

/// Answers `ContextProvider::validate_resource_access` from a context's role
/// state.
///
/// `Events` and `Members` require `Capability::MessagesRead`: per spec §5.3.1's
/// role table an `observer` — whose sole capability is `messages:read` — "can
/// see all content and membership", so that grant is exactly the authority to
/// read the event stream and the roster. `Tools` carries no separate grant
/// because its contents are the capability-filtered tool list; an agent with no
/// tool capabilities reads `[]` rather than being denied.
///
/// A context absent from the registry fails closed for every kind.
fn resource_access_from_role_state(
    bi: &NapiBridgeInstance,
    context_id: &str,
    agent_did: &str,
    resource: scp_mcp::server::ResourceKind,
) -> Result<(), String> {
    use scp_core::context::roles::Capability;
    use scp_mcp::server::ResourceKind;

    crate::runtime::with_context(bi, context_id, |rt| {
        let permitted = match resource {
            ResourceKind::Events | ResourceKind::Members => rt
                .role_state
                .member_has_capability(agent_did, &Capability::MessagesRead),
            ResourceKind::Tools => rt.role_state.members.contains(agent_did),
        };
        if permitted {
            Ok(())
        } else {
            Err(ScpNapiError::Context {
                message: format!(
                    "agent lacks messages:read in context '{context_id}' — \
                     required to read scp://{context_id}/{}",
                    resource.uri_suffix()
                ),
                code: codes::TRANS_5012.to_owned(),
            })
        }
    })
    .map_err(|e| e.to_string())
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
/// `pump` carries the honesty invariant: it exists only for a server built by
/// `McpServer::with_event_source`, which is the only constructor that
/// advertises `resources/subscribe`. `None` means the server was built by
/// `McpServer::new`, advertises `resources.subscribe: false`, and rejects the
/// request with a typed error. The capability cannot be advertised without the
/// machinery, because one call produces both.
async fn run_mcp_stdio_server(
    server: Arc<Mutex<scp_mcp::server::McpServer<McpNapiBridgeProvider>>>,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    pump: Option<ContextEventPump>,
) {
    tokio::select! {
        _ = shutdown_rx => {}
        result = scp_mcp::stdio::run_stdio(&server, pump) => {
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
    bi: &Arc<NapiBridgeInstance>,
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

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
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

    // The provider reads this instance's per-context registries through a
    // `Weak`, so the spawned server task cannot pin the instance alive.
    let provider = McpNapiBridgeProvider {
        bi: Arc::downgrade(bi),
        agent_did: config.identity_did,
        context_ids: config.context_ids,
    };
    // One call decides both the advertisement and the delivery machinery.
    let (server, pump) =
        scp_mcp::server::McpServer::with_optional_event_source(provider, context_events);

    let task_handle = crate::runtime().spawn(async move {
        match transport_mode.as_str() {
            "stdio" => {
                run_mcp_stdio_server(Arc::new(Mutex::new(server)), shutdown_rx, pump).await;
            }
            "sse" => {
                let sse_config =
                    scp_mcp::sse::SseConfig::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
                let sse_shutdown = scp_mcp::sse::ShutdownHandle::new();
                let sse_shutdown_trigger = sse_shutdown.clone();
                tokio::spawn(async move {
                    let _ = shutdown_rx.await;
                    sse_shutdown_trigger.shutdown();
                });
                let result = scp_mcp::sse::run_sse(server, sse_config, sse_shutdown, pump).await;
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

    use scp_core::context::membership::{ContextEvent, ContextEventEnvelope};
    use scp_mcp::protocol::{
        JSONRPC_VERSION, METHOD_INITIALIZE, METHOD_NOT_FOUND, METHOD_RESOURCES_SUBSCRIBE,
        METHOD_RESOURCES_UPDATED, RequestId,
    };
    use tokio::sync::broadcast;

    const SUB_CTX: &str = "ctx-subscribe-napi";
    const SUB_URI: &str = "scp://ctx-subscribe-napi/events";
    const AGENT_DID: &str = "did:test:napi-mcp-subscribe";

    /// Builds a bridge instance with `SUB_CTX` registered and `AGENT_DID` as
    /// its creator, plus an `McpServer` over the REAL NAPI bridge provider —
    /// the exact type `mcp_server_create_on` constructs.
    ///
    /// Returning the `Arc` matters: the provider holds a `Weak`, so dropping
    /// the instance would make every provider method degrade.
    fn napi_mcp_fixture() -> (
        Arc<NapiBridgeInstance>,
        scp_mcp::server::McpServer<McpNapiBridgeProvider>,
    ) {
        let bi = Arc::new(NapiBridgeInstance::new_napi());
        crate::runtime::register_ffi_state(&bi, SUB_CTX, AGENT_DID, &[])
            .expect("registering context FFI state must succeed");
        let provider = McpNapiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: AGENT_DID.to_owned(),
            context_ids: vec![SUB_CTX.to_owned()],
        };
        let server = scp_mcp::server::McpServer::new(provider);
        (bi, server)
    }

    /// The same fixture with a live event source wired, as
    /// `mcp_server_create_on` does when the supervisor yields a receiver.
    fn napi_mcp_fixture_wired() -> (
        Arc<NapiBridgeInstance>,
        scp_mcp::server::McpServer<McpNapiBridgeProvider>,
        scp_mcp::server::ContextEventPump,
        broadcast::Sender<ContextEventEnvelope>,
    ) {
        let bi = Arc::new(NapiBridgeInstance::new_napi());
        crate::runtime::register_ffi_state(&bi, SUB_CTX, AGENT_DID, &[])
            .expect("registering context FFI state must succeed");
        let provider = McpNapiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: AGENT_DID.to_owned(),
            context_ids: vec![SUB_CTX.to_owned()],
        };
        let (tx, rx) = broadcast::channel(16);
        let (server, pump) = scp_mcp::server::McpServer::with_event_source(provider, rx);
        (bi, server, pump, tx)
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
    /// `mcp_server_create_on` produces when `Supervisor::subscribe_events()`
    /// yields `None` — the server must advertise `resources.subscribe: false`
    /// AND reject `resources/subscribe`. The replaced bridge behaviour
    /// advertised the capability and then answered the call from the provider,
    /// so a client could hold a subscription that would never fire.
    #[test]
    fn mcp_subscribe_rejected_when_no_event_source_wired_napi() {
        let (_bi, mut server) = napi_mcp_fixture();
        assert!(
            !server.event_source_wired(),
            "a server built by McpServer::new must fail closed on subscriptions"
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

    /// Positive half of #1341. `McpServer::with_event_source` is the only
    /// constructor that sets the flag, and it yields the pump in the same
    /// call. The server then advertises the capability, accepts the
    /// subscription, and `notifications_for_event` — the function the pump
    /// drives for each received `ContextEvent` — emits a real
    /// `notifications/resources/updated` for the subscribed URI.
    #[test]
    fn mcp_subscribe_delivers_notifications_when_event_source_wired_napi() {
        let (_bi, mut server, _pump, _tx) = napi_mcp_fixture_wired();
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

    /// The NAPI provider must serve REAL context state, not empty stand-ins.
    ///
    /// Before this fix `context_members` returned `Vec::new()`,
    /// `context_events` returned `[]` and `context_tools` returned
    /// `Vec::new()`, while `validate_capability` returned `Err` unconditionally
    /// — dead placeholders on a shipped path that would have gone live the
    /// moment resource authorization started admitting anyone.
    #[test]
    fn napi_provider_serves_real_context_state() {
        use scp_mcp::server::{ContextProvider as _, ResourceKind};

        let (bi, _server) = napi_mcp_fixture();
        let provider = McpNapiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: AGENT_DID.to_owned(),
            context_ids: vec![SUB_CTX.to_owned()],
        };

        // The creator is a real member with a real role.
        let members = provider.context_members(SUB_CTX);
        assert!(
            members.iter().any(|m| m.did == AGENT_DID),
            "context_members must report the real roster, got: {members:?}"
        );
        assert_eq!(
            provider.agent_role(SUB_CTX).as_deref(),
            Some("admin"),
            "agent_role must resolve the creator's real role assignment"
        );

        // The event log is reported by count + Merkle root, matching PyO3 and
        // UniFFI — never a bare `[]`.
        let events = provider.context_events(SUB_CTX);
        assert!(
            events.get("event_count").is_some() && events.get("merkle_root").is_some(),
            "context_events must report real Merkle event-log state, got: {events}"
        );

        // The creator holds `messages:read`, so the resource gate admits it.
        for kind in [
            ResourceKind::Events,
            ResourceKind::Members,
            ResourceKind::Tools,
        ] {
            assert!(
                provider.validate_resource_access(SUB_CTX, kind).is_ok(),
                "the context creator must be able to read scp://{SUB_CTX}/{}",
                kind.uri_suffix()
            );
        }

        // A DID that is not a member is denied — the gate is real, not a
        // blanket allow.
        let outsider = McpNapiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: "did:test:not-a-member".to_owned(),
            context_ids: vec![SUB_CTX.to_owned()],
        };
        assert!(
            outsider
                .validate_resource_access(SUB_CTX, ResourceKind::Members)
                .is_err(),
            "a non-member must not be able to read the roster"
        );
        assert!(
            outsider.active_context_ids().is_empty(),
            "a non-member must not have the context in its served set"
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
