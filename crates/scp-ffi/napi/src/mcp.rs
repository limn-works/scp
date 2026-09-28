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
use std::io::{BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use napi_derive::napi;
use scp_mcp::allowlist;
use scp_mcp::client::{McpClient, McpTransport};
use scp_mcp::protocol::{JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};
use scp_mcp::server::{ContextProvider, McpServerForTransport};

use crate::error::ScpNapiError;
use crate::runtime::NapiBridgeInstance;

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
    /// Shared so a call clones it out of the registry and drops the shard
    /// guard before its network round trip; a disconnect or connect on the
    /// same shard then never waits on a silent server.
    pub(crate) client: Arc<Mutex<McpClient<McpClientTransportWrapper>>>,
    /// A stdio client's server process, which `mcp_client_disconnect_on`
    /// kills directly: an in-flight call's clone of `client` would otherwise
    /// keep the process alive, and a blocking thread parked on its stdout,
    /// for as long as the server stays silent. `None` for an SSE client,
    /// whose reads time out.
    pub(crate) stdio_server: Option<Arc<Mutex<std::process::Child>>>,
}

// Phase D (#1695): EMPTY_*_REGISTRY fallbacks and the `mcp_*_registry()`
// default-bridge lookup helpers were deleted. All MCP paths route through
// `bi.mcp_server_registry()` / `bi.mcp_client_registry()` against an
// explicit `&NapiBridgeInstance`.

/// Runs an MCP client's blocking I/O on tokio's blocking pool, so a slow or
/// silent server holds a blocking thread rather than an async worker that
/// the bridge's other tasks share. `code` names the operation in the error a
/// failed task returns.
async fn run_mcp_client_io<T: Send + 'static>(
    code: &str,
    io: impl FnOnce() -> Result<T, ScpNapiError> + Send + 'static,
) -> napi::Result<T> {
    tokio::task::spawn_blocking(io)
        .await
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Transport {
                message: format!("MCP client task failed: {e}"),
                code: code.to_owned(),
            })
        })?
        .map_err(napi::Error::from)
}

fn mcp_handle_id(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

// ---------------------------------------------------------------------------
// Transport implementations
// ---------------------------------------------------------------------------

/// Transport wrapper that delegates to either stdio or SSE.
pub(crate) enum McpClientTransportWrapper {
    Stdio(StdioMcpTransport),
    Sse(scp_mcp::sse_client::SseClientTransport),
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
    /// The server process, apart from the pipes an in-flight call holds, so
    /// a disconnect can stop it while a call waits on its stdout.
    child: Arc<Mutex<std::process::Child>>,
    inner: Mutex<StdioTransportInner>,
}

struct StdioTransportInner {
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
            child: Arc::new(Mutex::new(child)),
            inner: Mutex::new(StdioTransportInner { stdin, reader }),
        })
    }

    /// The server process, for [`McpClientEntry::stdio_server`].
    fn server_process(&self) -> Arc<Mutex<std::process::Child>> {
        Arc::clone(&self.child)
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

        // Read until this request's response, each line bounded to prevent
        // OOM: the server interleaves notifications on the same stream.
        scp_mcp::stdio::read_response(&mut guard.reader, &request.id)
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
        scp_mcp::stdio::stop_server_process(&self.child);
    }
}

// ---------------------------------------------------------------------------
// MCP FFI bridge context provider
// ---------------------------------------------------------------------------

/// FFI bridge provider for the MCP server.
///
/// Implements `ContextProvider` for one bridge instance. With a supervisor
/// attached, the provider reads each context's role state and event log from
/// the actor ([`live_role_state`] and `context_events`). With no supervisor
/// attached, it reads the bridge's own per-context copy of both. It reads the
/// outlet registry from the bridge's per-context state in either case. A read
/// that fails returns an error, never an empty roster, log or outlet list.
struct McpNapiBridgeProvider {
    /// Weak reference to the bridge instance whose registries this provider
    /// reads.
    ///
    /// `Weak`, not `Arc`, for the same reason as the `PyO3` and `UniFFI`
    /// providers: the MCP server task is spawned on the shared
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

/// Reads `context_id`'s current role state for an MCP authorization.
///
/// With a supervisor attached, the answer is the actor's role state, never this
/// bridge's copy (`UcanContextState.role_state`). Only the bridge's own join,
/// leave and governance calls resync that copy. A change the actor applies from
/// an inbound commit, such as another admin revoking this agent's
/// `messages:read` or removing it, never reaches the copy by itself, so a gate
/// reading the copy keeps authorizing the agent after the revocation. The
/// `UniFFI` provider asks the actor on every read for the same reason.
///
/// The function writes nothing back to the copy. The MCP transport task and the
/// notification pump call it concurrently with the bridge's own calls, so a
/// write-back could replace a newer copy with the older snapshot this call
/// read.
///
/// With no supervisor attached there is no actor and no inbound path, so the
/// copy is the context's only role state and is read as it stands.
///
/// # Errors
///
/// Fails when the actor does not hold the context or cannot be asked, and,
/// with no supervisor attached, when the bridge holds no copy of the context;
/// the caller then denies, because it cannot learn the current role state. The
/// message names whichever of the two held nothing.
fn live_role_state(
    bi: &NapiBridgeInstance,
    context_id: &str,
) -> Result<scp_core::context::roles::ContextRoleState, String> {
    held_role_state(bi, context_id)?.ok_or_else(|| {
        if bi.core.try_supervisor().is_some() {
            format!("context '{context_id}' is not held by the supervisor")
        } else {
            format!(
                "context '{context_id}' is not held by this bridge, and no supervisor is \
                 attached"
            )
        }
    })
}

/// Reads `context_id`'s current role state from the source [`live_role_state`]
/// names, and separates the two outcomes that function merges: `Ok(None)` when
/// the actor holds no such context (with no supervisor, when the bridge holds
/// no copy), and `Err` when the read itself failed.
///
/// # Errors
///
/// Fails when the actor cannot be asked or does not answer: from a
/// current-thread runtime, or when
/// `Supervisor::get_role_state_checked`
/// fails, which it does for a busy actor and for a context the crash watchdog
/// poisoned or is respawning, so none of those reads as `Ok(None)`.
fn held_role_state(
    bi: &NapiBridgeInstance,
    context_id: &str,
) -> Result<Option<scp_core::context::roles::ContextRoleState>, String> {
    let Some(supervisor) = bi.core.try_supervisor() else {
        // The closure cannot fail, so an error from `with_context` means the
        // bridge holds no copy of the context.
        return Ok(
            crate::runtime::with_context(bi, context_id, |rt| Ok(rt.role_state.clone())).ok(),
        );
    };
    let supervisor = Arc::clone(supervisor);
    let id = context_id.to_owned();
    let query = async move {
        supervisor
            .get_role_state_checked(&id)
            .await
            .map_err(|e| format!("role state of context '{id}' could not be read: {e}"))
    };
    match tokio::runtime::Handle::try_current() {
        // Inside the MCP transport task: the actor runs on this runtime's
        // other workers while this one blocks.
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| handle.block_on(query))
        }
        // A current-thread runtime would have to run the actor on the thread
        // this call blocks.
        Ok(_) => Err(format!(
            "cannot read the role state of context '{context_id}' from a \
             current-thread runtime"
        )),
        Err(_) => crate::runtime().block_on(query),
    }
}

/// Why the NAPI MCP server lists no tools and refuses every `tools/call`: this
/// bridge's `ContextProvider::invoke_outlet` is not implemented, so it reports
/// the capability as absent rather than advertising tools it cannot run. The
/// `PyO3` and `UniFFI` providers do run outlets from `tools/call`.
// Stub — see SCP-048
const OUTLET_INVOCATION_UNAVAILABLE: &str = "outlet invocation through the NAPI MCP server is not implemented: no \
     tools/call can run on this bridge, whatever grant the agent holds";

impl ContextProvider for McpNapiBridgeProvider {
    fn active_context_ids(&self) -> Result<Vec<scp_mcp::namespace::ContextId>, String> {
        // Configured ∩ live: a context the agent has left is no longer served,
        // so its tools and resources disappear from `tools/list` and
        // `resources/list` without restarting the server (ADR-015 AC7). A
        // context no actor holds is not served; a failed read is an error, not
        // a departure.
        let bi = self.upgrade_bi()?;
        let mut served = Vec::new();
        for id in &self.context_ids {
            if held_role_state(&bi, id)?
                .is_some_and(|role_state| role_state.members.contains(&self.agent_did))
            {
                served.push(id.clone());
            }
        }
        Ok(served)
    }

    fn agent_role(&self, context_id: &str) -> Result<Option<String>, String> {
        // A context nobody holds has no role for the agent; a dropped bridge
        // or a failed read is an error, never `None`.
        let bi = self.upgrade_bi()?;
        Ok(held_role_state(&bi, context_id)?.and_then(|role_state| {
            role_state
                .assignments
                .get(&self.agent_did)
                .map(|assignment| assignment.role_name.clone())
        }))
    }

    fn agent_did(&self) -> &str {
        &self.agent_did
    }

    fn context_tools(
        &self,
        context_id: &str,
    ) -> Result<Vec<scp_mcp::server::ContextOutletInfo>, String> {
        // A dropped bridge or an unreadable context is an error, never an
        // empty outlet registry.
        let bi = self.upgrade_bi()?;
        let Some(rt) = crate::runtime::ucan_registry(&bi).get(context_id) else {
            // This bridge creates a context's UCAN state lazily: the first
            // UCAN, event-log, outlet or outlet-stream call on the context runs
            // `ensure_registered`, and `context_create_on` and
            // `context_join_on` do not. Every outlet registration runs
            // `ensure_registered` first, so a context the supervisor holds with
            // no entry here has had no outlet registered through this bridge,
            // and its registry is empty. With no supervisor the entry is the
            // context's only state, so `held_role_state` finds no context.
            return match held_role_state(&bi, context_id)? {
                Some(_) => Ok(Vec::new()),
                None => Err(format!(
                    "context '{context_id}' is held neither by the supervisor nor by \
                     this bridge"
                )),
            };
        };
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
    }

    fn validate_capability(
        &self,
        _context_id: &str,
        _outlet_name: &str,
        _check: scp_mcp::server::CapabilityCheck,
    ) -> Result<(), scp_mcp::server::AccessRefusal> {
        // Stub — see SCP-048
        // `McpServer` lists a tool exactly when this method returns `Ok`, and
        // every `tools/call` ends in `invoke_outlet`. This bridge's
        // `invoke_outlet` is not implemented, so granting here would
        // put tools in `tools/list` that every `tools/call` then fails. The
        // denial keeps `tools/list` empty and refuses `tools/call` before it
        // reaches `invoke_outlet`, so a client sees the capability as absent.
        Err(scp_mcp::server::AccessRefusal::Denied(
            OUTLET_INVOCATION_UNAVAILABLE.to_owned(),
        ))
    }

    fn invoke_outlet(
        &self,
        _context_id: &str,
        _outlet_name: &str,
        _arguments: serde_json::Value,
    ) -> Result<serde_json::Value, scp_mcp::server::OutletInvokeError> {
        // Stub — see SCP-048
        Err(OUTLET_INVOCATION_UNAVAILABLE.to_owned().into())
    }

    fn validate_resource_access(
        &self,
        context_id: &str,
        resource: scp_mcp::server::ResourceKind,
    ) -> Result<(), scp_mcp::server::AccessRefusal> {
        use scp_mcp::server::AccessRefusal;
        // A dropped bridge instance or an unreadable role state is a failed
        // read, which `resources/list` reports as an error instead of
        // omitting the context's resources.
        let bi = self.upgrade_bi().map_err(AccessRefusal::Unreadable)?;
        let role_state = live_role_state(&bi, context_id).map_err(AccessRefusal::Unreadable)?;
        let access = resource.check_access(&role_state, &self.agent_did, context_id);
        access.map_err(AccessRefusal::Denied)
    }

    fn context_members(
        &self,
        context_id: &str,
    ) -> Result<Vec<scp_mcp::server::MemberInfo>, String> {
        // A dropped bridge or an unreadable context is an error, never an
        // empty roster.
        let bi = self.upgrade_bi()?;
        let role_state = live_role_state(&bi, context_id)?;
        Ok(role_state
            .members
            .iter()
            .map(|did| scp_mcp::server::MemberInfo {
                did: did.clone(),
                role: role_state
                    .assignments
                    .get(did)
                    .map_or_else(|| "member".to_owned(), |a| a.role_name.clone()),
            })
            .collect())
    }

    fn context_events(&self, context_id: &str) -> Result<serde_json::Value, String> {
        // The event log stores Merkle tree leaf hashes, not event payloads,
        // so the resource reports entry counts and Merkle roots in the shape
        // the PyO3 and UniFFI bridges return. A dropped bridge or an
        // unreadable log is an error, never an empty log.
        let bi = self.upgrade_bi()?;
        // `bridge_event_log` summarizes the bridge's local tree. The PyO3 and
        // UniFFI bridges append each MCP `tools/call` record to their local
        // tree; this bridge's `invoke_outlet` refuses every call, so it
        // appends none.
        let bridge_log = crate::runtime::with_context(&bi, context_id, |rt| {
            Ok((
                rt.core.event_log.leaves().len(),
                scp_event_log::tree::root(&rt.core.event_log),
            ))
        })
        .map_err(|e| format!("{e}"));
        // With a supervisor attached, the top level reports the actor's log,
        // whose events drive the pump's `resources/updated` notices, and
        // `bridge_event_log` is `null` when the bridge holds no local tree for
        // the context. Without a supervisor the bridge's tree is the context's
        // only log, so an unreadable tree is an error.
        let ((event_count, root), bridge_log) = if let Some(supervisor) = bi.core.try_supervisor() {
            let actor_log = supervisor
                .event_log_summary(&scp_core::context::state::context_id_to_bytes(context_id))
                .map_err(|e| format!("cannot read the event log of context '{context_id}': {e}"))?;
            (actor_log, bridge_log.ok())
        } else {
            let bridge_log = bridge_log?;
            (bridge_log, Some(bridge_log))
        };
        let bridge_event_log = bridge_log.map(|(count, root)| {
            serde_json::json!({ "event_count": count, "merkle_root": hex::encode(root) })
        });
        Ok(serde_json::json!({
            "event_count": event_count,
            "merkle_root": hex::encode(root),
            "bridge_event_log": bridge_event_log,
        }))
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
/// `server` is the [`McpServerForTransport`] bundle: it carries its pump iff it
/// advertises `resources/subscribe`. The bundle is built by
/// `McpServer::with_optional_event_source`, so the advertised capability and the
/// pump that honours it are one value — the loop cannot be handed one without the
/// other.
///
/// Both `shutdown_rx` (`mcp_server_stop`) AND the bridge instance's
/// `cancel_token` (`emergency_cancel_tasks` from `Drop`) terminate this task, so
/// a caller that drops `Scp` without calling `mcp_server_stop` still tears the
/// server and its pump down, as the SSE path and the `PyO3` and `UniFFI`
/// bridges do.
async fn run_mcp_stdio_server(
    server: McpServerForTransport<McpNapiBridgeProvider>,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    cancel_token: tokio_util::sync::CancellationToken,
) {
    tokio::select! {
        _ = shutdown_rx => {}
        () = cancel_token.cancelled() => {
            tracing::debug!("MCP stdio server task exiting — bridge instance cancelled");
        }
        result = scp_mcp::stdio::run_stdio(server) => {
            if let Err(e) = result {
                tracing::error!("MCP stdio server error: {e}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Builds the one server `mcp_server_create_on` hands to its transport,
/// paired with the supervisor's context event receiver when there is one.
///
/// `subscribe_events()` returns `None` only for a supervisor built without the
/// channel; every NAPI supervisor path enables it (see
/// `crate::runtime::build_supervisor_arc`). With no supervisor or no channel
/// the bundle is unwired: the server advertises every capability the event
/// pump backs as false (`resources.subscribe`, `resources.listChanged`,
/// `tools.listChanged`), rejects `resources/subscribe`, and sends no
/// `notifications/*/list_changed`, so those capabilities are honestly absent
/// rather than accepted-and-never-delivered. Serving is not failed: the server
/// still serves `resources/list|read`, from the actor when a supervisor is
/// attached and from the bridge state when none is. Failing outright would
/// deny working functionality over an optional feature. This server lists no
/// tools with or without a supervisor (`OUTLET_INVOCATION_UNAVAILABLE`).
///
/// One call decides both the advertisement and the delivery machinery, folded
/// into one `McpServerForTransport` bundle.
fn mcp_server_bundle(
    bi: &NapiBridgeInstance,
    provider: McpNapiBridgeProvider,
) -> scp_mcp::server::McpServerForTransport<McpNapiBridgeProvider> {
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
    scp_mcp::server::McpServer::with_optional_event_source(provider, context_events)
}

/// Per-bridge-instance implementation of [`Scp::mcp_server_create`](crate::scp::Scp::mcp_server_create).
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

    // The provider reads this instance's per-context registries through a
    // `Weak`, so the spawned server task cannot pin the instance alive.
    let provider = McpNapiBridgeProvider {
        bi: Arc::downgrade(bi),
        agent_did: config.identity_did,
        context_ids: config.context_ids,
    };
    // Subscribe to the supervisor's events *before* spawning, so no event
    // emitted between here and the transport loop starting is missed.
    let server = mcp_server_bundle(bi, provider);

    // The bridge instance's cancel token fires on `emergency_cancel_tasks()`
    // from `Drop`, so an instance dropped without an explicit `mcp_server_stop`
    // still tears down both the stdio and the SSE server + pump.
    let cancel_token = bi.core.cancel_token();

    let task_handle = crate::runtime().spawn(async move {
        match transport_mode.as_str() {
            "stdio" => {
                run_mcp_stdio_server(server, shutdown_rx, cancel_token).await;
            }
            "sse" => {
                // `SseConfig::new` draws a fresh bearer token, and the transport rejects
                // every request that does not present it. This bridge returns neither that
                // token nor the bound port to its caller, so no client can reach this
                // server.
                let sse_config =
                    scp_mcp::sse::SseConfig::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
                let sse_shutdown = scp_mcp::sse::ShutdownHandle::new();
                let sse_shutdown_trigger = sse_shutdown.clone();
                // Wire both `shutdown_rx` (mcp_server_stop) AND the bridge
                // instance's `cancel_token` (emergency_cancel_tasks from Drop) so
                // either signal tears down the SSE server + pump. Without the
                // cancel_token arm, a caller that drops `Scp` without calling
                // `mcp_server_stop` would leave this task running indefinitely.
                // The stdio path and the `PyO3` and `UniFFI` bridges wire both
                // signals the same way.
                tokio::spawn(async move {
                    tokio::select! {
                        _ = shutdown_rx => {}
                        () = cancel_token.cancelled() => {}
                    }
                    sse_shutdown_trigger.shutdown();
                });
                let result = scp_mcp::sse::run_sse(server, sse_config, sse_shutdown).await;
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

/// Per-bridge-instance implementation of [`Scp::mcp_server_stop`](crate::scp::Scp::mcp_server_stop).
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

/// Per-bridge-instance implementation of [`Scp::mcp_client_connect_stdio`](crate::scp::Scp::mcp_client_connect_stdio).
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
    let server = transport.server_process();

    let client = run_mcp_client_io(codes::TRANS_5016, move || {
        let mut client = McpClient::new(McpClientTransportWrapper::Stdio(transport));
        client.initialize().map_err(|e| ScpNapiError::Transport {
            message: format!("MCP initialize handshake failed: {e}"),
            code: codes::TRANS_5016.to_owned(),
        })?;
        Ok(client)
    })
    .await?;

    let handle_id = mcp_handle_id("mcp-client");
    let entry = McpClientEntry {
        client: Arc::new(Mutex::new(client)),
        stdio_server: Some(server),
    };

    bi.mcp_client_registry().insert(handle_id.clone(), entry);
    crate::increment_handle_count();

    Ok(NapiMcpClientHandle {
        handle_id,
        instance_id: bi.instance_id(),
    })
}

/// Per-bridge-instance implementation of [`Scp::mcp_client_connect_sse`](crate::scp::Scp::mcp_client_connect_sse).
pub(crate) async fn mcp_client_connect_sse_on(
    bi: &NapiBridgeInstance,
    url: String,
    auth_token: Option<String>,
) -> napi::Result<NapiMcpClientHandle> {
    // The same URL check the PyO3 and UniFFI twins run, so an empty or
    // over-long URL is a validation error on every binding.
    scp_ffi_common::validate::validate_relay_url(&url)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let client = run_mcp_client_io(codes::TRANS_5018, move || {
        let transport =
            scp_mcp::sse_client::SseClientTransport::connect(&url, auth_token.as_deref()).map_err(
                |e| ScpNapiError::Transport {
                    message: format!("failed to connect SSE client: {e}"),
                    code: codes::TRANS_5018.to_owned(),
                },
            )?;
        let mut client = McpClient::new(McpClientTransportWrapper::Sse(transport));
        client.initialize().map_err(|e| ScpNapiError::Transport {
            message: format!("MCP initialize handshake failed: {e}"),
            code: codes::TRANS_5018.to_owned(),
        })?;
        Ok(client)
    })
    .await?;

    let handle_id = mcp_handle_id("mcp-client");
    let entry = McpClientEntry {
        client: Arc::new(Mutex::new(client)),
        stdio_server: None,
    };

    bi.mcp_client_registry().insert(handle_id.clone(), entry);
    crate::increment_handle_count();

    Ok(NapiMcpClientHandle {
        handle_id,
        instance_id: bi.instance_id(),
    })
}

/// Per-bridge-instance implementation of [`Scp::mcp_client_disconnect`](crate::scp::Scp::mcp_client_disconnect).
#[allow(clippy::unused_async)]
pub(crate) async fn mcp_client_disconnect_on(
    bi: &NapiBridgeInstance,
    handle: &NapiMcpClientHandle,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, handle);
    let Some((_, entry)) = bi.mcp_client_registry().remove(&handle.handle_id) else {
        return Err(ScpNapiError::Transport {
            message: format!("MCP client handle '{}' not found", handle.handle_id),
            code: codes::TRANS_5019.to_owned(),
        }
        .into());
    };
    // A stdio server is dead when this returns, even while a call on the
    // handle is in flight; that call then fails on the closed stdout.
    if let Some(server) = entry.stdio_server {
        scp_mcp::stdio::stop_server_process(&server);
    }
    Ok(())
}

/// Per-bridge-instance implementation of [`Scp::mcp_client_list_tools`](crate::scp::Scp::mcp_client_list_tools).
pub(crate) async fn mcp_client_list_tools_on(
    bi: &NapiBridgeInstance,
    handle: &NapiMcpClientHandle,
) -> napi::Result<Vec<NapiMcpToolInfo>> {
    crate::napi_check_handle!(&bi.core, handle);
    let registry = Arc::clone(bi.mcp_client_registry());
    let handle_id = handle.handle_id.clone();
    let outlets = run_mcp_client_io(codes::TRANS_5022, move || {
        // Clone the client out so the shard guard drops before the I/O.
        let client = registry
            .get(&handle_id)
            .map(|entry| Arc::clone(&entry.client))
            .ok_or_else(|| ScpNapiError::Transport {
                message: format!("MCP client handle '{handle_id}' not found"),
                code: codes::TRANS_5020.to_owned(),
            })?;
        let client_guard = client.lock().map_err(|e| ScpNapiError::Transport {
            message: format!("client lock poisoned: {e}"),
            code: codes::TRANS_5021.to_owned(),
        })?;
        client_guard
            .list_tools()
            .map_err(|e| ScpNapiError::Transport {
                message: format!("tools/list failed: {e}"),
                code: codes::TRANS_5022.to_owned(),
            })
    })
    .await?;

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

/// Per-bridge-instance implementation of [`Scp::mcp_client_invoke`](crate::scp::Scp::mcp_client_invoke).
pub(crate) async fn mcp_client_invoke_on(
    bi: &NapiBridgeInstance,
    handle: &NapiMcpClientHandle,
    outlet_name: String,
    input_json: String,
    context_id: String,
    invoker_did: String,
) -> napi::Result<NapiMcpInvokeResult> {
    crate::napi_check_handle!(&bi.core, handle);
    let registry = Arc::clone(bi.mcp_client_registry());
    let handle_id = handle.handle_id.clone();
    let result = run_mcp_client_io(codes::TRANS_5025, move || {
        // Clone the client out so the shard guard drops before the I/O.
        let client = registry
            .get(&handle_id)
            .map(|entry| Arc::clone(&entry.client))
            .ok_or_else(|| ScpNapiError::Transport {
                message: format!("MCP client handle '{handle_id}' not found"),
                code: codes::TRANS_5023.to_owned(),
            })?;
        let input: serde_json::Value =
            serde_json::from_str(&input_json).map_err(|e| ScpNapiError::Transport {
                message: format!("invalid input JSON: {e}"),
                code: codes::VALID_7021.to_owned(),
            })?;
        let client_guard = client.lock().map_err(|e| ScpNapiError::Transport {
            message: format!("client lock poisoned: {e}"),
            code: codes::TRANS_5024.to_owned(),
        })?;
        client_guard
            .invoke(&outlet_name, input, &context_id, &invoker_did)
            .map_err(|e| ScpNapiError::Transport {
                message: format!("tools/call failed: {e}"),
                code: codes::TRANS_5025.to_owned(),
            })
    })
    .await?;

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

/// Maps [`AllowlistError`](scp_mcp::allowlist::AllowlistError) to the appropriate [`ScpNapiError`] variant.
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

    /// `mcp_client_connect_sse_on` sends the caller's token on its `GET`, so a
    /// TypeScript client passes the bearer check an SCP SSE server always
    /// runs, and it waits for the server off the async worker. The listener
    /// holds the connection silent until the timer branch has run, then
    /// closes it, so the connect fails after the header has gone out. On this
    /// single-threaded runtime a connect that blocked the worker would hold
    /// the timer branch for the listener's five-second hold.
    #[test]
    fn mcp_client_connect_sse_sends_the_bearer_token_napi() {
        use std::io::BufRead;
        let bi = NapiBridgeInstance::new_napi();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (conn, _) = listener.accept().expect("accept GET");
            let mut reader = std::io::BufReader::new(conn);
            let mut head = String::new();
            loop {
                let mut line = String::new();
                let n = reader.read_line(&mut line).expect("read head");
                if n == 0 || line == "\r\n" {
                    break;
                }
                head.push_str(&line);
            }
            let _ = release_rx.recv_timeout(std::time::Duration::from_secs(5));
            head
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let started = std::time::Instant::now();
        let (result, timer_done) = runtime.block_on(async {
            tokio::join!(
                mcp_client_connect_sse_on(
                    &bi,
                    format!("http://127.0.0.1:{port}/sse"),
                    Some("tok-1".to_owned()),
                ),
                async {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    let timer_done = started.elapsed();
                    let _ = release_tx.send(());
                    timer_done
                }
            )
        });
        let head = server.join().expect("server thread");
        assert!(
            head.contains("\r\nAuthorization: Bearer tok-1\r\n"),
            "the GET must carry the token, got: {head}"
        );
        assert!(result.is_err(), "the listener closed without a response");
        assert!(
            timer_done < std::time::Duration::from_secs(2),
            "the connect must wait off the async worker, but the timer took {timer_done:?}"
        );
    }

    /// An empty URL fails the relay-URL validation before any connect, the
    /// same validation error the `PyO3` and `UniFFI` twins return.
    #[test]
    fn mcp_client_connect_sse_validates_the_url_napi() {
        let bi = NapiBridgeInstance::new_napi();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let Err(err) = runtime.block_on(mcp_client_connect_sse_on(&bi, String::new(), None)) else {
            panic!("an empty URL must be rejected");
        };
        let expected = napi::Error::from(ScpNapiError::from(
            scp_ffi_common::validate::validate_relay_url("").expect_err("empty URL"),
        ));
        assert_eq!(err.reason, expected.reason, "got: {err}");
        assert!(
            !err.reason.contains(codes::TRANS_5018),
            "a bad URL is a validation error, not a transport error: {err}"
        );
    }

    /// A `tools/list` in flight against a silent stdio server holds a blocking
    /// thread and its own clone of the client, not the registry shard, so a
    /// disconnect of the same handle returns at once, and it kills the server
    /// process, so the in-flight call ends on the closed stdout. The stub
    /// server writes a notification before its `initialize` response, which
    /// the client reads past, then becomes a `sleep` that never answers and
    /// outlives the test unless the disconnect kills it.
    #[test]
    fn mcp_client_disconnect_does_not_wait_on_an_in_flight_call_napi() {
        let bi = NapiBridgeInstance::new_napi();
        let mut allowlist = scp_mcp::allowlist::StdioAllowlist::new_with_defaults();
        allowlist.configure(&["sh"]).expect("allow sh");
        let allowlist = Mutex::new(allowlist);
        let script = "read l; \
            echo '{\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}'; \
            echo '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\
            \"capabilities\":{},\"serverInfo\":{\"name\":\"stub\"}}}'; \
            exec sleep 600";
        let transport = StdioMcpTransport::spawn(
            &allowlist,
            &["sh".to_owned(), "-c".to_owned(), script.to_owned()],
        )
        .expect("spawn stub server");
        let server = transport.server_process();
        let mut client = McpClient::new(McpClientTransportWrapper::Stdio(transport));
        client
            .initialize()
            .expect("initialize must read past the notification");
        let handle_id = mcp_handle_id("mcp-client");
        bi.mcp_client_registry().insert(
            handle_id.clone(),
            McpClientEntry {
                client: Arc::new(Mutex::new(client)),
                stdio_server: Some(Arc::clone(&server)),
            },
        );
        crate::increment_handle_count();
        let handle = NapiMcpClientHandle {
            handle_id,
            instance_id: bi.instance_id(),
        };

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        // The timeout is built inside `block_on`, because its timer needs the
        // runtime's reactor.
        let joined = runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::join!(mcp_client_list_tools_on(&bi, &handle), async {
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    let started = std::time::Instant::now();
                    mcp_client_disconnect_on(&bi, &handle)
                        .await
                        .expect("disconnect a known handle");
                    started.elapsed()
                })
            })
            .await
        });
        if joined.is_err() {
            // Free the parked blocking thread, or the runtime's drop waits on
            // it for the stub's whole sleep.
            scp_mcp::stdio::stop_server_process(&server);
        }
        let (listed, disconnect_took) =
            joined.expect("the in-flight call must end once disconnect kills the server");
        assert!(
            disconnect_took < std::time::Duration::from_secs(1),
            "disconnect waited {disconnect_took:?} on the in-flight call"
        );
        assert!(
            server
                .lock()
                .expect("server lock")
                .try_wait()
                .expect("query the server process")
                .is_some(),
            "disconnect must kill the stdio server process"
        );
        assert!(
            listed.is_err(),
            "the killed stub server sent no tools/list response"
        );
    }

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
    // Resource subscriptions
    //
    // `McpNapiBridgeProvider::subscribe_resource` is gone: the capability is
    // no longer a provider concern. The transport owns it, and it is gated on
    // holding a real `Supervisor` event receiver. These tests assert that
    // honesty invariant from the NAPI side — advertisement and acceptance move
    // together, and a wired bridge actually yields a receiver.
    // -----------------------------------------------------------------------

    use scp_core::context::membership::ContextEvent;
    use scp_mcp::protocol::{
        JSONRPC_VERSION, METHOD_INITIALIZE, METHOD_NOT_FOUND, METHOD_RESOURCES_SUBSCRIBE,
        METHOD_RESOURCES_UPDATED, RequestId,
    };
    use tokio::sync::broadcast;

    /// The sender half of the supervisor's context-event channel.
    type ContextEventSender = broadcast::Sender<(String, ContextEvent)>;

    const SUB_CTX: &str = "ctx-subscribe-napi";
    const SUB_URI: &str = "scp://ctx-subscribe-napi/events";
    const AGENT_DID: &str = "did:test:napi-mcp-subscribe";

    /// Builds a bridge instance with `SUB_CTX` registered and `AGENT_DID` as
    /// its creator, plus an `McpServer` over the REAL NAPI bridge provider —
    /// the exact type `mcp_server_create_on` constructs.
    ///
    /// Returning the `Arc` matters: the provider holds a `Weak`, so dropping
    /// the instance would make the provider's state reads fail.
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
        ContextEventSender,
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

    /// Negative half: with no event receiver wired — what
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

    /// Positive half: `McpServer::with_event_source` (public only under
    /// `scp-mcp/testing`) builds the flag and the pump in one call, the same
    /// pair `with_optional_event_source(Some(rx))` seals into its bundle. The
    /// server then advertises the capability, accepts the
    /// subscription, and `notifications_for_event` — the function the pump
    /// drives for each received `ContextEvent` — emits a real
    /// `notifications/resources/updated` for the subscribed URI. The receiver
    /// comes from a detached channel and the pump does not run; the
    /// `pipeline_wiring` event-source gate covers which receiver the NAPI
    /// serve path passes.
    #[test]
    fn mcp_subscribe_produces_notifications_when_event_source_wired_napi() {
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

    /// `tools/list` must not name a tool that `tools/call` cannot run. The
    /// NAPI `invoke_outlet` is not implemented, so the context creator,
    /// who holds the admin role, sees an empty tool list and a `tools/call`
    /// refused at the capability check.
    #[test]
    fn napi_mcp_lists_no_tool_it_cannot_invoke() {
        let (_bi, mut server) = napi_mcp_fixture();
        let _ = initialize_and_read_subscribe_flag(&mut server);

        let listed = server
            .handle_request(&mcp_request(
                scp_mcp::protocol::METHOD_TOOLS_LIST,
                serde_json::json!({}),
            ))
            .expect("tools/list must produce a response");
        let tools = listed.result.expect("tools/list must succeed")["tools"].clone();
        assert_eq!(
            tools,
            serde_json::json!([]),
            "the NAPI server listed tools its invoke_outlet cannot execute"
        );

        let called = server
            .handle_request(&mcp_request(
                scp_mcp::protocol::METHOD_TOOLS_CALL,
                serde_json::json!({
                    "name": format!("{SUB_CTX}/send_message"),
                    "arguments": {},
                }),
            ))
            .expect("tools/call must produce a response");
        let error = called.error.expect("tools/call must be refused");
        assert_eq!(error.code, scp_mcp::protocol::CAPABILITY_DENIED);
        assert_eq!(error.message, OUTLET_INVOCATION_UNAVAILABLE);
    }

    /// The NAPI provider must serve REAL context state, not empty stand-ins.
    ///
    /// Before this fix `context_members` returned `Vec::new()`,
    /// `context_events` returned `[]` and `context_tools` returned
    /// `Vec::new()` — empty stand-ins on a shipped path that would have gone
    /// live the moment resource authorization started admitting anyone.
    /// (`validate_capability` denies every tool on purpose; see
    /// `napi_mcp_lists_no_tool_it_cannot_invoke`.)
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
        let members = provider
            .context_members(SUB_CTX)
            .expect("context_members must read a live context");
        assert!(
            members.iter().any(|m| m.did == AGENT_DID),
            "context_members must report the real roster, got: {members:?}"
        );
        assert_eq!(
            provider
                .agent_role(SUB_CTX)
                .expect("the role state reads")
                .as_deref(),
            Some("admin"),
            "agent_role must resolve the creator's real role assignment"
        );

        // The event log is reported by count + Merkle root, matching PyO3 and
        // UniFFI — never a bare `[]`.
        let events = provider
            .context_events(SUB_CTX)
            .expect("context_events must read a live context");
        assert!(
            events.get("event_count").is_some() && events.get("merkle_root").is_some(),
            "context_events must report real Merkle event-log state, got: {events}"
        );

        // A context the bridge cannot read is an error on every read, never
        // an empty registry, an empty roster or a `{"event_count": 0}` log.
        assert!(provider.context_tools("ctx-unknown").is_err());
        assert!(provider.context_members("ctx-unknown").is_err());
        assert!(provider.context_events("ctx-unknown").is_err());

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
        // The denial names the requirement each kind checks: membership for
        // `Tools`, `messages:read` for `Events` and `Members`.
        let tools_denial = outsider
            .validate_resource_access(SUB_CTX, ResourceKind::Tools)
            .expect_err("a non-member must not be able to read the tool list");
        assert!(
            matches!(
                &tools_denial,
                scp_mcp::server::AccessRefusal::Denied(msg) if msg.contains("lacks membership") && !msg.contains("messages:read")
            ),
            "the Tools denial must name membership, got: {tools_denial}"
        );
        for kind in [ResourceKind::Events, ResourceKind::Members] {
            let denial = outsider
                .validate_resource_access(SUB_CTX, kind)
                .expect_err("a non-member must be denied");
            assert!(
                matches!(&denial, scp_mcp::server::AccessRefusal::Denied(msg) if msg.contains("lacks messages:read")),
                "the {kind:?} denial must name messages:read, got: {denial}"
            );
        }
        assert!(
            outsider.active_context_ids().unwrap().is_empty(),
            "a non-member must not have the context in its served set"
        );
    }

    /// With a supervisor attached, every MCP gate answers from the actor's
    /// role state, not from the bridge's copy. The copy is resynced only by the
    /// bridge's own join, leave and governance calls, so a revocation or
    /// removal the actor applies from an inbound commit leaves the copy still
    /// granting. Here the copy names the agent as a member and the actor holds
    /// no such context — the state after the actor drops a context the agent
    /// was removed from — so every gate must deny.
    #[test]
    fn provider_gates_follow_the_actor_not_the_bridge_copy_napi() {
        use scp_mcp::server::{ContextProvider as _, ResourceKind};

        let (bi, _server) = napi_mcp_fixture();
        let provider = || McpNapiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: AGENT_DID.to_owned(),
            context_ids: vec![SUB_CTX.to_owned()],
        };

        // No supervisor: the copy is the context's only role state, and a
        // context the bridge holds no copy of is reported as such, not as one
        // a supervisor lacks.
        assert_eq!(
            provider().active_context_ids().unwrap(),
            vec![SUB_CTX.to_owned()]
        );
        let denial = provider()
            .validate_resource_access("ctx-the-bridge-never-held", ResourceKind::Events)
            .expect_err("a context the bridge holds no copy of must not be readable");
        assert!(
            matches!(
                &denial,
                scp_mcp::server::AccessRefusal::Unreadable(msg)
                    if msg.contains("not held by this bridge, and no supervisor is attached")
            ),
            "with no supervisor the denial must name the bridge, got: {denial}"
        );
        assert!(
            provider()
                .validate_resource_access(SUB_CTX, ResourceKind::Events)
                .is_ok()
        );
        assert!(provider().context_members(SUB_CTX).is_ok());
        assert!(
            provider()
                .agent_role(SUB_CTX)
                .expect("the role state reads")
                .is_some()
        );

        // The actor now exists and does not hold the context; the copy still
        // names the agent as a member.
        crate::runtime::init_supervisor_for_test_on(&bi);
        assert!(crate::runtime::supervisor(&bi).is_ok());

        assert!(
            provider().active_context_ids().unwrap().is_empty(),
            "a context the actor does not hold must drop out of the served set"
        );
        for kind in [
            ResourceKind::Events,
            ResourceKind::Members,
            ResourceKind::Tools,
        ] {
            let denial = provider()
                .validate_resource_access(SUB_CTX, kind)
                .expect_err("the bridge copy must not grant what the actor does not");
            assert!(
                matches!(
                    &denial,
                    scp_mcp::server::AccessRefusal::Unreadable(msg) if msg.contains("not held by the supervisor")
                ),
                "the {kind:?} denial must come from the actor query, got: {denial}"
            );
        }
        assert!(provider().context_members(SUB_CTX).is_err());
        assert!(
            provider()
                .agent_role(SUB_CTX)
                .expect("the role state reads")
                .is_none()
        );

        // The production shape: the MCP transport task on the multi-thread
        // runtime, where the query blocks one worker while the actor runs.
        let spawned = provider();
        let rt = crate::runtime();
        let served = rt
            .block_on(rt.spawn(async move { spawned.active_context_ids().unwrap() }))
            .unwrap();
        assert!(
            served.is_empty(),
            "the transport task must see the actor's role state too"
        );

        // A read the provider cannot make is an error, never "not served": a
        // current-thread runtime cannot run the actor while this call blocks
        // its only thread.
        let current_thread = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        assert!(
            current_thread
                .block_on(async { provider().active_context_ids() })
                .is_err(),
            "a failed participation read must not be reported as an empty served set"
        );
    }

    /// Registers `ctx_id` on the bridge with `copy_creator` as the copy's sole
    /// member, and creates it on the actor with `actor_creator` as its creator,
    /// so the bridge copy and the actor disagree about who is a member.
    fn setup_diverged_context(
        bi: &NapiBridgeInstance,
        ctx_id: &str,
        copy_creator: &str,
        actor_creator: &str,
    ) {
        crate::runtime::register_ffi_state(bi, ctx_id, copy_creator, &[])
            .expect("registering context FFI state must succeed");
        crate::runtime::init_supervisor_for_test_on(bi);
        let supervisor = Arc::clone(crate::runtime::supervisor(bi).unwrap());
        let params = scp_core::context::ContextParams {
            ceiling: vec![
                scp_core::context::params::Capability::new("messages:read")
                    .expect("known capability"),
            ],
            ..scp_core::context::ContextParams::default()
        };
        crate::runtime()
            .block_on(supervisor.create_context(
                ctx_id.to_owned(),
                params,
                scp_did::DID(actor_creator.to_owned()),
                None,
            ))
            .unwrap();
    }

    /// Every MCP gate answers from the actor's role state while the actor holds
    /// the context, and the gates write nothing back to the bridge copy.
    ///
    /// `revoked` is the state after an inbound commit removed the agent: the
    /// actor holds the context without the agent while the bridge copy still
    /// names the agent as its member. `granted` is the reverse. A gate that read
    /// the copy, or that let the copy decide, fails one of the two halves; a
    /// gate that wrote the actor's snapshot back into the copy fails the final
    /// assertions.
    #[test]
    fn provider_gates_read_the_actor_role_state_without_writing_the_copy_napi() {
        use scp_mcp::server::{ContextProvider as _, ResourceKind};

        let agent = "did:dht:z6MkNapiLiveRoleAgent";
        let other = "did:dht:z6MkNapiLiveRoleOther";
        let bi = Arc::new(NapiBridgeInstance::new_napi());
        let revoked = "ctx-napi-live-role-revoked";
        let granted = "ctx-napi-live-role-granted";
        setup_diverged_context(&bi, revoked, agent, other);
        setup_diverged_context(&bi, granted, other, agent);
        let copy_has_agent = |ctx: &str| {
            crate::runtime::with_context(&bi, ctx, |rt| Ok(rt.role_state.members.contains(agent)))
                .unwrap()
        };
        assert!(copy_has_agent(revoked) && !copy_has_agent(granted));
        let provider = |ctx: &str| McpNapiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: agent.to_owned(),
            context_ids: vec![ctx.to_owned()],
        };

        assert!(provider(revoked).active_context_ids().unwrap().is_empty());
        for (kind, requirement) in [
            (ResourceKind::Events, "lacks messages:read"),
            (ResourceKind::Members, "lacks messages:read"),
            (ResourceKind::Tools, "lacks membership"),
        ] {
            let denial = provider(revoked)
                .validate_resource_access(revoked, kind)
                .expect_err("the copy's grant must not outlive the actor's revocation");
            assert!(
                matches!(&denial, scp_mcp::server::AccessRefusal::Denied(msg) if msg.contains(requirement)),
                "{kind:?}: {denial}"
            );
        }
        assert!(
            provider(revoked)
                .agent_role(revoked)
                .expect("the role state reads")
                .is_none()
        );
        let members = provider(revoked).context_members(revoked).unwrap();
        assert!(members.iter().all(|m| m.did != agent));

        assert_eq!(
            provider(granted).active_context_ids().unwrap(),
            vec![granted.to_owned()]
        );
        for kind in [
            ResourceKind::Events,
            ResourceKind::Members,
            ResourceKind::Tools,
        ] {
            provider(granted)
                .validate_resource_access(granted, kind)
                .unwrap_or_else(|e| panic!("the actor grants {kind:?}: {e}"));
        }
        assert!(
            provider(granted)
                .agent_role(granted)
                .expect("the role state reads")
                .is_some()
        );

        // No write-back: each copy still holds what the bridge wrote into it.
        assert!(copy_has_agent(revoked) && !copy_has_agent(granted));
    }

    /// A context the supervisor holds but no UCAN, event-log or outlet call has
    /// touched has no UCAN state entry on this bridge (`context_create_on` and
    /// `context_join_on` create none). Its outlet registry is empty, so
    /// `tools/list` answers `[]`; it is not an unreadable context. A context
    /// neither the supervisor nor the bridge holds stays an error.
    #[test]
    fn served_context_without_ucan_state_lists_no_tools_napi() {
        use scp_mcp::server::ContextProvider as _;

        let agent = "did:dht:z6MkNapiLazyUcanAgent";
        let ctx = "ctx-napi-lazy-ucan-state";
        let bi = Arc::new(NapiBridgeInstance::new_napi());
        crate::runtime::init_supervisor_for_test_on(&bi);
        let supervisor = Arc::clone(crate::runtime::supervisor(&bi).unwrap());
        crate::runtime()
            .block_on(supervisor.create_context(
                ctx.to_owned(),
                scp_core::context::ContextParams::default(),
                scp_did::DID(agent.to_owned()),
                None,
            ))
            .unwrap();
        assert!(!crate::runtime::ucan_registry(&bi).contains_key(ctx));
        let provider = McpNapiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: agent.to_owned(),
            context_ids: vec![ctx.to_owned()],
        };
        assert_eq!(provider.active_context_ids().unwrap(), vec![ctx.to_owned()]);
        assert!(provider.context_tools(ctx).unwrap().is_empty());
        assert!(provider.context_tools("ctx-napi-held-by-no-one").is_err());

        let mut server = scp_mcp::server::McpServer::new(provider);
        initialize_and_read_subscribe_flag(&mut server);
        let listed = server
            .handle_request(&mcp_request(
                scp_mcp::protocol::METHOD_TOOLS_LIST,
                serde_json::json!({}),
            ))
            .expect("tools/list must produce a response");
        assert!(
            listed.error.is_none(),
            "tools/list failed: {:?}",
            listed.error
        );
        assert_eq!(listed.result.unwrap()["tools"], serde_json::json!([]));
    }

    /// With a supervisor attached, `scp://{ctx}/events` reports the actor's
    /// event log, whose events drive the `resources/updated` notices, at the
    /// top level, and reports the bridge's local tree under
    /// `bridge_event_log`, in the shape the `PyO3` and `UniFFI` bridges return.
    #[test]
    fn events_resource_reports_the_actor_log_and_the_bridge_log_napi() {
        use scp_mcp::server::ContextProvider as _;

        let agent = "did:dht:z6MkNapiEventsResourceAgent";
        let ctx_id = "ctx-napi-events-resource";
        let bi = Arc::new(NapiBridgeInstance::new_napi());
        setup_diverged_context(&bi, ctx_id, agent, agent);
        // Make the bridge's local tree diverge from the actor's log.
        crate::runtime::with_context(&bi, ctx_id, |rt| {
            rt.core.event_log.push_leaf_raw([0x5A; 32]);
            rt.core.event_log.push_leaf_raw([0xA5; 32]);
            Ok(())
        })
        .unwrap();

        let (count, root) = crate::runtime::supervisor(&bi)
            .unwrap()
            .event_log_summary(&scp_core::context::state::context_id_to_bytes(ctx_id))
            .unwrap();
        let resource = McpNapiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: agent.to_owned(),
            context_ids: vec![ctx_id.to_owned()],
        }
        .context_events(ctx_id)
        .unwrap();
        let (copy_count, copy_root) = crate::runtime::with_context(&bi, ctx_id, |rt| {
            Ok((
                rt.core.event_log.leaves().len(),
                scp_event_log::tree::root(&rt.core.event_log),
            ))
        })
        .unwrap();
        assert_ne!(root, copy_root, "the two logs must differ for this test");
        assert_eq!(
            resource,
            serde_json::json!({
                "event_count": count,
                "merkle_root": hex::encode(root),
                "bridge_event_log": {
                    "event_count": copy_count,
                    "merkle_root": hex::encode(copy_root),
                },
            })
        );
    }

    /// Wiring guard: `mcp_server_create_on` sources its receiver
    /// from `Supervisor::subscribe_events()`. Every NAPI supervisor path
    /// enables the broadcast channel (`build_supervisor_arc`), so that call
    /// must yield `Some`, and `mcp_server_bundle`, the function
    /// `mcp_server_create_on` builds its server with, must return the wired
    /// bundle. Were either to regress, a fully-wired bridge would silently
    /// downgrade to advertising `resources.subscribe: false`.
    #[test]
    fn supervisor_yields_context_event_receiver_for_mcp_napi() {
        let bi = Arc::new(NapiBridgeInstance::new_napi());
        crate::runtime::init_supervisor_for_test_on(&bi);

        let supervisor =
            crate::runtime::supervisor(&bi).expect("supervisor must be attached after init");
        assert!(
            supervisor.subscribe_events().is_some(),
            "the NAPI supervisor must expose a context event receiver so MCP \
             resource subscriptions are wired rather than advertised-and-dropped"
        );
        let bundle = mcp_server_bundle(
            &bi,
            McpNapiBridgeProvider {
                bi: Arc::downgrade(&bi),
                agent_did: AGENT_DID.to_owned(),
                context_ids: vec![SUB_CTX.to_owned()],
            },
        );
        assert_eq!(format!("{bundle:?}"), "McpServerForTransport::Wired");
    }

    /// A missing `Supervisor` degrades the subscription capability and must
    /// not fail MCP serving outright.
    ///
    /// With no supervisor, `resources/list|read` are served from the FFI
    /// bridge state alone, so refusing to serve over an unavailable optional
    /// feature would be a regression. The NAPI server lists no tools with or
    /// without a supervisor (see `napi_mcp_lists_no_tool_it_cannot_invoke`).
    /// The test drives the production entry point, checks that
    /// `mcp_server_bundle`, the function that entry point builds its server
    /// with, returns the unwired bundle, whose server advertises
    /// `resources.subscribe: false`, then reads `resources/list` through the
    /// provider type that entry point builds over the same instance, so a
    /// provider that served nothing without a supervisor fails here.
    #[test]
    fn missing_supervisor_degrades_subscriptions_not_the_whole_server_napi() {
        let (bi, mut server) = napi_mcp_fixture();
        assert!(
            crate::runtime::supervisor(&bi).is_err(),
            "precondition: this instance has no supervisor attached"
        );

        // Drive the production entry point. Were `mcp_server_create_on` to
        // propagate the missing-supervisor error (`supervisor(bi)?`), this
        // call would return `Err` and the test would fail.
        let handle = crate::runtime()
            .block_on(mcp_server_create_on(
                &bi,
                NapiMcpServerConfig {
                    identity_did: AGENT_DID.to_owned(),
                    context_ids: vec![SUB_CTX.to_owned()],
                    transport: "sse".to_owned(),
                },
            ))
            .expect("a missing supervisor must degrade subscriptions, not fail MCP serving");
        crate::runtime()
            .block_on(mcp_server_stop_on(&bi, &handle))
            .expect("the server created without a supervisor must stop cleanly");

        let bundle = mcp_server_bundle(
            &bi,
            McpNapiBridgeProvider {
                bi: Arc::downgrade(&bi),
                agent_did: AGENT_DID.to_owned(),
                context_ids: vec![SUB_CTX.to_owned()],
            },
        );
        assert_eq!(
            format!("{bundle:?}"),
            "McpServerForTransport::Unwired",
            "without a supervisor the served server must not advertise resources.subscribe"
        );
        // Initialize the fixture server only so it answers `resources/list`.
        // Its flag says nothing about the served server: the fixture builds
        // with `McpServer::new`, which never advertises subscriptions.
        let _ = initialize_and_read_subscribe_flag(&mut server);
        let listed = server
            .handle_request(&mcp_request("resources/list", serde_json::json!({})))
            .expect("resources/list must produce a response")
            .result
            .expect("resources/list must succeed without a supervisor");
        let uris: Vec<&str> = listed["resources"]
            .as_array()
            .expect("resources must be an array")
            .iter()
            .filter_map(|r| r["uri"].as_str())
            .collect();
        assert_eq!(
            uris,
            [
                "scp://ctx-subscribe-napi/events",
                "scp://ctx-subscribe-napi/members",
                "scp://ctx-subscribe-napi/tools",
            ],
            "a missing supervisor must leave resources/list serving the context"
        );
    }

    /// A provider whose bridge instance is gone reports its role read as an
    /// error, so `tools/list` cannot turn the failure into "no role" and hide
    /// the agent's `admin_only` outlets.
    #[test]
    fn agent_role_of_dropped_bridge_is_an_error_napi() {
        let provider = McpNapiBridgeProvider {
            bi: std::sync::Weak::new(),
            agent_did: "did:dht:z6MkTestUser".to_owned(),
            context_ids: vec!["ctx-test".to_owned()],
        };
        assert!(provider.agent_role("ctx-test").is_err());
    }
}
