//! MCP server implementation for SCP contexts.
//!
//! Exposes SCP context tools to MCP-compatible models via JSON-RPC 2.0. The
//! server handles:
//!
//! - **Tool listing** (`tools/list`) with capability filtering -- only tools
//!   the agent's role permits are listed.
//! - **Tool invocation** (`tools/call`) -- parses context namespace, validates
//!   UCAN capabilities, validates input/output against schemas, attaches
//!   provenance, and routes through SCP tool invocation.
//! - **Resource listing** (`resources/list`) -- exposes context event streams,
//!   members, and tools as MCP resources.
//! - **Resource reading** (`resources/read`) -- returns current state of a
//!   resource.
//! - **Resource subscriptions** (`resources/subscribe` /
//!   `resources/unsubscribe`) -- backed by the runtime's context event
//!   broadcast channel (`Supervisor::subscribe_events`). A transport-level
//!   pump feeds each [`ContextEvent`] to
//!   [`McpServer::notifications_for_event`], which emits
//!   `notifications/resources/updated` for every subscribed resource the
//!   event invalidates.
//! - **MCP lifecycle** (`initialize`, `notifications/initialized`, `ping`).
//! - **Dynamic updates** -- emits `notifications/tools/list_changed` when an
//!   event changes the capability-filtered tool set.
//!
//! The server uses trait-based abstractions ([`ContextProvider`]) so it can
//! be tested independently of the full SCP stack.
//!
//! See ADR-015 in `.docs/adrs/phase-3.md` for the full design.

use std::collections::HashSet;

use scp_core::context::membership::{ContextEvent, ContextEventEnvelope};
use scp_core::context::outlets::validate_value_against_schema;
use serde_json::Value;
use tokio::sync::broadcast;

use crate::namespace::{
    BUILTIN_TOOLS, BuiltinTool, ContextId, context_tool_definition, parse_namespaced_tool,
};
use crate::protocol::{
    self, ClientCapabilities, ContentItem, InitializeParams, InitializeResult, JsonRpcError,
    JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, RequestId, ResourceContent,
    ResourceDefinition, ResourceServerCapability, ResourcesListResult, ResourcesReadResult,
    ResourcesSubscribeParams, ServerCapabilities, ServerInfo, ToolDefinition, ToolServerCapability,
    ToolsCallParams, ToolsCallResult, ToolsListResult,
};
use crate::translator::{OutletKind, format_mcp_tool_name, parse_mcp_tool_name};

// ---------------------------------------------------------------------------
// MCP protocol version
// ---------------------------------------------------------------------------

/// The MCP protocol version this server supports.
const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

/// Server name reported during initialization.
const SERVER_NAME: &str = "scp-mcp";

/// Server version reported during initialization.
const SERVER_VERSION: &str = "0.1.0";

// ---------------------------------------------------------------------------
// Resource URI constants
// ---------------------------------------------------------------------------

/// URI scheme for SCP resources.
const RESOURCE_SCHEME: &str = "scp://";

/// The MCP resources SCP exposes for a context (ADR-015 AC3).
///
/// The set is closed: `scp://{ctx}/events`, `scp://{ctx}/members` and
/// `scp://{ctx}/tools` are the only resources this server serves. Modelling it
/// as an enum rather than a `&str` suffix means "unknown resource type" is a
/// *parse* failure that cannot reach a handler, every `match` over it is
/// exhaustive, and there is no place left for a stringly-typed authorization
/// name to be synthesized from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceKind {
    /// `scp://{ctx}/events` — the context event stream (count + Merkle root).
    Events,
    /// `scp://{ctx}/members` — the member list and role assignments.
    Members,
    /// `scp://{ctx}/tools` — the capability-filtered tool list.
    Tools,
}

/// Every [`ResourceKind`], for iteration.
const RESOURCE_KINDS: [ResourceKind; 3] = [
    ResourceKind::Events,
    ResourceKind::Members,
    ResourceKind::Tools,
];

impl ResourceKind {
    /// Returns the URI path segment for this resource.
    #[must_use]
    pub const fn uri_suffix(self) -> &'static str {
        match self {
            Self::Events => "events",
            Self::Members => "members",
            Self::Tools => "tools",
        }
    }

    /// Parses a URI path segment into a [`ResourceKind`].
    ///
    /// Returns `None` for any segment outside the closed set.
    #[must_use]
    pub fn from_uri_suffix(suffix: &str) -> Option<Self> {
        RESOURCE_KINDS
            .into_iter()
            .find(|k| k.uri_suffix() == suffix)
    }

    /// Returns the full `scp://{context_id}/{suffix}` URI for this resource.
    #[must_use]
    pub fn uri(self, context_id: &str) -> String {
        format!("{RESOURCE_SCHEME}{context_id}/{}", self.uri_suffix())
    }

    /// Human-readable label used in `resources/list`.
    const fn display_name(self) -> &'static str {
        match self {
            Self::Events => "Events",
            Self::Members => "Members",
            Self::Tools => "Tools",
        }
    }

    /// One-line description used in `resources/list`.
    const fn description(self) -> &'static str {
        match self {
            Self::Events => "Event stream for context",
            Self::Members => "Member list for context",
            Self::Tools => "Tool list for context",
        }
    }
}

// ---------------------------------------------------------------------------
// Provenance type
// ---------------------------------------------------------------------------

/// Provenance metadata attached to tool invocation results.
///
/// Records who invoked the tool, in which context, via which tool, so every
/// result is traceable to its source.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolProvenance {
    /// The DID of the agent that invoked the tool.
    pub invoked_by: String,
    /// The context in which the tool was invoked.
    pub context_id: String,
    /// The tool that was invoked.
    pub tool_name: String,
}

// ---------------------------------------------------------------------------
// Trait: ContextProvider
// ---------------------------------------------------------------------------

/// Describes an outlet available in a context, as seen by the MCP server.
///
/// Simplified view of `scp-core`'s outlet registration record — just what the
/// MCP layer needs for listing and invocation. Kept in SCP vocabulary
/// internally; the MCP boundary translation to `tool` is handled by
/// [`crate::translator`].
#[derive(Debug, Clone)]
pub struct ContextOutletInfo {
    /// The outlet id (without context prefix). This is the SCP `outlet_id`;
    /// the MCP-facing `tool.name` is derived from `(kind, outlet_id)` by the
    /// translator before it reaches the wire.
    pub name: String,
    /// Human-readable description.
    pub description: Option<String>,
    /// JSON Schema for the outlet's input parameters.
    pub input_schema: Value,
    /// JSON Schema for the outlet's output.
    pub output_schema: Option<Value>,
    /// Whether this outlet requires admin privileges.
    pub admin_only: bool,
    /// Outlet classification (§5.4.2). `Query` surfaces to MCP as
    /// `query.{outlet_id}`; `Action` surfaces as `call.{outlet_id}`. This is the
    /// canonical [`OutletKind`] enum (SCP-OUT-011); bridges populate it directly
    /// from the outlet registry's `kind`. Absence defaults to `Action`
    /// (fail-safe per §5.4.2).
    pub kind: OutletKind,
}

/// Describes a member of a context.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemberInfo {
    /// The member's DID.
    pub did: String,
    /// The member's role (e.g., "admin", "member").
    pub role: String,
}

/// Trait abstracting the server's access to SCP contexts, tools, and
/// capabilities.
///
/// Implementations bridge to the real SCP runtime; the trait boundary allows
/// the server to be tested with mock providers.
pub trait ContextProvider: Send + Sync {
    /// Returns the IDs of all contexts the agent currently participates in.
    fn active_context_ids(&self) -> Vec<ContextId>;

    /// Returns the agent's role in the given context (e.g., `"admin"`,
    /// `"member"`).
    fn agent_role(&self, context_id: &str) -> Option<String>;

    /// Returns the agent's DID.
    fn agent_did(&self) -> &str;

    /// Returns the context-registered tools for a context.
    ///
    /// Does not include built-in tools (those are generated by the server).
    fn context_tools(&self, context_id: &str) -> Vec<ContextOutletInfo>;

    /// Validates whether the agent has the UCAN capability to invoke the
    /// given tool in the given context.
    ///
    /// `tool_name` is always an SCP *outlet id* or a [`BuiltinTool`] name —
    /// never a resource URI or any other namespace. Resource authorization has
    /// its own method ([`Self::validate_resource_access`]) precisely because
    /// funnelling both through one stringly-typed call is what let
    /// `resources/read` gate on a `resource:{kind}` capability that exists in
    /// no ceiling, no role catalogue and no UCAN stem — denying every client
    /// unconditionally on every bridge.
    ///
    /// Returns `Ok(())` if permitted, or an error message if denied.
    ///
    /// # Errors
    ///
    /// Returns an error message if the agent lacks the required capability.
    fn validate_capability(&self, context_id: &str, tool_name: &str) -> Result<(), String>;

    /// Validates whether the agent may read a context resource
    /// (`scp://{context_id}/{kind}`).
    ///
    /// This is a distinct authorization axis from [`Self::validate_capability`]
    /// and MUST be answered from real context state, not stubbed:
    ///
    /// - [`ResourceKind::Events`] and [`ResourceKind::Members`] project the
    ///   context's event stream and roster. Per spec §5.3.1's role table an
    ///   `observer` — whose only capability is `messages:read` — "can see all
    ///   content and membership", so `Capability::MessagesRead` is the grant
    ///   these two require.
    /// - [`ResourceKind::Tools`] needs no separate grant: its *contents* are
    ///   the same capability-filtered list `tools/list` returns, so an agent
    ///   with no tool capabilities reads an empty array rather than being
    ///   denied. Implementations should return `Ok(())` for it whenever the
    ///   agent participates in the context.
    ///
    /// The same predicate gates `resources/list`, `resources/read`,
    /// `resources/subscribe` **and** notification delivery, so a client can
    /// never hold a subscription to a resource it cannot read (which would be
    /// an activity oracle over denied state).
    ///
    /// # Errors
    ///
    /// Returns an error message if the agent may not read the resource.
    fn validate_resource_access(
        &self,
        context_id: &str,
        resource: ResourceKind,
    ) -> Result<(), String>;

    /// Invokes a tool and returns its output as a JSON value.
    ///
    /// The implementation is responsible for schema validation and execution.
    ///
    /// # Errors
    ///
    /// Returns an error message if tool execution fails.
    fn invoke_outlet(
        &self,
        context_id: &str,
        tool_name: &str,
        arguments: Value,
    ) -> Result<Value, String>;

    /// Returns the current members of a context.
    fn context_members(&self, context_id: &str) -> Vec<MemberInfo>;

    /// Returns recent events for a context as a JSON value.
    fn context_events(&self, context_id: &str) -> Value;
}

// ---------------------------------------------------------------------------
// McpServer
// ---------------------------------------------------------------------------

/// An MCP server that exposes SCP context tools to MCP-compatible models.
///
/// Wraps a [`ContextProvider`] and handles JSON-RPC 2.0 request routing,
/// capability filtering, tool invocation, resource listing, and MCP lifecycle.
pub struct McpServer<P: ContextProvider> {
    /// The context provider backing this server.
    provider: P,
    /// Whether the client has completed the MCP initialize handshake.
    initialized: bool,
    /// Client capabilities received during initialization.
    client_capabilities: Option<ClientCapabilities>,
    /// Active resource subscriptions (URIs).
    subscriptions: HashSet<String>,
    /// Whether a real runtime event source is wired to this server.
    ///
    /// Set only by [`McpServer::with_event_source`], which is the *only*
    /// constructor that yields a [`ContextEventPump`] — so the flag cannot be
    /// true without the machinery that honours it existing, and cannot be
    /// false while that machinery exists. It decides every promise this server
    /// makes that only the pump can keep: `resources.subscribe`,
    /// `resources.listChanged` and `tools.listChanged` at `initialize`, and
    /// whether `resources/subscribe` is accepted.
    event_source_wired: bool,
}

/// The receiving half of a wired [`ContextEvent`] source, produced by
/// [`McpServer::with_event_source`] together with the server it feeds.
///
/// It exists so the "capability advertised" and "capability deliverable" states
/// are one value rather than two that a caller could set independently: there
/// is no way to obtain a server with `resources.subscribe: true` without also
/// obtaining the pump, and no way to obtain the pump without a server that
/// advertises it. A transport takes this by value and drives it; dropping it
/// unspawned is a bug the `#[must_use]` catches at compile time.
#[must_use = "hand this to a transport (run_stdio / run_sse) — dropping it leaves \
              resources.subscribe advertised with nothing delivering notifications"]
pub struct ContextEventPump {
    rx: broadcast::Receiver<ContextEventEnvelope>,
}

impl ContextEventPump {
    /// Consumes the pump, yielding the underlying receiver for a transport's
    /// delivery loop.
    pub(crate) fn into_receiver(self) -> broadcast::Receiver<ContextEventEnvelope> {
        self.rx
    }
}

impl std::fmt::Debug for ContextEventPump {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ContextEventPump")
    }
}

impl<P: ContextProvider> McpServer<P> {
    /// Creates an MCP server with **no** event source.
    ///
    /// Such a server advertises `resources.subscribe: false`,
    /// `resources.listChanged: false` and `tools.listChanged: false`, and
    /// rejects `resources/subscribe` with a typed error. There is no method
    /// that flips those flags afterwards — to serve subscriptions, construct
    /// with [`Self::with_event_source`] instead.
    #[must_use]
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            initialized: false,
            client_capabilities: None,
            subscriptions: HashSet::new(),
            // Fail closed: no event source, no promises that need one.
            event_source_wired: false,
        }
    }

    /// Creates an MCP server wired to a live [`ContextEvent`] source, together
    /// with the [`ContextEventPump`] a transport must drive.
    ///
    /// `rx` comes from
    /// [`Supervisor::subscribe_events`](scp_core::context::supervisor::Supervisor::subscribe_events).
    /// Because the flag and the pump are produced by this one call, the server
    /// is structurally unable to advertise a subscription it cannot deliver:
    /// there is no setter to desynchronize them.
    pub fn with_event_source(
        provider: P,
        rx: broadcast::Receiver<ContextEventEnvelope>,
    ) -> (Self, ContextEventPump) {
        let server = Self {
            provider,
            initialized: false,
            client_capabilities: None,
            subscriptions: HashSet::new(),
            event_source_wired: true,
        };
        (server, ContextEventPump { rx })
    }

    /// Creates an MCP server from an *optional* event source.
    ///
    /// Convenience for bridge code holding
    /// `Option<broadcast::Receiver<ContextEventEnvelope>>` from
    /// `Supervisor::subscribe_events()`: `Some` routes to
    /// [`Self::with_event_source`], `None` to [`Self::new`]. The returned
    /// `Option<ContextEventPump>` is `Some` exactly when the server advertises
    /// subscriptions.
    pub fn with_optional_event_source(
        provider: P,
        rx: Option<broadcast::Receiver<ContextEventEnvelope>>,
    ) -> (Self, Option<ContextEventPump>) {
        match rx {
            Some(rx) => {
                let (server, pump) = Self::with_event_source(provider, rx);
                (server, Some(pump))
            }
            None => (Self::new(provider), None),
        }
    }

    /// Returns whether a real runtime event source is wired to this server.
    ///
    /// This is the single bit behind `resources.subscribe`,
    /// `resources.listChanged` and `tools.listChanged`.
    #[must_use]
    pub const fn event_source_wired(&self) -> bool {
        self.event_source_wired
    }

    /// Returns a reference to the underlying context provider.
    #[must_use]
    pub const fn provider(&self) -> &P {
        &self.provider
    }

    /// Returns whether the MCP handshake has completed.
    #[must_use]
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    // -----------------------------------------------------------------------
    // Top-level request dispatch
    // -----------------------------------------------------------------------

    /// Handles an incoming JSON-RPC request and returns a response.
    ///
    /// Routes to the appropriate handler based on the `method` field.
    /// Notifications (`initialized`) return `None` (no response expected).
    pub fn handle_request(&mut self, request: &JsonRpcRequest) -> Option<JsonRpcResponse> {
        // Pre-initialization guard: only `initialize` and `ping` are allowed
        // before the server has completed the initialization handshake.
        if !self.initialized
            && request.method.as_str() != protocol::METHOD_INITIALIZE
            && request.method.as_str() != protocol::METHOD_PING
        {
            return Some(JsonRpcResponse::error(
                request.id.clone(),
                JsonRpcError {
                    code: protocol::INVALID_REQUEST,
                    message: "server not initialized: send initialize first".to_owned(),
                    data: None,
                },
            ));
        }

        match request.method.as_str() {
            protocol::METHOD_INITIALIZE => Some(self.handle_initialize(request)),
            protocol::METHOD_INITIALIZED => {
                self.handle_initialized();
                None // Notification -- no response.
            }
            protocol::METHOD_PING => Some(self.handle_ping(request)),
            protocol::METHOD_TOOLS_LIST => Some(self.handle_tools_list(request)),
            protocol::METHOD_TOOLS_CALL => Some(self.handle_tools_call(request)),
            protocol::METHOD_RESOURCES_LIST => Some(self.handle_resources_list(request)),
            protocol::METHOD_RESOURCES_READ => Some(self.handle_resources_read(request)),
            protocol::METHOD_RESOURCES_SUBSCRIBE => Some(self.handle_resources_subscribe(request)),
            protocol::METHOD_RESOURCES_UNSUBSCRIBE => {
                Some(self.handle_resources_unsubscribe(request))
            }
            _ => Some(JsonRpcResponse::error(
                request.id.clone(),
                JsonRpcError {
                    code: protocol::METHOD_NOT_FOUND,
                    message: format!("unknown method: {}", request.method),
                    data: None,
                },
            )),
        }
    }

    // -----------------------------------------------------------------------
    // MCP lifecycle handlers
    // -----------------------------------------------------------------------

    /// Handles the `initialize` request.
    fn handle_initialize(&mut self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let params: InitializeParams = match parse_params(request.params.as_ref()) {
            Ok(p) => p,
            Err(resp) => return with_id(resp, request.id.clone()),
        };

        self.client_capabilities = Some(params.capabilities);
        self.initialized = true;

        // Every advertised capability below is *derived* from
        // `event_source_wired`, never asserted. `notifications/tools/list_changed`
        // and `notifications/resources/list_changed` have exactly one production
        // emitter — `notifications_for_event`, driven by the pump — so without an
        // event source they can never be sent, and claiming otherwise is the same
        // false guarantee `resources.subscribe: true` used to make.
        let wired = self.event_source_wired;
        let result = InitializeResult {
            protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
            capabilities: ServerCapabilities {
                tools: Some(ToolServerCapability {
                    list_changed: wired,
                }),
                resources: Some(ResourceServerCapability {
                    subscribe: wired,
                    list_changed: wired,
                }),
            },
            server_info: ServerInfo {
                name: SERVER_NAME.to_owned(),
                version: Some(SERVER_VERSION.to_owned()),
            },
        };

        match serde_json::to_value(&result) {
            Ok(v) => JsonRpcResponse::success(request.id.clone(), v),
            Err(e) => internal_error(request.id.clone(), &e.to_string()),
        }
    }

    /// Handles the `notifications/initialized` notification.
    // Instance method signature kept for consistency with other handle_* methods
    // in the dispatch table; will use `self` for metrics/logging.
    #[allow(clippy::unused_self, clippy::missing_const_for_fn)]
    fn handle_initialized(&self) {
        // The client confirms it received the initialize response.
        // No action needed beyond what `handle_initialize` already did.
    }

    /// Handles the `ping` request.
    // Instance method signature kept for consistency with other handle_* methods
    // in the dispatch table; will use `self` for metrics/logging.
    #[allow(clippy::unused_self)]
    fn handle_ping(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        JsonRpcResponse::success(
            request.id.clone(),
            Value::Object(serde_json::Map::default()),
        )
    }

    // -----------------------------------------------------------------------
    // Tool listing
    // -----------------------------------------------------------------------

    /// Returns the capability-filtered tool definitions for one context.
    ///
    /// Single source for both `tools/list` and the `scp://{ctx}/tools`
    /// resource, so the resource can never surface a tool the agent is not
    /// permitted to see (which would make the resource a capability oracle
    /// over `tools/list`).
    fn visible_tools(&self, context_id: &str) -> Vec<ToolDefinition> {
        let agent_is_admin = self
            .provider
            .agent_role(context_id)
            .as_deref()
            .is_some_and(|r| r == "admin");

        let mut tools: Vec<ToolDefinition> = Vec::new();

        // Built-in tools -- available to participants that hold the capability.
        for builtin in BUILTIN_TOOLS {
            if self
                .provider
                .validate_capability(context_id, builtin.tool_name())
                .is_ok()
            {
                tools.push(builtin.to_tool_definition(context_id));
            }
        }

        // Context-registered outlets -- filtered by capability. Names are
        // kind-projected per §8.5 (Query → `query.{id}`, Action → `call.{id}`)
        // so MCP-consuming models can distinguish them lexically.
        for outlet_info in self.provider.context_tools(context_id) {
            // Skip admin-only outlets for non-admin agents.
            if outlet_info.admin_only && !agent_is_admin {
                continue;
            }

            // Validate capability against the outlet_id (SCP-internal name).
            // The kind prefix is an MCP-facing display concern, not part of
            // the authorization check.
            if self
                .provider
                .validate_capability(context_id, &outlet_info.name)
                .is_ok()
            {
                let mcp_name = format_mcp_tool_name(outlet_info.kind, &outlet_info.name);
                tools.push(context_tool_definition(
                    context_id,
                    &mcp_name,
                    outlet_info.description.as_deref(),
                    outlet_info.input_schema.clone(),
                ));
            }
        }

        tools
    }

    /// Handles `tools/list` -- returns all tools the agent can access across
    /// all active contexts, filtered by capability.
    fn handle_tools_list(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let mut tools: Vec<ToolDefinition> = Vec::new();
        for context_id in self.provider.active_context_ids() {
            tools.extend(self.visible_tools(&context_id));
        }

        let result = ToolsListResult {
            tools,
            next_cursor: None,
        };

        match serde_json::to_value(&result) {
            Ok(v) => JsonRpcResponse::success(request.id.clone(), v),
            Err(e) => internal_error(request.id.clone(), &e.to_string()),
        }
    }

    // -----------------------------------------------------------------------
    // Tool invocation
    // -----------------------------------------------------------------------

    /// Handles `tools/call` -- parses context namespace, validates membership
    /// and capability, validates input against schema, invokes the tool,
    /// validates output, and attaches provenance.
    // Five sequential validation phases (namespace parse, membership, UCAN,
    // input schema, output schema) plus invocation and provenance attachment
    // form a linear pipeline that reads worse when split across functions.
    #[allow(clippy::too_many_lines)]
    fn handle_tools_call(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let params: ToolsCallParams = match parse_params(request.params.as_ref()) {
            Ok(p) => p,
            Err(resp) => return with_id(resp, request.id.clone()),
        };

        // Parse namespace: context_id/tool_name.
        let (context_id, mcp_tool_name) = match parse_namespaced_tool(&params.name) {
            Ok(parsed) => parsed,
            Err(e) => {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    JsonRpcError {
                        code: protocol::INVALID_PARAMS,
                        message: e.to_string(),
                        data: None,
                    },
                );
            }
        };

        // Kind-prefix stripping per §8.5: MCP tool.name may carry a
        // `query.` / `call.` prefix projected from the outlet kind. The
        // authorization layer works with the SCP outlet_id, so strip the
        // prefix before validation and invocation. An unrecognized prefix
        // falls back to using the full name as the outlet_id with kind =
        // Action (fail-safe default per AC14).
        // The recovered kind is intentionally unused here: this MCP handler is
        // kind-agnostic and defers the Query/Action enforcement difference to
        // the runtime authorization gate — the ReadOnlyInvocation guard
        // (SCP-OUT-013) plus the split UCAN stems (SCP-OUT-014), which resolve
        // kind from the registry. It is NOT recorded in provenance. Note an
        // inbound (caller-derived) kind is advisory only; the authoritative kind
        // is the registry's — see the SECURITY note in translator.rs.
        let (_outlet_kind, owned_outlet_id) = parse_mcp_tool_name(mcp_tool_name);
        let tool_name: &str = owned_outlet_id.as_str();

        // Verify caller is a member of the target context.
        if !self
            .provider
            .active_context_ids()
            .iter()
            .any(|id| id == &context_id)
        {
            return JsonRpcResponse::error(
                request.id.clone(),
                JsonRpcError {
                    code: protocol::INTERNAL_ERROR,
                    message: format!(
                        "membership check failed: caller is not a member of context {context_id}"
                    ),
                    data: None,
                },
            );
        }

        // Validate UCAN capability.
        if let Err(msg) = self.provider.validate_capability(&context_id, tool_name) {
            return JsonRpcResponse::error(
                request.id.clone(),
                JsonRpcError {
                    code: protocol::CAPABILITY_DENIED,
                    message: msg,
                    data: None,
                },
            );
        }

        // Validate input against schema.
        if let Some(schema) = self.find_input_schema(&context_id, tool_name)
            && let Err(msg) = validate_value_against_schema(&params.arguments, &schema)
        {
            return JsonRpcResponse::error(
                request.id.clone(),
                JsonRpcError {
                    code: protocol::INVALID_PARAMS,
                    message: format!("schema validation failed: {msg}"),
                    data: None,
                },
            );
        }

        // Invoke the tool.
        match self
            .provider
            .invoke_outlet(&context_id, tool_name, params.arguments)
        {
            Ok(output) => {
                // Validate output against schema if available.
                if let Some(out_schema) = self.find_output_schema(&context_id, tool_name)
                    && let Err(msg) = validate_value_against_schema(&output, &out_schema)
                {
                    return JsonRpcResponse::error(
                        request.id.clone(),
                        JsonRpcError {
                            code: protocol::TOOL_EXECUTION_ERROR,
                            message: format!("output schema validation failed: {msg}"),
                            data: None,
                        },
                    );
                }

                // Attach provenance.
                let provenance = ToolProvenance {
                    invoked_by: self.provider.agent_did().to_owned(),
                    context_id: context_id.clone(),
                    tool_name: tool_name.to_owned(),
                };

                // Build response with output and provenance as _meta.
                let content_text = match serde_json::to_string(&output) {
                    Ok(s) => s,
                    Err(e) => {
                        return internal_error(request.id.clone(), &e.to_string());
                    }
                };

                let tool_result = ToolsCallResult {
                    content: vec![ContentItem::Text { text: content_text }],
                    is_error: false,
                };

                match serde_json::to_value(&tool_result) {
                    Ok(Value::Object(mut obj)) => {
                        if let Ok(prov_val) = serde_json::to_value(&provenance) {
                            let mut meta = serde_json::Map::new();
                            meta.insert("provenance".to_owned(), prov_val);
                            obj.insert("_meta".to_owned(), Value::Object(meta));
                        }
                        JsonRpcResponse::success(request.id.clone(), Value::Object(obj))
                    }
                    Ok(v) => JsonRpcResponse::success(request.id.clone(), v),
                    Err(e) => internal_error(request.id.clone(), &e.to_string()),
                }
            }
            Err(msg) => JsonRpcResponse::error(
                request.id.clone(),
                JsonRpcError {
                    code: protocol::TOOL_EXECUTION_ERROR,
                    message: msg,
                    data: None,
                },
            ),
        }
    }

    // -----------------------------------------------------------------------
    // Resource handlers
    // -----------------------------------------------------------------------

    /// Handles `resources/list` -- returns SCP context resources (events,
    /// members, tools) for all active contexts.
    ///
    /// Only resources the agent is actually authorized to read are listed.
    /// Listing a URI that `resources/read` then denies would advertise a
    /// resource the server cannot serve — the same class of false guarantee as
    /// advertising an undeliverable subscription — and would leak the
    /// existence of denied state.
    fn handle_resources_list(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let mut resources: Vec<ResourceDefinition> = Vec::new();

        for context_id in self.provider.active_context_ids() {
            for kind in RESOURCE_KINDS {
                if self
                    .provider
                    .validate_resource_access(&context_id, kind)
                    .is_err()
                {
                    continue;
                }
                resources.push(ResourceDefinition {
                    uri: kind.uri(&context_id),
                    name: format!("{context_id} {}", kind.display_name()),
                    description: Some(format!("{} {context_id}", kind.description())),
                    mime_type: Some("application/json".to_owned()),
                });
            }
        }

        let result = ResourcesListResult {
            resources,
            next_cursor: None,
        };

        match serde_json::to_value(&result) {
            Ok(v) => JsonRpcResponse::success(request.id.clone(), v),
            Err(e) => internal_error(request.id.clone(), &e.to_string()),
        }
    }

    /// The single authorization predicate for every resource operation.
    ///
    /// `resources/list`, `resources/read`, `resources/subscribe` and
    /// notification delivery all funnel through this, so the set of resources
    /// a client can subscribe to is exactly the set it can read. Any looser
    /// subscribe gate would hand the client an activity/timing oracle over
    /// state it is denied.
    ///
    /// Checks participation first so a non-participant learns only "not
    /// found", never whether a capability would have been granted.
    fn authorize_resource(
        &self,
        uri: &str,
        context_id: &str,
        kind: ResourceKind,
        request_id: &RequestId,
    ) -> Result<(), Box<JsonRpcResponse>> {
        if !self
            .provider
            .active_context_ids()
            .iter()
            .any(|served| served == context_id)
        {
            return Err(Box::new(resource_not_found(
                request_id.clone(),
                uri,
                format!("not a participant in context: {context_id}"),
            )));
        }

        self.provider
            .validate_resource_access(context_id, kind)
            .map_err(|msg| {
                Box::new(JsonRpcResponse::error(
                    request_id.clone(),
                    JsonRpcError {
                        code: protocol::CAPABILITY_DENIED,
                        message: msg,
                        data: Some(serde_json::json!({ "uri": uri })),
                    },
                ))
            })
    }

    /// Handles `resources/read` -- returns the current state of a resource.
    fn handle_resources_read(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let params: protocol::ResourcesReadParams = match parse_params(request.params.as_ref()) {
            Ok(p) => p,
            Err(resp) => return with_id(resp, request.id.clone()),
        };

        let (context_id, kind) = match parse_resource_uri(&params.uri) {
            Ok(parsed) => parsed,
            Err(msg) => return resource_not_found(request.id.clone(), &params.uri, msg),
        };

        if let Err(resp) = self.authorize_resource(&params.uri, &context_id, kind, &request.id) {
            return *resp;
        }

        let content_text = match kind {
            ResourceKind::Events => {
                let events = self.provider.context_events(&context_id);
                serde_json::to_string(&events)
            }
            ResourceKind::Members => {
                let members = self.provider.context_members(&context_id);
                serde_json::to_string(&members)
            }
            // Capability-filtered, exactly as `tools/list` is — this resource
            // must not become a side channel that names tools the agent may
            // not invoke.
            ResourceKind::Tools => {
                let names: Vec<String> = self
                    .visible_tools(&context_id)
                    .into_iter()
                    .map(|t| t.name)
                    .collect();
                serde_json::to_string(&names)
            }
        };

        match content_text {
            Ok(text) => {
                let result = ResourcesReadResult {
                    contents: vec![ResourceContent {
                        uri: params.uri,
                        mime_type: Some("application/json".to_owned()),
                        text: Some(text),
                        blob: None,
                    }],
                };
                match serde_json::to_value(&result) {
                    Ok(v) => JsonRpcResponse::success(request.id.clone(), v),
                    Err(e) => internal_error(request.id.clone(), &e.to_string()),
                }
            }
            Err(e) => internal_error(request.id.clone(), &e.to_string()),
        }
    }

    /// Handles `resources/subscribe` -- registers a subscription for resource
    /// updates.
    ///
    /// Authorization is **identical** to `resources/read`
    /// ([`Self::authorize_resource`]): participation in the named context plus
    /// the provider's resource grant. A looser subscribe gate would let a
    /// client hold a live subscription to a resource it cannot read and learn,
    /// from notification timing alone, that denied state is changing.
    fn handle_resources_subscribe(&mut self, request: &JsonRpcRequest) -> JsonRpcResponse {
        if let Some(resp) = self.reject_if_subscriptions_unwired(request) {
            return resp;
        }

        let params: ResourcesSubscribeParams = match parse_params(request.params.as_ref()) {
            Ok(p) => p,
            Err(resp) => return with_id(resp, request.id.clone()),
        };

        let (context_id, kind) = match parse_resource_uri(&params.uri) {
            Ok(parsed) => parsed,
            Err(msg) => return resource_not_found(request.id.clone(), &params.uri, msg),
        };

        if let Err(resp) = self.authorize_resource(&params.uri, &context_id, kind, &request.id) {
            return *resp;
        }

        self.subscriptions.insert(params.uri);

        JsonRpcResponse::success(
            request.id.clone(),
            Value::Object(serde_json::Map::default()),
        )
    }

    /// Handles `resources/unsubscribe` -- cancels a resource subscription.
    ///
    /// Idempotent: unsubscribing from a URI that is not currently subscribed
    /// succeeds. The MCP spec defines no distinct "not subscribed" error, and
    /// a client retrying an unsubscribe after a dropped response must not see
    /// a spurious failure.
    fn handle_resources_unsubscribe(&mut self, request: &JsonRpcRequest) -> JsonRpcResponse {
        if let Some(resp) = self.reject_if_subscriptions_unwired(request) {
            return resp;
        }

        let params: protocol::ResourcesUnsubscribeParams =
            match parse_params(request.params.as_ref()) {
                Ok(p) => p,
                Err(resp) => return with_id(resp, request.id.clone()),
            };

        // Validate the URI format so a malformed URI is reported rather than
        // silently treated as "nothing to remove".
        if let Err(msg) = parse_resource_uri(&params.uri) {
            return resource_not_found(request.id.clone(), &params.uri, msg);
        }

        self.subscriptions.remove(&params.uri);

        JsonRpcResponse::success(
            request.id.clone(),
            Value::Object(serde_json::Map::default()),
        )
    }

    /// Rejects a subscription request when no event source is wired.
    ///
    /// Returns `METHOD_NOT_FOUND`, matching the `resources.subscribe: false`
    /// this server advertised at `initialize`: the capability is honestly
    /// absent, and a client that ignores the advertisement gets a typed error
    /// rather than a success that never produces a notification.
    fn reject_if_subscriptions_unwired(&self, request: &JsonRpcRequest) -> Option<JsonRpcResponse> {
        if self.event_source_wired {
            return None;
        }
        Some(JsonRpcResponse::error(
            request.id.clone(),
            JsonRpcError {
                code: protocol::METHOD_NOT_FOUND,
                message: format!(
                    "{} is not supported: this server advertises \
                     resources.subscribe=false because no context event source is wired",
                    request.method
                ),
                data: None,
            },
        ))
    }

    // -----------------------------------------------------------------------
    // Dynamic context update notifications
    // -----------------------------------------------------------------------

    /// Returns whether the given resource URI currently has an active
    /// subscription.
    #[must_use]
    pub fn is_subscribed(&self, uri: &str) -> bool {
        self.subscriptions.contains(uri)
    }

    /// Returns the number of active resource subscriptions.
    #[must_use]
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }

    /// Resets every piece of per-session state.
    ///
    /// Called when a transport session ends. The next client must complete its
    /// own `initialize` handshake and re-register its subscriptions rather than
    /// inheriting the previous session's — a client that skipped the handshake
    /// would never learn which capabilities this server advertises, and one
    /// that inherited a subscription registry would receive updates it never
    /// asked for.
    ///
    /// `event_source_wired` is deliberately *not* reset: it describes the
    /// server's wiring, not the session.
    pub fn reset_session(&mut self) {
        self.subscriptions.clear();
        self.initialized = false;
        self.client_capabilities = None;
    }

    /// Creates a `notifications/tools/list_changed` notification.
    #[must_use]
    pub fn tools_list_changed_notification() -> JsonRpcNotification {
        JsonRpcNotification::new(protocol::METHOD_TOOLS_LIST_CHANGED, None)
    }

    /// Creates a `notifications/resources/list_changed` notification.
    #[must_use]
    pub fn resources_list_changed_notification() -> JsonRpcNotification {
        JsonRpcNotification::new(protocol::METHOD_RESOURCES_LIST_CHANGED, None)
    }

    /// Creates a `notifications/resources/updated` notification for `uri`.
    #[must_use]
    pub fn resource_updated_notification(uri: &str) -> JsonRpcNotification {
        JsonRpcNotification::new(
            protocol::METHOD_RESOURCES_UPDATED,
            Some(serde_json::json!({ "uri": uri })),
        )
    }

    /// Maps a runtime [`ContextEvent`] to the MCP notifications that must be
    /// pushed to the connected client.
    ///
    /// Returns one `notifications/resources/updated` per *subscribed* resource
    /// URI that the event invalidates, plus `notifications/tools/list_changed`
    /// and `notifications/resources/list_changed` when the event changes the
    /// visible tool set / the served resource set.
    ///
    /// # Re-authorization on every emission
    ///
    /// Each candidate URI is re-checked through the same
    /// [`Self::authorize_resource`] predicate that admitted the subscription.
    /// Capabilities are revocable mid-session — `CapabilitiesSuspended`,
    /// `ReadAccessRevoked` and `MemberLeft` are all in the classifier below —
    /// so a subscription registered while authorized must stop delivering the
    /// moment it is not. Without this the subscription would outlive the grant
    /// and become exactly the activity oracle the subscribe gate prevents.
    ///
    /// The subscription is *filtered*, not dropped: suspension is reversible
    /// (`ReadAccessRestored`, `CapabilitiesSuspended` expiry) and MCP has no
    /// server-initiated unsubscribe notification, so silently forgetting the
    /// registration would leave a client permanently stale after restoration
    /// with no way to learn it must re-subscribe.
    ///
    /// Events for contexts this server does not serve produce no notifications.
    #[must_use]
    pub fn notifications_for_event(
        &self,
        context_id: &str,
        event: &ContextEvent,
    ) -> Vec<JsonRpcNotification> {
        // A server that advertised none of the pump-backed capabilities must
        // produce none of their notifications, even if some caller hands it an
        // event anyway. This makes "advertised ⟺ emittable" total rather than
        // relying on the pump being the only caller.
        if !self.event_source_wired {
            return Vec::new();
        }

        let serves_context = self
            .provider
            .active_context_ids()
            .iter()
            .any(|c| c == context_id);
        if !serves_context {
            return Vec::new();
        }

        let affected = affected_resources(event);
        let mut out = Vec::new();

        for (changed, kind) in [
            (affected.events, ResourceKind::Events),
            (affected.members, ResourceKind::Members),
            (affected.tools, ResourceKind::Tools),
        ] {
            if !changed {
                continue;
            }
            let uri = kind.uri(context_id);
            if !self.subscriptions.contains(&uri) {
                continue;
            }
            if self
                .provider
                .validate_resource_access(context_id, kind)
                .is_err()
            {
                continue;
            }
            out.push(Self::resource_updated_notification(&uri));
        }

        if affected.tools {
            out.push(Self::tools_list_changed_notification());
            // The resource *set* is derived from `active_context_ids()`, and
            // the events classified as `tools` are exactly the membership and
            // lifecycle transitions that add or remove a served context — so
            // the client's cached `resources/list` is stale here too.
            out.push(Self::resources_list_changed_notification());
        }

        out
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Finds the input schema for a tool (built-in or context-registered).
    fn find_input_schema(&self, context_id: &str, tool_name: &str) -> Option<Value> {
        // Check built-in tools first.
        if let Some(builtin) = BuiltinTool::from_tool_name(tool_name) {
            return Some(builtin.input_schema());
        }

        // Check context-registered tools.
        self.provider
            .context_tools(context_id)
            .iter()
            .find(|t| t.name == tool_name)
            .map(|t| t.input_schema.clone())
    }

    /// Finds the output schema for a tool (context-registered only; built-ins
    /// have no output schema).
    fn find_output_schema(&self, context_id: &str, tool_name: &str) -> Option<Value> {
        self.provider
            .context_tools(context_id)
            .iter()
            .find(|t| t.name == tool_name)
            .and_then(|t| t.output_schema.clone())
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

/// Parses the `params` field of a JSON-RPC request into the expected type.
///
/// Returns the parsed value or a JSON-RPC error response (without an ID --
/// caller must attach the ID).
fn parse_params<T: serde::de::DeserializeOwned>(
    params: Option<&Value>,
) -> Result<T, Box<JsonRpcResponse>> {
    let value = params
        .cloned()
        .unwrap_or_else(|| Value::Object(serde_json::Map::default()));

    serde_json::from_value(value).map_err(|e| {
        Box::new(JsonRpcResponse::error(
            RequestId::Number(0), // Placeholder -- caller replaces.
            JsonRpcError {
                code: protocol::INVALID_PARAMS,
                message: format!("invalid params: {e}"),
                data: None,
            },
        ))
    })
}

/// Replaces the ID on a placeholder error response.
// Accepts Box<JsonRpcResponse> to pair with parse_params which returns
// Box<JsonRpcResponse> as the error type to avoid clippy::result_large_err.
#[allow(clippy::boxed_local)]
fn with_id(response: Box<JsonRpcResponse>, id: RequestId) -> JsonRpcResponse {
    let mut resp = *response;
    resp.id = id;
    resp
}

/// Creates a `-32002` resource-not-found response.
///
/// The MCP specification's example for this code carries the offending URI in
/// `data`, so a client handling several outstanding resource requests can tell
/// which one failed without correlating on the message text.
fn resource_not_found(id: RequestId, uri: &str, message: String) -> JsonRpcResponse {
    JsonRpcResponse::error(
        id,
        JsonRpcError {
            code: protocol::RESOURCE_NOT_FOUND,
            message,
            data: Some(serde_json::json!({ "uri": uri })),
        },
    )
}

/// Creates an internal error response.
fn internal_error(id: RequestId, message: &str) -> JsonRpcResponse {
    JsonRpcResponse::error(
        id,
        JsonRpcError {
            code: protocol::INTERNAL_ERROR,
            message: format!("internal error: {message}"),
            data: None,
        },
    )
}

/// Which of a context's MCP resources a [`ContextEvent`] invalidates.
///
/// Crate-internal: the fields name resource URIs that only [`ResourceKind`]
/// knows how to build, so this type is not something an external caller can act
/// on. Exposing it publicly would invite consumers to reconstruct those URIs by
/// hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AffectedResources {
    /// `scp://{ctx}/events` -- the context event stream.
    pub(crate) events: bool,
    /// `scp://{ctx}/members` -- the member list and role assignments.
    pub(crate) members: bool,
    /// `scp://{ctx}/tools` -- the capability-filtered tool list.
    pub(crate) tools: bool,
}

/// Classifies a [`ContextEvent`] by which MCP resources it invalidates.
///
/// **Bias: over-notify, never under-notify.** MCP clients respond to
/// `notifications/resources/updated` by re-reading the resource, so a spurious
/// notification costs one extra read, while a missed notification leaves the
/// client permanently stale. Where a variant's effect on the member list or
/// the capability-filtered tool list is ambiguous, it is classified as
/// affecting them.
///
/// `events` is true for every variant: `scp://{ctx}/events` exposes the
/// context event stream, which every event is by definition part of.
///
/// The match is exhaustive (no wildcard) so that adding a `ContextEvent`
/// variant fails to compile until its resource impact is decided — the same
/// discipline `strip_event_payload` uses in `scp-runtime`.
#[must_use]
pub(crate) const fn affected_resources(event: &ContextEvent) -> AffectedResources {
    // Changes the member list / role assignments AND the agent's
    // capability-filtered tool list.
    let members_and_tools = AffectedResources {
        events: true,
        members: true,
        tools: true,
    };
    // Changes the member list only (key/block-list state, not capabilities).
    let members_only = AffectedResources {
        events: true,
        members: true,
        tools: false,
    };
    // Data-plane / plumbing events: the event stream only.
    let events_only = AffectedResources {
        events: true,
        members: false,
        tools: false,
    };

    match event {
        // -- Membership, capability and lifecycle changes ------------------
        ContextEvent::MemberJoined { .. }
        | ContextEvent::MemberLeft { .. }
        | ContextEvent::ReadAccessRevoked { .. }
        | ContextEvent::ReadAccessRestored { .. }
        | ContextEvent::WriteAccessRevoked { .. }
        | ContextEvent::WriteAccessRestored { .. }
        | ContextEvent::CapabilitiesSuspended { .. }
        | ContextEvent::GovernanceActionExecuted { .. }
        | ContextEvent::CeilingChangeNotification { .. }
        | ContextEvent::ConsequenceTriggered { .. }
        | ContextEvent::ConsequenceEnforced { .. }
        | ContextEvent::ContextMigrationStarted { .. }
        | ContextEvent::ContextTombstoned { .. }
        | ContextEvent::SystemClose { .. }
        | ContextEvent::Expired
        | ContextEvent::ExpiryFailed { .. } => members_and_tools,

        // -- Member-state changes that do not alter the visible tool set ---
        ContextEvent::MemberBlocked { .. }
        | ContextEvent::MemberUnblocked { .. }
        | ContextEvent::AuthorBlocked { .. }
        | ContextEvent::AccessKeyRevoked { .. }
        | ContextEvent::AccessKeyRestored { .. } => members_only,

        // -- Event-stream-only ---------------------------------------------
        ContextEvent::MessageSent { .. }
        | ContextEvent::MessageReceived { .. }
        | ContextEvent::ContentKeysRotated { .. }
        | ContextEvent::EconomicPolicyChangeNotification { .. }
        | ContextEvent::VoteWithdrawn { .. }
        | ContextEvent::ProposalTimedOut { .. }
        | ContextEvent::DeadlockDetected { .. }
        | ContextEvent::AppBound { .. }
        | ContextEvent::AppUnbound { .. }
        | ContextEvent::DegradedMode { .. }
        | ContextEvent::WelcomeGenerated { .. }
        | ContextEvent::BufferOverflow { .. }
        | ContextEvent::SequenceGapDetected { .. }
        | ContextEvent::CheckpointCosignatureRequired { .. }
        | ContextEvent::ContextMigrationProposed { .. }
        | ContextEvent::ContextMigrationCancelled { .. }
        | ContextEvent::PaymentCaptureFailed { .. }
        | ContextEvent::PaymentReceived { .. }
        | ContextEvent::CommitBroadcastPending { .. }
        | ContextEvent::CommitBroadcastSucceeded { .. }
        | ContextEvent::CommitBroadcastFailed { .. }
        | ContextEvent::EquivocationDetected { .. }
        | ContextEvent::PseudonymAnnounced { .. } => events_only,
    }
}

/// Parses a resource URI into `(context_id, kind)`.
///
/// Expected format: `scp://{context_id}/{kind}` where `kind` is one of
/// [`ResourceKind`]'s suffixes. An unrecognized suffix fails here rather than
/// downstream, so no handler ever sees a resource type it has no arm for.
fn parse_resource_uri(uri: &str) -> Result<(String, ResourceKind), String> {
    let stripped = uri.strip_prefix(RESOURCE_SCHEME).ok_or_else(|| {
        format!("invalid resource URI: expected {RESOURCE_SCHEME} prefix, got {uri}")
    })?;

    let slash_pos = stripped
        .find('/')
        .ok_or_else(|| format!("invalid resource URI: missing resource type in {uri}"))?;

    let context_id = &stripped[..slash_pos];
    let resource_type = &stripped[slash_pos + 1..];

    if context_id.is_empty() {
        return Err(format!("invalid resource URI: empty context ID in {uri}"));
    }

    if resource_type.is_empty() {
        return Err(format!(
            "invalid resource URI: empty resource type in {uri}"
        ));
    }

    let kind = ResourceKind::from_uri_suffix(resource_type)
        .ok_or_else(|| format!("unknown resource type: {resource_type}"))?;

    Ok((context_id.to_owned(), kind))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::protocol::{JSONRPC_VERSION, METHOD_INITIALIZE, METHOD_PING};

    // -----------------------------------------------------------------------
    // Mock ContextProvider
    // -----------------------------------------------------------------------

    /// Mock provider for testing. Configurable contexts, tools, and capabilities.
    struct MockProvider {
        contexts: Vec<ContextId>,
        agent_did: String,
        roles: Vec<(String, String)>,               // (context_id, role)
        tools: Vec<(String, ContextOutletInfo)>,    // (context_id, tool)
        denied_capabilities: Vec<(String, String)>, // (context_id, tool_name)
        /// Resources the agent may NOT read, as `(context_id, kind)`.
        denied_resources: Vec<(String, ResourceKind)>,
        invoke_result: Result<Value, String>,
        members: Vec<(String, MemberInfo)>,
        events: Value,
    }

    impl Default for MockProvider {
        fn default() -> Self {
            Self {
                contexts: vec!["ctx_a".to_owned(), "ctx_b".to_owned()],
                agent_did: "did:dht:agent123".to_owned(),
                roles: vec![
                    ("ctx_a".to_owned(), "admin".to_owned()),
                    ("ctx_b".to_owned(), "member".to_owned()),
                ],
                tools: Vec::new(),
                denied_capabilities: Vec::new(),
                denied_resources: Vec::new(),
                invoke_result: Ok(serde_json::json!({"status": "ok"})),
                members: vec![
                    (
                        "ctx_a".to_owned(),
                        MemberInfo {
                            did: "did:dht:alice".to_owned(),
                            role: "admin".to_owned(),
                        },
                    ),
                    (
                        "ctx_a".to_owned(),
                        MemberInfo {
                            did: "did:dht:bob".to_owned(),
                            role: "member".to_owned(),
                        },
                    ),
                ],
                events: serde_json::json!([]),
            }
        }
    }

    impl ContextProvider for MockProvider {
        fn active_context_ids(&self) -> Vec<ContextId> {
            self.contexts.clone()
        }

        fn agent_role(&self, context_id: &str) -> Option<String> {
            self.roles
                .iter()
                .find(|(cid, _)| cid == context_id)
                .map(|(_, role)| role.clone())
        }

        fn agent_did(&self) -> &str {
            &self.agent_did
        }

        fn context_tools(&self, context_id: &str) -> Vec<ContextOutletInfo> {
            self.tools
                .iter()
                .filter(|(cid, _)| cid == context_id)
                .map(|(_, tool)| tool.clone())
                .collect()
        }

        fn validate_capability(&self, context_id: &str, tool_name: &str) -> Result<(), String> {
            if self
                .denied_capabilities
                .iter()
                .any(|(cid, tn)| cid == context_id && tn == tool_name)
            {
                Err(format!("capability denied: {tool_name} in {context_id}"))
            } else {
                Ok(())
            }
        }

        fn invoke_outlet(
            &self,
            _context_id: &str,
            _tool_name: &str,
            _arguments: Value,
        ) -> Result<Value, String> {
            self.invoke_result.clone()
        }

        fn validate_resource_access(
            &self,
            context_id: &str,
            resource: ResourceKind,
        ) -> Result<(), String> {
            if self
                .denied_resources
                .iter()
                .any(|(cid, kind)| cid == context_id && *kind == resource)
            {
                Err(format!(
                    "resource access denied: {} in {context_id}",
                    resource.uri_suffix()
                ))
            } else {
                Ok(())
            }
        }

        fn context_members(&self, context_id: &str) -> Vec<MemberInfo> {
            self.members
                .iter()
                .filter(|(cid, _)| cid == context_id)
                .map(|(_, m)| m.clone())
                .collect()
        }

        fn context_events(&self, _context_id: &str) -> Value {
            self.events.clone()
        }
    }

    // -----------------------------------------------------------------------
    // Helper: build JSON-RPC requests
    // -----------------------------------------------------------------------

    fn make_request(method: &str, params: Option<Value>) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            method: method.to_owned(),
            params,
            id: RequestId::Number(1),
        }
    }

    fn init_params() -> Value {
        serde_json::json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "test-client" }
        })
    }

    /// Creates an `McpServer` that has already completed initialization.
    fn initialized_server(provider: MockProvider) -> McpServer<MockProvider> {
        let mut server = McpServer::new(provider);
        let req = make_request(METHOD_INITIALIZE, Some(init_params()));
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_none());
        server
    }

    /// An initialized server with a runtime event source wired, as a transport
    /// would do when it holds a real `ContextEvent` receiver.
    fn subscribing_server(provider: MockProvider) -> McpServer<MockProvider> {
        let (mut server, pump) = McpServer::with_event_source(provider, test_event_source());
        // The pump would go to a transport; these tests drive
        // `notifications_for_event` directly, so hold it rather than drop it.
        std::mem::forget(pump);
        let req = make_request(METHOD_INITIALIZE, Some(init_params()));
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_none());
        server
    }

    /// A live `ContextEvent` receiver standing in for `Supervisor::subscribe_events`.
    ///
    /// The sender is leaked so the channel stays open for the test's lifetime;
    /// these tests exercise `McpServer`, not delivery.
    fn test_event_source() -> broadcast::Receiver<ContextEventEnvelope> {
        let (tx, rx) = broadcast::channel(16);
        std::mem::forget(tx);
        rx
    }

    // -----------------------------------------------------------------------
    // MCP lifecycle tests
    // -----------------------------------------------------------------------

    #[test]
    fn initialize_returns_server_info_and_capabilities() {
        let mut server = McpServer::new(MockProvider::default());
        let req = make_request(METHOD_INITIALIZE, Some(init_params()));
        let resp = server.handle_request(&req).unwrap();

        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], MCP_PROTOCOL_VERSION);
        assert_eq!(result["serverInfo"]["name"], SERVER_NAME);
        assert_eq!(result["serverInfo"]["version"], SERVER_VERSION);
        // `notifications/tools/list_changed` has exactly one emitter — the
        // event pump — so an unwired server must not advertise it either.
        assert!(
            !result["capabilities"]["tools"]["listChanged"]
                .as_bool()
                .unwrap()
        );
        assert!(
            !result["capabilities"]["resources"]["listChanged"]
                .as_bool()
                .unwrap()
        );
        // No event source wired, so the subscription capability is honestly
        // advertised as absent.
        assert!(
            !result["capabilities"]["resources"]["subscribe"]
                .as_bool()
                .unwrap()
        );
        assert!(server.is_initialized());
    }

    #[test]
    fn initialized_notification_returns_none() {
        let mut server = initialized_server(MockProvider::default());
        let req = make_request(protocol::METHOD_INITIALIZED, None);
        let resp = server.handle_request(&req);
        assert!(resp.is_none());
    }

    #[test]
    fn pre_initialization_guard_rejects_tools_list() {
        let mut server = McpServer::new(MockProvider::default());
        let req = make_request(protocol::METHOD_TOOLS_LIST, None);
        let resp = server.handle_request(&req).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, protocol::INVALID_REQUEST);
        assert!(err.message.contains("not initialized"));
    }

    #[test]
    fn pre_initialization_guard_allows_ping() {
        let mut server = McpServer::new(MockProvider::default());
        let req = make_request(METHOD_PING, None);
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_none());
    }

    #[test]
    fn ping_returns_empty_object() {
        let mut server = McpServer::new(MockProvider::default());
        let req = make_request(METHOD_PING, None);
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_none());
        assert!(resp.result.unwrap().is_object());
    }

    #[test]
    fn unknown_method_returns_method_not_found() {
        let mut server = initialized_server(MockProvider::default());
        let req = make_request("unknown/method", None);
        let resp = server.handle_request(&req).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, protocol::METHOD_NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // tools/list tests
    // -----------------------------------------------------------------------

    #[test]
    fn tools_list_returns_builtin_tools_for_all_contexts() {
        let mut server = initialized_server(MockProvider::default());
        let req = make_request(protocol::METHOD_TOOLS_LIST, None);
        let resp = server.handle_request(&req).unwrap();
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();

        // 2 contexts x 3 built-in tools = 6 minimum.
        assert!(
            tools.len() >= 6,
            "expected at least 6 tools, got {}",
            tools.len()
        );

        // Check namespacing.
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"ctx_a/send_message"));
        assert!(names.contains(&"ctx_a/read_messages"));
        assert!(names.contains(&"ctx_a/list_members"));
        assert!(names.contains(&"ctx_b/send_message"));
        assert!(names.contains(&"ctx_b/read_messages"));
        assert!(names.contains(&"ctx_b/list_members"));
    }

    #[test]
    fn tools_list_includes_context_registered_tools() {
        let provider = MockProvider {
            tools: vec![(
                "ctx_a".to_owned(),
                ContextOutletInfo {
                    name: "guide_assistant".to_owned(),
                    description: Some("Guide the assistant".to_owned()),
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: None,
                    admin_only: false,
                    kind: OutletKind::Action,
                },
            )],
            ..MockProvider::default()
        };
        let mut server = initialized_server(provider);
        let req = make_request(protocol::METHOD_TOOLS_LIST, None);
        let resp = server.handle_request(&req).unwrap();
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(
            tools
                .iter()
                .any(|t| t["name"].as_str().unwrap() == "ctx_a/call.guide_assistant")
        );
    }

    #[test]
    fn tools_list_filters_admin_only_tools_for_member_role() {
        let provider = MockProvider {
            tools: vec![
                (
                    "ctx_b".to_owned(),
                    ContextOutletInfo {
                        name: "admin_tool".to_owned(),
                        description: Some("Admin only".to_owned()),
                        input_schema: serde_json::json!({"type": "object"}),
                        output_schema: None,
                        admin_only: true,
                        kind: OutletKind::Action,
                    },
                ),
                (
                    "ctx_b".to_owned(),
                    ContextOutletInfo {
                        name: "member_tool".to_owned(),
                        description: Some("For all".to_owned()),
                        input_schema: serde_json::json!({"type": "object"}),
                        output_schema: None,
                        admin_only: false,
                        kind: OutletKind::Action,
                    },
                ),
            ],
            ..MockProvider::default()
        };
        let mut server = initialized_server(provider);
        let req = make_request(protocol::METHOD_TOOLS_LIST, None);
        let resp = server.handle_request(&req).unwrap();
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();

        // ctx_b has member role -- admin_tool should be filtered out.
        assert!(!names.contains(&"ctx_b/call.admin_tool"));
        assert!(names.contains(&"ctx_b/call.member_tool"));
    }

    #[test]
    fn tools_list_admin_sees_admin_tools() {
        let provider = MockProvider {
            tools: vec![(
                "ctx_a".to_owned(),
                ContextOutletInfo {
                    name: "admin_tool".to_owned(),
                    description: Some("Admin only".to_owned()),
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: None,
                    admin_only: true,
                    kind: OutletKind::Action,
                },
            )],
            ..MockProvider::default()
        };
        let mut server = initialized_server(provider);
        let req = make_request(protocol::METHOD_TOOLS_LIST, None);
        let resp = server.handle_request(&req).unwrap();
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        // ctx_a has admin role -- admin_tool should be visible.
        assert!(
            tools
                .iter()
                .any(|t| t["name"].as_str().unwrap() == "ctx_a/call.admin_tool")
        );
    }

    #[test]
    fn tools_list_filters_by_ucan_capability() {
        let provider = MockProvider {
            denied_capabilities: vec![("ctx_a".to_owned(), "send_message".to_owned())],
            ..MockProvider::default()
        };
        let mut server = initialized_server(provider);
        let req = make_request(protocol::METHOD_TOOLS_LIST, None);
        let resp = server.handle_request(&req).unwrap();
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();

        // send_message denied in ctx_a.
        assert!(!names.contains(&"ctx_a/send_message"));
        // But still available in ctx_b.
        assert!(names.contains(&"ctx_b/send_message"));
    }

    // -----------------------------------------------------------------------
    // tools/call tests
    // -----------------------------------------------------------------------

    #[test]
    fn tools_call_invokes_and_returns_result_with_provenance() {
        let mut server = initialized_server(MockProvider::default());
        let req = make_request(
            protocol::METHOD_TOOLS_CALL,
            Some(serde_json::json!({
                "name": "ctx_a/send_message",
                "arguments": {"content": "hello"}
            })),
        );
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);

        let result = resp.result.unwrap();
        // Check content.
        let content = result["content"].as_array().unwrap();
        assert!(!content.is_empty());

        // Check provenance.
        let provenance = &result["_meta"]["provenance"];
        assert_eq!(provenance["invoked_by"], "did:dht:agent123");
        assert_eq!(provenance["context_id"], "ctx_a");
        assert_eq!(provenance["tool_name"], "send_message");
    }

    #[test]
    fn tools_call_rejects_invalid_namespace() {
        let mut server = initialized_server(MockProvider::default());
        let req = make_request(
            protocol::METHOD_TOOLS_CALL,
            Some(serde_json::json!({
                "name": "no_slash_here",
                "arguments": {}
            })),
        );
        let resp = server.handle_request(&req).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, protocol::INVALID_PARAMS);
    }

    #[test]
    fn tools_call_rejects_denied_capability() {
        let provider = MockProvider {
            denied_capabilities: vec![("ctx_a".to_owned(), "send_message".to_owned())],
            ..MockProvider::default()
        };
        let mut server = initialized_server(provider);
        let req = make_request(
            protocol::METHOD_TOOLS_CALL,
            Some(serde_json::json!({
                "name": "ctx_a/send_message",
                "arguments": {"content": "hello"}
            })),
        );
        let resp = server.handle_request(&req).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, protocol::CAPABILITY_DENIED);
    }

    #[test]
    fn tools_call_validates_input_schema() {
        let mut server = initialized_server(MockProvider::default());
        // send_message requires {"type": "object"} input; send a string.
        let req = make_request(
            protocol::METHOD_TOOLS_CALL,
            Some(serde_json::json!({
                "name": "ctx_a/send_message",
                "arguments": "not an object"
            })),
        );
        let resp = server.handle_request(&req).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, protocol::INVALID_PARAMS);
        assert!(err.message.contains("schema validation failed"));
    }

    #[test]
    fn tools_call_validates_output_schema() {
        let provider = MockProvider {
            tools: vec![(
                "ctx_a".to_owned(),
                ContextOutletInfo {
                    name: "typed_tool".to_owned(),
                    description: None,
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: Some(serde_json::json!({"type": "object"})),
                    admin_only: false,
                    kind: OutletKind::Action,
                },
            )],
            // Return a string instead of an object.
            invoke_result: Ok(serde_json::json!("not an object")),
            ..MockProvider::default()
        };
        let mut server = initialized_server(provider);
        let req = make_request(
            protocol::METHOD_TOOLS_CALL,
            Some(serde_json::json!({
                "name": "ctx_a/typed_tool",
                "arguments": {}
            })),
        );
        let resp = server.handle_request(&req).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, protocol::TOOL_EXECUTION_ERROR);
        assert!(err.message.contains("output schema validation failed"));
    }

    #[test]
    fn tools_call_returns_execution_error() {
        let provider = MockProvider {
            invoke_result: Err("tool crashed".to_owned()),
            ..MockProvider::default()
        };
        let mut server = initialized_server(provider);
        let req = make_request(
            protocol::METHOD_TOOLS_CALL,
            Some(serde_json::json!({
                "name": "ctx_a/send_message",
                "arguments": {"content": "hello"}
            })),
        );
        let resp = server.handle_request(&req).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, protocol::TOOL_EXECUTION_ERROR);
        assert!(err.message.contains("tool crashed"));
    }

    #[test]
    fn tools_call_rejects_non_member_context() {
        // Agent only belongs to ctx_a and ctx_b, not ctx_x.
        let mut server = initialized_server(MockProvider::default());
        let req = make_request(
            protocol::METHOD_TOOLS_CALL,
            Some(serde_json::json!({
                "name": "ctx_x/send_message",
                "arguments": {"content": "hello"}
            })),
        );
        let resp = server.handle_request(&req).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, protocol::INTERNAL_ERROR);
        assert!(err.message.contains("membership check failed"));
        assert!(err.message.contains("ctx_x"));
    }

    #[test]
    fn tools_call_result_is_not_error_flag() {
        let mut server = initialized_server(MockProvider::default());
        let req = make_request(
            protocol::METHOD_TOOLS_CALL,
            Some(serde_json::json!({
                "name": "ctx_a/send_message",
                "arguments": {"content": "hello"}
            })),
        );
        let resp = server.handle_request(&req).unwrap();
        let result = resp.result.unwrap();
        assert!(!result["isError"].as_bool().unwrap_or(true));
    }

    // -----------------------------------------------------------------------
    // resources/list tests
    // -----------------------------------------------------------------------

    #[test]
    fn resources_list_returns_three_resources_per_context() {
        let mut server = initialized_server(MockProvider::default());
        let req = make_request(protocol::METHOD_RESOURCES_LIST, None);
        let resp = server.handle_request(&req).unwrap();
        let result = resp.result.unwrap();
        let resources = result["resources"].as_array().unwrap();

        // 2 contexts x 3 resources = 6.
        assert_eq!(resources.len(), 6);

        let uris: Vec<&str> = resources
            .iter()
            .map(|r| r["uri"].as_str().unwrap())
            .collect();
        assert!(uris.contains(&"scp://ctx_a/events"));
        assert!(uris.contains(&"scp://ctx_a/members"));
        assert!(uris.contains(&"scp://ctx_a/tools"));
        assert!(uris.contains(&"scp://ctx_b/events"));
        assert!(uris.contains(&"scp://ctx_b/members"));
        assert!(uris.contains(&"scp://ctx_b/tools"));
    }

    #[test]
    fn resources_list_includes_mime_type() {
        let mut server = initialized_server(MockProvider::default());
        let req = make_request(protocol::METHOD_RESOURCES_LIST, None);
        let resp = server.handle_request(&req).unwrap();
        let result = resp.result.unwrap();
        let resources = result["resources"].as_array().unwrap();

        for resource in resources {
            assert_eq!(resource["mimeType"], "application/json");
        }
    }

    // -----------------------------------------------------------------------
    // resources/read tests
    // -----------------------------------------------------------------------

    #[test]
    fn resources_read_returns_members() {
        let mut server = initialized_server(MockProvider::default());
        let req = make_request(
            protocol::METHOD_RESOURCES_READ,
            Some(serde_json::json!({"uri": "scp://ctx_a/members"})),
        );
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let contents = result["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["uri"], "scp://ctx_a/members");

        let text = contents[0]["text"].as_str().unwrap();
        let members: Vec<MemberInfo> = serde_json::from_str(text).unwrap();
        assert_eq!(members.len(), 2);
    }

    #[test]
    fn resources_read_returns_events() {
        let provider = MockProvider {
            events: serde_json::json!([{"type": "message", "content": "hi"}]),
            ..MockProvider::default()
        };
        let mut server = initialized_server(provider);
        let req = make_request(
            protocol::METHOD_RESOURCES_READ,
            Some(serde_json::json!({"uri": "scp://ctx_a/events"})),
        );
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let text = result["contents"][0]["text"].as_str().unwrap();
        let events: Value = serde_json::from_str(text).unwrap();
        assert!(events.is_array());
        assert_eq!(events.as_array().unwrap().len(), 1);
    }

    #[test]
    fn resources_read_returns_tools() {
        let provider = MockProvider {
            tools: vec![(
                "ctx_a".to_owned(),
                ContextOutletInfo {
                    name: "my_tool".to_owned(),
                    description: None,
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: None,
                    admin_only: false,
                    kind: OutletKind::Action,
                },
            )],
            ..MockProvider::default()
        };
        let mut server = initialized_server(provider);
        let req = make_request(
            protocol::METHOD_RESOURCES_READ,
            Some(serde_json::json!({"uri": "scp://ctx_a/tools"})),
        );
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let text = result["contents"][0]["text"].as_str().unwrap();
        let tools: Vec<String> = serde_json::from_str(text).unwrap();
        // The resource carries the same names `tools/list` publishes — the
        // namespaced, kind-projected MCP tool names a client can actually call
        // — so the two surfaces cannot disagree about what exists.
        assert!(
            tools.contains(&"ctx_a/call.my_tool".to_owned()),
            "tools resource must carry callable MCP names, got: {tools:?}"
        );
    }

    #[test]
    fn resources_read_rejects_invalid_uri() {
        let mut server = initialized_server(MockProvider::default());
        let req = make_request(
            protocol::METHOD_RESOURCES_READ,
            Some(serde_json::json!({"uri": "http://invalid/events"})),
        );
        let resp = server.handle_request(&req).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, protocol::RESOURCE_NOT_FOUND);
    }

    #[test]
    fn resources_read_rejects_unknown_context() {
        let mut server = initialized_server(MockProvider::default());
        let req = make_request(
            protocol::METHOD_RESOURCES_READ,
            Some(serde_json::json!({"uri": "scp://unknown_ctx/events"})),
        );
        let resp = server.handle_request(&req).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, protocol::RESOURCE_NOT_FOUND);
        assert!(err.message.contains("not a participant in context"));
        // The MCP spec's -32002 example carries the offending URI in `data`.
        assert_eq!(
            err.data.as_ref().unwrap()["uri"],
            "scp://unknown_ctx/events"
        );
    }

    #[test]
    fn resources_read_rejects_unknown_resource_type() {
        let mut server = initialized_server(MockProvider::default());
        let req = make_request(
            protocol::METHOD_RESOURCES_READ,
            Some(serde_json::json!({"uri": "scp://ctx_a/unknown"})),
        );
        let resp = server.handle_request(&req).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, protocol::RESOURCE_NOT_FOUND);
    }

    #[test]
    fn resources_read_rejects_denied_resource_access() {
        let provider = MockProvider {
            denied_resources: vec![("ctx_a".to_owned(), ResourceKind::Members)],
            ..MockProvider::default()
        };
        let mut server = initialized_server(provider);
        let req = make_request(
            protocol::METHOD_RESOURCES_READ,
            Some(serde_json::json!({"uri": "scp://ctx_a/members"})),
        );
        let resp = server.handle_request(&req).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, protocol::CAPABILITY_DENIED);
    }

    #[test]
    fn resources_read_succeeds_with_valid_ucan_and_membership() {
        // Default provider has ctx_a as active and no denied capabilities.
        let mut server = initialized_server(MockProvider::default());
        let req = make_request(
            protocol::METHOD_RESOURCES_READ,
            Some(serde_json::json!({"uri": "scp://ctx_a/members"})),
        );
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let result = resp.result.unwrap();
        let contents = result["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["uri"], "scp://ctx_a/members");
    }

    // -----------------------------------------------------------------------
    // resources/subscribe tests
    // -----------------------------------------------------------------------

    /// Subscribes `server` to `uri`, asserting the request succeeded.
    fn subscribe(server: &mut McpServer<MockProvider>, uri: &str) {
        let req = make_request(
            protocol::METHOD_RESOURCES_SUBSCRIBE,
            Some(serde_json::json!({ "uri": uri })),
        );
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_none(), "subscribe to {uri} failed: {resp:?}");
    }

    fn member_joined() -> ContextEvent {
        ContextEvent::MemberJoined {
            member_did: scp_did::DID("did:dht:z6MkNewMember".to_owned()),
            role_name: "member".to_owned(),
        }
    }

    fn message_sent() -> ContextEvent {
        ContextEvent::MessageSent {
            sender_did: scp_did::DID("did:dht:z6MkSender".to_owned()),
            sequence_number: 1,
            payload: vec![],
        }
    }

    // -----------------------------------------------------------------------
    // Resource authorization: subscribe and read share one predicate
    // -----------------------------------------------------------------------

    /// The `resources/subscribe` gate must be exactly the `resources/read`
    /// gate. Before this fix, subscribe checked only URI shape, resource type
    /// and participation, so a client denied `resources/read` on a resource
    /// could still hold a live subscription to it and learn — from the timing
    /// of every `notifications/resources/updated` — that the denied state was
    /// changing.
    #[test]
    fn capability_denied_client_cannot_subscribe() {
        let provider = MockProvider {
            denied_resources: vec![("ctx_a".to_owned(), ResourceKind::Members)],
            ..MockProvider::default()
        };
        let mut server = subscribing_server(provider);

        // Baseline: `resources/read` denies this resource.
        let read = make_request(
            protocol::METHOD_RESOURCES_READ,
            Some(serde_json::json!({"uri": "scp://ctx_a/members"})),
        );
        assert_eq!(
            server.handle_request(&read).unwrap().error.unwrap().code,
            protocol::CAPABILITY_DENIED
        );

        // `resources/subscribe` must deny it identically.
        let sub = make_request(
            protocol::METHOD_RESOURCES_SUBSCRIBE,
            Some(serde_json::json!({"uri": "scp://ctx_a/members"})),
        );
        let err = server
            .handle_request(&sub)
            .unwrap()
            .error
            .expect("subscribe must not succeed for a resource read denies");
        assert_eq!(err.code, protocol::CAPABILITY_DENIED);
        assert_eq!(err.data.as_ref().unwrap()["uri"], "scp://ctx_a/members");
        assert!(
            !server.is_subscribed("scp://ctx_a/members"),
            "a denied subscribe must not register a subscription"
        );

        // A resource the same client IS allowed to read still works, so the
        // gate is per-resource rather than a blanket denial.
        subscribe(&mut server, "scp://ctx_a/events");
    }

    /// Capabilities are revocable mid-session. A subscription registered while
    /// authorized must stop delivering the moment authorization is withdrawn,
    /// otherwise it outlives the grant and becomes the same activity oracle.
    #[test]
    fn revoked_resource_access_stops_notification_delivery() {
        let mut server = subscribing_server(MockProvider::default());
        subscribe(&mut server, "scp://ctx_a/members");
        assert!(
            server
                .notifications_for_event("ctx_a", &member_joined())
                .iter()
                .any(|n| n.method == protocol::METHOD_RESOURCES_UPDATED),
            "precondition: an authorized subscription delivers"
        );

        // Revoke access, as `CapabilitiesSuspended` / `ReadAccessRevoked`
        // would at the provider.
        let mut revoked = MockProvider::default();
        revoked
            .denied_resources
            .push(("ctx_a".to_owned(), ResourceKind::Members));
        let mut server = subscribing_server(revoked);
        server
            .subscriptions
            .insert("scp://ctx_a/members".to_owned());

        assert!(
            server
                .notifications_for_event("ctx_a", &member_joined())
                .iter()
                .all(|n| n.method != protocol::METHOD_RESOURCES_UPDATED),
            "a revoked subscription must stop delivering"
        );
        assert!(
            server.is_subscribed("scp://ctx_a/members"),
            "the registration is filtered, not forgotten — suspension is \
             reversible and MCP has no server-initiated unsubscribe"
        );
    }

    /// `resources/list` must not advertise a URI that `resources/read` denies.
    #[test]
    fn resources_list_omits_unauthorized_resources() {
        let provider = MockProvider {
            denied_resources: vec![("ctx_a".to_owned(), ResourceKind::Members)],
            ..MockProvider::default()
        };
        let mut server = initialized_server(provider);
        let req = make_request(protocol::METHOD_RESOURCES_LIST, None);
        let resp = server.handle_request(&req).unwrap();
        let uris: Vec<String> = resp.result.unwrap()["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["uri"].as_str().unwrap().to_owned())
            .collect();

        assert!(!uris.contains(&"scp://ctx_a/members".to_owned()));
        assert!(uris.contains(&"scp://ctx_a/events".to_owned()));
        assert!(uris.contains(&"scp://ctx_b/members".to_owned()));
    }

    // -----------------------------------------------------------------------
    // Fail-closed: no event source wired
    // -----------------------------------------------------------------------

    /// `tools.listChanged` was the sibling field of the same struct literal as
    /// `resources.subscribe` and stayed hard-coded `true` — the identical false
    /// guarantee, since the only production emitter of
    /// `notifications/tools/list_changed` is the event pump.
    #[test]
    fn unwired_server_advertises_list_changed_false() {
        let mut server = McpServer::new(MockProvider::default());
        let resp = server
            .handle_request(&make_request(METHOD_INITIALIZE, Some(init_params())))
            .unwrap();
        let caps = resp.result.unwrap();

        assert!(
            !caps["capabilities"]["tools"]["listChanged"]
                .as_bool()
                .unwrap(),
            "no event source means no tools/list_changed can ever be sent"
        );
        assert!(
            !caps["capabilities"]["resources"]["listChanged"]
                .as_bool()
                .unwrap()
        );
        assert!(
            !caps["capabilities"]["resources"]["subscribe"]
                .as_bool()
                .unwrap()
        );

        // And an unwired server can indeed never emit one, whoever calls.
        assert!(
            server
                .notifications_for_event("ctx_a", &member_joined())
                .is_empty(),
            "an unwired server must emit no pump-backed notification at all"
        );
    }

    /// A wired server advertises all three, because the pump exists to keep
    /// every one of them.
    #[test]
    fn wired_server_advertises_all_pump_backed_capabilities() {
        let (mut server, pump) =
            McpServer::with_event_source(MockProvider::default(), test_event_source());
        std::mem::forget(pump);
        let resp = server
            .handle_request(&make_request(METHOD_INITIALIZE, Some(init_params())))
            .unwrap();
        let caps = resp.result.unwrap();

        for path in ["subscribe", "listChanged"] {
            assert!(
                caps["capabilities"]["resources"][path].as_bool().unwrap(),
                "resources.{path} must be advertised on a wired server"
            );
        }
        assert!(
            caps["capabilities"]["tools"]["listChanged"]
                .as_bool()
                .unwrap()
        );
    }

    #[test]
    fn unwired_server_advertises_subscribe_false() {
        let server = initialized_server(MockProvider::default());
        assert!(!server.event_source_wired());
    }

    #[test]
    fn unwired_server_rejects_subscribe_instead_of_silently_accepting() {
        let mut server = initialized_server(MockProvider::default());
        let req = make_request(
            protocol::METHOD_RESOURCES_SUBSCRIBE,
            Some(serde_json::json!({"uri": "scp://ctx_a/events"})),
        );
        let resp = server.handle_request(&req).unwrap();

        let err = resp
            .error
            .expect("an unwired server must not report success for subscribe");
        assert_eq!(err.code, protocol::METHOD_NOT_FOUND);
        assert_eq!(server.subscription_count(), 0);
    }

    #[test]
    fn unwired_server_rejects_unsubscribe() {
        let mut server = initialized_server(MockProvider::default());
        let req = make_request(
            protocol::METHOD_RESOURCES_UNSUBSCRIBE,
            Some(serde_json::json!({"uri": "scp://ctx_a/events"})),
        );
        let resp = server.handle_request(&req).unwrap();
        assert_eq!(resp.error.unwrap().code, protocol::METHOD_NOT_FOUND);
    }

    #[test]
    fn wired_server_advertises_subscribe_true() {
        let (mut server, pump) =
            McpServer::with_event_source(MockProvider::default(), test_event_source());
        std::mem::forget(pump);
        let req = make_request(METHOD_INITIALIZE, Some(init_params()));
        let resp = server.handle_request(&req).unwrap();

        assert!(
            resp.result.unwrap()["capabilities"]["resources"]["subscribe"]
                .as_bool()
                .unwrap(),
            "a server with a wired event source must advertise the capability"
        );
    }

    // -----------------------------------------------------------------------
    // resources/subscribe behaviour (event source wired)
    // -----------------------------------------------------------------------

    #[test]
    fn resources_subscribe_succeeds() {
        let mut server = subscribing_server(MockProvider::default());
        subscribe(&mut server, "scp://ctx_a/events");
        assert!(server.is_subscribed("scp://ctx_a/events"));
        assert_eq!(server.subscription_count(), 1);
    }

    #[test]
    fn resources_subscribe_rejects_invalid_uri() {
        let mut server = subscribing_server(MockProvider::default());
        let req = make_request(
            protocol::METHOD_RESOURCES_SUBSCRIBE,
            Some(serde_json::json!({"uri": "invalid"})),
        );
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_some());
        assert_eq!(server.subscription_count(), 0);
    }

    #[test]
    fn resources_subscribe_rejects_context_the_agent_is_not_in() {
        let mut server = subscribing_server(MockProvider::default());
        let req = make_request(
            protocol::METHOD_RESOURCES_SUBSCRIBE,
            Some(serde_json::json!({"uri": "scp://ctx_stranger/events"})),
        );
        let resp = server.handle_request(&req).unwrap();
        let err = resp.error.expect("must reject a non-participant context");
        assert_eq!(err.code, protocol::RESOURCE_NOT_FOUND);
        assert!(err.message.contains("not a participant"), "{}", err.message);
        assert_eq!(server.subscription_count(), 0);
    }

    #[test]
    fn resources_subscribe_rejects_unknown_resource_type() {
        let mut server = subscribing_server(MockProvider::default());
        let req = make_request(
            protocol::METHOD_RESOURCES_SUBSCRIBE,
            Some(serde_json::json!({"uri": "scp://ctx_a/secrets"})),
        );
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_some());
        assert_eq!(server.subscription_count(), 0);
    }

    #[test]
    fn resources_unsubscribe_removes_the_subscription() {
        let mut server = subscribing_server(MockProvider::default());
        subscribe(&mut server, "scp://ctx_a/events");

        let req = make_request(
            protocol::METHOD_RESOURCES_UNSUBSCRIBE,
            Some(serde_json::json!({"uri": "scp://ctx_a/events"})),
        );
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_none());
        assert!(!server.is_subscribed("scp://ctx_a/events"));

        // And no notification is produced for it any more.
        assert!(
            server
                .notifications_for_event("ctx_a", &message_sent())
                .is_empty()
        );
    }

    #[test]
    fn resources_unsubscribe_is_idempotent() {
        let mut server = subscribing_server(MockProvider::default());
        let req = make_request(
            protocol::METHOD_RESOURCES_UNSUBSCRIBE,
            Some(serde_json::json!({"uri": "scp://ctx_a/events"})),
        );
        let resp = server.handle_request(&req).unwrap();
        assert!(
            resp.error.is_none(),
            "unsubscribing an unsubscribed URI must succeed"
        );
    }

    #[test]
    fn resources_unsubscribe_rejects_invalid_uri() {
        let mut server = subscribing_server(MockProvider::default());
        let req = make_request(
            protocol::METHOD_RESOURCES_UNSUBSCRIBE,
            Some(serde_json::json!({"uri": "nonsense"})),
        );
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_some());
    }

    #[test]
    fn reset_session_drops_everything() {
        let mut server = subscribing_server(MockProvider::default());
        subscribe(&mut server, "scp://ctx_a/events");
        subscribe(&mut server, "scp://ctx_b/members");
        assert_eq!(server.subscription_count(), 2);

        server.reset_session();

        assert_eq!(server.subscription_count(), 0);
        assert!(
            !server.is_initialized(),
            "the next client must complete its own handshake"
        );
        assert!(
            server
                .notifications_for_event("ctx_a", &message_sent())
                .is_empty()
        );
    }

    // -----------------------------------------------------------------------
    // Event -> notification mapping
    // -----------------------------------------------------------------------

    #[test]
    fn subscribed_event_stream_receives_resources_updated() {
        let mut server = subscribing_server(MockProvider::default());
        subscribe(&mut server, "scp://ctx_a/events");

        let notifs = server.notifications_for_event("ctx_a", &message_sent());

        assert_eq!(notifs.len(), 1);
        assert_eq!(notifs[0].method, protocol::METHOD_RESOURCES_UPDATED);
        assert_eq!(
            notifs[0].params.as_ref().unwrap()["uri"],
            "scp://ctx_a/events"
        );
    }

    #[test]
    fn unsubscribed_resource_produces_no_resources_updated() {
        let server = subscribing_server(MockProvider::default());

        // With nothing subscribed, an events-only change is entirely silent.
        assert!(
            server
                .notifications_for_event("ctx_a", &message_sent())
                .is_empty()
        );

        // A membership change still emits the list-changed notifications
        // (capability-gated, not subscription-gated) but no
        // `resources/updated`, because no resource is subscribed.
        let notifs = server.notifications_for_event("ctx_a", &member_joined());
        assert!(
            notifs
                .iter()
                .all(|n| n.method != protocol::METHOD_RESOURCES_UPDATED),
            "no resources/updated may be emitted without a subscription: {notifs:?}"
        );
    }

    #[test]
    fn event_for_another_context_does_not_notify() {
        let mut server = subscribing_server(MockProvider::default());
        subscribe(&mut server, "scp://ctx_a/events");

        // Same event, different context — the URI does not match.
        assert!(
            server
                .notifications_for_event("ctx_b", &message_sent())
                .is_empty()
        );
    }

    #[test]
    fn membership_event_updates_events_and_members_but_not_a_message() {
        let mut server = subscribing_server(MockProvider::default());
        subscribe(&mut server, "scp://ctx_a/events");
        subscribe(&mut server, "scp://ctx_a/members");

        let uris = |notifs: &[JsonRpcNotification]| -> Vec<String> {
            notifs
                .iter()
                .filter(|n| n.method == protocol::METHOD_RESOURCES_UPDATED)
                .map(|n| {
                    n.params.as_ref().unwrap()["uri"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                })
                .collect()
        };

        // MemberJoined invalidates both the event stream and the member list.
        let joined = server.notifications_for_event("ctx_a", &member_joined());
        assert_eq!(
            uris(&joined),
            vec!["scp://ctx_a/events", "scp://ctx_a/members"]
        );

        // A message only invalidates the event stream.
        let sent = server.notifications_for_event("ctx_a", &message_sent());
        assert_eq!(uris(&sent), vec!["scp://ctx_a/events"]);
    }

    #[test]
    fn capability_changing_event_emits_tools_list_changed() {
        let server = subscribing_server(MockProvider::default());
        // No resource subscription needed: tools/list_changed is gated on the
        // advertised capability, not on a subscription.
        let notifs = server.notifications_for_event("ctx_a", &member_joined());
        assert!(
            notifs
                .iter()
                .any(|n| n.method == protocol::METHOD_TOOLS_LIST_CHANGED),
            "membership change must invalidate the capability-filtered tool list"
        );

        // A plain message does not change the tool set.
        let sent = server.notifications_for_event("ctx_a", &message_sent());
        assert!(
            !sent
                .iter()
                .any(|n| n.method == protocol::METHOD_TOOLS_LIST_CHANGED)
        );
    }

    #[test]
    fn tools_list_changed_not_emitted_for_unserved_context() {
        let server = subscribing_server(MockProvider::default());
        let notifs = server.notifications_for_event("ctx_not_served", &member_joined());
        assert!(
            notifs.is_empty(),
            "an event for a context this server does not serve must be silent"
        );
    }

    #[test]
    fn affected_resources_classification() {
        // Every event is part of the event stream.
        assert!(affected_resources(&message_sent()).events);
        assert!(affected_resources(&member_joined()).events);

        // Membership changes hit members and the capability-filtered tools.
        let joined = affected_resources(&member_joined());
        assert!(joined.members && joined.tools);

        // A message changes neither the member list nor the tool list.
        let sent = affected_resources(&message_sent());
        assert!(!sent.members && !sent.tools);
    }

    // -----------------------------------------------------------------------
    // Notifications
    // -----------------------------------------------------------------------

    #[test]
    fn tools_list_changed_notification_has_correct_method() {
        let notif = McpServer::<MockProvider>::tools_list_changed_notification();
        assert_eq!(notif.method, protocol::METHOD_TOOLS_LIST_CHANGED);
        assert_eq!(notif.jsonrpc, JSONRPC_VERSION);
    }

    // -----------------------------------------------------------------------
    // Resource URI parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_resource_uri_valid() {
        let (ctx, rtype) = parse_resource_uri("scp://context_a/events").unwrap();
        assert_eq!(ctx, "context_a");
        assert_eq!(rtype, ResourceKind::Events);
    }

    #[test]
    fn parse_resource_uri_rejects_bad_scheme() {
        let err = parse_resource_uri("http://ctx/events").unwrap_err();
        assert!(err.contains("expected scp://"));
    }

    #[test]
    fn parse_resource_uri_rejects_missing_resource_type() {
        let err = parse_resource_uri("scp://ctx_only").unwrap_err();
        assert!(err.contains("missing resource type"));
    }

    #[test]
    fn parse_resource_uri_rejects_empty_context() {
        let err = parse_resource_uri("scp:///events").unwrap_err();
        assert!(err.contains("empty context ID"));
    }

    #[test]
    fn parse_resource_uri_rejects_empty_resource_type() {
        let err = parse_resource_uri("scp://ctx/").unwrap_err();
        assert!(err.contains("empty resource type"));
    }

    // -----------------------------------------------------------------------
    // Input/output validation (delegates to scp_core shared validation)
    // -----------------------------------------------------------------------

    #[test]
    fn shared_validation_accepts_matching_type() {
        let schema = serde_json::json!({"type": "object"});
        let input = serde_json::json!({"key": "value"});
        assert!(validate_value_against_schema(&input, &schema).is_ok());
    }

    #[test]
    fn shared_validation_rejects_type_mismatch() {
        let schema = serde_json::json!({"type": "object"});
        let input = serde_json::json!("string value");
        assert!(validate_value_against_schema(&input, &schema).is_err());
    }

    #[test]
    fn shared_validation_passes_when_no_type_constraint() {
        let schema = serde_json::json!({});
        let input = serde_json::json!(42);
        assert!(validate_value_against_schema(&input, &schema).is_ok());
    }

    #[test]
    fn shared_validation_rejects_non_object_schema() {
        let schema = serde_json::json!("not an object");
        let input = serde_json::json!(42);
        assert!(validate_value_against_schema(&input, &schema).is_err());
    }

    // -----------------------------------------------------------------------
    // ToolProvenance serialization
    // -----------------------------------------------------------------------

    #[test]
    fn tool_provenance_serialization_roundtrip() {
        let prov = ToolProvenance {
            invoked_by: "did:dht:alice".to_owned(),
            context_id: "ctx_a".to_owned(),
            tool_name: "send_message".to_owned(),
        };
        let json = serde_json::to_string(&prov).unwrap();
        let parsed: ToolProvenance = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.invoked_by, "did:dht:alice");
        assert_eq!(parsed.context_id, "ctx_a");
        assert_eq!(parsed.tool_name, "send_message");
    }

    // -----------------------------------------------------------------------
    // End-to-end: full lifecycle
    // -----------------------------------------------------------------------

    #[test]
    fn full_lifecycle_initialize_list_call() {
        let mut server = McpServer::new(MockProvider::default());

        // 1. Initialize.
        let init_req = make_request(METHOD_INITIALIZE, Some(init_params()));
        let init_resp = server.handle_request(&init_req).unwrap();
        assert!(init_resp.error.is_none());

        // 2. Initialized notification.
        let notif_req = make_request(protocol::METHOD_INITIALIZED, None);
        assert!(server.handle_request(&notif_req).is_none());

        // 3. List tools.
        let list_req = make_request(protocol::METHOD_TOOLS_LIST, None);
        let list_resp = server.handle_request(&list_req).unwrap();
        assert!(list_resp.error.is_none());
        let tools = list_resp.result.unwrap()["tools"].as_array().unwrap().len();
        assert!(tools >= 6);

        // 4. Call a tool.
        let call_req = make_request(
            protocol::METHOD_TOOLS_CALL,
            Some(serde_json::json!({
                "name": "ctx_a/send_message",
                "arguments": {"content": "hello world"}
            })),
        );
        let call_resp = server.handle_request(&call_req).unwrap();
        assert!(call_resp.error.is_none());

        // 5. List resources.
        let res_req = make_request(protocol::METHOD_RESOURCES_LIST, None);
        let res_resp = server.handle_request(&res_req).unwrap();
        assert!(res_resp.error.is_none());

        // 6. Read a resource.
        let read_req = make_request(
            protocol::METHOD_RESOURCES_READ,
            Some(serde_json::json!({"uri": "scp://ctx_a/members"})),
        );
        let read_resp = server.handle_request(&read_req).unwrap();
        assert!(read_resp.error.is_none());

        // 7. Ping.
        let ping_req = make_request(METHOD_PING, None);
        let ping_resp = server.handle_request(&ping_req).unwrap();
        assert!(ping_resp.error.is_none());
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn tools_list_with_no_contexts_returns_empty() {
        let provider = MockProvider {
            contexts: Vec::new(),
            ..MockProvider::default()
        };
        let mut server = initialized_server(provider);
        let req = make_request(protocol::METHOD_TOOLS_LIST, None);
        let resp = server.handle_request(&req).unwrap();
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(tools.is_empty());
    }

    #[test]
    fn resources_list_with_no_contexts_returns_empty() {
        let provider = MockProvider {
            contexts: Vec::new(),
            ..MockProvider::default()
        };
        let mut server = initialized_server(provider);
        let req = make_request(protocol::METHOD_RESOURCES_LIST, None);
        let resp = server.handle_request(&req).unwrap();
        let result = resp.result.unwrap();
        let resources = result["resources"].as_array().unwrap();
        assert!(resources.is_empty());
    }

    #[test]
    fn tools_call_with_missing_params_returns_error() {
        let mut server = initialized_server(MockProvider::default());
        // tools/call with no params -- missing "name" field.
        let req = make_request(protocol::METHOD_TOOLS_CALL, None);
        let resp = server.handle_request(&req).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, protocol::INVALID_PARAMS);
    }

    #[test]
    fn response_ids_match_request_ids() {
        let mut server = initialized_server(MockProvider::default());
        let mut req = make_request(METHOD_PING, None);
        req.id = RequestId::String("my-unique-id".to_owned());
        let resp = server.handle_request(&req).unwrap();
        assert_eq!(resp.id, RequestId::String("my-unique-id".to_owned()));
    }
}
