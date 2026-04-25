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
//! - **Resource subscriptions** (`resources/subscribe`) -- maps to SCP context
//!   event streams.
//! - **MCP lifecycle** (`initialize`, `notifications/initialized`, `ping`).
//! - **Dynamic updates** -- emits `notifications/tools/list_changed` on
//!   context join/leave/tool changes.
//!
//! The server uses trait-based abstractions ([`ContextProvider`]) so it can
//! be tested independently of the full SCP stack.
//!
//! See ADR-015 in `.docs/adrs/phase-3.md` for the full design.

use std::collections::HashSet;

use scp_core::context::tools::validate_value_against_schema;
use serde_json::Value;

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

/// Resource suffix for event streams.
const RESOURCE_EVENTS: &str = "events";

/// Resource suffix for member lists.
const RESOURCE_MEMBERS: &str = "members";

/// Resource suffix for tool lists.
const RESOURCE_TOOLS: &str = "tools";

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
    /// `query.{outlet_id}`; `Action` surfaces as `call.{outlet_id}`. Until
    /// SCP-OUT-017 provides the canonical enum, bridges that cannot yet
    /// distinguish Query from Action default to `Action`.
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
    /// Returns `Ok(())` if permitted, or an error message if denied.
    ///
    /// # Errors
    ///
    /// Returns an error message if the agent lacks the required capability.
    fn validate_capability(&self, context_id: &str, tool_name: &str) -> Result<(), String>;

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

    /// Subscribes to resource updates for a context resource.
    ///
    /// # Errors
    ///
    /// Returns an error message if the resource URI is invalid or the context
    /// does not exist.
    fn subscribe_resource(&self, uri: &str) -> Result<(), String>;
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
}

impl<P: ContextProvider> McpServer<P> {
    /// Creates a new MCP server backed by the given context provider.
    #[must_use]
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            initialized: false,
            client_capabilities: None,
            subscriptions: HashSet::new(),
        }
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

        let result = InitializeResult {
            protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
            capabilities: ServerCapabilities {
                tools: Some(ToolServerCapability { list_changed: true }),
                resources: Some(ResourceServerCapability { subscribe: true }),
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

    /// Handles `tools/list` -- returns all tools the agent can access across
    /// all active contexts, filtered by capability.
    fn handle_tools_list(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let mut tools: Vec<ToolDefinition> = Vec::new();
        let agent_role_is_admin = |ctx: &str| -> bool {
            self.provider
                .agent_role(ctx)
                .as_deref()
                .is_some_and(|r| r == "admin")
        };

        for context_id in self.provider.active_context_ids() {
            // Built-in tools -- always available to all participants.
            for builtin in BUILTIN_TOOLS {
                // Validate capability for each built-in tool.
                if self
                    .provider
                    .validate_capability(&context_id, builtin.tool_name())
                    .is_ok()
                {
                    tools.push(builtin.to_tool_definition(&context_id));
                }
            }

            // Context-registered outlets -- filtered by capability. Names are
            // kind-projected per §8.5.1 (Query → `query.{id}`, Action →
            // `call.{id}`) so MCP-consuming models can distinguish them
            // lexically.
            for outlet_info in self.provider.context_tools(&context_id) {
                // Skip admin-only outlets for non-admin agents.
                if outlet_info.admin_only && !agent_role_is_admin(&context_id) {
                    continue;
                }

                // Validate capability against the outlet_id (SCP-internal
                // name). The kind prefix is an MCP-facing display concern,
                // not part of the authorization check.
                if self
                    .provider
                    .validate_capability(&context_id, &outlet_info.name)
                    .is_ok()
                {
                    let mcp_name = format_mcp_tool_name(outlet_info.kind, &outlet_info.name);
                    tools.push(context_tool_definition(
                        &context_id,
                        &mcp_name,
                        outlet_info.description.as_deref(),
                        outlet_info.input_schema.clone(),
                    ));
                }
            }
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

        // Kind-prefix stripping per §8.5.1: MCP tool.name may carry a
        // `query.` / `call.` prefix projected from the outlet kind. The
        // authorization layer works with the SCP outlet_id, so strip the
        // prefix before validation and invocation. An unrecognized prefix
        // falls back to using the full name as the outlet_id with kind =
        // Action (fail-safe default per AC14).
        let (outlet_kind, owned_outlet_id) = parse_mcp_tool_name(mcp_tool_name);
        let _ = outlet_kind; // Kind is recorded in the provenance path; the
        // invocation handler itself is kind-agnostic until SCP-OUT-017 wires
        // the Query / Action dispatch difference.
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
    fn handle_resources_list(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let mut resources: Vec<ResourceDefinition> = Vec::new();

        for context_id in self.provider.active_context_ids() {
            resources.push(ResourceDefinition {
                uri: format!("{RESOURCE_SCHEME}{context_id}/{RESOURCE_EVENTS}"),
                name: format!("{context_id} Events"),
                description: Some(format!("Event stream for context {context_id}")),
                mime_type: Some("application/json".to_owned()),
            });

            resources.push(ResourceDefinition {
                uri: format!("{RESOURCE_SCHEME}{context_id}/{RESOURCE_MEMBERS}"),
                name: format!("{context_id} Members"),
                description: Some(format!("Member list for context {context_id}")),
                mime_type: Some("application/json".to_owned()),
            });

            resources.push(ResourceDefinition {
                uri: format!("{RESOURCE_SCHEME}{context_id}/{RESOURCE_TOOLS}"),
                name: format!("{context_id} Tools"),
                description: Some(format!("Tool list for context {context_id}")),
                mime_type: Some("application/json".to_owned()),
            });
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

    /// Handles `resources/read` -- returns the current state of a resource.
    fn handle_resources_read(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let params: protocol::ResourcesReadParams = match parse_params(request.params.as_ref()) {
            Ok(p) => p,
            Err(resp) => return with_id(resp, request.id.clone()),
        };

        let (context_id, resource_type) = match parse_resource_uri(&params.uri) {
            Ok(parsed) => parsed,
            Err(msg) => {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    JsonRpcError {
                        code: protocol::RESOURCE_NOT_FOUND,
                        message: msg,
                        data: None,
                    },
                );
            }
        };

        // Verify the context exists.
        if !self
            .provider
            .active_context_ids()
            .iter()
            .any(|id| id == &context_id)
        {
            return JsonRpcResponse::error(
                request.id.clone(),
                JsonRpcError {
                    code: protocol::RESOURCE_NOT_FOUND,
                    message: format!("context not found: {context_id}"),
                    data: None,
                },
            );
        }

        // Validate UCAN capability for the requested resource type.
        let capability_name = format!("resource:{resource_type}");
        if let Err(msg) = self
            .provider
            .validate_capability(&context_id, &capability_name)
        {
            return JsonRpcResponse::error(
                request.id.clone(),
                JsonRpcError {
                    code: protocol::CAPABILITY_DENIED,
                    message: msg,
                    data: None,
                },
            );
        }

        let content_text = match resource_type {
            RESOURCE_EVENTS => {
                let events = self.provider.context_events(&context_id);
                serde_json::to_string(&events)
            }
            RESOURCE_MEMBERS => {
                let members = self.provider.context_members(&context_id);
                serde_json::to_string(&members)
            }
            RESOURCE_TOOLS => {
                let tools = self.provider.context_tools(&context_id);
                let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
                serde_json::to_string(&names)
            }
            _ => {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    JsonRpcError {
                        code: protocol::RESOURCE_NOT_FOUND,
                        message: format!("unknown resource type: {resource_type}"),
                        data: None,
                    },
                );
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
    fn handle_resources_subscribe(&mut self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let params: ResourcesSubscribeParams = match parse_params(request.params.as_ref()) {
            Ok(p) => p,
            Err(resp) => return with_id(resp, request.id.clone()),
        };

        // Validate the URI format.
        if let Err(msg) = parse_resource_uri(&params.uri) {
            return JsonRpcResponse::error(
                request.id.clone(),
                JsonRpcError {
                    code: protocol::RESOURCE_NOT_FOUND,
                    message: msg,
                    data: None,
                },
            );
        }

        // Delegate to the provider for backend subscription.
        if let Err(msg) = self.provider.subscribe_resource(&params.uri) {
            return JsonRpcResponse::error(
                request.id.clone(),
                JsonRpcError {
                    code: protocol::RESOURCE_NOT_FOUND,
                    message: msg,
                    data: None,
                },
            );
        }

        self.subscriptions.insert(params.uri);

        JsonRpcResponse::success(
            request.id.clone(),
            Value::Object(serde_json::Map::default()),
        )
    }

    // -----------------------------------------------------------------------
    // Dynamic context update notifications
    // -----------------------------------------------------------------------

    /// Creates a `notifications/tools/list_changed` notification.
    ///
    /// Callers should send this notification to connected MCP clients when:
    /// - The agent joins or leaves a context.
    /// - A tool is registered, updated, or removed in a context.
    #[must_use]
    pub fn tools_list_changed_notification() -> JsonRpcNotification {
        JsonRpcNotification::new(protocol::METHOD_TOOLS_LIST_CHANGED, None)
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

/// Parses a resource URI into `(context_id, resource_type)`.
///
/// Expected format: `scp://context_id/resource_type` where `resource_type` is
/// one of `events`, `members`, `tools`.
fn parse_resource_uri(uri: &str) -> Result<(String, &str), String> {
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

    Ok((context_id.to_owned(), resource_type))
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

        fn subscribe_resource(&self, _uri: &str) -> Result<(), String> {
            Ok(())
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
        assert!(
            result["capabilities"]["tools"]["listChanged"]
                .as_bool()
                .unwrap()
        );
        assert!(
            result["capabilities"]["resources"]["subscribe"]
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
        assert!(tools.contains(&"my_tool".to_owned()));
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
        assert!(err.message.contains("context not found"));
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
    fn resources_read_rejects_denied_ucan_capability() {
        // Deny the resource:members capability for ctx_a.
        let provider = MockProvider {
            denied_capabilities: vec![("ctx_a".to_owned(), "resource:members".to_owned())],
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

    #[test]
    fn resources_subscribe_succeeds() {
        let mut server = initialized_server(MockProvider::default());
        let req = make_request(
            protocol::METHOD_RESOURCES_SUBSCRIBE,
            Some(serde_json::json!({"uri": "scp://ctx_a/events"})),
        );
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_none());
        assert!(server.subscriptions.contains("scp://ctx_a/events"));
    }

    #[test]
    fn resources_subscribe_rejects_invalid_uri() {
        let mut server = initialized_server(MockProvider::default());
        let req = make_request(
            protocol::METHOD_RESOURCES_SUBSCRIBE,
            Some(serde_json::json!({"uri": "invalid"})),
        );
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_some());
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
        assert_eq!(rtype, "events");
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
