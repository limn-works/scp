//! JSON-RPC 2.0 types and MCP-specific message types.
//!
//! Implements the wire format for the Model Context Protocol (MCP), which uses
//! JSON-RPC 2.0 as its transport encoding. This module provides:
//!
//! - **JSON-RPC 2.0 primitives:** [`JsonRpcRequest`], [`JsonRpcResponse`],
//!   [`JsonRpcError`], [`JsonRpcNotification`].
//! - **MCP lifecycle messages:** [`InitializeParams`], [`InitializeResult`],
//!   [`InitializedNotification`], [`PingParams`].
//! - **MCP tool messages:** [`ToolsListParams`], [`ToolsListResult`],
//!   [`ToolsCallParams`], [`ToolsCallResult`], [`ToolDefinition`].
//! - **MCP resource messages:** [`ResourcesListParams`],
//!   [`ResourcesListResult`], [`ResourcesReadParams`],
//!   [`ResourcesReadResult`], [`ResourcesSubscribeParams`].
//! - **Standard error codes** for JSON-RPC and MCP-specific errors.
//!
//! All types derive `Serialize` and `Deserialize` via `serde_json`.
//!
//! See ADR-015 in `.docs/adrs/phase-3.md` for the full design.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 constants
// ---------------------------------------------------------------------------

/// The JSON-RPC protocol version string.
pub const JSONRPC_VERSION: &str = "2.0";

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 error codes (standard)
// ---------------------------------------------------------------------------

/// Invalid JSON was received by the server.
pub const PARSE_ERROR: i64 = -32700;

/// The JSON sent is not a valid Request object.
pub const INVALID_REQUEST: i64 = -32600;

/// The method does not exist or is not available.
pub const METHOD_NOT_FOUND: i64 = -32601;

/// Invalid method parameter(s).
pub const INVALID_PARAMS: i64 = -32602;

/// Internal JSON-RPC error.
pub const INTERNAL_ERROR: i64 = -32603;

// ---------------------------------------------------------------------------
// MCP-specific error codes (reserved range: -32000 to -32099)
// ---------------------------------------------------------------------------

/// The requested resource was not found.
pub const RESOURCE_NOT_FOUND: i64 = -32002;

/// The requested tool was not found.
pub const TOOL_NOT_FOUND: i64 = -32004;

/// The caller lacks the required capability for the operation.
pub const CAPABILITY_DENIED: i64 = -32005;

/// Tool execution failed.
pub const TOOL_EXECUTION_ERROR: i64 = -32006;

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 request ID
// ---------------------------------------------------------------------------

/// A JSON-RPC 2.0 request identifier.
///
/// Per the spec, IDs can be strings, numbers, or null.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    /// A numeric request ID.
    Number(i64),
    /// A string request ID.
    String(String),
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 core types
// ---------------------------------------------------------------------------

/// A JSON-RPC 2.0 request.
///
/// ```json
/// {
///     "jsonrpc": "2.0",
///     "method": "tools/call",
///     "params": { "name": "ctx/send_message", "arguments": {} },
///     "id": 1
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// The method to invoke.
    pub method: String,
    /// Method parameters (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    /// Request identifier.
    pub id: RequestId,
}

/// A JSON-RPC 2.0 successful response.
///
/// Contains either a `result` or an `error`, never both.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// The result of the method invocation (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// The error object (present on failure).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    /// Request identifier (matches the request).
    pub id: RequestId,
}

impl JsonRpcResponse {
    /// Creates a success response with the given result.
    #[must_use]
    pub fn success(id: RequestId, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Creates an error response.
    #[must_use]
    pub fn error(id: RequestId, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            result: None,
            error: Some(error),
            id,
        }
    }
}

/// A JSON-RPC 2.0 error object.
///
/// Returned in [`JsonRpcResponse::error`] when a method invocation fails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// A number indicating the error type.
    pub code: i64,
    /// A short description of the error.
    pub message: String,
    /// Additional information about the error (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// A JSON-RPC 2.0 notification (request without an ID).
///
/// Notifications are fire-and-forget -- the server does not send a response.
///
/// ```json
/// {
///     "jsonrpc": "2.0",
///     "method": "notifications/tools/list_changed",
///     "params": {}
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// The notification method.
    pub method: String,
    /// Notification parameters (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

impl JsonRpcNotification {
    /// Creates a new notification with the given method and optional params.
    #[must_use]
    pub fn new(method: impl Into<String>, params: Option<serde_json::Value>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            method: method.into(),
            params,
        }
    }
}

// ---------------------------------------------------------------------------
// MCP method constants
// ---------------------------------------------------------------------------

/// MCP method: `initialize` -- sent by the client to negotiate capabilities.
pub const METHOD_INITIALIZE: &str = "initialize";

/// MCP notification: `notifications/initialized` -- sent by the client after
/// receiving the initialize response.
pub const METHOD_INITIALIZED: &str = "notifications/initialized";

/// MCP method: `ping` -- keepalive.
pub const METHOD_PING: &str = "ping";

/// MCP method: `tools/list` -- list available tools.
pub const METHOD_TOOLS_LIST: &str = "tools/list";

/// MCP method: `tools/call` -- invoke a tool.
pub const METHOD_TOOLS_CALL: &str = "tools/call";

/// MCP method: `resources/list` -- list available resources.
pub const METHOD_RESOURCES_LIST: &str = "resources/list";

/// MCP method: `resources/read` -- read a resource.
pub const METHOD_RESOURCES_READ: &str = "resources/read";

/// MCP method: `resources/subscribe` -- subscribe to resource updates.
pub const METHOD_RESOURCES_SUBSCRIBE: &str = "resources/subscribe";

/// MCP notification: `notifications/tools/list_changed` -- tool list updated.
pub const METHOD_TOOLS_LIST_CHANGED: &str = "notifications/tools/list_changed";

// ---------------------------------------------------------------------------
// MCP lifecycle messages
// ---------------------------------------------------------------------------

/// Client capabilities sent during initialization.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientCapabilities {
    /// Whether the client supports tool list change notifications.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolClientCapability>,

    /// Whether the client supports resource subscriptions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceClientCapability>,
}

/// Client capability for tools.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolClientCapability {
    /// Whether the client supports tool list change notifications.
    #[serde(default, rename = "listChanged")]
    pub list_changed: bool,
}

/// Client capability for resources.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceClientCapability {
    /// Whether the client supports resource subscriptions.
    #[serde(default)]
    pub subscribe: bool,
}

/// Parameters for the `initialize` request.
///
/// Sent by the MCP client at connection start to negotiate protocol version
/// and capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeParams {
    /// The protocol version the client supports.
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,

    /// Client capabilities.
    pub capabilities: ClientCapabilities,

    /// Information about the client.
    #[serde(rename = "clientInfo")]
    pub client_info: ClientInfo,
}

/// Information about the MCP client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    /// Client name (e.g., `"claude-code"`).
    pub name: String,
    /// Client version (e.g., `"1.0.0"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Result of the `initialize` request.
///
/// Returned by the MCP server with its capabilities and protocol version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeResult {
    /// The protocol version the server supports.
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,

    /// Server capabilities.
    pub capabilities: ServerCapabilities,

    /// Information about the server.
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
}

/// Server capabilities advertised during initialization.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerCapabilities {
    /// Tool-related capabilities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolServerCapability>,

    /// Resource-related capabilities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceServerCapability>,
}

/// Server capability for tools.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolServerCapability {
    /// Whether the server may send `notifications/tools/list_changed`.
    #[serde(default, rename = "listChanged")]
    pub list_changed: bool,
}

/// Server capability for resources.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceServerCapability {
    /// Whether the server supports resource subscriptions.
    #[serde(default)]
    pub subscribe: bool,
}

/// Information about the MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    /// Server name (e.g., `"scp-mcp"`).
    pub name: String,
    /// Server version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Parameters for the `notifications/initialized` notification.
///
/// Sent by the client after receiving the initialize response.
/// Currently empty per the MCP spec.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InitializedNotification {}

/// Parameters for the `ping` method.
///
/// Empty -- keepalive only.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PingParams {}

// ---------------------------------------------------------------------------
// MCP tool messages
// ---------------------------------------------------------------------------

/// An MCP tool definition.
///
/// Describes a tool available to the model, with its name, description,
/// and JSON Schema for input parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// The tool name, namespaced by context: `"context_id/tool_name"`.
    pub name: String,

    /// A human-readable description of what the tool does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// JSON Schema describing the tool's input parameters.
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

/// Parameters for `tools/list`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolsListParams {
    /// Optional cursor for pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Result of `tools/list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsListResult {
    /// The list of available tools.
    pub tools: Vec<ToolDefinition>,

    /// Cursor for the next page (if paginated).
    #[serde(skip_serializing_if = "Option::is_none", rename = "nextCursor")]
    pub next_cursor: Option<String>,
}

/// Parameters for `tools/call`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsCallParams {
    /// The namespaced tool name: `"context_id/tool_name"`.
    pub name: String,

    /// The tool's input arguments.
    #[serde(default)]
    pub arguments: serde_json::Value,
}

/// Content item in a tool call result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentItem {
    /// Text content.
    #[serde(rename = "text")]
    Text {
        /// The text content.
        text: String,
    },

    /// Image content (base64-encoded).
    #[serde(rename = "image")]
    Image {
        /// Base64-encoded image data.
        data: String,
        /// MIME type (e.g., `"image/png"`).
        #[serde(rename = "mimeType")]
        mime_type: String,
    },

    /// Embedded resource content.
    #[serde(rename = "resource")]
    Resource {
        /// The resource reference.
        resource: ResourceReference,
    },
}

/// A reference to an MCP resource within content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceReference {
    /// The resource URI.
    pub uri: String,
    /// MIME type of the resource content.
    #[serde(skip_serializing_if = "Option::is_none", rename = "mimeType")]
    pub mime_type: Option<String>,
    /// The text content of the resource (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// Result of `tools/call`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsCallResult {
    /// The tool output content.
    pub content: Vec<ContentItem>,

    /// Whether the tool call resulted in an error.
    #[serde(default, rename = "isError")]
    pub is_error: bool,
}

// ---------------------------------------------------------------------------
// MCP resource messages
// ---------------------------------------------------------------------------

/// An MCP resource definition.
///
/// Describes a resource available to the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceDefinition {
    /// Resource URI (e.g., `"scp://context_a/events"`).
    pub uri: String,

    /// Human-readable name.
    pub name: String,

    /// Description of the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// MIME type of the resource content.
    #[serde(skip_serializing_if = "Option::is_none", rename = "mimeType")]
    pub mime_type: Option<String>,
}

/// Parameters for `resources/list`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourcesListParams {
    /// Optional cursor for pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Result of `resources/list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesListResult {
    /// The list of available resources.
    pub resources: Vec<ResourceDefinition>,

    /// Cursor for the next page (if paginated).
    #[serde(skip_serializing_if = "Option::is_none", rename = "nextCursor")]
    pub next_cursor: Option<String>,
}

/// Parameters for `resources/read`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesReadParams {
    /// The URI of the resource to read.
    pub uri: String,
}

/// A content item within a resource read result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceContent {
    /// The resource URI.
    pub uri: String,

    /// MIME type of the content.
    #[serde(skip_serializing_if = "Option::is_none", rename = "mimeType")]
    pub mime_type: Option<String>,

    /// Text content (for text resources).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,

    /// Base64-encoded binary content (for binary resources).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
}

/// Result of `resources/read`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesReadResult {
    /// The resource contents.
    pub contents: Vec<ResourceContent>,
}

/// Parameters for `resources/subscribe`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesSubscribeParams {
    /// The URI of the resource to subscribe to.
    pub uri: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -- JSON-RPC Request ---------------------------------------------------

    #[test]
    fn request_serialization_roundtrip_with_numeric_id() {
        let req = JsonRpcRequest {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            method: "tools/call".to_owned(),
            params: Some(serde_json::json!({"name": "ctx/send_message"})),
            id: RequestId::Number(1),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: JsonRpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.jsonrpc, "2.0");
        assert_eq!(parsed.method, "tools/call");
        assert_eq!(parsed.id, RequestId::Number(1));
        assert!(parsed.params.is_some());
    }

    #[test]
    fn request_serialization_roundtrip_with_string_id() {
        let req = JsonRpcRequest {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            method: "ping".to_owned(),
            params: None,
            id: RequestId::String("abc-123".to_owned()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: JsonRpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, RequestId::String("abc-123".to_owned()));
        assert!(parsed.params.is_none());
    }

    #[test]
    fn request_deserializes_from_mcp_example() {
        let json = r#"{
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "context_a/guide_assistant",
                "arguments": { "query": "butter substitute" }
            },
            "id": 1
        }"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "tools/call");
        assert_eq!(req.id, RequestId::Number(1));
        let params = req.params.unwrap();
        assert_eq!(params["name"], "context_a/guide_assistant");
    }

    #[test]
    fn request_without_params_omits_field() {
        let req = JsonRpcRequest {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            method: "ping".to_owned(),
            params: None,
            id: RequestId::Number(5),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("params"));
    }

    // -- JSON-RPC Response --------------------------------------------------

    #[test]
    fn success_response_serialization_roundtrip() {
        let resp = JsonRpcResponse::success(RequestId::Number(1), serde_json::json!({"tools": []}));
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.jsonrpc, "2.0");
        assert!(parsed.result.is_some());
        assert!(parsed.error.is_none());
        assert_eq!(parsed.id, RequestId::Number(1));
    }

    #[test]
    fn error_response_serialization_roundtrip() {
        let err = JsonRpcError {
            code: METHOD_NOT_FOUND,
            message: "method not found".to_owned(),
            data: None,
        };
        let resp = JsonRpcResponse::error(RequestId::Number(2), err);
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.result.is_none());
        let error = parsed.error.unwrap();
        assert_eq!(error.code, METHOD_NOT_FOUND);
        assert_eq!(error.message, "method not found");
    }

    #[test]
    fn error_response_with_data() {
        let err = JsonRpcError {
            code: INVALID_PARAMS,
            message: "invalid params".to_owned(),
            data: Some(serde_json::json!({"field": "name"})),
        };
        let resp = JsonRpcResponse::error(RequestId::String("x".to_owned()), err);
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&json).unwrap();
        let error = parsed.error.unwrap();
        assert_eq!(error.data.unwrap()["field"], "name");
    }

    // -- JSON-RPC Notification ----------------------------------------------

    #[test]
    fn notification_serialization_roundtrip() {
        let notif = JsonRpcNotification::new(METHOD_TOOLS_LIST_CHANGED, None);
        let json = serde_json::to_string(&notif).unwrap();
        let parsed: JsonRpcNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.jsonrpc, "2.0");
        assert_eq!(parsed.method, METHOD_TOOLS_LIST_CHANGED);
        assert!(parsed.params.is_none());
    }

    #[test]
    fn notification_without_params_omits_field() {
        let notif = JsonRpcNotification::new("test/method", None);
        let json = serde_json::to_string(&notif).unwrap();
        assert!(!json.contains("params"));
    }

    #[test]
    fn notification_with_params() {
        let notif =
            JsonRpcNotification::new("test/method", Some(serde_json::json!({"key": "value"})));
        let json = serde_json::to_string(&notif).unwrap();
        assert!(json.contains("params"));
        let parsed: JsonRpcNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.params.unwrap()["key"], "value");
    }

    // -- JSON-RPC Error object ----------------------------------------------

    #[test]
    fn error_without_data_omits_field() {
        let err = JsonRpcError {
            code: PARSE_ERROR,
            message: "parse error".to_owned(),
            data: None,
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(!json.contains("data"));
    }

    // -- MCP Initialize -----------------------------------------------------

    #[test]
    fn initialize_params_roundtrip() {
        let params = InitializeParams {
            protocol_version: "2024-11-05".to_owned(),
            capabilities: ClientCapabilities::default(),
            client_info: ClientInfo {
                name: "test-client".to_owned(),
                version: Some("1.0.0".to_owned()),
            },
        };
        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(json["protocolVersion"], "2024-11-05");
        assert_eq!(json["clientInfo"]["name"], "test-client");
        let parsed: InitializeParams = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.protocol_version, "2024-11-05");
    }

    #[test]
    fn initialize_result_roundtrip() {
        let result = InitializeResult {
            protocol_version: "2024-11-05".to_owned(),
            capabilities: ServerCapabilities {
                tools: Some(ToolServerCapability { list_changed: true }),
                resources: Some(ResourceServerCapability { subscribe: true }),
            },
            server_info: ServerInfo {
                name: "scp-mcp".to_owned(),
                version: Some("0.1.0".to_owned()),
            },
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["serverInfo"]["name"], "scp-mcp");
        assert!(
            json["capabilities"]["tools"]["listChanged"]
                .as_bool()
                .unwrap()
        );
        let parsed: InitializeResult = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.server_info.name, "scp-mcp");
    }

    #[test]
    fn initialized_notification_is_empty() {
        let notif = InitializedNotification {};
        let json = serde_json::to_value(&notif).unwrap();
        assert!(json.as_object().unwrap().is_empty());
    }

    #[test]
    fn ping_params_is_empty() {
        let params = PingParams {};
        let json = serde_json::to_value(&params).unwrap();
        assert!(json.as_object().unwrap().is_empty());
    }

    // -- MCP Tools ----------------------------------------------------------

    #[test]
    fn tool_definition_roundtrip() {
        let tool = ToolDefinition {
            name: "context_a/send_message".to_owned(),
            description: Some("Send a message to the context".to_owned()),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "content": { "type": "string" }
                },
                "required": ["content"]
            }),
        };
        let json = serde_json::to_value(&tool).unwrap();
        assert_eq!(json["name"], "context_a/send_message");
        assert_eq!(json["inputSchema"]["type"], "object");
        let parsed: ToolDefinition = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.name, "context_a/send_message");
    }

    #[test]
    fn tools_list_result_roundtrip() {
        let result = ToolsListResult {
            tools: vec![
                ToolDefinition {
                    name: "ctx/send_message".to_owned(),
                    description: Some("Send a message".to_owned()),
                    input_schema: serde_json::json!({"type": "object"}),
                },
                ToolDefinition {
                    name: "ctx/read_messages".to_owned(),
                    description: Some("Read messages".to_owned()),
                    input_schema: serde_json::json!({"type": "object"}),
                },
            ],
            next_cursor: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ToolsListResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tools.len(), 2);
        assert!(parsed.next_cursor.is_none());
    }

    #[test]
    fn tools_call_params_roundtrip() {
        let params = ToolsCallParams {
            name: "context_a/guide_assistant".to_owned(),
            arguments: serde_json::json!({"query": "butter substitute"}),
        };
        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(json["name"], "context_a/guide_assistant");
        assert_eq!(json["arguments"]["query"], "butter substitute");
        let parsed: ToolsCallParams = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.name, "context_a/guide_assistant");
    }

    #[test]
    fn tools_call_result_with_text_content() {
        let result = ToolsCallResult {
            content: vec![ContentItem::Text {
                text: "Message sent successfully".to_owned(),
            }],
            is_error: false,
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ToolsCallResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.content.len(), 1);
        assert!(!parsed.is_error);
        match &parsed.content[0] {
            ContentItem::Text { text } => assert_eq!(text, "Message sent successfully"),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    #[test]
    fn tools_call_result_with_error() {
        let result = ToolsCallResult {
            content: vec![ContentItem::Text {
                text: "Tool execution failed".to_owned(),
            }],
            is_error: true,
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ToolsCallResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_error);
    }

    #[test]
    fn content_item_image_roundtrip() {
        let item = ContentItem::Image {
            data: "aGVsbG8=".to_owned(),
            mime_type: "image/png".to_owned(),
        };
        let json = serde_json::to_value(&item).unwrap();
        assert_eq!(json["type"], "image");
        assert_eq!(json["mimeType"], "image/png");
        let parsed: ContentItem = serde_json::from_value(json).unwrap();
        match parsed {
            ContentItem::Image { data, mime_type } => {
                assert_eq!(data, "aGVsbG8=");
                assert_eq!(mime_type, "image/png");
            }
            other => panic!("expected Image, got {other:?}"),
        }
    }

    #[test]
    fn content_item_resource_roundtrip() {
        let item = ContentItem::Resource {
            resource: ResourceReference {
                uri: "scp://ctx/events".to_owned(),
                mime_type: Some("application/json".to_owned()),
                text: Some("{\"events\": []}".to_owned()),
            },
        };
        let json = serde_json::to_value(&item).unwrap();
        assert_eq!(json["type"], "resource");
        assert_eq!(json["resource"]["uri"], "scp://ctx/events");
        let parsed: ContentItem = serde_json::from_value(json).unwrap();
        match parsed {
            ContentItem::Resource { resource } => {
                assert_eq!(resource.uri, "scp://ctx/events");
            }
            other => panic!("expected Resource, got {other:?}"),
        }
    }

    // -- MCP Resources ------------------------------------------------------

    #[test]
    fn resource_definition_roundtrip() {
        let resource = ResourceDefinition {
            uri: "scp://context_a/events".to_owned(),
            name: "Context A Events".to_owned(),
            description: Some("Event stream for context A".to_owned()),
            mime_type: Some("application/json".to_owned()),
        };
        let json = serde_json::to_value(&resource).unwrap();
        assert_eq!(json["uri"], "scp://context_a/events");
        assert_eq!(json["mimeType"], "application/json");
        let parsed: ResourceDefinition = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.uri, "scp://context_a/events");
    }

    #[test]
    fn resources_list_result_roundtrip() {
        let result = ResourcesListResult {
            resources: vec![ResourceDefinition {
                uri: "scp://ctx/events".to_owned(),
                name: "Events".to_owned(),
                description: None,
                mime_type: None,
            }],
            next_cursor: Some("page2".to_owned()),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ResourcesListResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.resources.len(), 1);
        assert_eq!(parsed.next_cursor.as_deref(), Some("page2"));
    }

    #[test]
    fn resources_read_params_roundtrip() {
        let params = ResourcesReadParams {
            uri: "scp://context_a/members".to_owned(),
        };
        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(json["uri"], "scp://context_a/members");
        let parsed: ResourcesReadParams = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.uri, "scp://context_a/members");
    }

    #[test]
    fn resources_read_result_with_text() {
        let result = ResourcesReadResult {
            contents: vec![ResourceContent {
                uri: "scp://ctx/members".to_owned(),
                mime_type: Some("application/json".to_owned()),
                text: Some("[\"did:dht:alice\"]".to_owned()),
                blob: None,
            }],
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ResourcesReadResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.contents.len(), 1);
        assert!(parsed.contents[0].text.is_some());
        assert!(parsed.contents[0].blob.is_none());
    }

    #[test]
    fn resources_subscribe_params_roundtrip() {
        let params = ResourcesSubscribeParams {
            uri: "scp://context_a/events".to_owned(),
        };
        let json = serde_json::to_value(&params).unwrap();
        let parsed: ResourcesSubscribeParams = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.uri, "scp://context_a/events");
    }

    // -- Error codes --------------------------------------------------------

    #[test]
    fn standard_error_codes_are_correct() {
        assert_eq!(PARSE_ERROR, -32700);
        assert_eq!(INVALID_REQUEST, -32600);
        assert_eq!(METHOD_NOT_FOUND, -32601);
        assert_eq!(INVALID_PARAMS, -32602);
        assert_eq!(INTERNAL_ERROR, -32603);
    }

    #[test]
    fn mcp_error_codes_in_reserved_range() {
        // MCP uses -32000 to -32099 for server errors.
        let mcp_codes = [
            RESOURCE_NOT_FOUND,
            TOOL_NOT_FOUND,
            CAPABILITY_DENIED,
            TOOL_EXECUTION_ERROR,
        ];
        for code in mcp_codes {
            assert!(
                (-32099..=-32000).contains(&code),
                "MCP error code {code} is outside reserved range -32099..-32000"
            );
        }
    }

    // -- Method constants ---------------------------------------------------

    #[test]
    fn method_constants_match_mcp_spec() {
        assert_eq!(METHOD_INITIALIZE, "initialize");
        assert_eq!(METHOD_INITIALIZED, "notifications/initialized");
        assert_eq!(METHOD_PING, "ping");
        assert_eq!(METHOD_TOOLS_LIST, "tools/list");
        assert_eq!(METHOD_TOOLS_CALL, "tools/call");
        assert_eq!(METHOD_RESOURCES_LIST, "resources/list");
        assert_eq!(METHOD_RESOURCES_READ, "resources/read");
        assert_eq!(METHOD_RESOURCES_SUBSCRIBE, "resources/subscribe");
        assert_eq!(
            METHOD_TOOLS_LIST_CHANGED,
            "notifications/tools/list_changed"
        );
    }

    // -- Tools list params default ------------------------------------------

    #[test]
    fn tools_list_params_default_has_no_cursor() {
        let params = ToolsListParams::default();
        assert!(params.cursor.is_none());
    }

    // -- Client capabilities default ----------------------------------------

    #[test]
    fn client_capabilities_default_is_empty() {
        let caps = ClientCapabilities::default();
        assert!(caps.tools.is_none());
        assert!(caps.resources.is_none());
    }

    // -- Server capabilities default ----------------------------------------

    #[test]
    fn server_capabilities_default_is_empty() {
        let caps = ServerCapabilities::default();
        assert!(caps.tools.is_none());
        assert!(caps.resources.is_none());
    }
}
