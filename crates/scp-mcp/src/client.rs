//! MCP client for consuming external tools with SCP provenance.
//!
//! An SCP agent can consume tools from external MCP servers (non-SCP tools).
//! When it does, the client wraps tool results with SCP provenance metadata:
//! "this result came from external MCP tool X, invoked by agent Y in context Z."
//! This maintains SCP's provenance-everywhere principle even for external tool
//! calls.
//!
//! The client uses a trait-based transport abstraction ([`McpTransport`]) to
//! communicate with external MCP servers via stdio or SSE. This allows the
//! client protocol logic to be tested independently of transport I/O.
//!
//! See ADR-015 in `.docs/adrs/phase-3.md` for the full design.

use std::sync::atomic::{AtomicI64, Ordering};

use serde::{Deserialize, Serialize};

use crate::protocol::{
    self, ClientCapabilities, ClientInfo, ContentItem, InitializeParams, InitializeResult,
    JSONRPC_VERSION, JsonRpcRequest, JsonRpcResponse, RequestId, ToolDefinition, ToolsCallParams,
    ToolsCallResult, ToolsListResult,
};

// ---------------------------------------------------------------------------
// Transport configuration
// ---------------------------------------------------------------------------

/// Configuration for connecting to an external MCP server.
#[derive(Debug, Clone)]
pub enum TransportConfig {
    /// Connect via stdio: spawn a subprocess and communicate over stdin/stdout.
    Stdio {
        /// The command to execute (e.g., `"uvx"`).
        command: String,
        /// Arguments to pass to the command (e.g., `["some-mcp-server"]`).
        args: Vec<String>,
    },
    /// Connect via SSE: HTTP client with Server-Sent Events for
    /// server-to-client messages and POST for client-to-server messages.
    Sse {
        /// The URL of the SSE endpoint (e.g., `"http://localhost:3001/sse"`).
        url: String,
    },
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by MCP client operations.
#[derive(Debug, thiserror::Error)]
pub enum McpClientError {
    /// The client has not completed the MCP initialize handshake.
    #[error("client not initialized: call initialize() first")]
    NotInitialized,

    /// Transport I/O failed.
    #[error("transport error: {0}")]
    Transport(String),

    /// The server returned a JSON-RPC error response.
    #[error("server error {code}: {message}")]
    ServerError {
        /// The JSON-RPC error code.
        code: i64,
        /// The error message.
        message: String,
    },

    /// Failed to parse the server's response.
    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

// ---------------------------------------------------------------------------
// Transport trait
// ---------------------------------------------------------------------------

/// Trait abstracting the transport layer for MCP client communication.
///
/// Implementations handle the actual I/O (stdio subprocess, HTTP/SSE).
/// The trait boundary allows the client to be tested with mock transports.
pub trait McpTransport: Send + Sync {
    /// Sends a JSON-RPC request and receives the response.
    ///
    /// # Errors
    ///
    /// Returns a transport error message if sending or receiving fails.
    fn send_request(&self, request: &JsonRpcRequest) -> Result<JsonRpcResponse, String>;

    /// Sends a JSON-RPC notification (no response expected).
    ///
    /// # Errors
    ///
    /// Returns a transport error message if sending fails.
    fn send_notification(
        &self,
        notification: &crate::protocol::JsonRpcNotification,
    ) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// Provenance types
// ---------------------------------------------------------------------------

/// Provenance metadata for results from external MCP tool calls.
///
/// Records the external tool source, the invoking agent's DID, the SCP
/// context in which the invocation was made, and the timestamp. This
/// maintains SCP's provenance-everywhere principle for external tool results.
///
/// Format: `{ source: "mcp:{tool_name}", invoked_by: did, context: ctx_id, timestamp: ts }`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalToolProvenance {
    /// The source of the tool result, formatted as `"mcp:{tool_name}"`.
    pub source: String,
    /// The DID of the agent that invoked the tool.
    pub invoked_by: String,
    /// The SCP context ID in which the invocation was made.
    pub context: String,
    /// The timestamp of the invocation (milliseconds since Unix epoch).
    pub timestamp: u64,
}

impl ExternalToolProvenance {
    /// Creates provenance metadata for an external MCP tool invocation.
    #[must_use]
    pub fn new(tool_name: &str, invoker_did: &str, context_id: &str, timestamp: u64) -> Self {
        Self {
            source: format!("mcp:{tool_name}"),
            invoked_by: invoker_did.to_owned(),
            context: context_id.to_owned(),
            timestamp,
        }
    }
}

/// The result of invoking an external MCP tool, wrapped with SCP provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolResult {
    /// The tool output content from the external MCP server.
    pub content: Vec<ContentItem>,
    /// Whether the tool call resulted in an error.
    pub is_error: bool,
    /// SCP provenance metadata recording the external tool source, invoking
    /// agent, context, and timestamp.
    pub provenance: ExternalToolProvenance,
}

// ---------------------------------------------------------------------------
// Timestamp provider
// ---------------------------------------------------------------------------

/// Trait for providing timestamps, allowing test injection.
pub trait TimestampProvider: Send + Sync {
    /// Returns the current time as milliseconds since Unix epoch.
    fn now_millis(&self) -> u64;
}

/// Default timestamp provider using `SystemTime`.
pub struct SystemTimestamp;

impl TimestampProvider for SystemTimestamp {
    fn now_millis(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// McpClient
// ---------------------------------------------------------------------------

/// MCP protocol version used by this client.
const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

/// Client name reported during initialization.
const CLIENT_NAME: &str = "scp-mcp-client";

/// Client version reported during initialization.
const CLIENT_VERSION: &str = "0.1.0";

/// An MCP client that connects to external MCP servers and wraps tool results
/// with SCP provenance metadata.
///
/// # Usage
///
/// 1. Create a client with a transport and timestamp provider.
/// 2. Call [`initialize`](Self::initialize) to complete the MCP handshake.
/// 3. Call [`list_tools`](Self::list_tools) to discover available tools.
/// 4. Call [`invoke`](Self::invoke) to invoke a tool with SCP provenance wrapping.
///
/// See ADR-015 in `.docs/adrs/phase-3.md` for the full design.
pub struct McpClient<T: McpTransport, C: TimestampProvider = SystemTimestamp> {
    /// The transport layer for communicating with the external MCP server.
    transport: T,
    /// Whether the MCP initialize handshake has completed.
    initialized: bool,
    /// Server capabilities received during initialization.
    server_info: Option<InitializeResult>,
    /// Monotonically increasing request ID counter.
    next_id: AtomicI64,
    /// Timestamp provider for provenance metadata.
    clock: C,
}

impl<T: McpTransport> McpClient<T, SystemTimestamp> {
    /// Creates a new MCP client with the given transport.
    ///
    /// Uses the system clock for timestamps. Call [`initialize`](Self::initialize)
    /// before listing or invoking tools.
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self {
            transport,
            initialized: false,
            server_info: None,
            next_id: AtomicI64::new(1),
            clock: SystemTimestamp,
        }
    }
}

impl<T: McpTransport, C: TimestampProvider> McpClient<T, C> {
    /// Creates a new MCP client with a custom timestamp provider.
    ///
    /// Useful for testing with deterministic timestamps.
    #[must_use]
    pub const fn with_clock(transport: T, clock: C) -> Self {
        Self {
            transport,
            initialized: false,
            server_info: None,
            next_id: AtomicI64::new(1),
            clock,
        }
    }

    /// Returns whether the MCP handshake has completed.
    #[must_use]
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns the server info received during initialization, if available.
    #[must_use]
    pub const fn server_info(&self) -> Option<&InitializeResult> {
        self.server_info.as_ref()
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Allocates a new request ID.
    fn next_request_id(&self) -> RequestId {
        RequestId::Number(self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    /// Sends a JSON-RPC request and returns the parsed response.
    fn send(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<JsonRpcResponse, McpClientError> {
        let request = JsonRpcRequest {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            method: method.to_owned(),
            params,
            id: self.next_request_id(),
        };

        self.transport
            .send_request(&request)
            .map_err(McpClientError::Transport)
    }

    /// Extracts the `result` field from a response, or converts the error.
    fn extract_result(response: &JsonRpcResponse) -> Result<&serde_json::Value, McpClientError> {
        if let Some(ref error) = response.error {
            return Err(McpClientError::ServerError {
                code: error.code,
                message: error.message.clone(),
            });
        }

        response.result.as_ref().ok_or_else(|| {
            McpClientError::InvalidResponse("response contains neither result nor error".to_owned())
        })
    }

    // -----------------------------------------------------------------------
    // MCP lifecycle
    // -----------------------------------------------------------------------

    /// Completes the MCP initialize handshake with the external server.
    ///
    /// Must be called before [`list_tools`](Self::list_tools) or
    /// [`invoke`](Self::invoke).
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails or the server returns an error.
    pub fn initialize(&mut self) -> Result<&InitializeResult, McpClientError> {
        let params = InitializeParams {
            protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
            capabilities: ClientCapabilities::default(),
            client_info: ClientInfo {
                name: CLIENT_NAME.to_owned(),
                version: Some(CLIENT_VERSION.to_owned()),
            },
        };

        let params_json = serde_json::to_value(&params)
            .map_err(|e| McpClientError::InvalidResponse(e.to_string()))?;

        let response = self.send(protocol::METHOD_INITIALIZE, Some(params_json))?;
        let result_value = Self::extract_result(&response)?;

        let init_result: InitializeResult = serde_json::from_value(result_value.clone())
            .map_err(|e| McpClientError::InvalidResponse(e.to_string()))?;

        self.server_info = Some(init_result);
        self.initialized = true;

        // Send the `initialized` notification.
        let notification = crate::protocol::JsonRpcNotification::new(
            protocol::METHOD_INITIALIZED,
            Some(serde_json::json!({})),
        );
        self.transport
            .send_notification(&notification)
            .map_err(McpClientError::Transport)?;

        // Safety: we just set server_info to Some above.
        self.server_info.as_ref().ok_or_else(|| {
            McpClientError::InvalidResponse("server_info unexpectedly None".to_owned())
        })
    }

    // -----------------------------------------------------------------------
    // Tool listing
    // -----------------------------------------------------------------------

    /// Lists available tools from the external MCP server.
    ///
    /// Sends a `tools/list` JSON-RPC request and returns the tool definitions.
    ///
    /// # Errors
    ///
    /// Returns [`McpClientError::NotInitialized`] if the handshake has not
    /// completed, or a transport/server error.
    pub fn list_tools(&self) -> Result<Vec<ToolDefinition>, McpClientError> {
        if !self.initialized {
            return Err(McpClientError::NotInitialized);
        }

        let response = self.send(protocol::METHOD_TOOLS_LIST, Some(serde_json::json!({})))?;
        let result_value = Self::extract_result(&response)?;

        let list_result: ToolsListResult = serde_json::from_value(result_value.clone())
            .map_err(|e| McpClientError::InvalidResponse(e.to_string()))?;

        Ok(list_result.tools)
    }

    // -----------------------------------------------------------------------
    // Tool invocation with provenance
    // -----------------------------------------------------------------------

    /// Invokes an external tool and wraps the result with SCP provenance.
    ///
    /// Sends a `tools/call` JSON-RPC request to the external MCP server, then
    /// wraps the result with provenance metadata recording the external tool
    /// source, the invoking agent's DID, the SCP context, and the timestamp.
    ///
    /// # Arguments
    ///
    /// * `tool` -- The name of the external tool to invoke.
    /// * `input` -- The tool's input arguments as a JSON value.
    /// * `context_id` -- The SCP context ID for provenance tracking.
    /// * `invoker_did` -- The DID of the agent invoking the tool.
    ///
    /// # Errors
    ///
    /// Returns [`McpClientError::NotInitialized`] if the handshake has not
    /// completed, or a transport/server error.
    pub fn invoke(
        &self,
        tool: &str,
        input: serde_json::Value,
        context_id: &str,
        invoker_did: &str,
    ) -> Result<McpToolResult, McpClientError> {
        if !self.initialized {
            return Err(McpClientError::NotInitialized);
        }

        let call_params = ToolsCallParams {
            name: tool.to_owned(),
            arguments: input,
        };

        let params_json = serde_json::to_value(&call_params)
            .map_err(|e| McpClientError::InvalidResponse(e.to_string()))?;

        let response = self.send(protocol::METHOD_TOOLS_CALL, Some(params_json))?;
        let result_value = Self::extract_result(&response)?;

        let call_result: ToolsCallResult = serde_json::from_value(result_value.clone())
            .map_err(|e| McpClientError::InvalidResponse(e.to_string()))?;

        let provenance =
            ExternalToolProvenance::new(tool, invoker_did, context_id, self.clock.now_millis());

        Ok(McpToolResult {
            content: call_result.content,
            is_error: call_result.is_error,
            provenance,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::protocol::{
        InitializeResult, JsonRpcError, JsonRpcNotification, ServerCapabilities, ServerInfo,
        ToolServerCapability,
    };

    // -----------------------------------------------------------------------
    // Mock transport
    // -----------------------------------------------------------------------

    /// Records all sent requests/notifications and returns pre-configured
    /// responses. Uses `Mutex` for `Send + Sync` required by `McpTransport`.
    struct MockTransport {
        responses: Mutex<Vec<JsonRpcResponse>>,
        sent_requests: Mutex<Vec<JsonRpcRequest>>,
        sent_notifications: Mutex<Vec<JsonRpcNotification>>,
    }

    impl MockTransport {
        fn new(responses: Vec<JsonRpcResponse>) -> Self {
            Self {
                responses: Mutex::new(responses),
                sent_requests: Mutex::new(Vec::new()),
                sent_notifications: Mutex::new(Vec::new()),
            }
        }

        fn sent_requests(&self) -> Vec<JsonRpcRequest> {
            self.sent_requests.lock().unwrap().clone()
        }

        fn sent_notifications(&self) -> Vec<JsonRpcNotification> {
            self.sent_notifications.lock().unwrap().clone()
        }
    }

    impl McpTransport for MockTransport {
        fn send_request(&self, request: &JsonRpcRequest) -> Result<JsonRpcResponse, String> {
            self.sent_requests.lock().unwrap().push(request.clone());
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                return Err("no more mock responses".to_owned());
            }
            Ok(responses.remove(0))
        }

        fn send_notification(&self, notification: &JsonRpcNotification) -> Result<(), String> {
            self.sent_notifications
                .lock()
                .unwrap()
                .push(notification.clone());
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Mock timestamp provider
    // -----------------------------------------------------------------------

    struct FixedClock(u64);

    impl TimestampProvider for FixedClock {
        fn now_millis(&self) -> u64 {
            self.0
        }
    }

    // -----------------------------------------------------------------------
    // Helper: build an initialize success response
    // -----------------------------------------------------------------------

    fn init_success_response(id: RequestId) -> JsonRpcResponse {
        let result = InitializeResult {
            protocol_version: "2024-11-05".to_owned(),
            capabilities: ServerCapabilities {
                tools: Some(ToolServerCapability { list_changed: true }),
                resources: None,
            },
            server_info: ServerInfo {
                name: "test-server".to_owned(),
                version: Some("1.0.0".to_owned()),
            },
        };
        JsonRpcResponse::success(id, serde_json::to_value(&result).unwrap())
    }

    /// Helper: build an initialized client with a mock transport that has
    /// additional responses queued.
    fn initialized_client(
        additional_responses: Vec<JsonRpcResponse>,
    ) -> McpClient<MockTransport, FixedClock> {
        // First response is for the initialize handshake.
        let mut responses = vec![init_success_response(RequestId::Number(1))];
        responses.extend(additional_responses);

        let transport = MockTransport::new(responses);
        let mut client = McpClient::with_clock(transport, FixedClock(1_700_000_000_000));
        client.initialize().unwrap();
        client
    }

    // -----------------------------------------------------------------------
    // ExternalToolProvenance tests
    // -----------------------------------------------------------------------

    #[test]
    fn provenance_new_formats_source_correctly() {
        let p = ExternalToolProvenance::new(
            "weather_lookup",
            "did:dht:z6MkAlice",
            "ctx-123",
            1_700_000_000_000,
        );
        assert_eq!(p.source, "mcp:weather_lookup");
        assert_eq!(p.invoked_by, "did:dht:z6MkAlice");
        assert_eq!(p.context, "ctx-123");
        assert_eq!(p.timestamp, 1_700_000_000_000);
    }

    #[test]
    fn provenance_serialization_roundtrip() {
        let p = ExternalToolProvenance::new(
            "external_tool",
            "did:dht:z6MkBob",
            "ctx-abc",
            1_700_000_000_000,
        );
        let json = serde_json::to_string(&p).unwrap();
        let parsed: ExternalToolProvenance = serde_json::from_str(&json).unwrap();
        assert_eq!(p, parsed);
    }

    #[test]
    fn provenance_json_has_expected_fields() {
        let p = ExternalToolProvenance::new("my_tool", "did:dht:z6MkTest", "ctx-xyz", 42);
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["source"], "mcp:my_tool");
        assert_eq!(json["invoked_by"], "did:dht:z6MkTest");
        assert_eq!(json["context"], "ctx-xyz");
        assert_eq!(json["timestamp"], 42);
    }

    // -----------------------------------------------------------------------
    // McpClient lifecycle tests
    // -----------------------------------------------------------------------

    #[test]
    fn client_not_initialized_by_default() {
        let transport = MockTransport::new(vec![]);
        let client = McpClient::with_clock(transport, FixedClock(0));
        assert!(!client.is_initialized());
        assert!(client.server_info().is_none());
    }

    #[test]
    fn initialize_completes_handshake() {
        let transport = MockTransport::new(vec![init_success_response(RequestId::Number(1))]);
        let mut client = McpClient::with_clock(transport, FixedClock(0));

        let result = client.initialize();
        assert!(result.is_ok());
        assert!(client.is_initialized());

        let info = client.server_info().unwrap();
        assert_eq!(info.server_info.name, "test-server");
        assert_eq!(info.protocol_version, "2024-11-05");
    }

    #[test]
    fn initialize_sends_request_and_notification() {
        let transport = MockTransport::new(vec![init_success_response(RequestId::Number(1))]);
        let mut client = McpClient::with_clock(transport, FixedClock(0));
        client.initialize().unwrap();

        // Verify the initialize request was sent.
        let requests = client.transport.sent_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "initialize");

        // Verify the initialized notification was sent.
        let notifications = client.transport.sent_notifications();
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].method, "notifications/initialized");
    }

    #[test]
    fn initialize_fails_on_transport_error() {
        let transport = MockTransport::new(vec![]); // No responses -> transport error.
        let mut client = McpClient::with_clock(transport, FixedClock(0));

        let result = client.initialize();
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Access client only after consuming result (which borrows &mut self).
        assert!(!client.is_initialized());
        assert!(matches!(err, McpClientError::Transport(_)));
    }

    #[test]
    fn initialize_fails_on_server_error() {
        let error_response = JsonRpcResponse::error(
            RequestId::Number(1),
            JsonRpcError {
                code: -32600,
                message: "bad request".to_owned(),
                data: None,
            },
        );
        let transport = MockTransport::new(vec![error_response]);
        let mut client = McpClient::with_clock(transport, FixedClock(0));

        let result = client.initialize();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            McpClientError::ServerError { code: -32600, .. }
        ));
    }

    // -----------------------------------------------------------------------
    // list_tools tests
    // -----------------------------------------------------------------------

    #[test]
    fn list_tools_requires_initialization() {
        let transport = MockTransport::new(vec![]);
        let client = McpClient::with_clock(transport, FixedClock(0));

        let result = client.list_tools();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            McpClientError::NotInitialized
        ));
    }

    #[test]
    fn list_tools_returns_tool_definitions() {
        let tools_response = {
            let result = ToolsListResult {
                tools: vec![
                    ToolDefinition {
                        name: "weather_lookup".to_owned(),
                        description: Some("Look up weather".to_owned()),
                        input_schema: serde_json::json!({"type": "object"}),
                    },
                    ToolDefinition {
                        name: "calendar_check".to_owned(),
                        description: None,
                        input_schema: serde_json::json!({"type": "object"}),
                    },
                ],
                next_cursor: None,
            };
            JsonRpcResponse::success(RequestId::Number(2), serde_json::to_value(&result).unwrap())
        };

        let client = initialized_client(vec![tools_response]);
        let tools = client.list_tools().unwrap();

        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "weather_lookup");
        assert_eq!(tools[0].description.as_deref(), Some("Look up weather"));
        assert_eq!(tools[1].name, "calendar_check");
    }

    #[test]
    fn list_tools_sends_correct_method() {
        let tools_response = {
            let result = ToolsListResult {
                tools: vec![],
                next_cursor: None,
            };
            JsonRpcResponse::success(RequestId::Number(2), serde_json::to_value(&result).unwrap())
        };

        let client = initialized_client(vec![tools_response]);
        client.list_tools().unwrap();

        let requests = client.transport.sent_requests();
        // First request is initialize, second is tools/list.
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].method, "tools/list");
    }

    #[test]
    fn list_tools_handles_empty_list() {
        let tools_response = {
            let result = ToolsListResult {
                tools: vec![],
                next_cursor: None,
            };
            JsonRpcResponse::success(RequestId::Number(2), serde_json::to_value(&result).unwrap())
        };

        let client = initialized_client(vec![tools_response]);
        let tools = client.list_tools().unwrap();
        assert!(tools.is_empty());
    }

    // -----------------------------------------------------------------------
    // invoke tests
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_requires_initialization() {
        let transport = MockTransport::new(vec![]);
        let client = McpClient::with_clock(transport, FixedClock(0));

        let result = client.invoke(
            "some_tool",
            serde_json::json!({}),
            "ctx-1",
            "did:dht:z6MkAlice",
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            McpClientError::NotInitialized
        ));
    }

    #[test]
    fn invoke_wraps_result_with_provenance() {
        let call_response = {
            let result = ToolsCallResult {
                content: vec![ContentItem::Text {
                    text: "Sunny, 72F".to_owned(),
                }],
                is_error: false,
            };
            JsonRpcResponse::success(RequestId::Number(2), serde_json::to_value(&result).unwrap())
        };

        let client = initialized_client(vec![call_response]);
        let result = client
            .invoke(
                "weather_lookup",
                serde_json::json!({"city": "San Francisco"}),
                "ctx-cooking",
                "did:dht:z6MkAlice",
            )
            .unwrap();

        // Verify content is passed through.
        assert_eq!(result.content.len(), 1);
        match &result.content[0] {
            ContentItem::Text { text } => assert_eq!(text, "Sunny, 72F"),
            other => panic!("expected Text, got {other:?}"),
        }
        assert!(!result.is_error);

        // Verify provenance is attached.
        assert_eq!(result.provenance.source, "mcp:weather_lookup");
        assert_eq!(result.provenance.invoked_by, "did:dht:z6MkAlice");
        assert_eq!(result.provenance.context, "ctx-cooking");
        assert_eq!(result.provenance.timestamp, 1_700_000_000_000);
    }

    #[test]
    fn invoke_sends_correct_tools_call_params() {
        let call_response = {
            let result = ToolsCallResult {
                content: vec![ContentItem::Text {
                    text: "ok".to_owned(),
                }],
                is_error: false,
            };
            JsonRpcResponse::success(RequestId::Number(2), serde_json::to_value(&result).unwrap())
        };

        let client = initialized_client(vec![call_response]);
        client
            .invoke(
                "my_tool",
                serde_json::json!({"key": "value"}),
                "ctx-1",
                "did:dht:z6MkTest",
            )
            .unwrap();

        let requests = client.transport.sent_requests();
        // First request is initialize, second is tools/call.
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].method, "tools/call");

        let params = requests[1].params.as_ref().unwrap();
        assert_eq!(params["name"], "my_tool");
        assert_eq!(params["arguments"]["key"], "value");
    }

    #[test]
    fn invoke_preserves_error_flag() {
        let call_response = {
            let result = ToolsCallResult {
                content: vec![ContentItem::Text {
                    text: "tool failed".to_owned(),
                }],
                is_error: true,
            };
            JsonRpcResponse::success(RequestId::Number(2), serde_json::to_value(&result).unwrap())
        };

        let client = initialized_client(vec![call_response]);
        let result = client
            .invoke(
                "flaky_tool",
                serde_json::json!({}),
                "ctx-1",
                "did:dht:z6MkAlice",
            )
            .unwrap();

        assert!(result.is_error);
        // Provenance is still attached even for error results.
        assert_eq!(result.provenance.source, "mcp:flaky_tool");
    }

    #[test]
    fn invoke_handles_server_error_response() {
        let error_response = JsonRpcResponse::error(
            RequestId::Number(2),
            JsonRpcError {
                code: protocol::TOOL_NOT_FOUND,
                message: "tool not found: nonexistent".to_owned(),
                data: None,
            },
        );

        let client = initialized_client(vec![error_response]);
        let result = client.invoke(
            "nonexistent",
            serde_json::json!({}),
            "ctx-1",
            "did:dht:z6MkAlice",
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            McpClientError::ServerError { code, message } => {
                assert_eq!(code, protocol::TOOL_NOT_FOUND);
                assert!(message.contains("nonexistent"));
            }
            other => panic!("expected ServerError, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // McpToolResult tests
    // -----------------------------------------------------------------------

    #[test]
    fn mcp_tool_result_serialization_roundtrip() {
        let result = McpToolResult {
            content: vec![ContentItem::Text {
                text: "hello".to_owned(),
            }],
            is_error: false,
            provenance: ExternalToolProvenance::new("test_tool", "did:dht:z6MkSer", "ctx-ser", 999),
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: McpToolResult = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.content.len(), 1);
        assert!(!parsed.is_error);
        assert_eq!(parsed.provenance.source, "mcp:test_tool");
        assert_eq!(parsed.provenance.invoked_by, "did:dht:z6MkSer");
        assert_eq!(parsed.provenance.context, "ctx-ser");
        assert_eq!(parsed.provenance.timestamp, 999);
    }

    #[test]
    fn mcp_tool_result_provenance_is_included_in_json() {
        let result = McpToolResult {
            content: vec![],
            is_error: false,
            provenance: ExternalToolProvenance::new("ext", "did:dht:z6MkX", "ctx-y", 123),
        };

        let json = serde_json::to_value(&result).unwrap();
        assert!(json["provenance"].is_object());
        assert_eq!(json["provenance"]["source"], "mcp:ext");
        assert_eq!(json["provenance"]["invoked_by"], "did:dht:z6MkX");
        assert_eq!(json["provenance"]["context"], "ctx-y");
        assert_eq!(json["provenance"]["timestamp"], 123);
    }

    // -----------------------------------------------------------------------
    // TransportConfig tests
    // -----------------------------------------------------------------------

    #[test]
    fn transport_config_stdio_holds_fields() {
        let config = TransportConfig::Stdio {
            command: "uvx".to_owned(),
            args: vec!["some-mcp-server".to_owned()],
        };
        match config {
            TransportConfig::Stdio { command, args } => {
                assert_eq!(command, "uvx");
                assert_eq!(args, vec!["some-mcp-server"]);
            }
            TransportConfig::Sse { .. } => panic!("expected Stdio variant"),
        }
    }

    #[test]
    fn transport_config_sse_holds_url() {
        let config = TransportConfig::Sse {
            url: "http://localhost:3001/sse".to_owned(),
        };
        match config {
            TransportConfig::Sse { url } => {
                assert_eq!(url, "http://localhost:3001/sse");
            }
            TransportConfig::Stdio { .. } => panic!("expected Sse variant"),
        }
    }

    // -----------------------------------------------------------------------
    // McpClientError tests
    // -----------------------------------------------------------------------

    #[test]
    fn error_not_initialized_display() {
        let err = McpClientError::NotInitialized;
        assert_eq!(
            err.to_string(),
            "client not initialized: call initialize() first"
        );
    }

    #[test]
    fn error_transport_display() {
        let err = McpClientError::Transport("connection refused".to_owned());
        assert_eq!(err.to_string(), "transport error: connection refused");
    }

    #[test]
    fn error_server_error_display() {
        let err = McpClientError::ServerError {
            code: -32601,
            message: "method not found".to_owned(),
        };
        assert_eq!(err.to_string(), "server error -32601: method not found");
    }

    #[test]
    fn error_invalid_response_display() {
        let err = McpClientError::InvalidResponse("missing result".to_owned());
        assert_eq!(err.to_string(), "invalid response: missing result");
    }

    // -----------------------------------------------------------------------
    // Request ID allocation
    // -----------------------------------------------------------------------

    #[test]
    fn request_ids_are_monotonically_increasing() {
        let tools_response_1 = {
            let result = ToolsListResult {
                tools: vec![],
                next_cursor: None,
            };
            JsonRpcResponse::success(RequestId::Number(2), serde_json::to_value(&result).unwrap())
        };
        let tools_response_2 = {
            let result = ToolsListResult {
                tools: vec![],
                next_cursor: None,
            };
            JsonRpcResponse::success(RequestId::Number(3), serde_json::to_value(&result).unwrap())
        };

        let client = initialized_client(vec![tools_response_1, tools_response_2]);
        client.list_tools().unwrap();
        client.list_tools().unwrap();

        let requests = client.transport.sent_requests();
        // IDs: 1 (initialize), 2 (first list_tools), 3 (second list_tools).
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].id, RequestId::Number(1));
        assert_eq!(requests[1].id, RequestId::Number(2));
        assert_eq!(requests[2].id, RequestId::Number(3));
    }
}
