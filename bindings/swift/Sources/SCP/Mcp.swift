import Foundation

// MARK: - McpToolDefinition

/// An MCP tool definition as reported by an external MCP server.
///
/// Represents a tool available through the Model Context Protocol. When
/// consumed via SCP, tool results are wrapped with provenance metadata
/// recording the external source, invoking agent, and context.
///
/// See ADR-015 in `.docs/adrs/phase-3.md`.
public nonisolated struct McpToolDefinition: Sendable {
    /// The tool name.
    public let name: String

    /// A human-readable description of what the tool does, if available.
    public let description: String?

    /// The JSON Schema describing the tool's input shape (as a JSON string).
    public let inputSchema: String

    /// Memberwise initializer.
    public init(name: String, description: String?, inputSchema: String) {
        self.name = name
        self.description = description
        self.inputSchema = inputSchema
    }
}

// MARK: - McpToolResult

/// The result of invoking an external MCP tool, wrapped with SCP provenance.
///
/// Maintains the protocol's provenance-everywhere principle: even tool calls
/// to external (non-SCP) MCP servers carry verifiable origin metadata.
///
/// See ADR-015 in `.docs/adrs/phase-3.md`.
public nonisolated struct McpToolResult: Sendable {
    /// The tool output content as serialized JSON.
    public let content: Data

    /// Whether the tool call resulted in an error.
    public let isError: Bool

    /// The source of the tool result, formatted as `"mcp:{tool_name}"`.
    public let source: String

    /// The DID of the agent that invoked the tool.
    public let invokedBy: String

    /// The SCP context ID in which the invocation was made.
    public let contextId: String

    /// The timestamp of the invocation (milliseconds since Unix epoch).
    public let timestamp: UInt64

    /// Memberwise initializer.
    public init(
        content: Data,
        isError: Bool,
        source: String,
        invokedBy: String,
        contextId: String,
        timestamp: UInt64
    ) {
        self.content = content
        self.isError = isError
        self.source = source
        self.invokedBy = invokedBy
        self.contextId = contextId
        self.timestamp = timestamp
    }
}

// MARK: - McpServerConfig

/// Configuration for serving SCP context tools via MCP.
///
/// Configures how the MCP server exposes SCP tools to MCP-compatible AI models.
/// The server handles tool listing with capability filtering, tool invocation
/// routing, and MCP lifecycle management.
public nonisolated struct McpServerConfig: Sendable {
    /// The context IDs whose tools should be exposed via MCP.
    public let contextIds: [String]

    /// The transport type for the MCP server.
    public let transport: McpTransportType

    /// Memberwise initializer.
    public init(contextIds: [String], transport: McpTransportType) {
        self.contextIds = contextIds
        self.transport = transport
    }
}

// MARK: - McpTransportType

/// The transport mechanism for MCP communication.
///
/// MCP supports two transport modes: stdio (subprocess communication) and
/// SSE (HTTP Server-Sent Events).
public nonisolated enum McpTransportType: Sendable {
    /// Communicate via standard input/output (stdio).
    ///
    /// The MCP server reads JSON-RPC requests from stdin and writes responses
    /// to stdout. Used when the model spawns the server as a subprocess.
    case stdio

    /// Communicate via HTTP with Server-Sent Events (SSE).
    ///
    /// The MCP server listens on the specified port. Server-to-client messages
    /// use SSE; client-to-server messages use HTTP POST.
    ///
    /// - Parameter port: The port to listen on.
    case sse(port: UInt16)
}

// MARK: - McpClientConfig

/// Configuration for connecting to an external MCP server.
///
/// Specifies how to connect to an external (non-SCP) MCP server. Tool results
/// from external servers are wrapped with SCP provenance metadata.
public nonisolated enum McpClientConfig: Sendable {
    /// Connect via stdio: spawn a subprocess and communicate over stdin/stdout.
    ///
    /// - Parameters:
    ///   - command: The command to execute (e.g., `"uvx"`).
    ///   - args: Arguments to pass to the command.
    case stdio(command: String, args: [String])

    /// Connect via SSE: HTTP client with Server-Sent Events.
    ///
    /// - Parameter url: The URL of the SSE endpoint.
    case sse(url: String)
}

// MARK: - UniFFI Bridge Stubs

/// Start an MCP server via the UniFFI bridge.
///
/// Placeholder stub for the UniFFI-generated `mcp_serve` function.
///
/// - Parameters:
///   - config: The MCP server configuration.
///   - completion: Callback delivering success or an error.
internal func scpMcpServe(
    config: McpServerConfig,
    completion: @Sendable @escaping (Result<Void, ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.Tool(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-MCP-001"
    )))
}

/// Create an MCP client via the UniFFI bridge.
///
/// Placeholder stub for the UniFFI-generated `mcp_client_create` function.
///
/// - Parameters:
///   - config: The MCP client configuration.
///   - completion: Callback delivering the client handle or an error.
internal func scpMcpClientCreate(
    config: McpClientConfig,
    completion: @Sendable @escaping (Result<McpClientHandle, ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.Tool(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-MCP-002"
    )))
}

/// List tools from an MCP client via the UniFFI bridge.
///
/// Placeholder stub for the UniFFI-generated `mcp_client_list_tools` function.
///
/// - Parameters:
///   - handle: The MCP client handle.
///   - completion: Callback delivering the tool definitions or an error.
internal func scpMcpClientListTools(
    handle: McpClientHandle,
    completion: @Sendable @escaping (Result<[McpToolDefinition], ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.Tool(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-MCP-003"
    )))
}

/// Invoke a tool via an MCP client via the UniFFI bridge.
///
/// Placeholder stub for the UniFFI-generated `mcp_client_invoke` function.
///
/// - Parameters:
///   - handle: The MCP client handle.
///   - toolName: The name of the tool to invoke.
///   - input: The tool input as serialized JSON.
///   - contextId: The SCP context ID for provenance.
///   - invokerDid: The DID of the invoking agent for provenance.
///   - completion: Callback delivering the result or an error.
internal func scpMcpClientInvoke(
    handle: McpClientHandle,
    toolName: String,
    input: Data,
    contextId: String,
    invokerDid: String,
    completion: @Sendable @escaping (Result<McpToolResult, ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.Tool(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-MCP-004"
    )))
}

// MARK: - McpClientHandle

/// Internal opaque handle wrapping the UniFFI-generated MCP client binding.
///
/// This placeholder mirrors the handle type that UniFFI will generate from
/// the Rust `McpClient` struct. When the XCFramework build pipeline ships
/// (SCP-103), this definition is replaced by the auto-generated type.
internal final class McpClientHandle: Sendable {
    /// Whether the MCP handshake has completed.
    let initialized: Bool

    /// Creates an ``McpClientHandle``.
    init(initialized: Bool = false) {
        self.initialized = initialized
    }
}

// MARK: - serveMcp

/// Starts an MCP server that exposes SCP context tools to MCP-compatible models.
///
/// Any MCP-compatible model (Claude, GPT, Gemini, open-source models) can
/// participate in SCP contexts through this server without knowing SCP exists.
/// The model sees MCP tools namespaced by context, calls them, and gets results.
///
/// The server handles:
/// - Tool listing (`tools/list`) with capability filtering
/// - Tool invocation (`tools/call`) with UCAN validation and provenance
/// - Resource listing and reading
/// - MCP lifecycle (`initialize`, `ping`)
///
/// This function bridges the asynchronous UniFFI `mcp_serve` call to
/// Swift concurrency via `CheckedContinuation`.
///
/// - Parameter config: The ``McpServerConfig`` specifying which contexts
///   to expose and the transport type.
/// - Throws: ``ScpError/tool(message:code:)`` if the server fails to start.
///
/// ## Provenance
///
/// - ADR-015 (MCP) in `.docs/adrs/phase-3.md`
/// - ADR-026 (Swift SDK) in `.docs/adrs/phase-5.md`
/// - Story SCP-101
public func serveMcp(config: McpServerConfig) async throws {
    try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<Void, Error>) in
        scpMcpServe(config: config) { result in
            switch result {
            case .success:
                continuation.resume()
            case .failure(let error):
                continuation.resume(throwing: error)
            }
        }
    }
}

// MARK: - McpClient

/// An MCP client for consuming external tools with SCP provenance.
///
/// Connects to an external MCP server (non-SCP) and wraps tool results with
/// SCP provenance metadata. This maintains SCP's provenance-everywhere
/// principle even for external tool calls.
///
/// ## Usage
///
/// ```swift
/// let client = try await McpClient.connect(config: .stdio(
///     command: "uvx",
///     args: ["some-mcp-server"]
/// ))
/// let tools = try await client.listTools()
/// let result = try await client.invoke(
///     tool: "weather_lookup",
///     input: jsonData,
///     contextId: "ctx-123",
///     invokerDid: "did:dht:z6Mk..."
/// )
/// ```
///
/// ## Provenance
///
/// - ADR-015 (MCP) in `.docs/adrs/phase-3.md`
/// - ADR-026 (Swift SDK) in `.docs/adrs/phase-5.md`
/// - Story SCP-101
public actor McpClient {
    /// The internal handle wrapping the native UniFFI MCP client.
    private let handle: McpClientHandle

    // MARK: - Internal Initializer

    /// Creates an ``McpClient`` from an internal ``McpClientHandle``.
    ///
    /// This initializer is internal -- callers use ``connect(config:)`` to
    /// obtain an ``McpClient``.
    ///
    /// - Parameter handle: The opaque MCP client handle from the UniFFI bridge.
    internal init(handle: McpClientHandle) {
        self.handle = handle
    }

    // MARK: - Factory

    /// Connects to an external MCP server and completes the MCP handshake.
    ///
    /// Establishes a connection using the specified transport (stdio or SSE)
    /// and performs the MCP `initialize` / `initialized` handshake.
    ///
    /// - Parameter config: The ``McpClientConfig`` specifying the connection
    ///   transport.
    /// - Returns: A connected ``McpClient`` ready to list and invoke tools.
    /// - Throws: ``ScpError/tool(message:code:)`` if the connection or
    ///   handshake fails.
    public static func connect(config: McpClientConfig) async throws -> McpClient {
        let handle = try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<McpClientHandle, Error>) in
            scpMcpClientCreate(config: config) { result in
                switch result {
                case .success(let clientHandle):
                    continuation.resume(returning: clientHandle)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
        return McpClient(handle: handle)
    }

    // MARK: - Tool Listing

    /// Lists available tools from the external MCP server.
    ///
    /// Sends a `tools/list` JSON-RPC request and returns the tool definitions.
    ///
    /// - Returns: An array of ``McpToolDefinition`` values describing available
    ///   tools.
    /// - Throws: ``ScpError/tool(message:code:)`` if the listing fails.
    public func listTools() async throws -> [McpToolDefinition] {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<[McpToolDefinition], Error>) in
            scpMcpClientListTools(handle: handle) { result in
                switch result {
                case .success(let tools):
                    continuation.resume(returning: tools)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    // MARK: - Tool Invocation

    /// Invokes an external tool and wraps the result with SCP provenance.
    ///
    /// Sends a `tools/call` JSON-RPC request to the external MCP server, then
    /// wraps the result with provenance metadata recording the external tool
    /// source, the invoking agent's DID, the SCP context, and the timestamp.
    ///
    /// - Parameters:
    ///   - tool: The name of the external tool to invoke.
    ///   - input: The tool's input as serialized JSON data.
    ///   - contextId: The SCP context ID for provenance tracking.
    ///   - invokerDid: The DID of the agent invoking the tool.
    /// - Returns: An ``McpToolResult`` containing the output and provenance.
    /// - Throws: ``ScpError/tool(message:code:)`` if invocation fails.
    public func invoke(
        tool: String,
        input: Data,
        contextId: String,
        invokerDid: String
    ) async throws -> McpToolResult {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<McpToolResult, Error>) in
            scpMcpClientInvoke(
                handle: handle,
                toolName: tool,
                input: input,
                contextId: contextId,
                invokerDid: invokerDid
            ) { result in
                switch result {
                case .success(let toolResult):
                    continuation.resume(returning: toolResult)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}
