import Foundation

// MARK: - McpToolDefinition

/// An MCP tool definition as reported by an MCP server.
///
/// Represents a tool available through the Model Context Protocol. When
/// consumed via SCP, tool results are wrapped with provenance metadata
/// recording the tool name as `mcp:{tool_name}`, the invoking agent, the
/// context, and the time. The provenance does not name the MCP server the
/// tool came from.
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

/// The result of invoking an MCP tool, wrapped with SCP provenance.
///
/// Follows the protocol's provenance-everywhere principle: a tool call to
/// any MCP server, an SCP SSE server or another, carries origin metadata that
/// the client records locally and does not sign. That metadata names the tool
/// but not the server, so two servers exposing the same tool name produce the
/// same `source`.
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

// MARK: - McpClientConfig

/// Configuration for connecting to an MCP server.
///
/// Specifies how to connect to an MCP server, an SCP SSE server or
/// another. Tool results are wrapped with SCP provenance metadata.
public nonisolated enum McpClientConfig: Sendable {
    /// Connect via stdio: spawn a subprocess and communicate over stdin/stdout.
    ///
    /// - Parameters:
    ///   - command: The command to execute (e.g., `"uvx"`).
    ///   - args: Arguments to pass to the command.
    case stdio(command: String, args: [String])

    /// Connect via SSE: HTTP client with Server-Sent Events.
    ///
    /// - Parameters:
    ///   - url: The URL of the SSE endpoint.
    ///   - authToken: The bearer token sent in an `Authorization` header on
    ///     every request, or `nil` for a server that runs no bearer check. An
    ///     SCP SSE server always runs one (ADR-015). The transport has no
    ///     TLS, so a token is sent only to a loopback host.
    case sse(url: String, authToken: String?)
}

// MARK: - McpClient

/// An MCP client that calls an MCP server's tools and records SCP provenance.
///
/// Connects to an MCP server, an SCP SSE server or another, via an
/// ``SCP`` instance and wraps tool results with SCP provenance metadata. This
/// maintains SCP's provenance-everywhere principle for every tool call.
///
/// ## Usage
///
/// ```swift
/// let scp = try SCP(storage: .inMemory)
/// let client = try await McpClient.connect(
///     scp: scp,
///     config: .stdio(command: "uvx", args: ["some-mcp-server"])
/// )
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
    /// The owning ``SCP`` instance — all UniFFI calls route through it.
    private let scp: SCP

    /// Opaque handle string returned by `mcpClientConnectStdio` /
    /// `mcpClientConnectSse`.
    private let handle: String

    /// Internal constructor used by the `connect` factory.
    init(scp: SCP, handle: String) {
        self.scp = scp
        self.handle = handle
    }

    // MARK: - Factory

    /// Connects to an MCP server, an SCP SSE server or another, and completes the MCP handshake.
    ///
    /// - Parameters:
    ///   - scp: The owning ``SCP`` instance whose MCP client registry
    ///     stores the connection.
    ///   - config: The ``McpClientConfig`` specifying the connection transport.
    /// - Returns: A connected ``McpClient`` ready to list and invoke tools.
    /// - Throws: ``ScpError/Outlet(msg:code:)`` if the connection or
    ///   handshake fails.
    public static func connect(
        scp: SCP,
        config: McpClientConfig
    ) async throws -> McpClient {
        switch config {
        case let .stdio(command, args):
            let handle = try await scp.mcpClientConnectStdio(command: [command] + args)
            return McpClient(scp: scp, handle: handle)
        case let .sse(url, authToken):
            let handle = try await scp.mcpClientConnectSse(url: url, authToken: authToken)
            return McpClient(scp: scp, handle: handle)
        }
    }

    // MARK: - Tool Listing

    /// Lists available tools from the connected MCP server.
    ///
    /// Sends a `tools/list` JSON-RPC request and returns the tool definitions.
    ///
    /// - Returns: An array of ``McpToolDefinition`` values describing available
    ///   tools.
    /// - Throws: ``ScpError/Outlet(msg:code:)`` if the listing fails.
    public func listTools() async throws -> [McpToolDefinition] {
        let tools = try await scp.mcpClientListTools(handle: handle)
        return tools.map { info in
            McpToolDefinition(
                name: info.name,
                description: info.description,
                inputSchema: info.inputSchemaJson
            )
        }
    }

    // MARK: - Tool Invocation

    /// Invokes a tool on the connected MCP server and wraps the result with SCP provenance.
    ///
    /// Sends a `tools/call` JSON-RPC request to the connected MCP server, then
    /// wraps the result with provenance metadata recording the tool
    /// source, the invoking agent's DID, the SCP context, and the timestamp.
    ///
    /// - Parameters:
    ///   - tool: The name of the tool to invoke.
    ///   - input: The tool's input as serialized JSON data.
    ///   - contextId: The SCP context ID for provenance tracking.
    ///   - invokerDid: The DID of the agent invoking the tool.
    /// - Returns: An ``McpToolResult`` containing the output and provenance.
    /// - Throws: ``ScpError/Outlet(msg:code:)`` if invocation fails.
    public func invoke(
        tool: String,
        input: Data,
        contextId: String,
        invokerDid: String
    ) async throws -> McpToolResult {
        let inputString = String(data: input, encoding: .utf8) ?? ""
        let result = try await scp.mcpClientInvoke(
            handle: handle,
            outletName: tool,
            inputJson: inputString,
            contextId: contextId,
            invokerDid: invokerDid
        )
        return McpToolResult(
            content: result.contentJson.data(using: .utf8) ?? Data(),
            isError: result.isError,
            source: result.source,
            invokedBy: result.invokedBy,
            contextId: result.contextId,
            timestamp: result.timestamp
        )
    }

    /// Disconnects from the MCP server and drops the bridge handle.
    public func disconnect() async throws {
        try await scp.mcpClientDisconnect(handle: handle)
    }
}
