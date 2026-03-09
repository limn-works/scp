import Foundation
@testable import SCP
import Testing

// MARK: - MCP Tests

/// Tests for MCP (Model Context Protocol) server and client operations:
/// serveMcp, McpClient connect, list tools, and invoke.
///
/// MCP operations do not yet have UniFFI bridge exports. The injectable
/// bridge pattern provides testable stubs with descriptive error messages
/// that will be replaced when the MCP Rust exports land.
///
/// Async roundtrip tests inject mock bridge functions to verify the delegation
/// pattern works end-to-end.
///
/// See ADR-015 (MCP), ADR-026 (Swift SDK), and story SCP-221.
struct McpTests {
    // MARK: - McpServerConfig type shape

    @Test("McpServerConfig stores context IDs and transport")
    func serverConfigFields() {
        let config = McpServerConfig(
            contextIds: ["ctx-1", "ctx-2"],
            transport: .stdio
        )
        #expect(config.contextIds.count == 2)
        #expect(config.contextIds[0] == "ctx-1")
    }

    @Test("McpServerConfig with SSE transport stores port")
    func serverConfigSseTransport() {
        let config = McpServerConfig(
            contextIds: ["ctx-1"],
            transport: .sse(port: 8080)
        )
        if case let .sse(port) = config.transport {
            #expect(port == 8080)
        } else {
            Issue.record("Expected SSE transport")
        }
    }

    @Test("McpServerConfig is Sendable")
    func serverConfigIsSendable() {
        let config: any Sendable = McpServerConfig(
            contextIds: ["ctx"],
            transport: .stdio
        )
        #expect(config is McpServerConfig)
    }

    // MARK: - McpTransportType type shape

    @Test("McpTransportType stdio variant")
    func transportTypeStdio() {
        let transport = McpTransportType.stdio
        if case .stdio = transport {
            // Matches expected variant
        } else {
            Issue.record("Expected stdio transport type")
        }
    }

    @Test("McpTransportType sse variant with port")
    func transportTypeSse() {
        let transport = McpTransportType.sse(port: 3000)
        if case let .sse(port) = transport {
            #expect(port == 3000)
        } else {
            Issue.record("Expected sse transport type")
        }
    }

    // MARK: - McpClientConfig type shape

    @Test("McpClientConfig stdio variant stores command and args")
    func clientConfigStdio() {
        let config = McpClientConfig.stdio(
            command: "uvx",
            args: ["some-mcp-server", "--port", "3000"]
        )
        if case let .stdio(command, args) = config {
            #expect(command == "uvx")
            #expect(args.count == 3)
            #expect(args[0] == "some-mcp-server")
        } else {
            Issue.record("Expected stdio client config")
        }
    }

    @Test("McpClientConfig sse variant stores URL")
    func clientConfigSse() {
        let config = McpClientConfig.sse(url: "http://localhost:8080/sse")
        if case let .sse(url) = config {
            #expect(url == "http://localhost:8080/sse")
        } else {
            Issue.record("Expected sse client config")
        }
    }

    @Test("McpClientConfig is Sendable")
    func clientConfigIsSendable() {
        let config: any Sendable = McpClientConfig.stdio(command: "test", args: [])
        #expect(config is McpClientConfig)
    }

    // MARK: - McpToolDefinition type shape

    @Test("McpToolDefinition stores name, description, and input schema")
    func toolDefinitionFields() {
        let def = McpToolDefinition(
            name: "weather_lookup",
            description: "Fetches current weather",
            inputSchema: #"{"type": "object", "properties": {"city": {"type": "string"}}}"#
        )
        #expect(def.name == "weather_lookup")
        #expect(def.description == "Fetches current weather")
        #expect(def.inputSchema.contains("city"))
    }

    @Test("McpToolDefinition with nil description")
    func toolDefinitionNilDescription() {
        let def = McpToolDefinition(
            name: "no-desc-tool",
            description: nil,
            inputSchema: "{}"
        )
        #expect(def.description == nil)
    }

    // MARK: - McpToolResult type shape

    @Test("McpToolResult stores all provenance fields")
    func toolResultFields() {
        let result = McpToolResult(
            content: Data(#"{"temperature": 72}"#.utf8),
            isError: false,
            source: "mcp:weather_lookup",
            invokedBy: "did:dht:z6MkAgent",
            contextId: "ctx-mcp-001",
            timestamp: 1_700_000_000
        )
        #expect(!result.isError)
        #expect(result.source == "mcp:weather_lookup")
        #expect(result.invokedBy == "did:dht:z6MkAgent")
        #expect(result.contextId == "ctx-mcp-001")
        #expect(result.timestamp == 1_700_000_000)
    }

    @Test("McpToolResult error case")
    func toolResultError() {
        let result = McpToolResult(
            content: Data(#"{"error": "not found"}"#.utf8),
            isError: true,
            source: "mcp:missing_tool",
            invokedBy: "did:dht:z6MkAgent",
            contextId: "ctx-mcp-001",
            timestamp: 1_700_000_000
        )
        #expect(result.isError)
    }

    // MARK: - serveMcp via injectable bridge (async roundtrip)

    @Test("serveMcp calls bridge function")
    func serveMcpRoundtrip() async throws {
        var served = false
        var receivedContextIds: [String]?

        let mockServe: McpBridge.ServeFn = { config in
            served = true
            receivedContextIds = config.contextIds
        }

        let config = McpServerConfig(
            contextIds: ["ctx-1", "ctx-2"],
            transport: .stdio
        )
        try await serveMcp(config: config, serveFn: mockServe)

        #expect(served)
        #expect(receivedContextIds == ["ctx-1", "ctx-2"])
    }

    @Test("serveMcp default throws awaiting UniFFI export")
    func serveMcpDefaultThrows() async {
        let config = McpServerConfig(contextIds: ["ctx-1"], transport: .stdio)
        do {
            try await serveMcp(config: config)
            Issue.record("Expected serveMcp to throw")
        } catch let error as ScpError {
            if case let .Tool(_, code) = error {
                #expect(code == "SCP-MCP-10001")
            } else {
                Issue.record("Expected ScpError.Tool, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - McpClient connect via injectable bridge (async roundtrip)

    @Test("McpClient.connect calls bridge and returns client")
    func mcpClientConnectRoundtrip() async throws {
        let mockCreate: McpBridge.ClientCreateFn = { config in
            if case let .stdio(command, _) = config {
                #expect(command == "uvx")
            }
            return McpClientHandle(initialized: true)
        }

        let client = try await McpClient.connect(
            config: .stdio(command: "uvx", args: ["test-server"]),
            createFn: mockCreate
        )
        #expect(client is McpClient)
    }

    @Test("McpClient.connect default throws awaiting UniFFI export")
    func mcpClientConnectDefaultThrows() async {
        do {
            _ = try await McpClient.connect(config: .stdio(command: "uvx", args: []))
            Issue.record("Expected McpClient.connect to throw")
        } catch let error as ScpError {
            if case let .Tool(_, code) = error {
                #expect(code == "SCP-MCP-10002")
            } else {
                Issue.record("Expected ScpError.Tool, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - McpClient listTools via injectable bridge (async roundtrip)

    @Test("McpClient.listTools calls bridge and returns tools")
    func mcpClientListToolsRoundtrip() async throws {
        let mockTools = [
            McpToolDefinition(name: "weather", description: "Get weather", inputSchema: "{}"),
            McpToolDefinition(name: "search", description: nil, inputSchema: "{}"),
        ]

        let mockListTools: McpBridge.ClientListToolsFn = { _ in
            mockTools
        }

        let client = McpClient(
            handle: McpClientHandle(initialized: true),
            listToolsFn: mockListTools
        )
        let tools = try await client.listTools()

        #expect(tools.count == 2)
        #expect(tools[0].name == "weather")
        #expect(tools[1].name == "search")
    }

    // MARK: - McpClient invoke via injectable bridge (async roundtrip)

    @Test("McpClient.invoke calls bridge and returns result")
    func mcpClientInvokeRoundtrip() async throws {
        let mockResult = McpToolResult(
            content: Data(#"{"temperature": 72}"#.utf8),
            isError: false,
            source: "mcp:weather",
            invokedBy: "did:dht:z6MkAgent",
            contextId: "ctx-test",
            timestamp: 1_700_000_000
        )

        let mockInvoke: McpBridge.ClientInvokeFn = { _, toolName, _, contextId, invokerDid in
            #expect(toolName == "weather")
            #expect(contextId == "ctx-test")
            #expect(invokerDid == "did:dht:z6MkAgent")
            return mockResult
        }

        let client = McpClient(
            handle: McpClientHandle(initialized: true),
            invokeFn: mockInvoke
        )
        let result = try await client.invoke(
            tool: "weather",
            input: Data("{}".utf8),
            contextId: "ctx-test",
            invokerDid: "did:dht:z6MkAgent"
        )

        #expect(!result.isError)
        #expect(result.source == "mcp:weather")
    }

    // MARK: - McpClientHandle type shape

    @Test("McpClientHandle tracks initialization state")
    func mcpClientHandleInit() {
        let uninit = McpClientHandle(initialized: false)
        let init_ = McpClientHandle(initialized: true)
        #expect(!uninit.initialized)
        #expect(init_.initialized)
    }
} // end McpTests
