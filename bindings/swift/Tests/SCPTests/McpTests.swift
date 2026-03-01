import Foundation
import Testing

@testable import SCP

// MARK: - MCP Tests

/// Tests for MCP (Model Context Protocol) server and client operations:
/// serveMcp, McpClient connect, list tools, and invoke.
///
/// These tests validate the Swift ergonomics layer and type shapes for MCP
/// integration. The UniFFI bridge stubs return placeholder errors until
/// SCP-103 ships.
///
/// See ADR-015 (MCP), ADR-026 (Swift SDK), and story SCP-102.
@Suite("MCP Tests")
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
        if case .sse(let port) = config.transport {
            #expect(port == 8080)
        } else {
            Issue.record("Expected SSE transport")
        }
    }

    @Test("McpServerConfig is Sendable")
    func serverConfigIsSendable() async {
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
        if case .sse(let port) = transport {
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
        if case .stdio(let command, let args) = config {
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
        if case .sse(let url) = config {
            #expect(url == "http://localhost:8080/sse")
        } else {
            Issue.record("Expected sse client config")
        }
    }

    @Test("McpClientConfig is Sendable")
    func clientConfigIsSendable() async {
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

    // MARK: - serveMcp (bridge stub error propagation)

    @Test("serveMcp throws bridge error with SCP-MCP-10001")
    func serveMcpThrowsBridgeError() async {
        let config = McpServerConfig(
            contextIds: ["ctx-1"],
            transport: .stdio
        )
        do {
            try await serveMcp(config: config)
            Issue.record("Expected serveMcp to throw")
        } catch let error as ScpError {
            if case .Tool(_, let code) = error {
                #expect(code == "SCP-MCP-10001")
            } else {
                Issue.record("Expected ScpError.Tool, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("serveMcp with SSE transport throws bridge error")
    func serveMcpSseThrowsBridgeError() async {
        let config = McpServerConfig(
            contextIds: ["ctx-sse"],
            transport: .sse(port: 9090)
        )
        do {
            try await serveMcp(config: config)
            Issue.record("Expected serveMcp to throw")
        } catch let error as ScpError {
            if case .Tool(_, let code) = error {
                #expect(code == "SCP-MCP-10001")
            } else {
                Issue.record("Expected ScpError.Tool, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - McpClient connect (bridge stub error propagation)

    @Test("McpClient.connect throws bridge error with SCP-MCP-10002")
    func mcpClientConnectThrowsBridgeError() async {
        do {
            _ = try await McpClient.connect(config: .stdio(
                command: "uvx",
                args: ["test-server"]
            ))
            Issue.record("Expected McpClient.connect to throw")
        } catch let error as ScpError {
            if case .Tool(_, let code) = error {
                #expect(code == "SCP-MCP-10002")
            } else {
                Issue.record("Expected ScpError.Tool, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("McpClient.connect with SSE throws bridge error")
    func mcpClientConnectSseThrowsBridgeError() async {
        do {
            _ = try await McpClient.connect(config: .sse(
                url: "http://localhost:8080/sse"
            ))
            Issue.record("Expected McpClient.connect to throw")
        } catch let error as ScpError {
            if case .Tool(_, let code) = error {
                #expect(code == "SCP-MCP-10002")
            } else {
                Issue.record("Expected ScpError.Tool, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - McpClient listTools (bridge stub error propagation)

    @Test("McpClient.listTools throws bridge error with SCP-MCP-10003")
    func mcpClientListToolsThrowsBridgeError() async {
        // Create a client directly from a handle (bypassing connect)
        let client = McpClient(handle: McpClientHandle(initialized: true))

        do {
            _ = try await client.listTools()
            Issue.record("Expected listTools to throw")
        } catch let error as ScpError {
            if case .Tool(_, let code) = error {
                #expect(code == "SCP-MCP-10003")
            } else {
                Issue.record("Expected ScpError.Tool, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - McpClient invoke (bridge stub error propagation)

    @Test("McpClient.invoke throws bridge error with SCP-MCP-10004")
    func mcpClientInvokeThrowsBridgeError() async {
        let client = McpClient(handle: McpClientHandle(initialized: true))

        do {
            _ = try await client.invoke(
                tool: "weather_lookup",
                input: Data(#"{"city": "NYC"}"#.utf8),
                contextId: "ctx-mcp-invoke",
                invokerDid: "did:dht:z6MkAgent"
            )
            Issue.record("Expected invoke to throw")
        } catch let error as ScpError {
            if case .Tool(_, let code) = error {
                #expect(code == "SCP-MCP-10004")
            } else {
                Issue.record("Expected ScpError.Tool, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
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
