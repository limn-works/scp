// MCP integration: expose SCP tools via MCP and consume external MCP servers.
//
// Demonstrates the McpServerConfig, McpClient, and serveMcp APIs using the
// actual SCP Swift SDK surface. Note: MCP bridge functions are not yet wired
// to UniFFI (see Mcp.swift) — this example shows the intended API shape.

import Foundation
import SCP

@main
struct McpIntegration {
    static func main() async throws {
        let identity = try await identityCreate(custody: "platform")

        // Create a context with tool capabilities
        let params = ContextParams(
            ceiling: ["msg:send", "msg:receive", "tool:invoke"],
            governance: .singleAdmin,
            memoryScope: .ephemeral,
            ttlSeconds: 3600,
            promotable: false
        )
        let handle = try await contextCreate(identity: identity, params: params)

        // Register a tool in the context
        let tool = ToolDefinition(
            name: "summarize",
            description: "Summarize text content",
            inputSchemaJson: #"{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}"#,
            outputSchemaJson: #"{"type":"object","properties":{"summary":{"type":"string"}}}"#,
            operatorDid: identity.did(),
            testVectorsJson: nil,
            implementationHash: nil
        )
        _ = try await toolRegister(handle: handle, definition: tool)

        // Start an MCP server exposing context tools on stdio.
        // Note: serveMcp takes an McpServerConfig, not a Context.
        // The bridge function is not yet wired — this will throw SCP-MCP-10001.
        let serverConfig = McpServerConfig(
            contextIds: [handle.contextId()],
            transport: .stdio
        )
        do {
            try await serveMcp(config: serverConfig)
        } catch {
            print("MCP server not yet available: \(error)")
        }

        // Connect as an MCP client to a remote server.
        // McpClient.connect takes an McpClientConfig enum.
        // The bridge function is not yet wired — this will throw SCP-MCP-10002.
        do {
            let client = try await McpClient.connect(
                config: .sse(url: "http://localhost:8080/mcp")
            )
            let tools = try await client.listTools()
            print("Remote server offers \(tools.count) tool(s)")

            let result = try await client.invoke(
                tool: "summarize",
                input: Data(#"{"text":"SCP is a protocol for..."}"#.utf8),
                contextId: handle.contextId(),
                invokerDid: identity.did()
            )
            // swiftlint:disable:next optional_data_string_conversion
            print("Result: \(String(decoding: result.content, as: UTF8.self))")
        } catch {
            print("MCP client not yet available: \(error)")
        }

        try await contextClose(handle: handle, identity: identity)
    }
}
