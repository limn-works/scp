// MCP integration: expose SCP tools via MCP and consume external MCP servers.
//
// Demonstrates tool registration using the SDK wrapper API and the
// ToolDefinition UniFFI type. MCP server/client bridge functions are not
// yet wired -- this example shows the tool registration pattern and
// documents the planned MCP surface.

import Foundation
import SCP

@main
struct McpIntegration {
    static func main() async throws {
        let identity = try await createIdentity(custody: "in_memory")

        // Create a context with tool capabilities
        let params = ContextParams(
            ceiling: ["messages:read", "messages:write", "tool:invoke:*", "tool:register"],
            governance: .singleAdmin,
            memoryScope: .ephemeral,
            ttlSeconds: 3600,
            promotable: false,
            minProtocolVersion: 0
        )
        let handle = try await contextCreate(identity: identity, params: params)

        // Register a tool in the context using the UniFFI ToolDefinition type
        let tool = ToolDefinition(
            name: "summarize",
            description: "Summarize text content",
            inputSchemaJson: #"{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}"#,
            outputSchemaJson: #"{"type":"object","properties":{"summary":{"type":"string"}}}"#,
            operatorDid: identity.did(),
            testVectorsJson: nil,
            implementationHash: nil,
            cost: nil
        )
        _ = try await toolRegister(handle: handle, definition: tool)

        // MCP server/client bridge functions are not yet wired.
        // When available, the pattern will be:
        //
        //   let serverConfig = McpServerConfig(
        //       identityDid: identity.did(),
        //       contextIds: [handle.contextId()],
        //       transport: "stdio",
        //       ucanToken: nil,
        //       proofTokens: nil
        //   )
        //   try await serveMcp(config: serverConfig)
        //
        //   let client = try await McpClient.connect(
        //       config: .sse(url: "http://localhost:8080/mcp")
        //   )
        //   let tools = try await client.listTools()
        //
        print("(MCP server/client not yet available via FFI bridge)")

        try await contextClose(handle: handle, identity: identity)
    }
}
