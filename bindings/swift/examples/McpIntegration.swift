// MCP integration: expose SCP tools via MCP and consume external MCP servers.
//
// Demonstrates tool registration against an explicit `SCP` instance
// (ADR-048). MCP server/client methods are available as `SCP` instance
// methods once the bridge is wired.

import Foundation
import SCP

@main
struct McpIntegration {
    static func main() async throws {
        let scp = SCP()
        defer { Task { try? await scp.shutdown(timeout: 5) } }

        let identity = try await scp.identityCreate(custody: "in_memory")

        let params = ContextParams(
            mode: .encrypted,
            ceiling: ["messages:read", "messages:write", "tool:invoke:*", "tool:register"],
            ceilingPolicy: .immutable,
            governance: .singleAdmin,
            memoryScope: .ephemeral,
            ttlSeconds: 3600,
            promotable: false,
            minProtocolVersion: 0,
            maxChainDepth: nil,
            maxNestingDepth: nil,
            sessionCap: nil,
            economicPolicy: nil
        )
        let handle = try await scp.contextCreate(identity: identity, params: params)

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
        _ = try await scp.toolRegister(handle: handle, definition: tool)

        // MCP server/client methods on SCP:
        //
        //   let serverConfig = McpServerConfig(
        //       identityDid: identity.did(),
        //       contextIds: [handle.contextId()],
        //       transport: "stdio",
        //       ucanToken: nil,
        //       proofTokens: nil
        //   )
        //   _ = try await scp.mcpServerCreate(config: serverConfig)
        //
        //   let client = try await McpClient.connect(
        //       scp: scp,
        //       config: .sse(url: "http://localhost:8080/mcp")
        //   )
        //   let tools = try await client.listTools()
        //
        print("(MCP server/client available via scp.mcpServerCreate / McpClient.connect)")

        try await scp.contextClose(handle: handle, identity: identity)
    }
}
