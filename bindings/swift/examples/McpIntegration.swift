/// MCP integration: expose SCP tools via MCP JSON-RPC server.

import SCP
import Foundation

@main
struct McpIntegration {
    static func main() async throws {
        let identity = try await Identity.create(custody: "platform")

        let ctx = try await Context.create(
            identity: identity,
            params: ContextParams(
                ceiling: ["msg:send", "msg:receive", "tool:invoke", "mcp:serve"],
                tools: [
                    ToolDefinition(
                        name: "summarize",
                        description: "Summarize text content",
                        inputSchema: #"{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}"#,
                        outputSchema: #"{"type":"object","properties":{"summary":{"type":"string"}}}"#,
                        operatorDid: identity.did
                    )
                ]
            )
        )

        // Start an MCP server exposing context tools on stdio
        let server = try await serveMcp(ctx, transport: .stdio)
        print("MCP server running, exposing tools")

        // Or connect as an MCP client to a remote server
        let client = try await McpClient.connect(url: "ws://localhost:8080/mcp")
        let tools = try await client.listTools()
        print("Remote server offers \(tools.count) tool(s)")

        let result = try await client.callTool("summarize", input: ["text": "SCP is a protocol for..."])
        print("Result: \(result)")

        try await client.close()
        try await server.stop()
        try await ctx.close()
    }
}
