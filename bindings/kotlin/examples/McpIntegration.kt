/** MCP integration: expose SCP tools via MCP JSON-RPC server. */

package works.limn.scp.examples

import works.limn.scp.Context
import works.limn.scp.CustodyType
import works.limn.scp.Identity
import works.limn.scp.McpClient
import works.limn.scp.ToolDefinition
import works.limn.scp.serveMcp
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    val identity = Identity.create(custody = CustodyType.IN_MEMORY)

    val ctx = Context.create(
        identity = identity,
        ceiling = listOf("messages:read", "messages:write", "tool:invoke:*", "tool:register"),
        memoryScope = "ephemeral",
        governance = "single_admin",
    )

    // Register a tool in the context
    val tool = ToolDefinition(
        name = "summarize",
        description = "Summarize text content",
        inputSchemaJson = """{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}""",
        outputSchemaJson = """{"type":"object","properties":{"summary":{"type":"string"}}}""",
        operatorDid = identity.did,
    )
    ctx.registerTool(tool)

    // Start an MCP server exposing context tools on stdio
    val server = serveMcp(ctx, transport = "stdio")
    println("MCP server running, exposing tools")

    // Or connect as an MCP client to a remote server
    val client = McpClient.connect("ws://localhost:8080/mcp")
    val tools = client.listTools()
    println("Remote server offers ${tools.size} tool(s)")

    val result = client.callTool("summarize", mapOf("text" to "SCP is a protocol for..."))
    println("Result: $result")

    client.close()
    server.stop()
    ctx.close(identity = identity)
}
