/** MCP integration: expose SCP tools via MCP JSON-RPC server. */

package works.limn.scp.examples

import works.limn.scp.Context
import works.limn.scp.Identity
import works.limn.scp.McpClient
import works.limn.scp.serveMcp
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    val identity = Identity.create(custody = "platform")

    val ctx = Context.create(
        identity = identity,
        params = mapOf(
            "ceiling" to listOf("msg:send", "msg:receive", "tool:invoke", "mcp:serve"),
            "tools" to listOf(
                mapOf(
                    "name" to "summarize",
                    "description" to "Summarize text content",
                    "inputSchema" to mapOf(
                        "type" to "object",
                        "properties" to mapOf("text" to mapOf("type" to "string")),
                        "required" to listOf("text"),
                    ),
                    "outputSchema" to mapOf(
                        "type" to "object",
                        "properties" to mapOf("summary" to mapOf("type" to "string")),
                    ),
                    "operator" to identity.did,
                ),
            ),
        ),
    )

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
    ctx.close()
}
