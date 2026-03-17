/**
 * MCP integration: expose SCP tools via MCP and consume external MCP servers.
 *
 * Demonstrates tool registration via the CoroutineBridge and the
 * ToolDefinition data class. MCP server/client functionality is not yet
 * wired through the FFI bridge -- this example shows the tool registration
 * pattern and documents the planned MCP surface.
 *
 * Prerequisites:
 *   implementation("works.limn:scp-kt:0.1.0")
 *
 * Usage:
 *   ./gradlew run --args="mcp"
 */

package works.limn.scp.examples

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.putJsonArray
import works.limn.scp.CustodyType
import works.limn.scp.ToolDefinition
import works.limn.scp.bridge.CoroutineBridge

fun mcpIntegrationExample(bridge: CoroutineBridge) = runBlocking {
    val operatorHandle = bridge.identity.create(CustodyType.IN_MEMORY)
    println("Operator handle: $operatorHandle")

    // Create a context with tool capabilities
    val paramsJson = buildJsonObject {
        putJsonArray("ceiling") {
            add(JsonPrimitive("messages:read"))
            add(JsonPrimitive("messages:write"))
            add(JsonPrimitive("tool:invoke:*"))
            add(JsonPrimitive("tool:register"))
        }
    }.toString()

    val contextHandle = bridge.context.create(operatorHandle, paramsJson)
    println("Context handle: $contextHandle")

    // Define a tool using the typed ToolDefinition data class.
    // ToolDefinition.toJson() serializes to the JSON format expected by the FFI bridge.
    val tool = ToolDefinition(
        name = "summarize",
        description = "Summarize text content",
        inputSchemaJson = """{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}""",
        outputSchemaJson = """{"type":"object","properties":{"summary":{"type":"string"}}}""",
        operatorDid = "did:dht:z6MkOperator",
    )

    // Register the tool in the context via the bridge
    val toolId = bridge.tools.register(contextHandle, tool.toJson())
    println("Registered tool: $toolId")

    // MCP server/client operations are not yet wired through the FFI bridge.
    // When available, the pattern will be:
    //
    //   // Start an MCP server exposing context tools
    //   val server = bridge.mcp.serve(contextHandle, transport = "stdio")
    //
    //   // Connect as an MCP client
    //   val client = bridge.mcp.connect("ws://localhost:8080/mcp")
    //   val tools = client.listTools()
    //   val result = client.callTool("summarize", """{"text":"..."}""")
    //
    println("(MCP server/client not yet available via FFI bridge)")

    bridge.context.close(contextHandle, operatorHandle)
    println("Context closed.")
}
