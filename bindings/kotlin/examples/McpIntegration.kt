/**
 * MCP integration: expose SCP outlets via MCP and consume external MCP servers.
 *
 * Demonstrates outlet registration via the CoroutineBridge and the
 * OutletDefinition data class. MCP server/client functionality is not yet
 * wired through the FFI bridge -- this example shows the outlet registration
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
import works.limn.scp.OutletDefinition
import works.limn.scp.bridge.CoroutineBridge

fun mcpIntegrationExample(bridge: CoroutineBridge) = runBlocking {
    val operatorHandle = bridge.identity.create(CustodyType.ENCRYPTED_FILE)
    println("Operator handle: $operatorHandle")

    // Create a context with outlet capabilities
    val paramsJson = buildJsonObject {
        putJsonArray("ceiling") {
            add(JsonPrimitive("messages:read"))
            add(JsonPrimitive("messages:write"))
            add(JsonPrimitive("outlet:call:*"))
            add(JsonPrimitive("outlet:register"))
        }
    }.toString()

    val contextHandle = bridge.context.create(operatorHandle, paramsJson)
    println("Context handle: $contextHandle")

    // Define an outlet using the typed OutletDefinition data class.
    // OutletDefinition.toJson() serializes to the JSON format expected by the FFI bridge.
    val outlet = OutletDefinition(
        name = "summarize",
        description = "Summarize text content",
        inputSchemaJson = """{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}""",
        outputSchemaJson = """{"type":"object","properties":{"summary":{"type":"string"}}}""",
        operatorDid = "did:dht:z6MkOperator",
    )

    // Register the outlet in the context via the bridge
    val outletId = bridge.outlets.register(contextHandle, outlet.toJson())
    println("Registered outlet: $outletId")

    // MCP server/client operations are not yet wired through the FFI bridge.
    // When available, the pattern will be:
    //
    //   // Start an MCP server exposing context outlets
    //   val server = bridge.mcp.serve(contextHandle, transport = "stdio")
    //
    //   // Connect as an MCP client
    //   val client = bridge.mcp.connect("ws://localhost:8080/mcp")
    //   val outlets = client.listTools()
    //   val result = client.callOutlet("summarize", """{"text":"..."}""")
    //
    println("(MCP server/client not yet available via FFI bridge)")

    bridge.context.close(contextHandle, operatorHandle)
    println("Context closed.")
}
