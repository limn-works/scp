/**
 * Tool invocation: register a tool with test vectors and invoke it.
 *
 * Demonstrates the ToolDefinition data class, tool registration via the
 * CoroutineBridge, and tool invocation. Uses the actual Kotlin SDK API surface.
 *
 * Prerequisites:
 *   implementation("works.limn:scp-kt:0.1.0")
 *
 * Usage:
 *   ./gradlew run --args="tool-invocation"
 */

package works.limn.scp.examples

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.putJsonArray
import works.limn.scp.CustodyType
import works.limn.scp.ToolDefinition
import works.limn.scp.bridge.CoroutineBridge

fun toolInvocationExample(bridge: CoroutineBridge) = runBlocking {
    val operatorHandle = bridge.identity.create(CustodyType.IN_MEMORY)
    println("Operator handle: $operatorHandle")

    // Define a weather tool using the typed ToolDefinition data class
    val weatherTool = ToolDefinition(
        name = "weather",
        description = "Get current weather for a city",
        inputSchemaJson = """{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}""",
        outputSchemaJson = """{"type":"object","properties":{"tempC":{"type":"number"},"condition":{"type":"string"}}}""",
        operatorDid = "did:dht:z6MkOperator",
        testVectorsJson = """[{"input":{"city":"Berlin"},"expected":{"tempC":18,"condition":"cloudy"}}]""",
    )

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

    // Register the tool via the bridge (toJson() serializes the ToolDefinition)
    val toolId = bridge.tools.register(contextHandle, weatherTool.toJson())
    println("Registered tool: $toolId")

    // Invoke the tool via the bridge
    val resultJson = bridge.tools.invoke(
        contextHandle,
        toolId,
        """{"city":"Berlin"}""",
        operatorHandle,
        null,
    )
    println("Weather result: $resultJson")

    bridge.context.close(contextHandle, operatorHandle)
    println("Context closed.")
}
