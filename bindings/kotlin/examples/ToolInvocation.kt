/** Tool invocation: register a tool with test vectors and invoke it. */

package works.limn.scp.examples

import works.limn.scp.Context
import works.limn.scp.CustodyType
import works.limn.scp.Identity
import works.limn.scp.ToolDefinition
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    val identity = Identity.create(custody = CustodyType.IN_MEMORY)

    val weatherTool = ToolDefinition(
        name = "weather",
        description = "Get current weather for a city",
        inputSchemaJson = """{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}""",
        outputSchemaJson = """{"type":"object","properties":{"tempC":{"type":"number"},"condition":{"type":"string"}}}""",
        operatorDid = identity.did,
        testVectorsJson = """[{"input":{"city":"Berlin"},"expected":{"tempC":18,"condition":"cloudy"}}]""",
    )

    val ctx = Context.create(
        identity = identity,
        ceiling = listOf("messages:read", "messages:write", "tool:invoke:*", "tool:register"),
        memoryScope = "ephemeral",
        governance = "single_admin",
    )

    // Register the tool
    val toolId = ctx.registerTool(weatherTool)
    println("Registered tool: $toolId")

    // Invoke the tool
    val result = ctx.invokeTool("weather", """{"city":"Berlin"}""", identity)
    println("Weather result: $result")

    ctx.close(identity = identity)
}
