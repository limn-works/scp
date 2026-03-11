/** Tool invocation: register a tool with test vectors and invoke it. */

package works.limn.scp.examples

import works.limn.scp.Context
import works.limn.scp.Identity
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    val identity = Identity.create(custody = "platform")

    val ctx = Context.create(
        identity = identity,
        params = mapOf(
            "ceiling" to listOf("msg:send", "msg:receive", "tool:invoke"),
            "tools" to listOf(
                mapOf(
                    "name" to "weather",
                    "description" to "Get current weather for a city",
                    "inputSchema" to mapOf(
                        "type" to "object",
                        "properties" to mapOf("city" to mapOf("type" to "string")),
                        "required" to listOf("city"),
                    ),
                    "outputSchema" to mapOf(
                        "type" to "object",
                        "properties" to mapOf(
                            "tempC" to mapOf("type" to "number"),
                            "condition" to mapOf("type" to "string"),
                        ),
                    ),
                    "operator" to identity.did,
                    "testVectors" to listOf(
                        mapOf(
                            "input" to mapOf("city" to "Berlin"),
                            "expectedOutput" to mapOf("tempC" to 18, "condition" to "cloudy"),
                            "description" to "Berlin weather lookup",
                        ),
                    ),
                ),
            ),
        ),
    )

    // Invoke the tool
    val result = ctx.invokeTool("weather", mapOf("city" to "Berlin"))
    println("Weather result: $result")

    ctx.close()
}
