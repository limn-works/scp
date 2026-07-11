/**
 * Outlet invocation: register an outlet with test vectors and invoke it.
 *
 * Demonstrates the OutletDefinition data class, outlet registration via the
 * CoroutineBridge, and outlet invocation. Uses the actual Kotlin SDK API surface.
 *
 * Prerequisites:
 *   implementation("works.limn:scp-kt:0.1.0")
 *
 * Usage:
 *   ./gradlew run --args="outlet-invocation"
 */

package works.limn.scp.examples

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.putJsonArray
import uniffi.scp.OutletKind
import works.limn.scp.CustodyType
import works.limn.scp.OutletDefinition
import works.limn.scp.bridge.CoroutineBridge

fun outletInvocationExample(bridge: CoroutineBridge) = runBlocking {
    val operatorHandle = bridge.identity.create(CustodyType.IN_MEMORY)
    println("Operator handle: $operatorHandle")

    // Define a weather outlet using the typed OutletDefinition data class
    val weatherOutlet = OutletDefinition(
        name = "weather",
        description = "Get current weather for a city",
        kind = OutletKind.ACTION,
        inputSchemaJson = """{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}""",
        outputSchemaJson = """{"type":"object","properties":{"tempC":{"type":"number"},"condition":{"type":"string"}}}""",
        operatorDid = "did:dht:z6MkOperator",
        testVectorsJson = """[{"input":{"city":"Berlin"},"expected":{"tempC":18,"condition":"cloudy"}}]""",
    )

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

    // Register the outlet via the bridge (toJson() serializes the OutletDefinition)
    val outletId = bridge.outlets.register(contextHandle, weatherOutlet.toJson())
    println("Registered outlet: $outletId")

    // Invoke the outlet via the bridge
    val resultJson = bridge.outlets.invoke(
        contextHandle,
        outletId,
        """{"city":"Berlin"}""",
        operatorHandle,
        null,
    )
    println("Weather result: $resultJson")

    bridge.context.close(contextHandle, operatorHandle)
    println("Context closed.")
}
