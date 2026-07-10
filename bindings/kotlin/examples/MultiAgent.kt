/**
 * Multi-agent coordination: multiple agents collaborating in a shared context.
 *
 * Demonstrates identity creation, context creation with governance, UCAN
 * minting, message sending, and message receiving using the actual Kotlin
 * SDK API surface via CoroutineBridge.
 *
 * Prerequisites:
 *   implementation("works.limn:scp-kt:0.1.0")
 *
 * Usage:
 *   ./gradlew run --args="multi-agent"
 */

package works.limn.scp.examples

import kotlinx.coroutines.async
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.putJsonArray
import works.limn.scp.CustodyType
import works.limn.scp.bridge.CoroutineBridge

suspend fun runAgent(
    name: String,
    agentHandle: Long,
    bridge: CoroutineBridge,
    contextHandle: Long,
) {
    // Agent joins the existing context
    bridge.context.join(contextHandle, agentHandle)
    println("[$name] Joined context")

    // Send a message
    bridge.context.send(contextHandle, agentHandle, "[$name] reporting in".toByteArray())
    println("[$name] Sent message")

    // Subscribe to messages via Flow
    val subscription = bridge.context.subscribe(contextHandle)
    var count = 0
    subscription.take(2).collect { messageJson ->
        println("[$name] Received: $messageJson")
        count++
    }

    bridge.context.leave(contextHandle, agentHandle)
    println("[$name] Left context")
}

fun multiAgentExample(bridge: CoroutineBridge) = runBlocking {
    // Create identities for coordinator and two agents
    val coordinatorHandle = bridge.identity.create(CustodyType.IN_MEMORY)
    val agentAHandle = bridge.identity.create(CustodyType.IN_MEMORY)
    val agentBHandle = bridge.identity.create(CustodyType.IN_MEMORY)
    println("Coordinator: $coordinatorHandle")
    println("Agent A: $agentAHandle")
    println("Agent B: $agentBHandle")

    // Coordinator creates the context with governance capabilities
    val paramsJson = buildJsonObject {
        putJsonArray("ceiling") {
            add(JsonPrimitive("messages:read"))
            add(JsonPrimitive("messages:write"))
            add(JsonPrimitive("outlet:call:*"))
            add(JsonPrimitive("member:invite"))
            add(JsonPrimitive("member:remove"))
            add(JsonPrimitive("role:assign"))
        }
        put("governance", JsonPrimitive("single_admin"))
        put("memory_scope", JsonPrimitive("ephemeral"))
    }.toString()

    val contextHandle = bridge.context.create(coordinatorHandle, paramsJson)
    println("Context created: $contextHandle")

    // Mint UCANs for each agent via the bridge
    //   bridge.ucan.mint(contextHandle, agentADid, """["messages:write","messages:read"]""")
    //   bridge.ucan.mint(contextHandle, agentBDid, """["messages:write","messages:read"]""")
    // (requires agent DIDs -- omitted in this example since handles are opaque Longs)

    // Run agents concurrently
    val taskA = async { runAgent("Agent-A", agentAHandle, bridge, contextHandle) }
    val taskB = async { runAgent("Agent-B", agentBHandle, bridge, contextHandle) }
    taskA.await()
    taskB.await()

    bridge.context.close(contextHandle, coordinatorHandle)
    println("Context closed.")
}
