/**
 * Basic messaging: create identity, create context, send and receive messages.
 *
 * Demonstrates the actual Kotlin SDK API surface. All FFI calls are dispatched
 * through the CoroutineBridge, which wraps blocking JNA calls on Dispatchers.IO.
 *
 * Prerequisites:
 *   implementation("works.limn:scp-kt:0.1.0")
 *
 * Usage:
 *   ./gradlew run --args="basic-messaging"
 */

package works.limn.scp.examples

import kotlinx.coroutines.flow.take
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.putJsonArray
import works.limn.scp.CustodyType
import works.limn.scp.bridge.CoroutineBridge

fun basicMessagingExample(bridge: CoroutineBridge) = runBlocking {
    // Create two identities (in_memory custody for examples)
    val aliceHandle = bridge.identity.create(CustodyType.ENCRYPTED_FILE)
    val bobHandle = bridge.identity.create(CustodyType.ENCRYPTED_FILE)
    println("Alice identity handle: $aliceHandle")
    println("Bob identity handle: $bobHandle")

    // Alice creates a context with messaging capabilities
    val paramsJson = buildJsonObject {
        putJsonArray("ceiling") {
            add(JsonPrimitive("messages:read"))
            add(JsonPrimitive("messages:write"))
            add(JsonPrimitive("member:invite"))
        }
        put("governance", kotlinx.serialization.json.JsonPrimitive("single_admin"))
        put("memory_scope", kotlinx.serialization.json.JsonPrimitive("ephemeral"))
    }.toString()

    val contextHandle = bridge.context.create(aliceHandle, paramsJson)
    println("Context handle: $contextHandle")

    // Bob joins the context
    bridge.context.join(contextHandle, bobHandle)
    println("Bob joined the context.")

    // Alice sends a message
    bridge.context.send(contextHandle, aliceHandle, "Hello Bob, this is Alice".toByteArray())
    println("Alice: Hello Bob, this is Alice")

    // Subscribe to incoming messages via Flow
    val subscription = bridge.context.subscribe(contextHandle)
    val collectorJob = launch {
        subscription.take(1).collect { messageJson ->
            println("Received: $messageJson")
        }
    }
    collectorJob.join()

    // Cleanup
    bridge.context.leave(contextHandle, bobHandle)
    bridge.context.close(contextHandle, aliceHandle)
    println("Context closed.")
}
