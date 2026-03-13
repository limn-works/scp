/**
 * Context creation and lifecycle management.
 *
 * Demonstrates creating an SCP context with governance parameters,
 * inspecting its state, joining/leaving, and managing membership.
 *
 * Prerequisites:
 *   implementation("works.limn:scp-kt:0.1.0")
 *
 * Usage:
 *   ./gradlew run --args="context"
 */

package works.limn.scp.examples

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import works.limn.scp.CustodyType
import works.limn.scp.bridge.CoroutineBridge

fun contextExample(bridge: CoroutineBridge) = runBlocking {
    // 1. Create the identity that will own the context.
    val aliceHandle = bridge.identity.create(CustodyType.IN_MEMORY)
    println("Alice identity handle: $aliceHandle")

    // 2. Define context parameters as JSON.
    //    The Kotlin SDK uses JSON strings for structured parameters
    //    passed through the FFI bridge.
    val paramsJson = buildJsonObject {
        putJsonArray("ceiling") {
            add(JsonPrimitive("messages:read"))
            add(JsonPrimitive("messages:write"))
            add(JsonPrimitive("member:invite"))
            add(JsonPrimitive("member:remove"))
            add(JsonPrimitive("tool:register"))
            add(JsonPrimitive("tool:invoke_all"))
        }
        put("mode", "Encrypted")
        put("memory_scope", "full")
        put("governance", "single_admin")
    }.toString()

    // 3. Create the context.
    //    Returns an opaque context handle (Long) for subsequent operations.
    val contextHandle = bridge.context.create(aliceHandle, paramsJson)
    println()
    println("Context created, handle: $contextHandle")

    // 4. Send a message to the context.
    val payload = "Hello, context!".toByteArray()
    bridge.context.send(contextHandle, payload)
    println("  Message sent successfully.")

    // 5. Query membership.
    val memberCount = bridge.membership.memberCount(contextHandle)
    println("  Member count: $memberCount")

    val members = bridge.membership.memberDids(contextHandle)
    println("  Members: $members")

    // 6. Bob joins the context.
    val bobHandle = bridge.identity.create(CustodyType.IN_MEMORY)
    val bobContextHandle = bridge.context.join(bobHandle, "context-id")
    println()
    println("Bob joined the context, handle: $bobContextHandle")

    val isBobMember = bridge.membership.isMember(contextHandle, "did:dht:z6MkBob")
    println("  Bob is member: $isBobMember")

    val bobRole = bridge.membership.memberRole(contextHandle, "did:dht:z6MkBob")
    println("  Bob role: $bobRole")

    // 7. Bob leaves the context.
    bridge.context.leave(bobContextHandle)
    println("Bob left the context.")

    // 8. Close the context for all members.
    bridge.context.close(contextHandle)
    println("Context closed.")

    println()
    println("Context lifecycle complete.")
}
