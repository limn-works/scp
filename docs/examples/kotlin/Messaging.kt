/**
 * Two-participant message exchange.
 *
 * Demonstrates creating a context, adding a second participant,
 * and exchanging messages between them. Shows how Flow-based
 * streaming delivers messages using Kotlin coroutines.
 *
 * Prerequisites:
 *   implementation("works.limn:scp-kt:0.1.0")
 *
 * Usage:
 *   ./gradlew run --args="messaging"
 */

package works.limn.scp.examples

import kotlinx.coroutines.flow.take
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.putJsonArray
import works.limn.scp.CustodyType
import works.limn.scp.bridge.CoroutineBridge

fun messagingExample(bridge: CoroutineBridge) = runBlocking {
    // 1. Create two identities.
    val aliceHandle = bridge.identity.create(CustodyType.IN_MEMORY)
    val bobHandle = bridge.identity.create(CustodyType.IN_MEMORY)
    println("Alice handle: $aliceHandle")
    println("Bob handle:   $bobHandle")

    // 2. Alice creates a context with messaging capabilities.
    val paramsJson = buildJsonObject {
        putJsonArray("ceiling") {
            add("messages:read")
            add("messages:write")
            add("member:invite")
            add("member:remove")
        }
    }.toString()

    val contextHandle = bridge.context.create(aliceHandle, paramsJson)
    println("\nContext handle: $contextHandle")

    // 3. Bob joins the context.
    val bobCtxHandle = bridge.context.join(bobHandle, "chat-demo")
    println("Bob joined the context.")

    val members = bridge.membership.memberDids(contextHandle)
    println("Members: $members")

    // 4. Alice sends a message.
    bridge.context.send(contextHandle, "Hello Bob!".toByteArray())
    println("\nAlice: Hello Bob!")

    // 5. Bob sends a reply.
    bridge.context.send(contextHandle, "Hi Alice!".toByteArray())
    println("Bob: Hi Alice!")

    // 6. Subscribe to incoming messages via Flow.
    //    The SDK provides two streaming patterns:
    //
    //    a) Cold Flow (ColdMessageFlow) -- single collector, backpressure:
    //       val flow = bridge.context.subscribe(contextHandle)
    //       flow.collect { messageJson ->
    //           println("Received: $messageJson")
    //       }
    //
    //    b) Hot SharedFlow (HotStreamFactory) -- multiple collectors, DROP_OLDEST:
    //       val sharedFlow = factory.incomingMessages(contextHandle)
    //       sharedFlow.collect { messageJson ->
    //           println("Received: $messageJson")
    //       }
    //
    //    Cold flows are lazy (no work until collected).
    //    Hot flows have a 64-item buffer with DROP_OLDEST overflow.
    //
    //    Here we demonstrate subscribing and taking a few messages:
    val subscription = bridge.context.subscribe(contextHandle)
    val collectorJob = launch {
        subscription.take(2).collect { messageJson ->
            println("  Received: $messageJson")
        }
    }

    // Wait for the collector to finish.
    collectorJob.join()
    println("\n(Messages consumed)")

    // 7. Bob leaves the context.
    bridge.context.leave(bobCtxHandle)
    println("\nBob left the context.")

    val remaining = bridge.membership.memberDids(contextHandle)
    println("Remaining members: $remaining")

    // 8. Clean up.
    bridge.context.close(contextHandle)
    println("Context closed.")

    println("\nMessage exchange complete.")
}
