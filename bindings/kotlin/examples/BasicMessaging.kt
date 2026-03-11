/** Basic messaging: create identity, create context, send and receive messages. */

package works.limn.scp.examples

import works.limn.scp.Context
import works.limn.scp.Identity
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    // Create two identities
    val alice = Identity.create(custody = "platform")
    val bob = Identity.create(custody = "platform")
    println("Alice DID: ${alice.did}")
    println("Bob DID: ${bob.did}")

    // Alice creates a context
    val ctxAlice = Context.create(
        identity = alice,
        params = mapOf(
            "ceiling" to listOf("msg:send", "msg:receive"),
            "ttl" to 3600,
            "governance" to "single_admin",
        ),
    )
    println("Context ID: ${ctxAlice.contextId}")

    // Bob joins the context
    val ctxBob = Context.join(identity = bob, contextId = ctxAlice.contextId)

    // Alice sends a message
    ctxAlice.send("Hello Bob, this is Alice".toByteArray())

    // Bob receives it
    val msg = ctxBob.receiveFlow().first()
    println("Bob received from ${msg.senderDid}: ${String(msg.content)}")

    // Cleanup
    ctxBob.leave()
    ctxAlice.close()
}
