/** Basic messaging: create identity, create context, send and receive messages. */

package works.limn.scp.examples

import works.limn.scp.CustodyType
import works.limn.scp.Identity
import works.limn.scp.Context
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    // Create two identities (in_memory custody for examples)
    val alice = Identity.create(custody = CustodyType.IN_MEMORY)
    val bob = Identity.create(custody = CustodyType.IN_MEMORY)
    println("Alice DID: ${alice.did}")
    println("Bob DID: ${bob.did}")

    // Alice creates a context
    val ctx = Context.create(
        identity = alice,
        ceiling = listOf("messages:read", "messages:write"),
        memoryScope = "ephemeral",
        governance = "single_admin",
        ttl = 3600,
    )
    println("Context ID: ${ctx.contextId}")

    // Bob joins the context
    ctx.join(identity = bob)

    // Alice sends a message
    ctx.send("Hello Bob, this is Alice".toByteArray())

    // Bob receives it
    val msg = ctx.receiveFlow().first()
    println("Bob received from ${msg.senderDid}: ${String(msg.content)}")

    // Cleanup
    ctx.leave(identity = bob)
    ctx.close(identity = alice)
}
