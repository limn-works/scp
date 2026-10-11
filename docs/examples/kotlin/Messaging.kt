/**
 * Two-party message exchange within a context.
 *
 * Demonstrates sending a message from one member and receiving it in
 * another member's node through a [MessageListener].
 *
 * Alice and Bob each run their own [SCP] instance, and both reach each other
 * through the relay at `relayUrl`. Bob must already be a member of the
 * context: `contextExample` shows the invite-and-join handshake that produces
 * `aliceHandle` and `bobHandle`.
 *
 * Prerequisites:
 *   implementation("works.limn:scp-kt:0.1.0")
 *
 * Usage:
 *   messagingExample(aliceNode, alice, aliceHandle, bobNode, bob, bobHandle, "wss://relay.example")
 */

package works.limn.scp.examples

import kotlinx.coroutines.runBlocking
import uniffi.scp.ContextHandle
import uniffi.scp.Identity
import uniffi.scp.Message
import uniffi.scp.MessageListener
import uniffi.scp.ScpException
import works.limn.scp.SCP

/** Prints each message the context delivers to Bob's node. */
class PrintingListener : MessageListener {
    override fun onMessage(message: Message) {
        println("[${message.senderDid}] ${message.payload.decodeToString()}")
    }

    override fun onError(error: ScpException) {
        println("Stream error: $error")
    }

    override fun onComplete() {
        println("Stream complete.")
    }
}

@Suppress("LongParameterList")
fun messagingExample(
    aliceNode: SCP,
    alice: Identity,
    aliceHandle: ContextHandle,
    bobNode: SCP,
    bob: Identity,
    bobHandle: ContextHandle,
    relayUrl: String,
) = runBlocking {
    // 1. Point each node at the relay that carries the context's traffic.
    aliceNode.configureRelayTransport(relayUrl, alice.did())
    bobNode.configureRelayTransport(relayUrl, bob.did())

    // 2. Bob subscribes. The listener runs once per delivered message.
    bobNode.contextSubscribe(bobHandle, PrintingListener())

    // 3. Alice sends a message. A context without an economic policy needs
    //    no spending UCAN.
    aliceNode.contextSend(aliceHandle, alice, "Hello Bob!".toByteArray(), spendingUcanJwt = null)
    println("Alice: Hello Bob!")

    // 4. Bob replies.
    bobNode.contextSend(bobHandle, bob, "Hi Alice!".toByteArray(), spendingUcanJwt = null)
    println("Bob: Hi Alice!")

    // 5. Bob leaves. His stream completes.
    bobNode.contextLeave(bobHandle, bob)
    println("\nBob left the context.")
    println("Message exchange complete.")
}
