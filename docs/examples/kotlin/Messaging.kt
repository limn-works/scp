/**
 * Two-party message exchange within a context over a relay.
 *
 * Demonstrates attaching each node to a relay, the invite-and-join
 * handshake, sending a message from one member, and receiving it in the
 * other member's node through a [MessageListener].
 *
 * Alice and Bob each run their own [SCP] instance with its own database, and
 * both reach the relay at `relayUrl`. Each node attaches the relay before it
 * creates or joins any context: the first context starts the node's context
 * supervisor, which binds the transport it finds then, and a later
 * `configureRelayTransport` call attaches nothing.
 *
 * Prerequisites:
 *   implementation("works.limn:scp-kt:0.1.0")
 *
 * Usage:
 *   messagingExample(aliceProvider, bobProvider, "wss://relay.example.com", context.filesDir, passphrase)
 */

package works.limn.scp.examples

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import uniffi.scp.CeilingPolicy
import uniffi.scp.ContextHandle
import uniffi.scp.ContextMode
import uniffi.scp.ContextParams
import uniffi.scp.GovernanceModel
import uniffi.scp.Identity
import uniffi.scp.InviteMemberOutcome
import uniffi.scp.KeyCustodyProvider
import uniffi.scp.MemoryScope
import uniffi.scp.Message
import uniffi.scp.MessageListener
import uniffi.scp.ScpException
import works.limn.scp.SCP
import java.io.File

/**
 * A send fails with this code until the peer's routing announcement has
 * arrived over the relay (spec §9.10.4). The send is rolled back, so a retry
 * is safe.
 */
private const val NO_PEER_ROUTE = "SCP-CTX-2095"
private const val SEND_ATTEMPTS = 10
private const val RETRY_DELAY_MS = 500L

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

/** Sends `text`, retrying only while the peer's route is unknown. */
private suspend fun sendWhenRoutable(
    node: SCP,
    handle: ContextHandle,
    identity: Identity,
    text: String,
) {
    for (attempt in 1..SEND_ATTEMPTS) {
        try {
            node.contextSend(handle, identity, text.toByteArray(), spendingUcanJwt = null)
            return
        } catch (e: ScpException.Context) {
            if (e.code != NO_PEER_ROUTE || attempt == SEND_ATTEMPTS) throw e
            delay(RETRY_DELAY_MS)
        }
    }
}

fun messagingExample(
    aliceProvider: KeyCustodyProvider,
    bobProvider: KeyCustodyProvider,
    relayUrl: String,
    storageRoot: File,
    storagePassphrase: String,
) = runBlocking {
    val aliceNode = SCP.withSqlite(File(storageRoot, "scp-messaging-alice"), storagePassphrase)
    val bobNode = SCP.withSqlite(File(storageRoot, "scp-messaging-bob"), storagePassphrase)

    // 1. Each side creates its identity and attaches the relay before any
    //    context exists.
    val alice = aliceNode.identityCreateWithCustody(aliceProvider)
    val bob = bobNode.identityCreateWithCustody(bobProvider)
    aliceNode.configureRelayTransport(relayUrl, alice.did())
    bobNode.configureRelayTransport(relayUrl, bob.did())
    aliceNode.transportConnect(relayUrl)
    bobNode.transportConnect(relayUrl)

    // 2. Alice creates the context. Inviting runs through the governance
    //    gate, so the ceiling carries governance:propose.
    val params =
        ContextParams(
            mode = ContextMode.ENCRYPTED,
            ceiling = listOf("messages:read", "messages:write", "member:invite", "governance:propose"),
            ceilingPolicy = CeilingPolicy.IMMUTABLE,
            governance = GovernanceModel.SINGLE_ADMIN,
            memoryScope = MemoryScope.EPHEMERAL,
            ttlSeconds = 0uL,
            promotable = false,
            minProtocolVersion = 0.toUShort(),
            maxChainDepth = null,
            maxNestingDepth = null,
            sessionCap = null,
            economicPolicy = null,
            consequenceRulesJson = null,
            consequenceConfigJson = null,
        )
    val aliceHandle = aliceNode.contextCreate(alice, params)

    // 3. Bob reserves a KeyPackage, Alice seals an invitation to it, and Bob
    //    joins from the sealed bundle.
    val reservation = bobNode.reserveKeyPackage(bob)
    val outcome =
        aliceNode.inviteMember(
            identity = alice,
            contextId = aliceHandle.contextId(),
            inviteeDid = bob.did(),
            inviteeKeyPackage = reservation.keyPackagePublic,
        )
    val bundle =
        when (outcome) {
            is InviteMemberOutcome.Sealed -> outcome.bundle
        }
    val bobHandle = bobNode.contextJoinFromWelcome(bob, bundle, reservation.reservationId)

    // 4. Bob subscribes. The listener runs once per delivered message.
    bobNode.contextSubscribe(bobHandle, PrintingListener())

    // 5. Alice sends a message. A context without an economic policy needs
    //    no spending UCAN.
    sendWhenRoutable(aliceNode, aliceHandle, alice, "Hello Bob!")
    println("Alice: Hello Bob!")

    // 6. Bob replies.
    sendWhenRoutable(bobNode, bobHandle, bob, "Hi Alice!")
    println("Bob: Hi Alice!")

    // 7. Bob leaves. His stream completes.
    bobNode.contextLeave(bobHandle, bob)
    println("\nBob left the context.")

    // SCP.shutdown takes a CoroutineBridge, and the SDK ships no NativeBindings
    // implementation to build one with, so this example cannot shut either
    // instance down. The finalizer logs a warning when the JVM collects it.
    println("Message exchange complete.")
}
