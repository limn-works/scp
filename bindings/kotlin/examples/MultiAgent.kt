/** Multi-agent coordination: multiple agents collaborating in a shared context. */

package works.limn.scp.examples

import works.limn.scp.Context
import works.limn.scp.CustodyType
import works.limn.scp.Identity
import works.limn.scp.Ucan
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.runBlocking

suspend fun runAgent(name: String, identity: Identity, ctx: Context) {
    ctx.join(identity = identity)
    println("[$name] Joined context ${ctx.contextId}")

    ctx.send("[$name] reporting in".toByteArray(), identity = identity)

    var count = 0
    ctx.receiveFlow().collect { msg ->
        val sender = msg.senderDid.take(16)
        println("[$name] Received from $sender...: ${String(msg.content)}")
        count++
        if (count >= 2) return@collect
    }

    ctx.leave(identity = identity)
    println("[$name] Left context")
}

fun main() = runBlocking {
    // Create identities for coordinator and two agents
    val coordinator = Identity.create(custody = CustodyType.IN_MEMORY)
    val agentA = Identity.create(custody = CustodyType.IN_MEMORY)
    val agentB = Identity.create(custody = CustodyType.IN_MEMORY)

    // Coordinator creates the context
    val ctx = Context.create(
        identity = coordinator,
        ceiling = listOf(
            "messages:read",
            "messages:write",
            "tool:invoke:*",
            "member:invite",
            "member:remove",
            "role:assign",
        ),
        roles = mapOf("agent" to listOf("messages:write", "messages:read", "tool:invoke:*")),
        memoryScope = "ephemeral",
        governance = "single_admin",
    )
    println("Context created: ${ctx.contextId}")

    // Mint UCANs for each agent
    Ucan.mint(
        issuer = coordinator,
        audience = agentA.did,
        capabilities = listOf("messages:write", "messages:read"),
        contextId = ctx.contextId,
    )
    Ucan.mint(
        issuer = coordinator,
        audience = agentB.did,
        capabilities = listOf("messages:write", "messages:read"),
        contextId = ctx.contextId,
    )

    // Run agents concurrently
    val taskA = async { runAgent("Agent-A", agentA, ctx) }
    val taskB = async { runAgent("Agent-B", agentB, ctx) }
    taskA.await()
    taskB.await()

    ctx.close(identity = coordinator)
}
