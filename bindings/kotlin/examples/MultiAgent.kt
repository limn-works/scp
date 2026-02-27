/** Multi-agent coordination: multiple agents collaborating in a shared context. */

package com.limn.scp.examples

import com.limn.scp.Context
import com.limn.scp.Identity
import com.limn.scp.Ucan
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.runBlocking

suspend fun runAgent(name: String, identity: Identity, contextId: String) {
    val ctx = Context.join(identity = identity, contextId = contextId)
    println("[$name] Joined context $contextId")

    ctx.send("[$name] reporting in".toByteArray())

    var count = 0
    ctx.receiveFlow().collect { msg ->
        val sender = msg.senderDid.take(16)
        println("[$name] Received from $sender...: ${String(msg.content)}")
        count++
        if (count >= 2) return@collect
    }

    ctx.leave()
    println("[$name] Left context")
}

fun main() = runBlocking {
    // Create identities for coordinator and two agents
    val coordinator = Identity.create(custody = "platform")
    val agentA = Identity.create(custody = "platform")
    val agentB = Identity.create(custody = "platform")

    // Coordinator creates the context
    val ctx = Context.create(
        identity = coordinator,
        params = mapOf(
            "ceiling" to listOf("msg:send", "msg:receive", "tool:invoke"),
            "roles" to mapOf("agent" to listOf("msg:send", "msg:receive", "tool:invoke")),
            "governance" to "single_admin",
        ),
    )
    println("Context created: ${ctx.contextId}")

    // Mint UCANs for each agent
    Ucan.mint(
        issuer = coordinator,
        audience = agentA.did,
        capabilities = listOf("msg:send", "msg:receive"),
        contextId = ctx.contextId,
    )
    Ucan.mint(
        issuer = coordinator,
        audience = agentB.did,
        capabilities = listOf("msg:send", "msg:receive"),
        contextId = ctx.contextId,
    )

    // Run agents concurrently
    val taskA = async { runAgent("Agent-A", agentA, ctx.contextId) }
    val taskB = async { runAgent("Agent-B", agentB, ctx.contextId) }
    taskA.await()
    taskB.await()

    ctx.close()
}
