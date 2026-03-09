// Multi-agent coordination: multiple agents collaborating in a shared context.

import Foundation
import SCP

@main
struct MultiAgent {
    static func runAgent(name: String, identity: Identity, contextId: String) async throws {
        let ctx = try await Context.join(identity: identity, contextId: contextId)
        print("[\(name)] Joined context \(contextId)")

        try await ctx.send(Data("[\(name)] reporting in".utf8))

        var count = 0
        for await msg in ctx.messages {
            // swiftlint:disable:next optional_data_string_conversion
            let text = String(decoding: msg.content, as: UTF8.self)
            let sender = String(msg.senderDid.prefix(16))
            print("[\(name)] Received from \(sender)...: \(text)")
            count += 1
            if count >= 2 { break }
        }

        try await ctx.leave()
        print("[\(name)] Left context")
    }

    static func main() async throws {
        // Create identities for coordinator and two agents
        let coordinator = try await Identity.create(custody: "platform")
        let agentA = try await Identity.create(custody: "platform")
        let agentB = try await Identity.create(custody: "platform")

        // Coordinator creates the context
        let ctx = try await Context.create(
            identity: coordinator,
            params: ContextParams(
                ceiling: ["msg:send", "msg:receive", "tool:invoke"],
                roles: ["agent": ["msg:send", "msg:receive", "tool:invoke"]],
                governance: "single_admin"
            )
        )
        print("Context created: \(ctx.contextId)")

        // Mint UCANs for each agent
        _ = try await Ucan.mint(
            issuer: coordinator,
            audience: agentA.did,
            capabilities: ["msg:send", "msg:receive"],
            contextId: ctx.contextId
        )
        _ = try await Ucan.mint(
            issuer: coordinator,
            audience: agentB.did,
            capabilities: ["msg:send", "msg:receive"],
            contextId: ctx.contextId
        )

        // Run agents concurrently
        async let taskA: Void = runAgent(name: "Agent-A", identity: agentA, contextId: ctx.contextId)
        async let taskB: Void = runAgent(name: "Agent-B", identity: agentB, contextId: ctx.contextId)
        _ = try await (taskA, taskB)

        try await ctx.close()
    }
}
