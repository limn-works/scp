// Multi-agent coordination: multiple agents collaborating in a shared context.
//
// Demonstrates identity creation, context creation with governance, UCAN
// minting, message sending, and message receiving using the actual SCP
// Swift SDK API surface.

import Foundation
import SCP

@main
struct MultiAgent {
    static func runAgent(
        name: String,
        identity: Identity,
        handle: ContextHandle
    ) async throws {
        // Agent joins the existing context
        try await contextJoin(handle: handle, identity: identity)
        print("[\(name)] Joined context \(handle.contextId())")

        // Send a message via the bridge function
        try await contextSend(
            handle: handle,
            identity: identity,
            payload: Data("[\(name)] reporting in".utf8)
        )

        // Subscribe to messages
        let (stream, continuation) = AsyncStream<Message>.makeStream()
        final class Listener: MessageListener, @unchecked Sendable {
            let continuation: AsyncStream<Message>.Continuation
            init(_ cont: AsyncStream<Message>.Continuation) {
                continuation = cont
            }

            func onMessage(message: Message) {
                continuation.yield(message)
            }

            func onError(error _: ScpError) {
                continuation.finish()
            }

            func onComplete() {
                continuation.finish()
            }
        }
        try await contextSubscribe(handle: handle, listener: Listener(continuation))

        var count = 0
        for await msg in stream {
            // swiftlint:disable:next optional_data_string_conversion
            let text = String(decoding: msg.payload, as: UTF8.self)
            let sender = String(msg.senderDid.prefix(16))
            print("[\(name)] Received from \(sender)...: \(text)")
            count += 1
            if count >= 2 { break }
        }

        try await contextLeave(handle: handle, identity: identity)
        print("[\(name)] Left context")
    }

    static func main() async throws {
        // Create identities for coordinator and two agents
        let coordinator = try await identityCreate(custody: "in_memory")
        let agentA = try await identityCreate(custody: "in_memory")
        let agentB = try await identityCreate(custody: "in_memory")

        // Coordinator creates the context
        let params = ContextParams(
            ceiling: [
                "messages:read",
                "messages:write",
                "tool:invoke:*",
                "member:invite",
                "member:remove",
                "role:assign"
            ],
            governance: .singleAdmin,
            memoryScope: .ephemeral,
            ttlSeconds: 3600,
            promotable: false,
            minProtocolVersion: 0
        )
        let handle = try await contextCreate(identity: coordinator, params: params)
        print("Context created: \(handle.contextId())")

        // Mint UCANs for each agent via the bridge function
        _ = try await ucanMint(
            handle: handle,
            memberDid: agentA.did(),
            capabilities: ["messages:write", "messages:read"]
        )
        _ = try await ucanMint(
            handle: handle,
            memberDid: agentB.did(),
            capabilities: ["messages:write", "messages:read"]
        )

        // Run agents concurrently
        async let taskA: Void = runAgent(name: "Agent-A", identity: agentA, handle: handle)
        async let taskB: Void = runAgent(name: "Agent-B", identity: agentB, handle: handle)
        _ = try await (taskA, taskB)

        try await contextClose(handle: handle, identity: coordinator)
    }
}
