// Multi-agent coordination: multiple agents collaborating in a shared context.
//
// Demonstrates the SCP Swift SDK `SCP` class: shared instance across
// agents, identity creation, UCAN minting, message sending, and message
// receiving.

import Foundation
import SCP

@main
struct MultiAgent {
    static func runAgent(
        scp: SCP,
        name: String,
        identity: Identity,
        handle: ContextHandle
    ) async throws {
        try await scp.contextJoin(handle: handle, identity: identity, spendingUcanJwt: nil)
        print("[\(name)] Joined context \(handle.contextId())")

        try await scp.contextSend(
            handle: handle,
            identity: identity,
            payload: Data("[\(name)] reporting in".utf8),
            spendingUcanJwt: nil
        )

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
        try await scp.contextSubscribe(handle: handle, listener: Listener(continuation))

        var count = 0
        for await msg in stream {
            // swiftlint:disable:next optional_data_string_conversion
            let text = String(decoding: msg.payload, as: UTF8.self)
            let sender = String(msg.senderDid.prefix(16))
            print("[\(name)] Received from \(sender)...: \(text)")
            count += 1
            if count >= 2 {
                break
            }
        }

        try await scp.contextLeave(handle: handle, identity: identity)
        print("[\(name)] Left context")
    }

    static func main() async throws {
        let scp = try SCP(storage: .inMemory)
        defer { Task { try? await scp.shutdown(timeout: 5) } }

        let coordinator = try await scp.identityCreate(custody: .inMemory)
        let agentA = try await scp.identityCreate(custody: .inMemory)
        let agentB = try await scp.identityCreate(custody: .inMemory)

        let params = ContextParams(
            mode: .encrypted,
            ceiling: [
                "messages:read",
                "messages:write",
                "outlet:call:*",
                "member:invite",
                "member:remove",
                "role:assign"
            ],
            ceilingPolicy: .immutable,
            governance: .singleAdmin,
            memoryScope: .ephemeral,
            ttlSeconds: 3600,
            promotable: false,
            minProtocolVersion: 0,
            maxChainDepth: nil,
            maxNestingDepth: nil,
            sessionCap: nil,
            economicPolicy: nil
        )
        let handle = try await scp.contextCreate(identity: coordinator, params: params)
        print("Context created: \(handle.contextId())")

        _ = try await scp.ucanMint(
            handle: handle,
            memberDid: agentA.did(),
            capabilities: ["messages:write", "messages:read"],
            proofs: nil
        )
        _ = try await scp.ucanMint(
            handle: handle,
            memberDid: agentB.did(),
            capabilities: ["messages:write", "messages:read"],
            proofs: nil
        )

        async let taskA: Void = runAgent(scp: scp, name: "Agent-A", identity: agentA, handle: handle)
        async let taskB: Void = runAgent(scp: scp, name: "Agent-B", identity: agentB, handle: handle)
        _ = try await (taskA, taskB)

        try await scp.contextClose(handle: handle, identity: coordinator)
    }
}
