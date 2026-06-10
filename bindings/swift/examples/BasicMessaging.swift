// Basic messaging: create identity, create context, send and receive messages.
//
// Demonstrates the SCP Swift SDK `SCP` class: instantiate once, then call
// instance methods for identity, context lifecycle, and messaging.

import Foundation
import SCP

@main
struct BasicMessaging {
    // swiftlint:disable:next function_body_length
    static func main() async throws {
        // Instantiate SCP (in_memory custody for examples).
        let scp = try SCP(storage: .inMemory)
        defer { Task { try? await scp.shutdown(timeout: 5) } }

        // Create two identities via the SDK wrapper function.
        let alice = try await scp.identityCreate(custody: "in_memory")
        let bob = try await scp.identityCreate(custody: "in_memory")
        print("Alice DID: \(alice.did())")
        print("Bob DID: \(bob.did())")

        // Alice creates a context.
        let params = ContextParams(
            mode: .encrypted,
            ceiling: ["messages:read", "messages:write", "member:invite"],
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
        let handle = try await scp.contextCreate(identity: alice, params: params)
        print("Context ID: \(handle.contextId())")

        // Bob joins the context
        try await scp.contextJoin(handle: handle, identity: bob, spendingUcanJwt: nil)

        // Send a message
        try await scp.contextSend(
            handle: handle,
            identity: alice,
            payload: Data("Hello Bob, this is Alice".utf8),
            spendingUcanJwt: nil
        )

        // Subscribe to messages via the MessageListener callback.
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

        for await msg in stream {
            // swiftlint:disable:next optional_data_string_conversion
            let text = String(decoding: msg.payload, as: UTF8.self)
            print("Bob received from \(msg.senderDid): \(text)")
            break
        }

        // Cleanup
        try await scp.contextLeave(handle: handle, identity: bob)
        try await scp.contextClose(handle: handle, identity: alice)
    }
}
