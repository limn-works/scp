// Basic messaging: create identity, create context, send and receive messages.
//
// Demonstrates the SCP Swift SDK wrapper API: `createIdentity()` for identity
// creation, `contextCreate()` for context creation, `contextSend()` for
// messaging, and the `MessageListener` callback pattern for receiving.

import Foundation
import SCP

@main
struct BasicMessaging {
    static func main() async throws {
        // Create two identities via the SDK wrapper function (in_memory custody for examples)
        let alice = try await createIdentity(custody: "in_memory")
        let bob = try await createIdentity(custody: "in_memory")
        print("Alice DID: \(alice.did())")
        print("Bob DID: \(bob.did())")

        // Alice creates a context.
        // ContextParams requires: ceiling, governance, memoryScope, ttlSeconds, promotable, minProtocolVersion
        let params = ContextParams(
            ceiling: ["messages:read", "messages:write", "member:invite"],
            governance: .singleAdmin,
            memoryScope: .ephemeral,
            ttlSeconds: 3600,
            promotable: false,
            minProtocolVersion: 0,
            maxChainDepth: nil,
            maxNestingDepth: nil,
            sessionCap: nil
        )
        let handle = try await contextCreate(identity: alice, params: params)
        print("Context ID: \(handle.contextId())")

        // Bob joins the context
        try await contextJoin(handle: handle, identity: bob)

        // Send a message via the UniFFI bridge function
        try await contextSend(
            handle: handle,
            identity: alice,
            payload: Data("Hello Bob, this is Alice".utf8)
        )

        // Subscribe to messages via the MessageListener callback pattern.
        // The SDK's Context actor wraps this into an AsyncStream via `context.messages`.
        // Here we use the bridge directly for illustration:
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

        for await msg in stream {
            // swiftlint:disable:next optional_data_string_conversion
            let text = String(decoding: msg.payload, as: UTF8.self)
            print("Bob received from \(msg.senderDid): \(text)")
            break
        }

        // Cleanup
        try await contextLeave(handle: handle, identity: bob)
        try await contextClose(handle: handle, identity: alice)
    }
}
