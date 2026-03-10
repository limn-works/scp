// Basic messaging: create identity, create context, send and receive messages.
//
// Demonstrates the actual SCP Swift SDK API surface. Identity creation uses
// the UniFFI `identityCreate` free function, context creation uses
// `contextCreate`, and the `Context` actor wraps the handle for send/receive.

import Foundation
import SCP

@main
struct BasicMessaging {
    static func main() async throws {
        // Create two identities via the UniFFI bridge function
        let alice = try await identityCreate(custody: "platform")
        let bob = try await identityCreate(custody: "platform")
        print("Alice DID: \(alice.did())")
        print("Bob DID: \(bob.did())")

        // Alice creates a context via the UniFFI bridge function.
        // ContextParams requires: ceiling, governance, memoryScope, ttlSeconds, promotable
        let params = ContextParams(
            ceiling: ["msg:send", "msg:receive"],
            governance: .singleAdmin,
            memoryScope: .ephemeral,
            ttlSeconds: 3600,
            promotable: false
        )
        let aliceHandle = try await contextCreate(identity: alice, params: params)
        print("Context ID: \(aliceHandle.contextId())")

        // Bob joins the context using the existing handle
        try await contextJoin(handle: aliceHandle, identity: bob)

        // Send a message via the UniFFI bridge function
        try await contextSend(
            handle: aliceHandle,
            identity: alice,
            payload: Data("Hello Bob, this is Alice".utf8)
        )

        // Subscribe to messages via the UniFFI bridge and AsyncStream adapter.
        // In production, the Context actor wraps this pattern:
        //   let stream = try await context.messages
        //   for await msg in stream { ... }
        //
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
        try await contextSubscribe(handle: aliceHandle, listener: Listener(continuation))

        for await msg in stream {
            // swiftlint:disable:next optional_data_string_conversion
            let text = String(decoding: msg.payload, as: UTF8.self)
            print("Bob received from \(msg.senderDid): \(text)")
            break
        }

        // Cleanup
        try await contextLeave(handle: aliceHandle, identity: bob)
        try await contextClose(handle: aliceHandle, identity: alice)
    }
}
