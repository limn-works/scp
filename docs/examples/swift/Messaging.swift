/// Two-participant message exchange.
///
/// Demonstrates creating a context, adding a second participant,
/// and exchanging messages between them. Shows how the AsyncStream
/// delivers messages using Swift structured concurrency.
///
/// Prerequisites:
///   - Add the SCP Swift package to your project
///   - import SCP
///
/// Usage:
///   swift run Messaging

import Foundation
import SCP

@main
struct MessagingExample {
    static func main() async throws {
        // 1. Create two identities.
        let alice = try await createIdentity(custody: "in_memory")
        let bob = try await createIdentity(custody: "in_memory")
        print("Alice: \(alice.did())")
        print("Bob:   \(bob.did())")

        // 2. Alice creates a context with messaging capabilities.
        let ceiling = [
            "messages:read",
            "messages:write",
            "member:invite",
            "member:remove",
        ]

        let ctx = try await Context.create(
            contextId: "chat-demo",
            ceiling: ceiling,
            createFn: ContextBridge.defaultCreate,
            sendFn: ContextBridge.defaultSend,
            subscribeFn: ContextBridge.defaultSubscribe,
            leaveFn: ContextBridge.defaultLeave,
            closeFn: ContextBridge.defaultClose
        )
        print("\nContext: \(ctx.contextId)")

        // 3. Bob joins the context.
        let handle = ctx.handle as! ContextHandle
        try await joinContext(handle: handle, identity: bob)
        print("Bob joined the context.")

        // 4. Alice sends a message.
        let msg1 = "Hello Bob!".data(using: .utf8)!
        try await ctx.send(msg1)
        print("\nAlice: Hello Bob!")

        // 5. Bob sends a reply.
        let msg2 = "Hi Alice!".data(using: .utf8)!
        try await ctx.send(msg2)
        print("Bob: Hi Alice!")

        // 6. Consume messages via AsyncStream.
        //    In a real application, this would run in a separate task:
        //
        //    Task {
        //        let stream = try await ctx.messages
        //        for await message in stream {
        //            let text = String(data: message.payload, encoding: .utf8) ?? "<binary>"
        //            print("[\(message.senderDid)] \(text)")
        //        }
        //        print("Stream finished.")
        //    }
        //
        //    The AsyncStream is backed by a UniFFI MessageListener callback.
        //    It finishes when the context is closed or left. Only one active
        //    stream per context is supported.
        print("\n(Message stream ready for consumption)")

        // 7. Clean up.
        try await ctx.leave()
        print("\nLeft the context.")
        print("Message exchange complete.")
    }
}
