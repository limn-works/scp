/// Context creation and lifecycle management.
///
/// Demonstrates creating an SCP context with governance parameters,
/// inspecting its state, sending messages, and managing membership.
///
/// Prerequisites:
///   - Add the SCP Swift package to your project
///   - import SCP
///
/// Usage:
///   swift run Context

import Foundation
import SCP

@main
struct ContextExample {
    static func main() async throws {
        // 1. Create the identity that will own the context.
        let alice = try await createIdentity(custody: "in_memory")
        print("Alice DID: \(alice.did())")

        // 2. Define the capability ceiling for the context.
        let ceiling = [
            "messages:read",
            "messages:write",
            "member:invite",
            "member:remove",
            "tool:register",
            "tool:invoke_all",
        ]

        // 3. Create the context.
        //    Context is an actor -- all operations are async and thread-safe.
        //    The injectable bridge pattern allows test injection of all
        //    UniFFI functions.
        let ctx = try await Context.create(
            contextId: "demo-context",
            ceiling: ceiling,
            createFn: ContextBridge.defaultCreate,
            sendFn: ContextBridge.defaultSend,
            subscribeFn: ContextBridge.defaultSubscribe,
            leaveFn: ContextBridge.defaultLeave,
            closeFn: ContextBridge.defaultClose
        )

        print()
        print("Context created: \(ctx.contextId)")
        print("  Creator: \(ctx.creatorDid)")

        let state = await ctx.state
        print("  State: \(state)")

        // 4. Send a message to the context.
        let payload = "Hello, context!".data(using: .utf8)!
        try await ctx.send(payload)
        print("  Message sent successfully.")

        // 5. Subscribe to incoming messages via AsyncStream.
        //    In a real application, consume this in a long-running task:
        //
        //    let stream = try await ctx.messages
        //    for await message in stream {
        //        print("[\(message.senderDid)] \(message.payload)")
        //    }
        //
        //    The stream finishes when the context is closed or left.
        print("  (Message stream ready for consumption)")

        // 6. Bob joins the context.
        let bob = try await createIdentity(custody: "in_memory")
        let handle = ctx.handle as! ContextHandle
        try await joinContext(handle: handle, identity: bob)
        print()
        print("Bob joined the context.")

        // 7. Leave the context gracefully.
        //    This sends a MemberLeft event and releases local resources.
        try await ctx.leave()
        print("Left the context.")

        // Alternatively, close the context for all members:
        // try await ctx.close()

        print()
        print("Context lifecycle complete.")
    }
}
