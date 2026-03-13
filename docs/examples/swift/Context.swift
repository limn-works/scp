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

        // 2. Define context parameters.
        //    ContextParams is a UniFFI-generated struct with governance,
        //    memory scope, TTL, and capability ceiling.
        let params = ContextParams(
            ceiling: [
                "messages:read",
                "messages:write",
                "member:invite",
                "member:remove",
                "tool:register",
                "tool:invoke_all",
            ],
            governance: .singleAdmin,
            memoryScope: .full,
            ttlSeconds: 0,
            promotable: false,
            minProtocolVersion: 0
        )

        // 3. Create the context via the UniFFI bridge.
        //    Returns a ContextHandle -- the opaque reference to Rust state.
        let handle = try await contextCreate(identity: alice, params: params)

        print()
        print("Context created: \(handle.contextId())")
        print("  Creator: \(handle.creatorDid())")

        let state = try handle.state()
        print("  State: \(state)")

        // 4. Send a message to the context.
        let payload = "Hello, context!".data(using: .utf8)!
        try await contextSend(handle: handle, identity: alice, payload: payload)
        print("  Message sent successfully.")

        // 5. Subscribe to incoming messages via the MessageListener callback.
        //    In a real application, implement the MessageListener protocol and
        //    consume messages asynchronously:
        //
        //    class MyListener: MessageListener {
        //        func onMessage(message: Message) {
        //            let text = String(data: message.payload, encoding: .utf8) ?? "<binary>"
        //            print("[\(message.senderDid)] \(text)")
        //        }
        //        func onError(error: ScpError) { print("Error: \(error)") }
        //        func onComplete() { print("Stream complete.") }
        //    }
        //    try await contextSubscribe(handle: handle, listener: MyListener())
        //
        print("  (Message stream ready for consumption)")

        // 6. Bob joins the context.
        let bob = try await createIdentity(custody: "in_memory")
        try await contextJoin(handle: handle, identity: bob)
        print()
        print("Bob joined the context.")

        // 7. Leave the context gracefully.
        //    This sends a MemberLeft event and releases local resources.
        try await contextLeave(handle: handle, identity: alice)
        print("Left the context.")

        // Alternatively, close the context for all members:
        // try await contextClose(handle: handle, identity: alice)

        print()
        print("Context lifecycle complete.")
    }
}
