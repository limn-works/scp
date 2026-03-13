/// Two-participant message exchange.
///
/// Demonstrates creating a context, adding a second participant,
/// and exchanging messages between them. Shows the UniFFI bridge
/// functions for context operations and message delivery.
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
        let params = ContextParams(
            ceiling: [
                "messages:read",
                "messages:write",
                "member:invite",
                "member:remove",
            ],
            governance: .singleAdmin,
            memoryScope: .full,
            ttlSeconds: 0,
            promotable: false,
            minProtocolVersion: 0
        )

        let handle = try await contextCreate(identity: alice, params: params)
        print("\nContext: \(handle.contextId())")

        // 3. Bob joins the context.
        try await contextJoin(handle: handle, identity: bob)
        print("Bob joined the context.")

        // 4. Alice sends a message.
        let msg1 = "Hello Bob!".data(using: .utf8)!
        try await contextSend(handle: handle, identity: alice, payload: msg1)
        print("\nAlice: Hello Bob!")

        // 5. Bob sends a reply.
        let msg2 = "Hi Alice!".data(using: .utf8)!
        try await contextSend(handle: handle, identity: bob, payload: msg2)
        print("Bob: Hi Alice!")

        // 6. Consume messages via a MessageListener.
        //    In a real application, implement the MessageListener protocol:
        //
        //    class ChatListener: MessageListener {
        //        func onMessage(message: Message) {
        //            let text = String(data: message.payload, encoding: .utf8) ?? "<binary>"
        //            print("[\(message.senderDid)] \(text)")
        //        }
        //        func onError(error: ScpError) { print("Error: \(error)") }
        //        func onComplete() { print("Stream complete.") }
        //    }
        //    try await contextSubscribe(handle: handle, listener: ChatListener())
        //
        //    Messages are delivered via the UniFFI callback interface.
        //    The stream finishes when the context is closed or left.
        print("\n(Message stream ready for consumption)")

        // 7. Clean up.
        try await contextLeave(handle: handle, identity: alice)
        print("\nLeft the context.")
        print("Message exchange complete.")
    }
}
