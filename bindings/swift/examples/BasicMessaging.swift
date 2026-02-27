/// Basic messaging: create identity, create context, send and receive messages.

import SCP
import Foundation

@main
struct BasicMessaging {
    static func main() async throws {
        // Create two identities
        let alice = try await Identity.create(custody: "platform")
        let bob = try await Identity.create(custody: "platform")
        print("Alice DID: \(alice.did)")
        print("Bob DID: \(bob.did)")

        // Alice creates a context
        let ctxAlice = try await Context.create(
            identity: alice,
            params: ContextParams(
                ceiling: ["msg:send", "msg:receive"],
                ttl: 3600,
                governance: "single_admin"
            )
        )
        print("Context ID: \(ctxAlice.contextId)")

        // Bob joins the context
        let ctxBob = try await Context.join(identity: bob, contextId: ctxAlice.contextId)

        // Alice sends a message
        try await ctxAlice.send(Data("Hello Bob, this is Alice".utf8))

        // Bob receives it
        for await msg in ctxBob.messages {
            let text = String(data: msg.content, encoding: .utf8)!
            print("Bob received from \(msg.senderDid): \(text)")
            break
        }

        // Cleanup
        try await ctxBob.leave()
        try await ctxAlice.close()
    }
}
