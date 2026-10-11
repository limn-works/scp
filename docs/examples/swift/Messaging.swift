/// Two-party message exchange within a context.
///
/// Demonstrates sending a message from one member and receiving it in
/// another member's node through a ``MessageListener``.
///
/// Alice and Bob each run their own `SCP` instance, and both reach each
/// other through the relay at `relayURL`. Bob must already be a member of
/// the context: `ContextExample` shows the invite-and-join handshake that
/// produces `aliceHandle` and `bobHandle`.
///
/// Prerequisites:
///   - Add the SCP Swift package to your project
///   - import SCP
///
/// Usage:
///   try await MessagingExample.run(
///       aliceNode: aliceNode, alice: alice, aliceHandle: aliceHandle,
///       bobNode: bobNode, bob: bob, bobHandle: bobHandle,
///       relayURL: "wss://relay.example")

import Foundation
import SCP

/// Prints each message the context delivers to Bob's node.
final class PrintingListener: MessageListener, @unchecked Sendable {
    func onMessage(message: Message) {
        let text = String(data: message.payload, encoding: .utf8) ?? "<binary>"
        print("[\(message.senderDid)] \(text)")
    }

    func onError(error: ScpError) {
        print("Stream error: \(error)")
    }

    func onComplete() {
        print("Stream complete.")
    }
}

enum MessagingExample {
    static func run(
        aliceNode: SCP,
        alice: Identity,
        aliceHandle: ContextHandle,
        bobNode: SCP,
        bob: Identity,
        bobHandle: ContextHandle,
        relayURL: String
    ) async throws {
        // 1. Point each node at the relay that carries the context's traffic.
        try await aliceNode.configureRelayTransport(relayUrl: relayURL, localDid: alice.did())
        try await bobNode.configureRelayTransport(relayUrl: relayURL, localDid: bob.did())

        // 2. Bob subscribes. The listener runs once per delivered message.
        try await bobNode.contextSubscribe(handle: bobHandle, listener: PrintingListener())

        // 3. Alice sends a message. A context without an economic policy
        //    needs no spending UCAN.
        try await aliceNode.contextSend(
            handle: aliceHandle,
            identity: alice,
            payload: Data("Hello Bob!".utf8),
            spendingUcanJwt: nil
        )
        print("Alice: Hello Bob!")

        // 4. Bob replies.
        try await bobNode.contextSend(
            handle: bobHandle,
            identity: bob,
            payload: Data("Hi Alice!".utf8),
            spendingUcanJwt: nil
        )
        print("Bob: Hi Alice!")

        // 5. Bob leaves. His stream completes.
        try await bobNode.contextLeave(handle: bobHandle, identity: bob)
        print("\nBob left the context.")
        print("Message exchange complete.")
    }
}
