/// Two-party message exchange within a context over a relay.
///
/// Demonstrates attaching each node to a relay, the invite-and-join
/// handshake, sending a message from one member, and receiving it in the
/// other member's node through a ``MessageListener``.
///
/// Alice and Bob each run their own `SCP` instance with its own database, and
/// both reach the relay at `relayURL`. Each node attaches the relay before it
/// creates or joins any context: the first context starts the node's context
/// supervisor, which binds the transport it finds then, and a later
/// `configureRelayTransport` call attaches nothing.
///
/// Prerequisites:
///   - Add the SCP Swift package to your project
///   - import SCP
///
/// Usage:
///   try await MessagingExample.run(
///       aliceProvider: aliceProvider, bobProvider: bobProvider,
///       relayURL: "wss://relay.example.com", storagePassphrase: passphrase)

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
    /// A send fails with this code until the peer's routing announcement has
    /// arrived over the relay (spec §9.10.4). The send is rolled back, so a
    /// retry is safe.
    static let noPeerRoute = "SCP-CTX-2095"
    static let sendAttempts = 10

    static func run(
        aliceProvider: KeyCustodyProvider,
        bobProvider: KeyCustodyProvider,
        relayURL: String,
        storagePassphrase: String
    ) async throws {
        let support = try FileManager.default
            .url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let aliceNode = try SCP.withStorage(
            sqliteDir: support.appendingPathComponent("scp-messaging-alice"), passphrase: storagePassphrase)
        let bobNode = try SCP.withStorage(
            sqliteDir: support.appendingPathComponent("scp-messaging-bob"), passphrase: storagePassphrase)

        // 1. Each side creates its identity and attaches the relay before
        //    any context exists.
        let alice = try await aliceNode.identityCreateWithCustody(provider: aliceProvider)
        let bob = try await bobNode.identityCreateWithCustody(provider: bobProvider)
        try await aliceNode.configureRelayTransport(relayUrl: relayURL, localDid: alice.did())
        try await bobNode.configureRelayTransport(relayUrl: relayURL, localDid: bob.did())
        _ = try await aliceNode.transportConnect(relayUrl: relayURL)
        _ = try await bobNode.transportConnect(relayUrl: relayURL)

        // 2. Alice creates the context. Inviting runs through the governance
        //    gate, so the ceiling carries governance:propose.
        let params = ContextParams(
            mode: .encrypted,
            ceiling: ["messages:read", "messages:write", "member:invite", "governance:propose"],
            ceilingPolicy: .immutable,
            governance: .singleAdmin,
            memoryScope: .ephemeral,
            ttlSeconds: 0,
            promotable: false,
            minProtocolVersion: 0,
            maxChainDepth: nil,
            maxNestingDepth: nil,
            sessionCap: nil,
            economicPolicy: nil,
            consequenceRulesJson: nil,
            consequenceConfigJson: nil
        )
        let aliceHandle = try await aliceNode.contextCreate(identity: alice, params: params)

        // 3. Bob reserves a KeyPackage, Alice seals an invitation to it, and
        //    Bob joins from the sealed bundle.
        let reservation = try await bobNode.reserveKeyPackage(identity: bob)
        let outcome = try await aliceNode.inviteMember(
            identity: alice,
            contextId: aliceHandle.contextId(),
            inviteeDid: bob.did(),
            inviteeKeyPackage: reservation.keyPackagePublic,
            relayUrls: [relayURL]
        )
        let bundle: SealedInvitation
        switch outcome {
        case let .sealed(sealed, _):
            bundle = sealed
        }
        let bobHandle = try await bobNode.contextJoinFromWelcome(
            identity: bob,
            sealed: bundle,
            reservationId: reservation.reservationId
        )

        // 4. Bob subscribes. The listener runs once per delivered message.
        try await bobNode.contextSubscribe(handle: bobHandle, listener: PrintingListener())

        // 5. Alice sends a message. A context without an economic policy
        //    needs no spending UCAN.
        try await sendWhenRoutable(node: aliceNode, handle: aliceHandle, identity: alice, text: "Hello Bob!")
        print("Alice: Hello Bob!")

        // 6. Bob replies.
        try await sendWhenRoutable(node: bobNode, handle: bobHandle, identity: bob, text: "Hi Alice!")
        print("Bob: Hi Alice!")

        // 7. Bob leaves. His stream completes.
        try await bobNode.contextLeave(handle: bobHandle, identity: bob)
        print("\nBob left the context.")

        try await bobNode.shutdown()
        try await aliceNode.shutdown()
        print("Message exchange complete.")
    }

    /// Sends `text`, retrying only while the peer's route is unknown.
    static func sendWhenRoutable(
        node: SCP, handle: ContextHandle, identity: Identity, text: String
    ) async throws {
        for attempt in 1...sendAttempts {
            do {
                try await node.contextSend(
                    handle: handle, identity: identity, payload: Data(text.utf8), spendingUcanJwt: nil)
                return
            } catch ScpError.Context(_, let code) where code == noPeerRoute && attempt < sendAttempts {
                try await Task.sleep(nanoseconds: 500_000_000)
            }
        }
    }
}
