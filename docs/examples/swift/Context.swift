/// Context creation and the invite-and-join handshake.
///
/// Demonstrates creating an SCP context with governance parameters,
/// inviting a second identity, joining from the sealed invitation, and
/// reading the membership.
///
/// The creator and the joiner each run their own `SCP` instance with its own
/// database, as two devices would, and each passes its own
/// ``KeyCustodyProvider``. ``CustodyType/inMemory`` works only in a build
/// compiled with the `testing` feature.
///
/// Prerequisites:
///   - Add the SCP Swift package to your project
///   - import SCP
///
/// Usage:
///   try await ContextExample.run(
///       aliceProvider: aliceProvider, bobProvider: bobProvider, storagePassphrase: passphrase)

import Foundation
import SCP

enum ContextExample {
    static func run(
        aliceProvider: KeyCustodyProvider,
        bobProvider: KeyCustodyProvider,
        storagePassphrase: String
    ) async throws {
        let support = try FileManager.default
            .url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let aliceNode = try SCP.withStorage(
            sqliteDir: support.appendingPathComponent("scp-context-alice"), passphrase: storagePassphrase)
        let bobNode = try SCP.withStorage(
            sqliteDir: support.appendingPathComponent("scp-context-bob"), passphrase: storagePassphrase)

        // 1. Each side creates its identity in its own node.
        let alice = try await aliceNode.identityCreateWithCustody(provider: aliceProvider)
        let bob = try await bobNode.identityCreateWithCustody(provider: bobProvider)
        print("Alice DID: \(alice.did())")
        print("Bob DID:   \(bob.did())")

        // 2. Define context parameters. The ceiling caps what any member can
        //    hold. Inviting runs through the governance gate, so the ceiling
        //    must carry governance:propose.
        let params = ContextParams(
            mode: .encrypted,
            ceiling: [
                "messages:read",
                "messages:write",
                "member:invite",
                "member:remove",
                "governance:propose",
            ],
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

        // 3. Alice creates the context. The returned ContextHandle is the
        //    reference every later context call takes.
        let handle = try await aliceNode.contextCreate(identity: alice, params: params)
        print()
        print("Context created: \(handle.contextId())")
        print("  Creator: \(handle.creatorDid())")
        print("  State: \(try handle.state())")

        // 4. Bob reserves a single-use KeyPackage and hands Alice its public
        //    bytes out of band.
        let reservation = try await bobNode.reserveKeyPackage(identity: bob)

        // 5. Alice seals an invitation to that KeyPackage. An empty relay list
        //    means Alice delivers the sealed bundle to Bob herself.
        let outcome = try await aliceNode.inviteMember(
            identity: alice,
            contextId: handle.contextId(),
            inviteeDid: bob.did(),
            inviteeKeyPackage: reservation.keyPackagePublic,
            relayUrls: []
        )
        let bundle: SealedInvitation
        switch outcome {
        case let .sealed(sealed, _):
            bundle = sealed
        }

        // 6. Bob opens the sealed bundle and joins.
        let bobHandle = try await bobNode.contextJoinFromWelcome(
            identity: bob,
            sealed: bundle,
            reservationId: reservation.reservationId
        )
        print()
        print("Bob joined context: \(bobHandle.contextId())")

        // 7. Read the membership from Alice's node.
        let members = await aliceNode.contextMemberDids(handle: handle)
        print("Members: \(members)")

        // 8. Close the context for every member.
        try await aliceNode.contextClose(handle: handle, identity: alice)
        print("Context closed.")

        try await bobNode.shutdown()
        try await aliceNode.shutdown()
        print()
        print("Context lifecycle complete.")
    }
}
