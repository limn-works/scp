// The quick start from `bindings/swift/README.md`, copied byte for byte below
// this header. `ReadmeQuickStartTests` fails when the copy and the README block
// differ, and runs `runQuickStart()`, so the README block compiles and runs as
// written. Edit both copies together.

import Foundation
import SCP

func runQuickStart() async throws {
    // Every call goes through an SCP instance, which takes a required storage backend.
    let scp = try SCP(storage: .inMemory)

    // Create a cryptographic identity (DID) whose keys live in the encrypted key file.
    let identity = try await scp.identityCreate(custody: .encryptedFile)
    print("DID: \(identity.did())")

    // Create an encrypted context that this identity administers.
    let ctx = try await scp.contextCreate(
        identity: identity,
        params: ContextParams(
            mode: .encrypted,
            ceiling: ["messages:read", "messages:write", "context:close"],
            ceilingPolicy: .immutable,
            governance: .singleAdmin,
            memoryScope: .ephemeral,
            ttlSeconds: 3600,
            promotable: false,
            minProtocolVersion: 0,
            maxChainDepth: nil,
            maxNestingDepth: nil,
            sessionCap: nil,
            economicPolicy: nil,
            consequenceRulesJson: nil,
            consequenceConfigJson: nil,
            capabilityRequirementsJson: nil
        )
    )

    // Send a message (MLS-encrypted, signed, provenance-tagged).
    try await scp.contextSend(
        handle: ctx,
        identity: identity,
        payload: Data("Hello from SCP".utf8),
        spendingUcanJwt: nil
    )

    try await scp.contextClose(handle: ctx, identity: identity)
    try await scp.shutdown()
}
