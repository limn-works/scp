/// Identity creation and DID document inspection.
///
/// Demonstrates creating a new SCP identity using did:dht,
/// inspecting the resulting DID document, and resolving it.
///
/// The Swift SDK ships no production key store that `identityCreate(custody:)`
/// reaches; the doc comment on ``CustodyType`` states how a shipped build
/// answers each case. A production caller passes ``AppleKeyCustody``, the
/// SDK's ``KeyCustodyProvider`` over the Keychain, to
/// `identityCreateWithCustody`. A shipped build refuses that call with
/// `SCP-IDENT-1100`, as it refuses every identity creation.
///
/// Prerequisites:
///   - Add the SCP Swift package to your project
///   - import SCP
///
/// Usage:
///   try await IdentityExample.run(provider: myProvider, storagePassphrase: passphrase)

import Foundation
import SCP

enum IdentityExample {
    static func run(provider: KeyCustodyProvider, storagePassphrase: String) async throws {
        let storageDir = try FileManager.default
            .url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
            .appendingPathComponent("scp-identity-example")
        let scp = try SCP.withStorage(sqliteDir: storageDir, passphrase: storagePassphrase)

        // 1. Create a new identity whose keys the caller's provider holds.
        let identity = try await scp.identityCreateWithCustody(provider: provider)

        print("DID: \(identity.did())")
        print("Custody: \(identity.custodyType())")
        print()

        // 2. Resolve the DID to its document.
        //    This queries the DHT and returns a DidDocument.
        let doc = try await identityResolve(did: identity.did())

        print("DID Document:")
        print("  ID: \(doc.id)")
        print("  Authentication methods: \(doc.authentication.count)")
        for vmId in doc.authentication {
            print("    - \(vmId)")
        }
        print("  Assertion methods: \(doc.assertionMethods.count)")
        print("  Service endpoints: \(doc.serviceEndpoints.count)")
        print()

        // 3. Add an agent key to the identity.
        let withAgent = try await identity.addAgentKey()
        print("Added agent key to: \(withAgent.did())")
        print("  Has agent key: \(withAgent.hasAgentKey())")
        if let pubKey = withAgent.getAgentPublicKey() {
            print("  Agent public key: \(pubKey)")
        }

        // 4. Rotate the agent key.
        let rotated = try await withAgent.rotateAgentKey()
        print("Rotated agent key for: \(rotated.did())")

        // 5. Remove the agent key.
        let cleaned = try await rotated.removeAgentKey()
        print("Removed agent key from: \(cleaned.did())")

        // 6. Load an existing identity by DID.
        let loaded = try await scp.identityLoad(did: identity.did())
        print("\nLoaded identity: \(loaded.did())")

        try await scp.shutdown()
        print()
        print("Identity operations complete.")
    }
}
