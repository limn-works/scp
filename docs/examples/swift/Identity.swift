/// Identity creation and DID document inspection.
///
/// Demonstrates creating a new SCP identity using did:dht,
/// inspecting the resulting DID document, and resolving it.
///
/// Prerequisites:
///   - Add the SCP Swift package to your project
///   - import SCP
///
/// Usage:
///   swift run Identity

import Foundation
import SCP

@main
struct IdentityExample {
    static func main() async throws {
        // 1. Create a new identity with in-memory key custody.
        //    In production, pass "encrypted_file" for the on-disk key store
        //    SCP implements, or "os_keystore" together with a
        //    KeyCustodyProvider to hold the keys in the Keychain. Section
        //    3.2.2 of the identity spec, the custody vocabulary, states those
        //    two values. Either call returns SCP-IDENT-1059 on a released
        //    framework, because no pre-rotation custody backend is wired yet.
        let identity = try await createIdentity(custody: "in_memory")

        print("DID: \(identity.did())")
        print("Custody: \(identity.custodyType())")
        print()

        // 2. Resolve the DID to its document.
        //    This queries the DHT and returns a DidDocument.
        let doc = try await resolveIdentity(did: identity.did())

        print("DID Document:")
        print("  ID: \(doc.id)")
        print("  Authentication methods: \(doc.authentication.count)")
        for vmId in doc.authentication {
            print("    - \(vmId)")
        }
        print("  Assertion methods: \(doc.assertionMethods.count)")
        print("  Service endpoints: \(doc.serviceEndpoints.count)")
        print()

        // 3. Create an identity with an agent signing key (ADR-039).
        //    Agent keys enable human+agent shared DID patterns.
        let agentIdentity = try await createIdentityWithAgentKey(
            custody: "in_memory"
        )
        print("Agent identity DID: \(agentIdentity.did())")

        // 4. Check for agent key and get its public key.
        let hasAgent = identityHasAgentKey(agentIdentity)
        print("  Has agent key: \(hasAgent)")

        if let pubKey = identityGetAgentPublicKey(agentIdentity) {
            print("  Agent public key: \(pubKey)")
        }
        print()

        // 5. Add an agent key to an existing identity.
        let withAgent = try await addAgentKeyToIdentity(identity)
        print("Added agent key to: \(withAgent.did())")

        // 6. Rotate the agent key.
        let rotated = try await rotateAgentKeyForIdentity(withAgent)
        print("Rotated agent key for: \(rotated.did())")

        // 7. Remove the agent key.
        let cleaned = try await removeAgentKeyFromIdentity(rotated)
        print("Removed agent key from: \(cleaned.did())")

        // 8. Load an existing identity by DID.
        let loaded = try await loadIdentity(did: identity.did())
        print("\nLoaded identity: \(loaded.did())")

        print()
        print("Identity operations complete.")
    }
}
