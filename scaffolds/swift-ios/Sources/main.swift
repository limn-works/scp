/// Minimal SCP iOS app scaffold.
///
/// Creates a DID identity with Keychain custody, opens an encrypted context,
/// and sends a message. Replace mock values with real relay URLs for production.

import Foundation
import SCP

@main
struct SCPiOSApp {
    static func main() async throws {
        // 1. Create a DID identity. No custody string reaches the Keychain —
        //    the bridge answers "platform" with SCP-IDENT-1003 — so hold keys
        //    in the Keychain by injecting a KeyCustodyProvider through
        //    identityCreateWithCustody instead. This in-memory store loses
        //    every key on process exit.
        let identity = try await createIdentity(custody: CustodyType.inMemory.rawValue)
        print("Created identity: \(identity.did())")

        // 2. Create an encrypted context via the UniFFI bridge.
        let params = ContextParams(
            ceiling: ["messages:read", "messages:write", "role:assign"],
            governance: .singleAdmin,
            memoryScope: .full,
            ttlSeconds: 0,
            promotable: false,
            minProtocolVersion: 0
        )
        let handle = try await contextCreate(identity: identity, params: params)
        print("Created context: \(handle.contextId())")

        // 3. Send a message.
        let payload = "Hello from iOS!".data(using: .utf8)!
        try await contextSend(handle: handle, identity: identity, payload: payload)
        print("Message sent.")

        // 4. Clean up.
        try await contextLeave(handle: handle, identity: identity)
        print("Done.")
    }
}
