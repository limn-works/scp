/// Minimal SCP macOS app scaffold.
///
/// Creates a DID identity with the in-memory key store, opens an encrypted
/// context, and sends a message. No custody string reaches the Keychain: the
/// UniFFI bridge answers "platform" with SCP-IDENT-1003, so Keychain-held keys
/// need a KeyCustodyProvider injected through identityCreateWithCustody.

import Foundation
import SCP

@main
struct SCPmacOSApp {
    static func main() async throws {
        // 1. Create a DID identity. This in-memory key store loses every key
        //    on process exit, and a released build rejects it with
        //    SCP-IDENT-1008.
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
        let payload = "Hello from macOS!".data(using: .utf8)!
        try await contextSend(handle: handle, identity: identity, payload: payload)
        print("Message sent.")

        // 4. Clean up.
        try await contextLeave(handle: handle, identity: identity)
        print("Done.")
    }
}
