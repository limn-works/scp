/// Minimal SCP iOS app scaffold.
///
/// Creates a DID identity with the encrypted key file SCP implements, opens an encrypted
/// context, and sends a message. Section 3.2.2 of the identity spec, the custody
/// vocabulary, names two values a shipped caller passes: "encrypted_file" for
/// the on-disk key store SCP implements, and "os_keystore" for the Keychain,
/// which needs a KeyCustodyProvider injected through identityCreateWithCustody.
/// Replace mock values with real relay URLs for production.

import Foundation
import SCP

@main
struct SCPiOSApp {
    static func main() async throws {
        // 1. Create a DID identity. This encrypted key file keeps every key
        //    on process exit, and a released build rejects it with
        //    SCP-IDENT-1008.
        let identity = try await createIdentity(custody: CustodyType.encryptedFile.rawValue)
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
