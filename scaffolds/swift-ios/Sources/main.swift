/// Minimal SCP iOS app scaffold.
///
/// Creates a DID identity with Keychain custody, opens an encrypted context,
/// and sends a message. Replace mock values with real relay URLs for production.

import SCP

@main
struct SCPiOSApp {
    static func main() async throws {
        // 1. Create a DID identity with platform (Keychain) custody.
        let identity = try await createIdentity(custody: CustodyType.platform.rawValue)
        print("Created identity: \(identity.did())")

        // 2. Create an encrypted context.
        let ctx = try await Context.create(
            contextId: "ios-demo",
            ceiling: ["messages:read", "messages:write", "role:assign"],
            createFn: ContextBridge.defaultCreate,
            sendFn: ContextBridge.defaultSend,
            subscribeFn: ContextBridge.defaultSubscribe,
            leaveFn: ContextBridge.defaultLeave,
            closeFn: ContextBridge.defaultClose
        )
        print("Created context: \(ctx.contextId)")

        // 3. Send a message.
        let payload = "Hello from iOS!".data(using: .utf8)!
        try await ctx.send(payload)
        print("Message sent.")

        // 4. Clean up.
        try await ctx.leave()
        print("Done.")
    }
}
