/// Minimal SCP macOS app scaffold.
///
/// Creates a DID identity with platform custody, opens an encrypted context,
/// and sends a message.

import SCP

@main
struct SCPmacOSApp {
    static func main() async throws {
        // 1. Create a DID identity with platform (Keychain) custody.
        let identity = try await createIdentity(custody: CustodyType.platform.rawValue)
        print("Created identity: \(identity.did())")

        // 2. Create an encrypted context.
        let ctx = try await Context.create(
            contextId: "macos-demo",
            ceiling: ["messages:read", "messages:write", "role:assign"],
            createFn: ContextBridge.defaultCreate,
            sendFn: ContextBridge.defaultSend,
            subscribeFn: ContextBridge.defaultSubscribe,
            leaveFn: ContextBridge.defaultLeave,
            closeFn: ContextBridge.defaultClose
        )
        print("Created context: \(ctx.contextId)")

        // 3. Send a message.
        let payload = "Hello from macOS!".data(using: .utf8)!
        try await ctx.send(payload)
        print("Message sent.")

        // 4. Clean up.
        try await ctx.leave()
        print("Done.")
    }
}
