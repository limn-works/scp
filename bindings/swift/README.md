# SCP Swift SDK

> `SCP` -- Shared Context Protocol for Swift

Cryptographic identity, encrypted contexts, capability-based auth, and outlet invocation for AI agents. Built on Rust via UniFFI, distributed as XCFramework.

## Install

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/limn/scp-swift", from: "0.1.0"),
]
```

## Quick Start

This quick start runs only against an XCFramework built with the `testing` feature (`./build-xcframework.sh --dev`), because a release build rejects `CustodyType.inMemory`.

```swift
import Foundation
import SCP

func runQuickStart() async throws {
    // Every call goes through an SCP instance, which takes a required storage backend.
    let scp = try SCP(storage: .inMemory)

    // Create a cryptographic identity (DID) whose keys live in process memory.
    let identity = try await scp.identityCreate(custody: .inMemory)
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
            consequenceConfigJson: nil
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
```

`Tests/SCPTests/ReadmeQuickStart.swift` holds a copy of the block above, and `ReadmeQuickStartTests` checks that the copy matches this file and runs it.

## Platform Support

- iOS >= 17
- macOS >= 14

## API Reference

Generated from source via DocC. Build locally:

```bash
swift package generate-documentation --target SCP
```

Published API docs are generated on every release by CI.

## Examples

See [`examples/`](./examples/) for runnable code:

| File | Description |
|------|-------------|
| `BasicMessaging.swift` | Create identity, context, send/receive messages |
| `OutletInvocation.swift` | Register and invoke a outlet with test vectors |
| `McpIntegration.swift` | Expose SCP outlets via MCP JSON-RPC server |
| `MultiAgent.swift` | Coordinate multiple agents in a shared context |

## Error Handling

All errors are cases of the `ScpError` enum with associated `message` and `code` values:

```swift
do {
    try await ctx.send(Data("data".utf8))
} catch ScpError.context(let message, let code) {
    print("[\(code)] \(message)")
}
```

## Source

- Scaffold: `.docs/scaffold/swift.md`
- Standards: `.docs/standards/swift.md`
- API sketch: `.docs/sketch.md`
