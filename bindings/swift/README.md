# SCP Swift SDK

> `SCP` -- Shared Context Protocol for Swift

Cryptographic identity, encrypted contexts, capability-based auth, and tool invocation for AI agents. Built on Rust via UniFFI, distributed as XCFramework.

## Install

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/limn/scp-swift", from: "0.1.0"),
]
```

## Quick Start

```swift
import SCP

// Create a cryptographic identity (DID)
let identity = try await Identity.create(custody: "platform")
print("DID: \(identity.did)")

// Create an encrypted context
let ctx = try await Context.create(
    identity: identity,
    params: ContextParams(
        ceiling: ["msg:send", "msg:receive"],
        ttl: 3600
    )
)

// Send a message (MLS-encrypted, signed, provenance-tagged)
try await ctx.send(Data("Hello from SCP".utf8))

// Receive messages
for await msg in ctx.messages {
    print("\(msg.senderDid): \(String(data: msg.content, encoding: .utf8)!)")
    break
}

try await ctx.close()
```

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
| `ToolInvocation.swift` | Register and invoke a tool with test vectors |
| `McpIntegration.swift` | Expose SCP tools via MCP JSON-RPC server |
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
