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

```swift
import SCP

// Every call routes through an SCP instance (ADR-048). Name a storage
// backend: this initializer has no default.
let scp = try SCP(storage: .inMemory)

// Create a cryptographic identity (DID). Name a custody backend too —
// `identityCreate` has no default either (spec §17.17.1, SCP-CAPSEL-8000).
// `"in_memory"` keeps key material in this process's heap and loses it at
// exit, and a build without the `testing` feature rejects it with
// SCP-IDENT-1008 — it is what this quick start uses and what a shipped app
// must not. A shipped iOS app names `"platform"` and wires a
// KeyCustodyProvider through `identityCreateWithCustody`, so the Secure
// Enclave holds the key material and it never enters this process.
let identity = try await scp.identityCreate(custody: "in_memory")
print("DID: \(identity.did())")

// Create an encrypted context. `ContextParams` names every parameter a
// prospective member reads before joining, so it carries no defaults. The
// ceiling bounds every capability any member can ever hold, so it must carry
// `context:close` for the `contextClose` call below to pass its capability
// check.
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
```

### What this quick start needs, and why a published artifact refuses it

Two things above run only on a build that carries the `testing` cargo feature,
and both refusals are the protocol failing closed rather than minting a
test-only stand-in (`.docs/adrs/ADR-062-capability-injection.md` §Decision 6):

1. `identityCreate` commits a pre-rotation commitment at creation, which spec
   §9.7.4.1 §3 makes mandatory. No production `PreRotationCustody` backend
   exists yet, so a published XCFramework answers every `identityCreate` call
   — whichever custody you name — with `[SCP-IDENT-1059] no production
   pre-rotation custody backend available`. Issue #1729 and RFC #2130 track
   the real backend.
2. `"in_memory"` custody is a development affordance whose key material lives
   in this process's heap and dies with it. A build without `testing` answers
   `[SCP-IDENT-1008] in_memory custody is not available in this build`. A
   shipped app names `"platform"` and wires a `KeyCustodyProvider` through
   `identityCreateWithCustody`, so the Secure Enclave holds the keys.

`build-xcframework.sh --dev` builds a macOS-arm64 XCFramework with `testing`
enabled, which runs the quick start today:

```bash
bindings/swift/build-xcframework.sh --dev
swift test --filter ReadmeQuickStartTests
```

`ReadmeQuickStartTests` runs the block above verbatim, so this README stops
drifting from what runs.

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
