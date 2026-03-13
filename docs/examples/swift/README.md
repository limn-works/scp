# SCP Swift SDK Examples

Demonstrates the core operations of the SCP Swift SDK: identity management,
context lifecycle, messaging, and tool invocation.

## Prerequisites

1. **Swift 6.2+** (via mise or Xcode):
   ```bash
   mise install swift@6.2
   ```

2. **Add the SCP package** to your `Package.swift`:
   ```swift
   dependencies: [
       .package(path: "../../bindings/swift")
   ]
   ```

   Or via URL when published:
   ```swift
   .package(url: "https://github.com/limn-works/scp-swift", from: "0.1.0")
   ```

## Running the Examples

Each example has a `@main` entry point:

```bash
# Identity creation and DID document inspection
swift run Identity

# Context creation and lifecycle management
swift run Context

# Two-party message exchange
swift run Messaging

# Tool registration and invocation
swift run Tools
```

## Examples

| File | Description |
|------|-------------|
| `Identity.swift` | Create identity, resolve DID, inspect document, agent key management |
| `Context.swift` | Create context, configure capabilities, join/leave, send messages |
| `Messaging.swift` | Two-party message exchange with `AsyncStream` receive |
| `Tools.swift` | Define tools with JSON schemas, register, verify, invoke, stateful sessions |

## Key Patterns

- **Actor-based Context**: `Context` is a Swift actor for thread-safe state management.
- **Injectable bridge**: All UniFFI calls are injected via `*Bridge` enums for testability.
- **AsyncStream**: `ctx.messages` returns an `AsyncStream<Message>` for push-based delivery.
- **Structured concurrency**: All operations are `async throws` using Swift concurrency.
- **Free functions**: Identity operations use top-level functions (`createIdentity`, `resolveIdentity`, etc.).
- **Resource cleanup**: Call `ctx.close()` explicitly. `deinit` schedules a detached cleanup task as safety net.

## Architecture Notes

The Swift SDK is a thin delegation layer over UniFFI-generated bindings. Every public method
calls exactly one UniFFI bridge function -- zero protocol logic lives in Swift. The injectable
bridge pattern (`*Bridge` enum with typealias closures and static defaults) enables unit testing
without the native Rust library.

## SDK Reference

- Swift SDK source: `bindings/swift/Sources/SCP/`
- UniFFI bridge: `crates/scp-ffi/uniffi/`
- Protocol spec: `.docs/specs/`
