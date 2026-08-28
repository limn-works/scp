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
| `Messaging.swift` | Two-party message exchange with `MessageListener` receive |
| `Tools.swift` | Define tools with JSON schemas, register, verify, invoke, stateful sessions |

## Key Patterns

- **UniFFI bridge functions**: Context operations use generated functions (`contextCreate`, `contextSend`, `contextJoin`, etc.) that delegate to Rust.
- **ContextHandle**: Opaque handle to Rust context state, returned by `contextCreate`.
- **ContextParams**: UniFFI-generated struct configuring governance, memory scope, TTL, and capability ceiling.
- **MessageListener**: Callback protocol for receiving messages via `contextSubscribe`.
- **Injectable bridge**: SDK wrapper layer uses `*Bridge` enums for testability.
- **Structured concurrency**: All operations are `async throws` using Swift concurrency.
- **Free functions**: Identity operations use top-level functions (`createIdentity`, `resolveIdentity`, etc.).
- **Resource cleanup**: Call `contextClose(handle:identity:)` when done with a context.

## Architecture Notes

The Swift SDK is a thin delegation layer over UniFFI-generated bindings. Every public method
calls exactly one UniFFI bridge function -- zero protocol logic lives in Swift. The injectable
bridge pattern (`*Bridge` enum with typealias closures and static defaults) enables unit testing
without the native Rust library.

## SDK Reference

- Swift SDK source: `bindings/swift/Sources/SCP/`
- UniFFI bridge: `crates/scp-ffi/uniffi/`
- Protocol spec: `.docs/specs/`

## Key custody

Every snippet here passes `in_memory`, which §3.2.2 of the identity spec, the custody
vocabulary, classifies as a test-harness string rather than a value a shipped caller
names. A shipped build rejects it with `SCP-IDENT-1008`. That section states the two
values a shipped caller does name: `encrypted_file` selects the on-disk key store SCP
implements, and `os_keystore` selects the operating system's own key store, which SCP
reaches through the platform key-custody callback the SDK consumer supplies. The words
`platform`, `software`, `file`, and `hardware` name no custody value.
