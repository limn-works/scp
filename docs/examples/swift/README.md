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

Each example is an `enum` with one `static func run` that your app calls. Every
example that creates an identity takes a `KeyCustodyProvider`. The SDK ships no
key store that `identityCreate(custody:)` reaches in a shipped build; the doc
comment on `CustodyType` in `Sources/SCP/Types.swift` states how a shipped
build answers each case. `AppleKeyCustody` is the SDK's `KeyCustodyProvider`
over the Keychain, the `os_keystore` custody request of spec 03 §3.2.2:

```swift
let myProvider = AppleKeyCustody()
let passphrase = "..."  // from the user or your app's keychain item
try await IdentityExample.run(provider: myProvider, storagePassphrase: passphrase)
try await ContextExample.run(
    aliceProvider: aliceProvider, bobProvider: bobProvider, storagePassphrase: passphrase)
try await MessagingExample.run(
    aliceProvider: aliceProvider, bobProvider: bobProvider,
    relayURL: "wss://relay.example.com", storagePassphrase: passphrase)
try await ToolsExample.run(provider: myProvider, storagePassphrase: passphrase)
```

`MessagingExample.run` needs a relay both nodes reach. Each node attaches the
relay with `configureRelayTransport` before it creates or joins a context; the
first context binds the transport the node has then, and a later call attaches
nothing.

## Examples

| File | Description |
|------|-------------|
| `Identity.swift` | Create identity, resolve DID, inspect document, agent key management |
| `Context.swift` | Create a context, reserve a KeyPackage, invite a member, join from the sealed invitation, read members, close |
| `Messaging.swift` | Two-party message exchange over a relay, received through a `MessageListener` |
| `Tools.swift` | Define an outlet with JSON schemas and test vectors, register it, verify it, mint a UCAN |

## Key Patterns

- **One `SCP` instance per node**: every operation is a method on `SCP`, built
  with `SCP.withStorage(sqliteDir:passphrase:)`. Call `shutdown()` when done.
- **ContextHandle**: opaque handle to Rust context state, returned by
  `contextCreate` and `contextJoinFromWelcome`. Every context method takes it.
- **ContextParams**: UniFFI-generated struct configuring mode, ceiling,
  governance, memory scope, TTL and limits. Every field is required.
- **MessageListener**: callback protocol for receiving messages through
  `contextSubscribe`.
- **Structured concurrency**: operations are `async throws`.
- **Resource cleanup**: call `contextClose(handle:identity:)` to close a context
  for every member, or `contextLeave(handle:identity:)` to leave it.

## Architecture Notes

The Swift SDK is a thin delegation layer over UniFFI-generated bindings. Every public method
calls exactly one UniFFI bridge function -- zero protocol logic lives in Swift.

## SDK Reference

- Swift SDK source: `bindings/swift/Sources/SCP/`
- UniFFI bridge: `crates/scp-ffi/uniffi/`
- Protocol spec: `.docs/specs/`
