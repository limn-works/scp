# SCP Swift macOS Scaffold

Minimal macOS app using the SCP Swift SDK with the in-memory key store. A caller reaches
the Keychain by naming `"os_keystore"` and supplying a `KeyCustodyProvider`; §3.2.2 of
the identity spec, the custody vocabulary, states that value and states that a bridge
holding no such provider returns a typed error rather than falling back to another
store.

## Prerequisites

- Xcode 16+ with Swift 6.2
- SCP Swift SDK (local dependency via `../../bindings/swift`)
- ScpFFI.xcframework binary target

## Build and Run

```bash
cd scaffolds/swift-macos
swift build
swift run
```

## What This Does

1. Creates a `did:dht` identity with the in-memory key store
2. Opens an encrypted context with messaging capabilities
3. Sends a message
4. Cleans up by leaving the context

## Next Steps

- Connect to a relay with `connectTransport()`
- Add tool registration and invocation
- Add MCP integration with `serveMcp()` / `McpClient.connect()`
- See `docs/examples/swift/` for more detailed examples
