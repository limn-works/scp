# SCP Swift macOS Scaffold

Minimal macOS app using the SCP Swift SDK. It creates its identity with the
in-memory key store, because no custody string reaches the Keychain — the
bridge answers `"platform"` with `SCP-IDENT-1003`. Hold keys in the Keychain
by injecting a `KeyCustodyProvider` through `identityCreateWithCustody`.

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
