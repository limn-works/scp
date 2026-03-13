# SCP Swift macOS Scaffold

Minimal macOS app using the SCP Swift SDK with Keychain key custody.

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

1. Creates a `did:dht` identity with Keychain key custody
2. Opens an encrypted context with messaging capabilities
3. Sends a message
4. Cleans up by leaving the context

## Next Steps

- Connect to a relay with `connectTransport()`
- Add tool registration and invocation
- Add MCP integration with `serveMcp()` / `McpClient.connect()`
- See `docs/examples/swift/` for more detailed examples
