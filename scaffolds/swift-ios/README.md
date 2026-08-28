# SCP Swift iOS Scaffold

Minimal iOS app using the SCP Swift SDK with the encrypted key file SCP implements. A caller reaches
the Keychain by naming `"os_keystore"` and supplying a `KeyCustodyProvider`; §3.2.2 of
the identity spec, the custody vocabulary, states that value and states that a bridge
holding no such provider returns a typed error rather than falling back to another
store.

## Prerequisites

- Xcode 16+ with Swift 6.2
- SCP Swift SDK (local dependency via `../../bindings/swift`)
- ScpFFI.xcframework binary target (build with `scripts/build-xcframework.sh`)

## Build and Run

```bash
cd scaffolds/swift-ios
swift build
```

For a full iOS app, open in Xcode and add to an iOS project target.

## What This Does

1. Creates a `did:dht` identity with the encrypted key file SCP implements
2. Opens an encrypted context with messaging capabilities
3. Sends a message
4. Cleans up by leaving the context

## Next Steps

- Add push notification support with `ApplePushProvider`
- Connect to a relay with `connectTransport()`
- Add a second participant with `joinContext()`
- Register tools with `registerTool()` and invoke with `invokeTool()`
- See `docs/examples/swift/` for more detailed examples
