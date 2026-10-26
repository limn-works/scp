# SCP Swift macOS Scaffold

Minimal macOS app using the SCP Swift SDK. Creates a DID identity through your key custody provider and opens an encrypted context.

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

1. Opens one `SCP` instance over a SQLCipher database in Application Support,
   keyed by the `SCP_STORAGE_PASSPHRASE` environment variable
2. Creates a `did:dht` identity through `identityCreateWithCustody(provider:)`
3. Opens an encrypted single-admin context
4. Closes the context and shuts the instance down

`Sources/main.swift` passes `AppleKeyCustody()`, the SDK's `KeyCustodyProvider`
over the Keychain, to `identityCreateWithCustody(provider:)`: the `os_keystore`
custody request of spec 03 §3.2.2. A build without the bridge's `testing`
feature has no independent next-set substrate and throws `SCP-IDENT-1100` from
that call; the custody paragraph of `docs/guides/sdk-quickstart.md` states which
identity creations a shipped build refuses.

## Next Steps

- Invite a second identity with `reserveKeyPackage(identity:)`,
  `inviteMember(identity:contextId:inviteeDid:inviteeKeyPackage:)` and
  `contextJoinFromWelcome(identity:sealed:reservationId:)`
- Connect to a relay with `configureRelayTransport(relayUrl:localDid:)`, then send
  with `contextSend` and receive with `contextSubscribe`
- Register an outlet with `outletRegister(handle:definition:)`
- See `docs/examples/swift/` for more detailed examples
