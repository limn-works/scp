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
custody request of spec 03 §3.2.2. The SDK's `CustodyType` case `.inMemory`
works only in a build compiled with the `testing` feature; a shipped build
rejects it with `SCP-IDENT-1008`.

## Next Steps

- Invite a second identity with `reserveKeyPackage(identity:)`,
  `inviteMember(identity:contextId:inviteeDid:inviteeKeyPackage:relayUrls:)` and
  `contextJoinFromWelcome(identity:sealed:reservationId:)`
- Connect to a relay with `configureRelayTransport(relayUrl:localDid:)`, then send
  with `contextSend` and receive with `contextSubscribe`
- Register an outlet with `outletRegister(handle:definition:)`
- See `docs/examples/swift/` for more detailed examples
