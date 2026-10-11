# SCP Kotlin Android Scaffold

Minimal Android app using the SCP Kotlin SDK. Creates a DID identity through your key custody provider and opens an encrypted context.

## Prerequisites

- JDK 17 (install via `mise install java@zulu-17`)
- Gradle 8.x
- SCP Kotlin SDK (`works.limn:scp-kt:0.1.0`)
- UniFFI native library (`libscp_ffi_uniffi.so`)

## Build and Run

```bash
cd scaffolds/kotlin-android
eval "$(mise env)"
export SCP_STORAGE_PASSPHRASE=...
./gradlew run
```

For a full Android app, import into Android Studio and add the SCP SDK as a dependency.

## What This Does

1. Opens one `SCP` instance over a SQLCipher database in `./scp-data`
2. Creates a `did:dht` identity through `identityCreateWithCustody(provider)`
3. Opens an encrypted single-admin context
4. Closes the context

`makeKeyCustodyProvider()` in `Main.kt` returns the
`uniffi.scp.KeyCustodyProvider` that `identityCreateWithCustody` takes. In an
Android app, return `UniffiKeyCustody(AndroidKeyCustody(applicationContext))`
from `works.limn:scp-kt-android`, the provider over Android Keystore. This
scaffold runs on the JVM with no Android `Context`, so the function throws
until you implement it over your key store. The KDoc of
`works.limn.scp.CustodyType` states which identity creations a build without
the `testing` feature refuses; `identityCreateWithCustody` is one of them.

The scaffold does not call `SCP.shutdown`: it takes a `CoroutineBridge`, and the
SDK ships no `NativeBindings` implementation to build one with.

## Next Steps

- Invite a second identity with `reserveKeyPackage`, `inviteMember` and
  `contextJoinFromWelcome`
- Connect to a relay with `configureRelayTransport`, then send with
  `contextSend` and receive with `contextSubscribe`
- Integrate with Android lifecycle (ViewModel, coroutine scopes)
- See `docs/examples/kotlin/` for more detailed examples
