# SCP Kotlin Android Scaffold

Minimal Android app using the SCP Kotlin SDK with the in-memory key store. A caller
reaches Android Keystore by naming `"os_keystore"` and supplying a
`KeyCustodyProvider`; §3.2.2 of the identity spec, the custody vocabulary, states that
value and states that a bridge holding no such provider returns a typed error rather
than falling back to another store.

## Prerequisites

- JDK 17 (install via `mise install java@zulu-17`)
- Gradle 8.x
- SCP Kotlin SDK (`works.limn:scp-kt:0.1.0`)
- UniFFI native library (`libscp_ffi_uniffi.so`)

## Build and Run

```bash
cd scaffolds/kotlin-android
eval "$(mise env)"
./gradlew run
```

For a full Android app, import into Android Studio and add the SCP SDK as a dependency.

## What This Does

1. Demonstrates the SCP Kotlin SDK API surface
2. Shows how to create identities, contexts, and send messages
3. Provides commented code for the full workflow

## Next Steps

- Load the native library with `System.loadLibrary("scp_ffi_uniffi")`
- Replace the `bridge.identity.create(CustodyType.ENCRYPTED_FILE)` call with `identityCreateWithCustody(provider)` on a `works.limn.scp.SCP` instance, passing your own `uniffi.scp.KeyCustodyProvider` over Android Keystore — that call returns `SCP-IDENT-1059` on a released build, because no pre-rotation custody backend is wired yet
- Add relay connectivity for real transport
- Integrate with Android lifecycle (ViewModel, coroutine scopes)
- See `docs/examples/kotlin/` for more detailed examples
