# SCP Kotlin Android Scaffold

Minimal Android app using the SCP Kotlin SDK. It creates its identity with
the in-memory key store, because no custody string reaches Android Keystore —
the bridge answers `"platform"` with `SCP-IDENT-1003`. Hold keys in Keystore
by injecting a `KeyCustodyProvider` through `identityCreateWithCustody`.

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
- Replace the `identityCreate("in_memory")` call with `scp.identityCreateWithCustody(provider)` for Android Keystore, passing your own `uniffi.scp.KeyCustodyProvider` — the UniFFI bridge rejects the custody strings `"platform"` and `"software"` with `SCP-IDENT-1003`
- Add relay connectivity for real transport
- Integrate with Android lifecycle (ViewModel, coroutine scopes)
- See `docs/examples/kotlin/` for more detailed examples
