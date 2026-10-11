# SCP Kotlin SDK Examples

Demonstrates the core operations of the SCP Kotlin SDK: identity management,
context lifecycle, messaging, and tool invocation.

## Prerequisites

1. **JDK 17** (via mise):
   ```bash
   mise install java@zulu-17
   ```

2. **Gradle 8.x** (via mise):
   ```bash
   mise install gradle@8
   ```

3. **Add the SDK dependency** to your `build.gradle.kts`:
   ```kotlin
   dependencies {
       implementation("works.limn:scp-kt:0.1.0")
   }
   ```

4. **Ensure the Rust native library is built**:
   ```bash
   cd bindings/kotlin
   eval "$(mise env)"
   ./gradlew assembleRelease
   ```

## Running the Examples

Each example is one top-level function that your app calls. Every example that
creates an identity takes a `uniffi.scp.KeyCustodyProvider`, the provider that
the `os_keystore` custody request reaches (spec section 3.2.2); the KDoc on
`works.limn.scp.CustodyType` states how a shipped build answers each entry.
On Android, `scp-kt-android` ships that provider over Android Keystore:
`UniffiKeyCustody` wraps an `AndroidKeyCustody`. On another JVM, implement
`uniffi.scp.KeyCustodyProvider` over your own key store.

```kotlin
val myProvider = UniffiKeyCustody(AndroidKeyCustody(applicationContext))
identityExample(myProvider, File(filesDir, "scp-identity"), passphrase)
contextExample(aliceProvider, bobProvider, filesDir, passphrase)
messagingExample(aliceProvider, bobProvider, "wss://relay.example.com", filesDir, passphrase)
toolsExample(myProvider, File(filesDir, "scp-tools"), passphrase)
```

`messagingExample` needs a relay both nodes reach. Each node attaches the relay
with `configureRelayTransport` before it creates or joins a context; the first
context binds the transport the node has then, and a later call attaches
nothing.

No example calls `SCP.shutdown`. It takes a `CoroutineBridge`, and the SDK ships
no `NativeBindings` implementation to build one with.

## Examples

| File | Description |
|------|-------------|
| `Identity.kt` | Create identity, resolve DID, agent key management |
| `Context.kt` | Create a context, reserve a KeyPackage, invite a member, join from the sealed invitation, read members, close |
| `Messaging.kt` | Two-party message exchange over a relay, received through a `MessageListener` |
| `Tools.kt` | Define an outlet with JSON schemas and test vectors, register it, verify it, mint a UCAN |

## Key Patterns

- **One `SCP` instance per node**: every operation is a `suspend` method on
  `SCP`, built with `SCP.withSqlite(dir, passphrase)`.
- **Opaque handles**: `uniffi.scp.Identity` and `uniffi.scp.ContextHandle` are the
  references every identity and context method takes.
- **Typed records**: `ContextParams` and `OutletDefinition` are UniFFI records.
  Every `ContextParams` field is required.
- **MessageListener**: callback interface for receiving messages through
  `contextSubscribe`.

## Architecture Notes

`SCP` forwards each call to the generated UniFFI `Scp` object. Zero protocol logic
lives in the Kotlin layer.

## SDK Reference

- Kotlin SDK source: `bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/`
- UniFFI bridge: `crates/scp-ffi/uniffi/`
- Protocol spec: `.docs/specs/`
