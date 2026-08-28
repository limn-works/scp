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

```bash
# Ensure JAVA_HOME is set
eval "$(mise env)"

# Identity creation and DID document inspection
./gradlew run --args="identity"

# Context creation and lifecycle management
./gradlew run --args="context"

# Two-party message exchange
./gradlew run --args="messaging"

# Tool registration and invocation
./gradlew run --args="tools"
```

## Examples

| File | Description |
|------|-------------|
| `Identity.kt` | Create identity, resolve DID, agent key management, device attestation |
| `Context.kt` | Create context, configure capabilities, join/leave, membership queries |
| `Messaging.kt` | Two-party message exchange with Flow-based streaming |
| `Tools.kt` | Define tools with JSON schemas, register, verify, invoke |

## Key Patterns

- **Coroutine bridge**: All FFI calls are suspend functions dispatched on `Dispatchers.IO`.
- **Opaque handles**: Identity and context are represented as `Long` handles in the bridge layer.
- **JSON parameters**: Structured data (context params, tool definitions) passed as JSON strings.
- **Flow streaming**: Messages delivered via cold `Flow<String>` or hot `SharedFlow<String>`.
- **Type-safe enums**: `CustodyType`, `BridgeMode`, `ShadowStatus` for typed parameters.
- **Cancellation**: `CancellationHandle` propagates coroutine cancellation to Rust.

## Architecture Notes

The Kotlin SDK uses a `CoroutineBridge` as the single dispatch gateway for all FFI calls.
Domain-specific bridges (`IdentityBridge`, `ContextBridge`, `ToolBridge`, etc.) group related
operations. Every SDK method delegates through the bridge to exactly one UniFFI function --
zero protocol logic lives in the Kotlin layer.

Streaming uses two patterns:
- **Cold Flow** (`ColdMessageFlow`): Single collector, natural backpressure.
- **Hot SharedFlow** (`HotStreamFactory`): Multiple collectors, 64-item buffer, `DROP_OLDEST`.

## SDK Reference

- Kotlin SDK source: `bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/`
- UniFFI bridge: `crates/scp-ffi/uniffi/`
- Protocol spec: `.docs/specs/`

## Key custody

Every snippet here passes `encrypted_file`, one of the two values §3.2.2 of the identity
spec, the custody vocabulary, states. It selects the on-disk key store SCP implements,
and the bridge reads its passphrase from the `SCP_KEY_PASSPHRASE` environment variable.
The other value, `os_keystore`, selects the operating system's own key store, which SCP
reaches through the platform key-custody callback the SDK consumer supplies. The words
`platform`, `software`, `file`, and `hardware` name no custody value, and `in_memory` is
a test-harness string a shipped build rejects with `SCP-IDENT-1008`.
