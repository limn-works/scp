# Kotlin SDK Scaffold

> Source of truth: .docs/specs/, .docs/sketch.md, .docs/adrs/. This file is downstream of those documents.

Build blueprint for the SCP Kotlin SDK: package structure, UniFFI bridge patterns, build configuration, and type definitions. See `.docs/standards/kotlin.md` for coding standards (style rules, linting, testing, CI).

## Package Layout

```
bindings/kotlin/
  build.gradle.kts              # Root build config
  settings.gradle.kts
  scp-kt/
    build.gradle.kts             # SDK module build
    src/
      main/kotlin/works/limn/scp/
        Identity.kt              # IdentityAdvancedBridge and the data classes its operations return
        Context.kt               # Context class (superseded: ADR-048 removed it; no Context.kt ships)
        Tools.kt                 # ToolDefinition, TestVector data classes
        Trust.kt                 # evaluateTrust(), TrustEvaluation
        EventLog.kt              # EventLog class, Event, Proof, Checkpoint
        Errors.kt                # Exception hierarchy (ScpException → subtypes)
        Transport.kt             # TransportConfig, relay connection
        Types.kt                 # Shared types: Message, Provenance, Capability
        Ucan.kt                  # UCAN validate(), mint(), revoke(), delegate()
        Mcp.kt                   # serveMcp(), McpClient
        internal/
          NativeLib.kt           # UniFFI-generated native bindings (auto-generated)
      main/resources/
        libscp_ffi.so            # Linux native library (bundled in JAR)
        libscp_ffi.dylib         # macOS native library
        scp_ffi.dll              # Windows native library
      test/kotlin/works/limn/scp/
        IdentityTest.kt
        ContextTest.kt
        ToolsTest.kt
        UcanTest.kt
        TransportTest.kt
        EventLogTest.kt
        McpTest.kt
        conformance/
          ConformanceTest.kt
```

## UniFFI Bridge

UniFFI generates Kotlin bindings from a single UDL (Universal Definition Language) file shared with Swift.

### UDL definition

Located at `crates/scp-ffi/uniffi/src/scp.udl`:

```
namespace scp {
  [Throws=ScpError]
  Identity identity_create(IdentityConfig config);

  [Throws=ScpError]
  Identity identity_load(bytes identifier);

  [Throws=ScpError]
  ResolutionOutcome identity_resolve(bytes identifier);
};

interface Identity {
  bytes identifier();
  CustodyType custody_type();

  [Throws=ScpError]
  Identity rotate_key();
};

interface Context {
  string context_id();
  string state();

  [Throws=ScpError]
  void send(bytes payload);

  [Throws=ScpError]
  ToolResult invoke_tool(string tool_id, string input_json);
};
```

UniFFI generates:
- `NativeLib.kt` — JNA bindings to the Rust shared library
- Kotlin classes wrapping each interface
- Kotlin enums for error types

### Async bridging

UniFFI supports Kotlin coroutines via `uniffi-kotlin-multiplatform`. This SDK wraps blocking FFI calls in an injected `ioDispatcher` (`CoroutineBridge.ioDispatcher`, which defaults to `Dispatchers.IO`) to avoid depending on the multiplatform plugin until it stabilizes. A test injects a `StandardTestDispatcher` there, so no call, and no subscription release, may name `Dispatchers.IO` directly. The `Context` class below is superseded: ADR-048 removed `Context` from the Kotlin surface, so no `Context.kt` ships and the sketch binds no code. It still shows the injected `ioDispatcher` and the `callbackFlow` subscription release that `bindings/kotlin/AGENTS.md` §Coroutines and streams requires of every shipped stream; a context is a handle that `CoroutineBridge.context` operates on.

```kotlin
class Context internal constructor(
    private val handle: ContextHandle,
    // Injected like CoroutineBridge.ioDispatcher, with the same default.
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    val contextId: String get() = handle.contextId()
    val state: String get() = handle.state()

    suspend fun send(payload: ByteArray) = withContext(ioDispatcher) {
        handle.send(payload)
    }

    suspend fun invokeTool(toolId: String, input: Map<String, Any>): Map<String, Any> =
        withContext(ioDispatcher) {
            val json = Json.encodeToString(input)
            val result = handle.invokeTool(toolId, json)
            Json.decodeFromString(result)
        }

    // Subscribe under NonCancellable and record the subscription inside that block: a
    // collector cancelled mid-call makes withContext throw on resumption and drop the block's
    // return value. Release it by suspending in a finally: awaitClose's lambda runs on the
    // collector's thread, an Android main thread under collectAsState.
    fun receiveFlow(): Flow<Message> = callbackFlow {
        var subscription: Subscription? = null
        try {
            withContext(NonCancellable + ioDispatcher) {
                subscription = handle.subscribe { envelope ->
                    trySend(envelope.toMessage())
                }
            }
            awaitClose()
        } finally {
            val opened = subscription
            if (opened != null) {
                withContext(NonCancellable + ioDispatcher) { opened.unsubscribe() }
            }
        }
    }
}
```

## build.gradle.kts

```kotlin
plugins {
    kotlin("jvm") version "2.0.0"
    kotlin("plugin.serialization") version "2.0.0"
    id("org.jlleitschuh.gradle.ktlint") version "12.1.0"
    id("io.gitlab.arturbosch.detekt") version "1.23.7"
}

group = "works.limn"
artifactId = "scp-kt"
version = "0.1.0"

kotlin {
    jvmToolchain(11)
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.10.0")
    implementation("net.java.dev.jna:jna:5.18.1")  // UniFFI JNA dependency

    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11+")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
}

tasks.test {
    useJUnitPlatform()
}

detekt {
    config.setFrom("detekt.yml")
    buildUponDefaultConfig = true
}
```

## Data Classes

```kotlin
data class Message(
    val senderIdentifier: ByteArray,
    val content: ByteArray,
    val timestamp: Long,
    val sequence: Long,
    val contextId: String,
    val provenance: Provenance? = null,
)

data class ToolDefinition(
    val name: String,
    val description: String,
    val inputSchema: Map<String, Any>,
    val outputSchema: Map<String, Any>,
    val operator: ByteArray,  // identifier
    val testVectors: List<TestVector>? = null,
    val implementationHash: ByteArray? = null,
)
```

## Exception Hierarchy

```kotlin
open class ScpException(
    message: String,
    val code: String,  // e.g., "SCP-CTX-2001"
) : Exception(message)

class IdentityException(message: String, code: String) : ScpException(message, code)
class ContextException(message: String, code: String) : ScpException(message, code)
class PermissionException(message: String, code: String) : ScpException(message, code)
class CryptoException(message: String, code: String) : ScpException(message, code)
class TransportException(message: String, code: String) : ScpException(message, code)
class ToolException(message: String, code: String) : ScpException(message, code)
class ValidationException(message: String, code: String) : ScpException(message, code)
```

## Identity Class

Superseded. `scp-kt` ships no `Identity` class, so this sketch binds no code; the shipped `Identity.kt` holds `IdentityAdvancedBridge` and the data classes its operations return.

```kotlin
class Identity private constructor(
    private val handle: IdentityHandle,
    private val ioDispatcher: CoroutineDispatcher,
) {
    val identifier: ByteArray get() = handle.identifier()
    val custodyType: CustodyType get() = handle.custodyType()

    companion object {
        // IdentityConfig is the three-slot config object
        // `.docs/standards/construction.md` states. Its `custody` slot carries
        // the bridge's KeyCustodyConfig and carries no default, because that
        // slot decides where an identity's private key lives. The ioDispatcher
        // parameter is injected like CoroutineBridge.ioDispatcher, with the same default.
        suspend fun create(
            config: IdentityConfig,
            ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
        ): Identity =
            withContext(ioDispatcher) {
                Identity(NativeLib.identityCreate(config), ioDispatcher)
            }

        suspend fun load(
            identifier: ByteArray,
            ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
        ): Identity =
            withContext(ioDispatcher) {
                Identity(NativeLib.identityLoad(identifier), ioDispatcher)
            }
    }

    suspend fun rotateKey(): Identity = withContext(ioDispatcher) {
        Identity(handle.rotateKey(), ioDispatcher)
    }
}
```

## Resource Management

A type whose teardown reaches the Rust engine exposes exactly one `suspend` teardown function and implements no `AutoCloseable` or `Closeable`, so no `use { }` block applies to it. `AutoCloseable.close()` is synchronous, so it could reach the engine only by blocking its calling thread, which never returns under an injected `StandardTestDispatcher` and risks an ANR on an Android main thread. `.docs/standards/sdk-common.md` §"Kotlin: why no `Closeable`" and ADR-028 (as amended, `.docs/adrs/phase-6.md`) state the rule; `.docs/lessons/kotlin/oncleared-must-not-block-its-caller.md` records the observed deadlock and the ANR risk.

```kotlin
class Relay internal constructor(
    private val bridge: ServerBridge,
    // ...
) {
    @Volatile
    var isShutdown: Boolean = false
        internal set

    // The only stop path. It suspends on the bridge's injected ioDispatcher. A failed
    // teardown propagates and leaves isShutdown false, so the relay still reads as live.
    // ServerBridge.shutdownRelay sets the flag inside its bridge call, because withContext
    // checks for cancellation as it returns: a flag set here after that call would stay false
    // for a caller cancelled after a finished teardown. ServerTest's "every stop method on a
    // lifecycle-owning type suspends" check skips every compiled `$lambda` body, so it catches
    // no blocking call inside a lambda written here.
    suspend fun shutdown() {
        bridge.shutdownRelay(this)
    }
}

class ServerBridge internal constructor(
    private val bindings: ServerBindings,
    private val bridge: CoroutineBridge,
) {
    internal suspend fun shutdownRelay(relay: Relay) = bridge.ffiCall {
        bindings.relayShutdown(relay.handleJson)
        // Reached only when the FFI call returns; an engine failure throws first.
        relay.isShutdown = true
    }
}

// Usage: call shutdown() from a coroutine the caller owns, never through runBlocking.
// Run it under NonCancellable: a finally block usually runs because the coroutine was
// cancelled, and in a cancelled coroutine the bridge's withContext(ioDispatcher) throws
// CancellationException before the FFI call starts, so a bare shutdown() tears nothing down.
val relay = Relay.startInMemory(bridge)
try {
    println(relay.relayUrl)
} finally {
    withContext(NonCancellable) { relay.shutdown() }
}
```

## Maven Central Publishing

Published as `works.limn:scp-kt` on Maven Central.

```kotlin
// Consumer usage
dependencies {
    implementation("works.limn:scp-kt:0.1.0")
}
```

Package includes:
- Kotlin source + compiled classes
- Native libraries for Linux (x86_64, aarch64), macOS (x86_64, aarch64), Windows (x86_64) bundled in JAR resources
- JNA dependency for UniFFI native bridge
