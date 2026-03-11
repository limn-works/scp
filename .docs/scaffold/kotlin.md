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
        Identity.kt              # Identity class, DIDDocument
        Context.kt               # Context class, Membership
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
  Identity identity_create(string custody);

  [Throws=ScpError]
  Identity identity_load(string did);

  [Throws=ScpError]
  DIDDocument identity_resolve(string did);
};

interface Identity {
  string did();
  string custody_type();

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

UniFFI supports Kotlin coroutines via `uniffi-kotlin-multiplatform`. This SDK wraps blocking FFI calls in `Dispatchers.IO` to avoid depending on the multiplatform plugin until it stabilizes:

```kotlin
class Context internal constructor(private val handle: ContextHandle) {
    val contextId: String get() = handle.contextId()
    val state: String get() = handle.state()

    suspend fun send(payload: ByteArray) = withContext(Dispatchers.IO) {
        handle.send(payload)
    }

    suspend fun invokeTool(toolId: String, input: Map<String, Any>): Map<String, Any> =
        withContext(Dispatchers.IO) {
            val json = Json.encodeToString(input)
            val result = handle.invokeTool(toolId, json)
            Json.decodeFromString(result)
        }

    fun receiveFlow(): Flow<Message> = callbackFlow {
        handle.subscribe { envelope ->
            trySend(envelope.toMessage())
        }
        awaitClose { handle.unsubscribe() }
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
    val senderDid: String,
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
    val operator: String,  // DID
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

```kotlin
class Identity private constructor(private val handle: IdentityHandle) {
    val did: String get() = handle.did()
    val custodyType: String get() = handle.custodyType()

    companion object {
        suspend fun create(custody: String = "platform"): Identity =
            withContext(Dispatchers.IO) {
                Identity(NativeLib.identityCreate(custody))
            }

        suspend fun load(did: String): Identity =
            withContext(Dispatchers.IO) {
                Identity(NativeLib.identityLoad(did))
            }
    }

    suspend fun rotateKey(): Identity = withContext(Dispatchers.IO) {
        Identity(handle.rotateKey())
    }
}
```

## Resource Management

Use `AutoCloseable` interface and `use { }` blocks:

```kotlin
class Context : AutoCloseable {
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun close() {
        scope.launch { leave() }
        scope.cancel()
        handle.let { ffi.ContextFree(it) }
    }

    suspend fun closeGracefully() {
        leave()
        handle.let { ffi.ContextFree(it) }
    }
}

// Usage
Context.create(params).use { ctx ->
    ctx.send(payload)
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
