# Kotlin SDK Scaffold

> Source of truth: .docs/specs/, .docs/sketch.md, .docs/adrs/. This file is downstream of those documents.

Build blueprint for the SCP Kotlin SDK: package structure, UniFFI bridge patterns, build configuration, and type definitions. See `.docs/standards/kotlin.md` for coding standards (style rules, linting, testing, CI).

## Package Layout

The tree lists the files `git ls-tree` shows under `bindings/kotlin/`, plus the generated UniFFI bindings, which the build writes and the repository does not track.

```
bindings/kotlin/
  AGENTS.md                      # Kotlin rules, including §Coroutines and streams
  README.md
  build.gradle.kts               # Root build config
  settings.gradle.kts
  gradle.properties
  detekt.yml
  gradlew, gradlew.bat, gradle/wrapper/
  examples/
    BasicMessaging.kt
    McpIntegration.kt
    MultiAgent.kt
    OutletInvocation.kt
  scp-kt/
    build.gradle.kts             # SDK module build; runs the UniFFI generator
    src/main/kotlin/works/limn/scp/
      SCP.kt                     # SCP instance class and its suspend shutdown(bridge, timeout)
      Server.kt                  # ServerBindings, ServerBridge, and Relay and Node with their suspend shutdown()
      Identity.kt                # IdentityAdvancedBridge, IdentityAdvancedBindings, and the data classes their operations return
      BridgeConnector.kt
      ConsequenceRule.kt
      Discovery.kt
      Economy.kt
      Media.kt
      Metadata.kt
      Outlets.kt
      OutletsStreaming.kt        # InvocationHandle and its suspend cancel()
      Provenance.kt
      Sync.kt
      Trust.kt
      TrustAdmission.kt
      TrustAggregate.kt
      Types.kt
      auth/ScpId.kt
      bridge/CoroutineBridge.kt  # CoroutineBridge and its injected ioDispatcher
      stream/Streams.kt          # ColdStreamFactory, HotStreamFactory, ColdMessageFlow
      internal/
        uniffi/scp/scp.kt        # UniFFI-generated bindings (generated, not tracked)
    src/test/kotlin/works/limn/scp/
      EconomyFormatTest.kt
      ErrorCodeTest.kt
      IdentityAgentKeyRealFfiTest.kt
      IdentityAttestationTest.kt
      IdentityVerifyLinkAttestationFfiTest.kt
      JoinFromWelcomeTest.kt
      McpAllowlistTest.kt
      NativeLibraryPathTest.kt
      OutletDefinitionTest.kt
      OutletSagaTest.kt
      OutletStreamingSagaTest.kt
      OutletsStreamingTest.kt
      PersistenceTest.kt
      ScpClassTest.kt
      ScpShutdownTest.kt
      ServerTest.kt
      SiteConfigTest.kt
      SmokeTest.kt
      TestVectorTest.kt
      TrustAdmissionFfiTest.kt
      TrustAdmissionTest.kt
      TrustAggregateFfiTest.kt
      TrustAggregateTest.kt
      TrustTest.kt
      TypesTest.kt
      ValidationTest.kt
      auth/ScpIdTest.kt
      bridge/
        CoroutineBridgeTest.kt
        IdentityAdvancedBridgeTest.kt
        SyncBridgeTest.kt
      conformance/
        ConformanceDispatcher.kt
        ConformanceFixture.kt
        ConformanceRunnerTest.kt
        ConformanceStubBindings.kt
        ContextConformanceTest.kt
        EncryptionConformanceTest.kt
        EventLogConformanceTest.kt
        GovernanceConformanceTest.kt
        IdentityConformanceTest.kt
        MessagingConformanceTest.kt
        OutletsConformanceTest.kt
        TransportConformanceTest.kt
        UcanConformanceTest.kt
      stream/
        StreamsTest.kt
        SubscriptionReleaseProbe.kt
  scp-kt-android/
    build.gradle.kts
    src/main/AndroidManifest.xml
    src/main/kotlin/works/limn/scp/android/
      ContextLifecycle.kt
      ScpViewModel.kt            # ScpViewModel; onCleared() launches its leave calls and returns
      compose/StateHolders.kt    # ScpHotStreams, its coordinator, and the remember* state holders
      platform/
        AndroidDeviceAttestation.kt
        AndroidKeyCustody.kt
        AndroidPushProvider.kt
        AndroidStorage.kt
        PlatformAdapter.kt
        Types.kt
    src/test/kotlin/works/limn/scp/android/
      ContextLifecycleTest.kt
      DispatcherInjectionScanTest.kt
      ScpViewModelCleanupLoggingTest.kt
      ScpViewModelTest.kt
      compose/StateHoldersTest.kt
      platform/
        AndroidDeviceAttestationTest.kt
        AndroidKeyCustodyTest.kt
        AndroidPushProviderTest.kt
        AndroidStorageTest.kt
        StorageConformanceTest.kt
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
- `scp-kt/src/main/kotlin/works/limn/scp/internal/uniffi/scp/scp.kt` — JNA bindings to the Rust shared library, in package `uniffi.scp`
- Kotlin classes wrapping each interface
- Kotlin enums for error types

### Async bridging

UniFFI supports Kotlin coroutines via `uniffi-kotlin-multiplatform`. This SDK wraps blocking FFI calls in an injected `ioDispatcher` (`CoroutineBridge.ioDispatcher`, which defaults to `Dispatchers.IO`) to avoid depending on the multiplatform plugin until it stabilizes. A test injects a `StandardTestDispatcher` there, so no FFI call and no subscription release in SDK code may name `Dispatchers.IO` directly; `DispatcherInjectionScanTest` in `scp-kt-android` fails on a `withContext` over `Dispatchers.IO` in either module's main sources outside the `platform` package, whose adapters call Play Integrity and Firebase and never the SCP FFI. The `Context` class below is superseded: ADR-048 removed `Context` from the Kotlin surface, so no `Context.kt` ships and the sketch binds no code. It still shows the injected `ioDispatcher` and the `callbackFlow` subscription release that `bindings/kotlin/AGENTS.md` §Coroutines and streams requires of every shipped stream; a context is a handle that `CoroutineBridge.context` operates on.

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
    // collector's thread, an Android main thread under collectAsState. Log a release that
    // throws instead of rethrowing it (sdk-common.md §Cleanup error handling): rethrown from
    // the finally, it would replace the collector's cancellation as the failure and propagate
    // to the collector's parent scope.
    fun receiveFlow(): Flow<Message> = callbackFlow {
        var subscription: Subscription? = null
        try {
            withContext(NonCancellable + ioDispatcher) {
                subscription = handle.subscribe { envelope ->
                    val result = trySend(envelope.toMessage())
                    if (result.isFailure && !result.isClosed) {
                        close(ContextException("Message buffer overflow", "SCP-CTX-2001"))
                    }
                }
            }
            awaitClose()
        } finally {
            val opened = subscription
            if (opened != null) {
                withContext(NonCancellable + ioDispatcher) {
                    // NonCancellable keeps the collector's cancellation out of this catch.
                    try {
                        opened.unsubscribe()
                    } catch (e: Exception) {
                        System.getLogger("works.limn.scp.Context")
                            .log(System.Logger.Level.WARNING, "unsubscribe failed when receiveFlow() closed", e)
                    }
                }
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

Superseded. `scp-kt` ships no hand-written `Identity` wrapper, so this sketch binds no code: `SCP` operations take the UniFFI-generated `uniffi.scp.Identity`, which `scp-kt` compiles from the bindings under `src/main/kotlin/works/limn/scp/internal`, and the shipped `Identity.kt` holds `IdentityAdvancedBridge` and the data classes its operations return.

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

`SCP.shutdown(bridge, timeout)` and `InvocationHandle.cancel()` are the Kotlin teardowns that reach the Rust engine today; `cancel()` suspends on the UniFFI-generated async `Scp.outletStreamCancel`. `Relay` and `Node` follow the same rule, but no production class implements the `ServerBindings` interface they call (`.docs/standards/sdk-capability-matrix.json` marks every Server operation `"kotlin": false`), so their `shutdown()` reaches only the test source set's `StubServerBindings`. `ScpHotStreams.close()` (`scp-kt-android`) follows it too, and no production class implements the `EventContextBindings` interface it releases through, so it reaches only test stubs.

```kotlin
class SCP internal constructor(
    private val inner: NativeScp,
) {
    private val shutdownRecorded = AtomicBoolean(false)

    // The only stop path. It suspends on the bridge's injected ioDispatcher. A failed
    // teardown propagates and leaves the flag false, so the instance still reads as live.
    // shutdown sets the flag inside the bridge block, because withContext checks for cancellation
    // as it returns: a flag set after ffiCallSuspend returned would stay false for a caller
    // cancelled after a finished teardown.
    suspend fun shutdown(bridge: CoroutineBridge, timeout: Duration = 5.seconds) {
        val millis = timeout.inWholeMilliseconds.coerceAtLeast(0).toULong()
        bridge.ffiCallSuspend {
            inner.shutdown(timeoutMillis = millis)
            // Reached only when the FFI call returns; an engine failure throws first.
            shutdownRecorded.set(true)
        }
    }
}

// Usage: call shutdown() from a coroutine the caller owns, never through runBlocking.
// Run it under NonCancellable: a finally block usually runs because the coroutine was
// cancelled, and in a cancelled coroutine the bridge's withContext(ioDispatcher) throws
// CancellationException before the FFI call starts, so a bare shutdown() tears nothing down.
// SCP.withStorage blocks, so the caller runs it on a dispatcher it injects (ioDispatcher,
// defaulting to Dispatchers.IO), never on Dispatchers.IO named at the call.
val scp = withContext(ioDispatcher) { SCP.withStorage(config) }
try {
    scp.contextCreate(identity, params)
} finally {
    withContext(NonCancellable) { scp.shutdown(bridge) }
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
