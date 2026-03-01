# scp-sdk-kotlin — Kotlin SDK Core Module

## Overview

Pure Kotlin ergonomics layer over UniFFI-generated Rust bindings. Provides idiomatic Kotlin API: `suspend` functions, `Flow<T>` streaming, `AutoCloseable` lifecycle. Zero protocol logic — every SDK method delegates through the coroutine bridge to exactly one UniFFI function (ADR-028 flat delegation pattern).

## Architecture

### Coroutine Bridge (`bridge/CoroutineBridge.kt`)

The single dispatcher gateway for all FFI calls. All SDK domain classes (Scp.kt, Context.kt, Identity.kt, etc.) delegate through this bridge.

| Component | Purpose |
|-----------|---------|
| `CoroutineBridge` | Central bridge with injectable dispatchers and domain sub-bridges |
| `IdentityBridge` | `create()`, `load()`, `resolve()` |
| `ContextBridge` | `create()`, `join()`, `leave()`, `close()`, `send()`, `subscribe()` |
| `ToolBridge` | `register()`, `invoke()`, `verify()` |
| `UcanBridge` | `validate()`, `mint()`, `revoke()` |
| `InfraBridge` | `eventLogQuery()`, `eventLogVerify()`, `transportConnect()`, `transportStatus()` |
| `NativeBindings` | Composite interface for UniFFI-generated functions (swap impl when NativeLib.kt is generated) |
| `CancellationHandle` | Thread-safe cancellation propagation to Rust for long-running ops |
| `BridgeException` | Carries structured SCP error codes from FFI layer |

### Dispatcher Strategy (ADR-028)

- **`Dispatchers.IO`**: All FFI calls (blocking JNA into Rust). Uses `ffiCall()` internally.
- **`Dispatchers.Default`**: CPU-bound work (JSON serialization, data mapping). Uses `cpuBound()`.
- **`Dispatchers.Main`**: Never used by the SDK. Only by Android ViewModels.

### Streaming (`stream/Streams.kt`)

Two-tier streaming architecture per ADR-028:

| Component | Type | API | Backpressure | Use Case |
|-----------|------|-----|--------------|----------|
| `ColdStreamFactory` | Cold | `Flow<String>` | Collector-driven (natural) | Paginated queries: event log, message history |
| `HotStreamFactory` | Hot | `SharedFlow<String>` | `DROP_OLDEST` (64 buffer) | Real-time events, multi-collector messages |
| `ColdMessageFlow` | Cold | `Flow<String>` via `callbackFlow` | `trySend` + explicit error on overflow | Single-collector message subscription (fixes SCP-115) |

**Cold streams** use `flow {}` builder with `withContext(ioDispatcher)` for FFI calls. Lazy: no work until collected.

**Hot streams** use `MutableSharedFlow` with `extraBufferCapacity = 64` and `BufferOverflow.DROP_OLDEST`. Callbacks from Rust use `tryEmit()` (non-blocking, never suspends). Multiple concurrent collectors supported. Idempotent: same SharedFlow returned for same context handle.

**`EventContextBindings`** extends `ContextBindings` with `contextSubscribeEvents()` / `contextUnsubscribeEvents()` for lifecycle event streams. When UniFFI generates the real bindings, implement this interface alongside `NativeBindings`.

## Gotchas

### detekt TooManyFunctions (threshold: 30)

The `NativeBindings` interface has 19 methods (one per UniFFI function). It is split into 5 domain sub-interfaces (`IdentityBindings`, `ContextBindings`, `ToolBindings`, `UcanBindings`, `InfraBindings`) with `NativeBindings` as the composite. The test stub `StubNativeBindings` uses `@Suppress("TooManyFunctions")` since it must implement all 19. The file-level threshold is 30 (set in `detekt.yml` per `standards/kotlin.md`).

### ktlint vs detekt line length conflict

ktlint's `function-body-expression-wrapping` rule wants single-line expression bodies when they fit, but detekt's `MaxLineLength` (120 chars) rejects long lines. When a single-param function's expression body exceeds 120 chars, shorten the parameter name or restructure to a block body. Do NOT use multi-line parameter formatting for single-param functions — ktlint rejects it.

### StandardTestDispatcher is a function, not a type

In `kotlinx-coroutines-test`, `StandardTestDispatcher()` is a top-level function returning `TestDispatcher`. Declare test fields as `TestDispatcher`, not `StandardTestDispatcher`.

### Streaming: Do NOT use suspending send() in Rust callbacks

Rust callbacks (`onMessage`, `onEvent`) run on non-coroutine threads. You cannot call suspending functions inside them. Use `trySend()` (in callbackFlow) or `tryEmit()` (in SharedFlow) -- both are non-blocking. Always handle the result of `trySend()` explicitly; the SCP-115 bridge silently discarded it.

### Streaming: No double-buffering

`callbackFlow` already has an internal `Channel.BUFFERED` buffer (64 items). Do NOT chain `.buffer(Channel.BUFFERED)` on the returned flow -- that creates ~128 total capacity and the documented 64-item invariant from ADR-028 is violated. The bridge-level `ContextBridge.subscribe()` has this bug; `ColdMessageFlow` in the stream package does not.

### Streaming: Always populate awaitClose in callbackFlow

`awaitClose { }` with an empty body means the Rust-side subscription handle is never released -- resource leak. Always call `contextUnsubscribe(handle)` inside `awaitClose`. Use `runBlocking(Dispatchers.IO)` (not the injected test dispatcher) to avoid deadlock in single-threaded test scenarios.

### Streaming: Hot stream cleanup is explicit

`HotStreamFactory` subscriptions are not tied to coroutine scope cancellation. You must call `stopContextEvents()`, `stopMessageStream()`, or `stopAll()` explicitly during teardown. In tests, use `@AfterEach` to call `factory.stopAll()`.

### UniFFI NativeLib.kt does not exist yet

The `NativeBindings` interface defines placeholder signatures matching ADR-028. When UniFFI generates `internal/NativeLib.kt`, create a concrete `NativeBindings` implementation that delegates to it.

## Build

```bash
# From bindings/kotlin/
./gradlew :scp-sdk-kotlin:build    # Full build (detekt + ktlint + compile + test)
./gradlew :scp-sdk-kotlin:test     # Tests only
./gradlew :scp-sdk-kotlin:detekt   # Static analysis only
./gradlew :scp-sdk-kotlin:runKtlintFormatOverMainSourceSet  # Auto-format
```

## Publishing (SCP-119)

Maven Central publishing is configured via `maven-publish` + `signing` plugins.

```bash
./gradlew :scp-sdk-kotlin:publishToMavenLocal    # Local testing
./gradlew :scp-sdk-kotlin:publish                 # Deploy to Sonatype OSSRH
```

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `MAVEN_CENTRAL_USERNAME` | Sonatype OSSRH username |
| `MAVEN_CENTRAL_TOKEN` | Sonatype OSSRH token |
| `GPG_KEY_ID` | GPG signing key ID |
| `GPG_PRIVATE_KEY` | ASCII-armored GPG private key |
| `GPG_PASSPHRASE` | GPG key passphrase |

Signing is skipped when `GPG_PRIVATE_KEY` is not set (local dev builds).

### Repositories

- **Staging** (releases): `https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/`
- **Snapshots**: `https://s01.oss.sonatype.org/content/repositories/snapshots/`

## Standards

Follow `.docs/standards/kotlin.md` for code style, naming, and testing conventions. Key rules:
- All I/O operations are `suspend` functions
- Blocking FFI calls wrapped in `withContext(Dispatchers.IO)`
- JUnit 5 with backtick-quoted test names
- `kotlinx.coroutines.test.runTest` for suspend function tests
