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

### Streaming

`callbackFlow` with `Channel.BUFFERED` (64 items) for message subscription. Cold stream semantics: subscription starts on collect, stops on cancel.

## Gotchas

### detekt TooManyFunctions (threshold: 11)

The `NativeBindings` interface has 19 methods (one per UniFFI function). It is split into 5 domain sub-interfaces (`IdentityBindings`, `ContextBindings`, `ToolBindings`, `UcanBindings`, `InfraBindings`) with `NativeBindings` as the composite. The test stub `StubNativeBindings` uses `@Suppress("TooManyFunctions")` since it must implement all 19.

### ktlint vs detekt line length conflict

ktlint's `function-body-expression-wrapping` rule wants single-line expression bodies when they fit, but detekt's `MaxLineLength` (120 chars) rejects long lines. When a single-param function's expression body exceeds 120 chars, shorten the parameter name or restructure to a block body. Do NOT use multi-line parameter formatting for single-param functions — ktlint rejects it.

### StandardTestDispatcher is a function, not a type

In `kotlinx-coroutines-test`, `StandardTestDispatcher()` is a top-level function returning `TestDispatcher`. Declare test fields as `TestDispatcher`, not `StandardTestDispatcher`.

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

## Standards

Follow `.docs/standards/kotlin.md` for code style, naming, and testing conventions. Key rules:
- All I/O operations are `suspend` functions
- Blocking FFI calls wrapped in `withContext(Dispatchers.IO)`
- JUnit 5 with backtick-quoted test names
- `kotlinx.coroutines.test.runTest` for suspend function tests
