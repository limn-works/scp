# scp-sdk-kotlin-android — Android Platform Adapter, Lifecycle & Compose Integration

## Overview

Android-specific platform trait implementations, lifecycle-aware resource management, and Jetpack Compose state holders for SCP. Implements the four UniFFI callback interfaces (`KeyCustodyProvider`, `DeviceAttestationProvider`, `PushProvider`, `StorageProvider`) using Android's native platform security stack (ADR-027), provides `LifecycleOwner`-aware cleanup of SCP resources (ADR-028), and exposes SCP context state as Compose-observable `State<T>` via remember-based patterns (ADR-028, SCP-118).

## Architecture

### Platform Adapters (`com.limn.scp.android.platform`)

Each platform trait is a Kotlin class that implements a UniFFI-generated callback interface. The Rust engine calls these via UniFFI's callback mechanism. All classes accept an Android `Context` parameter for platform API access.

| File | Trait | Platform API | Story |
|------|-------|-------------|-------|
| `AndroidDeviceAttestation.kt` | `DeviceAttestationProvider` | Play Integrity Standard API | SCP-111 |
| `AndroidKeyCustody.kt` | `KeyCustodyProvider` | Android Keystore (Ed25519 API 33+, Bouncy Castle fallback) | SCP-110 |
| `AndroidPushProvider.kt` | `PushProvider` | Firebase Cloud Messaging | SCP-112 |
| `AndroidStorage.kt` | `StorageProvider` | SQLCipher + TEE-derived AES-256 key | SCP-113 |
| `PlatformAdapter.kt` | Factory | Constructs and injects all four providers | SCP-114 |

### Lifecycle Integration (`com.limn.scp.android`)

Lifecycle-aware SCP resource management for Activities and Fragments. Keeps the core SDK Android-free.

| File | Purpose | Story |
|------|---------|-------|
| `ContextLifecycle.kt` | `Flow<T>.asLifecycleFlow(LifecycleOwner)` extension — scopes flow collection to lifecycle | SCP-117 |
| `ScpViewModel.kt` | `ScpViewModel` base class — tracks contexts, auto-cleanup on `onCleared()` | SCP-117 |

### Compose State Holders (`com.limn.scp.android.compose`)

Jetpack Compose integration via standard Compose patterns (`collectAsState()`, `DisposableEffect`, `remember`). No custom state management — thin wrappers that make SCP streams Compose-observable.

| Component | Purpose | Story |
|-----------|---------|-------|
| `ScpContextHolder` | Holds context handle + coroutine scope, cleaned up via `DisposableEffect` | SCP-118 |
| `rememberScpContext()` | Remember pattern for SCP context scoping with disposal cleanup | SCP-118 |
| `rememberScpFlow()` | Collect any `Flow<T>` as Compose `State<T>` via `collectAsState()` | SCP-118 |
| `rememberScpEventList()` | Accumulate `SharedFlow<String>` events into bounded `State<List<String>>` | SCP-118 |
| `rememberScpStateIn()` | Convert `Flow<T>` to `StateFlow` scoped to holder's coroutine scope | SCP-118 |
| `rememberScpHotStream()` | Managed hot stream subscription with `onStop` cleanup on disposal | SCP-118 |
| `ScpContextState` | Observable context state string wrapper with manual `refresh()` | SCP-118 |
| `rememberScpContextState()` | Remember pattern for `ScpContextState` keyed by context handle | SCP-118 |

## Gotchas

### UniFFI method naming: snake_case -> camelCase

The Rust `DeviceAttestationProvider` trait has `assert_request(request_hash)`. UniFFI generates Kotlin with camelCase: `assertRequest(requestHash)`. The ADR-027 code sample uses `assert()` which is **incorrect** — always check the UniFFI Rust trait definition in `crates/scp-ffi/uniffi/src/lib.rs` for authoritative method signatures.

### Shared types live in Types.kt

All shared types (`ScpException`, `WakeSignal`, `KeyType`, `CustodyType`, `KeyHandle`, `PseudonymKeyHandle`, `DestructionAttestation`, `DestructionMethod`) and trait interfaces (`KeyCustodyProvider`, `DeviceAttestationProvider`, `PushProvider`, `StorageProvider`) are defined in `Types.kt`. Do NOT define these types locally in adapter files. When UniFFI-generated bindings are available, replace `Types.kt` with the generated types.

`ScpException` uses the property name `code` (not `errorCode`). `WakeSignal` entries use UPPER_CASE (`PULL`, not `Pull`).

### android.util.Base64 in unit tests

`android.util.Base64` is not available in pure JVM unit tests. `AndroidDeviceAttestationTest` uses Robolectric (`@RunWith(RobolectricTestRunner::class)` + JUnit 4) to provide real `android.util.Base64` implementations on the host JVM. Other test files that don't need Android framework classes stay on JUnit 5.

### Context in unit tests

`AndroidDeviceAttestationTest` uses `ApplicationProvider.getApplicationContext()` from `androidx.test:core` (provided by Robolectric) for a real application context. `AndroidPushProviderTest` uses a null cast (`(null as Any?) as Context`) because it only needs the type, not a real context — this works with `isReturnDefaultValues = true` in testOptions. Integration tests on real devices should use `ApplicationProvider.getApplicationContext()`.

### Play Integrity requires real device

Play Integrity API calls fail on emulators and devices without Google Play Services. Unit tests cover deterministic logic only; integration tests require physical hardware.

### SQLCipher 4.6+ package rename

The dependency `net.zetetic:sqlcipher-android:4.6.x` uses package `net.zetetic.database.sqlcipher.*`. The old artifact `net.zetetic:android-database-sqlcipher:4.5.x` used `net.sqlcipher.database.*`. Key API differences: no `SQLiteDatabase.loadLibs()` (use `System.loadLibrary("sqlcipher")` instead), passphrase passed via `SQLiteOpenHelper` constructor (not `getWritableDatabase(String)`), and `SQLiteOpenHelper` implements `androidx.sqlite.db.SupportSQLiteOpenHelper` (requires `androidx.sqlite:sqlite:2.2.0`).

### EdDSA key generation uses NamedParameterSpec, not EdDSAParameterSpec

For Android Keystore Ed25519 key generation (API 33+), use `NamedParameterSpec.ED25519` as the algorithm parameter spec. `EdDSAParameterSpec` is for specifying prehash mode and context bytes, not the curve. The constant `Ed25519` lives on `NamedParameterSpec`, not `EdDSAParameterSpec`.

### Android Keystore AES-GCM requires setRandomizedEncryptionRequired(false) for deterministic IV

Android Keystore enforces randomized encryption by default for GCM keys. If you use a fixed/caller-supplied IV (as `AndroidStorage.getOrCreateStorageKey()` does for deterministic passphrase derivation), you **must** call `.setRandomizedEncryptionRequired(false)` on the `KeyGenParameterSpec.Builder`. Without this, `Cipher.init()` throws `InvalidAlgorithmParameterException` at runtime. This is invisible to JVM unit tests since they cannot use the real Android Keystore -- it only manifests on actual devices.

### StorageProvider method names match UniFFI callback interface

The Kotlin `StorageProvider` interface in `Types.kt` uses `set()`/`get()` matching the UniFFI `StorageProvider` callback interface in `crates/scp-ffi/uniffi/src/lib.rs`. The Rust `Storage` trait in `scp-platform/src/traits.rs` uses `store()`/`retrieve()` internally, but the UniFFI/Kotlin boundary uses `set`/`get`. The UniFFI trait uses `async` methods returning `Result<T, ScpError>` while the Kotlin interface uses synchronous methods with exceptions.

### SQL LIKE wildcards in prefix queries

`listKeys()` and `deletePrefix()` escape `%`, `_`, and `\` wildcards via `escapeLikePrefix()` and use `ESCAPE '\'` clauses in SQL LIKE patterns. The in-memory test double uses `startsWith` which does not need escaping but has equivalent prefix-match semantics.

### TestLifecycleOwner needs UnconfinedTestDispatcher for synchronous emission

`TestLifecycleOwner` from `lifecycle-runtime-testing` dispatches lifecycle events via a coroutine dispatcher. In tests, pass `UnconfinedTestDispatcher(testScheduler)` to `TestLifecycleOwner`'s constructor so lifecycle state changes take effect immediately. Using `StandardTestDispatcher` requires explicit `advanceUntilIdle()` calls between lifecycle transitions which can cause subtle ordering issues in flow collection tests.

### ScpViewModel.onCleared() must NOT use viewModelScope

DEFECT FOUND IN SCP-117 REVIEW: `ViewModel.clear()` cancels `viewModelScope` (via its `CloseableCoroutineScope` tag) **before** calling `onCleared()`. Any `viewModelScope.launch` inside `onCleared()` launches into a cancelled scope and silently does nothing — the coroutine is dropped. This means `ScpViewModel.onCleared()` as currently written does NOT call `leave()` on tracked contexts in production Android.

The fix is to use a dedicated cleanup scope held by the ViewModel:
```kotlin
private val cleanupScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

override fun onCleared() {
    cleanupScope.launch {
        val contexts = mutex.withLock {
            val snapshot = activeContexts.toList()
            activeContexts.clear()
            snapshot
        }
        for (ctx in contexts) {
            runCatching { ctx.bridge.context.leave(ctx.handle) }
        }
        cleanupScope.cancel()
    }
    super.onCleared()
}
```

Tests for `onCleared()` are also broken: `TestScpViewModel.callOnCleared()` calls `onCleared()` directly without pre-cancelling `viewModelScope`, so the tests pass but mask the production bug. Correct test strategy: use Robolectric with the real `ViewModelProvider` lifecycle, or restructure cleanup to use the dedicated scope above so its cancellation is controllable in tests.

In tests, set `Dispatchers.setMain(testDispatcher)` before constructing the ViewModel and call `Dispatchers.resetMain()` in teardown.

### Compose tests require Robolectric + JUnit 4

Compose UI tests (`createComposeRule()`) require `@RunWith(RobolectricTestRunner::class)` and JUnit 4's `@Rule` annotation for the Compose test rule. They cannot use JUnit 5's `@ExtendWith`. Use `@Config(manifest = Config.NONE, sdk = [33])` for headless execution. The `compose-ui-test-junit4` dependency is `testImplementation`, and `compose-ui-test-manifest` is `debugImplementation`.

### Compose plugin is kotlin("plugin.compose"), not a separate artifact

With Kotlin 2.x, the Compose compiler is built into the Kotlin compiler plugin. Declare `kotlin("plugin.compose")` in both the root `build.gradle.kts` (with `apply false`) and the android module. The old `org.jetbrains.compose.compiler` artifact is not needed. The Compose BOM (`androidx.compose:compose-bom:2024.12.01`) manages runtime/UI version alignment.

### rememberScpEventList accumulator uses synchronized, not mutex

The `rememberScpEventList` accumulator list is mutated inside a `map` operator on a `SharedFlow`. Since `map` can run on any dispatcher and the list is shared across the transform chain, access is synchronized via `synchronized(accumulator)` rather than a coroutine `Mutex` (which would require `suspend` context inside `map`).

### Anonymous CoroutineScope inside remember() leaks — always pair with DisposableEffect cancel

Any `CoroutineScope(...)` created inside a `remember { }` block is invisible to Compose. Compose will NOT cancel it when the Composable leaves composition. The scope's `SupervisorJob` keeps the scope and its child coroutines alive indefinitely — a resource leak.

Pattern to avoid:
```kotlin
// WRONG: scope is never cancelled
val stateFlow = remember(key) {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    someFlow.stateIn(scope, ...)
}
```

Correct pattern: hoist the scope out of the stateIn remember block and pair it with `DisposableEffect`:
```kotlin
// CORRECT: scope cancelled on disposal
val scope = remember(key) { CoroutineScope(SupervisorJob() + Dispatchers.Default) }
DisposableEffect(key) { onDispose { scope.cancel() } }
val stateFlow = remember(key) { someFlow.stateIn(scope, ...) }
```

Alternatively, use Compose's built-in `rememberCoroutineScope()` for the default dispatcher, or reuse an existing managed scope (e.g., `holder.scope` from `ScpContextHolder`) so cancellation is already handled.

This bug was flagged in the SCP-118 review. `rememberScpEventList` creates an anonymous scope that is never cancelled. `rememberScpStateIn` avoids this correctly by reusing `holder.scope`.

### Lifecycle extension is generic, not SCP-specific

`asLifecycleFlow` is defined as `Flow<T>.asLifecycleFlow()` (generic), not `Flow<Message>.asLifecycleFlow()`. This works with any Flow type including the bridge's `Flow<String>` from `ContextBridge.subscribe()` and the future ergonomics layer's `Flow<Message>` from `Context.receiveFlow()`.

## Build

```bash
# From bindings/kotlin/
./gradlew :scp-sdk-kotlin-android:build
./gradlew :scp-sdk-kotlin-android:test

# Requires Android SDK, Kotlin, Gradle (available via mise)
```

## Dependencies (from build.gradle.kts)

- `androidx.compose:compose-bom:2024.12.01` — Compose version alignment (SCP-118)
- `androidx.compose.runtime:runtime` — Compose runtime: `State<T>`, `collectAsState()`, `remember`, `DisposableEffect` (SCP-118)
- `androidx.compose.ui:ui` — Compose UI foundation (SCP-118)
- `androidx.lifecycle:lifecycle-runtime-ktx:2.8.7` — `flowWithLifecycle()` for lifecycle-scoped flows (SCP-117)
- `androidx.lifecycle:lifecycle-viewmodel-ktx:2.8.7` — ViewModel + `viewModelScope` (SCP-117)
- `com.google.android.play:integrity:1.4.0` — Play Integrity API
- `org.bouncycastle:bcprov-jdk18on:1.80` — Software Ed25519 fallback
- `com.google.firebase:firebase-messaging:24.1.0` — FCM push
- `net.zetetic:sqlcipher-android:4.6.1` — Encrypted storage (package: `net.zetetic.database.sqlcipher.*`)
- `androidx.sqlite:sqlite:2.2.0` — Required companion for sqlcipher-android 4.6+
- `androidx.security:security-crypto:1.1.0-alpha06` — EncryptedSharedPreferences
- `org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0` — Coroutines
- `org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0` — Android dispatcher
- `androidx.compose.ui:ui-test-junit4` — (test) Compose test rule for Robolectric (SCP-118)
- `androidx.lifecycle:lifecycle-runtime-testing:2.8.7` — (test) `TestLifecycleOwner` for lifecycle tests

## Standards

Follow `.docs/standards/kotlin.md` for code style, naming, and testing conventions. Key rules:
- All I/O operations are `suspend` functions
- Blocking FFI calls wrapped in `withContext(Dispatchers.IO)`
- JUnit 5 with backtick-quoted test names (except Robolectric tests which require JUnit 4 `@RunWith`)
- `kotlinx.coroutines.test.runTest` for suspend function tests
