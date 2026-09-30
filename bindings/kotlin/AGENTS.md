# Kotlin SDK (`scp-kt`) and Android adapter (`scp-kt-android`)

`scp-kt` is a thin layer over the UniFFI-generated bindings: every SDK method delegates through `bridge/CoroutineBridge.kt` to exactly one UniFFI function, and no protocol logic lives in Kotlin (ADR-028, the Kotlin SDK). FFI calls run on `Dispatchers.IO`, CPU-bound mapping on `Dispatchers.Default`, and the SDK never uses `Dispatchers.Main`. `scp-kt-android` implements the UniFFI callback interfaces with Android's platform security stack (ADR-027, the Android platform adapter) and adds lifecycle and Compose helpers. Follow `.docs/standards/kotlin.md`. mise supplies JDK 17 (zulu), Gradle 8.x, and Kotlin 2.x; run `eval "$(mise env)"`, then run Gradle from `bindings/kotlin/`.

## Build and generated code

- `./gradlew :scp-kt:generateUniffiBindings` needs the compiled Rust `cdylib`, because UniFFI embeds its metadata at compile time. It writes into the gitignored `scp-kt/src/main/kotlin/works/limn/scp/internal/`, inside the `src/main/kotlin` source root. Every task that reads that source root therefore declares `dependsOn("generateUniffiBindings")` (a reader of the generated code) or `mustRunAfter("generateUniffiBindings")` (detekt, ktlint, Dokka, which exclude it). Gradle reports a missing edge only when both tasks run in one build, which CI's separate lint, test, and docs jobs never do, so `checkUniffiBindingsOrdering` in `scp-kt/build.gradle.kts` enumerates the readers against Gradle's task model.
- detekt's `TooManyFunctions` threshold is 30 per file, so large suites split across files. A long single-parameter expression body that exceeds detekt's 120-character limit cannot be wrapped the way ktlint wants; shorten the parameter name or use a block body.

## Tests

- **JUnit 5 silently skips a `@Test` method that returns a value.** A Kotlin expression body takes its type from its last expression, and `assertNotNull`, `assertIs`, `assertIsNot`, and `requireNotNull` return their argument, so `fun x() = runBlocking { assertNotNull(y) }` never runs and appears in no pass, fail, or skip list. Give every `@Test` method a block body (`fun x() { runBlocking { … } }`). When a test run is your evidence, count the `<testcase>` elements in the JUnit XML against the file's `@Test` methods; `BUILD SUCCESSFUL` proves nothing.
- A backtick test name cannot contain `:`; use `-`.
- To assert that a `Flow` fails, use `async { runCatching { flow.first() } }`; `launch` propagates the exception and fails the test.
- `StandardTestDispatcher()` is a function returning `TestDispatcher`; declare fields as `TestDispatcher`.
- Raising a deprecation from `WARNING` to `ERROR` requires changing the tests' `@Suppress("DEPRECATION")` to `@Suppress("DEPRECATION_ERROR")`, or the tests stop compiling.
- A test that needs `android.util.Base64`, an application `Context`, or a Compose rule runs under Robolectric with JUnit 4 (`@RunWith(RobolectricTestRunner::class)`, `@Config(manifest = Config.NONE, sdk = [33])`); every other test uses JUnit 5.
- Both modules run their unit tests on the JUnit Platform: `scp-kt` through `useJUnitPlatform()` on `tasks.test`, and `scp-kt-android` through `unitTests.all { it.useJUnitPlatform() }`, which runs the JUnit 4 classes through `junit-vintage-engine`. Without it the Android Gradle plugin uses the JUnit 4 runner, which never discovers a Jupiter `@Test`.
- `flowWithLifecycle` and `repeatOnLifecycle` switch to `Dispatchers.Main.immediate`, which a local JVM test lacks; call `Dispatchers.setMain` in `@BeforeEach`.
- Kotlin mangles the JVM name of an `internal` member with the module name, so `getDeclaredMethod("name")` finds nothing; reference the member directly (`Type::member`).
- Pass `UnconfinedTestDispatcher(testScheduler)` to `TestLifecycleOwner` so lifecycle transitions apply immediately.

## Coroutines and streams

- A Rust callback (`onMessage`, `onEvent`) runs on a thread with no coroutine, so it cannot suspend: use `trySend` or `tryEmit`, and handle the `trySend` result.
- Every `callbackFlow` subscribes inside `try { withContext(NonCancellable + ioDispatcher) { handle = subscribe(...) }; awaitClose() }` and releases a recorded handle in that `try`'s `finally` through `withContext(NonCancellable + ioDispatcher)`, catching and logging an unsubscribe that throws (`.docs/standards/sdk-common.md` §Cleanup error handling; rethrown from that `finally`, it replaces the collector's cancellation as the failure and reaches the parent scope), never in `awaitClose`'s lambda, which runs on the collector's thread (an Android main thread under `collectAsState`). Record the handle inside the block: when `ioDispatcher` differs from the collector's dispatcher, so that `withContext` resumes the collector by dispatch, a collector cancelled during the subscribe makes `withContext` throw on that resumption, even under `NonCancellable`, and drop the block's return value. `HotStreamFactory` subscriptions outlive scope cancellation; stop them explicitly (`stopAll()` in teardown).
- `ViewModel.clear()` cancels `viewModelScope` before it calls `onCleared()`, so a launch into `viewModelScope` from `onCleared()` never runs; `ScpViewModel` launches its cleanup into its own scope and returns without blocking, because Android calls `onCleared()` on the main thread. A test that clears a view model goes through `ViewModelStore.clear()`, which runs that same cancel-then-`onCleared()` sequence.
- Compose does not cancel a `CoroutineScope` created inside `remember { }`. Pair it with `DisposableEffect { onDispose { scope.cancel() } }`, or reuse a managed scope.

## Android platform adapters

- UniFFI renames Rust methods to camelCase (`assert_request` → `assertRequest`); ADR-027's `assert()` sample is wrong. Read the Rust callback interface in `crates/scp-ffi/uniffi/src/lib.rs` for signatures.
- Shared types and callback interfaces live in `platform/Types.kt`; never redefine one in an adapter file. The Kotlin `StorageProvider` uses `set`/`get` like the UniFFI interface, although the Rust `Storage` trait says `store`/`retrieve`.
- `net.zetetic:sqlcipher-android` 4.6+ uses package `net.zetetic.database.sqlcipher.*`, loads with `System.loadLibrary("sqlcipher")` (there is no `loadLibs()`), takes the passphrase in the `SQLiteOpenHelper` constructor, and needs `androidx.sqlite:sqlite`.
- Generate an Android Keystore Ed25519 key with `NamedParameterSpec.ED25519`; `EdDSAParameterSpec` sets prehash mode and context, not the curve.
- A Keystore AES-GCM key used with a caller-supplied IV needs `.setRandomizedEncryptionRequired(false)`, or `Cipher.init()` throws `InvalidAlgorithmParameterException` on a device while every JVM test passes.
- Play Integrity calls fail on emulators and on devices without Google Play Services; unit tests cover the deterministic logic only.
- The Compose compiler is the `kotlin("plugin.compose")` Gradle plugin; the old `org.jetbrains.compose.compiler` artifact is not needed.
