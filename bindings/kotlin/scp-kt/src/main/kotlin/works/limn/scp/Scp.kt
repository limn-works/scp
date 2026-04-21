// Scp.kt — Kotlin SDK caller-owned SCP instance wrapper (#1549 Phase 4 PR 1, ADR-048).
//
// Each [SCP] wraps an independent UniFFI `Scp` opaque object (generated from
// `crates/scp-ffi/uniffi/src/scp.rs`). The class owns its own
// `UniffiBridgeInstance` — registries, transport, context manager — and is
// the preferred SDK entry point for multi-identity apps, per-tenant services,
// and parallel-safe tests.
//
// The free-function façade (`suspend(bridge, bindings)`, `resume(bridge,
// bindings)` in Lifecycle.kt, and the singleton-delegating top-level
// `suspend fun`s in the other modules) currently operates on the process-wide
// default instance and is annotated `@Deprecated` with
// `DeprecationLevel.WARNING`. Removal target: two release cycles after
// Phase 4 PR 1 merge.
//
// REGENERATION REQUIRED: The UniFFI-generated Kotlin bindings (`internal/`)
// are gitignored and regenerated at build time via
// `scripts/generate-uniffi-kotlin.sh` / `./gradlew :scp-kt:generateUniffiBindings`.
// The regenerated bindings include the `uniffi.scp.Scp` class, which this
// wrapper imports. In worktrees without the regenerated bindings, `./gradlew
// assembleRelease` fails at the `import uniffi.scp.Scp` line — this is
// expected; run `./gradlew generateUniffiBindings` first.
//
// Provenance: #1549, ADR-048, master plan decision 4 (SDK-facing class name).

@file:Suppress("MatchingDeclarationName")

package works.limn.scp

import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import java.util.logging.Level
import java.util.logging.Logger
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import uniffi.scp.Scp as NativeScp
import uniffi.scp.StorageConfig
import works.limn.scp.bridge.CoroutineBridge

/**
 * Caller-owned SCP instance — the preferred SDK entry point.
 *
 * Each [SCP] wraps an independent UniFFI `Scp` opaque object. Handles
 * minted by one instance are rejected by others via `HandleAffinityError`
 * at the FFI boundary.
 *
 * ```kotlin
 * // Fresh in-memory instance.
 * val scp = SCP()
 *
 * // Process-wide default (shared with the deprecated free-function façade).
 * val shared = SCP.default()
 *
 * // Graceful shutdown with a 1-second deadline for in-flight tasks.
 * val bridge = CoroutineBridge(...)
 * scp.shutdown(bridge, timeout = 1.seconds)
 * ```
 *
 * Not [AutoCloseable]: shutdown is a `suspend` function that drives an
 * async FFI deadline and requires a [CoroutineBridge]. A synchronous
 * `close()` cannot honor the timeout and would silently swallow it —
 * callers must invoke [shutdown] explicitly from a coroutine scope.
 *
 * @see works.limn.scp.bridge.CoroutineBridge
 */
class SCP internal constructor(
    internal val inner: NativeScp,
) {
    /**
     * Tracks whether [shutdown] has completed successfully. Read from the
     * finalizer fallback to decide whether to emit a "leaked without
     * shutdown" warning; written inside [shutdown] after the FFI call
     * returns. Must be atomic because finalizers run on a JVM-internal
     * thread pool that does not happen-before the coroutine that invoked
     * [shutdown].
     */
    private val isShutdown: AtomicBoolean = AtomicBoolean(false)

    /**
     * Constructs a fresh [SCP] with default in-memory state.
     *
     * Equivalent to the UniFFI `Scp()` constructor. No state is shared
     * with the process-wide default instance.
     *
     * @param storage Storage configuration. Defaults to
     *   [StorageConfig.InMemory]; [StorageConfig.Sqlite] is also supported
     *   (use [withSqlite] for the common on-disk case).
     */
    constructor(storage: StorageConfig = StorageConfig.InMemory) : this(NativeScp.withStorage(storage))

    /**
     * The monotonic identifier for this bridge instance, unique per
     * process. Used by the FFI handle-affinity check.
     */
    val instanceId: ULong
        get() = inner.instanceId()

    /**
     * Suspends this bridge instance (mobile/desktop backgrounding).
     *
     * Disconnects transport and flushes context snapshots.
     * Transport-dependent operations fail until [resume] is called.
     *
     * Dispatched on [kotlinx.coroutines.Dispatchers.IO] via the supplied
     * [CoroutineBridge].
     *
     * @throws uniffi.scp.ScpException.Transport if the transport lock is poisoned.
     */
    suspend fun suspend(bridge: CoroutineBridge) {
        bridge.ffiCall { inner.suspend() }
    }

    /**
     * Resumes a suspended bridge instance.
     *
     * Clears the suspended flag, then reconnects transport against pending
     * relay URLs and restores persisted contexts via the
     * [`BridgeInstanceCore::resume`](https://docs.rs/scp-ffi-common) override.
     * Routed through [CoroutineBridge.ffiCallSuspend] because UniFFI generates
     * `Scp.resume()` as a Kotlin `suspend fun` — the non-suspend [ffiCall]
     * lambda would reject the call.
     *
     * @throws uniffi.scp.ScpException.Context if the instance has been
     *   permanently shut down.
     */
    suspend fun resume(bridge: CoroutineBridge) {
        bridge.ffiCallSuspend { inner.resume() }
    }

    /**
     * Shuts down this instance with a graceful deadline.
     *
     * Awaits in-flight tasks up to [timeout], aborts any remaining
     * tasks, then runs typed-field cleanup. A second call is a no-op
     * (AlreadyShutDown is swallowed at the SDK surface).
     *
     * Converted to unsigned milliseconds for the UniFFI boundary after
     * the #1549 Phase 4 timeout unit unification — sub-millisecond
     * precision is not preserved. Negative durations are clamped to
     * zero.
     *
     * [timeout] defaults to 5 seconds — the same default the PyO3 and
     * NAPI SDK wrappers carry. Callers that need an explicit deadline
     * (e.g. abort immediately with `Duration.ZERO`, or wait
     * effectively-forever with a large `Duration.ofHours(n)`) pass the
     * argument explicitly. See PR #1690 retro api-design MODERATE.
     *
     * @param timeout Maximum duration to wait for in-flight tasks.
     *   Defaults to 5 seconds.
     */
    suspend fun shutdown(bridge: CoroutineBridge, timeout: Duration = 5.seconds) {
        val millis = timeout.inWholeMilliseconds.coerceAtLeast(0).toULong()
        bridge.ffiCallSuspend { inner.shutdown(timeoutMillis = millis) }
        // Record shutdown AFTER the FFI call returns so that a failed
        // shutdown does not silence the finalizer warning — a caller
        // who sees an exception here should know the instance is still
        // live and still worth a second [shutdown] attempt. SetRelease
        // orders the flip after the FFI mutation, matching Atomic default.
        isShutdown.set(true)
    }

    /**
     * Finalizer fallback: warns if the JVM garbage-collects an [SCP]
     * that was never [shutdown]. Callers MUST invoke [shutdown]
     * explicitly — the underlying `JoinSet` on the Rust side aborts
     * abruptly (not gracefully) when the opaque UniFFI handle is
     * dropped, so subscriptions and in-flight governance tasks lose
     * their chance to exit cleanly.
     *
     * Kotlin's `finalize()` is deprecated in favor of
     * `java.lang.ref.Cleaner` (JDK 9+), but Cleaner adds ceremony
     * (companion-hosted cleanup action, shared-executor, capturing
     * references carefully to avoid resurrection). For a simple
     * best-effort warning — where timing and ordering don't matter
     * because the Rust side does its own teardown on Drop — the
     * finalizer is sufficient and self-contained. When the JVM
     * finalizer is removed in a future release we will migrate to
     * Cleaner; the contract is unchanged.
     *
     * This is not a substitute for explicit shutdown. The Rust side
     * still tears down its `JoinSet` via Drop; the warning just makes
     * the resource leak visible to the developer.
     */
    @Suppress("ProtectedMemberInFinalClass", "Unused")
    protected fun finalize() {
        if (!isShutdown.get()) {
            Logger.getLogger("works.limn.scp.SCP").log(
                Level.WARNING,
                "SCP instance (id={0}) was garbage-collected without a shutdown() call. " +
                    "In-flight tasks (subscriptions, governance timeouts) were aborted " +
                    "abruptly instead of draining gracefully. Always call SCP.shutdown() " +
                    "explicitly — for example from a coroutine scope: " +
                    "`scope.launch { scp.shutdown(bridge, 5.seconds) }`.",
                arrayOf<Any>(instanceId),
            )
        }
    }

    companion object {
        /**
         * Returns a [SCP] wrapping the process-wide default instance.
         *
         * Repeated calls return distinct wrapper objects sharing the
         * same underlying UniFFI `Arc<UniffiBridgeInstance>` — their
         * [instanceId]s match.
         *
         * This is the bridge the deprecated free-function façade uses
         * under the hood. Prefer explicit construction ([SCP]) in new
         * code. Removal target: two release cycles after Phase 4 merge
         * (ADR-048).
         *
         * @throws uniffi.scp.ScpException.Context if the default instance
         *   is currently suspended or permanently shut down.
         */
        @Deprecated(
            message = (
                "SCP.default() returns the shared process-wide bridge instance. " +
                    "Construct `SCP()` explicitly per tenant/identity instead. " +
                    "Removal target: two release cycles after Phase 4 merge (ADR-048)."
            ),
            replaceWith = ReplaceWith("SCP()"),
            level = DeprecationLevel.WARNING,
        )
        fun default(): SCP = SCP(NativeScp.defaultInstance())

        /**
         * Constructs an [SCP] with an explicit storage configuration.
         *
         * Honors both [StorageConfig.InMemory] (encrypted in-memory,
         * ephemeral) and [StorageConfig.Sqlite] (SQLCipher-encrypted
         * on-disk, persistent). Prefer [withSqlite] when callers have a
         * directory and a raw key handy — it constructs the enum variant
         * for you.
         */
        fun withStorage(config: StorageConfig): SCP = SCP(NativeScp.withStorage(config))

        /**
         * Constructs an [SCP] backed by SQLCipher-encrypted on-disk storage.
         *
         * Convenience wrapper over [withStorage] for the common case:
         * given a directory and a raw encryption key, returns an [SCP]
         * whose underlying `UniffiBridgeInstance` persists context
         * snapshots and event log entries under `{dir}/scp.db`.
         *
         * The Rust bridge zeroizes its own copy of [key] after SQLCipher
         * consumes it internally; callers should zero their copy too
         * once the call returns. The directory is created implicitly
         * when SQLCipher opens the database file.
         *
         * @param dir Directory the database file is created in. Passed
         *   to the Rust side as `dir.absolutePath`.
         * @param key Raw encryption key material (typically 32 bytes).
         *   Callers are responsible for zeroizing their reference.
         */
        fun withSqlite(dir: File, key: ByteArray): SCP =
            SCP(
                NativeScp.withStorage(
                    StorageConfig.Sqlite(path = dir.absolutePath, key = key),
                ),
            )

        // NOTE: The bare UniFFI `Scp.withPersistence()` factory still
        // exists for internal use; it constructs a fresh instance with
        // no persistence attached and is not a useful entry point for
        // SDK callers. Production persistence flows through
        // [withStorage] / [withSqlite] and the `StorageConfig` enum.
    }
}
