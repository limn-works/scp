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

import kotlin.time.Duration
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
 * [SCP] implements [AutoCloseable] so it integrates with `use { }` blocks,
 * but note that `close()` is a no-op — callers must explicitly invoke
 * [shutdown] with a [CoroutineBridge] to drive the async FFI deadline.
 *
 * @see works.limn.scp.bridge.CoroutineBridge
 */
class SCP internal constructor(
    internal val inner: NativeScp,
) : AutoCloseable {
    /**
     * Constructs a fresh [SCP] with default in-memory state.
     *
     * Equivalent to the UniFFI `Scp()` constructor. No state is shared
     * with the process-wide default instance.
     *
     * @param storage Storage configuration. Defaults to
     *   [StorageConfig.InMemory]; filesystem variants land in Phase 4 PR 3.
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
     * Clears the suspended flag; the caller re-establishes the relay
     * connection explicitly.
     *
     * @throws uniffi.scp.ScpException.Context if the instance has been
     *   permanently shut down.
     */
    suspend fun resume(bridge: CoroutineBridge) {
        bridge.ffiCall { inner.resume() }
    }

    /**
     * Shuts down this instance with a graceful deadline.
     *
     * Awaits in-flight tasks up to [timeout], aborts any remaining
     * tasks, then runs typed-field cleanup. A second call is a no-op
     * (AlreadyShutDown is swallowed at the SDK surface).
     *
     * @param timeout Maximum duration to wait for in-flight tasks.
     *   Converted to whole seconds for the UniFFI boundary (sub-second
     *   precision is not preserved).
     */
    suspend fun shutdown(bridge: CoroutineBridge, timeout: Duration) {
        bridge.ffiCall { inner.shutdown(timeoutSecs = timeout.inWholeSeconds.toULong()) }
    }

    /**
     * [AutoCloseable] implementation — intentionally a no-op. The real
     * shutdown path requires a [CoroutineBridge] and must be called
     * from a coroutine scope; a synchronous `close()` cannot drive the
     * async FFI deadline. Callers using `use { }` blocks should invoke
     * [shutdown] explicitly inside the block.
     */
    override fun close() {
        // No-op: see KDoc above.
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
         * code.
         *
         * @throws uniffi.scp.ScpException.Context if the default instance
         *   is currently suspended or permanently shut down.
         */
        fun default(): SCP = SCP(NativeScp.defaultInstance())

        /**
         * Constructs an [SCP] with an explicit storage configuration.
         *
         * Phase 4 PR 1 honors only [StorageConfig.InMemory]; PR 3 adds
         * filesystem-backed variants.
         */
        fun withStorage(config: StorageConfig): SCP = SCP(NativeScp.withStorage(config))

        /**
         * Constructs an [SCP] with a persistence provider placeholder.
         *
         * Phase 4 PR 1 has no real persistence wiring; this factory
         * currently returns a fresh in-memory instance. PR 3 threads the
         * real `ContextPersistence` trait through.
         */
        fun withPersistence(): SCP = SCP(NativeScp.withPersistence())
    }
}
