// Lifecycle.kt — Kotlin SDK bridge lifecycle wrapper
//
// Wraps the UniFFI scp_suspend / scp_resume functions as Kotlin suspend
// helpers. Bindings are injected via LifecycleBindings so tests can stub
// the FFI layer.
//
// Provenance: scp-ffi-uniffi lib.rs (scp_suspend / scp_resume).

@file:Suppress("MatchingDeclarationName")

package works.limn.scp

import works.limn.scp.bridge.CoroutineBridge

/**
 * Bindings for the bridge lifecycle UniFFI exports.
 *
 * Both methods are blocking JNA calls into Rust and must be dispatched
 * on [kotlinx.coroutines.Dispatchers.IO].
 */
interface LifecycleBindings {
    /** Suspends the bridge instance (disconnects transport, sets suspended flag). */
    fun scpSuspend()

    /** Resumes a suspended bridge instance (clears suspended flag). */
    fun scpResume()
}

/**
 * Namespace object for default bindings; the generated UniFFI functions are
 * global, and this object lets SDK callers choose between the real bindings
 * and an injected stub for tests.
 */
object LifecycleBridge {
    /**
     * Default bindings — delegate to the UniFFI-generated `scpSuspend` /
     * `scpResume` top-level functions. The `internal/` package is generated
     * at build time (see `scripts/generate-uniffi-kotlin.sh`); tests
     * injecting a stub should supply their own [LifecycleBindings] instead.
     */
    val default: LifecycleBindings = object : LifecycleBindings {
        override fun scpSuspend() {
            uniffi.scp.scpSuspend()
        }

        override fun scpResume() {
            uniffi.scp.scpResume()
        }
    }
}

/**
 * Suspend the bridge instance for mobile/desktop backgrounding.
 *
 * Disconnects the transport (clearing the relay connection) and marks
 * the instance as suspended. Context state is preserved — the instance
 * remains alive but inactive. Transport-dependent operations will fail
 * until [resume] is called.
 *
 * After suspension, callers should call [resume] to re-activate and
 * then re-establish the relay connection via `transportConnect`.
 *
 * No-op if the bridge has not been initialized or has already shut down.
 *
 * @param bridge The coroutine bridge (used for dispatcher routing).
 * @param bindings Injectable bindings for testing; defaults to the
 *   UniFFI-generated functions.
 * @throws uniffi.scp.ScpException if transport cleanup fails.
 */
suspend fun suspend(
    bridge: CoroutineBridge,
    bindings: LifecycleBindings = LifecycleBridge.default,
) {
    bridge.ffiCall { bindings.scpSuspend() }
}

/**
 * Resume a suspended bridge instance.
 *
 * Clears the suspended flag so bridge operations can proceed. The caller
 * must re-establish the relay connection via `transportConnect` —
 * resume does not reconnect automatically.
 *
 * No-op if the bridge is not initialized.
 *
 * @param bridge The coroutine bridge (used for dispatcher routing).
 * @param bindings Injectable bindings for testing; defaults to the
 *   UniFFI-generated functions.
 * @throws uniffi.scp.ScpException if the bridge has been permanently shut down.
 */
suspend fun resume(
    bridge: CoroutineBridge,
    bindings: LifecycleBindings = LifecycleBridge.default,
) {
    bridge.ffiCall { bindings.scpResume() }
}
