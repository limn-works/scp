// ScpViewModel.kt — Base ViewModel with SCP resource lifecycle management (SCP-117)
//
// Tracks active SCP context handles and cleans them up when the ViewModel is cleared.
// Prevents resource leaks when Activities/Fragments are destroyed. Subclass this in
// your app's ViewModels to get automatic SCP resource cleanup.
//
// Provenance: ADR-028 (Kotlin SDK) Android lifecycle integration, SCP-117

package works.limn.scp.android

import android.util.Log
import androidx.lifecycle.ViewModel
import works.limn.scp.bridge.CoroutineBridge
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Resource handle for an active SCP context tracked by [ScpViewModel].
 *
 * Encapsulates the opaque context handle returned by [CoroutineBridge.ContextBridge.create]
 * or [CoroutineBridge.ContextBridge.join], the identity handle of the member, and the bridge
 * needed to call [leave] on cleanup.
 *
 * @property handle Opaque context handle from the FFI layer.
 * @property identityHandle Opaque identity handle for the member in this context.
 * @property bridge The [CoroutineBridge] used to dispatch cleanup operations.
 */
data class TrackedContext(
    val handle: Long,
    val identityHandle: Long,
    val bridge: CoroutineBridge,
)

/**
 * Base [ViewModel] that manages SCP resource lifecycle.
 *
 * Extend this class in your app's ViewModels to get automatic cleanup of SCP connections,
 * streams, and subscriptions when the ViewModel is cleared (i.e., when the associated
 * Activity or Fragment is destroyed and not recreating due to configuration change).
 *
 * Per ADR-028, the recommended pattern is:
 * 1. Create [CoroutineBridge] and context handles in the ViewModel
 * 2. Track contexts via [trackContext]
 * 3. Expose message flows via `stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())`
 * 4. Override [onCleared] calls [leave] on all tracked contexts automatically
 *
 * Usage:
 * ```kotlin
 * class ChatViewModel(private val bridge: CoroutineBridge) : ScpViewModel() {
 *     private val identityHandle = ...
 *     private val contextHandle = ...
 *
 *     init {
 *         trackContext(TrackedContext(contextHandle, identityHandle, bridge))
 *     }
 *
 *     val messages: StateFlow<List<String>> = bridge.context
 *         .subscribe(contextHandle)
 *         .asLifecycleFlow(...)
 *         .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
 * }
 * ```
 *
 * Thread safety: [trackContext] and [untrackContext] are safe to call from any coroutine
 * or thread. A monitor lock guards the internal context list. Neither method suspends and
 * neither blocks on coroutine machinery, so a caller running on a single-threaded
 * dispatcher cannot deadlock on them.
 *
 * @param cleanupDispatcher Dispatcher that runs the cleanup coroutine [onCleared] launches.
 *   That coroutine calls [CoroutineBridge.ContextBridge.leave], which dispatches its own FFI
 *   call onto the bridge's IO dispatcher. Defaults to [Dispatchers.IO]. A test injects the
 *   same `TestDispatcher` it gave [CoroutineBridge], so `advanceUntilIdle()` runs the cleanup
 *   coroutine and every `leave` call the coroutine makes.
 *
 * A Java subclass calls `super()`, so this class must keep a zero-argument JVM constructor.
 * Two rules supply one today, and `javap` on a compiled class reports an identical
 * constructor set under either: Kotlin emits a parameterless constructor whenever every
 * primary-constructor parameter carries a default, and `@JvmOverloads` emits one overload per
 * defaulted parameter. `@JvmOverloads` therefore adds nothing at one parameter; it starts
 * adding intermediate overloads as soon as a second defaulted parameter appears, which is why
 * it stays. Neither rule survives a parameter added without a default, so
 * `ScpViewModelTest.ScpViewModel exposes a zero-argument constructor to Java callers` asserts
 * that constructor by reflection.
 */
abstract class ScpViewModel @JvmOverloads constructor(
    cleanupDispatcher: CoroutineDispatcher = Dispatchers.IO,
) : ViewModel() {

    private val contextsLock = Any()
    private val activeContexts = mutableListOf<TrackedContext>()
    private val cleanupScope = CoroutineScope(SupervisorJob() + cleanupDispatcher)

    /**
     * Register a context for automatic cleanup on ViewModel clear.
     *
     * Call this after creating or joining a context to ensure it is cleaned up
     * when the ViewModel is destroyed. Returns the same [TrackedContext] for
     * chaining convenience.
     *
     * @param context The [TrackedContext] wrapping the context handle and bridge.
     * @return The same [context] passed in, for chaining.
     */
    fun trackContext(context: TrackedContext): TrackedContext {
        synchronized(contextsLock) { activeContexts.add(context) }
        return context
    }

    /**
     * Remove a context from automatic cleanup tracking.
     *
     * Call this if you manually close or leave a context before the ViewModel is cleared,
     * to avoid double-cleanup.
     *
     * @param context The [TrackedContext] to stop tracking.
     */
    fun untrackContext(context: TrackedContext) {
        synchronized(contextsLock) { activeContexts.remove(context) }
    }

    /**
     * Called when the ViewModel is cleared (Activity/Fragment destroyed permanently).
     *
     * What this method guarantees when it returns:
     * - [activeContexts] is empty, and a snapshot taken under [contextsLock] holds every
     *   context that [trackContext] registered and [untrackContext] did not remove. A second
     *   [onCleared] call therefore finds nothing to leave.
     * - A coroutine is submitted to [cleanupScope]. That coroutine calls
     *   [CoroutineBridge.ContextBridge.leave] once per snapshotted context, in snapshot
     *   order, unless one `leave` throws [CancellationException].
     * - A `leave` call that throws any exception other than [CancellationException] does not
     *   stop remaining `leave` calls. A `leave` call that throws [CancellationException]
     *   does stop them, because that exception reports that this cleanup coroutine was
     *   cancelled, and a coroutine must never swallow its own cancellation.
     *
     * What this method does not guarantee: that a submitted coroutine has started, or that
     * `leave` calls have finished. Cleanup is best-effort — those calls run to completion only
     * if a process outlives them. Blocking until they finish is not an option: [onCleared] runs
     * on an Android main thread, and blocking that thread on FFI calls both risks an ANR and
     * deadlocks whenever an injected dispatcher schedules its work onto a blocked thread.
     *
     * Uses a dedicated [cleanupScope] because `viewModelScope` is already cancelled before
     * [onCleared] is called, so a coroutine launched there would be dropped without running.
     * [onCleared] does not cancel [cleanupScope] afterwards. A [SupervisorJob] whose children
     * have all completed holds no thread, no handle, and no memory a cancellation would
     * release, and `cleanupDispatcher` belongs to whoever constructed this ViewModel, so
     * cancelling that job frees nothing. Cancelling it would instead make every later
     * [cleanupScope] launch a silent no-op, which drops `leave` for any context that
     * [trackContext] registers after a first [onCleared] call.
     */
    override fun onCleared() {
        super.onCleared()
        val contexts =
            synchronized(contextsLock) {
                val snapshot = activeContexts.toList()
                activeContexts.clear()
                snapshot
            }
        cleanupScope.launch {
            for (ctx in contexts) {
                runCatching { ctx.bridge.context.leave(ctx.handle, ctx.identityHandle) }
                    .onFailure { failure ->
                        if (failure is CancellationException) throw failure
                        onCleanupFailure(ctx, failure)
                    }
            }
        }
    }

    /**
     * Called once per context whose `leave` threw anything other than
     * [CancellationException].
     *
     * A `leave` reaches a runtime that rejects it deliberately, so an SDK that drops such a
     * rejection tells an app author nothing: `SCP-CTX-2015`, a `PermissionDenied`, and a
     * fail-closed persist error all reach this point. Override to fail closed, to retry, or
     * to tell a user that a departure did not land.
     *
     * A default body logs at warning level, which is what `.docs/standards/sdk-common.md`
     * §Cleanup error handling requires: "Errors during cleanup are logged but never
     * propagated as exceptions — callers must not be penalized for disposing resources."
     * That standard is why this method returns [Unit] rather than rethrowing, and why
     * [onCleared] keeps calling `leave` on remaining contexts after one fails.
     *
     * Runs on `cleanupDispatcher`, inside a cleanup coroutine, after [onCleared] has already
     * returned. It must not block that thread, for a reason
     * `.docs/lessons/kotlin/oncleared-must-not-block-its-caller.md` states.
     *
     * A throw from an override propagates into that cleanup coroutine and stops `leave` calls
     * for every context after this one, so an override that wants remaining calls attempted
     * catches its own errors.
     *
     * @param context Tracked context whose `leave` failed.
     * @param cause Throwable that `leave` threw, never a [CancellationException].
     */
    protected open fun onCleanupFailure(context: TrackedContext, cause: Throwable) {
        Log.w(
            TAG,
            "SCP context leave failed during ViewModel cleanup " +
                "(contextHandle=${context.handle}, identityHandle=${context.identityHandle})",
            cause,
        )
    }

    private companion object {
        private const val TAG = "ScpViewModel"
    }
}
