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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

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
 * A Java subclass calls `super()`, so this class must keep a zero-argument JVM constructor.
 * `ScpViewModelTest.ScpViewModel exposes a zero-argument constructor to Java callers` asserts
 * that constructor by reflection.
 */
abstract class ScpViewModel : ViewModel() {

    private val contextsLock = Any()
    private val activeContexts = mutableListOf<TrackedContext>()

    // Written and read only under [contextsLock]; true once [onCleared] has run.
    private var cleared = false

    // [launchLeave] starts each cleanup coroutine undispatched on the thread that calls
    // [onCleared] or [trackContext], and `Dispatchers.Unconfined` keeps it there only until
    // the first `leave` suspends into the bridge's I/O dispatcher, so [onCleared] returns
    // without waiting on an FFI call when that dispatcher dispatches. An inline one runs every
    // `leave` before [onCleared] returns unless the coroutine suspends on
    // [cleanupFailureLock], which another cleanup coroutine's [onCleanupFailure] call can hold.
    private val cleanupScope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)

    // Serializes [onCleanupFailure] across every cleanup coroutine: [onCleared] launches one
    // and each post-clear [trackContext] launches another, and with a dispatching bridge
    // their `leave` calls fail on different threads at once. A [Mutex] suspends a waiting
    // coroutine instead of blocking its thread, which may be an Android main thread. Under
    // `Dispatchers.Unconfined` a waiting coroutine resumes on the thread that unlocks it.
    private val cleanupFailureLock = Mutex()

    /**
     * Register a context for automatic cleanup on ViewModel clear.
     *
     * Call this after creating or joining a context to ensure it is cleaned up
     * when the ViewModel is destroyed. Returns the same [TrackedContext] for
     * chaining convenience.
     *
     * A context registered after [onCleared] has run is left at once, the way
     * `ViewModel.addCloseable` closes a resource added after clear: Android never calls
     * [onCleared] a second time, so tracking it would drop its `leave` silently. That
     * `leave` runs on the same cleanup coroutine path, and a failure reaches
     * [onCleanupFailure]. With a bridge whose I/O dispatcher runs inline, the `leave` runs on
     * the calling thread before this method returns, even when the caller is itself a
     * coroutine on `Dispatchers.Unconfined`, such as an [onCleanupFailure] override that
     * retries. So does its [onCleanupFailure] call, unless an [onCleanupFailure] call is
     * running at that moment, the retrying override's own included. In that case this method
     * returns first, and the call waits for the running one and then runs on the thread that
     * ran it.
     *
     * @param context The [TrackedContext] wrapping the context handle and bridge.
     * @return The same [context] passed in, for chaining.
     */
    fun trackContext(context: TrackedContext): TrackedContext {
        val alreadyCleared =
            synchronized(contextsLock) {
                if (!cleared) activeContexts.add(context)
                cleared
            }
        if (alreadyCleared) launchLeave(listOf(context))
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
     *   context that [trackContext] registered and [untrackContext] did not remove. The same
     *   lock marks this view model cleared, so every later [trackContext] leaves its context
     *   at once instead of tracking it.
     * - A coroutine is submitted to [cleanupScope]. That coroutine calls
     *   [CoroutineBridge.ContextBridge.leave] exactly once per snapshotted context, in
     *   snapshot order.
     * - A `leave` call that throws, whatever it throws, does not stop remaining `leave`
     *   calls. Its throwable goes to [onCleanupFailure]. That includes a
     *   [CancellationException]: nothing cancels [cleanupScope], so a cancellation that
     *   `leave` throws never reports that this cleanup coroutine was cancelled. It comes from
     *   inside `leave`, for example from an injected I/O dispatcher that rejected the task.
     * - An [onCleanupFailure] override that throws does not stop remaining `leave` calls
     *   either. Its throwable is logged at warning level and the loop continues.
     * - Snapshot order binds this coroutine only. A context [trackContext] registers after
     *   this call is left on a coroutine of its own, whose `leave` can run at the same time
     *   as this one's on another thread. [onCleanupFailure] calls never overlap.
     *
     * What this method does not guarantee: that `leave` calls have finished. The cleanup
     * coroutine starts on the calling thread and, when the bridge's I/O dispatcher dispatches
     * (the default `Dispatchers.IO` does), leaves it at the first `leave`. A dispatcher that
     * runs inline, such as `Dispatchers.Unconfined`, runs every `leave` and every
     * [onCleanupFailure] call on the calling thread before this method returns, unless
     * another cleanup coroutine's [onCleanupFailure] call is running when a `leave` fails. In
     * that case this method returns at that failure, and the rest of the loop, its
     * [onCleanupFailure] call included, runs on the thread that ran the other call. Cleanup is
     * best-effort — those calls run to completion only if a process outlives them. Blocking
     * until they finish is not an option: [onCleared] runs on an Android main thread, and
     * blocking that thread on FFI calls both risks an ANR and deadlocks whenever an injected
     * dispatcher schedules its work onto a blocked thread.
     *
     * Uses a dedicated [cleanupScope] because `viewModelScope` is already cancelled before
     * [onCleared] is called, so a coroutine launched there would be dropped without running.
     * [onCleared] does not cancel [cleanupScope] afterwards. A [SupervisorJob] whose children
     * have all completed holds no thread, no handle, and no memory a cancellation would
     * release, and [Dispatchers.Unconfined] owns no thread, so cancelling that job frees
     * nothing. Cancelling it would instead make every later [cleanupScope] launch a silent
     * no-op, which drops the `leave` that [trackContext] launches for a context registered
     * after [onCleared].
     */
    override fun onCleared() {
        super.onCleared()
        val contexts =
            synchronized(contextsLock) {
                cleared = true
                val snapshot = activeContexts.toList()
                activeContexts.clear()
                snapshot
            }
        launchLeave(contexts)
    }

    /**
     * Calls `leave` on each of [contexts] in order, on a coroutine [cleanupScope] owns.
     *
     * [CoroutineStart.UNDISPATCHED] runs the coroutine on the calling thread up to its first
     * suspension. A default start would, when the caller already runs inside a
     * `Dispatchers.Unconfined` coroutine (a retry from [onCleanupFailure] does), queue it on
     * that thread's unconfined event loop until the caller's coroutine suspends, and the
     * inline-bridge guarantees in the KDoc of [trackContext] and [onCleared] would not hold.
     */
    private fun launchLeave(contexts: List<TrackedContext>) {
        cleanupScope.launch(start = CoroutineStart.UNDISPATCHED) {
            for (ctx in contexts) {
                val failure =
                    runCatching { ctx.bridge.context.leave(ctx.handle, ctx.identityHandle) }
                        .exceptionOrNull() ?: continue
                cleanupFailureLock.withLock { runCatching { onCleanupFailure(ctx, failure) } }
                    .onFailure { overrideFailure ->
                        Log.w(
                            TAG,
                            "onCleanupFailure threw; remaining contexts are still left " +
                                "(contextHandle=${ctx.handle})",
                            overrideFailure,
                        )
                    }
            }
        }
    }

    /**
     * Called once per context whose `leave` threw, with whatever `leave` threw.
     *
     * A `leave` reaches a runtime that rejects it deliberately, so an SDK that drops such a
     * rejection tells an app author nothing: `SCP-CTX-2015`, a `PermissionDenied`, and a
     * fail-closed persist error all reach this point. Override to record the failure, to
     * retry, or to tell a user that a departure did not land.
     *
     * A default body logs at warning level, which is what `.docs/standards/sdk-common.md`
     * §Cleanup error handling requires: "Errors during cleanup are logged but never
     * propagated as exceptions — callers must not be penalized for disposing resources."
     * That standard is why this method returns [Unit] rather than rethrowing, and why a
     * cleanup coroutine keeps calling `leave` on its remaining contexts after one fails.
     *
     * Runs inside a cleanup coroutine. When the bridge's I/O dispatcher dispatches (the default
     * `Dispatchers.IO` does), that is on whichever thread resumed that coroutine, after
     * [onCleared] has already returned. A dispatcher that runs inline, such as
     * `Dispatchers.Unconfined`, runs it on the thread that called [onCleared] (an Android main
     * thread) before [onCleared] returns, unless another cleanup coroutine's call is running
     * at that moment: then [onCleared] returns first, and this call runs after the running one,
     * on the thread that ran it. Either way it must not block its thread, for a reason
     * `.docs/lessons/kotlin/oncleared-must-not-block-its-caller.md` states.
     *
     * Calls never overlap, so an override may update unsynchronized state, although
     * successive calls can run on different threads. [onCleared]'s coroutine and each
     * coroutine that [trackContext] launches after clear can see `leave` fail at the same
     * time; a [Mutex] makes each wait, suspended rather than blocking its thread, until the
     * running call returns. Calls from one coroutine keep its order; calls from different
     * coroutines have no defined order.
     *
     * A throw from an override does not propagate: the cleanup coroutine that called it,
     * whether [onCleared] or a [trackContext] after clear launched it, catches it, logs it at
     * warning level, and still calls `leave` on every remaining context, so throwing here
     * fails nothing closed. The coroutine catches it because an uncaught throw from it would
     * reach the thread's uncaught-exception handler, which on Android kills the process
     * after the screen that owned this ViewModel is gone.
     *
     * @param context Tracked context whose `leave` failed.
     * @param cause Throwable that `leave` threw. A [CancellationException] here was raised
     *   inside `leave`; it never means the cleanup coroutine was cancelled, because nothing
     *   cancels that coroutine.
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
