// ScpViewModel.kt — Base ViewModel with SCP resource lifecycle management (SCP-117)
//
// Tracks active SCP context handles and cleans them up when the ViewModel is cleared.
// Prevents resource leaks when Activities/Fragments are destroyed. Subclass this in
// your app's ViewModels to get automatic SCP resource cleanup.
//
// Provenance: ADR-028 (Kotlin SDK) Android lifecycle integration, SCP-117

package works.limn.scp.android

import androidx.lifecycle.ViewModel
import works.limn.scp.bridge.CoroutineBridge
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
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
 */
abstract class ScpViewModel(
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
     * - The tracked-context list is empty, and the snapshot it took holds every context
     *   that [trackContext] registered and [untrackContext] did not remove. A second
     *   [onCleared] call therefore finds nothing to leave.
     * - A coroutine is submitted to [cleanupScope], and that coroutine calls
     *   [CoroutineBridge.ContextBridge.leave] once for every context in the snapshot.
     * - A `leave` call that throws does not stop the remaining `leave` calls.
     *
     * What this method does not guarantee: that the `leave` calls have finished. Cleanup
     * is best-effort — the calls run to completion only if the process outlives them.
     * Blocking until they finish is not an option: [onCleared] runs on the Android main
     * thread, and blocking that thread on FFI calls both risks an ANR and deadlocks
     * whenever the injected dispatcher schedules its work onto the blocked thread.
     *
     * Uses a dedicated [cleanupScope] because `viewModelScope` is already cancelled before
     * [onCleared] is called, so a coroutine launched there would be dropped without running.
     * The scope is cancelled once the cleanup coroutine completes.
     */
    override fun onCleared() {
        super.onCleared()
        val contexts =
            synchronized(contextsLock) {
                val snapshot = activeContexts.toList()
                activeContexts.clear()
                snapshot
            }
        val cleanupJob =
            cleanupScope.launch {
                for (ctx in contexts) {
                    runCatching { ctx.bridge.context.leave(ctx.handle, ctx.identityHandle) }
                        .onFailure { failure -> if (failure is CancellationException) throw failure }
                }
            }
        cleanupJob.invokeOnCompletion { cleanupScope.cancel() }
    }
}
