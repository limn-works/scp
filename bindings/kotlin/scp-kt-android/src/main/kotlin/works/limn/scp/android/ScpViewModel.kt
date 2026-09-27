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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
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
 * or thread. The internal context list is protected by a [Mutex].
 */
abstract class ScpViewModel : ViewModel() {

    private val mutex = Mutex()
    private val activeContexts = mutableListOf<TrackedContext>()
    private val cleanupJob = SupervisorJob()

    // `Dispatchers.Unconfined` starts the cleanup coroutine on the thread that calls
    // [onCleared] and keeps it there only until the first `leave` suspends into the
    // bridge's I/O dispatcher, so [onCleared] returns without waiting on an FFI call.
    private val cleanupScope = CoroutineScope(cleanupJob + Dispatchers.Unconfined)

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
        runBlocking { mutex.withLock { activeContexts.add(context) } }
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
        runBlocking { mutex.withLock { activeContexts.remove(context) } }
    }

    /**
     * Called when the ViewModel is cleared (Activity/Fragment destroyed permanently).
     *
     * Android calls this method on the main thread after it has cancelled [viewModelScope],
     * so a coroutine launched into [viewModelScope] here would never run. The method
     * launches the cleanup into a dedicated [cleanupScope] instead and returns without
     * waiting for it: each `leave` is a blocking FFI call that the bridge runs on its I/O
     * dispatcher, and `.docs/standards/kotlin.md` keeps callers off the main thread.
     * The cleanup coroutine leaves every tracked context, catching each error so that one
     * failed `leave` does not stop the others.
     *
     * The method completes [cleanupJob] after launching, so the scope finishes once the
     * cleanup coroutine returns and a second call starts no second cleanup.
     */
    override fun onCleared() {
        super.onCleared()
        cleanupScope.launch {
            val contexts = mutex.withLock {
                val snapshot = activeContexts.toList()
                activeContexts.clear()
                snapshot
            }
            for (ctx in contexts) {
                runCatching { ctx.bridge.context.leave(ctx.handle, ctx.identityHandle) }
            }
        }
        cleanupJob.complete()
    }
}
