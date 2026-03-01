// ScpViewModel.kt — Base ViewModel with SCP resource lifecycle management (SCP-117)
//
// Tracks active SCP context handles and cleans them up when the ViewModel is cleared.
// Prevents resource leaks when Activities/Fragments are destroyed. Subclass this in
// your app's ViewModels to get automatic SCP resource cleanup.
//
// Provenance: ADR-028 (Kotlin SDK) Android lifecycle integration, SCP-117

package com.limn.scp.android

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.limn.scp.bridge.CoroutineBridge
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Resource handle for an active SCP context tracked by [ScpViewModel].
 *
 * Encapsulates the opaque context handle returned by [CoroutineBridge.ContextBridge.create]
 * or [CoroutineBridge.ContextBridge.join], along with the bridge needed to call [leave] on
 * cleanup.
 *
 * @property handle Opaque context handle from the FFI layer.
 * @property bridge The [CoroutineBridge] used to dispatch cleanup operations.
 */
data class TrackedContext(
    val handle: Long,
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
 *         trackContext(TrackedContext(contextHandle, bridge))
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
        viewModelScope.launch {
            mutex.withLock { activeContexts.add(context) }
        }
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
        viewModelScope.launch {
            mutex.withLock { activeContexts.remove(context) }
        }
    }

    /**
     * Called when the ViewModel is cleared (Activity/Fragment destroyed permanently).
     *
     * Leaves all tracked contexts gracefully. Errors during individual leave operations
     * are caught and swallowed to ensure all contexts are attempted. The bridge's context
     * leave operation dispatches on Dispatchers.IO via [CoroutineBridge.ffiCall].
     */
    override fun onCleared() {
        super.onCleared()
        viewModelScope.launch {
            val contexts = mutex.withLock {
                val snapshot = activeContexts.toList()
                activeContexts.clear()
                snapshot
            }
            for (ctx in contexts) {
                runCatching { ctx.bridge.context.leave(ctx.handle) }
            }
        }
    }
}
