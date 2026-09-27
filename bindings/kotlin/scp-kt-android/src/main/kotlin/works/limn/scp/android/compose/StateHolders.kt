// StateHolders.kt — Jetpack Compose state holders for SCP (SCP-118)
// Provenance: ADR-028 (Kotlin SDK) Compose integration, SCP-118

package works.limn.scp.android.compose

import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.State
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.job
import kotlinx.coroutines.launch

/**
 * Holder for an SCP context's observable state within a Composable.
 *
 * Wraps the raw context handle, identity handle, and a coroutine scope whose
 * cancellation marks the holder's end of life; [rememberScpStateIn] stops
 * collecting when that scope is cancelled. Created by [rememberScpContext]
 * and cleaned up via [DisposableEffect] when the Composable leaves composition.
 *
 * Mirrors the [works.limn.scp.android.TrackedContext] pattern from
 * [works.limn.scp.android.ScpViewModel] — both context and identity handles
 * are required for leave/close operations on the FFI bridge.
 *
 * @property contextHandle Opaque context handle from create/join.
 * @property identityHandle Opaque identity handle for the member in this context.
 * @property scope Coroutine scope that lives as long as the holder.
 *   Cancelled on disposal, which ends every [rememberScpStateIn]
 *   collection bound to this holder.
 * @property onDispose Cleanup callback invoked when the Composable
 *   leaves composition. Receives both the context handle and identity handle.
 *   Typically calls leave/close on the context.
 */
class ScpContextHolder(
    val contextHandle: Long,
    val identityHandle: Long,
    internal val scope: CoroutineScope,
    private val onDispose: (Long, Long) -> Unit,
) {
    internal fun dispose() {
        scope.cancel()
        onDispose(contextHandle, identityHandle)
    }
}

/**
 * Remember an SCP context scoped to the Composable's lifetime.
 *
 * Creates a [ScpContextHolder] that persists across recompositions for the
 * same [contextHandle] and [identityHandle]. When the Composable leaves composition, the
 * [onDispose] callback is invoked to clean up the context (e.g., call
 * `contextBridge.leave(handle, identityHandle)`), and the internal coroutine
 * scope is cancelled.
 *
 * Per ADR-028: `DisposableEffect(contextId) { onDispose { context.close() } }`
 * ensures the context is closed when the composable leaves composition.
 *
 * Usage:
 * ```kotlin
 * @Composable
 * fun ChatScreen(contextHandle: Long, identityHandle: Long, bridge: CoroutineBridge) {
 *     val holder = rememberScpContext(contextHandle, identityHandle) { ctxH, idH ->
 *         runBlocking(Dispatchers.IO) { bridge.context.leave(ctxH, idH) }
 *     }
 *     // Use holder to collect SCP streams
 * }
 * ```
 *
 * @param contextHandle Opaque context handle from create/join.
 * @param identityHandle Opaque identity handle for the member in this context.
 * @param onDispose Callback invoked when the Composable leaves composition.
 *   Receives the context handle and identity handle for cleanup. Runs on the
 *   composition thread; launch a coroutine for suspending cleanup operations.
 * @return A [ScpContextHolder] scoped to this Composable.
 */
@Composable
fun rememberScpContext(
    contextHandle: Long,
    identityHandle: Long,
    onDispose: (Long, Long) -> Unit,
): ScpContextHolder {
    val holder = remember(contextHandle, identityHandle) {
        ScpContextHolder(
            contextHandle = contextHandle,
            identityHandle = identityHandle,
            scope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
            onDispose = onDispose,
        )
    }
    DisposableEffect(contextHandle, identityHandle) {
        onDispose { holder.dispose() }
    }
    return holder
}

/**
 * Collect a [Flow] as Compose [State] with an initial value, scoped to
 * the Composable's lifetime.
 *
 * The collector subscribes to [flow] when the composition applies, before
 * any later work on the composition thread runs, so a hot flow cannot drop
 * an event emitted after the Composable appears. Collection runs in the
 * composition's coroutine context and stops when the Composable leaves
 * composition or [flow] changes.
 *
 * This is the primary integration point for SCP streams in Compose:
 * `val messages by rememberScpFlow(messageFlow, emptyList())`
 *
 * @param flow The SCP stream to collect (e.g., from ContextBridge.subscribe).
 * @param initial The initial value before the first emission.
 * @return Compose [State] that triggers recomposition on each emission.
 */
@Composable
fun <T> rememberScpFlow(
    flow: Flow<T>,
    initial: T,
): State<T> = rememberCollectedState(initial, flow) { state ->
    flow.collect { state.value = it }
}

/**
 * Collect a [SharedFlow] of SCP events as a Compose [State] list.
 *
 * Accumulates emissions from a hot [SharedFlow] (e.g., from
 * [works.limn.scp.stream.HotStreamFactory.contextEvents]) into a list
 * that grows as new events arrive. The list is capped at [maxItems]
 * to prevent unbounded memory growth in long-lived Composables.
 *
 * The collector subscribes to [eventFlow] when the composition applies,
 * before any later work on the composition thread runs. A hot flow that
 * replays nothing drops every event no subscriber holds, so a subscription
 * that started later, on another thread, would lose the events emitted
 * right after the Composable appears.
 *
 * Recomposition occurs on every new event. Collection stops and the
 * accumulated list is discarded when the Composable leaves composition
 * or [eventFlow] changes.
 *
 * @param eventFlow Hot SharedFlow of JSON-encoded events.
 * @param maxItems Maximum number of events to retain. Oldest events
 *   are dropped when the limit is exceeded. Defaults to 100. Read once,
 *   when collection of [eventFlow] starts.
 * @return Compose [State] containing the accumulated event list.
 */
@Composable
fun rememberScpEventList(
    eventFlow: SharedFlow<String>,
    maxItems: Int = MAX_EVENT_LIST_SIZE,
): State<List<String>> = rememberCollectedState(emptyList(), eventFlow) { state ->
    val accumulator = ArrayDeque<String>()
    eventFlow.collect { event ->
        accumulator.addLast(event)
        if (accumulator.size > maxItems) {
            accumulator.removeFirst()
        }
        state.value = accumulator.toList()
    }
}

/**
 * Collect a [Flow] as Compose [State], scoped to an [ScpContextHolder].
 *
 * The collector subscribes to [flow] when the composition applies, before
 * any later work on the composition thread runs, so a hot flow cannot drop
 * an event emitted after the Composable appears. Collection runs in the
 * composition's coroutine context and stops at the first of: the
 * Composable leaving composition, [holder] or [flow] changing, or the
 * holder being disposed. A recomposition with the same [holder] and [flow]
 * keeps the running collection.
 *
 * @param holder The [ScpContextHolder] whose disposal ends collection.
 * @param flow The SCP stream to collect.
 * @param initial The initial value before the first emission.
 * @return Compose [State] that triggers recomposition on each emission.
 */
@Composable
fun <T> rememberScpStateIn(
    holder: ScpContextHolder,
    flow: Flow<T>,
    initial: T,
): State<T> = rememberCollectedState(initial, holder, flow) { state ->
    val collector = currentCoroutineContext().job
    val holderDisposal = holder.scope.coroutineContext[Job]?.invokeOnCompletion {
        collector.cancel()
    }
    try {
        flow.collect { state.value = it }
    } finally {
        holderDisposal?.dispose()
    }
}

/**
 * Run [collect] against a remembered [MutableState] for as long as the
 * Composable stays in composition with the same [keys].
 *
 * The collecting coroutine starts undispatched in the composition's
 * coroutine context when the composition applies, so it runs up to its
 * first suspension, which for a flow collector is the subscription, before
 * the composition thread does anything else. Leaving composition or a
 * change of [keys] cancels it and discards the state.
 */
@Composable
private fun <R> rememberCollectedState(
    initial: R,
    vararg keys: Any?,
    collect: suspend (MutableState<R>) -> Unit,
): State<R> {
    val state = remember(*keys) { mutableStateOf(initial) }
    val scope = rememberCoroutineScope()
    DisposableEffect(*keys) {
        val job = scope.launch(start = CoroutineStart.UNDISPATCHED) { collect(state) }
        onDispose { job.cancel() }
    }
    return state
}

/**
 * Remember and manage an SCP hot stream subscription within a Composable.
 *
 * Creates a hot stream subscription that persists across recompositions
 * for the same [key]. The [start] suspend lambda is launched in a
 * coroutine scope tied to the Composable's lifetime. When the Composable
 * leaves composition, [onStop] is invoked to unsubscribe from the Rust
 * engine (e.g., call `hotStreamFactory.stopContextEvents(handle)`).
 *
 * The returned [State] is initially `null` until the [start] coroutine
 * completes and the [SharedFlow] is available. Callers should handle the
 * null case (e.g., show a loading indicator).
 *
 * Usage:
 * ```kotlin
 * @Composable
 * fun EventList(handle: Long, factory: HotStreamFactory) {
 *     val eventsState = rememberScpHotStream(
 *         key = handle,
 *         start = { factory.contextEvents(handle) },
 *         onStop = { factory.stopContextEvents(handle) },
 *     )
 *     val events = eventsState.value
 *     if (events != null) {
 *         val eventList by rememberScpFlow(events, emptyList<String>())
 *     }
 * }
 * ```
 *
 * @param key Recomposition key. The subscription restarts if this changes.
 * @param start Suspend factory lambda that creates the [SharedFlow]. Called
 *   once per [key] value. Runs in a coroutine scoped to the Composable.
 * @param onStop Suspend cleanup lambda invoked when the Composable leaves
 *   composition. Called inside `runBlocking` on the Main thread, so it
 *   must not dispatch to `Dispatchers.Main` — doing so will deadlock.
 * @return Compose [State] holding the [SharedFlow], or `null` until
 *   the subscription is established.
 */
@Composable
fun <T> rememberScpHotStream(
    key: Any,
    start: suspend () -> SharedFlow<T>,
    onStop: suspend () -> Unit,
): State<SharedFlow<T>?> {
    val flowState = remember(key) { mutableStateOf<SharedFlow<T>?>(null) }
    val scope = remember(key) { CoroutineScope(SupervisorJob() + Dispatchers.IO) }

    DisposableEffect(key) {
        scope.launch {
            flowState.value = start()
        }
        onDispose {
            // Run onStop before cancelling the scope. Using runBlocking here
            // is safe because onDispose runs on the composition thread (Main),
            // and the scope uses Dispatchers.IO, so there is no deadlock risk.
            // We must NOT launch { onStop() } then cancel — that races the
            // coroutine against scope cancellation and onStop may never execute.
            kotlinx.coroutines.runBlocking { onStop() }
            scope.cancel()
        }
    }
    return flowState
}

/**
 * Remember a Compose [State] derived from a raw SCP context state string.
 *
 * Wraps a state-query lambda in [remember] + [mutableStateOf] so the
 * current context state (e.g., "active", "closed") is observable by
 * Compose. Call [ScpContextState.refresh] to re-query the state and
 * trigger recomposition.
 *
 * @param contextHandle Opaque context handle.
 * @param queryState Lambda that returns the current state string for
 *   a context handle. Typically `{ handle.state() }`.
 * @return An [ScpContextState] whose [ScpContextState.value] is
 *   observable Compose state.
 */
@Composable
fun rememberScpContextState(
    contextHandle: Long,
    queryState: (Long) -> String,
): ScpContextState {
    return remember(contextHandle) {
        ScpContextState(contextHandle, queryState)
    }
}

/**
 * Observable wrapper around an SCP context's state string.
 *
 * The [value] property is backed by Compose [mutableStateOf], so reading
 * it inside a Composable triggers recomposition when the state changes.
 * Call [refresh] after operations that may change the context state
 * (e.g., after sending a message or receiving a state-change event).
 *
 * @property contextHandle The context whose state is tracked.
 * @property queryState Lambda to query the current state from the bridge.
 */
class ScpContextState(
    private val contextHandle: Long,
    private val queryState: (Long) -> String,
) {
    private val _state = mutableStateOf(queryState(contextHandle))

    val value: String
        get() = _state.value

    fun refresh() {
        _state.value = queryState(contextHandle)
    }
}

private const val MAX_EVENT_LIST_SIZE = 100
