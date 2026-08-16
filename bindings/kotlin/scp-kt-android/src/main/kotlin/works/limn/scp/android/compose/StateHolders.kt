// StateHolders.kt — Jetpack Compose state holders for SCP (SCP-118)
// Provenance: ADR-028 (Kotlin SDK) Compose integration, SCP-118

package works.limn.scp.android.compose

import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.State
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/**
 * Holder for an SCP context's observable state within a Composable.
 *
 * Wraps the raw context handle, identity handle, and coroutine scope needed
 * to collect SCP streams as Compose [State]. Created by [rememberScpContext]
 * and cleaned up via [DisposableEffect] when the Composable leaves composition.
 *
 * Mirrors the [works.limn.scp.android.TrackedContext] pattern from
 * [works.limn.scp.android.ScpViewModel] — both context and identity handles
 * are required for leave/close operations on the FFI bridge.
 *
 * @property contextHandle Opaque context handle from create/join.
 * @property identityHandle Opaque identity handle for the member in this context.
 * @property scope Coroutine scope for converting Flows to StateFlows.
 *   Cancelled on disposal.
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
 *     // A scope that outlives disposal, because rememberScpContext cancels a
 *     // holder's own scope before it calls onDispose.
 *     val cleanupScope = remember { CoroutineScope(SupervisorJob() + Dispatchers.IO) }
 *     val holder = rememberScpContext(contextHandle, identityHandle) { ctxH, idH ->
 *         cleanupScope.launch { bridge.context.leave(ctxH, idH) }
 *     }
 *     // Use holder to collect SCP streams
 * }
 * ```
 *
 * @param contextHandle Opaque context handle from create/join.
 * @param identityHandle Opaque identity handle for the member in this context.
 * @param onDispose Callback invoked when the Composable leaves composition.
 *   Receives a context handle and an identity handle for cleanup. Runs on a composition
 *   thread, which on Android is a main thread, so it MUST NOT block on a coroutine:
 *   `runBlocking` around a suspending SCP call risks an ANR, and deadlocks outright when
 *   a dispatcher underneath that call schedules its work onto a blocked thread. Launch
 *   that work on a scope which outlives disposal instead, as shown above. See
 *   `.docs/lessons/kotlin/oncleared-must-not-block-its-caller.md`.
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
 * Wraps `Flow.collectAsState()` with a [remember]-based scope and
 * [DisposableEffect] cleanup. The flow collection starts when the
 * Composable enters composition and stops when it leaves.
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
): State<T> = flow.collectAsState(initial = initial)

/**
 * Collect a [SharedFlow] of SCP events as a Compose [State] list.
 *
 * Accumulates emissions from a hot [SharedFlow] (e.g., from
 * [works.limn.scp.stream.HotStreamFactory.contextEvents]) into a list
 * that grows as new events arrive. The list is capped at [maxItems]
 * to prevent unbounded memory growth in long-lived Composables.
 *
 * Recomposition occurs on every new event. The accumulated list is
 * cleared when the Composable leaves composition.
 *
 * @param eventFlow Hot SharedFlow of JSON-encoded events.
 * @param maxItems Maximum number of events to retain. Oldest events
 *   are dropped when the limit is exceeded. Defaults to 100.
 * @return Compose [State] containing the accumulated event list.
 */
@Composable
fun rememberScpEventList(
    eventFlow: SharedFlow<String>,
    maxItems: Int = MAX_EVENT_LIST_SIZE,
): State<List<String>> {
    val scope = remember { CoroutineScope(SupervisorJob() + Dispatchers.Default) }
    DisposableEffect(Unit) {
        onDispose { scope.cancel() }
    }
    val stateFlow: StateFlow<List<String>> = remember(eventFlow) {
        val accumulator = mutableListOf<String>()
        eventFlow
            .map { event ->
                synchronized(accumulator) {
                    accumulator.add(event)
                    if (accumulator.size > maxItems) {
                        accumulator.removeAt(0)
                    }
                    accumulator.toList()
                }
            }
            .stateIn(
                scope = scope,
                started = SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS),
                initialValue = emptyList(),
            )
    }
    return stateFlow.collectAsState()
}

/**
 * Collect a [Flow] as Compose [State], scoped to an [ScpContextHolder].
 *
 * Converts the flow to a [StateFlow] using the holder's coroutine scope,
 * so collection stops automatically when the holder is disposed. Uses
 * [SharingStarted.WhileSubscribed] with a 5-second stop timeout to
 * survive brief recompositions without restarting the upstream flow.
 *
 * @param holder The [ScpContextHolder] whose scope drives collection.
 * @param flow The SCP stream to collect.
 * @param initial The initial value before the first emission.
 * @return Compose [State] that triggers recomposition on each emission.
 */
@Composable
fun <T> rememberScpStateIn(
    holder: ScpContextHolder,
    flow: Flow<T>,
    initial: T,
): State<T> {
    val stateFlow: StateFlow<T> = remember(holder, flow) {
        flow.stateIn(
            scope = holder.scope,
            started = SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS),
            initialValue = initial,
        )
    }
    return stateFlow.collectAsState()
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
 *   composition. Runs on [Dispatchers.IO], on a scope that disposal does not cancel, so
 *   it may suspend for as long as it needs. Disposal returns without waiting for it, so
 *   `onStop` finishes only if a process outlives it.
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
    // A second scope exists so that cancelling `scope` — which stops a subscription that
    // `start` opened — cannot cancel `onStop` before it has run. Disposal never cancels
    // this one.
    val stopScope = remember(key) { CoroutineScope(SupervisorJob() + Dispatchers.IO) }

    DisposableEffect(key) {
        scope.launch {
            flowState.value = start()
        }
        onDispose {
            // onDispose runs on a composition thread, which on Android is a main thread.
            // A `runBlocking { onStop() }` here parks that thread until onStop returns,
            // which risks an ANR and deadlocks whenever a dispatcher underneath onStop
            // schedules work back onto a parked thread — SCP-117's failure, in a
            // second spelling. See
            // `.docs/lessons/kotlin/oncleared-must-not-block-its-caller.md`.
            stopScope.launch { onStop() }
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

private const val STOP_TIMEOUT_MS = 5_000L
