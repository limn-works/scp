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
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

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
 * Sequences hot stream subscriptions that separate mounts open under one same key.
 *
 * Compose forgets every `remember(key)` value when a composable leaves composition, so no value
 * a composable remembers can order one mount's `onStop` against a later mount's `start`. Without
 * that ordering, navigating away from a screen and back leaves `onStop` running against whatever
 * subscription a registry holds at that moment, which is a subscription that a second mount just
 * opened: a collector then observes a [SharedFlow] that receives nothing further, and reports no
 * error.
 *
 * A caller constructs one coordinator outside composition — in a ViewModel, in an application
 * container, or in a dependency graph — and passes that instance to every
 * [rememberScpHotStream] call that shares a key space. Constructing one inside a composition
 * gives each mount its own coordinator, which reintroduces exactly that defect, so
 * [rememberScpHotStream] takes a coordinator as a required parameter and declares no default.
 *
 * This class holds per-key state: a [Mutex] that admits one start or one stop at a time, and one
 * [Job] naming whichever `onStop` [launchStop] launched most recently. [startAfterPendingStop]
 * joins that job before it runs a `start` lambda, so ordering rests on when a caller launched
 * `onStop`, not on when `onStop` reached a dispatcher. Per-key state leaves this map as soon as
 * no start and no stop holds it.
 *
 * @param scope Scope that runs every `onStop` lambda this coordinator launches. A caller owns
 *   that scope and decides when to cancel it. Composable disposal never cancels it, so an
 *   `onStop` outlives whichever mount launched it.
 */
class ScpHotStreamCoordinator(private val scope: CoroutineScope) {
    private val keyStates = ConcurrentHashMap<Any, KeyState>()

    /**
     * Launch [onStop] for [key] on this coordinator's scope, and record its [Job] before
     * returning, so a [startAfterPendingStop] call that begins afterwards joins it.
     *
     * [onStop] runs under [key]'s mutex, so it never overlaps a start for that same key.
     *
     * @return A [Job] running [onStop].
     */
    internal fun launchStop(
        key: Any,
        onStop: suspend () -> Unit,
    ): Job {
        val state = acquire(key)
        val job = scope.launch { state.mutex.withLock { onStop() } }
        state.lastStop.set(job)
        job.invokeOnCompletion { release(key) }
        return job
    }

    /**
     * Join whichever `onStop` [launchStop] recorded for [key], then run [start] under [key]'s
     * mutex and return what [start] returned.
     *
     * A caller cancelling this call releases that mutex, so a stop waiting on it proceeds.
     */
    internal suspend fun <T> startAfterPendingStop(
        key: Any,
        start: suspend () -> T,
    ): T {
        val state = acquire(key)
        try {
            state.lastStop.get()?.join()
            return state.mutex.withLock { start() }
        } finally {
            release(key)
        }
    }

    /**
     * Return [key]'s state, creating it when no start and no stop currently holds it, and count
     * this caller as one holder.
     *
     * [ConcurrentHashMap.compute] runs this function while it holds that key's bin lock, and
     * [release] removes an entry under that same lock, so no caller acquires a state that
     * another thread is removing.
     */
    private fun acquire(key: Any): KeyState =
        checkNotNull(
            keyStates.compute(key) { _, existing ->
                (existing ?: KeyState()).also { it.holders.incrementAndGet() }
            },
        ) { "compute returned no state for key $key" }

    /** Drop one holder of [key]'s state, and remove that state when it has no holder left. */
    private fun release(key: Any) {
        keyStates.computeIfPresent(key) { _, state ->
            if (state.holders.decrementAndGet() == 0) null else state
        }
    }

    /**
     * One key's coordination state.
     *
     * @property mutex Admits one start lambda or one stop lambda at a time for this key.
     * @property lastStop Job of whichever stop lambda [launchStop] launched most recently for
     *   this key, or `null` when [launchStop] has launched none since this state was created.
     * @property holders Count of starts and stops holding this state. [ScpHotStreamCoordinator]
     *   removes this state from its map when that count reaches zero, which happens only after
     *   every stop this state recorded has completed.
     */
    private class KeyState {
        val mutex = Mutex()
        val lastStop = AtomicReference<Job?>(null)
        val holders = AtomicInteger(0)
    }
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
 * [coordinator] sequences those two lambdas across mounts: a [start] for one key waits for an
 * [onStop] that an earlier mount launched under that same key. A caller holds that coordinator
 * outside composition, because Compose forgets everything this function remembers when a mount
 * ends. [ScpHotStreamCoordinator] states what a per-composition coordinator would break.
 *
 * The returned [State] is initially `null` until the [start] coroutine
 * completes and the [SharedFlow] is available. Callers should handle the
 * null case (e.g., show a loading indicator).
 *
 * Usage:
 * ```kotlin
 * // Constructed once outside composition — a ViewModel, an Application, or a DI graph owns
 * // both this scope and this coordinator.
 * val streamScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
 * val streamCoordinator = ScpHotStreamCoordinator(streamScope)
 *
 * @Composable
 * fun EventList(handle: Long, factory: HotStreamFactory, coordinator: ScpHotStreamCoordinator) {
 *     val eventsState = rememberScpHotStream(
 *         key = handle,
 *         coordinator = coordinator,
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
 * @param coordinator Orders this mount's [start] after any [onStop] an earlier mount launched
 *   under [key]. A caller constructs it outside composition and shares one instance across every
 *   mount that uses a given key space. The subscription restarts if this changes too, because a
 *   different coordinator orders a different key space.
 * @param start Suspend factory lambda that creates the [SharedFlow]. Called
 *   once per [key] value. Runs in a coroutine scoped to the Composable.
 * @param onStop Suspend cleanup lambda invoked when the Composable leaves
 *   composition. Runs on [coordinator]'s scope, which disposal does not cancel, so
 *   it may suspend for as long as it needs. Disposal returns without waiting for it, so
 *   `onStop` finishes only if a process outlives it.
 * @return Compose [State] holding the [SharedFlow], or `null` until
 *   the subscription is established.
 */
@Composable
fun <T> rememberScpHotStream(
    key: Any,
    coordinator: ScpHotStreamCoordinator,
    start: suspend () -> SharedFlow<T>,
    onStop: suspend () -> Unit,
): State<SharedFlow<T>?> {
    // Both remembered values key on `key` AND `coordinator`, matching the
    // DisposableEffect below. Keying the scope on `key` alone handed a changed
    // coordinator the scope the previous effect's onDispose had already
    // cancelled, so `scope.launch` returned an already-cancelled Job, `start`
    // never ran, and `flowState` kept the previous coordinator's flow — a
    // subscription nobody was serving, reported as a live one.
    val flowState = remember(key, coordinator) { mutableStateOf<SharedFlow<T>?>(null) }
    val scope = remember(key, coordinator) { CoroutineScope(SupervisorJob() + Dispatchers.IO) }

    DisposableEffect(key, coordinator) {
        scope.launch {
            flowState.value = coordinator.startAfterPendingStop(key) { start() }
        }
        onDispose {
            // onDispose runs on a composition thread, which on Android is a main thread.
            // A `runBlocking { onStop() }` here parks that thread until onStop returns,
            // which risks an ANR and deadlocks whenever a dispatcher underneath onStop
            // schedules work back onto a parked thread — SCP-117's failure, in a
            // second spelling. See
            // `.docs/lessons/kotlin/oncleared-must-not-block-its-caller.md`.
            // launchStop records this stop's Job before it returns, so a start that a later
            // mount begins under this same key joins that job instead of racing it. Cancelling
            // `scope` afterwards cancels only this mount's start, never that stop.
            coordinator.launchStop(key) { onStop() }
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
