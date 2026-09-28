// StateHolders.kt — Jetpack Compose state holders for SCP (SCP-118)
// Provenance: ADR-028 (Kotlin SDK) Compose integration, SCP-118

package works.limn.scp.android.compose

import android.util.Log
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.State
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

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
 * holder's internal coroutine scope is cancelled first, and the [onDispose] callback is
 * invoked after it to clean up the context (e.g., launch
 * `contextBridge.leave(handle, identityHandle)` on a scope that outlives disposal).
 *
 * Per ADR-028 (amended): [onDispose] launches its teardown on a scope that outlives
 * disposal, so the teardown runs off the composition thread and `onDispose` never blocks it.
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
 * Sequences hot stream subscriptions that separate mounts open under one same key.
 *
 * Compose forgets every `remember(key)` value when a composable leaves composition, so no value
 * a composable remembers can order one mount's `onStop` against a later mount's `start`, or tell
 * one mount that another mount under that same key is still collecting. A registry such as
 * [works.limn.scp.stream.HotStreamFactory] keys a subscription by context handle alone and hands
 * a second subscriber that same subscription, so without that knowledge a departing mount's
 * `onStop` releases a subscription that a different, still-composed mount collects from: that
 * collector then observes a [SharedFlow] that receives nothing further, and reports no error.
 * Navigating away from a screen and back produces it, and so does a navigation transition that
 * keeps an outgoing screen composed while an incoming screen under that same key starts.
 *
 * A caller constructs one coordinator outside composition — in a ViewModel, in an application
 * container, or in a dependency graph — and passes that instance to every
 * [rememberScpHotStream] call that shares a key space. Constructing one inside a composition
 * gives each mount its own coordinator, which reintroduces exactly that defect, so
 * [rememberScpHotStream] takes a coordinator as a required parameter and declares no default.
 *
 * This class holds per-key state: a count of live mounts, a [Mutex] that admits one start or one
 * stop at a time, the `onStop` lambdas of mounts that left while another mount under that key
 * stayed composed, and one [Job] naming the most recent stop it launched. [mount] counts a mount
 * and captures that job. [unmount] holds a departing mount's `onStop` while another mount under
 * that key stays composed, and when it removes the last live mount it launches one stop that
 * runs every `onStop` it held for that key and then the departing mount's own. So a mount that
 * leaves while another mount under that key stays composed stops nothing yet, and every mount's
 * `onStop` still runs once. [startMounted] joins the stop its mount captured before it runs a
 * `start` lambda, so ordering rests on when a caller launched `onStop`, not on when `onStop`
 * reached a dispatcher. Per-key state leaves this map as soon as no live mount and no pending
 * stop holds it.
 *
 * A key therefore groups lifetimes: a subscription stays open until the last mount under its
 * key leaves. Two mounts that share a key but hold different subscriptions — a `contextEvents`
 * stream and an `incomingMessages` stream keyed by one context handle — each still have their
 * `onStop` run, but the first one's runs only when the second one leaves. A key that names one
 * subscription, such as `"events" to handle`, releases each subscription as soon as its own
 * mounts leave. Every `onStop` must be idempotent, because mounts that shared one subscription
 * each release it; `HotStreamFactory`'s stop functions return without effect on a handle they
 * no longer hold.
 *
 * An `onStop` that throws is logged at warning level and goes no further, as
 * `.docs/standards/sdk-common.md` §Cleanup error handling requires of a cleanup error. Letting
 * it escape would reach the thread's uncaught-exception handler, which on Android kills the
 * process after the screen that mounted the stream is gone, and on a [scope] without a
 * [SupervisorJob] would also cancel that scope, so every later `onStop` would never run.
 *
 * @param scope Scope that runs every `onStop` lambda this coordinator launches. A caller owns
 *   that scope and decides when to cancel it. Composable disposal never cancels it, so an
 *   `onStop` outlives whichever mount launched it.
 */
class ScpHotStreamCoordinator(private val scope: CoroutineScope) {
    private val keyStates = ConcurrentHashMap<Any, KeyState>()

    /**
     * Run [onStop], logging whatever it throws. A throw that comes from cancelling this
     * coordinator's own [scope] still propagates, because [ensureActive] rethrows it.
     */
    private suspend fun runStop(onStop: suspend () -> Unit) {
        runCatching { onStop() }.onFailure { failure ->
            currentCoroutineContext().ensureActive()
            Log.w(COORDINATOR_TAG, "onStop threw while releasing a hot stream", failure)
        }
    }

    /**
     * One live mount under [key], as [mount] recorded it.
     *
     * @property key Key this mount was counted under.
     * @property state [key]'s state, which this mount holds until [unmount] releases it.
     * @property pendingStop Stop that [unmount] launched for [key] before this mount began, or
     *   `null` when none was recorded. [startMounted] joins it.
     */
    internal class Mount(
        val key: Any,
        val state: KeyState,
        val pendingStop: Job?,
    ) {
        /** Set by [unmount], so unmounting this mount twice removes it from the count once. */
        val unmounted = AtomicBoolean(false)
    }

    /**
     * Count one live mount under [key], and capture whichever stop [unmount] launched last for
     * [key], so this mount's [startMounted] waits for it.
     */
    internal fun mount(key: Any): Mount {
        val state = acquire(key)
        val pendingStop =
            synchronized(state) {
                state.liveMounts++
                state.lastStop
            }
        return Mount(key, state, pendingStop)
    }

    /**
     * Join the stop [mount] captured, then run [start] under that key's mutex and return what
     * [start] returned.
     *
     * A caller cancelling this call releases that mutex, so a stop waiting on it proceeds.
     *
     * @throws CancellationException when [unmount] has already removed [mount], checked under
     *   the mutex. That mount's own stop may have taken the mutex first and found nothing to
     *   release, and a start run after it would open a subscription that no stop releases.
     *   `Mutex.withLock` takes a free mutex without checking cancellation, so a cancelled
     *   caller alone does not prevent that.
     */
    internal suspend fun <T> startMounted(
        mount: Mount,
        start: suspend () -> T,
    ): T {
        mount.pendingStop?.join()
        return mount.state.mutex.withLock {
            if (mount.unmounted.get()) throw CancellationException("mount left before its start ran")
            start()
        }
    }

    /**
     * Remove [mount] from its key's live mounts. When another mount under that key is still
     * live, hold [onStop] for that key. When that leaves no live mount under that key, launch
     * one stop on this coordinator's scope that runs every held `onStop` and then [onStop],
     * each under that key's mutex, and record its [Job] before returning, so a [mount] that
     * begins afterwards captures it.
     *
     * @return A [Job] running every held `onStop` and [onStop], or `null` when another mount
     *   under that key is still live, so [onStop] waits for that mount's departure, or when
     *   [mount] was already unmounted, so [onStop] is dropped.
     */
    internal fun unmount(
        mount: Mount,
        onStop: suspend () -> Unit,
    ): Job? {
        if (!mount.unmounted.compareAndSet(false, true)) return null
        val state = mount.state
        val stopJob =
            synchronized(state) {
                state.liveMounts--
                if (state.liveMounts > 0) {
                    state.heldStops += onStop
                    null
                } else {
                    val stops = state.heldStops.toList() + onStop
                    state.heldStops.clear()
                    scope.launch(start = CoroutineStart.LAZY) {
                        state.mutex.withLock { stops.forEach { runStop(it) } }
                    }.also { state.lastStop = it }
                }
            }
        if (stopJob == null) {
            release(mount.key)
        } else {
            // This mount's hold on the state passes to its stop, so a later mount finds the
            // recorded stop until that stop completes.
            stopJob.invokeOnCompletion { release(mount.key) }
            stopJob.start()
        }
        return stopJob
    }

    /**
     * Return [key]'s state, creating it when nothing holds it, and count this caller as one
     * holder.
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
     * @property liveMounts Count of mounts that [mount] counted and [unmount] has not yet
     *   removed. Guarded by this object's monitor.
     * @property heldStops `onStop` lambdas of mounts that [unmount] removed while another mount
     *   under this key stayed live, in departure order. The stop that the last live mount's
     *   departure launches runs them. Guarded by this object's monitor.
     * @property lastStop Job of the stop [unmount] launched most recently for this key, or
     *   `null` when it has launched none since this state was created. Guarded by this object's
     *   monitor.
     * @property holders Count of live mounts and pending stops holding this state.
     *   [ScpHotStreamCoordinator] removes this state from its map when that count reaches zero,
     *   which happens only after every stop this state recorded has completed.
     */
    internal class KeyState {
        val mutex = Mutex()
        var liveMounts = 0
        val heldStops = mutableListOf<suspend () -> Unit>()
        var lastStop: Job? = null
        val holders = AtomicInteger(0)
    }
}

/**
 * Remember and manage an SCP hot stream subscription within a Composable.
 *
 * Creates a hot stream subscription that persists across recompositions
 * for the same [key]. The [start] suspend lambda is launched in a
 * coroutine scope tied to the Composable's lifetime. When the last mount under
 * [key] leaves composition, [onStop] is invoked to unsubscribe from the Rust
 * engine (e.g., call `hotStreamFactory.stopContextEvents(handle)`).
 *
 * [coordinator] sequences those two lambdas across mounts: a [start] for one key waits for an
 * [onStop] that an earlier mount launched under that same key, and a mount that leaves while
 * another mount under that same key is still composed defers its [onStop] until the last mount
 * under that key leaves, because a registry such as `HotStreamFactory` hands both mounts one
 * subscription. A [key] should name one subscription: two streams under one key each have their
 * [onStop] run, but a stream whose mount leaves first stays open until the other one's mount
 * leaves too. A caller holds that coordinator
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
 *   mount that uses a given key space. The subscription restarts if this changes too. A start
 *   under the new coordinator waits for the `onStop` that the replaced coordinator launched
 *   under that same [key], because neither coordinator can order the other's lambdas.
 * @param start Suspend factory lambda that creates the [SharedFlow]. Called
 *   once per [key] value. Runs in a coroutine scoped to the Composable.
 * @param onStop Suspend cleanup lambda invoked once the last live mount under [key] on
 *   [coordinator] leaves composition, whether that is this mount or a later one. It must be
 *   idempotent, because every mount under [key] has its own [onStop] run. Runs on
 *   [coordinator]'s scope, which disposal does not cancel, so it may suspend for as long as
 *   it needs. Disposal returns without waiting for it, so
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

    // A coordinator orders a stop and a start only when both go through that one instance.
    // When `coordinator` changes and `key` does not, the old effect's onDispose launches
    // onStop through the old coordinator and the new effect's start runs through the new
    // one, so neither coordinator orders them. The underlying resource is still one key
    // space (HotStreamFactory keys its subscriptions by context handle alone), and a start
    // that ran first would reuse the subscription the stale onStop then releases. This
    // holder survives a coordinator change because it keys on `key` alone. Compose runs the
    // old effect's onDispose before the new effect, so the new effect finds that stop's Job
    // here and its start joins it first.
    val swappedOutStop = remember(key) { AtomicReference<Job?>(null) }

    DisposableEffect(key, coordinator) {
        val pendingSwapStop = swappedOutStop.getAndSet(null)
        // Counted when this effect applies, after composition and after every onDispose in
        // the same apply pass, and before this effect's start launches. A mount under this
        // key that leaves from here on therefore sees this one as live and stops nothing,
        // and a mount that left in this pass has already run its unmount. The count must
        // stay here: a count taken during composition (in `remember`) would run before the
        // outgoing mount's unmount, and would leak when Compose abandons that composition.
        val mount = coordinator.mount(key)
        scope.launch {
            pendingSwapStop?.join()
            flowState.value = coordinator.startMounted(mount) { start() }
        }
        onDispose {
            // onDispose runs on a composition thread, which on Android is a main thread.
            // A `runBlocking { onStop() }` here parks that thread until onStop returns,
            // which risks an ANR and deadlocks whenever a dispatcher underneath onStop
            // schedules work back onto a parked thread — SCP-117's failure, in a
            // second spelling. See
            // `.docs/lessons/kotlin/oncleared-must-not-block-its-caller.md`.
            // unmount launches a stop only when this was the last live mount under this key
            // (holding onStop for that stop otherwise), and records that stop's Job before it returns, so a start that a later mount begins
            // under this same key joins that job instead of racing it. Cancelling `scope`
            // afterwards cancels only this mount's start, never that stop.
            swappedOutStop.set(coordinator.unmount(mount) { onStop() })
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

/** Log tag for failures [ScpHotStreamCoordinator] catches from `onStop`. */
private const val COORDINATOR_TAG = "ScpHotStreamCoordinator"
