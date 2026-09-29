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
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import works.limn.scp.stream.EventContextBindings
import works.limn.scp.stream.HotStreamFactory
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
 *         cleanupScope.launch {
 *             // A leave failure is logged, never thrown: an exception escaping this launch
 *             // reaches the thread's uncaught-exception handler, which on Android kills the
 *             // process (.docs/standards/sdk-common.md §Cleanup error handling).
 *             runCatching { bridge.context.leave(ctxH, idH) }
 *                 .onFailure { Log.w("ChatScreen", "leave failed after disposal", it) }
 *         }
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
 * [ScpHotStreams] constructs one coordinator together with the one [HotStreamFactory] whose
 * subscriptions it orders, so a coordinator and its registry share one lifetime and one
 * sharing, and no other coordinator orders that factory. A coordinator constructed per
 * composition, or per navigation destination, would count only its own mounts, so during a
 * transition between two screens that show one context handle, the outgoing screen's stop
 * would release the subscription the incoming screen collects.
 *
 * This class holds per-key state: a count of live mounts, a [Mutex] that admits one start or one
 * stop at a time, the `onStop` lambdas of mounts that left while another mount under that key
 * stayed composed, one [Job] naming the most recent stop it launched, and one [Job] that the
 * next stop it launches completes. [mount] counts a mount and captures the most recent stop.
 * [unmount] holds a departing mount's `onStop` while another mount under that key stays
 * composed, and when it removes the last live mount it launches one stop that runs every
 * `onStop` it held for that key and then the departing mount's own. So a mount that leaves while
 * another mount under that key stays composed stops nothing yet.
 *
 * Only a mount whose `start` ran has its `onStop` run: a mount that leaves before its `start`
 * takes the key's mutex opened nothing, and its `start` never runs afterwards. Two mounts whose
 * `start` returned one same object (compared by identity) hold one subscription, so this class
 * keeps and runs one `onStop` for that object; a registry such as `HotStreamFactory` returns one
 * [SharedFlow] instance for every caller of one subscription. A `start` that began runs to
 * completion even when its mount leaves meanwhile, so what it returned is compared too. A mount
 * whose `start` threw keeps its own `onStop`, because that `start` may have opened a
 * subscription it did not return. The `onStop` lambdas held for a key are therefore bounded by
 * the number of distinct objects its mounts' `start` returned, plus one per `start` that threw
 * and one for the `start` running under the key's mutex, not by how many mounts entered and left
 * while another mount stayed composed.
 *
 * Each stop joins the stop launched before it under that key before it takes
 * that key's mutex, and [startMounted] joins the stop its mount captured before it runs a
 * `start` lambda. Ordering therefore rests on when a caller launched `onStop`, not on when
 * `onStop` reached a dispatcher: a mount's `start` runs after every stop launched under its key
 * before that mount began. Per-key state leaves this map as soon as no live mount and no
 * pending stop holds it.
 *
 * A key therefore groups lifetimes: a subscription stays open until the last mount under its
 * key leaves. Two mounts that share a key but hold different subscriptions — a `contextEvents`
 * stream and an `incomingMessages` stream keyed by one context handle — each still have their
 * `onStop` run, but the first one's runs only when the second one leaves. A key that names one
 * subscription, such as `"events" to handle` for `contextEvents(handle)` and
 * `"messages" to handle` for `incomingMessages(handle)`, releases each subscription as soon as
 * its own mounts leave.
 *
 * Every mount that reaches one subscription MUST pass one same key. This class counts and
 * orders mounts per key only, so two keys for one subscription are two unrelated groups: a mount
 * under `handle` and a mount under `"events" to handle` that both reach one `contextEvents`
 * subscription never see each other, and the first to leave releases the subscription the other
 * still collects, which then receives nothing further and reports no error. [ScpHotStreams]
 * derives every key from one stream and one context handle, so no caller chooses a key.
 *
 * An `onStop` releases the subscription its mount's `start` returned and nothing
 * else, and must be idempotent, because a mount whose `start` returned a different object for
 * one subscription still has its own `onStop` run; `HotStreamFactory`'s stop functions return
 * without effect on a handle they no longer hold.
 *
 * An `onStop` that throws is logged at warning level and goes no further, as
 * `.docs/standards/sdk-common.md` §Cleanup error handling requires of a cleanup error. Letting
 * it escape would reach the thread's uncaught-exception handler, which on Android kills the
 * process after the screen that mounted the stream is gone, and on a [scope] without a
 * [SupervisorJob] would also cancel that scope, so every later `onStop` would never run.
 *
 * Cancelling [scope] ends this coordinator. A stop that cancellation prevents from running
 * every `onStop` it holds is logged at warning level, because each `onStop` it skipped leaves a
 * subscription open, and the [Job] [unmount] returned for each departure that stop covers
 * completes exceptionally instead of reporting that its `onStop` ran. A cancellation that
 * arrives after every `onStop` returned skips nothing, so that stop logs nothing and completes
 * that [Job] normally. A stop that held no `onStop` skipped none, so it logs nothing and completes
 * that [Job] normally. [startMounted] then refuses every
 * `start` with [ScpHotStreamCoordinatorClosedException], because no stop could release what that
 * `start` opened. [close] ends this coordinator the same way before [scope] is cancelled, and
 * returns once every running `start` and every launched stop has finished.
 *
 * @param scope Scope that runs every `onStop` lambda this coordinator launches. The owner of
 *   the [ScpHotStreams] that constructed this coordinator owns that scope, and cancels it only
 *   once every mount that passed that [ScpHotStreams] has left composition. Composable
 *   disposal never cancels it, so an `onStop` outlives whichever mount launched it.
 */
internal class ScpHotStreamCoordinator(private val scope: CoroutineScope) {
    private val keyStates = ConcurrentHashMap<Any, KeyState>()

    /** Set by [close]; [startMounted] refuses every `start` once it is set. */
    private val closed = AtomicBoolean(false)

    /**
     * Refuse every later `start`, then wait for each `start` running under a key's mutex and
     * for the last stop launched under each key, which joins every stop launched before it.
     * A stop whose scope was already cancelled returns from that wait at once.
     */
    internal suspend fun close() {
        closed.set(true)
        keyStates.values.toList().forEach { state ->
            // A start that passed the closed check holds this mutex until it returns.
            state.mutex.withLock {}
            synchronized(state) { state.lastStop }?.join()
        }
    }

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

        /**
         * [MountPhase.NOT_STARTED] until [startMounted] claims it for its `start`
         * ([MountPhase.STARTING]) or [unmount] claims it first ([MountPhase.LEFT_UNSTARTED]),
         * then a [Started] carrying what `start` returned. A `start` that threw leaves
         * [MountPhase.STARTING], which [unmount] treats as a subscription of its own. Whichever
         * of those two calls moves it off [MountPhase.NOT_STARTED] first decides whether this
         * mount's `start` runs and whether its `onStop` runs.
         */
        val phase = AtomicReference<Any>(MountPhase.NOT_STARTED)
    }

    /** What a mount's `start` returned; two are equal only when they carry one same object. */
    internal class Started(val value: Any?) {
        override fun equals(other: Any?): Boolean = other is Started && other.value === value

        override fun hashCode(): Int = System.identityHashCode(value)
    }

    /** A departed mount's `onStop`, kept with that mount so a stop can read what it started. */
    internal class HeldStop(val mount: Mount, val onStop: suspend () -> Unit)

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
     * A caller cancelling this call while it waits for that stop or that mutex ends it there,
     * and its `start` never runs. Once [start] runs, it runs to completion under
     * [NonCancellable], so a mount that leaves while its `start` is suspended still records what
     * that `start` returned, and a stop compares that object against the other held departures'
     * instead of keeping one more `onStop` for a subscription it cannot identify. A stop under
     * that key therefore waits for a running `start` to return, whoever cancelled its caller.
     *
     * @throws ScpHotStreamCoordinatorClosedException when [close] has run or this coordinator's
     *   scope is cancelled, checked under the mutex, because no stop could release what [start]
     *   opened.
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
            if (closed.get() || !scope.isActive) {
                throw ScpHotStreamCoordinatorClosedException("the coordinator is closed or its scope is cancelled")
            }
            if (!mount.phase.compareAndSet(MountPhase.NOT_STARTED, MountPhase.STARTING)) {
                throw CancellationException("mount left before its start ran")
            }
            withContext(NonCancellable) { start().also { mount.phase.set(Started(it)) } }
        }
    }

    /**
     * Remove [mount] from its key's live mounts. When another mount under that key is still
     * live, hold [onStop] for that key. When that leaves no live mount under that key, launch
     * one stop on this coordinator's scope that joins the stop launched before it under that
     * key, then runs every held `onStop` and then [onStop] under that key's mutex, and record
     * its [Job] before returning, so a [mount] that begins afterwards captures it.
     *
     * [onStop] is kept only when [mount]'s `start` ran or is running, and the stop runs it only
     * when no `onStop` it runs earlier came from a mount whose `start` returned that same object.
     * A held departure whose `start` returned an object an earlier held departure's `start`
     * returned adds nothing to the held list.
     *
     * @return A [Job] that the stop covering [onStop] completes once it has run every `onStop`
     *   it holds. Every departure that stop covers gets this one [Job], whether that stop
     *   launched now or launches at the last live mount's departure. It completes exceptionally
     *   when cancelling this coordinator's scope kept that stop from running every `onStop` it
     *   held, and normally when that cancellation arrived after the last `onStop` returned.
     *   `null` when [mount] was already unmounted, so [onStop] is dropped.
     */
    internal fun unmount(
        mount: Mount,
        onStop: suspend () -> Unit,
    ): Job? {
        if (!mount.unmounted.compareAndSet(false, true)) return null
        // Claimed before the mutex: a start that has not claimed the phase yet never runs.
        val leftUnstarted = mount.phase.compareAndSet(MountPhase.NOT_STARTED, MountPhase.LEFT_UNSTARTED)
        val own = if (leftUnstarted) null else HeldStop(mount, onStop)
        val state = mount.state
        var launched: Job? = null
        val stopDone =
            synchronized(state) {
                state.liveMounts--
                if (state.liveMounts > 0) {
                    if (own != null) {
                        val kept = distinctStarts(state.heldStops + own)
                        state.heldStops.clear()
                        state.heldStops += kept
                    }
                    state.nextStop ?: Job().also { state.nextStop = it }
                } else {
                    val stops = state.heldStops.toList() + listOfNotNull(own)
                    state.heldStops.clear()
                    // A stop launched earlier under this key may not have reached the mutex
                    // yet, so without this join a later stop could take the mutex first, and a
                    // mount that captured only the later stop would start before the earlier
                    // stop releases what that start opened.
                    val prior = state.lastStop
                    // One Job for every departure this stop covers, held ones and this one.
                    val done = state.nextStop ?: Job()
                    state.nextStop = null
                    // Set once every onStop has returned. Cancelling the scope while the last
                    // onStop runs still completes this stop's Job as cancelled, so the Job's
                    // completion cause alone cannot tell a skipped onStop from none skipped.
                    val ranEvery = AtomicBoolean(false)
                    scope.launch(start = CoroutineStart.LAZY) {
                        prior?.join()
                        state.mutex.withLock { distinctStarts(stops).forEach { runStop(it.onStop) } }
                        ranEvery.set(true)
                    }.also { stop ->
                        state.lastStop = stop
                        launched = stop
                        stop.invokeOnCompletion { cause ->
                            // A stop that held no onStop skipped none, so it reports no skip.
                            if (cause == null || ranEvery.get() || stops.isEmpty()) {
                                done.complete()
                            } else {
                                Log.w(COORDINATOR_TAG, SCOPE_CANCELLED_BEFORE_STOP, cause)
                                done.completeExceptionally(cause)
                            }
                        }
                    }
                    done
                }
            }
        val stopJob = launched
        if (stopJob == null) {
            release(mount.key)
        } else {
            // This mount's hold on the state passes to its stop, so a later mount finds the
            // recorded stop until that stop completes.
            stopJob.invokeOnCompletion { release(mount.key) }
            stopJob.start()
        }
        return stopDone
    }

    /**
     * [stops] without each entry whose mount's `start` returned an object an earlier entry's
     * `start` returned, in order. An entry whose `start` threw, or is still running, is kept.
     */
    private fun distinctStarts(stops: List<HeldStop>): List<HeldStop> {
        val seen = HashSet<Started>()
        return stops.filter { held ->
            val started = held.mount.phase.get() as? Started
            started == null || seen.add(started)
        }
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
     *   under this key stayed live and whose `start` ran, in departure order, at most one per
     *   object those mounts' `start` returned, plus each whose `start` threw or was still
     *   running when [unmount] last compacted this list. The stop that the last live mount's departure
     *   launches runs them. Guarded by this object's monitor.
     * @property lastStop Job of the stop [unmount] launched most recently for this key, or
     *   `null` when it has launched none since this state was created. The next stop [unmount]
     *   launches joins it. Guarded by this object's monitor.
     * @property nextStop Job that [unmount] returned for a departure it held, which the next
     *   stop [unmount] launches for this key completes on finishing, or `null` when no held
     *   departure is waiting. Guarded by this object's monitor.
     * @property holders Count of live mounts and pending stops holding this state.
     *   [ScpHotStreamCoordinator] removes this state from its map when that count reaches zero,
     *   which happens only after every stop this state recorded has completed.
     */
    internal class KeyState {
        val mutex = Mutex()
        var liveMounts = 0
        val heldStops = mutableListOf<HeldStop>()
        var lastStop: Job? = null
        var nextStop: CompletableJob? = null
        val holders = AtomicInteger(0)
    }
}

/**
 * Compose access to one [HotStreamFactory]'s context-event and incoming-message streams.
 *
 * This class constructs its own [HotStreamFactory] over [bindings] and its own
 * [ScpHotStreamCoordinator] on [scope], and exposes neither, so the coordinator that orders a
 * factory's subscriptions is always the one constructed with that factory, and no second
 * coordinator can reach it. [rememberContextEvents] and [rememberIncomingMessages] derive each
 * subscription's key from its stream and its context handle, so every mount of one
 * subscription counts under one key. A second instance over the same [bindings] opens a
 * second Rust subscription per stream it serves, and only that instance's stops release it.
 *
 * An application container, a dependency-graph singleton, or a ViewModel that every navigation
 * destination shares (one scoped to the activity or to the navigation graph) holds one instance
 * and passes it to every composable that shows a context's streams, so every screen showing
 * one context's stream shares one Rust subscription.
 *
 * Usage:
 * ```kotlin
 * // Built once, outside composition. Once every composable that passed hotStreams has left
 * // composition, its owner calls hotStreams.close() and then cancels streamScope.
 * val streamScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
 * val hotStreams = ScpHotStreams(bindings, streamScope, Dispatchers.IO)
 *
 * @Composable
 * fun EventList(handle: Long, hotStreams: ScpHotStreams) {
 *     val events = rememberContextEvents(hotStreams, handle).value
 *     if (events != null) {
 *         val eventList by rememberScpFlow(events, emptyList<String>())
 *     }
 * }
 * ```
 *
 * @param bindings Event bindings the owned [HotStreamFactory] subscribes through.
 * @param scope Scope that runs every `onStop` the owned coordinator launches. Its owner calls
 *   [close] and then cancels it, once every mount that passed this instance has left
 *   composition; cancelling it without [close] skips each pending stop, logs that skip, and
 *   refuses every later start.
 * @param ioDispatcher Dispatcher the owned [HotStreamFactory] subscribes and releases on. A test
 *   injects a `StandardTestDispatcher` here.
 */
class ScpHotStreams(
    bindings: EventContextBindings,
    scope: CoroutineScope,
    ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    internal val factory = HotStreamFactory(bindings, ioDispatcher)
    internal val coordinator = ScpHotStreamCoordinator(scope)

    /**
     * Release every Rust subscription this instance opened. Its owner calls this once every
     * mount that passed this instance has left composition, and before it cancels `scope`.
     *
     * This refuses every later `start` with [ScpHotStreamCoordinatorClosedException], waits for
     * each running `start` and each stop already launched, and then calls
     * [HotStreamFactory.stopAll], so a subscription whose stop a cancelled `scope` skipped is
     * released too. A mount still composed when this runs loses its subscription and receives
     * nothing further.
     */
    suspend fun close() {
        coordinator.close()
        factory.stopAll()
    }
}

/**
 * Remember [contextHandle]'s context-event stream from [hotStreams], opened through
 * [HotStreamFactory.contextEvents] and released through [HotStreamFactory.stopContextEvents]
 * when the last mount of that stream leaves composition.
 *
 * @return Compose [State] holding the [SharedFlow], or `null` until the subscription opens. A
 *   mount that starts after [hotStreams] is closed or its scope is cancelled has its start
 *   refused, and its [State] stays `null`. A mount that already holds a [SharedFlow] keeps it;
 *   once [ScpHotStreams.close] runs, that flow receives nothing further.
 */
@Composable
fun rememberContextEvents(
    hotStreams: ScpHotStreams,
    contextHandle: Long,
): State<SharedFlow<String>?> =
    rememberScpHotStream(
        key = HotStreamKind.CONTEXT_EVENTS to contextHandle,
        coordinator = hotStreams.coordinator,
        start = { hotStreams.factory.contextEvents(contextHandle) },
        onStop = { hotStreams.factory.stopContextEvents(contextHandle) },
    )

/**
 * Remember [contextHandle]'s incoming-message stream from [hotStreams], opened through
 * [HotStreamFactory.incomingMessages] and released through [HotStreamFactory.stopMessageStream]
 * when the last mount of that stream leaves composition.
 *
 * @return Compose [State] holding the [SharedFlow], or `null` until the subscription opens. A
 *   mount that starts after [hotStreams] is closed or its scope is cancelled has its start
 *   refused, and its [State] stays `null`. A mount that already holds a [SharedFlow] keeps it;
 *   once [ScpHotStreams.close] runs, that flow receives nothing further.
 */
@Composable
fun rememberIncomingMessages(
    hotStreams: ScpHotStreams,
    contextHandle: Long,
): State<SharedFlow<String>?> =
    rememberScpHotStream(
        key = HotStreamKind.INCOMING_MESSAGES to contextHandle,
        coordinator = hotStreams.coordinator,
        start = { hotStreams.factory.incomingMessages(contextHandle) },
        onStop = { hotStreams.factory.stopMessageStream(contextHandle) },
    )

/** Which [HotStreamFactory] stream a hot-stream key names, paired with a context handle. */
internal enum class HotStreamKind {
    CONTEXT_EVENTS,
    INCOMING_MESSAGES,
}

/**
 * Remember and manage one hot stream subscription within a Composable. [rememberContextEvents]
 * and [rememberIncomingMessages] are its only production callers, and each passes a key that
 * names one subscription.
 *
 * [start] runs once each time this mount begins under a ([key], [coordinator]) pair, and not
 * at all when the mount leaves before [start] takes the key's mutex. [coordinator] sequences
 * [start] and [onStop] across mounts: a [start] for one key waits for an [onStop] that an
 * earlier mount launched under that key, and a mount that leaves while another mount under
 * that key is still composed defers its [onStop] until the last mount under that key leaves.
 *
 * @param key Recomposition key, compared with `equals`. The subscription restarts if it
 *   changes. It names the one subscription [start] returns, because [coordinator] counts and
 *   orders mounts per key only.
 * @param coordinator Orders this mount's [start] after any [onStop] an earlier mount launched
 *   under [key]. The subscription restarts if it changes. [State] stays `null` once its scope
 *   is cancelled: the start is refused and logged at warning level.
 * @param start Suspend lambda that opens the [SharedFlow]. Once it begins, disposal does not
 *   cancel it: it runs to completion, so [coordinator] learns what it returned. It returns one
 *   same [SharedFlow] instance to every mount of one subscription, as `HotStreamFactory` does,
 *   because [coordinator] runs one [onStop] per instance it saw.
 * @param onStop Suspend lambda that releases the subscription [start] returned, and nothing
 *   else. [coordinator] runs it on its own scope once the last live mount under [key] leaves,
 *   and skips it when this mount left before its [start] ran or when an [onStop] it runs first
 *   came from a mount whose [start] returned the same instance. It must be idempotent, because
 *   mounts that got one subscription as different instances each have their own [onStop] run.
 *   Disposal returns without waiting for it.
 * @return Compose [State] holding the [SharedFlow], or `null` until the subscription is
 *   established.
 */
@Composable
internal fun <T> rememberScpHotStream(
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
        // Counted when this effect applies, after composition and after every onDispose in
        // the same apply pass, and before this effect's start launches. A mount under this
        // key that leaves from here on therefore sees this one as live and stops nothing,
        // and a mount that left in this pass has already run its unmount. A count taken during
        // composition (in `remember`) would run before the outgoing mount's unmount, and would
        // leak when Compose abandons that composition.
        val mount = coordinator.mount(key)
        scope.launch {
            try {
                flowState.value = coordinator.startMounted(mount, start)
            } catch (closed: ScpHotStreamCoordinatorClosedException) {
                Log.w(COORDINATOR_TAG, "hot stream not started", closed)
            }
        }
        onDispose {
            // onDispose runs on a composition thread, which on Android is a main thread.
            // A `runBlocking { onStop() }` here parks that thread until onStop returns,
            // which risks an ANR and deadlocks whenever a dispatcher underneath onStop
            // schedules work back onto a parked thread — SCP-117's failure, in a
            // second spelling. See
            // `.docs/lessons/kotlin/oncleared-must-not-block-its-caller.md`.
            // unmount launches a stop only when this was the last live mount under this key
            // (holding onStop for that stop otherwise), and records that stop's Job before it
            // returns, so a start that a later mount begins under this same key joins that job
            // instead of racing it. It drops onStop when this mount's start never ran there.
            // Cancelling `scope` afterwards cancels this mount's start only while it waits to
            // run (a start already running finishes), and never that stop.
            coordinator.unmount(mount, onStop)
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

/** Warning [ScpHotStreamCoordinator] logs when its scope's cancellation skipped an `onStop`. */
private const val SCOPE_CANCELLED_BEFORE_STOP =
    "coordinator scope cancelled before every onStop ran; a hot stream subscription stays open"

/** Where a mount stands before its `start` returns; [ScpHotStreamCoordinator.Mount.phase]. */
internal enum class MountPhase {
    /** Neither [ScpHotStreamCoordinator.startMounted] nor `unmount` has claimed the mount. */
    NOT_STARTED,

    /** `startMounted` claimed the mount and its `start` has not returned, or threw. */
    STARTING,

    /** `unmount` claimed the mount first, so its `start` never runs and its `onStop` is dropped. */
    LEFT_UNSTARTED,
}

/**
 * Thrown by [ScpHotStreamCoordinator]'s start path once that coordinator is closed or its scope
 * is cancelled: no stop could release a subscription a `start` opened then, so the coordinator
 * runs none.
 */
internal class ScpHotStreamCoordinatorClosedException(message: String) : IllegalStateException(message)
