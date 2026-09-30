// Streams.kt — Kotlin Flow/Channel streaming layer for the SCP SDK (SCP-116)
// Provenance: ADR-028 (Kotlin SDK), SCP-116

package works.limn.scp.stream

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import works.limn.scp.bridge.BridgeException
import works.limn.scp.bridge.ContextBindings
import works.limn.scp.bridge.InfraBindings
import works.limn.scp.bridge.MessageCallback
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.logging.Level
import java.util.logging.Logger

/**
 * Callback interface for real-time context events from the Rust engine.
 *
 * Mirrors the UniFFI callback interface for context lifecycle events:
 * member joins, member leaves, context state changes, and role assignments.
 * Used by [HotStreamFactory.contextEvents] to bridge callback-driven
 * delivery into a hot [SharedFlow].
 */
interface EventCallback {
    fun onEvent(eventJson: String)

    fun onError(
        code: String,
        message: String,
    )

    fun onComplete()
}

/**
 * Extended context bindings that include event subscription for hot streams.
 *
 * Extends [ContextBindings] with event-level subscription methods that
 * the Rust engine uses to push context lifecycle events (member joined,
 * member left, state changes) in real time.
 */
interface EventContextBindings : ContextBindings {
    fun contextSubscribeEvents(
        contextHandle: Long,
        callback: EventCallback,
    ): Long

    fun contextUnsubscribeEvents(subscriptionHandle: Long)
}

/**
 * Factory for cold [Flow] streams over paginated query results.
 *
 * Cold streams are lazy: no FFI work occurs until the flow is collected.
 * Each collection triggers a fresh query. Cancelling collection stops
 * the iteration — no resources remain open.
 *
 * ## Backpressure
 *
 * Cold streams use the collector's consumption rate as natural backpressure.
 * Each page is fetched only after the previous page's items have been emitted
 * and consumed by the collector. No internal buffering beyond the current page.
 *
 * ## Stream types
 *
 * - **Message history**: Paginated retrieval of past messages in a context.
 * - **Event log query**: Paginated retrieval of event log entries.
 *
 * @param infraBindings The infrastructure FFI bindings for event log queries.
 * @param ioDispatcher Dispatcher for FFI calls. Defaults to [Dispatchers.IO].
 */
class ColdStreamFactory(
    private val infraBindings: InfraBindings,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    /**
     * Cold flow of event log entries for a context, fetched page by page.
     *
     * Each emission is a JSON-encoded page of event log entries. The flow
     * terminates when the query returns an empty page (no more results).
     *
     * Collection triggers the first query. Cancelling the collector stops
     * fetching subsequent pages.
     *
     * @param contextHandle Handle from context create or join.
     * @param filterJson JSON-encoded query filter (e.g., event type, time range).
     * @param pageSize Number of entries per page.
     * @return Cold [Flow] of JSON-encoded event log pages.
     */
    fun eventLogPages(
        contextHandle: Long,
        filterJson: String,
        pageSize: Int = 50,
    ): Flow<String> = paginatedEventQuery(contextHandle, filterJson, pageSize)

    /**
     * Cold flow of message history for a context, fetched page by page.
     *
     * Each emission is a JSON-encoded page of historical messages. The flow
     * terminates when the query returns an empty page.
     *
     * Note: Currently delegates to the same FFI binding as [eventLogPages]
     * (`infraBindings.eventLogQuery`). These will diverge when separate
     * message-history FFI bindings are added.
     *
     * @param contextHandle Handle from context create or join.
     * @param filterJson JSON-encoded query filter (e.g., time range, sender).
     * @param pageSize Number of messages per page.
     * @return Cold [Flow] of JSON-encoded message history pages.
     */
    fun messageHistoryPages(
        contextHandle: Long,
        filterJson: String,
        pageSize: Int = 50,
    ): Flow<String> = paginatedEventQuery(contextHandle, filterJson, pageSize)

    /**
     * Shared implementation for paginated event/message queries.
     *
     * Both [eventLogPages] and [messageHistoryPages] currently use the same
     * FFI binding ([InfraBindings.eventLogQuery]). This shared function
     * eliminates the duplication. When separate FFI bindings exist for
     * message history, the two public functions will diverge.
     */
    private fun paginatedEventQuery(
        contextHandle: Long,
        filterJson: String,
        pageSize: Int,
    ): Flow<String> =
        flow {
            var offset = 0
            while (true) {
                val paginatedFilter = buildPaginatedFilter(filterJson, offset, pageSize)
                val page =
                    withContext(ioDispatcher) {
                        infraBindings.eventLogQuery(contextHandle, paginatedFilter)
                    }
                if (page == "[]" || page.isBlank()) break
                emit(page)
                offset += pageSize
            }
        }
}

/**
 * Build a paginated filter JSON by injecting offset and limit parameters.
 *
 * Appends pagination fields to the filter. The Rust engine's event log
 * query accepts `_offset` and `_limit` fields for cursor-based pagination.
 *
 * @param baseFilter The original filter JSON.
 * @param offset The current page offset.
 * @param pageSize The page size (limit).
 * @return JSON string with pagination fields injected.
 */
internal fun buildPaginatedFilter(
    baseFilter: String,
    offset: Int,
    pageSize: Int,
): String {
    val trimmed = baseFilter.trimEnd()
    if (trimmed == "{}" || trimmed.isBlank()) {
        return """{"_offset":$offset,"_limit":$pageSize}"""
    }
    val insertPoint = trimmed.lastIndexOf('}')
    if (insertPoint < 0) return """{"_offset":$offset,"_limit":$pageSize}"""
    val prefix = trimmed.substring(0, insertPoint).trimEnd()
    val separator = if (prefix.endsWith('{')) "" else ","
    return """$prefix$separator"_offset":$offset,"_limit":$pageSize}"""
}

/**
 * Factory for hot streams that deliver real-time events via [SharedFlow].
 *
 * Hot streams are always active once started: events are pushed by the Rust
 * engine regardless of whether any collector is listening. Late subscribers
 * receive events from the point they subscribe (with configurable replay).
 *
 * ## Backpressure
 *
 * Hot streams use a [MutableSharedFlow] with [BUFFER_CAPACITY] extra buffer
 * slots and [BufferOverflow.DROP_OLDEST] overflow strategy. This ensures the
 * Rust callback thread is never blocked — if all collectors fall behind, the
 * oldest undelivered events are dropped rather than blocking the engine.
 *
 * ## Stream types
 *
 * - **Context events**: Member joins, leaves, state changes, role assignments.
 * - **Incoming messages**: Real-time message delivery (hot variant for
 *   SharedFlow-based multi-collector scenarios).
 *
 * ## Cleanup
 *
 * Call [stopAll] in teardown, or [stopContextEvents] or [stopMessageStream] for
 * one handle, to unsubscribe from the Rust engine and remove the registry
 * entry. A Rust engine that reports a subscription complete ends it and drops
 * its registry entry, so no stop unsubscribes that one. Nothing else releases
 * a subscription: cancelling a collector's scope does not, and the factory has
 * no finalizer or cleaner, so dropping it without a stop leaves every
 * subscription it opened that the engine has not completed live, still
 * emitting into its [SharedFlow].
 */
class HotStreamFactory(
    private val contextBindings: EventContextBindings,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    private val activeEventSubscriptions = ConcurrentHashMap<Long, HotStreamState>()
    private val activeMessageSubscriptions = ConcurrentHashMap<Long, HotStreamState>()
    private val eventMutex = Mutex()
    private val messageMutex = Mutex()

    /**
     * Start a hot [SharedFlow] of real-time context events.
     *
     * The Rust engine pushes events via [EventCallback]. Multiple collectors
     * can subscribe to the returned [SharedFlow]; each receives all events
     * from their subscription point forward (plus [replay] historical events).
     *
     * Thread-safe: uses a [Mutex] to prevent duplicate subscriptions from
     * concurrent calls with the same [contextHandle] (TOCTOU fix).
     *
     * @param contextHandle Opaque context handle from create/join.
     * @param replay Number of past events to replay to new subscribers.
     * @return Hot [SharedFlow] of JSON-encoded context events.
     */
    suspend fun contextEvents(
        contextHandle: Long,
        replay: Int = 0,
    ): SharedFlow<String> =
        eventMutex.withLock {
            val existing = activeEventSubscriptions[contextHandle]
            if (existing != null) return@withLock existing.readOnly

            val sharedFlow =
                MutableSharedFlow<String>(
                    replay = replay,
                    extraBufferCapacity = BUFFER_CAPACITY,
                    onBufferOverflow = BufferOverflow.DROP_OLDEST,
                )
            val readOnly = sharedFlow.asSharedFlow()
            val slot = SubscriptionSlot(activeEventSubscriptions, contextHandle)

            val callback =
                object : EventCallback {
                    override fun onEvent(eventJson: String) {
                        sharedFlow.tryEmit(eventJson)
                    }

                    override fun onError(
                        code: String,
                        message: String,
                    ) {
                        sharedFlow.tryEmit(
                            Json.encodeToString(
                                buildJsonObject {
                                    put("_error", true)
                                    put("code", code)
                                    put("message", message)
                                },
                            ),
                        )
                    }

                    override fun onComplete() {
                        slot.markComplete()
                    }
                }

            // NonCancellable covers exactly two statements: one subscribe call into a Rust
            // engine, and one registry write naming what that call returned. A cancellation
            // arriving between those two statements leaves a live Rust subscription that no
            // registry entry names, so neither stopContextEvents nor stopAll can release it.
            // Every other statement in this function stays cancellable. withLock takes an
            // uncontended mutex without checking cancellation, and withContext checks only
            // the NonCancellable Job it installs, so ensureActive is what stops a caller that
            // is already cancelled from opening a subscription: a caller cancelled before the
            // block opens none, and a caller cancelled after it can still pass contextHandle
            // to stopContextEvents.
            currentCoroutineContext().ensureActive()
            withContext(NonCancellable + ioDispatcher) {
                val subscriptionHandle = contextBindings.contextSubscribeEvents(contextHandle, callback)
                slot.register(HotStreamState(readOnly, subscriptionHandle))
            }
            readOnly
        }

    /**
     * Start a hot [SharedFlow] of real-time incoming messages.
     *
     * Unlike [works.limn.scp.bridge.ContextBridge.subscribe] which returns a
     * cold [Flow] (one collector, subscription starts on collect), this
     * returns a hot [SharedFlow] suitable for multiple concurrent collectors.
     *
     * Thread-safe: uses a [Mutex] to prevent duplicate subscriptions from
     * concurrent calls with the same [contextHandle] (TOCTOU fix).
     *
     * @param contextHandle Opaque context handle from create/join.
     * @param replay Number of past messages to replay to new subscribers.
     * @return Hot [SharedFlow] of JSON-encoded messages.
     */
    suspend fun incomingMessages(
        contextHandle: Long,
        replay: Int = 0,
    ): SharedFlow<String> =
        messageMutex.withLock {
            val existing = activeMessageSubscriptions[contextHandle]
            if (existing != null) return@withLock existing.readOnly

            val sharedFlow =
                MutableSharedFlow<String>(
                    replay = replay,
                    extraBufferCapacity = BUFFER_CAPACITY,
                    onBufferOverflow = BufferOverflow.DROP_OLDEST,
                )
            val readOnly = sharedFlow.asSharedFlow()
            val slot = SubscriptionSlot(activeMessageSubscriptions, contextHandle)

            val callback =
                object : MessageCallback {
                    override fun onMessage(messageJson: String) {
                        sharedFlow.tryEmit(messageJson)
                    }

                    override fun onError(
                        code: String,
                        message: String,
                    ) {
                        sharedFlow.tryEmit(
                            Json.encodeToString(
                                buildJsonObject {
                                    put("_error", true)
                                    put("code", code)
                                    put("message", message)
                                },
                            ),
                        )
                    }

                    override fun onComplete() {
                        slot.markComplete()
                    }
                }

            // NonCancellable covers exactly two statements, for a reason contextEvents states
            // above its own subscribe call: a cancellation landing between a subscribe call and
            // a registry write orphans a live Rust subscription. ensureActive stops a caller
            // that is already cancelled before it opens one, for the reason contextEvents states.
            currentCoroutineContext().ensureActive()
            withContext(NonCancellable + ioDispatcher) {
                val subscriptionHandle = contextBindings.contextSubscribe(contextHandle, callback)
                slot.register(HotStreamState(readOnly, subscriptionHandle))
            }
            readOnly
        }

    /**
     * Stop receiving context events for the given context handle.
     *
     * Removes the handle's registry entry and unsubscribes from the Rust engine.
     * When the unsubscribe call succeeds, the [SharedFlow] returned by
     * [contextEvents] receives no new events after this call. When it throws,
     * the Rust subscription may stay live and keep emitting into that
     * [SharedFlow], although no registry entry names it any more.
     *
     * Takes [eventMutex], so a stop that races an in-flight [contextEvents] call for one same
     * handle waits for that call to record its subscription and then releases it. Without that
     * mutex a stop reads an empty registry, returns, and leaves a subscription that that same
     * in-flight call registers a moment later.
     *
     * Waits for [eventMutex] under [NonCancellable]: a cancelled caller that found the mutex
     * held would otherwise throw from `withLock` and leave this handle's subscription live.
     *
     * Never throws a release's failure (`.docs/standards/sdk-common.md` §Cleanup error
     * handling): an unsubscribe call that throws is logged at warning level, and the handle's
     * registry entry is gone by then, as [removeEventSubscription] states.
     *
     * @param contextHandle The context to stop receiving events for.
     */
    suspend fun stopContextEvents(contextHandle: Long) {
        withContext(NonCancellable) {
            eventMutex.withLock {
                releaseLogged("stopContextEvents", "context events", contextHandle) {
                    removeEventSubscription(contextHandle)
                }
            }
        }
    }

    /**
     * Stop receiving messages for the given context handle.
     *
     * Removes the handle's registry entry and unsubscribes from the Rust engine, and after an
     * unsubscribe call that throws the [SharedFlow] returned by [incomingMessages] may keep
     * receiving messages, as [stopContextEvents] states for events. Takes [messageMutex], and
     * waits for it under [NonCancellable], for the reasons [stopContextEvents] states about
     * [eventMutex]. An unsubscribe call that throws is logged, never thrown, as
     * [stopContextEvents] states.
     *
     * @param contextHandle The context to stop receiving messages for.
     */
    suspend fun stopMessageStream(contextHandle: Long) {
        withContext(NonCancellable) {
            messageMutex.withLock {
                releaseLogged("stopMessageStream", "incoming messages", contextHandle) {
                    removeMessageSubscription(contextHandle)
                }
            }
        }
    }

    /**
     * Stop all active subscriptions. Call during teardown.
     *
     * Takes each mutex once and then removes every handle under it, rather than delegating to
     * [stopContextEvents] and [stopMessageStream], because taking one non-reentrant [Mutex]
     * twice on one coroutine deadlocks that coroutine.
     *
     * The whole body runs under [NonCancellable]. Each removal's own `withContext` still runs
     * its block for a cancelled caller, and when [ioDispatcher] differs from that caller's
     * dispatcher, so that `withContext` resumes the caller by dispatch, it then throws
     * [kotlinx.coroutines.CancellationException] on that resumption; [releaseLogged] would catch
     * that throw after a release that succeeded and log it as a failed release. The wrapper keeps
     * that false warning out of the log.
     *
     * Attempts every release it holds and never throws a release's failure
     * (`.docs/standards/sdk-common.md` §Cleanup error handling): an unsubscribe call that
     * throws is logged at warning level, and the loop moves on to the next handle. Every
     * registry entry is gone when this returns, the failed ones included, because that
     * section requires local state to be released whatever a remote call reports.
     */
    suspend fun stopAll() {
        withContext(NonCancellable) {
            eventMutex.withLock {
                activeEventSubscriptions.keys.toList().forEach { handle ->
                    releaseLogged("stopAll", "context events", handle) { removeEventSubscription(handle) }
                }
            }
            messageMutex.withLock {
                activeMessageSubscriptions.keys.toList().forEach { handle ->
                    releaseLogged("stopAll", "incoming messages", handle) { removeMessageSubscription(handle) }
                }
            }
        }
    }

    /**
     * Run one release for [operation] and log its failure instead of throwing it.
     *
     * Catches [Exception], not [Throwable], so an [Error] such as an out-of-memory condition
     * still propagates. Every caller runs under [NonCancellable], so no cancellation of that
     * caller reaches this catch.
     */
    @Suppress("TooGenericExceptionCaught")
    private suspend fun releaseLogged(
        operation: String,
        stream: String,
        contextHandle: Long,
        release: suspend () -> Unit,
    ) {
        try {
            release()
        } catch (e: Exception) {
            logger.log(
                Level.WARNING,
                "HotStreamFactory.$operation: releasing $stream for context handle $contextHandle " +
                    "failed; its registry entry is removed and the Rust subscription may stay live",
                e,
            )
        }
    }

    /**
     * Remove one event subscription from [activeEventSubscriptions] and unsubscribe it.
     *
     * A caller holds [eventMutex] across this call. [NonCancellable] pairs a registry removal
     * with an unsubscribe call for a reason [contextEvents] states about its own subscribe
     * call: a cancellation landing between those two statements drops a caller's only route to
     * a live Rust subscription. The entry is removed before the unsubscribe call, so an
     * unsubscribe that throws still leaves no local state behind, and its throw propagates to
     * [releaseLogged], which logs it.
     */
    private suspend fun removeEventSubscription(contextHandle: Long) {
        withContext(NonCancellable + ioDispatcher) {
            val state = activeEventSubscriptions.remove(contextHandle) ?: return@withContext
            contextBindings.contextUnsubscribeEvents(state.subscriptionHandle)
        }
    }

    /**
     * Remove one message subscription from [activeMessageSubscriptions] and unsubscribe it.
     *
     * A caller holds [messageMutex] across this call, and [NonCancellable] pairs those two
     * statements, in that order, for the reasons [removeEventSubscription] states.
     */
    private suspend fun removeMessageSubscription(contextHandle: Long) {
        withContext(NonCancellable + ioDispatcher) {
            val state = activeMessageSubscriptions.remove(contextHandle) ?: return@withContext
            contextBindings.contextUnsubscribe(state.subscriptionHandle)
        }
    }

    private companion object {
        val logger: Logger = Logger.getLogger(HotStreamFactory::class.java.name)
    }
}

/**
 * Internal state for an active hot stream subscription.
 *
 * Pairs a read-only [SharedFlow] that a caller collects with a Rust subscription handle, so that
 * [HotStreamFactory.stopContextEvents], [HotStreamFactory.stopMessageStream], and
 * [HotStreamFactory.stopAll] can unsubscribe from a Rust engine.
 *
 * Carries no `equals` override, so two instances compare by identity. [SubscriptionSlot] relies
 * on that: it removes a registry entry only when that entry is its own instance.
 */
private class HotStreamState(
    val readOnly: SharedFlow<String>,
    val subscriptionHandle: Long,
)

/**
 * Registry entry for one subscription, written by [HotStreamFactory] and cleared by whichever
 * Rust callback reports that same subscription complete.
 *
 * A Rust callback thread runs [markComplete] outside any coroutine, so that thread cannot take
 * [HotStreamFactory]'s mutex. [ConcurrentHashMap.remove] with a value argument removes an entry
 * only when that entry is this slot's own [HotStreamState], so a completion callback belonging
 * to an earlier subscription never removes a later subscription that carries one same context
 * handle.
 */
private class SubscriptionSlot(
    private val registry: ConcurrentHashMap<Long, HotStreamState>,
    private val contextHandle: Long,
) {
    private val state = AtomicReference<HotStreamState?>(null)
    private val completed = AtomicBoolean(false)

    /** Publish [newState] to this slot and to [registry]. */
    fun register(newState: HotStreamState) {
        state.set(newState)
        registry[contextHandle] = newState
        // A Rust callback thread can report completion before this method publishes newState,
        // in which case markComplete found no state to remove. Re-reading that flag here makes
        // whichever of these two threads runs second remove an entry naming a subscription that
        // a Rust engine has already ended.
        if (completed.get()) {
            registry.remove(contextHandle, newState)
        }
    }

    /** Record that a Rust engine ended this subscription, and drop its registry entry. */
    fun markComplete() {
        completed.set(true)
        state.get()?.let { registry.remove(contextHandle, it) }
    }
}

/**
 * Cold flow of a context's messages, built on [ContextBindings] rather than on a
 * [works.limn.scp.bridge.CoroutineBridge] (SCP-115).
 *
 * It shares these behaviours with [works.limn.scp.bridge.ContextBridge.subscribe]:
 *
 * - A message that does not fit the `callbackFlow` buffer (`Channel.BUFFERED`, 64 items)
 *   closes the flow with [BridgeException] code `SCP-CTX-2001`, found through the [trySend]
 *   result; the callback runs on a non-suspending Rust thread, so it cannot call [send]. No
 *   `.buffer(...)` is chained after the `callbackFlow`.
 * - The subscribe call runs under [NonCancellable], so a collector cancelled during it still
 *   records the handle. Closing the flow then calls the unsubscribe function, suspending on
 *   the IO dispatcher rather than blocking the collector's thread. An unsubscribe that throws
 *   is logged at WARNING and not rethrown, and the Rust subscription may then stay live.
 *
 * It differs from [works.limn.scp.bridge.ContextBridge.subscribe] in three ways:
 *
 * 1. It takes the bindings and [ioDispatcher] as parameters instead of reading them from a
 *    [works.limn.scp.bridge.CoroutineBridge].
 * 2. It sets an [AtomicBoolean] as the first statement of the producer's `finally`, and skips
 *    [trySend] for a message the engine delivers from then on. That `finally` runs when the
 *    producer leaves its `try` block: after the channel closed and `awaitClose()` returned, or
 *    with the channel still open when an exception ended the block (the subscribe call threw,
 *    or the collector was cancelled). A message the engine delivers before the flag is set
 *    still reaches [trySend]; on a closed channel [trySend] fails and the callback ignores that
 *    failure.
 *    [works.limn.scp.bridge.ContextBridge.subscribe] has no such flag, so it calls [trySend]
 *    for every late message and ignores the failure the same way.
 * 3. It logs a failed release to the [COLD_MESSAGE_FLOW_LOGGER] logger.
 *
 * @param contextBindings The context FFI bindings.
 * @param contextHandle Opaque context handle from create/join.
 * @param ioDispatcher Dispatcher for FFI calls.
 * @return Cold [Flow] of JSON-encoded messages.
 */
@Suppress("FunctionName")
fun ColdMessageFlow(
    contextBindings: ContextBindings,
    contextHandle: Long,
    ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
): Flow<String> =
    callbackFlow {
        val closed = AtomicBoolean(false)

        val callback =
            object : MessageCallback {
                override fun onMessage(messageJson: String) {
                    if (closed.get()) return
                    val result = trySend(messageJson)
                    if (result.isFailure && !result.isClosed) {
                        close(BridgeException("Message buffer overflow", "SCP-CTX-2001"))
                    }
                }

                override fun onError(
                    code: String,
                    message: String,
                ) {
                    close(BridgeException(message, code))
                }

                override fun onComplete() {
                    close()
                }
            }

        // The handle is recorded inside the NonCancellable block, never taken from
        // withContext's return value: when ioDispatcher differs from the collector's
        // dispatcher, so that withContext resumes the collector by dispatch, a collector
        // cancelled while contextSubscribe runs makes withContext throw on that resumption and
        // drop whatever the block returned, which would leave a live Rust subscription that
        // nothing releases.
        var subscriptionHandle: Long? = null

        // Release the subscription by suspending on ioDispatcher, never by blocking: the
        // finally below runs on the collector's thread, which is an Android main thread under
        // collectAsState (ADR-028's AutoCloseable amendment). NonCancellable
        // lets the release run although the collector was cancelled. A release that throws
        // is logged, never rethrown (sdk-common.md §Cleanup error handling): rethrown from
        // the finally, it would replace the collector's cancellation as the failure and
        // propagate to the collector's parent scope.
        try {
            withContext(NonCancellable + ioDispatcher) {
                subscriptionHandle = contextBindings.contextSubscribe(contextHandle, callback)
            }
            awaitClose()
        } finally {
            closed.set(true)
            val opened = subscriptionHandle
            if (opened != null) {
                withContext(NonCancellable + ioDispatcher) {
                    releaseColdMessageSubscription(contextBindings, opened, contextHandle)
                }
            }
        }
    }

/**
 * Unsubscribe one [ColdMessageFlow] subscription and log its failure instead of throwing it.
 *
 * Catches [Exception], not [Throwable], so an [Error] such as an out-of-memory condition still
 * propagates. The caller runs this under [NonCancellable], so no cancellation of the collector
 * reaches this catch.
 */
@Suppress("TooGenericExceptionCaught")
private fun releaseColdMessageSubscription(
    contextBindings: ContextBindings,
    subscriptionHandle: Long,
    contextHandle: Long,
) {
    try {
        contextBindings.contextUnsubscribe(subscriptionHandle)
    } catch (e: Exception) {
        Logger.getLogger(COLD_MESSAGE_FLOW_LOGGER).log(
            Level.WARNING,
            "ColdMessageFlow: releasing subscription $subscriptionHandle for context handle " +
                "$contextHandle failed; the Rust subscription may stay live",
            e,
        )
    }
}

/** Logger name for [ColdMessageFlow]'s release failures. */
internal const val COLD_MESSAGE_FLOW_LOGGER = "works.limn.scp.stream.ColdMessageFlow"

/**
 * Buffer capacity for hot streams (SharedFlow extraBufferCapacity).
 *
 * Set to 64 to match the callbackFlow Channel.BUFFERED default from ADR-028.
 * For hot streams, this is the extra buffer beyond the replay cache.
 */
private const val BUFFER_CAPACITY = 64
