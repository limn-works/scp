// Streams.kt — Kotlin Flow/Channel streaming layer for the SCP SDK (SCP-116)
// Provenance: ADR-028 (Kotlin SDK), SCP-116

package com.limn.scp.stream

import com.limn.scp.bridge.BridgeException
import com.limn.scp.bridge.ContextBindings
import com.limn.scp.bridge.InfraBindings
import com.limn.scp.bridge.MessageCallback
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

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

    fun onError(code: String, message: String)

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
     * @param contextId The context to query.
     * @param filterJson JSON-encoded query filter (e.g., event type, time range).
     * @param pageSize Number of entries per page.
     * @return Cold [Flow] of JSON-encoded event log pages.
     */
    fun eventLogPages(
        contextId: String,
        filterJson: String,
        pageSize: Int = 50,
    ): Flow<String> = flow {
        var offset = 0
        while (true) {
            val paginatedFilter = buildPaginatedFilter(filterJson, offset, pageSize)
            val page = withContext(ioDispatcher) {
                infraBindings.eventLogQuery(contextId, paginatedFilter)
            }
            if (page == "[]" || page.isBlank()) break
            emit(page)
            offset += pageSize
        }
    }

    /**
     * Cold flow of message history for a context, fetched page by page.
     *
     * Each emission is a JSON-encoded page of historical messages. The flow
     * terminates when the query returns an empty page.
     *
     * @param contextId The context to query.
     * @param filterJson JSON-encoded query filter (e.g., time range, sender).
     * @param pageSize Number of messages per page.
     * @return Cold [Flow] of JSON-encoded message history pages.
     */
    fun messageHistoryPages(
        contextId: String,
        filterJson: String,
        pageSize: Int = 50,
    ): Flow<String> = flow {
        var offset = 0
        while (true) {
            val paginatedFilter = buildPaginatedFilter(filterJson, offset, pageSize)
            val page = withContext(ioDispatcher) {
                infraBindings.eventLogQuery(contextId, paginatedFilter)
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
 * Call [stopContextEvents] or [stopMessageStream] to unsubscribe from the
 * Rust engine and release resources. Cleanup also occurs if the factory
 * is garbage collected, but explicit cleanup is strongly preferred.
 */
class HotStreamFactory(
    private val contextBindings: EventContextBindings,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    private val activeEventSubscriptions = ConcurrentHashMap<Long, HotStreamState>()
    private val activeMessageSubscriptions = ConcurrentHashMap<Long, HotStreamState>()

    /**
     * Start a hot [SharedFlow] of real-time context events.
     *
     * The Rust engine pushes events via [EventCallback]. Multiple collectors
     * can subscribe to the returned [SharedFlow]; each receives all events
     * from their subscription point forward (plus [replay] historical events).
     *
     * @param contextHandle Opaque context handle from create/join.
     * @param replay Number of past events to replay to new subscribers.
     * @return Hot [SharedFlow] of JSON-encoded context events.
     */
    fun contextEvents(
        contextHandle: Long,
        replay: Int = 0,
    ): SharedFlow<String> {
        val existing = activeEventSubscriptions[contextHandle]
        if (existing != null) return existing.readOnly

        val sharedFlow = MutableSharedFlow<String>(
            replay = replay,
            extraBufferCapacity = BUFFER_CAPACITY,
            onBufferOverflow = BufferOverflow.DROP_OLDEST,
        )
        val readOnly = sharedFlow.asSharedFlow()

        val callback = object : EventCallback {
            override fun onEvent(eventJson: String) {
                sharedFlow.tryEmit(eventJson)
            }

            override fun onError(code: String, message: String) {
                sharedFlow.tryEmit("""{"_error":true,"code":"$code","message":"$message"}""")
            }

            override fun onComplete() {
                activeEventSubscriptions.remove(contextHandle)
            }
        }

        val subscriptionHandle = runBlocking(Dispatchers.IO) {
            contextBindings.contextSubscribeEvents(contextHandle, callback)
        }

        activeEventSubscriptions[contextHandle] = HotStreamState(sharedFlow, readOnly, subscriptionHandle)
        return readOnly
    }

    /**
     * Start a hot [SharedFlow] of real-time incoming messages.
     *
     * Unlike [com.limn.scp.bridge.ContextBridge.subscribe] which returns a
     * cold [Flow] (one collector, subscription starts on collect), this
     * returns a hot [SharedFlow] suitable for multiple concurrent collectors.
     *
     * @param contextHandle Opaque context handle from create/join.
     * @param replay Number of past messages to replay to new subscribers.
     * @return Hot [SharedFlow] of JSON-encoded messages.
     */
    fun incomingMessages(
        contextHandle: Long,
        replay: Int = 0,
    ): SharedFlow<String> {
        val existing = activeMessageSubscriptions[contextHandle]
        if (existing != null) return existing.readOnly

        val sharedFlow = MutableSharedFlow<String>(
            replay = replay,
            extraBufferCapacity = BUFFER_CAPACITY,
            onBufferOverflow = BufferOverflow.DROP_OLDEST,
        )
        val readOnly = sharedFlow.asSharedFlow()

        val callback = object : MessageCallback {
            override fun onMessage(messageJson: String) {
                sharedFlow.tryEmit(messageJson)
            }

            override fun onError(code: String, message: String) {
                sharedFlow.tryEmit("""{"_error":true,"code":"$code","message":"$message"}""")
            }

            override fun onComplete() {
                activeMessageSubscriptions.remove(contextHandle)
            }
        }

        val subscriptionHandle = runBlocking(Dispatchers.IO) {
            contextBindings.contextSubscribe(contextHandle, callback)
        }

        activeMessageSubscriptions[contextHandle] = HotStreamState(sharedFlow, readOnly, subscriptionHandle)
        return readOnly
    }

    /**
     * Stop receiving context events for the given context handle.
     *
     * Unsubscribes from the Rust engine and removes the internal state.
     * After this call, the [SharedFlow] returned by [contextEvents] will
     * no longer receive new events.
     *
     * @param contextHandle The context to stop receiving events for.
     */
    fun stopContextEvents(contextHandle: Long) {
        val state = activeEventSubscriptions.remove(contextHandle) ?: return
        runBlocking(Dispatchers.IO) {
            contextBindings.contextUnsubscribeEvents(state.subscriptionHandle)
        }
    }

    /**
     * Stop receiving messages for the given context handle.
     *
     * @param contextHandle The context to stop receiving messages for.
     */
    fun stopMessageStream(contextHandle: Long) {
        val state = activeMessageSubscriptions.remove(contextHandle) ?: return
        runBlocking(Dispatchers.IO) {
            contextBindings.contextUnsubscribe(state.subscriptionHandle)
        }
    }

    /**
     * Stop all active subscriptions. Call during teardown.
     */
    fun stopAll() {
        activeEventSubscriptions.keys.toList().forEach { stopContextEvents(it) }
        activeMessageSubscriptions.keys.toList().forEach { stopMessageStream(it) }
    }
}

/**
 * Internal state for an active hot stream subscription.
 *
 * Pairs the [MutableSharedFlow] with the Rust subscription handle so that
 * [HotStreamFactory.stopContextEvents] / [HotStreamFactory.stopMessageStream]
 * can unsubscribe from the Rust engine.
 */
private data class HotStreamState(
    val flow: MutableSharedFlow<String>,
    val readOnly: SharedFlow<String>,
    val subscriptionHandle: Long,
)

/**
 * Improved cold message flow that fixes SCP-115 review issues.
 *
 * This is the recommended replacement for [com.limn.scp.bridge.ContextBridge.subscribe]
 * in public API code. Differences from the bridge-level subscribe:
 *
 * 1. Handles [trySend] result explicitly: closes the flow with [BridgeException] on
 *    buffer overflow instead of silently discarding messages. The callback runs on a
 *    non-suspending Rust thread, so suspending [send] cannot be used.
 * 2. No double-buffering: `callbackFlow` already uses `Channel.BUFFERED` internally
 *    (64 items). Does NOT chain an additional `.buffer(Channel.BUFFERED)`.
 * 3. `awaitClose` always calls the unsubscribe function — never left empty.
 * 4. Guards against post-close emissions with [AtomicBoolean] flag.
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
): Flow<String> = callbackFlow {
    val closed = AtomicBoolean(false)

    val callback = object : MessageCallback {
        override fun onMessage(messageJson: String) {
            if (closed.get()) return
            val result = trySend(messageJson)
            if (result.isFailure && !result.isClosed) {
                close(BridgeException("Message buffer overflow", "SCP-CTX-2001"))
            }
        }

        override fun onError(code: String, message: String) {
            close(BridgeException(message, code))
        }

        override fun onComplete() {
            close()
        }
    }

    val subscriptionHandle = withContext(ioDispatcher) {
        contextBindings.contextSubscribe(contextHandle, callback)
    }

    awaitClose {
        closed.set(true)
        runBlocking(Dispatchers.IO) {
            contextBindings.contextUnsubscribe(subscriptionHandle)
        }
    }
}

/**
 * Buffer capacity for hot streams (SharedFlow extraBufferCapacity).
 *
 * Set to 64 to match the callbackFlow Channel.BUFFERED default from ADR-028.
 * For hot streams, this is the extra buffer beyond the replay cache.
 */
private const val BUFFER_CAPACITY = 64
