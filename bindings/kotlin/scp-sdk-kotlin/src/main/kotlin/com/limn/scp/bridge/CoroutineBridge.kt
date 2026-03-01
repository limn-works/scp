// CoroutineBridge.kt — Kotlin coroutine bridge over UniFFI-generated bindings (SCP-115)
//
// Wraps all UniFFI-generated sync functions as Kotlin suspend functions with proper
// dispatcher assignment per ADR-028:
//   - All FFI calls (blocking Rust operations) on Dispatchers.IO
//   - CPU-bound operations (data mapping, serialization) on Dispatchers.Default
//   - Coroutine cancellation propagated to Rust via CancellationHandle
//
// This bridge is the single point of FFI dispatch for the Kotlin SDK. Every public
// SDK method (Scp.kt, Context.kt, Identity.kt, etc.) delegates through this bridge
// to exactly one UniFFI function — zero protocol logic lives in the Kotlin layer.
//
// UniFFI-generated NativeLib.kt does not exist yet. The NativeBindings interface
// defines the expected UniFFI function signatures from ADR-028. When UniFFI bindings
// are generated, swap the NativeBindings implementation to delegate to NativeLib.
//
// Provenance: ADR-028 (Kotlin SDK), ADR-021 (UniFFI Bridge), SCP-115

package com.limn.scp.bridge

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.cancellation.CancellationException

/**
 * Handle for propagating coroutine cancellation to long-running Rust operations.
 *
 * When a coroutine is cancelled, the bridge checks [isCancelled] before and after
 * FFI calls. For long-running operations (e.g., transport connect, event log query),
 * the [CancellationHandle] is passed to the Rust side so it can poll for cancellation.
 *
 * Thread-safe: [cancel] can be called from any thread.
 */
class CancellationHandle {
    private val cancelled = AtomicBoolean(false)

    /** Returns true if cancellation has been requested. */
    val isCancelled: Boolean get() = cancelled.get()

    /** Request cancellation. Safe to call multiple times and from any thread. */
    fun cancel() {
        cancelled.set(true)
    }
}

/**
 * Callback interface for streaming message reception from the Rust engine.
 *
 * Mirrors the UniFFI callback interface that the Rust engine invokes when
 * messages arrive on a subscribed context. Used by [CoroutineBridge.contextSubscribe]
 * to bridge callback-driven delivery into a cold [Flow].
 */
interface MessageCallback {
    /** Called when a new message arrives. */
    fun onMessage(messageJson: String)

    /** Called when the subscription encounters an error. */
    fun onError(
        code: String,
        message: String,
    )

    /** Called when the subscription ends (context closed or unsubscribed). */
    fun onComplete()
}

/**
 * Native binding functions for identity operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched on [Dispatchers.IO].
 */
interface IdentityBindings {
    fun identityCreate(custody: String): Long

    fun identityLoad(did: String): Long

    fun identityResolve(did: String): String
}

/**
 * Native binding functions for context operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched on [Dispatchers.IO].
 */
interface ContextBindings {
    fun contextCreate(
        identityHandle: Long,
        paramsJson: String,
    ): Long

    fun contextJoin(
        identityHandle: Long,
        contextId: String,
    ): Long

    fun contextLeave(contextHandle: Long)

    fun contextClose(contextHandle: Long)

    fun contextSend(
        contextHandle: Long,
        payload: ByteArray,
    )

    fun contextSubscribe(
        contextHandle: Long,
        callback: MessageCallback,
    ): Long

    fun contextUnsubscribe(subscriptionHandle: Long)
}

/**
 * Native binding functions for tool operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched on [Dispatchers.IO].
 */
interface ToolBindings {
    fun toolRegister(
        contextHandle: Long,
        definitionJson: String,
    ): String

    fun toolInvoke(
        contextHandle: Long,
        toolId: String,
        inputJson: String,
    ): String

    fun toolVerify(
        toolId: String,
        inputJson: String,
        outputJson: String,
    ): Boolean
}

/**
 * Native binding functions for UCAN operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched on [Dispatchers.IO].
 */
interface UcanBindings {
    fun ucanValidate(
        token: String,
        capability: String,
        contextId: String,
    )

    fun ucanMint(
        identityHandle: Long,
        memberDid: String,
        capabilitiesJson: String,
    ): String

    fun ucanRevoke(
        identityHandle: Long,
        tokenId: String,
    )
}

/**
 * Native binding functions for event log and transport operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched on [Dispatchers.IO].
 */
interface InfraBindings {
    fun eventLogQuery(
        contextId: String,
        filterJson: String,
    ): String

    fun eventLogVerify(
        contextId: String,
        proofJson: String,
    ): Boolean

    fun transportConnect(
        configJson: String,
        cancellationHandle: CancellationHandle?,
    ): Long

    fun transportStatus(transportHandle: Long): String
}

/**
 * Composite interface defining the full set of UniFFI-generated native binding functions.
 *
 * Each method corresponds to a UniFFI bridge function listed in ADR-028.
 * When UniFFI generates `NativeLib.kt`, replace the implementation with delegation
 * to the generated bindings.
 *
 * Split into domain sub-interfaces ([IdentityBindings], [ContextBindings],
 * [ToolBindings], [UcanBindings], [InfraBindings]) for modularity.
 */
interface NativeBindings :
    IdentityBindings,
    ContextBindings,
    ToolBindings,
    UcanBindings,
    InfraBindings

/**
 * Kotlin coroutine bridge over UniFFI-generated native bindings.
 *
 * This is the single dispatcher gateway for all FFI calls in the Kotlin SDK.
 * Every SDK method delegates through this bridge to exactly one UniFFI function,
 * ensuring consistent dispatcher assignment and cancellation propagation.
 *
 * ## Dispatcher strategy (ADR-028)
 *
 * - **[Dispatchers.IO]**: All FFI calls that cross the JNA boundary into Rust.
 *   JNA calls block the calling thread; `Dispatchers.IO` is backed by a thread
 *   pool sized for blocking work, preventing starvation of the coroutine scheduler.
 *
 * - **[Dispatchers.Default]**: CPU-bound operations that do not cross the FFI
 *   boundary (JSON serialization, data mapping, validation). These run on the
 *   default thread pool optimized for CPU-bound work.
 *
 * ## Cancellation
 *
 * Every bridge method checks [ensureActive] before and after the FFI call.
 * For long-running operations, a [CancellationHandle] is propagated to the
 * Rust layer so it can poll for cancellation.
 *
 * ## Error handling
 *
 * FFI errors from the Rust engine are thrown as [BridgeException]. Callers
 * (the ergonomics layer in Scp.kt, Context.kt, etc.) map these to the
 * SDK's public exception hierarchy.
 *
 * @param nativeBindings The UniFFI-generated native bindings (or a test stub).
 * @param ioDispatcher Dispatcher for FFI calls. Defaults to [Dispatchers.IO].
 * @param cpuDispatcher Dispatcher for CPU-bound work. Defaults to [Dispatchers.Default].
 */
class CoroutineBridge(
    private val nativeBindings: NativeBindings,
    internal val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    internal val cpuDispatcher: CoroutineDispatcher = Dispatchers.Default,
) {
    /** Identity operations — all FFI, dispatched on IO. */
    val identity = IdentityBridge(nativeBindings, this)

    /** Context operations — FFI on IO, streaming via callbackFlow. */
    val context = ContextBridge(nativeBindings, this)

    /** Tool operations — FFI on IO. */
    val tools = ToolBridge(nativeBindings, this)

    /** UCAN operations — FFI on IO. */
    val ucan = UcanBridge(nativeBindings, this)

    /** Event log and transport operations — FFI on IO. */
    val infra = InfraBridge(nativeBindings, this)

    /**
     * Execute a CPU-bound operation on [Dispatchers.Default].
     *
     * Use for data mapping, serialization, and validation that does not
     * cross the FFI boundary.
     *
     * @param block The CPU-bound computation.
     * @return The computation result.
     */
    suspend fun <T> cpuBound(block: () -> T): T =
        withContext(cpuDispatcher) {
            ensureActive()
            block()
        }

    /**
     * Execute a blocking FFI call on [Dispatchers.IO] with cancellation checks.
     *
     * Checks [ensureActive] before the FFI call to fail fast if the coroutine
     * is already cancelled. Checks again after the call to propagate cancellation
     * that occurred during the blocking operation.
     *
     * @param block The blocking FFI operation.
     * @return The FFI call result.
     * @throws CancellationException if the coroutine was cancelled.
     * @throws BridgeException if the FFI call fails.
     */
    internal suspend fun <T> ffiCall(block: () -> T): T =
        withContext(ioDispatcher) {
            ensureActive()
            val result = block()
            ensureActive()
            result
        }

    /**
     * Execute a long-running FFI call with a [CancellationHandle] linked to the
     * coroutine's lifecycle.
     *
     * If the coroutine is cancelled during the FFI call, the [CancellationHandle]
     * is triggered so the Rust engine can abort the operation.
     *
     * @param cancellationHandle Handle to propagate cancellation to Rust.
     * @param block The blocking FFI operation.
     * @return The FFI call result.
     * @throws CancellationException if the coroutine was cancelled.
     * @throws BridgeException if the FFI call fails.
     */
    internal suspend fun <T> ffiCallWithCancellation(
        cancellationHandle: CancellationHandle,
        block: () -> T,
    ): T =
        withContext(ioDispatcher) {
            ensureActive()
            try {
                block()
            } finally {
                if (!isActive) {
                    cancellationHandle.cancel()
                }
            }
        }
}

/**
 * Identity operations bridge. Wraps identity-related FFI calls as suspend functions.
 */
class IdentityBridge internal constructor(
    private val bindings: IdentityBindings,
    private val bridge: CoroutineBridge,
) {
    /**
     * Create a new identity with the specified custody method.
     *
     * @param custody Key custody method: "platform" or "in_memory".
     * @return Opaque identity handle for use in subsequent operations.
     */
    suspend fun create(custody: String): Long = bridge.ffiCall { bindings.identityCreate(custody) }

    /**
     * Load an existing identity from storage by DID.
     *
     * @param did The DID string to load (e.g., "did:dht:...").
     * @return Opaque identity handle.
     */
    suspend fun load(did: String): Long = bridge.ffiCall { bindings.identityLoad(did) }

    /**
     * Resolve a DID document for the given DID.
     *
     * @param did The DID to resolve.
     * @return JSON-encoded DID document.
     */
    suspend fun resolve(did: String): String = bridge.ffiCall { bindings.identityResolve(did) }
}

/**
 * Context operations bridge. Wraps context-related FFI calls as suspend functions
 * and provides [Flow]-based streaming via [callbackFlow].
 */
class ContextBridge internal constructor(
    private val bindings: ContextBindings,
    private val bridge: CoroutineBridge,
) {
    /**
     * Create a new context.
     *
     * @param identityHandle Handle from identity create or load.
     * @param paramsJson JSON-encoded context parameters.
     * @return Opaque context handle.
     */
    suspend fun create(
        identityHandle: Long,
        paramsJson: String,
    ): Long = bridge.ffiCall { bindings.contextCreate(identityHandle, paramsJson) }

    /**
     * Join an existing context by ID.
     *
     * @param identityHandle Handle from identity create or load.
     * @param contextId The context ID to join.
     * @return Opaque context handle.
     */
    suspend fun join(
        identityHandle: Long,
        contextId: String,
    ): Long = bridge.ffiCall { bindings.contextJoin(identityHandle, contextId) }

    /**
     * Leave a context gracefully (member action).
     *
     * @param contextHandle Handle from context create or join.
     */
    suspend fun leave(contextHandle: Long): Unit = bridge.ffiCall { bindings.contextLeave(contextHandle) }

    /**
     * Close a context (admin action). Terminates the context for all members.
     *
     * @param contextHandle Handle from context create.
     */
    suspend fun close(contextHandle: Long): Unit = bridge.ffiCall { bindings.contextClose(contextHandle) }

    /**
     * Send a message to a context.
     *
     * @param contextHandle Handle from context create or join.
     * @param payload Raw message bytes.
     */
    suspend fun send(
        contextHandle: Long,
        payload: ByteArray,
    ): Unit = bridge.ffiCall { bindings.contextSend(contextHandle, payload) }

    /**
     * Subscribe to incoming messages on a context as a cold [Flow].
     *
     * Collection begins the UniFFI subscription; cancellation ends it.
     * Uses [callbackFlow] with [Channel.BUFFERED] capacity (64 items) to
     * absorb burst delivery from the Rust engine without dropping messages.
     *
     * Per ADR-028: `callbackFlow` is the streaming primitive for message
     * reception. Cold stream semantics: the subscription starts when the
     * flow is collected and stops when the collector cancels.
     *
     * @param contextHandle Handle from context create or join.
     * @return Cold [Flow] of JSON-encoded messages.
     */
    fun subscribe(contextHandle: Long): Flow<String> =
        callbackFlow {
            val callback =
                object : MessageCallback {
                    override fun onMessage(messageJson: String) {
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

            // Subscribe on IO dispatcher since it crosses the FFI boundary.
            val subscriptionHandle =
                withContext(bridge.ioDispatcher) {
                    bindings.contextSubscribe(contextHandle, callback)
                }

            awaitClose {
                // Use Dispatchers.IO directly — NOT bridge.ioDispatcher — because
                // awaitClose is a non-suspend lambda that blocks its thread via
                // runBlocking. If bridge.ioDispatcher is a single-threaded test
                // dispatcher, runBlocking would deadlock (blocking the only thread
                // that the dispatcher can schedule work on). Dispatchers.IO is an
                // unbounded thread pool that always has capacity.
                runBlocking(kotlinx.coroutines.Dispatchers.IO) {
                    bindings.contextUnsubscribe(subscriptionHandle)
                }
            }
        }
}

/**
 * Tool operations bridge. Wraps tool-related FFI calls as suspend functions.
 */
class ToolBridge internal constructor(
    private val bindings: ToolBindings,
    private val bridge: CoroutineBridge,
) {
    /**
     * Register a tool in a context.
     *
     * @param contextHandle Handle from context create or join.
     * @param definitionJson JSON-encoded tool definition.
     * @return The assigned tool ID.
     */
    suspend fun register(
        contextHandle: Long,
        definitionJson: String,
    ): String = bridge.ffiCall { bindings.toolRegister(contextHandle, definitionJson) }

    /**
     * Invoke a registered tool in a context.
     *
     * @param contextHandle Handle from context create or join.
     * @param toolId The tool's assigned ID.
     * @param inputJson JSON-encoded tool input.
     * @return JSON-encoded tool output.
     */
    suspend fun invoke(
        contextHandle: Long,
        toolId: String,
        inputJson: String,
    ): String = bridge.ffiCall { bindings.toolInvoke(contextHandle, toolId, inputJson) }

    /**
     * Verify a tool invocation's input/output pair.
     *
     * @param toolId The tool's ID.
     * @param inputJson JSON-encoded tool input.
     * @param outputJson JSON-encoded tool output.
     * @return true if the verification passes.
     */
    suspend fun verify(
        toolId: String,
        inputJson: String,
        outputJson: String,
    ): Boolean = bridge.ffiCall { bindings.toolVerify(toolId, inputJson, outputJson) }
}

/**
 * UCAN operations bridge. Wraps UCAN-related FFI calls as suspend functions.
 */
class UcanBridge internal constructor(
    private val bindings: UcanBindings,
    private val bridge: CoroutineBridge,
) {
    /**
     * Validate a UCAN token for a capability in a context.
     *
     * @param token The UCAN token string.
     * @param capability The capability to validate.
     * @param contextId The context ID.
     * @throws BridgeException if validation fails.
     */
    suspend fun validate(
        token: String,
        capability: String,
        contextId: String,
    ): Unit = bridge.ffiCall { bindings.ucanValidate(token, capability, contextId) }

    /**
     * Mint a UCAN token delegating capabilities to a member DID.
     *
     * @param identityHandle Handle from identity create or load.
     * @param memberDid The DID to delegate capabilities to.
     * @param capabilitiesJson JSON-encoded list of capabilities.
     * @return The minted UCAN token string.
     */
    suspend fun mint(
        identityHandle: Long,
        memberDid: String,
        capabilitiesJson: String,
    ): String = bridge.ffiCall { bindings.ucanMint(identityHandle, memberDid, capabilitiesJson) }

    /**
     * Revoke a previously minted UCAN token.
     *
     * @param identityHandle Handle from identity create or load.
     * @param tokenId The token ID to revoke.
     */
    suspend fun revoke(
        identityHandle: Long,
        tokenId: String,
    ): Unit = bridge.ffiCall { bindings.ucanRevoke(identityHandle, tokenId) }
}

/**
 * Event log and transport operations bridge. Wraps infrastructure FFI calls
 * as suspend functions, with cancellation support for long-running transport operations.
 */
class InfraBridge internal constructor(
    private val bindings: InfraBindings,
    private val bridge: CoroutineBridge,
) {
    /**
     * Query the event log for a context.
     *
     * @param contextId The context ID to query.
     * @param filterJson JSON-encoded query filter.
     * @return JSON-encoded event log entries.
     */
    suspend fun eventLogQuery(
        contextId: String,
        filterJson: String,
    ): String = bridge.ffiCall { bindings.eventLogQuery(contextId, filterJson) }

    /**
     * Verify an event log proof.
     *
     * @param contextId The context ID.
     * @param proofJson JSON-encoded proof to verify.
     * @return true if the proof is valid.
     */
    suspend fun eventLogVerify(
        contextId: String,
        proofJson: String,
    ): Boolean = bridge.ffiCall { bindings.eventLogVerify(contextId, proofJson) }

    /**
     * Connect to a transport relay.
     *
     * This is a potentially long-running operation. A [CancellationHandle] is
     * created and linked to the coroutine's cancellation so that the Rust
     * engine can poll for cancellation during connection establishment.
     *
     * @param configJson JSON-encoded transport configuration.
     * @return Opaque transport handle.
     */
    suspend fun transportConnect(configJson: String): Long {
        val cancellationHandle = CancellationHandle()
        return bridge.ffiCallWithCancellation(cancellationHandle) {
            bindings.transportConnect(configJson, cancellationHandle)
        }
    }

    /**
     * Query the status of a transport connection.
     *
     * @param transportHandle Handle from [transportConnect].
     * @return JSON-encoded transport status.
     */
    suspend fun transportStatus(handle: Long): String = bridge.ffiCall { bindings.transportStatus(handle) }
}

/**
 * Exception thrown by the coroutine bridge when an FFI call fails.
 *
 * Carries a structured error code from the Rust engine (e.g., "SCP-CTX-2001").
 * The ergonomics layer maps this to the SDK's public exception hierarchy.
 *
 * @property code Structured SCP error code.
 */
class BridgeException(
    message: String,
    val code: String,
) : Exception(message)
