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
// UniFFI-generated NativeLib.kt does not exist yet — generation requires a compiled
// Rust cdylib (see scripts/generate-uniffi-kotlin.sh and the generateUniffiBindings
// Gradle task). The NativeBindings interface defines a flat-function abstraction layer
// matching the ADR-028 bridge surface. When UniFFI generates the actual bindings into
// internal/NativeLib.kt, the generated code will use opaque Kotlin classes (Identity,
// ContextHandle, etc.) rather than Long handles — a concrete NativeBindings adapter
// must be written to bridge the two calling conventions.
//
// Provenance: ADR-028 (Kotlin SDK), ADR-021 (UniFFI Bridge), SCP-115, SCP-211

package works.limn.scp.bridge

import works.limn.scp.BridgeConnectorBindings
import works.limn.scp.BridgeConnectorBridge
import works.limn.scp.DiscoveryBindings
import works.limn.scp.DiscoveryBridge
import works.limn.scp.IdentityAdvancedBindings
import works.limn.scp.IdentityAdvancedBridge
import works.limn.scp.ProvenanceBindings
import works.limn.scp.ProvenanceBridge
import works.limn.scp.SyncBindings
import works.limn.scp.SyncBridge
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

    fun contextSetEconomicPolicy(
        contextHandle: Long,
        policyJson: String,
    )

    fun contextGetEconomicPolicy(contextHandle: Long): String?
}

/**
 * Native binding functions for membership queries.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched on [Dispatchers.IO].
 */
interface MembershipBindings {
    fun contextMemberCount(contextHandle: Long): Long?

    fun contextIsMember(
        contextHandle: Long,
        did: String,
    ): Boolean

    fun contextMemberDids(contextHandle: Long): List<String>

    fun contextMemberRole(
        contextHandle: Long,
        did: String,
    ): String?
}

/**
 * Native binding functions for governance operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched on [Dispatchers.IO].
 */
interface GovernanceBindings {
    fun governanceExecute(
        contextHandle: Long,
        proposalJson: String,
    ): String

    /** Propose a governance action for voting (#621). */
    fun governancePropose(
        contextHandle: Long,
        proposerDid: String,
        actionJson: String,
    ): String

    /** Approve a pending governance proposal (#621). */
    fun governanceApprove(
        contextHandle: Long,
        voterDid: String,
        proposalIdHex: String,
    ): String

    /** Reject a pending governance proposal (#621). */
    fun governanceReject(
        contextHandle: Long,
        voterDid: String,
        proposalIdHex: String,
    ): String

    /** Withdraw a vote on a pending governance proposal (#621). */
    fun governanceWithdraw(
        contextHandle: Long,
        voterDid: String,
        proposalIdHex: String,
    ): String
}

/**
 * Native binding functions for broadcast operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched on [Dispatchers.IO].
 */
interface BroadcastBindings {
    fun broadcastSubscribe(
        contextHandle: Long,
        subscriberDid: String,
    )

    fun broadcastUnsubscribe(
        contextHandle: Long,
        subscriberDid: String,
        rotateKeys: Boolean,
    )

    fun broadcastPublish(
        contextHandle: Long,
        authorDid: String,
        payload: ByteArray,
    )

    fun broadcastBlockSubscriber(
        contextHandle: Long,
        subscriberDid: String,
        blockerDid: String,
    )

    fun broadcastUnblockSubscriber(
        contextHandle: Long,
        subscriberDid: String,
        unblockerDid: String,
    )

    fun broadcastHandleKeyRequest(
        contextHandle: Long,
        authorDid: String,
        requesterDid: String,
    ): String

    fun broadcastSubscriberCount(contextHandle: Long): Long?

    fun broadcastIsSubscriber(
        contextHandle: Long,
        did: String,
    ): Boolean

    fun broadcastAdmission(contextHandle: Long): String?
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
        token: String,
    )

    fun ucanDelegate(
        contextHandle: Long,
        delegatorDid: String,
        delegateeDid: String,
        parentToken: String,
        capabilitiesJson: String,
    ): String
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

    fun transportDisconnect(transportHandle: Long)
}

/**
 * Composite interface defining the flat-function abstraction over UniFFI native bindings.
 *
 * Each method corresponds to a UniFFI bridge function listed in ADR-028. The actual
 * UniFFI-generated bindings (internal/NativeLib.kt) will expose opaque Kotlin classes
 * (Identity, ContextHandle, UcanToken, TransportManager) with suspend methods, records
 * as data classes, and sealed error hierarchies — not flat functions with Long handles.
 * A concrete adapter implementing this interface must translate between the two styles.
 *
 * Generation: `./gradlew :scp-kt:generateUniffiBindings` or
 * `./scripts/generate-uniffi-kotlin.sh` (requires compiled Rust cdylib).
 *
 * Split into domain sub-interfaces ([IdentityBindings], [ContextBindings],
 * [ToolBindings], [UcanBindings], [InfraBindings]) for modularity.
 */
interface NativeBindings :
    IdentityBindings,
    ContextBindings,
    MembershipBindings,
    GovernanceBindings,
    BroadcastBindings,
    ToolBindings,
    UcanBindings,
    InfraBindings

/**
 * Container for extended operation bindings added post-initial SDK (#421, #426, #428).
 *
 * Kept separate from [NativeBindings] to avoid exceeding the detekt
 * `TooManyFunctions` threshold (30) on the composite interface. Each field
 * is optional — callers provide only the binding implementations available.
 *
 * @property provenance Provenance evaluation, attachment, and chain depth bindings.
 * @property sync Sync/offline classification bindings.
 * @property discovery Address parsing, query creation, and normalization bindings.
 * @property bridgeConnector Bridge connector trust, registration, and shadow bindings.
 * @property identityAdvanced Agent key, migration, and device attestation bindings.
 */
data class ExtendedBindings(
    val provenance: ProvenanceBindings? = null,
    val sync: SyncBindings? = null,
    val discovery: DiscoveryBindings? = null,
    val bridgeConnector: BridgeConnectorBindings? = null,
    val identityAdvanced: IdentityAdvancedBindings? = null,
)

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
 * @param extendedBindings Optional extended bindings for additional operation categories.
 */
class CoroutineBridge(
    private val nativeBindings: NativeBindings,
    internal val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    internal val cpuDispatcher: CoroutineDispatcher = Dispatchers.Default,
    extendedBindings: ExtendedBindings? = null,
) {
    /** Identity operations — all FFI, dispatched on IO. */
    val identity = IdentityBridge(nativeBindings, this)

    /** Context operations — FFI on IO, streaming via callbackFlow. */
    val context = ContextBridge(nativeBindings, this)

    /** Tool operations — FFI on IO. */
    val tools = ToolBridge(nativeBindings, this)

    /** UCAN operations — FFI on IO. */
    val ucan = UcanBridge(nativeBindings, this)

    /** Membership query operations — FFI on IO. */
    val membership = MembershipBridgeOps(nativeBindings, this)

    /** Governance operations — FFI on IO. */
    val governance = GovernanceBridgeOps(nativeBindings, this)

    /** Broadcast operations — FFI on IO. */
    val broadcast = BroadcastBridgeOps(nativeBindings, this)

    /** Event log and transport operations — FFI on IO. */
    val infra = InfraBridge(nativeBindings, this)

    /** Provenance operations — FFI on IO. Null if bindings not provided. */
    val provenance: ProvenanceBridge? =
        extendedBindings?.provenance?.let { ProvenanceBridge(it, this) }

    /** Sync/offline operations — FFI on IO. Null if bindings not provided. */
    val sync: SyncBridge? =
        extendedBindings?.sync?.let { SyncBridge(it, this) }

    /** Discovery operations — FFI on IO. Null if bindings not provided. */
    val discovery: DiscoveryBridge? =
        extendedBindings?.discovery?.let { DiscoveryBridge(it, this) }

    /** Bridge connector operations — FFI on IO. Null if bindings not provided. */
    val bridgeConnector: BridgeConnectorBridge? =
        extendedBindings?.bridgeConnector?.let {
            BridgeConnectorBridge(it, this)
        }

    /** Advanced identity operations — FFI on IO. Null if bindings not provided. */
    val identityAdvanced: IdentityAdvancedBridge? =
        extendedBindings?.identityAdvanced?.let {
            IdentityAdvancedBridge(it, this)
        }

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
     * @param custody Key custody method.
     * @return Opaque identity handle for use in subsequent operations.
     */
    suspend fun create(custody: works.limn.scp.CustodyType): Long =
        bridge.ffiCall { bindings.identityCreate(custody.rawValue) }

    /**
     * Create a new identity with the specified custody method.
     *
     * Overload accepting a raw string for backward compatibility.
     *
     * @param custody Key custody method: "platform", "in_memory", or "software".
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
     * Set the economic policy for a context (§19.3).
     *
     * @param contextHandle Handle from context create or join.
     * @param policyJson JSON-encoded economic policy.
     */
    suspend fun setEconomicPolicy(
        contextHandle: Long,
        policyJson: String,
    ): Unit = bridge.ffiCall { bindings.contextSetEconomicPolicy(contextHandle, policyJson) }

    /**
     * Get the economic policy for a context.
     *
     * @param contextHandle Handle from context create or join.
     * @return JSON-encoded economic policy, or null if none is set.
     */
    suspend fun getEconomicPolicy(contextHandle: Long): String? =
        bridge.ffiCall { bindings.contextGetEconomicPolicy(contextHandle) }

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
     * @param token The full encoded JWT string of the token to revoke.
     */
    suspend fun revoke(
        identityHandle: Long,
        token: String,
    ): Unit = bridge.ffiCall { bindings.ucanRevoke(identityHandle, token) }

    /**
     * Delegate a UCAN token to another entity with attenuated capabilities.
     *
     * Creates a new UCAN derived from a parent token, signed with the delegator's
     * Ed25519 key. Delegation enforces attenuation: capabilities can only narrow,
     * never widen. The delegator must be the audience of the parent token.
     *
     * @param contextHandle Handle from context create or join.
     * @param delegatorDid DID of the entity delegating (must match parent token's audience).
     * @param delegateeDid DID of the entity receiving the delegation.
     * @param parentToken The encoded parent UCAN token (JWT format).
     * @param capabilitiesJson JSON-encoded list of capability URIs to delegate
     *   (must be a subset of parent's capabilities).
     * @return The delegated UCAN token string.
     * @throws BridgeException if delegation fails (e.g., capabilities wider than parent).
     *
     * See ADR-016 criterion 4, spec section 7.2.
     */
    suspend fun delegate(
        contextHandle: Long,
        delegatorDid: String,
        delegateeDid: String,
        parentToken: String,
        capabilitiesJson: String,
    ): String = bridge.ffiCall {
        bindings.ucanDelegate(
            contextHandle,
            delegatorDid,
            delegateeDid,
            parentToken,
            capabilitiesJson,
        )
    }
}

/**
 * Membership query operations bridge. Wraps membership-related FFI calls as suspend functions.
 */
class MembershipBridgeOps internal constructor(
    private val bindings: MembershipBindings,
    private val bridge: CoroutineBridge,
) {
    /**
     * Return the member count for a context.
     *
     * @param contextHandle Handle from context create or join.
     * @return The member count, or null if the context is not registered.
     */
    suspend fun memberCount(contextHandle: Long): Long? =
        bridge.ffiCall { bindings.contextMemberCount(contextHandle) }

    /**
     * Check whether a DID is a member of a context.
     *
     * @param contextHandle Handle from context create or join.
     * @param did The DID to check.
     * @return true if the DID is a member.
     */
    suspend fun isMember(
        contextHandle: Long,
        did: String,
    ): Boolean = bridge.ffiCall { bindings.contextIsMember(contextHandle, did) }

    /**
     * Return all member DIDs in a context.
     *
     * @param contextHandle Handle from context create or join.
     * @return List of DID strings.
     */
    suspend fun memberDids(contextHandle: Long): List<String> =
        bridge.ffiCall { bindings.contextMemberDids(contextHandle) }

    /**
     * Return the role of a member in a context.
     *
     * @param contextHandle Handle from context create or join.
     * @param did The DID of the member.
     * @return The role string, or null if the member is not found.
     */
    suspend fun memberRole(
        contextHandle: Long,
        did: String,
    ): String? = bridge.ffiCall { bindings.contextMemberRole(contextHandle, did) }
}

/**
 * Governance operations bridge. Wraps governance-related FFI calls as suspend functions.
 */
class GovernanceBridgeOps internal constructor(
    private val bindings: GovernanceBindings,
    private val bridge: CoroutineBridge,
) {
    /**
     * Execute a governance action on a context.
     *
     * @param contextHandle Handle from context create.
     * @param proposalJson JSON-encoded governance proposal.
     * @return A string describing the governance action result.
     */
    suspend fun execute(
        contextHandle: Long,
        proposalJson: String,
    ): String = bridge.ffiCall { bindings.governanceExecute(contextHandle, proposalJson) }

    /**
     * Propose a governance action for voting (#621).
     *
     * For `SingleAdmin` contexts, the proposal is auto-approved and executed
     * immediately. For multi-admin models, the proposal enters `Pending` status.
     *
     * @param contextHandle Handle from context create.
     * @param proposerDid DID of the proposer.
     * @param actionJson JSON-serialized governance action.
     * @return JSON string with `proposal_id`, `status`, and `execution_result`.
     */
    suspend fun propose(
        contextHandle: Long,
        proposerDid: String,
        actionJson: String,
    ): String = bridge.ffiCall {
        bindings.governancePropose(contextHandle, proposerDid, actionJson)
    }

    /**
     * Cast an approval vote on a pending governance proposal (#621).
     *
     * @param contextHandle Handle from context create.
     * @param voterDid DID of the voter.
     * @param proposalIdHex Hex-encoded 32-byte proposal ID.
     * @return JSON string with `status`.
     */
    suspend fun approve(
        contextHandle: Long,
        voterDid: String,
        proposalIdHex: String,
    ): String = bridge.ffiCall {
        bindings.governanceApprove(contextHandle, voterDid, proposalIdHex)
    }

    /**
     * Cast a rejection vote on a pending governance proposal (#621).
     *
     * @param contextHandle Handle from context create.
     * @param voterDid DID of the voter.
     * @param proposalIdHex Hex-encoded 32-byte proposal ID.
     * @return JSON string with `status`.
     */
    suspend fun reject(
        contextHandle: Long,
        voterDid: String,
        proposalIdHex: String,
    ): String = bridge.ffiCall {
        bindings.governanceReject(contextHandle, voterDid, proposalIdHex)
    }

    /**
     * Withdraw a previously cast vote on a pending governance proposal (#621).
     *
     * @param contextHandle Handle from context create.
     * @param voterDid DID of the voter.
     * @param proposalIdHex Hex-encoded 32-byte proposal ID.
     * @return JSON string with `status`.
     */
    suspend fun withdraw(
        contextHandle: Long,
        voterDid: String,
        proposalIdHex: String,
    ): String = bridge.ffiCall {
        bindings.governanceWithdraw(contextHandle, voterDid, proposalIdHex)
    }
}

/**
 * Broadcast operations bridge. Wraps broadcast-related FFI calls as suspend functions.
 */
class BroadcastBridgeOps internal constructor(
    private val bindings: BroadcastBindings,
    private val bridge: CoroutineBridge,
) {
    /**
     * Subscribe a DID to a broadcast context.
     *
     * @param contextHandle Handle from context create or join.
     * @param subscriberDid The DID subscribing to broadcasts.
     */
    suspend fun subscribe(
        contextHandle: Long,
        subscriberDid: String,
    ): Unit = bridge.ffiCall { bindings.broadcastSubscribe(contextHandle, subscriberDid) }

    /**
     * Unsubscribe a DID from a broadcast context.
     *
     * @param contextHandle Handle from context create or join.
     * @param subscriberDid The DID to unsubscribe.
     * @param rotateKeys Whether to rotate broadcast keys after unsubscription.
     */
    suspend fun unsubscribe(
        contextHandle: Long,
        subscriberDid: String,
        rotateKeys: Boolean = false,
    ): Unit = bridge.ffiCall {
        bindings.broadcastUnsubscribe(contextHandle, subscriberDid, rotateKeys)
    }

    /**
     * Publish a message to a broadcast context.
     *
     * @param contextHandle Handle from context create or join.
     * @param authorDid The DID of the author publishing the message.
     * @param payload Raw message bytes.
     */
    suspend fun publish(
        contextHandle: Long,
        authorDid: String,
        payload: ByteArray,
    ): Unit = bridge.ffiCall { bindings.broadcastPublish(contextHandle, authorDid, payload) }

    /**
     * Block a subscriber's read access in a broadcast context.
     *
     * @param contextHandle Handle from context create or join.
     * @param subscriberDid The DID of the subscriber to block.
     * @param blockerDid The DID of the blocker.
     */
    suspend fun blockSubscriber(
        contextHandle: Long,
        subscriberDid: String,
        blockerDid: String,
    ): Unit = bridge.ffiCall {
        bindings.broadcastBlockSubscriber(contextHandle, subscriberDid, blockerDid)
    }

    /**
     * Unblock a previously blocked subscriber in a broadcast context (§9.16.8).
     *
     * Forward-only: the unblocked subscriber can request the current key on
     * next pull but cannot decrypt content from the block period.
     *
     * @param contextHandle Handle from context create or join.
     * @param subscriberDid The DID of the subscriber to unblock.
     * @param unblockerDid The DID of the author performing the unblock.
     */
    suspend fun unblockSubscriber(
        contextHandle: Long,
        subscriberDid: String,
        unblockerDid: String,
    ): Unit = bridge.ffiCall {
        bindings.broadcastUnblockSubscriber(contextHandle, subscriberDid, unblockerDid)
    }

    /**
     * Handle a broadcast key request from a subscriber.
     *
     * @param contextHandle Handle from context create or join.
     * @param authorDid The DID of the author handling the request.
     * @param requesterDid The DID of the requester.
     * @return A string describing the key request decision.
     */
    suspend fun handleKeyRequest(
        contextHandle: Long,
        authorDid: String,
        requesterDid: String,
    ): String = bridge.ffiCall {
        bindings.broadcastHandleKeyRequest(contextHandle, authorDid, requesterDid)
    }

    /**
     * Return the number of broadcast subscribers for a context.
     *
     * @param contextHandle Handle from context create or join.
     * @return The subscriber count, or null if not a broadcast context.
     */
    suspend fun subscriberCount(contextHandle: Long): Long? =
        bridge.ffiCall { bindings.broadcastSubscriberCount(contextHandle) }

    /**
     * Check whether a DID is a broadcast subscriber.
     *
     * @param contextHandle Handle from context create or join.
     * @param did The DID to check.
     * @return true if the DID is a subscriber.
     */
    suspend fun isSubscriber(
        contextHandle: Long,
        did: String,
    ): Boolean = bridge.ffiCall { bindings.broadcastIsSubscriber(contextHandle, did) }

    /**
     * Return the broadcast admission policy for a context.
     *
     * @param contextHandle Handle from context create or join.
     * @return The policy string ("Open" or "Gated"), or null if not broadcast.
     */
    suspend fun admission(contextHandle: Long): String? =
        bridge.ffiCall { bindings.broadcastAdmission(contextHandle) }
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

    /**
     * Disconnect from a transport relay.
     *
     * Clears the relay adapter from the transport manager. After this call,
     * the transport reports disconnected status and the WebSocket connection
     * is released.
     *
     * This is idempotent -- calling it when already disconnected is a no-op.
     *
     * @param handle Handle from [transportConnect].
     */
    suspend fun transportDisconnect(handle: Long): Unit = bridge.ffiCall { bindings.transportDisconnect(handle) }
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
