// Scp.kt — Kotlin SDK caller-owned SCP instance wrapper (#1549 Phase 4, ADR-048).
//
// Each [SCP] wraps an independent UniFFI `Scp` opaque object (generated from
// `crates/scp-ffi/uniffi/src/scp.rs`). The class owns its own
// `UniffiBridgeInstance` — registries, transport, context manager — and is
// the SDK entry point for every caller: multi-identity apps, per-tenant
// services, and parallel-safe tests. The free-function façade
// (`suspend(bridge, bindings)`, `resume(bridge, bindings)`, and the
// singleton-delegating top-level `suspend fun`s in the other modules) was
// deleted in Phase 4 PR 4 (demolition) — callers MUST construct an [SCP]
// explicitly.
//
// REGENERATION REQUIRED: The UniFFI-generated Kotlin bindings (`internal/`)
// are gitignored and regenerated at build time via
// `scripts/generate-uniffi-kotlin.sh` / `./gradlew :scp-kt:generateUniffiBindings`.
// The regenerated bindings include the `uniffi.scp.Scp` class, which this
// wrapper imports. In worktrees without the regenerated bindings, `./gradlew
// assembleRelease` fails at the `import uniffi.scp.Scp` line — this is
// expected; run `./gradlew generateUniffiBindings` first.
//
// Provenance: #1549, ADR-048, master plan decision 4 (SDK-facing class name).

@file:Suppress("MatchingDeclarationName", "TooManyFunctions")

package works.limn.scp

import uniffi.scp.AssetEntry
import uniffi.scp.AttestationVerificationResult
import uniffi.scp.BatchPublishResult
import uniffi.scp.BridgeCredentialResult
import uniffi.scp.ChallengeResult
import uniffi.scp.Checkpoint
import uniffi.scp.ContextHandle
import uniffi.scp.ContextParams
import uniffi.scp.DidDocument
import uniffi.scp.Event
import uniffi.scp.Identity
import uniffi.scp.KeyCustodyProvider
import uniffi.scp.McpAllowlistState
import uniffi.scp.McpInvokeResult
import uniffi.scp.McpServerConfig
import uniffi.scp.McpToolInfo
import uniffi.scp.MessageListener
import uniffi.scp.Proof
import uniffi.scp.PublishResult
import uniffi.scp.ReconnectReport
import uniffi.scp.SagaResult
import uniffi.scp.SqliteKeyMaterial
import uniffi.scp.StorageConfig
import uniffi.scp.SyncPolicyResult
import uniffi.scp.ToolDefinition
import uniffi.scp.ToolVerificationResult
import uniffi.scp.TransportManager
import uniffi.scp.TransportStatus
import uniffi.scp.TrustScoreResult
import uniffi.scp.UcanToken
import works.limn.scp.bridge.CoroutineBridge
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import java.util.logging.Level
import java.util.logging.Logger
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import uniffi.scp.Scp as NativeScp

/**
 * Caller-owned SCP instance — the SDK entry point.
 *
 * Each [SCP] wraps an independent UniFFI `Scp` opaque object. Handles
 * minted by one instance are rejected by others via `HandleAffinityError`
 * at the FFI boundary.
 *
 * ```kotlin
 * // Storage selection is required — there is no default (spec §17.6).
 * val scp = SCP(StorageConfig.InMemory)
 *
 * // Graceful shutdown with a 1-second deadline for in-flight tasks.
 * val bridge = CoroutineBridge(...)
 * scp.shutdown(bridge, timeout = 1.seconds)
 * ```
 *
 * Not [AutoCloseable]: shutdown is a `suspend` function that drives an
 * async FFI deadline and requires a [CoroutineBridge]. A synchronous
 * `close()` cannot honor the timeout and would silently swallow it —
 * callers must invoke [shutdown] explicitly from a coroutine scope.
 *
 * After Phase 4 PR 4 (demolition) there is no `SCP.default()` — every
 * caller must construct `SCP()` explicitly. See ADR-048.
 *
 * @see works.limn.scp.bridge.CoroutineBridge
 */
@Suppress("TooManyFunctions", "LargeClass")
class SCP internal constructor(
    internal val inner: NativeScp,
) {
    /**
     * Tracks whether [shutdown] has completed successfully. Read from the
     * finalizer fallback to decide whether to emit a "leaked without
     * shutdown" warning; written inside [shutdown] after the FFI call
     * returns. Must be atomic because finalizers run on a JVM-internal
     * thread pool that does not happen-before the coroutine that invoked
     * [shutdown].
     */
    private val isShutdown: AtomicBoolean = AtomicBoolean(false)

    /**
     * Constructs a fresh [SCP] with an explicit storage configuration.
     *
     * Storage selection is MANDATORY (spec §17.6): `storage` is a required
     * argument — there is no zero-argument constructor and no default
     * backend. Pass [StorageConfig.InMemory] for development/test or
     * [StorageConfig.Sqlite] for production (use [withSqlite] for the
     * common on-disk case).
     *
     * @param storage Storage configuration. Required — no default.
     */
    constructor(storage: StorageConfig) : this(NativeScp.withStorage(storage))

    /**
     * The monotonic identifier for this bridge instance, unique per
     * process. Used by the FFI handle-affinity check.
     */
    val instanceId: ULong
        get() = inner.instanceId()

    /**
     * Suspends this bridge instance (mobile/desktop backgrounding).
     *
     * Disconnects transport and flushes context snapshots.
     * Transport-dependent operations fail until [resume] is called.
     *
     * Dispatched on [kotlinx.coroutines.Dispatchers.IO] via the supplied
     * [CoroutineBridge].
     *
     * Named [suspendInstance] (not `suspend`) because `suspend` is a soft
     * Kotlin keyword that shadows the coroutine modifier in IDE refactors,
     * documentation generators, and code-gen consumers (#1693).
     *
     * @throws uniffi.scp.ScpException.Transport if the transport lock is poisoned.
     */
    suspend fun suspendInstance(bridge: CoroutineBridge) {
        bridge.ffiCall { inner.suspend() }
    }

    /**
     * Resumes a suspended bridge instance.
     *
     * Clears the suspended flag, then reconnects transport against pending
     * relay URLs and restores persisted contexts via the
     * [`BridgeInstanceCore::resume`](https://docs.rs/scp-ffi-common) override.
     * Routed through [CoroutineBridge.ffiCallSuspend] because UniFFI generates
     * `Scp.resume()` as a Kotlin `suspend fun` — the non-suspend [ffiCall]
     * lambda would reject the call.
     *
     * @throws uniffi.scp.ScpException.Context if the instance has been
     *   permanently shut down.
     */
    suspend fun resume(bridge: CoroutineBridge) {
        bridge.ffiCallSuspend { inner.resume() }
    }

    /**
     * Shuts down this instance with a graceful deadline.
     *
     * Awaits in-flight tasks up to [timeout], aborts any remaining
     * tasks, then runs typed-field cleanup. A second call is a no-op
     * (AlreadyShutDown is swallowed at the SDK surface).
     *
     * Converted to unsigned milliseconds for the UniFFI boundary after
     * the #1549 Phase 4 timeout unit unification — sub-millisecond
     * precision is not preserved. Negative durations are clamped to
     * zero.
     *
     * [timeout] defaults to 5 seconds — the same default the PyO3 and
     * NAPI SDK wrappers carry. Callers that need an explicit deadline
     * (e.g. abort immediately with `Duration.ZERO`, or wait
     * effectively-forever with a large `Duration.ofHours(n)`) pass the
     * argument explicitly. See PR #1690 retro api-design MODERATE.
     *
     * @param timeout Maximum duration to wait for in-flight tasks.
     *   Defaults to 5 seconds.
     */
    suspend fun shutdown(
        bridge: CoroutineBridge,
        timeout: Duration = 5.seconds,
    ) {
        val millis = timeout.inWholeMilliseconds.coerceAtLeast(0).toULong()
        bridge.ffiCallSuspend { inner.shutdown(timeoutMillis = millis) }
        // Record shutdown AFTER the FFI call returns so that a failed
        // shutdown does not silence the finalizer warning — a caller
        // who sees an exception here should know the instance is still
        // live and still worth a second [shutdown] attempt. SetRelease
        // orders the flip after the FFI mutation, matching Atomic default.
        isShutdown.set(true)
    }

    /**
     * Finalizer fallback: warns if the JVM garbage-collects an [SCP]
     * that was never [shutdown]. Callers MUST invoke [shutdown]
     * explicitly — the underlying `JoinSet` on the Rust side aborts
     * abruptly (not gracefully) when the opaque UniFFI handle is
     * dropped, so subscriptions and in-flight governance tasks lose
     * their chance to exit cleanly.
     *
     * Kotlin's `finalize()` is deprecated in favor of
     * `java.lang.ref.Cleaner` (JDK 9+), but Cleaner adds ceremony
     * (companion-hosted cleanup action, shared-executor, capturing
     * references carefully to avoid resurrection). For a simple
     * best-effort warning — where timing and ordering don't matter
     * because the Rust side does its own teardown on Drop — the
     * finalizer is sufficient and self-contained. When the JVM
     * finalizer is removed in a future release we will migrate to
     * Cleaner; the contract is unchanged.
     *
     * This is not a substitute for explicit shutdown. The Rust side
     * still tears down its `JoinSet` via Drop; the warning just makes
     * the resource leak visible to the developer.
     */
    @Suppress("ProtectedMemberInFinalClass", "Unused")
    protected fun finalize() {
        if (!isShutdown.get()) {
            Logger.getLogger("works.limn.scp.SCP").log(
                Level.WARNING,
                "SCP instance (id={0}) was garbage-collected without a shutdown() call. " +
                    "In-flight tasks (subscriptions, governance timeouts) were aborted " +
                    "abruptly instead of draining gracefully. Always call SCP.shutdown() " +
                    "explicitly — for example from a coroutine scope: " +
                    "`scope.launch { scp.shutdown(bridge, 5.seconds) }`.",
                arrayOf<Any>(instanceId),
            )
        }
    }

    // ─── Bridge method forwarding (ADR-048 PR 4 — demolition Phase C) ───
    //
    // Every UniFFI `Scp` method is forwarded through the `inner` handle so
    // that callers write `scp.identityCreate(...)` as an idiomatic Kotlin
    // method call. No state is shared with any other [SCP] instance.
    //
    // UniFFI generates `suspend fun` for Rust `async fn` methods (dispatched
    // on the shared tokio runtime internally), and blocking `fun` for
    // synchronous Rust methods. Callers that need to dispatch the blocking
    // forwarders off the calling thread should wrap with
    // `withContext(Dispatchers.IO)` — mirroring the Swift SDK, the SCP class
    // does not inject a dispatcher around inner calls.

    /** Forwards to [NativeScp.accessKeyGenerate] on [inner]. */
    suspend fun accessKeyGenerate(
        contextId: String,
        memberDid: String,
        callerDid: String,
    ) = inner.accessKeyGenerate(
        contextId = contextId,
        memberDid = memberDid,
        callerDid = callerDid,
    )

    /** Forwards to [NativeScp.accessKeyRestore] on [inner]. */
    suspend fun accessKeyRestore(
        contextId: String,
        memberDid: String,
        callerDid: String,
    ) = inner.accessKeyRestore(
        contextId = contextId,
        memberDid = memberDid,
        callerDid = callerDid,
    )

    /** Forwards to [NativeScp.accessKeyRevoke] on [inner]. */
    suspend fun accessKeyRevoke(
        contextId: String,
        memberDid: String,
        callerDid: String,
    ) = inner.accessKeyRevoke(
        contextId = contextId,
        memberDid = memberDid,
        callerDid = callerDid,
    )

    // Bridge credential store (spec §12.11). Per-instance credential store
    // ops; each forwards to [inner]. Credentials live in THIS instance's
    // store (ADR-048 §1). The encrypted bytes never cross the FFI boundary;
    // only metadata is returned for provision/rotate.

    /** Forwards to [NativeScp.bridgeCredentialProvision] on [inner]. */
    suspend fun bridgeCredentialProvision(
        bridgeId: String,
        credentialType: String,
        plaintext: ByteArray,
        bridgeCredentialKey: ByteArray,
    ): BridgeCredentialResult =
        inner.bridgeCredentialProvision(
            bridgeId = bridgeId,
            credentialType = credentialType,
            plaintext = plaintext,
            bridgeCredentialKey = bridgeCredentialKey,
        )

    /** Forwards to [NativeScp.bridgeCredentialRetrieve] on [inner]. */
    suspend fun bridgeCredentialRetrieve(
        bridgeId: String,
        credentialType: String,
        bridgeCredentialKey: ByteArray,
    ): ByteArray =
        inner.bridgeCredentialRetrieve(
            bridgeId = bridgeId,
            credentialType = credentialType,
            bridgeCredentialKey = bridgeCredentialKey,
        )

    /** Forwards to [NativeScp.bridgeCredentialRotate] on [inner]. */
    suspend fun bridgeCredentialRotate(
        bridgeId: String,
        credentialType: String,
        newPlaintext: ByteArray,
        bridgeCredentialKey: ByteArray,
    ): BridgeCredentialResult =
        inner.bridgeCredentialRotate(
            bridgeId = bridgeId,
            credentialType = credentialType,
            newPlaintext = newPlaintext,
            bridgeCredentialKey = bridgeCredentialKey,
        )

    /** Forwards to [NativeScp.bridgeCredentialRevoke] on [inner]. */
    suspend fun bridgeCredentialRevoke(bridgeId: String) = inner.bridgeCredentialRevoke(bridgeId = bridgeId)

    /** Forwards to [NativeScp.bridgeCredentialList] on [inner]. */
    suspend fun bridgeCredentialList(bridgeId: String): List<String> = inner.bridgeCredentialList(bridgeId = bridgeId)

    /** Forwards to [NativeScp.bridgeCredentialStoreKey] on [inner]. */
    suspend fun bridgeCredentialStoreKey(
        bridgeId: String,
        key: ByteArray,
    ) = inner.bridgeCredentialStoreKey(bridgeId = bridgeId, key = key)

    /** Forwards to [NativeScp.bridgeCredentialGetKey] on [inner]. */
    suspend fun bridgeCredentialGetKey(bridgeId: String): ByteArray = inner.bridgeCredentialGetKey(bridgeId = bridgeId)

    /** Forwards to [NativeScp.bridgeCredentialDeleteKey] on [inner]. */
    suspend fun bridgeCredentialDeleteKey(bridgeId: String) = inner.bridgeCredentialDeleteKey(bridgeId = bridgeId)

    /** Forwards to [NativeScp.addCheckpointCosignature] on [inner]. */
    suspend fun addCheckpointCosignature(
        handle: ContextHandle,
        checkpointJson: String,
        signerDid: String,
        signatureHex: String,
    ): String =
        inner.addCheckpointCosignature(
            handle = handle,
            checkpointJson = checkpointJson,
            signerDid = signerDid,
            signatureHex = signatureHex,
        )

    /** Forwards to [NativeScp.addressResolve] on [inner]. */
    fun addressResolve(
        ownerDid: String,
        address: String,
        knownContextsJson: String?,
    ): String =
        inner.addressResolve(
            ownerDid = ownerDid,
            address = address,
            knownContextsJson = knownContextsJson,
        )

    /**
     * Aggregates all trust engine layers into a single `TrustInput` (§7.3).
     *
     * Every structured input is typed; the SDK serializes to the serde wire
     * shapes internally (ADR-058) via the TrustAggregate.kt encoders and
     * forwards to [NativeScp.aggregateTrustInput] on [inner] unchanged. An
     * empty collection is a real value ("no rules apply"), never a request
     * for defaults — the bridge receives `[]` / `{}` exactly as passed.
     *
     * @param contextId The context to aggregate trust inputs for.
     * @param subjectDid The DID of the subject to evaluate.
     * @param events Full signed event-log entries ([EventLogEntry]).
     * @param merkleRoot 32-byte Merkle root.
     * @param consequenceRules Typed [ConsequenceRule] values.
     * @param thresholdRequirements Typed [ThresholdRequirement] values keyed
     *   by [AttestationType].
     * @param attestorSets Typed [AttestorInfo] lists keyed by
     *   [AttestationType].
     * @param cachedAttestations Typed [CachedAttestation] values to seed the
     *   bridge's trust store.
     * @param challengeResults Typed [ChallengeVerification] records.
     * @return The aggregated `TrustInput` as a JSON string.
     * @throws IllegalArgumentException on a wrong-length byte array (before
     *   any bridge call).
     */
    @Suppress("LongParameterList")
    fun aggregateTrustInput(
        contextId: String,
        subjectDid: String,
        events: List<EventLogEntry>,
        merkleRoot: List<UByte>,
        consequenceRules: List<ConsequenceRule> = emptyList(),
        thresholdRequirements: Map<AttestationType, ThresholdRequirement> = emptyMap(),
        attestorSets: Map<AttestationType, List<AttestorInfo>> = emptyMap(),
        cachedAttestations: List<CachedAttestation> = emptyList(),
        challengeResults: List<ChallengeVerification> = emptyList(),
    ): String =
        inner.aggregateTrustInput(
            contextId = contextId,
            subjectDid = subjectDid,
            eventsJson = encodeEventLogEntriesJson(events),
            merkleRootJson = encodeMerkleRootJson(merkleRoot),
            consequenceRulesJson = encodeConsequenceRulesJson(consequenceRules),
            thresholdRequirementsJson = encodeThresholdRequirementsJson(thresholdRequirements),
            attestorSetsJson = encodeAttestorSetsJson(attestorSets),
            cachedAttestationsJson = encodeCachedAttestationsJson(cachedAttestations),
            challengeResultsJson = encodeChallengeVerificationsJson(challengeResults),
        )

    /** Forwards to [NativeScp.applyPendingCeilingModification] on [inner]. */
    suspend fun applyPendingCeilingModification(
        handle: ContextHandle,
        currentTimestamp: ULong,
    ): Boolean =
        inner.applyPendingCeilingModification(
            handle = handle,
            currentTimestamp = currentTimestamp,
        )

    /**
     * Routes through the UniFFI-generated free function
     * [uniffi.scp.bridgeEvaluateTrust]. ADR-048 §1 + §7 Kotlin bullet:
     * pure helper at the FFI Rust layer, method on `SCP` at the SDK
     * surface per Kotlin idiom.
     */
    fun bridgeEvaluateTrust(
        isBridged: Boolean,
        isNativeTransport: Boolean,
        shadowStatus: String,
    ): UByte =
        uniffi.scp.bridgeEvaluateTrust(
            isBridged = isBridged,
            isNativeTransport = isNativeTransport,
            shadowStatus = shadowStatus,
        )

    /** Forwards to [NativeScp.broadcastAdmission] on [inner]. */
    suspend fun broadcastAdmission(handle: ContextHandle): String? = inner.broadcastAdmission(handle = handle)

    /** Forwards to [NativeScp.broadcastBlockSubscriber] on [inner]. */
    suspend fun broadcastBlockSubscriber(
        handle: ContextHandle,
        subscriberDid: String,
        blockerDid: String,
    ) = inner.broadcastBlockSubscriber(
        handle = handle,
        subscriberDid = subscriberDid,
        blockerDid = blockerDid,
    )

    /** Forwards to [NativeScp.broadcastHandleKeyRequest] on [inner]. */
    suspend fun broadcastHandleKeyRequest(
        handle: ContextHandle,
        authorDid: String,
        requesterDid: String,
        wrappingPubkey: ByteArray,
    ): String? =
        inner.broadcastHandleKeyRequest(
            handle = handle,
            authorDid = authorDid,
            requesterDid = requesterDid,
            wrappingPubkey = wrappingPubkey,
        )

    /**
     * Opens an HPKE-sealed broadcast key (§5.14.2) using the subscriber's
     * 32-byte X25519 [wrappingSecret], returning the raw 32-byte AES-256
     * broadcast key. [sealedJson] is the JSON returned by
     * [broadcastHandleKeyRequest] on grant. Delegates to the generated
     * module-level `broadcastOpenKey` UniFFI free function (fully qualified to
     * avoid shadowing by this same-named wrapper).
     */
    fun broadcastOpenKey(
        sealedJson: String,
        wrappingSecret: ByteArray,
    ): ByteArray = uniffi.scp.broadcastOpenKey(sealedJson = sealedJson, wrappingSecret = wrappingSecret)

    /** Forwards to [NativeScp.broadcastIsSubscriber] on [inner]. */
    suspend fun broadcastIsSubscriber(
        handle: ContextHandle,
        did: String,
    ): Boolean =
        inner.broadcastIsSubscriber(
            handle = handle,
            did = did,
        )

    /** Forwards to [NativeScp.broadcastPublish] on [inner]. */
    suspend fun broadcastPublish(
        handle: ContextHandle,
        identity: Identity,
        payload: ByteArray,
    ) = inner.broadcastPublish(
        handle = handle,
        identity = identity,
        payload = payload,
    )

    /** Forwards to [NativeScp.broadcastPublishAsset] on [inner]. */
    suspend fun broadcastPublishAsset(
        handle: ContextHandle,
        identity: Identity,
        asset: AssetEntry,
        deployId: String?,
    ): PublishResult =
        inner.broadcastPublishAsset(
            handle = handle,
            identity = identity,
            asset = asset,
            deployId = deployId,
        )

    /** Forwards to [NativeScp.broadcastPublishAssets] on [inner]. */
    suspend fun broadcastPublishAssets(
        handle: ContextHandle,
        identity: Identity,
        assets: List<AssetEntry>,
        deployId: String?,
    ): BatchPublishResult =
        inner.broadcastPublishAssets(
            handle = handle,
            identity = identity,
            assets = assets,
            deployId = deployId,
        )

    /** Forwards to [NativeScp.broadcastSubscribe] on [inner]. */
    suspend fun broadcastSubscribe(
        handle: ContextHandle,
        subscriberDid: String,
    ) = inner.broadcastSubscribe(
        handle = handle,
        subscriberDid = subscriberDid,
    )

    /** Forwards to [NativeScp.broadcastSubscriberCount] on [inner]. */
    suspend fun broadcastSubscriberCount(handle: ContextHandle): ULong? =
        inner.broadcastSubscriberCount(
            handle = handle,
        )

    /** Forwards to [NativeScp.broadcastUnblockSubscriber] on [inner]. */
    suspend fun broadcastUnblockSubscriber(
        handle: ContextHandle,
        subscriberDid: String,
        unblockerDid: String,
    ) = inner.broadcastUnblockSubscriber(
        handle = handle,
        subscriberDid = subscriberDid,
        unblockerDid = unblockerDid,
    )

    /** Forwards to [NativeScp.broadcastUnsubscribe] on [inner]. */
    suspend fun broadcastUnsubscribe(
        handle: ContextHandle,
        subscriberDid: String,
        rotateKeys: Boolean,
    ) = inner.broadcastUnsubscribe(
        handle = handle,
        subscriberDid = subscriberDid,
        rotateKeys = rotateKeys,
    )

    /** Forwards to [NativeScp.configureLocalTransport] on [inner]. */
    fun configureLocalTransport(localDid: String) = inner.configureLocalTransport(localDid = localDid)

    /** Forwards to [NativeScp.configureRelayTransport] on [inner]. */
    suspend fun configureRelayTransport(
        relayUrl: String,
        localDid: String,
    ) = inner.configureRelayTransport(
        relayUrl = relayUrl,
        localDid = localDid,
    )

    /** Forwards to [NativeScp.contextClose] on [inner]. */
    suspend fun contextClose(
        handle: ContextHandle,
        identity: Identity,
    ) = inner.contextClose(
        handle = handle,
        identity = identity,
    )

    /** Forwards to [NativeScp.contextCreate] on [inner]. */
    suspend fun contextCreate(
        identity: Identity,
        params: ContextParams,
    ): ContextHandle =
        inner.contextCreate(
            identity = identity,
            params = params,
        )

    /** Forwards to [NativeScp.contextDrainEvents] on [inner]. */
    suspend fun contextDrainEvents(handle: ContextHandle): List<String> = inner.contextDrainEvents(handle = handle)

    /** Forwards to [NativeScp.contextExport] on [inner]. */
    suspend fun contextExport(handle: ContextHandle): ByteArray = inner.contextExport(handle = handle)

    /** Forwards to [NativeScp.contextHandleTtlExpiry] on [inner]. */
    suspend fun contextHandleTtlExpiry(handle: ContextHandle) = inner.contextHandleTtlExpiry(handle = handle)

    /**
     * Forwards to [NativeScp.contextImport] on [inner].
     *
     * [importerIdentity] supplies the §9.10.4 per-context pseudonym derivation
     * material so the importing member routes under its OWN routing ID rather
     * than inheriting the exporter's local-instance pseudonym.
     */
    suspend fun contextImport(data: ByteArray, importerIdentity: Identity): String =
        inner.contextImport(data = data, importerIdentity = importerIdentity)

    /** Forwards to [NativeScp.contextIsMember] on [inner]. */
    suspend fun contextIsMember(
        handle: ContextHandle,
        did: String,
    ): Boolean =
        inner.contextIsMember(
            handle = handle,
            did = did,
        )

    /** Forwards to [NativeScp.contextJoin] on [inner]. */
    suspend fun contextJoin(
        handle: ContextHandle,
        identity: Identity,
        spendingUcanJwt: String?,
    ) = inner.contextJoin(
        handle = handle,
        identity = identity,
        spendingUcanJwt = spendingUcanJwt,
    )

    /** Forwards to [NativeScp.contextLeave] on [inner]. */
    suspend fun contextLeave(
        handle: ContextHandle,
        identity: Identity,
    ) = inner.contextLeave(
        handle = handle,
        identity = identity,
    )

    /** Forwards to [NativeScp.contextMemberCount] on [inner]. */
    suspend fun contextMemberCount(handle: ContextHandle): ULong? = inner.contextMemberCount(handle = handle)

    /** Forwards to [NativeScp.contextMemberDids] on [inner]. */
    suspend fun contextMemberDids(handle: ContextHandle): List<String> = inner.contextMemberDids(handle = handle)

    /** Forwards to [NativeScp.contextMemberRole] on [inner]. */
    suspend fun contextMemberRole(
        handle: ContextHandle,
        did: String,
    ): String? =
        inner.contextMemberRole(
            handle = handle,
            did = did,
        )

    /** Forwards to [NativeScp.contextProposeTtlExtension] on [inner]. */
    suspend fun contextProposeTtlExtension(
        handle: ContextHandle,
        memberDid: String,
        proposedSeconds: ULong,
    ): Boolean =
        inner.contextProposeTtlExtension(
            handle = handle,
            memberDid = memberDid,
            proposedSeconds = proposedSeconds,
        )

    /** Forwards to [NativeScp.contextResetTtlTimer] on [inner]. */
    suspend fun contextResetTtlTimer(
        handle: ContextHandle,
        newSeconds: ULong,
    ) = inner.contextResetTtlTimer(
        handle = handle,
        newSeconds = newSeconds,
    )

    /**
     * Forwards to [NativeScp.contextSend] on [inner].
     *
     * Throws a `ContextError` with code `SCP-CTX-2095` when this is a
     * multi-member encrypted context and no peer has announced its routing ID
     * yet (§9.10.4): the send fails closed and is rolled back (no charge, no
     * event); retry once peers' pseudonym-announcement messages have arrived.
     * A lone-member send is a no-op; broadcast contexts are unaffected.
     */
    suspend fun contextSend(
        handle: ContextHandle,
        identity: Identity,
        payload: ByteArray,
        spendingUcanJwt: String?,
    ) = inner.contextSend(
        handle = handle,
        identity = identity,
        payload = payload,
        spendingUcanJwt = spendingUcanJwt,
    )

    /**
     * Reconnects [identity]'s contexts after an offline period, running the
     * ADR-029 six-phase reconnection protocol for each of [contextIds] flagged
     * `needsReconnect` (§23.11).
     *
     * The driver lives at the FFI relay-client layer (ADR-029
     * reconnection-driver addendum): it pulls relay-buffered messages via the
     * `TransportManager` and reaches actor-owned reconnection state through the
     * `Supervisor`. On success each context's `needsReconnect` flag is cleared.
     * [lastRelayContacts] maps context id to last-relay-contact Unix seconds
     * (tier classification); absent contexts default to the most conservative
     * tier. Forwards to [NativeScp.contextReconnect] on [inner].
     *
     * Catch-up integrity (§9.9.3, §23.7): equivocation where a peer reports the
     * **same** event count with a **different** Merkle root IS detected and
     * surfaced (`ReconnectReport.contexts[].equivocationsDetected`). However,
     * reconnection catch-up does NOT yet verify suffix integrity — the Merkle
     * consistency proof confirming that fetched events genuinely extend this
     * member's own history is specified separately. An equivocating relay that
     * keeps a member perpetually *behind* (never reaching equal count) is
     * therefore not yet detected on the catch-up path.
     */
    suspend fun reconnect(
        identity: Identity,
        contextIds: List<String>,
        lastRelayContacts: Map<String, ULong> = emptyMap(),
    ): ReconnectReport =
        inner.contextReconnect(
            identity = identity,
            contextIds = contextIds,
            lastRelayContacts = lastRelayContacts,
        )

    /** Forwards to [NativeScp.contextSubscribe] on [inner]. */
    suspend fun contextSubscribe(
        handle: ContextHandle,
        listener: MessageListener,
    ) = inner.contextSubscribe(
        handle = handle,
        listener = listener,
    )

    /** Forwards to [NativeScp.createGovernanceCheckpoint] on [inner]. */
    @Suppress("LongParameterList")
    suspend fun createGovernanceCheckpoint(
        handle: ContextHandle,
        checkpointSeq: ULong,
        merkleRootHex: String,
        eventCount: ULong,
        lastEventHashHex: String,
        stateSnapshotHashHex: String,
        creatorDid: String,
        creatorSignatureHex: String,
    ): String =
        inner.createGovernanceCheckpoint(
            handle = handle,
            checkpointSeq = checkpointSeq,
            merkleRootHex = merkleRootHex,
            eventCount = eventCount,
            lastEventHashHex = lastEventHashHex,
            stateSnapshotHashHex = stateSnapshotHashHex,
            creatorDid = creatorDid,
            creatorSignatureHex = creatorSignatureHex,
        )

    /** Forwards to [NativeScp.economyAntispamEscalatedCost] on [inner]. */
    @Suppress("LongParameterList")
    fun economyAntispamEscalatedCost(
        contextId: String,
        senderDid: String,
        now: ULong,
        baseCost: ULong,
        thresholdsJson: String,
        floor: ULong?,
        cap: ULong?,
    ): ULong =
        inner.economyAntispamEscalatedCost(
            contextId = contextId,
            senderDid = senderDid,
            now = now,
            baseCost = baseCost,
            thresholdsJson = thresholdsJson,
            floor = floor,
            cap = cap,
        )

    /** Forwards to [NativeScp.economyAntispamRecord] on [inner]. */
    fun economyAntispamRecord(
        contextId: String,
        senderDid: String,
        timestamp: ULong,
    ) = inner.economyAntispamRecord(
        contextId = contextId,
        senderDid = senderDid,
        timestamp = timestamp,
    )

    /** Forwards to [NativeScp.economyAntispamVelocity] on [inner]. */
    fun economyAntispamVelocity(
        contextId: String,
        senderDid: String,
        now: ULong,
    ): ULong =
        inner.economyAntispamVelocity(
            contextId = contextId,
            senderDid = senderDid,
            now = now,
        )

    /** Forwards to [NativeScp.economyBudgetGrant] on [inner]. */
    fun economyBudgetGrant(
        contextId: String,
        did: String,
        amount: ULong,
    ) = inner.economyBudgetGrant(
        contextId = contextId,
        did = did,
        amount = amount,
    )

    /** Forwards to [NativeScp.economyBudgetRecordSpend] on [inner]. */
    fun economyBudgetRecordSpend(
        contextId: String,
        did: String,
        amount: ULong,
    ) = inner.economyBudgetRecordSpend(
        contextId = contextId,
        did = did,
        amount = amount,
    )

    /** Forwards to [NativeScp.economyBudgetRemaining] on [inner]. */
    fun economyBudgetRemaining(
        contextId: String,
        did: String,
    ): ULong =
        inner.economyBudgetRemaining(
            contextId = contextId,
            did = did,
        )

    /**
     * Forwards to [NativeScp.economyVerifyPaymentReceipts] on [inner].
     *
     * Verifies a batch of payment receipts against the configured payment
     * adapter. Maximum 10,000 receipts per call. Returns a JSON object
     * `{"all_valid": <bool>, "results": [...]}`; `all_valid` is vacuously
     * `true` for an empty batch. Each entry's `ok` means the adapter
     * *responded* — NOT that the payment is valid; scan `valid`/`all_valid`
     * for payment validity.
     */
    suspend fun economyVerifyPaymentReceipts(receiptsJson: String): String =
        inner.economyVerifyPaymentReceipts(receiptsJson = receiptsJson)

    /**
     * Forwards to [NativeScp.evaluateInvitation] on [inner].
     *
     * The `known_did` allowlist (the sole auto-accept trigger, §5.12.2) travels
     * inside [policyJson] -- the policy's `TrustRequirement` `KnownDid` variant.
     * There is no separate trusted-DID parameter.
     */
    fun evaluateInvitation(
        paramsJson: String,
        inviterDid: String,
        identityDid: String,
        policyJson: String?,
        spendingJson: String?,
    ): String =
        inner.evaluateInvitation(
            paramsJson = paramsJson,
            inviterDid = inviterDid,
            identityDid = identityDid,
            policyJson = policyJson,
            spendingJson = spendingJson,
        )

    /** Forwards to [NativeScp.eventLogCheckpoint] on [inner]. */
    suspend fun eventLogCheckpoint(
        handle: ContextHandle,
        identity: Identity,
        epoch: ULong,
    ): Checkpoint =
        inner.eventLogCheckpoint(
            handle = handle,
            identity = identity,
            epoch = epoch,
        )

    /**
     * Forwards to [NativeScp.eventLogCheckpointByDid] on [inner].
     *
     * Signs with [identity]'s key material and records [did] as the
     * checkpoint sender. The UniFFI bridge has no DID-keyed identity
     * registry, so [identity] supplies the key material while [did] names
     * the member the checkpoint is attributed to (ADR-048 §7 per-SDK idiom).
     */
    suspend fun eventLogCheckpointByDid(
        handle: ContextHandle,
        identity: Identity,
        did: String,
        epoch: ULong,
    ): Checkpoint =
        inner.eventLogCheckpointByDid(
            handle = handle,
            identity = identity,
            did = did,
            epoch = epoch,
        )

    /** Forwards to [NativeScp.eventLogQuery] on [inner]. */
    suspend fun eventLogQuery(
        handle: ContextHandle,
        filterJson: String?,
    ): List<Event> =
        inner.eventLogQuery(
            handle = handle,
            filterJson = filterJson,
        )

    /** Forwards to [NativeScp.eventLogVerify] on [inner]. */
    suspend fun eventLogVerify(
        handle: ContextHandle,
        claimJson: String,
    ): Proof =
        inner.eventLogVerify(
            handle = handle,
            claimJson = claimJson,
        )

    /** Forwards to [NativeScp.finalizeClose] on [inner]. */
    suspend fun finalizeClose(handle: ContextHandle) = inner.finalizeClose(handle = handle)

    /** Forwards to [NativeScp.getEconomicPolicy] on [inner]. */
    fun getEconomicPolicy(handle: ContextHandle): String? = inner.getEconomicPolicy(handle = handle)

    /** Forwards to [NativeScp.governanceApprove] on [inner]. */
    suspend fun governanceApprove(
        handle: ContextHandle,
        voterDid: String,
        proposalIdHex: String,
    ): String =
        inner.governanceApprove(
            handle = handle,
            voterDid = voterDid,
            proposalIdHex = proposalIdHex,
        )

    /**
     * Forwards to [NativeScp.governanceExecute] on [inner].
     *
     * Executes a previously-approved governance proposal BY ID. The runtime
     * resolves the authoritative proposal from the context actor's own
     * quorum-validated governance engine; the caller supplies no proposal,
     * action, status, or identity. The executor and consequence subject are
     * resolved from the tracked proposal's proposer.
     */
    suspend fun governanceExecute(
        handle: ContextHandle,
        proposalIdHex: String,
    ): String =
        inner.governanceExecute(
            handle = handle,
            proposalIdHex = proposalIdHex,
        )

    /** Forwards to [NativeScp.governanceGetProposal] on [inner]. */
    suspend fun governanceGetProposal(
        handle: ContextHandle,
        proposalIdHex: String,
    ): String =
        inner.governanceGetProposal(
            handle = handle,
            proposalIdHex = proposalIdHex,
        )

    /** Forwards to [NativeScp.governanceListProposals] on [inner]. */
    suspend fun governanceListProposals(handle: ContextHandle): String = inner.governanceListProposals(handle = handle)

    /** Forwards to [NativeScp.governancePropose] on [inner]. */
    suspend fun governancePropose(
        handle: ContextHandle,
        proposerDid: String,
        actionJson: String,
    ): String =
        inner.governancePropose(
            handle = handle,
            proposerDid = proposerDid,
            actionJson = actionJson,
        )

    /** Forwards to [NativeScp.governanceReject] on [inner]. */
    suspend fun governanceReject(
        handle: ContextHandle,
        voterDid: String,
        proposalIdHex: String,
    ): String =
        inner.governanceReject(
            handle = handle,
            voterDid = voterDid,
            proposalIdHex = proposalIdHex,
        )

    /** Forwards to [NativeScp.governanceWithdraw] on [inner]. */
    suspend fun governanceWithdraw(
        handle: ContextHandle,
        voterDid: String,
        proposalIdHex: String,
    ): String =
        inner.governanceWithdraw(
            handle = handle,
            voterDid = voterDid,
            proposalIdHex = proposalIdHex,
        )

    /** Forwards to [NativeScp.handleDeregister] on [inner]. */
    fun handleDeregister(
        discoveryContextId: String,
        handle: String,
        did: String,
    ): String =
        inner.handleDeregister(
            discoveryContextId = discoveryContextId,
            handle = handle,
            did = did,
        )

    /** Forwards to [NativeScp.handleLookup] on [inner]. */
    fun handleLookup(
        discoveryContextId: String,
        handle: String,
        typeFilter: String?,
    ): String =
        inner.handleLookup(
            discoveryContextId = discoveryContextId,
            handle = handle,
            typeFilter = typeFilter,
        )

    /** Forwards to [NativeScp.handleRegister] on [inner]. */
    @Suppress("LongParameterList")
    fun handleRegister(
        discoveryContextId: String,
        handle: String,
        targetJson: String,
        registrantDid: String,
        description: String?,
        tags: List<String>?,
    ): String =
        inner.handleRegister(
            discoveryContextId = discoveryContextId,
            handle = handle,
            targetJson = targetJson,
            registrantDid = registrantDid,
            description = description,
            tags = tags,
        )

    /** Forwards to [NativeScp.identityAttestDevice] on [inner]. */
    suspend fun identityAttestDevice(identity: Identity): String = inner.identityAttestDevice(identity = identity)

    /**
     * Forwards to [NativeScp.identityCreate] on [inner].
     *
     * [testingSeed] is a testing-only parameter for the ADR-046
     * cross-bridge parity harness; pass `null` from production callers
     * (in-memory custody uses OS RNG when [testingSeed] is `null`). A
     * non-`null` [testingSeed] is only valid for `custody == "in_memory"`;
     * other custody types reject it with `SCP-VALID-7009`.
     */
    suspend fun identityCreate(custody: String, testingSeed: ByteArray? = null): Identity =
        inner.identityCreate(custody = custody, testingSeed = testingSeed)

    /** Forwards to [NativeScp.identityCreateLinkAttestation] on [inner]. */
    @Suppress("LongParameterList")
    suspend fun identityCreateLinkAttestation(
        identity: Identity,
        platform: String,
        handle: String,
        proof: String,
        verificationMethod: String,
        platformId: String?,
    ): String =
        inner.identityCreateLinkAttestation(
            identity = identity,
            platform = platform,
            handle = handle,
            proof = proof,
            verificationMethod = verificationMethod,
            platformId = platformId,
        )

    /** Forwards to [NativeScp.identityCreateWithAgentKey] on [inner]. */
    suspend fun identityCreateWithAgentKey(custody: String): Identity =
        inner.identityCreateWithAgentKey(
            custody = custody,
        )

    /** Forwards to [NativeScp.identityCreateWithCustody] on [inner]. */
    suspend fun identityCreateWithCustody(provider: KeyCustodyProvider): Identity =
        inner.identityCreateWithCustody(
            provider = provider,
        )

    /** Forwards to [NativeScp.identityExecuteCustodyMigration] on [inner]. */
    fun identityExecuteCustodyMigration(
        did: String,
        target: String,
        contextIds: List<String>,
    ): String =
        inner.identityExecuteCustodyMigration(
            did = did,
            target = target,
            contextIds = contextIds,
        )

    /** Forwards to [NativeScp.identityExecuteRecovery] on [inner]. */
    fun identityExecuteRecovery(
        did: String,
        tier: String,
        contextIds: List<String>,
    ): String =
        inner.identityExecuteRecovery(
            did = did,
            tier = tier,
            contextIds = contextIds,
        )

    /** Forwards to [NativeScp.identityLinkAttestations] on [inner]. */
    fun identityLinkAttestations(did: String): String = inner.identityLinkAttestations(did = did)

    /** Forwards to [NativeScp.identityLoad] on [inner]. */
    suspend fun identityLoad(did: String): Identity = inner.identityLoad(did = did)

    /** Forwards to [NativeScp.identityMigrate] on [inner]. */
    suspend fun identityMigrate(identity: Identity): Identity = inner.identityMigrate(identity = identity)

    /** Forwards to [NativeScp.identityRemoveLinkAttestation] on [inner]. */
    fun identityRemoveLinkAttestation(
        did: String,
        attestationId: String,
    ): Boolean =
        inner.identityRemoveLinkAttestation(
            did = did,
            attestationId = attestationId,
        )

    /**
     * Forwards to [NativeScp.identityRemove] on [inner].
     *
     * Removes the DID from this instance's SCP-side identity registry.
     * Idempotent — succeeds silently when the DID is not present.
     */
    fun identityRemove(did: String) = inner.identityRemove(did = did)

    /**
     * Forwards to [NativeScp.identityRemoveIfPresent] on [inner].
     *
     * Returns `true` if the identity was found and removed, `false` if the
     * DID was not in the registry.
     */
    fun identityRemoveIfPresent(did: String): Boolean = inner.identityRemoveIfPresent(did = did)

    /**
     * Routes through the UniFFI-generated free function
     * [uniffi.scp.identityResolve]. ADR-048 §1 + §7 Kotlin bullet.
     */
    suspend fun identityResolve(did: String): DidDocument = uniffi.scp.identityResolve(did = did)

    /**
     * Routes through the UniFFI-generated free function
     * [uniffi.scp.identityVerifyDeviceAttestation]. ADR-048 §1 + §7
     * Kotlin bullet.
     */
    suspend fun identityVerifyDeviceAttestation(
        did: String,
        tokenBase64: String,
    ): Boolean =
        uniffi.scp.identityVerifyDeviceAttestation(
            did = did,
            tokenBase64 = tokenBase64,
        )

    /**
     * Routes through the UniFFI-generated free function
     * [uniffi.scp.identityVerifyLinkAttestation]. ADR-048 §1 + §7
     * Kotlin bullet.
     */
    fun identityVerifyLinkAttestation(
        attestationJson: String,
        issuerPublicKeyHex: String,
    ): Boolean =
        uniffi.scp.identityVerifyLinkAttestation(
            attestationJson = attestationJson,
            issuerPublicKeyHex = issuerPublicKeyHex,
        )

    /** Forwards to [NativeScp.isLocalDid] on [inner]. */
    suspend fun isLocalDid(did: String): Boolean = inner.isLocalDid(did = did)

    /** Forwards to [NativeScp.mcpClientConnectSse] on [inner]. */
    suspend fun mcpClientConnectSse(url: String): String = inner.mcpClientConnectSse(url = url)

    /**
     * Forwards to [NativeScp.mcpClientConnectStdio] on [inner].
     *
     * `command[0]` is validated against THIS instance's stdio allowlist
     * (per-instance — disabling enforcement on another [Scp] does not
     * affect this one). To permit a binary not in the default allowlist,
     * call [mcpConfigureStdioAllowlist] first; use [mcpGetStdioAllowlist]
     * to inspect the current state.
     */
    suspend fun mcpClientConnectStdio(command: List<String>): String = inner.mcpClientConnectStdio(command = command)

    /** Forwards to [NativeScp.mcpClientDisconnect] on [inner]. */
    suspend fun mcpClientDisconnect(handle: String) = inner.mcpClientDisconnect(handle = handle)

    /** Forwards to [NativeScp.mcpClientInvoke] on [inner]. */
    suspend fun mcpClientInvoke(
        handle: String,
        toolName: String,
        inputJson: String,
        contextId: String,
        invokerDid: String,
    ): McpInvokeResult =
        inner.mcpClientInvoke(
            handle = handle,
            toolName = toolName,
            inputJson = inputJson,
            contextId = contextId,
            invokerDid = invokerDid,
        )

    /** Forwards to [NativeScp.mcpClientListTools] on [inner]. */
    suspend fun mcpClientListTools(handle: String): List<McpToolInfo> = inner.mcpClientListTools(handle = handle)

    /** Forwards to [NativeScp.mcpConfigureStdioAllowlist] on [inner]. */
    fun mcpConfigureStdioAllowlist(additionalBinaries: List<String>) =
        inner.mcpConfigureStdioAllowlist(
            additionalBinaries = additionalBinaries,
        )

    /**
     * Disable this instance's stdio allowlist (unrestricted mode).
     *
     * After calling this, **any** binary may be spawned by
     * [mcpClientConnectStdio] on this [Scp]. Other instances are
     * unaffected. Pass [iTrustAllCommands] = true to confirm
     * acknowledgement of the security implication; the call also writes
     * a warning via `println` for operator audit.
     */
    fun mcpDisableStdioAllowlist(iTrustAllCommands: Boolean = false) {
        require(iTrustAllCommands) {
            "Disabling the stdio allowlist allows any binary to be spawned by this Scp instance. " +
                "Pass iTrustAllCommands = true to confirm."
        }
        println(
            "[scp] MCP stdio allowlist enforcement disabled — arbitrary subprocess " +
                "spawning is now permitted on this instance",
        )
        inner.mcpDisableStdioAllowlist()
    }

    /** Forwards to [NativeScp.mcpGetStdioAllowlist] on [inner]. */
    fun mcpGetStdioAllowlist(): McpAllowlistState = inner.mcpGetStdioAllowlist()

    /** Forwards to [NativeScp.mcpResetStdioAllowlist] on [inner]. */
    fun mcpResetStdioAllowlist() = inner.mcpResetStdioAllowlist()

    /** Forwards to [NativeScp.mcpServerCreate] on [inner]. */
    suspend fun mcpServerCreate(config: McpServerConfig): String = inner.mcpServerCreate(config = config)

    /** Forwards to [NativeScp.mcpServerStop] on [inner]. */
    suspend fun mcpServerStop(handle: String) = inner.mcpServerStop(handle = handle)

    /** Forwards to [NativeScp.migrationState] on [inner]. */
    suspend fun migrationState(handle: ContextHandle): String? = inner.migrationState(handle = handle)

    /** Forwards to [NativeScp.petnameApplyEvent] on [inner]. */
    fun petnameApplyEvent(
        ownerDid: String,
        eventJson: String,
    ) = inner.petnameApplyEvent(
        ownerDid = ownerDid,
        eventJson = eventJson,
    )

    /** Forwards to [NativeScp.petnameContextCount] on [inner]. */
    fun petnameContextCount(ownerDid: String): UInt = inner.petnameContextCount(ownerDid = ownerDid)

    /** Forwards to [NativeScp.petnameDidCount] on [inner]. */
    fun petnameDidCount(ownerDid: String): UInt = inner.petnameDidCount(ownerDid = ownerDid)

    /** Forwards to [NativeScp.petnameGetForContext] on [inner]. */
    fun petnameGetForContext(
        ownerDid: String,
        contextId: String,
    ): String? =
        inner.petnameGetForContext(
            ownerDid = ownerDid,
            contextId = contextId,
        )

    /** Forwards to [NativeScp.petnameGetForDid] on [inner]. */
    fun petnameGetForDid(
        ownerDid: String,
        targetDid: String,
    ): String? =
        inner.petnameGetForDid(
            ownerDid = ownerDid,
            targetDid = targetDid,
        )

    /** Forwards to [NativeScp.petnameRemove] on [inner]. */
    fun petnameRemove(
        ownerDid: String,
        targetDid: String,
    ) = inner.petnameRemove(
        ownerDid = ownerDid,
        targetDid = targetDid,
    )

    /** Forwards to [NativeScp.petnameRemoveContext] on [inner]. */
    fun petnameRemoveContext(
        ownerDid: String,
        contextId: String,
    ) = inner.petnameRemoveContext(
        ownerDid = ownerDid,
        contextId = contextId,
    )

    /** Forwards to [NativeScp.petnameResolveContext] on [inner]. */
    fun petnameResolveContext(
        ownerDid: String,
        name: String,
    ): String =
        inner.petnameResolveContext(
            ownerDid = ownerDid,
            name = name,
        )

    /** Forwards to [NativeScp.petnameResolveDid] on [inner]. */
    fun petnameResolveDid(
        ownerDid: String,
        name: String,
    ): String =
        inner.petnameResolveDid(
            ownerDid = ownerDid,
            name = name,
        )

    /** Forwards to [NativeScp.petnameSet] on [inner]. */
    fun petnameSet(
        ownerDid: String,
        targetDid: String,
        name: String,
    ) = inner.petnameSet(
        ownerDid = ownerDid,
        targetDid = targetDid,
        name = name,
    )

    /** Forwards to [NativeScp.petnameSetContext] on [inner]. */
    fun petnameSetContext(
        ownerDid: String,
        contextId: String,
        name: String,
    ) = inner.petnameSetContext(
        ownerDid = ownerDid,
        contextId = contextId,
        name = name,
    )

    /** Forwards to [NativeScp.provenanceAttach] on [inner]. */
    @Suppress("LongParameterList")
    fun provenanceAttach(
        sourceContextId: String,
        sourceType: String,
        memoryScopeStr: String,
        members: List<String>,
        targetContextId: String,
        actorDid: String,
        existingChainDepth: UByte?,
    ): String =
        inner.provenanceAttach(
            sourceContextId = sourceContextId,
            sourceType = sourceType,
            memoryScopeStr = memoryScopeStr,
            members = members,
            targetContextId = targetContextId,
            actorDid = actorDid,
            existingChainDepth = existingChainDepth,
        )

    /** Forwards to [NativeScp.registerLocalDid] on [inner]. */
    suspend fun registerLocalDid(did: String) = inner.registerLocalDid(did = did)

    /** Forwards to [NativeScp.restoreAllContexts] on [inner]. */
    suspend fun restoreAllContexts(): String = inner.restoreAllContexts()

    /** Forwards to [NativeScp.restoreContext] on [inner]. */
    suspend fun restoreContext(contextId: String) = inner.restoreContext(contextId = contextId)

    /** Forwards to [NativeScp.scopeDeregister] on [inner]. */
    fun scopeDeregister(
        scopeContextId: String,
        name: String,
        did: String,
    ): String =
        inner.scopeDeregister(
            scopeContextId = scopeContextId,
            name = name,
            did = did,
        )

    /** Forwards to [NativeScp.scopeLookup] on [inner]. */
    fun scopeLookup(
        scopeContextId: String,
        name: String,
    ): String =
        inner.scopeLookup(
            scopeContextId = scopeContextId,
            name = name,
        )

    /** Forwards to [NativeScp.scopeRegister] on [inner]. */
    @Suppress("LongParameterList")
    fun scopeRegister(
        scopeContextId: String,
        name: String,
        targetContextId: String,
        relayUrls: List<String>,
        registrantDid: String,
        description: String?,
        tags: List<String>?,
    ): String =
        inner.scopeRegister(
            scopeContextId = scopeContextId,
            name = name,
            targetContextId = targetContextId,
            relayUrls = relayUrls,
            registrantDid = registrantDid,
            description = description,
            tags = tags,
        )

    /** Forwards to [NativeScp.setEconomicPolicy] on [inner]. */
    fun setEconomicPolicy(
        handle: ContextHandle,
        policyJson: String,
    ) = inner.setEconomicPolicy(
        handle = handle,
        policyJson = policyJson,
    )

    /**
     * Routes through the UniFFI-generated free function
     * [uniffi.scp.syncClassifyOffline]. ADR-048 §1 + §7 Kotlin bullet.
     */
    fun syncClassifyOffline(
        lastRelayContact: ULong,
        now: ULong,
    ): String =
        uniffi.scp.syncClassifyOffline(
            lastRelayContact = lastRelayContact,
            now = now,
        )

    /**
     * Routes through the UniFFI-generated free function
     * [uniffi.scp.syncClassifyOfflineCustom]. ADR-048 §1 + §7 Kotlin
     * bullet.
     */
    fun syncClassifyOfflineCustom(
        lastRelayContact: ULong,
        now: ULong,
        tier1ThresholdSecs: ULong,
        tier2ThresholdSecs: ULong,
    ): String =
        uniffi.scp.syncClassifyOfflineCustom(
            lastRelayContact = lastRelayContact,
            now = now,
            tier1ThresholdSecs = tier1ThresholdSecs,
            tier2ThresholdSecs = tier2ThresholdSecs,
        )

    /**
     * Routes through the UniFFI-generated free function
     * [uniffi.scp.syncGetPolicy]. ADR-048 §1 + §7 Kotlin bullet.
     */
    fun syncGetPolicy(): SyncPolicyResult = uniffi.scp.syncGetPolicy()

    /** Forwards to [NativeScp.tombstoneMigratedContext] on [inner]. */
    suspend fun tombstoneMigratedContext(handle: ContextHandle) = inner.tombstoneMigratedContext(handle = handle)

    /** Forwards to [NativeScp.toolInterfaceAccept] on [inner]. */
    suspend fun toolInterfaceAccept(
        handle: ContextHandle,
        interfaceJson: String,
    ): String =
        inner.toolInterfaceAccept(
            handle = handle,
            interfaceJson = interfaceJson,
        )

    /** Forwards to [NativeScp.toolInterfaceExpose] on [inner]. */
    suspend fun toolInterfaceExpose(
        handle: ContextHandle,
        toolId: String,
        targetContextId: String,
        rateLimitJson: String?,
    ): String =
        inner.toolInterfaceExpose(
            handle = handle,
            toolId = toolId,
            targetContextId = targetContextId,
            rateLimitJson = rateLimitJson,
        )

    /** Forwards to [NativeScp.toolInterfaceRevoke] on [inner]. */
    suspend fun toolInterfaceRevoke(
        handle: ContextHandle,
        interfaceIdHex: String,
    ): String =
        inner.toolInterfaceRevoke(
            handle = handle,
            interfaceIdHex = interfaceIdHex,
        )

    /** Forwards to [NativeScp.toolInvoke] on [inner]. */
    @Suppress("LongParameterList")
    suspend fun toolInvoke(
        handle: ContextHandle,
        toolId: String,
        inputJson: String,
        identity: Identity,
        ucanToken: String?,
        proofTokens: List<String>?,
        spendingUcanJwt: String?,
    ): String =
        inner.toolInvoke(
            handle = handle,
            toolId = toolId,
            inputJson = inputJson,
            identity = identity,
            ucanToken = ucanToken,
            proofTokens = proofTokens,
            spendingUcanJwt = spendingUcanJwt,
        )

    /** Forwards to [NativeScp.toolInvokeCrossContext] on [inner]. */
    @Suppress("LongParameterList")
    suspend fun toolInvokeCrossContext(
        sourceHandle: ContextHandle,
        targetHandle: ContextHandle,
        toolId: String,
        inputJson: String,
        identity: Identity,
        ucanToken: String,
        chainDepth: UByte,
        proofTokens: List<String>?,
    ): String =
        inner.toolInvokeCrossContext(
            sourceHandle = sourceHandle,
            targetHandle = targetHandle,
            toolId = toolId,
            inputJson = inputJson,
            identity = identity,
            ucanToken = ucanToken,
            chainDepth = chainDepth,
            proofTokens = proofTokens,
        )

    /**
     * Runs the §6.2.4 atomic cross-context tool-invocation saga (ADR-049 §3a).
     *
     * Forwards 1:1 to [NativeScp.toolInvokeCrossContextSaga] on [inner]. The
     * call blocks until the saga reaches a terminal state: it returns a
     * [SagaResult] on commit (carrying the supervisor-minted `sagaId` plus the
     * target's signed receipt and captured output, each `null` when absent and
     * never synthesized), or throws a typed [uniffi.scp.ScpException] for a
     * non-committed terminal — `ScpException.SagaAborted` (a Prepare-phase
     * abort: a PERMANENT rejection OR a RETRYABLE transient — rate limit or
     * participant actor unavailable — distinguished by the `SCP-SAGA-*` code;
     * carries an optional `retryAfterMs` back-off hint),
     * `ScpException.SagaNeedsRepair` (commit retries exhausted; carries
     * the durable `sagaId` operator-repair handle), or `ScpException.SagaBusy`
     * (the participant context set is contended; carries the
     * `contendedContext` id). Bridge-surfaced `ScpException.Validation` and
     * `ScpException.Permission` errors also propagate unchanged.
     *
     * This is a flat 1:1 forward: the caller principal is bound to the
     * authenticated FFI identity inside the bridge, and all argument
     * validation (including the asserted-nonce hex and the u64/u8 numeric
     * bounds enforced by [ULong]/[UByte]) is performed by the Rust core. The
     * 9-argument arity is dictated by the bridge op.
     *
     * @param sourceHandle The calling (source) context handle.
     * @param targetHandle The context holding the tool to invoke.
     * @param callerDid The invoking principal's DID.
     * @param toolRegistrationId The target tool's cross-context registration id.
     * @param inputJson JSON-encoded tool input.
     * @param assertedNonceHex The asserted replay-protection nonce as hex.
     * @param timestampMs The invocation timestamp in milliseconds.
     * @param chainDepth Current cross-context chain depth (0 for first hop).
     * @param ucanProofId Optional UCAN proof id for delegation-chain traversal.
     */
    @Suppress("LongParameterList")
    suspend fun toolInvokeCrossContextSaga(
        sourceHandle: ContextHandle,
        targetHandle: ContextHandle,
        callerDid: String,
        toolRegistrationId: String,
        inputJson: String,
        assertedNonceHex: String,
        timestampMs: ULong,
        chainDepth: UByte,
        ucanProofId: String?,
    ): SagaResult =
        inner.toolInvokeCrossContextSaga(
            sourceHandle = sourceHandle,
            targetHandle = targetHandle,
            callerDid = callerDid,
            toolRegistrationId = toolRegistrationId,
            inputJson = inputJson,
            assertedNonceHex = assertedNonceHex,
            timestampMs = timestampMs,
            chainDepth = chainDepth,
            ucanProofId = ucanProofId,
        )

    /** Forwards to [NativeScp.toolRegister] on [inner]. */
    suspend fun toolRegister(
        handle: ContextHandle,
        definition: ToolDefinition,
    ): String =
        inner.toolRegister(
            handle = handle,
            definition = definition,
        )

    /** Forwards to [NativeScp.toolSessionClose] on [inner]. */
    suspend fun toolSessionClose(
        handle: ContextHandle,
        sessionId: String,
    ) = inner.toolSessionClose(
        handle = handle,
        sessionId = sessionId,
    )

    /** Forwards to [NativeScp.toolSessionCreate] on [inner]. */
    suspend fun toolSessionCreate(
        handle: ContextHandle,
        toolId: String,
        sourceContextId: String,
        ttlSeconds: ULong?,
    ): String =
        inner.toolSessionCreate(
            handle = handle,
            toolId = toolId,
            sourceContextId = sourceContextId,
            ttlSeconds = ttlSeconds,
        )

    /** Forwards to [NativeScp.toolSessionInvoke] on [inner]. */
    @Suppress("LongParameterList")
    suspend fun toolSessionInvoke(
        handle: ContextHandle,
        sessionId: String,
        inputJson: String,
        identity: Identity,
        ucanToken: String,
        proofTokens: List<String>?,
    ): String =
        inner.toolSessionInvoke(
            handle = handle,
            sessionId = sessionId,
            inputJson = inputJson,
            identity = identity,
            ucanToken = ucanToken,
            proofTokens = proofTokens,
        )

    /** Forwards to [NativeScp.toolVerify] on [inner]. */
    suspend fun toolVerify(
        handle: ContextHandle,
        toolId: String,
    ): ToolVerificationResult =
        inner.toolVerify(
            handle = handle,
            toolId = toolId,
        )

    /** Forwards to [NativeScp.transportConnect] on [inner]. */
    suspend fun transportConnect(relayUrl: String): TransportManager = inner.transportConnect(relayUrl = relayUrl)

    /** Forwards to [NativeScp.transportDisconnect] on [inner]. */
    suspend fun transportDisconnect(manager: TransportManager) = inner.transportDisconnect(manager = manager)

    /** Forwards to [NativeScp.transportStatus] on [inner]. */
    suspend fun transportStatus(manager: TransportManager): TransportStatus = inner.transportStatus(manager = manager)

    /** Forwards to [NativeScp.trustCreateChallenge] on [inner]. */
    fun trustCreateChallenge(targetDid: String): ChallengeResult = inner.trustCreateChallenge(targetDid = targetDid)

    /**
     * Routes through the UniFFI-generated free function
     * [uniffi.scp.trustQueryScore]. ADR-048 §1 + §7 Kotlin bullet.
     */
    fun trustQueryScore(
        did: String,
        contextId: String,
    ): TrustScoreResult =
        uniffi.scp.trustQueryScore(
            did = did,
            contextId = contextId,
        )

    /**
     * Routes through the UniFFI-generated free function
     * [uniffi.scp.trustVerifyAttestation]. ADR-048 §1 + §7 Kotlin
     * bullet.
     */
    fun trustVerifyAttestation(attestationJson: String): AttestationVerificationResult =
        uniffi.scp.trustVerifyAttestation(
            attestationJson = attestationJson,
        )

    /** Forwards to [NativeScp.trustVerifyResponse] on [inner]. */
    fun trustVerifyResponse(
        challengeJson: String,
        responseJson: String,
    ): Boolean =
        inner.trustVerifyResponse(
            challengeJson = challengeJson,
            responseJson = responseJson,
        )

    /**
     * Read-only, structured counterpart to [ucanValidate].
     *
     * Runs the same 11-step ADR-016 validation pipeline but, instead of throwing
     * at the first failing stage, returns a [CapabilityValidation] of six
     * per-stage booleans (spec §7.2.4, ADR-057). The probe never records the
     * token's nonce, so calling it does not consume the token.
     * Capability/signature/expiry outcomes are reported via the booleans; only
     * malformed FFI inputs (bad handle / token / capability) throw.
     *
     * NOT AN AUTHORIZATION DECISION: this is a diagnostic, never a gate. A
     * no-capability (intrinsic-validity) result skips the invoked-capability
     * grant-match, so [CapabilityValidation.allValid] returning `true` does NOT
     * establish the token grants any particular capability.
     *
     * FAIL CLOSED: [presentingAgentDid] is required by the bridge (no silent
     * security default). Omitting it makes the bridge reject the call rather than
     * defaulting the presenting agent to the token's own `aud` — which would make
     * the step-5 audience check the tautology `aud == aud` and inflate trust. It
     * precedes [capability] because it is mandatory while [capability] is optional.
     *
     * @param capability Optional challenge capability URI. Omit it (or pass
     *   `null`) to evaluate the token's INTRINSIC validity with no
     *   invoked-capability grant-match challenge — the mode [evaluateTrust] uses.
     */
    suspend fun ucanEvaluate(
        handle: ContextHandle,
        token: String,
        presentingAgentDid: String,
        capability: String? = null,
        proofTokens: List<String>? = null,
    ): CapabilityValidation =
        CapabilityValidation.fromRecord(
            inner.ucanEvaluate(
                handle = handle,
                token = token,
                capability = capability,
                presentingAgentDid = presentingAgentDid,
                proofTokens = proofTokens,
            ),
        )

    /**
     * Computes the participation record (§7.3.2) for a subject in a context.
     *
     * The shared Rust core gathers the FULL context event log and flattens the
     * participation facts ONCE (`Supervisor::participation_record`), and the
     * UniFFI bridge sources the subject's accessible, currently-valid
     * attestations from its own persistent trust store (seeded by
     * [cachedAttestations]). The SDK RECEIVES the flattened [BehavioralRecord] —
     * it never re-aggregates event-log collections, so every binding observes
     * identical facts for the same context/subject.
     *
     * `attestationCount` is a credential-layer fact (§7.4): NOT a context-event
     * count, NOT Merkle-anchored, and verifier-relative. Pass the subject's
     * accessible attestations as [cachedAttestations] to populate it; the default
     * (empty) honestly reports only what the bridge's trust store already holds.
     *
     * SECURITY: `attestationCount` is authentic-but-self-mintable — an issuer is
     * self-certifying, so a subject can mint endorsements from DIDs it controls.
     * It MUST NOT be a sole trust or admission factor; use the
     * threshold/independence path (§7.3.5) for Sybil resistance.
     *
     * An empty event log surfaces as [uniffi.scp.ScpException.Context] carrying
     * [NO_PARTICIPATION_FACTS_CODE]; callers wanting the empty-log case as a
     * zeroed record (rather than an exception) should use [evaluateTrust].
     */
    fun participationRecord(
        contextId: String,
        subjectDid: String,
        cachedAttestations: List<CachedAttestation> = emptyList(),
    ): BehavioralRecord =
        BehavioralRecord.fromView(
            inner.participationRecord(
                contextId = contextId,
                subjectDid = subjectDid,
                cachedAttestationsJson = encodeCachedAttestationsJson(cachedAttestations),
            ),
        )

    /**
     * Evaluate the trustworthiness of a participant within a context
     * (spec §7.2.4, ADR-057). The protocol provides the data, not the verdict.
     *
     * - Layer 1 — protocol enforcement: each supplied capability token is run
     *   through the read-only [ucanEvaluate] diagnostic, yielding six per-stage
     *   booleans AND-combined across the token set (one token failing a stage
     *   makes that aggregate field `false`). This never inspects error prose. The
     *   subject is passed as the presenting agent (audience check against the DID
     *   under assessment) with no challenge capability (intrinsic-validity mode).
     *   With no tokens supplied, every field stays `false`.
     * - Layer 2 — behavioral validation: RECEIVES the subject's participation
     *   facts (§7.3.2) from the shared Rust core via [participationRecord]. A
     *   context with no convergent events yet (an empty event log) is folded into
     *   a zeroed [BehavioralRecord], branching on the STRUCTURED
     *   [NO_PARTICIPATION_FACTS_CODE] — never on error prose. Any other error
     *   propagates.
     *
     * The evaluation is labeled with the context the layers were computed against
     * — the handle's resolved [ContextHandle.contextId] — so it is never silently
     * mislabeled.
     *
     * SECURITY: the behavioral record's `attestationCount` (and any challenge
     * results, where consumed) are authentic-but-self-mintable signals — an
     * issuer/verifier is self-certifying, so a subject can mint them from DIDs it
     * controls. They MUST NOT be a sole trust or admission factor; use the
     * threshold/independence path (§7.3.5) for Sybil resistance.
     */
    suspend fun evaluateTrust(
        handle: ContextHandle,
        subjectDid: String,
        capabilityTokens: List<String> = emptyList(),
    ): TrustEvaluation {
        // Layer 1: AND-combine the structured per-stage booleans across tokens.
        // With no tokens every field stays false (no stage was observed to pass).
        var capabilityValidation =
            CapabilityValidation(
                tokensValid = false,
                signaturesValid = false,
                withinCeiling = false,
                nonceValid = false,
                notRevoked = false,
                timeBoundsValid = false,
            )
        if (capabilityTokens.isNotEmpty()) {
            var tokensValid = true
            var signaturesValid = true
            var withinCeiling = true
            var nonceValid = true
            var notRevoked = true
            var timeBoundsValid = true
            for (token in capabilityTokens) {
                val perToken = ucanEvaluate(handle = handle, token = token, presentingAgentDid = subjectDid)
                tokensValid = tokensValid && perToken.tokensValid
                signaturesValid = signaturesValid && perToken.signaturesValid
                withinCeiling = withinCeiling && perToken.withinCeiling
                nonceValid = nonceValid && perToken.nonceValid
                notRevoked = notRevoked && perToken.notRevoked
                timeBoundsValid = timeBoundsValid && perToken.timeBoundsValid
            }
            capabilityValidation =
                CapabilityValidation(
                    tokensValid = tokensValid,
                    signaturesValid = signaturesValid,
                    withinCeiling = withinCeiling,
                    nonceValid = nonceValid,
                    notRevoked = notRevoked,
                    timeBoundsValid = timeBoundsValid,
                )
        }

        // Label the evaluation with the SAME context the layers were computed
        // against (the handle's canonical id), and key the participation-record
        // lookup off it too.
        val resolvedContextId = handle.contextId()

        // Layer 2: behavioral record RECEIVED from the shared Rust core. An empty
        // event log (SCP-CTX-2076) is folded into a zeroed record — branching on
        // the STRUCTURED code, never error prose. No cached attestations are
        // supplied, so attestationCount reflects only the bridge's own trust
        // store (verifier-relative, §7.4).
        val behavioralRecord =
            try {
                participationRecord(contextId = resolvedContextId, subjectDid = subjectDid)
            } catch (e: uniffi.scp.ScpException.Context) {
                if (e.code != NO_PARTICIPATION_FACTS_CODE) throw e
                BehavioralRecord.zeroed(subjectDid = subjectDid)
            }

        return TrustEvaluation(
            subjectDid = subjectDid,
            contextId = resolvedContextId,
            capabilityValidation = capabilityValidation,
            behavioralRecord = behavioralRecord,
        )
    }

    /** Forwards to [NativeScp.ucanDelegate] on [inner]. */
    suspend fun ucanDelegate(
        handle: ContextHandle,
        delegatorDid: String,
        delegateeDid: String,
        parentToken: String,
        capabilities: List<String>,
    ): UcanToken =
        inner.ucanDelegate(
            handle = handle,
            delegatorDid = delegatorDid,
            delegateeDid = delegateeDid,
            parentToken = parentToken,
            capabilities = capabilities,
        )

    /** Forwards to [NativeScp.ucanMint] on [inner]. */
    suspend fun ucanMint(
        handle: ContextHandle,
        memberDid: String,
        capabilities: List<String>,
        proofs: List<String>?,
    ): UcanToken =
        inner.ucanMint(
            handle = handle,
            memberDid = memberDid,
            capabilities = capabilities,
            proofs = proofs,
        )

    /** Forwards to [NativeScp.ucanRevoke] on [inner]. */
    suspend fun ucanRevoke(
        handle: ContextHandle,
        token: String,
        revokerDid: String,
    ) = inner.ucanRevoke(
        handle = handle,
        token = token,
        revokerDid = revokerDid,
    )

    /**
     * Forwards to [NativeScp.ucanValidate] on [inner].
     *
     * [presentingAgentDid] is REQUIRED: the bridge fails closed on an absent
     * presenter rather than defaulting to the token's own `aud` (which would
     * make the audience check the tautology `aud == aud` and inflate trust).
     */
    suspend fun ucanValidate(
        handle: ContextHandle,
        token: String,
        capability: String,
        presentingAgentDid: String,
        proofTokens: List<String>?,
    ) = inner.ucanValidate(
        handle = handle,
        token = token,
        capability = capability,
        presentingAgentDid = presentingAgentDid,
        proofTokens = proofTokens,
    )

    /**
     * Verify participation profiles against admission requirements
     * (spec §7.3.2.1). Serializes the typed [RequireParticipation] /
     * [ParticipationProfile] values to the serde wire shape (ADR-058) and
     * routes through the UniFFI-generated free function
     * [uniffi.scp.verifyParticipationRequirements] unchanged. ADR-048 §1 + §7
     * Kotlin bullet.
     *
     * [expectedSubject] is the DID of the agent being admitted: only
     * profiles whose signed `subject_did` equals it contribute to any
     * threshold, freshness, or distinct-signer accounting, closing
     * cross-subject participation-profile replay.
     *
     * Returns normally when all requirements are satisfied; the bridge
     * throws on any failed requirement or malformed input.
     *
     * Security caveat — authenticity is not authorization: this verifies
     * signatures over the subject binding, not signer *legitimacy*. Because
     * `signer_public_key` is self-certifying, a subject can present
     * genuinely-signed profiles from signers it controls (inflating
     * `min_contexts`). Callers MUST establish signer legitimacy separately
     * (trusted-signer set, context-membership proof, or the §7.3.5
     * threshold/independence path) and MUST NOT treat success as authorization.
     */
    fun verifyParticipationRequirements(
        expectedSubject: String,
        requirements: List<RequireParticipation>,
        profiles: List<ParticipationProfile>,
    ) {
        uniffi.scp.verifyParticipationRequirements(
            expectedSubject = expectedSubject,
            requirementsJson = encodeRequireParticipationJson(requirements),
            profileJson = encodeParticipationProfileJson(profiles),
        )
    }

    /**
     * Verifies that an agent meets a context's capability requirements for
     * admission (spec §7.3.4.4, SCP-ACR-008). Serializes the typed
     * [CapabilityRequirement] / [ChallengeVerification] values (and the agent
     * capability URIs) to the serde wire shape (ADR-058) and routes through
     * the UniFFI-generated free function
     * [uniffi.scp.checkCapabilityRequirements] unchanged. ADR-048 §1 + §7
     * Kotlin bullet.
     *
     * [subjectDid]/[contextId] bind challenge verifications to the agent and
     * context being admitted: a [ChallengeVerification] only satisfies a
     * requirement when its signed `subject_did`/`context_id` equal these
     * values, closing cross-subject and cross-context attribution.
     *
     * Returns normally when all requirements are satisfied; the bridge throws
     * on any unmet requirement or malformed input.
     *
     * Security caveat — authenticity is not authorization: a passing
     * `ChallengeVerified` check proves the verifier's signature is authentic
     * and bound to this subject/context, NOT that the verifier is *trusted*.
     * Because `verifier_did` is self-certifying, a subject can present a
     * genuinely-signed result from a verifier it controls. Establish verifier
     * legitimacy separately and MUST NOT treat success as authorization.
     */
    fun checkCapabilityRequirements(
        contextId: String,
        subjectDid: String,
        requirements: List<CapabilityRequirement>,
        agentCapabilities: List<String>,
        challengeVerifications: List<ChallengeVerification>,
    ) {
        uniffi.scp.checkCapabilityRequirements(
            contextId = contextId,
            subjectDid = subjectDid,
            requirementsJson = encodeCapabilityRequirementsJson(requirements),
            agentCapabilitiesJson = encodeAgentCapabilitiesJson(agentCapabilities),
            challengeVerificationsJson = encodeChallengeVerificationsJson(challengeVerifications),
        )
    }

    companion object {
        /**
         * Constructs an [SCP] with an explicit storage configuration.
         *
         * Honors both [StorageConfig.InMemory] (encrypted in-memory,
         * ephemeral) and [StorageConfig.Sqlite] (SQLCipher-encrypted
         * on-disk, persistent). Prefer [withSqlite] when callers have a
         * directory and a raw key handy — it constructs the enum variant
         * for you.
         */
        fun withStorage(config: StorageConfig): SCP = SCP(NativeScp.withStorage(config))

        /**
         * Constructs an [SCP] backed by SQLCipher-encrypted on-disk storage.
         *
         * Convenience wrapper over [withStorage] for the common case:
         * given a directory and a raw encryption key, returns an [SCP]
         * whose underlying `UniffiBridgeInstance` persists context
         * snapshots and event log entries under `{dir}/scp.db`.
         *
         * The Rust bridge zeroizes its own copy of [key] after SQLCipher
         * consumes it internally; callers should zero their copy too
         * once the call returns. The directory is created implicitly
         * when SQLCipher opens the database file.
         *
         * @param dir Directory the database file is created in. Passed
         *   to the Rust side as `dir.absolutePath`.
         * @param key Raw encryption key material (typically 32 bytes).
         *   Callers are responsible for zeroizing their reference.
         */
        fun withSqlite(
            dir: File,
            key: ByteArray,
        ): SCP =
            SCP(
                NativeScp.withStorage(
                    StorageConfig.Sqlite(
                        path = dir.absolutePath,
                        key = SqliteKeyMaterial.Raw(key = key),
                    ),
                ),
            )

        /**
         * Constructs an [SCP] backed by SQLCipher-encrypted on-disk storage
         * whose key is derived from a passphrase via Argon2id (spec §17.6).
         *
         * Convenience wrapper over [withStorage] carrying
         * [SqliteKeyMaterial.Passphrase]. The passphrase derives the same
         * SQLCipher key on every open via a persisted per-database salt
         * sidecar (`{dir}/scp.salt`), so the same passphrase re-opens the
         * same database across restarts. The raw-key and passphrase paths
         * are mutually exclusive — the [SqliteKeyMaterial] sum type enforces
         * "exactly one".
         *
         * **Fail closed (spec §17.6):** if the database cannot be opened
         * (wrong passphrase against an existing DB, permission denied,
         * corrupt file, or a salt-sidecar fail-closed condition) this throws
         * `ScpException.Context` rather than silently degrading to in-memory
         * storage.
         *
         * The passphrase crosses the UniFFI boundary as a `String`; the Rust
         * side moves it into zeroizing memory before deriving the key.
         *
         * @param dir Directory the database (and salt sidecar) files live in.
         *   Passed to the Rust side as `dir.absolutePath`.
         * @param passphrase Human-chosen passphrase.
         */
        fun withSqlite(dir: File, passphrase: String): SCP =
            SCP(
                NativeScp.withStorage(
                    StorageConfig.Sqlite(
                        path = dir.absolutePath,
                        key = SqliteKeyMaterial.Passphrase(passphrase = passphrase),
                    ),
                ),
            )

        // Storage selection is mandatory (spec §17.6): the only
        // construction paths are [withStorage] / [withSqlite], both backed
        // by the typed `StorageConfig` enum. There is no zero-argument
        // factory that silently selects a backend.
    }
}
