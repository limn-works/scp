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

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import works.limn.scp.AssetEntry
import works.limn.scp.BatchPublishResult
import works.limn.scp.ConsequenceConfig
import works.limn.scp.ConsequenceRule
import works.limn.scp.encodeConsequenceConfigJson
import works.limn.scp.encodeConsequenceRulesJson
import works.limn.scp.validateContentPath
import works.limn.scp.validateDeployId
import works.limn.scp.validateMimeType
import works.limn.scp.BridgeConnectorBindings
import works.limn.scp.BridgeConnectorBridge
import works.limn.scp.DiscoveryBindings
import works.limn.scp.DiscoveryBridge
import works.limn.scp.EconomyBindings
import works.limn.scp.EconomyBridge
import works.limn.scp.IdentityAdvancedBindings
import works.limn.scp.IdentityAdvancedBridge
import works.limn.scp.InvitationBindings
import works.limn.scp.MetadataBindings
import works.limn.scp.MetadataBridge
import works.limn.scp.ProvenanceBindings
import works.limn.scp.ProvenanceBridge
import works.limn.scp.PublishResult
import works.limn.scp.ServerBindings
import works.limn.scp.ServerBridge
import works.limn.scp.SyncBindings
import works.limn.scp.SyncBridge
import works.limn.scp.TrustBindings
import works.limn.scp.auth.ScpIdBindings
import works.limn.scp.auth.ScpIdBridge
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
    /**
     * Creates a new DID identity with the specified custody method.
     *
     * Generates a new `did:dht` identity backed by the given custody type.
     * The returned handle retains key material for the identity's lifetime.
     *
     * @param custody Key custody method: `"in_memory"` (dev/test only, feature-gated),
     *   `"platform"` (Secure Enclave / Android Keystore), or `"software"`.
     * @return Opaque identity handle for use in subsequent operations.
     * @throws BridgeException with `SCP-IDENT-1008` if `"in_memory"` is requested
     *   but the `allow_in_memory_custody` feature is not enabled, or with
     *   `SCP-IDENT-1003` if `"platform"`/`"software"` is requested without a
     *   wired `KeyCustodyProvider`.
     */
    fun identityCreate(custody: String): Long

    /**
     * Loads an existing identity from storage by DID string.
     *
     * Returns a DID-string-only handle without local key material.
     * Key operations (signing, rotation) require a `KeyCustodyProvider`
     * callback to be wired separately.
     *
     * @param did The DID string to load (e.g., `"did:dht:z6Mk..."`).
     *   Only `did:dht` is currently supported.
     * @return Opaque identity handle.
     * @throws BridgeException with `SCP-IDENT-1004` if the DID method
     *   is not supported.
     */
    fun identityLoad(did: String): Long

    /**
     * Resolves a DID to its DID document via DHT lookup.
     *
     * Performs a network resolution of the given DID string and returns
     * the full DID document including verification methods, authentication
     * relationships, and service endpoints.
     *
     * @param did The DID string to resolve (e.g., `"did:dht:z6Mk..."`).
     * @return JSON-encoded DID document.
     * @throws BridgeException with `SCP-IDENT-1001` if resolution fails
     *   (not found on DHT, invalid format, or verification failure).
     */
    fun identityResolve(did: String): String
}

/**
 * Native binding functions for context operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched on [Dispatchers.IO].
 */
interface ContextBindings {
    /**
     * Creates a new SCP context with the given parameters.
     *
     * Registers the context in the shared `ContextManager`, derives a
     * context-scoped pseudonym routing ID, and initializes per-context
     * UCAN validation state (revocation list, nonce tracker, event log).
     *
     * @param identityHandle Opaque handle from [IdentityBindings.identityCreate]
     *   or [IdentityBindings.identityLoad].
     * @param paramsJson JSON-encoded context parameters (ceiling, governance
     *   model, memory scope, TTL, promotability, min protocol version).
     * @return Opaque context handle for use in subsequent context operations.
     * @throws BridgeException with `SCP-CTX-2001` if context creation fails
     *   or with `SCP-VALID-7000` if the identity DID is malformed.
     */
    fun contextCreate(
        identityHandle: Long,
        paramsJson: String,
        consequenceRulesJson: String? = null,
        consequenceConfigJson: String? = null,
    ): Long

    /**
     * Joins an existing SCP context.
     *
     * The context must be in `Active` state. Delegates to `ContextManager`
     * which validates version compatibility and adds the member with a
     * key package.
     *
     * @param contextHandle Opaque handle from [contextCreate].
     * @param identityHandle Opaque handle from [IdentityBindings.identityCreate]
     *   or [IdentityBindings.identityLoad].
     * @throws BridgeException with `SCP-CTX-2013` if the context is not
     *   in active state, or with `SCP-VALID-7000` if the DID is malformed.
     */
    fun contextJoin(
        contextHandle: Long,
        identityHandle: Long,
        spendingUcanJwt: String? = null,
    )

    /**
     * Leaves an SCP context gracefully (member-initiated).
     *
     * Removes the calling identity from the context's membership.
     * The context remains active for other members.
     *
     * @param contextHandle Opaque handle from [contextCreate] or [contextJoin].
     * @param identityHandle Opaque handle from [IdentityBindings.identityCreate]
     *   or [IdentityBindings.identityLoad].
     * @throws BridgeException with `SCP-CTX-2001` if the leave operation fails.
     */
    fun contextLeave(
        contextHandle: Long,
        identityHandle: Long,
    )

    /**
     * Closes an SCP context (admin action).
     *
     * Terminates the context for all members. Authorization is enforced
     * by the `ContextManager` via the `ContextClose` capability check.
     *
     * @param contextHandle Opaque handle from [contextCreate].
     * @param identityHandle Opaque handle from [IdentityBindings.identityCreate]
     *   or [IdentityBindings.identityLoad].
     * @throws BridgeException with `SCP-CTX-2001` if the close operation
     *   fails or the caller lacks the `ContextClose` capability.
     */
    fun contextClose(
        contextHandle: Long,
        identityHandle: Long,
    )

    /**
     * Sends a message to an SCP context.
     *
     * Creates an inner envelope with an Ed25519 signature over the payload
     * and delivers the message through the `ContextManager`'s transport
     * provider. The context must be in `Active` state.
     *
     * @param contextHandle Opaque handle from [contextCreate] or [contextJoin].
     * @param identityHandle Opaque handle from [IdentityBindings.identityCreate]
     *   or [IdentityBindings.identityLoad].
     * @param payload Raw message bytes (application content).
     * @throws BridgeException with `SCP-CTX-2019` if the context is not
     *   active, or with `SCP-CRYPTO-4001` if inner envelope signing fails.
     */
    fun contextSend(
        contextHandle: Long,
        identityHandle: Long,
        payload: ByteArray,
        spendingUcanJwt: String? = null,
    )

    /**
     * Subscribes to incoming messages on a context via a callback listener.
     *
     * The Kotlin SDK converts this callback into a cold [kotlinx.coroutines.flow.Flow]
     * via `callbackFlow`. The subscription starts when the flow is collected
     * and stops when the collector cancels.
     *
     * @param contextHandle Opaque handle from [contextCreate] or [contextJoin].
     * @param callback [MessageCallback] implementation invoked on message
     *   arrival, error, or subscription completion.
     * @return Opaque subscription handle for use with [contextUnsubscribe].
     * @throws BridgeException with `SCP-CTX-2021` if the context is not
     *   in active state.
     */
    fun contextSubscribe(
        contextHandle: Long,
        callback: MessageCallback,
    ): Long

    /**
     * Cancels a message subscription previously created by [contextSubscribe].
     *
     * Releases the Rust-side subscription resources. Idempotent: calling
     * this with an already-cancelled handle is a no-op.
     *
     * @param subscriptionHandle Handle returned by [contextSubscribe].
     */
    fun contextUnsubscribe(subscriptionHandle: Long)

    /**
     * Sets the economic policy for a context (spec section 19.3).
     *
     * Configures payment requirements, fee schedules, and economic
     * parameters for the context.
     *
     * @param contextHandle Opaque handle from [contextCreate] or [contextJoin].
     * @param policyJson JSON-encoded economic policy document.
     * @throws BridgeException if the policy JSON is invalid or the context
     *   is not in a valid state.
     */
    fun contextSetEconomicPolicy(
        contextHandle: Long,
        policyJson: String,
    )

    /**
     * Retrieves the current economic policy for a context.
     *
     * @param contextHandle Opaque handle from [contextCreate] or [contextJoin].
     * @return JSON-encoded economic policy, or `null` if no policy is set.
     */
    fun contextGetEconomicPolicy(contextHandle: Long): String?
}

/**
 * Native binding functions for membership queries.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched on [Dispatchers.IO].
 */
interface MembershipBindings {
    /**
     * Returns the number of members in a context.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @return The member count, or `null` if the context is not registered
     *   in the `ContextManager`.
     */
    fun contextMemberCount(contextHandle: Long): Long?

    /**
     * Checks whether a DID is a member of a context.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @param did The DID string to check membership for.
     * @return `true` if the DID is a current member of the context.
     */
    fun contextIsMember(
        contextHandle: Long,
        did: String,
    ): Boolean

    /**
     * Returns all member DIDs in a context.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @return List of DID strings for all current members.
     */
    fun contextMemberDids(contextHandle: Long): List<String>

    /**
     * Returns the role assigned to a member in a context.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @param did The DID of the member to query.
     * @return The role string (e.g., `"admin"`, `"member"`), or `null`
     *   if the DID is not a member of the context.
     */
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
    /**
     * Executes an approved governance action on a context.
     *
     * All 24 governance action variants (ADR-031) are supported. The
     * proposal must have `Approved` status. Role state is re-synced
     * from the `ContextManager` after execution.
     *
     * @param contextHandle Opaque handle from context create.
     * @param proposalJson JSON-serialized `GovernanceProposal` with
     *   `Approved` status.
     * @return JSON string describing the governance action result
     *   (e.g., `"MemberAdded"`, `"RoleChanged"`, `"ContextClosed"`).
     * @throws BridgeException with `SCP-PERM-3001` if the proposal is
     *   not approved or targets the wrong context, or with `SCP-CTX-2001`
     *   for other governance execution failures.
     */
    fun governanceExecute(
        contextHandle: Long,
        proposalJson: String,
    ): String

    /**
     * Proposes a governance action for voting.
     *
     * For `SingleAdmin` contexts, the proposal is auto-approved and
     * executed immediately. For multi-admin governance models, the
     * proposal enters `Pending` status and requires approval votes.
     *
     * @param contextHandle Opaque handle from context create.
     * @param proposerDid DID of the member submitting the proposal.
     * @param actionJson JSON-serialized governance action to propose.
     * @return JSON string with `proposal_id`, `status`, and
     *   `execution_result` (if auto-approved).
     * @throws BridgeException if the proposer lacks permission or
     *   the action JSON is malformed.
     */
    fun governancePropose(
        contextHandle: Long,
        proposerDid: String,
        actionJson: String,
    ): String

    /**
     * Casts an approval vote on a pending governance proposal.
     *
     * @param contextHandle Opaque handle from context create.
     * @param voterDid DID of the voting member.
     * @param proposalIdHex Hex-encoded 32-byte proposal identifier.
     * @return JSON string with updated proposal `status`.
     * @throws BridgeException if the proposal is not found, is not
     *   pending, or the voter lacks permission.
     */
    fun governanceApprove(
        contextHandle: Long,
        voterDid: String,
        proposalIdHex: String,
    ): String

    /**
     * Casts a rejection vote on a pending governance proposal.
     *
     * @param contextHandle Opaque handle from context create.
     * @param voterDid DID of the voting member.
     * @param proposalIdHex Hex-encoded 32-byte proposal identifier.
     * @return JSON string with updated proposal `status`.
     * @throws BridgeException if the proposal is not found, is not
     *   pending, or the voter lacks permission.
     */
    fun governanceReject(
        contextHandle: Long,
        voterDid: String,
        proposalIdHex: String,
    ): String

    /**
     * Withdraws a previously cast vote on a pending governance proposal.
     *
     * @param contextHandle Opaque handle from context create.
     * @param voterDid DID of the member withdrawing their vote.
     * @param proposalIdHex Hex-encoded 32-byte proposal identifier.
     * @return JSON string with updated proposal `status`.
     * @throws BridgeException if the proposal is not found or the
     *   voter has not voted on it.
     */
    fun governanceWithdraw(
        contextHandle: Long,
        voterDid: String,
        proposalIdHex: String,
    ): String

    /**
     * Retrieves a single governance proposal by its hex-encoded ID.
     *
     * @param contextHandle Opaque handle from context create.
     * @param proposalIdHex Hex-encoded 32-byte proposal identifier.
     * @return JSON string with full proposal details including action,
     *   status, votes, and execution result.
     * @throws BridgeException if the proposal is not found.
     */
    fun governanceGetProposal(
        contextHandle: Long,
        proposalIdHex: String,
    ): String

    /**
     * Lists all governance proposals for a context.
     *
     * @param contextHandle Opaque handle from context create.
     * @return JSON array of proposal objects.
     */
    fun governanceListProposals(contextHandle: Long): String

    /**
     * Applies a pending ceiling modification if the notification period has elapsed (#559).
     *
     * @param contextHandle Opaque handle from context create.
     * @param currentTimestamp Current Unix timestamp in seconds.
     * @return `true` if the modification was applied, `false` otherwise.
     */
    fun applyPendingCeilingModification(
        contextHandle: Long,
        currentTimestamp: Long,
    ): Boolean

    /**
     * Finalizes the cooperative close flow for a context in Closing state (#559).
     *
     * @param contextHandle Opaque handle from context create.
     */
    fun finalizeClose(contextHandle: Long)

    /**
     * Creates a governance checkpoint (ADR-031 section 9, #559).
     *
     * @param contextHandle Opaque handle from context create.
     * @param checkpointSeq Sequence number.
     * @param merkleRootHex Hex-encoded 32-byte Merkle root.
     * @param eventCount Number of events.
     * @param lastEventHashHex Hex-encoded 32-byte hash.
     * @param stateSnapshotHashHex Hex-encoded 32-byte hash.
     * @param creatorDid DID of the creator.
     * @param creatorSignatureHex Hex-encoded Ed25519 signature.
     * @return JSON string with the checkpoint object.
     */
    @Suppress("LongParameterList")
    fun createGovernanceCheckpoint(
        contextHandle: Long,
        checkpointSeq: Long,
        merkleRootHex: String,
        eventCount: Long,
        lastEventHashHex: String,
        stateSnapshotHashHex: String,
        creatorDid: String,
        creatorSignatureHex: String,
    ): String

    /**
     * Adds a cosignature to an existing checkpoint (ADR-031 section 9, #559).
     *
     * @param contextHandle Opaque handle from context create.
     * @param checkpointJson JSON-serialized checkpoint.
     * @param signerDid DID of the cosigner.
     * @param signatureHex Hex-encoded Ed25519 signature.
     * @return JSON string with attestation status and updated checkpoint.
     */
    fun addCheckpointCosignature(
        contextHandle: Long,
        checkpointJson: String,
        signerDid: String,
        signatureHex: String,
    ): String

    /**
     * Restores a single persisted context from storage (#559).
     *
     * @param contextId The context ID to restore.
     */
    fun restoreContext(contextId: String)

    /**
     * Restores all persisted contexts from storage (#559).
     *
     * @return JSON array of restored context ID strings.
     */
    fun restoreAllContexts(): String
}

/**
 * Native binding functions for broadcast operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched on [Dispatchers.IO].
 */
interface BroadcastBindings {
    /**
     * Subscribes a DID to receive broadcast messages in a context.
     *
     * Adds the subscriber to the broadcast group, granting them access
     * to the current sender key for decryption.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @param subscriberDid DID of the entity subscribing to broadcasts.
     * @throws BridgeException if subscription fails (e.g., admission
     *   policy rejection, context not active).
     */
    fun broadcastSubscribe(
        contextHandle: Long,
        subscriberDid: String,
    )

    /**
     * Unsubscribes a DID from a broadcast context.
     *
     * Removes the subscriber from the broadcast group. Optionally rotates
     * the sender key so the unsubscribed party cannot decrypt future messages.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @param subscriberDid DID of the entity to unsubscribe.
     * @param rotateKeys Whether to rotate broadcast keys after removal.
     *   Set to `true` when revoking access for security.
     * @throws BridgeException if unsubscription fails.
     */
    fun broadcastUnsubscribe(
        contextHandle: Long,
        subscriberDid: String,
        rotateKeys: Boolean,
    )

    /**
     * Publishes a message to all broadcast subscribers in a context.
     *
     * The message is encrypted with the current sender key so only
     * active subscribers can decrypt it.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @param identityHandle Opaque handle from [IdentityBindings.identityCreate]
     *   or [IdentityBindings.identityLoad] for the publishing author.
     * @param payload Raw message bytes to broadcast.
     * @throws BridgeException if publishing fails (e.g., author is not
     *   the broadcast owner, context not active).
     */
    fun broadcastPublish(
        contextHandle: Long,
        identityHandle: Long,
        payload: ByteArray,
    )

    /**
     * Blocks a subscriber's read access in a broadcast context (spec section 9.16).
     *
     * The blocked subscriber can no longer decrypt new messages. The sender
     * key is rotated so content published after the block is inaccessible
     * to the blocked party.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @param subscriberDid DID of the subscriber to block.
     * @param blockerDid DID of the author performing the block.
     * @throws BridgeException if the blocker lacks permission or the
     *   subscriber is not found.
     */
    fun broadcastBlockSubscriber(
        contextHandle: Long,
        subscriberDid: String,
        blockerDid: String,
    )

    /**
     * Unblocks a previously blocked subscriber in a broadcast context
     * (spec section 9.16.8).
     *
     * Forward-only restoration: the unblocked subscriber can request the
     * current key on the next pull but cannot decrypt content from the
     * block period.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @param subscriberDid DID of the subscriber to unblock.
     * @param unblockerDid DID of the author performing the unblock.
     * @throws BridgeException if the unblocker lacks permission.
     */
    fun broadcastUnblockSubscriber(
        contextHandle: Long,
        subscriberDid: String,
        unblockerDid: String,
    )

    /**
     * Handles a broadcast key request from a subscriber.
     *
     * Evaluates whether the requester should receive the current sender
     * key based on admission policy and block status.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @param authorDid DID of the broadcast author handling the request.
     * @param requesterDid DID of the subscriber requesting the key.
     * @return JSON string describing the key request decision.
     * @throws BridgeException if the request cannot be processed.
     */
    fun broadcastHandleKeyRequest(
        contextHandle: Long,
        authorDid: String,
        requesterDid: String,
    ): String

    /**
     * Returns the number of active broadcast subscribers for a context.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @return The subscriber count, or `null` if this is not a broadcast
     *   context or the context is not registered.
     */
    fun broadcastSubscriberCount(contextHandle: Long): Long?

    /**
     * Checks whether a DID is an active broadcast subscriber.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @param did The DID to check.
     * @return `true` if the DID is a current broadcast subscriber.
     */
    fun broadcastIsSubscriber(
        contextHandle: Long,
        did: String,
    ): Boolean

    /**
     * Returns the broadcast admission policy for a context.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @return The admission policy string (`"Open"` or `"Gated"`), or
     *   `null` if this is not a broadcast context.
     */
    fun broadcastAdmission(contextHandle: Long): String?

    /**
     * Publishes a single asset to a broadcast context as structured content (SCP-290).
     *
     * Constructs a `BroadcastContent` from the asset entry, computes an `ETag`,
     * and publishes via the broadcast content delivery layer.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @param identityHandle Opaque handle for the publishing author.
     * @param assetJson JSON-encoded asset entry (`path`, `content_type`, `body`).
     * @param deployId Optional deploy ID to group assets into atomic deploys.
     * @return JSON-encoded publish result (`blob_id`, `etag`).
     * @throws BridgeException if validation or publish fails.
     */
    fun broadcastPublishAsset(
        contextHandle: Long,
        identityHandle: Long,
        assetJson: String,
        deployId: String?,
    ): String

    /**
     * Publishes multiple assets to a broadcast context as structured content (SCP-290).
     *
     * All assets are published with the same deploy ID (auto-generated if not
     * provided). Returns a JSON array of publish results.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @param identityHandle Opaque handle for the publishing author.
     * @param assetsJson JSON-encoded array of asset entries.
     * @param deployId Optional deploy ID to group assets into atomic deploys.
     * @return JSON-encoded array of publish results.
     * @throws BridgeException if any asset fails validation or publish.
     */
    fun broadcastPublishAssets(
        contextHandle: Long,
        identityHandle: Long,
        assetsJson: String,
        deployId: String?,
    ): String
}

/**
 * Native binding functions for tool operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched on [Dispatchers.IO].
 */
interface ToolBindings {
    /**
     * Registers a tool in an SCP context.
     *
     * Validates the tool definition (name, input/output JSON schemas,
     * test vectors, implementation hash) and adds it to the context's
     * tool registry. The context must be in `Active` state.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @param definitionJson JSON-encoded tool definition including `name`,
     *   `description`, `input_schema_json`, `output_schema_json`,
     *   `operator_did`, and optional `test_vectors_json` and
     *   `implementation_hash`.
     * @return The assigned tool ID string (derived from the tool name).
     * @throws BridgeException with `SCP-TOOL-6003` if the context is not
     *   active, with `SCP-VALID-7035`/`SCP-VALID-7036` if schemas are
     *   invalid, or with `SCP-TOOL-6001` if registration fails.
     */
    fun toolRegister(
        contextHandle: Long,
        definitionJson: String,
    ): String

    /**
     * Invokes a registered tool in an SCP context.
     *
     * Validates the input against the tool's JSON schema, checks UCAN
     * authorization via the full 11-step ADR-016 pipeline, and dispatches
     * to the tool handler if one is registered. The context must be in
     * `Active` state.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @param toolId The tool's assigned ID from [toolRegister].
     * @param inputJson JSON-encoded tool input matching the tool's
     *   input schema.
     * @param identityHandle Opaque handle for the invoker's identity
     *   (used for capability checking).
     * @param ucanToken Optional JWT-encoded UCAN token authorizing the
     *   invocation. Must contain `tool_invoke:{tool_id}` or
     *   `tool_invoke:*` capability.
     * @param proofTokens Optional list of encoded parent UCAN tokens
     *   for delegation chain traversal (ADR-016 step 3).
     * @return JSON-encoded tool output.
     * @throws BridgeException with `SCP-TOOL-6005` if the context is not
     *   active, with `SCP-TOOL-6002` if invocation fails, or with
     *   `SCP-PERM-3001` if UCAN authorization fails.
     */
    @Suppress("LongParameterList") // FFI bridge — must match UniFFI export signature
    fun toolInvoke(
        contextHandle: Long,
        toolId: String,
        inputJson: String,
        identityHandle: Long,
        ucanToken: String?,
        proofTokens: List<String>?,
        spendingUcan: String?,
    ): String

    /**
     * Verifies a tool's registration status in an SCP context.
     *
     * Checks that the tool is registered and returns its verification
     * result including whether it passed and any failure details.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @param toolId The tool's assigned ID.
     * @return JSON-encoded verification result with `tool_id`, `passed`,
     *   and `failures` fields.
     * @throws BridgeException with `SCP-TOOL-6007` if the context is not
     *   active or verification encounters an error.
     */
    fun toolVerify(
        contextHandle: Long,
        toolId: String,
    ): String

    /**
     * Exposes a tool interface for cross-context sharing (§6.2.0.1 step 1).
     *
     * @param contextHandle Opaque handle for the source context.
     * @param toolId The ID of the tool to expose.
     * @param targetContextId The target context to expose the tool to.
     * @param rateLimitJson Optional per-interface rate limit as JSON.
     * @return JSON-encoded ToolInterface with `approved_by_source = true`.
     * @throws BridgeException with `SCP-TOOL-6030` if the caller is not
     *   an admin or the tool is not found.
     */
    fun toolInterfaceExpose(
        contextHandle: Long,
        toolId: String,
        targetContextId: String,
        rateLimitJson: String?,
    ): String

    /**
     * Accepts a cross-context tool interface (§6.2.0.1 step 4).
     *
     * @param contextHandle Opaque handle for the target context.
     * @param interfaceJson The ToolInterface JSON string to accept.
     * @return JSON-encoded updated ToolInterface with `approved_by_target = true`.
     * @throws BridgeException with `SCP-TOOL-6032` if the caller is not
     *   an admin or context mismatch.
     */
    fun toolInterfaceAccept(
        contextHandle: Long,
        interfaceJson: String,
    ): String

    /**
     * Revokes a cross-context tool interface (§6.2.0.1 step 5).
     *
     * @param contextHandle Opaque handle for the revoking context.
     * @param interfaceIdHex The 32-byte interface/offer ID as hex.
     * @return JSON-encoded InterfaceRevoked event.
     * @throws BridgeException with `SCP-VALID-7042` if hex is invalid.
     */
    fun toolInterfaceRevoke(
        contextHandle: Long,
        interfaceIdHex: String,
    ): String

    /**
     * Invokes a tool across context boundaries (spec section 6.2).
     *
     * Validates UCAN authorization against the target context, chain depth,
     * source context capability, and target context tool existence.
     *
     * @param sourceContextHandle Opaque handle for the calling (source) context.
     * @param targetContextHandle Opaque handle for the context containing the tool.
     * @param toolId The tool's assigned ID.
     * @param inputJson JSON-encoded tool input.
     * @param identityHandle Handle for the invoker's identity.
     * @param ucanToken JWT-encoded UCAN token authorizing the invocation.
     * @param chainDepth Current cross-context chain depth (0 for first hop).
     *   Context-configurable max (default 8), range 0-255 (ADR-043, spec §24.4).
     * @param proofTokens Optional parent UCAN tokens for delegation chain.
     * @return JSON-encoded tool output.
     * @throws BridgeException with `SCP-TOOL-6010` if source context not active,
     *   `SCP-TOOL-6011` if target context not active, `SCP-TOOL-6012` if chain
     *   depth exceeded, `SCP-TOOL-6002` if tool not found.
     */
    @Suppress("LongParameterList") // FFI bridge — must match UniFFI export signature
    fun toolInvokeCrossContext(
        sourceContextHandle: Long,
        targetContextHandle: Long,
        toolId: String,
        inputJson: String,
        identityHandle: Long,
        ucanToken: String,
        chainDepth: Int,
        proofTokens: List<String>?,
    ): String

    /**
     * Creates a stateful tool session (spec section 6.2.1).
     *
     * Sessions enable multi-turn workflows with state preservation across
     * invocations. Subject to per-caller caps (default: 1000 concurrent sessions, ADR-043).
     *
     * @param contextHandle Opaque handle for the context containing the tool.
     * @param toolId The tool to create a session for.
     * @param sourceContextId The calling context ID (session cap tracked per caller).
     * @param ttlSeconds Optional time-to-live in seconds, or null for context-lifetime.
     * @return The session ID (UUID string).
     * @throws BridgeException with `SCP-TOOL-6014` if context not active,
     *   `SCP-TOOL-6015` if session cap exceeded.
     */
    fun toolSessionCreate(
        contextHandle: Long,
        toolId: String,
        sourceContextId: String,
        ttlSeconds: Long?,
    ): String

    /**
     * Invokes a tool within an active session.
     *
     * Each call is individually governed: the invoker must present a valid
     * UCAN token. Session state is carried forward across invocations.
     *
     * @param contextHandle Opaque handle for the context containing the session.
     * @param sessionId The session ID from [toolSessionCreate].
     * @param inputJson JSON-encoded tool input.
     * @param identityHandle Handle for the invoker's identity.
     * @param ucanToken JWT-encoded UCAN token authorizing the invocation.
     * @param proofTokens Optional parent UCAN tokens for delegation chain.
     * @return JSON-encoded tool output.
     * @throws BridgeException with `SCP-TOOL-6017` if context not active,
     *   `SCP-TOOL-6018` if session not found, `SCP-TOOL-6019` if expired.
     */
    @Suppress("LongParameterList") // FFI bridge — must match UniFFI export signature
    fun toolSessionInvoke(
        contextHandle: Long,
        sessionId: String,
        inputJson: String,
        identityHandle: Long,
        ucanToken: String,
        proofTokens: List<String>?,
    ): String

    /**
     * Closes a stateful tool session.
     *
     * Removes the session, releasing the caller's session slot.
     *
     * @param contextHandle Opaque handle for the context containing the session.
     * @param sessionId The session ID to close.
     * @throws BridgeException with `SCP-TOOL-6021` if session not found.
     */
    fun toolSessionClose(
        contextHandle: Long,
        sessionId: String,
    )
}

/**
 * Native binding functions for UCAN operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched on [Dispatchers.IO].
 */
interface UcanBindings {
    /**
     * Validates a UCAN token for a specific capability in a context.
     *
     * Executes the full 11-step ADR-016 validation pipeline: JWT parsing,
     * Ed25519 signature verification, time-bound checks, nonce replay
     * prevention, revocation checking, delegation chain traversal, and
     * capability ceiling enforcement.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @param token The UCAN token string (JWT-encoded).
     * @param capability The capability URI to validate against (e.g.,
     *   `"scp:ctx:abc123/messages:write"`).
     * @param presentingAgentDid Optional DID of the presenting agent
     *   for delegation chain verification.
     * @param proofTokens Optional list of encoded parent UCAN tokens
     *   for delegation chain traversal (ADR-016 step 3).
     * @throws BridgeException with `SCP-PERM-3002` if validation fails
     *   (malformed token, expired, revoked, nonce replay, insufficient
     *   capability, or invalid signature).
     */
    fun ucanValidate(
        contextHandle: Long,
        token: String,
        capability: String,
        presentingAgentDid: String?,
        proofTokens: List<String>?,
    )

    /**
     * Mints a new UCAN token delegating capabilities to a member DID.
     *
     * Uses the context creator's retained key custody and active signing
     * key to produce a real Ed25519-signed UCAN token via
     * `scp_core::crypto::ucan::mint::mint_ucan`. Capabilities are
     * automatically scoped to the context. Enforces ceiling constraints.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @param memberDid The DID of the member receiving the token.
     * @param capabilitiesJson JSON-encoded list of capability URI strings
     *   to grant (e.g., `["messages:write", "tool_invoke:*"]`).
     * @return The minted UCAN token string (JWT-encoded).
     * @throws BridgeException with `SCP-VALID-7000` if `memberDid` is
     *   malformed, or with `SCP-PERM-3004` if the context lacks key
     *   custody for signing.
     */
    fun ucanMint(
        contextHandle: Long,
        memberDid: String,
        capabilitiesJson: String,
    ): String

    /**
     * Revokes a previously minted UCAN token.
     *
     * Adds the token to the context's revocation list. Subsequent
     * validation calls for this token will fail. Revocation is
     * idempotent: revoking a non-existent or already-revoked token
     * succeeds silently.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @param token The full encoded JWT string of the token to revoke.
     * @throws BridgeException if the revocation operation fails.
     */
    fun ucanRevoke(
        contextHandle: Long,
        token: String,
        revokerDid: String,
    )

    /**
     * Delegates a UCAN token to another entity with attenuated capabilities.
     *
     * Creates a new UCAN derived from a parent token, signed with the
     * delegator's Ed25519 key. Delegation enforces attenuation:
     * capabilities can only narrow, never widen. The delegator must be
     * the audience of the parent token.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @param delegatorDid DID of the entity delegating (must match the
     *   parent token's audience).
     * @param delegateeDid DID of the entity receiving the delegation.
     * @param parentToken The encoded parent UCAN token (JWT format).
     * @param capabilitiesJson JSON-encoded list of capability URIs to
     *   delegate (must be a subset of the parent's capabilities).
     * @return The delegated UCAN token string (JWT-encoded).
     * @throws BridgeException with `SCP-PERM-3001` if delegation fails
     *   (capabilities wider than parent, invalid parent token, or
     *   delegator is not the parent's audience).
     */
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
    /**
     * Queries the context event log with optional filters.
     *
     * Returns events from the Merkle-backed event log, filtered by
     * event type, actor DID, sequence range, and/or result limit. If no
     * stored events match, returns a `LogSummary` event with the current
     * Merkle root and event count.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @param filterJson JSON-encoded query filter with optional fields:
     *   `event_type` (string), `actor_did` (string), `after_sequence`
     *   (number), `before_sequence` (number), `limit` (number).
     * @return JSON-encoded list of event log entries.
     * @throws BridgeException with `SCP-CTX-2023` if the context is not
     *   found or the filter JSON is invalid.
     */
    fun eventLogQuery(
        contextHandle: Long,
        filterJson: String,
    ): String

    /**
     * Verifies a claim against the context event log using a Merkle proof.
     *
     * Generates and verifies an inclusion or absence proof for the given
     * claim against the event log's Merkle tree.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @param claimJson JSON-encoded claim with `type` (`"inclusion"` or
     *   `"absence"`), `leaf_index` (for inclusion proofs), or
     *   `event_hash` (hex-encoded, for absence proofs).
     * @return `true` if the Merkle proof is valid.
     * @throws BridgeException with `SCP-CTX-2025` if the claim JSON is
     *   invalid, or with `SCP-CTX-2026` if verification fails (empty
     *   log, invalid index, etc.).
     */
    fun eventLogVerify(
        contextHandle: Long,
        claimJson: String,
    ): Boolean

    /**
     * Generates a signed consistency checkpoint for equivocation detection.
     *
     * Creates a signed snapshot of the event log's Merkle root at the
     * given MLS epoch. Members exchange checkpoints to detect relay
     * equivocation: differing Merkle roots for the same event count
     * indicate the relay is showing different histories to different
     * members.
     *
     * @param contextHandle Opaque handle from context create or join.
     * @param identityHandle Opaque handle from identity create or load.
     *   Must have retained key custody for Ed25519 signing.
     * @param epoch The MLS epoch to checkpoint at.
     * @return JSON-encoded checkpoint containing `context_id`,
     *   `sender_did`, `event_count`, `merkle_root`, `epoch`,
     *   `signature`, and `timestamp`.
     * @throws BridgeException with `SCP-PERM-3008` if the identity
     *   lacks key custody, or with `SCP-CTX-2027` if checkpoint
     *   generation fails.
     */
    fun eventLogCheckpoint(
        contextHandle: Long,
        identityHandle: Long,
        epoch: Long,
    ): String

    /**
     * Connects to a transport relay.
     *
     * Establishes a WebSocket connection to an SCP relay at the URL
     * specified in the configuration. This is a potentially long-running
     * operation that supports cancellation via [CancellationHandle].
     *
     * @param configJson JSON-encoded transport configuration including
     *   the relay URL.
     * @param cancellationHandle Optional handle for propagating coroutine
     *   cancellation to the Rust engine during connection establishment.
     * @return Opaque transport handle for use with [transportStatus]
     *   and [transportDisconnect].
     * @throws BridgeException with `SCP-TRANS-5001` if connection fails
     *   (invalid URL, network error, relay unreachable).
     */
    fun transportConnect(
        configJson: String,
        cancellationHandle: CancellationHandle?,
    ): Long

    /**
     * Queries the status of a transport connection.
     *
     * Returns the current connection state including whether the
     * transport is connected, the relay URL, and round-trip latency.
     *
     * @param transportHandle Opaque handle from [transportConnect].
     * @return JSON-encoded transport status with `connected` (boolean),
     *   `relay_url` (string or null), and `latency_ms` (number or null).
     */
    fun transportStatus(transportHandle: Long): String

    /**
     * Disconnects from a transport relay.
     *
     * Clears the relay adapter and releases the WebSocket connection.
     * After this call, the transport reports disconnected status.
     * Idempotent: calling when already disconnected is a no-op.
     *
     * @param transportHandle Opaque handle from [transportConnect].
     */
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
 * @property identityAttestation Identity link attestation CRUD bindings (§3.5).
 * @property scpId SCPID DID authentication bindings (spec section 3.11).
 * @property trust Trust aggregation bindings.
 * @property economy Economic governance bindings.
 * @property invitation Invitation evaluation bindings.
 */
data class ExtendedBindings(
    val provenance: ProvenanceBindings? = null,
    val sync: SyncBindings? = null,
    val discovery: DiscoveryBindings? = null,
    val bridgeConnector: BridgeConnectorBindings? = null,
    val identityAdvanced: IdentityAdvancedBindings? = null,
    val scpId: ScpIdBindings? = null,
    val trust: TrustBindings? = null,
    val metadata: MetadataBindings? = null,
    val economy: EconomyBindings? = null,
    val invitation: InvitationBindings? = null,
    val server: ServerBindings? = null,
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
    /** Raw extended bindings for direct access by domain wrappers. */
    internal val extended: ExtendedBindings = extendedBindings ?: ExtendedBindings()

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

    /** SCPID authentication operations — FFI on IO. Null if bindings not provided. */
    val scpId: ScpIdBridge? =
        extendedBindings?.scpId?.let {
            ScpIdBridge(it, this)
        }

    /** Metadata and template operations — FFI on IO. Null if bindings not provided. */
    val metadata: MetadataBridge? =
        extendedBindings?.metadata?.let {
            MetadataBridge(it, this)
        }

    /** Economy governance operations — FFI on IO. Null if bindings not provided. */
    val economy: EconomyBridge? =
        extendedBindings?.economy?.let {
            EconomyBridge(it, this)
        }

    /** Server lifecycle operations — FFI on IO. Null if bindings not provided. */
    val server: ServerBridge? =
        extendedBindings?.server?.let {
            ServerBridge(it, this)
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
     * Execute a `suspend` FFI call on [Dispatchers.IO] with cancellation checks.
     *
     * The companion of [ffiCall] for UniFFI-generated async methods. UniFFI
     * compiles `async fn` Rust functions into Kotlin `suspend fun` bindings
     * (e.g., `Scp.shutdown(timeoutMillis)`), which cannot be invoked from the
     * non-suspend `() -> T` lambda accepted by [ffiCall].
     *
     * @param block The suspend FFI operation.
     * @return The FFI call result.
     * @throws CancellationException if the coroutine was cancelled.
     * @throws BridgeException if the FFI call fails.
     */
    internal suspend fun <T> ffiCallSuspend(block: suspend () -> T): T =
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
     * @param consequenceRulesJson Optional JSON-encoded array of consequence
     *   rules (ADR-017, #1531). When non-null, parsed by the bridge into the
     *   stored `ContextParams.consequence_rules`.
     * @param consequenceConfigJson Optional JSON-encoded
     *   `ConsequenceConfig` document (ADR-017, #1531). When non-null, parsed
     *   by the bridge into the stored `ContextParams.consequence_config`.
     *   Defaults to the protocol default
     *   (`allow_automatic_access_revocation = false`) when omitted.
     * @return Opaque context handle.
     */
    suspend fun create(
        identityHandle: Long,
        paramsJson: String,
        consequenceRulesJson: String? = null,
        consequenceConfigJson: String? = null,
    ): Long =
        bridge.ffiCall {
            bindings.contextCreate(
                identityHandle,
                paramsJson,
                consequenceRulesJson,
                consequenceConfigJson,
            )
        }

    /**
     * Create a new context using typed [ConsequenceRule] / [ConsequenceConfig]
     * shapes (H15).
     *
     * Encodes the typed values to the Rust serde wire format internally via
     * [encodeConsequenceRulesJson] / [encodeConsequenceConfigJson], then
     * delegates to the JSON-string overload above. This is the preferred
     * SDK entry point — call sites should not hand-roll JSON for consequence
     * rules.
     *
     * @param identityHandle Handle from identity create or load.
     * @param paramsJson JSON-encoded base context parameters (ceiling,
     *   governance, etc). Consequence rules and config travel in the typed
     *   parameters below, NOT in this JSON blob.
     * @param consequenceRules Typed list of consequence rules; `null` omits.
     * @param consequenceConfig Typed per-context config; `null` omits and the
     *   protocol default applies (`allowAutomaticAccessRevocation = false`).
     * @return Opaque context handle.
     */
    suspend fun create(
        identityHandle: Long,
        paramsJson: String,
        consequenceRules: List<ConsequenceRule>?,
        consequenceConfig: ConsequenceConfig?,
    ): Long {
        val rulesJson = consequenceRules?.let { encodeConsequenceRulesJson(it) }
        val configJson = consequenceConfig?.let { encodeConsequenceConfigJson(it) }
        return create(
            identityHandle = identityHandle,
            paramsJson = paramsJson,
            consequenceRulesJson = rulesJson,
            consequenceConfigJson = configJson,
        )
    }

    /**
     * Join an existing context.
     *
     * @param contextHandle Handle from context create.
     * @param identityHandle Handle from identity create or load.
     */
    suspend fun join(
        contextHandle: Long,
        identityHandle: Long,
        spendingUcanJwt: String? = null,
    ): Unit = bridge.ffiCall { bindings.contextJoin(contextHandle, identityHandle, spendingUcanJwt) }

    /**
     * Leave a context gracefully (member action).
     *
     * @param contextHandle Handle from context create or join.
     * @param identityHandle Handle from identity create or load.
     */
    suspend fun leave(
        contextHandle: Long,
        identityHandle: Long,
    ): Unit = bridge.ffiCall { bindings.contextLeave(contextHandle, identityHandle) }

    /**
     * Close a context (admin action). Terminates the context for all members.
     *
     * @param contextHandle Handle from context create.
     * @param identityHandle Handle from identity create or load.
     */
    suspend fun close(
        contextHandle: Long,
        identityHandle: Long,
    ): Unit = bridge.ffiCall { bindings.contextClose(contextHandle, identityHandle) }

    /**
     * Send a message to a context.
     *
     * @param contextHandle Handle from context create or join.
     * @param identityHandle Handle from identity create or load.
     * @param payload Raw message bytes.
     */
    suspend fun send(
        contextHandle: Long,
        identityHandle: Long,
        payload: ByteArray,
        spendingUcanJwt: String? = null,
    ): Unit =
        bridge.ffiCall {
            bindings.contextSend(contextHandle, identityHandle, payload, spendingUcanJwt)
        }

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
     * Tool invocation flows through the runtime's full economy
     * pipeline (`ContextManager::invoke_tool_with_economy`):
     * per-invocation pricing, per-DID velocity tracking, escalation,
     * budget enforcement, payment escrow, and the Matrix-style hard
     * rate limit are all enforced inside the runtime. See PR #1606 / C4.
     *
     * @param contextHandle Handle from context create or join.
     * @param toolId The tool's assigned ID.
     * @param inputJson JSON-encoded tool input.
     * @param identityHandle Handle for the invoker's identity.
     * @param ucanToken Optional UCAN token authorizing the invocation.
     * @param proofTokens Optional parent UCAN tokens for delegation chain.
     * @param spendingUcan Optional JWT-encoded `SpendingCapability` UCAN
     *   for paid tool invocations under spec section 19.5
     *   (AND-composition with the action UCAN). May be `null` for free
     *   tools.
     * @return JSON-encoded tool output.
     */
    @Suppress("LongParameterList") // FFI bridge — must match UniFFI export signature
    suspend fun invoke(
        contextHandle: Long,
        toolId: String,
        inputJson: String,
        identityHandle: Long,
        ucanToken: String?,
        proofTokens: List<String>? = null,
        spendingUcan: String? = null,
    ): String =
        bridge.ffiCall {
            bindings.toolInvoke(
                contextHandle,
                toolId,
                inputJson,
                identityHandle,
                ucanToken,
                proofTokens,
                spendingUcan,
            )
        }

    /**
     * Verify a tool's registration status in a context.
     *
     * @param contextHandle Handle from context create or join.
     * @param toolId The tool's ID.
     * @return JSON-encoded verification result.
     */
    suspend fun verify(
        contextHandle: Long,
        toolId: String,
    ): String = bridge.ffiCall { bindings.toolVerify(contextHandle, toolId) }

    /**
     * Expose a tool interface for cross-context sharing (§6.2.0.1 step 1).
     *
     * @param contextHandle Handle for the source context.
     * @param toolId The ID of the tool to expose.
     * @param targetContextId The target context to expose the tool to.
     * @param rateLimitJson Optional per-interface rate limit as JSON.
     * @return JSON-encoded ToolInterface.
     */
    suspend fun interfaceExpose(
        contextHandle: Long,
        toolId: String,
        targetContextId: String,
        rateLimitJson: String? = null,
    ): String =
        bridge.ffiCall {
            bindings.toolInterfaceExpose(contextHandle, toolId, targetContextId, rateLimitJson)
        }

    /**
     * Accept a cross-context tool interface (§6.2.0.1 step 4).
     *
     * @param contextHandle Handle for the target context.
     * @param interfaceJson The ToolInterface JSON string to accept.
     * @return JSON-encoded updated ToolInterface.
     */
    suspend fun interfaceAccept(
        contextHandle: Long,
        interfaceJson: String,
    ): String =
        bridge.ffiCall {
            bindings.toolInterfaceAccept(contextHandle, interfaceJson)
        }

    /**
     * Revoke a cross-context tool interface (§6.2.0.1 step 5).
     *
     * @param contextHandle Handle for the revoking context.
     * @param interfaceIdHex The 32-byte interface/offer ID as hex.
     * @return JSON-encoded InterfaceRevoked event.
     */
    suspend fun interfaceRevoke(
        contextHandle: Long,
        interfaceIdHex: String,
    ): String =
        bridge.ffiCall {
            bindings.toolInterfaceRevoke(contextHandle, interfaceIdHex)
        }

    /**
     * Invoke a tool across context boundaries (spec section 6.2).
     *
     * @param sourceContextHandle Handle for the calling (source) context.
     * @param targetContextHandle Handle for the context containing the tool.
     * @param toolId The tool's assigned ID.
     * @param inputJson JSON-encoded tool input.
     * @param identityHandle Handle for the invoker's identity.
     * @param ucanToken JWT-encoded UCAN token authorizing the invocation.
     * @param chainDepth Current cross-context chain depth (0 for first hop).
     *   Context-configurable max (default 8), range 0-255 (ADR-043, spec §24.4).
     * @param proofTokens Optional parent UCAN tokens for delegation chain.
     * @return JSON-encoded tool output.
     */
    @Suppress("LongParameterList") // FFI bridge — must match UniFFI export signature
    suspend fun invokeCrossContext(
        sourceContextHandle: Long,
        targetContextHandle: Long,
        toolId: String,
        inputJson: String,
        identityHandle: Long,
        ucanToken: String,
        chainDepth: Int,
        proofTokens: List<String>? = null,
    ): String =
        bridge.ffiCall {
            bindings.toolInvokeCrossContext(
                sourceContextHandle,
                targetContextHandle,
                toolId,
                inputJson,
                identityHandle,
                ucanToken,
                chainDepth,
                proofTokens,
            )
        }

    /**
     * Create a stateful tool session (spec section 6.2.1).
     *
     * @param contextHandle Handle for the context containing the tool.
     * @param toolId The tool to create a session for.
     * @param sourceContextId The calling context ID (session cap tracked per caller).
     * @param ttlSeconds Optional time-to-live in seconds, or null for context-lifetime.
     * @return The session ID (UUID string).
     */
    suspend fun sessionCreate(
        contextHandle: Long,
        toolId: String,
        sourceContextId: String,
        ttlSeconds: Long? = null,
    ): String =
        bridge.ffiCall {
            bindings.toolSessionCreate(contextHandle, toolId, sourceContextId, ttlSeconds)
        }

    /**
     * Invoke a tool within an active session.
     *
     * @param contextHandle Handle for the context containing the session.
     * @param sessionId The session ID from [sessionCreate].
     * @param inputJson JSON-encoded tool input.
     * @param identityHandle Handle for the invoker's identity.
     * @param ucanToken JWT-encoded UCAN token authorizing the invocation.
     * @param proofTokens Optional parent UCAN tokens for delegation chain.
     * @return JSON-encoded tool output.
     */
    @Suppress("LongParameterList") // FFI bridge — must match UniFFI export signature
    suspend fun sessionInvoke(
        contextHandle: Long,
        sessionId: String,
        inputJson: String,
        identityHandle: Long,
        ucanToken: String,
        proofTokens: List<String>? = null,
    ): String =
        bridge.ffiCall {
            bindings.toolSessionInvoke(
                contextHandle,
                sessionId,
                inputJson,
                identityHandle,
                ucanToken,
                proofTokens,
            )
        }

    /**
     * Close a stateful tool session.
     *
     * @param contextHandle Handle for the context containing the session.
     * @param sessionId The session ID to close.
     */
    suspend fun sessionClose(
        contextHandle: Long,
        sessionId: String,
    ): Unit =
        bridge.ffiCall {
            bindings.toolSessionClose(contextHandle, sessionId)
        }
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
     * @param contextHandle Handle from context create or join.
     * @param token The UCAN token string.
     * @param capability The capability to validate.
     * @param presentingAgentDid Optional DID of the presenting agent.
     * @param proofTokens Optional parent UCAN tokens for delegation chain.
     * @throws BridgeException if validation fails.
     */
    suspend fun validate(
        contextHandle: Long,
        token: String,
        capability: String,
        presentingAgentDid: String? = null,
        proofTokens: List<String>? = null,
    ): Unit =
        bridge.ffiCall {
            bindings.ucanValidate(contextHandle, token, capability, presentingAgentDid, proofTokens)
        }

    /**
     * Mint a UCAN token delegating capabilities to a member DID.
     *
     * @param contextHandle Handle from context create or join.
     * @param memberDid The DID to delegate capabilities to.
     * @param capabilitiesJson JSON-encoded list of capabilities.
     * @return The minted UCAN token string.
     */
    suspend fun mint(
        contextHandle: Long,
        memberDid: String,
        capabilitiesJson: String,
    ): String = bridge.ffiCall { bindings.ucanMint(contextHandle, memberDid, capabilitiesJson) }

    /**
     * Revoke a previously minted UCAN token.
     *
     * @param contextHandle Handle from context create or join.
     * @param token The full encoded JWT string of the token to revoke.
     * @param revokerDid The DID of the entity requesting the revocation.
     */
    suspend fun revoke(
        contextHandle: Long,
        token: String,
        revokerDid: String,
    ): Unit = bridge.ffiCall { bindings.ucanRevoke(contextHandle, token, revokerDid) }

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
    ): String =
        bridge.ffiCall {
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
    suspend fun memberCount(contextHandle: Long): Long? = bridge.ffiCall { bindings.contextMemberCount(contextHandle) }

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
    ): String =
        bridge.ffiCall {
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
    ): String =
        bridge.ffiCall {
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
    ): String =
        bridge.ffiCall {
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
    ): String =
        bridge.ffiCall {
            bindings.governanceWithdraw(contextHandle, voterDid, proposalIdHex)
        }

    /**
     * Retrieve a single governance proposal by hex-encoded ID (#621).
     *
     * @param contextHandle Handle from context create.
     * @param proposalIdHex Hex-encoded 32-byte proposal ID.
     * @return JSON string with proposal details.
     */
    suspend fun getProposal(
        contextHandle: Long,
        proposalIdHex: String,
    ): String =
        bridge.ffiCall {
            bindings.governanceGetProposal(contextHandle, proposalIdHex)
        }

    /**
     * List all governance proposals for a context (#621).
     *
     * @param contextHandle Handle from context create.
     * @return JSON array of proposals.
     */
    suspend fun listProposals(contextHandle: Long): String =
        bridge.ffiCall {
            bindings.governanceListProposals(contextHandle)
        }

    /**
     * Apply a pending ceiling modification (#559).
     *
     * @param contextHandle Handle from context create.
     * @param currentTimestamp Current Unix timestamp in seconds.
     * @return `true` if applied, `false` otherwise.
     */
    suspend fun applyPendingCeilingModification(
        contextHandle: Long,
        currentTimestamp: Long,
    ): Boolean =
        bridge.ffiCall {
            bindings.applyPendingCeilingModification(contextHandle, currentTimestamp)
        }

    /**
     * Finalize the cooperative close flow (#559).
     *
     * @param contextHandle Handle from context create.
     */
    suspend fun finalizeClose(contextHandle: Long): Unit =
        bridge.ffiCall {
            bindings.finalizeClose(contextHandle)
        }

    /**
     * Create a governance checkpoint (ADR-031 section 9, #559).
     *
     * @param contextHandle Handle from context create.
     * @param checkpointSeq Sequence number.
     * @param merkleRootHex Hex-encoded 32-byte Merkle root.
     * @param eventCount Number of events.
     * @param lastEventHashHex Hex-encoded 32-byte hash.
     * @param stateSnapshotHashHex Hex-encoded 32-byte hash.
     * @param creatorDid DID of the creator.
     * @param creatorSignatureHex Hex-encoded Ed25519 signature.
     * @return JSON string with the checkpoint object.
     */
    @Suppress("LongParameterList")
    suspend fun createGovernanceCheckpoint(
        contextHandle: Long,
        checkpointSeq: Long,
        merkleRootHex: String,
        eventCount: Long,
        lastEventHashHex: String,
        stateSnapshotHashHex: String,
        creatorDid: String,
        creatorSignatureHex: String,
    ): String =
        bridge.ffiCall {
            bindings.createGovernanceCheckpoint(
                contextHandle,
                checkpointSeq,
                merkleRootHex,
                eventCount,
                lastEventHashHex,
                stateSnapshotHashHex,
                creatorDid,
                creatorSignatureHex,
            )
        }

    /**
     * Add a cosignature to an existing checkpoint (ADR-031 section 9, #559).
     *
     * @param contextHandle Handle from context create.
     * @param checkpointJson JSON-serialized checkpoint.
     * @param signerDid DID of the cosigner.
     * @param signatureHex Hex-encoded Ed25519 signature.
     * @return JSON string with attestation status and updated checkpoint.
     */
    suspend fun addCheckpointCosignature(
        contextHandle: Long,
        checkpointJson: String,
        signerDid: String,
        signatureHex: String,
    ): String =
        bridge.ffiCall {
            bindings.addCheckpointCosignature(contextHandle, checkpointJson, signerDid, signatureHex)
        }

    /**
     * Restore a single persisted context (#559).
     *
     * @param contextId The context ID to restore.
     */
    suspend fun restoreContext(contextId: String): Unit =
        bridge.ffiCall {
            bindings.restoreContext(contextId)
        }

    /**
     * Restore all persisted contexts (#559).
     *
     * @return JSON array of restored context ID strings.
     */
    suspend fun restoreAllContexts(): String =
        bridge.ffiCall {
            bindings.restoreAllContexts()
        }
}

/**
 * Broadcast operations bridge. Wraps broadcast-related FFI calls as suspend functions.
 *
 * Set [defaultIdentityHandle] to avoid passing the identity handle to every
 * publish call. When a publish method receives `identityHandle = null`, it
 * falls back to [defaultIdentityHandle]. If both are null, a
 * [BridgeException] is thrown. Callers typically set this once after
 * identity creation (SCP-294b).
 */
class BroadcastBridgeOps internal constructor(
    private val bindings: BroadcastBindings,
    private val bridge: CoroutineBridge,
) {
    /**
     * Default identity handle used when publish methods receive a null
     * `identityHandle`. Set this after identity creation to avoid passing
     * the handle on every call (SCP-294b).
     */
    var defaultIdentityHandle: Long? = null

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
    ): Unit =
        bridge.ffiCall {
            bindings.broadcastUnsubscribe(contextHandle, subscriberDid, rotateKeys)
        }

    /**
     * Publish a message to a broadcast context.
     *
     * @param contextHandle Handle from context create or join.
     * @param identityHandle Handle from identity create or load for the
     *   publishing author.
     * @param payload Raw message bytes.
     */
    suspend fun publish(
        contextHandle: Long,
        identityHandle: Long,
        payload: ByteArray,
    ): Unit = bridge.ffiCall { bindings.broadcastPublish(contextHandle, identityHandle, payload) }

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
    ): Unit =
        bridge.ffiCall {
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
    ): Unit =
        bridge.ffiCall {
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
    ): String =
        bridge.ffiCall {
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
    suspend fun admission(contextHandle: Long): String? = bridge.ffiCall { bindings.broadcastAdmission(contextHandle) }

    /**
     * Publish a single asset to a broadcast context as structured content (SCP-290).
     *
     * @param contextHandle Handle from context create or join.
     * @param identityHandle Handle from identity create or load for the publishing author.
     *   Defaults to [defaultIdentityHandle] when null (SCP-294b).
     * @param asset The asset to publish (path, content type, body).
     * @param deployId Optional deploy ID to group assets into atomic deploys.
     * @return A [PublishResult] with blob ID and ETag.
     * @throws BridgeException if no identity handle is provided and
     *   [defaultIdentityHandle] is not set.
     */
    suspend fun publishAsset(
        contextHandle: Long,
        identityHandle: Long? = null,
        asset: AssetEntry,
        deployId: String? = null,
    ): PublishResult {
        // SCP-297: Client-side validation before FFI crossing.
        validateContentPath(asset.path)
        validateMimeType(asset.contentType)
        if (deployId != null) validateDeployId(deployId)

        val resolved = resolveIdentityHandle(identityHandle)
        val assetJson = serializeAsset(asset)
        val resultJson =
            bridge.ffiCall {
                bindings.broadcastPublishAsset(contextHandle, resolved, assetJson, deployId)
            }
        return parsePublishResult(resultJson)
    }

    /**
     * Publish multiple assets to a broadcast context as structured content (SCP-290).
     *
     * All assets are published with the same deploy ID (auto-generated if not
     * provided).
     *
     * @param contextHandle Handle from context create or join.
     * @param identityHandle Handle from identity create or load for the publishing author.
     *   Defaults to [defaultIdentityHandle] when null (SCP-294b).
     * @param assets The assets to publish.
     * @param deployId Optional deploy ID to group assets into atomic deploys.
     * @return A [BatchPublishResult] with per-asset results and the shared deploy ID.
     * @throws BridgeException if no identity handle is provided and
     *   [defaultIdentityHandle] is not set, or if any path/contentType/deployId
     *   is invalid (SCP-297).
     */
    suspend fun publishAssets(
        contextHandle: Long,
        identityHandle: Long? = null,
        assets: List<AssetEntry>,
        deployId: String? = null,
    ): BatchPublishResult {
        // SCP-297: Client-side validation before FFI crossing.
        for (asset in assets) {
            validateContentPath(asset.path)
            validateMimeType(asset.contentType)
        }
        if (deployId != null) validateDeployId(deployId)

        val resolved = resolveIdentityHandle(identityHandle)
        val assetsJson = serializeAssets(assets)
        val resultJson =
            bridge.ffiCall {
                bindings.broadcastPublishAssets(contextHandle, resolved, assetsJson, deployId)
            }
        return parsePublishResults(resultJson)
    }

    /**
     * Resolves the effective identity handle from an explicit value or the
     * [defaultIdentityHandle] fallback (SCP-294b).
     */
    private fun resolveIdentityHandle(explicit: Long?): Long =
        explicit ?: defaultIdentityHandle ?: throw BridgeException(
            "identityHandle is required: pass it explicitly or set " +
                "BroadcastBridgeOps.defaultIdentityHandle",
            "SCP-IDENT-1060",
        )
}

// ---------------------------------------------------------------------------
// Broadcast asset JSON helpers (SCP-290)
// ---------------------------------------------------------------------------

/**
 * Serializes an [AssetEntry] to a JSON string for the FFI bridge.
 *
 * Uses [kotlinx.serialization.json.buildJsonObject] to produce structurally
 * valid JSON, preventing injection via untrusted string fields. The body
 * is encoded as a Base64 string for safe JSON transport.
 */
internal fun serializeAsset(asset: AssetEntry): String =
    Json.encodeToString(
        buildJsonObject {
            put("path", asset.path)
            put("content_type", asset.contentType)
            put("body", java.util.Base64.getEncoder().encodeToString(asset.body))
        },
    )

/**
 * Serializes a list of [AssetEntry] values to a JSON array string.
 */
internal fun serializeAssets(assets: List<AssetEntry>): String =
    Json.encodeToString(
        kotlinx.serialization.json.buildJsonArray {
            for (asset in assets) {
                add(
                    buildJsonObject {
                        put("path", asset.path)
                        put("content_type", asset.contentType)
                        put("body", java.util.Base64.getEncoder().encodeToString(asset.body))
                    },
                )
            }
        },
    )

/** Extracts a required string field from a [JsonObject], throwing on absence. */
private fun JsonObject.requireString(
    field: String,
    context: String,
): String =
    this[field]?.jsonPrimitive?.content
        ?: throw BridgeException(
            "missing $field in $context",
            "SCP-CTX-2036",
        )

/** Parses a [JsonObject] into a [PublishResult], throwing on missing fields. */
private fun JsonObject.toPublishResult(
    context: String = "publish result",
): PublishResult = PublishResult(
    blobId = requireString("blob_id", context),
    etag = requireString("etag", context),
    deployId = requireString("deploy_id", context),
)

/**
 * Parses a JSON publish result string into a [PublishResult].
 *
 * Expected format: `{"blob_id":"...","etag":"...","deploy_id":"..."}`.
 *
 * @throws BridgeException if the JSON is malformed or missing required fields.
 */
internal fun parsePublishResult(json: String): PublishResult =
    Json.parseToJsonElement(json).jsonObject.toPublishResult()

/**
 * Parses a JSON batch publish result into a [BatchPublishResult].
 *
 * Expected format: `{"results":[...],"deploy_id":"..."}`.
 *
 * @throws BridgeException if the JSON is malformed.
 */
internal fun parsePublishResults(json: String): BatchPublishResult {
    val obj = Json.parseToJsonElement(json).jsonObject
    val deployId = obj.requireString("deploy_id", "batch publish result")
    val resultsArray =
        obj["results"]?.jsonArray
            ?: throw BridgeException(
                "missing results in batch publish result",
                "SCP-CTX-2036",
            )
    val results = resultsArray.map { it.jsonObject.toPublishResult() }
    return BatchPublishResult(results = results, deployId = deployId)
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
     * @param contextHandle Handle from context create or join.
     * @param filterJson JSON-encoded query filter.
     * @return JSON-encoded event log entries.
     */
    suspend fun eventLogQuery(
        contextHandle: Long,
        filterJson: String,
    ): String = bridge.ffiCall { bindings.eventLogQuery(contextHandle, filterJson) }

    /**
     * Verify a claim against the context event log (Merkle proof).
     *
     * @param contextHandle Handle from context create or join.
     * @param claimJson JSON-encoded claim to verify.
     * @return true if the proof is valid.
     */
    suspend fun eventLogVerify(
        contextHandle: Long,
        claimJson: String,
    ): Boolean = bridge.ffiCall { bindings.eventLogVerify(contextHandle, claimJson) }

    /**
     * Generate a signed consistency checkpoint for equivocation detection.
     *
     * Creates a signed snapshot of the event log's Merkle root at the given
     * epoch. Members exchange checkpoints to detect relay equivocation: if
     * two members have different Merkle roots for the same event count, the
     * relay is showing different histories to different members.
     *
     * @param contextHandle Handle from context create or join.
     * @param identityHandle Handle from identity create or load.
     * @param epoch The MLS epoch to checkpoint at.
     * @return JSON-encoded [Checkpoint] containing context_id, sender_did,
     *   event_count, merkle_root, epoch, signature, and timestamp.
     * @see <a href="https://github.com/limn-works/scp/blob/main/.docs/adrs/phase-2.md">ADR-011</a>
     *   acceptance criterion 8
     * @see <a href="https://github.com/limn-works/scp/blob/main/.docs/adrs/phase-4.md">ADR-030</a>
     */
    suspend fun eventLogCheckpoint(
        contextHandle: Long,
        identityHandle: Long,
        epoch: Long,
    ): String =
        bridge.ffiCall {
            bindings.eventLogCheckpoint(contextHandle, identityHandle, epoch)
        }

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
    cause: Throwable? = null,
) : Exception(message, cause)
