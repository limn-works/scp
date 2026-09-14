// BridgeConnector.kt — Kotlin SDK bridge connector wrappers (#421, SCP-RG-012)
//
// Wraps bridge connector UniFFI bridge functions as suspend functions
// with proper dispatcher assignment per ADR-028. Bridge connectors enable
// cross-platform communication through SCP's bridge protocol.
//
// Provenance: §12.2 (Bridge Connectors as Protocol Entities), SCP-RG-012

package works.limn.scp

import works.limn.scp.bridge.CoroutineBridge

/**
 * Native binding functions for bridge connector operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched
 * on [kotlinx.coroutines.Dispatchers.IO].
 */
/**
 * Every field spec 12.2.1's `RegisterBridge` action carries.
 *
 * [platformKey] and [platformKeyId] travel together: cooperative mode requires
 * both, and every other mode rejects both. A platform sends [platformKeyId] in
 * `X-SCP-Platform-Key-Id` on every webhook request, and every webhook signature
 * covers it (spec 12.10.2), so a cooperative bridge registered without both
 * values could never verify a webhook signature.
 *
 * @property contextId The context to register in.
 * @property operatorDid DID of the bridge operator.
 * @property governanceDid DID of the governance authority approving this
 *   registration; it must differ from [operatorDid] (self-approval is forbidden
 *   per ADR-023).
 * @property platform Platform identifier (e.g., "slack", "discord").
 * @property mode Bridge mode: "relay", "puppet", "api", or "cooperative".
 * @property webhookUrl Cooperative mode only: the platform's webhook receiver URL.
 * @property platformKey Cooperative mode only: the platform's 32-byte Ed25519
 *   webhook signing key.
 * @property platformKeyId Cooperative mode only: the platform's identifier for
 *   [platformKey]; spec 12.2.1 accepts 1-128 bytes of printable US-ASCII.
 * @property maxShadows Governance-configured shadow limit for this bridge.
 * @property displayName Human-readable name for this bridge.
 * @property description Free-text description of what this bridge carries.
 * @property operatorContact How to reach this bridge's operator.
 */
data class BridgeRegistrationParams(
    val contextId: String,
    val operatorDid: String,
    val governanceDid: String,
    val platform: String,
    val mode: String,
    val webhookUrl: String? = null,
    val platformKey: ByteArray? = null,
    val platformKeyId: String? = null,
    val maxShadows: UInt? = null,
    val displayName: String? = null,
    val description: String? = null,
    val operatorContact: String? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is BridgeRegistrationParams) return false
        return contextId == other.contextId &&
            operatorDid == other.operatorDid &&
            governanceDid == other.governanceDid &&
            platform == other.platform &&
            mode == other.mode &&
            webhookUrl == other.webhookUrl &&
            platformKeyContentEquals(other.platformKey) &&
            platformKeyId == other.platformKeyId &&
            maxShadows == other.maxShadows &&
            displayName == other.displayName &&
            description == other.description &&
            operatorContact == other.operatorContact
    }

    override fun hashCode(): Int {
        var result = contextId.hashCode()
        result = 31 * result + operatorDid.hashCode()
        result = 31 * result + governanceDid.hashCode()
        result = 31 * result + platform.hashCode()
        result = 31 * result + mode.hashCode()
        result = 31 * result + (webhookUrl?.hashCode() ?: 0)
        result = 31 * result + (platformKey?.contentHashCode() ?: 0)
        result = 31 * result + (platformKeyId?.hashCode() ?: 0)
        result = 31 * result + (maxShadows?.hashCode() ?: 0)
        result = 31 * result + (displayName?.hashCode() ?: 0)
        result = 31 * result + (description?.hashCode() ?: 0)
        result = 31 * result + (operatorContact?.hashCode() ?: 0)
        return result
    }

    /** Compares [platformKey] with [other] by content, treating two nulls as equal. */
    private fun platformKeyContentEquals(other: ByteArray?): Boolean {
        val mine = platformKey
        return when {
            mine == null -> other == null
            other == null -> false
            else -> mine.contentEquals(other)
        }
    }
}

interface BridgeConnectorBindings {
    /**
     * Evaluates the trust level for an action based on bridge provenance.
     *
     * @param isBridged Whether the action originates from a bridge.
     * @param isNativeTransport Whether native SCP transport is used.
     * @param shadowStatus Shadow provenance status: "shadow" or "claimed".
     * @return Trust tier integer (0-3, higher = more trusted).
     * @throws BridgeException if shadowStatus is invalid.
     */
    fun bridgeEvaluateTrust(
        isBridged: Boolean,
        isNativeTransport: Boolean,
        shadowStatus: String,
    ): Int

    /**
     * Registers a bridge connector with a context.
     *
     * @param params Every field spec 12.2.1's `RegisterBridge` action carries.
     * @return JSON string with the registration result.
     */
    fun bridgeRegister(params: BridgeRegistrationParams): String

    /**
     * Creates a shadow identity for a bridged participant.
     *
     * @param bridgeId The bridge connector ID.
     * @param platformHandle The participant's handle on the bridged platform.
     * @param bridgeMode Bridge mode: "relay", "puppet", "api", or "cooperative".
     * @param contextId The context the shadow will participate in.
     * @return JSON string with the shadow identity details.
     */
    fun bridgeCreateShadow(
        bridgeId: String,
        platformHandle: String,
        bridgeMode: String,
        contextId: String,
    ): String
}

/**
 * Bridge connector operations bridge. Wraps bridge connector FFI calls
 * as suspend functions.
 *
 * Bridge connectors enable participants on external platforms (Slack,
 * Discord, etc.) to interact within SCP contexts via shadow identities.
 * See §12.2 (Bridge Connectors as Protocol Entities).
 */
class BridgeConnectorBridge internal constructor(
    private val bindings: BridgeConnectorBindings,
    private val bridge: CoroutineBridge,
) {
    /**
     * Evaluates the trust level for an action based on bridge provenance.
     *
     * Returns an integer (0-3) representing the trust tier:
     * - 0: Lowest trust (bridged with shadow provenance)
     * - 3: Highest trust (native transport, no bridge)
     *
     * @param isBridged Whether the action originates from a bridge.
     * @param isNativeTransport Whether native SCP transport is used.
     * @param shadowStatus Shadow provenance status.
     * @return Trust tier integer (0-3).
     */
    suspend fun evaluateTrust(
        isBridged: Boolean,
        isNativeTransport: Boolean,
        shadowStatus: ShadowStatus,
    ): Int =
        bridge.ffiCall {
            bindings.bridgeEvaluateTrust(isBridged, isNativeTransport, shadowStatus.rawValue)
        }

    /**
     * Evaluates the trust level for an action based on bridge provenance.
     *
     * Overload accepting a raw string for backward compatibility.
     *
     * @param isBridged Whether the action originates from a bridge.
     * @param isNativeTransport Whether native SCP transport is used.
     * @param shadowStatus Shadow provenance status: "shadow" or "claimed".
     * @return Trust tier integer (0-3).
     */
    suspend fun evaluateTrust(
        isBridged: Boolean,
        isNativeTransport: Boolean,
        shadowStatus: String,
    ): Int =
        bridge.ffiCall {
            bindings.bridgeEvaluateTrust(isBridged, isNativeTransport, shadowStatus)
        }

    /**
     * Registers a bridge connector with a context.
     *
     * @param params Every field spec 12.2.1's `RegisterBridge` action carries,
     *   including the cooperative-mode platform key and its identifier.
     * @return JSON string with the registration result.
     */
    suspend fun register(params: BridgeRegistrationParams): String =
        bridge.ffiCall { bindings.bridgeRegister(params) }

    /**
     * Registers a bridge connector with a context.
     *
     * Overload carrying only the fields every mode requires; a cooperative
     * bridge needs [BridgeRegistrationParams.platformKey] and
     * [BridgeRegistrationParams.platformKeyId], so it goes through
     * [register] with a params value instead.
     *
     * @param contextId The context to register in.
     * @param operatorDid DID of the bridge operator.
     * @param governanceDid DID of the governance authority approving the
     *   registration.  Must differ from [operatorDid] (self-approval is
     *   forbidden per ADR-023).
     * @param platform Platform identifier (e.g., "slack", "discord").
     * @param mode Bridge mode.
     * @return JSON string with the registration result.
     */
    suspend fun register(
        contextId: String,
        operatorDid: String,
        governanceDid: String,
        platform: String,
        mode: BridgeMode,
    ): String =
        register(
            BridgeRegistrationParams(
                contextId = contextId,
                operatorDid = operatorDid,
                governanceDid = governanceDid,
                platform = platform,
                mode = mode.rawValue,
            ),
        )

    /**
     * Registers a bridge connector with a context.
     *
     * Overload accepting a raw string for backward compatibility.
     *
     * @param contextId The context to register in.
     * @param operatorDid DID of the bridge operator.
     * @param governanceDid DID of the governance authority approving the
     *   registration.  Must differ from [operatorDid] (self-approval is
     *   forbidden per ADR-023).
     * @param platform Platform identifier (e.g., "slack", "discord").
     * @param mode Bridge mode: "relay", "puppet", "api", or "cooperative".
     * @return JSON string with the registration result.
     */
    suspend fun register(
        contextId: String,
        operatorDid: String,
        governanceDid: String,
        platform: String,
        mode: String,
    ): String =
        register(
            BridgeRegistrationParams(
                contextId = contextId,
                operatorDid = operatorDid,
                governanceDid = governanceDid,
                platform = platform,
                mode = mode,
            ),
        )

    /**
     * Creates a shadow identity for a bridged participant.
     *
     * @param bridgeId The bridge connector ID.
     * @param platformHandle The participant's handle on the bridged platform.
     * @param bridgeMode Bridge mode.
     * @param contextId The context the shadow will participate in.
     * @return JSON string with the shadow identity details.
     */
    suspend fun createShadow(
        bridgeId: String,
        platformHandle: String,
        bridgeMode: BridgeMode,
        contextId: String,
    ): String =
        bridge.ffiCall {
            bindings.bridgeCreateShadow(bridgeId, platformHandle, bridgeMode.rawValue, contextId)
        }

    /**
     * Creates a shadow identity for a bridged participant.
     *
     * Overload accepting a raw string for backward compatibility.
     *
     * @param bridgeId The bridge connector ID.
     * @param platformHandle The participant's handle on the bridged platform.
     * @param bridgeMode Bridge mode: "relay", "puppet", "api", or "cooperative".
     * @param contextId The context the shadow will participate in.
     * @return JSON string with the shadow identity details.
     */
    suspend fun createShadow(
        bridgeId: String,
        platformHandle: String,
        bridgeMode: String,
        contextId: String,
    ): String =
        bridge.ffiCall {
            bindings.bridgeCreateShadow(bridgeId, platformHandle, bridgeMode, contextId)
        }
}
