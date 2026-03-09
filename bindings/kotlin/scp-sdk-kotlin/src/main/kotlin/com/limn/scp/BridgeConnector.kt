// BridgeConnector.kt — Kotlin SDK bridge connector wrappers (#421, SCP-RG-012)
//
// Wraps bridge connector UniFFI bridge functions as suspend functions
// with proper dispatcher assignment per ADR-028. Bridge connectors enable
// cross-platform communication through SCP's bridge protocol.
//
// Provenance: §12.2 (Bridge Connectors as Protocol Entities), SCP-RG-012

package com.limn.scp

import com.limn.scp.bridge.CoroutineBridge

/**
 * Native binding functions for bridge connector operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched
 * on [kotlinx.coroutines.Dispatchers.IO].
 */
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
     * @param contextId The context to register in.
     * @param operatorDid DID of the bridge operator.
     * @param platform Platform identifier (e.g., "slack", "discord").
     * @param mode Bridge mode: "relay", "puppet", "api", or "cooperative".
     * @return JSON string with the registration result.
     */
    fun bridgeRegister(
        contextId: String,
        operatorDid: String,
        platform: String,
        mode: String,
    ): String

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
     * @param contextId The context to register in.
     * @param operatorDid DID of the bridge operator.
     * @param platform Platform identifier (e.g., "slack", "discord").
     * @param mode Bridge mode.
     * @return JSON string with the registration result.
     */
    suspend fun register(
        contextId: String,
        operatorDid: String,
        platform: String,
        mode: BridgeMode,
    ): String =
        bridge.ffiCall {
            bindings.bridgeRegister(contextId, operatorDid, platform, mode.rawValue)
        }

    /**
     * Registers a bridge connector with a context.
     *
     * Overload accepting a raw string for backward compatibility.
     *
     * @param contextId The context to register in.
     * @param operatorDid DID of the bridge operator.
     * @param platform Platform identifier (e.g., "slack", "discord").
     * @param mode Bridge mode: "relay", "puppet", "api", or "cooperative".
     * @return JSON string with the registration result.
     */
    suspend fun register(
        contextId: String,
        operatorDid: String,
        platform: String,
        mode: String,
    ): String =
        bridge.ffiCall {
            bindings.bridgeRegister(contextId, operatorDid, platform, mode)
        }

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
