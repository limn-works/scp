// Server.kt -- Kotlin SDK wrappers for relay and application node lifecycle
//
// Wraps server-related UniFFI bridge functions as suspend functions with
// proper dispatcher assignment per ADR-028. Provides Relay and Node types
// that expose relay URL, DID, and shutdown operations as AutoCloseable
// resources with proper lifecycle methods.
//
// Provenance: crates/scp-ffi-common/src/server.rs, crates/scp-ffi/uniffi/src/server.rs

package works.limn.scp

import kotlinx.coroutines.runBlocking
import works.limn.scp.bridge.BridgeException
import works.limn.scp.bridge.CoroutineBridge

/**
 * Native binding functions for server lifecycle operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched
 * on [kotlinx.coroutines.Dispatchers.IO].
 */
interface ServerBindings {
    /**
     * Starts a relay with in-memory blob storage on an OS-assigned port.
     *
     * @return JSON-encoded relay handle with `relayUrl` and `relayPort` fields.
     */
    fun relayStartInMemory(): String

    /**
     * Starts a relay with redb-backed blob storage on an OS-assigned port.
     *
     * @param dataDir Directory for persistent blob storage.
     * @return JSON-encoded relay handle with `relayUrl` and `relayPort` fields.
     */
    fun relayStartLocal(dataDir: String): String

    /**
     * Starts a full application node with in-memory storage.
     *
     * @return JSON-encoded node handle with `relayUrl`, `relayPort`, and `did` fields.
     */
    fun nodeStartInMemory(): String

    /**
     * Starts a full application node with file-backed storage.
     *
     * @param dataDir Directory for persistent storage.
     * @return JSON-encoded node handle with `relayUrl`, `relayPort`, and `did` fields.
     */
    fun nodeStartLocal(dataDir: String): String

    /**
     * Shuts down a relay identified by its handle JSON.
     *
     * @param handleJson JSON-encoded relay handle.
     */
    fun relayShutdown(handleJson: String)

    /**
     * Shuts down a node identified by its handle JSON.
     *
     * @param handleJson JSON-encoded node handle.
     */
    fun nodeShutdown(handleJson: String)
}

/**
 * Internal data carrier for relay JSON parsing results.
 *
 * Not part of the public API -- use [Relay] instead.
 */
internal data class RelayInfo(
    val relayUrl: String,
    val relayPort: Int,
    val handleJson: String,
)

/**
 * Internal data carrier for node JSON parsing results.
 *
 * Not part of the public API -- use [Node] instead.
 */
internal data class NodeInfo(
    val relayUrl: String,
    val relayPort: Int,
    val did: String,
    val handleJson: String,
)

/**
 * Opaque handle to a running SCP relay server.
 *
 * Created via [Relay.Companion.startInMemory] or [Relay.Companion.startLocal].
 * The relay accepts WebSocket connections at [relayUrl] and can be gracefully
 * stopped via [shutdown] or [close] (for `use` blocks).
 *
 * Implements [AutoCloseable] so it can be used with Kotlin's `use` extension:
 * ```kotlin
 * Relay.startInMemory().use { relay ->
 *     println(relay.relayUrl)
 * } // shutdown() called automatically
 * ```
 */
class Relay internal constructor(
    /** The WebSocket URL clients should connect to (e.g. `ws://127.0.0.1:PORT/scp/v1`). */
    val relayUrl: String,
    /** The port the relay is listening on. */
    val relayPort: Int,
    private val bridge: ServerBridge,
    internal val handleJson: String,
) : AutoCloseable {
    /** `true` if [shutdown] has already been called. */
    var isShutdown: Boolean = false
        private set

    /**
     * Signals the relay server to stop accepting new connections.
     *
     * In-flight connection handlers drain naturally. Idempotent.
     */
    suspend fun shutdown() {
        bridge.shutdownRelay(this)
        isShutdown = true
    }

    /**
     * Synchronous [AutoCloseable] cleanup that delegates to [shutdown].
     *
     * Blocks the calling thread until shutdown completes. Prefer [shutdown]
     * from a coroutine scope; this exists for `use {}` block support.
     */
    override fun close() {
        runBlocking { shutdown() }
    }

    override fun toString(): String = "Relay(url=$relayUrl, relayPort=$relayPort)"

    companion object {
        /**
         * Starts a relay with in-memory blob storage on an OS-assigned port.
         *
         * @param bridge The [ServerBridge] providing FFI access.
         * @return A [Relay] whose [relayUrl] property contains the WebSocket URL.
         */
        suspend fun startInMemory(bridge: ServerBridge): Relay = bridge.startRelayInMemory()

        /**
         * Starts a relay with redb-backed blob storage on an OS-assigned port.
         *
         * @param bridge The [ServerBridge] providing FFI access.
         * @param dataDir Directory for persistent blob storage.
         * @return A [Relay] whose [relayUrl] property contains the WebSocket URL.
         */
        suspend fun startLocal(
            bridge: ServerBridge,
            dataDir: String,
        ): Relay = bridge.startRelayLocal(dataDir)
    }
}

/**
 * Opaque handle to a running SCP application node.
 *
 * Created via [Node.Companion.startInMemory] or [Node.Companion.startLocal].
 * The node includes a running relay server, a generated DID identity, and
 * (optionally) persistent storage.
 *
 * Implements [AutoCloseable] so it can be used with Kotlin's `use` extension:
 * ```kotlin
 * Node.startInMemory().use { node ->
 *     println(node.relayUrl)
 *     println(node.did)
 * } // shutdown() called automatically
 * ```
 */
class Node internal constructor(
    /** The WebSocket URL for this node's relay (e.g. `ws://127.0.0.1:PORT/scp/v1`). */
    val relayUrl: String,
    /** The port the node's relay is listening on. */
    val relayPort: Int,
    /** The node's DID string (e.g. `did:dht:z6Mk...`). */
    val did: String,
    private val bridge: ServerBridge,
    internal val handleJson: String,
) : AutoCloseable {
    /** `true` if [shutdown] has already been called. */
    var isShutdown: Boolean = false
        private set

    /**
     * Signals the node to stop (relay + background tasks).
     *
     * In-flight connection handlers drain naturally. Idempotent.
     */
    suspend fun shutdown() {
        bridge.shutdownNode(this)
        isShutdown = true
    }

    /**
     * Synchronous [AutoCloseable] cleanup that delegates to [shutdown].
     *
     * Blocks the calling thread until shutdown completes. Prefer [shutdown]
     * from a coroutine scope; this exists for `use {}` block support.
     */
    override fun close() {
        runBlocking { shutdown() }
    }

    override fun toString(): String = "Node(relayUrl=$relayUrl, did=$did)"

    companion object {
        /**
         * Starts a full application node with in-memory storage.
         *
         * Auto-wires in-memory key custody, in-memory storage, in-memory DHT
         * client, self-signed TLS, and a relay on an OS-assigned port.
         *
         * @param bridge The [ServerBridge] providing FFI access.
         * @return A [Node] with [relayUrl] and [did] populated.
         */
        suspend fun startInMemory(bridge: ServerBridge): Node = bridge.startNodeInMemory()

        /**
         * Starts a full application node with file-backed storage.
         *
         * @param bridge The [ServerBridge] providing FFI access.
         * @param dataDir Directory for persistent storage.
         * @return A [Node] with [relayUrl] and [did] populated.
         */
        suspend fun startLocal(
            bridge: ServerBridge,
            dataDir: String,
        ): Node = bridge.startNodeLocal(dataDir)
    }
}

/**
 * Kotlin SDK wrapper for server lifecycle operations.
 *
 * All operations delegate through the coroutine bridge to UniFFI-generated
 * Rust functions. Provides relay and application node startup/shutdown as
 * suspend functions with proper dispatcher assignment.
 */
class ServerBridge internal constructor(
    private val bindings: ServerBindings,
    private val bridge: CoroutineBridge,
) {
    /**
     * Starts a relay with in-memory blob storage on an OS-assigned port.
     *
     * @return A [Relay] whose [Relay.relayUrl] property contains the WebSocket URL.
     */
    suspend fun startRelayInMemory(): Relay =
        bridge.ffiCall {
            val json = bindings.relayStartInMemory()
            val info = parseRelayInfo(json)
            Relay(
                relayUrl = info.relayUrl,
                relayPort = info.relayPort,
                bridge = this@ServerBridge,
                handleJson = info.handleJson,
            )
        }

    /**
     * Starts a relay with redb-backed blob storage on an OS-assigned port.
     *
     * @param dataDir Directory for persistent blob storage.
     * @return A [Relay] whose [Relay.relayUrl] property contains the WebSocket URL.
     */
    suspend fun startRelayLocal(dataDir: String): Relay =
        bridge.ffiCall {
            val json = bindings.relayStartLocal(dataDir)
            val info = parseRelayInfo(json)
            Relay(
                relayUrl = info.relayUrl,
                relayPort = info.relayPort,
                bridge = this@ServerBridge,
                handleJson = info.handleJson,
            )
        }

    /**
     * Starts a full application node with in-memory storage.
     *
     * Auto-wires in-memory key custody, in-memory storage, in-memory DHT
     * client, self-signed TLS, and a relay on an OS-assigned port.
     *
     * @return A [Node] with [Node.relayUrl] and [Node.did] populated.
     */
    suspend fun startNodeInMemory(): Node =
        bridge.ffiCall {
            val json = bindings.nodeStartInMemory()
            val info = parseNodeInfo(json)
            Node(
                relayUrl = info.relayUrl,
                relayPort = info.relayPort,
                did = info.did,
                bridge = this@ServerBridge,
                handleJson = info.handleJson,
            )
        }

    /**
     * Starts a full application node with file-backed storage.
     *
     * @param dataDir Directory for persistent storage.
     * @return A [Node] with [Node.relayUrl] and [Node.did] populated.
     */
    suspend fun startNodeLocal(dataDir: String): Node =
        bridge.ffiCall {
            val json = bindings.nodeStartLocal(dataDir)
            val info = parseNodeInfo(json)
            Node(
                relayUrl = info.relayUrl,
                relayPort = info.relayPort,
                did = info.did,
                bridge = this@ServerBridge,
                handleJson = info.handleJson,
            )
        }

    /**
     * Shuts down a running relay. Idempotent.
     *
     * @param relay The relay to shut down.
     */
    internal suspend fun shutdownRelay(relay: Relay) =
        bridge.ffiCall {
            bindings.relayShutdown(relay.handleJson)
        }

    /**
     * Shuts down a running node (relay + background tasks). Idempotent.
     *
     * @param node The node to shut down.
     */
    internal suspend fun shutdownNode(node: Node) =
        bridge.ffiCall {
            bindings.nodeShutdown(node.handleJson)
        }

    private fun parseRelayInfo(json: String): RelayInfo {
        val obj =
            kotlinx.serialization.json.Json.parseToJsonElement(json)
                .jsonObject
        return RelayInfo(
            relayUrl = obj.requireString("relayUrl", "SCP-VALID-7050"),
            relayPort = obj.requireInt("relayPort", "SCP-VALID-7051"),
            handleJson = json,
        )
    }

    private fun parseNodeInfo(json: String): NodeInfo {
        val obj =
            kotlinx.serialization.json.Json.parseToJsonElement(json)
                .jsonObject
        return NodeInfo(
            relayUrl = obj.requireString("relayUrl", "SCP-VALID-7052"),
            relayPort = obj.requireInt("relayPort", "SCP-VALID-7053"),
            did = obj.requireString("did", "SCP-VALID-7054"),
            handleJson = json,
        )
    }
}

private val kotlinx.serialization.json.JsonElement.jsonObject
    get() = this as kotlinx.serialization.json.JsonObject

private val kotlinx.serialization.json.JsonElement.jsonPrimitive
    get() = this as kotlinx.serialization.json.JsonPrimitive

private fun kotlinx.serialization.json.JsonObject.requireString(
    key: String,
    errorCode: String,
): String =
    this[key]?.jsonPrimitive?.content
        ?: throw BridgeException("missing $key in handle JSON", errorCode)

private fun kotlinx.serialization.json.JsonObject.requireInt(
    key: String,
    errorCode: String,
): Int =
    this[key]?.jsonPrimitive?.content?.toInt()
        ?: throw BridgeException("missing $key in handle JSON", errorCode)
