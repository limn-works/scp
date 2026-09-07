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
 *
 * ## This interface has no production implementer, and that is deliberate
 *
 * No production class implements [ServerBindings]. The only implementer is
 * `StubServerBindings` in the test source set. Because no production Kotlin
 * code reaches these operations, all ten `Server` operations in
 * `.docs/standards/sdk-capability-matrix.json` carry `"kotlin": false` with a
 * matching `exemptions.kotlin` reason.
 *
 * [ServerBindings] and [ServerBridge] stay in scp-kt because Alec ruled on
 * 2026-08-17: "let's keep kotlin false but not forever. we can add impls
 * later." Do not delete either type, and do not read either type as a working
 * capability.
 *
 * scp-kt is a plain JVM library, so a relay IS implementable here: a relay is
 * an inbound listener (`TcpListener::bind`,
 * `crates/scp-transport/src/native/server.rs:446`), and a JVM server binds
 * ports. The separate Android module scp-kt-android depends on scp-kt, and
 * Android is not a relay or node environment: a phone sits behind carrier
 * CGNAT with no routable address, and Doze plus Android's
 * background-execution limits kill a persistent listener.
 *
 * Whoever implements [ServerBindings] flips those ten matrix cells back to
 * `true` and removes their exemptions.
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
     * Starts a full application node with encrypted in-memory storage.
     *
     * @param identityDid DID string of a pre-existing identity, or null to generate a fresh identity.
     * @return JSON-encoded node handle with `relayUrl`, `relayPort`, and `did` fields.
     */
    fun nodeStartInMemory(identityDid: String? = null): String

    /**
     * Starts a full application node on this instance's own storage backend.
     *
     * @param dataDir Directory for persistent storage.
     * @param identityDid DID string of a pre-existing identity, or null to generate a fresh identity.
     * @param passphrase Passphrase for Argon2id key derivation. Required when identityDid is null.
     * @return JSON-encoded node handle with `relayUrl`, `relayPort`, and `did` fields.
     */
    fun nodeStartLocal(dataDir: String, identityDid: String? = null, passphrase: String? = null): String

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

    // Broadcast deployment lifecycle (SCP-296, spec section 18.11.8)

    /**
     * Activates HTTP broadcast projection for a context.
     *
     * Three resolution modes:
     * 1. Both [broadcastKeyHex] **and** [authorDid] provided -- uses the
     *    explicit key with epoch 0.
     * 2. Only [authorDid] provided -- auto-resolves the broadcast key
     *    using that DID (useful when the author identity differs from the
     *    node identity).
     * 3. Neither provided -- auto-resolves using the node's identity DID.
     *
     * Providing [broadcastKeyHex] without [authorDid] is an error.
     *
     * @param handleJson JSON-encoded node handle.
     * @param contextId The context ID to project.
     * @param admission "open" or "gated".
     * @param hostname Virtual host hostname (RFC 1123).
     * @param broadcastKeyHex 32-byte AES-256 broadcast key as 64-char hex string, or null for auto-lookup.
     * @param authorDid DID of the broadcast key owner, or null for auto-lookup.
     * @param indexPath Default path for directory requests, or null for default "/index.html".
     * @param maxAssetsPerDeploy Max assets per deploy, or null for default 10000.
     * @param maxDeploySizeBytes Max total deploy size in bytes, or null for default 536870912.
     * @param deployRetentionCount Deploys to retain (1-8), or null for default 2.
     * @param cspOverride Optional Content-Security-Policy override.
     */
    @Suppress("LongParameterList")
    fun nodeEnableSiteProjection(
        handleJson: String,
        contextId: String,
        admission: String,
        hostname: String,
        broadcastKeyHex: String?,
        authorDid: String?,
        indexPath: String?,
        maxAssetsPerDeploy: Int?,
        maxDeploySizeBytes: Long?,
        deployRetentionCount: Int?,
        cspOverride: String?,
    )

    /**
     * Commits a deploy for a projected context.
     *
     * @param handleJson JSON-encoded node handle.
     * @param contextId The projected context ID.
     * @param deployId The deploy identifier (hex).
     * @return The number of assets in the committed deploy.
     */
    fun nodeCommitDeploy(handleJson: String, contextId: String, deployId: String): Int

    /**
     * Rolls back to a previous deploy for a projected context.
     *
     * @param handleJson JSON-encoded node handle.
     * @param contextId The projected context ID.
     * @param deployId The deploy identifier to roll back to.
     */
    fun nodeRollbackDeploy(handleJson: String, contextId: String, deployId: String)

    /**
     * Deactivates HTTP broadcast projection for a context.
     *
     * @param handleJson JSON-encoded node handle.
     * @param contextId The context ID to stop projecting.
     */
    fun nodeDisableSiteProjection(handleJson: String, contextId: String)

    /**
     * Starts the HTTP server in the background.
     *
     * @param handleJson JSON-encoded node handle.
     * @param bindAddr Socket address to bind (e.g. "127.0.0.1:8080"), or null for default.
     * @return The actual bound address as a string.
     */
    fun nodeServe(handleJson: String, bindAddr: String?): String

    /**
     * Returns the HTTP URL of the background server.
     *
     * @param handleJson JSON-encoded node handle.
     * @return The HTTP URL, or null if not serving.
     */
    fun nodeHttpUrl(handleJson: String): String?
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
    @Volatile
    var isShutdown: Boolean = false
        private set

    /**
     * Signals the relay server to stop accepting new connections.
     *
     * In-flight connection handlers drain naturally. Idempotent.
     */
    suspend fun shutdown() {
        try {
            bridge.shutdownRelay(this)
        } finally {
            isShutdown = true
        }
    }

    /**
     * Synchronous [AutoCloseable] cleanup that delegates to [shutdown].
     *
     * Blocks the calling thread until shutdown completes. Prefer [shutdown]
     * from a coroutine scope; this exists for `use {}` block support.
     *
     * Uses [kotlinx.coroutines.Dispatchers.Default] to avoid deadlocking
     * when called from a thread that already holds the event loop.
     */
    override fun close() {
        runBlocking(kotlinx.coroutines.Dispatchers.Default) { shutdown() }
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
    @Volatile
    var isShutdown: Boolean = false
        private set

    /**
     * Signals the node to stop (relay + background tasks).
     *
     * In-flight connection handlers drain naturally. Idempotent.
     */
    suspend fun shutdown() {
        try {
            bridge.shutdownNode(this)
        } finally {
            isShutdown = true
        }
    }

    /**
     * Synchronous [AutoCloseable] cleanup that delegates to [shutdown].
     *
     * Blocks the calling thread until shutdown completes. Prefer [shutdown]
     * from a coroutine scope; this exists for `use {}` block support.
     *
     * Uses [kotlinx.coroutines.Dispatchers.Default] to avoid deadlocking
     * when called from a thread that already holds the event loop.
     */
    override fun close() {
        runBlocking(kotlinx.coroutines.Dispatchers.Default) { shutdown() }
    }

    // HTTP server lifecycle

    /**
     * Starts the HTTP server in the background.
     *
     * Defaults to `127.0.0.1:8443` (loopback only) when [bindAddr] is null.
     * Pass `"0.0.0.0:PORT"` for network access.
     *
     * **Note:** The background server does not support TLS. All HTTP traffic is
     * plaintext. For production deployments requiring encryption, use the node
     * binary's `serve()` with TLS configuration.
     *
     * @param bindAddr Socket address to bind (e.g. `"127.0.0.1:8080"`).
     * @return The actual bound address as a string.
     * @throws BridgeException if the server is already running or binding fails.
     */
    suspend fun serve(bindAddr: String? = null): String =
        bridge.serve(this, bindAddr)

    /**
     * Returns the HTTP URL of the background server, or null if not serving.
     */
    suspend fun httpUrl(): String? =
        bridge.httpUrl(this)

    // Broadcast deployment lifecycle (SCP-296, spec section 18.11.8)

    /**
     * Activates HTTP broadcast projection for a context.
     *
     * Three resolution modes:
     * 1. Both [broadcastKeyHex] **and** [authorDid] provided -- uses the
     *    explicit key with epoch 0.
     * 2. Only [authorDid] provided -- auto-resolves the broadcast key
     *    using that DID (useful when the author identity differs from the
     *    node identity).
     * 3. Neither provided -- auto-resolves using the node's identity DID.
     *
     * Providing [broadcastKeyHex] without [authorDid] is an error.
     *
     * @param contextId The context ID to project.
     * @param admission "open" or "gated".
     * @param config [SiteConfig] with hostname, index path, and deploy limits.
     * @param broadcastKeyHex 32-byte AES-256 broadcast key as a 64-char hex string, or null for auto-lookup.
     * @param authorDid DID of the broadcast key owner, or null for auto-lookup.
     * @throws BridgeException if parameters are invalid or operation fails.
     */
    @Suppress("LongParameterList")
    suspend fun enableSiteProjection(
        contextId: String,
        admission: String,
        config: SiteConfig,
        broadcastKeyHex: String? = null,
        authorDid: String? = null,
    ) {
        validateAdmission(admission)
        require(broadcastKeyHex == null || authorDid != null) {
            "broadcastKeyHex requires authorDid -- provide the DID of the " +
                "broadcast key owner, or omit both for auto-resolve"
        }
        if (broadcastKeyHex != null) {
            validateBroadcastKeyHex(broadcastKeyHex)
        }
        bridge.enableSiteProjection(
            this,
            contextId,
            broadcastKeyHex,
            authorDid,
            admission,
            config,
        )
    }

    /**
     * Commits a deploy for a projected context (section 18.11.11).
     *
     * Scans blobs matching the [deployId], decrypts each to extract metadata,
     * builds an immutable path index, and atomically swaps the serving pointer.
     *
     * @param contextId The projected context ID.
     * @param deployId The deploy identifier (hex, from publish).
     * @return The number of assets in the committed deploy.
     * @throws BridgeException if the context is not projected or commit fails.
     */
    suspend fun commitDeploy(contextId: String, deployId: String): Int =
        bridge.commitDeploy(this, contextId, deployId)

    /**
     * Rolls back to a previous deploy for a projected context (section 18.11.11).
     *
     * Sets the path index pointer to a previous deploy within the retention window.
     *
     * @param contextId The projected context ID.
     * @param deployId The deploy identifier to roll back to.
     * @throws BridgeException if the context is not projected or deploy not found.
     */
    suspend fun rollbackDeploy(contextId: String, deployId: String) {
        bridge.rollbackDeploy(this, contextId, deployId)
    }

    /**
     * Deactivates HTTP broadcast projection for a context.
     *
     * Removes the projected context from the registry and drops all retained
     * epoch keys. Idempotent -- calling on a non-projected context is a no-op.
     *
     * @param contextId The context ID to stop projecting.
     */
    suspend fun disableSiteProjection(contextId: String) {
        bridge.disableSiteProjection(this, contextId)
    }

    override fun toString(): String = "Node(relayUrl=$relayUrl, did=$did)"

    companion object {
        /**
         * Starts a full application node with encrypted in-memory storage.
         *
         * When [identityDid] is provided, the node uses the pre-existing
         * identity instead of generating a fresh one. This enables identity
         * portability -- the same DID persists across node restarts.
         *
         * Auto-wires encrypted in-memory storage (ephemeral), self-signed TLS,
         * and a relay on an OS-assigned port. A build carrying a test-harness
         * feature also auto-wires in-memory key custody and an in-memory DHT
         * client; a shipped build fails closed instead when `identity` is absent.
         *
         * @param bridge The [ServerBridge] providing FFI access.
         * @param identityDid DID string of a pre-existing identity, or null to generate a fresh one.
         * @return A [Node] with [relayUrl] and [did] populated.
         */
        suspend fun startInMemory(
            bridge: ServerBridge,
            identityDid: String? = null,
        ): Node = bridge.startNodeInMemory(identityDid)

        /**
         * Starts a full application node on this instance's own storage backend.
         *
         * When [identityDid] is provided, the node uses the pre-existing
         * identity. When `null`, the node creates or reloads a persistent
         * identity via `FileKeyCustody`. The [passphrase] parameter is
         * required in this mode.
         *
         * No passphrase is required when [identityDid] is provided.
         *
         * @param bridge The [ServerBridge] providing FFI access.
         * @param dataDir Directory for persistent storage.
         * @param identityDid DID string of a pre-existing identity, or null to generate a fresh one.
         * @param passphrase Passphrase for Argon2id key derivation. Required when identityDid is null.
         * @return A [Node] with [relayUrl] and [did] populated.
         */
        suspend fun startLocal(
            bridge: ServerBridge,
            dataDir: String,
            identityDid: String? = null,
            passphrase: String? = null,
        ): Node = bridge.startNodeLocal(dataDir, identityDid, passphrase)
    }
}

/**
 * Kotlin SDK wrapper for server lifecycle operations.
 *
 * All operations delegate through the coroutine bridge to UniFFI-generated
 * Rust functions. Provides relay and application node startup/shutdown as
 * suspend functions with proper dispatcher assignment.
 *
 * ## Every method here runs against a [ServerBindings] that only tests supply
 *
 * [ServerBridge] delegates to [ServerBindings], and no production class
 * implements [ServerBindings] — see the note on that interface for the full
 * state. All ten `Server` operations in
 * `.docs/standards/sdk-capability-matrix.json` therefore carry
 * `"kotlin": false` with a matching `exemptions.kotlin` reason.
 *
 * [ServerBridge] stays in scp-kt because Alec ruled on 2026-08-17: "let's keep
 * kotlin false but not forever. we can add impls later." Do not delete this
 * class, and do not read it as a working capability. A JVM implementation of
 * [ServerBindings] makes every method here live, and whoever writes it flips
 * those ten matrix cells back to `true` and removes their exemptions.
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
     * Starts a full application node with encrypted in-memory storage.
     *
     * When [identityDid] is provided, the node uses the pre-existing
     * identity instead of generating a fresh one.
     *
     * @param identityDid DID string of a pre-existing identity, or null to generate a fresh one.
     * @return A [Node] with [Node.relayUrl] and [Node.did] populated.
     */
    suspend fun startNodeInMemory(identityDid: String? = null): Node =
        bridge.ffiCall {
            val json = bindings.nodeStartInMemory(identityDid)
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
     * Starts a full application node on this instance's own storage backend.
     *
     * @param dataDir Directory for persistent storage.
     * @param identityDid DID string of a pre-existing identity, or null to generate a fresh one.
     * @param passphrase Passphrase for Argon2id key derivation. Required when identityDid is null.
     * @return A [Node] with [Node.relayUrl] and [Node.did] populated.
     */
    suspend fun startNodeLocal(dataDir: String, identityDid: String? = null, passphrase: String? = null): Node =
        bridge.ffiCall {
            val json = bindings.nodeStartLocal(dataDir, identityDid, passphrase)
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

    // HTTP server lifecycle

    /**
     * Starts the HTTP server in the background.
     *
     * @param node The running node.
     * @param bindAddr Socket address to bind, or null for default.
     * @return The actual bound address as a string.
     */
    internal suspend fun serve(
        node: Node,
        bindAddr: String?,
    ): String = bridge.ffiCall {
        bindings.nodeServe(node.handleJson, bindAddr)
    }

    /**
     * Returns the HTTP URL of the background server, or null if not serving.
     *
     * @param node The running node.
     */
    internal suspend fun httpUrl(
        node: Node,
    ): String? = bridge.ffiCall {
        bindings.nodeHttpUrl(node.handleJson)
    }

    // Broadcast deployment lifecycle (SCP-296, spec section 18.11.8)

    /**
     * Activates HTTP broadcast projection for a context.
     *
     * Three resolution modes:
     * 1. Both [broadcastKeyHex] **and** [authorDid] provided -- uses the
     *    explicit key with epoch 0.
     * 2. Only [authorDid] provided -- auto-resolves the broadcast key
     *    using that DID (useful when the author identity differs from the
     *    node identity).
     * 3. Neither provided -- auto-resolves using the node's identity DID.
     *
     * Providing [broadcastKeyHex] without [authorDid] is an error.
     *
     * @param node The running node.
     * @param contextId The context ID to project.
     * @param broadcastKeyHex 32-byte AES-256 broadcast key as 64-char hex string, or null for auto-lookup.
     * @param authorDid DID of the broadcast key owner, or null for auto-lookup.
     * @param admission "open" or "gated".
     * @param config [SiteConfig] with hostname, index path, and deploy limits.
     */
    @Suppress("LongParameterList")
    internal suspend fun enableSiteProjection(
        node: Node,
        contextId: String,
        broadcastKeyHex: String?,
        authorDid: String?,
        admission: String,
        config: SiteConfig,
    ) = bridge.ffiCall {
        bindings.nodeEnableSiteProjection(
            node.handleJson,
            contextId,
            admission,
            config.hostname,
            broadcastKeyHex,
            authorDid,
            if (config.indexPath == "/index.html") null else config.indexPath,
            if (config.maxAssetsPerDeploy == 10_000) null else config.maxAssetsPerDeploy,
            if (config.maxDeploySizeBytes == 536_870_912L) null else config.maxDeploySizeBytes,
            if (config.deployRetentionCount == 2) null else config.deployRetentionCount,
            config.cspOverride,
        )
    }

    /**
     * Commits a deploy for a projected context.
     *
     * @param node The running node.
     * @param contextId The projected context ID.
     * @param deployId The deploy identifier (hex).
     * @return The number of assets in the committed deploy.
     */
    internal suspend fun commitDeploy(
        node: Node,
        contextId: String,
        deployId: String,
    ): Int = bridge.ffiCall {
        bindings.nodeCommitDeploy(node.handleJson, contextId, deployId)
    }

    /**
     * Rolls back to a previous deploy for a projected context.
     *
     * @param node The running node.
     * @param contextId The projected context ID.
     * @param deployId The deploy identifier to roll back to.
     */
    internal suspend fun rollbackDeploy(
        node: Node,
        contextId: String,
        deployId: String,
    ) = bridge.ffiCall {
        bindings.nodeRollbackDeploy(node.handleJson, contextId, deployId)
    }

    /**
     * Deactivates HTTP broadcast projection for a context.
     *
     * @param node The running node.
     * @param contextId The context ID to stop projecting.
     */
    internal suspend fun disableSiteProjection(
        node: Node,
        contextId: String,
    ) = bridge.ffiCall {
        bindings.nodeDisableSiteProjection(node.handleJson, contextId)
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
