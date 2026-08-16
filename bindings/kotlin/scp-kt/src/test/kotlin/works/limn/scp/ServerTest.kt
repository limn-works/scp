// ServerTest.kt -- Unit tests for Node broadcast deployment lifecycle (SCP-296)
//
// Tests use stub ServerBindings; no Rust binary required.
//
// Provenance: spec section 18.11.8, SCP-296

package works.limn.scp

import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import works.limn.scp.bridge.BridgeException
import works.limn.scp.bridge.CoroutineBridge
import works.limn.scp.conformance.ConformanceStubBindings
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ServerTest {

    private lateinit var testDispatcher: TestDispatcher
    private lateinit var stubBindings: StubServerBindings
    private lateinit var bridge: CoroutineBridge
    private lateinit var serverBridge: ServerBridge

    @BeforeEach
    fun setUp() {
        testDispatcher = StandardTestDispatcher()
        stubBindings = StubServerBindings()
        // CoroutineBridge requires NativeBindings — use ConformanceStubBindings.
        bridge = CoroutineBridge(
            nativeBindings = ConformanceStubBindings(),
            ioDispatcher = testDispatcher,
            cpuDispatcher = testDispatcher,
        )
        serverBridge = ServerBridge(bindings = stubBindings, bridge = bridge)
    }

    private suspend fun createNode(): Node {
        stubBindings.nodeStartInMemoryResult =
            """{"relayUrl":"ws://127.0.0.1:9876/scp/v1","relayPort":9876,"did":"did:dht:z6MkTestNode"}"""
        return Node.startInMemory(serverBridge)
    }

    // MARK: - enableSiteProjection

    @Test
    fun `enableSiteProjection delegates to bindings with correct arguments`() = runTest(testDispatcher) {
        val node = createNode()
        val config = SiteConfig(
            hostname = "mysite.example.com",
            indexPath = "/app.html",
            maxAssetsPerDeploy = 5000,
            maxDeploySizeBytes = 100_000_000L,
            deployRetentionCount = 4,
            cspOverride = "default-src 'self'",
        )

        node.enableSiteProjection(
            contextId = "ctx-123",
            admission = "open",
            config = config,
            broadcastKeyHex = "ab".repeat(32),
            authorDid = "did:dht:z6MkAuthor",
        )

        val args = stubBindings.lastEnableSiteProjectionArgs
        assertEquals("ctx-123", args?.contextId)
        assertEquals("ab".repeat(32), args?.broadcastKeyHex)
        assertEquals("did:dht:z6MkAuthor", args?.authorDid)
        assertEquals("open", args?.admission)
        assertEquals("mysite.example.com", args?.hostname)
        assertEquals("/app.html", args?.indexPath)
        assertEquals(5000, args?.maxAssetsPerDeploy)
        assertEquals(100_000_000L, args?.maxDeploySizeBytes)
        assertEquals(4, args?.deployRetentionCount)
        assertEquals("default-src 'self'", args?.cspOverride)
    }

    @Test
    fun `enableSiteProjection passes null for default SiteConfig values`() = runTest(testDispatcher) {
        val node = createNode()
        val config = SiteConfig(hostname = "example.com")

        node.enableSiteProjection(
            contextId = "ctx-456",
            admission = "gated",
            config = config,
            broadcastKeyHex = "cd".repeat(32),
            authorDid = "did:dht:z6MkAuthor2",
        )

        val args = stubBindings.lastEnableSiteProjectionArgs
        assertEquals(null, args?.indexPath)
        assertEquals(null, args?.maxAssetsPerDeploy)
        assertEquals(null, args?.maxDeploySizeBytes)
        assertEquals(null, args?.deployRetentionCount)
        assertEquals(null, args?.cspOverride)
    }

    // MARK: - commitDeploy

    @Test
    fun `commitDeploy returns asset count`() = runTest(testDispatcher) {
        val node = createNode()
        stubBindings.commitDeployResult = 42

        val count = node.commitDeploy("ctx-123", "deploy-abc")

        assertEquals(42, count)
    }

    @Test
    fun `commitDeploy propagates errors`() = runTest(testDispatcher) {
        val node = createNode()
        stubBindings.commitDeployError = BridgeException("not projected", "SCP-CTX-2080")

        assertFailsWith<BridgeException> {
            node.commitDeploy("ctx-bad", "deploy-xyz")
        }.also {
            assertTrue(it.message!!.contains("not projected"))
        }
    }

    // MARK: - rollbackDeploy

    @Test
    fun `rollbackDeploy delegates to bindings`() = runTest(testDispatcher) {
        val node = createNode()

        node.rollbackDeploy("ctx-123", "deploy-old")

        assertEquals("ctx-123", stubBindings.lastRollbackContextId)
        assertEquals("deploy-old", stubBindings.lastRollbackDeployId)
    }

    @Test
    fun `rollbackDeploy propagates errors`() = runTest(testDispatcher) {
        val node = createNode()
        stubBindings.rollbackDeployError = BridgeException("deploy not found", "SCP-CTX-2081")

        assertFailsWith<BridgeException> {
            node.rollbackDeploy("ctx-bad", "deploy-nope")
        }.also {
            assertTrue(it.message!!.contains("deploy not found"))
        }
    }

    // MARK: - disableSiteProjection

    @Test
    fun `disableSiteProjection delegates to bindings`() = runTest(testDispatcher) {
        val node = createNode()

        node.disableSiteProjection("ctx-123")

        assertEquals("ctx-123", stubBindings.lastDisableContextId)
    }

    @Test
    fun `disableSiteProjection is idempotent on unprojected context`() = runTest(testDispatcher) {
        val node = createNode()
        // Should not throw -- stub does nothing.
        node.disableSiteProjection("ctx-nonexistent")
    }

    // MARK: - Node properties

    @Test
    fun `node properties from handle JSON`() = runTest(testDispatcher) {
        val node = createNode()
        assertEquals("ws://127.0.0.1:9876/scp/v1", node.relayUrl)
        assertEquals(9876, node.relayPort)
        assertEquals("did:dht:z6MkTestNode", node.did)
    }

    // MARK: - Shutdown is one suspending path

    // Neither type implements AutoCloseable. A synchronous `close()` can only reach
    // `shutdown()` by blocking its calling thread on a coroutine whose dispatcher
    // neither type controls, which is what `.docs/lessons/kotlin/
    // oncleared-must-not-block-its-caller.md` forbids. Restoring `: AutoCloseable`
    // on either declaration fails this method.
    @Test
    fun `neither Relay nor Node implements AutoCloseable`() {
        assertFalse(
            AutoCloseable::class.java.isAssignableFrom(Relay::class.java),
            "Relay must expose suspend shutdown() alone, never a blocking close()",
        )
        assertFalse(
            AutoCloseable::class.java.isAssignableFrom(Node::class.java),
            "Node must expose suspend shutdown() alone, never a blocking close()",
        )
    }

    // Every declared method that stops a Node or a Relay suspends. A non-suspending
    // stop method under any name — `close`, `stop`, `dispose` — reintroduces that
    // same blocking shape, so this method matches on behaviour rather than on one
    // interface name. Kotlin compiles a suspend function to a JVM method taking a
    // trailing `kotlin.coroutines.Continuation`, which is how it is recognised here.
    @Test
    fun `every stop method on Relay and Node suspends`() {
        for (type in listOf(Relay::class.java, Node::class.java)) {
            val stopMethods = type.declaredMethods.filter { method ->
                method.name.substringBefore('$') in setOf("shutdown", "close", "stop", "dispose")
            }
            assertTrue(
                stopMethods.isNotEmpty(),
                "${type.simpleName} must declare a stop method",
            )
            for (method in stopMethods) {
                assertTrue(
                    method.parameterTypes.lastOrNull()?.name == "kotlin.coroutines.Continuation",
                    "${type.simpleName}.${method.name} must suspend, so a caller picks its dispatcher",
                )
            }
        }
    }

    @Test
    fun `shutdown marks a node shut down`() = runTest(testDispatcher) {
        val node = createNode()
        assertFalse(node.isShutdown)
        node.shutdown()
        assertTrue(node.isShutdown)
    }
}

// ---------------------------------------------------------------------------
// Stub ServerBindings
// ---------------------------------------------------------------------------

/**
 * Configurable stub for [ServerBindings] that records call arguments
 * and returns canned responses.
 */
internal class StubServerBindings : ServerBindings {

    // serve / httpUrl
    var serveResult: String = "127.0.0.1:8443"
    override fun nodeServe(handleJson: String, bindAddr: String?): String = serveResult

    var httpUrlResult: String? = null
    override fun nodeHttpUrl(handleJson: String): String? = httpUrlResult

    // Startup/shutdown
    var nodeStartInMemoryResult: String =
        """{"relayUrl":"ws://127.0.0.1:0/scp/v1","relayPort":0,"did":"did:dht:stub"}"""
    var relayStartInMemoryResult: String =
        """{"relayUrl":"ws://127.0.0.1:0/scp/v1","relayPort":0}"""

    override fun relayStartInMemory(): String = relayStartInMemoryResult
    override fun relayStartLocal(dataDir: String): String = relayStartInMemoryResult
    override fun nodeStartInMemory(identityDid: String?): String = nodeStartInMemoryResult
    override fun nodeStartLocal(
        dataDir: String,
        identityDid: String?,
        passphrase: String?,
    ): String = nodeStartInMemoryResult
    override fun relayShutdown(handleJson: String) { /* no-op stub */ }
    override fun nodeShutdown(handleJson: String) { /* no-op stub */ }

    // enableSiteProjection
    data class EnableArgs(
        val contextId: String,
        val broadcastKeyHex: String?,
        val authorDid: String?,
        val admission: String,
        val hostname: String,
        val indexPath: String?,
        val maxAssetsPerDeploy: Int?,
        val maxDeploySizeBytes: Long?,
        val deployRetentionCount: Int?,
        val cspOverride: String?,
    )

    var lastEnableSiteProjectionArgs: EnableArgs? = null

    @Suppress("LongParameterList")
    override fun nodeEnableSiteProjection(
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
    ) {
        lastEnableSiteProjectionArgs = EnableArgs(
            contextId, broadcastKeyHex, authorDid, admission, hostname,
            indexPath, maxAssetsPerDeploy, maxDeploySizeBytes, deployRetentionCount, cspOverride,
        )
    }

    // commitDeploy
    var commitDeployResult: Int = 0
    var commitDeployError: BridgeException? = null

    override fun nodeCommitDeploy(handleJson: String, contextId: String, deployId: String): Int {
        commitDeployError?.let { throw it }
        return commitDeployResult
    }

    // rollbackDeploy
    var lastRollbackContextId: String? = null
    var lastRollbackDeployId: String? = null
    var rollbackDeployError: BridgeException? = null

    override fun nodeRollbackDeploy(handleJson: String, contextId: String, deployId: String) {
        rollbackDeployError?.let { throw it }
        lastRollbackContextId = contextId
        lastRollbackDeployId = deployId
    }

    // disableSiteProjection
    var lastDisableContextId: String? = null

    override fun nodeDisableSiteProjection(handleJson: String, contextId: String) {
        lastDisableContextId = contextId
    }
}
