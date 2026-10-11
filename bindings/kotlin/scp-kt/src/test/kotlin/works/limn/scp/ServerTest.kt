// ServerTest.kt -- Unit tests for Node broadcast deployment lifecycle (SCP-296)
//
// Tests use stub ServerBindings; no Rust binary required.
//
// Provenance: spec section 18.11.8, SCP-296

package works.limn.scp

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
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
        bridge =
            CoroutineBridge(
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
    fun `enableSiteProjection delegates to bindings with correct arguments`() =
        runTest(testDispatcher) {
            val node = createNode()
            val config =
                SiteConfig(
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
    fun `enableSiteProjection passes null for default SiteConfig values`() =
        runTest(testDispatcher) {
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
    fun `commitDeploy returns asset count`() =
        runTest(testDispatcher) {
            val node = createNode()
            stubBindings.commitDeployResult = 42

            val count = node.commitDeploy("ctx-123", "deploy-abc")

            assertEquals(42, count)
        }

    @Test
    fun `commitDeploy propagates errors`() =
        runTest(testDispatcher) {
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
    fun `rollbackDeploy delegates to bindings`() =
        runTest(testDispatcher) {
            val node = createNode()

            node.rollbackDeploy("ctx-123", "deploy-old")

            assertEquals("ctx-123", stubBindings.lastRollbackContextId)
            assertEquals("deploy-old", stubBindings.lastRollbackDeployId)
        }

    @Test
    fun `rollbackDeploy propagates errors`() =
        runTest(testDispatcher) {
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
    fun `disableSiteProjection delegates to bindings`() =
        runTest(testDispatcher) {
            val node = createNode()

            node.disableSiteProjection("ctx-123")

            assertEquals("ctx-123", stubBindings.lastDisableContextId)
        }

    @Test
    fun `disableSiteProjection is idempotent on unprojected context`() =
        runTest(testDispatcher) {
            val node = createNode()
            // Should not throw -- stub does nothing.
            node.disableSiteProjection("ctx-nonexistent")
        }

    // MARK: - Node properties

    @Test
    fun `node properties from handle JSON`() =
        runTest(testDispatcher) {
            val node = createNode()
            assertEquals("ws://127.0.0.1:9876/scp/v1", node.relayUrl)
            assertEquals(9876, node.relayPort)
            assertEquals("did:dht:z6MkTestNode", node.did)
        }

    // MARK: - Shutdown is one suspending path

    // No type in the §Resource Lifecycle table's Kotlin row implements AutoCloseable.
    // A synchronous `close()` can only reach `shutdown()` by blocking its calling
    // thread on a coroutine whose dispatcher these types do not control, which is
    // what `.docs/standards/sdk-common.md` §"Kotlin: why no `Closeable`" and the
    // amendment to ADR-028 in `.docs/adrs/phase-6.md` both forbid, and what
    // `.docs/lessons/kotlin/oncleared-must-not-block-its-caller.md` records failing
    // twice. Restoring `: AutoCloseable` on any of these declarations fails this
    // method.
    @Test
    fun `no lifecycle-owning type implements AutoCloseable`() {
        for (type in listOf(Relay::class.java, Node::class.java, SCP::class.java)) {
            assertFalse(
                AutoCloseable::class.java.isAssignableFrom(type),
                "${type.simpleName} must expose a suspend teardown alone, never a blocking close()",
            )
        }
    }

    // Every declared method named `shutdown`, `close`, `stop`, or `dispose` on one of
    // these types suspends. A non-suspending method under any of those four names
    // reintroduces that same blocking shape. This method matches those four names and
    // nothing else: a blocking stop method under another name (`release`, `terminate`),
    // or a blocking top-level extension, which `declaredMethods` never lists, passes it.
    // Kotlin compiles a suspend function to a JVM method taking a
    // trailing `kotlin.coroutines.Continuation`, which is how it is recognised here.
    //
    // Two JVM-name suffixes are stripped before matching. Kotlin appends `$default`
    // to the synthetic overload it emits for a defaulted parameter, and appends
    // `-<hash>` to any method whose signature carries an inline value class —
    // `SCP.shutdown(bridge, timeout: Duration)` compiles to `shutdown-8Mi8wO0`.
    // Matching the raw JVM name would silently skip both. A name carrying `$lambda`
    // is excluded: it is the compiled body of a lambda written inside a stop method
    // (`shutdown$lambda$0`), not a stop method a caller can invoke.
    @Test
    fun `every stop method on a lifecycle-owning type suspends`() {
        for (type in listOf(Relay::class.java, Node::class.java, SCP::class.java)) {
            val stopMethods = type.declaredMethods.filter { isStopMethodName(it.name) }
            assertTrue(
                stopMethods.isNotEmpty(),
                "${type.simpleName} must declare a stop method",
            )
            for (method in stopMethods) {
                // A suspend function carries a `Continuation` parameter. It sits last on the
                // real method, and second-to-last on the `$default` synthetic (which appends
                // an int mask and an Object marker), so this asserts presence rather than
                // position. A genuinely non-suspending stop method carries none at all.
                assertTrue(
                    method.parameterTypes.any { it.name == "kotlin.coroutines.Continuation" },
                    "${type.simpleName}.${method.name} must suspend, so a caller picks its dispatcher",
                )
            }
        }
    }

    @Test
    fun `stop-method name filter keeps compiled stop overloads and drops lambda bodies`() {
        for (name in listOf("shutdown", "shutdown\$default", "shutdown-8Mi8wO0", "close", "stop", "dispose")) {
            assertTrue(isStopMethodName(name), "$name is a stop method")
        }
        for (name in listOf("shutdown\$lambda\$0", "close\$lambda\$1", "release", "shutdownAll")) {
            assertFalse(isStopMethodName(name), "$name is not a stop method")
        }
        // The name the compiler really emits for a lambda inside a stop method.
        val lambdaBodies =
            LambdaInStopFixture::class.java.declaredMethods.map { it.name }.filter { "\$lambda" in it }
        assertTrue(lambdaBodies.isNotEmpty(), "fixture must compile a lambda body method")
        for (name in lambdaBodies) assertFalse(isStopMethodName(name), "$name is a lambda body")
        assertTrue(
            LambdaInStopFixture::class.java.declaredMethods.any { isStopMethodName(it.name) },
            "fixture shutdown itself is a stop method",
        )
    }

    @Test
    fun `shutdown stops a node through the bridge and marks it shut down`() {
        runTest(testDispatcher) {
            val node = createNode()
            assertFalse(node.isShutdown)
            node.shutdown()
            assertEquals(listOf(node.handleJson), stubBindings.nodeShutdownHandles)
            assertTrue(node.isShutdown)
        }
    }

    @Test
    fun `shutdown stops a relay through the bridge and marks it shut down`() {
        runTest(testDispatcher) {
            val relay = Relay.startInMemory(serverBridge)
            assertFalse(relay.isShutdown)
            relay.shutdown()
            assertEquals(listOf(relay.handleJson), stubBindings.relayShutdownHandles)
            assertTrue(relay.isShutdown)
        }
    }

    // A failed engine teardown propagates, and the type keeps reporting itself live, so a
    // caller that retries on `!isShutdown` retries (sdk-common.md §"Kotlin: why no `Closeable`").
    @Test
    fun `a failed node shutdown propagates and leaves the node live`() {
        runTest(testDispatcher) {
            val node = createNode()
            stubBindings.shutdownFailure = IllegalStateException("engine refused stop")
            assertFailsWith<Exception> { node.shutdown() }
            assertEquals(listOf(node.handleJson), stubBindings.nodeShutdownHandles)
            assertFalse(node.isShutdown)
        }
    }

    @Test
    fun `a failed relay shutdown propagates and leaves the relay live`() {
        runTest(testDispatcher) {
            val relay = Relay.startInMemory(serverBridge)
            stubBindings.shutdownFailure = IllegalStateException("engine refused stop")
            assertFailsWith<Exception> { relay.shutdown() }
            assertEquals(listOf(relay.handleJson), stubBindings.relayShutdownHandles)
            assertFalse(relay.isShutdown)
        }
    }

    // A caller cancelled while the engine tears down gets a CancellationException from the
    // bridge's trailing ensureActive, although the teardown finished. The flag must still
    // record the shutdown, or `isShutdown` reports a torn-down object as live.
    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `a node shutdown whose caller is cancelled after the teardown still marks it shut down`() {
        runTest(testDispatcher) {
            val node = createNode()
            lateinit var caller: Job
            stubBindings.afterShutdown = { caller.cancel() }
            caller = launch { node.shutdown() }
            advanceUntilIdle()
            assertTrue(caller.isCancelled)
            assertEquals(listOf(node.handleJson), stubBindings.nodeShutdownHandles)
            assertTrue(node.isShutdown)
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `a relay shutdown whose caller is cancelled after the teardown still marks it shut down`() {
        runTest(testDispatcher) {
            val relay = Relay.startInMemory(serverBridge)
            lateinit var caller: Job
            stubBindings.afterShutdown = { caller.cancel() }
            caller = launch { relay.shutdown() }
            advanceUntilIdle()
            assertTrue(caller.isCancelled)
            assertEquals(listOf(relay.handleJson), stubBindings.relayShutdownHandles)
            assertTrue(relay.isShutdown)
        }
    }

    // The Relay and Node KDoc examples tear down from a `finally` block under NonCancellable.
    // These cases pin why: a cancelled owner reaches the `finally` block cancelled, and a bare
    // shutdown() there throws at the bridge's withContext before the FFI teardown runs.
    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `a relay shut down under NonCancellable in the finally block of a cancelled owner stops`() {
        runTest(testDispatcher) {
            val relay = Relay.startInMemory(serverBridge)
            val owner =
                launch {
                    try {
                        awaitCancellation()
                    } finally {
                        withContext(NonCancellable) { relay.shutdown() }
                    }
                }
            advanceUntilIdle()
            owner.cancel()
            advanceUntilIdle()
            assertTrue(owner.isCancelled)
            assertEquals(listOf(relay.handleJson), stubBindings.relayShutdownHandles)
            assertTrue(relay.isShutdown)
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `a relay shut down bare in the finally block of a cancelled owner stays live`() {
        runTest(testDispatcher) {
            val relay = Relay.startInMemory(serverBridge)
            val owner =
                launch {
                    try {
                        awaitCancellation()
                    } finally {
                        relay.shutdown()
                    }
                }
            advanceUntilIdle()
            owner.cancel()
            advanceUntilIdle()
            assertTrue(owner.isCancelled)
            assertEquals(emptyList<String>(), stubBindings.relayShutdownHandles)
            assertFalse(relay.isShutdown)
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `a node shut down under NonCancellable in the finally block of a cancelled owner stops`() {
        runTest(testDispatcher) {
            val node = createNode()
            val owner =
                launch {
                    try {
                        awaitCancellation()
                    } finally {
                        withContext(NonCancellable) { node.shutdown() }
                    }
                }
            advanceUntilIdle()
            owner.cancel()
            advanceUntilIdle()
            assertTrue(owner.isCancelled)
            assertEquals(listOf(node.handleJson), stubBindings.nodeShutdownHandles)
            assertTrue(node.isShutdown)
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `a node shut down bare in the finally block of a cancelled owner stays live`() {
        runTest(testDispatcher) {
            val node = createNode()
            val owner =
                launch {
                    try {
                        awaitCancellation()
                    } finally {
                        node.shutdown()
                    }
                }
            advanceUntilIdle()
            owner.cancel()
            advanceUntilIdle()
            assertTrue(owner.isCancelled)
            assertEquals(emptyList<String>(), stubBindings.nodeShutdownHandles)
            assertFalse(node.isShutdown)
        }
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

    override fun nodeServe(
        handleJson: String,
        bindAddr: String?,
    ): String = serveResult

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

    val relayShutdownHandles = mutableListOf<String>()
    val nodeShutdownHandles = mutableListOf<String>()

    /** When set, [relayShutdown] and [nodeShutdown] record the call and then throw this. */
    var shutdownFailure: RuntimeException? = null

    /** When set, [relayShutdown] and [nodeShutdown] run this after a teardown that succeeds. */
    var afterShutdown: (() -> Unit)? = null

    override fun relayShutdown(handleJson: String) {
        relayShutdownHandles += handleJson
        shutdownFailure?.let { throw it }
        afterShutdown?.invoke()
    }

    override fun nodeShutdown(handleJson: String) {
        nodeShutdownHandles += handleJson
        shutdownFailure?.let { throw it }
        afterShutdown?.invoke()
    }

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
        lastEnableSiteProjectionArgs =
            EnableArgs(
                contextId, broadcastKeyHex, authorDid, admission, hostname,
                indexPath, maxAssetsPerDeploy, maxDeploySizeBytes, deployRetentionCount, cspOverride,
            )
    }

    // commitDeploy
    var commitDeployResult: Int = 0
    var commitDeployError: BridgeException? = null

    override fun nodeCommitDeploy(
        handleJson: String,
        contextId: String,
        deployId: String,
    ): Int {
        commitDeployError?.let { throw it }
        return commitDeployResult
    }

    // rollbackDeploy
    var lastRollbackContextId: String? = null
    var lastRollbackDeployId: String? = null
    var rollbackDeployError: BridgeException? = null

    override fun nodeRollbackDeploy(
        handleJson: String,
        contextId: String,
        deployId: String,
    ) {
        rollbackDeployError?.let { throw it }
        lastRollbackContextId = contextId
        lastRollbackDeployId = deployId
    }

    // disableSiteProjection
    var lastDisableContextId: String? = null

    override fun nodeDisableSiteProjection(
        handleJson: String,
        contextId: String,
    ) {
        lastDisableContextId = contextId
    }
}

private fun isStopMethodName(jvmName: String): Boolean =
    "\$lambda" !in jvmName &&
        jvmName.substringBefore('$').substringBefore('-') in setOf("shutdown", "close", "stop", "dispose")

private class LambdaInStopFixture {
    var stopped = false

    fun shutdown() {
        runLater { stopped = true }
    }

    private fun runLater(block: () -> Unit) = block()
}
