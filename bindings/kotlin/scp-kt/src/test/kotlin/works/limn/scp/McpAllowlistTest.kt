// McpAllowlistTest.kt — SDK-level ceremony tests for the per-instance MCP
// stdio allowlist.
//
// The Kotlin wrapper requires `iTrustAllCommands = true` before delegating
// to the inner UniFFI-generated `Scp` and writes a runtime warning when
// proceeding. The throw happens at the wrapper layer before any native
// call — but constructing `SCP()` itself requires the UniFFI library. A
// cdylib that is absent or fails to load throws `UnsatisfiedLinkError` from
// the first native call and fails the test.
//
// Provenance: ADR-048 §1 multi-instance neutrality.

package works.limn.scp

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import uniffi.scp.StorageConfig
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

class McpAllowlistTest {
    private lateinit var scp: SCP

    @BeforeEach
    fun setUp() {
        scp = SCP(StorageConfig.InMemory)
    }

    @AfterEach
    fun tearDown() {
        if (!this::scp.isInitialized) return
        shutdownInstance(scp)
    }

    // / Shuts down [instance] using a fresh [CoroutineBridge] over the
    // / stub native bindings. Centralizes the cleanup pattern so changes
    // / to dispatcher wiring or shutdown timeout land in one place. See
    // / [ConformanceStubBindings] for the no-op shutdown surface.
    private fun shutdownInstance(instance: SCP) {
        runBlocking {
            val bridge =
                works.limn.scp.bridge.CoroutineBridge(
                    nativeBindings = works.limn.scp.conformance.ConformanceStubBindings(),
                    ioDispatcher = kotlinx.coroutines.Dispatchers.IO,
                    cpuDispatcher = kotlinx.coroutines.Dispatchers.Default,
                )
            instance.shutdown(bridge, 1.seconds)
        }
    }

    @Test
    fun `mcpDisableStdioAllowlist throws when iTrustAllCommands is omitted`() {
        val ex = assertThrows<IllegalArgumentException> { scp.mcpDisableStdioAllowlist() }
        assertTrue(
            ex.message.orEmpty().contains("iTrustAllCommands"),
            "expected ceremony message, got: ${ex.message}",
        )
    }

    @Test
    fun `mcpDisableStdioAllowlist throws when iTrustAllCommands is explicitly false`() {
        assertThrows<IllegalArgumentException> {
            scp.mcpDisableStdioAllowlist(iTrustAllCommands = false)
        }
    }

    @Test
    fun `mcpDisableStdioAllowlist succeeds when iTrustAllCommands is true and isolates`() {
        scp.mcpDisableStdioAllowlist(iTrustAllCommands = true)
        val aState = scp.mcpGetStdioAllowlist()
        assertTrue(aState.unrestricted, "instance a must report unrestricted after opt-in disable")

        // Sibling instance must remain restricted (per-instance isolation).
        val other = SCP(StorageConfig.InMemory)
        try {
            val bState = other.mcpGetStdioAllowlist()
            assertFalse(bState.unrestricted, "instance b must remain restricted")
            // Default allow set is identical on each fresh instance.
            assertEquals(aState.allowed.toSet(), bState.allowed.toSet())
        } finally {
            shutdownInstance(other)
        }
    }
}
