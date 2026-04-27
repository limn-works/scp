// McpAllowlistTest.kt — SDK-level ceremony tests for the per-instance MCP
// stdio allowlist (#1543 PR-D).
//
// The Kotlin wrapper requires `iTrustAllCommands = true` before delegating
// to the inner UniFFI-generated `Scp` and writes a runtime warning when
// proceeding. The throw happens at the wrapper layer before any native
// call — but constructing `SCP()` itself requires the UniFFI library, so
// the suite skips gracefully when the binary is unavailable, matching
// `ScpClassTest`'s pattern.
//
// Provenance: ADR-048 §1 multi-instance neutrality.

package works.limn.scp

import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class McpAllowlistTest {
    companion object {
        private var nativeAvailable = false
        private var skipReason = ""

        @JvmStatic
        @BeforeAll
        fun probeNativeLibrary() {
            try {
                Class.forName("uniffi.scp.ScpKt")
                Class.forName("uniffi.scp.Scp\$Companion")
                nativeAvailable = true
            } catch (e: ClassNotFoundException) {
                skipReason = "UniFFI bindings not available: ${e.message}"
            } catch (e: UnsatisfiedLinkError) {
                skipReason = "Native library link error: ${e.message}"
            } catch (e: ExceptionInInitializerError) {
                skipReason = "Native library init error: ${e.cause?.message ?: e.message}"
            } catch (e: NoClassDefFoundError) {
                skipReason = "Native library class not found: ${e.message}"
            }
        }
    }

    private lateinit var scp: SCP

    @BeforeEach
    fun setUp() {
        assumeTrue(nativeAvailable, skipReason)
        scp = SCP()
    }

    @AfterEach
    fun tearDown() {
        if (!this::scp.isInitialized) return
        runBlocking {
            val bridge =
                works.limn.scp.bridge.CoroutineBridge(
                    nativeBindings = works.limn.scp.conformance.ConformanceStubBindings(),
                    ioDispatcher = kotlinx.coroutines.Dispatchers.IO,
                    cpuDispatcher = kotlinx.coroutines.Dispatchers.Default,
                )
            scp.shutdown(bridge, 1.seconds)
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
        val other = SCP()
        try {
            val bState = other.mcpGetStdioAllowlist()
            assertFalse(bState.unrestricted, "instance b must remain restricted")
            // Default allow set is identical on each fresh instance.
            assertEquals(aState.allowed.toSet(), bState.allowed.toSet())
        } finally {
            runBlocking {
                val bridge =
                    works.limn.scp.bridge.CoroutineBridge(
                        nativeBindings = works.limn.scp.conformance.ConformanceStubBindings(),
                        ioDispatcher = kotlinx.coroutines.Dispatchers.IO,
                        cpuDispatcher = kotlinx.coroutines.Dispatchers.Default,
                    )
                other.shutdown(bridge, 1.seconds)
            }
        }
    }
}
