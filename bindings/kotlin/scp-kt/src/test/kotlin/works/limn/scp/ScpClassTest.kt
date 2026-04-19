// ScpClassTest.kt — Real-FFI tests for the SDK-level SCP class (#1549 Phase 4).
//
// Covers:
//   - SCP.withSqlite convenience companion (PR 3 StorageConfig::Sqlite)
//   - suspend / resume / shutdown routing through CoroutineBridge
//   - ffiCallSuspend wiring for UniFFI-generated `suspend fun` bindings
//
// All tests require the compiled UniFFI cdylib; if the native library is not
// loadable the suite skips via JUnit 5 assumptions, matching RealFFITest.
//
// Provenance: #1549 Phase 4 PR 3 (Kotlin slice). ADR-048.

package works.limn.scp

import java.nio.file.Files
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import works.limn.scp.bridge.CoroutineBridge
import works.limn.scp.conformance.ConformanceStubBindings
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class ScpClassTest {
    companion object {
        private var nativeAvailable = false
        private var skipReason = ""

        @JvmStatic
        @BeforeAll
        fun probeNativeLibrary() {
            try {
                Class.forName("uniffi.scp.ScpKt")
                // Touch a UniFFI helper to force JNA library resolution.
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

    private val createdInstances = mutableListOf<SCP>()

    private fun bridge(): CoroutineBridge =
        CoroutineBridge(
            nativeBindings = ConformanceStubBindings(),
            ioDispatcher = Dispatchers.IO,
            cpuDispatcher = Dispatchers.Default,
        )

    @BeforeEach
    fun requireNative() {
        assumeTrue(nativeAvailable, skipReason)
    }

    @AfterEach
    fun cleanup() {
        // Drain any SCP instances the test created. A second shutdown is a
        // no-op at the SDK surface (AlreadyShutDown is swallowed), so this
        // is safe even if the test already called shutdown() explicitly.
        val bridge = bridge()
        for (scp in createdInstances) {
            runBlocking { scp.shutdown(bridge, 1.seconds) }
        }
        createdInstances.clear()
    }

    // ── withSqlite ────────────────────────────────────────────────

    @Test
    fun `withSqlite constructs a persistent SCP backed by SqliteStorage`() =
        runTest {
            val dir = Files.createTempDirectory("scp-kotlin-sqlite-").toFile()
            dir.deleteOnExit()
            val key = ByteArray(32) { it.toByte() }

            val scp = SCP.withSqlite(dir, key)
            createdInstances += scp

            // The instance id is a monotonic counter; a fresh instance must
            // not collide with the reserved UNSET_INSTANCE_ID (0).
            assertNotEquals(0UL, scp.instanceId, "instanceId must not be UNSET")
        }

    @Test
    fun `withSqlite produces distinct instances across calls`() =
        runTest {
            val dirA = Files.createTempDirectory("scp-kotlin-sqlite-a-").toFile()
            val dirB = Files.createTempDirectory("scp-kotlin-sqlite-b-").toFile()
            dirA.deleteOnExit()
            dirB.deleteOnExit()
            val key = ByteArray(32) { 0x11 }

            val a = SCP.withSqlite(dirA, key)
            val b = SCP.withSqlite(dirB, key)
            createdInstances += a
            createdInstances += b

            assertNotEquals(
                a.instanceId,
                b.instanceId,
                "each SCP.withSqlite(...) must produce an independent UniffiBridgeInstance",
            )
        }

    // ── resume routed through ffiCallSuspend ──────────────────────

    @Test
    fun `resume invokes the async FFI path without blocking`() =
        runTest {
            val scp = SCP()
            createdInstances += scp
            val bridge = bridge()

            // resume() is async in PR 3B. If the SDK routed it through
            // ffiCall (non-suspend) this would either fail to compile or
            // blow up at runtime; reaching `assertTrue(true)` means the
            // suspend path executed end-to-end.
            scp.resume(bridge)
            assertTrue(true)
        }

    @Test
    fun `suspend-then-resume round-trips via CoroutineBridge`() =
        runTest {
            val scp = SCP()
            createdInstances += scp
            val bridge = bridge()

            scp.suspend(bridge)
            scp.resume(bridge)
            assertTrue(true)
        }

    // ── shutdown remains idempotent under ffiCallSuspend ──────────

    @Test
    fun `shutdown twice is idempotent`() =
        runTest {
            val scp = SCP()
            createdInstances += scp
            val bridge = bridge()

            scp.shutdown(bridge, 1.seconds)
            // Second shutdown must not throw — the SDK swallows
            // AlreadyShutDown at the wrapper layer.
            scp.shutdown(bridge, 1.seconds)
            assertTrue(true)
        }
}
