// ScpClassTest.kt — Real-FFI tests for the SDK-level SCP class (#1549 Phase 4).
//
// Covers:
//   - SCP.withSqlite convenience companion (PR 3 StorageConfig::Sqlite)
//   - suspendInstance / resume / shutdown routing through CoroutineBridge
//   - ffiCallSuspend wiring for UniFFI-generated `suspend fun` bindings
//
// Each test gets a fresh `SCP` via `@BeforeEach` and a deterministic
// shutdown via `@AfterEach`, so tests don't leak runtime state across the
// suite. After Phase 4 PR 4 (demolition) there is no `SCP.default()` —
// every caller must construct `SCP()` explicitly.
//
// All tests require the compiled UniFFI cdylib; if the native library is not
// loadable the suite skips via JUnit 5 assumptions, matching RealFFITest.
//
// Provenance: #1549 Phase 4 PR 3 / PR 4 (Kotlin slice). ADR-048.

package works.limn.scp

import java.nio.file.Files
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import works.limn.scp.bridge.CoroutineBridge
import works.limn.scp.conformance.ConformanceStubBindings

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

    private lateinit var scp: SCP

    private fun bridge(): CoroutineBridge =
        CoroutineBridge(
            nativeBindings = ConformanceStubBindings(),
            ioDispatcher = Dispatchers.IO,
            cpuDispatcher = Dispatchers.Default,
        )

    @BeforeEach
    fun setUp() {
        assumeTrue(nativeAvailable, skipReason)
        scp = SCP()
    }

    @AfterEach
    fun tearDown() {
        if (!this::scp.isInitialized) return
        // A second shutdown is a no-op at the SDK surface (AlreadyShutDown
        // is swallowed), so this is safe even if the test already called
        // shutdown() explicitly.
        runBlocking { scp.shutdown(bridge(), 1.seconds) }
    }

    // ── withSqlite ────────────────────────────────────────────────

    @Test
    fun `withSqlite constructs a persistent SCP backed by SqliteStorage`() =
        runTest {
            val dir = Files.createTempDirectory("scp-kotlin-sqlite-").toFile()
            dir.deleteOnExit()
            val key = ByteArray(32) { it.toByte() }

            val instance = SCP.withSqlite(dir, key)

            // The instance id is a monotonic counter; a fresh instance must
            // not collide with the reserved UNSET_INSTANCE_ID (0).
            assertNotEquals(0UL, instance.instanceId, "instanceId must not be UNSET")
            instance.shutdown(bridge(), 1.seconds)
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

            assertNotEquals(
                a.instanceId,
                b.instanceId,
                "each SCP.withSqlite(...) must produce an independent UniffiBridgeInstance",
            )
            a.shutdown(bridge(), 1.seconds)
            b.shutdown(bridge(), 1.seconds)
        }

    // ── Lifecycle routed through CoroutineBridge ──────────────────

    @Test
    fun `resume invokes the async FFI path without blocking`() =
        runTest {
            // resume() is async in PR 3B. If the SDK routed it through
            // ffiCall (non-suspend) this would either fail to compile or
            // blow up at runtime; reaching `assertTrue(true)` means the
            // suspend path executed end-to-end.
            scp.resume(bridge())
            assertTrue(true)
        }

    @Test
    fun `suspendInstance-then-resume round-trips via CoroutineBridge`() =
        runTest {
            scp.suspendInstance(bridge())
            scp.resume(bridge())
            assertTrue(true)
        }

    // ── shutdown remains idempotent under ffiCallSuspend ──────────

    @Test
    fun `shutdown twice is idempotent`() =
        runTest {
            scp.shutdown(bridge(), 1.seconds)
            // Second shutdown must not throw — the SDK swallows
            // AlreadyShutDown at the wrapper layer.
            scp.shutdown(bridge(), 1.seconds)
            assertTrue(true)
        }

    @Test
    fun `fresh SCP instances have distinct ids`() =
        runTest {
            val second = SCP()
            assertNotEquals(
                scp.instanceId,
                second.instanceId,
                "SCP() must allocate fresh instances, not reuse a cached handle",
            )
            second.shutdown(bridge(), 1.seconds)
        }

    // ── economy verify-payment-receipts (suspend, real UniFFI bridge) ──

    @Test
    fun `economyVerifyPaymentReceipts returns a results document for an empty batch`() =
        runBlocking {
            // The verify-payment-receipts path dispatches an
            // EconomyCommand to the supervisor, so a supervisor must be
            // attached first (mirrors the reference Rust test, which calls
            // configure_local_transport before the empty-batch call). An
            // empty receipt batch needs no payment adapter, so it is the
            // clean happy path once the supervisor is attached — the bridge
            // returns `{"all_valid":true,"results":[]}` (all_valid is
            // vacuously true for an empty batch).
            scp.configureLocalTransport("did:key:z6MkKotlinVerifyReceiptsEmptyTest")
            val out = scp.economyVerifyPaymentReceipts("[]")
            assertEquals("{\"all_valid\":true,\"results\":[]}", out)
        }
}
