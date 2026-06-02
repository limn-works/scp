// PersistenceTest.kt — SDK-layer smoke test for SQLite-backed persistence.
//
// #1549 Phase 4 PR 3. Verifies that the Kotlin SDK wrapper surface:
//
// 1. Accepts `SCP.withSqlite(dir, key)` and forwards to UniFFI
//    `Scp.withStorage(StorageConfig.Sqlite(path, key))` without raising.
// 2. Creates the SQLCipher database file at `{dir}/scp.db` as a side
//    effect of construction — see
//    `crates/scp-ffi/uniffi/src/runtime.rs::with_storage_uniffi`.
// 3. Drives the full `suspend() → resume() → shutdown()` lifecycle on
//    a SQLite-backed instance without error. All three are `suspend`
//    functions in the Kotlin SDK, routed through `CoroutineBridge`.
// 4. Is reconstructible against the SAME SQLite directory + key — the
//    reopened instance must open the encrypted database again without
//    re-deriving a fresh key.
//
// The wrapper surface is all this smoke test is responsible for. The
// end-to-end `identityCreate → contextCreate → contextSend → suspend
// → restore` path is exercised at the Rust integration layer
// (`crates/scp-testing/tests/integration/persistence_sdk.rs`) because
// the Kotlin `SCP` class does not yet surface context methods — the
// free-function façade routes to the process-global default instance,
// not to a caller-owned `SCP` handle, and that migration is in #1549
// PR 4+.
//
// The suite skips (via JUnit 5 `assumeTrue`) when the UniFFI cdylib
// is not loadable, matching the pattern in `ScpClassTest` and
// `RealFFITest`.

package works.limn.scp

import java.nio.file.Files
import kotlin.io.path.exists
import kotlin.io.path.pathString
import kotlin.test.assertNotEquals
import kotlin.test.assertFailsWith
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
class PersistenceTest {
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

    private val createdInstances = mutableListOf<SCP>()

    /// Stable 32-byte SQLCipher key. The specific value does not matter;
    /// only that the same key is reused across the two constructions
    /// that simulate process restart.
    private val sqliteKey: ByteArray = ByteArray(32) { 0x42 }

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
        val bridge = bridge()
        for (scp in createdInstances) {
            runBlocking { scp.shutdown(bridge, 1.seconds) }
        }
        createdInstances.clear()
    }

    @Test
    fun `withSqlite creates the SQLCipher database file at dir slash scp dot db`() =
        runTest {
            val dir = Files.createTempDirectory("scp-kotlin-persist-")
            dir.toFile().deleteOnExit()
            val dbPath = dir.resolve("scp.db")
            assertTrue(
                !dbPath.exists(),
                "scp.db must not exist before SCP.withSqlite at ${dbPath.pathString}",
            )

            val scp = SCP.withSqlite(dir.toFile(), sqliteKey)
            createdInstances += scp

            assertTrue(
                dbPath.exists(),
                "SCP.withSqlite(dir, key) must create scp.db at ${dbPath.pathString}",
            )
            assertNotEquals(0UL, scp.instanceId, "instanceId must be monotonic and non-UNSET")
        }

    @Test
    fun `withSqlite roundtrips suspend then resume via CoroutineBridge`() =
        runTest {
            val dir = Files.createTempDirectory("scp-kotlin-persist-lifecycle-")
            dir.toFile().deleteOnExit()
            val bridge = bridge()

            val scp = SCP.withSqlite(dir.toFile(), sqliteKey)
            createdInstances += scp

            scp.suspend(bridge)
            scp.resume(bridge)
            // Reaching here means both suspend and resume completed
            // without raising — the SQLite-backed path composes with
            // the async resume wiring introduced in #1549 PR 3.
            assertTrue(true)
        }

    @Test
    fun `withSqlite reopens the same dir plus key across two constructions`() =
        runTest {
            val dir = Files.createTempDirectory("scp-kotlin-persist-reopen-")
            dir.toFile().deleteOnExit()

            val scp1 = SCP.withSqlite(dir.toFile(), sqliteKey)
            val id1 = scp1.instanceId
            createdInstances += scp1

            val scp2 = SCP.withSqlite(dir.toFile(), sqliteKey)
            val id2 = scp2.instanceId
            createdInstances += scp2

            assertNotEquals(
                id1,
                id2,
                "each SCP.withSqlite(...) must produce an independent UniffiBridgeInstance",
            )
        }

    @Test
    fun `withSqlite fails closed on mismatched key without corrupting the DB`() =
        runTest {
            val dir = Files.createTempDirectory("scp-kotlin-persist-mismatch-")
            dir.toFile().deleteOnExit()

            // First open with the correct key — creates the encrypted DB.
            val scp1 = SCP.withSqlite(dir.toFile(), sqliteKey)
            createdInstances += scp1

            // Second open with a wrong key must FAIL CLOSED (spec §17.6):
            // the bridge throws rather than silently falling back to an
            // in-memory instance.
            val wrongKey = ByteArray(32) { 0x11 }
            assertFailsWith<uniffi.scp.ScpException> {
                SCP.withSqlite(dir.toFile(), wrongKey)
            }

            // Third open with the correct key — must still succeed (no
            // corruption from the rejected attempt).
            val scp3 = SCP.withSqlite(dir.toFile(), sqliteKey)
            createdInstances += scp3
        }

    @Test
    fun `withSqlite passphrase round trips across two constructions`() =
        runTest {
            val dir = Files.createTempDirectory("scp-kotlin-persist-passphrase-")
            dir.toFile().deleteOnExit()
            val dbPath = dir.resolve("scp.db")

            val scp1 = SCP.withSqlite(dir.toFile(), passphrase = "correct horse battery staple")
            createdInstances += scp1
            assertTrue(
                dbPath.exists(),
                "passphrase construction must create scp.db at ${dbPath.pathString}",
            )

            // Reopen with the SAME passphrase — must succeed (salt sidecar
            // re-derives the same key).
            val scp2 = SCP.withSqlite(dir.toFile(), passphrase = "correct horse battery staple")
            createdInstances += scp2
        }

    @Test
    fun `withSqlite fails closed on wrong passphrase`() =
        runTest {
            val dir = Files.createTempDirectory("scp-kotlin-persist-wrongpass-")
            dir.toFile().deleteOnExit()

            val scp1 = SCP.withSqlite(dir.toFile(), passphrase = "the-right-one")
            createdInstances += scp1

            // Reopen with the WRONG passphrase must fail closed — never
            // silently open a fresh DB (spec §17.6).
            assertFailsWith<uniffi.scp.ScpException> {
                SCP.withSqlite(dir.toFile(), passphrase = "the-WRONG-one")
            }
        }
}
