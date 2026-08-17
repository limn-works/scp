// PersistenceTest.kt — SDK-layer smoke test for SQLite-backed persistence.
//
// #1549 Phase 4 PR 3 + PR 4. Verifies that the Kotlin SDK wrapper surface:
//
// 1. Accepts `SCP.withSqlite(dir, key)` and forwards to UniFFI
//    `Scp.withStorage(StorageConfig.Sqlite(path, key))` without raising.
// 2. Creates the SQLCipher database file at `{dir}/scp.db` as a side
//    effect of construction — see
//    `crates/scp-ffi/uniffi/src/runtime.rs::with_storage_uniffi`.
// 3. Drives the full `suspendInstance() → resume() → shutdown()` lifecycle
//    on a SQLite-backed instance without error. All three are `suspend`
//    functions in the Kotlin SDK, routed through `CoroutineBridge`.
// 4. Is reconstructible against the SAME SQLite directory + key — the
//    reopened instance must open the encrypted database again without
//    re-deriving a fresh key.
//
// Each test gets its own tmp dir + `SCP.withSqlite(...)` instance and
// tears it down deterministically via `@AfterEach` so tests don't leak
// runtime state across the suite.
//
// The end-to-end `identityCreate → contextCreate → contextSend → suspend
// → restore` path is exercised at the Rust integration layer
// (`crates/scp-testing/tests/integration/persistence_sdk.rs`).
//
// The suite skips (via JUnit 5 `assumeTrue`) when the UniFFI cdylib
// is not loadable, matching the pattern in `ScpClassTest`.

package works.limn.scp

import java.io.File
import java.nio.file.Files
import kotlin.io.path.exists
import kotlin.io.path.pathString
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import uniffi.scp.ScpException
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
        /**
         * Error code the UniFFI bridge raises when a durable storage backend
         * cannot be opened — `StorageInitError::SqliteOpen` converted to
         * `ScpError::Validation` in `crates/scp-ffi/uniffi/src/runtime.rs`, the
         * same code the `PyO3` and NAPI bridges report for that same failure.
         * Spec §17.6 makes a failed durable-backend open terminal, so this code
         * is the observable proof that no in-memory downgrade happened.
         */
        private const val STORAGE_OPEN_FAILED_CODE = "SCP-STORAGE-8001"

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

    /// Stable 32-byte SQLCipher key. The specific value does not matter;
    /// only that the same key is reused across the two constructions
    /// that simulate process restart.
    private val sqliteKey: ByteArray = ByteArray(32) { 0x42 }

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
    fun tearDown() {
        val b = bridge()
        for (scp in createdInstances) {
            runBlocking { scp.shutdown(b, 1.seconds) }
        }
        createdInstances.clear()
    }

    private fun makeSqliteScp(dir: File): SCP {
        val scp = SCP.withSqlite(dir, sqliteKey)
        createdInstances += scp
        return scp
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

            val scp = makeSqliteScp(dir.toFile())

            assertTrue(
                dbPath.exists(),
                "SCP.withSqlite(dir, key) must create scp.db at ${dbPath.pathString}",
            )
            assertNotEquals(0UL, scp.instanceId, "instanceId must be monotonic and non-UNSET")
        }

    @Test
    fun `withSqlite roundtrips suspendInstance then resume via CoroutineBridge`() =
        runTest {
            val dir = Files.createTempDirectory("scp-kotlin-persist-lifecycle-")
            dir.toFile().deleteOnExit()
            val scp = makeSqliteScp(dir.toFile())

            scp.suspendInstance(bridge())
            scp.resume(bridge())
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

            val scp1 = makeSqliteScp(dir.toFile())
            val id1 = scp1.instanceId
            // Post-9fa80e13c: SqliteStorage::new propagates open failures
            // instead of falling back to in-memory, so the first instance
            // must release the DB before a second open can succeed. This
            // matches the Swift `testSqliteReopenWithSamePathAndKeySucceeds`
            // shape.
            scp1.shutdown(bridge(), 1.seconds)
            createdInstances.remove(scp1)

            val scp2 = makeSqliteScp(dir.toFile())
            val id2 = scp2.instanceId

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
            val scp1 = makeSqliteScp(dir.toFile())
            scp1.shutdown(bridge(), 1.seconds)
            createdInstances.remove(scp1)

            // Second open with a wrong key MUST throw — `SqliteStorage::new`
            // fails at the `PRAGMA key` / WAL-mode step because `SQLCipher`
            // rejects the key as "file is not a database". The UniFFI bridge
            // converts that `StorageInitError::SqliteOpen` to
            // `ScpError::Validation` with code `SCP-STORAGE-8001`
            // (`crates/scp-ffi/uniffi/src/runtime.rs`, the
            // `From<StorageInitError> for ScpError` impl), which the generated
            // Kotlin surfaces as `ScpException.Validation`. Main's 9fa80e13c
            // replaced the former silent fallback to in-memory (split-brain
            // where writes silently vanished) with hard-error propagation.
            val wrongKey = ByteArray(32) { 0x11 }
            val rejected =
                assertFailsWith<ScpException.Validation> {
                    SCP.withSqlite(dir.toFile(), wrongKey)
                }
            assertEquals(
                STORAGE_OPEN_FAILED_CODE,
                rejected.code,
                "a rejected SQLCipher key is a storage-open failure, not a context failure",
            )

            // Third open with the correct key — must still succeed, proving
            // the failed mismatched-key attempt did not corrupt or truncate
            // the encrypted database file.
            makeSqliteScp(dir.toFile())
        }

    @Test
    fun `withSqlite passphrase round trips across two constructions`() =
        runTest {
            val dir = Files.createTempDirectory("scp-kotlin-persist-passphrase-")
            dir.toFile().deleteOnExit()
            val dbPath = dir.resolve("scp.db")

            val scp1 = SCP.withSqlite(dir.toFile(), passphrase = "correct horse battery staple")
            assertTrue(
                dbPath.exists(),
                "passphrase construction must create scp.db at ${dbPath.pathString}",
            )

            // `SqliteStorage` holds a process-exclusive advisory lock on
            // `scp.db.lock` for its lifetime, so close the first handle before
            // the second construction. Leaving it open tested lock exclusion,
            // not the passphrase round trip this test is named for. The sibling
            // test `withSqlite reopens the same dir plus key across two
            // constructions` shuts down for the same reason.
            scp1.shutdown(bridge(), 1.seconds)

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
            // Release the advisory lock on `scp.db.lock` first, so the reopen
            // below fails on the WRONG PASSPHRASE and not on a still-held lock.
            // While the first handle stayed open, that lock rejected the second
            // construction, so the wrong passphrase decided nothing and this
            // test proved only that two handles cannot coexist.
            scp1.shutdown(bridge(), 1.seconds)

            // Reopen with the WRONG passphrase must fail closed — never
            // silently open a fresh DB (spec §17.6).
            val rejected =
                assertFailsWith<ScpException.Validation> {
                    SCP.withSqlite(dir.toFile(), passphrase = "the-WRONG-one")
                }
            assertEquals(
                STORAGE_OPEN_FAILED_CODE,
                rejected.code,
                "a rejected passphrase is a storage-open failure, not a context failure",
            )
        }
}
