// CustodyCallErrorCodeTest.kt — real-FFI proof that the custody strings the
// bridge refuses fail closed, and that the one string it accepts creates an
// identity.
//
// `SmokeTest` pins the SDK half: `CustodyType` carries three entries —
// `IN_MEMORY`, `PLATFORM`, and `SOFTWARE` — and `fromRawValue` maps each
// entry's raw string back to it. That the enum spells each refused string does
// not show what the bridge answers when a caller passes one, so this suite
// calls `SCP.identityCreate` against the compiled UniFFI cdylib with each
// refused string and reads the typed code off the thrown `ScpException`.
//
// The property under test: `SCP-IDENT-1003` reaches the caller and no identity
// is created. A bridge that instead built a key file would name Android
// Keystore and deliver something else, which is the failure SCP-294, "Fail
// closed on the custody strings the bridges reject, and normalize the identity
// parameter across SDKs", closes.
//
// Every test method uses a BLOCK body, not an `= runBlocking { ... }`
// expression body, for the reason `IdentityAgentKeyRealFfiTest` records: JUnit
// 5 refuses to execute a `@Test` method that returns a value, so an
// expression-bodied test can compile, report no failure, and never run.
//
// Provenance: section 3.2, Key Custody, of the identity spec
// (`.docs/specs/03-identity.md`), which names four custody sources in prose and
// no custody string; ADR-006, the platform abstraction, which defines the
// `KeyCustody` trait that `identityCreateWithCustody` injects; and the
// `"platform" | "software"` arm of `parse_custody_method` in
// `crates/scp-ffi/uniffi/src/bridge.rs`, which raises SCP-IDENT-1003 before any
// key store is built.

package works.limn.scp

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import uniffi.scp.ScpException
import uniffi.scp.StorageConfig
import works.limn.scp.bridge.CoroutineBridge
import works.limn.scp.conformance.ConformanceStubBindings
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.time.Duration.Companion.seconds

class CustodyCallErrorCodeTest {
    companion object {
        private const val PLATFORM_CUSTODY_REQUIRED_CODE = "SCP-IDENT-1003"
        private const val UNRECOGNIZED_CUSTODY_CODE = "SCP-VALID-7005"
        private val SHUTDOWN_TIMEOUT = 5.seconds

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
        scp = SCP(StorageConfig.InMemory)
    }

    @AfterEach
    fun tearDown() {
        if (!this::scp.isInitialized) return
        runBlocking { scp.shutdown(shutdownBridge(), SHUTDOWN_TIMEOUT) }
    }

    // The teardown overload needs a `CoroutineBridge`, and `shutdown` reaches
    // the real cdylib through the SDK's `inner`, so these stub bindings only
    // satisfy the signature. `IdentityAgentKeyRealFfiTest` builds the same
    // teardown bridge for the same reason.
    private fun shutdownBridge(): CoroutineBridge =
        CoroutineBridge(
            nativeBindings = ConformanceStubBindings(),
            ioDispatcher = Dispatchers.IO,
            cpuDispatcher = Dispatchers.Default,
        )

    @Test
    fun `identityCreate answers platform custody with SCP-IDENT-1003`() {
        runBlocking {
            val thrown =
                assertFailsWith<ScpException.Identity> {
                    scp.identityCreate(custody = CustodyType.PLATFORM)
                }
            assertEquals(
                PLATFORM_CUSTODY_REQUIRED_CODE,
                thrown.code,
                "\"platform\" must fail closed: no custody string reaches Android Keystore, " +
                    "so the bridge must not substitute a key file",
            )
        }
    }

    @Test
    fun `identityCreate answers software custody with SCP-IDENT-1003`() {
        runBlocking {
            val thrown =
                assertFailsWith<ScpException.Identity> {
                    scp.identityCreate(custody = CustodyType.SOFTWARE)
                }
            assertEquals(PLATFORM_CUSTODY_REQUIRED_CODE, thrown.code)
        }
    }

    @Test
    fun `identityCreateWithAgentKey answers platform custody with SCP-IDENT-1003`() {
        runBlocking {
            val thrown =
                assertFailsWith<ScpException.Identity> {
                    scp.identityCreateWithAgentKey(custody = CustodyType.PLATFORM)
                }
            assertEquals(PLATFORM_CUSTODY_REQUIRED_CODE, thrown.code)
        }
    }

    // `SCP.identityCreate` takes a `CustodyType`, so no caller of the SDK can
    // name a custody string the enum does not carry. This test reaches past
    // that signature to the UniFFI `Scp` object `SCP` holds in `inner`, because
    // the bridge still screens every string it receives and this test pins the
    // code it answers an unrecognized one with.
    @Test
    fun `identityCreate answers an unrecognized custody string with SCP-VALID-7005`() {
        runBlocking {
            val thrown =
                assertFailsWith<ScpException.Validation> {
                    scp.inner.identityCreate(custody = "magic", testingSeed = null)
                }
            assertEquals(UNRECOGNIZED_CUSTODY_CODE, thrown.code)
        }
    }

    @Test
    fun `identityCreate accepts the one custody string of the three the bridge parses`() {
        runBlocking {
            val identity = scp.identityCreate(custody = CustodyType.IN_MEMORY)
            assertEquals(
                true,
                identity.did().startsWith("did:dht:"),
                "the accepted custody string must mint a real did:dht identity",
            )
        }
    }
}
