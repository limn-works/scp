// CustodyCallErrorCodeTest.kt — real-FFI proof that every custody value the
// bridge refuses fails closed, that the one value it builds a key store from
// creates an identity, and that the published custody value comes off the
// running backend.
//
// `SmokeTest` pins the SDK half: `CustodyType` carries the two entries §3.2.2
// of the identity spec states — `ENCRYPTED_FILE` and `OS_KEYSTORE` — and spells
// none of the five retired strings. That the enum spells neither a retired
// string nor the test-harness string does not show what the bridge answers when
// a caller passes one, so this suite calls the compiled UniFFI cdylib with each
// one and reads the typed code off the thrown `ScpException`.
//
// The property under test: the refusal reaches the caller as a typed code and
// no identity is created. A bridge that instead built a key file would name
// Android Keystore and deliver something else, which is the failure SCP-294,
// "Fail closed on the custody strings the bridges reject, and normalize the
// identity parameter across SDKs", closes.
//
// Every test method uses a BLOCK body, not an `= runBlocking { ... }`
// expression body, for the reason `IdentityAgentKeyRealFfiTest` records: JUnit
// 5 refuses to execute a `@Test` method that returns a value, so an
// expression-bodied test can compile, report no failure, and never run.
//
// Provenance: §3.2.2 of the identity spec, "The Custody Vocabulary"
// (`.docs/specs/03-identity.md`), which states the two request-side values and
// the three published values; ADR-006, the platform abstraction, which defines
// the `KeyCustody` trait that `identityCreateWithCustody` injects; and
// `build_key_custody` in `crates/scp-ffi/uniffi/src/bridge.rs`, which raises
// SCP-IDENT-1003 for `"os_keystore"` without a provider and SCP-VALID-7005 for
// every string outside the vocabulary, both before any key store is built.

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
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.seconds

class CustodyCallErrorCodeTest {
    companion object {
        private const val CUSTODY_PROVIDER_REQUIRED_CODE = "SCP-IDENT-1003"
        private const val UNRECOGNIZED_CUSTODY_CODE = "SCP-VALID-7005"

        /**
         * The code every bridge raises for a DID it retains no custody for.
         *
         * This bridge raised `SCP-IDENT-1017` until the custody-vocabulary
         * change. The registry entry for that code reserves it for a handle
         * carrying no signing custody and names `SCP-IDENT-1001` for a DID an
         * instance never registered
         * (`crates/scp-ffi/common/src/error_codes.rs`), which is the condition
         * this suite exercises, and the `PyO3` and NAPI bridges already raised
         * `SCP-IDENT-1001` for it.
         */
        private const val REGISTRY_MISS_CODE = "SCP-IDENT-1001"

        /**
         * The five spellings §3.2.2 names and states "name no custody backend".
         * `"platform"` and `"file"` each built a key store at some point in a
         * bridge's history, so the SDK named one substrate and delivered
         * another; each one now fails closed.
         */
        private val RETIRED_SPELLINGS =
            listOf("platform", "software", "file", "platform_managed", "hardware")

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
    fun `identityCreate answers os_keystore without a provider with SCP-IDENT-1003`() {
        runBlocking {
            val thrown =
                assertFailsWith<ScpException.Identity> {
                    scp.identityCreate(custody = CustodyType.OS_KEYSTORE)
                }
            assertEquals(
                CUSTODY_PROVIDER_REQUIRED_CODE,
                thrown.code,
                "\"os_keystore\" must fail closed: identityCreate supplies no platform " +
                    "key-custody callback, so the bridge must not substitute a key file",
            )
        }
    }

    @Test
    fun `identityCreateWithAgentKey answers os_keystore without a provider with SCP-IDENT-1003`() {
        runBlocking {
            val thrown =
                assertFailsWith<ScpException.Identity> {
                    scp.identityCreateWithAgentKey(custody = CustodyType.OS_KEYSTORE)
                }
            assertEquals(CUSTODY_PROVIDER_REQUIRED_CODE, thrown.code)
        }
    }

    // `SCP.identityCreate` takes a `CustodyType`, so no caller of the SDK can
    // name a custody value the vocabulary does not state. The two tests below
    // reach past that signature to the UniFFI `Scp` object `SCP` holds in
    // `inner`, because the bridge still screens every string it receives and
    // they pin the code it answers each one with.
    @Test
    fun `identityCreate answers every retired custody spelling with SCP-VALID-7005`() {
        runBlocking {
            for (retired in RETIRED_SPELLINGS) {
                val thrown =
                    assertFailsWith<ScpException.Validation> {
                        scp.inner.identityCreate(custody = retired, testingSeed = null)
                    }
                assertEquals(UNRECOGNIZED_CUSTODY_CODE, thrown.code, "$retired must fail closed")
            }
        }
    }

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
    fun `identityCreate accepts the test-harness custody string this build compiles`() {
        runBlocking {
            val identity = scp.identityCreateInTestHarnessCustody()
            assertEquals(
                true,
                identity.did().startsWith("did:dht:"),
                "the test-harness custody string must mint a real did:dht identity",
            )
        }
    }

    // §3.2.2 states that the published value "is derived, never declared": the
    // bridge reads it off the running backend. The in-memory key store holds
    // every private key in a process-memory map that nothing gates, which is a
    // pair the published vocabulary states no value for, so the bridge
    // publishes nothing. ADR-039's Enforcement Stack layer 4 gives that absence
    // a meaning, "Absence of attestation is itself a signal".
    @Test
    fun `identityPublishedCustody reads the running backend`() {
        runBlocking {
            val identity = scp.identityCreateInTestHarnessCustody()
            assertNull(
                scp.identityPublishedCustody(identity.did()),
                "an unstatable pair publishes no custody value",
            )
        }
    }

    // The published value comes off the running backend, so an instance holding
    // no backend for a DID reports a typed error rather than a value it
    // reconstructed from the DID string.
    @Test
    fun `identityPublishedCustody fails closed for a DID this instance does not retain`() {
        runBlocking {
            val thrown =
                assertFailsWith<ScpException.Identity> {
                    scp.identityPublishedCustody("did:dht:z6MkNotRegistered")
                }
            assertEquals(REGISTRY_MISS_CODE, thrown.code)
        }
    }
}
