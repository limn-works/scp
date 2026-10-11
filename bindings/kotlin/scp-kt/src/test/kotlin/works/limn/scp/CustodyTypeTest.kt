// CustodyTypeTest.kt — CustodyType carries exactly the custody strings the
// UniFFI bridge accepts, and each entry reaches a key store through both
// identity-create methods on the public SCP class.
//
// The real-FFI tests run against the compiled UniFFI cdylib with no stub, so an
// entry the bridge refuses (`SCP-IDENT-1003` for "platform" or "software")
// fails here. Every test method has a block body (see bindings/kotlin/AGENTS.md).
//
// Provenance: spec §3.2 (Key Custody); .docs/standards/construction.md
// (consequential choices are enums, required choices are required); SCP-294.

package works.limn.scp

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import uniffi.scp.StorageConfig
import works.limn.scp.bridge.CoroutineBridge
import works.limn.scp.conformance.ConformanceStubBindings
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The custody strings `parse_custody_method` in
 * `crates/scp-ffi/uniffi/src/bridge.rs` builds a key store for. Listed as
 * literals so the test reads the bridge's accepted set, not the enum under test.
 */
private val BRIDGE_ACCEPTED_CUSTODY_STRINGS = listOf("in_memory")

class CustodyTypeTest {
    private lateinit var scp: SCP

    @BeforeEach
    fun setUp() {
        scp = SCP(StorageConfig.InMemory)
    }

    @AfterEach
    fun tearDown() {
        if (!this::scp.isInitialized) return
        // The stub-backed bridge only satisfies the shutdown signature; shutdown
        // reaches the real cdylib through `inner` (IdentityAgentKeyRealFfiTest
        // explains the same teardown).
        val bridge =
            CoroutineBridge(
                nativeBindings = ConformanceStubBindings(),
                ioDispatcher = Dispatchers.IO,
                cpuDispatcher = Dispatchers.Default,
            )
        runBlocking { scp.shutdown(bridge, 5.seconds) }
    }

    @Test
    fun `entries are exactly the custody strings the bridge accepts`() {
        assertEquals(BRIDGE_ACCEPTED_CUSTODY_STRINGS, CustodyType.entries.map { it.rawValue })
    }

    @Test
    fun `fromRawValue parses no string the bridge refuses`() {
        assertEquals(CustodyType.IN_MEMORY, CustodyType.fromRawValue("in_memory"))
        for (refused in listOf("platform", "software", "callback", "not-a-custody-type")) {
            assertNull(CustodyType.fromRawValue(refused), "fromRawValue parsed \"$refused\"")
        }
    }

    @Test
    fun `every entry creates an identity through identityCreate`() {
        runBlocking {
            for (custody in CustodyType.entries) {
                val identity = scp.identityCreate(custody = custody)
                assertTrue(identity.did().startsWith("did:"), "$custody created no DID")
            }
        }
    }

    @Test
    fun `every entry creates an identity through identityCreateWithAgentKey`() {
        runBlocking {
            for (custody in CustodyType.entries) {
                val identity = scp.identityCreateWithAgentKey(custody = custody)
                assertTrue(identity.did().startsWith("did:"), "$custody created no DID")
            }
        }
    }
}
