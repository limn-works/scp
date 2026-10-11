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
import uniffi.scp.ScpException
import uniffi.scp.StorageConfig
import works.limn.scp.bridge.CoroutineBridge
import works.limn.scp.conformance.ConformanceStubBindings
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.seconds

/**
 * The quoted custody strings a bridge custody rejection names after
 * "this bridge accepts " and before the next ";" (`ACCEPTED_CUSTODY` in
 * `crates/scp-ffi/uniffi/src/bridge.rs`), or null when the message carries no
 * such clause.
 */
internal fun acceptedCustodyStrings(rejection: String): List<String>? {
    if (!rejection.contains("this bridge accepts ")) return null
    val clause = rejection.substringAfter("this bridge accepts ").substringBefore(";")
    val quoted = Regex("\"([^\"]*)\"").findAll(clause).map { it.groupValues[1] }.toList()
    return quoted.ifEmpty { null }
}

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

    /** Reads the accepted set from the bridge's own `SCP-IDENT-1003` rejection of "platform". */
    @Test
    fun `entries are exactly the custody strings the bridge accepts`() {
        val rejection =
            assertFailsWith<ScpException.Identity> {
                runBlocking { scp.inner.identityCreate(custody = "platform", testingSeed = null) }
            }
        assertEquals("SCP-IDENT-1003", rejection.code)
        val accepted = assertNotNull(acceptedCustodyStrings(rejection.msg), rejection.msg)
        assertEquals(accepted, CustodyType.entries.map { it.rawValue })
    }

    @Test
    fun `acceptedCustodyStrings parses every quoted string in the clause`() {
        val message =
            "custody type \"x\" names no key store — this bridge accepts " +
                "\"in_memory\" or \"file\" only here; inject \"callback\""
        assertEquals(listOf("in_memory", "file"), acceptedCustodyStrings(message))
    }

    @Test
    fun `acceptedCustodyStrings is null without the clause`() {
        assertNull(acceptedCustodyStrings("custody type \"platform\" is refused"))
        assertNull(acceptedCustodyStrings("this bridge accepts nothing; done"))
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
                assertFalse(identity.verifyingKey().isNullOrEmpty(), "$custody holds no key")
            }
        }
    }

    @Test
    fun `every entry creates an identity through identityCreateWithAgentKey`() {
        runBlocking {
            for (custody in CustodyType.entries) {
                val identity = scp.identityCreateWithAgentKey(custody = custody)
                assertFalse(identity.verifyingKey().isNullOrEmpty(), "$custody holds no key")
            }
        }
    }
}
