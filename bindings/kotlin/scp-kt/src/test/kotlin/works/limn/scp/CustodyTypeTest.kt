// CustodyTypeTest.kt — CustodyType carries the custody request vocabulary of
// spec §3.2.2, and each entry gets the code that section gives it through both
// identity-create methods on the public SCP class.
//
// The real-FFI tests run against the compiled UniFFI cdylib built with the
// `testing` feature, with no stub. Every test method has a block body (see
// bindings/kotlin/AGENTS.md).
//
// Provenance: spec §3.2.2 (Custody request vocabulary);
// .docs/standards/sdk-common.md §Custody request; .docs/standards/construction.md
// (consequential choices are enums, required choices are required); SCP-294.

package works.limn.scp

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import uniffi.scp.Identity
import uniffi.scp.ScpException
import uniffi.scp.StorageConfig
import works.limn.scp.bridge.CoroutineBridge
import works.limn.scp.conformance.ConformanceStubBindings
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The quoted custody strings a bridge custody rejection names after
 * "this bridge accepts " and before the next ";" (`ACCEPTED_CUSTODY` in
 * `crates/scp-ffi/common/src/custody_request.rs`), or null when the message
 * carries no such clause.
 */
internal fun acceptedCustodyStrings(rejection: String): List<String>? {
    if (!rejection.contains("this bridge accepts ")) return null
    val clause = rejection.substringAfter("this bridge accepts ").substringBefore(";")
    val quoted = Regex("\"([^\"]*)\"").findAll(clause).map { it.groupValues[1] }.toList()
    return quoted.ifEmpty { null }
}

/** The error code a bridge call threw, or a description of what it did instead. */
private suspend fun errorCode(body: suspend () -> Identity): String =
    try {
        body()
        "created an identity"
    } catch (e: ScpException.Validation) {
        e.code
    } catch (e: ScpException.Identity) {
        e.code
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

    /**
     * Reads the accepted set from the bridge's own `SCP-VALID-7005` rejection of
     * "platform". The entries must be exactly that set, so the type carries no
     * third entry such as the test-harness `in_memory` string (spec section
     * 3.2.2).
     */
    @Test
    fun `request entries are exactly the custody strings the bridge accepts`() {
        val rejection =
            assertFailsWith<ScpException.Validation> {
                runBlocking { scp.inner.identityCreate(custody = "platform", testingSeed = null) }
            }
        assertEquals("SCP-VALID-7005", rejection.code)
        val accepted = assertNotNull(acceptedCustodyStrings(rejection.msg), rejection.msg)
        assertEquals(listOf(CustodyType.ENCRYPTED_FILE, CustodyType.OS_KEYSTORE).map { it.rawValue }, accepted)
        assertEquals(accepted, CustodyType.entries.map { it.rawValue })
    }

    @Test
    fun `acceptedCustodyStrings parses every quoted string in the clause`() {
        val message =
            "unknown custody type \"x\" — this bridge accepts custody " +
                "\"encrypted_file\" (a file) or \"os_keystore\" (a store); inject \"callback\""
        assertEquals(listOf("encrypted_file", "os_keystore"), acceptedCustodyStrings(message))
    }

    @Test
    fun `acceptedCustodyStrings is null without the clause`() {
        assertNull(acceptedCustodyStrings("custody type \"platform\" is refused"))
        assertNull(acceptedCustodyStrings("this bridge accepts nothing; done"))
    }

    @Test
    fun `fromRawValue parses each entry and no string outside the vocabulary`() {
        for (entry in CustodyType.entries) {
            assertEquals(entry, CustodyType.fromRawValue(entry.rawValue))
        }
        for (refused in listOf("in_memory", "platform", "software", "callback", "file", "ENCRYPTED_FILE")) {
            assertNull(CustodyType.fromRawValue(refused), "fromRawValue parsed \"$refused\"")
        }
    }

    /**
     * Strings outside the vocabulary, including the retired `platform`,
     * `software`, `file` and `callback`, are `SCP-VALID-7005` on both entry
     * points.
     */
    @Test
    fun `strings outside the vocabulary are VALID-7005`() {
        runBlocking {
            for (custody in listOf("platform", "software", "file", "callback", "EncryptedFile")) {
                val create = errorCode { scp.inner.identityCreate(custody = custody, testingSeed = null) }
                assertEquals("SCP-VALID-7005", create, "identityCreate($custody)")
                val agent = errorCode { scp.inner.identityCreateWithAgentKey(custody = custody) }
                assertEquals("SCP-VALID-7005", agent, "identityCreateWithAgentKey($custody)")
            }
        }
    }

    /**
     * OS_KEYSTORE needs a `KeyCustodyProvider`, which neither method takes, so
     * both answer it with `SCP-IDENT-1003` naming the method that does.
     */
    @Test
    fun `OS_KEYSTORE without a provider is IDENT-1003`() {
        val rejection =
            assertFailsWith<ScpException.Identity> {
                runBlocking { scp.identityCreate(custody = CustodyType.OS_KEYSTORE) }
            }
        assertEquals("SCP-IDENT-1003", rejection.code)
        assertTrue(rejection.msg.contains("identity_create_with_custody"), rejection.msg)
        runBlocking {
            val agent = errorCode { scp.identityCreateWithAgentKey(custody = CustodyType.OS_KEYSTORE) }
            assertEquals("SCP-IDENT-1003", agent)
        }
    }

    /**
     * A testing seed with any custody value other than `in_memory` is
     * `SCP-VALID-7009`. [SCP.identityCreate] sends no seed, so the test reaches
     * the bridge through [SCP.inner].
     */
    @Test
    fun `a seed with an entry is VALID-7009`() {
        runBlocking {
            for (custody in CustodyType.entries) {
                val seed = ByteArray(32) { 7 }
                val code = errorCode { scp.inner.identityCreate(custody = custody.rawValue, testingSeed = seed) }
                assertEquals("SCP-VALID-7009", code, "$custody")
            }
        }
    }

    /**
     * The test-harness helpers reach the in-memory key store with the raw
     * `in_memory` string through both identity-create methods on the testing
     * build, and the handle reports that string.
     */
    @Test
    fun `the harness reaches in_memory through both methods`() {
        runBlocking {
            val identity = scp.identityCreateInMemory()
            assertEquals(IN_MEMORY_CUSTODY, identity.custodyType())
            assertFalse(identity.verifyingKey().isNullOrEmpty(), "in_memory holds no key")
            val agent = scp.identityCreateWithAgentKeyInMemory()
            assertEquals(IN_MEMORY_CUSTODY, agent.custodyType())
        }
    }

    /**
     * The harness passes the ADR-046 seed to the bridge: a 32-byte seed creates
     * an identity, and a 31-byte seed is a validation error that only the
     * bridge's seed check raises.
     */
    @Test
    fun `the harness passes the testing seed to the bridge`() {
        runBlocking {
            val seeded = scp.identityCreateInMemory(testingSeed = ByteArray(32) { 7 })
            assertEquals(IN_MEMORY_CUSTODY, seeded.custodyType())
            val short = errorCode { scp.identityCreateInMemory(testingSeed = ByteArray(31) { 7 }) }
            assertTrue(short.startsWith("SCP-VALID-"), short)
        }
    }

    /**
     * ENCRYPTED_FILE opens `$HOME/.scp/keys.bin` under `SCP_KEY_PASSPHRASE`
     * through both methods, and the handle reports the request value. A missing
     * passphrase is `SCP-VALID-7001`, and a key file sealed under another
     * passphrase is `SCP-IDENT-1008`. The variables are restored before the test
     * returns.
     */
    @Test
    fun `ENCRYPTED_FILE creates an identity and rejects bad inputs`(
        @TempDir base: File,
    ) {
        val createHome = File(base, "create")
        val agentHome = File(base, "agent")
        withKeyFileEnvironment(createHome, "kotlin-encrypted-file-passphrase") {
            runBlocking {
                val identity = scp.identityCreate(custody = CustodyType.ENCRYPTED_FILE)
                assertEquals("encrypted_file", identity.custodyType())
                assertTrue(identity.did().startsWith("did:dht:"), identity.did())
                val keyFile = File(createHome, ".scp/keys.bin")
                assertTrue(keyFile.isFile, keyFile.path)

                libc.setenv("HOME", agentHome.absolutePath, 1)
                val agent = scp.identityCreateWithAgentKey(custody = CustodyType.ENCRYPTED_FILE)
                assertEquals("encrypted_file", agent.custodyType())

                libc.setenv("HOME", createHome.absolutePath, 1)
                libc.setenv("SCP_KEY_PASSPHRASE", "another-passphrase", 1)
                val wrongPassphrase = errorCode { scp.identityCreate(custody = CustodyType.ENCRYPTED_FILE) }
                assertEquals("SCP-IDENT-1008", wrongPassphrase)

                libc.unsetenv("SCP_KEY_PASSPHRASE")
                val noPassphrase =
                    errorCode { scp.identityCreateWithAgentKey(custody = CustodyType.ENCRYPTED_FILE) }
                assertEquals("SCP-VALID-7001", noPassphrase)
            }
        }
    }
}
