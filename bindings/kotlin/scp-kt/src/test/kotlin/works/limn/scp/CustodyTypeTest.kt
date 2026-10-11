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

import com.sun.jna.Library
import com.sun.jna.Native
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

/**
 * The libc environment calls. The bridge reads `HOME` and `SCP_KEY_PASSPHRASE`
 * from the process environment, which `System.getenv` only reads.
 */
private interface CLibrary : Library {
    fun setenv(
        name: String,
        value: String,
        overwrite: Int,
    ): Int

    fun unsetenv(name: String): Int

    fun getenv(name: String): String?
}

private val libc: CLibrary = Native.load("c", CLibrary::class.java)

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
     * "platform". The two request entries must be exactly that set; IN_MEMORY is
     * the testing affordance on top of it.
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
        assertEquals(
            listOf(CustodyType.ENCRYPTED_FILE, CustodyType.OS_KEYSTORE, CustodyType.IN_MEMORY),
            CustodyType.entries,
        )
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
        for (refused in listOf("platform", "software", "callback", "file", "ENCRYPTED_FILE")) {
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

    /** A testing seed with any entry other than IN_MEMORY is `SCP-VALID-7009`. */
    @Test
    fun `a seed without IN_MEMORY is VALID-7009`() {
        runBlocking {
            for (custody in listOf(CustodyType.ENCRYPTED_FILE, CustodyType.OS_KEYSTORE)) {
                val code = errorCode { scp.identityCreate(custody = custody, testingSeed = ByteArray(32) { 7 }) }
                assertEquals("SCP-VALID-7009", code, "$custody")
            }
        }
    }

    /** IN_MEMORY creates an identity through both methods on the testing build. */
    @Test
    fun `IN_MEMORY creates an identity through both methods`() {
        runBlocking {
            val identity = scp.identityCreate(custody = CustodyType.IN_MEMORY)
            assertEquals("in_memory", identity.custodyType())
            assertFalse(identity.verifyingKey().isNullOrEmpty(), "in_memory holds no key")
            val agent = scp.identityCreateWithAgentKey(custody = CustodyType.IN_MEMORY)
            assertEquals("in_memory", agent.custodyType())
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
        val savedHome = libc.getenv("HOME")
        val savedPassphrase = libc.getenv("SCP_KEY_PASSPHRASE")
        try {
            runBlocking {
                libc.setenv("SCP_KEY_PASSPHRASE", "kotlin-encrypted-file-passphrase", 1)
                libc.setenv("HOME", createHome.absolutePath, 1)
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
        } finally {
            if (savedHome != null) libc.setenv("HOME", savedHome, 1) else libc.unsetenv("HOME")
            if (savedPassphrase != null) {
                libc.setenv("SCP_KEY_PASSPHRASE", savedPassphrase, 1)
            } else {
                libc.unsetenv("SCP_KEY_PASSPHRASE")
            }
        }
    }
}
