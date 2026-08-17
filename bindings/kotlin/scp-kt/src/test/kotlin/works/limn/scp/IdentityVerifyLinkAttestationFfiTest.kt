// IdentityVerifyLinkAttestationFfiTest.kt — Real-FFI call-through tests for
// [SCP.identityVerifyLinkAttestation] (spec §3.5.4).
//
// GitHub issue #2335 finding 2: §3.5.4 step 1 resolves an issuer's DID document
// and takes a signing key from it, so a key a caller supplies is an assertion to
// check rather than a source of truth. Checking it needs a per-instance DID
// resolver, and a module-scope UniFFI free function of the same name reaches no
// bridge instance and declines with SCP-IDENT-1060. These tests prove the Kotlin
// wrapper takes the per-instance route: an SCP-IDENT-1060 here would mean it
// reverted to that free function.
//
// All tests require the compiled UniFFI cdylib; if the native library is not
// loadable the suite skips via JUnit 5 assumptions, matching
// TrustAggregateFfiTest.

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
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

class IdentityVerifyLinkAttestationFfiTest {
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
        scp = SCP(StorageConfig.InMemory)
    }

    @AfterEach
    fun tearDown() {
        if (!this::scp.isInitialized) return
        runBlocking { scp.shutdown(bridge(), 1.seconds) }
    }

    /**
     * Malformed attestation JSON is a caller error the shared flow reports as
     * SCP-IDENT-1044, before any resolution attempt. A wrapper routed to the
     * declining free function would report SCP-IDENT-1060 instead, whatever the
     * arguments say.
     */
    @Test
    fun `identityVerifyLinkAttestation reaches the per-instance route`() {
        val error =
            runCatching {
                runBlocking {
                    scp.identityVerifyLinkAttestation(
                        attestationJson = "not json",
                        issuerPublicKeyHex = "00".repeat(32),
                        referenceProof = "not_fetched",
                    )
                }
            }.exceptionOrNull()

        assertTrue(error is ScpException, "expected a typed ScpException, got $error")
        val message = error.message ?: ""
        assertTrue(
            message.contains("SCP-IDENT-1044"),
            "malformed attestation JSON must report SCP-IDENT-1044, got: $message",
        )
        assertFalse(
            message.contains("SCP-IDENT-1060"),
            "SCP-IDENT-1060 means this wrapper reached a module-scope free function: $message",
        )
    }

    /**
     * `referenceProof` carries a caller's own Class 2 fetch outcome (§3.5.4
     * Class 2 step 2). One shared parser accepts `"confirmed"` and
     * `"not_fetched"` and raises SCP-IDENT-1044 for every other string, so a
     * typo never lands a caller on a silent `"not_fetched"` verdict.
     */
    @Test
    fun `identityVerifyLinkAttestation rejects an unknown referenceProof value`() {
        val error =
            runCatching {
                runBlocking {
                    scp.identityVerifyLinkAttestation(
                        attestationJson = "not json",
                        issuerPublicKeyHex = "00".repeat(32),
                        referenceProof = "Confirmed",
                    )
                }
            }.exceptionOrNull()

        assertTrue(error is ScpException, "expected a typed ScpException, got $error")
        assertTrue(
            (error.message ?: "").contains("SCP-IDENT-1044"),
            "an unknown referenceProof must report SCP-IDENT-1044, got: ${error.message}",
        )
    }
}
