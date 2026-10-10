// BroadcastKeyRequestRealFfiTest.kt — real-FFI coverage for the requester
// wrapping key of a broadcast key request (spec §5.14.2, §9.5).
//
// The wrapping key is a 65-byte uncompressed P-256 point. Any other value is a
// caller-input error that every SDK reports as the same validation class with
// code SCP-VALID-7007. This suite calls `SCP.broadcastHandleKeyRequest` against
// the compiled UniFFI cdylib, with no stub binding, so a bridge that mapped the
// error to another class or code fails here.
//
// Provenance: SCP-307, spec §5.14.2 and §9.5, .docs/standards/sdk-common.md
// (error codes).

package works.limn.scp

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import uniffi.scp.CeilingPolicy
import uniffi.scp.ContextMode
import uniffi.scp.ContextParams
import uniffi.scp.GovernanceModel
import uniffi.scp.MemoryScope
import uniffi.scp.ScpException
import uniffi.scp.StorageConfig
import works.limn.scp.bridge.CoroutineBridge
import works.limn.scp.conformance.ConformanceStubBindings
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.seconds

class BroadcastKeyRequestRealFfiTest {
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

        /** The uncompressed P-256 base point G (SEC 2 §2.4.2), a valid point. */
        private val P256_G: ByteArray =
            (
                "04" +
                    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
                    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
            ).chunked(2).map { it.toInt(16).toByte() }.toByteArray()

        private const val INVALID_FORMAT_CODE = "SCP-VALID-7007"
    }

    private fun broadcastParams(): ContextParams =
        ContextParams(
            mode = ContextMode.BROADCAST,
            ceiling = listOf("messages:read"),
            ceilingPolicy = CeilingPolicy.IMMUTABLE,
            governance = GovernanceModel.SINGLE_ADMIN,
            memoryScope = MemoryScope.FULL,
            ttlSeconds = 3600uL,
            promotable = false,
            minProtocolVersion = 0.toUShort(),
            maxChainDepth = null,
            maxNestingDepth = null,
            sessionCap = null,
            economicPolicy = null,
            consequenceRulesJson = null,
            consequenceConfigJson = null,
        )

    private fun shutdownBridge(): CoroutineBridge =
        CoroutineBridge(
            nativeBindings = ConformanceStubBindings(),
            ioDispatcher = Dispatchers.IO,
            cpuDispatcher = Dispatchers.Default,
        )

    @Test
    fun `wrapping key that is not a 65-byte P-256 point is a Validation error with SCP-VALID-7007`() {
        assumeTrue(nativeAvailable, skipReason)
        runBlocking {
            val scp = SCP(StorageConfig.InMemory)
            try {
                val author = scp.identityCreate(custody = "in_memory")
                val subscriber = scp.identityCreate(custody = "in_memory")
                val handle = scp.contextCreate(author, broadcastParams())
                scp.broadcastSubscribe(handle, subscriber.did())

                val offCurve = ByteArray(65).also { it[0] = 0x04 }
                val cases = mapOf("64 bytes" to P256_G.copyOfRange(1, 65), "off curve" to offCurve)
                for ((case, key) in cases) {
                    val error =
                        assertFailsWith<ScpException.Validation>(case) {
                            scp.broadcastHandleKeyRequest(handle, author.did(), subscriber.did(), key)
                        }
                    assertEquals(INVALID_FORMAT_CODE, error.code, case)
                    assertContains(error.msg, "must be a 65-byte uncompressed P-256 point", message = case)
                }

                // Positive control: a valid point passes the same check and a
                // registered subscriber is granted the sealed key.
                val sealed = scp.broadcastHandleKeyRequest(handle, author.did(), subscriber.did(), P256_G)
                assertNotNull(sealed, "a registered subscriber with a valid wrapping key is granted the key")
            } finally {
                scp.shutdown(shutdownBridge(), 1.seconds)
            }
        }
    }
}
