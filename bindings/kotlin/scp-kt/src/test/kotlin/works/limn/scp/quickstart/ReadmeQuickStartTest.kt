// ReadmeQuickStartTest.kt — runs the quick start from `bindings/kotlin/README.md`
// verbatim, so a reader who copies that block runs code this suite proved.
//
// The block between the two marker comments is the README's `suspend fun main`
// body, unchanged. What surrounds it is the harness a README reader gets from
// process exit instead: the DID assertion and the shutdown. A change to either
// copy that the other does not mirror fails review, so the README stops
// drifting from what runs.
//
// Requires the compiled UniFFI cdylib; without a loadable native library the
// test skips via a JUnit 5 assumption, matching ScpClassTest.

package works.limn.scp.quickstart

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
import uniffi.scp.StorageConfig
import works.limn.scp.SCP
import works.limn.scp.bridge.CoroutineBridge
import works.limn.scp.conformance.ConformanceStubBindings
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

class ReadmeQuickStartTest {
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

    private fun shutdownBridge(): CoroutineBridge =
        CoroutineBridge(
            nativeBindings = ConformanceStubBindings(),
            ioDispatcher = Dispatchers.IO,
            cpuDispatcher = Dispatchers.Default,
        )

    @Test
    fun `the README quick start runs end to end`() {
        assumeTrue(nativeAvailable, skipReason)
        runBlocking {
            // ── README block starts here ──────────────────────────────────
            val scp = SCP(StorageConfig.InMemory)

            val identity = scp.identityCreate(custody = "in_memory")
            println("DID: ${identity.did()}")

            val ctx =
                scp.contextCreate(
                    identity = identity,
                    params =
                        ContextParams(
                            mode = ContextMode.ENCRYPTED,
                            ceiling = listOf("messages:read", "messages:write", "context:close"),
                            ceilingPolicy = CeilingPolicy.IMMUTABLE,
                            governance = GovernanceModel.SINGLE_ADMIN,
                            memoryScope = MemoryScope.EPHEMERAL,
                            ttlSeconds = 3600uL,
                            promotable = false,
                            minProtocolVersion = 0.toUShort(),
                            maxChainDepth = null,
                            maxNestingDepth = null,
                            sessionCap = null,
                            economicPolicy = null,
                            consequenceRulesJson = null,
                            consequenceConfigJson = null,
                        ),
                )

            scp.contextSend(
                handle = ctx,
                identity = identity,
                payload = "Hello from SCP".toByteArray(),
                spendingUcanJwt = null,
            )

            scp.contextClose(handle = ctx, identity = identity)
            // ── README block ends here ───────────────────────────────────

            assertTrue(
                identity.did().startsWith("did:"),
                "the quick start must mint a DID",
            )
            scp.shutdown(shutdownBridge(), 1.seconds)
        }
    }
}
