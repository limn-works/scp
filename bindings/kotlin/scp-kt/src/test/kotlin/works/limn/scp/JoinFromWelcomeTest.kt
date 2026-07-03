// JoinFromWelcomeTest.kt — SDK-wrapper tests for the ADR-049 Phase 2J joiner
// handshake ops: SCP.reserveKeyPackage (step 1) and
// SCP.contextJoinFromWelcome (step 2).
//
// The Kotlin SDK forwards 1:1 to the generated UniFFI `Scp` object: reserve
// returns the generated `ReservedKeyPackage` record unchanged, and join
// returns the opaque `ContextHandle`. There is no client-side guard layer —
// custody, DID/context-id validation, and single-use consume all live in the
// Rust core, so these tests exercise the real bridge.
//
// A full reserve -> Welcome -> join happy path cannot be driven from the
// Kotlin SDK alone: the creator-side "mint a Welcome for a reserved
// KeyPackage" op is not exposed at this bridge (it lives in the core E2E
// harness). This suite therefore covers what the SDK surface can prove
// end-to-end through real FFI:
//   - reserve mints a real single-use KeyPackage for a locally-custodied
//     identity (non-empty reservation id + non-empty PUBLIC bytes),
//   - reserve fails closed for a DID-only (non-custodied) identity, and
//   - join fails closed for a DID-only joiner at the pseudonym-derivation
//     seam BEFORE the single-use KeyPackage is consumed.
// These mirror the Python reference (tests/test_join_from_welcome.py,
// TestJoinerHandshakeRealFfi) and the Rust bridge unit tests.
//
// All tests require the compiled UniFFI cdylib; without a loadable native
// library the suite skips via JUnit 5 assumptions, matching ScpClassTest.
//
// Provenance: ADR-049 Phase 2J. Kotlin SDK slice.

package works.limn.scp

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
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
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalCoroutinesApi::class)
class JoinFromWelcomeTest {
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

        /** Canonical missing-key-material code (spec §17, ADR-048). */
        private const val MISSING_KEY_MATERIAL_CODE = "SCP-IDENT-1054"

        /** A syntactically-valid 64-hex context id (ADR-056). */
        private const val HEX_CONTEXT_ID =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

        private const val CREATOR_DID = "did:key:z6MkKotlin2jCreatorAbc"
    }

    private fun shutdownBridge(): CoroutineBridge =
        CoroutineBridge(
            nativeBindings = ConformanceStubBindings(),
            ioDispatcher = Dispatchers.IO,
            cpuDispatcher = Dispatchers.Default,
        )

    private fun makeParams(): ContextParams =
        ContextParams(
            mode = ContextMode.ENCRYPTED,
            ceiling = listOf("messages:read", "messages:write"),
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
        )

    // ── reserveKeyPackage — real UniFFI bridge ────────────────────────────

    @Test
    fun `reserveKeyPackage returns a reservation and non-empty public bytes`() {
        assumeTrue(nativeAvailable, skipReason)
        runBlocking {
            val scp = SCP(StorageConfig.InMemory)
            try {
                val joiner = scp.identityCreate(custody = "in_memory")

                val reservation = scp.reserveKeyPackage(joiner)

                assertTrue(
                    reservation.reservationId.isNotEmpty(),
                    "reservation id must be non-empty",
                )
                // Only the PUBLIC KeyPackage bytes cross the FFI boundary.
                assertTrue(
                    reservation.keyPackagePublic.isNotEmpty(),
                    "public KeyPackage bytes must be non-empty",
                )
            } finally {
                scp.shutdown(shutdownBridge(), 1.seconds)
            }
        }
    }

    @Test
    fun `reserveKeyPackage rejects a DID-only non-custodied identity`() {
        assumeTrue(nativeAvailable, skipReason)
        runBlocking {
            val scp = SCP(StorageConfig.InMemory)
            try {
                // Reloading a created identity yields a DID-only handle with no
                // retained key material — reserve must fail closed (the same
                // trust model as contextCreate).
                val custodied = scp.identityCreate(custody = "in_memory")
                val loaded = scp.identityLoad(custodied.did())

                try {
                    scp.reserveKeyPackage(loaded)
                    fail("expected reserveKeyPackage to reject a non-custodied identity")
                } catch (e: ScpException.Identity) {
                    assertEquals(
                        MISSING_KEY_MATERIAL_CODE,
                        e.code,
                        "expected SCP-IDENT-1054 for a non-custodied identity",
                    )
                }
            } finally {
                scp.shutdown(shutdownBridge(), 1.seconds)
            }
        }
    }

    // ── contextJoinFromWelcome — real UniFFI bridge ───────────────────────

    @Test
    fun `contextJoinFromWelcome rejects a DID-only joiner before consuming the KeyPackage`() {
        assumeTrue(nativeAvailable, skipReason)
        runBlocking {
            val scp = SCP(StorageConfig.InMemory)
            try {
                // The joiner's routing pseudonym is DERIVED from its local
                // custody; a DID-only handle hard-fails at the derivation seam
                // BEFORE the single-use KeyPackage is consumed. A bogus
                // reservation id + garbage Welcome never get reached.
                val custodied = scp.identityCreate(custody = "in_memory")
                val loaded = scp.identityLoad(custodied.did())

                try {
                    scp.contextJoinFromWelcome(
                        identity = loaded,
                        creatorDid = CREATOR_DID,
                        contextId = HEX_CONTEXT_ID,
                        params = makeParams(),
                        reservationId = "bogus-reservation-id",
                        welcomeBytes = "not-a-real-welcome".toByteArray(),
                    )
                    fail("expected contextJoinFromWelcome to reject a non-custodied joiner")
                } catch (e: ScpException.Identity) {
                    assertEquals(
                        MISSING_KEY_MATERIAL_CODE,
                        e.code,
                        "expected SCP-IDENT-1054 at the pseudonym-derivation seam",
                    )
                }
            } finally {
                scp.shutdown(shutdownBridge(), 1.seconds)
            }
        }
    }
}
