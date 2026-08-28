// IdentityConformanceTest.kt — Identity conformance tests for the Kotlin SDK (SCP-120)
// Provenance: SCP-120, .docs/scaffold/shared.md "Identity" category

package works.limn.scp.conformance

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import works.limn.scp.bridge.BridgeException
import works.limn.scp.bridge.CoroutineBridge
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Cross-platform conformance tests for identity operations.
 *
 * Covers: create, load, resolve, rotate key, verify self-certification.
 *
 * These tests verify that the Kotlin SDK API contract matches the
 * cross-platform specification defined in `.docs/scaffold/shared.md`.
 * When UniFFI bindings are generated, the stub bindings will be replaced
 * with real bridge calls and the tests will validate end-to-end behavior.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class IdentityConformanceTest {
    private lateinit var stubBindings: ConformanceStubBindings
    private lateinit var bridge: CoroutineBridge
    private lateinit var dispatcher: ConformanceDispatcher
    private lateinit var testDispatcher: TestDispatcher

    @BeforeEach
    fun setUp() {
        stubBindings = ConformanceStubBindings()
        testDispatcher = StandardTestDispatcher()
        bridge =
            CoroutineBridge(
                nativeBindings = stubBindings,
                ioDispatcher = testDispatcher,
                cpuDispatcher = testDispatcher,
            )
        dispatcher = ConformanceDispatcher(bridge)
    }

    @Nested
    inner class IdentityCreate {
        @Test
        fun `identity_create with encrypted_file custody returns handle`() =
            runTest(testDispatcher) {
                stubBindings.identityCreateResult = 42L
                val result =
                    dispatcher.dispatch(
                        "identity_create",
                        mapOf("custody" to "encrypted_file"),
                    )
                assertEquals("42", result["handle"])
                assertEquals("encrypted_file", result["custody_type"])
                assertEquals("encrypted_file", stubBindings.identityCreateCustody)
            }

        // This test asserted `custody_type == "platform"` until SCP-294, the
        // custody-naming story, and then that the dispatcher forwarded that
        // string unaltered. §3.2.2 of the identity spec names `"platform"`
        // among five spellings that "name no custody backend", and
        // `CustodyType` spells none of them, so the dispatcher now stops each
        // one before the bridge call. The rejection at the bridge is covered
        // against the compiled cdylib by `CustodyCallErrorCodeTest`.
        @Test
        fun `identity_create reports a retired custody spelling without calling the bridge`() =
            runTest(testDispatcher) {
                stubBindings.identityCreateResult = 1L
                for (retired in listOf("platform", "software", "file", "platform_managed", "hardware")) {
                    val result =
                        dispatcher.dispatch(
                            "identity_create",
                            mapOf("custody" to retired),
                        )
                    assertEquals("unknown_custody_type", result["error"], "$retired must be reported")
                    assertEquals(retired, result["detail"])
                }
                assertNull(stubBindings.identityCreateCustody)
            }

        // §3.2.2 states that `"in_memory"` "is a test-harness affordance and
        // not a value of this vocabulary" and that "no SDK enum spells it", so
        // a fixture naming it reaches the same report the retired spellings do.
        // A test that needs the in-memory key store passes the raw string to
        // the bridge instead — see `TestHarnessCustody`.
        @Test
        fun `identity_create reports the test-harness custody string without calling the bridge`() =
            runTest(testDispatcher) {
                stubBindings.identityCreateResult = 1L
                val result =
                    dispatcher.dispatch(
                        "identity_create",
                        mapOf("custody" to "in_memory"),
                    )
                assertEquals("unknown_custody_type", result["error"])
                assertEquals("in_memory", result["detail"])
                assertNull(stubBindings.identityCreateCustody)
            }

        /**
         * A fixture that names no custody gets none chosen for it. Key custody
         * decides who can reach a private key, and the agent-first API design
         * tenet of `CLAUDE.md` forbids an SDK making that choice for a caller.
         * This test replaced one asserting that the dispatcher defaulted to
         * `encrypted_file`.
         */
        @Test
        fun `identity_create chooses no custody for a fixture that names none`() =
            runTest(testDispatcher) {
                val result = dispatcher.dispatch("identity_create", emptyMap())
                assertEquals("missing_custody_type", result["error"])
                assertNull(result["custody_type"])
                assertNull(result["handle"])
            }

        @Test
        fun `identity_create propagates bridge error`() =
            runTest(testDispatcher) {
                stubBindings.identityCreateError =
                    BridgeException("Custody not available", "SCP-IDENT-1001")
                val result =
                    dispatcher.dispatch(
                        "identity_create",
                        mapOf("custody" to "os_keystore"),
                    )
                assertEquals("SCP-IDENT-1001", result["error"])
            }
    }

    @Nested
    inner class IdentityLoad {
        @Test
        fun `identity_load returns handle for valid DID`() =
            runTest(testDispatcher) {
                stubBindings.identityLoadResult = 5L
                val result =
                    dispatcher.dispatch(
                        "identity_load",
                        mapOf("did" to "did:dht:z6MkTest"),
                    )
                assertEquals("5", result["handle"])
                assertEquals("did:dht:z6MkTest", result["did"])
            }

        @Test
        fun `identity_load propagates not-found error`() =
            runTest(testDispatcher) {
                stubBindings.identityLoadError =
                    BridgeException("Identity not found", "SCP-IDENT-1002")
                val result =
                    dispatcher.dispatch(
                        "identity_load",
                        mapOf("did" to "did:dht:nonexistent"),
                    )
                assertEquals("SCP-IDENT-1002", result["error"])
            }
    }

    @Nested
    inner class IdentityResolve {
        @Test
        fun `identity_resolve returns DID document`() =
            runTest(testDispatcher) {
                val docJson = """{"did":"did:dht:z6MkResolved","keys":[]}"""
                stubBindings.identityResolveResult = docJson
                val result =
                    dispatcher.dispatch(
                        "identity_resolve",
                        mapOf("did" to "did:dht:z6MkResolved"),
                    )
                assertEquals("did:dht:z6MkResolved", result["did"])
                assertEquals(docJson, result["document"])
            }

        @Test
        fun `identity_resolve propagates resolution failure`() =
            runTest(testDispatcher) {
                stubBindings.identityResolveError =
                    BridgeException("Resolution failed", "SCP-IDENT-1003")
                val result =
                    dispatcher.dispatch(
                        "identity_resolve",
                        mapOf("did" to "did:dht:unreachable"),
                    )
                assertEquals("SCP-IDENT-1003", result["error"])
            }
    }

    @Nested
    inner class FixtureIntegration {
        @Test
        fun `fixture loader handles missing directory gracefully`() {
            val fixtures = ConformanceFixtureLoader.loadFixturesByCategory("identity")
            assertNotNull(fixtures)
            assertTrue(fixtures.size >= 0)
        }

        @Test
        fun `inline fixture matches dispatcher result`() =
            runTest(testDispatcher) {
                val fixture =
                    ConformanceFixture(
                        testId = "identity-create-001",
                        category = "identity",
                        description = "Create identity with in-memory custody",
                        operation = "identity_create",
                        input = mapOf("custody" to "encrypted_file"),
                        expected = mapOf("custody_type" to "encrypted_file"),
                    )
                val result = dispatcher.dispatch(fixture.operation, fixture.input)
                val mismatches = compareResults(result, fixture.expected)
                assertTrue(
                    mismatches.isEmpty(),
                    "Fixture ${fixture.testId}: $mismatches",
                )
            }
    }
}
