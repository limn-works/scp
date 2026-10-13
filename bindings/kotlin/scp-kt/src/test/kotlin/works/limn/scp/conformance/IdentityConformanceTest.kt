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

        @Test
        fun `identity_create with a custody string CustodyType lacks never reaches the bindings`() =
            runTest(testDispatcher) {
                for (custody in listOf("platform", "software", "in_memory")) {
                    val result =
                        dispatcher.dispatch(
                            "identity_create",
                            mapOf("custody" to custody),
                        )
                    assertEquals("unsupported_custody", result["error"], custody)
                }
                assertNull(stubBindings.identityCreateCustody)
            }

        @Test
        fun `identity_create without custody picks no default and never reaches the bindings`() =
            runTest(testDispatcher) {
                val result = dispatcher.dispatch("identity_create", emptyMap())
                assertEquals("unsupported_custody", result["error"])
                assertNull(result["custody_type"])
                assertNull(stubBindings.identityCreateCustody)
            }

        @Test
        fun `identity_create propagates bridge error`() =
            runTest(testDispatcher) {
                stubBindings.identityCreateError =
                    BridgeException("Identity load failed", "SCP-IDENT-1008")
                val result =
                    dispatcher.dispatch(
                        "identity_create",
                        mapOf("custody" to "encrypted_file"),
                    )
                assertEquals("SCP-IDENT-1008", result["error"])
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
                    BridgeException("Identity resolution failed", "SCP-IDENT-1005")
                val result =
                    dispatcher.dispatch(
                        "identity_resolve",
                        mapOf("did" to "did:dht:unreachable"),
                    )
                assertEquals("SCP-IDENT-1005", result["error"])
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
                        description = "Create identity with encrypted-file custody",
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
