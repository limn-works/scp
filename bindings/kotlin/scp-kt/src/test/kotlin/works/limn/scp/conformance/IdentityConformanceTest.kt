// IdentityConformanceTest.kt — Identity conformance tests for the Kotlin SDK (SCP-120)
// Provenance: SCP-120, .docs/scaffold/shared.md "Identity" category

package works.limn.scp.conformance

import works.limn.scp.bridge.BridgeException
import works.limn.scp.bridge.CoroutineBridge
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
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
        bridge = CoroutineBridge(
            nativeBindings = stubBindings,
            ioDispatcher = testDispatcher,
            cpuDispatcher = testDispatcher,
        )
        dispatcher = ConformanceDispatcher(bridge)
    }

    @Nested
    inner class IdentityCreate {
        @Test
        fun `identity_create with in_memory custody returns handle`() =
            runTest(testDispatcher) {
                stubBindings.identityCreateResult = 42L
                val result = dispatcher.dispatch(
                    "identity_create",
                    mapOf("custody" to "in_memory"),
                )
                assertEquals("42", result["handle"])
                assertEquals("in_memory", result["custody_type"])
                assertEquals("in_memory", stubBindings.identityCreateCustody)
            }

        @Test
        fun `identity_create with platform custody returns handle`() =
            runTest(testDispatcher) {
                stubBindings.identityCreateResult = 1L
                val result = dispatcher.dispatch(
                    "identity_create",
                    mapOf("custody" to "platform"),
                )
                assertEquals("1", result["handle"])
                assertEquals("platform", result["custody_type"])
            }

        @Test
        fun `identity_create defaults to in_memory when custody not specified`() =
            runTest(testDispatcher) {
                val result = dispatcher.dispatch("identity_create", emptyMap())
                assertEquals("in_memory", result["custody_type"])
            }

        @Test
        fun `identity_create propagates bridge error`() =
            runTest(testDispatcher) {
                stubBindings.identityCreateError =
                    BridgeException("Custody not available", "SCP-IDENT-1001")
                val result = dispatcher.dispatch(
                    "identity_create",
                    mapOf("custody" to "platform"),
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
                val result = dispatcher.dispatch(
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
                val result = dispatcher.dispatch(
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
                val result = dispatcher.dispatch(
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
                val result = dispatcher.dispatch(
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
                val fixture = ConformanceFixture(
                    testId = "identity-create-001",
                    category = "identity",
                    description = "Create identity with in-memory custody",
                    operation = "identity_create",
                    input = mapOf("custody" to "in_memory"),
                    expected = mapOf("custody_type" to "in_memory"),
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
