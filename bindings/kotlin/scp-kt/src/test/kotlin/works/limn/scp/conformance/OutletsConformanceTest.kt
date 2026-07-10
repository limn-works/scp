// OutletsConformanceTest.kt — Outlet conformance tests for the Kotlin SDK (SCP-120)
// Provenance: SCP-120, .docs/scaffold/shared.md "Outlets" category

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
import kotlin.test.assertTrue

/**
 * Cross-platform conformance tests for outlet operations.
 *
 * Covers: register, invoke, verify test vectors, update, cross-context.
 *
 * Outlet operations are exercised through the conformance dispatcher and
 * validated against expected outputs. Error paths verify that the bridge
 * correctly propagates structured error codes from the Rust engine.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class OutletsConformanceTest {
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
    inner class OutletRegister {
        @Test
        fun `outlet_register returns outlet ID`() =
            runTest(testDispatcher) {
                stubBindings.outletRegisterResult = "outlet-calc-001"
                val result =
                    dispatcher.dispatch(
                        "outlet_register",
                        mapOf(
                            "context_handle" to "10",
                            "definition" to """{"name":"calculator","schema":{}}""",
                        ),
                    )
                assertEquals("outlet-calc-001", result["outlet_id"])
            }

        @Test
        fun `outlet_register propagates error`() =
            runTest(testDispatcher) {
                stubBindings.outletRegisterError =
                    BridgeException("Context not found", "SCP-TOOL-6001")
                val result =
                    dispatcher.dispatch(
                        "outlet_register",
                        mapOf("context_handle" to "10", "definition" to "{}"),
                    )
                assertEquals("SCP-TOOL-6001", result["error"])
            }
    }

    @Nested
    inner class OutletInvoke {
        @Test
        fun `outlet_invoke returns output`() =
            runTest(testDispatcher) {
                stubBindings.outletInvokeResult = """{"result":42}"""
                val result =
                    dispatcher.dispatch(
                        "outlet_invoke",
                        mapOf(
                            "context_handle" to "10",
                            "outlet_id" to "outlet-calc-001",
                            "input" to """{"a":20,"b":22}""",
                        ),
                    )
                assertEquals("""{"result":42}""", result["output"])
            }

        @Test
        fun `outlet_invoke propagates not-found error`() =
            runTest(testDispatcher) {
                stubBindings.outletInvokeError =
                    BridgeException("Outlet not registered", "SCP-TOOL-6002")
                val result =
                    dispatcher.dispatch(
                        "outlet_invoke",
                        mapOf(
                            "context_handle" to "10",
                            "outlet_id" to "nonexistent",
                            "input" to "{}",
                        ),
                    )
                assertEquals("SCP-TOOL-6002", result["error"])
            }
    }

    @Nested
    inner class OutletVerify {
        @Test
        fun `outlet_verify returns result for registered outlet`() =
            runTest(testDispatcher) {
                stubBindings.outletVerifyResult = """{"outlet_id":"outlet-calc-001","passed":true,"failures":[]}"""
                val result =
                    dispatcher.dispatch(
                        "outlet_verify",
                        mapOf(
                            "context_handle" to "10",
                            "outlet_id" to "outlet-calc-001",
                        ),
                    )
                assertTrue(result["result"]?.contains("\"passed\":true") == true)
            }

        @Test
        fun `outlet_verify returns failed result`() =
            runTest(testDispatcher) {
                @Suppress("MaxLineLength")
                stubBindings.outletVerifyResult =
                    """{"outlet_id":"outlet-calc-001","passed":false,"failures":["signature mismatch"]}"""
                val result =
                    dispatcher.dispatch(
                        "outlet_verify",
                        mapOf(
                            "context_handle" to "10",
                            "outlet_id" to "outlet-calc-001",
                        ),
                    )
                assertTrue(result["result"]?.contains("\"passed\":false") == true)
            }

        @Test
        fun `outlet_verify propagates verification error`() =
            runTest(testDispatcher) {
                stubBindings.outletVerifyError =
                    BridgeException("Verification failed", "SCP-TOOL-6003")
                val result =
                    dispatcher.dispatch(
                        "outlet_verify",
                        mapOf(
                            "context_handle" to "10",
                            "outlet_id" to "outlet-calc-001",
                        ),
                    )
                assertEquals("SCP-TOOL-6003", result["error"])
            }
    }

    @Nested
    inner class FixtureIntegration {
        @Test
        fun `outlet register fixture matches dispatcher result`() =
            runTest(testDispatcher) {
                stubBindings.outletRegisterResult = "outlet-echo"
                val fixture =
                    ConformanceFixture(
                        testId = "outlet-register-001",
                        category = "outlets",
                        description = "Register a outlet in a context",
                        operation = "outlet_register",
                        input =
                            mapOf(
                                "context_handle" to "10",
                                "definition" to """{"name":"echo"}""",
                            ),
                        expected = mapOf("outlet_id" to "outlet-echo"),
                    )
                val result =
                    dispatcher.dispatch(
                        fixture.operation,
                        fixture.input,
                    )
                val mismatches = compareResults(result, fixture.expected)
                assertTrue(
                    mismatches.isEmpty(),
                    "Fixture ${fixture.testId}: $mismatches",
                )
            }
    }
}
