// ToolsConformanceTest.kt — Tool conformance tests for the Kotlin SDK (SCP-120)
// Provenance: SCP-120, .docs/scaffold/shared.md "Tools" category

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
import kotlin.test.assertTrue

/**
 * Cross-platform conformance tests for tool operations.
 *
 * Covers: register, invoke, verify test vectors, update, cross-context.
 *
 * Tool operations are exercised through the conformance dispatcher and
 * validated against expected outputs. Error paths verify that the bridge
 * correctly propagates structured error codes from the Rust engine.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ToolsConformanceTest {
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
    inner class ToolRegister {
        @Test
        fun `tool_register returns tool ID`() = runTest(testDispatcher) {
            stubBindings.toolRegisterResult = "tool-calc-001"
            val result = dispatcher.dispatch(
                "tool_register",
                mapOf(
                    "context_handle" to "10",
                    "definition" to """{"name":"calculator","schema":{}}""",
                ),
            )
            assertEquals("tool-calc-001", result["tool_id"])
        }

        @Test
        fun `tool_register propagates error`() = runTest(testDispatcher) {
            stubBindings.toolRegisterError =
                BridgeException("Context not found", "SCP-TOOL-6001")
            val result = dispatcher.dispatch(
                "tool_register",
                mapOf("context_handle" to "10", "definition" to "{}"),
            )
            assertEquals("SCP-TOOL-6001", result["error"])
        }
    }

    @Nested
    inner class ToolInvoke {
        @Test
        fun `tool_invoke returns output`() = runTest(testDispatcher) {
            stubBindings.toolInvokeResult = """{"result":42}"""
            val result = dispatcher.dispatch(
                "tool_invoke",
                mapOf(
                    "context_handle" to "10",
                    "tool_id" to "tool-calc-001",
                    "input" to """{"a":20,"b":22}""",
                ),
            )
            assertEquals("""{"result":42}""", result["output"])
        }

        @Test
        fun `tool_invoke propagates not-found error`() =
            runTest(testDispatcher) {
                stubBindings.toolInvokeError =
                    BridgeException("Tool not registered", "SCP-TOOL-6002")
                val result = dispatcher.dispatch(
                    "tool_invoke",
                    mapOf(
                        "context_handle" to "10",
                        "tool_id" to "nonexistent",
                        "input" to "{}",
                    ),
                )
                assertEquals("SCP-TOOL-6002", result["error"])
            }
    }

    @Nested
    inner class ToolVerify {
        @Test
        fun `tool_verify returns result for registered tool`() =
            runTest(testDispatcher) {
                stubBindings.toolVerifyResult = """{"tool_id":"tool-calc-001","passed":true,"failures":[]}"""
                val result = dispatcher.dispatch(
                    "tool_verify",
                    mapOf(
                        "context_handle" to "10",
                        "tool_id" to "tool-calc-001",
                    ),
                )
                assertTrue(result["result"]?.contains("\"passed\":true") == true)
            }

        @Test
        fun `tool_verify returns failed result`() =
            runTest(testDispatcher) {
                @Suppress("MaxLineLength")
                stubBindings.toolVerifyResult =
                    """{"tool_id":"tool-calc-001","passed":false,"failures":["signature mismatch"]}"""
                val result = dispatcher.dispatch(
                    "tool_verify",
                    mapOf(
                        "context_handle" to "10",
                        "tool_id" to "tool-calc-001",
                    ),
                )
                assertTrue(result["result"]?.contains("\"passed\":false") == true)
            }

        @Test
        fun `tool_verify propagates verification error`() =
            runTest(testDispatcher) {
                stubBindings.toolVerifyError =
                    BridgeException("Verification failed", "SCP-TOOL-6003")
                val result = dispatcher.dispatch(
                    "tool_verify",
                    mapOf(
                        "context_handle" to "10",
                        "tool_id" to "tool-calc-001",
                    ),
                )
                assertEquals("SCP-TOOL-6003", result["error"])
            }
    }

    @Nested
    inner class FixtureIntegration {
        @Test
        fun `tool register fixture matches dispatcher result`() =
            runTest(testDispatcher) {
                stubBindings.toolRegisterResult = "tool-echo"
                val fixture = ConformanceFixture(
                    testId = "tool-register-001",
                    category = "tools",
                    description = "Register a tool in a context",
                    operation = "tool_register",
                    input = mapOf(
                        "context_handle" to "10",
                        "definition" to """{"name":"echo"}""",
                    ),
                    expected = mapOf("tool_id" to "tool-echo"),
                )
                val result = dispatcher.dispatch(
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
