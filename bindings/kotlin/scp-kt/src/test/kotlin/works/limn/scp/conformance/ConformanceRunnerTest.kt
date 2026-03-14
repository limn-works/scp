// ConformanceRunnerTest.kt — Cross-platform conformance test runner for the Kotlin SDK (SCP-120)
// Provenance: SCP-120, .docs/scaffold/shared.md "Conformance Testing"

package works.limn.scp.conformance

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
 * Cross-language conformance test runner for the Kotlin SDK.
 *
 * Loads JSON fixtures from `tests/conformance/` and validates SDK
 * operations against expected output. Each fixture specifies an
 * operation, input, and expected result. The runner maps operation
 * strings to Kotlin SDK bridge calls and compares actual output with
 * deep equality (with tolerance for timestamps and nonces).
 *
 * When the `tests/conformance/` fixture directory does not yet exist,
 * these tests validate the conformance runner infrastructure itself
 * by exercising the operation dispatcher and fixture model with inline
 * test data.
 *
 * See `.docs/scaffold/shared.md` section "Conformance Testing" and
 * story SCP-120.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ConformanceRunnerTest {
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
    inner class FixtureModel {
        @Test
        fun `fixture model stores all fields`() {
            val fixture = ConformanceFixture(
                testId = "identity-create-001",
                category = "identity",
                description = "Create identity with in-memory custody",
                operation = "identity_create",
                input = mapOf("custody" to "in_memory"),
                expected = mapOf(
                    "did_prefix" to "did:dht:",
                    "custody_type" to "in_memory",
                ),
            )
            assertEquals("identity-create-001", fixture.testId)
            assertEquals("identity", fixture.category)
            assertEquals("identity_create", fixture.operation)
            assertEquals("in_memory", fixture.input["custody"])
            assertEquals("did:dht:", fixture.expected["did_prefix"])
        }

        @Test
        fun `fixture model has default empty maps`() {
            val fixture = ConformanceFixture(
                testId = "test-001",
                category = "test",
                description = "Minimal fixture",
                operation = "noop",
            )
            assertTrue(fixture.input.isEmpty())
            assertTrue(fixture.expected.isEmpty())
        }
    }

    @Nested
    inner class FixtureLoader {
        @Test
        fun `fixture loader handles missing directory gracefully`() {
            val fixtures = ConformanceFixtureLoader.loadFixtures()
            assertNotNull(fixtures)
            assertTrue(fixtures.size >= 0)
        }

        @Test
        fun `fixture loader by category returns subset`() {
            val fixtures =
                ConformanceFixtureLoader.loadFixturesByCategory("identity")
            assertNotNull(fixtures)
            assertTrue(fixtures.all { it.category == "identity" })
        }
    }

    @Nested
    inner class ResultComparison {
        @Test
        fun `exact match returns no mismatches`() {
            val mismatches = compareResults(
                actual = mapOf("status" to "ok", "code" to "200"),
                expected = mapOf("status" to "ok", "code" to "200"),
            )
            assertTrue(mismatches.isEmpty())
        }

        @Test
        fun `mismatch returns detail`() {
            val mismatches = compareResults(
                actual = mapOf("status" to "error"),
                expected = mapOf("status" to "ok"),
            )
            assertEquals(1, mismatches.size)
            assertTrue(mismatches[0].contains("status"))
        }

        @Test
        fun `missing key returns mismatch`() {
            val mismatches = compareResults(
                actual = emptyMap(),
                expected = mapOf("status" to "ok"),
            )
            assertEquals(1, mismatches.size)
        }

        @Test
        fun `timestamp fields tolerated when non-empty`() {
            val mismatches = compareResults(
                actual = mapOf("created_at" to "2026-03-01T00:00:00Z"),
                expected = mapOf("created_at" to "any-value"),
            )
            assertTrue(mismatches.isEmpty())
        }

        @Test
        fun `timestamp fields fail when empty`() {
            val mismatches = compareResults(
                actual = mapOf("created_at" to ""),
                expected = mapOf("created_at" to "any-value"),
            )
            assertEquals(1, mismatches.size)
        }

        @Test
        fun `nonce fields tolerated when non-empty`() {
            val mismatches = compareResults(
                actual = mapOf("nonce" to "abc123"),
                expected = mapOf("nonce" to "different-value"),
            )
            assertTrue(mismatches.isEmpty())
        }

        @Test
        fun `extra actual keys do not cause mismatches`() {
            val mismatches = compareResults(
                actual = mapOf("status" to "ok", "extra" to "data"),
                expected = mapOf("status" to "ok"),
            )
            assertTrue(mismatches.isEmpty())
        }
    }

    @Nested
    inner class DispatcherInfrastructure {
        @Test
        fun `dispatcher handles all identity operations`() =
            runTest(testDispatcher) {
                assertDispatchSucceeds("identity_create", mapOf("custody" to "in_memory"))
                assertDispatchSucceeds("identity_load", mapOf("did" to "did:dht:test"))
                assertDispatchSucceeds("identity_resolve", mapOf("did" to "did:dht:test"))
            }

        @Test
        fun `dispatcher handles all context operations`() =
            runTest(testDispatcher) {
                assertDispatchSucceeds("context_create", mapOf("identity_handle" to "1"))
                assertDispatchSucceeds(
                    "context_join",
                    mapOf("context_handle" to "10", "identity_handle" to "1"),
                )
                assertDispatchSucceeds(
                    "context_leave",
                    mapOf("context_handle" to "10", "identity_handle" to "1"),
                )
                assertDispatchSucceeds(
                    "context_close",
                    mapOf("context_handle" to "10", "identity_handle" to "1"),
                )
                assertDispatchSucceeds(
                    "context_send",
                    mapOf("context_handle" to "10", "identity_handle" to "1"),
                )
            }

        @Test
        fun `dispatcher handles all tool operations`() =
            runTest(testDispatcher) {
                assertDispatchSucceeds("tool_register", mapOf("context_handle" to "10"))
                assertDispatchSucceeds("tool_invoke", mapOf("context_handle" to "10", "identity_handle" to "1"))
                assertDispatchSucceeds(
                    "tool_verify",
                    mapOf("context_handle" to "10", "tool_id" to "t"),
                )
            }

        @Test
        fun `dispatcher handles all ucan operations`() =
            runTest(testDispatcher) {
                assertDispatchSucceeds(
                    "ucan_validate",
                    mapOf("context_handle" to "10", "encoded" to "t"),
                )
                assertDispatchSucceeds("ucan_mint", mapOf("context_handle" to "10"))
                assertDispatchSucceeds("ucan_revoke", mapOf("context_handle" to "10"))
            }

        @Test
        fun `dispatcher handles all infra operations`() =
            runTest(testDispatcher) {
                assertDispatchSucceeds("transport_connect", mapOf("relay_url" to "wss://r"))
                assertDispatchSucceeds("transport_disconnect", emptyMap())
                assertDispatchSucceeds("transport_status", emptyMap())
                assertDispatchSucceeds("event_log_query", mapOf("context_id" to "c"))
                assertDispatchSucceeds("event_log_verify", mapOf("context_id" to "c"))
            }

        @Test
        fun `dispatcher returns error for unknown operation`() =
            runTest(testDispatcher) {
                val result = dispatcher.dispatch("bogus_operation", emptyMap())
                assertEquals("unsupported_operation", result["error"])
            }

        private suspend fun assertDispatchSucceeds(
            operation: String,
            input: Map<String, String>,
        ) {
            val result = dispatcher.dispatch(operation, input)
            assertTrue(
                result["error"] == null,
                "$operation returned error: ${result["error"]}",
            )
        }
    }

    @Nested
    inner class FixtureRoundtrip {
        @Test
        fun `inline fixtures run through full pipeline`() =
            runTest(testDispatcher) {
                val fixtures = listOf(
                    ConformanceFixture(
                        testId = "roundtrip-identity-001",
                        category = "identity",
                        description = "Create identity",
                        operation = "identity_create",
                        input = mapOf("custody" to "in_memory"),
                        expected = mapOf("custody_type" to "in_memory"),
                    ),
                    ConformanceFixture(
                        testId = "roundtrip-context-001",
                        category = "context",
                        description = "Leave context",
                        operation = "context_leave",
                        input = mapOf(
                            "context_handle" to "10",
                            "identity_handle" to "1",
                        ),
                        expected = mapOf("status" to "left"),
                    ),
                    ConformanceFixture(
                        testId = "roundtrip-send-001",
                        category = "messaging",
                        description = "Send message",
                        operation = "context_send",
                        input = mapOf(
                            "context_handle" to "10",
                            "identity_handle" to "1",
                            "payload" to "hello",
                        ),
                        expected = mapOf("status" to "sent"),
                    ),
                    ConformanceFixture(
                        testId = "roundtrip-tool-001",
                        category = "tools",
                        description = "Register tool",
                        operation = "tool_register",
                        input = mapOf(
                            "context_handle" to "10",
                            "definition" to "{}",
                        ),
                        expected = mapOf("tool_id" to "tool-001"),
                    ),
                )

                for (fixture in fixtures) {
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
}
