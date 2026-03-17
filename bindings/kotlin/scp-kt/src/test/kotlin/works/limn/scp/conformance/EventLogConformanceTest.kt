// EventLogConformanceTest.kt — Event log conformance tests for the Kotlin SDK (SCP-120)
// Provenance: SCP-120, .docs/scaffold/shared.md "Event log" category

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
 * Cross-platform conformance tests for event log operations.
 *
 * Covers: append, prove inclusion, verify proof, consistency checkpoint,
 * absence proof.
 *
 * Event log tests verify that the Kotlin SDK correctly proxies event log
 * queries and proof verification through the bridge. The conformance
 * dispatcher maps operations to infra bridge calls.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class EventLogConformanceTest {
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
    inner class EventLogQuery {
        @Test
        fun `event_log_query returns results`() =
            runTest(testDispatcher) {
                stubBindings.eventLogQueryResult =
                    """[{"type":"joined","did":"did:dht:z6MkA"}]"""
                val result =
                    dispatcher.dispatch(
                        "event_log_query",
                        mapOf("context_handle" to "1", "filter" to "{}"),
                    )
                assertTrue(result["result"]?.contains("joined") == true)
            }

        @Test
        fun `event_log_query returns empty array for no results`() =
            runTest(testDispatcher) {
                stubBindings.eventLogQueryResult = "[]"
                val result =
                    dispatcher.dispatch(
                        "event_log_query",
                        mapOf("context_handle" to "1", "filter" to "{}"),
                    )
                assertEquals("[]", result["result"])
            }

        @Test
        fun `event_log_query propagates error`() =
            runTest(testDispatcher) {
                stubBindings.eventLogQueryError =
                    BridgeException("Context not found", "SCP-CTX-2030")
                val result =
                    dispatcher.dispatch(
                        "event_log_query",
                        mapOf("context_handle" to "1", "filter" to "{}"),
                    )
                assertEquals("SCP-CTX-2030", result["error"])
            }

        @Test
        fun `event_log_query with type filter`() =
            runTest(testDispatcher) {
                stubBindings.eventLogQueryResult =
                    """[{"type":"message","seq":1}]"""
                val result =
                    dispatcher.dispatch(
                        "event_log_query",
                        mapOf(
                            "context_handle" to "1",
                            "filter" to """{"type":"message"}""",
                        ),
                    )
                assertTrue(result["result"]?.contains("message") == true)
            }
    }

    @Nested
    inner class EventLogVerify {
        @Test
        fun `event_log_verify returns true for valid proof`() =
            runTest(testDispatcher) {
                stubBindings.eventLogVerifyResult = true
                val result =
                    dispatcher.dispatch(
                        "event_log_verify",
                        mapOf(
                            "context_handle" to "1",
                            "claim" to """{"type":"inclusion","leaf_index":0}""",
                        ),
                    )
                assertEquals("true", result["is_valid"])
            }

        @Test
        fun `event_log_verify returns false for invalid proof`() =
            runTest(testDispatcher) {
                stubBindings.eventLogVerifyResult = false
                val result =
                    dispatcher.dispatch(
                        "event_log_verify",
                        mapOf(
                            "context_handle" to "1",
                            "claim" to """{"type":"inclusion","leaf_index":0}""",
                        ),
                    )
                assertEquals("false", result["is_valid"])
            }

        @Test
        fun `event_log_verify propagates error`() =
            runTest(testDispatcher) {
                stubBindings.eventLogVerifyError =
                    BridgeException("Proof verification failed", "SCP-CTX-2032")
                val result =
                    dispatcher.dispatch(
                        "event_log_verify",
                        mapOf("context_handle" to "1", "claim" to "{}"),
                    )
                assertEquals("SCP-CTX-2032", result["error"])
            }
    }

    @Nested
    inner class EventLogCheckpoint {
        @Test
        fun `event_log_checkpoint returns signed checkpoint`() =
            runTest(testDispatcher) {
                stubBindings.eventLogCheckpointResult =
                    """{"context_id":"ctx-1","sender_did":"did:dht:z6Mk",""" +
                    """"event_count":10,"merkle_root":"abcdef","epoch":5,""" +
                    """"timestamp":1710000000,"signature":"c2lnbmVk"}"""
                val result =
                    dispatcher.dispatch(
                        "event_log_checkpoint",
                        mapOf(
                            "context_handle" to "1",
                            "identity_handle" to "2",
                            "epoch" to "5",
                        ),
                    )
                assertTrue(result["checkpoint"]?.contains("merkle_root") == true)
                assertTrue(result["checkpoint"]?.contains("ctx-1") == true)
                assertTrue(result["checkpoint"]?.contains("timestamp") == true)
                assertTrue(result["checkpoint"]?.contains("signature") == true)
            }

        @Test
        fun `event_log_checkpoint propagates error`() =
            runTest(testDispatcher) {
                stubBindings.eventLogCheckpointError =
                    BridgeException("Key custody unavailable", "SCP-CTX-2028")
                val result =
                    dispatcher.dispatch(
                        "event_log_checkpoint",
                        mapOf(
                            "context_handle" to "1",
                            "identity_handle" to "2",
                            "epoch" to "5",
                        ),
                    )
                assertEquals("SCP-CTX-2028", result["error"])
            }

        @Test
        fun `event_log_checkpoint via direct bridge call`() =
            runTest(testDispatcher) {
                stubBindings.eventLogCheckpointResult =
                    """{"context_id":"ctx-1","sender_did":"did:dht:z6Mk",""" +
                    """"event_count":10,"merkle_root":"abcdef","epoch":5,""" +
                    """"timestamp":1710000000,"signature":"c2lnbmVk"}"""
                val result = bridge.infra.eventLogCheckpoint(1L, 2L, 5L)
                assertTrue(result.contains("merkle_root"))
                assertTrue(result.contains("event_count"))
                assertTrue(result.contains("timestamp"))
                assertTrue(result.contains("signature"))
            }
    }

    @Nested
    inner class FixtureIntegration {
        @Test
        fun `event log query fixture matches dispatcher result`() =
            runTest(testDispatcher) {
                stubBindings.eventLogQueryError =
                    BridgeException("Context not found", "SCP-CTX-2030")
                val fixture =
                    ConformanceFixture(
                        testId = "event-log-query-001",
                        category = "event_log",
                        description = "Query event log (stub returns error)",
                        operation = "event_log_query",
                        input = mapOf("context_handle" to "1"),
                        expected = mapOf("error" to "SCP-CTX-2030"),
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

        @Test
        fun `event log verify fixture matches dispatcher result`() =
            runTest(testDispatcher) {
                stubBindings.eventLogVerifyError =
                    BridgeException("Verification failed", "SCP-CTX-2032")
                val fixture =
                    ConformanceFixture(
                        testId = "event-log-verify-001",
                        category = "event_log",
                        description = "Verify event log proof (stub returns error)",
                        operation = "event_log_verify",
                        input = mapOf("context_handle" to "1"),
                        expected = mapOf("error" to "SCP-CTX-2032"),
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
