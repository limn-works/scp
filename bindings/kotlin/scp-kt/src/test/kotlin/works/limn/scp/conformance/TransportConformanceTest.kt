// TransportConformanceTest.kt — Transport conformance tests for the Kotlin SDK (SCP-120)
// Provenance: SCP-120, .docs/scaffold/shared.md "Transport" category

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
 * Cross-platform conformance tests for transport operations.
 *
 * Covers: connect, send envelope, subscribe, query, multi-relay fanout,
 * deduplication.
 *
 * Transport tests validate connection lifecycle and status reporting
 * through the conformance dispatcher. Error paths verify that transport
 * errors carry the correct structured error codes.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class TransportConformanceTest {
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
    inner class TransportConnect {
        @Test
        fun `transport_connect returns handle`() =
            runTest(testDispatcher) {
                stubBindings.transportConnectResult = 99L
                val result = dispatcher.dispatch(
                    "transport_connect",
                    mapOf("relay_url" to "wss://relay.example.com/scp/v1"),
                )
                assertEquals("99", result["handle"])
                assertEquals("connected", result["status"])
            }

        @Test
        fun `transport_connect propagates connection error`() =
            runTest(testDispatcher) {
                stubBindings.transportConnectError =
                    BridgeException("Connection refused", "SCP-TRANS-5001")
                val result = dispatcher.dispatch(
                    "transport_connect",
                    mapOf("relay_url" to "wss://unreachable.example.com"),
                )
                assertEquals("SCP-TRANS-5001", result["error"])
            }

        @Test
        fun `transport_connect propagates TLS error`() =
            runTest(testDispatcher) {
                stubBindings.transportConnectError =
                    BridgeException("TLS handshake failed", "SCP-TRANS-5010")
                val result = dispatcher.dispatch(
                    "transport_connect",
                    mapOf("relay_url" to "wss://bad-cert.example.com"),
                )
                assertEquals("SCP-TRANS-5010", result["error"])
            }
    }

    @Nested
    inner class TransportDisconnect {
        @Test
        fun `transport_disconnect returns disconnected`() =
            runTest(testDispatcher) {
                val result = dispatcher.dispatch(
                    "transport_disconnect",
                    mapOf("transport_handle" to "99"),
                )
                assertEquals("disconnected", result["status"])
                assertTrue(stubBindings.transportDisconnectCalled)
            }

        @Test
        fun `transport_disconnect propagates error`() =
            runTest(testDispatcher) {
                stubBindings.transportDisconnectError =
                    BridgeException("Transport not connected", "SCP-TRANS-5003")
                val result = dispatcher.dispatch(
                    "transport_disconnect",
                    mapOf("transport_handle" to "99"),
                )
                assertEquals("SCP-TRANS-5003", result["error"])
            }

        @Test
        fun `transport connect then disconnect lifecycle`() =
            runTest(testDispatcher) {
                stubBindings.transportConnectResult = 42L
                val connectResult = dispatcher.dispatch(
                    "transport_connect",
                    mapOf("relay_url" to "wss://relay.example.com/scp/v1"),
                )
                assertEquals("42", connectResult["handle"])
                assertEquals("connected", connectResult["status"])

                val disconnectResult = dispatcher.dispatch(
                    "transport_disconnect",
                    mapOf("transport_handle" to "42"),
                )
                assertEquals("disconnected", disconnectResult["status"])
                assertTrue(stubBindings.transportDisconnectCalled)
            }
    }

    @Nested
    inner class TransportStatus {
        @Test
        fun `transport_status returns status JSON`() =
            runTest(testDispatcher) {
                stubBindings.transportStatusResult = """{"connected":true,"latency_ms":42}"""
                val result = dispatcher.dispatch(
                    "transport_status",
                    mapOf("transport_handle" to "99"),
                )
                assertEquals(
                    """{"connected":true,"latency_ms":42}""",
                    result["status_json"],
                )
            }

        @Test
        fun `transport_status propagates error for invalid handle`() =
            runTest(testDispatcher) {
                stubBindings.transportStatusError =
                    BridgeException("Transport not found", "SCP-TRANS-5002")
                val result = dispatcher.dispatch(
                    "transport_status",
                    mapOf("transport_handle" to "0"),
                )
                assertEquals("SCP-TRANS-5002", result["error"])
            }
    }

    @Nested
    inner class FixtureIntegration {
        @Test
        fun `transport connect fixture matches dispatcher result`() =
            runTest(testDispatcher) {
                stubBindings.transportConnectError =
                    BridgeException("Connection refused", "SCP-TRANS-5001")
                val fixture = ConformanceFixture(
                    testId = "transport-connect-001",
                    category = "transport",
                    description = "Connect to relay (stub returns error)",
                    operation = "transport_connect",
                    input = mapOf("relay_url" to "wss://relay.test/scp/v1"),
                    expected = mapOf("error" to "SCP-TRANS-5001"),
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
