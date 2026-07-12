// GovernanceConformanceTest.kt — Governance conformance tests for the Kotlin SDK (SCP-120)
// Provenance: SCP-120, .docs/scaffold/shared.md "UCAN" + "Error handling" categories

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
import kotlin.test.assertTrue

/**
 * Cross-platform conformance tests for governance operations.
 *
 * Covers: capability-based authorization enforcement, role-based access
 * control paths, ceiling governance, and context promotion policies.
 * These tests exercise governance through the UCAN and context bridges
 * to verify that the Kotlin SDK enforces the same authorization rules
 * as the Swift and Python SDKs.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class GovernanceConformanceTest {
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
    inner class CapabilityEnforcement {
        @Test
        fun `write capability required for context_send`() =
            runTest(testDispatcher) {
                stubBindings.contextSendError =
                    BridgeException("Write capability required", "SCP-PERM-3020")
                val result =
                    dispatcher.dispatch(
                        "context_send",
                        mapOf("context_handle" to "10", "identity_handle" to "1", "payload" to "hello"),
                    )
                assertEquals("SCP-PERM-3020", result["error"])
            }

        @Test
        fun `admin capability required for context_close`() =
            runTest(testDispatcher) {
                stubBindings.contextCloseError =
                    BridgeException("Admin capability required", "SCP-PERM-3021")
                val result =
                    dispatcher.dispatch(
                        "context_close",
                        mapOf("context_handle" to "10", "identity_handle" to "1"),
                    )
                assertEquals("SCP-PERM-3021", result["error"])
            }

        @Test
        fun `outlet_register requires outlet management capability`() =
            runTest(testDispatcher) {
                stubBindings.outletRegisterError =
                    BridgeException("Insufficient capability", "SCP-PERM-3022")
                val result =
                    dispatcher.dispatch(
                        "outlet_register",
                        mapOf("context_handle" to "10", "definition" to "{}"),
                    )
                assertEquals("SCP-PERM-3022", result["error"])
            }
    }

    @Nested
    inner class CeilingGovernance {
        @Test
        fun `ucan_mint respects ceiling constraints`() =
            runTest(testDispatcher) {
                stubBindings.ucanMintError =
                    BridgeException("Exceeds context ceiling", "SCP-PERM-3012")
                val result =
                    dispatcher.dispatch(
                        "ucan_mint",
                        mapOf(
                            "context_handle" to "10",
                            "audience_did" to "did:dht:z6MkMember",
                            "capabilities" to """["admin"]""",
                        ),
                    )
                assertEquals("SCP-PERM-3012", result["error"])
            }

        @Test
        fun `ucan_validate rejects capabilities above ceiling`() =
            runTest(testDispatcher) {
                stubBindings.ucanValidateError =
                    BridgeException("Capability above ceiling", "SCP-PERM-3013")
                val result =
                    dispatcher.dispatch(
                        "ucan_validate",
                        mapOf(
                            "context_handle" to "10",
                            "encoded" to "overcapped.token",
                            "capability" to "admin",
                        ),
                    )
                assertEquals("SCP-PERM-3013", result["error"])
            }
    }

    @Nested
    inner class ErrorCodeReachability {
        @Test
        fun `identity error codes are reachable`() =
            runTest(testDispatcher) {
                stubBindings.identityCreateError =
                    BridgeException("test", "SCP-IDENT-1001")
                val result =
                    dispatcher.dispatch(
                        "identity_create",
                        mapOf("custody" to "in_memory"),
                    )
                assertEquals("SCP-IDENT-1001", result["error"])
            }

        @Test
        fun `context error codes are reachable`() =
            runTest(testDispatcher) {
                stubBindings.contextCreateError =
                    BridgeException("test", "SCP-CTX-2001")
                val result =
                    dispatcher.dispatch(
                        "context_create",
                        mapOf("identity_handle" to "1"),
                    )
                assertEquals("SCP-CTX-2001", result["error"])
            }

        @Test
        fun `permission error codes are reachable`() =
            runTest(testDispatcher) {
                stubBindings.ucanValidateError =
                    BridgeException("test", "SCP-PERM-3001")
                val result =
                    dispatcher.dispatch(
                        "ucan_validate",
                        mapOf("context_handle" to "10", "encoded" to "t"),
                    )
                assertEquals("SCP-PERM-3001", result["error"])
            }

        @Test
        fun `transport error codes are reachable`() =
            runTest(testDispatcher) {
                stubBindings.transportConnectError =
                    BridgeException("test", "SCP-TRANS-5001")
                val result =
                    dispatcher.dispatch(
                        "transport_connect",
                        mapOf("relay_url" to "wss://test"),
                    )
                assertEquals("SCP-TRANS-5001", result["error"])
            }

        @Test
        fun `outlet error codes are reachable`() =
            runTest(testDispatcher) {
                stubBindings.outletInvokeError =
                    BridgeException("test", "SCP-OUTLET-6001")
                val result =
                    dispatcher.dispatch(
                        "outlet_invoke",
                        mapOf("context_handle" to "1", "outlet_id" to "t"),
                    )
                assertEquals("SCP-OUTLET-6001", result["error"])
            }

        @Test
        fun `BridgeException carries structured error code`() {
            val ex = BridgeException("test message", "SCP-CTX-2999")
            assertEquals("SCP-CTX-2999", ex.code)
            assertEquals("test message", ex.message)
        }

        @Test
        fun `error messages are actionable strings`() {
            val ex = BridgeException("Context not found", "SCP-CTX-2002")
            assertNotNull(ex.message)
            assertTrue(ex.message!!.isNotBlank())
            assertTrue(ex.code.startsWith("SCP-"))
        }
    }

    @Nested
    inner class UnsupportedOperations {
        @Test
        fun `unknown operation returns unsupported_operation error`() =
            runTest(testDispatcher) {
                val result =
                    dispatcher.dispatch(
                        "nonexistent_operation",
                        emptyMap(),
                    )
                assertEquals("unsupported_operation", result["error"])
            }
    }
}
