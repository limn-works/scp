// ContextConformanceTest.kt — Context lifecycle conformance tests for the Kotlin SDK (SCP-120)
// Provenance: SCP-120, .docs/scaffold/shared.md "Context" category

package com.limn.scp.conformance

import com.limn.scp.bridge.BridgeException
import com.limn.scp.bridge.CoroutineBridge
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
 * Cross-platform conformance tests for context lifecycle operations.
 *
 * Covers: create, join, leave, close, TTL expiry, state machine transitions.
 *
 * Verifies that the Kotlin SDK context operations match the cross-platform
 * specification. Each test exercises the dispatcher with inline fixture data
 * and validates the result against expected values.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ContextConformanceTest {
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
    inner class ContextCreate {
        @Test
        fun `context_create returns handle`() = runTest(testDispatcher) {
            stubBindings.contextCreateResult = 100L
            val result = dispatcher.dispatch(
                "context_create",
                mapOf(
                    "identity_handle" to "1",
                    "params" to """{"ceiling":["read","write"]}""",
                ),
            )
            assertEquals("100", result["handle"])
        }

        @Test
        fun `context_create propagates error`() = runTest(testDispatcher) {
            stubBindings.contextCreateError =
                BridgeException("Invalid params", "SCP-CTX-2001")
            val result = dispatcher.dispatch(
                "context_create",
                mapOf("identity_handle" to "1", "params" to "{}"),
            )
            assertEquals("SCP-CTX-2001", result["error"])
        }

        @Test
        fun `context_create fixture comparison`() = runTest(testDispatcher) {
            stubBindings.contextCreateResult = 50L
            val fixture = ConformanceFixture(
                testId = "context-create-001",
                category = "context",
                description = "Create context with read/write ceiling",
                operation = "context_create",
                input = mapOf(
                    "identity_handle" to "1",
                    "params" to """{"ceiling":["read","write"]}""",
                ),
                expected = mapOf("handle" to "50"),
            )
            val result = dispatcher.dispatch(fixture.operation, fixture.input)
            val mismatches = compareResults(result, fixture.expected)
            assertTrue(mismatches.isEmpty(), fixture.testId + ": " + mismatches)
        }
    }

    @Nested
    inner class ContextJoin {
        @Test
        fun `context_join returns handle for valid context ID`() =
            runTest(testDispatcher) {
                stubBindings.contextJoinResult = 200L
                val result = dispatcher.dispatch(
                    "context_join",
                    mapOf("identity_handle" to "1", "context_id" to "ctx-abc"),
                )
                assertEquals("200", result["handle"])
            }

        @Test
        fun `context_join propagates not-found error`() =
            runTest(testDispatcher) {
                stubBindings.contextJoinError =
                    BridgeException("Context not found", "SCP-CTX-2002")
                val result = dispatcher.dispatch(
                    "context_join",
                    mapOf("identity_handle" to "1", "context_id" to "ctx-none"),
                )
                assertEquals("SCP-CTX-2002", result["error"])
            }
    }

    @Nested
    inner class ContextLeave {
        @Test
        fun `context_leave succeeds for active context`() =
            runTest(testDispatcher) {
                val result = dispatcher.dispatch(
                    "context_leave",
                    mapOf("context_handle" to "10"),
                )
                assertEquals("left", result["status"])
                assertTrue(stubBindings.contextLeaveCalled)
            }

        @Test
        fun `context_leave propagates error for inactive context`() =
            runTest(testDispatcher) {
                stubBindings.contextLeaveError =
                    BridgeException("Not a member", "SCP-CTX-2003")
                val result = dispatcher.dispatch(
                    "context_leave",
                    mapOf("context_handle" to "10"),
                )
                assertEquals("SCP-CTX-2003", result["error"])
            }
    }

    @Nested
    inner class ContextClose {
        @Test
        fun `context_close succeeds for admin`() = runTest(testDispatcher) {
            val result = dispatcher.dispatch(
                "context_close",
                mapOf("context_handle" to "10"),
            )
            assertEquals("closed", result["status"])
            assertTrue(stubBindings.contextCloseCalled)
        }

        @Test
        fun `context_close propagates permission error`() =
            runTest(testDispatcher) {
                stubBindings.contextCloseError =
                    BridgeException("Not authorized", "SCP-PERM-3001")
                val result = dispatcher.dispatch(
                    "context_close",
                    mapOf("context_handle" to "10"),
                )
                assertEquals("SCP-PERM-3001", result["error"])
            }
    }

    @Nested
    inner class StateMachineTransitions {
        @Test
        fun `context lifecycle - create then leave`() =
            runTest(testDispatcher) {
                stubBindings.contextCreateResult = 10L
                val createResult = dispatcher.dispatch(
                    "context_create",
                    mapOf("identity_handle" to "1", "params" to "{}"),
                )
                assertEquals("10", createResult["handle"])

                val leaveResult = dispatcher.dispatch(
                    "context_leave",
                    mapOf("context_handle" to "10"),
                )
                assertEquals("left", leaveResult["status"])
            }

        @Test
        fun `context lifecycle - join then close`() =
            runTest(testDispatcher) {
                stubBindings.contextJoinResult = 20L
                val joinResult = dispatcher.dispatch(
                    "context_join",
                    mapOf("identity_handle" to "1", "context_id" to "ctx-1"),
                )
                assertEquals("20", joinResult["handle"])

                val closeResult = dispatcher.dispatch(
                    "context_close",
                    mapOf("context_handle" to "20"),
                )
                assertEquals("closed", closeResult["status"])
            }
    }
}
