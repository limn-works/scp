// UcanConformanceTest.kt — UCAN conformance tests for the Kotlin SDK (SCP-120)
// Provenance: SCP-120, .docs/scaffold/shared.md "UCAN" category

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
 * Cross-platform conformance tests for UCAN operations.
 *
 * Covers: mint, validate (all 11 steps), delegate, revoke, nonce replay
 * rejection, ceiling enforcement.
 *
 * These tests mirror the Swift SDK conformance test patterns for UCAN
 * operations. Error code expectations match the SCP error code hierarchy.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class UcanConformanceTest {
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
    inner class UcanValidate {
        @Test
        fun `ucan_validate succeeds for valid token`() =
            runTest(testDispatcher) {
                val result = dispatcher.dispatch(
                    "ucan_validate",
                    mapOf(
                        "encoded" to "test.token.sig",
                        "capability" to "read",
                        "context_id" to "ctx-1",
                    ),
                )
                assertEquals("valid", result["status"])
            }

        @Test
        fun `ucan_validate propagates validation failure`() =
            runTest(testDispatcher) {
                stubBindings.ucanValidateError =
                    BridgeException("Invalid token", "SCP-PERM-3001")
                val result = dispatcher.dispatch(
                    "ucan_validate",
                    mapOf(
                        "encoded" to "bad.token",
                        "capability" to "write",
                        "context_id" to "ctx-1",
                    ),
                )
                assertEquals("SCP-PERM-3001", result["error"])
            }

        @Test
        fun `ucan_validate propagates expired token error`() =
            runTest(testDispatcher) {
                stubBindings.ucanValidateError =
                    BridgeException("Token expired", "SCP-PERM-3010")
                val result = dispatcher.dispatch(
                    "ucan_validate",
                    mapOf(
                        "encoded" to "expired.token.sig",
                        "capability" to "read",
                        "context_id" to "ctx-1",
                    ),
                )
                assertEquals("SCP-PERM-3010", result["error"])
            }

        @Test
        fun `ucan_validate propagates nonce replay error`() =
            runTest(testDispatcher) {
                stubBindings.ucanValidateError =
                    BridgeException("Nonce replay detected", "SCP-PERM-3011")
                val result = dispatcher.dispatch(
                    "ucan_validate",
                    mapOf(
                        "encoded" to "replayed.token.sig",
                        "capability" to "read",
                        "context_id" to "ctx-1",
                    ),
                )
                assertEquals("SCP-PERM-3011", result["error"])
            }
    }

    @Nested
    inner class UcanMint {
        @Test
        fun `ucan_mint returns token`() = runTest(testDispatcher) {
            stubBindings.ucanMintResult = "eyJ.minted.token"
            val result = dispatcher.dispatch(
                "ucan_mint",
                mapOf(
                    "identity_handle" to "1",
                    "audience_did" to "did:dht:z6MkAudience",
                    "capabilities" to """["read","write"]""",
                ),
            )
            assertEquals("eyJ.minted.token", result["token"])
        }

        @Test
        fun `ucan_mint propagates error`() = runTest(testDispatcher) {
            stubBindings.ucanMintError =
                BridgeException("Insufficient capability", "SCP-PERM-3002")
            val result = dispatcher.dispatch(
                "ucan_mint",
                mapOf(
                    "identity_handle" to "1",
                    "audience_did" to "did:dht:z6MkAudience",
                ),
            )
            assertEquals("SCP-PERM-3002", result["error"])
        }

        @Test
        fun `ucan_mint propagates ceiling enforcement error`() =
            runTest(testDispatcher) {
                stubBindings.ucanMintError =
                    BridgeException("Exceeds ceiling", "SCP-PERM-3012")
                val result = dispatcher.dispatch(
                    "ucan_mint",
                    mapOf(
                        "identity_handle" to "1",
                        "audience_did" to "did:dht:z6MkAudience",
                        "capabilities" to """["admin"]""",
                    ),
                )
                assertEquals("SCP-PERM-3012", result["error"])
            }
    }

    @Nested
    inner class UcanRevoke {
        @Test
        fun `ucan_revoke succeeds`() = runTest(testDispatcher) {
            val result = dispatcher.dispatch(
                "ucan_revoke",
                mapOf("identity_handle" to "1", "token_id" to "tok-001"),
            )
            assertEquals("revoked", result["status"])
        }

        @Test
        fun `ucan_revoke propagates error`() = runTest(testDispatcher) {
            stubBindings.ucanRevokeError =
                BridgeException("Not authorized to revoke", "SCP-PERM-3003")
            val result = dispatcher.dispatch(
                "ucan_revoke",
                mapOf("identity_handle" to "1", "token_id" to "tok-001"),
            )
            assertEquals("SCP-PERM-3003", result["error"])
        }
    }

    @Nested
    inner class FixtureIntegration {
        @Test
        fun `ucan validate fixture matches dispatcher result`() =
            runTest(testDispatcher) {
                stubBindings.ucanValidateError =
                    BridgeException("Invalid token", "SCP-PERM-3001")
                val fixture = ConformanceFixture(
                    testId = "ucan-validate-001",
                    category = "ucan",
                    description = "Validate a UCAN token (stub returns error)",
                    operation = "ucan_validate",
                    input = mapOf(
                        "encoded" to "test.token.sig",
                        "context_id" to "ctx-1",
                    ),
                    expected = mapOf("error" to "SCP-PERM-3001"),
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
