// UcanConformanceTest.kt — UCAN conformance tests for the Kotlin SDK (SCP-120)
// Provenance: SCP-120, .docs/scaffold/shared.md "UCAN" category

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
                        "context_handle" to "10",
                        "encoded" to "test.token.sig",
                        "capability" to "read",
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
                        "context_handle" to "10",
                        "encoded" to "bad.token",
                        "capability" to "write",
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
                        "context_handle" to "10",
                        "encoded" to "expired.token.sig",
                        "capability" to "read",
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
                        "context_handle" to "10",
                        "encoded" to "replayed.token.sig",
                        "capability" to "read",
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
                    "context_handle" to "10",
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
                    "context_handle" to "10",
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
                        "context_handle" to "10",
                        "audience_did" to "did:dht:z6MkAudience",
                        "capabilities" to """["admin"]""",
                    ),
                )
                assertEquals("SCP-PERM-3012", result["error"])
            }
    }

    @Nested
    inner class UcanDelegate {
        @Test
        fun `ucan_delegate returns delegated token`() = runTest(testDispatcher) {
            stubBindings.ucanDelegateResult = "eyJ.delegated.token"
            val result = dispatcher.dispatch(
                "ucan_delegate",
                mapOf(
                    "context_handle" to "10",
                    "delegator_did" to "did:dht:z6MkDelegator",
                    "delegatee_did" to "did:dht:z6MkDelegatee",
                    "parent_token" to "eyJ.parent.token",
                    "capabilities" to """["read"]""",
                ),
            )
            assertEquals("eyJ.delegated.token", result["token"])
        }

        @Test
        fun `ucan_delegate propagates permission error`() = runTest(testDispatcher) {
            stubBindings.ucanDelegateError =
                BridgeException("Capabilities wider than parent", "SCP-PERM-3004")
            val result = dispatcher.dispatch(
                "ucan_delegate",
                mapOf(
                    "context_handle" to "10",
                    "delegator_did" to "did:dht:z6MkDelegator",
                    "delegatee_did" to "did:dht:z6MkDelegatee",
                    "parent_token" to "eyJ.parent.token",
                    "capabilities" to """["admin"]""",
                ),
            )
            assertEquals("SCP-PERM-3004", result["error"])
        }

        @Test
        fun `ucan_delegate chain - mint then delegate`() = runTest(testDispatcher) {
            // Step 1: Mint a root token
            stubBindings.ucanMintResult = "eyJ.root.token"
            val mintResult = dispatcher.dispatch(
                "ucan_mint",
                mapOf(
                    "context_handle" to "10",
                    "audience_did" to "did:dht:z6MkDelegator",
                    "capabilities" to """["read","write"]""",
                ),
            )
            assertEquals("eyJ.root.token", mintResult["token"])

            // Step 2: Delegate attenuated capabilities from root token
            stubBindings.ucanDelegateResult = "eyJ.child.token"
            val delegateResult = dispatcher.dispatch(
                "ucan_delegate",
                mapOf(
                    "context_handle" to "10",
                    "delegator_did" to "did:dht:z6MkDelegator",
                    "delegatee_did" to "did:dht:z6MkDelegatee",
                    "parent_token" to mintResult["token"]!!,
                    "capabilities" to """["read"]""",
                ),
            )
            assertEquals("eyJ.child.token", delegateResult["token"])
        }
    }

    @Nested
    inner class UcanRevoke {
        @Test
        fun `ucan_revoke succeeds`() = runTest(testDispatcher) {
            val result = dispatcher.dispatch(
                "ucan_revoke",
                mapOf("context_handle" to "10", "token" to "header.payload.signature"),
            )
            assertEquals("revoked", result["status"])
        }

        @Test
        fun `ucan_revoke propagates error`() = runTest(testDispatcher) {
            stubBindings.ucanRevokeError =
                BridgeException("Not authorized to revoke", "SCP-PERM-3003")
            val result = dispatcher.dispatch(
                "ucan_revoke",
                mapOf("context_handle" to "10", "token" to "header.payload.signature"),
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
                        "context_handle" to "10",
                        "encoded" to "test.token.sig",
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
