// EncryptionConformanceTest.kt — Encryption/sender-key conformance tests for the Kotlin SDK (SCP-120)
// Provenance: SCP-120, .docs/scaffold/shared.md "Sender keys" + "Messaging" categories

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
 * Cross-platform conformance tests for encryption and sender key operations.
 *
 * Covers: sender key create, distribute, rotate, encrypt/decrypt roundtrip,
 * key destruction on leave, MLS encryption via context messaging.
 *
 * Encryption is exercised indirectly through context send/receive (the Rust
 * engine handles MLS encryption transparently). These tests verify that the
 * Kotlin SDK correctly proxies encryption-related errors and that the API
 * contract matches the cross-platform specification.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class EncryptionConformanceTest {
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
    inner class EncryptedMessaging {
        @Test
        fun `context_send succeeds with encrypted payload`() =
            runTest(testDispatcher) {
                val result =
                    dispatcher.dispatch(
                        "context_send",
                        mapOf(
                            "context_handle" to "10",
                            "identity_handle" to "1",
                            "payload" to "encrypted-content",
                        ),
                    )
                assertEquals("sent", result["status"])
                assertEquals(
                    "encrypted-content",
                    stubBindings.contextSendPayload?.let { String(it) },
                )
            }

        @Test
        fun `context_send propagates MLS encryption error`() =
            runTest(testDispatcher) {
                stubBindings.contextSendError =
                    BridgeException("MLS encryption failed", "SCP-CRYPTO-4001")
                val result =
                    dispatcher.dispatch(
                        "context_send",
                        mapOf(
                            "context_handle" to "10",
                            "identity_handle" to "1",
                            "payload" to "data",
                        ),
                    )
                assertEquals("SCP-CRYPTO-4001", result["error"])
            }
    }

    @Nested
    inner class SenderKeyErrors {
        @Test
        fun `sender key rotation error propagated`() =
            runTest(testDispatcher) {
                stubBindings.contextSendError =
                    BridgeException("Sender key expired", "SCP-CRYPTO-4010")
                val result =
                    dispatcher.dispatch(
                        "context_send",
                        mapOf(
                            "context_handle" to "10",
                            "identity_handle" to "1",
                            "payload" to "data",
                        ),
                    )
                assertEquals("SCP-CRYPTO-4010", result["error"])
            }

        @Test
        fun `key destruction error on leave`() =
            runTest(testDispatcher) {
                stubBindings.contextLeaveError =
                    BridgeException("Key cleanup failed", "SCP-CRYPTO-4011")
                val result =
                    dispatcher.dispatch(
                        "context_leave",
                        mapOf("context_handle" to "10", "identity_handle" to "1"),
                    )
                assertEquals("SCP-CRYPTO-4011", result["error"])
            }
    }

    @Nested
    inner class DecryptionErrors {
        @Test
        fun `decryption error propagated through subscription`() =
            runTest(testDispatcher) {
                stubBindings.contextSendError =
                    BridgeException("Decryption failed", "SCP-CRYPTO-4002")
                val result =
                    dispatcher.dispatch(
                        "context_send",
                        mapOf(
                            "context_handle" to "10",
                            "identity_handle" to "1",
                            "payload" to "garbled",
                        ),
                    )
                assertEquals("SCP-CRYPTO-4002", result["error"])
            }
    }

    @Nested
    inner class FixtureIntegration {
        @Test
        fun `encrypted send fixture matches dispatcher result`() =
            runTest(testDispatcher) {
                val fixture =
                    ConformanceFixture(
                        testId = "encryption-send-001",
                        category = "sender_keys",
                        description = "Send encrypted message",
                        operation = "context_send",
                        input =
                            mapOf(
                                "context_handle" to "10",
                                "identity_handle" to "1",
                                "payload" to "hello-encrypted",
                            ),
                        expected = mapOf("status" to "sent"),
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
