// SyncBridgeTest.kt — Unit tests for SyncBridge delegation (#528)
//
// Verifies that SyncBridge methods delegate to the injected SyncBindings
// with correct argument forwarding and return value propagation.
//
// Uses the same mock-based pattern as CoroutineBridgeTest: injectable
// TestDispatcher, stub bindings with call tracking, runTest.
//
// Provenance: §23.6 (Sync Policy), #528

package works.limn.scp.bridge

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import works.limn.scp.SyncBindings
import works.limn.scp.SyncPolicy
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class SyncBridgeTest {
    private lateinit var bridge: CoroutineBridge
    private lateinit var stubBindings: StubNativeBindings
    private lateinit var stubSyncBindings: StubSyncBindings
    private lateinit var ioDispatcher: TestDispatcher

    @BeforeEach
    fun setUp() {
        stubBindings = StubNativeBindings()
        stubSyncBindings = StubSyncBindings()
        ioDispatcher = StandardTestDispatcher()
        bridge =
            CoroutineBridge(
                nativeBindings = stubBindings,
                ioDispatcher = ioDispatcher,
                cpuDispatcher = StandardTestDispatcher(),
                extendedBindings = ExtendedBindings(sync = stubSyncBindings),
            )
    }

    // -------------------------------------------------------------------
    // classifyOffline delegation
    // -------------------------------------------------------------------

    @Nested
    inner class ClassifyOfflineTests {
        @Test
        fun `classifyOffline delegates to syncClassifyOffline with correct args`() =
            runTest(ioDispatcher) {
                stubSyncBindings.classifyOfflineResult = "short"

                val result = bridge.sync!!.classifyOffline(1000L, 2000L)

                assertEquals("short", result)
                assertTrue(stubSyncBindings.classifyOfflineCalled)
                assertEquals(1000L, stubSyncBindings.lastClassifyLastRelayContact)
                assertEquals(2000L, stubSyncBindings.lastClassifyNow)
            }

        @Test
        fun `classifyOffline returns extended for large gap`() =
            runTest(ioDispatcher) {
                stubSyncBindings.classifyOfflineResult = "extended"

                val result = bridge.sync!!.classifyOffline(0L, 50_000L)

                assertEquals("extended", result)
                assertEquals(0L, stubSyncBindings.lastClassifyLastRelayContact)
                assertEquals(50_000L, stubSyncBindings.lastClassifyNow)
            }

        @Test
        fun `classifyOffline returns long for very large gap`() =
            runTest(ioDispatcher) {
                stubSyncBindings.classifyOfflineResult = "long"

                val result = bridge.sync!!.classifyOffline(0L, 1_000_000L)

                assertEquals("long", result)
            }
    }

    // -------------------------------------------------------------------
    // classifyOfflineCustom delegation
    // -------------------------------------------------------------------

    @Nested
    inner class ClassifyOfflineCustomTests {
        @Test
        fun `classifyOfflineCustom delegates to syncClassifyOfflineCustom with correct args`() =
            runTest(ioDispatcher) {
                stubSyncBindings.classifyOfflineCustomResult = "short"

                val result =
                    bridge.sync!!.classifyOfflineCustom(
                        lastRelayContact = 1000L,
                        now = 2000L,
                        tier1ThresholdSecs = 3600L,
                        tier2ThresholdSecs = 86400L,
                    )

                assertEquals("short", result)
                assertTrue(stubSyncBindings.classifyOfflineCustomCalled)
                assertEquals(1000L, stubSyncBindings.lastCustomLastRelayContact)
                assertEquals(2000L, stubSyncBindings.lastCustomNow)
                assertEquals(3600L, stubSyncBindings.lastCustomTier1)
                assertEquals(86400L, stubSyncBindings.lastCustomTier2)
            }

        @Test
        fun `classifyOfflineCustom forwards custom thresholds correctly`() =
            runTest(ioDispatcher) {
                stubSyncBindings.classifyOfflineCustomResult = "extended"

                val result =
                    bridge.sync!!.classifyOfflineCustom(
                        lastRelayContact = 0L,
                        now = 7200L,
                        tier1ThresholdSecs = 1800L,
                        tier2ThresholdSecs = 3600L,
                    )

                assertEquals("extended", result)
                assertEquals(1800L, stubSyncBindings.lastCustomTier1)
                assertEquals(3600L, stubSyncBindings.lastCustomTier2)
            }
    }

    // -------------------------------------------------------------------
    // getPolicy delegation
    // -------------------------------------------------------------------

    @Nested
    inner class GetPolicyTests {
        @Test
        fun `getPolicy delegates to syncGetPolicy and returns result`() =
            runTest(ioDispatcher) {
                val customPolicy =
                    SyncPolicy(
                        tier1ThresholdSecs = 7200L,
                        tier2ThresholdSecs = 302_400L,
                        gapTimeoutSecs = 15L,
                        reorderBufferCapacity = 50,
                        maxSequentialCommits = 200L,
                        commitProcessTimeoutSecs = 10L,
                        senderKeyTimeoutSecs = 120L,
                        reconnectionDedupWindowSecs = 60L,
                    )
                stubSyncBindings.getPolicyResult = customPolicy

                val result = bridge.sync!!.getPolicy()

                assertEquals(customPolicy, result)
                assertTrue(stubSyncBindings.getPolicyCalled)
            }

        @Test
        fun `getPolicy returns runtime values not hardcoded defaults`() =
            runTest(ioDispatcher) {
                val nonDefaultPolicy =
                    SyncPolicy(
                        tier1ThresholdSecs = 999L,
                        tier2ThresholdSecs = 888L,
                        gapTimeoutSecs = 777L,
                        reorderBufferCapacity = 666,
                        maxSequentialCommits = 555L,
                        commitProcessTimeoutSecs = 444L,
                        senderKeyTimeoutSecs = 333L,
                        reconnectionDedupWindowSecs = 222L,
                    )
                stubSyncBindings.getPolicyResult = nonDefaultPolicy

                val result = bridge.sync!!.getPolicy()

                // Verify each field matches the stub — NOT the Kotlin defaults
                assertEquals(999L, result.tier1ThresholdSecs)
                assertEquals(888L, result.tier2ThresholdSecs)
                assertEquals(777L, result.gapTimeoutSecs)
                assertEquals(666, result.reorderBufferCapacity)
                assertEquals(555L, result.maxSequentialCommits)
                assertEquals(444L, result.commitProcessTimeoutSecs)
                assertEquals(333L, result.senderKeyTimeoutSecs)
                assertEquals(222L, result.reconnectionDedupWindowSecs)
            }
    }
}

// ---------------------------------------------------------------------------
// Stub SyncBindings for testing
// ---------------------------------------------------------------------------

/**
 * Test stub for [SyncBindings] that records calls and returns configured results.
 *
 * Allows tests to verify which methods were called, with what arguments,
 * and to control return values.
 */
class StubSyncBindings : SyncBindings {
    // classifyOffline tracking
    var classifyOfflineCalled = false
    var lastClassifyLastRelayContact: Long? = null
    var lastClassifyNow: Long? = null
    var classifyOfflineResult = "short"

    // classifyOfflineCustom tracking
    var classifyOfflineCustomCalled = false
    var lastCustomLastRelayContact: Long? = null
    var lastCustomNow: Long? = null
    var lastCustomTier1: Long? = null
    var lastCustomTier2: Long? = null
    var classifyOfflineCustomResult = "short"

    // getPolicy tracking
    var getPolicyCalled = false
    var getPolicyResult = SyncPolicy()

    override fun syncClassifyOffline(
        lastRelayContact: Long,
        now: Long,
    ): String {
        classifyOfflineCalled = true
        lastClassifyLastRelayContact = lastRelayContact
        lastClassifyNow = now
        return classifyOfflineResult
    }

    override fun syncClassifyOfflineCustom(
        lastRelayContact: Long,
        now: Long,
        tier1ThresholdSecs: Long,
        tier2ThresholdSecs: Long,
    ): String {
        classifyOfflineCustomCalled = true
        lastCustomLastRelayContact = lastRelayContact
        lastCustomNow = now
        lastCustomTier1 = tier1ThresholdSecs
        lastCustomTier2 = tier2ThresholdSecs
        return classifyOfflineCustomResult
    }

    override fun syncGetPolicy(): SyncPolicy {
        getPolicyCalled = true
        return getPolicyResult
    }
}
