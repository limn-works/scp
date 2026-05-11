// IdentityAdvancedBridgeTest.kt — Unit tests for IdentityAdvancedBridge (#428)
//
// Verifies that IdentityAdvancedBridge methods delegate to the injected
// IdentityAdvancedBindings with correct argument forwarding, return value
// propagation, and error handling.
//
// Provenance: SCP-RG-019, §3.2 (Key Custody), §3.2.1 (Key Custody Migration),
//   §3.4 (Linking Identities), ADR-039 (Shared-DID Agent Binding)

package works.limn.scp.bridge

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import works.limn.scp.IdentityAdvancedBindings
import works.limn.scp.IdentityAdvancedBridge
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Stub implementation of [IdentityAdvancedBindings] for testing.
 *
 * Tracks calls, captures arguments, and returns configurable results
 * or throws configurable exceptions.
 */
class StubIdentityAdvancedBindings : IdentityAdvancedBindings {
    // Call tracking
    var createWithAgentKeyCalled = false
    var addAgentKeyCalled = false
    var rotateAgentKeyCalled = false
    var removeAgentKeyCalled = false
    var migrateCalled = false
    var attestDeviceCalled = false
    var verifyDeviceAttestationCalled = false
    var executeRecoveryCalled = false
    var executeCustodyMigrationCalled = false

    // Argument captures
    var lastCustody: String? = null
    var lastIdentityHandle: Long? = null
    var lastDid: String? = null
    var lastTier: String? = null
    var lastTarget: String? = null
    var lastContextIds: List<String>? = null
    var lastTokenBase64: String? = null

    // Configurable results
    var createWithAgentKeyResult = 100L
    var addAgentKeyResult = 101L
    var rotateAgentKeyResult = 102L
    var removeAgentKeyResult = 103L
    var migrateResult = 104L
    var rotationEventJsonResult: String? =
        """{"old_did":"did:dht:zOld","new_did":"did:dht:zNew","rotated_at":1700000000}"""
    var attestDeviceResult = "dGVzdC1hdHRlc3RhdGlvbg=="
    var verifyDeviceAttestationResult = true
    var executeRecoveryResult = """{"key_rotation_completed":true}"""
    var executeCustodyMigrationResult = """{"key_generated":true,"authorized":true}"""

    // Configurable errors
    var createWithAgentKeyError: Exception? = null
    var executeCustodyMigrationError: Exception? = null
    var executeRecoveryError: Exception? = null

    override fun identityCreateWithAgentKey(custody: String): Long {
        createWithAgentKeyCalled = true
        lastCustody = custody
        createWithAgentKeyError?.let { throw it }
        return createWithAgentKeyResult
    }

    override fun identityAddAgentKey(identityHandle: Long): Long {
        addAgentKeyCalled = true
        lastIdentityHandle = identityHandle
        return addAgentKeyResult
    }

    override fun identityRotateAgentKey(identityHandle: Long): Long {
        rotateAgentKeyCalled = true
        lastIdentityHandle = identityHandle
        return rotateAgentKeyResult
    }

    override fun identityRemoveAgentKey(identityHandle: Long): Long {
        removeAgentKeyCalled = true
        lastIdentityHandle = identityHandle
        return removeAgentKeyResult
    }

    override fun identityMigrate(identityHandle: Long): Long {
        migrateCalled = true
        lastIdentityHandle = identityHandle
        return migrateResult
    }

    override fun identityRotationEventJson(identityHandle: Long): String? {
        lastIdentityHandle = identityHandle
        return rotationEventJsonResult
    }

    override fun identityAttestDevice(identityHandle: Long): String {
        attestDeviceCalled = true
        lastIdentityHandle = identityHandle
        return attestDeviceResult
    }

    override fun identityVerifyDeviceAttestation(
        did: String,
        tokenBase64: String,
    ): Boolean {
        verifyDeviceAttestationCalled = true
        lastDid = did
        lastTokenBase64 = tokenBase64
        return verifyDeviceAttestationResult
    }

    override fun identityExecuteRecovery(
        did: String,
        tier: String,
        contextIds: List<String>,
    ): String {
        executeRecoveryCalled = true
        lastDid = did
        lastTier = tier
        lastContextIds = contextIds
        executeRecoveryError?.let { throw it }
        return executeRecoveryResult
    }

    override fun identityExecuteCustodyMigration(
        did: String,
        target: String,
        contextIds: List<String>,
    ): String {
        executeCustodyMigrationCalled = true
        lastDid = did
        lastTarget = target
        lastContextIds = contextIds
        executeCustodyMigrationError?.let { throw it }
        return executeCustodyMigrationResult
    }

    // Identity link attestation (§3.5.1) — stub implementations
    override fun identityCreateLinkAttestation(
        identityHandle: Long,
        platform: String,
        handle: String,
        proof: String,
        verificationMethod: String,
        platformId: String?,
    ): String = """{"id":"mock-id","type":"identity_link","issuer":"did:dht:z6mock"}"""

    override fun identityLinkAttestations(did: String): String = "[]"

    override fun identityRemoveLinkAttestation(
        did: String,
        attestationId: String,
    ): Boolean = true

    override fun identityVerifyLinkAttestation(
        attestationJson: String,
        issuerPublicKeyHex: String,
    ): Boolean = true
}

@OptIn(ExperimentalCoroutinesApi::class)
class IdentityAdvancedBridgeTest {
    private lateinit var bridge: CoroutineBridge
    private lateinit var stubBindings: StubNativeBindings
    private lateinit var stubAdvanced: StubIdentityAdvancedBindings
    private lateinit var advancedBridge: IdentityAdvancedBridge
    private lateinit var testDispatcher: TestDispatcher

    @BeforeEach
    fun setUp() {
        stubBindings = StubNativeBindings()
        stubAdvanced = StubIdentityAdvancedBindings()
        testDispatcher = StandardTestDispatcher()
        bridge =
            CoroutineBridge(
                nativeBindings = stubBindings,
                ioDispatcher = testDispatcher,
                cpuDispatcher = testDispatcher,
                extendedBindings = ExtendedBindings(identityAdvanced = stubAdvanced),
            )
        advancedBridge = bridge.identityAdvanced!!
    }

    @Nested
    inner class CreateWithAgentKey {
        @Test
        fun `createWithAgentKey delegates to bindings with custody string`() =
            runTest(testDispatcher) {
                val result = advancedBridge.createWithAgentKey("in_memory")
                assertTrue(stubAdvanced.createWithAgentKeyCalled)
                assertEquals("in_memory", stubAdvanced.lastCustody)
                assertEquals(100L, result)
            }

        @Test
        fun `createWithAgentKey propagates bridge error`() =
            runTest(testDispatcher) {
                stubAdvanced.createWithAgentKeyError = BridgeException("custody not available", "SCP-IDENT-1020")
                assertFailsWith<BridgeException> {
                    advancedBridge.createWithAgentKey("platform")
                }
            }
    }

    @Nested
    inner class AddAgentKey {
        @Test
        fun `addAgentKey delegates handle to bindings`() =
            runTest(testDispatcher) {
                val result = advancedBridge.addAgentKey(42L)
                assertTrue(stubAdvanced.addAgentKeyCalled)
                assertEquals(42L, stubAdvanced.lastIdentityHandle)
                assertEquals(101L, result)
            }
    }

    @Nested
    inner class RotateAgentKey {
        @Test
        fun `rotateAgentKey delegates handle to bindings`() =
            runTest(testDispatcher) {
                val result = advancedBridge.rotateAgentKey(42L)
                assertTrue(stubAdvanced.rotateAgentKeyCalled)
                assertEquals(42L, stubAdvanced.lastIdentityHandle)
                assertEquals(102L, result)
            }
    }

    @Nested
    inner class RemoveAgentKey {
        @Test
        fun `removeAgentKey delegates handle to bindings`() =
            runTest(testDispatcher) {
                val result = advancedBridge.removeAgentKey(42L)
                assertTrue(stubAdvanced.removeAgentKeyCalled)
                assertEquals(42L, stubAdvanced.lastIdentityHandle)
                assertEquals(103L, result)
            }
    }

    @Nested
    inner class Migrate {
        // The simpler `migrate` overload is deprecated at ERROR level
        // because it drops the rotation event required by spec §3.2.1
        // step 4b. We still test that the underlying binding plumbing
        // works for any legacy in-tree caller until the overload is
        // removed. `DEPRECATION_ERROR` is the Kotlin-specific suppress
        // key for `DeprecationLevel.ERROR` (plain `DEPRECATION` only
        // covers `DeprecationLevel.WARNING`).
        @Suppress("DEPRECATION_ERROR")
        @Test
        fun `migrate delegates handle to bindings`() =
            runTest(testDispatcher) {
                val result = advancedBridge.migrate(42L)
                assertTrue(stubAdvanced.migrateCalled)
                assertEquals(42L, stubAdvanced.lastIdentityHandle)
                assertEquals(104L, result)
            }

        @Test
        fun `migrateWithRotationEvent returns handle and rotation event JSON`() =
            runTest(testDispatcher) {
                val expectedJson =
                    """{"old_did":"did:dht:zOld","new_did":"did:dht:zNew","rotated_at":1700000000}"""
                stubAdvanced.rotationEventJsonResult = expectedJson
                val result = advancedBridge.migrateWithRotationEvent(42L)
                assertTrue(stubAdvanced.migrateCalled)
                assertEquals(104L, result.handle)
                assertEquals(expectedJson, result.rotationEventJson)
            }

        @Test
        fun `migrateWithRotationEvent surfaces null rotation event JSON`() =
            runTest(testDispatcher) {
                stubAdvanced.rotationEventJsonResult = null
                val result = advancedBridge.migrateWithRotationEvent(42L)
                assertEquals(104L, result.handle)
                assertEquals(null, result.rotationEventJson)
            }
    }

    @Nested
    inner class AttestDevice {
        @Test
        fun `attestDevice delegates handle and returns token`() =
            runTest(testDispatcher) {
                val result = advancedBridge.attestDevice(42L)
                assertTrue(stubAdvanced.attestDeviceCalled)
                assertEquals(42L, stubAdvanced.lastIdentityHandle)
                assertEquals("dGVzdC1hdHRlc3RhdGlvbg==", result)
            }
    }

    @Nested
    inner class VerifyDeviceAttestation {
        @Test
        fun `verifyDeviceAttestation delegates did and token`() =
            runTest(testDispatcher) {
                val result = advancedBridge.verifyDeviceAttestation("did:dht:z6MkTest", "dGVzdA==")
                assertTrue(stubAdvanced.verifyDeviceAttestationCalled)
                assertEquals("did:dht:z6MkTest", stubAdvanced.lastDid)
                assertEquals("dGVzdA==", stubAdvanced.lastTokenBase64)
                assertTrue(result)
            }

        @Test
        fun `verifyDeviceAttestation returns false for invalid token`() =
            runTest(testDispatcher) {
                stubAdvanced.verifyDeviceAttestationResult = false
                val result = advancedBridge.verifyDeviceAttestation("did:dht:z6MkTest", "aW52YWxpZA==")
                assertEquals(false, result)
            }
    }

    @Nested
    inner class ExecuteRecovery {
        @Test
        fun `executeRecovery delegates did, tier, and contextIds`() =
            runTest(testDispatcher) {
                val result = advancedBridge.executeRecovery("did:dht:z6MkTest", "agent", listOf("ctx-1"))
                assertTrue(stubAdvanced.executeRecoveryCalled)
                assertEquals("did:dht:z6MkTest", stubAdvanced.lastDid)
                assertEquals("agent", stubAdvanced.lastTier)
                assertEquals(listOf("ctx-1"), stubAdvanced.lastContextIds)
                assertTrue(result.contains("key_rotation_completed"))
            }

        @Test
        fun `executeRecovery propagates bridge error`() =
            runTest(testDispatcher) {
                stubAdvanced.executeRecoveryError = BridgeException("recovery failed", "SCP-IDENT-1030")
                assertFailsWith<BridgeException> {
                    advancedBridge.executeRecovery("did:dht:z6MkFail", "identity_key")
                }
            }
    }

    @Nested
    inner class ExecuteCustodyMigration {
        @Test
        fun `executeCustodyMigration delegates did, target, and contextIds`() =
            runTest(testDispatcher) {
                val result =
                    advancedBridge.executeCustodyMigration(
                        "did:dht:z6MkTest",
                        "hardware",
                        listOf("ctx-1", "ctx-2"),
                    )
                assertTrue(stubAdvanced.executeCustodyMigrationCalled)
                assertEquals("did:dht:z6MkTest", stubAdvanced.lastDid)
                assertEquals("hardware", stubAdvanced.lastTarget)
                assertEquals(listOf("ctx-1", "ctx-2"), stubAdvanced.lastContextIds)
                assertTrue(result.contains("key_generated"))
                assertTrue(result.contains("authorized"))
            }

        @Test
        fun `executeCustodyMigration with empty contextIds`() =
            runTest(testDispatcher) {
                advancedBridge.executeCustodyMigration("did:dht:z6MkTest", "software")
                assertEquals(emptyList(), stubAdvanced.lastContextIds)
            }

        @Test
        fun `executeCustodyMigration propagates bridge error`() =
            runTest(testDispatcher) {
                stubAdvanced.executeCustodyMigrationError =
                    BridgeException("backend not configured", "SCP-IDENT-1025")
                assertFailsWith<BridgeException> {
                    advancedBridge.executeCustodyMigration("did:dht:z6MkFail", "hardware")
                }
            }

        @Test
        fun `executeCustodyMigration supports all target types`() =
            runTest(testDispatcher) {
                for (target in listOf("platform_managed", "hardware", "software", "in_memory")) {
                    advancedBridge.executeCustodyMigration("did:dht:z6MkTest", target)
                    assertEquals(target, stubAdvanced.lastTarget)
                }
            }
    }
}
