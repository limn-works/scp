// ScpIdTest.kt — Unit tests for SCPID authentication wrappers (#1059)
//
// Verifies that ScpIdBridge methods delegate to the injected ScpIdBindings
// with correct argument forwarding, JSON parsing, and return value propagation.
//
// Uses the same mock-based pattern as SyncBridgeTest: injectable
// TestDispatcher, stub bindings with call tracking, runTest.
//
// Provenance: spec section 3.11 (SCPID), #1059

package works.limn.scp.auth

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import works.limn.scp.bridge.CoroutineBridge
import works.limn.scp.bridge.ExtendedBindings
import works.limn.scp.bridge.StubNativeBindings
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class ScpIdTest {
    private lateinit var bridge: CoroutineBridge
    private lateinit var stubBindings: StubNativeBindings
    private lateinit var stubScpIdBindings: StubScpIdBindings
    private lateinit var ioDispatcher: TestDispatcher

    @BeforeEach
    fun setUp() {
        stubBindings = StubNativeBindings()
        stubScpIdBindings = StubScpIdBindings()
        ioDispatcher = StandardTestDispatcher()
        bridge =
            CoroutineBridge(
                nativeBindings = stubBindings,
                ioDispatcher = ioDispatcher,
                cpuDispatcher = StandardTestDispatcher(),
                extendedBindings = ExtendedBindings(scpId = stubScpIdBindings),
            )
    }

    // -------------------------------------------------------------------
    // Challenge delegation
    // -------------------------------------------------------------------

    @Nested
    inner class ChallengeTests {
        @Test
        fun `challenge delegates to scpidChallenge with correct args`() =
            runTest(ioDispatcher) {
                stubScpIdBindings.challengeResult = TEST_CHALLENGE_JSON

                val result = bridge.scpId!!.challenge("https://app.example.com", 60)

                assertTrue(stubScpIdBindings.challengeCalled)
                assertEquals("https://app.example.com", stubScpIdBindings.lastChallengeAudience)
                assertEquals(60L, stubScpIdBindings.lastChallengeTtlSeconds)
                assertEquals("scpid/1.0", result.protocolVersion)
                assertEquals("https://app.example.com", result.audience)
                assertEquals(1700000000000L, result.issuedAt)
                assertEquals(1700000300000L, result.expiresAt)
                assertTrue(result.nonce.isNotEmpty())
                assertEquals(TEST_CHALLENGE_JSON, result.json)
            }

        @Test
        fun `challenge uses default TTL of 300 seconds`() =
            runTest(ioDispatcher) {
                stubScpIdBindings.challengeResult = TEST_CHALLENGE_JSON

                bridge.scpId!!.challenge("https://app.example.com")

                assertEquals(300L, stubScpIdBindings.lastChallengeTtlSeconds)
            }
    }

    // -------------------------------------------------------------------
    // Sign delegation
    // -------------------------------------------------------------------

    @Nested
    inner class SignTests {
        @Test
        fun `sign delegates to scpidSign with correct args`() =
            runTest(ioDispatcher) {
                stubScpIdBindings.challengeResult = TEST_CHALLENGE_JSON
                stubScpIdBindings.signResult = TEST_RESPONSE_JSON

                val challenge = bridge.scpId!!.challenge("https://app.example.com")
                val response = bridge.scpId!!.sign(42L, "#active", challenge)

                assertTrue(stubScpIdBindings.signCalled)
                assertEquals(42L, stubScpIdBindings.lastSignIdentityHandle)
                assertEquals("#active", stubScpIdBindings.lastSignKeyId)
                assertEquals(TEST_CHALLENGE_JSON, stubScpIdBindings.lastSignChallengeJson)
                assertEquals("did:dht:z6MkTestSigner", response.did)
                assertEquals("#active", response.signingKeyId)
                assertEquals("https://app.example.com", response.audience)
                assertEquals(TEST_RESPONSE_JSON, response.json)
            }
    }

    // -------------------------------------------------------------------
    // Verify delegation
    // -------------------------------------------------------------------

    @Nested
    inner class VerifyTests {
        @Test
        fun `verify delegates to scpidVerify with correct args`() =
            runTest(ioDispatcher) {
                stubScpIdBindings.challengeResult = TEST_CHALLENGE_JSON
                stubScpIdBindings.signResult = TEST_RESPONSE_JSON
                stubScpIdBindings.verifyResult = TEST_AUTH_JSON

                val challenge = bridge.scpId!!.challenge("https://app.example.com")
                val response = bridge.scpId!!.sign(42L, "#active", challenge)
                val auth = bridge.scpId!!.verify(response, challenge)

                assertTrue(stubScpIdBindings.verifyCalled)
                assertEquals(TEST_RESPONSE_JSON, stubScpIdBindings.lastVerifyResponseJson)
                assertEquals(TEST_CHALLENGE_JSON, stubScpIdBindings.lastVerifyChallengeJson)
                assertEquals("did:dht:z6MkTestSigner", auth.did)
                assertEquals("#active", auth.signingKeyId)
                assertEquals(1700000000500L, auth.signedAt)
            }

        @Test
        fun `verify result has correct DID`() =
            runTest(ioDispatcher) {
                stubScpIdBindings.challengeResult = TEST_CHALLENGE_JSON
                stubScpIdBindings.signResult = TEST_RESPONSE_JSON
                stubScpIdBindings.verifyResult = TEST_AUTH_JSON

                val challenge = bridge.scpId!!.challenge("https://app.example.com")
                val response = bridge.scpId!!.sign(42L, "#active", challenge)
                val auth = bridge.scpId!!.verify(response, challenge)

                assertEquals("did:dht:z6MkTestSigner", auth.did)
            }
    }

    // -------------------------------------------------------------------
    // Full roundtrip
    // -------------------------------------------------------------------

    @Nested
    inner class RoundtripTests {
        @Test
        fun `full challenge-sign-verify roundtrip`() =
            runTest(ioDispatcher) {
                stubScpIdBindings.challengeResult = TEST_CHALLENGE_JSON
                stubScpIdBindings.signResult = TEST_RESPONSE_JSON
                stubScpIdBindings.verifyResult = TEST_AUTH_JSON

                val challenge = bridge.scpId!!.challenge("https://app.example.com", 120)
                val response = bridge.scpId!!.sign(42L, "#active", challenge)
                val auth = bridge.scpId!!.verify(response, challenge)

                // Verify consistency across the roundtrip
                assertEquals("https://app.example.com", challenge.audience)
                assertEquals(response.did, auth.did)
                assertEquals(response.signingKeyId, auth.signingKeyId)
                assertEquals("did:dht:z6MkTestSigner", auth.did)
                assertEquals("#active", auth.signingKeyId)
            }
    }

    // -------------------------------------------------------------------
    // JSON parsing
    // -------------------------------------------------------------------

    @Nested
    inner class ParsingTests {
        @Test
        fun `parseChallenge extracts all fields`() {
            val result = ScpId.parseChallenge(TEST_CHALLENGE_JSON)

            assertEquals("scpid/1.0", result.protocolVersion)
            assertEquals(
                "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                result.nonce,
            )
            assertEquals("https://app.example.com", result.audience)
            assertEquals(1700000000000L, result.issuedAt)
            assertEquals(1700000300000L, result.expiresAt)
            assertEquals(TEST_CHALLENGE_JSON, result.json)
        }

        @Test
        fun `parseResponse extracts all fields`() {
            val result = ScpId.parseResponse(TEST_RESPONSE_JSON)

            assertEquals("scpid/1.0", result.protocolVersion)
            assertEquals("did:dht:z6MkTestSigner", result.did)
            assertEquals("#active", result.signingKeyId)
            assertEquals("https://app.example.com", result.audience)
            assertEquals(1700000000500L, result.signedAt)
            assertTrue(result.signature.isNotEmpty())
            assertEquals(TEST_RESPONSE_JSON, result.json)
        }

        @Test
        fun `parseAuthentication extracts all fields`() {
            val result = ScpId.parseAuthentication(TEST_AUTH_JSON)

            assertEquals("did:dht:z6MkTestSigner", result.did)
            assertEquals("#active", result.signingKeyId)
            assertEquals(1700000000500L, result.signedAt)
        }
    }

    // -------------------------------------------------------------------
    // ScpIdBridge wiring through CoroutineBridge
    // -------------------------------------------------------------------

    @Test
    fun `scpId bridge is non-null when bindings provided`() {
        assertNotNull(bridge.scpId)
    }

    @Test
    fun `scpId bridge is null when bindings not provided`() {
        val bridgeWithout =
            CoroutineBridge(
                nativeBindings = stubBindings,
                ioDispatcher = ioDispatcher,
                cpuDispatcher = StandardTestDispatcher(),
            )
        assertEquals(null, bridgeWithout.scpId)
    }

    companion object {
        // Test JSON fixtures matching the Rust bridge output format.

        private const val TEST_CHALLENGE_JSON =
            """{"protocol":"scpid/1.0","nonce":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4""" +
                """e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2","audience":"https://app.example.com",""" +
                """"issued_at":1700000000000,"expires_at":1700000300000}"""

        private const val TEST_RESPONSE_JSON =
            """{"protocol":"scpid/1.0","did":"did:dht:z6MkTestSigner",""" +
                """"signing_key_id":"#active","nonce":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4""" +
                """e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2","audience":"https://app.example.com",""" +
                """"signed_at":1700000000500,"signature":"aabbccddee00112233445566778899""" +
                """aabbccddee00112233445566778899aabbccddee00112233445566778899""" +
                """aabbccddee00112233445566778899aabbccdd"}"""

        private const val TEST_AUTH_JSON =
            """{"did":"did:dht:z6MkTestSigner","signing_key_id":"#active","signed_at":1700000000500}"""
    }
}

// ---------------------------------------------------------------------------
// Stub ScpIdBindings for testing
// ---------------------------------------------------------------------------

/**
 * Test stub for [ScpIdBindings] that records calls and returns configured results.
 */
class StubScpIdBindings : ScpIdBindings {
    // challenge tracking
    var challengeCalled = false
    var lastChallengeAudience: String? = null
    var lastChallengeTtlSeconds: Long? = null
    var challengeResult = ""

    // sign tracking
    var signCalled = false
    var lastSignIdentityHandle: Long? = null
    var lastSignKeyId: String? = null
    var lastSignChallengeJson: String? = null
    var signResult = ""

    // verify tracking
    var verifyCalled = false
    var lastVerifyResponseJson: String? = null
    var lastVerifyChallengeJson: String? = null
    var verifyResult = ""

    override fun scpidChallenge(
        audience: String,
        ttlSeconds: Long,
    ): String {
        challengeCalled = true
        lastChallengeAudience = audience
        lastChallengeTtlSeconds = ttlSeconds
        return challengeResult
    }

    override fun scpidSign(
        identityHandle: Long,
        signingKeyId: String,
        challengeJson: String,
    ): String {
        signCalled = true
        lastSignIdentityHandle = identityHandle
        lastSignKeyId = signingKeyId
        lastSignChallengeJson = challengeJson
        return signResult
    }

    override fun scpidVerify(
        responseJson: String,
        challengeJson: String,
    ): String {
        verifyCalled = true
        lastVerifyResponseJson = responseJson
        lastVerifyChallengeJson = challengeJson
        return verifyResult
    }
}
