package works.limn.scp.android.platform

import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.MessageDigest

// ---------------------------------------------------------------------------
// Unit tests for AndroidDeviceAttestation
// ---------------------------------------------------------------------------
//
// Play Integrity API calls need Google Play services, which the host JVM lacks.
// ADR-027 acceptance criterion 13 runs hardware tests on an API 33+ physical
// device or on an API 33 emulator with Play Store. These tests cover the
// deterministic, locally-testable parts of the attestation flow:
//   - clientDataJSON construction (fixed field order, Base64 encoding)
//   - Nonce computation (SHA-256 + Base64)
//
// No test covers the Play Integrity request, `attest` end to end, or
// `assertRequest`: each calls the Play Integrity API, which only an
// instrumented test on such a device or emulator can reach, and the module has
// no instrumented tests.
// Story SCP-111's criterion for end-to-end tests on a physical device is unmet.
//
// Uses Robolectric to provide android.util.Base64 on the host JVM.

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE, sdk = [35])
class AndroidDeviceAttestationTest {

    // -----------------------------------------------------------------------
    // clientDataJSON construction
    // -----------------------------------------------------------------------

    @Test
    fun `buildClientDataJSON produces deterministic fixed-order JSON`() {
        // Given: known challenge and device ID bytes
        val challenge = "test-challenge".toByteArray(Charsets.UTF_8)
        val deviceId = "test-device-id".toByteArray(Charsets.UTF_8)

        // When: building clientDataJSON twice with same inputs
        val attestation = createAttestationWithMockContext()
        val json1 = attestation.buildClientDataJSON(challenge, deviceId)
        val json2 = attestation.buildClientDataJSON(challenge, deviceId)

        // Then: output is identical (deterministic)
        assertEquals(json1, json2)

        // And: JSON has the correct fixed field order
        assertTrue(json1.startsWith("{\"challenge\":\""))
        assertTrue(json1.contains("\",\"deviceId\":\""))
        assertTrue(json1.endsWith("\",\"type\":\"scp-device-attestation-v1\"}"))
    }

    @Test
    fun `buildClientDataJSON encodes challenge and deviceId as Base64`() {
        val challenge = byteArrayOf(0x01, 0x02, 0x03)
        val deviceId = byteArrayOf(0x04, 0x05, 0x06)

        val attestation = createAttestationWithMockContext()
        val json = attestation.buildClientDataJSON(challenge, deviceId)

        // Base64 of [0x01, 0x02, 0x03] with NO_WRAP = "AQID"
        // Base64 of [0x04, 0x05, 0x06] with NO_WRAP = "BAUG"
        val expectedChallengeB64 = Base64.encodeToString(challenge, Base64.NO_WRAP)
        val expectedDeviceIdB64 = Base64.encodeToString(deviceId, Base64.NO_WRAP)

        val expected = "{\"challenge\":\"$expectedChallengeB64\"," +
            "\"deviceId\":\"$expectedDeviceIdB64\"," +
            "\"type\":\"scp-device-attestation-v1\"}"
        assertEquals(expected, json)
    }

    @Test
    fun `buildClientDataJSON handles empty byte arrays`() {
        val attestation = createAttestationWithMockContext()
        val json = attestation.buildClientDataJSON(ByteArray(0), ByteArray(0))

        // Empty byte array Base64 is ""
        val emptyB64 = Base64.encodeToString(ByteArray(0), Base64.NO_WRAP)
        val expected = "{\"challenge\":\"$emptyB64\"," +
            "\"deviceId\":\"$emptyB64\"," +
            "\"type\":\"scp-device-attestation-v1\"}"
        assertEquals(expected, json)
    }

    @Test
    fun `buildClientDataJSON includes type field scp-device-attestation-v1`() {
        val attestation = createAttestationWithMockContext()
        val json = attestation.buildClientDataJSON(
            "c".toByteArray(Charsets.UTF_8),
            "d".toByteArray(Charsets.UTF_8)
        )

        assertTrue(json.contains("\"type\":\"scp-device-attestation-v1\""))
    }

    // -----------------------------------------------------------------------
    // Nonce computation
    // -----------------------------------------------------------------------

    @Test
    fun `computeNonce produces SHA-256 then Base64 of clientDataJSON`() {
        val attestation = createAttestationWithMockContext()
        val clientDataJSON = "{\"challenge\":\"dGVzdA==\",\"deviceId\":\"ZGV2\",\"type\":\"scp-device-attestation-v1\"}"

        val nonce = attestation.computeNonce(clientDataJSON)

        // Manually compute expected: Base64(SHA-256(clientDataJSON.UTF8))
        val sha256 = MessageDigest.getInstance("SHA-256")
            .digest(clientDataJSON.toByteArray(Charsets.UTF_8))
        val expectedNonce = Base64.encodeToString(sha256, Base64.NO_WRAP)

        assertEquals(expectedNonce, nonce)
    }

    @Test
    fun `computeNonce is deterministic for same input`() {
        val attestation = createAttestationWithMockContext()
        val clientDataJSON = "some-fixed-input"

        val nonce1 = attestation.computeNonce(clientDataJSON)
        val nonce2 = attestation.computeNonce(clientDataJSON)

        assertEquals(nonce1, nonce2)
    }

    @Test
    fun `computeNonce differs for different inputs`() {
        val attestation = createAttestationWithMockContext()

        val nonce1 = attestation.computeNonce("input-a")
        val nonce2 = attestation.computeNonce("input-b")

        assertNotEquals(nonce1, nonce2)
    }

    @Test
    fun `computeNonce output is valid Base64`() {
        val attestation = createAttestationWithMockContext()
        val nonce = attestation.computeNonce("test-input")

        // Decode should not throw and should produce 32 bytes (SHA-256 output)
        val decoded = Base64.decode(nonce, Base64.NO_WRAP)
        assertEquals(32, decoded.size)
    }

    // -----------------------------------------------------------------------
    // Full nonce pipeline (buildClientDataJSON -> computeNonce)
    // -----------------------------------------------------------------------

    @Test
    fun `full nonce pipeline produces consistent results`() {
        val attestation = createAttestationWithMockContext()
        val challenge = "server-challenge".toByteArray(Charsets.UTF_8)
        val deviceId = "device-123".toByteArray(Charsets.UTF_8)

        val json = attestation.buildClientDataJSON(challenge, deviceId)
        val nonce = attestation.computeNonce(json)

        // Run the same pipeline again
        val json2 = attestation.buildClientDataJSON(challenge, deviceId)
        val nonce2 = attestation.computeNonce(json2)

        assertEquals(json, json2)
        assertEquals(nonce, nonce2)
    }

    @Test
    fun `nonce changes when challenge changes`() {
        val attestation = createAttestationWithMockContext()
        val deviceId = "device-123".toByteArray(Charsets.UTF_8)

        val json1 = attestation.buildClientDataJSON("challenge-a".toByteArray(), deviceId)
        val json2 = attestation.buildClientDataJSON("challenge-b".toByteArray(), deviceId)

        assertNotEquals(json1, json2)
        assertNotEquals(
            attestation.computeNonce(json1),
            attestation.computeNonce(json2)
        )
    }

    @Test
    fun `nonce changes when deviceId changes`() {
        val attestation = createAttestationWithMockContext()
        val challenge = "challenge".toByteArray(Charsets.UTF_8)

        val json1 = attestation.buildClientDataJSON(challenge, "device-a".toByteArray())
        val json2 = attestation.buildClientDataJSON(challenge, "device-b".toByteArray())

        assertNotEquals(json1, json2)
        assertNotEquals(
            attestation.computeNonce(json1),
            attestation.computeNonce(json2)
        )
    }

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    @Test
    fun `ATTESTATION_TYPE constant holds the legacy clientDataJSON type value`() {
        // Spec 27 quotes "scp-device-attestation-v1" only as part of the
        // clientDataJSON construction that the 2026-09-27 amendments to
        // ADR-025 and ADR-027 replaced; no normative text requires it.
        assertEquals("scp-device-attestation-v1", AndroidDeviceAttestation.ATTESTATION_TYPE)
    }

    @Test
    fun `error code is correctly defined`() {
        assertEquals("SCP-ATTEST-9001", AndroidDeviceAttestation.CODE_ATTESTATION_FAILED)
    }

    // -----------------------------------------------------------------------
    // ScpException error structure
    // -----------------------------------------------------------------------

    @Test
    fun `ScpException carries message and code`() {
        val exception = ScpException("test message", "SCP-ATTEST-9999")
        assertEquals("test message", exception.message)
        assertEquals("SCP-ATTEST-9999", exception.code)
    }

    @Test
    fun `ScpException is an Exception subclass`() {
        val exception = ScpException("msg", "SCP-ATTEST-9998")
        assertTrue(exception is Exception)
    }

    // -----------------------------------------------------------------------
    // Legacy clientDataJSON field order
    // -----------------------------------------------------------------------

    @Test
    fun `clientDataJSON fields appear in the fixed order challenge then deviceId then type`() {
        // Android formula: {"challenge":"<b64>","deviceId":"<b64>","type":"scp-device-attestation-v1"}
        //
        // This test pins the legacy clientDataJSON behaviour of the shipped
        // adapter. ADR-027 acceptance criterion 7, as its 2026-09-27 amendment
        // states it, replaced this JSON with requestHash = hex(D), where D is
        // the binding digest of 09-security-model.md section 9.3.1; story
        // SCP-111 carries that change. OQ-22 of spec 27 keeps two questions
        // open: which of the two device-attestation traits is normative, and
        // whether that trait's attest takes D or D's two inputs (a challenge
        // and an identifier).
        val attestation = createAttestationWithMockContext()
        val json = attestation.buildClientDataJSON(
            byteArrayOf(1, 2, 3),
            byteArrayOf(4, 5, 6)
        )

        // Parse field positions to verify order
        val challengeIdx = json.indexOf("\"challenge\"")
        val deviceIdIdx = json.indexOf("\"deviceId\"")
        val typeIdx = json.indexOf("\"type\"")

        assertTrue("challenge field must appear", challengeIdx >= 0)
        assertTrue("challenge must come before deviceId", challengeIdx < deviceIdIdx)
        assertTrue("deviceId must come before type", deviceIdIdx < typeIdx)
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * Create an [AndroidDeviceAttestation] with a Robolectric application context.
     *
     * The [android.content.Context] parameter is only used by
     * [IntegrityManagerFactory.create] during actual Play Integrity calls.
     * For testing deterministic helpers (buildClientDataJSON, computeNonce),
     * a Robolectric context is sufficient since those methods never touch it.
     */
    private fun createAttestationWithMockContext(): AndroidDeviceAttestation {
        return AndroidDeviceAttestation(ApplicationProvider.getApplicationContext())
    }
}
