/**
 * Unit tests for [AndroidPushProvider].
 *
 * Tests cover the [AndroidPushProvider.handleNotification] logic — payload
 * validation, wake signal generation, and error code correctness. The
 * [AndroidPushProvider.register] method requires a live Firebase instance and
 * is tested via integration tests (instrumented tests on a real or emulated
 * Android device).
 *
 * See ADR-027 (Android Platform Adapter) and §10.7 (push payload opacity).
 */

package works.limn.scp.android.platform

import android.content.Context
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals

class AndroidPushProviderTest {

    private lateinit var provider: AndroidPushProvider

    @BeforeEach
    fun setUp() {
        // handleNotification() is a pure function that does not use the Android
        // Context. An unsafe null cast works at the JVM level for unit tests.
        // Integration tests on a real device should use an actual Context.
        provider = AndroidPushProvider(
            @Suppress("CAST_NEVER_SUCCEEDS")
            (null as Any?) as Context
        )
    }

    // -----------------------------------------------------------------------
    // Valid payload tests
    // -----------------------------------------------------------------------

    @Test
    fun `valid scp payload returns WakeSignal Pull`() {
        val payload = mapOf("scp" to "1")
        val signal = provider.handleNotification(payload)
        assertEquals(WakeSignal.PULL, signal)
    }

    @Test
    fun `valid scp payload with only scp field returns Pull`() {
        // The opaque payload format: {"scp": "1"} — exactly one field.
        val payload = mapOf("scp" to "1")
        val signal = provider.handleNotification(payload)
        assertEquals(WakeSignal.PULL, signal)
    }

    // -----------------------------------------------------------------------
    // Missing field tests — error code SCP-TRANS-5001
    // -----------------------------------------------------------------------

    @Test
    fun `empty payload throws ScpException with code SCP-TRANS-5001`() {
        val payload = emptyMap<String, String>()
        val exception = assertThrows<ScpException> {
            provider.handleNotification(payload)
        }
        assertEquals("SCP-TRANS-5001", exception.code)
        assertEquals("FCM payload missing 'scp' field", exception.message)
    }

    @Test
    fun `payload without scp field throws ScpException with code SCP-TRANS-5001`() {
        val payload = mapOf("other" to "value")
        val exception = assertThrows<ScpException> {
            provider.handleNotification(payload)
        }
        assertEquals("SCP-TRANS-5001", exception.code)
    }

    @Test
    fun `payload with wrong key name throws ScpException with code SCP-TRANS-5001`() {
        // Case-sensitive: "SCP" is not "scp"
        val payload = mapOf("SCP" to "1")
        val exception = assertThrows<ScpException> {
            provider.handleNotification(payload)
        }
        assertEquals("SCP-TRANS-5001", exception.code)
    }

    // -----------------------------------------------------------------------
    // Unexpected value tests — error code SCP-TRANS-5002
    // -----------------------------------------------------------------------

    @Test
    fun `scp field with value 0 throws ScpException with code SCP-TRANS-5002`() {
        val payload = mapOf("scp" to "0")
        val exception = assertThrows<ScpException> {
            provider.handleNotification(payload)
        }
        assertEquals("SCP-TRANS-5002", exception.code)
        assertEquals("FCM payload 'scp' field has unexpected value: 0", exception.message)
    }

    @Test
    fun `scp field with value 2 throws ScpException with code SCP-TRANS-5002`() {
        val payload = mapOf("scp" to "2")
        val exception = assertThrows<ScpException> {
            provider.handleNotification(payload)
        }
        assertEquals("SCP-TRANS-5002", exception.code)
    }

    @Test
    fun `scp field with empty value throws ScpException with code SCP-TRANS-5002`() {
        val payload = mapOf("scp" to "")
        val exception = assertThrows<ScpException> {
            provider.handleNotification(payload)
        }
        assertEquals("SCP-TRANS-5002", exception.code)
    }

    @Test
    fun `scp field with arbitrary string throws ScpException with code SCP-TRANS-5002`() {
        val payload = mapOf("scp" to "wake")
        val exception = assertThrows<ScpException> {
            provider.handleNotification(payload)
        }
        assertEquals("SCP-TRANS-5002", exception.code)
        assertEquals("FCM payload 'scp' field has unexpected value: wake", exception.message)
    }

    @Test
    fun `scp field with whitespace-padded value throws ScpException with code SCP-TRANS-5002`() {
        // "1 " is not "1"
        val payload = mapOf("scp" to " 1")
        val exception = assertThrows<ScpException> {
            provider.handleNotification(payload)
        }
        assertEquals("SCP-TRANS-5002", exception.code)
    }

    // -----------------------------------------------------------------------
    // Type and interface tests
    // -----------------------------------------------------------------------

    @Test
    fun `WakeSignal Pull is the only valid signal for opaque payloads`() {
        // §10.7: opaque push payloads carry no context information.
        // The only valid response is Pull (fetch all pending envelopes).
        assertEquals(1, WakeSignal.entries.size)
        assertEquals(WakeSignal.PULL, WakeSignal.entries.first())
    }

    @Test
    fun `ScpException carries both message and code`() {
        val exception = ScpException("test message", "SCP-CTX-2999")
        assertEquals("test message", exception.message)
        assertEquals("SCP-CTX-2999", exception.code)
    }

    @Test
    fun `ScpException extends Exception`() {
        val exception: Exception = ScpException("test", "SCP-CTX-2999")
        assertEquals("test", exception.message)
    }

    // -----------------------------------------------------------------------
    // Payload with extra fields — still valid per FCM data message format
    // -----------------------------------------------------------------------

    @Test
    fun `payload with scp field and extra fields still returns Pull`() {
        // FCM data messages may contain additional fields from the relay.
        // As long as "scp" == "1", the handler accepts it. The opacity
        // requirement (§10.7) is enforced at the relay side — the client
        // validates only the wake signal field.
        val payload = mapOf("scp" to "1", "extra" to "ignored")
        val signal = provider.handleNotification(payload)
        assertEquals(WakeSignal.PULL, signal)
    }
}
