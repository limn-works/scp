/**
 * Unit tests for [AndroidPushProvider].
 *
 * Tests cover the [AndroidPushProvider.handleNotification] logic — payload
 * validation, wake signal generation, and error code correctness. The
 * [AndroidPushProvider.register] method requires a live Firebase instance,
 * and the module has no instrumented tests, so no test covers it.
 *
 * See ADR-027 (Android Platform Adapter) and §10.7 (push payload opacity).
 */

package works.limn.scp.android.platform

import androidx.test.core.app.ApplicationProvider
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

// AndroidPushProvider takes a non-null Context. Kotlin checks the cast
// `null as Context` at runtime and throws NullPointerException, so these tests
// run under Robolectric, which supplies an application Context on the host JVM.
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE, sdk = [35])
class AndroidPushProviderTest {

    private lateinit var provider: AndroidPushProvider

    @Before
    fun setUp() {
        provider = AndroidPushProvider(ApplicationProvider.getApplicationContext())
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
        val exception = assertFailsWith<ScpException> {
            provider.handleNotification(payload)
        }
        assertEquals("SCP-TRANS-5001", exception.code)
        assertEquals("FCM payload missing 'scp' field", exception.message)
    }

    @Test
    fun `payload without scp field throws ScpException with code SCP-TRANS-5001`() {
        val payload = mapOf("other" to "value")
        val exception = assertFailsWith<ScpException> {
            provider.handleNotification(payload)
        }
        assertEquals("SCP-TRANS-5001", exception.code)
    }

    @Test
    fun `payload with wrong key name throws ScpException with code SCP-TRANS-5001`() {
        // Case-sensitive: "SCP" is not "scp"
        val payload = mapOf("SCP" to "1")
        val exception = assertFailsWith<ScpException> {
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
        val exception = assertFailsWith<ScpException> {
            provider.handleNotification(payload)
        }
        assertEquals("SCP-TRANS-5002", exception.code)
        assertEquals("FCM payload 'scp' field has unexpected value: 0", exception.message)
    }

    @Test
    fun `scp field with value 2 throws ScpException with code SCP-TRANS-5002`() {
        val payload = mapOf("scp" to "2")
        val exception = assertFailsWith<ScpException> {
            provider.handleNotification(payload)
        }
        assertEquals("SCP-TRANS-5002", exception.code)
    }

    @Test
    fun `scp field with empty value throws ScpException with code SCP-TRANS-5002`() {
        val payload = mapOf("scp" to "")
        val exception = assertFailsWith<ScpException> {
            provider.handleNotification(payload)
        }
        assertEquals("SCP-TRANS-5002", exception.code)
    }

    @Test
    fun `scp field with arbitrary string throws ScpException with code SCP-TRANS-5002`() {
        val payload = mapOf("scp" to "wake")
        val exception = assertFailsWith<ScpException> {
            provider.handleNotification(payload)
        }
        assertEquals("SCP-TRANS-5002", exception.code)
        assertEquals("FCM payload 'scp' field has unexpected value: wake", exception.message)
    }

    @Test
    fun `scp field with whitespace-padded value throws ScpException with code SCP-TRANS-5002`() {
        // "1 " is not "1"
        val payload = mapOf("scp" to " 1")
        val exception = assertFailsWith<ScpException> {
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
        // As long as "scp" == "1", the handler accepts a payload with other
        // fields. §10.7 puts the opacity requirement on the push sender;
        // handleNotification checks only the wake signal field and does not
        // enforce opacity.
        val payload = mapOf("scp" to "1", "extra" to "ignored")
        val signal = provider.handleNotification(payload)
        assertEquals(WakeSignal.PULL, signal)
    }
}
