/**
 * AndroidPushProvider — FCM token retrieval and wake-signal handling for data-only payloads.
 *
 * This file implements the [PushProvider] interface for Android using Firebase Cloud
 * Messaging (FCM). It is one of the four platform providers assembled by
 * `AndroidPlatformAdapter` (ADR-027). No code passes it to the Rust engine, because the
 * UniFFI bridge has no function that accepts a push provider.
 *
 * ## FCM Payload Opacity (§10.7)
 *
 * §10.7 requires a push payload to carry only a wake signal: no sender, no context, no
 * count, no preview. Its §10.7.1 step 5 gives that payload as `{ "scp": 1 }`. ADR-027
 * carries the wake signal to Android as the FCM data-only message `{"data": {"scp": "1"}}`,
 * with no notification fields and no other SCP-specific content, so FCM learns only that
 * the device received a data message at a specific time. No relay or other code in this
 * repository sends an FCM message. When one arrives, FCM starts the app if it is not
 * running (Android delivers nothing to an app the user force-stopped) and delivers the
 * message to `FirebaseMessagingService.onMessageReceived`, where the caller passes its
 * data to [handleNotification]. No SDK code connects to a relay or pulls envelopes on a
 * push: the caller does both when [handleNotification] returns [WakeSignal.PULL].
 *
 * [handleNotification] checks only the `scp` field. It rejects a payload that lacks the
 * field with [ScpException] code `SCP-TRANS-5001`, and a payload whose field is not
 * `"1"` with code `SCP-TRANS-5002`. It accepts a payload that carries other fields
 * beside `"scp": "1"` and returns the same [WakeSignal.PULL] for it, reading nothing
 * else from the payload.
 *
 * Opacity is an obligation on the sender: §10.7.1 step 5 has the relay send exactly
 * `{ "scp": 1 }`. FCM has already carried every field of a payload before
 * [handleNotification] sees it, so no check in this class can keep a field from FCM. No
 * code in this repository sends a push, so no code meets the sender obligation. SCP-112's
 * criterion "FCM payload format is opaque" is unmet because no sender exists; rejecting
 * extra fields in [handleNotification] would not meet it.
 *
 * ## Token Registration Lifecycle
 *
 * FCM token registration is asynchronous. [register] retrieves the current FCM
 * registration token via `FirebaseMessaging.getInstance().token.await()` on
 * [Dispatchers.IO][kotlinx.coroutines.Dispatchers.IO]. The token may change over
 * time (e.g., app data cleared, app restored on new device). [register] only returns the
 * token; it sends nothing to a relay. §10.7.1 requires the client to send its relays a new
 * `PushRegistration` carrying the new token when the token changes, and no SDK code builds
 * or sends a `PushRegistration` or calls [register] again when the token changes.
 *
 * ## Thread Safety
 *
 * All suspend functions dispatch to [Dispatchers.IO][kotlinx.coroutines.Dispatchers.IO].
 * [handleNotification] is a synchronous function safe to call from any thread,
 * including the FCM `onMessageReceived` callback thread.
 *
 * See ADR-027 (Android Platform Adapter), ADR-021 (UniFFI Bridge), and §10.7.
 */

package works.limn.scp.android.platform

import android.content.Context
import com.google.firebase.messaging.FirebaseMessaging
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.withContext

/**
 * [PushProvider] implementation for Android using Firebase Cloud Messaging.
 *
 * Retrieves the FCM registration token and checks the `scp` field of incoming data-only
 * push payloads. ADR-027 carries §10.7's wake signal as the FCM data-only message
 * `{"data": {"scp": "1"}}`; [handleNotification] rejects a missing or wrong `scp` field and
 * accepts any other fields beside it.
 *
 * @param context Android application [Context]. The class does not read it and does not
 *   initialise Firebase: [register] calls `FirebaseMessaging.getInstance()`, which uses the
 *   default FirebaseApp, so the default FirebaseApp must be initialised before [register]
 *   runs. FirebaseInitProvider does this at app start when the app carries its Firebase
 *   configuration; otherwise the caller calls `FirebaseApp.initializeApp`.
 *   Callers should pass the application context to avoid activity lifecycle leaks.
 *
 * ## Usage
 *
 * ```kotlin
 * val pushProvider = AndroidPushProvider(applicationContext)
 *
 * // Fetch the FCM token. No SDK code sends the §10.7.1 PushRegistration yet; SCP-112 tracks it.
 * val token = pushProvider.register()
 *
 * // In FirebaseMessagingService.onMessageReceived:
 * val signal = pushProvider.handleNotification(remoteMessage.data)
 * // signal == WakeSignal.PULL → connect to relay and pull envelopes
 * ```
 *
 * See ADR-027 (Android Platform Adapter).
 */
class AndroidPushProvider(
    @Suppress("unused") private val context: Context
) : PushProvider {

    /**
     * Return the current FCM registration token. The method sends nothing to a relay; see
     * the file header for the §10.7.1 `PushRegistration` that no SDK code sends.
     *
     * Retrieves the current FCM instance token on [Dispatchers.IO]. A push sender
     * addresses FCM data messages to this device by the token; no sender in this
     * repository does so.
     *
     * @return The FCM registration token string.
     * @throws IllegalStateException from `FirebaseMessaging.getInstance()` if Firebase is
     *   not initialised. The method converts no failure to [ScpException].
     * @throws Exception whatever exception the FCM token task failed with, rethrown by
     *   `await()` unconverted.
     */
    override suspend fun register(): String {
        return withContext(Dispatchers.IO) {
            FirebaseMessaging.getInstance().token.await()
        }
    }

    /**
     * Handle an incoming FCM data-only push notification.
     *
     * Checks only the `scp` field: it must be present with value `"1"`. The method
     * neither checks nor reads any other field, so it accepts a payload that carries
     * other fields beside `"scp": "1"` and returns the same [WakeSignal.PULL] for it.
     * §10.7 opacity is the sender's obligation (§10.7.1 step 5): FCM has carried every
     * field before this method runs.
     *
     * @param payload The FCM data payload as a key-value map (from
     *   `RemoteMessage.getData()`). Expected: `{"scp": "1"}`.
     * @return [WakeSignal.PULL] — tells the caller to connect to the relay
     *   and pull all pending encrypted envelopes.
     * @throws ScpException with code `SCP-TRANS-5001` if the `scp` field is missing.
     * @throws ScpException with code `SCP-TRANS-5002` if the `scp` field has an
     *   unexpected value.
     */
    override fun handleNotification(payload: Map<String, String>): WakeSignal {
        // ADR-027's FCM data payload is {"scp": "1"}; the value "1" is the wake signal.
        // Only this field is checked or read; any other field passes unexamined.
        val scpField = payload["scp"]
            ?: throw ScpException(
                "FCM payload missing 'scp' field",
                "SCP-TRANS-5001"
            )
        if (scpField != "1") {
            throw ScpException(
                "FCM payload 'scp' field has unexpected value: $scpField",
                "SCP-TRANS-5002"
            )
        }
        return WakeSignal.PULL // connect to relay and pull pending envelopes
    }
}

// ADR-027 gives a push sender this FCM message structure — opaque, data-only.
// No code in this repository sends it:
// {
//   "to": "<fcm_token>",
//   "data": {
//     "scp": "1"
//   }
// }
// No "notification" key. No content visible to Android notification shade.
