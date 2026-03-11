/**
 * AndroidPushProvider — FCM push notification registration with opaque data-only payloads.
 *
 * This file implements the [PushProvider] interface for Android using Firebase Cloud
 * Messaging (FCM). It is one of the four platform providers assembled by
 * `AndroidPlatformAdapter` (ADR-027) and injected into the Rust engine at SDK
 * initialisation.
 *
 * ## FCM Payload Opacity (§10.7)
 *
 * The relay sends **only** `{"data": {"scp": "1"}}` — a data-only message with no
 * notification fields. No context ID, sender DID, message preview, or any other
 * metadata may appear in the FCM payload. The app wakes, connects to the SCP relay,
 * and pulls all pending encrypted envelopes. FCM learns only that the device
 * received a data message at a specific time.
 *
 * [handleNotification] **enforces** this invariant on receipt: payloads missing the
 * `scp` field or containing an unexpected value are rejected with [ScpException]
 * error codes `SCP-TRANS-5001` and `SCP-TRANS-5002` respectively.
 *
 * ## Token Registration Lifecycle
 *
 * FCM token registration is asynchronous. [register] retrieves the current FCM
 * registration token via `FirebaseMessaging.getInstance().token.await()` on
 * [Dispatchers.IO][kotlinx.coroutines.Dispatchers.IO]. The token may change over
 * time (e.g., app data cleared, app restored on new device); the SCP engine handles
 * token refresh by re-calling [register] when notified of a change.
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
 * Handles FCM token registration and validates incoming data-only push payloads
 * against the §10.7 opacity requirement. The relay sends `{"data": {"scp": "1"}}`
 * as the sole push payload format; any deviation is rejected.
 *
 * @param context Android application [Context], used for Firebase initialisation.
 *   Callers should pass the application context to avoid activity lifecycle leaks.
 *
 * ## Usage
 *
 * ```kotlin
 * val pushProvider = AndroidPushProvider(applicationContext)
 *
 * // Register for push notifications
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
     * Register for FCM push notifications and return the registration token.
     *
     * Retrieves the current FCM instance token on [Dispatchers.IO]. The token
     * is a server-side identifier that the SCP relay uses to target data-only
     * push messages to this device.
     *
     * @return The FCM registration token string.
     * @throws ScpException if Firebase is not initialised or token retrieval fails.
     */
    override suspend fun register(): String {
        return withContext(Dispatchers.IO) {
            FirebaseMessaging.getInstance().token.await()
        }
    }

    /**
     * Handle an incoming FCM data-only push notification.
     *
     * Validates that the payload conforms to the opaque format required by §10.7:
     * the `scp` field must be present with value `"1"`. No context ID, sender DID,
     * or message content is present in or extracted from the payload.
     *
     * @param payload The FCM data payload as a key-value map (from
     *   `RemoteMessage.getData()`). Expected: `{"scp": "1"}`.
     * @return [WakeSignal.PULL] — instructs the engine to connect to the relay
     *   and pull all pending encrypted envelopes.
     * @throws ScpException with code `SCP-TRANS-5001` if the `scp` field is missing.
     * @throws ScpException with code `SCP-TRANS-5002` if the `scp` field has an
     *   unexpected value.
     */
    override fun handleNotification(payload: Map<String, String>): WakeSignal {
        // FCM data payload: {"scp": "1"}
        // The value "1" is the wake signal. No context ID or sender information is present.
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

// Relay sends this FCM message structure — opaque, data-only:
// {
//   "to": "<fcm_token>",
//   "data": {
//     "scp": "1"
//   }
// }
// No "notification" key. No content visible to Android notification shade.
