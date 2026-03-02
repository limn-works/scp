package com.limn.scp.android.platform

import android.content.Context
import android.util.Base64
import android.util.Log
import com.google.android.gms.common.api.ApiException
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.withContext
import java.security.MessageDigest

/**
 * Android implementation of [DeviceAttestationProvider] using the Play Integrity
 * Standard API.
 *
 * ## Play Integrity Standard API
 *
 * Standard integrity requests return a verdict signed by Google's servers,
 * sufficient for SCP's attestation purpose. Classic attestation (APK certificate
 * chain) is not used -- it requires a dedicated Google Play Developer API call per
 * attestation with stricter rate limits and is designed for offline scenarios SCP
 * does not have. Standard is lower-cost, lower-latency, and simpler.
 *
 * ## Attestation flow (per ADR-027)
 *
 * 1. Construct `clientDataJSON` from the challenge, device ID, and attestation type.
 * 2. Compute `nonce = Base64(SHA-256(clientDataJSON))`.
 * 3. Request a standard integrity token from Play Integrity with the nonce.
 * 4. Return the integrity token JWT bytes for server-side verification.
 *
 * ## Thread safety
 *
 * All I/O operations run on [Dispatchers.IO] via [withContext]. The class holds
 * no mutable state and is safe for concurrent use.
 *
 * ## Server-side verification
 *
 * The returned integrity token is a JWT that must be verified server-side via
 * the Google Play Integrity API. The relay reconstructs the `clientDataJSON`
 * with the same fixed-field-order formula to verify the nonce embedded in the
 * integrity token.
 *
 * See ADR-027 in `.docs/adrs/phase-6.md` and `crates/scp-ffi/uniffi/src/lib.rs`
 * `DeviceAttestationProvider`.
 *
 * @param context Android application [Context] required by
 *   [IntegrityManagerFactory.create].
 */
class AndroidDeviceAttestation(private val context: Context) : DeviceAttestationProvider {

    /**
     * Generate an attestation token for the given challenge and device ID.
     *
     * Constructs a deterministic `clientDataJSON` with fixed field order:
     * `{"challenge":"<b64>","deviceId":"<b64>","type":"scp-device-attestation-v1"}`.
     * The nonce is `Base64(SHA-256(clientDataJSON))`. A Play Integrity Standard
     * token is requested with this nonce and returned as UTF-8 encoded JWT bytes.
     *
     * The relay reconstructs this JSON with the same fixed-field-order formula
     * to verify the nonce embedded in the integrity token.
     *
     * @param challenge Server-issued random challenge bytes.
     * @param deviceId Stable device/identity identifier bytes.
     * @return Play Integrity token bytes (JWT, UTF-8 encoded).
     * @throws ScpException if the Play Integrity API call fails.
     */
    override suspend fun attest(challenge: ByteArray, deviceId: ByteArray): ByteArray {
        val clientDataJSON = buildClientDataJSON(challenge, deviceId)
        val nonce = computeNonce(clientDataJSON)

        val integrityTokenResponse = try {
            withContext(Dispatchers.IO) {
                IntegrityManagerFactory.create(context)
                    .requestIntegrityToken(
                        IntegrityTokenRequest.builder()
                            .setNonce(nonce)
                            .build()
                    )
                    .await()
            }
        } catch (e: ApiException) {
            // Known Play Integrity API error — status code is a documented public
            // constant (API_NOT_AVAILABLE, INTEGRITY_TOKEN_PROVIDER_INVALID, etc.).
            // Preserve the original exception as cause for diagnostic context.
            throw ScpException(
                "Play Integrity token request failed: status ${e.statusCode}",
                CODE_ATTESTATION_FAILED,
                e
            )
        } catch (e: SecurityException) {
            // Permission or security policy violation during Play Integrity call.
            Log.e(TAG, "Security error during Play Integrity request", e)
            throw ScpException(
                "Play Integrity token request failed",
                CODE_ATTESTATION_FAILED,
                e
            )
        } catch (e: IllegalStateException) {
            // IntegrityManager used in invalid state (e.g., context destroyed).
            Log.e(TAG, "Illegal state during Play Integrity request", e)
            throw ScpException(
                "Play Integrity token request failed",
                CODE_ATTESTATION_FAILED,
                e
            )
        }

        // Return the integrity token (JWT) for server-side verification
        return integrityTokenResponse.token().toByteArray(Charsets.UTF_8)
    }

    /**
     * Generate a per-request assertion using a fresh integrity token.
     *
     * Play Integrity does not have a per-request assertion flow equivalent to
     * Apple App Attest assertions. For assertion-equivalent use cases, a fresh
     * Standard integrity token is requested with the request hash as the
     * challenge and an empty device ID.
     *
     * @param requestHash SHA-256 hash of the request data being asserted.
     * @return Play Integrity token bytes (JWT, UTF-8 encoded).
     * @throws ScpException if the Play Integrity API call fails.
     */
    override suspend fun assertRequest(requestHash: ByteArray): ByteArray {
        // Play Integrity does not have a per-request assertion flow equivalent
        // to App Attest assertions. For assertion-equivalent use cases, a fresh
        // Standard integrity token is requested.
        return attest(challenge = requestHash, deviceId = ByteArray(0))
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /**
     * Build the deterministic clientDataJSON string.
     *
     * Field order is fixed to ensure cross-platform determinism:
     * `{"challenge":"<b64>","deviceId":"<b64>","type":"scp-device-attestation-v1"}`
     *
     * Uses [Base64.NO_WRAP] for single-line Base64 encoding (no line breaks).
     */
    internal fun buildClientDataJSON(challenge: ByteArray, deviceId: ByteArray): String {
        val challengeB64 = Base64.encodeToString(challenge, Base64.NO_WRAP)
        val deviceIdB64 = Base64.encodeToString(deviceId, Base64.NO_WRAP)
        return "{\"challenge\":\"$challengeB64\",\"deviceId\":\"$deviceIdB64\",\"type\":\"$ATTESTATION_TYPE\"}"
    }

    /**
     * Compute the nonce for the integrity token request.
     *
     * `nonce = Base64(SHA-256(clientDataJSON.toByteArray(UTF-8)))`
     *
     * Uses [Base64.NO_WRAP] for single-line Base64 encoding.
     */
    internal fun computeNonce(clientDataJSON: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(clientDataJSON.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(digest, Base64.NO_WRAP)
    }

    companion object {
        private const val TAG = "AndroidDeviceAttestation"

        /** Attestation type field value for clientDataJSON. */
        const val ATTESTATION_TYPE = "scp-device-attestation-v1"

        /** Error code for Play Integrity attestation failure. */
        internal const val CODE_ATTESTATION_FAILED = "SCP-ATTEST-9001"
    }
}
