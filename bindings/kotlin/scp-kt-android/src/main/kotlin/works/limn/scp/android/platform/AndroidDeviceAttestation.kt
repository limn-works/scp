package works.limn.scp.android.platform

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
 * Android implementation of [DeviceAttestationProvider] using Play Integrity.
 *
 * ## Classic request, Standard required
 *
 * This adapter requests a Classic Play Integrity token: it passes a nonce
 * through `IntegrityTokenRequest.builder().setNonce(nonce)`. ADR-027's
 * 2026-09-27 amendment requires a Standard integrity request whose
 * `requestHash` is the lowercase hexadecimal form of the binding digest `D`,
 * and story SCP-111 tracks that change.
 *
 * ## Attestation flow as shipped
 *
 * 1. Construct `clientDataJSON` from the challenge, device ID, and attestation type.
 * 2. Compute `nonce = Base64(SHA-256(clientDataJSON))`.
 * 3. Request a Classic integrity token from Play Integrity with the nonce.
 * 4. Return the integrity token JWT bytes.
 *
 * ## Thread safety
 *
 * All I/O operations run on [Dispatchers.IO] via [withContext]. The class holds
 * no mutable state and is safe for concurrent use.
 *
 * ## Verification
 *
 * Google decodes an integrity token only for the Cloud project linked to the
 * requesting app. ADR-027's 2026-09-27 amendment requires the package's
 * verifier, named in the context's `accepted_android_packages`, to decode the
 * token and sign a verdict, and requires each reader to check that verdict.
 * §9.3.1 of `09-security-model.md` defines the procedure. No code implements
 * the verifier, the producer that publishes the token and verdict, or the
 * reader yet: story SCP-318 tracks the reference verifier, SCP-317 the
 * producer, and SCP-316 the reader.
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
     * The nonce is `Base64(SHA-256(clientDataJSON))`. The adapter requests a
     * Classic Play Integrity token with this nonce and returns it as UTF-8
     * encoded JWT bytes. ADR-027 acceptance criterion 7 requires a Standard
     * token, prepared with the `cloudProjectNumber` of the package verifier's
     * `PlayIntegrityVerifier` entry, whose `requestHash` is the lowercase
     * hexadecimal form of the binding digest `D`, and an adapter that does not
     * read [deviceId]. This adapter meets none of the three; story SCP-111's
     * acceptance criteria track each one.
     *
     * @param challenge The 32-byte binding digest `D` of
     *   `09-security-model.md` §9.3.1. ADR-025 and ADR-027 require the caller
     *   to pass `D`. No Rust code calls this method yet.
     * @param deviceId Device ID bytes, which this adapter base64-encodes into
     *   `clientDataJSON`. No verifier checks them, and they name no identity:
     *   `27-attestations.md` states that a device id is not an identifier, and
     *   ADR-027 acceptance criterion 7 requires the adapter not to read this
     *   parameter.
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

        // Return the integrity token (JWT) as UTF-8 bytes.
        return integrityTokenResponse.token().toByteArray(Charsets.UTF_8)
    }

    /**
     * Generate a per-request assertion using a fresh integrity token.
     *
     * Play Integrity does not have a per-request assertion flow equivalent to
     * Apple App Attest assertions. This method passes the request hash to
     * [attest] as the challenge with an empty device ID, so it returns a
     * Classic integrity token whose nonce is `Base64(SHA-256(clientDataJSON))`.
     * ADR-027 acceptance criterion 8 requires a Standard integrity token whose
     * `requestHash` is the lowercase hexadecimal form of `A`, requested
     * without routing through [attest]; story SCP-111's acceptance criteria
     * track both requirements.
     *
     * @param requestHash The 32-byte assertion digest `A` of
     *   `09-security-model.md` §9.3.1 over the request bytes. ADR-025 and
     *   ADR-027 require the caller to pass `A`, never the request bytes or
     *   their plain SHA-256. No Rust code calls this method yet.
     * @return Play Integrity token bytes (JWT, UTF-8 encoded).
     * @throws ScpException if the Play Integrity API call fails.
     */
    override suspend fun assertRequest(requestHash: ByteArray): ByteArray {
        // Play Integrity does not have a per-request assertion flow equivalent
        // to App Attest assertions. This call requests a fresh Classic
        // integrity token through `attest` (story SCP-111 tracks the Standard
        // request ADR-027 acceptance criterion 8 requires).
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
