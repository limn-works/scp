// PseudonymSecret.kt — the §9.10.4.A pseudonym secret and §9.10.4 context seed for
// AndroidKeyCustody.
//
// Provenance: spec §9.10.4 (context seed), §9.10.4.A (pseudonym secret), ADR-027.

package works.limn.scp.android.platform

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.NamedParameterSpec
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * The identity's `pseudonym_secret` (§9.10.4.A) and the context seed it keys:
 *
 *   context_seed = HMAC-SHA256(pseudonym_secret, contextId || suffix)
 *
 * Hardware identity: the secret is a device-local 256-bit HMAC key generated inside
 * Android Keystore at `generateKeypair`, non-exportable, and never derived from a
 * signature; the HMAC runs inside Keystore. A software identity's secret and seed are
 * computed by the Rust helper behind [P256Pseudonym.softwarePoint].
 */
internal object PseudonymSecret {
    /** Keystore alias of an identity's device-local pseudonym secret. */
    fun alias(keyId: String): String = "scp.pseudonym-secret.$keyId"

    /**
     * The context seed of the hardware identity [keyId], computed inside Keystore.
     *
     * @throws ScpException with code `SCP-CRYPTO-4006` if the identity has no pseudonym
     *   secret (a key generated before this secret existed must be regenerated).
     */
    fun keystoreContextSeed(
        keystore: KeystoreKeys,
        keyId: String,
        contextId: ByteArray,
        suffix: ByteArray,
    ): ByteArray = keystore.hmacSha256(alias(keyId), contextId, suffix)
        ?: throw ScpException(
            "Pseudonym secret not found in Keystore for identity $keyId",
            "SCP-CRYPTO-4006",
        )
}

/**
 * The Android Keystore operations of the hardware identity path: the Ed25519 identity
 * key and its HMAC-SHA256 pseudonym secret. [AndroidKeystoreKeys] is the production
 * implementation; JVM tests substitute a fake to run that path without a device.
 */
internal interface KeystoreKeys {
    /** Generates a non-exportable Ed25519 signing key at [alias]. */
    fun generateEd25519(alias: String)

    /** Generates a non-exportable 256-bit HMAC-SHA256 key at [alias]. */
    fun generateHmacSha256(alias: String)

    /**
     * HMAC-SHA256 under the key at [alias] over the concatenation of [parts], computed
     * inside Keystore, or `null` when no secret key is at [alias].
     */
    fun hmacSha256(alias: String, vararg parts: ByteArray): ByteArray?

    /** Whether any entry exists at [alias]. */
    fun containsAlias(alias: String): Boolean

    /** Deletes the entry at [alias]; a missing entry is not an error. */
    fun deleteEntry(alias: String)
}

/** [KeystoreKeys] over `AndroidKeyStore`. */
internal object AndroidKeystoreKeys : KeystoreKeys {
    private const val PROVIDER = "AndroidKeyStore"
    private const val HMAC = "HmacSHA256"
    private const val SECRET_BITS = 256

    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    override fun generateEd25519(alias: String) {
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setAlgorithmParameterSpec(NamedParameterSpec.ED25519)
            .setDigests() // EdDSA does not require explicit digest
            .setUserAuthenticationRequired(false) // SCP requires background processing
            .build()
        KeyPairGenerator.getInstance("EdDSA", PROVIDER).apply {
            initialize(spec)
            generateKeyPair()
        }
    }

    override fun generateHmacSha256(alias: String) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setKeySize(SECRET_BITS)
            .setUserAuthenticationRequired(false) // pseudonyms are derived in the background
            .build()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, PROVIDER).apply {
            init(spec)
            generateKey()
        }
    }

    override fun hmacSha256(alias: String, vararg parts: ByteArray): ByteArray? {
        val secret = keyStore().getKey(alias, null) as? SecretKey ?: return null
        val mac = Mac.getInstance(HMAC)
        mac.init(secret)
        parts.forEach { mac.update(it) }
        return mac.doFinal()
    }

    override fun containsAlias(alias: String): Boolean = keyStore().containsAlias(alias)

    override fun deleteEntry(alias: String) = keyStore().deleteEntry(alias)
}
