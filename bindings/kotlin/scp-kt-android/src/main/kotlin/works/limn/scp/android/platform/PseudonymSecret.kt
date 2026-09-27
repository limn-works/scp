// PseudonymSecret.kt — the §9.10.4.A pseudonym secret and §9.10.4 context seed for
// AndroidKeyCustody.
//
// Provenance: spec §9.10.4 (context seed), §9.10.4.A (pseudonym secret), ADR-027.

package works.limn.scp.android.platform

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * The identity's `pseudonym_secret` (§9.10.4.A) and the context seed it keys:
 *
 *   context_seed = HMAC-SHA256(pseudonym_secret, contextId || suffix)
 *
 * Hardware identity: the secret is a device-local 256-bit HMAC key generated inside
 * Android Keystore at `generateKeypair`, non-exportable, and never derived from a
 * signature; the HMAC runs inside Keystore. Software identity: the secret is
 * `HKDF-SHA256(ikm = Ed25519 private seed, salt = "scp-pseudonym-secret-v1", info = "",
 * len = 32)` (the §9.10.4 native interim), matching `scp-crypto/src/pseudonym.rs`.
 */
internal object PseudonymSecret {
    private const val HMAC = "HmacSHA256"
    private const val SECRET_BITS = 256
    private const val SOFTWARE_SALT = "scp-pseudonym-secret-v1"

    /** Keystore alias of an identity's device-local pseudonym secret. */
    fun alias(keyId: String): String = "scp.pseudonym-secret.$keyId"

    /** Generates the device-local pseudonym secret for the hardware identity [keyId]. */
    fun generateInKeystore(keyId: String) {
        val spec = KeyGenParameterSpec.Builder(alias(keyId), KeyProperties.PURPOSE_SIGN)
            .setKeySize(SECRET_BITS)
            .setUserAuthenticationRequired(false) // pseudonyms are derived in the background
            .build()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore").apply {
            init(spec)
            generateKey()
        }
    }

    /**
     * The context seed of the hardware identity [keyId], computed inside Keystore.
     *
     * @throws ScpException with code `SCP-CRYPTO-4001` if the identity has no pseudonym
     *   secret (a key generated before this secret existed must be regenerated).
     */
    fun keystoreContextSeed(keyId: String, contextId: ByteArray, suffix: ByteArray): ByteArray {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val secret = keyStore.getKey(alias(keyId), null) as? SecretKey
            ?: throw ScpException(
                "Pseudonym secret not found in Keystore for identity $keyId",
                "SCP-CRYPTO-4001",
            )
        val mac = Mac.getInstance(HMAC)
        mac.init(secret)
        mac.update(contextId)
        mac.update(suffix)
        return mac.doFinal()
    }

    /** The context seed of a software identity; the secret is wiped after keying the MAC. */
    fun softwareContextSeed(
        privateKey: Ed25519PrivateKeyParameters,
        contextId: ByteArray,
        suffix: ByteArray,
    ): ByteArray {
        val seed = privateKey.encoded
        val secret = try {
            hkdfSha256OneBlock(seed, SOFTWARE_SALT.toByteArray(Charsets.UTF_8), ByteArray(0))
        } finally {
            seed.fill(0)
        }
        val mac = Mac.getInstance(HMAC)
        try {
            mac.init(SecretKeySpec(secret, HMAC))
        } finally {
            secret.fill(0)
        }
        mac.update(contextId)
        mac.update(suffix)
        return mac.doFinal()
    }

    /** RFC 5869 HKDF-SHA256 extract-and-expand to one 32-byte block, `T(1)`. */
    private fun hkdfSha256OneBlock(ikm: ByteArray, salt: ByteArray, info: ByteArray): ByteArray {
        val extract = Mac.getInstance(HMAC)
        extract.init(SecretKeySpec(salt, HMAC))
        val prk = extract.doFinal(ikm)
        val expand = Mac.getInstance(HMAC)
        try {
            expand.init(SecretKeySpec(prk, HMAC))
        } finally {
            prk.fill(0)
        }
        expand.update(info)
        expand.update(byteArrayOf(0x01))
        return expand.doFinal()
    }
}
