// PseudonymSecret.kt — the §9.10.4.A pseudonym secret and §9.10.4 context seed for
// AndroidKeyCustody, and the Android Keystore operations AndroidKeyCustody uses.
//
// Provenance: spec §9.10.4 (context seed), §9.10.4.A (pseudonym secret), spec 09 §9.5 (P-256
// keys), ADR-027.

package works.limn.scp.android.platform

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.NamedParameterSpec
import javax.crypto.KeyAgreement
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
            KEY_NOT_FOUND,
        )
}

/**
 * The Android Keystore operations [AndroidKeyCustody] uses: the Ed25519 identity key and its
 * HMAC-SHA256 pseudonym secret, and the P-256 signing and agreement keys. [androidKeystoreKeys]
 * returns the production implementation; JVM tests substitute a fake to run those paths without
 * a device. A member lets a Keystore failure escape as the original exception, and
 * [AndroidKeyCustody] reports it as `SCP-CRYPTO-4060`.
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

    /**
     * Generates a non-exportable P-256 signing key at [alias], authorised for `DIGEST_NONE` so
     * that it signs the bridge's 32-byte digest as given, usable without user authentication.
     */
    fun generateP256Signing(alias: String)

    /** Generates a non-exportable P-256 key-agreement key (`PURPOSE_AGREE_KEY`, API 31+) at [alias]. */
    fun generateP256Agreement(alias: String)

    /** The public key of the P-256 key at [alias], from its certificate, or `null` when [alias] is absent. */
    fun p256PublicKey(alias: String): ECPublicKey?

    /**
     * The `NONEwithECDSA` signature of the P-256 key at [alias] over [digest], DER-encoded as
     * Keystore returns it, or `null` when [alias] is absent.
     */
    fun signP256Digest(alias: String, digest: ByteArray): ByteArray?

    /**
     * The ECDH shared secret (the agreed point's x-coordinate) of the P-256 key at [alias] and
     * [peer], or `null` when [alias] is absent.
     */
    fun agreeP256(alias: String, peer: PublicKey): ByteArray?

    /**
     * Whether `KeyInfo` places the key at [alias] in secure hardware, as [isSecureLevel] decides.
     * A missing alias or an unreadable `KeyInfo` throws; it never reads as either answer.
     */
    fun insideSecureHardware(alias: String): Boolean
}

/** The loaded `AndroidKeyStore`. */
private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

/** The production [KeystoreKeys], over `AndroidKeyStore`. */
@JvmSynthetic
internal fun androidKeystoreKeys(): KeystoreKeys = AndroidKeystoreKeys()

/**
 * [KeystoreKeys] over `AndroidKeyStore`. It holds no state; every call loads the store. Private
 * to this file, so no app code reaches it.
 */
private class AndroidKeystoreKeys : KeystoreKeys {
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

    override fun generateP256Signing(alias: String) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec(P256_CURVE))
            // The bridge passes the 32-byte SHA-256 digest; DIGEST_NONE signs it as given, where
            // DIGEST_SHA256 would hash it a second time.
            .setDigests(KeyProperties.DIGEST_NONE)
            .setUserAuthenticationRequired(false) // SCP signs in the background
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER).apply {
            initialize(spec)
            generateKeyPair()
        }
    }

    @RequiresApi(Build.VERSION_CODES.S)
    override fun generateP256Agreement(alias: String) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
            .setAlgorithmParameterSpec(ECGenParameterSpec(P256_CURVE))
            .setUserAuthenticationRequired(false) // SCP agrees in the background
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER).apply {
            initialize(spec)
            generateKeyPair()
        }
    }

    override fun p256PublicKey(alias: String): ECPublicKey? =
        keyStore().getCertificate(alias)?.publicKey as? ECPublicKey

    override fun signP256Digest(alias: String, digest: ByteArray): ByteArray? {
        val key = keyStore().getKey(alias, null) as? PrivateKey ?: return null
        return Signature.getInstance("NONEwithECDSA").run {
            initSign(key)
            update(digest)
            sign()
        }
    }

    override fun agreeP256(alias: String, peer: PublicKey): ByteArray? {
        val key = keyStore().getKey(alias, null) as? PrivateKey ?: return null
        return KeyAgreement.getInstance("ECDH", PROVIDER).run {
            init(key)
            doPhase(peer, true)
            generateSecret()
        }
    }

    override fun insideSecureHardware(alias: String): Boolean {
        val key = keyStore().getKey(alias, null) as? PrivateKey
            ?: throw KeyStoreException("No private key at $alias")
        val info = KeyFactory.getInstance(key.algorithm, PROVIDER).getKeySpec(key, KeyInfo::class.java)
        val sdk = Build.VERSION.SDK_INT
        // securityLevel exists from API 31 only; below it isSecureLevel reads isInsideSecureHardware.
        val level = if (sdk >= Build.VERSION_CODES.S) info.securityLevel else KeyProperties.SECURITY_LEVEL_SOFTWARE
        @Suppress("DEPRECATION") // the only security-level reading below API 31
        return isSecureLevel(level, info.isInsideSecureHardware, sdk)
    }

    private companion object {
        const val PROVIDER = "AndroidKeyStore"
        const val HMAC = "HmacSHA256"
        const val SECRET_BITS = 256
        const val P256_CURVE = "secp256r1"
    }
}
