// JcaFakeKeystoreKeys.kt — a JVM stand-in for Android Keystore in AndroidKeyCustody tests.
//
// JVM tests cannot reach AndroidKeyStore, so this fake keeps its keys in maps. Ed25519 entries
// are markers (no JVM test signs with a Keystore identity), HMAC entries compute a real
// HMAC-SHA256, and P-256 entries are real SunEC key pairs that sign with NONEwithECDSA and agree
// with ECDH, so a test checks P-256 output against the bridge's strict verifier and ECDH oracle.
// Switches inject the failures the custody must survive. What the fake cannot show (Keystore's
// DIGEST_NONE rule, PURPOSE_AGREE_KEY, a real KeyInfo) the emulator lane checks.
//
// Provenance: ADR-027 (Android Platform Adapter), spec 09 §9.5 (P-256 keys).

package works.limn.scp.android.platform

import java.security.InvalidKeyException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStoreException
import java.security.ProviderException
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

internal class JcaFakeKeystoreKeys(
    /** What [insideSecureHardware] reports for every key, as `KeyInfo` would. */
    var secureHardware: Boolean = true,
    /** Makes [generateHmacSha256] throw. */
    var failHmacGeneration: Boolean = false,
    /** Makes [generateP256Signing] and [generateP256Agreement] throw. */
    var failP256Generation: Boolean = false,
    /** Makes [p256PublicKey] return `null` for a key that exists. */
    var hidePublicKey: Boolean = false,
    /** Makes [deleteEntry] return without deleting. */
    var ignoreDeletes: Boolean = false,
) : KeystoreKeys {
    private enum class Purpose { SIGN, AGREE }

    /** Aliases whose next [deleteEntry] throws, once each. */
    val failDeleteOnce: MutableSet<String> = mutableSetOf()
    val ed25519 = mutableSetOf<String>()
    val hmacKeys = mutableMapOf<String, ByteArray>()
    private val p256 = mutableMapOf<String, Pair<KeyPair, Purpose>>()

    /** The number of [agreeP256] calls. */
    var agreeCalls = 0
        private set

    /** The P-256 aliases this fake holds. */
    val p256Aliases: Set<String> get() = p256.keys

    override fun generateEd25519(alias: String) {
        ed25519.add(alias)
    }

    override fun generateHmacSha256(alias: String) {
        if (failHmacGeneration) throw ProviderException("injected HMAC generation failure")
        hmacKeys[alias] = ByteArray(32).also { SecureRandom().nextBytes(it) }
    }

    override fun hmacSha256(alias: String, vararg parts: ByteArray): ByteArray? {
        val key = hmacKeys[alias] ?: return null
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        parts.forEach { mac.update(it) }
        return mac.doFinal()
    }

    override fun containsAlias(alias: String): Boolean = alias in ed25519 || alias in hmacKeys || alias in p256

    override fun deleteEntry(alias: String) {
        if (failDeleteOnce.remove(alias)) throw KeyStoreException("injected delete failure")
        if (ignoreDeletes) return
        ed25519.remove(alias)
        hmacKeys.remove(alias)
        p256.remove(alias)
    }

    override fun generateP256Signing(alias: String) = generate(alias, Purpose.SIGN)

    override fun generateP256Agreement(alias: String) = generate(alias, Purpose.AGREE)

    override fun p256PublicKey(alias: String): ECPublicKey? =
        if (hidePublicKey) null else p256[alias]?.first?.public as ECPublicKey?

    override fun signP256Digest(alias: String, digest: ByteArray): ByteArray? {
        val (pair, purpose) = p256[alias] ?: return null
        if (purpose != Purpose.SIGN) throw InvalidKeyException("$alias is not a signing key")
        return Signature.getInstance("NONEwithECDSA").apply {
            initSign(pair.private)
            update(digest)
        }.sign()
    }

    override fun agreeP256(alias: String, peer: PublicKey): ByteArray? {
        agreeCalls++
        val (pair, purpose) = p256[alias] ?: return null
        if (purpose != Purpose.AGREE) throw InvalidKeyException("$alias is not an agreement key")
        return KeyAgreement.getInstance("ECDH").apply {
            init(pair.private)
            doPhase(peer, true)
        }.generateSecret()
    }

    override fun insideSecureHardware(alias: String): Boolean {
        if (alias !in p256) throw KeyStoreException("no key at $alias")
        return secureHardware
    }

    private fun generate(alias: String, purpose: Purpose) {
        if (failP256Generation) throw ProviderException("injected P-256 generation failure")
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
        p256[alias] = pair to purpose
    }
}
