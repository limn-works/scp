// P256Keys.kt — the P-256 signing and HPKE P-256 agreement keys of AndroidKeyCustody (ADR-027).
//
// A P-256 signing key lives in Android Keystore at every supported API level and signs the
// bridge's 32-byte digest with NONEwithECDSA under a DIGEST_NONE key, returning DER; the bridge
// converts it to raw low-s and verifies it. An HPKE P-256 key lives in Keystore
// (PURPOSE_AGREE_KEY) when the instance's probe says the API level is 31 or higher, and
// otherwise as a Bouncy Castle scalar committed to EncryptedSharedPreferences. The probe picks
// the store; a failed Keystore create fails the mint and never falls back to software. Every
// key has a KeyRecords record, and every operation follows the record.
//
// What Kotlin cannot wipe (ADR-027 Rationale): a software key's private scalar lives for the
// key's life as an immutable BigInteger inside Bouncy Castle's key parameters, with every
// BigInteger its arithmetic derives; BigIntegers.asUnsignedByteArray drops the toByteArray copy
// it trims; the preferences hold it as a Base64 String, and Base64 encoding and decoding
// allocate their own buffers; EncryptedSharedPreferences and its Tink AEAD allocate plaintext
// buffers on every write and read; and each ECDH result passes through a BigInteger. Every
// intermediate ByteArray this file allocates is zeroed.
//
// Provenance: ADR-027 (Android Platform Adapter) criteria 1-5, spec 09 §9.5 (P-256 keys),
// RFC 9180 §7.1.1 (DH of DHKEM(P-256)).

package works.limn.scp.android.platform

import android.content.SharedPreferences
import android.os.Build
import android.os.Process
import android.security.keystore.KeyProperties
import android.util.Log
import java.math.BigInteger
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECKeyGenerationParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.util.BigIntegers

/** Whether Keystore offers P-256 key agreement (`PURPOSE_AGREE_KEY`) at API level [sdk]. */
internal fun keystoreAgreementAvailable(sdk: Int): Boolean = sdk >= Build.VERSION_CODES.S

/**
 * Whether a key's `KeyInfo` places it in secure hardware at API level [sdk]: from API 31 its
 * `securityLevel` [level] is the TEE, StrongBox or an unknown secure level; below API 31, where
 * `securityLevel` does not exist, its `isInsideSecureHardware` [insideSecureHardware]. The
 * adapter and the instrumented test both decide with this function.
 */
internal fun isSecureLevel(level: Int, insideSecureHardware: Boolean, sdk: Int): Boolean =
    if (sdk >= Build.VERSION_CODES.S) level in SECURE_LEVELS else insideSecureHardware

/** The `KeyInfo.securityLevel` values that place a key in secure hardware (API 31+). */
private val SECURE_LEVELS = setOf(
    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
    KeyProperties.SECURITY_LEVEL_STRONGBOX,
    KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE,
)

/** Logs a custody warning; [message] names a key id, never key material. */
internal fun logCustodyWarning(message: String, cause: Throwable) {
    Log.w("ScpKeyCustody", message, cause)
}

/**
 * This process's tag, `"<pid>:<start elapsed realtime>"`: the pid alone repeats across
 * processes, and the start time tells a restarted process with the same pid apart.
 */
internal fun currentProcessTag(): String = "${Process.myPid()}:${Process.getStartElapsedRealtime()}"

/**
 * The P-256 and HPKE P-256 keys of one [AndroidKeyCustody].
 *
 * @param prefs The adapter's preferences, holding the software scalars under `scp.p256.<id>`.
 * @param keystore The Keystore operations.
 * @param records The keys' records.
 * @param processTag This process's tag, written into each record a mint reserves.
 * @param warn Where [sweep] reports a record it leaves in place.
 */
internal class P256Keys(
    private val prefs: SharedPreferences,
    private val keystore: KeystoreKeys,
    private val records: KeyRecords,
    private val processTag: String,
    private val warn: (String, Throwable) -> Unit,
) {
    /**
     * Mints a [type] key in [role] under [id] in [backing]: reserves its record (the role in
     * the same commit), creates the key, reads its custody class (from `KeyInfo` for Keystore,
     * "software" otherwise) and settles the record. A failure is rolled back through [rollBack].
     */
    @Suppress("TooGenericExceptionCaught") // any failure must roll the mint back
    fun mint(id: String, type: KeyType, backing: Backing, role: KeyRole): KeyHandle {
        records.reserve(id, type, backing, role, processTag)
        try {
            val custody = when (backing) {
                Backing.KEYSTORE -> createInKeystore(id, type)
                Backing.SOFTWARE -> createInSoftware(id)
            }
            records.settle(id, custody)
            return KeyHandle(id = id, custodyType = custody)
        } catch (e: Exception) {
            throw rollBack(id, backing, e)
        }
    }

    /**
     * Signs the 32-byte [digest] with the P-256 key [id] and returns Keystore's DER signature.
     */
    fun sign(id: String, record: KeyRecord, digest: ByteArray): ByteArray {
        if (!record.type.isP256Ecdsa) custodyFailure("sign requires a P-256 ECDSA key; key $id is ${record.type.wire}")
        if (digest.size != DIGEST_SIZE) {
            custodyFailure("A P-256 key signs a $DIGEST_SIZE-byte digest, got ${digest.size} bytes")
        }
        return keystore.signP256Digest(keyAlias(id), digest)
            ?: throw ScpException("Key not found in Keystore: $id", KEY_NOT_FOUND)
    }

    /** The 33-byte compressed point of a P-256 key, or the 65-byte uncompressed point of an HPKE key. */
    fun publicKey(id: String, record: KeyRecord): ByteArray {
        val point = when (record.backing) {
            Backing.KEYSTORE -> keystorePoint(id)
            Backing.SOFTWARE -> (softwarePair(id).public as ECPublicKeyParameters).q
        }
        return point.getEncoded(record.type.isP256Ecdsa)
    }

    /**
     * The 32-byte ECDH secret of the HPKE key [id] and the 65-byte uncompressed [peer], which is
     * validated on the curve before any key is used.
     */
    fun agree(id: String, record: KeyRecord, peer: ByteArray): ByteArray {
        if (record.type != KeyType.HPKE_P256) {
            custodyFailure("dhAgree requires an HPKE P-256 key; key $id is ${record.type}")
        }
        val peerPoint = validPeer(peer)
        val secret = when (record.backing) {
            Backing.KEYSTORE -> {
                val spki = SPKI_PREFIX + peer
                val peerKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))
                keystore.agreeP256(keyAlias(id), peerKey)
                    ?: throw ScpException("Key not found in Keystore: $id", KEY_NOT_FOUND)
            }
            Backing.SOFTWARE -> {
                val agreement = ECDHBasicAgreement().apply { init(softwarePair(id).private) }
                val x = agreement.calculateAgreement(ECPublicKeyParameters(peerPoint, DOMAIN))
                BigIntegers.asUnsignedByteArray(SCALAR_SIZE, x)
            }
        }
        if (secret.size != SCALAR_SIZE) {
            secret.fill(0)
            custodyFailure("P-256 agreement returned ${secret.size} bytes, not $SCALAR_SIZE")
        }
        return secret
    }

    /**
     * Deletes the key material of [id], confirms it is gone, then removes the record, and with
     * it the key's role. Reports [DestructionMethod.SOFTWARE_ONLY] whatever the recorded
     * custody: Keystore issues no proof that it destroyed a key, and §9.15 rates a destruction
     * without a verified platform proof as software-only (ADR-027 criterion 4).
     */
    fun destroy(id: String, record: KeyRecord): DestructionAttestation {
        deleteMaterial(id, record.backing)
        records.remove(id)
        return DestructionAttestation(method = DestructionMethod.SOFTWARE_ONLY, confirmed = true)
    }

    /**
     * Destroys the key [id] whose record does not parse: deletes whatever material either store
     * holds under [id], confirms it is gone, then removes the record.
     */
    fun destroyUnreadable(id: String): DestructionAttestation {
        deleteMaterial(id, Backing.KEYSTORE)
        deleteMaterial(id, Backing.SOFTWARE)
        records.remove(id)
        return DestructionAttestation(method = DestructionMethod.SOFTWARE_ONLY, confirmed = true)
    }

    /**
     * Deletes every key whose record is still pending under another process's tag and returns
     * the swept ids. The adapter runs in one process (ADR-027 criterion 1), so such a record was
     * left by an earlier process that died between reserving the record and settling it. A
     * record pending under this process's tag belongs to a mint that may still be running, and
     * is left alone.
     *
     * Best-effort, and it never throws an [Exception]: an index that cannot be read ends the
     * sweep with nothing swept, and a record that does not parse, or whose key or record cannot
     * be removed, stays in place; each is reported through [warn], and the sweep goes on.
     * Removing an orphan cleans up an inert leak on which no §9.15 guarantee depends.
     */
    @Suppress("TooGenericExceptionCaught") // no failure of the sweep may fail construction
    fun sweep(): List<String> {
        val ids = try {
            records.ids()
        } catch (e: Exception) {
            warn("The P-256 record index could not be read; no abandoned mint was swept", e)
            return emptyList()
        }
        return ids.filter { id ->
            try {
                val record = records.get(id) ?: return@filter false
                if (record.custody != null || record.processTag == processTag) return@filter false
                deleteMaterial(id, record.backing)
                records.remove(id)
                true
            } catch (e: Exception) {
                warn("Abandoned P-256 mint $id could not be swept and stays reserved", e)
                false
            }
        }
    }

    private fun createInKeystore(id: String, type: KeyType): CustodyType {
        val alias = keyAlias(id)
        if (type.isP256Ecdsa) keystore.generateP256Signing(alias) else keystore.generateP256Agreement(alias)
        val created = keystore.p256PublicKey(alias)
            ?: throw ScpException("Keystore created no public key for key $id", CUSTODY_ERROR)
        validPoint(id, created)
        return if (keystore.insideSecureHardware(alias)) CustodyType.HARDWARE else CustodyType.SOFTWARE
    }

    private fun createInSoftware(id: String): CustodyType {
        val pair = ECKeyPairGenerator().apply { init(ECKeyGenerationParameters(DOMAIN, SecureRandom())) }
            .generateKeyPair()
        val scalar = BigIntegers.asUnsignedByteArray(SCALAR_SIZE, (pair.private as ECPrivateKeyParameters).d)
        try {
            synchronized(SOFTWARE_PAIRS) {
                val committed =
                    prefs.edit().putString(scalarKey(id), Base64.getEncoder().encodeToString(scalar)).commit()
                if (!committed) throw ScpException("Could not commit the scalar of key $id", CUSTODY_ERROR)
                SOFTWARE_PAIRS[id] = pair
            }
        } finally {
            scalar.fill(0)
        }
        return CustodyType.SOFTWARE
    }

    /** The validated point of the Keystore key [id]. */
    private fun keystorePoint(id: String): ECPoint = validPoint(
        id,
        keystore.p256PublicKey(keyAlias(id)) ?: throw ScpException("Key not found in Keystore: $id", KEY_NOT_FOUND),
    )

    /** The point of the Keystore public [key] of [id], refused when it is not a valid P-256 point. */
    private fun validPoint(id: String, key: ECPublicKey): ECPoint {
        val point = DOMAIN.curve.createPoint(key.w.affineX, key.w.affineY)
        if (point.isInfinity || !point.isValid) {
            throw ScpException("Keystore returned an invalid P-256 point for key $id", CUSTODY_ERROR)
        }
        return point
    }

    /**
     * The software key pair of [id], loaded from its committed scalar on first use, under the
     * monitor of [SOFTWARE_PAIRS]. A scalar that is missing, not 32 bytes, or outside [1, n − 1]
     * is `SCP-CRYPTO-4060`.
     */
    private fun softwarePair(id: String): AsymmetricCipherKeyPair = synchronized(SOFTWARE_PAIRS) {
        SOFTWARE_PAIRS[id]?.let { return@synchronized it }
        val text = prefs.getString(scalarKey(id), null)
            ?: custodyFailure("The record of key $id names a software scalar that is missing")
        val bytes = Base64.getDecoder().decode(text)
        val d = try {
            if (bytes.size != SCALAR_SIZE) {
                custodyFailure("The scalar of key $id is ${bytes.size} bytes, not $SCALAR_SIZE")
            }
            BigInteger(1, bytes)
        } finally {
            bytes.fill(0)
        }
        if (d.signum() == 0 || d >= DOMAIN.n) custodyFailure("The scalar of key $id is outside [1, n - 1]")
        AsymmetricCipherKeyPair(
            ECPublicKeyParameters(DOMAIN.g.multiply(d).normalize(), DOMAIN),
            ECPrivateKeyParameters(d, DOMAIN),
        ).also { SOFTWARE_PAIRS[id] = it }
    }

    /**
     * Deletes the material of [id] in [backing] and confirms by re-fetch: the alias by
     * `containsAlias`, the scalar by reading the entry back after a `commit()` removal. The
     * scalar and its cached pair go under the monitor of [SOFTWARE_PAIRS].
     */
    private fun deleteMaterial(id: String, backing: Backing) {
        when (backing) {
            Backing.KEYSTORE -> if (keystore.containsAlias(keyAlias(id))) keystore.deleteConfirmed(id, keyAlias(id))
            Backing.SOFTWARE -> synchronized(SOFTWARE_PAIRS) {
                SOFTWARE_PAIRS.remove(id)
                val committed = prefs.edit().remove(scalarKey(id)).commit()
                if (!committed || prefs.getString(scalarKey(id), null) != null) {
                    throw ScpException("Key destruction failed: the scalar of key $id persisted", CUSTODY_ERROR)
                }
            }
        }
    }

    /**
     * Rolls back the failed mint of [id]: deletes its material and, once that deletion is
     * confirmed, its record, then returns [cause]. When either cannot be confirmed, the record
     * stays (pending) and the returned `SCP-CRYPTO-4060` names [id], which [destroy] removes.
     */
    @Suppress("TooGenericExceptionCaught") // a failed cleanup is reported, never lost
    private fun rollBack(id: String, backing: Backing, cause: Exception): Exception {
        try {
            deleteMaterial(id, backing)
        } catch (cleanup: Exception) {
            return ScpException(
                "Mint of key $id failed and the key could not be deleted; destroyKey($id) retries",
                CUSTODY_ERROR,
                cause,
            ).apply { addSuppressed(cleanup) }
        }
        try {
            records.remove(id)
        } catch (cleanup: Exception) {
            return ScpException(
                "Mint of key $id failed and its record could not be removed; destroyKey($id) retries",
                CUSTODY_ERROR,
                cause,
            ).apply { addSuppressed(cleanup) }
        }
        return cause
    }

    private companion object {
        /**
         * The software HPKE key pairs loaded from their committed scalars, by key id, for every
         * instance in the process. One map serves the process, so a destroy through any instance
         * leaves no instance holding the destroyed pair; the single-process rule (ADR-027
         * criterion 1) makes this sound, because every instance reads the same preferences file,
         * so one id names one scalar. Every read and change of this map, and every write of a
         * scalar entry, runs under the map's monitor, so a destroy that runs while another thread
         * loads the same key cannot leave the pair cached: either the load finishes first and the
         * destroy removes its pair, or the destroy finishes first and the load finds no scalar.
         */
        val SOFTWARE_PAIRS = HashMap<String, AsymmetricCipherKeyPair>()

        const val SCALAR_SIZE = 32
        const val DIGEST_SIZE = 32
        const val UNCOMPRESSED_SIZE = 65
        const val UNCOMPRESSED_TAG: Byte = 0x04

        val DOMAIN = ECDomainParameters(SECNamedCurves.getByName("secp256r1"))

        /**
         * The DER SubjectPublicKeyInfo header of an uncompressed P-256 point: SEQUENCE {
         * AlgorithmIdentifier { id-ecPublicKey, secp256r1 }, BIT STRING (65 bytes) }.
         */
        val SPKI_PREFIX: ByteArray = byteArrayOf(
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x02,
            0x01, 0x06, 0x08, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07, 0x03,
            0x42, 0x00,
        )

        fun scalarKey(id: String) = "scp.p256.$id"

        /**
         * The point of a peer's 65-byte uncompressed SEC1 key: tag `0x04`, on the curve, not the
         * point at infinity; anything else is `SCP-CRYPTO-4060`.
         */
        fun validPeer(peer: ByteArray): ECPoint {
            if (peer.size != UNCOMPRESSED_SIZE || peer[0] != UNCOMPRESSED_TAG) {
                custodyFailure(
                    "An HPKE P-256 peer key is the $UNCOMPRESSED_SIZE-byte uncompressed point, got ${peer.size} bytes",
                )
            }
            val point = try {
                DOMAIN.curve.decodePoint(peer)
            } catch (e: IllegalArgumentException) {
                custodyFailure("The HPKE P-256 peer key is not on the curve", e)
            }
            if (point.isInfinity || !point.isValid) custodyFailure("The HPKE P-256 peer key is not a valid point")
            return point.normalize()
        }
    }
}
