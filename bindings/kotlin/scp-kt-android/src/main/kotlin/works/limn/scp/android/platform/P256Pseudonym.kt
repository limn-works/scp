// P256Pseudonym.kt — §9.10.4 P-256 pseudonym keys for AndroidKeyCustody.
//
// Provenance: spec §9.10.4 (seed-to-scalar), §9.10.4.A (pseudonym secret), §9.5
// (RFC 6979 low-s prehash ECDSA). The scalar reduction and the signer are the Rust
// `scp-crypto` ones, reached through the `scp-ffi-uniffi` exports in `p256_host.rs`,
// so this host re-implements neither.

package works.limn.scp.android.platform

import uniffi.scp.p256PublicKey
import uniffi.scp.p256SeedToScalar
import uniffi.scp.p256SignPrehashRfc6979
import java.nio.ByteBuffer
import java.security.MessageDigest
import uniffi.scp.ScpException as BridgeException

/**
 * P-256 pseudonym key registration, public key and prehash signing (§9.10.4, §9.5).
 *
 *   d = int(HKDF-Expand-SHA256(prk = context_seed, info = "SCP-PSEUDONYM-P256-V1", 48))
 *       mod (n - 1) + 1
 *   public_key = SEC1-compressed(d * G)   (33 bytes)
 */
internal object P256Pseudonym {
    /** HKDF-Expand label that turns a context seed into the pseudonym scalar. */
    const val SCALAR_LABEL = "SCP-PSEUDONYM-P256-V1"

    private const val DIGEST_SIZE = 32

    /**
     * Maps a 32-byte context seed to its pseudonym scalar, stores the scalar in [keys]
     * under [pseudonymId] as a pseudonym of [identityId], and zeroizes the seed.
     */
    fun register(
        keys: PseudonymKeys,
        identityId: String,
        pseudonymId: String,
        contextSeed: ByteArray,
    ): PseudonymKeyHandle {
        val scalar = try {
            bridged { p256SeedToScalar(SCALAR_LABEL.toByteArray(Charsets.UTF_8), contextSeed) }
        } finally {
            contextSeed.fill(0)
        }
        keys.put(identityId, pseudonymId, scalar)
        return PseudonymKeyHandle(id = pseudonymId, custodyType = CustodyType.SOFTWARE)
    }

    /**
     * The pseudonym handle id for ([identityId], [contextId], [epoch]): the same inputs
     * always name the same handle, so re-deriving keeps the existing entry (and wipes the
     * new scalar) instead of adding one. A `null` [epoch] is the v1 derivation.
     */
    fun pseudonymId(identityId: String, contextId: ByteArray, epoch: Long?): String {
        val sha = MessageDigest.getInstance("SHA-256")
        val identity = identityId.toByteArray(Charsets.UTF_8)
        sha.update("scp-android-pseudonym-id-v1".toByteArray(Charsets.UTF_8))
        sha.update(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(identity.size).array())
        sha.update(identity)
        sha.update(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(contextId.size).array())
        sha.update(contextId)
        if (epoch != null) sha.update(ByteBuffer.allocate(Long.SIZE_BYTES).putLong(epoch).array())
        return "p256-" + sha.digest().joinToString("") { "%02x".format(it) }
    }

    /** The 33-byte SEC1 compressed encoding of `d * G`. */
    fun compressedPublicKey(scalar: ByteArray): ByteArray = bridged { p256PublicKey(scalar) }

    /**
     * Signs a 32-byte digest without hashing it again, with the RFC 6979 nonce, and
     * returns the 64-byte low-s `r || s` (§9.5).
     *
     * @throws ScpException with code `SCP-CRYPTO-4003` if [digest] is not 32 bytes.
     */
    fun signPrehash(scalar: ByteArray, digest: ByteArray): ByteArray {
        if (digest.size != DIGEST_SIZE) {
            throw ScpException(
                "P-256 pseudonym keys sign only a 32-byte digest, got ${digest.size} bytes",
                "SCP-CRYPTO-4003",
            )
        }
        return bridged { p256SignPrehashRfc6979(scalar, digest) }
    }

    /** Maps a bridge error to this package's [ScpException], keeping its code. */
    private inline fun <T> bridged(call: () -> T): T = try {
        call()
    } catch (e: BridgeException.Validation) {
        throw ScpException(e.msg, e.code, e)
    } catch (e: BridgeException.Crypto) {
        throw ScpException(e.msg, e.code, e)
    }
}

/**
 * The in-memory P-256 pseudonym scalars of one [AndroidKeyCustody], each owned by the
 * identity it was derived from.
 *
 * Every access holds [lock]. A stored scalar array is never handed out: [withScalar]
 * lends a copy and wipes it afterwards, so wiping a stored array on replace or remove
 * cannot corrupt a signature in progress on another thread.
 */
internal class PseudonymKeys {
    private val lock = Any()
    private val scalars = HashMap<String, ByteArray>()
    private val byIdentity = HashMap<String, MutableSet<String>>()

    /**
     * Identities destroyed in this process. A derivation that read its seed before its
     * identity was destroyed must not store a scalar afterwards; handle ids are random
     * UUIDs, so this holds one short string per destroyed identity.
     */
    private val retired = HashSet<String>()

    /** Number of stored scalars. */
    val size: Int get() = synchronized(lock) { scalars.size }

    /**
     * Stores [scalar] under [pseudonymId] for [identityId]. An id already present keeps
     * its scalar (the same inputs derive the same scalar) and [scalar] is wiped.
     *
     * @throws ScpException with code `SCP-CRYPTO-4001` if [identityId] was destroyed;
     *   [scalar] is wiped.
     */
    fun put(identityId: String, pseudonymId: String, scalar: ByteArray) {
        synchronized(lock) {
            if (identityId in retired) {
                scalar.fill(0)
                throw ScpException("Key not found: $identityId", "SCP-CRYPTO-4001")
            }
            if (scalars.putIfAbsent(pseudonymId, scalar) != null) {
                scalar.fill(0)
            } else {
                byIdentity.getOrPut(identityId) { HashSet() }.add(pseudonymId)
            }
        }
    }

    /** Runs [use] on a copy of the scalar of [pseudonymId], or returns `null` if absent. */
    fun <T> withScalar(pseudonymId: String, use: (ByteArray) -> T): T? {
        val copy = synchronized(lock) { scalars[pseudonymId]?.copyOf() } ?: return null
        return try {
            use(copy)
        } finally {
            copy.fill(0)
        }
    }

    /** Wipes and removes the scalar of [pseudonymId]; `false` if there was none. */
    fun remove(pseudonymId: String): Boolean = synchronized(lock) {
        val scalar = scalars.remove(pseudonymId) ?: return false
        scalar.fill(0)
        byIdentity.values.forEach { it.remove(pseudonymId) }
        true
    }

    /**
     * Wipes and removes every scalar derived from [identityId], and refuses any later
     * [put] for it.
     */
    fun retireIdentity(identityId: String) {
        synchronized(lock) {
            retired.add(identityId)
            byIdentity.remove(identityId)?.forEach { scalars.remove(it)?.fill(0) }
        }
    }
}
