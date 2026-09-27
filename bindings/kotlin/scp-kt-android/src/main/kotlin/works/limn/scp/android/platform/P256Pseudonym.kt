// P256Pseudonym.kt — §9.10.4.A P-256 pseudonym arithmetic for AndroidKeyCustody.
//
// Provenance: spec §9.10.4.A (pseudonym recipe), §9.5.1 (64-byte low-s prehash ECDSA),
// `scp-crypto/src/pseudonym.rs` (Rust reference).

package works.limn.scp.android.platform

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import java.math.BigInteger
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * P-256 pseudonym key derivation and prehash signing (spec §9.10.4.A, §9.5.1).
 *
 *   d = int(HKDF-Expand-SHA256(prk = context_seed, info = "SCP-PSEUDONYM-P256-V1", 48))
 *       mod (n - 1) + 1
 *   public_key = SEC1-compressed(d * G)   (33 bytes)
 */
internal object P256Pseudonym {
    /** HKDF-Expand label that turns a context seed into the pseudonym scalar. */
    const val SCALAR_LABEL = "SCP-PSEUDONYM-P256-V1"

    private val curve = CustomNamedCurves.getByName("secp256r1")
    private val domain = ECDomainParameters(curve.curve, curve.g, curve.n, curve.h)
    private val halfOrder: BigInteger = curve.n.shiftRight(1)

    /**
     * Maps a 32-byte context seed to its pseudonym scalar, stores the scalar in [keys]
     * under a fresh handle id, and zeroizes the seed.
     */
    fun register(keys: MutableMap<String, BigInteger>, contextSeed: ByteArray): PseudonymKeyHandle {
        val scalar = seedToScalar(SCALAR_LABEL, contextSeed)
        contextSeed.fill(0)
        val id = UUID.randomUUID().toString()
        keys[id] = scalar
        return PseudonymKeyHandle(id = id, custodyType = CustodyType.SOFTWARE)
    }

    /** RFC 5869 HKDF-Expand with SHA-256. */
    fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val out = ByteArray(length)
        var block = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(block)
            mac.update(info)
            mac.update(counter.toByte())
            block = mac.doFinal()
            val take = minOf(block.size, length - offset)
            System.arraycopy(block, 0, out, offset, take)
            offset += take
            counter++
        }
        block.fill(0)
        return out
    }

    /** FIPS 186-5 A.2.1 seed-to-scalar (§9.10.4): 48 bytes, mod (n - 1), + 1. */
    fun seedToScalar(label: String, seed: ByteArray): BigInteger {
        val wide = hkdfExpand(seed, label.toByteArray(Charsets.UTF_8), 48)
        val scalar = BigInteger(1, wide).mod(curve.n.subtract(BigInteger.ONE)).add(BigInteger.ONE)
        wide.fill(0)
        return scalar
    }

    /** The 33-byte SEC1 compressed encoding of `d * G`. */
    fun compressedPublicKey(d: BigInteger): ByteArray =
        domain.g.multiply(d).normalize().getEncoded(true)

    /**
     * Signs a 32-byte digest without hashing it again (RFC 6979 nonce) and returns the
     * 64-byte `r || s` with low s (§9.5.1).
     *
     * @throws ScpException with code `SCP-CRYPTO-4003` if [digest] is not 32 bytes.
     */
    fun signPrehash(d: BigInteger, digest: ByteArray): ByteArray {
        if (digest.size != 32) {
            throw ScpException(
                "P-256 pseudonym keys sign only a 32-byte digest, got ${digest.size} bytes",
                "SCP-CRYPTO-4003",
            )
        }
        val signer = ECDSASigner(HMacDSAKCalculator(SHA256Digest()))
        signer.init(true, ECPrivateKeyParameters(d, domain))
        val (r, s) = signer.generateSignature(digest)
        val lowS = if (s > halfOrder) curve.n.subtract(s) else s
        return to32(r) + to32(lowS)
    }

    private fun to32(x: BigInteger): ByteArray {
        val bytes = x.toByteArray()
        return when {
            bytes.size == 32 -> bytes
            bytes.size > 32 -> bytes.copyOfRange(bytes.size - 32, bytes.size)
            else -> ByteArray(32 - bytes.size) + bytes
        }
    }
}
