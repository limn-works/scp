// Hkdf.kt — HKDF-SHA-256 (RFC 5869) for the Android platform adapters
//
// AndroidStorage derives the SQLCipher key with this object. It sits in its own
// file so that StorageKeyDerivationTest can check it against the RFC 5869 test
// vectors apart from the storage constants.
//
// Provenance: section 17.6 of .docs/specs/17-persistence-and-storage.md
// (SQLCipher key derivation), RFC 5869 (HKDF).

package works.limn.scp.android.platform

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HKDF-SHA-256 extract-and-expand, as RFC 5869 defines it.
 *
 * It runs one expand block, so it emits at most 32 bytes, which is all the
 * SQLCipher key needs.
 */
internal object Hkdf {

    /** Output length of SHA-256 in bytes. HKDF-Expand emits one block at this size. */
    const val SHA256_OUTPUT_BYTES = 32

    private const val MAC_ALGORITHM = "HmacSHA256"

    /**
     * Derives [length] bytes from [ikm] under [salt] and [info].
     *
     * Extract computes `PRK = HMAC-SHA256(salt, ikm)`. Expand computes
     * `T(1) = HMAC-SHA256(PRK, info || 0x01)` and truncates it to [length].
     * A caller that asks for more than 32 bytes gets an [IllegalArgumentException],
     * because this implementation runs one expand block.
     *
     * @param ikm Input keying material.
     * @param salt Domain-separating salt. An empty salt stands for 32 zero bytes, as
     *   RFC 5869 section 2.2 states.
     * @param info Context string that binds the output to a purpose.
     * @param length Output length in bytes, at most [SHA256_OUTPUT_BYTES].
     * @return [length] bytes of output keying material.
     */
    fun sha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..SHA256_OUTPUT_BYTES) {
            "HKDF-SHA-256 expand: length must be in 1..$SHA256_OUTPUT_BYTES for single-block output"
        }

        // Extract: PRK = HMAC-SHA256(salt, IKM). RFC 5869 section 2.2 reads an absent salt
        // as HashLen zero bytes; SecretKeySpec rejects an empty key, so pass those zeros.
        val extractMac = Mac.getInstance(MAC_ALGORITHM)
        extractMac.init(SecretKeySpec(if (salt.isEmpty()) ByteArray(SHA256_OUTPUT_BYTES) else salt, MAC_ALGORITHM))
        val prk = extractMac.doFinal(ikm)

        // Expand: OKM = T(1) where T(1) = HMAC-SHA256(PRK, info || 0x01)
        val expandMac = Mac.getInstance(MAC_ALGORITHM)
        expandMac.init(SecretKeySpec(prk, MAC_ALGORITHM))
        prk.fill(0) // zeroize PRK
        expandMac.update(info)
        expandMac.update(byteArrayOf(0x01))
        val okm = expandMac.doFinal()
        if (length == okm.size) return okm
        return okm.copyOf(length).also { okm.fill(0) }
    }
}
