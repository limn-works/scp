// Hkdf.kt — HKDF-SHA-256 (RFC 5869) for the Android platform adapters
//
// AndroidKeyCustody derives the pseudonym secret with HKDF-SHA-256, and
// AndroidStorage derives the SQLCipher passphrase with HKDF-SHA-256. Both call
// this object, so the package holds one implementation of the derivation rather
// than two.
//
// Provenance: section 17.6 of .docs/specs/17-persistence-and-storage.md
// (SQLCipher key derivation), RFC 5869 (HKDF).

package works.limn.scp.android.platform

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HKDF-SHA-256 extract-and-expand, as RFC 5869 defines it.
 *
 * The Rust core uses `hkdf::Hkdf::<Sha256>`; this object produces the same bytes
 * for the same inputs, so a Kotlin adapter and the Rust core agree on any key
 * they both derive.
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
     * @param salt Domain-separating salt. RFC 5869 permits an empty salt; every
     *   SCP caller passes a non-empty one.
     * @param info Context string that binds the output to a purpose.
     * @param length Output length in bytes, at most [SHA256_OUTPUT_BYTES].
     * @return [length] bytes of output keying material.
     */
    fun sha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..SHA256_OUTPUT_BYTES) {
            "HKDF-SHA-256 expand: length must be in 1..$SHA256_OUTPUT_BYTES for single-block output"
        }

        // Extract: PRK = HMAC-SHA256(salt, IKM)
        val extractMac = Mac.getInstance(MAC_ALGORITHM)
        extractMac.init(SecretKeySpec(salt, MAC_ALGORITHM))
        val prk = extractMac.doFinal(ikm)

        // Expand: OKM = T(1) where T(1) = HMAC-SHA256(PRK, info || 0x01)
        val expandMac = Mac.getInstance(MAC_ALGORITHM)
        expandMac.init(SecretKeySpec(prk, MAC_ALGORITHM))
        prk.fill(0) // zeroize PRK
        expandMac.update(info)
        expandMac.update(byteArrayOf(0x01))
        val okm = expandMac.doFinal()
        return okm.copyOf(length)
    }
}
