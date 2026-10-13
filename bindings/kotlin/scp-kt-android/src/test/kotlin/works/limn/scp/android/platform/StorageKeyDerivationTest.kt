// StorageKeyDerivationTest.kt — the SQLCipher key derivation (SCP-113)
//
// These tests pin AndroidStorage's SQLCipher key to HKDF-SHA-256 with the salt and
// info that section 17.6 of .docs/specs/17-persistence-and-storage.md fixes, and to
// the raw-key literal that section requires.
//
// An earlier revision of AndroidStorage encrypted the fixed label
// "scp-storage-passphrase" with AES-GCM under an all-zero IV and kept the first 32
// output bytes. `database key matches an independent HKDF-SHA-256 computation` and
// `flipping one input bit changes most output bits` both fail against that
// construction: a truncated GCM output is not an HKDF output, and a fixed-IV GCM
// output of a known plaintext changes one output bit per flipped plaintext bit.
//
// These tests run on a plain JVM. They call the derivation with a stand-in for the
// Keystore MAC output, so no Android Keystore is required; generating the Keystore
// HMAC key and computing the MAC need an instrumented test on a device. The
// AndroidStorage instances get a ContextWrapper whose noBackupFilesDir is a temporary
// directory; no test touches the database.
//
// Provenance: ADR-027 (Android Platform Adapter), section 17.6 of
// .docs/specs/17-persistence-and-storage.md (SQLCipher key derivation), RFC 5869 (HKDF).

package works.limn.scp.android.platform

import android.content.ContextWrapper
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Tests for [Hkdf] and for the SQLCipher key derivation in [AndroidStorage].
 */
class StorageKeyDerivationTest {

    @TempDir
    lateinit var tempDir: File

    // -------------------------------------------------------------------
    // Hkdf against RFC 5869 Appendix A
    // -------------------------------------------------------------------

    @Test
    fun `hkdf matches RFC 5869 test case 1 for the first 32 bytes`() {
        // RFC 5869 A.1: IKM = 0x0b x 22, salt = 0x00..0c, info = 0xf0..f9, L = 42.
        // A 32-byte request returns the first expand block, the first 32 bytes of OKM.
        val okm = Hkdf.sha256(
            ByteArray(22) { 0x0b },
            hex("000102030405060708090a0b0c"),
            hex("f0f1f2f3f4f5f6f7f8f9"),
            Hkdf.SHA256_OUTPUT_BYTES,
        )
        assertArrayEquals(hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"), okm)
    }

    @Test
    fun `hkdf matches RFC 5869 test case 2 for the first 32 bytes`() {
        // RFC 5869 A.2: 80-byte IKM 0x00..4f, salt 0x60..af, info 0xb0..ff, L = 82.
        val okm = Hkdf.sha256(range(0x00, 0x4f), range(0x60, 0xaf), range(0xb0, 0xff), Hkdf.SHA256_OUTPUT_BYTES)
        assertArrayEquals(hex("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"), okm)
    }

    @Test
    fun `hkdf matches RFC 5869 test case 3 for the first 32 bytes`() {
        // RFC 5869 A.3: IKM = 0x0b x 22, empty salt, empty info, L = 42. An empty salt
        // means a salt of 32 zero bytes, which HMAC treats the same as an empty key.
        val okm = Hkdf.sha256(ByteArray(22) { 0x0b }, ByteArray(0), ByteArray(0), Hkdf.SHA256_OUTPUT_BYTES)
        assertArrayEquals(hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"), okm)
    }

    @Test
    fun `hkdf truncates to the requested length`() {
        val full = Hkdf.sha256(ByteArray(22) { 0x0b }, hex("000102030405060708090a0b0c"), hex("f0f1"), 32)
        val short = Hkdf.sha256(ByteArray(22) { 0x0b }, hex("000102030405060708090a0b0c"), hex("f0f1"), 16)
        assertArrayEquals(full.copyOf(16), short)
    }

    @Test
    fun `hkdf rejects a request longer than one SHA-256 block`() {
        assertThrows(IllegalArgumentException::class.java) {
            Hkdf.sha256(ByteArray(32), "salt".toByteArray(), ByteArray(0), Hkdf.SHA256_OUTPUT_BYTES + 1)
        }
    }

    @Test
    fun `hkdf rejects a zero-length request`() {
        assertThrows(IllegalArgumentException::class.java) {
            Hkdf.sha256(ByteArray(32), "salt".toByteArray(), ByteArray(0), 0)
        }
    }

    // -------------------------------------------------------------------
    // deriveDatabaseKey and rawKeyLiteral
    // -------------------------------------------------------------------

    @Test
    fun `database key matches an independent HKDF-SHA-256 computation`() {
        // Computes section 17.6's derivation from RFC 5869's two steps without calling
        // Hkdf, so it checks the construction rather than restating Hkdf's output.
        val ikm = ByteArray(32) { (it * 7 + 3).toByte() }
        val dir = File(tempDir, "a")
        val sha = MessageDigest.getInstance("SHA-256")
        val salt = sha.digest("SCP-SQLCIPHER-KEY-V1".toByteArray(Charsets.UTF_8))
        val info = "scp-sqlcipher:".toByteArray(Charsets.UTF_8) +
            sha.digest(dir.absolutePath.toByteArray(Charsets.UTF_8))
        val prk = hmac(salt, ikm)
        val expected = hmac(prk, info + byteArrayOf(0x01))

        assertArrayEquals(expected, AndroidStorage.deriveDatabaseKey(ikm, dir))
    }

    @Test
    fun `database key is 32 bytes as section 17_6 requires`() {
        assertEquals(32, AndroidStorage.DATABASE_KEY_LENGTH)
        assertEquals(32, AndroidStorage.deriveDatabaseKey(ByteArray(32) { it.toByte() }, tempDir).size)
    }

    @Test
    fun `directory identifier is the 32-byte SHA-256 of the absolute path`() {
        val id = AndroidStorage.directoryIdentifier(tempDir)
        val expected = MessageDigest.getInstance("SHA-256").digest(tempDir.absolutePath.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected, id)
        assertEquals(32, id.size)
    }

    @Test
    fun `flipping one input bit changes most output bits`() {
        // A fixed-IV AES-GCM output of a known label changes exactly one output bit per
        // flipped input bit. HKDF's output has no such linear relation to its input.
        val ikm = ByteArray(32) { (it * 13 + 5).toByte() }
        val flipped = ikm.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }

        val differingBits = AndroidStorage.deriveDatabaseKey(ikm, tempDir)
            .zip(AndroidStorage.deriveDatabaseKey(flipped, tempDir))
            .sumOf { (a, b) -> Integer.bitCount((a.toInt() xor b.toInt()) and 0xFF) }

        assertTrue(differingBits > 64, "expected an avalanche over 256 output bits, saw $differingBits")
    }

    @Test
    fun `raw key literal is x quote 64 lowercase hex quote`() {
        val key = ByteArray(32) { (it * 9 + 0xA0).toByte() }
        val literal = String(AndroidStorage.rawKeyLiteral(key), Charsets.US_ASCII)
        val expectedHex = key.joinToString("") { "%02x".format(it.toInt() and 0xFF) }

        assertEquals("x'$expectedHex'", literal)
        assertEquals(67, literal.length)
    }

    // -------------------------------------------------------------------
    // AndroidStorage instances and storage directories
    // -------------------------------------------------------------------

    @Test
    fun `two instances over one directory derive the same passphrase`() {
        val ikm = ByteArray(32) { (it * 11).toByte() }
        val dir = File(tempDir, "same").apply { mkdirs() }

        val first = storageIn(dir).derivePassphrase(ikm)
        val second = storageIn(File(dir.path)).derivePassphrase(ikm.copyOf())

        assertArrayEquals(first, second)
    }

    @Test
    fun `two storage directories derive different passphrases`() {
        val ikm = ByteArray(32) { (it * 11).toByte() }

        val first = storageIn(File(tempDir, "one").apply { mkdirs() }).derivePassphrase(ikm)
        val second = storageIn(File(tempDir, "two").apply { mkdirs() }).derivePassphrase(ikm)

        assertFalse(first.contentEquals(second))
    }

    @Test
    fun `instance passphrase is the raw key literal of the directory's database key`() {
        val ikm = ByteArray(32) { (it + 1).toByte() }
        val dir = File(tempDir, "db").apply { mkdirs() }

        assertArrayEquals(
            AndroidStorage.rawKeyLiteral(AndroidStorage.deriveDatabaseKey(ikm, dir)),
            storageIn(dir).derivePassphrase(ikm),
        )
    }

    @Test
    fun `distinct Keystore MAC outputs yield distinct passphrases`() {
        val storage = storageIn(tempDir)
        val first = storage.derivePassphrase(ByteArray(32) { it.toByte() })
        val second = storage.derivePassphrase(ByteArray(32) { (it + 1).toByte() })
        assertFalse(first.contentEquals(second))
    }

    // -------------------------------------------------------------------
    // Keystore key shape and derivation parameters
    // -------------------------------------------------------------------

    @Test
    fun `the Keystore key is a MAC key, not a cipher key`() {
        // KeyProperties.KEY_ALGORITHM_HMAC_SHA256 is "HmacSHA256".
        assertEquals("HmacSHA256", AndroidStorage.MAC_ALGORITHM)
    }

    @Test
    fun `the HKDF salt label and info prefix match section 17_6`() {
        assertEquals("SCP-SQLCIPHER-KEY-V1", AndroidStorage.SQLCIPHER_SALT_LABEL)
        assertEquals("scp-sqlcipher:", AndroidStorage.SQLCIPHER_INFO_PREFIX)
    }

    @Test
    fun `the MAC label is the one the Keystore key signs`() {
        assertEquals("scp-storage-passphrase", AndroidStorage.DERIVATION_LABEL)
    }

    private fun storageIn(dir: File): AndroidStorage =
        AndroidStorage(object : ContextWrapper(null) {
            override fun getNoBackupFilesDir(): File = dir
        })

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(data)

    private fun range(from: Int, to: Int): ByteArray = ByteArray(to - from + 1) { (from + it).toByte() }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
