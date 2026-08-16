// StorageKeyDerivationTest.kt — the SQLCipher passphrase derivation (SCP-113)
//
// These tests pin AndroidStorage.deriveDatabaseKey to HKDF-SHA-256 with the salt and
// info that section 17.6 of .docs/specs/17-persistence-and-storage.md fixes for the
// SQLCipher key.
//
// An earlier revision of AndroidStorage derived the passphrase by encrypting the fixed
// label "scp-storage-passphrase" with AES-GCM under an all-zero IV and truncating the
// ciphertext to 32 bytes. `derivation matches an independent HKDF-SHA-256 computation`
// and `flipping one input bit changes most output bits` both fail against that
// construction: the first because a truncated GCM ciphertext is not an HKDF output, the
// second because a fixed-IV GCM ciphertext of a known plaintext changes one output bit
// per flipped plaintext bit.
//
// These tests run on a plain JVM. They call deriveDatabaseKey, which reads only its
// argument and the constants beside it, so no Android Keystore is required. The Keystore
// half of getOrCreateStorageKey — generating the HMAC key and computing the TEE MAC —
// needs an instrumented test on a device.
//
// This file uses JUnit 4 because the :scp-kt-android unit-test tasks run the JUnit 4
// runner: build.gradle.kts never calls useJUnitPlatform(), so a JUnit 5 test in this
// module is compiled and then never executed.
//
// Provenance: ADR-027 (Android Platform Adapter), section 17.6 of
// .docs/specs/17-persistence-and-storage.md (SQLCipher key derivation), RFC 5869 (HKDF).

package works.limn.scp.android.platform

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Tests for [Hkdf] and for [AndroidStorage.deriveDatabaseKey].
 */
class StorageKeyDerivationTest {

    // -------------------------------------------------------------------
    // Hkdf against RFC 5869 Appendix A
    // -------------------------------------------------------------------

    @Test
    fun `hkdf matches RFC 5869 test case 1 for the first 32 bytes`() {
        // RFC 5869 A.1: SHA-256, IKM = 0x0b x 22, salt = 0x000102..0c, info = 0xf0f1..f9,
        // L = 42. The first HKDF-Expand block T(1) is the first 32 bytes of that OKM,
        // which is what a 32-byte request returns.
        val ikm = ByteArray(22) { 0x0b }
        val salt = hex("000102030405060708090a0b0c")
        val info = hex("f0f1f2f3f4f5f6f7f8f9")
        val okm42 = "3cb25f25faacd57a90434f64d0362f2a" +
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
            "34007208d5b887185865"

        val actual = Hkdf.sha256(ikm, salt, info, Hkdf.SHA256_OUTPUT_BYTES)

        assertArrayEquals(hex(okm42.substring(0, 64)), actual)
    }

    @Test
    fun `hkdf matches RFC 5869 test case 2 for the first 32 bytes`() {
        // RFC 5869 A.2: SHA-256, 80-byte IKM, 80-byte salt, 80-byte info, L = 82.
        val ikm = hex((0x00..0x4f).joinToString("") { "%02x".format(it) })
        val salt = hex((0x60..0xaf).joinToString("") { "%02x".format(it) })
        val info = hex((0xb0..0xff).joinToString("") { "%02x".format(it) })
        val firstBlock = "b11e398dc80327a1c8e7f78c596a4934" +
            "4f012eda2d4efad8a050cc4c19afa97c"

        val actual = Hkdf.sha256(ikm, salt, info, Hkdf.SHA256_OUTPUT_BYTES)

        assertArrayEquals(hex(firstBlock), actual)
    }

    @Test
    fun `hkdf truncates to the requested length`() {
        val okm = Hkdf.sha256(ByteArray(22) { 0x0b }, hex("000102030405060708090a0b0c"), hex("f0f1"), 16)
        assertEquals(16, okm.size)
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
    // AndroidStorage.deriveDatabaseKey
    // -------------------------------------------------------------------

    @Test
    fun `derivation matches an independent HKDF-SHA-256 computation`() {
        // This test computes HKDF-SHA-256 from RFC 5869's two steps directly, without
        // calling Hkdf, so it checks the primitive AndroidStorage uses rather than
        // restating Hkdf's own output. A derivation that encrypts a label and truncates
        // the ciphertext fails this assertion.
        val ikm = ByteArray(32) { (it * 7 + 3).toByte() }

        val salt = MessageDigest.getInstance("SHA-256")
            .digest(AndroidStorage.SQLCIPHER_SALT_LABEL.toByteArray(Charsets.UTF_8))
        val prkMac = Mac.getInstance("HmacSHA256")
        prkMac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = prkMac.doFinal(ikm)
        val okmMac = Mac.getInstance("HmacSHA256")
        okmMac.init(SecretKeySpec(prk, "HmacSHA256"))
        okmMac.update(AndroidStorage.SQLCIPHER_INFO.toByteArray(Charsets.UTF_8))
        okmMac.update(byteArrayOf(0x01))
        val expected = okmMac.doFinal()

        assertArrayEquals(expected, AndroidStorage.deriveDatabaseKey(ikm))
    }

    @Test
    fun `derivation returns exactly 32 bytes as section 17_6 requires`() {
        assertEquals(32, AndroidStorage.DATABASE_KEY_LENGTH)
        assertEquals(32, AndroidStorage.deriveDatabaseKey(ByteArray(32) { it.toByte() }).size)
    }

    @Test
    fun `derivation returns 32 bytes for an input of any length`() {
        assertEquals(32, AndroidStorage.deriveDatabaseKey(ByteArray(1)).size)
        assertEquals(32, AndroidStorage.deriveDatabaseKey(ByteArray(64) { it.toByte() }).size)
    }

    @Test
    fun `derivation is deterministic for the same input keying material`() {
        val ikm = ByteArray(32) { (it * 11).toByte() }
        assertArrayEquals(
            AndroidStorage.deriveDatabaseKey(ikm),
            AndroidStorage.deriveDatabaseKey(ikm.copyOf()),
        )
    }

    @Test
    fun `distinct input keying material yields distinct passphrases`() {
        val first = AndroidStorage.deriveDatabaseKey(ByteArray(32) { it.toByte() })
        val second = AndroidStorage.deriveDatabaseKey(ByteArray(32) { (it + 1).toByte() })
        assertFalse(first.contentEquals(second))
    }

    @Test
    fun `flipping one input bit changes most output bits`() {
        // A fixed-IV AES-GCM ciphertext of a known label changes exactly one output bit
        // per flipped input bit, because the keystream does not depend on the plaintext.
        // HKDF's output has no such linear relation to its input.
        val ikm = ByteArray(32) { (it * 13 + 5).toByte() }
        val flipped = ikm.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }

        val differingBits = AndroidStorage.deriveDatabaseKey(ikm)
            .zip(AndroidStorage.deriveDatabaseKey(flipped))
            .sumOf { (a, b) -> Integer.bitCount((a.toInt() xor b.toInt()) and 0xFF) }

        assertTrue(
            "expected an avalanche over 256 output bits, saw $differingBits differing bits",
            differingBits > 64,
        )
    }

    // -------------------------------------------------------------------
    // Keystore key shape and derivation parameters
    // -------------------------------------------------------------------

    @Test
    fun `the Keystore key is a MAC key, not a cipher key`() {
        // KeyProperties.KEY_ALGORITHM_HMAC_SHA256 is "HmacSHA256". A cipher-based
        // derivation would name a transformation such as "AES/GCM/NoPadding" here.
        assertEquals("HmacSHA256", AndroidStorage.MAC_ALGORITHM)
    }

    @Test
    fun `the alias is unchanged so an old-format device fails closed`() {
        // Reusing the alias makes Mac.init reject the AES key that the AES-GCM revision
        // left behind. A new alias would instead open a fresh empty database beside the
        // unreadable old one.
        assertEquals("scp.storage.key", AndroidStorage.KEY_ALIAS)
    }

    @Test
    fun `the HKDF info binds the derivation to the Keystore alias`() {
        assertEquals("scp-sqlcipher:${AndroidStorage.KEY_ALIAS}", AndroidStorage.SQLCIPHER_INFO)
    }

    @Test
    fun `the HKDF salt label matches section 17_6`() {
        assertEquals("SCP-SQLCIPHER-KEY-V1", AndroidStorage.SQLCIPHER_SALT_LABEL)
    }

    @Test
    fun `the MAC label is the one the TEE signs`() {
        assertEquals("scp-storage-passphrase", AndroidStorage.DERIVATION_LABEL)
    }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
