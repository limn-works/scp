// AndroidKeyCustodyTest.kt — Unit tests for AndroidKeyCustody (SCP-110)
//
// These tests exercise the software fallback path (Bouncy Castle) since Android Keystore
// is not available in JVM unit tests. AndroidKeyCustodyPseudonymLifecycleTest runs the
// Keystore path (API 33+, CustodyType.HARDWARE) against a fake KeystoreKeys; no on-device
// test of the real Keystore exists yet. Three checks on a hardware handle throw before they
// read Keystore, so a JVM test reaches them: exportSigningKeyBytes's SCP-CRYPTO-4005,
// dhAgree's SCP-CRYPTO-4003 for a peer key that is not 32 bytes, and dhAgree's
// SCP-CRYPTO-4006 for a 32-byte peer key, because a Keystore handle never enters softwareKeys.
//
// Uses InMemorySharedPreferences to inject a test double for EncryptedSharedPreferences,
// allowing verification of Ed25519 key persistence without the Android framework.
//
// Provenance: ADR-027 (Android Platform Adapter), ADR-006 (Platform Abstraction Layer),
// SCP-110 (Implement Android Keystore KeyCustody trait).

package works.limn.scp.android.platform

import android.content.SharedPreferences
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.concurrent.ConcurrentHashMap

/** Decodes lowercase hex. */
private fun hex(text: String): ByteArray =
    ByteArray(text.length / 2) { text.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

/**
 * In-memory [SharedPreferences] test double for [AndroidKeyCustody] persistence tests.
 *
 * Provides the minimal SharedPreferences contract needed by AndroidKeyCustody:
 * [getAll], [getString], [edit] with [putString], [remove], and [apply]/[commit].
 * All other SharedPreferences methods throw [UnsupportedOperationException].
 */
internal class InMemorySharedPreferences : SharedPreferences {
    private val store = ConcurrentHashMap<String, Any?>()

    override fun getAll(): MutableMap<String, *> = store.toMutableMap()

    override fun getString(key: String?, defValue: String?): String? =
        store[key] as? String ?: defValue

    override fun contains(key: String?): Boolean = store.containsKey(key)

    override fun edit(): SharedPreferences.Editor = InMemoryEditor(store)

    override fun getStringSet(key: String?, defValues: MutableSet<String>?) = defValues
    override fun getInt(key: String?, defValue: Int) = defValue
    override fun getLong(key: String?, defValue: Long) = defValue
    override fun getFloat(key: String?, defValue: Float) = defValue
    override fun getBoolean(key: String?, defValue: Boolean) = defValue
    override fun registerOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?,
    ) = Unit
    override fun unregisterOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?,
    ) = Unit

    private class InMemoryEditor(
        private val store: ConcurrentHashMap<String, Any?>,
    ) : SharedPreferences.Editor {
        private val pending = mutableMapOf<String, Any?>()
        private val removals = mutableSetOf<String>()

        override fun putString(key: String?, value: String?): SharedPreferences.Editor {
            if (key != null) { pending[key] = value; removals.remove(key) }
            return this
        }
        override fun remove(key: String?): SharedPreferences.Editor {
            if (key != null) { removals.add(key); pending.remove(key) }
            return this
        }
        override fun apply() { commit() }
        override fun commit(): Boolean {
            removals.forEach { store.remove(it) }
            pending.forEach { (k, v) -> if (v != null) store[k] = v else store.remove(k) }
            removals.clear()
            pending.clear()
            return true
        }
        override fun clear(): SharedPreferences.Editor { store.clear(); return this }
        override fun putStringSet(k: String?, v: MutableSet<String>?) = this
        override fun putInt(k: String?, v: Int) = this
        override fun putLong(k: String?, v: Long) = this
        override fun putFloat(k: String?, v: Float) = this
        override fun putBoolean(k: String?, v: Boolean) = this
    }
}

/**
 * Unit tests for [AndroidKeyCustody]: the software fallback path, plus the three Keystore-handle
 * checks a JVM test reaches.
 *
 * Android Keystore is not available in JVM unit tests. These tests verify:
 * - Software Ed25519 key generation, signing, and public key extraction
 * - Software X25519 key generation and DH agreement, and `SCP-CRYPTO-4003` for a peer key that
 *   is not 32 bytes and `SCP-CRYPTO-4006` for a 32-byte one from dhAgree for a
 *   [CustodyType.HARDWARE] handle, each thrown before it reads Keystore
 * - Pseudonym derivation determinism
 * - Key destruction, and the error codes a destroyed handle yields
 * - Signing-key export: the seed of a software Ed25519 key, `SCP-CRYPTO-4003` for an X25519
 *   key, `SCP-CRYPTO-4006` for a missing key, and
 *   `SCP-CRYPTO-4005` for a [CustodyType.HARDWARE] handle, which throws before it reads Keystore
 * - Error handling (key not found, wrong key type)
 * - Ed25519 key persistence to EncryptedSharedPreferences
 *
 * The Build.VERSION.SDK_INT in JVM tests defaults to 0, which is below
 * API 33 (TIRAMISU), so all Ed25519 keys will use the software path.
 */
class AndroidKeyCustodyTest {

    private lateinit var prefs: InMemorySharedPreferences
    private lateinit var custody: AndroidKeyCustody

    @BeforeEach
    fun setUp() {
        prefs = InMemorySharedPreferences()
        custody = AndroidKeyCustody(prefs)
    }

    // -------------------------------------------------------------------
    // Ed25519 software key generation
    // -------------------------------------------------------------------

    @Nested
    inner class GenerateKeypairEd25519 {

        @Test
        fun `generateKeypair ED25519 returns SOFTWARE custody on JVM`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            assertEquals(CustodyType.SOFTWARE, handle.custodyType)
            assertNotNull(handle.id)
            assertTrue(handle.id.isNotEmpty())
        }

        @Test
        fun `generateKeypair ED25519 produces unique key IDs`() {
            val handle1 = custody.generateKeypair(KeyType.ED25519)
            val handle2 = custody.generateKeypair(KeyType.ED25519)
            assertNotEquals(handle1.id, handle2.id)
        }

        @Test
        fun `generateKeypair ED25519 stores key in softwareKeys map`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            assertTrue(custody.softwareKeys.containsKey(handle.id))
        }
    }

    // -------------------------------------------------------------------
    // X25519 software key generation
    // -------------------------------------------------------------------

    @Nested
    inner class GenerateKeypairX25519 {

        @Test
        fun `generateKeypair X25519 returns SOFTWARE custody`() {
            val handle = custody.generateKeypair(KeyType.X25519)
            assertEquals(CustodyType.SOFTWARE, handle.custodyType)
        }

        @Test
        fun `generateKeypair X25519 stores key in softwareKeys map`() {
            val handle = custody.generateKeypair(KeyType.X25519)
            assertTrue(custody.softwareKeys.containsKey(handle.id))
        }
    }

    // -------------------------------------------------------------------
    // Ed25519 signing
    // -------------------------------------------------------------------

    @Nested
    inner class SignEd25519 {

        @Test
        fun `sign produces valid 64-byte Ed25519 signature`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            val data = "test message for signing".toByteArray(Charsets.UTF_8)
            val signature = custody.sign(handle, data)
            assertEquals(64, signature.size)
        }

        @Test
        fun `sign produces verifiable signature`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            val data = "hello SCP protocol".toByteArray(Charsets.UTF_8)
            val signature = custody.sign(handle, data)
            val publicKeyBytes = custody.publicKey(handle)

            // Verify the signature using Bouncy Castle
            val pubKeyParams = Ed25519PublicKeyParameters(publicKeyBytes, 0)
            val verifier = Ed25519Signer()
            verifier.init(false, pubKeyParams)
            verifier.update(data, 0, data.size)
            assertTrue(verifier.verifySignature(signature))
        }

        @Test
        fun `sign with different data produces different signatures`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            val data1 = "message one".toByteArray(Charsets.UTF_8)
            val data2 = "message two".toByteArray(Charsets.UTF_8)
            val sig1 = custody.sign(handle, data1)
            val sig2 = custody.sign(handle, data2)
            // Ed25519 is deterministic, so different data MUST produce different sigs
            assertTrue(!sig1.contentEquals(sig2))
        }

        @Test
        fun `sign with empty data produces valid signature`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            val signature = custody.sign(handle, ByteArray(0))
            assertEquals(64, signature.size)

            // Verify
            val publicKeyBytes = custody.publicKey(handle)
            val pubKeyParams = Ed25519PublicKeyParameters(publicKeyBytes, 0)
            val verifier = Ed25519Signer()
            verifier.init(false, pubKeyParams)
            verifier.update(ByteArray(0), 0, 0)
            assertTrue(verifier.verifySignature(signature))
        }

        @Test
        fun `sign throws SCP-CRYPTO-4006 for missing key`() {
            val fakeHandle = KeyHandle(id = "nonexistent-key", custodyType = CustodyType.SOFTWARE)
            val exception = assertThrows<ScpException> {
                custody.sign(fakeHandle, "data".toByteArray())
            }
            assertEquals("SCP-CRYPTO-4006", exception.code)
        }

        @Test
        fun `sign throws SCP-CRYPTO-4003 for X25519 key`() {
            val handle = custody.generateKeypair(KeyType.X25519)
            val exception = assertThrows<ScpException> {
                custody.sign(handle, "data".toByteArray())
            }
            assertEquals("SCP-CRYPTO-4003", exception.code)
        }
    }

    // -------------------------------------------------------------------
    // Public key extraction
    // -------------------------------------------------------------------

    @Nested
    inner class PublicKeyExtraction {

        @Test
        fun `publicKey returns 32 bytes for Ed25519`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            val pubKey = custody.publicKey(handle)
            assertEquals(32, pubKey.size)
        }

        @Test
        fun `publicKey returns 32 bytes for X25519`() {
            val handle = custody.generateKeypair(KeyType.X25519)
            val pubKey = custody.publicKey(handle)
            assertEquals(32, pubKey.size)
        }

        @Test
        fun `publicKey is deterministic for same handle`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            val pubKey1 = custody.publicKey(handle)
            val pubKey2 = custody.publicKey(handle)
            assertArrayEquals(pubKey1, pubKey2)
        }

        @Test
        fun `publicKey differs between different keys`() {
            val handle1 = custody.generateKeypair(KeyType.ED25519)
            val handle2 = custody.generateKeypair(KeyType.ED25519)
            val pubKey1 = custody.publicKey(handle1)
            val pubKey2 = custody.publicKey(handle2)
            assertTrue(!pubKey1.contentEquals(pubKey2))
        }

        @Test
        fun `publicKey throws SCP-CRYPTO-4006 for missing key`() {
            val fakeHandle = KeyHandle(id = "nonexistent-key", custodyType = CustodyType.SOFTWARE)
            val exception = assertThrows<ScpException> {
                custody.publicKey(fakeHandle)
            }
            assertEquals("SCP-CRYPTO-4006", exception.code)
        }

        @Test
        fun `Ed25519 X509 SubjectPublicKeyInfo encoding is 44 bytes per RFC 8410`() {
            // Verify the assumption underpinning the check() assertion in publicKeyFromKeystore:
            // Bouncy Castle's Ed25519 SubjectPublicKeyInfo encoding must be exactly 44 bytes
            // (12-byte ASN.1 header + 32-byte raw key). This is the fixed encoding from RFC 8410 §3.
            val handle = custody.generateKeypair(KeyType.ED25519)
            val keyPair = custody.softwareKeys[handle.id]
                ?: error("softwareKeys missing key for ${handle.id}")
            val pubKeyParams = keyPair.public as Ed25519PublicKeyParameters

            // Build the X.509 SubjectPublicKeyInfo encoding the same way Android Keystore would
            val subjectPublicKeyInfo = org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory
                .createSubjectPublicKeyInfo(pubKeyParams)
            val spkiEncoded = subjectPublicKeyInfo.encoded

            assertEquals(44, spkiEncoded.size, "Ed25519 X.509 SPKI must be 44 bytes per RFC 8410")

            // The last 32 bytes must match the raw public key
            val rawKey = pubKeyParams.encoded
            assertEquals(32, rawKey.size)
            assertArrayEquals(rawKey, spkiEncoded.takeLast(32).toByteArray())
        }
    }

    // -------------------------------------------------------------------
    // Key destruction
    // -------------------------------------------------------------------

    @Nested
    inner class DestroyKey {

        @Test
        fun `destroyKey removes Ed25519 key from softwareKeys`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            assertTrue(custody.softwareKeys.containsKey(handle.id))

            val attestation = custody.destroyKey(handle)
            assertEquals(DestructionMethod.SOFTWARE_ONLY, attestation.method)
            assertTrue(attestation.confirmed)
            assertTrue(!custody.softwareKeys.containsKey(handle.id))
        }

        @Test
        fun `destroyKey removes X25519 key from softwareKeys`() {
            val handle = custody.generateKeypair(KeyType.X25519)
            val attestation = custody.destroyKey(handle)
            assertEquals(DestructionMethod.SOFTWARE_ONLY, attestation.method)
            assertTrue(attestation.confirmed)
            assertTrue(!custody.softwareKeys.containsKey(handle.id))
        }

        @Test
        fun `destroyKey makes subsequent sign fail with SCP-CRYPTO-4006`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            custody.destroyKey(handle)

            val exception = assertThrows<ScpException> {
                custody.sign(handle, "data".toByteArray())
            }
            assertEquals("SCP-CRYPTO-4006", exception.code)
        }

        @Test
        fun `destroyKey makes subsequent publicKey fail with SCP-CRYPTO-4006`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            custody.destroyKey(handle)

            val exception = assertThrows<ScpException> {
                custody.publicKey(handle)
            }
            assertEquals("SCP-CRYPTO-4006", exception.code)
        }

        @Test
        fun `destroyKey makes subsequent dhAgree fail with SCP-CRYPTO-4006 or 4003 for a wrong-length peer`() {
            val handle = custody.generateKeypair(KeyType.X25519)
            custody.destroyKey(handle)

            val destroyed = assertThrows<ScpException> {
                custody.dhAgree(handle, ByteArray(32))
            }
            assertEquals("SCP-CRYPTO-4006", destroyed.code)

            // dhAgree checks the peer key's length before it looks up the handle.
            val wrongLength = assertThrows<ScpException> {
                custody.dhAgree(handle, ByteArray(31))
            }
            assertEquals("SCP-CRYPTO-4003", wrongLength.code)
        }

        @Test
        fun `destroyKey throws SCP-CRYPTO-4006 for already-destroyed key`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            custody.destroyKey(handle)

            val exception = assertThrows<ScpException> {
                custody.destroyKey(handle)
            }
            assertEquals("SCP-CRYPTO-4006", exception.code)
        }

        @Test
        fun `destroyKey throws SCP-CRYPTO-4006 for nonexistent key`() {
            val fakeHandle = KeyHandle(id = "nonexistent-key", custodyType = CustodyType.SOFTWARE)
            val exception = assertThrows<ScpException> {
                custody.destroyKey(fakeHandle)
            }
            assertEquals("SCP-CRYPTO-4006", exception.code)
        }
    }

    // -------------------------------------------------------------------
    // X25519 DH agreement
    // -------------------------------------------------------------------

    @Nested
    inner class DhAgree {

        @Test
        fun `dhAgree produces 32-byte shared secret`() {
            val aliceHandle = custody.generateKeypair(KeyType.X25519)
            val bobHandle = custody.generateKeypair(KeyType.X25519)

            val alicePub = custody.publicKey(aliceHandle)
            val bobPub = custody.publicKey(bobHandle)

            val aliceSecret = custody.dhAgree(aliceHandle, bobPub)
            assertEquals(32, aliceSecret.size)
        }

        @Test
        fun `dhAgree is symmetric - both sides derive same secret`() {
            val aliceHandle = custody.generateKeypair(KeyType.X25519)
            val bobHandle = custody.generateKeypair(KeyType.X25519)

            val alicePub = custody.publicKey(aliceHandle)
            val bobPub = custody.publicKey(bobHandle)

            val aliceSecret = custody.dhAgree(aliceHandle, bobPub)
            val bobSecret = custody.dhAgree(bobHandle, alicePub)

            assertArrayEquals(aliceSecret, bobSecret)
        }

        @Test
        fun `dhAgree with different peers produces different secrets`() {
            val aliceHandle = custody.generateKeypair(KeyType.X25519)
            val bobHandle = custody.generateKeypair(KeyType.X25519)
            val charlieHandle = custody.generateKeypair(KeyType.X25519)

            val bobPub = custody.publicKey(bobHandle)
            val charliePub = custody.publicKey(charlieHandle)

            val secretWithBob = custody.dhAgree(aliceHandle, bobPub)
            val secretWithCharlie = custody.dhAgree(aliceHandle, charliePub)

            assertTrue(!secretWithBob.contentEquals(secretWithCharlie))
        }

        @Test
        fun `dhAgree throws SCP-CRYPTO-4006 for missing key`() {
            val fakeHandle = KeyHandle(id = "nonexistent-key", custodyType = CustodyType.SOFTWARE)
            val exception = assertThrows<ScpException> {
                custody.dhAgree(fakeHandle, ByteArray(32))
            }
            assertEquals("SCP-CRYPTO-4006", exception.code)
        }

        @Test
        fun `dhAgree throws SCP-CRYPTO-4006 for a hardware handle and never reads Keystore`() {
            // A Keystore handle has no softwareKeyTypes entry, so dhAgree skips the key-type
            // check and fails the software-key lookup before any Keystore call.
            val hardwareHandle = KeyHandle(id = "keystore-key", custodyType = CustodyType.HARDWARE)
            val exception = assertThrows<ScpException> {
                custody.dhAgree(hardwareHandle, ByteArray(32))
            }
            assertEquals("SCP-CRYPTO-4006", exception.code)
            // The peer length check still runs first for a hardware handle.
            val lengthException = assertThrows<ScpException> {
                custody.dhAgree(hardwareHandle, ByteArray(31))
            }
            assertEquals("SCP-CRYPTO-4003", lengthException.code)
        }

        @Test
        fun `dhAgree throws SCP-CRYPTO-4003 for wrong-size peerPublic`() {
            val handle = custody.generateKeypair(KeyType.X25519)
            for (badSize in listOf(0, 16, 31, 33, 64)) {
                val exception = assertThrows<ScpException> {
                    custody.dhAgree(handle, ByteArray(badSize))
                }
                assertEquals("SCP-CRYPTO-4003", exception.code)
            }
        }

        @Test
        fun `dhAgree lets IllegalStateException escape for an all-zero low-order peer key`() {
            val handle = custody.generateKeypair(KeyType.X25519)
            // A 32-byte peer key passes the length check, so only the low order of the point
            // separates this call from the successful agreements above.
            val exception = assertThrows<IllegalStateException> {
                custody.dhAgree(handle, ByteArray(32))
            }
            // assertThrows fails on an ScpException, which is not an IllegalStateException.
            assertEquals("X25519 agreement failed", exception.message)
        }
    }

    // -------------------------------------------------------------------
    // Pseudonym derivation
    // -------------------------------------------------------------------

    @Nested
    inner class DerivePseudonym {

        @Test
        fun `derivePseudonym is deterministic for same identity and context`() {
            val identityHandle = custody.generateKeypair(KeyType.ED25519)
            val contextId = "deterministic-context".toByteArray(Charsets.UTF_8)

            val point1 = custody.derivePseudonym(identityHandle, contextId)
            val point2 = custody.derivePseudonym(identityHandle, contextId)
            assertArrayEquals(point1, point2)
        }

        @Test
        fun `derivePseudonym produces different keys for different contexts`() {
            val identityHandle = custody.generateKeypair(KeyType.ED25519)
            val contextA = "context-alpha".toByteArray(Charsets.UTF_8)
            val contextB = "context-bravo".toByteArray(Charsets.UTF_8)

            val pubKeyA = custody.derivePseudonym(identityHandle, contextA)
            val pubKeyB = custody.derivePseudonym(identityHandle, contextB)
            assertTrue(!pubKeyA.contentEquals(pubKeyB))
        }

        @Test
        fun `derivePseudonym produces different keys for different identities`() {
            val identity1 = custody.generateKeypair(KeyType.ED25519)
            val identity2 = custody.generateKeypair(KeyType.ED25519)
            val contextId = "same-context".toByteArray(Charsets.UTF_8)

            val pubKey1 = custody.derivePseudonym(identity1, contextId)
            val pubKey2 = custody.derivePseudonym(identity2, contextId)
            assertTrue(!pubKey1.contentEquals(pubKey2))
        }

        @Test
        fun `derivePseudonym throws SCP-CRYPTO-4006 for missing identity key`() {
            val fakeHandle = KeyHandle(id = "nonexistent-key", custodyType = CustodyType.SOFTWARE)
            val exception = assertThrows<ScpException> {
                custody.derivePseudonym(fakeHandle, "ctx".toByteArray())
            }
            assertEquals("SCP-CRYPTO-4006", exception.code)
        }

        @Test
        fun `derivePseudonym throws SCP-CRYPTO-4003 for X25519 identity key`() {
            val x25519Handle = custody.generateKeypair(KeyType.X25519)
            val exception = assertThrows<ScpException> {
                custody.derivePseudonym(x25519Handle, "ctx".toByteArray())
            }
            assertEquals("SCP-CRYPTO-4003", exception.code)
        }

        @Test
        fun `derivePseudonym public key is a 33-byte compressed P-256 point`() {
            val identityHandle = custody.generateKeypair(KeyType.ED25519)
            val pubKey = custody.derivePseudonym(
                identityHandle,
                "test-ctx".toByteArray(Charsets.UTF_8),
            )
            assertEquals(33, pubKey.size)
            assertTrue(pubKey[0] == 0x02.toByte() || pubKey[0] == 0x03.toByte())
        }
    }

    // -------------------------------------------------------------------
    // Signing-key export
    // -------------------------------------------------------------------

    @Nested
    inner class ExportSigningKeyBytes {

        @Test
        fun `exportSigningKeyBytes rejects a hardware handle with SCP-CRYPTO-4005 citing ADR-063`() {
            // The hardware branch throws before it reads Android Keystore, so a JVM test reaches it.
            val hardwareHandle = KeyHandle(id = "keystore-key", custodyType = CustodyType.HARDWARE)
            val exception = assertThrows<ScpException> {
                custody.exportSigningKeyBytes(hardwareHandle)
            }
            assertEquals("SCP-CRYPTO-4005", exception.code)
            val message = exception.message.orEmpty()
            assertTrue(message.contains("ADR-063's curve slice"), message)
            // ADR-063 requires every key-export accessor to leave the custody adapters and all
            // three bridges, not only for governance signing, so the message may not narrow the
            // clause.
            assertTrue(message.contains("every key-export accessor"), message)
            assertTrue(!message.contains("for governance signing"), message)
            // The curve slice has not landed, so the message may not state its signer path as current.
            assertTrue(message.contains("has not landed"), message)
            assertTrue(!message.contains("replaces raw-key export"), message)
            assertTrue(!message.contains("GitHub issue"), message)
            // The adapter never reads KeyInfo.securityLevel, so the message may not claim a TEE.
            assertTrue(message.contains("Android Keystore custody"), message)
            assertTrue(!message.contains("TEE"), message)
        }

        @Test
        fun `exportSigningKeyBytes returns the 32-byte seed of a software Ed25519 key`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            val seed = custody.exportSigningKeyBytes(handle)
            assertEquals(32, seed.size)
            // The exported seed regenerates the handle's public key, so it is that key's seed.
            val derivedPublic = Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded
            assertArrayEquals(custody.publicKey(handle), derivedPublic)
        }

        @Test
        fun `exportSigningKeyBytes throws SCP-CRYPTO-4003 for an X25519 key`() {
            val x25519Handle = custody.generateKeypair(KeyType.X25519)
            val exception = assertThrows<ScpException> {
                custody.exportSigningKeyBytes(x25519Handle)
            }
            assertEquals("SCP-CRYPTO-4003", exception.code)
        }

        @Test
        fun `exportSigningKeyBytes throws SCP-CRYPTO-4006 for a missing software key`() {
            val missing = KeyHandle(id = "nonexistent-key", custodyType = CustodyType.SOFTWARE)
            val exception = assertThrows<ScpException> {
                custody.exportSigningKeyBytes(missing)
            }
            assertEquals("SCP-CRYPTO-4006", exception.code)
        }
    }

    // -------------------------------------------------------------------
    // Type safety and error handling
    // -------------------------------------------------------------------

    @Nested
    inner class TypeSafety {

        @Test
        fun `ScpException carries correct error code`() {
            val exception = ScpException("test message", "SCP-CRYPTO-4006")
            assertEquals("SCP-CRYPTO-4006", exception.code)
            assertEquals("test message", exception.message)
        }

        @Test
        fun `KeyHandle equality works correctly`() {
            val handle1 = KeyHandle(id = "abc", custodyType = CustodyType.SOFTWARE)
            val handle2 = KeyHandle(id = "abc", custodyType = CustodyType.SOFTWARE)
            val handle3 = KeyHandle(id = "def", custodyType = CustodyType.SOFTWARE)
            assertEquals(handle1, handle2)
            assertNotEquals(handle1, handle3)
        }

        @Test
        fun `DestructionAttestation equality works correctly`() {
            val att1 = DestructionAttestation(
                method = DestructionMethod.SOFTWARE_ONLY,
                confirmed = true,
            )
            val att2 = DestructionAttestation(
                method = DestructionMethod.SOFTWARE_ONLY,
                confirmed = true,
            )
            assertEquals(att1, att2)
        }
    }

    // -------------------------------------------------------------------
    // Concurrency safety (basic)
    // -------------------------------------------------------------------

    @Nested
    inner class ConcurrencySafety {

        @Test
        fun `multiple keys can be generated and used independently`() {
            val handles = (1..10).map { custody.generateKeypair(KeyType.ED25519) }
            val data = "concurrent signing test".toByteArray(Charsets.UTF_8)

            handles.forEach { handle ->
                val signature = custody.sign(handle, data)
                assertEquals(64, signature.size)

                val pubKey = custody.publicKey(handle)
                assertEquals(32, pubKey.size)

                // Verify signature
                val pubKeyParams = Ed25519PublicKeyParameters(pubKey, 0)
                val verifier = Ed25519Signer()
                verifier.init(false, pubKeyParams)
                verifier.update(data, 0, data.size)
                assertTrue(verifier.verifySignature(signature))
            }
        }

        @Test
        fun `destroying one key does not affect others`() {
            val handle1 = custody.generateKeypair(KeyType.ED25519)
            val handle2 = custody.generateKeypair(KeyType.ED25519)

            custody.destroyKey(handle1)

            // handle2 should still work
            val data = "still works".toByteArray(Charsets.UTF_8)
            val signature = custody.sign(handle2, data)
            assertEquals(64, signature.size)

            // handle1 should fail
            assertThrows<ScpException> {
                custody.sign(handle1, data)
            }
        }
    }

    // -------------------------------------------------------------------
    // Ed25519 key persistence
    // -------------------------------------------------------------------

    @Nested
    inner class Ed25519Persistence {

        @Test
        fun `generateKeypair ED25519 persists key to SharedPreferences`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            val prefsKey = "scp.ed25519.${handle.id}"
            assertTrue(prefs.contains(prefsKey))
            assertNotNull(prefs.getString(prefsKey, null))
        }

        @Test
        fun `generateKeypair X25519 does NOT persist to SharedPreferences`() {
            val handle = custody.generateKeypair(KeyType.X25519)
            val prefsKey = "scp.ed25519.${handle.id}"
            assertTrue(!prefs.contains(prefsKey))
        }

        @Test
        fun `restored Ed25519 key produces same public key`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            val originalPubKey = custody.publicKey(handle)

            // Simulate process death: create a new AndroidKeyCustody with the same prefs
            val restored = AndroidKeyCustody(prefs)
            val restoredHandle = KeyHandle(id = handle.id, custodyType = CustodyType.SOFTWARE)
            val restoredPubKey = restored.publicKey(restoredHandle)

            assertArrayEquals(originalPubKey, restoredPubKey)
        }

        @Test
        fun `restored Ed25519 key produces valid signatures`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            val originalPubKey = custody.publicKey(handle)

            // Simulate process death
            val restored = AndroidKeyCustody(prefs)
            val restoredHandle = KeyHandle(id = handle.id, custodyType = CustodyType.SOFTWARE)
            val data = "signed after restore".toByteArray(Charsets.UTF_8)
            val signature = restored.sign(restoredHandle, data)

            // Verify with the original public key
            val pubKeyParams = Ed25519PublicKeyParameters(originalPubKey, 0)
            val verifier = Ed25519Signer()
            verifier.init(false, pubKeyParams)
            verifier.update(data, 0, data.size)
            assertTrue(verifier.verifySignature(signature))
        }

        @Test
        fun `destroyKey removes Ed25519 key from SharedPreferences`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            val prefsKey = "scp.ed25519.${handle.id}"
            assertTrue(prefs.contains(prefsKey))

            custody.destroyKey(handle)
            assertTrue(!prefs.contains(prefsKey))
        }

        @Test
        fun `destroyKey prevents restoration of Ed25519 key`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            custody.destroyKey(handle)

            // Simulate process death — destroyed key should not be restored
            val restored = AndroidKeyCustody(prefs)
            assertThrows<ScpException> {
                restored.publicKey(
                    KeyHandle(id = handle.id, custodyType = CustodyType.SOFTWARE),
                )
            }
        }

        @Test
        fun `destroyKey on one instance leaves the key signing on another instance that restored it`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            val originalPubKey = custody.publicKey(handle)
            val other = AndroidKeyCustody(prefs)

            custody.destroyKey(handle)

            val exception = assertThrows<ScpException> {
                custody.sign(handle, "data".toByteArray())
            }
            assertEquals("SCP-CRYPTO-4006", exception.code)

            val data = "signed after another instance destroyed the key".toByteArray(Charsets.UTF_8)
            val signature = other.sign(handle, data)
            val verifier = Ed25519Signer()
            verifier.init(false, Ed25519PublicKeyParameters(originalPubKey, 0))
            verifier.update(data, 0, data.size)
            assertTrue(verifier.verifySignature(signature))
        }

        @Test
        fun `multiple Ed25519 keys are all persisted and restored`() {
            val handles = (1..5).map { custody.generateKeypair(KeyType.ED25519) }
            val pubKeys = handles.map { custody.publicKey(it) }

            // Simulate process death
            val restored = AndroidKeyCustody(prefs)
            handles.forEachIndexed { idx, handle ->
                val restoredHandle = KeyHandle(id = handle.id, custodyType = CustodyType.SOFTWARE)
                val restoredPubKey = restored.publicKey(restoredHandle)
                assertArrayEquals(pubKeys[idx], restoredPubKey)
            }
        }

        @Test
        fun `deriving a pseudonym persists nothing to SharedPreferences`() {
            val identityHandle = custody.generateKeypair(KeyType.ED25519)
            val before = prefs.all.toMap()
            custody.derivePseudonym(identityHandle, "test-ctx".toByteArray(Charsets.UTF_8))
            custody.deriveRotatablePseudonym(identityHandle, "test-ctx".toByteArray(Charsets.UTF_8), 1L)

            assertTrue(prefs.contains("scp.ed25519.${identityHandle.id}"))
            assertEquals(before, prefs.all.toMap())
        }
    }

    // -------------------------------------------------------------------
    // Known-answer tests for pseudonym derivation (spec §25.19)
    //
    // Pins the software-custody P-256 pseudonym points for the §25.19 vectors 30
    // and 31 over context "context-alpha", proving the Kotlin adapter matches the
    // cross-platform recipe (§9.10.4.A). The seed-to-scalar step under the §25.2
    // label "SCP-TEST-VECTOR-KEY-V1" is pinned by spec_25_19_vectors_30_31 in
    // crates/scp-crypto/src/pseudonym.rs; the adapter's ikm is its Ed25519 seed, so
    // the test installs the literal spec scalar as that seed.
    //   pseudonym_secret = HKDF-SHA256(ikm, salt="scp-pseudonym-secret-v1")
    //   v1 seed          = HMAC-SHA256(secret, ctx || "scp-pseudonym")
    //   v2 seed          = HMAC-SHA256(secret, ctx || BE64(epoch) || "scp-pseudonym-v2")
    //   d                = HKDF-Expand(seed, "SCP-PSEUDONYM-P256-V1", 48) mod (n-1) + 1
    //   pseudonym        = SEC1-compressed(d * G)
    // -------------------------------------------------------------------

    @Nested
    inner class PseudonymKnownAnswerVectors {

        @Test
        fun `vector 30 static and rotatable pseudonyms match spec bytes`() {
            assertVectorMatches(
                expectedScalar = "32c69e4a096fadd1a8d0a21e0a97f124d5c4c8c5b15b96027beadb91c2f3ec64",
                expectedV1 = "0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72",
                expectedV2Epoch1 = "0276c50b92dacbe6ae1a3761d007b7fe75016a4c076f214694c95d13162ff24479",
            )
        }

        @Test
        fun `vector 31 static and rotatable pseudonyms match spec bytes`() {
            assertVectorMatches(
                expectedScalar = "65d56a863d03d31ea15ade82f677058d5bbe53afedc6ff7d2b8846aa25a1bc2b",
                expectedV1 = "0239f7c3213f3567183fd2fcf7aec6c884bc70e0e694c42053284a4b5ebef4fe2d",
                expectedV2Epoch1 = "037967cfe8d3111cdd72288ea3f444c15b710300323162fec63ca9036af73754e3",
            )
        }

        /**
         * Injects the spec identity scalar as the Ed25519 seed, then asserts that v1
         * [derivePseudonym] and v2 [AndroidKeyCustody.deriveRotatablePseudonym] (epoch 1) over
         * context "context-alpha" produce the spec-pinned public key bytes, and that v1 and v2
         * are distinct.
         */
        private fun assertVectorMatches(
            expectedScalar: String,
            expectedV1: String,
            expectedV2Epoch1: String,
        ) {
            val identityHandle = injectSoftwareEd25519(hex(expectedScalar))
            val contextAlpha = "context-alpha".toByteArray(Charsets.UTF_8)

            val v1Hex = custody.derivePseudonym(identityHandle, contextAlpha).toHexString()
            assertEquals(expectedV1, v1Hex)

            val v2Hex = custody.deriveRotatablePseudonym(identityHandle, contextAlpha, 1L).toHexString()
            assertEquals(expectedV2Epoch1, v2Hex)

            assertNotEquals(v1Hex, v2Hex)
        }

        /**
         * Inserts a deterministic software Ed25519 identity key built from [seed] directly
         * into the custody's internal software-key maps, returning a [KeyHandle] for it.
         *
         * Bypasses [AndroidKeyCustody.generateKeypair] (which uses a random seed) so the KAT
         * can pin a known identity seed (§25.19 vectors). Software path only — JVM unit tests
         * cannot reach the Android Keystore hardware path.
         */
        private fun injectSoftwareEd25519(seed: ByteArray): KeyHandle {
            val privateParams = Ed25519PrivateKeyParameters(seed, 0)
            val publicParams = privateParams.generatePublicKey()
            val keyId = "kat-${seed.toHexString().take(8)}"
            custody.softwareKeys[keyId] = AsymmetricCipherKeyPair(publicParams, privateParams)
            custody.softwareKeyTypes[keyId] = KeyType.ED25519
            return KeyHandle(id = keyId, custodyType = CustodyType.SOFTWARE)
        }

        private fun ByteArray.toHexString(): String =
            joinToString("") { byte -> "%02x".format(byte) }
    }
}
