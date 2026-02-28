// AndroidKeyCustodyTest.kt — Unit tests for AndroidKeyCustody (SCP-110)
//
// These tests exercise the software fallback path (Bouncy Castle) since Android Keystore
// is not available in JVM unit tests. The Keystore path (API 33+, CustodyType.HARDWARE)
// requires an Android device or emulator and is tested via instrumented tests.
//
// Provenance: ADR-027 (Android Platform Adapter), ADR-006 (Platform Abstraction Layer),
// SCP-110 (Implement Android Keystore KeyCustody trait).

package com.limn.scp.android.platform

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

/**
 * Unit tests for [AndroidKeyCustody] software fallback path.
 *
 * Android Keystore is not available in JVM unit tests. These tests verify:
 * - Software Ed25519 key generation, signing, and public key extraction
 * - Software X25519 key generation and DH agreement
 * - Pseudonym derivation determinism
 * - Key destruction
 * - Error handling (key not found, wrong key type)
 *
 * The Build.VERSION.SDK_INT in JVM tests defaults to 0, which is below
 * API 33 (TIRAMISU), so all Ed25519 keys will use the software path.
 */
class AndroidKeyCustodyTest {

    private lateinit var custody: AndroidKeyCustody

    @BeforeEach
    fun setUp() {
        custody = AndroidKeyCustody()
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
        fun `sign throws SCP-CRYPTO-4001 for missing key`() {
            val fakeHandle = KeyHandle(id = "nonexistent-key", custodyType = CustodyType.SOFTWARE)
            val exception = assertThrows<ScpException> {
                custody.sign(fakeHandle, "data".toByteArray())
            }
            assertEquals("SCP-CRYPTO-4001", exception.errorCode)
        }

        @Test
        fun `sign throws SCP-CRYPTO-4003 for X25519 key`() {
            val handle = custody.generateKeypair(KeyType.X25519)
            val exception = assertThrows<ScpException> {
                custody.sign(handle, "data".toByteArray())
            }
            assertEquals("SCP-CRYPTO-4003", exception.errorCode)
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
        fun `publicKey throws SCP-CRYPTO-4001 for missing key`() {
            val fakeHandle = KeyHandle(id = "nonexistent-key", custodyType = CustodyType.SOFTWARE)
            val exception = assertThrows<ScpException> {
                custody.publicKey(fakeHandle)
            }
            assertEquals("SCP-CRYPTO-4001", exception.errorCode)
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
        fun `destroyKey makes subsequent sign fail with SCP-CRYPTO-4001`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            custody.destroyKey(handle)

            val exception = assertThrows<ScpException> {
                custody.sign(handle, "data".toByteArray())
            }
            assertEquals("SCP-CRYPTO-4001", exception.errorCode)
        }

        @Test
        fun `destroyKey makes subsequent publicKey fail with SCP-CRYPTO-4001`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            custody.destroyKey(handle)

            val exception = assertThrows<ScpException> {
                custody.publicKey(handle)
            }
            assertEquals("SCP-CRYPTO-4001", exception.errorCode)
        }

        @Test
        fun `destroyKey throws SCP-CRYPTO-4001 for already-destroyed key`() {
            val handle = custody.generateKeypair(KeyType.ED25519)
            custody.destroyKey(handle)

            val exception = assertThrows<ScpException> {
                custody.destroyKey(handle)
            }
            assertEquals("SCP-CRYPTO-4001", exception.errorCode)
        }

        @Test
        fun `destroyKey throws SCP-CRYPTO-4001 for nonexistent key`() {
            val fakeHandle = KeyHandle(id = "nonexistent-key", custodyType = CustodyType.SOFTWARE)
            val exception = assertThrows<ScpException> {
                custody.destroyKey(fakeHandle)
            }
            assertEquals("SCP-CRYPTO-4001", exception.errorCode)
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
        fun `dhAgree throws SCP-CRYPTO-4002 for missing key`() {
            val fakeHandle = KeyHandle(id = "nonexistent-key", custodyType = CustodyType.SOFTWARE)
            val exception = assertThrows<ScpException> {
                custody.dhAgree(fakeHandle, ByteArray(32))
            }
            assertEquals("SCP-CRYPTO-4002", exception.errorCode)
        }
    }

    // -------------------------------------------------------------------
    // Pseudonym derivation
    // -------------------------------------------------------------------

    @Nested
    inner class DerivePseudonym {

        @Test
        fun `derivePseudonym returns SOFTWARE custody`() {
            val identityHandle = custody.generateKeypair(KeyType.ED25519)
            val contextId = "test-context-id".toByteArray(Charsets.UTF_8)

            val pseudonym = custody.derivePseudonym(identityHandle, contextId)
            assertEquals(CustodyType.SOFTWARE, pseudonym.custodyType)
            assertNotNull(pseudonym.id)
            assertTrue(pseudonym.id.isNotEmpty())
        }

        @Test
        fun `derivePseudonym produces signable key`() {
            val identityHandle = custody.generateKeypair(KeyType.ED25519)
            val contextId = "test-context".toByteArray(Charsets.UTF_8)

            val pseudonym = custody.derivePseudonym(identityHandle, contextId)

            // The pseudonym key should be usable for signing
            val pseudonymKeyHandle = KeyHandle(
                id = pseudonym.id,
                custodyType = pseudonym.custodyType,
            )
            val data = "pseudonym signed message".toByteArray(Charsets.UTF_8)
            val signature = custody.sign(pseudonymKeyHandle, data)
            assertEquals(64, signature.size)

            // Verify signature
            val pubKeyBytes = custody.publicKey(pseudonymKeyHandle)
            val pubKeyParams = Ed25519PublicKeyParameters(pubKeyBytes, 0)
            val verifier = Ed25519Signer()
            verifier.init(false, pubKeyParams)
            verifier.update(data, 0, data.size)
            assertTrue(verifier.verifySignature(signature))
        }

        @Test
        fun `derivePseudonym is deterministic for same identity and context`() {
            val identityHandle = custody.generateKeypair(KeyType.ED25519)
            val contextId = "deterministic-context".toByteArray(Charsets.UTF_8)

            val pseudonym1 = custody.derivePseudonym(identityHandle, contextId)
            val pseudonym2 = custody.derivePseudonym(identityHandle, contextId)

            // Public keys must be identical (deterministic derivation)
            val pubKey1Handle = KeyHandle(id = pseudonym1.id, custodyType = pseudonym1.custodyType)
            val pubKey2Handle = KeyHandle(id = pseudonym2.id, custodyType = pseudonym2.custodyType)
            val pubKey1 = custody.publicKey(pubKey1Handle)
            val pubKey2 = custody.publicKey(pubKey2Handle)
            assertArrayEquals(pubKey1, pubKey2)
        }

        @Test
        fun `derivePseudonym produces different keys for different contexts`() {
            val identityHandle = custody.generateKeypair(KeyType.ED25519)
            val contextA = "context-alpha".toByteArray(Charsets.UTF_8)
            val contextB = "context-bravo".toByteArray(Charsets.UTF_8)

            val pseudonymA = custody.derivePseudonym(identityHandle, contextA)
            val pseudonymB = custody.derivePseudonym(identityHandle, contextB)

            val pubKeyA = custody.publicKey(
                KeyHandle(id = pseudonymA.id, custodyType = pseudonymA.custodyType),
            )
            val pubKeyB = custody.publicKey(
                KeyHandle(id = pseudonymB.id, custodyType = pseudonymB.custodyType),
            )
            assertTrue(!pubKeyA.contentEquals(pubKeyB))
        }

        @Test
        fun `derivePseudonym produces different keys for different identities`() {
            val identity1 = custody.generateKeypair(KeyType.ED25519)
            val identity2 = custody.generateKeypair(KeyType.ED25519)
            val contextId = "same-context".toByteArray(Charsets.UTF_8)

            val pseudonym1 = custody.derivePseudonym(identity1, contextId)
            val pseudonym2 = custody.derivePseudonym(identity2, contextId)

            val pubKey1 = custody.publicKey(
                KeyHandle(id = pseudonym1.id, custodyType = pseudonym1.custodyType),
            )
            val pubKey2 = custody.publicKey(
                KeyHandle(id = pseudonym2.id, custodyType = pseudonym2.custodyType),
            )
            assertTrue(!pubKey1.contentEquals(pubKey2))
        }

        @Test
        fun `derivePseudonym throws SCP-CRYPTO-4001 for missing identity key`() {
            val fakeHandle = KeyHandle(id = "nonexistent-key", custodyType = CustodyType.SOFTWARE)
            val exception = assertThrows<ScpException> {
                custody.derivePseudonym(fakeHandle, "ctx".toByteArray())
            }
            assertEquals("SCP-CRYPTO-4001", exception.errorCode)
        }

        @Test
        fun `derivePseudonym throws SCP-CRYPTO-4003 for X25519 identity key`() {
            val x25519Handle = custody.generateKeypair(KeyType.X25519)
            val exception = assertThrows<ScpException> {
                custody.derivePseudonym(x25519Handle, "ctx".toByteArray())
            }
            assertEquals("SCP-CRYPTO-4003", exception.errorCode)
        }

        @Test
        fun `derivePseudonym public key is 32 bytes`() {
            val identityHandle = custody.generateKeypair(KeyType.ED25519)
            val pseudonym = custody.derivePseudonym(
                identityHandle,
                "test-ctx".toByteArray(Charsets.UTF_8),
            )
            val pubKey = custody.publicKey(
                KeyHandle(id = pseudonym.id, custodyType = pseudonym.custodyType),
            )
            assertEquals(32, pubKey.size)
        }
    }

    // -------------------------------------------------------------------
    // Type safety and error handling
    // -------------------------------------------------------------------

    @Nested
    inner class TypeSafety {

        @Test
        fun `ScpException carries correct error code`() {
            val exception = ScpException("test message", "SCP-CRYPTO-4001")
            assertEquals("SCP-CRYPTO-4001", exception.errorCode)
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
        fun `PseudonymKeyHandle equality works correctly`() {
            val handle1 = PseudonymKeyHandle(id = "abc", custodyType = CustodyType.SOFTWARE)
            val handle2 = PseudonymKeyHandle(id = "abc", custodyType = CustodyType.SOFTWARE)
            assertEquals(handle1, handle2)
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
}
