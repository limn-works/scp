// AndroidKeyCustodyP256Test.kt — the P-256 signing and HPKE P-256 agreement keys of
// AndroidKeyCustody, on the JVM.
//
// JcaFakeKeystoreKeys stands in for Android Keystore with real SunEC keys, so every output is
// checked against the bridge itself: signatures through TestingCallbackCustody and the strict
// verifier, agreements against the bridge's ECDH oracle. The emulator lane checks what the fake
// cannot (Keystore's DIGEST_NONE rule, PURPOSE_AGREE_KEY, a real KeyInfo).
//
// Provenance: ADR-027 (Android Platform Adapter) criteria 1-5, spec 09 §9.5 (P-256 keys),
// RFC 9180 §7.1.1 (DH of DHKEM(P-256)).

package works.limn.scp.android.platform

import android.content.SharedPreferences
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Base64
import kotlinx.coroutines.test.runTest
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.util.BigIntegers
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.fail
import uniffi.scp.CustodyKeyRole
import uniffi.scp.CustodyKeyType
import uniffi.scp.TestingCallbackCustody
import uniffi.scp.testingP256Ecdh
import uniffi.scp.testingP256VerifyStrict
import uniffi.scp.ScpException as BridgeException

private val CURVE = SECNamedCurves.getByName("secp256r1")

/** This test process's tag, as the instances under test see it. */
private const val TAG = "100:200"

/** A tag no instance under test holds: a process that died mid-mint. */
private const val FOREIGN_TAG = "77:1"

/** A uniformly random scalar in [1, n − 1], as 32 bytes. */
private fun randomScalar(): ByteArray {
    val random = SecureRandom()
    while (true) {
        val d = BigInteger(256, random)
        if (d.signum() > 0 && d < CURVE.n) return BigIntegers.asUnsignedByteArray(32, d)
    }
}

/** The 65-byte uncompressed point of [scalar]. */
private fun pointOf(scalar: ByteArray): ByteArray =
    CURVE.g.multiply(BigInteger(1, scalar)).normalize().getEncoded(false)

private fun digest(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

/** The custody error code [block] throws. */
private fun codeOf(block: () -> Unit): String = assertThrows<ScpException> { block() }.code

/** The bridge error [block] throws. */
private suspend fun bridgeError(block: suspend () -> Unit): BridgeException {
    try {
        block()
    } catch (e: BridgeException) {
        return e
    }
    fail("expected uniffi.scp.ScpException")
}

/**
 * [SharedPreferences] over [inner] whose `commit()` returns false for an editor that writes a key
 * starting with [failPrefix]; every other editor commits to [inner].
 */
private class RefusingPrefs(
    private val inner: SharedPreferences,
    private val failPrefix: String,
) : SharedPreferences by inner {
    override fun edit(): SharedPreferences.Editor = Editor(inner.edit())

    private inner class Editor(private val delegate: SharedPreferences.Editor) : SharedPreferences.Editor by delegate {
        private var refused = false

        override fun putString(key: String?, value: String?): SharedPreferences.Editor {
            if (key != null && key.startsWith(failPrefix)) refused = true
            delegate.putString(key, value)
            return this
        }

        override fun remove(key: String?): SharedPreferences.Editor {
            delegate.remove(key)
            return this
        }

        override fun commit(): Boolean = !refused && delegate.commit()

        override fun apply() {
            commit()
        }
    }
}

class AndroidKeyCustodyP256Test {
    private lateinit var prefs: InMemorySharedPreferences
    private lateinit var keys: JcaFakeKeystoreKeys

    @BeforeEach
    fun setUp() {
        prefs = InMemorySharedPreferences()
        keys = JcaFakeKeystoreKeys()
    }

    private fun custody(
        agreementInKeystore: Boolean = true,
        store: SharedPreferences = prefs,
        ed25519InKeystore: Boolean = false,
        tag: String = TAG,
    ) = AndroidKeyCustody(store, keys, ed25519InKeystore, agreementInKeystore, tag)

    private fun alias(id: String) = "scp.key.$id"

    /** The ids of every record [prefs] holds. */
    private fun recordIds(): Set<String> = KeyRecords(prefs).ids()

    // -------------------------------------------------------------------
    // Signing
    // -------------------------------------------------------------------

    @Nested
    inner class Signing {
        @Test
        fun `p256 sign through the bridge is raw low-s and verifies strictly`() {
            runTest {
                val bridge = TestingCallbackCustody(UniffiKeyCustody(custody()))
                val id = bridge.generateKeypair(CustodyKeyType.P256)
                val publicKey = bridge.publicKey(id)
                assertEquals(33, publicKey.size)
                repeat(64) {
                    val digest = digest()
                    val signature = bridge.sign(id, digest)
                    assertEquals(64, signature.size)
                    assertTrue(testingP256VerifyStrict(publicKey, digest, signature))
                }
            }
        }

        @Test
        fun `host sign returns a DER signature over the digest`() {
            val custody = custody()
            val handle = custody.generateKeypair(KeyType.P256)
            val signature = custody.sign(handle, digest())
            val sequence = ASN1Sequence.getInstance(signature)
            assertEquals(2, sequence.size())
            for (part in sequence) {
                val value = (part as ASN1Integer).value
                assertTrue(value.signum() > 0 && value < CURVE.n)
            }
        }

        @Test
        fun `sign refuses a digest that is not 32 bytes`() {
            val custody = custody()
            val handle = custody.generateKeypair(KeyType.P256)
            for (size in listOf(0, 31, 33, 64)) {
                assertEquals("SCP-CRYPTO-4060", codeOf { custody.sign(handle, ByteArray(size)) }, "size $size")
            }
        }
    }

    // -------------------------------------------------------------------
    // Agreement
    // -------------------------------------------------------------------

    @Nested
    inner class Agreement {
        @Test
        fun `hpke agreement matches the oracle in both stores, including a secret with a leading zero`() {
            for (inKeystore in listOf(true, false)) {
                val custody = custody(agreementInKeystore = inKeystore)
                val handle = custody.generateKeypair(KeyType.HPKE_P256)
                val hostPublic = custody.publicKey(handle)
                repeat(8) {
                    val peer = randomScalar()
                    assertArrayEquals(testingP256Ecdh(peer, hostPublic), custody.dhAgree(handle, pointOf(peer)))
                }
                // About one peer in 256 gives a secret whose first byte is zero; the custody must
                // return it at full width.
                val (peer, expected) = generateSequence { randomScalar() }
                    .map { it to testingP256Ecdh(it, hostPublic) }
                    .first { it.second[0] == 0.toByte() }
                val secret = custody.dhAgree(handle, pointOf(peer))
                assertEquals(32, secret.size)
                assertArrayEquals(expected, secret, "keystore=$inKeystore")
            }
        }

        @Test
        fun `off-curve, compressed and short peers are refused before the key is used`() {
            val custody = custody()
            val handle = custody.generateKeypair(KeyType.HPKE_P256)
            val valid = pointOf(randomScalar())
            val offCurve = valid.copyOf().also { it[64] = (it[64] + 1).toByte() }
            val compressed = CURVE.g.multiply(BigInteger.TEN).normalize().getEncoded(true)
            val wrongTag = valid.copyOf().also { it[0] = 0x02 }
            val zeros = ByteArray(65).also { it[0] = 0x04 }
            for (peer in listOf(offCurve, compressed, wrongTag, zeros, ByteArray(32), ByteArray(0))) {
                assertEquals("SCP-CRYPTO-4060", codeOf { custody.dhAgree(handle, peer) })
            }
            assertEquals(0, keys.agreeCalls)
        }

        @Test
        fun `the bridge refuses an off-curve peer too`() {
            runTest {
                val bridge = TestingCallbackCustody(UniffiKeyCustody(custody()))
                val id = bridge.generateKeypair(CustodyKeyType.HPKE_P256)
                val offCurve = pointOf(randomScalar()).also { it[64] = (it[64] + 1).toByte() }
                bridgeError { bridge.dhAgree(id, offCurve) }
                assertEquals(0, keys.agreeCalls)
            }
        }

        @Test
        fun `a key reopened by an instance with the other probe keeps its store`() {
            val minted = custody(agreementInKeystore = true)
            val handle = minted.generateKeypair(KeyType.HPKE_P256)
            val hostPublic = minted.publicKey(handle)

            val reopened = custody(agreementInKeystore = false)
            val peer = randomScalar()
            assertArrayEquals(testingP256Ecdh(peer, hostPublic), reopened.dhAgree(handle, pointOf(peer)))
            assertEquals(1, keys.agreeCalls)
            assertNull(prefs.getString("scp.p256.${handle.id}", null))
        }
    }

    // -------------------------------------------------------------------
    // Types, public keys and custody
    // -------------------------------------------------------------------

    @Nested
    inner class TypesAndCustody {
        @Test
        fun `wrong-type operations are refused with SCP-CRYPTO-4060`() {
            val custody = custody()
            val signing = custody.generateKeypair(KeyType.P256)
            val agreement = custody.generateKeypair(KeyType.HPKE_P256)
            val ed25519 = custody.generateKeypair(KeyType.ED25519)
            val peer = pointOf(randomScalar())

            assertEquals("SCP-CRYPTO-4060", codeOf { custody.sign(agreement, digest()) })
            assertEquals("SCP-CRYPTO-4060", codeOf { custody.dhAgree(signing, peer) })
            assertEquals("SCP-CRYPTO-4060", codeOf { custody.dhAgree(ed25519, peer) })
            for (handle in listOf(signing, agreement)) {
                assertEquals("SCP-CRYPTO-4060", codeOf { custody.derivePseudonym(handle, byteArrayOf(1)) })
                assertEquals("SCP-CRYPTO-4060", codeOf { custody.deriveRotatablePseudonym(handle, byteArrayOf(1), 1) })
            }
            assertEquals(0, keys.agreeCalls)
        }

        @Test
        fun `getPublicKey reports each type's encoding and the recorded role`() {
            runTest {
                val provider = UniffiKeyCustody(custody())
                val signingId = provider.generateKeypair(CustodyKeyType.P256, CustodyKeyRole.IDENTITY)
                val signing = provider.getPublicKey(signingId)
                assertEquals(CustodyKeyType.P256, signing.keyType)
                assertEquals(CustodyKeyRole.IDENTITY, signing.role)
                assertEquals(33, signing.publicKey.size)
                assertTrue(signing.publicKey[0] == 0x02.toByte() || signing.publicKey[0] == 0x03.toByte())

                val agreementId = provider.generateKeypair(CustodyKeyType.HPKE_P256, CustodyKeyRole.OPERATIONAL)
                val agreement = provider.getPublicKey(agreementId)
                assertEquals(CustodyKeyType.HPKE_P256, agreement.keyType)
                assertEquals(CustodyKeyRole.OPERATIONAL, agreement.role)
                assertEquals(65, agreement.publicKey.size)
                assertEquals(0x04.toByte(), agreement.publicKey[0])
            }
        }

        @Test
        fun `custody follows what Keystore reports for each key`() {
            runTest {
                val provider = UniffiKeyCustody(custody(agreementInKeystore = true))
                val secure = provider.generateKeypair(CustodyKeyType.P256, CustodyKeyRole.OPERATIONAL)
                keys.secureHardware = false
                val insecure = provider.generateKeypair(CustodyKeyType.P256, CustodyKeyRole.OPERATIONAL)
                val insecureAgreement = provider.generateKeypair(CustodyKeyType.HPKE_P256, CustodyKeyRole.OPERATIONAL)
                keys.secureHardware = true
                val software = UniffiKeyCustody(custody(agreementInKeystore = false))
                    .generateKeypair(CustodyKeyType.HPKE_P256, CustodyKeyRole.OPERATIONAL)

                assertEquals("hardware", provider.custodyType(secure))
                // The record keeps what was read at mint, whatever Keystore reports later.
                assertEquals("software", provider.custodyType(insecure))
                assertEquals("software", provider.custodyType(insecureAgreement))
                assertEquals("software", provider.custodyType(software))
                assertEquals(CustodyType.SOFTWARE, custody().resolveKeyHandle(insecure).custodyType)
            }
        }

        @Test
        fun `an unknown id has in_memory custody`() {
            assertEquals("in_memory", UniffiKeyCustody(custody()).custodyType("12345"))
        }

        @Test
        fun `the probe picks the agreement store`() {
            val inSoftware = custody(agreementInKeystore = false).generateKeypair(KeyType.HPKE_P256)
            assertFalse(keys.containsAlias(alias(inSoftware.id)))
            assertNotNull(prefs.getString("scp.p256.${inSoftware.id}", null))
            assertEquals(Backing.SOFTWARE, KeyRecords(prefs).get(inSoftware.id)?.backing)

            val inKeystore = custody(agreementInKeystore = true).generateKeypair(KeyType.HPKE_P256)
            assertTrue(keys.containsAlias(alias(inKeystore.id)))
            assertNull(prefs.getString("scp.p256.${inKeystore.id}", null))
            assertEquals(Backing.KEYSTORE, KeyRecords(prefs).get(inKeystore.id)?.backing)
        }

        @Test
        fun `Keystore agreement starts at API 31`() {
            assertFalse(keystoreAgreementAvailable(30))
            assertTrue(keystoreAgreementAvailable(31))
            assertTrue(keystoreAgreementAvailable(35))
        }
    }

    // -------------------------------------------------------------------
    // Software HPKE scalars
    // -------------------------------------------------------------------

    @Nested
    inner class SoftwareScalars {
        @Test
        fun `software HPKE keys survive a new instance, each scalar stored at 32 bytes`() {
            val custody = custody(agreementInKeystore = false)
            val handles = (1..16).map { custody.generateKeypair(KeyType.HPKE_P256) }
            val publics = handles.map { custody.publicKey(it) }
            for (handle in handles) {
                val stored = Base64.getDecoder().decode(prefs.getString("scp.p256.${handle.id}", null))
                assertEquals(32, stored.size)
            }

            val restored = custody(agreementInKeystore = true)
            handles.forEachIndexed { index, handle ->
                assertArrayEquals(publics[index], restored.publicKey(handle))
                val peer = randomScalar()
                assertArrayEquals(testingP256Ecdh(peer, publics[index]), restored.dhAgree(handle, pointOf(peer)))
            }
        }

        @Test
        fun `a restored scalar below 2^248 keeps its leading zero byte`() {
            val handle = custody(agreementInKeystore = false).generateKeypair(KeyType.HPKE_P256)
            val small = BigIntegers.asUnsignedByteArray(32, BigInteger(240, SecureRandom()).add(BigInteger.ONE))
            assertEquals(0.toByte(), small[0])
            prefs.edit().putString("scp.p256.${handle.id}", Base64.getEncoder().encodeToString(small)).commit()

            val restored = custody(agreementInKeystore = false)
            val hostPublic = restored.publicKey(handle)
            assertArrayEquals(pointOf(small), hostPublic)
            val peer = randomScalar()
            assertArrayEquals(testingP256Ecdh(peer, hostPublic), restored.dhAgree(handle, pointOf(peer)))
        }

        @Test
        fun `a stored scalar that is not a valid 32-byte scalar fails closed`() {
            val handle = custody(agreementInKeystore = false).generateKeypair(KeyType.HPKE_P256)
            val n = BigIntegers.asUnsignedByteArray(32, CURVE.n)
            for (bad in listOf(ByteArray(31) { 1 }, ByteArray(33) { 1 }, ByteArray(32), n)) {
                prefs.edit().putString("scp.p256.${handle.id}", Base64.getEncoder().encodeToString(bad)).commit()
                val restored = custody(agreementInKeystore = false)
                assertEquals("SCP-CRYPTO-4060", codeOf { restored.publicKey(handle) }, "size ${bad.size}")
            }
        }

        @Test
        fun `the software scalar is committed before generateKeypair returns`() {
            val refusing = custody(agreementInKeystore = false, store = RefusingPrefs(prefs, "scp.p256."))
            assertEquals("SCP-CRYPTO-4060", codeOf { refusing.generateKeypair(KeyType.HPKE_P256) })
            assertTrue(prefs.all.isEmpty(), "left behind: ${prefs.all.keys}")
            assertTrue(refusing.keyRoles.persistedIds().isEmpty())
        }
    }

    // -------------------------------------------------------------------
    // Failed mints
    // -------------------------------------------------------------------

    @Nested
    inner class FailedMints {
        @Test
        fun `a Keystore agreement failure never falls back to software`() {
            keys.failP256Generation = true
            val custody = custody(agreementInKeystore = true)
            for (type in listOf(KeyType.HPKE_P256, KeyType.P256)) {
                val error = assertThrows<ScpException> { custody.generateKeypair(type) }
                assertEquals("SCP-CRYPTO-4060", error.code)
                assertTrue(error.cause is java.security.ProviderException)
            }
            assertTrue(prefs.all.isEmpty(), "left behind: ${prefs.all.keys}")
            assertTrue(keys.p256Aliases.isEmpty())
        }

        @Test
        fun `a failed mint rolls back the key, its record and its role`() {
            keys.hidePublicKey = true
            val custody = custody()
            assertEquals("SCP-CRYPTO-4060", codeOf { custody.generateKeypair(KeyType.P256) })
            assertTrue(keys.p256Aliases.isEmpty())
            assertTrue(prefs.all.isEmpty(), "left behind: ${prefs.all.keys}")
        }

        @Test
        fun `an unconfirmed rollback names the id and keeps the record until destroyKey succeeds`() {
            keys.hidePublicKey = true
            keys.ignoreDeletes = true
            val custody = custody()
            val error = assertThrows<ScpException> { custody.generateKeypair(KeyType.HPKE_P256) }
            assertEquals("SCP-CRYPTO-4060", error.code)
            val id = recordIds().single()
            assertTrue(error.message.orEmpty().contains(id), error.message)
            assertNotNull(error.cause)
            assertEquals(1, error.suppressed.size)
            assertNull(KeyRecords(prefs).get(id)?.custody)
            assertTrue(keys.containsAlias(alias(id)))
            assertEquals("SCP-CRYPTO-4006", codeOf { custody.resolveKeyHandle(id) })

            keys.hidePublicKey = false
            keys.ignoreDeletes = false
            val attestation = custody.destroyKeyById(id)
            assertEquals(DestructionMethod.SOFTWARE_ONLY, attestation.method)
            assertFalse(keys.containsAlias(alias(id)))
            assertTrue(prefs.all.isEmpty(), "left behind: ${prefs.all.keys}")
        }
    }

    // -------------------------------------------------------------------
    // Destroy
    // -------------------------------------------------------------------

    @Nested
    inner class Destroy {
        @Test
        fun `destroy confirms by re-fetch and keeps the record when the alias survives`() {
            val custody = custody()
            val handle = custody.generateKeypair(KeyType.P256)
            keys.ignoreDeletes = true
            assertEquals("SCP-CRYPTO-4060", codeOf { custody.destroyKey(handle) })
            assertNotNull(KeyRecords(prefs).get(handle.id))
            assertTrue(custody.keyRoles.contains(handle.id))

            keys.ignoreDeletes = false
            custody.destroyKey(handle)
            assertFalse(keys.containsAlias(alias(handle.id)))
            assertTrue(prefs.all.isEmpty(), "left behind: ${prefs.all.keys}")
        }

        @Test
        fun `destroy deletes an orphan alias that has no record, below API 33`() {
            keys.generateP256Signing(alias("4242"))
            val custody = custody(ed25519InKeystore = false)
            assertEquals(DestructionMethod.HARDWARE, custody.destroyKeyById("4242").method)
            assertFalse(keys.containsAlias(alias("4242")))
        }

        @Test
        fun `destroying a P-256 key leaves another identity's pseudonym secret alone`() {
            val custody = custody(ed25519InKeystore = true)
            val identity = custody.generateKeypair(KeyType.ED25519)
            val before = custody.derivePseudonym(identity, byteArrayOf(7))
            custody.destroyKey(custody.generateKeypair(KeyType.P256))
            assertArrayEquals(before, custody.derivePseudonym(identity, byteArrayOf(7)))
            assertEquals(1, keys.hmacKeys.size)
        }

        @Test
        fun `a destroyed key is gone and its method follows the recorded custody`() {
            runTest {
                val custody = custody(agreementInKeystore = true)
                val provider = UniffiKeyCustody(custody)
                val hardware = custody.generateKeypair(KeyType.P256)
                keys.secureHardware = false
                val softKeystore = custody.generateKeypair(KeyType.HPKE_P256)
                val software = custody(agreementInKeystore = false).generateKeypair(KeyType.HPKE_P256)

                assertEquals(DestructionMethod.HARDWARE, custody.destroyKey(hardware).method)
                assertEquals(DestructionMethod.SOFTWARE_ONLY, custody.destroyKey(softKeystore).method)
                assertEquals(DestructionMethod.SOFTWARE_ONLY, custody.destroyKey(software).method)

                val peer = pointOf(randomScalar())
                for (handle in listOf(hardware, softKeystore, software)) {
                    assertEquals("SCP-CRYPTO-4006", codeOf { custody.sign(handle, digest()) })
                    assertEquals("SCP-CRYPTO-4006", codeOf { custody.publicKey(handle) })
                    assertEquals("SCP-CRYPTO-4006", codeOf { custody.dhAgree(handle, peer) })
                    assertEquals("SCP-CRYPTO-4006", codeOf { custody.destroyKey(handle) })
                    assertEquals("in_memory", provider.custodyType(handle.id))
                }
                assertTrue(keys.p256Aliases.isEmpty())
                assertTrue(prefs.all.isEmpty(), "left behind: ${prefs.all.keys}")
            }
        }
    }

    // -------------------------------------------------------------------
    // Pending mints left by a crash
    // -------------------------------------------------------------------

    @Nested
    inner class PendingMints {
        @Test
        fun `a new instance sweeps the pending mints of another process`() {
            val records = KeyRecords(prefs)
            records.reserve("11", KeyType.HPKE_P256, Backing.KEYSTORE, FOREIGN_TAG)
            keys.generateP256Agreement(alias("11"))
            records.reserve("12", KeyType.HPKE_P256, Backing.SOFTWARE, FOREIGN_TAG)
            prefs.edit().putString("scp.p256.12", Base64.getEncoder().encodeToString(randomScalar())).commit()
            records.reserve("13", KeyType.P256, Backing.KEYSTORE, FOREIGN_TAG)

            custody()

            assertTrue(keys.p256Aliases.isEmpty())
            assertTrue(prefs.all.isEmpty(), "left behind: ${prefs.all.keys}")
        }

        @Test
        fun `a new instance leaves this process's pending mint and settled keys alone`() {
            val settled = custody().generateKeypair(KeyType.P256)
            KeyRecords(prefs).reserve("21", KeyType.HPKE_P256, Backing.KEYSTORE, TAG)
            keys.generateP256Agreement(alias("21"))

            val reopened = custody()

            assertTrue(keys.containsAlias(alias("21")))
            assertNull(KeyRecords(prefs).get("21")?.custody)
            assertNotNull(KeyRecords(prefs).get("21"))
            assertTrue(keys.containsAlias(alias(settled.id)))
            assertEquals(CustodyType.HARDWARE, reopened.resolveKeyHandle(settled.id).custodyType)
        }

        @Test
        fun `a pending id is unusable and the bridge destroys it`() {
            runTest {
                val custody = custody()
                KeyRecords(prefs).reserve("31", KeyType.P256, Backing.KEYSTORE, TAG)
                keys.generateP256Signing(alias("31"))
                val pending = KeyHandle(id = "31", custodyType = CustodyType.HARDWARE)
                assertEquals("SCP-CRYPTO-4006", codeOf { custody.sign(pending, digest()) })
                assertEquals("SCP-CRYPTO-4006", codeOf { custody.publicKey(pending) })

                val bridge = TestingCallbackCustody(UniffiKeyCustody(custody))
                assertEquals("in_memory", bridge.custodyType("31"))
                bridge.destroyKey("31")

                assertFalse(keys.containsAlias(alias("31")))
                assertTrue(prefs.all.isEmpty(), "left behind: ${prefs.all.keys}")
            }
        }
    }
}
