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
import java.io.IOException
import java.math.BigInteger
import java.security.GeneralSecurityException
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
import org.junit.jupiter.api.Assertions.assertSame
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

/** A tag no instance under test holds: an earlier process that died mid-mint. */
private const val FOREIGN_TAG = "77:1"

/** The main process name the instances under test are told they run in. */
private const val MAIN_PROCESS = "works.limn.app"

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

/**
 * [SharedPreferences] over [inner] whose editors drop every removal of a key starting with
 * [keepPrefix] and still return `true` from `commit()`: a store that reports a removal it did
 * not make.
 */
private class KeepingPrefs(
    private val inner: SharedPreferences,
    private val keepPrefix: String,
) : SharedPreferences by inner {
    override fun edit(): SharedPreferences.Editor = Editor(inner.edit())

    private inner class Editor(private val delegate: SharedPreferences.Editor) : SharedPreferences.Editor by delegate {
        override fun putString(key: String?, value: String?): SharedPreferences.Editor {
            delegate.putString(key, value)
            return this
        }

        override fun remove(key: String?): SharedPreferences.Editor {
            if (key == null || !key.startsWith(keepPrefix)) delegate.remove(key)
            return this
        }

        override fun commit(): Boolean {
            delegate.commit()
            return true
        }
    }
}

/**
 * [SharedPreferences] over [inner] whose `getAll` fails the test: the adapter reads its entries
 * one by one, because `getAll` on EncryptedSharedPreferences decrypts every value in the file.
 */
private class NoGetAllPrefs(private val inner: SharedPreferences) : SharedPreferences by inner {
    override fun getAll(): MutableMap<String, *> = throw AssertionError("AndroidKeyCustody called getAll()")
}

/**
 * [SharedPreferences] over [inner] whose `getString` of [unreadableKey] throws the
 * `ClassCastException` a real store throws for a value that is not a string.
 */
private class UnreadableKeyPrefs(
    private val inner: SharedPreferences,
    private val unreadableKey: String,
) : SharedPreferences by inner {
    override fun getString(key: String?, defValue: String?): String? {
        if (key == unreadableKey) throw ClassCastException("$key holds a value that is not a String")
        return inner.getString(key, defValue)
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
        warnings: MutableList<String> = mutableListOf(),
    ) = AndroidKeyCustody.create(
        encryptedPrefs = store,
        keystore = keys,
        keystoreEd25519 = ed25519InKeystore,
        keystoreAgreement = agreementInKeystore,
        processTag = tag,
        processName = MAIN_PROCESS,
        mainProcessName = MAIN_PROCESS,
        warn = { message, _ -> warnings += message },
    )

    private fun alias(id: String) = "scp.key.$id"

    /**
     * A settled software HPKE key under [id] whose committed scalar is [scalar], written beside
     * the adapter, so no instance has loaded its pair.
     */
    private fun storedSoftwareKey(
        scalar: ByteArray,
        id: String = SecureRandom().nextLong().toULong().toString(),
    ): KeyHandle {
        val records = KeyRecords(prefs)
        records.reserve(id, KeyType.HPKE_P256, Backing.SOFTWARE, KeyRole.OPERATIONAL, TAG)
        records.settle(id, CustodyType.SOFTWARE)
        prefs.edit().putString("scp.p256.$id", Base64.getEncoder().encodeToString(scalar)).commit()
        return KeyHandle(id = id, custodyType = CustodyType.SOFTWARE)
    }

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

        /**
         * Spec 09 §9.7.4.1 (SCP-345): a key-event key mints in Keystore, signs a 32-byte digest,
         * and reports `P256_KEY_EVENT` with a 33-byte point, also from an adapter reopened over
         * the same records. A key recorded as `P256` would report `P256` after the reopen, which
         * the bridge's record refuses.
         */
        @Test
        fun `p256 key-event key generates, signs a digest and reports its type, also after a reopen`() {
            runTest {
                val provider = UniffiKeyCustody(custody())
                val id = provider.generateKeypair(CustodyKeyType.P256_KEY_EVENT, CustodyKeyRole.OPERATIONAL)
                val minted = provider.getPublicKey(id)
                assertEquals(CustodyKeyType.P256_KEY_EVENT, minted.keyType)
                assertEquals(CustodyKeyRole.OPERATIONAL, minted.role)
                assertEquals(33, minted.publicKey.size)
                assertEquals(KeyType.P256_KEY_EVENT, KeyRecords(prefs).get(id)?.type)
                assertEquals("p256-key-event", KeyType.P256_KEY_EVENT.wire)

                val digest = digest()
                val der = ASN1Sequence.getInstance(provider.sign(id, digest))
                val r = (der.getObjectAt(0) as ASN1Integer).value
                val s = (der.getObjectAt(1) as ASN1Integer).value
                val lowS = if (s > CURVE.n.shiftRight(1)) CURVE.n - s else s
                val raw = BigIntegers.asUnsignedByteArray(32, r) + BigIntegers.asUnsignedByteArray(32, lowS)
                assertTrue(testingP256VerifyStrict(minted.publicKey, digest, raw))

                val reopened = UniffiKeyCustody(custody()).getPublicKey(id)
                assertEquals(CustodyKeyType.P256_KEY_EVENT, reopened.keyType)
                assertArrayEquals(minted.publicKey, reopened.publicKey)
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
        fun `an unknown or pending id is SCP-CRYPTO-4006 whatever the peer`() {
            val custody = custody()
            KeyRecords(prefs).reserve("71", KeyType.HPKE_P256, Backing.KEYSTORE, KeyRole.OPERATIONAL, TAG)
            keys.generateP256Agreement(alias("71"))
            val badPeers = listOf(ByteArray(0), ByteArray(3), ByteArray(65))
            for (id in listOf("999", "71")) {
                for (custodyType in listOf(CustodyType.HARDWARE, CustodyType.SOFTWARE)) {
                    for (peer in badPeers) {
                        val handle = KeyHandle(id = id, custodyType = custodyType)
                        assertEquals("SCP-CRYPTO-4006", codeOf { custody.dhAgree(handle, peer) }, "$id $custodyType")
                    }
                }
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
            val softwareAgreement = custody(agreementInKeystore = false).generateKeypair(KeyType.HPKE_P256)
            assertEquals(Backing.SOFTWARE, KeyRecords(prefs).get(softwareAgreement.id)?.backing)
            assertEquals("SCP-CRYPTO-4060", codeOf { custody.sign(softwareAgreement, digest()) })
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
        fun `isSecureLevel reads securityLevel from API 31 and isInsideSecureHardware below`() {
            val secure = mapOf(
                android.security.keystore.KeyProperties.SECURITY_LEVEL_SOFTWARE to false,
                android.security.keystore.KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT to true,
                android.security.keystore.KeyProperties.SECURITY_LEVEL_STRONGBOX to true,
                android.security.keystore.KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE to true,
                android.security.keystore.KeyProperties.SECURITY_LEVEL_UNKNOWN to false,
            )
            assertEquals(5, secure.keys.size)
            for ((level, expected) in secure) {
                for (inside in listOf(true, false)) {
                    // API 31: securityLevel decides, whatever isInsideSecureHardware says.
                    assertEquals(expected, isSecureLevel(level, inside, 31), "level $level at 31")
                    // API 30: securityLevel does not exist; isInsideSecureHardware decides.
                    assertEquals(inside, isSecureLevel(level, inside, 30), "level $level at 30")
                }
            }
        }

        @Test
        fun `Keystore agreement starts at API 31`() {
            assertFalse(keystoreAgreementAvailable(30))
            assertTrue(keystoreAgreementAvailable(31))
            assertTrue(keystoreAgreementAvailable(35))
        }
    }

    // -------------------------------------------------------------------
    // Roles
    // -------------------------------------------------------------------

    @Nested
    inner class Roles {
        @Test
        fun `a second instance reads the role a P-256 key was minted in from its record`() {
            runTest {
                val first = UniffiKeyCustody(custody())
                val signing = first.generateKeypair(CustodyKeyType.P256, CustodyKeyRole.IDENTITY)
                val agreement = first.generateKeypair(CustodyKeyType.HPKE_P256, CustodyKeyRole.OPERATIONAL)

                // The role sits in the record, written by the commit that reserved it; no
                // separate role entry exists for a crash to split from the record.
                assertEquals(KeyRole.IDENTITY, KeyRecords(prefs).get(signing)?.role)
                assertEquals(KeyRole.OPERATIONAL, KeyRecords(prefs).get(agreement)?.role)
                assertTrue(prefs.all.keys.none { it.startsWith("scp.role.") }, "role entries: ${prefs.all.keys}")

                val second = UniffiKeyCustody(custody())
                assertEquals(CustodyKeyRole.IDENTITY, second.getPublicKey(signing).role)
                assertEquals(CustodyKeyRole.OPERATIONAL, second.getPublicKey(agreement).role)
            }
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
            handles.forEachIndexed { index, handle ->
                val stored = Base64.getDecoder().decode(prefs.getString("scp.p256.${handle.id}", null))
                assertEquals(32, stored.size)
                // The process-wide pair cache would serve a wrong scalar's key pair, so the
                // committed scalar itself must produce the minted public key.
                assertArrayEquals(publics[index], pointOf(stored))
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
            val small = BigIntegers.asUnsignedByteArray(32, BigInteger(240, SecureRandom()).add(BigInteger.ONE))
            assertEquals(0.toByte(), small[0])
            val handle = storedSoftwareKey(small)

            val restored = custody(agreementInKeystore = false)
            val hostPublic = restored.publicKey(handle)
            assertArrayEquals(pointOf(small), hostPublic)
            val peer = randomScalar()
            assertArrayEquals(testingP256Ecdh(peer, hostPublic), restored.dhAgree(handle, pointOf(peer)))
        }

        @Test
        fun `a stored scalar that is not a valid 32-byte scalar fails closed`() {
            val n = BigIntegers.asUnsignedByteArray(32, CURVE.n)
            for (bad in listOf(ByteArray(31) { 1 }, ByteArray(33) { 1 }, ByteArray(32), n)) {
                val handle = storedSoftwareKey(bad)
                val restored = custody(agreementInKeystore = false)
                assertEquals("SCP-CRYPTO-4060", codeOf { restored.publicKey(handle) }, "size ${bad.size}")
            }
        }

        @Test
        fun `the software scalar is committed before generateKeypair returns`() {
            val refusing = custody(agreementInKeystore = false, store = RefusingPrefs(prefs, "scp.p256."))
            assertEquals("SCP-CRYPTO-4060", codeOf { refusing.generateKeypair(KeyType.HPKE_P256) })
            assertTrue(prefs.all.isEmpty(), "left behind: ${prefs.all.keys}")
        }

        @Test
        fun `a software key destroyed through one instance stays cached in no other instance`() {
            val destroying = custody(agreementInKeystore = false)
            val other = custody(agreementInKeystore = false)
            val handle = destroying.generateKeypair(KeyType.HPKE_P256)
            val minted = destroying.publicKey(handle)
            // The other instance loads the pair.
            assertArrayEquals(minted, other.publicKey(handle))

            destroying.destroyKey(handle)

            // Under the same id, a new scalar: an instance that still caches the destroyed pair
            // answers with the destroyed key's point.
            val scalar = randomScalar()
            storedSoftwareKey(scalar, id = handle.id)
            assertArrayEquals(pointOf(scalar), other.publicKey(handle))
            val peer = randomScalar()
            assertArrayEquals(testingP256Ecdh(peer, pointOf(scalar)), other.dhAgree(handle, pointOf(peer)))
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
        fun `a record removal that commits but keeps the entry is refused`() {
            val keeping = KeyRecords(KeepingPrefs(prefs, "scp.keymeta."))
            keeping.reserve("81", KeyType.P256, Backing.KEYSTORE, KeyRole.OPERATIONAL, TAG)
            val error = assertThrows<ScpException> { keeping.remove("81") }
            assertEquals("SCP-CRYPTO-4060", error.code)
            assertTrue(error.message.orEmpty().contains("Could not remove the record of key 81"), error.message)
            assertNotNull(KeyRecords(prefs).get("81"))
        }

        @Test
        fun `a rollback whose record removal is not confirmed names the id, and destroyKey completes it`() {
            keys.hidePublicKey = true
            val custody = custody(store = KeepingPrefs(prefs, "scp.keymeta."))
            val error = assertThrows<ScpException> { custody.generateKeypair(KeyType.P256) }
            assertEquals("SCP-CRYPTO-4060", error.code)
            val id = KeyRecords(prefs).ids().single()
            assertTrue(error.message.orEmpty().contains("its record could not be removed"), error.message)
            assertTrue(error.message.orEmpty().contains(id), error.message)
            assertEquals(1, error.suppressed.size)
            assertFalse(keys.containsAlias(alias(id)))
            assertNull(KeyRecords(prefs).get(id)?.custody)

            keys.hidePublicKey = false
            assertEquals(DestructionMethod.SOFTWARE_ONLY, custody(store = prefs).destroyKeyById(id).method)
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
            assertEquals(KeyRole.OPERATIONAL, custody.roleOf(handle.id))

            keys.ignoreDeletes = false
            custody.destroyKey(handle)
            assertFalse(keys.containsAlias(alias(handle.id)))
            assertTrue(prefs.all.isEmpty(), "left behind: ${prefs.all.keys}")
        }

        @Test
        fun `destroy deletes an orphan alias that has no record, below API 33`() {
            keys.generateP256Signing(alias("4242"))
            val custody = custody(ed25519InKeystore = false)
            assertEquals(DestructionMethod.SOFTWARE_ONLY, custody.destroyKeyById("4242").method)
            assertFalse(keys.containsAlias(alias("4242")))
        }

        @Test
        fun `a Keystore Ed25519 identity's destruction reports software-only`() {
            val custody = custody(ed25519InKeystore = true)
            val identity = custody.generateKeypair(KeyType.ED25519, KeyRole.IDENTITY)
            assertEquals(CustodyType.HARDWARE, identity.custodyType)
            assertEquals(DestructionMethod.SOFTWARE_ONLY, custody.destroyKey(identity).method)
            assertFalse(keys.containsAlias(alias(identity.id)))
        }

        @Test
        fun `a destroy retry after the identity alias is gone removes its secret and role, then reports 4006`() {
            val custody = custody(ed25519InKeystore = true)
            val identity = custody.generateKeypair(KeyType.ED25519, KeyRole.IDENTITY)
            custody.derivePseudonym(identity, byteArrayOf(7))
            assertEquals(1, keys.hmacKeys.size)
            keys.deleteEntry(alias(identity.id))

            assertEquals("SCP-CRYPTO-4006", codeOf { custody.destroyKeyById(identity.id) })
            assertTrue(keys.hmacKeys.isEmpty())
            assertNull(custody.roleOf(identity.id))
            assertTrue(prefs.all.isEmpty(), "left behind: ${prefs.all.keys}")
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
        fun `a destroyed key is gone and every destruction reports software-only`() {
            runTest {
                val custody = custody(agreementInKeystore = true)
                val provider = UniffiKeyCustody(custody)
                val hardware = custody.generateKeypair(KeyType.P256)
                keys.secureHardware = false
                val softKeystore = custody.generateKeypair(KeyType.HPKE_P256)
                val software = custody(agreementInKeystore = false).generateKeypair(KeyType.HPKE_P256)

                // Keystore issues no proof of destruction, so a hardware key reports software-only too.
                assertEquals(CustodyType.HARDWARE, KeyRecords(prefs).get(hardware.id)?.custody)
                assertEquals(DestructionMethod.SOFTWARE_ONLY, custody.destroyKey(hardware).method)
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
        fun `construction outside the main process is refused with SCP-CRYPTO-4060`() {
            for (processName in listOf("$MAIN_PROCESS:remote", "other.app", null)) {
                val error = assertThrows<ScpException> {
                    AndroidKeyCustody.create(prefs, keys, processName = processName, mainProcessName = MAIN_PROCESS)
                }
                assertEquals("SCP-CRYPTO-4060", error.code)
                assertTrue(error.message.orEmpty().contains("only in the app's main process"), error.message)
            }
            assertTrue(prefs.all.isEmpty(), "left behind: ${prefs.all.keys}")
            AndroidKeyCustody.create(prefs, keys, processName = MAIN_PROCESS, mainProcessName = MAIN_PROCESS)
        }

        @Test
        fun `a preferences file that cannot be opened or read is SCP-CRYPTO-4060, never a raw exception`() {
            for (failure in listOf(GeneralSecurityException("master key unavailable"), IOException("unreadable"))) {
                val error = assertThrows<ScpException> {
                    AndroidKeyCustody.openPreferences(MAIN_PROCESS, MAIN_PROCESS) { throw failure }
                }
                assertEquals("SCP-CRYPTO-4060", error.code)
                assertSame(failure, error.cause)
            }

            var opened = false
            val refused = assertThrows<ScpException> {
                AndroidKeyCustody.openPreferences("other.app", MAIN_PROCESS) {
                    opened = true
                    prefs
                }
            }
            assertEquals("SCP-CRYPTO-4060", refused.code)
            assertFalse(opened, "the preferences were opened outside the main process")
            assertSame(prefs, AndroidKeyCustody.openPreferences(MAIN_PROCESS, MAIN_PROCESS) { prefs })

            // A file that opens but whose role index cannot be read fails construction typed too.
            val unreadable = assertThrows<ScpException> { custody(store = UnreadableKeyPrefs(prefs, "scp.role.ids")) }
            assertEquals("SCP-CRYPTO-4060", unreadable.code)
            assertTrue(unreadable.cause is ClassCastException, "cause: ${unreadable.cause}")
        }

        @Test
        fun `a new instance sweeps the pending mints an earlier process left under its own tag`() {
            // One process runs the adapter at a time, so a pending record under another tag was
            // left by an earlier process that died mid-mint.
            val records = KeyRecords(prefs)
            records.reserve("11", KeyType.HPKE_P256, Backing.KEYSTORE, KeyRole.OPERATIONAL, FOREIGN_TAG)
            keys.generateP256Agreement(alias("11"))
            records.reserve("12", KeyType.HPKE_P256, Backing.SOFTWARE, KeyRole.OPERATIONAL, FOREIGN_TAG)
            prefs.edit().putString("scp.p256.12", Base64.getEncoder().encodeToString(randomScalar())).commit()
            records.reserve("13", KeyType.P256, Backing.KEYSTORE, KeyRole.IDENTITY, FOREIGN_TAG)
            assertEquals(KeyRole.IDENTITY, records.get("13")?.role)

            val warnings = mutableListOf<String>()
            custody(warnings = warnings)

            assertTrue(keys.p256Aliases.isEmpty())
            assertTrue(prefs.all.isEmpty(), "left behind: ${prefs.all.keys}")
            assertTrue(warnings.isEmpty(), warnings.toString())
        }

        @Test
        fun `a sweep that cannot delete an orphan leaves it reserved, warns, and construction succeeds`() {
            // A software identity: the fake does not sign with a Keystore Ed25519 key.
            val first = custody()
            val identity = first.generateKeypair(KeyType.ED25519, KeyRole.IDENTITY)
            val settled = first.generateKeypair(KeyType.P256)
            KeyRecords(prefs).reserve("51", KeyType.P256, Backing.KEYSTORE, KeyRole.OPERATIONAL, FOREIGN_TAG)
            keys.generateP256Signing(alias("51"))
            keys.ignoreDeletes = true

            val warnings = mutableListOf<String>()
            val reopened = custody(warnings = warnings)

            assertEquals(64, reopened.sign(identity, byteArrayOf(1, 2, 3)).size)
            assertNotNull(reopened.sign(settled, digest()))
            assertNull(KeyRecords(prefs).get("51")?.custody)
            assertNotNull(KeyRecords(prefs).get("51"))
            assertTrue(keys.containsAlias(alias("51")))
            assertEquals(1, warnings.size, warnings.toString())
            assertTrue(warnings.single().contains("51"), warnings.single())
        }

        @Test
        fun `an unreadable record index warns, and construction succeeds with existing keys working`() {
            val first = custody(agreementInKeystore = false)
            val identity = first.generateKeypair(KeyType.ED25519, KeyRole.IDENTITY)
            val signing = first.generateKeypair(KeyType.P256)
            val agreement = first.generateKeypair(KeyType.HPKE_P256)
            val agreementPublic = first.publicKey(agreement)

            val warnings = mutableListOf<String>()
            val reopened = custody(
                agreementInKeystore = false,
                store = UnreadableKeyPrefs(prefs, "scp.keymeta.ids"),
                warnings = warnings,
            )

            assertEquals(1, warnings.size, warnings.toString())
            assertTrue(warnings.single().contains("index"), warnings.single())
            assertEquals(64, reopened.sign(identity, byteArrayOf(4, 5, 6)).size)
            assertEquals(2, ASN1Sequence.getInstance(reopened.sign(signing, digest())).size())
            val peer = randomScalar()
            assertArrayEquals(testingP256Ecdh(peer, agreementPublic), reopened.dhAgree(agreement, pointOf(peer)))
        }

        @Test
        fun `a record that does not parse fails only its own id`() {
            val first = custody()
            val settled = first.generateKeypair(KeyType.P256)
            val records = KeyRecords(prefs)
            records.reserve("61", KeyType.P256, Backing.KEYSTORE, KeyRole.OPERATIONAL, FOREIGN_TAG)
            keys.generateP256Signing(alias("61"))
            prefs.edit().putString("scp.keymeta.61", "P256|keystore|garbage").commit()

            runTest {
                val warnings = mutableListOf<String>()
                val reopened = custody(warnings = warnings)
                val provider = UniffiKeyCustody(reopened)
                assertEquals(1, warnings.size, warnings.toString())

                // Every other key works, and a new mint succeeds.
                assertNotNull(reopened.sign(settled, digest()))
                assertEquals("hardware", provider.custodyType(settled.id))
                val fresh = reopened.generateKeypair(KeyType.HPKE_P256)
                assertEquals(65, reopened.publicKey(fresh).size)

                // The corrupt id fails closed, and destroy removes it.
                assertEquals("SCP-CRYPTO-4060", codeOf { reopened.resolveKeyHandle("61") })
                assertEquals("in_memory", provider.custodyType("61"))
                assertEquals(DestructionMethod.SOFTWARE_ONLY, reopened.destroyKeyById("61").method)
                assertFalse(keys.containsAlias(alias("61")))
                assertFalse(KeyRecords(prefs).contains("61"))
            }
        }

        @Test
        fun `settled keys minted under another tag survive a reopen and still work`() {
            val minting = custody(tag = FOREIGN_TAG)
            val signing = minting.generateKeypair(KeyType.P256)
            val agreement = minting.generateKeypair(KeyType.HPKE_P256)
            val agreementPublic = minting.publicKey(agreement)

            val reopened = custody(tag = TAG)

            assertNotNull(KeyRecords(prefs).get(signing.id)?.custody)
            assertNotNull(KeyRecords(prefs).get(agreement.id)?.custody)
            val bridgeDigest = digest()
            val der = ASN1Sequence.getInstance(reopened.sign(signing, bridgeDigest))
            assertEquals(2, der.size())
            val peer = randomScalar()
            assertArrayEquals(testingP256Ecdh(peer, agreementPublic), reopened.dhAgree(agreement, pointOf(peer)))
        }

        @Test
        fun `restoring an instance never calls getAll`() {
            val first = custody(agreementInKeystore = false)
            val identity = first.generateKeypair(KeyType.ED25519, KeyRole.IDENTITY)
            val signing = first.generateKeypair(KeyType.P256)
            // Stored beside the adapter, so no instance has cached its pair and the restored
            // instance loads it through NoGetAllPrefs.
            val scalar = randomScalar()
            val agreement = storedSoftwareKey(scalar)
            KeyRecords(prefs).reserve("91", KeyType.HPKE_P256, Backing.SOFTWARE, KeyRole.OPERATIONAL, FOREIGN_TAG)

            val restored = custody(agreementInKeystore = false, store = NoGetAllPrefs(prefs))

            assertEquals(64, restored.sign(identity, byteArrayOf(9)).size)
            assertNotNull(restored.sign(signing, digest()))
            assertArrayEquals(pointOf(scalar), restored.publicKey(agreement))
            assertFalse(KeyRecords(prefs).contains("91"))
            restored.destroyKey(agreement)
            restored.generateKeypair(KeyType.HPKE_P256)
        }

        @Test
        fun `a new instance leaves this process's pending mint and settled keys alone`() {
            val settled = custody().generateKeypair(KeyType.P256)
            KeyRecords(prefs).reserve("21", KeyType.HPKE_P256, Backing.KEYSTORE, KeyRole.OPERATIONAL, TAG)
            keys.generateP256Agreement(alias("21"))

            val reopened = custody()

            assertTrue(keys.containsAlias(alias("21")))
            assertNull(KeyRecords(prefs).get("21")?.custody)
            assertNotNull(KeyRecords(prefs).get("21"))
            assertTrue(keys.containsAlias(alias(settled.id)))
            assertEquals(CustodyType.HARDWARE, reopened.resolveKeyHandle(settled.id).custodyType)
        }

        @Test
        fun `a pending id is unusable, the bridge refuses it unrecorded, and the host destroys it`() {
            runTest {
                val custody = custody()
                KeyRecords(prefs).reserve("31", KeyType.P256, Backing.KEYSTORE, KeyRole.OPERATIONAL, TAG)
                keys.generateP256Signing(alias("31"))
                val pending = KeyHandle(id = "31", custodyType = CustodyType.HARDWARE)
                assertEquals("SCP-CRYPTO-4006", codeOf { custody.sign(pending, digest()) })
                assertEquals("SCP-CRYPTO-4006", codeOf { custody.publicKey(pending) })
                assertEquals("SCP-CRYPTO-4006", codeOf { custody.derivePseudonym(pending, ByteArray(16)) })
                assertEquals("SCP-CRYPTO-4006", codeOf { custody.deriveRotatablePseudonym(pending, ByteArray(16), 3) })

                // The bridge holds no custody record for an id it never
                // minted, so it refuses the destroy before any host call
                // (spec 17 section 17.3); the key is still there afterwards.
                val bridge = TestingCallbackCustody(UniffiKeyCustody(custody))
                assertEquals("in_memory", bridge.custodyType("31"))
                val refused = runCatching { bridge.destroyKey("31") }.exceptionOrNull()
                assertEquals("SCP-CRYPTO-4006", (refused as? BridgeException.Crypto)?.code, "refused: $refused")
                assertTrue(keys.containsAlias(alias("31")))

                custody.destroyKey(pending)
                assertFalse(keys.containsAlias(alias("31")))
                assertTrue(prefs.all.isEmpty(), "left behind: ${prefs.all.keys}")
            }
        }
    }
}
