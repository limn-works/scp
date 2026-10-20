// Instrumented P-256 custody tests (ADR-027, SCP-307). They run `AndroidKeyCustody(context)`, the
// production constructor, against the device's own Android Keystore and EncryptedSharedPreferences,
// and check what the JVM fake cannot: that Keystore accepts the signing and agreement specs, that
// the API-level probe picks the store the device supports, that the recorded custody equals the
// security level `KeyInfo` reports, that keys survive a new instance over the real encrypted file,
// and that destroy leaves nothing behind. Signatures are checked with the bridge's strict verifier
// and agreements against the bridge's Rust ECDH oracle.
//
// Every test records the ids it mints; `@After` destroys any still present and asserts that no
// `scp.key.<id>` alias and no `scp.p256.<id>` or `scp.keymeta.<id>` entry remains for them.

package works.limn.scp.android.platform

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.util.BigIntegers
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.scp.CustodyKeyType
import uniffi.scp.ScpException
import uniffi.scp.TestingCallbackCustody
import uniffi.scp.testingP256Ecdh
import uniffi.scp.testingP256VerifyStrict

private val CURVE = SECNamedCurves.getByName("secp256r1")
private const val SCALAR_SIZE = 32
private const val SIGN_ITERATIONS = 32
private const val AGREE_ITERATIONS = 8

/** The tag the lane's log check reads; one line per key whose `KeyInfo` a test read. */
private const val KEYINFO_TAG = "SCP_KEYINFO"

@RunWith(AndroidJUnit4::class)
class AndroidKeyCustodyP256InstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val random = SecureRandom()
    private val minted = mutableListOf<String>()

    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    /**
     * A second view of the custody's encrypted file, for asserting what it holds. The context
     * caches one `SharedPreferences` per file name, so this reader sees every committed write.
     */
    private val prefs: SharedPreferences =
        EncryptedSharedPreferences.create(
            AndroidKeyCustody.PREFS_FILENAME,
            MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )

    @After
    fun nothingRemainsForMintedIds() {
        val custody = AndroidKeyCustody(context)
        for (id in minted) {
            runCatching { custody.destroyKeyById(id) }
        }
        for (id in minted) {
            assertFalse("alias of $id remains", keyStore.containsAlias(alias(id)))
            assertNull("scalar of $id remains", prefs.getString("scp.p256.$id", null))
            assertNull("record of $id remains", prefs.getString("scp.keymeta.$id", null))
        }
    }

    @Test
    fun p256SignVerifiesStrictly(): Unit = runBlocking {
        val bridge = TestingCallbackCustody(UniffiKeyCustody(AndroidKeyCustody(context)))
        val id = bridge.generateKeypair(CustodyKeyType.P256).also { minted += it }
        val publicKey = bridge.publicKey(id)
        assertEquals(33, publicKey.size)
        repeat(SIGN_ITERATIONS) {
            val digest = ByteArray(32).also(random::nextBytes)
            val signature = bridge.sign(id, digest)
            assertEquals(64, signature.size)
            assertTrue("strict verify rejected iteration $it", testingP256VerifyStrict(publicKey, digest, signature))
        }
    }

    @Test
    fun hpkeAgreementMatchesOracle(): Unit = runBlocking {
        val custody = AndroidKeyCustody(context)
        val bridge = TestingCallbackCustody(UniffiKeyCustody(custody))
        val id = bridge.generateKeypair(CustodyKeyType.HPKE_P256).also { minted += it }
        val record = checkNotNull(custody.keyRecords.get(id)) { "no record for $id" }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            assertTrue("API ${Build.VERSION.SDK_INT} must hold the key in Keystore", keyStore.containsAlias(alias(id)))
            assertEquals(Backing.KEYSTORE, record.backing)
        } else {
            assertFalse("API ${Build.VERSION.SDK_INT} has no Keystore ECDH", keyStore.containsAlias(alias(id)))
            assertEquals(Backing.SOFTWARE, record.backing)
            assertEquals("software", bridge.custodyType(id))
        }
        val hostPublic = bridge.publicKey(id)
        assertEquals(65, hostPublic.size)
        repeat(AGREE_ITERATIONS) {
            val peer = scalar()
            assertArrayEquals(testingP256Ecdh(peer, hostPublic), bridge.dhAgree(id, pointOf(peer)))
        }
    }

    @Test
    fun custodyMatchesKeyInfo(): Unit = runBlocking {
        val bridge = TestingCallbackCustody(UniffiKeyCustody(AndroidKeyCustody(context)))
        val ids = listOf(
            bridge.generateKeypair(CustodyKeyType.P256),
            bridge.generateKeypair(CustodyKeyType.HPKE_P256),
        ).also { minted += it }
        for (id in ids) {
            val keyAlias = alias(id)
            if (!keyStore.containsAlias(keyAlias)) {
                // A software HPKE key (API 30 and below) has no KeyInfo; its custody is software.
                assertEquals("software", bridge.custodyType(id))
                continue
            }
            val secure = keyInfoSecure(keyAlias)
            assertEquals(if (secure) "hardware" else "software", bridge.custodyType(id))
        }
    }

    @Test
    fun keysSurviveANewInstance(): Unit = runBlocking {
        val first = TestingCallbackCustody(UniffiKeyCustody(AndroidKeyCustody(context)))
        val signing = first.generateKeypair(CustodyKeyType.P256).also { minted += it }
        val agreement = first.generateKeypair(CustodyKeyType.HPKE_P256).also { minted += it }
        val signingPublic = first.publicKey(signing)
        val agreementPublic = first.publicKey(agreement)

        val reopened = TestingCallbackCustody(UniffiKeyCustody(AndroidKeyCustody(context)))
        assertArrayEquals(signingPublic, reopened.publicKey(signing))
        assertArrayEquals(agreementPublic, reopened.publicKey(agreement))
        val digest = ByteArray(32).also(random::nextBytes)
        assertTrue(testingP256VerifyStrict(signingPublic, digest, reopened.sign(signing, digest)))
        val peer = scalar()
        assertArrayEquals(testingP256Ecdh(peer, agreementPublic), reopened.dhAgree(agreement, pointOf(peer)))
    }

    @Test
    fun destroyRemovesEverything(): Unit = runBlocking {
        val bridge = TestingCallbackCustody(UniffiKeyCustody(AndroidKeyCustody(context)))
        val ids = listOf(
            bridge.generateKeypair(CustodyKeyType.P256),
            bridge.generateKeypair(CustodyKeyType.HPKE_P256),
        ).also { minted += it }
        for (id in ids) {
            bridge.destroyKey(id)
            assertFalse(keyStore.containsAlias(alias(id)))
            assertNull(prefs.getString("scp.p256.$id", null))
            assertNull(prefs.getString("scp.keymeta.$id", null))
            assertEquals("in_memory", bridge.custodyType(id))
            try {
                bridge.publicKey(id)
                fail("publicKey of destroyed key $id succeeded")
            } catch (expected: ScpException.Crypto) {
                assertEquals("SCP-CRYPTO-4006", expected.code)
            }
        }
        // A new instance over the same file finds neither key.
        val reopened = UniffiKeyCustody(AndroidKeyCustody(context))
        for (id in ids) assertEquals("in_memory", reopened.custodyType(id))
    }

    /**
     * Whether `KeyInfo`, read here independently of the adapter, places [alias] in secure
     * hardware: on API 31+ a `securityLevel` of TEE, StrongBox or unknown-secure, below it
     * `isInsideSecureHardware`. Logs the level under [KEYINFO_TAG] so the lane can show that a
     * leg observed a non-secure level.
     */
    private fun keyInfoSecure(alias: String): Boolean {
        val key = keyStore.getKey(alias, null) as PrivateKey
        val info = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java)
        val secure: Boolean
        val level: String
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            level = info.securityLevel.toString()
            secure = info.securityLevel in setOf(
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                KeyProperties.SECURITY_LEVEL_STRONGBOX,
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE,
            )
        } else {
            @Suppress("DEPRECATION")
            val inside = info.isInsideSecureHardware
            level = "insideSecureHardware=$inside"
            secure = inside
        }
        Log.i(KEYINFO_TAG, "api=${Build.VERSION.SDK_INT} alias=$alias level=$level secure=$secure")
        return secure
    }

    /** A scalar drawn uniformly from [1, n-1], as 32 bytes. */
    private fun scalar(): ByteArray =
        BigIntegers.asUnsignedByteArray(
            SCALAR_SIZE,
            BigIntegers.createRandomInRange(BigInteger.ONE, CURVE.n.subtract(BigInteger.ONE), random),
        )

    private fun alias(id: String): String = "scp.key.$id"

    private fun pointOf(scalar: ByteArray): ByteArray =
        CURVE.g.multiply(BigInteger(1, scalar)).normalize().getEncoded(false)
}
