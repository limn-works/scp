// AndroidKeyCustodyPseudonymLifecycleTest.kt — pseudonym key lifecycle in AndroidKeyCustody.
//
// Covers the Keystore identity path through a fake KeystoreKeys (JVM tests cannot reach
// AndroidKeyStore), destruction of an identity's pseudonyms, and concurrent re-derivation.
//
// Provenance: spec §9.10.4 (pseudonym derivation), §9.10.4.A (pseudonym secret), §9.15
// (key destruction verification), ADR-027 (Android Platform Adapter).

package works.limn.scp.android.platform

import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * [KeystoreKeys] fake: Ed25519 entries are markers (the tests here never sign with the
 * identity), HMAC entries hold a random 32-byte key and compute a real HMAC-SHA256.
 */
private class FakeKeystoreKeys(private val failHmacGeneration: Boolean = false) : KeystoreKeys {
    val ed25519 = mutableSetOf<String>()
    val hmacKeys = mutableMapOf<String, ByteArray>()

    override fun generateEd25519(alias: String) {
        ed25519.add(alias)
    }

    override fun generateHmacSha256(alias: String) {
        if (failHmacGeneration) throw java.security.ProviderException("injected HMAC generation failure")
        hmacKeys[alias] = ByteArray(32).also { SecureRandom().nextBytes(it) }
    }

    override fun hmacSha256(alias: String, vararg parts: ByteArray): ByteArray? {
        val key = hmacKeys[alias] ?: return null
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        parts.forEach { mac.update(it) }
        return mac.doFinal()
    }

    override fun containsAlias(alias: String): Boolean = alias in ed25519 || alias in hmacKeys

    override fun deleteEntry(alias: String) {
        ed25519.remove(alias)
        hmacKeys.remove(alias)
    }
}

class AndroidKeyCustodyPseudonymLifecycleTest {
    private val curve = CustomNamedCurves.getByName("secp256r1")
    private val domain = ECDomainParameters(curve.curve, curve.g, curve.n, curve.h)

    private fun handleOf(pseudonym: PseudonymKeyHandle) =
        KeyHandle(id = pseudonym.id, custodyType = pseudonym.custodyType)

    private fun verifies(publicKey: ByteArray, digest: ByteArray, signature: ByteArray): Boolean {
        val verifier = ECDSASigner()
        verifier.init(false, ECPublicKeyParameters(curve.curve.decodePoint(publicKey), domain))
        return verifier.verifySignature(
            digest,
            BigInteger(1, signature.copyOfRange(0, 32)),
            BigInteger(1, signature.copyOfRange(32, 64)),
        )
    }

    /**
     * The Keystore identity path end to end: the pseudonym secret is created with the
     * identity, derivation is stable, destroying the identity deletes the secret alias,
     * and derivation then fails with `SCP-CRYPTO-4001`.
     */
    @Test
    fun `keystore identity pseudonym secret lives and dies with the identity`() {
        val keystore = FakeKeystoreKeys()
        val custody = AndroidKeyCustody(InMemorySharedPreferences(), keystore, keystoreEd25519 = true)
        val identity = custody.generateKeypair(KeyType.ED25519)
        assertEquals(CustodyType.HARDWARE, identity.custodyType)
        assertTrue(keystore.containsAlias(PseudonymSecret.alias(identity.id)))

        val contextId = "keystore-context".toByteArray()
        val first = custody.derivePseudonym(identity, contextId)
        val firstPoint = custody.publicKey(handleOf(first))
        val second = custody.derivePseudonym(identity, contextId)
        assertEquals(first.id, second.id)
        assertArrayEquals(firstPoint, custody.publicKey(handleOf(second)))

        assertTrue(custody.destroyKey(identity).confirmed)
        assertFalse(keystore.containsAlias(PseudonymSecret.alias(identity.id)))
        assertFalse(keystore.containsAlias("scp.key.${identity.id}"))

        val error = assertThrows<ScpException> { custody.derivePseudonym(identity, contextId) }
        assertEquals("SCP-CRYPTO-4001", error.code)
    }

    /** A failed pseudonym-secret generation leaves no orphaned identity in Keystore. */
    @Test
    fun `failed pseudonym secret generation deletes the identity key`() {
        val keystore = FakeKeystoreKeys(failHmacGeneration = true)
        val custody = AndroidKeyCustody(InMemorySharedPreferences(), keystore, keystoreEd25519 = true)
        assertThrows<java.security.ProviderException> { custody.generateKeypair(KeyType.ED25519) }
        assertTrue(keystore.ed25519.isEmpty(), "the Ed25519 alias must be deleted")
        assertTrue(keystore.hmacKeys.isEmpty())
    }

    /** Destroying an identity destroys every pseudonym derived from it (§9.10.4.A). */
    @Test
    fun `destroying an identity destroys its pseudonyms`() {
        val custody = AndroidKeyCustody(InMemorySharedPreferences())
        val identity = custody.generateKeypair(KeyType.ED25519)
        val first = custody.derivePseudonym(identity, "context-a".toByteArray())
        val second = custody.deriveRotatablePseudonym(identity, "context-b".toByteArray(), 3)
        val digest = MessageDigest.getInstance("SHA-256").digest("before".toByteArray())
        custody.sign(handleOf(first), digest)
        custody.sign(handleOf(second), digest)

        assertTrue(custody.destroyKey(identity).confirmed)
        assertEquals(0, custody.pseudonymKeys.size)
        for (pseudonym in listOf(first, second)) {
            val signError = assertThrows<ScpException> { custody.sign(handleOf(pseudonym), digest) }
            assertEquals("SCP-CRYPTO-4001", signError.code)
            val keyError = assertThrows<ScpException> { custody.publicKey(handleOf(pseudonym)) }
            assertEquals("SCP-CRYPTO-4001", keyError.code)
        }
    }

    /**
     * Re-deriving a pseudonym while another thread signs with it never corrupts a
     * signature: every signature verifies under the pseudonym's public key.
     */
    @Test
    fun `concurrent re-derive and sign on one pseudonym always verify`() {
        val custody = AndroidKeyCustody(InMemorySharedPreferences())
        val identity = custody.generateKeypair(KeyType.ED25519)
        val contextId = "race-context".toByteArray()
        val pseudonym = custody.derivePseudonym(identity, contextId)
        val publicKey = custody.publicKey(handleOf(pseudonym))
        val rounds = 300
        val pool = Executors.newFixedThreadPool(4)
        val start = CountDownLatch(1)
        try {
            val derivers = List(2) {
                pool.submit {
                    start.await()
                    repeat(rounds) { custody.derivePseudonym(identity, contextId) }
                }
            }
            val signers = List(2) { thread ->
                pool.submit<List<Boolean>> {
                    start.await()
                    List(rounds) { round ->
                        val digest = MessageDigest.getInstance("SHA-256")
                            .digest("t$thread r$round".toByteArray())
                        verifies(publicKey, digest, custody.sign(handleOf(pseudonym), digest))
                    }
                }
            }
            start.countDown()
            derivers.forEach { it.get(60, TimeUnit.SECONDS) }
            val results = signers.flatMap { it.get(60, TimeUnit.SECONDS) }
            assertEquals(2 * rounds, results.size)
            assertTrue(results.all { it }, "every concurrent signature must verify")
        } finally {
            pool.shutdownNow()
        }
    }

    /**
     * Destroying a pseudonym while other threads sign with it never yields a bad
     * signature: each sign either verifies under the pseudonym's point or fails with
     * `SCP-CRYPTO-4001`. A sign that used the stored scalar array instead of a copy
     * would see it wiped mid-signature.
     *
     * The signers sign without pause until the cycler finishes, so every destroy lands
     * while a sign may be in flight. Before each destroy the cycler waits for one more
     * verified signature, so every cycle overlaps signing whatever the scheduler does.
     */
    @Test
    fun `destroying a pseudonym while others sign never yields a bad signature`() {
        val custody = AndroidKeyCustody(InMemorySharedPreferences())
        val identity = custody.generateKeypair(KeyType.ED25519)
        val contextId = "destroy-race-context".toByteArray()
        val pseudonym = custody.derivePseudonym(identity, contextId)
        val publicKey = custody.publicKey(handleOf(pseudonym))
        val rounds = 300
        val verified = AtomicInteger(0)
        val done = AtomicBoolean(false)
        val pool = Executors.newFixedThreadPool(3)
        val start = CountDownLatch(1)
        try {
            val cycler = pool.submit {
                start.await()
                try {
                    repeat(rounds) {
                        val seen = verified.get()
                        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
                        while (verified.get() == seen) {
                            check(System.nanoTime() < deadline) { "no signature verified within 30 s" }
                            Thread.onSpinWait()
                        }
                        custody.destroyKey(handleOf(pseudonym))
                        assertEquals(pseudonym.id, custody.derivePseudonym(identity, contextId).id)
                    }
                } finally {
                    done.set(true)
                }
            }
            val signers = List(2) { thread ->
                pool.submit {
                    start.await()
                    var round = 0
                    while (!done.get()) {
                        val digest = MessageDigest.getInstance("SHA-256")
                            .digest("d$thread r${round++}".toByteArray())
                        val signature = try {
                            custody.sign(handleOf(pseudonym), digest)
                        } catch (e: ScpException) {
                            assertEquals("SCP-CRYPTO-4001", e.code, "only not-found may fail a sign")
                            null
                        }
                        if (signature != null) {
                            assertTrue(verifies(publicKey, digest, signature), "signature must verify")
                            verified.incrementAndGet()
                        }
                    }
                }
            }
            start.countDown()
            cycler.get(60, TimeUnit.SECONDS)
            signers.forEach { it.get(60, TimeUnit.SECONDS) }
            assertTrue(verified.get() >= rounds, "a signature must verify before every destroy")
        } finally {
            done.set(true)
            pool.shutdownNow()
        }
    }

    /**
     * A derivation still in flight when its identity is retired stores nothing: the
     * scalar is wiped and `SCP-CRYPTO-4001` is thrown.
     */
    @Test
    fun `register after the identity is retired stores nothing`() {
        val keys = PseudonymKeys()
        keys.retireIdentity("retired-identity")
        val contextSeed = ByteArray(32) { 0x5a }
        val error = assertThrows<ScpException> {
            P256Pseudonym.register(keys, "retired-identity", "p256-retired", contextSeed)
        }
        assertEquals("SCP-CRYPTO-4001", error.code)
        assertTrue(contextSeed.all { it == 0.toByte() }, "the context seed must be wiped")
        assertEquals(0, keys.size)
    }

    /**
     * [PseudonymKeys.withScalar] lends a copy: removing the pseudonym inside the block
     * wipes the stored array but not the lent one, and the lent copy is wiped once the
     * block returns.
     */
    @Test
    fun `withScalar lends a copy that survives removal and is wiped afterwards`() {
        val keys = PseudonymKeys()
        val original = ByteArray(32) { (it + 1).toByte() }
        keys.put("identity", "p", original.copyOf())
        var lent: ByteArray? = null
        val result = keys.withScalar("p") { scalar ->
            lent = scalar
            assertTrue(keys.remove("p"), "the pseudonym must be stored")
            assertArrayEquals(original, scalar, "removal must not wipe the lent copy")
            "done"
        }
        assertEquals("done", result)
        val captured = checkNotNull(lent) { "withScalar must run the block" }
        assertTrue(captured.all { it == 0.toByte() }, "the lent copy must be wiped after the block")
        assertEquals(0, keys.size)
    }
}
