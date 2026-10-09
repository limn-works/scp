// AndroidKeyCustodyPseudonymLifecycleTest.kt — pseudonym lifecycle in AndroidKeyCustody.
//
// Covers the Keystore identity path through a fake KeystoreKeys (JVM tests cannot reach
// AndroidKeyStore): a pseudonym is derivable only while its identity exists, and a destroy
// interrupted between the pseudonym secret and the identity is completed by a retry.
//
// Provenance: spec §9.10.4 (pseudonym derivation), §9.10.4.A (pseudonym secret, and
// a pseudonym dies with its identity), ADR-027 (Android Platform Adapter).

package works.limn.scp.android.platform

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * [KeystoreKeys] fake: Ed25519 entries are markers (the tests here never sign with the
 * identity), HMAC entries hold a random 32-byte key and compute a real HMAC-SHA256.
 */
private class FakeKeystoreKeys(
    private val failHmacGeneration: Boolean = false,
    /** Aliases whose next [deleteEntry] throws, once each. */
    val failDeleteOnce: MutableSet<String> = mutableSetOf(),
) : KeystoreKeys {
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
        if (failDeleteOnce.remove(alias)) throw java.security.KeyStoreException("injected delete failure")
        ed25519.remove(alias)
        hmacKeys.remove(alias)
    }
}

class AndroidKeyCustodyPseudonymLifecycleTest {
    /**
     * The Keystore identity path end to end: the pseudonym secret is created with the
     * identity, derivation is stable, destroying the identity deletes both aliases, and
     * derivation then fails with `SCP-CRYPTO-4006`.
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
        assertEquals(33, first.size)
        assertArrayEquals(first, custody.derivePseudonym(identity, contextId))

        assertTrue(custody.destroyKey(identity).confirmed)
        assertFalse(keystore.containsAlias(PseudonymSecret.alias(identity.id)))
        assertFalse(keystore.containsAlias("scp.key.${identity.id}"))

        val error = assertThrows<ScpException> { custody.derivePseudonym(identity, contextId) }
        assertEquals("SCP-CRYPTO-4006", error.code)
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

    /**
     * Destroying identity U makes every v1 and v2 pseudonym of U underivable with
     * `SCP-CRYPTO-4006`, on both the software and the Keystore path, while bystander V
     * still derives the same points (§9.10.4.A).
     */
    @Test
    fun `destroying an identity makes its pseudonyms underivable while a bystander still derives`() {
        val custodies = listOf(
            AndroidKeyCustody(InMemorySharedPreferences()),
            AndroidKeyCustody(InMemorySharedPreferences(), FakeKeystoreKeys(), keystoreEd25519 = true),
        )
        for (custody in custodies) {
            val identity = custody.generateKeypair(KeyType.ED25519)
            val bystander = custody.generateKeypair(KeyType.ED25519)
            val contextId = "context-a".toByteArray()
            val bystanderV1 = custody.derivePseudonym(bystander, contextId)
            val bystanderV2 = custody.deriveRotatablePseudonym(bystander, contextId, 3)
            custody.derivePseudonym(identity, contextId)
            custody.deriveRotatablePseudonym(identity, contextId, 3)

            assertTrue(custody.destroyKey(identity).confirmed)

            val v1Error = assertThrows<ScpException> { custody.derivePseudonym(identity, contextId) }
            assertEquals("SCP-CRYPTO-4006", v1Error.code, "${identity.custodyType} v1")
            val v2Error = assertThrows<ScpException> {
                custody.deriveRotatablePseudonym(identity, contextId, 3)
            }
            assertEquals("SCP-CRYPTO-4006", v2Error.code, "${identity.custodyType} v2")
            assertArrayEquals(bystanderV1, custody.derivePseudonym(bystander, contextId))
            assertArrayEquals(bystanderV2, custody.deriveRotatablePseudonym(bystander, contextId, 3))
        }
    }

    /**
     * A destroy whose pseudonym-secret delete fails leaves the identity in place and
     * reports `SCP-CRYPTO-4004`; the identity then still derives. A retry deletes both
     * aliases, after which derivation fails with `SCP-CRYPTO-4006` and no secret alias
     * is left.
     */
    @Test
    fun `a destroy that fails on the secret alias is completed by a retry`() {
        val keystore = FakeKeystoreKeys()
        val custody = AndroidKeyCustody(InMemorySharedPreferences(), keystore, keystoreEd25519 = true)
        val identity = custody.generateKeypair(KeyType.ED25519)
        val secretAlias = PseudonymSecret.alias(identity.id)
        val contextId = "retry-context".toByteArray()
        val point = custody.derivePseudonym(identity, contextId)

        keystore.failDeleteOnce.add(secretAlias)
        val failed = assertThrows<ScpException> { custody.destroyKey(identity) }
        assertEquals("SCP-CRYPTO-4004", failed.code)
        assertTrue(keystore.containsAlias("scp.key.${identity.id}"), "the identity must survive a failed destroy")
        assertArrayEquals(point, custody.derivePseudonym(identity, contextId))

        assertTrue(custody.destroyKey(identity).confirmed)
        assertFalse(keystore.containsAlias(secretAlias))
        assertFalse(keystore.containsAlias("scp.key.${identity.id}"))
        val error = assertThrows<ScpException> { custody.derivePseudonym(identity, contextId) }
        assertEquals("SCP-CRYPTO-4006", error.code)
    }

    /**
     * A pseudonym secret left behind without its identity alias is not derivable, and
     * a destroy of that identity deletes the secret before reporting `SCP-CRYPTO-4006`.
     */
    @Test
    fun `an orphaned pseudonym secret is underivable and removed by destroy`() {
        val keystore = FakeKeystoreKeys()
        val custody = AndroidKeyCustody(InMemorySharedPreferences(), keystore, keystoreEd25519 = true)
        val identity = custody.generateKeypair(KeyType.ED25519)
        val secretAlias = PseudonymSecret.alias(identity.id)
        keystore.ed25519.remove("scp.key.${identity.id}")

        val deriveError = assertThrows<ScpException> {
            custody.derivePseudonym(identity, "orphan".toByteArray())
        }
        assertEquals("SCP-CRYPTO-4006", deriveError.code)

        val destroyError = assertThrows<ScpException> { custody.destroyKey(identity) }
        assertEquals("SCP-CRYPTO-4006", destroyError.code)
        assertFalse(keystore.containsAlias(secretAlias), "the orphaned secret must be deleted")
    }
}
