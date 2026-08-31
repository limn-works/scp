// UniffiKeyCustodyTest.kt — the adapter that lets `identityCreateWithCustody`
// reach the shipped Android key custody.
//
// [UniffiKeyCustody] presents [AndroidKeyCustody] as the
// `uniffi.scp.KeyCustodyProvider` the bridge calls back into. The two
// interfaces name the same eleven operations and declare them differently:
// the Kotlin one takes a [KeyHandle] and returns [PseudonymKeyHandle] and
// [DestructionAttestation], the generated one takes an id string and returns
// `ByteArray` and `Unit`. Before the adapter existed, `os_keystore` had no
// producer on Android — §3.2.2 of the identity spec gives that value the
// operating system's own key store, and the bridge reaches it only through an
// injected provider.
//
// Every test here runs the Bouncy Castle software path, because a JVM unit test
// reaches no Android Keystore.
//
// These tests are JUnit 4, not JUnit 5 like the sibling `AndroidKeyCustodyTest`.
// This module's unit-test task runs on the JUnit 4 runner —
// `bindings/kotlin/scp-kt-android/build.gradle.kts` declares
// `junit-jupiter-engine` and `junit-vintage-engine` but calls no
// `useJUnitPlatform()`, which `:scp-kt` does call — so no
// `org.junit.jupiter.api.Test` method in this module is discovered, and a JUnit
// 5 test here would compile, report no failure, and never run. A JUnit 4 test
// runs, which is what a test proving this adapter has to do.
//
// Provenance: ADR-027 (Android Platform Adapter), ADR-006 (Platform
// Abstraction Layer), §3.2.2 of the identity spec (The Custody Vocabulary).

package works.limn.scp.android.platform

import android.content.SharedPreferences
import kotlinx.coroutines.runBlocking
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.ConcurrentHashMap

/**
 * In-memory [SharedPreferences] double, so [AndroidKeyCustody] persists its
 * software Ed25519 seeds without the Android framework.
 *
 * `AndroidKeyCustodyTest` declares a private double of the same shape; Kotlin
 * scopes a private top-level declaration to its own file, so this file declares
 * its own rather than widening that one's visibility.
 */
private class InMemoryPrefs : SharedPreferences {
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
            if (key != null) {
                pending[key] = value
                removals.remove(key)
            }
            return this
        }

        override fun remove(key: String?): SharedPreferences.Editor {
            if (key != null) {
                removals.add(key)
                pending.remove(key)
            }
            return this
        }

        override fun apply() {
            commitPending()
        }

        override fun commit(): Boolean {
            commitPending()
            return true
        }

        private fun commitPending() {
            removals.forEach { store.remove(it) }
            pending.forEach { (key, value) -> store[key] = value }
            removals.clear()
            pending.clear()
        }

        override fun clear(): SharedPreferences.Editor = this
        override fun putStringSet(
            key: String?,
            values: MutableSet<String>?,
        ): SharedPreferences.Editor = this

        override fun putInt(key: String?, value: Int): SharedPreferences.Editor = this
        override fun putLong(key: String?, value: Long): SharedPreferences.Editor = this
        override fun putFloat(key: String?, value: Float): SharedPreferences.Editor = this
        override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor = this
    }
}

class UniffiKeyCustodyTest {

    private lateinit var custody: AndroidKeyCustody
    private lateinit var adapter: UniffiKeyCustody

    @Before
    fun setUp() {
        custody = AndroidKeyCustody(InMemoryPrefs())
        adapter = UniffiKeyCustody(custody)
    }

    /**
     * The adapter recovers a [KeyHandle] from the bare id the callback
     * interface passes, so a signature made through it verifies under the
     * public key the same id reports.
     */
    @Test
    fun `signs and reports a public key for a bare key id`() {
        runBlocking {
            val keyId = adapter.generateKeypair("ed25519")

            val publicKey = adapter.getPublicKey(keyId)
            assertEquals(32, publicKey.size)

            val message = "payload".toByteArray(Charsets.UTF_8)
            val signature = adapter.sign(keyId, message)
            assertEquals(64, signature.size)

            val verifier = Ed25519Signer()
            verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
            verifier.update(message, 0, message.size)
            assertTrue("signature must verify", verifier.verifySignature(signature))
        }
    }

    /**
     * The two published facts §3.2.2 of the identity spec names reach the bridge
     * through the adapter, and so does the storage-location string
     * `scp_platform::CustodyType` consumes.
     */
    @Test
    fun `forwards both published facts and the storage location`() {
        runBlocking {
            val keyId = adapter.generateKeypair("ed25519")

            assertTrue(
                "a Bouncy Castle key can leave its store",
                adapter.keyIsExtractable(keyId),
            )
            assertEquals("unprotected", adapter.unlockFactor(keyId))
            assertEquals("software", adapter.custodyType(keyId))
        }
    }

    /**
     * A derived pseudonym crosses as `[public_key(32) || key_id_utf8]`, the
     * layout `scp_ffi_common::custody_parse::unpack_pseudonym` reads, and the id
     * in its tail resolves to that same key.
     */
    @Test
    fun `packs a derived pseudonym into the layout the bridge unpacks`() {
        runBlocking {
            val keyId = adapter.generateKeypair("ed25519")
            val contextId = "context-alpha".toByteArray(Charsets.UTF_8)

            val packed = adapter.derivePseudonym(keyId, contextId)
            assertTrue(
                "packed pseudonym must carry a key id after the key",
                packed.size > 32,
            )

            val pseudonymPublicKey = packed.copyOfRange(0, 32)
            val pseudonymId = String(packed.copyOfRange(32, packed.size), Charsets.UTF_8)
            assertArrayEquals(
                "the packed key must be the derived pseudonym's own key",
                pseudonymPublicKey,
                adapter.getPublicKey(pseudonymId),
            )

            val rotatable = adapter.deriveRotatablePseudonym(keyId, contextId, 1uL)
            assertFalse(
                "epoch 1 must not collide with the static derivation",
                rotatable.copyOfRange(0, 32).contentEquals(pseudonymPublicKey),
            )
        }
    }

    /** X25519 key agreement crosses the adapter on both sides. */
    @Test
    fun `agrees on a shared secret through the adapter`() {
        runBlocking {
            val alice = adapter.generateKeypair("x25519")
            val bob = adapter.generateKeypair("x25519")

            val alicePublic = adapter.getPublicKey(alice)
            val bobPublic = adapter.getPublicKey(bob)

            assertArrayEquals(
                adapter.dhAgree(alice, bobPublic),
                adapter.dhAgree(bob, alicePublic),
            )
        }
    }

    /**
     * `destroyKey` drops the [DestructionAttestation] the Android adapter
     * returns, because the callback interface declares no return value, and the
     * key is gone afterwards.
     */
    @Test
    fun `destroys a key through the adapter`() {
        runBlocking {
            val keyId = adapter.generateKeypair("ed25519")
            adapter.destroyKey(keyId)

            val thrown = runCatching { adapter.getPublicKey(keyId) }.exceptionOrNull()
            assertNotNull("a destroyed key must not resolve", thrown)
            assertTrue(
                "a destroyed key must fail with the callback interface's exception type",
                thrown is uniffi.scp.ScpException.Crypto,
            )
        }
    }

    /**
     * An id neither store holds reaches the caller as the callback interface's
     * own exception type carrying the Android adapter's code. A
     * `works.limn.scp.android.platform.ScpException` escaping unconverted would
     * reach UniFFI as an undeclared error and lose that code.
     */
    @Test
    fun `an unknown key id throws the uniffi exception with the adapter's code`() {
        runBlocking {
            val thrown = runCatching { adapter.sign("no-such-key", ByteArray(1)) }
                .exceptionOrNull()
            assertTrue(
                "an unknown id must throw uniffi.scp.ScpException.Crypto, got $thrown",
                thrown is uniffi.scp.ScpException.Crypto,
            )
            assertEquals(
                "SCP-CRYPTO-4001",
                (thrown as uniffi.scp.ScpException.Crypto).code,
            )
        }
    }

    /** A key-type string outside the two the callback trait states fails closed. */
    @Test
    fun `an unknown key type throws the uniffi exception`() {
        runBlocking {
            val thrown = runCatching { adapter.generateKeypair("rsa") }.exceptionOrNull()
            assertTrue(
                "an unknown key type must throw uniffi.scp.ScpException.Crypto, got $thrown",
                thrown is uniffi.scp.ScpException.Crypto,
            )
            assertEquals(
                "SCP-CRYPTO-4003",
                (thrown as uniffi.scp.ScpException.Crypto).code,
            )
        }
    }

    /**
     * `custodyType` is the one callback method the generated interface declares
     * without an error, so an id neither store holds reads `"software"` — the
     * answer carrying the weaker claim of the three — rather than throwing
     * across the FFI boundary.
     */
    @Test
    fun `custodyType answers software for an id neither store holds`() {
        assertEquals("software", adapter.custodyType("no-such-key"))
    }

    /**
     * [AndroidKeyCustody.resolveKeyHandle] is what turns a bare id back into the
     * handle every method of the Kotlin interface takes, and it fails closed for
     * an id neither store holds.
     */
    @Test
    fun `resolveKeyHandle names the store that holds a key`() {
        runBlocking {
            val generated = custody.generateKeypair(KeyType.ED25519)

            val resolved = custody.resolveKeyHandle(generated.id)
            assertEquals(generated.id, resolved.id)
            assertEquals(CustodyType.SOFTWARE, resolved.custodyType)

            val thrown = runCatching { custody.resolveKeyHandle("no-such-key") }
                .exceptionOrNull()
            assertTrue(
                "an unknown id must throw the Android adapter's exception, got $thrown",
                thrown is ScpException,
            )
            assertEquals("SCP-CRYPTO-4001", (thrown as ScpException).code)
        }
    }
}
