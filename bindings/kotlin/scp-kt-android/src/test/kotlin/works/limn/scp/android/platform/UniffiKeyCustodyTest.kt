// UniffiKeyCustodyTest.kt — UniffiKeyCustody as the scp-ffi-uniffi KeyCustodyProvider (ADR-027)
//
// Calls every member of `uniffi.scp.KeyCustodyProvider` through UniffiKeyCustody over the software
// path of AndroidKeyCustody (JVM tests run with Build.VERSION.SDK_INT 0, below API 33), and checks
// the host contract on KeyCustodyProvider in crates/scp-ffi/uniffi/src/lib.rs: decimal u64 key ids,
// recorded roles, SCP-CRYPTO-4006 for an unknown id, and `uniffi.scp.ScpException` as the only
// thrown type.
//
// Provenance: spec 03 §3.2.2, ADR-027 (Android Platform Adapter), spec 25 §25.19 (pseudonym
// vectors 30 and 31).

package works.limn.scp.android.platform

import kotlinx.coroutines.test.runTest
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail
import uniffi.scp.CustodyKeyRole
import uniffi.scp.CustodyKeyType
import uniffi.scp.KeyCustodyProvider as BridgeProvider
import uniffi.scp.ScpException as BridgeException

/** Decodes lowercase hex. */
private fun unhex(text: String): ByteArray =
    ByteArray(text.length / 2) { text.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

/** The `uniffi.scp.ScpException.Crypto` [block] throws; fails when it throws nothing else. */
private suspend fun cryptoError(block: suspend () -> Unit): BridgeException.Crypto {
    try {
        block()
    } catch (e: BridgeException.Crypto) {
        return e
    }
    fail("expected uniffi.scp.ScpException.Crypto")
}

class UniffiKeyCustodyTest {
    private lateinit var prefs: InMemorySharedPreferences
    private lateinit var custody: AndroidKeyCustody

    // Typed as the generated interface, so every call below goes through the bridge protocol.
    private lateinit var provider: BridgeProvider

    @BeforeEach
    fun setUp() {
        prefs = InMemorySharedPreferences()
        custody = AndroidKeyCustody(prefs)
        provider = UniffiKeyCustody(custody)
    }

    /** Installs a software Ed25519 identity from [seed] under a decimal id, in [role]. */
    private fun installSeed(seed: ByteArray, role: KeyRole? = KeyRole.IDENTITY): String {
        val privateParams = Ed25519PrivateKeyParameters(seed, 0)
        val keyId = "18446744073709551557"
        custody.softwareKeys[keyId] = AsymmetricCipherKeyPair(privateParams.generatePublicKey(), privateParams)
        custody.softwareKeyTypes[keyId] = KeyType.ED25519
        if (role != null) custody.keyRoles.record(keyId, role, persist = false)
        return keyId
    }

    @Test
    fun `generateKeypair returns canonical decimal u64 ids`() {
        runTest {
            repeat(16) {
                for (type in listOf(CustodyKeyType.ED25519, CustodyKeyType.X25519)) {
                    val id = provider.generateKeypair(type, CustodyKeyRole.OPERATIONAL)
                    assertEquals(id, id.toULong().toString(), "id $id is not canonical decimal u64")
                }
            }
        }
    }

    @Test
    fun `identity key signs, reports its role, and exports its seed`() {
        runTest {
            val id = provider.generateKeypair(CustodyKeyType.ED25519, CustodyKeyRole.IDENTITY)

            val publicKey = provider.getPublicKey(id)
            assertEquals(CustodyKeyType.ED25519, publicKey.keyType)
            assertEquals(CustodyKeyRole.IDENTITY, publicKey.role)
            assertEquals(32, publicKey.publicKey.size)

            val message = "custody round trip".toByteArray()
            val signature = provider.sign(id, message)
            val verifier = Ed25519Signer().apply {
                init(false, Ed25519PublicKeyParameters(publicKey.publicKey, 0))
                update(message, 0, message.size)
            }
            assertTrue(verifier.verifySignature(signature))

            val seed = provider.exportSigningKeyBytes(id)
            assertArrayEquals(publicKey.publicKey, Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded)
            assertEquals("software", provider.custodyType(id))
        }
    }

    @Test
    fun `operational X25519 keys report their role and agree`() {
        runTest {
            val alice = provider.generateKeypair(CustodyKeyType.X25519, CustodyKeyRole.OPERATIONAL)
            val bob = provider.generateKeypair(CustodyKeyType.X25519, CustodyKeyRole.OPERATIONAL)
            val alicePublic = provider.getPublicKey(alice)
            val bobPublic = provider.getPublicKey(bob)
            assertEquals(CustodyKeyType.X25519, alicePublic.keyType)
            assertEquals(CustodyKeyRole.OPERATIONAL, alicePublic.role)

            val aliceShared = provider.dhAgree(alice, bobPublic.publicKey)
            assertArrayEquals(aliceShared, provider.dhAgree(bob, alicePublic.publicKey))
            assertEquals(32, aliceShared.size)
        }
    }

    @Test
    fun `dhAgree on an Ed25519 key uses the SHA-512(seed) X25519 scalar`() {
        runTest {
            // RFC 8032 §7.1 test 1 seed against RFC 7748 §6.1 Alice's public key. The expected secret
            // is X25519 of Alice's private scalar and the seed's converted public key
            // d85e07ec22b0ad881537c2f44d662d1a143cf830c57aca4305d85c7a90f6b62e, computed independently.
            val id = installSeed(unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
            val shared = provider.dhAgree(id, unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
            assertEquals("90f395580ca33f3c54390ac1d7210220b6a336de2c47a61ac90ff56e6be11f18", shared.hex())
        }
    }

    @Test
    fun `pseudonym members return the spec 25_19 vector 30 and 31 points`() {
        runTest {
            val context = "context-alpha".toByteArray()
            val vectors = listOf(
                Triple(
                    "32c69e4a096fadd1a8d0a21e0a97f124d5c4c8c5b15b96027beadb91c2f3ec64",
                    "0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72",
                    "0276c50b92dacbe6ae1a3761d007b7fe75016a4c076f214694c95d13162ff24479",
                ),
                Triple(
                    "65d56a863d03d31ea15ade82f677058d5bbe53afedc6ff7d2b8846aa25a1bc2b",
                    "0239f7c3213f3567183fd2fcf7aec6c884bc70e0e694c42053284a4b5ebef4fe2d",
                    "037967cfe8d3111cdd72288ea3f444c15b710300323162fec63ca9036af73754e3",
                ),
            )
            for ((seed, v1, v2) in vectors) {
                val id = installSeed(unhex(seed))
                val static = provider.derivePseudonym(id, context)
                assertEquals(33, static.size)
                assertEquals(v1, static.hex())
                assertEquals(v2, provider.deriveRotatablePseudonym(id, context, 1uL).hex())
            }
        }
    }

    @Test
    fun `an epoch above Long MAX_VALUE reaches the HMAC body unchanged`() {
        runTest {
            val id = installSeed(unhex("32c69e4a096fadd1a8d0a21e0a97f124d5c4c8c5b15b96027beadb91c2f3ec64"))
            val context = "context-alpha".toByteArray()
            val handle = KeyHandle(id = id, custodyType = CustodyType.SOFTWARE)
            assertArrayEquals(
                custody.deriveRotatablePseudonym(handle, context, -1L),
                provider.deriveRotatablePseudonym(id, context, ULong.MAX_VALUE),
            )
        }
    }

    @Test
    fun `every keyed member throws SCP-CRYPTO-4006 for an unknown id`() {
        runTest {
            val unknown = "12345"
            val peer = ByteArray(32) { 9 }
            val calls: List<Pair<String, suspend () -> Unit>> = listOf(
                "sign" to { provider.sign(unknown, byteArrayOf(1)) },
                "getPublicKey" to { provider.getPublicKey(unknown) },
                "destroyKey" to { provider.destroyKey(unknown) },
                "dhAgree" to { provider.dhAgree(unknown, peer) },
                "derivePseudonym" to { provider.derivePseudonym(unknown, byteArrayOf(1)) },
                "deriveRotatablePseudonym" to { provider.deriveRotatablePseudonym(unknown, byteArrayOf(1), 1uL) },
                "exportSigningKeyBytes" to { provider.exportSigningKeyBytes(unknown) },
            )
            for ((name, call) in calls) {
                assertEquals("SCP-CRYPTO-4006", cryptoError(call).code, name)
            }
            assertEquals("unknown", provider.custodyType(unknown))
        }
    }

    @Test
    fun `a destroyed key is unknown and its role is forgotten`() {
        runTest {
            val id = provider.generateKeypair(CustodyKeyType.ED25519, CustodyKeyRole.IDENTITY)
            provider.destroyKey(id)

            assertEquals("SCP-CRYPTO-4006", cryptoError { provider.sign(id, byteArrayOf(1)) }.code)
            assertEquals("SCP-CRYPTO-4006", cryptoError { provider.destroyKey(id) }.code)
            assertNull(custody.keyRoles.roleOf(id))
            assertFalse(prefs.contains("scp.role.$id"))
        }
    }

    @Test
    fun `an Android error keeps its code and cause`() {
        runTest {
            val id = provider.generateKeypair(CustodyKeyType.X25519, CustodyKeyRole.OPERATIONAL)
            val error = cryptoError { provider.sign(id, byteArrayOf(1)) }
            assertEquals("SCP-CRYPTO-4003", error.code)
            assertTrue(error.cause is ScpException)
        }
    }

    @Test
    fun `a non-ScpException failure becomes SCP-CRYPTO-4060 carrying the cause`() {
        runTest {
            // Bouncy Castle throws IllegalStateException for a low-order peer key.
            val id = provider.generateKeypair(CustodyKeyType.X25519, CustodyKeyRole.OPERATIONAL)
            val error = cryptoError { provider.dhAgree(id, ByteArray(32)) }
            assertEquals("SCP-CRYPTO-4060", error.code)
            assertTrue(error.cause is IllegalStateException)
        }
    }

    @Test
    fun `P256 and HPKE P256 fail closed with SCP-CRYPTO-4060`() {
        runTest {
            for (type in listOf(CustodyKeyType.P256, CustodyKeyType.HPKE_P256)) {
                val error = cryptoError { provider.generateKeypair(type, CustodyKeyRole.OPERATIONAL) }
                assertEquals("SCP-CRYPTO-4060", error.code, type.name)
            }
            assertTrue(custody.softwareKeys.isEmpty())
        }
    }

    @Test
    fun `getPublicKey fails closed with SCP-CRYPTO-4060 for a key with no recorded role`() {
        runTest {
            val id = installSeed(ByteArray(32) { 7 }, role = null)
            assertEquals("SCP-CRYPTO-4060", cryptoError { provider.getPublicKey(id) }.code)
        }
    }

    @Test
    fun `an Ed25519 key's role survives a new custody instance`() {
        runTest {
            val id = provider.generateKeypair(CustodyKeyType.ED25519, CustodyKeyRole.IDENTITY)
            val restored = UniffiKeyCustody(AndroidKeyCustody(prefs))
            assertEquals(CustodyKeyRole.IDENTITY, restored.getPublicKey(id).role)
            assertArrayEquals(provider.getPublicKey(id).publicKey, restored.getPublicKey(id).publicKey)
        }
    }

    @Test
    fun `generateKeypair on the Kotlin interface mints an operational key`() {
        runTest {
            val handle = custody.generateKeypair(KeyType.ED25519)
            assertEquals(CustodyKeyRole.OPERATIONAL, provider.getPublicKey(handle.id).role)
        }
    }
}
