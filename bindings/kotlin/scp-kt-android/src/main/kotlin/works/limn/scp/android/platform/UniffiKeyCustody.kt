// UniffiKeyCustody.kt — AndroidKeyCustody as the scp-ffi-uniffi KeyCustodyProvider (ADR-027)
//
// The `os_keystore` custody request of spec 03 §3.2.2 reaches the host key store only through a
// `uniffi.scp.KeyCustodyProvider` passed to `SCP.identityCreateWithCustody`. This class is that
// provider over [AndroidKeyCustody], so an Android app passes `UniffiKeyCustody(custody)` and
// writes no glue. It follows the host contract on `KeyCustodyProvider` in
// `crates/scp-ffi/uniffi/src/lib.rs`: decimal u64 key ids, the role recorded at generation and
// reported from getPublicKey, `SCP-CRYPTO-4006` for an unknown id, and `uniffi.scp.ScpException`
// as the only thrown type.
//
// Provenance: spec 03 §3.2.2, ADR-027 (Android Platform Adapter), ADR-006 (Platform Abstraction
// Layer).

package works.limn.scp.android.platform

import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.scp.CustodyKeyRole
import uniffi.scp.CustodyKeyType
import uniffi.scp.CustodyPublicKey
import uniffi.scp.ScpException as BridgeException

/**
 * [AndroidKeyCustody] as the UniFFI-generated `uniffi.scp.KeyCustodyProvider`, the provider
 * `SCP.identityCreateWithCustody` takes for the `os_keystore` custody request (spec 03 §3.2.2):
 *
 * ```kotlin
 * val identity = scp.identityCreateWithCustody(UniffiKeyCustody(AndroidKeyCustody(context)))
 * ```
 *
 * Each member resolves its key id against [inner] and forwards to the [AndroidKeyCustody]
 * method of the same purpose on [Dispatchers.IO], since Keystore and the encrypted preferences
 * block.
 *
 * Errors: every failure reaches the bridge as `uniffi.scp.ScpException.Crypto`. An
 * [ScpException] from [inner] keeps its code, so an unknown or destroyed id arrives as
 * `SCP-CRYPTO-4006`, which the bridge reports as key-not-found; any other code, and any other
 * exception (carried as the cause), the bridge reports as the custody error `SCP-CRYPTO-4060`.
 * Coroutine cancellation propagates unchanged.
 *
 * The adapter holds Ed25519, P-256 signing and HPKE P-256 keys. A P-256 signature is Keystore's DER over the bridge's
 * 32-byte digest; the bridge converts it to raw low-s and verifies it.
 *
 * @param inner The custody whose keys this adapter exposes.
 */
class UniffiKeyCustody(private val inner: AndroidKeyCustody) : uniffi.scp.KeyCustodyProvider {
    override suspend fun sign(keyId: String, message: ByteArray): ByteArray =
        bridged { inner.sign(inner.resolveKeyHandle(keyId), message) }

    /**
     * The key's type, public key and recorded role. A key [inner] holds with no recorded role,
     * such as a persisted seed whose role entry is missing from the preferences, fails with
     * `SCP-CRYPTO-4060`, because guessing a role could promote an operational key to the
     * identity.
     */
    override suspend fun getPublicKey(keyId: String): CustodyPublicKey = bridged {
        val handle = inner.resolveKeyHandle(keyId)
        val publicKey = inner.publicKey(handle)
        val keyType = when (keyTypeOf(keyId, handle)) {
            KeyType.ED25519 -> CustodyKeyType.ED25519
            KeyType.P256 -> CustodyKeyType.P256
            KeyType.HPKE_P256 -> CustodyKeyType.HPKE_P256
        }
        val role = when (inner.roleOf(keyId)) {
            KeyRole.IDENTITY -> CustodyKeyRole.IDENTITY
            KeyRole.OPERATIONAL -> CustodyKeyRole.OPERATIONAL
            null -> throw ScpException("No role recorded for key $keyId", CUSTODY_ERROR)
        }
        CustodyPublicKey(keyType = keyType, publicKey = publicKey, role = role)
    }

    /**
     * Destroys the key [keyId], including a P-256 key whose mint is still pending and a Keystore
     * alias that has no record, so a key left by a failed or interrupted mint is destroyable.
     */
    override suspend fun destroyKey(keyId: String) {
        bridged { inner.destroyKeyById(keyId) }
    }

    /** Mints a [keyType] key in [role] and returns its decimal u64 id. */
    override suspend fun generateKeypair(keyType: CustodyKeyType, role: CustodyKeyRole): String = bridged {
        val androidType = when (keyType) {
            CustodyKeyType.ED25519 -> KeyType.ED25519
            CustodyKeyType.P256 -> KeyType.P256
            CustodyKeyType.HPKE_P256 -> KeyType.HPKE_P256
        }
        val androidRole = when (role) {
            CustodyKeyRole.IDENTITY -> KeyRole.IDENTITY
            CustodyKeyRole.OPERATIONAL -> KeyRole.OPERATIONAL
        }
        inner.generateKeypair(androidType, androidRole).id
    }

    override suspend fun dhAgree(keyId: String, peerPublic: ByteArray): ByteArray =
        bridged { inner.dhAgree(inner.resolveKeyHandle(keyId), peerPublic) }

    override suspend fun derivePseudonym(keyId: String, contextId: ByteArray): ByteArray =
        bridged { inner.derivePseudonym(inner.resolveKeyHandle(keyId), contextId) }

    /**
     * The §25.19 v2 pseudonym point. [pseudonymEpoch] is passed to [inner] as the `Long` with
     * the same 64 bits, so the big-endian epoch in the HMAC body is unchanged.
     */
    override suspend fun deriveRotatablePseudonym(
        keyId: String,
        contextId: ByteArray,
        pseudonymEpoch: ULong,
    ): ByteArray = bridged {
        inner.deriveRotatablePseudonym(inner.resolveKeyHandle(keyId), contextId, pseudonymEpoch.toLong())
    }

    /**
     * The custody class of [keyId]: for a P-256 key the class its record holds, read from
     * `KeyInfo` at mint; `"hardware"` for a Keystore Ed25519 key (which does not read
     * `KeyInfo`); `"software"` for a software key; and `"in_memory"` for an id [inner] does not
     * hold, or whose mint is pending. This member is synchronous and cannot throw to the bridge,
     * so an unknown id reports the weakest custody.
     */
    override fun custodyType(keyId: String): String =
        runCatching { inner.resolveKeyHandle(keyId).custodyType }.fold(
            onSuccess = {
                when (it) {
                    CustodyType.HARDWARE -> "hardware"
                    CustodyType.SOFTWARE -> "software"
                    CustodyType.IN_MEMORY -> "in_memory"
                }
            },
            onFailure = { "in_memory" },
        )

    /**
     * The type of [keyId]: from its record for a P-256 key, from `softwareKeyTypes` for a
     * software key, and Ed25519 for a Keystore key without a record, the only type
     * [AndroidKeyCustody] keeps there. Anything else is `SCP-CRYPTO-4060`.
     */
    private fun keyTypeOf(keyId: String, handle: KeyHandle): KeyType =
        inner.keyRecords.get(keyId)?.type
            ?: inner.softwareKeyTypes[keyId]
            ?: if (handle.custodyType == CustodyType.HARDWARE) {
                KeyType.ED25519
            } else {
                throw ScpException("No key type recorded for key $keyId", CUSTODY_ERROR)
            }

    /**
     * Runs [block] on [Dispatchers.IO] and converts its failure as the class KDoc states. An
     * [Error] and a [CancellationException] propagate unchanged.
     */
    private suspend fun <T> bridged(block: () -> T): T = withContext(Dispatchers.IO) {
        runCatching(block).getOrElse { e ->
            throw when (e) {
                is CancellationException, is BridgeException, !is Exception -> e
                is ScpException -> BridgeException.Crypto(e.message ?: e.code, e.code).apply { initCause(e) }
                else -> BridgeException.Crypto(e.message ?: e.javaClass.name, CUSTODY_ERROR).apply { initCause(e) }
            }
        }
    }
}
