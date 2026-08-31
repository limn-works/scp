package works.limn.scp.android.platform

/**
 * Presents an [AndroidKeyCustody] as the `uniffi.scp.KeyCustodyProvider` the
 * UniFFI bridge calls back into, so an Android app passes the shipped adapter
 * to `works.limn.scp.Scp.identityCreateWithCustody`.
 *
 * The two interfaces name the same eleven operations and declare them
 * differently. [KeyCustodyProvider] is the Kotlin-idiomatic one: it takes a
 * [KeyHandle] and a [KeyType], and it returns [PseudonymKeyHandle] and
 * [DestructionAttestation]. `uniffi.scp.KeyCustodyProvider` is generated from
 * the Rust callback trait: it takes an opaque id string and a key-type string,
 * it returns `ByteArray` and `Unit`, and its eight I/O methods are `suspend`.
 * Neither interface can satisfy the other, so this class converts between them
 * in one place. Before it existed, `identityCreateWithCustody` reached no
 * shipped Android adapter and `os_keystore` had no producer on Android.
 *
 * Three conversions carry a decision:
 *
 * 1. **Id to handle.** Every [KeyCustodyProvider] method takes a [KeyHandle],
 *    which pairs the id with the [CustodyType] naming which store holds the
 *    key, and the UniFFI interface passes the id alone.
 *    [AndroidKeyCustody.resolveKeyHandle] asks the two stores which one holds
 *    the id, and throws `SCP-CRYPTO-4001` when neither does.
 * 2. **Pseudonym packing.** The UniFFI interface returns a pseudonym as
 *    `[public_key_bytes (32) || key_id_utf8]`, which
 *    `scp_ffi_common::custody_parse::unpack_pseudonym` reads on the Rust side.
 *    [KeyCustodyProvider.derivePseudonym] returns a [PseudonymKeyHandle]
 *    carrying no public key, so this class reads the public key back through
 *    [KeyCustodyProvider.publicKey] and concatenates the two.
 * 3. **Exception mapping.** [AndroidKeyCustody] throws
 *    `works.limn.scp.android.platform.ScpException`, and UniFFI declares
 *    `uniffi.scp.ScpException` as the callback error type. Every method here
 *    converts the first into `uniffi.scp.ScpException.Crypto`, preserving the
 *    structured code the Android adapter raised, so a caller reads the
 *    condition rather than an unexpected-error wrapper.
 *
 * The epoch conversion is unsigned on one side and signed on the other. The
 * Rust trait declares `pseudonym_epoch: u64`, which UniFFI renders as
 * `kotlin.ULong`, and [KeyCustodyProvider.deriveRotatablePseudonym] takes a
 * `Long`. [toLong] reinterprets the same 64 bits, and the adapter folds the
 * value in as a big-endian 8-byte block
 * ([AndroidKeyCustody.deriveRotatablePseudonym]), so the two agree on every
 * epoch including those above `Long.MAX_VALUE`.
 *
 * ```kotlin
 * val custody = AndroidKeyCustody(context)
 * val identity = scp.identityCreateWithCustody(UniffiKeyCustody(custody))
 * ```
 *
 * Neither published fact this class forwards reaches a non-extractable
 * published custody value today: [AndroidKeyCustody.unlockFactor] answers
 * `"unprotected"` for every key, and §3.2.2 of the identity spec states no
 * published value for a pair carrying that factor, so the bridge publishes
 * nothing. Open question OQ-12 of that spec asks which further pairs the
 * published vocabulary should state.
 *
 * See ADR-027, the Android platform adapter, ADR-006, the platform
 * abstraction, and §3.2.2 of the identity spec, the custody vocabulary.
 *
 * @property inner The Android adapter this class forwards every call to.
 */
class UniffiKeyCustody(
    private val inner: AndroidKeyCustody,
) : uniffi.scp.KeyCustodyProvider {

    /** Signs [message] with the Ed25519 key [keyId] names. */
    override suspend fun sign(keyId: String, message: ByteArray): ByteArray =
        mapErrors { inner.sign(inner.resolveKeyHandle(keyId), message) }

    /** Returns the 32 raw public-key bytes for [keyId]. */
    override suspend fun getPublicKey(keyId: String): ByteArray =
        mapErrors { inner.publicKey(inner.resolveKeyHandle(keyId)) }

    /**
     * Destroys the key material [keyId] names.
     *
     * Drops the [DestructionAttestation] the Android adapter returns, because
     * the UniFFI interface declares no return value. A caller that needs the
     * attestation calls [AndroidKeyCustody.destroyKey] directly.
     */
    override suspend fun destroyKey(keyId: String) {
        mapErrors { inner.destroyKey(inner.resolveKeyHandle(keyId)) }
    }

    /**
     * Generates a keypair and returns the id half of its handle.
     *
     * @param keyType `"ed25519"` or `"x25519"`, the two strings the Rust
     *   callback trait states.
     * @throws uniffi.scp.ScpException.Crypto carrying `SCP-CRYPTO-4003` for any
     *   other string.
     */
    override suspend fun generateKeypair(keyType: String): String = mapErrors {
        val parsed = when (keyType) {
            "ed25519" -> KeyType.ED25519
            "x25519" -> KeyType.X25519
            else -> throw ScpException(
                "Unknown key type '$keyType' — the callback interface states " +
                    "\"ed25519\" and \"x25519\"",
                "SCP-CRYPTO-4003",
            )
        }
        inner.generateKeypair(parsed).id
    }

    /** Performs X25519 Diffie-Hellman with the key [keyId] names. */
    override suspend fun dhAgree(keyId: String, peerPublic: ByteArray): ByteArray =
        mapErrors { inner.dhAgree(inner.resolveKeyHandle(keyId), peerPublic) }

    /** Derives a context-scoped pseudonym keypair from the key [keyId] names. */
    override suspend fun derivePseudonym(keyId: String, contextId: ByteArray): ByteArray =
        mapErrors {
            packPseudonym(inner.derivePseudonym(inner.resolveKeyHandle(keyId), contextId))
        }

    /**
     * Derives an epoch-versioned pseudonym keypair from the key [keyId] names.
     *
     * [pseudonymEpoch] crosses as a `ULong` and the Android adapter takes a
     * `Long`; [ULong.toLong] reinterprets the same 64 bits, which is what the
     * adapter folds in as a big-endian block.
     */
    override suspend fun deriveRotatablePseudonym(
        keyId: String,
        contextId: ByteArray,
        pseudonymEpoch: ULong,
    ): ByteArray = mapErrors {
        packPseudonym(
            inner.deriveRotatablePseudonym(
                inner.resolveKeyHandle(keyId),
                contextId,
                pseudonymEpoch.toLong(),
            ),
        )
    }

    /** Returns the raw 32 Ed25519 private-key bytes for [keyId]. */
    override suspend fun exportSigningKeyBytes(keyId: String): ByteArray =
        mapErrors { inner.exportSigningKeyBytes(inner.resolveKeyHandle(keyId)) }

    /**
     * Reports where the key [keyId] names lives: `"hardware"`, `"software"`, or
     * `"in_memory"`, the three strings `scp_platform::CustodyType` consumes.
     *
     * The UniFFI interface declares no error for this method, so an id neither
     * store holds reads `"software"` rather than throwing. That is the answer
     * carrying the weaker claim of the three: `"hardware"` would tell the core
     * a key sits in the TEE on the strength of an id nothing resolved.
     */
    override fun custodyType(keyId: String): String =
        when (runCatching { inner.resolveKeyHandle(keyId) }.getOrNull()?.custodyType) {
            CustodyType.HARDWARE -> "hardware"
            CustodyType.IN_MEMORY -> "in_memory"
            CustodyType.SOFTWARE, null -> "software"
        }

    /**
     * Reports whether the private key [keyId] names can leave its store.
     *
     * One of the two facts §3.2.2 of the identity spec states a DID document
     * publishes about custody.
     */
    override fun keyIsExtractable(keyId: String): Boolean =
        mapErrors { inner.keyIsExtractable(inner.resolveKeyHandle(keyId)) }

    /**
     * Reports which factor unlocks the key [keyId] names.
     *
     * The other fact §3.2.2 of the identity spec states a DID document
     * publishes about custody. [AndroidKeyCustody.unlockFactor] answers
     * `"unprotected"` for every key it holds.
     */
    override fun unlockFactor(keyId: String): String =
        mapErrors { inner.unlockFactor(inner.resolveKeyHandle(keyId)) }

    /**
     * Packs a [PseudonymKeyHandle] into the layout the Rust side unpacks: the
     * 32 public-key bytes followed by the handle id's UTF-8 bytes.
     *
     * [KeyCustodyProvider.derivePseudonym] returns no public key, so this reads
     * one back through [KeyCustodyProvider.publicKey] on the derived handle.
     */
    private fun packPseudonym(pseudonym: PseudonymKeyHandle): ByteArray {
        val handle = KeyHandle(id = pseudonym.id, custodyType = pseudonym.custodyType)
        return inner.publicKey(handle) + pseudonym.id.toByteArray(Charsets.UTF_8)
    }

    /**
     * Runs [block] and converts a `works.limn.scp.android.platform.ScpException`
     * into the `uniffi.scp.ScpException` the callback interface declares,
     * carrying the same code.
     *
     * An Android-package `ScpException` that escaped unconverted would reach
     * UniFFI as an undeclared error, which loses the structured code the
     * Android adapter raised.
     */
    private inline fun <T> mapErrors(block: () -> T): T =
        try {
            block()
        } catch (e: ScpException) {
            // `uniffi.scp.ScpException.Crypto` takes a message and a code and
            // no cause, so `initCause` carries the Android adapter's exception
            // and its stack trace across the conversion rather than dropping
            // them.
            throw uniffi.scp.ScpException.Crypto(
                msg = e.message ?: "key custody operation failed",
                code = e.code,
            ).apply { initCause(e) }
        }
}
