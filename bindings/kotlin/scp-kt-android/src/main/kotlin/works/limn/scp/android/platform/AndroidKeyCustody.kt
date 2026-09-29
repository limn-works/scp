// AndroidKeyCustody.kt — KeyCustodyProvider implementation for Android (ADR-027)
//
// Ed25519 key custody using Android Keystore (TEE-backed) on API 33+ and Bouncy Castle
// software fallback on API 26-32. X25519 wrapping keys are always software-managed via
// Bouncy Castle. StrongBox is explicitly NOT used due to 10-100x latency penalty that
// is incompatible with SCP's frequent signing operations.
//
// Private keys never cross the custody boundary — all signing and DH operations happen
// inside this class. Raw private key bytes stay inside the Kotlin adapter. This class
// implements this package's own [KeyCustodyProvider], not the `scp-ffi-uniffi` bridge
// protocol: no in-tree Kotlin host implements the bridge protocol yet (S0 PR8 conforms it).
//
// Software Ed25519 keys (API 26-32 fallback) are persisted to EncryptedSharedPreferences
// (Jetpack Security) so they survive process death. Without this, API 26-32 users would
// lose their DID identity key on every process restart — causing identity loss, context
// membership loss, and UCAN delegation loss. See issue #119.
//
// Provenance: ADR-027 (Android Platform Adapter), ADR-006 (Platform Abstraction Layer),
// ADR-025 (Apple Platform Adapter — parallel reference), section 9.12 (Compromise Recovery),
// section 9.15 (Key Destruction Verification).

package works.limn.scp.android.platform

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyStore
import java.security.Signature
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.prng.FixedSecureRandom
import java.security.SecureRandom

/**
 * Android Keystore-backed key custody provider for SCP Ed25519 and X25519 keys.
 *
 * Implements this package's [KeyCustodyProvider] interface (mirroring the Rust `KeyCustody`
 * trait from `scp-platform/src/traits.rs`). It does NOT implement the `scp-ffi-uniffi`
 * `KeyCustodyProvider` callback protocol (whose key ids are u64 strings and whose
 * `derivePseudonym` returns a `PseudonymResult`): no in-tree Kotlin host implements the
 * bridge protocol yet, and S0 PR8 conforms this class to it.
 *
 * ## Key storage strategy
 *
 * - **Ed25519 on API 33+ (Android 13+):** Android Keystore natively supports `EdDSA`
 *   with `Ed25519` parameter spec. Keys are TEE-backed — the private key bytes never
 *   leave the Trusted Execution Environment. This is a stronger security posture than
 *   Apple's Secure Enclave (which only supports P-256). [CustodyType.HARDWARE] is reported.
 *
 * - **Ed25519 on API 26-32:** `EdDSA` is not available in Android Keystore on these API
 *   levels. Bouncy Castle provides software Ed25519. Keys are stored in [softwareKeys]
 *   in-memory. [CustodyType.SOFTWARE] is reported.
 *
 * - **X25519 (all API levels):** X25519 key agreement is not supported by Android Keystore
 *   at any API level. All X25519 wrapping keys are software-managed via Bouncy Castle,
 *   stored in [softwareKeys]. [CustodyType.SOFTWARE] is reported.
 *
 * ## TEE vs StrongBox
 *
 * TEE is the default and only option. StrongBox is NOT used. StrongBox operations are
 * 10-100x slower than TEE — latency that would visibly degrade SCP protocol participation
 * where every send operation requires a signature. See ADR-027 for the full rationale.
 *
 * ## Thread safety
 *
 * Android Keystore operations are thread-safe. The [softwareKeys] map is a
 * [ConcurrentHashMap] for safe concurrent access from multiple UniFFI callback threads.
 *
 * ## Compromise recovery
 *
 * Key rotation follows the 6-step recovery process from section 9.12:
 *   1. Generate new identity keypair via [generateKeypair]
 *   2. Publish new DID document with updated key material
 *   3. Re-join affected contexts with new identity
 *   4. Revoke UCAN delegations from compromised key
 *   5. Request admin role re-assignment in governed contexts
 *   6. Destroy compromised key via [destroyKey]
 *
 * See ADR-027 for the full Android platform adapter design.
 *
 * @property encryptedPrefs Persistent storage for software Ed25519 private key seeds.
 *   In production, this is an [EncryptedSharedPreferences] instance backed by Android
 *   Keystore. In tests, a plain [SharedPreferences] can be injected.
 * @property keystore The Android Keystore operations of the hardware identity path;
 *   JVM tests inject a fake.
 * @property keystoreEd25519 Whether Ed25519 identities are generated in [keystore]
 *   (API 33+) rather than in software.
 */
class AndroidKeyCustody internal constructor(
    private val encryptedPrefs: SharedPreferences,
    private val keystore: KeystoreKeys = AndroidKeystoreKeys,
    private val keystoreEd25519: Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU,
) : KeyCustodyProvider {

    /**
     * Production constructor — creates [EncryptedSharedPreferences] backed by Android
     * Keystore for persisting software Ed25519 keys (ADR-027, #119).
     *
     * @param context Android application context. Must be an application context
     *   (not an activity context) to avoid memory leaks from long-lived references.
     */
    constructor(context: Context) : this(
        EncryptedSharedPreferences.create(
            PREFS_FILENAME,
            MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
            context.applicationContext,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        ),
    )

    // -----------------------------------------------------------------------
    // Software key storage — used for API 26-32 Ed25519 and all X25519 keys
    // -----------------------------------------------------------------------

    /**
     * In-memory storage for software-managed keys (Bouncy Castle).
     *
     * Key: UUID string (same as [KeyHandle.id]).
     * Value: Bouncy Castle asymmetric key pair (Ed25519 or X25519).
     *
     * This map is only used for keys that cannot be stored in Android Keystore:
     * - Ed25519 keys on API 26-32 (no Keystore EdDSA support)
     * - X25519 keys on all API levels (no Keystore X25519 support)
     *
     * Ed25519 identity keys are additionally backed by [encryptedPrefs] so they
     * survive process death. X25519 wrapping keys are ephemeral.
     */
    internal val softwareKeys = ConcurrentHashMap<String, AsymmetricCipherKeyPair>()

    /**
     * Tracks the [KeyType] for each software-managed key.
     *
     * Used to enforce type safety in [sign] and [dhAgree] operations.
     */
    internal val softwareKeyTypes = ConcurrentHashMap<String, KeyType>()

    /**
     * P-256 pseudonym private scalars (32-byte big-endian, §9.10.4), keyed by the
     * deterministic pseudonym handle id of [P256Pseudonym.pseudonymId].
     *
     * Pseudonym keys are in-memory: they are re-derived on demand from the identity
     * key's pseudonym secret, so they are never persisted. One entry exists per
     * (identity, context, epoch), because re-deriving keeps the existing one, and
     * destroying the identity destroys all of its entries.
     */
    internal val pseudonymKeys = PseudonymKeys()

    /**
     * Delegate for Bouncy Castle software key operations.
     *
     * Shares the same [softwareKeys] and [softwareKeyTypes] maps so that keys
     * created via the delegate are visible to [AndroidKeyCustody] methods
     * (e.g., [dhAgree], [derivePseudonym]) and vice versa. Also holds a
     * reference to [encryptedPrefs] for persisting Ed25519 key seeds.
     */
    private val softwareKeyOps = SoftwareKeyOps(softwareKeys, softwareKeyTypes, encryptedPrefs)

    init {
        softwareKeyOps.restorePersistedEd25519Keys()
    }

    // -----------------------------------------------------------------------
    // KeyCustodyProvider implementation
    // -----------------------------------------------------------------------

    /**
     * Generates a new keypair of the specified type.
     *
     * Routing logic:
     * - [KeyType.ED25519] + API 33+: Android Keystore TEE-backed via `EdDSA` algorithm.
     * - [KeyType.ED25519] + API 26-32: Bouncy Castle software fallback.
     * - [KeyType.X25519]: Always Bouncy Castle software (Keystore has no X25519 support).
     *
     * @param keyType The type of key to generate.
     * @return [KeyHandle] with [CustodyType.HARDWARE] for Keystore keys or
     *   [CustodyType.SOFTWARE] for Bouncy Castle keys.
     */
    override fun generateKeypair(keyType: KeyType): KeyHandle {
        val keyId = UUID.randomUUID().toString()
        return when {
            keystoreEd25519 && keyType == KeyType.ED25519 -> {
                generateKeystoreEd25519(keyId)
            }
            keyType == KeyType.ED25519 -> {
                softwareKeyOps.generateEd25519(keyId)
            }
            else -> {
                // X25519 wrapping keys are always software-managed
                softwareKeyOps.generateX25519(keyId)
            }
        }
    }

    /**
     * Signs [data] with the Ed25519 key identified by [keyHandle].
     *
     * For hardware-backed keys ([CustodyType.HARDWARE]): the signing operation happens
     * entirely inside the TEE via Android Keystore's `EdDSA` signature provider. The
     * private key bytes never leave hardware.
     *
     * For software-backed keys ([CustodyType.SOFTWARE]): Bouncy Castle's [Ed25519Signer]
     * performs the signing with key material from [softwareKeys].
     *
     * @param keyHandle Handle returned by [generateKeypair] for an Ed25519 key.
     * @param data The bytes to sign. For a pseudonym handle from [derivePseudonym], a
     *   32-byte digest, signed without a second hash as P-256 ECDSA with an RFC 6979
     *   nonce and low s (§9.5).
     * @return 64-byte signature.
     * @throws ScpException with code `SCP-CRYPTO-4006` if the key is not found.
     * @throws ScpException with code `SCP-CRYPTO-4003` if the key is not Ed25519.
     * @throws ScpException with code `SCP-VALID-7005` if a pseudonym handle is given
     *   anything but a 32-byte digest.
     */
    override fun sign(keyHandle: KeyHandle, data: ByteArray): ByteArray {
        pseudonymKeys.withScalar(keyHandle.id) { P256Pseudonym.signPrehash(it, data) }?.let { return it }
        return if (keyHandle.custodyType == CustodyType.HARDWARE) {
            signWithKeystore(keyHandle, data)
        } else {
            softwareKeyOps.sign(keyHandle, data)
        }
    }

    /**
     * Returns the raw 32-byte public key for [keyHandle].
     *
     * For hardware-backed Ed25519 keys: extracts the raw 32-byte Ed25519 public key
     * from the X.509-encoded certificate in Android Keystore. The X.509 SubjectPublicKeyInfo
     * encoding for Ed25519 has a 12-byte header; the raw key is the last 32 bytes.
     *
     * For software-backed keys: returns the Bouncy Castle public key parameters directly.
     *
     * @param keyHandle Handle returned by [generateKeypair] or [derivePseudonym].
     * @return Raw 32-byte public key bytes, or the 33-byte compressed P-256 point for a
     *   pseudonym handle.
     * @throws ScpException with code `SCP-CRYPTO-4006` if the key is not found.
     */
    override fun publicKey(keyHandle: KeyHandle): ByteArray {
        pseudonymKeys.withScalar(keyHandle.id) { P256Pseudonym.compressedPublicKey(it) }?.let { return it }
        return if (keyHandle.custodyType == CustodyType.HARDWARE) {
            publicKeyFromKeystore(keyHandle)
        } else {
            softwareKeyOps.publicKey(keyHandle)
        }
    }

    /**
     * Destroys the key material associated with [keyHandle].
     *
     * For hardware-backed keys: deletes the entry from Android Keystore and performs
     * a re-fetch to confirm deletion (section 9.15 key destruction verification).
     *
     * For software-backed keys: removes the entry from the [softwareKeys] map.
     *
     * For an identity key: also wipes every P-256 pseudonym scalar derived from it, and
     * refuses any derivation from it still in flight (§9.10.4.A).
     *
     * After this call, all subsequent operations with the same handle will throw
     * [ScpException] with code `SCP-CRYPTO-4006`.
     *
     * @param keyHandle Handle to destroy.
     * @return [DestructionAttestation] confirming the destruction method and verification.
     * @throws ScpException with code `SCP-CRYPTO-4006` if the handle is already invalid.
     * @throws ScpException with code `SCP-CRYPTO-4004` if destruction cannot be confirmed.
     */
    override fun destroyKey(keyHandle: KeyHandle): DestructionAttestation {
        if (pseudonymKeys.remove(keyHandle.id)) {
            return DestructionAttestation(method = DestructionMethod.SOFTWARE_ONLY, confirmed = true)
        }
        val attestation = if (keyHandle.custodyType == CustodyType.HARDWARE) {
            destroyKeystoreKey(keyHandle)
        } else {
            softwareKeyOps.destroy(keyHandle)
        }
        // After the identity is gone no new derivation can start, and retiring wipes
        // the ones already stored and refuses the ones still in flight.
        pseudonymKeys.retireIdentity(keyHandle.id)
        return attestation
    }

    /**
     * Performs X25519 Diffie-Hellman key agreement.
     *
     * X25519 wrapping keys are always software-managed (Bouncy Castle), as Android Keystore
     * does not support X25519. The private key never leaves the [AndroidKeyCustody] boundary
     * -- the scalar multiplication happens inside this method.
     *
     * @param keyHandle Handle to an X25519 key from [generateKeypair].
     * @param peerPublic 32-byte X25519 public key of the peer.
     * @return 32-byte X25519 shared secret.
     * @throws ScpException with code `SCP-CRYPTO-4006` if the X25519 key is not found.
     */
    override fun dhAgree(keyHandle: KeyHandle, peerPublic: ByteArray): ByteArray {
        if (peerPublic.size != 32) {
            throw ScpException(
                "peerPublic must be exactly 32 bytes (X25519 public key), got ${peerPublic.size}",
                "SCP-CRYPTO-4003",
            )
        }

        // Enforce X25519 type — passing an Ed25519 handle would cause a
        // Bouncy Castle ClassCastException when interpreting Ed25519PrivateKeyParameters
        // as X25519PrivateKeyParameters.
        val storedType = softwareKeyTypes[keyHandle.id]
        if (storedType != null && storedType != KeyType.X25519) {
            throw ScpException(
                "dhAgree requires an X25519 key; handle '${keyHandle.id}' is Ed25519",
                "SCP-CRYPTO-4003",
            )
        }

        val keyPair = softwareKeys[keyHandle.id]
            ?: throw ScpException(
                "X25519 key not found: ${keyHandle.id}",
                "SCP-CRYPTO-4006",
            )
        val agreement = X25519Agreement()
        agreement.init(keyPair.private)
        val secret = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(
            X25519PublicKeyParameters(peerPublic, 0),
            secret,
            0,
        )
        return secret
    }

    /**
     * Derives a deterministic, context-scoped P-256 pseudonym keypair (§9.10.4).
     *
     * ## Algorithm (spec §9.10.4, §9.10.4.A):
     *
     *   1. `seed = HMAC-SHA256(pseudonym_secret, contextId || "scp-pseudonym")`, where
     *      `pseudonym_secret` is the identity key's §9.10.4.A secret (see [contextSeed]).
     *   2. `d = HKDF-Expand-SHA256(prk = seed, info = "SCP-PSEUDONYM-P256-V1", 48)
     *      mod (n - 1) + 1` (FIPS 186-5 A.2.1), computed by the Rust `scp-crypto`
     *      reduction through the `p256PseudonymScalar` export.
     *   3. The public key is the 33-byte compressed point `d * G`.
     *
     * **Software keys (API 26-32, [CustodyType.SOFTWARE]):** `pseudonym_secret =
     * HKDF-SHA256(ikm = Ed25519 private seed, salt = "scp-pseudonym-secret-v1", info = "",
     * len = 32)`, the §9.10.4.A native interim until S12, so software pseudonyms match
     * every other software custody byte for byte (§25.19).
     *
     * **Hardware keys (API 33+, [CustodyType.HARDWARE]):** `pseudonym_secret` is a
     * device-local HMAC-SHA256 key generated inside Android Keystore alongside the
     * identity key at [generateKeypair]; Keystore computes the HMAC of step 1 and the
     * secret never leaves it. It is never derived from a signature (§9.10.4.A), so the
     * pseudonym is device-local and stable across launches.
     *
     * The same `keyHandle` + `contextId` always yields the same point and the same
     * handle id, so re-deriving keeps the existing entry (and wipes the new scalar)
     * instead of adding one.
     *
     * @param keyHandle Handle to the identity Ed25519 key (source for derivation).
     * @param contextId Raw context ID bytes.
     * @return [PseudonymKeyHandle] referencing the derived signing key.
     * @throws ScpException with code `SCP-CRYPTO-4006` if the identity key or its
     *   pseudonym secret is not found.
     * @throws ScpException with code `SCP-CRYPTO-4003` if the identity key is not Ed25519.
     */
    override fun derivePseudonym(keyHandle: KeyHandle, contextId: ByteArray): PseudonymKeyHandle {
        requireEd25519Identity(keyHandle, "derivePseudonym")
        // v1 HMAC body: contextId || "scp-pseudonym".
        val seed = contextSeed(keyHandle, contextId, "scp-pseudonym".toByteArray(Charsets.UTF_8))
        val id = P256Pseudonym.pseudonymId(keyHandle.id, contextId, null)
        return P256Pseudonym.register(pseudonymKeys, keyHandle.id, id, seed)
    }

    /**
     * Derives a deterministic, context-scoped, epoch-rotatable P-256 pseudonym keypair
     * (§9.10.4.1).
     *
     * Identical to [derivePseudonym] except the HMAC body is `contextId || BE64(epoch) ||
     * "scp-pseudonym-v2"`, yielding an independent, unlinkable pseudonym per epoch for
     * the same identity and context. The `"scp-pseudonym-v2"` separator differs from
     * v1's `"scp-pseudonym"`, so a v2 pseudonym at any epoch never collides with the v1
     * [derivePseudonym] output. The pseudonym secret, the scalar reduction and the
     * handle-id rule are those of [derivePseudonym].
     *
     * @param keyHandle Handle to the identity Ed25519 key (source for derivation).
     * @param contextId Raw context ID bytes.
     * @param pseudonymEpoch Rotation epoch counter, mixed in as a big-endian u64.
     * @return [PseudonymKeyHandle] referencing the derived signing key.
     * @throws ScpException with code `SCP-CRYPTO-4006` if the identity key or its
     *   pseudonym secret is not found.
     * @throws ScpException with code `SCP-CRYPTO-4003` if the identity key is not Ed25519.
     */
    override fun deriveRotatablePseudonym(
        keyHandle: KeyHandle,
        contextId: ByteArray,
        pseudonymEpoch: Long,
    ): PseudonymKeyHandle {
        requireEd25519Identity(keyHandle, "deriveRotatablePseudonym")
        val epochBe = ByteBuffer.allocate(Long.SIZE_BYTES)
            .order(ByteOrder.BIG_ENDIAN)
            .putLong(pseudonymEpoch)
            .array()
        // v2 HMAC body: contextId || BE64(epoch) || "scp-pseudonym-v2".
        val seed = contextSeed(
            keyHandle,
            contextId,
            epochBe + "scp-pseudonym-v2".toByteArray(Charsets.UTF_8),
        )
        val id = P256Pseudonym.pseudonymId(keyHandle.id, contextId, pseudonymEpoch)
        return P256Pseudonym.register(pseudonymKeys, keyHandle.id, id, seed)
    }

    /** Rejects a software identity handle recorded as X25519 with `SCP-CRYPTO-4003`. */
    private fun requireEd25519Identity(keyHandle: KeyHandle, operation: String) {
        if (keyHandle.custodyType != CustodyType.SOFTWARE) return
        val storedType = softwareKeyTypes[keyHandle.id]
        if (storedType != null && storedType != KeyType.ED25519) {
            throw ScpException(
                "$operation requires an Ed25519 key; handle '${keyHandle.id}' is X25519",
                "SCP-CRYPTO-4003",
            )
        }
    }

    /**
     * `HMAC-SHA256(pseudonym_secret, contextId || suffix)`, the §9.10.4 context seed:
     * inside Android Keystore for a hardware identity, from the Ed25519 seed for a
     * software one (see [PseudonymSecret]).
     */
    private fun contextSeed(keyHandle: KeyHandle, contextId: ByteArray, suffix: ByteArray): ByteArray {
        if (keyHandle.custodyType == CustodyType.HARDWARE) {
            return PseudonymSecret.keystoreContextSeed(keystore, keyHandle.id, contextId, suffix)
        }
        val keyPair = softwareKeys[keyHandle.id]
            ?: throw ScpException("Key not found: ${keyHandle.id}", "SCP-CRYPTO-4006")
        return PseudonymSecret.softwareContextSeed(
            keyPair.private as Ed25519PrivateKeyParameters,
            contextId,
            suffix,
        )
    }

    /**
     * Exports the raw 32-byte Ed25519 private key bytes for governance vote signing.
     *
     * For software-backed keys ([CustodyType.SOFTWARE]): extracts the 32-byte seed from
     * the Bouncy Castle [Ed25519PrivateKeyParameters] and returns a copy.
     *
     * For hardware-backed keys ([CustodyType.HARDWARE]): throws an error because TEE keys
     * are non-extractable. Governance signing on hardware-backed keys requires a future
     * architectural change to use a Signer trait instead of raw key export.
     *
     * @param keyHandle Handle returned by [generateKeypair] for an Ed25519 key.
     * @return 32-byte raw Ed25519 private key bytes.
     * @throws ScpException with code `SCP-CRYPTO-4003` if the key is not Ed25519.
     * @throws ScpException with code `SCP-CRYPTO-4005` if the key is hardware-backed
     *   (TEE keys are non-extractable).
     * @throws ScpException with code `SCP-CRYPTO-4006` if the key is not found.
     */
    override fun exportSigningKeyBytes(keyHandle: KeyHandle): ByteArray {
        if (keyHandle.custodyType == CustodyType.HARDWARE) {
            throw ScpException(
                "Cannot export signing key bytes from hardware-backed TEE custody " +
                    "(handle '${keyHandle.id}'). Hardware keys are non-extractable. " +
                    "Governance signing on hardware-backed keys requires a Signer trait " +
                    "(see GitHub issue for architectural fix).",
                "SCP-CRYPTO-4005",
            )
        }

        val storedType = softwareKeyTypes[keyHandle.id]
        if (storedType != null && storedType != KeyType.ED25519) {
            throw ScpException(
                "exportSigningKeyBytes requires an Ed25519 key; handle '${keyHandle.id}' is X25519",
                "SCP-CRYPTO-4003",
            )
        }

        val keyPair = softwareKeys[keyHandle.id]
            ?: throw ScpException(
                "Key not found: ${keyHandle.id}",
                "SCP-CRYPTO-4006",
            )

        val privateParams = keyPair.private as Ed25519PrivateKeyParameters
        val seed = privateParams.encoded
        val result = seed.copyOf()
        seed.fill(0)
        return result
    }

    // -----------------------------------------------------------------------
    // Private: Keystore Ed25519 operations (API 33+)
    // -----------------------------------------------------------------------

    /**
     * Generates a TEE-backed Ed25519 keypair using Android Keystore.
     *
     * Uses the `EdDSA` algorithm with `Ed25519` parameter spec, available on API 33+.
     * The private key is generated inside the TEE and never leaves it. Signing operations
     * are performed by the TEE directly.
     *
     * StrongBox is NOT requested (`setIsStrongBoxBacked` is not called) per ADR-027:
     * StrongBox operations are 10-100x slower than TEE and would degrade SCP protocol
     * participation.
     *
     * `setUserAuthenticationRequired(false)` allows background processing — SCP needs
     * to sign messages during relay connections and message processing without user
     * interaction.
     */
    @Suppress("TooGenericExceptionCaught") // any failure must delete the half-made identity
    private fun generateKeystoreEd25519(keyId: String): KeyHandle {
        val keystoreAlias = "scp.key.$keyId"
        keystore.generateEd25519(keystoreAlias)
        try {
            keystore.generateHmacSha256(PseudonymSecret.alias(keyId))
        } catch (e: Exception) {
            // An identity without its pseudonym secret could never derive a pseudonym,
            // and no handle to it is returned, so it would sit orphaned in Keystore.
            try {
                keystore.deleteEntry(keystoreAlias)
            } catch (cleanup: Exception) {
                e.addSuppressed(cleanup)
            }
            throw e
        }
        return KeyHandle(id = keyId, custodyType = CustodyType.HARDWARE)
    }

    /**
     * Signs data using a TEE-backed Ed25519 key in Android Keystore.
     *
     * The signing operation happens entirely inside the TEE — the private key bytes
     * never leave hardware.
     */
    private fun signWithKeystore(keyHandle: KeyHandle, data: ByteArray): ByteArray {
        val keystoreAlias = "scp.key.${keyHandle.id}"
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val entry = keyStore.getEntry(keystoreAlias, null) as? KeyStore.PrivateKeyEntry
            ?: throw ScpException(
                "Key not found in Keystore: ${keyHandle.id}",
                "SCP-CRYPTO-4006",
            )
        return Signature.getInstance("EdDSA").apply {
            initSign(entry.privateKey)
            update(data)
        }.sign()
    }

    /**
     * Extracts the raw 32-byte Ed25519 public key from Android Keystore.
     *
     * Android Keystore returns the public key in X.509 SubjectPublicKeyInfo encoding.
     * For Ed25519, the raw 32-byte key is the last 32 bytes of the encoded form
     * (the first 12 bytes are the ASN.1 header: SEQUENCE + OID for Ed25519).
     */
    private fun publicKeyFromKeystore(keyHandle: KeyHandle): ByteArray {
        val keystoreAlias = "scp.key.${keyHandle.id}"
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val entry = keyStore.getEntry(keystoreAlias, null) as? KeyStore.PrivateKeyEntry
            ?: throw ScpException(
                "Key not found in Keystore: ${keyHandle.id}",
                "SCP-CRYPTO-4006",
            )
        val encoded = entry.certificate.publicKey.encoded
        // X.509 SubjectPublicKeyInfo for Ed25519 is 44 bytes: 12-byte header + 32-byte key (RFC 8410 §3)
        check(encoded.size == X509_ED25519_SPKI_SIZE) {
            "Expected $X509_ED25519_SPKI_SIZE-byte X.509 Ed25519 SubjectPublicKeyInfo encoding, " +
                "got ${encoded.size} bytes — key alias may hold a non-Ed25519 key"
        }
        return encoded.takeLast(RAW_ED25519_KEY_SIZE).toByteArray()
    }

    /**
     * Deletes a TEE-backed key from Android Keystore and verifies deletion.
     *
     * Performs the key destruction verification required by section 9.15:
     *   1. Delete the Keystore entry.
     *   2. Re-fetch to confirm the alias no longer exists.
     *   3. Return [DestructionAttestation] with [DestructionMethod.HARDWARE] and `confirmed = true`.
     *
     * Returns [DestructionMethod.HARDWARE] because the key material resided in the TEE
     * and was destroyed by the hardware security module.
     */
    private fun destroyKeystoreKey(keyHandle: KeyHandle): DestructionAttestation {
        val keystoreAlias = "scp.key.${keyHandle.id}"

        if (!keystore.containsAlias(keystoreAlias)) {
            throw ScpException(
                "Key not found in Keystore: ${keyHandle.id}",
                "SCP-CRYPTO-4006",
            )
        }

        keystore.deleteEntry(keystoreAlias)
        val secretAlias = PseudonymSecret.alias(keyHandle.id)
        if (keystore.containsAlias(secretAlias)) keystore.deleteEntry(secretAlias)

        // Verify deletion per section 9.15 — re-fetch must confirm absence
        if (keystore.containsAlias(keystoreAlias) || keystore.containsAlias(secretAlias)) {
            throw ScpException(
                "Key destruction failed: entry persisted after deletion for ${keyHandle.id}",
                "SCP-CRYPTO-4004",
            )
        }

        return DestructionAttestation(
            method = DestructionMethod.HARDWARE,
            confirmed = true,
        )
    }

    companion object {
        /** Raw Ed25519 public key size in bytes. */
        private const val RAW_ED25519_KEY_SIZE = 32

        /** X.509 SubjectPublicKeyInfo encoding size for Ed25519 (RFC 8410 §3): 12-byte ASN.1 header + 32-byte key. */
        private const val X509_ED25519_SPKI_SIZE = 44

        /** Filename for the EncryptedSharedPreferences storing software Ed25519 keys. */
        internal const val PREFS_FILENAME = "scp_key_custody"
    }
}

/**
 * Bouncy Castle software key operations for [AndroidKeyCustody].
 *
 * Manages Ed25519 and X25519 keys in software for platforms where Android Keystore
 * does not support these algorithms (Ed25519 on API 26-32, X25519 on all API levels).
 *
 * Extracted from [AndroidKeyCustody] to keep the parent class focused on routing
 * between hardware and software custody while respecting function count limits.
 *
 * @param softwareKeys Shared key storage map (same instance as [AndroidKeyCustody.softwareKeys]).
 * @param softwareKeyTypes Shared key type tracking map.
 * @param encryptedPrefs Persistent storage for Ed25519 private key seeds (ADR-027, #119).
 */
internal class SoftwareKeyOps(
    private val softwareKeys: ConcurrentHashMap<String, AsymmetricCipherKeyPair>,
    private val softwareKeyTypes: ConcurrentHashMap<String, KeyType>,
    private val encryptedPrefs: SharedPreferences,
) {
    /**
     * Generates a software-backed Ed25519 keypair using Bouncy Castle.
     *
     * Used as fallback on API 26-32 where Android Keystore does not support EdDSA.
     * The key pair is stored in [softwareKeys], tracked in [softwareKeyTypes], and
     * the private key seed is persisted to [encryptedPrefs] so it survives process
     * death (ADR-027, #119).
     *
     * The 32-byte Ed25519 private key seed is written to EncryptedSharedPreferences
     * under the key `scp.ed25519.<keyId>`. After writing, the local byte array copy
     * is zeroed to minimize the window of plaintext key material in memory.
     */
    fun generateEd25519(keyId: String): KeyHandle {
        val keyPair = Ed25519KeyPairGenerator().apply {
            init(Ed25519KeyGenerationParameters(SecureRandom()))
        }.generateKeyPair()
        softwareKeys[keyId] = keyPair
        softwareKeyTypes[keyId] = KeyType.ED25519

        // Persist the 32-byte Ed25519 private key seed to EncryptedSharedPreferences
        persistEd25519Key(keyId, keyPair)

        return KeyHandle(id = keyId, custodyType = CustodyType.SOFTWARE)
    }

    /**
     * Generates a software-backed X25519 keypair using Bouncy Castle.
     *
     * X25519 wrapping keys are always software-managed because Android Keystore
     * does not support X25519 at any API level.
     */
    fun generateX25519(keyId: String): KeyHandle {
        val keyPair = X25519KeyPairGenerator().apply {
            init(X25519KeyGenerationParameters(SecureRandom()))
        }.generateKeyPair()
        softwareKeys[keyId] = keyPair
        softwareKeyTypes[keyId] = KeyType.X25519
        return KeyHandle(id = keyId, custodyType = CustodyType.SOFTWARE)
    }

    /**
     * Signs data using a software-backed Ed25519 key from Bouncy Castle.
     */
    fun sign(keyHandle: KeyHandle, data: ByteArray): ByteArray {
        val keyPair = softwareKeys[keyHandle.id]
            ?: throw ScpException(
                "Key not found: ${keyHandle.id}",
                "SCP-CRYPTO-4006",
            )

        // Enforce Ed25519 type
        val storedType = softwareKeyTypes[keyHandle.id]
        if (storedType != null && storedType != KeyType.ED25519) {
            throw ScpException(
                "sign requires an Ed25519 key; handle '${keyHandle.id}' is X25519",
                "SCP-CRYPTO-4003",
            )
        }

        val signer = Ed25519Signer()
        signer.init(true, keyPair.private)
        signer.update(data, 0, data.size)
        return signer.generateSignature()
    }

    /**
     * Returns the raw 32-byte public key from a software-backed key.
     */
    fun publicKey(keyHandle: KeyHandle): ByteArray {
        val keyPair = softwareKeys[keyHandle.id]
            ?: throw ScpException(
                "Key not found: ${keyHandle.id}",
                "SCP-CRYPTO-4006",
            )

        val storedType = softwareKeyTypes[keyHandle.id]
        return when (storedType) {
            KeyType.X25519 -> {
                val pubKey = keyPair.public as org.bouncycastle.crypto.params.X25519PublicKeyParameters
                pubKey.encoded
            }
            else -> {
                // Ed25519
                val pubKey = keyPair.public as Ed25519PublicKeyParameters
                pubKey.encoded
            }
        }
    }

    /**
     * Destroys a software-backed key by removing it from both the in-memory map
     * and [encryptedPrefs].
     *
     * Returns [DestructionMethod.SOFTWARE_ONLY] because the key material was stored
     * in software (Bouncy Castle in-memory + EncryptedSharedPreferences) without
     * hardware protection.
     */
    fun destroy(keyHandle: KeyHandle): DestructionAttestation {
        val removed = softwareKeys.remove(keyHandle.id)
        softwareKeyTypes.remove(keyHandle.id)

        // Remove from EncryptedSharedPreferences (no-op if not an Ed25519 identity key)
        val prefsKey = "$PREFS_KEY_PREFIX${keyHandle.id}"
        encryptedPrefs.edit().remove(prefsKey).apply()

        if (removed == null) {
            throw ScpException(
                "Key not found: ${keyHandle.id}",
                "SCP-CRYPTO-4006",
            )
        }

        // Verify removal — key should no longer be in the map
        if (softwareKeys.containsKey(keyHandle.id)) {
            throw ScpException(
                "Key destruction failed: entry persisted after removal for ${keyHandle.id}",
                "SCP-CRYPTO-4004",
            )
        }

        return DestructionAttestation(
            method = DestructionMethod.SOFTWARE_ONLY,
            confirmed = true,
        )
    }

    // -----------------------------------------------------------------------
    // Private: EncryptedSharedPreferences persistence (ADR-027, #119)
    // -----------------------------------------------------------------------

    /**
     * Persists an Ed25519 private key seed to [encryptedPrefs].
     *
     * Extracts the 32-byte seed from the Bouncy Castle [Ed25519PrivateKeyParameters],
     * encodes it as a Base64 string, writes it to EncryptedSharedPreferences, and then
     * zeroes the local byte array copy to minimize plaintext key material in memory.
     */
    private fun persistEd25519Key(keyId: String, keyPair: AsymmetricCipherKeyPair) {
        val privateParams = keyPair.private as Ed25519PrivateKeyParameters
        val seed = privateParams.encoded
        try {
            val encoded = java.util.Base64.getEncoder().encodeToString(seed)
            encryptedPrefs.edit().putString("$PREFS_KEY_PREFIX$keyId", encoded).apply()
        } finally {
            seed.fill(0)
        }
    }

    /**
     * Restores all persisted Ed25519 keys from [encryptedPrefs] into [softwareKeys].
     *
     * Called from [AndroidKeyCustody.init]. For each entry matching the [PREFS_KEY_PREFIX],
     * decodes the Base64-encoded 32-byte seed, reconstructs the Bouncy Castle Ed25519 keypair
     * using [FixedSecureRandom] for deterministic derivation from the seed, and places
     * the key pair into [softwareKeys] and [softwareKeyTypes].
     *
     * The decoded seed bytes are zeroed after keypair reconstruction.
     */
    fun restorePersistedEd25519Keys() {
        encryptedPrefs.all
            .filter { (key, value) -> key.startsWith(PREFS_KEY_PREFIX) && value is String }
            .forEach { (prefsKey, value) ->
                val keyId = prefsKey.removePrefix(PREFS_KEY_PREFIX)
                val seed = java.util.Base64.getDecoder().decode(value as String)
                try {
                    val keyPair = Ed25519KeyPairGenerator().apply {
                        init(Ed25519KeyGenerationParameters(FixedSecureRandom(seed)))
                    }.generateKeyPair()
                    softwareKeys[keyId] = keyPair
                    softwareKeyTypes[keyId] = KeyType.ED25519
                } finally {
                    seed.fill(0)
                }
            }
    }

    companion object {
        /** Key prefix for Ed25519 private key entries in EncryptedSharedPreferences. */
        private const val PREFS_KEY_PREFIX = "scp.ed25519."
    }
}
