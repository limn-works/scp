// AndroidKeyCustody.kt — KeyCustodyProvider implementation for Android (ADR-027)
//
// Ed25519 key custody using Android Keystore on API 33+ and Bouncy Castle
// software fallback on API 26-32. X25519 wrapping keys are always software-managed via
// Bouncy Castle. StrongBox is explicitly NOT used due to 10-100x latency penalty that
// is incompatible with SCP's frequent signing operations. ADR-027, as amended on 2026-09-10,
// requires a different scheme: an EC P-256 signing key in Keystore at every supported API
// level, and P-256 key agreement in Keystore from API 31 with a Bouncy Castle software P-256
// agreement key below it. This class's signing and agreement keys have not moved to P-256;
// story SCP-110 tracks that move. Its pseudonyms are P-256 points (§9.10.4).
//
// Android Keystore does not hand a Keystore-held Ed25519 private key to the app. This class never
// reads KeyInfo.securityLevel, so it does not know whether Keystore put the key in the TEE or in
// software, and it reports CustodyType.HARDWARE for every Keystore key. This class performs all signing
// and DH itself and returns signatures, shared secrets and pseudonym points. One path hands a
// caller a software private key:
// - exportSigningKeyBytes returns the 32-byte private seed of a software Ed25519 identity key,
//   which generateKeypair creates on API 26-32. That seed is also the HKDF input of the
//   identity's software pseudonym secret, so its holder derives every pseudonym of the identity.
//   ADR-027 acceptance criterion 14 (private key isolation) says the Rust engine receives only
//   signatures and public keys, never private key material. The UniFFI KeyCustodyProvider
//   callback declares export_signing_key_bytes, which would carry this seed to Rust, so this
//   method's design diverges from criterion 14.
// The pseudonym secret of a Keystore identity is a Keystore HMAC-SHA256 key that never leaves
// Keystore, and no pseudonym has a private key this class holds. No other public method returns
// a software private key, and no public method returns an X25519 private key. The softwareKeys
// map is not behind that boundary: it is `internal`, so any code in this module reads every
// software key pair, X25519 included, and Kotlin compiles it to a public JVM getter with a
// mangled name that Java code in an app can call.
// This class implements this package's own [KeyCustodyProvider], not the `scp-ffi-uniffi` bridge
// protocol, and no code passes this class to the Rust engine.
//
// Software Ed25519 keys that generateKeypair creates (API 26-32 fallback) are persisted to
// EncryptedSharedPreferences (Jetpack Security) so they survive process death once the write
// reaches disk. The write uses apply(), which queues it and returns first; when the process
// dies before the queued write lands, the key is lost. Without persistence,
// API 26-32 users would lose their DID identity key on every process restart — causing
// identity loss, context membership loss, and UCAN delegation loss. No pseudonym key is
// stored: the pseudonym methods return a P-256 point.
//
// Provenance: ADR-027 (Android Platform Adapter), ADR-006 (Platform Abstraction Layer),
// ADR-025 (Apple Platform Adapter — parallel reference), section 9.12 (Compromise Recovery),
// section 9.15 (Ephemeral Key Destruction Verification).

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
 * Implements the Kotlin [KeyCustodyProvider] interface in `Types.kt`, whose KDoc states how
 * it differs from the Rust `KeyCustody` trait and from the UniFFI `KeyCustodyProvider`
 * callback interface. No code passes this class to the Rust engine: `SCP.identityCreateWithCustody`
 * in `scp-kt` takes the UniFFI-generated `uniffi.scp.KeyCustodyProvider`, whose key ids are u64
 * strings, and this class does not implement it.
 *
 * ## Key storage strategy
 *
 * - **Ed25519 on API 33+ (Android 13+):** Android Keystore natively supports `EdDSA`
 *   with `Ed25519` parameter spec. Keystore holds the key and does not hand its private
 *   bytes to the app. [CustodyType.HARDWARE] is reported for every Keystore key. The
 *   adapter does not read `KeyInfo.securityLevel`, so on a device whose KeyMint runs in
 *   software (an API 33 emulator, for one) the key is held in software and the handle
 *   still says [CustodyType.HARDWARE].
 *
 * - **Ed25519 on API 26-32:** `EdDSA` is not available in Android Keystore on these API
 *   levels. Bouncy Castle provides software Ed25519. The key pair is held in [softwareKeys]
 *   in memory, and its 32-byte private seed is written to [encryptedPrefs] with `apply()`,
 *   which returns before the write reaches disk. The key survives process death once the
 *   write lands, and is lost when the process dies first. [CustodyType.SOFTWARE] is reported.
 *
 * - **Pseudonyms (all API levels):** [derivePseudonym] and [deriveRotatablePseudonym]
 *   return a 33-byte compressed P-256 point and store no key. A Keystore identity's pseudonym
 *   secret is a Keystore HMAC-SHA256 key that [generateKeypair] creates beside the identity
 *   key; a software identity's is derived from its Ed25519 seed.
 *
 * - **X25519 (all API levels):** This class keeps every X25519 wrapping key in Bouncy Castle
 *   software, stored in [softwareKeys], at every API level. It does not use the X25519 key
 *   agreement Android Keystore offers from API 33. [CustodyType.SOFTWARE] is reported.
 *
 * ADR-027, as amended on 2026-09-10, requires P-256 signing and agreement keys in place of
 * this scheme; the file header
 * states the required scheme.
 *
 * ## StrongBox
 *
 * StrongBox is NOT requested; Keystore chooses where to put the key. StrongBox operations are
 * 10-100x slower than TEE operations — latency that would visibly degrade SCP protocol participation
 * where every send operation requires a signature. See ADR-027 for the full rationale.
 *
 * ## Errors
 *
 * This class converts no exception to [ScpException]. Each method throws [ScpException] only for
 * the codes its KDoc names, and every other failure escapes as the original throwable. The
 * KDoc of [KeyCustodyProvider] lists the Keystore and JCA exceptions each method can let escape,
 * and the [dhAgree] KDoc names the Bouncy Castle `IllegalStateException` a low-order peer key
 * raises.
 *
 * ## Thread safety
 *
 * Android Keystore operations are thread-safe. The [softwareKeys] map is a
 * [ConcurrentHashMap] for safe concurrent access from multiple threads.
 *
 * ## Compromise recovery
 *
 * `.docs/specs/09-security-model.md` §9.12 (Compromise Recovery Protocol) defines the recovery
 * steps. This KDoc does not restate them.
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
     * Keystore for persisting software Ed25519 keys (ADR-027).
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
    // Software key storage — API 26-32 Ed25519 keys and X25519 keys
    // -----------------------------------------------------------------------

    /**
     * In-memory storage for software-managed keys (Bouncy Castle).
     *
     * Key: UUID string (same as [KeyHandle.id]).
     * Value: Bouncy Castle asymmetric key pair (Ed25519 or X25519).
     *
     * This map holds two kinds of key:
     * - Ed25519 keys that [generateKeypair] creates on API 26-32 (no Keystore EdDSA support)
     * - X25519 keys on all API levels (this class does not use Keystore X25519)
     *
     * Ed25519 keys that [generateKeypair] creates are additionally written to [encryptedPrefs]
     * with `apply()`, so they survive process death once the queued write reaches disk.
     * X25519 wrapping keys are held in memory only. No pseudonym key is stored.
     *
     * The map is `internal`, not `private`, because the unit tests read it. Kotlin compiles an
     * `internal` property to a public JVM getter with a mangled name, so Java code in an app can
     * read every private key in this map.
     */
    internal val softwareKeys = ConcurrentHashMap<String, AsymmetricCipherKeyPair>()

    /**
     * Tracks the [KeyType] for each software-managed key.
     *
     * Used to enforce type safety in [sign] and [dhAgree] operations.
     */
    internal val softwareKeyTypes = ConcurrentHashMap<String, KeyType>()

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
     * - [KeyType.ED25519] + API 33+: Android Keystore via the `EdDSA` algorithm.
     * - [KeyType.ED25519] + API 26-32: Bouncy Castle software fallback.
     * - [KeyType.X25519]: Always Bouncy Castle software (this class does not use Keystore X25519).
     *
     * @param keyType The type of key to generate.
     * @return [KeyHandle] with [CustodyType.HARDWARE] for Keystore keys or
     *   [CustodyType.SOFTWARE] for Bouncy Castle keys. The method reports
     *   [CustodyType.HARDWARE] without reading `KeyInfo.securityLevel`, so a key that a
     *   software KeyMint holds is reported as [CustodyType.HARDWARE].
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
     * For Keystore keys ([CustodyType.HARDWARE]): Android Keystore's `EdDSA` signature
     * provider signs, and Keystore does not hand the private key bytes to the app.
     *
     * For software-backed keys ([CustodyType.SOFTWARE]): Bouncy Castle's [Ed25519Signer]
     * performs the signing with key material from [softwareKeys].
     *
     * The method signs any [data] and applies no domain separation. No pseudonym secret
     * depends on a signature: a Keystore identity's pseudonym secret is a separate Keystore
     * HMAC-SHA256 key (§9.10.4.A).
     *
     * @param keyHandle Handle returned by [generateKeypair] for an Ed25519 key.
     * @param data The bytes to sign.
     * @return 64-byte signature.
     * @throws ScpException with code `SCP-CRYPTO-4006` if the key is not found.
     * @throws ScpException with code `SCP-CRYPTO-4003` if the key is not Ed25519.
     */
    override fun sign(keyHandle: KeyHandle, data: ByteArray): ByteArray {
        return if (keyHandle.custodyType == CustodyType.HARDWARE) {
            signWithKeystore(keyHandle, data)
        } else {
            softwareKeyOps.sign(keyHandle, data)
        }
    }

    /**
     * Returns the raw 32-byte public key for [keyHandle].
     *
     * For Keystore Ed25519 keys ([CustodyType.HARDWARE]): extracts the raw 32-byte Ed25519 public key
     * from the X.509-encoded certificate in Android Keystore. The X.509 SubjectPublicKeyInfo
     * encoding for Ed25519 has a 12-byte header; the raw key is the last 32 bytes.
     *
     * For software-backed keys: returns the Bouncy Castle public key parameters directly.
     *
     * @param keyHandle Handle returned by [generateKeypair].
     * @return Raw 32-byte public key bytes.
     * @throws ScpException with code `SCP-CRYPTO-4006` if the key is not found.
     */
    override fun publicKey(keyHandle: KeyHandle): ByteArray {
        return if (keyHandle.custodyType == CustodyType.HARDWARE) {
            publicKeyFromKeystore(keyHandle)
        } else {
            softwareKeyOps.publicKey(keyHandle)
        }
    }

    /**
     * Destroys the key material associated with [keyHandle].
     *
     * For Keystore keys ([CustodyType.HARDWARE]): deletes the pseudonym secret and then the
     * identity entry from Android Keystore, re-fetching each to confirm deletion (section 9.15
     * key destruction verification).
     *
     * For software-backed keys: removes the entry from the [softwareKeys] map and removes the
     * seed of a software Ed25519 key that [generateKeypair] creates (API 26-32) from
     * [encryptedPrefs] with `apply()`, which returns before the removal reaches disk. The
     * post-deletion check reads only [softwareKeys].
     *
     * No pseudonym key exists to destroy: once the identity (and, for a hardware
     * identity, its pseudonym secret) is gone, no pseudonym of it can be derived
     * (§9.10.4.A).
     *
     * After this call, operations with the same handle on the same instance throw [ScpException]
     * with code `SCP-CRYPTO-4006`, with two exceptions: [dhAgree] throws `SCP-CRYPTO-4003` when its
     * peer key is not 32 bytes, because it checks the peer key's length before any key lookup;
     * and [exportSigningKeyBytes] on a Keystore handle ([CustodyType.HARDWARE]) throws
     * `SCP-CRYPTO-4005`, because it refuses on [KeyHandle.custodyType] before any key lookup.
     * Each instance holds its own [softwareKeys] map and restores every persisted software Ed25519
     * seed into it when constructed, so another instance in the same process that already holds a
     * software key keeps signing with it after this call.
     * When the process dies before `apply()` writes the removal to disk, the next instance's
     * `restorePersistedEd25519Keys` reloads the seed and the key signs again, although this
     * call returned `confirmed = true`.
     *
     * @param keyHandle Handle to destroy.
     * @return [DestructionAttestation] naming the destruction method, with `confirmed` always
     *   `true`: a failed post-deletion check throws `SCP-CRYPTO-4004` instead.
     * @throws ScpException with code `SCP-CRYPTO-4006` if the handle is already invalid.
     * @throws ScpException with code `SCP-CRYPTO-4004` if destruction cannot be confirmed.
     */
    override fun destroyKey(keyHandle: KeyHandle): DestructionAttestation =
        if (keyHandle.custodyType == CustodyType.HARDWARE) {
            destroyKeystoreKey(keyHandle)
        } else {
            softwareKeyOps.destroy(keyHandle)
        }

    /**
     * Performs X25519 Diffie-Hellman key agreement.
     *
     * X25519 wrapping keys are always software-managed (Bouncy Castle); this class does not use
     * the X25519 key agreement Android Keystore offers from API 33. The scalar multiplication
     * happens inside this method, and no public method of this class returns the X25519 private
     * key. The `internal` [softwareKeys] map still holds it, readable by any code in this module
     * and by Java code through the map's mangled public JVM getter.
     *
     * @param keyHandle Handle to an X25519 key from [generateKeypair].
     * @param peerPublic 32-byte X25519 public key of the peer.
     * @return 32-byte X25519 shared secret.
     * @throws ScpException with code `SCP-CRYPTO-4006` if [peerPublic] is 32 bytes long and no
     *   software key sits under [keyHandle]: a destroyed or unknown handle, or a Keystore
     *   Ed25519 handle, which never enters [softwareKeyTypes] and so skips the key-type check.
     * @throws ScpException with code `SCP-CRYPTO-4003` if [peerPublic] is not 32 bytes long,
     *   checked before any key lookup, or [keyHandle] names a software Ed25519 key.
     * @throws IllegalStateException from Bouncy Castle ("X25519 agreement failed") if
     *   [peerPublic] is 32 bytes long but a low-order point, such as 32 zero bytes, which makes
     *   the shared secret all zero. This method checks no point order, so a peer that publishes
     *   such a key reaches this exception, and a `catch (e: ScpException)` does not catch it.
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
     * Derives the deterministic, context-scoped P-256 pseudonym of an identity and
     * returns its 33-byte compressed point (§9.10.4, §9.10.4.A). Nothing is stored.
     *
     * ## Algorithm (spec §9.10.4, §9.10.4.A):
     *
     *   1. `seed = HMAC-SHA256(pseudonym_secret, contextId || "scp-pseudonym")`, where
     *      `pseudonym_secret` is the identity key's §9.10.4.A secret.
     *   2. `d = HKDF-Expand-SHA256(prk = seed, info = "SCP-PSEUDONYM-P256-V1", 48)
     *      mod (n - 1) + 1` (FIPS 186-5 A.2.1).
     *   3. The pseudonym is the 33-byte compressed point `d * G`.
     *
     * **Software keys (API 26-32, [CustodyType.SOFTWARE]):** `pseudonym_secret =
     * HKDF-SHA256(ikm = Ed25519 private seed, salt = "scp-pseudonym-secret-v1")`, the
     * §9.10.4.A native interim until S12. The Rust helper behind
     * [P256Pseudonym.softwarePoint] runs all three steps, so software pseudonyms match
     * every other software custody byte for byte (§25.19).
     *
     * **Hardware keys (API 33+, [CustodyType.HARDWARE]):** `pseudonym_secret` is a
     * device-local HMAC-SHA256 key generated inside Android Keystore alongside the
     * identity key at [generateKeypair]; Keystore computes step 1 and the secret never
     * leaves it. It is never derived from a signature (§9.10.4.A), so the pseudonym is
     * device-local and stable across launches. Steps 2 and 3 run in the Rust helper
     * behind [P256Pseudonym.pointFromSeed].
     *
     * @param keyHandle Handle to the identity Ed25519 key (source for derivation).
     * @param contextId Raw context ID bytes.
     * @return The 33-byte SEC1 compressed P-256 point.
     * @throws ScpException with code `SCP-CRYPTO-4006` if the identity key or its
     *   pseudonym secret is not found.
     * @throws ScpException with code `SCP-CRYPTO-4003` if the identity key is not Ed25519.
     */
    override fun derivePseudonym(keyHandle: KeyHandle, contextId: ByteArray): ByteArray {
        requireEd25519Identity(keyHandle, "derivePseudonym")
        // v1 HMAC body: contextId || "scp-pseudonym".
        return pseudonymPoint(keyHandle, contextId, null, "scp-pseudonym".toByteArray(Charsets.UTF_8))
    }

    /**
     * Derives the deterministic, context-scoped, epoch-rotatable P-256 pseudonym of an
     * identity and returns its 33-byte compressed point (§9.10.4.1).
     *
     * Identical to [derivePseudonym] except the HMAC body is `contextId || BE64(epoch) ||
     * "scp-pseudonym-v2"`, yielding an independent, unlinkable pseudonym per epoch for
     * the same identity and context. The `"scp-pseudonym-v2"` separator differs from
     * v1's `"scp-pseudonym"`, so a v2 pseudonym at any epoch never collides with the v1
     * [derivePseudonym] output.
     *
     * @param keyHandle Handle to the identity Ed25519 key (source for derivation).
     * @param contextId Raw context ID bytes.
     * @param pseudonymEpoch Rotation epoch counter, mixed in as a big-endian u64.
     * @return The 33-byte SEC1 compressed P-256 point.
     * @throws ScpException with code `SCP-CRYPTO-4006` if the identity key or its
     *   pseudonym secret is not found.
     * @throws ScpException with code `SCP-CRYPTO-4003` if the identity key is not Ed25519.
     */
    override fun deriveRotatablePseudonym(
        keyHandle: KeyHandle,
        contextId: ByteArray,
        pseudonymEpoch: Long,
    ): ByteArray {
        requireEd25519Identity(keyHandle, "deriveRotatablePseudonym")
        val epochBe = ByteBuffer.allocate(Long.SIZE_BYTES)
            .order(ByteOrder.BIG_ENDIAN)
            .putLong(pseudonymEpoch)
            .array()
        // v2 HMAC body: contextId || BE64(epoch) || "scp-pseudonym-v2".
        return pseudonymPoint(
            keyHandle,
            contextId,
            pseudonymEpoch,
            epochBe + "scp-pseudonym-v2".toByteArray(Charsets.UTF_8),
        )
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
     * The pseudonym point of [keyHandle]. A hardware identity computes the context seed
     * `HMAC-SHA256(pseudonym_secret, contextId || suffix)` inside Keystore, and only
     * while its identity alias exists, so a destroy that removed the identity but not
     * yet the secret cannot leave a derivable pseudonym. A software identity passes its
     * Ed25519 seed to the Rust helper with [epoch] (`null` for v1), and the seed copy is
     * wiped.
     */
    private fun pseudonymPoint(
        keyHandle: KeyHandle,
        contextId: ByteArray,
        epoch: Long?,
        suffix: ByteArray,
    ): ByteArray {
        if (keyHandle.custodyType == CustodyType.HARDWARE) {
            if (!keystore.containsAlias("scp.key.${keyHandle.id}")) {
                throw ScpException("Key not found in Keystore: ${keyHandle.id}", "SCP-CRYPTO-4006")
            }
            val seed = PseudonymSecret.keystoreContextSeed(keystore, keyHandle.id, contextId, suffix)
            return P256Pseudonym.pointFromSeed(seed)
        }
        val keyPair = softwareKeys[keyHandle.id]
            ?: throw ScpException("Key not found: ${keyHandle.id}", "SCP-CRYPTO-4006")
        val seed = (keyPair.private as Ed25519PrivateKeyParameters).encoded
        return try {
            P256Pseudonym.softwarePoint(seed, contextId, epoch)
        } finally {
            seed.fill(0)
        }
    }

    /**
     * Exports the raw 32-byte Ed25519 private key bytes for governance vote signing.
     *
     * For software-backed keys ([CustodyType.SOFTWARE]): extracts the 32-byte seed from
     * the Bouncy Castle [Ed25519PrivateKeyParameters] and returns a copy. That covers a
     * [generateKeypair] key on API 26-32; no pseudonym has a stored key to export.
     *
     * For Keystore keys ([CustodyType.HARDWARE]): throws an error because Keystore does
     * not hand the private key bytes to the app, so this method cannot hand a Keystore key's
     * bytes to a core function that takes a raw signing key. ADR-063's curve slice requires
     * every core function that takes a raw signing key to take a signer instead, and every
     * key-export accessor to leave the custody adapters and all three bridges. That slice
     * has not landed, so this accessor still exports the seed of a software key. ADR-027
     * acceptance criterion 14 (private key isolation) already says the Rust engine receives
     * only signatures and public keys, never private key material, and the UniFFI
     * `KeyCustodyProvider` callback's `export_signing_key_bytes` would carry this seed to Rust,
     * so this method's design diverges from criterion 14. No code passes this class to the
     * Rust engine, so no seed from it reaches Rust.
     *
     * @param keyHandle Handle naming an Ed25519 key held in software, which [generateKeypair]
     *   returned. The method checks only [KeyHandle.custodyType] and the stored key type.
     * @return 32-byte raw Ed25519 private key bytes.
     * @throws ScpException with code `SCP-CRYPTO-4003` if the key is not Ed25519.
     * @throws ScpException with code `SCP-CRYPTO-4005` if the handle is a Keystore handle
     *   ([CustodyType.HARDWARE]), checked before any key lookup, so a destroyed or unknown
     *   Keystore handle also gets this code (Keystore does not hand its private key bytes to
     *   the app).
     * @throws ScpException with code `SCP-CRYPTO-4006` if the handle is a software handle and
     *   no software key is found under it.
     */
    override fun exportSigningKeyBytes(keyHandle: KeyHandle): ByteArray {
        if (keyHandle.custodyType == CustodyType.HARDWARE) {
            throw ScpException(
                "Cannot export signing key bytes from Android Keystore custody " +
                    "(handle '${keyHandle.id}'). Keystore keys are non-extractable. " +
                    "ADR-063's curve slice requires every core function that takes a raw " +
                    "signing key to take a signer instead, and every key-export accessor to " +
                    "leave the custody adapters and all three bridges; that slice has not landed.",
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
     * Generates an Ed25519 keypair in Android Keystore.
     *
     * Uses the `EdDSA` algorithm with `Ed25519` parameter spec, available on API 33+.
     * Keystore generates the private key and does not hand it to the app; Keystore signs.
     * This method does not read `KeyInfo.securityLevel` and returns [CustodyType.HARDWARE]
     * whether Keystore put the key in the TEE or, on a device whose KeyMint runs in
     * software, in software.
     *
     * StrongBox is NOT requested (`setIsStrongBoxBacked` is not called) per ADR-027:
     * StrongBox operations are 10-100x slower than TEE operations and would degrade SCP
     * protocol participation.
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
     * Signs data using an Ed25519 key in Android Keystore.
     *
     * Keystore signs; the private key bytes are not handed to the app.
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
     * Deletes a Keystore identity and its pseudonym secret from Android Keystore and
     * verifies deletion.
     *
     * Performs the key destruction verification required by section 9.15:
     *   1. Delete the pseudonym secret, then the identity entry. The secret goes first so
     *      that a failure between the two leaves the identity in place, and a retry
     *      completes the destroy.
     *   2. Re-fetch to confirm neither alias exists.
     *   3. Return [DestructionAttestation] with [DestructionMethod.HARDWARE] and `confirmed = true`.
     *
     * An identity alias that is already absent reports `SCP-CRYPTO-4006`, after deleting
     * any pseudonym secret left behind and confirming it is gone (`SCP-CRYPTO-4004` if it
     * persists).
     *
     * Returns [DestructionMethod.HARDWARE] because Keystore held and deleted the key. The
     * method does not read `KeyInfo.securityLevel`, so it reports
     * [DestructionMethod.HARDWARE] also for a key that a software KeyMint held.
     */
    private fun destroyKeystoreKey(keyHandle: KeyHandle): DestructionAttestation {
        val keystoreAlias = "scp.key.${keyHandle.id}"
        val secretAlias = PseudonymSecret.alias(keyHandle.id)

        if (!keystore.containsAlias(keystoreAlias)) {
            if (keystore.containsAlias(secretAlias)) keystore.deleteConfirmed(keyHandle.id, secretAlias)
            throw ScpException(
                "Key not found in Keystore: ${keyHandle.id}",
                "SCP-CRYPTO-4006",
            )
        }

        // Secret first, then identity; each deletion is re-fetched per section 9.15.
        keystore.deleteConfirmed(keyHandle.id, secretAlias, keystoreAlias)

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
 * Manages two kinds of software key: Ed25519 keys that [AndroidKeyCustody.generateKeypair]
 * creates on API 26-32, where Android Keystore has no EdDSA; and X25519 keys on all API
 * levels, because [AndroidKeyCustody] does not use Keystore X25519.
 *
 * Extracted from [AndroidKeyCustody] to keep the parent class focused on routing
 * between hardware and software custody while respecting function count limits.
 *
 * @param softwareKeys Shared key storage map (same instance as [AndroidKeyCustody.softwareKeys]).
 * @param softwareKeyTypes Shared key type tracking map.
 * @param encryptedPrefs Persistent storage for Ed25519 private key seeds (ADR-027).
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
     * the private key seed is written to [encryptedPrefs] with `apply()`, so it survives
     * process death once the queued write reaches disk and is lost when the process dies
     * first (ADR-027).
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
     * X25519 wrapping keys are always software-managed; this class does not use the X25519
     * key agreement Android Keystore offers from API 33.
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
     * Destroys a software-backed key by removing it from the in-memory map and removing its
     * seed entry from [encryptedPrefs], which only an Ed25519 key that [generateEd25519]
     * created has; for an X25519 key the removal is a no-op.
     *
     * Returns [DestructionMethod.SOFTWARE_ONLY] because the key material was held in software
     * (the Bouncy Castle in-memory map, plus EncryptedSharedPreferences for a generated Ed25519
     * key) without hardware protection. The `apply()` call queues the [encryptedPrefs] removal and returns
     * before the removal reaches disk, and the verification reads only [softwareKeys], so
     * `confirmed = true` does not show that the persisted seed is gone.
     */
    fun destroy(keyHandle: KeyHandle): DestructionAttestation {
        val removed = softwareKeys.remove(keyHandle.id)
        softwareKeyTypes.remove(keyHandle.id)

        // Remove from EncryptedSharedPreferences (no-op unless generateEd25519 persisted the key)
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
    // Private: EncryptedSharedPreferences persistence (ADR-027)
    // -----------------------------------------------------------------------

    /**
     * Persists an Ed25519 private key seed to [encryptedPrefs].
     *
     * Extracts the 32-byte seed from the Bouncy Castle [Ed25519PrivateKeyParameters],
     * encodes it as a Base64 string, queues its write to EncryptedSharedPreferences with
     * `apply()` (which returns before the write reaches disk), and then
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

/**
 * Deletes each of [aliases] in order and confirms by re-fetch that none remains
 * (section 9.15). A Keystore failure or a surviving alias is `SCP-CRYPTO-4004`, and
 * the aliases after a failed one are left in place.
 */
private fun KeystoreKeys.deleteConfirmed(keyId: String, vararg aliases: String) {
    for (alias in aliases) {
        try {
            deleteEntry(alias)
        } catch (e: java.security.KeyStoreException) {
            throw ScpException(
                "Key destruction failed: Keystore could not delete $alias for $keyId",
                "SCP-CRYPTO-4004",
                e,
            )
        }
        if (containsAlias(alias)) {
            throw ScpException(
                "Key destruction failed: $alias persisted after deletion for $keyId",
                "SCP-CRYPTO-4004",
            )
        }
    }
}
