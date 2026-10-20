// AndroidKeyCustody.kt — KeyCustodyProvider implementation for Android (ADR-027)
//
// Three key types. A P-256 signing key lives in Android Keystore at every supported API level.
// An HPKE P-256 agreement key lives in Keystore (PURPOSE_AGREE_KEY) from API 31, and below it as
// a Bouncy Castle scalar committed to EncryptedSharedPreferences; a probe fixed at construction
// picks the store, and a failed Keystore create fails the mint instead of falling back. Each
// P-256 key has a KeyRecords record naming its type, its store and the custody class read from
// Keystore's KeyInfo at mint, and every operation follows the record (P256Keys.kt). An Ed25519
// key lives in Keystore on API 33+ and in Bouncy Castle software below it. StrongBox is not
// requested, because its 10-100x latency is incompatible with SCP's frequent signing.
//
// A Keystore Ed25519 key is reported as CustodyType.HARDWARE without reading KeyInfo, so a key
// that a software KeyMint holds is over-claimed; P-256 keys do not share that gap.
// This class performs all signing and DH itself and returns signatures, shared secrets and
// pseudonym points; no public method returns a private key (ADR-027 acceptance criterion 14).
// The pseudonym secret of a Keystore identity is a Keystore HMAC-SHA256 key that never leaves
// Keystore. The softwareKeys map is `internal`, so code in this module reads every software
// Ed25519 key pair; it and every other internal member carry @JvmSynthetic, so Java
// code in an app cannot reach them through their mangled public JVM names.
//
// The adapter runs in the app's main process only (ADR-027 criterion 1): construction anywhere
// else throws SCP-CRYPTO-4060, because SharedPreferences.commit() writes a process's whole
// cached map and two processes would lose each other's records.
// UniffiKeyCustody wraps this class as the `scp-ffi-uniffi` bridge's
// `uniffi.scp.KeyCustodyProvider`, so the `os_keystore` custody of spec 03 §3.2.2 reaches
// Keystore through `SCP.identityCreateWithCustody(UniffiKeyCustody(it))`.
//
// Every persisted write (software Ed25519 seeds, HPKE scalars, records, roles) uses commit(),
// and a write that does not commit fails the operation with SCP-CRYPTO-4060. The adapter reads
// its preferences entry by entry through id indexes, never through getAll(), which would
// decrypt every stored seed and scalar.
//
// Provenance: ADR-027 (Android Platform Adapter), ADR-006 (Platform Abstraction Layer),
// ADR-025 (Apple Platform Adapter — parallel reference), spec 09 §9.5 (P-256 keys), section 9.12
// (Compromise Recovery), section 9.15 (Ephemeral Key Destruction Verification).

package works.limn.scp.android.platform

import android.app.ActivityManager
import android.app.Application
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.os.Process
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyStore
import java.security.SecureRandom
import java.security.Signature
import java.util.concurrent.ConcurrentHashMap
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.prng.FixedSecureRandom
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * Android key custody provider for SCP Ed25519, P-256 and HPKE P-256 keys.
 *
 * Implements the Kotlin [KeyCustodyProvider] interface in `Types.kt`, whose KDoc states how
 * it differs from the Rust `KeyCustody` trait and from the UniFFI `KeyCustodyProvider`
 * callback interface. [UniffiKeyCustody] wraps an instance as the UniFFI-generated
 * `uniffi.scp.KeyCustodyProvider` that `SCP.identityCreateWithCustody` in `scp-kt` takes.
 *
 * ## Key ids
 *
 * Every key id is the canonical decimal form of a random `ULong`, the only id shape the bridge
 * accepts. [generateKeypair] draws a fresh id while the drawn one names a software key, a
 * recorded role, a P-256 record or a Keystore alias, so a live key never shares an id. Two
 * concurrent generations draw the same id with probability 2^-64.
 *
 * ## Process
 *
 * The adapter runs in the app's main process only. [SharedPreferences.Editor.commit] writes the
 * committing process's whole cached map, so two processes over one preferences file lose each
 * other's records and roles; the production constructor throws `SCP-CRYPTO-4060` in any other
 * process (ADR-027 criterion 1).
 *
 * ## Key storage strategy
 *
 * - **P-256 (all API levels):** a Keystore `PURPOSE_SIGN` key over secp256r1 with
 *   `DIGEST_NONE`, which signs the bridge's 32-byte digest with `NONEwithECDSA` and returns
 *   DER. Its custody class is read from `KeyInfo` at mint and recorded.
 * - **HPKE P-256, API 31+:** a Keystore `PURPOSE_AGREE_KEY` key; custody from `KeyInfo`.
 * - **HPKE P-256, API 26-30:** a Bouncy Castle scalar committed to [encryptedPrefs];
 *   [CustodyType.SOFTWARE].
 * - **Ed25519, API 33+:** Keystore `EdDSA`. [CustodyType.HARDWARE] is reported without reading
 *   `KeyInfo`, so on a device whose KeyMint runs in software the handle over-claims.
 * - **Ed25519, API 26-32:** Bouncy Castle, held in [softwareKeys], its 32-byte seed committed to
 *   [encryptedPrefs]. [CustodyType.SOFTWARE].
 * - **Pseudonyms:** [derivePseudonym] and [deriveRotatablePseudonym] return a 33-byte
 *   compressed P-256 point of an Ed25519 identity and store no key.
 *
 * ## Errors
 *
 * Every public method throws only [ScpException]: `SCP-CRYPTO-4006` for a key it does not hold
 * (or whose mint is still pending, which reads as absent), and `SCP-CRYPTO-4060` for every other
 * failure, with the original exception as the cause. A P-256 record that does not parse fails
 * only the operations on its own id. An [Error] propagates unchanged.
 *
 * ## Thread safety
 *
 * Android Keystore operations are thread-safe. The key maps are [ConcurrentHashMap]s, and the
 * persisted id indexes change under one process-wide lock. The software HPKE key pairs loaded
 * from their scalars sit in one process-wide map under its own lock, which every instance
 * shares, so a destroy through any instance leaves the pair cached in none.
 *
 * ## Compromise recovery
 *
 * `.docs/specs/09-security-model.md` §9.12 (Compromise Recovery Protocol) defines the recovery
 * steps. This KDoc does not restate them.
 *
 * @property encryptedPrefs Persistent storage for software seeds and scalars, key records and
 *   roles. In production an [EncryptedSharedPreferences] instance; tests inject a plain one.
 * @property keystore The Android Keystore operations; JVM tests inject a fake.
 * @property keystoreEd25519 Whether Ed25519 identities are generated in [keystore] (API 33+).
 * @param keystoreAgreement Whether HPKE P-256 keys are generated in [keystore] (API 31+), from
 *   [keystoreAgreementAvailable]. Only new mints read it; an existing key follows its record.
 * @param processTag This process's tag (see [currentProcessTag]). Construction sweeps, best
 *   effort, every P-256 mint left pending under another tag.
 * @param warn Where the sweep reports a pending mint it leaves in place.
 * @throws ScpException with code `SCP-CRYPTO-4060` when a persisted Ed25519 seed cannot be
 *   restored. The sweep never fails construction.
 */
class AndroidKeyCustody private constructor(
    private val encryptedPrefs: SharedPreferences,
    private val keystore: KeystoreKeys,
    private val keystoreEd25519: Boolean,
    private val keystoreAgreement: Boolean,
    processTag: String,
    warn: (String, Throwable) -> Unit,
) : KeyCustodyProvider {

    /**
     * Production constructor — creates [EncryptedSharedPreferences] backed by Android
     * Keystore for the adapter's persisted keys and records (ADR-027).
     *
     * @param context Android application context. Must be an application context
     *   (not an activity context) to avoid memory leaks from long-lived references.
     * @throws ScpException with code `SCP-CRYPTO-4060` outside the app's main process, before
     *   the preferences file is opened, and when the master key or the preferences file cannot
     *   be opened or read. The constructor throws no other exception.
     */
    constructor(context: Context) : this(
        openPreferences(context),
        androidKeystoreKeys(),
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU,
        keystoreAgreementAvailable(Build.VERSION.SDK_INT),
        currentProcessTag(),
        ::logCustodyWarning,
    )

    /**
     * The software Ed25519 key pairs (Bouncy Castle), by key id.
     *
     * `internal`, not `private`, because the unit tests read it; `@JvmSynthetic`, so Java code
     * in an app cannot call its mangled public JVM getter.
     */
    @get:JvmSynthetic
    internal val softwareKeys = ConcurrentHashMap<String, AsymmetricCipherKeyPair>()

    /** The [KeyType] of each key in [softwareKeys]: [KeyType.ED25519]. */
    @get:JvmSynthetic
    internal val softwareKeyTypes = ConcurrentHashMap<String, KeyType>()

    private val softwareKeyOps = SoftwareKeyOps(softwareKeys, softwareKeyTypes, encryptedPrefs)

    /**
     * The role of each Ed25519 key, persisted beside it in [encryptedPrefs]. A P-256 key's
     * role lives in its record instead (see [roleOf]).
     */
    @get:JvmSynthetic
    internal val keyRoles = custodyGuarded { KeyRoles(encryptedPrefs) }

    /** The record of each P-256 and HPKE P-256 key, its role included. */
    @get:JvmSynthetic
    internal val keyRecords = KeyRecords(encryptedPrefs)

    private val p256 = P256Keys(encryptedPrefs, keystore, keyRecords, processTag, warn)

    init {
        custodyGuarded {
            softwareKeyOps.restorePersistedEd25519Keys(keyRoles.persistedIds())
        }
        p256.sweep()
    }

    // -----------------------------------------------------------------------
    // KeyCustodyProvider implementation
    // -----------------------------------------------------------------------

    /**
     * Generates a new keypair of [keyType] in [KeyRole.OPERATIONAL]; the bridge mints an
     * identity through [UniffiKeyCustody], which names the role. The store per type is in the
     * class KDoc.
     */
    override fun generateKeypair(keyType: KeyType): KeyHandle = generateKeypair(keyType, KeyRole.OPERATIONAL)

    /**
     * Generates a [keyType] keypair under a fresh decimal `ULong` id (see the class KDoc) and
     * records [role] for the key's lifetime. A P-256 key's record carries its role, committed in
     * the one write that reserves the record before the key is created; an Ed25519 key records
     * its role through [KeyRoles.mint], persisted before the key is created.
     * A failure leaves neither the key nor its role, except the one case [P256Keys.mint] names:
     * a P-256 key whose rollback cannot be confirmed keeps its pending record, and
     * `SCP-CRYPTO-4060` names the id for [destroyKeyById].
     *
     * @throws ScpException with code `SCP-CRYPTO-4060` if every drawn id is taken, a write does
     *   not commit, or the store fails.
     */
    @JvmSynthetic
    internal fun generateKeypair(keyType: KeyType, role: KeyRole): KeyHandle = custodyGuarded {
        val keyId = generateSequence { SecureRandom().nextLong().toULong().toString() }
            .take(MINT_ATTEMPTS)
            .firstOrNull { id ->
                !softwareKeys.containsKey(id) && !keyRoles.contains(id) && !keyRecords.contains(id) &&
                    !keystore.containsAlias(keyAlias(id))
            }
            ?: throw ScpException("No free key id after $MINT_ATTEMPTS draws", CUSTODY_ERROR)
        when (keyType) {
            KeyType.P256 -> p256.mint(keyId, KeyType.P256, Backing.KEYSTORE, role)
            KeyType.HPKE_P256 ->
                p256.mint(keyId, KeyType.HPKE_P256, if (keystoreAgreement) Backing.KEYSTORE else Backing.SOFTWARE, role)
            KeyType.ED25519 -> keyRoles.mint(keyId, role, persist = true) {
                if (keystoreEd25519) keystore.generateIdentity(keyId) else softwareKeyOps.generateEd25519(keyId)
            }
        }
    }

    /**
     * The role [keyId] was minted in: from its record for a P-256 key, read on every call, and
     * from [keyRoles] otherwise; `null` when none is recorded.
     *
     * @throws ScpException with code `SCP-CRYPTO-4060` when the key's record does not parse.
     */
    @JvmSynthetic
    internal fun roleOf(keyId: String): KeyRole? = keyRecords.get(keyId)?.role ?: keyRoles.roleOf(keyId)

    /**
     * The [KeyHandle] of the key named [keyId]: for a P-256 key, the custody its record holds;
     * otherwise [CustodyType.SOFTWARE] when this instance holds a software key under it, and
     * [CustodyType.HARDWARE] when (API 33+) Keystore holds its Ed25519 alias.
     *
     * @throws ScpException with code `SCP-CRYPTO-4006` when no store holds [keyId], or its P-256
     *   mint is still pending.
     */
    @JvmSynthetic
    internal fun resolveKeyHandle(keyId: String): KeyHandle = custodyGuarded {
        val record = settledRecord(keyId)
        when {
            record != null -> KeyHandle(id = keyId, custodyType = checkNotNull(record.custody))
            softwareKeys.containsKey(keyId) -> KeyHandle(id = keyId, custodyType = CustodyType.SOFTWARE)
            keystoreEd25519 && keystore.containsAlias(keyAlias(keyId)) ->
                KeyHandle(id = keyId, custodyType = CustodyType.HARDWARE)
            else -> throw ScpException("Key not found: $keyId", KEY_NOT_FOUND)
        }
    }

    /**
     * Signs [data] with the key named by [keyHandle].
     *
     * A P-256 key (by its record) signs [data] as a 32-byte digest in Keystore with
     * `NONEwithECDSA` and returns the DER signature; the bridge converts it to raw low-s. An
     * Ed25519 key signs [data] in Keystore ([CustodyType.HARDWARE]) or Bouncy Castle and returns
     * 64 bytes. No domain separation is applied.
     *
     * @throws ScpException with code `SCP-CRYPTO-4006` if the key is not found.
     * @throws ScpException with code `SCP-CRYPTO-4060` if the key cannot sign (HPKE P-256), a
     *   P-256 digest is not 32 bytes, or the store fails.
     */
    override fun sign(keyHandle: KeyHandle, data: ByteArray): ByteArray = custodyGuarded {
        val record = settledRecord(keyHandle.id)
        when {
            record != null -> p256.sign(keyHandle.id, record, data)
            keyHandle.custodyType == CustodyType.HARDWARE -> keystore.signEd25519(keyHandle.id, data)
            else -> softwareKeyOps.sign(keyHandle, data)
        }
    }

    /**
     * The public key of [keyHandle]: 32 bytes for Ed25519, the 33-byte compressed
     * point for P-256, and the 65-byte uncompressed point for HPKE P-256.
     *
     * @throws ScpException with code `SCP-CRYPTO-4006` if the key is not found.
     */
    override fun publicKey(keyHandle: KeyHandle): ByteArray = custodyGuarded {
        val record = settledRecord(keyHandle.id)
        when {
            record != null -> p256.publicKey(keyHandle.id, record)
            keyHandle.custodyType == CustodyType.HARDWARE -> keystore.ed25519PublicKey(keyHandle.id)
            else -> softwareKeyOps.publicKey(keyHandle)
        }
    }

    /**
     * Destroys the key named by [keyHandle]; the same as [destroyKeyById] on its id.
     */
    override fun destroyKey(keyHandle: KeyHandle): DestructionAttestation = destroyKeyById(keyHandle.id)

    /**
     * Destroys the key named [keyId] and confirms by re-fetch that its material is gone (section
     * 9.15). Every destruction reports [DestructionMethod.SOFTWARE_ONLY]: Keystore issues no
     * proof that it destroyed a key, and §9.15 rates a destruction without a verified platform
     * proof as software-only (ADR-027 criterion 4).
     *
     * - **A P-256 key, settled or pending:** deletes the Keystore alias or the committed scalar,
     *   then the record, which holds the key's role.
     * - **A P-256 key whose record does not parse:** deletes the alias and the scalar, whichever
     *   exists, then the record.
     * - **A software Ed25519 key:** removes it from [softwareKeys] and its seed from
     *   [encryptedPrefs] with `commit()`, confirmed by re-reading the entry, then its role.
     *   Another instance in the same process that already holds the key in its own map keeps it
     *   until that instance is gone.
     * - **A Keystore alias with no record** (an Ed25519 identity, or a P-256 key left by a crash
     *   before its record), whatever the API level: deletes the pseudonym secret, then the alias,
     *   then the role.
     *
     * A retry after a failure removes what the failed attempt left. When the key material was
     * already gone, the retry removes any pseudonym secret and role left behind and then throws
     * `SCP-CRYPTO-4006`, as for a key the adapter never held.
     *
     * @return [DestructionAttestation] with `confirmed = true`; an unconfirmed deletion throws.
     * @throws ScpException with code `SCP-CRYPTO-4006` if no store holds [keyId].
     * @throws ScpException with code `SCP-CRYPTO-4060` if a deletion cannot be confirmed.
     */
    @JvmSynthetic
    internal fun destroyKeyById(keyId: String): DestructionAttestation = custodyGuarded {
        if (keyRecords.isUnreadable(keyId)) return@custodyGuarded p256.destroyUnreadable(keyId)
        keyRecords.get(keyId)?.let { return@custodyGuarded p256.destroy(keyId, it) }
        val attestation = if (softwareKeys.containsKey(keyId)) {
            softwareKeyOps.destroy(keyId)
        } else {
            destroyKeystoreKey(keyId)
        }
        keyRoles.forget(keyId)
        attestation
    }

    /**
     * Diffie-Hellman agreement of the key named by [keyHandle] with [peerPublic].
     *
     * Only an HPKE P-256 key agrees: [peerPublic] is the 65-byte uncompressed point, validated
     * on the curve before the key is used, and the result is the 32-byte x-coordinate (RFC 9180
     * §7.1.1). An Ed25519 key never agrees (ADR-021, 2026-10-18 amendment), and neither does a
     * P-256 signing key.
     *
     * @throws ScpException with code `SCP-CRYPTO-4006` if the key is not found.
     * @throws ScpException with code `SCP-CRYPTO-4060` for a peer key that fails validation, a
     *   key type that does not agree, or a store failure.
     */
    override fun dhAgree(keyHandle: KeyHandle, peerPublic: ByteArray): ByteArray = custodyGuarded {
        val record = settledRecord(keyHandle.id)
        when {
            record != null -> p256.agree(keyHandle.id, record, peerPublic)
            keyHandle.custodyType == CustodyType.HARDWARE ->
                if (!keystore.containsAlias(keyAlias(keyHandle.id))) {
                    throw ScpException("Key not found in Keystore: ${keyHandle.id}", KEY_NOT_FOUND)
                } else {
                    throw ScpException(
                        "dhAgree cannot use Keystore key '${keyHandle.id}': it is an Ed25519 key, and an " +
                            "Ed25519 key never agrees",
                        CUSTODY_ERROR,
                    )
                }
            else -> softwareKeyOps.refuseAgreement(keyHandle)
        }
    }

    /**
     * Derives the deterministic, context-scoped P-256 pseudonym of an Ed25519 identity and
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
     * §9.10.4.A native interim until the identity key moves to P-256 (SCP-315). The Rust helper
     * behind [P256Pseudonym.softwarePoint] runs all three steps, so software pseudonyms match
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
     *   pseudonym secret is not found, or [keyHandle] names a P-256 mint still pending.
     * @throws ScpException with code `SCP-CRYPTO-4060` if the key is not an Ed25519 identity.
     */
    override fun derivePseudonym(keyHandle: KeyHandle, contextId: ByteArray): ByteArray =
        // v1 HMAC body: contextId || "scp-pseudonym".
        pseudonymPoint("derivePseudonym", keyHandle, contextId, null, "scp-pseudonym".toByteArray(Charsets.UTF_8))

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
     *   pseudonym secret is not found, or [keyHandle] names a P-256 mint still pending.
     * @throws ScpException with code `SCP-CRYPTO-4060` if the key is not an Ed25519 identity.
     */
    override fun deriveRotatablePseudonym(
        keyHandle: KeyHandle,
        contextId: ByteArray,
        pseudonymEpoch: Long,
    ): ByteArray {
        val epochBe = ByteBuffer.allocate(Long.SIZE_BYTES)
            .order(ByteOrder.BIG_ENDIAN)
            .putLong(pseudonymEpoch)
            .array()
        // v2 HMAC body: contextId || BE64(epoch) || "scp-pseudonym-v2".
        return pseudonymPoint(
            "deriveRotatablePseudonym",
            keyHandle,
            contextId,
            pseudonymEpoch,
            epochBe + "scp-pseudonym-v2".toByteArray(Charsets.UTF_8),
        )
    }

    /**
     * The pseudonym point of [keyHandle]. A pending P-256 id is `SCP-CRYPTO-4006`, as for every
     * operation but destroy; a settled P-256 key is rejected with
     * `SCP-CRYPTO-4060`, naming [operation]. A hardware identity computes the
     * context seed `HMAC-SHA256(pseudonym_secret, contextId || suffix)` inside Keystore, and
     * only while its identity alias exists, so a destroy that removed the identity but not yet
     * the secret cannot leave a derivable pseudonym. A software identity passes its Ed25519 seed
     * to the Rust helper with [epoch] (`null` for v1), and the seed copy is wiped.
     */
    private fun pseudonymPoint(
        operation: String,
        keyHandle: KeyHandle,
        contextId: ByteArray,
        epoch: Long?,
        suffix: ByteArray,
    ): ByteArray = custodyGuarded {
        settledRecord(keyHandle.id)?.let {
            throw ScpException("$operation requires an Ed25519 key; key '${keyHandle.id}' is ${it.type}", CUSTODY_ERROR)
        }
        softwareKeyTypes.requireEd25519Identity(keyHandle, operation)
        if (keyHandle.custodyType == CustodyType.HARDWARE) {
            if (!keystore.containsAlias(keyAlias(keyHandle.id))) {
                throw ScpException("Key not found in Keystore: ${keyHandle.id}", KEY_NOT_FOUND)
            }
            val seed = PseudonymSecret.keystoreContextSeed(keystore, keyHandle.id, contextId, suffix)
            return@custodyGuarded P256Pseudonym.pointFromSeed(seed)
        }
        val keyPair = softwareKeys[keyHandle.id]
            ?: throw ScpException("Key not found: ${keyHandle.id}", KEY_NOT_FOUND)
        val seed = (keyPair.private as Ed25519PrivateKeyParameters).encoded
        try {
            P256Pseudonym.softwarePoint(seed, contextId, epoch)
        } finally {
            seed.fill(0)
        }
    }

    /**
     * The record of [keyId], or `null` for a key without one.
     *
     * @throws ScpException with code `SCP-CRYPTO-4006` when the record is still pending: the key
     *   is not usable until its mint settles, and [destroyKeyById] removes it.
     */
    private fun settledRecord(keyId: String): KeyRecord? {
        val record = keyRecords.get(keyId) ?: return null
        if (record.custody == null) throw ScpException("Key $keyId is not usable: its mint is pending", KEY_NOT_FOUND)
        return record
    }

    /**
     * Deletes the Keystore identity [keyId] and its pseudonym secret and confirms both are gone
     * (section 9.15): the secret first, so a failure between the two leaves the identity, and a
     * retry completes the destroy. An identity alias that is already absent reports
     * `SCP-CRYPTO-4006`, after deleting any pseudonym secret and role left behind.
     */
    private fun destroyKeystoreKey(keyId: String): DestructionAttestation {
        val keystoreAlias = keyAlias(keyId)
        val secretAlias = PseudonymSecret.alias(keyId)
        if (!keystore.containsAlias(keystoreAlias)) {
            if (keystore.containsAlias(secretAlias)) keystore.deleteConfirmed(keyId, secretAlias)
            if (keyRoles.contains(keyId)) keyRoles.forget(keyId)
            throw ScpException("Key not found: $keyId", KEY_NOT_FOUND)
        }
        keystore.deleteConfirmed(keyId, secretAlias, keystoreAlias)
        return DestructionAttestation(method = DestructionMethod.SOFTWARE_ONLY, confirmed = true)
    }

    companion object {
        /** Filename for the EncryptedSharedPreferences of the adapter's keys and records. */
        internal const val PREFS_FILENAME = "scp_key_custody"

        /**
         * The number of fresh ids [generateKeypair] draws before it gives up. Eight collisions
         * in a row among random 64-bit ids means the stores are not behaving, not bad luck.
         */
        private const val MINT_ATTEMPTS = 8

        /** The process name [create] assumes when a test names none: the main process's own. */
        private const val TEST_PROCESS = "works.limn.scp.test"

        /**
         * An adapter over [encryptedPrefs] and [keystore], for the JVM tests, after the same
         * main-process check the production constructor makes: [processName] is this process's
         * name and [mainProcessName] the app's main process name.
         *
         * @throws ScpException with code `SCP-CRYPTO-4060` when [processName] is not
         *   [mainProcessName].
         */
        @JvmSynthetic
        @Suppress("LongParameterList") // one parameter per injected dependency
        internal fun create(
            encryptedPrefs: SharedPreferences,
            keystore: KeystoreKeys,
            keystoreEd25519: Boolean = false,
            keystoreAgreement: Boolean = false,
            processTag: String = currentProcessTag(),
            processName: String? = TEST_PROCESS,
            mainProcessName: String = TEST_PROCESS,
            warn: (String, Throwable) -> Unit = ::logCustodyWarning,
        ): AndroidKeyCustody {
            requireMainProcess(processName, mainProcessName)
            return AndroidKeyCustody(encryptedPrefs, keystore, keystoreEd25519, keystoreAgreement, processTag, warn)
        }

        /**
         * The production preferences, opened only after [requireMainProcess] has checked that
         * this is the app's main process.
         */
        private fun openPreferences(context: Context): SharedPreferences =
            openPreferences(currentProcessName(context), context.applicationInfo.processName) {
                EncryptedSharedPreferences.create(
                    PREFS_FILENAME,
                    MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
                    context.applicationContext,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
                )
            }

        /**
         * Runs [requireMainProcess] on [processName] and [mainProcessName], then [open]. A
         * failure of [open] (`MasterKeys.getOrCreate` and `EncryptedSharedPreferences.create`
         * throw `GeneralSecurityException` and `IOException`) becomes `SCP-CRYPTO-4060`, so the
         * production constructor throws only [ScpException].
         *
         * @throws ScpException with code `SCP-CRYPTO-4060` outside the main process, or when
         *   [open] fails.
         */
        @JvmSynthetic
        internal fun openPreferences(
            processName: String?,
            mainProcessName: String,
            open: () -> SharedPreferences,
        ): SharedPreferences {
            requireMainProcess(processName, mainProcessName)
            return custodyGuarded(open)
        }

        /**
         * This process's name: `Application.getProcessName()` from API 28, and below it the
         * entry of `ActivityManager.runningAppProcesses` whose pid is this process's. `null`
         * when it cannot be read.
         */
        private fun currentProcessName(context: Context): String? =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                Application.getProcessName()
            } else {
                (context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager)
                    ?.runningAppProcesses
                    ?.firstOrNull { it.pid == Process.myPid() }
                    ?.processName
            }
    }
}

/**
 * Refuses to build an adapter outside the app's main process: [processName] is this process's
 * name, `null` when it could not be read, and [mainProcessName] the app's main process name.
 *
 * @throws ScpException with code `SCP-CRYPTO-4060` naming the rule when they differ.
 */
internal fun requireMainProcess(processName: String?, mainProcessName: String) {
    if (processName == null || processName != mainProcessName) {
        throw ScpException(
            "AndroidKeyCustody runs only in the app's main process ($mainProcessName), not in " +
                "${processName ?: "an unnamed process"}: SharedPreferences.commit() writes a " +
                "process's whole cached map, so two processes lose each other's key records " +
                "(ADR-027 acceptance criterion 1)",
            CUSTODY_ERROR,
        )
    }
}

/** Raw Ed25519 public key size in bytes. */
private const val RAW_ED25519_KEY_SIZE = 32

/** X.509 SubjectPublicKeyInfo size for Ed25519 (RFC 8410 §3): 12-byte header + 32-byte key. */
private const val X509_ED25519_SPKI_SIZE = 44

/**
 * Rejects a software identity handle that this map records as anything but Ed25519 with
 * `SCP-CRYPTO-4060`, naming [operation]. The receiver is [AndroidKeyCustody.softwareKeyTypes].
 */
private fun Map<String, KeyType>.requireEd25519Identity(keyHandle: KeyHandle, operation: String) {
    if (keyHandle.custodyType != CustodyType.SOFTWARE) return
    when (val type = this[keyHandle.id]) {
        KeyType.ED25519, null -> Unit
        KeyType.P256, KeyType.HPKE_P256 -> throw ScpException(
            "$operation requires an Ed25519 key; handle '${keyHandle.id}' is $type",
            CUSTODY_ERROR,
        )
    }
}

/**
 * Generates an Ed25519 identity keypair in Android Keystore under `scp.key.<keyId>`, beside
 * its pseudonym secret, and returns its [CustodyType.HARDWARE] handle.
 *
 * Uses the `EdDSA` algorithm with `Ed25519` parameter spec, available on API 33+. Keystore
 * generates the private key and does not hand it to the app. This function does not read
 * `KeyInfo` and returns [CustodyType.HARDWARE] wherever Keystore put the key. StrongBox is not
 * requested, and no user authentication is required, so SCP signs in the background.
 */
@Suppress("TooGenericExceptionCaught") // any failure must delete the half-made identity
private fun KeystoreKeys.generateIdentity(keyId: String): KeyHandle {
    val keystoreAlias = keyAlias(keyId)
    generateEd25519(keystoreAlias)
    try {
        generateHmacSha256(PseudonymSecret.alias(keyId))
    } catch (e: Exception) {
        // An identity without its pseudonym secret could never derive a pseudonym,
        // and no handle to it is returned, so it would sit orphaned in Keystore.
        try {
            deleteEntry(keystoreAlias)
        } catch (cleanup: Exception) {
            e.addSuppressed(cleanup)
        }
        throw e
    }
    return KeyHandle(id = keyId, custodyType = CustodyType.HARDWARE)
}

/** The Keystore Ed25519 private key entry of [keyId], or `SCP-CRYPTO-4006` when it is absent. */
private fun KeystoreKeys.ed25519Entry(keyId: String): KeyStore.PrivateKeyEntry {
    val alias = keyAlias(keyId)
    val entry = if (containsAlias(alias)) {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getEntry(alias, null)
    } else {
        null
    }
    return entry as? KeyStore.PrivateKeyEntry
        ?: throw ScpException("Key not found in Keystore: $keyId", KEY_NOT_FOUND)
}

/** Signs [data] with the Keystore Ed25519 key [keyId]; Keystore holds the private key. */
private fun KeystoreKeys.signEd25519(keyId: String, data: ByteArray): ByteArray =
    Signature.getInstance("EdDSA").apply {
        initSign(ed25519Entry(keyId).privateKey)
        update(data)
    }.sign()

/**
 * The raw 32-byte public key of the Keystore Ed25519 key [keyId]: the last 32 bytes of its
 * 44-byte X.509 SubjectPublicKeyInfo (RFC 8410 §3).
 */
private fun KeystoreKeys.ed25519PublicKey(keyId: String): ByteArray {
    val encoded = ed25519Entry(keyId).certificate.publicKey.encoded
    if (encoded.size != X509_ED25519_SPKI_SIZE) {
        throw ScpException(
            "Key $keyId has a ${encoded.size}-byte public key, not the $X509_ED25519_SPKI_SIZE-byte " +
                "X.509 Ed25519 encoding",
            CUSTODY_ERROR,
        )
    }
    return encoded.copyOfRange(X509_ED25519_SPKI_SIZE - RAW_ED25519_KEY_SIZE, X509_ED25519_SPKI_SIZE)
}

/**
 * Bouncy Castle software Ed25519 key operations for [AndroidKeyCustody], on API 26-32, where
 * Android Keystore has no EdDSA.
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
     * Generates a software Ed25519 keypair and commits its 32-byte seed to [encryptedPrefs]
     * under `scp.ed25519.<keyId>` before the maps name the key, so a write that does not commit
     * leaves no key behind.
     *
     * @throws ScpException with code `SCP-CRYPTO-4060` when the seed does not commit.
     */
    fun generateEd25519(keyId: String): KeyHandle {
        val keyPair = Ed25519KeyPairGenerator().apply {
            init(Ed25519KeyGenerationParameters(SecureRandom()))
        }.generateKeyPair()
        persistEd25519Key(keyId, keyPair)
        softwareKeys[keyId] = keyPair
        softwareKeyTypes[keyId] = KeyType.ED25519
        return KeyHandle(id = keyId, custodyType = CustodyType.SOFTWARE)
    }

    /** Signs [data] with the software Ed25519 key under [keyHandle]; any other type is 4060. */
    fun sign(keyHandle: KeyHandle, data: ByteArray): ByteArray {
        val keyPair = softwareKeys[keyHandle.id]
            ?: throw ScpException("Key not found: ${keyHandle.id}", KEY_NOT_FOUND)
        when (val type = softwareKeyTypes[keyHandle.id]) {
            KeyType.ED25519 -> Unit
            KeyType.P256, KeyType.HPKE_P256, null ->
                throw ScpException("sign requires an Ed25519 key; handle '${keyHandle.id}' is $type", CUSTODY_ERROR)
        }
        val signer = Ed25519Signer()
        signer.init(true, keyPair.private)
        signer.update(data, 0, data.size)
        return signer.generateSignature()
    }

    /**
     * Refuses agreement with the software key under [keyHandle]: every software key is Ed25519,
     * and an Ed25519 key never agrees (ADR-021, 2026-10-18 amendment).
     *
     * @throws ScpException with code `SCP-CRYPTO-4006` if no software key sits under [keyHandle].
     * @throws ScpException with code `SCP-CRYPTO-4060` otherwise.
     */
    fun refuseAgreement(keyHandle: KeyHandle): Nothing {
        // The key comes first, so an unknown key is SCP-CRYPTO-4006 whatever the peer.
        if (!softwareKeys.containsKey(keyHandle.id)) {
            throw ScpException("Key not found: ${keyHandle.id}", KEY_NOT_FOUND)
        }
        throw ScpException(
            "dhAgree cannot use key '${keyHandle.id}': it is an Ed25519 key, and an Ed25519 key never agrees",
            CUSTODY_ERROR,
        )
    }

    /** The raw 32-byte public key of the software key under [keyHandle]. */
    fun publicKey(keyHandle: KeyHandle): ByteArray {
        val keyPair = softwareKeys[keyHandle.id]
            ?: throw ScpException("Key not found: ${keyHandle.id}", KEY_NOT_FOUND)
        return when (val type = softwareKeyTypes[keyHandle.id]) {
            KeyType.ED25519 -> (keyPair.public as Ed25519PublicKeyParameters).encoded
            KeyType.P256, KeyType.HPKE_P256, null ->
                throw ScpException("Software key '${keyHandle.id}' has type $type", CUSTODY_ERROR)
        }
    }

    /**
     * Destroys the software key [keyId]: removes it from the maps and its seed entry (which only
     * a generated Ed25519 key has) from [encryptedPrefs] with `commit()`, then confirms by
     * re-reading the entry and the map. [DestructionMethod.SOFTWARE_ONLY].
     *
     * @throws ScpException with code `SCP-CRYPTO-4060` if the removal does not commit or the
     *   seed is still readable.
     */
    fun destroy(keyId: String): DestructionAttestation {
        softwareKeys.remove(keyId)
        softwareKeyTypes.remove(keyId)
        val prefsKey = "$PREFS_KEY_PREFIX$keyId"
        val committed = encryptedPrefs.edit().remove(prefsKey).commit()
        if (!committed || encryptedPrefs.getString(prefsKey, null) != null || softwareKeys.containsKey(keyId)) {
            throw ScpException("Key destruction failed: the seed of key $keyId persisted", CUSTODY_ERROR)
        }
        return DestructionAttestation(method = DestructionMethod.SOFTWARE_ONLY, confirmed = true)
    }

    /**
     * Commits the 32-byte seed of an Ed25519 key, Base64-encoded, to [encryptedPrefs], then
     * zeroes the local seed copy.
     *
     * @throws ScpException with code `SCP-CRYPTO-4060` when the write does not commit.
     */
    private fun persistEd25519Key(keyId: String, keyPair: AsymmetricCipherKeyPair) {
        val seed = (keyPair.private as Ed25519PrivateKeyParameters).encoded
        try {
            val encoded = java.util.Base64.getEncoder().encodeToString(seed)
            if (!encryptedPrefs.edit().putString("$PREFS_KEY_PREFIX$keyId", encoded).commit()) {
                throw ScpException("Could not commit the seed of key $keyId", CUSTODY_ERROR)
            }
        } finally {
            seed.fill(0)
        }
    }

    /**
     * Restores the persisted Ed25519 seed of each of [keyIds] that has one into [softwareKeys],
     * reading each entry with `getString`. A seed that is not 32 bytes is `SCP-CRYPTO-4060`. The
     * decoded seed bytes are zeroed after the keypair is rebuilt.
     */
    fun restorePersistedEd25519Keys(keyIds: Set<String>) {
        for (keyId in keyIds) {
            val stored = encryptedPrefs.getString("$PREFS_KEY_PREFIX$keyId", null) ?: continue
            val seed = java.util.Base64.getDecoder().decode(stored)
            try {
                if (seed.size != ED25519_SEED_SIZE) {
                    throw ScpException("The seed of key $keyId is ${seed.size} bytes", CUSTODY_ERROR)
                }
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

    private companion object {
        /** Key prefix for Ed25519 private key entries in EncryptedSharedPreferences. */
        const val PREFS_KEY_PREFIX = "scp.ed25519."
        const val ED25519_SEED_SIZE = 32
    }
}

/**
 * Deletes each of [aliases] in order and confirms by re-fetch that none remains (section 9.15).
 * A Keystore failure or a surviving alias is `SCP-CRYPTO-4060`, and the aliases after a failed
 * one are left in place.
 */
internal fun KeystoreKeys.deleteConfirmed(keyId: String, vararg aliases: String) {
    for (alias in aliases) {
        try {
            deleteEntry(alias)
        } catch (e: java.security.KeyStoreException) {
            throw ScpException("Key destruction failed: Keystore could not delete $alias for $keyId", CUSTODY_ERROR, e)
        }
        if (containsAlias(alias)) {
            throw ScpException("Key destruction failed: $alias persisted after deletion for $keyId", CUSTODY_ERROR)
        }
    }
}
