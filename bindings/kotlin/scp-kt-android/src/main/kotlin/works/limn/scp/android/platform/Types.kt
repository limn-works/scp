// Types.kt — Supporting types for Android platform adapters (ADR-027)
//
// These types are the Kotlin-side contract of the Android adapters. Each interface's KDoc states
// how it differs from the Rust `scp-platform` trait (crates/scp-platform/src/traits.rs) and from
// the UniFFI callback interface (crates/scp-ffi/uniffi/src/lib.rs) for the same capability. No
// code passes an Android adapter to the Rust engine. The UniFFI bridge has no function that
// accepts a storage, push or device attestation provider. `SCP.identityCreateWithCustody` in
// `scp-kt` accepts a key custody provider, but only the UniFFI-generated
// `uniffi.scp.KeyCustodyProvider`, which these interfaces are not. ADR-021 (the UniFFI bridge)
// and ADR-027 require each Android adapter to implement its UniFFI callback interface and to be
// injected into the Rust engine, so these interfaces diverge from both ADRs. Stories SCP-110 to
// SCP-113 of `.docs/prds/main.json` stay in progress while any acceptance criterion their
// descriptions record as unmet stands; each adapter's trait criterion is one of them. Story
// SCP-214 tracks injecting a key custody provider into the Rust engine.
//
// Provenance: ADR-027 (Android Platform Adapter), ADR-006 (Platform Abstraction Layer),
// ADR-025 (Apple Platform Adapter — parallel reference).

package works.limn.scp.android.platform

/**
 * The type of cryptographic key managed by a [KeyHandle].
 *
 * The shipped variants name curves: Ed25519 keys are used for identity and signing,
 * X25519 keys are used for key agreement (HPKE wrapping keys). ADR-006, as amended on
 * 2026-09-10, names the two key types by purpose, `P256Signing` and `P256Agreement`; this
 * enum has not moved to them.
 */
enum class KeyType {
    /** Ed25519 signing key (identity keys, active signing keys, pseudonym keys). */
    ED25519,

    /** X25519 key agreement key (HPKE wrapping keys). */
    X25519,
}

/**
 * The custody type for a given key, indicating where the key material is stored
 * and how it is protected.
 *
 * See ADR-006 for the custody model. [AndroidKeyCustody] reports [HARDWARE] for a
 * Keystore key and [SOFTWARE] for a Bouncy Castle key. No Android adapter reports
 * [IN_MEMORY]; the value matches the custody type of ADR-006's in-memory testing
 * adapter, which is Rust code and reports the Rust `CustodyType`.
 */
enum class CustodyType {
    /**
     * Key material is stored in memory only. No Android adapter reports this value; it
     * matches the Rust in-memory testing adapter of ADR-006.
     */
    IN_MEMORY,

    /**
     * Key material is held by Android Keystore, which does not hand the private bytes to the
     * app. [AndroidKeyCustody] reports this value for every Keystore key without reading
     * `KeyInfo.securityLevel`, so the value does not show whether Keystore put the key in the
     * TEE or, on a device whose KeyMint runs in software, in software.
     */
    HARDWARE,

    /**
     * Key material is held by Bouncy Castle in the app process, not by Android Keystore.
     * [AndroidKeyCustody] also writes the private key seed of each software Ed25519 key it
     * generates (API 26-32) to an on-disk EncryptedSharedPreferences file. Software X25519
     * keys and derived pseudonym keys stay in process memory only.
     */
    SOFTWARE,
}

/**
 * Opaque handle to a cryptographic key managed by a [KeyCustodyProvider] implementation.
 *
 * @property id Unique identifier for the key. For Android Keystore keys, this maps to
 *   alias `scp.key.$id`. For software keys, this maps to a [ConcurrentHashMap] entry and,
 *   for a software Ed25519 key that [KeyCustodyProvider.generateKeypair] creates (API 26-32),
 *   also to the EncryptedSharedPreferences entry `scp.ed25519.$id`. A derived pseudonym key
 *   is also a software Ed25519 key, and it has no EncryptedSharedPreferences entry.
 * @property custodyType Where the key material is stored ([CustodyType.HARDWARE] for Keystore,
 *   [CustodyType.SOFTWARE] for Bouncy Castle fallback).
 */
data class KeyHandle(
    val id: String,
    val custodyType: CustodyType,
)

/**
 * Handle to a derived pseudonym keypair.
 *
 * Pseudonym keys are always software-managed regardless of whether the source
 * identity key is a Keystore key. See ADR-006 for the derivation algorithm.
 *
 * @property id Unique identifier for the pseudonym signing key.
 * @property custodyType Always [CustodyType.SOFTWARE] for derived pseudonym keys.
 */
data class PseudonymKeyHandle(
    val id: String,
    val custodyType: CustodyType,
)

/**
 * Attestation that a key has been destroyed.
 *
 * For Android Keystore keys, [method] is [DestructionMethod.HARDWARE] because Keystore held
 * the key and deleted it. [AndroidKeyCustody] does not read `KeyInfo.securityLevel`, so
 * [DestructionMethod.HARDWARE] does not show whether the key sat in the TEE or in a software
 * KeyMint. For Bouncy Castle keys, [method] is [DestructionMethod.SOFTWARE_ONLY].
 *
 * See section 9.15 of the SCP specification for key destruction requirements.
 *
 * @property method The mechanism by which key material was destroyed.
 * @property confirmed Always `true` in an attestation [AndroidKeyCustody] returns. After
 *   deleting, [AndroidKeyCustody] checks that no key sits under the handle's id and throws
 *   [ScpException] with code `SCP-CRYPTO-4004` when one does, so it never returns `false`, and
 *   the field says no more than that [KeyCustodyProvider.destroyKey] returned. For a Keystore
 *   key, the check asks Keystore whether it still holds the alias. For a software key, the check
 *   reads the in-memory map right after removing the id from it, so it fails only when another
 *   call inserts the same id between the removal and the check, and [AndroidKeyCustody] inserts
 *   only fresh random UUIDs. It does not read the EncryptedSharedPreferences entry that holds
 *   the seed of a software Ed25519 key that [KeyCustodyProvider.generateKeypair] creates
 *   (API 26-32). [AndroidKeyCustody] removes that entry with
 *   `apply()`, which returns before the removal reaches disk, so `confirmed` is `true` while the
 *   seed can still be on disk. When the process dies before the write lands, the next
 *   [AndroidKeyCustody] instance restores the seed at startup and the key signs again.
 */
data class DestructionAttestation(
    val method: DestructionMethod,
    val confirmed: Boolean,
)

/**
 * The mechanism by which key material was destroyed.
 *
 * See section 9.15 of the SCP specification.
 */
enum class DestructionMethod {
    /**
     * Key material was deleted from software storage: the Bouncy Castle in-memory map and,
     * for a software Ed25519 key that [KeyCustodyProvider.generateKeypair] creates
     * (API 26-32), its EncryptedSharedPreferences entry. [AndroidKeyCustody]
     * removes that entry with `apply()`, which writes the removal to disk asynchronously.
     */
    SOFTWARE_ONLY,

    /** Key material was deleted from Android Keystore (see [CustodyType.HARDWARE]). */
    HARDWARE,
}

/**
 * SCP-specific exception with structured error codes.
 *
 * Error codes follow the pattern `SCP-{DOMAIN}-{NUMBER}`:
 * - `SCP-CRYPTO-4001`: Key not found (a software or Keystore lookup, any key type, X25519
 *   included), with two exceptions: [KeyCustodyProvider.dhAgree] throws `SCP-CRYPTO-4002` for a
 *   missing key, and [KeyCustodyProvider.exportSigningKeyBytes] throws `SCP-CRYPTO-4005` for a
 *   Keystore handle ([CustodyType.HARDWARE]) whether or not its key exists
 * - `SCP-CRYPTO-4002`: [KeyCustodyProvider.dhAgree] found no software key under the handle: a
 *   destroyed or unknown handle, or a Keystore Ed25519 handle
 * - `SCP-CRYPTO-4003`: Wrong key type for operation, or a [KeyCustodyProvider.dhAgree] peer
 *   public key that is not 32 bytes long. [KeyCustodyProvider.dhAgree] raises it for a wrong
 *   key type only when the handle names a software Ed25519 key.
 * - `SCP-CRYPTO-4004`: Key destruction failed
 * - `SCP-CRYPTO-4005`: Signing key export refused, because the handle is a Keystore handle
 *   (thrown only by [KeyCustodyProvider.exportSigningKeyBytes], from [KeyHandle.custodyType]
 *   before any key lookup, so a destroyed Keystore handle also gets it; retrying cannot succeed)
 * - `SCP-TRANS-5001`: Push payload has no `scp` field
 * - `SCP-TRANS-5002`: Push payload `scp` field is not `"1"`
 * - `SCP-STORAGE-8001`: Storage key not found. Defined as `AndroidStorage.ERROR_KEY_NOT_FOUND`
 *   but thrown by no adapter: a missing key makes [StorageProvider.get] return `null`
 * - `SCP-STORAGE-8002`: Storage operation failed
 * - `SCP-STORAGE-8003`: The Keystore key or the SQLCipher passphrase derivation threw a
 *   `GeneralSecurityException`. [StorageProvider] lists how any other open failure reaches
 *   the caller
 * - `SCP-ATTEST-9001`: Play Integrity attestation failed
 *
 * @property code Structured SCP error code.
 */
open class ScpException(
    message: String,
    val code: String,
    cause: Throwable? = null,
) : Exception(message, cause)

/**
 * A wake signal produced by push notification handling.
 *
 * Indicates that the application should wake up and process pending messages
 * from the SCP relay. See ADR-027 for the FCM data-only payload design.
 */
enum class WakeSignal {
    /** Connect to the relay and pull pending envelopes. */
    PULL,
}

/**
 * Platform trait for device attestation.
 *
 * Abstracts device-level attestation token generation behind a uniform interface.
 * The Android implementation requests a Classic Play Integrity token; ADR-027
 * requires a Standard request, and story SCP-111 tracks that change.
 *
 * This interface declares the two methods of the UniFFI `DeviceAttestationProvider` callback
 * interface in `crates/scp-ffi/uniffi/src/lib.rs` under the Kotlin names UniFFI generates for
 * them, and like the callback's they take and return bytes and suspend. It differs from the
 * callback in its error type: its methods throw this file's [ScpException], while the callback
 * declares `ScpError`, which UniFFI generates in Kotlin as `uniffi.scp.ScpException`, a
 * different class. ADR-027 states that a UniFFI callback that throws any exception other than
 * the generated one panics the Rust caller. It does not mirror the Rust `DeviceAttestation`
 * trait in `crates/scp-platform/src/traits.rs`. The trait's `attest` takes no argument, the
 * trait declares a `verify` method that this interface lacks and no `assert_request`, while
 * this interface declares [assertRequest], and the trait returns a `PlatformError`.
 *
 * See ADR-006 for the platform abstraction design and ADR-027 for the Android adapter.
 */
interface DeviceAttestationProvider {
    /**
     * Generate an attestation token for the given challenge and device ID.
     *
     * @param challenge The 32-byte binding digest `D` of
     *   `09-security-model.md` §9.3.1. ADR-025 and ADR-027 require the caller
     *   to pass `D`. No Rust code calls this method yet.
     * @param deviceId Device ID bytes. `27-attestations.md` states that a device id is not an
     *   identifier, and ADR-027 acceptance criterion 7 requires the Android adapter not to read
     *   this parameter; [AndroidDeviceAttestation] reads it into the `clientDataJSON` nonce
     *   today (see its KDoc).
     * @return Platform-specific attestation token bytes.
     * @throws ScpException if attestation fails. ADR-027 acceptance criterion 7 requires the
     *   Android adapter to throw [ScpException] with code `SCP-ATTEST-9001` for every failure;
     *   [AndroidDeviceAttestation] converts only some exception types (see its KDoc).
     */
    suspend fun attest(challenge: ByteArray, deviceId: ByteArray): ByteArray

    /**
     * Generate a per-request assertion.
     *
     * @param requestHash The 32-byte assertion digest `A` of
     *   `09-security-model.md` §9.3.1 over the request bytes. ADR-025 and
     *   ADR-027 require the caller to pass `A`, never the request bytes or
     *   their plain SHA-256. No Rust code calls this method yet.
     * @return Platform-specific assertion token bytes.
     * @throws ScpException if assertion fails. ADR-027's Implementation paragraph on
     *   `AndroidDeviceAttestation.kt` requires every failure to leave the Android adapter as
     *   [ScpException]; acceptance criterion 8, which covers this method, names no error rule;
     *   [AndroidDeviceAttestation] converts only some exception types (see its KDoc).
     */
    suspend fun assertRequest(requestHash: ByteArray): ByteArray
}

/**
 * Platform trait for push notification registration and handling.
 *
 * Abstracts platform-specific push notification registration and notification
 * handling. The Android implementation uses Firebase Cloud Messaging (FCM).
 *
 * This interface matches neither Rust declaration. [register] returns a `String` token and
 * suspends, and [handleNotification] takes a `Map<String, String>` payload, returns a
 * [WakeSignal], and is synchronous. The Rust `Push` trait in `crates/scp-platform/src/traits.rs`
 * declares the same two methods, but its `register` returns a `PushToken` of bytes, its
 * `handle_notification` takes the payload as `&[u8]`, and both methods are `async`. The UniFFI
 * `PushProvider` callback interface in `crates/scp-ffi/uniffi/src/lib.rs` names them
 * `register_push` and `handle_notification`. Both are `async`: `register_push` returns bytes,
 * and `handle_notification` takes and returns bytes. [handleNotification] throws this file's
 * [ScpException], while the callback declares `ScpError`, which UniFFI generates in Kotlin as
 * `uniffi.scp.ScpException`, a different class, and the Rust trait returns a `PlatformError`.
 * ADR-027 states that a UniFFI callback that throws any exception other than the generated one
 * panics the Rust caller.
 *
 * See ADR-006 for the platform abstraction design and ADR-027 for the Android adapter.
 */
interface PushProvider {
    /**
     * Return the platform-specific push token. The method sends nothing to a relay; the
     * §10.7.1 `PushRegistration` that carries the token to a relay is a separate message.
     *
     * @return The push notification registration token string.
     * @throws Exception whatever the platform token source throws when retrieval fails. The
     *   interface does not require [ScpException], and [AndroidPushProvider] converts no
     *   failure to it.
     */
    suspend fun register(): String

    /**
     * Handle an incoming push notification payload and produce a wake signal.
     *
     * @param payload The push notification data payload as a key-value map.
     * @return [WakeSignal] indicating the action the caller should take.
     * @throws ScpException with code `SCP-TRANS-5001` if the payload has no `scp` field.
     * @throws ScpException with code `SCP-TRANS-5002` if the `scp` field is not `"1"`.
     *   [AndroidPushProvider] checks no other property of the payload: it returns
     *   [WakeSignal.PULL] for a payload that carries other fields beside `"scp": "1"`. §10.7
     *   opacity is the sender's obligation (§10.7.1 step 5).
     */
    fun handleNotification(payload: Map<String, String>): WakeSignal
}

/**
 * Platform trait for cryptographic key custody.
 *
 * Abstracts key generation, signing, key agreement, and pseudonym derivation
 * behind a uniform interface. The Android implementation ([AndroidKeyCustody])
 * uses Android Keystore for Ed25519 on API 33+ and Bouncy Castle
 * for software fallback on API 26-32, and it performs key agreement with a software X25519 key
 * that Bouncy Castle holds in process memory at every API level. ADR-027, as amended on
 * 2026-09-10, requires a different scheme: an EC P-256 signing key in Keystore at every
 * supported API level, and P-256 key agreement in Keystore from API 31 with a Bouncy Castle
 * software P-256 agreement key, stored in EncryptedSharedPreferences, below it. Story SCP-110
 * tracks both moves.
 *
 * This interface matches neither Rust declaration.
 *
 * - Method set: it declares the methods of the UniFFI `KeyCustodyProvider` callback interface in
 *   `crates/scp-ffi/uniffi/src/lib.rs` except `custody_type`, and it names the callback's
 *   `get_public_key` [publicKey], the name the Rust trait's `public_key` takes in Kotlin. The
 *   Rust `KeyCustody` trait in `crates/scp-platform/src/traits.rs` does not declare
 *   `export_signing_key_bytes`, and it also declares `custody_type`, `ed25519_to_x25519_agree`,
 *   `import_ed25519_signing_key` and `generate_ephemeral_ed25519_seed`, which this interface
 *   lacks.
 * - Parameters: its methods name a key by a [KeyHandle], a data class of a `String` id and a
 *   [CustodyType]. The Rust trait's `KeyHandle` is a different type, an opaque `u64`, and the
 *   UniFFI callback's methods take a `String` key ID. [generateKeypair] takes a [KeyType] enum,
 *   as the Rust trait's takes a `KeyType` enum of the same two variants, while the UniFFI
 *   callback's takes a `String` key type. [deriveRotatablePseudonym] takes `pseudonymEpoch` as
 *   a signed `Long`, while both Rust declarations take a `u64`, which UniFFI generates in Kotlin
 *   as `ULong`.
 * - Return types: [generateKeypair] returns a [KeyHandle], while the Rust trait's returns its
 *   `u64` `KeyHandle` and the UniFFI callback's `generate_keypair` returns a `String` key ID.
 *   [destroyKey] returns a [DestructionAttestation], while both Rust declarations return
 *   nothing. The pseudonym methods return a [PseudonymKeyHandle], while the Rust trait returns
 *   a `PseudonymKeypair` and the UniFFI callback returns bytes. [sign], [publicKey] and
 *   [dhAgree] return a [ByteArray], as the UniFFI callback's methods return bytes, while the
 *   Rust trait returns a `Signature`, a `PublicKey` and a `SharedSecret`.
 * - Synchrony: its methods are synchronous. Every method of both Rust declarations is `async`
 *   except `custody_type`, which is synchronous in both.
 * - Errors: its methods throw this file's [ScpException]. The UniFFI callback declares
 *   `ScpError`, which UniFFI generates in Kotlin as `uniffi.scp.ScpException`, a different
 *   class, and the Rust trait returns a `PlatformError`. ADR-027 states that a UniFFI callback
 *   that throws any exception other than the generated one panics the Rust caller.
 *
 * [AndroidKeyCustody] converts no exception to [ScpException]. Each method throws [ScpException]
 * only for the codes its `@throws` lines name, and every other failure escapes as the original
 * throwable, so a `catch (e: ScpException)` does not catch it. The Keystore path, which an
 * Ed25519 [generateKeypair] takes on API 33+ and each other method below takes for a
 * [CustodyType.HARDWARE] handle, can let these escape:
 *
 * - [generateKeypair]: `KeyPairGenerator.getInstance` throws `NoSuchAlgorithmException` or
 *   `NoSuchProviderException`, `initialize` throws `InvalidAlgorithmParameterException`, and
 *   `generateKeyPair` throws `ProviderException` when Keystore fails to generate the key.
 * - [sign], [derivePseudonym] and [deriveRotatablePseudonym], which sign through Keystore to
 *   derive the pseudonym secret: `KeyStore.getInstance` throws `KeyStoreException`,
 *   `KeyStore.load` throws `IOException`, `NoSuchAlgorithmException` or `CertificateException`,
 *   `KeyStore.getEntry` throws `KeyStoreException`, `NoSuchAlgorithmException` or
 *   `UnrecoverableEntryException`, `Signature.getInstance` throws `NoSuchAlgorithmException`,
 *   `Signature.initSign` throws `InvalidKeyException`, and `Signature.sign` throws
 *   `SignatureException`.
 * - [publicKey]: the same `KeyStore.getInstance`, `KeyStore.load` and `KeyStore.getEntry`
 *   exceptions, and `IllegalStateException` when the encoded public key is not the 44-byte
 *   X.509 Ed25519 SubjectPublicKeyInfo.
 * - [destroyKey]: the same `KeyStore.getInstance` and `KeyStore.load` exceptions, and
 *   `KeyStoreException` from `containsAlias` and `deleteEntry`.
 *
 * [dhAgree] and [exportSigningKeyBytes] do not reach Keystore. [dhAgree] still lets one
 * non-[ScpException] escape, and remote input causes it: [dhAgree] passes a 32-byte peer key to
 * Bouncy Castle with no point-order check, so a low-order peer key, such as 32 zero bytes, makes
 * Bouncy Castle throw `IllegalStateException` ("X25519 agreement failed") because the shared
 * secret is all zero.
 *
 * See ADR-006 for the platform abstraction design and ADR-027 for the Android adapter.
 */
interface KeyCustodyProvider {
    /**
     * Generate a new keypair of the specified type.
     *
     * Ed25519 keys may be Keystore keys ([CustodyType.HARDWARE], API 33+).
     * X25519 wrapping keys are always software-managed (Bouncy Castle) and held in process
     * memory only, which diverges from ADR-027's P-256 agreement key (see the interface KDoc).
     *
     * [AndroidKeyCustody] throws no [ScpException] from this method. A Keystore failure escapes
     * as the original exception, listed in the interface KDoc.
     *
     * @param keyType The type of key to generate.
     * @return An opaque [KeyHandle] referencing the generated key.
     */
    fun generateKeypair(keyType: KeyType): KeyHandle

    /**
     * Sign data with an Ed25519 key.
     *
     * @param keyHandle Handle to an Ed25519 key.
     * @param data The bytes to sign.
     * @return 64-byte Ed25519 signature.
     * @throws ScpException with code `SCP-CRYPTO-4001` if key not found.
     * @throws ScpException with code `SCP-CRYPTO-4003` if key is not Ed25519.
     */
    fun sign(keyHandle: KeyHandle, data: ByteArray): ByteArray

    /**
     * Return the raw public key bytes for a handle.
     *
     * Works for both Ed25519 (32 bytes) and X25519 (32 bytes) key handles.
     *
     * @param keyHandle Handle to any key type.
     * @return Raw public key bytes (32 bytes).
     * @throws ScpException with code `SCP-CRYPTO-4001` if key not found.
     */
    fun publicKey(keyHandle: KeyHandle): ByteArray

    /**
     * Destroy key material associated with a handle.
     *
     * After this call, operations with the same handle on the same [AndroidKeyCustody] instance
     * throw [ScpException] with code `SCP-CRYPTO-4001`, with two exceptions: [dhAgree] throws
     * `SCP-CRYPTO-4002`, or `SCP-CRYPTO-4003` when its peer key is not 32 bytes, because it
     * checks the peer key's length before any key lookup; and [exportSigningKeyBytes] on a
     * Keystore handle ([CustodyType.HARDWARE]) throws `SCP-CRYPTO-4005`, because it refuses on
     * [KeyHandle.custodyType] before any key lookup.
     * Each [AndroidKeyCustody] instance holds its own map of software keys and restores every
     * persisted software Ed25519 seed into it when constructed, so another instance in the same
     * process that already holds a software key keeps signing with it after this call. The
     * other direction also holds: an instance constructed before another instance generated a
     * software Ed25519 key does not hold that key, yet its destroyKey queues removal of the key's
     * persisted seed and then throws `SCP-CRYPTO-4001` because its own map lacks the key. The
     * instance that holds the key keeps signing with it until its process ends, and no process
     * started after the removal reaches disk restores it.
     * [AndroidKeyCustody] removes the persisted seed of a software Ed25519 key that
     * [generateKeypair] creates (API 26-32) with an asynchronous `apply()`, so a later process
     * can restore the key when this process dies before the removal reaches disk (see
     * [DestructionAttestation.confirmed]).
     *
     * @param keyHandle Handle to destroy.
     * @return A [DestructionAttestation] naming the destruction method, with
     *   [DestructionAttestation.confirmed] always `true`: a failed post-deletion check throws
     *   `SCP-CRYPTO-4004` instead.
     * @throws ScpException with code `SCP-CRYPTO-4001` if no key sits under the handle: for a
     *   Keystore handle, Keystore holds no alias `scp.key.<id>`; for a software handle, this
     *   instance's software key map holds no entry, and the persisted seed under the handle's ID
     *   is already queued for removal when this is thrown.
     * @throws ScpException with code `SCP-CRYPTO-4004` if destruction cannot be confirmed.
     */
    fun destroyKey(keyHandle: KeyHandle): DestructionAttestation

    /**
     * Perform X25519 Diffie-Hellman key agreement.
     *
     * Returns the 32-byte shared secret. No method of this interface returns the X25519 private
     * key: [exportSigningKeyBytes] throws `SCP-CRYPTO-4003` for an X25519 handle. See
     * [AndroidKeyCustody.dhAgree] for where the software implementation holds the key.
     *
     * @param keyHandle Handle to an X25519 key.
     * @param peerPublic 32-byte X25519 public key of the peer.
     * @return 32-byte X25519 shared secret.
     * @throws ScpException with code `SCP-CRYPTO-4002` if [peerPublic] is 32 bytes long and no
     *   software key sits under [keyHandle]: a destroyed or unknown handle, or a Keystore
     *   Ed25519 handle.
     * @throws ScpException with code `SCP-CRYPTO-4003` if [peerPublic] is not 32 bytes long,
     *   checked before any key lookup, or [keyHandle] names a software Ed25519 key.
     * @throws IllegalStateException from Bouncy Castle ("X25519 agreement failed") if
     *   [peerPublic] is 32 bytes long but a low-order point, such as 32 zero bytes, which makes
     *   the shared secret all zero. No point order is checked, so a `catch (e: ScpException)`
     *   does not catch it.
     */
    fun dhAgree(keyHandle: KeyHandle, peerPublic: ByteArray): ByteArray

    /**
     * Derive a deterministic, context-scoped pseudonym keypair.
     *
     * Shipped algorithm. The HMAC key is a private-derived `pseudonym_secret`, NEVER the
     * public key (public-key keying would be a membership-enumeration oracle):
     *   1. `seed = HMAC-SHA256(pseudonym_secret, contextId || "scp-pseudonym")`
     *   2. `pseudonym_keypair = Ed25519_keygen(seed[0..32])`  // RFC-8032 seed
     *
     * Software custody: `pseudonym_secret = HKDF-SHA256(ed25519_private_seed,
     * salt="scp-pseudonym-secret-v1")`. This Ed25519 derivation diverges from spec §9.10.4
     * and §9.10.4.A and from ADR-027 acceptance criterion 6, which key the software
     * `pseudonym_secret` on the P-256 private scalar and turn `seed` into a P-256 keypair
     * through the FIPS 186-5 Appendix A.2.1 seed-to-scalar step. Android software pseudonyms
     * therefore do not match the spec §25.19 known-answer vectors. Story SCP-110 tracks the
     * move to P-256. Keystore
     * custody ([CustodyType.HARDWARE]): [AndroidKeyCustody] computes
     * `pseudonym_secret = SHA-256(sign(keyHandle, "scp-pseudonym-secret-v1"))`.
     * [sign] returns that signature to any caller holding the custody object, so
     * such a caller can recompute every pseudonym; the secret does not stay inside
     * Keystore. This diverges from ADR-027 acceptance criterion 6, which makes the
     * secret a symmetric key generated inside the secure boundary.
     *
     * @param keyHandle Handle to the identity Ed25519 key.
     * @param contextId Raw context ID bytes.
     * @return A [PseudonymKeyHandle] to the derived signing key.
     * @throws ScpException with code `SCP-CRYPTO-4001` if key not found.
     * @throws ScpException with code `SCP-CRYPTO-4003` if key is not Ed25519.
     */
    fun derivePseudonym(keyHandle: KeyHandle, contextId: ByteArray): PseudonymKeyHandle

    /**
     * Derive a deterministic, context-scoped, epoch-rotatable pseudonym keypair.
     *
     * Identical to [derivePseudonym] except the per-epoch domain separator and the
     * big-endian epoch counter are mixed into the HMAC body, so each epoch yields an
     * independent, unlinkable pseudonym for the same identity and context (spec
     * §9.10.4.A). The HMAC key is the private-derived `pseudonym_secret`, NEVER the
     * public key (public-key keying would be a membership-enumeration oracle). Shipped
     * algorithm:
     *   1. `seed = HMAC-SHA256(pseudonym_secret, contextId || BE64(epoch) || "scp-pseudonym-v2")`
     *   2. `pseudonym_keypair = Ed25519_keygen(seed[0..32])`  // RFC-8032 seed
     *
     * The `"scp-pseudonym-v2"` domain separator differs from v1's `"scp-pseudonym"`,
     * so v2 at any epoch never collides with the v1 [derivePseudonym] output.
     *
     * Software custody: `pseudonym_secret = HKDF-SHA256(ed25519_private_seed,
     * salt="scp-pseudonym-secret-v1")`. This Ed25519 derivation diverges from spec §9.10.4.A,
     * which keys the software `pseudonym_secret` on the P-256 private scalar and turns `seed`
     * into a P-256 keypair through the seed-to-scalar step of §9.10.4 (FIPS 186-5 Appendix
     * A.2.1), so Android software pseudonyms do not match the spec §25.19 known-answer vectors.
     * Story SCP-110 tracks the move to P-256. Keystore
     * custody ([CustodyType.HARDWARE]): [AndroidKeyCustody] computes
     * `pseudonym_secret = SHA-256(sign(keyHandle, "scp-pseudonym-secret-v1"))`.
     * [sign] returns that signature to any caller holding the custody object, so
     * such a caller can recompute every pseudonym; the secret does not stay inside
     * Keystore. This diverges from ADR-027 acceptance criterion 6, which makes the
     * secret a symmetric key generated inside the secure boundary.
     *
     * @param keyHandle Handle to the identity Ed25519 key.
     * @param contextId Raw context ID bytes.
     * @param pseudonymEpoch Rotation epoch counter, mixed in as a big-endian u64.
     * @return A [PseudonymKeyHandle] to the derived signing key.
     * @throws ScpException with code `SCP-CRYPTO-4001` if key not found.
     * @throws ScpException with code `SCP-CRYPTO-4003` if key is not Ed25519.
     */
    fun deriveRotatablePseudonym(
        keyHandle: KeyHandle,
        contextId: ByteArray,
        pseudonymEpoch: Long,
    ): PseudonymKeyHandle

    /**
     * Export the raw Ed25519 private key bytes (32 bytes) for a key handle.
     *
     * A software-backed key ([CustodyType.SOFTWARE]) exports its 32-byte seed. Keystore keys
     * ([CustodyType.HARDWARE]) are non-extractable, so the method MUST throw `SCP-CRYPTO-4005`
     * for a Keystore handle. The refusal covers every use of the key bytes, not one caller:
     * its message states that Keystore keys are non-extractable and that ADR-063's curve
     * slice, which removes every key-export accessor, has not landed.
     *
     * ADR-063's curve slice requires every core function that takes a raw signing key to
     * take a signer instead, and every key-export accessor, this method included, to leave
     * the custody adapters and all three bridges. That slice has not landed, so this method
     * still exports the seed of a software key. ADR-027 acceptance criterion 14 (private key
     * isolation) says the Rust engine receives only signatures and public keys, never private
     * key material, and the UniFFI `KeyCustodyProvider` callback's `export_signing_key_bytes`
     * would carry this seed to Rust, so this method's design diverges from criterion 14.
     *
     * @param keyHandle Handle to an Ed25519 key.
     * @return 32-byte raw Ed25519 private key bytes.
     * @throws ScpException with code `SCP-CRYPTO-4001` if the handle is a software handle
     *   and no software key is found under it.
     * @throws ScpException with code `SCP-CRYPTO-4003` if key is not Ed25519.
     * @throws ScpException with code `SCP-CRYPTO-4005` if the handle is a Keystore handle
     *   ([CustodyType.HARDWARE]), checked before any key lookup, so a destroyed or unknown
     *   Keystore handle also gets this code (Keystore keys are non-extractable).
     */
    fun exportSigningKeyBytes(keyHandle: KeyHandle): ByteArray
}

/**
 * Platform trait for encrypted key-value storage.
 *
 * Abstracts persistent, encrypted storage behind a uniform interface. The Android
 * implementation ([AndroidStorage]) uses SQLCipher with a 32-byte passphrase derived from an
 * AES-256 key that Android Keystore holds; SQLCipher derives the database key from that
 * passphrase. The adapter does not read `KeyInfo.securityLevel`, so it does not know whether
 * Keystore put the AES key in the TEE or in software.
 *
 * This interface declares the six methods of the UniFFI `StorageProvider` callback interface in
 * `crates/scp-ffi/uniffi/src/lib.rs` under the same names. The Rust `Storage` trait in
 * `crates/scp-platform/src/traits.rs` declares the same six operations but names `set` and
 * `get` as `store` and `retrieve`. The methods of this interface are synchronous, while every
 * method of both Rust declarations is `async`. [deletePrefix] returns a signed `Long`, while
 * both Rust declarations return a `u64`, which UniFFI generates in Kotlin as `ULong`. The
 * methods throw this file's [ScpException], while the callback declares `ScpError`, which
 * UniFFI generates in Kotlin as `uniffi.scp.ScpException`, a different class, and the Rust
 * trait returns a `PlatformError`. ADR-027 states that a UniFFI callback that throws any
 * exception other than the generated one panics the Rust caller.
 *
 * [AndroidStorage] opens its database on the first method call and retries the open on every
 * call until one succeeds, so each method can also throw an open failure, in one of three forms:
 * - `SCP-STORAGE-8003` when the Keystore key or the passphrase derivation throws a
 *   `GeneralSecurityException`.
 * - `SCP-STORAGE-8002` when opening the database throws an `android.database.SQLException` or
 *   an `IllegalStateException`.
 * - the original non-[ScpException] throwable for every other open failure, for example the
 *   `UnsatisfiedLinkError` from loading the SQLCipher library, the `IOException` from
 *   `KeyStore.load`, or a `ProviderException` from Keystore key generation. A caller that
 *   catches only [ScpException] does not catch these.
 *
 * The class KDoc of [AndroidStorage] lists the same cases.
 *
 * All keys are UTF-8 strings. Values are opaque byte arrays. Keys are unique — storing
 * a value with an existing key replaces the previous value.
 *
 * See ADR-006 for the platform abstraction design and ADR-027 for the Android adapter.
 */
interface StorageProvider {
    /**
     * Store a key-value pair, replacing any existing value for the key.
     *
     * Named `set` to match the UniFFI `StorageProvider` callback interface.
     *
     * @param key The storage key (UTF-8 string).
     * @param data The value to store (opaque bytes).
     * @throws ScpException with code `SCP-STORAGE-8002` if the store operation fails.
     * @throws ScpException with code `SCP-STORAGE-8003` if [AndroidStorage] cannot open its
     *   database because the Keystore key or the passphrase derivation throws a
     *   `GeneralSecurityException`. Other open failures are listed on [StorageProvider].
     */
    fun set(key: String, data: ByteArray)

    /**
     * Retrieve the value associated with a key.
     *
     * Named `get` to match the UniFFI `StorageProvider` callback interface.
     *
     * @param key The storage key to look up.
     * @return The stored bytes, or `null` if the key does not exist.
     * @throws ScpException with code `SCP-STORAGE-8002` if the read operation fails.
     * @throws ScpException with code `SCP-STORAGE-8003` if [AndroidStorage] cannot open its
     *   database because the Keystore key or the passphrase derivation throws a
     *   `GeneralSecurityException`. Other open failures are listed on [StorageProvider].
     */
    fun get(key: String): ByteArray?

    /**
     * Delete the value associated with a key.
     *
     * Deleting a non-existent key is a no-op (no exception thrown).
     *
     * @param key The storage key to delete.
     * @throws ScpException with code `SCP-STORAGE-8002` if the delete operation fails.
     * @throws ScpException with code `SCP-STORAGE-8003` if [AndroidStorage] cannot open its
     *   database because the Keystore key or the passphrase derivation throws a
     *   `GeneralSecurityException`. Other open failures are listed on [StorageProvider].
     */
    fun delete(key: String)

    /**
     * List all keys matching a prefix, in lexicographic order.
     *
     * Lexicographic ordering is required for KeyPackage buffer management
     * and event log range queries. An empty prefix returns all keys.
     *
     * @param prefix The key prefix to match. Use `""` for all keys.
     * @return Keys matching the prefix, sorted in ascending lexicographic order.
     * @throws ScpException with code `SCP-STORAGE-8002` if the list operation fails.
     * @throws ScpException with code `SCP-STORAGE-8003` if [AndroidStorage] cannot open its
     *   database because the Keystore key or the passphrase derivation throws a
     *   `GeneralSecurityException`. Other open failures are listed on [StorageProvider].
     */
    fun listKeys(prefix: String): List<String>

    /**
     * Delete all keys matching a prefix.
     *
     * @param prefix The key prefix to match.
     * @return The number of keys deleted.
     * @throws ScpException with code `SCP-STORAGE-8002` if the delete operation fails.
     * @throws ScpException with code `SCP-STORAGE-8003` if [AndroidStorage] cannot open its
     *   database because the Keystore key or the passphrase derivation throws a
     *   `GeneralSecurityException`. Other open failures are listed on [StorageProvider].
     */
    fun deletePrefix(prefix: String): Long

    /**
     * Check whether a key exists in storage.
     *
     * @param key The storage key to check.
     * @return `true` if the key exists, `false` otherwise.
     * @throws ScpException with code `SCP-STORAGE-8002` if the check operation fails.
     * @throws ScpException with code `SCP-STORAGE-8003` if [AndroidStorage] cannot open its
     *   database because the Keystore key or the passphrase derivation throws a
     *   `GeneralSecurityException`. Other open failures are listed on [StorageProvider].
     */
    fun exists(key: String): Boolean
}
