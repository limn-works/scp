// Types.kt — Supporting types for Android platform adapters (ADR-027)
//
// These types are the Kotlin-side contract of the Android adapters. Each interface's KDoc states
// how it differs from the Rust `scp-platform` trait (crates/scp-platform/src/traits.rs) and from
// the UniFFI callback interface (crates/scp-ffi/uniffi/src/lib.rs) for the same capability. The
// UniFFI bridge has no function that accepts a storage, push or device attestation provider, so
// no code passes those adapters to the Rust engine. `SCP.identityCreateWithCustody` in `scp-kt`
// accepts the UniFFI-generated `uniffi.scp.KeyCustodyProvider`, which these interfaces are not;
// [UniffiKeyCustody] implements it over [AndroidKeyCustody]. ADR-021 (the UniFFI bridge) and
// ADR-027 require each Android adapter to implement its UniFFI callback interface and to be
// injected into the Rust engine, so the storage, push and device attestation interfaces diverge
// from both ADRs. Stories SCP-110 to
// SCP-113 of `.docs/prds/main.json` stay in progress while any acceptance criterion their
// descriptions record as unmet stands; each adapter's trait criterion is one of them. Story
// SCP-214 tracks injecting a key custody provider into the Rust engine.
//
// Provenance: ADR-027 (Android Platform Adapter), ADR-006 (Platform Abstraction Layer),
// ADR-025 (Apple Platform Adapter — parallel reference).

package works.limn.scp.android.platform

/**
 * The type of cryptographic key managed by a [KeyHandle], one per UniFFI `CustodyKeyType`.
 *
 * @property wire The host key-type name the bridge parses (`KeyType::parse`).
 */
enum class KeyType(val wire: String) {
    /** Ed25519 signing key (identity keys, active signing keys). */
    ED25519("ed25519"),

    /** P-256 signing key: signs a 32-byte digest and returns DER (spec 09 §9.5). */
    P256("p256"),

    /** P-256 agreement key for DHKEM(P-256) HPKE (spec 09 §9.5, RFC 9180 §7.1). */
    HPKE_P256("hpke-p256"),

    /**
     * P-256 key-event key: signs only the 32-byte digests of key-event-log changes and custody
     * probes and returns DER (spec 09 §9.7.4.1, SCP-345). Recorded as its own type, so it never
     * signs as a [P256] key after a restart.
     */
    P256_KEY_EVENT("p256-key-event"),
    ;

    /** Whether this type is an ECDSA P-256 key, signing or key event, held in Keystore. */
    val isP256Ecdsa: Boolean get() = this == P256 || this == P256_KEY_EVENT
}

/**
 * The role a key was minted in, recorded by [AndroidKeyCustody] for the key's lifetime.
 *
 * Mirrors the UniFFI `CustodyKeyRole`: the bridge names the role when it generates a key
 * and reads it back from `getPublicKey`, binding a key it has not seen as an identity only
 * when the reported role is [IDENTITY] (`crates/scp-ffi/uniffi/src/lib.rs`).
 */
enum class KeyRole {
    /** The participant's identity key, the only pseudonym-derivation source. */
    IDENTITY,

    /** Any other key. */
    OPERATIONAL,
}

/**
 * The custody type for a given key, indicating where the key material is stored
 * and how it is protected.
 *
 * See ADR-006 for the custody model. For a P-256 or HPKE P-256 key, [AndroidKeyCustody]
 * records the custody class when it mints the key, from the security level Keystore's
 * `KeyInfo` reports, and reports the recorded class. For an Ed25519 key it reports
 * [HARDWARE] for a Keystore key and [SOFTWARE] for a Bouncy Castle key. No Android adapter
 * reports [IN_MEMORY] for a key it holds; [UniffiKeyCustody] reports `"in_memory"` for an id
 * it does not hold, the weakest class the bridge reads.
 */
enum class CustodyType {
    /**
     * Key material is stored in memory only. No Android adapter reports this value; it
     * matches the Rust in-memory testing adapter of ADR-006.
     */
    IN_MEMORY,

    /**
     * Key material is held by Android Keystore in secure hardware, which does not hand the
     * private bytes to the app. A P-256 or HPKE P-256 key reports this value only when
     * `KeyInfo` places it in the TEE, in StrongBox, or at an unknown secure level. A Keystore
     * Ed25519 key reports it without [AndroidKeyCustody] reading `KeyInfo`, so for that key the
     * value does not show whether Keystore put it in the TEE or, on a device whose KeyMint runs
     * in software, in software.
     */
    HARDWARE,

    /**
     * Key material is held in software: by Bouncy Castle in the app process, or by a Keystore
     * whose `KeyInfo` reports a software security level (an emulator, or a device whose KeyMint
     * runs in software). [AndroidKeyCustody] commits the private key seed of each software
     * Ed25519 key it generates (API 26-32) and the private scalar of each software HPKE P-256
     * key (API 26-30) to an on-disk EncryptedSharedPreferences file.
     */
    SOFTWARE,
}

/**
 * Opaque handle to a cryptographic key managed by a [KeyCustodyProvider] implementation.
 *
 * @property id Unique identifier for the key. For Android Keystore keys, this maps to
 *   alias `scp.key.$id`. For software keys, this maps to an in-memory entry and, for a
 *   software Ed25519 key that [KeyCustodyProvider.generateKeypair] creates (API 26-32), also to
 *   the EncryptedSharedPreferences entry `scp.ed25519.$id`; for a software HPKE P-256 key
 *   (API 26-30), to the entry `scp.p256.$id`. A P-256 or HPKE P-256 key also has the record
 *   `scp.keymeta.$id`, which names its type, its store, its custody class and its role.
 * @property custodyType The custody class: for a P-256 or HPKE P-256 key, the class recorded
 *   at mint; otherwise [CustodyType.HARDWARE] for Keystore and [CustodyType.SOFTWARE] for
 *   Bouncy Castle. [AndroidKeyCustody] routes a P-256 or HPKE P-256 key by its record, never
 *   by this field.
 */
data class KeyHandle(
    val id: String,
    val custodyType: CustodyType,
)

/**
 * Attestation that a key has been destroyed.
 *
 * [AndroidKeyCustody] reports [DestructionMethod.SOFTWARE_ONLY] for every key, Keystore keys
 * included: Keystore issues no proof that it destroyed a key, and section 9.15 rates a
 * destruction without a verified platform proof as software-only (ADR-027 criterion 4).
 *
 * See section 9.15 of the SCP specification for key destruction requirements.
 *
 * @property method The mechanism by which key material was destroyed.
 * @property confirmed Always `true` in an attestation [AndroidKeyCustody] returns: it confirms
 *   each deletion by re-fetch and throws [ScpException] with code `SCP-CRYPTO-4060` when one is
 *   not confirmed, so it never returns `false`. For a Keystore key, the re-fetch asks Keystore
 *   whether it still holds the alias. For a persisted software key (a software Ed25519 seed or a
 *   software HPKE P-256 scalar), the removal is written with `commit()`, which returns after the
 *   write reaches disk, and the re-fetch reads the entry back.
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
     * Key material was deleted, with no platform proof of the destruction: from software
     * storage (the Bouncy Castle in-memory map and, for a persisted software key, its
     * EncryptedSharedPreferences entry, removed with `commit()`), or from Android Keystore,
     * which confirms only that it no longer holds the alias. Every destruction
     * [AndroidKeyCustody] performs reports this value.
     */
    SOFTWARE_ONLY,

    /**
     * Key material was destroyed in secure hardware that proved the destruction (section 9.15).
     * [AndroidKeyCustody] never reports it: Keystore issues no such proof.
     */
    HARDWARE,
}

/**
 * SCP-specific exception with structured error codes.
 *
 * Error codes follow the pattern `SCP-{DOMAIN}-{NUMBER}`:
 * - `SCP-CRYPTO-4006`: Key not found (a software or Keystore lookup, any key type, a P-256
 *   key whose mint has not settled, or a Keystore identity's pseudonym secret)
 * - `SCP-CRYPTO-4060`: Every other [KeyCustodyProvider] failure of [AndroidKeyCustody]: a key
 *   of the wrong type for the operation, an input of the wrong length or an invalid peer point,
 *   a deletion that cannot be confirmed, a preferences write that does not commit, and any
 *   Keystore, JCA or Bouncy Castle exception, carried as the cause. No other exception leaves
 *   an [AndroidKeyCustody] method.
 * - `SCP-TRANS-5080`: Wake payload invalid: the push payload has no `scp` field, or its
 *   `scp` field is not `"1"`
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
     * @throws ScpException if attestation fails.
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
     * @throws ScpException if assertion fails.
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
     * @throws ScpException with code `SCP-TRANS-5080` (wake payload invalid) if the payload
     *   has no `scp` field or its `scp` field is not `"1"`.
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
 * behind a uniform interface. The Android implementation ([AndroidKeyCustody]) holds Ed25519,
 * P-256 signing and HPKE P-256 keys (ADR-027):
 *
 * - P-256 signing keys in Android Keystore at every supported API level, signing the bridge's
 *   32-byte digest with `NONEwithECDSA` under a `DIGEST_NONE` key.
 * - HPKE P-256 agreement keys in Android Keystore (`PURPOSE_AGREE_KEY`) from API 31, and as a
 *   Bouncy Castle scalar committed to EncryptedSharedPreferences on API 26-30. The store is
 *   chosen by the API level alone, never by catching a failed Keystore create.
 * - Ed25519 keys in Android Keystore on API 33+ and in Bouncy Castle on API 26-32.
 *
 * Each P-256 and HPKE P-256 key has a record, committed when it is minted, that names its type,
 * its store and its custody class; every later operation on the key follows the record.

 * This interface matches neither Rust declaration. It is not the `scp-ffi-uniffi`
 * `KeyCustodyProvider` callback protocol, whose key ids are u64 strings; [UniffiKeyCustody]
 * implements that protocol over [AndroidKeyCustody], whose key ids are decimal u64 strings.
 *
 * - Method set: it declares the methods of the UniFFI `KeyCustodyProvider` callback interface in
 *   `crates/scp-ffi/uniffi/src/lib.rs` except `custody_type`, and it names the callback's
 *   `get_public_key` [publicKey], the name the Rust trait's `public_key` takes in Kotlin. The
 *   Rust `KeyCustody` trait in `crates/scp-platform/src/traits.rs` also declares
 *   `custody_type`, `import_ed25519_signing_key` and `generate_ephemeral_ed25519_seed`, which
 *   this interface lacks. No method of this interface
 *   returns a private key (ADR-027 acceptance criterion 14, private key isolation).
 * - Parameters: its methods name a key by a [KeyHandle], a data class of a `String` id and a
 *   [CustodyType]. The Rust trait's `KeyHandle` is a different type, an opaque `u64`, and the
 *   UniFFI callback's methods take a `String` key ID. [generateKeypair] takes a [KeyType] enum,
 *   as the Rust trait's takes a `KeyType` enum of the same key types (Ed25519, P-256 signing and
 *   HPKE P-256), while the UniFFI
 *   callback's takes a `String` key type. [deriveRotatablePseudonym] takes `pseudonymEpoch` as
 *   a signed `Long`, while both Rust declarations take a `u64`, which UniFFI generates in Kotlin
 *   as `ULong`.
 * - Return types: [generateKeypair] returns a [KeyHandle], while the Rust trait's returns its
 *   `u64` `KeyHandle` and the UniFFI callback's `generate_keypair` returns a `String` key ID.
 *   [destroyKey] returns a [DestructionAttestation], while both Rust declarations return
 *   nothing. The pseudonym methods return a [ByteArray] holding a 33-byte compressed P-256
 *   point, as the UniFFI callback returns bytes, while the Rust trait returns a `Pseudonym`.
 *   [sign], [publicKey] and
 *   [dhAgree] return a [ByteArray], as the UniFFI callback's methods return bytes, while the
 *   Rust trait returns a `Signature`, a `PublicKey` and a `SharedSecret`.
 * - Synchrony: its methods are synchronous. Every method of both Rust declarations is `async`
 *   except `custody_type`, which is synchronous in both.
 * - Errors: its methods throw this file's [ScpException]. The UniFFI callback declares
 *   `ScpError`, which UniFFI generates in Kotlin as `uniffi.scp.ScpException`, a different
 *   class, and the Rust trait returns a `PlatformError`. ADR-027 states that a UniFFI callback
 *   that throws any exception other than the generated one panics the Rust caller.
 *
 * [AndroidKeyCustody] throws [ScpException] and nothing else from every method of this
 * interface: `SCP-CRYPTO-4006` for a key it does not hold, and `SCP-CRYPTO-4060` for every
 * other failure, with the Keystore, JCA, Bouncy Castle or preferences exception as the cause.
 * Every write to EncryptedSharedPreferences uses `commit()`, and a write that does not commit
 * fails the call with `SCP-CRYPTO-4060`.
 *
 * See ADR-006 for the platform abstraction design and ADR-027 for the Android adapter.
 */
interface KeyCustodyProvider {
    /**
     * Generate a new keypair of the specified type, in the store the interface KDoc names.
     *
     * A P-256 or HPKE P-256 mint commits the key's record before it creates the key and settles
     * the record's custody class after. A mint that fails deletes what it created and its record;
     * when it cannot confirm the deletion it keeps the record and throws `SCP-CRYPTO-4060` naming
     * the key id, which [destroyKey] then removes.
     *
     * @param keyType The type of key to generate.
     * @return An opaque [KeyHandle] referencing the generated key.
     * @throws ScpException with code `SCP-CRYPTO-4060` if every key id drawn is taken, a
     *   preferences write does not commit, or the store fails to create the key.
     */
    fun generateKeypair(keyType: KeyType): KeyHandle

    /**
     * Sign data with an Ed25519 or P-256 signing key.
     *
     * @param keyHandle Handle to an Ed25519 or P-256 key.
     * @param data For an Ed25519 key, the message. For a P-256 key, the 32-byte digest the
     *   bridge computed (§9.5.1), signed as given with no second hash.
     * @return For an Ed25519 key, the 64-byte signature. For a P-256 key, the DER-encoded ECDSA
     *   signature Keystore produced; the bridge converts it to raw low-s and verifies it.
     * @throws ScpException with code `SCP-CRYPTO-4006` if key not found.
     * @throws ScpException with code `SCP-CRYPTO-4060` if the key is HPKE P-256, or
     *   a P-256 [data] is not 32 bytes.
     */
    fun sign(keyHandle: KeyHandle, data: ByteArray): ByteArray

    /**
     * Return the raw public key bytes for a handle.
     *
     * @param keyHandle Handle to any key type.
     * @return The raw 32-byte key (Ed25519), the 33-byte compressed SEC1 point (P-256),
     *   or the 65-byte uncompressed SEC1 point (HPKE P-256).
     * @throws ScpException with code `SCP-CRYPTO-4006` if key not found.
     */
    fun publicKey(keyHandle: KeyHandle): ByteArray

    /**
     * Destroy key material associated with a handle.
     *
     * Every deletion is confirmed by re-fetch: a Keystore alias by `containsAlias`, a persisted
     * software seed or scalar by reading the entry back after a `commit()` removal. After this
     * call, operations with the same handle throw [ScpException] with code `SCP-CRYPTO-4006`.
     * A P-256 or HPKE P-256 key's record is removed only after its key material is confirmed
     * gone, so a destroy that fails can be retried. A key whose mint never settled (a
     * `pending` record) and a Keystore alias `scp.key.<id>` with no record are destroyed too.
     *
     * Each [AndroidKeyCustody] instance keeps its own in-memory map of software keys, so another
     * instance in the same process that already loaded a software key keeps using it until that
     * instance is dropped; no instance constructed after this call loads it.
     *
     * No pseudonym key exists to destroy: once the identity (and, for a Keystore identity, its
     * pseudonym secret) is gone, deriving any of its pseudonyms fails with `SCP-CRYPTO-4006`
     * (`09-security-model.md` §9.10.4.A).
     *
     * @param keyHandle Handle to destroy.
     * @return A [DestructionAttestation] naming the destruction method, with
     *   [DestructionAttestation.confirmed] always `true`: an unconfirmed deletion throws
     *   `SCP-CRYPTO-4060` instead.
     * @throws ScpException with code `SCP-CRYPTO-4006` if no key sits under the handle (for a
     *   Keystore identity, any pseudonym secret left behind is deleted first).
     * @throws ScpException with code `SCP-CRYPTO-4060` if a deletion cannot be confirmed or a
     *   store fails.
     */
    fun destroyKey(keyHandle: KeyHandle): DestructionAttestation

    /**
     * Perform Diffie-Hellman key agreement with an HPKE P-256 key.
     *
     * No method of this interface returns the private key. The returned secret is a [ByteArray]
     * that [AndroidKeyCustody] does not wipe; the caller owns it.
     *
     * @param keyHandle Handle to an HPKE P-256 key. An Ed25519 or P-256 signing key never
     *   agrees.
     * @param peerPublic The peer's 65-byte uncompressed SEC1 point, checked on the curve before
     *   the key is used.
     * @return The 32-byte shared secret: the P-256 x-coordinate left-padded to 32 bytes.
     * @throws ScpException with code `SCP-CRYPTO-4006` if no key sits under [keyHandle].
     * @throws ScpException with code `SCP-CRYPTO-4060` for a key that never agrees, a
     *   [peerPublic] of the wrong length or off the curve.
     */
    fun dhAgree(keyHandle: KeyHandle, peerPublic: ByteArray): ByteArray

    /**
     * Derive a deterministic, context-scoped pseudonym and return its point.
     *
     * Shipped algorithm. The HMAC key is a private-derived `pseudonym_secret`, NEVER the
     * public key (public-key keying would be a membership-enumeration oracle):
     *   1. `seed = HMAC-SHA256(pseudonym_secret, contextId || "scp-pseudonym")`
     *   2. `d = HKDF-Expand-SHA256(seed, "SCP-PSEUDONYM-P256-V1", 48) mod (n - 1) + 1`;
     *      the pseudonym is the 33-byte compressed point `d * G`. No pseudonym key is
     *      stored, and none can sign.
     *
     * Software custody: `pseudonym_secret = HKDF-SHA256(ikm = ed25519_private_seed,
     * salt = "scp-pseudonym-secret-v1")`, the §9.10.4.A native interim until the identity key
     * moves to P-256 (story SCP-315); the steps after it match every other software custody
     * byte for byte (§25.19). Keystore custody ([CustodyType.HARDWARE]): `pseudonym_secret` is
     * a device-local HMAC-SHA256 key that [AndroidKeyCustody] generates inside Android Keystore
     * at [generateKeypair]. Keystore computes step 1, the secret never leaves it, and no
     * signature feeds it, so the pseudonym is device-local by design (not identical across
     * devices).
     *
     * The pseudonym dies with its identity (`09-security-model.md` §9.10.4.A): once
     * the identity is destroyed, the derivation fails with key-not-found
     * (`SCP-CRYPTO-4006`).
     *
     * @param keyHandle Handle to the identity Ed25519 key.
     * @param contextId Raw context ID bytes.
     * @return The 33-byte SEC1 compressed P-256 point.
     * @throws ScpException with code `SCP-CRYPTO-4006` if key not found.
     * @throws ScpException with code `SCP-CRYPTO-4060` if key is not Ed25519.
     */
    fun derivePseudonym(keyHandle: KeyHandle, contextId: ByteArray): ByteArray

    /**
     * Derive a deterministic, context-scoped, epoch-rotatable pseudonym and return its point.
     *
     * Identical to [derivePseudonym] except the per-epoch domain separator and the
     * big-endian epoch counter are mixed into the HMAC body, so each epoch yields an
     * independent, unlinkable pseudonym for the same identity and context (spec
     * §9.10.4.A). The HMAC key is the private-derived `pseudonym_secret`, NEVER the
     * public key (public-key keying would be a membership-enumeration oracle). Shipped
     * algorithm:
     *   1. `seed = HMAC-SHA256(pseudonym_secret, contextId || BE64(epoch) || "scp-pseudonym-v2")`
     *   2. `d = HKDF-Expand-SHA256(seed, "SCP-PSEUDONYM-P256-V1", 48) mod (n - 1) + 1`;
     *      the pseudonym is the 33-byte compressed point `d * G`. No pseudonym key is
     *      stored, and none can sign.
     *
     * The `"scp-pseudonym-v2"` domain separator differs from v1's `"scp-pseudonym"`,
     * so v2 at any epoch never collides with the v1 [derivePseudonym] output.
     *
     * Software custody: `pseudonym_secret = HKDF-SHA256(ikm = ed25519_private_seed,
     * salt = "scp-pseudonym-secret-v1")`, the §9.10.4.A native interim until the identity key
     * moves to P-256 (story SCP-315); the steps after it match every other software custody
     * byte for byte (§25.19). Keystore custody ([CustodyType.HARDWARE]): `pseudonym_secret` is
     * a device-local HMAC-SHA256 key that [AndroidKeyCustody] generates inside Android Keystore
     * at [generateKeypair]. Keystore computes step 1, the secret never leaves it, and no
     * signature feeds it, so the pseudonym is device-local by design (not identical across
     * devices).
     *
     * The pseudonym dies with its identity (`09-security-model.md` §9.10.4.A): once
     * the identity is destroyed, the derivation fails with key-not-found
     * (`SCP-CRYPTO-4006`).
     *
     * @param keyHandle Handle to the identity Ed25519 key.
     * @param contextId Raw context ID bytes.
     * @param pseudonymEpoch Rotation epoch counter, mixed in as a big-endian u64.
     * @return The 33-byte SEC1 compressed P-256 point.
     * @throws ScpException with code `SCP-CRYPTO-4006` if key not found.
     * @throws ScpException with code `SCP-CRYPTO-4060` if key is not Ed25519.
     */
    fun deriveRotatablePseudonym(
        keyHandle: KeyHandle,
        contextId: ByteArray,
        pseudonymEpoch: Long,
    ): ByteArray
}

/**
 * Platform trait for encrypted key-value storage.
 *
 * Abstracts persistent, encrypted storage behind a uniform interface. The Android
 * implementation ([AndroidStorage]) uses SQLCipher with a key derived as persistence spec §17.6
 * requires; [AndroidStorage] states the derivation.
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
