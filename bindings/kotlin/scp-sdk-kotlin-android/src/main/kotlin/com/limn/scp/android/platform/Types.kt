// Types.kt — Supporting types for Android platform adapters (ADR-027)
//
// These types mirror the Rust `scp-platform` trait signatures (crates/scp-platform/src/traits.rs)
// and the UniFFI callback interface contract (crates/scp-ffi/uniffi/src/bridge.rs). They will
// eventually be replaced by UniFFI-generated Kotlin types once the full FFI binding pipeline is
// wired. Until then, they serve as the Kotlin-side contract.
//
// Provenance: ADR-027 (Android Platform Adapter), ADR-006 (Platform Abstraction Layer),
// ADR-025 (Apple Platform Adapter — parallel reference).

package com.limn.scp.android.platform

/**
 * The type of cryptographic key managed by a [KeyHandle].
 *
 * See ADR-006: Ed25519 keys are used for identity and signing,
 * X25519 keys are used for key agreement (HPKE wrapping keys).
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
 * See ADR-006 for the custody model: production adapters use hardware-backed
 * custody, while the testing adapter uses [InMemory].
 */
enum class CustodyType {
    /** Key material is stored in memory only (testing adapter). */
    IN_MEMORY,

    /** Key material is protected by a hardware security module (Android Keystore TEE). */
    HARDWARE,

    /** Key material is stored in software (Bouncy Castle) but not in a hardware security module. */
    SOFTWARE,
}

/**
 * Opaque handle to a cryptographic key managed by a [KeyCustodyProvider] implementation.
 *
 * @property id Unique identifier for the key. For Android Keystore keys, this maps to
 *   alias `scp.key.$id`. For software keys, this maps to a [ConcurrentHashMap] entry.
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
 * identity key is hardware-backed. See ADR-006 for the derivation algorithm.
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
 * For Android Keystore-backed keys, [method] is [DestructionMethod.HARDWARE] because
 * the key material resides in the TEE and deletion removes it from hardware. For
 * software-backed keys, [method] is [DestructionMethod.SOFTWARE_ONLY].
 *
 * See section 9.15 of the SCP specification for key destruction requirements.
 *
 * @property method The mechanism by which key material was destroyed.
 * @property confirmed `true` when the post-deletion verification confirmed the key is gone.
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
    /** Key material was deleted from software storage (Bouncy Castle in-memory map). */
    SOFTWARE_ONLY,

    /** Key material was destroyed by the hardware security module (Android Keystore TEE). */
    HARDWARE,
}

/**
 * SCP-specific exception with structured error codes.
 *
 * Error codes follow the pattern `SCP-{DOMAIN}-{NUMBER}`:
 * - `SCP-CRYPTO-4001`: Ed25519 key not found
 * - `SCP-CRYPTO-4002`: X25519 key not found
 * - `SCP-CRYPTO-4003`: Wrong key type for operation
 * - `SCP-CRYPTO-4004`: Key destruction failed
 * - `SCP-CRYPTO-4005`: Cryptographic operation failed
 * - `SCP-STORAGE-6001`: Storage key not found
 * - `SCP-STORAGE-6002`: Storage operation failed
 * - `SCP-STORAGE-6003`: Storage encryption key derivation failed
 *
 * @property code Structured SCP error code.
 */
open class ScpException(
    message: String,
    val code: String,
) : Exception(message)

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
 * The Android implementation uses the Play Integrity Standard API.
 *
 * This interface mirrors the Rust `DeviceAttestation` trait in `scp-platform/src/traits.rs`.
 *
 * See ADR-006 for the platform abstraction design and ADR-027 for the Android adapter.
 */
interface DeviceAttestationProvider {
    /**
     * Generate an attestation token for the given challenge and device ID.
     *
     * @param challenge Server-issued random challenge bytes.
     * @param deviceId Stable device/identity identifier bytes.
     * @return Platform-specific attestation token bytes.
     * @throws ScpException if attestation fails.
     */
    suspend fun attest(challenge: ByteArray, deviceId: ByteArray): ByteArray

    /**
     * Generate a per-request assertion.
     *
     * @param requestHash SHA-256 hash of the request data being asserted.
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
 * This interface mirrors the Rust `Push` trait in `scp-platform/src/traits.rs`.
 *
 * See ADR-006 for the platform abstraction design and ADR-027 for the Android adapter.
 */
interface PushProvider {
    /**
     * Register for push notifications and return the platform-specific token.
     *
     * @return The push notification registration token string.
     * @throws ScpException if token retrieval fails.
     */
    suspend fun register(): String

    /**
     * Handle an incoming push notification payload and produce a wake signal.
     *
     * @param payload The push notification data payload as a key-value map.
     * @return [WakeSignal] indicating the action the engine should take.
     * @throws ScpException if the payload is invalid.
     */
    fun handleNotification(payload: Map<String, String>): WakeSignal
}

/**
 * Platform trait for cryptographic key custody.
 *
 * Abstracts key generation, signing, key agreement, and pseudonym derivation
 * behind a uniform interface. The Android implementation ([AndroidKeyCustody])
 * uses Android Keystore for TEE-backed Ed25519 on API 33+ and Bouncy Castle
 * for software fallback on API 26-32.
 *
 * This interface mirrors the Rust `KeyCustody` trait in `scp-platform/src/traits.rs`
 * and the UniFFI `KeyCustodyProvider` callback interface in `scp-ffi/uniffi/src/bridge.rs`.
 *
 * See ADR-006 for the platform abstraction design and ADR-027 for the Android adapter.
 */
interface KeyCustodyProvider {
    /**
     * Generate a new keypair of the specified type.
     *
     * Ed25519 keys may be hardware-backed (Android Keystore TEE on API 33+).
     * X25519 wrapping keys are always software-managed (Bouncy Castle).
     *
     * @param keyType The type of key to generate.
     * @return An opaque [KeyHandle] referencing the generated key.
     * @throws ScpException if key generation fails.
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
     * After this call, all subsequent operations with the same handle will
     * throw [ScpException] with code `SCP-CRYPTO-4001`.
     *
     * @param keyHandle Handle to destroy.
     * @return A [DestructionAttestation] confirming the destruction.
     * @throws ScpException with code `SCP-CRYPTO-4001` if the handle is already invalid.
     * @throws ScpException with code `SCP-CRYPTO-4004` if destruction cannot be confirmed.
     */
    fun destroyKey(keyHandle: KeyHandle): DestructionAttestation

    /**
     * Perform X25519 Diffie-Hellman key agreement.
     *
     * Returns the 32-byte shared secret. The private key never leaves the
     * custody boundary.
     *
     * @param keyHandle Handle to an X25519 key.
     * @param peerPublic 32-byte X25519 public key of the peer.
     * @return 32-byte X25519 shared secret.
     * @throws ScpException with code `SCP-CRYPTO-4002` if X25519 key not found.
     */
    fun dhAgree(keyHandle: KeyHandle, peerPublic: ByteArray): ByteArray

    /**
     * Derive a deterministic, context-scoped pseudonym keypair.
     *
     * Algorithm (all implementations MUST produce identical output):
     *   1. `seed = HMAC-SHA256(identity_key_material, contextId || "scp-pseudonym")`
     *   2. `pseudonym_keypair = Ed25519_keygen(seed[0..32])`
     *
     * @param keyHandle Handle to the identity Ed25519 key.
     * @param contextId Raw context ID bytes.
     * @return A [PseudonymKeyHandle] to the derived signing key.
     * @throws ScpException with code `SCP-CRYPTO-4001` if key not found.
     * @throws ScpException with code `SCP-CRYPTO-4003` if key is not Ed25519.
     */
    fun derivePseudonym(keyHandle: KeyHandle, contextId: ByteArray): PseudonymKeyHandle
}

/**
 * Platform trait for encrypted key-value storage.
 *
 * Abstracts persistent, encrypted storage behind a uniform interface. The Android
 * implementation ([AndroidStorage]) uses SQLCipher with a TEE-derived AES-256
 * encryption key stored in Android Keystore.
 *
 * This interface mirrors the Rust `Storage` trait in `scp-platform/src/traits.rs`
 * and the UniFFI `StorageProvider` callback interface in `scp-ffi/uniffi/src/bridge.rs`.
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
     * @param key The storage key (UTF-8 string).
     * @param data The value to store (opaque bytes).
     * @throws ScpException with code `SCP-STORAGE-6002` if the store operation fails.
     */
    fun store(key: String, data: ByteArray)

    /**
     * Retrieve the value associated with a key.
     *
     * @param key The storage key to look up.
     * @return The stored bytes, or `null` if the key does not exist.
     * @throws ScpException with code `SCP-STORAGE-6002` if the read operation fails.
     */
    fun retrieve(key: String): ByteArray?

    /**
     * Delete the value associated with a key.
     *
     * Deleting a non-existent key is a no-op (no exception thrown).
     *
     * @param key The storage key to delete.
     * @throws ScpException with code `SCP-STORAGE-6002` if the delete operation fails.
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
     * @throws ScpException with code `SCP-STORAGE-6002` if the list operation fails.
     */
    fun listKeys(prefix: String): List<String>

    /**
     * Delete all keys matching a prefix.
     *
     * @param prefix The key prefix to match.
     * @return The number of keys deleted.
     * @throws ScpException with code `SCP-STORAGE-6002` if the delete operation fails.
     */
    fun deletePrefix(prefix: String): Long

    /**
     * Check whether a key exists in storage.
     *
     * @param key The storage key to check.
     * @return `true` if the key exists, `false` otherwise.
     * @throws ScpException with code `SCP-STORAGE-6002` if the check operation fails.
     */
    fun exists(key: String): Boolean
}
