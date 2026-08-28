// PlatformAdapter.kt — Android platform adapter factory (ADR-027)
//
// Assembles all four Android platform providers (KeyCustody, DeviceAttestation,
// PushProvider, Storage) into a single adapter object. No custody string selects
// it: the UniFFI bridge answers "platform" with SCP-IDENT-1003, and a caller
// reaches Android Keystore by injecting a KeyCustodyProvider through
// SCP.identityCreateWithCustody.
//
// Provenance: ADR-027 (Android Platform Adapter), ADR-006 (Platform Abstraction Layer).

package works.limn.scp.android.platform

import android.content.Context

/**
 * Assembled Android platform adapter holding all four provider implementations.
 *
 * Created by [AndroidPlatformAdapter.make] and passed to the Rust engine via
 * UniFFI at SDK initialization time. Each provider implements the corresponding
 * UniFFI callback interface defined in `crates/scp-ffi/uniffi/src/bridge.rs`.
 *
 * @property keyCustody Android Keystore key management (TEE-backed Ed25519 on API 33+).
 * @property deviceAttestation Play Integrity Standard API device attestation.
 * @property push Firebase Cloud Messaging with opaque data-only payloads.
 * @property storage SQLCipher encrypted storage with TEE-derived AES-256 key.
 */
data class AndroidPlatformAdapterImpl(
    val keyCustody: KeyCustodyProvider,
    val deviceAttestation: DeviceAttestationProvider,
    val push: PushProvider,
    val storage: StorageProvider,
)

/**
 * Factory for constructing the complete Android platform adapter.
 *
 * Assembles the four platform providers ([AndroidKeyCustody],
 * [AndroidDeviceAttestation], [AndroidPushProvider], [AndroidStorage]) using
 * the provided Android [Context]. The returned [AndroidPlatformAdapterImpl] is
 * passed to `NativeLib.scpCreate()` to inject platform capabilities into the
 * Rust engine.
 *
 * ## Usage
 *
 * ```kotlin
 * val adapter = AndroidPlatformAdapter.make(applicationContext)
 * val scp = NativeLib.scpCreate(adapter)
 * ```
 *
 * ## Provider construction
 *
 * - [AndroidKeyCustody] requires context for EncryptedSharedPreferences access (#119).
 * - [AndroidDeviceAttestation] requires context for Play Integrity API access.
 * - [AndroidPushProvider] requires context for FCM token retrieval.
 * - [AndroidStorage] requires context for database file and Keystore access.
 *
 * See ADR-027 in `.docs/adrs/phase-6.md` for the full design rationale.
 */
object AndroidPlatformAdapter {

    /**
     * Constructs and returns a complete Android platform adapter.
     *
     * @param context Android application context. Must be an application context
     *   (not an activity context) to avoid memory leaks from long-lived references.
     * @return [AndroidPlatformAdapterImpl] with all four providers initialized.
     */
    fun make(context: Context): AndroidPlatformAdapterImpl {
        return AndroidPlatformAdapterImpl(
            keyCustody = AndroidKeyCustody(context),
            deviceAttestation = AndroidDeviceAttestation(context),
            push = AndroidPushProvider(context),
            storage = AndroidStorage(context),
        )
    }
}
