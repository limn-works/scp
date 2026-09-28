// PlatformAdapter.kt — Android platform adapter factory (ADR-027)
//
// Assembles all four Android platform providers (KeyCustody, DeviceAttestation,
// PushProvider, Storage) into a single adapter object. No code in the Kotlin SDKs calls
// the factory, and no code passes the adapter to the Rust engine.
//
// Provenance: ADR-027 (Android Platform Adapter), ADR-006 (Platform Abstraction Layer).

package works.limn.scp.android.platform

import android.content.Context

/**
 * Assembled Android platform adapter holding all four provider implementations.
 *
 * Created by [AndroidPlatformAdapter.make]. Each provider implements a Kotlin interface in
 * `Types.kt`, and each interface's KDoc states how it differs from the Rust trait and from the
 * UniFFI callback interface in `crates/scp-ffi/uniffi/src/lib.rs`. No code passes this
 * adapter to the Rust engine yet, because the `Types.kt` interfaces are not the
 * UniFFI-generated callback interfaces of the `uniffi.scp` package.
 *
 * @property keyCustody Android Keystore key management (TEE-backed Ed25519 on API 33+).
 * @property deviceAttestation Play Integrity device attestation, which requests a Classic
 *   token today; story SCP-111 tracks the Standard request ADR-027 requires.
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
 * the provided Android [Context]. No code passes the returned
 * [AndroidPlatformAdapterImpl] to the Rust engine: its providers implement the Kotlin
 * interfaces in `Types.kt`, and `SCP.identityCreateWithCustody` in `scp-kt` takes the
 * UniFFI-generated `uniffi.scp.KeyCustodyProvider`, so it cannot accept them.
 *
 * ## Provider construction
 *
 * - [AndroidKeyCustody] requires context for EncryptedSharedPreferences access.
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
