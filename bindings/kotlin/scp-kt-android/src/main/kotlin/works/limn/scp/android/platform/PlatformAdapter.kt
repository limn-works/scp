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
 * adapter to the Rust engine yet. The UniFFI bridge has no function that accepts a storage,
 * push or device attestation provider, and `SCP.identityCreateWithCustody` in `scp-kt`
 * accepts only the UniFFI-generated `uniffi.scp.KeyCustodyProvider`, which [keyCustody]
 * does not implement.
 *
 * @property keyCustody Android Keystore key management (Keystore-held Ed25519 on API 33+ today,
 *   reported as [CustodyType.HARDWARE] without a `KeyInfo.securityLevel` check; ADR-027
 *   requires P-256 at every supported API level, and no story tracks that move yet).
 * @property deviceAttestation Play Integrity device attestation, which requests a Classic
 *   token today; story SCP-111 tracks the Standard request ADR-027 requires.
 * @property push Firebase Cloud Messaging; checks only the `scp` wake field of a data-only
 *   payload and does not enforce the opaque payload §10.7 defines.
 * @property storage SQLCipher encrypted storage whose 32-byte key is derived from a
 *   Keystore-held AES-256 key.
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
 * [AndroidPlatformAdapterImpl] to the Rust engine: the UniFFI bridge has no function that
 * accepts a storage, push or device attestation provider, and `SCP.identityCreateWithCustody`
 * in `scp-kt` takes the UniFFI-generated `uniffi.scp.KeyCustodyProvider`, which the Kotlin
 * [KeyCustodyProvider] in `Types.kt` is not.
 *
 * ## Provider construction
 *
 * - [AndroidKeyCustody] requires context for EncryptedSharedPreferences access.
 * - [AndroidDeviceAttestation] requires context for Play Integrity API access.
 * - [AndroidPushProvider] takes a context it does not read; FCM token retrieval goes through
 *   `FirebaseMessaging.getInstance()`, and the caller initialises Firebase.
 * - [AndroidStorage] requires context for the database file path and the SQLCipher open helper.
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
