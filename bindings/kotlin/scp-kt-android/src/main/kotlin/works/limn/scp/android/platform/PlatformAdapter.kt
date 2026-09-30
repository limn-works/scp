// PlatformAdapter.kt — Android platform adapter factory (ADR-027)
//
// Assembles all four Android platform providers (KeyCustody, DeviceAttestation,
// PushProvider, Storage) into a single adapter object. No code in the Kotlin SDKs calls
// the factory, and no code passes the adapter to the Rust engine. ADR-027 requires the Kotlin
// SDK's `SCP.create()` to call the factory and inject the four providers into the Rust engine
// as UniFFI callback interfaces (ADR-021, the UniFFI bridge), so the shipped factory diverges
// from both ADRs; story SCP-214 tracks injecting a key custody provider.
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
 *   requires P-256 at every supported API level; story SCP-110 tracks that move).
 * @property deviceAttestation Play Integrity device attestation, which requests a Classic
 *   token today; story SCP-111 tracks the Standard request ADR-027 requires.
 * @property push Firebase Cloud Messaging; checks only the `scp` wake field of a data-only
 *   payload and returns the same [WakeSignal.PULL] whatever other fields it carries. §10.7
 *   opacity binds the sender (§10.7.1 step 5), and no code in this repository sends a push, so
 *   SCP-112's opacity criterion is unmet.
 * @property storage SQLCipher encrypted storage whose 32-byte passphrase is derived from a
 *   Keystore-held AES-256 key; SQLCipher derives the database key from that passphrase.
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
 * ## Divergence from ADR-027 acceptance criterion 12
 *
 * The criterion requires [make] to construct [AndroidDeviceAttestation] for each call with the
 * `cloudProjectNumber` of the package verifier's `PlayIntegrityVerifier` entry, and to throw
 * [ScpException] when any provider fails to initialize (for example, Play Integrity
 * unavailable or FCM not configured). [make] does neither. It calls the four constructors once,
 * passes no `cloudProjectNumber`, and probes no provider:
 *
 * - [AndroidKeyCustody]'s constructor gets or creates the Keystore master key and opens
 *   EncryptedSharedPreferences, and an exception from either reaches the caller as thrown,
 *   not wrapped in [ScpException].
 * - [AndroidDeviceAttestation] creates its `IntegrityManager` inside each
 *   [AndroidDeviceAttestation.attest] call, so an absent Play Integrity service surfaces at
 *   that call.
 * - [AndroidPushProvider] does not touch Firebase until [AndroidPushProvider.register].
 * - [AndroidStorage] opens its database on its first method call.
 *
 * See ADR-027 in `.docs/adrs/phase-6.md` for the full design rationale.
 */
object AndroidPlatformAdapter {

    /**
     * Constructs and returns a complete Android platform adapter.
     *
     * @param context Android application context. Must be an application context
     *   (not an activity context) to avoid memory leaks from long-lived references.
     * @return [AndroidPlatformAdapterImpl] holding the four constructed providers. [make] adds
     *   no check of its own, so a missing Play Integrity service, an unconfigured Firebase or
     *   an unopenable database surfaces at the first call that needs it, not here.
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
