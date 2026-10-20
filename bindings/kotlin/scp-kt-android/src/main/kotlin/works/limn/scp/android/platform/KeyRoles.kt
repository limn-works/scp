// KeyRoles.kt — the role each AndroidKeyCustody key was minted in (ADR-027)
//
// The UniFFI KeyCustodyProvider contract (crates/scp-ffi/uniffi/src/lib.rs) requires a host to
// record the role generate_keypair names and report it from get_public_key for the key's
// lifetime, across sessions. A key that survives process death (a Keystore Ed25519 key, a
// software Ed25519 key whose seed AndroidKeyCustody persists, or a P-256 or HPKE P-256 key) has
// its role persisted beside it; an X25519 key lives in process memory only, and so does its role.
//
// Provenance: ADR-027 (Android Platform Adapter), ADR-006 (Platform Abstraction Layer).

package works.limn.scp.android.platform

import android.content.SharedPreferences
import java.util.concurrent.ConcurrentHashMap

/**
 * The [KeyRole] of every key an [AndroidKeyCustody] holds.
 *
 * A key gets its role only through [mint] and loses it only through [forget], so no key is
 * created without its role. Roles of persisted keys are written to [prefs] under
 * `scp.role.<keyId>` with `commit()`, together with the key id in the index [persistedIds]
 * reads, and restored when the instance is constructed by reading each indexed id's entry
 * with `getString`. A key with no recorded role has none: [roleOf] returns `null` and the
 * caller fails closed, so no role is ever guessed.
 *
 * @param prefs The same preferences [AndroidKeyCustody] persists its software keys in.
 */
internal class KeyRoles(private val prefs: SharedPreferences) {
    private val roles = ConcurrentHashMap<String, KeyRole>()
    private val index = PersistedIds(prefs, INDEX_KEY)

    init {
        for (keyId in index.read()) {
            val stored = prefs.getString("$PREFS_KEY_PREFIX$keyId", null)
            KeyRole.entries.firstOrNull { it.name == stored }?.let { roles[keyId] = it }
        }
    }

    /** The ids of every key whose role is persisted. */
    fun persistedIds(): Set<String> = index.read()

    /**
     * Records [role] for [keyId], then runs [generate], which creates the key and leaves nothing
     * behind when it throws. When [persist] is set (the key itself outlives the process), the
     * role reaches [prefs] through `commit()` before [generate] runs, so a key on disk always
     * has its role on disk. When [generate] throws, the role is removed again and the exception
     * propagates.
     *
     * A removal that does not commit is attached to the propagating exception as suppressed.
     *
     * @throws ScpException with code `SCP-CRYPTO-4060` when [prefs] does not commit the role;
     *   [generate] has not run.
     */
    @Suppress("TooGenericExceptionCaught") // any failure must remove the role it recorded
    fun mint(keyId: String, role: KeyRole, persist: Boolean, generate: () -> KeyHandle): KeyHandle {
        roles[keyId] = role
        try {
            val written = !persist ||
                index.commit(keyId, present = true) { it.putString("$PREFS_KEY_PREFIX$keyId", role.name) }
            if (!written) throw ScpException("Could not write the role of key $keyId", CUSTODY_ERROR)
            return generate()
        } catch (e: Throwable) {
            roles.remove(keyId)
            if (persist) removeAfterFailure(keyId, e)
            throw e
        }
    }

    /** Removes the persisted role of [keyId] after [failure], attaching a failed removal to it. */
    @Suppress("TooGenericExceptionCaught") // a failed cleanup is reported, never lost
    private fun removeAfterFailure(keyId: String, failure: Throwable) {
        try {
            if (!removePersisted(keyId)) {
                failure.addSuppressed(ScpException("Could not remove the role of key $keyId", CUSTODY_ERROR))
            }
        } catch (cleanup: Exception) {
            failure.addSuppressed(cleanup)
        }
    }

    /** The role recorded for [keyId], or `null` when none is. */
    fun roleOf(keyId: String): KeyRole? = roles[keyId]

    /** Whether a role is recorded for [keyId]. */
    fun contains(keyId: String): Boolean = roles.containsKey(keyId)

    /**
     * Removes the role recorded for [keyId], in memory and in [prefs] through `commit()`.
     *
     * @throws ScpException with code `SCP-CRYPTO-4060` when [prefs] does not commit the removal.
     *   The caller has already destroyed the key, so the role left behind names an absent key,
     *   and every member resolves the key before its role.
     */
    fun forget(keyId: String) {
        roles.remove(keyId)
        if (!removePersisted(keyId)) {
            throw ScpException("Key $keyId is destroyed but its role could not be removed", CUSTODY_ERROR)
        }
    }

    private fun removePersisted(keyId: String): Boolean =
        index.commit(keyId, present = false) { it.remove("$PREFS_KEY_PREFIX$keyId") }

    private companion object {
        const val PREFS_KEY_PREFIX = "scp.role."
        const val INDEX_KEY = "scp.role.ids"
    }
}
