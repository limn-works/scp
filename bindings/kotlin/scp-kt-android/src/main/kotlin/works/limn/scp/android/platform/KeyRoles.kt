// KeyRoles.kt — the role each AndroidKeyCustody key was minted in (ADR-027)
//
// The UniFFI KeyCustodyProvider contract (crates/scp-ffi/uniffi/src/lib.rs) requires a host to
// record the role generate_keypair names and report it from get_public_key for the key's
// lifetime, across sessions. A key that survives process death (a Keystore Ed25519 key, or a
// software Ed25519 key whose seed AndroidKeyCustody persists) has its role persisted beside it;
// an X25519 key lives in process memory only, and so does its role.
//
// Provenance: ADR-027 (Android Platform Adapter), ADR-006 (Platform Abstraction Layer).

package works.limn.scp.android.platform

import android.content.SharedPreferences
import java.util.concurrent.ConcurrentHashMap

/**
 * The [KeyRole] of every key an [AndroidKeyCustody] holds.
 *
 * Roles of persisted keys are written to [prefs] under `scp.role.<keyId>` with `apply()`, and
 * restored when the instance is constructed. A key with no recorded role has none: [roleOf]
 * returns `null` and the caller fails closed, so no role is ever guessed.
 *
 * @param prefs The same preferences [AndroidKeyCustody] persists software Ed25519 seeds in.
 */
internal class KeyRoles(private val prefs: SharedPreferences) {
    private val roles = ConcurrentHashMap<String, KeyRole>()

    init {
        prefs.all
            .filter { (key, value) -> key.startsWith(PREFS_KEY_PREFIX) && value is String }
            .forEach { (prefsKey, value) ->
                val role = KeyRole.entries.firstOrNull { it.name == value } ?: return@forEach
                roles[prefsKey.removePrefix(PREFS_KEY_PREFIX)] = role
            }
    }

    /** Records [role] for [keyId], persisting it when the key itself outlives the process. */
    fun record(keyId: String, role: KeyRole, persist: Boolean) {
        roles[keyId] = role
        if (persist) prefs.edit().putString("$PREFS_KEY_PREFIX$keyId", role.name).apply()
    }

    /** The role recorded for [keyId], or `null` when none is. */
    fun roleOf(keyId: String): KeyRole? = roles[keyId]

    /** Whether a role is recorded for [keyId]. */
    fun contains(keyId: String): Boolean = roles.containsKey(keyId)

    /** Removes the role recorded for [keyId], in memory and in [prefs]. */
    fun forget(keyId: String) {
        roles.remove(keyId)
        prefs.edit().remove("$PREFS_KEY_PREFIX$keyId").apply()
    }

    private companion object {
        const val PREFS_KEY_PREFIX = "scp.role."
    }
}
