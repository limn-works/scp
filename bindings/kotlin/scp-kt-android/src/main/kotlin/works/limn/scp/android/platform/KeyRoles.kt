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
 * A key gets its role only through [mint] and loses it only through [forget], so no key is
 * created without its role. Roles of persisted keys are written to [prefs] under
 * `scp.role.<keyId>` with `commit()`, and restored when the instance is constructed. A key with
 * no recorded role has none: [roleOf] returns `null` and the caller fails closed, so no role is
 * ever guessed.
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

    /**
     * Records [role] for [keyId], then runs [generate], which creates the key and leaves nothing
     * behind when it throws. When [persist] is set (the key itself outlives the process), the
     * role reaches [prefs] through `commit()` before [generate] runs, so a key on disk always
     * has its role on disk. When [generate] throws, the role is removed again and the exception
     * propagates.
     *
     * @throws ScpException with code `SCP-CRYPTO-4060` when [prefs] does not commit the role;
     *   [generate] has not run.
     */
    @Suppress("TooGenericExceptionCaught") // any failure must remove the role it recorded
    fun mint(keyId: String, role: KeyRole, persist: Boolean, generate: () -> KeyHandle): KeyHandle {
        roles[keyId] = role
        try {
            if (persist) commitOrThrow(keyId) { it.putString("$PREFS_KEY_PREFIX$keyId", role.name) }
            return generate()
        } catch (e: Throwable) {
            roles.remove(keyId)
            if (persist) {
                try {
                    prefs.edit().remove("$PREFS_KEY_PREFIX$keyId").commit()
                } catch (cleanup: Exception) {
                    e.addSuppressed(cleanup)
                }
            }
            throw e
        }
    }

    /** The role recorded for [keyId], or `null` when none is. */
    fun roleOf(keyId: String): KeyRole? = roles[keyId]

    /** Whether a role is recorded for [keyId]. */
    fun contains(keyId: String): Boolean = roles.containsKey(keyId)

    /**
     * Removes the role recorded for [keyId], in memory and in [prefs] through `commit()`. The
     * caller has already destroyed the key, so a removal [prefs] does not commit leaves a role
     * for an absent key, which no member reads: each resolves the key before its role.
     */
    fun forget(keyId: String) {
        roles.remove(keyId)
        prefs.edit().remove("$PREFS_KEY_PREFIX$keyId").commit()
    }

    private fun commitOrThrow(keyId: String, change: (SharedPreferences.Editor) -> Unit) {
        val editor = prefs.edit()
        change(editor)
        if (!editor.commit()) {
            throw ScpException("Could not write the role of key $keyId", "SCP-CRYPTO-4060")
        }
    }

    private companion object {
        const val PREFS_KEY_PREFIX = "scp.role."
    }
}
