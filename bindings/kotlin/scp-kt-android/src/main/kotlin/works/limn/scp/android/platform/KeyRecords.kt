// KeyRecords.kt — the per-key record of every AndroidKeyCustody P-256 and HPKE P-256 key, and
// the persisted id index that lets the adapter read its preferences one entry at a time
// (ADR-027).
//
// A P-256 key lives in Keystore or, for HPKE on API 26-30, as a Bouncy Castle scalar in
// EncryptedSharedPreferences, and Keystore reports its security level per key. The record names
// the key's type, its store and its custody class, and is committed before the key is created,
// so every operation, the bridge's custody query and a later destroy follow what was minted,
// never the key type or the probe of the instance that reopens it.
//
// Provenance: ADR-027 (Android Platform Adapter) criteria 1 and 4, spec 09 §9.5 (P-256 keys).

package works.limn.scp.android.platform

import android.content.SharedPreferences

/** Where a P-256 key's private material lives. */
internal enum class Backing(val wire: String) {
    /** An Android Keystore entry at alias `scp.key.<id>`. */
    KEYSTORE("keystore"),

    /** A Bouncy Castle scalar committed to the preferences entry `scp.p256.<id>`. */
    SOFTWARE("software"),
}

/**
 * The record of one P-256 or HPKE P-256 key.
 *
 * @property custody The custody class settled at mint, or `null` while the mint is pending.
 * @property processTag The tag of the process that reserved the record (see [currentProcessTag]).
 */
internal data class KeyRecord(
    val type: KeyType,
    val backing: Backing,
    val custody: CustodyType?,
    val processTag: String,
)

/**
 * The records of an [AndroidKeyCustody]'s P-256 and HPKE P-256 keys, in [prefs] under
 * `scp.keymeta.<id>` as `"<KeyType>|<keystore|software>|<hardware|software|pending>|<tag>"`.
 *
 * Every write uses `commit()`, and a write that does not commit throws `SCP-CRYPTO-4060`. Reads
 * go to [prefs] each time, so every instance over the same preferences sees every record.
 */
internal class KeyRecords(private val prefs: SharedPreferences) {
    private val index = PersistedIds(prefs, INDEX_KEY)

    /** The ids of every record, from the index. */
    fun ids(): Set<String> = index.read()

    /**
     * Commits a `pending` record of [type] in [backing] for [id], reserved by [processTag], and
     * adds [id] to the index in the same commit.
     */
    fun reserve(id: String, type: KeyType, backing: Backing, processTag: String) {
        require(type == KeyType.P256 || type == KeyType.HPKE_P256) { "only P-256 keys have records" }
        val committed = index.commit(id, present = true) {
            it.putString(key(id), encode(KeyRecord(type, backing, null, processTag)))
        }
        if (!committed) throw ScpException("Could not write the record of key $id", CUSTODY_ERROR)
    }

    /** Settles the pending record of [id] with [custody]. */
    fun settle(id: String, custody: CustodyType) {
        val record = get(id) ?: throw ScpException("No record to settle for key $id", CUSTODY_ERROR)
        if (!prefs.edit().putString(key(id), encode(record.copy(custody = custody))).commit()) {
            throw ScpException("Could not settle the record of key $id", CUSTODY_ERROR)
        }
    }

    /**
     * The record of [id], or `null` when there is none.
     *
     * @throws ScpException with code `SCP-CRYPTO-4060` when the stored record does not parse.
     */
    fun get(id: String): KeyRecord? {
        val text = prefs.getString(key(id), null) ?: return null
        return decode(text) ?: throw ScpException("The record of key $id is malformed", CUSTODY_ERROR)
    }

    /** Whether a record exists for [id]. */
    fun contains(id: String): Boolean = prefs.getString(key(id), null) != null

    /**
     * Removes the record of [id] and its index entry in one commit, then confirms by re-reading
     * that the record is gone.
     */
    fun remove(id: String) {
        val committed = index.commit(id, present = false) { it.remove(key(id)) }
        if (!committed || prefs.getString(key(id), null) != null) {
            throw ScpException("Could not remove the record of key $id", CUSTODY_ERROR)
        }
    }

    private fun key(id: String) = "$PREFIX$id"

    private companion object {
        const val PREFIX = "scp.keymeta."
        const val INDEX_KEY = "scp.keymeta.ids"
        const val PENDING = "pending"
        const val FIELDS = 4

        fun encode(record: KeyRecord): String {
            val custody = when (record.custody) {
                CustodyType.HARDWARE -> "hardware"
                CustodyType.SOFTWARE -> "software"
                CustodyType.IN_MEMORY -> error("a P-256 record never holds in_memory custody")
                null -> PENDING
            }
            return listOf(record.type.name, record.backing.wire, custody, record.processTag).joinToString("|")
        }

        fun decode(text: String): KeyRecord? {
            val parts = text.split('|', limit = FIELDS)
            if (parts.size != FIELDS) return null
            val type = KeyType.entries.firstOrNull { it.name == parts[0] }
            val backing = Backing.entries.firstOrNull { it.wire == parts[1] }
            val custody = when (parts[2]) {
                "hardware" -> CustodyType.HARDWARE
                "software" -> CustodyType.SOFTWARE
                else -> null
            }
            // Only P-256 keys have records, and a P-256 signing key lives only in Keystore.
            val valid = (type == KeyType.HPKE_P256 || (type == KeyType.P256 && backing == Backing.KEYSTORE)) &&
                backing != null && (custody != null || parts[2] == PENDING)
            return if (valid && type != null && backing != null) KeyRecord(type, backing, custody, parts[3]) else null
        }
    }
}

/**
 * A set of key ids persisted in [prefs] under [indexKey] as one space-separated string, so a
 * reader fetches each entry it needs with `getString` instead of `getAll`, which would decrypt
 * every value in an EncryptedSharedPreferences file, private key material included.
 *
 * Every change runs under one process-wide lock: each production [AndroidKeyCustody] opens its
 * own EncryptedSharedPreferences over the same file, so an instance lock would let two
 * instances' read-modify-write of the index lose an id.
 */
internal class PersistedIds(private val prefs: SharedPreferences, private val indexKey: String) {
    /** The persisted ids. */
    fun read(): Set<String> =
        prefs.getString(indexKey, null)?.split(' ')?.filter { it.isNotEmpty() }?.toSet().orEmpty()

    /**
     * Applies [change] and adds [id] to the index ([present]) or removes it, in one editor, and
     * returns what `commit()` returned.
     */
    fun commit(id: String, present: Boolean, change: (SharedPreferences.Editor) -> Unit): Boolean =
        synchronized(LOCK) {
            val ids = if (present) read() + id else read() - id
            val editor = prefs.edit()
            change(editor)
            if (ids.isEmpty()) editor.remove(indexKey) else editor.putString(indexKey, ids.sorted().joinToString(" "))
            editor.commit()
        }

    private companion object {
        val LOCK = Any()
    }
}

/** The custody error code, for every failure that has no more specific one. */
internal const val CUSTODY_ERROR = "SCP-CRYPTO-4060"

/**
 * Runs [block] and rethrows its failure as an [ScpException]: an [ScpException] unchanged, any
 * other [Exception] as `SCP-CRYPTO-4060` with the original as the cause. An [Error] propagates.
 */
@Suppress("TooGenericExceptionCaught") // every exception becomes a typed custody error
internal inline fun <T> custodyGuarded(block: () -> T): T =
    try {
        block()
    } catch (e: ScpException) {
        throw e
    } catch (e: Exception) {
        throw ScpException(e.message ?: e.javaClass.name, CUSTODY_ERROR, e)
    }

/** Throws `SCP-CRYPTO-4060` with [message] and [cause]. */
internal fun custodyFailure(message: String, cause: Throwable? = null): Nothing =
    throw ScpException(message, CUSTODY_ERROR, cause)
