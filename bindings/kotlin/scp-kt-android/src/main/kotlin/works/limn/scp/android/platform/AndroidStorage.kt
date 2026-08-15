// AndroidStorage.kt — StorageProvider implementation for Android (ADR-027)
//
// Encrypted key-value storage using SQLCipher. The database encryption key is a
// 32-byte value derived from a TEE-backed HMAC-SHA-256 key in Android Keystore.
// The Keystore key never leaves the TEE; the TEE computes one HMAC over a fixed
// label, and HKDF-SHA-256 expands that HMAC output into the 32-byte SQLCipher
// passphrase. This gives the database a hardware-rooted chain of trust without
// requiring SQLCipher itself to understand Android Keystore.
//
// The database file is "scp.db" in the application's noBackupFilesDir directory.
// This directory is excluded from Android Auto Backup, ensuring that SQLCipher
// databases protected by TEE-derived keys are not backed up to Google Drive
// (where the TEE key would not be available to decrypt them).
// SQLCipher provides transparent full-database encryption — the OS file is
// unreadable without the derived passphrase.
//
// Provenance: ADR-027 (Android Platform Adapter), ADR-006 (Platform Abstraction Layer),
// ADR-025 (Apple Platform Adapter — parallel reference), section 17.6 of
// .docs/specs/17-persistence-and-storage.md (SQLCipher key derivation — HKDF-SHA-256,
// 32-byte key, salt SHA-256("SCP-SQLCIPHER-KEY-V1"), info prefix "scp-sqlcipher:").

package works.limn.scp.android.platform

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import net.zetetic.database.sqlcipher.SQLiteDatabase
import net.zetetic.database.sqlcipher.SQLiteOpenHelper
import java.io.File
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Android SQLCipher-backed storage provider for SCP.
 *
 * Implements the [StorageProvider] interface (mirroring the Rust `Storage` trait
 * from `scp-platform/src/traits.rs`). This class is injected into the Rust engine via
 * the UniFFI callback interface at `SCP.create()` time; all storage operations are
 * dispatched from Rust through the UniFFI boundary into this class.
 *
 * ## Encryption architecture
 *
 * The database encryption key is derived through a TEE-backed chain of trust:
 *
 * 1. Android Keystore holds a 256-bit HMAC-SHA-256 key (alias: `scp.storage.key`) inside
 *    the TEE. The key is generated on first use and persists across app restarts.
 * 2. The TEE computes `ikm = HMAC-SHA-256(keystore_key, "scp-storage-passphrase")`.
 *    HMAC is deterministic, so the same Keystore key yields the same 32 bytes on every
 *    open. HMAC takes no nonce, so no nonce has to be stored or reused.
 * 3. HKDF-SHA-256 derives the 32-byte SQLCipher passphrase from that `ikm`, under the
 *    salt and info that section 17.6 of `.docs/specs/17-persistence-and-storage.md`
 *    fixes for the SQLCipher key.
 * 4. SQLCipher uses this 32-byte passphrase for full-database encryption.
 *
 * Step 3 is a key derivation, not an encryption. An earlier revision of this file ran
 * AES-GCM over the label under an all-zero IV and truncated the ciphertext to 32 bytes.
 * Under a fixed IV, AES-GCM's keystream depends on the key alone, so that ciphertext was
 * the known label XOR one reusable keystream, which is not key material. HKDF-SHA-256 is
 * the primitive that section 17.6 mandates, and it is the primitive
 * [AndroidKeyCustody] already uses for the pseudonym secret; both call [Hkdf].
 *
 * Section 17.6 binds its `info` to a DID. This adapter has no DID: ADR-027 fixes the
 * constructor at `AndroidStorage(context: Context)`, and the database opens before any
 * identity is loaded. The `info` therefore binds the Keystore alias, which names the key
 * this derivation actually roots in, and the TEE key binds the database to the device.
 *
 * The Keystore key bytes never leave the TEE. The derived passphrase exists in memory
 * only during database open and is not persisted to disk in plaintext.
 *
 * ## Devices holding a passphrase from the AES-GCM revision
 *
 * A device that already ran the AES-GCM revision holds an AES key under
 * [KEY_ALIAS] and a database encrypted under the truncated-ciphertext passphrase.
 * That database is unreadable after this change, and SCP is pre-release, so this file
 * ships no migration: `CLAUDE.md` forbids migration code before release.
 * [getOrCreateStorageKey] fails closed on such a device — `Mac.init` rejects an AES key
 * with an `InvalidKeyException`, which surfaces as [ERROR_KEY_DERIVATION_FAILED].
 * Reusing the alias is deliberate: a fresh alias would generate a new HMAC key, derive a
 * working passphrase, and open a new empty database beside the old unreadable one, which
 * hides the data loss instead of reporting it.
 *
 * ## Thread safety
 *
 * SQLCipher's [SQLiteDatabase] is thread-safe for concurrent reads and serialized writes.
 * The [db] property uses lazy initialization with the default `SYNCHRONIZED` mode,
 * ensuring the database is opened exactly once.
 *
 * ## Key ID
 *
 * The Android Keystore alias is [KEY_ALIAS] (`scp.storage.key`). This alias is distinct
 * from the key custody aliases (`scp.key.*`) to prevent collision.
 *
 * @param context Android application context for database file path resolution.
 */
class AndroidStorage(private val context: Context) : StorageProvider {

    /**
     * Lazily-opened encrypted SQLite database.
     *
     * The database is opened on first access. SQLCipher libraries must be loaded
     * before any database operation via [SQLiteDatabase.loadLibs].
     */
    internal val db: SQLiteDatabase by lazy { openEncryptedDatabase() }

    private fun openEncryptedDatabase(): SQLiteDatabase {
        System.loadLibrary("sqlcipher")
        val encryptionKey = getOrCreateStorageKey()
        try {
            // The passphrase is passed as byte[] to the SQLiteOpenHelper constructor.
            // SQLCipher 4.6+ uses the constructor-supplied key for encryption.
            // The ByteArray source (encryptionKey) is zeroed in the finally block.
            // The real protection is TEE-backed key derivation — the passphrase is
            // useless without the Android Keystore key.
            //
            // The database path is computed from noBackupFilesDir so that the
            // encrypted database is excluded from Android Auto Backup. Backed-up
            // databases would be unreadable on a different device because the TEE
            // key that derived the passphrase is device-bound.
            val dbPath = File(context.noBackupFilesDir, DATABASE_NAME).absolutePath
            val helper = ScpDatabaseHelper(context, dbPath, encryptionKey)
            return helper.writableDatabase
        } finally {
            // Zero key material immediately after use to limit exposure window.
            encryptionKey.fill(0)
        }
    }

    /**
     * Retrieves or generates the TEE-backed HMAC-SHA-256 key, then derives the SQLCipher
     * passphrase from it.
     *
     * The Keystore key is generated on first call and persists in hardware. Subsequent calls
     * retrieve the existing key. HMAC-SHA-256 is deterministic, so a given Keystore key and
     * the fixed [DERIVATION_LABEL] always produce the same input keying material, and
     * [derivePassphrase] always expands that material to the same 32 bytes.
     *
     * A device holding the AES key that the earlier AES-GCM revision generated under
     * [KEY_ALIAS] reaches `Mac.init`, which rejects an AES key with an `InvalidKeyException`
     * and therefore fails closed with [ERROR_KEY_DERIVATION_FAILED]. See the class
     * documentation for why this file ships no migration.
     *
     * @return 32-byte SQLCipher passphrase derived from the TEE key.
     * @throws ScpException with code `SCP-STORAGE-8003` if key derivation fails.
     */
    internal fun getOrCreateStorageKey(): ByteArray {
        try {
            val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

            if (!keyStore.containsAlias(KEY_ALIAS)) {
                val keySpec = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setKeySize(KEY_SIZE_BITS)
                    .setUserAuthenticationRequired(false) // background access required
                    .build()
                KeyGenerator.getInstance(MAC_ALGORITHM, KEYSTORE_PROVIDER)
                    .apply { init(keySpec) }
                    .generateKey()
            }

            // The TEE computes one HMAC over the fixed label. The Keystore key bytes never
            // leave the TEE, and HMAC takes no nonce, so nothing has to be stored alongside
            // the database to reproduce this value on the next open.
            val secretKey = keyStore.getKey(KEY_ALIAS, null) as SecretKey
            val ikm = Mac.getInstance(MAC_ALGORITHM)
                .apply { init(secretKey) }
                .doFinal(DERIVATION_LABEL.toByteArray(Charsets.UTF_8))

            try {
                return derivePassphrase(ikm)
            } finally {
                ikm.fill(0) // zeroize the TEE-derived input keying material
            }
        } catch (e: ScpException) {
            throw e
        } catch (e: GeneralSecurityException) {
            throw ScpException("Storage encryption key derivation failed", ERROR_KEY_DERIVATION_FAILED, e)
        }
    }

    override fun set(key: String, data: ByteArray) {
        try {
            db.execSQL(
                "INSERT OR REPLACE INTO $TABLE_NAME ($COLUMN_KEY, $COLUMN_VALUE) VALUES (?, ?)",
                arrayOf(key, data)
            )
        } catch (e: ScpException) {
            throw e
        } catch (e: android.database.SQLException) {
            throw ScpException("Storage set operation failed", ERROR_STORAGE_OPERATION_FAILED, e)
        } catch (e: IllegalStateException) {
            throw ScpException("Storage set operation failed", ERROR_STORAGE_OPERATION_FAILED, e)
        }
    }

    override fun get(key: String): ByteArray? {
        try {
            val cursor = db.rawQuery(
                "SELECT $COLUMN_VALUE FROM $TABLE_NAME WHERE $COLUMN_KEY = ?",
                arrayOf(key)
            )
            return cursor.use {
                if (it.moveToFirst()) it.getBlob(0) else null
            }
        } catch (e: ScpException) {
            throw e
        } catch (e: android.database.SQLException) {
            throw ScpException("Storage get operation failed", ERROR_STORAGE_OPERATION_FAILED, e)
        } catch (e: IllegalStateException) {
            throw ScpException("Storage get operation failed", ERROR_STORAGE_OPERATION_FAILED, e)
        }
    }

    override fun delete(key: String) {
        try {
            db.execSQL(
                "DELETE FROM $TABLE_NAME WHERE $COLUMN_KEY = ?",
                arrayOf<Any>(key)
            )
        } catch (e: ScpException) {
            throw e
        } catch (e: android.database.SQLException) {
            throw ScpException("Storage delete operation failed", ERROR_STORAGE_OPERATION_FAILED, e)
        } catch (e: IllegalStateException) {
            throw ScpException("Storage delete operation failed", ERROR_STORAGE_OPERATION_FAILED, e)
        }
    }

    override fun listKeys(prefix: String): List<String> {
        try {
            val escaped = escapeLikePrefix(prefix)
            val cursor = db.rawQuery(
                "SELECT $COLUMN_KEY FROM $TABLE_NAME WHERE $COLUMN_KEY LIKE ? ESCAPE '\\' ORDER BY $COLUMN_KEY ASC",
                arrayOf("$escaped%")
            )
            return cursor.use {
                buildList {
                    while (it.moveToNext()) {
                        add(it.getString(0))
                    }
                }
            }
        } catch (e: ScpException) {
            throw e
        } catch (e: android.database.SQLException) {
            throw ScpException("Storage listKeys failed", ERROR_STORAGE_OPERATION_FAILED, e)
        } catch (e: IllegalStateException) {
            throw ScpException("Storage listKeys failed", ERROR_STORAGE_OPERATION_FAILED, e)
        }
    }

    override fun deletePrefix(prefix: String): Long {
        try {
            val escaped = escapeLikePrefix(prefix)
            return executeDeletePrefixTransaction(escaped)
        } catch (e: ScpException) {
            throw e
        } catch (e: android.database.SQLException) {
            throw ScpException("Storage deletePrefix failed", ERROR_STORAGE_OPERATION_FAILED, e)
        } catch (e: IllegalStateException) {
            throw ScpException("Storage deletePrefix failed", ERROR_STORAGE_OPERATION_FAILED, e)
        }
    }

    /**
     * Executes the delete-prefix operation within a database transaction.
     *
     * Extracted from [deletePrefix] to reduce nesting depth. Performs the DELETE
     * and queries `changes()` to return the number of affected rows.
     */
    private fun executeDeletePrefixTransaction(escapedPrefix: String): Long {
        db.beginTransaction()
        try {
            db.execSQL(
                "DELETE FROM $TABLE_NAME WHERE $COLUMN_KEY LIKE ? ESCAPE '\\'",
                arrayOf<Any>("$escapedPrefix%")
            )
            val cursor = db.rawQuery("SELECT changes()", emptyArray())
            val count = cursor.use {
                if (it.moveToFirst()) it.getLong(0) else 0L
            }
            db.setTransactionSuccessful()
            return count
        } finally {
            db.endTransaction()
        }
    }

    override fun exists(key: String): Boolean {
        try {
            val cursor = db.rawQuery(
                "SELECT 1 FROM $TABLE_NAME WHERE $COLUMN_KEY = ? LIMIT 1",
                arrayOf(key)
            )
            return cursor.use { it.moveToFirst() }
        } catch (e: ScpException) {
            throw e
        } catch (e: android.database.SQLException) {
            throw ScpException("Storage exists check failed", ERROR_STORAGE_OPERATION_FAILED, e)
        } catch (e: IllegalStateException) {
            throw ScpException("Storage exists check failed", ERROR_STORAGE_OPERATION_FAILED, e)
        }
    }

    companion object {
        /**
         * Escape SQL LIKE wildcard characters in a prefix string.
         *
         * `%` and `_` are LIKE wildcards in SQLite and must be escaped with `\`
         * when used as literal characters in prefix queries.
         */
        private fun escapeLikePrefix(prefix: String): String =
            prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

        /**
         * Expands TEE-derived input keying material into the 32-byte SQLCipher passphrase.
         *
         * Section 17.6 of `.docs/specs/17-persistence-and-storage.md` fixes this derivation:
         * HKDF-SHA-256 (RFC 5869), salt `SHA-256("SCP-SQLCIPHER-KEY-V1")`, info prefixed
         * `"scp-sqlcipher:"`, output 32 bytes. [getOrCreateStorageKey] supplies [ikm] as the
         * HMAC that the Android Keystore key computes over [DERIVATION_LABEL].
         *
         * This function reads only its argument and the constants beside it, so a JVM unit
         * test can call it without an Android Keystore and pin the derivation to HKDF.
         *
         * @param ikm 32 bytes of input keying material from the TEE.
         * @return the 32-byte SQLCipher passphrase.
         */
        internal fun derivePassphrase(ikm: ByteArray): ByteArray = Hkdf.sha256(
            ikm = ikm,
            salt = MessageDigest.getInstance("SHA-256")
                .digest(SQLCIPHER_SALT_LABEL.toByteArray(Charsets.UTF_8)),
            info = SQLCIPHER_INFO.toByteArray(Charsets.UTF_8),
            length = PASSPHRASE_LENGTH,
        )

        /** Android Keystore provider name. */
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"

        /** Alias for the TEE-backed HMAC-SHA-256 storage key. */
        internal const val KEY_ALIAS = "scp.storage.key"

        /** Keystore key size in bits. */
        private const val KEY_SIZE_BITS = 256

        /**
         * Algorithm of the Keystore key and of the MAC computed under it.
         *
         * `KeyGenerator.getInstance` and `Mac.getInstance` both take this name, and it
         * equals `KeyProperties.KEY_ALGORITHM_HMAC_SHA256`. Naming it here rather than
         * reading `KeyProperties` keeps the value readable in a JVM unit test, where the
         * Android framework classes return defaults.
         */
        internal const val MAC_ALGORITHM = "HmacSHA256"

        /** Fixed label the Keystore key MACs to produce the HKDF input keying material. */
        internal const val DERIVATION_LABEL = "scp-storage-passphrase"

        /** Label hashed to form the HKDF salt (section 17.6 of the persistence spec). */
        internal const val SQLCIPHER_SALT_LABEL = "SCP-SQLCIPHER-KEY-V1"

        /**
         * HKDF info for the SQLCipher passphrase.
         *
         * Section 17.6 of the persistence spec writes this as `"scp-sqlcipher:" || did`.
         * This adapter has no DID at database-open time, so the suffix is [KEY_ALIAS] — the
         * Keystore key the derivation roots in. See the class documentation.
         */
        internal const val SQLCIPHER_INFO = "scp-sqlcipher:$KEY_ALIAS"

        /** Length of the derived SQLCipher passphrase in bytes. */
        internal const val PASSPHRASE_LENGTH = 32

        /** SQLCipher database file name. */
        internal const val DATABASE_NAME = "scp.db"

        /** Database schema version. */
        internal const val DATABASE_VERSION = 1

        /** Key-value table name. */
        internal const val TABLE_NAME = "kv"

        /** Key column name. */
        internal const val COLUMN_KEY = "key"

        /** Value column name. */
        internal const val COLUMN_VALUE = "value"

        /** Error code: storage key not found. */
        internal const val ERROR_KEY_NOT_FOUND = "SCP-STORAGE-8001"

        /** Error code: storage operation failed. */
        internal const val ERROR_STORAGE_OPERATION_FAILED = "SCP-STORAGE-8002"

        /** Error code: storage encryption key derivation failed. */
        internal const val ERROR_KEY_DERIVATION_FAILED = "SCP-STORAGE-8003"
    }
}

/**
 * SQLiteOpenHelper for the SCP encrypted key-value database.
 *
 * Creates the `kv` table with `key` as `TEXT PRIMARY KEY` and `value` as `BLOB NOT NULL`,
 * using `WITHOUT ROWID` for a clustered primary key layout that matches the Rust
 * `SqliteStorage` schema. The primary key enforces INSERT OR REPLACE semantics.
 *
 * The [databasePath] is the full filesystem path to the database file (typically
 * within `noBackupFilesDir`). Passing a full path rather than just a filename
 * overrides SQLiteOpenHelper's default database directory.
 */
internal class ScpDatabaseHelper(
    context: Context,
    databasePath: String,
    password: ByteArray,
) : SQLiteOpenHelper(
    context,
    databasePath,
    password,
    null, // cursorFactory
    AndroidStorage.DATABASE_VERSION,
    0, // minimumSupportedVersion
    null, // errorHandler
    null, // databaseHook
    false, // enableWriteAheadLogging
) {
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS ${AndroidStorage.TABLE_NAME} (
                ${AndroidStorage.COLUMN_KEY} TEXT PRIMARY KEY,
                ${AndroidStorage.COLUMN_VALUE} BLOB NOT NULL
            ) WITHOUT ROWID
            """.trimIndent()
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // v1 is the initial schema. Future migrations will be added here.
    }
}
