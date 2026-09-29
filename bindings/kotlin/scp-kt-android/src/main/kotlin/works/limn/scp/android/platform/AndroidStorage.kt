// AndroidStorage.kt — StorageProvider implementation for Android (ADR-027)
//
// Encrypted key-value storage using SQLCipher. The adapter opens the database with a
// 32-byte SQLCipher passphrase derived from a Keystore-held AES-256 key, and SQLCipher
// derives the database encryption key from that passphrase. Keystore does not hand
// the AES key to the app; the key encrypts a fixed 22-byte label via AES-GCM with a
// fixed IV, and the first 32 of the 38 output bytes (the 22 ciphertext bytes and the
// first 10 bytes of the 16-byte GCM tag) are the SQLCipher passphrase. The adapter
// does not read KeyInfo.securityLevel, so it does not know whether Keystore put the
// AES key in the TEE or, on a device whose KeyMint runs in software, in software.
//
// The database file is "scp.db" in the application's noBackupFilesDir directory.
// This directory is excluded from Android Auto Backup, ensuring that SQLCipher
// databases protected by Keystore-derived keys are not backed up to Google Drive
// (where the Keystore key would not be available to decrypt them).
// SQLCipher provides transparent full-database encryption — the OS file is
// unreadable without the derived passphrase.
//
// Provenance: ADR-027 (Android Platform Adapter), ADR-006 (Platform Abstraction Layer),
// ADR-025 (Apple Platform Adapter — parallel reference), section 17 (Persistence Architecture).

package works.limn.scp.android.platform

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import net.zetetic.database.sqlcipher.SQLiteDatabase
import net.zetetic.database.sqlcipher.SQLiteOpenHelper
import java.io.File
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android SQLCipher-backed storage provider for SCP.
 *
 * Implements the Kotlin [StorageProvider] interface in `Types.kt`, whose KDoc states how it
 * differs from the Rust `Storage` trait and from the UniFFI `StorageProvider` callback
 * interface. No code passes this class to the Rust engine, because the UniFFI bridge has no
 * function that accepts a storage provider.
 *
 * ## Encryption architecture
 *
 * SQLCipher derives the database encryption key from a passphrase, and the adapter derives
 * that passphrase from a Keystore-held key:
 *
 * 1. Android Keystore holds an AES-256-GCM key (alias: `scp.storage.key`). The key is
 *    generated on first use and persists across app restarts. The adapter does not read
 *    `KeyInfo.securityLevel`, so it does not know whether Keystore put the key in the TEE
 *    or, on a device whose KeyMint runs in software, in software.
 * 2. The Keystore key encrypts a fixed 22-byte label (`"scp-storage-passphrase"`) using
 *    AES-GCM with a fixed 12-byte zero IV. The fixed IV makes the 38-byte output (22 bytes
 *    of ciphertext followed by the 16-byte GCM tag) deterministic.
 * 3. The first 32 bytes of that output (the ciphertext and the first 10 bytes of the tag)
 *    are the SQLCipher passphrase. SQLCipher derives the database encryption key from that
 *    passphrase and encrypts the whole database with the derived key.
 *
 * Keystore does not hand the AES key bytes to the app. The derived passphrase is not
 * persisted to disk in plaintext, but key material stays in process memory: SQLCipher keeps
 * the database key it derives from the passphrase in native memory for as long as the
 * database is open, and the adapter zeroes only the returned passphrase array after open,
 * not the 38-byte `doFinal` output or the list `take` builds from it, which stay on the
 * JVM heap until garbage collection.
 *
 * ## Thread safety
 *
 * SQLCipher's [SQLiteDatabase] is safe to call from several threads. [ScpDatabaseHelper]
 * disables write-ahead logging, so the connection pool holds one connection and reads and
 * writes both run one at a time on it. The [db] property uses lazy initialization with the
 * default `SYNCHRONIZED` mode, so it keeps the first successful open and every later access
 * reuses that database.
 *
 * ## Errors
 *
 * The [db] property opens the database on the first access, and each [StorageProvider]
 * method reads [db] inside its `try` block. Until one open succeeds, every method call
 * retries the open, because a failed `lazy` initializer caches nothing. A failed open reaches
 * the caller in one of three forms:
 * - `SCP-STORAGE-8003` when [getOrCreateStorageKey] catches a `GeneralSecurityException`.
 * - `SCP-STORAGE-8002` when opening the database throws an `android.database.SQLException`
 *   or an `IllegalStateException`.
 * - the original non-[ScpException] throwable for every other failure, for example the
 *   `UnsatisfiedLinkError` from `System.loadLibrary("sqlcipher")` or the `IOException` from
 *   `KeyStore.load`.
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
     * The database is opened on first access. `openEncryptedDatabase` loads the SQLCipher
     * native library with `System.loadLibrary("sqlcipher")` before it opens the database.
     */
    internal val db: SQLiteDatabase by lazy { openEncryptedDatabase() }

    private fun openEncryptedDatabase(): SQLiteDatabase {
        System.loadLibrary("sqlcipher")
        val encryptionKey = getOrCreateStorageKey()
        try {
            // The passphrase is passed as byte[] to the SQLiteOpenHelper constructor.
            // SQLCipher 4.6+ derives the database encryption key from the constructor-supplied
            // passphrase.
            // The returned ByteArray (encryptionKey) is zeroed in the finally block; the
            // intermediate copies inside getOrCreateStorageKey are not.
            // The real protection is Keystore-held key derivation — the passphrase
            // cannot be recomputed without the Android Keystore key.
            //
            // The database path is computed from noBackupFilesDir so that the
            // encrypted database is excluded from Android Auto Backup. Backed-up
            // databases would be unreadable on a different device because the Keystore
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
     * Retrieve or generate the Keystore-held AES-256 key, then derive the SQLCipher passphrase.
     *
     * The Keystore key is generated on first call and persists in Android Keystore. Subsequent calls
     * retrieve the existing key. The derived passphrase is deterministic for a given Keystore
     * key (fixed IV, fixed plaintext label).
     *
     * @return 32-byte SQLCipher passphrase derived from the Keystore key.
     * @throws ScpException with code `SCP-STORAGE-8003` if key derivation fails.
     */
    internal fun getOrCreateStorageKey(): ByteArray {
        try {
            val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

            if (!keyStore.containsAlias(KEY_ALIAS)) {
                val keySpec = KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(KEY_SIZE_BITS)
                    .setRandomizedEncryptionRequired(false) // required for caller-supplied IV with GCM
                    .setUserAuthenticationRequired(false) // background access required
                    .build()
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
                    .apply { init(keySpec) }
                    .generateKey()
            }

            // Derive a 32-byte SQLCipher passphrase by encrypting a fixed label with the Keystore key.
            // Keystore does not hand the key bytes to the app — this pattern uses AES-GCM with a
            // deterministic IV to produce a stable 32-byte value for the SQLCipher passphrase.
            val secretKey = keyStore.getKey(KEY_ALIAS, null) as SecretKey
            val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION).apply {
                init(
                    Cipher.ENCRYPT_MODE,
                    secretKey,
                    GCMParameterSpec(GCM_TAG_LENGTH_BITS, ByteArray(GCM_IV_LENGTH))
                )
            }
            val ciphertext = cipher.doFinal(DERIVATION_LABEL.toByteArray(Charsets.UTF_8))
            // doFinal returns 38 bytes: 22 of ciphertext, then the 16-byte GCM tag. Keep the first 32.
            return ciphertext.take(PASSPHRASE_LENGTH).toByteArray()
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

    /**
     * Returns keys matching [prefix], by SQL `LIKE`. SQLite's `LIKE` ignores ASCII letter
     * case and no `PRAGMA case_sensitive_like` is set, so "ctx.a" also matches "ctx.Abc";
     * the Rust SqliteStorage and AppleStorage prefix scans are case-sensitive.
     */
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

    /**
     * Deletes keys matching [prefix], by the same case-insensitive SQL `LIKE` as
     * [listKeys], so deletePrefix("ctx.a") also deletes "ctx.Abc".
     */
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


        /** Android Keystore provider name. */
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"

        /** Alias for the Keystore-held AES-256 key that derives the SQLCipher passphrase. */
        internal const val KEY_ALIAS = "scp.storage.key"

        /** AES key size in bits. */
        private const val KEY_SIZE_BITS = 256

        /** Cipher transformation for AES-GCM key derivation. */
        private const val CIPHER_TRANSFORMATION = "AES/GCM/NoPadding"

        /** GCM authentication tag length in bits. */
        private const val GCM_TAG_LENGTH_BITS = 128

        /** GCM initialization vector length in bytes (12-byte fixed zero IV for determinism). */
        private const val GCM_IV_LENGTH = 12

        /** Fixed label encrypted by the Keystore key to derive the SQLCipher passphrase. */
        private const val DERIVATION_LABEL = "scp-storage-passphrase"

        /** Length of the derived SQLCipher passphrase in bytes. */
        private const val PASSPHRASE_LENGTH = 32

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

        /**
         * Error code: storage key not found. No code path throws it: a missing key makes
         * [AndroidStorage.get] return `null`.
         */
        internal const val ERROR_KEY_NOT_FOUND = "SCP-STORAGE-8001"

        /** Error code: storage operation failed. */
        internal const val ERROR_STORAGE_OPERATION_FAILED = "SCP-STORAGE-8002"

        /** Error code: the Keystore key or the SQLCipher passphrase derivation failed. */
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
