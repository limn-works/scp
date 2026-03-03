// AndroidStorage.kt — StorageProvider implementation for Android (ADR-027)
//
// Encrypted key-value storage using SQLCipher. The database encryption key is a
// 32-byte value derived from a TEE-backed AES-256 key in Android Keystore. The
// Keystore key never leaves the TEE; it encrypts a fixed label via AES-GCM to
// produce a deterministic 32-byte passphrase for SQLCipher. This gives the
// database a hardware-rooted chain of trust without requiring SQLCipher itself
// to understand Android Keystore.
//
// The database file is "scp.db" in the application's noBackupFilesDir directory.
// This directory is excluded from Android Auto Backup, ensuring that SQLCipher
// databases protected by TEE-derived keys are not backed up to Google Drive
// (where the TEE key would not be available to decrypt them).
// SQLCipher provides transparent full-database encryption — the OS file is
// unreadable without the derived passphrase.
//
// Provenance: ADR-027 (Android Platform Adapter), ADR-006 (Platform Abstraction Layer),
// ADR-025 (Apple Platform Adapter — parallel reference), section 17 (Persistence Architecture).

package com.limn.scp.android.platform

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
 * Implements the [StorageProvider] interface (mirroring the Rust `Storage` trait
 * from `scp-platform/src/traits.rs`). This class is injected into the Rust engine via
 * the UniFFI callback interface at `SCP.create()` time; all storage operations are
 * dispatched from Rust through the UniFFI boundary into this class.
 *
 * ## Encryption architecture
 *
 * The database encryption key is derived through a TEE-backed chain of trust:
 *
 * 1. Android Keystore holds an AES-256-GCM key (alias: `scp.storage.key`) inside the TEE.
 *    The key is generated on first use and persists across app restarts.
 * 2. The Keystore key encrypts a fixed label (`"scp-storage-passphrase"`) using AES-GCM
 *    with a fixed 12-byte zero IV. The fixed IV produces a deterministic ciphertext that
 *    serves as the SQLCipher passphrase.
 * 3. SQLCipher uses this 32-byte passphrase for full-database encryption.
 *
 * The Keystore key bytes never leave the TEE. The derived passphrase exists in memory
 * only during database open and is not persisted to disk in plaintext.
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
     * Retrieve or generate the TEE-backed AES-256 key, then derive the SQLCipher passphrase.
     *
     * The Keystore key is generated on first call and persists in hardware. Subsequent calls
     * retrieve the existing key. The derived passphrase is deterministic for a given Keystore
     * key (fixed IV, fixed plaintext label).
     *
     * @return 32-byte SQLCipher passphrase derived from the TEE key.
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
            // The actual key bytes never leave the TEE — this pattern uses AES-GCM with a deterministic
            // IV to produce a stable 32-byte value for the SQLCipher passphrase.
            val secretKey = keyStore.getKey(KEY_ALIAS, null) as SecretKey
            val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION).apply {
                init(
                    Cipher.ENCRYPT_MODE,
                    secretKey,
                    GCMParameterSpec(GCM_TAG_LENGTH_BITS, ByteArray(GCM_IV_LENGTH))
                )
            }
            val ciphertext = cipher.doFinal(DERIVATION_LABEL.toByteArray(Charsets.UTF_8))
            // Take first 32 bytes of the ciphertext (which includes ciphertext + GCM tag)
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


        /** Android Keystore provider name. */
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"

        /** Alias for the TEE-backed AES-256 storage encryption key. */
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
