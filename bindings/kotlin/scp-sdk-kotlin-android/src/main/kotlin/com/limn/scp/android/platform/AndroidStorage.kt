// AndroidStorage.kt — StorageProvider implementation for Android (ADR-027)
//
// Encrypted key-value storage using SQLCipher. The database encryption key is a
// 32-byte value derived from a TEE-backed AES-256 key in Android Keystore. The
// Keystore key never leaves the TEE; it encrypts a fixed label via AES-GCM to
// produce a deterministic 32-byte passphrase for SQLCipher. This gives the
// database a hardware-rooted chain of trust without requiring SQLCipher itself
// to understand Android Keystore.
//
// The database file is "scp.db" in the application's private database directory.
// SQLCipher provides transparent full-database encryption — the OS file is
// unreadable without the derived passphrase.
//
// Provenance: ADR-027 (Android Platform Adapter), ADR-006 (Platform Abstraction Layer),
// ADR-025 (Apple Platform Adapter — parallel reference), section 17 (Persistence Architecture).

package com.limn.scp.android.platform

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import net.sqlcipher.database.SQLiteDatabase
import net.sqlcipher.database.SQLiteOpenHelper
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
        SQLiteDatabase.loadLibs(context)
        val encryptionKey = getOrCreateStorageKey()
        val passphrase = String(encryptionKey, Charsets.ISO_8859_1)
        val helper = ScpDatabaseHelper(context)
        return helper.getWritableDatabase(passphrase)
    }

    /**
     * Retrieve or generate the TEE-backed AES-256 key, then derive the SQLCipher passphrase.
     *
     * The Keystore key is generated on first call and persists in hardware. Subsequent calls
     * retrieve the existing key. The derived passphrase is deterministic for a given Keystore
     * key (fixed IV, fixed plaintext label).
     *
     * @return 32-byte SQLCipher passphrase derived from the TEE key.
     * @throws ScpException with code `SCP-STORAGE-6003` if key derivation fails.
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
        } catch (e: Exception) {
            if (e is ScpException) throw e
            throw ScpException(
                "Failed to derive storage encryption key: ${e.message}",
                ERROR_KEY_DERIVATION_FAILED
            )
        }
    }

    override fun store(key: String, data: ByteArray) {
        try {
            db.execSQL(
                "INSERT OR REPLACE INTO $TABLE_NAME ($COLUMN_KEY, $COLUMN_VALUE) VALUES (?, ?)",
                arrayOf(key, data)
            )
        } catch (e: Exception) {
            if (e is ScpException) throw e
            throw ScpException(
                "Storage store failed for key '$key': ${e.message}",
                ERROR_STORAGE_OPERATION_FAILED
            )
        }
    }

    override fun retrieve(key: String): ByteArray? {
        try {
            val cursor = db.rawQuery(
                "SELECT $COLUMN_VALUE FROM $TABLE_NAME WHERE $COLUMN_KEY = ?",
                arrayOf(key)
            )
            return cursor.use {
                if (it.moveToFirst()) it.getBlob(0) else null
            }
        } catch (e: Exception) {
            if (e is ScpException) throw e
            throw ScpException(
                "Storage retrieve failed for key '$key': ${e.message}",
                ERROR_STORAGE_OPERATION_FAILED
            )
        }
    }

    override fun delete(key: String) {
        try {
            db.execSQL(
                "DELETE FROM $TABLE_NAME WHERE $COLUMN_KEY = ?",
                arrayOf<Any>(key)
            )
        } catch (e: Exception) {
            if (e is ScpException) throw e
            throw ScpException(
                "Storage delete failed for key '$key': ${e.message}",
                ERROR_STORAGE_OPERATION_FAILED
            )
        }
    }

    override fun listKeys(prefix: String): List<String> {
        try {
            val cursor = db.rawQuery(
                "SELECT $COLUMN_KEY FROM $TABLE_NAME WHERE $COLUMN_KEY LIKE ? ORDER BY $COLUMN_KEY ASC",
                arrayOf("$prefix%")
            )
            return cursor.use {
                buildList {
                    while (it.moveToNext()) {
                        add(it.getString(0))
                    }
                }
            }
        } catch (e: Exception) {
            if (e is ScpException) throw e
            throw ScpException(
                "Storage listKeys failed for prefix '$prefix': ${e.message}",
                ERROR_STORAGE_OPERATION_FAILED
            )
        }
    }

    override fun deletePrefix(prefix: String): Long {
        try {
            db.execSQL(
                "DELETE FROM $TABLE_NAME WHERE $COLUMN_KEY LIKE ?",
                arrayOf<Any>("$prefix%")
            )
            val cursor = db.rawQuery("SELECT changes()", emptyArray())
            return cursor.use {
                if (it.moveToFirst()) it.getLong(0) else 0L
            }
        } catch (e: Exception) {
            if (e is ScpException) throw e
            throw ScpException(
                "Storage deletePrefix failed for prefix '$prefix': ${e.message}",
                ERROR_STORAGE_OPERATION_FAILED
            )
        }
    }

    override fun exists(key: String): Boolean {
        try {
            val cursor = db.rawQuery(
                "SELECT 1 FROM $TABLE_NAME WHERE $COLUMN_KEY = ? LIMIT 1",
                arrayOf(key)
            )
            return cursor.use { it.moveToFirst() }
        } catch (e: Exception) {
            if (e is ScpException) throw e
            throw ScpException(
                "Storage exists check failed for key '$key': ${e.message}",
                ERROR_STORAGE_OPERATION_FAILED
            )
        }
    }

    companion object {
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
        internal const val ERROR_KEY_NOT_FOUND = "SCP-STORAGE-6001"

        /** Error code: storage operation failed. */
        internal const val ERROR_STORAGE_OPERATION_FAILED = "SCP-STORAGE-6002"

        /** Error code: storage encryption key derivation failed. */
        internal const val ERROR_KEY_DERIVATION_FAILED = "SCP-STORAGE-6003"
    }
}

/**
 * SQLiteOpenHelper for the SCP encrypted key-value database.
 *
 * Creates the `kv` table with a unique `key` column (TEXT) and a `value` column (BLOB)
 * on first database creation. The `key` column has a UNIQUE constraint to enforce
 * INSERT OR REPLACE semantics.
 */
internal class ScpDatabaseHelper(
    context: Context,
) : SQLiteOpenHelper(
    context,
    AndroidStorage.DATABASE_NAME,
    null,
    AndroidStorage.DATABASE_VERSION
) {
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS ${AndroidStorage.TABLE_NAME} (
                ${AndroidStorage.COLUMN_KEY} TEXT NOT NULL UNIQUE,
                ${AndroidStorage.COLUMN_VALUE} BLOB NOT NULL
            )
            """.trimIndent()
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // v1 is the initial schema. Future migrations will be added here.
    }
}
