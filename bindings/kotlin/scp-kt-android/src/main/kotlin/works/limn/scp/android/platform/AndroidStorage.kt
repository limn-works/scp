// AndroidStorage.kt — StorageProvider implementation for Android (ADR-027)
//
// Encrypted key-value storage using SQLCipher. A non-exportable HMAC-SHA-256 key in
// Android Keystore MACs a fixed label, and HKDF-SHA-256 derives the 32-byte SQLCipher
// key from that MAC output under the salt and info of section 17.6 of
// .docs/specs/17-persistence-and-storage.md. The adapter passes the key to SQLCipher
// in raw-key syntax, so SQLCipher runs no second KDF over it. The adapter does not read
// KeyInfo.securityLevel, so it does not know whether Keystore put the HMAC key in the
// TEE or, on a device whose KeyMint runs in software, in software.
//
// The database file is "scp.db" in the application's noBackupFilesDir directory.
// This directory is excluded from Android Auto Backup, ensuring that SQLCipher
// databases protected by Keystore-derived keys are not backed up to Google Drive
// (where the Keystore key would not be available to decrypt them).
// SQLCipher provides transparent full-database encryption — the OS file is
// unreadable without the derived passphrase.
//
// Provenance: ADR-027 (Android Platform Adapter), ADR-006 (Platform Abstraction Layer),
// ADR-025 (Apple Platform Adapter — parallel reference), section 17.6 of
// .docs/specs/17-persistence-and-storage.md (SQLCipher key derivation), RFC 5869 (HKDF).

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
 * Implements the Kotlin [StorageProvider] interface in `Types.kt`, whose KDoc states how it
 * differs from the Rust `Storage` trait and from the UniFFI `StorageProvider` callback
 * interface. No code passes this class to the Rust engine, because the UniFFI bridge has no
 * function that accepts a storage provider.
 *
 * ## Encryption architecture
 *
 * Section 17.6 of `.docs/specs/17-persistence-and-storage.md` fixes the SQLCipher key
 * derivation, and the adapter follows it:
 *
 * 1. Android Keystore holds a 256-bit HMAC-SHA-256 key (alias: `scp.storage.key`,
 *    purpose `PURPOSE_SIGN`). The key is generated on first use, persists across app
 *    restarts, and is not exportable. The adapter does not read `KeyInfo.securityLevel`,
 *    so it does not know whether Keystore put the key in the TEE or, on a device whose
 *    KeyMint runs in software, in software.
 * 2. Keystore computes `ikm = HMAC-SHA-256(keystore_key, "scp-storage-passphrase")`. HMAC
 *    is deterministic and takes no nonce, so the same Keystore key yields the same 32
 *    bytes on every open and nothing is stored beside the database.
 * 3. HKDF-SHA-256 derives the 32-byte key: salt `SHA-256("SCP-SQLCIPHER-KEY-V1")`, info
 *    `"scp-sqlcipher:" || identifier`, where the identifier is the 32-byte SHA-256 digest
 *    of the database directory's absolute path. Two storage directories therefore get two
 *    keys, and one directory gets the same key on every open.
 * 4. The adapter hands SQLCipher the key as the raw-key literal `x'<64 hex>'`, so SQLCipher
 *    uses the 32 bytes as the database key and runs no PBKDF2 over them.
 *
 * Section 17.6 says the identifier binds the database to one identity. This adapter opens
 * its database before any identity loads, and it keeps one database per storage directory,
 * so the directory digest is the identifier. A move of the app's data directory to another
 * path changes the key, and the open then fails: SQLCipher rejects the existing file, and
 * the adapter never creates a fresh database in its place.
 *
 * Keystore does not hand the HMAC key bytes to the app. The derived key is not persisted
 * to disk, but key material stays in process memory: SQLCipher keeps the database key in
 * native memory for as long as the database is open. The adapter zeroes the MAC output,
 * the HKDF output and the raw-key literal once each has been used; the JCA `Mac` objects
 * keep their internal state until garbage collection.
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

    /**
     * Directory that holds [DATABASE_NAME]: the app's `noBackupFilesDir`, which Android Auto
     * Backup excludes. A backed-up database would be unreadable on another device, because
     * the Keystore key that derives its SQLCipher key is device-bound. The HKDF info binds
     * this directory, so the open and the derivation both read it here.
     */
    private val databaseDirectory: File
        get() = context.noBackupFilesDir

    private fun openEncryptedDatabase(): SQLiteDatabase {
        System.loadLibrary("sqlcipher")
        val encryptionKey = getOrCreateStorageKey()
        try {
            // The raw-key literal is passed as byte[] to the SQLiteOpenHelper constructor,
            // which hands it to sqlite3_key; SQLCipher reads the x'..' form as the key itself.
            // The literal is zeroed in the finally block. The protection is the Keystore
            // key: the literal cannot be recomputed without it.
            val dbPath = File(databaseDirectory, DATABASE_NAME).absolutePath
            val helper = ScpDatabaseHelper(context, dbPath, encryptionKey)
            return helper.writableDatabase
        } finally {
            // Zero the key literal immediately after use to limit the exposure window.
            encryptionKey.fill(0)
        }
    }

    /**
     * Retrieves or generates the Keystore-held HMAC-SHA-256 key, then derives the SQLCipher
     * key from it as section 17.6 requires.
     *
     * The Keystore key is generated on first call and persists in Android Keystore.
     * Subsequent calls retrieve the existing key. HMAC is deterministic, so the same
     * Keystore key, the fixed [DERIVATION_LABEL] and the same [databaseDirectory] always
     * yield the same result.
     *
     * @return the SQLCipher raw-key literal `x'<64 hex>'` as ASCII bytes; see
     *   [derivePassphrase].
     * @throws ScpException with code `SCP-STORAGE-8003` if a Keystore, key-generation or
     *   MAC call throws a `GeneralSecurityException`, including the `InvalidKeyException`
     *   `Mac.init` throws when the alias holds a key that is not an HMAC-SHA-256 key. Every
     *   other failure propagates unconverted, for example the `IOException` from
     *   `KeyStore.load`, a `ProviderException` from Keystore key generation, or the
     *   `NullPointerException` the `as SecretKey` cast throws when `KeyStore.getKey`
     *   returns `null`.
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

            // Keystore computes one HMAC over the fixed label; the key bytes never reach
            // the app, and HMAC takes no nonce, so nothing is stored beside the database.
            val secretKey = keyStore.getKey(KEY_ALIAS, null) as SecretKey
            val ikm = Mac.getInstance(MAC_ALGORITHM)
                .apply { init(secretKey) }
                .doFinal(DERIVATION_LABEL.toByteArray(Charsets.UTF_8))
            try {
                return derivePassphrase(ikm)
            } finally {
                ikm.fill(0)
            }
        } catch (e: ScpException) {
            throw e
        } catch (e: GeneralSecurityException) {
            throw ScpException("Storage encryption key derivation failed", ERROR_KEY_DERIVATION_FAILED, e)
        }
    }

    /**
     * Derives this instance's SQLCipher raw-key literal from the Keystore MAC output [ikm].
     *
     * Calls [deriveDatabaseKey] with [databaseDirectory] and encodes the result with
     * [rawKeyLiteral]. It reads no Keystore state, so a JVM unit test can show that two
     * instances over one directory agree and that two directories disagree.
     *
     * @param ikm the 32-byte HMAC that the Keystore key computes over [DERIVATION_LABEL].
     * @return the ASCII bytes of `x'<64 hex>'`; the caller zeroes them after use.
     */
    internal fun derivePassphrase(ikm: ByteArray): ByteArray {
        val key = deriveDatabaseKey(ikm, databaseDirectory)
        try {
            return rawKeyLiteral(key)
        } finally {
            key.fill(0)
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

        /**
         * HKDF-SHA-256 from section 17.6 of `.docs/specs/17-persistence-and-storage.md`:
         * salt `SHA-256("SCP-SQLCIPHER-KEY-V1")`, info `"scp-sqlcipher:" || identifier`,
         * 32 bytes out. The identifier is [directoryIdentifier] of [databaseDirectory].
         *
         * @param ikm input keying material, the Keystore MAC output.
         * @param databaseDirectory directory holding [DATABASE_NAME].
         * @return the 32-byte SQLCipher key; the caller zeroes it after use.
         */
        internal fun deriveDatabaseKey(ikm: ByteArray, databaseDirectory: File): ByteArray = Hkdf.sha256(
            ikm = ikm,
            salt = sha256(SQLCIPHER_SALT_LABEL.toByteArray(Charsets.UTF_8)),
            info = SQLCIPHER_INFO_PREFIX.toByteArray(Charsets.UTF_8) + directoryIdentifier(databaseDirectory),
            length = DATABASE_KEY_LENGTH,
        )

        /** The 32-byte SHA-256 digest of [directory]'s absolute path in UTF-8. */
        internal fun directoryIdentifier(directory: File): ByteArray =
            sha256(directory.absolutePath.toByteArray(Charsets.UTF_8))

        /**
         * Encodes [key] as SQLCipher's raw-key literal `x'<lowercase hex>'` in ASCII bytes.
         *
         * Section 17.6 requires this form: SQLCipher uses the hex-decoded bytes as the
         * database key, where a plain passphrase would get a second, redundant PBKDF2. The
         * bytes are built directly, never through a `String`, so the caller can zero them.
         */
        internal fun rawKeyLiteral(key: ByteArray): ByteArray {
            val out = ByteArray(key.size * 2 + RAW_KEY_FRAMING_BYTES)
            out[0] = 'x'.code.toByte()
            out[1] = '\''.code.toByte()
            key.forEachIndexed { i, b ->
                out[2 + i * 2] = HEX_DIGITS[(b.toInt() shr 4) and 0x0F]
                out[3 + i * 2] = HEX_DIGITS[b.toInt() and 0x0F]
            }
            out[out.size - 1] = '\''.code.toByte()
            return out
        }

        private fun sha256(input: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(input)

        private val HEX_DIGITS = "0123456789abcdef".toByteArray(Charsets.US_ASCII)

        /** `x'` before the hex digits and `'` after them. */
        private const val RAW_KEY_FRAMING_BYTES = 3

        /** Android Keystore provider name. */
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"

        /** Alias for the Keystore-held HMAC-SHA-256 key that derives the SQLCipher key. */
        internal const val KEY_ALIAS = "scp.storage.key"

        /** Keystore HMAC key size in bits. */
        private const val KEY_SIZE_BITS = 256

        /**
         * Algorithm of the Keystore key and of the MAC computed under it. It equals
         * `KeyProperties.KEY_ALGORITHM_HMAC_SHA256`; a JVM unit test reads this constant,
         * where the Android stub would return a default.
         */
        internal const val MAC_ALGORITHM = "HmacSHA256"

        /** Fixed label the Keystore key MACs to produce the HKDF input keying material. */
        internal const val DERIVATION_LABEL = "scp-storage-passphrase"

        /** Label hashed to form the HKDF salt (section 17.6). */
        internal const val SQLCIPHER_SALT_LABEL = "SCP-SQLCIPHER-KEY-V1"

        /** HKDF info prefix (section 17.6); the 32-byte directory identifier follows it. */
        internal const val SQLCIPHER_INFO_PREFIX = "scp-sqlcipher:"

        /** Length of the derived SQLCipher key in bytes (section 17.6). */
        internal const val DATABASE_KEY_LENGTH = 32

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

        /**
         * Error code: the Keystore key or the SQLCipher key derivation threw a
         * `GeneralSecurityException`. [AndroidStorage.getOrCreateStorageKey] lists the
         * failures it does not convert.
         */
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
