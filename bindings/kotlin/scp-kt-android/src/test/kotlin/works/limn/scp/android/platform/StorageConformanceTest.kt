// StorageConformanceTest.kt — Storage trait conformance tests (SCP-PERSIST-060)
//
// Kotlin JUnit 5 port of the Rust `storage_conformance!()` macro (SCP-PERSIST-030).
// Exercises all 13 conformance cases against two StorageProvider test doubles:
//
// 1. InMemoryStorageProvider  — ConcurrentHashMap-backed, validates interface contract
// 2. SqliteStorageProvider    — org.xerial:sqlite-jdbc on JVM, validates the SQL paths
//                               (schema, LIKE escaping, ORDER BY, WITHOUT ROWID)
//
// The production AndroidStorage uses SQLCipher (net.zetetic:sqlcipher-android) with
// TEE-derived encryption, which requires Android hardware. These tests exercise the
// same SQL statements against unencrypted JVM SQLite to verify correctness of the
// query logic without Android runtime dependencies.
//
// Provenance: ADR-027 (Android Platform Adapter), ADR-006 (Platform Abstraction Layer),
// section 17 (Persistence Architecture), SCP-PERSIST-030 (storage_conformance!() macro).

package works.limn.scp.android.platform

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.sql.Connection
import java.sql.DriverManager
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

// ---------------------------------------------------------------------------
// SqliteStorageProvider — JVM SQLite test double
// ---------------------------------------------------------------------------

/**
 * [StorageProvider] backed by JVM SQLite (org.xerial:sqlite-jdbc).
 *
 * Uses the same SQL statements and schema as the production [AndroidStorage] class,
 * but runs on a plain JVM without encryption. This validates the SQL query logic
 * (LIKE escaping, ORDER BY, WITHOUT ROWID, INSERT OR REPLACE, changes()) without
 * requiring Android platform APIs.
 *
 * Each instance creates an in-memory SQLite database (`jdbc:sqlite::memory:`) so
 * tests are isolated and fast. The [close] method releases the JDBC connection.
 */
class SqliteStorageProvider : StorageProvider, AutoCloseable {

    /** Lock object for serializing all database access. JDBC connections are not thread-safe. */
    private val lock = Any()

    private val conn: Connection = DriverManager.getConnection("jdbc:sqlite::memory:").also { c ->
        c.createStatement().use { stmt ->
            stmt.execute(
                """
                CREATE TABLE IF NOT EXISTS ${AndroidStorage.TABLE_NAME} (
                    ${AndroidStorage.COLUMN_KEY} TEXT PRIMARY KEY,
                    ${AndroidStorage.COLUMN_VALUE} BLOB NOT NULL
                ) WITHOUT ROWID
                """.trimIndent()
            )
        }
    }

    override fun set(key: String, data: ByteArray): Unit = synchronized(lock) {
        conn.prepareStatement(
            "INSERT OR REPLACE INTO ${AndroidStorage.TABLE_NAME} " +
                "(${AndroidStorage.COLUMN_KEY}, ${AndroidStorage.COLUMN_VALUE}) VALUES (?, ?)"
        ).use { ps ->
            ps.setString(1, key)
            ps.setBytes(2, data)
            ps.executeUpdate()
        }
    }

    override fun get(key: String): ByteArray? = synchronized(lock) {
        conn.prepareStatement(
            "SELECT ${AndroidStorage.COLUMN_VALUE} FROM ${AndroidStorage.TABLE_NAME} " +
                "WHERE ${AndroidStorage.COLUMN_KEY} = ?"
        ).use { ps ->
            ps.setString(1, key)
            ps.executeQuery().use { rs ->
                return if (rs.next()) rs.getBytes(1) else null
            }
        }
    }

    override fun delete(key: String): Unit = synchronized(lock) {
        conn.prepareStatement(
            "DELETE FROM ${AndroidStorage.TABLE_NAME} WHERE ${AndroidStorage.COLUMN_KEY} = ?"
        ).use { ps ->
            ps.setString(1, key)
            ps.executeUpdate()
        }
    }

    override fun listKeys(prefix: String): List<String> = synchronized(lock) {
        val escaped = escapeLikePrefix(prefix)
        conn.prepareStatement(
            "SELECT ${AndroidStorage.COLUMN_KEY} FROM ${AndroidStorage.TABLE_NAME} " +
                "WHERE ${AndroidStorage.COLUMN_KEY} LIKE ? ESCAPE '\\' " +
                "ORDER BY ${AndroidStorage.COLUMN_KEY} ASC"
        ).use { ps ->
            ps.setString(1, "$escaped%")
            ps.executeQuery().use { rs ->
                return buildList {
                    while (rs.next()) {
                        add(rs.getString(1))
                    }
                }
            }
        }
    }

    override fun deletePrefix(prefix: String): Long = synchronized(lock) {
        val escaped = escapeLikePrefix(prefix)
        conn.prepareStatement(
            "DELETE FROM ${AndroidStorage.TABLE_NAME} " +
                "WHERE ${AndroidStorage.COLUMN_KEY} LIKE ? ESCAPE '\\'"
        ).use { ps ->
            ps.setString(1, "$escaped%")
            return ps.executeUpdate().toLong()
        }
    }

    override fun exists(key: String): Boolean = synchronized(lock) {
        conn.prepareStatement(
            "SELECT 1 FROM ${AndroidStorage.TABLE_NAME} " +
                "WHERE ${AndroidStorage.COLUMN_KEY} = ? LIMIT 1"
        ).use { ps ->
            ps.setString(1, key)
            ps.executeQuery().use { rs ->
                return rs.next()
            }
        }
    }

    override fun close() {
        synchronized(lock) {
            conn.close()
        }
    }

    companion object {
        /** Mirrors [AndroidStorage.escapeLikePrefix] for SQL LIKE wildcard escaping. */
        private fun escapeLikePrefix(prefix: String): String =
            prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    }
}

// ---------------------------------------------------------------------------
// Conformance test suite — parameterized over StorageProvider implementations
// ---------------------------------------------------------------------------

/**
 * Abstract base class containing all 13 storage conformance test cases.
 *
 * Subclasses provide a concrete [StorageProvider] via [createProvider]. Test names
 * match the Rust `storage_conformance!()` macro test functions for traceability.
 */
abstract class StorageConformanceBase {

    protected lateinit var storage: StorageProvider

    abstract fun createProvider(): StorageProvider

    @BeforeEach
    fun setUp() {
        storage = createProvider()
    }

    // -- 1. roundtrip --

    @Test
    fun `roundtrip - store and retrieve returns identical bytes`() {
        val key = "conformance.roundtrip"
        val value = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())
        storage.set(key, value)
        val retrieved = storage.get(key)
        assertNotNull(retrieved)
        assertArrayEquals(value, retrieved)
    }

    // -- 2. missing_returns_none --

    @Test
    fun `missing_returns_none - retrieve absent key returns null`() {
        val result = storage.get("conformance.missing")
        assertNull(result)
    }

    // -- 3. delete_removes --

    @Test
    fun `delete_removes - delete then retrieve returns null`() {
        val key = "conformance.delete"
        storage.set(key, "data".toByteArray())
        storage.delete(key)
        assertNull(storage.get(key))
    }

    // -- 4. list_keys_sorted --

    @Test
    fun `list_keys_sorted - listKeys returns all keys in lexicographic order`() {
        storage.set("charlie", "c".toByteArray())
        storage.set("alpha", "a".toByteArray())
        storage.set("bravo", "b".toByteArray())
        val keys = storage.listKeys("")
        assertEquals(listOf("alpha", "bravo", "charlie"), keys)
    }

    // -- 5. list_keys_prefix_sorted --

    @Test
    fun `list_keys_prefix_sorted - listKeys filters by prefix and returns sorted`() {
        storage.set("scp.context.1", "a".toByteArray())
        storage.set("scp.context.2", "b".toByteArray())
        storage.set("scp.key.1", "c".toByteArray())
        storage.set("other.data", "d".toByteArray())
        val contextKeys = storage.listKeys("scp.context.")
        assertEquals(listOf("scp.context.1", "scp.context.2"), contextKeys)
    }

    // -- 6. delete_prefix_removes --

    @Test
    fun `delete_prefix_removes - deletePrefix removes matching keys`() {
        storage.set("ctx.1", "a".toByteArray())
        storage.set("ctx.2", "b".toByteArray())
        storage.set("ctx.3", "c".toByteArray())
        storage.set("other.1", "d".toByteArray())
        storage.deletePrefix("ctx.")
        assertNull(storage.get("ctx.1"))
        assertNull(storage.get("ctx.2"))
        assertNull(storage.get("ctx.3"))
        assertArrayEquals("d".toByteArray(), storage.get("other.1"))
    }

    // -- 7. delete_prefix_zero --

    @Test
    fun `delete_prefix_zero - deletePrefix with no matches returns zero`() {
        storage.set("key1", "data".toByteArray())
        val deleted = storage.deletePrefix("nonexistent.")
        assertEquals(0L, deleted)
        assertTrue(storage.exists("key1"))
    }

    // -- 8. exists_true --

    @Test
    fun `exists_true - exists returns true for present key`() {
        storage.set("present", "data".toByteArray())
        assertTrue(storage.exists("present"))
    }

    // -- 9. exists_false --

    @Test
    fun `exists_false - exists returns false for missing key`() {
        assertFalse(storage.exists("absent"))
    }

    // -- 10. exists_after_delete --

    @Test
    fun `exists_after_delete - exists returns false after deletion`() {
        storage.set("temp", "data".toByteArray())
        storage.delete("temp")
        assertFalse(storage.exists("temp"))
    }

    // -- 11. overwrite --

    @Test
    fun `overwrite - store replaces existing value for same key`() {
        val key = "overwrite.key"
        storage.set(key, "first".toByteArray())
        storage.set(key, "second".toByteArray())
        assertArrayEquals("second".toByteArray(), storage.get(key))
    }

    // -- 12. concurrent_access --

    @Test
    fun `concurrent_access - stores from multiple threads do not interfere`() {
        val threadCount = 8
        val keysPerThread = 50
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(threadCount)

        for (t in 0 until threadCount) {
            executor.submit {
                try {
                    for (i in 0 until keysPerThread) {
                        val key = "thread.$t.key.$i"
                        storage.set(key, key.toByteArray())
                    }
                } finally {
                    latch.countDown()
                }
            }
        }

        assertTrue(latch.await(10, TimeUnit.SECONDS), "Concurrent stores should complete within timeout")
        executor.shutdown()

        // Verify all keys are present and correct
        for (t in 0 until threadCount) {
            for (i in 0 until keysPerThread) {
                val key = "thread.$t.key.$i"
                val retrieved = storage.get(key)
                assertNotNull(retrieved, "Key $key should be present after concurrent store")
                assertArrayEquals(key.toByteArray(), retrieved, "Value for $key should match")
            }
        }

        val totalKeys = storage.listKeys("thread.").size
        assertEquals(threadCount * keysPerThread, totalKeys)
    }

    // -- 13. store_empty_value --

    @Test
    fun `store_empty_value - empty byte array round-trips correctly`() {
        val key = "empty.value"
        val value = ByteArray(0)
        storage.set(key, value)
        val retrieved = storage.get(key)
        assertNotNull(retrieved)
        assertEquals(0, retrieved!!.size)
    }

    // -- Additional: delete_prefix_returns_count --

    @Test
    fun `delete_prefix_returns_count - deletePrefix returns number of deleted keys`() {
        storage.set("batch.1", "a".toByteArray())
        storage.set("batch.2", "b".toByteArray())
        storage.set("batch.3", "c".toByteArray())
        storage.set("other.1", "d".toByteArray())
        val deleted = storage.deletePrefix("batch.")
        assertEquals(3L, deleted)
    }

    // -- Additional: list_keys_returns_sorted (lexicographic with numeric suffixes) --

    @Test
    fun `list_keys_returns_sorted - lexicographic order handles numeric suffixes`() {
        // Lexicographic: "10" < "2" < "9" (string ordering, not numeric)
        storage.set("key.10", "a".toByteArray())
        storage.set("key.2", "b".toByteArray())
        storage.set("key.9", "c".toByteArray())
        val keys = storage.listKeys("key.")
        assertEquals(listOf("key.10", "key.2", "key.9"), keys)
    }
}

// ---------------------------------------------------------------------------
// Concrete test classes — one per StorageProvider implementation
// ---------------------------------------------------------------------------

/**
 * Conformance tests against [InMemoryStorageProvider].
 *
 * Validates the StorageProvider interface contract using the in-memory test double.
 * This exercises the same logical behavior as the Rust `storage_conformance!()` macro
 * run against `InMemoryStorage`.
 */
class InMemoryStorageConformanceTest : StorageConformanceBase() {
    override fun createProvider(): StorageProvider = InMemoryStorageProvider()
}

/**
 * Conformance tests against [SqliteStorageProvider].
 *
 * Validates the SQL query paths (INSERT OR REPLACE, LIKE with escaping, ORDER BY,
 * WITHOUT ROWID schema, changes() count) using JVM SQLite (org.xerial:sqlite-jdbc).
 * This exercises the same SQL statements that the production [AndroidStorage] uses
 * via SQLCipher, without requiring Android runtime.
 */
class SqliteStorageConformanceTest : StorageConformanceBase() {

    private lateinit var sqliteProvider: SqliteStorageProvider

    override fun createProvider(): StorageProvider {
        sqliteProvider = SqliteStorageProvider()
        return sqliteProvider
    }

    @AfterEach
    fun tearDown() {
        if (::sqliteProvider.isInitialized) {
            sqliteProvider.close()
        }
    }

    // -- SQL-specific tests not covered by the base conformance suite --

    @Nested
    inner class SqlSpecific {

        @Test
        fun `LIKE wildcard in key name does not cause false matches`() {
            storage.set("a%b", "percent".toByteArray())
            storage.set("a_b", "underscore".toByteArray())
            storage.set("axb", "no-match".toByteArray())
            storage.set("ab", "no-match".toByteArray())

            // Prefix "a%" should match only "a%b", not "axb" or "ab"
            val percentKeys = storage.listKeys("a%")
            assertEquals(listOf("a%b"), percentKeys)

            // Prefix "a_" should match only "a_b", not "axb"
            val underscoreKeys = storage.listKeys("a_")
            assertEquals(listOf("a_b"), underscoreKeys)
        }

        @Test
        fun `deletePrefix with LIKE wildcards in prefix only deletes exact prefix matches`() {
            storage.set("test%key.1", "a".toByteArray())
            storage.set("test%key.2", "b".toByteArray())
            storage.set("testXkey.1", "c".toByteArray())

            val deleted = storage.deletePrefix("test%key.")
            assertEquals(2L, deleted)
            assertNull(storage.get("test%key.1"))
            assertNull(storage.get("test%key.2"))
            assertArrayEquals("c".toByteArray(), storage.get("testXkey.1"))
        }

        @Test
        fun `backslash in key name round-trips correctly`() {
            val key = "path\\to\\key"
            val value = "backslash".toByteArray()
            storage.set(key, value)
            assertArrayEquals(value, storage.get(key))
            assertTrue(storage.exists(key))
        }

        @Test
        fun `large binary value round-trips through SQL`() {
            val key = "large.blob"
            val value = ByteArray(65536) { (it % 256).toByte() }
            storage.set(key, value)
            val retrieved = storage.get(key)
            assertNotNull(retrieved)
            assertArrayEquals(value, retrieved)
        }

        @Test
        fun `deletePrefix with empty prefix deletes all keys`() {
            storage.set("a", "1".toByteArray())
            storage.set("b", "2".toByteArray())
            storage.set("c", "3".toByteArray())
            val deleted = storage.deletePrefix("")
            assertEquals(3L, deleted)
            assertEquals(emptyList<String>(), storage.listKeys(""))
        }
    }
}
