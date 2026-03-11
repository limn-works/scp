// AndroidStorageTest.kt — Unit tests for AndroidStorage (SCP-113)
//
// IMPORTANT: These are IN-MEMORY-ONLY tests. All StorageProvider contract tests run
// against InMemoryStorageProvider, NOT the real AndroidStorage implementation. The
// following production behaviors are NOT exercised by these tests:
//   - Android Keystore TEE key derivation (Bug #2: setRandomizedEncryptionRequired)
//   - SQLCipher SQL LIKE escaping with % and _ wildcards (Bug #4)
//   - Non-atomic deletePrefix under concurrent access (Bug #5)
//   - Passphrase ByteArray zeroing after database open (Bug #3)
//
// Instrumented tests on real devices are required to verify the full SQLCipher +
// Android Keystore path. See ADR-027 for the testing strategy.
//
// Test strategies:
//
// 1. **Contract tests**: Verify the StorageProvider interface contract using an
//    InMemoryStorageProvider that mirrors the production AndroidStorage semantics
//    (INSERT OR REPLACE, lexicographic ordering, prefix matching). These tests
//    validate that any conforming StorageProvider implementation behaves correctly.
//
// 2. **AndroidStorage verification tests**: Verify that AndroidStorage uses the
//    correct Keystore alias, error codes, and constant values. These verify the
//    production class structure without requiring Android runtime dependencies.
//
// Provenance: ADR-027 (Android Platform Adapter), ADR-006 (Platform Abstraction Layer),
// SCP-113 (Android Storage trait with TEE-backed SQLCipher).

package works.limn.scp.android.platform

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.util.TreeMap

/**
 * In-memory implementation of [StorageProvider] for contract testing.
 *
 * Mirrors the SQLCipher-backed production semantics: INSERT OR REPLACE on store,
 * lexicographic ordering on listKeys, prefix-based matching, and cursor-style
 * retrieval. This implementation validates the StorageProvider contract without
 * requiring Android runtime dependencies.
 */
class InMemoryStorageProvider : StorageProvider {

    // TreeMap provides natural lexicographic ordering, matching SQLCipher's
    // ORDER BY key ASC behavior.
    private val data = TreeMap<String, ByteArray>()

    override fun set(key: String, data: ByteArray) {
        this.data[key] = data.copyOf()
    }

    override fun get(key: String): ByteArray? {
        return data[key]?.copyOf()
    }

    override fun delete(key: String) {
        data.remove(key)
    }

    override fun listKeys(prefix: String): List<String> {
        return data.keys.filter { it.startsWith(prefix) }
    }

    override fun deletePrefix(prefix: String): Long {
        val keysToDelete = data.keys.filter { it.startsWith(prefix) }
        keysToDelete.forEach { data.remove(it) }
        return keysToDelete.size.toLong()
    }

    override fun exists(key: String): Boolean {
        return data.containsKey(key)
    }
}

/**
 * Unit tests for the [StorageProvider] contract and [AndroidStorage] structure.
 */
class AndroidStorageTest {

    private lateinit var storage: StorageProvider

    @BeforeEach
    fun setUp() {
        storage = InMemoryStorageProvider()
    }

    // -------------------------------------------------------------------
    // Store and retrieve round-trip
    // -------------------------------------------------------------------

    @Nested
    inner class StoreAndRetrieve {

        @Test
        fun `store then retrieve returns same bytes`() {
            val key = "test.key"
            val value = "hello world".toByteArray()
            storage.set(key, value)
            val retrieved = storage.get(key)
            assertNotNull(retrieved)
            assertArrayEquals(value, retrieved)
        }

        @Test
        fun `store then retrieve with binary data preserves bytes`() {
            val key = "binary.key"
            val value = byteArrayOf(0x00, 0x01, 0xFF.toByte(), 0x7F, 0x80.toByte())
            storage.set(key, value)
            val retrieved = storage.get(key)
            assertNotNull(retrieved)
            assertArrayEquals(value, retrieved)
        }

        @Test
        fun `store then retrieve with empty value returns empty bytes`() {
            val key = "empty.value"
            val value = ByteArray(0)
            storage.set(key, value)
            val retrieved = storage.get(key)
            assertNotNull(retrieved)
            assertEquals(0, retrieved!!.size)
        }

        @Test
        fun `store replaces existing value for same key`() {
            val key = "replace.key"
            val value1 = "first".toByteArray()
            val value2 = "second".toByteArray()
            storage.set(key, value1)
            storage.set(key, value2)
            val retrieved = storage.get(key)
            assertArrayEquals(value2, retrieved)
        }

        @Test
        fun `store with large value round-trips correctly`() {
            val key = "large.key"
            val value = ByteArray(65536) { (it % 256).toByte() }
            storage.set(key, value)
            val retrieved = storage.get(key)
            assertNotNull(retrieved)
            assertArrayEquals(value, retrieved)
        }

        @Test
        fun `store multiple keys with different values`() {
            storage.set("key1", "value1".toByteArray())
            storage.set("key2", "value2".toByteArray())
            storage.set("key3", "value3".toByteArray())
            assertArrayEquals("value1".toByteArray(), storage.get("key1"))
            assertArrayEquals("value2".toByteArray(), storage.get("key2"))
            assertArrayEquals("value3".toByteArray(), storage.get("key3"))
        }
    }

    // -------------------------------------------------------------------
    // Key-not-found behavior
    // -------------------------------------------------------------------

    @Nested
    inner class KeyNotFound {

        @Test
        fun `retrieve non-existent key returns null`() {
            val result = storage.get("nonexistent")
            assertNull(result)
        }

        @Test
        fun `retrieve after delete returns null`() {
            val key = "delete.me"
            storage.set(key, "data".toByteArray())
            storage.delete(key)
            assertNull(storage.get(key))
        }

        @Test
        fun `exists returns false for non-existent key`() {
            assertFalse(storage.exists("nonexistent"))
        }

        @Test
        fun `exists returns true for stored key`() {
            storage.set("present", "data".toByteArray())
            assertTrue(storage.exists("present"))
        }

        @Test
        fun `exists returns false after delete`() {
            storage.set("temp", "data".toByteArray())
            storage.delete("temp")
            assertFalse(storage.exists("temp"))
        }
    }

    // -------------------------------------------------------------------
    // Delete operations
    // -------------------------------------------------------------------

    @Nested
    inner class DeleteOperations {

        @Test
        fun `delete removes key-value pair`() {
            storage.set("key", "value".toByteArray())
            assertTrue(storage.exists("key"))
            storage.delete("key")
            assertFalse(storage.exists("key"))
            assertNull(storage.get("key"))
        }

        @Test
        fun `delete non-existent key is a no-op`() {
            // Should not throw
            storage.delete("nonexistent")
        }

        @Test
        fun `delete does not affect other keys`() {
            storage.set("keep", "data".toByteArray())
            storage.set("remove", "data".toByteArray())
            storage.delete("remove")
            assertArrayEquals("data".toByteArray(), storage.get("keep"))
            assertNull(storage.get("remove"))
        }

        @Test
        fun `deletePrefix removes matching keys and returns count`() {
            storage.set("ctx.1", "a".toByteArray())
            storage.set("ctx.2", "b".toByteArray())
            storage.set("ctx.3", "c".toByteArray())
            storage.set("other.1", "d".toByteArray())
            val deleted = storage.deletePrefix("ctx.")
            assertEquals(3L, deleted)
            assertNull(storage.get("ctx.1"))
            assertNull(storage.get("ctx.2"))
            assertNull(storage.get("ctx.3"))
            assertArrayEquals("d".toByteArray(), storage.get("other.1"))
        }

        @Test
        fun `deletePrefix with no matches returns zero`() {
            storage.set("key1", "data".toByteArray())
            val deleted = storage.deletePrefix("nonexistent.")
            assertEquals(0L, deleted)
            assertTrue(storage.exists("key1"))
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

    // -------------------------------------------------------------------
    // List operations
    // -------------------------------------------------------------------

    @Nested
    inner class ListOperations {

        @Test
        fun `listKeys returns keys in lexicographic order`() {
            storage.set("charlie", "c".toByteArray())
            storage.set("alpha", "a".toByteArray())
            storage.set("bravo", "b".toByteArray())
            val keys = storage.listKeys("")
            assertEquals(listOf("alpha", "bravo", "charlie"), keys)
        }

        @Test
        fun `listKeys with prefix filters correctly`() {
            storage.set("scp.context.1", "a".toByteArray())
            storage.set("scp.context.2", "b".toByteArray())
            storage.set("scp.key.1", "c".toByteArray())
            storage.set("other.data", "d".toByteArray())
            val contextKeys = storage.listKeys("scp.context.")
            assertEquals(listOf("scp.context.1", "scp.context.2"), contextKeys)
        }

        @Test
        fun `listKeys with no matches returns empty list`() {
            storage.set("key", "value".toByteArray())
            val keys = storage.listKeys("nonexistent.")
            assertEquals(emptyList<String>(), keys)
        }

        @Test
        fun `listKeys on empty store returns empty list`() {
            val keys = storage.listKeys("")
            assertEquals(emptyList<String>(), keys)
        }

        @Test
        fun `listKeys with empty prefix returns all keys sorted`() {
            storage.set("z", "1".toByteArray())
            storage.set("a", "2".toByteArray())
            storage.set("m", "3".toByteArray())
            val keys = storage.listKeys("")
            assertEquals(listOf("a", "m", "z"), keys)
        }

        @Test
        fun `listKeys lexicographic order handles numeric suffixes correctly`() {
            // Lexicographic: "10" < "2" < "9" (string ordering, not numeric)
            storage.set("key.10", "a".toByteArray())
            storage.set("key.2", "b".toByteArray())
            storage.set("key.9", "c".toByteArray())
            val keys = storage.listKeys("key.")
            assertEquals(listOf("key.10", "key.2", "key.9"), keys)
        }
    }

    // -------------------------------------------------------------------
    // AndroidStorage constants and structure verification
    // -------------------------------------------------------------------

    @Nested
    inner class AndroidStorageConstants {

        @Test
        fun `KEY_ALIAS matches ADR-027 specification`() {
            assertEquals("scp.storage.key", AndroidStorage.KEY_ALIAS)
        }

        @Test
        fun `DATABASE_NAME matches ADR-027 specification`() {
            assertEquals("scp.db", AndroidStorage.DATABASE_NAME)
        }

        @Test
        fun `DATABASE_VERSION is 1 for initial schema`() {
            assertEquals(1, AndroidStorage.DATABASE_VERSION)
        }

        @Test
        fun `TABLE_NAME is kv for key-value store`() {
            assertEquals("kv", AndroidStorage.TABLE_NAME)
        }

        @Test
        fun `COLUMN_KEY name is key`() {
            assertEquals("key", AndroidStorage.COLUMN_KEY)
        }

        @Test
        fun `COLUMN_VALUE name is value`() {
            assertEquals("value", AndroidStorage.COLUMN_VALUE)
        }

        @Test
        fun `error codes follow SCP-STORAGE domain pattern`() {
            assertTrue(AndroidStorage.ERROR_KEY_NOT_FOUND.startsWith("SCP-STORAGE-"))
            assertTrue(AndroidStorage.ERROR_STORAGE_OPERATION_FAILED.startsWith("SCP-STORAGE-"))
            assertTrue(AndroidStorage.ERROR_KEY_DERIVATION_FAILED.startsWith("SCP-STORAGE-"))
        }

        @Test
        fun `error code SCP-STORAGE-8001 is key not found`() {
            assertEquals("SCP-STORAGE-8001", AndroidStorage.ERROR_KEY_NOT_FOUND)
        }

        @Test
        fun `error code SCP-STORAGE-8002 is storage operation failed`() {
            assertEquals("SCP-STORAGE-8002", AndroidStorage.ERROR_STORAGE_OPERATION_FAILED)
        }

        @Test
        fun `error code SCP-STORAGE-8003 is key derivation failed`() {
            assertEquals("SCP-STORAGE-8003", AndroidStorage.ERROR_KEY_DERIVATION_FAILED)
        }
    }

    // -------------------------------------------------------------------
    // StorageProvider interface contract
    // -------------------------------------------------------------------

    @Nested
    inner class StorageProviderContract {

        @Test
        fun `InMemoryStorageProvider implements StorageProvider`() {
            // Compile-time check: InMemoryStorageProvider IS-A StorageProvider
            val provider: StorageProvider = InMemoryStorageProvider()
            assertNotNull(provider)
        }

        @Test
        fun `StorageProvider store-retrieve-delete lifecycle`() {
            val key = "lifecycle.key"
            val value = "lifecycle data".toByteArray()

            // Initially absent
            assertNull(storage.get(key))
            assertFalse(storage.exists(key))

            // Store
            storage.set(key, value)
            assertTrue(storage.exists(key))
            assertArrayEquals(value, storage.get(key))

            // Update
            val updated = "updated data".toByteArray()
            storage.set(key, updated)
            assertArrayEquals(updated, storage.get(key))

            // Delete
            storage.delete(key)
            assertNull(storage.get(key))
            assertFalse(storage.exists(key))
        }

        @Test
        fun `StorageProvider prefix operations are consistent`() {
            // Store a batch of keys under a prefix
            for (i in 1..5) {
                storage.set("batch.$i", "data-$i".toByteArray())
            }
            storage.set("other.1", "other".toByteArray())

            // List matches only prefix
            val batchKeys = storage.listKeys("batch.")
            assertEquals(5, batchKeys.size)
            assertTrue(batchKeys.all { it.startsWith("batch.") })

            // Delete prefix removes only matching keys
            val deleted = storage.deletePrefix("batch.")
            assertEquals(5L, deleted)
            assertEquals(emptyList<String>(), storage.listKeys("batch."))
            assertTrue(storage.exists("other.1"))
        }
    }

    // -------------------------------------------------------------------
    // TEE key derivation verification (constants and structure)
    // -------------------------------------------------------------------

    @Nested
    inner class TeeKeyDerivation {

        @Test
        fun `AndroidStorage class exists and implements StorageProvider`() {
            // Verify at the type level that AndroidStorage implements the trait
            assertTrue(StorageProvider::class.java.isAssignableFrom(AndroidStorage::class.java))
        }

        @Test
        fun `getOrCreateStorageKey is accessible for integration testing`() {
            // Verify the method exists on the production class (will throw at runtime
            // without Android Keystore, but the method signature is correct)
            val method = AndroidStorage::class.java.getDeclaredMethod("getOrCreateStorageKey")
            assertNotNull(method)
        }

        @Test
        fun `AndroidStorage requires Context constructor parameter`() {
            // Verify constructor signature matches ADR-027: AndroidStorage(context: Context)
            val constructor = AndroidStorage::class.java.constructors
            assertEquals(1, constructor.size)
            assertEquals(1, constructor[0].parameterCount)
            assertEquals(
                "android.content.Context",
                constructor[0].parameterTypes[0].name
            )
        }

        @Test
        fun `ScpException for key derivation failure carries correct error code`() {
            val exception = ScpException(
                "Failed to derive storage encryption key: test",
                AndroidStorage.ERROR_KEY_DERIVATION_FAILED
            )
            assertEquals("SCP-STORAGE-8003", exception.code)
            assertTrue(exception.message!!.contains("derive storage encryption key"))
        }

        @Test
        fun `ScpException for storage operation failure carries correct error code`() {
            val exception = ScpException(
                "Storage set operation failed",
                AndroidStorage.ERROR_STORAGE_OPERATION_FAILED
            )
            assertEquals("SCP-STORAGE-8002", exception.code)
            assertTrue(exception.message!!.contains("Storage set operation failed"))
        }
    }

    // -------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------

    @Nested
    inner class EdgeCases {

        @Test
        fun `store with key containing special characters round-trips`() {
            val key = "scp.context/abc-123_def.key"
            val value = "special".toByteArray()
            storage.set(key, value)
            assertArrayEquals(value, storage.get(key))
        }

        @Test
        fun `store with key containing dots as namespace separator`() {
            storage.set("scp.identity.main", "identity".toByteArray())
            storage.set("scp.identity.backup", "backup".toByteArray())
            storage.set("scp.context.room1", "room1".toByteArray())
            val identityKeys = storage.listKeys("scp.identity.")
            assertEquals(2, identityKeys.size)
            assertEquals(listOf("scp.identity.backup", "scp.identity.main"), identityKeys)
        }

        @Test
        fun `delete then re-store with same key works`() {
            val key = "reuse.key"
            storage.set(key, "first".toByteArray())
            storage.delete(key)
            storage.set(key, "second".toByteArray())
            assertArrayEquals("second".toByteArray(), storage.get(key))
        }

        @Test
        fun `store value of exactly 32 bytes round-trips`() {
            // 32 bytes is the SQLCipher passphrase length — ensure no special handling
            val key = "exact32"
            val value = ByteArray(32) { it.toByte() }
            storage.set(key, value)
            assertArrayEquals(value, storage.get(key))
        }

        @Test
        fun `concurrent stores to different keys do not interfere`() {
            // Sequential simulation of concurrent access pattern
            val keys = (1..100).map { "concurrent.$it" }
            keys.forEach { storage.set(it, it.toByteArray()) }
            keys.forEach { key ->
                assertArrayEquals(key.toByteArray(), storage.get(key))
            }
            assertEquals(100, storage.listKeys("concurrent.").size)
        }
    }
}
