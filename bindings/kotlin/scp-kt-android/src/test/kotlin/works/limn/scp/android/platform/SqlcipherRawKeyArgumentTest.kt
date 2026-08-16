// SqlcipherRawKeyArgumentTest.kt — the bytes AndroidStorage hands SQLCipher (SCP-113)
//
// Section 17.6 of .docs/specs/17-persistence-and-storage.md requires the derived
// 32-byte key to reach SQLCipher through raw-key syntax: `x'<64 hex chars>'`. SQLCipher
// reads an argument of exactly that shape as 32 raw key bytes and reads every other
// argument as a password to PBKDF2-stretch, so an adapter that hands over the 32 raw
// bytes encrypts its database under a key no other SCP adapter computes.
//
// These tests pin AndroidStorage.sqlcipherRawKeyArgument to that shape and to those
// exact bytes for two fixed keys.
//
// ## Why no test here opens a database the Rust adapter wrote
//
// The SQLCipher library ships only Android ABI binaries: net.zetetic:sqlcipher-android
// 4.6.1 carries `jni/arm64-v8a`, `jni/armeabi-v7a`, `jni/x86`, and `jni/x86_64`, and no
// host-JVM binary. `System.loadLibrary("sqlcipher")` therefore fails on the host JVM,
// under Robolectric as well, and org.xerial:sqlite-jdbc — the JVM SQLite this module
// already tests against — carries no cipher codec. No unit test in this module can open
// an encrypted database at all.
//
// The cross-adapter claim is instead pinned from both sides against one shared value,
// the raw-key argument for a fixed 32-byte key:
//
//   - This file asserts that AndroidStorage builds exactly that argument.
//   - `sqlcipher_raw_key_argument_opens_a_database_this_adapter_wrote` in
//     crates/scp-platform/src/sqlite/mod.rs writes a database with the Rust adapter
//     under the same 32-byte key, reopens the file with that same argument, and reads
//     the value back.
//
// Together the two tests say: the argument Android sends opens a database the Rust
// adapter created. The step neither test executes is SQLCipher's own equivalence
// between an argument delivered through `sqlite3_key` (Android's path) and the same
// argument delivered through `PRAGMA key` (the Rust path); SQLCipher applies its
// raw-key check to the password bytes themselves, after either delivery.
//
// This file uses JUnit 4 because the :scp-kt-android unit-test tasks run the JUnit 4
// runner: build.gradle.kts never calls useJUnitPlatform(), so a JUnit 5 test in this
// module is compiled and then never executed.
//
// Provenance: ADR-027 (Android Platform Adapter), section 17.6 of
// .docs/specs/17-persistence-and-storage.md (SQLCipher key derivation and the
// "SQLCipher configuration" block that mandates raw-key syntax).

package works.limn.scp.android.platform

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for [AndroidStorage.sqlcipherRawKeyArgument].
 */
class SqlcipherRawKeyArgumentTest {

    @Test
    fun `argument for the all-zero key is x quote 64 zeros quote`() {
        val expected = "x'" + "0".repeat(64) + "'"
        assertEquals(expected, String(AndroidStorage.sqlcipherRawKeyArgument(ByteArray(32)), Charsets.US_ASCII))
    }

    @Test
    fun `argument for the counting key matches the Rust adapter's vector`() {
        // The same 32 bytes and the same expected string appear in
        // `sqlcipher_raw_key_argument_opens_a_database_this_adapter_wrote`
        // (crates/scp-platform/src/sqlite/mod.rs), where the Rust adapter writes a
        // database under this key and reopens it with this argument.
        val key = ByteArray(32) { it.toByte() }
        val expected = "x'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'"

        assertEquals(expected, String(AndroidStorage.sqlcipherRawKeyArgument(key), Charsets.US_ASCII))
    }

    @Test
    fun `argument for a high-byte key uses lowercase hex`() {
        // SQLCipher accepts either case, but the Rust adapters emit lowercase via
        // hex::encode, so this adapter emits lowercase too and the two byte strings
        // compare equal.
        val key = ByteArray(32) { 0xAB.toByte() }
        val expected = "x'" + "ab".repeat(32) + "'"

        assertEquals(expected, String(AndroidStorage.sqlcipherRawKeyArgument(key), Charsets.US_ASCII))
    }

    @Test
    fun `argument is 67 bytes, which is what selects SQLCipher's raw-key mode`() {
        // SQLCipher selects raw-key mode when the password is (key_sz * 2) + 3 bytes,
        // starts with "x'", and holds hex digits between the quotes.
        assertEquals(67, AndroidStorage.RAW_KEY_ARGUMENT_LENGTH)

        val argument = AndroidStorage.sqlcipherRawKeyArgument(ByteArray(32) { (it * 5).toByte() })

        assertEquals(67, argument.size)
        assertEquals('x'.code.toByte(), argument[0])
        assertEquals('\''.code.toByte(), argument[1])
        assertEquals('\''.code.toByte(), argument[66])
        assertTrue(
            "every character between the quotes must be a lowercase hex digit",
            argument.copyOfRange(2, 66).all { it.toInt().toChar() in "0123456789abcdef" },
        )
    }

    @Test
    fun `the argument is not the raw key bytes`() {
        // Handing SQLCipher the 32 derived bytes is what this test rejects: SQLCipher
        // would PBKDF2-stretch them, and the resulting database key would differ from
        // the one the Apple and Rust adapters compute for the same 32 bytes.
        val key = ByteArray(32) { (it * 3 + 1).toByte() }

        val argument = AndroidStorage.sqlcipherRawKeyArgument(key)

        assertFalse(argument.contentEquals(key))
        assertFalse(argument.size == key.size)
    }

    @Test
    fun `distinct keys yield distinct arguments`() {
        val first = AndroidStorage.sqlcipherRawKeyArgument(ByteArray(32) { it.toByte() })
        val second = AndroidStorage.sqlcipherRawKeyArgument(ByteArray(32) { (it + 1).toByte() })

        assertFalse(first.contentEquals(second))
    }

    @Test
    fun `the derived database key feeds the argument at its declared length`() {
        // deriveDatabaseKey emits DATABASE_KEY_LENGTH bytes, and the argument builder
        // requires exactly that many, so the two agree by construction rather than by
        // coincidence.
        val derived = AndroidStorage.deriveDatabaseKey(ByteArray(32) { (it * 7).toByte() })

        assertEquals(AndroidStorage.DATABASE_KEY_LENGTH, derived.size)
        assertEquals(
            AndroidStorage.RAW_KEY_ARGUMENT_LENGTH,
            AndroidStorage.sqlcipherRawKeyArgument(derived).size,
        )
    }

    @Test
    fun `a key of the wrong length is rejected rather than silently padded`() {
        assertThrows(IllegalArgumentException::class.java) {
            AndroidStorage.sqlcipherRawKeyArgument(ByteArray(31))
        }
        assertThrows(IllegalArgumentException::class.java) {
            AndroidStorage.sqlcipherRawKeyArgument(ByteArray(33))
        }
    }

    @Test
    fun `the builder leaves its input key untouched`() {
        // openEncryptedDatabase zeroes the derived key right after building the
        // argument, so the builder must not depend on the key afterwards.
        val key = ByteArray(32) { (it * 9 + 2).toByte() }
        val copy = key.copyOf()

        AndroidStorage.sqlcipherRawKeyArgument(key)

        assertArrayEquals(copy, key)
    }
}
