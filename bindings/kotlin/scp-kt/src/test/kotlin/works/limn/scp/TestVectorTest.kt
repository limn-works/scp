// TestVectorTest.kt — Unit tests for TestVector data class (#1096)
//
// Verifies that the TestVector type matches scp-core::context::tools::TestVector:
// description, input, and expectedOutput fields are stored and forwarded correctly.
//
// Provenance: spec §7.3.3, ADR-010 (phase-2), issue #1096

package works.limn.scp

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class TestVectorTest {
    @Test
    fun `TestVector stores description, input, and expected output`() {
        val vector = TestVector(
            description = "addition of two operands",
            input = """{"operands": [2, 3]}""",
            expectedOutput = """{"sum": 5}""",
        )
        assertEquals("addition of two operands", vector.description)
        assertEquals("""{"operands": [2, 3]}""", vector.input)
        assertEquals("""{"sum": 5}""", vector.expectedOutput)
    }

    @Test
    fun `TestVector data class equality compares all fields`() {
        val a = TestVector(
            description = "add",
            input = """{"a": 1}""",
            expectedOutput = """{"b": 2}""",
        )
        val b = TestVector(
            description = "add",
            input = """{"a": 1}""",
            expectedOutput = """{"b": 2}""",
        )
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun `TestVector with different description is not equal`() {
        val a = TestVector(
            description = "add",
            input = "{}",
            expectedOutput = "{}",
        )
        val b = TestVector(
            description = "subtract",
            input = "{}",
            expectedOutput = "{}",
        )
        assertNotEquals(a, b)
    }

    @Test
    fun `TestVector copy preserves description`() {
        val original = TestVector(
            description = "original description",
            input = """{"x": 1}""",
            expectedOutput = """{"y": 2}""",
        )
        val copied = original.copy(input = """{"x": 99}""")
        assertEquals("original description", copied.description)
        assertEquals("""{"x": 99}""", copied.input)
        assertEquals("""{"y": 2}""", copied.expectedOutput)
    }

    @Test
    fun `TestVector toString includes all fields`() {
        val vector = TestVector(
            description = "smoke",
            input = "{}",
            expectedOutput = "{}",
        )
        val str = vector.toString()
        assert(str.contains("smoke")) { "toString() should contain description" }
        assert(str.contains("input")) { "toString() should reference input" }
        assert(str.contains("expectedOutput")) { "toString() should reference expectedOutput" }
    }
}
