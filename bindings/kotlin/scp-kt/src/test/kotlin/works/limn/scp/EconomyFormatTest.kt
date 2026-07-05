// EconomyFormatTest.kt — Unit tests for the economy amount display helper.
//
// The SCP protocol wire form for a monetary value is a smallest-unit integer
// (decimal string in JSON, native integer in MessagePack; ADR-060). The Kotlin
// SDK exposes amounts as ULong and renders the human decimal for display via
// formatAmount, using an SDK-side per-currency decimals table.
//
// Provenance: ADR-060 (monetary value representation), spec §19

package works.limn.scp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class EconomyFormatTest {
    @Test
    fun `USD formats with two decimals`() {
        assertEquals("1.50", formatAmount(150uL, "USD"))
        assertEquals("0.00", formatAmount(0uL, "USD"))
        assertEquals("0.05", formatAmount(5uL, "USD"))
        assertEquals("12345.67", formatAmount(1_234_567uL, "USD"))
    }

    @Test
    fun `BTC formats with eight decimals`() {
        assertEquals("1.00000000", formatAmount(100_000_000uL, "BTC"))
        assertEquals("0.00000001", formatAmount(1uL, "BTC"))
    }

    @Test
    fun `zero-decimal currency formats as the bare integer`() {
        assertEquals("150", formatAmount(150uL, "SAT"))
        assertEquals("0", formatAmount(0uL, "SAT"))
    }

    @Test
    fun `full known-currency table`() {
        assertEquals("1.00", formatAmount(100uL, "EUR"))
        assertEquals("1.00", formatAmount(100uL, "GBP"))
        assertEquals("1.000000000", formatAmount(1_000_000_000uL, "SOL"))
        assertEquals("1.000000", formatAmount(1_000_000uL, "USDC"))
        assertEquals("1.000000000000000000", formatAmount(1_000_000_000_000_000_000uL, "ETH"))
    }

    @Test
    fun `currency codes match case-insensitively`() {
        assertEquals("1.50", formatAmount(150uL, "usd"))
        assertEquals("1.50", formatAmount(150uL, "Usd"))
    }

    @Test
    fun `amounts above 2 to the 53 format exactly`() {
        // 2^53 + 1 — the first integer a Double cannot represent exactly.
        assertEquals("90071992547409.93", formatAmount(9_007_199_254_740_993uL, "USD"))
        // The full-width ULong maximum.
        assertEquals("184467440737095516.15", formatAmount(ULong.MAX_VALUE, "USD"))
    }

    @Test
    fun `explicit decimals override`() {
        assertEquals("1.500", formatAmount(1500uL, 3))
        assertEquals("42", formatAmount(42uL, 0))
        assertEquals("12.3456", formatAmount(123_456uL, 4))
    }

    @Test
    fun `unknown currency throws with the economy code`() {
        // Pure SDK-side display helper: an idiomatic IllegalArgumentException,
        // not a BridgeException (which carries FFI codes). The SCP-ECON-12070
        // code is kept in the message for cross-SDK parity.
        val ex =
            assertThrows(IllegalArgumentException::class.java) { formatAmount(100uL, "XYZ") }
        assertTrue(ex.message?.contains("SCP-ECON-12070") == true)
    }

    @Test
    fun `negative decimals override throws`() {
        val ex = assertThrows(IllegalArgumentException::class.java) { formatAmount(1uL, -1) }
        assertTrue(ex.message?.contains("SCP-ECON-12070") == true)
    }
}
