// Economy.kt — Kotlin SDK economic amount-display surface.
//
// All monetary values in SCP are smallest-currency-unit integers on the wire
// (cents for USD, satoshis for BTC); the decimal scale used to render them is
// a purely SDK-side concern. This file holds that display surface and nothing
// else: pure integer/string arithmetic with no FFI dependency, mirrored by
// `format_amount` in the Python SDK and `formatAmount` in the TypeScript SDK.
//
// The `EconomyBindings` / `EconomyBridge` pair that used to live here was a
// zero-implementor stub over the deleted `CoroutineBridge` scaffold and was
// removed with it; it never reached the UniFFI economy exports.
//
// Provenance: spec §19 (Economic Governance), ADR-033, ADR-060.

package works.limn.scp

// ---------------------------------------------------------------------------
// Amount display formatting (ADR-060 SDK display surface)
// ---------------------------------------------------------------------------

/**
 * Number of decimal places for well-known currencies, keyed by uppercase
 * currency code. The SCP protocol does NOT store per-currency decimals -- the
 * wire form is always a smallest-unit integer -- so this table lives entirely
 * in the SDK for display. The same values are used across every SDK
 * (TypeScript, Python, Swift) for cross-binding consistency.
 */
private val KNOWN_CURRENCY_DECIMALS: Map<String, Int> =
    mapOf(
        "USD" to 2,
        "EUR" to 2,
        "GBP" to 2,
        "BTC" to 8,
        "SAT" to 0,
        "SOL" to 9,
        "USDC" to 6,
        "ETH" to 18,
    )

private fun formatWithDecimals(
    amount: ULong,
    decimals: Int,
): String {
    // Operate on the decimal digit string directly (no divisor arithmetic), so
    // any [decimals] -- even beyond a ULong's digit count -- formats exactly
    // with no overflow. A full-width ULong formats exactly.
    val digits = amount.toString()
    if (decimals == 0) {
        // The amount is already in whole display units -- no fraction.
        return digits
    }
    if (digits.length <= decimals) {
        return "0." + "0".repeat(decimals - digits.length) + digits
    }
    val split = digits.length - decimals
    return digits.substring(0, split) + "." + digits.substring(split)
}

/**
 * Formats a smallest-unit monetary amount as a human-readable decimal string,
 * applying the currency's decimal scale.
 *
 * Pure integer/string arithmetic (no floating point), so a full-width [ULong]
 * formats exactly.
 *
 * ```kotlin
 * formatAmount(150uL, "USD")        // "1.50"
 * formatAmount(100_000_000uL, "BTC") // "1.00000000"
 * ```
 *
 * @param amount Smallest-unit amount (e.g. cents, satoshis).
 * @param currency A known currency code (case-insensitive).
 * @return The human-decimal representation.
 * @throws IllegalArgumentException (SCP-ECON-12070) if the currency is unknown;
 *     use the [formatAmount] overload taking `decimals` for unknown/custom
 *     currencies. This is a pure SDK-side display helper that never touches the
 *     FFI bridge, so it raises an idiomatic argument exception rather than a
 *     [works.limn.scp.bridge.BridgeException] (which carries FFI error codes);
 *     the `SCP-ECON-12070` code is kept in the message for cross-SDK parity.
 */
fun formatAmount(
    amount: ULong,
    currency: String,
): String {
    val decimals =
        KNOWN_CURRENCY_DECIMALS[currency.uppercase()]
            ?: throw IllegalArgumentException(
                "[SCP-ECON-12070] unknown currency \"$currency\" has no known decimals; " +
                    "use formatAmount(amount, decimals) with an explicit scale",
            )
    return formatWithDecimals(amount, decimals)
}

/**
 * Formats a smallest-unit monetary amount using an explicit decimal scale, for
 * unknown or custom currencies.
 *
 * @param amount Smallest-unit amount (e.g. cents, satoshis).
 * @param decimals The number of fractional decimal places (0..100).
 * @return The human-decimal representation.
 * @throws IllegalArgumentException (SCP-ECON-12070) if [decimals] is out of
 *     range. Pure SDK-side display helper — no FFI bridge, so an idiomatic
 *     argument exception rather than a
 *     [works.limn.scp.bridge.BridgeException]; the `SCP-ECON-12070` code is
 *     kept in the message for cross-SDK parity.
 */
fun formatAmount(
    amount: ULong,
    decimals: Int,
): String {
    // `require` raises IllegalArgumentException — the idiomatic non-bridge
    // exception; the SCP-ECON-12070 code stays in the message for cross-SDK
    // parity.
    require(decimals in 0..100) { "[SCP-ECON-12070] decimals must be in 0..100, got $decimals" }
    return formatWithDecimals(amount, decimals)
}
