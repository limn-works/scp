@testable import SCP
import XCTest

/// Tests for the economy amount display helper (`Economy.format`).
///
/// The SCP protocol wire form for a monetary value is a smallest-unit integer
/// (decimal string in JSON, native integer in MessagePack; ADR-060). The Swift
/// SDK exposes amounts as `UInt64` and renders the human decimal for display
/// via `Economy.format`, using an SDK-side per-currency decimals table.
///
/// These tests do NOT require the native UniFFI binary — `Economy.format` is
/// pure Swift integer/string arithmetic.
final class EconomyTests: XCTestCase {
    func testUsdTwoDecimals() throws {
        XCTAssertEqual(try Economy.format(amount: 150, currency: "USD"), "1.50")
        XCTAssertEqual(try Economy.format(amount: 0, currency: "USD"), "0.00")
        XCTAssertEqual(try Economy.format(amount: 5, currency: "USD"), "0.05")
        XCTAssertEqual(try Economy.format(amount: 1_234_567, currency: "USD"), "12345.67")
    }

    func testBtcEightDecimals() throws {
        XCTAssertEqual(try Economy.format(amount: 100_000_000, currency: "BTC"), "1.00000000")
        XCTAssertEqual(try Economy.format(amount: 1, currency: "BTC"), "0.00000001")
    }

    func testZeroDecimalCurrency() throws {
        XCTAssertEqual(try Economy.format(amount: 150, currency: "SAT"), "150")
        XCTAssertEqual(try Economy.format(amount: 0, currency: "SAT"), "0")
    }

    func testFullKnownCurrencyTable() throws {
        XCTAssertEqual(try Economy.format(amount: 100, currency: "EUR"), "1.00")
        XCTAssertEqual(try Economy.format(amount: 100, currency: "GBP"), "1.00")
        XCTAssertEqual(try Economy.format(amount: 1_000_000_000, currency: "SOL"), "1.000000000")
        XCTAssertEqual(try Economy.format(amount: 1_000_000, currency: "USDC"), "1.000000")
        XCTAssertEqual(
            try Economy.format(amount: 1_000_000_000_000_000_000, currency: "ETH"),
            "1.000000000000000000"
        )
    }

    func testCaseInsensitiveCurrency() throws {
        XCTAssertEqual(try Economy.format(amount: 150, currency: "usd"), "1.50")
        XCTAssertEqual(try Economy.format(amount: 150, currency: "Usd"), "1.50")
    }

    func testAmountsAbove2To53FormatExactly() throws {
        // 2^53 + 1 — the first integer a `Double` cannot represent exactly.
        XCTAssertEqual(
            try Economy.format(amount: 9_007_199_254_740_993, currency: "USD"),
            "90071992547409.93"
        )
        // The full-width UInt64 maximum.
        XCTAssertEqual(
            try Economy.format(amount: UInt64.max, currency: "USD"),
            "184467440737095516.15"
        )
    }

    func testExplicitDecimalsOverride() throws {
        XCTAssertEqual(try Economy.format(amount: 1500, decimals: 3), "1.500")
        XCTAssertEqual(try Economy.format(amount: 42, decimals: 0), "42")
        XCTAssertEqual(try Economy.format(amount: 123_456, decimals: 4), "12.3456")
    }

    func testUnknownCurrencyThrows() {
        XCTAssertThrowsError(try Economy.format(amount: 100, currency: "XYZ")) { error in
            guard case let ScpError.Validation(_, code) = error else {
                return XCTFail("expected ScpError.Validation, got \(error)")
            }
            XCTAssertEqual(code, "SCP-ECON-12070")
        }
    }

    func testNegativeDecimalsThrows() {
        XCTAssertThrowsError(try Economy.format(amount: 1, decimals: -1)) { error in
            guard case ScpError.Validation = error else {
                return XCTFail("expected ScpError.Validation, got \(error)")
            }
        }
    }
}
