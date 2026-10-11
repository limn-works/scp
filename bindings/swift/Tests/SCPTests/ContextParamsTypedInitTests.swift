@testable import SCP
import XCTest

/// Tests that the typed ``ContextParams`` initializer forwards the ceiling the
/// caller declared, as written.
///
/// A create whose ceiling is empty fails in the bridge with `SCP-VALID-7005`
/// (construction.md M2). An initializer that replaced an empty list with a
/// default ceiling would turn that refusal into a context with capabilities
/// nobody chose, so the empty list must reach the bridge unchanged.
final class ContextParamsTypedInitTests: XCTestCase {
    private func makeParams(ceiling: [String]) throws -> ContextParams {
        try ContextParams(
            mode: .encrypted,
            ceiling: ceiling,
            ceilingPolicy: .immutable,
            governance: .singleAdmin,
            memoryScope: .ephemeral,
            ttlSeconds: 3600,
            promotable: false,
            consequenceRules: nil,
            consequenceConfig: nil
        )
    }

    func testEmptyCeilingStaysEmpty() throws {
        XCTAssertEqual(try makeParams(ceiling: []).ceiling, [])
    }

    func testDeclaredCeilingStandsAsWritten() throws {
        XCTAssertEqual(
            try makeParams(ceiling: ["messages:read"]).ceiling,
            ["messages:read"]
        )
    }
}
